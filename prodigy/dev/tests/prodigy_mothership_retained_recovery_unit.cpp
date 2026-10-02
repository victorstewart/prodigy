#include <cassert>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <prodigy/mothership/mothership.retained.recovery.h>
#include <prodigy/mothership/mothership.retained.recovery.command.h>
#include <prodigy/mothership/mothership.tidesdb.migration.h>

static bool retainedDescriptorLockChecksDrainProducer(void)
{
  using namespace MothershipTidesMigration;
  const std::string stateLock = "/var/lib/prodigy/state/LOCK";
  const std::string secretsLock = "/var/lib/prodigy/secrets/LOCK";
  const std::string checkState = descriptorLockCheckCommand(stateLock);
  const std::string checkSecrets = descriptorLockCheckCommand(secretsLock);

  std::filesystem::create_directories(".run");
  const std::string descriptorPath = ".run/retained-descriptors-" + std::to_string(::getpid());
  auto run = [&](const std::string& descriptors, const std::string& check) {
    { std::ofstream output(descriptorPath, std::ios::binary); if (!output) return false; output << descriptors; }
    String failure;
    const std::string command = "set -o pipefail; fds=$(cat " + quote(descriptorPath) + "); " + check;
    return prodigyRunLocalShellCommand(text(command), &failure);
  };

  // Keep a matching lock before a payload far larger than a pipe buffer.  The
  // fixed command must drain it; the historical grep -q command makes printf
  // fail with SIGPIPE under pipefail after accepting the first line.
  std::string descriptors = stateLock + "\n" + secretsLock + "\n";
  descriptors.append(8 * 1024 * 1024, 'x');
  bool passed = run(descriptors, checkState) && run(descriptors, checkSecrets);

  passed = passed && !run(secretsLock + "\n" + stateLock + ".stale", checkState);
  passed = passed && !run(stateLock + "\n" + secretsLock + ".stale", checkSecrets);
  std::filesystem::remove(descriptorPath);
  return passed;
}

static void assertRetainedBootstrapUnorderedMapRoundTrip(void)
{
  NeuronContainerBootstrap bootstrap = {};
  for (uint64_t index = 0; index < 16; ++index)
  {
    const uint64_t subscriptionService = 1000 + index;
    const uint64_t advertisementService = 2000 + index;
    bootstrap.plan.subscriptions[subscriptionService] = Subscription(
        subscriptionService, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::any);
    bootstrap.plan.advertisements[advertisementService] = Advertisement(
        advertisementService, ContainerState::scheduled, ContainerState::destroying, uint16_t(3000 + index));

    SubscriptionPairing subscriptionPairing = {};
    subscriptionPairing.secret = 10 + index;
    subscriptionPairing.address = 20 + index;
    subscriptionPairing.service = subscriptionService;
    subscriptionPairing.port = uint16_t(4000 + index);
    bootstrap.plan.subscriptionPairings.insert(subscriptionService, subscriptionPairing);

    AdvertisementPairing advertisementPairing = {};
    advertisementPairing.secret = 30 + index;
    advertisementPairing.address = 40 + index;
    advertisementPairing.service = advertisementService;
    bootstrap.plan.advertisementPairings.insert(advertisementService, advertisementPairing);
  }

  String serialized = {};
  BitseryEngine::serialize(serialized, bootstrap);
  NeuronContainerBootstrap roundTrip = {};
  assert(BitseryEngine::deserializeSafe(serialized, roundTrip));
  assert(prodigyPersistentRetainedBootstrapEqual(bootstrap, roundTrip));

  auto changed = roundTrip.plan.advertisements.find(2000);
  assert(changed != roundTrip.plan.advertisements.end());
  changed->second.port += 1;
  assert(!prodigyPersistentRetainedBootstrapEqual(bootstrap, roundTrip));
}

static void assertRetainedRecoveryObservedLifecycleComparison(void)
{
  NeuronContainerBootstrap reconstructed = {};
  reconstructed.plan.uuid = 0x91;
  reconstructed.plan.state = ContainerState::scheduled;
  reconstructed.plan.runtimeReady = false;
  reconstructed.plan.config.memoryMB = 256;
  reconstructed.plan.statefulMeshRoles.sibling = 41;
  reconstructed.plan.subscriptions[100] = Subscription(100, ContainerState::scheduled,
      ContainerState::destroying, SubscriptionNature::any);
  reconstructed.plan.advertisements[200] = Advertisement(200, ContainerState::scheduled,
      ContainerState::destroying, 4443);
  SubscriptionPairing subscription = {};
  subscription.service = 100; subscription.port = 4443; subscription.address = 0x12; subscription.secret = 0x34;
  AdvertisementPairing advertisement = {};
  advertisement.service = 200; advertisement.address = 0x56; advertisement.secret = 0x78;
  reconstructed.plan.subscriptionPairings.insert(subscription.service, subscription);
  reconstructed.plan.advertisementPairings.insert(advertisement.service, advertisement);

  auto observed = reconstructed;
  observed.plan.state = ContainerState::healthy;
  observed.plan.runtimeReady = true;
  // ContainerView::generatePlan owns these live edges and may rotate them after
  // launch.  The retained comparator intentionally ignores only these maps.
  observed.plan.subscriptionPairings.clear();
  observed.plan.advertisementPairings.clear();
  for (const auto state : {ContainerState::scheduled, ContainerState::healthy}) {
    for (const bool ready : {false, true}) {
      observed.plan.state = state;
      observed.plan.runtimeReady = ready;
      assert(mothershipRetainedRecoveryBootstrapMatchesObservedLifecycle(observed, reconstructed));
    }
  }
  auto invalidReconstruction = reconstructed;
  invalidReconstruction.plan.runtimeReady = true;
  assert(!mothershipRetainedRecoveryBootstrapMatchesObservedLifecycle(observed, invalidReconstruction));

  auto invalidLifecycle = observed;
  invalidLifecycle.plan.state = ContainerState::destroying;
  assert(!mothershipRetainedRecoveryBootstrapMatchesObservedLifecycle(invalidLifecycle, reconstructed));
  auto changedConfig = observed;
  ++changedConfig.plan.config.memoryMB;
  assert(!mothershipRetainedRecoveryBootstrapMatchesObservedLifecycle(changedConfig, reconstructed));
  auto changedService = observed;
  changedService.plan.advertisements.find(200)->second.port++;
  assert(!mothershipRetainedRecoveryBootstrapMatchesObservedLifecycle(changedService, reconstructed));
  auto changedRole = observed;
  ++changedRole.plan.statefulMeshRoles.sibling;
  assert(!mothershipRetainedRecoveryBootstrapMatchesObservedLifecycle(changedRole, reconstructed));
  auto changedCredentials = observed;
  changedCredentials.plan.hasCredentialBundle = true;
  assert(!mothershipRetainedRecoveryBootstrapMatchesObservedLifecycle(changedCredentials, reconstructed));
}

static void assertEmptyMachineColdCanonicalRuntimeRecovery(void)
{
  const String bundle = MothershipTidesMigration::text(std::string(64, 'd'));
  ProdigyPersistentBrainSnapshot source = {};
  source.brainConfig.clusterUUID = 0x31;
  source.brainConfig.datacenterFragment = 7;
  Vector<MothershipRetainedRecoveryMachineInput> machines = {};
  for (uint32_t index = 1; index <= 3; ++index)
  {
    ClusterMachine topology = {};
    topology.uuid = index;
    source.topology.machines.push_back(topology);
    MothershipRetainedRecoveryMachineInput machine = {};
    machine.machineUUID = index;
    machine.machineFragment = index;
    machines.push_back(std::move(machine));
  }
  auto statefulPlan = [](uint16_t applicationID, bool neverShard) {
    DeploymentPlan plan = {};
    plan.config.type = ApplicationType::stateful;
    plan.config.applicationID = applicationID;
    plan.config.versionID = 4;
    plan.config.memoryMB = 128;
    plan.config.storageMB = 64;
    plan.config.nLogicalCores = 1;
    plan.isStateful = true;
    plan.stateful.clientPrefix = 0x1100000000000000ULL;
    plan.stateful.siblingPrefix = 0x1200000000000000ULL;
    plan.stateful.cousinPrefix = 0x1300000000000000ULL;
    plan.stateful.seedingPrefix = 0x1400000000000000ULL;
    plan.stateful.shardingPrefix = 0x1500000000000000ULL;
    plan.stateful.neverShard = neverShard;
    plan.stateful.allMasters = false;
    return plan;
  };
  auto statelessPlan = [](uint16_t applicationID) {
    DeploymentPlan plan = {};
    plan.config.type = ApplicationType::stateless;
    plan.config.applicationID = applicationID;
    plan.config.versionID = 4;
    plan.config.memoryMB = 64;
    plan.config.storageMB = 32;
    plan.config.nLogicalCores = 1;
    return plan;
  };
  auto parametersFor = [&](const DeploymentPlan& plan, uint128_t uuid, uint32_t machine,
                           uint8_t fragment, bool client) {
    ContainerParameters parameters = {};
    parameters.uuid = uuid;
    parameters.deploymentID = plan.config.deploymentID();
    parameters.memoryMB = plan.config.memoryMB;
    parameters.storageMB = plan.config.storageMB;
    parameters.nLogicalCores = applicationSharedCPUCoreHint(plan.config);
    parameters.cpuMode = plan.config.cpuMode;
    parameters.requestedCPUMillis = applicationRequestedCPUMillis(plan.config);
    parameters.private6.network.is6 = true;
    parameters.private6.cidr = 128;
    std::memcpy(parameters.private6.network.v6, container_network_subnet6.value, 11);
    parameters.private6.network.v6[11] = source.brainConfig.datacenterFragment;
    parameters.private6.network.v6[14] = machine;
    parameters.private6.network.v6[15] = fragment;
    if (plan.isStateful)
    {
      parameters.statefulMeshRoles = StatefulMeshRoles::forShardGroup(
          plan.stateful, plan.config.applicationID, 0);
      if (!client) parameters.statefulMeshRoles.client = 0;
      if (plan.stateful.neverShard)
      {
        parameters.statefulMeshRoles.cousin = 0;
        parameters.statefulMeshRoles.sharding = 0;
      }
      parameters.statefulMeshRoles.topologyBridge = 0;
      parameters.statefulTopology.shardGroup = 0;
      parameters.statefulTopology.workerCount = 1;
      parameters.statefulTopology.topologyEpoch = 1;
      parameters.statefulTopology.sourceEpoch = 1;
      parameters.statefulTopology.targetEpoch = 1;
      parameters.statefulTopology.servingMode = StatefulTopologyServingMode::serve;
      if (client) parameters.advertisesOnPorts[parameters.statefulMeshRoles.client] = uint16_t(12000 + fragment);
      parameters.advertisesOnPorts[parameters.statefulMeshRoles.sibling] = uint16_t(12100 + fragment);
      parameters.advertisesOnPorts[parameters.statefulMeshRoles.seeding] = uint16_t(12200 + fragment);
      if (!plan.stateful.neverShard)
      {
        parameters.advertisesOnPorts[parameters.statefulMeshRoles.cousin] = uint16_t(12300 + fragment);
        parameters.advertisesOnPorts[parameters.statefulMeshRoles.sharding] = uint16_t(12400 + fragment);
      }
    }
    return parameters;
  };

  Vector<BrainReplicatedContainerRuntimeState> coldStates = {};
  for (uint32_t deploymentIndex = 0; deploymentIndex < 4; ++deploymentIndex)
  {
    DeploymentPlan plan = statefulPlan(uint16_t(91 + deploymentIndex), deploymentIndex >= 2);
    const uint64_t deploymentID = plan.config.deploymentID();
    source.masterAuthority.deploymentPlans[deploymentID] = plan;
    for (uint32_t machine = 2; machine <= 3; ++machine)
    {
      const uint8_t fragment = uint8_t(deploymentIndex + 1);
      machines[machine - 1].parameters.push_back(parametersFor(
          plan, 0x1000 + deploymentIndex * 0x10 + machine, machine, fragment, false));
      machines[machine - 1].observedCreatedAtMs.push_back(1791000000000LL + deploymentIndex * 10 + machine);
    }
    ContainerParameters original = parametersFor(
        plan, 0x2000 + deploymentIndex, 1, uint8_t(deploymentIndex + 1), true);
    NeuronContainerBootstrap coldBootstrap = {};
    String failure = {};
    assert(prodigyBuildRetainedContainerBootstrap(
        plan, original, 1, source.brainConfig.datacenterFragment,
        1791000000100LL + deploymentIndex, coldBootstrap, &failure));
    BrainReplicatedContainerRuntimeState cold = {};
    cold.machineUUID = 1;
    cold.plan = coldBootstrap.plan;
    cold.plan.state = ContainerState::healthy;
    cold.plan.runtimeReady = true;
    // ContainerPlan owns service maps; retain a nested map through RRF7 rather
    // than asserting against ContainerParameters-only transport fields.
    const uint64_t nestedService = 0x5100 + deploymentIndex;
    cold.plan.subscriptions.emplace(nestedService, Subscription(
        nestedService, ContainerState::scheduled, ContainerState::destroying,
        SubscriptionNature::any));
    coldStates.push_back(std::move(cold));
  }
  // Two stateless survivors join the four two-member stateful cohorts below.
  // The partial Hot handoff added later brings the live record count to 13.
  for (uint32_t index = 0; index < 2; ++index)
  {
    DeploymentPlan plan = statelessPlan(uint16_t(201 + index));
    source.masterAuthority.deploymentPlans[plan.config.deploymentID()] = plan;
    const uint32_t machine = index < 3 ? 2 : 3;
    const uint8_t fragment = uint8_t(5 + (index < 3 ? index : index - 3));
    machines[machine - 1].parameters.push_back(parametersFor(plan, 0x3000 + index, machine, fragment, false));
    machines[machine - 1].observedCreatedAtMs.push_back(1791000000200LL + index);
  }
  assert(machines[1].parameters.size() + machines[2].parameters.size() == 10);
  bytell_hash_map<uint64_t, DeploymentPlan> approved = source.masterAuthority.deploymentPlans;

  // A stale, unobserved nuc1 stateless owner must not survive as a scheduled
  // replay when the sealed cold source selects only these four client masters.
  BrainReplicatedContainerRuntimeState staleStateless = {};
  staleStateless.machineUUID = 1;
  staleStateless.plan.uuid = 0x9ff;
  source.masterAuthority.containerRuntimeStates.push_back(staleStateless);

  String failure = {};
  auto valid = source;
  assert(mothershipPrepareRetainedRecoverySnapshot(
      valid, approved, machines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, coldStates));
  assert(valid.masterAuthority.containerRuntimeStates.size() == 4);
  assert(valid.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses.size() == 3);
  const auto& witness = valid.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0];
  assert(witness.machineUUID == 1 && witness.containerBootstraps.size() == 4);
  bytell_hash_set<uint64_t> coldDeployments = {};
  for (const String& serialized : witness.containerBootstraps)
  {
    NeuronContainerBootstrap replay = {};
    assert(BitseryEngine::deserializeSafe(serialized, replay) &&
        replay.plan.state == ContainerState::scheduled && replay.plan.runtimeReady == false &&
        replay.plan.statefulMeshRoles.client != 0);
    coldDeployments.insert(replay.plan.config.deploymentID());
  }
  assert(coldDeployments.size() == 4);

  auto wrongMachine = coldStates;
  wrongMachine[0].machineUUID = 2;
  auto wrongMachineSnapshot = source;
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      wrongMachineSnapshot, approved, machines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, wrongMachine));
  auto wrongPlan = coldStates;
  ++wrongPlan[0].plan.config.memoryMB;
  auto wrongPlanSnapshot = source;
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      wrongPlanSnapshot, approved, machines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, wrongPlan));
  auto missingClient = coldStates;
  missingClient[0].plan.statefulMeshRoles.client = 0;
  auto missingClientSnapshot = source;
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      missingClientSnapshot, approved, machines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, missingClient));
  auto wrongGeneratedRoles = coldStates;
  wrongGeneratedRoles[0].plan.statefulMeshRoles.cousin = 0;
  auto wrongGeneratedRolesSnapshot = source;
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      wrongGeneratedRolesSnapshot, approved, machines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, wrongGeneratedRoles));
  auto wrongUUID = coldStates;
  wrongUUID[0].plan.uuid = 0;
  auto wrongUUIDSnapshot = source;
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      wrongUUIDSnapshot, approved, machines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, wrongUUID));
  auto collisionMachines = machines;
  collisionMachines[1].parameters[0].uuid = coldStates[0].plan.uuid;
  auto collisionSnapshot = source;
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      collisionSnapshot, approved, collisionMachines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, coldStates));

  // A failed in-place stateful rollout can have two retained predecessor
  // members and one live, non-client successor. It is not an ordinary
  // zero-client deployment: the existing materialized-recovery owner resumes
  // this exact 2+1 lineage only after its operation is durable.
  DeploymentPlan activeHot = statefulPlan(303, false);
  activeHot.config.versionID = 40;
  DeploymentPlan successorHot = activeHot;
  successorHot.config.versionID = 41;
  successorHot.stateful.allowUpdateInPlace = true;
  successorHot.config.containerBlobSHA256 = MothershipTidesMigration::text(std::string(64, 'a'));
  const uint64_t activeHotID = activeHot.config.deploymentID();
  const uint64_t successorHotID = successorHot.config.deploymentID();
  source.masterAuthority.deploymentPlans[activeHotID] = activeHot;
  source.masterAuthority.deploymentPlans[successorHotID] = successorHot;
  machines[1].parameters.push_back(parametersFor(activeHot, 0x5101, 2, 50, true));
  machines[1].observedCreatedAtMs.push_back(1791000000401LL);
  machines[2].parameters.push_back(parametersFor(activeHot, 0x5102, 3, 50, false));
  machines[2].observedCreatedAtMs.push_back(1791000000402LL);
  // The observed running successor shares nuc2 with one predecessor member;
  // the real resume owner deliberately permits this 2+1 placement.
  machines[1].parameters.push_back(parametersFor(successorHot, 0x5103, 2, 51, false));
  machines[1].observedCreatedAtMs.push_back(1791000000403LL);
  assert(machines[1].parameters.size() + machines[2].parameters.size() == 13);
  approved = source.masterAuthority.deploymentPlans;

  // These planner-only successor records were retained by a stopped Brain but
  // are absent from the sealed live inventory. The partial-handoff path must
  // remove only these planned ghosts, never a materialized unknown process.
  for (uint32_t index = 0; index < 2; ++index)
  {
    const uint32_t machine = 2 + index;
    ContainerParameters staleParameters = parametersFor(
        successorHot, 0x5201 + index, machine, uint8_t(52 + index), false);
    NeuronContainerBootstrap staleBootstrap = {};
    assert(prodigyBuildRetainedContainerBootstrap(
        successorHot, staleParameters, machine, source.brainConfig.datacenterFragment,
        1791000000410LL + index, staleBootstrap, &failure));
    BrainReplicatedContainerRuntimeState stale = {};
    stale.machineUUID = machine;
    stale.plan = staleBootstrap.plan;
    stale.plan.state = ContainerState::planned;
    stale.plan.runtimeReady = false;
    source.masterAuthority.containerRuntimeStates.push_back(std::move(stale));
  }
  ProdigyMaterializedStatefulRecoveryOperation partial = {};
  partial.operationID = "123e4567-e89b-42d3-a456-426614174099"_ctv;
  partial.activeDeploymentID = activeHotID;
  partial.successorDeploymentID = successorHotID;
  partial.successorBlobSHA256 = successorHot.config.containerBlobSHA256;
  partial.accepted = partial.started = true;
  partial.updatedAtMs = 1791000000420LL;

  auto withoutPartial = source;
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      withoutPartial, approved, machines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, coldStates));
  auto partialPrepared = source;
  assert(mothershipPrepareRetainedRecoverySnapshot(
      partialPrepared, approved, machines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, coldStates, &partial));
  assert(partialPrepared.masterAuthority.runtimeState.materializedStatefulRecoveryOperations.size() == 1);
  assert(partialPrepared.masterAuthority.runtimeState.materializedStatefulRecoveryOperations[0].operationID.equals(partial.operationID));
  uint32_t canonicalActive = 0, canonicalSuccessor = 0;
  for (const BrainReplicatedContainerRuntimeState& state : partialPrepared.masterAuthority.containerRuntimeStates)
  {
    if (state.plan.config.deploymentID() == activeHotID) ++canonicalActive;
    if (state.plan.config.deploymentID() == successorHotID) ++canonicalSuccessor;
    if (state.plan.config.deploymentID() == activeHotID || state.plan.config.deploymentID() == successorHotID)
      assert(state.plan.state == ContainerState::scheduled && state.plan.runtimeReady == false);
  }
  assert(canonicalActive == 2 && canonicalSuccessor == 1);

  // Re-entering against the already prepared authority is idempotent: the
  // exact operation is retained once and the canonical 2+1 inventory stays
  // unchanged.  prepareLocal clears the sealed envelope and rolls back its
  // staging generation before it calls the pure helper on an already-prepared
  // snapshot; mirror that boundary here rather than asking the helper to
  // accept a live coordinator envelope.
  auto normalizeAlreadyPreparedForPureHelper = [](ProdigyPersistentBrainSnapshot& snapshot) {
    snapshot.masterAuthority.runtimeState.updateSelf = {};
    assert(snapshot.masterAuthority.runtimeState.generation > 0);
    --snapshot.masterAuthority.runtimeState.generation;
  };
  auto alreadyPrepared = partialPrepared;
  normalizeAlreadyPreparedForPureHelper(alreadyPrepared);
  assert(mothershipPrepareRetainedRecoverySnapshot(
      alreadyPrepared, approved, machines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, coldStates, &partial));
  assert(alreadyPrepared.masterAuthority.runtimeState.materializedStatefulRecoveryOperations.size() == 1);
  auto duplicatedOperation = partialPrepared;
  normalizeAlreadyPreparedForPureHelper(duplicatedOperation);
  duplicatedOperation.masterAuthority.runtimeState.materializedStatefulRecoveryOperations.push_back(partial);
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      duplicatedOperation, approved, machines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, coldStates, &partial));

  auto completed = partial;
  completed.completed = true;
  auto completedSnapshot = source;
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      completedSnapshot, approved, machines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, coldStates, &completed));
  auto wrongBlob = partial;
  wrongBlob.successorBlobSHA256 = MothershipTidesMigration::text(std::string(64, 'b'));
  auto wrongBlobSnapshot = source;
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      wrongBlobSnapshot, approved, machines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, coldStates, &wrongBlob));
  auto wrongRoleMachines = machines;
  wrongRoleMachines[1].parameters.back().statefulMeshRoles.client =
      StatefulMeshRoles::forShardGroup(successorHot.stateful, successorHot.config.applicationID, 0).client;
  auto wrongRoleSnapshot = source;
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      wrongRoleSnapshot, approved, wrongRoleMachines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, coldStates, &partial));
  auto extraMachines = machines;
  extraMachines[1].parameters.push_back(parametersFor(successorHot, 0x5104, 2, 54, false));
  extraMachines[1].observedCreatedAtMs.push_back(1791000000404LL);
  auto extraSnapshot = source;
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      extraSnapshot, approved, extraMachines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, coldStates, &partial));
  auto collidingOperation = source;
  auto otherOperation = partial;
  otherOperation.operationID = "123e4567-e89b-42d3-a456-426614174098"_ctv;
  collidingOperation.masterAuthority.runtimeState.materializedStatefulRecoveryOperations.push_back(otherOperation);
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      collidingOperation, approved, machines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, coldStates, &partial));
  auto collidingRetry = source;
  ProdigyMaterializedStatefulRecoveryRetry retry = {};
  retry.operationID = partial.operationID;
  collidingRetry.masterAuthority.runtimeState.materializedStatefulRecoveryRetries.push_back(retry);
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      collidingRetry, approved, machines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, coldStates, &partial));
  auto materializedGhost = source;
  for (BrainReplicatedContainerRuntimeState& state : materializedGhost.masterAuthority.containerRuntimeStates)
  {
    if (state.plan.config.deploymentID() == successorHotID)
    {
      state.plan.state = ContainerState::healthy;
      break;
    }
  }
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      materializedGhost, approved, machines, bundle, &failure, {}, {}, 0, nullptr, false, true, 1, coldStates, &partial));
  auto nullFailureGhost = materializedGhost;
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      nullFailureGhost, approved, machines, bundle, nullptr, {}, {}, 0, nullptr, false, true, 1, coldStates, &partial));

  // RRF7 binds its original selected-state bytes rather than reserializing
  // unordered maps after decode. Exercise both private-copy persistence and
  // idempotent re-entry through the command-local prepare owner.
  using namespace MothershipRetainedRecovery;
  Request request = {};
  request.clusterUUID = source.brainConfig.clusterUUID;
  request.bundleSHA = bundle;
  request.plans = approved;
  request.machines = machines;
  ColdCanonicalSource coldSource = {};
  coldSource.sourceStatePath = "/root/nametag/.run/fixture/state.copy10"_ctv;
  coldSource.sourceSnapshotSHA256 = MothershipTidesMigration::text(std::string(64, 'e'));
  for (const BrainReplicatedContainerRuntimeState& cold : coldStates)
    coldSource.requestedContainerUUIDs.push_back(cold.plan.uuid);
  coldSource.states = coldStates;
  coldSource.selectedStatesSHA256 = coldCanonicalRuntimeStatesDigest(
      coldSource.states, &coldSource.serializedStates);
  const String rrf7 = encodeColdCanonicalSourceRequest(request, MothershipTidesMigration::Plan{}, 1, coldSource);
  Request decodedRequest = {};
  MothershipRetainedRecoveryMixedProof decodedProof = {};
  uint128_t decodedEmpty = 0;
  ColdCanonicalSource decodedCold = {};
  assert(decodeRequest(MothershipTidesMigration::str(rrf7), decodedRequest, &decodedProof,
      nullptr, &decodedEmpty, &decodedCold) && decodedEmpty == 1 &&
      coldCanonicalUUIDsEqual(decodedCold.requestedContainerUUIDs, coldSource.requestedContainerUUIDs) &&
      decodedCold.serializedStates == coldSource.serializedStates &&
      decodedCold.states.size() == coldStates.size() &&
      decodedCold.states[0].plan.subscriptions.size() ==
          coldStates[0].plan.subscriptions.size() &&
      decodedCold.states[0].plan.subscriptions.find(0x5100) !=
          decodedCold.states[0].plan.subscriptions.end() &&
      decodedCold.states[0].plan.subscriptions.find(0x5100)->second.nature ==
          SubscriptionNature::any);
  auto tamperedCold = coldSource;
  tamperedCold.serializedStates[tamperedCold.serializedStates.size() - 1] ^= 1;
  const String tampered = encodeColdCanonicalSourceRequest(request, MothershipTidesMigration::Plan{}, 1, tamperedCold);
  assert(!decodeRequest(MothershipTidesMigration::str(tampered), decodedRequest, &decodedProof,
      nullptr, &decodedEmpty, &decodedCold));

  const String rrf8 = encodePartialHandoffRequest(
      request, MothershipTidesMigration::Plan{}, 1, coldSource, partial);
  ProdigyMaterializedStatefulRecoveryOperation decodedPartial = {};
  assert(decodeRequest(MothershipTidesMigration::str(rrf8), decodedRequest, &decodedProof,
      nullptr, &decodedEmpty, &decodedCold, &decodedPartial) &&
      partialHandoffsEqual(decodedPartial, partial));
  // A prior sealed RRF8 may carry its own cold source. It is historical proof
  // for RRF9 and must not be rejected merely because it is not a plain request.
  assert(decodedEmpty != 0 && !decodedCold.states.empty() &&
      partialHandoffsEqual(decodedPartial, partial));
  decodedPartial = partial;
  assert(decodeRequest(MothershipTidesMigration::str(rrf7), decodedRequest, &decodedProof,
      nullptr, &decodedEmpty, &decodedCold, &decodedPartial) && decodedPartial.operationID.empty());

  Schema8PartialHandoffRequest malformedPartial = {};
  malformedPartial.coldRequest = rrf7;
  malformedPartial.operation = partial;
  malformedPartial.operation.completed = true;
  String malformedPartialBytes = {};
  BitseryEngine::serialize(malformedPartialBytes, malformedPartial);
  String malformedPartialFrame = {};
  malformedPartialFrame.append("RRF8", 4);
  malformedPartialFrame.append(malformedPartialBytes.data(), malformedPartialBytes.size());
  assert(!decodeRequest(MothershipTidesMigration::str(malformedPartialFrame), decodedRequest,
      &decodedProof, nullptr, &decodedEmpty, &decodedCold, &decodedPartial));
  malformedPartial.operation = partial;
  malformedPartial.coldRequest[0] = 'X';
  malformedPartialBytes.clear();
  BitseryEngine::serialize(malformedPartialBytes, malformedPartial);
  malformedPartialFrame.clear();
  malformedPartialFrame.append("RRF8", 4);
  malformedPartialFrame.append(malformedPartialBytes.data(), malformedPartialBytes.size());
  assert(!decodeRequest(MothershipTidesMigration::str(malformedPartialFrame), decodedRequest,
      &decodedProof, nullptr, &decodedEmpty, &decodedCold, &decodedPartial));

  // RRF9 is deliberately a normal canonical request plus the one stale,
  // non-client predecessor parameter record.  It cannot carry a cold source,
  // a second partial-handoff envelope, or an invented active deployment plan.
  MothershipRetainedRecoveryOrphanedStatefulPredecessor orphan = {};
  orphan.operation = partial;
  orphan.machineUUID = 3;
  orphan.priorRequestSHA256 = MothershipTidesMigration::text(std::string(64, 'a'));
  orphan.priorManifestSHA256 = MothershipTidesMigration::text(std::string(64, 'b'));
  orphan.rejectedCandidateSHA256 = MothershipTidesMigration::text(std::string(64, 'c'));
  orphan.successorBootstraps.push_back({2, "seed-successor-a"_ctv});
  orphan.successorBootstraps.push_back({3, "seed-successor-b"_ctv});
  for (const ContainerParameters& parameters : machines[2].parameters)
    if (parameters.deploymentID == activeHotID && parameters.statefulMeshRoles.client == 0)
      orphan.parameters = parameters;
  assert(mothershipRetainedRecoveryOrphanedStatefulPredecessorValid(orphan));
  auto duplicateSuccessorMachine = orphan;
  duplicateSuccessorMachine.successorBootstraps[1].machineUUID =
      duplicateSuccessorMachine.successorBootstraps[0].machineUUID;
  assert(!mothershipRetainedRecoveryOrphanedStatefulPredecessorValid(duplicateSuccessorMachine));
  assert(mothershipRetainedRecoveryOrphanedStatefulPredecessorMatchesSnapshot(partialPrepared, orphan, &failure));
  assert(mothershipRetainedRecoveryOrphanedStatefulPredecessorParametersMatchHistorical(
      orphan.parameters, orphan.parameters));
  auto wrongHistoricalParameters = orphan.parameters;
  ++wrongHistoricalParameters.storageMB;
  assert(!mothershipRetainedRecoveryOrphanedStatefulPredecessorParametersMatchHistorical(
      orphan.parameters, wrongHistoricalParameters));
  Request orphanRequest = request;
  const String rrf9 = encodeOrphanedStatefulPredecessorRequest(
      orphanRequest, MothershipTidesMigration::Plan{}, orphan);
  MothershipRetainedRecoveryOrphanedStatefulPredecessor decodedOrphan = {};
  assert(decodeRequest(MothershipTidesMigration::str(rrf9), decodedRequest, &decodedProof,
      nullptr, &decodedEmpty, &decodedCold, &decodedPartial, &decodedOrphan) &&
      decodedRequest.plans.find(activeHotID) != decodedRequest.plans.end() &&
      decodedRequest.plans.find(successorHotID) != decodedRequest.plans.end() &&
      decodedOrphan.machineUUID == orphan.machineUUID &&
      decodedOrphan.parameters.uuid == orphan.parameters.uuid &&
      mothershipRetainedRecoveryPartialHandoffEqual(decodedOrphan.operation, orphan.operation));
  auto malformedOrphan = orphan;
  malformedOrphan.parameters.statefulMeshRoles.client = 1;
  assert(!mothershipRetainedRecoveryOrphanedStatefulPredecessorValid(malformedOrphan));
  malformedOrphan = orphan;
  malformedOrphan.operation.completed = true;
  assert(!mothershipRetainedRecoveryOrphanedStatefulPredecessorValid(malformedOrphan));
  auto missingOrphanOperation = partialPrepared;
  missingOrphanOperation.masterAuthority.runtimeState.materializedStatefulRecoveryOperations.clear();
  assert(!mothershipRetainedRecoveryOrphanedStatefulPredecessorMatchesSnapshot(
      missingOrphanOperation, orphan, &failure));
  auto missingOrphanRuntime = partialPrepared;
  missingOrphanRuntime.masterAuthority.containerRuntimeStates.erase(
      std::remove_if(missingOrphanRuntime.masterAuthority.containerRuntimeStates.begin(),
          missingOrphanRuntime.masterAuthority.containerRuntimeStates.end(), [&](const auto& state) {
            return state.plan.uuid == orphan.parameters.uuid;
          }), missingOrphanRuntime.masterAuthority.containerRuntimeStates.end());
  assert(mothershipRetainedRecoveryOrphanedStatefulPredecessorMatchesSnapshot(
      missingOrphanRuntime, orphan, &failure));
  assert(mothershipRetainedRecoveryOrphanedStatefulPredecessorMatchesSnapshot(
      missingOrphanRuntime, orphan, &failure, true));
  auto wrongOrphanRuntime = partialPrepared;
  for (auto& state : wrongOrphanRuntime.masterAuthority.containerRuntimeStates)
    if (state.plan.uuid == orphan.parameters.uuid) state.machineUUID = 1;
  assert(!mothershipRetainedRecoveryOrphanedStatefulPredecessorMatchesSnapshot(
      wrongOrphanRuntime, orphan, &failure));
  wrongOrphanRuntime = partialPrepared;
  for (auto& state : wrongOrphanRuntime.masterAuthority.containerRuntimeStates)
    if (state.plan.uuid == orphan.parameters.uuid) ++state.plan.statefulTopology.workerCount;
  assert(!mothershipRetainedRecoveryOrphanedStatefulPredecessorMatchesSnapshot(
      wrongOrphanRuntime, orphan, &failure));

  const auto root = std::filesystem::current_path() / ".run" /
      ("retained-cold-canonical-" + std::to_string(::getpid()));
  std::filesystem::remove_all(root);
  std::filesystem::create_directories(root);

  // Exercise the command-local RRF9 projection. Its request retains the old
  // plan solely to compare every stopped copy before preparation erases it;
  // only the exact durable operation and sealed non-client predecessor permit
  // removing that stale runtime entry while successors remain canonical.
  auto orphanSnapshot = source;
  orphanSnapshot.masterAuthority.deploymentPlans.clear();
  // The seed can retain the culled predecessor plan and its current a6cb-like
  // runtime record; RRF9 retains that plan only as immutable proof.
  orphanSnapshot.masterAuthority.deploymentPlans[activeHotID] = activeHot;
  orphanSnapshot.masterAuthority.deploymentPlans[successorHotID] = successorHot;
  // A retained fleet is full inventory: machine 1 also needs its ordinary
  // canonical survivor while the orphan itself remains proof-only.
  DeploymentPlan orphanCompanion = {};
  for (const auto& [deploymentID, plan] : approved)
    if (!plan.isStateful) { orphanCompanion = plan; break; }
  assert(orphanCompanion.config.deploymentID() != 0);
  orphanSnapshot.masterAuthority.deploymentPlans[orphanCompanion.config.deploymentID()] = orphanCompanion;
  orphanSnapshot.masterAuthority.runtimeState = {};
  orphanSnapshot.masterAuthority.runtimeState.materializedStatefulRecoveryOperations.push_back(partial);
  orphanSnapshot.masterAuthority.containerRuntimeStates.clear();
  Vector<MothershipRetainedRecoveryMachineInput> orphanMachines = {};
  for (uint32_t index = 1; index <= 3; ++index) {
    MothershipRetainedRecoveryMachineInput machine = {};
    machine.machineUUID = index; machine.machineFragment = index;
    orphanMachines.push_back(std::move(machine));
  }
  const ContainerParameters orphanCompanionParameters =
      parametersFor(orphanCompanion, 0x5300, 1, 60, false);
  orphanMachines[0].parameters.push_back(orphanCompanionParameters);
  orphanMachines[0].observedCreatedAtMs.push_back(1791000000500LL);
  const ContainerParameters orphanSuccessorClient=parametersFor(successorHot, 0x5301, 2, 61, true);
  const ContainerParameters orphanSuccessorPeer=parametersFor(successorHot, 0x5302, 3, 62, false);
  orphanMachines[1].parameters.push_back(orphanSuccessorClient);
  orphanMachines[1].observedCreatedAtMs.push_back(1791000000501LL);
  orphanMachines[2].parameters.push_back(orphanSuccessorPeer);
  orphanMachines[2].observedCreatedAtMs.push_back(1791000000502LL);
  auto addOrphanSuccessorRuntime = [&](const ContainerParameters& parameters, uint32_t machine, int64_t created) {
    NeuronContainerBootstrap bootstrap = {};
    assert(prodigyBuildRetainedContainerBootstrap(successorHot, parameters, machine,
        orphanSnapshot.brainConfig.datacenterFragment, created, bootstrap, &failure));
    BrainReplicatedContainerRuntimeState runtime = {};
    runtime.machineUUID = machine; runtime.plan = bootstrap.plan;
    runtime.plan.state = ContainerState::healthy; runtime.plan.runtimeReady = true;
    orphanSnapshot.masterAuthority.containerRuntimeStates.push_back(std::move(runtime));
  };
  addOrphanSuccessorRuntime(orphanSuccessorClient, 2, 1791000000501LL);
  addOrphanSuccessorRuntime(orphanSuccessorPeer, 3, 1791000000502LL);
  // Followers may retain stale planned/scheduled lineage rows. They are
  // removed only because they are non-ready; a healthy unknown row is denied.
  auto addStaleLineageRuntime = [&](const DeploymentPlan& plan,
                                    const ContainerParameters& parameters,
                                    uint32_t machine, int64_t created) {
    NeuronContainerBootstrap bootstrap = {};
    assert(prodigyBuildRetainedContainerBootstrap(plan, parameters, machine,
        orphanSnapshot.brainConfig.datacenterFragment, created, bootstrap, &failure));
    BrainReplicatedContainerRuntimeState runtime = {};
    runtime.machineUUID = machine; runtime.plan = bootstrap.plan;
    runtime.plan.state = ContainerState::scheduled; runtime.plan.runtimeReady = false;
    orphanSnapshot.masterAuthority.containerRuntimeStates.push_back(std::move(runtime));
  };
  addStaleLineageRuntime(activeHot, orphan.parameters, 3, 1791000000503LL);
  const ContainerParameters staleOldClient = parametersFor(activeHot, 0x5303, 1, 63, true);
  addStaleLineageRuntime(activeHot, staleOldClient, 1, 1791000000504LL);
  const ContainerParameters staleSuccessor = parametersFor(successorHot, 0x5304, 1, 64, false);
  addStaleLineageRuntime(successorHot, staleSuccessor, 1, 1791000000505LL);
  orphan.successorBootstraps.clear();
  for (const BrainReplicatedContainerRuntimeState& state : orphanSnapshot.masterAuthority.containerRuntimeStates) {
    if (state.plan.config.deploymentID() != successorHotID ||
        state.plan.state != ContainerState::healthy || !state.plan.runtimeReady) continue;
    NeuronContainerBootstrap bootstrap = {};
    bootstrap.plan = state.plan;
    bootstrap.metricPolicy = prodigyNeuronMetricPolicyForDeployment(successorHot);
    String serialized = {}; BitseryEngine::serialize(serialized, bootstrap);
    orphan.successorBootstraps.push_back({state.machineUUID, std::move(serialized)});
  }
  Request localOrphanRequest = {};
  localOrphanRequest.clusterUUID = orphanSnapshot.brainConfig.clusterUUID;
  localOrphanRequest.bundleSHA = bundle;
  localOrphanRequest.plans = orphanSnapshot.masterAuthority.deploymentPlans;
  localOrphanRequest.machines = orphanMachines;
  const String localRrf9 = encodeOrphanedStatefulPredecessorRequest(
      localOrphanRequest, MothershipTidesMigration::Plan{}, orphan);
  auto orphanWitnessSnapshot = orphanSnapshot;
  orphanWitnessSnapshot.masterAuthority.deploymentPlans.erase(activeHotID);
  orphanWitnessSnapshot.masterAuthority.containerRuntimeStates.clear();
  assert(mothershipPrepareRetainedRecoverySnapshot(
      orphanWitnessSnapshot, localOrphanRequest.plans, localOrphanRequest.machines, bundle, &failure));
  const auto orphanRoot = root / "orphaned-stateful-predecessor";
  std::filesystem::create_directories(orphanRoot);
  const auto orphanStatePath = (orphanRoot / "state.new10").string();
  const auto orphanRequestPath = (orphanRoot / "request").string();
  {
    ProdigyPersistentStateStore store(MothershipTidesMigration::text(orphanStatePath));
    assert(store.saveBrainSnapshot(orphanSnapshot, &failure));
  }
  std::filesystem::create_directories(orphanStatePath + ".secrets");
  MothershipTidesMigration::durable(orphanRequestPath, localRrf9);
  WitnessSet orphanWitnesses = {};
  orphanWitnesses.requestSHA = MothershipTidesMigration::text(MothershipTidesMigration::digest(orphanRequestPath));
  orphanWitnesses.witnesses = orphanWitnessSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
  String orphanWitnessBytes = {};
  BitseryEngine::serialize(orphanWitnessBytes, orphanWitnesses);
  MothershipTidesMigration::durable(orphanRequestPath + ".witnesses", orphanWitnessBytes);
  // A follower may retain the proof-only plan, but it must be byte-for-byte
  // the same deployment authority sealed in the request.
  auto mismatchedActivePlan = orphanSnapshot;
  mismatchedActivePlan.masterAuthority.deploymentPlans[activeHotID].stateful.allMasters = true;
  const auto mismatchedStatePath = (orphanRoot / "mismatched-active-plan" / "state.new10").string();
  std::filesystem::create_directories(std::filesystem::path(mismatchedStatePath).parent_path());
  {
    ProdigyPersistentStateStore store(MothershipTidesMigration::text(mismatchedStatePath));
    assert(store.saveBrainSnapshot(mismatchedActivePlan, &failure));
  }
  std::filesystem::create_directories(mismatchedStatePath + ".secrets");
  assert(!prepareLocal(orphanRequestPath.c_str(), mismatchedStatePath.c_str(), false, &failure));
  assert(failure == "orphaned stateful predecessor retained active plan differs from sealed authority"_ctv);
  assert(prepareLocal(orphanRequestPath.c_str(), orphanStatePath.c_str(), false, &failure));
  assert(prepareLocal(orphanRequestPath.c_str(), orphanStatePath.c_str(), true, &failure));
  ProdigyPersistentBrainSnapshot orphanAfter = {};
  loadSnapshot(orphanStatePath, orphanAfter);
  assert(orphanAfter.masterAuthority.runtimeState.materializedStatefulRecoveryOperations.size() == 1 &&
      mothershipRetainedRecoveryPartialHandoffEqual(
          orphanAfter.masterAuthority.runtimeState.materializedStatefulRecoveryOperations[0], partial));
  uint32_t retainedSuccessors = 0;
  for (const BrainReplicatedContainerRuntimeState& state : orphanAfter.masterAuthority.containerRuntimeStates) {
    assert(state.plan.uuid != orphan.parameters.uuid && state.plan.uuid != staleOldClient.uuid &&
        state.plan.uuid != staleSuccessor.uuid);
    if (state.plan.config.deploymentID() == successorHotID) {
      ++retainedSuccessors;
      assert(state.plan.state == ContainerState::scheduled && !state.plan.runtimeReady);
    }
  }
  assert(retainedSuccessors == 2 && orphanAfter.masterAuthority.deploymentPlans.find(activeHotID) ==
      orphanAfter.masterAuthority.deploymentPlans.end());

  // An unknown healthy lineage row is not projection material and must abort
  // preparation before it changes the copied authority.
  auto unknownHealthySnapshot = orphanSnapshot;
  // Mutate the unique stale successor rather than append a duplicate UUID;
  // snapshot-side credential validation must remain valid to reach RRF9.
  auto& unknownHealthy = unknownHealthySnapshot.masterAuthority.containerRuntimeStates.back();
  unknownHealthy.plan.state = ContainerState::healthy;
  unknownHealthy.plan.runtimeReady = true;
  const auto unknownStatePath = (orphanRoot / "unknown-healthy" / "state.new10").string();
  std::filesystem::create_directories(std::filesystem::path(unknownStatePath).parent_path());
  {
    ProdigyPersistentStateStore store(MothershipTidesMigration::text(unknownStatePath));
    assert(store.saveBrainSnapshot(unknownHealthySnapshot, &failure));
  }
  std::filesystem::create_directories(unknownStatePath + ".secrets");
  assert(!prepareLocal(orphanRequestPath.c_str(), unknownStatePath.c_str(), false, &failure));
  assert(failure == "orphaned stateful predecessor retains an unknown healthy or ready lineage record"_ctv);
  std::filesystem::remove_all(orphanRoot);
  const auto statePath = (root / "state.new10").string();
  const auto requestPath = (root / "request").string();
  {
    ProdigyPersistentStateStore store(MothershipTidesMigration::text(statePath));
    assert(store.saveBrainSnapshot(source, &failure));
  }
  std::filesystem::create_directories(statePath + ".secrets");
  const String aggregateBefore = coldCanonicalStateAggregateDigest(statePath);
  const auto inspectionRoot = root / "inspection";
  std::filesystem::create_directories(inspectionRoot);
  const auto inspectionState = (inspectionRoot / "state.new10").string();
  std::filesystem::copy(statePath, inspectionState, std::filesystem::copy_options::recursive);
  std::filesystem::copy(statePath + ".secrets", inspectionState + ".secrets",
      std::filesystem::copy_options::recursive);
  assert(coldCanonicalStateAggregateDigest(inspectionState) == aggregateBefore);
  ProdigyPersistentBrainSnapshot readOnlySource = {};
  loadSnapshot(inspectionState, readOnlySource);
  std::filesystem::remove_all(inspectionRoot);
  assert(coldCanonicalStateAggregateDigest(statePath) == aggregateBefore);
  MothershipTidesMigration::durable(requestPath, rrf8);
  WitnessSet sealed = {};
  sealed.requestSHA = MothershipTidesMigration::text(MothershipTidesMigration::digest(requestPath));
  sealed.witnesses = partialPrepared.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
  String witnessBytes = {};
  BitseryEngine::serialize(witnessBytes, sealed);
  MothershipTidesMigration::durable(requestPath + ".witnesses", witnessBytes);
  assert(prepareLocal(requestPath.c_str(), statePath.c_str(), false, &failure));
  ProdigyPersistentBrainSnapshot persisted = {};
  loadSnapshot(statePath, persisted);
  assert(prodigyPersistentBrainSnapshotsEqual(partialPrepared, persisted));
  assert(prepareLocal(requestPath.c_str(), statePath.c_str(), false, &failure));
  assert(prepareLocal(requestPath.c_str(), statePath.c_str(), true, &failure));
  std::filesystem::remove_all(root);
}

static DeploymentPlan retainedRecoveryCidFixturePlan(void)
{
  DeploymentPlan plan = {};
  plan.config.type = ApplicationType::stateless;
  plan.config.applicationID = 77;
  plan.config.versionID = 9;
  plan.config.memoryMB = 256;
  plan.config.storageMB = 128;
  plan.config.nLogicalCores = 1;
  Wormhole wormhole = {};
  wormhole.name = "retained-cid-runtime"_ctv;
  wormhole.externalPort = 443;
  wormhole.containerPort = 8443;
  wormhole.layer4 = 17;
  wormhole.isQuic = true;
  wormhole.hasQuicCidKeyState = true;
  wormhole.quicCidKeyState.rotationHours = 24;
  wormhole.quicCidKeyState.activeKeyIndex = 0;
  wormhole.quicCidKeyState.rotatedAtMs = 1790040000000LL;
  wormhole.quicCidKeyState.keyMaterialByIndex[0] = uint128_t(0x101);
  wormhole.quicCidKeyState.keyMaterialByIndex[1] = uint128_t(0x202);
  plan.wormholes.push_back(std::move(wormhole));
  return plan;
}

static bool retainedRecoveryAllowsRuntimeCidDrift(void)
{
  const DeploymentPlan frozen = retainedRecoveryCidFixturePlan();
  auto local = frozen;
  auto& cid = local.wormholes[0].quicCidKeyState;
  cid.activeKeyIndex = 1;
  cid.rotatedAtMs += 3600 * 1000;
  cid.keyMaterialByIndex[0] = uint128_t(0x303);
  cid.keyMaterialByIndex[1] = uint128_t(0x404);
  return mothershipRetainedRecoveryPlansEqual(local, frozen);
}

static void assertRetainedRecoveryRuntimeCidDriftPreservesLocalPlan(
    const ProdigyPersistentBrainSnapshot& base,
    const bytell_hash_map<uint64_t, DeploymentPlan>& approvedPlans,
    const Vector<MothershipRetainedRecoveryMachineInput>& machines,
    const String& bundleSHA256,
    uint64_t deploymentID)
{
  auto approved = approvedPlans;
  DeploymentPlan frozen = retainedRecoveryCidFixturePlan();
  assert(frozen.config.deploymentID() == deploymentID);
  approved.insert_or_assign(deploymentID, frozen);
  auto retainedMachines = machines;
  for (auto& machine : retainedMachines)
    for (auto& parameters : machine.parameters)
      parameters.wormholes = frozen.wormholes;

  DeploymentPlan local = frozen;
  auto& localCid = local.wormholes[0].quicCidKeyState;
  localCid.activeKeyIndex = 1;
  localCid.rotatedAtMs += 3600 * 1000;
  localCid.keyMaterialByIndex[0] = uint128_t(0x303);
  localCid.keyMaterialByIndex[1] = uint128_t(0x404);

  auto recovered = base;
  recovered.masterAuthority.deploymentPlans.insert_or_assign(deploymentID, local);
  String failure = {};
  assert(mothershipPrepareRetainedRecoverySnapshot(recovered, approved, retainedMachines, bundleSHA256, &failure));
  const auto retained = recovered.masterAuthority.deploymentPlans.find(deploymentID);
  assert(retained != recovered.masterAuthority.deploymentPlans.end());
  assert(prodigyPersistentSerializedEqual(retained->second, local));
  const auto& retainedCid = retained->second.wormholes[0].quicCidKeyState;
  assert(retainedCid.activeKeyIndex == localCid.activeKeyIndex &&
         retainedCid.rotatedAtMs == localCid.rotatedAtMs &&
         retainedCid.keyMaterialByIndex[0] == localCid.keyMaterialByIndex[0] &&
         retainedCid.keyMaterialByIndex[1] == localCid.keyMaterialByIndex[1]);

  auto recoveredAgain = base;
  recoveredAgain.masterAuthority.deploymentPlans.insert_or_assign(deploymentID, frozen);
  assert(mothershipPrepareRetainedRecoverySnapshot(recoveredAgain, approved, retainedMachines, bundleSHA256, &failure));
  assert(MothershipRetainedRecovery::witnessesEquivalent(
      recovered.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses,
      recoveredAgain.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses));
  for (const auto& witness : recovered.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses)
  {
    assert(!witness.containerBootstraps.empty());
    for (const auto& bytes : witness.containerBootstraps)
    {
      NeuronContainerBootstrap bootstrap;
      assert(BitseryEngine::deserializeSafe(bytes, bootstrap));
      assert(prodigyPersistentSerializedEqual(bootstrap.plan.wormholes, frozen.wormholes));
    }
  }

  MothershipRetainedRecovery::WitnessSet sealed = {};
  sealed.witnesses = recovered.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
  String encoded = {};
  BitseryEngine::serialize(encoded, sealed);
  MothershipRetainedRecovery::WitnessSet decoded = {};
  assert(BitseryEngine::deserializeSafe(encoded, decoded));
  assert(MothershipRetainedRecovery::witnessesEquivalent(sealed.witnesses, decoded.witnesses));

  struct DeclarationMutation {
    void (*apply)(DeploymentPlan&);
  };
  const DeclarationMutation mutations[] = {
    {[](DeploymentPlan& plan) { ++plan.wormholes[0].quicCidKeyState.rotationHours; }},
    {[](DeploymentPlan& plan) { ++plan.wormholes[0].externalPort; }},
    {[](DeploymentPlan& plan) { plan.config.containerBlobSHA256.assign(std::string(64, 'a').c_str()); }},
    {[](DeploymentPlan& plan) { ++plan.config.memoryMB; }},
  };
  for (const DeclarationMutation& mutation : mutations)
  {
    auto incompatible = base;
    incompatible.masterAuthority.deploymentPlans.insert_or_assign(deploymentID, local);
    mutation.apply(incompatible.masterAuthority.deploymentPlans.find(deploymentID)->second);
    assert(!mothershipPrepareRetainedRecoverySnapshot(incompatible, approved, retainedMachines, bundleSHA256, &failure));
  }
}

static int retainedPrecheckpointFailures(void)
{
  using namespace MothershipRetainedRecovery;
  int failed = 0;
  auto expect = [&](bool value, const char *label) {
    if (!value) { std::fprintf(stderr, "FAIL: %s\n", label); ++failed; }
  };

  ProdigyPersistentBrainSnapshot prior = {};
  prior.brainConfig.clusterUUID = 0xA551;
  prior.brainConfig.datacenterFragment = 7;
  DeploymentPlan frozen = retainedRecoveryCidFixturePlan();
  const uint64_t deploymentID = frozen.config.deploymentID();
  DeploymentPlan local = frozen;
  local.wormholes[0].quicCidKeyState.activeKeyIndex = 1;
  local.wormholes[0].quicCidKeyState.rotatedAtMs += 3600 * 1000;
  local.wormholes[0].quicCidKeyState.keyMaterialByIndex[0] = uint128_t(0x303);
  local.wormholes[0].quicCidKeyState.keyMaterialByIndex[1] = uint128_t(0x404);
  prior.masterAuthority.deploymentPlans.insert_or_assign(deploymentID, local);
  ApiCredential credential = {};
  credential.name.assign("precheckpoint-credential"_ctv);
  credential.metadata.insert_or_assign("scope"_ctv, "retained"_ctv);
  ApplicationApiCredentialSet credentialSet = {};
  credentialSet.applicationID = frozen.config.applicationID;
  credentialSet.credentials.push_back(credential);
  prior.masterAuthority.apiCredentialSetsByApp.insert_or_assign(credentialSet.applicationID, credentialSet);

  Request request = {};
  request.clusterUUID = prior.brainConfig.clusterUUID;
  String priorBlob = "retained-precheckpoint-installed-bundle"_ctv;
  String currentBlob = "retained-precheckpoint-successor-bundle"_ctv;
  String previousDigest = {}, currentDigest = {};
  expect(prodigyComputeSHA256Hex(priorBlob, previousDigest), "precheckpoint_prior_digest_constructs");
  expect(prodigyComputeSHA256Hex(currentBlob, currentDigest), "precheckpoint_current_digest_constructs");
  request.bundleSHA = currentDigest;
  request.plans.insert_or_assign(deploymentID, frozen);
  for (uint32_t index = 1; index <= 3; ++index)
  {
    ClusterMachine topologyMachine = {};
    topologyMachine.uuid = index;
    prior.topology.machines.push_back(topologyMachine);
    MothershipRetainedRecoveryMachineInput machine = {};
    machine.machineUUID = index;
    machine.machineFragment = index;
    ContainerParameters parameters = {};
    parameters.uuid = 0xB000 + index;
    parameters.deploymentID = deploymentID;
    parameters.memoryMB = frozen.config.memoryMB;
    parameters.storageMB = frozen.config.storageMB;
    parameters.nLogicalCores = applicationSharedCPUCoreHint(frozen.config);
    parameters.cpuMode = frozen.config.cpuMode;
    parameters.requestedCPUMillis = applicationRequestedCPUMillis(frozen.config);
    parameters.wormholes = frozen.wormholes;
    parameters.private6.network.is6 = true;
    parameters.private6.cidr = 128;
    std::memcpy(parameters.private6.network.v6, container_network_subnet6.value, 11);
    parameters.private6.network.v6[11] = 7;
    parameters.private6.network.v6[14] = index;
    parameters.private6.network.v6[15] = 1;
    machine.parameters.push_back(std::move(parameters));
    machine.observedCreatedAtMs.push_back(1790350000000LL + index);
    request.machines.push_back(std::move(machine));
  }

  auto& update = prior.masterAuthority.runtimeState.updateSelf;
  update.state = uint8_t(ProdigyPersistentUpdateSelfState::Phase::waitingForBundleEchos);
  update.expectedEchos = 2;
  update.bundleBlob = priorBlob;
  update.workerExpectedBundleSHA256 = previousDigest;
  for (const auto& machine : prior.topology.machines)
  {
    ProdigyPersistentUpdateSelfMachineRecoveryWitness witness = {};
    witness.machineUUID = machine.uuid;
    update.machineRecoveryWitnesses.push_back(std::move(witness));
  }

  // The predecessor is explicitly sealed and no echo, handoff, worker or
  // local execution evidence exists.  This is the live retained-12 shape.
  expect(mothershipRetainedRecoveryCanReplaceUpdate(prior, currentDigest, previousDigest),
         "precheckpoint_prior_predicate_accepts_sealed_previous");
  expect(!mothershipRetainedRecoveryCanReplaceUpdate(prior, currentDigest, {}),
         "precheckpoint_prior_predicate_rejects_absent_previous");
  auto currentCandidate = prior;
  currentCandidate.masterAuthority.runtimeState.updateSelf.bundleBlob = currentBlob;
  currentCandidate.masterAuthority.runtimeState.updateSelf.workerExpectedBundleSHA256 = currentDigest;
  expect(mothershipRetainedRecoveryCanReplaceUpdate(currentCandidate, currentDigest, {}),
         "precheckpoint_current_candidate_keeps_empty_previous_compatibility");
  String wrongPrevious = text(std::string(64, 'd'));
  expect(!mothershipRetainedRecoveryCanReplaceUpdate(prior, currentDigest, wrongPrevious),
         "precheckpoint_prior_predicate_rejects_wrong_previous");
  auto wrongPayload = prior;
  wrongPayload.masterAuthority.runtimeState.updateSelf.bundleBlob.assign("other-precheckpoint-bundle"_ctv);
  expect(!mothershipRetainedRecoveryCanReplaceUpdate(wrongPayload, currentDigest, previousDigest),
         "precheckpoint_prior_predicate_rejects_wrong_blob");
  auto wrongDigest = prior;
  wrongDigest.masterAuthority.runtimeState.updateSelf.workerExpectedBundleSHA256 = currentDigest;
  expect(!mothershipRetainedRecoveryCanReplaceUpdate(wrongDigest, currentDigest, previousDigest),
         "precheckpoint_prior_predicate_rejects_prior_blob_successor_digest");
  auto wrongPair = prior;
  wrongPair.masterAuthority.runtimeState.updateSelf.bundleBlob = currentBlob;
  expect(!mothershipRetainedRecoveryCanReplaceUpdate(wrongPair, currentDigest, previousDigest),
         "precheckpoint_prior_predicate_rejects_successor_blob_prior_digest");

  struct UnsafeMutation { const char *name; void (*apply)(ProdigyPersistentUpdateSelfState&); };
  const UnsafeMutation unsafe[] = {
    {"phase", [](auto& value) { value.state = uint8_t(ProdigyPersistentUpdateSelfState::Phase::waitingForFollowerReboots); }},
    {"missing-expected-echo", [](auto& value) { value.expectedEchos = 0; }},
    {"unknown-echo", [](auto& value) { value.bundleEchos = 1; value.bundleEchoPeerKeys.push_back(99); }},
    {"topology-echo-count", [](auto& value) { value.expectedEchos = 3; }},
    {"relinquish-echo", [](auto& value) { value.relinquishEchos = 1; }},
    {"planned-master", [](auto& value) { value.plannedMasterPeerKey = 1; }},
    {"designated-master", [](auto& value) { value.pendingDesignatedMasterPeerKey = 1; }},
    {"staged-only", [](auto& value) { value.useStagedBundleOnly = true; }},
    {"relinquish-key", [](auto& value) { value.relinquishEchoPeerKeys.push_back(1); }},
    {"follower-boot", [](auto& value) { value.followerBootNsByPeerKey.push_back({.peerKey = 1, .bootNs = 1}); }},
    {"follower-reboot", [](auto& value) { value.followerRebootedPeerKeys.push_back(1); }},
    {"worker-failure", [](auto& value) { value.workerFailure.assign("failed"_ctv); }},
    {"worker-machine", [](auto& value) { value.workerMachineUUIDs.push_back(1); }},
    {"worker-staged", [](auto& value) { value.workerStagedMachineUUIDs.push_back(1); }},
    {"worker-transition", [](auto& value) { value.workerTransitionIssuedMachineUUIDs.push_back(1); }},
    {"worker-reboot", [](auto& value) { value.workerRebootedMachineUUIDs.push_back(1); }},
    {"worker-state-upload", [](auto& value) { value.workerStateUploadedMachineUUIDs.push_back(1); }},
    {"local-machine", [](auto& value) { value.localMachineUUID = 1; }},
    {"local-bundle", [](auto& value) { value.localBundleRegistered = true; }},
    {"local-bootstrap", [](auto& value) { value.localContainerBootstraps.push_back("bootstrap"_ctv); }},
  };
  for (const UnsafeMutation& mutation : unsafe)
  {
    auto unsafePrior = prior;
    mutation.apply(unsafePrior.masterAuthority.runtimeState.updateSelf);
    const std::string label = std::string("precheckpoint_prior_predicate_rejects-") + mutation.name;
    expect(!mothershipRetainedRecoveryCanReplaceUpdate(unsafePrior, currentDigest, previousDigest), label.c_str());
  }
  static constexpr const char *witnessMutationNames[] = {"missing", "duplicate", "unknown", "registered"};
  for (uint32_t mutation = 0; mutation < 4; ++mutation)
  {
    auto unsafePrior = prior;
    auto& witnesses = unsafePrior.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
    if (mutation == 0) witnesses.clear();
    if (mutation == 1) witnesses.push_back(witnesses[0]);
    if (mutation == 2) witnesses[0].machineUUID = 0xDEAD;
    if (mutation == 3) witnesses[0].bundleRegistered = true;
    const std::string label = std::string("precheckpoint_prior_predicate_rejects-witness-") + witnessMutationNames[mutation];
    expect(!mothershipRetainedRecoveryCanReplaceUpdate(unsafePrior, currentDigest, previousDigest), label.c_str());
  }

  String failure = {};
  auto prepared = prior;
  expect(mothershipPrepareRetainedRecoverySnapshot(
      prepared, request.plans, request.machines, currentDigest, &failure, previousDigest),
      "precheckpoint_prior_snapshot_preparation_accepts_sealed_previous");
  expect(prepared.masterAuthority.runtimeState.generation ==
         prior.masterAuthority.runtimeState.generation + 1 &&
      mothershipRetainedRecoveryEnvelopeMatches(
          prepared.masterAuthority.runtimeState.updateSelf, currentDigest),
      "precheckpoint_prior_preparation_advances_generation_and_envelopes");
  const auto preparedPlan = prepared.masterAuthority.deploymentPlans.find(deploymentID);
  const auto preparedCredentials = prepared.masterAuthority.apiCredentialSetsByApp.find(credentialSet.applicationID);
  const auto priorCredentials = prior.masterAuthority.apiCredentialSetsByApp.find(credentialSet.applicationID);
  expect(preparedPlan != prepared.masterAuthority.deploymentPlans.end() &&
      preparedPlan->second.wormholes[0].quicCidKeyState.activeKeyIndex == 1 &&
      preparedCredentials != prepared.masterAuthority.apiCredentialSetsByApp.end() &&
      priorCredentials != prior.masterAuthority.apiCredentialSetsByApp.end() &&
      prodigyPersistentSerializedEqual(preparedCredentials->second, priorCredentials->second),
      "precheckpoint_prior_preparation_preserves_local_cid_and_credentials");

  const auto root = std::filesystem::current_path() / ".run" /
      ("retained-precheckpoint-" + std::to_string(::getpid()));
  std::filesystem::remove_all(root);
  std::filesystem::create_directories(root);
  const auto statePath = (root / "state.new10").string();
  const auto requestPath = (root / "request").string();
  {
    ProdigyPersistentStateStore store(MothershipTidesMigration::text(statePath));
    expect(store.saveBrainSnapshot(prior, &failure), "precheckpoint_private_seed_persists");
  }
  std::filesystem::create_directories(statePath + ".secrets");
  String encoded = {};
  BitseryEngine::serialize(encoded, request);
  MothershipTidesMigration::durable(requestPath, encoded);
  WitnessSet sealed = {};
  sealed.requestSHA = MothershipTidesMigration::text(MothershipTidesMigration::digest(requestPath));
  sealed.witnesses = prepared.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
  BitseryEngine::serialize(encoded, sealed);
  MothershipTidesMigration::durable(requestPath + ".witnesses", encoded);
  expect(prepareLocal(requestPath.c_str(), statePath.c_str(), false, &failure, previousDigest),
         "precheckpoint_private_prepare_accepts_sealed_previous");
  ProdigyPersistentBrainSnapshot readback = {};
  loadSnapshot(statePath, readback);
  expect(prodigyPersistentBrainSnapshotsEqual(readback, prepared),
         "precheckpoint_private_prepare_exact_readback");
  expect(prepareLocal(requestPath.c_str(), statePath.c_str(), false, &failure, previousDigest),
         "precheckpoint_private_prepare_idempotent_retry");
  expect(prepareLocal(requestPath.c_str(), statePath.c_str(), true, &failure, previousDigest),
         "precheckpoint_private_prepare_idempotent_verify");
  std::filesystem::remove_all(root);
  return failed;
}

static void assertSchema4ConflictingClientRetirement(void)
{
  const uint128_t formatterTarget=(uint128_t(0x4fbeb7f9454a068aULL)<<64)|uint128_t(0x1eea562809529ff6ULL);
  String targetArgument={};targetArgument.snprintf<"{itoh}"_ctv>(formatterTarget);
  assert(MothershipTidesMigration::uuid(MothershipTidesMigration::str(targetArgument))==formatterTarget);
  bool duplicatePrefixRejected=false;
  try { (void)MothershipTidesMigration::uuid("0x"+MothershipTidesMigration::str(targetArgument)); }
  catch(const std::exception&) { duplicatePrefixRejected=true; }
  assert(duplicatePrefixRejected);
  const String current=MothershipTidesMigration::text(std::string(64,'a')),
      previous=MothershipTidesMigration::text(std::string(64,'b')),
      interrupted=MothershipTidesMigration::text(std::string(64,'c'));
  DeploymentPlan plan={}; plan.config.type=ApplicationType::stateful; plan.config.applicationID=91; plan.config.versionID=7;
  plan.config.memoryMB=128; plan.config.storageMB=64; plan.config.nLogicalCores=1; plan.isStateful=true;
  plan.stateful.clientPrefix=0x1100000000000000ULL; plan.stateful.siblingPrefix=0x1200000000000000ULL;
  plan.stateful.cousinPrefix=0x1300000000000000ULL; plan.stateful.seedingPrefix=0x1400000000000000ULL;
  plan.stateful.shardingPrefix=0x1500000000000000ULL; plan.stateful.neverShard=true; plan.stateful.allMasters=false;
  const uint64_t deploymentID=plan.config.deploymentID(); ProdigyPersistentBrainSnapshot snapshot={};
  snapshot.brainConfig.clusterUUID=0x71; snapshot.brainConfig.datacenterFragment=7; snapshot.masterAuthority.deploymentPlans[deploymentID]=plan;
  DeploymentPlan companion={}; companion.config.type=ApplicationType::stateless; companion.config.applicationID=92; companion.config.versionID=7;
  companion.config.memoryMB=128; companion.config.storageMB=64; companion.config.nLogicalCores=1;
  const uint64_t companionDeploymentID=companion.config.deploymentID(); snapshot.masterAuthority.deploymentPlans[companionDeploymentID]=companion;
  bytell_hash_map<uint64_t,DeploymentPlan> approved=snapshot.masterAuthority.deploymentPlans;
  Vector<MothershipRetainedRecoveryMachineInput> machines={};
  for(uint32_t index=0;index<3;++index) {
    ClusterMachine clusterMachine={}; clusterMachine.uuid=index+1; snapshot.topology.machines.push_back(clusterMachine);
    MothershipRetainedRecoveryMachineInput machine={}; machine.machineUUID=index+1; machine.machineFragment=index+1;
    ContainerParameters p={}; p.uuid=0x700+index; p.deploymentID=deploymentID; p.memoryMB=128;p.storageMB=64;
    p.nLogicalCores=applicationSharedCPUCoreHint(plan.config);p.cpuMode=plan.config.cpuMode;p.requestedCPUMillis=applicationRequestedCPUMillis(plan.config);
    p.private6.network.is6=true;p.private6.cidr=128;std::memcpy(p.private6.network.v6,container_network_subnet6.value,11);
    p.private6.network.v6[11]=7;p.private6.network.v6[14]=index+1;p.private6.network.v6[15]=1;
    p.statefulMeshRoles=StatefulMeshRoles::forShardGroup(plan.stateful,plan.config.applicationID,0);
    p.statefulMeshRoles.cousin=0;p.statefulMeshRoles.sharding=0;p.statefulMeshRoles.topologyBridge=0;
    if(index==2) p.statefulMeshRoles.client=0;
    p.statefulTopology.shardGroup=0;p.statefulTopology.workerCount=1;p.statefulTopology.topologyEpoch=1;p.statefulTopology.sourceEpoch=1;p.statefulTopology.targetEpoch=1;p.statefulTopology.servingMode=StatefulTopologyServingMode::serve;
    p.advertisesOnPorts[p.statefulMeshRoles.sibling]=12001;p.advertisesOnPorts[p.statefulMeshRoles.seeding]=12002;
    if(p.statefulMeshRoles.client) p.advertisesOnPorts[p.statefulMeshRoles.client]=12003;
    machine.parameters.push_back(p);machine.observedCreatedAtMs.push_back(1790040000000LL+index);
    if(index==0) {
      ContainerParameters extra=p; extra.uuid=0x799; extra.deploymentID=companionDeploymentID;
      extra.cpuMode=companion.config.cpuMode;extra.requestedCPUMillis=applicationRequestedCPUMillis(companion.config);
      extra.statefulMeshRoles={};extra.statefulTopology={};extra.advertisesOnPorts.clear();extra.private6.network.v6[15]=2;
      machine.parameters.push_back(std::move(extra));machine.observedCreatedAtMs.push_back(1790040000100LL);
    }
    machines.push_back(std::move(machine));
  }
  const MothershipRetainedRecoveryMixedProof proof={4,3,1,0x700}; const Vector<uint128_t> successor={3}; String failure;
  BrainReplicatedContainerRuntimeState targetRuntime={};targetRuntime.machineUUID=1;targetRuntime.plan.uuid=proof.staleExcludedContainerUUID;
  snapshot.masterAuthority.containerRuntimeStates.push_back(targetRuntime);
  // Build the exact full witness as the dormant schema-four form, then prove
  // only the named duplicate can project it to a strict two-record envelope.
  auto dormant=snapshot; assert(mothershipPrepareRetainedRecoverySnapshot(dormant,approved,machines,interrupted,&failure,{}, {},proof.staleExcludedContainerUUID,&proof,true,false));
  dormant.masterAuthority.runtimeState.updateSelf.state=0; dormant.masterAuthority.runtimeState.updateSelf.expectedEchos=0;
  auto staleInput=dormant;
  staleInput.masterAuthority.containerRuntimeStates.clear();
  staleInput.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].containerBootstraps.erase(
      staleInput.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].containerBootstraps.begin());
  // The stale 23-record coordinator belongs to the prior runtime, not the
  // one-record mixed successor; the existing failed-coordinator predicate
  // binds its expected digest to `previous`.
  staleInput.masterAuthority.runtimeState.updateSelf.workerExpectedBundleSHA256=previous;
  staleInput.masterAuthority.runtimeState.updateSelf.workerFailure="local post-exec bundle digest mismatch"_ctv;
  auto stale23=staleInput;
  const bool stalePrepared=mothershipPrepareRetiredConflictingClientSchema4Snapshot(stale23,approved,machines,current,previous,interrupted,successor,proof,proof.staleExcludedContainerUUID,&failure);
  if(!stalePrepared) std::fprintf(stderr,"schema-four stale23 retirement: %s\n",failure.c_str());
  assert(stalePrepared);
  assert(stale23.masterAuthority.containerRuntimeStates.empty() &&
         mothershipRetainedRecoveryWitnessContainerCount(stale23.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses)==3);
  // Exercise the actual RRF5 local save, reload, and verify path.  The
  // derived request carries 23 containers, but its adjacent immutable RRF4
  // source supplies the full 24-record coordinator proof.
  MothershipRetainedRecovery::Request original={}; original.clusterUUID=snapshot.brainConfig.clusterUUID;
  original.bundleSHA=current; original.interruptedBundleSHA=interrupted; original.mixedSuccessorMachineUUIDs=successor;
  original.plans=approved; original.machines=machines;
  auto projected=original; uint32_t projectedRemoved=0;
  for(auto& machine:projected.machines) {
    Vector<ContainerParameters> params; Vector<int64_t> created;
    for(uint32_t index=0;index<machine.parameters.size();++index) {
      if(machine.parameters[index].uuid==proof.staleExcludedContainerUUID) {++projectedRemoved;continue;}
      params.push_back(machine.parameters[index]); created.push_back(machine.observedCreatedAtMs[index]);
    }
    machine.parameters=std::move(params); machine.observedCreatedAtMs=std::move(created);
  }
  assert(projectedRemoved==1);
  const auto rrf5Root=std::filesystem::current_path()/".run"/("retired-rrf5-"+std::to_string(::getpid()));
  std::filesystem::create_directories(rrf5Root);
  const auto rrf5State=(rrf5Root/"state.new10").string(), rrf5Path=(rrf5Root/"request").string();
  { ProdigyPersistentStateStore store(MothershipTidesMigration::text(rrf5State)); assert(store.saveBrainSnapshot(staleInput,&failure)); }
  std::filesystem::create_directories(rrf5State+".secrets");
  MothershipTidesMigration::Plan rrf5Plan={}; rrf5Plan.schemaVersion=4;
  rrf5Plan.sealedCanonicalContainerCount=proof.canonicalContainerCount;
  rrf5Plan.staleCoordinatorCanonicalContainerCount=proof.staleCoordinatorCanonicalContainerCount;
  rrf5Plan.sealedInterruptedExpectedEchos=proof.interruptedExpectedEchos;
  rrf5Plan.staleExcludedContainerUUID=proof.staleExcludedContainerUUID;
  MothershipTidesMigration::durable(rrf5Path+".original",MothershipRetainedRecovery::encodeRequest(original,rrf5Plan));
  const String rrf5Bytes=MothershipRetainedRecovery::encodeRetiredConflictingClientRequest(projected,proof,proof.staleExcludedContainerUUID);
  MothershipTidesMigration::durable(rrf5Path,rrf5Bytes);
  auto sealedSnapshot=staleInput;
  assert(mothershipPrepareRetiredConflictingClientSchema4Snapshot(sealedSnapshot,approved,machines,current,previous,interrupted,successor,proof,proof.staleExcludedContainerUUID,&failure));
  MothershipRetainedRecovery::WitnessSet rrf5Witnesses={};rrf5Witnesses.requestSHA=MothershipTidesMigration::text(MothershipTidesMigration::digest(rrf5Path));
  rrf5Witnesses.witnesses=sealedSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
  String rrf5WitnessBytes={}; BitseryEngine::serialize(rrf5WitnessBytes,rrf5Witnesses); MothershipTidesMigration::durable(rrf5Path+".witnesses",rrf5WitnessBytes);
  const bool rrf5Prepared=MothershipRetainedRecovery::prepareLocal(rrf5Path.c_str(),rrf5State.c_str(),false,&failure,previous);
  if(!rrf5Prepared) std::fprintf(stderr,"schema-four RRF5 prepare: %s\n",failure.c_str());
  assert(rrf5Prepared);
  const bool rrf5Verified=MothershipRetainedRecovery::prepareLocal(rrf5Path.c_str(),rrf5State.c_str(),true,&failure,previous);
  if(!rrf5Verified) std::fprintf(stderr,"schema-four RRF5 verify: %s\n",failure.c_str());
  assert(rrf5Verified);
  ProdigyPersistentBrainSnapshot rrf5After={};MothershipRetainedRecovery::loadSnapshot(rrf5State,rrf5After);
  assert(rrf5After.masterAuthority.containerRuntimeStates.empty() &&
         mothershipRetainedRecoveryWitnessContainerCount(rrf5After.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses)==3);
  std::filesystem::remove_all(rrf5Root);
  const bool dormantPrepared=mothershipPrepareRetiredConflictingClientSchema4Snapshot(dormant,approved,machines,current,previous,interrupted,successor,proof,proof.staleExcludedContainerUUID,&failure);
  if(!dormantPrepared) std::fprintf(stderr,"schema-four dormant24 retirement: %s\n",failure.c_str());
  assert(dormantPrepared);
  assert(mothershipRetainedRecoveryWitnessContainerCount(dormant.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses)==3);
  assert(dormant.masterAuthority.containerRuntimeStates.empty());
  auto unknown=snapshot; unknown.masterAuthority.runtimeState.updateSelf.state=99;
  assert(!mothershipPrepareRetiredConflictingClientSchema4Snapshot(unknown,approved,machines,current,previous,interrupted,successor,proof,proof.staleExcludedContainerUUID,&failure));
  auto wrong= snapshot;
  assert(!mothershipPrepareRetiredConflictingClientSchema4Snapshot(wrong,approved,machines,current,previous,interrupted,successor,proof,0,&failure));
}

int main()
{
  if (const char *only = std::getenv("PRODIGY_TEST_ONLY"); only != nullptr &&
      std::strcmp(only, "retained-cold-canonical") == 0)
  {
    assertEmptyMachineColdCanonicalRuntimeRecovery();
    std::printf("RETAINED_COLD_CANONICAL_RESULT failed_assertions=0\n");
    return 0;
  }
  assertRetainedRecoveryObservedLifecycleComparison();
  assertEmptyMachineColdCanonicalRuntimeRecovery();
  const bool runtimeCidDriftAccepted = retainedRecoveryAllowsRuntimeCidDrift();
  if (const char *only = std::getenv("PRODIGY_TEST_ONLY"); only != nullptr &&
      std::strcmp(only, "retained-precheckpoint") == 0)
  {
    const int failedAssertions = retainedPrecheckpointFailures();
    std::printf("RETAINED_PRECHECKPOINT_RESULT failed_assertions=%d\n", failedAssertions);
    return failedAssertions == 0 ? 0 : 1;
  }
  // The focused runner records the old-handler rejection without an assert
  // abort.  A corrected handler must return zero failed assertions.
  if (const char *only = std::getenv("PRODIGY_TEST_ONLY"); only != nullptr &&
      std::strcmp(only, "retained-cid") == 0)
  {
    const int failedAssertions = runtimeCidDriftAccepted ? 0 : 1;
    std::printf("RETAINED_CID_RESULT failed_assertions=%d\n", failedAssertions);
    return failedAssertions == 0 ? 0 : 1;
  }
  assert(runtimeCidDriftAccepted);
  assert(retainedPrecheckpointFailures() == 0);
  assertSchema4ConflictingClientRetirement();
  // Recovery must reject malformed input before it opens or mutates a private
  // state copy.  This is the boundary used by the command owner before fence.
  ProdigyPersistentBrainSnapshot snapshot = {};
  bytell_hash_map<uint64_t, DeploymentPlan> plans = {};
  Vector<MothershipRetainedRecoveryMachineInput> machines = {};
  String failure = {};
  assert(!mothershipPrepareRetainedRecoverySnapshot(snapshot, plans, machines,
                                                    "not-a-digest"_ctv, &failure));
  assert(failure.size() > 0);

  String quiesce = {};
  mothershipBuildTidesDBMigrationServiceQuiesceCommand(quiesce);
  assert(strstr(quiesce.c_str(), "retained containers require a recovery checkpoint") != nullptr);

  using namespace MothershipRetainedRecovery;
  if (!retainedDescriptorLockChecksDrainProducer()) return 1;
  assertRetainedBootstrapUnorderedMapRoundTrip();
  // Maintenance and resumption cannot manufacture authority from an incomplete
  // migration receipt or run without the explicitly supplied tool artifact.
  {
    Plan plan;plan.operationRoot="/unopened-maintenance-fixture";
    Execution execution(plan);
    for(bool activated:{false,true}) {
      execution.receipt.activationBoundaryCrossed=activated;
      execution.receipt.phase=MothershipTidesDBMigrationPhase::validated;
      bool rejected=false;
      try {compactContained(execution,"/unopened-bundle");} catch(const std::exception&) {rejected=true;}
      assert(rejected);
      rejected=false;
      try {resumeCompacted(execution,"/unopened-bundle");} catch(const std::exception&) {rejected=true;}
      assert(rejected);
    }
    execution.receipt.phase=MothershipTidesDBMigrationPhase::completed;
    bool rejected=false;
    try {compactContained(execution,nullptr);} catch(const std::exception&) {rejected=true;}
    assert(rejected);
    rejected=false;
    try {resumeCompacted(execution,nullptr);} catch(const std::exception&) {rejected=true;}
    assert(rejected);
    for(const std::string output:{"", "{}", "{\"reclaimComplete\":false}", "{\"reclaimComplete\":true,\"logicalSHA256\":\"invalid\"}"}) {
      rejected=false;
      try {(void)compactionBaselineSHA(output);} catch(const std::exception&) {rejected=true;}
      assert(rejected);
    }
    assert(compactionBaselineSHA("{\"reclaimComplete\":true,\"logicalSHA256\":\""+std::string(64,'a')+"\"}")==std::string(64,'a'));
  }
  // The sealed manifest owns its complete inventory count. A successor after
  // containment can have different extras while retaining the canonical 23.
  {
    fs::create_directories(".run");
    char directory[]=".run/retained-manifest-unit-XXXXXX";
    assert(::mkdtemp(directory));
    const std::string path=std::string(directory)+"/manifest.json";
    Plan plan; plan.clusterUUID=7;
    for(uint32_t machine=1;machine<=3;++machine) { MothershipTidesMigration::Machine selected; selected.uuid=machine; plan.machines.push_back(selected); }
    for(uint32_t count:{23u,31u,34u}) {
      std::string json="{\"schemaVersion\":1,\"clusterUUID\":\"0x7\",\"bundleSHA256\":\""+std::string(64,'a')+"\",\"canonicalContainerCount\":23,\"machines\":[";
      for(uint32_t machine=1;machine<=3;++machine) {
        if(machine>1)json+=",";
        json+="{\"machineUUID\":\"0x"+std::to_string(machine)+"\",\"machineFragment\":"+std::to_string(machine)+",\"records\":[";
        bool first=true;
        for(uint32_t index=machine-1;index<count;index+=3) {
          if(!first)json+=",";first=false;
          String id;id.snprintf<"{itoh}"_ctv>(uint128_t(index+100));
          json+="{\"uuid\":\""+str(id)+"\",\"pid\":"+std::to_string(index+200)+",\"createdAtMs\":1,\"start\":\"1\",\"exeSHA256\":\""+std::string(64,'b')+"\",\"paramsSHA256\":\""+std::string(64,'c')+"\",\"paramsPath\":\"/private/params\",\"canonical\":"+(index<23?"true":"false")+"}";
        }
        json+="]}";
      }
      json+="]}";durable(path,text(json));
      const auto manifest=parseManifest(path,plan);
      assert(manifest.records.size()==count);
    }
    // A fresh uniform recovery can declare the actual surviving count without
    // borrowing a historical schema-four coordinator proof.  Only one named
    // registered machine may have an empty process set.
    const auto emptyManifest=std::string("{\"schemaVersion\":1,\"clusterUUID\":\"0x7\",\"bundleSHA256\":\"")+std::string(64,'a')+
      "\",\"canonicalContainerCount\":2,\"machines\":[{\"machineUUID\":\"0x1\",\"machineFragment\":1,\"emptyRetainedInventory\":true,\"records\":[]},{\"machineUUID\":\"0x2\",\"machineFragment\":2,\"records\":[{\"uuid\":\"0x65\",\"pid\":201,\"createdAtMs\":1,\"start\":\"1\",\"exeSHA256\":\""+std::string(64,'b')+"\",\"paramsSHA256\":\""+std::string(64,'c')+"\",\"paramsPath\":\"/private/params2\",\"canonical\":true}]},{\"machineUUID\":\"0x3\",\"machineFragment\":3,\"records\":[{\"uuid\":\"0x66\",\"pid\":202,\"createdAtMs\":1,\"start\":\"1\",\"exeSHA256\":\""+std::string(64,'b')+"\",\"paramsSHA256\":\""+std::string(64,'c')+"\",\"paramsPath\":\"/private/params3\",\"canonical\":true}]}]}";
    durable(path,text(emptyManifest)); const auto emptyParsed=parseManifest(path,plan);
    assert(emptyParsed.canonicalContainerCount==2 && emptyParsed.records.size()==2 && emptyParsed.emptyRetainedInventoryMachineUUID==1);
    auto rejectsEmptyManifest=[&](std::string value) { durable(path,text(value)); bool rejected=false; try {(void)parseManifest(path,plan);} catch(const std::exception&) {rejected=true;} assert(rejected); };
    auto badEmptyType=emptyManifest; badEmptyType.replace(badEmptyType.find("\"emptyRetainedInventory\":true"),std::strlen("\"emptyRetainedInventory\":true"),"\"emptyRetainedInventory\":1"); rejectsEmptyManifest(std::move(badEmptyType));
    auto unsealedEmpty=emptyManifest; unsealedEmpty.erase(unsealedEmpty.find("\"emptyRetainedInventory\":true,"),std::strlen("\"emptyRetainedInventory\":true,")); rejectsEmptyManifest(std::move(unsealedEmpty));
    fs::remove_all(directory);
  }

  // Version two is deliberately confined to retained recovery and binds every
  // observed executable pair to one of exactly two locally approved bundles.
  // Parser failures happen before any Mothership connection or lifecycle work.
  {
    fs::create_directories(".run");
    char directory[]=".run/retained-mixed-plan-unit-XXXXXX";
    assert(::mkdtemp(directory));
    const std::string path=std::string(directory)+"/plan.json";
    const std::string oldRuntime(64,'a'), oldBundle(64,'b');
    const std::string newRuntime(64,'c'), interruptedBundle(64,'d');
    auto planJSON=[&](bool retained=true) {
      return std::string("{\"schemaVersion\":2,\"retainedRecoveryMode\":")+(retained?"true":"false")+
        ",\"clusterUUID\":\"0x7\",\"operationID\":\"0x8\",\"operationRoot\":\"/private/operation\",\"registryRoot\":\"/private/registry\",\"bundlePath\":\"/private/successor.bundle\",\"runtimeRoot\":\"/root/prodigy-nuc\",\"statePath\":\"/var/lib/prodigy/state\",\"secretsPath\":\"/var/lib/prodigy/secrets\",\"expectedOldRuntimeSHA256\":\""+oldRuntime+"\",\"expectedOldBundleSHA256\":\""+oldBundle+"\",\"machines\":["
        "{\"machineUUID\":\"0x1\",\"linuxMachineID\":\"11111111111111111111111111111111\",\"sshAddress\":\"fd72::1\",\"installedRuntimeRoot\":\"/root/prodigy-nuc\",\"installedRuntimeSHA256\":\""+oldRuntime+"\",\"installedBundleSHA256\":\""+oldBundle+"\"},"
        "{\"machineUUID\":\"0x2\",\"linuxMachineID\":\"22222222222222222222222222222222\",\"sshAddress\":\"fd72::2\",\"installedRuntimeRoot\":\"/root/prodigy\",\"installedRuntimeSHA256\":\""+newRuntime+"\",\"installedBundleSHA256\":\""+interruptedBundle+"\"},"
        "{\"machineUUID\":\"0x3\",\"linuxMachineID\":\"33333333333333333333333333333333\",\"sshAddress\":\"fd72::3\",\"installedRuntimeRoot\":\"/root/prodigy\",\"installedRuntimeSHA256\":\""+newRuntime+"\",\"installedBundleSHA256\":\""+interruptedBundle+"\"}],\"approvedPredecessors\":["
        "{\"runtimeSHA256\":\""+oldRuntime+"\",\"bundleSHA256\":\""+oldBundle+"\",\"bundlePath\":\"/private/old.bundle\"},"
        "{\"runtimeSHA256\":\""+newRuntime+"\",\"bundleSHA256\":\""+interruptedBundle+"\",\"bundlePath\":\"/private/interrupted.bundle\"}]}";
    };
    auto writePlan=[&](const std::string& value) { durable(path,text(value)); assert(::chmod(path.c_str(),0600)==0); };
    auto rejects=[&](const std::string& value) { writePlan(value); bool rejected=false; try {(void)MothershipTidesMigration::parse(path.c_str());} catch(const std::exception&) {rejected=true;} assert(rejected); };
    writePlan(planJSON()); const auto parsed=MothershipTidesMigration::parse(path.c_str());
    assert(parsed.mixedPredecessors && parsed.approvedPredecessors.size()==2 && parsed.machines[0].runtimeRoot=="/root/prodigy-nuc");
    assert(retainedRecoveryHasMixedInstalledPredecessors(parsed));
    String genericFailure;
    assert(!MothershipTidesMigration::run(path.c_str(),false,&genericFailure));
    assert(genericFailure=="mixed predecessors require the retained recovery command"_ctv);
    auto missingIdentity=planJSON(); const auto identity="\"installedRuntimeSHA256\":\""+oldRuntime+"\","; missingIdentity.erase(missingIdentity.find(identity),identity.size()); rejects(missingIdentity);
    auto unknownPair=planJSON(); unknownPair.replace(unknownPair.find("\"installedRuntimeSHA256\":\""+newRuntime),std::string("\"installedRuntimeSHA256\":\"").size()+newRuntime.size(),"\"installedRuntimeSHA256\":\""+std::string(64,'e')); rejects(unknownPair);
    auto duplicatePair=planJSON(); const auto second="{\"runtimeSHA256\":\""+newRuntime+"\",\"bundleSHA256\":\""+interruptedBundle+"\",\"bundlePath\":\"/private/interrupted.bundle\"}"; const auto first="{\"runtimeSHA256\":\""+oldRuntime+"\",\"bundleSHA256\":\""+oldBundle+"\",\"bundlePath\":\"/private/old.bundle\"}"; duplicatePair.replace(duplicatePair.find(second),second.size(),first); rejects(duplicatePair);
    auto excessApproved=planJSON(); const auto excess="{\"runtimeSHA256\":\""+std::string(64,'e')+"\",\"bundleSHA256\":\""+std::string(64,'f')+"\",\"bundlePath\":\"/private/excess.bundle\"}"; excessApproved.insert(excessApproved.rfind("]}"),","+excess); rejects(excessApproved);
    const auto oldMachine="{\"machineUUID\":\"0x1\",\"linuxMachineID\":\"11111111111111111111111111111111\",\"sshAddress\":\"fd72::1\",\"installedRuntimeRoot\":\"/root/prodigy-nuc\",\"installedRuntimeSHA256\":\""+oldRuntime+"\",\"installedBundleSHA256\":\""+oldBundle+"\"}";
    const auto installedMachine="{\"machineUUID\":\"0x1\",\"linuxMachineID\":\"11111111111111111111111111111111\",\"sshAddress\":\"fd72::1\",\"installedRuntimeRoot\":\"/root/prodigy\",\"installedRuntimeSHA256\":\""+newRuntime+"\",\"installedBundleSHA256\":\""+interruptedBundle+"\"}";
    auto uniformSplitRoot=planJSON(); uniformSplitRoot.replace(uniformSplitRoot.find(oldMachine),oldMachine.size(),installedMachine);
    writePlan(uniformSplitRoot); const auto uniformParsed=MothershipTidesMigration::parse(path.c_str());
    assert(uniformParsed.mixedPredecessors && !retainedRecoveryHasMixedInstalledPredecessors(uniformParsed));
    auto uniformSameRoot=uniformSplitRoot;
    for(size_t position=0;(position=uniformSameRoot.find("\"installedRuntimeRoot\":\"/root/prodigy\"",position))!=std::string::npos;position+=1)
      uniformSameRoot.replace(position,std::strlen("\"installedRuntimeRoot\":\"/root/prodigy\""),"\"installedRuntimeRoot\":\"/root/prodigy-nuc\"");
    rejects(uniformSameRoot);
    auto duplicateMachine=planJSON(); duplicateMachine.replace(duplicateMachine.find("\"machineUUID\":\"0x3\""),std::strlen("\"machineUUID\":\"0x3\""),"\"machineUUID\":\"0x2\""); rejects(duplicateMachine);
    rejects(planJSON(false));
    fs::remove_all(directory);
  }

  // Schema four seals a three-host 1+2 installed predecessor inventory.
  {
    fs::create_directories(".run"); char directory[]=".run/retained-mixed14-plan-unit-XXXXXX"; assert(::mkdtemp(directory));
    const std::string path=std::string(directory)+"/plan.json", a(64,'a'), b(64,'b'), c(64,'c'), d(64,'d');
    const auto planJSON=std::string("{\"schemaVersion\":4,\"retainedRecoveryMode\":true,\"clusterUUID\":\"0x7\",\"operationID\":\"0x8\",\"operationRoot\":\"/private/operation\",\"registryRoot\":\"/private/registry\",\"bundlePath\":\"/private/successor.bundle\",\"runtimeRoot\":\"/root/prodigy\",\"statePath\":\"/var/lib/prodigy/state\",\"secretsPath\":\"/var/lib/prodigy/secrets\",\"expectedOldRuntimeSHA256\":\"")+a+"\",\"expectedOldBundleSHA256\":\""+b+"\",\"sealedRetainedRecovery\":{\"canonicalContainerCount\":24,\"staleCoordinatorCanonicalContainerCount\":23,\"interruptedExpectedEchos\":2,\"staleExcludedContainerUUID\":\"0x3e8\",\"serviceRuntimeSHA256\":\""+std::string(64,'e')+"\",\"serviceBundleSHA256\":\""+std::string(64,'f')+"\",\"serviceBundlePath\":\"/private/service.bundle\"},\"machines\":[{\"machineUUID\":\"0x1\",\"linuxMachineID\":\"11111111111111111111111111111111\",\"sshAddress\":\"fd72::1\",\"installedRuntimeRoot\":\"/root/prodigy\",\"installedRuntimeSHA256\":\""+a+"\",\"installedBundleSHA256\":\""+b+"\"},{\"machineUUID\":\"0x2\",\"linuxMachineID\":\"22222222222222222222222222222222\",\"sshAddress\":\"fd72::2\",\"installedRuntimeRoot\":\"/root/prodigy\",\"installedRuntimeSHA256\":\""+a+"\",\"installedBundleSHA256\":\""+b+"\"},{\"machineUUID\":\"0x3\",\"linuxMachineID\":\"33333333333333333333333333333333\",\"sshAddress\":\"fd72::3\",\"installedRuntimeRoot\":\"/root/prodigy\",\"installedRuntimeSHA256\":\""+c+"\",\"installedBundleSHA256\":\""+d+"\"}],\"approvedPredecessors\":[{\"runtimeSHA256\":\""+a+"\",\"bundleSHA256\":\""+b+"\",\"bundlePath\":\"/private/old.bundle\"},{\"runtimeSHA256\":\""+c+"\",\"bundleSHA256\":\""+d+"\",\"bundlePath\":\"/private/new.bundle\"}]}";
    durable(path,text(planJSON)); assert(::chmod(path.c_str(),0600)==0); const auto parsed=MothershipTidesMigration::parse(path.c_str());
    assert(parsed.explicitMixedRuntimeInventory && parsed.mixedPredecessors); fs::remove_all(directory);
  }

  // Version three is the retained-only form for a uniform logical
  // predecessor whose actual executable root differs by host.  It is kept
  // separate from version two: there is no second predecessor identity.
  {
    fs::create_directories(".run");
    char directory[]=".run/retained-split-root-plan-unit-XXXXXX";
    assert(::mkdtemp(directory));
    const std::string path=std::string(directory)+"/plan.json";
    const std::string oldRuntime(64,'a'), oldBundle(64,'b');
    auto planJSON=[&](bool retained=true) {
      return std::string("{\"schemaVersion\":3,\"retainedRecoveryMode\":")+(retained?"true":"false")+
        ",\"clusterUUID\":\"0x7\",\"operationID\":\"0x8\",\"operationRoot\":\"/private/operation\",\"registryRoot\":\"/private/registry\",\"bundlePath\":\"/private/successor.bundle\",\"runtimeRoot\":\"/root/prodigy-nuc-20260914\",\"statePath\":\"/var/lib/prodigy/state\",\"secretsPath\":\"/var/lib/prodigy/secrets\",\"expectedOldRuntimeSHA256\":\""+oldRuntime+"\",\"expectedOldBundleSHA256\":\""+oldBundle+"\",\"machines\":["
        "{\"machineUUID\":\"0x1\",\"linuxMachineID\":\"11111111111111111111111111111111\",\"sshAddress\":\"fd72::1\",\"installedRuntimeRoot\":\"/root/prodigy\",\"installedRuntimeSHA256\":\""+oldRuntime+"\",\"installedBundleSHA256\":\""+oldBundle+"\"},"
        "{\"machineUUID\":\"0x2\",\"linuxMachineID\":\"22222222222222222222222222222222\",\"sshAddress\":\"fd72::2\",\"installedRuntimeRoot\":\"/root/prodigy\",\"installedRuntimeSHA256\":\""+oldRuntime+"\",\"installedBundleSHA256\":\""+oldBundle+"\"},"
        "{\"machineUUID\":\"0x3\",\"linuxMachineID\":\"33333333333333333333333333333333\",\"sshAddress\":\"fd72::3\",\"installedRuntimeRoot\":\"/root/prodigy-nuc-20260914\",\"installedRuntimeSHA256\":\""+oldRuntime+"\",\"installedBundleSHA256\":\""+oldBundle+"\"}]}";
    };
    auto writePlan=[&](const std::string& value) { durable(path,text(value)); assert(::chmod(path.c_str(),0600)==0); };
    auto rejects=[&](const std::string& value) { writePlan(value); bool rejected=false; try {(void)MothershipTidesMigration::parse(path.c_str());} catch(const std::exception&) {rejected=true;} assert(rejected); };
    writePlan(planJSON()); const auto parsed=MothershipTidesMigration::parse(path.c_str());
    assert(parsed.retainedRecovery && !parsed.mixedPredecessors && parsed.approvedPredecessors.empty());
    assert(parsed.machines[0].runtimeRoot=="/root/prodigy" && parsed.machines[2].runtimeRoot=="/root/prodigy-nuc-20260914");
    String genericFailure;
    assert(!MothershipTidesMigration::run(path.c_str(),false,&genericFailure));
    assert(genericFailure=="per-host installed roots require the retained recovery command"_ctv);
    auto runtimeMismatch=planJSON(); runtimeMismatch.replace(runtimeMismatch.find("\"installedRuntimeSHA256\":\""+oldRuntime),std::string("\"installedRuntimeSHA256\":\"").size()+oldRuntime.size(),"\"installedRuntimeSHA256\":\""+std::string(64,'c')); rejects(runtimeMismatch);
    auto bundleMismatch=planJSON(); bundleMismatch.replace(bundleMismatch.find("\"installedBundleSHA256\":\""+oldBundle),std::string("\"installedBundleSHA256\":\"").size()+oldBundle.size(),"\"installedBundleSHA256\":\""+std::string(64,'d')); rejects(bundleMismatch);
    rejects(planJSON(false));
    auto unsafeRoot=planJSON(); unsafeRoot.replace(unsafeRoot.find("\"installedRuntimeRoot\":\"/root/prodigy\""),std::strlen("\"installedRuntimeRoot\":\"/root/prodigy\""),"\"installedRuntimeRoot\":\"/root/../unsafe\""); rejects(unsafeRoot);
    auto missingRoot=planJSON(); const std::string rootField="\"installedRuntimeRoot\":\"/root/prodigy\","; missingRoot.erase(missingRoot.find(rootField),rootField.size()); rejects(missingRoot);
    fs::remove_all(directory);
  }

  Request request;request.clusterUUID=1;
  String interruptedBundle = "retained-recovery-interrupted-update-bundle"_ctv;
  assert(prodigyComputeSHA256Hex(interruptedBundle,request.bundleSHA));
  String bytes;BitseryEngine::serialize(bytes,request);Request decoded;
  assert(BitseryEngine::deserializeSafe(bytes,decoded) && decoded.clusterUUID==1 && decoded.bundleSHA==request.bundleSHA);
  Manifest sealedManifest = {}; Manifest successor = {};
  Record record = {}; record.machine=1; record.container=2; record.pid=3; record.created=4; record.start="5"; record.executableSHA=std::string(64,'a'); record.paramsSHA=std::string(64,'b'); record.paramsPath="/root/params"; record.canonical=true;
  sealedManifest.records.push_back(record); successor.records.push_back(record);
  assert(sameRecordIdentity(sealedManifest,successor));
  successor.records[0].pid++;
  assert(!sameRecordIdentity(sealedManifest,successor));
  Manifest canonicalPredecessor = {}, canonicalSuccessor = {};
  for (uint32_t index=0;index<23;++index) {
    Record canonical = record;
    canonical.container=100+index;
    canonical.pid=200+index;
    canonical.created=300+index;
    canonicalPredecessor.records.push_back(canonical);
    canonicalSuccessor.records.push_back(canonical);
  }
  Record differentExtra = record;
  differentExtra.container=1000;
  differentExtra.canonical=false;
  canonicalSuccessor.records.push_back(differentExtra);
  assert(sameCanonicalRecordIdentity(canonicalPredecessor,canonicalSuccessor));
  canonicalSuccessor.records[0].start="changed";
  assert(!sameCanonicalRecordIdentity(canonicalPredecessor,canonicalSuccessor));
  MothershipTidesMigration::Plan predecessorPlan = {}, successorPlan = {};
  predecessorPlan.operationID=1; successorPlan.operationID=2; predecessorPlan.operationRoot="/root/old"; successorPlan.operationRoot="/root/new";
  predecessorPlan.clusterUUID=7; successorPlan.clusterUUID=7; predecessorPlan.identity="7"; successorPlan.identity="7";
  predecessorPlan.registryRoot="/root/registry"; successorPlan.registryRoot="/root/registry"; predecessorPlan.runtimeRoot="/root/prodigy"; successorPlan.runtimeRoot="/root/prodigy";
  predecessorPlan.statePath="/var/lib/prodigy/state"; successorPlan.statePath=predecessorPlan.statePath; predecessorPlan.secretsPath="/var/lib/prodigy/secrets"; successorPlan.secretsPath=predecessorPlan.secretsPath;
  predecessorPlan.oldRuntimeSHA=std::string(64,'a'); successorPlan.oldRuntimeSHA=predecessorPlan.oldRuntimeSHA; predecessorPlan.oldBundleSHA=std::string(64,'b'); successorPlan.oldBundleSHA=predecessorPlan.oldBundleSHA;
  MothershipTidesMigration::Machine plannedMachine = {}; plannedMachine.uuid=3; plannedMachine.linuxID="0123456789abcdef0123456789abcdef"; plannedMachine.address="fd72::1"; plannedMachine.runtimeRoot="/root/observed-prodigy"; plannedMachine.installedRuntimeSHA=std::string(64,'a'); plannedMachine.installedBundleSHA=std::string(64,'b'); predecessorPlan.machines.push_back(plannedMachine); successorPlan.machines.push_back(plannedMachine);
  assert(samePlanTarget(predecessorPlan,successorPlan)); successorPlan.operationRoot=predecessorPlan.operationRoot;
  assert(!samePlanTarget(predecessorPlan,successorPlan));
  successorPlan.operationRoot="/root/new";
  MothershipTidesMigration::Execution serviceRootFixture(predecessorPlan);
  assert(serviceRootFixture.activeRuntimeRoot(serviceRootFixture.plan.machines[0])=="/root/observed-prodigy");
  assert(serviceRootFixture.serviceRuntimeRoot()=="/root/prodigy");
  assert(serviceRootFixture.serviceExecStartCheck().find("/root/prodigy/prodigy")!=std::string::npos);
  for (auto member : {&MothershipTidesMigration::Plan::statePath, &MothershipTidesMigration::Plan::secretsPath,
                      &MothershipTidesMigration::Plan::runtimeRoot, &MothershipTidesMigration::Plan::registryRoot,
                      &MothershipTidesMigration::Plan::oldRuntimeSHA, &MothershipTidesMigration::Plan::oldBundleSHA}) {
    auto invalid=successorPlan; invalid.*member+="-changed";
    assert(!samePlanTarget(predecessorPlan,invalid));
  }
  auto wrongMachine=successorPlan; wrongMachine.machines[0].linuxID[0]='f';
  assert(!samePlanTarget(predecessorPlan,wrongMachine));
  MothershipTidesDBMigrationReceipt containedReceipt = {};
  containedReceipt.newRuntimeSHA256=text(std::string(64,'c'));
  containedReceipt.approvedBundleSHA256=text(std::string(64,'d'));
  successorPlan.oldRuntimeSHA=std::string(64,'c');
  successorPlan.oldBundleSHA=std::string(64,'d');
  assert(sameContainedSuccessorTarget(predecessorPlan,containedReceipt,successorPlan));
  successorPlan.oldBundleSHA=std::string(64,'e');
  assert(!sameContainedSuccessorTarget(predecessorPlan,containedReceipt,successorPlan));
  successorPlan.oldBundleSHA=std::string(64,'d');
  MothershipTidesMigration::Machine inventoryMachine = {}; inventoryMachine.uuid=1;
  assert(inventoryProgram("/sealed-manifest",inventoryMachine,InventoryMode::sealed).find("actual==expected")!=std::string::npos);
  assert(inventoryProgram("/sealed-manifest",inventoryMachine,InventoryMode::canonical).find("canonical_only=True")!=std::string::npos);
  assert(inventoryProgram("/sealed-manifest",inventoryMachine,InventoryMode::retire).find("canonical <= actual <= expected")!=std::string::npos);
  for (auto mode : {InventoryMode::sealed, InventoryMode::canonical, InventoryMode::remaining, InventoryMode::retire}) {
    const auto command=inventoryProgram("/sealed-MODE-manifest",inventoryMachine,mode);
    assert(command.find("/sealed-MODE-manifest")!=std::string::npos);
    if(mode!=InventoryMode::retire) assert(command.find("pidfd_send_signal")==std::string::npos);
    String syntaxFailure;
    const auto check="python3 -c "+quote("import ast,shlex,sys; ast.parse(shlex.split(sys.argv[1])[2])")+" "+quote(command);
    assert(prodigyRunLocalShellCommand(text(check),&syntaxFailure));
  }
  const auto stop=MothershipTidesMigration::quiesceServiceCommand();
  assert(stop.find("retained containers require")<stop.find("systemctl stop"));
  assert(MothershipTidesMigration::quiesceServiceCommand(true).find("retained containers require")==std::string::npos);
  assert(!prepareLocal("/absent/request","/var/lib/prodigy/state",false,&failure));
  // Exercise the actual private-copy save and independent reopen/readback.
  const auto root=std::filesystem::current_path()/".run"/("retained-recovery-"+std::to_string(::getpid()));
  assert(!std::filesystem::exists(root));std::filesystem::create_directories(root);
  const uint128_t formattedTarget=(uint128_t(0x4fbeb7f9454a068aULL)<<64)|uint128_t(0x1eea562809529ff6ULL);
  const auto prefixManifest=(root/"prefix-manifest.json").string(), prefixDerived=(root/"prefix-derived.json").string();
  { std::ofstream output(prefixManifest); assert(output); output << "{\"canonicalContainerCount\":1,\"machines\":[{\"records\":[{\"uuid\":\"0x4fbeb7f9454a068a1eea562809529ff6\",\"canonical\":true}]}]}"; }
  const auto derivedPrefixCommand=derivedConflictingClientManifestProgram(prefixManifest,formattedTarget);
  const auto retiredPrefixCommand=inventoryProgram(prefixManifest,inventoryMachine,InventoryMode::retireConflictingClient,formattedTarget);
  const auto storagePrefixCommand=conflictingClientStorageProgram(prefixManifest,formattedTarget,true);
  assert(derivedPrefixCommand.find("0x0x")==std::string::npos && retiredPrefixCommand.find("0x0x")==std::string::npos && storagePrefixCommand.find("0x0x")==std::string::npos);
  String prefixFailure; assert(prodigyRunLocalShellCommand(text(derivedPrefixCommand+" > "+quote(prefixDerived)),&prefixFailure));
  const auto derivedPrefix=MothershipTidesMigration::read(prefixDerived); assert(derivedPrefix.find("\"canonical\":false")!=std::string::npos && derivedPrefix.find("\"canonicalContainerCount\":0")!=std::string::npos);
  const auto statePath=(root/"state.new10").string(), requestPath=(root/"request").string();
  snapshot.brainConfig.clusterUUID=1;snapshot.brainConfig.datacenterFragment=7;
  DeploymentPlan deployment = {};deployment.config.type=ApplicationType::stateless;deployment.config.applicationID=77;deployment.config.versionID=9;
  deployment.config.memoryMB=256;deployment.config.storageMB=128;deployment.config.nLogicalCores=1;
  const auto deploymentID=deployment.config.deploymentID();
  snapshot.masterAuthority.deploymentPlans[deploymentID]=deployment;
  request.plans=snapshot.masterAuthority.deploymentPlans;
  for(uint32_t i=1;i<=3;++i) {
    ClusterMachine machine = {};machine.uuid=i;snapshot.topology.machines.push_back(machine);
    MothershipRetainedRecoveryMachineInput input;input.machineUUID=i;input.machineFragment=i;
    ContainerParameters params = {};params.uuid=i+100;params.deploymentID=deploymentID;
    params.memoryMB=deployment.config.memoryMB;params.storageMB=deployment.config.storageMB;
    params.nLogicalCores=applicationSharedCPUCoreHint(deployment.config);params.cpuMode=deployment.config.cpuMode;params.requestedCPUMillis=applicationRequestedCPUMillis(deployment.config);
    params.private6.network.is6=true;params.private6.cidr=128;
    std::memcpy(params.private6.network.v6,container_network_subnet6.value,11);
    params.private6.network.v6[11]=7;params.private6.network.v6[12]=0;params.private6.network.v6[13]=0;params.private6.network.v6[14]=i;params.private6.network.v6[15]=1;
    for(uint64_t service=1;service<=16;++service) {
      SubscriptionPairing subscriptionPairing = {};subscriptionPairing.secret=service;subscriptionPairing.address=service+100;subscriptionPairing.service=service;subscriptionPairing.port=uint16_t(5000+service);
      params.subscriptionPairings.insert(service,subscriptionPairing);
      AdvertisementPairing advertisementPairing = {};advertisementPairing.secret=service+200;advertisementPairing.address=service+300;advertisementPairing.service=service+1000;
      params.advertisementPairings.insert(service+1000,advertisementPairing);
    }
    input.parameters.push_back(params);input.observedCreatedAtMs.push_back(1790040000000LL);request.machines.push_back(input);
  }
  // BrainConfig and API credentials contain nested unordered maps as well.
  ApiCredential credential = {};credential.name="fixture"_ctv;
  for (uint32_t index=0;index<32;++index) {
    String key;key.snprintf<"key-{itoa}"_ctv>(index);
    MachineConfig machine = {};machine.slug=key;machine.nLogicalCores=index+1;
    snapshot.brainConfig.configBySlug[key]=machine;
    snapshot.brainConfig.dnsCredential.metadata[key]=key;
    credential.metadata[key]=key;
  }
  ApplicationApiCredentialSet credentials = {};credentials.applicationID=77;credentials.credentials.push_back(credential);
  snapshot.masterAuthority.apiCredentialSetsByApp[77]=credentials;

  assertRetainedRecoveryRuntimeCidDriftPreservesLocalPlan(
      snapshot, request.plans, request.machines, request.bundleSHA, deploymentID);

  // A registered Brain can reboot after its service state is durable but
  // before it reconstructs a single retained application process.  The
  // request must name exactly that empty machine; its two surviving peers
  // still supply the normal stateful-role proof.
  auto zeroInventoryRequest=request;
  zeroInventoryRequest.machines[0].parameters.clear();
  zeroInventoryRequest.machines[0].observedCreatedAtMs.clear();
  auto zeroInventorySnapshot=snapshot;
  assert(mothershipPrepareRetainedRecoverySnapshot(
      zeroInventorySnapshot,zeroInventoryRequest.plans,zeroInventoryRequest.machines,request.bundleSHA,&failure,
      {},{},0,nullptr,false,true,zeroInventoryRequest.machines[0].machineUUID));
  assert(zeroInventorySnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses.size()==3);
  assert(zeroInventorySnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].containerBootstraps.empty());
  auto unsealedZeroInventory=snapshot;
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      unsealedZeroInventory,zeroInventoryRequest.plans,zeroInventoryRequest.machines,request.bundleSHA,&failure));
  auto wrongZeroInventory=snapshot;
  assert(!mothershipPrepareRetainedRecoverySnapshot(
      wrongZeroInventory,zeroInventoryRequest.plans,zeroInventoryRequest.machines,request.bundleSHA,&failure,
      {},{},0,nullptr,false,true,zeroInventoryRequest.machines[1].machineUUID));
  Plan uniformFreshPlan={}; uniformFreshPlan.schemaVersion=3;
  const String zeroInventoryBytes=encodeRequest(
      zeroInventoryRequest,uniformFreshPlan,zeroInventoryRequest.machines[0].machineUUID);
  Request decodedZeroInventory={}; MothershipRetainedRecoveryMixedProof decodedZeroProof={};
  uint128_t decodedZeroMachine=0;
  assert(zeroInventoryBytes.size()>4 && decodeRequest(MothershipTidesMigration::str(zeroInventoryBytes),decodedZeroInventory,
      &decodedZeroProof,nullptr,&decodedZeroMachine));
  assert(decodedZeroMachine==zeroInventoryRequest.machines[0].machineUUID && decodedZeroProof.canonicalContainerCount==0 &&
         decodedZeroInventory.machines[0].parameters.empty());
  Schema6EmptyInventoryRequest inventedProof={}; inventedProof.request.request=zeroInventoryRequest;
  inventedProof.request.proof.canonicalContainerCount=2; inventedProof.request.proof.staleCoordinatorCanonicalContainerCount=1;
  inventedProof.request.proof.interruptedExpectedEchos=1; inventedProof.request.proof.staleExcludedContainerUUID=99;
  inventedProof.emptyRetainedInventoryMachineUUID=zeroInventoryRequest.machines[0].machineUUID;
  String inventedProofBytes={}; BitseryEngine::serialize(inventedProofBytes,inventedProof);
  String inventedProofFrame={}; inventedProofFrame.append("RRF6",4); inventedProofFrame.append(inventedProofBytes.data(),inventedProofBytes.size());
  assert(!decodeRequest(MothershipTidesMigration::str(inventedProofFrame),decodedZeroInventory,
      &decodedZeroProof,nullptr,&decodedZeroMachine));

  // A normal update that stopped while merely collecting bundle echoes may be
  // replaced.  Both a complete and lagging echo set are pre-exec states.
  auto makeInterruptedUpdate = [&](uint32_t expectedEchos, uint32_t bundleEchos) {
    ProdigyPersistentBrainSnapshot interrupted = snapshot;
    auto& update=interrupted.masterAuthority.runtimeState.updateSelf;
    update.state=uint8_t(ProdigyPersistentUpdateSelfState::Phase::waitingForBundleEchos);
    update.expectedEchos=expectedEchos;
    update.bundleEchos=bundleEchos;
    update.bundleBlob=interruptedBundle;
    update.workerExpectedBundleSHA256=request.bundleSHA;
    for(uint32_t index=0;index<bundleEchos;++index) update.bundleEchoPeerKeys.push_back(1+index);
    return interrupted;
  };
  auto fullEchoSnapshot=makeInterruptedUpdate(2,2);
  assert(mothershipRetainedRecoveryCanReplaceUpdate(fullEchoSnapshot,request.bundleSHA,{}));
  auto laggingEchoSnapshot=makeInterruptedUpdate(2,1);
  assert(mothershipRetainedRecoveryCanReplaceUpdate(laggingEchoSnapshot,request.bundleSHA,{}));
  auto unknownEchoPeerSnapshot=laggingEchoSnapshot;
  unknownEchoPeerSnapshot.masterAuthority.runtimeState.updateSelf.bundleEchoPeerKeys[0]=99;
  assert(!mothershipRetainedRecoveryCanReplaceUpdate(unknownEchoPeerSnapshot,request.bundleSHA,{}));
  auto duplicateEchoPeerSnapshot=fullEchoSnapshot;
  duplicateEchoPeerSnapshot.masterAuthority.runtimeState.updateSelf.bundleEchoPeerKeys[1]=1;
  assert(!mothershipRetainedRecoveryCanReplaceUpdate(duplicateEchoPeerSnapshot,request.bundleSHA,{}));
  auto laterPhaseSnapshot=laggingEchoSnapshot;
  laterPhaseSnapshot.masterAuthority.runtimeState.updateSelf.state=uint8_t(ProdigyPersistentUpdateSelfState::Phase::waitingForFollowerReboots);
  assert(!mothershipRetainedRecoveryCanReplaceUpdate(laterPhaseSnapshot,request.bundleSHA,{}));
  auto wrongDigestSnapshot=laggingEchoSnapshot;
  wrongDigestSnapshot.masterAuthority.runtimeState.updateSelf.workerExpectedBundleSHA256.assign(std::string(64,'f').c_str());
  assert(!mothershipRetainedRecoveryCanReplaceUpdate(wrongDigestSnapshot,request.bundleSHA,{}));
  auto wrongBlobSnapshot=laggingEchoSnapshot;
  wrongBlobSnapshot.masterAuthority.runtimeState.updateSelf.bundleBlob.assign("different-bundle"_ctv);
  assert(!mothershipRetainedRecoveryCanReplaceUpdate(wrongBlobSnapshot,request.bundleSHA,{}));
  auto registeredWitnessSnapshot=laggingEchoSnapshot;
  for(const ClusterMachine& machine:registeredWitnessSnapshot.topology.machines) {
    ProdigyPersistentUpdateSelfMachineRecoveryWitness witness = {};
    witness.machineUUID=machine.uuid;
    registeredWitnessSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses.push_back(witness);
  }
  registeredWitnessSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].bundleRegistered=true;
  assert(!mothershipRetainedRecoveryCanReplaceUpdate(registeredWitnessSnapshot,request.bundleSHA,{}));
  auto transitionSnapshot=laggingEchoSnapshot;
  transitionSnapshot.masterAuthority.runtimeState.updateSelf.workerTransitionIssuedMachineUUIDs.push_back(1);
  assert(!mothershipRetainedRecoveryCanReplaceUpdate(transitionSnapshot,request.bundleSHA,{}));

  // A rejected update can have already retained its payload and intended
  // worker digest while the authority-ack admission barrier rejects it.  It
  // has not issued work, handoff, or recovery state, so a fenced retained
  // recovery may replace this one exact pre-admission record.
  auto rejectedBeforeAdmissionSnapshot=snapshot;
  auto& rejectedBeforeAdmission=rejectedBeforeAdmissionSnapshot.masterAuthority.runtimeState.updateSelf;
  rejectedBeforeAdmission.state=uint8_t(ProdigyPersistentUpdateSelfState::Phase::idle);
  rejectedBeforeAdmission.bundleBlob=interruptedBundle;
  rejectedBeforeAdmission.workerExpectedBundleSHA256=request.bundleSHA;
  rejectedBeforeAdmission.workerFailure.assign("current master authority is not durably acknowledged by every registered peer"_ctv);
  assert(mothershipRetainedRecoveryCanReplaceUpdate(rejectedBeforeAdmissionSnapshot,request.bundleSHA,{}));
  String rejectedCandidateBlob = "rejected-pre-admission-candidate"_ctv, rejectedCandidateSHA = {};
  assert(prodigyComputeSHA256Hex(rejectedCandidateBlob, rejectedCandidateSHA));
  auto differentRejectedCandidate = rejectedBeforeAdmissionSnapshot;
  differentRejectedCandidate.masterAuthority.runtimeState.updateSelf.bundleBlob = rejectedCandidateBlob;
  differentRejectedCandidate.masterAuthority.runtimeState.updateSelf.workerExpectedBundleSHA256 = rejectedCandidateSHA;
  assert(!mothershipRetainedRecoveryCanReplaceUpdate(differentRejectedCandidate, request.bundleSHA, {}));
  assert(mothershipRetainedRecoveryCanReplaceUpdate(
      differentRejectedCandidate, request.bundleSHA, {}, {}, rejectedCandidateSHA));

  auto wrongRejectedDigest=rejectedBeforeAdmissionSnapshot;
  wrongRejectedDigest.masterAuthority.runtimeState.updateSelf.workerExpectedBundleSHA256.assign(std::string(64,'e').c_str());
  assert(!mothershipRetainedRecoveryCanReplaceUpdate(wrongRejectedDigest,request.bundleSHA,{}));
  auto wrongRejectedBlob=rejectedBeforeAdmissionSnapshot;
  wrongRejectedBlob.masterAuthority.runtimeState.updateSelf.bundleBlob.assign("wrong-rejected-before-admission-bundle"_ctv);
  assert(!mothershipRetainedRecoveryCanReplaceUpdate(wrongRejectedBlob,request.bundleSHA,{}));

  struct RejectedBeforeAdmissionMutation {
    const char *name;
    void (*apply)(ProdigyPersistentUpdateSelfState&);
  };
  const RejectedBeforeAdmissionMutation unsafeRejectedBeforeAdmission[] = {
    {"no-rejection", [](ProdigyPersistentUpdateSelfState& update) { update.workerFailure.clear(); }},
    {"phase", [](ProdigyPersistentUpdateSelfState& update) { update.state=uint8_t(ProdigyPersistentUpdateSelfState::Phase::waitingForBundleEchos); }},
    {"echo", [](ProdigyPersistentUpdateSelfState& update) { update.expectedEchos=1; }},
    {"handoff", [](ProdigyPersistentUpdateSelfState& update) { update.plannedMasterPeerKey=1; }},
    {"reboot", [](ProdigyPersistentUpdateSelfState& update) { update.followerRebootedPeerKeys.push_back(1); }},
    {"worker", [](ProdigyPersistentUpdateSelfState& update) { update.workerMachineUUIDs.push_back(1); }},
    {"local", [](ProdigyPersistentUpdateSelfState& update) { update.localMachineUUID=1; }},
    {"witness", [](ProdigyPersistentUpdateSelfState& update) { ProdigyPersistentUpdateSelfMachineRecoveryWitness witness={};witness.machineUUID=1;update.machineRecoveryWitnesses.push_back(std::move(witness)); }},
  };
  for (const RejectedBeforeAdmissionMutation& mutation : unsafeRejectedBeforeAdmission)
  {
    auto unsafe=rejectedBeforeAdmissionSnapshot;
    mutation.apply(unsafe.masterAuthority.runtimeState.updateSelf);
    assert(!mothershipRetainedRecoveryCanReplaceUpdate(unsafe,request.bundleSHA,{}));
  }

  auto rejectedBeforeAdmissionPrepared=rejectedBeforeAdmissionSnapshot;
  assert(mothershipPrepareRetainedRecoverySnapshot(rejectedBeforeAdmissionPrepared,request.plans,request.machines,request.bundleSHA,&failure));
  const auto rejectedRecoveryRoot=root/"rejected-before-admission";
  std::filesystem::create_directories(rejectedRecoveryRoot);
  const auto rejectedStatePath=(rejectedRecoveryRoot/"state.new10").string();
  const auto rejectedRequestPath=(rejectedRecoveryRoot/"request").string();
  { ProdigyPersistentStateStore store(MothershipTidesMigration::text(rejectedStatePath)); assert(store.saveBrainSnapshot(rejectedBeforeAdmissionSnapshot,&failure)); }
  std::filesystem::create_directories(rejectedStatePath+".secrets");
  BitseryEngine::serialize(bytes,request);MothershipTidesMigration::durable(rejectedRequestPath,bytes);
  WitnessSet rejectedSealed = {};
  rejectedSealed.requestSHA=MothershipTidesMigration::text(MothershipTidesMigration::digest(rejectedRequestPath));
  rejectedSealed.witnesses=rejectedBeforeAdmissionPrepared.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
  BitseryEngine::serialize(bytes,rejectedSealed);MothershipTidesMigration::durable(rejectedRequestPath+".witnesses",bytes);
  assert(prepareLocal(rejectedRequestPath.c_str(),rejectedStatePath.c_str(),false,&failure));
  ProdigyPersistentBrainSnapshot rejectedAfter = {};
  loadSnapshot(rejectedStatePath,rejectedAfter);
  assert(prodigyPersistentBrainSnapshotsEqual(rejectedAfter,rejectedBeforeAdmissionPrepared));
  assert(prepareLocal(rejectedRequestPath.c_str(),rejectedStatePath.c_str(),true,&failure));

  auto exhaustedSnapshot=laggingEchoSnapshot;
  exhaustedSnapshot.masterAuthority.runtimeState.generation=std::numeric_limits<uint64_t>::max();
  assert(!mothershipPrepareRetainedRecoverySnapshot(exhaustedSnapshot,request.plans,request.machines,request.bundleSHA,&failure));
  String snapshotBytes;BitseryEngine::serialize(snapshotBytes,snapshot);
  ProdigyPersistentBrainSnapshot snapshotRoundTrip;
  assert(BitseryEngine::deserializeSafe(snapshotBytes,snapshotRoundTrip));
  assert(prodigyPersistentBrainSnapshotsEqual(snapshot,snapshotRoundTrip));
  snapshotRoundTrip.brainConfig.configBySlug.begin()->second.nLogicalCores+=1;
  assert(!prodigyPersistentBrainSnapshotsEqual(snapshot,snapshotRoundTrip));
  snapshotRoundTrip=snapshot;
  snapshotRoundTrip.masterAuthority.apiCredentialSetsByApp[77].credentials[0].metadata.begin()->second="changed"_ctv;
  assert(!prodigyPersistentBrainSnapshotsEqual(snapshot,snapshotRoundTrip));
  auto preparedSnapshot=laggingEchoSnapshot;
  assert(mothershipPrepareRetainedRecoverySnapshot(preparedSnapshot,request.plans,request.machines,request.bundleSHA,&failure));

  // A follower may still hold the sealed envelope from the predecessor
  // recovery.  It is neither an idle state nor this request's envelope, so it
  // needs the explicitly sealed predecessor digest to be replaced once.
  const String previousBundleSHA=text(std::string(64,'b'));
  auto predecessorEnvelopeSnapshot=snapshot;
  auto& predecessorEnvelope=predecessorEnvelopeSnapshot.masterAuthority.runtimeState.updateSelf;
  predecessorEnvelope={};
  predecessorEnvelope.workerExpectedBundleSHA256=previousBundleSHA;
  predecessorEnvelope.machineRecoveryWitnesses=preparedSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
  assert(mothershipRetainedRecoveryEnvelopeMatches(predecessorEnvelope,previousBundleSHA));
  assert(mothershipRetainedRecoveryCanReplaceUpdate(predecessorEnvelopeSnapshot,request.bundleSHA,previousBundleSHA));
  assert(!mothershipRetainedRecoveryCanReplaceUpdate(predecessorEnvelopeSnapshot,request.bundleSHA,text(std::string(64,'c'))));
  auto predecessorPrepared=predecessorEnvelopeSnapshot;
  assert(mothershipPrepareRetainedRecoverySnapshot(predecessorPrepared,request.plans,request.machines,request.bundleSHA,&failure,previousBundleSHA));
  assert(predecessorPrepared.masterAuthority.runtimeState.generation==predecessorEnvelopeSnapshot.masterAuthority.runtimeState.generation+1);
  assert(mothershipRetainedRecoveryEnvelopeMatches(predecessorPrepared.masterAuthority.runtimeState.updateSelf,request.bundleSHA));

  // A mixed predecessor can have its former coordinator at the only later
  // phase accepted by retained recovery.  The exact all-machine witness and
  // both successor-machine reboot records make this distinct from an ordinary
  // phase-two update.
  const String interruptedBundleSHA=text(std::string(64,'e'));
  auto mixedWitness=snapshot;
  mixedWitness.masterAuthority.runtimeState.updateSelf={};
  assert(mothershipPrepareRetainedRecoverySnapshot(mixedWitness,request.plans,request.machines,
                                                   interruptedBundleSHA,&failure));
  Vector<uint128_t> mixedSuccessors={2,3};
  // A successor can retain the exact interrupted envelope without taking any
  // update step. Its reconstructed witness must still contain no registered
  // successor before it can be replaced.
  auto mixedInterruptedEnvelope=mixedWitness;
  assert(mothershipPrepareRetainedRecoveryMixedInterruptedSnapshot(
      mixedInterruptedEnvelope,request.plans,request.machines,request.bundleSHA,
      previousBundleSHA,interruptedBundleSHA,mixedSuccessors,&failure));
  assert(mothershipRetainedRecoveryEnvelopeMatches(
      mixedInterruptedEnvelope.masterAuthority.runtimeState.updateSelf,request.bundleSHA));
  auto mixedInterruptedEnvelopeRegistered=mixedWitness;
  mixedInterruptedEnvelopeRegistered.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[1].bundleRegistered=true;
  assert(!mothershipPrepareRetainedRecoveryMixedInterruptedSnapshot(
      mixedInterruptedEnvelopeRegistered,request.plans,request.machines,request.bundleSHA,
      previousBundleSHA,interruptedBundleSHA,mixedSuccessors,&failure));

  // A later phase-one echo collection can retain the known earlier
  // digest failure. Echoes are from the old coordinator and need
  // only be unique known peers; they are not the successor cohort.
  String interruptedEchoBlob="mixed-interrupted-echo-bundle"_ctv,interruptedEchoSHA={};
  assert(prodigyComputeSHA256Hex(interruptedEchoBlob,interruptedEchoSHA));
  auto mixedEchoWitness=snapshot;
  mixedEchoWitness.masterAuthority.runtimeState.updateSelf={};
  assert(mothershipPrepareRetainedRecoverySnapshot(mixedEchoWitness,request.plans,request.machines,
                                                   interruptedEchoSHA,&failure));
  auto mixedEcho=mixedEchoWitness;
  auto& mixedEchoUpdate=mixedEcho.masterAuthority.runtimeState.updateSelf;
  mixedEchoUpdate.state=uint8_t(ProdigyPersistentUpdateSelfState::Phase::waitingForBundleEchos);
  mixedEchoUpdate.expectedEchos=2; mixedEchoUpdate.bundleEchos=2;
  mixedEchoUpdate.bundleEchoPeerKeys={1,3};
  mixedEchoUpdate.bundleBlob=interruptedEchoBlob;
  mixedEchoUpdate.workerExpectedBundleSHA256=interruptedEchoSHA;
  mixedEchoUpdate.workerFailure="local post-exec bundle digest mismatch"_ctv;
  for (auto& witness:mixedEchoUpdate.machineRecoveryWitnesses)
    witness.bundleRegistered=witness.machineUUID==2 || witness.machineUUID==3;
  auto mixedEchoPrepared=mixedEcho;
  assert(mothershipPrepareRetainedRecoveryMixedInterruptedSnapshot(
      mixedEchoPrepared,request.plans,request.machines,request.bundleSHA,
      previousBundleSHA,interruptedEchoSHA,mixedSuccessors,&failure));
  assert(mothershipRetainedRecoveryEnvelopeMatches(
      mixedEchoPrepared.masterAuthority.runtimeState.updateSelf,request.bundleSHA));
  auto mixedEchoWrongFailure=mixedEcho;
  mixedEchoWrongFailure.masterAuthority.runtimeState.updateSelf.workerFailure="other failure"_ctv;
  assert(!mothershipPrepareRetainedRecoveryMixedInterruptedSnapshot(
      mixedEchoWrongFailure,request.plans,request.machines,request.bundleSHA,
      previousBundleSHA,interruptedEchoSHA,mixedSuccessors,&failure));
  auto mixedEchoWrongDigest=mixedEcho;
  mixedEchoWrongDigest.masterAuthority.runtimeState.updateSelf.bundleBlob="other interrupted echo bundle"_ctv;
  assert(!mothershipPrepareRetainedRecoveryMixedInterruptedSnapshot(
      mixedEchoWrongDigest,request.plans,request.machines,request.bundleSHA,
      previousBundleSHA,interruptedEchoSHA,mixedSuccessors,&failure));
  auto mixedEchoWrongRegistration=mixedEcho;
  mixedEchoWrongRegistration.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[1].bundleRegistered=false;
  assert(!mothershipPrepareRetainedRecoveryMixedInterruptedSnapshot(
      mixedEchoWrongRegistration,request.plans,request.machines,request.bundleSHA,
      previousBundleSHA,interruptedEchoSHA,mixedSuccessors,&failure));
  auto mixedEchoTransition=mixedEcho;
  mixedEchoTransition.masterAuthority.runtimeState.updateSelf.workerTransitionIssuedMachineUUIDs.push_back(2);
  assert(!mothershipPrepareRetainedRecoveryMixedInterruptedSnapshot(
      mixedEchoTransition,request.plans,request.machines,request.bundleSHA,
      previousBundleSHA,interruptedEchoSHA,mixedSuccessors,&failure));

  // The runtime-12 recovery case has a 24-container sealed fleet, one
  // installed runtime-13 successor, and two acknowledged bundle echoes.  Its
  // old coordinator has a separate inert 23-container failed witness; it is
  // never treated as the 24-container successor witness.
  auto schema4Request=request;
  for (uint32_t machine=0;machine<schema4Request.machines.size();++machine) {
    const auto original=schema4Request.machines[machine].parameters[0];
    for (uint32_t replica=2;replica<=8;++replica) {
      auto parameters=original; parameters.uuid=uint128_t(10000+machine*100+replica);
      parameters.private6.network.v6[15]=uint8_t(replica);
      schema4Request.machines[machine].parameters.push_back(parameters);
      schema4Request.machines[machine].observedCreatedAtMs.push_back(1790040000000LL+replica);
    }
  }
  String schema4Blob="sealed-schema-four-interrupted-bundle"_ctv,schema4InterruptedSHA={};
  assert(prodigyComputeSHA256Hex(schema4Blob,schema4InterruptedSHA));
  auto schema4Witness=snapshot; schema4Witness.masterAuthority.runtimeState.updateSelf={};
  assert(mothershipPrepareRetainedRecoverySnapshot(schema4Witness,schema4Request.plans,schema4Request.machines,
                                                   schema4InterruptedSHA,&failure));
  MothershipRetainedRecoveryMixedProof schema4Proof={24,23,2,schema4Request.machines[0].parameters.back().uuid};
  assert(mothershipRetainedRecoveryWitnessContainerCount(
      schema4Witness.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses)==24);
  Vector<uint128_t> oneSuccessor={3};
  auto dormantSeed=schema4Witness;
  dormantSeed.masterAuthority.runtimeState.updateSelf.state=0;
  dormantSeed.masterAuthority.runtimeState.updateSelf.expectedEchos=0;
  dormantSeed.masterAuthority.runtimeState.updateSelf.bundleEchos=0;
  dormantSeed.masterAuthority.runtimeState.updateSelf.workerExpectedBundleSHA256=schema4InterruptedSHA;
  assert(mothershipPrepareRetainedRecoverySchema4Snapshot(
      dormantSeed,schema4Request.plans,schema4Request.machines,request.bundleSHA,
      previousBundleSHA,schema4InterruptedSHA,oneSuccessor,schema4Proof,&failure));
  auto dormantWithWork=dormantSeed;
  dormantWithWork.masterAuthority.runtimeState.updateSelf.workerExpectedBundleSHA256=schema4InterruptedSHA;
  dormantWithWork.masterAuthority.runtimeState.updateSelf.workerMachineUUIDs.push_back(1);
  assert(!mothershipPrepareRetainedRecoverySchema4Snapshot(
      dormantWithWork,schema4Request.plans,schema4Request.machines,request.bundleSHA,
      previousBundleSHA,schema4InterruptedSHA,oneSuccessor,schema4Proof,&failure));
  auto dormantWithoutWitness=dormantSeed;
  dormantWithoutWitness.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses.clear();
  assert(!mothershipPrepareRetainedRecoverySchema4Snapshot(
      dormantWithoutWitness,schema4Request.plans,schema4Request.machines,request.bundleSHA,
      previousBundleSHA,schema4InterruptedSHA,oneSuccessor,schema4Proof,&failure));
  auto schema4Master=schema4Witness;
  auto& schema4Update=schema4Master.masterAuthority.runtimeState.updateSelf;
  schema4Update.state=uint8_t(ProdigyPersistentUpdateSelfState::Phase::waitingForBundleEchos);
  schema4Update.expectedEchos=2; schema4Update.bundleEchos=2; schema4Update.bundleEchoPeerKeys={1,3};
  schema4Update.bundleBlob=schema4Blob; schema4Update.workerExpectedBundleSHA256=schema4InterruptedSHA;
  schema4Update.workerFailure.clear();
  for (auto& witness:schema4Update.machineRecoveryWitnesses) witness.bundleRegistered=witness.machineUUID==3;
  auto schema4Prepared=schema4Master;
  assert(mothershipPrepareRetainedRecoveryMixedInterruptedSnapshot(
      schema4Prepared,schema4Request.plans,schema4Request.machines,request.bundleSHA,
      previousBundleSHA,schema4InterruptedSHA,oneSuccessor,&failure,&schema4Proof));
  auto schema4UnexpectedFailure=schema4Master;
  schema4UnexpectedFailure.masterAuthority.runtimeState.updateSelf.workerFailure="unrelated failure"_ctv;
  assert(!mothershipPrepareRetainedRecoveryMixedInterruptedSnapshot(
      schema4UnexpectedFailure,schema4Request.plans,schema4Request.machines,request.bundleSHA,
      previousBundleSHA,schema4InterruptedSHA,oneSuccessor,&failure,&schema4Proof));
  // Exercise the exact framed local preparation path too: the proof and its
  // witnesses are request-digest sealed before the private snapshot is opened.
  const auto schema4Root=root/"schema-four"; std::filesystem::create_directories(schema4Root);
  const auto schema4State=(schema4Root/"state.new10").string(), schema4RequestPath=(schema4Root/"request").string();
  { ProdigyPersistentStateStore store(MothershipTidesMigration::text(schema4State)); assert(store.saveBrainSnapshot(schema4Master,&failure)); }
  std::filesystem::create_directories(schema4State+".secrets");
  Request schema4FileRequest=schema4Request; schema4FileRequest.interruptedBundleSHA=schema4InterruptedSHA;
  schema4FileRequest.mixedSuccessorMachineUUIDs=oneSuccessor;
  MothershipTidesMigration::Plan schema4Plan={}; schema4Plan.schemaVersion=4;
  schema4Plan.sealedCanonicalContainerCount=24; schema4Plan.staleCoordinatorCanonicalContainerCount=23; schema4Plan.sealedInterruptedExpectedEchos=2;
  schema4Plan.staleExcludedContainerUUID=schema4Proof.staleExcludedContainerUUID;
  const String schema4Bytes=encodeRequest(schema4FileRequest,schema4Plan);
  Request schema4Decoded={}; MothershipRetainedRecoveryMixedProof schema4DecodedProof={};
  assert(schema4Bytes.size()>4 && decodeRequest(MothershipTidesMigration::str(schema4Bytes),schema4Decoded,&schema4DecodedProof));
  assert(schema4Decoded.clusterUUID==schema4FileRequest.clusterUUID &&
         schema4Decoded.bundleSHA==schema4FileRequest.bundleSHA &&
         schema4Decoded.interruptedBundleSHA==schema4InterruptedSHA &&
         schema4Decoded.mixedSuccessorMachineUUIDs==oneSuccessor &&
         schema4DecodedProof.canonicalContainerCount==schema4Proof.canonicalContainerCount &&
         schema4DecodedProof.staleCoordinatorCanonicalContainerCount==schema4Proof.staleCoordinatorCanonicalContainerCount &&
         schema4DecodedProof.interruptedExpectedEchos==schema4Proof.interruptedExpectedEchos &&
         schema4DecodedProof.staleExcludedContainerUUID==schema4Proof.staleExcludedContainerUUID);
  // The retirement envelope is distinct from (and therefore cannot overwrite)
  // the immutable RRF4 evidence.  It binds the only allowed exclusion in its
  // own frame; ordinary RRF4 decoding reports no retired target.
  auto retiredRequest=schema4FileRequest; uint32_t removed=0;
  for(auto& machine:retiredRequest.machines) {
    Vector<ContainerParameters> retained; Vector<int64_t> created;
    for(uint32_t index=0;index<machine.parameters.size();++index) {
      if(machine.parameters[index].uuid==schema4Proof.staleExcludedContainerUUID) {++removed;continue;}
      retained.push_back(machine.parameters[index]); created.push_back(machine.observedCreatedAtMs[index]);
    }
    machine.parameters=std::move(retained); machine.observedCreatedAtMs=std::move(created);
  }
  assert(removed==1);
  const String retiredBytes=encodeRetiredConflictingClientRequest(retiredRequest,schema4Proof,schema4Proof.staleExcludedContainerUUID);
  Request retiredDecoded={}; MothershipRetainedRecoveryMixedProof retiredProof={}; uint128_t retiredUUID=0;
  assert(retiredBytes.size()>4 && decodeRequest(MothershipTidesMigration::str(retiredBytes),retiredDecoded,&retiredProof,&retiredUUID));
  assert(retiredUUID==schema4Proof.staleExcludedContainerUUID && retiredDecoded.machines.size()==3 &&
         retiredProof.staleExcludedContainerUUID==schema4Proof.staleExcludedContainerUUID);
  MothershipTidesMigration::durable(schema4RequestPath,schema4Bytes);
  WitnessSet schema4Sealed={}; schema4Sealed.requestSHA=MothershipTidesMigration::text(MothershipTidesMigration::digest(schema4RequestPath));
  schema4Sealed.witnesses=schema4Prepared.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
  BitseryEngine::serialize(bytes,schema4Sealed); MothershipTidesMigration::durable(schema4RequestPath+".witnesses",bytes);
  const bool schema4LocalPrepared=prepareLocal(
      schema4RequestPath.c_str(),schema4State.c_str(),false,&failure,previousBundleSHA);
  if (!schema4LocalPrepared)
    std::fprintf(stderr,"schema-four local preparation: %s\n",failure.c_str());
  assert(schema4LocalPrepared);
  auto activeHandoff=schema4Master;
  activeHandoff.masterAuthority.runtimeState.updateSelf.state=uint8_t(ProdigyPersistentUpdateSelfState::Phase::waitingForFollowerReboots);
  assert(!mothershipPrepareRetainedRecoveryMixedInterruptedSnapshot(
      activeHandoff,schema4Request.plans,schema4Request.machines,request.bundleSHA,
      previousBundleSHA,schema4InterruptedSHA,oneSuccessor,&failure,&schema4Proof));
  auto staleWizard=schema4Witness;
  auto& staleUpdate=staleWizard.masterAuthority.runtimeState.updateSelf;
  staleUpdate={}; staleUpdate.workerExpectedBundleSHA256=previousBundleSHA;
  staleUpdate.workerFailure="local post-exec bundle digest mismatch"_ctv;
  staleUpdate.machineRecoveryWitnesses=schema4Witness.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
  staleUpdate.machineRecoveryWitnesses[0].containerBootstraps.pop_back();
  for (auto& witness:staleUpdate.machineRecoveryWitnesses) witness.bundleRegistered=false;
  assert(mothershipRetainedRecoveryCanReplaceMixedFailedCoordinator(staleWizard,previousBundleSHA,schema4Proof,schema4Witness.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses));
  auto staleWrongDigest=staleWizard;
  staleWrongDigest.masterAuthority.runtimeState.updateSelf.workerExpectedBundleSHA256=schema4InterruptedSHA;
  assert(!mothershipRetainedRecoveryCanReplaceMixedFailedCoordinator(staleWrongDigest,previousBundleSHA,schema4Proof,schema4Witness.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses));
  auto staleUnknown=staleWizard;
  staleUnknown.masterAuthority.runtimeState.updateSelf.workerMachineUUIDs.push_back(1);
  assert(!mothershipRetainedRecoveryCanReplaceMixedFailedCoordinator(staleUnknown,previousBundleSHA,schema4Proof,schema4Witness.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses));
  auto staleChanged=staleWizard;
  staleChanged.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].bundleRegistered=true;
  assert(!mothershipRetainedRecoveryCanReplaceMixedFailedCoordinator(staleChanged,previousBundleSHA,schema4Proof,schema4Witness.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses));
  auto staleCrossMachine=staleWizard;
  auto moved=staleCrossMachine.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].containerBootstraps.back();
  staleCrossMachine.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].containerBootstraps.pop_back();
  staleCrossMachine.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[1].containerBootstraps.push_back(std::move(moved));
  assert(!mothershipRetainedRecoveryCanReplaceMixedFailedCoordinator(staleCrossMachine,previousBundleSHA,schema4Proof,schema4Witness.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses));

  auto mixedCoordinator=snapshot;
  auto& mixedUpdate=mixedCoordinator.masterAuthority.runtimeState.updateSelf;
  mixedUpdate.state=uint8_t(ProdigyPersistentUpdateSelfState::Phase::waitingForFollowerReboots);
  mixedUpdate.expectedEchos=2;
  mixedUpdate.bundleEchos=2;
  mixedUpdate.bundleEchoPeerKeys=mixedSuccessors;
  mixedUpdate.followerRebootedPeerKeys=mixedSuccessors;
  for (uint128_t peer : mixedSuccessors) {
    ProdigyPersistentUpdateSelfFollowerBoot boot={};boot.peerKey=peer;boot.bootNs=int64_t(peer);
    mixedUpdate.followerBootNsByPeerKey.push_back(boot);
  }
  mixedUpdate.workerExpectedBundleSHA256=interruptedBundleSHA;
  mixedUpdate.machineRecoveryWitnesses=mixedWitness.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
  mixedUpdate.workerFailure="local post-exec bundle digest mismatch"_ctv;
  for (auto& witness : mixedUpdate.machineRecoveryWitnesses)
    witness.bundleRegistered = witness.machineUUID == 2 || witness.machineUUID == 3;
  const auto mixedExpectedWitnesses=mixedUpdate.machineRecoveryWitnesses;
  assert(mothershipRetainedRecoveryCanReplaceMixedHandoff(
      mixedCoordinator,interruptedBundleSHA,mixedExpectedWitnesses,mixedSuccessors));
  // Recovery observes a later timestamp and inventory order than the saved
  // process state.  Matching remains UUID-bound and every other bootstrap
  // field remains subject to the existing semantic equality owner.
  auto mixedReordered=mixedCoordinator;
  auto mixedReorderedExpected=mixedExpectedWitnesses;
  auto appendValidReorderBootstrap = [&](Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness>& witnesses) {
    auto parameters=request.machines[0].parameters[0];
    parameters.uuid+=uint128_t(1000); parameters.private6.network.v6[15]=2;
    NeuronContainerBootstrap bootstrap={}; String bootstrapFailure;
    const auto deployment=request.plans.find(parameters.deploymentID);
    assert(deployment!=request.plans.end());
    assert(prodigyBuildRetainedContainerBootstrap(
        deployment->second,parameters,request.machines[0].machineFragment,
        snapshot.brainConfig.datacenterFragment,request.machines[0].observedCreatedAtMs[0],
        bootstrap,&bootstrapFailure));
    for (const auto& encoded : witnesses[0].containerBootstraps) {
      NeuronContainerBootstrap existing={}; assert(BitseryEngine::deserializeSafe(encoded,existing));
      assert(existing.plan.uuid!=bootstrap.plan.uuid);
    }
    String encoded; BitseryEngine::serialize(encoded,bootstrap);
    witnesses[0].containerBootstraps.push_back(std::move(encoded));
  };
  appendValidReorderBootstrap(mixedReordered.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses);
  appendValidReorderBootstrap(mixedReorderedExpected);
  auto& reorderedBootstraps=mixedReordered.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].containerBootstraps;
  assert(reorderedBootstraps.size() > 1);
  for (auto& encoded : reorderedBootstraps) {
    NeuronContainerBootstrap bootstrap={}; assert(BitseryEngine::deserializeSafe(encoded,bootstrap));
    ++bootstrap.plan.createdAtMs; BitseryEngine::serialize(encoded,bootstrap);
  }
  std::swap(reorderedBootstraps[0],reorderedBootstraps[1]);
  assert(mothershipRetainedRecoveryCanReplaceMixedHandoff(
      mixedReordered,interruptedBundleSHA,mixedReorderedExpected,mixedSuccessors));
  auto mixedStableFieldChanged=mixedReordered;
  String& changedBootstrap=mixedStableFieldChanged.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].containerBootstraps[0];
  NeuronContainerBootstrap changed={}; assert(BitseryEngine::deserializeSafe(changedBootstrap,changed));
  ++changed.plan.config.memoryMB; BitseryEngine::serialize(changedBootstrap,changed);
  assert(!mothershipRetainedRecoveryCanReplaceMixedHandoff(
      mixedStableFieldChanged,interruptedBundleSHA,mixedReorderedExpected,mixedSuccessors));
  auto mixedPrepared=mixedCoordinator;
  assert(mothershipPrepareRetainedRecoveryMixedHandoffSnapshot(
      mixedPrepared,request.plans,request.machines,request.bundleSHA,previousBundleSHA,
      interruptedBundleSHA,mixedSuccessors,&failure));
  // The exceptional proof removes only the exact, validated update record.
  // Snapshot equality covers the topology, plans, config, paired credentials,
  // and runtime key material under the normal persistent-state owner.
  auto mixedExpected=mixedCoordinator;
  mixedExpected.masterAuthority.runtimeState.updateSelf={};
  assert(mothershipPrepareRetainedRecoverySnapshot(
      mixedExpected,request.plans,request.machines,request.bundleSHA,&failure));
  assert(prodigyPersistentBrainSnapshotsEqual(mixedPrepared,mixedExpected));
  assert(mothershipRetainedRecoveryEnvelopeMatches(
      mixedPrepared.masterAuthority.runtimeState.updateSelf,request.bundleSHA));
  auto mixedWrongPeer=mixedCoordinator;
  mixedWrongPeer.masterAuthority.runtimeState.updateSelf.followerRebootedPeerKeys[1]=1;
  assert(!mothershipRetainedRecoveryCanReplaceMixedHandoff(
      mixedWrongPeer,interruptedBundleSHA,mixedExpectedWitnesses,mixedSuccessors));
  auto mixedTransition=mixedCoordinator;
  mixedTransition.masterAuthority.runtimeState.updateSelf.workerTransitionIssuedMachineUUIDs.push_back(2);
  assert(!mothershipRetainedRecoveryCanReplaceMixedHandoff(
      mixedTransition,interruptedBundleSHA,mixedExpectedWitnesses,mixedSuccessors));
  auto preexistingSnapshot=preparedSnapshot;
  String& originalBootstrap=preexistingSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].containerBootstraps[0];
  NeuronContainerBootstrap decodedBootstrap = {};assert(BitseryEngine::deserializeSafe(originalBootstrap,decodedBootstrap));
  NeuronContainerBootstrap reorderedBootstrap=decodedBootstrap;
  Vector<std::pair<uint64_t,Vector<SubscriptionPairing>>> subscriptionPairings = {};
  for(const auto& [service,pairings]:decodedBootstrap.plan.subscriptionPairings) subscriptionPairings.emplace_back(service,pairings);
  reorderedBootstrap.plan.subscriptionPairings.clear();
  for(auto iterator=subscriptionPairings.rbegin();iterator!=subscriptionPairings.rend();++iterator)
    for(const SubscriptionPairing& pairing:iterator->second) reorderedBootstrap.plan.subscriptionPairings.insert(iterator->first,pairing);
  String reorderedBytes = {};BitseryEngine::serialize(reorderedBytes,reorderedBootstrap);
  assert(!originalBootstrap.equals(reorderedBytes));
  originalBootstrap=std::move(reorderedBytes);
  assert(prodigyPersistentRetainedBootstrapEqual(decodedBootstrap,reorderedBootstrap));
  // Save the interrupted normal update, rather than the recovery envelope.
  // prepareLocal must replace it once, then recognize its own envelope on
  // retry without touching unrelated deployment or credential authority.
  { ProdigyPersistentStateStore store(MothershipTidesMigration::text(statePath)); assert(store.saveBrainSnapshot(laggingEchoSnapshot,&failure)); }
  std::filesystem::create_directories(statePath+".secrets");
  BitseryEngine::serialize(bytes,request);MothershipTidesMigration::durable(requestPath,bytes);
  WitnessSet sealed;sealed.requestSHA=MothershipTidesMigration::text(MothershipTidesMigration::digest(requestPath));
  sealed.witnesses=preparedSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
  BitseryEngine::serialize(bytes,sealed);MothershipTidesMigration::durable(requestPath+".witnesses",bytes);
  const bool prepared=prepareLocal(requestPath.c_str(),statePath.c_str(),false,&failure);
  if(!prepared)std::fprintf(stderr,"private recovery preparation: %s\n",failure.c_str());
  assert(prepared);
  ProdigyPersistentBrainSnapshot after;loadSnapshot(statePath,after);
  assert(after.masterAuthority.runtimeState.generation==1 && after.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses.size()==3);
  assert(after.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].containerBootstraps[0].equals(sealed.witnesses[0].containerBootstraps[0]));
  assert(prodigyPersistentBrainSnapshotsEqual(after,preparedSnapshot));
  assert(after.masterAuthority.apiCredentialSetsByApp[77].credentials[0].metadata==credential.metadata);
  // A saved request is an idempotent retry even if its outer marker was lost.
  assert(prepareLocal(requestPath.c_str(),statePath.c_str(),false,&failure));
  assert(prepareLocal(requestPath.c_str(),statePath.c_str(),true,&failure));
  ProdigyPersistentBrainSnapshot afterRetry;loadSnapshot(statePath,afterRetry);
  assert(prodigyPersistentBrainSnapshotsEqual(after,afterRetry));
  // The private database can already contain the same recovery envelope with
  // unordered plan maps encoded in a different iteration order. Semantic
  // witness matching accepts it, then rewrites the exact sealed bytes.
  { ProdigyPersistentStateStore store(MothershipTidesMigration::text(statePath)); assert(store.saveBrainSnapshot(preexistingSnapshot,&failure)); }
  assert(prepareLocal(requestPath.c_str(),statePath.c_str(),false,&failure));
  assert(prepareLocal(requestPath.c_str(),statePath.c_str(),true,&failure));
  ProdigyPersistentBrainSnapshot afterReordered;loadSnapshot(statePath,afterReordered);
  assert(prodigyPersistentBrainSnapshotsEqual(after,afterReordered));
  assert(afterReordered.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].containerBootstraps[0].equals(sealed.witnesses[0].containerBootstraps[0]));
  request.machines[0].parameters[0].memoryMB+=1;
  BitseryEngine::serialize(bytes,request);MothershipTidesMigration::durable(requestPath,bytes);
  assert(!prepareLocal(requestPath.c_str(),statePath.c_str(),true,&failure));
  std::filesystem::remove_all(root);
  return 0;
}
