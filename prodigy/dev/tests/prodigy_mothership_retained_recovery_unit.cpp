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

int main()
{
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
      std::string json="{\"schemaVersion\":1,\"clusterUUID\":\"0x7\",\"bundleSHA256\":\""+std::string(64,'a')+"\",\"machines\":[";
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
  MothershipTidesMigration::Machine plannedMachine = {}; plannedMachine.uuid=3; plannedMachine.linuxID="0123456789abcdef0123456789abcdef"; plannedMachine.address="fd72::1"; predecessorPlan.machines.push_back(plannedMachine); successorPlan.machines.push_back(plannedMachine);
  assert(samePlanTarget(predecessorPlan,successorPlan)); successorPlan.operationRoot=predecessorPlan.operationRoot;
  assert(!samePlanTarget(predecessorPlan,successorPlan));
  successorPlan.operationRoot="/root/new";
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
