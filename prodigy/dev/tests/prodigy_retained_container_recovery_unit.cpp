#include <cassert>
#include <cstdio>
#include <cstring>

#include <prodigy/persistent.state.h>
#include <prodigy/container.contract.h>
#include <prodigy/retained.container.recovery.h>
#include <prodigy/neuron/neuron.h>

#include <filesystem>
#include <fstream>
#include <sys/eventfd.h>
#include <unistd.h>

// This fixture deliberately stops before gateway recovery admission.  It
// models the handoff after a Brain-control replacement: an exact retained
// process still owns its cgroup, but it must not become restore-current until
// the replacement stream supplies an authenticated stateUpload replay.
class RetainedGatewayInventoryNeuron final : public Neuron {
public:
  String inventoryRoot = {};
  NeuronBrainControlStream *retiredBrain = nullptr;

  ~RetainedGatewayInventoryNeuron()
  {
    delete brain;
    delete retiredBrain;
  }

  String containerCgroupInventoryRoot(void) const override { return inventoryRoot; }

  bool installPendingRetainedGateway(const std::filesystem::path& root, uint128_t containerUUID,
                                     pid_t pid)
  {
    inventoryRoot.assign(root.c_str());
    brain = new NeuronBrainControlStream();
    brain->connected = true;
    brain->fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (brain->fd < 0) return false;

    auto container = std::make_unique<Container>();
    container->plan.uuid = containerUUID;
    container->plan.system.kind = SystemContainerKind::crossClusterMasqueGateway;
    container->name.assignItoa(containerUUID);
    container->pid = pid;
    const std::filesystem::path leaf = root / (std::to_string(uint64_t(containerUUID)) + ".slice") / "leaf";
    container->cgroup = Filesystem::openDirectoryAt(-1, String(leaf.c_str()));
    container->pidfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (container->cgroup < 0 || container->pidfd < 0) return false;

    const uint64_t admission = beginPendingContainerLaunch(container->plan);
    if (admission == 0) return false;
    stateUploadRestoreEpoch = 1;
    auto operation = std::make_unique<StateUploadRestoreOperation>();
    operation->container = std::move(container);
    operation->fragment = lcsubnet6;
    operation->epoch = stateUploadRestoreEpoch;
    operation->stream = brain;
    operation->streamGeneration = brain->ioGeneration;
    operation->requestedStream = brain;
    operation->requestedGeneration = brain->ioGeneration;
    operation->launchAdmissionGeneration = admission;
    pendingStateUploadRestores.insert_or_assign(containerUUID, std::move(operation));
    return true;
  }

  void replaceControlWithoutReplay(void)
  {
    fenceStateUploadRestoresForControl(brain);
    resetContainerLaunchControlForBrainReplacement();
    retiredBrain = brain;
    brain = new NeuronBrainControlStream();
    brain->connected = true;
    brain->fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  }

  bool inventoryCompleteForTest(String& failure) const { return liveContainerInventoryComplete(failure); }

  bool restoreStillFencedForTest(uint128_t containerUUID)
  {
    const auto found = pendingStateUploadRestores.find(containerUUID);
    return found != pendingStateUploadRestores.end() && found->second != nullptr &&
        found->second->container != nullptr &&
        !stateUploadRestoreCurrent(*found->second, containerUUID) &&
        crossClusterMasqueGatewayListenerForContainer(containerUUID) == nullptr;
  }
};

static DeploymentPlan deployment(bool stateful)
{
  DeploymentPlan plan = {};
  plan.config.type = stateful ? ApplicationType::stateful : ApplicationType::stateless;
  plan.config.applicationID = 77;
  plan.config.versionID = 9;
  plan.config.memoryMB = 256;
  plan.config.storageMB = 128;
  plan.config.nLogicalCores = 1;
  plan.isStateful = stateful;
  if (stateful)
  {
    plan.stateful.clientPrefix = 0x1100000000000000ULL;
    plan.stateful.siblingPrefix = 0x1200000000000000ULL;
    plan.stateful.cousinPrefix = 0x1300000000000000ULL;
    plan.stateful.seedingPrefix = 0x1400000000000000ULL;
    plan.stateful.shardingPrefix = 0x1500000000000000ULL;
    plan.stateful.neverShard = true;
    plan.stateful.writerMode = StatefulWriterMode::allMasters;
  }
  return plan;
}

static ContainerParameters parametersFor(const DeploymentPlan& deployment)
{
  ContainerParameters parameters = {};
  parameters.uuid = 0x7711;
  parameters.deploymentID = deployment.config.deploymentID();
  parameters.memoryMB = deployment.config.memoryMB;
  parameters.storageMB = deployment.config.storageMB;
  parameters.nLogicalCores = uint16_t(applicationSharedCPUCoreHint(deployment.config));
  parameters.cpuMode = deployment.config.cpuMode;
  parameters.requestedCPUMillis = applicationRequestedCPUMillis(deployment.config);
  parameters.private6.network.is6 = true;
  parameters.private6.cidr = 128;
  std::memcpy(parameters.private6.network.v6, container_network_subnet6.value, 11);
  parameters.private6.network.v6[11] = 7;
  parameters.private6.network.v6[12] = 0x01;
  parameters.private6.network.v6[13] = 0x02;
  parameters.private6.network.v6[14] = 0x03;
  parameters.private6.network.v6[15] = 4;
  if (deployment.isStateful)
  {
    parameters.statefulMeshRoles = StatefulMeshRoles::forShardGroup(deployment.stateful, deployment.config.applicationID, 0);
    parameters.statefulMeshRoles.cousin = 0;
    parameters.statefulMeshRoles.sharding = 0;
    parameters.statefulMeshRoles.topologyBridge = 0;
    parameters.statefulTopology.shardGroup = 0;
    parameters.statefulTopology.workerCount = prodigyStatefulWorkerCountForLogicalCores(deployment.config.nLogicalCores);
    parameters.statefulTopology.topologyEpoch = parameters.statefulTopology.workerCount;
    parameters.statefulTopology.sourceEpoch = parameters.statefulTopology.workerCount;
    parameters.statefulTopology.targetEpoch = parameters.statefulTopology.workerCount;
    parameters.statefulTopology.servingMode = StatefulTopologyServingMode::serve;
    parameters.advertisesOnPorts[parameters.statefulMeshRoles.sibling] = 12001;
    parameters.advertisesOnPorts[parameters.statefulMeshRoles.seeding] = 12002;
    parameters.advertisesOnPorts[parameters.statefulMeshRoles.client] = 12003;
  }
  return parameters;
}

static constexpr uint8_t datacenterFragment = 7;
static constexpr uint32_t machineFragment = 0x010203;
static constexpr int64_t observedCreatedAtMs = 1790039900000LL;

static void expectValidStateless(void)
{
  DeploymentPlan plan = deployment(false);
  ContainerParameters parameters = parametersFor(plan);
  NeuronContainerBootstrap bootstrap = {};
  String failure = {};
  assert(prodigyBuildRetainedContainerBootstrap(plan, parameters, machineFragment, datacenterFragment, observedCreatedAtMs, bootstrap, &failure));
  assert(bootstrap.plan.uuid == parameters.uuid);
  assert(bootstrap.plan.config.deploymentID() == parameters.deploymentID);
  assert(bootstrap.plan.lifetime == ApplicationLifetime::base);
  assert(bootstrap.plan.state == ContainerState::scheduled && bootstrap.plan.runtimeReady == false);
  assert(bootstrap.plan.createdAtMs == observedCreatedAtMs);
  assert(bootstrap.plan.addresses.size() == 1 && bootstrap.plan.fragment == 4);
}

static void expectValidStateful(void)
{
  DeploymentPlan plan = deployment(true);
  ContainerParameters parameters = parametersFor(plan);
  NeuronContainerBootstrap bootstrap = {};
  String failure = {};
  assert(prodigyBuildRetainedContainerBootstrap(plan, parameters, machineFragment, datacenterFragment, observedCreatedAtMs, bootstrap, &failure));
  assert(bootstrap.plan.isStateful && bootstrap.plan.nShardGroups == 1 && bootstrap.plan.shardGroup == 0);
  assert(bootstrap.plan.advertisements.size() == 3);
  assert(bootstrap.plan.statefulMeshRoles.cousin == 0 && bootstrap.plan.statefulMeshRoles.sharding == 0);
}

static void expectReplicaAndShardableRecovery()
{
  DeploymentPlan plan=deployment(true);plan.stateful.writerMode = StatefulWriterMode::localSingleWriter;plan.stateful.neverShard=false;
  auto parameters=parametersFor(plan);
  const auto roles=StatefulMeshRoles::forShardGroup(plan.stateful,plan.config.applicationID,0);
  parameters.statefulMeshRoles=roles;parameters.statefulMeshRoles.client=0;parameters.statefulMeshRoles.topologyBridge=0;
  parameters.advertisesOnPorts.erase(roles.client);
  parameters.advertisesOnPorts[roles.cousin]=12004;parameters.advertisesOnPorts[roles.sharding]=12005;
  NeuronContainerBootstrap bootstrap;String failure;
  const bool okay=prodigyBuildRetainedContainerBootstrap(plan,parameters,machineFragment,datacenterFragment,observedCreatedAtMs,bootstrap,&failure);
  if (!okay) std::fprintf(stderr,"replica reconstruction: %s\n",failure.c_str());
  assert(okay);
  assert(bootstrap.plan.statefulMeshRoles.client==0 && bootstrap.plan.advertisements.size()==4);
  parameters.statefulTopology.operationID=99;
  assert(!prodigyBuildRetainedContainerBootstrap(plan,parameters,machineFragment,datacenterFragment,observedCreatedAtMs,bootstrap,&failure));
}
static void expectCompactStartupCPURecovery()
{
  DeploymentPlan plan=deployment(false);plan.config.cpuMode=ApplicationCPUMode::shared;plan.config.sharedCPUMillis=250;
  auto parameters=parametersFor(plan);String raw;assert(ProdigyWire::serializeContainerParameters(raw,parameters));
  ContainerParameters decoded;assert(ProdigyWire::deserializeStartupContainerParameters(raw,decoded));
  assert(decoded.requestedCPUMillis==0);
  prodigyRestoreRetainedStartupCPUFields(raw,plan,decoded);
  NeuronContainerBootstrap bootstrap;String failure;
  assert(prodigyBuildRetainedContainerBootstrap(plan,decoded,machineFragment,datacenterFragment,observedCreatedAtMs,bootstrap,&failure));
}

static void expectGraphReplicaRecovery()
{
  for (uint16_t app : {uint16_t(2), uint16_t(5)}) {
    DeploymentPlan plan = deployment(true);
    plan.config.applicationID = app; plan.stateful.writerMode = StatefulWriterMode::localSingleWriter;
    plan.stateful.seedingAlways = true;
    plan.stateful.clientPrefix = 0;
    plan.stateful.siblingPrefix = prodigyRuntimeStatefulServicePrefix(app, 2);
    plan.stateful.cousinPrefix = prodigyRuntimeStatefulServicePrefix(app, 3);
    plan.stateful.seedingPrefix = prodigyRuntimeStatefulServicePrefix(app, 4);
    plan.stateful.shardingPrefix = prodigyRuntimeStatefulServicePrefix(app, 5);
    plan.whiteholes.emplace_back();
    assert(prodigyGraphDeploymentPlanCanonical(plan, true));
    auto parameters = parametersFor(plan);
    parameters.advertisesOnPorts.erase(0);
    parameters.statefulTopology.servingMode = StatefulTopologyServingMode::catchupOnly;
    Whitehole egress = plan.whiteholes[0]; egress.hasAddress = true;
    egress.address = IPAddress("2001:db8::7", true); egress.sourcePort = 12009; egress.bindingNonce = 91;
    parameters.whiteholes.push_back(egress);
    NeuronContainerBootstrap bootstrap; String failure;
    auto recover = [&](const ContainerParameters& candidate) {
      return prodigyBuildRetainedContainerBootstrap(plan, candidate, machineFragment, datacenterFragment,
          observedCreatedAtMs, bootstrap, &failure);
    };
    assert(recover(parameters));
    assert(bootstrap.plan.shardGroup == 0 && bootstrap.plan.nShardGroups == 1 &&
        bootstrap.plan.statefulMeshRoles.client == 0 && bootstrap.plan.advertisements.size() == 2 &&
        bootstrap.plan.whiteholes[0].bindingNonce == egress.bindingNonce &&
        bootstrap.plan.statefulTopology.servingMode == StatefulTopologyServingMode::catchupOnly);
    String encoded; BitseryEngine::serialize(encoded, parameters); ContainerParameters readback;
    assert(BitseryEngine::deserializeSafe(encoded, readback) && recover(readback));
    auto bad = parameters; bad.statefulTopology.shardGroup = 1; assert(!recover(bad));
    bad = parameters; bad.statefulTopology.servingMode = StatefulTopologyServingMode::serve; assert(!recover(bad));
    bad = parameters; ++bad.statefulTopology.topologyEpoch; assert(!recover(bad));
    bad = parameters; bad.statefulMeshRoles.client = prodigyRuntimeStatefulServicePrefix(app, 1); assert(!recover(bad));
    bad = parameters; bad.advertisesOnPorts[prodigyRuntimeStatefulServicePrefix(app, 1)] = 12003; assert(!recover(bad));
    bad = parameters; bad.whiteholes[0].bindingNonce = 0; assert(!recover(bad));
    assert(!prodigyGraphTopologyCanonical(plan, parameters.statefulTopology, 2));
    plan.config.applicationID = 10;
    assert(!prodigyGraphDeploymentPlanCanonical(plan, true));
  }
}

static void expectGraphAllMastersRecovery()
{
  for (uint16_t app : {uint16_t(2), uint16_t(5)}) {
    DeploymentPlan plan = deployment(true);
    plan.config.applicationID = app;
    plan.stateful.writerMode = StatefulWriterMode::allMasters;
    plan.stateful.seedingAlways = false;
    plan.stateful.clientPrefix = prodigyRuntimeStatefulServicePrefix(app, 1);
    plan.stateful.siblingPrefix = prodigyRuntimeStatefulServicePrefix(app, 2);
    plan.stateful.cousinPrefix = prodigyRuntimeStatefulServicePrefix(app, 3);
    plan.stateful.seedingPrefix = prodigyRuntimeStatefulServicePrefix(app, 4);
    plan.stateful.shardingPrefix = prodigyRuntimeStatefulServicePrefix(app, 5);
    assert(prodigyGraphDeploymentPlanCanonical(plan, false));
    assert(!prodigyGraphDeploymentPlanCanonical(plan, true));
    auto parameters = parametersFor(plan);
    NeuronContainerBootstrap bootstrap; String failure;
    assert(prodigyBuildRetainedContainerBootstrap(plan, parameters, machineFragment, datacenterFragment,
        observedCreatedAtMs, bootstrap, &failure));
    const auto generated = StatefulMeshRoles::forShardGroup(plan.stateful, app, 0);
    assert(bootstrap.plan.statefulMeshRoles.client == generated.client);
    assert(bootstrap.plan.statefulMeshRoles.seeding == generated.seeding);
    assert(bootstrap.plan.statefulMeshRoles.cousin == 0 && bootstrap.plan.statefulMeshRoles.sharding == 0);
    assert(bootstrap.plan.nShardGroups == 1 && bootstrap.plan.shardGroup == 0);
    assert(bootstrap.plan.whiteholes.empty());
    auto badPlan = plan; badPlan.stateful.clientPrefix = 0;
    assert(!prodigyGraphDeploymentPlanCanonical(badPlan, false));
    badPlan = plan; ++badPlan.stateful.siblingPrefix;
    assert(!prodigyGraphDeploymentPlanCanonical(badPlan, false));
    badPlan = plan; ++badPlan.stateful.seedingPrefix;
    assert(!prodigyGraphDeploymentPlanCanonical(badPlan, false));
    badPlan = plan; badPlan.stateful.seedingAlways = true;
    assert(!prodigyGraphDeploymentPlanCanonical(badPlan, false));
    badPlan = plan; badPlan.whiteholes.emplace_back();
    assert(!prodigyGraphDeploymentPlanCanonical(badPlan, false));
    auto badParameters = parameters; badParameters.statefulTopology.shardGroup = 1;
    assert(!prodigyBuildRetainedContainerBootstrap(plan, badParameters, machineFragment, datacenterFragment,
        observedCreatedAtMs, bootstrap, &failure));
    badParameters = parameters; badParameters.statefulTopology.servingMode = StatefulTopologyServingMode::catchupOnly;
    assert(!prodigyBuildRetainedContainerBootstrap(plan, badParameters, machineFragment, datacenterFragment,
        observedCreatedAtMs, bootstrap, &failure));
    assert(!prodigyGraphTopologyCanonical(plan, parameters.statefulTopology, 2));
  }
}

static void expectLegacyGraphWriterEgressRecovery()
{
  for (uint16_t app : {uint16_t(2), uint16_t(5)}) {
    DeploymentPlan plan = deployment(true);
    plan.config.applicationID = app; plan.stateful.writerMode = StatefulWriterMode::localSingleWriter; plan.stateful.seedingAlways = true;
    plan.stateful.clientPrefix = prodigyRuntimeStatefulServicePrefix(app, 1);
    plan.stateful.siblingPrefix = prodigyRuntimeStatefulServicePrefix(app, 2);
    plan.stateful.cousinPrefix = prodigyRuntimeStatefulServicePrefix(app, 3);
    plan.stateful.seedingPrefix = prodigyRuntimeStatefulServicePrefix(app, 4);
    plan.stateful.shardingPrefix = prodigyRuntimeStatefulServicePrefix(app, 5);
    plan.whiteholes.emplace_back();
    assert(prodigyGraphDeploymentPlanCanonical(plan, false));
    auto parameters = parametersFor(plan);
    Whitehole egress = plan.whiteholes[0]; egress.hasAddress = true;
    egress.address = IPAddress("2001:db8::8", true); egress.sourcePort = 12010; egress.bindingNonce = 92;
    parameters.whiteholes.push_back(egress);
    NeuronContainerBootstrap bootstrap; String failure;
    assert(prodigyBuildRetainedContainerBootstrap(plan, parameters, machineFragment, datacenterFragment,
        observedCreatedAtMs, bootstrap, &failure));
    auto bad = parameters; bad.whiteholes.clear();
    assert(!prodigyBuildRetainedContainerBootstrap(plan, bad, machineFragment, datacenterFragment,
        observedCreatedAtMs, bootstrap, &failure));
    bad = parameters; bad.whiteholes[0].bindingNonce = 0;
    assert(!prodigyBuildRetainedContainerBootstrap(plan, bad, machineFragment, datacenterFragment,
        observedCreatedAtMs, bootstrap, &failure));
  }
}

static void expectColdInventoryRejectsRetainedUnownedProcesses()
{
  const auto scratch = std::filesystem::current_path() / ".run";
  std::filesystem::create_directories(scratch);
  std::string temporary = (scratch / "prodigy-inventory-unit-XXXXXX").string();
  const char *created = mkdtemp(temporary.data());
  assert(created);
  const std::filesystem::path root = created;
  String failure;
  bool knowsOwner = false;
  auto owner = [&](const std::string& name, pid_t pid) {
    return knowsOwner && name == "7711" && pid == 123;
  };
  assert(prodigyContainerInventoryCgroupsOwned(root / "missing", owner, failure));
  assert(prodigyContainerInventoryCgroupsOwned(root, owner, failure));
  const auto slice = root / "7711.slice";
  std::filesystem::create_directories(slice / "leaf");
  std::ofstream(slice / "cgroup.events") << "populated 1\nfrozen 0\n";
  std::ofstream(slice / "leaf" / "cgroup.procs") << "456\n123\n";
  // Regression: a cold empty map must not release the Brain recovery barrier.
  assert(!prodigyContainerInventoryCgroupsOwned(root, owner, failure));
  assert(failure.size() > 0);
  knowsOwner = true;
  assert(prodigyContainerInventoryCgroupsOwned(root, owner, failure));
  // A stale PID or an unreported second slice is not a complete inventory.
  std::ofstream(slice / "leaf" / "cgroup.procs") << "456\n";
  assert(!prodigyContainerInventoryCgroupsOwned(root, owner, failure));
  std::ofstream(slice / "leaf" / "cgroup.procs") << "123\n";
  const auto extra = root / "8822.slice";
  std::filesystem::create_directories(extra / "leaf");
  std::ofstream(extra / "cgroup.events") << "populated 1\nfrozen 0\n";
  std::ofstream(extra / "leaf" / "cgroup.procs") << "789\n";
  assert(!prodigyContainerInventoryCgroupsOwned(root, owner, failure));
  std::ofstream(extra / "cgroup.events") << "populated 0\nfrozen 0\n";
  assert(prodigyContainerInventoryCgroupsOwned(root, owner, failure));
  std::filesystem::remove(slice / "leaf" / "cgroup.procs");
  assert(!prodigyContainerInventoryCgroupsOwned(root, owner, failure));
  std::filesystem::remove_all(root);
}

static void expectRetainedGatewayRemainsInventoryOwnedAcrossControlReplacement()
{
  const auto scratch = std::filesystem::current_path() / ".run";
  std::filesystem::create_directories(scratch);
  std::string temporary = (scratch / "prodigy-retained-gateway-inventory-XXXXXX").string();
  char *created = mkdtemp(temporary.data());
  assert(created != nullptr);
  const std::filesystem::path root = created;
  constexpr uint128_t containerUUID = uint128_t(0x7711);
  constexpr pid_t retainedPID = 4242;
  const auto leaf = root / "30481.slice" / "leaf";
  std::filesystem::create_directories(leaf);
  std::ofstream(root / "30481.slice" / "cgroup.events") << "populated 1\nfrozen 0\n";
  std::ofstream(leaf / "cgroup.procs") << retainedPID << "\n";

  RetainedGatewayInventoryNeuron neuron = {};
  assert(neuron.installPendingRetainedGateway(root, containerUUID, retainedPID));
  neuron.replaceControlWithoutReplay();

  String failure = {};
  // The exact pending launch/PID/cgroup still owns the observed process, so
  // the first stateUpload must be eligible to report it to the replacement
  // stream.  It remains restore-fenced until that authenticated replay.
  assert(neuron.inventoryCompleteForTest(failure));
  assert(neuron.restoreStillFencedForTest(containerUUID));
  std::filesystem::remove_all(root);
}

int main()
{
  expectGraphReplicaRecovery();
  expectGraphAllMastersRecovery();
  expectLegacyGraphWriterEgressRecovery();
  expectColdInventoryRejectsRetainedUnownedProcesses();
  expectRetainedGatewayRemainsInventoryOwnedAcrossControlReplacement();
  expectCompactStartupCPURecovery();
  expectReplicaAndShardableRecovery();
  expectValidStateless();
  expectValidStateful();

  DeploymentPlan plan = deployment(false);
  ContainerParameters parameters = parametersFor(plan);
  NeuronContainerBootstrap bootstrap = {};
  String failure = {};

  parameters.deploymentID += 1;
  assert(prodigyBuildRetainedContainerBootstrap(plan, parameters, machineFragment, datacenterFragment, observedCreatedAtMs, bootstrap, &failure) == false);
  parameters = parametersFor(plan);
  parameters.memoryMB += 1;
  assert(prodigyBuildRetainedContainerBootstrap(plan, parameters, machineFragment, datacenterFragment, observedCreatedAtMs, bootstrap, &failure) == false);
  parameters = parametersFor(plan);
  parameters.private6.network.v6[14] ^= 1;
  assert(prodigyBuildRetainedContainerBootstrap(plan, parameters, machineFragment, datacenterFragment, observedCreatedAtMs, bootstrap, &failure) == false);

  DeploymentPlan stateful = deployment(true);
  parameters = parametersFor(stateful);
  parameters.statefulMeshRoles.cousin = StatefulMeshRoles::forShardGroup(stateful.stateful, stateful.config.applicationID, 0).cousin;
  assert(prodigyBuildRetainedContainerBootstrap(stateful, parameters, machineFragment, datacenterFragment, observedCreatedAtMs, bootstrap, &failure) == false);
  parameters = parametersFor(stateful);
  parameters.advertisesOnPorts[0xbeef] = 12345;
  assert(prodigyBuildRetainedContainerBootstrap(stateful, parameters, machineFragment, datacenterFragment, observedCreatedAtMs, bootstrap, &failure) == false);
}
