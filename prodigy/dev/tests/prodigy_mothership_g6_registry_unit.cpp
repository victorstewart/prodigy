#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <unistd.h>

#include <prodigy/mothership/mothership.cluster.registry.h>

static String digest(char value)
{
  String result = {};
  for (uint32_t index = 0; index < 64; ++index) result.append(value);
  return result;
}

static CousinRouteRecord makeRoute()
{
  CousinRouteRecord value = {};
  value.routeUUID = 0x101; value.operationUUID = 0x102; value.pairUUID = 0x103;
  value.logicalWorkloadUUID = 0x104; value.logicalServiceUUID = 0x105;
  value.sourceClusterUUID = 0x201; value.destinationClusterUUID = 0x202;
  value.sourceApplicationID = 7; value.destinationApplicationID = 19;
  value.sourceCousinServicePrefix = MeshServices::generateStatefulService(7, 3);
  value.destinationCousinServicePrefix = MeshServices::generateStatefulService(19, 3);
  value.slots.insert(3); value.destinationRoutablePrefixUUID = 0x106;
  value.destinationPublicAddress = IPAddress("2001:db8::1", true); value.destinationTCPPort = 443;
  value.sourcePermissionUUID = 0x301; value.destinationPermissionUUID = 0x302;
  value.transportProtocol = IPPROTO_TCP; value.destinationCIDR = 64; value.pathMTU = 1500;
  value.generation = 1; value.issuedAtMs = 100; value.expiresAtMs = 200;
  value.keyEpoch = 1; value.rootGeneration = 1;
  return value;
}

static ProdigyLocalCousinServicePermission makePermission(const CousinRouteRecord& route, bool source)
{
  ProdigyLocalCousinServicePermission value = {};
  value.protocolVersion = ProdigyLocalCousinServicePermission::baselineVersion;
  value.permissionUUID = source ? route.sourcePermissionUUID : route.destinationPermissionUUID;
  value.pairUUID = route.pairUUID; value.logicalWorkloadUUID = route.logicalWorkloadUUID;
  value.logicalServiceUUID = route.logicalServiceUUID;
  value.localClusterUUID = source ? route.sourceClusterUUID : route.destinationClusterUUID;
  value.peerClusterUUID = source ? route.destinationClusterUUID : route.sourceClusterUUID;
  value.localHalf = source ? CousinRouteHalf::source : CousinRouteHalf::destination;
  value.localApplicationID = source ? route.sourceApplicationID : route.destinationApplicationID;
  value.peerApplicationID = source ? route.destinationApplicationID : route.sourceApplicationID;
  value.localCousinServicePrefix = source ? route.sourceCousinServicePrefix : route.destinationCousinServicePrefix;
  value.peerCousinServicePrefix = source ? route.destinationCousinServicePrefix : route.sourceCousinServicePrefix;
  value.slots = route.slots;
  value.localDeploymentID = (uint64_t(value.localApplicationID) << 48) | (source ? 1 : 2);
  value.canonicalPlanSHA256 = digest(source ? 'a' : 'b'); value.artifactSHA256 = digest(source ? 'c' : 'd');
  value.artifactBytes = 8192; value.generation = 1; value.acceptedAuthorityGeneration = 7;
  value.baselineLogicalCores = 2; value.baselineMemoryMB = 1024; value.baselineStorageMB = 1024;
  return value;
}

static CousinRouteApplyReceipt makeRouteReceipt(const CousinRouteRecord& route, CousinRouteHalf half)
{
  CousinRouteApplyReceipt value = {};
  value.routeUUID = route.routeUUID; value.generation = route.generation;
  assert(cousinRouteAuthorizationDigest(route, value.authorizationSHA256));
  value.localClusterUUID = half == CousinRouteHalf::source ? route.sourceClusterUUID : route.destinationClusterUUID;
  value.localHalf = half; value.keyEpoch = route.keyEpoch;
  value.localRuntimeRevision = half == CousinRouteHalf::source ? 7 : 8;
  value.installedState = route.state;
  return value;
}

static MothershipPhysicalFaultMachineObservation observation(uint128_t cluster, uint128_t machine,
                                                             uint64_t topology, char state)
{
  MothershipPhysicalFaultMachineObservation value = {};
  value.clusterUUID = cluster; value.machineUUID = machine; value.topologyVersion = topology;
  value.stateSHA256 = digest(state);
  return value;
}

int main()
{
  char directoryTemplate[] = "/tmp/prodigy-g6-registry-XXXXXX";
  char *directory = ::mkdtemp(directoryTemplate);
  assert(directory != nullptr);
  struct ScopedDirectory {
    std::filesystem::path path;
    ~ScopedDirectory() { std::filesystem::remove_all(path); }
  } cleanup {directory};

  String path(directory), failure = {};
  MothershipProductionPairIntent intent = {};
  intent.operationUUID = 0x401; intent.route = makeRoute();
  intent.sourcePermission = makePermission(intent.route, true);
  intent.destinationPermission = makePermission(intent.route, false);
  intent.sourceRouteReceipt = makeRouteReceipt(intent.route, CousinRouteHalf::source);
  intent.destinationRouteReceipt = makeRouteReceipt(intent.route, CousinRouteHalf::destination);
  intent.sourceWorkload.clusterUUID = intent.route.sourceClusterUUID;
  intent.sourceWorkload.applicationID = 31;
  intent.sourceWorkload.deploymentID = (uint64_t(31) << 48) | 11;
  intent.sourceWorkload.canonicalPlanSHA256 = digest('e');
  intent.sourceWorkload.artifactSHA256 = digest('f'); intent.sourceWorkload.artifactBytes = 4096;
  intent.sourceWorkload.replicas = 1; intent.sourceWorkload.endpointMachineUUID = 0x601;
  intent.sourceWorkload.endpointIPv4 = "192.0.2.1"_ctv; intent.sourceWorkload.endpointTCPPort = 8080;
  intent.targetWorkload.clusterUUID = intent.route.destinationClusterUUID;
  intent.targetWorkload.applicationID = 31;
  intent.targetWorkload.deploymentID = (uint64_t(31) << 48) | 12;
  intent.targetWorkload.canonicalPlanSHA256 = intent.sourceWorkload.canonicalPlanSHA256;
  intent.targetWorkload.artifactSHA256 = digest('f'); intent.targetWorkload.artifactBytes = 4096;
  intent.targetWorkload.replicas = 1; intent.targetWorkload.endpointMachineUUID = 0x602;
  intent.targetWorkload.endpointIPv4 = "198.51.100.2"_ctv; intent.targetWorkload.endpointTCPPort = 8080;
  intent.physicalBoundaryUUID = 0x501;
  intent.selectorMachineUUID = 0x603;
  intent.selectorExecutorKind = MothershipPhysicalFaultExecutorKind::localVM;
  intent.selectorLocalVMBoundaryUUID = 0x801;
  intent.selectorAddress = "192.0.2.3"_ctv;
  intent.selectorTCPPort = 18080;
  intent.ingressWitnessMachineUUID = 0x601;
  intent.ingressWitnessExecutorKind = MothershipPhysicalFaultExecutorKind::localVM;
  intent.ingressWitnessLocalVMBoundaryUUID = 0x803;
  assert(intent.selectorMachineUUID != intent.sourceWorkload.endpointMachineUUID);

  {
    MothershipClusterRegistry registry(path);
    CousinRouteRecord storedRoute = {}; CousinRouteApplyReceipt storedReceipt = {};
    bool resumed = false;

    MothershipLocalMembershipCleanupRecord cleanupIntent = {};
    cleanupIntent.clusterUUID = 0xa01;
    cleanupIntent.desiredSpecSHA256 = digest('a');
    MothershipLocalMembershipCleanupMachine cleanupMachine = {};
    cleanupMachine.machine.source = MothershipClusterMachineSource::adopted;
    cleanupMachine.machine.backing = ClusterMachineBacking::owned;
    cleanupMachine.machine.kind = MachineConfig::MachineKind::vm;
    cleanupMachine.machine.lifetime = MachineLifetime::owned;
    cleanupMachine.machine.isBrain = true;
    cleanupMachine.machine.ssh.address = "10.66.6.2"_ctv;
    cleanupMachine.machine.ssh.user = "root"_ctv;
    cleanupMachine.machine.ssh.port = 22;
    cleanupMachine.machine.uuid = 0xa02;
    cleanupMachine.machine.rackUUID = 17;
    cleanupIntent.machines.push_back(cleanupMachine);
    cleanupMachine.machine.ssh.address = "10.66.6.3"_ctv;
    cleanupMachine.machine.uuid = 0xa03;
    cleanupMachine.machine.rackUUID = 19;
    cleanupIntent.machines.push_back(cleanupMachine);
    MothershipLocalMembershipCleanupRecord storedCleanup = {};
    assert(registry.admitLocalMembershipCleanup(
        cleanupIntent, storedCleanup, resumed, &failure) && !resumed);
    assert(storedCleanup.machines.size() == 2 &&
           storedCleanup.machines[0].machine.uuid == 0xa02 &&
           storedCleanup.machines[0].machine.rackUUID == 17 &&
           storedCleanup.machines[1].machine.uuid == 0xa03 &&
           storedCleanup.machines[1].machine.rackUUID == 19);
    assert(registry.admitLocalMembershipCleanup(
        cleanupIntent, storedCleanup, resumed, &failure) && resumed);
    auto conflictingCleanup = cleanupIntent;
    conflictingCleanup.desiredSpecSHA256 = digest('b');
    assert(!registry.admitLocalMembershipCleanup(
        conflictingCleanup, storedCleanup, resumed, &failure));
    conflictingCleanup = cleanupIntent;
    conflictingCleanup.machines[1].machine.uuid++;
    assert(!registry.admitLocalMembershipCleanup(
        conflictingCleanup, storedCleanup, resumed, &failure));
    assert(registry.commitLocalMembershipCleanup(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256,
        storedCleanup, resumed, &failure) && !resumed);
    assert(registry.commitLocalMembershipCleanup(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256,
        storedCleanup, resumed, &failure) && resumed);
    assert(!registry.clearCompletedLocalMembershipCleanup(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256, &failure));
    assert(registry.completeLocalMembershipCleanupMachine(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256, 0,
        storedCleanup, resumed, &failure) && !resumed);
    assert(storedCleanup.machines[0].cleaned && !storedCleanup.machines[1].cleaned);
    assert(registry.completeLocalMembershipCleanupMachine(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256, 0,
        storedCleanup, resumed, &failure) && resumed);
    assert(!registry.clearCompletedLocalMembershipCleanup(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256, &failure));
    assert(registry.completeLocalMembershipCleanupMachine(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256, 1,
        storedCleanup, resumed, &failure) && !resumed);
    assert(registry.clearCompletedLocalMembershipCleanup(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256, &failure));
    assert(!registry.loadLocalMembershipCleanup(
        cleanupIntent.clusterUUID, storedCleanup, &failure) &&
        failure.equal("record not found"_ctv));

    assert(registry.recordCousinRoute(intent.route, storedRoute, resumed, &failure) && !resumed);
    assert(registry.recordCousinRouteApplyReceipt(intent.sourceRouteReceipt, storedReceipt, resumed, &failure));
    assert(registry.recordCousinRouteApplyReceipt(intent.destinationRouteReceipt, storedReceipt, resumed, &failure));

    MothershipProductionPairRecord pair = {};
    assert(registry.admitProductionPair(intent, 1000, pair, resumed, &failure) && !resumed);
    assert(registry.admitProductionPair(intent, 1001, pair, resumed, &failure) && resumed);
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::targetAdmitted,
                                          digest('1'), 1001, pair, resumed, &failure) && !resumed);
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::targetAdmitted,
                                          digest('1'), 1001, pair, resumed, &failure) && resumed);
    assert(!registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::targetAdmitted,
                                           digest('2'), 1001, pair, resumed, &failure));

    MothershipLocalVMBoundaryDescriptor localBoundary = {};
    localBoundary.vmBoundaryUUID = 0x801; localBoundary.clusterUUID = intent.route.sourceClusterUUID;
    localBoundary.machineUUID = intent.selectorMachineUUID; localBoundary.taskID = "g6-local-1"_ctv;
    localBoundary.hostAddress = "192.0.2.10"_ctv;
    localBoundary.hostUser = "root"_ctv; localBoundary.hostPrivateKeyPath = "/tmp/g6-key"_ctv;
    localBoundary.hostPublicKeyOpenSSH = "ssh-ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA g6"_ctv;
    localBoundary.statePath = "/var/tmp/prodigy-g6/machine-1.json"_ctv;
    localBoundary.executorSHA256 = digest('7'); localBoundary.immutableStateSHA256 = digest('8');
    localBoundary.registeredAtMs = 1003;
    assert(mothershipPhysicalFaultProviderStateRootValid(
        "/var/lib/prodigy/mothership-physical-faults"_ctv));
    assert(!mothershipPhysicalFaultProviderStateRootValid("/tmp/physical-faults"_ctv));
    MothershipLocalVMBoundaryDescriptor targetLocal = localBoundary;
    targetLocal.vmBoundaryUUID = 0x802; targetLocal.clusterUUID = intent.route.destinationClusterUUID;
    targetLocal.machineUUID = intent.targetWorkload.endpointMachineUUID;
    targetLocal.taskID = "g6-local-2"_ctv; targetLocal.statePath = "/var/tmp/prodigy-g6/machine-2.json"_ctv;
    MothershipLocalVMBoundaryDescriptor storedLocal = {};
    assert(registry.registerLocalVMBoundary(localBoundary, storedLocal, resumed, &failure) && !resumed);
    assert(registry.registerLocalVMBoundary(targetLocal, storedLocal, resumed, &failure) && !resumed);
    auto refreshedLocal = localBoundary;
    refreshedLocal.executorSHA256 = digest('6');
    const auto rejectsBoundaryRefreshDrift = [&](auto mutate) {
      auto drifted = refreshedLocal;
      mutate(drifted);
      assert(!registry.refreshLocalVMBoundaryExecutor(localBoundary, drifted, storedLocal, resumed, &failure));
    };
    rejectsBoundaryRefreshDrift([](auto& value) { value.vmBoundaryUUID++; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.clusterUUID++; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.machineUUID++; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.taskID = "g6-other-task"_ctv; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.hostAddress = "192.0.2.11"_ctv; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.hostPort++; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.hostUser = "admin"_ctv; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.hostPrivateKeyPath = "/tmp/g6-other-key"_ctv; });
    rejectsBoundaryRefreshDrift([](auto& value) {
      value.hostPublicKeyOpenSSH = "ssh-ed25519 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB g6"_ctv;
    });
    rejectsBoundaryRefreshDrift([](auto& value) { value.statePath = "/var/tmp/prodigy-g6/other.json"_ctv; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.immutableStateSHA256 = digest('0'); });
    rejectsBoundaryRefreshDrift([](auto& value) { value.registeredAtMs++; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.retired = true; });
    auto staleExpectedLocal = localBoundary;
    staleExpectedLocal.executorSHA256 = digest('5');
    assert(!registry.refreshLocalVMBoundaryExecutor(staleExpectedLocal, refreshedLocal,
                                                   storedLocal, resumed, &failure));
    assert(registry.refreshLocalVMBoundaryExecutor(localBoundary, refreshedLocal,
                                                   storedLocal, resumed, &failure) && !resumed);
    assert(storedLocal.executorSHA256 == digest('6'));
    assert(registry.refreshLocalVMBoundaryExecutor(localBoundary, refreshedLocal,
                                                   storedLocal, resumed, &failure) && resumed);
    localBoundary = refreshedLocal;

    Vector<uint128_t> expectedBoundaryMachines = {0x601, 0x602, 0x603};
    Vector<MothershipLocalVMBoundaryDescriptor> inspectedBoundaries = {localBoundary};
    assert(!MothershipClusterRegistry::activeLocalVMBoundariesExactForMachines(
        localBoundary.clusterUUID, expectedBoundaryMachines, inspectedBoundaries, &failure));
    auto secondBoundary = localBoundary;
    secondBoundary.vmBoundaryUUID = 0x804; secondBoundary.machineUUID = 0x602;
    auto thirdBoundary = localBoundary;
    thirdBoundary.vmBoundaryUUID = 0x805; thirdBoundary.machineUUID = 0x601;
    inspectedBoundaries.push_back(secondBoundary); inspectedBoundaries.push_back(thirdBoundary);
    assert(MothershipClusterRegistry::activeLocalVMBoundariesExactForMachines(
        localBoundary.clusterUUID, expectedBoundaryMachines, inspectedBoundaries, &failure));
    auto duplicateBoundary = secondBoundary;
    duplicateBoundary.vmBoundaryUUID = 0x806;
    inspectedBoundaries.push_back(duplicateBoundary);
    assert(!MothershipClusterRegistry::activeLocalVMBoundariesExactForMachines(
        localBoundary.clusterUUID, expectedBoundaryMachines, inspectedBoundaries, &failure));
    inspectedBoundaries.pop_back();
    auto injectedNewlineKey = localBoundary;
    String unsafePublicKey = {};
    unsafePublicKey.append("ssh-ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA g6"_ctv);
    unsafePublicKey.append('\n');
    assert(unsafePublicKey[unsafePublicKey.size() - 1] == '\n');
    injectedNewlineKey.hostPublicKeyOpenSSH = std::move(unsafePublicKey);
    assert(!registry.registerLocalVMBoundary(injectedNewlineKey, storedLocal, resumed, &failure));

    MothershipPhysicalServiceTransitBoundary boundary = {};
    boundary.boundaryUUID = 0x501; boundary.pairOperationUUID = intent.operationUUID;
    boundary.routeUUID = intent.route.routeUUID; boundary.routeGeneration = intent.route.generation;
    boundary.sourceClusterUUID = intent.route.sourceClusterUUID;
    boundary.targetClusterUUID = intent.route.destinationClusterUUID;
    boundary.sourceMachineUUID = intent.selectorMachineUUID; boundary.targetMachineUUID = 0x602;
    boundary.sourceExecutorKind = MothershipPhysicalFaultExecutorKind::localVM;
    boundary.targetExecutorKind = MothershipPhysicalFaultExecutorKind::localVM;
    boundary.sourceLocalVMBoundaryUUID = localBoundary.vmBoundaryUUID;
    boundary.targetLocalVMBoundaryUUID = targetLocal.vmBoundaryUUID;
    boundary.sourceAddress = intent.selectorAddress;
    boundary.targetAddress = intent.targetWorkload.endpointIPv4;
    boundary.sourceTCPPort = intent.selectorTCPPort;
    boundary.targetTCPPort = intent.targetWorkload.endpointTCPPort; boundary.pathMTU = intent.route.pathMTU;
    assert(cousinRouteAuthorizationDigest(intent.route, boundary.routeAuthorizationSHA256));
    boundary.admissionReceiptSHA256 = digest('2'); boundary.admittedAtMs = 1002;
    MothershipPhysicalServiceTransitBoundary storedBoundary = {};
    assert(registry.admitPhysicalServiceTransitBoundary(boundary, storedBoundary, resumed, &failure) && !resumed);
    assert(registry.admitPhysicalServiceTransitBoundary(boundary, storedBoundary, resumed, &failure) && resumed);
    auto changedSourcePort = boundary; changedSourcePort.sourceTCPPort++;
    assert(!registry.admitPhysicalServiceTransitBoundary(changedSourcePort, storedBoundary, resumed, &failure));
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::transitApplied,
                                          boundary.admissionReceiptSHA256, 1002, pair, resumed, &failure));

    MothershipPhysicalClusterNetworkFaultRequest network = {};
    network.operationUUID = 0x701; network.boundaryUUID = boundary.boundaryUUID;
    network.sourceClusterUUID = boundary.sourceClusterUUID; network.targetClusterUUID = boundary.targetClusterUUID;
    network.sourceMachineUUID = boundary.sourceMachineUUID; network.targetMachineUUID = boundary.targetMachineUUID;
    network.direction = MothershipPhysicalFaultDirection::sourceToTarget; network.durationMilliseconds = 1000;
    network.routeUUID = boundary.routeUUID; network.routeGeneration = boundary.routeGeneration;
    network.routeAuthorizationSHA256 = boundary.routeAuthorizationSHA256;
    network.sourceAddress = boundary.sourceAddress; network.targetAddress = boundary.targetAddress;
    network.sourceTopologyVersion = 7; network.targetTopologyVersion = 8;
    MothershipPhysicalClusterNetworkFaultRecord networkRecord = {};
    const auto sourceAdmission = observation(network.sourceClusterUUID, network.sourceMachineUUID, 7, 'e');
    const auto targetAdmission = observation(network.targetClusterUUID, network.targetMachineUUID, 8, 'f');
    assert(registry.admitPhysicalClusterNetworkFault(network, sourceAdmission, targetAdmission,
                                                     networkRecord, resumed, &failure) && !resumed);
    assert(networkRecord.sourceAdmission.stateSHA256 == sourceAdmission.stateSHA256);
    assert(networkRecord.targetAdmission.stateSHA256 == targetAdmission.stateSHA256);
    assert(registry.admitPhysicalClusterNetworkFault(network, sourceAdmission, targetAdmission,
                                                     networkRecord, resumed, &failure) && resumed);
    auto staleSourceAdmission = sourceAdmission; staleSourceAdmission.stateSHA256 = digest('0');
    assert(!registry.admitPhysicalClusterNetworkFault(network, staleSourceAdmission, targetAdmission,
                                                      networkRecord, resumed, &failure));
    auto retargeted = network; retargeted.targetMachineUUID++;
    assert(!registry.admitPhysicalClusterNetworkFault(retargeted, sourceAdmission, targetAdmission,
                                                      networkRecord, resumed, &failure));
    auto reassigned = network; reassigned.targetAddress = "2001:db8::2"_ctv;
    assert(!registry.admitPhysicalClusterNetworkFault(reassigned, sourceAdmission, targetAdmission,
                                                      networkRecord, resumed, &failure));
    MothershipPhysicalClusterNetworkFaultReceipt networkReceipt = {};
    networkReceipt.operationUUID = network.operationUUID; networkReceipt.boundaryUUID = network.boundaryUUID;
    networkReceipt.admission = network;
    networkReceipt.sourceBefore = sourceAdmission;
    networkReceipt.targetBefore = targetAdmission;
    networkReceipt.sourceAfter = networkReceipt.sourceBefore; networkReceipt.targetAfter = networkReceipt.targetBefore;
    networkReceipt.sourceInstalledAtMonotonicMilliseconds = 100;
    networkReceipt.sourceRestoredAtMonotonicMilliseconds = 1100;
    networkReceipt.sourceRestored = true; networkReceipt.restored = true;
    auto mismatchedNetworkReceipt = networkReceipt;
    mismatchedNetworkReceipt.sourceBefore.stateSHA256 = digest('a');
    mismatchedNetworkReceipt.sourceAfter = mismatchedNetworkReceipt.sourceBefore;
    assert(!registry.recordPhysicalClusterNetworkFaultReceipt(network, mismatchedNetworkReceipt,
                                                               networkRecord, resumed, &failure));
    assert(registry.recordPhysicalClusterNetworkFaultReceipt(network, networkReceipt, networkRecord, resumed, &failure) && !resumed);
    assert(registry.recordPhysicalClusterNetworkFaultReceipt(network, networkReceipt, networkRecord, resumed, &failure) && resumed);

    auto bidirectional = network; bidirectional.operationUUID++;
    bidirectional.direction = MothershipPhysicalFaultDirection::both;
    MothershipPhysicalClusterNetworkFaultReceipt bidirectionalReceipt = networkReceipt;
    bidirectionalReceipt.operationUUID = bidirectional.operationUUID;
    bidirectionalReceipt.admission = bidirectional;
    assert(!mothershipPhysicalClusterNetworkFaultReceiptValid(bidirectional, bidirectionalReceipt, &failure));
    bidirectionalReceipt.targetInstalledAtMonotonicMilliseconds = 200;
    bidirectionalReceipt.targetRestoredAtMonotonicMilliseconds = 1200;
    bidirectionalReceipt.targetRestored = true;
    assert(mothershipPhysicalClusterNetworkFaultReceiptValid(bidirectional, bidirectionalReceipt, &failure));

    assert(registry.registerLocalVMBoundary(localBoundary, storedLocal, resumed, &failure) && resumed);
    MothershipLocalVMBoundaryDescriptor foundLocal = {};
    assert(registry.findActiveLocalVMBoundary(localBoundary.clusterUUID, localBoundary.machineUUID,
                                              foundLocal, &failure));
    assert(foundLocal.vmBoundaryUUID == localBoundary.vmBoundaryUUID);
    auto duplicateMachine = localBoundary; duplicateMachine.vmBoundaryUUID++;
    assert(!registry.registerLocalVMBoundary(duplicateMachine, storedLocal, resumed, &failure));

    MothershipLocalVMMachineFaultRequest local = {};
    local.operationUUID = 0x901; local.vmBoundaryUUID = localBoundary.vmBoundaryUUID;
    local.clusterUUID = localBoundary.clusterUUID; local.machineUUID = localBoundary.machineUUID;
    local.action = MothershipLocalVMMachineFaultAction::coldReboot;
    local.durationMilliseconds = 1000; local.expectedBootSHA256 = digest('9');
    MothershipLocalVMMachineFaultRecord localRecord = {};
    const auto localAdmission = observation(local.clusterUUID, local.machineUUID, 9, '9');
    assert(registry.admitLocalVMMachineFault(local, localAdmission, localRecord, resumed, &failure) && !resumed);
    assert(localRecord.admission.stateSHA256 == local.expectedBootSHA256);
    assert(registry.admitLocalVMMachineFault(local, localAdmission, localRecord, resumed, &failure) && resumed);
    auto staleLocalAdmission = localAdmission; staleLocalAdmission.topologyVersion++;
    assert(!registry.admitLocalVMMachineFault(local, staleLocalAdmission, localRecord, resumed, &failure));
    MothershipLocalVMMachineFaultReceipt localReceipt = {};
    localReceipt.operationUUID = local.operationUUID; localReceipt.vmBoundaryUUID = local.vmBoundaryUUID;
    localReceipt.before = observation(local.clusterUUID, local.machineUUID, 9, '9');
    localReceipt.after = observation(local.clusterUUID, local.machineUUID, 10, '0');
    localReceipt.restoredBootSHA256 = digest('0'); localReceipt.faultedAtMonotonicMilliseconds = 1000;
    localReceipt.restoredAtMonotonicMilliseconds = 2000; localReceipt.restored = true;
    auto mismatchedLocalReceipt = localReceipt;
    mismatchedLocalReceipt.before.topologyVersion++;
    assert(!registry.recordLocalVMMachineFaultReceipt(local, mismatchedLocalReceipt,
                                                       localRecord, resumed, &failure));
    assert(registry.recordLocalVMMachineFaultReceipt(local, localReceipt, localRecord, resumed, &failure) && !resumed);
    assert(registry.recordLocalVMMachineFaultReceipt(local, localReceipt, localRecord, resumed, &failure) && resumed);

    MothershipLocalAuthorityRecoveryCohortRequest cohort = {};
    cohort.operationUUID = 0xb01; cohort.clusterUUID = localBoundary.clusterUUID;
    cohort.topologyVersion = 17;
    cohort.timeoutMilliseconds = mothershipLocalAuthorityRecoveryMinimumTimeoutMilliseconds;
    for (uint128_t machine : {uint128_t(0xb11), uint128_t(0xb12), uint128_t(0xb13)})
    {
      MothershipLocalAuthorityRecoveryExecutor executor = {};
      executor.machineUUID = machine; executor.boundaryUUID = machine + 0x100;
      executor.executorOperationUUID = machine + 0x200; executor.immutableBoundarySHA256 = digest('a');
      cohort.executors.push_back(std::move(executor));
    }
    MothershipLocalAuthorityRecoveryCohortRecord cohortRecord = {};
    assert(registry.admitLocalAuthorityRecoveryCohort(cohort, cohortRecord, resumed, &failure) && !resumed);
    assert(registry.admitLocalAuthorityRecoveryCohort(cohort, cohortRecord, resumed, &failure) && resumed);
    auto conflictingCohort = cohort; conflictingCohort.timeoutMilliseconds++;
    assert(!registry.admitLocalAuthorityRecoveryCohort(conflictingCohort, cohortRecord, resumed, &failure));
    assert(registry.advanceLocalAuthorityRecoveryCohort(
        cohort.operationUUID, cohort.executors[0].boundaryUUID, MothershipLocalAuthorityRecoveryPhase::armed,
        digest('b'), cohortRecord, resumed, &failure) && !resumed);
    assert(!registry.advanceLocalAuthorityRecoveryCohort(
        cohort.operationUUID, cohort.executors[0].boundaryUUID, MothershipLocalAuthorityRecoveryPhase::released,
        digest('c'), cohortRecord, resumed, &failure));
    for (uint32_t index = 1; index < cohort.executors.size(); ++index)
    {
      const auto& executor = cohort.executors[index];
      assert(registry.advanceLocalAuthorityRecoveryCohort(
          cohort.operationUUID, executor.boundaryUUID, MothershipLocalAuthorityRecoveryPhase::armed,
          digest('b'), cohortRecord, resumed, &failure) && !resumed);
    }
    assert(cohortRecord.phase == MothershipLocalAuthorityRecoveryPhase::armed);
    assert(registry.advanceLocalAuthorityRecoveryCohort(
        cohort.operationUUID, cohort.executors[0].boundaryUUID, MothershipLocalAuthorityRecoveryPhase::armed,
        digest('b'), cohortRecord, resumed, &failure) && resumed);
    assert(!registry.advanceLocalAuthorityRecoveryCohort(
        cohort.operationUUID, cohort.executors[0].boundaryUUID, MothershipLocalAuthorityRecoveryPhase::recovered,
        digest('c'), cohortRecord, resumed, &failure));
    for (const auto& executor : cohort.executors)
      assert(registry.advanceLocalAuthorityRecoveryCohort(
          cohort.operationUUID, executor.boundaryUUID, MothershipLocalAuthorityRecoveryPhase::released,
          digest('c'), cohortRecord, resumed, &failure) && !resumed);
    for (const auto& executor : cohort.executors)
      assert(registry.advanceLocalAuthorityRecoveryCohort(
          cohort.operationUUID, executor.boundaryUUID, MothershipLocalAuthorityRecoveryPhase::recovered,
          digest('d'), cohortRecord, resumed, &failure) && !resumed);
    assert(cohortRecord.phase == MothershipLocalAuthorityRecoveryPhase::recovered);
    assert(registry.advanceLocalAuthorityRecoveryCohort(
        cohort.operationUUID, cohort.executors[0].boundaryUUID, MothershipLocalAuthorityRecoveryPhase::recovered,
        digest('d'), cohortRecord, resumed, &failure) && resumed);
    assert(!registry.advanceLocalAuthorityRecoveryCohort(
        cohort.operationUUID, cohort.executors[0].boundaryUUID, MothershipLocalAuthorityRecoveryPhase::recovered,
        digest('e'), cohortRecord, resumed, &failure));

    MothershipPhysicalServiceTransitBoundary closed = {};
    assert(!registry.closePhysicalServiceTransitBoundary(boundary.boundaryUUID, digest('8'), closed, resumed, &failure));
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::sourceIngressWitnessed,
                                          digest('3'), 1003, pair, resumed, &failure));
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::targetSelected,
                                          digest('4'), 1004, pair, resumed, &failure));
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::targetIngressWitnessed,
                                          digest('5'), 1005, pair, resumed, &failure));
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::sourceDrained,
                                          digest('6'), 1006, pair, resumed, &failure));
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::sourceRetired,
                                          digest('7'), 1007, pair, resumed, &failure));
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::cleanupComplete,
                                          digest('8'), 1008, pair, resumed, &failure));
    assert(registry.closePhysicalServiceTransitBoundary(boundary.boundaryUUID, digest('8'), closed, resumed, &failure) && !resumed);
    assert(closed.admissionReceiptSHA256 == digest('2') && closed.cleanupReceiptSHA256 == digest('8'));
    assert(registry.closePhysicalServiceTransitBoundary(boundary.boundaryUUID, digest('8'), closed, resumed, &failure) && resumed);
    assert(!registry.closePhysicalServiceTransitBoundary(boundary.boundaryUUID, digest('9'), closed, resumed, &failure));

    MothershipProductionPairIntent abortedIntent = intent;
    abortedIntent.operationUUID = 0x402; abortedIntent.physicalBoundaryUUID = 0x502;
    assert(registry.admitProductionPair(abortedIntent, 1010, pair, resumed, &failure) && !resumed);
    assert(registry.advanceProductionPair(abortedIntent.operationUUID, MothershipProductionPairPhase::targetAdmitted,
                                          digest('a'), 1011, pair, resumed, &failure));
    MothershipPhysicalServiceTransitBoundary abortBoundary = boundary;
    abortBoundary.boundaryUUID = abortedIntent.physicalBoundaryUUID;
    abortBoundary.pairOperationUUID = abortedIntent.operationUUID;
    abortBoundary.admissionReceiptSHA256 = digest('b'); abortBoundary.cleanupReceiptSHA256.clear(); abortBoundary.closed = false;
    assert(registry.admitPhysicalServiceTransitBoundary(abortBoundary, storedBoundary, resumed, &failure) && !resumed);
    const String abortReceipt = digest('c');
    assert(registry.closePhysicalServiceTransitBoundaryBeforeTransit(abortBoundary.boundaryUUID, abortReceipt,
                                                                      closed, resumed, &failure) && !resumed);
    assert(registry.abortProductionPairBeforeTransit(abortedIntent.operationUUID, abortReceipt, 1012,
                                                     pair, resumed, &failure) && !resumed);
    assert(pair.phase == MothershipProductionPairPhase::abortedBeforeTransit);
    assert(registry.abortProductionPairBeforeTransit(abortedIntent.operationUUID, abortReceipt, 1012,
                                                     pair, resumed, &failure) && resumed);
    assert(registry.closePhysicalServiceTransitBoundaryBeforeTransit(abortBoundary.boundaryUUID, abortReceipt,
                                                                      closed, resumed, &failure) && resumed);
    assert(!registry.abortProductionPairBeforeTransit(abortedIntent.operationUUID, digest('d'), 1012,
                                                      pair, resumed, &failure));

    MothershipProductionPairIntent preCutoverIntent = intent;
    preCutoverIntent.operationUUID = 0x404; preCutoverIntent.physicalBoundaryUUID = 0x504;
    assert(registry.admitProductionPair(preCutoverIntent, 1013, pair, resumed, &failure) && !resumed);
    assert(registry.advanceProductionPair(preCutoverIntent.operationUUID, MothershipProductionPairPhase::targetAdmitted,
                                          digest('a'), 1014, pair, resumed, &failure));
    MothershipPhysicalServiceTransitBoundary preCutoverBoundary = boundary;
    preCutoverBoundary.boundaryUUID = preCutoverIntent.physicalBoundaryUUID;
    preCutoverBoundary.pairOperationUUID = preCutoverIntent.operationUUID;
    preCutoverBoundary.admissionReceiptSHA256 = digest('b');
    preCutoverBoundary.cleanupReceiptSHA256.clear(); preCutoverBoundary.closed = false;
    assert(registry.admitPhysicalServiceTransitBoundary(preCutoverBoundary, storedBoundary, resumed, &failure) && !resumed);
    assert(registry.advanceProductionPair(preCutoverIntent.operationUUID, MothershipProductionPairPhase::transitApplied,
                                          digest('c'), 1015, pair, resumed, &failure));
    const String preCutoverPendingReceipt = digest('d');
    const String preCutoverAbortReceipt = digest('e');
    assert(registry.prepareProductionPairAbortBeforeCutover(preCutoverIntent.operationUUID, preCutoverPendingReceipt,
                                                            1016, pair, resumed, &failure) && !resumed);
    assert(pair.phase == MothershipProductionPairPhase::abortBeforeCutoverPending &&
           pair.cleanupReceiptSHA256 == preCutoverPendingReceipt);
    // Simulate a crash after the provider has removed the selector but before
    // the terminal pair write.  The durable pending record is the retry input.
    assert(registry.loadProductionPair(preCutoverIntent.operationUUID, pair, &failure) &&
           pair.phase == MothershipProductionPairPhase::abortBeforeCutoverPending &&
           pair.cleanupReceiptSHA256 == preCutoverPendingReceipt);
    assert(registry.prepareProductionPairAbortBeforeCutover(preCutoverIntent.operationUUID, preCutoverPendingReceipt,
                                                            1016, pair, resumed, &failure) && resumed);
    assert(!registry.prepareProductionPairAbortBeforeCutover(preCutoverIntent.operationUUID, digest('f'), 1016,
                                                             pair, resumed, &failure));
    assert(!registry.closePhysicalServiceTransitBoundary(preCutoverBoundary.boundaryUUID, preCutoverAbortReceipt,
                                                         closed, resumed, &failure));
    assert(registry.abortProductionPairBeforeCutover(preCutoverIntent.operationUUID, preCutoverAbortReceipt, 1016,
                                                     pair, resumed, &failure) && !resumed);
    assert(pair.phase == MothershipProductionPairPhase::abortedBeforeCutover);
    assert(registry.abortProductionPairBeforeCutover(preCutoverIntent.operationUUID, preCutoverAbortReceipt, 1016,
                                                     pair, resumed, &failure) && resumed);
    assert(!registry.abortProductionPairBeforeCutover(preCutoverIntent.operationUUID, digest('f'), 1016,
                                                      pair, resumed, &failure));
    assert(registry.closePhysicalServiceTransitBoundary(preCutoverBoundary.boundaryUUID, preCutoverAbortReceipt,
                                                        closed, resumed, &failure) && !resumed);
    assert(registry.closePhysicalServiceTransitBoundary(preCutoverBoundary.boundaryUUID, preCutoverAbortReceipt,
                                                        closed, resumed, &failure) && resumed);
    assert(!registry.closePhysicalServiceTransitBoundary(preCutoverBoundary.boundaryUUID, digest('f'),
                                                         closed, resumed, &failure));
    MothershipProductionPairIntent nextIntent = abortedIntent;
    nextIntent.operationUUID = 0x403; nextIntent.physicalBoundaryUUID = 0x503;
    assert(registry.admitProductionPair(nextIntent, 1017, pair, resumed, &failure) && !resumed);
  }

  {
    MothershipClusterRegistry reopened(path);
    MothershipProductionPairRecord pair = {}; MothershipPhysicalServiceTransitBoundary boundary = {};
    MothershipLocalVMBoundaryDescriptor localBoundary = {};
    assert(reopened.loadProductionPair(intent.operationUUID, pair, &failure) &&
           pair.phase == MothershipProductionPairPhase::cleanupComplete);
    assert(reopened.loadPhysicalServiceTransitBoundary(0x501, boundary, &failure) && boundary.closed &&
           boundary.admissionReceiptSHA256 == digest('2') && boundary.cleanupReceiptSHA256 == digest('8'));
    assert(reopened.loadProductionPair(0x404, pair, &failure) &&
           pair.phase == MothershipProductionPairPhase::abortedBeforeCutover &&
           pair.cleanupReceiptSHA256 == digest('e'));
    assert(reopened.loadPhysicalServiceTransitBoundary(0x504, boundary, &failure) && boundary.closed &&
           boundary.cleanupReceiptSHA256 == digest('e'));
    assert(reopened.loadLocalVMBoundary(0x801, localBoundary, &failure) && !localBoundary.retired &&
           localBoundary.executorSHA256 == digest('6'));
    MothershipLocalAuthorityRecoveryCohortRecord cohort = {};
    assert(reopened.loadLocalAuthorityRecoveryCohort(0xb01, cohort, &failure) &&
           cohort.phase == MothershipLocalAuthorityRecoveryPhase::recovered);
  }

  std::puts("PASS: G6 registry persists exact production-pair, transit, and fault owners");
  return 0;
}
