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

class TestPairBoundaryRecordV1Fixture {
public:
  uint32_t version = 1;
  MothershipVirtualDatacenterPairBoundaryDescriptor boundary;
  uint64_t sourceDeploymentID = 0, targetDeploymentID = 0;
  String sourcePlanSHA256, targetPlanSHA256, sourceBlobSHA256, targetBlobSHA256;
  uint64_t selectorGeneration = 0;
  bool closed = false;
};

template <typename S>
static void serialize(S&& serializer, TestPairBoundaryRecordV1Fixture& record)
{
  serializer.value4b(record.version); serializer.object(record.boundary);
  serializer.value8b(record.sourceDeploymentID); serializer.value8b(record.targetDeploymentID);
  serializer.text1b(record.sourcePlanSHA256, 64); serializer.text1b(record.targetPlanSHA256, 64);
  serializer.text1b(record.sourceBlobSHA256, 64); serializer.text1b(record.targetBlobSHA256, 64);
  serializer.value8b(record.selectorGeneration); serializer.value1b(record.closed);
}

class TestPairBoundaryRecordV2Fixture : public TestPairBoundaryRecordV1Fixture {
public:
  String targetRequestPlan, targetRequestPlanSHA256;
  uint64_t targetBlobBytes = 0;
  String targetAdmissionReceipt;
};

template <typename S>
static void serialize(S&& serializer, TestPairBoundaryRecordV2Fixture& record)
{
  serializer.value4b(record.version); serializer.object(record.boundary);
  serializer.value8b(record.sourceDeploymentID); serializer.value8b(record.targetDeploymentID);
  serializer.text1b(record.sourcePlanSHA256, 64); serializer.text1b(record.targetPlanSHA256, 64);
  serializer.text1b(record.sourceBlobSHA256, 64); serializer.text1b(record.targetBlobSHA256, 64);
  serializer.value8b(record.selectorGeneration); serializer.value1b(record.closed);
  serializer.text1b(record.targetRequestPlan, 1024 * 1024);
  serializer.text1b(record.targetRequestPlanSHA256, 64);
  serializer.value8b(record.targetBlobBytes); serializer.text1b(record.targetAdmissionReceipt, 64 * 1024);
}

int main(void)
{
  char directoryTemplate[] = "/tmp/prodigy-upgrade-admission-registry-XXXXXX";
  char *directory = ::mkdtemp(directoryTemplate);
  assert(directory != nullptr);
  struct ScopedTestDirectory {
    std::filesystem::path path;
    ~ScopedTestDirectory() { std::filesystem::remove_all(path); }
  } ownedDirectory {directory};
  String path(directory);
  {
  MothershipClusterRegistry registry(path);
  MothershipUpgradeAdmissionRecord request = {};
  request.clusterUUID = uint128_t(0xA11);
  request.operationID = uint128_t(0xB22);
  request.sourceBundleSHA256 = digest('a');
  request.sourceContractSHA256 = digest('b');
  request.sourceReleaseID.assign("source-release"_ctv);
  request.sourceProdigySHA256 = digest('c');
  request.sourceMothershipSHA256 = digest('d');
  request.targetBundleSHA256 = digest('e');
  request.targetContractSHA256 = digest('f');
  request.authorityGeneration = 7;
  request.masterUUID = uint128_t(0xC33);
  request.masterBootNs = 8;
  request.semanticObservationSHA256 = digest('1');
  request.approvedPath = 1;
  request.observationReceiptVersion = 1;
  request.observationReportSHA256 = digest('2');
  request.plannerInputSHA256 = digest('3');
  request.firstStopGate.assign("fleet digest evidence unavailable"_ctv);

  MothershipUpgradeAdmissionRecord recorded = {};
  bool resumed = false;
  String failure = {};
  assert(registry.recordUpgradeAdmission(request, recorded, resumed, &failure));
  assert(!resumed && recorded.firstStopGate == request.firstStopGate);
  assert(registry.recordUpgradeAdmission(request, recorded, resumed, &failure));
  assert(resumed);
  request.observationReceiptVersion = 2;
  request.observationReportSHA256 = digest('4');
  request.plannerInputSHA256 = digest('5');
  assert(registry.recordUpgradeAdmission(request, recorded, resumed, &failure));
  assert(!resumed && recorded.rejectedObservations.size() == 1);
  MothershipUpgradeAdmissionRecord loaded = {};
  assert(registry.loadUpgradeAdmission(request.clusterUUID, request.operationID, loaded, &failure));
  assert(loaded.semanticObservationSHA256 == request.semanticObservationSHA256 &&
         loaded.authorityGeneration == request.authorityGeneration && loaded.masterUUID == request.masterUUID);
  request.targetBundleSHA256 = digest('6');
  assert(!registry.recordUpgradeAdmission(request, recorded, resumed, &failure));
  assert(failure == "upgrade admission operation identity conflicts with existing immutable record"_ctv);
  MothershipUpgradeAdmissionRecord incomplete = request;
  incomplete.operationID = uint128_t(0xE55);
  incomplete.masterUUID = 0;
  assert(!registry.recordUpgradeAdmission(incomplete, recorded, resumed, &failure));
  assert(failure == "upgrade admission record is invalid"_ctv);
  MothershipTestPairBoundaryRecord pair = {}, pairStored = {}, pairLoaded = {};
  pair.boundary.operationID = "0x0abc"_ctv;
  pair.boundary.sourceClusterUUID = "0x0a11"_ctv;
  pair.boundary.targetClusterUUID = "0x0a22"_ctv;
  pair.boundary.sourceWorkspace = "/tmp/source"_ctv;
  pair.boundary.targetWorkspace = "/tmp/target"_ctv;
  pair.boundary.sourceRuntimeIdentity = "1001"_ctv;
  pair.boundary.targetRuntimeIdentity = "1002"_ctv;
  pair.boundary.sourceParentNamespace = "pvd-p-1001"_ctv;
  pair.boundary.targetParentNamespace = "pvd-p-1002"_ctv;
  pair.boundary.sourceMachineIndex = pair.boundary.targetMachineIndex = 1;
  pair.boundary.sourceMachinePrivate4 = "10.0.0.10"_ctv;
  pair.boundary.targetMachinePrivate4 = "10.0.1.10"_ctv;
  pair.boundary.endpointIPv4 = "198.18.0.1"_ctv;
  pair.boundary.endpointPort = 19090;
  pair.sourceDeploymentID = 100;
  pair.targetDeploymentID = 200;
  pair.sourcePlanSHA256 = digest('a'); pair.targetPlanSHA256 = digest('b');
  pair.sourceBlobSHA256 = digest('c'); pair.targetBlobSHA256 = digest('c');
  TestPairBoundaryRecordV1Fixture priorV1 = {};
  priorV1.boundary = pair.boundary; priorV1.sourceDeploymentID = pair.sourceDeploymentID;
  priorV1.targetDeploymentID = pair.targetDeploymentID; priorV1.sourcePlanSHA256 = pair.sourcePlanSHA256;
  priorV1.targetPlanSHA256 = pair.targetPlanSHA256; priorV1.sourceBlobSHA256 = pair.sourceBlobSHA256;
  priorV1.targetBlobSHA256 = pair.targetBlobSHA256;
  String v1Bytes = {}, currentV1Bytes = {};
  BitseryEngine::serialize(v1Bytes, priorV1);
  auto currentV1 = pair; BitseryEngine::serialize(currentV1Bytes, currentV1);
  assert(v1Bytes == currentV1Bytes);
  assert(registry.admitTestPairBoundary(pair, pairStored, &failure));
  assert(registry.loadTestPairBoundary(pair.boundary.operationID, pairLoaded, &failure));
  assert(MothershipClusterRegistry::testPairBoundaryIdentityMatches(pair, pairLoaded));
  assert(registry.admitTestPairBoundary(pair, pairStored, &failure));
  auto changed = pair;
  changed.targetPlanSHA256 = digest('d');
  assert(!registry.admitTestPairBoundary(changed, pairStored, &failure));
  changed = pair; changed.boundary.operationID = "0x0abd"_ctv;
  assert(!registry.admitTestPairBoundary(changed, pairStored, &failure));
  changed = pair; changed.boundary.operationID = "0x000abc"_ctv;
  assert(!registry.admitTestPairBoundary(changed, pairStored, &failure));
  bool ownsBoundary = false;
  assert(registry.clusterHasOpenTestPairBoundary(uint128_t(0xa11), ownsBoundary, &failure) && ownsBoundary);
  assert(registry.clusterHasOpenTestPairBoundary(uint128_t(0xa22), ownsBoundary, &failure) && ownsBoundary);
  assert(!registry.clusterHasOpenTestPairBoundary(0, ownsBoundary, &failure) && !ownsBoundary &&
         failure == "test pair boundary cluster UUID is required"_ctv);
  assert(registry.advanceTestPairBoundary(pair, 1, false, pairStored, &failure));
  assert(!registry.advanceTestPairBoundary(pair, 1, false, pairLoaded, &failure)); // stale generation
  assert(!registry.advanceTestPairBoundary(pairStored, 0, false, pairLoaded, &failure));
  assert(registry.advanceTestPairBoundary(pairStored, 1, true, pairLoaded, &failure));
  assert(registry.clusterHasOpenTestPairBoundary(uint128_t(0xa11), ownsBoundary, &failure) && !ownsBoundary);
  assert(!registry.admitTestPairBoundary(pair, pairStored, &failure)); // closed ID cannot resurrect
  assert(!registry.advanceTestPairBoundary(pairLoaded, 1, false, pairStored, &failure));
  MothershipTestPairBoundaryRecord migration = pair;
  migration.version = 2; migration.boundary.operationID = "0x0abe"_ctv;
  migration.targetPlanSHA256.clear();
  DeploymentPlan targetPlan = {};
  targetPlan.config.applicationID = 7; targetPlan.config.versionID = 1;
  targetPlan.config.type = ApplicationType::stateless;
  targetPlan.stateless.nBase = 1;
  targetPlan.hasApiCredentialPolicy = true; targetPlan.apiCredentialPolicy.applicationID = 7;
  Wormhole endpoint = {}; endpoint.source = ExternalAddressSource::registeredRoutablePrefix;
  endpoint.routablePrefixUUID = 8; endpoint.layer4 = IPPROTO_TCP;
  endpoint.externalPort = endpoint.containerPort = 19090;
  targetPlan.wormholes.push_back(endpoint);
  migration.targetDeploymentID = targetPlan.config.deploymentID();
  BitseryEngine::serialize(migration.targetRequestPlan, targetPlan);
  assert(prodigyComputeSHA256Hex(migration.targetRequestPlan, migration.targetRequestPlanSHA256));
  migration.targetBlobBytes = 1234;
  TestPairBoundaryRecordV2Fixture priorV2 = {};
  priorV2.version = migration.version; priorV2.boundary = migration.boundary;
  priorV2.sourceDeploymentID = migration.sourceDeploymentID; priorV2.targetDeploymentID = migration.targetDeploymentID;
  priorV2.sourcePlanSHA256 = migration.sourcePlanSHA256; priorV2.targetPlanSHA256 = migration.targetPlanSHA256;
  priorV2.sourceBlobSHA256 = migration.sourceBlobSHA256; priorV2.targetBlobSHA256 = migration.targetBlobSHA256;
  priorV2.targetRequestPlan = migration.targetRequestPlan; priorV2.targetRequestPlanSHA256 = migration.targetRequestPlanSHA256;
  priorV2.targetBlobBytes = migration.targetBlobBytes;
  String v2Bytes = {}, currentV2Bytes = {};
  BitseryEngine::serialize(v2Bytes, priorV2);
  auto currentV2 = migration; BitseryEngine::serialize(currentV2Bytes, currentV2);
  assert(v2Bytes == currentV2Bytes);
  assert(registry.admitTestPairBoundary(migration, pairStored, &failure));
  assert(!registry.advanceTestPairBoundary(pairStored, 1, false, pairLoaded, &failure));
  auto conflict = migration; conflict.targetRequestPlanSHA256 = digest('e');
  assert(!registry.admitTestPairBoundary(conflict, pairLoaded, &failure));
  conflict = migration; conflict.targetBlobBytes += 1;
  assert(!registry.admitTestPairBoundary(conflict, pairLoaded, &failure));
  StatelessDeploymentAdmissionReceipt receipt = {};
  receipt.supported = receipt.accepted = receipt.peersCapable = true;
  auto& admission = receipt.admission;
  admission.operationID = uint128_t(0xabe); admission.clusterUUID = uint128_t(0xa22);
  admission.deploymentID = targetPlan.config.deploymentID(); admission.applicationID = 7; admission.versionID = 1;
  admission.requestPlanSHA256 = migration.targetRequestPlanSHA256;
  admission.normalizedPlanSHA256 = digest('d'); admission.artifactSHA256 = migration.targetBlobSHA256;
  admission.artifactBytes = migration.targetBlobBytes;
  admission.acceptedAuthorityGeneration = 9; admission.acceptedMasterUUID = 10; admission.acceptedMasterBootNs = 11;
  receipt.currentAuthorityGeneration = 9; receipt.currentMasterUUID = 10; receipt.currentMasterBootNs = 11;
  auto pendingReceipt = receipt; pendingReceipt.accepted = false; pendingReceipt.launchPending = true;
  assert(MothershipClusterRegistry::testPairTargetAdmissionIdentityMatches(pairStored, pendingReceipt));
  assert(!registry.recordTestPairTargetAdmission(pairStored, pendingReceipt, pairLoaded, &failure));
  pendingReceipt = receipt; pendingReceipt.peersCapable = false;
  assert(!registry.recordTestPairTargetAdmission(pairStored, pendingReceipt, pairLoaded, &failure));
  auto rejectedReceipt = receipt; rejectedReceipt.admission.operationID += 1;
  assert(!registry.recordTestPairTargetAdmission(pairStored, rejectedReceipt, pairLoaded, &failure));
  rejectedReceipt = receipt; rejectedReceipt.admission.artifactBytes += 1;
  assert(!registry.recordTestPairTargetAdmission(pairStored, rejectedReceipt, pairLoaded, &failure));
  assert(registry.recordTestPairTargetAdmission(pairStored, receipt, pairLoaded, &failure));
  assert(pairLoaded.targetPlanSHA256 == admission.normalizedPlanSHA256);
  assert(registry.admitTestPairBoundary(migration, pairStored, &failure)); // original request resumes accepted state
  assert(pairStored.targetAdmissionReceipt == pairLoaded.targetAdmissionReceipt);
  receipt.currentAuthorityGeneration = 20; receipt.currentMasterUUID = 21; receipt.currentMasterBootNs = 22;
  assert(registry.recordTestPairTargetAdmission(pairStored, receipt, pairLoaded, &failure));
  assert(pairStored.targetAdmissionReceipt == pairLoaded.targetAdmissionReceipt); // original acceptance retained
  rejectedReceipt = receipt; rejectedReceipt.admission.acceptedMasterUUID += 1;
  assert(!registry.recordTestPairTargetAdmission(pairStored, rejectedReceipt, pairLoaded, &failure));
  assert(registry.advanceTestPairBoundary(pairStored, 1, false, pairLoaded, &failure));
  }
  { // Cold registry reopen retains the exact target and selector; no second request owner.
    MothershipClusterRegistry registry(path);
    String operation("0x0abe"); String failure = {}; MothershipTestPairBoundaryRecord record = {};
    assert(registry.loadTestPairBoundary(operation, record, &failure));
    assert(record.version == 2 && record.selectorGeneration == 1 && !record.closed);
    StatelessDeploymentAdmissionReceipt receipt = {};
    assert(BitseryEngine::deserializeSafe(record.targetAdmissionReceipt, receipt));
    assert(receipt.accepted && receipt.admission.acceptedMasterUUID == 10 && receipt.currentMasterUUID == 10);
    assert(MothershipClusterRegistry::testPairTargetAdmissionMatches(record, receipt));

    MothershipTestPairBoundaryRecord readiness = record;
    readiness.version = 3;
    readiness.boundary.operationID = "0x0abf"_ctv;
    readiness.boundary.sourceClusterUUID = "0x0b11"_ctv;
    readiness.boundary.targetClusterUUID = "0x0b22"_ctv;
    readiness.targetPlanSHA256.clear(); readiness.targetAdmissionReceipt.clear();
    readiness.selectorGeneration = 0; readiness.closed = false;
    readiness.targetReadinessIntent.commissionedBrainCount = 3;
    readiness.targetReadinessIntent.declaredStatelessWorkloadCount = 1;
    ClusterTopology commissionedTopology = {};
    commissionedTopology.version = 9;
    for (uint128_t uuid : {uint128_t(0xb101), uint128_t(0xb102), uint128_t(0xb103)})
    {
      ClusterMachine& machine = commissionedTopology.machines.emplace_back();
      machine.uuid = uuid; machine.isBrain = true;
    }
    prodigyAppendUniqueClusterMachineAddress(commissionedTopology.machines[0].addresses.privateAddresses,
                                             readiness.boundary.targetMachinePrivate4, 24);
    assert(!mothershipBuildTestPairTargetReadinessIntent(ClusterTopology {}, readiness.boundary.targetMachinePrivate4,
                                                           readiness.targetReadinessIntent));
    assert(mothershipBuildTestPairTargetReadinessIntent(
        commissionedTopology, readiness.boundary.targetMachinePrivate4, readiness.targetReadinessIntent));
    assert(MothershipClusterRegistry::testPairBoundaryRecordValid(readiness));
    MothershipTestPairBoundaryRecord pairStored = {}, pairLoaded = {};
    assert(registry.admitTestPairBoundary(readiness, pairStored, &failure));
    assert(registry.admitTestPairBoundary(readiness, pairStored, &failure)); // exact pending retry
    assert(!registry.advanceTestPairBoundary(pairStored, 1, false, pairLoaded, &failure));
    auto changedIntent = readiness;
    changedIntent.targetReadinessIntent.endpointMachineUUID = uint128_t(0xb199);
    assert(!registry.admitTestPairBoundary(changedIntent, pairLoaded, &failure));
    auto stateful = readiness;
    DeploymentPlan forbidden = {};
    assert(BitseryEngine::deserializeSafe(stateful.targetRequestPlan, forbidden));
    forbidden.isStateful = true;
    BitseryEngine::serialize(stateful.targetRequestPlan, forbidden);
    assert(prodigyComputeSHA256Hex(stateful.targetRequestPlan, stateful.targetRequestPlanSHA256));
    assert(!MothershipClusterRegistry::testPairBoundaryRecordValid(stateful));

    auto v3Receipt = receipt;
    v3Receipt.admission.operationID = uint128_t(0xabf);
    v3Receipt.admission.clusterUUID = uint128_t(0xb22);
    assert(registry.recordTestPairTargetAdmission(pairStored, v3Receipt, pairLoaded, &failure));
    assert(pairLoaded.targetReadinessIntent.commissionedBrainUUIDs ==
           readiness.targetReadinessIntent.commissionedBrainUUIDs);
    assert(registry.admitTestPairBoundary(readiness, pairStored, &failure)); // exact accepted retry
    ClusterStatusReport clusterReport = {};
    clusterReport.hasTopology = true; clusterReport.topology = commissionedTopology;
    clusterReport.nMachines = 3; clusterReport.nApplications = 1;
    for (const ClusterMachine& expected : commissionedTopology.machines)
    {
      MachineStatusReport& machine = clusterReport.machineReports.emplace_back();
      machine.state = "healthy"_ctv; machine.isBrain = machine.controlPlaneReachable = machine.runtimeReady = true;
      machine.currentMaster = expected.uuid == commissionedTopology.machines[0].uuid;
      machine.machineUUID.assignItoh(expected.uuid);
    }
    ApplicationStatusReport& application = clusterReport.applicationReports.emplace_back();
    application.applicationID = 7;
    DeploymentStatusReport& deployment = application.deploymentReports.emplace_back();
    deployment.versionID = 1; deployment.state = DeploymentState::running;
    deployment.nTarget = deployment.nDeployed = deployment.nHealthy = 1;
    DeploymentIdentityReport identity = {};
    identity.found = identity.live = identity.profileEligible = true;
    identity.clusterUUID = uint128_t(0xb22); identity.deploymentID = readiness.targetDeploymentID;
    identity.applicationID = 7; identity.versionID = 1; identity.state = DeploymentState::running;
    identity.canonicalPlanSHA256 = pairStored.targetPlanSHA256; identity.containerBlobSHA256 = pairStored.targetBlobSHA256;
    identity.containerBlobBytes = pairStored.targetBlobBytes;
    identity.nTarget = identity.nDeployed = identity.nHealthy = 1;
    identity.observedEndpointIPv4 = readiness.boundary.endpointIPv4;
    identity.observedEndpointPort = readiness.boundary.endpointPort;
    identity.observedEndpointMachineUUID = commissionedTopology.machines[0].uuid;
    identity.authorityGeneration = 9; identity.masterUUID = commissionedTopology.machines[0].uuid; identity.masterBootNs = 11;
    assert(MothershipClusterRegistry::testPairWholeDestinationReady(pairStored, clusterReport, identity, &failure));
    auto reorderedTopology = clusterReport;
    reorderedTopology.topology.version += 1;
    std::reverse(reorderedTopology.topology.machines.begin(), reorderedTopology.topology.machines.end());
    assert(MothershipClusterRegistry::testPairWholeDestinationReady(pairStored, reorderedTopology, identity, &failure));
    auto unhealthy = clusterReport; unhealthy.machineReports[1].runtimeReady = false;
    assert(!MothershipClusterRegistry::testPairWholeDestinationReady(pairStored, unhealthy, identity, &failure));
    auto duplicateBrain = clusterReport; duplicateBrain.machineReports[2].machineUUID = duplicateBrain.machineReports[1].machineUUID;
    assert(!MothershipClusterRegistry::testPairWholeDestinationReady(pairStored, duplicateBrain, identity, &failure));
    auto missingWorkload = clusterReport; missingWorkload.nApplications = 0; missingWorkload.applicationReports.clear();
    assert(!MothershipClusterRegistry::testPairWholeDestinationReady(pairStored, missingWorkload, identity, &failure));
    auto extraWorkload = clusterReport; extraWorkload.nApplications = 2;
    assert(!MothershipClusterRegistry::testPairWholeDestinationReady(pairStored, extraWorkload, identity, &failure));
    auto statefulWorkload = clusterReport; statefulWorkload.applicationReports[0].deploymentReports[0].isStateful = true;
    assert(!MothershipClusterRegistry::testPairWholeDestinationReady(pairStored, statefulWorkload, identity, &failure));
    auto changedTopology = clusterReport; changedTopology.topology.machines[2].uuid = uint128_t(0xb104);
    assert(!MothershipClusterRegistry::testPairWholeDestinationReady(pairStored, changedTopology, identity, &failure));
    auto stalePlan = identity; stalePlan.canonicalPlanSHA256 = digest('f');
    assert(!MothershipClusterRegistry::testPairWholeDestinationReady(pairStored, clusterReport, stalePlan, &failure));
    auto wrongEndpointMachine = identity; wrongEndpointMachine.observedEndpointMachineUUID = commissionedTopology.machines[1].uuid;
    assert(!MothershipClusterRegistry::testPairWholeDestinationReady(pairStored, clusterReport, wrongEndpointMachine, &failure));
    auto staleMaster = identity; staleMaster.masterUUID = commissionedTopology.machines[1].uuid;
    assert(!MothershipClusterRegistry::testPairWholeDestinationReady(pairStored, clusterReport, staleMaster, &failure));
    auto staleState = identity; staleState.state = DeploymentState::deploying;
    assert(!MothershipClusterRegistry::testPairWholeDestinationReady(pairStored, clusterReport, staleState, &failure));
    auto staleVersion = identity; staleVersion.versionID = 2;
    assert(!MothershipClusterRegistry::testPairWholeDestinationReady(pairStored, clusterReport, staleVersion, &failure));
    assert(!registry.advanceTestPairBoundary(readiness, 1, false, pairLoaded, &failure)); // stale pre-admission expectation
    MothershipVirtualDatacenterPairDrainObservation drain = {};
    drain.operationID = readiness.boundary.operationID; drain.sourceClusterUUID = readiness.boundary.sourceClusterUUID;
    drain.targetClusterUUID = readiness.boundary.targetClusterUUID;
    drain.sourceRuntimeIdentity = readiness.boundary.sourceRuntimeIdentity;
    drain.targetRuntimeIdentity = readiness.boundary.targetRuntimeIdentity;
    drain.sourceMachineIndex = readiness.boundary.sourceMachineIndex;
    drain.targetMachineIndex = readiness.boundary.targetMachineIndex;
    drain.selectedTarget = drain.drainCapability = true; drain.sourceFlows = 0; drain.targetFlows = 7;
    assert(!registry.recordTestPairSourceDrain(pairStored, drain, pairLoaded, &failure)); // selector still source
    assert(registry.advanceTestPairBoundary(pairStored, 1, false, pairLoaded, &failure));
    pairStored = pairLoaded;
    auto nonzeroSource = drain; nonzeroSource.sourceFlows = 1;
    assert(!registry.recordTestPairSourceDrain(pairStored, nonzeroSource, pairLoaded, &failure));
    auto conflictDrain = drain; conflictDrain.operationID = "0x0ac0"_ctv;
    assert(!registry.recordTestPairSourceDrain(pairStored, conflictDrain, pairLoaded, &failure));
    assert(registry.recordTestPairSourceDrain(pairStored, drain, pairLoaded, &failure));
    assert(!pairLoaded.sourceDrainObservation.empty());
    MothershipTestPairBoundaryRecord drainReloaded = {};
    assert(registry.loadTestPairBoundary(readiness.boundary.operationID, drainReloaded, &failure));
    auto retryDrain = drain; retryDrain.targetFlows = 99;
    assert(registry.recordTestPairSourceDrain(drainReloaded, retryDrain, pairStored, &failure));
    assert(pairStored.sourceDrainObservation == drainReloaded.sourceDrainObservation);

    // Arm the exact open v3 pair. The fence is durable before the external
    // guest lifecycle owner can reset anything.
    MothershipVirtualDatacenterPairGuestResetFence resetFence = {};
    resetFence.operationID = pairStored.boundary.operationID;
    assert(mothershipVirtualDatacenterPairDescriptorSHA256(pairStored.boundary, resetFence.descriptorSHA256));
    resetFence.bootID = "11111111-1111-4111-8111-111111111111"_ctv;
    resetFence.guestID = "nametag-prodigy"_ctv;
    auto staleBeforeArm = pairStored;
    assert(registry.recordTestPairGuestResetFence(pairStored, resetFence, pairLoaded, &failure));
    assert(pairLoaded.version == 4 && pairLoaded.guestResetFence.bootID == resetFence.bootID &&
           pairLoaded.guestResetCompletedBootID.empty());
    assert(registry.recordTestPairGuestResetFence(staleBeforeArm, resetFence, pairStored, &failure)); // exact retry
    auto conflictingFence = resetFence;
    conflictingFence.bootID = "22222222-2222-4222-8222-222222222222"_ctv;
    assert(!registry.recordTestPairGuestResetFence(staleBeforeArm, conflictingFence, pairStored, &failure));
    assert(!registry.recordTestPairTargetAdmission(pairLoaded, v3Receipt, pairStored, &failure));
    assert(!registry.recordTestPairSourceDrain(pairLoaded, retryDrain, pairStored, &failure));
    assert(!registry.advanceTestPairBoundary(pairLoaded, 0, false, pairStored, &failure));
    assert(!registry.advanceTestPairBoundary(pairLoaded, 1, true, pairStored, &failure)); // reset receipt required before close
    assert(!registry.recordTestPairGuestResetCompletion(pairLoaded, resetFence.bootID, pairStored, &failure));
    String completedBootID = "33333333-3333-4333-8333-333333333333"_ctv;
    assert(registry.recordTestPairGuestResetCompletion(pairLoaded, completedBootID, pairStored, &failure));
    assert(pairStored.guestResetCompletedBootID == completedBootID);
    assert(registry.recordTestPairGuestResetCompletion(pairLoaded, completedBootID, pairStored, &failure)); // exact completion retry
    assert(!registry.recordTestPairGuestResetCompletion(pairLoaded, "44444444-4444-4444-8444-444444444444"_ctv, pairStored, &failure));
    assert(registry.advanceTestPairBoundary(pairStored, 1, true, pairLoaded, &failure));
    assert(!registry.recordTestPairSourceDrain(pairLoaded, retryDrain, pairStored, &failure));
    MothershipTestPairBoundaryRecord reopened = {};
    assert(registry.loadTestPairBoundary(readiness.boundary.operationID, reopened, &failure));
    assert(reopened.version == 4 && reopened.closed && reopened.guestResetFence.bootID == resetFence.bootID &&
           reopened.guestResetCompletedBootID == completedBootID &&
           reopened.targetReadinessIntent.commissionedBrainUUIDs == readiness.targetReadinessIntent.commissionedBrainUUIDs);

    // Disposal fencing is also valid before selection or a drain receipt: the
    // provider's dead-owner proof and later changed boot ID establish cleanup
    // safety for an interrupted legacy pair.
    auto earlyReset = readiness;
    earlyReset.boundary.operationID = "0x0ac1"_ctv;
    earlyReset.boundary.sourceClusterUUID = "0x0c11"_ctv;
    earlyReset.boundary.targetClusterUUID = "0x0c22"_ctv;
    earlyReset.targetPlanSHA256.clear(); earlyReset.targetAdmissionReceipt.clear();
    earlyReset.selectorGeneration = 0; earlyReset.closed = false;
    assert(registry.admitTestPairBoundary(earlyReset, pairStored, &failure));
    MothershipVirtualDatacenterPairGuestResetFence earlyFence = {};
    earlyFence.operationID = earlyReset.boundary.operationID;
    assert(mothershipVirtualDatacenterPairDescriptorSHA256(earlyReset.boundary, earlyFence.descriptorSHA256));
    earlyFence.bootID = "55555555-5555-4555-8555-555555555555"_ctv;
    earlyFence.guestID = "nametag-prodigy"_ctv;
    assert(registry.recordTestPairGuestResetFence(pairStored, earlyFence, pairLoaded, &failure));
    assert(pairLoaded.version == 4 && pairLoaded.selectorGeneration == 0 &&
           pairLoaded.targetAdmissionReceipt.empty() && pairLoaded.sourceDrainObservation.empty());
    String earlyCompletedBootID = "66666666-6666-4666-8666-666666666666"_ctv;
    assert(registry.recordTestPairGuestResetCompletion(pairLoaded, earlyCompletedBootID, pairStored, &failure));
    assert(registry.advanceTestPairBoundary(pairStored, 0, true, pairLoaded, &failure));
    assert(pairLoaded.closed && pairLoaded.guestResetCompletedBootID == earlyCompletedBootID);
  }
  return 0;
}
