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

static ProdigyLocalCousinServicePermission testPairCousinPermission(
    uint128_t permissionUUID, uint128_t pairUUID, uint128_t localClusterUUID,
    uint128_t peerClusterUUID, CousinRouteHalf localHalf, uint16_t localApplicationID,
    uint16_t peerApplicationID, uint64_t localDeploymentID, uint64_t localCousinServicePrefix,
    uint64_t peerCousinServicePrefix, char planDigest, char artifactDigest)
{
  ProdigyLocalCousinServicePermission permission = {};
  permission.protocolVersion = ProdigyLocalCousinServicePermission::baselineVersion;
  permission.permissionUUID = permissionUUID;
  permission.pairUUID = pairUUID;
  permission.logicalWorkloadUUID = 0x510;
  permission.logicalServiceUUID = 0x511;
  permission.localClusterUUID = localClusterUUID;
  permission.peerClusterUUID = peerClusterUUID;
  permission.localHalf = localHalf;
  permission.localApplicationID = localApplicationID;
  permission.peerApplicationID = peerApplicationID;
  permission.localCousinServicePrefix = localCousinServicePrefix;
  permission.peerCousinServicePrefix = peerCousinServicePrefix;
  permission.slots.insert(3);
  permission.localDeploymentID = localDeploymentID;
  permission.canonicalPlanSHA256 = digest(planDigest);
  permission.artifactSHA256 = digest(artifactDigest);
  permission.artifactBytes = 8192;
  permission.generation = 1;
  permission.acceptedAuthorityGeneration = 7;
  permission.baselineLogicalCores = 2;
  permission.baselineMemoryMB = 1024;
  permission.baselineStorageMB = 1024;
  return permission;
}

static CousinRouteApplyReceipt testPairCousinRouteReceipt(
    const CousinRouteRecord& route, CousinRouteHalf localHalf, uint64_t localRuntimeRevision)
{
  CousinRouteApplyReceipt receipt = {};
  receipt.routeUUID = route.routeUUID;
  receipt.generation = route.generation;
  assert(cousinRouteAuthorizationDigest(route, receipt.authorizationSHA256));
  receipt.localClusterUUID = localHalf == CousinRouteHalf::source ? route.sourceClusterUUID : route.destinationClusterUUID;
  receipt.localHalf = localHalf;
  receipt.keyEpoch = route.keyEpoch;
  receipt.localRuntimeRevision = localRuntimeRevision;
  receipt.installedState = route.state;
  return receipt;
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
  MothershipUpgradeAdmissionRecord expectedEligibleAdmission = {};
  MothershipUpgradeAdmissionRecord expectedIneligibleAdmission = {};
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
  if (!registry.recordUpgradeAdmission(request, recorded, resumed, &failure)) {
    std::fprintf(stderr,"initial upgrade admission failure: %s\n",failure.c_str()); assert(false);
  }
  assert(!resumed && recorded.firstStopGate == request.firstStopGate);
  assert(registry.recordUpgradeAdmission(request, recorded, resumed, &failure));
  assert(resumed);
  MothershipUpgradeAdmissionRecord ineligible = request;
  ineligible.operationID = uint128_t(0xB23);
  assert(registry.recordUpgradeAdmission(ineligible, expectedIneligibleAdmission, resumed, &failure));
  assert(!resumed && !expectedIneligibleAdmission.eligible);
  request.observationReceiptVersion = 2;
  request.observationReportSHA256 = digest('4');
  request.plannerInputSHA256 = digest('5');
  request.eligible = true;
  request.firstStopGate.clear();
  assert(registry.recordUpgradeAdmission(request, recorded, resumed, &failure));
  assert(!resumed && recorded.eligible && recorded.rejectedObservations.size() == 1);
  expectedEligibleAdmission = recorded;
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

  // A live remote runtime recovery is a separate, receipt-led process
  // replacement. It binds the immutable admitted source/target bundle pair and
  // cannot replace a member, its source process, or its stopped-store proof on
  // retry.
  MothershipProdigyCluster remote = {};
  remote.clusterUUID = expectedEligibleAdmission.clusterUUID;
  remote.deploymentMode = MothershipClusterDeploymentMode::remote;
  remote.provider = MothershipClusterProvider::vultr;
  remote.nBrains = 3;
  remote.topology.version = 1;
  for (uint32_t index = 0; index < 3; ++index)
  {
    ClusterMachine machine = {};
    machine.uuid = uint128_t(0xD10 + index);
    machine.isBrain = true;
    remote.topology.machines.push_back(std::move(machine));
  }
  remote.topology.machines[0].hardware.inventoryComplete = true;
  remote.topology.machines[0].hardware.collectedAtMs = 10;
  remote.topology.machines[0].hardware.cpu.logicalCores = 4;
  remote.topology.machines[0].hardware.memory.totalMB = 8192;
  remote.topology.machines[0].totalLogicalCores = 4;
  remote.topology.machines[0].totalMemoryMB = 8192;
  String topologyBytes = {}, topologySHA256 = {};
  auto topologyCopy = remote.topology;
  assert(BitseryEngine::serialize(topologyBytes, topologyCopy));
  assert(prodigyComputeSHA256Hex(topologyBytes, topologySHA256));
  String admissionBytes = {}, admissionSHA256 = {};
  auto admissionCopy = expectedEligibleAdmission;
  assert(BitseryEngine::serialize(admissionBytes, admissionCopy));
  assert(prodigyComputeSHA256Hex(admissionBytes, admissionSHA256));
  MothershipRemoteRuntimeRecoveryCohortRecord recovery = {};
  recovery.clusterUUID = remote.clusterUUID;
  recovery.operationID = expectedEligibleAdmission.operationID;
  remote.remoteProdigyPath = "/root/prodigy"_ctv;
  recovery.runtimeRoot = remote.remoteProdigyPath;
  recovery.authorityGeneration = expectedEligibleAdmission.authorityGeneration;
  recovery.cohortInterruptionAccepted = true;
  recovery.topologySHA256 = topologySHA256;
  recovery.admissionRecordSHA256 = admissionSHA256;
  recovery.sourceBundleSHA256 = expectedEligibleAdmission.sourceBundleSHA256;
  recovery.sourceContractSHA256 = expectedEligibleAdmission.sourceContractSHA256;
  recovery.sourceProdigySHA256 = expectedEligibleAdmission.sourceProdigySHA256;
  recovery.sourceMothershipSHA256 = expectedEligibleAdmission.sourceMothershipSHA256;
  recovery.targetBundleSHA256 = expectedEligibleAdmission.targetBundleSHA256;
  recovery.targetContractSHA256 = expectedEligibleAdmission.targetContractSHA256;
  recovery.targetProdigySHA256 = digest('7');
  recovery.targetMothershipSHA256 = digest('8');
  for (uint32_t index = 0; index < 3; ++index)
  {
    MothershipRemoteRuntimeRecoveryMember member = {};
    member.machineUUID = remote.topology.machines[index].uuid;
    member.linuxMachineID.assign(index == 0 ? "00000000000000000000000000000001" :
                                 index == 1 ? "00000000000000000000000000000002" :
                                              "00000000000000000000000000000003");
    member.bootID.assign(index == 0 ? "00000000-0000-4000-8000-000000000001" :
                         index == 1 ? "00000000-0000-4000-8000-000000000002" :
                                      "00000000-0000-4000-8000-000000000003");
    member.sourceProcessPID = 100 + index;
    member.sourceProcessStartTicks = 1000 + index;
    recovery.members.push_back(std::move(member));
  }
  MothershipRemoteRuntimeRecoveryCohortRecord recoveryStored = {};
  bool recoveryPending = true;
  assert(registry.remoteRuntimeRecoveryPending(remote.clusterUUID, recoveryPending, &failure));
  assert(!recoveryPending);
  const auto addPhaseReceipts = [](MothershipRemoteRuntimeRecoveryCohortRecord& candidate) {
    for (uint32_t index = 0; index < candidate.members.size(); ++index)
    {
      while (candidate.members[index].phaseReceipts.size() < uint8_t(candidate.phase))
      {
        MothershipRemoteRuntimeRecoveryMember::PhaseReceipt receipt = {};
        const auto receiptPhase = MothershipRemoteRuntimeRecoveryPhase(
            candidate.members[index].phaseReceipts.size() + 1);
        MothershipClusterRegistry::remoteRuntimeRecoveryOperationMarker(
            candidate.operationID, candidate.members[index].machineUUID, receiptPhase, receipt.operationMarker);
        receipt.receiptSHA256 = digest(char('0' + uint8_t(receiptPhase) + index));
        candidate.members[index].phaseReceipts.push_back(std::move(receipt));
      }
    }
  };
  const auto addAbortReceipts = [](MothershipRemoteRuntimeRecoveryCohortRecord& candidate) {
    assert(candidate.phase == MothershipRemoteRuntimeRecoveryPhase::abortedBeforeInstallation);
    for (uint32_t index = 0; index < candidate.members.size(); ++index)
    {
      assert(candidate.members[index].phaseReceipts.size() == 3);
      MothershipRemoteRuntimeRecoveryMember::PhaseReceipt receipt = {};
      MothershipClusterRegistry::remoteRuntimeRecoveryOperationMarker(
          candidate.operationID, candidate.members[index].machineUUID,
          MothershipRemoteRuntimeRecoveryPhase::abortedBeforeInstallation, receipt.operationMarker);
      receipt.receiptSHA256 = digest(char('a' + index));
      candidate.members[index].phaseReceipts.push_back(std::move(receipt));
    }
  };
  const auto makeWithdrawableRecovery = [&](uint128_t operationID, MothershipUpgradePath path = MothershipUpgradePath::sameLogicalRollout) {
    auto admission = expectedEligibleAdmission;
    admission.operationID = operationID;
    admission.approvedPath = uint8_t(path);
    assert(registry.recordUpgradeAdmission(admission, recorded, resumed, &failure));
    String bytes = {}, sha256 = {};
    auto copy = admission;
    assert(BitseryEngine::serialize(bytes, copy));
    assert(prodigyComputeSHA256Hex(bytes, sha256));
    auto cohort = recovery;
    cohort.operationID = operationID;
    cohort.admissionRecordSHA256 = sha256;
    return cohort;
  };
  auto cohortOnlyAdmission = makeWithdrawableRecovery(uint128_t(0xD1F), MothershipUpgradePath::sameLogicalCohortRecovery);
  assert(registry.admitRemoteRuntimeRecoveryCohort(cohortOnlyAdmission,remote,recoveryStored,resumed,&failure));
  assert(registry.withdrawRemoteRuntimeRecoveryCohort(remote.clusterUUID,cohortOnlyAdmission.operationID,recoveryStored,&failure));
  auto withdrawnAtAdmission = makeWithdrawableRecovery(uint128_t(0xD20));
  assert(registry.admitRemoteRuntimeRecoveryCohort(withdrawnAtAdmission, remote, recoveryStored, resumed, &failure));
  assert(!resumed);
  const auto admittedBeforeWithdrawal = recoveryStored;
  auto directWithdrawal = recoveryStored;
  directWithdrawal.phase = MothershipRemoteRuntimeRecoveryPhase::withdrawnBeforeFence;
  assert(!registry.advanceRemoteRuntimeRecoveryCohort(directWithdrawal, directWithdrawal.phase, recoveryStored, resumed, &failure));
  assert(registry.withdrawRemoteRuntimeRecoveryCohort(remote.clusterUUID, withdrawnAtAdmission.operationID, recoveryStored, &failure));
  assert(recoveryStored.phase == MothershipRemoteRuntimeRecoveryPhase::withdrawnBeforeFence);
  assert(MothershipClusterRegistry::remoteRuntimeRecoveryIdentityMatches(admittedBeforeWithdrawal, recoveryStored));
  for (const auto& member : recoveryStored.members)
  {
    assert(member.phaseReceipts.empty());
    assert(member.stateSHA256.empty() && member.secretsSHA256.empty() && member.containerInventorySHA256.empty());
    assert(member.privateLoaderSHA256.empty() && member.retainedNetworkSHA256.empty());
    assert(!member.targetRuntimeInstalled);
  }
  auto withdrawnReplay = recoveryStored;
  assert(registry.withdrawRemoteRuntimeRecoveryCohort(remote.clusterUUID, withdrawnAtAdmission.operationID, recoveryStored, &failure));
  String withdrawnBytes = {}, withdrawnReplayBytes = {};
  assert(BitseryEngine::serialize(withdrawnBytes, recoveryStored));
  assert(BitseryEngine::serialize(withdrawnReplayBytes, withdrawnReplay));
  assert(withdrawnBytes == withdrawnReplayBytes);
  assert(registry.remoteRuntimeRecoveryPending(remote.clusterUUID, recoveryPending, &failure));
  assert(!recoveryPending);
  auto withdrawnAtStage = makeWithdrawableRecovery(uint128_t(0xD21));
  assert(registry.admitRemoteRuntimeRecoveryCohort(withdrawnAtStage, remote, recoveryStored, resumed, &failure));
  withdrawnAtStage.phase = MothershipRemoteRuntimeRecoveryPhase::staged;
  addPhaseReceipts(withdrawnAtStage);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(withdrawnAtStage, withdrawnAtStage.phase, recoveryStored, resumed, &failure));
  const auto stagedBeforeWithdrawal = recoveryStored;
  assert(registry.withdrawRemoteRuntimeRecoveryCohort(remote.clusterUUID, withdrawnAtStage.operationID, recoveryStored, &failure));
  assert(recoveryStored.phase == MothershipRemoteRuntimeRecoveryPhase::withdrawnBeforeFence);
  assert(MothershipClusterRegistry::remoteRuntimeRecoveryIdentityMatches(stagedBeforeWithdrawal, recoveryStored));
  for (uint32_t index = 0; index < recoveryStored.members.size(); ++index)
  {
    assert(recoveryStored.members[index].phaseReceipts.size() == 1);
    assert(recoveryStored.members[index].phaseReceipts[0].operationMarker == stagedBeforeWithdrawal.members[index].phaseReceipts[0].operationMarker);
    assert(recoveryStored.members[index].phaseReceipts[0].receiptSHA256 == stagedBeforeWithdrawal.members[index].phaseReceipts[0].receiptSHA256);
    assert(recoveryStored.members[index].stateSHA256.empty() && recoveryStored.members[index].secretsSHA256.empty());
    assert(recoveryStored.members[index].containerInventorySHA256.empty() && recoveryStored.members[index].privateLoaderSHA256.empty());
    assert(recoveryStored.members[index].retainedNetworkSHA256.empty() && !recoveryStored.members[index].targetRuntimeInstalled);
  }
  assert(registry.withdrawRemoteRuntimeRecoveryCohort(remote.clusterUUID, withdrawnAtStage.operationID, recoveryStored, &failure));
  assert(registry.remoteRuntimeRecoveryPending(remote.clusterUUID, recoveryPending, &failure));
  assert(!recoveryPending);
  auto wrongBoot = recovery;
  wrongBoot.members[0].bootID.assign("not-a-kernel-boot-id"_ctv);
  assert(!registry.admitRemoteRuntimeRecoveryCohort(wrongBoot, remote, recoveryStored, resumed, &failure));
  assert(registry.admitRemoteRuntimeRecoveryCohort(recovery, remote, recoveryStored, resumed, &failure));
  assert(!resumed && recoveryStored.phase == MothershipRemoteRuntimeRecoveryPhase::admitted);
  assert(registry.remoteRuntimeRecoveryPending(remote.clusterUUID, recoveryPending, &failure));
  assert(recoveryPending);
  assert(registry.remoteRuntimeRecoveryPending(remote.clusterUUID + 1, recoveryPending, &failure));
  assert(!recoveryPending);
  assert(registry.admitRemoteRuntimeRecoveryCohort(recovery, remote, recoveryStored, resumed, &failure));
  assert(resumed);
  auto partialRecovery = recovery;
  partialRecovery.members.pop_back();
  assert(!registry.admitRemoteRuntimeRecoveryCohort(partialRecovery, remote, recoveryStored, resumed, &failure));
  auto wrongAdmission = recovery;
  wrongAdmission.targetBundleSHA256 = digest('9');
  assert(!registry.admitRemoteRuntimeRecoveryCohort(wrongAdmission, remote, recoveryStored, resumed, &failure));
  auto overlappingAdmission = expectedEligibleAdmission;
  overlappingAdmission.operationID = uint128_t(0xD22);
  assert(registry.recordUpgradeAdmission(overlappingAdmission, recorded, resumed, &failure));
  String overlappingAdmissionBytes = {}, overlappingAdmissionSHA256 = {};
  auto overlappingAdmissionCopy = overlappingAdmission;
  assert(BitseryEngine::serialize(overlappingAdmissionBytes, overlappingAdmissionCopy));
  assert(prodigyComputeSHA256Hex(overlappingAdmissionBytes, overlappingAdmissionSHA256));
  auto overlappingRecovery = recovery;
  overlappingRecovery.operationID = overlappingAdmission.operationID;
  overlappingRecovery.admissionRecordSHA256 = overlappingAdmissionSHA256;
  assert(!registry.admitRemoteRuntimeRecoveryCohort(overlappingRecovery, remote, recoveryStored, resumed, &failure));
  auto abortTooEarly = recovery;
  abortTooEarly.phase = MothershipRemoteRuntimeRecoveryPhase::frozen;
  addPhaseReceipts(abortTooEarly);
  for (uint32_t index = 0; index < abortTooEarly.members.size(); ++index)
  {
    abortTooEarly.members[index].stateSHA256 = digest(char('a' + index));
    abortTooEarly.members[index].secretsSHA256 = digest(char('d' + index));
    abortTooEarly.members[index].containerInventorySHA256 = digest(char('1' + index));
    abortTooEarly.members[index].privateLoaderSHA256 = digest(char('4' + index));
    abortTooEarly.members[index].retainedNetworkSHA256 = digest(char('7' + index));
  }
  abortTooEarly.phase = MothershipRemoteRuntimeRecoveryPhase::abortedBeforeInstallation;
  addAbortReceipts(abortTooEarly);
  assert(!registry.abortRemoteRuntimeRecoveryCohort(abortTooEarly, recoveryStored, &failure));
  auto phase = recovery;
  phase.phase = MothershipRemoteRuntimeRecoveryPhase::staged;
  addPhaseReceipts(phase);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(phase, phase.phase, recoveryStored, resumed, &failure));
  assert(!resumed && recoveryStored.phase == MothershipRemoteRuntimeRecoveryPhase::staged);
  auto alteredIdentity = phase;
  alteredIdentity.members[0].sourceProcessStartTicks += 1;
  assert(!registry.advanceRemoteRuntimeRecoveryCohort(alteredIdentity, alteredIdentity.phase, recoveryStored, resumed, &failure));
  auto skipped = phase;
  skipped.phase = MothershipRemoteRuntimeRecoveryPhase::frozen;
  addPhaseReceipts(skipped);
  for (uint32_t index = 0; index < skipped.members.size(); ++index)
  {
    skipped.members[index].stateSHA256 = digest(char('a' + index));
    skipped.members[index].secretsSHA256 = digest(char('d' + index));
    skipped.members[index].containerInventorySHA256 = digest(char('1' + index));
    skipped.members[index].privateLoaderSHA256 = digest(char('4' + index));
    skipped.members[index].retainedNetworkSHA256 = digest(char('7' + index));
  }
  assert(!registry.advanceRemoteRuntimeRecoveryCohort(skipped, skipped.phase, recoveryStored, resumed, &failure));
  phase.phase = MothershipRemoteRuntimeRecoveryPhase::fenced;
  addPhaseReceipts(phase);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(phase, phase.phase, recoveryStored, resumed, &failure));
  assert(!registry.withdrawRemoteRuntimeRecoveryCohort(remote.clusterUUID, recovery.operationID, recoveryStored, &failure));
  assert(failure == "remote runtime recovery cohort can be withdrawn only before fence"_ctv);
  phase.phase = MothershipRemoteRuntimeRecoveryPhase::frozen;
  addPhaseReceipts(phase);
  for (uint32_t index = 0; index < phase.members.size(); ++index)
  {
    phase.members[index].stateSHA256 = digest(char('a' + index));
    phase.members[index].secretsSHA256 = digest(char('d' + index));
    phase.members[index].containerInventorySHA256 = digest(char('1' + index));
    phase.members[index].privateLoaderSHA256 = digest(char('4' + index));
    phase.members[index].retainedNetworkSHA256 = digest(char('7' + index));
  }
  assert(registry.advanceRemoteRuntimeRecoveryCohort(phase, phase.phase, recoveryStored, resumed, &failure));
  auto abortMissingReceipt = phase;
  abortMissingReceipt.phase = MothershipRemoteRuntimeRecoveryPhase::abortedBeforeInstallation;
  assert(!registry.abortRemoteRuntimeRecoveryCohort(abortMissingReceipt, recoveryStored, &failure));
  auto abortChangedProof = phase;
  abortChangedProof.phase = MothershipRemoteRuntimeRecoveryPhase::abortedBeforeInstallation;
  addAbortReceipts(abortChangedProof);
  abortChangedProof.members[0].stateSHA256 = digest('f');
  assert(!registry.abortRemoteRuntimeRecoveryCohort(abortChangedProof, recoveryStored, &failure));
  auto abortWithInstalledTarget = phase;
  abortWithInstalledTarget.phase = MothershipRemoteRuntimeRecoveryPhase::abortedBeforeInstallation;
  addAbortReceipts(abortWithInstalledTarget);
  abortWithInstalledTarget.members[0].targetRuntimeInstalled = true;
  assert(!registry.abortRemoteRuntimeRecoveryCohort(abortWithInstalledTarget, recoveryStored, &failure));
  auto aborted = phase;
  aborted.phase = MothershipRemoteRuntimeRecoveryPhase::abortedBeforeInstallation;
  addAbortReceipts(aborted);
  assert(!registry.advanceRemoteRuntimeRecoveryCohort(aborted, aborted.phase, recoveryStored, resumed, &failure));
  assert(registry.abortRemoteRuntimeRecoveryCohort(aborted, recoveryStored, &failure));
  assert(recoveryStored.phase == MothershipRemoteRuntimeRecoveryPhase::abortedBeforeInstallation);
  for (uint32_t index = 0; index < phase.members.size(); ++index)
  {
    assert(recoveryStored.members[index].phaseReceipts.size() == 4);
    for (uint32_t receiptIndex = 0; receiptIndex < 3; ++receiptIndex)
    {
      assert(recoveryStored.members[index].phaseReceipts[receiptIndex].operationMarker ==
             phase.members[index].phaseReceipts[receiptIndex].operationMarker);
      assert(recoveryStored.members[index].phaseReceipts[receiptIndex].receiptSHA256 ==
             phase.members[index].phaseReceipts[receiptIndex].receiptSHA256);
    }
    assert(!recoveryStored.members[index].targetRuntimeInstalled);
  }
  assert(registry.abortRemoteRuntimeRecoveryCohort(aborted, recoveryStored, &failure));
  assert(registry.remoteRuntimeRecoveryPending(remote.clusterUUID, recoveryPending, &failure));
  assert(!recoveryPending);
  auto recoveryAfterAbort = makeWithdrawableRecovery(uint128_t(0xD23));
  assert(registry.admitRemoteRuntimeRecoveryCohort(recoveryAfterAbort, remote, recoveryStored, resumed, &failure));
  phase = recoveryAfterAbort;
  phase.phase = MothershipRemoteRuntimeRecoveryPhase::staged;
  addPhaseReceipts(phase);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(phase, phase.phase, recoveryStored, resumed, &failure));
  phase.phase = MothershipRemoteRuntimeRecoveryPhase::fenced;
  addPhaseReceipts(phase);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(phase, phase.phase, recoveryStored, resumed, &failure));
  phase.phase = MothershipRemoteRuntimeRecoveryPhase::frozen;
  addPhaseReceipts(phase);
  for (uint32_t index = 0; index < phase.members.size(); ++index)
  {
    phase.members[index].stateSHA256 = digest(char('a' + index));
    phase.members[index].secretsSHA256 = digest(char('d' + index));
    phase.members[index].containerInventorySHA256 = digest(char('1' + index));
    phase.members[index].privateLoaderSHA256 = digest(char('4' + index));
    phase.members[index].retainedNetworkSHA256 = digest(char('7' + index));
  }
  assert(registry.advanceRemoteRuntimeRecoveryCohort(phase, phase.phase, recoveryStored, resumed, &failure));
  phase.phase = MothershipRemoteRuntimeRecoveryPhase::quiesced;
  addPhaseReceipts(phase);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(phase, phase.phase, recoveryStored, resumed, &failure));
  auto abortTooLate = phase;
  abortTooLate.phase = MothershipRemoteRuntimeRecoveryPhase::abortedBeforeInstallation;
  for (auto& member : abortTooLate.members) member.phaseReceipts.pop_back();
  addAbortReceipts(abortTooLate);
  assert(!registry.abortRemoteRuntimeRecoveryCohort(abortTooLate, recoveryStored, &failure));
  auto alteredProof = phase;
  alteredProof.members[0].stateSHA256 = digest('f');
  assert(!registry.advanceRemoteRuntimeRecoveryCohort(alteredProof, alteredProof.phase, recoveryStored, resumed, &failure));
  auto alteredPrivateLoader = phase;
  alteredPrivateLoader.members[0].privateLoaderSHA256 = digest('f');
  assert(!registry.advanceRemoteRuntimeRecoveryCohort(alteredPrivateLoader, alteredPrivateLoader.phase, recoveryStored, resumed, &failure));
  auto alteredNetwork = phase;
  alteredNetwork.members[0].retainedNetworkSHA256 = digest('f');
  assert(!registry.advanceRemoteRuntimeRecoveryCohort(alteredNetwork, alteredNetwork.phase, recoveryStored, resumed, &failure));
  auto alteredReceipt = phase;
  alteredReceipt.members[0].phaseReceipts[0].receiptSHA256 = digest('f');
  assert(!registry.advanceRemoteRuntimeRecoveryCohort(alteredReceipt, alteredReceipt.phase, recoveryStored, resumed, &failure));
  phase.phase = MothershipRemoteRuntimeRecoveryPhase::installed;
  addPhaseReceipts(phase);
  phase.members[0].targetRuntimeInstalled = true;
  phase.members[1].targetRuntimeInstalled = true;
  assert(!registry.advanceRemoteRuntimeRecoveryCohort(phase, phase.phase, recoveryStored, resumed, &failure));
  phase.members[2].targetRuntimeInstalled = true;
  assert(registry.advanceRemoteRuntimeRecoveryCohort(phase, phase.phase, recoveryStored, resumed, &failure));
  phase.phase = MothershipRemoteRuntimeRecoveryPhase::activationStarted;
  addPhaseReceipts(phase);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(phase, phase.phase, recoveryStored, resumed, &failure));
  phase.phase = MothershipRemoteRuntimeRecoveryPhase::completed;
  addPhaseReceipts(phase);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(phase, phase.phase, recoveryStored, resumed, &failure));
  auto regressed = phase;
  regressed.phase = MothershipRemoteRuntimeRecoveryPhase::installed;
  for (auto& member : regressed.members)
    while (member.phaseReceipts.size() > uint8_t(regressed.phase)) member.phaseReceipts.pop_back();
  assert(!registry.advanceRemoteRuntimeRecoveryCohort(regressed, regressed.phase, recoveryStored, resumed, &failure));
  assert(registry.advanceRemoteRuntimeRecoveryCohort(phase, phase.phase, recoveryStored, resumed, &failure));
  assert(resumed);
  assert(registry.remoteRuntimeRecoveryPending(remote.clusterUUID, recoveryPending, &failure));
  assert(!recoveryPending);

  // Version-three handoffs preserve the old frozen semantics while carrying
  // separate lineage bytes for the phase-six successor form.  In particular,
  // those archived bytes are mandatory evidence, never a replacement for the
  // child cohort's fresh member identities.
  MothershipRemoteRuntimeRecoveryHandoffRecord activatedShape = {};
  activatedShape.version = 3;
  activatedShape.clusterUUID = remote.clusterUUID;
  activatedShape.parentOperationID = uint128_t(0xd2f0);
  activatedShape.childOperationID = uint128_t(0xd2f1);
  activatedShape.parentCohortSHA256 = digest('a');
  activatedShape.childAdmissionSHA256 = digest('b');
  activatedShape.childCohortSHA256 = digest('c');
  activatedShape.parentTopology = remote.topology;
  activatedShape.declaredTopology = remote.topology;
  activatedShape.observedTopology = remote.topology;
  activatedShape.restorationReceiptSHA256 = {digest('1'),digest('2'),digest('3')};
  activatedShape.kind = MothershipRemoteRuntimeRecoveryHandoffRecord::Kind::activationStarted;
  activatedShape.parentRequestSHA256 = digest('d');
  activatedShape.parentStartupRequestSHA256 = digest('e');
  activatedShape.parentStartupWitnessesSHA256 = digest('f');
  assert(MothershipClusterRegistry::remoteRuntimeRecoveryHandoffValid(activatedShape));
  auto missingActivatedLineage = activatedShape;
  missingActivatedLineage.parentStartupWitnessesSHA256.clear();
  assert(!MothershipClusterRegistry::remoteRuntimeRecoveryHandoffValid(missingActivatedLineage));
  auto malformedActivatedKind = activatedShape;
  malformedActivatedKind.kind = MothershipRemoteRuntimeRecoveryHandoffRecord::Kind(7);
  assert(!MothershipClusterRegistry::remoteRuntimeRecoveryHandoffValid(malformedActivatedKind));
  auto frozenWithActivatedBytes = activatedShape;
  frozenWithActivatedBytes.kind = MothershipRemoteRuntimeRecoveryHandoffRecord::Kind::frozenBeforeInstallation;
  assert(!MothershipClusterRegistry::remoteRuntimeRecoveryHandoffValid(frozenWithActivatedBytes));

  // A phase-six successor is deliberately not an ordinary update admission:
  // its authority is the sealed installed parent plus the new exact cohort.
  // Exercise the complete registry path so a later refactor cannot silently
  // reintroduce the ordinary-admission dependency.
  auto activeParent = makeWithdrawableRecovery(uint128_t(0xd2f0));
  String activeTopologyBytes = {}, activeTopologySHA = {};
  auto activeTopology = remote.topology;
  assert(BitseryEngine::serialize(activeTopologyBytes, activeTopology));
  assert(prodigyComputeSHA256Hex(activeTopologyBytes, activeTopologySHA));
  activeParent.topologySHA256 = activeTopologySHA;
  assert(registry.admitRemoteRuntimeRecoveryCohort(activeParent, remote, recoveryStored, resumed, &failure));
  activeParent = recoveryStored;
  activeParent.phase=MothershipRemoteRuntimeRecoveryPhase::staged; addPhaseReceipts(activeParent);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(activeParent,activeParent.phase,recoveryStored,resumed,&failure)); activeParent=recoveryStored;
  activeParent.phase=MothershipRemoteRuntimeRecoveryPhase::fenced; addPhaseReceipts(activeParent);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(activeParent,activeParent.phase,recoveryStored,resumed,&failure)); activeParent=recoveryStored;
  activeParent.phase=MothershipRemoteRuntimeRecoveryPhase::frozen; addPhaseReceipts(activeParent);
  for(uint32_t index=0;index<activeParent.members.size();++index) { activeParent.members[index].stateSHA256=digest(char('a'+index)); activeParent.members[index].secretsSHA256=digest(char('d'+index)); activeParent.members[index].containerInventorySHA256=digest(char('1'+index)); activeParent.members[index].privateLoaderSHA256=digest(char('4'+index)); activeParent.members[index].retainedNetworkSHA256=digest(char('7'+index)); }
  assert(registry.advanceRemoteRuntimeRecoveryCohort(activeParent,activeParent.phase,recoveryStored,resumed,&failure)); activeParent=recoveryStored;
  activeParent.phase=MothershipRemoteRuntimeRecoveryPhase::quiesced; addPhaseReceipts(activeParent);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(activeParent,activeParent.phase,recoveryStored,resumed,&failure)); activeParent=recoveryStored;
  activeParent.phase=MothershipRemoteRuntimeRecoveryPhase::installed; addPhaseReceipts(activeParent);
  for(auto& member:activeParent.members) member.targetRuntimeInstalled=true;
  assert(registry.advanceRemoteRuntimeRecoveryCohort(activeParent,activeParent.phase,recoveryStored,resumed,&failure)); activeParent=recoveryStored;
  activeParent.phase=MothershipRemoteRuntimeRecoveryPhase::activationStarted; addPhaseReceipts(activeParent);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(activeParent,activeParent.phase,recoveryStored,resumed,&failure)); activeParent=recoveryStored;
  String activeParentBytes = {}, activeParentSHA = {};
  auto activeParentCopy = recoveryStored;
  assert(BitseryEngine::serialize(activeParentBytes, activeParentCopy));
  assert(prodigyComputeSHA256Hex(activeParentBytes, activeParentSHA));
  auto activeChild = activeParent;
  activeChild.operationID = uint128_t(0xd2f1);
  activeChild.phase = MothershipRemoteRuntimeRecoveryPhase::admitted;
  activeChild.admissionRecordSHA256 = digest('9');
  activeChild.sourceBundleSHA256 = activeParent.targetBundleSHA256;
  activeChild.sourceContractSHA256 = activeParent.targetContractSHA256;
  activeChild.sourceProdigySHA256 = activeParent.targetProdigySHA256;
  activeChild.sourceMothershipSHA256 = activeParent.targetMothershipSHA256;
  for (auto& member : activeChild.members) {
    member.bootID = "00000000-0000-4000-8000-0000000000aa"_ctv;
    member.sourceProcessPID += 7000; member.sourceProcessStartTicks += 7000;
    member.stateSHA256.clear(); member.secretsSHA256.clear(); member.containerInventorySHA256.clear();
    member.privateLoaderSHA256.clear(); member.retainedNetworkSHA256.clear(); member.targetRuntimeInstalled=false; member.phaseReceipts.clear();
  }
  String activeChildSHA = {};
  assert(MothershipClusterRegistry::remoteRuntimeRecoveryActivationBindingDigest(activeParent, activeChild, activeChild.admissionRecordSHA256));
  assert(MothershipClusterRegistry::remoteRuntimeRecoveryInitialCohortDigest(activeChild, activeChildSHA));
  auto activeHandoff = activatedShape;
  activeHandoff.clusterUUID=remote.clusterUUID; activeHandoff.parentOperationID=activeParent.operationID;
  activeHandoff.childOperationID=activeChild.operationID; activeHandoff.parentCohortSHA256=activeParentSHA;
  activeHandoff.childAdmissionSHA256=activeChild.admissionRecordSHA256; activeHandoff.childCohortSHA256=activeChildSHA;
  activeHandoff.parentTopology=remote.topology; activeHandoff.declaredTopology=remote.topology; activeHandoff.observedTopology=remote.topology;
  MothershipRemoteRuntimeRecoveryHandoffRecord activeStored = {};
  assert(registry.admitRemoteRuntimeRecoveryHandoff(activeHandoff, remote, activeChild, activeStored, recoveryStored, resumed, &failure));
  assert(!resumed && recoveryStored.operationID==activeChild.operationID);
  bool activeSuperseded=false;
  assert(registry.remoteRuntimeRecoveryParentSuperseded(activeParent,activeSuperseded,&failure) && activeSuperseded);
  MothershipRemoteRuntimeRecoveryCohortRecord loadedParent={};
  assert(registry.loadRemoteRuntimeRecoveryCohort(remote.clusterUUID,activeParent.operationID,loadedParent,&failure));
  String loadedParentBytes={}; assert(BitseryEngine::serialize(loadedParentBytes,loadedParent)); assert(loadedParentBytes==activeParentBytes);
  assert(registry.admitRemoteRuntimeRecoveryHandoff(activeHandoff, remote, activeChild, activeStored, recoveryStored, resumed, &failure) && resumed);
  auto forgedActiveBinding=activeChild; forgedActiveBinding.admissionRecordSHA256=digest('9');
  auto forgedActiveHandoff=activeHandoff; forgedActiveHandoff.childAdmissionSHA256=forgedActiveBinding.admissionRecordSHA256;
  assert(MothershipClusterRegistry::remoteRuntimeRecoveryInitialCohortDigest(forgedActiveBinding,forgedActiveHandoff.childCohortSHA256));
  assert(!registry.validateRemoteRuntimeRecoveryHandoff(forgedActiveHandoff,remote,forgedActiveBinding,&failure));
  auto wrongActiveDigest=activeHandoff; wrongActiveDigest.parentCohortSHA256=digest('8');
  assert(!registry.validateRemoteRuntimeRecoveryHandoff(wrongActiveDigest,remote,activeChild,&failure));
  auto wrongActiveMember=activeChild; wrongActiveMember.members[0].linuxMachineID.assign("000000000000000000000000000000ff"_ctv);
  assert(!registry.validateRemoteRuntimeRecoveryHandoff(activeHandoff,remote,wrongActiveMember,&failure));
  auto wrongActiveArtifact=activeChild; wrongActiveArtifact.sourceProdigySHA256=digest('8');
  assert(!registry.validateRemoteRuntimeRecoveryHandoff(activeHandoff,remote,wrongActiveArtifact,&failure));
  auto secondActiveChild=activeHandoff; secondActiveChild.childOperationID=uint128_t(0xd2f2);
  assert(!registry.validateRemoteRuntimeRecoveryHandoff(secondActiveChild,remote,activeChild,&failure));
  auto activeTransition=recoveryStored; activeTransition.phase=MothershipRemoteRuntimeRecoveryPhase::staged;
  addPhaseReceipts(activeTransition);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(activeTransition,activeTransition.phase,recoveryStored,resumed,&failure));
  for (const auto nextPhase : {MothershipRemoteRuntimeRecoveryPhase::fenced, MothershipRemoteRuntimeRecoveryPhase::frozen,
                               MothershipRemoteRuntimeRecoveryPhase::quiesced, MothershipRemoteRuntimeRecoveryPhase::installed,
                               MothershipRemoteRuntimeRecoveryPhase::activationStarted, MothershipRemoteRuntimeRecoveryPhase::completed}) {
    auto next=recoveryStored; next.phase=nextPhase; addPhaseReceipts(next);
    if (nextPhase==MothershipRemoteRuntimeRecoveryPhase::frozen) for(uint32_t index=0;index<next.members.size();++index) { next.members[index].stateSHA256=digest(char('a'+index)); next.members[index].secretsSHA256=digest(char('d'+index)); next.members[index].containerInventorySHA256=digest(char('1'+index)); next.members[index].privateLoaderSHA256=digest(char('4'+index)); next.members[index].retainedNetworkSHA256=digest(char('7'+index)); }
    if (nextPhase==MothershipRemoteRuntimeRecoveryPhase::installed) for(auto& member:next.members) member.targetRuntimeInstalled=true;
    assert(registry.advanceRemoteRuntimeRecoveryCohort(next,nextPhase,recoveryStored,resumed,&failure));
  }
  assert(registry.remoteRuntimeRecoveryPending(remote.clusterUUID,recoveryPending,&failure) && !recoveryPending);
  assert(registry.loadRemoteRuntimeRecoveryCohort(remote.clusterUUID,activeParent.operationID,loadedParent,&failure));
  assert(BitseryEngine::serialize(loadedParentBytes,loadedParent) && loadedParentBytes==activeParentBytes);

  // A frozen, never-installed cohort may hand off only to one newly admitted
  // child. The child retains the restored host/boot identities but records
  // fresh source process identities and the exact rack-only observed topology.
  auto handoffParent = makeWithdrawableRecovery(uint128_t(0xD30));
  assert(registry.admitRemoteRuntimeRecoveryCohort(handoffParent, remote, recoveryStored, resumed, &failure));
  handoffParent.phase = MothershipRemoteRuntimeRecoveryPhase::staged;
  addPhaseReceipts(handoffParent);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(handoffParent, handoffParent.phase, recoveryStored, resumed, &failure));
  handoffParent.phase = MothershipRemoteRuntimeRecoveryPhase::fenced;
  addPhaseReceipts(handoffParent);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(handoffParent, handoffParent.phase, recoveryStored, resumed, &failure));
  handoffParent.phase = MothershipRemoteRuntimeRecoveryPhase::frozen;
  addPhaseReceipts(handoffParent);
  for (uint32_t index = 0; index < handoffParent.members.size(); ++index)
  {
    handoffParent.members[index].stateSHA256 = digest(char('a' + index));
    handoffParent.members[index].secretsSHA256 = digest(char('d' + index));
    handoffParent.members[index].containerInventorySHA256 = digest(char('1' + index));
    handoffParent.members[index].privateLoaderSHA256 = digest(char('4' + index));
    handoffParent.members[index].retainedNetworkSHA256 = digest(char('7' + index));
  }
  assert(registry.advanceRemoteRuntimeRecoveryCohort(handoffParent, handoffParent.phase, recoveryStored, resumed, &failure));
  handoffParent = recoveryStored;
  const ClusterTopology parentTopology = remote.topology;
  ++remote.topology.version;
  remote.topology.machines[0].hardware.collectedAtMs = 11;
  remote.topology.machines[0].hardware.network.internet.attempted = true;
  auto handoffAdmission = expectedEligibleAdmission;
  handoffAdmission.operationID = uint128_t(0xD31);
  handoffAdmission.targetBundleSHA256 = digest('e');
  handoffAdmission.targetContractSHA256 = digest('f');
  assert(registry.recordUpgradeAdmission(handoffAdmission, recorded, resumed, &failure));
  String handoffAdmissionBytes = {}, handoffAdmissionSHA256 = {};
  auto handoffAdmissionCopy = handoffAdmission;
  assert(BitseryEngine::serialize(handoffAdmissionBytes, handoffAdmissionCopy));
  assert(prodigyComputeSHA256Hex(handoffAdmissionBytes, handoffAdmissionSHA256));
  auto handoffChild = handoffParent;
  handoffChild.operationID = handoffAdmission.operationID;
  handoffChild.authorityGeneration = handoffAdmission.authorityGeneration;
  handoffChild.admissionRecordSHA256 = handoffAdmissionSHA256;
  handoffChild.targetBundleSHA256 = handoffAdmission.targetBundleSHA256;
  handoffChild.targetContractSHA256 = handoffAdmission.targetContractSHA256;
  handoffChild.targetProdigySHA256 = digest('e');
  handoffChild.targetMothershipSHA256 = digest('f');
  handoffChild.phase = MothershipRemoteRuntimeRecoveryPhase::admitted;
  for (uint32_t index = 0; index < handoffChild.members.size(); ++index)
  {
    handoffChild.members[index].sourceProcessPID += 1000;
    handoffChild.members[index].sourceProcessStartTicks += 1000;
    handoffChild.members[index].stateSHA256.clear(); handoffChild.members[index].secretsSHA256.clear();
    handoffChild.members[index].containerInventorySHA256.clear(); handoffChild.members[index].privateLoaderSHA256.clear();
    handoffChild.members[index].retainedNetworkSHA256.clear(); handoffChild.members[index].targetRuntimeInstalled = false;
    handoffChild.members[index].phaseReceipts.clear();
  }
  ClusterTopology observedTopology = remote.topology;
  observedTopology.machines[0].rackUUID = 17;
  auto addressDriftTopology = observedTopology;
  addressDriftTopology.machines[0].ssh.address = "198.51.100.17"_ctv;
  assert(!MothershipClusterRegistry::remoteRuntimeRecoveryRackOnlyTopologyDriftValid(remote.topology, addressDriftTopology));
  auto regressedTopology = observedTopology;
  regressedTopology.version = remote.topology.version - 1;
  assert(!MothershipClusterRegistry::remoteRuntimeRecoveryRackOnlyTopologyDriftValid(remote.topology, regressedTopology));
  String observedTopologyBytes = {}, observedTopologySHA256 = {};
  auto observedTopologyCopy = observedTopology;
  assert(BitseryEngine::serialize(observedTopologyBytes, observedTopologyCopy));
  assert(prodigyComputeSHA256Hex(observedTopologyBytes, observedTopologySHA256));
  handoffChild.topologySHA256 = observedTopologySHA256;
  String parentBytes = {}, parentSHA256 = {}, childSHA256 = {};
  auto handoffParentCopy = handoffParent;
  assert(BitseryEngine::serialize(parentBytes, handoffParentCopy));
  assert(prodigyComputeSHA256Hex(parentBytes, parentSHA256));
  assert(MothershipClusterRegistry::remoteRuntimeRecoveryInitialCohortDigest(handoffChild, childSHA256));
  MothershipRemoteRuntimeRecoveryHandoffRecord handoff = {};
  handoff.clusterUUID = remote.clusterUUID;
  handoff.parentOperationID = handoffParent.operationID;
  handoff.childOperationID = handoffChild.operationID;
  handoff.parentCohortSHA256 = parentSHA256;
  handoff.childAdmissionSHA256 = handoffAdmissionSHA256;
  handoff.childCohortSHA256 = childSHA256;
  handoff.parentTopology = parentTopology;
  handoff.declaredTopology = remote.topology;
  handoff.observedTopology = observedTopology;
  handoff.restorationReceiptSHA256.push_back(digest('1'));
  handoff.restorationReceiptSHA256.push_back(digest('2'));
  handoff.restorationReceiptSHA256.push_back(digest('3'));
  MothershipRemoteRuntimeRecoveryHandoffRecord handoffStored = {}, handoffLoaded = {};
  auto oldSchemaHandoff = handoff;
  oldSchemaHandoff.version = 1;
  oldSchemaHandoff.parentTopology = {};
  assert(MothershipClusterRegistry::remoteRuntimeRecoveryHandoffValid(oldSchemaHandoff));
  String oldSchemaBytes = {};
  MothershipRemoteRuntimeRecoveryHandoffRecord oldSchemaDecoded = {};
  assert(BitseryEngine::serialize(oldSchemaBytes, oldSchemaHandoff));
  assert(BitseryEngine::deserializeSafe(oldSchemaBytes, oldSchemaDecoded));
  assert(oldSchemaDecoded.version == 1 && oldSchemaDecoded.parentTopology.machines.empty() &&
         MothershipClusterRegistry::remoteRuntimeRecoveryParentTopology(oldSchemaDecoded) == oldSchemaDecoded.declaredTopology &&
         MothershipClusterRegistry::remoteRuntimeRecoveryHandoffValid(oldSchemaDecoded));
  auto changedParentRack = handoff;
  ++changedParentRack.parentTopology.machines[0].rackUUID;
  assert(!MothershipClusterRegistry::remoteRuntimeRecoveryHandoffValid(changedParentRack));
  auto changedParentMachine = handoff;
  changedParentMachine.parentTopology.machines[0].isBrain = false;
  assert(!MothershipClusterRegistry::remoteRuntimeRecoveryHandoffValid(changedParentMachine));
  auto decreasedDeclaredTopology = handoff;
  decreasedDeclaredTopology.declaredTopology.version = parentTopology.version - 1;
  assert(!MothershipClusterRegistry::remoteRuntimeRecoveryHandoffValid(decreasedDeclaredTopology));
  auto staleHardware = handoff.declaredTopology;
  staleHardware.machines[0].hardware.collectedAtMs = parentTopology.machines[0].hardware.collectedAtMs;
  assert(!MothershipClusterRegistry::remoteRuntimeRecoveryParentToDeclaredTopologyValid(parentTopology, staleHardware));
  auto versionOnlyAdvance = parentTopology;
  ++versionOnlyAdvance.version;
  assert(MothershipClusterRegistry::remoteRuntimeRecoveryParentToDeclaredTopologyValid(parentTopology, versionOnlyAdvance));
  auto sameVersionHardware = parentTopology;
  sameVersionHardware.machines[0].hardware.collectedAtMs = parentTopology.machines[0].hardware.collectedAtMs + 1;
  sameVersionHardware.machines[0].hardware.network.internet.attempted = true;
  assert(!MothershipClusterRegistry::remoteRuntimeRecoveryParentToDeclaredTopologyValid(parentTopology, sameVersionHardware));
  auto notReadyHardware = handoff.declaredTopology;
  notReadyHardware.machines[0].hardware.inventoryComplete = false;
  assert(!MothershipClusterRegistry::remoteRuntimeRecoveryParentToDeclaredTopologyValid(parentTopology, notReadyHardware));
  auto changedCapacity = handoff.declaredTopology;
  ++changedCapacity.machines[0].totalMemoryMB;
  assert(!MothershipClusterRegistry::remoteRuntimeRecoveryParentToDeclaredTopologyValid(parentTopology, changedCapacity));
  auto changedIdentity = handoff.declaredTopology;
  ++changedIdentity.machines[0].uuid;
  assert(!MothershipClusterRegistry::remoteRuntimeRecoveryParentToDeclaredTopologyValid(parentTopology, changedIdentity));
  auto missingReceipt = handoff;
  missingReceipt.restorationReceiptSHA256.pop_back();
  assert(!registry.admitRemoteRuntimeRecoveryHandoff(missingReceipt, remote, handoffChild, handoffStored, recoveryStored, resumed, &failure));
  auto changedBootChild = handoffChild;
  changedBootChild.members[0].bootID = "00000000-0000-4000-8000-000000000099"_ctv;
  assert(!registry.admitRemoteRuntimeRecoveryHandoff(handoff, remote, changedBootChild, handoffStored, recoveryStored, resumed, &failure));
  auto installedChild = handoffChild;
  installedChild.members[0].targetRuntimeInstalled = true;
  assert(!registry.admitRemoteRuntimeRecoveryHandoff(handoff, remote, installedChild, handoffStored, recoveryStored, resumed, &failure));
  assert(registry.validateRemoteRuntimeRecoveryHandoff(handoff, remote, handoffChild, &failure));
  assert(!registry.loadRemoteRuntimeRecoveryHandoffForChild(remote.clusterUUID, handoffChild.operationID, handoffLoaded, &failure));
  assert(failure == "record not found"_ctv);
  assert(!registry.loadRemoteRuntimeRecoveryCohort(remote.clusterUUID, handoffChild.operationID, recoveryStored, &failure));
  assert(failure == "record not found"_ctv);
  auto mismatchedParentDigest = handoff;
  mismatchedParentDigest.parentCohortSHA256 = digest('9');
  assert(!registry.validateRemoteRuntimeRecoveryHandoff(mismatchedParentDigest, remote, handoffChild, &failure));
  assert(failure == "remote runtime recovery handoff parent cohort digest differs"_ctv);
  assert(registry.admitRemoteRuntimeRecoveryHandoff(handoff, remote, handoffChild, handoffStored, recoveryStored, resumed, &failure));
  assert(!resumed && handoffStored.childOperationID == handoffChild.operationID && recoveryStored.operationID == handoffChild.operationID);
  assert(registry.loadRemoteRuntimeRecoveryHandoffForChild(remote.clusterUUID, handoffChild.operationID, handoffLoaded, &failure));
  assert(handoffLoaded.parentCohortSHA256 == parentSHA256 && handoffLoaded.observedTopology == observedTopology);
  bool parentSuperseded = false;
  assert(registry.remoteRuntimeRecoveryParentSuperseded(handoffParent, parentSuperseded, &failure) && parentSuperseded);
  auto supersededAbort = handoffParent;
  supersededAbort.phase = MothershipRemoteRuntimeRecoveryPhase::abortedBeforeInstallation;
  addAbortReceipts(supersededAbort);
  assert(!registry.abortRemoteRuntimeRecoveryCohort(supersededAbort, recoveryStored, &failure));
  auto changedParent = handoffParent;
  changedParent.members[0].stateSHA256 = digest('9');
  assert(!registry.remoteRuntimeRecoveryParentSuperseded(changedParent, parentSuperseded, &failure));
  auto changedSourceChild = handoffChild;
  changedSourceChild.sourceProdigySHA256 = digest('9');
  assert(!registry.admitRemoteRuntimeRecoveryHandoff(handoff, remote, changedSourceChild, handoffStored, recoveryStored, resumed, &failure));
  auto changedChild = handoffChild;
  changedChild.targetBundleSHA256 = digest('9');
  assert(!registry.admitRemoteRuntimeRecoveryHandoff(handoff, remote, changedChild, handoffStored, recoveryStored, resumed, &failure));
  auto cyclic = handoff;
  cyclic.parentOperationID = cyclic.childOperationID;
  assert(!registry.admitRemoteRuntimeRecoveryHandoff(cyclic, remote, handoffChild, handoffStored, recoveryStored, resumed, &failure));
  auto secondChild = handoff;
  secondChild.childOperationID = uint128_t(0xD32);
  assert(!registry.admitRemoteRuntimeRecoveryHandoff(secondChild, remote, handoffChild, handoffStored, recoveryStored, resumed, &failure));
  auto parentAdvance = handoffParent;
  parentAdvance.phase = MothershipRemoteRuntimeRecoveryPhase::quiesced;
  addPhaseReceipts(parentAdvance);
  assert(!registry.advanceRemoteRuntimeRecoveryCohort(parentAdvance, parentAdvance.phase, recoveryStored, resumed, &failure));
  assert(registry.remoteRuntimeRecoveryPending(remote.clusterUUID, recoveryPending, &failure));
  assert(recoveryPending);
  assert(registry.loadRemoteRuntimeRecoveryCohort(remote.clusterUUID, handoffChild.operationID, recoveryStored, &failure));
  auto completedChild = recoveryStored;
  completedChild.phase = MothershipRemoteRuntimeRecoveryPhase::staged;
  addPhaseReceipts(completedChild);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(completedChild, completedChild.phase, recoveryStored, resumed, &failure));
  completedChild = recoveryStored;
  completedChild.phase = MothershipRemoteRuntimeRecoveryPhase::fenced;
  addPhaseReceipts(completedChild);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(completedChild, completedChild.phase, recoveryStored, resumed, &failure));
  completedChild = recoveryStored;
  completedChild.phase = MothershipRemoteRuntimeRecoveryPhase::frozen;
  addPhaseReceipts(completedChild);
  for (uint32_t index = 0; index < completedChild.members.size(); ++index)
  {
    completedChild.members[index].stateSHA256 = digest(char('a' + index));
    completedChild.members[index].secretsSHA256 = digest(char('d' + index));
    completedChild.members[index].containerInventorySHA256 = digest(char('1' + index));
    completedChild.members[index].privateLoaderSHA256 = digest(char('4' + index));
    completedChild.members[index].retainedNetworkSHA256 = digest(char('7' + index));
  }
  assert(registry.advanceRemoteRuntimeRecoveryCohort(completedChild, completedChild.phase, recoveryStored, resumed, &failure));
  completedChild = recoveryStored;
  completedChild.phase = MothershipRemoteRuntimeRecoveryPhase::quiesced;
  addPhaseReceipts(completedChild);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(completedChild, completedChild.phase, recoveryStored, resumed, &failure));
  completedChild = recoveryStored;
  completedChild.phase = MothershipRemoteRuntimeRecoveryPhase::installed;
  addPhaseReceipts(completedChild);
  for (auto& member : completedChild.members) member.targetRuntimeInstalled = true;
  assert(registry.advanceRemoteRuntimeRecoveryCohort(completedChild, completedChild.phase, recoveryStored, resumed, &failure));
  completedChild = recoveryStored;
  completedChild.phase = MothershipRemoteRuntimeRecoveryPhase::activationStarted;
  addPhaseReceipts(completedChild);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(completedChild, completedChild.phase, recoveryStored, resumed, &failure));
  completedChild = recoveryStored;
  completedChild.phase = MothershipRemoteRuntimeRecoveryPhase::completed;
  addPhaseReceipts(completedChild);
  assert(registry.advanceRemoteRuntimeRecoveryCohort(completedChild, completedChild.phase, recoveryStored, resumed, &failure));
  auto postHandoffRecovery = makeWithdrawableRecovery(uint128_t(0xD33));
  String postHandoffTopologyBytes = {}, postHandoffTopologySHA256 = {};
  auto postHandoffTopology = remote.topology;
  assert(BitseryEngine::serialize(postHandoffTopologyBytes, postHandoffTopology));
  assert(prodigyComputeSHA256Hex(postHandoffTopologyBytes, postHandoffTopologySHA256));
  postHandoffRecovery.topologySHA256 = postHandoffTopologySHA256;
  assert(registry.admitRemoteRuntimeRecoveryCohort(postHandoffRecovery, remote, recoveryStored, resumed, &failure));
  assert(!resumed && recoveryStored.operationID == postHandoffRecovery.operationID);
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
  { // A fresh registry handle must observe the exact durable admission state.
    MothershipClusterRegistry registry(path);
    String failure = {}, expectedBytes = {}, loadedBytes = {};
    MothershipUpgradeAdmissionRecord loaded = {};
    assert(registry.loadUpgradeAdmission(
        expectedEligibleAdmission.clusterUUID, expectedEligibleAdmission.operationID, loaded, &failure));
    auto expectedCopy = expectedEligibleAdmission;
    auto loadedCopy = loaded;
    assert(BitseryEngine::serialize(expectedBytes, expectedCopy));
    assert(BitseryEngine::serialize(loadedBytes, loadedCopy));
    assert(expectedBytes == loadedBytes && loaded.eligible);

    expectedBytes.clear(); loadedBytes.clear(); loaded = {};
    assert(registry.loadUpgradeAdmission(
        expectedIneligibleAdmission.clusterUUID, expectedIneligibleAdmission.operationID, loaded, &failure));
    expectedCopy = expectedIneligibleAdmission;
    loadedCopy = loaded;
    assert(BitseryEngine::serialize(expectedBytes, expectedCopy));
    assert(BitseryEngine::serialize(loadedBytes, loadedCopy));
    assert(expectedBytes == loadedBytes && !loaded.eligible);

    MothershipUpgradeAdmissionRecord missing = {};
    assert(!registry.loadUpgradeAdmission(
        expectedEligibleAdmission.clusterUUID, uint128_t(0xB24), missing, &failure));
    auto conflicting = expectedEligibleAdmission;
    conflicting.targetBundleSHA256 = digest('9');
    bool resumed = false;
    assert(!registry.recordUpgradeAdmission(conflicting, loaded, resumed, &failure));
    assert(failure == "upgrade admission operation identity conflicts with existing immutable record"_ctv);
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

    // V5 binds the narrow transfer to the exact active COUSIN transport
    // workload and its two Brain-owned permissions.  None of those identities
    // may be replaced by a later route/permission observation.
    MothershipTestPairBoundaryRecord finalTransport = readiness;
    finalTransport.version = 5;
    finalTransport.boundary.operationID = "0x0ac2"_ctv;
    finalTransport.boundary.sourceClusterUUID = "0x0d11"_ctv;
    finalTransport.boundary.targetClusterUUID = "0x0d22"_ctv;
    finalTransport.sourceDeploymentID = (uint64_t(11) << 48) | 1;
    finalTransport.targetPlanSHA256.clear();
    finalTransport.targetAdmissionReceipt.clear();
    finalTransport.selectorGeneration = 0;
    finalTransport.closed = false;
    finalTransport.sourceDrainObservation.clear();
    finalTransport.guestResetFence = {};
    finalTransport.guestResetCompletedBootID.clear();
    const uint64_t sourceTransportDeploymentID = (uint64_t(19) << 48) | 1;
    const uint64_t targetTransportDeploymentID = (uint64_t(23) << 48) | 2;
    assert(mothershipBuildTestPairTargetReadinessIntent(
        commissionedTopology, finalTransport.boundary.targetMachinePrivate4,
        finalTransport.targetReadinessIntent, targetTransportDeploymentID, 3));

    auto& transport = finalTransport.cousinTransport;
    transport.route.routeUUID = 0x520;
    transport.route.operationUUID = 0x521;
    transport.route.pairUUID = 0x500;
    transport.route.logicalWorkloadUUID = 0x510;
    transport.route.logicalServiceUUID = 0x511;
    transport.route.sourceClusterUUID = uint128_t(0xd11);
    transport.route.destinationClusterUUID = uint128_t(0xd22);
    transport.route.sourceApplicationID = 19;
    transport.route.destinationApplicationID = 23;
    transport.route.sourceCousinServicePrefix = MeshServices::generateStatefulService(19, 3);
    transport.route.destinationCousinServicePrefix = MeshServices::generateStatefulService(23, 3);
    transport.route.slots.insert(3);
    transport.route.destinationRoutablePrefixUUID = 0x522;
    transport.route.destinationPublicAddress = IPAddress("2001:db8::1", true);
    transport.route.destinationTCPPort = 443;
    transport.route.sourcePermissionUUID = 0x523;
    transport.route.destinationPermissionUUID = 0x524;
    transport.route.transportProtocol = IPPROTO_TCP;
    transport.route.destinationCIDR = 64;
    transport.route.pathMTU = 1500;
    transport.route.generation = 1;
    transport.route.issuedAtMs = 100;
    transport.route.expiresAtMs = 200;
    transport.route.keyEpoch = 1;
    transport.route.rootGeneration = 1;
    transport.sourcePermission = testPairCousinPermission(
        transport.route.sourcePermissionUUID, transport.route.pairUUID, transport.route.sourceClusterUUID,
        transport.route.destinationClusterUUID, CousinRouteHalf::source, 19, 23,
        sourceTransportDeploymentID, MeshServices::generateStatefulService(19, 3),
        MeshServices::generateStatefulService(23, 3), 'a', 'b');
    transport.destinationPermission = testPairCousinPermission(
        transport.route.destinationPermissionUUID, transport.route.pairUUID, transport.route.destinationClusterUUID,
        transport.route.sourceClusterUUID, CousinRouteHalf::destination, 23, 19,
        targetTransportDeploymentID, MeshServices::generateStatefulService(23, 3),
        MeshServices::generateStatefulService(19, 3), 'c', 'd');
    transport.sourceApplyReceipt = testPairCousinRouteReceipt(transport.route, CousinRouteHalf::source, 31);
    transport.destinationApplyReceipt = testPairCousinRouteReceipt(transport.route, CousinRouteHalf::destination, 32);
    assert(MothershipClusterRegistry::testPairCousinTransportIntentValid(finalTransport));
    assert(MothershipClusterRegistry::testPairBoundaryRecordValid(finalTransport));
    assert(registry.admitTestPairBoundary(finalTransport, pairStored, &failure));
    assert(registry.admitTestPairBoundary(finalTransport, pairLoaded, &failure)); // exact pending retry
    auto changedTransport = finalTransport;
    changedTransport.cousinTransport.route.state = CousinRouteState::draining;
    assert(!registry.admitTestPairBoundary(changedTransport, pairLoaded, &failure));
    changedTransport = finalTransport;
    changedTransport.cousinTransport.destinationPermission.permissionUUID += 1;
    assert(!registry.admitTestPairBoundary(changedTransport, pairLoaded, &failure));

    auto v5Receipt = receipt;
    v5Receipt.admission.operationID = uint128_t(0xac2);
    v5Receipt.admission.clusterUUID = uint128_t(0xd22);
    assert(registry.recordTestPairTargetAdmission(pairStored, v5Receipt, pairLoaded, &failure));
    pairStored = pairLoaded;
    assert(registry.admitTestPairBoundary(finalTransport, pairLoaded, &failure)); // exact accepted retry

    ClusterStatusReport v5Status = clusterReport;
    v5Status.nApplications = 2;
    ApplicationStatusReport& transportApplication = v5Status.applicationReports.emplace_back();
    transportApplication.applicationID = transport.destinationPermission.localApplicationID;
    DeploymentStatusReport& transportDeployment = transportApplication.deploymentReports.emplace_back();
    transportDeployment.versionID = targetTransportDeploymentID & ((uint64_t(1) << 48) - 1);
    transportDeployment.state = DeploymentState::running;
    transportDeployment.isStateful = true;
    transportDeployment.nTarget = transportDeployment.nDeployed = transportDeployment.nHealthy = 3;
    DeploymentIdentityReport v5Identity = identity;
    v5Identity.clusterUUID = uint128_t(0xd22);
    v5Identity.deploymentID = finalTransport.targetDeploymentID;
    v5Identity.canonicalPlanSHA256 = pairStored.targetPlanSHA256;
    DeploymentIdentityReport transportIdentity = {};
    transportIdentity.found = transportIdentity.live = transportIdentity.isStateful = true;
    transportIdentity.clusterUUID = uint128_t(0xd22);
    transportIdentity.applicationID = transport.destinationPermission.localApplicationID;
    transportIdentity.deploymentID = targetTransportDeploymentID;
    transportIdentity.versionID = targetTransportDeploymentID & ((uint64_t(1) << 48) - 1);
    transportIdentity.canonicalPlanSHA256 = transport.destinationPermission.canonicalPlanSHA256;
    transportIdentity.containerBlobSHA256 = transport.destinationPermission.artifactSHA256;
    transportIdentity.containerBlobBytes = transport.destinationPermission.artifactBytes;
    transportIdentity.authorityGeneration = 9;
    transportIdentity.masterUUID = commissionedTopology.machines[0].uuid;
    transportIdentity.masterBootNs = 11;
    transportIdentity.state = DeploymentState::running;
    transportIdentity.nTarget = transportIdentity.nDeployed = transportIdentity.nHealthy = 3;
    assert(MothershipClusterRegistry::testPairWholeDestinationReady(
        pairStored, v5Status, v5Identity, &failure, &transportIdentity));
    auto missingTransport = v5Status;
    missingTransport.nApplications = 1;
    missingTransport.applicationReports.pop_back();
    assert(!MothershipClusterRegistry::testPairWholeDestinationReady(
        pairStored, missingTransport, v5Identity, &failure, &transportIdentity));
    auto extraTransport = v5Status;
    extraTransport.nApplications = 3;
    extraTransport.applicationReports.emplace_back();
    extraTransport.applicationReports.back().applicationID = 31;
    assert(!MothershipClusterRegistry::testPairWholeDestinationReady(
        pairStored, extraTransport, v5Identity, &failure, &transportIdentity));
    auto unhealthyTransport = v5Status;
    unhealthyTransport.applicationReports[1].deploymentReports[0].nHealthy = 2;
    assert(!MothershipClusterRegistry::testPairWholeDestinationReady(
        pairStored, unhealthyTransport, v5Identity, &failure, &transportIdentity));
    auto staleTransportIdentity = transportIdentity;
    staleTransportIdentity.canonicalPlanSHA256 = digest('e');
    assert(!MothershipClusterRegistry::testPairWholeDestinationReady(
        pairStored, v5Status, v5Identity, &failure, &staleTransportIdentity));

    MothershipVirtualDatacenterPairDrainObservation v5Drain = {};
    v5Drain.operationID = finalTransport.boundary.operationID;
    v5Drain.sourceClusterUUID = finalTransport.boundary.sourceClusterUUID;
    v5Drain.targetClusterUUID = finalTransport.boundary.targetClusterUUID;
    v5Drain.sourceRuntimeIdentity = finalTransport.boundary.sourceRuntimeIdentity;
    v5Drain.targetRuntimeIdentity = finalTransport.boundary.targetRuntimeIdentity;
    v5Drain.sourceMachineIndex = finalTransport.boundary.sourceMachineIndex;
    v5Drain.targetMachineIndex = finalTransport.boundary.targetMachineIndex;
    v5Drain.selectedTarget = v5Drain.drainCapability = true;
    v5Drain.sourceFlows = 0;
    v5Drain.targetFlows = 4;
    assert(registry.advanceTestPairBoundary(pairStored, 1, false, pairLoaded, &failure));
    pairStored = pairLoaded;
    assert(registry.recordTestPairSourceDrain(pairStored, v5Drain, pairLoaded, &failure));
    assert(registry.recordTestPairSourceDrain(pairLoaded, v5Drain, pairStored, &failure)); // exact drain retry

    MothershipVirtualDatacenterPairGuestResetFence v5Fence = {};
    v5Fence.operationID = pairStored.boundary.operationID;
    assert(mothershipVirtualDatacenterPairDescriptorSHA256(pairStored.boundary, v5Fence.descriptorSHA256));
    v5Fence.bootID = "77777777-7777-4777-8777-777777777777"_ctv;
    v5Fence.guestID = "nametag-prodigy"_ctv;
    assert(registry.recordTestPairGuestResetFence(pairStored, v5Fence, pairLoaded, &failure));
    assert(pairLoaded.version == 6 && pairLoaded.cousinTransport.route.routeUUID == transport.route.routeUUID);
    assert(registry.recordTestPairGuestResetFence(pairStored, v5Fence, pairLoaded, &failure)); // v5 identity retry
    String v5CompletedBootID = "88888888-8888-4888-8888-888888888888"_ctv;
    assert(registry.recordTestPairGuestResetCompletion(pairLoaded, v5CompletedBootID, pairStored, &failure));
    assert(registry.advanceTestPairBoundary(pairStored, 1, true, pairLoaded, &failure));
    assert(pairLoaded.closed && pairLoaded.version == 6 &&
           pairLoaded.guestResetCompletedBootID == v5CompletedBootID &&
           pairLoaded.cousinTransport.destinationPermission.permissionUUID == transport.destinationPermission.permissionUUID);
  }
  return 0;
}
