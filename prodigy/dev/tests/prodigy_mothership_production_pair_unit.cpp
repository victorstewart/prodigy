#include <cassert>
#include <cstdio>

#include <prodigy/mothership/mothership.production.pair.h>

static String digest(char value)
{
  String result = {};
  for (uint32_t index = 0; index < 64; ++index) result.append(value);
  return result;
}

static CousinRouteRecord route()
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

static ProdigyLocalCousinServicePermission permission(const CousinRouteRecord& route, bool source)
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

static CousinRouteApplyReceipt receipt(const CousinRouteRecord& route, CousinRouteHalf half)
{
  CousinRouteApplyReceipt value = {};
  value.routeUUID = route.routeUUID; value.generation = route.generation;
  assert(cousinRouteAuthorizationDigest(route, value.authorizationSHA256));
  value.localClusterUUID = half == CousinRouteHalf::source ? route.sourceClusterUUID : route.destinationClusterUUID;
  value.localHalf = half; value.keyEpoch = route.keyEpoch; value.localRuntimeRevision = half == CousinRouteHalf::source ? 7 : 8;
  value.installedState = route.state;
  return value;
}

static MothershipProductionPairIntent intent()
{
  MothershipProductionPairIntent value = {};
  value.operationUUID = 0x401; value.route = route();
  value.sourcePermission = permission(value.route, true);
  value.destinationPermission = permission(value.route, false);
  value.sourceRouteReceipt = receipt(value.route, CousinRouteHalf::source);
  value.destinationRouteReceipt = receipt(value.route, CousinRouteHalf::destination);
  value.sourceWorkload.clusterUUID = value.route.sourceClusterUUID;
  value.sourceWorkload.applicationID = 31;
  value.sourceWorkload.deploymentID = (uint64_t(31) << 48) | 11;
  value.sourceWorkload.canonicalPlanSHA256 = digest('e');
  value.sourceWorkload.artifactSHA256 = digest('f'); value.sourceWorkload.artifactBytes = 4096;
  value.sourceWorkload.replicas = 1; value.sourceWorkload.endpointMachineUUID = 0x501;
  value.sourceWorkload.endpointIPv4 = "192.0.2.11"_ctv; value.sourceWorkload.endpointTCPPort = 8080;
  value.targetWorkload.clusterUUID = value.route.destinationClusterUUID;
  value.targetWorkload.applicationID = 31;
  value.targetWorkload.deploymentID = (uint64_t(31) << 48) | 12;
  value.targetWorkload.canonicalPlanSHA256 = value.sourceWorkload.canonicalPlanSHA256;
  value.targetWorkload.artifactSHA256 = digest('f'); value.targetWorkload.artifactBytes = 4096;
  value.targetWorkload.replicas = 1; value.targetWorkload.endpointMachineUUID = 0x502;
  value.targetWorkload.endpointIPv4 = "198.51.100.12"_ctv; value.targetWorkload.endpointTCPPort = 8080;
  value.physicalBoundaryUUID = 0x601;
  value.selectorMachineUUID = 0x504;
  value.selectorExecutorKind = MothershipPhysicalFaultExecutorKind::providerCloudVM;
  value.selectorCloudID = "provider-machine-501"_ctv;
  value.selectorAddress = "192.0.2.13"_ctv;
  value.selectorTCPPort = 18080;
  value.ingressWitnessMachineUUID = 0x503;
  value.ingressWitnessExecutorKind = MothershipPhysicalFaultExecutorKind::providerCloudVM;
  value.ingressWitnessCloudID = "provider-machine-503"_ctv;
  return value;
}

static MothershipProductionPairIntent statefulIntent()
{
  auto value = intent();
  value.protocolVersion = MothershipProductionPairIntent::statefulVersion;
  value.sourceWorkload.applicationID = value.targetWorkload.applicationID = 3;
  value.sourceWorkload.deploymentID = (uint64_t(3) << 48) | 11;
  value.targetWorkload.deploymentID = (uint64_t(3) << 48) | 12;
  value.sourceWorkload.replicas = value.targetWorkload.replicas = 3;
  value.sourceWorkload.endpointMachineUUID = value.targetWorkload.endpointMachineUUID = 0;
  value.sourceWorkload.endpointTCPPort = value.targetWorkload.endpointTCPPort = 0;
  value.sourceWorkload.endpointIPv4.clear(); value.targetWorkload.endpointIPv4.clear();
  value.physicalBoundaryUUID = value.selectorMachineUUID = value.selectorLocalVMBoundaryUUID = 0;
  value.selectorCloudID.clear(); value.selectorAddress.clear(); value.selectorTCPPort = 0;
  value.ingressWitnessMachineUUID = value.ingressWitnessLocalVMBoundaryUUID = 0; value.ingressWitnessCloudID.clear();
  auto& data = value.stateful;
  data.contractSHA256 = digest('a'); data.shardManifestSHA256 = digest('b');
  data.datasetUUID = 0x701; data.snapshotUUID = 0x702; data.shardGroup = 3;
  data.snapshotPreparingEpoch = 1; data.initialCatchupEpoch = 2; data.sourceFenceEpoch = 3;
  data.fencedCatchupEpoch = 4; data.targetOwnershipEpoch = 5; data.sourceRetainedEpoch = 6;
  String credentialBytes; auto credentials = data.credentials;
  BitseryEngine::serialize(credentialBytes, credentials);
  assert(prodigyComputeSHA256Hex(credentialBytes, data.credentialManifestSHA256));
  DeploymentPlan targetPlan = {};
  targetPlan.config.applicationID = 3; targetPlan.config.versionID = 12;
  targetPlan.config.type = ApplicationType::stateful;
  targetPlan.config.containerBlobSHA256 = value.targetWorkload.artifactSHA256;
  targetPlan.config.containerBlobBytes = value.targetWorkload.artifactBytes;
  targetPlan.isStateful = true;
  BitseryEngine::serialize(data.targetDeploymentPlan, targetPlan);
  assert(prodigyComputeSHA256Hex(data.targetDeploymentPlan, value.targetWorkload.canonicalPlanSHA256));
  for (unsigned index = 0; index < 3; ++index) {
    ProdigyStatefulServingAuthorityMember member;
    member.containerUUID = 0x801 + index; member.machineUUID = 0x901 + index;
    member.shardGroup = 3; member.isSource = true; member.advertiseClient = index == 0;
    member.planSHA256 = digest('d'); data.cohort.push_back(member);
    data.targetMachineUUIDs.push_back(0xa01 + index);
  }
  return value;
}

static MothershipProductionStatefulReceipt statefulProof(const MothershipProductionPairIntent& intent,
                                                        MothershipProductionPairPhase phase)
{
  MothershipProductionStatefulReceipt proof;
  proof.phase = phase; proof.operationUUID = intent.operationUUID;
  auto copy = intent; String encoded;
  BitseryEngine::serialize(encoded, copy); assert(prodigyComputeSHA256Hex(encoded, proof.intentSHA256));
  proof.observedMasterUUID = 0xb01; proof.observedMasterBootNs = 100; proof.observedAuthorityGeneration = 10;
  const bool preparing = phase == MothershipProductionPairPhase::snapshotVerified;
  const bool postCleanup = phase == MothershipProductionPairPhase::sourceCleanupVerified;
  const bool retained = postCleanup || phase == MothershipProductionPairPhase::statefulAbortedBeforeFence;
  const bool source = preparing || retained || phase == MothershipProductionPairPhase::sourceWriterFenced;
  const bool active = phase == MothershipProductionPairPhase::targetOwnershipActive;
  for (unsigned index = 0; index < 3; ++index) {
    MothershipProductionStatefulMemberReceipt member;
    member.containerUUID = source ? 0x801 + index : 0xc01 + index;
    member.machineUUID = source ? 0x901 + index : 0xa01 + index;
    auto& receipt = member.receipt;
    auto& authority = receipt.authority;
    authority.operationUUID = intent.operationUUID;
    authority.sourceClusterUUID = intent.route.sourceClusterUUID; authority.targetClusterUUID = intent.route.destinationClusterUUID;
    authority.localClusterUUID = source ? authority.sourceClusterUUID : authority.targetClusterUUID;
    authority.writeOwnerClusterUUID = active || postCleanup ? authority.targetClusterUUID : authority.sourceClusterUUID;
    authority.datasetUUID = intent.stateful.datasetUUID; authority.snapshotUUID = intent.stateful.snapshotUUID;
    authority.shardGroup = intent.stateful.shardGroup;
    authority.contractSHA256 = intent.stateful.contractSHA256; authority.shardManifestSHA256 = intent.stateful.shardManifestSHA256;
    authority.mode = retained ? StatefulDataAuthorityMode::retainedSource : (preparing ? StatefulDataAuthorityMode::snapshotPreparing :
        (source ? StatefulDataAuthorityMode::fenced : (active ? StatefulDataAuthorityMode::writeOwner : StatefulDataAuthorityMode::catchupOnly)));
    authority.authorityEpoch = retained ? 6 : (preparing ? 1 : (phase == MothershipProductionPairPhase::catchupVerified ? 2 :
        (source ? 3 : (active ? 5 : 4))));
    if (!preparing) authority.snapshotBoundarySHA256 = digest('e');
    if (!preparing && (!source || postCleanup)) authority.requiredAppliedWatermarkSHA256 = phase == MothershipProductionPairPhase::catchupVerified ? digest('e') : digest('f');
    receipt.ready = phase != MothershipProductionPairPhase::catchupVerified; receipt.snapshotReceiptSHA256 = digest('e');
    if (!preparing && phase != MothershipProductionPairPhase::catchupVerified) receipt.appliedWatermarkSHA256 = digest('f');
    if (postCleanup || (source && !preparing && !retained)) receipt.fenceReceiptSHA256 = digest('1');
    if (retained) receipt.cleanupReceiptSHA256 = digest('2');
    proof.members.push_back(member);
    ProdigyStatefulServingAuthorityMember identity;
    identity.containerUUID = member.containerUUID; identity.machineUUID = member.machineUUID;
    identity.shardGroup = 3; identity.isSource = source; identity.advertiseClient = (preparing || (retained && !postCleanup) || active) && index == 0;
    identity.planSHA256 = digest('3'); proof.cohort.push_back(identity);
  }
  return proof;
}

static void testStatefulPair()
{
  String failure;
  auto request = statefulIntent();
  assert(mothershipProductionPairIntentValid(request, &failure));
  for (uint16_t retained : {2, 5, 10}) {
    auto forbidden = request;
    forbidden.sourceWorkload.applicationID = forbidden.targetWorkload.applicationID = retained;
    forbidden.sourceWorkload.deploymentID = (uint64_t(retained) << 48) | 11;
    forbidden.targetWorkload.deploymentID = (uint64_t(retained) << 48) | 12;
    assert(!mothershipProductionPairIntentValid(forbidden));
  }
  auto physical = request; physical.selectorAddress = "192.0.2.1"_ctv;
  assert(!mothershipProductionPairIntentValid(physical));
  auto foreignShard = request; foreignShard.stateful.shardGroup = 4;
  assert(!mothershipProductionPairIntentValid(foreignShard));
  auto predictedTarget = request; predictedTarget.stateful.cohort[0].isSource = false;
  assert(!mothershipProductionPairIntentValid(predictedTarget));
  MothershipProductionPairRecord record;
  assert(mothershipProductionPairBegin(request, 100, record));
  assert(mothershipProductionPairAdvance(record, MothershipProductionPairPhase::targetAdmitted, digest('4'), 101));
  assert(!mothershipProductionPairMarkTransitApplied(record, digest('5'), 102));
  assert(!mothershipProductionPairApplyStatefulReceipt(record,
      statefulProof(request, MothershipProductionPairPhase::targetOwnershipActive), 102));
  const MothershipProductionPairPhase phases[] = {
    MothershipProductionPairPhase::snapshotVerified, MothershipProductionPairPhase::catchupVerified,
    MothershipProductionPairPhase::sourceWriterFenced, MothershipProductionPairPhase::fencedCatchupVerified,
    MothershipProductionPairPhase::targetOwnershipActive};
  for (unsigned index = 0; index < 5; ++index) {
    StatefulDataAuthorityOperation command;
    assert(mothershipProductionPairStatefulCommand(record, phases[index], command));
    assert(command.authority.shardGroup == request.stateful.shardGroup && command.authority.operationUUID == request.operationUUID);
    if (index == 0) assert(command.authority.snapshotBoundarySHA256.empty());
    if (index == 2) assert(command.authority.requiredAppliedWatermarkSHA256.empty());
    if (index >= 3) assert(command.authority.requiredAppliedWatermarkSHA256 == digest('f'));
    record.hasPendingStatefulCommand = true; record.pendingStatefulPhase = phases[index];
    assert(mothershipProductionPairRecordValid(record));
    const auto proof = statefulProof(request, phases[index]);
    if (index == 1) {
      assert(!proof.members[0].receipt.ready && prodigyStatefulDataAuthorityReceiptStaged(proof.members[0].receipt));
      auto ambiguous = proof.members[0].receipt; ambiguous.appliedWatermarkSHA256 = digest('f');
      assert(!prodigyStatefulDataAuthorityReceiptValid(ambiguous));
    }
    auto wrong = proof; wrong.members[0].receipt.authority.authorityEpoch = 1;
    if (index != 0) assert(!mothershipProductionPairApplyStatefulReceipt(record, wrong, 102 + index));
    wrong = proof; wrong.members[0].receipt.authority.shardGroup = 4;
    assert(!mothershipProductionPairApplyStatefulReceipt(record, wrong, 102 + index));
    wrong = proof; wrong.members[0].receipt.authority.operationUUID++;
    assert(!mothershipProductionPairApplyStatefulReceipt(record, wrong, 102 + index));
    assert(mothershipProductionPairApplyStatefulReceipt(record, proof, 102 + index, &failure));
    assert(mothershipProductionPairApplyStatefulReceipt(record, proof, 102 + index));
    String encoded; auto copy = record;
    BitseryEngine::serialize(encoded, copy);
    MothershipProductionPairRecord restored;
    assert(BitseryEngine::deserializeSafe(encoded, restored) && mothershipProductionPairRecordValid(restored));
    record = restored; // Coordinator cold/master recovery preserves each exact gate.
    if (index != 0) assert(!mothershipProductionPairApplyStatefulReceipt(record, statefulProof(request, phases[index - 1]), 110));
  }
  assert(!mothershipProductionPairMarkTransitApplied(record, digest('5'), 111));
  assert(mothershipProductionPairAdvance(record, MothershipProductionPairPhase::targetSelected, digest('5'), 111));
  assert(!mothershipProductionPairAdvance(record, MothershipProductionPairPhase::sourceRetired, digest('6'), 112));
  StatefulDataAuthorityOperation cleanupCommand;
  assert(mothershipProductionPairStatefulCommand(record, MothershipProductionPairPhase::sourceCleanupVerified, cleanupCommand));
  assert(cleanupCommand.authority.mode == StatefulDataAuthorityMode::retainedSource &&
      cleanupCommand.authority.writeOwnerClusterUUID == request.route.destinationClusterUUID &&
      cleanupCommand.authority.requiredAppliedWatermarkSHA256 == digest('f'));
  auto sourceCleanup = statefulProof(request, MothershipProductionPairPhase::sourceCleanupVerified);
  auto wrongCleanup = sourceCleanup; wrongCleanup.members[0].receipt.fenceReceiptSHA256 = digest('8');
  assert(!mothershipProductionPairApplyStatefulReceipt(record, wrongCleanup, 112));
  assert(mothershipProductionPairApplyStatefulReceipt(record, sourceCleanup, 112));
  assert(mothershipProductionPairAdvance(record, MothershipProductionPairPhase::sourceRetired, digest('6'), 113));
  assert(mothershipProductionPairAdvance(record, MothershipProductionPairPhase::cleanupComplete, digest('7'), 114));
  assert(!mothershipProductionPairAbortStatefulBeforeFence(record, digest('6'), 112, false));
  MothershipProductionPairRecord aborted;
  assert(mothershipProductionPairBegin(request, 100, aborted));
  assert(mothershipProductionPairAdvance(aborted, MothershipProductionPairPhase::targetAdmitted, digest('4'), 101));
  assert(mothershipProductionPairApplyStatefulReceipt(aborted, statefulProof(request, phases[0]), 102));
  assert(mothershipProductionPairAbortStatefulBeforeFence(aborted, digest('6'), 103, false));
  assert(!mothershipProductionPairAbortStatefulBeforeFence(aborted, digest('7'), 104, true));
  auto cleanup = statefulProof(request, MothershipProductionPairPhase::statefulAbortedBeforeFence);
  assert(!mothershipProductionPairObserveStatefulAbort(aborted, cleanup, 104));
  auto targetCompensation = digest('8');
  assert(mothershipProductionPairObserveStatefulTargetCompensation(aborted, targetCompensation, 104));
  assert(mothershipProductionPairObserveStatefulTargetCompensation(aborted, targetCompensation, 104));
  assert(!mothershipProductionPairObserveStatefulTargetCompensation(aborted, digest('9'), 104));
  assert(mothershipProductionPairObserveStatefulAbort(aborted, cleanup, 105));
  assert(mothershipProductionPairAbortStatefulBeforeFence(aborted, digest('7'), 106, true, &failure, &cleanup, &targetCompensation));
  assert(mothershipProductionPairAbortStatefulBeforeFence(aborted, digest('7'), 106, true, &failure, &cleanup, &targetCompensation));
  auto conflictingCleanup = cleanup; conflictingCleanup.members[0].receipt.cleanupReceiptSHA256 = digest('a');
  assert(!mothershipProductionPairAbortStatefulBeforeFence(aborted, digest('7'), 106, true, &failure, &conflictingCleanup, &targetCompensation));
  auto conflictingTarget = digest('a');
  assert(!mothershipProductionPairAbortStatefulBeforeFence(aborted, digest('7'), 106, true, &failure, &cleanup, &conflictingTarget));
  assert(mothershipProductionPairRecordValid(aborted));
  assert(!aborted.statefulAbortTargetAdmissionIssued); // no catchup command was authorized
  MothershipProductionPairRecord pendingTarget;
  assert(mothershipProductionPairBegin(request, 100, pendingTarget));
  assert(mothershipProductionPairAdvance(pendingTarget, MothershipProductionPairPhase::targetAdmitted, digest('4'), 101));
  assert(mothershipProductionPairApplyStatefulReceipt(pendingTarget, statefulProof(request, phases[0]), 102));
  pendingTarget.hasPendingStatefulCommand = true; pendingTarget.pendingStatefulPhase = phases[1];
  assert(mothershipProductionPairRecordValid(pendingTarget));
  assert(mothershipProductionPairAbortStatefulBeforeFence(pendingTarget, digest('6'), 103, false));
  assert(pendingTarget.statefulAbortTargetAdmissionIssued);
  // A partition/partial target keeps abort pending and the source writer live;
  // neither source cleanup nor a terminal record can precede its exact fence.
  assert(!mothershipProductionPairObserveStatefulAbort(pendingTarget, cleanup, 104));
  assert(!mothershipProductionPairAbortStatefulBeforeFence(pendingTarget, digest('7'), 104, true, nullptr, &cleanup, &targetCompensation));
  String abortBytes; BitseryEngine::serialize(abortBytes, pendingTarget);
  MothershipProductionPairRecord recoveredAbort;
  assert(BitseryEngine::deserializeSafe(abortBytes, recoveredAbort) && mothershipProductionPairRecordValid(recoveredAbort));
  assert(recoveredAbort.statefulAbortTargetAdmissionIssued && !recoveredAbort.hasStatefulAbortReceipt);
  assert(mothershipProductionPairObserveStatefulTargetCompensation(recoveredAbort, targetCompensation, 105));
  assert(mothershipProductionPairObserveStatefulAbort(recoveredAbort, cleanup, 106));
  assert(mothershipProductionPairAbortStatefulBeforeFence(recoveredAbort, digest('7'), 107, true, nullptr, &cleanup, &targetCompensation));
  auto fenceInFlight = pendingTarget;
  fenceInFlight.phase = MothershipProductionPairPhase::catchupVerified;
  fenceInFlight.statefulAbortTargetAdmissionIssued = false;
  fenceInFlight.cleanupReceiptSHA256.clear();
  fenceInFlight.statefulReceipts.push_back(statefulProof(request, phases[1]));
  fenceInFlight.hasPendingStatefulCommand = true; fenceInFlight.pendingStatefulPhase = phases[2];
  assert(mothershipProductionPairRecordValid(fenceInFlight));
  assert(!mothershipProductionPairAbortStatefulBeforeFence(fenceInFlight, digest('6'), 110, false));
  auto prior = statefulProof(request, phases[0]).members[0].receipt.authority;
  auto fenced = statefulProof(request, phases[2]).members[0].receipt.authority;
  auto retained = cleanup.members[0].receipt.authority;
  assert(prodigyStatefulDataAuthorityCanAdvance(prior, fenced));
  assert(prodigyStatefulDataAuthorityCanAdvance(prior, retained));
  assert(!prodigyStatefulDataAuthorityCanAdvance(fenced, retained));
  auto postCleanup = sourceCleanup.members[0].receipt.authority;
  assert(prodigyStatefulDataAuthorityCanAdvance(fenced, postCleanup));
  StatefulTopology sourceTopology; sourceTopology.servingMode = StatefulTopologyServingMode::applicationDataAuthority;
  sourceTopology.dataAuthority = postCleanup;
  assert(!prodigyStatefulTopologyServesClients(sourceTopology));
  auto target = statefulProof(request, phases[4]).members[0].receipt.authority;
  auto reverse = prior;
  reverse.operationUUID++; reverse.previousOperationUUID = target.operationUUID; reverse.previousAuthorityEpoch = target.authorityEpoch;
  reverse.authorityEpoch = 7; reverse.sourceClusterUUID = target.targetClusterUUID; reverse.targetClusterUUID = target.sourceClusterUUID;
  reverse.localClusterUUID = reverse.writeOwnerClusterUUID = reverse.sourceClusterUUID;
  reverse.snapshotUUID++;
  assert(prodigyStatefulDataAuthorityCanAdvance(target, reverse));
  auto reverseTarget = reverse;
  reverseTarget.localClusterUUID = reverseTarget.targetClusterUUID; reverseTarget.mode = StatefulDataAuthorityMode::catchupOnly;
  reverseTarget.snapshotBoundarySHA256 = reverseTarget.requiredAppliedWatermarkSHA256 = digest('e'); reverseTarget.authorityEpoch = 8;
  assert(prodigyStatefulDataAuthorityCanAdvance(fenced, reverseTarget));
  assert(prodigyStatefulDataAuthorityCanAdvance(postCleanup, reverseTarget));
  reverseTarget.previousOperationUUID++;
  assert(!prodigyStatefulDataAuthorityCanAdvance(fenced, reverseTarget));
}

int main()
{
  testStatefulPair();
  String failure = {};
  MothershipProductionPairIntent request = intent();
  assert(request.protocolVersion == 6);
  assert(mothershipProductionPairIngressAddressValid("192.0.2.13"_ctv));
  assert(!mothershipProductionPairIngressAddressValid("0.0.0.0"_ctv));
  assert(!mothershipProductionPairIngressAddressValid("127.0.0.1"_ctv));
  assert(!mothershipProductionPairIngressAddressValid("169.254.1.1"_ctv));
  assert(!mothershipProductionPairIngressAddressValid("224.0.0.1"_ctv));
  assert(request.selectorMachineUUID != request.sourceWorkload.endpointMachineUUID);
  assert(mothershipProductionPairIntentValid(request, &failure));

  MothershipProductionPairRecord record = {};
  assert(mothershipProductionPairBegin(request, 1000, record, &failure));
  assert(mothershipProductionPairRecordValid(record, &failure));
  assert(mothershipProductionPairAdvance(record, MothershipProductionPairPhase::targetAdmitted, digest('1'), 1001, &failure));
  assert(mothershipProductionPairAdvance(record, MothershipProductionPairPhase::targetAdmitted, digest('1'), 1001, &failure));
  assert(!mothershipProductionPairAdvance(record, MothershipProductionPairPhase::targetAdmitted, digest('2'), 1001, &failure));
  assert(mothershipProductionPairMarkTransitApplied(record, digest('2'), 1002, &failure));
  assert(mothershipProductionPairMarkTransitApplied(record, digest('2'), 1002, &failure));
  assert(!mothershipProductionPairMarkTransitApplied(record, digest('z'), 1002, &failure));
  assert(!mothershipProductionPairAdvance(record, MothershipProductionPairPhase::targetSelected, digest('3'), 1003, &failure));
  assert(mothershipProductionPairAdvance(record, MothershipProductionPairPhase::sourceIngressWitnessed, digest('3'), 1003, &failure));
  assert(mothershipProductionPairAdvance(record, MothershipProductionPairPhase::targetSelected, digest('4'), 1004, &failure));
  assert(!mothershipProductionPairAdvance(record, MothershipProductionPairPhase::sourceDrained, digest('5'), 1005, &failure));
  assert(mothershipProductionPairAdvance(record, MothershipProductionPairPhase::targetIngressWitnessed, digest('5'), 1005, &failure));
  assert(mothershipProductionPairAdvance(record, MothershipProductionPairPhase::sourceDrained, digest('6'), 1006, &failure));
  assert(mothershipProductionPairAdvance(record, MothershipProductionPairPhase::sourceRetired, digest('7'), 1007, &failure));
  assert(mothershipProductionPairAdvance(record, MothershipProductionPairPhase::cleanupComplete, digest('8'), 1008, &failure));
  assert(mothershipProductionPairRecordValid(record, &failure));

  MothershipProductionPairIntent changed = request;
  changed.destinationPermission.artifactSHA256 = digest('z');
  assert(!mothershipProductionPairIntentValid(changed, &failure) || !mothershipProductionPairIntentExactMatches(request, changed));
  changed = request; changed.destinationPermission.localDeploymentID++;
  assert(!mothershipProductionPairIntentExactMatches(request, changed));
  changed = request; changed.sourceRouteReceipt.localRuntimeRevision++;
  assert(!mothershipProductionPairIntentExactMatches(request, changed));
  changed = request; changed.selectorMachineUUID++;
  assert(mothershipProductionPairIntentValid(changed, &failure));
  assert(!mothershipProductionPairIntentExactMatches(request, changed));
  changed = request; changed.ingressWitnessMachineUUID = request.selectorMachineUUID;
  assert(!mothershipProductionPairIntentValid(changed, &failure));
  changed = request; changed.selectorCloudID = "provider-machine-reassigned"_ctv;
  assert(mothershipProductionPairIntentValid(changed, &failure));
  assert(!mothershipProductionPairIntentExactMatches(request, changed));
  changed = request; changed.selectorExecutorKind = MothershipPhysicalFaultExecutorKind::localVM;
  assert(!mothershipProductionPairIntentValid(changed, &failure));
  changed = request; changed.protocolVersion = 4;
  assert(!mothershipProductionPairIntentValid(changed, &failure));
  changed = request;
  changed.sourceWorkload.endpointIPv4 = "2001:db8:1::11"_ctv;
  changed.targetWorkload.endpointIPv4 = "2001:db8:2::12"_ctv;
  assert(mothershipProductionPairIntentValid(changed, &failure));
  String ipv6Encoded = {}; auto ipv6RoundTripSource = changed;
  BitseryEngine::serialize(ipv6Encoded, ipv6RoundTripSource);
  MothershipProductionPairIntent ipv6RoundTrip = {};
  assert(BitseryEngine::deserializeSafe(ipv6Encoded, ipv6RoundTrip));
  assert(mothershipProductionPairIntentValid(ipv6RoundTrip, &failure));
  assert(ipv6RoundTrip.sourceWorkload.endpointIPv4 == changed.sourceWorkload.endpointIPv4 &&
         ipv6RoundTrip.targetWorkload.endpointIPv4 == changed.targetWorkload.endpointIPv4);
  changed.sourceWorkload.endpointIPv4 = "not-an-address"_ctv;
  assert(!mothershipProductionPairIntentValid(changed, &failure));

  String encoded = {}; auto roundTripSource = request;
  BitseryEngine::serialize(encoded, roundTripSource);
  MothershipProductionPairIntent roundTrip = {};
  assert(BitseryEngine::deserializeSafe(encoded, roundTrip));
  assert(mothershipProductionPairIntentExactMatches(request, roundTrip));

  MothershipProductionPairRecord skipped = {};
  assert(mothershipProductionPairBegin(request, 1000, skipped, &failure));
  assert(mothershipProductionPairRecordMatchesIntent(skipped, request));
  assert(!mothershipProductionPairAdvance(skipped, MothershipProductionPairPhase::sourceDrained, digest('7'), 1001, &failure));

  MothershipProductionPairRecord aborted = {};
  assert(mothershipProductionPairBegin(request, 1000, aborted, &failure));
  assert(mothershipProductionPairAdvance(aborted, MothershipProductionPairPhase::targetAdmitted,
                                         digest('a'), 1001, &failure));
  assert(mothershipProductionPairAbortBeforeTransit(aborted, digest('b'), 1002, &failure));
  assert(aborted.phase == MothershipProductionPairPhase::abortedBeforeTransit);
  assert(mothershipProductionPairRecordValid(aborted, &failure));
  assert(mothershipProductionPairAbortBeforeTransit(aborted, digest('b'), 1002, &failure));
  assert(!mothershipProductionPairAbortBeforeTransit(aborted, digest('c'), 1002, &failure));
  assert(!mothershipProductionPairAdvance(aborted, MothershipProductionPairPhase::targetSelected,
                                          digest('c'), 1003, &failure));
  assert(mothershipProductionPairAbortBeforeTransit(skipped, digest('b'), 1002, &failure));
  assert(skipped.phase == MothershipProductionPairPhase::abortedBeforeTransit);
  assert(skipped.targetAdmissionReceiptSHA256.empty());
  assert(mothershipProductionPairRecordValid(skipped, &failure));
  assert(mothershipProductionPairAbortBeforeTransit(skipped, digest('b'), 1002, &failure));
  assert(!mothershipProductionPairAbortBeforeTransit(skipped, digest('c'), 1002, &failure));
  MothershipProductionPairRecord afterTransit = {};
  assert(mothershipProductionPairBegin(request, 1000, afterTransit, &failure));
  assert(mothershipProductionPairAdvance(afterTransit, MothershipProductionPairPhase::targetAdmitted,
                                         digest('a'), 1001, &failure));
  assert(mothershipProductionPairMarkTransitApplied(afterTransit, digest('b'), 1002, &failure));
  assert(!mothershipProductionPairAbortBeforeTransit(afterTransit, digest('c'), 1003, &failure));
  assert(!mothershipProductionPairAbortBeforeCutover(afterTransit, digest('c'), 1003, &failure));
  // The durable pending state is the coordinator write-ahead record.  A crash
  // after it survives provider removal and lets the same abort resume without
  // requiring a now-deleted live selector to be queried again.
  assert(mothershipProductionPairPrepareAbortBeforeCutover(afterTransit, digest('c'), 1003, &failure));
  assert(afterTransit.phase == MothershipProductionPairPhase::abortBeforeCutoverPending);
  assert(mothershipProductionPairRecordValid(afterTransit, &failure));
  assert(mothershipProductionPairPrepareAbortBeforeCutover(afterTransit, digest('c'), 1003, &failure));
  assert(!mothershipProductionPairPrepareAbortBeforeCutover(afterTransit, digest('d'), 1003, &failure));
  assert(!mothershipProductionPairAdvance(afterTransit, MothershipProductionPairPhase::targetSelected,
                                          digest('d'), 1004, &failure));
  assert(mothershipProductionPairAbortBeforeCutover(afterTransit, digest('d'), 1004, &failure));
  assert(afterTransit.phase == MothershipProductionPairPhase::abortedBeforeCutover);
  assert(mothershipProductionPairRecordValid(afterTransit, &failure));
  assert(mothershipProductionPairAbortBeforeCutover(afterTransit, digest('d'), 1004, &failure));
  assert(!mothershipProductionPairAbortBeforeCutover(afterTransit, digest('e'), 1004, &failure));
  std::puts("PASS: production paired-migration state validation, abort write-ahead, and idempotency");
  return 0;
}
