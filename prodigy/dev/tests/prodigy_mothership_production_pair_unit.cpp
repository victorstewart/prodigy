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

int main()
{
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
