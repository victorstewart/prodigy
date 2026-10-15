#pragma once

// Durable, provider-neutral coordination state for one cross-cluster service
// move.  This is intentionally a Mothership record: Brains retain ownership of
// deployment, permission, route, and retirement state.  The record binds the
// exact facts Mothership observed from those owners and makes retries/recovery
// fail closed without embedding a test-provider boundary or provider secret.

#include <arpa/inet.h>

#include <prodigy/cousin.route.h>
#include <prodigy/mothership/mothership.physical.fault.h>

enum class MothershipProductionPairPhase : uint8_t {
  prepared = 1,
  targetAdmitted = 2,
  transitApplied = 3,
  sourceIngressWitnessed = 4,
  targetSelected = 5,
  targetIngressWitnessed = 6,
  sourceDrained = 7,
  sourceRetired = 8,
  cleanupComplete = 9,
  // No traffic selection became durable.  The admitted target remains intact,
  // but the provisional selector and any physical-boundary admission were
  // removed under one exact abort receipt.
  abortedBeforeTransit = 10,
};

static inline bool mothershipProductionPairPhaseValid(MothershipProductionPairPhase phase)
{
  return phase >= MothershipProductionPairPhase::prepared &&
         phase <= MothershipProductionPairPhase::abortedBeforeTransit;
}

static inline bool mothershipProductionPairTerminal(MothershipProductionPairPhase phase)
{
  return phase == MothershipProductionPairPhase::cleanupComplete ||
         phase == MothershipProductionPairPhase::abortedBeforeTransit;
}

// An opaque owner-issued receipt is recorded only by its exact SHA-256 digest.
// It must not be a provider response, secret, or a replacement for the owner
// state it attests.
static inline bool mothershipProductionPairReceiptValid(const String& receipt)
{
  return prodigyIsSHA256HexDigest(receipt);
}

// Exact live identity of the stateless workload endpoint on one side of the
// migration.  The COUSIN permissions below bind a separate stateful transport
// deployment; keeping the two identities distinct prevents a healthy transport
// replica from being mistaken for the workload that will be retired.
class MothershipProductionWorkloadIdentity {
public:
  static constexpr uint32_t version = 1;

  uint32_t protocolVersion = version;
  uint128_t clusterUUID = 0;
  uint16_t applicationID = 0;
  uint64_t deploymentID = 0;
  String canonicalPlanSHA256 = {};
  String artifactSHA256 = {};
  uint64_t artifactBytes = 0;
  uint32_t replicas = 0;
  uint128_t endpointMachineUUID = 0;
  String endpointIPv4 = {};
  uint16_t endpointTCPPort = 0;
};

template <typename S>
static void serialize(S&& serializer, MothershipProductionWorkloadIdentity& identity)
{
  serializer.value4b(identity.protocolVersion);
  serializer.value16b(identity.clusterUUID);
  serializer.value2b(identity.applicationID);
  serializer.value8b(identity.deploymentID);
  serializer.text1b(identity.canonicalPlanSHA256, 64);
  serializer.text1b(identity.artifactSHA256, 64);
  serializer.value8b(identity.artifactBytes);
  serializer.value4b(identity.replicas);
  serializer.value16b(identity.endpointMachineUUID);
  serializer.text1b(identity.endpointIPv4, INET_ADDRSTRLEN);
  serializer.value2b(identity.endpointTCPPort);
}

static inline bool mothershipProductionWorkloadIdentityValid(
    const MothershipProductionWorkloadIdentity& identity)
{
  struct in_addr address = {};
  String endpoint = identity.endpointIPv4;
  return identity.protocolVersion == MothershipProductionWorkloadIdentity::version &&
         identity.clusterUUID != 0 && identity.applicationID != 0 && identity.deploymentID != 0 &&
         uint16_t(identity.deploymentID >> 48) == identity.applicationID &&
         mothershipProductionPairReceiptValid(identity.canonicalPlanSHA256) &&
         mothershipProductionPairReceiptValid(identity.artifactSHA256) && identity.artifactBytes != 0 &&
         identity.replicas == 1 && identity.endpointMachineUUID != 0 && identity.endpointTCPPort != 0 &&
         ::inet_pton(AF_INET, endpoint.c_str(), &address) == 1;
}

class MothershipProductionPairIntent {
public:
  static constexpr uint32_t version = 6;

  uint32_t protocolVersion = version;
  uint128_t operationUUID = 0;
  CousinRouteRecord route = {};
  ProdigyLocalCousinServicePermission sourcePermission = {};
  ProdigyLocalCousinServicePermission destinationPermission = {};
  CousinRouteApplyReceipt sourceRouteReceipt = {};
  CousinRouteApplyReceipt destinationRouteReceipt = {};
  MothershipProductionWorkloadIdentity sourceWorkload = {};
  MothershipProductionWorkloadIdentity targetWorkload = {};
  uint128_t physicalBoundaryUUID = 0;
  uint128_t selectorMachineUUID = 0;
  MothershipPhysicalFaultExecutorKind selectorExecutorKind = MothershipPhysicalFaultExecutorKind::localVM;
  uint128_t selectorLocalVMBoundaryUUID = 0;
  String selectorCloudID = {};
  String selectorAddress = {};
  uint16_t selectorTCPPort = 0;
  // A distinct, admitted topology member executes the traffic witness.  The
  // relay's own counters can corroborate this observation but can never
  // replace it as authorization to retire the source.
  uint128_t ingressWitnessMachineUUID = 0;
  MothershipPhysicalFaultExecutorKind ingressWitnessExecutorKind = MothershipPhysicalFaultExecutorKind::localVM;
  uint128_t ingressWitnessLocalVMBoundaryUUID = 0;
  String ingressWitnessCloudID = {};
};

template <typename S>
static void serialize(S&& serializer, MothershipProductionPairIntent& intent)
{
  serializer.value4b(intent.protocolVersion);
  serializer.value16b(intent.operationUUID);
  serializer.object(intent.route);
  serializer.object(intent.sourcePermission);
  serializer.object(intent.destinationPermission);
  serializer.object(intent.sourceRouteReceipt);
  serializer.object(intent.destinationRouteReceipt);
  serializer.object(intent.sourceWorkload);
  serializer.object(intent.targetWorkload);
  serializer.value16b(intent.physicalBoundaryUUID);
  serializer.value16b(intent.selectorMachineUUID);
  serializer.value1b(intent.selectorExecutorKind);
  serializer.value16b(intent.selectorLocalVMBoundaryUUID);
  serializer.text1b(intent.selectorCloudID, 1024);
  serializer.text1b(intent.selectorAddress, INET_ADDRSTRLEN);
  serializer.value2b(intent.selectorTCPPort);
  serializer.value16b(intent.ingressWitnessMachineUUID);
  serializer.value1b(intent.ingressWitnessExecutorKind);
  serializer.value16b(intent.ingressWitnessLocalVMBoundaryUUID);
  serializer.text1b(intent.ingressWitnessCloudID, 1024);
}

// The relay must be one concrete address on the admitted source machine.  A
// loopback listener can exercise its upstream sockets, but it is not a service
// transit boundary because no physical client can enter through it.
static inline bool mothershipProductionPairIngressAddressValid(const String& value)
{
  struct in_addr address = {};
  String owned = value;
  if (::inet_pton(AF_INET, owned.c_str(), &address) != 1) return false;
  const uint32_t host = uint32_t(ntohl(address.s_addr));
  return host != 0 && host != UINT32_MAX && (host >> 24) != 127 &&
      (host & 0xf0000000u) != 0xe0000000u && (host & 0xffff0000u) != 0xa9fe0000u;
}

static inline bool mothershipProductionPairIntentExactMatches(
    const MothershipProductionPairIntent& left, const MothershipProductionPairIntent& right)
{
  String leftBytes = {}, rightBytes = {};
  MothershipProductionPairIntent leftCopy = left, rightCopy = right;
  BitseryEngine::serialize(leftBytes, leftCopy);
  BitseryEngine::serialize(rightBytes, rightCopy);
  return leftBytes == rightBytes;
}

static inline bool mothershipProductionPairIntentValid(const MothershipProductionPairIntent& intent,
                                                       String *failure = nullptr)
{
  if (failure) failure->clear();
  auto reject = [&](const char *reason) { if (failure) failure->assign(reason); return false; };
  const auto& route = intent.route;
  const auto& source = intent.sourcePermission;
  const auto& destination = intent.destinationPermission;
  if (intent.protocolVersion != MothershipProductionPairIntent::version || intent.operationUUID == 0 ||
      !cousinRouteStructurallyValid(route) || !cousinRouteCurrentContract(route) ||
      route.state != CousinRouteState::active ||
      !prodigyLocalCousinServicePermissionValid(source) ||
      !prodigyLocalCousinServicePermissionValid(destination) ||
      source.state != ProdigyLocalCousinServicePermissionState::active ||
      destination.state != ProdigyLocalCousinServicePermissionState::active ||
      !mothershipProductionWorkloadIdentityValid(intent.sourceWorkload) ||
      !mothershipProductionWorkloadIdentityValid(intent.targetWorkload) ||
      intent.physicalBoundaryUUID == 0 ||
      intent.selectorMachineUUID == 0 ||
      !mothershipPhysicalFaultExecutorIdentityValid(intent.selectorExecutorKind,
                                                     intent.selectorLocalVMBoundaryUUID,
                                                     intent.selectorCloudID) ||
      !mothershipProductionPairIngressAddressValid(intent.selectorAddress) ||
      intent.selectorTCPPort == 0 || intent.ingressWitnessMachineUUID == 0 ||
      !mothershipPhysicalFaultExecutorIdentityValid(intent.ingressWitnessExecutorKind,
                                                     intent.ingressWitnessLocalVMBoundaryUUID,
                                                     intent.ingressWitnessCloudID))
    return reject("production pair intent has an invalid operation, active route, or active permission");

  if (source.localHalf != CousinRouteHalf::source || destination.localHalf != CousinRouteHalf::destination ||
      source.pairUUID != route.pairUUID || destination.pairUUID != route.pairUUID ||
      source.logicalWorkloadUUID != route.logicalWorkloadUUID || destination.logicalWorkloadUUID != route.logicalWorkloadUUID ||
      source.logicalServiceUUID != route.logicalServiceUUID || destination.logicalServiceUUID != route.logicalServiceUUID ||
      source.localClusterUUID != route.sourceClusterUUID || source.peerClusterUUID != route.destinationClusterUUID ||
      destination.localClusterUUID != route.destinationClusterUUID || destination.peerClusterUUID != route.sourceClusterUUID ||
      source.localApplicationID != route.sourceApplicationID || source.peerApplicationID != route.destinationApplicationID ||
      destination.localApplicationID != route.destinationApplicationID || destination.peerApplicationID != route.sourceApplicationID ||
      source.localCousinServicePrefix != route.sourceCousinServicePrefix ||
      source.peerCousinServicePrefix != route.destinationCousinServicePrefix ||
      destination.localCousinServicePrefix != route.destinationCousinServicePrefix ||
      destination.peerCousinServicePrefix != route.sourceCousinServicePrefix ||
      source.slots != route.slots || destination.slots != route.slots ||
      source.permissionUUID != route.sourcePermissionUUID || destination.permissionUUID != route.destinationPermissionUUID ||
      source.localDeploymentID == destination.localDeploymentID ||
      intent.sourceWorkload.clusterUUID != route.sourceClusterUUID ||
      intent.targetWorkload.clusterUUID != route.destinationClusterUUID ||
      intent.selectorMachineUUID != intent.sourceWorkload.endpointMachineUUID ||
      intent.ingressWitnessMachineUUID == intent.selectorMachineUUID ||
      intent.sourceWorkload.deploymentID == source.localDeploymentID ||
      intent.targetWorkload.deploymentID == destination.localDeploymentID ||
      intent.sourceWorkload.applicationID != intent.targetWorkload.applicationID ||
      intent.sourceWorkload.artifactSHA256 != intent.targetWorkload.artifactSHA256 ||
      intent.sourceWorkload.artifactBytes != intent.targetWorkload.artifactBytes ||
      intent.sourceWorkload.endpointIPv4 == intent.targetWorkload.endpointIPv4)
    return reject("production pair intent permissions do not exactly bind the route scope");

  if (!cousinRouteReceiptsAcknowledgedAt(route, intent.sourceRouteReceipt, intent.destinationRouteReceipt,
                                         route.issuedAtMs))
    return reject("production pair intent route receipts do not acknowledge the exact active route");
  return true;
}

class MothershipProductionPairRecord {
public:
  static constexpr uint32_t version = 2;

  uint32_t protocolVersion = version;
  MothershipProductionPairIntent intent = {};
  MothershipProductionPairPhase phase = MothershipProductionPairPhase::prepared;
  uint64_t transitionGeneration = 1;
  int64_t transitionedAtMs = 0;

  String targetAdmissionReceiptSHA256 = {};
  String transitApplyReceiptSHA256 = {};
  String sourceIngressWitnessReceiptSHA256 = {};
  String targetSelectionReceiptSHA256 = {};
  String targetIngressWitnessReceiptSHA256 = {};
  String sourceDrainReceiptSHA256 = {};
  String sourceRetirementReceiptSHA256 = {};
  String cleanupReceiptSHA256 = {};
};

template <typename S>
static void serialize(S&& serializer, MothershipProductionPairRecord& record)
{
  serializer.value4b(record.protocolVersion);
  serializer.object(record.intent);
  serializer.value1b(record.phase);
  serializer.value8b(record.transitionGeneration);
  serializer.value8b(record.transitionedAtMs);
  serializer.text1b(record.targetAdmissionReceiptSHA256, 64);
  serializer.text1b(record.transitApplyReceiptSHA256, 64);
  serializer.text1b(record.sourceIngressWitnessReceiptSHA256, 64);
  serializer.text1b(record.targetSelectionReceiptSHA256, 64);
  serializer.text1b(record.targetIngressWitnessReceiptSHA256, 64);
  serializer.text1b(record.sourceDrainReceiptSHA256, 64);
  serializer.text1b(record.sourceRetirementReceiptSHA256, 64);
  serializer.text1b(record.cleanupReceiptSHA256, 64);
}

static inline bool mothershipProductionPairRecordValid(const MothershipProductionPairRecord& record,
                                                        String *failure = nullptr)
{
  if (failure) failure->clear();
  auto reject = [&](const char *reason) { if (failure) failure->assign(reason); return false; };
  if (record.protocolVersion != MothershipProductionPairRecord::version ||
      !mothershipProductionPairIntentValid(record.intent) || !mothershipProductionPairPhaseValid(record.phase) ||
      record.transitionGeneration == 0 || record.transitionedAtMs <= 0)
    return reject("production pair record has an invalid immutable intent or transition identity");
  if (record.phase == MothershipProductionPairPhase::abortedBeforeTransit)
  {
    if (!mothershipProductionPairReceiptValid(record.targetAdmissionReceiptSHA256) ||
        !record.transitApplyReceiptSHA256.empty() || !record.sourceIngressWitnessReceiptSHA256.empty() ||
        !record.targetSelectionReceiptSHA256.empty() || !record.targetIngressWitnessReceiptSHA256.empty() ||
        !record.sourceDrainReceiptSHA256.empty() || !record.sourceRetirementReceiptSHA256.empty() ||
        !mothershipProductionPairReceiptValid(record.cleanupReceiptSHA256))
      return reject("production pair pre-transit abort has invalid receipts");
    return true;
  }
  const auto require = [&](const String& receipt, MothershipProductionPairPhase atLeast) {
    return record.phase < atLeast ? receipt.empty() : mothershipProductionPairReceiptValid(receipt);
  };
  if (!require(record.targetAdmissionReceiptSHA256, MothershipProductionPairPhase::targetAdmitted) ||
      !require(record.transitApplyReceiptSHA256, MothershipProductionPairPhase::transitApplied) ||
      !require(record.sourceIngressWitnessReceiptSHA256, MothershipProductionPairPhase::sourceIngressWitnessed) ||
      !require(record.targetSelectionReceiptSHA256, MothershipProductionPairPhase::targetSelected) ||
      !require(record.targetIngressWitnessReceiptSHA256, MothershipProductionPairPhase::targetIngressWitnessed) ||
      !require(record.sourceDrainReceiptSHA256, MothershipProductionPairPhase::sourceDrained) ||
      !require(record.sourceRetirementReceiptSHA256, MothershipProductionPairPhase::sourceRetired) ||
      !require(record.cleanupReceiptSHA256, MothershipProductionPairPhase::cleanupComplete))
    return reject("production pair record has a missing, premature, or malformed owner receipt");
  return true;
}

static inline bool mothershipProductionPairRecordMatchesIntent(const MothershipProductionPairRecord& record,
                                                               const MothershipProductionPairIntent& intent)
{
  return mothershipProductionPairRecordValid(record) && mothershipProductionPairIntentValid(intent) &&
         mothershipProductionPairIntentExactMatches(record.intent, intent);
}

static inline bool mothershipProductionPairBegin(const MothershipProductionPairIntent& intent, int64_t nowMs,
                                                 MothershipProductionPairRecord& record, String *failure = nullptr)
{
  if (failure) failure->clear();
  if (!mothershipProductionPairIntentValid(intent) || nowMs <= 0) {
    if (failure) failure->assign("production pair begin requires a valid exact intent and timestamp");
    return false;
  }
  record = {};
  record.intent = intent;
  record.transitionedAtMs = nowMs;
  return true;
}

static inline String *mothershipProductionPairReceiptSlot(MothershipProductionPairRecord& record,
                                                           MothershipProductionPairPhase phase)
{
  switch (phase) {
    case MothershipProductionPairPhase::targetAdmitted: return &record.targetAdmissionReceiptSHA256;
    case MothershipProductionPairPhase::sourceIngressWitnessed: return &record.sourceIngressWitnessReceiptSHA256;
    case MothershipProductionPairPhase::targetSelected: return &record.targetSelectionReceiptSHA256;
    case MothershipProductionPairPhase::targetIngressWitnessed: return &record.targetIngressWitnessReceiptSHA256;
    case MothershipProductionPairPhase::sourceDrained: return &record.sourceDrainReceiptSHA256;
    case MothershipProductionPairPhase::sourceRetired: return &record.sourceRetirementReceiptSHA256;
    case MothershipProductionPairPhase::cleanupComplete: return &record.cleanupReceiptSHA256;
    case MothershipProductionPairPhase::abortedBeforeTransit: return &record.cleanupReceiptSHA256;
    default: return nullptr;
  }
}

// Advance one durable phase. Repeating the exact phase/receipt is a successful
// retry; a stale phase, skipped phase, or changed receipt fails closed.
static inline bool mothershipProductionPairAdvance(MothershipProductionPairRecord& record,
                                                   MothershipProductionPairPhase next,
                                                   const String& receiptSHA256, int64_t nowMs,
                                                   String *failure = nullptr)
{
  if (failure) failure->clear();
  if (!mothershipProductionPairRecordValid(record) || !mothershipProductionPairPhaseValid(next) ||
      nowMs < record.transitionedAtMs || !mothershipProductionPairReceiptValid(receiptSHA256)) {
    if (failure) failure->assign("production pair advance has invalid record, phase, receipt, or timestamp");
    return false;
  }
  const uint8_t current = uint8_t(record.phase), requested = uint8_t(next);
  if (next == MothershipProductionPairPhase::transitApplied ||
      next == MothershipProductionPairPhase::abortedBeforeTransit || requested < current || requested > current + 1) {
    if (failure) failure->assign("production pair advance must move exactly one receipt-bearing phase");
    return false;
  }
  String *slot = mothershipProductionPairReceiptSlot(record, next);
  if (slot == nullptr) { if (failure) failure->assign("production pair phase has no owner receipt slot"); return false; }
  if (requested == current) {
    if (*slot != receiptSHA256) { if (failure) failure->assign("production pair retry receipt conflicts with durable receipt"); return false; }
    return true;
  }
  *slot = receiptSHA256;
  record.phase = next;
  ++record.transitionGeneration;
  record.transitionedAtMs = nowMs;
  return mothershipProductionPairRecordValid(record, failure);
}

// Abort is intentionally not an ordinary ordinal transition: it is the one
// safe terminal branch before traffic selection.  The caller first removes the
// exact provider selector and closes any provisional boundary, then persists
// this receipt.  Repeating the exact receipt is a successful retry.
static inline bool mothershipProductionPairAbortBeforeTransit(MothershipProductionPairRecord& record,
                                                               const String& receiptSHA256, int64_t nowMs,
                                                               String *failure = nullptr)
{
  if (failure) failure->clear();
  if (!mothershipProductionPairRecordValid(record) || nowMs < record.transitionedAtMs ||
      !mothershipProductionPairReceiptValid(receiptSHA256))
  { if (failure) failure->assign("production pair abort has invalid record, receipt, or timestamp"); return false; }
  if (record.phase == MothershipProductionPairPhase::abortedBeforeTransit)
  {
    if (record.cleanupReceiptSHA256 == receiptSHA256) return true;
    if (failure) failure->assign("production pair abort retry receipt conflicts with durable receipt");
    return false;
  }
  if (record.phase != MothershipProductionPairPhase::targetAdmitted)
  { if (failure) failure->assign("production pair abort requires the target-admitted pre-transit phase"); return false; }
  record.cleanupReceiptSHA256 = receiptSHA256;
  record.phase = MothershipProductionPairPhase::abortedBeforeTransit;
  ++record.transitionGeneration;
  record.transitionedAtMs = nowMs;
  return mothershipProductionPairRecordValid(record, failure);
}

// The route receipts are immutable exact identity, but their application is a
// separate durable barrier between target admission and traffic selection.
static inline bool mothershipProductionPairMarkTransitApplied(MothershipProductionPairRecord& record,
                                                              const String& receiptSHA256, int64_t nowMs,
                                                              String *failure = nullptr)
{
  if (failure) failure->clear();
  if (!mothershipProductionPairRecordValid(record) || nowMs < record.transitionedAtMs ||
      !mothershipProductionPairReceiptValid(receiptSHA256)) {
    if (failure) failure->assign("production pair transit requires the durably admitted target");
    return false;
  }
  if (record.phase == MothershipProductionPairPhase::transitApplied) {
    if (record.transitApplyReceiptSHA256 == receiptSHA256) return true;
    if (failure) failure->assign("production pair transit retry receipt conflicts with durable receipt");
    return false;
  }
  if (record.phase != MothershipProductionPairPhase::targetAdmitted) {
    if (failure) failure->assign("production pair transit requires the durably admitted target");
    return false;
  }
  record.transitApplyReceiptSHA256 = receiptSHA256;
  record.phase = MothershipProductionPairPhase::transitApplied;
  ++record.transitionGeneration;
  record.transitionedAtMs = nowMs;
  return mothershipProductionPairRecordValid(record, failure);
}
