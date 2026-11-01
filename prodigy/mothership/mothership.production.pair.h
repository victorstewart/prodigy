#pragma once

// Durable, provider-neutral coordination state for one cross-cluster service
// move.  This is intentionally a Mothership record: Brains retain ownership of
// deployment, permission, route, and retirement state.  The record binds the
// exact facts Mothership observed from those owners and makes retries/recovery
// fail closed without embedding a test-provider boundary or provider secret.

#include <arpa/inet.h>
#include <array>

#include <prodigy/cousin.route.h>
#include <prodigy/persistent.codec.h>
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
  // Transit was durably applied, but no source ingress witness or target
  // selection became durable.  The exact source-selected, zero-flow relay is
  // removed and its physical boundary is closed under one abort receipt.
  abortedBeforeCutover = 11,
  // The zero-flow source-selected state was observed and its abort was made
  // durable before the external selector is removed.  This is deliberately
  // nonterminal: retries must finish that exact compensation before the
  // boundary can close.
  abortBeforeCutoverPending = 12,
  // Version-seven application data gates precede the existing transit phases.
  snapshotVerified = 13,
  catchupVerified = 14,
  sourceWriterFenced = 15,
  targetOwnershipActive = 16,
  statefulAbortBeforeFencePending = 17,
  statefulAbortedBeforeFence = 18,
  fencedCatchupVerified = 19,
  sourceCleanupVerified = 20,
};

static inline bool mothershipProductionPairPhaseValid(MothershipProductionPairPhase phase)
{
  return phase >= MothershipProductionPairPhase::prepared &&
         phase <= MothershipProductionPairPhase::sourceCleanupVerified;
}

static inline bool mothershipProductionPairTerminal(MothershipProductionPairPhase phase)
{
  return phase == MothershipProductionPairPhase::cleanupComplete ||
         phase == MothershipProductionPairPhase::abortedBeforeTransit ||
         phase == MothershipProductionPairPhase::abortedBeforeCutover ||
         phase == MothershipProductionPairPhase::statefulAbortedBeforeFence;
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
  // Keep the historic wire field name while admitting either numeric address
  // family for the workload.  The selector listener itself remains IPv4.
  serializer.text1b(identity.endpointIPv4, INET6_ADDRSTRLEN);
  serializer.value2b(identity.endpointTCPPort);
}

static inline bool mothershipProductionWorkloadIdentityValid(
    const MothershipProductionWorkloadIdentity& identity, bool stateful = false)
{
  struct in_addr address4 = {};
  struct in6_addr address6 = {};
  String endpoint = identity.endpointIPv4;
  return identity.protocolVersion == MothershipProductionWorkloadIdentity::version &&
         identity.clusterUUID != 0 && identity.applicationID != 0 && identity.deploymentID != 0 &&
         uint16_t(identity.deploymentID >> 48) == identity.applicationID &&
         mothershipProductionPairReceiptValid(identity.canonicalPlanSHA256) &&
         mothershipProductionPairReceiptValid(identity.artifactSHA256) && identity.artifactBytes != 0 &&
         identity.replicas == (stateful ? 3u : 1u) &&
         (stateful ? (identity.endpointMachineUUID == 0 && identity.endpointTCPPort == 0 && endpoint.empty()) :
          (identity.endpointMachineUUID != 0 && identity.endpointTCPPort != 0 &&
           (::inet_pton(AF_INET, endpoint.c_str(), &address4) == 1 || ::inet_pton(AF_INET6, endpoint.c_str(), &address6) == 1)));
}

class MothershipProductionCredentialIdentity {
public:
  uint128_t clusterUUID = 0;
  String name;
  uint64_t generation = 0;
  String applyReceiptSHA256;
};

template <typename S>
static void serialize(S&& serializer, MothershipProductionCredentialIdentity& value)
{
  serializer.value16b(value.clusterUUID);
  serializer.text1b(value.name, 256);
  serializer.value8b(value.generation);
  serializer.text1b(value.applyReceiptSHA256, 64);
}

// This is the one declared Nametag profile, not a general database migration
// protocol. The application owns the meaning and enforcement of these proofs.
class MothershipProductionStatefulIntent {
public:
  uint32_t contractVersion = StatefulDataAuthority::version;
  String contractSHA256;
  String shardManifestSHA256;
  uint128_t datasetUUID = 0;
  uint128_t snapshotUUID = 0;
  String snapshotBoundarySHA256;
  uint64_t sourceDurableWatermark = 0;
  String sourceDurableWatermarkSHA256;
  uint64_t sourceFenceEpoch = 0;
  uint64_t targetOwnershipEpoch = 0;
  uint64_t snapshotPreparingEpoch = 0;
  uint64_t initialCatchupEpoch = 0;
  uint64_t fencedCatchupEpoch = 0;
  uint64_t sourceRetainedEpoch = 0;
  uint32_t shardGroup = 0;
  uint32_t nShardGroups = 0;
  uint128_t previousOperationUUID = 0;
  uint64_t previousAuthorityEpoch = 0;
  Vector<ProdigyStatefulServingAuthorityMember> cohort;
  Vector<uint128_t> targetMachineUUIDs;
  String credentialManifestSHA256;
  uint32_t credentialCount = 0;
  Vector<MothershipProductionCredentialIdentity> credentials;
  String targetDeploymentPlan;
};

// Operator input for a read-only Nametag preparation.  Application facts and
// lifecycle receipts deliberately have no representation here: those arrive
// only from authenticated owners after this request has been accepted.
class MothershipNametagStatefulPreparationRequest {
public:
  static constexpr uint32_t version = 3;
  uint32_t protocolVersion = version;
  uint128_t operationUUID = 0;
  uint128_t routeUUID = 0;
  uint128_t sourceClusterUUID = 0;
  uint128_t targetClusterUUID = 0;
  uint64_t sourceDeploymentID = 0;
  uint32_t shardGroup = UINT32_MAX;
  String targetDeploymentPlan;
  Vector<MothershipProductionCredentialIdentity> credentials;
};

template <typename S>
static void serialize(S&& serializer, MothershipNametagStatefulPreparationRequest& value)
{
  serializer.value4b(value.protocolVersion); serializer.value16b(value.operationUUID);
  serializer.value16b(value.routeUUID); serializer.value16b(value.sourceClusterUUID);
  serializer.value16b(value.targetClusterUUID); serializer.value8b(value.sourceDeploymentID);
  serializer.value4b(value.shardGroup);
  serializer.text1b(value.targetDeploymentPlan, 1024 * 1024); serializer.container(value.credentials, 256);
}

static inline bool mothershipNametagStatefulPreparationRequestValid(
    const MothershipNametagStatefulPreparationRequest& request)
{
  if (request.protocolVersion != MothershipNametagStatefulPreparationRequest::version || request.operationUUID == 0 ||
      request.routeUUID == 0 || request.sourceClusterUUID == 0 || request.targetClusterUUID == 0 ||
      request.sourceClusterUUID == request.targetClusterUUID || request.sourceDeploymentID == 0 ||
      request.shardGroup > UINT16_MAX ||
      request.targetDeploymentPlan.empty()) return false;
  const MothershipProductionCredentialIdentity *previous = nullptr;
  for (const auto& credential : request.credentials) {
    if (credential.clusterUUID == 0 || credential.name.empty() || credential.generation == 0 ||
        !prodigyIsSHA256HexDigest(credential.applyReceiptSHA256) || (previous &&
        (credential.clusterUUID < previous->clusterUUID || (credential.clusterUUID == previous->clusterUUID &&
         !prodigyPersistentStringComesBefore(previous->name, credential.name))))) return false;
    previous = &credential;
  }
  return true;
}

template <typename S>
static void serialize(S&& serializer, MothershipProductionStatefulIntent& value)
{
  serializer.value4b(value.contractVersion);
  serializer.text1b(value.contractSHA256, 64);
  serializer.text1b(value.shardManifestSHA256, 64);
  serializer.value16b(value.datasetUUID);
  serializer.value16b(value.snapshotUUID);
  serializer.text1b(value.snapshotBoundarySHA256, 64);
  serializer.value8b(value.sourceDurableWatermark);
  serializer.text1b(value.sourceDurableWatermarkSHA256, 64);
  serializer.value8b(value.sourceFenceEpoch);
  serializer.value8b(value.targetOwnershipEpoch);
  serializer.value8b(value.snapshotPreparingEpoch);
  serializer.value8b(value.initialCatchupEpoch);
  serializer.value8b(value.fencedCatchupEpoch);
  serializer.value8b(value.sourceRetainedEpoch);
  serializer.value4b(value.shardGroup);
  serializer.value4b(value.nShardGroups);
  serializer.value16b(value.previousOperationUUID);
  serializer.value8b(value.previousAuthorityEpoch);
  serializer.container(value.cohort, 4096);
  serializer.container(value.targetMachineUUIDs, 3, [](auto& nested, uint128_t& uuid) { nested.value16b(uuid); });
  serializer.text1b(value.credentialManifestSHA256, 64);
  serializer.value4b(value.credentialCount);
  serializer.container(value.credentials, 256);
  serializer.text1b(value.targetDeploymentPlan, 1024 * 1024);
}

class MothershipProductionStatefulMemberReceipt {
public:
  uint128_t containerUUID = 0;
  uint128_t machineUUID = 0;
  StatefulDataAuthorityReceipt receipt;
};

template <typename S>
static void serialize(S&& serializer, MothershipProductionStatefulMemberReceipt& value)
{
  serializer.value16b(value.containerUUID);
  serializer.value16b(value.machineUUID);
  serializer.object(value.receipt);
}

class MothershipProductionStatefulReceipt {
public:
  MothershipProductionPairPhase phase = MothershipProductionPairPhase::snapshotVerified;
  uint128_t operationUUID = 0;
  String intentSHA256;
  // An authenticated owner observation, never JSON supplied by the operator.
  uint128_t observedMasterUUID = 0;
  int64_t observedMasterBootNs = 0;
  uint64_t observedAuthorityGeneration = 0;
  Vector<MothershipProductionStatefulMemberReceipt> members;
  Vector<ProdigyStatefulServingAuthorityMember> cohort;
};

template <typename S>
static void serialize(S&& serializer, MothershipProductionStatefulReceipt& value)
{
  serializer.value1b(value.phase);
  serializer.value16b(value.operationUUID);
  serializer.text1b(value.intentSHA256, 64);
  serializer.value16b(value.observedMasterUUID);
  serializer.value8b(value.observedMasterBootNs);
  serializer.value8b(value.observedAuthorityGeneration);
  serializer.container(value.members, 4096);
  serializer.container(value.cohort, 3);
}

class MothershipProductionPairIntent {
public:
  static constexpr uint32_t version = 6;
  static constexpr uint32_t statefulVersion = 8;

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
  MothershipProductionStatefulIntent stateful;
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
  if (intent.protocolVersion == MothershipProductionPairIntent::statefulVersion)
    serializer.object(intent.stateful);
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
  const bool stateful = intent.protocolVersion == MothershipProductionPairIntent::statefulVersion;
  if ((!stateful && intent.protocolVersion != MothershipProductionPairIntent::version) || intent.operationUUID == 0 ||
      !cousinRouteStructurallyValid(route) || !cousinRouteCurrentContract(route) ||
      route.state != CousinRouteState::active ||
      !prodigyLocalCousinServicePermissionValid(source) ||
      !prodigyLocalCousinServicePermissionValid(destination) ||
      source.state != ProdigyLocalCousinServicePermissionState::active ||
      destination.state != ProdigyLocalCousinServicePermissionState::active ||
      !mothershipProductionWorkloadIdentityValid(intent.sourceWorkload, stateful) ||
      !mothershipProductionWorkloadIdentityValid(intent.targetWorkload, stateful) ||
      (!stateful && (intent.physicalBoundaryUUID == 0 ||
      intent.selectorMachineUUID == 0 ||
      !mothershipPhysicalFaultExecutorIdentityValid(intent.selectorExecutorKind,
                                                     intent.selectorLocalVMBoundaryUUID,
                                                     intent.selectorCloudID) ||
      !mothershipProductionPairIngressAddressValid(intent.selectorAddress) ||
      intent.selectorTCPPort == 0 || intent.ingressWitnessMachineUUID == 0 ||
      !mothershipPhysicalFaultExecutorIdentityValid(intent.ingressWitnessExecutorKind,
                                                     intent.ingressWitnessLocalVMBoundaryUUID,
                                                     intent.ingressWitnessCloudID))) ||
      (stateful && (intent.physicalBoundaryUUID != 0 || intent.selectorMachineUUID != 0 ||
       intent.selectorLocalVMBoundaryUUID != 0 || !intent.selectorCloudID.empty() || !intent.selectorAddress.empty() ||
       intent.selectorTCPPort != 0 || intent.ingressWitnessMachineUUID != 0 ||
       intent.ingressWitnessLocalVMBoundaryUUID != 0 || !intent.ingressWitnessCloudID.empty())))
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
      (!stateful && source.localDeploymentID == destination.localDeploymentID) ||
      (!stateful && (intent.sourceWorkload.clusterUUID != route.sourceClusterUUID ||
                     intent.targetWorkload.clusterUUID != route.destinationClusterUUID)) ||
      (!stateful && intent.ingressWitnessMachineUUID == intent.selectorMachineUUID) ||
      (!stateful && intent.sourceWorkload.deploymentID == source.localDeploymentID) ||
      (!stateful && intent.targetWorkload.deploymentID == destination.localDeploymentID) ||
      intent.sourceWorkload.applicationID != intent.targetWorkload.applicationID ||
      intent.sourceWorkload.artifactSHA256 != intent.targetWorkload.artifactSHA256 ||
      intent.sourceWorkload.artifactBytes != intent.targetWorkload.artifactBytes ||
      (!stateful && intent.sourceWorkload.endpointIPv4 == intent.targetWorkload.endpointIPv4))
    return reject("production pair intent permissions do not exactly bind the route scope");

  if (!cousinRouteReceiptsAcknowledgedAt(route, intent.sourceRouteReceipt, intent.destinationRouteReceipt,
                                         route.issuedAtMs))
    return reject("production pair intent route receipts do not acknowledge the exact active route");
  if (stateful)
  {
    const auto& data = intent.stateful;
    const bool reversed = route.sourceClusterUUID == intent.targetWorkload.clusterUUID &&
        route.destinationClusterUUID == intent.sourceWorkload.clusterUUID;
    const auto& routeSourceWorkload = intent.targetWorkload;
    const auto& routeDestinationWorkload = intent.sourceWorkload;
    uint16_t routeSlot = 0;
    // Hot/Cold is the fixed three-group production topology.  Keeping this at
    // the durable intent owner makes both fresh preparation and resume reject
    // a differently-cardinalized transfer before any phase can advance.
    const bool exactShardSlot = data.nShardGroups == 3 &&
        prodigyCousinServicePermissionSingleSlot(source, routeSlot) &&
        statefulServiceGroupOwnerForSlot(routeSlot, uint16_t(data.nShardGroups)) == data.shardGroup;
    if ((intent.sourceWorkload.applicationID != 3 && intent.sourceWorkload.applicationID != 4) ||
        !reversed ||
        source.localDeploymentID != routeSourceWorkload.deploymentID ||
        source.localApplicationID != routeSourceWorkload.applicationID ||
        source.canonicalPlanSHA256 != routeSourceWorkload.canonicalPlanSHA256 ||
        source.artifactSHA256 != routeSourceWorkload.artifactSHA256 || source.artifactBytes != routeSourceWorkload.artifactBytes ||
        destination.localDeploymentID != routeDestinationWorkload.deploymentID ||
        destination.localApplicationID != routeDestinationWorkload.applicationID ||
        destination.canonicalPlanSHA256 != routeDestinationWorkload.canonicalPlanSHA256 ||
        destination.artifactSHA256 != routeDestinationWorkload.artifactSHA256 || destination.artifactBytes != routeDestinationWorkload.artifactBytes ||
        data.contractVersion != StatefulDataAuthority::version || !prodigyIsSHA256HexDigest(data.contractSHA256) ||
        !prodigyIsSHA256HexDigest(data.shardManifestSHA256) || data.datasetUUID == 0 || data.snapshotUUID == 0 ||
        (!data.snapshotBoundarySHA256.empty() && !prodigyIsSHA256HexDigest(data.snapshotBoundarySHA256)) ||
        (!data.sourceDurableWatermarkSHA256.empty() && !prodigyIsSHA256HexDigest(data.sourceDurableWatermarkSHA256)) || data.sourceFenceEpoch == 0 ||
        data.snapshotPreparingEpoch == 0 || data.initialCatchupEpoch <= data.snapshotPreparingEpoch ||
        ((data.previousOperationUUID == 0) != (data.previousAuthorityEpoch == 0)) ||
        (data.previousAuthorityEpoch != 0 && data.snapshotPreparingEpoch <= data.previousAuthorityEpoch) ||
        data.sourceFenceEpoch <= data.initialCatchupEpoch || data.fencedCatchupEpoch <= data.sourceFenceEpoch ||
        data.targetOwnershipEpoch <= data.fencedCatchupEpoch || data.sourceRetainedEpoch <= data.targetOwnershipEpoch ||
        !exactShardSlot || data.shardGroup >= data.nShardGroups || data.shardGroup > UINT16_MAX ||
        data.cohort.size() != 3 || data.targetMachineUUIDs.size() != 3 ||
        !prodigyIsSHA256HexDigest(data.credentialManifestSHA256) ||
        data.credentialCount != data.credentials.size() || data.credentials.size() > 256)
      return reject("Nametag stateful pair requires Hot/Cold and an exact versioned data, epoch, cohort and credential contract");
    bytell_hash_set<uint128_t> containers;
    bytell_hash_map<uint32_t, std::array<uint32_t, 4>> groups;
    const ProdigyStatefulServingAuthorityMember *previous = nullptr;
    for (const auto& member : data.cohort) {
      if (!member.isSource || member.shardGroup != data.shardGroup || member.containerUUID == 0 || member.machineUUID == 0 || !prodigyIsSHA256HexDigest(member.planSHA256) ||
          !containers.insert(member.containerUUID).second || (previous &&
          (member.shardGroup < previous->shardGroup || (member.shardGroup == previous->shardGroup &&
          (member.isSource < previous->isSource || (member.isSource == previous->isSource && member.containerUUID <= previous->containerUUID))))))
        return reject("Nametag stateful cohort is incomplete, duplicated or noncanonical");
      previous = &member;
      auto& counts = groups[member.shardGroup];
      ++counts[member.isSource ? 0 : 1];
      if (member.advertiseClient) ++counts[member.isSource ? 2 : 3];
    }
    for (const auto& [shard, counts] : groups)
      if (counts[0] != 3 || counts[1] != 0 || counts[2] != 1 || counts[3] != 0)
        return reject("Nametag immutable admission binds only the source cohort; target identities come from the deployment owner");
    uint128_t previousMachine = 0;
    for (uint128_t machine : data.targetMachineUUIDs) {
      if (machine <= previousMachine) return reject("Nametag target machine set is not canonical");
      previousMachine = machine;
    }
    const MothershipProductionCredentialIdentity *previousCredential = nullptr;
    bool sourceCredentials = false, targetCredentials = false;
    for (const auto& credential : data.credentials) {
      if ((credential.clusterUUID != route.sourceClusterUUID && credential.clusterUUID != route.destinationClusterUUID) ||
          credential.name.empty() || credential.name.size() > 256 || credential.generation == 0 ||
          !prodigyIsSHA256HexDigest(credential.applyReceiptSHA256) || (previousCredential &&
          (credential.clusterUUID < previousCredential->clusterUUID || (credential.clusterUUID == previousCredential->clusterUUID &&
           !prodigyPersistentStringComesBefore(previousCredential->name, credential.name)))))
        return reject("Nametag stateful credential application identities are invalid or noncanonical");
      previousCredential = &credential;
      sourceCredentials |= credential.clusterUUID == route.sourceClusterUUID;
      targetCredentials |= credential.clusterUUID == route.destinationClusterUUID;
    }
    if (!data.credentials.empty() && (!sourceCredentials || !targetCredentials))
      return reject("Nametag credentials require application receipts on both clusters");
    auto credentials = data.credentials;
    String credentialBytes, credentialDigest;
    BitseryEngine::serialize(credentialBytes, credentials);
    if (!prodigyComputeSHA256Hex(credentialBytes, credentialDigest) || credentialDigest != data.credentialManifestSHA256)
      return reject("Nametag credential manifest does not bind the exact declared set, including the empty set");
    DeploymentPlan targetPlan;
    String targetDigest;
    if (!BitseryEngine::deserializeSafe(data.targetDeploymentPlan, targetPlan) ||
        !prodigyComputeSHA256Hex(data.targetDeploymentPlan, targetDigest) || targetDigest != intent.targetWorkload.canonicalPlanSHA256 ||
        !targetPlan.isStateful || targetPlan.config.type != ApplicationType::stateful ||
        targetPlan.config.deploymentID() != intent.targetWorkload.deploymentID ||
        targetPlan.config.applicationID != intent.targetWorkload.applicationID ||
        targetPlan.config.containerBlobSHA256 != intent.targetWorkload.artifactSHA256 ||
        targetPlan.config.containerBlobBytes != intent.targetWorkload.artifactBytes ||
        targetPlan.stateful.allMasters || targetPlan.useHostNetworkNamespace || !targetPlan.wormholes.empty() ||
        !prodigyCousinAutomaticWhiteholePlanValid(targetPlan.whiteholes) ||
        !targetPlan.horizontalScalers.empty() || !targetPlan.verticalScalers.empty() ||
        targetPlan.canaryCount != 0)
      return reject("Nametag target admission requires the exact outbound IPv6/TCP COUSIN deployment and Discombobulator artifact plan");
  }
  return true;
}

static inline uint8_t mothershipProductionPairPhaseOrder(const MothershipProductionPairIntent& intent,
                                                         MothershipProductionPairPhase phase)
{
  if (intent.protocolVersion != MothershipProductionPairIntent::statefulVersion)
    return uint8_t(phase);
  switch (phase) {
    case MothershipProductionPairPhase::prepared: return 1;
    case MothershipProductionPairPhase::targetAdmitted: return 2;
    case MothershipProductionPairPhase::snapshotVerified: return 3;
    case MothershipProductionPairPhase::catchupVerified: return 4;
    case MothershipProductionPairPhase::sourceWriterFenced: return 5;
    case MothershipProductionPairPhase::fencedCatchupVerified: return 6;
    case MothershipProductionPairPhase::targetOwnershipActive: return 7;
    case MothershipProductionPairPhase::targetSelected: return 8;
    case MothershipProductionPairPhase::sourceCleanupVerified: return 9;
    case MothershipProductionPairPhase::sourceRetired: return 10;
    case MothershipProductionPairPhase::cleanupComplete: return 11;
    default: return 0;
  }
}

static inline bool mothershipProductionStatefulReceiptValid(const MothershipProductionPairIntent& intent,
                                                            const MothershipProductionStatefulReceipt& proof)
{
  String encoded, intentDigest;
  auto copy = intent;
  if (intent.protocolVersion != MothershipProductionPairIntent::statefulVersion ||
      !mothershipProductionPairIntentValid(intent) || proof.operationUUID != intent.operationUUID ||
      !BitseryEngine::serialize(encoded, copy) || !prodigyComputeSHA256Hex(encoded, intentDigest) ||
      proof.intentSHA256 != intentDigest || proof.observedMasterUUID == 0 ||
      proof.observedMasterBootNs <= 0 || proof.observedAuthorityGeneration == 0 ||
      (proof.phase != MothershipProductionPairPhase::snapshotVerified &&
       proof.phase != MothershipProductionPairPhase::catchupVerified &&
       proof.phase != MothershipProductionPairPhase::sourceWriterFenced &&
       proof.phase != MothershipProductionPairPhase::fencedCatchupVerified &&
       proof.phase != MothershipProductionPairPhase::targetOwnershipActive &&
       proof.phase != MothershipProductionPairPhase::sourceCleanupVerified &&
       proof.phase != MothershipProductionPairPhase::statefulAbortedBeforeFence))
    return false;
  const bool preparing = proof.phase == MothershipProductionPairPhase::snapshotVerified;
  const bool cleanup = proof.phase == MothershipProductionPairPhase::sourceCleanupVerified;
  const bool retained = cleanup || proof.phase == MothershipProductionPairPhase::statefulAbortedBeforeFence;
  const bool source = retained || preparing || proof.phase == MothershipProductionPairPhase::sourceWriterFenced;
  const bool active = proof.phase == MothershipProductionPairPhase::targetOwnershipActive;
  if (proof.members.size() != 3 || proof.cohort.size() != 3) return false;
  uint128_t previousCohort = 0;
  uint32_t clients = 0;
  bytell_hash_set<uint128_t> machines;
  for (const auto& member : proof.cohort) {
    if (member.containerUUID <= previousCohort || member.machineUUID == 0 || member.shardGroup != intent.stateful.shardGroup ||
        member.isSource != source || !prodigyIsSHA256HexDigest(member.planSHA256) || !machines.insert(member.machineUUID).second) return false;
    previousCohort = member.containerUUID;
    if (member.advertiseClient) ++clients;
  }
  if (clients != ((preparing || (retained && !cleanup) || active) ? 1u : 0u)) return false;
  uint128_t previous = 0;
  for (const auto& observed : proof.members) {
    if (observed.containerUUID <= previous) return false;
    previous = observed.containerUUID;
    const auto member = std::find_if(proof.cohort.begin(), proof.cohort.end(), [&](const auto& candidate) {
      return candidate.containerUUID == observed.containerUUID && candidate.machineUUID == observed.machineUUID && candidate.isSource == source;
    });
    if (source) {
      if (std::none_of(intent.stateful.cohort.begin(), intent.stateful.cohort.end(), [&](const auto& candidate) {
        return candidate.containerUUID == observed.containerUUID && candidate.machineUUID == observed.machineUUID;
      })) return false;
    } else if (std::find(intent.stateful.targetMachineUUIDs.begin(), intent.stateful.targetMachineUUIDs.end(), observed.machineUUID) ==
               intent.stateful.targetMachineUUIDs.end()) return false;
    const auto& data = observed.receipt.authority;
    const auto expectedMode = retained ? StatefulDataAuthorityMode::retainedSource : (preparing ? StatefulDataAuthorityMode::snapshotPreparing :
        (source ? StatefulDataAuthorityMode::fenced :
         (active ? StatefulDataAuthorityMode::writeOwner : StatefulDataAuthorityMode::catchupOnly)));
    if (member == proof.cohort.end() || !prodigyStatefulDataAuthorityReceiptValid(observed.receipt) ||
        (proof.phase == MothershipProductionPairPhase::catchupVerified
         ? !prodigyStatefulDataAuthorityReceiptStaged(observed.receipt) : !observed.receipt.ready) ||
        data.operationUUID != intent.operationUUID || data.datasetUUID != intent.stateful.datasetUUID ||
        data.snapshotUUID != intent.stateful.snapshotUUID || data.shardGroup != intent.stateful.shardGroup ||
        data.nShardGroups != intent.stateful.nShardGroups ||
        data.previousOperationUUID != intent.stateful.previousOperationUUID || data.sourceClusterUUID != intent.sourceWorkload.clusterUUID ||
        data.previousAuthorityEpoch != intent.stateful.previousAuthorityEpoch ||
        data.targetClusterUUID != intent.targetWorkload.clusterUUID ||
        data.localClusterUUID != (source ? intent.sourceWorkload.clusterUUID : intent.targetWorkload.clusterUUID) ||
        data.writeOwnerClusterUUID != ((active || cleanup) ? intent.targetWorkload.clusterUUID : intent.sourceWorkload.clusterUUID) ||
        data.authorityEpoch != (retained ? intent.stateful.sourceRetainedEpoch : (preparing ? intent.stateful.snapshotPreparingEpoch :
          (proof.phase == MothershipProductionPairPhase::catchupVerified ? intent.stateful.initialCatchupEpoch :
           (source ? intent.stateful.sourceFenceEpoch :
            (active ? intent.stateful.targetOwnershipEpoch : intent.stateful.fencedCatchupEpoch))))) ||
        data.mode != expectedMode ||
        data.contractSHA256 != intent.stateful.contractSHA256 || data.shardManifestSHA256 != intent.stateful.shardManifestSHA256 ||
        (!preparing && !intent.stateful.snapshotBoundarySHA256.empty() && data.snapshotBoundarySHA256 != intent.stateful.snapshotBoundarySHA256)) return false;
  }
  return true;
}

// Separate from production_pairs: preparation is durable evidence, not pair
// admission. The exact request digest makes retries byte-stable across restart
// while refusing a different request under the same operation UUID.
class MothershipNametagStatefulPreparationRecord {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  String requestSHA256;
  MothershipProductionPairIntent intent;
};

template <typename S>
static void serialize(S&& serializer, MothershipNametagStatefulPreparationRecord& value)
{
  serializer.value4b(value.protocolVersion); serializer.text1b(value.requestSHA256, 64); serializer.object(value.intent);
}

static inline bool mothershipNametagStatefulPreparationRecordValid(
    const MothershipNametagStatefulPreparationRecord& record)
{
  return record.protocolVersion == MothershipNametagStatefulPreparationRecord::version &&
      prodigyIsSHA256HexDigest(record.requestSHA256) &&
      record.intent.protocolVersion == MothershipProductionPairIntent::statefulVersion &&
      mothershipProductionPairIntentValid(record.intent);
}

static inline bool mothershipSynthesizeNametagStatefulPreparation(
    const MothershipNametagStatefulPreparationRequest& request, const CousinRouteRecord& route,
    const ProdigyLocalCousinServicePermission& sourcePermission,
    const ProdigyLocalCousinServicePermission& destinationPermission,
    const CousinRouteApplyReceipt& sourceReceipt, const CousinRouteApplyReceipt& destinationReceipt,
    const MothershipProductionWorkloadIdentity& sourceWorkload,
    const MothershipProductionWorkloadIdentity& targetWorkload,
    const StatefulDataAuthorityPreparation& challenge,
    const Vector<ProdigyStatefulServingAuthorityMember>& cohort,
    const Vector<StatefulDataAuthorityPreparationMember>& observations,
    const Vector<uint128_t>& targetMachines, uint128_t mintedDatasetUUID, uint128_t mintedSnapshotUUID,
    MothershipProductionPairIntent& intent, String *failure = nullptr)
{
  if (failure) failure->clear();
  auto reject = [&](const char *reason) { if (failure) failure->assign(reason); return false; };
  if (!mothershipNametagStatefulPreparationRequestValid(request) || !cousinRouteCurrentContract(route) ||
      route.state != CousinRouteState::active || request.routeUUID != route.routeUUID ||
      request.sourceClusterUUID != sourceWorkload.clusterUUID ||
      request.targetClusterUUID != targetWorkload.clusterUUID ||
      request.sourceDeploymentID != sourceWorkload.deploymentID ||
      route.sourceClusterUUID != targetWorkload.clusterUUID ||
      route.destinationClusterUUID != sourceWorkload.clusterUUID ||
      sourceWorkload.applicationID != targetWorkload.applicationID ||
      (sourceWorkload.applicationID != 3 && sourceWorkload.applicationID != 4) ||
      request.shardGroup != challenge.shardGroup || challenge.nShardGroups != 3 ||
      request.shardGroup >= challenge.nShardGroups ||
      !prodigyStatefulDataAuthorityPreparationMembersAgree(challenge, cohort, observations) ||
      targetMachines.size() != 3 || !mothershipProductionWorkloadIdentityValid(sourceWorkload, true) ||
      !mothershipProductionWorkloadIdentityValid(targetWorkload, true))
    return reject("Nametag preparation requires exact Hot/Cold identities and unanimous source evidence");
  uint128_t previousMachine = 0;
  for (uint128_t machine : targetMachines) { if (machine == 0 || machine <= previousMachine) return reject("Nametag preparation target cohort is not canonical"); previousMachine = machine; }
  const auto& proof = observations.front().preparation;
  const bool established = proof.hasAuthority;
  if (established && (proof.datasetUUID == 0 || proof.currentAuthority.localClusterUUID != sourceWorkload.clusterUUID ||
                      proof.currentAuthority.writeOwnerClusterUUID != sourceWorkload.clusterUUID ||
                      proof.currentAuthority.mode != StatefulDataAuthorityMode::writeOwner))
    return reject("Nametag preparation source authority is not the current writer lineage");
  if (!established && (mintedDatasetUUID == 0 || proof.datasetUUID != 0 || proof.mode != StatefulDataAuthorityMode::writeOwner ||
                       proof.writeOwnerClusterUUID != sourceWorkload.clusterUUID))
    return reject("Nametag preparation virgin source evidence is invalid");
  if (mintedSnapshotUUID == 0) return reject("Nametag preparation cannot mint snapshot identity");
  const uint64_t baseEpoch = established ? proof.currentAuthority.authorityEpoch : 0;
  if (baseEpoch > UINT64_MAX - 6) return reject("Nametag preparation authority epoch exhausted");
  intent = {}; intent.protocolVersion = MothershipProductionPairIntent::statefulVersion; intent.operationUUID = request.operationUUID;
  intent.route = route; intent.sourcePermission = sourcePermission; intent.destinationPermission = destinationPermission;
  intent.sourceRouteReceipt = sourceReceipt; intent.destinationRouteReceipt = destinationReceipt;
  intent.sourceWorkload = sourceWorkload; intent.targetWorkload = targetWorkload;
  auto& data = intent.stateful;
  data.contractVersion = proof.contractVersion; data.contractSHA256 = proof.contractSHA256;
  data.shardManifestSHA256 = proof.shardManifestSHA256; data.datasetUUID = established ? proof.datasetUUID : mintedDatasetUUID;
  data.snapshotUUID = mintedSnapshotUUID; data.snapshotBoundarySHA256.clear();
  data.sourceDurableWatermark = proof.durableWatermark; data.sourceDurableWatermarkSHA256 = proof.durableWatermarkSHA256;
  data.snapshotPreparingEpoch = baseEpoch + 1; data.initialCatchupEpoch = baseEpoch + 2;
  data.sourceFenceEpoch = baseEpoch + 3; data.fencedCatchupEpoch = baseEpoch + 4;
  data.targetOwnershipEpoch = baseEpoch + 5; data.sourceRetainedEpoch = baseEpoch + 6;
  data.shardGroup = challenge.shardGroup; data.nShardGroups = challenge.nShardGroups;
  data.previousOperationUUID = established ? proof.currentAuthority.operationUUID : 0;
  data.previousAuthorityEpoch = established ? proof.currentAuthority.authorityEpoch : 0;
  data.cohort = cohort; data.targetMachineUUIDs = targetMachines; data.credentials = request.credentials;
  data.credentialCount = data.credentials.size(); data.targetDeploymentPlan = request.targetDeploymentPlan;
  String credentials; auto copy = data.credentials;
  if (!BitseryEngine::serialize(credentials, copy) ||
      !prodigyComputeSHA256Hex(credentials, data.credentialManifestSHA256))
    return reject("Nametag preparation cannot hash credential manifest");
  return mothershipProductionPairIntentValid(intent, failure);
}

class MothershipProductionPairRecord {
public:
  static constexpr uint32_t version = 2;
  static constexpr uint32_t statefulVersion = 4;

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
  Vector<MothershipProductionStatefulReceipt> statefulReceipts;
  bool hasStatefulAbortReceipt = false;
  MothershipProductionStatefulReceipt statefulAbortReceipt;
  bool hasPendingStatefulCommand = false;
  MothershipProductionPairPhase pendingStatefulPhase = MothershipProductionPairPhase::prepared;
  bool statefulAbortTargetAdmissionIssued = false;
  String statefulTargetCompensationReceiptSHA256;
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
  if (record.protocolVersion == MothershipProductionPairRecord::statefulVersion) {
    serializer.container(record.statefulReceipts, 6);
    serializer.value1b(record.hasStatefulAbortReceipt);
    if (record.hasStatefulAbortReceipt) serializer.object(record.statefulAbortReceipt);
    serializer.value1b(record.hasPendingStatefulCommand);
    serializer.value1b(record.pendingStatefulPhase);
    serializer.value1b(record.statefulAbortTargetAdmissionIssued);
    serializer.text1b(record.statefulTargetCompensationReceiptSHA256, 64);
  }
}

static inline bool mothershipProductionPairRecordValid(const MothershipProductionPairRecord& record,
                                                        String *failure = nullptr)
{
  if (failure) failure->clear();
  auto reject = [&](const char *reason) { if (failure) failure->assign(reason); return false; };
  const bool stateful = record.intent.protocolVersion == MothershipProductionPairIntent::statefulVersion;
  if (record.protocolVersion != (stateful ? MothershipProductionPairRecord::statefulVersion : MothershipProductionPairRecord::version) ||
      !mothershipProductionPairIntentValid(record.intent) || !mothershipProductionPairPhaseValid(record.phase) ||
      record.transitionGeneration == 0 || record.transitionedAtMs <= 0)
    return reject("production pair record has an invalid immutable intent or transition identity");
  if (stateful) {
    const uint8_t order = mothershipProductionPairPhaseOrder(record.intent, record.phase);
    if (record.hasPendingStatefulCommand &&
        (mothershipProductionPairPhaseOrder(record.intent, record.pendingStatefulPhase) != order + 1 ||
         (mothershipProductionPairPhaseOrder(record.intent, record.pendingStatefulPhase) > 7 &&
          record.pendingStatefulPhase != MothershipProductionPairPhase::sourceCleanupVerified)))
      return reject("stateful desired command is not the exact next durable data gate");
    const bool aborting = record.phase == MothershipProductionPairPhase::statefulAbortBeforeFencePending ||
                          record.phase == MothershipProductionPairPhase::statefulAbortedBeforeFence ||
                          record.phase == MothershipProductionPairPhase::abortedBeforeTransit;
    if ((!aborting && (order == 0 || record.statefulReceipts.size() !=
          (order >= 9 ? 6u : std::min<uint8_t>(order > 2 ? order - 2 : 0, 5)))) ||
        (aborting && record.statefulReceipts.size() > 2))
      return reject("Nametag stateful record has missing, premature or unsupported data gates");
    constexpr MothershipProductionPairPhase phases[] = {
      MothershipProductionPairPhase::snapshotVerified, MothershipProductionPairPhase::catchupVerified,
      MothershipProductionPairPhase::sourceWriterFenced, MothershipProductionPairPhase::fencedCatchupVerified,
      MothershipProductionPairPhase::targetOwnershipActive, MothershipProductionPairPhase::sourceCleanupVerified};
    for (uint32_t index = 0; index < record.statefulReceipts.size(); ++index)
      if (record.statefulReceipts[index].phase != phases[index] ||
          !mothershipProductionStatefulReceiptValid(record.intent, record.statefulReceipts[index]))
        return reject("Nametag stateful record has a stale or contradictory application receipt");
    if (!record.statefulReceipts.empty()) {
      const auto& snapshot = record.statefulReceipts.front().members.front().receipt.snapshotReceiptSHA256;
      String finalWatermark;
      if (record.statefulReceipts.size() >= 3)
        finalWatermark = record.statefulReceipts[2].members.front().receipt.appliedWatermarkSHA256;
      for (uint32_t index = 0; index < record.statefulReceipts.size(); ++index)
        for (const auto& member : record.statefulReceipts[index].members) {
          const auto& receipt = member.receipt;
          if ((index == 0 && receipt.snapshotReceiptSHA256 != snapshot) ||
              (index != 0 && receipt.authority.snapshotBoundarySHA256 != snapshot) ||
              (index == 1 && !prodigyStatefulDataAuthorityReceiptStaged(receipt)) ||
              (index >= 2 && receipt.appliedWatermarkSHA256 != finalWatermark))
            return reject("stateful proof does not preserve the authenticated snapshot and final fenced watermark");
          if (index == 5) {
            const auto& fences = record.statefulReceipts[2].members;
            auto fence = std::find_if(fences.begin(), fences.end(), [&](const auto& value) { return value.containerUUID == member.containerUUID; });
            if (fence == fences.end() || receipt.fenceReceiptSHA256 != fence->receipt.fenceReceiptSHA256)
              return reject("source cleanup must preserve the exact durable source fence receipt");
          }
        }
      if (record.statefulReceipts.size() > 3) {
        const auto& initial = record.statefulReceipts[1].cohort;
        for (uint32_t index : {3u, 4u}) {
          if (index >= record.statefulReceipts.size()) continue;
          const auto& later = record.statefulReceipts[index].cohort;
          for (uint32_t member = 0; member < initial.size(); ++member)
            if (initial[member].containerUUID != later[member].containerUUID || initial[member].machineUUID != later[member].machineUUID ||
                initial[member].shardGroup != later[member].shardGroup)
              return reject("stateful promotion changes the exact admitted target cohort");
        }
      }
    }
    if (aborting && record.phase != MothershipProductionPairPhase::abortedBeforeTransit) {
      if (!mothershipProductionPairReceiptValid(record.targetAdmissionReceiptSHA256) ||
          !mothershipProductionPairReceiptValid(record.cleanupReceiptSHA256) ||
          !record.transitApplyReceiptSHA256.empty() || !record.sourceIngressWitnessReceiptSHA256.empty() ||
          !record.targetSelectionReceiptSHA256.empty() || !record.targetIngressWitnessReceiptSHA256.empty() ||
          !record.sourceDrainReceiptSHA256.empty() || !record.sourceRetirementReceiptSHA256.empty())
        return reject("stateful pre-fence compensation contains traffic or writer-transfer effects");
      const bool terminal = record.phase == MothershipProductionPairPhase::statefulAbortedBeforeFence;
      if ((terminal && (!record.hasStatefulAbortReceipt || !mothershipProductionPairReceiptValid(record.statefulTargetCompensationReceiptSHA256))) ||
          (!record.statefulTargetCompensationReceiptSHA256.empty() && !mothershipProductionPairReceiptValid(record.statefulTargetCompensationReceiptSHA256)) ||
          (record.hasStatefulAbortReceipt && !mothershipProductionStatefulReceiptValid(record.intent, record.statefulAbortReceipt)))
        return reject("stateful abort lacks the authenticated source-retained cleanup receipt");
      if (record.hasStatefulAbortReceipt) {
        if (record.statefulReceipts.empty() || !mothershipProductionPairReceiptValid(record.statefulTargetCompensationReceiptSHA256))
          return reject("source cleanup lacks its recorded transactional snapshot and target compensation");
        const auto& snapshot = record.statefulReceipts.front().members.front().receipt.snapshotReceiptSHA256;
        for (const auto& member : record.statefulAbortReceipt.members)
          if (member.receipt.authority.snapshotBoundarySHA256 != snapshot || member.receipt.snapshotReceiptSHA256 != snapshot)
            return reject("source abort cleanup differs from its authenticated snapshot");
      }
      return true;
    }
    if (record.hasStatefulAbortReceipt || record.statefulAbortTargetAdmissionIssued || !record.statefulTargetCompensationReceiptSHA256.empty())
      return reject("stateful abort receipt is premature");
  } else if (!record.statefulReceipts.empty() || record.phase >= MothershipProductionPairPhase::snapshotVerified)
    return reject("stateless pair cannot contain application data phases");
  if (record.phase == MothershipProductionPairPhase::abortedBeforeTransit)
  {
    // A prepare preflight can fail after the immutable intent is durable but
    // before target admission is recorded.  That prepared coordinator still
    // needs one terminal, retry-safe escape hatch; an empty target receipt
    // distinguishes it from an abort after target admission.
    if ((!record.targetAdmissionReceiptSHA256.empty() &&
         !mothershipProductionPairReceiptValid(record.targetAdmissionReceiptSHA256)) ||
        !record.transitApplyReceiptSHA256.empty() || !record.sourceIngressWitnessReceiptSHA256.empty() ||
        !record.targetSelectionReceiptSHA256.empty() || !record.targetIngressWitnessReceiptSHA256.empty() ||
        !record.sourceDrainReceiptSHA256.empty() || !record.sourceRetirementReceiptSHA256.empty() ||
        !mothershipProductionPairReceiptValid(record.cleanupReceiptSHA256))
      return reject("production pair pre-transit abort has invalid receipts");
    return true;
  }
  if (record.phase == MothershipProductionPairPhase::abortedBeforeCutover)
  {
    if (!mothershipProductionPairReceiptValid(record.targetAdmissionReceiptSHA256) ||
        !mothershipProductionPairReceiptValid(record.transitApplyReceiptSHA256) ||
        !record.sourceIngressWitnessReceiptSHA256.empty() || !record.targetSelectionReceiptSHA256.empty() ||
        !record.targetIngressWitnessReceiptSHA256.empty() || !record.sourceDrainReceiptSHA256.empty() ||
        !record.sourceRetirementReceiptSHA256.empty() ||
        !mothershipProductionPairReceiptValid(record.cleanupReceiptSHA256))
      return reject("production pair pre-cutover abort has invalid receipts");
    return true;
  }
  if (record.phase == MothershipProductionPairPhase::abortBeforeCutoverPending)
  {
    // cleanupReceiptSHA256 is the durable pre-removal receipt only while the
    // abort is pending.  The terminal abort replaces it with the exact
    // completion receipt after the provider reports the selector removed.
    if (!mothershipProductionPairReceiptValid(record.targetAdmissionReceiptSHA256) ||
        !mothershipProductionPairReceiptValid(record.transitApplyReceiptSHA256) ||
        !record.sourceIngressWitnessReceiptSHA256.empty() || !record.targetSelectionReceiptSHA256.empty() ||
        !record.targetIngressWitnessReceiptSHA256.empty() || !record.sourceDrainReceiptSHA256.empty() ||
        !record.sourceRetirementReceiptSHA256.empty() ||
        !mothershipProductionPairReceiptValid(record.cleanupReceiptSHA256))
      return reject("production pair pending pre-cutover abort has invalid receipts");
    return true;
  }
  const auto require = [&](const String& receipt, MothershipProductionPairPhase atLeast) {
    return mothershipProductionPairPhaseOrder(record.intent, record.phase) < mothershipProductionPairPhaseOrder(record.intent, atLeast)
        ? receipt.empty() : mothershipProductionPairReceiptValid(receipt);
  };
  if (stateful) {
    if (!record.transitApplyReceiptSHA256.empty() || !record.sourceIngressWitnessReceiptSHA256.empty() ||
        !record.targetIngressWitnessReceiptSHA256.empty() || !record.sourceDrainReceiptSHA256.empty() ||
        !require(record.targetAdmissionReceiptSHA256, MothershipProductionPairPhase::targetAdmitted) ||
        !require(record.targetSelectionReceiptSHA256, MothershipProductionPairPhase::targetSelected) ||
        !require(record.sourceRetirementReceiptSHA256, MothershipProductionPairPhase::sourceRetired) ||
        !require(record.cleanupReceiptSHA256, MothershipProductionPairPhase::cleanupComplete))
      return reject("stateful pair requires internal COUSIN selection and retirement receipts, never a physical IPv4 selector");
    return true;
  }
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

static inline bool mothershipProductionPairStatefulCommand(const MothershipProductionPairRecord& record,
    MothershipProductionPairPhase phase, StatefulDataAuthorityOperation& command)
{
  command = {};
  if (!mothershipProductionPairRecordValid(record) ||
      record.intent.protocolVersion != MothershipProductionPairIntent::statefulVersion) return false;
  const auto& intent = record.intent; const auto& data = intent.stateful;
  const bool preparing = phase == MothershipProductionPairPhase::snapshotVerified;
  const bool cleanup = phase == MothershipProductionPairPhase::sourceCleanupVerified;
  const bool source = preparing || cleanup || phase == MothershipProductionPairPhase::sourceWriterFenced;
  const bool active = phase == MothershipProductionPairPhase::targetOwnershipActive;
  const bool initialCatchup = phase == MothershipProductionPairPhase::catchupVerified;
  if (!preparing && !source && !active && !initialCatchup && phase != MothershipProductionPairPhase::fencedCatchupVerified) return false;
  if (!preparing && record.statefulReceipts.empty()) return false;
  if ((active || cleanup || phase == MothershipProductionPairPhase::fencedCatchupVerified) && record.statefulReceipts.size() < 3) return false;
  auto& authority = command.authority;
  command.deploymentID = source ? intent.sourceWorkload.deploymentID : intent.targetWorkload.deploymentID;
  auto copy = intent; String bytes; BitseryEngine::serialize(bytes, copy);
  if (!prodigyComputeSHA256Hex(bytes, command.pairIntentSHA256)) return false;
  command.cohort = source ? data.cohort : Vector<ProdigyStatefulServingAuthorityMember>{};
  command.deploymentPlan = source ? String() : data.targetDeploymentPlan;
  authority.operationUUID = intent.operationUUID; authority.previousOperationUUID = data.previousOperationUUID;
  authority.contractVersion = data.contractVersion;
  authority.previousAuthorityEpoch = data.previousAuthorityEpoch;
  authority.datasetUUID = data.datasetUUID; authority.snapshotUUID = data.snapshotUUID;
  authority.sourceClusterUUID = intent.sourceWorkload.clusterUUID; authority.targetClusterUUID = intent.targetWorkload.clusterUUID;
  authority.localClusterUUID = source ? authority.sourceClusterUUID : authority.targetClusterUUID;
  authority.writeOwnerClusterUUID = active || cleanup ? authority.targetClusterUUID : authority.sourceClusterUUID;
  authority.shardGroup = data.shardGroup; authority.nShardGroups = data.nShardGroups;
  authority.contractSHA256 = data.contractSHA256;
  authority.shardManifestSHA256 = data.shardManifestSHA256;
  authority.mode = cleanup ? StatefulDataAuthorityMode::retainedSource : (preparing ? StatefulDataAuthorityMode::snapshotPreparing :
      (source ? StatefulDataAuthorityMode::fenced : (active ? StatefulDataAuthorityMode::writeOwner : StatefulDataAuthorityMode::catchupOnly)));
  authority.authorityEpoch = cleanup ? data.sourceRetainedEpoch : (preparing ? data.snapshotPreparingEpoch : (source ? data.sourceFenceEpoch :
      (initialCatchup ? data.initialCatchupEpoch : (active ? data.targetOwnershipEpoch : data.fencedCatchupEpoch))));
  if (!preparing) authority.snapshotBoundarySHA256 = record.statefulReceipts.front().members.front().receipt.snapshotReceiptSHA256;
  if (!source || cleanup) authority.requiredAppliedWatermarkSHA256 = initialCatchup ? authority.snapshotBoundarySHA256 :
      record.statefulReceipts[2].members.front().receipt.appliedWatermarkSHA256;
  if (active || cleanup) {
    auto fence = record.statefulReceipts[2]; String encoded; BitseryEngine::serialize(encoded, fence);
    if (!prodigyComputeSHA256Hex(encoded, command.sourceFenceReceiptSHA256)) return false;
  }
  return prodigyStatefulDataAuthorityValid(authority);
}

static inline bool mothershipProductionPairApplyStatefulReceipt(MothershipProductionPairRecord& record,
    const MothershipProductionStatefulReceipt& proof, int64_t nowMs, String *failure = nullptr)
{
  if (failure) failure->clear();
  auto reject = [&](const char *reason) { if (failure) failure->assign(reason); return false; };
  if (!mothershipProductionPairRecordValid(record) || nowMs < record.transitionedAtMs ||
      !mothershipProductionStatefulReceiptValid(record.intent, proof))
    return reject("stateful pair proof does not bind the exact admitted application authority");
  if (record.phase == proof.phase) {
    String expected, observed;
    auto saved = record.statefulReceipts.back(), incoming = proof;
    BitseryEngine::serialize(expected, saved); BitseryEngine::serialize(observed, incoming);
    return expected == observed || reject("stateful pair replay changed its durable owner receipt");
  }
  if (mothershipProductionPairPhaseOrder(record.intent, proof.phase) !=
      mothershipProductionPairPhaseOrder(record.intent, record.phase) + 1)
    return reject("stateful pair requires snapshot, catchup, source fence, then target ownership in order");
  // Snapshot identity is immutable across catchup and activation. Authority
  // observations may advance after election, but an older same-master receipt
  // cannot supersede the admitted application proof.
  for (const auto& previous : record.statefulReceipts) {
    if (previous.observedMasterUUID == proof.observedMasterUUID &&
        previous.observedMasterBootNs == proof.observedMasterBootNs &&
        previous.observedAuthorityGeneration > proof.observedAuthorityGeneration)
      return reject("stateful pair proof rolls back the observed authority generation");
    for (const auto& member : proof.members) for (const auto& saved : previous.members)
      if (member.containerUUID == saved.containerUUID &&
          member.receipt.snapshotReceiptSHA256 != saved.receipt.snapshotReceiptSHA256)
        return reject("stateful pair proof changes the admitted snapshot receipt");
  }
  auto updated = record;
  updated.statefulReceipts.push_back(proof);
  updated.hasPendingStatefulCommand = false;
  updated.pendingStatefulPhase = MothershipProductionPairPhase::prepared;
  updated.phase = proof.phase;
  ++updated.transitionGeneration;
  updated.transitionedAtMs = nowMs;
  if (!mothershipProductionPairRecordValid(updated, failure)) return false;
  record = std::move(updated);
  return true;
}

static inline bool mothershipProductionPairAbortStatefulBeforeFence(MothershipProductionPairRecord& record,
    const String& receiptSHA256, int64_t nowMs, bool completed, String *failure = nullptr,
    const MothershipProductionStatefulReceipt *sourceCleanup = nullptr,
    const String *targetCompensationReceiptSHA256 = nullptr)
{
  if (failure) failure->clear();
  const auto requested = completed ? MothershipProductionPairPhase::statefulAbortedBeforeFence :
                                    MothershipProductionPairPhase::statefulAbortBeforeFencePending;
  if (!mothershipProductionPairRecordValid(record) ||
      record.intent.protocolVersion != MothershipProductionPairIntent::statefulVersion ||
      !mothershipProductionPairReceiptValid(receiptSHA256) || nowMs < record.transitionedAtMs) return false;
  if (record.hasPendingStatefulCommand &&
      mothershipProductionPairPhaseOrder(record.intent, record.pendingStatefulPhase) >= 5) {
    if (failure) failure->assign("source fence command may already be durable; pre-fence compensation is forbidden"_ctv);
    return false;
  }
  if (record.phase == requested) {
    if (record.cleanupReceiptSHA256 != receiptSHA256) return false;
    if (!completed) return true;
    if (!sourceCleanup || !targetCompensationReceiptSHA256 ||
        record.statefulTargetCompensationReceiptSHA256 != *targetCompensationReceiptSHA256) return false;
    auto saved = record.statefulAbortReceipt, incoming = *sourceCleanup;
    String savedBytes, incomingBytes;
    BitseryEngine::serialize(savedBytes, saved); BitseryEngine::serialize(incomingBytes, incoming);
    return savedBytes == incomingBytes;
  }
  if (completed ? record.phase != MothershipProductionPairPhase::statefulAbortBeforeFencePending :
      (record.phase != MothershipProductionPairPhase::targetAdmitted &&
       record.phase != MothershipProductionPairPhase::snapshotVerified &&
       record.phase != MothershipProductionPairPhase::catchupVerified)) {
    if (failure) failure->assign("stateful compensation is allowed only before the source writer fence"_ctv);
    return false;
  }
  auto updated = record;
  if (!completed) updated.statefulAbortTargetAdmissionIssued =
      record.phase == MothershipProductionPairPhase::catchupVerified ||
      (record.hasPendingStatefulCommand && record.pendingStatefulPhase == MothershipProductionPairPhase::catchupVerified);
  updated.hasPendingStatefulCommand = false;
  updated.pendingStatefulPhase = MothershipProductionPairPhase::prepared;
  if (completed) {
    if (!sourceCleanup || sourceCleanup->phase != MothershipProductionPairPhase::statefulAbortedBeforeFence ||
        !mothershipProductionStatefulReceiptValid(record.intent, *sourceCleanup) ||
        !record.hasStatefulAbortReceipt || !targetCompensationReceiptSHA256 ||
        record.statefulTargetCompensationReceiptSHA256 != *targetCompensationReceiptSHA256 ||
        !mothershipProductionPairReceiptValid(*targetCompensationReceiptSHA256)) return false;
    String savedBytes, incomingBytes;
    auto saved = record.statefulAbortReceipt, incoming = *sourceCleanup;
    BitseryEngine::serialize(savedBytes, saved); BitseryEngine::serialize(incomingBytes, incoming);
    if (savedBytes != incomingBytes) return false;
    updated.hasStatefulAbortReceipt = true;
    updated.statefulAbortReceipt = *sourceCleanup;
    updated.statefulTargetCompensationReceiptSHA256 = *targetCompensationReceiptSHA256;
  }
  updated.phase = requested;
  updated.cleanupReceiptSHA256 = receiptSHA256;
  updated.transitionedAtMs = nowMs;
  ++updated.transitionGeneration;
  if (!mothershipProductionPairRecordValid(updated, failure)) return false;
  record = std::move(updated);
  return true;
}

// Abort evidence is checkpointed before the next effect. A lost cleanup reply
// can therefore resume without re-opening a snapshot or accepting caller proof.
static inline bool mothershipProductionPairObserveStatefulAbort(MothershipProductionPairRecord& record,
    const MothershipProductionStatefulReceipt& proof, int64_t nowMs, String *failure = nullptr)
{
  if (!mothershipProductionPairRecordValid(record) ||
      record.phase != MothershipProductionPairPhase::statefulAbortBeforeFencePending || nowMs < record.transitionedAtMs ||
      !mothershipProductionStatefulReceiptValid(record.intent, proof)) return false;
  auto updated = record;
  MothershipProductionStatefulReceipt *existing = nullptr;
  if (proof.phase == MothershipProductionPairPhase::snapshotVerified) {
    if (updated.statefulReceipts.empty()) updated.statefulReceipts.push_back(proof);
    else existing = &updated.statefulReceipts.front();
  } else if (proof.phase == MothershipProductionPairPhase::statefulAbortedBeforeFence) {
    if (!mothershipProductionPairReceiptValid(record.statefulTargetCompensationReceiptSHA256)) return false;
    if (updated.hasStatefulAbortReceipt) existing = &updated.statefulAbortReceipt;
    else { updated.hasStatefulAbortReceipt = true; updated.statefulAbortReceipt = proof; }
  } else return false;
  if (existing) {
    String a, b; auto copy = proof;
    BitseryEngine::serialize(a, *existing); BitseryEngine::serialize(b, copy);
    return a == b;
  }
  ++updated.transitionGeneration; updated.transitionedAtMs = nowMs;
  if (!mothershipProductionPairRecordValid(updated, failure)) return false;
  record = std::move(updated); return true;
}

static inline bool mothershipProductionPairObserveStatefulTargetCompensation(MothershipProductionPairRecord& record,
    const String& receiptSHA256, int64_t nowMs, String *failure = nullptr)
{
  if (!mothershipProductionPairRecordValid(record) ||
      record.phase != MothershipProductionPairPhase::statefulAbortBeforeFencePending ||
      record.statefulReceipts.empty() || !mothershipProductionPairReceiptValid(receiptSHA256) || nowMs < record.transitionedAtMs) return false;
  if (!record.statefulTargetCompensationReceiptSHA256.empty()) return record.statefulTargetCompensationReceiptSHA256 == receiptSHA256;
  auto updated = record; updated.statefulTargetCompensationReceiptSHA256 = receiptSHA256;
  ++updated.transitionGeneration; updated.transitionedAtMs = nowMs;
  if (!mothershipProductionPairRecordValid(updated, failure)) return false;
  record = std::move(updated); return true;
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
  if (intent.protocolVersion == MothershipProductionPairIntent::statefulVersion)
    record.protocolVersion = MothershipProductionPairRecord::statefulVersion;
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
    case MothershipProductionPairPhase::abortedBeforeCutover: return &record.cleanupReceiptSHA256;
    case MothershipProductionPairPhase::abortBeforeCutoverPending: return &record.cleanupReceiptSHA256;
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
  const uint8_t current = mothershipProductionPairPhaseOrder(record.intent, record.phase);
  const uint8_t requested = mothershipProductionPairPhaseOrder(record.intent, next);
  if (next == MothershipProductionPairPhase::transitApplied ||
      next == MothershipProductionPairPhase::abortedBeforeTransit ||
      next == MothershipProductionPairPhase::abortedBeforeCutover ||
      next == MothershipProductionPairPhase::abortBeforeCutoverPending || requested < current || requested > current + 1) {
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
  if (record.phase != MothershipProductionPairPhase::prepared &&
      record.phase != MothershipProductionPairPhase::targetAdmitted)
  { if (failure) failure->assign("production pair abort requires a prepared pre-transit phase"); return false; }
  record.cleanupReceiptSHA256 = receiptSHA256;
  record.phase = MothershipProductionPairPhase::abortedBeforeTransit;
  ++record.transitionGeneration;
  record.transitionedAtMs = nowMs;
  return mothershipProductionPairRecordValid(record, failure);
}

// This write-ahead transition records the exact zero-flow observation before
// the external provider is asked to remove the selector.  It closes the crash
// window where provider removal succeeds but the terminal registry write does
// not.  cleanupReceiptSHA256 carries the pre-removal receipt until terminal
// completion replaces it.
static inline bool mothershipProductionPairPrepareAbortBeforeCutover(MothershipProductionPairRecord& record,
                                                                      const String& receiptSHA256, int64_t nowMs,
                                                                      String *failure = nullptr)
{
  if (failure) failure->clear();
  if (!mothershipProductionPairRecordValid(record) || nowMs < record.transitionedAtMs ||
      !mothershipProductionPairReceiptValid(receiptSHA256))
  { if (failure) failure->assign("production pair pre-cutover abort preparation has invalid record, receipt, or timestamp"); return false; }
  if (record.phase == MothershipProductionPairPhase::abortBeforeCutoverPending)
  {
    if (record.cleanupReceiptSHA256 == receiptSHA256) return true;
    if (failure) failure->assign("production pair pending pre-cutover abort retry receipt conflicts with durable receipt");
    return false;
  }
  if (record.phase != MothershipProductionPairPhase::transitApplied)
  { if (failure) failure->assign("production pair pre-cutover abort preparation requires an unwitnessed transit phase"); return false; }
  record.cleanupReceiptSHA256 = receiptSHA256;
  record.phase = MothershipProductionPairPhase::abortBeforeCutoverPending;
  ++record.transitionGeneration;
  record.transitionedAtMs = nowMs;
  return mothershipProductionPairRecordValid(record, failure);
}

// This is deliberately distinct from the pre-transit branch.  It is allowed
// only after the pre-removal observation is durable and before any
// ingress/cutover evidence can authorize traffic selection.
static inline bool mothershipProductionPairAbortBeforeCutover(MothershipProductionPairRecord& record,
                                                               const String& receiptSHA256, int64_t nowMs,
                                                               String *failure = nullptr)
{
  if (failure) failure->clear();
  if (!mothershipProductionPairRecordValid(record) || nowMs < record.transitionedAtMs ||
      !mothershipProductionPairReceiptValid(receiptSHA256))
  { if (failure) failure->assign("production pair pre-cutover abort has invalid record, receipt, or timestamp"); return false; }
  if (record.phase == MothershipProductionPairPhase::abortedBeforeCutover)
  {
    if (record.cleanupReceiptSHA256 == receiptSHA256) return true;
    if (failure) failure->assign("production pair pre-cutover abort retry receipt conflicts with durable receipt");
    return false;
  }
  if (record.phase != MothershipProductionPairPhase::abortBeforeCutoverPending)
  { if (failure) failure->assign("production pair pre-cutover abort requires a durable pending abort"); return false; }
  record.cleanupReceiptSHA256 = receiptSHA256;
  record.phase = MothershipProductionPairPhase::abortedBeforeCutover;
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
  if (record.intent.protocolVersion == MothershipProductionPairIntent::statefulVersion ||
      !mothershipProductionPairRecordValid(record) || nowMs < record.transitionedAtMs ||
      !mothershipProductionPairReceiptValid(receiptSHA256)) {
    if (failure) failure->assign("production pair transit requires the durably admitted target");
    return false;
  }
  if (record.phase == MothershipProductionPairPhase::transitApplied) {
    if (record.transitApplyReceiptSHA256 == receiptSHA256) return true;
    if (failure) failure->assign("production pair transit retry receipt conflicts with durable receipt");
    return false;
  }
  const auto expected = record.intent.protocolVersion == MothershipProductionPairIntent::statefulVersion
      ? MothershipProductionPairPhase::targetOwnershipActive : MothershipProductionPairPhase::targetAdmitted;
  if (record.phase != expected) {
    if (failure) failure->assign("production pair transit requires the durably admitted target");
    return false;
  }
  record.transitApplyReceiptSHA256 = receiptSHA256;
  record.phase = MothershipProductionPairPhase::transitApplied;
  ++record.transitionGeneration;
  record.transitionedAtMs = nowMs;
  return mothershipProductionPairRecordValid(record, failure);
}
