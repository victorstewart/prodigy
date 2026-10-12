#pragma once

#include <array>
#include <cstdint>

#include <networking/includes.h>
#include <services/bitsery.h>
#include <networking/ip.h>
#include <services/prodigy.h>

#include <prodigy/cousin.service.permission.h>
#include <prodigy/sha256.digest.h>

constexpr static int64_t cousinRouteMaximumLifetimeMs = 24LL * 60 * 60 * 1000;
// A route UUID admits at most this many distinct operation identities over its
// lifetime. After the cap, an operator must allocate a new route UUID.
constexpr static uint32_t cousinRouteMaximumOperationGenerations = 64;
constexpr static uint32_t cousinRouteMaximumPriorOperationUUIDs = cousinRouteMaximumOperationGenerations - 1;
constexpr static uint32_t cousinRouteMinimumPathMTU = 1280;
constexpr static uint32_t cousinRouteMaximumPathMTU = 65535;

enum class CousinRouteState : uint8_t {
  active = 1,
  draining = 2,
  withdrawn = 3,
  revoked = 4
};

// This is routing authorization only. logicalWorkloadUUID identifies the
// operator-approved routing domain; it is deliberately not application data
// lineage, a durability assertion, or a writer-fencing token.
class CousinRouteRecord {
public:
  // Version one did not bind the route to the exact local permissions or a
  // concrete network profile.  It remains decodable for retained records, but
  // new admissions must use this current, fail-closed version-two contract.
  uint32_t version = 2;
  uint128_t routeUUID = 0;
  uint128_t operationUUID = 0;
  // The registry owns this bounded, sorted anti-reuse history. It is excluded
  // from caller authorization and exact retry identity.
  Vector<uint128_t> priorOperationUUIDs;
  uint128_t pairUUID = 0;
  uint128_t logicalWorkloadUUID = 0;
  uint128_t logicalServiceUUID = 0;

  uint128_t sourceClusterUUID = 0;
  uint16_t sourceApplicationID = 0;
  uint64_t sourceCousinServicePrefix = 0;
  uint128_t destinationClusterUUID = 0;
  uint16_t destinationApplicationID = 0;
  uint64_t destinationCousinServicePrefix = 0;
  CousinRouteSlotBitmap slots;

  uint128_t destinationRoutablePrefixUUID = 0;
  IPAddress destinationPublicAddress;
  uint16_t destinationTCPPort = 0;

  uint128_t sourcePermissionUUID = 0;
  uint128_t destinationPermissionUUID = 0;
  uint8_t transportProtocol = 0;
  // Prefix length of the registered destination range.  The range network is
  // resolved by its UUID; callers must use cousinRouteDestinationRangeContains
  // to bind that authoritative range before installing the route.
  uint8_t destinationCIDR = 0;
  uint16_t pathMTU = 0;

  uint64_t generation = 0;
  int64_t issuedAtMs = 0;
  int64_t expiresAtMs = 0;
  uint64_t keyEpoch = 0;
  uint64_t rootGeneration = 0;
  CousinRouteState state = CousinRouteState::active;
  uint64_t withdrawalGeneration = 0;
  int64_t withdrawnAtMs = 0;
};

// This is an authenticated runtime assertion supplied to Mothership. It has
// no secret material and does not participate in route authorization bytes.
class CousinRouteApplyReceipt {
public:
  uint32_t version = 1;
  uint128_t routeUUID = 0;
  uint64_t generation = 0;
  String authorizationSHA256;
  uint128_t localClusterUUID = 0;
  CousinRouteHalf localHalf = CousinRouteHalf::source;
  uint64_t keyEpoch = 0;
  uint64_t localRuntimeRevision = 0;
  CousinRouteState installedState = CousinRouteState::active;
};

// Brain's half-specific durable route contract.  Mothership supplies the
// expected current authority identity and exact v2 route; a Brain persists
// only its own half and returns the receipt it minted for that copy.
class ProdigyCousinRouteRequest {
public:
  static constexpr uint32_t version = 1;

  uint32_t protocolVersion = version;
  uint64_t expectedAuthorityGeneration = 0;
  uint128_t expectedMasterUUID = 0;
  int64_t expectedMasterBootNs = 0;
  CousinRouteHalf localHalf = CousinRouteHalf::source;
  CousinRouteRecord route = {};
};

class ProdigyCousinRouteQuery {
public:
  static constexpr uint32_t version = 1;

  uint32_t protocolVersion = version;
  uint128_t routeUUID = 0;
};

class ProdigyCousinRouteResponse {
public:
  static constexpr uint32_t version = 1;

  uint32_t protocolVersion = version;
  bool success = false;
  bool found = false;
  bool qualified = false;
  uint128_t localClusterUUID = 0;
  uint64_t currentAuthorityGeneration = 0;
  uint128_t currentMasterUUID = 0;
  int64_t currentMasterBootNs = 0;
  CousinRouteRecord route = {};
  CousinRouteApplyReceipt applyReceipt = {};
  String failure = {};
};

static inline bool cousinRouteAuthorizationDigest(const CousinRouteRecord& route, String& digest);
static inline bool cousinRouteAllowsNewAdmissionAt(const CousinRouteRecord& route, int64_t nowMs);
static inline bool cousinRouteStructurallyValid(const CousinRouteRecord& route);
static inline bool cousinRouteCurrentContract(const CousinRouteRecord& route);
static inline bool cousinRouteApplyReceiptStructurallyValid(const CousinRouteApplyReceipt& receipt);
static inline bool cousinRouteApplyReceiptMatchesCurrentRoute(const CousinRouteApplyReceipt& receipt,
                                                              const CousinRouteRecord& route);
static inline bool cousinRouteKeyEpochTransitionValid(const CousinRouteRecord& prior,
                                                       const CousinRouteRecord& next);

template <typename S>
static void serialize(S&& serializer, CousinRouteRecord& route)
{
  serializer.value4b(route.version);
  serializer.value16b(route.routeUUID);
  serializer.value16b(route.operationUUID);
  serializer.container(route.priorOperationUUIDs, cousinRouteMaximumPriorOperationUUIDs,
      [](auto& nested, uint128_t& operationUUID) { nested.value16b(operationUUID); });
  serializer.value16b(route.pairUUID);
  serializer.value16b(route.logicalWorkloadUUID);
  serializer.value16b(route.logicalServiceUUID);
  serializer.value16b(route.sourceClusterUUID);
  serializer.value2b(route.sourceApplicationID);
  serializer.value8b(route.sourceCousinServicePrefix);
  serializer.value16b(route.destinationClusterUUID);
  serializer.value2b(route.destinationApplicationID);
  serializer.value8b(route.destinationCousinServicePrefix);
  serializer.object(route.slots);
  serializer.value16b(route.destinationRoutablePrefixUUID);
  serializer.object(route.destinationPublicAddress);
  serializer.value2b(route.destinationTCPPort);
  if (route.version >= 2)
  {
    serializer.value16b(route.sourcePermissionUUID);
    serializer.value16b(route.destinationPermissionUUID);
    serializer.value1b(route.transportProtocol);
    serializer.value1b(route.destinationCIDR);
    serializer.value2b(route.pathMTU);
  }
  serializer.value8b(route.generation);
  serializer.value8b(route.issuedAtMs);
  serializer.value8b(route.expiresAtMs);
  serializer.value8b(route.keyEpoch);
  serializer.value8b(route.rootGeneration);
  serializer.value1b(route.state);
  serializer.value8b(route.withdrawalGeneration);
  serializer.value8b(route.withdrawnAtMs);
}

template <typename S>
static void serialize(S&& serializer, CousinRouteApplyReceipt& receipt)
{
  serializer.value4b(receipt.version);
  serializer.value16b(receipt.routeUUID);
  serializer.value8b(receipt.generation);
  serializer.text1b(receipt.authorizationSHA256, 64);
  serializer.value16b(receipt.localClusterUUID);
  serializer.value1b(receipt.localHalf);
  serializer.value8b(receipt.keyEpoch);
  serializer.value8b(receipt.localRuntimeRevision);
  serializer.value1b(receipt.installedState);
}

template <typename S>
static void serialize(S&& serializer, ProdigyCousinRouteRequest& request)
{
  serializer.value4b(request.protocolVersion);
  serializer.value8b(request.expectedAuthorityGeneration);
  serializer.value16b(request.expectedMasterUUID);
  serializer.value8b(request.expectedMasterBootNs);
  serializer.value1b(request.localHalf);
  serializer.object(request.route);
}

template <typename S>
static void serialize(S&& serializer, ProdigyCousinRouteQuery& query)
{
  serializer.value4b(query.protocolVersion);
  serializer.value16b(query.routeUUID);
}

template <typename S>
static void serialize(S&& serializer, ProdigyCousinRouteResponse& response)
{
  serializer.value4b(response.protocolVersion);
  serializer.value1b(response.success);
  serializer.value1b(response.found);
  serializer.value1b(response.qualified);
  serializer.value16b(response.localClusterUUID);
  serializer.value8b(response.currentAuthorityGeneration);
  serializer.value16b(response.currentMasterUUID);
  serializer.value8b(response.currentMasterBootNs);
  serializer.object(response.route);
  serializer.object(response.applyReceipt);
  serializer.text1b(response.failure, 4096);
}

static inline bool cousinRouteStateValid(CousinRouteState state)
{
  return state == CousinRouteState::active || state == CousinRouteState::draining ||
         state == CousinRouteState::withdrawn || state == CousinRouteState::revoked;
}

static inline bool cousinRouteTerminal(const CousinRouteRecord& route)
{
  return route.state == CousinRouteState::withdrawn || route.state == CousinRouteState::revoked;
}

static inline bool cousinRouteCurrentContract(const CousinRouteRecord& route)
{
  return route.version == 2;
}

static inline bool cousinRouteDestinationRangeContainsAddress(const CousinRouteRecord& route,
                                                               const IPPrefix& registeredRange)
{
  return registeredRange.network.is6 && registeredRange.cidr == route.destinationCIDR &&
         registeredRange.equals(registeredRange.canonicalized()) &&
         registeredRange.containsAddress(route.destinationPublicAddress);
}

static inline bool cousinRouteStructurallyValid(const CousinRouteRecord& route)
{
  if ((route.version != 1 && route.version != 2) || route.routeUUID == 0 || route.operationUUID == 0 || route.pairUUID == 0 || route.logicalWorkloadUUID == 0 || route.logicalServiceUUID == 0 ||
      route.sourceClusterUUID == 0 || route.destinationClusterUUID == 0 || route.sourceClusterUUID == route.destinationClusterUUID ||
      route.sourceApplicationID == 0 || route.destinationApplicationID == 0 ||
      !MeshServices::isPrefix(route.sourceCousinServicePrefix) || !MeshServices::isPrefix(route.destinationCousinServicePrefix) ||
      cousinRouteServiceApplicationID(route.sourceCousinServicePrefix) != route.sourceApplicationID ||
      cousinRouteServiceApplicationID(route.destinationCousinServicePrefix) != route.destinationApplicationID ||
      route.slots.empty() || route.destinationRoutablePrefixUUID == 0 || route.destinationPublicAddress.is6 == false ||
      route.destinationPublicAddress.isNull() || route.destinationTCPPort == 0 || route.generation == 0 ||
      route.issuedAtMs <= 0 || route.expiresAtMs <= route.issuedAtMs ||
      route.expiresAtMs - route.issuedAtMs > cousinRouteMaximumLifetimeMs || route.keyEpoch == 0 ||
      route.rootGeneration == 0 || !cousinRouteStateValid(route.state))
  {
    return false;
  }
  if (cousinRouteCurrentContract(route) &&
      (route.sourcePermissionUUID == 0 || route.destinationPermissionUUID == 0 ||
       route.transportProtocol != IPPROTO_TCP || route.destinationCIDR == 0 || route.destinationCIDR > 128 ||
       route.pathMTU < cousinRouteMinimumPathMTU || route.pathMTU > cousinRouteMaximumPathMTU)) return false;
  if (route.priorOperationUUIDs.size() > cousinRouteMaximumPriorOperationUUIDs) return false;
  for (uint32_t index = 0; index < route.priorOperationUUIDs.size(); ++index)
  {
    if (route.priorOperationUUIDs[index] == 0 || route.priorOperationUUIDs[index] == route.operationUUID) return false;
    if (index != 0 && route.priorOperationUUIDs[index - 1] >= route.priorOperationUUIDs[index]) return false;
  }
  if (cousinRouteTerminal(route))
  {
    // First profile has no deferred withdrawal floor: the terminal marker
    // applies to this generation exactly.
    return route.withdrawalGeneration == route.generation && route.withdrawnAtMs >= route.issuedAtMs;
  }
  return route.withdrawalGeneration == 0 && route.withdrawnAtMs == 0;
}

static inline bool cousinRouteOperationUUIDWasUsed(const CousinRouteRecord& route, uint128_t operationUUID)
{
  if (operationUUID == 0) return false;
  if (route.operationUUID == operationUUID) return true;
  for (uint128_t prior : route.priorOperationUUIDs)
    if (prior == operationUUID) return true;
  return false;
}

static inline bool cousinRouteRememberPriorOperationUUID(CousinRouteRecord& route, uint128_t operationUUID)
{
  if (operationUUID == 0 || operationUUID == route.operationUUID ||
      route.priorOperationUUIDs.size() >= cousinRouteMaximumPriorOperationUUIDs)
  {
    return false;
  }
  uint32_t position = 0;
  while (position < route.priorOperationUUIDs.size() && route.priorOperationUUIDs[position] < operationUUID) ++position;
  if (position < route.priorOperationUUIDs.size() && route.priorOperationUUIDs[position] == operationUUID) return false;
  route.priorOperationUUIDs.insert(route.priorOperationUUIDs.begin() + position, operationUUID);
  return true;
}

static inline bool cousinRouteApplyReceiptStructurallyValid(const CousinRouteApplyReceipt& receipt)
{
  return receipt.version == 1 && receipt.routeUUID != 0 && receipt.generation != 0 &&
         prodigyIsSHA256HexDigest(receipt.authorizationSHA256) && receipt.localClusterUUID != 0 &&
         cousinRouteHalfValid(receipt.localHalf) && receipt.keyEpoch != 0 &&
         receipt.localRuntimeRevision != 0 && cousinRouteStateValid(receipt.installedState);
}

static inline bool prodigyCousinRouteRequestValid(const ProdigyCousinRouteRequest& request)
{
  if (request.protocolVersion != ProdigyCousinRouteRequest::version || request.expectedAuthorityGeneration == 0 ||
      request.expectedMasterUUID == 0 || request.expectedMasterBootNs <= 0 || !cousinRouteHalfValid(request.localHalf) ||
      !cousinRouteStructurallyValid(request.route) || !cousinRouteCurrentContract(request.route)) return false;
  return request.localHalf == CousinRouteHalf::source ? request.route.sourceClusterUUID != 0 :
                                                        request.route.destinationClusterUUID != 0;
}

static inline bool prodigyCousinRouteQueryValid(const ProdigyCousinRouteQuery& query)
{
  return query.protocolVersion == ProdigyCousinRouteQuery::version && query.routeUUID != 0;
}

static inline bool prodigyCousinRouteResponseValid(const ProdigyCousinRouteResponse& response)
{
  if (response.protocolVersion != ProdigyCousinRouteResponse::version || response.localClusterUUID == 0 ||
      response.currentAuthorityGeneration == 0 || response.currentMasterUUID == 0 || response.currentMasterBootNs <= 0) return false;
  if (!response.success) return !response.found && !response.qualified && response.failure.empty() == false;
  if (!response.found) return !response.qualified && response.failure.empty();
  if (!cousinRouteStructurallyValid(response.route) || !cousinRouteCurrentContract(response.route) ||
      !cousinRouteApplyReceiptStructurallyValid(response.applyReceipt) ||
      !cousinRouteApplyReceiptMatchesCurrentRoute(response.applyReceipt, response.route)) return false;
  const uint128_t expectedCluster = response.applyReceipt.localHalf == CousinRouteHalf::source ?
      response.route.sourceClusterUUID : response.route.destinationClusterUUID;
  if (response.localClusterUUID != expectedCluster) return false;
  return response.qualified ? response.failure.empty() : true;
}

static inline bool cousinRouteApplyReceiptMatchesCurrentRoute(const CousinRouteApplyReceipt& receipt,
                                                              const CousinRouteRecord& route)
{
  String authorizationSHA256 = {};
  if (!cousinRouteApplyReceiptStructurallyValid(receipt) || !cousinRouteAuthorizationDigest(route, authorizationSHA256) ||
      receipt.routeUUID != route.routeUUID || receipt.generation != route.generation ||
      receipt.authorizationSHA256 != authorizationSHA256 || receipt.keyEpoch != route.keyEpoch ||
      receipt.installedState != route.state)
  {
    return false;
  }
  return receipt.localHalf == CousinRouteHalf::source ? receipt.localClusterUUID == route.sourceClusterUUID :
                                                        receipt.localClusterUUID == route.destinationClusterUUID;
}

static inline bool cousinRouteApplyReceiptExactMatches(const CousinRouteApplyReceipt& lhs,
                                                       const CousinRouteApplyReceipt& rhs)
{
  String left = {}, right = {};
  CousinRouteApplyReceipt leftCopy = lhs, rightCopy = rhs;
  BitseryEngine::serialize(left, leftCopy);
  BitseryEngine::serialize(right, rightCopy);
  return left == right;
}

// Persisted receipts show only that both halves previously acknowledged this
// generation. They do not prove either runtime remains live after a restart or
// failure; a later authenticated runtime observation owns that claim.
static inline bool cousinRouteReceiptsAcknowledgedAt(const CousinRouteRecord& route,
                                                     const CousinRouteApplyReceipt& source,
                                                     const CousinRouteApplyReceipt& destination,
                                                     int64_t nowMs)
{
  return cousinRouteAllowsNewAdmissionAt(route, nowMs) && source.localHalf == CousinRouteHalf::source &&
         destination.localHalf == CousinRouteHalf::destination &&
         cousinRouteApplyReceiptMatchesCurrentRoute(source, route) &&
         cousinRouteApplyReceiptMatchesCurrentRoute(destination, route);
}

static inline bool cousinRouteKeyEpochTransitionValid(const CousinRouteRecord& prior, const CousinRouteRecord& next)
{
  if (next.keyEpoch < prior.keyEpoch || next.rootGeneration < prior.rootGeneration) return false;
  return next.rootGeneration == prior.rootGeneration || next.keyEpoch > prior.keyEpoch;
}

static inline bool cousinRouteScopeMatches(const CousinRouteRecord& lhs, const CousinRouteRecord& rhs)
{
  return lhs.routeUUID == rhs.routeUUID && lhs.pairUUID == rhs.pairUUID &&
         lhs.logicalWorkloadUUID == rhs.logicalWorkloadUUID && lhs.logicalServiceUUID == rhs.logicalServiceUUID &&
         lhs.sourceClusterUUID == rhs.sourceClusterUUID && lhs.sourceApplicationID == rhs.sourceApplicationID &&
         lhs.sourceCousinServicePrefix == rhs.sourceCousinServicePrefix &&
         lhs.destinationClusterUUID == rhs.destinationClusterUUID && lhs.destinationApplicationID == rhs.destinationApplicationID &&
         lhs.destinationCousinServicePrefix == rhs.destinationCousinServicePrefix && lhs.slots == rhs.slots &&
         lhs.destinationRoutablePrefixUUID == rhs.destinationRoutablePrefixUUID &&
         lhs.version == rhs.version && lhs.sourcePermissionUUID == rhs.sourcePermissionUUID &&
         lhs.destinationPermissionUUID == rhs.destinationPermissionUUID &&
         lhs.transportProtocol == rhs.transportProtocol && lhs.destinationCIDR == rhs.destinationCIDR &&
         lhs.pathMTU == rhs.pathMTU;
}

// Two independently named routes may share a pair and workload, but they may
// not describe the same permission-bound peer/range.  This is deliberately
// narrower than routeUUID scope: different peers or non-overlapping ranges
// remain representable as separate records without an ambiguous duplicate.
static inline bool cousinRoutePeerRangeScopeMatches(const CousinRouteRecord& lhs, const CousinRouteRecord& rhs)
{
  return lhs.pairUUID == rhs.pairUUID && lhs.logicalWorkloadUUID == rhs.logicalWorkloadUUID &&
         lhs.logicalServiceUUID == rhs.logicalServiceUUID &&
         lhs.sourceClusterUUID == rhs.sourceClusterUUID && lhs.destinationClusterUUID == rhs.destinationClusterUUID &&
         lhs.sourcePermissionUUID == rhs.sourcePermissionUUID && lhs.destinationPermissionUUID == rhs.destinationPermissionUUID &&
         lhs.sourceCousinServicePrefix == rhs.sourceCousinServicePrefix &&
         lhs.destinationCousinServicePrefix == rhs.destinationCousinServicePrefix && lhs.slots == rhs.slots &&
         lhs.destinationRoutablePrefixUUID == rhs.destinationRoutablePrefixUUID &&
         lhs.transportProtocol == rhs.transportProtocol && lhs.destinationCIDR == rhs.destinationCIDR &&
         lhs.destinationPublicAddress.equals(rhs.destinationPublicAddress) && lhs.destinationTCPPort == rhs.destinationTCPPort;
}

// Shared by Mothership's registry and Brain's durable-half owner.  Neither may
// revive a terminal record, regress the exact authorization scope, or reuse a
// key epoch after advancing the pair-root generation.
static inline bool cousinRouteTransitionAllowed(const CousinRouteRecord& prior, const CousinRouteRecord& next)
{
  if (!cousinRouteStructurallyValid(prior) || !cousinRouteStructurallyValid(next) ||
      prior.routeUUID != next.routeUUID || next.generation <= prior.generation ||
      !cousinRouteScopeMatches(prior, next) || cousinRouteTerminal(prior) ||
      !cousinRouteKeyEpochTransitionValid(prior, next)) return false;
  if (cousinRouteTerminal(next)) return true;
  return !(prior.state == CousinRouteState::draining && next.state == CousinRouteState::active);
}

static inline bool cousinRouteExactMatches(const CousinRouteRecord& lhs, const CousinRouteRecord& rhs)
{
  String left = {}, right = {};
  CousinRouteRecord leftCopy = lhs, rightCopy = rhs;
  // The registry appends prior operation IDs after accepting an update. They
  // are anti-reuse metadata, not part of a caller's immutable request bytes.
  leftCopy.priorOperationUUIDs.clear();
  rightCopy.priorOperationUUIDs.clear();
  BitseryEngine::serialize(left, leftCopy);
  BitseryEngine::serialize(right, rightCopy);
  return left == right;
}

static inline bool cousinRouteAuthorizationDigest(const CousinRouteRecord& route, String& digest)
{
  if (!cousinRouteStructurallyValid(route)) return false;
  String encoded = {};
  CousinRouteRecord copy = route;
  copy.priorOperationUUIDs.clear();
  BitseryEngine::serialize(encoded, copy);
  return prodigyComputeSHA256Hex(encoded, digest, nullptr);
}

static inline bool cousinRouteAllowsNewAdmissionAt(const CousinRouteRecord& route, int64_t nowMs)
{
  return cousinRouteStructurallyValid(route) &&
         route.state == CousinRouteState::active &&
         nowMs >= route.issuedAtMs && nowMs < route.expiresAtMs;
}

static inline bool cousinRouteAllowsExistingFlowAt(const CousinRouteRecord& route, int64_t nowMs)
{
  return cousinRouteStructurallyValid(route) &&
         (route.state == CousinRouteState::active || route.state == CousinRouteState::draining) &&
         nowMs >= route.issuedAtMs && nowMs < route.expiresAtMs;
}

static inline bool cousinRouteUsableAt(const CousinRouteRecord& route, int64_t nowMs)
{
  return cousinRouteAllowsNewAdmissionAt(route, nowMs);
}
