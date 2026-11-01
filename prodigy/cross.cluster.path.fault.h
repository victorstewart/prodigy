#pragma once

// Typed, reversible qualification fault contract for one enrolled MASQUE/BGP
// path.  This is deliberately not a route or process-control API: only the
// production gateway owner may implement execution inside its admitted
// namespace.  The contract prevents a qualification caller from selecting a
// host, endpoint, tunnel, or flow label outside the durable authority.

#include <prodigy/cross.cluster.mesh.route.h>
#include <prodigy/pair.private.bgp.secret.h>

enum class ProdigyCrossClusterPathFaultPhase : uint8_t { active = 1, restored = 2 };

static inline bool prodigyCrossClusterPathFaultDirectionValid(ProdigyCrossClusterPathFaultDirection value)
{ return value == ProdigyCrossClusterPathFaultDirection::localToPeer || value == ProdigyCrossClusterPathFaultDirection::peerToLocal; }

static inline ProdigyPairPrivateBGPSecretScope prodigyCrossClusterPathFaultScope(
    const CrossClusterMasqueGatewayAuthority& authority)
{
  ProdigyPairPrivateBGPSecretScope scope = {};
  scope.pairUUID = authority.pairUUID; scope.operationUUID = authority.pairOperationUUID;
  scope.keyEpoch = authority.keyGeneration; scope.tunnelSlot = authority.tunnelSlot;
  scope.clusterUUID = authority.localClusterUUID; scope.machineUUID = authority.localMachineUUID;
  scope.authorityGeneration = authority.pairAuthorityGeneration; scope.gatewayGeneration = authority.generation;
  return scope;
}

static inline bool prodigyCrossClusterPathFaultScopeEqual(const ProdigyPairPrivateBGPSecretScope& left,
                                                          const ProdigyPairPrivateBGPSecretScope& right)
{ return prodigyPairPrivateBGPSecretScopeEqual(left, right); }

// This is an opaque canonical rendering of the already-owned private BGP
// scope, not caller text.  It is suitable for the sealed physical provider's
// flowIdentity field while remaining independent of an endpoint spelling.
static inline void prodigyCrossClusterPathFaultFlowIdentity(
    const ProdigyPairPrivateBGPSecretScope& scope, String& output)
{
  output.clear(); output.append("masque-bgp:"_ctv);
  String field = {};
  const auto append128 = [&](uint128_t value) { field.clear(); field.assignItoh(value); output.append(field); output.append('/'); };
  const auto append64 = [&](uint64_t value) { field.clear(); field.assignItoh(value); output.append(field); output.append('/'); };
  append128(scope.pairUUID); append128(scope.operationUUID); append64(scope.keyEpoch);
  field.clear(); field.assignItoa(scope.tunnelSlot); output.append(field); output.append('/');
  append128(scope.clusterUUID); append128(scope.machineUUID); append64(scope.authorityGeneration);
  field.clear(); field.assignItoh(scope.gatewayGeneration); output.append(field);
}


static inline bool prodigyCrossClusterPathFaultRequestValid(const ProdigyCrossClusterPathFaultRequest& value)
{
  String expected = {};
  const ProdigyPairPrivateBGPSecretScope scope = prodigyCrossClusterPathFaultScope(value.authority);
  prodigyCrossClusterPathFaultFlowIdentity(scope, expected);
  return (value.protocolVersion == ProdigyCrossClusterPathFaultRequest::version ||
          (value.protocolVersion == ProdigyCrossClusterPathFaultRequest::leaseVersion && value.expiresAtMilliseconds != 0)) && value.operationUUID != 0 &&
      prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(value.authority) &&
      value.authority.state == CrossClusterMasqueGatewayState::active &&
      prodigyCrossClusterPathFaultDirectionValid(value.direction) &&
      prodigyCrossClusterPathFaultScopeEqual(value.scope, scope) && value.flowIdentity == expected;
}

static inline bool prodigyCrossClusterPathFaultRequestEqual(
    const ProdigyCrossClusterPathFaultRequest& left, const ProdigyCrossClusterPathFaultRequest& right)
{
  String leftBytes = {}, rightBytes = {};
  auto leftCopy = left, rightCopy = right;
  BitseryEngine::serialize(leftBytes, leftCopy); BitseryEngine::serialize(rightBytes, rightCopy);
  return leftBytes == rightBytes;
}

// The authenticated control channel supplies the observed peer identity out
// of band.  It is compared with the authority's pinned local identity here;
// a payload-provided digest can never authenticate a pause by itself.
static inline bool prodigyCrossClusterPathFaultControlAuthenticated(
    const ProdigyCrossClusterPathFaultRequest& request, const String& authenticatedControlIdentitySHA256)
{
  return prodigyCrossClusterPathFaultRequestValid(request) &&
      authenticatedControlIdentitySHA256 == request.authority.localIdentitySHA256;
}

// A container restart is safe only when its exact admitted system-plan
// identity was durably recorded before retirement.  Neuron owns execution;
// this record is deliberately transport-neutral so Brain/Mothership's
// existing durable lifecycle owner can journal it without acquiring a second
// launcher or reconstructing an artifact from operator input.

static inline bool prodigyCrossClusterPathFaultGatewayPlanMatchesAuthority(
    const SystemContainerRuntimePlan& plan, const CrossClusterMasqueGatewayAuthority& authority)
{
  String endpoint = {};
  if (!ClusterMachine::renderIPAddressLiteral(authority.listenerPublicUDPEndpoint, endpoint)) return false;
  const bool egressAddress = authority.listenerPublicUDPEndpoint.is6 ?
      std::memcmp(plan.egress.address6, authority.listenerPublicUDPEndpoint.v6, sizeof(plan.egress.address6)) == 0 :
      htonl(plan.egress.address4) == authority.listenerPublicUDPEndpoint.v4;
  return plan.kind == SystemContainerKind::crossClusterMasqueGateway &&
      plan.artifact.sha256 == authority.artifactSHA256 && plan.artifact.bytes == authority.artifactBytes &&
      plan.egress.configured() && plan.egress.protocol == IPPROTO_UDP &&
      plan.egress.port == authority.listenerPublicUDPPort && plan.egress.peerIsIPv6 == authority.listenerPublicUDPEndpoint.is6 &&
      egressAddress && plan.egress.allowIngressFromPeer == (authority.localRole == CrossClusterMasqueGatewayRole::listener) &&
      plan.gatewayPairUUID == authority.pairUUID && plan.gatewayLocalClusterUUID == authority.localClusterUUID &&
      plan.gatewayLocalMachineUUID == authority.localMachineUUID &&
      plan.gatewayKeyEpoch == authority.keyGeneration &&
      plan.gatewayAuthorityGeneration == authority.pairAuthorityGeneration &&
      plan.gatewayGeneration == authority.generation && plan.gatewayTunnelInterface == authority.privateTunnelInterface &&
      plan.gatewayEndpoint == endpoint && plan.gatewayLocalIdentity == authority.localIdentitySHA256 &&
      plan.gatewayPeerIdentity == authority.peerIdentitySHA256 && plan.gatewayPeerTrust == authority.peerTrustSHA256;
}

static inline bool prodigyCrossClusterPathFaultGatewayLifecycleRecordValid(
    const ProdigyCrossClusterPathFaultGatewayLifecycleRecord& value)
{
  if (value.protocolVersion != ProdigyCrossClusterPathFaultGatewayLifecycleRecord::version ||
      !prodigyCrossClusterPathFaultRequestValid(value.request) || value.admittedLaunchGeneration == 0 ||
      !prodigyCrossClusterPathFaultGatewayPlanMatchesAuthority(value.admittedPlan, value.request.authority)) return false;
  switch (value.phase) {
    case ProdigyCrossClusterPathFaultGatewayLifecyclePhase::prepared:
      // This is the write-ahead resume intent; no destructive action has run.
      return value.retiringContainerUUID != 0 && value.replacementContainerUUID == 0;
    case ProdigyCrossClusterPathFaultGatewayLifecyclePhase::suspended:
      return value.retiringContainerUUID != 0 && value.replacementContainerUUID == 0;
    case ProdigyCrossClusterPathFaultGatewayLifecyclePhase::restoreNeeded:
      return value.retiringContainerUUID != 0 && value.replacementContainerUUID == 0;
    case ProdigyCrossClusterPathFaultGatewayLifecyclePhase::restored:
      return value.retiringContainerUUID != 0 && value.replacementContainerUUID != 0 &&
          value.replacementContainerUUID != value.retiringContainerUUID;
  }
  return false;
}

// Implemented only by the admitted MASQUE gateway/session owner.  This is a
// control seam, not a second tunnel state machine: it accepts an exact scope
// and exposes no host, interface, namespace, or free-form endpoint argument.
class ProdigyCrossClusterPathFaultSessionControl {
public:
  virtual ~ProdigyCrossClusterPathFaultSessionControl() = default;
  virtual bool pause(const ProdigyCrossClusterPathFaultRequest& request) = 0;
  virtual bool query(const ProdigyCrossClusterPathFaultRequest& request, bool& authenticatedReady) = 0;
  virtual bool resume(const ProdigyCrossClusterPathFaultRequest& request) = 0;
};

// The retained, credential-checked gateway readiness stream is also the only
// local control boundary allowed to carry these commands.  One shared payload
// travels in both directions; `fromGateway` supplies the role semantics.  A
// gateway that has not implemented this version cannot acknowledge a command,
// so callers remain fail-closed rather than falling back to a host action.
// One payload is carried in both directions on the authenticated Brain/Neuron
// stream; the response flag supplies its direction.
class ProdigyCrossClusterPathFaultControl {
public:
  uint32_t protocolVersion = 1;
  bool response = false;
  ProdigyCrossClusterPathFaultGatewayAction action = ProdigyCrossClusterPathFaultGatewayAction::query;
  ProdigyCrossClusterPathFaultRequest request;
  bool accepted = false, sessionReady = false, bgpReady = false;
};
template <typename S> static void serialize(S&& s, ProdigyCrossClusterPathFaultControl& value)
{ s.value4b(value.protocolVersion); s.value1b(value.response); s.value1b(value.action); s.object(value.request); s.value1b(value.accepted); s.value1b(value.sessionReady); s.value1b(value.bgpReady); }
static inline bool prodigyCrossClusterPathFaultControlValid(const ProdigyCrossClusterPathFaultControl& value)
{
  return value.protocolVersion == 1 && value.request.protocolVersion == ProdigyCrossClusterPathFaultRequest::leaseVersion &&
      prodigyCrossClusterPathFaultRequestValid(value.request) &&
      (value.action == ProdigyCrossClusterPathFaultGatewayAction::pause || value.action == ProdigyCrossClusterPathFaultGatewayAction::query || value.action == ProdigyCrossClusterPathFaultGatewayAction::resume) &&
      (value.response || (!value.accepted && !value.sessionReady && !value.bgpReady));
}
// A rejected completed observation can be transient while the gateway's
// independent expiry restoration is still converging. Pending sends and
// successful observations are never replaced; pause is never replayed here.
static inline bool prodigyCrossClusterPathFaultRetryRejectedObservation(
    const ProdigyCrossClusterPathFaultControl& request, bool received,
    const ProdigyCrossClusterPathFaultControl& response)
{
  return received && prodigyCrossClusterPathFaultControlValid(request) && !request.response &&
      request.action != ProdigyCrossClusterPathFaultGatewayAction::pause &&
      prodigyCrossClusterPathFaultControlValid(response) && response.response && !response.accepted &&
      response.action == request.action && prodigyCrossClusterPathFaultRequestEqual(request.request, response.request);
}

static inline bool prodigyCrossClusterPathFaultGatewayControlPayloadValid(
    const ProdigyCrossClusterPathFaultGatewayControlPayload& value)
{
  if ((value.protocolVersion != ProdigyCrossClusterPathFaultGatewayControlPayload::version &&
       value.protocolVersion != ProdigyCrossClusterPathFaultGatewayControlPayload::leaseVersion) ||
      (value.protocolVersion == value.version && !prodigyCrossClusterPathFaultRequestValid(value.request)) ||
      (value.protocolVersion == value.leaseVersion && (!value.operationUUID || !value.pairUUID || !value.clusterUUID || !value.machineUUID || !value.keyEpoch || !value.authorityGeneration || !value.gatewayGeneration || !value.expiresAtMilliseconds)) ||
      (value.action != ProdigyCrossClusterPathFaultGatewayAction::pause &&
       value.action != ProdigyCrossClusterPathFaultGatewayAction::query &&
       value.action != ProdigyCrossClusterPathFaultGatewayAction::resume)) return false;
  // A command never claims a resulting state. A response is accepted only
  // when it came from the pinned gateway process on the held Unix stream.
  return value.fromGateway ? (value.protocolVersion == value.leaseVersion || value.accepted) :
      (!value.accepted && !value.authenticatedReady);
}
static inline bool prodigyCrossClusterPathFaultGatewayLeasePayload(
    const ProdigyCrossClusterPathFaultRequest& request,
    ProdigyCrossClusterPathFaultGatewayAction action,
    ProdigyCrossClusterPathFaultGatewayControlPayload& value)
{
  value = {};
  if (request.protocolVersion != ProdigyCrossClusterPathFaultRequest::leaseVersion ||
      !prodigyCrossClusterPathFaultRequestValid(request)) return false;
  value.protocolVersion = value.leaseVersion; value.action = action;
  value.operationUUID = request.operationUUID; value.pairUUID = request.scope.pairUUID;
  value.clusterUUID = request.scope.clusterUUID; value.machineUUID = request.scope.machineUUID;
  value.keyEpoch = request.scope.keyEpoch; value.authorityGeneration = request.scope.authorityGeneration;
  value.gatewayGeneration = request.scope.gatewayGeneration;
  value.expiresAtMilliseconds = request.expiresAtMilliseconds;
  return prodigyCrossClusterPathFaultGatewayControlPayloadValid(value);
}
static inline bool prodigyCrossClusterPathFaultGatewayLeaseResponseMatches(
    const ProdigyCrossClusterPathFaultGatewayControlPayload& command,
    const ProdigyCrossClusterPathFaultGatewayControlPayload& response)
{
  return prodigyCrossClusterPathFaultGatewayControlPayloadValid(command) && !command.fromGateway &&
      prodigyCrossClusterPathFaultGatewayControlPayloadValid(response) && response.fromGateway && response.accepted &&
      command.protocolVersion == response.protocolVersion && command.action == response.action &&
      command.operationUUID == response.operationUUID && command.pairUUID == response.pairUUID &&
      command.clusterUUID == response.clusterUUID && command.machineUUID == response.machineUUID &&
      command.keyEpoch == response.keyEpoch && command.authorityGeneration == response.authorityGeneration &&
      command.gatewayGeneration == response.gatewayGeneration && command.expiresAtMilliseconds == response.expiresAtMilliseconds;
}
static inline bool prodigyEncodeCrossClusterPathFaultGatewayControlFrame(
    const ProdigyCrossClusterPathFaultGatewayControlPayload& value, String& frame)
{
  frame.clear(); auto copy = value; String payload = {};
  if (!prodigyCrossClusterPathFaultGatewayControlPayloadValid(value) ||
      !BitseryEngine::serialize(payload, copy) || payload.size() == 0 || payload.size() > 2044) return false;
  const uint32_t bytes = uint32_t(payload.size()); frame.append(reinterpret_cast<const char *>(&bytes), sizeof(bytes)); frame.append(payload); return true;
}
static inline bool prodigyDecodeCrossClusterPathFaultGatewayControlFrame(
    const uint8_t *bytes, uint32_t size, ProdigyCrossClusterPathFaultGatewayControlPayload& value)
{
  value = {}; if (bytes == nullptr || size < sizeof(uint32_t) || size > 2048) return false;
  uint32_t payloadBytes = 0; memcpy(&payloadBytes, bytes, sizeof(payloadBytes));
  if (payloadBytes == 0 || payloadBytes > 2044 || payloadBytes != size - sizeof(uint32_t)) return false;
  String payload = {}; payload.append(reinterpret_cast<const char *>(bytes + sizeof(uint32_t)), payloadBytes);
  return BitseryEngine::deserializeSafe(payload, value) && prodigyCrossClusterPathFaultGatewayControlPayloadValid(value);
}

// Test-only in-memory seam. Production code must supply the MASQUE gateway
// owner; this class has no sockets, namespace handles, or network effects.
class ProdigyCrossClusterPathFaultInMemorySessionControl final : public ProdigyCrossClusterPathFaultSessionControl {
  ProdigyCrossClusterPathFaultRequest retained = {};
  bool paused = false;
public:
  bool pause(const ProdigyCrossClusterPathFaultRequest& request) override
  {
    if (!prodigyCrossClusterPathFaultRequestValid(request)) return false;
    if (retained.operationUUID == 0) retained = request;
    if (!prodigyCrossClusterPathFaultRequestEqual(retained, request)) return false;
    paused = true; return true;
  }
  bool query(const ProdigyCrossClusterPathFaultRequest& request, bool& authenticatedReady) override
  {
    authenticatedReady = false;
    if (retained.operationUUID == 0 || !prodigyCrossClusterPathFaultRequestEqual(retained, request)) return false;
    authenticatedReady = !paused; return true;
  }
  bool resume(const ProdigyCrossClusterPathFaultRequest& request) override
  {
    if (retained.operationUUID == 0 || !prodigyCrossClusterPathFaultRequestEqual(retained, request)) return false;
    paused = false; return true;
  }
};

class ProdigyCrossClusterPathFaultSurvivorReceipt {
public:
  ProdigyPairPrivateBGPSecretScope scope;
  ProdigyCrossClusterMasqueGatewayReadiness masque;
  ProdigyCrossClusterPrivateBGPReadiness privateBGP;
};
template <typename S> static void serialize(S&& s, ProdigyCrossClusterPathFaultSurvivorReceipt& value)
{ s.object(value.scope); s.object(value.masque); s.object(value.privateBGP); }

class ProdigyCrossClusterPathFaultReceipt {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  ProdigyCrossClusterPathFaultRequest request;
  ProdigyCrossClusterPathFaultPhase phase = ProdigyCrossClusterPathFaultPhase::active;
  // Active proof is emitted only by the future gateway-session owner after it
  // has suspended the exact scope and withdrawn its local route.
  bool selectedMasqueSessionDown = false;
  bool selectedPrivateBGPDown = false;
  bool selectedRouteWithdrawn = false;
  ProdigyCrossClusterMasqueGatewayReadiness selectedMasque;
  ProdigyCrossClusterPrivateBGPReadiness selectedPrivateBGP;
  Vector<ProdigyCrossClusterPathFaultSurvivorReceipt> surviving;
};
template <typename S> static void serialize(S&& s, ProdigyCrossClusterPathFaultReceipt& value)
{ s.value4b(value.protocolVersion); s.object(value.request); s.value1b(value.phase); s.value1b(value.selectedMasqueSessionDown); s.value1b(value.selectedPrivateBGPDown); s.value1b(value.selectedRouteWithdrawn); s.object(value.selectedMasque); s.object(value.selectedPrivateBGP); s.container(value.surviving, 18); }

static inline bool prodigyCrossClusterPathFaultReceiptValid(
    const ProdigyCrossClusterPathFaultRequest& request,
    const ProdigyCrossClusterPathFaultReceipt& receipt,
    const Vector<CrossClusterMasqueGatewayAuthority>& admittedAuthorities)
{
  if (!prodigyCrossClusterPathFaultRequestValid(request) || receipt.protocolVersion != ProdigyCrossClusterPathFaultReceipt::version ||
      !prodigyCrossClusterPathFaultRequestValid(receipt.request) ||
      !prodigyCrossClusterPathFaultRequestEqual(receipt.request, request) || admittedAuthorities.empty()) return false;
  uint32_t selected = 0; bool selectedAuthorityExact = false;
  for (const auto& authority : admittedAuthorities) {
    if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority) || authority.state != CrossClusterMasqueGatewayState::active) return false;
    if (prodigyCrossClusterPathFaultScopeEqual(prodigyCrossClusterPathFaultScope(authority), request.scope)) {
      ++selected;
      String expected = {}, observed = {}; auto expectedCopy = request.authority, observedCopy = authority;
      BitseryEngine::serialize(expected, expectedCopy); BitseryEngine::serialize(observed, observedCopy);
      selectedAuthorityExact = expected == observed;
    }
  }
  if (selected != 1 || !selectedAuthorityExact || receipt.surviving.size() != admittedAuthorities.size() - 1) return false;
  if (receipt.phase == ProdigyCrossClusterPathFaultPhase::active) {
    if (!receipt.selectedMasqueSessionDown || !receipt.selectedPrivateBGPDown || !receipt.selectedRouteWithdrawn ||
        !prodigyCrossClusterMasqueGatewayReadinessMatches(request.authority, receipt.selectedMasque) ||
        !prodigyCrossClusterPrivateBGPReadinessMatchesAuthority(receipt.selectedPrivateBGP, request.authority) ||
        receipt.selectedMasque.authenticatedMasqueQUICReady || receipt.selectedPrivateBGP.sessionEstablished ||
        receipt.selectedPrivateBGP.peerSitePrefixImported || receipt.selectedPrivateBGP.switchboardFallbackInstalled) return false;
  } else if (receipt.phase == ProdigyCrossClusterPathFaultPhase::restored) {
    if (receipt.selectedMasqueSessionDown || receipt.selectedPrivateBGPDown || receipt.selectedRouteWithdrawn ||
        !prodigyCrossClusterMasqueGatewayReady(request.authority, &receipt.selectedMasque) ||
        !prodigyCrossClusterPrivateBGPReadinessMatchesAuthority(receipt.selectedPrivateBGP, request.authority) ||
        !prodigyCrossClusterPrivateBGPReady(receipt.selectedPrivateBGP)) return false;
  } else return false;
  for (const auto& authority : admittedAuthorities) {
    const auto scope = prodigyCrossClusterPathFaultScope(authority);
    if (prodigyCrossClusterPathFaultScopeEqual(scope, request.scope)) continue;
    uint32_t matches = 0;
    for (const auto& survivor : receipt.surviving)
      if (prodigyCrossClusterPathFaultScopeEqual(survivor.scope, scope) &&
          prodigyCrossClusterMasqueGatewayReady(authority, &survivor.masque) &&
          prodigyCrossClusterPrivateBGPReadinessMatchesAuthority(survivor.privateBGP, authority) &&
          prodigyCrossClusterPrivateBGPReady(survivor.privateBGP)) ++matches;
    if (matches != 1) return false;
  }
  return true;
}
