#pragma once

// Cross-cluster container routing is projected only from Mothership's durable
// MASQUE gateway authority. Pair enrollment authenticates the sites, while
// the gateway record selects the data-plane hosts and canonical site /96s.
// Application COUSIN routes are intentionally not part of this path.

#include <prodigy/types.h>
#include <macros/bytes.h>
#include <services/time.h>
#include <services/prodigy.h>
#include <networking/socket.h>
#include <networking/ring.h>
#include <networking/stream.h>
#include <networking/multiplexer.h>
#include <networking/bgp.h>
#include <switchboard/overlay.route.h>

class ProdigyCrossClusterMeshRoute {
public:
  uint128_t pairUUID = 0;
  uint128_t pairOperationUUID = 0;
  uint128_t localClusterUUID = 0;
  uint128_t peerClusterUUID = 0;
  uint128_t localMachineUUID = 0;
  uint128_t peerMachineUUID = 0;
  uint8_t localDatacenterFragment = 0;
  uint8_t peerDatacenterFragment = 0;
  IPPrefix localSitePrefix = {};
  IPPrefix peerSitePrefix = {};
  uint64_t keyEpoch = 0;
  uint64_t authorityGeneration = 0;
  uint64_t gatewayGeneration = 0;
  CrossClusterMasqueGatewayRole localRole = CrossClusterMasqueGatewayRole::listener;
};

template <typename S>
static void serialize(S&& serializer, ProdigyCrossClusterMeshRoute& route)
{
  serializer.value16b(route.pairUUID);
  serializer.value16b(route.pairOperationUUID);
  serializer.value16b(route.localClusterUUID);
  serializer.value16b(route.peerClusterUUID);
  serializer.value16b(route.localMachineUUID);
  serializer.value16b(route.peerMachineUUID);
  serializer.value1b(route.localDatacenterFragment);
  serializer.value1b(route.peerDatacenterFragment);
  serializer.object(route.localSitePrefix);
  serializer.object(route.peerSitePrefix);
  serializer.value8b(route.keyEpoch);
  serializer.value8b(route.authorityGeneration);
  serializer.value8b(route.gatewayGeneration);
  serializer.value1b(route.localRole);
}

static inline bool prodigyCrossClusterMeshRouteValid(const ProdigyCrossClusterMeshRoute& route)
{
  return route.pairUUID != 0 && route.pairOperationUUID != 0 && route.localClusterUUID != 0 &&
      route.peerClusterUUID != 0 && route.localClusterUUID != route.peerClusterUUID &&
      route.localMachineUUID != 0 && route.peerMachineUUID != 0 &&
      route.localMachineUUID != route.peerMachineUUID &&
      route.localDatacenterFragment != 0 && route.peerDatacenterFragment != 0 &&
      route.localDatacenterFragment != route.peerDatacenterFragment &&
      prodigyContainerDatacenterSitePrefixValid(
          route.localSitePrefix, route.localDatacenterFragment) &&
      prodigyContainerDatacenterSitePrefixValid(
          route.peerSitePrefix, route.peerDatacenterFragment) &&
      route.keyEpoch != 0 && route.authorityGeneration != 0 &&
      route.gatewayGeneration != 0 &&
      (route.localRole == CrossClusterMasqueGatewayRole::listener ||
       route.localRole == CrossClusterMasqueGatewayRole::connector);
}

// This is a transient Mothership/Brain projection input, not a new registry
// or tunnel declaration.  Its endpoint tuple must be supplied by the future
// authenticated underlay owner; control-carrier addresses are explicitly not
// accepted as a data-plane default.
class ProdigyCrossClusterAuthenticatedOverlayUnderlay {
public:
  uint128_t pairUUID = 0;
  uint128_t localMachineUUID = 0;
  uint128_t peerMachineUUID = 0;
  uint64_t keyEpoch = 0;
  uint64_t authorityGeneration = 0;
  uint64_t gatewayGeneration = 0;
  IPAddress nextHop = {};
  IPAddress sourceAddress = {};
  bool useGatewayMAC = true;
  String nextHopMAC;
};

static inline bool prodigyCrossClusterMasqueGatewayReadinessMatches(
    const CrossClusterMasqueGatewayAuthority& authority,
    const ProdigyCrossClusterMasqueGatewayReadiness& readiness);

// The retained readiness carrier is also the sole local control boundary for
// the already-owned path-fault operation. Keep its payload declaration here
// so the v2 carrier envelope can embed it without creating a second authority
// or a second local framing contract. Validation remains with the request and
// lease owner in cross.cluster.path.fault.h.
enum class ProdigyCrossClusterPathFaultGatewayAction : uint8_t { pause = 1, query = 2, resume = 3 };
class ProdigyCrossClusterPathFaultGatewayControlPayload {
public:
  static constexpr uint32_t version = 1;
  static constexpr uint32_t leaseVersion = 2;
  uint32_t protocolVersion = version;
  bool fromGateway = false;
  ProdigyCrossClusterPathFaultGatewayAction action = ProdigyCrossClusterPathFaultGatewayAction::query;
  ProdigyCrossClusterPathFaultRequest request;
  bool accepted = false, authenticatedReady = false;
  uint128_t operationUUID = 0, pairUUID = 0, clusterUUID = 0, machineUUID = 0;
  uint64_t keyEpoch = 0, authorityGeneration = 0, gatewayGeneration = 0;
  uint64_t expiresAtMilliseconds = 0;
};
template <typename S> static void serialize(S&& s, ProdigyCrossClusterPathFaultGatewayControlPayload& value)
{ s.value4b(value.protocolVersion); s.value1b(value.fromGateway); s.value1b(value.action); if (value.protocolVersion == value.leaseVersion) { s.value16b(value.operationUUID); s.value16b(value.pairUUID); s.value16b(value.clusterUUID); s.value16b(value.machineUUID); s.value8b(value.keyEpoch); s.value8b(value.authorityGeneration); s.value8b(value.gatewayGeneration); s.value8b(value.expiresAtMilliseconds); } else s.object(value.request); s.value1b(value.accepted); s.value1b(value.authenticatedReady); }

// This is the bounded local-only wire payload for the gateway readiness
// socket. It is deliberately distinct from the Brain projection: the token
// binds the receipt to one container launch and `ready=false` is an immediate
// revocation, never a deferred health hint.
class ProdigyCrossClusterMasqueGatewayLocalReceipt {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  String launchToken;
  ProdigyCrossClusterMasqueGatewayReadiness readiness;
  String routeSetSHA256;
  bool ready = false;
};

template <typename S>
static void serialize(S&& s, ProdigyCrossClusterMasqueGatewayLocalReceipt& receipt)
{
  s.value4b(receipt.protocolVersion);
  s.text1b(receipt.launchToken, 128);
  s.value16b(receipt.readiness.pairUUID);
  s.value16b(receipt.readiness.localClusterUUID);
  s.value16b(receipt.readiness.localMachineUUID);
  s.value8b(receipt.readiness.keyEpoch);
  s.value8b(receipt.readiness.authorityGeneration);
  s.value8b(receipt.readiness.gatewayGeneration);
  s.value1b(receipt.readiness.authenticatedMasqueQUICReady);
  s.text1b(receipt.routeSetSHA256, 64);
  s.value1b(receipt.ready);
}

static inline bool prodigyCrossClusterMasqueGatewayLocalReceiptValid(
    const CrossClusterMasqueGatewayAuthority& authority,
    const String& expectedLaunchToken,
    const ProdigyCrossClusterMasqueGatewayLocalReceipt& receipt)
{
  return receipt.protocolVersion == ProdigyCrossClusterMasqueGatewayLocalReceipt::version &&
      expectedLaunchToken.size() >= 32 && receipt.launchToken.equal(expectedLaunchToken) &&
      prodigyIsSHA256HexDigest(receipt.routeSetSHA256) && receipt.ready &&
      receipt.readiness.authenticatedMasqueQUICReady &&
      prodigyCrossClusterMasqueGatewayReadinessMatches(authority, receipt.readiness);
}

// Local readiness is a bounded versioned stream record, never a Message frame.
// The four-byte little-endian length lets the listener reject truncation and
// prevents a gateway process from consuming unbounded Neuron memory.
static inline bool prodigyDecodeCrossClusterMasqueGatewayLocalReceiptFrame(
    const uint8_t *bytes, uint32_t size,
    ProdigyCrossClusterMasqueGatewayLocalReceipt& receipt)
{
  receipt = {};
  if (bytes == nullptr || size < sizeof(uint32_t) || size > 512) return false;
  uint32_t payloadBytes = 0;
  memcpy(&payloadBytes, bytes, sizeof(payloadBytes));
  if (payloadBytes == 0 || payloadBytes > 508 || payloadBytes != size - sizeof(uint32_t)) return false;
  String payload = {};
  payload.append(reinterpret_cast<const char *>(bytes + sizeof(uint32_t)), payloadBytes);
  return BitseryEngine::deserializeSafe(payload, receipt) &&
      receipt.protocolVersion == ProdigyCrossClusterMasqueGatewayLocalReceipt::version;
}

static inline bool prodigyEncodeCrossClusterMasqueGatewayLocalReceiptFrame(
    const ProdigyCrossClusterMasqueGatewayLocalReceipt& receipt, String& frame)
{
  frame.clear();
  auto copy = receipt;
  String payload = {};
  if (!BitseryEngine::serialize(payload, copy) || payload.size() == 0 || payload.size() > 508) return false;
  const uint32_t payloadBytes = uint32_t(payload.size());
  frame.append(reinterpret_cast<const char *>(&payloadBytes), sizeof(payloadBytes));
  frame.append(payload);
  return true;
}

// V2 is the one tagged local-carrier record in both directions. It embeds the
// existing path-fault payload rather than making rebind a second authority.
enum class ProdigyGatewayLocalDirection : uint8_t { gatewayToNeuron = 1, neuronToGateway = 2 };
enum class ProdigyGatewayLocalKind : uint8_t { readiness = 1, rebindHello = 2, rebindChallenge = 3, rebindReceipt = 4, pathFault = 5 };
enum class ProdigyGatewayLocalCarrierMode : uint8_t { undecided = 0, legacyV1 = 1, v2 = 2 };
enum class ProdigyGatewayLocalCarrierPhase : uint8_t { initial = 1, rebindHello = 2, rebindReceipt = 3, established = 4 };

class ProdigyGatewayLocalTuple { public: uint128_t pairUUID = 0, localClusterUUID = 0, localMachineUUID = 0; uint64_t keyEpoch = 0, authorityGeneration = 0, gatewayGeneration = 0; };
template <typename S> static void serialize(S&& s, ProdigyGatewayLocalTuple& value)
{ s.value16b(value.pairUUID); s.value16b(value.localClusterUUID); s.value16b(value.localMachineUUID); s.value8b(value.keyEpoch); s.value8b(value.authorityGeneration); s.value8b(value.gatewayGeneration); }
class ProdigyGatewayLocalReadinessBody { public: String launchToken; ProdigyGatewayLocalTuple tuple; bool authenticatedMasqueQUICReady = false; String routeSetSHA256; bool ready = false; };
template <typename S> static void serialize(S&& s, ProdigyGatewayLocalReadinessBody& value)
{ s.text1b(value.launchToken, 128); s.object(value.tuple); s.value1b(value.authenticatedMasqueQUICReady); s.text1b(value.routeSetSHA256, 64); s.value1b(value.ready); }
class ProdigyGatewayLocalRebindHelloBody { public: String recoveryToken; ProdigyGatewayLocalTuple tuple; };
template <typename S> static void serialize(S&& s, ProdigyGatewayLocalRebindHelloBody& value)
{ s.text1b(value.recoveryToken, 128); s.object(value.tuple); }
class ProdigyGatewayLocalRebindChallengeBody { public: ProdigyGatewayLocalTuple tuple; uint8_t nonce[16] = {}; };
template <typename S> static void serialize(S&& s, ProdigyGatewayLocalRebindChallengeBody& value)
{ s.object(value.tuple); for (uint8_t& byte : value.nonce) s.value1b(byte); }
class ProdigyGatewayLocalRebindReceiptBody { public: ProdigyGatewayLocalTuple tuple; uint8_t nonce[16] = {}; bool authenticatedMasqueQUICReady = false; String routeSetSHA256; bool ready = false; };
template <typename S> static void serialize(S&& s, ProdigyGatewayLocalRebindReceiptBody& value)
{ s.object(value.tuple); for (uint8_t& byte : value.nonce) s.value1b(byte); s.value1b(value.authenticatedMasqueQUICReady); s.text1b(value.routeSetSHA256, 64); s.value1b(value.ready); }

class ProdigyGatewayLocalControlFrame {
public:
  static constexpr uint32_t version = 2;
  uint32_t protocolVersion = version;
  ProdigyGatewayLocalDirection direction = ProdigyGatewayLocalDirection::gatewayToNeuron;
  ProdigyGatewayLocalKind kind = ProdigyGatewayLocalKind::readiness;
  ProdigyGatewayLocalReadinessBody readiness;
  ProdigyGatewayLocalRebindHelloBody rebindHello;
  ProdigyGatewayLocalRebindChallengeBody rebindChallenge;
  ProdigyGatewayLocalRebindReceiptBody rebindReceipt;
  ProdigyCrossClusterPathFaultGatewayControlPayload pathFault;
};
template <typename S> static void serialize(S&& s, ProdigyGatewayLocalControlFrame& value)
{
  s.value4b(value.protocolVersion); s.value1b(value.direction); s.value1b(value.kind);
  switch (value.kind) {
    case ProdigyGatewayLocalKind::readiness: s.object(value.readiness); break;
    case ProdigyGatewayLocalKind::rebindHello: s.object(value.rebindHello); break;
    case ProdigyGatewayLocalKind::rebindChallenge: s.object(value.rebindChallenge); break;
    case ProdigyGatewayLocalKind::rebindReceipt: s.object(value.rebindReceipt); break;
    case ProdigyGatewayLocalKind::pathFault: s.object(value.pathFault); break;
    default: break;
  }
}
static inline bool prodigyGatewayLocalTupleValid(const ProdigyGatewayLocalTuple& value)
{ return value.pairUUID != 0 && value.localClusterUUID != 0 && value.localMachineUUID != 0 && value.keyEpoch != 0 && value.authorityGeneration != 0 && value.gatewayGeneration != 0; }
static inline bool prodigyGatewayLocalV2TokenValid(const String& value)
{
  if (value.size() != 32) return false;
  for (uint32_t index = 0; index < value.size(); ++index)
  {
    const char byte = value[index];
    if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'))) return false;
  }
  return true;
}
static inline bool prodigyGatewayLocalNonceValid(const uint8_t (&nonce)[16])
{ for (uint8_t byte : nonce) if (byte != 0) return true; return false; }
static inline bool prodigyGatewayLocalDirectionValid(ProdigyGatewayLocalDirection value)
{ return value == ProdigyGatewayLocalDirection::gatewayToNeuron || value == ProdigyGatewayLocalDirection::neuronToGateway; }
static inline bool prodigyGatewayLocalKindValid(ProdigyGatewayLocalKind value)
{ return value == ProdigyGatewayLocalKind::readiness || value == ProdigyGatewayLocalKind::rebindHello || value == ProdigyGatewayLocalKind::rebindChallenge || value == ProdigyGatewayLocalKind::rebindReceipt || value == ProdigyGatewayLocalKind::pathFault; }
static inline bool prodigyGatewayLocalControlFrameValid(const ProdigyGatewayLocalControlFrame& value)
{
  if (value.protocolVersion != ProdigyGatewayLocalControlFrame::version || !prodigyGatewayLocalDirectionValid(value.direction) || !prodigyGatewayLocalKindValid(value.kind)) return false;
  switch (value.kind) {
    case ProdigyGatewayLocalKind::readiness: return prodigyGatewayLocalV2TokenValid(value.readiness.launchToken) && prodigyGatewayLocalTupleValid(value.readiness.tuple) && value.readiness.authenticatedMasqueQUICReady && value.readiness.ready && prodigyIsSHA256HexDigest(value.readiness.routeSetSHA256);
    case ProdigyGatewayLocalKind::rebindHello: return prodigyGatewayLocalV2TokenValid(value.rebindHello.recoveryToken) && prodigyGatewayLocalTupleValid(value.rebindHello.tuple);
    case ProdigyGatewayLocalKind::rebindChallenge: return prodigyGatewayLocalTupleValid(value.rebindChallenge.tuple) && prodigyGatewayLocalNonceValid(value.rebindChallenge.nonce);
    case ProdigyGatewayLocalKind::rebindReceipt: return prodigyGatewayLocalTupleValid(value.rebindReceipt.tuple) && prodigyGatewayLocalNonceValid(value.rebindReceipt.nonce) && value.rebindReceipt.authenticatedMasqueQUICReady && value.rebindReceipt.ready && prodigyIsSHA256HexDigest(value.rebindReceipt.routeSetSHA256);
    case ProdigyGatewayLocalKind::pathFault: return value.pathFault.protocolVersion == ProdigyCrossClusterPathFaultGatewayControlPayload::version || value.pathFault.protocolVersion == ProdigyCrossClusterPathFaultGatewayControlPayload::leaseVersion;
  }
  return false;
}
static inline bool prodigyGatewayLocalCarrierLockMode(ProdigyGatewayLocalCarrierMode& mode, const uint8_t *bytes, uint32_t size, bool recoveryCarrier)
{
  if (bytes == nullptr || size < 8 || size > 512) return false;
  uint32_t payloadBytes = 0, version = 0; memcpy(&payloadBytes, bytes, sizeof(payloadBytes)); memcpy(&version, bytes + sizeof(payloadBytes), sizeof(version));
  if (payloadBytes != size - sizeof(uint32_t)) return false;
  if (mode == ProdigyGatewayLocalCarrierMode::undecided) {
    if (version == ProdigyCrossClusterMasqueGatewayLocalReceipt::version && !recoveryCarrier) { mode = ProdigyGatewayLocalCarrierMode::legacyV1; return true; }
    if (version == ProdigyGatewayLocalControlFrame::version) { mode = ProdigyGatewayLocalCarrierMode::v2; return true; }
    return false;
  }
  return (mode == ProdigyGatewayLocalCarrierMode::legacyV1 && !recoveryCarrier && version == ProdigyCrossClusterMasqueGatewayLocalReceipt::version) || (mode == ProdigyGatewayLocalCarrierMode::v2 && version == ProdigyGatewayLocalControlFrame::version);
}
static inline bool prodigyGatewayLocalControlFrameAllowed(ProdigyGatewayLocalCarrierMode mode, ProdigyGatewayLocalCarrierPhase phase, const ProdigyGatewayLocalControlFrame& frame)
{
  if (mode != ProdigyGatewayLocalCarrierMode::v2 || !prodigyGatewayLocalControlFrameValid(frame)) return false;
  if (phase == ProdigyGatewayLocalCarrierPhase::initial) return frame.direction == ProdigyGatewayLocalDirection::gatewayToNeuron && frame.kind == ProdigyGatewayLocalKind::readiness;
  if (phase == ProdigyGatewayLocalCarrierPhase::rebindHello) return frame.direction == ProdigyGatewayLocalDirection::gatewayToNeuron && frame.kind == ProdigyGatewayLocalKind::rebindHello;
  if (phase == ProdigyGatewayLocalCarrierPhase::rebindReceipt) return frame.direction == ProdigyGatewayLocalDirection::gatewayToNeuron && frame.kind == ProdigyGatewayLocalKind::rebindReceipt;
  return frame.kind == ProdigyGatewayLocalKind::pathFault && ((frame.direction == ProdigyGatewayLocalDirection::gatewayToNeuron) == frame.pathFault.fromGateway);
}
// Outbound recovery traffic has one legal transition.  Keep this separate
// from the inbound phase validator so a locally constructed challenge cannot
// accidentally inherit a gateway-to-Neuron permission.
static inline bool prodigyGatewayLocalControlFrameAllowedForSend(ProdigyGatewayLocalCarrierPhase phase, const ProdigyGatewayLocalControlFrame& frame)
{
  if (!prodigyGatewayLocalControlFrameValid(frame) || frame.direction != ProdigyGatewayLocalDirection::neuronToGateway) return false;
  if (phase == ProdigyGatewayLocalCarrierPhase::rebindHello) return frame.kind == ProdigyGatewayLocalKind::rebindChallenge;
  return phase == ProdigyGatewayLocalCarrierPhase::established && frame.kind == ProdigyGatewayLocalKind::pathFault && !frame.pathFault.fromGateway;
}
static inline bool prodigyEncodeGatewayLocalControlFrame(const ProdigyGatewayLocalControlFrame& value, String& frame)
{
  frame.clear(); auto copy = value; String payload = {};
  if (!prodigyGatewayLocalControlFrameValid(value) || !BitseryEngine::serialize(payload, copy) || payload.size() == 0 || payload.size() > 508) return false;
  const uint32_t payloadBytes = uint32_t(payload.size()); frame.append(reinterpret_cast<const char *>(&payloadBytes), sizeof(payloadBytes)); frame.append(payload); return true;
}
static inline bool prodigyDecodeGatewayLocalControlFrame(const uint8_t *bytes, uint32_t size, ProdigyGatewayLocalControlFrame& value)
{
  value = {}; if (bytes == nullptr || size < sizeof(uint32_t) || size > 512) return false;
  uint32_t payloadBytes = 0; memcpy(&payloadBytes, bytes, sizeof(payloadBytes));
  if (payloadBytes == 0 || payloadBytes > 508 || payloadBytes != size - sizeof(uint32_t)) return false;
  String payload = {}; payload.append(reinterpret_cast<const char *>(bytes + sizeof(uint32_t)), payloadBytes);
  return BitseryEngine::deserializeSafe(payload, value) && prodigyGatewayLocalControlFrameValid(value);
}

static inline bool prodigyCrossClusterMasqueGatewayReadinessMatches(
    const CrossClusterMasqueGatewayAuthority& authority,
    const ProdigyCrossClusterMasqueGatewayReadiness& readiness)
{
  return prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority) &&
      readiness.pairUUID == authority.pairUUID &&
      readiness.localClusterUUID == authority.localClusterUUID &&
      readiness.localMachineUUID == authority.localMachineUUID &&
      readiness.keyEpoch == authority.keyGeneration &&
      readiness.authorityGeneration == authority.pairAuthorityGeneration &&
      readiness.gatewayGeneration == authority.generation;
}

static inline bool prodigyCrossClusterMasqueGatewayReady(
    const CrossClusterMasqueGatewayAuthority& authority,
    const ProdigyCrossClusterMasqueGatewayReadiness* readiness)
{
  return authority.state == CrossClusterMasqueGatewayState::active && readiness != nullptr &&
      readiness->authenticatedMasqueQUICReady &&
      prodigyCrossClusterMasqueGatewayReadinessMatches(authority, *readiness);
}

// This plan deliberately contains only the one site prefix whose datacenter
// byte Mothership assigned to this cluster.  The BGP runtime supplies its
// configured next hop and applies the action; it does not infer authority or
// gateway readiness itself.
class ProdigyCrossClusterSiteBGPRoutePlan {
public:
  uint128_t pairUUID = 0;
  uint128_t localClusterUUID = 0;
  uint128_t localMachineUUID = 0;
  IPPrefix localSitePrefix = {};
  uint64_t keyEpoch = 0;
  uint64_t authorityGeneration = 0;
  uint64_t gatewayGeneration = 0;
  BGPIPv6UnicastAdvertisementAction action = BGPIPv6UnicastAdvertisementAction::none;
};

static inline bool prodigyCrossClusterSiteBGPRoutePlanValid(
    const ProdigyCrossClusterSiteBGPRoutePlan& plan)
{
  return plan.pairUUID != 0 && plan.localClusterUUID != 0 && plan.localMachineUUID != 0 &&
      plan.keyEpoch != 0 && plan.authorityGeneration != 0 && plan.gatewayGeneration != 0 &&
      plan.localSitePrefix.network.is6 && plan.localSitePrefix.cidr == 96 &&
      plan.localSitePrefix.equals(plan.localSitePrefix.canonicalized()) &&
      bgpIPv6UnicastAdvertisementActionValid(plan.action);
}

// A structurally valid withdrawn authority intentionally produces a withdraw
// plan.  Likewise, readiness loss withdraws an already-originated local /96.
// Calling code may safely discard a `none` action after recording the desired
// state, making repeated authority/readiness snapshots idempotent.
static inline bool prodigyBuildCrossClusterSiteBGPRoutePlan(
    const CrossClusterMasqueGatewayAuthority& authority,
    const ProdigyCrossClusterMasqueGatewayReadiness* readiness,
    bool currentlyAdvertised, ProdigyCrossClusterSiteBGPRoutePlan& plan)
{
  plan = {};
  if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority)) return false;

  plan.pairUUID = authority.pairUUID;
  plan.localClusterUUID = authority.localClusterUUID;
  plan.localMachineUUID = authority.localMachineUUID;
  plan.localSitePrefix = authority.localSitePrefix;
  plan.keyEpoch = authority.keyGeneration;
  plan.authorityGeneration = authority.pairAuthorityGeneration;
  plan.gatewayGeneration = authority.generation;
  plan.action = bgpIPv6UnicastAdvertisementTransition(
      currentlyAdvertised, prodigyCrossClusterMasqueGatewayReady(authority, readiness));
  return prodigyCrossClusterSiteBGPRoutePlanValid(plan);
}

static inline bool prodigyCrossClusterAuthenticatedOverlayUnderlayValid(
    const ProdigyCrossClusterMeshRoute& mesh,
    const ProdigyCrossClusterAuthenticatedOverlayUnderlay& underlay)
{
  return prodigyCrossClusterMeshRouteValid(mesh) && underlay.pairUUID == mesh.pairUUID &&
      underlay.localMachineUUID == mesh.localMachineUUID &&
      underlay.peerMachineUUID == mesh.peerMachineUUID &&
      underlay.keyEpoch == mesh.keyEpoch &&
      underlay.authorityGeneration == mesh.authorityGeneration &&
      underlay.gatewayGeneration == mesh.gatewayGeneration &&
      underlay.nextHop.is6 && !underlay.nextHop.isNull() && underlay.sourceAddress.is6 &&
      !underlay.sourceAddress.isNull() && !underlay.nextHop.equals(underlay.sourceAddress);
}

static inline bool prodigyBuildCrossClusterOverlayMachineRoute(
    const ProdigyCrossClusterMeshRoute& mesh,
    const ProdigyCrossClusterAuthenticatedOverlayUnderlay& underlay,
    uint32_t peerMachineFragment, SwitchboardOverlayMachineRoute& route)
{
  route = {};
  if (!prodigyCrossClusterAuthenticatedOverlayUnderlayValid(mesh, underlay) ||
      peerMachineFragment == 0 || peerMachineFragment > 0x00ffffffu)
  {
    return false;
  }

  route.machineFragment = switchboardMakeOverlayMachineIdentity(mesh.peerDatacenterFragment, peerMachineFragment);
  route.nextHop = underlay.nextHop;
  route.sourceAddress = underlay.sourceAddress;
  route.useGatewayMAC = underlay.useGatewayMAC;
  route.nextHopMAC = underlay.nextHopMAC;
  switchboard_overlay_machine_route value = {};
  if (!switchboardBuildOverlayMachineRouteValue(route, value))
  {
    route = {};
    return false;
  }
  return true;
}

// Install one route for the peer site's complete container /96 rather than
// materializing a route for every remote machine.  The BPF lookup first tries
// a full dc:machine identity and then this {dc,0} key, so local/exact machine
// routes retain precedence while a newly created remote machine is reachable
// without a control-plane fanout.
static inline bool prodigyBuildCrossClusterOverlayDatacenterRoute(
    const ProdigyCrossClusterMeshRoute& mesh,
    const ProdigyCrossClusterAuthenticatedOverlayUnderlay& underlay,
    SwitchboardOverlayMachineRoute& route)
{
  route = {};
  if (!prodigyCrossClusterAuthenticatedOverlayUnderlayValid(mesh, underlay))
  {
    return false;
  }

  route.machineFragment = switchboardMakeOverlayDatacenterRouteKey(mesh.peerDatacenterFragment);
  route.nextHop = underlay.nextHop;
  route.sourceAddress = underlay.sourceAddress;
  route.useGatewayMAC = underlay.useGatewayMAC;
  route.nextHopMAC = underlay.nextHopMAC;
  switchboard_overlay_machine_route value = {};
  if (!switchboardBuildOverlayMachineRouteValue(route, value))
  {
    route = {};
    return false;
  }
  return true;
}

// A remote cluster owns one fixed-container-network /96: the canonical /88
// plus its nonzero datacenter tag.  This pure selection primitive deliberately
// has no BPF map or tunnel lifecycle ownership.  An exact dc:machine route
// always wins; only an authenticated enrolled peer may provide the /96
// fallback for otherwise-unresolved machines at its datacenter.
static inline bool prodigySelectCrossClusterOverlayRoute(
    uint32_t destinationMachineIdentity,
    const SwitchboardOverlayMachineRoute *exactMachineRoute,
    const ProdigyCrossClusterMeshRoute& mesh,
    const ProdigyCrossClusterAuthenticatedOverlayUnderlay& underlay,
    SwitchboardOverlayMachineRoute& selected)
{
  selected = {};
  if (!switchboardOverlayMachineIdentityIsValid(destinationMachineIdentity) ||
      !prodigyCrossClusterMeshRouteValid(mesh))
  {
    return false;
  }

  if (exactMachineRoute != nullptr && exactMachineRoute->machineFragment == destinationMachineIdentity)
  {
    switchboard_overlay_machine_route value = {};
    if (switchboardBuildOverlayMachineRouteValue(*exactMachineRoute, value))
    {
      selected = *exactMachineRoute;
      return true;
    }
    return false;
  }

  const uint8_t destinationDatacenter = uint8_t(destinationMachineIdentity >> 24);
  if (destinationDatacenter != mesh.peerDatacenterFragment ||
      !prodigyCrossClusterAuthenticatedOverlayUnderlayValid(mesh, underlay))
  {
    return false;
  }

  return prodigyBuildCrossClusterOverlayDatacenterRoute(mesh, underlay, selected);
}

static inline bool prodigyBuildCrossClusterMeshRoute(
    const CrossClusterMasqueGatewayAuthority& authority,
    ProdigyCrossClusterMeshRoute& projection)
{
  projection = {};
  if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority) ||
      authority.state != CrossClusterMasqueGatewayState::active)
  {
    return false;
  }

  projection.pairUUID = authority.pairUUID;
  projection.pairOperationUUID = authority.pairOperationUUID;
  projection.localClusterUUID = authority.localClusterUUID;
  projection.peerClusterUUID = authority.peerClusterUUID;
  projection.localMachineUUID = authority.localMachineUUID;
  projection.peerMachineUUID = authority.peerMachineUUID;
  projection.localDatacenterFragment = authority.localDatacenterFragment;
  projection.peerDatacenterFragment = authority.peerDatacenterFragment;
  projection.localSitePrefix = authority.localSitePrefix;
  projection.peerSitePrefix = authority.peerSitePrefix;
  projection.keyEpoch = authority.keyGeneration;
  projection.authorityGeneration = authority.pairAuthorityGeneration;
  projection.gatewayGeneration = authority.generation;
  projection.localRole = authority.localRole;
  return prodigyCrossClusterMeshRouteValid(projection);
}
