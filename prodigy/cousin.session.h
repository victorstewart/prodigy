#pragma once

#include <networking/includes.h>
#include <array>
#include <openssl/crypto.h>
#include <prodigy/cousin.discovery.h>
#include <prodigy/cousin.route.h>
#include <prodigy/cluster.pair.keys.h>

// A three-site, three-replica cohort needs 96 ordinary local-half records per
// site (eight groups, two peers, both directions). The seed source additionally
// holds 48 pulls and four remote App6 Truth sessions. Keep a bounded reserve
// for replacement leases while those 148 records coexist.
constexpr inline uint32_t ProdigyCousinSessionMaximumRecords = 256;
constexpr inline uint32_t ProdigyCousinSessionMaximumBytes = 16384;
constexpr inline uint32_t ProdigyCousinSessionLeaseMs = 10000;
constexpr inline uint32_t ProdigyCousinSessionPendingMs = 5000;
constexpr inline uint32_t ProdigyCousinSessionRenewMs = 2000;
constexpr inline uint32_t ProdigyCousinSessionLegacyProtocolVersion = 1;
constexpr inline uint32_t ProdigyCousinSessionDirectProtocolVersion = 2;
constexpr inline uint32_t ProdigyCousinSessionProtocolVersion = 3;
constexpr inline uint32_t ProdigyCousinSessionPrivateContainerProtocolVersion = 4;
constexpr inline uint32_t ProdigyCousinCarrierMaximumPayloadBytes = 1200;
constexpr inline uint32_t ProdigyCousinCarrierMaximumCredits = 64;

// v3 chooses one of two deliberately narrow data planes.  `direct` preserves
// the v2 socket/BPF path.  `reverseCarrier` is an authenticated multiplexed
// stream on the already-established pair-control connection; it is not a
// listener, tunnel, proxy, or a replacement for the direct data plane.
enum class ProdigyCousinSessionTransport : uint8_t { direct = 1, reverseCarrier = 2 };

enum class ProdigyCousinCarrierKind : uint8_t {
  open = 1, openAck = 2, data = 3, fin = 4, reset = 5, window = 6
};

// One bounded reverse-carrier record.  The pair-control transport supplies
// peer authentication; this frame supplies per-session/generation fencing and
// a small explicit credit window.  Payload is intentionally capped below the
// pair-control record ceiling so control traffic cannot be starved by a data
// frame.
struct ProdigyCousinCarrierFrame {
  uint32_t protocolVersion = 1;
  ProdigyCousinCarrierKind kind = ProdigyCousinCarrierKind::open;
  uint128_t sessionUUID = 0;
  uint64_t leaseGeneration = 0;
  uint64_t sequence = 0;
  uint32_t credits = 0;
  String payload = {};
};

template <typename S>
static void serialize(S&& s, ProdigyCousinCarrierFrame& v)
{
  s.value4b(v.protocolVersion); s.value1b(v.kind); s.value16b(v.sessionUUID);
  s.value8b(v.leaseGeneration); s.value8b(v.sequence); s.value4b(v.credits);
  s.text1b(v.payload, ProdigyCousinCarrierMaximumPayloadBytes);
}

static inline bool prodigyCousinCarrierFrameValid(const ProdigyCousinCarrierFrame& v)
{
  const uint8_t kind = uint8_t(v.kind);
  if (v.protocolVersion != 1 || kind < uint8_t(ProdigyCousinCarrierKind::open) ||
      kind > uint8_t(ProdigyCousinCarrierKind::window) || v.sessionUUID == 0 ||
      v.leaseGeneration == 0 || v.sequence == 0 || v.credits > ProdigyCousinCarrierMaximumCredits ||
      v.payload.size() > ProdigyCousinCarrierMaximumPayloadBytes) return false;
  switch (v.kind) {
    case ProdigyCousinCarrierKind::open:
    case ProdigyCousinCarrierKind::openAck:
    case ProdigyCousinCarrierKind::window:
      return v.payload.empty() && v.credits != 0;
    case ProdigyCousinCarrierKind::data:
      // Data carries the sender's post-consumption remaining window.  Zero is
      // valid only for the final credit and is checked against prior state by
      // the pair-control ledger.
      return !v.payload.empty();
    case ProdigyCousinCarrierKind::fin:
    case ProdigyCousinCarrierKind::reset:
      return v.payload.empty() && v.credits == 0;
  }
  return false;
}

// The local Neuron supplies caller identity. Applications can select only a
// permission, logical slot and an already allocated Whitehole lease.
struct ProdigyCousinSessionRequest {
  uint32_t protocolVersion = 1;
  uint128_t requestUUID = 0;
  uint128_t permissionUUID = 0;
  uint64_t bindingNonce = 0;
  uint16_t slot = 0;
};

// Public, immutable identity of one ephemeral session. Neither enrollment roots
// nor application PSKs belong on the pair-control carrier.
struct ProdigyCousinSessionRouteBinding {
  // Preserve the complete authority which admitted the session. The current
  // route may advance into draining while this authority remains eligible for
  // its already-open flow, so a digest of only the new route is insufficient.
  CousinRouteRecord authorizedRoute = {};
  String authorizationSHA256 = {};
};

struct ProdigyCousinSessionRecord {
  // Version 1 did not carry route authority. It remains decodable only so
  // persisted/queued legacy messages can be rejected or retired by their
  // caller without a codec ambiguity. New sessions use version 2.
  // Keep the default v2 so existing callers cannot accidentally mint a v3
  // record without its mandatory pair-control binding.  Brain explicitly
  // selects v3 for all newly selected sessions.
  uint32_t protocolVersion = ProdigyCousinSessionDirectProtocolVersion;
  uint128_t sessionUUID = 0;
  uint128_t requestUUID = 0;
  uint64_t rootGeneration = 0;
  uint64_t keyEpoch = 0;
  uint16_t slot = 0;
  ProdigyLocalCousinServicePermission sourcePermission = {};
  uint128_t sourceContainerUUID = 0;
  uint128_t sourceNodeUUID = 0;
  uint32_t sourceContainerID = 0;
  uint16_t sourceShardGroup = 0;
  uint16_t sourceShardGroups = 0;
  uint64_t sourceService = 0;
  uint64_t sourceBindingNonce = 0;
  IPAddress sourceAddress = {};
  uint16_t sourceTCPPort = 0;
  ProdigyCousinCounterpart destination = {};
  ProdigyCousinSessionRouteBinding route = {};
  ProdigyCousinSessionTransport transport = ProdigyCousinSessionTransport::direct;
  // Oriented source-carrier -> destination-carrier endpoint pair.  These are
  // immutable v3 session identity and therefore included in digest/KDF input.
  ClusterPairControlEndpoint sourceCarrier = {}, destinationCarrier = {};
  // Compatibility storage only: a pair-control counter is local evidence and
  // never part of the v3 record, digest, or KDF context.
  uint64_t carrierConnectionID = 0;
};

static inline bool prodigyCousinSessionUsesPrivateContainerEndpoints(const ProdigyCousinSessionRecord& session)
{
  return session.protocolVersion == ProdigyCousinSessionPrivateContainerProtocolVersion &&
      session.transport == ProdigyCousinSessionTransport::direct &&
      session.route.authorizedRoute.version == 3 &&
      session.route.authorizedRoute.endpointKind == CousinRouteEndpointKind::privateContainer;
}

enum class ProdigyCousinSessionControlKind : uint8_t {
  propose = 1, ready = 2, renew = 3, revoke = 4, reject = 5
};

struct ProdigyCousinSessionControl {
  uint32_t protocolVersion = 1;
  uint64_t leaseGeneration = 1;
  ProdigyCousinSessionControlKind kind = ProdigyCousinSessionControlKind::propose;
  ProdigyCousinSessionRecord session = {};
  String failure = {};
};

struct ProdigyCousinSessionPublication {
  uint32_t protocolVersion = 1;
  uint128_t nodeUUID = 0;
  uint64_t projectionGeneration = 0;
  ClusterPairControlEndpoint localEndpoint = {}, remoteEndpoint = {};
  uint64_t connectionID = 0;
  ProdigyCousinSessionControl control = {};
};

struct ProdigyCousinSessionReceipt {
  uint32_t protocolVersion = 1;
  ClusterPairControlEndpoint localEndpoint = {}, remoteEndpoint = {};
  uint64_t projectionGeneration = 0;
  uint64_t connectionID = 0;
  uint64_t sequence = 0;
  bool disconnected = false;
  ProdigyCousinSessionControl control = {};
  // v2 local-only evidence from the authenticated, accepted control socket.
  // Never sent by the peer or included in the immutable session/KDF.
  IPAddress authenticatedSourceAddress = {};
};

// Application 6's live, persistent observation of its Truth carrier. This is
// an append-only observation payload: the Brain derives no session authority
// from it, but can reject a deployment whose authenticated application path is
// stale, disconnected, or points at another Truth writer.
struct ProdigyApp6TruthMeshReceipt {
  uint32_t protocolVersion = 1;
  uint128_t localApplicationContainerUUID = 0;
  uint128_t localClusterUUID = 0;
  uint128_t remoteClusterUUID = 0;
  uint128_t truthWriterContainerUUID = 0;
  uint128_t sessionUUID = 0;
  uint64_t commandGeneration = 0;
  uint64_t reconnectGeneration = 0;
  String lastSuccessfulRequestWatermarkSHA256 = {};
  uint128_t reverseCarrierUUID = 0;
  bool live = false;
  // v2: private direct transport is bound to the exact admitted route.
  uint128_t routeUUID = 0;
  uint64_t routeGeneration = 0;
};

enum class ProdigyCousinSessionLocalKind : uint8_t {
  install = 1, activate = 2, renew = 3, revoke = 4, reject = 5
};

// Private Brain -> local application projection. Kernel-only recipients receive
// ProdigyCousinAdmissionCommand instead, so fleet fanout never distributes PSKs.
struct ProdigyCousinSessionLocalCommand {
  uint32_t protocolVersion = 1;
  uint64_t leaseGeneration = 1;
  ProdigyCousinSessionLocalKind kind = ProdigyCousinSessionLocalKind::install;
  CousinRouteHalf localHalf = CousinRouteHalf::destination;
  uint128_t requestUUID = 0;
  uint64_t carrierConnectionID = 0;
  uint64_t carrierGeneration = 0;
  ProdigyCousinSessionRecord session = {};
  uint32_t validForMs = 0;
  std::array<uint8_t, 32> psk = {};
  String canonicalContext = {};
  String failure = {};
  // v2, destination only: exact observed carrier address, same authorized port.
  IPAddress authenticatedSourceAddress = {};
  ~ProdigyCousinSessionLocalCommand() { OPENSSL_cleanse(psk.data(), psk.size()); }
};

struct ProdigyCousinSessionLocalAck {
  uint32_t protocolVersion = 1;
  uint64_t leaseGeneration = 1;
  uint128_t sessionUUID = 0;
  ProdigyCousinSessionLocalKind kind = ProdigyCousinSessionLocalKind::install;
  bool success = false;
  String failure = {};
};

struct ProdigyCousinAdmissionCommand {
  uint32_t protocolVersion = 1;
  uint64_t leaseGeneration = 1;
  ProdigyCousinSessionRecord session = {};
  bool revoke = false;
  uint32_t validForMs = 0;
  IPAddress authenticatedSourceAddress = {};
};

struct ProdigyCousinAdmissionAck {
  static constexpr uint32_t version = 1, privateContainerVersion = 2;
  uint32_t protocolVersion = version;
  uint64_t leaseGeneration = 1;
  uint128_t sessionUUID = 0;
  uint32_t containerID = 0;
  String wormholeRevision = {};
  bool revoked = false;
  bool success = false;
  String failure = {};
};

template <typename S>
static void serialize(S&& s, ProdigyCousinSessionRequest& v)
{
  s.value4b(v.protocolVersion); s.value16b(v.requestUUID);
  s.value16b(v.permissionUUID); s.value8b(v.bindingNonce); s.value2b(v.slot);
}

template <typename S>
static void serialize(S&& s, ProdigyCousinSessionRecord& v)
{
  s.value4b(v.protocolVersion); s.value16b(v.sessionUUID); s.value16b(v.requestUUID);
  s.value8b(v.rootGeneration); s.value8b(v.keyEpoch); s.value2b(v.slot);
  s.object(v.sourcePermission); s.value16b(v.sourceContainerUUID); s.value16b(v.sourceNodeUUID);
  s.value4b(v.sourceContainerID); s.value2b(v.sourceShardGroup); s.value2b(v.sourceShardGroups);
  s.value8b(v.sourceService); s.value8b(v.sourceBindingNonce); s.object(v.sourceAddress);
  s.value2b(v.sourceTCPPort); s.object(v.destination);
  if (v.protocolVersion >= ProdigyCousinSessionDirectProtocolVersion)
  {
    s.object(v.route.authorizedRoute); s.text1b(v.route.authorizationSHA256, 64);
  }
  if (v.protocolVersion >= ProdigyCousinSessionProtocolVersion) {
    s.value1b(v.transport); s.object(v.sourceCarrier); s.object(v.destinationCarrier);
  }
}

template <typename S>
static void serialize(S&& s, ProdigyCousinSessionControl& v)
{
  s.value4b(v.protocolVersion); s.value8b(v.leaseGeneration); s.value1b(v.kind); s.object(v.session); s.text1b(v.failure, 1024);
}

template <typename S>
static void serialize(S&& s, ProdigyCousinSessionPublication& v)
{
  s.value4b(v.protocolVersion); s.value16b(v.nodeUUID); s.value8b(v.projectionGeneration);
  s.object(v.localEndpoint); s.object(v.remoteEndpoint); s.value8b(v.connectionID); s.object(v.control);
}

template <typename S>
static void serialize(S&& s, ProdigyCousinSessionReceipt& v)
{
  s.value4b(v.protocolVersion); s.object(v.localEndpoint); s.object(v.remoteEndpoint);
  s.value8b(v.projectionGeneration); s.value8b(v.connectionID); s.value8b(v.sequence);
  s.value1b(v.disconnected); s.object(v.control);
  if (v.protocolVersion >= 2) s.object(v.authenticatedSourceAddress);
}

template <typename S>
static void serialize(S&& s, ProdigyApp6TruthMeshReceipt& v)
{
  s.value4b(v.protocolVersion); s.value16b(v.localApplicationContainerUUID);
  s.value16b(v.localClusterUUID); s.value16b(v.remoteClusterUUID);
  s.value16b(v.truthWriterContainerUUID); s.value16b(v.sessionUUID);
  s.value8b(v.commandGeneration); s.value8b(v.reconnectGeneration);
  s.text1b(v.lastSuccessfulRequestWatermarkSHA256, 64); s.value16b(v.reverseCarrierUUID);
  s.value1b(v.live);
  if (v.protocolVersion >= 2) { s.value16b(v.routeUUID); s.value8b(v.routeGeneration); }
}

static inline bool prodigyApp6TruthMeshReceiptValid(const ProdigyApp6TruthMeshReceipt& v)
{
  return (v.protocolVersion == 1 || v.protocolVersion == 2) && v.localApplicationContainerUUID != 0 && v.localClusterUUID != 0 &&
      v.remoteClusterUUID != 0 &&
      v.truthWriterContainerUUID != 0 && v.sessionUUID != 0 && v.commandGeneration != 0 &&
      v.reconnectGeneration != 0 &&
      (v.protocolVersion == 1 ? v.reverseCarrierUUID != 0 :
       (v.reverseCarrierUUID == 0 && v.routeUUID != 0 && v.routeGeneration != 0)) &&
      prodigyIsSHA256HexDigest(v.lastSuccessfulRequestWatermarkSHA256);
}

// Bind a direct receipt to the exact authenticated session and lease. Live
// session and local transport checks remain the caller's responsibility.
static inline bool prodigyApp6PrivateTruthReceiptMatchesSession(
    const ProdigyApp6TruthMeshReceipt& receipt, const ProdigyCousinSessionRecord& record, uint64_t leaseGeneration)
{
  return receipt.protocolVersion == 2 && prodigyApp6TruthMeshReceiptValid(receipt) &&
      leaseGeneration == receipt.commandGeneration && leaseGeneration == receipt.reconnectGeneration &&
      record.sessionUUID == receipt.sessionUUID && record.sourceContainerUUID == receipt.localApplicationContainerUUID &&
      record.sourcePermission.localClusterUUID == receipt.localClusterUUID &&
      record.destination.permission.localClusterUUID == receipt.remoteClusterUUID &&
      record.destination.containerUUID == receipt.truthWriterContainerUUID &&
      record.route.authorizedRoute.routeUUID == receipt.routeUUID &&
      record.route.authorizedRoute.generation == receipt.routeGeneration &&
      prodigyCousinSessionUsesPrivateContainerEndpoints(record);
}

template <typename S>
static void serialize(S&& s, ProdigyCousinSessionLocalCommand& v)
{
  s.value4b(v.protocolVersion); s.value8b(v.leaseGeneration); s.value1b(v.kind); s.value1b(v.localHalf); s.value16b(v.requestUUID);
  s.object(v.session); s.value4b(v.validForMs);
  for (uint8_t& byte : v.psk) s.value1b(byte);
  s.text1b(v.canonicalContext, 64); s.text1b(v.failure, 1024);
  if (v.protocolVersion >= 2) s.object(v.authenticatedSourceAddress);
  if (v.protocolVersion >= 3) { s.value8b(v.carrierConnectionID); s.value8b(v.carrierGeneration); }
}

template <typename S>
static void serialize(S&& s, ProdigyCousinSessionLocalAck& v)
{
  s.value4b(v.protocolVersion); s.value8b(v.leaseGeneration); s.value16b(v.sessionUUID); s.value1b(v.kind);
  s.value1b(v.success); s.text1b(v.failure, 1024);
}

template <typename S>
static void serialize(S&& s, ProdigyCousinAdmissionCommand& v)
{
  s.value4b(v.protocolVersion); s.value8b(v.leaseGeneration); s.object(v.session); s.value1b(v.revoke); s.value4b(v.validForMs);
  if (v.protocolVersion >= 2) s.object(v.authenticatedSourceAddress);
}

template <typename S>
static void serialize(S&& s, ProdigyCousinAdmissionAck& v)
{
  s.value4b(v.protocolVersion); s.value8b(v.leaseGeneration); s.value16b(v.sessionUUID); s.value4b(v.containerID);
  s.text1b(v.wormholeRevision, 64); s.value1b(v.revoked); s.value1b(v.success); s.text1b(v.failure, 1024);
}

static inline bool prodigyCousinSessionRequestValid(const ProdigyCousinSessionRequest& v)
{
  return v.protocolVersion == 1 && v.requestUUID != 0 && v.permissionUUID != 0 &&
      v.bindingNonce != 0 && v.slot < nStatefulServiceGroupSlots;
}

static inline bool prodigyCousinSessionRouteBindingValid(const ProdigyCousinSessionRouteBinding& v)
{
  String digest = {};
  return v.authorizedRoute.state == CousinRouteState::active &&
      cousinRouteAuthorizationDigest(v.authorizedRoute, digest) &&
      prodigyIsSHA256HexDigest(v.authorizationSHA256) && v.authorizationSHA256 == digest;
}

static inline bool prodigyCousinSessionRouteBindingForRoute(const CousinRouteRecord& route,
                                                            ProdigyCousinSessionRouteBinding& binding)
{
  String digest = {};
  if (route.state != CousinRouteState::active || !cousinRouteAuthorizationDigest(route, digest)) return false;
  binding.authorizedRoute = route;
  binding.authorizationSHA256 = std::move(digest);
  return true;
}

static inline bool prodigyCousinSessionRouteBindingMatchesRoute(const ProdigyCousinSessionRouteBinding& binding,
                                                                 const CousinRouteRecord& route)
{
  String digest = {}, authorizedBytes = {}, routeBytes = {};
  CousinRouteRecord authorizedCopy = binding.authorizedRoute, routeCopy = route;
  return prodigyCousinSessionRouteBindingValid(binding) && cousinRouteAuthorizationDigest(route, digest) &&
      BitseryEngine::serialize(authorizedBytes, authorizedCopy) && BitseryEngine::serialize(routeBytes, routeCopy) &&
      authorizedBytes == routeBytes && binding.authorizationSHA256 == digest;
}

static inline bool prodigyCousinGlobalIPv6AddressValid(const IPAddress& address)
{
  return prodigyCousinDirectIPv6AddressValid(address) && (address.v6[0] & 0xe0u) == 0x20u;
}

static inline bool prodigyCousinNonGlobalIPv6AddressValid(const IPAddress& address)
{
  return prodigyCousinDirectIPv6AddressValid(address) && !prodigyCousinGlobalIPv6AddressValid(address);
}

static inline bool prodigyCousinSessionCarrierBindingValid(const ProdigyCousinSessionRecord& session)
{
  return clusterPairControlEndpointValid(session.sourceCarrier) &&
      clusterPairControlEndpointValid(session.destinationCarrier) &&
      session.sourceCarrier.clusterUUID == session.sourcePermission.localClusterUUID &&
      session.destinationCarrier.clusterUUID == session.destination.permission.localClusterUUID &&
      session.sourceCarrier.clusterUUID != session.destinationCarrier.clusterUUID;
}

// Reverse carrier is intentionally narrower than ordinary client authority:
// it is only the app6 client to a discovered Hot/Cold writer or the singleton
// Truth writer.  Pair-control is bidirectional: either logical data half may
// be the LAN/private initiator, but exactly one bound endpoint orientation
// must prove a non-global -> global carrier.
static inline bool prodigyCousinReverseCarrierSessionValid(const ProdigyCousinSessionRecord& session)
{
  return session.transport == ProdigyCousinSessionTransport::reverseCarrier &&
      session.sourcePermission.protocolVersion == ProdigyLocalCousinServicePermission::purposeVersion &&
      session.sourcePermission.purpose == ProdigyCousinServicePurpose::clientAuthority &&
      session.sourcePermission.localApplicationID == 6 &&
      (session.sourcePermission.peerApplicationID == 3 || session.sourcePermission.peerApplicationID == 4 ||
       session.sourcePermission.peerApplicationID == 10) &&
      session.sourcePermission.transportSourcePolicy == ProdigyCousinTransportSourcePolicy::exact &&
      session.destination.permission.localApplicationID == session.sourcePermission.peerApplicationID &&
      session.destination.permission.purpose == ProdigyCousinServicePurpose::clientAuthority &&
      (session.sourcePermission.peerApplicationID != 10 ||
       (session.destination.shardGroup == 0 && session.destination.shardGroups == 1)) &&
      prodigyCousinNonGlobalIPv6AddressValid(session.sourceAddress) &&
      prodigyCousinNonGlobalIPv6AddressValid(session.destination.publicAddress) &&
      prodigyCousinSessionCarrierBindingValid(session) &&
      (clusterPairControlEndpointNATCompatibleOutbound(session.sourceCarrier, session.destinationCarrier) ||
       clusterPairControlEndpointNATCompatibleOutbound(session.destinationCarrier, session.sourceCarrier));
}

static inline bool prodigyCousinSessionTransportSourceValid(const ProdigyCousinSessionRecord& session)
{
  if (session.sourcePermission.transportSourcePolicy == ProdigyCousinTransportSourcePolicy::exact) return true;
  return session.sourcePermission.protocolVersion == ProdigyLocalCousinServicePermission::purposeVersion &&
      session.sourcePermission.transportSourcePolicy == ProdigyCousinTransportSourcePolicy::authenticatedNAT &&
      prodigyCousinDirectIPv6AddressValid(session.sourceAddress) && (session.sourceAddress.v6[0] & 0xfeu) == 0xfcu &&
      prodigyCousinGlobalIPv6AddressValid(session.destination.publicAddress);
}

// The desired-session driver and its admission path use the same bounded gate.
// This never authorizes a caller-supplied endpoint or a legacy automatic flow.
static inline bool prodigyCousinAutomaticSessionDesired(
    const ProdigyLocalCousinServicePermission& permission, const CousinRouteRecord& route,
    bool exactLivePlanService, uint32_t usableWhiteholes, int64_t nowMs)
{
  return prodigyLocalCousinServicePermissionValid(permission) &&
      permission.protocolVersion == ProdigyLocalCousinServicePermission::purposeVersion &&
      permission.state == ProdigyLocalCousinServicePermissionState::active && permission.localHalf == CousinRouteHalf::source &&
      exactLivePlanService && usableWhiteholes == 1 && cousinRouteCurrentContract(route) &&
      cousinRouteAllowsNewAdmissionAt(route, nowMs) && route.sourcePermissionUUID == permission.permissionUUID &&
      route.pairUUID == permission.pairUUID && route.logicalWorkloadUUID == permission.logicalWorkloadUUID &&
      route.logicalServiceUUID == permission.logicalServiceUUID && route.sourceClusterUUID == permission.localClusterUUID &&
      route.destinationClusterUUID == permission.peerClusterUUID && route.sourceApplicationID == permission.localApplicationID &&
      route.destinationApplicationID == permission.peerApplicationID &&
      route.sourceCousinServicePrefix == permission.localCousinServicePrefix && route.destinationCousinServicePrefix == permission.peerCousinServicePrefix &&
      route.slots == permission.slots;
}

static inline bool prodigyCousinSessionRecordValid(const ProdigyCousinSessionRecord& v)
{
  return (v.protocolVersion == ProdigyCousinSessionLegacyProtocolVersion ||
          v.protocolVersion == ProdigyCousinSessionDirectProtocolVersion ||
          v.protocolVersion == ProdigyCousinSessionProtocolVersion ||
          v.protocolVersion == ProdigyCousinSessionPrivateContainerProtocolVersion) &&
      v.sessionUUID != 0 && v.requestUUID != 0 &&
      v.rootGeneration != 0 && v.keyEpoch != 0 && v.sourceContainerUUID != 0 && v.sourceNodeUUID != 0 &&
      v.sourceContainerID != 0 && v.sourceShardGroups != 0 &&
      v.sourceShardGroups < nStatefulServiceGroupSlots - 1 && v.sourceShardGroup < v.sourceShardGroups &&
      prodigyCousinServicePermissionGroupValid(v.sourcePermission, v.sourceShardGroup, v.sourceShardGroups) &&
      v.sourceBindingNonce != 0 && prodigyCousinDirectIPv6AddressValid(v.sourceAddress) && v.sourceTCPPort != 0 &&
      v.sourcePermission.state == ProdigyLocalCousinServicePermissionState::active &&
      prodigyCousinCounterpartMatchesPermission(v.destination, v.sourcePermission, v.slot,
          v.protocolVersion == ProdigyCousinSessionPrivateContainerProtocolVersion) &&
      v.sourceService == MeshServices::constrainPrefixToGroup(v.sourcePermission.localCousinServicePrefix, v.sourceShardGroup) &&
      statefulServiceGroupOwnerForSlot(v.slot, v.sourceShardGroups) == v.sourceShardGroup &&
      prodigyCousinSessionTransportSourceValid(v) &&
      (v.protocolVersion == ProdigyCousinSessionPrivateContainerProtocolVersion ?
          (v.route.authorizedRoute.version == 3 && v.route.authorizedRoute.endpointKind == CousinRouteEndpointKind::privateContainer &&
           v.destination.routablePrefixUUID == 0 && v.sourcePermission.transportSourcePolicy == ProdigyCousinTransportSourcePolicy::exact &&
           v.route.authorizedRoute.destinationPublicAddress.equals(v.destination.publicAddress) &&
           v.route.authorizedRoute.destinationTCPPort == v.destination.publicTCPPort &&
           v.route.authorizedRoute.sourcePermissionUUID == v.sourcePermission.permissionUUID &&
           v.route.authorizedRoute.destinationPermissionUUID == v.destination.permission.permissionUUID &&
           v.transport == ProdigyCousinSessionTransport::direct) :
          (v.route.authorizedRoute.version < 3 && v.destination.routablePrefixUUID != 0)) &&
      (v.protocolVersion == ProdigyCousinSessionLegacyProtocolVersion || prodigyCousinSessionRouteBindingValid(v.route)) &&
      (v.protocolVersion < ProdigyCousinSessionProtocolVersion ?
          v.transport == ProdigyCousinSessionTransport::direct :
          (v.transport == ProdigyCousinSessionTransport::direct ? prodigyCousinSessionCarrierBindingValid(v) :
           prodigyCousinReverseCarrierSessionValid(v)));
}

// A v1 record is structurally decodable for compatibility but can never satisfy
// this predicate, so it cannot become a current route session. A higher
// generation may preserve an immediately-prior active authority only while it
// is draining, remains in the same immutable scope/root/key epoch, and the
// originally authorized route has not expired. It never authorizes a new flow.
static inline bool prodigyCousinSessionCurrentForRoute(const ProdigyCousinSessionRecord& session,
                                                       const CousinRouteRecord& route, int64_t nowMs)
{
  if (session.protocolVersion < ProdigyCousinSessionDirectProtocolVersion || !prodigyCousinSessionRecordValid(session) ||
      !cousinRouteAllowsExistingFlowAt(route, nowMs) || session.rootGeneration != route.rootGeneration ||
      session.keyEpoch != route.keyEpoch || session.sourcePermission.pairUUID != route.pairUUID ||
      session.sourcePermission.logicalWorkloadUUID != route.logicalWorkloadUUID ||
      session.sourcePermission.logicalServiceUUID != route.logicalServiceUUID ||
      session.sourcePermission.localClusterUUID != route.sourceClusterUUID ||
      session.sourcePermission.peerClusterUUID != route.destinationClusterUUID ||
      session.sourcePermission.localApplicationID != route.sourceApplicationID ||
      session.destination.permission.localApplicationID != route.destinationApplicationID ||
      session.sourcePermission.localCousinServicePrefix != route.sourceCousinServicePrefix ||
      session.destination.permission.localCousinServicePrefix != route.destinationCousinServicePrefix ||
      !route.slots.contains(session.slot)) return false;
  if (prodigyCousinSessionRouteBindingMatchesRoute(session.route, route)) return true;
  const CousinRouteRecord& authorized = session.route.authorizedRoute;
  return route.state == CousinRouteState::draining && cousinRouteAllowsExistingFlowAt(authorized, nowMs) &&
      cousinRouteScopeMatches(authorized, route) && authorized.rootGeneration == route.rootGeneration &&
      authorized.keyEpoch == route.keyEpoch && route.generation == authorized.generation + 1 &&
      (route.operationUUID == authorized.operationUUID || cousinRouteOperationUUIDWasUsed(route, authorized.operationUUID));
}

// Unlike the existing-flow predicate above, opening a new session requires the
// exact active route that authorized it. A draining successor may preserve an
// old session but can never admit another one through that authority.
static inline bool prodigyCousinSessionCanOpenForRoute(const ProdigyCousinSessionRecord& session,
                                                       const CousinRouteRecord& route, int64_t nowMs)
{
  return prodigyCousinSessionCurrentForRoute(session, route, nowMs) &&
      cousinRouteAllowsNewAdmissionAt(route, nowMs) && prodigyCousinSessionRouteBindingMatchesRoute(session.route, route);
}

static inline bool prodigyCousinSessionDigest(const ProdigyCousinSessionRecord& session, String& digest)
{
  digest.clear();
  if (!prodigyCousinSessionRecordValid(session)) return false;
  String encoded = {}; auto copy = session;
  return BitseryEngine::serialize(encoded, copy) && encoded.size() <= ProdigyCousinSessionMaximumBytes &&
      prodigyComputeSHA256Hex(encoded, digest);
}

static inline bool prodigyCousinSessionExact(const ProdigyCousinSessionRecord& a,
                                            const ProdigyCousinSessionRecord& b)
{
  String first = {}, second = {};
  return prodigyCousinSessionDigest(a, first) && prodigyCousinSessionDigest(b, second) && first == second;
}

static inline bool prodigyCousinSessionControlValid(const ProdigyCousinSessionControl& v)
{
  const uint8_t kind = uint8_t(v.kind);
  return v.protocolVersion == 1 && v.leaseGeneration != 0 && kind >= 1 && kind <= 5 && v.failure.size() <= 1024 &&
      prodigyCousinSessionRecordValid(v.session);
}

static inline bool prodigyCousinSessionControlFromCluster(const ProdigyCousinSessionControl& v, uint128_t cluster)
{
  if (!prodigyCousinSessionControlValid(v)) return false;
  const bool source = cluster == v.session.sourcePermission.localClusterUUID;
  const bool destination = cluster == v.session.destination.permission.localClusterUUID;
  switch (v.kind) {
    case ProdigyCousinSessionControlKind::propose:
    case ProdigyCousinSessionControlKind::renew: return source;
    case ProdigyCousinSessionControlKind::ready:
    case ProdigyCousinSessionControlKind::reject: return destination;
    case ProdigyCousinSessionControlKind::revoke: return source || destination;
  }
  return false;
}

static inline bool prodigyCousinSessionPublicationValid(const ProdigyCousinSessionPublication& v)
{
  const bool endpointBound = v.control.session.protocolVersion < ProdigyCousinSessionProtocolVersion ||
      ((v.localEndpoint == v.control.session.sourceCarrier && v.remoteEndpoint == v.control.session.destinationCarrier) ||
       (v.localEndpoint == v.control.session.destinationCarrier && v.remoteEndpoint == v.control.session.sourceCarrier));
  return v.protocolVersion == 1 && v.nodeUUID != 0 && v.nodeUUID == v.localEndpoint.nodeUUID &&
      v.projectionGeneration != 0 && v.connectionID != 0 &&
      clusterPairControlEndpointValid(v.localEndpoint) && clusterPairControlEndpointValid(v.remoteEndpoint) &&
      v.localEndpoint.clusterUUID != v.remoteEndpoint.clusterUUID &&
      endpointBound &&
      prodigyCousinSessionControlFromCluster(v.control, v.localEndpoint.clusterUUID) &&
      ((v.localEndpoint.clusterUUID == v.control.session.sourcePermission.localClusterUUID &&
        v.remoteEndpoint.clusterUUID == v.control.session.destination.permission.localClusterUUID) ||
       (v.remoteEndpoint.clusterUUID == v.control.session.sourcePermission.localClusterUUID &&
        v.localEndpoint.clusterUUID == v.control.session.destination.permission.localClusterUUID));
}

static inline bool prodigyCousinSessionReceiptValid(const ProdigyCousinSessionReceipt& v)
{
  if ((v.protocolVersion != 1 && v.protocolVersion != 2) || v.projectionGeneration == 0 || v.connectionID == 0 ||
      !clusterPairControlEndpointValid(v.localEndpoint) || !clusterPairControlEndpointValid(v.remoteEndpoint) ||
      v.localEndpoint.clusterUUID == v.remoteEndpoint.clusterUUID ||
      (v.protocolVersion == 1 && !v.authenticatedSourceAddress.isNull())) return false;
  if (v.disconnected) return true;
  if (v.control.session.protocolVersion >= ProdigyCousinSessionProtocolVersion &&
      !((v.localEndpoint == v.control.session.destinationCarrier && v.remoteEndpoint == v.control.session.sourceCarrier) ||
        (v.localEndpoint == v.control.session.sourceCarrier && v.remoteEndpoint == v.control.session.destinationCarrier))) return false;
  const bool natSource = v.control.session.sourcePermission.transportSourcePolicy == ProdigyCousinTransportSourcePolicy::authenticatedNAT &&
      v.control.session.sourcePermission.localClusterUUID == v.remoteEndpoint.clusterUUID;
  if (natSource != (v.protocolVersion == 2) || (natSource &&
      (!prodigyCousinSessionTransportSourceValid(v.control.session) || !prodigyCousinGlobalIPv6AddressValid(v.authenticatedSourceAddress) ||
       v.remoteEndpoint.nodeUUID != v.control.session.sourceNodeUUID ||
       !clusterPairControlEndpointNATCompatibleOutbound(v.remoteEndpoint, v.localEndpoint)))) return false;
  ProdigyCousinSessionPublication reversed = {};
  reversed.nodeUUID = v.remoteEndpoint.nodeUUID; reversed.localEndpoint = v.remoteEndpoint;
  reversed.remoteEndpoint = v.localEndpoint; reversed.projectionGeneration = v.projectionGeneration;
  reversed.connectionID = v.connectionID; reversed.control = v.control;
  return v.sequence != 0 && prodigyCousinSessionPublicationValid(reversed);
}

static inline bool prodigyCousinDestinationSourceProjectionValid(uint32_t version,
    const ProdigyCousinSessionRecord& session, const IPAddress& authenticatedSourceAddress)
{
  if (session.sourcePermission.transportSourcePolicy == ProdigyCousinTransportSourcePolicy::exact)
    return (version == 1 || version == 3) && authenticatedSourceAddress.isNull();
  return version == 2 && prodigyCousinSessionTransportSourceValid(session) &&
      prodigyCousinGlobalIPv6AddressValid(authenticatedSourceAddress);
}

static inline bool prodigyCousinSessionLocalCommandValid(const ProdigyCousinSessionLocalCommand& v)
{
  const uint8_t kind = uint8_t(v.kind);
  if ((v.protocolVersion != 1 && v.protocolVersion != 2 && v.protocolVersion != 3) || v.leaseGeneration == 0 || kind < 1 || kind > 5 || v.requestUUID == 0 ||
      !cousinRouteHalfValid(v.localHalf) || v.failure.size() > 1024) return false;
  uint8_t key = 0;
  for (uint8_t byte : v.psk) key |= byte;
  if (v.kind == ProdigyCousinSessionLocalKind::reject)
    return v.protocolVersion == 1 && v.authenticatedSourceAddress.isNull() && !v.failure.empty() && key == 0 && v.canonicalContext.empty();
  if (!prodigyCousinSessionRecordValid(v.session) || v.requestUUID != v.session.requestUUID) return false;
  if (v.localHalf == CousinRouteHalf::source ?
      ((v.protocolVersion != 1 && v.protocolVersion != 3) || !v.authenticatedSourceAddress.isNull()) :
      !prodigyCousinDestinationSourceProjectionValid(v.protocolVersion, v.session, v.authenticatedSourceAddress)) return false;
  if (v.kind == ProdigyCousinSessionLocalKind::revoke)
    return key == 0 && v.canonicalContext.empty();
  if (v.session.transport == ProdigyCousinSessionTransport::reverseCarrier &&
      (v.protocolVersion != 3 || v.carrierConnectionID == 0 || v.carrierGeneration == 0)) return false;
  String digest = {};
  return v.validForMs != 0 && v.validForMs <= ProdigyCousinSessionLeaseMs && key != 0 &&
      prodigyCousinSessionDigest(v.session, digest) && digest == v.canonicalContext &&
      (v.kind != ProdigyCousinSessionLocalKind::install || v.localHalf == CousinRouteHalf::destination) &&
      (v.kind != ProdigyCousinSessionLocalKind::activate || v.localHalf == CousinRouteHalf::source);
}

static inline bool prodigyCousinSessionLocalAckValid(const ProdigyCousinSessionLocalAck& v)
{
  return v.protocolVersion == 1 && v.leaseGeneration != 0 && v.sessionUUID != 0 && uint8_t(v.kind) >= 1 &&
      uint8_t(v.kind) <= 4 && v.failure.size() <= 1024;
}

static inline bool prodigyCousinAdmissionCommandValid(const ProdigyCousinAdmissionCommand& v)
{
  return prodigyCousinDestinationSourceProjectionValid(v.protocolVersion, v.session, v.authenticatedSourceAddress) &&
      v.leaseGeneration != 0 && prodigyCousinSessionRecordValid(v.session) &&
      (v.revoke || (v.validForMs != 0 && v.validForMs <= ProdigyCousinSessionLeaseMs));
}

static inline bool prodigyCousinAdmissionAckValid(const ProdigyCousinAdmissionAck& v)
{
  return v.leaseGeneration != 0 && v.sessionUUID != 0 && v.containerID != 0 &&
      ((v.protocolVersion == ProdigyCousinAdmissionAck::version && prodigyIsSHA256HexDigest(v.wormholeRevision)) ||
       (v.protocolVersion == ProdigyCousinAdmissionAck::privateContainerVersion && v.wormholeRevision.empty())) &&
      v.failure.size() <= 1024;
}

static inline bool prodigyCousinSessionKeyContext(const ProdigyCousinSessionRecord& session,
                                                 ClusterPairKeyContext& context)
{
  context = {};
  if (!prodigyCousinSessionDigest(session, context.channelIdentity)) return false;
  context.scope = ClusterPairKeyScope::serviceRoute;
  context.purpose = ClusterPairKeyPurpose::serviceSessionAuthentication;
  context.logicalWorkloadUUID = session.sourcePermission.logicalWorkloadUUID;
  context.logicalServiceUUID = session.sourcePermission.logicalServiceUUID;
  context.slots.insert(session.slot);
  context.keyEpoch = session.keyEpoch;
  context.senderClusterUUID = session.sourcePermission.localClusterUUID;
  context.receiverClusterUUID = session.destination.permission.localClusterUUID;
  context.senderNodeUUID = session.sourceContainerUUID;
  context.receiverNodeUUID = session.destination.containerUUID;
  context.senderRole = session.sourceService;
  context.receiverRole = session.destination.service;
  return clusterPairKeyContextValid(context);
}
