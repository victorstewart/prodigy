#pragma once

#include <networking/includes.h>
#include <array>
#include <openssl/crypto.h>
#include <prodigy/cousin.discovery.h>
#include <prodigy/cluster.pair.keys.h>

constexpr inline uint32_t ProdigyCousinSessionMaximumRecords = 64;
constexpr inline uint32_t ProdigyCousinSessionMaximumBytes = 16384;
constexpr inline uint32_t ProdigyCousinSessionLeaseMs = 10000;
constexpr inline uint32_t ProdigyCousinSessionPendingMs = 5000;
constexpr inline uint32_t ProdigyCousinSessionRenewMs = 2000;

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
struct ProdigyCousinSessionRecord {
  uint32_t protocolVersion = 1;
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
};

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
  ProdigyCousinSessionRecord session = {};
  uint32_t validForMs = 0;
  std::array<uint8_t, 32> psk = {};
  String canonicalContext = {};
  String failure = {};
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
};

struct ProdigyCousinAdmissionAck {
  uint32_t protocolVersion = 1;
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
}

template <typename S>
static void serialize(S&& s, ProdigyCousinSessionLocalCommand& v)
{
  s.value4b(v.protocolVersion); s.value8b(v.leaseGeneration); s.value1b(v.kind); s.value1b(v.localHalf); s.value16b(v.requestUUID);
  s.object(v.session); s.value4b(v.validForMs);
  for (uint8_t& byte : v.psk) s.value1b(byte);
  s.text1b(v.canonicalContext, 64); s.text1b(v.failure, 1024);
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

static inline bool prodigyCousinSessionRecordValid(const ProdigyCousinSessionRecord& v)
{
  return v.protocolVersion == 1 && v.sessionUUID != 0 && v.requestUUID != 0 &&
      v.rootGeneration != 0 && v.keyEpoch != 0 && v.sourceContainerUUID != 0 && v.sourceNodeUUID != 0 &&
      v.sourceContainerID != 0 && v.sourceShardGroups != 0 &&
      v.sourceShardGroups < nStatefulServiceGroupSlots - 1 && v.sourceShardGroup < v.sourceShardGroups &&
      v.sourceBindingNonce != 0 && prodigyCousinDirectIPv6AddressValid(v.sourceAddress) && v.sourceTCPPort != 0 &&
      v.sourcePermission.state == ProdigyLocalCousinServicePermissionState::active &&
      prodigyCousinCounterpartMatchesPermission(v.destination, v.sourcePermission, v.slot) &&
      v.sourceService == MeshServices::constrainPrefixToGroup(v.sourcePermission.localCousinServicePrefix, v.sourceShardGroup) &&
      statefulServiceGroupOwnerForSlot(v.slot, v.sourceShardGroups) == v.sourceShardGroup;
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
  return v.protocolVersion == 1 && v.nodeUUID != 0 && v.nodeUUID == v.localEndpoint.nodeUUID &&
      v.projectionGeneration != 0 && v.connectionID != 0 &&
      clusterPairControlEndpointValid(v.localEndpoint) && clusterPairControlEndpointValid(v.remoteEndpoint) &&
      v.localEndpoint.clusterUUID != v.remoteEndpoint.clusterUUID &&
      prodigyCousinSessionControlFromCluster(v.control, v.localEndpoint.clusterUUID) &&
      ((v.localEndpoint.clusterUUID == v.control.session.sourcePermission.localClusterUUID &&
        v.remoteEndpoint.clusterUUID == v.control.session.destination.permission.localClusterUUID) ||
       (v.remoteEndpoint.clusterUUID == v.control.session.sourcePermission.localClusterUUID &&
        v.localEndpoint.clusterUUID == v.control.session.destination.permission.localClusterUUID));
}

static inline bool prodigyCousinSessionReceiptValid(const ProdigyCousinSessionReceipt& v)
{
  if (v.protocolVersion != 1 || v.projectionGeneration == 0 || v.connectionID == 0 ||
      !clusterPairControlEndpointValid(v.localEndpoint) || !clusterPairControlEndpointValid(v.remoteEndpoint) ||
      v.localEndpoint.clusterUUID == v.remoteEndpoint.clusterUUID) return false;
  if (v.disconnected) return true;
  ProdigyCousinSessionPublication reversed = {};
  reversed.nodeUUID = v.remoteEndpoint.nodeUUID; reversed.localEndpoint = v.remoteEndpoint;
  reversed.remoteEndpoint = v.localEndpoint; reversed.projectionGeneration = v.projectionGeneration;
  reversed.connectionID = v.connectionID; reversed.control = v.control;
  return v.sequence != 0 && prodigyCousinSessionPublicationValid(reversed);
}

static inline bool prodigyCousinSessionLocalCommandValid(const ProdigyCousinSessionLocalCommand& v)
{
  const uint8_t kind = uint8_t(v.kind);
  if (v.protocolVersion != 1 || v.leaseGeneration == 0 || kind < 1 || kind > 5 || v.requestUUID == 0 ||
      !cousinRouteHalfValid(v.localHalf) || v.failure.size() > 1024) return false;
  uint8_t key = 0;
  for (uint8_t byte : v.psk) key |= byte;
  if (v.kind == ProdigyCousinSessionLocalKind::reject)
    return !v.failure.empty() && key == 0 && v.canonicalContext.empty();
  if (!prodigyCousinSessionRecordValid(v.session) || v.requestUUID != v.session.requestUUID) return false;
  if (v.kind == ProdigyCousinSessionLocalKind::revoke)
    return key == 0 && v.canonicalContext.empty();
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
  return v.protocolVersion == 1 && v.leaseGeneration != 0 && prodigyCousinSessionRecordValid(v.session) &&
      (v.revoke || (v.validForMs != 0 && v.validForMs <= ProdigyCousinSessionLeaseMs));
}

static inline bool prodigyCousinAdmissionAckValid(const ProdigyCousinAdmissionAck& v)
{
  return v.protocolVersion == 1 && v.leaseGeneration != 0 && v.sessionUUID != 0 && v.containerID != 0 &&
      prodigyIsSHA256HexDigest(v.wormholeRevision) && v.failure.size() <= 1024;
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
