#pragma once

#include <cstdint>

#include <services/bitsery.h>
#include <networking/ip.h>
#include <services/prodigy.h>

#include <prodigy/cluster.pair.endpoint.h>
#include <prodigy/cousin.service.permission.h>

constexpr inline uint32_t ProdigyCousinDiscoveryMaximumRecords = 64;
constexpr inline uint32_t ProdigyCousinDiscoveryMaximumPairs = 64;
constexpr inline uint32_t ProdigyCousinDiscoveryMaximumBytes = 65536;
constexpr inline int64_t ProdigyCousinDiscoveryMaximumAgeMs = 6000;

class ProdigyCousinCounterpart {
public:
  ProdigyLocalCousinServicePermission permission = {};
  uint128_t containerUUID = 0;
  uint128_t nodeUUID = 0;
  uint32_t containerID = 0;
  uint16_t shardGroup = 0;
  uint16_t shardGroups = 0;
  uint64_t service = 0;
  uint16_t servicePort = 0;
  CousinRouteSlotBitmap ownedSlots = {};
  uint128_t routablePrefixUUID = 0;
  IPAddress publicAddress = {};
  uint16_t publicTCPPort = 0;
  String wormholeRevision = {};
};

class ProdigyCousinDiscoverySnapshot {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  uint128_t pairUUID = 0;
  uint128_t sourceClusterUUID = 0;
  uint128_t peerClusterUUID = 0;
  uint64_t rootGeneration = 0;
  uint64_t keyEpoch = 0;
  uint64_t authorityGeneration = 0;
  Vector<ProdigyCousinCounterpart> records = {};
};

class ProdigyCousinDiscoveryPublication {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  uint128_t nodeUUID = 0;
  uint64_t projectionGeneration = 0;
  ProdigyCousinDiscoverySnapshot snapshot = {};
};

class ProdigyCousinDiscoveryReceipt {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  ClusterPairControlEndpoint localEndpoint = {};
  ClusterPairControlEndpoint remoteEndpoint = {};
  uint64_t wireEpoch = 0;
  uint64_t projectionGeneration = 0;
  uint64_t connectionID = 0;
  uint64_t sequence = 0;
  bool withdrawn = false;
  ProdigyCousinDiscoverySnapshot snapshot = {};
};

class ProdigyCousinDiscoveryQuery {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  uint128_t permissionUUID = 0;
  uint16_t slot = 0;
};

class ProdigyCousinDiscoveryResponse {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  bool success = false;
  Vector<ProdigyCousinCounterpart> records = {};
  String failure = {};
};

template <typename S>
static void serialize(S&& serializer, ProdigyCousinCounterpart& value)
{
  serializer.object(value.permission);
  serializer.value16b(value.containerUUID);
  serializer.value16b(value.nodeUUID);
  serializer.value4b(value.containerID);
  serializer.value2b(value.shardGroup);
  serializer.value2b(value.shardGroups);
  serializer.value8b(value.service);
  serializer.value2b(value.servicePort);
  serializer.object(value.ownedSlots);
  serializer.value16b(value.routablePrefixUUID);
  serializer.object(value.publicAddress);
  serializer.value2b(value.publicTCPPort);
  serializer.text1b(value.wormholeRevision, 64);
}

template <typename S>
static void serialize(S&& serializer, ProdigyCousinDiscoverySnapshot& value)
{
  serializer.value4b(value.protocolVersion);
  serializer.value16b(value.pairUUID);
  serializer.value16b(value.sourceClusterUUID);
  serializer.value16b(value.peerClusterUUID);
  serializer.value8b(value.rootGeneration);
  serializer.value8b(value.keyEpoch);
  serializer.value8b(value.authorityGeneration);
  serializer.container(value.records, ProdigyCousinDiscoveryMaximumRecords,
      [](auto& nested, ProdigyCousinCounterpart& record) { nested.object(record); });
}

template <typename S>
static void serialize(S&& serializer, ProdigyCousinDiscoveryPublication& value)
{
  serializer.value4b(value.protocolVersion);
  serializer.value16b(value.nodeUUID);
  serializer.value8b(value.projectionGeneration);
  serializer.object(value.snapshot);
}

template <typename S>
static void serialize(S&& serializer, ProdigyCousinDiscoveryReceipt& value)
{
  serializer.value4b(value.protocolVersion);
  serializer.object(value.localEndpoint);
  serializer.object(value.remoteEndpoint);
  serializer.value8b(value.wireEpoch);
  serializer.value8b(value.projectionGeneration);
  serializer.value8b(value.connectionID);
  serializer.value8b(value.sequence);
  serializer.value1b(value.withdrawn);
  serializer.object(value.snapshot);
}

template <typename S>
static void serialize(S&& serializer, ProdigyCousinDiscoveryQuery& value)
{
  serializer.value4b(value.protocolVersion);
  serializer.value16b(value.permissionUUID);
  serializer.value2b(value.slot);
}

template <typename S>
static void serialize(S&& serializer, ProdigyCousinDiscoveryResponse& value)
{
  serializer.value4b(value.protocolVersion);
  serializer.value1b(value.success);
  serializer.container(value.records, ProdigyCousinDiscoveryMaximumRecords,
      [](auto& nested, ProdigyCousinCounterpart& record) { nested.object(record); });
  serializer.text1b(value.failure, 1024);
}

static inline bool prodigyCousinDirectIPv6AddressValid(const IPAddress& value)
{
  if (!value.is6 || value.isNull()) return false;
  const uint8_t *address = value.v6;
  const bool loopback = address[15] == 1 && [] (const uint8_t *bytes) {
    for (uint32_t index = 0; index < 15; ++index) if (bytes[index] != 0) return false;
    return true;
  }(address);
  const bool mappedV4 = address[0] == 0 && address[1] == 0 && address[2] == 0 && address[3] == 0 &&
      address[4] == 0 && address[5] == 0 && address[6] == 0 && address[7] == 0 && address[8] == 0 &&
      address[9] == 0 && address[10] == 0xff && address[11] == 0xff;
  const bool linkLocal = address[0] == 0xfe && (address[1] & 0xc0u) == 0x80u;
  return !loopback && !mappedV4 && !linkLocal && address[0] != 0xff;
}

static inline bool prodigyCousinCounterpartValid(const ProdigyCousinCounterpart& value)
{
  if (!prodigyLocalCousinServicePermissionValid(value.permission) ||
      value.permission.localHalf != CousinRouteHalf::destination ||
      value.permission.state != ProdigyLocalCousinServicePermissionState::active || value.containerUUID == 0 ||
      value.nodeUUID == 0 || value.containerID == 0 || value.shardGroups == 0 ||
      value.shardGroups >= nStatefulServiceGroupSlots - 1 || value.shardGroup >= value.shardGroups ||
      !MeshServices::isShard(value.service) ||
      value.service != MeshServices::constrainPrefixToGroup(value.permission.localCousinServicePrefix, value.shardGroup) ||
      value.servicePort == 0 || value.ownedSlots.empty() || value.routablePrefixUUID == 0 ||
      !prodigyCousinDirectIPv6AddressValid(value.publicAddress) || value.publicTCPPort == 0 ||
      !prodigyIsSHA256HexDigest(value.wormholeRevision)) return false;
  for (uint16_t slot = 0; slot < nStatefulServiceGroupSlots; ++slot)
  {
    const bool expected = value.permission.slots.contains(slot) &&
        statefulServiceGroupOwnerForSlot(slot, value.shardGroups) == value.shardGroup;
    if (value.ownedSlots.contains(slot) != expected) return false;
  }
  return true;
}

static inline bool prodigyCousinDiscoverySnapshotValid(const ProdigyCousinDiscoverySnapshot& snapshot)
{
  if (snapshot.protocolVersion != ProdigyCousinDiscoverySnapshot::version || snapshot.pairUUID == 0 ||
      snapshot.sourceClusterUUID == 0 || snapshot.peerClusterUUID == 0 ||
      snapshot.sourceClusterUUID == snapshot.peerClusterUUID || snapshot.rootGeneration == 0 ||
      snapshot.keyEpoch == 0 || snapshot.authorityGeneration == 0 ||
      snapshot.records.size() > ProdigyCousinDiscoveryMaximumRecords) return false;
  for (uint32_t index = 0; index < snapshot.records.size(); ++index)
  {
    const auto& record = snapshot.records[index];
    if (!prodigyCousinCounterpartValid(record) || record.permission.pairUUID != snapshot.pairUUID ||
        record.permission.localClusterUUID != snapshot.sourceClusterUUID ||
        record.permission.peerClusterUUID != snapshot.peerClusterUUID ||
        record.permission.acceptedAuthorityGeneration > snapshot.authorityGeneration) return false;
    for (uint32_t earlier = 0; earlier < index; ++earlier)
      if (snapshot.records[earlier].containerUUID == record.containerUUID &&
          snapshot.records[earlier].permission.permissionUUID == record.permission.permissionUUID) return false;
  }
  return true;
}

static inline bool prodigyCousinDiscoveryPublicationValid(const ProdigyCousinDiscoveryPublication& publication)
{
  return publication.protocolVersion == ProdigyCousinDiscoveryPublication::version && publication.nodeUUID != 0 &&
      publication.projectionGeneration != 0 && prodigyCousinDiscoverySnapshotValid(publication.snapshot);
}

static inline bool prodigyCousinDiscoveryReceiptValid(const ProdigyCousinDiscoveryReceipt& receipt)
{
  return receipt.protocolVersion == ProdigyCousinDiscoveryReceipt::version &&
      clusterPairControlEndpointValid(receipt.localEndpoint) && clusterPairControlEndpointValid(receipt.remoteEndpoint) &&
      receipt.localEndpoint.clusterUUID != receipt.remoteEndpoint.clusterUUID && receipt.wireEpoch != 0 &&
      receipt.projectionGeneration != 0 && receipt.connectionID != 0 && receipt.sequence != 0 &&
      prodigyCousinDiscoverySnapshotValid(receipt.snapshot) &&
      receipt.snapshot.sourceClusterUUID == receipt.remoteEndpoint.clusterUUID &&
      receipt.snapshot.peerClusterUUID == receipt.localEndpoint.clusterUUID &&
      receipt.snapshot.keyEpoch == receipt.wireEpoch && receipt.withdrawn == receipt.snapshot.records.empty();
}

static inline bool prodigyCousinDiscoveryQueryValid(const ProdigyCousinDiscoveryQuery& query)
{
  return query.protocolVersion == ProdigyCousinDiscoveryQuery::version && query.permissionUUID != 0 &&
      query.slot < nStatefulServiceGroupSlots;
}

static inline bool prodigyCousinCounterpartMatchesPermission(const ProdigyCousinCounterpart& counterpart,
    const ProdigyLocalCousinServicePermission& sourcePermission, uint16_t slot)
{
  if (!prodigyCousinCounterpartValid(counterpart) ||
      !prodigyLocalCousinServicePermissionValid(sourcePermission) ||
      sourcePermission.localHalf != CousinRouteHalf::source ||
      sourcePermission.state != ProdigyLocalCousinServicePermissionState::active || slot >= nStatefulServiceGroupSlots ||
      !sourcePermission.slots.contains(slot) || !counterpart.ownedSlots.contains(slot)) return false;
  const auto& destination = counterpart.permission;
  return sourcePermission.pairUUID == destination.pairUUID &&
      sourcePermission.logicalWorkloadUUID == destination.logicalWorkloadUUID &&
      sourcePermission.logicalServiceUUID == destination.logicalServiceUUID &&
      sourcePermission.localClusterUUID == destination.peerClusterUUID &&
      sourcePermission.peerClusterUUID == destination.localClusterUUID &&
      sourcePermission.localApplicationID == destination.peerApplicationID &&
      sourcePermission.peerApplicationID == destination.localApplicationID &&
      sourcePermission.localCousinServicePrefix == destination.peerCousinServicePrefix &&
      sourcePermission.peerCousinServicePrefix == destination.localCousinServicePrefix &&
      sourcePermission.slots.contains(slot) && destination.slots.contains(slot);
}
