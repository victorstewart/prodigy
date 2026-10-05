#pragma once

// Public, exact IPv6 Switchboard control endpoint identity. This is a durable
// roster descriptor, not a listener, transport credential, or NAT policy.

#include <algorithm>
#include <cstdint>

#include <networking/ip.h>
#include <services/bitsery.h>
#include <types/types.containers.h>

enum class ClusterPairControlNodeRole : uint64_t { switchboard = 1 };

struct ClusterPairControlEndpoint {
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  uint128_t clusterUUID = 0;
  uint128_t nodeUUID = 0;
  ClusterPairControlNodeRole role = ClusterPairControlNodeRole::switchboard;
  IPAddress address = {};
  uint16_t port = 0;

  bool operator==(const ClusterPairControlEndpoint& other) const
  {
    return protocolVersion == other.protocolVersion && clusterUUID == other.clusterUUID && nodeUUID == other.nodeUUID &&
        role == other.role && port == other.port && address.equals(other.address);
  }
  bool operator!=(const ClusterPairControlEndpoint& other) const { return !(*this == other); }
};

static inline bool clusterPairControlEndpointValid(const ClusterPairControlEndpoint& endpoint)
{
  if (endpoint.protocolVersion != ClusterPairControlEndpoint::version || endpoint.clusterUUID == 0 || endpoint.nodeUUID == 0 ||
      endpoint.port == 0 || endpoint.role != ClusterPairControlNodeRole::switchboard || !endpoint.address.is6 || endpoint.address.isNull()) return false;
  // Exact IPv6 tuple only: never infer a NAT or v4 mapping.
  const uint8_t *address = endpoint.address.v6;
  const bool loopback = std::all_of(address, address + 15, [](uint8_t byte) { return byte == 0; }) && address[15] == 1;
  const bool mappedV4 = std::all_of(address, address + 10, [](uint8_t byte) { return byte == 0; }) &&
                        address[10] == 0xff && address[11] == 0xff;
  const bool linkLocal = address[0] == 0xfe && (address[1] & 0xc0u) == 0x80u;
  return !loopback && !mappedV4 && !linkLocal && address[0] != 0xff;
}

static inline bool clusterPairControlEndpointEquals(const ClusterPairControlEndpoint& left,
                                                    const ClusterPairControlEndpoint& right)
{
  return left == right;
}

template <typename S>
static void serialize(S&& serializer, ClusterPairControlEndpoint& endpoint)
{
  serializer.value4b(endpoint.protocolVersion);
  serializer.value16b(endpoint.clusterUUID);
  serializer.value16b(endpoint.nodeUUID);
  uint64_t role = uint64_t(endpoint.role);
  serializer.value8b(role);
  endpoint.role = ClusterPairControlNodeRole(role);
  for (uint8_t& byte : endpoint.address.v6) serializer.value1b(byte);
  serializer.value1b(endpoint.address.is6);
  serializer.value2b(endpoint.port);
}
