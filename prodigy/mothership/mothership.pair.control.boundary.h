#pragma once

// Typed, non-secret description of a Mothership-owned test-VDC pair-control
// boundary.  The provider receives only this already-authorized description;
// it does not discover clusters, endpoints, or transport credentials.

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>

#include <prodigy/cluster.pair.authority.h>
#include <prodigy/mothership/mothership.virtual.datacenter.h>

constexpr static uint16_t mothershipPairControlBoundaryPort = 315;
constexpr static uint32_t mothershipPairControlBoundaryMaximumEndpoints = 16;

class MothershipPairControlBoundaryDescriptor {
public:
  static constexpr uint32_t version = 1;

  uint32_t protocolVersion = version;
  uint128_t operationUUID = 0;
  uint128_t firstClusterUUID = 0;
  uint128_t secondClusterUUID = 0;
  String firstWorkspace;
  String secondWorkspace;
  String firstRuntimeIdentity;
  String secondRuntimeIdentity;
  String firstPrivateIPv6Subnet;
  String secondPrivateIPv6Subnet;
  Vector<ClusterPairControlEndpoint> firstEndpoints;
  Vector<ClusterPairControlEndpoint> secondEndpoints;
  uint16_t port = 0;
};

template <typename S>
static void serialize(S&& serializer, MothershipPairControlBoundaryDescriptor& descriptor)
{
  serializer.value4b(descriptor.protocolVersion);
  serializer.value16b(descriptor.operationUUID);
  serializer.value16b(descriptor.firstClusterUUID);
  serializer.value16b(descriptor.secondClusterUUID);
  serializer.text1b(descriptor.firstWorkspace, UINT32_MAX);
  serializer.text1b(descriptor.secondWorkspace, UINT32_MAX);
  serializer.text1b(descriptor.firstRuntimeIdentity, 32);
  serializer.text1b(descriptor.secondRuntimeIdentity, 32);
  serializer.text1b(descriptor.firstPrivateIPv6Subnet, INET6_ADDRSTRLEN + 3);
  serializer.text1b(descriptor.secondPrivateIPv6Subnet, INET6_ADDRSTRLEN + 3);
  serializer.container(descriptor.firstEndpoints, mothershipPairControlBoundaryMaximumEndpoints,
      [](auto& nested, auto& endpoint) { nested.object(endpoint); });
  serializer.container(descriptor.secondEndpoints, mothershipPairControlBoundaryMaximumEndpoints,
      [](auto& nested, auto& endpoint) { nested.object(endpoint); });
  serializer.value2b(descriptor.port);
}

static inline bool mothershipPairControlBoundaryIPv6Subnet(
    const String& text, uint8_t network[16])
{
  if (text.size() < 4 || text.size() > INET6_ADDRSTRLEN + 3 || text[text.size() - 3] != '/' ||
      text[text.size() - 2] != '6' || text[text.size() - 1] != '4')
  {
    return false;
  }

  String address = text.substr(0, text.size() - 3, Copy::yes);
  if (address.empty() || inet_pton(AF_INET6, address.c_str(), network) != 1 ||
      (network[0] & 0xfeu) != 0xfcu)
  {
    return false;
  }
  for (uint32_t index = 8; index < 16; ++index)
    if (network[index] != 0) return false;

  char canonicalBuffer[INET6_ADDRSTRLEN] = {};
  if (inet_ntop(AF_INET6, network, canonicalBuffer, sizeof(canonicalBuffer)) == nullptr) return false;
  String canonical = {};
  canonical.assign(canonicalBuffer);
  canonical.append("/64"_ctv);
  return canonical == text;
}

static inline bool mothershipPairControlBoundaryAddressInSubnet(
    const ClusterPairControlEndpoint& endpoint, const uint8_t network[16])
{
  return endpoint.address.is6 && std::memcmp(endpoint.address.v6, network, 8) == 0 &&
      std::any_of(endpoint.address.v6 + 8, endpoint.address.v6 + 16,
          [](uint8_t byte) { return byte != 0; });
}

static inline bool mothershipPairControlBoundaryEndpointCSV(
    const Vector<ClusterPairControlEndpoint>& endpoints, String& csv)
{
  csv.clear();
  Vector<uint32_t> order;
  order.reserve(endpoints.size());
  for (uint32_t index = 0; index < endpoints.size(); ++index)
  {
    if (!endpoints[index].address.is6) return false;
    order.push_back(index);
  }
  std::sort(order.begin(), order.end(), [&](uint32_t left, uint32_t right) {
    return std::memcmp(endpoints[left].address.v6, endpoints[right].address.v6, 16) < 0;
  });
  for (uint32_t index = 0; index < order.size(); ++index)
  {
    if (index != 0)
    {
      if (std::memcmp(endpoints[order[index - 1]].address.v6, endpoints[order[index]].address.v6, 16) == 0) return false;
      csv.append(',');
    }
    char addressBuffer[INET6_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET6, endpoints[order[index]].address.v6, addressBuffer, sizeof(addressBuffer)) == nullptr) return false;
    csv.append(addressBuffer);
  }
  return !csv.empty();
}

static inline bool mothershipPairControlBoundaryWorkspaceTextValid(const String& workspace)
{
  if (!mothershipTestClusterWorkspaceRootValid(workspace)) return false;
  for (char byte : workspace)
    if (byte <= ' ' || byte == 0x7f) return false;
  return true;
}

static inline bool mothershipPairControlBoundaryValid(
    const MothershipPairControlBoundaryDescriptor& descriptor, String *failure = nullptr)
{
  if (failure != nullptr) failure->clear();
  auto reject = [&](const char *reason) -> bool {
    if (failure != nullptr) failure->assign(reason);
    return false;
  };
  if (descriptor.protocolVersion != MothershipPairControlBoundaryDescriptor::version || descriptor.operationUUID == 0 ||
      descriptor.firstClusterUUID == 0 || descriptor.secondClusterUUID == 0 ||
      descriptor.firstClusterUUID >= descriptor.secondClusterUUID || descriptor.port != mothershipPairControlBoundaryPort)
  {
    return reject("pair-control boundary requires canonical distinct identifiers and TCP port 315");
  }
  if (!mothershipPairControlBoundaryWorkspaceTextValid(descriptor.firstWorkspace) ||
      !mothershipPairControlBoundaryWorkspaceTextValid(descriptor.secondWorkspace) ||
      descriptor.firstWorkspace == descriptor.secondWorkspace ||
      !mothershipVirtualDatacenterPairBoundaryRuntimeValid(descriptor.firstRuntimeIdentity) ||
      !mothershipVirtualDatacenterPairBoundaryRuntimeValid(descriptor.secondRuntimeIdentity) ||
      descriptor.firstRuntimeIdentity == descriptor.secondRuntimeIdentity)
  {
    return reject("pair-control boundary has invalid workspace or runtime identity");
  }

  uint8_t firstSubnet[16] = {}, secondSubnet[16] = {};
  if (!mothershipPairControlBoundaryIPv6Subnet(descriptor.firstPrivateIPv6Subnet, firstSubnet) ||
      !mothershipPairControlBoundaryIPv6Subnet(descriptor.secondPrivateIPv6Subnet, secondSubnet) ||
      std::memcmp(firstSubnet, secondSubnet, sizeof(firstSubnet)) == 0)
  {
    return reject("pair-control boundary requires distinct canonical private IPv6 /64 subnets");
  }
  if (!prodigyClusterPairEndpointsValid(descriptor.firstEndpoints, descriptor.firstClusterUUID) ||
      !prodigyClusterPairEndpointsValid(descriptor.secondEndpoints, descriptor.secondClusterUUID))
  {
    return reject("pair-control boundary endpoints are not exact cluster rosters");
  }
  for (const auto& endpoint : descriptor.firstEndpoints)
    if (endpoint.port != descriptor.port || !mothershipPairControlBoundaryAddressInSubnet(endpoint, firstSubnet))
      return reject("first pair-control endpoint is outside its exact private IPv6 subnet");
  for (const auto& endpoint : descriptor.secondEndpoints)
    if (endpoint.port != descriptor.port || !mothershipPairControlBoundaryAddressInSubnet(endpoint, secondSubnet))
      return reject("second pair-control endpoint is outside its exact private IPv6 subnet");

  String firstCSV = {}, secondCSV = {};
  if (!mothershipPairControlBoundaryEndpointCSV(descriptor.firstEndpoints, firstCSV) ||
      !mothershipPairControlBoundaryEndpointCSV(descriptor.secondEndpoints, secondCSV))
  {
    return reject("pair-control boundary endpoint addresses are invalid or duplicate");
  }
  return true;
}

static inline bool mothershipPairControlBoundaryEqual(
    const MothershipPairControlBoundaryDescriptor& left, const MothershipPairControlBoundaryDescriptor& right)
{
  if (left.protocolVersion != right.protocolVersion || left.operationUUID != right.operationUUID ||
      left.firstClusterUUID != right.firstClusterUUID || left.secondClusterUUID != right.secondClusterUUID ||
      left.firstWorkspace != right.firstWorkspace || left.secondWorkspace != right.secondWorkspace ||
      left.firstRuntimeIdentity != right.firstRuntimeIdentity || left.secondRuntimeIdentity != right.secondRuntimeIdentity ||
      left.firstPrivateIPv6Subnet != right.firstPrivateIPv6Subnet ||
      left.secondPrivateIPv6Subnet != right.secondPrivateIPv6Subnet || left.port != right.port ||
      left.firstEndpoints.size() != right.firstEndpoints.size() || left.secondEndpoints.size() != right.secondEndpoints.size())
  {
    return false;
  }
  for (uint32_t index = 0; index < left.firstEndpoints.size(); ++index)
    if (left.firstEndpoints[index] != right.firstEndpoints[index]) return false;
  for (uint32_t index = 0; index < left.secondEndpoints.size(); ++index)
    if (left.secondEndpoints[index] != right.secondEndpoints[index]) return false;
  return true;
}

// `action` is launch, query, or remove.  The resulting vector is a complete
// provider argv tail, including the selector and all twelve typed arguments.
static inline bool mothershipPairControlBoundaryArguments(
    const MothershipPairControlBoundaryDescriptor& descriptor, const String& action, Vector<String>& arguments,
    String *failure = nullptr)
{
  arguments.clear();
  if (!mothershipPairControlBoundaryValid(descriptor, failure)) return false;
  if (action != "launch"_ctv && action != "query"_ctv && action != "remove"_ctv)
  {
    if (failure != nullptr) failure->assign("pair-control provider action is unsupported");
    return false;
  }

  String operation = {}, firstCluster = {}, secondCluster = {}, firstCSV = {}, secondCSV = {}, port = {};
  operation.assignItoh(descriptor.operationUUID);
  firstCluster.assignItoh(descriptor.firstClusterUUID);
  secondCluster.assignItoh(descriptor.secondClusterUUID);
  if (!mothershipPairControlBoundaryEndpointCSV(descriptor.firstEndpoints, firstCSV) ||
      !mothershipPairControlBoundaryEndpointCSV(descriptor.secondEndpoints, secondCSV))
  {
    if (failure != nullptr) failure->assign("pair-control endpoint CSV cannot be rendered");
    return false;
  }
  port.assignItoa(descriptor.port);

  if (action == "launch"_ctv)
  {
    arguments.push_back("--pair-control-launch"_ctv);
  }
  else
  {
    arguments.push_back("--pair-control-action"_ctv);
    arguments.push_back(action);
  }
  arguments.push_back(operation);
  arguments.push_back(firstCluster);
  arguments.push_back(secondCluster);
  arguments.push_back(descriptor.firstWorkspace);
  arguments.push_back(descriptor.secondWorkspace);
  arguments.push_back(descriptor.firstRuntimeIdentity);
  arguments.push_back(descriptor.secondRuntimeIdentity);
  arguments.push_back(descriptor.firstPrivateIPv6Subnet);
  arguments.push_back(descriptor.secondPrivateIPv6Subnet);
  arguments.push_back(firstCSV);
  arguments.push_back(secondCSV);
  arguments.push_back(port);
  return true;
}

static inline bool mothershipPairControlBoundaryPreparedReceiptValid(
    const MothershipPairControlBoundaryDescriptor& descriptor, const String& receipt)
{
  if (!mothershipPairControlBoundaryValid(descriptor)) return false;
  String operation = {}, firstCluster = {}, secondCluster = {}, expected = {};
  operation.assignItoh(descriptor.operationUUID);
  firstCluster.assignItoh(descriptor.firstClusterUUID);
  secondCluster.assignItoh(descriptor.secondClusterUUID);
  expected.snprintf<
      "PAIR_CONTROL operationID={} firstClusterUUID={} secondClusterUUID={} firstRuntimeIdentity={} secondRuntimeIdentity={} firstPrivate6Subnet={} secondPrivate6Subnet={} port=315 phase=prepared\n"_ctv>(
      operation, firstCluster, secondCluster, descriptor.firstRuntimeIdentity, descriptor.secondRuntimeIdentity,
      descriptor.firstPrivateIPv6Subnet, descriptor.secondPrivateIPv6Subnet);
  return receipt == expected;
}
