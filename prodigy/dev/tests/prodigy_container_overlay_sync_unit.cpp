#include <limits.h>
#include <networking/includes.h>
#include <services/debug.h>

#include <prodigy/neuron/neuron.h>
#include <prodigy/quic.cid.generator.h>
#include <switchboard/common/checksum.h>
#include <switchboard/kernel/structs.h>
#include <switchboard/overlay.route.h>

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

class TestSuite {
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    if (condition)
    {
      std::fprintf(stderr, "PASS: %s\n", name);
    }
    else
    {
      std::fprintf(stderr, "FAIL: %s\n", name);
      failed += 1;
    }
  }

  bool require(bool condition, const char *name)
  {
    expect(condition, name);
    return condition;
  }
};

static IPPrefix makePrefix(const char *cidr)
{
  const char *slash = std::strrchr(cidr, '/');
  if (slash == nullptr)
  {
    std::fprintf(stderr, "unable to parse cidr: %s\n", cidr);
    std::abort();
  }

  String addressText = {};
  addressText.assign(cidr, uint64_t(slash - cidr));

  IPPrefix prefix = {};
  if (ClusterMachine::parseIPAddressLiteral(addressText, prefix.network) == false)
  {
    std::fprintf(stderr, "unable to parse cidr address: %s\n", cidr);
    std::abort();
  }

  prefix.cidr = uint8_t(std::strtoul(slash + 1, nullptr, 10));
  return prefix;
}

template <typename Key, typename Value>
static bool lookupProgramMapElement(BPFProgram& program, StringType auto&& mapName, const Key& key, Value& value)
{
  bool found = false;
  program.openMap(mapName, [&](int mapFD) -> void {
    if (mapFD < 0)
    {
      return;
    }

    found = (bpf_map_lookup_elem(mapFD, &key, &value) == 0);
  });

  return found;
}

template <typename Key, typename Value>
static bool updateProgramMapElement(BPFProgram& program, StringType auto&& mapName, const Key& key, const Value& value)
{
  bool updated = false;
  program.openMap(mapName, [&](int mapFD) -> void {
    if (mapFD < 0)
    {
      return;
    }

    updated = (bpf_map_update_elem(mapFD, &key, &value, BPF_ANY) == 0);
  });

  return updated;
}

static switchboard_wormhole_egress_key makeWormholeEgressKey(uint8_t datacenterPrefix,
                                                             uint32_t containerKey,
                                                             uint16_t containerPort,
                                                             uint8_t proto)
{
  switchboard_wormhole_egress_key key;
  std::memset(&key, 0, sizeof(key));
  key.container[0] = datacenterPrefix;
  key.container[1] = static_cast<uint8_t>((containerKey >> 16) & 0xFF);
  key.container[2] = static_cast<uint8_t>((containerKey >> 8) & 0xFF);
  key.container[3] = static_cast<uint8_t>(containerKey & 0xFF);
  key.container[4] = static_cast<uint8_t>((containerKey >> 24) & 0xFF);
  key.port = htons(containerPort);
  key.proto = proto;
  return key;
}

static Vector<uint8_t> makeIPv6UDPFrame(const char *srcIPv6,
                                        const char *dstIPv6,
                                        uint16_t sourcePort,
                                        uint16_t destPort,
                                        bool includeEthernet)
{
  const size_t ethBytes = includeEthernet ? sizeof(struct ethhdr) : 0u;
  Vector<uint8_t> frame = {};
  frame.resize(ethBytes + sizeof(struct ipv6hdr) + sizeof(struct udphdr));
  std::memset(frame.data(), 0, frame.size());

  if (includeEthernet)
  {
    struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(frame.data());
    eth->h_proto = bpf_htons(ETH_P_IPV6);
  }

  struct ipv6hdr *ip6h = reinterpret_cast<struct ipv6hdr *>(frame.data() + ethBytes);
  ip6h->version = 6;
  ip6h->nexthdr = IPPROTO_UDP;
  ip6h->payload_len = htons(sizeof(struct udphdr));
  if (inet_pton(AF_INET6, srcIPv6, ip6h->saddr.s6_addr) != 1 || inet_pton(AF_INET6, dstIPv6, ip6h->daddr.s6_addr) != 1)
  {
    std::fprintf(stderr, "unable to build ipv6 test frame\n");
    std::abort();
  }

  struct udphdr *udph = reinterpret_cast<struct udphdr *>(frame.data() + ethBytes + sizeof(struct ipv6hdr));
  udph->source = htons(sourcePort);
  udph->dest = htons(destPort);
  udph->len = htons(sizeof(struct udphdr));
  return frame;
}

static void parseIPv6Bytes(const char *text, uint8_t out[16])
{
  if (inet_pton(AF_INET6, text, out) != 1)
  {
    std::fprintf(stderr, "unable to parse ipv6 test address: %s\n", text);
    std::abort();
  }
}

static in_addr parseIPv4Address(const char *text)
{
  in_addr address = {};
  if (inet_pton(AF_INET, text, &address) != 1)
  {
    std::fprintf(stderr, "unable to parse ipv4 test address: %s\n", text);
    std::abort();
  }

  return address;
}

static switchboard_wormhole_egress4_key makeWormholeEgress4Key(const char *sourceIPv4,
                                                               uint16_t containerPort,
                                                               uint8_t proto)
{
  switchboard_wormhole_egress4_key key;
  std::memset(&key, 0, sizeof(key));
  key.addr = parseIPv4Address(sourceIPv4).s_addr;
  key.port = htons(containerPort);
  key.proto = proto;
  return key;
}

static container_egress_allow_key makeContainerEgressAllowKey(const char *address, uint16_t port, uint8_t proto)
{
  container_egress_allow_key key = {};
  key.proto = proto;
  key.port = htons(port);
  key.addr = parseIPv4Address(address).s_addr;
  return key;
}

static Vector<uint8_t> makeIPv4L4FrameWithPayload(const char *srcIPv4,
                                                  const char *dstIPv4,
                                                  uint8_t proto,
                                                  uint16_t sourcePort,
                                                  uint16_t destPort,
                                                  const Vector<uint8_t>& payload)
{
  const size_t l4Size = (proto == IPPROTO_TCP) ? sizeof(struct tcphdr) : sizeof(struct udphdr);
  Vector<uint8_t> frame = {};
  frame.resize(sizeof(struct ethhdr) + sizeof(struct iphdr) + l4Size + payload.size());
  std::memset(frame.data(), 0, frame.size());

  struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(frame.data());
  eth->h_proto = bpf_htons(ETH_P_IP);

  struct iphdr *ip4 = reinterpret_cast<struct iphdr *>(eth + 1);
  ip4->version = 4;
  ip4->ihl = 5;
  ip4->ttl = 64;
  ip4->protocol = proto;
  ip4->tot_len = htons(static_cast<uint16_t>(sizeof(struct iphdr) + l4Size + payload.size()));
  ip4->saddr = parseIPv4Address(srcIPv4).s_addr;
  ip4->daddr = parseIPv4Address(dstIPv4).s_addr;

  uint8_t *l4 = reinterpret_cast<uint8_t *>(ip4 + 1);
  if (proto == IPPROTO_TCP)
  {
    struct tcphdr *tcph = reinterpret_cast<struct tcphdr *>(l4);
    tcph->source = htons(sourcePort);
    tcph->dest = htons(destPort);
    tcph->doff = 5;
    tcph->syn = 1;
    std::memcpy(tcph + 1, payload.data(), payload.size());
  }
  else
  {
    struct udphdr *udph = reinterpret_cast<struct udphdr *>(l4);
    udph->source = htons(sourcePort);
    udph->dest = htons(destPort);
    udph->len = htons(static_cast<uint16_t>(sizeof(struct udphdr) + payload.size()));
    std::memcpy(udph + 1, payload.data(), payload.size());
  }

  return frame;
}

static Vector<uint8_t> makeIPv6L4FrameWithPayload(const char *srcIPv6,
                                                  const char *dstIPv6,
                                                  uint8_t proto,
                                                  uint16_t sourcePort,
                                                  uint16_t destPort,
                                                  const Vector<uint8_t>& payload,
                                                  bool includeEthernet)
{
  const size_t ethBytes = includeEthernet ? sizeof(struct ethhdr) : 0u;
  const size_t l4Size = (proto == IPPROTO_TCP) ? sizeof(struct tcphdr) : sizeof(struct udphdr);
  Vector<uint8_t> frame = {};
  frame.resize(ethBytes + sizeof(struct ipv6hdr) + l4Size + payload.size());
  std::memset(frame.data(), 0, frame.size());

  if (includeEthernet)
  {
    struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(frame.data());
    eth->h_proto = bpf_htons(ETH_P_IPV6);
  }

  struct ipv6hdr *ip6h = reinterpret_cast<struct ipv6hdr *>(frame.data() + ethBytes);
  ip6h->version = 6;
  ip6h->nexthdr = proto;
  ip6h->hop_limit = 64;
  ip6h->payload_len = htons(static_cast<uint16_t>(l4Size + payload.size()));
  parseIPv6Bytes(srcIPv6, ip6h->saddr.s6_addr);
  parseIPv6Bytes(dstIPv6, ip6h->daddr.s6_addr);

  uint8_t *l4 = frame.data() + ethBytes + sizeof(struct ipv6hdr);
  if (proto == IPPROTO_TCP)
  {
    struct tcphdr *tcph = reinterpret_cast<struct tcphdr *>(l4);
    tcph->source = htons(sourcePort);
    tcph->dest = htons(destPort);
    tcph->doff = 5;
    tcph->syn = 1;
    std::memcpy(tcph + 1, payload.data(), payload.size());
    tcph->check = compute_ipv6_transport_checksum_portable(
        ip6h->saddr.s6_addr,
        ip6h->daddr.s6_addr,
        IPPROTO_TCP,
        tcph,
        static_cast<__u32>(sizeof(struct tcphdr) + payload.size()),
        __builtin_offsetof(struct tcphdr, check));
  }
  else
  {
    struct udphdr *udph = reinterpret_cast<struct udphdr *>(l4);
    udph->source = htons(sourcePort);
    udph->dest = htons(destPort);
    udph->len = htons(static_cast<uint16_t>(sizeof(struct udphdr) + payload.size()));
    std::memcpy(udph + 1, payload.data(), payload.size());

    udph->check = compute_ipv6_transport_checksum_portable(
        ip6h->saddr.s6_addr,
        ip6h->daddr.s6_addr,
        IPPROTO_UDP,
        udph,
        static_cast<__u32>(sizeof(struct udphdr) + payload.size()),
        __builtin_offsetof(struct udphdr, check));
  }

  return frame;
}

static Vector<uint8_t> makeIPv6UDPFrameWithPayload(const char *srcIPv6,
                                                   const char *dstIPv6,
                                                   uint16_t sourcePort,
                                                   uint16_t destPort,
                                                   const Vector<uint8_t>& payload,
                                                   bool includeEthernet)
{
  return makeIPv6L4FrameWithPayload(srcIPv6, dstIPv6, IPPROTO_UDP, sourcePort, destPort, payload, includeEthernet);
}

static Vector<uint8_t> makeIPv6QuicLongHeaderFrame(const char *srcIPv6,
                                                   const char *dstIPv6,
                                                   uint16_t sourcePort,
                                                   uint16_t destPort,
                                                   uint8_t packetType,
                                                   const ProdigyQuicCID& cid,
                                                   bool includeEthernet)
{
  if (cid.id_len == 0 || cid.id_len > QUIC_CID_LEN)
  {
    std::fprintf(stderr, "invalid quic cid length for test frame: %u\n", unsigned(cid.id_len));
    std::abort();
  }

  const size_t ethBytes = includeEthernet ? sizeof(struct ethhdr) : 0u;
  constexpr size_t quicPayloadBytes = sizeof(struct quic_long_header) + 1u;
  Vector<uint8_t> frame = {};
  frame.resize(ethBytes + sizeof(struct ipv6hdr) + sizeof(struct udphdr) + quicPayloadBytes);
  std::memset(frame.data(), 0, frame.size());

  if (includeEthernet)
  {
    struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(frame.data());
    eth->h_proto = bpf_htons(ETH_P_IPV6);
  }

  struct ipv6hdr *ip6h = reinterpret_cast<struct ipv6hdr *>(frame.data() + ethBytes);
  ip6h->version = 6;
  ip6h->nexthdr = IPPROTO_UDP;
  ip6h->hop_limit = 64;
  ip6h->payload_len = htons(static_cast<uint16_t>(sizeof(struct udphdr) + quicPayloadBytes));
  parseIPv6Bytes(srcIPv6, ip6h->saddr.s6_addr);
  parseIPv6Bytes(dstIPv6, ip6h->daddr.s6_addr);

  struct udphdr *udph = reinterpret_cast<struct udphdr *>(ip6h + 1);
  udph->source = htons(sourcePort);
  udph->dest = htons(destPort);
  udph->len = htons(static_cast<uint16_t>(sizeof(struct udphdr) + quicPayloadBytes));

  struct quic_long_header *quic = reinterpret_cast<struct quic_long_header *>(udph + 1);
  quic->flags = QUIC_V1_LONG_HEADER | packetType;
  quic->version = 1;
  quic->conn_id_lens = cid.id_len;
  std::memcpy(quic->dst_cid, cid.id, cid.id_len);
  *(reinterpret_cast<uint8_t *>(quic + 1)) = 0;

  udph->check = compute_ipv6_transport_checksum_portable(
      ip6h->saddr.s6_addr,
      ip6h->daddr.s6_addr,
      IPPROTO_UDP,
      udph,
      static_cast<__u32>(sizeof(struct udphdr) + quicPayloadBytes),
      __builtin_offsetof(struct udphdr, check));

  return frame;
}

static switchboard_wormhole_egress_key makeLookupKeyFromFrame(const Vector<uint8_t>& frame, __be16 protocol)
{
  switchboard_ipv6_skb_layout layout = {};
  if (switchboardResolveIPv6SKBLayout(frame.data(), frame.data() + frame.size(), protocol, &layout) == false)
  {
    std::fprintf(stderr, "unable to resolve ipv6 skb layout for test frame\n");
    std::abort();
  }

  switchboard_wormhole_egress_key key = {};
  const struct ipv6hdr *ip6h = reinterpret_cast<const struct ipv6hdr *>(frame.data() + layout.l3Offset);
  const __be16 *sourcePort = reinterpret_cast<const __be16 *>(frame.data() + layout.sourcePortOffset);
  std::memcpy(key.container, ip6h->saddr.s6_addr + 11, sizeof(key.container));
  key.port = *sourcePort;
  key.proto = ip6h->nexthdr;
  return key;
}

static bool wormholeEgressKeysEqual(const switchboard_wormhole_egress_key& lhs, const switchboard_wormhole_egress_key& rhs)
{
  return std::memcmp(lhs.container, rhs.container, sizeof(lhs.container)) == 0 && lhs.port == rhs.port && lhs.proto == rhs.proto;
}

class NoopNeuronIaaS final : public NeuronIaaS {
public:

  void gatherSelfData(uint128_t& uuid, String& metro, bool& isBrain, EthDevice& eth, IPAddress& private4) override
  {
    uuid = 0;
    metro.clear();
    isBrain = false;
    (void)eth;
    private4 = {};
  }

  void downloadContainerToPath(CoroutineStack *coro, uint64_t deploymentID, const String& path) override
  {
    (void)coro;
    (void)deploymentID;
    (void)path;
  }
};

class OverlayTestNeuron final : public Neuron {
public:

  NoopNeuronIaaS localIaaS = {};

  OverlayTestNeuron()
  {
    iaas = &localIaaS;
  }

  void pushContainer(Container *container) override
  {
    (void)container;
  }

  void popContainer(Container *container) override
  {
    (void)container;
  }

  bool ensureHostNetworkingReady(String *failureReport = nullptr) override
  {
    if (failureReport)
    {
      failureReport->clear();
    }
    return true;
  }

  void downloadContainer(CoroutineStack *coro, uint64_t deploymentID) override
  {
    (void)coro;
    (void)deploymentID;
  }

  void seedOverlayRoutingConfigForTest(const SwitchboardOverlayRoutingConfig& config)
  {
    overlayRoutingConfig = config;
  }

  void syncOverlayRoutingProgramsForTest(void)
  {
    syncOverlayRoutingPrograms();
  }

  void registerContainerForTest(Container *container)
  {
    containers.insert_or_assign(container->plan.uuid, container);
  }

  void unregisterContainerForTest(uint128_t uuid)
  {
    containers.erase(uuid);
  }
};

static void testContainerPeerOverlayRoutingSyncPopulatesMapsAndRemovesStaleEntries(TestSuite& suite)
{
  OverlayTestNeuron neuron = {};
  NeuronBase *previousNeuron = thisNeuron;
  thisNeuron = &neuron;

  SwitchboardOverlayRoutingConfig config = {};
  config.containerNetworkViaOverlay = true;
  config.overlaySubnets.push_back(makePrefix("198.18.55.77/12"));
  config.overlaySubnets.push_back(makePrefix("198.16.0.1/12"));
  config.overlaySubnets.push_back(makePrefix("2001:db8:abcd:1234:5678:9abc::1/64"));
  config.overlaySubnets.push_back(makePrefix("2001:db8:abcd:1234::beef/64"));

  SwitchboardOverlayMachineRoute route1 = {};
  route1.machineFragment = 0x000001u;
  route1.nextHop = IPAddress("198.51.100.44", false);
  route1.sourceAddress = IPAddress("198.51.100.10", false);
  route1.useGatewayMAC = true;

  SwitchboardOverlayMachineRoute route2 = {};
  route2.machineFragment = 0x000002u;
  route2.nextHop = IPAddress("2001:db8::44", true);
  route2.sourceAddress = IPAddress("2001:db8::10", true);
  route2.nextHopMAC = "fa:6d:18:7d:9f:5e"_ctv;

  SwitchboardOverlayMachineRoute route3 = {};
  route3.machineFragment = 0x010102u;
  route3.nextHop = IPAddress("2001:db8::45", true);
  route3.sourceAddress = IPAddress("2001:db8::11", true);
  route3.useGatewayMAC = true;

  SwitchboardOverlayMachineRoute invalidRoute = {};
  invalidRoute.machineFragment = 0;
  invalidRoute.nextHop = IPAddress("2001:db8::46", true);
  invalidRoute.sourceAddress = IPAddress("2001:db8::12", true);

  config.machineRoutes.push_back(route1);
  config.machineRoutes.push_back(route2);
  config.machineRoutes.push_back(route3);
  config.machineRoutes.push_back(invalidRoute);

  SwitchboardOverlayHostedIngressRoute hostedIngress4 = {};
  hostedIngress4.prefix = makePrefix("203.0.113.77/32");
  hostedIngress4.machineFragment = route1.machineFragment;
  config.hostedIngressRoutes.push_back(hostedIngress4);

  SwitchboardOverlayHostedIngressRoute hostedIngress6 = {};
  hostedIngress6.prefix = makePrefix("2001:db8:100::c/128");
  hostedIngress6.machineFragment = route2.machineFragment;
  config.hostedIngressRoutes.push_back(hostedIngress6);

  String objectPath = {};
  objectPath.assign(PRODIGY_TEST_BINARY_DIR);
  objectPath.append("/container.egress.router.ebpf.o"_ctv);

  BPFProgram peerProgram = {};
  Container container = {};
  container.plan.uuid = 0x8801;
  container.peer_program = &peerProgram;
  neuron.registerContainerForTest(&container);

  if (suite.require(peerProgram.load(objectPath, "ct_egress"_ctv), "container_peer_overlay_sync_loads_egress_router"))
  {
    neuron.seedOverlayRoutingConfigForTest(config);
    neuron.syncOverlayRoutingProgramsForTest();

    switchboard_overlay_config overlayConfig = {};
    peerProgram.getArrayElement("ovl_config"_ctv, 0, overlayConfig);
    suite.expect(overlayConfig.container_network_enabled == 1, "container_peer_overlay_sync_sets_overlay_enabled");

    Vector<switchboard_overlay_prefix4_key> desiredPrefixes4 = {};
    Vector<switchboard_overlay_prefix6_key> desiredPrefixes6 = {};
    switchboardBuildOverlayPrefixKeys(config.overlaySubnets, desiredPrefixes4, desiredPrefixes6);

    __u8 present = 0;
    suite.expect(desiredPrefixes4.size() == 1 && lookupProgramMapElement(peerProgram, "ovl_pfx4"_ctv, desiredPrefixes4[0], present) && present == 1,
                 "container_peer_overlay_sync_populates_ipv4_prefix_map");

    present = 0;
    suite.expect(desiredPrefixes6.size() == 1 && lookupProgramMapElement(peerProgram, "ovl_pfx6"_ctv, desiredPrefixes6[0], present) && present == 1,
                 "container_peer_overlay_sync_populates_ipv6_prefix_map");

    switchboard_overlay_machine_route routeValue = {};
    suite.expect(lookupProgramMapElement(peerProgram,
                                         "ovl_mach_full"_ctv,
                                         switchboardMakeOverlayMachineRouteKey(route2.machineFragment),
                                         routeValue),
                 "container_peer_overlay_sync_populates_full_route_map");
    suite.expect(routeValue.family == SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6, "container_peer_overlay_sync_preserves_route_family");
    suite.expect(routeValue.use_gateway_mac == 0, "container_peer_overlay_sync_preserves_direct_mac_flag");
    suite.expect(std::memcmp(routeValue.next_hop6, route2.nextHop.v6, sizeof(routeValue.next_hop6)) == 0, "container_peer_overlay_sync_preserves_route_next_hop");
    suite.expect(std::memcmp(routeValue.source6, route2.sourceAddress.v6, sizeof(routeValue.source6)) == 0, "container_peer_overlay_sync_preserves_route_source");
    const uint8_t expectedRoute2MAC[6] = {0xfa, 0x6d, 0x18, 0x7d, 0x9f, 0x5e};
    suite.expect(std::memcmp(routeValue.next_hop_mac, expectedRoute2MAC, sizeof(expectedRoute2MAC)) == 0, "container_peer_overlay_sync_preserves_route_direct_mac");

    suite.expect(lookupProgramMapElement(peerProgram,
                                         "ovl_mach_low8"_ctv,
                                         switchboardMakeOverlayMachineRouteKey(route1.machineFragment & 0xFFu),
                                         routeValue),
                 "container_peer_overlay_sync_populates_unique_low8_route");
    suite.expect(routeValue.use_gateway_mac == 1, "container_peer_overlay_sync_preserves_gateway_route_flag");
    routeValue = {};
    suite.expect(lookupProgramMapElement(peerProgram,
                                         "ovl_mach_low8"_ctv,
                                         switchboardMakeOverlayMachineRouteKey(route2.machineFragment & 0xFFu),
                                         routeValue) == false,
                 "container_peer_overlay_sync_drops_ambiguous_low8_route");

    switchboard_overlay_hosted_ingress_route4 hostedIngressValue4 = {};
    switchboard_overlay_prefix4_key hostedIngressKey4 = switchboardMakeOverlayPrefix4Key(hostedIngress4.prefix);
    suite.expect(lookupProgramMapElement(peerProgram,
                                         "ovl_host4"_ctv,
                                         hostedIngressKey4,
                                         hostedIngressValue4),
                 "container_peer_overlay_sync_populates_ipv4_hosted_ingress_route_map");
    suite.expect(hostedIngressValue4.machine_fragment == hostedIngress4.machineFragment,
                 "container_peer_overlay_sync_preserves_ipv4_hosted_ingress_machine_fragment");

    switchboard_overlay_hosted_ingress_route6 hostedIngressValue6 = {};
    switchboard_overlay_prefix6_key hostedIngressKey6 = switchboardMakeOverlayPrefix6Key(hostedIngress6.prefix);
    suite.expect(lookupProgramMapElement(peerProgram,
                                         "ovl_host6"_ctv,
                                         hostedIngressKey6,
                                         hostedIngressValue6),
                 "container_peer_overlay_sync_populates_ipv6_hosted_ingress_route_map");
    suite.expect(hostedIngressValue6.machine_fragment == hostedIngress6.machineFragment,
                 "container_peer_overlay_sync_preserves_ipv6_hosted_ingress_machine_fragment");

    SwitchboardOverlayRoutingConfig disabled = {};
    neuron.seedOverlayRoutingConfigForTest(disabled);
    neuron.syncOverlayRoutingProgramsForTest();

    overlayConfig = {};
    peerProgram.getArrayElement("ovl_config"_ctv, 0, overlayConfig);
    suite.expect(overlayConfig.container_network_enabled == 0, "container_peer_overlay_sync_clears_overlay_enabled");

    present = 0;
    suite.expect(lookupProgramMapElement(peerProgram, "ovl_pfx4"_ctv, desiredPrefixes4[0], present) == false, "container_peer_overlay_sync_removes_ipv4_prefix_map_entries");
    present = 0;
    suite.expect(lookupProgramMapElement(peerProgram, "ovl_pfx6"_ctv, desiredPrefixes6[0], present) == false, "container_peer_overlay_sync_removes_ipv6_prefix_map_entries");
    routeValue = {};
    suite.expect(lookupProgramMapElement(peerProgram,
                                         "ovl_mach_full"_ctv,
                                         switchboardMakeOverlayMachineRouteKey(route2.machineFragment),
                                         routeValue) == false,
                 "container_peer_overlay_sync_removes_full_route_map_entries");
    suite.expect(lookupProgramMapElement(peerProgram,
                                         "ovl_mach_low8"_ctv,
                                         switchboardMakeOverlayMachineRouteKey(route1.machineFragment & 0xFFu),
                                         routeValue) == false,
                 "container_peer_overlay_sync_removes_low8_route_map_entries");
    hostedIngressValue4 = {};
    suite.expect(lookupProgramMapElement(peerProgram,
                                         "ovl_host4"_ctv,
                                         hostedIngressKey4,
                                         hostedIngressValue4) == false,
                 "container_peer_overlay_sync_removes_ipv4_hosted_ingress_route_map_entries");
    hostedIngressValue6 = {};
    suite.expect(lookupProgramMapElement(peerProgram,
                                         "ovl_host6"_ctv,
                                         hostedIngressKey6,
                                         hostedIngressValue6) == false,
                 "container_peer_overlay_sync_removes_ipv6_hosted_ingress_route_map_entries");
  }

  peerProgram.close();
  container.peer_program = nullptr;
  neuron.unregisterContainerForTest(container.plan.uuid);
  thisNeuron = previousNeuron;
}

static void testContainerPeerRuntimeSyncPopulatesAndClearsWormholeEgressBindings(TestSuite& suite)
{
  String objectPath = {};
  objectPath.assign(PRODIGY_TEST_BINARY_DIR);
  objectPath.append("/container.egress.router.ebpf.o"_ctv);

  BPFProgram peerProgram = {};
  if (suite.require(peerProgram.load(objectPath, "ct_egress"_ctv), "container_peer_runtime_sync_loads_egress_router"))
  {
    SwitchboardWormholeEgressBindingEntry stale = {};
    stale.key = makeWormholeEgressKey(0xca, 0x01020305u, 9443, IPPROTO_UDP);
    suite.require(switchboardBuildWormholeEgressBinding(IPAddress("2001:db8:100::dead", true),
                                                        9443,
                                                        IPPROTO_UDP,
                                                        stale.binding),
                  "container_peer_runtime_sync_builds_stale_binding");

    Vector<SwitchboardWormholeEgressBindingEntry> staleBindings = {};
    staleBindings.push_back(stale);
    switchboardSyncWormholeEgressBindingsForProgram(&peerProgram, staleBindings, 0, "unit-stale-seed");

    switchboard_wormhole_egress_binding loadedBinding = {};
    suite.expect(lookupProgramMapElement(peerProgram,
                                         "wh_egress"_ctv,
                                         stale.key,
                                         loadedBinding),
                 "container_peer_runtime_sync_seeds_stale_binding");

    SwitchboardWormholeEgressBindingEntry desired = {};
    desired.key = makeWormholeEgressKey(0xca, 0x01020304u, 8443, IPPROTO_UDP);
    suite.require(switchboardBuildWormholeEgressBinding(IPAddress("2001:db8:100::a", true),
                                                        443,
                                                        IPPROTO_UDP,
                                                        desired.binding),
                  "container_peer_runtime_sync_builds_desired_binding");

    Vector<SwitchboardWormholeEgressBindingEntry> desiredBindings = {};
    desiredBindings.push_back(desired);
    switchboardSyncWormholeEgressBindingsForProgram(&peerProgram, desiredBindings, 0, "unit-runtime-sync");

    loadedBinding = {};
    suite.expect(lookupProgramMapElement(peerProgram,
                                         "wh_egress"_ctv,
                                         stale.key,
                                         loadedBinding) == false,
                 "container_peer_runtime_sync_removes_stale_binding");

    loadedBinding = {};
    suite.expect(lookupProgramMapElement(peerProgram,
                                         "wh_egress"_ctv,
                                         desired.key,
                                         loadedBinding),
                 "container_peer_runtime_sync_populates_desired_binding");
    const uint8_t *desiredBytes = reinterpret_cast<const uint8_t *>(&desired.key);
    suite.expect(sizeof(switchboard_wormhole_egress_key) == 10, "container_peer_runtime_sync_egress_key_has_expected_padded_size");
    suite.expect(desiredBytes[5] == 0 && desiredBytes[9] == 0,
                 "container_peer_runtime_sync_zeroes_wormhole_egress_key_padding");
    suite.expect(loadedBinding.is_ipv6 == 1, "container_peer_runtime_sync_preserves_ipv6_flag");
    suite.expect(loadedBinding.proto == IPPROTO_UDP, "container_peer_runtime_sync_preserves_protocol");
    suite.expect(ntohs(loadedBinding.port) == 443, "container_peer_runtime_sync_preserves_external_port");
    suite.expect(std::memcmp(loadedBinding.addr6, desired.binding.addr6, sizeof(loadedBinding.addr6)) == 0,
                 "container_peer_runtime_sync_preserves_external_address");

    Vector<SwitchboardWormholeEgressBindingEntry> noBindings = {};
    switchboardSyncWormholeEgressBindingsForProgram(&peerProgram, noBindings, 0, "unit-clear-sync");

    loadedBinding = {};
    suite.expect(lookupProgramMapElement(peerProgram,
                                         "wh_egress"_ctv,
                                         desired.key,
                                         loadedBinding) == false,
                 "container_peer_runtime_sync_clears_removed_bindings");
  }

  peerProgram.close();
}

static void testSystemEgressPolicyConstrainsIPv4(TestSuite& suite)
{
  OverlayTestNeuron neuron = {};
  NeuronBase *previousNeuron = thisNeuron;
  thisNeuron = &neuron;
  neuron.private4 = IPAddress("10.8.0.44", false);

  Container container = {};
  container.plan.system.kind = SystemContainerKind::mothershipTunnelProvider;
  container.plan.system.egress.address4 = 0x5db8d822u;
  container.plan.system.egress.port = 443;
  container.plan.fragment = 0x4e;

  container_network_policy policy = {};
  suite.expect(container.buildContainerNetworkPolicy(policy), "system_egress_policy_builds");
  suite.expect(policy.egressAllowlistOnly == 1, "system_egress_policy_constrains_egress");
  suite.expect(policy.requiresPublic4 == 1, "system_egress_policy_requires_ipv4");

  thisNeuron = previousNeuron;
}

static void testContainerPeerEgressRouterLoadsAfterWormholeSourceRewrite(TestSuite& suite)
{
  String objectPath = {};
  objectPath.assign(PRODIGY_TEST_BINARY_DIR);
  objectPath.append("/container.egress.router.ebpf.o"_ctv);

  BPFProgram peerProgram = {};
  suite.expect(peerProgram.load(objectPath, "ct_egress"_ctv),
               "container_peer_egress_router_loads_after_wormhole_source_rewrite");
  peerProgram.close();
}

static void testContainerPeerEgressRouterDropsPacketsOverConfiguredMTU(TestSuite& suite)
{
  String objectPath = {};
  objectPath.assign(PRODIGY_TEST_BINARY_DIR);
  objectPath.append("/container.egress.router.ebpf.o"_ctv);

  BPFProgram peerProgram = {};
  suite.expect(peerProgram.load(objectPath, "ct_egress"_ctv),
               "container_peer_egress_router_drop_over_mtu_loads_program");

  if (peerProgram.prog_fd >= 0)
  {
    container_network_policy networkPolicy = {};
    networkPolicy.interContainerMTU = 1280u;
    peerProgram.setArrayElement("ct_net_policy"_ctv, 0, networkPolicy);

    Vector<uint8_t> payload = {};
    payload.resize(1300u);
    for (uint32_t index = 0; index < payload.size(); index += 1)
    {
      payload[index] = static_cast<uint8_t>((index * 17u + 5u) & 0xffu);
    }

    Vector<uint8_t> frame = makeIPv6UDPFrameWithPayload(
        "fdf8:d94c:7c33:e26e:ca4b:f501:f454:a6ee",
        "fdf8:d94c:7c33:e26e:ca4b:f501:e160:7c7b",
        8443,
        47'156,
        payload,
        true);
    Vector<uint8_t> output = {};
    output.resize(frame.size());

    LIBBPF_OPTS(bpf_test_run_opts, opts,
                .data_in = frame.data(),
                .data_out = output.data(),
                .data_size_in = static_cast<__u32>(frame.size()),
                .data_size_out = static_cast<__u32>(output.size()),
                .repeat = 1, );

    int runResult = bpf_prog_test_run_opts(peerProgram.prog_fd, &opts);
    suite.expect(runResult == 0, "container_peer_egress_router_drop_over_mtu_test_run_succeeds");
    suite.expect(opts.retval == NETKIT_DROP,
                 "container_peer_egress_router_drop_over_mtu_returns_drop");

    __u64 oversizeDrops = 0;
    peerProgram.getArrayElement("ct_stats"_ctv, 1, oversizeDrops);
    suite.expect(oversizeDrops == 1,
                 "container_peer_egress_router_drop_over_mtu_bumps_stat");
  }

  peerProgram.close();
}

static void testContainerPeerEgressRouterEnforcesSystemAllowlist(TestSuite& suite)
{
  String objectPath = {};
  objectPath.assign(PRODIGY_TEST_BINARY_DIR);
  objectPath.append("/container.egress.router.ebpf.o"_ctv);

  BPFProgram peerProgram = {};
  suite.expect(peerProgram.load(objectPath, "ct_egress"_ctv),
               "container_peer_egress_router_system_allowlist_loads_program");

  if (peerProgram.prog_fd >= 0)
  {
    container_network_policy networkPolicy = {};
    networkPolicy.egressAllowlistOnly = 1;
    networkPolicy.interContainerMTU = 9000;
    peerProgram.setArrayElement("ct_net_policy"_ctv, 0, networkPolicy);

    __u32 nicIfidx = 77;
    peerProgram.setArrayElement("ct_dev_map"_ctv, 0, nicIfidx);

    mac localMAC = {};
    localMAC.mac[5] = 0x0a;
    peerProgram.setArrayElement("mac_map"_ctv, 0, localMAC);

    mac gatewayMAC = {};
    gatewayMAC.mac[5] = 0x01;
    peerProgram.setArrayElement("gw_mac_map"_ctv, 0, gatewayMAC);

    __u8 allowed = 1;
    container_egress_allow_key allow4 = makeContainerEgressAllowKey("93.184.216.34", 443, IPPROTO_UDP);
    suite.expect(updateProgramMapElement(peerProgram, "ct_egress_allow"_ctv, allow4, allowed),
                 "container_peer_egress_router_system_allowlist_sets_ipv4_rule");

    Vector<uint8_t> payload = {};
    payload.resize(16);
    auto runFrame = [&](const Vector<uint8_t>& frame, const char *name, Vector<uint8_t> *observed) -> int {
      Vector<uint8_t> output = {};
      output.resize(frame.size() + 64u);
      LIBBPF_OPTS(bpf_test_run_opts, opts,
                  .data_in = const_cast<uint8_t *>(frame.data()),
                  .data_out = output.data(),
                  .data_size_in = static_cast<__u32>(frame.size()),
                  .data_size_out = static_cast<__u32>(output.size()),
                  .repeat = 1, );
      int runResult = bpf_prog_test_run_opts(peerProgram.prog_fd, &opts);
      suite.expect(runResult == 0, name);
      if (runResult == 0 && observed)
      {
        *observed = output;
      }
      return runResult == 0 ? int(opts.retval) : -1;
    };

    suite.expect(runFrame(makeIPv4L4FrameWithPayload("198.51.100.10", "93.184.216.34", IPPROTO_UDP, 49'152, 443, payload),
                          "container_peer_egress_router_system_allowlist_ipv4_allowed_runs",
                          nullptr) == TC_ACT_REDIRECT,
                 "container_peer_egress_router_system_allowlist_ipv4_allowed_redirects");
    suite.expect(runFrame(makeIPv4L4FrameWithPayload("198.51.100.10", "93.184.216.34", IPPROTO_UDP, 49'152, 53, payload),
                          "container_peer_egress_router_system_allowlist_dns_denied_runs",
                          nullptr) == NETKIT_DROP,
                 "container_peer_egress_router_system_allowlist_dns_denied_drops");
    suite.expect(runFrame(makeIPv4L4FrameWithPayload("198.51.100.10", "93.184.216.34", IPPROTO_TCP, 49'152, 443, payload),
                          "container_peer_egress_router_system_allowlist_proto_denied_runs",
                          nullptr) == NETKIT_DROP,
                 "container_peer_egress_router_system_allowlist_proto_denied_drops");
    suite.expect(runFrame(makeIPv6L4FrameWithPayload("2606:4700:4700::100", "fd00::1", IPPROTO_TCP, 49'152, 8443, payload, true),
                          "container_peer_egress_router_system_allowlist_ipv6_runs",
                          nullptr) == NETKIT_DROP,
                 "container_peer_egress_router_system_allowlist_ipv6_drops");
  }

  peerProgram.close();
}

static void testWormholeEgressBindingReconcilePreservesDesiredKeysDuringStaleRemoval(TestSuite& suite)
{
  SwitchboardWormholeEgressBindingEntry desired = {};
  desired.key = makeWormholeEgressKey(0xca, 0x01020304u, 8443, IPPROTO_UDP);
  suite.require(switchboardBuildWormholeEgressBinding(IPAddress("2001:db8:100::a", true),
                                                      443,
                                                      IPPROTO_UDP,
                                                      desired.binding),
                "wormhole_egress_reconcile_builds_desired_binding");

  SwitchboardWormholeEgressBindingEntry stale = {};
  stale.key = makeWormholeEgressKey(0xca, 0x01020305u, 9443, IPPROTO_UDP);
  suite.require(switchboardBuildWormholeEgressBinding(IPAddress("2001:db8:100::b", true),
                                                      9443,
                                                      IPPROTO_UDP,
                                                      stale.binding),
                "wormhole_egress_reconcile_builds_stale_binding");

  Vector<switchboard_wormhole_egress_key> existingKeys = {};
  existingKeys.push_back(desired.key);
  existingKeys.push_back(stale.key);

  Vector<SwitchboardWormholeEgressBindingEntry> desiredBindings = {};
  desiredBindings.push_back(desired);

  struct ReconcileOp {
    bool isUpsert = false;
    switchboard_wormhole_egress_key key = {};
  };

  Vector<ReconcileOp> ops = {};
  switchboardReconcileWormholeEgressBindings(existingKeys, desiredBindings, [&](const SwitchboardWormholeEgressBindingEntry& entry) -> void {
    ReconcileOp op = {};
    op.isUpsert = true;
    op.key = entry.key;
    ops.push_back(op);
  },
                                             [&](const switchboard_wormhole_egress_key& key) -> void {
                                               ReconcileOp op = {};
                                               op.isUpsert = false;
                                               op.key = key;
                                               ops.push_back(op);
                                             });

  suite.expect(ops.size() == 2, "wormhole_egress_reconcile_emits_expected_op_count");
  suite.expect(ops.size() > 0 && ops[0].isUpsert, "wormhole_egress_reconcile_upserts_before_removals");
  suite.expect(ops.size() > 0 && switchboardWormholeEgressKeysEqual(ops[0].key, desired.key),
               "wormhole_egress_reconcile_first_upsert_targets_desired_key");
  suite.expect(ops.size() > 1 && ops[1].isUpsert == false, "wormhole_egress_reconcile_emits_stale_delete");
  suite.expect(ops.size() > 1 && switchboardWormholeEgressKeysEqual(ops[1].key, stale.key),
               "wormhole_egress_reconcile_only_deletes_stale_key");
}

static void testWormholeRewriteLayoutResolvesEthernetAndL3Frames(TestSuite& suite)
{
  const char *sourceIPv6 = "fdf8:d94c:7c33:e26e:ca4b:f501:343c:ea35";
  const char *destIPv6 = "fdf8:d94c:7c33:e26e:ca4b:f501:1cf5:e5c1";
  switchboard_wormhole_egress_key expected = makeWormholeEgressKey(0x01, 0x35343ceau, 8443, IPPROTO_UDP);

  Vector<uint8_t> ethernetFrame = makeIPv6UDPFrame(sourceIPv6, destIPv6, 8443, 55'538, true);
  switchboard_ipv6_skb_layout ethernetLayout = {};
  suite.require(switchboardResolveIPv6SKBLayout(ethernetFrame.data(),
                                                ethernetFrame.data() + ethernetFrame.size(),
                                                bpf_htons(ETH_P_IPV6),
                                                &ethernetLayout),
                "wormhole_rewrite_layout_resolves_ethernet_ipv6_frame");
  suite.expect(ethernetLayout.l3Offset == sizeof(struct ethhdr), "wormhole_rewrite_layout_ethernet_l3_offset");
  suite.expect(ethernetLayout.sourcePortOffset == sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + __builtin_offsetof(struct udphdr, source),
               "wormhole_rewrite_layout_ethernet_source_port_offset");
  switchboard_wormhole_egress_key ethernetKey = makeLookupKeyFromFrame(ethernetFrame, bpf_htons(ETH_P_IPV6));
  suite.expect(wormholeEgressKeysEqual(ethernetKey, expected), "wormhole_rewrite_layout_ethernet_lookup_key_matches_binding");

  Vector<uint8_t> l3Frame = makeIPv6UDPFrame(sourceIPv6, destIPv6, 8443, 55'538, false);
  switchboard_ipv6_skb_layout l3Layout = {};
  suite.require(switchboardResolveIPv6SKBLayout(l3Frame.data(),
                                                l3Frame.data() + l3Frame.size(),
                                                bpf_htons(ETH_P_IPV6),
                                                &l3Layout),
                "wormhole_rewrite_layout_resolves_l3_ipv6_frame");
  suite.expect(l3Layout.l3Offset == 0, "wormhole_rewrite_layout_l3_offset_zero");
  suite.expect(l3Layout.sourcePortOffset == sizeof(struct ipv6hdr) + __builtin_offsetof(struct udphdr, source),
               "wormhole_rewrite_layout_l3_source_port_offset");
  switchboard_wormhole_egress_key l3Key = makeLookupKeyFromFrame(l3Frame, bpf_htons(ETH_P_IPV6));
  suite.expect(wormholeEgressKeysEqual(l3Key, expected), "wormhole_rewrite_layout_l3_lookup_key_matches_binding");
}

static void testContainerPeerEgressRouterRewritesCrossMachineWormholeReplyForOverlay(TestSuite& suite)
{
  String objectPath = {};
  objectPath.assign(PRODIGY_TEST_BINARY_DIR);
  objectPath.append("/container.egress.router.ebpf.o"_ctv);

  BPFProgram peerProgram = {};
  suite.expect(peerProgram.load(objectPath, "ct_egress"_ctv),
               "container_peer_egress_router_cross_machine_wormhole_reply_loads_program");

  if (peerProgram.prog_fd >= 0)
  {
    local_container_subnet6 localSubnet = {};
    localSubnet.dpfx = 0x01;
    localSubnet.mpfx[0] = 0xf4;
    localSubnet.mpfx[1] = 0x54;
    localSubnet.mpfx[2] = 0xa6;
    peerProgram.setArrayElement("lc_subnet"_ctv, 0, localSubnet);

    __u32 nicIfidx = 77;
    peerProgram.setArrayElement("ct_dev_map"_ctv, 0, nicIfidx);

    mac localMAC = {};
    localMAC.mac[0] = 0x02;
    localMAC.mac[1] = 0x42;
    localMAC.mac[2] = 0xac;
    localMAC.mac[3] = 0x11;
    localMAC.mac[4] = 0x00;
    localMAC.mac[5] = 0x03;
    peerProgram.setArrayElement("mac_map"_ctv, 0, localMAC);

    mac gatewayMAC = {};
    gatewayMAC.mac[0] = 0x02;
    gatewayMAC.mac[1] = 0x42;
    gatewayMAC.mac[2] = 0xac;
    gatewayMAC.mac[3] = 0x11;
    gatewayMAC.mac[4] = 0x00;
    gatewayMAC.mac[5] = 0x01;
    peerProgram.setArrayElement("gw_mac_map"_ctv, 0, gatewayMAC);

    switchboard_overlay_config overlayConfig = {};
    overlayConfig.container_network_enabled = 1;
    peerProgram.setArrayElement("ovl_config"_ctv, 0, overlayConfig);

    switchboard_overlay_machine_route route = {};
    route.family = SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6;
    route.use_gateway_mac = 1;
    parseIPv6Bytes("fd00:10::c", route.source6);
    parseIPv6Bytes("fd00:10::a", route.next_hop6);
    switchboard_overlay_machine_route_key routeKey = switchboardMakeOverlayMachineRouteKey(0xe1607cu);
    suite.expect(updateProgramMapElement(peerProgram, "ovl_mach_full"_ctv, routeKey, route),
                 "container_peer_egress_router_cross_machine_wormhole_reply_sets_overlay_route");

    switchboard_wormhole_egress_key bindingKey = makeWormholeEgressKey(0x01, 0xeef454a6u, 8443, IPPROTO_UDP);
    switchboard_wormhole_egress_binding binding = {};
    parseIPv6Bytes("2001:db8:100::c", reinterpret_cast<uint8_t *>(binding.addr6));
    binding.port = htons(443);
    binding.proto = IPPROTO_UDP;
    binding.is_ipv6 = 1;
    suite.expect(updateProgramMapElement(peerProgram, "wh_egress"_ctv, bindingKey, binding),
                 "container_peer_egress_router_cross_machine_wormhole_reply_sets_binding");

    Vector<uint8_t> payload = {};
    payload.resize(2044u - sizeof(struct udphdr));
    for (uint32_t index = 0; index < payload.size(); index += 1)
    {
      payload[index] = static_cast<uint8_t>((index * 41u + 23u) & 0xffu);
    }

    Vector<uint8_t> frame = makeIPv6UDPFrameWithPayload(
        "fdf8:d94c:7c33:e26e:ca4b:f501:f454:a6ee",
        "fdf8:d94c:7c33:e26e:ca4b:f501:e160:7c7b",
        8443,
        47'156,
        payload,
        true);
    Vector<uint8_t> output = {};
    output.resize(frame.size() + sizeof(struct ipv6hdr) + 64u);

    LIBBPF_OPTS(bpf_test_run_opts, opts,
                .data_in = frame.data(),
                .data_out = output.data(),
                .data_size_in = static_cast<__u32>(frame.size()),
                .data_size_out = static_cast<__u32>(output.size()),
                .repeat = 1, );

    int runResult = bpf_prog_test_run_opts(peerProgram.prog_fd, &opts);
    suite.expect(runResult == 0, "container_peer_egress_router_cross_machine_wormhole_reply_test_run_succeeds");
    suite.expect(opts.retval == TC_ACT_REDIRECT,
                 "container_peer_egress_router_cross_machine_wormhole_reply_redirects_to_nic");
    suite.expect(opts.data_size_out == frame.size() + sizeof(struct ipv6hdr),
                 "container_peer_egress_router_cross_machine_wormhole_reply_adds_outer_ipv6_header");

    if (runResult == 0 && opts.data_size_out >= (sizeof(struct ethhdr) + (2u * sizeof(struct ipv6hdr)) + sizeof(struct udphdr)))
    {
      const uint8_t expectedGatewayMAC[6] = {0x02, 0x42, 0xac, 0x11, 0x00, 0x01};
      const uint8_t expectedLocalMAC[6] = {0x02, 0x42, 0xac, 0x11, 0x00, 0x03};
      uint8_t expectedOuterSrc[16] = {};
      uint8_t expectedOuterDst[16] = {};
      uint8_t expectedInnerSrc[16] = {};
      uint8_t expectedInnerDst[16] = {};
      parseIPv6Bytes("fd00:10::c", expectedOuterSrc);
      parseIPv6Bytes("fd00:10::a", expectedOuterDst);
      parseIPv6Bytes("2001:db8:100::c", expectedInnerSrc);
      parseIPv6Bytes("fdf8:d94c:7c33:e26e:ca4b:f501:e160:7c7b", expectedInnerDst);

      const struct ethhdr *eth = reinterpret_cast<const struct ethhdr *>(output.data());
      suite.expect(eth->h_proto == bpf_htons(ETH_P_IPV6),
                   "container_peer_egress_router_cross_machine_wormhole_reply_preserves_ipv6_ethertype");
      suite.expect(std::memcmp(eth->h_source, expectedLocalMAC, sizeof(expectedLocalMAC)) == 0,
                   "container_peer_egress_router_cross_machine_wormhole_reply_sets_source_mac");
      suite.expect(std::memcmp(eth->h_dest, expectedGatewayMAC, sizeof(expectedGatewayMAC)) == 0,
                   "container_peer_egress_router_cross_machine_wormhole_reply_sets_gateway_mac");

      const struct ipv6hdr *outer6 = reinterpret_cast<const struct ipv6hdr *>(output.data() + sizeof(struct ethhdr));
      suite.expect(outer6->nexthdr == IPPROTO_IPV6,
                   "container_peer_egress_router_cross_machine_wormhole_reply_wraps_inner_ipv6");
      suite.expect(std::memcmp(outer6->saddr.s6_addr, expectedOuterSrc, sizeof(expectedOuterSrc)) == 0,
                   "container_peer_egress_router_cross_machine_wormhole_reply_sets_outer_source");
      suite.expect(std::memcmp(outer6->daddr.s6_addr, expectedOuterDst, sizeof(expectedOuterDst)) == 0,
                   "container_peer_egress_router_cross_machine_wormhole_reply_sets_outer_destination");

      const struct ipv6hdr *inner6 = reinterpret_cast<const struct ipv6hdr *>(output.data() + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
      bool innerProtocolMatches = (inner6->nexthdr == IPPROTO_UDP);
      bool innerSourceNonZero = false;
      for (size_t index = 0; index < sizeof(expectedInnerSrc); index += 1)
      {
        if (inner6->saddr.s6_addr[index] != 0)
        {
          innerSourceNonZero = true;
          break;
        }
      }
      bool innerDestinationMatches = (std::memcmp(inner6->daddr.s6_addr, expectedInnerDst, sizeof(expectedInnerDst)) == 0);
      const struct udphdr *udph = reinterpret_cast<const struct udphdr *>(inner6 + 1);
      __u16 expectedChecksum = compute_ipv6_transport_checksum_portable(
          inner6->saddr.s6_addr,
          inner6->daddr.s6_addr,
          IPPROTO_UDP,
          udph,
          ntohs(udph->len),
          __builtin_offsetof(struct udphdr, check));
      bool checksumMatches = (udph->check == expectedChecksum);

      if (!innerProtocolMatches || !innerSourceNonZero || !innerDestinationMatches || !checksumMatches)
      {
        char innerSourceText[INET6_ADDRSTRLEN] = {};
        char innerDestText[INET6_ADDRSTRLEN] = {};
        char expectedDestText[INET6_ADDRSTRLEN] = {};
        (void)inet_ntop(AF_INET6, inner6->saddr.s6_addr, innerSourceText, sizeof(innerSourceText));
        (void)inet_ntop(AF_INET6, inner6->daddr.s6_addr, innerDestText, sizeof(innerDestText));
        (void)inet_ntop(AF_INET6, expectedInnerDst, expectedDestText, sizeof(expectedDestText));
        std::fprintf(stderr,
                     "container_peer_egress_router_cross_machine_wormhole_reply debug inner nexthdr=%u src=%s dst=%s expected_dst=%s udp_check=%u expected_check=%u\n",
                     unsigned(inner6->nexthdr),
                     innerSourceText,
                     innerDestText,
                     expectedDestText,
                     unsigned(ntohs(udph->check)),
                     unsigned(ntohs(expectedChecksum)));
      }

      suite.expect(innerProtocolMatches,
                   "container_peer_egress_router_cross_machine_wormhole_reply_keeps_udp_inner_protocol");
      suite.expect(innerSourceNonZero,
                   "container_peer_egress_router_cross_machine_wormhole_reply_preserves_nonzero_inner_source_address");
      suite.expect(innerDestinationMatches,
                   "container_peer_egress_router_cross_machine_wormhole_reply_preserves_inner_destination_address");
      suite.expect(ntohs(udph->source) != 0,
                   "container_peer_egress_router_cross_machine_wormhole_reply_preserves_nonzero_inner_source_port");
      suite.expect(ntohs(udph->dest) == 47'156,
                   "container_peer_egress_router_cross_machine_wormhole_reply_preserves_inner_destination_port");
      suite.expect(ntohs(udph->len) == (sizeof(struct udphdr) + payload.size()),
                   "container_peer_egress_router_cross_machine_wormhole_reply_preserves_udp_length");
      suite.expect(std::memcmp(reinterpret_cast<const uint8_t *>(udph + 1), payload.data(), payload.size()) == 0,
                   "container_peer_egress_router_cross_machine_wormhole_reply_preserves_payload");
      suite.expect(checksumMatches,
                   "container_peer_egress_router_cross_machine_wormhole_reply_recomputes_udp_checksum");
    }

    peerProgram.close();
  }
}

static void testContainerPeerEgressRouterEncapsulatesHostedIngress(TestSuite& suite, bool ipv6, uint8_t proto)
{
  const char *label = ipv6
                          ? (proto == IPPROTO_TCP ? "container_peer_egress_router_hosted_ingress_ipv6_tcp" : "container_peer_egress_router_hosted_ingress_ipv6_udp")
                          : (proto == IPPROTO_TCP ? "container_peer_egress_router_hosted_ingress_ipv4_tcp" : "container_peer_egress_router_hosted_ingress_ipv4_udp");
  auto expectNamed = [&](bool condition, const char *suffix) -> void {
    char name[256] = {};
    std::snprintf(name, sizeof(name), "%s_%s", label, suffix);
    suite.expect(condition, name);
  };

  String objectPath = {};
  objectPath.assign(PRODIGY_TEST_BINARY_DIR);
  objectPath.append("/container.egress.router.ebpf.o"_ctv);

  BPFProgram peerProgram = {};
  expectNamed(peerProgram.load(objectPath, "ct_egress"_ctv), "loads_program");

  if (peerProgram.prog_fd >= 0)
  {
    container_network_policy networkPolicy = {};
    networkPolicy.requiresPublic4 = 1;
    networkPolicy.interContainerMTU = 9000;
    peerProgram.setArrayElement("ct_net_policy"_ctv, 0, networkPolicy);

    __u32 nicIfidx = 77;
    peerProgram.setArrayElement("ct_dev_map"_ctv, 0, nicIfidx);

    mac localMAC = {};
    localMAC.mac[0] = 0x02;
    localMAC.mac[1] = 0x42;
    localMAC.mac[2] = 0xac;
    localMAC.mac[3] = 0x11;
    localMAC.mac[4] = 0x00;
    localMAC.mac[5] = 0x0a;
    peerProgram.setArrayElement("mac_map"_ctv, 0, localMAC);

    mac gatewayMAC = {};
    gatewayMAC.mac[0] = 0x02;
    gatewayMAC.mac[1] = 0x42;
    gatewayMAC.mac[2] = 0xac;
    gatewayMAC.mac[3] = 0x11;
    gatewayMAC.mac[4] = 0x00;
    gatewayMAC.mac[5] = 0x01;
    peerProgram.setArrayElement("gw_mac_map"_ctv, 0, gatewayMAC);

    const uint32_t machineFragment = 0x000002u;
    if (ipv6)
    {
      switchboard_overlay_hosted_ingress_route6 hosted = {};
      hosted.machine_fragment = machineFragment;
      switchboard_overlay_prefix6_key hostedKey = switchboardMakeOverlayPrefix6Key(makePrefix("2001:db8::1/128"));
      expectNamed(updateProgramMapElement(peerProgram, "ovl_host6"_ctv, hostedKey, hosted),
                  "sets_hosted_route");
    }
    else
    {
      switchboard_overlay_hosted_ingress_route4 hosted = {};
      hosted.machine_fragment = machineFragment;
      switchboard_overlay_prefix4_key hostedKey = switchboardMakeOverlayPrefix4Key(makePrefix("198.18.0.1/32"));
      expectNamed(updateProgramMapElement(peerProgram, "ovl_host4"_ctv, hostedKey, hosted),
                  "sets_hosted_route");
    }

    switchboard_overlay_machine_route route = {};
    route.family = SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6;
    route.use_gateway_mac = 1;
    parseIPv6Bytes("fd00:10::a", route.source6);
    parseIPv6Bytes("fd00:10::b", route.next_hop6);
    switchboard_overlay_machine_route_key routeKey = switchboardMakeOverlayMachineRouteKey(machineFragment);
    expectNamed(updateProgramMapElement(peerProgram, "ovl_mach_full"_ctv, routeKey, route),
                "sets_machine_route");

    Vector<uint8_t> payload = {};
    payload.resize(32);
    for (uint32_t index = 0; index < payload.size(); index += 1)
    {
      payload[index] = static_cast<uint8_t>((index * 17u + 9u) & 0xffu);
    }

    Vector<uint8_t> frame = ipv6
                                ? makeIPv6L4FrameWithPayload("2001:db8::77", "2001:db8::1", proto, 49'152, 443, payload, true)
                                : makeIPv4L4FrameWithPayload("198.18.0.77", "198.18.0.1", proto, 49'152, 443, payload);
    Vector<uint8_t> output = {};
    output.resize(frame.size() + sizeof(struct ipv6hdr) + 64u);

    LIBBPF_OPTS(bpf_test_run_opts, opts,
                .data_in = frame.data(),
                .data_out = output.data(),
                .data_size_in = static_cast<__u32>(frame.size()),
                .data_size_out = static_cast<__u32>(output.size()),
                .repeat = 1, );

    int runResult = bpf_prog_test_run_opts(peerProgram.prog_fd, &opts);
    expectNamed(runResult == 0, "test_run_succeeds");
    expectNamed(opts.retval == TC_ACT_REDIRECT, "redirects_to_nic");
    expectNamed(opts.data_size_out == frame.size() + sizeof(struct ipv6hdr), "adds_outer_ipv6_header");

    const size_t innerHeaderSize = ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
    const size_t transportHeaderSize = (proto == IPPROTO_TCP) ? sizeof(struct tcphdr) : sizeof(struct udphdr);
    if (runResult == 0 && opts.data_size_out >= (sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + innerHeaderSize + transportHeaderSize))
    {
      const uint8_t expectedGatewayMAC[6] = {0x02, 0x42, 0xac, 0x11, 0x00, 0x01};
      const uint8_t expectedLocalMAC[6] = {0x02, 0x42, 0xac, 0x11, 0x00, 0x0a};
      uint8_t expectedOuterSrc[16] = {};
      uint8_t expectedOuterDst[16] = {};
      parseIPv6Bytes("fd00:10::a", expectedOuterSrc);
      parseIPv6Bytes("fd00:10::b", expectedOuterDst);

      const struct ethhdr *eth = reinterpret_cast<const struct ethhdr *>(output.data());
      expectNamed(eth->h_proto == bpf_htons(ETH_P_IPV6), "sets_ipv6_ethertype");
      expectNamed(std::memcmp(eth->h_source, expectedLocalMAC, sizeof(expectedLocalMAC)) == 0,
                  "sets_source_mac");
      expectNamed(std::memcmp(eth->h_dest, expectedGatewayMAC, sizeof(expectedGatewayMAC)) == 0,
                  "sets_gateway_mac");

      const struct ipv6hdr *outer6 = reinterpret_cast<const struct ipv6hdr *>(output.data() + sizeof(struct ethhdr));
      expectNamed(outer6->nexthdr == (ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP), "sets_outer_next_header");
      expectNamed(std::memcmp(outer6->saddr.s6_addr, expectedOuterSrc, sizeof(expectedOuterSrc)) == 0,
                  "sets_outer_source");
      expectNamed(std::memcmp(outer6->daddr.s6_addr, expectedOuterDst, sizeof(expectedOuterDst)) == 0,
                  "sets_outer_destination");

      const uint8_t *transportPayload = nullptr;
      if (ipv6)
      {
        uint8_t expectedSource[16] = {};
        uint8_t expectedDestination[16] = {};
        parseIPv6Bytes("2001:db8::77", expectedSource);
        parseIPv6Bytes("2001:db8::1", expectedDestination);

        const struct ipv6hdr *inner6 = reinterpret_cast<const struct ipv6hdr *>(outer6 + 1);
        expectNamed(inner6->nexthdr == proto, "preserves_inner_protocol");
        expectNamed(std::memcmp(inner6->saddr.s6_addr, expectedSource, sizeof(expectedSource)) == 0,
                    "preserves_inner_source");
        expectNamed(std::memcmp(inner6->daddr.s6_addr, expectedDestination, sizeof(expectedDestination)) == 0,
                    "preserves_inner_destination");

        if (proto == IPPROTO_TCP)
        {
          const struct tcphdr *tcph = reinterpret_cast<const struct tcphdr *>(inner6 + 1);
          expectNamed(ntohs(tcph->source) == 49'152, "preserves_inner_source_port");
          expectNamed(ntohs(tcph->dest) == 443, "preserves_inner_destination_port");
          transportPayload = reinterpret_cast<const uint8_t *>(tcph + 1);
        }
        else
        {
          const struct udphdr *udph = reinterpret_cast<const struct udphdr *>(inner6 + 1);
          expectNamed(ntohs(udph->source) == 49'152, "preserves_inner_source_port");
          expectNamed(ntohs(udph->dest) == 443, "preserves_inner_destination_port");
          transportPayload = reinterpret_cast<const uint8_t *>(udph + 1);
        }
      }
      else
      {
        const struct iphdr *inner4 = reinterpret_cast<const struct iphdr *>(outer6 + 1);
        expectNamed(inner4->protocol == proto, "preserves_inner_protocol");
        expectNamed(inner4->saddr == parseIPv4Address("198.18.0.77").s_addr, "preserves_inner_source");
        expectNamed(inner4->daddr == parseIPv4Address("198.18.0.1").s_addr, "preserves_inner_destination");

        if (proto == IPPROTO_TCP)
        {
          const struct tcphdr *tcph = reinterpret_cast<const struct tcphdr *>(inner4 + 1);
          expectNamed(ntohs(tcph->source) == 49'152, "preserves_inner_source_port");
          expectNamed(ntohs(tcph->dest) == 443, "preserves_inner_destination_port");
          transportPayload = reinterpret_cast<const uint8_t *>(tcph + 1);
        }
        else
        {
          const struct udphdr *udph = reinterpret_cast<const struct udphdr *>(inner4 + 1);
          expectNamed(ntohs(udph->source) == 49'152, "preserves_inner_source_port");
          expectNamed(ntohs(udph->dest) == 443, "preserves_inner_destination_port");
          transportPayload = reinterpret_cast<const uint8_t *>(udph + 1);
        }
      }

      expectNamed(transportPayload != nullptr && std::memcmp(transportPayload, payload.data(), payload.size()) == 0,
                  "preserves_payload");
    }

    peerProgram.close();
  }
}

static void testContainerPeerEgressRouterRewritesIPv4WormholeSource(TestSuite& suite, uint8_t proto)
{
  const char *label = proto == IPPROTO_TCP
                          ? "container_peer_egress_router_ipv4_wormhole_source_tcp"
                          : "container_peer_egress_router_ipv4_wormhole_source_udp";
  auto expectNamed = [&](bool condition, const char *suffix) -> void {
    char name[256] = {};
    std::snprintf(name, sizeof(name), "%s_%s", label, suffix);
    suite.expect(condition, name);
  };

  String objectPath = {};
  objectPath.assign(PRODIGY_TEST_BINARY_DIR);
  objectPath.append("/container.egress.router.ebpf.o"_ctv);

  BPFProgram peerProgram = {};
  expectNamed(peerProgram.load(objectPath, "ct_egress"_ctv), "loads_program");
  if (peerProgram.prog_fd < 0)
  {
    return;
  }

  container_network_policy networkPolicy = {};
  networkPolicy.requiresPublic4 = 1;
  networkPolicy.interContainerMTU = 9000;
  peerProgram.setArrayElement("ct_net_policy"_ctv, 0, networkPolicy);

  __u32 nicIfidx = 77;
  peerProgram.setArrayElement("ct_dev_map"_ctv, 0, nicIfidx);

  mac localMAC = {};
  localMAC.mac[0] = 0x02;
  localMAC.mac[1] = 0x42;
  localMAC.mac[2] = 0xac;
  localMAC.mac[3] = 0x11;
  localMAC.mac[4] = 0x00;
  localMAC.mac[5] = 0x0a;
  peerProgram.setArrayElement("mac_map"_ctv, 0, localMAC);

  mac gatewayMAC = {};
  gatewayMAC.mac[0] = 0x02;
  gatewayMAC.mac[1] = 0x42;
  gatewayMAC.mac[2] = 0xac;
  gatewayMAC.mac[3] = 0x11;
  gatewayMAC.mac[4] = 0x00;
  gatewayMAC.mac[5] = 0x01;
  peerProgram.setArrayElement("gw_mac_map"_ctv, 0, gatewayMAC);

  switchboard_wormhole_egress4_key bindingKey = makeWormholeEgress4Key("198.18.0.1", 8443, proto);
  switchboard_wormhole_egress_binding binding = {};
  binding.addr4 = parseIPv4Address("198.18.0.1").s_addr;
  binding.port = htons(443);
  binding.proto = proto;
  binding.is_ipv6 = 0;
  expectNamed(updateProgramMapElement(peerProgram, "wh_egress4"_ctv, bindingKey, binding),
              "sets_ipv4_binding");

  Vector<uint8_t> payload = {};
  payload.resize(32);
  for (uint32_t index = 0; index < payload.size(); index += 1)
  {
    payload[index] = static_cast<uint8_t>((index * 19u + 3u) & 0xffu);
  }

  Vector<uint8_t> frame = makeIPv4L4FrameWithPayload(
      "198.18.0.1",
      "10.0.0.1",
      proto,
      8443,
      49'152,
      payload);
  Vector<uint8_t> output = {};
  output.resize(frame.size() + 64u);

  LIBBPF_OPTS(bpf_test_run_opts, opts,
              .data_in = frame.data(),
              .data_out = output.data(),
              .data_size_in = static_cast<__u32>(frame.size()),
              .data_size_out = static_cast<__u32>(output.size()),
              .repeat = 1, );

  int runResult = bpf_prog_test_run_opts(peerProgram.prog_fd, &opts);
  expectNamed(runResult == 0, "test_run_succeeds");
  expectNamed(opts.retval == TC_ACT_REDIRECT, "redirects_to_nic");
  expectNamed(opts.data_size_out == frame.size(), "keeps_packet_size");

  if (runResult == 0 && opts.data_size_out >= sizeof(struct ethhdr) + sizeof(struct iphdr))
  {
    const struct ethhdr *eth = reinterpret_cast<const struct ethhdr *>(output.data());
    const struct iphdr *ip4 = reinterpret_cast<const struct iphdr *>(eth + 1);
    expectNamed(eth->h_proto == bpf_htons(ETH_P_IP), "keeps_ipv4_ethertype");
    expectNamed(ip4->saddr == parseIPv4Address("198.18.0.1").s_addr, "keeps_external_source_address");
    expectNamed(ip4->daddr == parseIPv4Address("10.0.0.1").s_addr, "keeps_client_destination_address");

    const uint8_t *transportPayload = nullptr;
    if (proto == IPPROTO_TCP)
    {
      const struct tcphdr *tcph = reinterpret_cast<const struct tcphdr *>(ip4 + 1);
      expectNamed(ntohs(tcph->source) == 443, "rewrites_source_port");
      expectNamed(ntohs(tcph->dest) == 49'152, "keeps_destination_port");
      transportPayload = reinterpret_cast<const uint8_t *>(tcph + 1);
    }
    else
    {
      const struct udphdr *udph = reinterpret_cast<const struct udphdr *>(ip4 + 1);
      expectNamed(ntohs(udph->source) == 443, "rewrites_source_port");
      expectNamed(ntohs(udph->dest) == 49'152, "keeps_destination_port");
      transportPayload = reinterpret_cast<const uint8_t *>(udph + 1);
    }

    expectNamed(transportPayload != nullptr && std::memcmp(transportPayload, payload.data(), payload.size()) == 0,
                "preserves_payload");
  }

  peerProgram.close();
}

static void testContainerPeerEgressRouterRoutesIPv6QuicHighSlotPortal(TestSuite& suite)
{
  const char *label = "container_peer_egress_router_ipv6_quic_high_slot_portal";
  auto expectNamed = [&](bool condition, const char *suffix) -> void {
    char name[256] = {};
    std::snprintf(name, sizeof(name), "%s_%s", label, suffix);
    suite.expect(condition, name);
  };

  String objectPath = {};
  objectPath.assign(PRODIGY_TEST_BINARY_DIR);
  objectPath.append("/container.egress.router.ebpf.o"_ctv);

  BPFProgram peerProgram = {};
  expectNamed(peerProgram.load(objectPath, "ct_egress"_ctv), "loads_program");
  if (peerProgram.prog_fd < 0)
  {
    return;
  }

  local_container_subnet6 localSubnet = {};
  localSubnet.dpfx = 0x01;
  localSubnet.mpfx[0] = 0xfb;
  localSubnet.mpfx[1] = 0xde;
  localSubnet.mpfx[2] = 0xab;
  peerProgram.setArrayElement("lc_subnet"_ctv, 0, localSubnet);

  container_network_policy networkPolicy = {};
  networkPolicy.interContainerMTU = 9000u;
  peerProgram.setArrayElement("ct_net_policy"_ctv, 0, networkPolicy);

  __u32 nicIfidx = 77;
  peerProgram.setArrayElement("ct_dev_map"_ctv, 0, nicIfidx);

  mac localMAC = {};
  localMAC.mac[0] = 0x02;
  localMAC.mac[1] = 0x42;
  localMAC.mac[2] = 0xac;
  localMAC.mac[3] = 0x11;
  localMAC.mac[4] = 0x00;
  localMAC.mac[5] = 0x0a;
  peerProgram.setArrayElement("mac_map"_ctv, 0, localMAC);

  mac gatewayMAC = {};
  gatewayMAC.mac[0] = 0x02;
  gatewayMAC.mac[1] = 0x42;
  gatewayMAC.mac[2] = 0xac;
  gatewayMAC.mac[3] = 0x11;
  gatewayMAC.mac[4] = 0x00;
  gatewayMAC.mac[5] = 0x01;
  peerProgram.setArrayElement("gw_mac_map"_ctv, 0, gatewayMAC);

  switchboard_overlay_config overlayConfig = {};
  overlayConfig.container_network_enabled = 1;
  peerProgram.setArrayElement("ovl_config"_ctv, 0, overlayConfig);

  switchboard_overlay_machine_route route = {};
  route.family = SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6;
  route.use_gateway_mac = 1;
  parseIPv6Bytes("fd00:10::c", route.source6);
  parseIPv6Bytes("fd00:10::d", route.next_hop6);
  switchboard_overlay_machine_route_key routeKey = switchboardMakeOverlayMachineRouteKey(0xad8c51u);
  expectNamed(updateProgramMapElement(peerProgram, "ovl_mach_full"_ctv, routeKey, route),
              "sets_remote_app_overlay_route");

  uint8_t appContainerID[5] = {0x01, 0xad, 0x8c, 0x51, 0xb9};
  uint8_t external6[16] = {};
  parseIPv6Bytes("2602:fac0:0:12ab:34cd::1", external6);

  uint8_t key[16] = {
      0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
      0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01};
  ProdigyQuicCidEncryptor encryptor = {};
  expectNamed(encryptor.setKey(key), "encryptor_accepts_key");

  struct sockaddr_in6 cidDestination = {};
  cidDestination.sin6_family = AF_INET6;
  cidDestination.sin6_port = htons(443);
  std::memcpy(cidDestination.sin6_addr.s6_addr, external6, sizeof(cidDestination.sin6_addr.s6_addr));

  uint32_t nonceCursor = 11;
  ProdigyQuicCID cid = prodigyGenerateQuicCID(encryptor,
                                              appContainerID,
                                              &nonceCursor,
                                              reinterpret_cast<const struct sockaddr *>(&cidDestination));
  expectNamed(cid.id_len == QUIC_CID_LEN, "generates_ipv6_cid");

  portal_definition portal = {};
  std::memcpy(portal.addr6, external6, sizeof(portal.addr6));
  portal.port = htons(443);
  portal.proto = IPPROTO_UDP;

  portal_meta meta = {};
  meta.flags = F_QUIC_PORTAL;
  meta.slot = 1020u;
  expectNamed(updateProgramMapElement(peerProgram, "ext_portals"_ctv, portal, meta),
              "installs_high_slot_quic_portal");

  switchboard_wormhole_target_key targetKey = {};
  targetKey.slot = meta.slot;
  std::memcpy(targetKey.container, appContainerID, sizeof(targetKey.container));
  uint16_t targetPort = htons(8443);
  expectNamed(updateProgramMapElement(peerProgram, "wh_targets"_ctv, targetKey, targetPort),
              "installs_target_container_port");

  struct
  {
    uint32_t rk[44];
  } aesState = {};
  expectNamed(prodigyBuildQuicCidDecryptRoundKeys(key, aesState.rk),
              "builds_decrypt_state");

  uint32_t decryptIndex = quicCidPortalDecryptMapIndex(meta.slot, quicCidEncryptedKeyIndex(cid.id));
  expectNamed(updateProgramMapElement(peerProgram, "quic_cid_dec"_ctv, decryptIndex, aesState),
              "installs_high_slot_decrypt_state");

  Vector<uint8_t> frame = makeIPv6QuicLongHeaderFrame(
      "fdf8:d94c:7c33:e26e:ca4b:f501:fbde:ab7e",
      "2602:fac0:0:12ab:34cd::1",
      41'252,
      443,
      QUIC_V1_HANDSHAKE,
      cid,
      true);
  Vector<uint8_t> output = {};
  output.resize(frame.size() + sizeof(struct ipv6hdr) + 64u);

  LIBBPF_OPTS(bpf_test_run_opts, opts,
              .data_in = frame.data(),
              .data_out = output.data(),
              .data_size_in = static_cast<__u32>(frame.size()),
              .data_size_out = static_cast<__u32>(output.size()),
              .repeat = 1, );

  int runResult = bpf_prog_test_run_opts(peerProgram.prog_fd, &opts);
  expectNamed(runResult == 0, "test_run_succeeds");
  if (runResult == 0 && (opts.retval != TC_ACT_REDIRECT || opts.data_size_out != frame.size() + sizeof(struct ipv6hdr)))
  {
    __u64 stats[8] = {};
    for (uint32_t index = 0; index < 8; ++index)
    {
      peerProgram.getArrayElement("ct_stats"_ctv, index, stats[index]);
    }
    std::fprintf(stderr,
                 "container_peer_egress_router_ipv6_quic_high_slot_portal debug retval=%u data_size_out=%u expected_size=%zu stats_enter=%llu stats_drop_mtu=%llu stats_ipv6=%llu stats_nic=%llu stats_local=%llu stats_portal_local=%llu\n",
                 unsigned(opts.retval),
                 unsigned(opts.data_size_out),
                 frame.size() + sizeof(struct ipv6hdr),
                 static_cast<unsigned long long>(stats[0]),
                 static_cast<unsigned long long>(stats[1]),
                 static_cast<unsigned long long>(stats[3]),
                 static_cast<unsigned long long>(stats[4]),
                 static_cast<unsigned long long>(stats[5]),
                 static_cast<unsigned long long>(stats[7]));
  }
  expectNamed(opts.retval == TC_ACT_REDIRECT, "redirects_to_nic");
  expectNamed(opts.data_size_out == frame.size() + sizeof(struct ipv6hdr), "adds_outer_ipv6_header");

  if (runResult == 0 && opts.data_size_out >= (sizeof(struct ethhdr) + (2u * sizeof(struct ipv6hdr)) + sizeof(struct udphdr) + sizeof(struct quic_long_header)))
  {
    const uint8_t expectedGatewayMAC[6] = {0x02, 0x42, 0xac, 0x11, 0x00, 0x01};
    const uint8_t expectedLocalMAC[6] = {0x02, 0x42, 0xac, 0x11, 0x00, 0x0a};
    uint8_t expectedOuterSrc[16] = {};
    uint8_t expectedOuterDst[16] = {};
    uint8_t expectedInnerSrc[16] = {};
    uint8_t expectedInnerDst[16] = {};
    parseIPv6Bytes("fd00:10::c", expectedOuterSrc);
    parseIPv6Bytes("fd00:10::d", expectedOuterDst);
    parseIPv6Bytes("fdf8:d94c:7c33:e26e:ca4b:f501:fbde:ab7e", expectedInnerSrc);
    parseIPv6Bytes("fdf8:d94c:7c33:e26e:ca4b:f501:ad8c:51b9", expectedInnerDst);

    const struct ethhdr *eth = reinterpret_cast<const struct ethhdr *>(output.data());
    expectNamed(eth->h_proto == bpf_htons(ETH_P_IPV6), "sets_outer_ethertype");
    expectNamed(std::memcmp(eth->h_source, expectedLocalMAC, sizeof(expectedLocalMAC)) == 0,
                "sets_source_mac");
    expectNamed(std::memcmp(eth->h_dest, expectedGatewayMAC, sizeof(expectedGatewayMAC)) == 0,
                "sets_gateway_mac");

    const struct ipv6hdr *outer6 = reinterpret_cast<const struct ipv6hdr *>(output.data() + sizeof(struct ethhdr));
    expectNamed(outer6->nexthdr == IPPROTO_IPV6, "wraps_inner_ipv6");
    expectNamed(std::memcmp(outer6->saddr.s6_addr, expectedOuterSrc, sizeof(expectedOuterSrc)) == 0,
                "sets_outer_source");
    expectNamed(std::memcmp(outer6->daddr.s6_addr, expectedOuterDst, sizeof(expectedOuterDst)) == 0,
                "sets_outer_destination");

    const struct ipv6hdr *inner6 = reinterpret_cast<const struct ipv6hdr *>(outer6 + 1);
    const struct udphdr *udph = reinterpret_cast<const struct udphdr *>(inner6 + 1);
    const struct quic_long_header *quic = reinterpret_cast<const struct quic_long_header *>(udph + 1);
    __u16 expectedChecksum = compute_ipv6_transport_checksum_portable(
        inner6->saddr.s6_addr,
        inner6->daddr.s6_addr,
        IPPROTO_UDP,
        udph,
        ntohs(udph->len),
        __builtin_offsetof(struct udphdr, check));

    expectNamed(inner6->nexthdr == IPPROTO_UDP, "keeps_udp_inner_protocol");
    expectNamed(std::memcmp(inner6->saddr.s6_addr, expectedInnerSrc, sizeof(expectedInnerSrc)) == 0,
                "preserves_probe_source");
    expectNamed(std::memcmp(inner6->daddr.s6_addr, expectedInnerDst, sizeof(expectedInnerDst)) == 0,
                "rewrites_destination_to_app_container");
    expectNamed(ntohs(udph->source) == 41'252, "preserves_source_port");
    expectNamed(ntohs(udph->dest) == 8443, "rewrites_destination_port");
    expectNamed(udph->check == expectedChecksum, "recomputes_udp_checksum");
    expectNamed((quic->flags & QUIC_V1_PACKET_TYPE_MASK) == QUIC_V1_HANDSHAKE,
                "preserves_handshake_packet_type");
    expectNamed(quic->conn_id_lens == QUIC_CID_LEN && std::memcmp(quic->dst_cid, cid.id, cid.id_len) == 0,
                "preserves_routing_cid_payload");
  }

  peerProgram.close();
}

int main(void)
{
  if (const char *allow = std::getenv("PRODIGY_DEV_ALLOW_BPF_ATTACH"); allow == nullptr || std::strcmp(allow, "1") != 0)
  {
    std::fprintf(stderr, "SKIP: container overlay sync unit loads BPF programs; set PRODIGY_DEV_ALLOW_BPF_ATTACH=1 only inside an authorized isolated VM\n");
    return 77;
  }

  TestSuite suite = {};

  testContainerPeerOverlayRoutingSyncPopulatesMapsAndRemovesStaleEntries(suite);
  testContainerPeerRuntimeSyncPopulatesAndClearsWormholeEgressBindings(suite);
  testSystemEgressPolicyConstrainsIPv4(suite);
  testContainerPeerEgressRouterLoadsAfterWormholeSourceRewrite(suite);
  testContainerPeerEgressRouterDropsPacketsOverConfiguredMTU(suite);
  testContainerPeerEgressRouterEnforcesSystemAllowlist(suite);
  testWormholeEgressBindingReconcilePreservesDesiredKeysDuringStaleRemoval(suite);
  testWormholeRewriteLayoutResolvesEthernetAndL3Frames(suite);
  testContainerPeerEgressRouterRewritesCrossMachineWormholeReplyForOverlay(suite);
  testContainerPeerEgressRouterEncapsulatesHostedIngress(suite, false, IPPROTO_UDP);
  testContainerPeerEgressRouterEncapsulatesHostedIngress(suite, false, IPPROTO_TCP);
  testContainerPeerEgressRouterEncapsulatesHostedIngress(suite, true, IPPROTO_UDP);
  testContainerPeerEgressRouterEncapsulatesHostedIngress(suite, true, IPPROTO_TCP);
  testContainerPeerEgressRouterRewritesIPv4WormholeSource(suite, IPPROTO_UDP);
  testContainerPeerEgressRouterRewritesIPv4WormholeSource(suite, IPPROTO_TCP);
  testContainerPeerEgressRouterRoutesIPv6QuicHighSlotPortal(suite);

  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
