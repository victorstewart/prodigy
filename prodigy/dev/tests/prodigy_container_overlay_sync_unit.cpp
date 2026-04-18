#include <networking/includes.h>
#include <services/debug.h>

#include <prodigy/neuron/neuron.h>
#include <switchboard/common/checksum.h>
#include <switchboard/overlay.route.h>

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <linux/pkt_cls.h>
#include <netinet/udp.h>

class TestSuite
{
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
   program.openMap(mapName, [&] (int mapFD) -> void {

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
   program.openMap(mapName, [&] (int mapFD) -> void {

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
   if (inet_pton(AF_INET6, srcIPv6, ip6h->saddr.s6_addr) != 1
      || inet_pton(AF_INET6, dstIPv6, ip6h->daddr.s6_addr) != 1)
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

static Vector<uint8_t> makeIPv6UDPFrameWithPayload(const char *srcIPv6,
   const char *dstIPv6,
   uint16_t sourcePort,
   uint16_t destPort,
   const Vector<uint8_t>& payload,
   bool includeEthernet)
{
   const size_t ethBytes = includeEthernet ? sizeof(struct ethhdr) : 0u;
   Vector<uint8_t> frame = {};
   frame.resize(ethBytes + sizeof(struct ipv6hdr) + sizeof(struct udphdr) + payload.size());
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
   ip6h->payload_len = htons(static_cast<uint16_t>(sizeof(struct udphdr) + payload.size()));
   parseIPv6Bytes(srcIPv6, ip6h->saddr.s6_addr);
   parseIPv6Bytes(dstIPv6, ip6h->daddr.s6_addr);

   struct udphdr *udph = reinterpret_cast<struct udphdr *>(frame.data() + ethBytes + sizeof(struct ipv6hdr));
   udph->source = htons(sourcePort);
   udph->dest = htons(destPort);
   udph->len = htons(static_cast<uint16_t>(sizeof(struct udphdr) + payload.size()));
   std::memcpy(frame.data() + ethBytes + sizeof(struct ipv6hdr) + sizeof(struct udphdr), payload.data(), payload.size());

   udph->check = compute_ipv6_transport_checksum_portable(
      ip6h->saddr.s6_addr,
      ip6h->daddr.s6_addr,
      IPPROTO_UDP,
      udph,
      static_cast<__u32>(sizeof(struct udphdr) + payload.size()),
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
   return std::memcmp(lhs.container, rhs.container, sizeof(lhs.container)) == 0
      && lhs.port == rhs.port
      && lhs.proto == rhs.proto;
}

class NoopNeuronIaaS final : public NeuronIaaS
{
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

class OverlayTestNeuron final : public Neuron
{
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

   if (suite.require(peerProgram.load(objectPath, "container_egress_router"_ctv), "container_peer_overlay_sync_loads_egress_router"))
   {
      neuron.seedOverlayRoutingConfigForTest(config);
      neuron.syncOverlayRoutingProgramsForTest();

      switchboard_overlay_config overlayConfig = {};
      peerProgram.getArrayElement("overlay_config_map"_ctv, 0, overlayConfig);
      suite.expect(overlayConfig.container_network_enabled == 1, "container_peer_overlay_sync_sets_overlay_enabled");

      Vector<switchboard_overlay_prefix4_key> desiredPrefixes4 = {};
      Vector<switchboard_overlay_prefix6_key> desiredPrefixes6 = {};
      switchboardBuildOverlayPrefixKeys(config.overlaySubnets, desiredPrefixes4, desiredPrefixes6);

      __u8 present = 0;
      suite.expect(desiredPrefixes4.size() == 1
         && lookupProgramMapElement(peerProgram, "overlay_routable_prefixes4"_ctv, desiredPrefixes4[0], present)
         && present == 1,
         "container_peer_overlay_sync_populates_ipv4_prefix_map");

      present = 0;
      suite.expect(desiredPrefixes6.size() == 1
         && lookupProgramMapElement(peerProgram, "overlay_routable_prefixes6"_ctv, desiredPrefixes6[0], present)
         && present == 1,
         "container_peer_overlay_sync_populates_ipv6_prefix_map");

      switchboard_overlay_machine_route routeValue = {};
      suite.expect(lookupProgramMapElement(peerProgram,
         "overlay_machine_routes_full"_ctv,
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
         "overlay_machine_routes_low8"_ctv,
         switchboardMakeOverlayMachineRouteKey(route1.machineFragment & 0xFFu),
         routeValue),
         "container_peer_overlay_sync_populates_unique_low8_route");
      suite.expect(routeValue.use_gateway_mac == 1, "container_peer_overlay_sync_preserves_gateway_route_flag");
      routeValue = {};
      suite.expect(lookupProgramMapElement(peerProgram,
         "overlay_machine_routes_low8"_ctv,
         switchboardMakeOverlayMachineRouteKey(route2.machineFragment & 0xFFu),
         routeValue) == false,
         "container_peer_overlay_sync_drops_ambiguous_low8_route");

      switchboard_overlay_hosted_ingress_route4 hostedIngressValue4 = {};
      switchboard_overlay_prefix4_key hostedIngressKey4 = switchboardMakeOverlayPrefix4Key(hostedIngress4.prefix);
      suite.expect(lookupProgramMapElement(peerProgram,
         "overlay_hosted_ingress_routes4"_ctv,
         hostedIngressKey4,
         hostedIngressValue4),
         "container_peer_overlay_sync_populates_ipv4_hosted_ingress_route_map");
      suite.expect(hostedIngressValue4.machine_fragment == hostedIngress4.machineFragment,
         "container_peer_overlay_sync_preserves_ipv4_hosted_ingress_machine_fragment");

      switchboard_overlay_hosted_ingress_route6 hostedIngressValue6 = {};
      switchboard_overlay_prefix6_key hostedIngressKey6 = switchboardMakeOverlayPrefix6Key(hostedIngress6.prefix);
      suite.expect(lookupProgramMapElement(peerProgram,
         "overlay_hosted_ingress_routes6"_ctv,
         hostedIngressKey6,
         hostedIngressValue6),
         "container_peer_overlay_sync_populates_ipv6_hosted_ingress_route_map");
      suite.expect(hostedIngressValue6.machine_fragment == hostedIngress6.machineFragment,
         "container_peer_overlay_sync_preserves_ipv6_hosted_ingress_machine_fragment");

      SwitchboardOverlayRoutingConfig disabled = {};
      neuron.seedOverlayRoutingConfigForTest(disabled);
      neuron.syncOverlayRoutingProgramsForTest();

      overlayConfig = {};
      peerProgram.getArrayElement("overlay_config_map"_ctv, 0, overlayConfig);
      suite.expect(overlayConfig.container_network_enabled == 0, "container_peer_overlay_sync_clears_overlay_enabled");

      present = 0;
      suite.expect(lookupProgramMapElement(peerProgram, "overlay_routable_prefixes4"_ctv, desiredPrefixes4[0], present) == false, "container_peer_overlay_sync_removes_ipv4_prefix_map_entries");
      present = 0;
      suite.expect(lookupProgramMapElement(peerProgram, "overlay_routable_prefixes6"_ctv, desiredPrefixes6[0], present) == false, "container_peer_overlay_sync_removes_ipv6_prefix_map_entries");
      routeValue = {};
      suite.expect(lookupProgramMapElement(peerProgram,
         "overlay_machine_routes_full"_ctv,
         switchboardMakeOverlayMachineRouteKey(route2.machineFragment),
         routeValue) == false,
         "container_peer_overlay_sync_removes_full_route_map_entries");
      suite.expect(lookupProgramMapElement(peerProgram,
         "overlay_machine_routes_low8"_ctv,
         switchboardMakeOverlayMachineRouteKey(route1.machineFragment & 0xFFu),
         routeValue) == false,
         "container_peer_overlay_sync_removes_low8_route_map_entries");
      hostedIngressValue4 = {};
      suite.expect(lookupProgramMapElement(peerProgram,
         "overlay_hosted_ingress_routes4"_ctv,
         hostedIngressKey4,
         hostedIngressValue4) == false,
         "container_peer_overlay_sync_removes_ipv4_hosted_ingress_route_map_entries");
      hostedIngressValue6 = {};
      suite.expect(lookupProgramMapElement(peerProgram,
         "overlay_hosted_ingress_routes6"_ctv,
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
   if (suite.require(peerProgram.load(objectPath, "container_egress_router"_ctv), "container_peer_runtime_sync_loads_egress_router"))
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
            "wormhole_egress_bindings"_ctv,
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
            "wormhole_egress_bindings"_ctv,
            stale.key,
            loadedBinding) == false,
         "container_peer_runtime_sync_removes_stale_binding");

      loadedBinding = {};
      suite.expect(lookupProgramMapElement(peerProgram,
            "wormhole_egress_bindings"_ctv,
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
            "wormhole_egress_bindings"_ctv,
            desired.key,
            loadedBinding) == false,
         "container_peer_runtime_sync_clears_removed_bindings");
   }

   peerProgram.close();
}

static void testContainerPeerEgressRouterLoadsAfterWormholeSourceRewrite(TestSuite& suite)
{
   String objectPath = {};
   objectPath.assign(PRODIGY_TEST_BINARY_DIR);
   objectPath.append("/container.egress.router.ebpf.o"_ctv);

   BPFProgram peerProgram = {};
   suite.expect(peerProgram.load(objectPath, "container_egress_router"_ctv),
      "container_peer_egress_router_loads_after_wormhole_source_rewrite");
   peerProgram.close();
}

static void testContainerPeerEgressRouterDropsPacketsOverConfiguredMTU(TestSuite& suite)
{
   String objectPath = {};
   objectPath.assign(PRODIGY_TEST_BINARY_DIR);
   objectPath.append("/container.egress.router.ebpf.o"_ctv);

   BPFProgram peerProgram = {};
   suite.expect(peerProgram.load(objectPath, "container_egress_router"_ctv),
      "container_peer_egress_router_drop_over_mtu_loads_program");

   if (peerProgram.prog_fd >= 0)
   {
      container_network_policy networkPolicy = {};
      networkPolicy.interContainerMTU = 1280u;
      peerProgram.setArrayElement("container_network_policy_map"_ctv, 0, networkPolicy);

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
         47156,
         payload,
         true);
      Vector<uint8_t> output = {};
      output.resize(frame.size());

      LIBBPF_OPTS(bpf_test_run_opts, opts,
         .data_in = frame.data(),
         .data_out = output.data(),
         .data_size_in = static_cast<__u32>(frame.size()),
         .data_size_out = static_cast<__u32>(output.size()),
         .repeat = 1,
      );

      int runResult = bpf_prog_test_run_opts(peerProgram.prog_fd, &opts);
      suite.expect(runResult == 0, "container_peer_egress_router_drop_over_mtu_test_run_succeeds");
      suite.expect(opts.retval == NETKIT_DROP,
         "container_peer_egress_router_drop_over_mtu_returns_drop");

      __u64 oversizeDrops = 0;
      peerProgram.getArrayElement("container_router_stats_map"_ctv, 1, oversizeDrops);
      suite.expect(oversizeDrops == 1,
         "container_peer_egress_router_drop_over_mtu_bumps_stat");
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

   struct ReconcileOp
   {
      bool isUpsert = false;
      switchboard_wormhole_egress_key key = {};
   };

   Vector<ReconcileOp> ops = {};
   switchboardReconcileWormholeEgressBindings(existingKeys,
      desiredBindings,
      [&] (const SwitchboardWormholeEgressBindingEntry& entry) -> void {
         ReconcileOp op = {};
         op.isUpsert = true;
         op.key = entry.key;
         ops.push_back(op);
      },
      [&] (const switchboard_wormhole_egress_key& key) -> void {
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

   Vector<uint8_t> ethernetFrame = makeIPv6UDPFrame(sourceIPv6, destIPv6, 8443, 55538, true);
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

   Vector<uint8_t> l3Frame = makeIPv6UDPFrame(sourceIPv6, destIPv6, 8443, 55538, false);
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
   suite.expect(peerProgram.load(objectPath, "container_egress_router"_ctv),
      "container_peer_egress_router_cross_machine_wormhole_reply_loads_program");

   if (peerProgram.prog_fd >= 0)
   {
      local_container_subnet6 localSubnet = {};
      localSubnet.dpfx = 0x01;
      localSubnet.mpfx[0] = 0xf4;
      localSubnet.mpfx[1] = 0x54;
      localSubnet.mpfx[2] = 0xa6;
      peerProgram.setArrayElement("local_container_subnet_map"_ctv, 0, localSubnet);

      __u32 nicIfidx = 77;
      peerProgram.setArrayElement("container_device_map"_ctv, 0, nicIfidx);

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
      peerProgram.setArrayElement("gateway_mac_map"_ctv, 0, gatewayMAC);

      switchboard_overlay_config overlayConfig = {};
      overlayConfig.container_network_enabled = 1;
      peerProgram.setArrayElement("overlay_config_map"_ctv, 0, overlayConfig);

      switchboard_overlay_machine_route route = {};
      route.family = SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6;
      route.use_gateway_mac = 1;
      parseIPv6Bytes("fd00:10::c", route.source6);
      parseIPv6Bytes("fd00:10::a", route.next_hop6);
      switchboard_overlay_machine_route_key routeKey = switchboardMakeOverlayMachineRouteKey(0xe1607cu);
      suite.expect(updateProgramMapElement(peerProgram, "overlay_machine_routes_full"_ctv, routeKey, route),
         "container_peer_egress_router_cross_machine_wormhole_reply_sets_overlay_route");

      switchboard_wormhole_egress_key bindingKey = makeWormholeEgressKey(0x01, 0xeef454a6u, 8443, IPPROTO_UDP);
      switchboard_wormhole_egress_binding binding = {};
      parseIPv6Bytes("2001:db8:100::c", reinterpret_cast<uint8_t *>(binding.addr6));
      binding.port = htons(443);
      binding.proto = IPPROTO_UDP;
      binding.is_ipv6 = 1;
      suite.expect(updateProgramMapElement(peerProgram, "wormhole_egress_bindings"_ctv, bindingKey, binding),
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
         47156,
         payload,
         true);
      Vector<uint8_t> output = {};
      output.resize(frame.size() + sizeof(struct ipv6hdr) + 64u);

      LIBBPF_OPTS(bpf_test_run_opts, opts,
         .data_in = frame.data(),
         .data_out = output.data(),
         .data_size_in = static_cast<__u32>(frame.size()),
         .data_size_out = static_cast<__u32>(output.size()),
         .repeat = 1,
      );

      int runResult = bpf_prog_test_run_opts(peerProgram.prog_fd, &opts);
      suite.expect(runResult == 0, "container_peer_egress_router_cross_machine_wormhole_reply_test_run_succeeds");
      suite.expect(opts.retval == TC_ACT_REDIRECT,
         "container_peer_egress_router_cross_machine_wormhole_reply_redirects_to_nic");
      suite.expect(opts.data_size_out == frame.size() + sizeof(struct ipv6hdr),
         "container_peer_egress_router_cross_machine_wormhole_reply_adds_outer_ipv6_header");

      if (runResult == 0
         && opts.data_size_out >= (sizeof(struct ethhdr) + (2u * sizeof(struct ipv6hdr)) + sizeof(struct udphdr)))
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
         suite.expect(ntohs(udph->dest) == 47156,
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

int main(void)
{
   TestSuite suite = {};

   testContainerPeerOverlayRoutingSyncPopulatesMapsAndRemovesStaleEntries(suite);
   testContainerPeerRuntimeSyncPopulatesAndClearsWormholeEgressBindings(suite);
   testContainerPeerEgressRouterLoadsAfterWormholeSourceRewrite(suite);
   testContainerPeerEgressRouterDropsPacketsOverConfiguredMTU(suite);
   testWormholeEgressBindingReconcilePreservesDesiredKeysDuringStaleRemoval(suite);
   testWormholeRewriteLayoutResolvesEthernetAndL3Frames(suite);
   testContainerPeerEgressRouterRewritesCrossMachineWormholeReplyForOverlay(suite);

   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
