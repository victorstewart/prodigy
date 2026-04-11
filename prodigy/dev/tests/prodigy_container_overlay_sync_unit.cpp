#include <networking/includes.h>
#include <services/debug.h>

#include <prodigy/neuron/neuron.h>
#include <switchboard/common/checksum.h>
#include <switchboard/overlay.route.h>

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

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

int main(void)
{
   TestSuite suite = {};

   testContainerPeerOverlayRoutingSyncPopulatesMapsAndRemovesStaleEntries(suite);
   testContainerPeerRuntimeSyncPopulatesAndClearsWormholeEgressBindings(suite);
   testContainerPeerEgressRouterLoadsAfterWormholeSourceRewrite(suite);
   testWormholeEgressBindingReconcilePreservesDesiredKeysDuringStaleRemoval(suite);
   testWormholeRewriteLayoutResolvesEthernetAndL3Frames(suite);

   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
