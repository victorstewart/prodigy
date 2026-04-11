#include <networking/includes.h>
#include <services/debug.h>

#include <switchboard/common/local_container_subnet.h>
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
         basics_log("PASS: %s\n", name);
      }
      else
      {
         basics_log("FAIL: %s\n", name);
         failed += 1;
      }
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

int main(void)
{
   TestSuite suite = {};

   Vector<IPPrefix> prefixes = {};
   prefixes.push_back(makePrefix("198.18.55.77/12"));
   prefixes.push_back(makePrefix("198.16.0.1/12"));
   prefixes.push_back(makePrefix("2001:db8:abcd:1234:5678:9abc::1/64"));
   prefixes.push_back(makePrefix("2001:db8:abcd:1234::beef/64"));

   Vector<switchboard_overlay_prefix4_key> keys4 = {};
   Vector<switchboard_overlay_prefix6_key> keys6 = {};
   switchboardBuildOverlayPrefixKeys(prefixes, keys4, keys6);

   suite.expect(keys4.size() == 1, "switchboard_overlay_prefix_ipv4_dedupes");
   suite.expect(keys4[0].prefixlen == 12, "switchboard_overlay_prefix_ipv4_prefixlen");
   suite.expect(ntohl(keys4[0].addr) == 0xC6100000u, "switchboard_overlay_prefix_ipv4_masks_host_bits");

   suite.expect(keys6.size() == 1, "switchboard_overlay_prefix_ipv6_dedupes");
   suite.expect(keys6[0].prefixlen == 64, "switchboard_overlay_prefix_ipv6_prefixlen");

   const uint8_t expectedIPv6[16] = {
      0x20, 0x01, 0x0d, 0xb8,
      0xab, 0xcd, 0x12, 0x34,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00
   };
   suite.expect(std::memcmp(keys6[0].addr, expectedIPv6, sizeof(expectedIPv6)) == 0, "switchboard_overlay_prefix_ipv6_masks_host_bits");

   SwitchboardOverlayMachineRoute route4 = {};
   route4.machineFragment = 0x2A;
   route4.nextHop = IPAddress("198.51.100.44", false);
   route4.sourceAddress = IPAddress("198.51.100.10", false);
   route4.useGatewayMAC = true;

   switchboard_overlay_machine_route value4 = {};
   suite.expect(switchboardBuildOverlayMachineRouteValue(route4, value4), "switchboard_overlay_route_value_ipv4_builds");
   suite.expect(value4.family == SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV4, "switchboard_overlay_route_value_ipv4_family");
   suite.expect(value4.use_gateway_mac == 1, "switchboard_overlay_route_value_ipv4_gateway_mac_flag");
   suite.expect(value4.next_hop4 == route4.nextHop.v4, "switchboard_overlay_route_value_ipv4_next_hop");
   suite.expect(value4.source4 == route4.sourceAddress.v4, "switchboard_overlay_route_value_ipv4_source");

   SwitchboardOverlayMachineRoute route6 = {};
   route6.machineFragment = 0x010203u;
   route6.nextHop = IPAddress("2001:db8::44", true);
   route6.sourceAddress = IPAddress("2001:db8::10", true);
    route6.useGatewayMAC = false;
   route6.nextHopMAC = "fa:6d:18:7d:9f:5e"_ctv;

   switchboard_overlay_machine_route value6 = {};
   suite.expect(switchboardBuildOverlayMachineRouteValue(route6, value6), "switchboard_overlay_route_value_ipv6_builds");
   suite.expect(value6.family == SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6, "switchboard_overlay_route_value_ipv6_family");
   suite.expect(value6.use_gateway_mac == 0, "switchboard_overlay_route_value_ipv6_direct_mac_flag");
   suite.expect(std::memcmp(value6.next_hop6, route6.nextHop.v6, sizeof(value6.next_hop6)) == 0, "switchboard_overlay_route_value_ipv6_next_hop");
   suite.expect(std::memcmp(value6.source6, route6.sourceAddress.v6, sizeof(value6.source6)) == 0, "switchboard_overlay_route_value_ipv6_source");
   const uint8_t expectedMAC[6] = {0xfa, 0x6d, 0x18, 0x7d, 0x9f, 0x5e};
   suite.expect(std::memcmp(value6.next_hop_mac, expectedMAC, sizeof(expectedMAC)) == 0, "switchboard_overlay_route_value_ipv6_direct_mac");

   SwitchboardOverlayMachineRoute mixed = route6;
   mixed.sourceAddress = IPAddress("198.51.100.10", false);
   suite.expect(switchboardBuildOverlayMachineRouteValue(mixed, value6) == false, "switchboard_overlay_route_value_rejects_mixed_family");

   SwitchboardOverlayMachineRoute missing = route6;
   missing.machineFragment = 0;
   suite.expect(switchboardBuildOverlayMachineRouteValue(missing, value6) == false, "switchboard_overlay_route_value_rejects_zero_fragment");

   SwitchboardOverlayMachineRoute invalidMac = route6;
   invalidMac.nextHopMAC = "not-a-mac"_ctv;
   suite.expect(switchboardBuildOverlayMachineRouteValue(invalidMac, value6) == false, "switchboard_overlay_route_value_rejects_invalid_direct_mac");

   switchboard_overlay_machine_route_key fullKey = switchboardMakeOverlayMachineRouteKey(route6.machineFragment);
   switchboard_overlay_machine_route_key lowKey = switchboardMakeOverlayMachineRouteKey(route4.machineFragment & 0xFFu);
   suite.expect(fullKey.fragment == 0x010203u, "switchboard_overlay_route_key_full_fragment");
   suite.expect(lowKey.fragment == 0x2Au, "switchboard_overlay_route_key_low8_fragment");

   Vector<SwitchboardOverlayHostedIngressRoute> hostedIngressRoutes = {};
   SwitchboardOverlayHostedIngressRoute hosted6 = {};
   hosted6.prefix = makePrefix("2001:db8:100::c/128");
   hosted6.machineFragment = 0x010203u;
   hostedIngressRoutes.push_back(hosted6);

   SwitchboardOverlayHostedIngressRoute hosted6Duplicate = hosted6;
   hostedIngressRoutes.push_back(hosted6Duplicate);

   SwitchboardOverlayHostedIngressRoute hosted4 = {};
   hosted4.prefix = makePrefix("203.0.113.9/32");
   hosted4.machineFragment = 0x2Au;
   hostedIngressRoutes.push_back(hosted4);

   Vector<std::pair<switchboard_overlay_prefix4_key, switchboard_overlay_hosted_ingress_route4>> hostedIngressEntries4 = {};
   Vector<std::pair<switchboard_overlay_prefix6_key, switchboard_overlay_hosted_ingress_route6>> hostedIngressEntries6 = {};
   switchboardBuildOverlayHostedIngressRouteEntries(hostedIngressRoutes, hostedIngressEntries4, hostedIngressEntries6);

   suite.expect(hostedIngressEntries4.size() == 1, "switchboard_overlay_hosted_ingress_ipv4_dedupes");
   suite.expect(hostedIngressEntries4[0].second.machine_fragment == hosted4.machineFragment, "switchboard_overlay_hosted_ingress_ipv4_preserves_machine_fragment");
   suite.expect(hostedIngressEntries6.size() == 1, "switchboard_overlay_hosted_ingress_ipv6_dedupes");
   suite.expect(hostedIngressEntries6[0].second.machine_fragment == hosted6.machineFragment, "switchboard_overlay_hosted_ingress_ipv6_preserves_machine_fragment");

   local_container_subnet6 localSubnet = {};
   localSubnet.dpfx = 0x01;
   localSubnet.mpfx[0] = 0x8a;
   localSubnet.mpfx[1] = 0x85;
   localSubnet.mpfx[2] = 0x20;

   uint8_t localContainerIPv6[16] = {};
   std::memcpy(localContainerIPv6, container_network_subnet6.value, sizeof(container_network_subnet6.value));
   localContainerIPv6[11] = localSubnet.dpfx;
   localContainerIPv6[12] = localSubnet.mpfx[0];
   localContainerIPv6[13] = localSubnet.mpfx[1];
   localContainerIPv6[14] = localSubnet.mpfx[2];
   localContainerIPv6[15] = 0x9e;

   uint8_t remoteContainerIPv6[16] = {};
   std::memcpy(remoteContainerIPv6, container_network_subnet6.value, sizeof(container_network_subnet6.value));
   remoteContainerIPv6[11] = localSubnet.dpfx;
   remoteContainerIPv6[12] = 0xa5;
   remoteContainerIPv6[13] = 0x77;
   remoteContainerIPv6[14] = 0x01;
   remoteContainerIPv6[15] = 0x9e;

   uint8_t publicIPv6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x44};
   uint8_t wrongPrefixSameMachineIPv6[16] = {};
   std::memcpy(wrongPrefixSameMachineIPv6, publicIPv6, sizeof(wrongPrefixSameMachineIPv6));
   wrongPrefixSameMachineIPv6[11] = localSubnet.dpfx;
   wrongPrefixSameMachineIPv6[12] = localSubnet.mpfx[0];
   wrongPrefixSameMachineIPv6[13] = localSubnet.mpfx[1];
   wrongPrefixSameMachineIPv6[14] = localSubnet.mpfx[2];
   wrongPrefixSameMachineIPv6[15] = 0x9e;

   uint8_t zeroContainerFragmentIPv6[16] = {};
   std::memcpy(zeroContainerFragmentIPv6, remoteContainerIPv6, sizeof(zeroContainerFragmentIPv6));
   zeroContainerFragmentIPv6[15] = 0x00;

   suite.expect(switchboardContainerIPv6TargetsLocalMachine(localContainerIPv6, &localSubnet), "switchboard_local_container_subnet_detects_local_machine_delivery");
   suite.expect(switchboardContainerIPv6TargetsRemoteMachine(localContainerIPv6, &localSubnet) == false, "switchboard_local_container_subnet_local_delivery_is_not_remote");
   suite.expect(switchboardContainerIPv6TargetsRemoteMachine(remoteContainerIPv6, &localSubnet), "switchboard_local_container_subnet_detects_cross_machine_delivery");
   suite.expect(switchboardContainerIPv6TargetsLocalMachine(remoteContainerIPv6, &localSubnet) == false, "switchboard_local_container_subnet_cross_machine_delivery_is_not_local");
   suite.expect(switchboardContainerIPv6TargetsLocalMachine(publicIPv6, &localSubnet) == false, "switchboard_local_container_subnet_ignores_public_ipv6");
   suite.expect(switchboardContainerIPv6TargetsLocalMachine(wrongPrefixSameMachineIPv6, &localSubnet) == false, "switchboard_local_container_subnet_requires_container_prefix_for_local_delivery");
   suite.expect(switchboardContainerIPv6TargetsRemoteMachine(publicIPv6, &localSubnet) == false, "switchboard_remote_container_detection_ignores_public_ipv6");
   suite.expect(switchboardContainerIPv6TargetsRemoteMachine(wrongPrefixSameMachineIPv6, &localSubnet) == false, "switchboard_remote_container_detection_requires_container_prefix");
   __u8 resolvedLocalFragment = 0;
   suite.expect(switchboardResolveLocalContainerIPv6Fragment(localContainerIPv6, &localSubnet, &resolvedLocalFragment), "switchboard_local_container_subnet_resolves_local_container_fragment");
   suite.expect(resolvedLocalFragment == 0x9e, "switchboard_local_container_subnet_preserves_local_container_fragment");
   resolvedLocalFragment = 0;
   suite.expect(switchboardResolveLocalContainerIPv6Fragment(remoteContainerIPv6, &localSubnet, &resolvedLocalFragment) == false, "switchboard_local_container_subnet_rejects_remote_container_fragment_resolution");
   resolvedLocalFragment = 0;
   suite.expect(switchboardResolveLocalContainerIPv6Fragment(zeroContainerFragmentIPv6, &localSubnet, &resolvedLocalFragment) == false, "switchboard_local_container_subnet_rejects_zero_fragment_resolution");
   suite.expect(switchboardNetkitIngressL3Offset(true) == (__u32)sizeof(struct ethhdr), "switchboard_netkit_ingress_l3_offset_preserves_host_ethernet_placeholder");
   suite.expect(switchboardNetkitIngressL3Offset(false) == 0u, "switchboard_netkit_ingress_l3_offset_is_zero_without_host_ethernet");
   suite.expect(switchboardHostIngressOverlayMinimumLinearBytes(htons(ETH_P_IPV6)) == (__u32)(sizeof(struct ethhdr) + 40u + 40u), "switchboard_host_ingress_overlay_pull_bytes_ipv6_cover_outer_and_inner_ipv6");
   suite.expect(switchboardHostIngressOverlayMinimumLinearBytes(htons(ETH_P_IP)) == (__u32)(sizeof(struct ethhdr) + 20u + 40u), "switchboard_host_ingress_overlay_pull_bytes_ipv4_cover_outer_ipv4_and_inner_ipv6");
   suite.expect(switchboardHostIngressOverlayMinimumLinearBytes(0) == 0u, "switchboard_host_ingress_overlay_pull_bytes_ignore_non_ip");
   suite.expect(switchboardHostIngressEffectiveProtocol(htons(ETH_P_IP), htons(ETH_P_IPV6), false) == (__be16)htons(ETH_P_IP), "switchboard_host_ingress_protocol_keeps_wire_ethertype_without_decap");
   suite.expect(switchboardHostIngressEffectiveProtocol(htons(ETH_P_IP), htons(ETH_P_IPV6), true) == (__be16)htons(ETH_P_IPV6), "switchboard_host_ingress_protocol_uses_inner_ipv6_after_ipv4_decap");
   suite.expect(switchboardHostIngressEffectiveProtocol(htons(ETH_P_IPV6), htons(ETH_P_IP), true) == (__be16)htons(ETH_P_IP), "switchboard_host_ingress_protocol_uses_inner_ipv4_after_ipv6_decap");
   suite.expect(switchboardHostIngressEffectiveProtocol(htons(ETH_P_IP), 0, true) == (__be16)htons(ETH_P_IP), "switchboard_host_ingress_protocol_rejects_invalid_inner_protocol");

   container_id localContainerID = {};
   localContainerID.value[0] = localSubnet.dpfx;
   localContainerID.value[1] = localSubnet.mpfx[0];
   localContainerID.value[2] = localSubnet.mpfx[1];
   localContainerID.value[3] = localSubnet.mpfx[2];
   localContainerID.value[4] = 0x9e;
   localContainerID.hasID = true;

   container_id remoteContainerID = {};
   remoteContainerID.value[0] = localSubnet.dpfx;
   remoteContainerID.value[1] = 0xa5;
   remoteContainerID.value[2] = 0x77;
   remoteContainerID.value[3] = 0x01;
   remoteContainerID.value[4] = 0x9e;
   remoteContainerID.hasID = true;

   container_id unresolvedContainerID = {};

   suite.expect(switchboardContainerIDTargetsLocalMachine(&localContainerID, &localSubnet), "switchboard_container_id_detects_local_machine_delivery");
   suite.expect(switchboardContainerIDTargetsRemoteMachine(&localContainerID, &localSubnet) == false, "switchboard_container_id_local_delivery_is_not_remote");
   suite.expect(switchboardContainerIDTargetsRemoteMachine(&remoteContainerID, &localSubnet), "switchboard_container_id_detects_cross_machine_delivery");
   suite.expect(switchboardContainerIDTargetsLocalMachine(&remoteContainerID, &localSubnet) == false, "switchboard_container_id_cross_machine_delivery_is_not_local");
   suite.expect(switchboardContainerIDTargetsLocalMachine(&unresolvedContainerID, &localSubnet) == false, "switchboard_container_id_rejects_unresolved_container");
   suite.expect(switchboardContainerIDTargetsRemoteMachine(&unresolvedContainerID, &localSubnet) == false, "switchboard_container_id_unresolved_container_is_not_remote");

   switchboard_overlay_machine_route_key localRouteKey = {};
   suite.expect(switchboardExtractOverlayMachineFragmentFromIPv6(localContainerIPv6, &localRouteKey.fragment), "switchboard_overlay_route_key_ipv6_extracts_local_machine_fragment");
   suite.expect(localRouteKey.fragment == 0x8a8520u, "switchboard_overlay_route_key_ipv6_local_machine_fragment_value");

   switchboard_overlay_machine_route_key remoteRouteKey = {};
   suite.expect(switchboardExtractOverlayMachineFragmentFromIPv6(remoteContainerIPv6, &remoteRouteKey.fragment), "switchboard_overlay_route_key_ipv6_extracts_remote_machine_fragment");
   suite.expect(remoteRouteKey.fragment == 0xa57701u, "switchboard_overlay_route_key_ipv6_remote_machine_fragment_value");

   uint8_t zeroMachineFragmentIPv6[16] = {};
   std::memcpy(zeroMachineFragmentIPv6, container_network_subnet6.value, sizeof(container_network_subnet6.value));
   zeroMachineFragmentIPv6[11] = localSubnet.dpfx;
   zeroMachineFragmentIPv6[15] = 0x9e;
   suite.expect(switchboardExtractOverlayMachineFragmentFromIPv6(zeroMachineFragmentIPv6, &remoteRouteKey.fragment) == false, "switchboard_overlay_route_key_ipv6_rejects_zero_machine_fragment");

   suite.expect(switchboardExtractOverlayMachineFragmentFromIPv6(zeroContainerFragmentIPv6, &remoteRouteKey.fragment) == false, "switchboard_overlay_route_key_ipv6_rejects_zero_container_fragment");

   uint8_t rebuiltContainerIPv6[16] = {};
   suite.expect(switchboardBuildContainerNetworkIPv6(rebuiltContainerIPv6, &localContainerID), "switchboard_builds_container_ipv6_from_container_id");
   suite.expect(std::memcmp(rebuiltContainerIPv6, localContainerIPv6, sizeof(rebuiltContainerIPv6)) == 0, "switchboard_builds_expected_container_ipv6_bytes");
   suite.expect(switchboardBuildContainerNetworkIPv6(rebuiltContainerIPv6, &unresolvedContainerID) == false, "switchboard_rejects_container_ipv6_build_for_unresolved_container");

   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
