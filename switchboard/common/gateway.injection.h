#pragma once

#include <linux/icmpv6.h>
#include <linux/ipv6.h>
#ifdef __cplusplus
#include <netinet/tcp.h>
#else
#include <linux/tcp.h>
#endif

#include <switchboard/common/local_container_subnet.h>

struct switchboard_masque_gateway_ptb6 {
  const struct ipv6hdr *quotedIPv6;
  const struct tcphdr *quotedTCP;
  __u32 mtu;
};

__attribute__((__always_inline__)) static inline bool switchboardMasqueGatewayIPv6Equal(
    const __u8 lhs[16], const __u8 rhs[16])
{
#pragma unroll
  for (int i = 0; i < 16; ++i)
  {
    if (lhs[i] != rhs[i]) return false;
  }
  return true;
}

__attribute__((__always_inline__)) static inline __u32 switchboardMasqueGatewayReadNetworkU32(
    const __u8 value[4])
{
  return ((__u32)value[0] << 24) | ((__u32)value[1] << 16) |
      ((__u32)value[2] << 8) | (__u32)value[3];
}

__attribute__((__always_inline__)) static inline __u16 switchboardMasqueGatewayReadNetworkU16(
    const __u8 value[2])
{
  return ((__u16)value[0] << 8) | (__u16)value[1];
}

__attribute__((__always_inline__)) static inline bool switchboardMasqueGatewayReservedLocalSourceValid(
    const __u8 source[16], const struct local_container_subnet6 *localSubnet)
{
  return source != NULL && localSubnet != NULL &&
      switchboardContainerIPv6TargetsLocalMachine(source, localSubnet) &&
      (source[15] == SWITCHBOARD_MASQUE_GATEWAY_FRAGMENT_FIRST ||
       source[15] == SWITCHBOARD_MASQUE_GATEWAY_FRAGMENT_SECOND);
}

// Parse only the bounded shape of an RFC 4443 Packet Too Big that a gateway
// emits toward the original sender. Route and endpoint-flow authorization
// remain with the ingress and egress policy owners.
__attribute__((__always_inline__)) static inline bool switchboardMasqueGatewayPTB6ShapeValid(
    const struct ipv6hdr *outer, const void *data_end, __u32 maximumMTU,
    struct switchboard_masque_gateway_ptb6 *result)
{
  if (outer == NULL || result == NULL || (const void *)(outer + 1) > data_end ||
      outer->nexthdr != IPPROTO_ICMPV6 || maximumMTU < 1280)
  {
    return false;
  }

  const struct icmp6hdr *icmp = (const struct icmp6hdr *)(outer + 1);
  if ((const void *)(icmp + 1) > data_end || icmp->icmp6_type != ICMPV6_PKT_TOOBIG ||
      icmp->icmp6_code != 0)
  {
    return false;
  }

  const __u32 mtu = switchboardMasqueGatewayReadNetworkU32((const __u8 *)&icmp->icmp6_mtu);
  const struct ipv6hdr *quoted = (const struct ipv6hdr *)(icmp + 1);
  if (mtu < 1280 || mtu > maximumMTU || (const void *)(quoted + 1) > data_end ||
      quoted->nexthdr != IPPROTO_TCP ||
      switchboardMasqueGatewayReadNetworkU16((const __u8 *)&quoted->payload_len) + sizeof(*quoted) <= mtu ||
      switchboardMasqueGatewayIPv6Equal(outer->daddr.s6_addr, quoted->saddr.s6_addr) == false)
  {
    return false;
  }

  const struct tcphdr *quotedTCP = (const struct tcphdr *)(quoted + 1);
  if ((const void *)(quotedTCP + 1) > data_end)
  {
    return false;
  }

  result->quotedIPv6 = quoted;
  result->quotedTCP = quotedTCP;
  result->mtu = mtu;
  return true;
}

// This mark is issued only by host egress after a selected site fallback has
// already encapsulated the packet and selected a reserved gateway netkit.
// Gateway ingress consumes it once; it is not a general allowlist bypass.
static inline bool switchboardMasqueGatewayInjectionOuterValid(
    __u32 mark, __u8 nextHeader, const __u8 source[16], const __u8 destination[16],
    const struct local_container_subnet6 *localSubnet)
{
  return mark == SWITCHBOARD_MASQUE_GATEWAY_INJECTION_SKB_MARK &&
      (nextHeader == SWITCHBOARD_IP_PROTOCOL_IPIP || nextHeader == SWITCHBOARD_IP_PROTOCOL_IPV6) &&
      source != 0 && destination != 0 && localSubnet != 0 &&
      switchboardContainerIPv6TargetsLocalMachine(source, localSubnet) && source[15] == 0 &&
      switchboardContainerIPv6TargetsLocalMachine(destination, localSubnet) &&
      (destination[15] == SWITCHBOARD_MASQUE_GATEWAY_FRAGMENT_FIRST ||
       destination[15] == SWITCHBOARD_MASQUE_GATEWAY_FRAGMENT_SECOND);
}

// This is the receiver-side half of a private session tunnel. It authorizes
// only the selected local MASQUE gateway to relay a remote ordinary container
// packet toward its local ordinary endpoint. Endpoint session grants remain
// enforced at source egress and destination ingress.
__attribute__((__always_inline__)) static inline bool switchboardMasqueGatewayRemoteTransitPermitted(
    __u8 effectiveNetworkMode, const struct local_container_subnet6 *localSubnet,
    __u8 gatewayFragment, const __u8 source[16], const __u8 destination[16],
    bool tcpHeaderValid, const struct switchboard_overlay_machine_route *sourceSiteRoute)
{
  if (effectiveNetworkMode != CONTAINER_NETWORK_DESTINATION_ALLOWLIST || localSubnet == 0 ||
      source == 0 || destination == 0 || tcpHeaderValid == false || sourceSiteRoute == 0 ||
      (gatewayFragment != SWITCHBOARD_MASQUE_GATEWAY_FRAGMENT_FIRST &&
       gatewayFragment != SWITCHBOARD_MASQUE_GATEWAY_FRAGMENT_SECOND) ||
      source[11] == localSubnet->dpfx || destination[11] != localSubnet->dpfx ||
      source[15] == 0 || destination[15] == 0 ||
      source[15] == SWITCHBOARD_MASQUE_GATEWAY_FRAGMENT_FIRST ||
      source[15] == SWITCHBOARD_MASQUE_GATEWAY_FRAGMENT_SECOND ||
      destination[15] == SWITCHBOARD_MASQUE_GATEWAY_FRAGMENT_FIRST ||
      destination[15] == SWITCHBOARD_MASQUE_GATEWAY_FRAGMENT_SECOND)
  {
    return false;
  }

  __u32 sourceMachine = 0, destinationMachine = 0;
  if (switchboardExtractOverlayMachineIdentityFromIPv6(source, &sourceMachine) == false ||
      switchboardExtractOverlayMachineIdentityFromIPv6(destination, &destinationMachine) == false)
  {
    return false;
  }

  return sourceSiteRoute->family == SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6 &&
      sourceSiteRoute->use_gateway_mac == SWITCHBOARD_OVERLAY_ROUTE_ACTION_LOCAL_CONTAINER_REDIRECT &&
      sourceSiteRoute->next_hop_mac[0] == gatewayFragment &&
      sourceSiteRoute->next_hop_mac[1] == 0 && sourceSiteRoute->next_hop_mac[2] == 0 &&
      sourceSiteRoute->next_hop_mac[3] == 0 && sourceSiteRoute->next_hop_mac[4] == 0 &&
      sourceSiteRoute->next_hop_mac[5] == 0;
}

static inline bool switchboardMasqueGatewayRedirectPermitted(
    __u8 action, __u8 fragment, bool boundaryMapPresent)
{
  return action == SWITCHBOARD_OVERLAY_ROUTE_ACTION_LOCAL_CONTAINER_REDIRECT &&
      (fragment == SWITCHBOARD_MASQUE_GATEWAY_FRAGMENT_FIRST ||
       fragment == SWITCHBOARD_MASQUE_GATEWAY_FRAGMENT_SECOND) && boundaryMapPresent;
}
