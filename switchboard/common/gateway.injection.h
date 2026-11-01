#pragma once

#include <switchboard/common/local_container_subnet.h>

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
