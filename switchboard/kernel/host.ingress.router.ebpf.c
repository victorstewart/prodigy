#include <ebpf/kernel/includes.h>
#include <ebpf/kernel/containersubnet.h>

#include <switchboard/common/checksum.h>
#include <switchboard/common/constants.h>
#include <switchboard/kernel/csum.h>
#include <switchboard/kernel/l4.ports.h>
#include <switchboard/kernel/services.h>
#include <switchboard/kernel/structs.h>
#include <switchboard/kernel/layer4.h>
#include <switchboard/kernel/overlay.encap.h>
#include <switchboard/kernel/overlay.ingress.auth.h>
#include <switchboard/kernel/overlay.routing.h>
#include <switchboard/kernel/portal.routing.h>
#include <switchboard/kernel/whitehole.routing.h>
#include <switchboard/kernel/wormhole.flow.h>

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
// Dev/test fake-boundary probes can inject IPv4 portal packets from inside the
// ecosystem. Production host ingress also owns portal state because a selected
// wormhole may arrive over another machine's overlay.
#endif

// the neuron attaches this program to the NIC
// if packet is destined for a container, it gets redirected into the host-side
// primary netkit path for that container
// otherwise passed to the kernel

__attribute__((__always_inline__)) static inline bool lookup_whitehole_reply_binding_ipv4(struct ethhdr *eth, void *data_end, struct switchboard_whitehole_binding *binding, bool *bound)
{
  if (bound == NULL)
  {
    return false;
  }
  *bound = false;
  struct iphdr *iph = (struct iphdr *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
  {
    return false;
  }

  struct flow_key flow = {};
  flow.src = iph->saddr;
  flow.dst = iph->daddr;
  flow.proto = iph->protocol;

  struct switchboard_l4_ports l4 = {};
  if (switchboard_parse_l4_ports((void *)(iph + 1), data_end, iph->protocol, sizeof(struct ethhdr) + sizeof(struct iphdr), &l4) == false)
  {
    return false;
  }
  flow.port16[0] = l4.source;
  flow.port16[1] = l4.dest;

  struct switchboard_whitehole_binding current = {};
  if (whitehole_binding_lookup(flow.proto, false, &flow.dst, flow.port16[1], &current) == false)
  {
    return false;
  }
  *bound = true;
  return whitehole_reply_binding_lookup(&flow, &current, binding);
}

__attribute__((__always_inline__)) static inline bool lookup_whitehole_reply_binding_ipv6(struct ethhdr *eth, void *data_end, struct switchboard_whitehole_binding *binding, bool *bound)
{
  if (bound == NULL)
  {
    return false;
  }
  *bound = false;
  struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
  if ((void *)(ip6h + 1) > data_end)
  {
    return false;
  }

  struct flow_key flow = {};
  bpf_memcpy(flow.srcv6, ip6h->saddr.s6_addr32, sizeof(flow.srcv6));
  bpf_memcpy(flow.dstv6, ip6h->daddr.s6_addr32, sizeof(flow.dstv6));
  flow.proto = ip6h->nexthdr;

  struct switchboard_l4_ports l4 = {};
  if (switchboard_parse_l4_ports((void *)(ip6h + 1), data_end, ip6h->nexthdr, sizeof(struct ethhdr) + sizeof(struct ipv6hdr), &l4) == false)
  {
    return false;
  }
  flow.port16[0] = l4.source;
  flow.port16[1] = l4.dest;

  struct switchboard_whitehole_binding current = {};
  if (whitehole_binding_lookup(flow.proto, true, flow.dstv6, flow.port16[1], &current) == false)
  {
    return false;
  }
  *bound = true;
  return whitehole_reply_binding_lookup(&flow, &current, binding);
}

__attribute__((__always_inline__)) static inline bool overlay_inner_ipv4_matches_declared_endpoint(struct iphdr *inner4, void *data_end)
{
  if (switchboard_unfragmented_ipv4(inner4, data_end) == false)
  {
    return false;
  }

  struct switchboard_l4_ports l4 = {};
  if (switchboard_parse_l4_ports((void *)(inner4 + 1), data_end, inner4->protocol, 0, &l4) == false)
  {
    return false;
  }

  struct portal_definition portal = {};
  portal.addr4 = inner4->daddr;
  portal.port = l4.dest;
  portal.proto = inner4->protocol;
  if (bpf_map_lookup_elem(&ext_portals, &portal) != NULL)
  {
    return true;
  }

  struct switchboard_whitehole_binding binding = {};
  return whitehole_binding_lookup(portal.proto, false, &portal.addr4, portal.port, &binding);
}

__attribute__((__always_inline__)) static inline bool overlay_inner_ipv6_matches_declared_endpoint(struct ipv6hdr *inner6, void *data_end)
{
  if ((void *)(inner6 + 1) > data_end)
  {
    return false;
  }

  struct switchboard_l4_ports l4 = {};
  if (switchboard_parse_l4_ports((void *)(inner6 + 1), data_end, inner6->nexthdr, 0, &l4) == false)
  {
    return false;
  }

  struct portal_definition portal = {};
  bpf_memcpy(portal.addr6, inner6->daddr.s6_addr32, sizeof(portal.addr6));
  portal.port = l4.dest;
  portal.proto = inner6->nexthdr;
  if (bpf_map_lookup_elem(&ext_portals, &portal) != NULL)
  {
    return true;
  }

  struct switchboard_whitehole_binding binding = {};
  return whitehole_binding_lookup(portal.proto, true, portal.addr6, portal.port, &binding);
}

__attribute__((__always_inline__)) static inline bool overlay_inner_targets_local(__u8 inner_proto, void *inner_l3, void *data_end)
{
  if (inner_proto == IPPROTO_IPIP)
  {
    struct iphdr *inner4 = (struct iphdr *)inner_l3;
    if ((void *)(inner4 + 1) > data_end)
    {
      return false;
    }

    if (overlayRoutablePrefixesContainIPv4(inner4->daddr))
    {
      return true;
    }

    return overlay_inner_ipv4_matches_declared_endpoint(inner4, data_end);
  }

  if (inner_proto == IPPROTO_IPV6)
  {
    struct ipv6hdr *inner6 = (struct ipv6hdr *)inner_l3;
    if ((void *)(inner6 + 1) > data_end)
    {
      return false;
    }

    if (localSubnetContainsDaddr(inner6->daddr.s6_addr) || overlayRoutablePrefixesContainIPv6(inner6->daddr.s6_addr32))
    {
      return true;
    }

    return overlay_inner_ipv6_matches_declared_endpoint(inner6, data_end);
  }

  return false;
}

__attribute__((__always_inline__)) static inline bool overlay_minimum_linear_bytes(struct __sk_buff *skb, __be16 wire_protocol, __u32 *minimum_bytes)
{
  if (skb == NULL || minimum_bytes == NULL)
  {
    return false;
  }

  *minimum_bytes = 0u;
  __u32 outer_header_bytes = 0u;
  __u32 outer_protocol_offset = 0u;
  if (wire_protocol == BE_ETH_P_IPV6)
  {
    outer_header_bytes = sizeof(struct ipv6hdr);
    outer_protocol_offset = sizeof(struct ethhdr) + __builtin_offsetof(struct ipv6hdr, nexthdr);
  }
  else if (wire_protocol == BE_ETH_P_IP)
  {
    outer_header_bytes = sizeof(struct iphdr);
    outer_protocol_offset = sizeof(struct ethhdr) + __builtin_offsetof(struct iphdr, protocol);
  }
  else
  {
    return true;
  }

  __u8 inner_protocol = 0;
  if (bpf_skb_load_bytes(skb, outer_protocol_offset, &inner_protocol, sizeof(inner_protocol)) != 0)
  {
    return false;
  }
  if (inner_protocol != IPPROTO_IPIP && inner_protocol != IPPROTO_IPV6)
  {
    return true;
  }

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  __u32 zero = 0;
  struct local_container_subnet6 *localSubnet = bpf_map_lookup_elem(&lc_subnet, &zero);
  if ((void *)(eth + 1) > data_end)
  {
    return false;
  }
  if (wire_protocol == BE_ETH_P_IPV6)
  {
    struct ipv6hdr *outer6 = (void *)(eth + 1);
    if ((void *)(outer6 + 1) > data_end ||
        overlayIngressPeerAuthorizedIPv6(skb, outer6->saddr.s6_addr, outer6->daddr.s6_addr, localSubnet) == false)
    {
      return false;
    }
  }
  else
  {
    struct iphdr *outer4 = (void *)(eth + 1);
    if ((void *)(outer4 + 1) > data_end ||
        overlayIngressPeerAuthorizedIPv4(outer4->saddr, outer4->daddr) == false)
    {
      return false;
    }
  }

  __u8 version_ihl = 0;
  if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &version_ihl, sizeof(version_ihl)) != 0 ||
      (wire_protocol == BE_ETH_P_IP ? version_ihl != 0x45u : (version_ihl >> 4) != 6u))
  {
    return false;
  }

  const __u32 inner_offset = sizeof(struct ethhdr) + outer_header_bytes;
  if (bpf_skb_load_bytes(skb, inner_offset, &version_ihl, sizeof(version_ihl)) != 0 ||
      (inner_protocol == IPPROTO_IPIP ? version_ihl != 0x45u : (version_ihl >> 4) != 6u))
  {
    return false;
  }

  const __u32 transport_protocol_offset = inner_offset + (inner_protocol == IPPROTO_IPIP
                                                               ? __builtin_offsetof(struct iphdr, protocol)
                                                               : __builtin_offsetof(struct ipv6hdr, nexthdr));
  __u8 transport_protocol = 0;
  if (bpf_skb_load_bytes(skb, transport_protocol_offset, &transport_protocol, sizeof(transport_protocol)) != 0)
  {
    return false;
  }

  *minimum_bytes = switchboardHostIngressOverlayMinimumLinearBytes(wire_protocol, inner_protocol, transport_protocol);
  return *minimum_bytes != 0u;
}

__attribute__((__always_inline__)) static inline int maybe_redirect_whitehole_reply(struct ethhdr *eth, void *data_end, bool *handled)
{
  if (handled == NULL)
  {
    return TC_ACT_OK;
  }

  *handled = false;

  if (eth->h_proto == BE_ETH_P_IPV6)
  {
    struct switchboard_whitehole_binding replyBinding = {};
    bool bound = false;
    if (lookup_whitehole_reply_binding_ipv6(eth, data_end, &replyBinding, &bound))
    {
      *handled = true;
      null_mac_addresses(eth);
      if (replyBinding.container.hasID && redirectContainerFragment(replyBinding.container.value[4], true))
      {
        return TC_ACT_REDIRECT;
      }

      return TC_ACT_SHOT;
    }
    if (bound)
    {
      *handled = true;
      return TC_ACT_SHOT;
    }
  }
  else if (eth->h_proto == BE_ETH_P_IP)
  {
    struct switchboard_whitehole_binding replyBinding = {};
    bool bound = false;
    if (lookup_whitehole_reply_binding_ipv4(eth, data_end, &replyBinding, &bound))
    {
      *handled = true;
      null_mac_addresses(eth);
      if (replyBinding.container.hasID && redirectContainerFragment(replyBinding.container.value[4], true))
      {
        return TC_ACT_REDIRECT;
      }

      return TC_ACT_SHOT;
    }
    if (bound)
    {
      *handled = true;
      return TC_ACT_SHOT;
    }
  }

  return TC_ACT_OK;
}

__attribute__((__always_inline__)) static inline bool switchboardParsePortalPacket(struct __sk_buff *skb,
                                                                                    struct ethhdr *eth,
                                                                                    void *data_end,
                                                                                    bool isIPv6,
                                                                                    struct packet_description *packet)
{
  if (skb == NULL || eth == NULL || packet == NULL || (void *)(eth + 1) > data_end)
  {
    return false;
  }

  bpf_memset(packet, 0, sizeof(*packet));
  if (isIPv6)
  {
    struct ipv6hdr *ip6h = (void *)(eth + 1);
    if (eth->h_proto != BE_ETH_P_IPV6 || (void *)(ip6h + 1) > data_end)
    {
      return false;
    }
    packet->flow.proto = ip6h->nexthdr;
    bpf_memcpy(packet->flow.srcv6, ip6h->saddr.s6_addr32, sizeof(packet->flow.srcv6));
    bpf_memcpy(packet->flow.dstv6, ip6h->daddr.s6_addr32, sizeof(packet->flow.dstv6));
  }
  else
  {
    struct iphdr *iph = (void *)(eth + 1);
    if (eth->h_proto != BE_ETH_P_IP || switchboard_unfragmented_ipv4(iph, data_end) == false)
    {
      return false;
    }
    packet->flow.proto = iph->protocol;
    packet->flow.src = iph->saddr;
    packet->flow.dst = iph->daddr;
  }

  if (packet->flow.proto == IPPROTO_TCP)
  {
    return parse_tcp((void *)(long)skb->data, data_end, isIPv6, packet);
  }
  if (packet->flow.proto == IPPROTO_UDP)
  {
    return parse_udp((void *)(long)skb->data, data_end, isIPv6, packet);
  }
  return false;
}

__attribute__((__always_inline__)) static inline int switchboardRouteSelectedWormhole(struct __sk_buff *skb,
                                                                                       const struct container_id *containerID,
                                                                                       bool isIPv6)
{
  if (skb == NULL || containerID == NULL || containerID->hasID == false)
  {
    return TC_ACT_SHOT;
  }
  __u32 machineFragment = ((__u32)containerID->value[1] << 16) |
                          ((__u32)containerID->value[2] << 8) |
                          (__u32)containerID->value[3];
  struct switchboard_overlay_machine_route *route = lookupOverlayMachineRouteByFragment(machineFragment);
  if (skb->len <= sizeof(struct ethhdr) || skb->len - sizeof(struct ethhdr) > 0xffffu)
  {
    return TC_ACT_SHOT;
  }
  __u16 innerBytes = (__u16)(skb->len - sizeof(struct ethhdr));
  return innerBytes <= WORMHOLE_PUBLIC_INGRESS_L3_MTU && route != NULL &&
                 switchboardEncapWormholeSKB(skb,
                                             innerBytes,
                                             isIPv6 ? IPPROTO_IPV6 : IPPROTO_IPIP,
                                             route,
                                             containerID)
             ? TC_ACT_OK
             : TC_ACT_SHOT;
}

__attribute__((__always_inline__)) static inline bool switchboardLearnAndRewriteLocalWormholeIPv6(struct __sk_buff *skb,
                                                                                                   struct packet_description *packet,
                                                                                                   const struct container_id *containerID,
                                                                                                   __be16 targetPort)
{
  struct portal_definition portal = {};
  if (switchboardPacketPortalDefinition(packet, true, &portal) == false ||
      switchboardLearnPublicWormholeFlowIPv6(packet, containerID, targetPort, &portal) == false ||
      switchboardRewriteWormholeIPv6TargetSKB(skb, packet, containerID, targetPort) == false)
  {
    return false;
  }
  skb->mark = SWITCHBOARD_WORMHOLE_SKB_MARK;
  return true;
}

__attribute__((__always_inline__)) static inline bool switchboardLearnAndRewriteLocalWormholeIPv4(struct __sk_buff *skb,
                                                                                                   struct packet_description *packet,
                                                                                                   const struct container_id *containerID,
                                                                                                   __be16 targetPort)
{
  struct portal_definition portal = {};
  if (switchboardPacketPortalDefinition(packet, false, &portal) == false ||
      switchboardLearnPublicWormholeFlowIPv4(packet, containerID, targetPort, &portal) == false ||
      switchboardRewriteWormholeIPv4TargetSKB(skb, packet, targetPort) == false)
  {
    return false;
  }
  skb->mark = SWITCHBOARD_WORMHOLE_SKB_MARK;
  return true;
}

__attribute__((__always_inline__)) static inline int maybe_redirect_ipv4_portal_packet(struct __sk_buff *skb,
                                                                                       struct ethhdr *eth,
                                                                                       void *data_end,
                                                                                       struct packet_description *packet,
                                                                                       bool *handled)
{
  if (packet == NULL || handled == NULL)
  {
    return TC_ACT_OK;
  }

  *handled = false;

  if (eth == NULL || eth->h_proto != BE_ETH_P_IP)
  {
    return TC_ACT_OK;
  }

  if (switchboardParsePortalPacket(skb, eth, data_end, false, packet) == false)
  {
    return TC_ACT_OK;
  }

  struct container_id containerID = {};
  struct portal_meta *portalMeta = NULL;
  int resolved = switchboardResolveExternalPortalTarget((void *)(long)skb->data,
                                                        data_end,
                                                        false,
                                                        packet,
                                                        &containerID,
                                                        &portalMeta);
  if (resolved == SWITCHBOARD_PORTAL_TARGET_NONE)
  {
    return TC_ACT_OK;
  }

  *handled = true;
  if (resolved != SWITCHBOARD_PORTAL_TARGET_RESOLVED || portalMeta == NULL || containerID.hasID == false)
  {
    return TC_ACT_SHOT;
  }

  __u32 zeroidx = 0;
  struct local_container_subnet6 *localSubnet = bpf_map_lookup_elem(&lc_subnet, &zeroidx);
  if (switchboardContainerIDTargetsLocalMachine(&containerID, localSubnet) == false)
  {
    return switchboardRouteSelectedWormhole(skb, &containerID, false);
  }

  __u16 targetPort = 0;
  if (switchboardLookupWormholeTargetPort(portalMeta->slot, &containerID, &targetPort) == false ||
      switchboardLearnAndRewriteLocalWormholeIPv4(skb, packet, &containerID, targetPort) == false)
  {
    return TC_ACT_SHOT;
  }

  data_end = (void *)(long)skb->data_end;
  eth = (struct ethhdr *)(long)skb->data;
  if ((void *)(eth + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }

  null_mac_addresses(eth);
  if (redirectContainerFragment(containerID.value[4], true))
  {
    return TC_ACT_REDIRECT;
  }

  return TC_ACT_SHOT;
}

__attribute__((__always_inline__)) static inline int maybe_redirect_ipv6_portal_packet(struct __sk_buff *skb,
                                                                                       struct ethhdr *eth,
                                                                                       void *data_end,
                                                                                       struct packet_description *packet,
                                                                                       bool *handled)
{
  if (packet == NULL || handled == NULL)
  {
    return TC_ACT_OK;
  }

  *handled = false;

  if (eth == NULL || eth->h_proto != BE_ETH_P_IPV6)
  {
    return TC_ACT_OK;
  }

  if (switchboardParsePortalPacket(skb, eth, data_end, true, packet) == false)
  {
    return TC_ACT_OK;
  }

  struct container_id containerID = {};
  struct portal_meta *portalMeta = NULL;
  int resolved = switchboardResolveExternalPortalTarget((void *)(long)skb->data,
                                                        data_end,
                                                        true,
                                                        packet,
                                                        &containerID,
                                                        &portalMeta);
  if (resolved == SWITCHBOARD_PORTAL_TARGET_NONE)
  {
    return TC_ACT_OK;
  }

  *handled = true;
  if (resolved != SWITCHBOARD_PORTAL_TARGET_RESOLVED || portalMeta == NULL || containerID.hasID == false)
  {
    return TC_ACT_SHOT;
  }

  __u32 zeroidx = 0;
  struct local_container_subnet6 *localSubnet = bpf_map_lookup_elem(&lc_subnet, &zeroidx);
  if (switchboardContainerIDTargetsLocalMachine(&containerID, localSubnet) == false)
  {
    return switchboardRouteSelectedWormhole(skb, &containerID, true);
  }

  __u16 targetPort = 0;
  if (switchboardLookupWormholeTargetPort(portalMeta->slot, &containerID, &targetPort) == false ||
      switchboardLearnAndRewriteLocalWormholeIPv6(skb, packet, &containerID, targetPort) == false)
  {
    return TC_ACT_SHOT;
  }

  data_end = (void *)(long)skb->data_end;
  eth = (struct ethhdr *)(long)skb->data;
  if ((void *)(eth + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }

  null_mac_addresses(eth);
  if (redirectContainerFragment(containerID.value[4], true))
  {
    return TC_ACT_REDIRECT;
  }

  return TC_ACT_SHOT;
}

__attribute__((__always_inline__)) static inline int switchboardRedirectSelectedWormhole(struct __sk_buff *skb,
                                                                                          const struct container_id *containerID,
                                                                                          bool isIPv6,
                                                                                          struct packet_description *packet)
{
  if (skb == NULL || containerID == NULL || containerID->hasID == false || packet == NULL)
  {
    return TC_ACT_SHOT;
  }

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  struct portal_definition portal = {};
  if (switchboardParsePortalPacket(skb, eth, data_end, isIPv6, packet) == false ||
      switchboardPacketPortalDefinition(packet, isIPv6, &portal) == false)
  {
    return TC_ACT_SHOT;
  }

  struct portal_meta *meta = bpf_map_lookup_elem(&ext_portals, &portal);
  __be16 targetPort = 0;
  // The unchanged inner destination tuple is the canonical portal identity.
  // Resolve its target-machine-local slot here; slot allocation order is not
  // a cluster-wide wire contract.
  if (meta == NULL ||
      switchboardLookupWormholeTargetPort(meta->slot, containerID, &targetPort) == false)
  {
    return TC_ACT_SHOT;
  }

  bool rewritten = isIPv6
                       ? switchboardLearnAndRewriteLocalWormholeIPv6(skb, packet, containerID, targetPort)
                       : switchboardLearnAndRewriteLocalWormholeIPv4(skb, packet, containerID, targetPort);
  if (rewritten == false)
  {
    return TC_ACT_SHOT;
  }

  data_end = (void *)(long)skb->data_end;
  eth = (void *)(long)skb->data;
  if ((void *)(eth + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }
  null_mac_addresses(eth);
  return redirectContainerFragment(containerID->value[4], true) ? TC_ACT_REDIRECT : TC_ACT_SHOT;
}

__attribute__((__always_inline__)) static inline int maybe_redirect_wormhole_overlay_packet(struct __sk_buff *skb,
                                                                                             struct packet_description *packet,
                                                                                             bool *handled)
{
  if (skb == NULL || packet == NULL || handled == NULL)
  {
    return TC_ACT_OK;
  }
  *handled = false;

  __be16 wireProtocol = 0;
  if (bpf_skb_load_bytes(skb, __builtin_offsetof(struct ethhdr, h_proto), &wireProtocol, sizeof(wireProtocol)) != 0)
  {
    return TC_ACT_OK;
  }

  __u32 outerBytes = 0;
  __u32 outerProtocolOffset = 0;
  if (wireProtocol == BE_ETH_P_IPV6)
  {
    outerBytes = sizeof(struct ipv6hdr);
    outerProtocolOffset = sizeof(struct ethhdr) + __builtin_offsetof(struct ipv6hdr, nexthdr);
  }
  else if (wireProtocol == BE_ETH_P_IP)
  {
    outerBytes = sizeof(struct iphdr);
    outerProtocolOffset = sizeof(struct ethhdr) + __builtin_offsetof(struct iphdr, protocol);
  }
  else
  {
    return TC_ACT_OK;
  }

  __u8 outerProtocol = 0;
  __u8 outerVersion = 0;
  if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &outerVersion, sizeof(outerVersion)) != 0 ||
      bpf_skb_load_bytes(skb, outerProtocolOffset, &outerProtocol, sizeof(outerProtocol)) != 0)
  {
    return TC_ACT_OK;
  }
  if (outerProtocol != IPPROTO_GRE)
  {
    return TC_ACT_OK;
  }
  *handled = true;
  if (wireProtocol == BE_ETH_P_IPV6 ? (outerVersion >> 4) != 6u : outerVersion != 0x45u)
  {
    return TC_ACT_SHOT;
  }

  struct switchboard_wormhole_overlay_header wormhole = {};
  __u32 wormholeOffset = sizeof(struct ethhdr) + outerBytes;
  if (bpf_skb_load_bytes(skb, wormholeOffset, &wormhole, sizeof(wormhole)) != 0 ||
      wormhole.flags != switchboardHostToBE16(SWITCHBOARD_WORMHOLE_GRE_FLAGS))
  {
    return TC_ACT_SHOT;
  }
  if (switchboardWormholeOverlayHeaderValid(&wormhole) == false)
  {
    return TC_ACT_SHOT;
  }

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *outerEth = data;
  __u32 zero = 0;
  struct local_container_subnet6 *localSubnet = bpf_map_lookup_elem(&lc_subnet, &zero);
  if ((void *)(outerEth + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }
  if (wireProtocol == BE_ETH_P_IPV6)
  {
    struct ipv6hdr *outer6 = (void *)(outerEth + 1);
    if ((void *)(outer6 + 1) > data_end ||
        overlayIngressPeerAuthorizedIPv6(skb, outer6->saddr.s6_addr, outer6->daddr.s6_addr, localSubnet) == false)
    {
      return TC_ACT_SHOT;
    }
  }
  else
  {
    struct iphdr *outer4 = (void *)(outerEth + 1);
    if ((void *)(outer4 + 1) > data_end ||
        overlayIngressPeerAuthorizedIPv4(outer4->saddr, outer4->daddr) == false)
    {
      return TC_ACT_SHOT;
    }
  }

  __u32 innerOffset = wormholeOffset + sizeof(wormhole);
  __u8 version = 0;
  if (bpf_skb_load_bytes(skb, innerOffset, &version, sizeof(version)) != 0 ||
      (wormhole.protocol == BE_ETH_P_IPV6 ? (version >> 4) != 6u : version != 0x45u))
  {
    return TC_ACT_SHOT;
  }

  __u32 transportProtocolOffset = innerOffset + (wormhole.protocol == BE_ETH_P_IPV6
                                                      ? __builtin_offsetof(struct ipv6hdr, nexthdr)
                                                      : __builtin_offsetof(struct iphdr, protocol));
  __u8 transportProtocol = 0;
  if (bpf_skb_load_bytes(skb, transportProtocolOffset, &transportProtocol, sizeof(transportProtocol)) != 0 ||
      (transportProtocol != IPPROTO_TCP && transportProtocol != IPPROTO_UDP))
  {
    return TC_ACT_SHOT;
  }
  __u32 minimumBytes = switchboardHostIngressWormholeOverlayMinimumLinearBytes(wireProtocol,
                                                                               wormhole.protocol,
                                                                               transportProtocol);
  if (minimumBytes == 0u || bpf_skb_pull_data(skb, minimumBytes) != 0)
  {
    return TC_ACT_SHOT;
  }

  struct container_id containerID = {};
  if (switchboardWormholeOverlayContainerID(&wormhole, &containerID) == false ||
      switchboardContainerIDTargetsLocalMachine(&containerID, localSubnet) == false)
  {
    return TC_ACT_SHOT;
  }

  __u64 decapFlags = switchboardAdjustRoomPreserveOffloadFlags() |
                     (wormhole.protocol == BE_ETH_P_IPV6 ? BPF_F_ADJ_ROOM_DECAP_L3_IPV6 : BPF_F_ADJ_ROOM_DECAP_L3_IPV4);
  if (bpf_skb_adjust_room(skb,
                          -(__s32)(outerBytes + sizeof(wormhole)),
                          BPF_ADJ_ROOM_MAC,
                          decapFlags) != 0)
  {
    return TC_ACT_SHOT;
  }

  data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = (void *)(long)skb->data;
  if ((void *)(eth + 1) > data_end || skb->protocol != wormhole.protocol)
  {
    return TC_ACT_SHOT;
  }
  eth->h_proto = wormhole.protocol;
  return switchboardRedirectSelectedWormhole(skb,
                                              &containerID,
                                              wormhole.protocol == BE_ETH_P_IPV6,
                                              packet);
}

__attribute__((__always_inline__)) static inline bool maybe_decap_overlay_packet(struct __sk_buff *skb)
{
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = (struct ethhdr *)(long)skb->data;
  if ((void *)(eth + 1) > data_end)
  {
    return false;
  }

  if (eth->h_proto == BE_ETH_P_IPV6)
  {
    struct ipv6hdr *ipv6h = (struct ipv6hdr *)(eth + 1);
    if ((void *)(ipv6h + 1) > data_end)
    {
      return false;
    }

    if (ipv6h->nexthdr != IPPROTO_IPIP && ipv6h->nexthdr != IPPROTO_IPV6)
    {
      return false;
    }

    void *inner_l3 = (void *)(ipv6h + 1);
    if (overlay_inner_targets_local(ipv6h->nexthdr, inner_l3, data_end) == false)
    {
      return false;
    }

    __u64 decap_flags = switchboardAdjustRoomPreserveOffloadFlags() | (ipv6h->nexthdr == IPPROTO_IPV6
                                                                           ? BPF_F_ADJ_ROOM_DECAP_L3_IPV6
                                                                           : BPF_F_ADJ_ROOM_DECAP_L3_IPV4);
    return bpf_skb_adjust_room(skb,
                               -(__s32)sizeof(struct ipv6hdr),
                               BPF_ADJ_ROOM_MAC,
                               decap_flags) == 0;
  }

  if (eth->h_proto == BE_ETH_P_IP)
  {
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
    {
      return false;
    }

    if (iph->protocol != IPPROTO_IPIP && iph->protocol != IPPROTO_IPV6)
    {
      return false;
    }

    void *inner_l3 = (void *)(iph + 1);
    if (overlay_inner_targets_local(iph->protocol, inner_l3, data_end) == false)
    {
      return false;
    }

    __u64 decap_flags = switchboardAdjustRoomPreserveOffloadFlags() | (iph->protocol == IPPROTO_IPV6
                                                                           ? BPF_F_ADJ_ROOM_DECAP_L3_IPV6
                                                                           : BPF_F_ADJ_ROOM_DECAP_L3_IPV4);
    return bpf_skb_adjust_room(skb,
                               -(__s32)sizeof(struct iphdr),
                               BPF_ADJ_ROOM_MAC,
                               decap_flags) == 0;
  }

  return false;
}

__attribute__((__always_inline__)) static inline int maybe_route_hosted_ingress_packet(struct __sk_buff *skb, struct ethhdr *eth, void *data_end, bool *handled)
{
  if (handled == NULL)
  {
    return TC_ACT_OK;
  }

  *handled = false;

  if (eth == NULL)
  {
    return TC_ACT_OK;
  }

  int action = TC_ACT_OK;
  if (eth->h_proto == BE_ETH_P_IP && switchboardMaybeRouteHostedIngressIPv4(skb, eth, data_end, &action))
  {
    *handled = true;
    return action;
  }

  if (eth->h_proto == BE_ETH_P_IPV6 && switchboardMaybeRouteHostedIngressIPv6(skb, eth, data_end, &action))
  {
    *handled = true;
    return action;
  }

  return TC_ACT_OK;
}

__attribute__((__always_inline__)) static inline int maybe_redirect_plain_local_ipv6_packet(struct ethhdr *eth, void *data_end, bool *handled)
{
  if (handled == NULL)
  {
    return TC_ACT_OK;
  }

  *handled = false;

  if (eth == NULL || eth->h_proto != BE_ETH_P_IPV6)
  {
    return TC_ACT_OK;
  }

  struct ipv6hdr *ipv6h = (struct ipv6hdr *)(eth + 1);
  if ((void *)(ipv6h + 1) > data_end)
  {
    return TC_ACT_OK;
  }

  if (ipv6h->nexthdr == IPPROTO_IPIP || ipv6h->nexthdr == IPPROTO_IPV6)
  {
    return TC_ACT_OK;
  }

  __be8 *daddr6 = ipv6h->daddr.s6_addr;
  if (localSubnetContainsDaddr(daddr6) == false)
  {
    return TC_ACT_OK;
  }

  *handled = true;
  // netkit_xmit() classifies skb->pkt_type for the destination peer before
  // the primary-attached BPF program runs. Normalize the host NIC Ethernet
  // header here so the receiving peer is PACKET_HOST, not OTHERHOST.
  null_mac_addresses(eth);
  if (redirectToContainer(daddr6, true) == TC_ACT_REDIRECT)
  {
    return TC_ACT_REDIRECT;
  }

  // Container-subnet destinations must resolve to a host-side primary
  // netkit device for the destination container. If the boundary map is stale
  // or the container is gone, fail closed.
  return TC_ACT_SHOT;
}

// Native host traffic should bypass the heavier overlay/container parsing path.
// The maintained host-control failure is on plain machine-to-machine TCP/UDP,
// so only keep packets on the slow path when they can still target a container,
// a whitehole reply binding, or an overlay decap path.
__attribute__((__always_inline__)) static inline bool should_fast_pass_native_host_packet(struct ethhdr *eth, void *data_end)
{
  if (eth == NULL)
  {
    return false;
  }

  if (eth->h_proto == BE_ETH_P_IP)
  {
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    struct switchboard_whitehole_binding replyBinding = {};
    bool whiteholeBound = false;
    if ((void *)(iph + 1) > data_end)
    {
      return false;
    }

    if (iph->protocol == IPPROTO_IPIP || iph->protocol == IPPROTO_IPV6)
    {
      return false;
    }

    if (overlayRoutablePrefixesContainIPv4(iph->daddr))
    {
      return false;
    }

    if (lookup_whitehole_reply_binding_ipv4(eth, data_end, &replyBinding, &whiteholeBound) || whiteholeBound)
    {
      return false;
    }

    return true;
  }

  if (eth->h_proto == BE_ETH_P_IPV6)
  {
    struct ipv6hdr *ipv6h = (struct ipv6hdr *)(eth + 1);
    struct switchboard_whitehole_binding replyBinding = {};
    bool whiteholeBound = false;
    if ((void *)(ipv6h + 1) > data_end)
    {
      return false;
    }

    if (ipv6h->nexthdr == IPPROTO_IPIP || ipv6h->nexthdr == IPPROTO_IPV6)
    {
      return false;
    }

    if (localSubnetContainsDaddr(ipv6h->daddr.s6_addr) || overlayRoutablePrefixesContainIPv6(ipv6h->daddr.s6_addr32))
    {
      return false;
    }

    if (lookup_whitehole_reply_binding_ipv6(eth, data_end, &replyBinding, &whiteholeBound) || whiteholeBound)
    {
      return false;
    }

    return true;
  }

  return false;
}

SEC("tcx/ingress")
int host_ingress(struct __sk_buff *skb)
{
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = (struct ethhdr *)(long)skb->data;

  if ((void *)(eth + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }

  struct packet_description portalPacket = {};

  bool handledWhiteholeReply = false;
  int whiteholeReplyAction = maybe_redirect_whitehole_reply(eth, data_end, &handledWhiteholeReply);
  if (handledWhiteholeReply)
  {
    return whiteholeReplyAction;
  }

  bool handledWormholeOverlay = false;
  int wormholeOverlayAction = maybe_redirect_wormhole_overlay_packet(skb, &portalPacket, &handledWormholeOverlay);
  if (handledWormholeOverlay)
  {
    return wormholeOverlayAction;
  }

  bool handledIPv4Portal = false;
  int ipv4PortalAction = maybe_redirect_ipv4_portal_packet(skb, eth, data_end, &portalPacket, &handledIPv4Portal);
  if (handledIPv4Portal)
  {
    return ipv4PortalAction;
  }

  bool handledIPv6Portal = false;
  int ipv6PortalAction = maybe_redirect_ipv6_portal_packet(skb, eth, data_end, &portalPacket, &handledIPv6Portal);
  if (handledIPv6Portal)
  {
    return ipv6PortalAction;
  }

  bool handledHostedIngress = false;
  int hostedIngressAction = maybe_route_hosted_ingress_packet(skb, eth, data_end, &handledHostedIngress);
  if (handledHostedIngress)
  {
    return hostedIngressAction;
  }

  bool handledPlainLocalIPv6 = false;
  int plainLocalIPv6Action = maybe_redirect_plain_local_ipv6_packet(eth, data_end, &handledPlainLocalIPv6);
  if (handledPlainLocalIPv6)
  {
    return plainLocalIPv6Action;
  }

  if (should_fast_pass_native_host_packet(eth, data_end))
  {
    return TC_ACT_OK;
  }

  __u32 minimum_linear_bytes = 0u;
  if (overlay_minimum_linear_bytes(skb, eth->h_proto, &minimum_linear_bytes) == false ||
      (minimum_linear_bytes != 0u && bpf_skb_pull_data(skb, minimum_linear_bytes) != 0))
  {
    return TC_ACT_SHOT;
  }

  data_end = (void *)(long)skb->data_end;
  eth = (struct ethhdr *)(long)skb->data;
  if ((void *)(eth + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }

  bool decapped = minimum_linear_bytes != 0u && maybe_decap_overlay_packet(skb);

  // maybe_decap_overlay_packet() can call bpf_skb_adjust_room(), which invalidates
  // all previously derived packet pointers regardless of whether we ended up
  // decapsulating. Always refresh skb data pointers before continuing.
  eth = (struct ethhdr *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;
  if ((void *)(eth + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }

  __be16 protocol = switchboardHostIngressEffectiveProtocol(eth->h_proto, skb->protocol, decapped);
  if (eth->h_proto != protocol)
  {
    // After overlay decap the kernel updates skb->protocol to the inner L3
    // type, but the preserved Ethernet placeholder still carries the outer
    // ethertype. Normalize it before parsing or redirecting into netkit.
    eth->h_proto = protocol;
  }

  if (protocol == BE_ETH_P_IPV6)
  {
    struct ipv6hdr *ipv6h = (struct ipv6hdr *)(eth + 1);
    struct switchboard_whitehole_binding replyBinding = {};
    bool whiteholeBound = false;

    if ((void *)(ipv6h + 1) > data_end)
    {
      return TC_ACT_SHOT;
    }

    if (decapped)
    {
      bool handledDecappedIPv6Portal = false;
      int decappedIPv6PortalAction = maybe_redirect_ipv6_portal_packet(skb,
                                                                       eth,
                                                                       data_end,
                                                                       &portalPacket,
                                                                       &handledDecappedIPv6Portal);
      if (handledDecappedIPv6Portal)
      {
        return decappedIPv6PortalAction;
      }
    }

    __be8 *daddr6 = ipv6h->daddr.s6_addr;

    if (localSubnetContainsDaddr(daddr6))
    {
      // netkit_xmit() classifies skb->pkt_type for the destination peer before
      // the primary-attached BPF program runs. Normalize the host NIC Ethernet
      // header here so the receiving peer is PACKET_HOST, not OTHERHOST.
      null_mac_addresses(eth);
      if (redirectToContainer(daddr6, true) == TC_ACT_REDIRECT)
      {
        return TC_ACT_REDIRECT;
      }
      else
      {
        // Container-subnet destinations must resolve to a host-side primary
        // netkit device for the destination container.
        // If the boundary map is stale or the container is gone, fail closed.
        return TC_ACT_SHOT;
      }
    }

    if (lookup_whitehole_reply_binding_ipv6(eth, data_end, &replyBinding, &whiteholeBound))
    {
      null_mac_addresses(eth);
      if (replyBinding.container.hasID && redirectContainerFragment(replyBinding.container.value[4], true))
      {
        return TC_ACT_REDIRECT;
      }

      return TC_ACT_SHOT;
    }
    if (whiteholeBound)
    {
      return TC_ACT_SHOT;
    }

    if (overlayRoutablePrefixesContainIPv6(ipv6h->daddr.s6_addr32))
    {
      struct container_id containerID = {.value = {0}, .hasID = false};
      if (setContainerIDFromDistributedIPv6(&containerID, ipv6h->daddr.s6_addr32) == false)
      {
        return TC_ACT_SHOT;
      }

      null_mac_addresses(eth);
      if (redirectContainerFragment(containerID.value[4], true))
      {
        return TC_ACT_REDIRECT;
      }

      return TC_ACT_SHOT;
    }
  }
  else if (protocol == BE_ETH_P_IP)
  {
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    struct switchboard_whitehole_binding replyBinding = {};
    bool whiteholeBound = false;
    if ((void *)(iph + 1) > data_end)
    {
      return TC_ACT_SHOT;
    }

    bool handledDecappedIPv4Portal = false;
    int decappedIPv4PortalAction = maybe_redirect_ipv4_portal_packet(skb,
                                                                     eth,
                                                                     data_end,
                                                                     &portalPacket,
                                                                     &handledDecappedIPv4Portal);
    if (handledDecappedIPv4Portal)
    {
      return decappedIPv4PortalAction;
    }

    if (lookup_whitehole_reply_binding_ipv4(eth, data_end, &replyBinding, &whiteholeBound))
    {
      null_mac_addresses(eth);
      if (replyBinding.container.hasID && redirectContainerFragment(replyBinding.container.value[4], true))
      {
        return TC_ACT_REDIRECT;
      }

      return TC_ACT_SHOT;
    }
    if (whiteholeBound)
    {
      return TC_ACT_SHOT;
    }

    if (overlayRoutablePrefixesContainIPv4(iph->daddr))
    {
      __u32 zeroidx = 0;
      struct local_container_subnet6 *localcontainersubnet6 = bpf_map_lookup_elem(&lc_subnet, &zeroidx);
      struct container_id containerID = {.value = {0}, .hasID = false};
      if (setContainerIDFromDistributedIPv4(&containerID, iph->daddr, localcontainersubnet6) == false)
      {
        return TC_ACT_SHOT;
      }

      null_mac_addresses(eth);
      if (redirectContainerFragment(containerID.value[4], true))
      {
        return TC_ACT_REDIRECT;
      }

      return TC_ACT_SHOT;
    }
  }

  return TC_ACT_OK;
}
