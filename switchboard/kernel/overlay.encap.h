#pragma once

#include <switchboard/kernel/csum.h>
#include <switchboard/kernel/overlay.routing.h>
#include <switchboard/kernel/services.h>

__attribute__((__always_inline__)) static inline bool switchboardEncapSKBV6(struct __sk_buff *skb,
                                                                            __u16 inner_packet_len,
                                                                            __u8 inner_proto,
                                                                            const struct switchboard_overlay_machine_route *route)
{
  if (route == NULL || route->family != SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6)
  {
    return false;
  }

  // NETKIT_L3 skb overlay growth preserves the transport payload but can
  // leave the first inner L3 header bytes zeroed. Snapshot the inner header
  // and restore it after outer-header insertion so host ingress can still
  // route by the destination container subnet.
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = (struct ethhdr *)(long)skb->data;
  struct ipv6hdr inner6 = {};
  struct iphdr inner4 = {};

  if ((void *)(eth + 1) > data_end)
  {
    return false;
  }

  if (inner_proto == IPPROTO_IPV6)
  {
    struct ipv6hdr *originalInner6 = (struct ipv6hdr *)(eth + 1);
    if ((void *)(originalInner6 + 1) > data_end)
    {
      return false;
    }

    bpf_memcpy(&inner6, originalInner6, sizeof(inner6));
  }
  else if (inner_proto == IPPROTO_IPIP)
  {
    struct iphdr *originalInner4 = (struct iphdr *)(eth + 1);
    if ((void *)(originalInner4 + 1) > data_end)
    {
      return false;
    }

    bpf_memcpy(&inner4, originalInner4, sizeof(inner4));
  }
  else
  {
    return false;
  }

  if (bpf_skb_adjust_room(skb, (__s32)sizeof(struct ipv6hdr), BPF_ADJ_ROOM_NET, switchboardOverlayEncapAdjustRoomFlagsIPv6()))
  {
    return false;
  }

  data_end = (void *)(long)skb->data_end;
  eth = (struct ethhdr *)(long)skb->data;
  struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);

  if ((void *)(eth + 1) > data_end || (void *)(ip6h + 1) > data_end)
  {
    return false;
  }

  if (inner_proto == IPPROTO_IPV6)
  {
    struct ipv6hdr *restoredInner6 = (struct ipv6hdr *)(ip6h + 1);
    if ((void *)(restoredInner6 + 1) > data_end)
    {
      return false;
    }

    bpf_memcpy(restoredInner6, &inner6, sizeof(inner6));
  }
  else
  {
    struct iphdr *restoredInner4 = (struct iphdr *)(ip6h + 1);
    if ((void *)(restoredInner4 + 1) > data_end)
    {
      return false;
    }

    bpf_memcpy(restoredInner4, &inner4, sizeof(inner4));
  }

  eth->h_proto = BE_ETH_P_IPV6;
  ip6h->priority = 0;
  ip6h->version = 6;
  bpf_memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
  ip6h->payload_len = bpf_htons(inner_packet_len);
  ip6h->nexthdr = inner_proto;
  ip6h->hop_limit = 64;
  bpf_memcpy(ip6h->saddr.s6_addr, route->source6, sizeof(route->source6));
  bpf_memcpy(ip6h->daddr.s6_addr, route->next_hop6, sizeof(route->next_hop6));

  if (route->use_gateway_mac != 0)
  {
    return from_us_to_gateway(eth);
  }

  return from_us_to_overlay_next_hop(eth, route->next_hop_mac);
}

__attribute__((__always_inline__)) static inline bool switchboardEncapSKBV4(struct __sk_buff *skb,
                                                                            __u16 inner_packet_len,
                                                                            __u8 inner_proto,
                                                                            const struct switchboard_overlay_machine_route *route)
{
  if (route == NULL || route->family != SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV4)
  {
    return false;
  }

  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = (struct ethhdr *)(long)skb->data;
  struct ipv6hdr inner6 = {};
  struct iphdr inner4 = {};

  if ((void *)(eth + 1) > data_end)
  {
    return false;
  }

  if (inner_proto == IPPROTO_IPV6)
  {
    struct ipv6hdr *originalInner6 = (struct ipv6hdr *)(eth + 1);
    if ((void *)(originalInner6 + 1) > data_end)
    {
      return false;
    }

    bpf_memcpy(&inner6, originalInner6, sizeof(inner6));
  }
  else if (inner_proto == IPPROTO_IPIP)
  {
    struct iphdr *originalInner4 = (struct iphdr *)(eth + 1);
    if ((void *)(originalInner4 + 1) > data_end)
    {
      return false;
    }

    bpf_memcpy(&inner4, originalInner4, sizeof(inner4));
  }
  else
  {
    return false;
  }

  if (bpf_skb_adjust_room(skb, (__s32)sizeof(struct iphdr), BPF_ADJ_ROOM_NET, switchboardOverlayEncapAdjustRoomFlagsIPv4()))
  {
    return false;
  }

  data_end = (void *)(long)skb->data_end;
  eth = (struct ethhdr *)(long)skb->data;
  struct iphdr *iph = (struct iphdr *)(eth + 1);

  if ((void *)(eth + 1) > data_end || (void *)(iph + 1) > data_end)
  {
    return false;
  }

  if (inner_proto == IPPROTO_IPV6)
  {
    struct ipv6hdr *restoredInner6 = (struct ipv6hdr *)(iph + 1);
    if ((void *)(restoredInner6 + 1) > data_end)
    {
      return false;
    }

    bpf_memcpy(restoredInner6, &inner6, sizeof(inner6));
  }
  else
  {
    struct iphdr *restoredInner4 = (struct iphdr *)(iph + 1);
    if ((void *)(restoredInner4 + 1) > data_end)
    {
      return false;
    }

    bpf_memcpy(restoredInner4, &inner4, sizeof(inner4));
  }

  eth->h_proto = BE_ETH_P_IP;
  iph->version = 4;
  iph->ihl = 5;
  iph->tos = 0;
  iph->tot_len = bpf_htons(inner_packet_len + sizeof(struct iphdr));
  iph->id = 0;
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = inner_proto;
  iph->check = 0;
  iph->saddr = route->source4;
  iph->daddr = route->next_hop4;

  __u64 csum = 0;
  ipv4_csum_inline(iph, &csum);
  iph->check = (__u16)csum;

  if (route->use_gateway_mac != 0)
  {
    return from_us_to_gateway(eth);
  }

  return from_us_to_overlay_next_hop(eth, route->next_hop_mac);
}

__attribute__((__always_inline__)) static inline bool switchboardMaybeRouteHostedIngressIPv4(struct __sk_buff *skb, struct ethhdr *eth, void *data_end, int *action)
{
  if (action == NULL)
  {
    return false;
  }

  struct iphdr *iph = (struct iphdr *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
  {
    *action = TC_ACT_SHOT;
    return true;
  }

  __u32 machine_fragment = 0;
  if (lookupHostedIngressMachineFragmentIPv4(iph->daddr, &machine_fragment) == false)
  {
    return false;
  }

  struct switchboard_overlay_machine_route *route = lookupOverlayMachineRouteByFragment(machine_fragment);
  if (route == NULL)
  {
    *action = TC_ACT_SHOT;
    return true;
  }

  __u16 inner_packet_len = (__u16)(skb->len - sizeof(struct ethhdr));
  if (switchboardEncapSKBV6(skb, inner_packet_len, IPPROTO_IPIP, route) || switchboardEncapSKBV4(skb, inner_packet_len, IPPROTO_IPIP, route))
  {
    *action = TC_ACT_OK;
    return true;
  }

  *action = TC_ACT_SHOT;
  return true;
}

__attribute__((__always_inline__)) static inline bool switchboardMaybeRouteHostedIngressIPv6(struct __sk_buff *skb, struct ethhdr *eth, void *data_end, int *action)
{
  if (action == NULL)
  {
    return false;
  }

  struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
  if ((void *)(ip6h + 1) > data_end)
  {
    *action = TC_ACT_SHOT;
    return true;
  }

  __u32 machine_fragment = 0;
  if (lookupHostedIngressMachineFragmentIPv6(ip6h->daddr.s6_addr32, &machine_fragment) == false)
  {
    return false;
  }

  struct switchboard_overlay_machine_route *route = lookupOverlayMachineRouteByFragment(machine_fragment);
  if (route == NULL)
  {
    *action = TC_ACT_SHOT;
    return true;
  }

  __u16 inner_packet_len = (__u16)(skb->len - sizeof(struct ethhdr));
  if (switchboardEncapSKBV6(skb, inner_packet_len, IPPROTO_IPV6, route) || switchboardEncapSKBV4(skb, inner_packet_len, IPPROTO_IPV6, route))
  {
    *action = TC_ACT_OK;
    return true;
  }

  *action = TC_ACT_SHOT;
  return true;
}
