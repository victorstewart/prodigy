#pragma once

#include <ebpf/kernel/containersubnet.h>

#include <switchboard/kernel/csum.h>
#include <switchboard/kernel/l4.ports.h>
#include <switchboard/kernel/maps.h>
#include <switchboard/kernel/overlay.encap.h>
#include <switchboard/kernel/overlay.routing.h>
#include <switchboard/kernel/whitehole.routing.h>
#include <switchboard/kernel/wormhole.flow.h>

__attribute__((__always_inline__)) static inline bool switchboardRewriteWormholeIPv6SourceTupleSKB(
    struct __sk_buff *skb,
    const struct switchboard_ipv6_skb_layout *layout,
    const struct ipv6hdr *ip6h,
    const struct switchboard_wormhole_egress_binding *binding,
    __u32 checksumOffset,
    __be16 oldSourcePort)
{
  __be32 oldAddress[4] = {};
  bpf_memcpy(oldAddress, ip6h->saddr.s6_addr32, sizeof(oldAddress));
  if (bpf_memcmp(oldAddress, binding->addr6, sizeof(oldAddress)) != 0 &&
      replace_l4_checksum_ipv6_address_skb(skb, checksumOffset, oldAddress, binding->addr6) == false)
  {
    return false;
  }
  if (oldSourcePort != binding->port &&
      replace_l4_checksum_word16_skb(skb, checksumOffset, oldSourcePort, binding->port, 0) != 0)
  {
    return false;
  }

  const __u64 rewriteFlags = switchboardPacketRewriteStoreFlags();
  if (oldSourcePort != binding->port &&
      bpf_skb_store_bytes(skb, layout->sourcePortOffset, &binding->port, sizeof(binding->port), rewriteFlags) != 0)
  {
    return false;
  }
  return bpf_memcmp(oldAddress, binding->addr6, sizeof(oldAddress)) == 0 ||
         bpf_skb_store_bytes(skb, layout->sourceAddressOffset, binding->addr6, sizeof(binding->addr6), rewriteFlags) == 0;
}

__attribute__((__always_inline__)) static inline int switchboardRewriteWormholeSourceIPv6SKB(struct __sk_buff *skb)
{
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct switchboard_ipv6_skb_layout layout = {};

  if (switchboardResolveIPv6SKBLayout(data, data_end, skb->protocol, &layout) == false)
  {
    return SWITCHBOARD_WORMHOLE_REPLY_NONE;
  }

  struct ipv6hdr *ip6h = (struct ipv6hdr *)((__u8 *)data + layout.l3Offset);
  if ((void *)(ip6h + 1) > data_end)
  {
    return SWITCHBOARD_WORMHOLE_REPLY_NONE;
  }

  struct switchboard_wormhole_egress_binding binding = {};
  int disposition = switchboardWormholeReplyDispositionIPv6(ip6h, data_end, &binding);
  if (disposition != SWITCHBOARD_WORMHOLE_REPLY_PUBLIC)
  {
    return disposition;
  }

  if (ip6h->nexthdr == IPPROTO_UDP)
  {
    struct udphdr *udph = (struct udphdr *)(ip6h + 1);
    if ((void *)(udph + 1) > data_end)
    {
      return SWITCHBOARD_WORMHOLE_REPLY_DROP;
    }

    __be16 oldSourcePort = udph->source;
    if (switchboardRewriteWormholeIPv6SourceTupleSKB(skb,
                                                     &layout,
                                                     ip6h,
                                                     &binding,
                                                     layout.transportOffset + __builtin_offsetof(struct udphdr, check),
                                                     oldSourcePort) == false)
    {
      return SWITCHBOARD_WORMHOLE_REPLY_DROP;
    }

    return SWITCHBOARD_WORMHOLE_REPLY_PUBLIC;
  }

  if (ip6h->nexthdr == IPPROTO_TCP)
  {
    struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1);
    if ((void *)(tcph + 1) > data_end)
    {
      return SWITCHBOARD_WORMHOLE_REPLY_DROP;
    }

    __be16 oldSourcePort = tcph->source;
    if (switchboardRewriteWormholeIPv6SourceTupleSKB(skb,
                                                     &layout,
                                                     ip6h,
                                                     &binding,
                                                     layout.transportOffset + __builtin_offsetof(struct tcphdr, check),
                                                     oldSourcePort) == false)
    {
      return SWITCHBOARD_WORMHOLE_REPLY_DROP;
    }

    return SWITCHBOARD_WORMHOLE_REPLY_PUBLIC;
  }

  return SWITCHBOARD_WORMHOLE_REPLY_DROP;
}

__attribute__((__always_inline__)) static inline int switchboardRewriteWormholeSourceIPv4SKB(struct __sk_buff *skb)
{
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  if (data == NULL || data_end == NULL || skb->protocol != bpf_htons(ETH_P_IP))
  {
    return SWITCHBOARD_WORMHOLE_REPLY_NONE;
  }

  struct ethhdr *eth = (struct ethhdr *)data;
  __u32 l3Offset = 0;
  if ((void *)(eth + 1) <= data_end && eth->h_proto == bpf_htons(ETH_P_IP))
  {
    l3Offset = sizeof(struct ethhdr);
  }

  struct iphdr *iph = (struct iphdr *)((__u8 *)data + l3Offset);
  if (switchboard_unfragmented_ipv4(iph, data_end) == false)
  {
    return SWITCHBOARD_WORMHOLE_REPLY_DROP;
  }

  __u8 proto = iph->protocol;
  if (proto != IPPROTO_UDP && proto != IPPROTO_TCP)
  {
    return SWITCHBOARD_WORMHOLE_REPLY_NONE;
  }

  struct switchboard_wormhole_egress_binding binding = {};
  int disposition = switchboardWormholeReplyDispositionIPv4(iph, data_end, &binding);
  if (disposition != SWITCHBOARD_WORMHOLE_REPLY_PUBLIC)
  {
    return disposition;
  }

  __u32 l4Offset = l3Offset + sizeof(struct iphdr);
  struct switchboard_l4_ports l4 = {};
  if (switchboard_parse_l4_ports((__u8 *)data + l4Offset, data_end, proto, l4Offset, &l4) == false)
  {
    return SWITCHBOARD_WORMHOLE_REPLY_DROP;
  }

  __be32 bindingAddress = binding.addr4;
  __be16 bindingPort = binding.port;

  const __u64 rewriteFlags = switchboardPacketRewriteStoreFlags();
  __be32 oldSourceAddress = iph->saddr;
  __be16 oldSourcePort = l4.source;

  if (oldSourceAddress != bindingAddress)
  {
    if (bpf_l3_csum_replace(skb,
                            l3Offset + __builtin_offsetof(struct iphdr, check),
                            oldSourceAddress,
                            bindingAddress,
                            sizeof(__be32)) != 0 ||
        bpf_skb_store_bytes(skb,
                            l3Offset + __builtin_offsetof(struct iphdr, saddr),
                            &bindingAddress,
                            sizeof(bindingAddress),
                            rewriteFlags) != 0)
    {
      return SWITCHBOARD_WORMHOLE_REPLY_DROP;
    }

    if (proto == IPPROTO_TCP || l4.udpChecksumPresent)
    {
      if (replace_l4_checksum_word32_skb(skb,
                                         l4.checksumOffset,
                                         oldSourceAddress,
                                         bindingAddress,
                                         BPF_F_PSEUDO_HDR) != 0)
      {
        return SWITCHBOARD_WORMHOLE_REPLY_DROP;
      }
    }
  }

  if (oldSourcePort != bindingPort)
  {
    if (bpf_skb_store_bytes(skb,
                            l4Offset,
                            &bindingPort,
                            sizeof(bindingPort),
                            rewriteFlags) != 0)
    {
      return SWITCHBOARD_WORMHOLE_REPLY_DROP;
    }

    if (proto == IPPROTO_TCP || l4.udpChecksumPresent)
    {
      if (replace_l4_checksum_word16_skb(skb,
                                         l4.checksumOffset,
                                         oldSourcePort,
                                         bindingPort,
                                         0) != 0)
      {
        return SWITCHBOARD_WORMHOLE_REPLY_DROP;
      }
    }
  }

  return SWITCHBOARD_WORMHOLE_REPLY_PUBLIC;
}

__attribute__((__always_inline__)) static inline int switchboardMaybeLearnWhiteholeIPv4(struct ethhdr *eth, void *data_end)
{
  struct iphdr *iph = (struct iphdr *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }

  struct flow_key flow = {};
  flow.src = iph->saddr;
  flow.dst = iph->daddr;
  flow.proto = iph->protocol;

  struct switchboard_l4_ports l4 = {};
  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
  {
    return TC_ACT_OK;
  }
  if (switchboard_parse_l4_ports((void *)(iph + 1), data_end, iph->protocol, sizeof(struct ethhdr) + sizeof(struct iphdr), &l4) == false)
  {
    return TC_ACT_SHOT;
  }
  flow.port16[0] = l4.source;
  flow.port16[1] = l4.dest;

  struct switchboard_whitehole_binding binding = {};
  if (whitehole_binding_lookup(flow.proto, false, &flow.src, flow.port16[0], &binding) == false)
  {
    return TC_ACT_OK;
  }

  struct flow_key reverse = {};
  reverse_flow_key(&flow, &reverse);
  struct switchboard_whitehole_reply reply = {
      .binding = binding,
      .expiresAtNs = bpf_ktime_get_ns() + WHITEHOLE_REPLY_IDLE_NS,
  };
  bpf_map_update_elem(&white_replies, &reverse, &reply, BPF_ANY);
  return TC_ACT_OK;
}

__attribute__((__always_inline__)) static inline int switchboardMaybeLearnWhiteholeIPv6(struct ethhdr *eth, void *data_end)
{
  struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
  if ((void *)(ip6h + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }

  struct flow_key flow = {};
  bpf_memcpy(flow.srcv6, ip6h->saddr.s6_addr32, sizeof(flow.srcv6));
  bpf_memcpy(flow.dstv6, ip6h->daddr.s6_addr32, sizeof(flow.dstv6));
  flow.proto = ip6h->nexthdr;

  struct switchboard_l4_ports l4 = {};
  if (ip6h->nexthdr != IPPROTO_TCP && ip6h->nexthdr != IPPROTO_UDP)
  {
    return TC_ACT_OK;
  }
  if (switchboard_parse_l4_ports((void *)(ip6h + 1), data_end, ip6h->nexthdr, sizeof(struct ethhdr) + sizeof(struct ipv6hdr), &l4) == false)
  {
    return TC_ACT_SHOT;
  }
  flow.port16[0] = l4.source;
  flow.port16[1] = l4.dest;

  struct switchboard_whitehole_binding binding = {};
  if (whitehole_binding_lookup(flow.proto, true, flow.srcv6, flow.port16[0], &binding) == false)
  {
    return TC_ACT_OK;
  }

  struct flow_key reverse = {};
  reverse_flow_key(&flow, &reverse);
  struct switchboard_whitehole_reply reply = {
      .binding = binding,
      .expiresAtNs = bpf_ktime_get_ns() + WHITEHOLE_REPLY_IDLE_NS,
  };
  bpf_map_update_elem(&white_replies, &reverse, &reply, BPF_ANY);
  return TC_ACT_OK;
}

__attribute__((__always_inline__)) static inline int switchboardMaybeEncapOverlayIPv4(struct __sk_buff *skb, struct ethhdr *eth, void *data_end)
{
  struct iphdr *iph = (struct iphdr *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }

  if (iph->protocol == IPPROTO_IPIP || iph->protocol == IPPROTO_IPV6)
  {
    return TC_ACT_OK;
  }

  if (overlayRoutablePrefixesContainIPv4(iph->daddr) == false)
  {
    return TC_ACT_OK;
  }

  struct switchboard_overlay_machine_route_key key = {};
  if (overlayRouteKeyFromIPv4(iph->daddr, &key) == false)
  {
    return TC_ACT_SHOT;
  }

  struct switchboard_overlay_machine_route *route = lookupOverlayMachineRouteLow8(&key);
  if (route == NULL)
  {
    return TC_ACT_SHOT;
  }

  __u16 inner_packet_len = (__u16)(skb->len - sizeof(struct ethhdr));
  if (switchboardEncapSKBV6(skb, inner_packet_len, IPPROTO_IPIP, route) || switchboardEncapSKBV4(skb, inner_packet_len, IPPROTO_IPIP, route))
  {
    return TC_ACT_OK;
  }

  return TC_ACT_SHOT;
}

__attribute__((__always_inline__)) static inline int switchboardMaybeEncapOverlayIPv6(struct __sk_buff *skb, struct ethhdr *eth, void *data_end)
{
  struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
  if ((void *)(ip6h + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }

  if (ip6h->nexthdr == IPPROTO_IPIP || ip6h->nexthdr == IPPROTO_IPV6)
  {
    return TC_ACT_OK;
  }

  bool container_overlay = containsContainerNetworkIPv6(ip6h->daddr.s6_addr32) && overlayContainerNetworkEnabled();
  bool routable_overlay = overlayRoutablePrefixesContainIPv6(ip6h->daddr.s6_addr32);
  if (container_overlay == false && routable_overlay == false)
  {
    return TC_ACT_OK;
  }

  struct switchboard_overlay_machine_route_key key = {};
  if (overlayRouteKeyFromIPv6(ip6h->daddr.s6_addr32, &key) == false)
  {
    return TC_ACT_SHOT;
  }

  struct switchboard_overlay_machine_route *route = lookupOverlayMachineRouteFull(&key);
  if (route == NULL)
  {
    return TC_ACT_SHOT;
  }

  __u16 inner_packet_len = (__u16)(skb->len - sizeof(struct ethhdr));
  if (switchboardEncapSKBV6(skb, inner_packet_len, IPPROTO_IPV6, route) || switchboardEncapSKBV4(skb, inner_packet_len, IPPROTO_IPV6, route))
  {
    return TC_ACT_OK;
  }

  return TC_ACT_SHOT;
}

__attribute__((__always_inline__)) static inline int switchboardRouteOutboundEthFrame(struct __sk_buff *skb, struct ethhdr *eth, void *data_end)
{
  if ((void *)(eth + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }

  if (eth->h_proto == BE_ETH_P_IP)
  {
    if (skb->mark != SWITCHBOARD_WORMHOLE_REPLY_VALIDATED_SKB_MARK &&
        switchboardRewriteWormholeSourceIPv4SKB(skb) == SWITCHBOARD_WORMHOLE_REPLY_DROP)
    {
      return TC_ACT_SHOT;
    }

    data_end = (void *)(long)skb->data_end;
    eth = (struct ethhdr *)(long)skb->data;
    if ((void *)(eth + 1) > data_end)
    {
      return TC_ACT_SHOT;
    }

    int whitehole_action = switchboardMaybeLearnWhiteholeIPv4(eth, data_end);
    if (whitehole_action != TC_ACT_OK)
    {
      return whitehole_action;
    }

    int hosted_ingress_action = TC_ACT_OK;
    if (switchboardMaybeRouteHostedIngressIPv4(skb, eth, data_end, &hosted_ingress_action))
    {
      return hosted_ingress_action;
    }

    return switchboardMaybeEncapOverlayIPv4(skb, eth, data_end);
  }

  if (eth->h_proto == BE_ETH_P_IPV6)
  {
    if (skb->mark != SWITCHBOARD_WORMHOLE_REPLY_VALIDATED_SKB_MARK &&
        switchboardRewriteWormholeSourceIPv6SKB(skb) == SWITCHBOARD_WORMHOLE_REPLY_DROP)
    {
      return TC_ACT_SHOT;
    }

    data_end = (void *)(long)skb->data_end;
    eth = (struct ethhdr *)(long)skb->data;
    if ((void *)(eth + 1) > data_end)
    {
      return TC_ACT_SHOT;
    }

    int whitehole_action = switchboardMaybeLearnWhiteholeIPv6(eth, data_end);
    if (whitehole_action != TC_ACT_OK)
    {
      return whitehole_action;
    }

    int hosted_ingress_action = TC_ACT_OK;
    if (switchboardMaybeRouteHostedIngressIPv6(skb, eth, data_end, &hosted_ingress_action))
    {
      return hosted_ingress_action;
    }

    return switchboardMaybeEncapOverlayIPv6(skb, eth, data_end);
  }

  return TC_ACT_OK;
}
