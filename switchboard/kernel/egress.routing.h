#pragma once

#include <ebpf/kernel/containersubnet.h>

#include <switchboard/kernel/csum.h>
#include <switchboard/kernel/l4.ports.h>
#include <switchboard/kernel/maps.h>
#include <switchboard/kernel/overlay.encap.h>
#include <switchboard/kernel/overlay.routing.h>
#include <switchboard/kernel/whitehole.routing.h>

__attribute__((__always_inline__)) static inline bool switchboardRewriteWormholeSourceIPv6SKB(struct __sk_buff *skb)
{
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct switchboard_ipv6_skb_layout layout = {};

  if (switchboardResolveIPv6SKBLayout(data, data_end, skb->protocol, &layout) == false)
  {
    setBufferOnPacket((__u8 *)"wormhole:no_ip6", sizeof("wormhole:no_ip6") - 1);
    return false;
  }

  struct ipv6hdr *ip6h = (struct ipv6hdr *)((__u8 *)data + layout.l3Offset);
  if ((void *)(ip6h + 1) > data_end)
  {
    setBufferOnPacket((__u8 *)"wormhole:no_ip6", sizeof("wormhole:no_ip6") - 1);
    return false;
  }

  if (switchboardWormholeSourceRewriteEligibleIPv6(ip6h->saddr.s6_addr, ip6h->daddr.s6_addr) == false)
  {
    setBufferOnPacket((__u8 *)"wormhole:not_local", sizeof("wormhole:not_local") - 1);
    return false;
  }

  struct switchboard_wormhole_egress_key key;
  // This hash key is 10 bytes with padding. The peer-program lookup must zero
  // the full object before populating fields or the map lookup can miss even
  // when the visible container/port/proto fields match the installed entry.
  bpf_memset(&key, 0, sizeof(key));
  key.proto = ip6h->nexthdr;
  bpf_memcpy(key.container, ip6h->saddr.s6_addr + 11, sizeof(key.container));

  if (ip6h->nexthdr == IPPROTO_UDP)
  {
    struct udphdr *udph = (struct udphdr *)(ip6h + 1);
    if ((void *)(udph + 1) > data_end)
    {
      setBufferOnPacket((__u8 *)"wormhole:no_udp", sizeof("wormhole:no_udp") - 1);
      return false;
    }

    key.port = udph->source;
    struct switchboard_wormhole_egress_binding *binding = bpf_map_lookup_elem(&wh_egress, &key);
    if (binding == NULL)
    {
      setBufferOnPacket((__u8 *)"wormhole:udp_nomap", sizeof("wormhole:udp_nomap") - 1);
      return false;
    }

    if (binding->is_ipv6 == 0 || binding->proto != IPPROTO_UDP)
    {
      setBufferOnPacket((__u8 *)"wormhole:udp_badbind", sizeof("wormhole:udp_badbind") - 1);
      return false;
    }

    const __u64 rewriteFlags = switchboardPacketRewriteManualChecksumDataStoreFlags();
    __be16 oldSourcePort = udph->source;

    if (oldSourcePort != binding->port && bpf_skb_store_bytes(skb, layout.sourcePortOffset, &binding->port, sizeof(binding->port), rewriteFlags) != 0)
    {
      setBufferOnPacket((__u8 *)"wormhole:udp_port_store", sizeof("wormhole:udp_port_store") - 1);
      return false;
    }

    if (bpf_skb_store_bytes(skb, layout.sourceAddressOffset, binding->addr6, sizeof(binding->addr6), rewriteFlags) != 0)
    {
      setBufferOnPacket((__u8 *)"wormhole:udp_addr", sizeof("wormhole:udp_addr") - 1);
      return false;
    }

    if (store_recomputed_ipv6_transport_checksum_skb(skb, IPPROTO_UDP) == false)
    {
      setBufferOnPacket((__u8 *)"wormhole:udp_recompute", sizeof("wormhole:udp_recompute") - 1);
      return false;
    }

    setBufferOnPacket((__u8 *)"wormhole:udp_ok", sizeof("wormhole:udp_ok") - 1);
    return true;
  }

  if (ip6h->nexthdr == IPPROTO_TCP)
  {
    struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1);
    if ((void *)(tcph + 1) > data_end)
    {
      setBufferOnPacket((__u8 *)"wormhole:no_tcp", sizeof("wormhole:no_tcp") - 1);
      return false;
    }

    key.port = tcph->source;
    struct switchboard_wormhole_egress_binding *binding = bpf_map_lookup_elem(&wh_egress, &key);
    if (binding == NULL)
    {
      setBufferOnPacket((__u8 *)"wormhole:tcp_nomap", sizeof("wormhole:tcp_nomap") - 1);
      return false;
    }

    if (binding->is_ipv6 == 0 || binding->proto != IPPROTO_TCP)
    {
      setBufferOnPacket((__u8 *)"wormhole:tcp_badbind", sizeof("wormhole:tcp_badbind") - 1);
      return false;
    }

    const __u64 rewriteFlags = switchboardPacketRewriteManualChecksumDataStoreFlags();
    __be16 oldSourcePort = tcph->source;

    if (oldSourcePort != binding->port && bpf_skb_store_bytes(skb, layout.sourcePortOffset, &binding->port, sizeof(binding->port), rewriteFlags) != 0)
    {
      setBufferOnPacket((__u8 *)"wormhole:tcp_port_store", sizeof("wormhole:tcp_port_store") - 1);
      return false;
    }

    if (bpf_skb_store_bytes(skb, layout.sourceAddressOffset, binding->addr6, sizeof(binding->addr6), rewriteFlags) != 0)
    {
      setBufferOnPacket((__u8 *)"wormhole:tcp_addr", sizeof("wormhole:tcp_addr") - 1);
      return false;
    }

    if (store_recomputed_ipv6_transport_checksum_skb(skb, IPPROTO_TCP) == false)
    {
      setBufferOnPacket((__u8 *)"wormhole:tcp_recompute", sizeof("wormhole:tcp_recompute") - 1);
      return false;
    }

    setBufferOnPacket((__u8 *)"wormhole:tcp_ok", sizeof("wormhole:tcp_ok") - 1);
    return true;
  }

  setBufferOnPacket((__u8 *)"wormhole:proto_skip", sizeof("wormhole:proto_skip") - 1);
  return false;
}

__attribute__((__always_inline__)) static inline bool switchboardRewriteWormholeSourceIPv4SKB(struct __sk_buff *skb)
{
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  if (data == NULL || data_end == NULL || skb->protocol != bpf_htons(ETH_P_IP))
  {
    return false;
  }

  struct ethhdr *eth = (struct ethhdr *)data;
  __u32 l3Offset = 0;
  if ((void *)(eth + 1) <= data_end && eth->h_proto == bpf_htons(ETH_P_IP))
  {
    l3Offset = sizeof(struct ethhdr);
  }

  struct iphdr *iph = (struct iphdr *)((__u8 *)data + l3Offset);
  if ((void *)(iph + 1) > data_end || iph->ihl != 5)
  {
    return false;
  }

  __u8 proto = iph->protocol;
  if (proto != IPPROTO_UDP && proto != IPPROTO_TCP)
  {
    return false;
  }

  __u32 l4Offset = l3Offset + sizeof(struct iphdr);
  struct switchboard_l4_ports l4 = {};
  if (switchboard_parse_l4_ports((__u8 *)data + l4Offset, data_end, proto, l4Offset, &l4) == false)
  {
    return false;
  }

  struct switchboard_wormhole_egress4_key key;
  bpf_memset(&key, 0, sizeof(key));
  key.addr = iph->saddr;
  key.port = l4.source;
  key.proto = proto;

  struct switchboard_wormhole_egress_binding *binding = bpf_map_lookup_elem(&wh_egress4, &key);
  if (binding == NULL)
  {
    return false;
  }

  __u8 bindingIsIPv6 = binding->is_ipv6;
  __u8 bindingProto = binding->proto;
  __be32 bindingAddress = binding->addr4;
  __be16 bindingPort = binding->port;

  if (bindingIsIPv6 != 0 || bindingProto != proto)
  {
    return false;
  }

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
      return false;
    }

    if (proto == IPPROTO_TCP || l4.udpChecksumPresent)
    {
      if (replace_l4_checksum_word32_skb(skb,
                                         l4.checksumOffset,
                                         oldSourceAddress,
                                         bindingAddress,
                                         BPF_F_PSEUDO_HDR) != 0)
      {
        return false;
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
      return false;
    }

    if (proto == IPPROTO_TCP || l4.udpChecksumPresent)
    {
      if (replace_l4_checksum_word16_skb(skb,
                                         l4.checksumOffset,
                                         oldSourcePort,
                                         bindingPort,
                                         0) != 0)
      {
        return false;
      }
    }
  }

  return true;
}

__attribute__((__always_inline__)) static inline bool switchboardRewriteSystemEgressIPv4SKB(struct __sk_buff *skb)
{
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  if (data == NULL || data_end == NULL || skb->protocol != bpf_htons(ETH_P_IP))
  {
    return false;
  }

  struct ethhdr *eth = (struct ethhdr *)data;
  __u32 l3Offset = 0;
  if ((void *)(eth + 1) <= data_end && eth->h_proto == bpf_htons(ETH_P_IP))
  {
    l3Offset = sizeof(struct ethhdr);
  }

  struct iphdr *iph = (struct iphdr *)((__u8 *)data + l3Offset);
  if ((void *)(iph + 1) > data_end || iph->ihl != 5)
  {
    return false;
  }

  __be32 outsideSource4 = 0;
  __u8 containerFragment = 0;
  if (containerSystemEgressIPv4Config(&outsideSource4, &containerFragment) == false || iph->saddr == 0 || iph->saddr == outsideSource4)
  {
    return false;
  }

  __u8 proto = iph->protocol;
  __u32 l4Offset = l3Offset + sizeof(struct iphdr);
  struct switchboard_l4_ports l4 = {};
  if (switchboard_parse_l4_ports((__u8 *)data + l4Offset, data_end, proto, l4Offset, &l4) == false)
  {
    return false;
  }

  __u32 zeroidx = 0;
  struct local_container_subnet6 *subnet = bpf_map_lookup_elem(&lc_subnet, &zeroidx);
  if (subnet == NULL || subnet->dpfx == 0)
  {
    return false;
  }

  struct flow_key reply = {};
  reply.src = iph->daddr;
  reply.dst = outsideSource4;
  reply.proto = proto;
  reply.port16[0] = l4.dest;
  reply.port16[1] = l4.source;

  struct switchboard_system_egress_nat_binding binding = {};
  binding.container.hasID = true;
  binding.container.value[0] = subnet->dpfx;
  binding.container.value[1] = subnet->mpfx[0];
  binding.container.value[2] = subnet->mpfx[1];
  binding.container.value[3] = subnet->mpfx[2];
  binding.container.value[4] = containerFragment;
  binding.inside_addr4 = iph->saddr;
  if (bpf_map_update_elem(&system_egress_nat, &reply, &binding, BPF_ANY) != 0)
  {
    return false;
  }

  __be32 insideSource4 = iph->saddr;
  if (bpf_l3_csum_replace(skb,
                          l3Offset + __builtin_offsetof(struct iphdr, check),
                          insideSource4,
                          outsideSource4,
                          sizeof(__be32)) != 0 ||
      bpf_skb_store_bytes(skb,
                          l3Offset + __builtin_offsetof(struct iphdr, saddr),
                          &outsideSource4,
                          sizeof(outsideSource4),
                          switchboardPacketRewriteStoreFlags()) != 0)
  {
    return false;
  }

  if (proto == IPPROTO_TCP || l4.udpChecksumPresent)
  {
    return replace_l4_checksum_word32_skb(skb,
                                          l4.checksumOffset,
                                          insideSource4,
                                          outsideSource4,
                                          BPF_F_PSEUDO_HDR) == 0;
  }

  return true;
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
  bpf_map_update_elem(&white_replies, &reverse, &binding, BPF_ANY);
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
  bpf_map_update_elem(&white_replies, &reverse, &binding, BPF_ANY);
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
    return setInstruction(TC_ACT_OK);
  }

  return TC_ACT_SHOT;
}

__attribute__((__always_inline__)) static inline int switchboardMaybeEncapOverlayIPv6(struct __sk_buff *skb, struct ethhdr *eth, void *data_end)
{
  struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
  if ((void *)(ip6h + 1) > data_end)
  {
    setBufferOnPacket((__u8 *)"overlay6:no_ip6", sizeof("overlay6:no_ip6") - 1);
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
    setBufferOnPacket((__u8 *)"overlay6:skip", sizeof("overlay6:skip") - 1);
    return TC_ACT_OK;
  }

  struct switchboard_overlay_machine_route_key key = {};
  if (overlayRouteKeyFromIPv6(ip6h->daddr.s6_addr32, &key) == false)
  {
    setBufferOnPacket((__u8 *)"overlay6:key_fail", sizeof("overlay6:key_fail") - 1);
    return TC_ACT_SHOT;
  }

  struct switchboard_overlay_machine_route *route = lookupOverlayMachineRouteFull(&key);
  if (route == NULL)
  {
    setBufferOnPacket((__u8 *)"overlay6:no_route", sizeof("overlay6:no_route") - 1);
    return TC_ACT_SHOT;
  }

  __u16 inner_packet_len = (__u16)(skb->len - sizeof(struct ethhdr));
  if (switchboardEncapSKBV6(skb, inner_packet_len, IPPROTO_IPV6, route) || switchboardEncapSKBV4(skb, inner_packet_len, IPPROTO_IPV6, route))
  {
    setCheckpoint("overlay6:encap_ok");
    setBufferOnPacket((__u8 *)"overlay6:encap_ok", sizeof("overlay6:encap_ok") - 1);
    return setInstruction(TC_ACT_OK);
  }

  setBufferOnPacket((__u8 *)"overlay6:encap_fail", sizeof("overlay6:encap_fail") - 1);
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
    (void)switchboardRewriteWormholeSourceIPv4SKB(skb);

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
    (void)switchboardRewriteWormholeSourceIPv6SKB(skb);

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

  return setInstruction(TC_ACT_OK);
}
