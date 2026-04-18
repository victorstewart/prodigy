#pragma once

#include <ebpf/kernel/containersubnet.h>

#include <switchboard/kernel/csum.h>
#include <switchboard/kernel/maps.h>
#include <switchboard/kernel/overlay.routing.h>
#include <switchboard/kernel/whitehole.routing.h>

__attribute__((__always_inline__))
static inline bool switchboardRewriteWormholeSourceIPv6SKB(struct __sk_buff *skb)
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
      struct switchboard_wormhole_egress_binding *binding = bpf_map_lookup_elem(&wormhole_egress_bindings, &key);
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

      if (oldSourcePort != binding->port
         && bpf_skb_store_bytes(skb, layout.sourcePortOffset, &binding->port, sizeof(binding->port), rewriteFlags) != 0)
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
      struct switchboard_wormhole_egress_binding *binding = bpf_map_lookup_elem(&wormhole_egress_bindings, &key);
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

      if (oldSourcePort != binding->port
         && bpf_skb_store_bytes(skb, layout.sourcePortOffset, &binding->port, sizeof(binding->port), rewriteFlags) != 0)
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

__attribute__((__always_inline__))
static inline int switchboardMaybeLearnWhiteholeIPv4(struct ethhdr *eth, void *data_end)
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

   if (iph->protocol == IPPROTO_TCP)
   {
      struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
      if ((void *)(tcph + 1) > data_end)
      {
         return TC_ACT_SHOT;
      }

      flow.port16[0] = tcph->source;
      flow.port16[1] = tcph->dest;
   }
   else if (iph->protocol == IPPROTO_UDP)
   {
      struct udphdr *udph = (struct udphdr *)(iph + 1);
      if ((void *)(udph + 1) > data_end)
      {
         return TC_ACT_SHOT;
      }

      flow.port16[0] = udph->source;
      flow.port16[1] = udph->dest;
   }
   else
   {
      return TC_ACT_OK;
   }

   struct switchboard_whitehole_binding binding = {};
   if (whitehole_binding_lookup(flow.proto, false, &flow.src, flow.port16[0], &binding) == false)
   {
      return TC_ACT_OK;
   }

   struct flow_key reverse = {};
   reverse_flow_key(&flow, &reverse);
   bpf_map_update_elem(&whitehole_reply_flows, &reverse, &binding, BPF_ANY);
   return TC_ACT_OK;
}

__attribute__((__always_inline__))
static inline int switchboardMaybeLearnWhiteholeIPv6(struct ethhdr *eth, void *data_end)
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

   if (ip6h->nexthdr == IPPROTO_TCP)
   {
      struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1);
      if ((void *)(tcph + 1) > data_end)
      {
         return TC_ACT_SHOT;
      }

      flow.port16[0] = tcph->source;
      flow.port16[1] = tcph->dest;
   }
   else if (ip6h->nexthdr == IPPROTO_UDP)
   {
      struct udphdr *udph = (struct udphdr *)(ip6h + 1);
      if ((void *)(udph + 1) > data_end)
      {
         return TC_ACT_SHOT;
      }

      flow.port16[0] = udph->source;
      flow.port16[1] = udph->dest;
   }
   else
   {
      return TC_ACT_OK;
   }

   struct switchboard_whitehole_binding binding = {};
   if (whitehole_binding_lookup(flow.proto, true, flow.srcv6, flow.port16[0], &binding) == false)
   {
      return TC_ACT_OK;
   }

   struct flow_key reverse = {};
   reverse_flow_key(&flow, &reverse);
   bpf_map_update_elem(&whitehole_reply_flows, &reverse, &binding, BPF_ANY);
   return TC_ACT_OK;
}

__attribute__((__always_inline__))
static inline bool switchboardEncapSKBV6(struct __sk_buff *skb,
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

__attribute__((__always_inline__))
static inline bool switchboardEncapSKBV4(struct __sk_buff *skb,
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

__attribute__((__always_inline__))
static inline int switchboardMaybeEncapOverlayIPv4(struct __sk_buff *skb, struct ethhdr *eth, void *data_end)
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
   if (switchboardEncapSKBV6(skb, inner_packet_len, IPPROTO_IPIP, route)
      || switchboardEncapSKBV4(skb, inner_packet_len, IPPROTO_IPIP, route))
   {
      return setInstruction(TC_ACT_OK);
   }

   return TC_ACT_SHOT;
}

__attribute__((__always_inline__))
static inline bool switchboardMaybeRouteHostedIngressIPv4(struct ethhdr *eth, void *data_end, int *action)
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

   *action = route->use_gateway_mac ? (from_us_to_gateway(eth) ? TC_ACT_OK : TC_ACT_SHOT)
      : (from_us_to_overlay_next_hop(eth, route->next_hop_mac) ? TC_ACT_OK : TC_ACT_SHOT);
   return true;
}

__attribute__((__always_inline__))
static inline int switchboardMaybeEncapOverlayIPv6(struct __sk_buff *skb, struct ethhdr *eth, void *data_end)
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
   if (switchboardEncapSKBV6(skb, inner_packet_len, IPPROTO_IPV6, route)
      || switchboardEncapSKBV4(skb, inner_packet_len, IPPROTO_IPV6, route))
   {
      setCheckpoint("overlay6:encap_ok");
      setBufferOnPacket((__u8 *)"overlay6:encap_ok", sizeof("overlay6:encap_ok") - 1);
      return setInstruction(TC_ACT_OK);
   }

   setBufferOnPacket((__u8 *)"overlay6:encap_fail", sizeof("overlay6:encap_fail") - 1);
   return TC_ACT_SHOT;
}

__attribute__((__always_inline__))
static inline bool switchboardMaybeRouteHostedIngressIPv6(struct ethhdr *eth, void *data_end, int *action)
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

   *action = route->use_gateway_mac ? (from_us_to_gateway(eth) ? TC_ACT_OK : TC_ACT_SHOT)
      : (from_us_to_overlay_next_hop(eth, route->next_hop_mac) ? TC_ACT_OK : TC_ACT_SHOT);
   return true;
}

__attribute__((__always_inline__))
static inline int switchboardRouteOutboundEthFrame(struct __sk_buff *skb, struct ethhdr *eth, void *data_end)
{
   if ((void *)(eth + 1) > data_end)
   {
      return TC_ACT_SHOT;
   }

   if (eth->h_proto == BE_ETH_P_IP)
   {
      int whitehole_action = switchboardMaybeLearnWhiteholeIPv4(eth, data_end);
      if (whitehole_action != TC_ACT_OK)
      {
         return whitehole_action;
      }

      int hosted_ingress_action = TC_ACT_OK;
      if (switchboardMaybeRouteHostedIngressIPv4(eth, data_end, &hosted_ingress_action))
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
      if (switchboardMaybeRouteHostedIngressIPv6(eth, data_end, &hosted_ingress_action))
      {
         return hosted_ingress_action;
      }

      return switchboardMaybeEncapOverlayIPv6(skb, eth, data_end);
   }

   return setInstruction(TC_ACT_OK);
}
