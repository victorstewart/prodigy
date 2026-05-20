#include <ebpf/kernel/includes.h>
#include <ebpf/kernel/containersubnet.h>

#ifndef NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
#define NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE 0
#endif

#include <switchboard/common/checksum.h>
#include <switchboard/common/constants.h>
#include <switchboard/kernel/csum.h>
#include <switchboard/kernel/services.h>
#include <switchboard/kernel/structs.h>
#include <switchboard/kernel/layer4.h>
#include <switchboard/kernel/overlay.encap.h>
#include <switchboard/kernel/overlay.routing.h>
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
#include <switchboard/kernel/portal.routing.h>
#endif
#include <switchboard/kernel/whitehole.routing.h>

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
// Dev/test fake-boundary probes can inject IPv4 portal packets from inside the
// ecosystem. Production external traffic should have already been normalized by
// the boundary path, so host ingress must not pay these portal/CID lookups.
struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 16);
  __type(key, __u32);
  __type(value, __u64);
} dev_host_route_stats SEC(".maps");

__attribute__((__always_inline__))
static inline void bump_dev_host_route_stat(__u32 index)
{
  __u64 *slot = bpf_map_lookup_elem(&dev_host_route_stats, &index);
  if (slot)
  {
    __sync_fetch_and_add(slot, 1);
  }
}

#endif

// the neuron attaches this program to the NIC
// if packet is destined for a container, it gets redirected into the host-side
// primary netkit path for that container
// otherwise passed to the kernel

__attribute__((__always_inline__))
static inline bool lookup_whitehole_reply_binding_ipv4(struct ethhdr *eth, void *data_end, struct switchboard_whitehole_binding *binding)
{
   struct iphdr *iph = (struct iphdr *)(eth + 1);
   if ((void *)(iph + 1) > data_end)
   {
      return false;
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
         return false;
      }

      flow.port16[0] = tcph->source;
      flow.port16[1] = tcph->dest;
   }
   else if (iph->protocol == IPPROTO_UDP)
   {
      struct udphdr *udph = (struct udphdr *)(iph + 1);
      if ((void *)(udph + 1) > data_end)
      {
         return false;
      }

      flow.port16[0] = udph->source;
      flow.port16[1] = udph->dest;
   }
   else
   {
      return false;
   }

   struct switchboard_whitehole_binding *reply = bpf_map_lookup_elem(&whitehole_reply_flows, &flow);
   if (reply == NULL)
   {
      return false;
   }

   bpf_memcpy(binding, reply, sizeof(*binding));
   return true;
}

__attribute__((__always_inline__))
static inline bool lookup_whitehole_reply_binding_ipv6(struct ethhdr *eth, void *data_end, struct switchboard_whitehole_binding *binding)
{
   struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
   if ((void *)(ip6h + 1) > data_end)
   {
      return false;
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
         return false;
      }

      flow.port16[0] = tcph->source;
      flow.port16[1] = tcph->dest;
   }
   else if (ip6h->nexthdr == IPPROTO_UDP)
   {
      struct udphdr *udph = (struct udphdr *)(ip6h + 1);
      if ((void *)(udph + 1) > data_end)
      {
         return false;
      }

      flow.port16[0] = udph->source;
      flow.port16[1] = udph->dest;
   }
   else
   {
      return false;
   }

   struct switchboard_whitehole_binding *reply = bpf_map_lookup_elem(&whitehole_reply_flows, &flow);
   if (reply == NULL)
   {
      return false;
   }

   bpf_memcpy(binding, reply, sizeof(*binding));
   return true;
}

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
__attribute__((__always_inline__))
static inline bool overlay_inner_ipv4_matches_external_portal(struct iphdr *inner4, void *data_end)
{
   if ((void *)(inner4 + 1) > data_end || inner4->ihl != 5)
   {
      return false;
   }

   __u16 destPort = 0;
   if (inner4->protocol == IPPROTO_TCP)
   {
      struct tcphdr *tcp = (struct tcphdr *)(inner4 + 1);
      if ((void *)(tcp + 1) > data_end)
      {
         return false;
      }

      destPort = tcp->dest;
   }
   else if (inner4->protocol == IPPROTO_UDP)
   {
      struct udphdr *udp = (struct udphdr *)(inner4 + 1);
      if ((void *)(udp + 1) > data_end)
      {
         return false;
      }

      destPort = udp->dest;
   }
   else
   {
      return false;
   }

   struct portal_definition portal = {};
   portal.addr4 = inner4->daddr;
   portal.port = destPort;
   portal.proto = inner4->protocol;
   return bpf_map_lookup_elem(&external_portals, &portal) != NULL;
}

__attribute__((__always_inline__))
static inline bool overlay_inner_ipv6_matches_external_portal(struct ipv6hdr *inner6, void *data_end)
{
   if ((void *)(inner6 + 1) > data_end)
   {
      return false;
   }

   __u16 destPort = 0;
   if (inner6->nexthdr == IPPROTO_TCP)
   {
      struct tcphdr *tcp = (struct tcphdr *)(inner6 + 1);
      if ((void *)(tcp + 1) > data_end)
      {
         return false;
      }

      destPort = tcp->dest;
   }
   else if (inner6->nexthdr == IPPROTO_UDP)
   {
      struct udphdr *udp = (struct udphdr *)(inner6 + 1);
      if ((void *)(udp + 1) > data_end)
      {
         return false;
      }

      destPort = udp->dest;
   }
   else
   {
      return false;
   }

   struct portal_definition portal = {};
   bpf_memcpy(portal.addr6, inner6->daddr.s6_addr32, sizeof(portal.addr6));
   portal.port = destPort;
   portal.proto = inner6->nexthdr;
   return bpf_map_lookup_elem(&external_portals, &portal) != NULL;
}
#endif

__attribute__((__always_inline__))
static inline bool overlay_inner_targets_local(__u8 inner_proto, void *inner_l3, void *data_end)
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

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
      return overlay_inner_ipv4_matches_external_portal(inner4, data_end);
#else
      return false;
#endif
   }

   if (inner_proto == IPPROTO_IPV6)
   {
      struct ipv6hdr *inner6 = (struct ipv6hdr *)inner_l3;
      if ((void *)(inner6 + 1) > data_end)
      {
         return false;
      }

      if (localSubnetContainsDaddr(inner6->daddr.s6_addr)
         || overlayRoutablePrefixesContainIPv6(inner6->daddr.s6_addr32))
      {
         return true;
      }

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
      return overlay_inner_ipv6_matches_external_portal(inner6, data_end);
#else
      return false;
#endif
   }

  return false;
}

__attribute__((__always_inline__))
static inline int maybe_redirect_whitehole_reply(struct ethhdr *eth, void *data_end, bool *handled)
{
   if (handled == NULL)
   {
      return TC_ACT_OK;
   }

   *handled = false;

   if (eth->h_proto == BE_ETH_P_IPV6)
   {
      struct switchboard_whitehole_binding replyBinding = {};
      if (lookup_whitehole_reply_binding_ipv6(eth, data_end, &replyBinding))
      {
         *handled = true;
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
         bump_dev_host_route_stat(9);
#endif
         null_mac_addresses(eth);
         if (replyBinding.container.hasID && redirectContainerFragment(replyBinding.container.value[4], true))
         {
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
            bump_dev_host_route_stat(15);
#endif
            return setInstruction(TC_ACT_REDIRECT);
         }

         return TC_ACT_SHOT;
      }
   }
   else if (eth->h_proto == BE_ETH_P_IP)
   {
      struct switchboard_whitehole_binding replyBinding = {};
      if (lookup_whitehole_reply_binding_ipv4(eth, data_end, &replyBinding))
      {
         *handled = true;
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
         bump_dev_host_route_stat(2);
#endif
         null_mac_addresses(eth);
         if (replyBinding.container.hasID && redirectContainerFragment(replyBinding.container.value[4], true))
         {
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
            bump_dev_host_route_stat(3);
#endif
            return setInstruction(TC_ACT_REDIRECT);
         }

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
         bump_dev_host_route_stat(7);
#endif
         return TC_ACT_SHOT;
      }
   }

   return TC_ACT_OK;
}

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
__attribute__((__always_inline__))
static inline int maybe_redirect_ipv4_portal_packet(struct __sk_buff *skb, struct ethhdr *eth, void *data_end, bool *handled)
{
   if (handled == NULL)
   {
      return TC_ACT_OK;
   }

   *handled = false;

   if (eth == NULL || eth->h_proto != BE_ETH_P_IP)
   {
      return TC_ACT_OK;
   }

   struct iphdr *iph = (struct iphdr *)(eth + 1);
   if ((void *)(iph + 1) > data_end || iph->ihl != 5)
   {
      return TC_ACT_OK;
   }

   struct packet_description pckt = {};
   pckt.flow.proto = iph->protocol;
   pckt.flow.src = iph->saddr;
   pckt.flow.dst = iph->daddr;

   if (iph->protocol == IPPROTO_TCP)
   {
      if (parse_tcp((void *)(long)skb->data, data_end, false, &pckt) == false)
      {
         return TC_ACT_OK;
      }
   }
   else if (iph->protocol == IPPROTO_UDP)
   {
      if (parse_udp((void *)(long)skb->data, data_end, false, &pckt) == false)
      {
         return TC_ACT_OK;
      }
   }
   else
   {
      return TC_ACT_OK;
   }

   struct container_id containerID = {};
   struct portal_meta *portalMeta = NULL;
   int resolved = switchboardResolveExternalPortalTarget((void *)(long)skb->data,
      data_end,
      false,
      &pckt,
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
   struct local_container_subnet6 *localSubnet = bpf_map_lookup_elem(&local_container_subnet_map, &zeroidx);
   if (switchboardContainerIDTargetsLocalMachine(&containerID, localSubnet) == false)
   {
      int overlayAction = TC_ACT_OK;
      if (switchboardMaybeRouteHostedIngressIPv4(skb, eth, data_end, &overlayAction))
      {
         return overlayAction;
      }

      return TC_ACT_SHOT;
   }

   __u16 targetPort = 0;
   if (switchboardLookupWormholeTargetPort(portalMeta->slot, &containerID, &targetPort) == false
      || switchboardRewriteWormholeIPv4TargetSKB(skb, &pckt, targetPort) == false)
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
      return setInstruction(TC_ACT_REDIRECT);
   }

   return TC_ACT_SHOT;
}

__attribute__((__always_inline__))
static inline int maybe_redirect_ipv6_portal_packet(struct __sk_buff *skb, struct ethhdr *eth, void *data_end, bool *handled)
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

   struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
   if ((void *)(ip6h + 1) > data_end)
   {
      return TC_ACT_OK;
   }

   struct packet_description pckt = {};
   pckt.flow.proto = ip6h->nexthdr;
   bpf_memcpy(pckt.flow.srcv6, ip6h->saddr.s6_addr32, sizeof(pckt.flow.srcv6));
   bpf_memcpy(pckt.flow.dstv6, ip6h->daddr.s6_addr32, sizeof(pckt.flow.dstv6));

   if (ip6h->nexthdr == IPPROTO_TCP)
   {
      if (parse_tcp((void *)(long)skb->data, data_end, true, &pckt) == false)
      {
         return TC_ACT_OK;
      }
   }
   else if (ip6h->nexthdr == IPPROTO_UDP)
   {
      if (parse_udp((void *)(long)skb->data, data_end, true, &pckt) == false)
      {
         return TC_ACT_OK;
      }
   }
   else
   {
      return TC_ACT_OK;
   }

   struct container_id containerID = {};
   struct portal_meta *portalMeta = NULL;
   int resolved = switchboardResolveExternalPortalTarget((void *)(long)skb->data,
      data_end,
      true,
      &pckt,
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
   struct local_container_subnet6 *localSubnet = bpf_map_lookup_elem(&local_container_subnet_map, &zeroidx);
   if (switchboardContainerIDTargetsLocalMachine(&containerID, localSubnet) == false)
   {
      int overlayAction = TC_ACT_OK;
      if (switchboardMaybeRouteHostedIngressIPv6(skb, eth, data_end, &overlayAction))
      {
         return overlayAction;
      }

      return TC_ACT_SHOT;
   }

   __u16 targetPort = 0;
   if (switchboardLookupWormholeTargetPort(portalMeta->slot, &containerID, &targetPort) == false
      || switchboardRewriteWormholeIPv6TargetSKB(skb, &pckt, &containerID, targetPort) == false)
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
      return setInstruction(TC_ACT_REDIRECT);
   }

   return TC_ACT_SHOT;
}
#endif

__attribute__((__always_inline__))
static inline bool maybe_decap_overlay_packet(struct __sk_buff *skb)
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

      __u64 decap_flags = switchboardAdjustRoomPreserveOffloadFlags()
         | (ipv6h->nexthdr == IPPROTO_IPV6
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

      __u64 decap_flags = switchboardAdjustRoomPreserveOffloadFlags()
         | (iph->protocol == IPPROTO_IPV6
            ? BPF_F_ADJ_ROOM_DECAP_L3_IPV6
            : BPF_F_ADJ_ROOM_DECAP_L3_IPV4);
      return bpf_skb_adjust_room(skb,
         -(__s32)sizeof(struct iphdr),
         BPF_ADJ_ROOM_MAC,
         decap_flags) == 0;
   }

  return false;
}

__attribute__((__always_inline__))
static inline int maybe_route_hosted_ingress_packet(struct __sk_buff *skb, struct ethhdr *eth, void *data_end, bool *handled)
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

__attribute__((__always_inline__))
static inline int maybe_redirect_plain_local_ipv6_packet(struct ethhdr *eth, void *data_end, bool *handled)
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
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
   bump_dev_host_route_stat(4);
   bump_dev_host_route_stat(13);
#endif
   // netkit_xmit() classifies skb->pkt_type for the destination peer before
   // the primary-attached BPF program runs. Normalize the host NIC Ethernet
   // header here so the receiving peer is PACKET_HOST, not OTHERHOST.
   null_mac_addresses(eth);
   if (redirectToContainer(daddr6, true) == TC_ACT_REDIRECT)
   {
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
      bump_dev_host_route_stat(5);
#endif
      return setInstruction(TC_ACT_REDIRECT);
   }

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
   bump_dev_host_route_stat(6);
#endif
   // Container-subnet destinations must resolve to a host-side primary
   // netkit device for the destination container. If the boundary map is stale
   // or the container is gone, fail closed.
   return TC_ACT_SHOT;
}

// Native host traffic should bypass the heavier overlay/container parsing path.
// The maintained host-control failure is on plain machine-to-machine TCP/UDP,
// so only keep packets on the slow path when they can still target a container,
// a whitehole reply binding, or an overlay decap path.
__attribute__((__always_inline__))
static inline bool should_fast_pass_native_host_packet(struct ethhdr *eth, void *data_end)
{
   if (eth == NULL)
   {
      return false;
   }

   if (eth->h_proto == BE_ETH_P_IP)
   {
      struct iphdr *iph = (struct iphdr *)(eth + 1);
      struct switchboard_whitehole_binding replyBinding = {};
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

      if (lookup_whitehole_reply_binding_ipv4(eth, data_end, &replyBinding))
      {
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
         bump_dev_host_route_stat(1);
#endif
         return false;
      }

      return true;
   }

   if (eth->h_proto == BE_ETH_P_IPV6)
   {
      struct ipv6hdr *ipv6h = (struct ipv6hdr *)(eth + 1);
      struct switchboard_whitehole_binding replyBinding = {};
      if ((void *)(ipv6h + 1) > data_end)
      {
         return false;
      }

      if (ipv6h->nexthdr == IPPROTO_IPIP || ipv6h->nexthdr == IPPROTO_IPV6)
      {
         return false;
      }

      if (localSubnetContainsDaddr(ipv6h->daddr.s6_addr)
         || overlayRoutablePrefixesContainIPv6(ipv6h->daddr.s6_addr32))
      {
         return false;
      }

      if (lookup_whitehole_reply_binding_ipv6(eth, data_end, &replyBinding))
      {
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
         bump_dev_host_route_stat(8);
#endif
         return false;
      }

      return true;
   }

   return false;
}

SEC("tcx/ingress")
int host_ingress_router(struct __sk_buff *skb)
{
#if PRODIGY_DEBUG
  logSKB(skb);
#endif

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
  bump_dev_host_route_stat(0);
#endif

  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = (struct ethhdr *)(long)skb->data;

  if ((void *)(eth + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }

  bool handledWhiteholeReply = false;
  int whiteholeReplyAction = maybe_redirect_whitehole_reply(eth, data_end, &handledWhiteholeReply);
  if (handledWhiteholeReply)
  {
    return whiteholeReplyAction;
  }

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
  bool handledIPv4Portal = false;
  int ipv4PortalAction = maybe_redirect_ipv4_portal_packet(skb, eth, data_end, &handledIPv4Portal);
  if (handledIPv4Portal)
  {
    return ipv4PortalAction;
  }

  bool handledIPv6Portal = false;
  int ipv6PortalAction = maybe_redirect_ipv6_portal_packet(skb, eth, data_end, &handledIPv6Portal);
  if (handledIPv6Portal)
  {
    return ipv6PortalAction;
  }
#endif

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
    setCheckpoint("native-pass");
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
    bump_dev_host_route_stat(14);
#endif
    return setInstruction(TC_ACT_OK);
  }

  __u32 minimum_linear_bytes = switchboardHostIngressOverlayMinimumLinearBytes(eth->h_proto);
  if (minimum_linear_bytes != 0u && bpf_skb_pull_data(skb, minimum_linear_bytes) != 0)
  {
    return TC_ACT_SHOT;
  }

  data_end = (void *)(long)skb->data_end;
  eth = (struct ethhdr *)(long)skb->data;
  if ((void *)(eth + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }

  bool decapped = maybe_decap_overlay_packet(skb);

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

    if ((void *)(ipv6h + 1) > data_end)
    {
      return TC_ACT_SHOT;
    }

    __be8 *daddr6 = ipv6h->daddr.s6_addr;

    if (localSubnetContainsDaddr(daddr6))
    {
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
      bump_dev_host_route_stat(4);
      if (ipv6h->nexthdr == IPPROTO_IPIP)
      {
        bump_dev_host_route_stat(11);
      }
      else if (ipv6h->nexthdr == IPPROTO_IPV6)
      {
        bump_dev_host_route_stat(12);
      }
      else
      {
        bump_dev_host_route_stat(13);
      }
#endif
      // netkit_xmit() classifies skb->pkt_type for the destination peer before
      // the primary-attached BPF program runs. Normalize the host NIC Ethernet
      // header here so the receiving peer is PACKET_HOST, not OTHERHOST.
      null_mac_addresses(eth);
      if (redirectToContainer(daddr6, true) == TC_ACT_REDIRECT)
      {
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
        bump_dev_host_route_stat(5);
#endif
        return setInstruction(TC_ACT_REDIRECT);
      }
      else
      {
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
        bump_dev_host_route_stat(6);
#endif
        // Container-subnet destinations must resolve to a host-side primary
        // netkit device for the destination container.
        // If the boundary map is stale or the container is gone, fail closed.
        return TC_ACT_SHOT;
      }
    }

    if (lookup_whitehole_reply_binding_ipv6(eth, data_end, &replyBinding))
    {
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
      bump_dev_host_route_stat(9);
#endif
      null_mac_addresses(eth);
      if (replyBinding.container.hasID && redirectContainerFragment(replyBinding.container.value[4], true))
      {
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
        bump_dev_host_route_stat(15);
#endif
        return setInstruction(TC_ACT_REDIRECT);
      }

      return TC_ACT_SHOT;
    }

    setCheckpoint("redirectToContainer");

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
        return setInstruction(TC_ACT_REDIRECT);
      }

      return TC_ACT_SHOT;
    }
  }
  else if (protocol == BE_ETH_P_IP)
  {
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    struct switchboard_whitehole_binding replyBinding = {};
    if ((void *)(iph + 1) > data_end)
    {
      return TC_ACT_SHOT;
    }

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
    bool handledDecappedIPv4Portal = false;
    int decappedIPv4PortalAction = maybe_redirect_ipv4_portal_packet(skb, eth, data_end, &handledDecappedIPv4Portal);
    if (handledDecappedIPv4Portal)
    {
      return decappedIPv4PortalAction;
    }
#endif

    if (lookup_whitehole_reply_binding_ipv4(eth, data_end, &replyBinding))
    {
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
      bump_dev_host_route_stat(2);
#endif
      null_mac_addresses(eth);
      if (replyBinding.container.hasID && redirectContainerFragment(replyBinding.container.value[4], true))
      {
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
        bump_dev_host_route_stat(3);
#endif
        return setInstruction(TC_ACT_REDIRECT);
      }

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
      bump_dev_host_route_stat(7);
#endif
      return TC_ACT_SHOT;
    }

    if (overlayRoutablePrefixesContainIPv4(iph->daddr))
    {
      __u32 zeroidx = 0;
      struct local_container_subnet6 *localcontainersubnet6 = bpf_map_lookup_elem(&local_container_subnet_map, &zeroidx);
      struct container_id containerID = {.value = {0}, .hasID = false};
      if (setContainerIDFromDistributedIPv4(&containerID, iph->daddr, localcontainersubnet6) == false)
      {
        return TC_ACT_SHOT;
      }

      null_mac_addresses(eth);
      if (redirectContainerFragment(containerID.value[4], true))
      {
        return setInstruction(TC_ACT_REDIRECT);
      }

      return TC_ACT_SHOT;
    }
  }

  setCheckpoint("passing");
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
  bump_dev_host_route_stat(10);
#endif
  return setInstruction(TC_ACT_OK);
}
