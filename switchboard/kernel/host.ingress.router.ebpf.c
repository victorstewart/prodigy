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
#include <switchboard/kernel/overlay.routing.h>
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
#include <switchboard/kernel/quic.h>
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

struct
{
   __uint(type, BPF_MAP_TYPE_HASH);
   __type(key, struct portal_definition);
   __type(value, struct portal_meta);
   __uint(max_entries, MAX_PORTALS);
} external_portals SEC(".maps");

struct
{
   __uint(type, BPF_MAP_TYPE_HASH);
   __type(key, struct switchboard_wormhole_target_key);
   __type(value, __u16);
   __uint(max_entries, MAX_PORTALS * 256);
} wormhole_target_ports SEC(".maps");
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

      return overlayRoutablePrefixesContainIPv4(inner4->daddr);
   }

   if (inner_proto == IPPROTO_IPV6)
   {
      struct ipv6hdr *inner6 = (struct ipv6hdr *)inner_l3;
      if ((void *)(inner6 + 1) > data_end)
      {
         return false;
      }

      return localSubnetContainsDaddr(inner6->daddr.s6_addr)
         || overlayRoutablePrefixesContainIPv6(inner6->daddr.s6_addr32);
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
static inline bool host_ingress_lookup_wormhole_target_port(__u32 slot, const struct container_id *containerID, __u16 *targetPort)
{
   if (containerID == NULL || targetPort == NULL || containerID->hasID == false)
   {
      return false;
   }

   struct switchboard_wormhole_target_key key = {
      .slot = slot,
   };
   bpf_memcpy(key.container, containerID->value, sizeof(key.container));

   __u16 *value = bpf_map_lookup_elem(&wormhole_target_ports, &key);
   if (value == NULL || *value == 0)
   {
      return false;
   }

   *targetPort = *value;
   return true;
}

__attribute__((__always_inline__))
static inline bool host_ingress_rewrite_wormhole_ipv4_target_skb(struct __sk_buff *skb,
   struct packet_description *pckt,
   __u16 targetPort)
{
   void *data = (void *)(long)skb->data;
   void *data_end = (void *)(long)skb->data_end;

   if (pckt == NULL || (pckt->flow.proto != IPPROTO_UDP && pckt->flow.proto != IPPROTO_TCP))
   {
      return false;
   }

   struct ethhdr *eth = (struct ethhdr *)data;
   if ((void *)(eth + 1) > data_end || eth->h_proto != BE_ETH_P_IP)
   {
      return false;
   }

   struct iphdr *iph = (struct iphdr *)(eth + 1);
   if ((void *)(iph + 1) > data_end || iph->ihl != 5)
   {
      return false;
   }

   __be16 oldTargetPort = pckt->flow.port16[1];
   if (oldTargetPort == targetPort)
   {
      return true;
   }

   const __u32 l4Offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
   const __u64 rewriteFlags = switchboardPacketRewriteStoreFlags();

   if (pckt->flow.proto == IPPROTO_UDP)
   {
      struct udphdr *udph = (struct udphdr *)((__u8 *)data + l4Offset);
      if ((void *)(udph + 1) > data_end)
      {
         return false;
      }

      bool udpChecksumPresent = (udph->check != 0);
      if (bpf_skb_store_bytes(skb, l4Offset + __builtin_offsetof(struct udphdr, dest), &targetPort, sizeof(targetPort), rewriteFlags) != 0)
      {
         return false;
      }

      if (udpChecksumPresent
         && replace_l4_checksum_word16_skb(skb,
            l4Offset + __builtin_offsetof(struct udphdr, check),
            oldTargetPort,
            targetPort,
            0) != 0)
      {
         return false;
      }
   }
   else
   {
      struct tcphdr *tcph = (struct tcphdr *)((__u8 *)data + l4Offset);
      if ((void *)(tcph + 1) > data_end)
      {
         return false;
      }

      if (bpf_skb_store_bytes(skb, l4Offset + __builtin_offsetof(struct tcphdr, dest), &targetPort, sizeof(targetPort), rewriteFlags) != 0
         || replace_l4_checksum_word16_skb(skb,
            l4Offset + __builtin_offsetof(struct tcphdr, check),
            oldTargetPort,
            targetPort,
            0) != 0)
      {
         return false;
      }
   }

   pckt->flow.port16[1] = targetPort;
   return true;
}

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

   struct portal_definition portal = {};
   portal.addr4 = pckt.flow.dst;
   portal.port = pckt.flow.port16[1];
   portal.proto = pckt.flow.proto;

   struct portal_meta *portalMeta = bpf_map_lookup_elem(&external_portals, &portal);
   if (portalMeta == NULL)
   {
      return TC_ACT_OK;
   }

   *handled = true;
   if ((portalMeta->flags & F_QUIC_PORTAL) == 0)
   {
      return TC_ACT_SHOT;
   }

   struct container_id containerID = {};
   (void)parse_quic(&containerID, portalMeta, (void *)(long)skb->data, data_end, false, &pckt.flow);
   if (containerID.hasID == false)
   {
      return TC_ACT_SHOT;
   }

   __u32 zeroidx = 0;
   struct local_container_subnet6 *localSubnet = bpf_map_lookup_elem(&local_container_subnet_map, &zeroidx);
   if (switchboardContainerIDTargetsLocalMachine(&containerID, localSubnet) == false)
   {
      return TC_ACT_OK;
   }

   __u16 targetPort = 0;
   if (host_ingress_lookup_wormhole_target_port(portalMeta->slot, &containerID, &targetPort) == false
      || host_ingress_rewrite_wormhole_ipv4_target_skb(skb, &pckt, targetPort) == false)
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
#endif

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
