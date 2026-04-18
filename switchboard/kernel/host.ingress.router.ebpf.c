#include <ebpf/kernel/includes.h>
#include <ebpf/kernel/containersubnet.h>
#include <switchboard/common/checksum.h>
#include <switchboard/kernel/overlay.routing.h>
#include <switchboard/kernel/whitehole.routing.h>

#ifndef NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
#define NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE 0
#endif

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
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
      null_mac_addresses(eth);
      if (replyBinding.container.hasID && redirectContainerFragment(replyBinding.container.value[4], true))
      {
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
      null_mac_addresses(eth);
      if (replyBinding.container.hasID && redirectContainerFragment(replyBinding.container.value[4], true))
      {
        return setInstruction(TC_ACT_REDIRECT);
      }

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
