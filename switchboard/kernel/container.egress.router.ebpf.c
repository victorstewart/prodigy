#include <ebpf/kernel/includes.h>
#include <ebpf/kernel/containersubnet.h>

#include <switchboard/kernel/egress.routing.h>
#include <switchboard/kernel/portal.routing.h>

// This program is attached as BPF_NETKIT_PEER using the host-side primary
// ifindex. Upstream netkit resolves that attach type to the peer endpoint, and
// netkit_xmit() runs the program attached to the transmitting endpoint. That
// makes this the container -> host egress hook after packets leave the
// container network stack. If the destination is another local container,
// preserve any wormhole source tuple first and then forward there; otherwise
// forward toward the NIC.

struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 16);
  __type(key, __u32);
  __type(value, __u64);
} container_router_stats_map SEC(".maps");

// container_router_stats_map indexes:
// 0 entered
// 1 dropped_over_mtu
// 2 dropped_public_ipv4
// 3 saw_ipv6
// 4 redirected_to_nic
// 5 redirected_to_container
// 6 dropped_multicast
// 7 redirected_portal_to_container

static __always_inline void bumpPacketCounter(__u32 index)
{
  __u64 *slot = bpf_map_lookup_elem(&container_router_stats_map, &index);
  if (slot)
  {
    __sync_fetch_and_add(slot, 1);
  }
}

SEC("netkit/peer")
int container_egress_router(struct __sk_buff *skb)
{
  logSKB(skb);

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  __be16 protocol = skb->protocol;
  void *l3_data = data;
  struct ethhdr *eth = (struct ethhdr *)data;

  if ((void *)(eth + 1) <= data_end && eth->h_proto == protocol)
  {
    l3_data = (void *)(eth + 1);
  }

  bumpPacketCounter(0);

  __u32 interContainerMTU = containerInterContainerMTU();
  __u32 l3Offset = (__u32)((const __u8 *)l3_data - (const __u8 *)data);
  __u32 l3Length = ((__u32)skb->len > l3Offset) ? ((__u32)skb->len - l3Offset) : 0u;
  if (interContainerMTU != 0 && l3Length > interContainerMTU)
  {
    bumpPacketCounter(1);
#if PRODIGY_DEBUG
    setCheckpoint("dropOversizeInterContainerMTU");
#endif
    return NETKIT_DROP;
  }

  if (protocol == BE_ETH_P_IP && containerRequiresPublic4() == false)
  {
    bumpPacketCounter(2);
    return NETKIT_DROP;
  }

  if (protocol == BE_ETH_P_IPV6)
  {
    bumpPacketCounter(3);

    struct ipv6hdr *ipv6h = (struct ipv6hdr *)l3_data;

    if ((void *)(ipv6h + 1) > data_end)
    {
      return NETKIT_DROP;
    }

    __be8 *daddr6 = ipv6h->daddr.s6_addr;

    // Public-ingress wormhole replies can target either another local
    // container or a remote-machine container before the return path leaves
    // this container egress hook. Preserve the external source tuple here so
    // both direct local delivery and redirect-to-NIC paths keep the public
    // reply identity instead of leaking the internal container source tuple.
    (void)switchboardRewriteWormholeSourceIPv6SKB(skb);

    // bpf_skb_store_bytes() inside the wormhole rewrite helper invalidates all
    // previously derived packet pointers. Refresh the SKB view before reading
    // the destination subnet or parsing L4.
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    l3_data = data;
    eth = (struct ethhdr *)data;

    if ((void *)(eth + 1) <= data_end && eth->h_proto == protocol)
    {
      l3_data = (void *)(eth + 1);
    }

    ipv6h = (struct ipv6hdr *)l3_data;
    if ((void *)(ipv6h + 1) > data_end)
    {
      return NETKIT_DROP;
    }

    daddr6 = ipv6h->daddr.s6_addr;

    if (localSubnetContainsDaddr(daddr6))
    {
      __u8 redirectDaddr6[16] = {};
      bpf_memcpy(redirectDaddr6, daddr6, sizeof(redirectDaddr6));

      setCheckpoint("redirectToContainer");
      bumpPacketCounter(5);
      // this redirects from the perspective of the host device's interface index namespace
      return redirectToContainer(redirectDaddr6, false);
    }
    // these will only be router solitication messages if we've
    // disabled multicast on the interface
    else if (isMulticast(daddr6))
    {
      bumpPacketCounter(6);
      return NETKIT_DROP;
    }

    struct packet_description pckt = {};
    pckt.flow.proto = ipv6h->nexthdr;
    bpf_memcpy(pckt.flow.srcv6, ipv6h->saddr.s6_addr32, sizeof(pckt.flow.srcv6));
    bpf_memcpy(pckt.flow.dstv6, ipv6h->daddr.s6_addr32, sizeof(pckt.flow.dstv6));

    if (pckt.flow.proto == IPPROTO_TCP)
    {
      if (parse_tcp(data, data_end, true, &pckt) == false)
      {
        return NETKIT_DROP;
      }
    }
    else if (pckt.flow.proto == IPPROTO_UDP)
    {
      if (parse_udp(data, data_end, true, &pckt) == false)
      {
        return NETKIT_DROP;
      }
    }
    else
    {
      goto redirect_to_nic;
    }

    struct container_id containerID = {};
    struct portal_meta *portalMeta = NULL;
    int portalTarget = switchboardResolveExternalPortalTarget(data, data_end, true, &pckt, &containerID, &portalMeta);
    if (portalTarget == SWITCHBOARD_PORTAL_TARGET_DROP)
    {
      return NETKIT_DROP;
    }

    if (portalTarget == SWITCHBOARD_PORTAL_TARGET_RESOLVED)
    {
      __u16 targetPort = 0;
      if (switchboardLookupWormholeTargetPort(portalMeta->slot, &containerID, &targetPort) == false
         || switchboardRewriteWormholeIPv6TargetSKB(skb, &pckt, &containerID, targetPort) == false)
      {
         return NETKIT_DROP;
      }

      __u32 zeroidx = 0;
      struct local_container_subnet6 *localSubnet = bpf_map_lookup_elem(&local_container_subnet_map, &zeroidx);
      if (switchboardContainerIDTargetsLocalMachine(&containerID, localSubnet))
      {
        setCheckpoint("redirectPortalToContainer");
        bumpPacketCounter(7);
        return redirectContainerFragment(containerID.value[4], false) ? NETKIT_REDIRECT : NETKIT_DROP;
      }
    }
  }

redirect_to_nic:
  setCheckpoint("redirectToNIC");
  bumpPacketCounter(4);

  __u32 zeroidx = 0;
  __u32 *nic_idx = bpf_map_lookup_elem(&container_device_map, &zeroidx);
  if (!nic_idx)
  {
    return NETKIT_DROP;
  }

  data_end = (void *)(long)skb->data_end;
  eth = (struct ethhdr *)(long)skb->data;
  if ((void *)(eth + 1) > data_end)
  {
    return NETKIT_DROP;
  }

  // NETKIT_L3 skbs already carry an ETH_HLEN placeholder with h_proto set.
  // Prepending another Ethernet header here corrupts outbound frames on the
  // host NIC by leaving the original placeholder in front of the IPv6 packet.
  if (from_us_to_gateway(eth) == false)
  {
    return NETKIT_DROP;
  }

  eth->h_proto = protocol;

  int outbound_action = switchboardRouteOutboundEthFrame(skb, eth, data_end);
  if (outbound_action != TC_ACT_OK)
  {
    return NETKIT_DROP;
  }

  setCheckpoint("redirectToNIC: checkpoint 3");
  logPacketRedirectIfIdx(*nic_idx);
  logSKB(skb);
  return setInstruction(bpf_redirect(*nic_idx, 0));
}
