#include <ebpf/kernel/includes.h>
#include <ebpf/kernel/containersubnet.h>

#include <switchboard/kernel/egress.routing.h>
#include <switchboard/kernel/container.egress.policy.h>
#include <switchboard/kernel/portal.routing.h>

// This program is attached as BPF_NETKIT_PEER using the host-side primary
// ifindex. Upstream netkit resolves that attach type to the peer endpoint, and
// netkit_xmit() runs the program attached to the transmitting endpoint. That
// makes this the container -> host egress hook after packets leave the
// container network stack. If the destination is another local container,
// preserve any wormhole source tuple first and then forward there; otherwise
// forward toward the NIC.

SEC("netkit/peer")
int ct_egress(struct __sk_buff *skb)
{
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  __be16 protocol = skb->protocol;
  void *l3_data = data;
  struct ethhdr *eth = (struct ethhdr *)data;

  if ((void *)(eth + 1) <= data_end && eth->h_proto == protocol)
  {
    l3_data = (void *)(eth + 1);
  }

  __u32 interContainerMTU = containerInterContainerMTU();
  __u32 l3Offset = (__u32)((const __u8 *)l3_data - (const __u8 *)data);
  __u32 l3Length = ((__u32)skb->len > l3Offset) ? ((__u32)skb->len - l3Offset) : 0u;
  if (interContainerMTU != 0 && l3Length > interContainerMTU)
  {
    return NETKIT_DROP;
  }

  __u8 networkMode = containerNetworkMode();
  if (networkMode == CONTAINER_NETWORK_DENY || networkMode > CONTAINER_NETWORK_DECLARED_ONLY)
  {
    return NETKIT_DROP;
  }
  if (networkMode == CONTAINER_NETWORK_DESTINATION_ALLOWLIST)
  {
    __u8 proto = 0;
    __be16 port = 0;
    if (protocol == BE_ETH_P_IP)
    {
      struct iphdr *iph = (struct iphdr *)l3_data;
      if ((void *)(iph + 1) > data_end || iph->ihl != 5)
      {
        return NETKIT_DROP;
      }
      proto = iph->protocol;
      struct switchboard_l4_ports l4 = {};
      if (switchboard_parse_l4_ports((void *)(iph + 1), data_end, proto, l3Offset + sizeof(struct iphdr), &l4) == false)
      {
        return NETKIT_DROP;
      }
      port = l4.dest;
      if (containerEgressAllow4(iph->daddr, proto, port) == false)
      {
        return NETKIT_DROP;
      }
      goto redirect_to_nic;
    }
    return NETKIT_DROP;
  }
  if (networkMode == CONTAINER_NETWORK_DECLARED_ONLY)
  {
    if (protocol == BE_ETH_P_IP)
    {
      struct iphdr *iph = (struct iphdr *)l3_data;
      if ((void *)(iph + 1) > data_end || iph->ihl != 5 ||
          containerWhiteholePublicEgressIPv4(iph, data_end) == false)
      {
        return NETKIT_DROP;
      }
      goto redirect_to_nic;
    }
    if (protocol == BE_ETH_P_IPV6)
    {
      struct ipv6hdr *ip6h = (struct ipv6hdr *)l3_data;
      if ((void *)(ip6h + 1) > data_end)
      {
        return NETKIT_DROP;
      }
      if (containerWhiteholePublicEgressIPv6(ip6h, data_end))
      {
        goto redirect_to_nic;
      }
      if (containerDeclaredInternalEgressIPv6(ip6h, data_end) == false)
      {
        return NETKIT_DROP;
      }
    }
    else
    {
      return NETKIT_DROP;
    }
  }

  if (protocol == BE_ETH_P_IP && containerRequiresPublic4() == false)
  {
    return NETKIT_DROP;
  }

  if (protocol == BE_ETH_P_IPV6)
  {
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
      // Let the host's per-container /128 route deliver same-machine traffic.
      // A direct bpf_redirect() to an L3 netkit strips its synthetic Ethernet
      // placeholder before the target netkit transmit path and drops the skb.
      return NETKIT_PASS;
    }
    // these will only be router solitication messages if we've
    // disabled multicast on the interface
    else if (isMulticast(daddr6))
    {
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
      if (switchboardLookupWormholeTargetPort(portalMeta->slot, &containerID, &targetPort) == false || switchboardRewriteWormholeIPv6TargetSKB(skb, &pckt, &containerID, targetPort) == false)
      {
        return NETKIT_DROP;
      }

      __u32 zeroidx = 0;
      struct local_container_subnet6 *localSubnet = bpf_map_lookup_elem(&lc_subnet, &zeroidx);
      if (switchboardContainerIDTargetsLocalMachine(&containerID, localSubnet))
      {
        return redirectContainerFragment(containerID.value[4], false) ? NETKIT_REDIRECT : NETKIT_DROP;
      }
    }
  }

redirect_to_nic: ;
  __u32 zeroidx = 0;
  __u32 *nic_idx = bpf_map_lookup_elem(&ct_dev_map, &zeroidx);
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

  return bpf_redirect(*nic_idx, 0);
}
