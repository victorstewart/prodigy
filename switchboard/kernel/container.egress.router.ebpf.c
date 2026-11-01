#include <ebpf/kernel/includes.h>
#include <ebpf/kernel/containersubnet.h>

#include <switchboard/kernel/egress.routing.h>
#include <switchboard/kernel/container.egress.policy.h>
#include <switchboard/kernel/portal.routing.h>

__attribute__((__always_inline__)) static inline bool containerMasqueGatewayRemoteTransitIPv6(
    struct ipv6hdr *ip6h, void *data_end)
{
  if (ip6h == NULL || (void *)(ip6h + 1) > data_end || ip6h->nexthdr != IPPROTO_TCP ||
      (void *)((struct tcphdr *)(ip6h + 1) + 1) > data_end)
  {
    return false;
  }

  __u32 zeroidx = 0, sourceMachine = 0;
  struct container_network_policy *policy = bpf_map_lookup_elem(&ct_net_policy, &zeroidx);
  struct local_container_subnet6 *localSubnet = bpf_map_lookup_elem(&lc_subnet, &zeroidx);
  if (policy == NULL || localSubnet == NULL ||
      switchboardExtractOverlayMachineIdentityFromIPv6(ip6h->saddr.s6_addr, &sourceMachine) == false)
  {
    return false;
  }

  // Do not use an exact machine route here: only the selected source-site
  // fallback proves that this gateway owns the remote-site tunnel boundary.
  struct switchboard_overlay_machine_route *sourceSiteRoute = lookupOverlaySiteRoute(sourceMachine);
  return switchboardMasqueGatewayRemoteTransitPermitted(containerNetworkMode(), localSubnet,
      policy->containerFragment, ip6h->saddr.s6_addr, ip6h->daddr.s6_addr, true, sourceSiteRoute);
}

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

  // Public-ingress wormhole replies can target either another local
  // container or a remote destination. Authenticate and preserve their
  // external source tuple at this per-container hook, where the exact owner
  // identity is available, before any host-wide routing step.
  skb->mark = 0;
  skb->priority = 0;
  int wormholeReply = SWITCHBOARD_WORMHOLE_REPLY_NONE;
  if (protocol == BE_ETH_P_IP)
  {
    wormholeReply = switchboardRewriteWormholeSourceIPv4SKB(skb);
  }
  else if (protocol == BE_ETH_P_IPV6)
  {
    wormholeReply = switchboardRewriteWormholeSourceIPv6SKB(skb);
  }
  if (wormholeReply == SWITCHBOARD_WORMHOLE_REPLY_DROP)
  {
    return NETKIT_DROP;
  }
  if (wormholeReply != SWITCHBOARD_WORMHOLE_REPLY_NONE)
  {
    skb->mark = SWITCHBOARD_WORMHOLE_REPLY_VALIDATED_SKB_MARK;
  }

  // A public rewrite can invalidate packet pointers. Re-establish the view
  // before applying egress policy or routing the authenticated reply.
  data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;
  l3_data = data;
  eth = (struct ethhdr *)data;
  if ((void *)(eth + 1) <= data_end && eth->h_proto == protocol)
  {
    l3_data = (void *)(eth + 1);
  }

  // A reply is authenticated against the selected server's exact public
  // wormhole flow before reaching this point.  Its destination is the
  // originating whitehole tuple, whose binding is the authoritative client
  // container owner.  Keep a local reply on the netkit path instead of
  // handing it to host routing (which cannot return it to the client netkit).
  if (wormholeReply == SWITCHBOARD_WORMHOLE_REPLY_PUBLIC)
  {
    struct switchboard_whitehole_binding clientBinding = {};
    struct switchboard_l4_ports l4 = {};
    __u32 zeroidx = 0;
    struct local_container_subnet6 *localSubnet = bpf_map_lookup_elem(&lc_subnet, &zeroidx);
    bool localClient = false;

    if (protocol == BE_ETH_P_IP)
    {
      struct iphdr *iph = (struct iphdr *)l3_data;
      if (switchboard_unfragmented_ipv4(iph, data_end) == false ||
          switchboard_parse_l4_ports((void *)(iph + 1), data_end, iph->protocol,
                                     l3Offset + sizeof(struct iphdr), &l4) == false)
      {
        return NETKIT_DROP;
      }
      localClient = whitehole_binding_lookup(iph->protocol, false, &iph->daddr, l4.dest, &clientBinding) &&
                    clientBinding.container.hasID &&
                    switchboardContainerIDTargetsLocalMachine(&clientBinding.container, localSubnet);
    }
    else if (protocol == BE_ETH_P_IPV6)
    {
      struct ipv6hdr *ip6h = (struct ipv6hdr *)l3_data;
      if ((void *)(ip6h + 1) > data_end ||
          switchboard_parse_l4_ports((void *)(ip6h + 1), data_end, ip6h->nexthdr,
                                     l3Offset + sizeof(struct ipv6hdr), &l4) == false)
      {
        return NETKIT_DROP;
      }
      localClient = whitehole_binding_lookup(ip6h->nexthdr, true, ip6h->daddr.s6_addr, l4.dest, &clientBinding) &&
                    clientBinding.container.hasID &&
                    switchboardContainerIDTargetsLocalMachine(&clientBinding.container, localSubnet);
    }

    if (localClient)
    {
      return redirectContainerFragment(clientBinding.container.value[4], false) ? NETKIT_REDIRECT : NETKIT_DROP;
    }
  }

  bool masqueGatewayTransit = false;
  if (networkMode == CONTAINER_NETWORK_DESTINATION_ALLOWLIST && wormholeReply == SWITCHBOARD_WORMHOLE_REPLY_NONE)
  {
    __u8 proto = 0;
    __be16 port = 0;
    if (protocol == BE_ETH_P_IP)
    {
      struct iphdr *iph = (struct iphdr *)l3_data;
      if (switchboard_unfragmented_ipv4(iph, data_end) == false)
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
      goto forward_to_host;
    }
    if (protocol == BE_ETH_P_IPV6)
    {
      struct ipv6hdr *ip6h = (struct ipv6hdr *)l3_data;
      struct switchboard_l4_ports l4 = {};
      if (containerMasqueGatewayRemoteTransitIPv6(ip6h, data_end))
      {
        masqueGatewayTransit = true;
      }
      else
      {
        if ((void *)(ip6h + 1) > data_end || ip6h->nexthdr != IPPROTO_UDP ||
            switchboard_parse_l4_ports((void *)(ip6h + 1), data_end, ip6h->nexthdr,
                                      l3Offset + sizeof(struct ipv6hdr), &l4) == false ||
            containerEgressAllow6(ip6h->daddr.s6_addr, ip6h->nexthdr, l4.dest) == false)
        {
          return NETKIT_DROP;
        }
        goto forward_to_host;
      }
    }
    if (!masqueGatewayTransit) return NETKIT_DROP;
  }
  bool privateSiteFlow = false;
  if (protocol == BE_ETH_P_IPV6)
  {
    struct ipv6hdr *ip6h = (struct ipv6hdr *)l3_data;
    if ((void *)(ip6h + 1) > data_end) return NETKIT_DROP;
    privateSiteFlow = switchboardCrossSiteContainerFlow(ip6h->saddr.s6_addr, ip6h->daddr.s6_addr);
  }
  // Public application ingress may use unrestricted policy, but its private
  // cross-site sockets still require an exact authenticated session lease.
  if ((networkMode == CONTAINER_NETWORK_DECLARED_ONLY || privateSiteFlow) &&
      wormholeReply == SWITCHBOARD_WORMHOLE_REPLY_NONE && !masqueGatewayTransit)
  {
    if (protocol == BE_ETH_P_IP)
    {
      struct iphdr *iph = (struct iphdr *)l3_data;
      if (switchboard_unfragmented_ipv4(iph, data_end) == false ||
          containerWhiteholePublicEgressIPv4(iph, data_end) == false)
      {
        return NETKIT_DROP;
      }
      goto forward_to_host;
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
        goto forward_to_host;
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

  if (protocol == BE_ETH_P_IP)
  {
    struct iphdr *iph = (struct iphdr *)l3_data;
    if (switchboard_unfragmented_ipv4(iph, data_end) == false)
    {
      return NETKIT_DROP;
    }

    if (wormholeReply == SWITCHBOARD_WORMHOLE_REPLY_NONE)
    {
      struct packet_description pckt = {};
      pckt.flow.proto = iph->protocol;
      pckt.flow.src = iph->saddr;
      pckt.flow.dst = iph->daddr;
      if (pckt.flow.proto == IPPROTO_TCP)
      {
        if (parse_tcp(data, data_end, false, &pckt) == false)
        {
          return NETKIT_DROP;
        }
      }
      else if (pckt.flow.proto == IPPROTO_UDP)
      {
        if (parse_udp(data, data_end, false, &pckt) == false)
        {
          return NETKIT_DROP;
        }
      }
      else
      {
        goto forward_to_host;
      }

      struct container_id containerID = {};
      struct portal_meta *portalMeta = NULL;
      int portalTarget = switchboardResolveExternalPortalTarget(data, data_end, false, &pckt, &containerID, &portalMeta);
      if (portalTarget == SWITCHBOARD_PORTAL_TARGET_DROP)
      {
        return NETKIT_DROP;
      }

      if (portalTarget == SWITCHBOARD_PORTAL_TARGET_RESOLVED)
      {
        if (portalMeta != NULL)
        {
          (void)switchboardSelectPairAdmissionTarget(&pckt, portalMeta->slot, &containerID);
        }
        __u16 targetPort = 0;
        if (portalMeta == NULL || switchboardLookupWormholeTargetPort(portalMeta->slot, &containerID, &targetPort) == false)
        {
          return NETKIT_DROP;
        }

        __u32 zeroidx = 0;
        struct local_container_subnet6 *localSubnet = bpf_map_lookup_elem(&lc_subnet, &zeroidx);
        if (switchboardContainerIDTargetsLocalMachine(&containerID, localSubnet))
        {
          struct portal_definition portal = {};
          if (switchboardPacketPortalDefinition(&pckt, false, &portal) == false ||
              switchboardLearnPublicWormholeFlowIPv4(&pckt, &containerID, targetPort, &portal, portalMeta->slot) == false ||
              switchboardRewriteWormholeIPv4TargetSKB(skb, &pckt, targetPort) == false)
          {
            return NETKIT_DROP;
          }
          skb->mark = SWITCHBOARD_WORMHOLE_SKB_MARK;
          return redirectContainerFragment(containerID.value[4], false) ? NETKIT_REDIRECT : NETKIT_DROP;
        }
      }
    }

    if (wormholeReply == SWITCHBOARD_WORMHOLE_REPLY_NONE && containerRequiresPublic4() == false)
    {
      return NETKIT_DROP;
    }
  }

  if (protocol == BE_ETH_P_IPV6)
  {
    struct ipv6hdr *ipv6h = (struct ipv6hdr *)l3_data;

    if ((void *)(ipv6h + 1) > data_end)
    {
      return NETKIT_DROP;
    }

    __be8 *daddr6 = ipv6h->daddr.s6_addr;

    if (localSubnetContainsDaddr(daddr6))
    {
      // Let the host's per-container /128 route deliver same-machine traffic.
      // A direct bpf_redirect() to an L3 netkit strips its synthetic Ethernet
      // placeholder before the target netkit transmit path and drops the skb.
      skb->mark = 0;
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
      goto forward_to_host;
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
      if (portalMeta != NULL)
      {
        (void)switchboardSelectPairAdmissionTarget(&pckt, portalMeta->slot, &containerID);
      }
      __u16 targetPort = 0;
      if (portalMeta == NULL || switchboardLookupWormholeTargetPort(portalMeta->slot, &containerID, &targetPort) == false)
      {
        return NETKIT_DROP;
      }

      __u32 zeroidx = 0;
      struct local_container_subnet6 *localSubnet = bpf_map_lookup_elem(&lc_subnet, &zeroidx);
      if (switchboardContainerIDTargetsLocalMachine(&containerID, localSubnet))
      {
        struct portal_definition portal = {};
        if (switchboardPacketPortalDefinition(&pckt, true, &portal) == false ||
            switchboardLearnPublicWormholeFlowIPv6(&pckt, &containerID, targetPort, &portal, portalMeta->slot) == false ||
            switchboardRewriteWormholeIPv6TargetSKB(skb, &pckt, &containerID, targetPort) == false)
        {
          return NETKIT_DROP;
        }
        skb->mark = SWITCHBOARD_WORMHOLE_SKB_MARK;
        return redirectContainerFragment(containerID.value[4], false) ? NETKIT_REDIRECT : NETKIT_DROP;
      }

      __u32 machineFragment = switchboardMakeOverlayMachineIdentity(containerID.value[0], ((__u32)containerID.value[1] << 16) |
                              ((__u32)containerID.value[2] << 8) |
                              (__u32)containerID.value[3]);
      struct switchboard_overlay_machine_route *route = lookupOverlayMachineRouteByFragment(machineFragment);
      if (skb->len <= sizeof(struct ethhdr) || skb->len - sizeof(struct ethhdr) > 0xffffu)
      {
        return NETKIT_DROP;
      }
      // This branch bypasses normal outbound routing, which learns the reverse
      // whitehole flow before forwarding. Preserve that reply authorization
      // before encapsulation changes the packet headers.
      if (route == NULL || switchboardMaybeLearnWhiteholeIPv6(eth, data_end) != TC_ACT_OK)
      {
        return NETKIT_DROP;
      }
      __u16 innerBytes = (__u16)(skb->len - sizeof(struct ethhdr));
      if (switchboardEncapWormholeSKB(skb,
                                                       innerBytes,
                                                       IPPROTO_IPV6,
                                                       route,
                                                       &containerID) == false)
      {
        return NETKIT_DROP;
      }
      int injectionAction = switchboardCompleteMasqueGatewayInjection(skb, route);
      if (injectionAction == TC_ACT_REDIRECT) return NETKIT_REDIRECT;
      return injectionAction == TC_ACT_OK ? NETKIT_PASS : NETKIT_DROP;
    }
  }

forward_to_host: ;
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
  if (outbound_action == TC_ACT_REDIRECT) return NETKIT_REDIRECT;
  if (outbound_action != TC_ACT_OK) return NETKIT_DROP;

  // L3 netkit packets carry only a synthetic Ethernet placeholder, so a
  // direct bpf_redirect() to a MAC device is rejected by skb_do_redirect().
  // PASS lets netkit remove that placeholder and gives the packet to the host
  // stack, which routes it through the existing host-egress program.
  return NETKIT_PASS;
}
