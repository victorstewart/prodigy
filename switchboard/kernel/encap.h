#pragma once

#include <switchboard/common/constants.h>
#include <switchboard/kernel/csum.h>

__attribute__((__always_inline__)) static inline void create_v6_hdr(struct ipv6hdr *ip6h, struct local_container_subnet6 *localsubnet6, struct container_id *containerID, __u16 payload_len, __u8 proto)
{
  // struct ipv6hdr {
  // #if defined(__LITTLE_ENDIAN_BITFIELD)
  // 	__u8			priority:4,
  // 				version:4;
  // #elif defined(__BIG_ENDIAN_BITFIELD)
  // 	__u8			version:4,
  // 				priority:4;
  // #else
  // #error	"Please fix <asm/byteorder.h>"
  // #endif
  // 	__u8			flow_lbl[3];

  // 	__be16			payload_len;
  // 	__u8			nexthdr;
  // 	__u8			hop_limit;

  // 	__struct_group(/* no tag */, addrs, /* no attrs */,
  // 		struct	in6_addr	saddr;
  // 		struct	in6_addr	daddr;
  // 	);
  // };

  ip6h->priority = 0;
  ip6h->version = 6;
  bpf_memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
  ip6h->payload_len = bpf_htons(payload_len);
  ip6h->nexthdr = proto;
  ip6h->hop_limit = 64;
  bpf_memcpy(ip6h->saddr.s6_addr, (__u8 *)&container_network_subnet6, 11);
  bpf_memcpy(ip6h->saddr.s6_addr + 11, (__u8 *)localsubnet6, 4);
  ip6h->saddr.s6_addr[15] = 0; // aka this host

  bpf_memcpy(ip6h->daddr.s6_addr, (__u8 *)&container_network_subnet6, 11);
  bpf_memcpy(ip6h->daddr.s6_addr + 11, (__u8 *)containerID, 5);
}

__attribute__((__always_inline__)) static inline bool markLocalOverlayXDP(struct xdp_md *xdp)
{
  if (bpf_xdp_adjust_meta(xdp, -(int)sizeof(__u32)) != 0)
  {
    return false;
  }
  void *data = (void *)(long)xdp->data;
  __u32 *marker = (void *)(long)xdp->data_meta;
  if ((void *)(marker + 1) > data)
  {
    return false;
  }
  *marker = SWITCHBOARD_OVERLAY_LOCAL_XDP_META_MAGIC;
  return true;
}

__attribute__((__always_inline__)) static inline bool encap_v6(struct xdp_md *xdp, bool localDelivery, struct local_container_subnet6 *localsubnet6, struct container_id *containerID, __u16 packet_len, bool is_ipv6)
{
  // ip(6)ip6 encap
  if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct ipv6hdr)))
  {
    return false;
  }
  if (localDelivery && markLocalOverlayXDP(xdp) == false)
  {
    return false;
  }

  // struct ethhdr {
  // 	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
  // 	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
  // 	__be16		h_proto;		/* packet type ID field	*/
  // } __attribute__((packed));

  // struct ethhdr is 14 bytes
  // struct ipv6hdr is 40 bytes

  // oldeth + inner_ip6h + tcp||udp
  // 0        14           54
  //
  // neweth + outer_ip6h + inner_ip6h +
  // -40      -26       	 14

  // so inner_ip6h doesn't need to be touched

  // every pointer gets verifier-invalidated after changing the packet

  // check vm_host_ingress

  void *data = (void *)(long)xdp->data;
  void *data_end = (void *)(long)xdp->data_end;
  struct ethhdr *new_eth = data;
  struct ethhdr *old_eth = data + sizeof(struct ipv6hdr);
  struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);

  if ((void *)(new_eth + 1) > data_end || (void *)(old_eth + 1) > data_end || (void *)(ip6h + 1) > data_end)
  {
    return false;
  }

  if (localDelivery == false)
  {
    if (from_us_to_gateway(new_eth) == false)
    {
      return false;
    }
  }
  else
  {
    // Local-delivery packets stay on this NIC path; preserve the original L2
    // source/destination addresses instead of leaving them undefined.
    bpf_memcpy(new_eth->h_source, old_eth->h_source, 6);
    bpf_memcpy(new_eth->h_dest, old_eth->h_dest, 6);
  }

  new_eth->h_proto = BE_ETH_P_IPV6;

  create_v6_hdr(ip6h, localsubnet6, containerID, packet_len, is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP);

  return true;
}

__attribute__((__always_inline__)) static inline bool encap_v6_route(struct xdp_md *xdp,
                                                                     const struct switchboard_overlay_machine_route *route,
                                                                     __u16 packet_len,
                                                                     bool is_ipv6)
{
  if (route == NULL || route->family != SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6)
  {
    return false;
  }

  if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct ipv6hdr)))
  {
    return false;
  }

  void *data = (void *)(long)xdp->data;
  void *data_end = (void *)(long)xdp->data_end;
  struct ethhdr *new_eth = data;
  struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);

  if ((void *)(new_eth + 1) > data_end || (void *)(ip6h + 1) > data_end)
  {
    return false;
  }

  if (route->use_gateway_mac != 0)
  {
    if (from_us_to_gateway(new_eth) == false)
    {
      return false;
    }
  }
  else if (from_us_to_overlay_next_hop(new_eth, route->next_hop_mac) == false)
  {
    return false;
  }

  new_eth->h_proto = BE_ETH_P_IPV6;

  ip6h->priority = 0;
  ip6h->version = 6;
  bpf_memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
  ip6h->payload_len = bpf_htons(packet_len);
  ip6h->nexthdr = is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP;
  ip6h->hop_limit = 64;
  bpf_memcpy(ip6h->saddr.s6_addr, route->source6, sizeof(route->source6));
  bpf_memcpy(ip6h->daddr.s6_addr, route->next_hop6, sizeof(route->next_hop6));

  return true;
}

__attribute__((__always_inline__)) static inline bool encap_wormhole_v6(struct xdp_md *xdp,
                                                                        bool localDelivery,
                                                                        struct local_container_subnet6 *localsubnet6,
                                                                        struct container_id *containerID,
                                                                        __u16 packet_len,
                                                                        bool is_ipv6)
{
  const int added = (int)(sizeof(struct ipv6hdr) + sizeof(struct switchboard_wormhole_overlay_header));
  if (localsubnet6 == NULL || bpf_xdp_adjust_head(xdp, -added))
  {
    return false;
  }
  if (localDelivery && markLocalOverlayXDP(xdp) == false)
  {
    return false;
  }

  void *data = (void *)(long)xdp->data;
  void *data_end = (void *)(long)xdp->data_end;
  struct ethhdr *new_eth = data;
  struct ethhdr *old_eth = data + added;
  struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
  struct switchboard_wormhole_overlay_header *wormhole = (void *)(ip6h + 1);
  if ((void *)(new_eth + 1) > data_end || (void *)(old_eth + 1) > data_end ||
      (void *)(ip6h + 1) > data_end || (void *)(wormhole + 1) > data_end)
  {
    return false;
  }

  if (localDelivery)
  {
    bpf_memcpy(new_eth->h_source, old_eth->h_source, ETH_ALEN);
    bpf_memcpy(new_eth->h_dest, old_eth->h_dest, ETH_ALEN);
  }
  else if (from_us_to_gateway(new_eth) == false)
  {
    return false;
  }

  new_eth->h_proto = BE_ETH_P_IPV6;
  create_v6_hdr(ip6h,
                localsubnet6,
                containerID,
                (__u16)(packet_len + sizeof(*wormhole)),
                IPPROTO_GRE);
  switchboardBuildWormholeOverlayHeader(wormhole, containerID, is_ipv6);
  return switchboardWormholeOverlayHeaderValid(wormhole);
}

__attribute__((__always_inline__)) static inline bool encap_wormhole_route(struct xdp_md *xdp,
                                                                           const struct switchboard_overlay_machine_route *route,
                                                                           const struct container_id *containerID,
                                                                           __u16 packet_len,
                                                                           bool is_ipv6)
{
  if (route == NULL || containerID == NULL || containerID->hasID == false)
  {
    return false;
  }

  __u32 outerBytes = route->family == SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6
                         ? sizeof(struct ipv6hdr)
                         : (route->family == SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV4 ? sizeof(struct iphdr) : 0u);
  if (outerBytes == 0u || bpf_xdp_adjust_head(xdp, -(int)(outerBytes + sizeof(struct switchboard_wormhole_overlay_header))))
  {
    return false;
  }

  void *data = (void *)(long)xdp->data;
  void *data_end = (void *)(long)xdp->data_end;
  struct ethhdr *eth = data;
  struct switchboard_wormhole_overlay_header *wormhole = data + sizeof(struct ethhdr) + outerBytes;
  if ((void *)(eth + 1) > data_end || (void *)(wormhole + 1) > data_end)
  {
    return false;
  }

  if (route->use_gateway_mac != 0)
  {
    if (from_us_to_gateway(eth) == false)
    {
      return false;
    }
  }
  else if (from_us_to_overlay_next_hop(eth, route->next_hop_mac) == false)
  {
    return false;
  }

  switchboardBuildWormholeOverlayHeader(wormhole, containerID, is_ipv6);
  if (switchboardWormholeOverlayHeaderValid(wormhole) == false)
  {
    return false;
  }

  if (route->family == SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6)
  {
    struct ipv6hdr *ip6h = (void *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end)
    {
      return false;
    }
    eth->h_proto = BE_ETH_P_IPV6;
    ip6h->priority = 0;
    ip6h->version = 6;
    bpf_memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
    ip6h->payload_len = bpf_htons((__u16)(packet_len + sizeof(*wormhole)));
    ip6h->nexthdr = IPPROTO_GRE;
    ip6h->hop_limit = 64;
    bpf_memcpy(ip6h->saddr.s6_addr, route->source6, sizeof(route->source6));
    bpf_memcpy(ip6h->daddr.s6_addr, route->next_hop6, sizeof(route->next_hop6));
    return true;
  }

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
  {
    return false;
  }
  eth->h_proto = BE_ETH_P_IP;
  iph->version = 4;
  iph->ihl = 5;
  iph->tos = 0;
  iph->tot_len = bpf_htons((__u16)(sizeof(*iph) + sizeof(*wormhole) + packet_len));
  iph->id = 0;
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_GRE;
  iph->check = 0;
  iph->saddr = route->source4;
  iph->daddr = route->next_hop4;
  __u64 csum = 0;
  ipv4_csum_inline(iph, &csum);
  iph->check = (__u16)csum;
  return true;
}
