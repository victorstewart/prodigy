#pragma once

__attribute__((__always_inline__)) 
static inline void create_v6_hdr(struct ipv6hdr *ip6h, struct local_container_subnet6 *localsubnet6, struct container_id *containerID, __u16 payload_len, __u8 proto) 
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

__attribute__((__always_inline__)) 
static inline bool encap_v6(struct xdp_md *xdp, bool localDelivery, struct local_container_subnet6 *localsubnet6, struct container_id *containerID, __u16 packet_len, bool is_ipv6) 
{
  	// ip(6)ip6 encap
  	if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct ipv6hdr)))
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
      if (from_us_to_gateway(new_eth) == false) return false;
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
