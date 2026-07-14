#include <ebpf/kernel/includes.h>
#if PRODIGY_DEBUG
#include <ebpf/kernel/debug.h>
#endif
#include <switchboard/common/checksum.h>
#include <switchboard/common/public.destination.h>
#include <switchboard/kernel/container.ingress.policy.h>

// This program is attached as BPF_NETKIT_PRIMARY on the host-side primary
// endpoint. Upstream netkit runs the program attached to the transmitting
// endpoint, so this is the host -> container hook after host routing redirects
// traffic toward the pair. netkit_xmit() has already classified skb->pkt_type
// for the destination peer before this program runs, so this hook must not try
// to repair peer packet-type classification. It only preserves the Ethernet
// header and decapsulates outer IP headers when needed.

SEC("netkit/primary")
int ct_ingress(struct __sk_buff *skb)
{
#if PRODIGY_DEBUG
  logSKB(skb);
#endif

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  __be16 protocol = skb->protocol;
  void *l3_data = data;
  struct ethhdr *eth = (struct ethhdr *)data;
  bool has_host_ethernet = false;

  if ((void *)(eth + 1) <= data_end && eth->h_proto == protocol)
  {
    l3_data = (void *)(eth + 1);
    has_host_ethernet = true;
  }

  if (protocol == BE_ETH_P_IPV6)
  {
    struct ipv6hdr *ipv6h = (struct ipv6hdr *)l3_data;

    if ((void *)(ipv6h + 1) > data_end)
    {
      return NETKIT_DROP;
    }

    if (ipv6h->nexthdr == IPPROTO_IPIP || ipv6h->nexthdr == IPPROTO_IPV6) // we encapsulated 4 in 6 || 6 in 6
    {
      __u64 decap_flags = switchboardAdjustRoomPreserveOffloadFlags() | (ipv6h->nexthdr == IPPROTO_IPV6
                                                                             ? BPF_F_ADJ_ROOM_DECAP_L3_IPV6
                                                                             : BPF_F_ADJ_ROOM_DECAP_L3_IPV4);

      // strip the encapsulation header
      if (bpf_skb_adjust_room(skb,
                              -(__s32)sizeof(struct ipv6hdr),
                              BPF_ADJ_ROOM_MAC,
                              decap_flags))
      {
        return NETKIT_DROP;
      }

      // bpf_skb_adjust_room invalidates the packet, need to reauthorize.
      data = (void *)(long)skb->data;
      data_end = (void *)(long)skb->data_end;
      protocol = skb->protocol;
      l3_data = data;

      if (has_host_ethernet)
      {
        eth = (struct ethhdr *)data;
        if ((void *)(eth + 1) > data_end)
        {
          return NETKIT_DROP;
        }

        eth->h_proto = switchboardHostIngressEffectiveProtocol(eth->h_proto, protocol, true);
        l3_data = (void *)(eth + 1);
      }

      if (protocol == BE_ETH_P_IPV6)
      {
        ipv6h = (struct ipv6hdr *)l3_data;
        if ((void *)(ipv6h + 1) > data_end)
        {
          return NETKIT_DROP;
        }
      }
    }
  }

  __u8 networkMode = containerNetworkMode();
  if (networkMode == CONTAINER_NETWORK_DENY || networkMode > CONTAINER_NETWORK_DECLARED_ONLY)
  {
    return NETKIT_DROP;
  }
  if (networkMode == CONTAINER_NETWORK_DECLARED_ONLY && protocol == BE_ETH_P_IPV6)
  {
    struct ipv6hdr *ip6h = (struct ipv6hdr *)l3_data;
    if ((void *)(ip6h + 1) > data_end)
    {
      return NETKIT_DROP;
    }
    if (switchboardContainerDestinationIPv6(ip6h->daddr.s6_addr))
    {
      struct tcphdr *tcp = (struct tcphdr *)(ip6h + 1);
      if (ip6h->nexthdr != IPPROTO_TCP || (void *)(tcp + 1) > data_end ||
          containerLearnOrAuthorizeInboundTCP(ip6h, tcp) == false)
      {
        return NETKIT_DROP;
      }
    }
  }

  if (protocol == BE_ETH_P_IP && containerRequiresPublic4() == false)
  {
    return NETKIT_DROP;
  }

  return NETKIT_PASS;
}
