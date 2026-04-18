#include <ebpf/kernel/includes.h>
#include <switchboard/common/checksum.h>

// This program is attached as BPF_NETKIT_PRIMARY on the host-side primary
// endpoint. Upstream netkit runs the program attached to the transmitting
// endpoint, so this is the host -> container hook after host routing redirects
// traffic toward the pair. netkit_xmit() has already classified skb->pkt_type
// for the destination peer before this program runs, so this hook must not try
// to repair peer packet-type classification. It only preserves the Ethernet
// header and decapsulates outer IP headers when needed.

struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 16);
  __type(key, __u32);
  __type(value, __u64);
} container_router_stats_map SEC(".maps");

// container_router_stats_map indexes:
// 0 entered
// 1 decapped_ipv6
// 2 dropped_public_ipv4
// 3 passed
// 4 reserved_host_ethernet_mac_normalization_is_done_in_host_ingress
// 5 l3_too_short_before_decap
// 6 reserved_legacy_strip_host_ethernet_failed
// 7 saw_ipv6
// 8 l3_too_short_after_decap
// 9 saw_plain_ipv6
// 10 saw_l3_without_ethernet
// 11 saw_host_ethernet
// 12 saw_non_ipv6

static __always_inline void bumpPacketCounter(__u32 index)
{
  __u64 *slot = bpf_map_lookup_elem(&container_router_stats_map, &index);
  if (slot)
  {
    __sync_fetch_and_add(slot, 1);
  }
}

#if PRODIGY_DEBUG
static __always_inline void logPostAdjustL3Frame(void *l3_data, void *data_end, __be16 protocol)
{
  struct packet *pkt = getPacket();

  if (pkt == NULL || l3_data == NULL || data_end == NULL)
  {
    return;
  }

  if (protocol == BE_ETH_P_IPV6)
  {
    struct ipv6hdr *ipv6h = (struct ipv6hdr *)l3_data;
    if ((void *)(ipv6h + 1) <= data_end)
    {
      logIp6FrameHeader(ipv6h, pkt);
      setCheckpoint("post-strip-ip6");
    }
  }
  else if (protocol == BE_ETH_P_IP)
  {
    struct iphdr *iph = (struct iphdr *)l3_data;
    if ((void *)(iph + 1) <= data_end)
    {
      logIpFrameHeader(iph, pkt);
      setCheckpoint("post-strip-ip4");
    }
  }
}
#endif

SEC("netkit/primary")
int container_ingress_router(struct __sk_buff *skb)
{
  logSKB(skb);

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
    bumpPacketCounter(11);
  }
  else
  {
    bumpPacketCounter(10);
  }

  bumpPacketCounter(0);

  if (protocol == BE_ETH_P_IPV6)
  {
    bumpPacketCounter(7);
    struct ipv6hdr *ipv6h = (struct ipv6hdr *)l3_data;

    if ((void *)(ipv6h + 1) > data_end)
    {
      bumpPacketCounter(5);
      return NETKIT_DROP;
    }

    if (ipv6h->nexthdr == IPPROTO_IPIP || ipv6h->nexthdr == IPPROTO_IPV6) // we encapsulated 4 in 6 || 6 in 6
    {
      setCheckpoint("decapping");
      bumpPacketCounter(1);

      __u64 decap_flags = switchboardAdjustRoomPreserveOffloadFlags()
         | (ipv6h->nexthdr == IPPROTO_IPV6
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
          bumpPacketCounter(8);
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
          bumpPacketCounter(8);
          return NETKIT_DROP;
        }
      }
    }
    else
    {
      bumpPacketCounter(9);
    }
  }
  else
  {
    bumpPacketCounter(12);
  }

  if (protocol == BE_ETH_P_IP && containerRequiresPublic4() == false)
  {
    bumpPacketCounter(2);
    return NETKIT_DROP;
  }

#if PRODIGY_DEBUG
  logPostAdjustL3Frame(l3_data, data_end, protocol);
#endif

  bumpPacketCounter(3);

  return NETKIT_PASS;
}
