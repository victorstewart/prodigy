#include <ebpf/kernel/includes.h>
#include <ebpf/kernel/containersubnet.h>

// when running prodigy on our dev cluster, this program captures
// ingress packets from the application server dev anycast address targeted
// at the application server and redirects them into the physical NIC ingress
// where they'll be captured by the switchboard

SEC("tcx/ingress")
int tunnel_to_nic(struct __sk_buff *skb)
{
#if PRODIGY_DEBUG
  logSKB(skb);
#endif

  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = (struct ethhdr *)(long)skb->data;

  if ((void *)(eth + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }

  if (eth->h_proto == BE_ETH_P_IPV6)
  {
    struct ipv6hdr *ipv6h = (struct ipv6hdr *)(eth + 1);

    if ((void *)(ipv6h + 1) > data_end)
    {
      return TC_ACT_SHOT;
    }

    // 2602:FAC0:0FFF:FFFF::/64
    unsigned char dev_anycast6[16] = {0x26, 0x02, 0xFA, 0xC0, 0x0F, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    if (bpf_memcmp(ipv6h->daddr.s6_addr, dev_anycast6, 8) == 0)
    {
      redirectL2ToNIC(skb, eth);
      return setInstruction(TC_ACT_REDIRECT);
    }
  }
  else if (eth->h_proto == BE_ETH_P_IP)
  {
    struct iphdr *iph = (struct iphdr *)(eth + 1);

    if ((void *)(iph + 1) > data_end)
    {
      return TC_ACT_SHOT;
    }

    // 23.144.200.254/32
    __u32 dev_anycast4 = __constant_htonl(0x1790C8FE);

    if (iph->daddr == dev_anycast4)
    {
      redirectL2ToNIC(skb, eth);
      return setInstruction(TC_ACT_REDIRECT);
    }
  }

  setCheckpoint("passing");

  return setInstruction(TC_ACT_OK);
}
