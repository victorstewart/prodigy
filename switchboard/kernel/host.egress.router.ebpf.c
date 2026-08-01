#include <ebpf/kernel/includes.h>
#include <ebpf/kernel/containersubnet.h>

#include <switchboard/kernel/egress.routing.h>

SEC("tcx/egress")
int host_egress(struct __sk_buff *skb)
{
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = (struct ethhdr *)(long)skb->data;

  if ((void *)(eth + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }
  int result = switchboardRouteOutboundEthFrame(skb, eth, data_end);
  if (skb->mark == SWITCHBOARD_WORMHOLE_REPLY_VALIDATED_SKB_MARK)
  {
    skb->mark = 0;
  }
  return result;
}
