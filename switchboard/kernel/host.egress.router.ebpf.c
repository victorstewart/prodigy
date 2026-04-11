#include <ebpf/kernel/includes.h>
#include <ebpf/kernel/containersubnet.h>

#include <switchboard/kernel/egress.routing.h>

SEC("tcx/egress")
int host_egress_router(struct __sk_buff *skb)
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
   return switchboardRouteOutboundEthFrame(skb, eth, data_end);
}
