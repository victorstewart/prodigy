#include <ebpf/kernel/includes.h>
#include <ebpf/kernel/containersubnet.h>

#include <switchboard/kernel/egress.routing.h>

// A registered hosted prefix can coincide with the peer's physical address.
// Traffic already using the exact selected underlay endpoints must stay on the
// host route, not be sent back through the hosted-ingress overlay again.
__attribute__((__always_inline__)) static inline bool host_egress_is_exact_overlay_underlay(struct ethhdr *eth, void *data_end)
{
  __u32 fragment = 0;
  if (eth->h_proto == BE_ETH_P_IPV6)
  {
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end || !lookupHostedIngressMachineFragmentIPv6(ip6h->daddr.s6_addr32, &fragment)) return false;
    struct switchboard_overlay_machine_route *route = lookupOverlayMachineRouteByFragment(fragment);
    return route && route->family == SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6 &&
        route->use_gateway_mac != SWITCHBOARD_OVERLAY_ROUTE_ACTION_LOCAL_CONTAINER_REDIRECT &&
        bpf_memcmp(ip6h->saddr.s6_addr, route->source6, 16) == 0 &&
        bpf_memcmp(ip6h->daddr.s6_addr, route->next_hop6, 16) == 0;
  }
  if (eth->h_proto == BE_ETH_P_IP)
  {
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end || !lookupHostedIngressMachineFragmentIPv4(iph->daddr, &fragment)) return false;
    struct switchboard_overlay_machine_route *route = lookupOverlayMachineRouteByFragment(fragment);
    return route && route->family == SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV4 &&
        route->use_gateway_mac != SWITCHBOARD_OVERLAY_ROUTE_ACTION_LOCAL_CONTAINER_REDIRECT &&
        iph->saddr == route->source4 && iph->daddr == route->next_hop4;
  }
  return false;
}

SEC("tcx/egress")
int host_egress(struct __sk_buff *skb)
{
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = (struct ethhdr *)(long)skb->data;

  if ((void *)(eth + 1) > data_end)
  {
    return TC_ACT_SHOT;
  }
  if (host_egress_is_exact_overlay_underlay(eth, data_end))
  {
    if (skb->mark == SWITCHBOARD_WORMHOLE_REPLY_VALIDATED_SKB_MARK) skb->mark = 0;
    return TC_ACT_OK;
  }
  int result = switchboardRouteOutboundEthFrame(skb, eth, data_end);
  if (skb->mark == SWITCHBOARD_WORMHOLE_REPLY_VALIDATED_SKB_MARK)
  {
    skb->mark = 0;
  }
  return result;
}
