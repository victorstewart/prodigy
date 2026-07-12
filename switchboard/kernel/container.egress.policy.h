#pragma once

#include <linux/tcp.h>

#include <switchboard/common/public.destination.h>
#include <switchboard/kernel/container.tcp.flow.h>
#include <switchboard/kernel/l4.ports.h>
#include <switchboard/kernel/whitehole.routing.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct container_service_peer);
  __type(value, __u8);
  __uint(max_entries, CONTAINER_SERVICE_PAIRINGS_MAP_ENTRIES);
} ct_sub_targets SEC(".maps");

__attribute__((__always_inline__)) static inline bool containerWhiteholePublicEgressIPv4(struct iphdr *iph, void *data_end)
{
  struct switchboard_l4_ports l4 = {};
  if (switchboardPublicDestinationIPv4(iph->daddr) == false ||
      (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) ||
      switchboard_parse_l4_ports((void *)(iph + 1), data_end, iph->protocol, 0, &l4) == false)
  {
    return false;
  }
  struct switchboard_whitehole_binding binding = {};
  return whitehole_binding_lookup(iph->protocol, false, &iph->saddr, l4.source, &binding);
}

__attribute__((__always_inline__)) static inline bool containerWhiteholePublicEgressIPv6(struct ipv6hdr *ip6h, void *data_end)
{
  struct switchboard_l4_ports l4 = {};
  if (switchboardPublicDestinationIPv6(ip6h->daddr.s6_addr) == false ||
      (ip6h->nexthdr != IPPROTO_TCP && ip6h->nexthdr != IPPROTO_UDP) ||
      switchboard_parse_l4_ports((void *)(ip6h + 1), data_end, ip6h->nexthdr, 0, &l4) == false)
  {
    return false;
  }
  struct switchboard_whitehole_binding binding = {};
  return whitehole_binding_lookup(ip6h->nexthdr, true, ip6h->saddr.s6_addr, l4.source, &binding);
}

__attribute__((__always_inline__)) static inline bool containerDeclaredInternalEgressIPv6(struct ipv6hdr *ip6h, void *data_end)
{
  if (containerNetworkAddressMatches(ip6h->saddr.s6_addr) == false ||
      switchboardContainerDestinationIPv6(ip6h->daddr.s6_addr) == false ||
      ip6h->nexthdr != IPPROTO_TCP)
  {
    return false;
  }
  struct tcphdr *tcp = (struct tcphdr *)(ip6h + 1);
  if ((void *)(tcp + 1) > data_end)
  {
    return false;
  }
  struct flow_key flow = {};
  bpf_memcpy(flow.srcv6, ip6h->saddr.s6_addr32, sizeof(flow.srcv6));
  bpf_memcpy(flow.dstv6, ip6h->daddr.s6_addr32, sizeof(flow.dstv6));
  flow.port16[0] = tcp->source;
  flow.port16[1] = tcp->dest;
  flow.proto = IPPROTO_TCP;
  if (tcp->syn && tcp->ack == 0)
  {
    struct container_service_peer target = {};
    bpf_memcpy(target.address, ip6h->daddr.s6_addr, sizeof(target.address));
    target.port = tcp->dest;
    return bpf_map_lookup_elem(&ct_sub_targets, &target) != NULL &&
           containerAuthorizeTCPFlow(&flow);
  }
  return containerTCPFlowCurrent(&flow, tcp->fin, tcp->rst);
}
