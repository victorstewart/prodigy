#pragma once

#include <linux/tcp.h>

#include <switchboard/common/public.destination.h>
#include <switchboard/kernel/container.tcp.flow.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct container_service_peer);
  __type(value, __u8);
  __uint(max_entries, CONTAINER_SERVICE_PAIRINGS_MAP_ENTRIES);
} ct_adv_sources SEC(".maps");

__attribute__((__always_inline__)) static inline bool containerLearnOrAuthorizeInboundTCP(struct ipv6hdr *ip6h, struct tcphdr *tcp)
{
  if (containerNetworkAddressMatches(ip6h->daddr.s6_addr) == false)
  {
#if PRODIGY_DEBUG
    setCheckpoint("inboundDestinationMismatch");
#endif
    return false;
  }
  if (switchboardContainerDestinationIPv6(ip6h->saddr.s6_addr) == false)
  {
#if PRODIGY_DEBUG
    setCheckpoint("inboundSourceMismatch");
#endif
    return false;
  }

  struct flow_key inbound = {};
  bpf_memcpy(inbound.srcv6, ip6h->saddr.s6_addr32, sizeof(inbound.srcv6));
  bpf_memcpy(inbound.dstv6, ip6h->daddr.s6_addr32, sizeof(inbound.dstv6));
  inbound.port16[0] = tcp->source;
  inbound.port16[1] = tcp->dest;
  inbound.proto = IPPROTO_TCP;

  struct flow_key reverse = {};
  reverse_flow_key(&inbound, &reverse);
  if (tcp->syn && tcp->ack == 0)
  {
    struct container_service_peer source = {};
    bpf_memcpy(source.address, ip6h->saddr.s6_addr, sizeof(source.address));
    source.port = tcp->dest;
    if (bpf_map_lookup_elem(&ct_adv_sources, &source) == NULL)
    {
#if PRODIGY_DEBUG
      setCheckpoint("inboundPairingMissing");
#endif
      return false;
    }
    if (containerAuthorizeTCPFlow(&reverse) == false)
    {
#if PRODIGY_DEBUG
      setCheckpoint("inboundFlowInsertFailed");
#endif
      return false;
    }
    return true;
  }
  if (containerTCPFlowCurrent(&reverse, tcp->fin, tcp->rst) == false)
  {
#if PRODIGY_DEBUG
    setCheckpoint("inboundFlowMissing");
#endif
    return false;
  }
  return true;
}
