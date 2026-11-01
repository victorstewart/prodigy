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

// Value 1 admits a connector's exact peer; value 2 denotes a listener's
// destination port and is consulted only on a marked Wormhole ingress.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct container_egress_allow_key);
  __type(value, __u8);
  __uint(max_entries, CONTAINER_EGRESS_ALLOWLIST_MAX_ENTRIES);
} ct_ing_allow SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct container_egress_allow6_key);
  __type(value, __u8);
  __uint(max_entries, CONTAINER_EGRESS_ALLOWLIST_MAX_ENTRIES);
} ct_ing_allow6 SEC(".maps");

__attribute__((__always_inline__)) static inline bool containerSystemIngressAllow4(__be32 saddr, __u8 proto, __be16 port, __u8 expected)
{
  struct container_egress_allow_key key = {.proto = proto, .port = port, .addr = saddr};
  __u8 *value = bpf_map_lookup_elem(&ct_ing_allow, &key);
  return value != NULL && *value == expected;
}

__attribute__((__always_inline__)) static inline bool containerSystemIngressAllow6(const __u8 saddr[16], __u8 proto, __be16 port, __u8 expected)
{
  struct container_egress_allow6_key key = {.proto = proto, .port = port};
  bpf_memcpy(key.addr, saddr, sizeof(key.addr));
  __u8 *value = bpf_map_lookup_elem(&ct_ing_allow6, &key);
  return value != NULL && *value == expected;
}

__attribute__((noinline)) static bool containerLearnOrAuthorizeInboundTCP(struct ipv6hdr *ip6h, struct tcphdr *tcp)
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
  if (switchboardCrossSiteContainerFlow(ip6h->saddr.s6_addr, ip6h->daddr.s6_addr))
  {
    return containerTCPFlowHasBoundAuthorization(&reverse) &&
        (containerTCPFlowCurrent(&reverse, tcp->fin, tcp->rst) ||
         (tcp->rst == 0 && containerAuthorizeTCPFlow(&reverse)));
  }
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
  if (containerTCPFlowCurrent(&reverse, tcp->fin, tcp->rst))
  {
    return true;
  }

  // Match the egress policy's idle-flow recovery. The exact advertiser tuple
  // remains the authority, so removing a declared pairing still prevents a
  // stale kernel TCP connection from recreating its flow state.
  struct container_service_peer source = {};
  bpf_memcpy(source.address, ip6h->saddr.s6_addr, sizeof(source.address));
  source.port = tcp->dest;
  if (tcp->rst || bpf_map_lookup_elem(&ct_adv_sources, &source) == NULL ||
      containerAuthorizeTCPFlow(&reverse) == false)
  {
#if PRODIGY_DEBUG
    setCheckpoint("inboundFlowMissing");
#endif
    return false;
  }
  return true;
}
