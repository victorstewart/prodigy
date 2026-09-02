#pragma once

#include <linux/tcp.h>
#include <linux/udp.h>

#include <switchboard/common/local_container_subnet.h>
#include <switchboard/kernel/flow.h>
#include <switchboard/kernel/l4.ports.h>
#include <switchboard/kernel/maps.h>
#include <switchboard/kernel/wormhole.maps.h>

enum {
  SWITCHBOARD_WORMHOLE_REPLY_DROP = -1,
  SWITCHBOARD_WORMHOLE_REPLY_NONE = 0,
  SWITCHBOARD_WORMHOLE_REPLY_PRIVATE = SWITCHBOARD_WORMHOLE_FLOW_PRIVATE,
  SWITCHBOARD_WORMHOLE_REPLY_PUBLIC = SWITCHBOARD_WORMHOLE_FLOW_PUBLIC,
};

__attribute__((__always_inline__)) static inline bool switchboardWormholeFlowMatches(const struct switchboard_wormhole_flow *state,
                                                                                      const struct switchboard_wormhole_egress_binding *binding,
                                                                                      const __u8 container[5],
                                                                                      __u8 disposition)
{
  return state != NULL && binding != NULL && binding->owner_generation != 0 && container != NULL && state->disposition == disposition &&
         bpf_memcmp(state->container, container, sizeof(state->container)) == 0 &&
         bpf_memcmp(&state->binding, binding, sizeof(*binding)) == 0;
}

__attribute__((__always_inline__)) static inline __u64 switchboardWormholeFlowAtomicTransition(const struct switchboard_wormhole_flow *state)
{
  return __sync_val_compare_and_swap((__u64 *)&state->transition, 0, 0);
}

__attribute__((__always_inline__)) static inline __u64 switchboardWormholeFlowAtomicExpiry(const struct switchboard_wormhole_flow *state)
{
  return __sync_val_compare_and_swap((__u64 *)&state->expiresAtNs, 0, 0);
}

__attribute__((__always_inline__)) static inline bool switchboardExtendWormholeFlow(struct switchboard_wormhole_flow *state,
                                                                                    __u64 expiresAtNs)
{
  __u64 current = switchboardWormholeFlowAtomicExpiry(state);
  if (current >= expiresAtNs)
  {
    return true;
  }
  __u64 observed = __sync_val_compare_and_swap(&state->expiresAtNs, current, expiresAtNs);
  if (observed == current || observed >= expiresAtNs)
  {
    return true;
  }
  current = observed;
  observed = __sync_val_compare_and_swap(&state->expiresAtNs, current, expiresAtNs);
  if (observed == current || observed >= expiresAtNs)
  {
    return true;
  }
  current = observed;
  observed = __sync_val_compare_and_swap(&state->expiresAtNs, current, expiresAtNs);
  if (observed == current || observed >= expiresAtNs)
  {
    return true;
  }
  current = observed;
  observed = __sync_val_compare_and_swap(&state->expiresAtNs, current, expiresAtNs);
  return observed == current || observed >= expiresAtNs;
}

__attribute__((__always_inline__)) static inline bool switchboardShortenWormholeFlow(struct switchboard_wormhole_flow *state,
                                                                                     __u64 expiresAtNs)
{
  __u64 current = switchboardWormholeFlowAtomicExpiry(state);
  if (current <= expiresAtNs)
  {
    return true;
  }
  __u64 observed = __sync_val_compare_and_swap(&state->expiresAtNs, current, expiresAtNs);
  if (observed == current || observed <= expiresAtNs)
  {
    return true;
  }
  current = observed;
  observed = __sync_val_compare_and_swap(&state->expiresAtNs, current, expiresAtNs);
  if (observed == current || observed <= expiresAtNs)
  {
    return true;
  }
  current = observed;
  observed = __sync_val_compare_and_swap(&state->expiresAtNs, current, expiresAtNs);
  if (observed == current || observed <= expiresAtNs)
  {
    return true;
  }
  current = observed;
  observed = __sync_val_compare_and_swap(&state->expiresAtNs, current, expiresAtNs);
  return observed == current || observed <= expiresAtNs;
}

__attribute__((__always_inline__)) static inline bool switchboardRefreshEstablishedWormholeState(struct switchboard_wormhole_flow *state,
                                                                                                  __u64 now,
                                                                                                  __u8 proto,
                                                                                                  bool closing)
{
  __u64 transition = switchboardWormholeFlowAtomicTransition(state);
  __u32 phase = switchboardWormholeFlowTransitionPhase(transition);
  if (phase == SWITCHBOARD_WORMHOLE_FLOW_ESTABLISHED_CLOSING)
  {
    if (proto != IPPROTO_TCP)
    {
      return false;
    }
    (void)switchboardShortenWormholeFlow(state, now + WORMHOLE_FLOW_CLOSE_NS);
    return true;
  }
  if (phase != SWITCHBOARD_WORMHOLE_FLOW_ESTABLISHED)
  {
    return false;
  }

  if (proto == IPPROTO_TCP && closing)
  {
    __u64 closingTransition = switchboardWormholeFlowTransition(SWITCHBOARD_WORMHOLE_FLOW_ESTABLISHED_CLOSING, 0);
    __u64 observed = __sync_val_compare_and_swap(&state->transition, transition, closingTransition);
    if (observed != transition && observed != closingTransition)
    {
      return false;
    }
    (void)switchboardShortenWormholeFlow(state, now + WORMHOLE_FLOW_CLOSE_NS);
    return true;
  }

  (void)switchboardExtendWormholeFlow(state, now + switchboardWormholeFlowLifetimeNs(proto, false));
  transition = switchboardWormholeFlowAtomicTransition(state);
  phase = switchboardWormholeFlowTransitionPhase(transition);
  if (phase == SWITCHBOARD_WORMHOLE_FLOW_ESTABLISHED_CLOSING)
  {
    (void)switchboardShortenWormholeFlow(state, now + WORMHOLE_FLOW_CLOSE_NS);
    return proto == IPPROTO_TCP;
  }
  return phase == SWITCHBOARD_WORMHOLE_FLOW_ESTABLISHED;
}

enum {
  SWITCHBOARD_WORMHOLE_OWNER_ABSENT = 0,
  SWITCHBOARD_WORMHOLE_OWNER_MATCH = 1,
  SWITCHBOARD_WORMHOLE_OWNER_CONFLICT = -1,
};

__attribute__((__always_inline__)) static inline int switchboardRefreshEstablishedWormholeFlow(const struct flow_key *key,
                                                                                                const struct switchboard_wormhole_egress_binding *binding,
                                                                                                const __u8 container[5],
                                                                                                __u8 disposition,
                                                                                                __u8 proto,
                                                                                                bool closing)
{
  struct switchboard_wormhole_flow_key ownerKey = switchboardWormholeFlowMapKey(key, binding->owner_generation);
  struct switchboard_wormhole_flow *state = bpf_map_lookup_elem(&wh_flows, &ownerKey);
  if (state == NULL)
  {
    return SWITCHBOARD_WORMHOLE_OWNER_ABSENT;
  }

  __u64 now = bpf_ktime_get_ns();
  bool matches = switchboardWormholeFlowAtomicExpiry(state) > now &&
                 switchboardWormholeFlowMatches(state, binding, container, disposition) &&
                 switchboardRefreshEstablishedWormholeState(state, now, proto, closing);
  return matches ? SWITCHBOARD_WORMHOLE_OWNER_MATCH : SWITCHBOARD_WORMHOLE_OWNER_CONFLICT;
}

__attribute__((__always_inline__)) static inline bool switchboardClaimPendingWormholeFlow(const struct flow_key *key,
                                                                                           const struct switchboard_wormhole_flow *desired)
{
  struct switchboard_wormhole_flow_key ownerKey = switchboardWormholeFlowMapKey(key, desired->binding.owner_generation);
  struct switchboard_wormhole_flow *state = bpf_map_lookup_elem(&wh_pending, &ownerKey);
  __u64 now = bpf_ktime_get_ns();
  if (state == NULL && bpf_map_update_elem(&wh_pending, &ownerKey, desired, BPF_NOEXIST) == 0)
  {
    return true;
  }
  if (state == NULL)
  {
    state = bpf_map_lookup_elem(&wh_pending, &ownerKey);
    if (state == NULL)
    {
      return false;
    }
  }

  __u32 phase = switchboardWormholeFlowTransitionPhase(switchboardWormholeFlowAtomicTransition(state));
  return switchboardWormholeFlowAtomicExpiry(state) > now &&
         (phase == SWITCHBOARD_WORMHOLE_FLOW_PENDING || phase == SWITCHBOARD_WORMHOLE_FLOW_REVERSE_SEEN) &&
         switchboardWormholeFlowMatches(state, &desired->binding, desired->container, desired->disposition);
}

__attribute__((__always_inline__)) static inline bool switchboardCurrentContainerID(__u8 container[5])
{
  __u32 zero = 0;
  struct local_container_subnet6 *subnet = bpf_map_lookup_elem(&lc_subnet, &zero);
  struct container_network_policy *policy = bpf_map_lookup_elem(&ct_net_policy, &zero);
  if (container == NULL || subnet == NULL || policy == NULL || subnet->dpfx == 0 || policy->containerFragment == 0)
  {
    return false;
  }
  container[0] = subnet->dpfx;
  bpf_memcpy(container + 1, subnet->mpfx, sizeof(subnet->mpfx));
  container[4] = policy->containerFragment;
  return true;
}

__attribute__((__always_inline__)) static inline bool switchboardClaimWormholeFlow(const struct flow_key *key,
                                                                                   const struct switchboard_wormhole_egress_binding *binding,
                                                                                   const __u8 container[5],
                                                                                   __u8 disposition,
                                                                                   __u8 proto)
{
  if (key == NULL || binding == NULL || container == NULL ||
      (disposition != SWITCHBOARD_WORMHOLE_FLOW_PRIVATE && disposition != SWITCHBOARD_WORMHOLE_FLOW_PUBLIC) ||
      binding->owner_generation == 0 || (proto != IPPROTO_TCP && proto != IPPROTO_UDP))
  {
    return false;
  }

  __u64 now = bpf_ktime_get_ns();
  struct switchboard_wormhole_flow desired = {};
  bpf_memcpy(&desired.binding, binding, sizeof(desired.binding));
  bpf_memcpy(desired.container, container, sizeof(desired.container));
  desired.disposition = disposition;
  desired.phase = SWITCHBOARD_WORMHOLE_FLOW_PENDING;
  desired.expiresAtNs = now + switchboardWormholeInitialFlowLifetimeNs(proto);

  int established = switchboardRefreshEstablishedWormholeFlow(key, binding, container, disposition, proto, false);
  if (established != SWITCHBOARD_WORMHOLE_OWNER_ABSENT)
  {
    return established == SWITCHBOARD_WORMHOLE_OWNER_MATCH;
  }
  return switchboardClaimPendingWormholeFlow(key, &desired);
}

__attribute__((__always_inline__)) static inline bool switchboardAuthorizePendingWormholeFlow(const struct flow_key *key,
                                                                                               const struct switchboard_wormhole_egress_binding *binding,
                                                                                               const __u8 container[5],
                                                                                               __u8 disposition)
{
  struct switchboard_wormhole_flow_key ownerKey = switchboardWormholeFlowMapKey(key, binding->owner_generation);
  struct switchboard_wormhole_flow *state = bpf_map_lookup_elem(&wh_pending, &ownerKey);
  if (state == NULL)
  {
    return false;
  }
  __u64 now = bpf_ktime_get_ns();
  __u32 phase = switchboardWormholeFlowTransitionPhase(switchboardWormholeFlowAtomicTransition(state));
  return switchboardWormholeFlowAtomicExpiry(state) > now &&
         (phase == SWITCHBOARD_WORMHOLE_FLOW_PENDING || phase == SWITCHBOARD_WORMHOLE_FLOW_REVERSE_SEEN) &&
         switchboardWormholeFlowMatches(state, binding, container, disposition);
}

enum {
  SWITCHBOARD_WORMHOLE_PROMOTION_NOT_READY = 0,
  SWITCHBOARD_WORMHOLE_PROMOTION_ESTABLISHED = 1,
  SWITCHBOARD_WORMHOLE_PROMOTION_FAILED = -1,
};

__attribute__((__always_inline__)) static inline int switchboardPromoteTCPWormholeFlow(const struct flow_key *key,
                                                                                        const struct switchboard_wormhole_egress_binding *binding,
                                                                                        const __u8 container[5],
                                                                                        __u8 disposition,
                                                                                        __be32 acknowledgedSequence,
                                                                                        bool closing)
{
  struct switchboard_wormhole_flow_key ownerKey = switchboardWormholeFlowMapKey(key, binding->owner_generation);
  struct switchboard_wormhole_flow *pending = bpf_map_lookup_elem(&wh_pending, &ownerKey);
  if (pending == NULL)
  {
    return SWITCHBOARD_WORMHOLE_PROMOTION_NOT_READY;
  }

  __u64 now = bpf_ktime_get_ns();
  struct switchboard_wormhole_flow desired = {};
  __u64 transition = switchboardWormholeFlowAtomicTransition(pending);
  bool valid = switchboardWormholeFlowTransitionPhase(transition) == SWITCHBOARD_WORMHOLE_FLOW_REVERSE_SEEN &&
               switchboardWormholeFlowTransitionExpectedAck(transition) == acknowledgedSequence &&
               switchboardWormholeFlowAtomicExpiry(pending) > now &&
               switchboardWormholeFlowMatches(pending, binding, container, disposition);
  if (valid)
  {
    desired.binding = pending->binding;
    desired.container[0] = pending->container[0];
    desired.container[1] = pending->container[1];
    desired.container[2] = pending->container[2];
    desired.container[3] = pending->container[3];
    desired.container[4] = pending->container[4];
    desired.disposition = pending->disposition;
    desired.phase = closing ? SWITCHBOARD_WORMHOLE_FLOW_ESTABLISHED_CLOSING
                            : SWITCHBOARD_WORMHOLE_FLOW_ESTABLISHED;
    desired.expiresAtNs = now + switchboardWormholeFlowLifetimeNs(IPPROTO_TCP, closing);
  }
  if (valid == false)
  {
    return SWITCHBOARD_WORMHOLE_PROMOTION_NOT_READY;
  }

  if (bpf_map_update_elem(&wh_flows, &ownerKey, &desired, BPF_NOEXIST) != 0 &&
      switchboardRefreshEstablishedWormholeFlow(key,
                                                &desired.binding,
                                                desired.container,
                                                desired.disposition,
                                                IPPROTO_TCP,
                                                closing) != SWITCHBOARD_WORMHOLE_OWNER_MATCH)
  {
    return SWITCHBOARD_WORMHOLE_PROMOTION_FAILED;
  }
  (void)bpf_map_delete_elem(&wh_pending, &ownerKey);
  return SWITCHBOARD_WORMHOLE_PROMOTION_ESTABLISHED;
}

__attribute__((__always_inline__)) static inline bool switchboardAuthorizeWormholeIngress(const struct flow_key *key,
                                                                                           const struct switchboard_wormhole_egress_binding *binding,
                                                                                           const __u8 container[5],
                                                                                           __u8 disposition,
                                                                                           __u8 proto,
                                                                                           bool closing,
                                                                                           bool acknowledgesSyn,
                                                                                           __be32 acknowledgedSequence)
{
  int established = switchboardRefreshEstablishedWormholeFlow(key, binding, container, disposition, proto, closing);
  if (established != SWITCHBOARD_WORMHOLE_OWNER_ABSENT)
  {
    return established == SWITCHBOARD_WORMHOLE_OWNER_MATCH;
  }
  if (proto == IPPROTO_TCP && acknowledgesSyn)
  {
    int promotion = switchboardPromoteTCPWormholeFlow(key,
                                                      binding,
                                                      container,
                                                      disposition,
                                                      acknowledgedSequence,
                                                      closing);
    return promotion == SWITCHBOARD_WORMHOLE_PROMOTION_ESTABLISHED;
  }
  return switchboardAuthorizePendingWormholeFlow(key, binding, container, disposition);
}

__attribute__((__always_inline__)) static inline bool switchboardWormholeExposureKeyIPv6(const __u8 address[16],
                                                                                         __be16 port,
                                                                                         __u8 proto,
                                                                                         struct switchboard_wormhole_egress_key *key)
{
  if (key == NULL || port == 0 || (proto != IPPROTO_TCP && proto != IPPROTO_UDP) ||
      switchboardContainerNetworkPrefixMatchesIPv6(address) == false)
  {
    return false;
  }

  bpf_memset(key, 0, sizeof(*key));
  bpf_memcpy(key->container, address + 11, sizeof(key->container));
  key->port = port;
  key->proto = proto;
  return true;
}

__attribute__((__always_inline__)) static inline bool switchboardWormholeFlowKeyFromTranslatedIngress(const struct flow_key *inbound,
                                                                                                       const struct container_id *containerID,
                                                                                                       __be16 targetPort,
                                                                                                       struct flow_key *reply)
{
  if (inbound == NULL || containerID == NULL || containerID->hasID == false || reply == NULL || targetPort == 0)
  {
    return false;
  }

  struct flow_key translated = {};
  bpf_memcpy(translated.srcv6, inbound->srcv6, sizeof(translated.srcv6));
  if (switchboardBuildContainerNetworkIPv6((__u8 *)translated.dstv6, containerID) == false)
  {
    return false;
  }
  translated.port16[0] = inbound->port16[0];
  translated.port16[1] = targetPort;
  translated.proto = inbound->proto;
  reverse_flow_key(&translated, reply);
  return true;
}

__attribute__((noinline)) static bool switchboardLearnPublicWormholeFlowIPv6(const struct packet_description *packet,
                                                                                             const struct container_id *containerID,
                                                                                             __be16 targetPort,
                                                                                             const struct portal_definition *portal)
{
  if (packet == NULL || portal == NULL ||
      portal->port != packet->flow.port16[1] || portal->proto != packet->flow.proto ||
      bpf_memcmp(portal->addr6, packet->flow.dstv6, sizeof(portal->addr6)) != 0)
  {
    return false;
  }

  struct switchboard_wormhole_egress_key exposed = {};
  bpf_memcpy(exposed.container, containerID->value, sizeof(exposed.container));
  exposed.port = targetPort;
  exposed.proto = packet->flow.proto;
  struct switchboard_wormhole_egress_binding *binding = bpf_map_lookup_elem(&wh_egress, &exposed);
  if (binding == NULL || binding->owner_generation == 0 || binding->is_ipv6 == 0 ||
      binding->port != portal->port || binding->proto != portal->proto ||
      bpf_memcmp(binding->addr6, portal->addr6, sizeof(binding->addr6)) != 0)
  {
    return false;
  }

  struct flow_key reply = {};
  if (switchboardWormholeFlowKeyFromTranslatedIngress(&packet->flow, containerID, targetPort, &reply) == false)
  {
    return false;
  }

  return switchboardClaimWormholeFlow(&reply,
                                      binding,
                                      containerID->value,
                                      SWITCHBOARD_WORMHOLE_FLOW_PUBLIC,
                                      packet->flow.proto);
}

__attribute__((noinline)) static bool switchboardLearnPublicWormholeFlowIPv4(const struct packet_description *packet,
                                                                                             const struct container_id *containerID,
                                                                                             __be16 targetPort,
                                                                                             const struct portal_definition *portal)
{
  if (packet == NULL || containerID == NULL || containerID->hasID == false || portal == NULL || targetPort == 0 ||
      portal->addr4 != packet->flow.dst || portal->port != packet->flow.port16[1] ||
      portal->proto != packet->flow.proto)
  {
    return false;
  }

  struct switchboard_wormhole_egress4_key exposed = {};
  exposed.addr = portal->addr4;
  exposed.port = targetPort;
  exposed.proto = packet->flow.proto;
  struct switchboard_wormhole_egress_binding *binding = bpf_map_lookup_elem(&wh_egress4, &exposed);
  if (binding == NULL || binding->owner_generation == 0 || binding->is_ipv6 != 0 ||
      binding->addr4 != portal->addr4 || binding->port != portal->port || binding->proto != portal->proto)
  {
    return false;
  }

  struct flow_key translated = {};
  translated.src = packet->flow.src;
  translated.dst = packet->flow.dst;
  translated.port16[0] = packet->flow.port16[0];
  translated.port16[1] = targetPort;
  translated.proto = packet->flow.proto;
  struct flow_key reply = {};
  reverse_flow_key(&translated, &reply);

  return switchboardClaimWormholeFlow(&reply,
                                      binding,
                                      containerID->value,
                                      SWITCHBOARD_WORMHOLE_FLOW_PUBLIC,
                                      packet->flow.proto);
}

__attribute__((noinline)) static bool switchboardClassifyWormholeIngressIPv4(struct iphdr *iph,
                                                                              void *data_end,
                                                                              bool publicIngress)
{
  if (switchboard_unfragmented_ipv4(iph, data_end) == false)
  {
    return false;
  }
  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
  {
    return publicIngress == false;
  }

  __be16 sourcePort = 0;
  __be16 targetPort = 0;
  bool closing = false;
  bool reset = false;
  bool acknowledgesSyn = false;
  __be32 acknowledgedSequence = 0;
  if (iph->protocol == IPPROTO_TCP)
  {
    struct tcphdr *tcp = (struct tcphdr *)(iph + 1);
    if ((void *)(tcp + 1) > data_end)
    {
      return false;
    }
    sourcePort = tcp->source;
    targetPort = tcp->dest;
    closing = tcp->fin;
    reset = tcp->rst;
    acknowledgesSyn = tcp->ack && tcp->syn == 0 && tcp->rst == 0;
    acknowledgedSequence = tcp->ack_seq;
  }
  else
  {
    struct udphdr *udp = (struct udphdr *)(iph + 1);
    if ((void *)(udp + 1) > data_end)
    {
      return false;
    }
    sourcePort = udp->source;
    targetPort = udp->dest;
  }

  struct switchboard_wormhole_egress4_key exposed = {};
  exposed.addr = iph->daddr;
  exposed.port = targetPort;
  exposed.proto = iph->protocol;
  struct switchboard_wormhole_egress_binding *configured = bpf_map_lookup_elem(&wh_egress4, &exposed);
  if (configured == NULL)
  {
    return publicIngress == false;
  }

  struct flow_key inbound = {};
  inbound.src = iph->saddr;
  inbound.dst = iph->daddr;
  inbound.port16[0] = sourcePort;
  inbound.port16[1] = targetPort;
  inbound.proto = iph->protocol;
  struct flow_key reply = {};
  reverse_flow_key(&inbound, &reply);
  __u8 container[5] = {};
  if (switchboardCurrentContainerID(container) == false)
  {
    return false;
  }

  if (publicIngress)
  {
    return switchboardAuthorizeWormholeIngress(&reply,
                                               configured,
                                               container,
                                               SWITCHBOARD_WORMHOLE_FLOW_PUBLIC,
                                               iph->protocol,
                                               closing || reset,
                                               acknowledgesSyn,
                                               acknowledgedSequence);
  }

  if (iph->protocol == IPPROTO_TCP && acknowledgesSyn)
  {
    return switchboardAuthorizeWormholeIngress(&reply,
                                               configured,
                                               container,
                                               SWITCHBOARD_WORMHOLE_FLOW_PRIVATE,
                                               iph->protocol,
                                               closing || reset,
                                               acknowledgesSyn,
                                               acknowledgedSequence);
  }
  return switchboardClaimWormholeFlow(&reply,
                                      configured,
                                      container,
                                      SWITCHBOARD_WORMHOLE_FLOW_PRIVATE,
                                      iph->protocol);
}

__attribute__((noinline)) static bool switchboardClassifyWormholeIngressIPv6(struct ipv6hdr *ip6h,
                                                                              void *data_end,
                                                                              bool publicIngress)
{
  if (ip6h == NULL || (void *)(ip6h + 1) > data_end)
  {
    return false;
  }
  if (ip6h->nexthdr != IPPROTO_TCP && ip6h->nexthdr != IPPROTO_UDP)
  {
    return publicIngress == false;
  }

  __be16 sourcePort = 0;
  __be16 targetPort = 0;
  bool closing = false;
  bool reset = false;
  bool acknowledgesSyn = false;
  __be32 acknowledgedSequence = 0;
  if (ip6h->nexthdr == IPPROTO_TCP)
  {
    struct tcphdr *tcp = (struct tcphdr *)(ip6h + 1);
    if ((void *)(tcp + 1) > data_end)
    {
      return false;
    }
    sourcePort = tcp->source;
    targetPort = tcp->dest;
    closing = tcp->fin;
    reset = tcp->rst;
    acknowledgesSyn = tcp->ack && tcp->syn == 0 && tcp->rst == 0;
    acknowledgedSequence = tcp->ack_seq;
  }
  else
  {
    struct udphdr *udp = (struct udphdr *)(ip6h + 1);
    if ((void *)(udp + 1) > data_end)
    {
      return false;
    }
    sourcePort = udp->source;
    targetPort = udp->dest;
  }

  struct switchboard_wormhole_egress_key exposed = {};
  if (switchboardWormholeExposureKeyIPv6(ip6h->daddr.s6_addr, targetPort, ip6h->nexthdr, &exposed) == false)
  {
    return publicIngress == false;
  }
  struct switchboard_wormhole_egress_binding *configured = bpf_map_lookup_elem(&wh_egress, &exposed);
  if (configured == NULL)
  {
    return publicIngress == false;
  }

  struct flow_key inbound = {};
  bpf_memcpy(inbound.srcv6, ip6h->saddr.s6_addr32, sizeof(inbound.srcv6));
  bpf_memcpy(inbound.dstv6, ip6h->daddr.s6_addr32, sizeof(inbound.dstv6));
  inbound.port16[0] = sourcePort;
  inbound.port16[1] = targetPort;
  inbound.proto = ip6h->nexthdr;
  struct flow_key reply = {};
  reverse_flow_key(&inbound, &reply);
  const __u8 *container = ip6h->daddr.s6_addr + 11;

  if (publicIngress)
  {
    return switchboardAuthorizeWormholeIngress(&reply,
                                               configured,
                                               container,
                                               SWITCHBOARD_WORMHOLE_FLOW_PUBLIC,
                                               ip6h->nexthdr,
                                               closing || reset,
                                               acknowledgesSyn,
                                               acknowledgedSequence);
  }

  if (ip6h->nexthdr == IPPROTO_TCP && acknowledgesSyn)
  {
    return switchboardAuthorizeWormholeIngress(&reply,
                                               configured,
                                               container,
                                               SWITCHBOARD_WORMHOLE_FLOW_PRIVATE,
                                               ip6h->nexthdr,
                                               closing || reset,
                                               acknowledgesSyn,
                                               acknowledgedSequence);
  }
  return switchboardClaimWormholeFlow(&reply,
                                      configured,
                                      container,
                                      SWITCHBOARD_WORMHOLE_FLOW_PRIVATE,
                                      ip6h->nexthdr);
}

__attribute__((__always_inline__)) static inline int switchboardResolveWormholeReplyOwnership(struct switchboard_wormhole_flow *established,
                                                                                               struct switchboard_wormhole_flow *pending,
                                                                                               const struct switchboard_wormhole_egress_binding *configured,
                                                                                               const __u8 container[5],
                                                                                               __u8 proto,
                                                                                               bool closing,
                                                                                               bool tcpSynAck,
                                                                                               __be32 expectedAck,
                                                                                               struct switchboard_wormhole_egress_binding *binding)
{
  __u64 now = bpf_ktime_get_ns();
  if (established != NULL)
  {
    bool valid = proto == IPPROTO_TCP && configured != NULL &&
                 switchboardWormholeFlowAtomicExpiry(established) > now &&
                 (established->disposition == SWITCHBOARD_WORMHOLE_FLOW_PRIVATE ||
                  established->disposition == SWITCHBOARD_WORMHOLE_FLOW_PUBLIC) &&
                 switchboardWormholeFlowMatches(established, configured, container, established->disposition) &&
                 switchboardRefreshEstablishedWormholeState(established, now, proto, closing);
    int disposition = valid ? established->disposition : SWITCHBOARD_WORMHOLE_REPLY_DROP;
    if (valid)
    {
      if (disposition == SWITCHBOARD_WORMHOLE_FLOW_PUBLIC)
      {
        *binding = established->binding;
      }
    }
    return disposition;
  }

  if (pending == NULL)
  {
    return configured == NULL ? SWITCHBOARD_WORMHOLE_REPLY_NONE : SWITCHBOARD_WORMHOLE_REPLY_DROP;
  }

  __u64 transition = switchboardWormholeFlowAtomicTransition(pending);
  __u32 phase = switchboardWormholeFlowTransitionPhase(transition);
  bool valid = configured != NULL && switchboardWormholeFlowAtomicExpiry(pending) > now &&
               (phase == SWITCHBOARD_WORMHOLE_FLOW_PENDING || phase == SWITCHBOARD_WORMHOLE_FLOW_REVERSE_SEEN) &&
               (pending->disposition == SWITCHBOARD_WORMHOLE_FLOW_PRIVATE ||
                pending->disposition == SWITCHBOARD_WORMHOLE_FLOW_PUBLIC) &&
               switchboardWormholeFlowMatches(pending, configured, container, pending->disposition);
  int disposition = valid ? pending->disposition : SWITCHBOARD_WORMHOLE_REPLY_DROP;
  if (valid)
  {
    if (proto == IPPROTO_UDP)
    {
      (void)switchboardExtendWormholeFlow(pending, now + WORMHOLE_FLOW_UDP_IDLE_NS);
      __u64 pendingTransition = switchboardWormholeFlowTransition(SWITCHBOARD_WORMHOLE_FLOW_PENDING, 0);
      __u64 reverseTransition = switchboardWormholeFlowTransition(SWITCHBOARD_WORMHOLE_FLOW_REVERSE_SEEN, 0);
      __u64 observed = __sync_val_compare_and_swap(&pending->transition, pendingTransition, reverseTransition);
      valid = observed == pendingTransition || observed == reverseTransition;
    }
    else if (tcpSynAck)
    {
      (void)switchboardExtendWormholeFlow(pending, now + WORMHOLE_FLOW_EMBRYONIC_NS);
      __u64 pendingTransition = switchboardWormholeFlowTransition(SWITCHBOARD_WORMHOLE_FLOW_PENDING, 0);
      __u64 reverseTransition = switchboardWormholeFlowTransition(SWITCHBOARD_WORMHOLE_FLOW_REVERSE_SEEN, expectedAck);
      __u64 observed = __sync_val_compare_and_swap(&pending->transition, pendingTransition, reverseTransition);
      valid = observed == pendingTransition || observed == reverseTransition;
    }
    else if (closing)
    {
      (void)switchboardExtendWormholeFlow(pending, now + WORMHOLE_FLOW_CLOSE_NS);
    }
    if (valid && disposition == SWITCHBOARD_WORMHOLE_FLOW_PUBLIC)
    {
      *binding = pending->binding;
    }
  }
  return valid ? disposition : SWITCHBOARD_WORMHOLE_REPLY_DROP;
}

__attribute__((__always_inline__)) static inline bool switchboardTCPSynAckExpectedAck(const struct tcphdr *tcp,
                                                                                       void *data_end,
                                                                                       __u32 transportBytes,
                                                                                       __be32 *expectedAck)
{
  if (tcp == NULL || expectedAck == NULL || tcp->syn == 0 || tcp->ack == 0 || tcp->rst || tcp->doff < 5)
  {
    return false;
  }
  __u32 headerBytes = (__u32)tcp->doff * 4u;
  if ((__u8 *)tcp + headerBytes > (__u8 *)data_end || transportBytes < headerBytes)
  {
    return false;
  }
  *expectedAck = bpf_htonl(bpf_ntohl(tcp->seq) + 1u + (transportBytes - headerBytes) + (tcp->fin ? 1u : 0u));
  return true;
}

__attribute__((__always_inline__)) static inline int switchboardWormholeReplyDispositionIPv6(struct ipv6hdr *ip6h,
                                                                                             void *data_end,
                                                                                             struct switchboard_wormhole_egress_binding *binding)
{
  if (ip6h == NULL || binding == NULL || (void *)(ip6h + 1) > data_end ||
      (ip6h->nexthdr != IPPROTO_TCP && ip6h->nexthdr != IPPROTO_UDP))
  {
    return SWITCHBOARD_WORMHOLE_REPLY_NONE;
  }

  __be16 sourcePort = 0;
  __be16 destPort = 0;
  bool closing = false;
  bool reset = false;
  bool tcpSynAck = false;
  __be32 expectedAck = 0;
  if (ip6h->nexthdr == IPPROTO_TCP)
  {
    struct tcphdr *tcp = (struct tcphdr *)(ip6h + 1);
    if ((void *)(tcp + 1) > data_end)
    {
      return SWITCHBOARD_WORMHOLE_REPLY_DROP;
    }
    sourcePort = tcp->source;
    destPort = tcp->dest;
    closing = tcp->fin;
    reset = tcp->rst;
    tcpSynAck = switchboardTCPSynAckExpectedAck(tcp,
                                                data_end,
                                                (__u32)bpf_ntohs(ip6h->payload_len),
                                                &expectedAck);
  }
  else
  {
    struct udphdr *udp = (struct udphdr *)(ip6h + 1);
    if ((void *)(udp + 1) > data_end)
    {
      return SWITCHBOARD_WORMHOLE_REPLY_DROP;
    }
    sourcePort = udp->source;
    destPort = udp->dest;
  }

  struct switchboard_wormhole_egress_key exposed = {};
  __u8 container[5] = {};
  bool canonicalContainerSource = switchboardWormholeExposureKeyIPv6(ip6h->saddr.s6_addr,
                                                                      sourcePort,
                                                                      ip6h->nexthdr,
                                                                      &exposed);
  if (canonicalContainerSource)
  {
    bpf_memcpy(container, exposed.container, sizeof(container));
  }
  else
  {
    if (switchboardCurrentContainerID(container) == false)
    {
      return SWITCHBOARD_WORMHOLE_REPLY_NONE;
    }
    bpf_memcpy(exposed.container, container, sizeof(exposed.container));
    exposed.port = sourcePort;
    exposed.proto = ip6h->nexthdr;
  }
  struct switchboard_wormhole_egress_binding *configured = bpf_map_lookup_elem(&wh_egress, &exposed);
  if (configured == NULL)
  {
    return SWITCHBOARD_WORMHOLE_REPLY_NONE;
  }
  if (configured->owner_generation == 0 || configured->proto != ip6h->nexthdr)
  {
    return SWITCHBOARD_WORMHOLE_REPLY_DROP;
  }
  if (canonicalContainerSource == false &&
      (configured->is_ipv6 == 0 || bpf_memcmp(configured->addr6, ip6h->saddr.s6_addr, sizeof(configured->addr6)) != 0))
  {
    return SWITCHBOARD_WORMHOLE_REPLY_NONE;
  }

  struct flow_key reply = {};
  if (canonicalContainerSource)
  {
    bpf_memcpy(reply.srcv6, ip6h->saddr.s6_addr32, sizeof(reply.srcv6));
  }
  else
  {
    struct container_id containerID = {};
    containerID.hasID = true;
    bpf_memcpy(containerID.value, container, sizeof(containerID.value));
    if (switchboardBuildContainerNetworkIPv6((__u8 *)reply.srcv6, &containerID) == false)
    {
      return SWITCHBOARD_WORMHOLE_REPLY_DROP;
    }
  }
  bpf_memcpy(reply.dstv6, ip6h->daddr.s6_addr32, sizeof(reply.dstv6));
  reply.port16[0] = sourcePort;
  reply.port16[1] = destPort;
  reply.proto = ip6h->nexthdr;

  struct switchboard_wormhole_flow_key ownerKey = switchboardWormholeFlowMapKey(&reply, configured->owner_generation);
  struct switchboard_wormhole_flow *established = bpf_map_lookup_elem(&wh_flows, &ownerKey);
  struct switchboard_wormhole_flow *pending = established == NULL ? bpf_map_lookup_elem(&wh_pending, &ownerKey) : NULL;
  // The portal address family constrains public source rewriting, not private IPv6 mesh ownership.
  struct switchboard_wormhole_flow *owner = established == NULL ? pending : established;
  if (configured->is_ipv6 == 0 && owner != NULL && owner->disposition == SWITCHBOARD_WORMHOLE_FLOW_PUBLIC)
  {
    return SWITCHBOARD_WORMHOLE_REPLY_DROP;
  }
  return switchboardResolveWormholeReplyOwnership(established,
                                                  pending,
                                                  configured,
                                                  container,
                                                  ip6h->nexthdr,
                                                  closing || reset,
                                                  tcpSynAck,
                                                  expectedAck,
                                                  binding);
}

__attribute__((__always_inline__)) static inline int switchboardWormholeReplyDispositionIPv4(struct iphdr *iph,
                                                                                             void *data_end,
                                                                                             struct switchboard_wormhole_egress_binding *binding)
{
  if (binding == NULL)
  {
    return SWITCHBOARD_WORMHOLE_REPLY_NONE;
  }
  if (switchboard_unfragmented_ipv4(iph, data_end) == false)
  {
    return SWITCHBOARD_WORMHOLE_REPLY_DROP;
  }
  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
  {
    return SWITCHBOARD_WORMHOLE_REPLY_NONE;
  }

  __be16 sourcePort = 0;
  __be16 destPort = 0;
  bool closing = false;
  bool reset = false;
  bool tcpSynAck = false;
  __be32 expectedAck = 0;
  if (iph->protocol == IPPROTO_TCP)
  {
    struct tcphdr *tcp = (struct tcphdr *)(iph + 1);
    if ((void *)(tcp + 1) > data_end)
    {
      return SWITCHBOARD_WORMHOLE_REPLY_DROP;
    }
    sourcePort = tcp->source;
    destPort = tcp->dest;
    closing = tcp->fin;
    reset = tcp->rst;
    __u32 totalBytes = (__u32)bpf_ntohs(iph->tot_len);
    tcpSynAck = totalBytes >= sizeof(struct iphdr) &&
                switchboardTCPSynAckExpectedAck(tcp,
                                                data_end,
                                                totalBytes - sizeof(struct iphdr),
                                                &expectedAck);
  }
  else
  {
    struct udphdr *udp = (struct udphdr *)(iph + 1);
    if ((void *)(udp + 1) > data_end)
    {
      return SWITCHBOARD_WORMHOLE_REPLY_DROP;
    }
    sourcePort = udp->source;
    destPort = udp->dest;
  }

  struct flow_key reply = {};
  reply.src = iph->saddr;
  reply.dst = iph->daddr;
  reply.port16[0] = sourcePort;
  reply.port16[1] = destPort;
  reply.proto = iph->protocol;
  struct switchboard_wormhole_egress4_key exposed = {};
  exposed.addr = iph->saddr;
  exposed.port = sourcePort;
  exposed.proto = iph->protocol;
  struct switchboard_wormhole_egress_binding *configured = bpf_map_lookup_elem(&wh_egress4, &exposed);
  if (configured == NULL)
  {
    return SWITCHBOARD_WORMHOLE_REPLY_NONE;
  }
  if (configured->owner_generation == 0 || configured->is_ipv6 != 0 || configured->proto != iph->protocol)
  {
    return SWITCHBOARD_WORMHOLE_REPLY_DROP;
  }
  struct switchboard_wormhole_flow_key ownerKey = switchboardWormholeFlowMapKey(&reply, configured->owner_generation);
  struct switchboard_wormhole_flow *established = bpf_map_lookup_elem(&wh_flows, &ownerKey);
  struct switchboard_wormhole_flow *pending = established == NULL ? bpf_map_lookup_elem(&wh_pending, &ownerKey) : NULL;
  __u8 container[5] = {};
  if (switchboardCurrentContainerID(container) == false)
  {
    return SWITCHBOARD_WORMHOLE_REPLY_DROP;
  }
  return switchboardResolveWormholeReplyOwnership(established,
                                                  pending,
                                                  configured,
                                                  container,
                                                  iph->protocol,
                                                  closing || reset,
                                                  tcpSynAck,
                                                  expectedAck,
                                                  binding);
}
