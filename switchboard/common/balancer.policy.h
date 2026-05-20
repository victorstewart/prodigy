#pragma once

#include <linux/in.h>

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

__attribute__((__always_inline__))
static inline bool switchboardBalancerPassesIPv6ToKernel(__u8 nextHeader)
{
   // Host-owned IPv6 addresses need ICMPv6 for neighbor discovery, router
   // control, and path-MTU signaling. Cross-machine Switchboard overlay packets
   // must also reach the TC host-ingress program for decapsulation. The balancer
   // only owns native TCP/UDP service ingress.
   return nextHeader == IPPROTO_ICMPV6 || nextHeader == IPPROTO_IPIP || nextHeader == IPPROTO_IPV6;
}
