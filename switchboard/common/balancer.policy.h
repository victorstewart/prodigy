#pragma once

#include <linux/in.h>

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

__attribute__((__always_inline__))
static inline bool switchboardBalancerPassesIPv6ToKernel(__u8 nextHeader)
{
   // Host-owned IPv6 addresses need ICMPv6 for neighbor discovery, router
   // control, and path-MTU signaling. The balancer only owns TCP/UDP service
   // ingress, so kernel-handled ICMPv6 must continue through untouched.
   return nextHeader == IPPROTO_ICMPV6;
}
