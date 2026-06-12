#pragma once

#include <linux/in.h>

#include <switchboard/common/constants.h>

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

__attribute__((__always_inline__)) static inline bool switchboardBalancerPassesIPv6ToKernel(__u8 nextHeader)
{
  // Host-owned IPv6 addresses need ICMPv6 for neighbor discovery, router
  // control, and path-MTU signaling. Cross-machine Switchboard overlay packets
  // must also reach the TC host-ingress program for decapsulation. The balancer
  // only owns native TCP/UDP service ingress.
  return nextHeader == IPPROTO_ICMPV6 || nextHeader == IPPROTO_IPIP || nextHeader == IPPROTO_IPV6;
}

__attribute__((__always_inline__)) static inline bool switchboardQuicV1PacketTypeAllowsHashFallback(__u8 packetType)
{
  return packetType == QUIC_V1_CLIENT_INITIAL;
}

__attribute__((__always_inline__)) static inline bool switchboardQuicV1DestinationCidLengthValid(__u8 cidLength)
{
  return cidLength <= QUIC_V1_MAX_CONNECTION_ID_LEN;
}

__attribute__((__always_inline__)) static inline bool switchboardQuicV1DestinationCidUsesProdigySchema(__u8 cidLength)
{
  return cidLength == QUIC_CID_LEN;
}

__attribute__((__always_inline__)) static inline bool switchboardQuicV1LongHeaderAllowsHashFallback(__u8 packetType, __u8 cidLength)
{
  return switchboardQuicV1PacketTypeAllowsHashFallback(packetType) &&
         switchboardQuicV1DestinationCidLengthValid(cidLength);
}
