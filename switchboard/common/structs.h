#pragma once

#include <linux/if_ether.h>
#include <linux/types.h>

enum
{
   SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV4 = 4,
   SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6 = 6,
};

struct portal_definition {
   union {
      __be32 addr4;
      __be32 addr6[4];
   };
   __u16 port;
   __u8 proto;
};

struct portal_meta {
   __u32 flags;
   __u32 slot;
};

struct container_id {
   __u8 value[5]; // 1 datacenter byte + 3 machine bytes + 1 container byte
   bool hasID;
};

struct switchboard_whitehole_binding {
   struct container_id container;
   __u64 nonce;
};

struct switchboard_wormhole_target_key {
   __u32 slot;
   __u8 container[5];
};

struct switchboard_wormhole_egress_key {
   __u8 container[5];
   __u16 port;
   __u8 proto;
};

struct switchboard_wormhole_egress_binding {
   union {
      __be32 addr4;
      __be32 addr6[4];
   };
   __u16 port;
   __u8 proto;
   __u8 is_ipv6;
};

struct switchboard_owned_routable_prefix4_key {
   __u32 prefixlen;
   __be32 addr;
};

struct switchboard_owned_routable_prefix6_key {
   __u32 prefixlen;
   __u8 addr[16];
};

struct switchboard_overlay_prefix4_key {
   __u32 prefixlen;
   __be32 addr;
};

struct switchboard_overlay_prefix6_key {
   __u32 prefixlen;
   __u8 addr[16];
};

struct switchboard_overlay_hosted_ingress_route4 {
   __u32 machine_fragment;
};

struct switchboard_overlay_hosted_ingress_route6 {
   __u32 machine_fragment;
};

struct switchboard_overlay_machine_route_key {
   __u32 fragment;
};

struct switchboard_overlay_machine_route {
   __u8 family;
   __u8 use_gateway_mac;
   __u8 next_hop_mac[6];
   __be32 next_hop4;
   __u8 next_hop6[16];
   __be32 source4;
   __u8 source6[16];
};

struct switchboard_overlay_config {
   __u8 container_network_enabled;
   __u8 reserved[3];
};

static inline __be16 switchboardHostToBE16(__u16 host)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
   return (__be16)__builtin_bswap16(host);
#else
   return (__be16)host;
#endif
}

static inline __u32 switchboardNetkitIngressL3Offset(bool has_host_ethernet)
{
   return has_host_ethernet ? (__u32)sizeof(struct ethhdr) : 0u;
}

static inline __u32 switchboardHostIngressOverlayMinimumLinearBytes(__be16 wire_protocol)
{
   const __u32 ipv4_header_bytes = 20u;
   const __u32 ipv6_header_bytes = 40u;

   if (wire_protocol == switchboardHostToBE16(ETH_P_IPV6))
   {
      return (__u32)(sizeof(struct ethhdr) + ipv6_header_bytes + ipv6_header_bytes);
   }

   if (wire_protocol == switchboardHostToBE16(ETH_P_IP))
   {
      return (__u32)(sizeof(struct ethhdr) + ipv4_header_bytes + ipv6_header_bytes);
   }

   return 0u;
}

static inline __be16 switchboardHostIngressEffectiveProtocol(__be16 wire_protocol, __be16 skb_protocol, bool decapped)
{
   if (decapped
      && (skb_protocol == switchboardHostToBE16(ETH_P_IP)
         || skb_protocol == switchboardHostToBE16(ETH_P_IPV6)))
   {
      return skb_protocol;
   }

   return wire_protocol;
}
