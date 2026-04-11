#pragma once

#include <switchboard/kernel/overlay.maps.h>
#include <switchboard/common/local_container_subnet.h>
#include <ebpf/kernel/services.h>

__attribute__((__always_inline__))
static inline bool containsContainerNetworkIPv6(const __u32 dstv6[4])
{
   return switchboardContainerNetworkPrefixMatchesIPv6((const __u8 *)dstv6);
}

__attribute__((__always_inline__))
static inline bool overlayRoutablePrefixesContainIPv4(__be32 dest_ip)
{
   struct switchboard_overlay_prefix4_key key = {
      .prefixlen = 32,
      .addr = dest_ip,
   };

   return bpf_map_lookup_elem(&overlay_routable_prefixes4, &key) != NULL;
}

__attribute__((__always_inline__))
static inline bool overlayRoutablePrefixesContainIPv6(const __u32 dstv6[4])
{
   struct switchboard_overlay_prefix6_key key = {
      .prefixlen = 128,
   };
   bpf_memcpy(key.addr, dstv6, sizeof(key.addr));

   return bpf_map_lookup_elem(&overlay_routable_prefixes6, &key) != NULL;
}

__attribute__((__always_inline__))
static inline bool lookupHostedIngressMachineFragmentIPv4(__be32 dst, __u32 *machine_fragment)
{
   if (machine_fragment == NULL)
   {
      return false;
   }

   struct switchboard_overlay_prefix4_key key = {
      .prefixlen = 32,
      .addr = dst,
   };

   struct switchboard_overlay_hosted_ingress_route4 *route = bpf_map_lookup_elem(&overlay_hosted_ingress_routes4, &key);
   if (route == NULL || route->machine_fragment == 0)
   {
      return false;
   }

   *machine_fragment = route->machine_fragment;
   return true;
}

__attribute__((__always_inline__))
static inline bool lookupHostedIngressMachineFragmentIPv6(const __u32 dstv6[4], __u32 *machine_fragment)
{
   if (machine_fragment == NULL)
   {
      return false;
   }

   struct switchboard_overlay_prefix6_key key = {
      .prefixlen = 128,
   };
   bpf_memcpy(key.addr, dstv6, sizeof(key.addr));

   struct switchboard_overlay_hosted_ingress_route6 *route = bpf_map_lookup_elem(&overlay_hosted_ingress_routes6, &key);
   if (route == NULL || route->machine_fragment == 0)
   {
      return false;
   }

   *machine_fragment = route->machine_fragment;
   return true;
}

__attribute__((__always_inline__))
static inline bool overlayContainerNetworkEnabled(void)
{
   __u32 zeroidx = 0;
   struct switchboard_overlay_config *config = bpf_map_lookup_elem(&overlay_config_map, &zeroidx);
   if (config == NULL)
   {
      return false;
   }

   return (config->container_network_enabled != 0);
}

__attribute__((__always_inline__))
static inline bool redirectContainerFragment(__u8 container_fragment, bool is_ingress)
{
   __u32 container_index = container_fragment;

   struct packet *pkt = getPacket();
   if (pkt)
   {
      pkt->containerID.value[4] = container_fragment;
   }

   __u32 *primary_device_idx = bpf_map_lookup_elem(&container_device_map, &container_index);
   if (primary_device_idx == NULL)
   {
      return false;
   }

   logPacketRedirectIfIdx(*primary_device_idx);

   if (is_ingress)
   {
      return (setInstruction(bpf_redirect(*primary_device_idx, 0)) == TC_ACT_REDIRECT);
   }

   return (setInstruction(bpf_redirect(*primary_device_idx, 0)) == TC_ACT_REDIRECT);
}

__attribute__((__always_inline__))
static inline bool setContainerIDFromDistributedIPv4(struct container_id *containerID, __be32 dst, const struct local_container_subnet6 *localcontainersubnet6)
{
   const __u8 *dst_bytes = (const __u8 *)&dst;
   __u8 machine_fragment = dst_bytes[2];
   __u8 container_fragment = dst_bytes[3];

   if (localcontainersubnet6 == NULL || machine_fragment == 0 || container_fragment == 0)
   {
      return false;
   }

   containerID->value[0] = localcontainersubnet6->dpfx;
   containerID->value[1] = localcontainersubnet6->mpfx[0];
   containerID->value[2] = localcontainersubnet6->mpfx[1];
   containerID->value[3] = machine_fragment;
   containerID->value[4] = container_fragment;
   containerID->hasID = true;

   return true;
}

__attribute__((__always_inline__))
static inline bool setContainerIDFromDistributedIPv6(struct container_id *containerID, const __u32 dstv6[4])
{
   const __u8 *bytes = (const __u8 *)dstv6;
   __u8 datacenter_fragment = bytes[11];
   __u8 machine_fragment0 = bytes[12];
   __u8 machine_fragment1 = bytes[13];
   __u8 machine_fragment2 = bytes[14];
   __u8 container_fragment = bytes[15];

   if (datacenter_fragment == 0 || container_fragment == 0)
   {
      return false;
   }

   containerID->value[0] = datacenter_fragment;
   containerID->value[1] = machine_fragment0;
   containerID->value[2] = machine_fragment1;
   containerID->value[3] = machine_fragment2;
   containerID->value[4] = container_fragment;
   containerID->hasID = true;

   return true;
}

__attribute__((__always_inline__))
static inline bool overlayRouteKeyFromIPv4(__be32 dst, struct switchboard_overlay_machine_route_key *key)
{
   if (key == NULL)
   {
      return false;
   }

   const __u8 *dst_bytes = (const __u8 *)&dst;
   if (dst_bytes[2] == 0 || dst_bytes[3] == 0)
   {
      return false;
   }

   key->fragment = dst_bytes[2];
   return true;
}

__attribute__((__always_inline__))
static inline bool overlayRouteKeyFromIPv6(const __u32 dstv6[4], struct switchboard_overlay_machine_route_key *key)
{
   if (key == NULL)
   {
      return false;
   }

   __u32 fragment = 0;
   if (switchboardExtractOverlayMachineFragmentFromIPv6((const __u8 *)dstv6, &fragment) == false)
   {
      return false;
   }

   key->fragment = fragment;
   return true;
}

__attribute__((__always_inline__))
static inline struct switchboard_overlay_machine_route *lookupOverlayMachineRouteFull(const struct switchboard_overlay_machine_route_key *key)
{
   if (key == NULL)
   {
      return NULL;
   }

   return bpf_map_lookup_elem(&overlay_machine_routes_full, key);
}

__attribute__((__always_inline__))
static inline struct switchboard_overlay_machine_route *lookupOverlayMachineRouteLow8(const struct switchboard_overlay_machine_route_key *key)
{
   if (key == NULL)
   {
      return NULL;
   }

   return bpf_map_lookup_elem(&overlay_machine_routes_low8, key);
}

__attribute__((__always_inline__))
static inline struct switchboard_overlay_machine_route *lookupOverlayMachineRouteByFragment(__u32 machine_fragment)
{
   if (machine_fragment == 0)
   {
      return NULL;
   }

   struct switchboard_overlay_machine_route_key key = {
      .fragment = machine_fragment,
   };

   struct switchboard_overlay_machine_route *route = lookupOverlayMachineRouteFull(&key);
   if (route != NULL)
   {
      return route;
   }

   key.fragment = (machine_fragment & 0xFFu);
   return lookupOverlayMachineRouteLow8(&key);
}
