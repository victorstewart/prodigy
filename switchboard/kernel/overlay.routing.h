#pragma once

#include <switchboard/kernel/overlay.maps.h>
#include <switchboard/common/local_container_subnet.h>
#include <ebpf/kernel/services.h>

__attribute__((__always_inline__)) static inline bool containsContainerNetworkIPv6(const __u32 dstv6[4])
{
  return switchboardContainerNetworkPrefixMatchesIPv6((const __u8 *)dstv6);
}

__attribute__((__always_inline__)) static inline bool overlayRoutablePrefixesContainIPv4(__be32 dest_ip)
{
  struct switchboard_overlay_prefix4_key key = {
      .prefixlen = 32,
      .addr = dest_ip,
  };

  return bpf_map_lookup_elem(&ovl_pfx4, &key) != NULL;
}

__attribute__((__always_inline__)) static inline bool overlayRoutablePrefixesContainIPv6(const __u32 dstv6[4])
{
  struct switchboard_overlay_prefix6_key key = {
      .prefixlen = 128,
  };
  bpf_memcpy(key.addr, dstv6, sizeof(key.addr));

  return bpf_map_lookup_elem(&ovl_pfx6, &key) != NULL;
}

__attribute__((__always_inline__)) static inline bool lookupHostedIngressMachineFragmentIPv4(__be32 dst, __u32 *machine_fragment)
{
  if (machine_fragment == NULL)
  {
    return false;
  }

  struct switchboard_overlay_prefix4_key key = {
      .prefixlen = 32,
      .addr = dst,
  };

  struct switchboard_overlay_hosted_ingress_route4 *route = bpf_map_lookup_elem(&ovl_host4, &key);
  if (route == NULL || route->machine_fragment == 0)
  {
    return false;
  }

  *machine_fragment = route->machine_fragment;
  return true;
}

__attribute__((__always_inline__)) static inline bool lookupHostedIngressMachineFragmentIPv6(const __u32 dstv6[4], __u32 *machine_fragment)
{
  if (machine_fragment == NULL)
  {
    return false;
  }

  struct switchboard_overlay_prefix6_key key = {
      .prefixlen = 128,
  };
  bpf_memcpy(key.addr, dstv6, sizeof(key.addr));

  struct switchboard_overlay_hosted_ingress_route6 *route = bpf_map_lookup_elem(&ovl_host6, &key);
  if (route == NULL || route->machine_fragment == 0)
  {
    return false;
  }

  *machine_fragment = route->machine_fragment;
  return true;
}

__attribute__((__always_inline__)) static inline bool overlayContainerNetworkEnabled(void)
{
  __u32 zeroidx = 0;
  struct switchboard_overlay_config *config = bpf_map_lookup_elem(&ovl_config, &zeroidx);
  if (config == NULL)
  {
    return false;
  }

  return (config->container_network_enabled != 0);
}

__attribute__((__always_inline__)) static inline bool redirectContainerFragment(__u8 container_fragment, bool is_ingress)
{
  __u32 container_index = container_fragment;

  __u32 *primary_device_idx = bpf_map_lookup_elem(&ct_dev_map, &container_index);
  if (primary_device_idx == NULL)
  {
    return false;
  }

  if (is_ingress)
  {
    return (bpf_redirect(*primary_device_idx, 0) == TC_ACT_REDIRECT);
  }

  return (bpf_redirect(*primary_device_idx, 0) == TC_ACT_REDIRECT);
}

__attribute__((__always_inline__)) static inline bool setContainerIDFromDistributedIPv4(struct container_id *containerID, __be32 dst, const struct local_container_subnet6 *localcontainersubnet6)
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

__attribute__((__always_inline__)) static inline bool setContainerIDFromDistributedIPv6(struct container_id *containerID, const __u32 dstv6[4])
{
  const __u8 *bytes = (const __u8 *)dstv6;
  __u8 datacenter_fragment = bytes[11];
  __u8 machine_fragment0 = bytes[12];
  __u8 machine_fragment1 = bytes[13];
  __u8 machine_fragment2 = bytes[14];
  __u8 container_fragment = bytes[15];

  if (datacenter_fragment == 0 || (machine_fragment0 == 0 && machine_fragment1 == 0 && machine_fragment2 == 0) || container_fragment == 0)
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

__attribute__((__always_inline__)) static inline bool overlayRouteKeyFromIPv4(__be32 dst, struct switchboard_overlay_machine_route_key *key)
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

__attribute__((__always_inline__)) static inline bool overlayRouteKeyFromIPv6(const __u32 dstv6[4], struct switchboard_overlay_machine_route_key *key)
{
  if (key == NULL)
  {
    return false;
  }

  __u32 identity = 0;
  if (switchboardExtractOverlayMachineIdentityFromIPv6((const __u8 *)dstv6, &identity) == false)
  {
    return false;
  }

  key->fragment = identity;
  return true;
}

__attribute__((__always_inline__)) static inline struct switchboard_overlay_machine_route *lookupOverlayMachineRouteFull(const struct switchboard_overlay_machine_route_key *key)
{
  if (key == NULL)
  {
    return NULL;
  }

  return bpf_map_lookup_elem(&ovl_mach_full, key);
}

__attribute__((__always_inline__)) static inline struct switchboard_overlay_machine_route *lookupOverlayMachineRouteLow8(const struct switchboard_overlay_machine_route_key *key)
{
  if (key == NULL)
  {
    return NULL;
  }

  return bpf_map_lookup_elem(&ovl_mach_low8, key);
}

__attribute__((__always_inline__)) static inline bool overlaySiteRouteSetValid(const struct switchboard_overlay_site_route_set *routes)
{
  if (routes == NULL || routes->version != SWITCHBOARD_OVERLAY_SITE_ROUTE_SET_VERSION ||
      routes->count == 0 || routes->count > SWITCHBOARD_OVERLAY_SITE_ROUTE_SET_MAX_CANDIDATES) return false;
#pragma unroll
  for (__u32 i = 0; i < SWITCHBOARD_OVERLAY_SITE_ROUTE_SET_MAX_CANDIDATES; ++i)
  {
    if (i >= routes->count) break;
    const struct switchboard_overlay_machine_route *candidate = &routes->candidates[i];
    if ((candidate->family != SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV4 &&
         candidate->family != SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6) ||
        candidate->use_gateway_mac > SWITCHBOARD_OVERLAY_ROUTE_ACTION_LOCAL_CONTAINER_REDIRECT) return false;
    if (candidate->use_gateway_mac == SWITCHBOARD_OVERLAY_ROUTE_ACTION_LOCAL_CONTAINER_REDIRECT &&
        (candidate->next_hop_mac[0] != SWITCHBOARD_MASQUE_GATEWAY_FRAGMENT_FIRST &&
         candidate->next_hop_mac[0] != SWITCHBOARD_MASQUE_GATEWAY_FRAGMENT_SECOND)) return false;
    if (candidate->use_gateway_mac == SWITCHBOARD_OVERLAY_ROUTE_ACTION_LOCAL_CONTAINER_REDIRECT)
    {
#pragma unroll
      for (__u32 j = 1; j < sizeof(candidate->next_hop_mac); ++j)
        if (candidate->next_hop_mac[j] != 0) return false;
    }
  }
  return true;
}

// The destination machine identity is stable for a flow and available at all
// existing overlay call sites.  Exact machine routes bypass this entirely.
__attribute__((__always_inline__)) static inline struct switchboard_overlay_machine_route *lookupOverlaySiteRoute(__u32 machine_fragment)
{
  struct switchboard_overlay_machine_route_key key = {
      .fragment = switchboardMakeOverlayDatacenterRouteKey((__u8)(machine_fragment >> 24)),
  };
  struct switchboard_overlay_site_route_set *routes = bpf_map_lookup_elem(&ovl_site_rts_v2, &key);
  if (overlaySiteRouteSetValid(routes) == false) return NULL;
  const __u32 count = routes->count;
  // Keep the fixed array bound explicit for the verifier; the validator above
  // remains responsible for candidate contents and the count contract.
  if (count == 0 || count > SWITCHBOARD_OVERLAY_SITE_ROUTE_SET_MAX_CANDIDATES) return NULL;
  __u32 hash = machine_fragment ^ (machine_fragment >> 16) ^ 0x9e3779b9u;
  __u32 candidateIndex = hash % count;
  // LLVM can prove the following check from modulo arithmetic and discard it,
  // while the verifier cannot carry that proof into map-value pointer math.
  // Keep the existing policy, but retain a verifier-visible array bound.
  barrier_var(candidateIndex);
  if (candidateIndex >= SWITCHBOARD_OVERLAY_SITE_ROUTE_SET_MAX_CANDIDATES) return NULL;
  return &routes->candidates[candidateIndex];
}

__attribute__((__always_inline__)) static inline struct switchboard_overlay_machine_route *lookupOverlayMachineRouteByFragment(__u32 machine_fragment)
{
  if (switchboardOverlayMachineIdentityIsValid(machine_fragment) == false)
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

  // A nonzero datacenter owns a container-network /96.  A site route may
  // serve an exact-machine miss, but a low-8 alias cannot prove the same
  // datacenter and must not route a withdrawn remote site to a local machine.
  route = lookupOverlaySiteRoute(machine_fragment);
  if (route != NULL)
  {
    return route;
  }

  return NULL;
}
