#pragma once

#include <ebpf/common/structs.h>
#include <switchboard/common/structs.h>

static inline bool switchboardContainerNetworkPrefixMatchesIPv6(const __u8 *addr6)
{
  if (addr6 == 0)
  {
    return false;
  }

  return (addr6[0] == container_network_subnet6.value[0] &&
          addr6[1] == container_network_subnet6.value[1] &&
          addr6[2] == container_network_subnet6.value[2] &&
          addr6[3] == container_network_subnet6.value[3] &&
          addr6[4] == container_network_subnet6.value[4] &&
          addr6[5] == container_network_subnet6.value[5] &&
          addr6[6] == container_network_subnet6.value[6] &&
          addr6[7] == container_network_subnet6.value[7] &&
          addr6[8] == container_network_subnet6.value[8] &&
          addr6[9] == container_network_subnet6.value[9] &&
          addr6[10] == container_network_subnet6.value[10]);
}

static inline bool switchboardLocalContainerSubnetMatchesIPv6(const __u8 *addr6, const struct local_container_subnet6 *subnet)
{
  if (addr6 == 0 || subnet == 0)
  {
    return false;
  }

  return (addr6[11] == subnet->dpfx &&
          addr6[12] == subnet->mpfx[0] &&
          addr6[13] == subnet->mpfx[1] &&
          addr6[14] == subnet->mpfx[2]);
}

static inline bool switchboardContainerIPv6TargetsLocalMachine(const __u8 *addr6, const struct local_container_subnet6 *subnet)
{
  return switchboardContainerNetworkPrefixMatchesIPv6(addr6) && switchboardLocalContainerSubnetMatchesIPv6(addr6, subnet);
}

static inline bool switchboardContainerIPv6TargetsRemoteMachine(const __u8 *addr6, const struct local_container_subnet6 *subnet)
{
  return switchboardContainerNetworkPrefixMatchesIPv6(addr6) && switchboardLocalContainerSubnetMatchesIPv6(addr6, subnet) == false;
}

static inline bool switchboardResolveLocalContainerIPv6Fragment(const __u8 *addr6, const struct local_container_subnet6 *subnet, __u8 *fragment)
{
  if (fragment == 0 || switchboardContainerIPv6TargetsLocalMachine(addr6, subnet) == false || addr6[15] == 0)
  {
    return false;
  }

  *fragment = addr6[15];
  return true;
}

static inline bool switchboardContainerIDTargetsLocalMachine(const struct container_id *containerID, const struct local_container_subnet6 *subnet)
{
  return containerID != 0 && containerID->hasID && subnet != 0 && containerID->value[0] == subnet->dpfx && containerID->value[1] == subnet->mpfx[0] && containerID->value[2] == subnet->mpfx[1] && containerID->value[3] == subnet->mpfx[2];
}

static inline bool switchboardContainerIDTargetsRemoteMachine(const struct container_id *containerID, const struct local_container_subnet6 *subnet)
{
  return containerID != 0 && containerID->hasID && switchboardContainerIDTargetsLocalMachine(containerID, subnet) == false;
}

static inline bool switchboardBuildContainerNetworkIPv6(__u8 *addr6, const struct container_id *containerID)
{
  if (addr6 == 0 || containerID == 0 || containerID->hasID == false)
  {
    return false;
  }

  __builtin_memcpy(addr6, container_network_subnet6.value, sizeof(container_network_subnet6.value));
  __builtin_memcpy(addr6 + sizeof(container_network_subnet6.value), containerID->value, sizeof(containerID->value));
  return true;
}

// The full 32-bit overlay identity is { datacenter:8, machine:24 }.  IPv4
// keeps its historical low-8 machine lookup separately; it must not collapse
// IPv6 identities from different datacenters.
static inline bool switchboardOverlayMachineIdentityIsValid(__u32 identity)
{
  return (identity >> 24) != 0 && (identity & 0x00ffffffu) != 0;
}

// A datacenter route represents the remote container-network /96.  It uses
// the same full-route map as a machine route, with the machine fragment zero.
static inline bool switchboardOverlayDatacenterRouteIsValid(__u32 route_key)
{
  return (route_key >> 24) != 0 && (route_key & 0x00ffffffu) == 0;
}

static inline bool switchboardOverlayRouteKeyIsValid(__u32 route_key)
{
  return switchboardOverlayMachineIdentityIsValid(route_key) || switchboardOverlayDatacenterRouteIsValid(route_key);
}

static inline __u32 switchboardMakeOverlayMachineIdentity(__u8 datacenter_fragment, __u32 machine_fragment)
{
  if (datacenter_fragment == 0 || machine_fragment == 0 || machine_fragment > 0x00ffffffu)
  {
    return 0;
  }

  return ((__u32)datacenter_fragment << 24) | machine_fragment;
}

static inline __u32 switchboardMakeOverlayDatacenterRouteKey(__u8 datacenter_fragment)
{
  return datacenter_fragment == 0 ? 0 : ((__u32)datacenter_fragment << 24);
}

static inline bool switchboardExtractOverlayMachineIdentityFromIPv6(const __u8 *addr6, __u32 *identity)
{
  if (addr6 == 0 || identity == 0 || switchboardContainerNetworkPrefixMatchesIPv6(addr6) == false)
  {
    return false;
  }

  if (addr6[11] == 0 || (addr6[12] == 0 && addr6[13] == 0 && addr6[14] == 0) || addr6[15] == 0)
  {
    return false;
  }

  *identity = switchboardMakeOverlayMachineIdentity(addr6[11], (((__u32)addr6[12]) << 16) | (((__u32)addr6[13]) << 8) | (__u32)addr6[14]);
  return switchboardOverlayMachineIdentityIsValid(*identity);
}

static inline bool switchboardWormholeSourceRewriteEligibleIPv6(const __u8 *src6, const __u8 *dst6)
{
  (void)dst6;

  // Wormhole replies must preserve their external source tuple even when the
  // receiver has already been translated onto an internal container-network
  // IPv6. Destination locality must not suppress rewrite eligibility.
  return switchboardContainerNetworkPrefixMatchesIPv6(src6);
}
