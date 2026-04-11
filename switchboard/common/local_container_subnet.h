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
   return switchboardContainerNetworkPrefixMatchesIPv6(addr6)
      && switchboardLocalContainerSubnetMatchesIPv6(addr6, subnet);
}

static inline bool switchboardContainerIPv6TargetsRemoteMachine(const __u8 *addr6, const struct local_container_subnet6 *subnet)
{
   return switchboardContainerNetworkPrefixMatchesIPv6(addr6)
      && switchboardLocalContainerSubnetMatchesIPv6(addr6, subnet) == false;
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
   return containerID != 0
      && containerID->hasID
      && subnet != 0
      && containerID->value[0] == subnet->dpfx
      && containerID->value[1] == subnet->mpfx[0]
      && containerID->value[2] == subnet->mpfx[1]
      && containerID->value[3] == subnet->mpfx[2];
}

static inline bool switchboardContainerIDTargetsRemoteMachine(const struct container_id *containerID, const struct local_container_subnet6 *subnet)
{
   return containerID != 0
      && containerID->hasID
      && switchboardContainerIDTargetsLocalMachine(containerID, subnet) == false;
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

static inline bool switchboardExtractOverlayMachineFragmentFromIPv6(const __u8 *addr6, __u32 *fragment)
{
   if (addr6 == 0 || fragment == 0)
   {
      return false;
   }

   if (addr6[12] == 0 && addr6[13] == 0 && addr6[14] == 0)
   {
      return false;
   }

   if (addr6[15] == 0)
   {
      return false;
   }

   *fragment = (((__u32)addr6[12]) << 16) | (((__u32)addr6[13]) << 8) | (__u32)addr6[14];
   return true;
}

static inline bool switchboardWormholeSourceRewriteEligibleIPv6(const __u8 *src6, const __u8 *dst6)
{
   (void)dst6;

   // Wormhole replies must preserve their external source tuple even when the
   // receiver has already been translated onto an internal container-network
   // IPv6. Destination locality must not suppress rewrite eligibility.
   return switchboardContainerNetworkPrefixMatchesIPv6(src6);
}
