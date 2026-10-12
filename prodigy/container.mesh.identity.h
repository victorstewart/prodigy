#pragma once

#include <cstring>

#include <ebpf/common/structs.h>
#include <prodigy/types.h>

static inline bool prodigyValidateContainerPlanMeshIdentity(
    const ContainerPlan& plan,
    const local_container_subnet6& machineSubnet)
{
  bool ownsMeshAddress = false;
  for (const IPPrefix& address : plan.addresses)
  {
    if (!address.network.is6 || address.cidr != 128 ||
        std::memcmp(address.network.v6,
                    container_network_subnet6.value,
                    sizeof(container_network_subnet6.value)) != 0)
    {
      continue;
    }

    if (address.network.v6[11] != machineSubnet.dpfx ||
        address.network.v6[12] != machineSubnet.mpfx[0] ||
        address.network.v6[13] != machineSubnet.mpfx[1] ||
        address.network.v6[14] != machineSubnet.mpfx[2] ||
        address.network.v6[15] != plan.fragment)
    {
      return false;
    }
    ownsMeshAddress = true;
  }

  return ownsMeshAddress ||
         (plan.addresses.empty() &&
          plan.system.kind == SystemContainerKind::mothershipTunnelProvider &&
          plan.fragment == prodigyMothershipTunnelProviderRuntimeFragment);
}
