#include <prodigy/prodigy.h>
#include <prodigy/brain/brain.h>

#include <cstdio>
#include <cstdlib>

class TestSuite {
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    std::printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    failed += condition ? 0 : 1;
  }
};

int main(void)
{
  TestSuite suite = {};
  Machine machine = {};
  constexpr uint8_t used = 17;
  constexpr uint8_t available = 18;
  machine.usedContainerFragments.insert(used);

  suite.expect(machine.containerFragmentAvailable(0) == false, "fragment_zero_is_unavailable");
  suite.expect(machine.containerFragmentAvailable(prodigyMothershipTunnelProviderRuntimeFragment) == false, "fragment_reserved_is_unavailable");
  suite.expect(machine.containerFragmentAvailable(used) == false, "fragment_used_is_unavailable");
  suite.expect(machine.containerFragmentAvailable(available), "fragment_unused_is_available");
  suite.expect(Machine::maxSchedulableContainers == 254, "fragment_capacity_matches_usable_address_cardinality");

  machine.usedContainerFragments.clear();
  constexpr uint8_t finalFragment = 253;
  for (uint32_t fragment = 1; fragment <= UINT8_MAX; ++fragment)
  {
    if (fragment != finalFragment && fragment != prodigyMothershipTunnelProviderRuntimeFragment)
    {
      machine.usedContainerFragments.insert(fragment);
    }
  }
  suite.expect(machine.getContainerFragment() == finalFragment, "fragment_allocator_finds_only_remaining_fragment");
  suite.expect(machine.getContainerFragment() == 0, "fragment_allocator_fails_promptly_when_exhausted");

  local_container_subnet6 machineSubnet = {};
  machineSubnet.dpfx = 3;
  machineSubnet.mpfx[0] = 0x12;
  machineSubnet.mpfx[1] = 0x34;
  machineSubnet.mpfx[2] = 0x56;
  ContainerPlan meshPlan = {};
  meshPlan.fragment = 17;
  IPPrefix meshAddress = {};
  meshAddress.network.is6 = true;
  meshAddress.cidr = 128;
  std::memcpy(meshAddress.network.v6,
              container_network_subnet6.value,
              sizeof(container_network_subnet6.value));
  meshAddress.network.v6[11] = machineSubnet.dpfx;
  meshAddress.network.v6[12] = machineSubnet.mpfx[0];
  meshAddress.network.v6[13] = machineSubnet.mpfx[1];
  meshAddress.network.v6[14] = machineSubnet.mpfx[2];
  meshAddress.network.v6[15] = meshPlan.fragment;
  meshPlan.addresses.push_back(meshAddress);
  suite.expect(prodigyValidateContainerPlanMeshIdentity(meshPlan, machineSubnet),
               "container_mesh_identity_accepts_exact_reserved_address");

  meshPlan.addresses.push_back(meshAddress);
  suite.expect(prodigyValidateContainerPlanMeshIdentity(meshPlan, machineSubnet),
               "container_mesh_identity_accepts_duplicate_matching_reserved_addresses");

  IPPrefix externalAddress("198.51.100.7", false, 32);
  meshPlan.addresses.push_back(externalAddress);
  suite.expect(prodigyValidateContainerPlanMeshIdentity(meshPlan, machineSubnet),
               "container_mesh_identity_ignores_non_mesh_address");

  IPPrefix foreignMeshAddress = meshAddress;
  foreignMeshAddress.network.v6[14] ^= 1;
  meshPlan.addresses.push_back(foreignMeshAddress);
  suite.expect(!prodigyValidateContainerPlanMeshIdentity(meshPlan, machineSubnet),
               "container_mesh_identity_rejects_any_foreign_reserved_address");

  ContainerPlan nonMeshOnly = {};
  nonMeshOnly.fragment = meshPlan.fragment;
  nonMeshOnly.addresses.push_back(externalAddress);
  suite.expect(!prodigyValidateContainerPlanMeshIdentity(nonMeshOnly, machineSubnet),
               "container_mesh_identity_requires_reserved_address");

  ContainerPlan tunnelProvider = {};
  tunnelProvider.fragment = prodigyMothershipTunnelProviderRuntimeFragment;
  tunnelProvider.system.kind = SystemContainerKind::mothershipTunnelProvider;
  suite.expect(prodigyValidateContainerPlanMeshIdentity(tunnelProvider, machineSubnet),
               "container_mesh_identity_allows_empty_tunnel_provider");
  tunnelProvider.fragment = 17;
  suite.expect(!prodigyValidateContainerPlanMeshIdentity(tunnelProvider, machineSubnet),
               "container_mesh_identity_rejects_empty_tunnel_provider_without_reserved_fragment");
  tunnelProvider.fragment = prodigyMothershipTunnelProviderRuntimeFragment;
  tunnelProvider.addresses.push_back(externalAddress);
  suite.expect(!prodigyValidateContainerPlanMeshIdentity(tunnelProvider, machineSubnet),
               "container_mesh_identity_rejects_nonempty_tunnel_provider_without_reserved_address");
  suite.expect(!prodigyValidateContainerPlanMeshIdentity(ContainerPlan {}, machineSubnet),
               "container_mesh_identity_rejects_empty_application_plan");

  ContainerPlan forged = {};
  Container *container = reinterpret_cast<Container *>(uintptr_t(1));
  ContainerManager::createContainer(forged, ""_ctv, container);
  suite.expect(container == nullptr, "create_container_rejects_forged_zero_fragment");

  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
