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

  ContainerPlan forged = {};
  Container *container = reinterpret_cast<Container *>(uintptr_t(1));
  ContainerManager::createContainer(forged, ""_ctv, container);
  suite.expect(container == nullptr, "create_container_rejects_forged_zero_fragment");

  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
