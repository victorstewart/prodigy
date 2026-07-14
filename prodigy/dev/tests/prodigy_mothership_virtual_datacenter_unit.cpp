#include <prodigy/mothership/mothership.virtual.datacenter.h>

#include <services/debug.h>

#include <cstdlib>
#include <cstring>

class TestSuite {
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    if (condition)
    {
      basics_log("PASS: %s\n", name);
    }
    else
    {
      basics_log("FAIL: %s\n", name);
      std::fprintf(stderr, "FAIL: %s\n", name);
      failed += 1;
    }
  }
};

static bool containsAddress(const Vector<ClusterMachineAddress>& addresses, const char *address, uint8_t prefixLength)
{
  for (const ClusterMachineAddress& candidate : addresses)
  {
    if (candidate.address.equals(String(address)) && candidate.cidr == prefixLength)
    {
      return true;
    }
  }
  return false;
}

int main(void)
{
  TestSuite suite;

  suite.expect(mothershipTestClusterWorkspaceRootValid("/tmp/vdc"_ctv), "workspace_accepts_nested_absolute_path");
  suite.expect(mothershipTestClusterWorkspaceRootValid("/tmp/space dir/vdc"_ctv), "workspace_accepts_spaces");
  suite.expect(mothershipTestClusterWorkspaceRootValid("/vdc"_ctv) == false, "workspace_rejects_root_child");
  suite.expect(mothershipTestClusterWorkspaceRootValid("relative/vdc"_ctv) == false, "workspace_rejects_relative_path");
  suite.expect(mothershipTestClusterWorkspaceRootValid("/tmp/../vdc"_ctv) == false, "workspace_rejects_parent_component");
  suite.expect(mothershipTestClusterWorkspaceRootValid("/tmp/vdc/"_ctv) == false, "workspace_rejects_trailing_slash");

  MothershipProdigyCluster cluster = {};
  cluster.name = "virtual-datacenter-unit"_ctv;
  cluster.deploymentMode = MothershipClusterDeploymentMode::test;
  cluster.nBrains = 2;
  cluster.machineSchemas.push_back(MothershipProdigyClusterMachineSchema {});
  cluster.machineSchemas[0].schema = "test-brain"_ctv;
  cluster.test.specified = true;
  cluster.test.workspaceRoot = "/tmp/prodigy/vdc-unit"_ctv;
  cluster.test.machineCount = 3;
  cluster.test.storageDeviceCount = 2;
  cluster.test.storageDeviceMB = 768;
  cluster.test.brainBootstrapFamily = MothershipClusterTestBootstrapFamily::multihome6;
  cluster.test.enableFakeIpv4Boundary = false;

  ClusterTopology topology = {};
  String failure = {};
  suite.expect(mothershipBuildVirtualDatacenterTopology(cluster, topology, &failure), "build_topology");
  suite.expect(failure.empty(), "build_topology_clears_failure");
  suite.expect(topology.machines.size() == 3, "topology_machine_count");
  suite.expect(clusterTopologyBrainCount(topology) == 2, "topology_brain_count");
  suite.expect(topology.machines[0].source == ClusterMachineSource::created &&
               topology.machines[0].backing == ClusterMachineBacking::owned,
               "topology_machine_ownership");
  suite.expect(containsAddress(topology.machines[0].addresses.privateAddresses, "10.0.0.10", 24), "topology_first_private_ipv4");
  suite.expect(containsAddress(topology.machines[0].addresses.privateAddresses, "fd00:10::a", 64), "topology_first_private_ipv6");
  suite.expect(containsAddress(topology.machines[0].addresses.publicAddresses, "2001:db8:100::a", 64), "topology_first_public_ipv6");
  suite.expect(topology.machines[0].peerAddresses.size() == 2, "topology_multihome_peer_addresses");

  String provisionedPath = {};
  mothershipVirtualDatacenterPath(cluster.test.workspaceRoot, mothershipVirtualDatacenterProvisionedFilename, provisionedPath);
  suite.expect(provisionedPath.equals("/tmp/prodigy/vdc-unit/virtual-datacenter.provisioned"_ctv), "provisioned_marker_path");

  if (suite.failed != 0)
  {
    basics_log("mothership_virtual_datacenter_unit failed=%d\n", suite.failed);
    return EXIT_FAILURE;
  }

  basics_log("mothership_virtual_datacenter_unit ok\n");
  return EXIT_SUCCESS;
}
