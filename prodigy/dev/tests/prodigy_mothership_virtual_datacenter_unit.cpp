#include <prodigy/mothership/mothership.virtual.datacenter.h>
#include <prodigy/mothership/mothership.virtual.datacenter.recovery.h>
#include <sys/wait.h>

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
  cluster.clusterUUID = 0x1234;
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

  String controlSocketPath = {};
  mothershipResolveTestClusterControlSocketPath(cluster, controlSocketPath);
  suite.expect(controlSocketPath.equals("/tmp/prodigy-vdc-0x1234/mothership.sock"_ctv), "control_socket_path_is_bounded_by_cluster_identity");
  cluster.test.workspaceRoot = "/tmp/prodigy/a-deliberately-long-test-workspace-name-that-would-overflow-a-linux-unix-socket-path/vdc-unit"_ctv;
  mothershipResolveTestClusterControlSocketPath(cluster, controlSocketPath);
  suite.expect(controlSocketPath.equals("/tmp/prodigy-vdc-0x1234/mothership.sock"_ctv), "long_workspace_does_not_expand_control_socket_path");
  cluster.test.workspaceRoot = "/tmp/prodigy/vdc-unit"_ctv;

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

  uint64_t parsed = 0;
  char processState = 0;
  String processStat = "917 (provider ) with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123456 0\n"_ctv;
  suite.expect(mothershipVDCParseStat(processStat, 917, parsed, processState) && parsed == 123456 && processState == 'S',
               "recovery_stat_handles_spaces_and_parentheses");
  suite.expect(mothershipVDCParseStat(processStat, 918, parsed, processState) == false, "recovery_stat_rejects_pid_mismatch");
  suite.expect(mothershipVDCParseStat("917 (truncated)"_ctv, 917, parsed, processState) == false, "recovery_stat_rejects_truncation");
  constexpr char overflow[] = "18446744073709551616";
  suite.expect(mothershipVDCParseUnsigned(overflow, overflow + sizeof(overflow) - 1, parsed) == false, "recovery_identity_rejects_overflow");

  Vector<String> providerArguments = {};
  for (const char *argument : {"bash", "/proc/self/fd/7", "--serve", "/tmp/prodigy/vdc-unit", "3", "2", "65495", "0", "42", "4", "8192", "8192", "0", "1024", "/tmp/prodigy-vdc-0x1234/mothership.sock"})
    providerArguments.emplace_back(argument);
  String originals[12];
  suite.expect(mothershipVDCProviderArguments(providerArguments, cluster.test.workspaceRoot, 917, originals), "recovery_binds_exact_original_provider_arguments");
  providerArguments[3].assign("/tmp/another-workspace"_ctv);
  providerArguments[14] = cluster.test.workspaceRoot;
  suite.expect(mothershipVDCProviderArguments(providerArguments, cluster.test.workspaceRoot, 917, originals) == false,
               "recovery_rejects_workspace_in_wrong_argument");
  providerArguments[3] = cluster.test.workspaceRoot;
  providerArguments[1].assign("/tmp/unsealed-script"_ctv);
  suite.expect(mothershipVDCProviderArguments(providerArguments, cluster.test.workspaceRoot, 917, originals) == false,
               "recovery_rejects_unsealed_provider_command");

  MothershipVDCBundleRecovery recovery = {};
  recovery.clusterUUID = cluster.clusterUUID;
  recovery.operationID = 0x5678;
  recovery.runtimeIdentity = 917;
  recovery.machineIndex = 2;
  recovery.phase = MothershipVDCRecoveryPhase::ready;
  recovery.supervisor = {917, 10, 20, 30};
  recovery.worker = {923, 11, 21, 31};
  recovery.adopter = {929, 12, 20, 30};
  recovery.expectedOldBundle.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
  recovery.successorBundle.assign("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv);
  recovery.providerArguments[0] = cluster.test.workspaceRoot;
  char recoveryDirectory[] = "./vdc-recovery-unit.XXXXXX";
  const bool directoryCreated = ::mkdtemp(recoveryDirectory) != nullptr;
  suite.expect(directoryCreated, "recovery_creates_scoped_test_directory");
  if (directoryCreated)
  {
    String directory(recoveryDirectory);
    suite.expect(mothershipVDCWriteRecovery(directory, recovery, &failure), "recovery_durably_writes_intent");
    MothershipVDCBundleRecovery restored = {};
    suite.expect(mothershipVDCReadRecovery(directory, restored) && restored.clusterUUID == recovery.clusterUUID &&
                 restored.operationID == recovery.operationID && restored.runtimeIdentity == recovery.runtimeIdentity &&
                 restored.machineIndex == 2 && restored.phase == MothershipVDCRecoveryPhase::ready &&
                 mothershipVDCSameProcess(restored.supervisor, recovery.supervisor) &&
                 mothershipVDCSameProcess(restored.worker, recovery.worker) &&
                 mothershipVDCSameProcess(restored.adopter, recovery.adopter) &&
                 restored.expectedOldBundle == recovery.expectedOldBundle && restored.successorBundle == recovery.successorBundle &&
                 restored.providerArguments[0] == cluster.test.workspaceRoot, "recovery_preserves_distinct_runtime_and_process_identity");
    recovery.version = 2;
    suite.expect(mothershipVDCWriteRecovery(directory, recovery, &failure) && mothershipVDCReadRecovery(directory, restored) == false,
                 "recovery_rejects_unknown_journal_version");
    String path = {}; mothershipVirtualDatacenterPath(directory, "operation", path);
    ::unlink(path.c_str()); ::rmdir(recoveryDirectory);
  }

  // Signal only this test's own child. A stale start-time must not affect it.
  pid_t child = ::fork();
  if (child == 0) { while (true) ::pause(); }
  suite.expect(child > 0, "recovery_creates_owned_identity_fixture");
  if (child > 0)
  {
    MothershipVDCProcessIdentity identity = {};
    bool observed = mothershipVDCReadProcess(child, identity);
    suite.expect(observed, "recovery_reads_owned_process_identity");
    MothershipVDCProcessIdentity stale = identity;
    ++stale.startTime;
    suite.expect(mothershipVDCSignal(stale, SIGKILL) == false && ::kill(child, 0) == 0, "recovery_rejects_stale_identity_without_signaling");
    bool stopped = observed && mothershipVDCSignal(identity, SIGSTOP);
    suite.expect(stopped, "recovery_stops_only_verified_process");
    int status = 0;
    bool frozen = false;
    for (unsigned attempt = 0; stopped && attempt < 100; ++attempt) {
      if (::waitpid(child, &status, WUNTRACED | WNOHANG) == child) { frozen = WIFSTOPPED(status); break; }
      ::usleep(10000);
    }
    suite.expect(frozen, "recovery_observes_frozen_identity");
    suite.expect(mothershipVDCSignal(identity, SIGCONT), "recovery_resumes_verified_process");
    (void)::kill(child, SIGKILL);
    (void)::waitpid(child, &status, 0);
  }

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
