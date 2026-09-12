#include <prodigy/mothership/mothership.virtual.datacenter.h>
#include <prodigy/mothership/mothership.virtual.datacenter.recovery.h>
#include <sys/wait.h>

#include <services/debug.h>

#include <cstdlib>
#include <cstring>
#include <string>

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

static void testPublicationPreservesSelectedMachine(TestSuite& suite)
{
  std::string sourcePath = __FILE__;
  const size_t root = sourcePath.rfind("/dev/tests/");
  suite.expect(root != std::string::npos, "publication_fixture_locates_provider_owner");
  if (root == std::string::npos) return;
  sourcePath.resize(root);
  sourcePath += "/mothership/mothership.virtual.datacenter.provider.sh";
  String source = {};
  if (mothershipVDCRead(String(sourcePath.c_str()), source, 1024 * 1024) == false)
  { suite.expect(false, "publication_fixture_reads_provider_owner"); return; }
  std::string text(reinterpret_cast<const char *>(source.data()), source.size());
  size_t begin = text.find("publish_runtime()\n{\n");
  size_t end = text.find("\nrecovery_hold()\n", begin);
  if (begin == std::string::npos || end == std::string::npos)
  { suite.expect(false, "publication_fixture_extracts_existing_owner"); return; }
  // Execute only the real publication function against plain fixture files.
  // No provider launch, mount, network or service action belongs in this unit.
  std::string script = "set -euo pipefail\n" + text.substr(begin, end - begin) + R"TEST(
workspace=fixture
manifest_path="$PWD/manifest.json"
runtime_path="$PWD/runtime"
control_socket_path=/tmp/fixture.sock
parent_ns=fixture-parent
pid=1234
machine_count=4
brain_count=1
machine_logical_cores=8
machine_memory_mb=16384
machine_storage_mb=8192
storage_device_count=0
storage_device_mb=1024
inter_container_mtu=9000
fake_boundary=0
child_names=(one two three four)
machine_pids=(101 202 303 404)
index=2
publish_runtime
[[ "$index" == 2 && "${machine_pids[$((index - 1))]}" == 202 ]]
[[ "$(wc -l < "$runtime_path")" == 4 ]]
)TEST";
  char temporary[] = "./vdc-publication-unit.XXXXXX";
  if (::mkdtemp(temporary) == nullptr)
  { suite.expect(false, "publication_fixture_creates_owned_directory"); return; }
  String scriptPath = {};
  mothershipVirtualDatacenterPath(String(temporary), "probe.sh", scriptPath);
  String failure = {};
  bool written = mothershipVirtualDatacenterWriteFile(scriptPath, String(script.c_str()), 0600, &failure);
  pid_t child = written ? ::fork() : -1;
  if (child == 0)
  {
    if (::chdir(temporary) != 0) _exit(125);
    ::execl("/bin/bash", "bash", "probe.sh", static_cast<char *>(nullptr));
    _exit(127);
  }
  int status = 0;
  pid_t waited = -1;
  if (child > 0) do { waited = ::waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
  suite.expect(written && waited == child && child > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "publication_preserves_selected_machine_and_replacement_pid");
  for (const char *name : {"probe.sh", "manifest.json", "runtime"})
  { String path = {}; mothershipVirtualDatacenterPath(String(temporary), name, path); ::unlink(path.c_str()); }
  ::rmdir(temporary);
}

static void testFaultLinkRebindsPublishedProvider(TestSuite& suite)
{
  std::string sourcePath = __FILE__;
  const size_t root = sourcePath.rfind("/dev/tests/");
  suite.expect(root != std::string::npos, "fault_fixture_locates_provider_owner");
  if (root == std::string::npos) return;
  sourcePath.resize(root);
  sourcePath += "/mothership/mothership.virtual.datacenter.provider.sh";
  String source = {};
  if (mothershipVDCRead(String(sourcePath.c_str()), source, 1024 * 1024) == false)
  { suite.expect(false, "fault_fixture_reads_provider_owner"); return; }
  std::string text(reinterpret_cast<const char *>(source.data()), source.size());
  size_t begin = text.find("runtime_identity_for_workspace()\n{\n");
  size_t end = text.find("\nfault_datacenter()\n", begin);
  if (begin == std::string::npos || end == std::string::npos)
  { suite.expect(false, "fault_fixture_extracts_link_owner"); return; }
  // This executes only fault link bookkeeping with shell mocks. It models a
  // committed adopter publishing PID 900 during a link fault while the
  // retained resource identity stays 700. No namespace is entered.
  std::string script = "set -euo pipefail\n" + text.substr(begin, end - begin) + R"TEST(
workspace="$PWD/workspace"
mkdir -p "$workspace"
printf '700\n' > "$workspace/virtual-datacenter.pid"
printf '700\n' > "$workspace/virtual-datacenter.identity"
valid_workspace() { [[ "$1" == "$workspace" ]]; }
provider_process() { [[ "$#" -eq 2 && "$2" == "$workspace" && ( "$1" == 700 || "$1" == 900 ) ]]; }
nsenter() {
  case "$*" in
    '-t 700 -m -- ip netns exec pvd-p-700 ip link set vp1 down')
      printf '700 down\n' >> "$workspace/transitions"
      printf '900\n' > "$workspace/virtual-datacenter.pid"
      ;;
    '-t 900 -m -- ip netns exec pvd-p-700 ip link set vp1 up')
      printf '900 up\n' >> "$workspace/transitions"
      ;;
    *) return 1 ;;
  esac
}
fault_link_set "$workspace" 700 vp1 down
fault_link_set "$workspace" 700 vp1 up
printf '701\n' > "$workspace/virtual-datacenter.identity"
! fault_link_set "$workspace" 700 vp1 up
[[ "$(<"$workspace/transitions")" == $'700 down\n900 up' ]]
)TEST";
  char temporary[] = "./vdc-fault-link-unit.XXXXXX";
  if (::mkdtemp(temporary) == nullptr)
  { suite.expect(false, "fault_fixture_creates_owned_directory"); return; }
  String scriptPath = {};
  mothershipVirtualDatacenterPath(String(temporary), "probe.sh", scriptPath);
  String failure = {};
  bool written = mothershipVirtualDatacenterWriteFile(scriptPath, String(script.c_str()), 0600, &failure);
  pid_t child = written ? ::fork() : -1;
  if (child == 0)
  {
    if (::chdir(temporary) != 0) _exit(125);
    ::execl("/bin/bash", "bash", "probe.sh", static_cast<char *>(nullptr));
    _exit(127);
  }
  int status = 0;
  pid_t waited = -1;
  if (child > 0) do { waited = ::waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
  suite.expect(written && waited == child && child > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "fault_link_rebinds_published_provider_with_retained_namespace");
  for (const char *name : {"probe.sh", "workspace/virtual-datacenter.pid", "workspace/virtual-datacenter.identity",
                           "workspace/transitions"})
  { String path = {}; mothershipVirtualDatacenterPath(String(temporary), name, path); ::unlink(path.c_str()); }
  String workspacePath = {}; mothershipVirtualDatacenterPath(String(temporary), "workspace", workspacePath);
  ::rmdir(workspacePath.c_str());
  ::rmdir(temporary);
}

int main(void)
{
  TestSuite suite;
  testPublicationPreservesSelectedMachine(suite);
  testFaultLinkRebindsPublishedProvider(suite);

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
  recovery.expectedIncompleteWorkerBundle = recovery.expectedOldBundle;
  recovery.previousBootSHA256 = recovery.expectedOldBundle;
  recovery.successorBootSHA256 = recovery.successorBundle;
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
                 restored.expectedIncompleteWorkerBundle == recovery.expectedIncompleteWorkerBundle &&
                 restored.previousBootSHA256 == recovery.previousBootSHA256 && restored.successorBootSHA256 == recovery.successorBootSHA256 &&
                 restored.providerArguments[0] == cluster.test.workspaceRoot, "recovery_preserves_distinct_runtime_and_process_identity");
    recovery.version = 3;
    suite.expect(mothershipVDCWriteRecovery(directory, recovery, &failure) && mothershipVDCReadRecovery(directory, restored) == false,
                 "recovery_rejects_unknown_journal_version");
    String path = {}; mothershipVirtualDatacenterPath(directory, "operation", path);
    ::unlink(path.c_str()); ::rmdir(recoveryDirectory);
  }

  ProdigyPersistentBootState retainedBoot = {};
  retainedBoot.bootstrapConfig.nodeRole = ProdigyBootstrapNodeRole::brain;
  retainedBoot.bootstrapConfig.controlSocketPath = controlSocketPath;
  retainedBoot.bootstrapSshPrivateKeyPath = "/root/.ssh/retained-private-key"_ctv;
  retainedBoot.initialTopology = topology;
  String originalBoot = {}, successorBoot = {};
  renderProdigyPersistentBootStateJSON(retainedBoot, originalBoot);
  recovery.machineIndex = 1;
  recovery.providerArguments[11] = controlSocketPath;
  suite.expect(mothershipVDCPrepareSupersessionBoot(originalBoot, recovery, successorBoot, &failure),
               "recovery_prepares_bound_bootstrap_receipt");
  ProdigyPersistentBootState successorState = {};
  suite.expect(parseProdigyPersistentBootStateJSON(successorBoot, successorState, &failure) &&
               successorState.bootstrapBundleSupersession.operationID == recovery.operationID &&
               successorState.bootstrapBundleSupersession.clusterUUID == recovery.clusterUUID &&
               successorState.bootstrapBundleSupersession.expectedIncompleteWorkerBundleSHA256 == recovery.expectedIncompleteWorkerBundle &&
               successorState.bootstrapBundleSupersession.successorBundleSHA256 == recovery.successorBundle &&
               successorState.bootstrapBundleSupersession.targetControlSocketPath == controlSocketPath &&
               successorState.bootstrapSshPrivateKeyPath == retainedBoot.bootstrapSshPrivateKeyPath &&
               successorState.initialTopology.machines.size() == retainedBoot.initialTopology.machines.size(),
               "recovery_receipt_preserves_retained_boot_configuration");
  recovery.machineIndex = 2;
  suite.expect(mothershipVDCPrepareSupersessionBoot(originalBoot, recovery, successorBoot, &failure) == false,
               "recovery_rejects_bootstrap_receipt_for_worker");
  recovery.machineIndex = 1;
  recovery.providerArguments[11] = "/tmp/another-cluster.sock"_ctv;
  suite.expect(mothershipVDCPrepareSupersessionBoot(originalBoot, recovery, successorBoot, &failure) == false,
               "recovery_rejects_bootstrap_control_identity_mismatch");

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
