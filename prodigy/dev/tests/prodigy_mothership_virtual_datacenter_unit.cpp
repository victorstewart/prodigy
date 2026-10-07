#include <prodigy/mothership/mothership.virtual.datacenter.h>
#include <prodigy/mothership/mothership.virtual.datacenter.recovery.h>
#include <sys/wait.h>

#include <services/debug.h>

#include <cstdlib>
#include <filesystem>
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
  suite.expect(text.find("members_provisioned_path=") != std::string::npos &&
               text.find("while [[ ! -r \"${members_provisioned_path}\" ]]") != std::string::npos &&
               text.find("start_machine 1") != std::string::npos,
               "provider_starts_seed_before_member_receipt");
  suite.expect(text.find("--transport-tls-json-path=${transport_tls_path}") != std::string::npos &&
               text.find("PRODIGY_DEV_SHARED_TRANSPORT_TLS_DIR=") == std::string::npos,
               "provider_requires_canonical_transport_tls_material");
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
datacenter_fragment=1
private4_prefix=10.0.0
private4_subnet=10.0.0.0/24
private6_prefix=fd00:10
private6_subnet=fd00:10::/64
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

static void testTwoPhaseStartGate(TestSuite& suite)
{
  std::string sourcePath = __FILE__;
  const size_t root = sourcePath.rfind("/dev/tests/");
  suite.expect(root != std::string::npos, "phase_gate_fixture_locates_provider_owner");
  if (root == std::string::npos) return;
  sourcePath.resize(root);
  sourcePath += "/mothership/mothership.virtual.datacenter.provider.sh";
  String source = {};
  if (mothershipVDCRead(String(sourcePath.c_str()), source, 1024 * 1024) == false)
  { suite.expect(false, "phase_gate_fixture_reads_provider_owner"); return; }
  std::string text(reinterpret_cast<const char *>(source.data()), source.size());
  size_t begin = text.find("start_initial_runtime()\n{\n");
  size_t end = text.find("\nif [[ \"${adopted_mode}\" -eq 0 ]]", begin);
  if (begin == std::string::npos || end == std::string::npos)
  { suite.expect(false, "phase_gate_fixture_extracts_provider_owner"); return; }
  std::string script = "set -euo pipefail\n" + text.substr(begin, end - begin) + R"TEST(
workspace="$PWD/workspace"
seed_runtime_path="$workspace/seed-runtime"
members_provisioned_path="$workspace/members-provisioned"
machine_count=3
pid=987
machine_pids=()
mkdir -p "$workspace"
start_machine() { local index="$1"; machine_pids[$((index - 1))]=$((100 + index)); printf '%s\n' "$index" >> "$workspace/starts"; }
start_initial_runtime & gate=$!
for _ in $(seq 1 100); do [[ -s "$workspace/starts" ]] && break; sleep 0.01; done
[[ "$(<"$workspace/starts")" == 1 ]]
[[ ! -e "$seed_runtime_path" || "$(<"$seed_runtime_path")" == 101 ]]
printf 'members\n' > "$members_provisioned_path.$$.tmp"
mv -f "$members_provisioned_path.$$.tmp" "$members_provisioned_path"
wait "$gate"
[[ "$(tr '\n' ' ' < "$workspace/starts")" == '1 2 3 ' ]]
rm -f "$workspace/starts" "$members_provisioned_path"
start_initial_runtime & malformed=$!
for _ in $(seq 1 100); do [[ -s "$workspace/starts" ]] && break; sleep 0.01; done
printf 'unexpected\n' > "$members_provisioned_path.$$.tmp"
mv -f "$members_provisioned_path.$$.tmp" "$members_provisioned_path"
if wait "$malformed"; then exit 1; fi
[[ "$(<"$workspace/starts")" == 1 ]]
)TEST";
  char temporary[] = "./vdc-phase-gate-unit.XXXXXX";
  if (::mkdtemp(temporary) == nullptr)
  { suite.expect(false, "phase_gate_fixture_creates_owned_directory"); return; }
  String scriptPath = {};
  mothershipVirtualDatacenterPath(String(temporary), "probe.sh", scriptPath);
  String failure = {};
  bool written = mothershipVirtualDatacenterWriteFile(scriptPath, String(script.c_str()), 0600, &failure);
  pid_t child = written ? ::fork() : -1;
  if (child == 0) { if (::chdir(temporary) != 0) _exit(125); ::execl("/bin/bash", "bash", "probe.sh", static_cast<char *>(nullptr)); _exit(127); }
  int status = 0;
  pid_t waited = -1;
  if (child > 0) do { waited = ::waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
  suite.expect(written && waited == child && child > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "provider_phase_gate_starts_seed_then_requires_valid_member_receipt");
  std::filesystem::remove_all(temporary);
}

static void testUnexpectedRuntimeExitPreservesLiveApplicationCgroup(TestSuite& suite)
{
  std::string sourcePath = __FILE__;
  const size_t root = sourcePath.rfind("/dev/tests/");
  suite.expect(root != std::string::npos, "runtime_exit_guard_locates_provider_owner");
  if (root == std::string::npos) return;
  sourcePath.resize(root);
  sourcePath += "/mothership/mothership.virtual.datacenter.provider.sh";
  String source = {};
  if (mothershipVDCRead(String(sourcePath.c_str()), source, 1024 * 1024) == false)
  { suite.expect(false, "runtime_exit_guard_reads_provider_owner"); return; }
  std::string text(reinterpret_cast<const char *>(source.data()), source.size());
  size_t begin = text.find("machine_application_container_state()\n{\n");
  size_t end = text.find("\nif [[ \"${adopted_mode}\" -eq 0 ]]", begin);
  if (begin == std::string::npos || end == std::string::npos)
  { suite.expect(false, "runtime_exit_guard_extracts_provider_owner"); return; }
  // Execute the real post-exit policy against plain fixture cgroup files and
  // lifecycle mocks. No cgroup mount, process signal, namespace, or provider
  // lifecycle operation occurs in this unit.
  std::string script = "set -euo pipefail\n" + text.substr(begin, end - begin) + R"TEST(
cgroup_root="$PWD/cgroups"
workspace="$PWD/workspace"
machine_count=1
machine_exit_held=()
mkdir -p "$cgroup_root/machine1" "$workspace"
printf 'populated 0\nfrozen 0\n' > "$cgroup_root/machine1/cgroup.events"
calls=()
reset_machine_cgroup() { calls+=(reset); }
start_machine() { calls+=(start); }
publish_runtime() { calls+=(publish); }
# An authoritative populated=0 cgroup restarts.
handle_machine_exit 1 777
[[ "${calls[*]}" == "reset start publish" ]]
[[ ! -e "$workspace/machine-exits.log" ]]
# A retained process holds without reset or replacement.
calls=()
printf 'populated 1\nfrozen 0\n' > "$cgroup_root/machine1/cgroup.events"
handle_machine_exit 1 777
[[ "${#calls[@]}" == 0 && "${machine_exit_held[0]}" == 1 ]]
machine_exit_is_held 1
grep -qx '.*reason=retained-machine-cgroup-populated' "$workspace/machine-exits.log"
# A deliberate fault remains authorized after its marker is removed, even
# when it follows an ordinary hold and descendants remain populated.
printf '777\n' > "$workspace/fault-machine-1"
! machine_exit_is_held 1
handle_machine_exit 1 777
[[ "${#calls[@]}" == 0 && "${machine_exit_held[0]}" == 1 ]]
mv "$workspace/fault-machine-1" "$workspace/fault-machine-reset-1"
! machine_exit_is_held 1
handle_machine_exit 1 777
[[ "${calls[*]}" == "reset start publish" && "${machine_exit_held[0]}" == 0 ]]
[[ ! -e "$workspace/fault-machine-reset-1" ]]
# Missing or malformed authoritative state is not evidence of emptiness.
machine_exit_held=()
calls=()
rm -f "$cgroup_root/machine1/cgroup.events"
handle_machine_exit 1 777
[[ "${#calls[@]}" == 0 && "${machine_exit_held[0]}" == 1 ]]
grep -qx '.*reason=machine-cgroup-state-unavailable' "$workspace/machine-exits.log"
# A stale fault ticket cannot destroy applications owned by a later runtime.
machine_exit_held=()
calls=()
printf 'populated 1\nfrozen 0\n' > "$cgroup_root/machine1/cgroup.events"
printf '999\n' > "$workspace/fault-machine-reset-1"
handle_machine_exit 1 777
[[ "${#calls[@]}" == 0 && "${machine_exit_held[0]}" == 1 ]]
[[ ! -e "$workspace/fault-machine-reset-1" ]]
grep -qx '.*ticketPid=999' "$workspace/machine-exits.log"
# A malformed populated record also holds.
machine_exit_held=()
calls=()
printf 'populated invalid\nfrozen 0\n' > "$cgroup_root/machine1/cgroup.events"
handle_machine_exit 1 777
[[ "${#calls[@]}" == 0 && "${machine_exit_held[0]}" == 1 ]]
grep -qx '.*reason=machine-cgroup-state-unavailable' "$workspace/machine-exits.log"
)TEST";
  char temporary[] = "./vdc-runtime-exit-guard-unit.XXXXXX";
  if (::mkdtemp(temporary) == nullptr)
  { suite.expect(false, "runtime_exit_guard_creates_owned_directory"); return; }
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
               "runtime_exit_policy_holds_live_or_indeterminate_cgroups_and_restarts_only_empty_machine");
  std::error_code error;
  std::filesystem::remove_all(temporary, error);
}

static void testFaultDatacenterBindsResetTicketToKilledPID(TestSuite& suite)
{
  std::string sourcePath = __FILE__;
  const size_t root = sourcePath.rfind("/dev/tests/");
  suite.expect(root != std::string::npos, "fault_ticket_fixture_locates_provider_owner");
  if (root == std::string::npos) return;
  sourcePath.resize(root);
  sourcePath += "/mothership/mothership.virtual.datacenter.provider.sh";
  String source = {};
  if (mothershipVDCRead(String(sourcePath.c_str()), source, 1024 * 1024) == false)
  { suite.expect(false, "fault_ticket_fixture_reads_provider_owner"); return; }
  std::string text(reinterpret_cast<const char *>(source.data()), source.size());
  size_t begin = text.find("fault_datacenter()\n{\n");
  size_t end = text.find("\nprobe_datacenter()\n", begin);
  if (begin == std::string::npos || end == std::string::npos)
  { suite.expect(false, "fault_ticket_fixture_extracts_provider_owner"); return; }
  // Execute the real fault issuer with process, network, and delay operations
  // mocked. This verifies its ticket is atomically derived before the kill.
  std::string script = "set -euo pipefail\n" + text.substr(begin, end - begin) + R"TEST(
workspace="$PWD/workspace"
mkdir -p "$workspace"
printf '44\n' > "$workspace/virtual-datacenter.pid"
printf '777\n' > "$workspace/virtual-datacenter.runtime"
valid_workspace() { [[ "$1" == "$workspace" ]]; }
provider_process() { [[ "$1" == 44 && "$2" == "$workspace" ]]; }
runtime_identity_for_workspace() { printf '44\n'; }
validate_machine_indices() { [[ "$1" == 1 && "$2" == 1 ]]; }
command() { return 0; }
kill() {
  if [[ "$1" == -0 && "$2" == 888 && "$#" == 2 ]]; then return 0; fi
  if [[ "$1" == -KILL && "$2" == -- && "$3" == -777 && "$#" == 3 ]]; then
    printf '%s\n' "$*" >> "$workspace/kills"; return 0
  fi
  if [[ "$1" == -KILL && "$2" == 777 && "$#" == 2 ]]; then
    printf '%s\n' "$*" >> "$workspace/kills"; return 0
  fi
  return 1
}
sleep_milliseconds() { printf '888\n' > "$workspace/virtual-datacenter.runtime"; }
fault_datacenter "$workspace" crash 1 1 0 0 0
[[ "$(<"$workspace/kills")" == $'-KILL -- -777\n-KILL 777' ]]
[[ "$(<"$workspace/fault-machine-reset-1")" == 777 ]]
[[ ! -e "$workspace/fault-machine-1" ]]
)TEST";
  char temporary[] = "./vdc-fault-ticket-unit.XXXXXX";
  if (::mkdtemp(temporary) == nullptr)
  { suite.expect(false, "fault_ticket_fixture_creates_owned_directory"); return; }
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
               "fault_issuer_binds_post_duration_reset_ticket_to_exact_killed_runtime_pid");
  std::error_code error;
  std::filesystem::remove_all(temporary, error);
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
  testTwoPhaseStartGate(suite);
  testUnexpectedRuntimeExitPreservesLiveApplicationCgroup(suite);
  testFaultDatacenterBindsResetTicketToKilledPID(suite);
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

  MothershipProdigyCluster spareCluster = cluster;
  spareCluster.test.machineCount = 4;
  spareCluster.test.spareMachineCount = 1;
  spareCluster.bootstrapSshUser = defaultMothershipClusterSSHUser();
  spareCluster.bootstrapSshPrivateKeyPath = prodigyDefaultBootstrapSSHPrivateKeyPath();
  spareCluster.bootstrapSshHostKeyPackage.publicKeyOpenSSH.assign("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture prodigy-test"_ctv);
  ClusterTopology spareTopology = {};
  suite.expect(mothershipBuildVirtualDatacenterTopology(spareCluster, spareTopology, &failure) &&
                   spareTopology.machines.size() == 3 && clusterTopologyBrainCount(spareTopology) == 2,
               "spare_topology_excludes_final_machine_from_initial_members");
  suite.expect(spareTopology.machines.size() == 3 && containsAddress(spareTopology.machines.back().addresses.privateAddresses, "10.0.0.12", 24),
               "spare_topology_keeps_last_initial_machine_address");
  ClusterMachine spareMachine = {};
  suite.expect(mothershipBuildVirtualDatacenterSpareMachine(spareCluster, spareMachine, &failure),
               "spare_descriptor_builds");
  suite.expect(spareMachine.uuid == 0 && spareMachine.source == ClusterMachineSource::adopted &&
                   spareMachine.backing == ClusterMachineBacking::owned && spareMachine.isBrain == false &&
                   spareMachine.hasCloud == false && spareMachine.ssh.address.equals("10.0.0.13"_ctv) &&
                   spareMachine.ssh.port == 22 && spareMachine.ssh.user.equals(defaultMothershipClusterSSHUser()) &&
                   spareMachine.ssh.privateKeyPath.equals(prodigyDefaultBootstrapSSHPrivateKeyPath()) &&
                   spareMachine.ssh.hostPublicKeyOpenSSH.equals(spareCluster.bootstrapSshHostKeyPackage.publicKeyOpenSSH),
               "spare_descriptor_is_ordinary_owned_ssh_adoption_candidate");
  MothershipProdigyCluster malformedSpare = spareCluster;
  malformedSpare.bootstrapSshHostKeyPackage.publicKeyOpenSSH.clear();
  suite.expect(!mothershipBuildVirtualDatacenterSpareMachine(malformedSpare, spareMachine, &failure),
               "spare_descriptor_rejects_missing_pinned_host_key");
  malformedSpare = spareCluster;
  malformedSpare.test.spareMachineCount = 0;
  suite.expect(!mothershipBuildVirtualDatacenterSpareMachine(malformedSpare, spareMachine, &failure),
               "spare_descriptor_rejects_absent_spare_shape");

  MothershipProdigyCluster independentCluster = cluster;
  independentCluster.datacenterFragment = 2;
  ClusterTopology independentTopology = {};
  suite.expect(mothershipBuildVirtualDatacenterTopology(independentCluster, independentTopology, &failure),
               "build_independent_fragment_topology");
  suite.expect(containsAddress(independentTopology.machines[0].addresses.privateAddresses, "10.0.1.10", 24) &&
                   containsAddress(independentTopology.machines[0].addresses.privateAddresses, "fd00:10:1::a", 64),
               "independent_fragment_uses_distinct_private_network_domain");
  String independentControlSocketPath = {};
  mothershipResolveTestClusterControlSocketPath(independentCluster, independentControlSocketPath);
  suite.expect(independentControlSocketPath.equals("/tmp/prodigy-vdc-0x1234-d2/mothership.sock"_ctv),
               "independent_fragment_binds_provider_control_path");

  ProdigyRuntimeEnvironmentConfig runtimeEnvironment = {};
  AddMachines bootstrapRequest = {};
  bootstrapRequest.clusterUUID = cluster.clusterUUID;
  bootstrapRequest.controlSocketPath = controlSocketPath;
  ClusterTopology seedTopology = topology;
  seedTopology.machines.erase(seedTopology.machines.begin() + 1, seedTopology.machines.end());
  seedTopology.machines[0].uuid = 0x4a01;
  suite.expect(mothershipAssignVirtualDatacenterMachineUUIDs(seedTopology, topology, &failure),
               "bootstrap_members_preallocate_durable_identities");
  suite.expect(topology.machines[0].uuid == seedTopology.machines[0].uuid &&
                   topology.machines[1].uuid != 0 && topology.machines[2].uuid != 0 &&
                   topology.machines[0].uuid != topology.machines[1].uuid &&
                   topology.machines[0].uuid != topology.machines[2].uuid &&
                   topology.machines[1].uuid != topology.machines[2].uuid,
               "bootstrap_members_preserve_seed_and_allocate_distinct_peer_identities");
  const ClusterTopology assignedTopology = topology;
  {
    ProdigyInitialTransportCredentialProjection projection, independentProjection;
    suite.expect(mothershipBuildInitialTransportCredentialProjection(cluster.clusterUUID, topology, projection, &failure) &&
                     projection.ledger.size() == 5 && projection.authority.valid(),
                 "aegis_initial_cohort_has_brain_and_hosted_neuron_scopes");
    suite.expect(mothershipBuildInitialTransportCredentialProjection(cluster.clusterUUID + 1, topology, independentProjection, &failure) &&
                     CRYPTO_memcmp(projection.authority.root, independentProjection.authority.root, sizeof(projection.authority.root)) != 0,
                 "aegis_independent_clusters_have_independent_roots");
    for (const auto& machine : topology.machines)
    {
      String bootJSON, privateJSON;
      ProdigyPersistentLocalBrainState local;
      bool built = prodigyBuildRemoteBootstrapBootMaterial(machine, bootstrapRequest, topology, runtimeEnvironment,
                                                           bootJSON, privateJSON, &failure, &projection);
      bool parsed = built && parseProdigyPersistentLocalBrainStateJSON(privateJSON, local, &failure);
      suite.expect(parsed && local.transportCredentials.enabled && local.transportCredentials.self.nodeUUID == machine.uuid &&
                       (local.transportCredentials.self.role == ProdigyTransportCredentialNodeRole::brain) == machine.isBrain &&
                       local.transportCredentialAuthorityRoot.valid() == machine.isBrain &&
                       prodigyLocalTransportCredentialStateValid(local),
                   "aegis_boot_material_binds_machine_role_and_keeps_root_brain_only");
    }
    ClusterTopology invalid = topology;
    invalid.machines.back().uuid = invalid.machines.front().uuid;
    suite.expect(!mothershipBuildInitialTransportCredentialProjection(cluster.clusterUUID, invalid, independentProjection, &failure) &&
                     !independentProjection.authority.valid() && independentProjection.ledger.empty(),
                 "aegis_initial_cohort_rejects_duplicate_machine_without_partial_secret");
  }
  suite.expect(mothershipAssignVirtualDatacenterMachineUUIDs(seedTopology, topology, &failure) &&
                   topology == assignedTopology,
               "bootstrap_member_identity_assignment_retries_without_changing_published_ids");
  ClusterTopology duplicateUUIDTopology = topology;
  duplicateUUIDTopology.machines[2].uuid = duplicateUUIDTopology.machines[1].uuid;
  suite.expect(mothershipAssignVirtualDatacenterMachineUUIDs(seedTopology, duplicateUUIDTopology, &failure) == false,
               "bootstrap_member_identity_assignment_rejects_duplicate_existing_ids");
  ClusterTopology ambiguousSeedTopology = topology;
  ambiguousSeedTopology.machines[0].uuid = 0;
  ambiguousSeedTopology.machines[1] = ambiguousSeedTopology.machines[0];
  suite.expect(mothershipAssignVirtualDatacenterMachineUUIDs(seedTopology, ambiguousSeedTopology, &failure) == false &&
                   ambiguousSeedTopology.machines[0].uuid == 0 && ambiguousSeedTopology.machines[1].uuid == 0,
               "bootstrap_member_identity_assignment_rejects_ambiguous_seed_without_partial_assignment");
  ClusterTopology seedUUIDCollisionTopology = topology;
  seedUUIDCollisionTopology.machines[0].uuid = 0;
  seedUUIDCollisionTopology.machines[1].uuid = seedTopology.machines[0].uuid;
  suite.expect(mothershipAssignVirtualDatacenterMachineUUIDs(seedTopology, seedUUIDCollisionTopology, &failure) == false &&
                   seedUUIDCollisionTopology.machines[0].uuid == 0,
               "bootstrap_member_identity_assignment_rejects_member_id_that_conflicts_with_zero_id_seed");
  String seedBootJSON = {}, seedTLSJSON = {}, peerBootJSON = {}, peerTLSJSON = {};
  suite.expect(prodigyBuildRemoteBootstrapBootMaterial(seedTopology.machines[0], bootstrapRequest, seedTopology,
                                                       runtimeEnvironment, seedBootJSON, seedTLSJSON, &failure),
               "bootstrap_seed_material_builds");
  ProdigyPersistentBootState seedBoot = {};
  ProdigyPersistentLocalBrainState seedTLS = {};
  suite.expect(parseProdigyPersistentBootStateJSON(seedBootJSON, seedBoot, &failure) &&
               parseProdigyPersistentLocalBrainStateJSON(seedTLSJSON, seedTLS, &failure),
               "bootstrap_seed_material_parses");
  suite.expect(seedBoot.initialTopology.machines.size() == 1 &&
               seedBoot.bootstrapConfig.bootstrapPeers.empty(),
               "bootstrap_seed_starts_alone");
  suite.expect(seedTLS.ownerClusterUUID == cluster.clusterUUID && seedTLS.transportTLSConfigured(),
               "bootstrap_seed_uses_configured_cluster_tls_authority");
  suite.expect(prodigyBuildRemoteBootstrapBootMaterial(topology.machines[1], bootstrapRequest, topology,
                                                       runtimeEnvironment, peerBootJSON, peerTLSJSON, &failure),
               "bootstrap_peer_material_builds");
  ProdigyPersistentBootState peerBoot = {};
  ProdigyPersistentLocalBrainState peerTLS = {};
  suite.expect(parseProdigyPersistentBootStateJSON(peerBootJSON, peerBoot, &failure) &&
               parseProdigyPersistentLocalBrainStateJSON(peerTLSJSON, peerTLS, &failure),
               "bootstrap_peer_material_parses");
  suite.expect(peerBoot.initialTopology.machines.size() == topology.machines.size() &&
               peerBoot.bootstrapConfig.bootstrapPeers.size() == clusterTopologyBrainCount(topology) - 1,
               "bootstrap_peer_receives_full_membership_before_admission");
  suite.expect(peerTLS.ownerClusterUUID == seedTLS.ownerClusterUUID && peerTLS.uuid != seedTLS.uuid &&
               peerTLS.transportTLS.clusterRootCertPem.equals(seedTLS.transportTLS.clusterRootCertPem),
               "bootstrap_peer_shares_seed_authority_with_distinct_identity");
  suite.expect(seedTLS.uuid == topology.machines[0].uuid &&
                   peerTLS.uuid == topology.machines[1].uuid &&
                   peerBoot.initialTopology.machines[0].uuid == topology.machines[0].uuid &&
                   peerBoot.initialTopology.machines[1].uuid == topology.machines[1].uuid &&
                   peerBoot.initialTopology.machines[2].uuid == topology.machines[2].uuid,
               "bootstrap_peer_tls_and_boot_topology_use_durable_member_identities");
  Vector<ClusterMachine> readyMachines = {};
  for (const ClusterMachine& machine : topology.machines)
  {
    if (machine.sameIdentityAs(seedTopology.machines[0]) == false) readyMachines.push_back(machine);
  }
  suite.expect(readyMachines.size() == 2 && readyMachines[0].uuid == topology.machines[1].uuid &&
                   readyMachines[1].uuid == topology.machines[2].uuid,
               "bootstrap_members_ready_request_carries_preallocated_tls_identities");
  for (uint32_t index = 1; index < topology.machines.size(); ++index)
  {
    String memberBootJSON = {}, memberTLSJSON = {};
    ProdigyPersistentBootState memberBoot = {};
    ProdigyPersistentLocalBrainState memberTLS = {};
    const bool built = prodigyBuildRemoteBootstrapBootMaterial(topology.machines[index], bootstrapRequest, topology,
                                                                runtimeEnvironment, memberBootJSON, memberTLSJSON, &failure);
    const bool parsedMember = built && parseProdigyPersistentBootStateJSON(memberBootJSON, memberBoot, &failure) &&
                              parseProdigyPersistentLocalBrainStateJSON(memberTLSJSON, memberTLS, &failure);
    suite.expect(parsedMember && memberTLS.uuid == topology.machines[index].uuid &&
                     memberBoot.initialTopology.machines.size() == topology.machines.size() &&
                     memberBoot.initialTopology.machines[index].uuid == topology.machines[index].uuid,
                 "bootstrap_every_member_tls_identity_matches_ready_identity");
  }

  uint64_t parsed = 0;
  char processState = 0;
  String processStat = "917 (provider ) with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123456 0\n"_ctv;
  suite.expect(mothershipVDCParseStat(processStat, 917, parsed, processState) && parsed == 123456 && processState == 'S',
               "recovery_stat_handles_spaces_and_parentheses");
  suite.expect(mothershipVDCParseStat(processStat, 918, parsed, processState) == false, "recovery_stat_rejects_pid_mismatch");
  suite.expect(mothershipVDCParseStat("917 (truncated)"_ctv, 917, parsed, processState) == false, "recovery_stat_rejects_truncation");
  constexpr char overflow[] = "18446744073709551616";
  suite.expect(mothershipVDCParseUnsigned(overflow, overflow + sizeof(overflow) - 1, parsed) == false, "recovery_identity_rejects_overflow");
  suite.expect(mothershipVDCRecoveryTargetIsSupported(1, 1) == false, "recovery_rejects_only_brain");
  suite.expect(mothershipVDCRecoveryTargetIsSupported(2, 3) == false, "recovery_rejects_second_brain");
  suite.expect(mothershipVDCRecoveryTargetIsSupported(2, 3, false, true), "recovery_allows_test_only_three_brain_follower");
  suite.expect(mothershipVDCRecoveryTargetIsSupported(0, 3, false, true) == false, "recovery_rejects_test_follower_zero_index");
  suite.expect(mothershipVDCRecoveryTargetIsSupported(0, 1) == false, "recovery_rejects_zero_machine_index");
  suite.expect(mothershipVDCRecoveryTargetIsSupported(2, 1), "recovery_allows_worker_after_brains");
  MothershipVDCTestRecoveryFaultPhase testFault = MothershipVDCTestRecoveryFaultPhase::none;
  suite.expect(mothershipVDCTestParseRecoveryFaultPhase("frozen"_ctv, testFault) &&
               testFault == MothershipVDCTestRecoveryFaultPhase::frozen,
               "recovery_accepts_test_fault_at_frozen_transition");
  suite.expect(mothershipVDCTestParseRecoveryFaultPhase("rootInstalled"_ctv, testFault) &&
               testFault == MothershipVDCTestRecoveryFaultPhase::rootInstalled,
               "recovery_accepts_test_fault_after_durable_root_install");
  suite.expect(mothershipVDCTestParseRecoveryFaultPhase("workerReplaced"_ctv, testFault) &&
               testFault == MothershipVDCTestRecoveryFaultPhase::workerReplaced,
               "recovery_accepts_test_fault_after_durable_replacement");
  suite.expect(mothershipVDCTestParseRecoveryFaultPhase("committed"_ctv, testFault) == false &&
               testFault == MothershipVDCTestRecoveryFaultPhase::none,
               "recovery_rejects_unqualified_test_fault_phase");

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
  recovery.testOnlyFollowerReplacement = true;
  recovery.selectedMachineUUID.assign("11111111111111111111111111111111"_ctv);
  recovery.masterMachineUUID.assign("22222222222222222222222222222222"_ctv);
  recovery.witnessMachineUUID.assign("33333333333333333333333333333333"_ctv);
  recovery.preflightReportSHA256.assign("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"_ctv);
  recovery.commissionedBrains[0] = {923, 11, 21, 31};
  recovery.commissionedBrains[1] = {929, 12, 22, 32};
  recovery.commissionedBrains[2] = {937, 13, 23, 33};
  recovery.version = 3;
  suite.expect(mothershipVDCTestFollowerRecoveryMatches(recovery, recovery.clusterUUID, 2,
                                                         recovery.expectedOldBundle, recovery.successorBundle),
               "recovery_accepts_exact_test_follower_retry_binding");
  suite.expect(mothershipVDCTestFollowerRecoveryMatches(recovery, recovery.clusterUUID, 2,
                                                         recovery.successorBundle, recovery.expectedOldBundle) == false,
               "recovery_rejects_test_follower_retry_with_reversed_bundle_binding");
  char recoveryDirectory[] = "./vdc-recovery-unit.XXXXXX";
  const bool directoryCreated = ::mkdtemp(recoveryDirectory) != nullptr;
  suite.expect(directoryCreated, "recovery_creates_scoped_test_directory");
  if (directoryCreated)
  {
    String directory(recoveryDirectory);
    MothershipVDCBundleRecovery legacyRecovery = recovery;
    legacyRecovery.version = 2;
    suite.expect(mothershipVDCWriteRecovery(directory, legacyRecovery, &failure), "recovery_preserves_v2_journal_writer");
    MothershipVDCBundleRecovery restored = recovery;
    suite.expect(mothershipVDCReadRecovery(directory, restored) && restored.version == 2 &&
                 restored.expectedOldBundle == legacyRecovery.expectedOldBundle && restored.testOnlyFollowerReplacement == false &&
                 restored.selectedMachineUUID.empty() && restored.preflightReportSHA256.empty() &&
                 restored.commissionedBrains[0].pid == 0,
                 "recovery_reads_existing_v2_journal_without_v3_tail");
    suite.expect(mothershipVDCWriteRecovery(directory, recovery, &failure), "recovery_durably_writes_intent");
    suite.expect(mothershipVDCReadRecovery(directory, restored) && restored.clusterUUID == recovery.clusterUUID &&
                 restored.operationID == recovery.operationID && restored.runtimeIdentity == recovery.runtimeIdentity &&
                 restored.machineIndex == 2 && restored.phase == MothershipVDCRecoveryPhase::ready &&
                 mothershipVDCSameProcess(restored.supervisor, recovery.supervisor) &&
                 mothershipVDCSameProcess(restored.worker, recovery.worker) &&
                 mothershipVDCSameProcess(restored.adopter, recovery.adopter) &&
                 restored.expectedOldBundle == recovery.expectedOldBundle && restored.successorBundle == recovery.successorBundle &&
                 restored.expectedIncompleteWorkerBundle == recovery.expectedIncompleteWorkerBundle &&
                 restored.previousBootSHA256 == recovery.previousBootSHA256 && restored.successorBootSHA256 == recovery.successorBootSHA256 &&
                 restored.providerArguments[0] == cluster.test.workspaceRoot && restored.testOnlyFollowerReplacement &&
                 restored.selectedMachineUUID == recovery.selectedMachineUUID && restored.masterMachineUUID == recovery.masterMachineUUID &&
                 restored.witnessMachineUUID == recovery.witnessMachineUUID && restored.preflightReportSHA256 == recovery.preflightReportSHA256 &&
                 mothershipVDCSameProcess(restored.commissionedBrains[2], recovery.commissionedBrains[2]),
                 "recovery_preserves_test_follower_preflight_and_process_identity");
    recovery.version = 4;
    recovery.retainedTCX[0] = {7, 46, 123, 456, 800, 801, {1,2,3,4,5,6,7,8}};
    recovery.retainedTCX[1] = {7, 47, 124, 457, 800, 801, {8,7,6,5,4,3,2,1}};
    suite.expect(mothershipVDCWriteRecovery(directory, recovery, &failure) && mothershipVDCReadRecovery(directory, restored) &&
                 restored.version == 4 && restored.retainedTCX[0].ifindex == 7 &&
                 restored.retainedTCX[0].attachType == 46 && restored.retainedTCX[0].programID == 123 &&
                 restored.retainedTCX[0].linkID == 456 && restored.retainedTCX[0].programTag[7] == 8 &&
                 restored.retainedTCX[0].wormholeFlowMapID == 800 && restored.retainedTCX[1].wormholePendingFlowMapID == 801 &&
                 restored.retainedTCX[1].linkID == 457 && restored.retainedTCX[1].programTag[7] == 1 &&
                 mothershipVDCTestFollowerRecoveryMatches(restored, recovery.clusterUUID, 2, recovery.expectedOldBundle, recovery.successorBundle),
                 "recovery_preserves_exact_retained_tcx_link_identity");
    recovery.version = 3;
    suite.expect(mothershipVDCWriteRecovery(directory, recovery, &failure) && mothershipVDCReadRecovery(directory, restored) &&
                 restored.retainedTCX[0].linkID == 0 && restored.retainedTCX[1].programID == 0,
                 "recovery_does_not_invent_retained_links_for_old_journal");
    recovery.version = 5;
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
