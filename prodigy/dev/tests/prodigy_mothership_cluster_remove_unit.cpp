#include <prodigy/mothership/mothership.cluster.remove.h>
#include <services/debug.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

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
      std::fprintf(stderr, "FAIL: %s\n", name);
      failed += 1;
    }
  }
};

static MothershipProdigyClusterMachine makeAdoptedMachine(const String& sshAddress, bool isBrain, ClusterMachineBacking backing = ClusterMachineBacking::owned)
{
  MothershipProdigyClusterMachine machine = {};
  machine.source = MothershipClusterMachineSource::adopted;
  machine.backing = backing;
  machine.kind = MachineConfig::MachineKind::vm;
  machine.lifetime = (backing == ClusterMachineBacking::cloud) ? MachineLifetime::reserved : MachineLifetime::owned;
  machine.isBrain = isBrain;
  machine.ssh.address = sshAddress;
  machine.ssh.port = 22;
  machine.ssh.user = "root"_ctv;
  machine.ssh.privateKeyPath = "/root/.ssh/test"_ctv;
  prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, sshAddress);
  if (backing == ClusterMachineBacking::cloud)
  {
    machine.cloud.schema = "vm"_ctv;
    machine.cloud.cloudID = sshAddress;
    machine.cloud.providerMachineType = "provider-type"_ctv;
  }
  return machine;
}

static ClusterMachine makeTopologyMachine(const String& sshAddress, ClusterMachineSource source, ClusterMachineBacking backing)
{
  ClusterMachine machine = {};
  machine.source = source;
  machine.backing = backing;
  machine.kind = MachineConfig::MachineKind::vm;
  machine.lifetime = (backing == ClusterMachineBacking::cloud) ? MachineLifetime::reserved : MachineLifetime::owned;
  machine.isBrain = true;
  machine.ssh.address = sshAddress;
  machine.ssh.port = 22;
  machine.ssh.user = "root"_ctv;
  machine.ssh.privateKeyPath = "/root/.ssh/test"_ctv;
  prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, sshAddress);
  if (backing == ClusterMachineBacking::cloud)
  {
    machine.cloud.schema = "vm"_ctv;
    machine.cloud.cloudID = sshAddress;
    machine.cloud.providerMachineType = "provider-type"_ctv;
  }
  return machine;
}

class FakeRemoveHooks final : public MothershipClusterRemoveHooks {
public:

  bool failDNSCleanup = false;
  bool failAdoptedWipe = false;
  uint32_t dnsRecordsToRemove = 0;

  uint32_t removeDNSCalls = 0;
  uint32_t stopTestClusterCalls = 0;
  uint32_t stopLocalCalls = 0;
  uint32_t stopAdoptedCalls = 0;
  uint32_t destroyCreatedCalls = 0;

  Vector<String> stoppedAdoptedSSHAddresses = {};
  Vector<String> destroyedCreatedCloudIDs = {};
  Vector<String> callOrder = {};

  bool removeDNSBindings(const MothershipProdigyCluster& cluster, uint32_t& removed, String *failure = nullptr) override
  {
    (void)cluster;
    removeDNSCalls += 1;
    callOrder.push_back("dns"_ctv);
    if (failDNSCleanup)
    {
      if (failure)
      {
        failure->assign("dns cleanup failed"_ctv);
      }
      return false;
    }

    removed = dnsRecordsToRemove;
    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  bool stopTestCluster(const MothershipProdigyCluster& cluster, String *failure = nullptr) override
  {
    (void)cluster;
    stopTestClusterCalls += 1;
    callOrder.push_back("test"_ctv);
    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  bool stopAndWipeLocalMachine(const MothershipProdigyCluster& cluster, String *failure = nullptr) override
  {
    (void)cluster;
    stopLocalCalls += 1;
    callOrder.push_back("local"_ctv);
    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  bool stopAndWipeAdoptedMachine(const MothershipProdigyCluster& cluster, const MothershipProdigyClusterMachine& machine, String *failure = nullptr) override
  {
    (void)cluster;
    stopAdoptedCalls += 1;
    stoppedAdoptedSSHAddresses.push_back(machine.ssh.address);
    callOrder.push_back("adopted"_ctv);
    if (failAdoptedWipe)
    {
      if (failure)
      {
        failure->assign("adopted wipe failed"_ctv);
      }
      return false;
    }

    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  bool destroyCreatedCloudMachines(const MothershipProdigyCluster& cluster, const Vector<ClusterMachine>& machines, uint32_t& destroyed, String *failure = nullptr) override
  {
    (void)cluster;
    destroyCreatedCalls += 1;
    callOrder.push_back("destroy"_ctv);
    destroyed = uint32_t(machines.size());
    for (const ClusterMachine& machine : machines)
    {
      destroyedCreatedCloudIDs.push_back(machine.cloud.cloudID);
    }
    if (failure)
    {
      failure->clear();
    }
    return true;
  }
};

static bool equalStrings(const Vector<String>& values, std::initializer_list<const char *> expected)
{
  if (values.size() != expected.size())
  {
    return false;
  }

  uint32_t index = 0;
  for (const char *item : expected)
  {
    String expectedValue = {};
    expectedValue.assign(item);
    if (values[index] != expectedValue)
    {
      return false;
    }

    index += 1;
  }

  return true;
}

static bool stringContains(const String& haystack, const char *needle)
{
  String haystackText = {};
  haystackText.assign(haystack);
  return std::strstr(haystackText.c_str(), needle) != nullptr;
}

static std::string shellQuote(const std::string& value)
{
  std::string quoted = "'";
  for (char c : value)
  {
    if (c == '\'') quoted += "'\\''";
    else quoted += c;
  }
  return quoted + "'";
}

static void replaceAll(std::string& value, const std::string& from, const std::string& to)
{
  size_t offset = 0;
  while ((offset = value.find(from, offset)) != std::string::npos)
  {
    value.replace(offset, from.size(), to);
    offset += to.size();
  }
}

static bool runStorageCleanupScript(const String& rendered, const char *scenario, bool expectSuccess, bool expectUnmount, bool expectWipe, bool expectContainerKill = false)
{
  char templatePath[] = "/tmp/prodigy-remove-unit-XXXXXX";
  char *rootPath = ::mkdtemp(templatePath);
  if (rootPath == nullptr) return false;
  std::string root(rootPath);
  std::string fake = root + "/fake";
  std::string state = root + "/state";
  std::string containers = root + "/containers";
  std::string cgroups = root + "/cgroups";
  std::string run = root + "/run";
  ::mkdir(fake.c_str(), 0700); ::mkdir(state.c_str(), 0700); ::mkdir(containers.c_str(), 0700); ::mkdir(cgroups.c_str(), 0700); ::mkdir(run.c_str(), 0700);
  if (std::string(scenario) != "external") std::ofstream(state + "/containers.btrfs.loop").put('x');
  auto write = [&](const char *name, const char *body) { std::ofstream file(fake + "/" + name); file << "#!/bin/sh\n" << body; file.close(); ::chmod((fake + "/" + name).c_str(), 0700); };
  write("systemctl", R"SH(case "$*" in
  *LoadState*) echo loaded;;
  *ActiveState*) { [ "$MOCK_SCENARIO" = stoppedfailed ] || [ "$MOCK_SCENARIO" = failedrunning ]; } && echo failed || echo inactive;;
  *MainPID*) [ "$MOCK_SCENARIO" = failedrunning ] && echo 935 || echo 0;;
  *stop*) echo stop >>"$MOCK_ROOT/log"; [ "$MOCK_SCENARIO" = stopfail ] && exit 1;;
esac
exit 0
)SH");
  write("mountpoint", "[ \"$2\" = \"$MOCK_CONTAINERS\" ] && [ -f \"$MOCK_ROOT/mounted\" ]\n");
  write("findmnt", R"SH(case "$*" in
  *FSTYPE*) echo btrfs;;
  *--target*) [ "$MOCK_SCENARIO" = external ] && echo /dev/sda || echo /dev/loop7;;
  *) echo /dev/sda; [ "$MOCK_SCENARIO" = elsewhere ] && echo /dev/loop7;;
esac
exit 0
)SH");
  write("losetup", R"SH(if [ "$1" = -j ]; then
  [ "$MOCK_SCENARIO" = lookupfail ] && exit 1;
  [ "$MOCK_SCENARIO" = ambiguous ] && exit 0;
  [ -f "$MOCK_ROOT/associated" ] && echo /dev/loop7;
else
  echo detach >>"$MOCK_ROOT/log";
  /bin/rm -f "$MOCK_ROOT/associated";
fi
exit 0
)SH");
  write("umount", R"SH(echo umount >>"$MOCK_ROOT/log";
[ "$MOCK_SCENARIO" = umountfail ] && exit 1;
/bin/rm -f "$MOCK_ROOT/mounted";
[ "$MOCK_SCENARIO" = autoclear ] && /bin/rm -f "$MOCK_ROOT/associated";
exit 0
)SH");
  write("rm", "echo rm >>\"$MOCK_ROOT/log\"\n");
  write("sleep", "exit 0\n");
  write("cat", R"SH(case "$1" in
  "$MOCK_CGROUP"/*.slice/leaf/cgroup.procs)
    case "$MOCK_SCENARIO" in
      cgroup-populated)
        if [ -s "${1%/cgroup.procs}/cgroup.kill" ]; then
          if [ ! -f "$MOCK_ROOT/cgroup-kill-logged" ]; then echo kill >>"$MOCK_ROOT/log"; : >"$MOCK_ROOT/cgroup-kill-logged"; fi;
        else
          echo 123;
        fi;;
      cgroup-remains) echo 123;;
      cgroup-read-fail) exit 1;;
      *) exec /bin/cat "$@";;
    esac;;
  *) exec /bin/cat "$@";;
esac
)SH");
  std::string leaf = cgroups + "/retained.slice/leaf";
  if (std::string(scenario) == "cgroup-populated")
  {
    ::mkdir((cgroups + "/retained.slice").c_str(), 0700); ::mkdir(leaf.c_str(), 0700);
    std::ofstream(leaf + "/cgroup.kill");
    std::ofstream(leaf + "/cgroup.procs"); // Virtual cgroup files report zero stat size.
  }
  else if (std::string(scenario) == "cgroup-kill-fail")
  {
    ::mkdir((cgroups + "/retained.slice").c_str(), 0700); ::mkdir(leaf.c_str(), 0700); ::mkdir((leaf + "/cgroup.kill").c_str(), 0700);
    std::ofstream(leaf + "/cgroup.procs"); // Virtual cgroup files report zero stat size.
  }
  else if (std::string(scenario) == "cgroup-remains" || std::string(scenario) == "cgroup-read-fail")
  {
    ::mkdir((cgroups + "/retained.slice").c_str(), 0700); ::mkdir(leaf.c_str(), 0700);
    std::ofstream(leaf + "/cgroup.kill");
    std::ofstream(leaf + "/cgroup.procs"); // Virtual cgroup files report zero stat size.
  }
  std::ofstream(root + "/mounted").put('x');
  if (std::string(scenario) != "external") std::ofstream(root + "/associated").put('x');
  String renderedCopy = rendered;
  std::string command(renderedCopy.c_str());
  replaceAll(command, "/var/lib/prodigy/containers.btrfs.loop", "@OWNED_LOOP_IMAGE@");
  replaceAll(command, "/sys/fs/cgroup/containers.slice", cgroups);
  replaceAll(command, "/var/lib/prodigy", state);
  replaceAll(command, "/containers", containers);
  replaceAll(command, "/run/prodigy", run);
  replaceAll(command, "@OWNED_LOOP_IMAGE@", state + "/containers.btrfs.loop");
  // A missing mock must fail closed rather than invoke a real host command.
  std::string invoke = "PATH=" + shellQuote(fake) + " MOCK_ROOT=" + shellQuote(root) + " MOCK_CONTAINERS=" + shellQuote(containers) + " MOCK_CGROUP=" + shellQuote(cgroups) + " MOCK_SCENARIO=" + shellQuote(scenario) + " /bin/sh -c " + shellQuote(command);
  bool success = ::system(invoke.c_str()) == 0;
  std::ifstream log(root + "/log"); std::string lines((std::istreambuf_iterator<char>(log)), {});
  const size_t stop = lines.find("stop");
  const size_t kill = lines.find("kill");
  const size_t unmount = lines.find("umount");
  const size_t wipe = lines.find("rm");
  bool killOrder = expectContainerKill == false || (kill != std::string::npos && unmount != std::string::npos && wipe != std::string::npos && stop != std::string::npos && stop < kill && kill < unmount && unmount < wipe);
  bool okay = success == expectSuccess && (unmount != std::string::npos) == expectUnmount && (wipe != std::string::npos) == expectWipe && killOrder;
  (void)::system(("/bin/rm -rf " + shellQuote(root)).c_str());
  return okay;
}

int main(void)
{
  TestSuite suite;

  {
    String command = {};
    mothershipBuildProdigyStateWipeCommand("/var/lib/prodigy/state"_ctv, command);
    suite.expect(runStorageCleanupScript(command, "autoclear", true, true, true), "remove_owned_loop_autoclear_before_wipe");
    suite.expect(runStorageCleanupScript(command, "detach", true, true, true), "remove_owned_loop_explicit_detach_before_wipe");
    suite.expect(runStorageCleanupScript(command, "external", true, false, true), "remove_external_containers_preserved");
    suite.expect(runStorageCleanupScript(command, "ambiguous", false, false, false), "remove_ambiguous_loop_refuses_wipe");
    suite.expect(runStorageCleanupScript(command, "umountfail", false, true, false), "remove_failed_unmount_refuses_wipe");
    suite.expect(runStorageCleanupScript(command, "stopfail", false, false, false), "remove_failed_stop_refuses_wipe");
    suite.expect(runStorageCleanupScript(command, "stoppedfailed", true, true, true), "remove_stopped_failed_unit_allows_owned_cleanup");
    suite.expect(runStorageCleanupScript(command, "failedrunning", false, false, false), "remove_failed_unit_with_live_pid_refuses_cleanup");
    suite.expect(runStorageCleanupScript(command, "lookupfail", false, false, false), "remove_failed_loop_lookup_refuses_wipe");
    suite.expect(runStorageCleanupScript(command, "elsewhere", false, true, false), "remove_loop_mounted_elsewhere_refuses_wipe");
    suite.expect(runStorageCleanupScript(command, "cgroup-populated", true, true, true, true), "remove_populated_owned_cgroup_kills_before_storage_wipe");
    suite.expect(runStorageCleanupScript(command, "cgroup-kill-fail", false, false, false), "remove_owned_cgroup_kill_failure_refuses_storage_wipe");
    suite.expect(runStorageCleanupScript(command, "cgroup-remains", false, false, false), "remove_owned_cgroup_remaining_processes_refuse_storage_wipe");
    suite.expect(runStorageCleanupScript(command, "cgroup-read-fail", false, false, false), "remove_owned_cgroup_read_failure_refuses_storage_wipe");
  }

  {
    MothershipProdigyCluster cluster = {};
    cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
    cluster.remoteProdigyPath = "/srv/prodigy/current"_ctv;
    cluster.controls.push_back(MothershipProdigyClusterControl {
        .kind = MothershipClusterControlKind::unixSocket,
        .path = "/srv/prodigy/run/control.sock"_ctv});

    String command = {};
    mothershipBuildRemoteProdigyUninstallCommand(cluster, command);
    suite.expect(stringContains(command, "systemctl show --property=LoadState --value prodigy") && stringContains(command, "failed to stop prodigy"), "remove_remote_uninstall_stops_and_verifies");
    suite.expect(stringContains(command, "/etc/systemd/system/prodigy.service"), "remove_remote_uninstall_removes_unit");
    suite.expect(stringContains(command, "/srv/prodigy/current"), "remove_remote_uninstall_removes_install_root");
    suite.expect(stringContains(command, "/srv/prodigy/current.new"), "remove_remote_uninstall_removes_install_root_temp");
    suite.expect(stringContains(command, "/srv/prodigy/current.prev"), "remove_remote_uninstall_removes_install_root_previous");
    suite.expect(stringContains(command, "/srv/prodigy/prodigy.service.tmp"), "remove_remote_uninstall_removes_unit_temp");
    suite.expect(stringContains(command, "/srv/prodigy/prodigy.bundle.tar.zst.tmp"), "remove_remote_uninstall_removes_bundle_temp");
    suite.expect(stringContains(command, "/srv/prodigy/run/control.sock"), "remove_remote_uninstall_removes_control_socket");
    suite.expect(stringContains(command, "/root/prodigy.bundle.new.tar.zst"), "remove_remote_uninstall_removes_staged_bundle");
    suite.expect(stringContains(command, "/run/prodigy /var/lib/prodigy /var/log/prodigy"), "remove_remote_uninstall_removes_runtime_state_and_logs");
    suite.expect(stringContains(command, "systemctl daemon-reload || true; systemctl reset-failed prodigy || true"), "remove_remote_uninstall_reloads_systemd");
  }

  {
    MothershipProdigyCluster cluster = {};
    cluster.deploymentMode = MothershipClusterDeploymentMode::test;

    FakeRemoveHooks hooks = {};
    MothershipClusterRemoveSummary summary = {};
    String failure = {};
    bool ok = mothershipRemoveClusterRuntime(cluster, hooks, summary, &failure);
    suite.expect(ok, "remove_test_cluster_ok");
    suite.expect(failure.size() == 0, "remove_test_cluster_no_failure");
    suite.expect(hooks.removeDNSCalls == 1, "remove_test_cluster_dns_cleanup_called_once");
    suite.expect(hooks.stopTestClusterCalls == 1, "remove_test_cluster_stops_runner");
    suite.expect(hooks.stopLocalCalls == 0, "remove_test_cluster_no_local_wipe");
    suite.expect(hooks.stopAdoptedCalls == 0, "remove_test_cluster_no_adopted_wipe");
    suite.expect(hooks.destroyCreatedCalls == 0, "remove_test_cluster_no_cloud_destroy");
    suite.expect(equalStrings(hooks.callOrder, {"dns", "test"}), "remove_test_cluster_call_order");
  }

  {
    MothershipProdigyCluster cluster = {};
    cluster.deploymentMode = MothershipClusterDeploymentMode::local;
    cluster.includeLocalMachine = true;
    cluster.machines.push_back(makeAdoptedMachine("10.0.0.20"_ctv, true));

    FakeRemoveHooks hooks = {};
    MothershipClusterRemoveSummary summary = {};
    String failure = {};
    bool ok = mothershipRemoveClusterRuntime(cluster, hooks, summary, &failure);
    suite.expect(ok, "remove_local_cluster_ok");
    suite.expect(failure.size() == 0, "remove_local_cluster_no_failure");
    suite.expect(summary.removedDNSRecords == 0, "remove_local_cluster_no_dns_records");
    suite.expect(summary.stoppedLocalMachine, "remove_local_cluster_stopped_local");
    suite.expect(summary.wipedAdoptedMachines == 1, "remove_local_cluster_wiped_adopted_count");
    suite.expect(summary.destroyedCreatedCloudMachines == 0, "remove_local_cluster_no_cloud_destroy");
    suite.expect(hooks.stopLocalCalls == 1, "remove_local_cluster_local_called_once");
    suite.expect(hooks.stopAdoptedCalls == 1, "remove_local_cluster_adopted_called_once");
    suite.expect(hooks.destroyCreatedCalls == 0, "remove_local_cluster_destroy_not_called");
    suite.expect(equalStrings(hooks.callOrder, {"dns", "local", "adopted"}), "remove_local_cluster_call_order");
  }

  {
    MothershipProdigyCluster cluster = {};
    cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
    cluster.machines.push_back(makeAdoptedMachine("10.0.1.10"_ctv, true, ClusterMachineBacking::cloud));

    ClusterMachine adoptedTopologyMachine = makeTopologyMachine("10.0.1.11"_ctv, ClusterMachineSource::adopted, ClusterMachineBacking::owned);
    cluster.topology.machines.push_back(adoptedTopologyMachine);

    ClusterMachine createdMachineA = makeTopologyMachine("i-created-1"_ctv, ClusterMachineSource::created, ClusterMachineBacking::cloud);
    createdMachineA.cloud.cloudID = "i-created-1"_ctv;
    cluster.topology.machines.push_back(createdMachineA);

    ClusterMachine createdMachineADuplicate = createdMachineA;
    cluster.topology.machines.push_back(createdMachineADuplicate);

    ClusterMachine createdMachineB = makeTopologyMachine("i-created-2"_ctv, ClusterMachineSource::created, ClusterMachineBacking::cloud);
    createdMachineB.cloud.cloudID = "i-created-2"_ctv;
    cluster.topology.machines.push_back(createdMachineB);

    FakeRemoveHooks hooks = {};
    MothershipClusterRemoveSummary summary = {};
    String failure = {};
    bool ok = mothershipRemoveClusterRuntime(cluster, hooks, summary, &failure);
    suite.expect(ok, "remove_remote_mixed_cluster_ok");
    suite.expect(failure.size() == 0, "remove_remote_mixed_cluster_no_failure");
    suite.expect(summary.stoppedLocalMachine == false, "remove_remote_mixed_cluster_no_local_machine");
    suite.expect(summary.wipedAdoptedMachines == 2, "remove_remote_mixed_cluster_wiped_two_adopted");
    suite.expect(summary.destroyedCreatedCloudMachines == 2, "remove_remote_mixed_cluster_destroyed_two_created");
    suite.expect(hooks.stopAdoptedCalls == 2, "remove_remote_mixed_cluster_adopted_called_twice");
    suite.expect(hooks.destroyCreatedCalls == 1, "remove_remote_mixed_cluster_destroy_called_once");
    suite.expect(equalStrings(hooks.stoppedAdoptedSSHAddresses, {"10.0.1.10", "10.0.1.11"}), "remove_remote_mixed_cluster_adopted_targets");
    suite.expect(equalStrings(hooks.destroyedCreatedCloudIDs, {"i-created-1", "i-created-2"}), "remove_remote_mixed_cluster_created_targets");
    suite.expect(equalStrings(hooks.callOrder, {"dns", "adopted", "adopted", "destroy"}), "remove_remote_mixed_cluster_call_order");
  }

  {
    MothershipProdigyCluster cluster = {};
    cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
    cluster.dnsProvider = MothershipClusterProvider::cloudflare;

    ClusterMachine createdMachine = makeTopologyMachine("i-created-dns"_ctv, ClusterMachineSource::created, ClusterMachineBacking::cloud);
    createdMachine.cloud.cloudID = "i-created-dns"_ctv;
    cluster.topology.machines.push_back(createdMachine);

    FakeRemoveHooks hooks = {};
    hooks.dnsRecordsToRemove = 1;

    MothershipClusterRemoveSummary summary = {};
    String failure = {};
    bool ok = mothershipRemoveClusterRuntime(cluster, hooks, summary, &failure);
    suite.expect(ok, "remove_cluster_reports_dns_cleanup_ok");
    suite.expect(summary.removedDNSRecords == 1, "remove_cluster_reports_aaaa_dns_cleanup_count");
    suite.expect(hooks.destroyCreatedCalls == 1, "remove_cluster_destroys_after_dns_cleanup");
    suite.expect(equalStrings(hooks.callOrder, {"dns", "destroy"}), "remove_cluster_dns_cleanup_before_destroy");
  }

  {
    MothershipProdigyCluster cluster = {};
    cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
    cluster.dnsProvider = MothershipClusterProvider::cloudflare;

    ClusterMachine createdMachine = makeTopologyMachine("i-created-skipped"_ctv, ClusterMachineSource::created, ClusterMachineBacking::cloud);
    createdMachine.cloud.cloudID = "i-created-skipped"_ctv;
    cluster.topology.machines.push_back(createdMachine);

    FakeRemoveHooks hooks = {};
    hooks.failDNSCleanup = true;

    MothershipClusterRemoveSummary summary = {};
    String failure = {};
    bool ok = mothershipRemoveClusterRuntime(cluster, hooks, summary, &failure);
    suite.expect(ok == false, "remove_cluster_fails_when_dns_cleanup_fails");
    suite.expect(failure == "dns cleanup failed"_ctv, "remove_cluster_dns_cleanup_failure_reason");
    suite.expect(summary.destroyedCreatedCloudMachines == 0, "remove_cluster_no_destroy_after_dns_cleanup_failure");
    suite.expect(hooks.destroyCreatedCalls == 0, "remove_cluster_destroy_not_called_after_dns_cleanup_failure");
    suite.expect(equalStrings(hooks.callOrder, {"dns"}), "remove_cluster_dns_cleanup_failure_call_order");
  }

  {
    MothershipProdigyCluster cluster = {};
    cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
    cluster.machines.push_back(makeAdoptedMachine("10.0.2.10"_ctv, true));

    ClusterMachine createdMachine = makeTopologyMachine("i-created-3"_ctv, ClusterMachineSource::created, ClusterMachineBacking::cloud);
    createdMachine.cloud.cloudID = "i-created-3"_ctv;
    cluster.topology.machines.push_back(createdMachine);

    FakeRemoveHooks hooks = {};
    hooks.failAdoptedWipe = true;

    MothershipClusterRemoveSummary summary = {};
    String failure = {};
    bool ok = mothershipRemoveClusterRuntime(cluster, hooks, summary, &failure);
    suite.expect(ok == false, "remove_remote_cluster_fails_when_adopted_wipe_fails");
    suite.expect(failure == "adopted wipe failed"_ctv, "remove_remote_cluster_failure_reason");
    suite.expect(hooks.stopAdoptedCalls == 1, "remove_remote_cluster_failed_after_first_adopted");
    suite.expect(hooks.destroyCreatedCalls == 0, "remove_remote_cluster_no_destroy_after_adopted_failure");
  }

  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
