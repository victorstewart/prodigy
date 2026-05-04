#include <prodigy/mothership/mothership.cluster.remove.h>
#include <services/debug.h>

#include <cstdio>
#include <cstdlib>

class TestSuite
{
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

class FakeRemoveHooks final : public MothershipClusterRemoveHooks
{
public:

   bool failAdoptedWipe = false;

   uint32_t stopTestClusterCalls = 0;
   uint32_t stopLocalCalls = 0;
   uint32_t stopAdoptedCalls = 0;
   uint32_t destroyCreatedCalls = 0;

   Vector<String> stoppedAdoptedSSHAddresses = {};
   Vector<String> destroyedCreatedCloudIDs = {};
   Vector<String> callOrder = {};

   bool stopTestCluster(const MothershipProdigyCluster& cluster, String *failure = nullptr) override
   {
      (void)cluster;
      stopTestClusterCalls += 1;
      callOrder.push_back("test"_ctv);
      if (failure) failure->clear();
      return true;
   }

   bool stopAndWipeLocalMachine(const MothershipProdigyCluster& cluster, String *failure = nullptr) override
   {
      (void)cluster;
      stopLocalCalls += 1;
      callOrder.push_back("local"_ctv);
      if (failure) failure->clear();
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
         if (failure) failure->assign("adopted wipe failed"_ctv);
         return false;
      }

      if (failure) failure->clear();
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
      if (failure) failure->clear();
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

int main(void)
{
   TestSuite suite;

   {
      String command = {};
      mothershipBuildProdigyStateWipeCommand("/var/lib/prodigy/state"_ctv, command);
      suite.expect(command == "systemctl stop prodigy || true; systemctl disable prodigy || true; rm -rf /run/prodigy /var/lib/prodigy"_ctv, "remove_local_wipe_command_default_paths");
   }

   {
      MothershipProdigyCluster cluster = {};
      cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
      cluster.remoteProdigyPath = "/srv/prodigy/current"_ctv;
      cluster.controls.push_back(MothershipProdigyClusterControl{
         .kind = MothershipClusterControlKind::unixSocket,
         .path = "/srv/prodigy/run/control.sock"_ctv
      });

      String command = {};
      mothershipBuildRemoteProdigyUninstallCommand(cluster, command);
      suite.expect(stringContains(command, "systemctl stop prodigy || true; systemctl disable prodigy || true"), "remove_remote_uninstall_stops_and_disables");
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
      suite.expect(hooks.stopTestClusterCalls == 1, "remove_test_cluster_stops_runner");
      suite.expect(hooks.stopLocalCalls == 0, "remove_test_cluster_no_local_wipe");
      suite.expect(hooks.stopAdoptedCalls == 0, "remove_test_cluster_no_adopted_wipe");
      suite.expect(hooks.destroyCreatedCalls == 0, "remove_test_cluster_no_cloud_destroy");
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
      suite.expect(summary.stoppedLocalMachine, "remove_local_cluster_stopped_local");
      suite.expect(summary.wipedAdoptedMachines == 1, "remove_local_cluster_wiped_adopted_count");
      suite.expect(summary.destroyedCreatedCloudMachines == 0, "remove_local_cluster_no_cloud_destroy");
      suite.expect(hooks.stopLocalCalls == 1, "remove_local_cluster_local_called_once");
      suite.expect(hooks.stopAdoptedCalls == 1, "remove_local_cluster_adopted_called_once");
      suite.expect(hooks.destroyCreatedCalls == 0, "remove_local_cluster_destroy_not_called");
      suite.expect(equalStrings(hooks.callOrder, {"local", "adopted"}), "remove_local_cluster_call_order");
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
      suite.expect(equalStrings(hooks.callOrder, {"adopted", "adopted", "destroy"}), "remove_remote_mixed_cluster_call_order");
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
