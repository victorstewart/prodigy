#include <prodigy/mothership/mothership.provider.machine.destroy.h>
#include <services/debug.h>

#include <cstdio>
#include <cstdlib>

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
      failed += 1;
    }
  }
};

class FakeDestroyBrainIaaS : public BrainIaaS {
public:

  Vector<String> destroyedCloudIDs;
  String lastHardRebootCloudID;
  uint32_t hardRebootCalls = 0;
  String hardRebootFailure;
  String destroyedClusterUUID;
  uint32_t destroyedClusterCount = 0;
  String clusterDestroyFailure;

  void boot(void) override {}
  void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) override
  {
    (void)coro;
    (void)lifetime;
    (void)config;
    (void)count;
    (void)newMachines;
    error.clear();
  }
  void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines, String& failure) override
  {
    (void)coro;
    (void)metro;
    (void)machines;
  }
  void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains, String& failure) override
  {
    (void)coro;
    (void)selfUUID;
    (void)selfIsBrain;
    (void)brains;
  }
  void hardRebootMachine(CoroutineStack *coro, const String& cloudID, String& failure) override
  {
    (void)coro;
    hardRebootCalls += 1;
    lastHardRebootCloudID = cloudID;
    failure = hardRebootFailure;
  }
  void reportHardwareFailure(uint128_t uuid, const String& report) override
  {
    (void)uuid;
    (void)report;
  }
  void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
  {
    (void)coro;
    (void)decommissionedIDs;
  }
  void destroyMachine(CoroutineStack *coro, const String& cloudID, String& failure) override
  {
    (void)coro;
    failure.clear();
    destroyedCloudIDs.push_back(cloudID);
  }

  void destroyClusterMachines(CoroutineStack *coro, const String& clusterUUID, uint32_t& destroyed, String& error) override
  {
    (void)coro;
    destroyedClusterUUID = clusterUUID;
    destroyed = destroyedClusterCount;
    error = clusterDestroyFailure;
    co_return;
  }

  uint32_t supportedMachineKindsMask() const override
  {
    return 3u;
  }
};

int main(void)
{
  TestSuite suite;

  FakeDestroyBrainIaaS iaas = {};
  String failure = {};
  bool rebooted = mothershipHardRebootProviderMachineInline(iaas, "i-reboot-001"_ctv, &failure);
  suite.expect(rebooted, "hard_reboot_provider_machine_ok");
  suite.expect(failure.size() == 0, "hard_reboot_provider_machine_no_failure");
  suite.expect(iaas.hardRebootCalls == 1, "hard_reboot_provider_machine_one_call");
  suite.expect(iaas.lastHardRebootCloudID == "i-reboot-001"_ctv, "hard_reboot_provider_machine_exact_cloud_id");

  iaas.hardRebootFailure.assign("provider hard reboot failed"_ctv);
  failure.clear();
  rebooted = mothershipHardRebootProviderMachineInline(iaas, "i-reboot-002"_ctv, &failure);
  suite.expect(rebooted == false, "hard_reboot_provider_machine_propagates_failure");
  suite.expect(failure == "provider hard reboot failed"_ctv, "hard_reboot_provider_machine_failure_reason");
  suite.expect(iaas.hardRebootCalls == 2 && iaas.lastHardRebootCloudID == "i-reboot-002"_ctv,
               "hard_reboot_provider_machine_failure_keeps_exact_cloud_id");
  iaas.hardRebootFailure.clear();

  failure.clear();
  rebooted = mothershipHardRebootProviderMachineInline(iaas, ""_ctv, &failure);
  suite.expect(rebooted == false, "hard_reboot_provider_machine_rejects_empty");
  suite.expect(failure == "cloudID required"_ctv, "hard_reboot_provider_machine_rejects_empty_reason");
  suite.expect(iaas.hardRebootCalls == 2, "hard_reboot_provider_machine_empty_skips_provider");

  ClusterTopology topology = {};
  ClusterMachine created = {};
  created.uuid = 0x1234;
  created.source = ClusterMachineSource::created;
  created.backing = ClusterMachineBacking::cloud;
  created.cloud.cloudID.assign("provider-machine-1234"_ctv);
  topology.machines.push_back(created);
  ClusterMachine adopted = created;
  adopted.uuid = 0x5678;
  adopted.source = ClusterMachineSource::adopted;
  topology.machines.push_back(adopted);
  ClusterMachine createdB = created;
  createdB.uuid = 0x9abc;
  createdB.cloud.cloudID.assign("provider-machine-9abc"_ctv);
  topology.machines.push_back(createdB);

  String resolvedCloudID = {};
  failure.clear();
  suite.expect(mothershipResolveCreatedCloudMachineID(topology, created.uuid, resolvedCloudID, &failure) &&
                   resolvedCloudID == created.cloud.cloudID && failure.empty(),
               "hard_reboot_target_resolves_exact_created_cloud_machine");
  suite.expect(mothershipResolveCreatedCloudMachineID(topology, adopted.uuid, resolvedCloudID, &failure) == false &&
                   failure == "hard reboot requires a Mothership-created cloud machine"_ctv,
               "hard_reboot_target_rejects_adopted_machine");
  suite.expect(mothershipResolveCreatedCloudMachineID(topology, 0x9999, resolvedCloudID, &failure) == false &&
                   failure == "machineUUID is not present in cluster topology"_ctv,
               "hard_reboot_target_rejects_unknown_machine");

  ClusterTopology observedTopology = topology;
  failure.clear();
  suite.expect(mothershipResolveVerifiedCreatedCloudMachineID(
                   topology, observedTopology, created.uuid, resolvedCloudID, &failure) &&
                   resolvedCloudID == created.cloud.cloudID && failure.empty(),
               "hard_reboot_target_requires_durable_and_observed_identity_agreement");
  observedTopology.machines[0].cloud.cloudID.assign("provider-machine-substituted"_ctv);
  suite.expect(mothershipResolveVerifiedCreatedCloudMachineID(
                   topology, observedTopology, created.uuid, resolvedCloudID, &failure) == false &&
                   failure == "durable and observed hard reboot cloud identities disagree"_ctv &&
                   resolvedCloudID.empty(),
               "hard_reboot_target_rejects_observed_cloud_identity_substitution");
  observedTopology = topology;
  observedTopology.machines[2].cloud.cloudID.assign("provider-machine-nontarget-substituted"_ctv);
  suite.expect(mothershipResolveVerifiedCreatedCloudMachineID(
                   topology, observedTopology, created.uuid, resolvedCloudID, &failure) == false &&
                   failure == "durable and observed topology machine authorization disagree"_ctv &&
                   resolvedCloudID.empty(),
               "hard_reboot_target_rejects_nontarget_authorization_substitution");

  topology.machines.push_back(created);
  suite.expect(mothershipResolveCreatedCloudMachineID(topology, created.uuid, resolvedCloudID, &failure) == false &&
                   failure == "machineUUID is ambiguous in cluster topology"_ctv,
               "hard_reboot_target_rejects_ambiguous_machine");

  Vector<String> cloudIDs = {};
  cloudIDs.push_back("i-001"_ctv);
  cloudIDs.push_back("i-002"_ctv);

  failure.clear();
  bool destroyed = mothershipDestroyProviderMachinesInline(iaas, cloudIDs, &failure);
  suite.expect(destroyed, "destroy_provider_machines_ok");
  suite.expect(failure.size() == 0, "destroy_provider_machines_no_failure");
  suite.expect(iaas.destroyedCloudIDs.size() == 2, "destroy_provider_machines_count");
  suite.expect(iaas.destroyedCloudIDs[0] == "i-001"_ctv, "destroy_provider_machines_first");
  suite.expect(iaas.destroyedCloudIDs[1] == "i-002"_ctv, "destroy_provider_machines_second");

  Vector<String> badCloudIDs = {};
  badCloudIDs.push_back(""_ctv);
  failure.clear();
  bool rejected = mothershipDestroyProviderMachinesInline(iaas, badCloudIDs, &failure);
  suite.expect(rejected == false, "destroy_provider_machines_rejects_empty");
  suite.expect(failure == "cloudID required"_ctv, "destroy_provider_machines_rejects_empty_reason");

  iaas.destroyedClusterCount = 5;
  failure.clear();
  uint32_t destroyedClusterMachines = 0;
  bool destroyedCluster = mothershipDestroyProviderClusterMachinesInline(iaas, "0xabc123"_ctv, destroyedClusterMachines, &failure);
  suite.expect(destroyedCluster, "destroy_provider_cluster_machines_ok");
  suite.expect(failure.size() == 0, "destroy_provider_cluster_machines_no_failure");
  suite.expect(iaas.destroyedClusterUUID == "0xabc123"_ctv, "destroy_provider_cluster_machines_uuid");
  suite.expect(destroyedClusterMachines == 5, "destroy_provider_cluster_machines_count");

  iaas.clusterDestroyFailure.assign("provider cluster destroy failed"_ctv);
  failure.clear();
  destroyedCluster = mothershipDestroyProviderClusterMachinesInline(iaas, "0xabc123"_ctv, destroyedClusterMachines, &failure);
  suite.expect(destroyedCluster == false, "destroy_provider_cluster_machines_propagates_failure");
  suite.expect(failure == "provider cluster destroy failed"_ctv, "destroy_provider_cluster_machines_failure_reason");
  iaas.clusterDestroyFailure.clear();

  failure.clear();
  destroyedCluster = mothershipDestroyProviderClusterMachinesInline(iaas, ""_ctv, destroyedClusterMachines, &failure);
  suite.expect(destroyedCluster == false, "destroy_provider_cluster_machines_rejects_empty");
  suite.expect(failure == "clusterUUID required"_ctv, "destroy_provider_cluster_machines_rejects_empty_reason");

  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
