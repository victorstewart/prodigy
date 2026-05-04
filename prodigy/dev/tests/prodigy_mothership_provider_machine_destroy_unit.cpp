#include <prodigy/mothership/mothership.provider.machine.destroy.h>
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

class FakeDestroyBrainIaaS : public BrainIaaS
{
public:

   Vector<String> destroyedCloudIDs;
   String destroyedClusterUUID;
   uint32_t destroyedClusterCount = 0;

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
   void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines) override
   {
      (void)coro;
      (void)metro;
      (void)machines;
   }
   void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains) override
   {
      (void)coro;
      (void)selfUUID;
      (void)selfIsBrain;
      (void)brains;
   }
   void hardRebootMachine(uint128_t uuid) override { (void)uuid; }
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
   void destroyMachine(Machine *machine) override
   {
      if (machine != nullptr)
      {
         destroyedCloudIDs.push_back(machine->cloudID);
      }
   }

   bool destroyClusterMachines(const String& clusterUUID, uint32_t& destroyed, String& error) override
   {
      destroyedClusterUUID = clusterUUID;
      destroyed = destroyedClusterCount;
      error.clear();
      return true;
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
   Vector<String> cloudIDs = {};
   cloudIDs.push_back("i-001"_ctv);
   cloudIDs.push_back("i-002"_ctv);

   String failure = {};
   bool destroyed = mothershipDestroyProviderMachines(iaas, cloudIDs, &failure);
   suite.expect(destroyed, "destroy_provider_machines_ok");
   suite.expect(failure.size() == 0, "destroy_provider_machines_no_failure");
   suite.expect(iaas.destroyedCloudIDs.size() == 2, "destroy_provider_machines_count");
   suite.expect(iaas.destroyedCloudIDs[0] == "i-001"_ctv, "destroy_provider_machines_first");
   suite.expect(iaas.destroyedCloudIDs[1] == "i-002"_ctv, "destroy_provider_machines_second");

   Vector<String> badCloudIDs = {};
   badCloudIDs.push_back(""_ctv);
   failure.clear();
   bool rejected = mothershipDestroyProviderMachines(iaas, badCloudIDs, &failure);
   suite.expect(rejected == false, "destroy_provider_machines_rejects_empty");
   suite.expect(failure == "cloudID required"_ctv, "destroy_provider_machines_rejects_empty_reason");

   iaas.destroyedClusterCount = 5;
   failure.clear();
   uint32_t destroyedClusterMachines = 0;
   bool destroyedCluster = mothershipDestroyProviderClusterMachines(iaas, "0xabc123"_ctv, destroyedClusterMachines, &failure);
   suite.expect(destroyedCluster, "destroy_provider_cluster_machines_ok");
   suite.expect(failure.size() == 0, "destroy_provider_cluster_machines_no_failure");
   suite.expect(iaas.destroyedClusterUUID == "0xabc123"_ctv, "destroy_provider_cluster_machines_uuid");
   suite.expect(destroyedClusterMachines == 5, "destroy_provider_cluster_machines_count");

   failure.clear();
   destroyedCluster = mothershipDestroyProviderClusterMachines(iaas, ""_ctv, destroyedClusterMachines, &failure);
   suite.expect(destroyedCluster == false, "destroy_provider_cluster_machines_rejects_empty");
   suite.expect(failure == "clusterUUID required"_ctv, "destroy_provider_cluster_machines_rejects_empty_reason");

   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
