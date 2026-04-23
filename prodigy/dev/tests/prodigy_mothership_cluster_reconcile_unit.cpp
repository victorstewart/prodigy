#include <prodigy/mothership/mothership.cluster.reconcile.h>
#include <services/debug.h>
#include <prodigy/dev/tests/prodigy_test_ssh_keys.h>

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

int main(void)
{
   TestSuite suite;

   MothershipProdigyCluster cluster = {};
   cluster.nBrains = 3;
   cluster.bootstrapSshUser = "root"_ctv;
   cluster.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
   cluster.remoteProdigyPath = "/root/prodigy"_ctv;
   cluster.controls.push_back(MothershipProdigyClusterControl {
      .kind = MothershipClusterControlKind::unixSocket,
      .path = "/run/prodigy/control.sock"_ctv
   });

   MothershipProdigyClusterMachine adoptedBrain = {};
   adoptedBrain.source = MothershipClusterMachineSource::adopted;
   adoptedBrain.backing = ClusterMachineBacking::cloud;
   adoptedBrain.kind = MachineConfig::MachineKind::vm;
   adoptedBrain.lifetime = MachineLifetime::reserved;
   adoptedBrain.isBrain = true;
   adoptedBrain.cloud.schema = "vm-brain"_ctv;
   adoptedBrain.cloud.providerMachineType = "n2-standard-4"_ctv;
   adoptedBrain.cloud.cloudID = "789654123000222"_ctv;
   adoptedBrain.ssh.address = "203.0.113.10"_ctv;
   adoptedBrain.ssh.port = 22;
   adoptedBrain.ssh.user = "root"_ctv;
   adoptedBrain.ssh.privateKeyPath = prodigyTestClientSSHPrivateKeyPath();
   prodigyAppendUniqueClusterMachineAddress(adoptedBrain.addresses.publicAddresses, "203.0.113.10"_ctv);
   prodigyAppendUniqueClusterMachineAddress(adoptedBrain.addresses.privateAddresses, "10.0.0.11"_ctv);
   adoptedBrain.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
   cluster.machines.push_back(adoptedBrain);

   MothershipProdigyClusterMachineSchema createdSchema = {};
   createdSchema.schema = "vm-brain"_ctv;
   createdSchema.kind = MachineConfig::MachineKind::vm;
   createdSchema.lifetime = MachineLifetime::ondemand;
   createdSchema.providerMachineType = "n2-standard-4"_ctv;
   createdSchema.budget = 2;
   cluster.machineSchemas.push_back(createdSchema);

   MothershipProdigyClusterMachineSchema workerSchema = {};
   workerSchema.schema = "vm-worker"_ctv;
   workerSchema.kind = MachineConfig::MachineKind::vm;
   workerSchema.lifetime = MachineLifetime::ondemand;
   workerSchema.providerMachineType = "n2-standard-8"_ctv;
   workerSchema.budget = 2;
   cluster.machineSchemas.push_back(workerSchema);

   ClusterTopology topology = {};
   topology.version = 5;

   ClusterMachine existingBrain = {};
   existingBrain.source = ClusterMachineSource::adopted;
   existingBrain.backing = ClusterMachineBacking::cloud;
   existingBrain.kind = MachineConfig::MachineKind::vm;
   existingBrain.lifetime = MachineLifetime::reserved;
   existingBrain.isBrain = true;
   existingBrain.cloud.schema = "vm-brain"_ctv;
   existingBrain.cloud.providerMachineType = "n2-standard-4"_ctv;
   existingBrain.cloud.cloudID = "789654123000111"_ctv;
   existingBrain.ssh.address = "203.0.113.9"_ctv;
   existingBrain.ssh.port = 22;
   existingBrain.ssh.user = "root"_ctv;
   existingBrain.ssh.privateKeyPath = prodigyTestClientSSHPrivateKeyPath();
   prodigyAppendUniqueClusterMachineAddress(existingBrain.addresses.publicAddresses, "203.0.113.9"_ctv, 24, "203.0.113.1"_ctv);
   prodigyAppendUniqueClusterMachineAddress(existingBrain.addresses.privateAddresses, "10.0.0.10"_ctv, 24, "10.0.0.1"_ctv);
   existingBrain.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
   topology.machines.push_back(existingBrain);

   AddMachines request = {};
   String failure;
   bool built = mothershipBuildClusterAddMachinesRequest(cluster, topology, request, &failure);
   suite.expect(built, "reconcile_build_request");
   suite.expect(failure.size() == 0, "reconcile_build_request_no_failure");
   suite.expect(request.bootstrapSshUser.equals(cluster.bootstrapSshUser), "reconcile_bootstrap_ssh_user");
   suite.expect(request.bootstrapSshPrivateKeyPath.equals(cluster.bootstrapSshPrivateKeyPath), "reconcile_bootstrap_ssh_key");
   suite.expect(request.remoteProdigyPath.equals(cluster.remoteProdigyPath), "reconcile_remote_prodigy_path");
   suite.expect(request.controlSocketPath.equals("/run/prodigy/control.sock"_ctv), "reconcile_control_socket_path");
   suite.expect(request.adoptedMachines.size() == 1, "reconcile_missing_adopted_added");
   suite.expect(request.adoptedMachines[0].cloud.schema.equals(adoptedBrain.cloud.schema), "reconcile_adopted_machine_schema");
   suite.expect(request.adoptedMachines[0].cloud.cloudID.equals(adoptedBrain.cloud.cloudID), "reconcile_adopted_cloud_id");
   suite.expect(request.adoptedMachines[0].isBrain, "reconcile_adopted_is_brain");

   ClusterMachine duplicateAdopted = existingBrain;
   cluster.machines.clear();
   cluster.machineSchemas.clear();
   cluster.machineSchemas.push_back(createdSchema);
   topology.machines.clear();
   topology.machines.push_back(existingBrain);
   cluster.machines.push_back(MothershipProdigyClusterMachine{
      .source = MothershipClusterMachineSource::adopted,
      .backing = duplicateAdopted.backing,
      .kind = duplicateAdopted.kind,
      .lifetime = duplicateAdopted.lifetime,
      .isBrain = duplicateAdopted.isBrain,
      .cloud = duplicateAdopted.cloud,
      .ssh = duplicateAdopted.ssh,
      .addresses = duplicateAdopted.addresses,
      .ownership = duplicateAdopted.ownership
   });

   request = {};
   failure.clear();
   built = mothershipBuildClusterAddMachinesRequest(cluster, topology, request, &failure);
   suite.expect(built, "reconcile_duplicate_identity_ok");
   suite.expect(request.adoptedMachines.size() == 0, "reconcile_duplicate_identity_not_readded");

   cluster.nBrains = 5;
   createdSchema.budget = 1;
   cluster.machineSchemas.clear();
   cluster.machineSchemas.push_back(createdSchema);

   request = {};
   failure.clear();
   built = mothershipBuildClusterAddMachinesRequest(cluster, topology, request, &failure);
   suite.expect(built, "reconcile_machine_schemas_ignored_by_manual_request");
   suite.expect(failure.size() == 0, "reconcile_machine_schemas_ignored_no_failure");
   suite.expect(request.adoptedMachines.size() == 0, "reconcile_machine_schemas_ignored_no_adopted");

   {
      MothershipProdigyCluster remoteCluster = {};
      remoteCluster.deploymentMode = MothershipClusterDeploymentMode::remote;
      remoteCluster.nBrains = 1;
      remoteCluster.machineSchemas.push_back(MothershipProdigyClusterMachineSchema{
         .schema = "vm-worker"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::ondemand,
         .providerMachineType = "n2-standard-8"_ctv,
         .budget = 1
      });

      ClusterTopology remoteTopology = {};

      ClusterMachine orphanCreated = {};
      orphanCreated.source = ClusterMachineSource::created;
      orphanCreated.backing = ClusterMachineBacking::cloud;
      orphanCreated.kind = MachineConfig::MachineKind::vm;
      orphanCreated.lifetime = MachineLifetime::ondemand;
      orphanCreated.isBrain = true;
      orphanCreated.cloud.schema = "vm-legacy"_ctv;
      orphanCreated.cloud.providerMachineType = "legacy-type"_ctv;
      orphanCreated.cloud.cloudID = "i-legacy"_ctv;
      orphanCreated.creationTimeMs = 10;
      remoteTopology.machines.push_back(orphanCreated);

      ClusterMachine excessCreated = {};
      excessCreated.source = ClusterMachineSource::created;
      excessCreated.backing = ClusterMachineBacking::cloud;
      excessCreated.kind = MachineConfig::MachineKind::vm;
      excessCreated.lifetime = MachineLifetime::ondemand;
      excessCreated.isBrain = false;
      excessCreated.cloud.schema = "vm-worker"_ctv;
      excessCreated.cloud.providerMachineType = "n2-standard-8"_ctv;
      excessCreated.cloud.cloudID = "i-worker-a"_ctv;
      excessCreated.creationTimeMs = 20;
      remoteTopology.machines.push_back(excessCreated);

      ClusterMachine extraCreated = excessCreated;
      extraCreated.cloud.cloudID = "i-worker-b"_ctv;
      extraCreated.creationTimeMs = 21;
      remoteTopology.machines.push_back(extraCreated);

      request = {};
      failure.clear();
      built = mothershipBuildClusterAddMachinesRequest(remoteCluster, remoteTopology, request, &failure);
      suite.expect(built, "reconcile_remote_created_machines_ignored_build");
      suite.expect(failure.size() == 0, "reconcile_remote_created_machines_ignored_no_failure");
      suite.expect(request.removedMachines.size() == 0, "reconcile_remote_created_machines_ignored_no_removals");
   }

   {
      MothershipProdigyCluster localControlCluster = {};
      localControlCluster.deploymentMode = MothershipClusterDeploymentMode::local;
      localControlCluster.includeLocalMachine = true;
      localControlCluster.nBrains = 1;

      MothershipProdigyCluster localDesiredCluster = localControlCluster;
      localDesiredCluster.includeLocalMachine = false;
      localDesiredCluster.machines.push_back(adoptedBrain);

      ClusterMachine localMachine = {};
      localMachine.source = ClusterMachineSource::adopted;
      localMachine.backing = ClusterMachineBacking::owned;
      localMachine.kind = MachineConfig::MachineKind::vm;
      localMachine.lifetime = MachineLifetime::owned;
      localMachine.isBrain = true;
      prodigyAppendUniqueClusterMachineAddress(localMachine.addresses.privateAddresses, "10.0.0.5"_ctv);
      localMachine.ssh.address = "10.0.0.5"_ctv;
      localMachine.ssh.user = "root"_ctv;
      localMachine.ssh.privateKeyPath = prodigyTestClientSSHPrivateKeyPath();
      localMachine.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;

      ClusterTopology localTopology = {};
      localTopology.machines.push_back(localMachine);
      ClusterMachine existingDesiredAdopted = {};
      mothershipFillAdoptedClusterMachine(adoptedBrain, existingDesiredAdopted);
      localTopology.machines.push_back(existingDesiredAdopted);

      request = {};
      failure.clear();
      bool changed = false;
      built = mothershipBuildDesiredClusterReconcileRequest(
         localControlCluster,
         localDesiredCluster,
         localTopology,
         request,
         changed,
         &failure,
         &localMachine,
         true);
      suite.expect(built, "reconcile_local_remove_builds");
      suite.expect(failure.size() == 0, "reconcile_local_remove_no_failure");
      suite.expect(changed, "reconcile_local_remove_changed");
      suite.expect(request.removedMachines.size() == 1, "reconcile_local_remove_marks_local_machine");
      suite.expect(request.removedMachines[0].sameIdentityAs(localMachine), "reconcile_local_remove_matches_local_machine");
      suite.expect(request.adoptedMachines.size() == 0, "reconcile_local_remove_keeps_present_adopted_machine");
   }

   {
      MothershipProdigyCluster localControlCluster = {};
      localControlCluster.deploymentMode = MothershipClusterDeploymentMode::local;
      localControlCluster.includeLocalMachine = false;
      localControlCluster.nBrains = 1;
      localControlCluster.machines.push_back(adoptedBrain);

      MothershipProdigyCluster localDesiredCluster = localControlCluster;
      localDesiredCluster.includeLocalMachine = true;

      ClusterMachine localMachine = {};
      localMachine.source = ClusterMachineSource::adopted;
      localMachine.backing = ClusterMachineBacking::owned;
      localMachine.kind = MachineConfig::MachineKind::vm;
      localMachine.lifetime = MachineLifetime::owned;
      localMachine.isBrain = true;
      prodigyAppendUniqueClusterMachineAddress(localMachine.addresses.privateAddresses, "10.0.0.5"_ctv);
      localMachine.ssh.address = "10.0.0.5"_ctv;
      localMachine.ssh.user = "root"_ctv;
      localMachine.ssh.privateKeyPath = prodigyTestClientSSHPrivateKeyPath();
      localMachine.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;

      ClusterTopology remoteOnlyTopology = {};
      ClusterMachine existingDesiredAdopted = {};
      mothershipFillAdoptedClusterMachine(adoptedBrain, existingDesiredAdopted);
      remoteOnlyTopology.machines.push_back(existingDesiredAdopted);

      request = {};
      failure.clear();
      bool changed = false;
      built = mothershipBuildDesiredClusterReconcileRequest(
         localControlCluster,
         localDesiredCluster,
         remoteOnlyTopology,
         request,
         changed,
         &failure,
         &localMachine,
         false);
      suite.expect(built, "reconcile_local_add_builds");
      suite.expect(failure.size() == 0, "reconcile_local_add_no_failure");
      suite.expect(changed, "reconcile_local_add_changed");
      suite.expect(request.readyMachines.size() == 1, "reconcile_local_add_marks_ready_machine");
      suite.expect(request.readyMachines[0].sameIdentityAs(localMachine), "reconcile_local_add_matches_local_machine");
      suite.expect(request.removedMachines.size() == 0, "reconcile_local_add_no_removed_machine");
   }

   {
      MothershipProdigyCluster localControlCluster = {};
      localControlCluster.deploymentMode = MothershipClusterDeploymentMode::local;
      localControlCluster.includeLocalMachine = false;
      localControlCluster.nBrains = 1;
      localControlCluster.machines.push_back(adoptedBrain);

      MothershipProdigyCluster localDesiredCluster = localControlCluster;
      localDesiredCluster.machines.clear();

      ClusterTopology remoteOnlyTopology = {};
      remoteOnlyTopology.machines.push_back(existingBrain);

      request = {};
      failure.clear();
      bool changed = false;
      built = mothershipBuildDesiredClusterReconcileRequest(
         localControlCluster,
         localDesiredCluster,
         remoteOnlyTopology,
         request,
         changed,
         &failure);
      suite.expect(built, "reconcile_remove_adopted_builds");
      suite.expect(failure.size() == 0, "reconcile_remove_adopted_no_failure");
      suite.expect(changed, "reconcile_remove_adopted_changed");
      suite.expect(request.removedMachines.size() == 1, "reconcile_remove_adopted_marks_machine");
      suite.expect(request.removedMachines[0].sameIdentityAs(existingBrain), "reconcile_remove_adopted_matches_machine");
      suite.expect(request.adoptedMachines.size() == 0, "reconcile_remove_adopted_no_missing_adds");
   }

   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
