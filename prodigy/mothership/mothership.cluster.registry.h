#pragma once

#include <cstdint>
#include <cstdlib>

#include <networking/includes.h>
#include <types/types.containers.h>
#include <databases/embedded/tidesdb.h>
#include <prodigy/iaas/bootstrap.ssh.h>
#include <prodigy/mothership/mothership.cluster.reconcile.h>
#include <prodigy/mothership/mothership.cluster.test.h>
#include <prodigy/mothership/mothership.cluster.types.h>

class MothershipClusterRegistry
{
private:

   TidesDB db;

   static constexpr auto clustersColumnFamily = "clusters"_ctv;
   static constexpr auto clustersByUUIDColumnFamily = "clusters_by_uuid"_ctv;

   static void resolveDefaultDBPath(String& path)
   {
      if (const char *overridePath = getenv("PRODIGY_MOTHERSHIP_TIDESDB_PATH"); overridePath && overridePath[0] != '\0')
      {
         path.snprintf<"{}/clusters"_ctv>(String(overridePath));
         return;
      }

      if (const char *home = getenv("HOME"); home && home[0] != '\0')
      {
         path.snprintf<"{}/.prodigy/mothership/clusters"_ctv>(String(home));
         return;
      }

      path.assign("/tmp/prodigy-mothership/clusters"_ctv);
   }

   static bool requireRootBootstrapSSHUser(const MothershipProdigyCluster& cluster, String *failure = nullptr)
   {
      if (cluster.bootstrapSshUser.equals(defaultMothershipClusterSSHUser()))
      {
         if (failure) failure->clear();
         return true;
      }

      if (failure) failure->assign("automatic bootstrap requires bootstrapSshUser=root"_ctv);
      return false;
   }

   static bool resolveBootstrapSSHKeyPackage(MothershipProdigyCluster& cluster, bool generateIfMissing, String *failure = nullptr)
   {
      if (failure) failure->clear();

      String generatedComment = {};
      if (cluster.clusterUUID != 0)
      {
         generatedComment.snprintf<"prodigy-bootstrap-{itoh}"_ctv>(cluster.clusterUUID);
      }
      else if (cluster.name.size() > 0)
      {
         generatedComment.snprintf<"prodigy-bootstrap-{}"_ctv>(cluster.name);
      }
      else
      {
         generatedComment.assign("prodigy-bootstrap"_ctv);
      }

      Vault::SSHKeyPackage package = {};
      if (prodigyResolveBootstrapSSHKeyPackage(
            cluster.bootstrapSshKeyPackage,
            cluster.bootstrapSshPrivateKeyPath,
            generatedComment,
            generateIfMissing,
            package,
            failure) == false)
      {
         return false;
      }

      cluster.bootstrapSshKeyPackage = std::move(package);
      if (prodigyBootstrapSSHKeyPackageConfigured(cluster.bootstrapSshKeyPackage)
         && cluster.bootstrapSshPrivateKeyPath.size() == 0)
      {
         cluster.bootstrapSshPrivateKeyPath.assign(prodigyDefaultBootstrapSSHPrivateKeyPath());
      }

      return true;
   }

   static bool resolveBootstrapSSHHostKeyPackage(MothershipProdigyCluster& cluster, bool generateIfMissing, String *failure = nullptr)
   {
      if (failure) failure->clear();

      String generatedComment = {};
      if (cluster.clusterUUID != 0)
      {
         generatedComment.snprintf<"prodigy-host-{itoh}"_ctv>(cluster.clusterUUID);
      }
      else if (cluster.name.size() > 0)
      {
         generatedComment.snprintf<"prodigy-host-{}"_ctv>(cluster.name);
      }
      else
      {
         generatedComment.assign("prodigy-host"_ctv);
      }

      Vault::SSHKeyPackage package = {};
      if (prodigyResolveBootstrapSSHKeyPackage(
            cluster.bootstrapSshHostKeyPackage,
            {} /* privateKeyPath */,
            generatedComment,
            generateIfMissing,
            package,
            failure) == false)
      {
         return false;
      }

      cluster.bootstrapSshHostKeyPackage = std::move(package);
      return true;
   }

   static bool deserializeClusterValue(const uint8_t *value, size_t valueSize, MothershipProdigyCluster& cluster)
   {
      String serialized;
      serialized.append(value, valueSize);
      return BitseryEngine::deserializeSafe(serialized, cluster);
   }

   static void ensureClusterUUID(MothershipProdigyCluster& cluster)
   {
      if (cluster.clusterUUID != 0)
      {
         return;
      }

      do
      {
         cluster.clusterUUID = Random::generateNumberWithNBits<128, uint128_t>();
      }
      while (cluster.clusterUUID == 0);
   }

   static void renderClusterUUIDKey(uint128_t clusterUUID, String& key)
   {
      key.assignItoh(clusterUUID);
   }

   static uint32_t implicitBrainMachineCapacity(const MothershipProdigyCluster& cluster)
   {
      if (mothershipClusterIncludesLocalMachine(cluster))
      {
         return 1;
      }

      if (cluster.deploymentMode == MothershipClusterDeploymentMode::test)
      {
         return cluster.test.machineCount;
      }

      return 0;
   }

   static uint32_t effectiveBrainMachineCapacity(const MothershipProdigyCluster& cluster)
   {
      uint64_t capacity = implicitBrainMachineCapacity(cluster);

      for (const MothershipProdigyClusterMachine& machine : cluster.machines)
      {
         if (machine.isBrain)
         {
            capacity += 1;
         }
      }

      for (const MothershipProdigyClusterMachineSchema& managedSchema : cluster.machineSchemas)
      {
         capacity += managedSchema.budget;
      }

      if (capacity > UINT32_MAX)
      {
         return UINT32_MAX;
      }

      return uint32_t(capacity);
   }

   static bool clusterRequiresProdigyProviderCredential(const MothershipProdigyCluster& cluster)
   {
      if (cluster.deploymentMode != MothershipClusterDeploymentMode::remote)
      {
         return false;
      }

      if (cluster.provider == MothershipClusterProvider::gcp)
      {
         return false;
      }

      if (cluster.provider == MothershipClusterProvider::aws
         && cluster.aws.configured())
      {
         return false;
      }

      if (cluster.provider == MothershipClusterProvider::azure
         && cluster.azure.managedIdentityResourceID.size() > 0)
      {
         return false;
      }

      for (const MothershipProdigyClusterMachineSchema& managedSchema : cluster.machineSchemas)
      {
         if (managedSchema.budget > 0)
         {
            return true;
         }
      }

      return false;
   }

   static bool parseAzureScopeTriplet(const String& scope, String& subscriptionID, String& resourceGroup, String& location)
   {
      subscriptionID.clear();
      resourceGroup.clear();
      location.clear();
      if (scope.size() == 0)
      {
         return false;
      }

      auto assignSegment = [&] (const char *key, String& out) -> bool {
         String needle = {};
         needle.snprintf<"{}/"_ctv>(String(key));
         int64_t offset = -1;
         for (uint64_t index = 0; index + needle.size() <= scope.size(); ++index)
         {
            if (memcmp(scope.data() + index, needle.data(), needle.size()) == 0)
            {
               offset = int64_t(index + needle.size());
               break;
            }
         }

         if (offset < 0)
         {
            return false;
         }

         uint64_t end = scope.size();
         int64_t slash = -1;
         for (uint64_t index = uint64_t(offset); index < scope.size(); ++index)
         {
            if (scope[index] == '/')
            {
               slash = int64_t(index);
               break;
            }
         }
         if (slash >= 0)
         {
            end = uint64_t(slash);
         }

         if (end <= uint64_t(offset))
         {
            return false;
         }

         out.assign(scope.substr(uint64_t(offset), end - uint64_t(offset), Copy::yes));
         return out.size() > 0;
      };

      if (assignSegment("subscriptions", subscriptionID)
         && assignSegment("resourceGroups", resourceGroup))
      {
         if (assignSegment("locations", location) == false)
         {
            int64_t slash = scope.rfindChar('/');
            if (slash >= 0 && uint64_t(slash + 1) < scope.size())
            {
               location.assign(scope.substr(uint64_t(slash + 1), scope.size() - uint64_t(slash + 1), Copy::yes));
            }
         }
      }

      if (subscriptionID.size() == 0 || resourceGroup.size() == 0 || location.size() == 0)
      {
         Vector<String> parts;
         uint64_t start = 0;
         for (uint64_t index = 0; index <= scope.size(); ++index)
         {
            if (index == scope.size() || scope[index] == '/')
            {
               if (index > start)
               {
                  parts.push_back(scope.substr(start, index - start, Copy::yes));
               }
               start = index + 1;
            }
         }

         if (parts.size() >= 3)
         {
            subscriptionID = parts[0];
            resourceGroup = parts[1];
            location = parts[2];
         }
      }

      return subscriptionID.size() > 0 && resourceGroup.size() > 0 && location.size() > 0;
   }

   static bool clusterHasManagedMachineSchemas(const MothershipProdigyCluster& cluster)
   {
      for (const MothershipProdigyClusterMachineSchema& managedSchema : cluster.machineSchemas)
      {
         if (managedSchema.budget > 0)
         {
            return true;
         }
      }

      return false;
   }

   static void renderManagedGcpTemplateBase(const MothershipProdigyCluster& cluster, String& templateBase)
   {
      templateBase.snprintf<"prodigy-{itoa}-gcp-template"_ctv>(uint64_t(cluster.clusterUUID));
   }

   static void renderManagedAzureIdentityBase(const MothershipProdigyCluster& cluster, String& identityBase)
   {
      identityBase.snprintf<"prodigy-{itoa}-azure-mi"_ctv>(uint64_t(cluster.clusterUUID));
   }

   static bool deriveAwsInstanceProfileNameFromArn(const String& arn, String& profileName)
   {
      profileName.clear();
      int64_t slash = arn.rfindChar('/');
      if (slash < 0 || uint64_t(slash + 1) >= arn.size())
      {
         return false;
      }

      profileName.assign(arn.substr(uint64_t(slash + 1), arn.size() - uint64_t(slash + 1), Copy::yes));
      return profileName.size() > 0;
   }

   static bool deriveAzureManagedIdentityNameFromResourceID(const String& resourceID, String& identityName)
   {
      identityName.clear();
      int64_t slash = resourceID.rfindChar('/');
      if (slash < 0 || uint64_t(slash + 1) >= resourceID.size())
      {
         return false;
      }

      identityName.assign(resourceID.substr(uint64_t(slash + 1), resourceID.size() - uint64_t(slash + 1), Copy::yes));
      return identityName.size() > 0;
   }

   static bool normalizeRemoteAzureManagedIdentityContract(MothershipProdigyCluster& cluster, String *failure)
   {
      if (cluster.provider != MothershipClusterProvider::azure)
      {
         if (cluster.azure.configured())
         {
            if (failure) failure->assign("non-azure clusters must not include azure config"_ctv);
            return false;
         }

         return true;
      }

      bool hasManagedSchemas = clusterHasManagedMachineSchemas(cluster);
      if (hasManagedSchemas == false)
      {
         return true;
      }

      if (cluster.propagateProviderCredentialToProdigy)
      {
         if (failure) failure->assign("azure remote clusters must not propagate provider credentials to Prodigy"_ctv);
         return false;
      }

      String subscriptionID = {};
      String resourceGroup = {};
      String location = {};
      if (parseAzureScopeTriplet(cluster.providerScope, subscriptionID, resourceGroup, location) == false)
      {
         if (failure) failure->assign("azure providerScope requires subscription/resourceGroup/location"_ctv);
         return false;
      }

      if (cluster.azure.managedIdentityName.size() == 0
         && cluster.azure.managedIdentityResourceID.size() > 0)
      {
         if (deriveAzureManagedIdentityNameFromResourceID(cluster.azure.managedIdentityResourceID, cluster.azure.managedIdentityName) == false)
         {
            if (failure) failure->assign("azure.managedIdentityResourceID must end with an identity name"_ctv);
            return false;
         }
      }

      if (cluster.azure.managedIdentityName.size() == 0)
      {
         renderManagedAzureIdentityBase(cluster, cluster.azure.managedIdentityName);
      }

      if (cluster.azure.managedIdentityResourceID.size() == 0)
      {
         cluster.azure.managedIdentityResourceID.snprintf<
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{}"_ctv>(
               subscriptionID,
               resourceGroup,
               cluster.azure.managedIdentityName);
      }

      return true;
   }

   static bool normalizeRemoteAwsInstanceProfileContract(MothershipProdigyCluster& cluster, String *failure)
   {
      if (cluster.provider != MothershipClusterProvider::aws)
      {
         if (cluster.aws.configured())
         {
            if (failure) failure->assign("non-aws clusters must not include aws config"_ctv);
            return false;
         }

         return true;
      }

      if (clusterHasManagedMachineSchemas(cluster) == false)
      {
         return true;
      }

      if (cluster.propagateProviderCredentialToProdigy)
      {
         if (failure) failure->assign("aws remote clusters must not propagate provider credentials to Prodigy"_ctv);
         return false;
      }

      if (cluster.aws.instanceProfileName.size() == 0
         && cluster.aws.instanceProfileArn.size() == 0)
      {
         if (failure) failure->assign("aws remote machineSchemas require aws.instanceProfileName or aws.instanceProfileArn"_ctv);
         return false;
      }

      if (cluster.aws.instanceProfileName.size() == 0
         && cluster.aws.instanceProfileArn.size() > 0)
      {
         if (deriveAwsInstanceProfileNameFromArn(cluster.aws.instanceProfileArn, cluster.aws.instanceProfileName) == false)
         {
            if (failure) failure->assign("aws.instanceProfileArn must end with an instance profile name"_ctv);
            return false;
         }
      }

      return true;
   }

   static bool normalizeRemoteGcpManagedTemplateContract(MothershipProdigyCluster& cluster, String *failure)
   {
      if (cluster.provider != MothershipClusterProvider::gcp)
      {
         if (cluster.gcp.configured())
         {
            if (failure) failure->assign("non-gcp clusters must not include gcp config"_ctv);
            return false;
         }

         return true;
      }

      bool hasManagedSchemas = clusterHasManagedMachineSchemas(cluster);
      if (hasManagedSchemas == false)
      {
         if (cluster.propagateProviderCredentialToProdigy)
         {
            if (failure) failure->assign("gcp remote clusters must not propagate provider credentials to Prodigy"_ctv);
            return false;
         }

         return true;
      }

      if (cluster.gcp.serviceAccountEmail.size() == 0)
      {
         if (failure) failure->assign("gcp remote machineSchemas require gcp.serviceAccountEmail"_ctv);
         return false;
      }

      if (cluster.propagateProviderCredentialToProdigy)
      {
         if (failure) failure->assign("gcp remote clusters must not propagate provider credentials to Prodigy"_ctv);
         return false;
      }

      if (cluster.gcp.network.size() == 0)
      {
         cluster.gcp.network.assign("global/networks/default"_ctv);
      }

      String templateBase = {};
      renderManagedGcpTemplateBase(cluster, templateBase);
      String sharedTemplate = {};
      sharedTemplate.snprintf<"{}-standard"_ctv>(templateBase);
      String sharedSpotTemplate = {};
      sharedSpotTemplate.snprintf<"{}-spot"_ctv>(templateBase);

      String expectedTemplate = {};
      String expectedSpotTemplate = {};

      for (MothershipProdigyClusterMachineSchema& schema : cluster.machineSchemas)
      {
         if (schema.budget == 0)
         {
            continue;
         }

         if (schema.kind != MachineConfig::MachineKind::vm)
         {
            if (failure) failure->assign("gcp remote machineSchemas currently require kind=vm"_ctv);
            return false;
         }

         if (schema.vmImageURI.size() == 0)
         {
            if (failure) failure->assign("gcp remote machineSchemas require vmImageURI"_ctv);
            return false;
         }

         if (schema.providerMachineType.size() == 0)
         {
            if (failure) failure->assign("gcp remote machineSchemas require providerMachineType"_ctv);
            return false;
         }

         if (schema.lifetime == MachineLifetime::spot)
         {
            if (schema.gcpInstanceTemplateSpot.size() == 0)
            {
               schema.gcpInstanceTemplateSpot = sharedSpotTemplate;
            }

            if (expectedSpotTemplate.size() == 0)
            {
               expectedSpotTemplate = schema.gcpInstanceTemplateSpot;
            }
            else if (schema.gcpInstanceTemplateSpot.equals(expectedSpotTemplate) == false)
            {
               if (failure) failure->assign("gcp remote machineSchemas must share one gcpInstanceTemplateSpot"_ctv);
               return false;
            }
         }
         else
         {
            if (schema.gcpInstanceTemplate.size() == 0)
            {
               schema.gcpInstanceTemplate = sharedTemplate;
            }

            if (expectedTemplate.size() == 0)
            {
               expectedTemplate = schema.gcpInstanceTemplate;
            }
            else if (schema.gcpInstanceTemplate.equals(expectedTemplate) == false)
            {
               if (failure) failure->assign("gcp remote machineSchemas must share one gcpInstanceTemplate"_ctv);
               return false;
            }
         }
      }

      return true;
   }

   static bool findClusterMachineSchema(
      const Vector<MothershipProdigyClusterMachineSchema>& machineSchemas,
      const String& schemaKey,
      MothershipProdigyClusterMachineSchema *schemaOut = nullptr)
   {
      for (const MothershipProdigyClusterMachineSchema& schema : machineSchemas)
      {
         if (schema.schema.equals(schemaKey))
         {
            if (schemaOut != nullptr)
            {
               *schemaOut = schema;
            }

            return true;
         }
      }

      return false;
   }

   static bool validateUniqueClusterMachineIdentities(const MothershipProdigyCluster& cluster, String *failure = nullptr)
   {
      for (uint32_t index = 0; index < cluster.machines.size(); ++index)
      {
         ClusterMachine machine = {};
         mothershipFillAdoptedClusterMachine(cluster.machines[index], machine);

         for (uint32_t other = index + 1; other < cluster.machines.size(); ++other)
         {
            ClusterMachine otherMachine = {};
            mothershipFillAdoptedClusterMachine(cluster.machines[other], otherMachine);
            if (machine.sameIdentityAs(otherMachine) == false)
            {
               continue;
            }

            String label = {};
            machine.renderIdentityLabel(label);
            if (failure) failure->snprintf<"cluster machines contain duplicate identity '{}'"_ctv>(label);
            return false;
         }
      }

      return true;
   }

   static void collectClaimedClusterMachines(const MothershipProdigyCluster& cluster, Vector<ClusterMachine>& claimedMachines)
   {
      claimedMachines.clear();

      auto appendUnique = [&] (const ClusterMachine& claimedMachine) -> void {
         for (const ClusterMachine& existingMachine : claimedMachines)
         {
            if (existingMachine.sameIdentityAs(claimedMachine))
            {
               return;
            }
         }

         claimedMachines.push_back(claimedMachine);
      };

      for (const MothershipProdigyClusterMachine& machine : cluster.machines)
      {
         ClusterMachine claimedMachine = {};
         mothershipFillAdoptedClusterMachine(machine, claimedMachine);
         appendUnique(claimedMachine);
      }

      for (const ClusterMachine& machine : cluster.topology.machines)
      {
         appendUnique(machine);
      }
   }

   static bool validateClusterMachineSchemaCoverage(const MothershipProdigyCluster& cluster, String *failure = nullptr)
   {
      for (uint32_t index = 0; index < cluster.machineSchemas.size(); ++index)
      {
         const MothershipProdigyClusterMachineSchema& schema = cluster.machineSchemas[index];
         if (schema.schema.size() == 0)
         {
            if (failure) failure->assign("cluster machineSchemas require schema"_ctv);
            return false;
         }

         for (uint32_t other = index + 1; other < cluster.machineSchemas.size(); ++other)
         {
            if (cluster.machineSchemas[other].schema.equals(schema.schema))
            {
               if (failure) failure->snprintf<"cluster machineSchemas contain duplicate schema '{}'"_ctv>(schema.schema);
               return false;
            }
         }
      }

      auto requireSchema = [&] (const String& schemaKey, MachineConfig::MachineKind kind, const char *what) -> bool {

         if (schemaKey.size() == 0)
         {
            if (failure) failure->snprintf<"cluster {} requires cloud.schema"_ctv>(String(what));
            return false;
         }

         MothershipProdigyClusterMachineSchema schema = {};
         if (findClusterMachineSchema(cluster.machineSchemas, schemaKey, &schema) == false)
         {
            if (failure) failure->snprintf<"cluster {} references unknown machineSchema '{}'"_ctv>(String(what), schemaKey);
            return false;
         }

         if (schema.kind != kind)
         {
            if (failure) failure->snprintf<"cluster {} kind mismatch for machineSchema '{}'"_ctv>(String(what), schemaKey);
            return false;
         }

         return true;
      };

      for (const MothershipProdigyClusterMachine& machine : cluster.machines)
      {
         if (machine.backing == ClusterMachineBacking::cloud
            && requireSchema(machine.cloud.schema, machine.kind, "machine") == false)
         {
            return false;
         }
      }

      for (const MothershipProdigyClusterMachineSchema& managedSchema : cluster.machineSchemas)
      {
         if (requireSchema(managedSchema.schema, managedSchema.kind, "schema") == false)
         {
            return false;
         }
      }

      return true;
   }

   static bool normalizeMachineForStorage(MothershipProdigyClusterMachine& machine, const MothershipProdigyCluster& cluster, String *failure)
   {
      Vector<ClusterMachineAddress> normalizedPrivateAddresses = {};
      Vector<ClusterMachineAddress> normalizedPublicAddresses = {};
      for (const ClusterMachineAddress& address : machine.addresses.privateAddresses)
      {
         prodigyAppendUniqueClusterMachineAddress(normalizedPrivateAddresses, address);
      }
      for (const ClusterMachineAddress& address : machine.addresses.publicAddresses)
      {
         prodigyAppendUniqueClusterMachineAddress(normalizedPublicAddresses, address);
      }
      machine.addresses.privateAddresses = std::move(normalizedPrivateAddresses);
      machine.addresses.publicAddresses = std::move(normalizedPublicAddresses);

      if (machine.source != MothershipClusterMachineSource::adopted)
      {
         if (failure) failure->assign("cluster machines must be adopted");
         return false;
      }

      if (machine.ssh.address.size() == 0)
      {
         if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(machine.addresses.privateAddresses); privateAddress != nullptr)
         {
            machine.ssh.address = privateAddress->address;
         }
         else if (const ClusterMachineAddress *publicAddress = prodigyFirstClusterMachineAddress(machine.addresses.publicAddresses); publicAddress != nullptr)
         {
            machine.ssh.address = publicAddress->address;
         }
      }

      if (machine.ssh.address.size() == 0)
      {
         if (failure) failure->assign("cluster machines require sshAddress");
         return false;
      }

      if (machine.ssh.port == 0)
      {
         machine.ssh.port = 22;
      }

      if (machine.ssh.user.size() == 0)
      {
         if (cluster.bootstrapSshUser.size() > 0)
         {
            machine.ssh.user = cluster.bootstrapSshUser;
         }
         else
         {
            machine.ssh.user.assign(defaultMothershipClusterSSHUser());
         }
      }

      if (machine.ssh.privateKeyPath.size() == 0)
      {
         machine.ssh.privateKeyPath = cluster.bootstrapSshPrivateKeyPath;
      }

      if (machine.ssh.privateKeyPath.size() == 0)
      {
         if (failure) failure->assign("cluster machines require sshPrivateKeyPath");
         return false;
      }

      if (machine.ssh.hostPublicKeyOpenSSH.size() == 0)
      {
         if (failure) failure->assign("cluster machines require ssh.hostPublicKeyOpenSSH");
         return false;
      }

      if (machine.backing == ClusterMachineBacking::cloud)
      {
         if (machine.cloudPresent() == false)
         {
            if (failure) failure->assign("cloud cluster machines require cloud");
            return false;
         }

         if (machine.lifetime == MachineLifetime::owned)
         {
            if (failure) failure->assign("cloud cluster machines must not use lifetime=owned");
            return false;
         }

         if (machine.cloud.schema.size() == 0)
         {
            if (failure) failure->assign("cloud cluster machines require cloud.schema");
            return false;
         }

         if (machine.cloud.providerMachineType.size() == 0)
         {
            if (failure) failure->assign("cloud cluster machines require cloud.providerMachineType");
            return false;
         }

         if (machine.cloud.cloudID.size() == 0)
         {
            if (failure) failure->assign("cloud cluster machines require cloud.cloudID");
            return false;
         }
      }
      else
      {
         if (machine.cloudPresent())
         {
            if (failure) failure->assign("owned cluster machines must not include cloud fields");
            return false;
         }
      }

      return true;
   }

   static bool validateClusterEnvironmentBGP(const ProdigyEnvironmentBGPConfig& bgp, String *failure)
   {
      if (bgp.configured() == false)
      {
         return true;
      }

      const NeuronBGPConfig& config = bgp.config;
      if (config.enabled == false)
      {
         if (config.ourBGPID != 0
            || config.community != 0
            || config.nextHop4.isNull() == false
            || config.nextHop6.isNull() == false
            || config.peers.empty() == false)
         {
            if (failure) failure->assign("disabled bgp must not include peer or nextHop settings");
            return false;
         }

         return true;
      }

      if (config.nextHop4.isNull() == false && config.nextHop4.is6)
      {
         if (failure) failure->assign("bgp.nextHop4 must be ipv4");
         return false;
      }

      if (config.nextHop6.isNull() == false && config.nextHop6.is6 == false)
      {
         if (failure) failure->assign("bgp.nextHop6 must be ipv6");
         return false;
      }

      if (config.peers.empty())
      {
         if (failure) failure->assign("bgp.enabled requires peers");
         return false;
      }

      if (config.nextHop4.isNull() && config.nextHop6.isNull())
      {
         if (failure) failure->assign("bgp.enabled requires nextHop4 or nextHop6");
         return false;
      }

      for (const NeuronBGPPeerConfig& peer : config.peers)
      {
         if (peer.peerASN == 0)
         {
            if (failure) failure->assign("bgp.peers require peerASN");
            return false;
         }

         if (peer.peerAddress.isNull())
         {
            if (failure) failure->assign("bgp.peers require peerAddress");
            return false;
         }

         if (peer.sourceAddress.isNull())
         {
            if (failure) failure->assign("bgp.peers require sourceAddress");
            return false;
         }
      }

      return true;
   }

   static bool normalizeClusterForStorage(MothershipProdigyCluster& cluster, String *failure)
   {
      if (cluster.name.size() == 0)
      {
         if (failure) failure->assign("cluster name required");
         return false;
      }

      ensureClusterUUID(cluster);

      if (cluster.nBrains == 0)
      {
         cluster.nBrains = 1;
      }

      if (cluster.sharedCPUOvercommitPermille < prodigySharedCPUOvercommitMinPermille
         || cluster.sharedCPUOvercommitPermille > prodigySharedCPUOvercommitMaxPermille)
      {
         if (failure) failure->assign("sharedCpuOvercommit must be in 1.0..2.0");
         return false;
      }

      if (mothershipClusterUsesTestRunner(cluster))
      {
         if (cluster.test.specified == false)
         {
            if (failure) failure->assign("test clusters require test config");
            return false;
         }

         if (cluster.provider != MothershipClusterProvider::unknown)
         {
            if (failure) failure->assign("test clusters must not include provider");
            return false;
         }

         if (cluster.providerCredentialName.size() > 0)
         {
            if (failure) failure->assign("test clusters must not include providerCredentialName");
            return false;
         }

         if (cluster.providerScope.size() > 0)
         {
            if (failure) failure->assign("test clusters must not include providerScope");
            return false;
         }

         if (cluster.propagateProviderCredentialToProdigy)
         {
            if (failure) failure->assign("test clusters must not include propagateProviderCredentialToProdigy");
            return false;
         }

         if (cluster.gcp.configured())
         {
            if (failure) failure->assign("test clusters must not include gcp config"_ctv);
            return false;
         }

         if (cluster.azure.configured())
         {
            if (failure) failure->assign("test clusters must not include azure config"_ctv);
            return false;
         }

         if (mothershipTestClusterWorkspaceRootValid(cluster.test.workspaceRoot) == false)
         {
            if (failure) failure->assign("test clusters require absolute test.workspaceRoot");
            return false;
         }

         if (cluster.test.machineCount == 0)
         {
            if (failure) failure->assign("test clusters require test.machineCount");
            return false;
         }

         if (cluster.test.interContainerMTU != 0
            && (cluster.test.interContainerMTU < prodigyRuntimeTestInterContainerMTUMin
               || cluster.test.interContainerMTU > prodigyRuntimeTestInterContainerMTUMax))
         {
            if (failure) failure->assign("test.interContainerMTU must be 0 or between 1280 and 65535");
            return false;
         }

         if (cluster.nBrains > cluster.test.machineCount)
         {
            if (failure) failure->assign("test.machineCount is below nBrains");
            return false;
         }

         if (cluster.test.host.mode == MothershipClusterTestHostMode::local)
         {
            if (cluster.test.host.ssh.address.size() > 0
               || cluster.test.host.ssh.privateKeyPath.size() > 0
               || cluster.test.host.ssh.hostPublicKeyOpenSSH.size() > 0
               || cluster.test.host.ssh.user.size() > 0
               || cluster.test.host.ssh.port != 22)
            {
               if (failure) failure->assign("test.local host must not include ssh fields");
               return false;
            }

            cluster.remoteProdigyPath.clear();
         }
         else if (cluster.test.host.mode == MothershipClusterTestHostMode::ssh)
         {
            if (cluster.test.host.ssh.address.size() == 0)
            {
               if (failure) failure->assign("test.ssh host requires ssh.address");
               return false;
            }

            if (cluster.test.host.ssh.port == 0)
            {
               cluster.test.host.ssh.port = 22;
            }

            if (cluster.test.host.ssh.user.size() == 0)
            {
               cluster.test.host.ssh.user.assign(defaultMothershipClusterSSHUser());
            }

            if (cluster.test.host.ssh.privateKeyPath.size() == 0)
            {
               if (failure) failure->assign("test.ssh host requires ssh.privateKeyPath");
               return false;
            }

            if (cluster.test.host.ssh.hostPublicKeyOpenSSH.size() == 0)
            {
               if (failure) failure->assign("test.ssh host requires ssh.hostPublicKeyOpenSSH");
               return false;
            }

            if (cluster.remoteProdigyPath.size() == 0)
            {
               cluster.remoteProdigyPath.assign(defaultMothershipRemoteProdigyPath());
            }
         }
         else
         {
            if (failure) failure->assign("test host mode invalid");
            return false;
         }

         if (cluster.controls.empty() == false)
         {
            if (failure) failure->assign("test clusters manage controls automatically");
            return false;
         }

         if (cluster.machines.empty() == false)
         {
            if (failure) failure->assign("test clusters must not include machines");
            return false;
         }

         cluster.bootstrapSshUser.clear();
         cluster.bootstrapSshKeyPackage.clear();
         cluster.bootstrapSshHostKeyPackage.clear();
         cluster.bootstrapSshPrivateKeyPath.clear();
         mothershipResolveTestClusterControlRecord(cluster.controls, cluster);
      }
      else if (cluster.test.specified)
      {
         if (failure) failure->assign("non-test clusters must not include test config");
         return false;
      }

      if (cluster.controls.size() == 0)
      {
         if (failure) failure->assign("cluster controls required");
         return false;
      }

      for (MothershipProdigyClusterControl& control : cluster.controls)
      {
         if (control.kind == MothershipClusterControlKind::unixSocket)
         {
            if (control.path.size() == 0)
            {
               if (failure) failure->assign("unixSocket control requires path");
               return false;
            }
         }
         else
         {
            if (failure) failure->assign("unsupported cluster control kind");
            return false;
         }
      }

      if (validateClusterEnvironmentBGP(cluster.bgp, failure) == false)
      {
         return false;
      }

      if (cluster.datacenterFragment == 0)
      {
         if (failure) failure->assign("cluster datacenterFragment must be in 1..255");
         return false;
      }

      if (cluster.autoscaleIntervalSeconds == 0 || cluster.autoscaleIntervalSeconds > 86'400)
      {
         if (failure) failure->assign("cluster autoscaleIntervalSeconds must be in 1..86400");
         return false;
      }

      if (cluster.deploymentMode != MothershipClusterDeploymentMode::local)
      {
         cluster.includeLocalMachine = false;
      }

      if (cluster.deploymentMode == MothershipClusterDeploymentMode::local)
      {
         if (cluster.provider != MothershipClusterProvider::unknown)
         {
            if (failure) failure->assign("local clusters must not include provider");
            return false;
         }

         if (cluster.providerCredentialName.size() > 0)
         {
            if (failure) failure->assign("local clusters must not include providerCredentialName");
            return false;
         }

         if (cluster.providerScope.size() > 0)
         {
            if (failure) failure->assign("local clusters must not include providerScope");
            return false;
         }

         if (cluster.propagateProviderCredentialToProdigy)
         {
            if (failure) failure->assign("local clusters must not include propagateProviderCredentialToProdigy");
            return false;
         }

         if (cluster.gcp.configured())
         {
            if (failure) failure->assign("local clusters must not include gcp config"_ctv);
            return false;
         }

         if (cluster.azure.configured())
         {
            if (failure) failure->assign("local clusters must not include azure config"_ctv);
            return false;
         }

         uint32_t adoptedMachines = 0;
         for (MothershipProdigyClusterMachine& machine : cluster.machines)
         {
            if (normalizeMachineForStorage(machine, cluster, failure) == false)
            {
               return false;
            }

            adoptedMachines += 1;
         }

         if (cluster.includeLocalMachine == false && adoptedMachines == 0)
         {
            if (failure) failure->assign("local clusters without includeLocalMachine require adopted machines");
            return false;
         }

         if (adoptedMachines == 0)
         {
            cluster.bootstrapSshUser.clear();
            cluster.bootstrapSshKeyPackage.clear();
            cluster.bootstrapSshHostKeyPackage.clear();
            cluster.bootstrapSshPrivateKeyPath.clear();
            cluster.remoteProdigyPath.clear();
         }
         else
         {
            if (cluster.bootstrapSshUser.size() == 0)
            {
               cluster.bootstrapSshUser.assign(defaultMothershipClusterSSHUser());
            }

            if (requireRootBootstrapSSHUser(cluster, failure) == false)
            {
               return false;
            }

            if (cluster.bootstrapSshPrivateKeyPath.size() == 0)
            {
               if (failure) failure->assign("local clusters with adopted machines require bootstrapSshPrivateKeyPath");
               return false;
            }

            if (cluster.remoteProdigyPath.size() == 0)
            {
               cluster.remoteProdigyPath.assign(defaultMothershipRemoteProdigyPath());
            }
         }

         if (effectiveBrainMachineCapacity(cluster) < cluster.nBrains)
         {
            if (failure) failure->assign("brain capacity is below nBrains");
            return false;
         }
      }
      else if (cluster.deploymentMode == MothershipClusterDeploymentMode::test)
      {
         if (effectiveBrainMachineCapacity(cluster) < cluster.nBrains)
         {
            if (failure) failure->assign("brain capacity is below nBrains");
            return false;
         }
      }
      else
      {
         if (cluster.bgp.configured())
         {
            if (mothershipClusterProviderSupportsManagedBGP(cluster.provider) == false)
            {
               if (failure) failure->assign("remote cluster provider does not support bgp");
               return false;
            }
         }

         if (cluster.provider == MothershipClusterProvider::unknown)
         {
            if (failure) failure->assign("remote clusters require provider");
            return false;
         }

         if (prodigyMachineCpuArchitectureSupportedTarget(cluster.architecture) == false)
         {
            if (failure) failure->assign("remote clusters require architecture=x86_64|aarch64");
            return false;
         }

         if (cluster.providerCredentialName.size() == 0)
         {
            if (failure) failure->assign("remote clusters require providerCredentialName");
            return false;
         }

         if (cluster.bootstrapSshUser.size() == 0)
         {
            cluster.bootstrapSshUser.assign(defaultMothershipClusterSSHUser());
         }

         if (requireRootBootstrapSSHUser(cluster, failure) == false)
         {
            return false;
         }

         if (resolveBootstrapSSHKeyPackage(cluster, true, failure) == false)
         {
            return false;
         }

         if (resolveBootstrapSSHHostKeyPackage(cluster, true, failure) == false)
         {
            return false;
         }

         if (cluster.bootstrapSshPrivateKeyPath.size() == 0)
         {
            if (failure) failure->assign("remote clusters require bootstrap ssh private key install path");
            return false;
         }

         if (cluster.remoteProdigyPath.size() == 0)
         {
            cluster.remoteProdigyPath.assign(defaultMothershipRemoteProdigyPath());
         }

         if (normalizeRemoteAwsInstanceProfileContract(cluster, failure) == false)
         {
            return false;
         }

         if (normalizeRemoteGcpManagedTemplateContract(cluster, failure) == false)
         {
            return false;
         }

         if (normalizeRemoteAzureManagedIdentityContract(cluster, failure) == false)
         {
            return false;
         }

         for (uint32_t index = 0; index < cluster.machineSchemas.size(); ++index)
         {
            MothershipProdigyClusterMachineSchema& schema = cluster.machineSchemas[index];

            if (schema.schema.size() == 0)
            {
               if (failure) failure->assign("cluster machineSchemas require schema");
               return false;
            }

            if (schema.lifetime == MachineLifetime::owned)
            {
               if (failure) failure->assign("cluster machineSchemas must not use lifetime=owned");
               return false;
            }

            if (schema.providerMachineType.size() == 0)
            {
               if (failure) failure->assign("cluster machineSchemas require providerMachineType");
               return false;
            }

            if (schema.cpu.architecture == MachineCpuArchitecture::unknown)
            {
               if (failure) failure->snprintf<"cluster machineSchema '{}' is missing inferred cpu architecture"_ctv>(schema.schema);
               return false;
            }

            if (schema.cpu.architecture != cluster.architecture)
            {
               if (failure) failure->snprintf<"cluster machineSchema '{}' architecture '{}' does not match cluster architecture '{}'"_ctv>(
                  schema.schema,
                  String(machineCpuArchitectureName(schema.cpu.architecture)),
                  String(machineCpuArchitectureName(cluster.architecture)));
               return false;
            }

            for (uint32_t other = index + 1; other < cluster.machineSchemas.size(); ++other)
            {
               if (cluster.machineSchemas[other].schema.equals(schema.schema))
               {
                  if (failure) failure->snprintf<"cluster machineSchemas contain duplicate schema '{}'"_ctv>(schema.schema);
                  return false;
               }
            }
         }

         if (clusterRequiresProdigyProviderCredential(cluster) && cluster.propagateProviderCredentialToProdigy == false)
         {
            if (failure) failure->assign("clusters with machineSchemas require propagateProviderCredentialToProdigy");
            return false;
         }

         uint32_t adoptedMachines = 0;
         for (MothershipProdigyClusterMachine& machine : cluster.machines)
         {
            if (normalizeMachineForStorage(machine, cluster, failure) == false)
            {
               return false;
            }

            if (machine.source == MothershipClusterMachineSource::adopted)
            {
               adoptedMachines += 1;
            }
         }

         if (adoptedMachines == 0 && cluster.machineSchemas.size() == 0)
         {
            if (failure) failure->assign("remote clusters require adopted machines or machineSchemas");
            return false;
         }

         if (effectiveBrainMachineCapacity(cluster) < cluster.nBrains)
         {
            if (failure) failure->assign("brain capacity is below nBrains");
            return false;
         }
      }

      if (validateUniqueClusterMachineIdentities(cluster, failure) == false)
      {
         return false;
      }

      if (validateClusterMachineSchemaCoverage(cluster, failure) == false)
      {
         return false;
      }

      if (cluster.desiredEnvironment == ProdigyEnvironmentKind::unknown
         && (cluster.deploymentMode == MothershipClusterDeploymentMode::local
            || cluster.deploymentMode == MothershipClusterDeploymentMode::test))
      {
         cluster.desiredEnvironment = ProdigyEnvironmentKind::dev;
      }

      if (cluster.environmentConfigured && cluster.desiredEnvironment == ProdigyEnvironmentKind::unknown)
      {
         if (failure) failure->assign("environmentConfigured requires desiredEnvironment");
         return false;
      }

      return true;
   }

public:

   static bool validateClusterForStorage(const MothershipProdigyCluster& cluster, MothershipProdigyCluster& normalizedCluster, String *failure = nullptr)
   {
      MothershipProdigyCluster candidate = cluster;
      if (normalizeClusterForStorage(candidate, failure) == false)
      {
         return false;
      }

      normalizedCluster = std::move(candidate);
      return true;
   }

   explicit MothershipClusterRegistry(const String& path = ""_ctv)
      : db(path.size() > 0 ? path : [] () -> String {
         String resolved;
         resolveDefaultDBPath(resolved);
         return resolved;
      }())
   {
   }

   const String& path(void)
   {
      return db.path();
   }

   bool clusterExists(const String& name, bool& exists, String *failure = nullptr)
   {
      exists = false;

      if (name.size() == 0)
      {
         if (failure) failure->assign("cluster name required");
         return false;
      }

      String serialized;
      String readFailure;
      if (db.read(clustersColumnFamily, name, serialized, &readFailure))
      {
         exists = true;
         if (failure) failure->clear();
         return true;
      }

      if (readFailure.equal("record not found"_ctv))
      {
         if (failure) failure->clear();
         return true;
      }

      if (failure) *failure = readFailure;
      return false;
   }

   bool getClusterNameByUUID(uint128_t clusterUUID, String& name, String *failure = nullptr)
   {
      name.clear();

      if (clusterUUID == 0)
      {
         if (failure) failure->assign("clusterUUID required");
         return false;
      }

      String clusterUUIDKey = {};
      renderClusterUUIDKey(clusterUUID, clusterUUIDKey);
      return db.read(clustersByUUIDColumnFamily, clusterUUIDKey, name, failure);
   }

   bool validateClusterForUpsert(const MothershipProdigyCluster& cluster, MothershipProdigyCluster& normalizedCluster, String *failure = nullptr)
   {
      MothershipProdigyCluster candidate = cluster;
      if (normalizeClusterForStorage(candidate, failure) == false)
      {
         return false;
      }

      Vector<ClusterMachine> candidateClaims = {};
      collectClaimedClusterMachines(candidate, candidateClaims);
      if (candidateClaims.empty())
      {
         normalizedCluster = std::move(candidate);
         if (failure) failure->clear();
         return true;
      }

      Vector<MothershipProdigyCluster> clusters = {};
      if (listClusters(clusters, failure) == false)
      {
         return false;
      }

      for (const MothershipProdigyCluster& existingCluster : clusters)
      {
         if (existingCluster.name.equals(candidate.name)
            || (candidate.clusterUUID != 0 && existingCluster.clusterUUID == candidate.clusterUUID))
         {
            continue;
         }

         Vector<ClusterMachine> existingClaims = {};
         collectClaimedClusterMachines(existingCluster, existingClaims);
         for (const ClusterMachine& candidateMachine : candidateClaims)
         {
            for (const ClusterMachine& existingMachine : existingClaims)
            {
               if (candidateMachine.sameIdentityAs(existingMachine) == false)
               {
                  continue;
               }

               String label = {};
               candidateMachine.renderIdentityLabel(label);
               if (failure) failure->snprintf<"machine '{}' already belongs to cluster '{}'"_ctv>(label, existingCluster.name);
               return false;
            }
         }
      }

      normalizedCluster = std::move(candidate);
      if (failure) failure->clear();
      return true;
   }

   bool upsertCluster(const MothershipProdigyCluster& cluster, MothershipProdigyCluster *storedCluster = nullptr, String *failure = nullptr)
   {
      String serialized;
      MothershipProdigyCluster stored = cluster;

      MothershipProdigyCluster existingCluster = {};
      String existingFailure = {};
      bool hadExistingCluster = getCluster(cluster.name, existingCluster, &existingFailure);
      if (hadExistingCluster == false && existingFailure.equal("record not found"_ctv) == false)
      {
         if (failure) *failure = existingFailure;
         return false;
      }

      if (hadExistingCluster && stored.clusterUUID == 0)
      {
         stored.clusterUUID = existingCluster.clusterUUID;
      }

      if (hadExistingCluster && mothershipClusterUsesTestRunner(stored))
      {
         stored.controls.clear();
      }

      if (validateClusterForUpsert(stored, stored, failure) == false)
      {
         return false;
      }

      if (hadExistingCluster && existingCluster.clusterUUID != 0 && stored.clusterUUID != existingCluster.clusterUUID)
      {
         if (failure) failure->assign("clusterUUID is immutable for an existing cluster");
         return false;
      }

      String existingUUIDOwner = {};
      String uuidIndexFailure = {};
      bool uuidMapped = getClusterNameByUUID(stored.clusterUUID, existingUUIDOwner, &uuidIndexFailure);
      if (uuidMapped)
      {
         if (existingUUIDOwner.equals(stored.name) == false)
         {
            if (failure) failure->assign("clusterUUID already exists");
            return false;
         }
      }
      else if (uuidIndexFailure.equal("record not found"_ctv) == false)
      {
         if (failure) *failure = uuidIndexFailure;
         return false;
      }

      BitseryEngine::serialize(serialized, stored);
      if (db.write(clustersColumnFamily, stored.name, serialized, failure) == false)
      {
         return false;
      }

      String clusterUUIDKey = {};
      renderClusterUUIDKey(stored.clusterUUID, clusterUUIDKey);
      if (db.write(clustersByUUIDColumnFamily, clusterUUIDKey, stored.name, failure) == false)
      {
         if (hadExistingCluster)
         {
            String rollbackSerialized = {};
            BitseryEngine::serialize(rollbackSerialized, existingCluster);
            String rollbackFailure = {};
            (void)db.write(clustersColumnFamily, existingCluster.name, rollbackSerialized, &rollbackFailure);
         }
         else
         {
            String rollbackFailure = {};
            (void)db.remove(clustersColumnFamily, stored.name, &rollbackFailure);
         }

         return false;
      }

      if (storedCluster != nullptr)
      {
         *storedCluster = stored;
      }

      return true;
   }

   bool createCluster(const MothershipProdigyCluster& cluster, MothershipProdigyCluster *storedCluster = nullptr, String *failure = nullptr)
   {
      bool exists = false;
      if (clusterExists(cluster.name, exists, failure) == false)
      {
         return false;
      }

      if (exists)
      {
         if (failure) failure->assign("cluster already exists");
         return false;
      }

      return upsertCluster(cluster, storedCluster, failure);
   }

   bool getCluster(const String& name, MothershipProdigyCluster& cluster, String *failure = nullptr)
   {
      if (name.size() == 0)
      {
         if (failure) failure->assign("cluster name required");
         return false;
      }

      String serialized;
      if (db.read(clustersColumnFamily, name, serialized, failure) == false)
      {
         return false;
      }

      if (deserializeClusterValue(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size(), cluster) == false)
      {
         if (failure) failure->assign("cluster record decode failed");
         return false;
      }

      return true;
   }

   bool getClusterByIdentity(const String& identity, MothershipProdigyCluster& cluster, String *failure = nullptr)
   {
      if (identity.size() == 0)
      {
         if (failure) failure->assign("cluster identity required");
         return false;
      }

      String getFailure = {};
      if (getCluster(identity, cluster, &getFailure))
      {
         if (failure) failure->clear();
         return true;
      }

      if (getFailure.equal("record not found"_ctv) == false)
      {
         if (failure) *failure = getFailure;
         return false;
      }

      String clusterName = {};
      if (db.read(clustersByUUIDColumnFamily, identity, clusterName, &getFailure))
      {
         return getCluster(clusterName, cluster, failure);
      }

      if (getFailure.equal("record not found"_ctv) == false)
      {
         if (failure) *failure = getFailure;
         return false;
      }

      if (failure) failure->assign("record not found"_ctv);
      return false;
   }

   bool removeClusterByIdentity(const String& identity, String *failure = nullptr)
   {
      MothershipProdigyCluster cluster = {};
      if (getClusterByIdentity(identity, cluster, failure) == false)
      {
         return false;
      }

      return removeCluster(cluster.name, failure);
   }

   bool removeCluster(const String& name, String *failure = nullptr)
   {
      if (name.size() == 0)
      {
         if (failure) failure->assign("cluster name required");
         return false;
      }

      MothershipProdigyCluster cluster = {};
      if (getCluster(name, cluster, failure) == false)
      {
         return false;
      }

      String serializedCluster = {};
      BitseryEngine::serialize(serializedCluster, cluster);

      if (db.remove(clustersColumnFamily, name, failure) == false)
      {
         return false;
      }

      if (cluster.clusterUUID != 0)
      {
         String clusterUUIDKey = {};
         renderClusterUUIDKey(cluster.clusterUUID, clusterUUIDKey);

         String removeIndexFailure = {};
         if (db.remove(clustersByUUIDColumnFamily, clusterUUIDKey, &removeIndexFailure) == false
             && removeIndexFailure.equal("record not found"_ctv) == false)
         {
            String rollbackFailure = {};
            (void)db.write(clustersColumnFamily, cluster.name, serializedCluster, &rollbackFailure);

            if (failure) *failure = removeIndexFailure;
            return false;
         }
      }

      return true;
   }

   bool listClusters(Vector<MothershipProdigyCluster>& clusters, String *failure = nullptr)
   {
      clusters.clear();

      Vector<String> serializedClusters;
      if (db.listValues(clustersColumnFamily, serializedClusters, failure) == false)
      {
         return false;
      }

      for (const String& serialized : serializedClusters)
      {
         MothershipProdigyCluster cluster = {};
         if (deserializeClusterValue(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size(), cluster) == false)
         {
            if (failure) failure->assign("cluster record decode failed");
            return false;
         }

         clusters.push_back(cluster);
      }

      return true;
   }
};
