#pragma once

#include <cstdlib>
#include <memory>
#include <unistd.h>

#include <prodigy/cluster.machine.helpers.h>
#include <prodigy/iaas/iaas.h>
#include <prodigy/mothership/mothership.cluster.reconcile.h>
#include <prodigy/mothership/mothership.cluster.test.h>
#include <prodigy/mothership/mothership.provider.credentials.h>
#include <prodigy/persistent.state.h>

enum class MothershipClusterSeedMode : uint8_t
{
   local = 0,
   adopted = 1,
   created = 2
};

class MothershipClusterSeedPlan
{
public:

   MothershipClusterSeedMode mode = MothershipClusterSeedMode::local;
   ClusterMachine seedMachine;
   CreateMachinesInstruction createInstruction;
};

class MothershipClusterCreateTimingSummary
{
public:

   ProdigyTimingAttribution prepareProviderBootstrapArtifacts;
   ProdigyTimingAttribution createSeedMachine;
   ProdigyTimingAttribution bootstrapRemoteSeed;
   ProdigyTimingAttribution configureSeedCluster;
   ProdigyTimingAttribution fetchSeedTopology;
   ProdigyTimingAttribution applyAddMachines;
   ProdigyTimingAttribution upsertMachineSchemas;
   ProdigyTimingAttribution total;
};

static inline void mothershipAccumulateClusterCreateTimingStage(
   MothershipClusterCreateTimingSummary *summary,
   ProdigyTimingAttribution MothershipClusterCreateTimingSummary::*member,
   const ProdigyTimingAttribution& attribution)
{
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
   if (summary == nullptr)
   {
      return;
   }

   prodigyAccumulateTimingAttribution(summary->*member, attribution);
   prodigyAccumulateTimingAttribution(summary->total, attribution);
#else
   (void)summary;
   (void)member;
   (void)attribution;
#endif
}

static inline bool mothershipClusterMachineReadyResourcesAvailable(const ClusterMachine& machine)
{
   Machine snapshot = prodigyBuildMachineSnapshotFromClusterMachine(machine);
   return prodigyMachineReadyResourcesAvailable(snapshot);
}

static inline uint32_t mothershipClusterTopologyMachinesWithReadyResources(const ClusterTopology& topology)
{
   uint32_t ready = 0;
   for (const ClusterMachine& machine : topology.machines)
   {
      if (mothershipClusterMachineReadyResourcesAvailable(machine))
      {
         ready += 1;
      }
   }

   return ready;
}

static inline bool mothershipTestClusterTopologyReady(const ClusterTopology& topology, uint32_t expectedMachines, uint32_t expectedBrains)
{
   if (topology.machines.size() != expectedMachines)
   {
      return false;
   }

   if (clusterTopologyBrainCount(topology) != expectedBrains)
   {
      return false;
   }

   return mothershipClusterTopologyMachinesWithReadyResources(topology) == expectedMachines;
}

static inline bool mothershipMapClusterProviderEnvironment(MothershipClusterProvider provider, ProdigyEnvironmentKind& environment)
{
   switch (provider)
   {
      case MothershipClusterProvider::gcp:
      {
         environment = ProdigyEnvironmentKind::gcp;
         return true;
      }
      case MothershipClusterProvider::aws:
      {
         environment = ProdigyEnvironmentKind::aws;
         return true;
      }
      case MothershipClusterProvider::azure:
      {
         environment = ProdigyEnvironmentKind::azure;
         return true;
      }
      case MothershipClusterProvider::vultr:
      {
         environment = ProdigyEnvironmentKind::vultr;
         return true;
      }
      case MothershipClusterProvider::unknown:
      {
         environment = ProdigyEnvironmentKind::unknown;
         return false;
      }
   }

   environment = ProdigyEnvironmentKind::unknown;
   return false;
}

static inline bool mothershipBuildClusterRuntimeEnvironment(const MothershipProdigyCluster& cluster, const MothershipProviderCredential *credential, ProdigyRuntimeEnvironmentConfig& runtimeEnvironment, String *failure = nullptr)
{
   runtimeEnvironment = {};
   if (failure) failure->clear();

   if (cluster.desiredEnvironment != ProdigyEnvironmentKind::unknown)
   {
      runtimeEnvironment.kind = cluster.desiredEnvironment;
   }
   else if (cluster.deploymentMode == MothershipClusterDeploymentMode::local
      || cluster.deploymentMode == MothershipClusterDeploymentMode::test)
   {
      runtimeEnvironment.kind = ProdigyEnvironmentKind::dev;
   }
   else
   {
      (void)mothershipMapClusterProviderEnvironment(cluster.provider, runtimeEnvironment.kind);
   }

   runtimeEnvironment.providerScope = cluster.providerScope;

   if (cluster.bgp.configured())
   {
      if (cluster.deploymentMode != MothershipClusterDeploymentMode::local
         && cluster.deploymentMode != MothershipClusterDeploymentMode::test
         && mothershipClusterProviderSupportsManagedBGP(cluster.provider) == false)
      {
         if (failure) failure->assign("remote cluster provider does not support bgp"_ctv);
         return false;
      }

      runtimeEnvironment.bgp = cluster.bgp;
   }

   if (cluster.provider == MothershipClusterProvider::azure)
   {
      runtimeEnvironment.azure.managedIdentityResourceID = cluster.azure.managedIdentityResourceID;
   }
   else if (cluster.provider == MothershipClusterProvider::aws)
   {
      runtimeEnvironment.aws.instanceProfileName = cluster.aws.instanceProfileName;
      runtimeEnvironment.aws.instanceProfileArn = cluster.aws.instanceProfileArn;
   }

   if (cluster.deploymentMode == MothershipClusterDeploymentMode::test)
   {
      runtimeEnvironment.test.enabled = true;
      runtimeEnvironment.test.enableFakeIpv4Boundary = cluster.test.enableFakeIpv4Boundary;
      runtimeEnvironment.test.interContainerMTU = cluster.test.interContainerMTU;
   }

   if (cluster.propagateProviderCredentialToProdigy)
   {
      if (credential == nullptr)
      {
         if (failure) failure->assign("cluster requires propagated provider credential"_ctv);
         return false;
      }

      if (MothershipProviderCredentialRegistry::applyCredentialToRuntimeEnvironment(*credential, runtimeEnvironment, failure) == false)
      {
         return false;
      }
   }

   prodigyStripManagedCloudBootstrapCredentials(runtimeEnvironment);
   prodigyApplyInternalRuntimeEnvironmentDefaults(runtimeEnvironment);
   return true;
}

static inline bool mothershipBuildClusterProvisioningRuntimeEnvironment(const MothershipProdigyCluster& cluster, const MothershipProviderCredential *credential, ProdigyRuntimeEnvironmentConfig& runtimeEnvironment, String *failure = nullptr)
{
   if (mothershipBuildClusterRuntimeEnvironment(cluster, credential, runtimeEnvironment, failure) == false)
   {
      return false;
   }

   if (credential != nullptr && cluster.propagateProviderCredentialToProdigy == false)
   {
      if (MothershipProviderCredentialRegistry::applyCredentialToRuntimeEnvironment(*credential, runtimeEnvironment, failure) == false)
      {
         return false;
      }
   }

   return true;
}

static inline bool mothershipResolveClusterControlSocketPath(const MothershipProdigyCluster& cluster, String& controlSocketPath, String *failure);

static inline bool mothershipBuildClusterBrainConfig(const MothershipProdigyCluster& cluster, const MothershipProviderCredential *credential, BrainConfig& config, String *failure = nullptr)
{
   config = {};
   if (failure) failure->clear();

   config.clusterUUID = cluster.clusterUUID;
   config.datacenterFragment = cluster.datacenterFragment;
   config.autoscaleIntervalSeconds = cluster.autoscaleIntervalSeconds;
   config.sharedCPUOvercommitPermille = cluster.sharedCPUOvercommitPermille;

   for (const MothershipProdigyClusterMachineSchema& machineSchema : cluster.machineSchemas)
   {
      MachineConfig machineConfig = {};
      mothershipBuildMachineConfigFromSchema(machineSchema, machineConfig);
      config.configBySlug.insert_or_assign(machineSchema.schema, std::move(machineConfig));
   }

   config.requiredBrainCount = cluster.nBrains;
   config.architecture = cluster.architecture;
   config.bootstrapSshUser = cluster.bootstrapSshUser;
   config.bootstrapSshKeyPackage = cluster.bootstrapSshKeyPackage;
   config.bootstrapSshHostKeyPackage = cluster.bootstrapSshHostKeyPackage;
   config.bootstrapSshPrivateKeyPath = cluster.bootstrapSshPrivateKeyPath;
   config.remoteProdigyPath = cluster.remoteProdigyPath;

   if (mothershipResolveClusterControlSocketPath(cluster, config.controlSocketPath, failure) == false)
   {
      return false;
   }

   if (mothershipBuildClusterRuntimeEnvironment(cluster, credential, config.runtimeEnvironment, failure) == false)
   {
      return false;
   }

   return true;
}

static inline void mothershipBuildSeedBootstrapRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& configuredRuntimeEnvironment, ProdigyRuntimeEnvironmentConfig& bootstrapRuntimeEnvironment)
{
   bootstrapRuntimeEnvironment = configuredRuntimeEnvironment;

   // The seed only needs provider identity/defaults on first boot. Delay the
   // actual provider secret until Mothership reaches the control socket and
   // sends the real BrainConfig through configure().
   // `clear()` on a view-backed String leaves the old capacity in place, which
   // can revive the prior length on a later copy. Hard-reset the secret field
   // so first-boot state cannot regain the provider credential.
   bootstrapRuntimeEnvironment.providerCredentialMaterial.reset();
   bootstrapRuntimeEnvironment.aws.bootstrapCredentialRefreshCommand.reset();
   bootstrapRuntimeEnvironment.aws.bootstrapCredentialRefreshFailureHint.reset();
   bootstrapRuntimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand.reset();
   bootstrapRuntimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint.reset();
   bootstrapRuntimeEnvironment.azure.bootstrapAccessTokenRefreshCommand.reset();
   bootstrapRuntimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint.reset();
}

static inline bool mothershipResolveClusterControlSocketPath(const MothershipProdigyCluster& cluster, String& controlSocketPath, String *failure = nullptr)
{
   controlSocketPath.clear();

   for (const MothershipProdigyClusterControl& control : cluster.controls)
   {
      if (control.kind == MothershipClusterControlKind::unixSocket && control.path.size() > 0)
      {
         controlSocketPath = control.path;
         if (failure) failure->clear();
         return true;
      }
   }

   if (failure) failure->assign("cluster has no unixSocket control"_ctv);
   return false;
}

static inline bool mothershipBuildClusterBootstrapRequest(const MothershipProdigyCluster& cluster, AddMachines& request, String *failure = nullptr)
{
   request = {};
   request.bootstrapSshUser = cluster.bootstrapSshUser;
   request.bootstrapSshKeyPackage = cluster.bootstrapSshKeyPackage;
   request.bootstrapSshHostKeyPackage = cluster.bootstrapSshHostKeyPackage;
   request.bootstrapSshPrivateKeyPath = cluster.bootstrapSshPrivateKeyPath;
   request.remoteProdigyPath = cluster.remoteProdigyPath;
   request.clusterUUID = cluster.clusterUUID;
   request.architecture = cluster.architecture;
   return mothershipResolveClusterControlSocketPath(cluster, request.controlSocketPath, failure);
}

static inline void mothershipBuildMachineSchemaPatches(const MothershipProdigyCluster& cluster, Vector<ProdigyManagedMachineSchemaPatch>& patches)
{
   patches.clear();
   patches.reserve(cluster.machineSchemas.size());

   for (const MothershipProdigyClusterMachineSchema& managedSchema : cluster.machineSchemas)
   {
      ProdigyManagedMachineSchemaPatch patch = {};
      patch.schema = managedSchema.schema;
      patch.hasKind = true;
      patch.kind = managedSchema.kind;
      patch.hasLifetime = true;
      patch.lifetime = managedSchema.lifetime;
      patch.hasIpxeScriptURL = true;
      patch.ipxeScriptURL = managedSchema.ipxeScriptURL;
      patch.hasVmImageURI = true;
      patch.vmImageURI = managedSchema.vmImageURI;
      patch.hasGcpInstanceTemplate = true;
      patch.gcpInstanceTemplate = managedSchema.gcpInstanceTemplate;
      patch.hasGcpInstanceTemplateSpot = true;
      patch.gcpInstanceTemplateSpot = managedSchema.gcpInstanceTemplateSpot;
      patch.hasProviderMachineType = true;
      patch.providerMachineType = managedSchema.providerMachineType;
      patch.hasProviderReservationID = true;
      patch.providerReservationID = managedSchema.providerReservationID;
      patch.hasRegion = true;
      patch.region = managedSchema.region;
      patch.hasZone = true;
      patch.zone = managedSchema.zone;
      patch.hasCpu = true;
      patch.cpu = managedSchema.cpu;
      patch.hasBudget = true;
      patch.budget = managedSchema.budget;
      patches.push_back(std::move(patch));
   }
}

static inline bool mothershipSelectClusterSeedPlan(const MothershipProdigyCluster& cluster, MothershipClusterSeedPlan& plan, String *failure = nullptr)
{
   plan = {};
   if (failure) failure->clear();

   if (mothershipClusterIncludesLocalMachine(cluster))
   {
      plan.mode = MothershipClusterSeedMode::local;
      return true;
   }

   auto takeAdoptedBrain = [&] (const MothershipProdigyClusterMachine& machine) -> void {

      mothershipFillAdoptedClusterMachine(machine, plan.seedMachine);
      plan.mode = MothershipClusterSeedMode::adopted;
   };

   auto takeCreatedBrain = [&] (const MothershipProdigyClusterMachineSchema& managedSchema) -> void {

      plan.mode = MothershipClusterSeedMode::created;
      plan.createInstruction = {};
      plan.createInstruction.kind = managedSchema.kind;
      plan.createInstruction.lifetime = managedSchema.lifetime;
      plan.createInstruction.backing = ClusterMachineBacking::cloud;
      plan.createInstruction.cloud.schema = managedSchema.schema;
      plan.createInstruction.cloud.providerMachineType = managedSchema.providerMachineType;
      plan.createInstruction.count = 1;
      plan.createInstruction.isBrain = true;
      plan.createInstruction.region = managedSchema.region;
      plan.createInstruction.zone = managedSchema.zone;
   };

   if (cluster.deploymentMode == MothershipClusterDeploymentMode::local)
   {
      for (const MothershipProdigyClusterMachine& machine : cluster.machines)
      {
         if (machine.isBrain)
         {
            takeAdoptedBrain(machine);
            return true;
         }
      }

      if (failure) failure->assign("local clusters without includeLocalMachine require at least one adopted brain machine"_ctv);
      return false;
   }

   for (const MothershipProdigyClusterMachine& machine : cluster.machines)
   {
      if (machine.isBrain)
      {
         takeAdoptedBrain(machine);
         return true;
      }
   }

   for (const MothershipProdigyClusterMachineSchema& managedSchema : cluster.machineSchemas)
   {
      if (managedSchema.budget > 0)
      {
         takeCreatedBrain(managedSchema);
         return true;
      }
   }

   if (failure) failure->assign("cluster requires a brain seed machine"_ctv);
   return false;
}

static inline void mothershipBuildSeedTopology(const ClusterMachine& seedMachine, ClusterTopology& topology)
{
   topology = {};
   topology.machines.push_back(seedMachine);
}

static inline bool mothershipProvisionCreatedSeedMachine(
   const MothershipProdigyCluster& cluster,
   const CreateMachinesInstruction& instruction,
   BrainIaaS& iaas,
   ClusterMachine& seedMachine,
   BrainIaaSMachineProvisioningProgressSink *progressSink = nullptr,
   ProdigyTimingAttribution *timingAttribution = nullptr,
   String *failure = nullptr)
{
   seedMachine = {};
   if (failure) failure->clear();
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
   uint64_t stageStartNs = Time::now<TimeResolution::ns>();
   uint64_t providerWaitNs = 0;
#endif

   auto finalizeTiming = [&] () -> void {

#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
      if (timingAttribution != nullptr)
      {
         prodigyFinalizeTimingAttribution(Time::now<TimeResolution::ns>() - stageStartNs, providerWaitNs, *timingAttribution);
      }
#else
      (void)timingAttribution;
#endif
   };

   if (instruction.backing != ClusterMachineBacking::cloud)
   {
      if (failure) failure->assign("created seed machine currently requires backing=cloud"_ctv);
      finalizeTiming();
      return false;
   }

   String schemaKey = {};
   if (instruction.cloud.schema.size() > 0)
   {
      schemaKey.assign(instruction.cloud.schema);
   }
   else
   {
      if (failure) failure->assign("created seed machine requires cloud.schema"_ctv);
      finalizeTiming();
      return false;
   }

   const MothershipProdigyClusterMachineSchema *managedSchema = nullptr;
   for (const MothershipProdigyClusterMachineSchema& candidate : cluster.machineSchemas)
   {
      if (candidate.schema.equals(schemaKey))
      {
         managedSchema = &candidate;
         break;
      }
   }

   if (managedSchema == nullptr)
   {
      if (failure) failure->snprintf<"unknown machine schema '{}'"_ctv>(schemaKey);
      finalizeTiming();
      return false;
   }

   if (instruction.kind != managedSchema->kind)
   {
      if (failure) failure->snprintf<"created machine kind mismatch for schema '{}'"_ctv>(schemaKey);
      finalizeTiming();
      return false;
   }

   if (iaas.supports(managedSchema->kind) == false)
   {
      if (failure) failure->snprintf<"current runtime environment does not support machine kind for schema '{}'"_ctv>(schemaKey);
      finalizeTiming();
      return false;
   }

   if (iaas.supportsAutoProvision() == false)
   {
      if (failure) failure->assign("current runtime environment does not support automatic machine provisioning"_ctv);
      finalizeTiming();
      return false;
   }

   iaas.configureBootstrapSSHAccess(cluster.bootstrapSshUser, cluster.bootstrapSshKeyPackage, cluster.bootstrapSshHostKeyPackage, cluster.bootstrapSshPrivateKeyPath);
   iaas.configureProvisioningProgressSink(progressSink);

   MachineConfig machineConfig = {};
   mothershipBuildMachineConfigFromSchema(*managedSchema, machineConfig);

   CoroutineStack coro;
   bytell_hash_set<Machine *> createdSnapshots;
   String providerError;

   iaas.configureProvisioningClusterUUID(cluster.clusterUUID);
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
   uint64_t providerWaitStartNs = Time::now<TimeResolution::ns>();
#endif
   iaas.spinMachines(&coro, instruction.lifetime, machineConfig, 1, instruction.isBrain, createdSnapshots, providerError);
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
   providerWaitNs += (Time::now<TimeResolution::ns>() - providerWaitStartNs);
#endif
   coro.co_consume();
   iaas.configureProvisioningProgressSink(nullptr);

   if (createdSnapshots.size() != 1)
   {
      if (failure)
      {
         if (providerError.size() > 0)
         {
            failure->assign(providerError);
         }
         else
         {
            failure->snprintf<"provider returned {itoa} created machines but 1 was requested"_ctv>(createdSnapshots.size());
         }
      }

      for (Machine *snapshot : createdSnapshots)
      {
         iaas.destroyMachine(snapshot);
         prodigyDestroyMachineSnapshot(snapshot);
      }

      finalizeTiming();
      return false;
   }

   Machine *snapshot = *createdSnapshots.begin();
   prodigyPopulateCreatedClusterMachineFromSnapshot(seedMachine, snapshot, instruction, machineConfig, cluster.bootstrapSshUser, cluster.bootstrapSshPrivateKeyPath, cluster.bootstrapSshHostKeyPackage.publicKeyOpenSSH);
   prodigyDestroyMachineSnapshot(snapshot);

   if (failure) failure->clear();
   finalizeTiming();
   return true;
}

static inline void mothershipDestroyCreatedClusterMachine(BrainIaaS& iaas, const ClusterMachine& clusterMachine)
{
   if (clusterMachine.source != ClusterMachineSource::created
      || clusterMachine.backing != ClusterMachineBacking::cloud
      || clusterMachine.cloud.cloudID.size() == 0)
   {
      return;
   }

   Machine machine = prodigyBuildMachineSnapshotFromClusterMachine(clusterMachine);
   iaas.destroyMachine(&machine);
}

static inline void mothershipDestroyCreatedClusterMachines(BrainIaaS& iaas, const ClusterTopology& topology)
{
   Vector<String> destroyedCloudIDs;

   for (const ClusterMachine& clusterMachine : topology.machines)
   {
      if (clusterMachine.source != ClusterMachineSource::created
         || clusterMachine.backing != ClusterMachineBacking::cloud
         || clusterMachine.cloud.cloudID.size() == 0)
      {
         continue;
      }

      bool alreadyDestroyed = false;
      for (const String& cloudID : destroyedCloudIDs)
      {
         if (cloudID.equals(clusterMachine.cloud.cloudID))
         {
            alreadyDestroyed = true;
            break;
         }
      }

      if (alreadyDestroyed)
      {
         continue;
      }

      mothershipDestroyCreatedClusterMachine(iaas, clusterMachine);
      destroyedCloudIDs.push_back(clusterMachine.cloud.cloudID);
   }
}

class MothershipClusterCreateHooks
{
public:

   virtual ~MothershipClusterCreateHooks() = default;
   virtual bool startTestCluster(const MothershipProdigyCluster& cluster, String *failure = nullptr) = 0;
   virtual bool stopTestCluster(const MothershipProdigyCluster& cluster, String *failure = nullptr) = 0;
   virtual bool prepareProviderBootstrapArtifacts(const MothershipProdigyCluster& cluster, ProdigyTimingAttribution *timingAttribution = nullptr, String *failure = nullptr) = 0;
   virtual bool bootstrapLocalSeed(const ProdigyPersistentBootState& bootState, String *failure = nullptr) = 0;
   virtual bool createSeedMachine(const MothershipProdigyCluster& cluster, const CreateMachinesInstruction& instruction, ClusterMachine& seedMachine, ProdigyTimingAttribution *timingAttribution = nullptr, String *failure = nullptr) = 0;
   virtual bool destroyCreatedSeedMachine(const MothershipProdigyCluster& cluster, const ClusterMachine& seedMachine, String *failure = nullptr) = 0;
   virtual bool bootstrapRemoteSeed(const MothershipProdigyCluster& cluster, const ClusterMachine& seedMachine, const AddMachines& request, const ClusterTopology& topology, const ProdigyRuntimeEnvironmentConfig& runtimeEnvironment, ProdigyTimingAttribution *timingAttribution = nullptr, String *failure = nullptr) = 0;
   virtual bool configureSeedCluster(const MothershipProdigyCluster& cluster, const BrainConfig& config, String *failure = nullptr) = 0;
   virtual bool fetchSeedTopology(const MothershipProdigyCluster& cluster, ClusterTopology& topology, String *failure = nullptr) = 0;
   virtual bool applyAddMachines(const MothershipProdigyCluster& cluster, const AddMachines& request, ClusterTopology& topology, ProdigyTimingAttribution *timingAttribution = nullptr, String *failure = nullptr) = 0;
   virtual bool upsertMachineSchemas(const MothershipProdigyCluster& cluster, const Vector<ProdigyManagedMachineSchemaPatch>& patches, ClusterTopology& topology, ProdigyTimingAttribution *timingAttribution = nullptr, String *failure = nullptr) = 0;
};

static inline bool mothershipStandUpCluster(MothershipProdigyCluster& cluster, const MothershipProviderCredential *credential, MothershipClusterCreateHooks& hooks, MothershipClusterCreateTimingSummary *timingSummary = nullptr, String *failure = nullptr)
{
   if (failure) failure->clear();

   BrainConfig config = {};
   if (mothershipBuildClusterBrainConfig(cluster, credential, config, failure) == false)
   {
      return false;
   }

   if (cluster.deploymentMode == MothershipClusterDeploymentMode::test)
   {
      bool started = false;
      auto failWithCleanup = [&] (const String& localFailure) -> bool {

         if (failure)
         {
            failure->assign(localFailure);
         }

         if (started == false)
         {
            return false;
         }

         const char *keepFailedTestCluster = std::getenv("PRODIGY_MOTHERSHIP_KEEP_FAILED_TEST_CLUSTER");
         if (keepFailedTestCluster != nullptr
            && (std::strcmp(keepFailedTestCluster, "1") == 0
               || std::strcmp(keepFailedTestCluster, "true") == 0
               || std::strcmp(keepFailedTestCluster, "TRUE") == 0
               || std::strcmp(keepFailedTestCluster, "yes") == 0
               || std::strcmp(keepFailedTestCluster, "YES") == 0
               || std::strcmp(keepFailedTestCluster, "on") == 0
               || std::strcmp(keepFailedTestCluster, "ON") == 0))
         {
            if (failure != nullptr)
            {
               failure->append(" | preserved failed test cluster workspace because PRODIGY_MOTHERSHIP_KEEP_FAILED_TEST_CLUSTER is set"_ctv);
            }
            return false;
         }

         String cleanupFailure = {};
         if (hooks.stopTestCluster(cluster, &cleanupFailure) == false && cleanupFailure.size() > 0 && failure != nullptr)
         {
            failure->append(" | cleanup failure: "_ctv);
            failure->append(cleanupFailure);
         }

         return false;
      };

      String localFailure = {};
      if (hooks.startTestCluster(cluster, &localFailure) == false)
      {
         if (failure) failure->assign(localFailure);
         return false;
      }

      started = true;

      if ((config.configBySlug.empty() == false) || config.runtimeEnvironment.configured())
      {
         if (hooks.configureSeedCluster(cluster, config, &localFailure) == false)
         {
            return failWithCleanup(localFailure);
         }

         cluster.environmentConfigured = config.runtimeEnvironment.configured();
      }

      ClusterTopology topology = {};
      constexpr uint32_t topologyFetchAttempts = 200;
      constexpr useconds_t topologyFetchRetrySleepUs = 100 * 1000;
      uint32_t fetchedMachines = 0;
      uint32_t fetchedBrains = 0;
      uint32_t fetchedReadyMachines = 0;
      bool topologyReady = false;
      for (uint32_t attempt = 0; attempt < topologyFetchAttempts; attempt += 1)
      {
         if (hooks.fetchSeedTopology(cluster, topology, &localFailure) == false)
         {
            return failWithCleanup(localFailure);
         }

         fetchedMachines = topology.machines.size();
         fetchedBrains = clusterTopologyBrainCount(topology);
         fetchedReadyMachines = mothershipClusterTopologyMachinesWithReadyResources(topology);
         if (mothershipTestClusterTopologyReady(topology, cluster.test.machineCount, cluster.nBrains))
         {
            topologyReady = true;
            break;
         }

         usleep(topologyFetchRetrySleepUs);
      }

      if (topologyReady == false)
      {
         localFailure.snprintf<"test cluster topology mismatch after wait expectedMachines={itoa} gotMachines={itoa} expectedBrains={itoa} gotBrains={itoa} readyMachines={itoa}"_ctv>(
            uint64_t(cluster.test.machineCount),
            uint64_t(fetchedMachines),
            uint64_t(cluster.nBrains),
            uint64_t(fetchedBrains),
            uint64_t(fetchedReadyMachines));
         return failWithCleanup(localFailure);
      }

      cluster.topology = topology;
      return true;
   }

   AddMachines bootstrapRequest = {};
   if (mothershipBuildClusterBootstrapRequest(cluster, bootstrapRequest, failure) == false)
   {
      return false;
   }

   MothershipClusterSeedPlan seedPlan = {};
   if (mothershipSelectClusterSeedPlan(cluster, seedPlan, failure) == false)
   {
      return false;
   }

   bool prepareProviderBootstrapArtifacts =
      cluster.deploymentMode == MothershipClusterDeploymentMode::remote
      && (cluster.provider == MothershipClusterProvider::gcp
         || cluster.provider == MothershipClusterProvider::azure);
   if (prepareProviderBootstrapArtifacts)
   {
      prepareProviderBootstrapArtifacts = false;
      for (const MothershipProdigyClusterMachineSchema& managedSchema : cluster.machineSchemas)
      {
         if (managedSchema.budget > 0)
         {
            prepareProviderBootstrapArtifacts = true;
            break;
         }
      }
   }

   if (prepareProviderBootstrapArtifacts)
   {
      String localFailure = {};
      ProdigyTimingAttribution stageTiming = {};
      if (hooks.prepareProviderBootstrapArtifacts(cluster, &stageTiming, &localFailure) == false)
      {
         if (failure) failure->assign(localFailure);
         return false;
      }

      mothershipAccumulateClusterCreateTimingStage(timingSummary, &MothershipClusterCreateTimingSummary::prepareProviderBootstrapArtifacts, stageTiming);
   }

   bool destroyCreatedSeedOnFailure = false;
   auto failWithCleanup = [&] (const String& localFailure) -> bool {

      if (failure)
      {
         failure->assign(localFailure);
      }

      if (destroyCreatedSeedOnFailure == false)
      {
         return false;
      }

      String cleanupFailure;
      if (hooks.destroyCreatedSeedMachine(cluster, seedPlan.seedMachine, &cleanupFailure) == false && cleanupFailure.size() > 0)
      {
         if (failure)
         {
            failure->append(" | cleanup failure: "_ctv);
            failure->append(cleanupFailure);
         }
      }

      return false;
   };

   if (seedPlan.mode == MothershipClusterSeedMode::local)
   {
      ProdigyPersistentBootState bootState = {};
      bootState.bootstrapConfig.nodeRole = ProdigyBootstrapNodeRole::brain;
      bootState.bootstrapConfig.controlSocketPath = bootstrapRequest.controlSocketPath;
      bootState.bootstrapSshUser = bootstrapRequest.bootstrapSshUser;
      bootState.bootstrapSshKeyPackage = bootstrapRequest.bootstrapSshKeyPackage;
      bootState.bootstrapSshHostKeyPackage = bootstrapRequest.bootstrapSshHostKeyPackage;
      bootState.bootstrapSshPrivateKeyPath = bootstrapRequest.bootstrapSshPrivateKeyPath;
      prodigyOwnRuntimeEnvironmentConfig(config.runtimeEnvironment, bootState.runtimeEnvironment);

      if (hooks.bootstrapLocalSeed(bootState, failure) == false)
      {
         return false;
      }
   }
   else
   {
      if (seedPlan.mode == MothershipClusterSeedMode::created)
      {
         String localFailure;
         ProdigyTimingAttribution stageTiming = {};
         if (hooks.createSeedMachine(cluster, seedPlan.createInstruction, seedPlan.seedMachine, &stageTiming, &localFailure) == false)
         {
            if (failure) failure->assign(localFailure);
            return false;
         }

         mothershipAccumulateClusterCreateTimingStage(timingSummary, &MothershipClusterCreateTimingSummary::createSeedMachine, stageTiming);
         destroyCreatedSeedOnFailure = true;
      }

      ClusterTopology seedTopology = {};
      mothershipBuildSeedTopology(seedPlan.seedMachine, seedTopology);
      cluster.topology = seedTopology;

      ProdigyRuntimeEnvironmentConfig bootstrapRuntimeEnvironment = {};
      mothershipBuildSeedBootstrapRuntimeEnvironment(config.runtimeEnvironment, bootstrapRuntimeEnvironment);

      String localFailure;
      ProdigyTimingAttribution stageTiming = {};
      if (hooks.bootstrapRemoteSeed(cluster, seedPlan.seedMachine, bootstrapRequest, seedTopology, bootstrapRuntimeEnvironment, &stageTiming, &localFailure) == false)
      {
         return failWithCleanup(localFailure);
      }

      mothershipAccumulateClusterCreateTimingStage(timingSummary, &MothershipClusterCreateTimingSummary::bootstrapRemoteSeed, stageTiming);
   }

   bool deferProviderCredentialUntilAfterTopology =
      seedPlan.mode != MothershipClusterSeedMode::local
      && config.runtimeEnvironment.providerCredentialMaterial.size() > 0;
   {
      // The seed must always receive cluster identity and scheduler/runtime
      // defaults first. Remote managed machine schemas are applied only after
      // manual membership changes so the seed does not over-provision before
      // adopted brains are attached.
      BrainConfig initialConfig = config;
      if (deferProviderCredentialUntilAfterTopology)
      {
         initialConfig.runtimeEnvironment.providerCredentialMaterial.reset();
      }
      String localFailure;
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
      uint64_t stageStartNs = Time::now<TimeResolution::ns>();
#endif
      if (hooks.configureSeedCluster(cluster, initialConfig, &localFailure) == false)
      {
         return failWithCleanup(localFailure);
      }

      ProdigyTimingAttribution stageTiming = {};
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
      prodigyFinalizeTimingAttribution(Time::now<TimeResolution::ns>() - stageStartNs, 0, stageTiming);
#endif
      mothershipAccumulateClusterCreateTimingStage(timingSummary, &MothershipClusterCreateTimingSummary::configureSeedCluster, stageTiming);

      if (deferProviderCredentialUntilAfterTopology == false)
      {
         cluster.environmentConfigured = config.runtimeEnvironment.configured();
      }
   }

   ClusterTopology currentTopology = cluster.topology;
   bool requiresExplicitSeedTopologyFetch =
      cluster.deploymentMode != MothershipClusterDeploymentMode::remote
      || cluster.machines.empty() == false;
   if (requiresExplicitSeedTopologyFetch)
   {
      String localFailure;
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
      uint64_t stageStartNs = Time::now<TimeResolution::ns>();
#endif
      if (hooks.fetchSeedTopology(cluster, currentTopology, &localFailure) == false)
      {
         return failWithCleanup(localFailure);
      }

      ProdigyTimingAttribution stageTiming = {};
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
      prodigyFinalizeTimingAttribution(Time::now<TimeResolution::ns>() - stageStartNs, 0, stageTiming);
#endif
      mothershipAccumulateClusterCreateTimingStage(timingSummary, &MothershipClusterCreateTimingSummary::fetchSeedTopology, stageTiming);
   }

   cluster.topology = currentTopology;

   AddMachines request = {};
   if (mothershipBuildClusterAddMachinesRequest(cluster, currentTopology, request, failure) == false)
   {
      return false;
   }

   if (request.adoptedMachines.empty() == false || request.readyMachines.empty() == false || request.removedMachines.empty() == false)
   {
      ClusterTopology finalTopology = {};
      String localFailure;
      ProdigyTimingAttribution stageTiming = {};
      if (hooks.applyAddMachines(cluster, request, finalTopology, &stageTiming, &localFailure) == false)
      {
         return failWithCleanup(localFailure);
      }

      cluster.topology = finalTopology;
      mothershipAccumulateClusterCreateTimingStage(timingSummary, &MothershipClusterCreateTimingSummary::applyAddMachines, stageTiming);
   }

   if (deferProviderCredentialUntilAfterTopology)
   {
      String localFailure;
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
      uint64_t stageStartNs = Time::now<TimeResolution::ns>();
#endif
      if (hooks.configureSeedCluster(cluster, config, &localFailure) == false)
      {
         return failWithCleanup(localFailure);
      }

      ProdigyTimingAttribution stageTiming = {};
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
      prodigyFinalizeTimingAttribution(Time::now<TimeResolution::ns>() - stageStartNs, 0, stageTiming);
#endif
      mothershipAccumulateClusterCreateTimingStage(timingSummary, &MothershipClusterCreateTimingSummary::configureSeedCluster, stageTiming);
      cluster.environmentConfigured = config.runtimeEnvironment.configured();
   }

   bool hasManagedMachineSchemas = false;
   if (cluster.deploymentMode == MothershipClusterDeploymentMode::remote)
   {
      for (const MothershipProdigyClusterMachineSchema& managedSchema : cluster.machineSchemas)
      {
         if (managedSchema.budget > 0)
         {
            hasManagedMachineSchemas = true;
            break;
         }
      }
   }

   if (hasManagedMachineSchemas)
   {
      Vector<ProdigyManagedMachineSchemaPatch> patches = {};
      mothershipBuildMachineSchemaPatches(cluster, patches);

      ClusterTopology finalTopology = {};
      String localFailure;
      ProdigyTimingAttribution stageTiming = {};
      if (hooks.upsertMachineSchemas(cluster, patches, finalTopology, &stageTiming, &localFailure) == false)
      {
         return failWithCleanup(localFailure);
      }

      cluster.topology = finalTopology;
      mothershipAccumulateClusterCreateTimingStage(timingSummary, &MothershipClusterCreateTimingSummary::upsertMachineSchemas, stageTiming);
   }

   return true;
}

static inline bool mothershipRestartTestClusterToDesiredShape(
   const MothershipProdigyCluster& currentCluster,
   MothershipProdigyCluster& desiredCluster,
   const ClusterTopology& currentTopology,
   MothershipClusterCreateHooks& hooks,
   bool& changed,
   String *failure = nullptr)
{
   changed = false;
   if (failure) failure->clear();

   uint32_t runtimeBrains = clusterTopologyBrainCount(currentTopology);
   if (currentTopology.machines.size() == desiredCluster.test.machineCount && runtimeBrains == desiredCluster.nBrains)
   {
      desiredCluster.topology = currentTopology;
      return true;
   }

   String localFailure = {};
   if (hooks.stopTestCluster(currentCluster, &localFailure) == false)
   {
      if (failure) failure->assign(localFailure);
      return false;
   }

   if (mothershipStandUpCluster(desiredCluster, nullptr, hooks, nullptr, &localFailure) == false)
   {
      if (failure) failure->assign(localFailure);
      return false;
   }

   changed = true;
   if (failure) failure->clear();
   return true;
}
