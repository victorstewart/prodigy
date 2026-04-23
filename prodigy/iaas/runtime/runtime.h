#pragma once

#include <memory>
#include <services/debug.h>

#include <prodigy/bootstrap.config.h>
#include <prodigy/iaas/aws/aws.h>
#include <prodigy/iaas/azure/azure.h>
#include <prodigy/iaas/bootstrap/bootstrap.h>
#include <prodigy/iaas/dev/dev.h>
#include <prodigy/iaas/gcp/gcp.h>
#include <prodigy/iaas/vultr/vultr.h>
#include <prodigy/persistent.state.h>

static inline std::unique_ptr<BrainIaaS> prodigyCreateProviderBrainIaaS(const ProdigyRuntimeEnvironmentConfig& config)
{
   switch (config.kind)
   {
      case ProdigyEnvironmentKind::dev:
      {
         return std::make_unique<DevBrainIaaS>();
      }
      case ProdigyEnvironmentKind::gcp:
      {
         return std::make_unique<GcpBrainIaaS>();
      }
      case ProdigyEnvironmentKind::aws:
      {
         return std::make_unique<AwsBrainIaaS>();
      }
      case ProdigyEnvironmentKind::azure:
      {
         return std::make_unique<AzureBrainIaaS>();
      }
      case ProdigyEnvironmentKind::vultr:
      {
         return std::make_unique<VultrBrainIaaS>();
      }
      case ProdigyEnvironmentKind::unknown:
      default:
      {
         return nullptr;
      }
   }
}

static inline std::unique_ptr<NeuronIaaS> prodigyCreateProviderNeuronIaaS(const ProdigyRuntimeEnvironmentConfig& config)
{
   switch (config.kind)
   {
      case ProdigyEnvironmentKind::dev:
      {
         return std::make_unique<DevNeuronIaaS>();
      }
      case ProdigyEnvironmentKind::gcp:
      {
         return std::make_unique<GcpNeuronIaaS>();
      }
      case ProdigyEnvironmentKind::aws:
      {
         return std::make_unique<AwsNeuronIaaS>();
      }
      case ProdigyEnvironmentKind::azure:
      {
         return std::make_unique<AzureNeuronIaaS>();
      }
      case ProdigyEnvironmentKind::vultr:
      {
         return std::make_unique<VultrNeuronIaaS>();
      }
      case ProdigyEnvironmentKind::unknown:
      default:
      {
         return nullptr;
      }
   }
}

class RuntimeAwareBrainIaaS : public BrainIaaS
{
private:

   ProdigyBootstrapConfig bootstrapConfig;
   ProdigyRuntimeEnvironmentConfig runtimeEnvironment;
   ProdigyPersistentBootState persistentBootState = {};
   ProdigyPersistentStateStore *stateStore = nullptr;
   BootstrapBrainIaaS bootstrapDelegate;
   std::unique_ptr<BrainIaaS> providerDelegate;

   BrainIaaS *activeDelegate(void)
   {
      return providerDelegate ? providerDelegate.get() : static_cast<BrainIaaS *>(&bootstrapDelegate);
   }

   void persistBootState(void)
   {
      if (stateStore == nullptr)
      {
         return;
      }

      persistentBootState.bootstrapConfig = bootstrapConfig;
      prodigyOwnRuntimeEnvironmentConfig(runtimeEnvironment, persistentBootState.runtimeEnvironment);

      String failure;
      if (stateStore->saveBootState(persistentBootState, &failure) == false)
      {
         basics_log("RuntimeAwareBrainIaaS boot-state persist failed: %s\n", failure.c_str());
      }
   }

public:

   RuntimeAwareBrainIaaS(ProdigyPersistentStateStore *store, const ProdigyBootstrapConfig& bootstrap, const ProdigyPersistentBootState& bootState)
      : bootstrapConfig(bootstrap), stateStore(store), bootstrapDelegate(bootstrap)
   {
      persistentBootState = bootState;
      prodigyOwnRuntimeEnvironmentConfig(bootState.runtimeEnvironment, runtimeEnvironment);
      prodigyStripManagedCloudBootstrapCredentials(runtimeEnvironment);
      prodigyApplyInternalRuntimeEnvironmentDefaults(runtimeEnvironment);
      providerDelegate = prodigyCreateProviderBrainIaaS(runtimeEnvironment);
      if (providerDelegate)
      {
         providerDelegate->configureRuntimeEnvironment(runtimeEnvironment);
      }
      persistBootState();
   }

   void configureBootstrapTopology(const ProdigyBootstrapConfig& bootstrap)
   {
      bootstrapConfig = bootstrap;
      bootstrapDelegate = BootstrapBrainIaaS(bootstrapConfig);
      persistBootState();
   }

   void boot(void) override
   {
      activeDelegate()->boot();
   }

   void configureRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& config) override
   {
      prodigyOwnRuntimeEnvironmentConfig(config, runtimeEnvironment);
      prodigyStripManagedCloudBootstrapCredentials(runtimeEnvironment);
      prodigyApplyInternalRuntimeEnvironmentDefaults(runtimeEnvironment);
      providerDelegate = prodigyCreateProviderBrainIaaS(runtimeEnvironment);
      if (providerDelegate)
      {
         providerDelegate->configureRuntimeEnvironment(runtimeEnvironment);
      }
      persistBootState();
   }

   void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) override
   {
      activeDelegate()->spinMachines(coro, lifetime, config, count, newMachines, error);
   }

   void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bool isBrain, bytell_hash_set<Machine *>& newMachines, String& error) override
   {
      activeDelegate()->spinMachines(coro, lifetime, config, count, isBrain, newMachines, error);
   }

   void configureBootstrapSSHAccess(const String& user, const Vault::SSHKeyPackage& keyPackage, const Vault::SSHKeyPackage& hostKeyPackage, const String& privateKeyPath) override
   {
      persistentBootState.bootstrapSshUser.assign(user);
      persistentBootState.bootstrapSshKeyPackage = keyPackage;
      persistentBootState.bootstrapSshHostKeyPackage = hostKeyPackage;
      persistentBootState.bootstrapSshPrivateKeyPath.assign(privateKeyPath);
      activeDelegate()->configureBootstrapSSHAccess(user, keyPackage, hostKeyPackage, privateKeyPath);
      persistBootState();
   }

   void configureProvisioningProgressSink(BrainIaaSMachineProvisioningProgressSink *sink) override
   {
      activeDelegate()->configureProvisioningProgressSink(sink);
   }

   void configureProvisioningClusterUUID(uint128_t clusterUUID) override
   {
      activeDelegate()->configureProvisioningClusterUUID(clusterUUID);
   }

   bool supportsIncrementalProvisioningCallbacks() const override
   {
      return providerDelegate ? providerDelegate->supportsIncrementalProvisioningCallbacks() : bootstrapDelegate.supportsIncrementalProvisioningCallbacks();
   }

   void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines) override
   {
      bootstrapDelegate.getMachines(coro, metro, machines);
   }

   void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains) override
   {
      bootstrapDelegate.getBrains(coro, selfUUID, selfIsBrain, brains);
   }

   bool resolveLocalBrainPeerAddress(IPAddress& address, String& addressText) const override
   {
      return bootstrapDelegate.resolveLocalBrainPeerAddress(address, addressText);
   }

   bool bgpEnabledForEnvironment(void) const override
   {
      if (runtimeEnvironment.bgp.configured())
      {
         return runtimeEnvironment.bgp.config.enabled;
      }

      return providerDelegate ? providerDelegate->bgpEnabledForEnvironment() : false;
   }

   bool inferMachineSchemaCpuCapability(const MachineConfig& config, MachineSchemaCpuCapability& capability, String& error) override
   {
      return activeDelegate()->inferMachineSchemaCpuCapability(config, capability, error);
   }

   bool supportsAuthoritativeMachineSchemaCpuCapabilityInference(void) const override
   {
      return providerDelegate ? providerDelegate->supportsAuthoritativeMachineSchemaCpuCapabilityInference() : bootstrapDelegate.supportsAuthoritativeMachineSchemaCpuCapabilityInference();
   }

   void hardRebootMachine(uint128_t uuid) override
   {
      activeDelegate()->hardRebootMachine(uuid);
   }

   void reportHardwareFailure(uint128_t uuid, const String& report) override
   {
      activeDelegate()->reportHardwareFailure(uuid, report);
   }

   void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
   {
      activeDelegate()->checkForSpotTerminations(coro, decommissionedIDs);
   }

   void destroyMachine(Machine *machine) override
   {
      activeDelegate()->destroyMachine(machine);
   }

   bool destroyClusterMachines(const String& clusterUUID, uint32_t& destroyed, String& error) override
   {
      return activeDelegate()->destroyClusterMachines(clusterUUID, destroyed, error);
   }

   bool ensureProdigyMachineTags(const String& clusterUUID, Machine *machine, String& error) override
   {
      return activeDelegate()->ensureProdigyMachineTags(clusterUUID, machine, error);
   }

   bool assignProviderElasticAddress(Machine *machine,
      ExternalAddressFamily family,
      const String& requestedAddress,
      const String& providerPool,
      IPAddress& assignedAddress,
      String& allocationID,
      String& associationID,
      bool& releaseOnRemove,
      String& error) override
   {
      return activeDelegate()->assignProviderElasticAddress(machine,
         family,
         requestedAddress,
         providerPool,
         assignedAddress,
         allocationID,
         associationID,
         releaseOnRemove,
         error);
   }

   bool releaseProviderElasticAddress(const RegisteredRoutableAddress& address, String& error) override
   {
      return activeDelegate()->releaseProviderElasticAddress(address, error);
   }

   uint32_t supportedMachineKindsMask() const override
   {
      return providerDelegate ? providerDelegate->supportedMachineKindsMask() : bootstrapDelegate.supportedMachineKindsMask();
   }

   bool supportsAutoProvision() const override
   {
      return providerDelegate ? providerDelegate->supportsAutoProvision() : bootstrapDelegate.supportsAutoProvision();
   }
};

class RuntimeAwareNeuronIaaS : public NeuronIaaS
{
private:

   ProdigyBootstrapConfig bootstrapConfig;
   ProdigyRuntimeEnvironmentConfig runtimeEnvironment;
   ProdigyPersistentBootState persistentBootState = {};
   ProdigyPersistentStateStore *stateStore = nullptr;
   BootstrapNeuronIaaS bootstrapDelegate;
   std::unique_ptr<NeuronIaaS> providerDelegate;

   NeuronIaaS *activeDelegate(void)
   {
      return providerDelegate ? providerDelegate.get() : static_cast<NeuronIaaS *>(&bootstrapDelegate);
   }

   uint128_t resolvePersistentLocalNodeUUID(void)
   {
      if (stateStore == nullptr)
      {
         return 0;
      }

      ProdigyPersistentLocalBrainState localState = {};
      String loadFailure = {};
      if (stateStore->loadLocalBrainState(localState, &loadFailure))
      {
         if (localState.uuid != 0)
         {
            return localState.uuid;
         }
      }
      else if (loadFailure.size() > 0 && loadFailure != "record not found"_ctv)
      {
         basics_log("RuntimeAwareNeuronIaaS local-state load failed: %s\n", loadFailure.c_str());
      }

      if (bootstrapConfig.nodeRole != ProdigyBootstrapNodeRole::brain)
      {
         return 0;
      }

      uint128_t uuid = 0;
      String failure;
      if (stateStore->loadOrCreateLocalBrainUUID(uuid, &failure) == false)
      {
         basics_log("RuntimeAwareNeuronIaaS local-brain-uuid persist failed: %s\n", failure.c_str());
         return 0;
      }

      return uuid;
   }

   void persistBootState(void)
   {
      if (stateStore == nullptr)
      {
         return;
      }

      persistentBootState.bootstrapConfig = bootstrapConfig;
      prodigyOwnRuntimeEnvironmentConfig(runtimeEnvironment, persistentBootState.runtimeEnvironment);

      String failure;
      if (stateStore->saveBootState(persistentBootState, &failure) == false)
      {
         basics_log("RuntimeAwareNeuronIaaS boot-state persist failed: %s\n", failure.c_str());
      }
   }

public:

   RuntimeAwareNeuronIaaS(ProdigyPersistentStateStore *store, const ProdigyBootstrapConfig& bootstrap, const ProdigyPersistentBootState& bootState)
      : bootstrapConfig(bootstrap), stateStore(store), bootstrapDelegate(bootstrap)
   {
      persistentBootState = bootState;
      prodigyOwnRuntimeEnvironmentConfig(bootState.runtimeEnvironment, runtimeEnvironment);
      prodigyStripManagedCloudBootstrapCredentials(runtimeEnvironment);
      prodigyApplyInternalRuntimeEnvironmentDefaults(runtimeEnvironment);
      providerDelegate = prodigyCreateProviderNeuronIaaS(runtimeEnvironment);
      if (providerDelegate)
      {
         providerDelegate->configureRuntimeEnvironment(runtimeEnvironment);
      }
      persistBootState();
   }

   void configureBootstrapTopology(const ProdigyBootstrapConfig& bootstrap)
   {
      bootstrapConfig = bootstrap;
      bootstrapDelegate = BootstrapNeuronIaaS(bootstrapConfig);
      persistBootState();
   }

   void configureRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& config) override
   {
      prodigyOwnRuntimeEnvironmentConfig(config, runtimeEnvironment);
      prodigyStripManagedCloudBootstrapCredentials(runtimeEnvironment);
      prodigyApplyInternalRuntimeEnvironmentDefaults(runtimeEnvironment);
      providerDelegate = prodigyCreateProviderNeuronIaaS(runtimeEnvironment);
      if (providerDelegate)
      {
         providerDelegate->configureRuntimeEnvironment(runtimeEnvironment);
      }
      persistBootState();
   }

   void gatherSelfData(uint128_t& uuid, String& metro, bool& isBrain, EthDevice& eth, IPAddress& private4) override
   {
      activeDelegate()->gatherSelfData(uuid, metro, isBrain, eth, private4);
      if (uint128_t persistentUUID = resolvePersistentLocalNodeUUID(); persistentUUID != 0)
      {
         uuid = persistentUUID;
      }
      isBrain = (bootstrapConfig.nodeRole == ProdigyBootstrapNodeRole::brain);
   }

   void gatherBGPConfig(NeuronBGPConfig& config, EthDevice& eth, const IPAddress& private4) override
   {
      if (prodigyResolveRuntimeEnvironmentBGPOverride(runtimeEnvironment, private4, config))
      {
         return;
      }

      activeDelegate()->gatherBGPConfig(config, eth, private4);
   }

   void setLocalContainerPrefixes(const Vector<IPPrefix>& prefixes) override
   {
      activeDelegate()->setLocalContainerPrefixes(prefixes);
   }

   void downloadContainerToPath(CoroutineStack *coro, uint64_t deploymentID, const String& path) override
   {
      activeDelegate()->downloadContainerToPath(coro, deploymentID, path);
   }
};
