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

static inline std::unique_ptr<BrainIaaS> prodigyCreateProviderBrainIaaS(
    const ProdigyRuntimeEnvironmentConfig& config,
    ProdigyProviderServices services)
{
  std::unique_ptr<BrainIaaS> provider;
  switch (config.kind)
  {
    case ProdigyEnvironmentKind::dev:
      {
        provider = std::make_unique<DevBrainIaaS>();
        break;
      }
    case ProdigyEnvironmentKind::gcp:
      {
        provider = std::make_unique<GcpBrainIaaS>();
        break;
      }
    case ProdigyEnvironmentKind::aws:
      {
        provider = std::make_unique<AwsBrainIaaS>();
        break;
      }
    case ProdigyEnvironmentKind::azure:
      {
        provider = std::make_unique<AzureBrainIaaS>();
        break;
      }
    case ProdigyEnvironmentKind::vultr:
      {
        provider = std::make_unique<VultrBrainIaaS>();
        break;
      }
    case ProdigyEnvironmentKind::unknown:
    default:
      {
        break;
      }
  }

  if (provider)
  {
    provider->configureProviderServices(services);
  }
  return provider;
}

static inline std::unique_ptr<NeuronIaaS> prodigyCreateProviderNeuronIaaS(
    const ProdigyRuntimeEnvironmentConfig& config,
    ProdigyProviderServices services)
{
  std::unique_ptr<NeuronIaaS> provider;
  switch (config.kind)
  {
    case ProdigyEnvironmentKind::dev:
      {
        provider = std::make_unique<DevNeuronIaaS>();
        break;
      }
    case ProdigyEnvironmentKind::gcp:
      {
        provider = std::make_unique<GcpNeuronIaaS>();
        break;
      }
    case ProdigyEnvironmentKind::aws:
      {
        provider = std::make_unique<AwsNeuronIaaS>();
        break;
      }
    case ProdigyEnvironmentKind::azure:
      {
        provider = std::make_unique<AzureNeuronIaaS>();
        break;
      }
    case ProdigyEnvironmentKind::vultr:
      {
        provider = std::make_unique<VultrNeuronIaaS>();
        break;
      }
    case ProdigyEnvironmentKind::unknown:
    default:
      {
        break;
      }
  }

  if (provider)
  {
    provider->configureProviderServices(services);
  }
  return provider;
}

class RuntimeAwareBrainIaaS : public BrainIaaS {
private:

  ProdigyBootstrapConfig bootstrapConfig;
  ProdigyRuntimeEnvironmentConfig runtimeEnvironment;
  ProdigyRuntimeEnvironmentConfig pendingRuntimeEnvironment;
  ProdigyPersistentBootState persistentBootState = {};
  ProdigyPersistentStateStore *stateStore = nullptr;
  BootstrapBrainIaaS bootstrapDelegate;
  std::unique_ptr<BrainIaaS> providerDelegate;
  bool providerReconfigurationPending = false;
  bool elasticAddressOperationBatchActive = false;
  bool elasticAddressReleaseFenceActive = false;

  BrainIaaS *activeDelegate(void)
  {
    return providerDelegate ? providerDelegate.get() : static_cast<BrainIaaS *>(&bootstrapDelegate);
  }

  void applyRuntimeEnvironment(void)
  {
    providerDelegate = prodigyCreateProviderBrainIaaS(runtimeEnvironment, providerServices);
    if (providerDelegate)
    {
      providerDelegate->configureRuntimeEnvironment(runtimeEnvironment);
    }
    providerReconfigurationPending = false;
  }

  void applyPendingRuntimeEnvironment(BrainIaaS *completedDelegate)
  {
    if (completedDelegate != nullptr && providerReconfigurationPending &&
        elasticAddressOperationBatchActive == false && elasticAddressReleaseFenceActive == false &&
        completedDelegate == providerDelegate.get() &&
        completedDelegate->hasActiveControlOperations() == false)
    {
      prodigyOwnRuntimeEnvironmentConfig(pendingRuntimeEnvironment, runtimeEnvironment);
      pendingRuntimeEnvironment = {};
      applyRuntimeEnvironment();
      persistBootState();
    }
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

  RuntimeAwareBrainIaaS(ProdigyPersistentStateStore *store,
                        const ProdigyBootstrapConfig& bootstrap,
                        const ProdigyPersistentBootState& bootState,
                        ProdigyProviderServices requestedProviderServices)
      : bootstrapConfig(bootstrap),
        stateStore(store),
        bootstrapDelegate(bootstrap)
  {
    providerServices = requestedProviderServices;
    persistentBootState = bootState;
    prodigyOwnRuntimeEnvironmentConfig(bootState.runtimeEnvironment, runtimeEnvironment);
    prodigyStripManagedCloudBootstrapCredentials(runtimeEnvironment);
    prodigyApplyInternalRuntimeEnvironmentDefaults(runtimeEnvironment);
    applyRuntimeEnvironment();
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

  bool beginElasticAddressOperationBatch(void) override
  {
    if (elasticAddressOperationBatchActive)
    {
      return false;
    }
    elasticAddressOperationBatchActive = true;
    return true;
  }

  void endElasticAddressOperationBatch(void) override
  {
    if (elasticAddressOperationBatchActive == false)
    {
      return;
    }
    elasticAddressOperationBatchActive = false;
    applyPendingRuntimeEnvironment(providerDelegate.get());
  }

  void configureRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& config) override
  {
    if (elasticAddressReleaseFenceActive)
    {
      return;
    }
    ProdigyRuntimeEnvironmentConfig requestedEnvironment;
    prodigyOwnRuntimeEnvironmentConfig(config, requestedEnvironment);
    prodigyStripManagedCloudBootstrapCredentials(requestedEnvironment);
    prodigyApplyInternalRuntimeEnvironmentDefaults(requestedEnvironment);
    if (providerDelegate &&
        (providerDelegate->hasActiveControlOperations() || elasticAddressOperationBatchActive))
    {
      prodigyOwnRuntimeEnvironmentConfig(requestedEnvironment, pendingRuntimeEnvironment);
      providerReconfigurationPending = true;
      return;
    }
    prodigyOwnRuntimeEnvironmentConfig(requestedEnvironment, runtimeEnvironment);
    applyRuntimeEnvironment();
    persistBootState();
  }

  bool setElasticAddressReleaseFenceActive(bool active) override
  {
    if (active && providerDelegate == nullptr)
    {
      return false;
    }
    elasticAddressReleaseFenceActive = active;
    if (active == false)
    {
      applyPendingRuntimeEnvironment(providerDelegate.get());
    }
    return true;
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

  void configureProvisioningOperationID(uint64_t operationID) override
  {
    activeDelegate()->configureProvisioningOperationID(operationID);
  }

  bool provisioningOperationSettled(void) override
  {
    return activeDelegate()->provisioningOperationSettled();
  }

  bool supportsIncrementalProvisioningCallbacks() const override
  {
    return providerDelegate ? providerDelegate->supportsIncrementalProvisioningCallbacks() : bootstrapDelegate.supportsIncrementalProvisioningCallbacks();
  }

  bool supportsTransactionalElasticAddresses(void) const override
  {
    return providerDelegate && providerDelegate->supportsTransactionalElasticAddresses();
  }

  bool validateProviderElasticAddressPlan(const ProviderElasticAddressPlan& plan,
                                          const ProviderElasticAddressRequest& request,
                                          uint128_t transactionNonce) const override
  {
    return providerDelegate &&
           providerDelegate->validateProviderElasticAddressPlan(plan, request, transactionNonce);
  }

  void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines, String& failure) override
  {
    bootstrapDelegate.getMachines(coro, metro, machines, failure);
  }

  void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains, String& failure) override
  {
    bootstrapDelegate.getBrains(coro, selfUUID, selfIsBrain, brains, failure);
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

  void inferMachineSchemaCpuCapability(CoroutineStack *coro, const MachineConfig& config, MachineSchemaCpuCapability& capability, String& error) override
  {
    activeDelegate()->inferMachineSchemaCpuCapability(coro, config, capability, error);
  }

  bool supportsAuthoritativeMachineSchemaCpuCapabilityInference(void) const override
  {
    return providerDelegate ? providerDelegate->supportsAuthoritativeMachineSchemaCpuCapabilityInference() : bootstrapDelegate.supportsAuthoritativeMachineSchemaCpuCapabilityInference();
  }

  void preflightClusterCreate(CoroutineStack *coro, const BrainIaaSClusterCreatePreflight& preflight, String& error) override
  {
    activeDelegate()->preflightClusterCreate(coro, preflight, error);
  }

  void hardRebootMachine(CoroutineStack *coro, const String& cloudID, String& failure) override
  {
    if (coro == nullptr)
    {
      failure.assign("provider hard reboot coroutine required"_ctv);
      co_return;
    }
    BrainIaaS *delegate = activeDelegate();
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          delegate->hardRebootMachine(coro, cloudID, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }

    applyPendingRuntimeEnvironment(delegate);
  }

  void reportHardwareFailure(uint128_t uuid, const String& report) override
  {
    activeDelegate()->reportHardwareFailure(uuid, report);
  }

  void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
  {
    BrainIaaS *delegate = activeDelegate();
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          delegate->checkForSpotTerminations(coro, decommissionedIDs);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }

    applyPendingRuntimeEnvironment(delegate);
  }

  void destroyMachine(CoroutineStack *coro, const String& cloudID, String& failure) override
  {
    if (coro == nullptr)
    {
      failure.assign("provider machine destroy coroutine required"_ctv);
      co_return;
    }
    BrainIaaS *delegate = activeDelegate();
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          delegate->destroyMachine(coro, cloudID, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }

    applyPendingRuntimeEnvironment(delegate);
  }

  void destroyClusterMachines(CoroutineStack *coro, const String& clusterUUID, uint32_t& destroyed, String& error) override
  {
    if (coro == nullptr)
    {
      destroyed = 0;
      error.assign("provider cluster destroy coroutine required"_ctv);
      co_return;
    }
    BrainIaaS *delegate = activeDelegate();
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          delegate->destroyClusterMachines(coro, clusterUUID, destroyed, error);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }

    applyPendingRuntimeEnvironment(delegate);
  }

  void ensureProdigyMachineTags(CoroutineStack *coro,
                                const String& clusterUUID,
                                const String& cloudID,
                                String& error) override
  {
    if (coro == nullptr)
    {
      error.assign("provider machine tags coroutine required"_ctv);
      co_return;
    }
    BrainIaaS *delegate = activeDelegate();
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          delegate->ensureProdigyMachineTags(coro, clusterUUID, cloudID, error);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }

    applyPendingRuntimeEnvironment(delegate);
  }

  void prepareProviderElasticAddress(CoroutineStack *coro,
                                     const ProviderElasticAddressRequest& request,
                                     uint128_t transactionNonce,
                                     ProviderElasticAddressPlan& plan,
                                     String& error) override
  {
    if (coro == nullptr)
    {
      plan = {};
      error.assign("provider elastic address prepare coroutine required"_ctv);
      co_return;
    }

    BrainIaaS *delegate = activeDelegate();
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          delegate->prepareProviderElasticAddress(coro, request, transactionNonce, plan, error);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }

    applyPendingRuntimeEnvironment(delegate);
  }

  void applyProviderElasticAddress(CoroutineStack *coro,
                                   const ProviderElasticAddressPlan& plan,
                                   ProviderElasticAddressAssignment& assignment,
                                   String& error) override
  {
    if (coro == nullptr)
    {
      assignment = {};
      error.assign("provider elastic address apply coroutine required"_ctv);
      co_return;
    }

    BrainIaaS *delegate = activeDelegate();
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          delegate->applyProviderElasticAddress(coro, plan, assignment, error);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }

    applyPendingRuntimeEnvironment(delegate);
  }

  void compensateProviderElasticAddress(CoroutineStack *coro,
                                        const ProviderElasticAddressPlan& plan,
                                        String& error) override
  {
    if (coro == nullptr)
    {
      error.assign("provider elastic address compensation coroutine required"_ctv);
      co_return;
    }

    BrainIaaS *delegate = activeDelegate();
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          delegate->compensateProviderElasticAddress(coro, plan, error);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }

    applyPendingRuntimeEnvironment(delegate);
  }

  void releaseProviderElasticAddress(CoroutineStack *coro,
                                     const ProviderElasticAddressRelease& release,
                                     String& error) override
  {
    if (coro == nullptr)
    {
      error.assign("provider elastic address release coroutine required"_ctv);
      co_return;
    }

    BrainIaaS *delegate = activeDelegate();
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          delegate->releaseProviderElasticAddress(coro, release, error);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }

    applyPendingRuntimeEnvironment(delegate);
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

class RuntimeAwareNeuronIaaS : public NeuronIaaS {
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

  RuntimeAwareNeuronIaaS(ProdigyPersistentStateStore *store,
                         const ProdigyBootstrapConfig& bootstrap,
                         const ProdigyPersistentBootState& bootState,
                         ProdigyProviderServices requestedProviderServices)
      : bootstrapConfig(bootstrap),
        stateStore(store),
        bootstrapDelegate(bootstrap)
  {
    providerServices = requestedProviderServices;
    persistentBootState = bootState;
    prodigyOwnRuntimeEnvironmentConfig(bootState.runtimeEnvironment, runtimeEnvironment);
    prodigyStripManagedCloudBootstrapCredentials(runtimeEnvironment);
    prodigyApplyInternalRuntimeEnvironmentDefaults(runtimeEnvironment);
    providerDelegate = prodigyCreateProviderNeuronIaaS(runtimeEnvironment, providerServices);
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
    providerDelegate = prodigyCreateProviderNeuronIaaS(runtimeEnvironment, providerServices);
    if (providerDelegate)
    {
      providerDelegate->configureRuntimeEnvironment(runtimeEnvironment);
    }
    persistBootState();
  }

  void gatherSelfData(CoroutineStack *coro, uint128_t& uuid, String& metro, bool& isBrain, EthDevice& eth, IPAddress& private4) override
  {
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          activeDelegate()->gatherSelfData(coro, uuid, metro, isBrain, eth, private4);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
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

};
