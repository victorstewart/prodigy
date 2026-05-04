#pragma once

#include <macros/bytes.h>
#include <prodigy/types.h>
#include <services/bitsery.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/msg.h>
#include <networking/pool.h>
#include <networking/socket.h>
#include <networking/eth.h>
#include <cstdio>

class CoroutineStack;
class Machine;
class BrainView;

class BrainIaaSMachineProvisioningProgressSink {
public:

   virtual ~BrainIaaSMachineProvisioningProgressSink() = default;
   virtual void reportMachineProvisioningAccepted(const String& cloudID)
   {
      (void)cloudID;
   }
   virtual void reportMachineProvisioned(const Machine& machine)
   {
      (void)machine;
   }
   virtual void reportMachineProvisioningProgress(const Vector<MachineProvisioningProgress>& progress) = 0;
};

class BrainIaaSMachineProvisioningProgressReporter {
private:

   BrainIaaSMachineProvisioningProgressSink *sink = nullptr;
   Vector<MachineProvisioningProgress> progress;
   int64_t nextEmitAtMs = 0;

   static bool matchesIdentity(const MachineProvisioningProgress& candidate, const String& providerName, const String& cloudID)
   {
      if (cloudID.size() > 0 && candidate.cloud.cloudID.size() > 0)
      {
         return candidate.cloud.cloudID.equals(cloudID);
      }

      if (providerName.size() > 0 && candidate.providerName.size() > 0)
      {
         return candidate.providerName.equals(providerName);
      }

      return false;
   }

public:

   void configureSink(BrainIaaSMachineProvisioningProgressSink *progressSink)
   {
      sink = progressSink;
   }

   void reset(void)
   {
      progress.clear();
      nextEmitAtMs = 0;
   }

   MachineProvisioningProgress& upsert(const String& schema, const String& providerMachineType, const String& providerName, const String& cloudID)
   {
      for (MachineProvisioningProgress& candidate : progress)
      {
         if (matchesIdentity(candidate, providerName, cloudID))
         {
            if (schema.size() > 0)
            {
               candidate.cloud.schema = schema;
            }
            if (providerMachineType.size() > 0)
            {
               candidate.cloud.providerMachineType = providerMachineType;
            }
            if (providerName.size() > 0)
            {
               candidate.providerName = providerName;
            }
            if (cloudID.size() > 0)
            {
               candidate.cloud.cloudID = cloudID;
            }
            return candidate;
         }
      }

      MachineProvisioningProgress& created = progress.emplace_back();
      created.cloud.schema = schema;
      created.cloud.providerMachineType = providerMachineType;
      created.providerName = providerName;
      created.cloud.cloudID = cloudID;
      return created;
   }

   void emitMaybe(int64_t nowMs, int64_t intervalMs = 15'000)
   {
      if (sink == nullptr || progress.empty())
      {
         return;
      }

      if (nextEmitAtMs == 0 || nowMs >= nextEmitAtMs)
      {
         sink->reportMachineProvisioningProgress(progress);
         nextEmitAtMs = nowMs + intervalMs;
      }
   }

   void emitNow(void)
   {
      if (sink != nullptr && progress.empty() == false)
      {
         sink->reportMachineProvisioningProgress(progress);
      }
   }

   void notifyMachineProvisioningAccepted(const String& cloudID)
   {
      if (sink != nullptr && cloudID.size() > 0)
      {
         sink->reportMachineProvisioningAccepted(cloudID);
      }
   }

   void notifyMachineProvisioned(const Machine& machine)
   {
      if (sink != nullptr)
      {
#if PRODIGY_DEBUG
         std::fprintf(stderr,
            "iaas provisioning notify-provisioned sink=%p machine=%p\n",
            static_cast<void *>(sink),
            static_cast<const void *>(&machine));
#endif
         sink->reportMachineProvisioned(machine);
      }
   }
};

class BrainIaaS {
public:

   virtual ~BrainIaaS() = default;

	virtual void boot(void) = 0;
   virtual void configureRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& config)
   {
      (void)config;
   }

   virtual void configureBootstrapSSHAccess(const String& user, const Vault::SSHKeyPackage& keyPackage, const Vault::SSHKeyPackage& hostKeyPackage, const String& privateKeyPath)
   {
      (void)user;
      (void)keyPackage;
      (void)hostKeyPackage;
      (void)privateKeyPath;
   }

   virtual void configureProvisioningProgressSink(BrainIaaSMachineProvisioningProgressSink *sink)
   {
      (void)sink;
   }
   virtual void configureProvisioningClusterUUID(uint128_t clusterUUID)
   {
      (void)clusterUUID;
   }
   virtual bool resolveLocalBrainPeerAddress(IPAddress& address, String& addressText) const
   {
      address = {};
      addressText.clear();
      return false;
   }
   virtual bool bgpEnabledForEnvironment(void) const
   {
      return false;
   }
   virtual bool inferMachineSchemaCpuCapability(const MachineConfig& config, MachineSchemaCpuCapability& capability, String& error)
   {
      (void)config;
      capability = {};
      error.assign("inferMachineSchemaCpuCapability not implemented"_ctv);
      return false;
   }
   virtual bool supportsAuthoritativeMachineSchemaCpuCapabilityInference(void) const
   {
      return false;
   }
	virtual void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) = 0;
   virtual void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bool isBrain, bytell_hash_set<Machine *>& newMachines, String& error)
   {
      (void)isBrain;
      spinMachines(coro, lifetime, config, count, newMachines, error);
   }
	virtual void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines) = 0;
	virtual void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains) = 0;
	virtual void hardRebootMachine(uint128_t uuid) = 0;
   virtual void reportHardwareFailure(uint128_t uuid, const String& report) = 0;
   virtual void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) = 0;
   virtual void destroyMachine(Machine *machine) = 0;
   virtual bool destroyClusterMachines(const String& clusterUUID, uint32_t& destroyed, String& error)
   {
      (void)clusterUUID;
      destroyed = 0;
      error.assign("destroyClusterMachines not implemented"_ctv);
      return false;
   }
   virtual bool ensureProdigyMachineTags(const String& clusterUUID, Machine *machine, String& error)
   {
      (void)clusterUUID;
      (void)machine;
      error.clear();
      return true;
   }
   virtual bool assignProviderElasticAddress(Machine *machine,
      ExternalAddressFamily family,
      const String& requestedAddress,
      const String& providerPool,
      IPAddress& assignedAddress,
      String& allocationID,
      String& associationID,
      bool& releaseOnRemove,
      String& error)
   {
      (void)machine;
      (void)family;
      (void)requestedAddress;
      (void)providerPool;
      assignedAddress = {};
      allocationID.clear();
      associationID.clear();
      releaseOnRemove = false;
      error.assign("assignProviderElasticAddress not implemented"_ctv);
      return false;
   }
   virtual bool releaseProviderElasticAddress(const RegisteredRoutableAddress& address, String& error)
   {
      (void)address;
      error.assign("releaseProviderElasticAddress not implemented"_ctv);
      return false;
   }
    // Capability mask for supported machine kinds (bit 0 = bareMetal, bit 1 = vm)
    virtual uint32_t supportedMachineKindsMask() const = 0;
   virtual bool supportsAutoProvision() const { return false; }
   virtual bool supportsIncrementalProvisioningCallbacks() const { return false; }
    bool supports(MachineConfig::MachineKind kind) const
    {
        uint32_t bit = (kind == MachineConfig::MachineKind::bareMetal) ? 1u : 2u;
        return (supportedMachineKindsMask() & bit) != 0u;
    }
};

class NeuronIaaS {
public:

      virtual ~NeuronIaaS() = default;

		virtual void gatherSelfData(uint128_t& uuid, String& metro, bool& isBrain, EthDevice& eth, IPAddress& private4) = 0;

      virtual void configureRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& config)
      {
         (void)config;
      }

      virtual void gatherBGPConfig(NeuronBGPConfig& config, EthDevice& eth, const IPAddress& private4)
      {
         (void)config;
         (void)eth;
         (void)private4;
      }

      virtual void setLocalContainerPrefixes(const Vector<IPPrefix>& prefixes)
      {
         (void)prefixes;
      }

		virtual void downloadContainerToPath(CoroutineStack *coro, uint64_t deploymentID, const String& path) = 0;
};
