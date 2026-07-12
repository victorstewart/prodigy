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
#include <prodigy/host.http.operation.h>
#include <prodigy/host.delay.operation.h>
#include <openssl/evp.h>
#include <chrono>
#include <cstdio>

class CoroutineStack;
class Machine;
class BrainView;

class ProviderElasticAddressRequest
{
public:

  String cloudID;
  ExternalAddressFamily family = ExternalAddressFamily::ipv4;
  ElasticPrefixIntent intent = ElasticPrefixIntent::any;
  String requestedAddress;
  String providerPool;
  IPPrefix deliveryPrefix;
};

class ProviderElasticAddressAssignment
{
public:

  IPPrefix assignedPrefix;
  IPPrefix deliveryPrefix;
  String allocationID;
  String associationID;
  bool releaseOnRemove = false;
};

class ProviderElasticAddressRelease
{
public:

  uint128_t transactionNonce = 0;
  RoutablePrefixKind kind = RoutablePrefixKind::elastic;
  IPPrefix assignedPrefix;
  String allocationID;
  String associationID;
  bool releaseOnRemove = false;
};

class ProviderElasticAddressPlan
{
public:

  constexpr static uint32_t maximumBytes = 32_KB;

  String opaque;
};

class ProviderElasticAddressPlanBinding
{
public:

  constexpr static uint8_t currentVersion = 1;

  uint8_t version = currentVersion;
  uint128_t transactionNonce = 0;
  String cloudID;
  ExternalAddressFamily family = ExternalAddressFamily::ipv4;
  ElasticPrefixIntent intent = ElasticPrefixIntent::any;
  String requestedAddress;
  String providerPool;
  IPPrefix deliveryPrefix;
  String providerPlan;
};

template <typename S>
static void serialize(S&& serializer, ProviderElasticAddressPlanBinding& binding)
{
  serializer.value1b(binding.version);
  serializer.value16b(binding.transactionNonce);
  serializer.text1b(binding.cloudID, UINT32_MAX);
  serializer.value1b(binding.family);
  serializer.value1b(binding.intent);
  serializer.text1b(binding.requestedAddress, UINT32_MAX);
  serializer.text1b(binding.providerPool, UINT32_MAX);
  serializer.object(binding.deliveryPrefix);
  serializer.text1b(binding.providerPlan, UINT32_MAX);
}

static inline bool prodigyComputeElasticAddressPlanBindingDigest(
    const ProviderElasticAddressPlan& plan,
    const ProviderElasticAddressRequest& request,
    uint128_t transactionNonce,
    String& digest)
{
  digest.clear();
  if (transactionNonce == 0 || request.cloudID.empty() ||
      request.cloudID.size() > 4_KB || request.requestedAddress.size() > 4_KB ||
      request.providerPool.size() > 4_KB ||
      (request.family != ExternalAddressFamily::ipv4 &&
       request.family != ExternalAddressFamily::ipv6) ||
      elasticPrefixIntentIsValid(request.intent) == false ||
      request.deliveryPrefix.network.isNull() ||
      request.deliveryPrefix.network.is6 != (request.family == ExternalAddressFamily::ipv6) ||
      request.deliveryPrefix.cidr != (request.family == ExternalAddressFamily::ipv6 ? 128 : 32) ||
      request.deliveryPrefix.equals(request.deliveryPrefix.canonicalized()) == false ||
      plan.opaque.empty() || plan.opaque.size() > ProviderElasticAddressPlan::maximumBytes)
  {
    return false;
  }

  ProviderElasticAddressPlanBinding binding;
  binding.transactionNonce = transactionNonce;
  binding.cloudID.assign(request.cloudID);
  binding.family = request.family;
  binding.intent = request.intent;
  binding.requestedAddress.assign(request.requestedAddress);
  binding.providerPool.assign(request.providerPool);
  binding.deliveryPrefix = request.deliveryPrefix;
  binding.providerPlan.assign(plan.opaque);
  String material;
  BitseryEngine::serialize(material, binding);

  uint8_t rawDigest[EVP_MAX_MD_SIZE];
  unsigned int rawDigestSize = 0;
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  const bool ok = context != nullptr &&
                  EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
                  EVP_DigestUpdate(context, material.data(), size_t(material.size())) == 1 &&
                  EVP_DigestFinal_ex(context, rawDigest, &rawDigestSize) == 1 &&
                  rawDigestSize == 32;
  if (context != nullptr)
  {
    EVP_MD_CTX_free(context);
  }
  if (ok == false)
  {
    return false;
  }

  constexpr static char hex[] = "0123456789abcdef";
  digest.reserve(64);
  for (uint32_t index = 0; index < rawDigestSize; ++index)
  {
    digest.append(hex[rawDigest[index] >> 4]);
    digest.append(hex[rawDigest[index] & 0x0f]);
  }
  return true;
}

static inline bool prodigyValidateElasticAddressPlanBinding(
    const ProviderElasticAddressPlan& plan,
    const ProviderElasticAddressRequest& request,
    uint128_t transactionNonce,
    const String& expectedDigest)
{
  String actualDigest;
  return expectedDigest.size() == 64 &&
         prodigyComputeElasticAddressPlanBindingDigest(plan, request, transactionNonce,
                                                       actualDigest) &&
         actualDigest.equals(expectedDigest);
}

class ProdigyProviderServices {
public:

  ProdigyHostHttpSubmission http;
  ProdigyHostDelayOperation::Submission delay;
  std::chrono::steady_clock::time_point operationDeadline = std::chrono::steady_clock::time_point::max();
};

class BrainIaaSClusterCreatePreflight {
public:

  Vector<MachineConfig> configs;
  String gcpServiceAccountEmail;
  String gcpNetwork;
  String gcpSubnetwork;
  String azureManagedIdentityResourceID;
};

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
protected:

  ProdigyProviderServices providerServices;

public:

  virtual ~BrainIaaS() = default;

  void configureProviderServices(ProdigyProviderServices services)
  {
    providerServices = services;
  }

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
  virtual void configureProvisioningOperationID(uint64_t operationID)
  {
    (void)operationID;
  }
  virtual bool provisioningOperationSettled(void)
  {
    return true;
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
  virtual void inferMachineSchemaCpuCapability(CoroutineStack *coro, const MachineConfig& config, MachineSchemaCpuCapability& capability, String& error)
  {
    (void)coro;
    (void)config;
    capability = {};
    error.assign("inferMachineSchemaCpuCapability not implemented"_ctv);
  }
  virtual bool supportsAuthoritativeMachineSchemaCpuCapabilityInference(void) const
  {
    return false;
  }
  virtual void preflightClusterCreate(CoroutineStack *coro, const BrainIaaSClusterCreatePreflight& preflight, String& error)
  {
    (void)coro;
    (void)preflight;
    error.clear();
  }
  virtual void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) = 0;
  virtual void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bool isBrain, bytell_hash_set<Machine *>& newMachines, String& error)
  {
    (void)isBrain;
    spinMachines(coro, lifetime, config, count, newMachines, error);
  }
  virtual void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines, String& failure) = 0;
  virtual void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains, String& failure) = 0;
  virtual void hardRebootMachine(CoroutineStack *coro, const String& cloudID, String& failure) = 0;
  virtual void reportHardwareFailure(uint128_t uuid, const String& report) = 0;
  virtual bool hasActiveControlOperations(void) const
  {
    return false;
  }
  virtual bool beginElasticAddressOperationBatch(void)
  {
    return true;
  }
  virtual void endElasticAddressOperationBatch(void)
  {}
  virtual bool supportsTransactionalElasticAddresses(void) const
  {
    return false;
  }
  virtual bool validateProviderElasticAddressPlan(const ProviderElasticAddressPlan& plan,
                                                  const ProviderElasticAddressRequest& request,
                                                  uint128_t transactionNonce) const
  {
    (void)plan;
    (void)request;
    (void)transactionNonce;
    return false;
  }
  virtual bool setElasticAddressReleaseFenceActive(bool active)
  {
    (void)active;
    return true;
  }
  virtual void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) = 0;
  virtual void destroyMachine(CoroutineStack *coro, const String& cloudID, String& failure) = 0;
  virtual void destroyClusterMachines(CoroutineStack *coro, const String& clusterUUID, uint32_t& destroyed, String& error)
  {
    (void)coro;
    (void)clusterUUID;
    destroyed = 0;
    error.assign("destroyClusterMachines not implemented"_ctv);
  }
  virtual void ensureProdigyMachineTags(CoroutineStack *coro,
                                        const String& clusterUUID,
                                        const String& cloudID,
                                        String& error)
  {
    (void)coro;
    (void)clusterUUID;
    (void)cloudID;
    error.clear();
  }
  virtual void prepareProviderElasticAddress(CoroutineStack *coro,
                                             const ProviderElasticAddressRequest& request,
                                             uint128_t transactionNonce,
                                             ProviderElasticAddressPlan& plan,
                                             String& error)
  {
    (void)coro;
    (void)request;
    (void)transactionNonce;
    plan = {};
    error.assign("prepareProviderElasticAddress not implemented"_ctv);
  }
  virtual void applyProviderElasticAddress(CoroutineStack *coro,
                                           const ProviderElasticAddressPlan& plan,
                                           ProviderElasticAddressAssignment& assignment,
                                           String& error)
  {
    (void)coro;
    (void)plan;
    assignment = {};
    error.assign("applyProviderElasticAddress not implemented"_ctv);
  }
  virtual void compensateProviderElasticAddress(CoroutineStack *coro,
                                                const ProviderElasticAddressPlan& plan,
                                                String& error)
  {
    (void)coro;
    (void)plan;
    error.assign("compensateProviderElasticAddress not implemented"_ctv);
  }
  virtual void releaseProviderElasticAddress(CoroutineStack *coro,
                                             const ProviderElasticAddressRelease& release,
                                             String& error)
  {
    (void)coro;
    (void)release;
    error.assign("releaseProviderElasticAddress not implemented"_ctv);
  }
  // Capability mask for supported machine kinds (bit 0 = bareMetal, bit 1 = vm)
  virtual uint32_t supportedMachineKindsMask() const = 0;
  virtual bool supportsAutoProvision() const
  {
    return false;
  }
  virtual bool supportsIncrementalProvisioningCallbacks() const
  {
    return false;
  }
  bool supports(MachineConfig::MachineKind kind) const
  {
    uint32_t bit = (kind == MachineConfig::MachineKind::bareMetal) ? 1u : 2u;
    return (supportedMachineKindsMask() & bit) != 0u;
  }
};

class NeuronIaaS {
protected:

  ProdigyProviderServices providerServices;

public:

  virtual ~NeuronIaaS() = default;

  void configureProviderServices(ProdigyProviderServices services)
  {
    providerServices = services;
  }

  virtual void gatherSelfData(CoroutineStack *coro, uint128_t& uuid, String& metro, bool& isBrain, EthDevice& eth, IPAddress& private4) = 0;

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

};
