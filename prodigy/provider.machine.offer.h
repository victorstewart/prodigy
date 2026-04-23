#pragma once

#include <cmath>

#include <prodigy/types.h>

enum class ProviderMachineBillingModel : uint8_t
{
   hourly = 0,
   spot = 1
};

static inline const char *providerMachineBillingModelName(ProviderMachineBillingModel model)
{
   switch (model)
   {
      case ProviderMachineBillingModel::hourly:
      {
         return "hourly";
      }
      case ProviderMachineBillingModel::spot:
      {
         return "spot";
      }
   }

   return "unknown";
}

static inline bool parseProviderMachineBillingModel(const String& text, ProviderMachineBillingModel& model)
{
   if (text.equal("hourly"_ctv))
   {
      model = ProviderMachineBillingModel::hourly;
      return true;
   }

   if (text.equal("spot"_ctv))
   {
      model = ProviderMachineBillingModel::spot;
      return true;
   }

   return false;
}

static inline void providerCanonicalizeCountry(const String& input, String& canonical)
{
   canonical.clear();

   for (uint64_t index = 0; index < input.size(); ++index)
   {
      unsigned char c = unsigned(input[index]);
      if (std::isalnum(c))
      {
         canonical.append(char(std::tolower(c)));
      }
   }
}

static inline bool providerCountriesMatch(const String& lhs, const String& rhs)
{
   String left = {};
   String right = {};
   providerCanonicalizeCountry(lhs, left);
   providerCanonicalizeCountry(rhs, right);
   return left.size() > 0 && left.equals(right);
}

static inline uint32_t providerMachineKindMaskBit(MachineConfig::MachineKind kind)
{
   switch (kind)
   {
      case MachineConfig::MachineKind::bareMetal:
      {
         return 1u;
      }
      case MachineConfig::MachineKind::vm:
      {
         return 2u;
      }
   }

   return 0u;
}

static inline uint32_t providerMachineKindMaskAll(void)
{
   return providerMachineKindMaskBit(MachineConfig::MachineKind::bareMetal)
      | providerMachineKindMaskBit(MachineConfig::MachineKind::vm);
}

static inline bool providerMachineKindMaskAllows(uint32_t mask, MachineConfig::MachineKind kind)
{
   if (mask == 0)
   {
      return true;
   }

   return (mask & providerMachineKindMaskBit(kind)) != 0;
}

class ProviderMachineOfferSurveyRequest
{
public:

   String country;
   ProviderMachineBillingModel billingModel = ProviderMachineBillingModel::hourly;
   uint32_t machineKindsMask = 0;
   bool requireFreeTierEligible = false;
   uint32_t minLogicalCores = 0;
   uint32_t minMemoryMB = 0;
   uint32_t minStorageMB = 0;
   uint32_t minGPUs = 0;
   uint32_t minGPUMemoryGB = 0;
   uint32_t minNICSpeedGbps = 0;
   bool requireHostPublic4 = false;
   bool requireHostPublic6 = false;
};

class ProviderMachineOffer
{
public:

   ProdigyEnvironmentKind provider = ProdigyEnvironmentKind::unknown;
   String providerScope;
   String country;
   String region;
   String zone;
   String providerMachineType;
   MachineLifetime lifetime = MachineLifetime::ondemand;
   MachineConfig::MachineKind kind = MachineConfig::MachineKind::vm;
   uint32_t nLogicalCores = 0;
   uint32_t nMemoryMB = 0;
   uint32_t nStorageMB = 0;
   uint32_t gpuCount = 0;
   uint32_t gpuMemoryMBPerDevice = 0;
   uint32_t nicSpeedMbps = 0;
   bool providesHostPublic4 = false;
   bool providesHostPublic6 = false;
   bool hasInternetAccess = false;
   bool freeTierEligible = false;
   double hourlyUSD = 0.0;

   bool operator==(const ProviderMachineOffer& other) const
   {
      return provider == other.provider
         && providerScope.equals(other.providerScope)
         && country.equals(other.country)
         && region.equals(other.region)
         && zone.equals(other.zone)
         && providerMachineType.equals(other.providerMachineType)
         && lifetime == other.lifetime
         && kind == other.kind
         && nLogicalCores == other.nLogicalCores
         && nMemoryMB == other.nMemoryMB
         && nStorageMB == other.nStorageMB
         && gpuCount == other.gpuCount
         && gpuMemoryMBPerDevice == other.gpuMemoryMBPerDevice
         && nicSpeedMbps == other.nicSpeedMbps
         && providesHostPublic4 == other.providesHostPublic4
         && providesHostPublic6 == other.providesHostPublic6
         && hasInternetAccess == other.hasInternetAccess
         && freeTierEligible == other.freeTierEligible
         && std::fabs(hourlyUSD - other.hourlyUSD) <= 1e-9;
   }

   bool operator!=(const ProviderMachineOffer& other) const
   {
      return (*this == other) == false;
   }
};

static inline bool providerMachineOfferBuildMachineConfig(const ProviderMachineOffer& offer, MachineConfig& config)
{
   config = {};
   config.kind = offer.kind;
   config.slug = offer.providerMachineType;
   config.nLogicalCores = offer.nLogicalCores;
   config.nMemoryMB = offer.nMemoryMB;
   config.nStorageMB = offer.nStorageMB;
   config.providesHostPublic4 = offer.providesHostPublic4;
   config.providesHostPublic6 = offer.providesHostPublic6;
   return config.nLogicalCores > 0 && config.nMemoryMB > 0;
}

static inline bool providerMachineOfferResolveUsableResourcesFromTotals(
   uint32_t totalLogicalCores,
   uint32_t totalMemoryMB,
   uint32_t totalStorageMB,
   uint32_t& usableLogicalCores,
   uint32_t& usableMemoryMB,
   uint32_t& usableStorageMB)
{
   usableLogicalCores = 0;
   usableMemoryMB = 0;
   usableStorageMB = 0;

   ClusterMachineOwnership ownership = {};
   ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
   return clusterMachineResolveOwnedResources(
      ownership,
      totalLogicalCores,
      totalMemoryMB,
      totalStorageMB,
      usableLogicalCores,
      usableMemoryMB,
      usableStorageMB
   );
}

static inline bool providerMachineOfferResolveUsableResources(
   const ProviderMachineOffer& offer,
   uint32_t& usableLogicalCores,
   uint32_t& usableMemoryMB,
   uint32_t& usableStorageMB)
{
   return providerMachineOfferResolveUsableResourcesFromTotals(
      offer.nLogicalCores,
      offer.nMemoryMB,
      offer.nStorageMB,
      usableLogicalCores,
      usableMemoryMB,
      usableStorageMB
   );
}

static inline bool providerMachineOfferMatchesSurveyRequest(const ProviderMachineOffer& offer, const ProviderMachineOfferSurveyRequest& request)
{
   if (request.country.size() > 0 && providerCountriesMatch(offer.country, request.country) == false)
   {
      return false;
   }

   if (providerMachineKindMaskAllows(request.machineKindsMask, offer.kind) == false)
   {
      return false;
   }

   if (request.requireFreeTierEligible && offer.freeTierEligible == false)
   {
      return false;
   }

   uint32_t usableLogicalCores = 0;
   uint32_t usableMemoryMB = 0;
   uint32_t usableStorageMB = 0;
   if (providerMachineOfferResolveUsableResources(offer, usableLogicalCores, usableMemoryMB, usableStorageMB) == false)
   {
      return false;
   }

   if (request.minLogicalCores > 0 && usableLogicalCores < request.minLogicalCores)
   {
      return false;
   }

   if (request.minMemoryMB > 0 && usableMemoryMB < request.minMemoryMB)
   {
      return false;
   }

   if (request.minStorageMB > 0 && usableStorageMB < request.minStorageMB)
   {
      return false;
   }

   if (request.minGPUs > 0 && offer.gpuCount < request.minGPUs)
   {
      return false;
   }

   if (request.minGPUMemoryGB > 0 && offer.gpuMemoryMBPerDevice < (request.minGPUMemoryGB * 1024u))
   {
      return false;
   }

   uint64_t requiredNICSpeedMbps = uint64_t(request.minNICSpeedGbps) * 1000u;
   if (requiredNICSpeedMbps > 0 && uint64_t(offer.nicSpeedMbps) < requiredNICSpeedMbps)
   {
      return false;
   }

   if (request.requireHostPublic4 && offer.providesHostPublic4 == false)
   {
      return false;
   }

   if (request.requireHostPublic6 && offer.providesHostPublic6 == false)
   {
      return false;
   }

   return true;
}
