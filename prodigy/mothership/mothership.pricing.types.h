#pragma once

#include <cstdint>

#include <prodigy/mothership/mothership.cluster.types.h>
#include <prodigy/mothership/mothership.provider.credential.types.h>
#include <prodigy/provider.machine.offer.h>
#include <prodigy/types.h>

enum class MothershipProviderOfferPriceCompleteness : uint8_t
{
   computeOnly = 0,
   computeStorageNetwork = 1
};

class MothershipProviderScopeTarget
{
public:

   class PricingProviderCredentialOverride
   {
   public:

      MothershipClusterProvider provider = MothershipClusterProvider::unknown;
      String material;
      String scope;
   };

   MothershipClusterProvider provider = MothershipClusterProvider::unknown;
   String providerScope;
   String providerCredentialName;
   PricingProviderCredentialOverride providerCredentialOverride;
   bool hasProviderCredentialOverride = false;
};

template <typename S>
static void serialize(S&& serializer, MothershipProviderScopeTarget::PricingProviderCredentialOverride& credential)
{
   serializer.value1b(credential.provider);
   serializer.text1b(credential.material, UINT32_MAX);
   serializer.text1b(credential.scope, UINT32_MAX);
}

template <typename S>
static void serialize(S&& serializer, MothershipProviderScopeTarget& target)
{
   serializer.value1b(target.provider);
   serializer.text1b(target.providerScope, UINT32_MAX);
   serializer.text1b(target.providerCredentialName, UINT32_MAX);
   serializer.object(target.providerCredentialOverride);
   serializer.value1b(target.hasProviderCredentialOverride);
}

class MothershipPlanningApplication
{
public:

   String name;
   ApplicationConfig config;
   uint32_t instances = 1;
};

template <typename S>
static void serialize(S&& serializer, MothershipPlanningApplication& application)
{
   serializer.text1b(application.name, UINT32_MAX);
   serializer.object(application.config);
   serializer.value4b(application.instances);
}

class MothershipMachineOfferSelection
{
public:

   String providerMachineType;
   MachineConfig::MachineKind kind = MachineConfig::MachineKind::vm;
   uint32_t count = 0;
   uint32_t storageMB = 0;
};

template <typename S>
static void serialize(S&& serializer, MothershipMachineOfferSelection& selection)
{
   serializer.text1b(selection.providerMachineType, UINT32_MAX);
   serializer.value1b(selection.kind);
   serializer.value4b(selection.count);
   serializer.value4b(selection.storageMB);
}

class MothershipStoragePricingTier
{
public:

   uint32_t capacityGB = 0;
   uint64_t hourlyMicrousd = 0;
};

template <typename S>
static void serialize(S&& serializer, MothershipStoragePricingTier& tier)
{
   serializer.value4b(tier.capacityGB);
   serializer.value8b(tier.hourlyMicrousd);
}

class MothershipProviderMachineOffer
{
public:

   MothershipClusterProvider provider = MothershipClusterProvider::unknown;
   String providerScope;
   String country;
   String region;
   String zone;
   String providerMachineType;
   ProviderMachineBillingModel billingModel = ProviderMachineBillingModel::hourly;
   MachineConfig::MachineKind kind = MachineConfig::MachineKind::vm;
   uint32_t nLogicalCores = 0;
   uint32_t nMemoryMB = 0;
   uint32_t nStorageMBDefault = 0;
   uint32_t gpuCount = 0;
   uint32_t gpuMemoryMBPerDevice = 0;
   uint32_t nicSpeedMbps = 0;
   bool providesHostPublic4 = false;
   bool providesHostPublic6 = false;
   bool freeTierEligible = false;
   uint64_t hourlyMicrousd = 0;
   uint64_t extraStorageMicrousdPerGBHour = 0;
   uint64_t ingressMicrousdPerGB = 0;
   uint64_t egressMicrousdPerGB = 0;
   Vector<MothershipStoragePricingTier> storageTiers;
   MothershipProviderOfferPriceCompleteness priceCompleteness = MothershipProviderOfferPriceCompleteness::computeOnly;
};

template <typename S>
static void serialize(S&& serializer, MothershipProviderMachineOffer& offer)
{
   serializer.value1b(offer.provider);
   serializer.text1b(offer.providerScope, UINT32_MAX);
   serializer.text1b(offer.country, UINT32_MAX);
   serializer.text1b(offer.region, UINT32_MAX);
   serializer.text1b(offer.zone, UINT32_MAX);
   serializer.text1b(offer.providerMachineType, UINT32_MAX);
   serializer.value1b(offer.billingModel);
   serializer.value1b(offer.kind);
   serializer.value4b(offer.nLogicalCores);
   serializer.value4b(offer.nMemoryMB);
   serializer.value4b(offer.nStorageMBDefault);
   serializer.value4b(offer.gpuCount);
   serializer.value4b(offer.gpuMemoryMBPerDevice);
   serializer.value4b(offer.nicSpeedMbps);
   serializer.value1b(offer.providesHostPublic4);
   serializer.value1b(offer.providesHostPublic6);
   serializer.value1b(offer.freeTierEligible);
   serializer.value8b(offer.hourlyMicrousd);
   serializer.value8b(offer.extraStorageMicrousdPerGBHour);
   serializer.value8b(offer.ingressMicrousdPerGB);
   serializer.value8b(offer.egressMicrousdPerGB);
   serializer.container(offer.storageTiers, UINT32_MAX);
   serializer.value1b(offer.priceCompleteness);
}

class MothershipProviderOfferSurveyRequest
{
public:

   MothershipProviderScopeTarget target;
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

template <typename S>
static void serialize(S&& serializer, MothershipProviderOfferSurveyRequest& request)
{
   serializer.object(request.target);
   serializer.text1b(request.country, UINT32_MAX);
   serializer.value1b(request.billingModel);
   serializer.value4b(request.machineKindsMask);
   serializer.value1b(request.requireFreeTierEligible);
   serializer.value4b(request.minLogicalCores);
   serializer.value4b(request.minMemoryMB);
   serializer.value4b(request.minStorageMB);
   serializer.value4b(request.minGPUs);
   serializer.value4b(request.minGPUMemoryGB);
   serializer.value4b(request.minNICSpeedGbps);
   serializer.value1b(request.requireHostPublic4);
   serializer.value1b(request.requireHostPublic6);
}

class MothershipClusterCostEstimateRequest
{
public:

   MothershipProviderScopeTarget target;
   String country;
   ProviderMachineBillingModel billingModel = ProviderMachineBillingModel::hourly;
   uint64_t ingressMBPerHour = 0;
   uint64_t egressMBPerHour = 0;
   Vector<MothershipMachineOfferSelection> machines;
   Vector<MothershipPlanningApplication> applications;
};

template <typename S>
static void serialize(S&& serializer, MothershipClusterCostEstimateRequest& request)
{
   serializer.object(request.target);
   serializer.text1b(request.country, UINT32_MAX);
   serializer.value1b(request.billingModel);
   serializer.value8b(request.ingressMBPerHour);
   serializer.value8b(request.egressMBPerHour);
   serializer.container(request.machines, UINT32_MAX);
   serializer.container(request.applications, UINT32_MAX);
}

class MothershipClusterRecommendationRequest
{
public:

   Vector<MothershipProviderScopeTarget> targets;
   String country;
   ProviderMachineBillingModel billingModel = ProviderMachineBillingModel::hourly;
   uint32_t minMachines = 0;
   uint32_t machineKindsMask = 0;
   uint64_t budgetMicrousd = 0;
   bool hasBudget = false;
   uint64_t ingressMBPerHour = 0;
   uint64_t egressMBPerHour = 0;
   Vector<MothershipPlanningApplication> applications;
};

template <typename S>
static void serialize(S&& serializer, MothershipClusterRecommendationRequest& request)
{
   serializer.container(request.targets, UINT32_MAX);
   serializer.text1b(request.country, UINT32_MAX);
   serializer.value1b(request.billingModel);
   serializer.value4b(request.minMachines);
   serializer.value4b(request.machineKindsMask);
   serializer.value8b(request.budgetMicrousd);
   serializer.value1b(request.hasBudget);
   serializer.value8b(request.ingressMBPerHour);
   serializer.value8b(request.egressMBPerHour);
   serializer.container(request.applications, UINT32_MAX);
}

class MothershipClusterHourlyEstimate
{
public:

   bool fits = false;
   ProviderMachineBillingModel billingModel = ProviderMachineBillingModel::hourly;
   uint64_t hourlyMicrousd = 0;
   uint64_t computeHourlyMicrousd = 0;
   uint64_t storageHourlyMicrousd = 0;
   uint64_t ingressHourlyMicrousd = 0;
   uint64_t egressHourlyMicrousd = 0;
   uint32_t totalMachines = 0;
   String failure;
};

template <typename S>
static void serialize(S&& serializer, MothershipClusterHourlyEstimate& estimate)
{
   serializer.value1b(estimate.fits);
   serializer.value1b(estimate.billingModel);
   serializer.value8b(estimate.hourlyMicrousd);
   serializer.value8b(estimate.computeHourlyMicrousd);
   serializer.value8b(estimate.storageHourlyMicrousd);
   serializer.value8b(estimate.ingressHourlyMicrousd);
   serializer.value8b(estimate.egressHourlyMicrousd);
   serializer.value4b(estimate.totalMachines);
   serializer.text1b(estimate.failure, UINT32_MAX);
}

class MothershipClusterRecommendation
{
public:

   bool found = false;
   bool withinBudget = false;
   MothershipProviderScopeTarget target;
   String country;
   ProviderMachineBillingModel billingModel = ProviderMachineBillingModel::hourly;
   Vector<MothershipMachineOfferSelection> machineSelections;
   uint32_t totalMachines = 0;
   uint64_t hourlyMicrousd = 0;
   uint64_t computeHourlyMicrousd = 0;
   uint64_t storageHourlyMicrousd = 0;
   uint64_t ingressHourlyMicrousd = 0;
   uint64_t egressHourlyMicrousd = 0;
   String failure;
};

template <typename S>
static void serialize(S&& serializer, MothershipClusterRecommendation& recommendation)
{
   serializer.value1b(recommendation.found);
   serializer.value1b(recommendation.withinBudget);
   serializer.object(recommendation.target);
   serializer.text1b(recommendation.country, UINT32_MAX);
   serializer.value1b(recommendation.billingModel);
   serializer.container(recommendation.machineSelections, UINT32_MAX);
   serializer.value4b(recommendation.totalMachines);
   serializer.value8b(recommendation.hourlyMicrousd);
   serializer.value8b(recommendation.computeHourlyMicrousd);
   serializer.value8b(recommendation.storageHourlyMicrousd);
   serializer.value8b(recommendation.ingressHourlyMicrousd);
   serializer.value8b(recommendation.egressHourlyMicrousd);
   serializer.text1b(recommendation.failure, UINT32_MAX);
}
