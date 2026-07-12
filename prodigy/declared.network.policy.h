#pragma once

#include <sys/capability.h>

#include <prodigy/types.h>

static inline bool declaredNetworkPairingsValid(const ContainerPlan& plan)
{
  uint64_t subscriptionCount = 0;
  for (const auto& [service, pairings] : plan.subscriptionPairings.map)
  {
    if (plan.subscriptions.contains(service) == false)
    {
      return false;
    }
    subscriptionCount += pairings.size();
    if (subscriptionCount > CONTAINER_SERVICE_PAIRINGS_MAX_ENTRIES)
    {
      return false;
    }
    for (const SubscriptionPairing& pairing : pairings)
    {
      if (pairing.service != service || pairing.address == 0 || pairing.port == 0)
      {
        return false;
      }
    }
  }

  uint64_t advertisementCount = 0;
  for (const auto& [service, pairings] : plan.advertisementPairings.map)
  {
    auto advertisement = plan.advertisements.find(service);
    if (advertisement == plan.advertisements.end() || advertisement->second.port == 0)
    {
      return false;
    }
    advertisementCount += pairings.size();
    if (advertisementCount > CONTAINER_SERVICE_PAIRINGS_MAX_ENTRIES)
    {
      return false;
    }
    for (const AdvertisementPairing& pairing : pairings)
    {
      if (pairing.service != service || pairing.address == 0)
      {
        return false;
      }
    }
  }
  return true;
}

static inline bool declaredNetworkAccessValid(const ContainerPlan& plan)
{
  if (plan.networkAccess == ContainerNetworkAccess::unrestricted)
  {
    return true;
  }
  return plan.networkAccess == ContainerNetworkAccess::declaredOnly &&
         (plan.whiteholes.empty() || resolvedWhiteholesValid(plan.whiteholes)) &&
         declaredNetworkPairingsValid(plan) && plan.fragment != 0 && plan.wormholes.empty() &&
         plan.useHostNetworkNamespace == false && plan.isSystemContainer() == false &&
         plan.config.capabilities.contains(CAP_NET_RAW) == false &&
         plan.config.capabilities.contains(CAP_NET_ADMIN) == false &&
         plan.config.capabilities.contains(CAP_SYS_ADMIN) == false &&
         plan.config.capabilities.contains(CAP_BPF) == false;
}
