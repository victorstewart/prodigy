#pragma once

#include <sys/capability.h>

#include <prodigy/types.h>

static inline bool declaredNetworkPairingsValid(const ContainerPlan& plan)
{
  uint64_t subscriptionCount = 0;
  for (const auto& [service, pairings] : plan.subscriptionPairings.map)
  {
    bool declaredSubscription = plan.subscriptions.contains(service);
    if (declaredSubscription == false)
    {
      for (const auto& [declaredService, subscription] : plan.subscriptions)
      {
        (void)subscription;
        if (MeshServices::isPrefix(declaredService) && MeshRegistry::prefixContains(declaredService, service))
        {
          declaredSubscription = true;
          break;
        }
      }
    }
    if (declaredSubscription == false)
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

static inline const char *declaredNetworkAccessFailure(const ContainerPlan& plan)
{
  if (plan.networkAccess == ContainerNetworkAccess::unrestricted)
  {
    return nullptr;
  }
  if (plan.networkAccess != ContainerNetworkAccess::declaredOnly)
  {
    return "invalid container networkAccess mode";
  }
  if (plan.whiteholes.empty() == false && resolvedWhiteholesValid(plan.whiteholes) == false)
  {
    return "invalid container declaredOnly whiteholes";
  }
  if (declaredNetworkPairingsValid(plan) == false)
  {
    return "invalid container declaredOnly service pairings";
  }
  if (plan.fragment == 0)
  {
    return "invalid container declaredOnly zero fragment";
  }
  if (plan.wormholes.empty() == false)
  {
    return "invalid container declaredOnly wormholes";
  }
  if (plan.useHostNetworkNamespace)
  {
    return "invalid container declaredOnly host network namespace";
  }
  if (plan.isSystemContainer())
  {
    return "invalid container declaredOnly system container";
  }
  if (plan.config.capabilities.contains(CAP_NET_RAW) ||
      plan.config.capabilities.contains(CAP_NET_ADMIN) ||
      plan.config.capabilities.contains(CAP_SYS_ADMIN) ||
      plan.config.capabilities.contains(CAP_BPF))
  {
    return "invalid container declaredOnly capability";
  }
  return nullptr;
}

static inline bool declaredNetworkAccessValid(const ContainerPlan& plan)
{
  return declaredNetworkAccessFailure(plan) == nullptr;
}
