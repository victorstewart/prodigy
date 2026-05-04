// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../neuron_hub.h"

#include <compare>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace ProdigySDK::Opinionated
{
   struct PairingKey
   {
      U128 secret{};
      std::uint64_t service = 0;

      auto operator<=>(const PairingKey&) const = default;

      static PairingKey fromAdvertisement(const AdvertisementPairing& pairing)
      {
         return PairingKey {
            .secret = pairing.secret,
            .service = pairing.service,
         };
      }

      static PairingKey fromSubscription(const SubscriptionPairing& pairing)
      {
         return PairingKey {
            .secret = pairing.secret,
            .service = pairing.service,
         };
      }
   };

   enum class ActivationActionKind : std::uint8_t
   {
      registerAdvertiser = 1,
      connectSubscriber = 2,
      deactivateAdvertiser = 3,
      deactivateSubscriber = 4,
   };

   struct ActivationAction
   {
      ActivationActionKind kind = ActivationActionKind::registerAdvertiser;
      std::optional<AdvertisementPairing> advertisement;
      std::optional<SubscriptionPairing> subscription;
      std::optional<PairingKey> pairingKey;

      static ActivationAction registerAdvertiser(const AdvertisementPairing& pairing)
      {
         ActivationAction action;
         action.kind = ActivationActionKind::registerAdvertiser;
         action.advertisement = pairing;
         return action;
      }

      static ActivationAction connectSubscriber(const SubscriptionPairing& pairing)
      {
         ActivationAction action;
         action.kind = ActivationActionKind::connectSubscriber;
         action.subscription = pairing;
         return action;
      }

      static ActivationAction deactivateAdvertiser(const PairingKey& key)
      {
         ActivationAction action;
         action.kind = ActivationActionKind::deactivateAdvertiser;
         action.pairingKey = key;
         return action;
      }

      static ActivationAction deactivateSubscriber(const PairingKey& key)
      {
         ActivationAction action;
         action.kind = ActivationActionKind::deactivateSubscriber;
         action.pairingKey = key;
         return action;
      }
   };

   class PairingBook
   {
   public:

      const std::map<PairingKey, AdvertisementPairing>& advertisements(void) const
      {
         return advertisements_;
      }

      const std::map<PairingKey, SubscriptionPairing>& subscriptions(void) const
      {
         return subscriptions_;
      }

      std::vector<ActivationAction> seedFromParameters(const ContainerParameters& parameters)
      {
         std::vector<ActivationAction> actions;
         actions.reserve(
            parameters.advertisementPairings.size() + parameters.subscriptionPairings.size());

         for (const AdvertisementPairing& pairing : parameters.advertisementPairings)
         {
            if (std::optional<ActivationAction> action = applyAdvertisementPairing(pairing))
            {
               actions.push_back(*action);
            }
         }

         for (const SubscriptionPairing& pairing : parameters.subscriptionPairings)
         {
            if (std::optional<ActivationAction> action = applySubscriptionPairing(pairing))
            {
               actions.push_back(*action);
            }
         }

         return actions;
      }

      std::optional<ActivationAction> applyAdvertisementPairing(const AdvertisementPairing& pairing)
      {
         const PairingKey key = PairingKey::fromAdvertisement(pairing);
         if (pairing.activate)
         {
            advertisements_[key] = pairing;
            return ActivationAction::registerAdvertiser(pairing);
         }

         if (advertisements_.erase(key) == 0)
         {
            return std::nullopt;
         }

         return ActivationAction::deactivateAdvertiser(key);
      }

      std::optional<ActivationAction> applySubscriptionPairing(const SubscriptionPairing& pairing)
      {
         const PairingKey key = PairingKey::fromSubscription(pairing);
         if (pairing.activate)
         {
            subscriptions_[key] = pairing;
            return ActivationAction::connectSubscriber(pairing);
         }

         if (subscriptions_.erase(key) == 0)
         {
            return std::nullopt;
         }

         return ActivationAction::deactivateSubscriber(key);
      }

   private:

      std::map<PairingKey, AdvertisementPairing> advertisements_;
      std::map<PairingKey, SubscriptionPairing> subscriptions_;
   };
}
