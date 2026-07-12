#pragma once

#include <prodigy/types.h>
#include <services/crypto.h>

#include <cstdint>

namespace ProdigyDns
{

class ControlPairingLeases final
{
public:

   constexpr static size_t maximumLeases = 1024;
   constexpr static int64_t minimumLifetimeMs = 60 * 1000;
   constexpr static int64_t maximumLifetimeMs = 30LL * 24 * 60 * 60 * 1000;

   struct Hooks
   {
      void *context = nullptr;
      bool (*persist)(void *context,
                      const ProdigyMasterAuthorityRuntimeState& state,
                      String *failure) = nullptr;
      bool (*pair)(void *context,
                   const ProdigyDnsControlPairingLease& lease,
                   bool activate,
                   String *failure) = nullptr;
   };

private:

   ProdigyMasterAuthorityRuntimeState& state;
   Hooks hooks;

   static uint128_t nonzeroSecret(void)
   {
      uint128_t value = 0;
      while (value == 0)
      {
         value = Crypto::secureRandomNumber<uint128_t>();
      }
      return value;
   }

   bool persist(String *failure)
   {
      if (hooks.persist == nullptr)
      {
         if (failure)
         {
            failure->assign("DNS control pairing persistence hook is unavailable"_ctv);
         }
         return false;
      }
      return hooks.persist(hooks.context, state, failure);
   }

   bool pair(const ProdigyDnsControlPairingLease& lease,
             bool activate,
             String *failure)
   {
      if (hooks.pair == nullptr)
      {
         if (failure)
         {
            failure->assign("DNS control pairing activation hook is unavailable"_ctv);
         }
         return false;
      }
      return hooks.pair(hooks.context, lease, activate, failure);
   }

   bool containsLeaseID(uint128_t leaseID) const
   {
      for (const auto& lease : state.dnsControlPairingLeases)
      {
         if (lease.leaseID == leaseID)
         {
            return true;
         }
      }
      return false;
   }

   uint64_t nextGeneration(void)
   {
      uint64_t generation = state.nextDnsControlPairingGeneration++;
      if (generation == 0)
      {
         generation = state.nextDnsControlPairingGeneration++;
      }
      if (state.nextDnsControlPairingGeneration == 0)
      {
         state.nextDnsControlPairingGeneration = 1;
      }
      return generation;
   }

public:

   ControlPairingLeases(ProdigyMasterAuthorityRuntimeState& requestedState,
                        Hooks requestedHooks)
       : state(requestedState), hooks(requestedHooks)
   {}

   bool mint(ProdigyDnsControlClientRole role,
             const IPAddress& clientAddress,
             int64_t nowMs,
             int64_t lifetimeMs,
             ProdigyDnsControlPairingLease& minted,
             String *failure = nullptr)
   {
      minted = {};
      if ((role != ProdigyDnsControlClientRole::mothership &&
           role != ProdigyDnsControlClientRole::prodigy) ||
          clientAddress.is6 == false || clientAddress.isNull() || nowMs < 0 ||
          lifetimeMs < minimumLifetimeMs || lifetimeMs > maximumLifetimeMs ||
          nowMs > INT64_MAX - lifetimeMs)
      {
         if (failure)
         {
            failure->assign("DNS control pairing lease request is invalid or capacity is exhausted"_ctv);
         }
         return false;
      }

      for (auto& existing : state.dnsControlPairingLeases)
      {
         if (existing.desiredActive && existing.role == role &&
             existing.clientAddress.equals(clientAddress) &&
             existing.expiresAtMs > nowMs)
         {
            minted = existing;
            if (existing.applied)
            {
               if (failure)
               {
                  failure->clear();
               }
               return true;
            }
            if (pair(existing, true, failure) == false)
            {
               return false;
            }
            existing.applied = true;
            minted = existing;
            return persist(failure);
         }
      }

      if (state.dnsControlPairingLeases.size() >= maximumLeases)
      {
         if (failure)
         {
            failure->assign("DNS control pairing lease capacity is exhausted"_ctv);
         }
         return false;
      }

      ProdigyDnsControlPairingLease lease;
      do
      {
         lease.leaseID = nonzeroSecret();
      } while (containsLeaseID(lease.leaseID));
      lease.secret = nonzeroSecret();
      lease.clientAddress = clientAddress;
      lease.generation = nextGeneration();
      lease.expiresAtMs = nowMs + lifetimeMs;
      lease.role = role;
      lease.desiredActive = true;
      lease.applied = false;

      state.dnsControlPairingLeases.push_back(lease);
      if (persist(failure) == false)
      {
         state.dnsControlPairingLeases.pop_back();
         return false;
      }
      minted = lease;
      if (pair(lease, true, failure) == false)
      {
         return false;
      }

      state.dnsControlPairingLeases.back().applied = true;
      minted = state.dnsControlPairingLeases.back();
      if (persist(failure) == false)
      {
         return false;
      }
      if (failure)
      {
         failure->clear();
      }
      return true;
   }

   bool revoke(uint128_t leaseID,
               uint64_t generation,
               String *failure = nullptr)
   {
      for (size_t index = 0; index < state.dnsControlPairingLeases.size();
           index += 1)
      {
         auto& lease = state.dnsControlPairingLeases[index];
         if (lease.leaseID != leaseID || lease.generation != generation)
         {
            continue;
         }
         lease.desiredActive = false;
         if (persist(failure) == false)
         {
            return false;
         }
         if (lease.applied && pair(lease, false, failure) == false)
         {
            return false;
         }
         lease.applied = false;
         state.dnsControlPairingLeases.erase(
             state.dnsControlPairingLeases.begin() + index);
         return persist(failure);
      }

      if (failure)
      {
         failure->assign("DNS control pairing lease was not found"_ctv);
      }
      return false;
   }

   bool reconcile(int64_t nowMs, String *failure = nullptr)
   {
      bool expiryChanged = false;
      for (auto& lease : state.dnsControlPairingLeases)
      {
         if (lease.desiredActive && lease.expiresAtMs <= nowMs)
         {
            lease.desiredActive = false;
            expiryChanged = true;
         }
      }
      if (expiryChanged && persist(failure) == false)
      {
         return false;
      }

      for (size_t index = 0; index < state.dnsControlPairingLeases.size();)
      {
         auto& lease = state.dnsControlPairingLeases[index];
         if (lease.desiredActive)
         {
            if (pair(lease, true, failure) == false)
            {
               return false;
            }
            if (lease.applied == false)
            {
               lease.applied = true;
               if (persist(failure) == false)
               {
                  return false;
               }
            }
            index += 1;
            continue;
         }
         if (lease.applied && pair(lease, false, failure) == false)
         {
            return false;
         }
         lease.applied = false;
         state.dnsControlPairingLeases.erase(
             state.dnsControlPairingLeases.begin() + index);
         if (persist(failure) == false)
         {
            return false;
         }
      }

      if (failure)
      {
         failure->clear();
      }
      return true;
   }
};

} // namespace ProdigyDns
