#pragma once

#include <array>
#include <cstdint>
#include <mutex>
#include <utility>
#include <vector>

class ProdigyContainerDeviceMapCoordinator
{
public:
   using Owner = unsigned __int128;
   static constexpr uint8_t fastRecoveryAttempts = 3;
   static constexpr uint64_t fastRecoveryDelayMs = 1'000;
   static constexpr uint64_t slowRecoveryDelayMs = 30'000;

   enum class Outcome : uint8_t
   {
      committed,
      rejected,
      quarantined
   };

   enum class IfindexState : uint8_t
   {
      present,
      absent,
      unknown
   };

   enum class RetirementAction : uint8_t
   {
      observe,
      destroy,
      complete
   };

   struct MapTarget
   {
      uint64_t identity = 0;
      uint32_t fragment = 0;
      uint32_t desired = 0;
      void *context = nullptr;
      bool (*read)(void *, uint32_t, uint32_t&) = nullptr;
      bool (*write)(void *, uint32_t, uint32_t) = nullptr;
   };

   struct Reservation
   {
      Owner owner = 0;
      uint32_t ifindex = 0;
      void *context = nullptr;
      bool retiring = false;
      bool quarantined = false;

      bool active(void) const
      {
         return owner != 0;
      }
   };

   static void appendAuthoritativeMap(
       MapTarget target,
       const std::array<Reservation, 256>& current,
       uint32_t zeroFragment,
       std::vector<MapTarget>& targets)
   {
      for (uint32_t fragment = 0; fragment < current.size(); ++fragment)
      {
         const Reservation& reservation = current[fragment];
         target.fragment = fragment;
         target.desired = fragment == 0
                              ? zeroFragment
                              : (reservation.active() && reservation.retiring == false ? reservation.ifindex : 0);
         targets.push_back(target);
      }
   }

   static constexpr uint64_t recoveryDelayMs(uint8_t attempts)
   {
      return attempts < fastRecoveryAttempts ? fastRecoveryDelayMs : slowRecoveryDelayMs;
   }

   static constexpr uint8_t nextRecoveryAttempt(uint8_t attempts)
   {
      return attempts == 255 ? attempts : uint8_t(attempts + 1);
   }

   static constexpr RetirementAction retirementAction(
       bool observeOnly,
       uint32_t ifindex,
       uint32_t nameIfindex,
       IfindexState nameState,
       IfindexState indexState)
   {
      if (nameState == IfindexState::absent && indexState == IfindexState::absent)
      {
         return RetirementAction::complete;
      }
      if (observeOnly == false && ifindex != 0 && nameIfindex == ifindex &&
          nameState == IfindexState::present && indexState == IfindexState::present)
      {
         return RetirementAction::destroy;
      }
      return RetirementAction::observe;
   }

private:
   std::mutex mutex;
   std::array<Reservation, 256> reservations = {};

   static Outcome mutate(const std::vector<MapTarget>& targets)
   {
      if (targets.empty())
      {
         return Outcome::rejected;
      }

      std::vector<uint32_t> prior(targets.size());
      for (uint32_t targetIndex = 0; targetIndex < targets.size(); ++targetIndex)
      {
         const MapTarget& target = targets[targetIndex];
         if (target.identity == 0 || target.read == nullptr || target.write == nullptr)
         {
            return Outcome::rejected;
         }
         for (uint32_t previous = 0; previous < targetIndex; ++previous)
         {
            if (targets[previous].identity == target.identity && targets[previous].fragment == target.fragment)
            {
               return Outcome::rejected;
            }
         }
         if (target.fragment > 255 || target.read(target.context, target.fragment, prior[targetIndex]) == false)
         {
            return Outcome::rejected;
         }
      }

      std::vector<uint32_t> attempted;
      attempted.reserve(targets.size());
      for (uint32_t targetIndex = 0; targetIndex < targets.size(); ++targetIndex)
      {
         const MapTarget& target = targets[targetIndex];
         if (prior[targetIndex] == target.desired)
         {
            continue;
         }

         attempted.push_back(targetIndex);
         uint32_t observed = 0;
         if (target.write(target.context, target.fragment, target.desired) == false ||
             target.read(target.context, target.fragment, observed) == false || observed != target.desired)
         {
            bool restored = true;
            for (auto it = attempted.rbegin(); it != attempted.rend(); ++it)
            {
               const MapTarget& rollbackTarget = targets[*it];
               uint32_t rollbackObserved = 0;
               (void)rollbackTarget.write(rollbackTarget.context, rollbackTarget.fragment, prior[*it]);
               if (rollbackTarget.read(rollbackTarget.context, rollbackTarget.fragment, rollbackObserved) == false ||
                   rollbackObserved != prior[*it])
               {
                  restored = false;
               }
            }
            return restored ? Outcome::rejected : Outcome::quarantined;
         }
      }
      return Outcome::committed;
   }

   template <typename Prepare>
   Outcome synchronize(Owner owner, uint8_t fragment, uint32_t ifindex, void *context, bool retiring, Prepare&& prepare)
   {
      if (owner == 0 || fragment == 0 || ifindex == 0)
      {
         return Outcome::rejected;
      }

      std::lock_guard lock(mutex);
      for (uint32_t currentFragment = 0; retiring == false && currentFragment < reservations.size(); ++currentFragment)
      {
         const Reservation& current = reservations[currentFragment];
         if (current.quarantined &&
             (currentFragment != fragment || current.owner != owner ||
              current.ifindex != ifindex || current.context != context))
         {
            return Outcome::rejected;
         }
      }
      Reservation& reservation = reservations[fragment];
      bool newlyReserved = false;
      if (reservation.active())
      {
         if (reservation.owner != owner || reservation.ifindex != ifindex || reservation.context != context)
         {
            return Outcome::rejected;
         }
         if (reservation.retiring && retiring == false)
         {
            return Outcome::rejected;
         }
      }
      else if (retiring)
      {
         return Outcome::rejected;
      }
      else
      {
         reservation.owner = owner;
         reservation.ifindex = ifindex;
         reservation.context = context;
         newlyReserved = true;
      }

      std::vector<MapTarget> targets;
      Outcome outcome = prepare(targets, reservations) ? mutate(targets) : Outcome::rejected;
      if (outcome == Outcome::committed)
      {
         reservation.retiring = retiring;
         reservation.quarantined = false;
      }
      else
      {
         if (retiring)
         {
            reservation.retiring = true;
            reservation.quarantined = true;
            outcome = Outcome::quarantined;
         }
         else if (outcome == Outcome::quarantined || newlyReserved)
         {
            reservation.quarantined = true;
         }
         if (newlyReserved)
         {
            // Prior map bytes may already name this ifindex; only verified retirement can release it.
            outcome = Outcome::quarantined;
         }
      }
      return outcome;
   }

public:
   template <typename Prepare>
   Outcome registerDevice(Owner owner, uint8_t fragment, uint32_t ifindex, void *context, Prepare&& prepare)
   {
      return synchronize(owner, fragment, ifindex, context, false, std::forward<Prepare>(prepare));
   }

   template <typename Prepare>
   Outcome retireDevice(Owner owner, uint8_t fragment, uint32_t ifindex, void *context, Prepare&& prepare)
   {
      return synchronize(owner, fragment, ifindex, context, true, std::forward<Prepare>(prepare));
   }

   void noteCleanupFailure(Owner owner, uint8_t fragment, uint32_t ifindex, void *context)
   {
      std::lock_guard lock(mutex);
      Reservation& reservation = reservations[fragment];
      if (reservation.owner == owner && reservation.ifindex == ifindex && reservation.context == context)
      {
         reservation.quarantined = true;
      }
   }

   bool completeRetirement(Owner owner, uint8_t fragment, uint32_t ifindex, void *context)
   {
      std::lock_guard lock(mutex);
      Reservation& reservation = reservations[fragment];
      if (reservation.owner != owner || reservation.ifindex != ifindex ||
          reservation.context != context || reservation.retiring == false)
      {
         return false;
      }
      reservation = {};
      return true;
   }

   Reservation reservation(uint8_t fragment)
   {
      std::lock_guard lock(mutex);
      return reservations[fragment];
   }

};
