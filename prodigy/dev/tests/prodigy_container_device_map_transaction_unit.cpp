#include <prodigy/container.device.map.h>

#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

class TestSuite
{
public:
   int failed = 0;

   void expect(bool condition, const char *name)
   {
      std::printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
      failed += condition ? 0 : 1;
   }
};

struct Faults
{
   int failRead = -1;
   int failWrite = -1;
   int failRollbackWrite = -1;
   int failRollbackRead = -1;
   int reads = 0;
   int writes = 0;
   bool updateFailed = false;
};

struct FakeMap
{
   std::array<uint32_t, 256> values = {};
   Faults *faults = nullptr;

   static bool read(void *context, uint32_t fragment, uint32_t& value)
   {
      FakeMap& map = *static_cast<FakeMap *>(context);
      int call = ++map.faults->reads;
      if (call == map.faults->failRead ||
          (map.faults->updateFailed && call == map.faults->failRollbackRead))
      {
         return false;
      }
      value = map.values[fragment];
      return true;
   }

   static bool write(void *context, uint32_t fragment, uint32_t value)
   {
      FakeMap& map = *static_cast<FakeMap *>(context);
      int call = ++map.faults->writes;
      if (map.faults->updateFailed && call == map.faults->failRollbackWrite)
      {
         return false;
      }
      map.values[fragment] = value;
      if (call == map.faults->failWrite)
      {
         map.faults->updateFailed = true;
         return false;
      }
      return true;
   }
};

using Coordinator = ProdigyContainerDeviceMapCoordinator;
using Reservations = std::array<Coordinator::Reservation, 256>;

static Coordinator::MapTarget target(uint64_t identity, FakeMap& map, uint8_t fragment, uint32_t ifindex)
{
   Coordinator::MapTarget result = {};
   result.identity = identity;
   result.fragment = fragment;
   result.desired = ifindex;
   result.context = &map;
   result.read = FakeMap::read;
   result.write = FakeMap::write;
   return result;
}

static auto prepareTwoMaps(FakeMap& first, FakeMap& second, uint8_t fragment, uint32_t ifindex)
{
   return [&first, &second, fragment, ifindex](std::vector<Coordinator::MapTarget>& targets, const Reservations&) -> bool {
      targets.push_back(target(1, first, fragment, ifindex));
      targets.push_back(target(2, second, fragment, ifindex));
      return true;
   };
}

static bool mapsEqual(const FakeMap& first, const FakeMap& second, uint8_t fragment, uint32_t value)
{
   return first.values[fragment] == value && second.values[fragment] == value;
}

static void testSuccessfulCommit(TestSuite& suite)
{
   Faults faults = {};
   FakeMap first = {{}, &faults};
   FakeMap second = {{}, &faults};
   Coordinator coordinator;
   int ownerContext = 1;
   auto outcome = coordinator.registerDevice(11, 7, 101, &ownerContext, prepareTwoMaps(first, second, 7, 101));
   auto reservation = coordinator.reservation(7);
   suite.expect(outcome == Coordinator::Outcome::committed && mapsEqual(first, second, 7, 101),
                "device_map_success_commits_every_live_map");
   suite.expect(reservation.owner == 11 && reservation.ifindex == 101 && reservation.context == &ownerContext,
                "device_map_success_retains_exact_identity_reservation");
}

static void testInitialReadFailure(TestSuite& suite)
{
   Faults faults = {};
   faults.failRead = 1;
   FakeMap first = {{}, &faults};
   FakeMap second = {{}, &faults};
   first.values[7] = 101;
   Coordinator coordinator;
   int ownerContext = 1;
   auto outcome = coordinator.registerDevice(11, 7, 101, &ownerContext, prepareTwoMaps(first, second, 7, 101));
   auto reservation = coordinator.reservation(7);
   suite.expect(outcome == Coordinator::Outcome::quarantined && faults.writes == 0 &&
                    reservation.active() && reservation.quarantined,
                "device_map_snapshot_failure_retains_unknown_prior_mapping");

   faults = {};
   auto retired = coordinator.retireDevice(11, 7, 101, &ownerContext,
                                            prepareTwoMaps(first, second, 7, 0));
   suite.expect(retired == Coordinator::Outcome::committed && mapsEqual(first, second, 7, 0) &&
                    coordinator.completeRetirement(11, 7, 101, &ownerContext),
                "device_map_snapshot_failure_requires_verified_retirement");
}

static void testAuthoritativeRecoverySweep(TestSuite& suite)
{
   Faults faults = {};
   FakeMap host = {{}, &faults};
   FakeMap peer = {{}, &faults};
   host.values[0] = 701;
   host.values[31] = 702;
   peer.values[0] = 703;
   peer.values[31] = 704;
   Coordinator coordinator;
   int ownerContext = 1;
   auto outcome = coordinator.registerDevice(11, 7, 101, &ownerContext,
      [&](std::vector<Coordinator::MapTarget>& targets, const Reservations& reservations) -> bool {
         Coordinator::appendAuthoritativeMap(target(1, host, 0, 0), reservations, 0, targets);
         Coordinator::appendAuthoritativeMap(target(2, peer, 0, 0), reservations, 55, targets);
         return true;
      });

   bool inactiveCleared = true;
   for (uint32_t fragment = 1; fragment < 256; ++fragment)
   {
      if (fragment != 7)
      {
         inactiveCleared = inactiveCleared && host.values[fragment] == 0 && peer.values[fragment] == 0;
      }
   }
   suite.expect(outcome == Coordinator::Outcome::committed && host.values[0] == 0 &&
                    peer.values[0] == 55 && host.values[7] == 101 && peer.values[7] == 101 && inactiveCleared,
                "device_map_recovery_sweep_clears_stale_preattached_slots");
}

static void testPrepareFailure(TestSuite& suite)
{
   Faults faults = {};
   FakeMap first = {{}, &faults};
   FakeMap second = {{}, &faults};
   first.values[7] = 101;
   Coordinator coordinator;
   int ownerContext = 1;
   auto outcome = coordinator.registerDevice(11, 7, 101, &ownerContext,
      [](std::vector<Coordinator::MapTarget>&, const Reservations&) -> bool {
         return false;
      });
   auto reservation = coordinator.reservation(7);
   suite.expect(outcome == Coordinator::Outcome::quarantined && reservation.active() && reservation.quarantined,
                "device_map_prepare_failure_retains_unknown_prior_mapping");

   auto retired = coordinator.retireDevice(11, 7, 101, &ownerContext,
                                            prepareTwoMaps(first, second, 7, 0));
   suite.expect(retired == Coordinator::Outcome::committed && mapsEqual(first, second, 7, 0) &&
                    coordinator.completeRetirement(11, 7, 101, &ownerContext),
                "device_map_prepare_failure_requires_verified_retirement");
}

static void testUpdateFailuresRollback(TestSuite& suite)
{
   for (int failedWrite : {1, 2})
   {
      Faults faults = {};
      faults.failWrite = failedWrite;
      FakeMap first = {{}, &faults};
      FakeMap second = {{}, &faults};
      Coordinator coordinator;
      int ownerContext = 1;
      auto outcome = coordinator.registerDevice(11, 7, 101, &ownerContext, prepareTwoMaps(first, second, 7, 101));
      auto reservation = coordinator.reservation(7);
      suite.expect(outcome == Coordinator::Outcome::quarantined && mapsEqual(first, second, 7, 0) &&
                       reservation.active() && reservation.quarantined,
                   failedWrite == 1 ? "device_map_first_update_failure_rolls_back_and_quarantines"
                                    : "device_map_later_update_failure_rolls_back_and_quarantines");
      faults = {};
      suite.expect(coordinator.retireDevice(11, 7, 101, &ownerContext,
                                            prepareTwoMaps(first, second, 7, 0)) ==
                          Coordinator::Outcome::committed &&
                       coordinator.completeRetirement(11, 7, 101, &ownerContext),
                   failedWrite == 1 ? "device_map_first_update_failure_retires_before_release"
                                    : "device_map_later_update_failure_retires_before_release");
   }
}

static void testUpdateReadbackFailureRollsBack(TestSuite& suite)
{
   Faults faults = {};
   faults.failRead = 4;
   FakeMap first = {{}, &faults};
   FakeMap second = {{}, &faults};
   Coordinator coordinator;
   int ownerContext = 1;
   auto outcome = coordinator.registerDevice(11, 7, 101, &ownerContext, prepareTwoMaps(first, second, 7, 101));
   auto reservation = coordinator.reservation(7);
   suite.expect(outcome == Coordinator::Outcome::quarantined && mapsEqual(first, second, 7, 0) &&
                    reservation.active() && reservation.quarantined,
                "device_map_update_readback_failure_rolls_back_and_quarantines");
   faults = {};
   suite.expect(coordinator.retireDevice(11, 7, 101, &ownerContext,
                                         prepareTwoMaps(first, second, 7, 0)) ==
                       Coordinator::Outcome::committed &&
                    coordinator.completeRetirement(11, 7, 101, &ownerContext),
                "device_map_update_readback_failure_retires_before_release");
}

static void testUnchangedPriorIfindexRetainedOnFailure(TestSuite& suite)
{
   Faults faults = {};
   faults.failWrite = 1;
   FakeMap first = {{}, &faults};
   FakeMap second = {{}, &faults};
   first.values[7] = 101;
   Coordinator coordinator;
   int ownerContext = 1;
   int replacementContext = 2;
   auto outcome = coordinator.registerDevice(11, 7, 101, &ownerContext,
                                              prepareTwoMaps(first, second, 7, 101));
   int prepareCalls = 0;
   auto replacement = coordinator.registerDevice(22, 8, 202, &replacementContext,
      [&](std::vector<Coordinator::MapTarget>&, const Reservations&) -> bool {
         ++prepareCalls;
         return true;
      });
   auto reservation = coordinator.reservation(7);
   suite.expect(outcome == Coordinator::Outcome::quarantined && first.values[7] == 101 &&
                    second.values[7] == 0 && reservation.owner == 11 && reservation.ifindex == 101 &&
                    reservation.context == &ownerContext && reservation.quarantined &&
                    replacement == Coordinator::Outcome::rejected && prepareCalls == 0,
                "device_map_unchanged_stale_ifindex_blocks_replacement_after_failure");

   faults = {};
   auto retired = coordinator.retireDevice(11, 7, 101, &ownerContext,
                                            prepareTwoMaps(first, second, 7, 0));
   suite.expect(retired == Coordinator::Outcome::committed && mapsEqual(first, second, 7, 0) &&
                    coordinator.completeRetirement(11, 7, 101, &ownerContext),
                "device_map_unchanged_stale_ifindex_cleared_before_release");
}

static void testUnprovableRollbackQuarantines(TestSuite& suite)
{
   for (bool failWrite : {true, false})
   {
      Faults faults = {};
      faults.failWrite = 2;
      faults.failRollbackWrite = failWrite ? 3 : -1;
      faults.failRollbackRead = failWrite ? -1 : 4;
      FakeMap first = {{}, &faults};
      FakeMap second = {{}, &faults};
      Coordinator coordinator;
      int ownerContext = 1;
      auto outcome = coordinator.registerDevice(11, 7, 101, &ownerContext, prepareTwoMaps(first, second, 7, 101));
      auto reservation = coordinator.reservation(7);
      suite.expect(outcome == Coordinator::Outcome::quarantined && reservation.quarantined &&
                       reservation.owner == 11 && reservation.ifindex == 101,
                   failWrite ? "device_map_rollback_write_failure_quarantines_identity"
                             : "device_map_rollback_readback_failure_quarantines_identity");
   }
}

static void testRetirementFailuresQuarantine(TestSuite& suite)
{
   for (bool failSnapshot : {true, false})
   {
      Faults faults = {};
      FakeMap first = {{}, &faults};
      FakeMap second = {{}, &faults};
      Coordinator coordinator;
      int ownerContext = 1;
      int replacementContext = 2;
      suite.expect(coordinator.registerDevice(11, 7, 101, &ownerContext,
                                              prepareTwoMaps(first, second, 7, 101)) ==
                       Coordinator::Outcome::committed,
                   failSnapshot ? "device_map_retirement_read_failure_fixture_registered"
                                : "device_map_retirement_rollback_fixture_registered");

      faults = {};
      faults.failRead = failSnapshot ? 1 : -1;
      faults.failWrite = failSnapshot ? -1 : 1;
      auto retired = coordinator.retireDevice(11, 7, 101, &ownerContext,
                                               prepareTwoMaps(first, second, 7, 0));
      auto reservation = coordinator.reservation(7);
      int prepareCalls = 0;
      auto replacement = coordinator.registerDevice(22, 8, 202, &replacementContext,
         [&](std::vector<Coordinator::MapTarget>&, const Reservations&) -> bool {
            ++prepareCalls;
            return true;
         });
      suite.expect(retired == Coordinator::Outcome::quarantined && reservation.retiring &&
                       reservation.quarantined && replacement == Coordinator::Outcome::rejected && prepareCalls == 0,
                   failSnapshot ? "device_map_retirement_read_failure_blocks_reuse"
                                : "device_map_retirement_verified_rollback_blocks_reuse");

      faults = {};
      suite.expect(coordinator.retireDevice(11, 7, 101, &ownerContext,
                                            prepareTwoMaps(first, second, 7, 0)) ==
                          Coordinator::Outcome::committed &&
                       coordinator.completeRetirement(11, 7, 101, &ownerContext),
                   failSnapshot ? "device_map_retirement_read_failure_recovers_exact_owner"
                                : "device_map_retirement_verified_rollback_recovers_exact_owner");
   }
}

static void testRecoveryCadenceContinues(TestSuite& suite)
{
   suite.expect(Coordinator::recoveryDelayMs(0) == Coordinator::fastRecoveryDelayMs &&
                    Coordinator::recoveryDelayMs(2) == Coordinator::fastRecoveryDelayMs &&
                    Coordinator::recoveryDelayMs(3) == Coordinator::slowRecoveryDelayMs &&
                    Coordinator::recoveryDelayMs(255) == Coordinator::slowRecoveryDelayMs,
                "device_map_recovery_switches_to_bounded_slow_cadence");
   suite.expect(Coordinator::nextRecoveryAttempt(2) == 3 && Coordinator::nextRecoveryAttempt(3) == 4 &&
                    Coordinator::nextRecoveryAttempt(255) == 255,
                "device_map_recovery_continues_after_fast_attempts_without_overflow");
}

static void testOriginalIfindexRetirementProof(TestSuite& suite)
{
   using State = Coordinator::IfindexState;
   using Action = Coordinator::RetirementAction;
   suite.expect(Coordinator::retirementAction(false, 41, 41, State::present, State::present) == Action::destroy,
                "device_map_exact_name_and_ifindex_permit_initial_delete");
   suite.expect(Coordinator::retirementAction(true, 41, 41, State::present, State::present) == Action::observe,
                "device_map_exact_name_and_ifindex_aba_forbids_second_delete");
   suite.expect(Coordinator::retirementAction(false, 41, 0, State::absent, State::present) == Action::observe,
                "device_map_renamed_interface_enters_observe_only");
   suite.expect(Coordinator::retirementAction(true, 41, 0, State::absent, State::absent) == Action::complete,
                "device_map_absent_name_and_ifindex_prove_retirement");
   suite.expect(Coordinator::retirementAction(true, 41, 0, State::absent, State::present) == Action::observe,
                "device_map_reused_original_ifindex_remains_quarantined");
   suite.expect(Coordinator::retirementAction(true, 41, 0, State::unknown, State::absent) == Action::observe,
                "device_map_unknown_name_state_remains_quarantined");
}

static void testQuarantineBlocksIfindexReuse(TestSuite& suite)
{
   Faults faults = {};
   FakeMap first = {{}, &faults};
   FakeMap second = {{}, &faults};
   Coordinator coordinator;
   int firstOwner = 1;
   int secondOwner = 2;
   int retiringOwner = 3;
   suite.expect(coordinator.registerDevice(33, 6, 303, &retiringOwner,
                                           prepareTwoMaps(first, second, 6, 303)) ==
                    Coordinator::Outcome::committed,
                "device_map_quarantine_fixture_registered");
   faults = {};
   faults.failWrite = 2;
   faults.failRollbackWrite = 3;
   auto quarantined = coordinator.registerDevice(11, 7, 101, &firstOwner, prepareTwoMaps(first, second, 7, 101));

   int prepareCalls = 0;
   auto replacement = coordinator.registerDevice(22, 8, 202, &secondOwner,
      [&](std::vector<Coordinator::MapTarget>&, const Reservations&) -> bool {
         ++prepareCalls;
         return true;
      });
   suite.expect(quarantined == Coordinator::Outcome::quarantined &&
                    replacement == Coordinator::Outcome::rejected && prepareCalls == 0,
                "device_map_quarantine_blocks_stale_ifindex_reuse_before_mutation");

   auto wrongFragment = coordinator.registerDevice(11, 8, 101, &firstOwner,
      [&](std::vector<Coordinator::MapTarget>&, const Reservations&) -> bool {
         ++prepareCalls;
         return true;
      });
   suite.expect(wrongFragment == Coordinator::Outcome::rejected && prepareCalls == 0,
                "device_map_quarantine_requires_exact_fragment_for_repair");

   faults = {};
   auto unrelatedRetirement = coordinator.retireDevice(33, 6, 303, &retiringOwner,
                                                         prepareTwoMaps(first, second, 6, 0));
   suite.expect(unrelatedRetirement == Coordinator::Outcome::committed &&
                    coordinator.completeRetirement(33, 6, 303, &retiringOwner),
                "device_map_quarantine_allows_unrelated_retirement");

   auto repaired = coordinator.retireDevice(11, 7, 101, &firstOwner, prepareTwoMaps(first, second, 7, 0));
   suite.expect(repaired == Coordinator::Outcome::committed &&
                    coordinator.completeRetirement(11, 7, 101, &firstOwner),
                "device_map_exact_quarantined_owner_can_repair_and_retire");
}

static void testRetiringDeviceExcludedFromNewRegistration(TestSuite& suite)
{
   Faults faults = {};
   FakeMap first = {{}, &faults};
   FakeMap second = {{}, &faults};
   Coordinator coordinator;
   int firstOwner = 1;
   int secondOwner = 2;
   coordinator.registerDevice(11, 7, 101, &firstOwner, prepareTwoMaps(first, second, 7, 101));
   auto retired = coordinator.retireDevice(11, 7, 101, &firstOwner, prepareTwoMaps(first, second, 7, 0));

   bool sawRetiring = false;
   auto replacement = coordinator.registerDevice(22, 8, 202, &secondOwner,
      [&](std::vector<Coordinator::MapTarget>& targets, const Reservations& reservations) -> bool {
         sawRetiring = reservations[7].retiring;
         targets.push_back(target(1, first, 8, 202));
         targets.push_back(target(2, second, 8, 202));
         return true;
      });
   suite.expect(retired == Coordinator::Outcome::committed && sawRetiring &&
                    replacement == Coordinator::Outcome::committed && mapsEqual(first, second, 7, 0) &&
                    mapsEqual(first, second, 8, 202),
                "device_map_new_registration_does_not_resurrect_retiring_ifindex");
   suite.expect(coordinator.completeRetirement(11, 7, 101, &firstOwner),
                "device_map_retiring_interleaving_releases_original_identity");
}

static void testConcurrentRetirementAndRegistration(TestSuite& suite)
{
   Faults faults = {};
   FakeMap first = {{}, &faults};
   FakeMap second = {{}, &faults};
   Coordinator coordinator;
   int firstOwner = 1;
   int secondOwner = 2;
   suite.expect(coordinator.registerDevice(11, 7, 101, &firstOwner, prepareTwoMaps(first, second, 7, 101)) ==
                    Coordinator::Outcome::committed,
                "device_map_concurrency_fixture_registered");

   std::atomic<bool> start = false;
   Coordinator::Outcome retired = Coordinator::Outcome::rejected;
   Coordinator::Outcome replacement = Coordinator::Outcome::committed;
   auto retirePrepare = prepareTwoMaps(first, second, 7, 0);
   auto replacementPrepare = prepareTwoMaps(first, second, 7, 202);
   std::thread retiring([&] {
      while (start.load(std::memory_order_acquire) == false)
      {
      }
      retired = coordinator.retireDevice(11, 7, 101, &firstOwner, retirePrepare);
   });
   std::thread registering([&] {
      while (start.load(std::memory_order_acquire) == false)
      {
      }
      replacement = coordinator.registerDevice(22, 7, 202, &secondOwner, replacementPrepare);
   });
   start.store(true, std::memory_order_release);
   retiring.join();
   registering.join();

   suite.expect(retired == Coordinator::Outcome::committed && replacement == Coordinator::Outcome::rejected &&
                    mapsEqual(first, second, 7, 0),
                "device_map_concurrent_retire_register_is_serial_and_fail_closed");
   int cleanupCalls = 0;
   cleanupCalls += coordinator.completeRetirement(11, 7, 101, &secondOwner) ? 1 : 0;
   suite.expect(cleanupCalls == 0 && coordinator.reservation(7).active(),
                "device_map_stale_context_cannot_release_retirement");
   coordinator.noteCleanupFailure(11, 7, 101, &secondOwner);
   suite.expect(coordinator.reservation(7).quarantined == false,
                "device_map_stale_context_cannot_quarantine_retirement");
   cleanupCalls += coordinator.completeRetirement(11, 7, 101, &firstOwner) ? 1 : 0;
   cleanupCalls += coordinator.completeRetirement(11, 7, 101, &firstOwner) ? 1 : 0;
   suite.expect(cleanupCalls == 1 && coordinator.reservation(7).active() == false,
                "device_map_retirement_releases_exactly_once");
   suite.expect(coordinator.registerDevice(22, 7, 202, &secondOwner, replacementPrepare) ==
                    Coordinator::Outcome::committed && mapsEqual(first, second, 7, 202),
                "device_map_reuse_allowed_only_after_verified_retirement");
}

int main(void)
{
   TestSuite suite;
   testSuccessfulCommit(suite);
   testInitialReadFailure(suite);
   testAuthoritativeRecoverySweep(suite);
   testPrepareFailure(suite);
   testUpdateFailuresRollback(suite);
   testUpdateReadbackFailureRollsBack(suite);
   testUnchangedPriorIfindexRetainedOnFailure(suite);
   testUnprovableRollbackQuarantines(suite);
   testRetirementFailuresQuarantine(suite);
   testQuarantineBlocksIfindexReuse(suite);
   testRetiringDeviceExcludedFromNewRegistration(suite);
   testConcurrentRetirementAndRegistration(suite);
   testRecoveryCadenceContinues(suite);
   testOriginalIfindexRetirementProof(suite);
   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
