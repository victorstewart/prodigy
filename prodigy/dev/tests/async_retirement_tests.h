// Included by prodigy_brain_replication_credentials_unit.cpp after its shared
// TestBrain and TestSuite fixtures.

#include <tuple>
#include <memory>

static void testAsyncMachineRetirementJournalDurability(TestSuite& suite)
{
  struct Result { uint32_t completions = 0; bool durable = false; };
  auto beginRetirement = [](TestBrain& brain, uint128_t uuid) {
    Machine machine = {};
    machine.uuid = uuid;
    Vector<Machine *> aliases;
    aliases.push_back(&machine);
    uint64_t identityID = 0;
    std::shared_ptr<Result> result = std::make_shared<Result>();
    const bool admitted = brain.journalMachineRetirement(
        aliases, false, identityID, [result](bool receipt) {
          result->completions += 1;
          result->durable = receipt;
        });
    return std::tuple<uint64_t, bool, std::shared_ptr<Result>>(
        identityID, admitted, std::move(result));
  };

  {
    TestBrain brain;
    brain.weAreMaster = true;
    brain.nBrains = 1;
    brain.holdRuntimePersistence = true;
    auto [identityID, admitted, result] = beginRetirement(brain, 0x9911);
    suite.expect(admitted && result->completions == 0 && !result->durable && identityID != 0 &&
                     brain.machineRetirementPersistencePending &&
                     brain.pendingRuntimePersistence.size() == 1,
                 "retirement_journal_holds_completion_and_provider_fence_before_durable_receipt");
    brain.reapRetiringMachines();
    suite.expect(brain.retiredMachineIdentities.contains(identityID) &&
                     brain.machineRetirementPersistencePending,
                 "retirement_recheck_does_not_advance_while_journal_receipt_is_held");
    brain.finishRuntimePersistence(true);
    suite.expect(result->completions == 1 && result->durable && !brain.machineRetirementPersistencePending &&
                     brain.masterAuthorityRuntimeStateDurable &&
                     brain.retiredMachineIdentities.contains(identityID) &&
                     brain.machineRetirementJournalPresent(brain.masterAuthorityRuntimeState),
                 "retirement_journal_enables_provider_fence_only_after_durable_receipt");
  }

  {
    TestBrain brain;
    brain.weAreMaster = true;
    brain.nBrains = 1;
    brain.holdRuntimePersistence = true;
    auto [identityID, admitted, result] = beginRetirement(brain, 0x9912);
    suite.expect(admitted && result->completions == 0 && !result->durable && identityID != 0 &&
                     brain.machineRetirementPersistencePending,
                 "retirement_journal_failure_holds_provider_fence_before_receipt");
    brain.finishRuntimePersistence(false);
    suite.expect(result->completions == 1 && !result->durable && !brain.machineRetirementPersistencePending &&
                     !brain.retiredMachineIdentities.contains(identityID) &&
                     !brain.machineRetirementJournalPresent(brain.masterAuthorityRuntimeState),
                 "retirement_journal_failure_restores_candidate_before_provider_progress");
  }
}
