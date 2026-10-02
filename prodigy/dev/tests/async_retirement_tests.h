// Included by prodigy_brain_replication_credentials_unit.cpp after its shared
// TestBrain and TestSuite fixtures.

#include <tuple>
#include <memory>

static void testAsyncMachineRetirementJournalDurability(TestSuite& suite)
{
  struct Result { uint32_t completions = 0; bool durable = false; };
  struct FenceIaaS final : NoopBrainIaaS {
    bool active = false;
    Vector<bool> transitions;

    bool setProviderReconfigurationFenceActive(bool enabled) override
    {
      transitions.push_back(enabled);
      active = enabled;
      return true;
    }
  };
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

  {
    TestBrain brain;
    FenceIaaS provider;
    brain.iaas = &provider;
    brain.weAreMaster = true;
    brain.nBrains = 1;
    auto [identityID, admitted, result] = beginRetirement(brain, 0x9913);
    const uint64_t durableGeneration = brain.masterAuthorityRuntimeState.generation;
    auto retirement = brain.retiredMachineIdentities.find(identityID);
    if (retirement != brain.retiredMachineIdentities.end())
    {
      retirement->second.evacuationComplete = true;
      retirement->second.topologyAbsent = true;
      retirement->second.topologyObservationEpoch = brain.masterAuthorityEpoch;
    }

    brain.holdRuntimePersistence = true;
    brain.settleRetiredMachineIdentities();
    suite.expect(admitted && result->completions == 1 && result->durable && identityID != 0 &&
                     brain.machineRetirementPersistencePending &&
                     brain.pendingRuntimePersistence.size() == 1 &&
                     brain.retiredMachineIdentities.empty() &&
                     !brain.machineRetirementJournalPresent(brain.masterAuthorityRuntimeState) &&
                     provider.active && provider.transitions.size() == 1 && provider.transitions[0],
                 "retirement_final_clear_holds_provider_fence_until_journal_receipt");

    brain.finishRuntimePersistence(false);
    suite.expect(!brain.machineRetirementPersistencePending &&
                     brain.retiredMachineIdentities.contains(identityID) &&
                     brain.masterAuthorityRuntimeState.generation == durableGeneration &&
                     brain.masterAuthorityRuntimeStateDurable &&
                     brain.durableMasterAuthorityRuntimeStateGeneration == durableGeneration &&
                     brain.machineRetirementJournalPresent(brain.masterAuthorityRuntimeState) &&
                     provider.active && provider.transitions.size() == 1,
                 "retirement_final_clear_failed_receipt_restores_carrier_identity_and_fence");

    brain.settleRetiredMachineIdentities();
    suite.expect(brain.machineRetirementPersistencePending &&
                     brain.pendingRuntimePersistence.size() == 1 && provider.active &&
                     provider.transitions.size() == 1,
                 "retirement_final_clear_retry_holds_fence_before_successful_receipt");
    brain.finishRuntimePersistence(true);
    suite.expect(!brain.machineRetirementPersistencePending && brain.retiredMachineIdentities.empty() &&
                     !brain.machineRetirementJournalPresent(brain.masterAuthorityRuntimeState) &&
                     brain.masterAuthorityRuntimeState.generation == durableGeneration + 1 &&
                     brain.masterAuthorityRuntimeStateDurable &&
                     brain.durableMasterAuthorityRuntimeStateGeneration == durableGeneration + 1 &&
                     !provider.active && provider.transitions.size() == 2 &&
                     provider.transitions[0] && !provider.transitions[1],
                 "retirement_final_clear_success_releases_provider_fence_once");
  }

  {
    TestBrain brain;
    FenceIaaS provider;
    brain.iaas = &provider;
    brain.weAreMaster = true;
    brain.nBrains = 1;
    TaskExecutionRecord malformed = {};
    malformed.executionID = 0;
    malformed.versionID = 1;
    brain.masterAuthorityRuntimeState.taskExecutions.insert_or_assign(0, malformed);
    bool completionCalled = false;
    bool durable = true;
    brain.commitMachineRetirementJournalAsync([&](bool receipt) {
      completionCalled = true;
      durable = receipt;
    });
    suite.expect(completionCalled && !durable && brain.persistCalls == 0 &&
                     brain.masterAuthorityRuntimeState.taskExecutions.contains(0) &&
                     !brain.machineRetirementJournalPresent(brain.masterAuthorityRuntimeState) &&
                     provider.transitions.empty(),
                 "retirement_final_clear_rejects_malformed_existing_carrier");
  }
}
