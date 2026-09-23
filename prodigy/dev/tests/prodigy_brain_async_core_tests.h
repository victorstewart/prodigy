// Included after the shared Brain fixtures.
static void testAsyncCorePersistenceGates(TestSuite& suite)
{
  for (int result = 0; result < 4; ++result)
  {
    ScopedAsyncMothershipRing ring;
    ScopedSocketPair sockets;
    TestBrain brain; NoopBrainIaaS iaas; Mothership stream;
    brain.iaas = &iaas; brain.weAreMaster = true; brain.noMasterYet = false;
    brain.holdClusterOwnership = true; brain.holdRuntimePersistence = true;
    if (suite.require(sockets.create(suite, "configure_async_persistence_socket_pair"),
                      "configure_async_persistence_socket_pair_required") == false) return;
    stream.isFixedFile = false; stream.fd = sockets.takeLeft();
    if (suite.require(brain.activateMothershipConnection(&stream),
                      "configure_async_persistence_activates_mothership") == false) return;
    RingDispatcher::installMultiplexee(&stream, &brain);
    BrainConfig config; config.clusterUUID = 0x8112;
    String payload, frame; BitseryEngine::serialize(payload, config);
    brain.mothershipHandler(&stream, buildMothershipMessage(frame, MothershipTopic::configure, payload));
    suite.expect(brain.brainConfig.clusterUUID == 0 && brain.pendingClusterOwnership.size() == 1 &&
                     brain.pendingRuntimePersistence.empty() && stream.wBuffer.empty(),
                 "configure_waits_for_owned_cluster_before_mutation");
    if (result == 3) ++brain.masterAuthorityEpoch;
    brain.finishClusterOwnership(result != 0);
    if (result == 0 || result == 3)
      suite.expect(brain.brainConfig.clusterUUID == 0 && brain.pendingRuntimePersistence.empty(),
                   "configure_failed_or_stale_ownership_is_inert");
    else
    {
      suite.expect(brain.pendingRuntimePersistence.size() == 1 && stream.wBuffer.empty(),
                   "configure_waits_for_snapshot_before_reply");
      brain.finishRuntimePersistence(result == 1);
      suite.expect(result == 1 ? !stream.wBuffer.empty() : brain.brainConfig.clusterUUID == 0,
                   "configure_snapshot_receipt_releases_reply_or_rolls_back");
    }
    RingDispatcher::eraseMultiplexee(&stream);
    brain.activeMotherships.erase(&stream); brain.closingMotherships.erase(&stream);
    if (stream.fd >= 0) { ::close(stream.fd); stream.fd = -1; }
  }
  for (int result = 0; result < 3; ++result)
  {
    TestBrain brain;
    brain.weAreMaster = true; brain.nBrains = 1; brain.holdRuntimePersistence = true;
    const uint64_t initial = brain.masterAuthorityRuntimeState.generation;
    brain.noteMasterAuthorityRuntimeStateChanged();
    suite.expect(!brain.masterAuthorityRuntimeStateDurable && brain.pendingRuntimePersistence.size() == 1,
                 "authority_note_waits_for_receipt");
    if (result == 2) ++brain.masterAuthorityEpoch;
    brain.finishRuntimePersistence(result != 0);
    suite.expect(brain.masterAuthorityRuntimeStateDurable == (result == 1),
                 "authority_note_failure_or_stale_cannot_mark_durable");
    suite.expect(brain.masterAuthorityRuntimeState.generation == initial + 1,
                 "authority_note_advances_exactly_once");
  }
  for (int result = 0; result < 3; ++result)
  {
    TestBrain brain; brain.holdRuntimePersistence = true;
    const auto oldNext = brain.masterAuthorityRuntimeState.nextPendingAddMachinesOperationID;
    bool called = false, accepted = false; uint64_t operation = 0;
    brain.journalAutonomousProvisioningOperationAsync(42, ApplicationLifetime::base, "schema"_ctv, 2,
      [&](bool durable, uint64_t id) { called = true; accepted = durable; operation = id; });
    suite.expect(!called && brain.pendingRuntimePersistence.size() == 1,
                 "autonomous_admission_defers_provider_continuation");
    if (result == 2) ++brain.masterAuthorityEpoch;
    brain.finishRuntimePersistence(result != 0);
    suite.expect(called && accepted == (result == 1) && (accepted ? operation == oldNext : operation == 0),
                 "autonomous_admission_receipt_success_failure_stale");
    if (result == 0)
      suite.expect(brain.masterAuthorityRuntimeState.pendingAutonomousProvisioningOperations.empty() &&
                       brain.masterAuthorityRuntimeState.nextPendingAddMachinesOperationID == oldNext,
                   "autonomous_admission_failure_restores_current_candidate");
  }
  for (bool durable : {false, true})
  {
    TestBrain brain;
    uint64_t operation = 0;
    brain.journalAutonomousProvisioningOperationAsync(42, ApplicationLifetime::base, "schema"_ctv, 1,
      [&](bool, uint64_t id) { operation = id; });
    brain.holdRuntimePersistence = true;
    bool called = false, accepted = false;
    brain.settleAutonomousProvisioningOperationAsync(operation,
      [&](bool result) { called = true; accepted = result; });
    suite.expect(!called && brain.pendingRuntimePersistence.size() == 1,
                 "autonomous_settlement_defers_completion");
    brain.finishRuntimePersistence(durable);
    suite.expect(called && accepted == durable &&
                     brain.masterAuthorityRuntimeState.pendingAutonomousProvisioningOperations.empty() == durable,
                 "autonomous_settlement_receipt_or_restores_intent");
  }
  for (int result = 0; result < 3; ++result)
  {
    ScopedFreshRing ring;
    ResumableAddMachinesBrain brain;
    brain.weAreMaster = true; brain.noMasterYet = false; brain.ignited = true;
    brain.brainConfig.osUpdatesEnabled = true;
    brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, "apt-update"_ctv));
    Machine machine;
    seedOSUpdateMachine(brain, machine, "async-os"_ctv, MachineConfig::MachineKind::bareMetal,
                        0x8111, "22.04"_ctv);
    machine.neuron.wBuffer.clear();
    brain.holdRuntimePersistence = true;
    const MachineState previous = machine.state;
    brain.queueMachineOSUpdate(&machine);
    suite.expect(machine.neuron.wBuffer.empty() && brain.pendingRuntimePersistence.size() == 1,
                 "os_update_has_no_command_before_durable_receipt");
    if (result == 2) ++machine.neuron.ioGeneration;
    brain.finishRuntimePersistence(result != 0);
    suite.expect(machine.neuron.wBuffer.empty() == (result != 1),
                 "os_update_emits_command_only_for_durable_current_stream");
    if (result == 0) suite.expect(machine.state == previous && !machine.osUpdateCommandIssued,
                                 "os_update_failure_restores_current_candidate");
    brain.neurons.erase(&machine.neuron); brain.machinesByUUID.erase(machine.uuid); brain.machines.erase(&machine);
  }
  for (int result = 0; result < 3; ++result)
  {
    TestBrain brain; brain.holdRuntimePersistence = true;
    FailedDeploymentRecord record;
    record.deploymentID = 42; record.hasOperatorCancellation = true;
    record.operationID.assign("123e4567-e89b-42d3-a456-426614174021"_ctv);
    record.cancellationPhase = CancelDeploymentPhase::accepted;
    brain.failedDeployments.insert_or_assign(42, record);
    bool called = false, accepted = false;
    brain.persistAndReplicateOperatorCancellationAsync(brain.failedDeployments.at(42),
      [&](bool durable) { called = true; accepted = durable; });
    suite.expect(!called && brain.pendingCancellationPersistence.contains(42),
                 "cancellation_journal_waits_for_receipt");
    if (result == 2) ++brain.masterAuthorityEpoch;
    brain.finishRuntimePersistence(result != 0);
    suite.expect(result == 2 ? !called : (called && accepted == (result == 1)),
                 "cancellation_journal_failure_or_stale_cannot_release_effects");
    suite.expect(!brain.pendingCancellationPersistence.contains(42),
                 "cancellation_journal_receipt_releases_pending_slot");
  }
}
