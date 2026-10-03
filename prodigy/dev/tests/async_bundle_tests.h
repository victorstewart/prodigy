// Included after the shared Brain and bundle fixtures.
static void runAsyncBundleTests(TestSuite& suite)
{
  for (int outcome = 0; outcome < 3; ++outcome)
  {
    ScopedRing ring;
    TestBrain brain;
    brain.nBrains = 1;
    brain.weAreMaster = true;
    brain.noMasterYet = false;
    brain.holdRuntimePersistence = true;
    brain.updateSelfUseStagedBundleOnly = true;
    BrainView peer;
    peer.uuid = 0xabc1; peer.boottimens = 100;
    peer.connected = true; peer.isFixedFile = true; peer.fslot = 21;
    brain.brains.insert(&peer);
    brain.beginUpdateSelfBundle(1);
    suite.expect(brain.updateSelfBundleIssuedPeerKeys.empty() && brain.pendingRuntimePersistence.size() == 1,
                 "bundle_begin_waits_for_durable_receipt");
    // A heartbeat retry must respect the same held receipt.
    brain.queueUpdateSelfBundleToPeer(&peer);
    suite.expect(peer.wBuffer.empty(), "bundle_retry_cannot_bypass_receipt");
    if (outcome == 2) ++brain.masterAuthorityEpoch;
    brain.finishRuntimePersistence(outcome != 0);
    suite.expect(brain.updateSelfBundleIssuedPeerKeys.contains(peer.uuid) == (outcome == 1),
                 "bundle_begin_success_failure_stale");
    if (outcome == 1)
    {
      peer.pendingSend = false; peer.wBuffer.clear();
      brain.onUpdateSelfBundleEcho(&peer);
      suite.expect(brain.updateSelfTransitionIssuedPeerKeys.empty(), "follower_transition_waits_for_echo_receipt");
      brain.finishRuntimePersistence(true);
      suite.expect(brain.pendingRuntimePersistence.size() == 1 && brain.updateSelfTransitionIssuedPeerKeys.empty(),
                   "follower_transition_waits_for_phase_receipt");
      brain.finishRuntimePersistence(true);
      suite.expect(brain.updateSelfTransitionIssuedPeerKeys.contains(peer.uuid), "follower_transition_after_durable_phase");
    }
    brain.brains.erase(&peer);
  }
  {
    ScopedRing ring;
    TestBrain master;
    master.weAreMaster = true;
    master.noMasterYet = false;
    master.nBrains = 3;
    master.masterAuthorityRuntimeStateDurable = true;
    master.durableMasterAuthorityRuntimeStateGeneration = master.masterAuthorityRuntimeState.generation;
    master.updateSelfState = Brain::UpdateSelfState::waitingForFollowerReboots;
    master.updateSelfExpectedEchos = 2;

    Machine firstMachine = {}, secondMachine = {};
    firstMachine.uuid = 0xd101; secondMachine.uuid = 0xd102;
    BrainView first = {}, second = {};
    first.uuid = 0xd001; first.boottimens = 101; first.ioGeneration = 1; first.transportEpoch = 1;
    second.uuid = 0xd002; second.boottimens = 102; second.ioGeneration = 1; second.transportEpoch = 1;
    first.connected = second.connected = true;
    first.isFixedFile = second.isFixedFile = true;
    first.fslot = 41; second.fslot = 42;
    first.registrationFresh = second.registrationFresh = true;
    first.machine = &firstMachine; second.machine = &secondMachine;
    master.brains.insert(&first);
    master.brains.insert(&second);
    master.updateSelfFollowerBootNsByPeerKey.insert_or_assign(first.uuid, first.boottimens);
    master.updateSelfFollowerBootNsByPeerKey.insert_or_assign(second.uuid, second.boottimens);

    second.connected = false;
    suite.expect(master.hasConnectedBrainMajority(),
                 "serial_follower_transition_degraded_cluster_has_current_majority");
    master.queueUpdateSelfTransitionToPeer(&first);
    suite.expect(master.updateSelfTransitionIssuedPeerKeys.empty(),
                 "serial_follower_transition_preserves_majority_during_restart");
    second.connected = true;
    master.maybeQueueUpdateSelfFollowerTransition();
    suite.expect(master.updateSelfTransitionIssuedPeerKeys.size() == 1 &&
                     master.updateSelfTransitionIssuedPeerKeys.contains(first.uuid) &&
                     !master.updateSelfTransitionIssuedPeerKeys.contains(second.uuid),
                 "serial_follower_transition_issues_lowest_peer_only");
    master.queueUpdateSelfTransitionToPeer(&second);
    suite.expect(master.updateSelfTransitionIssuedPeerKeys.size() == 1,
                 "serial_follower_transition_reconnect_cannot_issue_second");
    master.holdRuntimePersistence = true;
    // A reconnect replaces the old transport, so its undrained write buffer
    // cannot continue to hold the retry path closed.
    first.pendingSend = false;
    first.wBuffer.clear();
    master.updateSelfFollowerReconnectedPeerKeys.insert(first.uuid);
    master.onUpdateSelfPeerRegistration(&first);
    suite.expect(master.updateSelfFollowerRebootedPeerKeys.empty() &&
                     master.updateSelfTransitionIssuedPeerKeys.empty() &&
                     master.pendingRuntimePersistence.size() == 1,
                 "serial_follower_transition_same_boot_reconnect_waits_for_retry_receipt");
    master.finishRuntimePersistence(true);
    // Persistence may publish the current authority state.  The retry is
    // allowed only after the replacement transport has completed that send.
    first.wBuffer.clear();
    first.clearQueuedSendBytes();
    first.pendingSend = false;
    master.maybeQueueUpdateSelfFollowerTransition();
    suite.expect(master.updateSelfFollowerRebootedPeerKeys.empty() &&
                     master.updateSelfTransitionIssuedPeerKeys.size() == 1 &&
                     master.updateSelfTransitionIssuedPeerKeys.contains(first.uuid) &&
                     !master.updateSelfTransitionIssuedPeerKeys.contains(second.uuid),
                 "serial_follower_transition_same_boot_reconnect_retries_only_prior_target");
    first.boottimens = 201;
    master.noteUpdateSelfFollowerReboot(&first, "test", 101);
    suite.expect(master.pendingRuntimePersistence.size() == 1 &&
                     !master.updateSelfTransitionIssuedPeerKeys.contains(second.uuid),
                 "serial_follower_transition_waits_for_reboot_receipt");
    master.finishRuntimePersistence(false);
    master.maybeQueueUpdateSelfFollowerTransition();
    suite.expect(!master.updateSelfTransitionIssuedPeerKeys.contains(second.uuid),
                 "serial_follower_transition_failed_receipt_fences_next");
    master.brains.erase(&first);
    master.brains.erase(&second);
  }
  {
    ScopedRing ring;
    TestBrain master;
    master.weAreMaster = true;
    master.noMasterYet = false;
    master.nBrains = 3;
    master.masterAuthorityRuntimeStateDurable = true;
    master.durableMasterAuthorityRuntimeStateGeneration = master.masterAuthorityRuntimeState.generation;
    master.updateSelfState = Brain::UpdateSelfState::waitingForFollowerReboots;
    master.updateSelfExpectedEchos = 2;

    Machine firstMachine = {}, secondMachine = {};
    firstMachine.uuid = 0xd201; secondMachine.uuid = 0xd202;
    BrainView first = {}, second = {};
    first.uuid = 0xd101; first.boottimens = 101; first.ioGeneration = 1; first.transportEpoch = 1;
    second.uuid = 0xd102; second.boottimens = 102; second.ioGeneration = 1; second.transportEpoch = 1;
    first.connected = second.connected = true;
    first.isFixedFile = second.isFixedFile = true;
    first.fslot = 51; second.fslot = 52;
    first.registrationFresh = second.registrationFresh = true;
    first.machine = &firstMachine; second.machine = &secondMachine;
    master.brains.insert(&first);
    master.brains.insert(&second);
    master.updateSelfFollowerBootNsByPeerKey.insert_or_assign(first.uuid, first.boottimens);
    master.updateSelfFollowerBootNsByPeerKey.insert_or_assign(second.uuid, second.boottimens);
    const String expectedDigest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
    master.updateSelfWorkerExpectedBundleSHA256 = expectedDigest;
    ProdigyPersistentUpdateSelfMachineRecoveryWitness firstRecoveryWitness = {};
    firstRecoveryWitness.machineUUID = firstMachine.uuid;
    ProdigyPersistentUpdateSelfMachineRecoveryWitness secondRecoveryWitness = {};
    secondRecoveryWitness.machineUUID = secondMachine.uuid;
    master.updateSelfMachineRecoveryWitnesses.push_back(std::move(firstRecoveryWitness));
    master.updateSelfMachineRecoveryWitnesses.push_back(std::move(secondRecoveryWitness));

    auto acknowledgeCurrentAuthority = [&](TestBrain& candidate, BrainView& peer) {
      String serialized = {}, digest = {};
      suite.require(candidate.serializeCurrentMasterAuthorityTransition(serialized, digest),
                    "serial_follower_transition_authority_digest");
      candidate.noteMasterAuthorityTransitionSentToPeer(&peer, candidate.masterAuthorityRuntimeState, digest);
      ProdigyMasterAuthorityStateTransitionAck acknowledgement = {};
      acknowledgement.generation = candidate.masterAuthorityRuntimeState.generation;
      acknowledgement.peerUUID = peer.uuid;
      acknowledgement.peerBootNs = peer.boottimens;
      acknowledgement.transitionDigest = digest;
      candidate.acknowledgeMasterAuthorityTransition(&peer, acknowledgement);
    };
    auto completePeerSend = [](BrainView& peer) {
      peer.wBuffer.clear();
      peer.clearQueuedSendBytes();
      peer.pendingSend = false;
    };

    master.maybeQueueUpdateSelfFollowerTransition();
    const ProdigyPersistentUpdateSelfState beforeFollowerRegistration =
        master.capturePersistentUpdateSelfState();
    // Model a new coordinator rather than calling the generic restore helper
    // in place: that helper is also used by live authority reconciliation and
    // rollback paths, where its transport-local send credits remain valid.
    master.brains.erase(&first);
    master.brains.erase(&second);
    first.pendingSend = false;
    first.wBuffer.clear();
    TestBrain recovered;
    recovered.weAreMaster = true;
    recovered.noMasterYet = false;
    recovered.nBrains = 3;
    recovered.masterAuthorityRuntimeStateDurable = true;
    recovered.durableMasterAuthorityRuntimeStateGeneration = recovered.masterAuthorityRuntimeState.generation;
    recovered.updateSelfExpectedEchos = 2;
    recovered.brains.insert(&first);
    recovered.brains.insert(&second);
    recovered.restorePersistentUpdateSelfState(beforeFollowerRegistration);
    first.boottimens = 201;
    recovered.onUpdateSelfPeerRegistration(&first);
    suite.expect(recovered.lastPersistedUpdateSelfState.followerRebootedPeerKeys.size() == 1 &&
                     recovered.lastPersistedUpdateSelfState.followerRebootedPeerKeys[0] == first.uuid,
                 "serial_follower_transition_persists_reboot_order");
    suite.expect(recovered.updateSelfFollowerRebootedPeerKeys.contains(first.uuid) &&
                     recovered.updateSelfTransitionIssuedPeerKeys.empty(),
                 "serial_follower_transition_restore_retries_only_next_peer");
    acknowledgeCurrentAuthority(recovered, first);
    acknowledgeCurrentAuthority(recovered, second);
    completePeerSend(first);
    completePeerSend(second);
    recovered.maybeQueueUpdateSelfFollowerTransition();
    suite.expect(!recovered.updateSelfTransitionIssuedPeerKeys.contains(second.uuid),
                 "serial_follower_transition_waits_for_runtime_inventory");
    recovered.queueUpdateSelfTransitionToPeer(&second);
    suite.expect(!recovered.updateSelfTransitionIssuedPeerKeys.contains(second.uuid),
                 "serial_follower_transition_direct_reconnect_path_waits_for_runtime_inventory");
    firstMachine.runtimeReady = true;
    recovered.persistedMachineInventoryUploaded.insert(firstMachine.uuid);
    recovered.maybeQueueUpdateSelfFollowerTransition();
    suite.expect(!recovered.updateSelfTransitionIssuedPeerKeys.contains(second.uuid),
                 "serial_follower_transition_missing_digest_attestation_fences_next");
    auto *firstWitness = recovered.findUpdateSelfMachineRecoveryWitness(firstMachine.uuid);
    suite.require(firstWitness != nullptr, "serial_follower_transition_first_machine_witness_present");
    firstWitness->bundleRegistered = true; // an earlier matching registration
    suite.expect(recovered.noteLocalBundleRegistration(&firstMachine,
                                                     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv) == false &&
                     firstWitness->bundleRegistered == false,
                 "serial_follower_transition_stale_digest_credit_revoked");
    acknowledgeCurrentAuthority(recovered, first);
    acknowledgeCurrentAuthority(recovered, second);
    completePeerSend(first);
    completePeerSend(second);
    recovered.maybeQueueUpdateSelfFollowerTransition();
    suite.expect(!recovered.updateSelfTransitionIssuedPeerKeys.contains(second.uuid),
                 "serial_follower_transition_mismatched_digest_fences_next");
    suite.expect(recovered.noteLocalBundleRegistration(&firstMachine, expectedDigest) &&
                     firstWitness->bundleRegistered,
                 "serial_follower_transition_matching_digest_attests_canonical_machine");
    acknowledgeCurrentAuthority(recovered, first);
    acknowledgeCurrentAuthority(recovered, second);
    completePeerSend(first);
    completePeerSend(second);
    recovered.maybeQueueUpdateSelfFollowerTransition();
    suite.expect(recovered.updateSelfTransitionIssuedPeerKeys.contains(second.uuid),
                 "serial_follower_transition_advances_after_fresh_inventory_matching_digest_and_ack");
    recovered.queueUpdateSelfTransitionToPeer(&first);
    suite.expect(recovered.updateSelfTransitionIssuedPeerKeys.size() == 1 &&
                     recovered.updateSelfTransitionIssuedPeerKeys.contains(second.uuid),
                 "serial_follower_transition_reconnect_does_not_reissue_completed_peer");
    recovered.maybeRelinquishMasterForUpdateSelf();
    suite.expect(recovered.updateSelfState == Brain::UpdateSelfState::waitingForFollowerReboots,
                 "serial_follower_transition_no_master_handoff_before_all_ready");

    second.boottimens = 202;
    secondMachine.runtimeReady = true;
    recovered.persistedMachineInventoryUploaded.insert(secondMachine.uuid);
    recovered.noteUpdateSelfFollowerReboot(&second, "test", 102);
    auto *secondWitness = recovered.findUpdateSelfMachineRecoveryWitness(secondMachine.uuid);
    suite.require(secondWitness != nullptr, "serial_follower_transition_second_machine_witness_present");
    suite.expect(recovered.noteLocalBundleRegistration(&secondMachine, expectedDigest) &&
                     secondWitness->bundleRegistered,
                 "serial_follower_transition_second_matching_digest_attests_canonical_machine");
    acknowledgeCurrentAuthority(recovered, first);
    acknowledgeCurrentAuthority(recovered, second);
    completePeerSend(first);
    completePeerSend(second);
    recovered.maybeRelinquishMasterForUpdateSelf();
    suite.expect(recovered.updateSelfState == Brain::UpdateSelfState::waitingForRelinquishEchos,
                 "serial_follower_transition_master_handoff_after_all_ready");
    recovered.brains.erase(&first);
    recovered.brains.erase(&second);
  }
  for (int outcome = 0; outcome < 3; ++outcome)
  {
    TestBrain brain;
    brain.holdRuntimePersistence = true;
    Machine worker;
    worker.uuid = 0xbb01; worker.neuron.machine = &worker;
    brain.machines.insert(&worker);
    brain.machinesByUUID.insert_or_assign(worker.uuid, &worker);
    brain.updateSelfWorkerMachineUUIDs.insert(worker.uuid);
    brain.updateSelfWorkerStagedMachineUUIDs.insert(worker.uuid);
    brain.queueWorkerBundleTransitionIfReady();
    suite.expect(worker.neuron.wBuffer.empty() && brain.pendingRuntimePersistence.size() == 1,
                 "worker_exec_command_waits_for_receipt");
    brain.queueWorkerBundleTransitionIfReady();
    suite.expect(worker.neuron.wBuffer.empty(), "worker_exec_retry_cannot_bypass_receipt");
    if (outcome == 2) ++brain.masterAuthorityEpoch;
    brain.finishRuntimePersistence(outcome != 0);
    suite.expect(!worker.neuron.wBuffer.empty() == (outcome == 1), "worker_exec_success_failure_stale");
    if (outcome == 1)
    {
      brain.updateSelfWorkerRebootedMachineUUIDs.insert(worker.uuid);
      brain.noteWorkerStateUpload(&worker.neuron);
      suite.expect(worker.inBinaryUpdate && brain.pendingRuntimePersistence.size() == 1,
                   "worker_inventory_keeps_exec_fence_until_durable");
      brain.finishRuntimePersistence(true);
      suite.expect(!worker.inBinaryUpdate, "worker_inventory_receipt_releases_exec_fence");
    }
    brain.machines.erase(&worker);
  }
  for (int outcome = 0; outcome < 3; ++outcome)
  {
    ScopedRing ring;
    TestBrain brain;
    brain.weAreMaster = true; brain.noMasterYet = false; brain.nBrains = 1;
    brain.holdRuntimePersistence = true;
    brain.updateSelfState = Brain::UpdateSelfState::waitingForRelinquishEchos;
    brain.updateSelfExpectedEchos = 1;
    brain.updateSelfPlannedMasterPeerKey = 0xcc01;
    BrainView peer; peer.uuid = 0xcc01; peer.boottimens = 100;
    brain.brains.insert(&peer);
    brain.onUpdateSelfRelinquishEcho(&peer);
    suite.expect(brain.weAreMaster && brain.transitionToNewBundleCalls == 0 && brain.pendingRuntimePersistence.size() == 1,
                 "final_relinquish_waits_for_echo_receipt");
    if (outcome == 2) ++brain.masterAuthorityEpoch;
    brain.finishRuntimePersistence(outcome != 0);
    if (outcome == 1)
    {
      suite.expect(!brain.weAreMaster && brain.transitionToNewBundleCalls == 0 && brain.pendingRuntimePersistence.size() == 1,
                   "final_relinquish_waits_for_handoff_receipt");
      brain.finishRuntimePersistence(true);
    }
    suite.expect(brain.transitionToNewBundleCalls == (outcome == 1 ? 1 : 0), "final_relinquish_success_failure_stale");
    brain.brains.erase(&peer);
  }
}
