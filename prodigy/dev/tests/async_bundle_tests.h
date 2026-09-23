// Included after the shared Brain and bundle fixtures.
static void runAsyncBundleTests(TestSuite& suite)
{
  for (int outcome = 0; outcome < 3; ++outcome)
  {
    ScopedRing ring;
    TestBrain brain;
    brain.nBrains = 1;
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
