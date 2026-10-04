#pragma once

static void testPairedSourceRetirementWireContract(TestSuite& suite)
{
  ProdigyPairedSourceRetirementRequest request = {};
  request.operationID = uint128_t(0x71);
  request.sourceClusterUUID = uint128_t(0x72);
  request.targetClusterUUID = uint128_t(0x73);
  request.sourceDeploymentID = (uint64_t(62'010) << 48) | 4;
  request.targetDeploymentID = (uint64_t(62'011) << 48) | 5;
  request.expectedAuthorityGeneration = 9;
  request.expectedMasterUUID = uint128_t(0x74);
  request.expectedMasterBootNs = 10;
  request.sourceNormalizedPlanSHA256.assign("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv);
  request.sourceBlobSHA256.assign("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"_ctv);
  request.sourceBlobBytes = 4096;
  String encoded = {};
  BitseryEngine::serialize(encoded, request);
  ProdigyPairedSourceRetirementRequest decoded = {};
  suite.expect(prodigyPairedSourceRetirementRequestValid(request) &&
                   BitseryEngine::deserializeSafe(encoded, decoded) &&
                   decoded.operationID == request.operationID &&
                   decoded.expectedMasterUUID == request.expectedMasterUUID,
               "paired_source_retirement_request_roundtrip_binds_fresh_authority_identity");
  decoded.targetDeploymentID = request.sourceDeploymentID;
  suite.expect(prodigyPairedSourceRetirementRequestValid(decoded),
               "paired_source_retirement_request_allows_independent_cluster_deployment_id_coincidence");
  encoded.append(uint8_t(0));
  suite.expect(BitseryEngine::deserializeSafe(encoded, decoded) == false,
               "paired_source_retirement_request_rejects_trailing_bytes");
  request.sourceNormalizedPlanSHA256.assign("not-a-digest"_ctv);
  request.expectedMasterBootNs = -1;
  suite.expect(!prodigyPairedSourceRetirementRequestValid(request),
               "paired_source_retirement_request_requires_sha_and_positive_boot_identity");
}

static void testPairedSourceRetirementLaunchFence(TestSuite& suite)
{
  StreamingTestBrain brain = {};
  ProdigyContainerRetirementJournal journal = {};
  journal.version = ProdigyContainerRetirementJournal::currentVersion;
  ProdigyContainerRetirementIntent intent = {};
  intent.containerUUID = uint128_t(0x801); intent.machineUUID = uint128_t(0x802);
  intent.deploymentID = (uint64_t(1) << 48) | 0x803; intent.applicationID = 1; intent.intentGeneration = 2;
  intent.kind = ProdigyContainerRetirementKind::statelessPairedMigration;
  intent.pairedOperationID = uint128_t(0x804); intent.pairedSourceClusterUUID = uint128_t(0x805);
  intent.pairedTargetClusterUUID = uint128_t(0x806); intent.pairedTargetDeploymentID = 0x807;
  intent.killAcked = true;
  journal.intents.push_back(intent);
  ProdigyPairedSourceRetirementFence fence = {};
  fence.operationID = intent.pairedOperationID; fence.sourceClusterUUID = intent.pairedSourceClusterUUID;
  fence.targetClusterUUID = intent.pairedTargetClusterUUID; fence.sourceDeploymentID = intent.deploymentID;
  fence.targetDeploymentID = intent.pairedTargetDeploymentID; fence.sourceBlobBytes = 4096;
  fence.sourceNormalizedPlanSHA256.assign("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv);
  fence.sourceBlobSHA256.assign("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"_ctv);
  fence.cohort.push_back({intent.containerUUID, intent.machineUUID, intent.intentGeneration});
  journal.pairedSourceFences.push_back(fence);
  suite.expect(prodigyStoreContainerRetirementJournalCarrier(brain.masterAuthorityRuntimeState.taskExecutions, journal, 1) &&
               brain.pairedSourceRetirementLaunchFenced(intent.deploymentID) &&
               !brain.pairedSourceRetirementLaunchFenced(intent.deploymentID + 1),
               "paired_source_retirement_fence_blocks_only_sealed_source_deployment_after_restore");
  BrainReplicatedContainerRuntimeState unexpected = {};
  unexpected.plan.uuid = uint128_t(0x899);
  unexpected.plan.config.applicationID = 1;
  unexpected.plan.config.versionID = 0x803;
  suite.expect(brain.applyReplicatedContainerRuntimeStateNow(unexpected) ==
                   StreamingTestBrain::ReplicatedContainerRuntimeStateApplyResult::rejected,
               "paired_source_retirement_fence_rejects_fresh_uuid_runtime_ingress");


}

static ProdigyPairedSourceRetirementRequest pairedSourceRetirementBehaviorRequest(
    const StreamingTestBrain& brain, uint128_t operationID)
{
  ProdigyPairedSourceRetirementRequest request = {};
  request.operationID = operationID;
  request.sourceClusterUUID = brain.brainConfig.clusterUUID;
  request.targetClusterUUID = uint128_t(0x9901);
  request.sourceDeploymentID = (uint64_t(1) << 48) | 0x901;
  request.targetDeploymentID = (uint64_t(2) << 48) | 0x902;
  request.expectedAuthorityGeneration = brain.masterAuthorityRuntimeState.generation;
  request.expectedMasterUUID = brain.getExistingMasterUUID();
  request.expectedMasterBootNs = request.expectedMasterUUID == brain.selfBrainUUID() ? brain.boottimens : 0;
  request.sourceNormalizedPlanSHA256.assign("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv);
  request.sourceBlobSHA256.assign("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"_ctv);
  request.sourceBlobBytes = 4096;
  return request;
}

static void testPairedSourceRetirementPrepareGuards(TestSuite& suite)
{
  StreamingTestBrain brain = {};
  TestNeuron self = {};
  ScopedStatelessAdmissionBehaviorIdentity identity(brain, self, uint128_t(0x9911));
  Mothership mothership = {};
  initializeStatelessAdmissionBehaviorFixture(brain, mothership, uint128_t(0x9922));
  brain.nBrains = 2; // commissioned topology has no current v3-reader ACK.
  const auto request = pairedSourceRetirementBehaviorRequest(brain, uint128_t(0x9933));
  PairedSourceRetirementReceipt receipt = {};
  const auto before = brain.masterAuthorityRuntimeState.taskExecutions;
  suite.expect(!brain.preparePairedSourceRetirement(request, receipt) && !receipt.peersCapable &&
                   receipt.failure.size() > 0 && brain.masterAuthorityRuntimeState.taskExecutions == before,
               "paired_source_retirement_old_reader_blocks_prepare_without_journal_effect");

  auto stale = request;
  stale.expectedAuthorityGeneration += 1;
  receipt = {};
  suite.expect(!brain.preparePairedSourceRetirement(stale, receipt) && receipt.failure.size() > 0 &&
                   brain.masterAuthorityRuntimeState.taskExecutions == before,
               "paired_source_retirement_stale_authority_tuple_rejects_without_journal_effect");
}

static void testPairedSourceRetirementDurabilityAndPeerAck(TestSuite& suite)
{
  ScopedAsyncMothershipRing ring = {};
  StreamingTestBrain brain = {};
  TestNeuron self = {};
  ScopedStatelessAdmissionBehaviorIdentity identity(brain, self, uint128_t(0x9941));
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  Mothership mothership = {};
  ScopedStatelessAdmissionBehaviorArtifactIO artifactIO(brain, mothership);
  initializeStatelessAdmissionBehaviorFixture(brain, mothership, uint128_t(0x9942));
  BrainView peer = {};
  if (!addStatelessAdmissionBehaviorAuthenticatedPeer(suite, brain, peer, uint128_t(0x9943), 101)) return;
  peer.pairedSourceRetirementCapabilityAcknowledged = true;
  DeploymentPlan plan = statelessAdmissionBehaviorPlan(62012);
  String artifact = {}, failure = {};
  if (!suite.require(loadStatelessAdmissionBehaviorArtifact(artifact, failure), "paired_retirement_real_app_artifact"))
  { brain.brains.erase(&peer); ProdigyTransportTLSRuntime::clear(); return; }
  prodigyComputeSHA256Hex(artifact, plan.config.containerBlobSHA256);
  plan.config.containerBlobBytes = artifact.size();
  ApplicationDeployment deployment = {};
  deployment.plan = plan; deployment.state = DeploymentState::running;
  deployment.nTargetBase = 1; deployment.nDeployedBase = 1; deployment.nHealthyBase = 1;
  Machine machine = {};
  machine.uuid = self.uuid;
  machine.state = MachineState::healthy;
  machine.runtimeReady = true;
  machine.neuron.machine = &machine;
  machine.neuron.connected = true;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 2;
  machine.neuron.pendingSend = true;
  ContainerView *container = new ContainerView;
  container->uuid = uint128_t(0x9944); container->machine = &machine;
  container->applicationID = plan.config.applicationID; container->deploymentID = plan.config.deploymentID();
  container->lifetime = ApplicationLifetime::base;
  container->state = ContainerState::healthy; container->runtimeReady = true;
  const uint128_t containerUUID = container->uuid;
  const uint64_t deploymentID = container->deploymentID;
  deployment.containers.insert(container);
  machine.upsertContainerIndexEntry(deploymentID, container);
  brain.deployments.insert_or_assign(deploymentID, &deployment);
  brain.deploymentPlans.insert_or_assign(deploymentID, plan);
  brain.containers.insert_or_assign(containerUUID, container);
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);
  auto request = pairedSourceRetirementBehaviorRequest(brain, uint128_t(0x9945));
  request.sourceDeploymentID = deploymentID;
  request.sourceBlobSHA256 = plan.config.containerBlobSHA256; request.sourceBlobBytes = artifact.size();
  String encoded = {}; BitseryEngine::serialize(encoded, plan);
  prodigyComputeSHA256Hex(encoded, request.sourceNormalizedPlanSHA256);
  acknowledgeStatelessAdmissionBehaviorAuthority(brain, peer);
  const auto before = brain.masterAuthorityRuntimeState.taskExecutions;
  PairedSourceRetirementReceipt receipt = {};
  auto wrongPlan = request; wrongPlan.sourceNormalizedPlanSHA256[0] = wrongPlan.sourceNormalizedPlanSHA256[0] == '0' ? '1' : '0';
  suite.expect(!brain.preparePairedSourceRetirement(wrongPlan, receipt) && !receipt.failure.empty() &&
               brain.masterAuthorityRuntimeState.taskExecutions == before,
               "paired_retirement_mismatched_plan_has_no_effect");
  peer.pairedSourceRetirementCapabilityAcknowledged = false;
  suite.expect(!brain.preparePairedSourceRetirement(request, receipt) && !receipt.peersCapable &&
               brain.masterAuthorityRuntimeState.taskExecutions == before,
               "paired_retirement_missing_current_reader_ack_has_no_effect");
  peer.pairedSourceRetirementCapabilityAcknowledged = true;
  brain.holdRuntimePersistence = true;
  (void)brain.preparePairedSourceRetirement(request, receipt);
  const bool prepared = brain.pendingRuntimePersistence.size() == 1 && receipt.failure.empty();
  suite.expect(prepared && container->state == ContainerState::healthy && container->runtimeReady &&
               machine.neuron.wBuffer.empty() && !brain.reconcileContainerRetirements(),
               "paired_retirement_held_persistence_preserves_source_and_blocks_kills");
  if (prepared)
  {
    brain.quarantineReplicatedContainerRetirements();
    suite.expect(container->state == ContainerState::healthy && container->runtimeReady,
                 "paired_retirement_replication_apply_cannot_infer_global_ack");
    const auto plannedBefore = deployment.toSchedule.size();
    deployment.recoverAfterReboot();
    suite.expect(deployment.toSchedule.size() == plannedBefore && deployment.containers.size() == 1,
                 "paired_retirement_recovery_cannot_allocate_replacement_uuid");
    brain.finishRuntimePersistence(false);
    suite.expect(!brain.reconcileContainerRetirements() && container->state == ContainerState::healthy &&
                 machine.neuron.wBuffer.empty(), "paired_retirement_failed_persistence_preserves_source");
    brain.retryMasterAuthorityRuntimeStatePersistence();
    brain.finishRuntimePersistence(true);
    brain.holdRuntimePersistence = false;
    suite.expect(!brain.reconcileContainerRetirements() && container->state == ContainerState::healthy &&
                 machine.neuron.wBuffer.empty(), "paired_retirement_durable_without_all_peer_ack_preserves_source");
    request.expectedAuthorityGeneration = brain.masterAuthorityRuntimeState.generation;
    suite.expect(!brain.preparePairedSourceRetirement(request, receipt) && !receipt.sealed &&
                 !receipt.sealedFence.empty() && receipt.failure.empty(), "paired_retirement_same_operation_pending_retry");
    acknowledgeStatelessAdmissionBehaviorAuthority(brain, peer);
    suite.expect(brain.preparePairedSourceRetirement(request, receipt) && receipt.sealed && !receipt.terminal,
                 "paired_retirement_exact_ack_seals_existing_cohort_without_claiming_terminal");
    auto conflict = request; ++conflict.targetDeploymentID;
    suite.expect(!brain.preparePairedSourceRetirement(conflict, receipt) && !receipt.failure.empty(),
                 "paired_retirement_conflicting_retry_rejects_sealed_identity");

    machine.neuron.wBuffer.clear();
    bool dispatchPending = !brain.reconcileContainerRetirements();
    uint32_t killFrames = 0;
    bool exactKill = false;
    auto observeKill = [&] {
      forEachMessageInBuffer(machine.neuron.wBuffer, [&](Message *message) {
        if (NeuronTopic(message->topic) != NeuronTopic::killContainer) return;
        uint8_t *args = message->args;
        uint128_t queuedUUID = 0;
        Message::extractArg<ArgumentNature::fixed>(args, queuedUUID);
        ++killFrames;
        exactKill = exactKill || queuedUUID == containerUUID;
      });
    };
    observeKill();
    // Ordinary destruction can first queue route teardown.  Once that queue is
    // consumed, the same retirement reconciliation owns the Neuron kill.
    if (!exactKill)
    {
      machine.neuron.wBuffer.clear();
      dispatchPending = !brain.reconcileContainerRetirements() && dispatchPending;
      observeKill();
    }
    suite.expect(dispatchPending && container->state == ContainerState::destroying &&
                 deployment.containers.empty() && deployment.waitingOnContainers.contains(container) &&
                 killFrames == 1 && exactKill,
                 "paired_retirement_exact_ack_dispatches_one_authorized_kill");

    machine.neuron.wBuffer.clear();
    brain.holdRuntimePersistence = true;
    String terminalFrame = {};
    brain.neuronHandler(&machine.neuron, buildNeuronMessage(terminalFrame, NeuronTopic::killContainer, containerUUID));
    ProdigyContainerRetirementJournal terminalJournal = {};
    const auto *pendingIntent = brain.decodeContainerRetirementJournal(brain.masterAuthorityRuntimeState, terminalJournal)
                                        ? prodigyFindContainerRetirementIntentInValidatedJournal(terminalJournal, containerUUID)
                                        : nullptr;
    suite.expect(pendingIntent != nullptr && pendingIntent->killAcked && pendingIntent->bootstrap.empty() &&
                 brain.pendingRuntimePersistence.size() == 1 && brain.containers.contains(containerUUID),
                 "paired_retirement_terminal_ack_waits_for_durable_journal_before_object_destruction");
    brain.finishRuntimePersistence(true);
    brain.holdRuntimePersistence = false;
    terminalJournal = {};
    const auto *durableIntent = brain.decodeContainerRetirementJournal(brain.masterAuthorityRuntimeState, terminalJournal)
                                        ? prodigyFindContainerRetirementIntentInValidatedJournal(terminalJournal, containerUUID)
                                        : nullptr;
    request.expectedAuthorityGeneration = brain.masterAuthorityRuntimeState.generation;
    PairedSourceRetirementReceipt terminalReceipt = {};
    const bool terminalBeforePeerAck = brain.preparePairedSourceRetirement(request, terminalReceipt);
    suite.expect(durableIntent != nullptr && durableIntent->killAcked && durableIntent->bootstrap.empty() &&
                 brain.masterAuthorityRuntimeStateDurable && !terminalBeforePeerAck && !terminalReceipt.terminal &&
                 !brain.reconcileContainerRetirements() && brain.containers.contains(containerUUID),
                 "paired_retirement_durable_terminal_ack_requires_current_peer_ack_before_source_destruction");
    acknowledgeStatelessAdmissionBehaviorAuthority(brain, peer);
    const bool terminalAfterPeerAck = brain.preparePairedSourceRetirement(request, terminalReceipt);
    suite.expect(terminalAfterPeerAck && terminalReceipt.sealed && terminalReceipt.terminal &&
                 brain.reconcileContainerRetirements() &&
                 !brain.containers.contains(containerUUID) && deployment.waitingOnContainers.empty() &&
                 deployment.nHealthyBase == 0,
                 "paired_retirement_durable_terminal_ack_removes_source_without_healthy_count");
  }
  if (auto live = brain.containers.find(containerUUID); live != brain.containers.end() && live->second != nullptr)
  {
    ContainerView *remaining = live->second;
    brain.containers.erase(containerUUID);
    deployment.containers.erase(remaining);
    deployment.waitingOnContainers.erase(remaining);
    machine.removeContainerIndexEntry(deploymentID, remaining);
    delete remaining;
  }
  brain.neurons.erase(&machine.neuron); brain.machinesByUUID.erase(machine.uuid); brain.machines.erase(&machine);
  brain.deployments.erase(deploymentID);
  deployment.containers.clear(); deployment.waitingOnContainers.clear();
  brain.brains.erase(&peer); ProdigyTransportTLSRuntime::clear();
}
