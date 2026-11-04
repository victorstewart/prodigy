// Uses the same admissible three-member deployment shape as the existing lifecycle test.
static void testAsyncMaterializedRecoveryAcceptance(TestSuite& suite)
{
 for (bool isRetry : {false, true}) for (int result = 0; result < 3; ++result)
 {
  ScopedRing scopedRing;
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.ignited = true;
  BrainBase *savedBrain = thisBrain;
  thisBrain = &brain;
  constexpr uint16_t applicationID = 63112;
  String name = "materialized-recovery-test"_ctv;
  brain.reservedApplicationIDsByName.insert_or_assign(name, applicationID);
  brain.reservedApplicationNamesByID.insert_or_assign(applicationID, name);
  auto *active = new ApplicationDeployment();
  auto *successor = new ApplicationDeployment();
  active->plan = makeDeploymentPlan(applicationID, 201);
  active->plan.config.type = ApplicationType::stateful;
  active->plan.isStateful = true;
  active->plan.canaryCount = 0;
  active->plan.config.nLogicalCores = 1;
  active->plan.config.memoryMB = 64;
  active->plan.config.storageMB = 256;
  active->plan.stateful.allowUpdateInPlace = true;
  active->state = DeploymentState::none;
  active->nShardGroups = 1;
  active->nTargetBase = active->nDeployedBase = 3;
  active->nHealthyBase = 1;
  successor->plan = active->plan;
  successor->plan.config.versionID = 202;
  successor->plan.config.containerBlobSHA256.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
  successor->state = DeploymentState::waitingToDeploy;
  active->next = successor;
  successor->previous = active;
  const uint64_t activeID = active->plan.config.deploymentID();
  const uint64_t successorID = successor->plan.config.deploymentID();
  brain.deployments.insert_or_assign(activeID, active);
  brain.deployments.insert_or_assign(successorID, successor);
  brain.deploymentsByApp.insert_or_assign(applicationID, successor);
  Machine machines[3] = {};
  ContainerView containers[3] = {};
  for (uint32_t index = 0; index < 3; ++index)
  {
    Machine& machine = machines[index];
    machine.uuid = 0x7b1000 + index;
    machine.state = MachineState::healthy;
    machine.runtimeReady = true;
    machine.ownedLogicalCores = 4;
    machine.memoryMB_available = 4096;
    machine.storageMB_available = 4096;
    prodigyRecomputeMachineCPUAvailability(&machine, prodigyActiveSharedCPUOvercommitPermille());
    machine.neuron.isFixedFile = true;
    machine.neuron.fslot = 20 + index;
    machine.neuron.connected = true;
    ContainerView& container = containers[index];
    container.uuid = 0x7b2000 + index;
    container.deploymentID = activeID;
    container.applicationID = applicationID;
    container.isStateful = true;
    container.lifetime = ApplicationLifetime::base;
    container.shardGroup = 0;
    container.machine = &machine;
    container.state = index == 0 ? ContainerState::healthy : ContainerState::scheduled;
    active->containers.insert(&container);
    brain.containers.insert_or_assign(container.uuid, &container);
  }
  suite.expect(active->recoveredMaterializedStatefulRollForwardIsSafe(),
               "materialized_recovery_request_fixture_is_admissible");
  RecoverMaterializedStatefulDeployment request = {};
  request.applicationName = name;
  request.applicationID = applicationID;
  request.activeVersionID = 201;
  request.successorVersionID = 202;
  request.operationID.assign("123e4567-e89b-42d3-a456-426614174010"_ctv);
  request.successorBlobSHA256 = successor->plan.config.containerBlobSHA256;
  Mothership mothership = {};
  mothership.isFixedFile = true; mothership.fslot = 27;
  brain.activeMotherships.insert(&mothership);
  if (isRetry)
  {
    ProdigyMaterializedStatefulRecoveryOperation admitted;
    admitted.operationID = request.operationID;
    admitted.activeDeploymentID = activeID; admitted.successorDeploymentID = successorID;
    admitted.successorBlobSHA256 = request.successorBlobSHA256;
    admitted.accepted = admitted.started = true;
    brain.masterAuthorityRuntimeState.materializedStatefulRecoveryOperations.push_back(admitted);
  successor->containers.clear();
  active->containers.erase(&containers[2]);
  successor->state = DeploymentState::failed;
  successor->materializedStatefulRecoveryOwnsTransition = true;
  successor->materializedStatefulRecoveryHealthFailed = true;
  brain.machines.insert(&machines[2]);
  brain.containers.erase(containers[2].uuid);
  containers[0].state = ContainerState::scheduled;
  active->nHealthyBase = 0;
  auto retry = request;
  retry.retryFailedSuccessor = true;
  retry.replacementSuccessorVersionID = 203;
  retry.replacementSuccessorBlobSHA256.assign("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv);
  retry.sourceContainerUUID = uint128_t(0x7b4001);
  retry.failedSuccessorContainerUUID = uint128_t(0x7b4002);
  retry.sourceMachineUUID = machines[2].uuid;
  retry.sourceDevice = 56;
  retry.sourceInode = 265;
  retry.sourceUID = 12517185;
  retry.sourceGID = 12517185;
  retry.sourcePID = 42;
  retry.captureSHA256.assign("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"_ctv);
    request = retry;
  }
  brain.holdRuntimePersistence = true;
  String payload, frame;
  BitseryEngine::serialize(payload, request);
  brain.mothershipHandler(&mothership,
      buildMothershipMessage(frame, MothershipTopic::recoverMaterializedStatefulDeployment, payload));
  suite.expect(mothership.wBuffer.empty() && brain.pendingRuntimePersistence.size() == 1,
               isRetry ? "recovery_retry_awaits_receipt" : "recovery_acceptance_awaits_receipt");
  brain.recoverDeploymentsAfterNeuronState();
  suite.expect(successor->toSchedule.empty() && successor->containers.empty(),
               "pending_recovery_acceptance_cannot_start_from_another_callback");
  if (result == 2) ++brain.masterAuthorityEpoch;
  brain.finishRuntimePersistence(result != 0);
  if (result == 2)
    suite.expect(mothership.wBuffer.empty(), "stale_recovery_receipt_cannot_acknowledge");
  else
  {
    RecoverMaterializedStatefulDeployment response;
    suite.expect(extractAsyncRequestResponse(mothership.wBuffer,
        MothershipTopic::recoverMaterializedStatefulDeployment, response) && response.success == (result == 1) &&
        response.operationID.equals(request.operationID),
        isRetry ? "recovery_retry_receipt_response" : "recovery_acceptance_receipt_response");
  }
  if (result == 0)
    suite.expect(isRetry ? brain.masterAuthorityRuntimeState.materializedStatefulRecoveryRetries.empty() :
                          brain.masterAuthorityRuntimeState.materializedStatefulRecoveryOperations.empty(),
                 "failed_recovery_receipt_restores_only_its_candidate");
  brain.activeMotherships.erase(&mothership);
  brain.containers.clear(); brain.machines.clear();
  active->containers.clear(); successor->containers.clear();
  brain.deployments.clear(); brain.deploymentsByApp.clear();
  active->next = nullptr; successor->previous = nullptr;
  delete successor; delete active; thisBrain = savedBrain;
 }
}

static void testAsyncLocalBundleRecoveryWitnessRepair(TestSuite& suite)
{
  ScopedFreshRing ring = {};
  StreamingTestBrain brain = {};
  NoopBrainIaaS iaas = {};
  TestNeuron self = {};
  BrainBase *savedBrain = thisBrain;
  NeuronBase *savedNeuron = thisNeuron;
  thisBrain = &brain;
  thisNeuron = &self;
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.ignited = true;
  brain.nBrains = 3;
  brain.masterAuthorityEpoch = 17;
  brain.boottimens = 700'100'001;
  brain.masterAuthorityRuntimeState.generation = 51;
  brain.masterAuthorityRuntimeState.hasCompletedInitialMasterElection = true;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = 51;
  brain.hasAuthoritativeTopology = true;
  brain.brainConfig.clusterUUID = uint128_t(0x7300);
  const String installedBundle =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv;
  self.uuid = uint128_t(0x7301);
  self.setInstalledBundleDigestForTest(installedBundle);

  Machine machines[3] = {};
  ScopedSocketPair neuronSockets[3] = {};
  const uint128_t machineUUIDs[3] = {
      self.uuid, uint128_t(0x7302), uint128_t(0x7303)};
  bool fixtureReady = true;
  for (uint32_t index = 0; index < 3; ++index)
  {
    fixtureReady = neuronSockets[index].create(
        suite, "local_bundle_witness_repair_neuron_control_socket") && fixtureReady;
    Machine& machine = machines[index];
    machine.uuid = machineUUIDs[index];
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;
    machine.isBrain = true;
    machine.isThisMachine = index == 0;
    machine.runtimeReady = true;
    machine.storageMB_available = 8192;
    machine.neuron.machine = &machine;
    machine.neuron.isFixedFile = true;
    machine.neuron.fslot = neuronSockets[index].adoptLeftIntoFixedFileSlot();
    machine.neuron.connected = machine.neuron.fslot >= 0;
    brain.machines.insert(&machine);
    brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
    brain.persistedMachineInventoryUploaded.insert(machine.uuid);
    brain.persistedMachineStateUploadPlansByMachine.insert_or_assign(
        machine.uuid, Vector<String>{});
    ClusterMachine topologyMember = {};
    topologyMember.uuid = machine.uuid;
    topologyMember.isBrain = true;
    brain.authoritativeTopology.machines.push_back(topologyMember);

    ProdigyPersistentUpdateSelfMachineRecoveryWitness witness = {};
    witness.machineUUID = machine.uuid;
    witness.bundleRegistered = true;
    brain.updateSelfMachineRecoveryWitnesses.push_back(std::move(witness));
    fixtureReady = machine.neuron.connected && fixtureReady;
  }
  brain.updateSelfWorkerExpectedBundleSHA256.assign(installedBundle);
  brain.masterAuthorityRuntimeState.updateSelf = brain.capturePersistentUpdateSelfState();
  suite.require(fixtureReady, "local_bundle_witness_repair_arms_exact_machine_cohort");

  BrainView peers[2] = {};
  ProdigyTransportTLSStream peerTransports[2] = {};
  std::array<uint8_t, 32> peerPSK = {};
  peerPSK.fill(0x73);
  for (uint32_t index = 0; index < 2; ++index)
  {
    BrainView& peer = peers[index];
    peer.uuid = machineUUIDs[index + 1];
    peer.machine = &machines[index + 1];
    peer.boottimens = 730'000'010 + index;
    peer.ioGeneration = 1;
    peer.transportEpoch = 1;
    peer.version = ProdigyBinaryVersion;
    peer.connected = true;
    peer.isFixedFile = true;
    peer.fslot = 60 + index;
    peer.registrationFresh = true;
    peer.existingMasterUUID = self.uuid;
    reserveTransportStream(peer);
    reserveTransportStream(peerTransports[index]);
    fixtureReady = peer.beginTransportAEGIS(
                       false, peerPSK.data(), "local-bundle-witness-repair-peer"_ctv,
                       self.uuid, peer.uuid) &&
        peerTransports[index].beginTransportAEGIS(
            true, peerPSK.data(), "local-bundle-witness-repair-peer"_ctv,
            peer.uuid, self.uuid) &&
        completeTransportHandshake(peer, peerTransports[index]) && fixtureReady;
    peer.containerRetirementCapabilityAcknowledged = true;
    peer.containerRetirementCapabilityUUID = peer.uuid;
    peer.containerRetirementCapabilityBootNs = peer.boottimens;
    peer.containerRetirementCapabilityIOGeneration = peer.ioGeneration;
    brain.brains.insert(&peer);
  }
  suite.require(fixtureReady, "local_bundle_witness_repair_authenticates_exact_brain_cohort");

  String serializedAuthority = {}, authorityDigest = {};
  suite.require(brain.serializeCurrentMasterAuthorityTransition(
                    serializedAuthority, authorityDigest),
                "local_bundle_witness_repair_serializes_current_authority");
  for (BrainView& peer : peers)
  {
    brain.noteMasterAuthorityTransitionSentToPeer(
        &peer, brain.masterAuthorityRuntimeState, authorityDigest);
    ProdigyMasterAuthorityStateTransitionAck acknowledgement = {};
    acknowledgement.generation = brain.masterAuthorityRuntimeState.generation;
    acknowledgement.peerUUID = peer.uuid;
    acknowledgement.peerBootNs = peer.boottimens;
    acknowledgement.transitionDigest.assign(authorityDigest);
    brain.acknowledgeMasterAuthorityTransition(&peer, acknowledgement);
  }
  Mothership mothership = {};
  mothership.isFixedFile = true;
  mothership.fslot = 27;
  brain.activeMotherships.insert(&mothership);
  RepairLocalBundleRecoveryWitness query = {};
  query.action = ProdigyLocalBundleRecoveryWitnessRepairAction::query;
  query.operationUUID = uint128_t(0x7304);
  query.clusterUUID = brain.brainConfig.clusterUUID;
  RepairLocalBundleRecoveryWitness pendingObservation = {};
  suite.require(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, query, pendingObservation) &&
          pendingObservation.success && pendingObservation.witnessPresent &&
          !pendingObservation.eligible && !pendingObservation.completed &&
          pendingObservation.failure.equal(
              "fresh authenticated three-machine fleet observation is incomplete"_ctv) &&
          brain.upgradeAdmissionObservation.receiptVersion != 0 &&
          brain.upgradeAdmissionObservation.expectedPeerGenerations.size() == 2,
      "local_bundle_witness_repair_query_owns_fresh_fleet_observation");

  auto& observation = brain.upgradeAdmissionObservation;
  for (BrainView& peer : peers)
  {
    ProdigyUpgradeAdmissionPeerObservation response = {};
    response.brainUUID = peer.uuid;
    response.machineUUID = peer.uuid;
    response.receiptVersion = observation.receiptVersion;
    response.authorityGeneration = observation.authorityGeneration;
    response.requesterTransportGeneration = peer.ioGeneration;
    response.masterUUID = self.uuid;
    response.masterBootNs = brain.boottimens;
    response.nonce = observation.nonce;
    response.observedAtMs = observation.requestedAtMs;
    response.codeSupportsSerialFollowers = true;
    response.localInstalledBundleVerified = true;
    response.stateUploadFresh = true;
    response.authorityAcknowledged = true;
    response.recoveryWitnessAcknowledged = true;
    response.installedBundleSHA256.assign(installedBundle);
    observation.received.insert_or_assign(peer.uuid, std::move(response));
  }
  MothershipUpgradeAdmissionReport admission = {};
  brain.collectUpgradeAdmissionReport(admission);
  suite.require(admission.observationComplete && admission.authorityAcknowledged &&
                    admission.recoveryWitnessAcknowledged &&
                    admission.commissionedPeerTransportVerified &&
                    admission.fleetBundleDigestsFresh && admission.fleetInventoriesFresh &&
                    admission.peers.size() == 3 &&
                    admission.masterApprovedBundleSHA256.equals(installedBundle),
                "local_bundle_witness_repair_completes_fresh_exact_fleet_receipt");
  RepairLocalBundleRecoveryWitness queryResponse = {};
  suite.require(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, query, queryResponse) &&
          queryResponse.success && queryResponse.witnessPresent && queryResponse.eligible &&
          !queryResponse.completed &&
          prodigyLocalBundleRecoveryWitnessRepairScopeValid(queryResponse.scope) &&
          queryResponse.scope.operationUUID == query.operationUUID &&
          queryResponse.scope.clusterUUID == query.clusterUUID &&
          queryResponse.scope.machines.size() == 3,
      "local_bundle_witness_repair_query_returns_exact_eligible_scope");
  String queryDigest = {};
  suite.require(
      prodigyLocalBundleRecoveryWitnessRepairScopeSHA256(
          queryResponse.scope, queryDigest) &&
          queryDigest.equals(queryResponse.scopeSHA256),
      "local_bundle_witness_repair_query_scope_is_canonical");

  RepairLocalBundleRecoveryWitness retire = query;
  retire.action = ProdigyLocalBundleRecoveryWitnessRepairAction::retire;
  retire.scopeSHA256.assign(
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv);
  RepairLocalBundleRecoveryWitness stale = {};
  suite.expect(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, retire, stale) &&
          !stale.success &&
          stale.failure.equal(
              "local bundle recovery witness repair query receipt is stale or mismatched"_ctv) &&
          brain.updateSelfMachineRecoveryWitnesses.size() == 3,
      "local_bundle_witness_repair_rejects_stale_scope_without_mutation");

  retire.scopeSHA256 = queryResponse.scopeSHA256;
  const ProdigyPersistentUpdateSelfState before = brain.capturePersistentUpdateSelfState();
  brain.holdRuntimePersistence = true;
  auto dispatchRetire = [&]() {
    mothership.wBuffer.clear();
    String payload = {}, frame = {};
    auto mutableRequest = retire;
    BitseryEngine::serialize(payload, mutableRequest);
    brain.mothershipHandler(
        &mothership,
        buildMothershipMessage(
            frame, MothershipTopic::repairLocalBundleRecoveryWitness, payload));
  };
  dispatchRetire();
  suite.require(mothership.wBuffer.empty() &&
                    brain.pendingRuntimePersistence.size() == 1 &&
                    brain.updateSelfWorkerExpectedBundleSHA256.empty() &&
                    brain.updateSelfMachineRecoveryWitnesses.empty(),
                "local_bundle_witness_repair_waits_for_durable_commit");
  brain.finishRuntimePersistence(false);
  RepairLocalBundleRecoveryWitness failed = {};
  suite.expect(
      extractAsyncRequestResponse(
          mothership.wBuffer,
          MothershipTopic::repairLocalBundleRecoveryWitness,
          failed) &&
          !failed.success && !failed.completed && failed.witnessPresent &&
          failed.failure.equal(
              "local bundle recovery witness repair durable commit failed"_ctv) &&
          equalSerializedObjects(before, brain.capturePersistentUpdateSelfState()) &&
          !brain.masterAuthorityRuntimeState.taskExecutions.contains(
              prodigyLocalBundleRecoveryWitnessRepairJournalExecutionID),
      "local_bundle_witness_repair_failed_commit_restores_witness_and_receipt");

  dispatchRetire();
  suite.require(mothership.wBuffer.empty() &&
                    brain.pendingRuntimePersistence.size() == 1,
                "local_bundle_witness_repair_lost_response_waits_for_commit");
  brain.activeMotherships.erase(&mothership);
  brain.finishRuntimePersistence(true);
  suite.require(mothership.wBuffer.empty() &&
                    brain.updateSelfWorkerExpectedBundleSHA256.empty() &&
                    brain.updateSelfMachineRecoveryWitnesses.empty(),
                "local_bundle_witness_repair_lost_response_commits_only_witness_retirement");

  String authorityBytes = {};
  auto authorityCopy = brain.masterAuthorityRuntimeState;
  ProdigyMasterAuthorityRuntimeState reloadedAuthority = {};
  ProdigyLocalBundleRecoveryWitnessRepairJournal reloadedJournal = {};
  suite.require(
      BitseryEngine::serialize(authorityBytes, authorityCopy) &&
          BitseryEngine::deserializeSafe(authorityBytes, reloadedAuthority) &&
          brain.decodeLocalBundleRecoveryWitnessRepairJournal(
              reloadedAuthority, reloadedJournal) &&
          reloadedJournal.receipts.size() == 1 &&
          prodigyLocalBundleRecoveryWitnessRepairReceiptValid(
              reloadedJournal.receipts.front()) &&
          !brain.hasUpdateSelfRecoveryWitness(reloadedAuthority.updateSelf),
      "local_bundle_witness_repair_receipt_and_retirement_survive_authority_reload");
  brain.masterAuthorityRuntimeState = std::move(reloadedAuthority);
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration =
      brain.masterAuthorityRuntimeState.generation;
  brain.activeMotherships.insert(&mothership);

  RepairLocalBundleRecoveryWitness replay = {};
  suite.expect(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, retire, replay) &&
          replay.success && replay.idempotent && replay.completed &&
          replay.scopeSHA256.equals(retire.scopeSHA256) &&
          replay.durableGeneration ==
              reloadedJournal.receipts.front().retiredAtAuthorityGeneration,
      "local_bundle_witness_repair_lost_response_retry_replays_exact_receipt");

  auto collision = retire;
  collision.scopeSHA256.assign(
      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"_ctv);
  RepairLocalBundleRecoveryWitness collisionResponse = {};
  suite.expect(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, collision, collisionResponse) &&
          !collisionResponse.success &&
          collisionResponse.failure.equal(
              "local bundle recovery witness repair operation UUID collision"_ctv),
      "local_bundle_witness_repair_rejects_operation_uuid_scope_collision");

  auto absentQuery = query;
  absentQuery.operationUUID = uint128_t(0x7305);
  RepairLocalBundleRecoveryWitness absent = {};
  suite.expect(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, absentQuery, absent) &&
          absent.success && !absent.witnessPresent && !absent.eligible &&
          !absent.completed &&
          absent.failure.equal("local bundle recovery witness is absent"_ctv) &&
          !brain.pruneExpiredTaskExecutionRecords(INT64_MAX) &&
          brain.masterAuthorityRuntimeState.taskExecutions.contains(
              prodigyLocalBundleRecoveryWitnessRepairJournalExecutionID),
      "local_bundle_witness_repair_terminal_journal_is_nonexpiring");

  auto legacyJournal = reloadedJournal;
  legacyJournal.protocolVersion =
      ProdigyLocalBundleRecoveryWitnessRepairJournal::legacyVersion;
  String legacyJournalBytes = {};
  ProdigyLocalBundleRecoveryWitnessRepairJournal decodedLegacyJournal = {};
  suite.expect(
      prodigyLocalBundleRecoveryWitnessRepairJournalValid(legacyJournal) &&
          BitseryEngine::serialize(legacyJournalBytes, legacyJournal) &&
          BitseryEngine::deserializeSafe(legacyJournalBytes, decodedLegacyJournal) &&
          prodigyLocalBundleRecoveryWitnessRepairJournalValid(decodedLegacyJournal) &&
          decodedLegacyJournal.protocolVersion ==
              ProdigyLocalBundleRecoveryWitnessRepairJournal::legacyVersion,
      "local_bundle_witness_repair_reads_legacy_same_bundle_journal");

  // Reproduce the post-upgrade deadlock: every current Neuron attests one
  // newer bundle, while the durable update-self coordinator still owns an
  // all-machine terminal witness for the released predecessor. One captured
  // bootstrap retains its UUID and canonical owner but no longer matches the
  // deployment artifact authority, so it must never be projected.
  constexpr uint16_t retainedApplicationID = 63114;
  ApplicationDeployment retainedDeployment = {};
  retainedDeployment.plan = makeDeploymentPlan(retainedApplicationID, 1);
  retainedDeployment.plan.config.containerBlobSHA256.assign(
      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"_ctv);
  retainedDeployment.plan.config.containerBlobBytes = 4096;
  retainedDeployment.state = DeploymentState::running;
  const uint64_t retainedDeploymentID =
      retainedDeployment.plan.config.deploymentID();
  brain.deployments.insert_or_assign(retainedDeploymentID, &retainedDeployment);
  brain.deploymentsByApp.insert_or_assign(
      retainedApplicationID, &retainedDeployment);
  brain.deploymentPlans.insert_or_assign(
      retainedDeploymentID, retainedDeployment.plan);

  ContainerView retainedContainer = {};
  retainedContainer.uuid = uint128_t(0x7307);
  retainedContainer.applicationID = retainedApplicationID;
  retainedContainer.deploymentID = retainedDeploymentID;
  retainedContainer.machine = &machines[0];
  retainedContainer.fragment = 7;
  retainedContainer.lifetime = ApplicationLifetime::base;
  retainedContainer.state = ContainerState::healthy;
  retainedContainer.runtimeReady = true;
  retainedContainer.createdAtMs = 7'307;
  brain.brainConfig.datacenterFragment = 0x73;
  for (uint32_t index = 0; index < 3; ++index)
  {
    machines[index].fragment = 0x7301 + index;
    brain.masterAuthorityRuntimeState.machineFragmentAssignments.push_back(
        {machines[index].uuid, machines[index].fragment});
  }

  CrossClusterMasqueGatewayAuthority retainedGatewayAuthority = {};
  retainedGatewayAuthority.pairUUID = uint128_t(0x7310);
  retainedGatewayAuthority.pairOperationUUID = uint128_t(0x7311);
  retainedGatewayAuthority.localClusterUUID = brain.brainConfig.clusterUUID;
  retainedGatewayAuthority.peerClusterUUID = uint128_t(0x7400);
  retainedGatewayAuthority.localMachineUUID = machines[0].uuid;
  retainedGatewayAuthority.peerMachineUUID = uint128_t(0x7401);
  retainedGatewayAuthority.localDatacenterFragment = 0x73;
  retainedGatewayAuthority.peerDatacenterFragment = 0x74;
  retainedGatewayAuthority.localSitePrefix =
      prodigyContainerDatacenterSitePrefix(0x73);
  retainedGatewayAuthority.peerSitePrefix =
      prodigyContainerDatacenterSitePrefix(0x74);
  retainedGatewayAuthority.artifactSHA256.assign(
      "abababababababababababababababababababababababababababababababab"_ctv);
  retainedGatewayAuthority.artifactBytes = 4096;
  retainedGatewayAuthority.listenerPublicUDPEndpoint =
      IPAddress("198.51.100.73", false);
  retainedGatewayAuthority.listenerPublicUDPPort = 4433;
  retainedGatewayAuthority.privateTunnelInterface.assign("mtbgprepair"_ctv);
  retainedGatewayAuthority.privateTunnelLocalIPv6 = IPAddress("fd00::1", true);
  retainedGatewayAuthority.privateTunnelPeerIPv6 = IPAddress("fd00::2", true);
  retainedGatewayAuthority.privateLocalASN = 42001;
  retainedGatewayAuthority.privatePeerASN = 42002;
  retainedGatewayAuthority.privateLocalBGPID = 1;
  retainedGatewayAuthority.privatePeerBGPID = 2;
  retainedGatewayAuthority.privateSessionCredentialSHA256.assign(
      "bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc"_ctv);
  retainedGatewayAuthority.localIdentitySHA256.assign(
      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"_ctv);
  retainedGatewayAuthority.peerIdentitySHA256.assign(
      "dededededededededededededededededededededededededededededededede"_ctv);
  retainedGatewayAuthority.peerTrustSHA256.assign(
      "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"_ctv);
  retainedGatewayAuthority.generation = 1;
  retainedGatewayAuthority.pairAuthorityGeneration = 7;
  retainedGatewayAuthority.keyGeneration = 3;
  retainedGatewayAuthority.localRole =
      CrossClusterMasqueGatewayRole::listener;
  retainedGatewayAuthority.state = CrossClusterMasqueGatewayState::active;
  ProdigyClusterPairEnrollment retainedGatewayEnrollment = {};
  retainedGatewayEnrollment.pairUUID = retainedGatewayAuthority.pairUUID;
  retainedGatewayEnrollment.localClusterUUID =
      retainedGatewayAuthority.localClusterUUID;
  retainedGatewayEnrollment.peerClusterUUID =
      retainedGatewayAuthority.peerClusterUUID;
  retainedGatewayEnrollment.operationUUID =
      retainedGatewayAuthority.pairOperationUUID;
  retainedGatewayEnrollment.rootGeneration = 1;
  retainedGatewayEnrollment.agreedKeyEpoch =
      retainedGatewayAuthority.keyGeneration;
  retainedGatewayEnrollment.localAuthorityGeneration =
      retainedGatewayAuthority.pairAuthorityGeneration;
  retainedGatewayEnrollment.state = ProdigyClusterPairEnrollmentState::active;
  for (uint32_t byte = 0; byte < sizeof(retainedGatewayEnrollment.root); ++byte)
    retainedGatewayEnrollment.root[byte] = uint8_t(byte + 1);
  ProdigyClusterPairEnrollmentOperation retainedGatewayOperation = {};
  retainedGatewayOperation.pairUUID = retainedGatewayAuthority.pairUUID;
  retainedGatewayOperation.operationUUID =
      retainedGatewayAuthority.pairOperationUUID;
  retainedGatewayOperation.localAuthorityGeneration =
      retainedGatewayAuthority.pairAuthorityGeneration;
  retainedGatewayOperation.transitionGeneration =
      brain.masterAuthorityRuntimeState.generation + 1;
  retainedGatewayOperation.pinnedMasterAuthorityEpoch =
      brain.masterAuthorityEpoch;
  retainedGatewayOperation.initialProjectionDelivered = true;
  retainedGatewayOperation.frozenElectorate = {
      machineUUIDs[0], machineUUIDs[1], machineUUIDs[2]};
  ClusterPairControlEndpoint retainedGatewayLocalEndpoint = {};
  retainedGatewayLocalEndpoint.clusterUUID =
      retainedGatewayAuthority.localClusterUUID;
  retainedGatewayLocalEndpoint.nodeUUID = machineUUIDs[0];
  retainedGatewayLocalEndpoint.address = IPAddress("fd00:73::1", true);
  retainedGatewayLocalEndpoint.port =
      uint16_t(ReservedPorts::clusterPairControl);
  ClusterPairControlEndpoint retainedGatewayPeerEndpoint = {};
  retainedGatewayPeerEndpoint.clusterUUID =
      retainedGatewayAuthority.peerClusterUUID;
  retainedGatewayPeerEndpoint.nodeUUID = retainedGatewayAuthority.peerMachineUUID;
  retainedGatewayPeerEndpoint.address = IPAddress("fd00:74::1", true);
  retainedGatewayPeerEndpoint.port =
      uint16_t(ReservedPorts::clusterPairControl);
  retainedGatewayOperation.localEndpoints = {retainedGatewayLocalEndpoint};
  retainedGatewayOperation.peerEndpoints = {retainedGatewayPeerEndpoint};
  auto& transportRoot =
      brain.masterAuthorityRuntimeState.transportCredentialAuthorityRoot;
  transportRoot.authorityEpoch = 1;
  transportRoot.keyEpoch = 1;
  transportRoot.authorityGeneration =
      brain.masterAuthorityRuntimeState.generation;
  for (uint32_t byte = 0; byte < sizeof(transportRoot.root); ++byte)
    transportRoot.root[byte] = uint8_t(byte + 1);
  for (uint32_t index = 0; index < 3; ++index)
  {
    ProdigyTransportCredentialEnrollment enrollment = {};
    enrollment.operationUUID = uint128_t(0x7320 + index);
    enrollment.nodeUUID = machineUUIDs[index];
    enrollment.clusterUUID = brain.brainConfig.clusterUUID;
    enrollment.authorityEpoch = transportRoot.authorityEpoch;
    enrollment.keyEpoch = transportRoot.keyEpoch;
    enrollment.authorityGeneration = transportRoot.authorityGeneration;
    enrollment.role = ProdigyTransportCredentialNodeRole::brain;
    enrollment.state = ProdigyTransportCredentialEnrollmentState::active;
    brain.masterAuthorityRuntimeState.transportCredentialEnrollments.push_back(
        std::move(enrollment));
  }
  for (BrainView& peer : peers)
  {
    peer.clusterPairEnrollmentCapabilityAcknowledged = true;
    peer.clusterPairOperationsCapabilityAcknowledged = true;
  }
  brain.masterAuthorityRuntimeState.clusterPairEnrollments.push_back(
      retainedGatewayEnrollment);
  brain.masterAuthorityRuntimeState.clusterPairEnrollmentOperations.push_back(
      retainedGatewayOperation);
  brain.masterAuthorityRuntimeState.crossClusterMasqueGatewayAuthorities.push_back(
      retainedGatewayAuthority);
  NeuronContainerBootstrap absentGatewayBootstrap = {};
  suite.require(
      brain.buildCrossClusterMasqueGatewayPlan(
          retainedGatewayAuthority,
          prodigyCrossClusterMasqueGatewayRuntimeFragmentFirst,
          uint128_t(0x7309), absentGatewayBootstrap.plan),
      "local_bundle_witness_repair_builds_semantically_current_gateway_bootstrap");
  String serializedAbsentGatewayBootstrap = {};
  suite.require(
      BitseryEngine::serialize(
          serializedAbsentGatewayBootstrap, absentGatewayBootstrap),
      "local_bundle_witness_repair_serializes_absent_gateway_bootstrap");
  retainedContainer.setMeshAddress(
      container_network_subnet6,
      brain.brainConfig.datacenterFragment,
      machines[0].fragment,
      retainedContainer.fragment);
  retainedContainer.addresses.emplace_back(
      retainedContainer.meshAddress, uint8_t(128));
  retainedDeployment.containers.insert(&retainedContainer);
  machines[0].upsertContainerIndexEntry(
      retainedDeploymentID, &retainedContainer);
  brain.containers.insert_or_assign(
      retainedContainer.uuid, &retainedContainer);

  NeuronContainerBootstrap staleBootstrap = {};
  staleBootstrap.plan.uuid = retainedContainer.uuid;
  staleBootstrap.plan.config = retainedDeployment.plan.config;
  staleBootstrap.plan.fragment = retainedContainer.fragment;
  staleBootstrap.plan.addresses = retainedContainer.addresses;
  staleBootstrap.plan.config.containerBlobSHA256.assign(
      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"_ctv);
  String serializedStaleBootstrap = {};
  suite.require(
      BitseryEngine::serialize(serializedStaleBootstrap, staleBootstrap),
      "local_bundle_witness_repair_serializes_superseded_bootstrap");

  NeuronContainerBootstrap absentBootstrap = staleBootstrap;
  absentBootstrap.plan.uuid = uint128_t(0x7308);
  absentBootstrap.plan.config = retainedDeployment.plan.config;
  String serializedAbsentBootstrap = {};
  suite.require(
      BitseryEngine::serialize(serializedAbsentBootstrap, absentBootstrap),
      "local_bundle_witness_repair_serializes_absent_retained_bootstrap");

  const String supersededBundle =
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_ctv;
  brain.updateSelfWorkerExpectedBundleSHA256 = supersededBundle;
  brain.updateSelfWorkerFailure.assign(
      "local post-exec bundle digest mismatch"_ctv);
  for (uint128_t machineUUID : machineUUIDs)
  {
    brain.updateSelfWorkerMachineUUIDs.insert(machineUUID);
    brain.updateSelfWorkerStagedMachineUUIDs.insert(machineUUID);
    brain.updateSelfWorkerTransitionIssuedMachineUUIDs.insert(machineUUID);
    brain.updateSelfWorkerRebootedMachineUUIDs.insert(machineUUID);
  }
  brain.updateSelfWorkerStateUploadedMachineUUIDs.insert(machineUUIDs[1]);
  brain.updateSelfWorkerStateUploadedMachineUUIDs.insert(machineUUIDs[2]);
  brain.updateSelfMachineRecoveryWitnesses.clear();
  for (uint32_t index = 0; index < 3; ++index)
  {
    ProdigyPersistentUpdateSelfMachineRecoveryWitness witness = {};
    witness.machineUUID = machines[index].uuid;
    witness.bundleRegistered = false;
    if (index == 0)
    {
      witness.containerBootstraps.push_back(serializedStaleBootstrap);
      witness.containerBootstraps.push_back(serializedAbsentBootstrap);
      witness.containerBootstraps.push_back(
          serializedAbsentGatewayBootstrap);
    }
    brain.updateSelfMachineRecoveryWitnesses.push_back(std::move(witness));
    if (index != 0)
    {
      machines[index].neuron.verifiedInstalledBundleSHA256.assign(installedBundle);
      machines[index].neuron.verifiedInstalledBundleIOGeneration =
          machines[index].neuron.ioGeneration;
      machines[index].neuron.verifiedInstalledBundleAuthorityEpoch =
          brain.masterAuthorityEpoch;
    }
  }
  brain.recoveringPersistedNeuronInventory = true;
  ++brain.masterAuthorityRuntimeState.generation;
  brain.masterAuthorityRuntimeState.updateSelf =
      brain.capturePersistentUpdateSelfState();
  brain.masterAuthorityRuntimeState.updateSelfFollowerConcurrency = 1;
  brain.masterAuthorityRuntimeState.updateSelfFollowerTransitionIssuedPeerKeys = {
      peers[0].uuid, peers[1].uuid};
  brain.masterAuthorityRuntimeState.updateSelfFollowerReadyPeerKeys = {
      peers[0].uuid};
  brain.restoreUpdateSelfFollowerConcurrencyState(
      brain.masterAuthorityRuntimeState);
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration =
      brain.masterAuthorityRuntimeState.generation;

  serializedAuthority.clear();
  authorityDigest.clear();
  suite.require(
      brain.serializeCurrentMasterAuthorityTransition(
          serializedAuthority, authorityDigest),
      "local_bundle_witness_repair_serializes_superseded_authority");
  for (BrainView& peer : peers)
  {
    brain.noteMasterAuthorityTransitionSentToPeer(
        &peer, brain.masterAuthorityRuntimeState, authorityDigest);
    ProdigyMasterAuthorityStateTransitionAck acknowledgement = {};
    acknowledgement.generation = brain.masterAuthorityRuntimeState.generation;
    acknowledgement.peerUUID = peer.uuid;
    acknowledgement.peerBootNs = peer.boottimens;
    acknowledgement.transitionDigest.assign(authorityDigest);
    brain.acknowledgeMasterAuthorityTransition(&peer, acknowledgement);
  }

  RepairLocalBundleRecoveryWitness supersededQuery = query;
  supersededQuery.operationUUID = uint128_t(0x7306);
  for (Machine& machine : machines)
  {
    machine.neuron.wBuffer.clear();
    machine.stateUploadRequestPending = false;
    machine.stateUploadRequestIOGeneration = 0;
  }
  brain.queueNeuronStateUploadForMachine(&machines[0]);
  suite.expect(
      machines[0].stateUploadRequestPending &&
          machines[0].stateUploadRequestIOGeneration ==
              machines[0].neuron.ioGeneration &&
          !machines[0].neuron.wBuffer.empty() &&
          !brain.persistedMachineInventoryUploaded.contains(machines[0].uuid),
      "local_bundle_witness_repair_requests_observation_without_projecting_stale_bootstraps");
  machines[0].neuron.wBuffer.clear();
  machines[0].stateUploadRequestPending = false;
  machines[0].stateUploadRequestIOGeneration = 0;
  machines[0].runtimeReady = true;

  RepairLocalBundleRecoveryWitness missingAbsenceProof = {};
  suite.expect(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, supersededQuery, missingAbsenceProof) &&
          missingAbsenceProof.success && missingAbsenceProof.witnessPresent &&
          !missingAbsenceProof.eligible &&
          missingAbsenceProof.failure.equal(
              "superseded local bundle witness identity lacks a canonical retained owner or fresh authenticated fleet-absence proof"_ctv),
      "local_bundle_witness_repair_rejects_absent_identity_without_fresh_fleet_proof");

  for (Machine& machine : machines)
  {
    machine.runtimeReady = true;
    brain.persistedMachineInventoryUploaded.insert(machine.uuid);
    auto& inventory = brain.containerRetirementInventoryByMachine[machine.uuid];
    inventory.authorityEpoch = brain.masterAuthorityEpoch;
    inventory.ioGeneration = machine.neuron.ioGeneration;
    inventory.present.clear();
  }
  brain.containerRetirementInventoryByMachine[machines[2].uuid].present.insert(
      absentBootstrap.plan.uuid);
  RepairLocalBundleRecoveryWitness conflictingAbsenceProof = {};
  suite.expect(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, supersededQuery, conflictingAbsenceProof) &&
          conflictingAbsenceProof.success && conflictingAbsenceProof.witnessPresent &&
          !conflictingAbsenceProof.eligible &&
          conflictingAbsenceProof.failure.equal(
              "superseded local bundle witness identity lacks a canonical retained owner or fresh authenticated fleet-absence proof"_ctv),
      "local_bundle_witness_repair_rejects_identity_reported_by_another_machine");
  brain.containerRetirementInventoryByMachine[machines[2].uuid].present.erase(
      absentBootstrap.plan.uuid);
  brain.containerRetirementInventoryByMachine[machines[2].uuid].present.insert(
      absentGatewayBootstrap.plan.uuid);
  RepairLocalBundleRecoveryWitness conflictingGatewayAbsenceProof = {};
  suite.expect(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, supersededQuery,
          conflictingGatewayAbsenceProof) &&
          conflictingGatewayAbsenceProof.success &&
          conflictingGatewayAbsenceProof.witnessPresent &&
          !conflictingGatewayAbsenceProof.eligible &&
          conflictingGatewayAbsenceProof.failure.equal(
              "superseded local bundle witness identity lacks a canonical retained owner or fresh authenticated fleet-absence proof"_ctv),
      "local_bundle_witness_repair_rejects_gateway_identity_reported_by_another_machine");
  brain.containerRetirementInventoryByMachine[machines[2].uuid].present.erase(
      absentGatewayBootstrap.plan.uuid);
  RepairLocalBundleRecoveryWitness supersededResponse = {};
  suite.require(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, supersededQuery, supersededResponse) &&
          supersededResponse.success && supersededResponse.witnessPresent &&
          supersededResponse.eligible && !supersededResponse.completed &&
          prodigyLocalBundleRecoveryWitnessRepairScopeSuperseded(
              supersededResponse.scope) &&
          supersededResponse.scope.installedBundleSHA256.equals(installedBundle) &&
          supersededResponse.scope.witnessExpectedBundleSHA256.equals(
              supersededBundle) &&
          std::all_of(
              supersededResponse.scope.machines.begin(),
              supersededResponse.scope.machines.end(),
              [](const auto& machine) { return !machine.bundleRegistered; }),
      "local_bundle_witness_repair_queries_exact_superseded_scope");

  brain.updateSelfTransitionIssuedPeerKeys.erase(peers[0].uuid);
  brain.masterAuthorityRuntimeState.updateSelfFollowerTransitionIssuedPeerKeys = {
      peers[1].uuid};
  RepairLocalBundleRecoveryWitness readyWithoutIssued = {};
  suite.expect(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, supersededQuery, readyWithoutIssued) &&
          readyWithoutIssued.success && readyWithoutIssued.witnessPresent &&
          !readyWithoutIssued.eligible &&
          readyWithoutIssued.failure.equal(
              "superseded local bundle follower progress differs from durable witness cohort"_ctv),
      "local_bundle_witness_repair_rejects_ready_follower_without_durable_issue");
  brain.updateSelfTransitionIssuedPeerKeys.insert(peers[0].uuid);
  brain.masterAuthorityRuntimeState.updateSelfFollowerTransitionIssuedPeerKeys = {
      peers[0].uuid, peers[1].uuid};

  const uint128_t unknownFollower = uint128_t(0x73ff);
  brain.updateSelfTransitionIssuedPeerKeys.erase(peers[1].uuid);
  brain.updateSelfTransitionIssuedPeerKeys.insert(unknownFollower);
  brain.masterAuthorityRuntimeState.updateSelfFollowerTransitionIssuedPeerKeys = {
      peers[0].uuid, unknownFollower};
  RepairLocalBundleRecoveryWitness foreignFollower = {};
  suite.expect(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, supersededQuery, foreignFollower) &&
          foreignFollower.success && foreignFollower.witnessPresent &&
          !foreignFollower.eligible &&
          foreignFollower.failure.equal(
              "superseded local bundle follower progress differs from durable witness cohort"_ctv),
      "local_bundle_witness_repair_rejects_foreign_durable_follower_progress");
  brain.updateSelfTransitionIssuedPeerKeys.erase(unknownFollower);
  brain.updateSelfTransitionIssuedPeerKeys.insert(peers[1].uuid);
  brain.masterAuthorityRuntimeState.updateSelfFollowerTransitionIssuedPeerKeys = {
      peers[0].uuid, peers[1].uuid};

  brain.updateSelfTransitionSentPeerKeys.insert(peers[1].uuid);
  RepairLocalBundleRecoveryWitness sentTransition = {};
  suite.expect(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, supersededQuery, sentTransition) &&
          sentTransition.success && sentTransition.witnessPresent &&
          !sentTransition.eligible &&
          sentTransition.failure.equal(
              "superseded local bundle persistence or transition continuation is active"_ctv),
      "local_bundle_witness_repair_rejects_process_local_follower_transition");
  brain.updateSelfTransitionSentPeerKeys.clear();

  brain.updateSelfPersistencePending = 1;
  RepairLocalBundleRecoveryWitness activeCoordinator = {};
  suite.expect(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, supersededQuery, activeCoordinator) &&
          activeCoordinator.success && activeCoordinator.witnessPresent &&
          !activeCoordinator.eligible &&
          activeCoordinator.failure.equal(
              "superseded local bundle persistence or transition continuation is active"_ctv),
      "local_bundle_witness_repair_rejects_active_superseded_coordinator");
  brain.updateSelfPersistencePending = 0;

  const String currentThirdDigest =
      machines[2].neuron.verifiedInstalledBundleSHA256;
  machines[2].neuron.verifiedInstalledBundleSHA256.assign(
      "9999999999999999999999999999999999999999999999999999999999999999"_ctv);
  RepairLocalBundleRecoveryWitness mixedBundle = {};
  suite.expect(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, supersededQuery, mixedBundle) &&
          mixedBundle.success && mixedBundle.witnessPresent &&
          !mixedBundle.eligible,
      "local_bundle_witness_repair_rejects_mixed_current_bundle_cohort");
  machines[2].neuron.verifiedInstalledBundleSHA256 = currentThirdDigest;

  RepairLocalBundleRecoveryWitness supersededRetire = supersededQuery;
  supersededRetire.action =
      ProdigyLocalBundleRecoveryWitnessRepairAction::retire;
  supersededRetire.scopeSHA256.assign(
      "8888888888888888888888888888888888888888888888888888888888888888"_ctv);
  const ProdigyPersistentUpdateSelfState supersededBefore =
      brain.capturePersistentUpdateSelfState();
  const uint8_t supersededFollowerConcurrencyBefore =
      brain.updateSelfFollowerConcurrency;
  const auto supersededIssuedBefore =
      brain.updateSelfTransitionIssuedPeerKeys;
  const auto supersededReadyBefore =
      brain.updateSelfFollowerReadyPeerKeys;
  const uint8_t supersededDurableFollowerConcurrencyBefore =
      brain.masterAuthorityRuntimeState.updateSelfFollowerConcurrency;
  const auto supersededDurableIssuedBefore =
      brain.masterAuthorityRuntimeState.updateSelfFollowerTransitionIssuedPeerKeys;
  const auto supersededDurableReadyBefore =
      brain.masterAuthorityRuntimeState.updateSelfFollowerReadyPeerKeys;
  const auto samePeerKeys = [](const auto& left, const auto& right) {
    return left.size() == right.size() &&
        std::all_of(left.begin(), left.end(), [&](uint128_t peerKey) {
          return right.contains(peerKey);
        });
  };
  const auto supersededFollowerProgressRestored = [&]() {
    return brain.updateSelfFollowerConcurrency ==
            supersededFollowerConcurrencyBefore &&
        samePeerKeys(brain.updateSelfTransitionIssuedPeerKeys,
                     supersededIssuedBefore) &&
        samePeerKeys(brain.updateSelfFollowerReadyPeerKeys,
                     supersededReadyBefore) &&
        brain.masterAuthorityRuntimeState.updateSelfFollowerConcurrency ==
            supersededDurableFollowerConcurrencyBefore &&
        brain.masterAuthorityRuntimeState.updateSelfFollowerTransitionIssuedPeerKeys ==
            supersededDurableIssuedBefore &&
        brain.masterAuthorityRuntimeState.updateSelfFollowerReadyPeerKeys ==
            supersededDurableReadyBefore;
  };
  RepairLocalBundleRecoveryWitness staleSuperseded = {};
  suite.expect(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, supersededRetire, staleSuperseded) &&
          !staleSuperseded.success &&
          staleSuperseded.failure.equal(
              "local bundle recovery witness repair query receipt is stale or mismatched"_ctv) &&
          equalSerializedObjects(
              supersededBefore, brain.capturePersistentUpdateSelfState()) &&
          supersededFollowerProgressRestored(),
      "local_bundle_witness_repair_rejects_stale_superseded_scope_without_mutation");

  supersededRetire.scopeSHA256 = supersededResponse.scopeSHA256;
  auto dispatchSupersededRetire = [&]() {
    mothership.wBuffer.clear();
    String payload = {}, frame = {};
    auto mutableRequest = supersededRetire;
    BitseryEngine::serialize(payload, mutableRequest);
    brain.mothershipHandler(
        &mothership,
        buildMothershipMessage(
            frame, MothershipTopic::repairLocalBundleRecoveryWitness, payload));
  };
  brain.holdRuntimePersistence = true;
  dispatchSupersededRetire();
  suite.require(
      mothership.wBuffer.empty() &&
          brain.pendingRuntimePersistence.size() == 1 &&
          !brain.hasUpdateSelfRecoveryWitness(
              brain.capturePersistentUpdateSelfState()) &&
          brain.updateSelfFollowerConcurrency == 0 &&
          brain.updateSelfTransitionIssuedPeerKeys.empty() &&
          brain.updateSelfFollowerReadyPeerKeys.empty() &&
          brain.masterAuthorityRuntimeState.updateSelfFollowerConcurrency == 0 &&
          brain.masterAuthorityRuntimeState
              .updateSelfFollowerTransitionIssuedPeerKeys.empty() &&
          brain.masterAuthorityRuntimeState.updateSelfFollowerReadyPeerKeys.empty(),
      "local_bundle_witness_repair_superseded_retirement_waits_for_commit");
  brain.finishRuntimePersistence(false);
  RepairLocalBundleRecoveryWitness failedSuperseded = {};
  suite.expect(
      extractAsyncRequestResponse(
          mothership.wBuffer,
          MothershipTopic::repairLocalBundleRecoveryWitness,
          failedSuperseded) &&
          !failedSuperseded.success && failedSuperseded.witnessPresent &&
          prodigyPersistentUpdateSelfStatesEquivalent(
              supersededBefore, brain.capturePersistentUpdateSelfState()) &&
          supersededFollowerProgressRestored(),
      "local_bundle_witness_repair_failed_superseded_commit_restores_full_coordinator");

  dispatchSupersededRetire();
  suite.require(
      mothership.wBuffer.empty() &&
          brain.pendingRuntimePersistence.size() == 1,
      "local_bundle_witness_repair_superseded_retry_waits_for_commit");
  for (Machine& machine : machines) machine.neuron.connected = false;
  brain.finishRuntimePersistence(true);
  RepairLocalBundleRecoveryWitness completedSuperseded = {};
  const ProdigyPersistentUpdateSelfState emptyCoordinator = {};
  ProdigyLocalBundleRecoveryWitnessRepairJournal completedJournal = {};
  suite.expect(
      extractAsyncRequestResponse(
          mothership.wBuffer,
          MothershipTopic::repairLocalBundleRecoveryWitness,
          completedSuperseded) &&
          completedSuperseded.success && completedSuperseded.completed &&
          equalSerializedObjects(
              emptyCoordinator, brain.capturePersistentUpdateSelfState()) &&
          brain.updateSelfFollowerConcurrency == 0 &&
          brain.updateSelfTransitionIssuedPeerKeys.empty() &&
          brain.updateSelfFollowerReadyPeerKeys.empty() &&
          brain.masterAuthorityRuntimeState.updateSelfFollowerConcurrency == 0 &&
          brain.masterAuthorityRuntimeState
              .updateSelfFollowerTransitionIssuedPeerKeys.empty() &&
          brain.masterAuthorityRuntimeState.updateSelfFollowerReadyPeerKeys.empty() &&
          brain.recoveringPersistedNeuronInventory &&
          std::all_of(
              std::begin(machines), std::end(machines),
              [](const Machine& machine) {
                return !machine.runtimeReady &&
                    machine.stateUploadRequestPending;
              }) &&
          brain.decodeLocalBundleRecoveryWitnessRepairJournal(
              brain.masterAuthorityRuntimeState, completedJournal) &&
          completedJournal.protocolVersion ==
              ProdigyLocalBundleRecoveryWitnessRepairJournal::version &&
          completedJournal.receipts.size() == 2 &&
          prodigyLocalBundleRecoveryWitnessRepairScopeSuperseded(
              completedJournal.receipts.back().scope),
      "local_bundle_witness_repair_commits_superseded_receipt_and_requeues_fresh_inventory");

  RepairLocalBundleRecoveryWitness supersededReplay = {};
  suite.expect(
      issueDeploymentLifecycleOperationForTest<
          MothershipTopic::repairLocalBundleRecoveryWitness>(
          brain, mothership, supersededRetire, supersededReplay) &&
          supersededReplay.success && supersededReplay.idempotent &&
          supersededReplay.completed &&
          supersededReplay.scopeSHA256.equals(
              supersededRetire.scopeSHA256),
      "local_bundle_witness_repair_replays_superseded_terminal_receipt");

  if (brain.artifactIO)
  {
    suite.expect(
        quiesceArtifactIOForTest(brain.artifactIO.get()),
        "local_bundle_witness_repair_quiesces_artifact_io");
    brain.artifactIO.reset();
  }

  machines[0].removeContainerIndexEntry(
      retainedDeploymentID, &retainedContainer);
  retainedDeployment.containers.erase(&retainedContainer);
  brain.containers.erase(retainedContainer.uuid);
  brain.deploymentPlans.erase(retainedDeploymentID);
  brain.deploymentsByApp.erase(retainedApplicationID);
  brain.deployments.erase(retainedDeploymentID);

  brain.activeMotherships.erase(&mothership);
  for (uint32_t index = 0; index < 2; ++index) brain.brains.erase(&peers[index]);
  for (uint32_t index = 0; index < 3; ++index)
  {
    brain.persistedMachineStateUploadPlansByMachine.erase(machines[index].uuid);
    brain.persistedMachineInventoryUploaded.erase(machines[index].uuid);
    brain.machinesByUUID.erase(machines[index].uuid);
    brain.machines.erase(&machines[index]);
  }
  thisBrain = savedBrain;
  thisNeuron = savedNeuron;
}

static void testAsyncRetainedStatefulRearmAcceptance(TestSuite& suite)
{
  ScopedFreshRing ring = {};
  StreamingTestBrain brain = {};
  NoopBrainIaaS iaas = {};
  TestNeuron self = {};
  BrainBase *savedBrain = thisBrain;
  NeuronBase *savedNeuron = thisNeuron;
  thisBrain = &brain;
  thisNeuron = &self;
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.ignited = true;
  brain.nBrains = 3;
  brain.masterAuthorityEpoch = 7;
  brain.boottimens = 700'000'001;
  brain.masterAuthorityRuntimeState.generation = 41;
  brain.masterAuthorityRuntimeState.hasCompletedInitialMasterElection = true;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = 41;
  brain.hasAuthoritativeTopology = true;
  brain.brainConfig.clusterUUID = uint128_t(0x7100);

  constexpr uint16_t applicationID = 63'114;
  constexpr uint64_t versionID = 91;
  const uint64_t deploymentID = (uint64_t(applicationID) << 48) | versionID;
  String applicationName = "retained-rearm-test"_ctv;
  brain.reservedApplicationIDsByName.insert_or_assign(applicationName, applicationID);
  brain.reservedApplicationNamesByID.insert_or_assign(applicationID, applicationName);

  Rack racks[3] = {};
  Machine machines[3] = {};
  ScopedSocketPair neuronSockets[3] = {};
  const uint128_t machineUUIDs[3] = {uint128_t(0x7101), uint128_t(0x7102), uint128_t(0x7103)};
  self.uuid = machineUUIDs[0];
  bool fixtureReady = true;
  for (uint32_t index = 0; index < 3; ++index)
  {
    fixtureReady = neuronSockets[index].create(suite, "retained_rearm_neuron_control_socket") && fixtureReady;
    racks[index].uuid = 0x7110 + index;
    Machine& machine = machines[index];
    machine.uuid = machineUUIDs[index];
    machine.private4 = 0x0a710001 + index;
    machine.rack = &racks[index];
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;
    machine.isBrain = true;
    machine.isThisMachine = index == 0;
    machine.hardware.inventoryComplete = true;
    machine.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
    machine.hardware.cpu.logicalCores = machine.ownedLogicalCores = machine.totalLogicalCores =
        machine.nLogicalCores_available = 8;
    machine.hardware.memory.totalMB = machine.ownedMemoryMB = machine.totalMemoryMB =
        machine.memoryMB_available = 8192;
    machine.ownedStorageMB = machine.totalStorageMB = machine.storageMB_available = 8192;
    machine.neuron.machine = &machine;
    machine.neuron.isFixedFile = true;
    machine.neuron.fslot = neuronSockets[index].adoptLeftIntoFixedFileSlot();
    machine.neuron.connected = machine.neuron.fslot >= 0;
    machine.runtimeReady = machine.neuron.connected;
    racks[index].machines.insert(&machine);
    brain.racks.insert_or_assign(racks[index].uuid, &racks[index]);
    brain.machines.insert(&machine);
    brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
    ClusterMachine topologyMember = {};
    topologyMember.uuid = machine.uuid;
    topologyMember.isBrain = true;
    brain.authoritativeTopology.machines.push_back(topologyMember);
    fixtureReady = machine.runtimeReady && fixtureReady;
  }
  suite.require(fixtureReady, "retained_rearm_arms_exact_three_neuron_controls");

  BrainView peers[2] = {};
  ProdigyTransportTLSStream peerTransports[2] = {};
  std::array<uint8_t, 32> peerPSK = {};
  peerPSK.fill(0x71);
  for (uint32_t index = 0; index < 2; ++index)
  {
    BrainView& peer = peers[index];
    peer.uuid = machineUUIDs[index + 1];
    peer.boottimens = 710'000'010 + index;
    peer.ioGeneration = 1;
    peer.transportEpoch = 1;
    peer.version = ProdigyBinaryVersion;
    peer.connected = true;
    peer.isFixedFile = true;
    peer.fslot = 50 + index;
    peer.registrationFresh = true;
    peer.existingMasterUUID = self.uuid;
    reserveTransportStream(peer);
    reserveTransportStream(peerTransports[index]);
    fixtureReady = peer.beginTransportAEGIS(false, peerPSK.data(), "retained-rearm-peer"_ctv,
                       self.uuid, peer.uuid) &&
        peerTransports[index].beginTransportAEGIS(true, peerPSK.data(), "retained-rearm-peer"_ctv,
            peer.uuid, self.uuid) &&
        completeTransportHandshake(peer, peerTransports[index]) && fixtureReady;
    peer.containerRetirementCapabilityAcknowledged = true;
    peer.containerRetirementCapabilityUUID = peer.uuid;
    peer.containerRetirementCapabilityBootNs = peer.boottimens;
    peer.containerRetirementCapabilityIOGeneration = peer.ioGeneration;
    brain.brains.insert(&peer);
  }
  suite.require(fixtureReady, "retained_rearm_authenticates_exact_brain_cohort");

  auto *deployment = new ApplicationDeployment();
  deployment->plan = makeDeploymentPlan(applicationID, versionID);
  deployment->plan.config.type = ApplicationType::stateful;
  deployment->plan.config.containerBlobSHA256.assign(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
  deployment->plan.config.containerBlobBytes = 4096;
  deployment->plan.isStateful = true;
  deployment->plan.canaryCount = 0;
  deployment->plan.useHostNetworkNamespace = false;
  deployment->plan.stateful.allMasters = true;
  deployment->plan.stateful.allowUpdateInPlace = true;
  deployment->plan.stateful.clientPrefix = (uint64_t(applicationID) << 48) | (uint64_t(1) << 40);
  deployment->plan.stateful.siblingPrefix = (uint64_t(applicationID) << 48) | (uint64_t(2) << 40);
  deployment->plan.stateful.cousinPrefix = (uint64_t(applicationID) << 48) | (uint64_t(3) << 40);
  deployment->plan.stateful.seedingPrefix = (uint64_t(applicationID) << 48) | (uint64_t(4) << 40);
  deployment->plan.stateful.shardingPrefix = (uint64_t(applicationID) << 48) | (uint64_t(5) << 40);
  deployment->state = DeploymentState::none;
  deployment->nShardGroups = 1;
  deployment->nTargetBase = 0;
  deployment->nDeployedBase = 0;
  deployment->nHealthyBase = 2;
  deployment->brainBlobEchoPeerKeys.insert(machineUUIDs[1]);
  deployment->brainBlobEchoPeerKeys.insert(machineUUIDs[2]);
  const StatefulMeshRoles roles =
      StatefulMeshRoles::forShardGroup(deployment->plan.stateful, applicationID, 0);
  ContainerView retained[2] = {};
  for (uint32_t index = 0; index < 2; ++index)
  {
    retained[index].uuid = uint128_t(0x7201 + index);
    retained[index].deploymentID = deploymentID;
    retained[index].applicationID = applicationID;
    retained[index].machine = &machines[index];
    retained[index].lifetime = ApplicationLifetime::base;
    retained[index].isStateful = true;
    retained[index].shardGroup = 0;
    retained[index].state = ContainerState::healthy;
    retained[index].runtimeReady = true;
    retained[index].explicitStatefulMeshRoles = roles;
    retained[index].advertisements.emplace(
        roles.client, Advertisement(roles.client, ContainerState::healthy, ContainerState::destroying,
                                    uint16_t(19'210 + index)));
    retained[index].advertisingOnPorts.insert(uint16_t(19'210 + index));
    deployment->containers.insert(&retained[index]);
    deployment->containersByShardGroup.insert(0, &retained[index]);
    deployment->countPerMachine[&machines[index]] = 1;
    deployment->countPerRack[&racks[index]] = 1;
    deployment->racksByShardGroup[0].insert(&racks[index]);
    brain.containers.insert_or_assign(retained[index].uuid, &retained[index]);
    machines[index].upsertContainerIndexEntry(deploymentID, &retained[index]);
  }
  brain.deployments.insert_or_assign(deploymentID, deployment);
  brain.deploymentsByApp.insert_or_assign(applicationID, deployment);
  brain.deploymentPlans.insert_or_assign(deploymentID, deployment->plan);

  RearmRetainedStatefulDeployment request = {};
  auto& scope = request.proof.scope;
  scope.operationID.assign("123e4567-e89b-42d3-a456-426614174013"_ctv);
  scope.clusterUUID = brain.brainConfig.clusterUUID;
  scope.applicationName = applicationName;
  scope.applicationID = applicationID;
  scope.deploymentID = deploymentID;
  scope.versionID = versionID;
  DeploymentPlan planCopy = deployment->plan;
  String planBytes = {};
  BitseryEngine::serialize(planBytes, planCopy);
  prodigyComputeSHA256Hex(planBytes, scope.canonicalPlanSHA256);
  scope.artifactSHA256 = deployment->plan.config.containerBlobSHA256;
  scope.artifactBytes = deployment->plan.config.containerBlobBytes;
  scope.machineUUIDs = {machineUUIDs[0], machineUUIDs[1], machineUUIDs[2]};
  for (uint32_t index = 0; index < 2; ++index)
    scope.retainedMembers.push_back({
        .containerUUID = retained[index].uuid, .machineUUID = machines[index].uuid, .shardGroup = 0,
        .state = ContainerState::healthy, .runtimeReady = true});
  scope.expectedState = DeploymentState::none;
  scope.expectedTarget = 0;
  scope.expectedDeployed = 0;
  scope.expectedHealthy = 2;
  scope.expectedAcknowledgedPeers = 2;
  scope.expectedRuntimeMembers = 2;
  scope.expectedRuntimeStateRecords = 0;
  scope.desiredReplicas = 3;
  scope.expectedAuthorityGeneration = 41;
  scope.expectedMasterUUID = self.uuid;
  scope.expectedMasterBootNs = brain.boottimens;
  scope.expectedIPv6Only = true;
  suite.require(prodigyRetainedStatefulRearmScopeSHA256(scope, request.proof.retainedStateSHA256),
                "retained_rearm_builds_canonical_proof_digest");

  auto acknowledgeCurrentAuthority = [&]() {
    String serialized = {}, digest = {};
    if (!brain.serializeCurrentMasterAuthorityTransition(serialized, digest)) return false;
    for (BrainView& peer : peers)
    {
      brain.noteMasterAuthorityTransitionSentToPeer(&peer, brain.masterAuthorityRuntimeState, digest);
      ProdigyMasterAuthorityStateTransitionAck acknowledgement = {};
      acknowledgement.generation = brain.masterAuthorityRuntimeState.generation;
      acknowledgement.peerUUID = peer.uuid;
      acknowledgement.peerBootNs = peer.boottimens;
      acknowledgement.transitionDigest.assign(digest);
      brain.acknowledgeMasterAuthorityTransition(&peer, acknowledgement);
    }
    return brain.containerRetirementAuthorityAcknowledged();
  };
  const bool initialAuthorityAcknowledged = acknowledgeCurrentAuthority();
  suite.require(initialAuthorityAcknowledged,
                "retained_rearm_starts_from_exact_acknowledged_authority");

  Mothership mothership = {};
  mothership.isFixedFile = true;
  mothership.fslot = 27;
  brain.activeMotherships.insert(&mothership);
  auto rehash = [](RearmRetainedStatefulDeployment& candidate) {
    candidate.proof.acceptedAtMs = 0;
    candidate.proof.retainedStateSHA256.clear();
    return prodigyRetainedStatefulRearmScopeSHA256(
        candidate.proof.scope, candidate.proof.retainedStateSHA256);
  };
  auto rejects = [&](RearmRetainedStatefulDeployment candidate, auto expectedFailure, const char *name) {
    RearmRetainedStatefulDeployment response = {};
    const bool canonical = rehash(candidate);
    suite.expect(canonical &&
                     issueDeploymentLifecycleOperationForTest<MothershipTopic::rearmRetainedStatefulDeployment>(
                         brain, mothership, candidate, response) &&
                     !response.success && response.failure.equal(expectedFailure) &&
                     brain.masterAuthorityRuntimeState.materializedStatefulRecoveryOperations.empty() &&
                     brain.masterAuthorityRuntimeState.retainedStatefulRearmProofs.empty(),
                 name);
  };

  auto mismatched = request;
  mismatched.proof.scope.clusterUUID += 1;
  rejects(mismatched,
          "retained stateful re-arm predicate mismatch: retained stateful re-arm cluster identity differs"_ctv,
          "retained_rearm_rejects_cluster_mismatch_with_exact_predicate");
  mismatched = request;
  --mismatched.proof.scope.applicationID;
  mismatched.proof.scope.deploymentID =
      (uint64_t(mismatched.proof.scope.applicationID) << 48) | mismatched.proof.scope.versionID;
  rejects(mismatched,
          "retained stateful re-arm predicate mismatch: retained stateful re-arm application reservation differs"_ctv,
          "retained_rearm_rejects_application_mismatch_with_exact_predicate");
  mismatched = request;
  ++mismatched.proof.scope.versionID;
  mismatched.proof.scope.deploymentID =
      (uint64_t(mismatched.proof.scope.applicationID) << 48) | mismatched.proof.scope.versionID;
  rejects(mismatched,
          "retained stateful re-arm predicate mismatch: retained stateful re-arm target is not the canonical application head"_ctv,
          "retained_rearm_rejects_deployment_version_mismatch_with_exact_predicate");
  mismatched = request;
  mismatched.proof.scope.canonicalPlanSHA256.assign(
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv);
  rejects(mismatched,
          "retained stateful re-arm predicate mismatch: retained stateful re-arm canonical plan digest differs"_ctv,
          "retained_rearm_rejects_plan_mismatch_with_exact_predicate");
  mismatched = request;
  mismatched.proof.scope.artifactSHA256.assign(
      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"_ctv);
  rejects(mismatched,
          "retained stateful re-arm predicate mismatch: retained stateful re-arm artifact identity differs"_ctv,
          "retained_rearm_rejects_artifact_digest_mismatch_with_exact_predicate");
  mismatched = request;
  ++mismatched.proof.scope.artifactBytes;
  rejects(mismatched,
          "retained stateful re-arm predicate mismatch: retained stateful re-arm artifact identity differs"_ctv,
          "retained_rearm_rejects_artifact_size_mismatch_with_exact_predicate");
  mismatched = request;
  mismatched.proof.scope.machineUUIDs[2] = uint128_t(0x7104);
  rejects(mismatched,
          "retained stateful re-arm predicate mismatch: retained stateful re-arm machine identity set differs"_ctv,
          "retained_rearm_rejects_machine_set_mismatch_with_exact_predicate");
  mismatched = request;
  mismatched.proof.scope.retainedMembers[0].containerUUID = uint128_t(0x7200);
  rejects(mismatched,
          "retained stateful re-arm predicate mismatch: retained stateful re-arm retained storage identity differs"_ctv,
          "retained_rearm_rejects_storage_owner_mismatch_with_exact_predicate");

  ApplicationDeployment successor = {};
  deployment->next = &successor;
  rejects(request,
          "retained stateful re-arm predicate mismatch: retained stateful re-arm target has a predecessor or successor"_ctv,
          "retained_rearm_rejects_existing_successor_with_exact_predicate");
  deployment->next = nullptr;
  FailedDeploymentRecord tombstone = {};
  tombstone.deploymentID = deploymentID;
  brain.failedDeployments.insert_or_assign(deploymentID, tombstone);
  rejects(request,
          "retained stateful re-arm predicate mismatch: retained stateful re-arm target has a terminal tombstone"_ctv,
          "retained_rearm_rejects_terminal_tombstone_with_exact_predicate");
  brain.failedDeployments.erase(deploymentID);
  ProdigyMaterializedStatefulRecoveryOperation conflicting = {};
  conflicting.operationID.assign("123e4567-e89b-42d3-a456-426614174014"_ctv);
  conflicting.successorDeploymentID = deploymentID;
  conflicting.successorBlobSHA256 = scope.artifactSHA256;
  conflicting.accepted = conflicting.started = true;
  brain.masterAuthorityRuntimeState.materializedStatefulRecoveryOperations.push_back(conflicting);
  RearmRetainedStatefulDeployment conflictResponse = {};
  suite.expect(issueDeploymentLifecycleOperationForTest<MothershipTopic::rearmRetainedStatefulDeployment>(
                   brain, mothership, request, conflictResponse) && !conflictResponse.success &&
                   conflictResponse.failure.equal(
                       "retained stateful deployment is already owned by another recovery operation"_ctv),
               "retained_rearm_rejects_conflicting_recovery_operation");
  brain.masterAuthorityRuntimeState.materializedStatefulRecoveryOperations.clear();
  mismatched = request;
  mismatched.proof.scope.expectedIPv6Only = false;
  RearmRetainedStatefulDeployment networkResponse = {};
  suite.expect(issueDeploymentLifecycleOperationForTest<MothershipTopic::rearmRetainedStatefulDeployment>(
                   brain, mothership, mismatched, networkResponse) && !networkResponse.success &&
                   networkResponse.failure.equal("invalid retained stateful re-arm request"_ctv),
               "retained_rearm_rejects_non_ipv6_scope");
  peers[0].containerRetirementCapabilityAcknowledged = false;
  RearmRetainedStatefulDeployment staleAuthorityResponse = {};
  suite.expect(issueDeploymentLifecycleOperationForTest<MothershipTopic::rearmRetainedStatefulDeployment>(
                   brain, mothership, request, staleAuthorityResponse) && !staleAuthorityResponse.success &&
                   staleAuthorityResponse.failure.equal(
                       "retained stateful re-arm predicate mismatch: retained stateful re-arm authority is not acknowledged by the exact brain cohort"_ctv),
               "retained_rearm_rejects_unacknowledged_brain_authority");
  peers[0].containerRetirementCapabilityAcknowledged = true;

  auto dispatch = [&]() {
    mothership.wBuffer.clear();
    RearmRetainedStatefulDeployment mutableRequest = request;
    String payload = {}, frame = {};
    BitseryEngine::serialize(payload, mutableRequest);
    brain.mothershipHandler(&mothership,
        buildMothershipMessage(frame, MothershipTopic::rearmRetainedStatefulDeployment, payload));
  };
  brain.holdRuntimePersistence = true;
  dispatch();
  suite.expect(mothership.wBuffer.empty() && brain.pendingRuntimePersistence.size() == 1 &&
                   deployment->containers.size() == 2,
               "retained_rearm_waits_for_durable_acceptance_before_mutation");
  brain.finishRuntimePersistence(false);
  RearmRetainedStatefulDeployment failedPersistence = {};
  suite.expect(extractAsyncRequestResponse(mothership.wBuffer,
                   MothershipTopic::rearmRetainedStatefulDeployment, failedPersistence) &&
                   !failedPersistence.success &&
                   failedPersistence.failure.equal("retained stateful re-arm durable acceptance failed"_ctv) &&
                   brain.masterAuthorityRuntimeState.materializedStatefulRecoveryOperations.empty() &&
                   brain.masterAuthorityRuntimeState.retainedStatefulRearmProofs.empty() &&
                   deployment->containers.size() == 2,
               "retained_rearm_failed_receipt_rolls_back_without_launch");

  // The second durable receipt is deliberately delivered after the client
  // disappears. The exact request must then resume from the saved operation
  // without admitting or scheduling a second candidate.
  dispatch();
  suite.require(mothership.wBuffer.empty() && brain.pendingRuntimePersistence.size() == 1,
                "retained_rearm_lost_response_fixture_waits_for_receipt");
  brain.activeMotherships.erase(&mothership);
  brain.finishRuntimePersistence(true);
  suite.expect(mothership.wBuffer.empty() &&
                   brain.masterAuthorityRuntimeState.materializedStatefulRecoveryOperations.size() == 1 &&
                   brain.masterAuthorityRuntimeState.retainedStatefulRearmProofs.size() == 1 &&
                   deployment->nTarget() == 0 && deployment->containers.size() == 2,
               "retained_rearm_lost_response_still_persists_one_operation");
  String authorityBytes = {};
  auto authorityCopy = brain.masterAuthorityRuntimeState;
  ProdigyMasterAuthorityRuntimeState reloadedAuthority = {};
  suite.require(BitseryEngine::serialize(authorityBytes, authorityCopy) &&
                    BitseryEngine::deserializeSafe(authorityBytes, reloadedAuthority) &&
                    prodigyRetainedStatefulRearmProofsValid(reloadedAuthority),
                "retained_rearm_operation_survives_authority_process_reload");
  brain.masterAuthorityRuntimeState = std::move(reloadedAuthority);
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = brain.masterAuthorityRuntimeState.generation;
  deployment->plan.stateful.allowUpdateInPlace = false;
  suite.require(acknowledgeCurrentAuthority(),
                "retained_rearm_final_peer_receipt_wakes_recovered_scheduler");
  suite.expect(deployment->nTarget() == 0 && deployment->containers.size() == 2,
               "retained_rearm_reloaded_operation_rejects_plan_semantic_drift");
  deployment->plan.stateful.allowUpdateInPlace = true;
  const uint128_t originalTopologyMachine = brain.authoritativeTopology.machines[2].uuid;
  brain.authoritativeTopology.machines[2].uuid = uint128_t(0x7104);
  brain.recoverDeploymentsAfterNeuronState();
  suite.expect(deployment->nTarget() == 0 && deployment->containers.size() == 2,
               "retained_rearm_reloaded_operation_rejects_vm_identity_drift");
  brain.authoritativeTopology.machines[2].uuid = originalTopologyMachine;
  brain.recoverDeploymentsAfterNeuronState();
  brain.activeMotherships.insert(&mothership);
  RearmRetainedStatefulDeployment replay = {};
  const bool replayIssued =
      issueDeploymentLifecycleOperationForTest<MothershipTopic::rearmRetainedStatefulDeployment>(
          brain, mothership, request, replay);
  const bool replayExact = replayIssued && replay.success && replay.idempotent &&
      replay.proof.acceptedAtMs > 0 && replay.durableGeneration >= 42 && deployment->nTarget() == 3 &&
      brain.masterAuthorityRuntimeState.materializedStatefulRecoveryOperations.size() == 1 &&
      brain.masterAuthorityRuntimeState.retainedStatefulRearmProofs.size() == 1;
  suite.expect(replayExact,
               "retained_rearm_nonzero_target_lost_response_retry_is_exactly_idempotent");
  auto changed = request;
  changed.proof.scope.retainedMembers[0].machineUUID = machineUUIDs[2];
  changed.proof.retainedStateSHA256.clear();
  prodigyRetainedStatefulRearmScopeSHA256(changed.proof.scope, changed.proof.retainedStateSHA256);
  RearmRetainedStatefulDeployment rejected = {};
  suite.expect(issueDeploymentLifecycleOperationForTest<MothershipTopic::rearmRetainedStatefulDeployment>(
                   brain, mothership, changed, rejected) && !rejected.success &&
                   rejected.failure.equal("retained stateful re-arm operationID collision"_ctv),
               "retained_rearm_rejects_changed_storage_owner_on_replay");

  ContainerView *replacement = nullptr;
  for (ContainerView *container : deployment->containers)
    if (container != &retained[0] && container != &retained[1]) replacement = container;
  suite.require(replacement != nullptr, "retained_rearm_schedules_one_missing_replica");
  if (replacement != nullptr)
  {
    suite.expect(deployment->containers.size() == 3 && deployment->waitingOnContainers.size() == 1,
                 "retained_rearm_schedules_exactly_one_missing_replica");
    suite.expect(replacement->machine == &machines[2] &&
                     replacement->machine->uuid == scope.machineUUIDs[2],
                 "retained_rearm_schedules_the_exact_missing_vm_identity");
    brain.recoverDeploymentsAfterNeuronState();
    suite.expect(deployment->containers.size() == 3 && deployment->waitingOnContainers.size() == 1,
                 "retained_rearm_partial_launch_does_not_duplicate_replica");
    suite.expect(deployment->containers.size() == 3 && deployment->waitingOnContainers.size() == 1 &&
                     brain.containers.at(retained[0].uuid) == &retained[0] &&
                     brain.containers.at(retained[1].uuid) == &retained[1] &&
                     retained[0].machine == &machines[0] && retained[1].machine == &machines[1] &&
                     deployment->plan.config.applicationID == applicationID &&
                     deployment->plan.config.versionID == versionID &&
                     deployment->plan.config.deploymentID() == deploymentID &&
                     deployment->plan.stateful.allMasters && !deployment->plan.useHostNetworkNamespace,
                 "retained_rearm_preserves_deployment_storage_vm_and_ipv6_identity");
    brain.recoverDeploymentsAfterNeuronState();
    suite.expect(deployment->containers.size() == 3 && deployment->waitingOnContainers.size() == 1,
                 "retained_rearm_reloaded_operation_partial_launch_remains_exactly_once");
    deployment->destructContainer(replacement);
    deployment->containerDestroyed(replacement);
  }
  brain.activeMotherships.erase(&mothership);
  brain.containers.clear();
  deployment->containers.clear();
  brain.deployments.clear();
  brain.deploymentsByApp.clear();
  brain.deploymentPlans.clear();
  brain.statefulServingRuntimeStates.clear();
  for (uint32_t index = 0; index < 2; ++index) brain.brains.erase(&peers[index]);
  for (uint32_t index = 0; index < 3; ++index)
  {
    machines[index].containersByDeploymentID.clear();
    racks[index].machines.erase(&machines[index]);
    brain.machines.erase(&machines[index]);
    brain.machinesByUUID.erase(machines[index].uuid);
    brain.racks.erase(racks[index].uuid);
  }
  delete deployment;
  thisBrain = savedBrain;
  thisNeuron = savedNeuron;
}

static void testMaterializedRecoveryBlockers(TestSuite& suite)
{
  ScopedRing scopedRing;
  TestBrain brain = {};
  String blocker = {};
  brain.recoveringPersistedNeuronInventory = true;
  suite.expect(!brain.finalizePersistedNeuronInventoryRecovery(&blocker) &&
                   blocker.equal("persisted machine inventory is not enumerated"_ctv),
               "materialized_recovery_reports_unenumerated_inventory_blocker");

  brain.persistedMachineInventoryEnumerated = true;
  blocker.clear();
  suite.expect(!brain.finalizePersistedNeuronInventoryRecovery(&blocker) &&
                   blocker.equal("no machine inventory is available"_ctv),
               "materialized_recovery_reports_empty_machine_inventory_blocker");

  constexpr uint16_t applicationID = 63113;
  constexpr uint64_t deploymentID = (uint64_t(applicationID) << 48) | 1;
  ApplicationDeployment retained = {};
  retained.plan = makeDeploymentPlan(applicationID, 1);
  retained.plan.config.type = ApplicationType::stateful;
  retained.plan.isStateful = true;
  ContainerView retainedRuntimes[3] = {};
  for (uint32_t index = 0; index < 3; ++index)
  {
    retainedRuntimes[index].uuid = uint128_t(0x63113001 + index);
    retainedRuntimes[index].deploymentID = deploymentID;
    retainedRuntimes[index].applicationID = applicationID;
    retained.containers.insert(&retainedRuntimes[index]);
  }
  brain.deploymentsByApp.insert_or_assign(applicationID, &retained);
  blocker.clear();
  suite.expect(!brain.materializedRecoveryCanonicalActiveDeployment(applicationID, deploymentID, blocker) &&
                   blocker.equal("canonical active deployment owner is missing while the application report retains runtimes"_ctv),
               "materialized_recovery_rejects_retained_report_without_canonical_owner");

  ApplicationDeployment canonicalEmpty = {};
  canonicalEmpty.plan = retained.plan;
  brain.deployments.insert_or_assign(deploymentID, &canonicalEmpty);
  blocker.clear();
  suite.expect(!brain.materializedRecoveryCanonicalActiveDeployment(applicationID, deploymentID, blocker) &&
                   blocker.equal("application report and canonical active deployment owners differ"_ctv),
               "materialized_recovery_rejects_three_reported_runtimes_against_empty_canonical_cohort");

  Machine machine = {};
  machine.uuid = 0x63113002;
  blocker.clear();
  suite.expect(!brain.durableRecoveryWitnessBootstrapsProjectable(&machine, {}, blocker) &&
                   blocker.equal("durable retained bootstrap machine identity or fragment is unavailable"_ctv),
               "materialized_recovery_rejects_zero_fragment_durable_witness_projection");
  machine.fragment = 0x6311;
  brain.masterAuthorityRuntimeState.machineFragmentAssignments.push_back({machine.uuid, machine.fragment});
  blocker.clear();
  suite.expect(brain.durableRecoveryWitnessBootstrapsProjectable(&machine, {}, blocker) && blocker.empty(),
               "materialized_recovery_accepts_authoritative_empty_machine_witness");

  BrainBase *savedBrain = thisBrain;
  thisBrain = &brain;
  brain.weAreMaster = true;
  brain.ignited = true;
  String name = "materialized-recovery-blocker-test"_ctv;
  brain.reservedApplicationNamesByID.insert_or_assign(applicationID, name);
  Mothership mothership = {};
  mothership.isFixedFile = true;
  mothership.fslot = 99;
  brain.activeMotherships.insert(&mothership);
  RecoverMaterializedStatefulDeployment request = {};
  request.applicationName = name;
  request.applicationID = applicationID;
  request.activeVersionID = 1;
  request.successorVersionID = 2;
  request.operationID.assign("123e4567-e89b-42d3-a456-426614174011"_ctv);
  request.successorBlobSHA256.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
  String payload = {}, frame = {};
  BitseryEngine::serialize(payload, request);
  brain.mothershipHandler(&mothership, buildMothershipMessage(
      frame, MothershipTopic::recoverMaterializedStatefulDeployment, payload));
  RecoverMaterializedStatefulDeployment response = {};
  suite.expect(extractAsyncRequestResponse(mothership.wBuffer,
                   MothershipTopic::recoverMaterializedStatefulDeployment, response) && !response.success &&
                   response.failure.equal("materialized stateful recovery inventory is not authoritative: no machine inventory is available"_ctv),
               "materialized_recovery_returns_exact_inventory_blocker_to_mothership");
  mothership.wBuffer.clear();
  request.retryFailedSuccessor = true;
  request.replacementSuccessorVersionID = 3;
  request.replacementSuccessorBlobSHA256.assign("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv);
  request.sourceContainerUUID = 1;
  request.failedSuccessorContainerUUID = 2;
  request.sourceMachineUUID = 3;
  request.sourceDevice = 4;
  request.sourceInode = 5;
  request.sourcePID = 6;
  request.captureSHA256.assign("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"_ctv);
  payload.clear(); frame.clear();
  BitseryEngine::serialize(payload, request);
  brain.mothershipHandler(&mothership, buildMothershipMessage(
      frame, MothershipTopic::recoverMaterializedStatefulDeployment, payload));
  response = {};
  suite.expect(extractAsyncRequestResponse(mothership.wBuffer,
                   MothershipTopic::recoverMaterializedStatefulDeployment, response) && !response.success &&
                   response.failure.equal("materialized stateful recovery retry inventory is not authoritative: no machine inventory is available"_ctv),
               "materialized_recovery_retry_returns_exact_inventory_blocker_to_mothership");
  brain.activeMotherships.erase(&mothership);
  thisBrain = savedBrain;
}
