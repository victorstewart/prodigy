// Include after prodigy_brain_replication_credentials_unit.cpp shared fixtures.
static void testUpgradeAdmissionObservationFences(TestSuite& suite)
{
  ScopedAsyncMothershipRing ring = {};
  TestNeuron local = {};
  NeuronBase *previousNeuron = thisNeuron;
  local.uuid = uint128_t(0x550);
  thisNeuron = &local;
  TestBrain brain = {};
  brain.weAreMaster = true; brain.noMasterYet = false;
  brain.boottimens = 97;
  brain.masterAuthorityRuntimeState.generation = 41;
  BrainView peer = {};
  peer.uuid = uint128_t(0x551); peer.boottimens = 991; peer.ioGeneration = 7;
  peer.registrationFresh = true;
  brain.brains.insert(&peer);
  auto& pending = brain.upgradeAdmissionObservation;
  pending.receiptVersion = 9; pending.authorityGeneration = 41; pending.nonce = 13;
  pending.capacityRequest.operationID.assignItoh(uint128_t(1));
  for (uint32_t i = 0; i < 64; ++i) { pending.capacityRequest.targetBundleSHA256.append('a'); pending.capacityRequest.targetContractSHA256.append('b'); }
  pending.capacityRequest.requiredStagingBytes = 4096;
  pending.requestedAtMs = Time::msSinceBoot();
  pending.expectedPeerGenerations.insert_or_assign(peer.uuid, peer.ioGeneration);
  pending.commissionedPeerUUIDs.insert(peer.uuid); pending.requiredPeerCount = 1;
  auto send = [&](ProdigyUpgradeAdmissionPeerObservation response) {
    String payload = {}, frame = {}; BitseryEngine::serialize(payload, response);
    brain.brainHandler(&peer, buildBrainMessage(frame, BrainTopic::observeUpgradeAdmissionResponse, payload));
  };
  auto valid = [&] {
    ProdigyUpgradeAdmissionPeerObservation r = {};
    r.brainUUID = peer.uuid; r.machineUUID = peer.uuid; r.receiptVersion = pending.receiptVersion;
    r.authorityGeneration = pending.authorityGeneration; r.requesterTransportGeneration = peer.ioGeneration;
    r.masterUUID = brain.selfBrainUUID(); r.masterBootNs = brain.boottimens; r.nonce = pending.nonce;
    r.observedAtMs = 1; r.operationID.assign(pending.capacityRequest.operationID);
    r.targetBundleSHA256.assign(pending.capacityRequest.targetBundleSHA256);
    r.targetContractSHA256.assign(pending.capacityRequest.targetContractSHA256);
    r.requiredStagingBytes = pending.capacityRequest.requiredStagingBytes;
    r.stagingCapacityProbeComplete = r.stagingCapacityVerified = true; r.stagingAvailableBytes = 4096;
    return r;
  };
  auto r = valid(); send(r);
  suite.expect(pending.received.size() == 1, "upgrade_observation_accepts_exact_fence");
  const uint64_t acceptedNonce = pending.nonce;
  r.nonce += 1; send(r);
  suite.expect(pending.received.size() == 1 && pending.received.contains(peer.uuid) &&
                   pending.received.at(peer.uuid).nonce == acceptedNonce,
               "upgrade_observation_rejects_wrong_nonce_without_overwrite");
  pending.received.clear(); r = valid(); r.masterBootNs += 1; send(r);
  suite.expect(pending.received.empty(), "upgrade_observation_rejects_wrong_master_boot");
  r = valid(); r.masterUUID += 1; send(r);
  suite.expect(pending.received.empty(), "upgrade_observation_rejects_cross_master_response");
  r = valid(); r.authorityGeneration += 1; send(r);
  suite.expect(pending.received.empty(), "upgrade_observation_rejects_wrong_generation");
  r = valid(); r.requesterTransportGeneration += 1; send(r);
  suite.expect(pending.received.empty(), "upgrade_observation_rejects_wrong_transport_generation");
  r = valid(); r.targetBundleSHA256[0] = 'c'; send(r);
  suite.expect(pending.received.empty(), "upgrade_observation_rejects_wrong_target_capacity_response");
  r = valid(); pending.requestedAtMs = Time::msSinceBoot() - 30'001; send(r);
  suite.expect(pending.received.empty(), "upgrade_observation_rejects_stale_local_receipt");
  brain.brains.erase(&peer);
  thisNeuron = previousNeuron;
}

static void testAdmittedUpdateRejectsUnfencedRequests(TestSuite& suite)
{
  ScopedAsyncMothershipRing ring = {};
  TestNeuron local = {};
  local.uuid = uint128_t(0xA551);
  String sourceDigest = {};
  for (uint32_t index = 0; index < 64; ++index) sourceDigest.append('a');
  local.setInstalledBundleDigestForTest(sourceDigest);
  NeuronBase *previousNeuron = thisNeuron;
  thisNeuron = &local;
  TestBrain brain = {};
  brain.weAreMaster = true; brain.noMasterYet = false; brain.nBrains = 1;
  brain.boottimens = 91; brain.brainConfig.clusterUUID = uint128_t(0xA556);
  brain.masterAuthorityRuntimeState.generation = 17;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = 17;
  Machine localMachine = {};
  localMachine.uuid = local.uuid; localMachine.isThisMachine = true; localMachine.isBrain = true;
  localMachine.state = MachineState::healthy; localMachine.runtimeReady = true;
  brain.machines.insert(&localMachine); brain.machinesByUUID.insert_or_assign(local.uuid, &localMachine);
  brain.persistedMachineInventoryUploaded.insert(local.uuid);
  brain.persistedMachineStateUploadPlansByMachine.insert_or_assign(local.uuid, Vector<String>{});
  Mothership mothership = {};

  MothershipUpgradeAdmissionReport report = {};
  brain.collectUpgradeAdmissionReport(report);
  if (suite.require(report.observationComplete && report.masterApprovedBundleSHA256 == sourceDigest,
                    "admitted_update_rejection_fixture_has_fresh_complete_observation") == false)
  {
    brain.machinesByUUID.erase(local.uuid); brain.machines.erase(&localMachine);
    thisNeuron = previousNeuron;
    return;
  }

  String target = "not-the-target"_ctv, targetDigest = {}, contractDigest = {}, hashFailure = {};
  if (suite.require(prodigyComputeSHA256Hex(target, targetDigest, &hashFailure),
                    "admitted_update_rejection_fixture_hashes_target") == false)
  {
    brain.machinesByUUID.erase(local.uuid); brain.machines.erase(&localMachine);
    thisNeuron = previousNeuron;
    return;
  }
  for (uint32_t index = 0; index < 64; ++index) contractDigest.append('c');
  ProdigyAdmittedUpdateRequest request = {};
  request.operationID.assignItoh(uint128_t(1));
  uint128_t parsedOperationID = 0;
  if (suite.require(prodigyParseCanonicalHex128(request.operationID, parsedOperationID) &&
                        parsedOperationID == uint128_t(1),
                    "admitted_update_rejection_fixture_operation_id_is_canonical") == false)
  {
    brain.machinesByUUID.erase(local.uuid); brain.machines.erase(&localMachine);
    thisNeuron = previousNeuron;
    return;
  }
  request.sourceBundleSHA256 = sourceDigest;
  request.targetBundleSHA256 = targetDigest;
  request.targetContractSHA256 = contractDigest;
  request.requiredStagingBytes = 1;
  ProdigyUpgradeAdmissionReportRequest capacityRequest = {};
  capacityRequest.operationID.assign(request.operationID);
  capacityRequest.targetBundleSHA256.assign(targetDigest);
  capacityRequest.targetContractSHA256.assign(contractDigest);
  capacityRequest.requiredStagingBytes = request.requiredStagingBytes;
  brain.beginUpgradeAdmissionObservation(&capacityRequest);
  for (uint32_t attempt = 0; attempt < 20 && !brain.upgradeAdmissionObservation.localCapacityMeasurementComplete; ++attempt) ring.runFor(10);
  brain.collectUpgradeAdmissionReport(report);
  request.authorityGeneration = report.authorityGeneration;
  request.masterUUID = report.masterUUID;
  request.masterBootNs = report.masterBootNs;
  request.receiptVersion = report.observationReceiptVersion;
  request.nonce = report.observationNonce;

  auto expectRejected = [&](const ProdigyAdmittedUpdateRequest& mutated, const char *failure,
                            const char *name) {
    String serialized = {}, frame = {};
    ProdigyAdmittedUpdateRequest encoded = mutated;
    BitseryEngine::serialize(serialized, encoded);
    brain.mothershipHandler(&mothership,
                            buildMothershipMessage(frame, MothershipTopic::updateProdigyAdmitted,
                                                   serialized, target));
    if (mothership.wBuffer.size() < sizeof(Message))
    {
      suite.expect(false, name);
      return;
    }
    Message *response = reinterpret_cast<Message *>(mothership.wBuffer.data());
    String responseBytes = {}; uint8_t *args = response->args;
    Message::extractToStringView(args, responseBytes);
    MothershipResponse result = {};
    suite.expect(MothershipTopic(response->topic) == MothershipTopic::updateProdigyAdmitted &&
                     args == response->terminal() && BitseryEngine::deserializeSafe(responseBytes, result) &&
                     !result.success && result.failure.equals(String(failure)) &&
                     brain.pendingMothershipUpdateArtifact == nullptr && brain.transitionToNewBundleCalls == 0,
                 name);
    mothership.wBuffer.clear();
  };

  ProdigyAdmittedUpdateRequest mutated = request;
  mutated.authorityGeneration += 1;
  expectRejected(mutated, "admitted update authority observation is stale",
                 "admitted_update_rejects_stale_generation_before_staging");
  mutated = request; mutated.masterUUID += 1;
  expectRejected(mutated, "admitted update authority observation is stale",
                 "admitted_update_rejects_cross_master_before_staging");
  mutated = request; mutated.masterBootNs += 1;
  expectRejected(mutated, "admitted update authority observation is stale",
                 "admitted_update_rejects_stale_master_boot_before_staging");
  mutated = request; mutated.receiptVersion += 1;
  expectRejected(mutated, "admitted update authority observation is stale",
                 "admitted_update_rejects_stale_receipt_before_staging");
  mutated = request; mutated.nonce += 1;
  expectRejected(mutated, "admitted update authority observation is stale",
                 "admitted_update_rejects_stale_nonce_before_staging");
  mutated = request; mutated.sourceBundleSHA256[0] = 'd';
  expectRejected(mutated, "admitted update authority observation is stale",
                 "admitted_update_rejects_source_digest_mismatch_before_staging");
  mutated = request; mutated.targetBundleSHA256[0] = 'd';
  expectRejected(mutated, "admitted update authority observation is stale",
                 "admitted_update_rejects_target_binding_mismatch_before_staging");

  String legacyFrame = {};
  Message::construct(legacyFrame, MothershipTopic::updateProdigy, "unapproved-bundle"_ctv);
  brain.mothershipHandler(&mothership, reinterpret_cast<Message *>(legacyFrame.data()));
  Message *legacyResponse = mothership.wBuffer.size() < sizeof(Message) ? nullptr :
      reinterpret_cast<Message *>(mothership.wBuffer.data());
  String legacyBytes = {}; MothershipResponse legacyResult = {};
  if (legacyResponse != nullptr)
  {
    uint8_t *args = legacyResponse->args;
    Message::extractToStringView(args, legacyBytes);
    suite.expect(MothershipTopic(legacyResponse->topic) == MothershipTopic::updateProdigy &&
                     args == legacyResponse->terminal() && BitseryEngine::deserializeSafe(legacyBytes, legacyResult) &&
                     !legacyResult.success && legacyResult.failure == "legacy updateProdigy is not an admission path"_ctv,
                 "legacy_update_topic_is_not_an_admission_bypass");
  }
  else suite.expect(false, "legacy_update_topic_emits_rejection");
  if (brain.artifactIO)
  {
    suite.expect(quiesceArtifactIOForTest(brain.artifactIO.get()),
                 "admitted_update_rejection_quiesces_capacity_probe_io");
    brain.artifactIO.reset();
  }
  brain.machinesByUUID.erase(local.uuid); brain.machines.erase(&localMachine);
  thisNeuron = previousNeuron;
}

static void testAdmittedUpdateCanonicalOperationPassesFreshFence(TestSuite& suite)
{
  ScopedAsyncMothershipRing ring = {};
  TestNeuron localNeuron = {};
  localNeuron.uuid = uint128_t(0xA552);
  String sourceDigest = {};
  for (uint32_t index = 0; index < 64; ++index) sourceDigest.append('a');
  localNeuron.setInstalledBundleDigestForTest(sourceDigest);
  NeuronBase *previousNeuron = thisNeuron;
  thisNeuron = &localNeuron;
  TestBrain brain = {};
  brain.weAreMaster = true; brain.noMasterYet = false; brain.nBrains = 1;
  brain.boottimens = 92; brain.brainConfig.clusterUUID = uint128_t(0xA553);
  brain.masterAuthorityRuntimeState.generation = 18;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = 18;
  Machine local = {};
  local.uuid = localNeuron.uuid; local.isThisMachine = true; local.isBrain = true;
  local.state = MachineState::healthy; local.runtimeReady = true;
  brain.machines.insert(&local); brain.machinesByUUID.insert_or_assign(local.uuid, &local);
  brain.persistedMachineInventoryUploaded.insert(local.uuid);
  brain.persistedMachineStateUploadPlansByMachine.insert_or_assign(local.uuid, Vector<String>{});
  ScopedSocketPair sockets = {};
  Mothership mothership = {};
  if (suite.require(sockets.create(suite, "admitted_update_canonical_operation_socket_pair"),
                    "admitted_update_canonical_operation_requires_socket_pair") == false)
  {
    thisNeuron = previousNeuron;
    return;
  }
  mothership.isFixedFile = true;
  mothership.fslot = sockets.adoptLeftIntoFixedFileSlot();
  if (suite.require(mothership.fslot >= 0 && brain.activateMothershipConnection(&mothership),
                    "admitted_update_canonical_operation_activates_mothership") == false)
  {
    thisNeuron = previousNeuron;
    return;
  }
  MothershipUpgradeAdmissionReport report = {};
  brain.collectUpgradeAdmissionReport(report);
  if (suite.require(report.observationComplete && report.masterApprovedBundleSHA256 == sourceDigest,
                    "admitted_update_canonical_operation_has_complete_one_brain_observation") == false)
  {
    brain.activeMotherships.erase(&mothership); brain.machinesByUUID.erase(local.uuid); brain.machines.erase(&local);
    thisNeuron = previousNeuron;
    return;
  }
  String target = "candidate-bytes"_ctv, targetDigest = {}, contractDigest = {};
  String hashFailure = {};
  suite.require(prodigyComputeSHA256Hex(target, targetDigest, &hashFailure),
                "admitted_update_canonical_operation_hashes_target");
  for (uint32_t index = 0; index < 64; ++index) contractDigest.append('c');
  ProdigyAdmittedUpdateRequest request = {};
  request.operationID.assignItoh(uint128_t(1));
  uint128_t parsedOperationID = 0;
  suite.require(prodigyParseCanonicalHex128(request.operationID, parsedOperationID) &&
                    parsedOperationID == uint128_t(1),
                "admitted_update_canonical_operation_id_is_canonical");
  request.sourceBundleSHA256 = sourceDigest; request.targetBundleSHA256 = targetDigest;
  request.targetContractSHA256 = contractDigest; request.authorityGeneration = report.authorityGeneration;
  request.masterUUID = report.masterUUID; request.masterBootNs = report.masterBootNs;
  request.requiredStagingBytes = 1;
  ProdigyUpgradeAdmissionReportRequest capacityRequest = {};
  capacityRequest.operationID.assign(request.operationID); capacityRequest.targetBundleSHA256.assign(targetDigest);
  capacityRequest.targetContractSHA256.assign(contractDigest); capacityRequest.requiredStagingBytes = 1;
  brain.beginUpgradeAdmissionObservation(&capacityRequest);
  for (uint32_t attempt = 0; attempt < 20 && !brain.upgradeAdmissionObservation.localCapacityMeasurementComplete; ++attempt) ring.runFor(10);
  brain.collectUpgradeAdmissionReport(report);
  request.authorityGeneration = report.authorityGeneration; request.masterUUID = report.masterUUID;
  request.masterBootNs = report.masterBootNs; request.receiptVersion = report.observationReceiptVersion; request.nonce = report.observationNonce;
  String serialized = {}, frame = {};
  BitseryEngine::serialize(serialized, request);
  brain.mothershipHandler(&mothership,
      buildMothershipMessage(frame, MothershipTopic::updateProdigyAdmitted, serialized, target));
  suite.expect(brain.pendingMothershipUpdateArtifact != nullptr && mothership.wBuffer.empty(),
               "admitted_update_canonical_0x_operation_passes_fresh_fence_to_async_proof");
  for (uint32_t attempt = 0; attempt < 100 && brain.pendingMothershipUpdateArtifact != nullptr; ++attempt)
    ring.runFor(20);
  String responseBytes = {};
  uint8_t receiveBuffer[4096] = {};
  for (;;)
  {
    const ssize_t received = ::recv(sockets.right, receiveBuffer, sizeof(receiveBuffer), 0);
    if (received <= 0) break;
    responseBytes.append(receiveBuffer, uint64_t(received));
  }
  MothershipResponse contractFailure = {};
  bool rejectedAfterAsyncProof = false;
  if (responseBytes.size() >= sizeof(Message))
  {
    Message *response = reinterpret_cast<Message *>(responseBytes.data());
    String serializedResponse = {}; uint8_t *args = response->args;
    Message::extractToStringView(args, serializedResponse);
    rejectedAfterAsyncProof = MothershipTopic(response->topic) == MothershipTopic::updateProdigyAdmitted &&
        args == response->terminal() && BitseryEngine::deserializeSafe(serializedResponse, contractFailure) &&
        !contractFailure.success &&
        contractFailure.failure == "bundle artifact preparation failed: admitted bundle contract proof differs"_ctv;
  }
  suite.expect(rejectedAfterAsyncProof && brain.pendingMothershipUpdateArtifact == nullptr,
               "admitted_update_async_contract_proof_mismatch_rejects_without_publish");
  if (brain.artifactIO)
  {
    suite.expect(quiesceArtifactIOForTest(brain.artifactIO.get()),
                 "admitted_update_async_contract_proof_quiesces_artifact_io");
    brain.artifactIO.reset();
  }
  brain.activeMotherships.erase(&mothership); brain.machinesByUUID.erase(local.uuid); brain.machines.erase(&local);
  thisNeuron = previousNeuron;
}

static void testUpgradeAdmissionObservedCapacityFacts(TestSuite& suite)
{
  MothershipUpgradeAdmissionReport report = {};
  report.commissionedBrainCount = 3;
  report.healthyCommissionedBrainCount = 2;
  report.activeDeploymentCount = 7;
  report.readySchedulableStorageBytes = 9ull * 1024ull * 1024ull;
  report.commissionedPeerTransportVerified = true;
  String bytes = {}; BitseryEngine::serialize(bytes, report);
  MothershipUpgradeAdmissionReport decoded = {};
  suite.expect(BitseryEngine::deserializeSafe(bytes, decoded) && decoded.commissionedBrainCount == 3 &&
      decoded.healthyCommissionedBrainCount == 2 && decoded.activeDeploymentCount == 7 &&
      decoded.readySchedulableStorageBytes == report.readySchedulableStorageBytes &&
      decoded.commissionedPeerTransportVerified,
               "upgrade_admission_observed_capacity_facts_roundtrip");
}

static void testUpgradeAdmissionComputedReadinessFacts(TestSuite& suite);

static void testUpgradeAdmissionTargetBoundStagingCapacity(TestSuite& suite)
{
  ScopedAsyncMothershipRing ring = {};
  TestNeuron local = {};
  local.uuid = uint128_t(0xCA91);
  String digest = {}; for (uint32_t i = 0; i < 64; ++i) digest.append('a');
  local.setInstalledBundleDigestForTest(digest);
  NeuronBase *previousNeuron = thisNeuron; thisNeuron = &local;
  TestBrain brain = {};
  brain.weAreMaster = true; brain.noMasterYet = false; brain.nBrains = 1;
  brain.boottimens = 71; brain.brainConfig.clusterUUID = uint128_t(0xCA92);
  brain.masterAuthorityRuntimeState.generation = 9;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = 9;
  brain.testUpgradeAdmissionCapacityAvailableBytes = 4096;
  Machine machine = {}; machine.uuid = local.uuid; machine.isThisMachine = machine.isBrain = true;
  machine.state = MachineState::healthy; machine.runtimeReady = true;
  brain.machines.insert(&machine); brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.persistedMachineInventoryUploaded.insert(machine.uuid);

  ProdigyUpgradeAdmissionReportRequest request = {};
  request.operationID.assignItoh(uint128_t(1));
  request.targetBundleSHA256.assign(digest);
  String contract = {}; for (uint32_t i = 0; i < 64; ++i) contract.append('b');
  request.targetContractSHA256.assign(contract); request.requiredStagingBytes = 4096;
  brain.beginUpgradeAdmissionObservation(&request);
  for (uint32_t i = 0; i < 20 && !brain.upgradeAdmissionObservation.localCapacityMeasurementComplete; ++i) ring.runFor(10);
  MothershipUpgradeAdmissionReport report = {};
  brain.collectUpgradeAdmissionReport(report);
  suite.expect(report.version == 4 && report.operationID == request.operationID &&
                   report.targetBundleSHA256 == request.targetBundleSHA256 &&
                   report.targetContractSHA256 == request.targetContractSHA256 &&
                   report.requiredStagingBytes == request.requiredStagingBytes &&
                   report.stagingCapacityResponsesComplete && report.stagingCapacityComplete &&
                   report.peers.size() == 1 && report.peers[0].stagingCapacityProbeComplete &&
                   report.peers[0].stagingAvailableBytes == 4096,
               "upgrade_admission_capacity_binds_exact_target_and_actual_async_probe");
  ProdigyAdmittedUpdateRequest emptyRequest = {};
  emptyRequest.operationID.assign(request.operationID);
  emptyRequest.sourceBundleSHA256.assign(digest);
  emptyRequest.targetBundleSHA256.assign(request.targetBundleSHA256);
  emptyRequest.targetContractSHA256.assign(request.targetContractSHA256);
  emptyRequest.requiredStagingBytes = request.requiredStagingBytes;
  emptyRequest.requiresEmptyWorkloadSet = true;
  emptyRequest.authorityGeneration = report.authorityGeneration;
  emptyRequest.masterUUID = report.masterUUID; emptyRequest.masterBootNs = report.masterBootNs;
  emptyRequest.receiptVersion = report.observationReceiptVersion; emptyRequest.nonce = report.observationNonce;
  suite.expect(brain.admittedUpdateObservationIsCurrent(emptyRequest),
               "upgrade_admission_empty_execution_fence_accepts_current_empty_workload_set");
  String encodedEmpty = {}; BitseryEngine::serialize(encodedEmpty, emptyRequest);
  ProdigyAdmittedUpdateRequest decodedEmpty = {};
  suite.expect(BitseryEngine::deserializeSafe(encodedEmpty, decodedEmpty) && decodedEmpty.requiresEmptyWorkloadSet &&
                   decodedEmpty.requiredStagingBytes == emptyRequest.requiredStagingBytes,
               "upgrade_admission_execution_request_roundtrip_retains_empty_and_capacity_fences");
  emptyRequest.operationID.assignItoh(uint128_t(9));
  suite.expect(!brain.admittedUpdateObservationIsCurrent(emptyRequest),
               "upgrade_admission_execution_fence_rejects_another_operation_using_same_target");
  emptyRequest.operationID.assign(request.operationID);
  DeploymentPlan pendingPlan = {};
  brain.deploymentPlans.insert_or_assign(99, pendingPlan);
  brain.collectUpgradeAdmissionReport(report);
  suite.expect(report.activeDeploymentCount == 1,
               "upgrade_admission_report_conservatively_counts_unmaterialized_deployment_plan");
  suite.expect(!brain.admittedUpdateObservationIsCurrent(emptyRequest),
               "upgrade_admission_empty_execution_fence_rejects_new_workload_after_observation");
  brain.deploymentPlans.erase(99);
  brain.pendingMothershipSpinArtifacts.insert_or_assign(100, nullptr);
  suite.expect(brain.upgradeAdmissionActiveDeploymentCount() == 1 && !brain.admittedUpdateObservationIsCurrent(emptyRequest),
               "upgrade_admission_empty_execution_fence_includes_pending_artifact_admission");
  brain.pendingMothershipSpinArtifacts.erase(100);

  brain.testUpgradeAdmissionCapacityAvailableBytes = 4095;
  request.operationID.assignItoh(uint128_t(2));
  brain.beginUpgradeAdmissionObservation(&request);
  for (uint32_t i = 0; i < 20 && !brain.upgradeAdmissionObservation.localCapacityMeasurementComplete; ++i) ring.runFor(10);
  brain.collectUpgradeAdmissionReport(report);
  suite.expect(report.stagingCapacityResponsesComplete && !report.stagingCapacityComplete &&
                   report.peers.size() == 1 && report.peers[0].stagingAvailableBytes == 4095 &&
                   !report.peers[0].stagingCapacityVerified,
               "upgrade_admission_capacity_rejects_insufficient_exact_target_probe");

  brain.testUpgradeAdmissionCapacityProbeSucceeds = false;
  request.operationID.assignItoh(uint128_t(3));
  brain.beginUpgradeAdmissionObservation(&request);
  for (uint32_t i = 0; i < 20 && !brain.upgradeAdmissionObservation.localCapacityMeasurementComplete; ++i) ring.runFor(10);
  brain.collectUpgradeAdmissionReport(report);
  suite.expect(report.stagingCapacityResponsesComplete && !report.stagingCapacityComplete &&
                   report.peers.size() == 1 && !report.peers[0].stagingCapacityVerified,
               "upgrade_admission_capacity_rejects_probe_failure");
  const uint64_t expiredReceipt = report.observationReceiptVersion;
  brain.testUpgradeAdmissionCapacityProbeSucceeds = true;
  brain.testUpgradeAdmissionCapacityAvailableBytes = 4096;
  brain.upgradeAdmissionObservation.requestedAtMs = 0;
  brain.collectUpgradeAdmissionReport(report);
  for (uint32_t i = 0; i < 20 && !brain.upgradeAdmissionObservation.localCapacityMeasurementComplete; ++i) ring.runFor(10);
  brain.collectUpgradeAdmissionReport(report);
  suite.expect(report.observationReceiptVersion != expiredReceipt && report.operationID == request.operationID &&
                   report.targetBundleSHA256 == request.targetBundleSHA256 &&
                   report.targetContractSHA256 == request.targetContractSHA256 && report.requiredStagingBytes == 4096 &&
                   report.stagingCapacityComplete,
               "upgrade_admission_expired_observation_refresh_preserves_owned_target_request");
  if (brain.artifactIO) { (void)quiesceArtifactIOForTest(brain.artifactIO.get()); brain.artifactIO.reset(); }
  brain.machinesByUUID.erase(machine.uuid); brain.machines.erase(&machine); thisNeuron = previousNeuron;
  testUpgradeAdmissionComputedReadinessFacts(suite);
}

static void testUpgradeAdmissionComputedReadinessFacts(TestSuite& suite)
{
  TestBrain brain = {};
  brain.weAreMaster = true; brain.noMasterYet = false;
  brain.masterAuthorityRuntimeState.generation = 5;
  Machine local = {}; local.uuid = 0x100; local.state = MachineState::healthy; local.runtimeReady = true;
  local.storageMB_available = 10;
  Machine followerMachine = {}; followerMachine.uuid = 0x200; followerMachine.state = MachineState::healthy;
  followerMachine.runtimeReady = true; followerMachine.storageMB_available = INT32_MAX;
  BrainView follower = {}; follower.uuid = followerMachine.uuid; follower.machine = &followerMachine;
  follower.registrationFresh = true; follower.connected = true; follower.isMasterBrain = false;
  follower.isFixedFile = true; follower.fslot = 17;
  brain.machines.insert(&local); brain.machines.insert(&followerMachine); brain.brains.insert(&follower);
  MothershipUpgradeAdmissionReport report = {};
  brain.collectUpgradeAdmissionReport(report);
  suite.expect(report.commissionedBrainCount == 2 && report.healthyCommissionedBrainCount == 2 &&
                   report.readySchedulableStorageBytes == (uint64_t(10) + uint64_t(INT32_MAX)) * 1024ull * 1024ull,
               "upgrade_admission_report_counts_healthy_commissioned_and_storage");
  suite.expect(!report.commissionedPeerTransportVerified,
               "upgrade_admission_report_does_not_treat_plaintext_peer_as_verified_tls");
  follower.connected = false; brain.collectUpgradeAdmissionReport(report);
  suite.expect(report.commissionedPeerTransportVerified == false,
               "upgrade_admission_report_rejects_disconnected_commissioned_peer_transport");
  follower.connected = true; followerMachine.runtimeReady = false; brain.collectUpgradeAdmissionReport(report);
  suite.expect(report.healthyCommissionedBrainCount == 1 &&
                   report.readySchedulableStorageBytes == uint64_t(10) * 1024ull * 1024ull,
               "upgrade_admission_report_excludes_nonruntime_ready_machine_capacity");
  followerMachine.runtimeReady = true;
  if (configureSingleNodeTransportRuntime(suite, "upgrade_admission_report_unverified_tls", follower.uuid))
  {
    reserveTransportStream(follower);
    if (suite.require(follower.beginTransportTLS(true),
                      "upgrade_admission_report_starts_unverified_tls_peer"))
    {
      brain.collectUpgradeAdmissionReport(report);
      suite.expect(report.commissionedPeerTransportVerified == false,
                   "upgrade_admission_report_rejects_unverified_tls_peer_transport");
    }
  }
  ProdigyTransportTLSRuntime::clear();
  {
    String failure = {}, rootCertPem = {}, rootKeyPem = {}, peerCertPem = {}, peerKeyPem = {};
    Vector<String> addresses = {};
    addresses.push_back("fd00::200"_ctv);
    ProdigyTransportTLSStream server = {};
    reserveTransportStream(follower);
    reserveTransportStream(server);
    if (suite.require(Vault::generateTransportRootCertificateEd25519(rootCertPem, rootKeyPem, &failure),
                      "upgrade_admission_report_verified_tls_generate_root") &&
        suite.require(Vault::generateTransportNodeCertificateEd25519(rootCertPem, rootKeyPem, follower.uuid,
                                                                      addresses, peerCertPem, peerKeyPem, &failure),
                      "upgrade_admission_report_verified_tls_generate_peer_leaf") &&
        suite.require(configureTransportRuntimeForNode(follower.uuid, rootCertPem, rootKeyPem, peerCertPem, peerKeyPem,
                                                       &failure),
                      "upgrade_admission_report_verified_tls_configure_client") &&
        suite.require(follower.beginTransportTLS(false), "upgrade_admission_report_verified_tls_begin_client") &&
        suite.require(configureTransportRuntimeForNode(follower.uuid, rootCertPem, rootKeyPem, peerCertPem, peerKeyPem,
                                                       &failure),
                      "upgrade_admission_report_verified_tls_configure_server") &&
        suite.require(server.beginTransportTLS(true), "upgrade_admission_report_verified_tls_begin_server") &&
        suite.require(completeTransportHandshake(follower, server),
                      "upgrade_admission_report_verified_tls_handshake") &&
        suite.require(brain.verifyBrainTransportTLSPeer(&follower),
                      "upgrade_admission_report_verified_tls_extracts_peer_uuid"))
    {
      suite.expect(follower.isTLSNegotiated() && follower.tlsPeerVerified &&
                       follower.tlsPeerUUID == follower.uuid,
                   "upgrade_admission_report_verified_tls_fixture_is_active_and_uuid_bound");
      brain.collectUpgradeAdmissionReport(report);
      suite.expect(report.commissionedPeerTransportVerified,
                   "upgrade_admission_report_accepts_active_verified_uuid_bound_tls_peer");
      follower.tlsPeerUUID = follower.uuid + 1;
      brain.collectUpgradeAdmissionReport(report);
      suite.expect(!report.commissionedPeerTransportVerified,
                   "upgrade_admission_report_rejects_active_verified_tls_peer_with_wrong_uuid_binding");
    }
  }
  ProdigyTransportTLSRuntime::clear();
  brain.brains.erase(&follower); brain.machines.erase(&followerMachine); brain.machines.erase(&local);
}

#ifndef PRODIGY_TEST_UPGRADE_BUNDLE
#define PRODIGY_TEST_UPGRADE_BUNDLE ""
#endif

static void testGeneratedUpgradeBundlePolicyAndAsyncOwner(TestSuite& suite)
{
  ScopedAsyncMothershipRing ring = {};
  ScopedTempDir stage = {};
  if (suite.require(stage.valid(), "generated_upgrade_bundle_owner_stage_created") == false) return;

  const String bundlePath = PRODIGY_TEST_UPGRADE_BUNDLE;
  if (suite.require(bundlePath.empty() == false, "generated_upgrade_bundle_fixture_path_configured") == false) return;

  String bundle = {};
  Filesystem::openReadAtClose(-1, bundlePath, bundle);
  if (suite.require(bundle.empty() == false, "generated_upgrade_bundle_fixture_bytes_available") == false) return;

  String digest = {}, failure = {};
  ProdigyApprovedUpgradeBundle approved = {};
  const bool approvedBundle = prodigyComputeSHA256Hex(bundle, digest, &failure) &&
      prodigyApproveBundleUpgradeContract(bundlePath, approved, &failure);
  if (suite.require(approvedBundle, "generated_upgrade_bundle_fixture_is_approved") == false) return;
  suite.expect(approved.bundleSHA256 == digest &&
                   approved.envelope.approvedBundleSHA256 == digest &&
                   approved.contract.contractSHA256 == approved.envelope.contractSHA256,
               "generated_upgrade_bundle_approval_binds_exact_bytes_and_contract");
  suite.expect(approved.contract.disposition == MothershipUpgradeDisposition::unsupported &&
                   !approved.contract.compatibility.allCompatible(),
               "generated_upgrade_bundle_policy_is_explicitly_unsupported");

  String policyFailure = {};
  const bool policyAdmits = prodigyPreflightLegacySameClusterUpdate(
      approved, approved.contract.architecture, uint128_t(1), nullptr, true, &policyFailure);
  suite.expect(!policyAdmits &&
                   policyFailure == "approved target release declares upgrades unsupported"_ctv,
               "generated_upgrade_bundle_unsupported_policy_rejects_before_source_claims");

  struct AsyncOwnerState {
    ProdigyPreparedBundleArtifact prepared = {};
    String failure = {};
    bool durabilitySynced = false;
    bool terminal = false;
  };
  auto state = std::make_shared<AsyncOwnerState>();
  auto artifactIO = ProdigyArtifactIO::startOwned();
  if (suite.require(artifactIO != nullptr, "generated_upgrade_bundle_owner_starts_async_artifact_io") == false) return;

  String stagedPath = {};
  stagedPath.assign((stage.path / "prodigy.bundle.tar.zst").c_str());
  ProdigyArtifactIO *owner = artifactIO.get();
  const bool submitted = owner->submit(
      bundle.size(),
      [state, stagedPath, bundle, digest] {
        (void)prodigyPrepareBundleArtifact(state->prepared, stagedPath, bundle, digest, &state->failure);
      },
      [owner, state] {
        if (state->prepared.prepared == false || !state->failure.empty() ||
            !prodigyPublishPreparedBundleArtifact(state->prepared, &state->failure))
        {
          state->terminal = true;
          return;
        }
        if (!owner->continueWith(
                [state] {
                  state->durabilitySynced = prodigyFsyncPublishedBundleArtifact(state->prepared, &state->failure);
                },
                [state] { state->terminal = true; },
                [state](std::exception_ptr) {
                  state->failure.assign("generated upgrade bundle durability worker failed"_ctv);
                  state->terminal = true;
                }))
        {
          state->failure.assign("generated upgrade bundle durability continuation was not queued"_ctv);
          state->terminal = true;
        }
      },
      [state](std::exception_ptr) {
        state->failure.assign("generated upgrade bundle preparation worker failed"_ctv);
        state->terminal = true;
      });
  if (suite.require(submitted, "generated_upgrade_bundle_owner_queues_async_stage") == false) return;
  suite.expect(pumpArtifactIOForTest([&] { return state->terminal; }),
               "generated_upgrade_bundle_owner_completes_async_stage_and_durability");
  suite.expect(state->prepared.published && state->durabilitySynced && state->failure.empty(),
               "generated_upgrade_bundle_owner_publishes_and_fsyncs_verified_bytes");

  String published = {}, publishedDigest = {};
  Filesystem::openReadAtClose(-1, stagedPath, published);
  suite.expect(published == bundle &&
                   prodigyLoadBundleExpectedSHA256Hex(stagedPath, publishedDigest, &failure) &&
                   publishedDigest == digest,
               "generated_upgrade_bundle_owner_publishes_matching_bundle_and_sidecar");
  suite.expect(quiesceArtifactIOForTest(artifactIO.get()),
               "generated_upgrade_bundle_owner_quiesces_async_artifact_io");
  prodigyDiscardPreparedBundleArtifact(state->prepared);
  artifactIO.reset();
}

static void testGeneratedUnsupportedBundleFailsAdmittedAsyncProofBeforePublication(TestSuite& suite)
{
  ScopedAsyncMothershipRing ring = {};
  ScopedTempDir stage = {};
  if (suite.require(stage.valid(), "generated_unsupported_admission_stage_created") == false) return;

  const String bundlePath = PRODIGY_TEST_UPGRADE_BUNDLE;
  if (suite.require(bundlePath.empty() == false,
                    "generated_unsupported_admission_fixture_path_configured") == false)
    return;
  String target = {}, targetDigest = {}, failure = {};
  ProdigyApprovedUpgradeBundle approved = {};
  Filesystem::openReadAtClose(-1, bundlePath, target);
  if (suite.require(!target.empty() && prodigyComputeSHA256Hex(target, targetDigest, &failure) &&
                        prodigyApproveBundleUpgradeContract(bundlePath, approved, &failure),
                    "generated_unsupported_admission_loads_approved_bundle") == false)
    return;
  if (suite.require(approved.contract.disposition == MothershipUpgradeDisposition::unsupported,
                    "generated_unsupported_admission_fixture_declares_unsupported") == false)
    return;

  TestNeuron localNeuron = {};
  localNeuron.uuid = uint128_t(0xA554);
  localNeuron.setInstalledBundleDigestForTest(targetDigest);
  NeuronBase *previousNeuron = thisNeuron;
  thisNeuron = &localNeuron;
  TestBrain brain = {};
  brain.testMothershipStagedBundlePath.assign((stage.path / "prodigy.bundle.tar.zst").c_str());
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.nBrains = 1;
  brain.boottimens = 93;
  brain.brainConfig.clusterUUID = uint128_t(0xA555);
  brain.masterAuthorityRuntimeState.generation = 19;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = 19;
  Machine local = {};
  local.uuid = localNeuron.uuid;
  local.isThisMachine = true;
  local.isBrain = true;
  local.state = MachineState::healthy;
  local.runtimeReady = true;
  brain.machines.insert(&local);
  brain.machinesByUUID.insert_or_assign(local.uuid, &local);
  brain.persistedMachineInventoryUploaded.insert(local.uuid);
  brain.persistedMachineStateUploadPlansByMachine.insert_or_assign(local.uuid, Vector<String>{});

  ScopedSocketPair sockets = {};
  Mothership mothership = {};
  if (suite.require(sockets.create(suite, "generated_unsupported_admission_socket_pair"),
                    "generated_unsupported_admission_requires_socket_pair") == false)
  {
    brain.machinesByUUID.erase(local.uuid);
    brain.machines.erase(&local);
    thisNeuron = previousNeuron;
    return;
  }
  mothership.isFixedFile = true;
  mothership.fslot = sockets.adoptLeftIntoFixedFileSlot();
  if (suite.require(mothership.fslot >= 0 && brain.activateMothershipConnection(&mothership),
                    "generated_unsupported_admission_activates_mothership") == false)
  {
    brain.machinesByUUID.erase(local.uuid);
    brain.machines.erase(&local);
    thisNeuron = previousNeuron;
    return;
  }

  MothershipUpgradeAdmissionReport report = {};
  brain.collectUpgradeAdmissionReport(report);
  if (suite.require(report.observationComplete && report.masterApprovedBundleSHA256 == targetDigest,
                    "generated_unsupported_admission_has_fresh_source_observation") == false)
  {
    brain.activeMotherships.erase(&mothership);
    brain.machinesByUUID.erase(local.uuid);
    brain.machines.erase(&local);
    thisNeuron = previousNeuron;
    return;
  }
  ProdigyAdmittedUpdateRequest request = {};
  request.operationID.assignItoh(uint128_t(1));
  uint128_t parsedOperationID = 0;
  if (suite.require(prodigyParseCanonicalHex128(request.operationID, parsedOperationID) &&
                        parsedOperationID == uint128_t(1),
                    "generated_unsupported_admission_operation_id_is_canonical") == false)
  {
    brain.activeMotherships.erase(&mothership);
    brain.machinesByUUID.erase(local.uuid);
    brain.machines.erase(&local);
    thisNeuron = previousNeuron;
    return;
  }
  request.sourceBundleSHA256 = targetDigest;
  request.targetBundleSHA256 = targetDigest;
  request.targetContractSHA256 = approved.contract.contractSHA256;
  request.requiredStagingBytes = 1;
  ProdigyUpgradeAdmissionReportRequest capacityRequest = {};
  capacityRequest.operationID.assign(request.operationID);
  capacityRequest.targetBundleSHA256.assign(targetDigest);
  capacityRequest.targetContractSHA256.assign(approved.contract.contractSHA256);
  capacityRequest.requiredStagingBytes = 1;
  brain.beginUpgradeAdmissionObservation(&capacityRequest);
  for (uint32_t attempt = 0; attempt < 20 && !brain.upgradeAdmissionObservation.localCapacityMeasurementComplete; ++attempt) ring.runFor(10);
  brain.collectUpgradeAdmissionReport(report);
  request.authorityGeneration = report.authorityGeneration;
  request.masterUUID = report.masterUUID;
  request.masterBootNs = report.masterBootNs;
  request.receiptVersion = report.observationReceiptVersion;
  request.nonce = report.observationNonce;
  String serialized = {}, frame = {};
  BitseryEngine::serialize(serialized, request);
  brain.mothershipHandler(
      &mothership,
      buildMothershipMessage(frame, MothershipTopic::updateProdigyAdmitted, serialized, target));
  suite.expect(brain.pendingMothershipUpdateArtifact != nullptr && mothership.wBuffer.empty(),
               "generated_unsupported_admission_reaches_async_contract_proof");
  for (uint32_t attempt = 0; attempt < 100 && brain.pendingMothershipUpdateArtifact != nullptr; ++attempt)
    ring.runFor(20);

  String responseBytes = {};
  uint8_t receiveBuffer[4096] = {};
  for (;;)
  {
    const ssize_t received = ::recv(sockets.right, receiveBuffer, sizeof(receiveBuffer), 0);
    if (received <= 0) break;
    responseBytes.append(receiveBuffer, uint64_t(received));
  }
  MothershipResponse response = {};
  bool rejected = false;
  if (responseBytes.size() >= sizeof(Message))
  {
    Message *message = reinterpret_cast<Message *>(responseBytes.data());
    String serializedResponse = {};
    uint8_t *args = message->args;
    Message::extractToStringView(args, serializedResponse);
    rejected = MothershipTopic(message->topic) == MothershipTopic::updateProdigyAdmitted &&
        args == message->terminal() && BitseryEngine::deserializeSafe(serializedResponse, response) &&
        !response.success &&
        response.failure == "bundle artifact preparation failed: approved target release declares upgrades unsupported"_ctv;
  }
  suite.expect(rejected && brain.pendingMothershipUpdateArtifact == nullptr &&
                   brain.transitionToNewBundleCalls == 0 &&
                   ::access(brain.testMothershipStagedBundlePath.c_str(), F_OK) != 0,
               "generated_unsupported_admission_rejects_before_bundle_publication_or_transition");
  if (brain.artifactIO)
  {
    suite.expect(quiesceArtifactIOForTest(brain.artifactIO.get()),
                 "generated_unsupported_admission_quiesces_artifact_io");
    brain.artifactIO.reset();
  }
  brain.activeMotherships.erase(&mothership);
  brain.machinesByUUID.erase(local.uuid);
  brain.machines.erase(&local);
  thisNeuron = previousNeuron;
}
