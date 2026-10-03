#pragma once

// Included after the credential unit's Brain, Ring, and socket fixtures.
static ProdigyDeploymentPlacementPolicy placementPolicyForTest(
    uint16_t applicationID, uint64_t versionID, const char *operationID,
    std::initializer_list<uint128_t> eligible)
{
  ProdigyDeploymentPlacementPolicy policy = {};
  policy.applicationID = applicationID;
  policy.versionID = versionID;
  policy.operationID.assign(operationID);
  for (uint128_t machineUUID : eligible) policy.eligibleMachineUUIDs.push_back(machineUUID);
  return policy;
}

static bool decodePlacementPolicyResponse(String& bytes, CommitDeploymentPlacementPolicyResponse& response)
{
  bool decoded = false;
  forEachMessageInBuffer(bytes, [&](Message *message) {
    if (MothershipTopic(message->topic) != MothershipTopic::commitDeploymentPlacementPolicy) return;
    uint8_t *args = message->args;
    String payload = {};
    Message::extractToStringView(args, payload);
    decoded = BitseryEngine::deserializeSafe(payload, response);
  });
  return decoded;
}

static String placementPolicySpinResponse(TestBrain& brain, Mothership& stream, DeploymentPlan& plan)
{
  String serialized = {}, frame = {}, reason = {};
  BitseryEngine::serialize(serialized, plan);
  stream.wBuffer.clear();
  brain.mothershipHandler(&stream, buildMothershipMessage(
      frame, MothershipTopic::spinApplication, uint16_t(plan.config.applicationID), serialized,
      "placement policy rejection must precede artifact handling"_ctv));
  forEachMessageInBuffer(stream.wBuffer, [&](Message *response) {
    if (MothershipTopic(response->topic) != MothershipTopic::spinApplication) return;
    uint8_t *args = response->args;
    uint8_t code = uint8_t(SpinApplicationResponseCode::okay);
    Message::extractArg<ArgumentNature::fixed>(args, code);
    if (SpinApplicationResponseCode(code) == SpinApplicationResponseCode::invalidPlan && args < response->terminal())
      Message::extractToStringView(args, reason);
  });
  return reason;
}

static void testPlacementPolicyCommitDurabilityAndReplay(TestSuite& suite)
{
  ScopedAsyncMothershipRing ring = {};
  ScopedSocketPair sockets = {};
  TestBrain brain = {};
  Mothership stream = {};
  ApplicationDeployment active = {};
  constexpr uint16_t app = 61'001;
  active.plan.config.applicationID = app;
  active.plan.config.versionID = 7;
  active.plan.isStateful = false;
  brain.deploymentsByApp.insert_or_assign(app, &active);
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.ignited = true;
  brain.holdRuntimePersistence = true;
  if (!suite.require(sockets.create(suite, "placement_policy_commit_socket_pair"),
                     "placement_policy_commit_socket_pair_required")) return;
  stream.isFixedFile = true;
  stream.fslot = sockets.adoptLeftIntoFixedFileSlot();
  if (!suite.require(stream.fslot >= 0, "placement_policy_commit_adopts_fixed_file_socket")) return;
  if (!suite.require(brain.activateMothershipConnection(&stream), "placement_policy_commit_activates_mothership")) return;
  RingDispatcher::installMultiplexee(&stream, &brain);

  auto request = placementPolicyForTest(app, 8,
      "123e4567-e89b-42d3-a456-426614174001", {uint128_t(0x1001)});
  String payload = {}, frame = {};
  BitseryEngine::serialize(payload, request);
  brain.mothershipHandler(&stream, buildMothershipMessage(frame, MothershipTopic::commitDeploymentPlacementPolicy, payload));
  suite.expect(brain.masterAuthorityRuntimeState.deploymentPlacementPolicies.size() == 1 &&
                   brain.pendingRuntimePersistence.size() == 1 && stream.wBuffer.empty(),
               "placement_policy_commit_waits_for_durable_authority_receipt");
  brain.finishRuntimePersistence(false);
  CommitDeploymentPlacementPolicyResponse rejected = {};
  suite.expect(decodePlacementPolicyResponse(stream.wBuffer, rejected) && !rejected.success &&
                   rejected.failure.equals("deployment placement durable acceptance failed"_ctv) &&
                   brain.masterAuthorityRuntimeState.deploymentPlacementPolicies.empty(),
               "placement_policy_failed_durability_rolls_back_without_success");

  stream.wBuffer.clear();
  brain.mothershipHandler(&stream, buildMothershipMessage(frame, MothershipTopic::commitDeploymentPlacementPolicy, payload));
  brain.finishRuntimePersistence(true);
  CommitDeploymentPlacementPolicyResponse accepted = {};
  suite.expect(decodePlacementPolicyResponse(stream.wBuffer, accepted) && accepted.success &&
                   accepted.durableGeneration != 0 &&
                   brain.masterAuthorityRuntimeState.deploymentPlacementPolicies.size() == 1,
               "placement_policy_durable_commit_replies_only_after_persistence");

  stream.wBuffer.clear();
  brain.mothershipHandler(&stream, buildMothershipMessage(frame, MothershipTopic::commitDeploymentPlacementPolicy, payload));
  CommitDeploymentPlacementPolicyResponse replay = {};
  suite.expect(decodePlacementPolicyResponse(stream.wBuffer, replay) && replay.success &&
                   brain.pendingRuntimePersistence.empty() &&
                   brain.masterAuthorityRuntimeState.deploymentPlacementPolicies.size() == 1,
               "placement_policy_same_operation_replay_is_idempotent");
  auto conflict = placementPolicyForTest(app, 8, "123e4567-e89b-42d3-a456-426614174001", {uint128_t(0x1002)});
  BitseryEngine::serialize(payload, conflict);
  stream.wBuffer.clear();
  brain.mothershipHandler(&stream, buildMothershipMessage(frame, MothershipTopic::commitDeploymentPlacementPolicy, payload));
  CommitDeploymentPlacementPolicyResponse collision = {};
  suite.expect(decodePlacementPolicyResponse(stream.wBuffer, collision) && !collision.success &&
                   collision.failure.equals("deployment placement operationID collision"_ctv),
               "placement_policy_same_operation_conflict_is_rejected");
  RingDispatcher::eraseMultiplexee(&stream);
  brain.activeMotherships.erase(&stream);
  brain.closingMotherships.erase(&stream);
  brain.deploymentsByApp.erase(app);
}

static void testPlacementPolicyCapabilityAndAdmissionGuards(TestSuite& suite)
{
  ScopedFreshRing ring = {};
  ScopedSocketPair sockets = {};
  TestBrain brain = {};
  Mothership stream = {};
  ApplicationDeployment active = {};
  constexpr uint16_t app = 61'002;
  active.plan.config.applicationID = app; active.plan.config.versionID = 7;
  brain.deploymentsByApp.insert_or_assign(app, &active);
  brain.weAreMaster = true; brain.noMasterYet = false; brain.ignited = true;
  brain.activateMothershipConnection(&stream);
  auto request = placementPolicyForTest(app, 8, "123e4567-e89b-42d3-a456-426614174002", {uint128_t(0x2001)});
  String payload = {}, frame = {};
  auto submit = [&]() {
    BitseryEngine::serialize(payload, request); stream.wBuffer.clear();
    brain.mothershipHandler(&stream, buildMothershipMessage(frame, MothershipTopic::commitDeploymentPlacementPolicy, payload));
    CommitDeploymentPlacementPolicyResponse response = {}; decodePlacementPolicyResponse(stream.wBuffer, response); return response;
  };
  if (suite.require(sockets.create(suite, "placement_policy_capability_wire_socket_pair"),
                    "placement_policy_capability_wire_socket_pair_required") == false)
  {
    brain.activeMotherships.erase(&stream); brain.deploymentsByApp.erase(app);
    return;
  }
  BrainView peer = {}; peer.isMasterBrain = false; peer.registrationFresh = false; peer.connected = true;
  peer.isFixedFile = true;
  peer.fslot = sockets.adoptLeftIntoFixedFileSlot();
  if (suite.require(peer.fslot >= 0, "placement_policy_capability_wire_adopts_peer_socket") == false)
  {
    brain.activeMotherships.erase(&stream); brain.deploymentsByApp.erase(app);
    return;
  }
  brain.brains.insert(&peer);
  auto oldPeer = submit();
  suite.expect(!oldPeer.success && oldPeer.failure.equals("deployment placement requires explicit peer capability acknowledgement"_ctv) &&
                   brain.masterAuthorityRuntimeState.deploymentPlacementPolicies.empty(),
               "placement_policy_unacknowledged_or_disconnected_commissioned_peer_blocks_mutation");
  auto registerPeer = [&](uint64_t version) {
    String registrationFrame = {};
    peer.wBuffer.clear();
    brain.brainHandler(&peer, buildBrainMessage(
        registrationFrame, BrainTopic::registration, uint128_t(0x2002), int64_t(2), version,
        uint128_t(0), "test-kernel"_ctv, "test-os"_ctv, "test-version"_ctv));
    bool advertised = false;
    forEachMessageInBuffer(peer.wBuffer, [&](Message *message) {
      advertised = advertised || BrainTopic(message->topic) == BrainTopic::advertiseCapabilities;
    });
    return advertised;
  };
  auto observationSent = [&]() {
    peer.wBuffer.clear();
    brain.upgradeAdmissionObservation = {};
    brain.beginUpgradeAdmissionObservation();
    bool sent = false;
    forEachMessageInBuffer(peer.wBuffer, [&](Message *message) {
      sent = sent || BrainTopic(message->topic) == BrainTopic::observeUpgradeAdmission;
    });
    return sent;
  };

  const bool old19Advertised = registerPeer(19);
  const bool old19Observed = observationSent();
  peer.wBuffer.clear();
  auto old19Unacknowledged = submit();
  suite.expect(peer.registrationFresh && !old19Advertised && !old19Observed &&
                   !peer.placementPolicyCapabilityAcknowledged &&
                   !old19Unacknowledged.success && brain.masterAuthorityRuntimeState.deploymentPlacementPolicies.empty() &&
                   !brain.containerRetirementPeerCapabilityCurrent(&peer),
               "placement_policy_registration_does_not_send_unknown_capability_topic_to_v19_or_open_feature_gates");

  const bool old20Advertised = registerPeer(20);
  const bool old20Observed = observationSent();
  peer.wBuffer.clear();
  auto old20Unacknowledged = submit();
  suite.expect(!old20Advertised && !old20Observed && !peer.placementPolicyCapabilityAcknowledged &&
                   !old20Unacknowledged.success && brain.masterAuthorityRuntimeState.deploymentPlacementPolicies.empty() &&
                   !brain.containerRetirementPeerCapabilityCurrent(&peer),
               "placement_policy_registration_does_not_send_unknown_capability_topic_to_v20_or_open_feature_gates");

  const bool v21Advertised = registerPeer(21);
  const bool v21Observed = observationSent();
  peer.wBuffer.clear();
  auto unacknowledged = submit();
  suite.expect(v21Advertised && v21Observed && !peer.placementPolicyCapabilityAcknowledged &&
                   !unacknowledged.success && brain.masterAuthorityRuntimeState.deploymentPlacementPolicies.empty() &&
                   !brain.containerRetirementPeerCapabilityCurrent(&peer),
               "placement_policy_v21_registration_probes_but_explicit_authenticated_capability_ack_still_gates_features");
  String acknowledgementFrame = {};
  brain.brainHandler(&peer, buildBrainMessage(acknowledgementFrame, BrainTopic::acknowledgeCapabilities, uint64_t(1)));
  suite.expect(peer.placementPolicyCapabilityAcknowledged,
               "placement_policy_explicit_capability_acknowledgement_unblocks_peer_gate");
  request.versionID = 7;
  auto sameVersion = submit();
  suite.expect(!sameVersion.success &&
                   brain.masterAuthorityRuntimeState.deploymentPlacementPolicies.empty(),
               "placement_policy_commit_rejects_non_successor_request_without_mutation");
  brain.brains.erase(&peer); brain.activeMotherships.erase(&stream); brain.deploymentsByApp.erase(app);
  if (brain.artifactIO)
  {
    suite.expect(quiesceArtifactIOForTest(brain.artifactIO.get()),
                 "placement_policy_capability_fixture_quiesces_old_peer_reconciliation_worker");
    brain.artifactIO.reset();
  }
}

static void testPlacementPolicySpinAdmission(TestSuite& suite)
{
  TestBrain brain = {};
  Mothership stream = {};
  constexpr uint16_t app = 61'004;
  brain.weAreMaster = true; brain.noMasterYet = false; brain.ignited = true;
  stream.isFixedFile = true; stream.fslot = 1;
  brain.mothership = &stream;
  brain.activateMothershipConnection(&stream);
  String reserveFailure = {};
  suite.require(brain.reserveApplicationIDMapping("PlacementSuccessor"_ctv, app, &reserveFailure),
                "placement_policy_spin_reserves_successor_application");
  brain.masterAuthorityRuntimeState.deploymentPlacementPolicies.push_back(
      placementPolicyForTest(app, 8, "123e4567-e89b-42d3-a456-426614174004", {uint128_t(0x4001)}));
  DeploymentPlan nonconstructive = makeDeploymentPlan(app, 8);
  nonconstructive.moveConstructively = false;
  DeploymentPlan stateful = makeDeploymentPlan(app, 8);
  stateful.isStateful = true;
  stateful.config.type = ApplicationType::stateful;
  const String expected = "invalid plan: placement policy requires a stateless constructive successor"_ctv;
  suite.expect(placementPolicySpinResponse(brain, stream, nonconstructive).equals(expected) &&
                   placementPolicySpinResponse(brain, stream, stateful).equals(expected) &&
                   brain.deployments.empty() && brain.deploymentPlans.empty(),
               "placement_policy_spin_admission_rejects_nonconstructive_and_stateful_successors_before_artifact_use");
  brain.activeMotherships.erase(&stream);
}

static void testPlacementPolicyRestoreAndEligibility(TestSuite& suite)
{
  TestBrain source = {};
  const auto policy = placementPolicyForTest(61'003, 9,
      "123e4567-e89b-42d3-a456-426614174003", {uint128_t(0x3001)});
  source.masterAuthorityRuntimeState.deploymentPlacementPolicies.push_back(policy);
  source.masterAuthorityRuntimeState.generation = 9;
  ProdigyPersistentMasterAuthorityPackage package = {};
  source.capturePersistentMasterAuthorityPackage(package);
  TestBrain successor = {};
  suite.require(successor.applyPersistentMasterAuthorityPackage(package), "placement_policy_successor_restores_authority_package");
  suite.expect(successor.masterAuthorityRuntimeState.deploymentPlacementPolicies.size() == 1 &&
                   successor.masterAuthorityRuntimeState.deploymentPlacementPolicies[0].operationID.equals(policy.operationID),
               "placement_policy_persists_across_successor_restore");
  ApplicationDeployment target = {}; target.plan.config.applicationID = policy.applicationID; target.plan.config.versionID = policy.versionID;
  target.plan.config.nLogicalCores = 1; target.plan.config.memoryMB = 64; target.plan.config.storageMB = 64;
  ApplicationDeployment unrelated = {}; unrelated.plan.config.applicationID = policy.applicationID + 1; unrelated.plan.config.versionID = policy.versionID;
  unrelated.plan.config.nLogicalCores = 1; unrelated.plan.config.memoryMB = 64; unrelated.plan.config.storageMB = 64;
  target.applyCommittedPlacementPolicy(successor.masterAuthorityRuntimeState.deploymentPlacementPolicies[0]);
  Machine allowed = {}; allowed.uuid = uint128_t(0x3001); allowed.totalLogicalCores = allowed.ownedLogicalCores = 8; allowed.totalMemoryMB = allowed.ownedMemoryMB = 4096; allowed.totalStorageMB = allowed.ownedStorageMB = 4096;
  allowed.nLogicalCores_available = 8; allowed.memoryMB_available = 4096; allowed.storageMB_available = 4096;
  Machine denied = allowed; denied.uuid = uint128_t(0x3002);
  suite.expect(ApplicationDeployment::nFitOnMachine(&target, &allowed, 1) > 0 &&
                   ApplicationDeployment::nFitOnMachine(&target, &denied, 1) == 0 &&
                   ApplicationDeployment::nFitOnMachine(&unrelated, &denied, 1) > 0,
               "placement_policy_nfit_limits_only_committed_successor_and_leaves_unrelated_app_eligible");
}

static void testPlacementPolicyTests(TestSuite& suite)
{
  testPlacementPolicyCommitDurabilityAndReplay(suite);
  testPlacementPolicyCapabilityAndAdmissionGuards(suite);
  testPlacementPolicySpinAdmission(suite);
  testPlacementPolicyRestoreAndEligibility(suite);
}
