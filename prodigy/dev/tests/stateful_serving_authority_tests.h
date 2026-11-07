#pragma once

static void testAllMastersSeedBootstrapSchema(TestSuite& suite)
{
  auto plan = makeDeploymentPlan(3, 112);
  ProdigyStatefulServingAuthority authority = {};
  authority.deploymentID = plan.config.deploymentID(); authority.applicationID = 3;
  authority.revision = 1; authority.phase = StatefulWorkerTopologyUpgradePhase::allMastersSeedBootstrap;
  authority.targetConfig = plan.config; authority.allMasters = true;
  auto& b = authority.allMastersSeedBootstrap;
  b.sourceClusterUUID = 3; b.targetClusterUUID = 4; b.targetDeploymentID = authority.deploymentID;
  b.qualificationRunUUID = 1; b.successorOperationUUID = 2; b.shardGroup = 0; b.expectedSeedGeneration = 5;
  auto& q = authority.qualificationCancellation;
  q.request.applicationName = "bootstrap-test"_ctv; q.request.applicationID = 3;
  q.request.activeVersionID = 111; q.request.successorVersionID = 112;
  q.request.operationID = "00000000-0000-0000-0000-000000000001"_ctv; q.request.reason = "qualification"_ctv;
  q.qualificationRunUUID = 1; q.successorOperationUUID = 2; q.sourceClusterUUID = 3;
  q.executionGeneration = 1; q.deadlineAtMilliseconds = 123456;
  q.placementIntentSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv;
  q.successorPlanSHA256 = q.successorArtifactSHA256 = q.placementIntentSHA256;
  q.members.push_back({4, 5}); q.members.push_back({6, 7}); q.members.push_back({8, 9});
  Vector<BrainReplicatedContainerRuntimeState> states;
  suite.expect(prodigyValidateStatefulServingAuthority(authority, states, 1), "bootstrap_empty_scope_valid");
  suite.expect(prodigyStatefulServingAuthorityMatchesShard(authority, authority.deploymentID, 0) &&
      !prodigyStatefulServingAuthorityMatchesShard(authority, authority.deploymentID, 1), "bootstrap_empty_scope_matches_only_selected_shard");
  String bytes; auto original = authority; ProdigyStatefulServingAuthority decoded;
  suite.expect(BitseryEngine::serialize(bytes, original) && BitseryEngine::deserializeSafe(bytes, decoded) &&
      decoded == authority && prodigyValidateStatefulServingAuthority(decoded, states, 1), "bootstrap_authority_roundtrip");
  decoded.allMastersSeedBootstrap.successorOperationUUID++;
  suite.expect(!prodigyValidateStatefulServingAuthority(decoded, states, 1), "bootstrap_scope_mismatch_rejected");
  auto other = authority; other.allMastersSeedBootstrap.shardGroup = 1;
  suite.expect(!prodigyStatefulServingAuthoritySameScope(authority, other), "bootstrap_shards_are_distinct_scopes");
  ProdigyAllMastersSeedBootstrapOperation op; op.bootstrap = b; op.qualificationCancellation = q;
  String wire; ProdigyAllMastersSeedBootstrapOperation restored;
  suite.expect(BitseryEngine::serialize(wire, op) && BitseryEngine::deserializeSafe(wire, restored) &&
      restored.protocolVersion == op.version && restored.bootstrap == b, "bootstrap_operation_roundtrip");
  StatefulTopology topology; topology.shardGroup = 0; topology.servingMode = StatefulTopologyServingMode::allMastersSeedBootstrap;
  topology.allMastersSeedBootstrap = b;
  suite.expect(prodigyStatefulTopologyIsAllMastersSeedBootstrap(topology) && prodigyStatefulTopologyServesClients(topology),
      "bootstrap_listener_remains_published");
  topology.allMastersSeedBootstrap.expectedSeedGeneration = 0;
  suite.expect(!prodigyStatefulTopologyIsAllMastersSeedBootstrap(topology) && !prodigyStatefulTopologyServesClients(topology),
      "bootstrap_missing_generation_rejected");
  // The initial form has no predecessor. It has its own authority and operation
  // discriminator while using the same native seed-binding tuple.
  auto initial = authority; initial.phase = StatefulWorkerTopologyUpgradePhase::initialAllMastersSeedBootstrap;
  initial.targetConfig.type = ApplicationType::stateful;
  initial.targetConfig.containerBlobSHA256 = q.successorArtifactSHA256;
  initial.targetConfig.containerBlobBytes = 42;
  auto& is = initial.initialAllMastersSeedBootstrap;
  is.bootstrap = b; is.baselineOperationUUID = 99; is.nShardGroups = 1;
  is.planSHA256 = q.successorPlanSHA256; is.artifactSHA256 = q.successorArtifactSHA256; is.artifactBytes = 42;
  suite.expect(prodigyValidateStatefulServingAuthority(initial, states, 1), "initial_bootstrap_empty_scope_valid");
  String initialBytes; auto initialCopy = initial; ProdigyStatefulServingAuthority initialDecoded;
  suite.expect(BitseryEngine::serialize(initialBytes, initialCopy) && BitseryEngine::deserializeSafe(initialBytes, initialDecoded) &&
      initialDecoded == initial && prodigyValidateStatefulServingAuthority(initialDecoded, states, 1), "initial_bootstrap_authority_roundtrip");
  suite.expect(prodigyStatefulServingAuthoritySameScope(initial, authority) &&
      prodigyStatefulServingAuthorityMatchesShard(initial, initial.deploymentID, 0) &&
      !prodigyStatefulServingAuthorityMatchesShard(initial, initial.deploymentID, 1), "initial_bootstrap_exact_scope");
  initialDecoded.initialAllMastersSeedBootstrap.baselineOperationUUID = 0;
  suite.expect(!prodigyValidateStatefulServingAuthority(initialDecoded, states, 1), "initial_bootstrap_requires_baseline");
  initialDecoded = initial; initialDecoded.initialAllMastersSeedBootstrap.bootstrap.expectedSeedGeneration = 0;
  suite.expect(!prodigyValidateStatefulServingAuthority(initialDecoded, states, 1), "initial_bootstrap_requires_generation");
  initialDecoded = initial; initialDecoded.initialAllMastersSeedBootstrap.artifactBytes++;
  suite.expect(!prodigyValidateStatefulServingAuthority(initialDecoded, states, 1), "initial_bootstrap_requires_exact_artifact");
  initialDecoded = initial; initialDecoded.applicationID = 2; initialDecoded.targetConfig.applicationID = 2;
  initialDecoded.deploymentID = initialDecoded.targetConfig.deploymentID();
  initialDecoded.initialAllMastersSeedBootstrap.bootstrap.targetDeploymentID = initialDecoded.deploymentID;
  initialDecoded.initialAllMastersSeedBootstrap.nShardGroups = 2;
  suite.expect(!prodigyValidateStatefulServingAuthority(initialDecoded, states, 1), "initial_bootstrap_graph_requires_one_group");
  ProdigyInitialAllMastersSeedBootstrapOperation initialOp, initialOpDecoded; initialOp.scope = is;
  String initialWire;
  suite.expect(BitseryEngine::serialize(initialWire, initialOp) && BitseryEngine::deserializeSafe(initialWire, initialOpDecoded) &&
      initialOpDecoded.protocolVersion == initialOp.version && initialOpDecoded.scope.baselineOperationUUID == 99 &&
      initialOp.version != op.version, "initial_bootstrap_operation_roundtrip_distinct");
  {
    ScopedRing ring = {};
    StreamingTestBrain candidate = {}; BrainBase *oldBrain = thisBrain; thisBrain = &candidate;
    NeuronBase *oldNeuron = thisNeuron; Neuron self = {}; self.uuid = 0x8301; thisNeuron = &self;
    candidate.weAreMaster = true; candidate.nBrains = 1; candidate.boottimens = 100; candidate.brainConfig.clusterUUID = b.targetClusterUUID;
    candidate.masterAuthorityEpoch = 9; candidate.masterAuthorityRuntimeState.generation = 1;
    candidate.masterAuthorityRuntimeStateDurable = true; candidate.durableMasterAuthorityRuntimeStateGeneration = 1;
    candidate.hasAuthoritativeTopology = true; candidate.authoritativeTopology.machines.push_back(ClusterMachine {});
    candidate.authoritativeTopology.machines.back().uuid = self.uuid; candidate.authoritativeTopology.machines.back().isBrain = true;
    auto initialPlan = plan; initialPlan.isStateful = true; initialPlan.stateful.allMasters = true;
    initialPlan.canaryCount = 0; initialPlan.config = initial.targetConfig;
    String serializedPlan; BitseryEngine::serialize(serializedPlan, initialPlan);
    String planHash; prodigyComputeSHA256Hex(serializedPlan, planHash);
    initial.initialAllMastersSeedBootstrap.planSHA256 = planHash;
    ProdigyInitialAllMastersSeedBootstrapOperation query; query.query = true;
    query.scope = initial.initialAllMastersSeedBootstrap; query.deploymentPlan = serializedPlan;
    auto install = query; install.query = false;
    install.expectedAuthorityGeneration = candidate.masterAuthorityRuntimeState.generation;
    install.expectedMasterUUID = self.uuid; install.expectedMasterBootNs = candidate.boottimens;
    auto response = candidate.initialAllMastersSeedBootstrapOperation(install);
    if (!response.accepted) fprintf(stderr, "initial bootstrap install: %s\n", response.failure.c_str());
    suite.expect(response.accepted && candidate.masterAuthorityRuntimeState.statefulServingAuthorities.size() == 1,
        "initial_bootstrap_install_empty_target");
    response = candidate.initialAllMastersSeedBootstrapOperation(query);
    suite.expect(response.accepted, "initial_bootstrap_query_exact_authority");
    query.scope.bootstrap.expectedSeedGeneration++;
    response = candidate.initialAllMastersSeedBootstrapOperation(query);
    suite.expect(!response.accepted && !response.failure.empty(), "initial_bootstrap_query_conflict_rejected");
    candidate.authoritativeTopology.machines.push_back(ClusterMachine {});
    candidate.authoritativeTopology.machines.back().uuid = 0x8302; candidate.authoritativeTopology.machines.back().isBrain = true;
    response = candidate.initialAllMastersSeedBootstrapOperation(query);
    suite.expect(!response.accepted && !response.failure.empty(), "initial_bootstrap_old_or_missing_peer_rejected");
    thisNeuron = oldNeuron; thisBrain = oldBrain;
  }
  TestBrain brain = {}; brain.masterAuthorityRuntimeState.statefulServingAuthorities.push_back(authority);
  BrainBase *savedBrain = thisBrain; thisBrain = &brain;
  ApplicationDeployment predecessor = {}, successor = {}; successor.plan = plan; predecessor.next = &successor;
  predecessor.rollForward();
  suite.expect(successor.state == DeploymentState::none && brain.allMastersSeedBootstrapAwaitingCancellation(authority.deploymentID),
      "bootstrap_roll_forward_waits_for_qualified_cancellation");
  thisBrain = savedBrain;
}

static void testRestoredRuntimeRequiresFreshInventory(TestSuite& suite)
{
  ScopedRing ring = {};
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.ignited = true;
  brain.masterAuthorityEpoch = 31;
  brain.brainConfig.datacenterFragment = 1;
  brain.recoveringPersistedNeuronInventory = true;
  brain.persistedMachineInventoryEnumerated = true;
  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;
  Rack rack = {}; rack.uuid = 62050;
  Machine machine = {};
  machine.uuid = 0x62050;
  machine.private4 = 0x0a00002c;
  machine.state = MachineState::healthy;
  machine.runtimeReady = true;
  machine.fragment = 0x1236;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 42;
  machine.neuron.connected = true;
  machine.neuron.pendingSend = true;
  machine.neuron.ioGeneration = 3;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);
  auto acceptInventory = [&](uint64_t epoch, uint64_t generation, bool present) {
    brain.persistedMachineInventoryUploaded.insert(machine.uuid);
    brain.persistedMachineStateUploadPlansByMachine[machine.uuid].clear();
    auto& inventory = brain.containerRetirementInventoryByMachine[machine.uuid];
    inventory.authorityEpoch = epoch;
    inventory.ioGeneration = generation;
    inventory.present.clear();
    if (present) { inventory.present.insert(0x620501); inventory.present.insert(0x620502); }
    machine.runtimeReady = true;
  };
  acceptInventory(brain.masterAuthorityEpoch, machine.neuron.ioGeneration, false);
  ApplicationDeployment first = {}, second = {};
  first.plan = makeDeploymentPlan(62050, 1);
  second.plan = makeDeploymentPlan(62051, 1);
  for (auto *deployment : {&first, &second})
  {
    deployment->plan.stateless.nBase = 1;
    deployment->nTargetBase = 1;
    ContainerView seed = {};
    seed.uuid = deployment == &first ? 0x620501 : 0x620502;
    seed.deploymentID = deployment->plan.config.deploymentID();
    seed.applicationID = deployment->plan.config.applicationID;
    seed.machine = &machine;
    seed.lifetime = ApplicationLifetime::base;
    seed.state = ContainerState::scheduled;
    seed.fragment = deployment == &first ? 11 : 12;
    BrainReplicatedContainerRuntimeState state = {};
    state.machineUUID = machine.uuid;
    state.machinePrivate4 = machine.private4;
    state.plan = seed.generatePlan(deployment->plan);
    brain.applyReplicatedContainerRuntimeState(state);
  }
  auto materialize = [&](ApplicationDeployment& deployment) {
    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
    brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);
    brain.applyPendingReplicatedContainerRuntimeStates(deployment.plan.config.deploymentID());
  };
  materialize(first);
  suite.expect(machine.neuron.wBuffer.empty() && !brain.finalizePersistedNeuronInventoryRecovery(),
               "restored_runtime_waits_for_complete_pending_batch");
  acceptInventory(brain.masterAuthorityEpoch - 1, machine.neuron.ioGeneration, false);
  materialize(second);
  suite.expect(machine.neuron.wBuffer.empty() && !brain.finalizePersistedNeuronInventoryRecovery(),
               "restored_runtime_rejects_previous_authority_inventory");
  acceptInventory(brain.masterAuthorityEpoch, machine.neuron.ioGeneration - 1, false);
  suite.expect(!brain.finalizePersistedNeuronInventoryRecovery() && machine.neuron.wBuffer.empty(),
               "restored_runtime_rejects_previous_connection_inventory");
  acceptInventory(brain.masterAuthorityEpoch, machine.neuron.ioGeneration, false);
  suite.expect(!brain.finalizePersistedNeuronInventoryRecovery(), "restored_runtime_replay_keeps_recovery_closed");
  uint32_t frames = 0;
  bytell_hash_set<uint128_t> replayed;
  forEachMessageInBuffer(machine.neuron.wBuffer, [&](Message *message) {
    if (NeuronTopic(message->topic) != NeuronTopic::stateUpload) return;
    ++frames;
    uint8_t *args = message->args;
    local_container_subnet6 fragment = {};
    Message::extractBytes<Alignment::one>(args, reinterpret_cast<uint8_t *>(&fragment), sizeof(fragment));
    for (uint32_t i = 0; i < 2; ++i)
    {
      String serialized;
      Message::extractToStringView(args, serialized);
      NeuronContainerBootstrap bootstrap = {};
      if (BitseryEngine::deserializeSafe(serialized, bootstrap)) replayed.insert(bootstrap.plan.uuid);
    }
  });
  suite.expect(frames == 1 && replayed.size() == 2 && replayed.contains(0x620501) && replayed.contains(0x620502),
               "restored_runtime_replays_complete_canonical_uuids_once");
  suite.expect(!machine.runtimeReady && !brain.persistedMachineInventoryUploaded.contains(machine.uuid) &&
                   first.nHealthyBase == 0 && second.nHealthyBase == 0,
               "restored_runtime_replay_invalidates_inventory_without_inventing_health");
  const auto queuedBytes = machine.neuron.wBuffer.size();
  (void)brain.finalizePersistedNeuronInventoryRecovery();
  suite.expect(machine.neuron.wBuffer.size() == queuedBytes, "restored_runtime_replay_does_not_flood_inflight_request");
  acceptInventory(brain.masterAuthorityEpoch, machine.neuron.ioGeneration, true);
  (void)brain.finalizePersistedNeuronInventoryRecovery();
  uint32_t settledReplayFrames = 0;
  forEachMessageInBuffer(machine.neuron.wBuffer, [&](Message *message) {
    if (NeuronTopic(message->topic) == NeuronTopic::stateUpload) ++settledReplayFrames;
  });
  suite.expect(brain.pendingRestoredContainerInventory.empty() && settledReplayFrames == 1,
               "restored_runtime_fresh_observation_settles_exact_replay");
  for (auto *deployment : {&first, &second})
  {
    Vector<ContainerView *> restored;
    for (ContainerView *container : deployment->containers) restored.push_back(container);
    for (ContainerView *container : restored)
    {
      deployment->containers.erase(container);
      machine.removeContainerIndexEntry(container->deploymentID, container);
      brain.containers.erase(container->uuid);
      delete container;
    }
    brain.deployments.erase(deployment->plan.config.deploymentID());
    brain.deploymentsByApp.erase(deployment->plan.config.applicationID);
  }
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

// Included after TestBrain/TestSuite.  This keeps the authority fixture in the
// credential target, where async master-authority persistence is already real.
static BrainReplicatedContainerRuntimeState servingAuthorityTestState(
    uint128_t uuid, uint128_t machine, bool client)
{
  BrainReplicatedContainerRuntimeState state = {};
  state.machineUUID = machine;
  state.plan.uuid = uuid;
  state.plan.config.applicationID = 7;
  state.plan.config.versionID = 9;
  state.plan.config.type = ApplicationType::stateful;
  state.plan.isStateful = true;
  state.plan.shardGroup = 0;
  state.plan.statefulMeshRoles.client = 99;
  state.plan.statefulTopology.shardGroup = 0;
  state.plan.statefulTopology.topologyEpoch = 22;
  state.plan.statefulTopology.sourceEpoch = 22;
  state.plan.statefulTopology.targetEpoch = 22;
  state.plan.statefulTopology.servingMode = StatefulTopologyServingMode::serve;
  if (client) state.plan.advertisements.emplace(99, Advertisement(99, ContainerState::healthy, ContainerState::destroying, 1));
  return state;
}

static ProdigyMasterAuthorityStateTransition servingAuthorityTestTransition()
{
  ProdigyMasterAuthorityStateTransition transition = {};
  transition.version = 2;
  transition.runtimeState.generation = 10;
  ProdigyStatefulServingAuthority authority = {};
  authority.deploymentID = (uint64_t(7) << 48) | 9;
  authority.applicationID = 7;
  authority.operationID = 77;
  authority.revision = 10;
  authority.phase = StatefulWorkerTopologyUpgradePhase::none;
  authority.sourceEpoch = 22;
  authority.targetEpoch = 22;
  for (uint32_t i = 0; i < 3; ++i)
  {
    auto state = servingAuthorityTestState(10 + i, 20 + i, i == 0);
    transition.servingRuntimeStates.push_back(state);
    if (i == 0) authority.targetConfig = state.plan.config;
    ProdigyStatefulServingAuthorityMember member = {};
    member.containerUUID = state.plan.uuid; member.machineUUID = state.machineUUID;
    member.shardGroup = 0; member.advertiseClient = i == 0;
    (void)prodigyStatefulServingRuntimeDigest(state, member.planSHA256);
    authority.members.push_back(std::move(member));
  }
  transition.runtimeState.statefulServingAuthorities.push_back(std::move(authority));
  return transition;
}

static void testStatefulServingAuthorityTransitionFences(TestSuite& suite)
{
  TestBrain receiver = {};
  auto valid = servingAuthorityTestTransition();
  Brain::PreparedMasterAuthorityTransition prepared = {};
  suite.expect(receiver.prepareReplicatedMasterAuthorityTransition(valid, prepared),
               "serving_authority_transition_accepts_complete_v2_payload");

  auto missing = valid; missing.servingRuntimeStates.clear();
  suite.expect(!receiver.prepareReplicatedMasterAuthorityTransition(missing, prepared),
               "serving_authority_transition_rejects_missing_payload_before_persistence");
  auto changed = valid; changed.servingRuntimeStates[0].plan.uuid += 1;
  suite.expect(!receiver.prepareReplicatedMasterAuthorityTransition(changed, prepared),
               "serving_authority_transition_rejects_changed_payload_before_persistence");
  receiver.masterAuthorityRuntimeState = valid.runtimeState;
  receiver.statefulServingRuntimeStates = valid.servingRuntimeStates;
  receiver.masterAuthorityRuntimeStateDurable = true;
  receiver.durableMasterAuthorityRuntimeStateGeneration = valid.runtimeState.generation;
  auto stale = valid; stale.runtimeState.generation = 11; stale.runtimeState.statefulServingAuthorities[0].revision = 9;
  suite.expect(!receiver.prepareReplicatedMasterAuthorityTransition(stale, prepared),
               "serving_authority_transition_rejects_stale_revision");
  ContainerPlan stalePlan = valid.servingRuntimeStates[0].plan;
  stalePlan.advertisements.clear();
  stalePlan.statefulTopology.servingMode = StatefulTopologyServingMode::catchupOnly;
  suite.expect(receiver.projectStatefulServingPlan(stalePlan, valid.servingRuntimeStates[0].machineUUID) &&
                   stalePlan.advertisements.contains(99) && stalePlan.statefulTopology.servingMode == StatefulTopologyServingMode::serve,
               "serving_authority_stale_inventory_cannot_remove_selected_client");
  suite.expect(!receiver.projectStatefulServingPlan(stalePlan, 999),
               "serving_authority_inventory_wrong_machine_is_rejected");
  auto wrongDeployment = valid.servingRuntimeStates[0].plan;
  ++wrongDeployment.config.versionID;
  suite.expect(!receiver.projectStatefulServingPlan(wrongDeployment, valid.servingRuntimeStates[0].machineUUID),
               "serving_authority_uuid_cannot_move_to_uncovered_deployment");
  auto next = valid;
  next.runtimeState.generation = 11;
  next.runtimeState.statefulServingAuthorities[0].revision = 11;
  receiver.persistSucceeds = false;
  suite.expect(!receiver.applyReplicatedMasterAuthorityTransition(next, true) &&
                   receiver.masterAuthorityRuntimeState.generation == 10 && receiver.statefulServingRuntimeStates.size() == 3,
               "serving_authority_failed_persistence_keeps_previous_revision_and_payload");
  String previousDigest, retainedDigest;
  prodigyStatefulServingRuntimeDigest(valid.servingRuntimeStates[0], previousDigest);
  prodigyStatefulServingRuntimeDigest(receiver.statefulServingRuntimeStates[0], retainedDigest);
  suite.expect(previousDigest.equals(retainedDigest), "serving_authority_failed_persistence_keeps_previous_exact_payload");
  auto legacy = valid; legacy.version = 1;
  suite.expect(!receiver.prepareReplicatedMasterAuthorityTransition(legacy, prepared),
               "serving_authority_transition_rejects_legacy_payload_version");
}

static void testStatefulServingAuthorityAsyncReceipt(TestSuite& suite)
{
  ScopedRing scopedRing = {};
  TestNeuron self = {};
  self.uuid = 0x761005;
  NeuronBase *previousNeuron = thisNeuron;
  thisNeuron = &self;
  TestBrain follower = {};
  follower.asyncMasterAuthorityPersistence = true;
  follower.holdRuntimePersistence = true;
  follower.boottimens = 761004;
  BrainView master = {};
  authorizeMasterPeerForTest(follower, master, 77, 0x761001, 761001);
  follower.brains.insert(&master);
  auto transition = servingAuthorityTestTransition();
  transition.brainConfig.clusterUUID = 0x761002;
  String serialized, messageBuffer;
  BitseryEngine::serialize(serialized, transition);
  auto ackCount = [&]() {
    uint32_t count = 0;
    forEachMessageInBuffer(master.wBuffer, [&](Message *message) {
      if (BrainTopic(message->topic) == BrainTopic::replicateMasterAuthorityState) ++count;
    });
    return count;
  };
  auto submit = [&]() {
    follower.brainHandler(&master, buildBrainMessage(messageBuffer, BrainTopic::replicateMasterAuthorityState, serialized));
  };
  submit();
  suite.expect(follower.pendingRuntimePersistence.size() == 1 && ackCount() == 0 &&
                   follower.statefulServingRuntimeStates.empty(),
               "serving_authority_held_private_payload_has_no_early_apply_or_ack");
  follower.finishRuntimePersistence(false);
  suite.expect(follower.masterAuthorityRuntimeState.generation == 0 &&
                   follower.statefulServingRuntimeStates.empty() && ackCount() == 0,
               "serving_authority_async_failed_persistence_has_no_apply_or_ack");
  submit();
  follower.finishRuntimePersistence(true);
  suite.expect(follower.masterAuthorityRuntimeState.generation == 10 &&
                   follower.statefulServingRuntimeStates.size() == 3 && ackCount() == 1,
               "serving_authority_async_durable_private_payload_precedes_ack");
  follower.brains.erase(&master);
  thisNeuron = previousNeuron;
}

static void testStatefulServingAuthorityFanoutCapability(TestSuite& suite)
{
  ScopedRing ring = {};
  TestBrain master = {};
  master.weAreMaster = true;
  master.nBrains = 2;
  auto transition = servingAuthorityTestTransition();
  master.masterAuthorityRuntimeState = transition.runtimeState;
  master.statefulServingRuntimeStates = transition.servingRuntimeStates;
  master.masterAuthorityRuntimeStateDurable = true;
  master.durableMasterAuthorityRuntimeStateGeneration = transition.runtimeState.generation;
  BrainView peer = {};
  peer.uuid = 0x762001;
  peer.boottimens = 762001;
  peer.ioGeneration = 2;
  peer.connected = true;
  peer.isFixedFile = true;
  peer.fslot = 76;
  peer.registrationFresh = true;
  peer.pendingSend = true;
  master.brains.insert(&peer);
  auto count = [&]() {
    uint32_t frames = 0;
    forEachMessageInBuffer(peer.wBuffer, [&](Message *message) {
      if (BrainTopic(message->topic) == BrainTopic::replicateMasterAuthorityState) ++frames;
    });
    return frames;
  };
  master.queueMasterAuthorityRuntimeStateReplication(false);
  suite.expect(count() == 0 && !master.masterAuthorityReplicationByPeer.contains(&peer),
               "serving_authority_normal_fanout_rejects_incapable_peer_without_sent_receipt");
  reserveTransportStream(peer);
  ProdigyTransportTLSStream client = {};
  reserveTransportStream(client);
  if (configureSingleNodeTransportRuntime(suite, "serving_fanout_tls", peer.uuid) &&
      suite.require(peer.beginTransportTLS(true) && client.beginTransportTLS(false) &&
                    completeTransportHandshake(client, peer), "serving_fanout_tls_handshake"))
  {
    peer.tlsPeerVerified = true;
    peer.tlsPeerUUID = peer.uuid;
    peer.clearQueuedSendBytes();
    peer.pendingSend = true;
    peer.pendingSendBytes = 0;
    peer.containerRetirementCapabilityAcknowledged = true;
    peer.containerRetirementCapabilityUUID = peer.uuid;
    peer.containerRetirementCapabilityBootNs = peer.boottimens;
    peer.containerRetirementCapabilityIOGeneration = peer.ioGeneration;
    master.queueMasterAuthorityRuntimeStateReplication(false);
    suite.expect(count() == 0 && !master.masterAuthorityReplicationByPeer.contains(&peer),
                 "serving_authority_normal_fanout_requires_serving_bit_in_addition_to_retirement");
    peer.statefulServingAuthorityCapabilityAcknowledged = true;
    master.queueMasterAuthorityRuntimeStateReplication(false);
    suite.expect(count() == 1 && master.masterAuthorityReplicationByPeer.contains(&peer),
                 "serving_authority_normal_fanout_sends_to_fresh_tls_capable_peer");
    peer.clearQueuedSendBytes(); peer.pendingSend = true; peer.pendingSendBytes = 0;
    master.masterAuthorityReplicationByPeer.erase(&peer);
    ++peer.ioGeneration;
    master.queueMasterAuthorityRuntimeStateReplication(false);
    suite.expect(count() == 0 && !master.masterAuthorityReplicationByPeer.contains(&peer),
                 "serving_authority_normal_fanout_rejects_stale_connection_capability");
  }
  master.brains.erase(&peer);
  ProdigyTransportTLSRuntime::clear();
}
