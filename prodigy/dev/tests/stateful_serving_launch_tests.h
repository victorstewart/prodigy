#pragma once

// Included after the concrete Brain fixtures and serving-authority helpers.
static void testStatefulServingSnapshotFiltersOnlyUnsentReservations(TestSuite& suite);

static void testStatefulServingLaunchAdmission(TestSuite& suite)
{
  ScopedFreshRing ring = {};
  TestNeuron local = {};
  local.uuid = 0x77110001;
  NeuronBase *previousNeuron = thisNeuron;
  BrainBase *previousBrain = thisBrain;
  thisNeuron = &local;
  StreamingTestBrain brain = {};
  thisBrain = &brain;
  brain.weAreMaster = true;
  brain.nBrains = 1;
  brain.hasAuthoritativeTopology = true;
  ClusterMachine self = {}; self.uuid = local.uuid; self.isBrain = true;
  brain.authoritativeTopology.machines.push_back(self);
  brain.masterAuthorityRuntimeState.generation = 40;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = 40;
  brain.holdRuntimePersistence = true;
  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(7, 9);
  deployment.plan.isStateful = true;
  deployment.plan.config.type = ApplicationType::stateful;
  deployment.nShardGroups = 1;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  Machine machine = {}; machine.uuid = local.uuid;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  ProdigyStatefulServingAuthority authority = {};
  authority.deploymentID = deployment.plan.config.deploymentID();
  authority.applicationID = 7;
  authority.operationID = 7711;
  authority.revision = 40;
  authority.phase = StatefulWorkerTopologyUpgradePhase::greenBootstrap;
  authority.sourceEpoch = 22;
  authority.targetEpoch = 33;
  authority.targetConfig = deployment.plan.config;
  auto launchState = [&](uint128_t uuid, bool source, bool client) {
    auto state = servingAuthorityTestState(uuid, machine.uuid, client);
    state.plan.config = deployment.plan.config;
    state.plan.state = ContainerState::scheduled;
    state.plan.statefulTopology.operationID = authority.operationID;
    state.plan.statefulTopology.sourceEpoch = authority.sourceEpoch;
    state.plan.statefulTopology.targetEpoch = authority.targetEpoch;
    state.plan.statefulTopology.topologyEpoch = source ? authority.sourceEpoch : authority.targetEpoch;
    state.plan.statefulTopology.servingMode = source ? StatefulTopologyServingMode::serve : StatefulTopologyServingMode::catchupOnly;
    state.plan.statefulTopology.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;
    return state;
  };
  for (uint32_t i = 0; i < 3; ++i)
  {
    auto state = launchState(0x77111000 + i, true, i == 0);
    ProdigyStatefulServingAuthorityMember member = {};
    member.containerUUID = state.plan.uuid;
    member.machineUUID = machine.uuid;
    member.isSource = true;
    member.advertiseClient = i == 0;
    prodigyStatefulServingRuntimeDigest(state, member.planSHA256);
    authority.members.push_back(member);
    brain.statefulServingRuntimeStates.push_back(state);
  }
  brain.masterAuthorityRuntimeState.statefulServingAuthorities.push_back(authority);
  suite.require(brain.containerRetirementAuthorityAcknowledged(), "serving_launch_initial_authority_is_qualified");
  ContainerView target[4];
  ContainerPlan plans[4];
  for (uint32_t i = 0; i < 4; ++i)
  {
    plans[i] = launchState(0x77112000 + i, false, false).plan;
    target[i].uuid = plans[i].uuid;
    target[i].deploymentID = authority.deploymentID;
    target[i].applicationID = authority.applicationID;
    target[i].machine = &machine;
    target[i].isStateful = true;
    target[i].state = ContainerState::scheduled;
    brain.containers.insert_or_assign(target[i].uuid, &target[i]);
  }
  using Admission = BrainBase::StatefulServingLaunchAdmission;
  for (uint32_t i = 0; i < 3; ++i)
  {
    ContainerPlan unknown = plans[i];
    suite.expect(!brain.projectStatefulServingPlan(unknown, machine.uuid), "serving_launch_unknown_uuid_cannot_supply_its_own_authority");
    const auto before = brain.masterAuthorityRuntimeState.generation;
    suite.expect(brain.prepareStatefulServingLaunch(&deployment, &target[i], plans[i], machine.uuid) == Admission::pending &&
                     brain.pendingRuntimePersistence.size() == 1 && machine.neuron.wBuffer.empty(),
                 "serving_launch_exact_green_target_waits_for_persistence");
    if (i < 2)
      suite.expect(brain.prepareStatefulServingLaunch(&deployment, &target[i + 1], plans[i + 1], machine.uuid) == Admission::pending &&
                       brain.masterAuthorityRuntimeState.generation == before + 1 && brain.pendingRuntimePersistence.size() == 1,
                   "serving_launch_serializes_next_target_behind_current_receipt");
    if (i == 0)
    {
      brain.finishRuntimePersistence(false);
      suite.expect(brain.prepareStatefulServingLaunch(&deployment, &target[i], plans[i], machine.uuid) == Admission::pending,
                   "serving_launch_failed_receipt_keeps_exact_launch_blocked");
      brain.retryMasterAuthorityRuntimeStatePersistence();
    }
    brain.finishRuntimePersistence(true);
    suite.expect(brain.prepareStatefulServingLaunch(&deployment, &target[i], plans[i], machine.uuid) == Admission::ready,
                 "serving_launch_durable_exact_member_becomes_ready");
    auto changed = plans[i]; changed.config.memoryMB += 1;
    suite.expect(brain.prepareStatefulServingLaunch(&deployment, &target[i], changed, machine.uuid) == Admission::rejected,
                 "serving_launch_changed_plan_cannot_reuse_sealed_member");
  }
  const auto generation = brain.masterAuthorityRuntimeState.generation;
  suite.expect(brain.prepareStatefulServingLaunch(&deployment, &target[3], plans[3], machine.uuid) == Admission::rejected &&
                   brain.masterAuthorityRuntimeState.generation == generation,
               "serving_launch_fourth_target_rejected_without_mutation");
  auto steady = servingAuthorityTestTransition();
  brain.masterAuthorityRuntimeState = steady.runtimeState;
  brain.statefulServingRuntimeStates = steady.servingRuntimeStates;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = steady.runtimeState.generation;
  plans[3].statefulTopology = steady.servingRuntimeStates[0].plan.statefulTopology;
  plans[3].config = steady.servingRuntimeStates[0].plan.config;
  suite.expect(brain.prepareStatefulServingLaunch(&deployment, &target[3], plans[3], machine.uuid) == Admission::rejected &&
                   brain.masterAuthorityRuntimeState.generation == steady.runtimeState.generation &&
                   machine.neuron.wBuffer.empty(),
               "serving_launch_ordinary_replacement_needs_terminal_proof");
  for (const auto& container : target) brain.containers.erase(container.uuid);
  brain.deployments.erase(authority.deploymentID);
  brain.machines.erase(&machine);
  brain.machinesByUUID.erase(machine.uuid);
  thisBrain = previousBrain;
  thisNeuron = previousNeuron;

  testStatefulServingSnapshotFiltersOnlyUnsentReservations(suite);
}

// Snapshot filtering is deliberately driven by the same canonical runtime
// record used in production.  A planned covered-green reservation has not
// reached the Neuron and may be recomputed after a cold restart; a scheduled
// record without the deployment's deferred-authority proof must remain.
static void testStatefulServingSnapshotFiltersOnlyUnsentReservations(TestSuite& suite)
{
  ScopedFreshRing ring = {};
  TestNeuron local = {};
  local.uuid = 0x77113001;
  NeuronBase *previousNeuron = thisNeuron;
  BrainBase *previousBrain = thisBrain;
  thisNeuron = &local;
  StreamingTestBrain brain = {};
  thisBrain = &brain;
  brain.weAreMaster = true;
  brain.nBrains = 1;
  brain.hasAuthoritativeTopology = true;
  ClusterMachine self = {}; self.uuid = local.uuid; self.isBrain = true;
  brain.authoritativeTopology.machines.push_back(self);
  brain.masterAuthorityRuntimeState.generation = 71;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = 71;

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(71, 19);
  deployment.plan.isStateful = true;
  deployment.plan.config.type = ApplicationType::stateful;
  deployment.nShardGroups = 1;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  Machine machine = {}; machine.uuid = local.uuid; machine.private4 = 0x0a771301;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

  ProdigyStatefulServingAuthority authority = {};
  authority.deploymentID = deployment.plan.config.deploymentID();
  authority.applicationID = deployment.plan.config.applicationID;
  authority.operationID = 0x771130;
  authority.revision = brain.masterAuthorityRuntimeState.generation;
  authority.phase = StatefulWorkerTopologyUpgradePhase::greenBootstrap;
  authority.sourceEpoch = 17;
  authority.targetEpoch = 71;
  authority.targetConfig = deployment.plan.config;

  ContainerView admitted = {}, planned = {}, scheduled = {}, wrongOperation = {};
  auto makeTarget = [&](ContainerView& container, uint128_t uuid, ContainerState state, uint32_t operationID) {
    container.uuid = uuid;
    container.deploymentID = deployment.plan.config.deploymentID();
    container.applicationID = deployment.plan.config.applicationID;
    container.machine = &machine;
    container.isStateful = true;
    container.shardGroup = 0;
    container.lifetime = ApplicationLifetime::base;
    container.state = state;
    container.explicitStatefulMeshRoles =
        StatefulMeshRoles::forShardGroup(deployment.plan.stateful, deployment.plan.config.applicationID, 0);
    container.explicitStatefulTopology.operationID = operationID;
    container.explicitStatefulTopology.shardGroup = 0;
    container.explicitStatefulTopology.topologyEpoch = authority.targetEpoch;
    container.explicitStatefulTopology.workerCount = 2;
    container.explicitStatefulTopology.servingMode = StatefulTopologyServingMode::catchupOnly;
    container.explicitStatefulTopology.sourceEpoch = authority.sourceEpoch;
    container.explicitStatefulTopology.targetEpoch = authority.targetEpoch;
    container.explicitStatefulTopology.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;
    brain.containers.insert_or_assign(container.uuid, &container);
    deployment.containers.insert(&container);
    deployment.containersByShardGroup.insert(0, &container);
  };
  makeTarget(admitted, 0x77113101, ContainerState::planned, authority.operationID);
  makeTarget(planned, 0x77113102, ContainerState::planned, authority.operationID);
  makeTarget(scheduled, 0x77113103, ContainerState::scheduled, authority.operationID);
  makeTarget(wrongOperation, 0x77113104, ContainerState::planned, authority.operationID + 1);

  // Membership, rather than the local state enum, is the durable admission
  // proof.  Keep this UUID even while the launch's local persistence is held.
  ProdigyStatefulServingAuthorityMember admittedMember = {};
  admittedMember.containerUUID = admitted.uuid;
  admittedMember.machineUUID = machine.uuid;
  admittedMember.shardGroup = 0;
  admittedMember.isSource = false;
  BrainReplicatedContainerRuntimeState admittedState = {};
  suite.require(brain.captureReplicatedContainerRuntimeState(&admitted, admittedState) &&
                    prodigyStatefulServingRuntimeDigest(admittedState, admittedMember.planSHA256),
                "serving_launch_snapshot_has_exact_admitted_payload");
  authority.members.push_back(admittedMember);
  brain.statefulServingRuntimeStates.push_back(admittedState);
  for (uint32_t index = 0; index < 3; ++index)
  {
    auto source = servingAuthorityTestState(0x77113201 + index, machine.uuid, index == 0);
    source.plan.config = deployment.plan.config;
    source.plan.statefulTopology.operationID = authority.operationID;
    source.plan.statefulTopology.topologyEpoch = authority.sourceEpoch;
    source.plan.statefulTopology.sourceEpoch = authority.sourceEpoch;
    source.plan.statefulTopology.targetEpoch = authority.targetEpoch;
    source.plan.statefulTopology.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;
    ProdigyStatefulServingAuthorityMember member = {};
    member.containerUUID = source.plan.uuid; member.machineUUID = source.machineUUID;
    member.isSource = true; member.advertiseClient = index == 0;
    prodigyStatefulServingRuntimeDigest(source, member.planSHA256);
    authority.members.push_back(member);
    brain.statefulServingRuntimeStates.push_back(source);
  }
  suite.require(prodigyValidateStatefulServingAuthority(authority, brain.statefulServingRuntimeStates, authority.revision),
                "serving_launch_snapshot_uses_valid_partial_green_authority");
  brain.masterAuthorityRuntimeState.statefulServingAuthorities.push_back(authority);

  BrainReplicatedContainerRuntimeState plannedPending = {};
  BrainReplicatedContainerRuntimeState scheduledPending = {};
  BrainReplicatedContainerRuntimeState wrongPending = {};
  suite.require(brain.captureReplicatedContainerRuntimeState(&planned, plannedPending) &&
                    brain.captureReplicatedContainerRuntimeState(&scheduled, scheduledPending) &&
                    brain.captureReplicatedContainerRuntimeState(&wrongOperation, wrongPending),
                "serving_launch_snapshot_filter_builds_canonical_runtime_records");
  brain.pendingReplicatedContainerRuntimeStates[deployment.plan.config.deploymentID()].push_back(plannedPending);
  brain.pendingReplicatedContainerRuntimeStates[deployment.plan.config.deploymentID()].push_back(scheduledPending);
  brain.pendingReplicatedContainerRuntimeStates[deployment.plan.config.deploymentID()].push_back(wrongPending);

  ProdigyPersistentMasterAuthorityPackage package = {};
  brain.capturePersistentMasterAuthorityPackage(package);
  bytell_hash_set<uint128_t> captured;
  for (const auto& state : package.containerRuntimeStates) captured.insert(state.plan.uuid);
  suite.expect(captured.contains(admitted.uuid) && !captured.contains(planned.uuid) &&
                   captured.contains(scheduled.uuid) && captured.contains(wrongOperation.uuid),
               "serving_launch_snapshot_omits_only_unadmitted_exact_planned_green_reservation");
  String encoded;
  BitseryEngine::serialize(encoded, package);
  ProdigyPersistentMasterAuthorityPackage decoded = {};
  suite.require(BitseryEngine::deserializeSafe(encoded, decoded), "serving_launch_partial_snapshot_roundtrips");
  TestBrain cold = {};
  suite.require(cold.applyPersistentMasterAuthorityPackage(decoded), "serving_launch_partial_snapshot_cold_apply");
  bytell_hash_set<uint128_t> coldUUIDs;
  for (const auto& [deploymentID, states] : cold.pendingReplicatedContainerRuntimeStates)
    for (const auto& state : states) coldUUIDs.insert(state.plan.uuid);
  suite.expect(coldUUIDs.contains(admitted.uuid) && !coldUUIDs.contains(planned.uuid) &&
                   coldUUIDs.contains(scheduled.uuid) && coldUUIDs.contains(wrongOperation.uuid),
               "serving_launch_cold_restore_preserves_admitted_and_uncertain_records_only");

  suite.expect(!brain.isUnsentStatefulServingReservation(scheduledPending) &&
                   !brain.isUnsentStatefulServingReservation(wrongPending),
               "serving_launch_snapshot_requires_deferred_authority_proof_and_exact_operation");

  // The full recovery barrier is deliberately separate from authority
  // projection: no scheduling path may run while it remains false.
  brain.recoveringPersistedNeuronInventory = true;
  suite.expect(!brain.statefulServingRecoveryReady(),
               "serving_launch_snapshot_recovery_barrier_closes_before_target_refill");
  brain.recoveringPersistedNeuronInventory = false;
  suite.expect(!brain.statefulServingRecoveryReady(),
               "serving_launch_snapshot_pending_records_also_hold_recovery");
  brain.pendingReplicatedContainerRuntimeStates.clear();
  suite.expect(brain.statefulServingRecoveryReady(),
               "serving_launch_snapshot_recovery_barrier_reopens_after_inventory_settles");

  for (ContainerView *container : {&admitted, &planned, &scheduled, &wrongOperation})
  {
    deployment.containers.erase(container);
    while (deployment.containersByShardGroup.eraseEntry(0, container)) {}
    brain.containers.erase(container->uuid);
  }
  brain.pendingReplicatedContainerRuntimeStates.clear();
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.machines.erase(&machine);
  brain.machinesByUUID.erase(machine.uuid);
  thisBrain = previousBrain;
  thisNeuron = previousNeuron;
}
