#pragma once

// Include after the credential unit's TestBrain and TestSuite fixtures.

static ProdigyContainerRetirementIntent containerRetirementAuthorityIntent(
    uint128_t containerUUID, uint128_t machineUUID, bool acknowledged = false)
{
  ProdigyContainerRetirementIntent intent = {};
  intent.containerUUID = containerUUID;
  intent.applicationID = 73;
  intent.deploymentID = (uint64_t(intent.applicationID) << 48) | 19;
  intent.machineUUID = machineUUID;
  intent.topologyOperationID = 211;
  intent.sourceEpoch = 3;
  intent.targetEpoch = 4;
  intent.intentGeneration = 100;
  intent.killAcked = acknowledged;
  if (!acknowledged)
  {
    NeuronContainerBootstrap bootstrap = {};
    bootstrap.plan.uuid = containerUUID;
    bootstrap.plan.config.applicationID = intent.applicationID;
    bootstrap.plan.config.versionID = 19;
    bootstrap.plan.config.type = ApplicationType::stateful;
    bootstrap.plan.isStateful = true;
    bootstrap.plan.restartOnFailure = false;
    BitseryEngine::serialize(intent.bootstrap, bootstrap);
  }
  return intent;
}

static bool containerRetirementInstallJournal(
    TestBrain& brain, const ProdigyContainerRetirementJournal& journal)
{
  return prodigyStoreContainerRetirementJournalCarrier(
      brain.masterAuthorityRuntimeState.taskExecutions, journal, 1);
}

static void testContainerRetirementAuthority(TestSuite& suite)
{
  constexpr uint128_t machineUUID = uint128_t(0x730001);
  constexpr uint128_t sourceUUID = uint128_t(0x730011);
  constexpr uint128_t extraUUID = uint128_t(0x730012);

  TestBrain brain = {};
  brain.masterAuthorityRuntimeState.generation = 100;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = 100;

  ProdigyContainerRetirementJournal current = {};
  current.intents.push_back(containerRetirementAuthorityIntent(sourceUUID, machineUUID));
  suite.expect(containerRetirementInstallJournal(brain, current),
               "container_retirement_authority_setup_journal");

  // The replicated-authority preparation path must reject a sender that
  // removes, rewinds, or rebinds a durable retirement source before persistence.
  auto rejectsIncoming = [&brain](ProdigyMasterAuthorityRuntimeState incoming) {
    Brain::PreparedMasterAuthorityRuntimeState prepared = {};
    return brain.prepareReplicatedMasterAuthorityRuntimeState(incoming, prepared) == false;
  };

  ProdigyMasterAuthorityRuntimeState removed = brain.masterAuthorityRuntimeState;
  removed.taskExecutions.erase(prodigyContainerRetirementJournalExecutionID);
  removed.generation += 1;
  suite.expect(rejectsIncoming(removed), "container_retirement_authority_rejects_journal_removal");

  ProdigyContainerRetirementJournal acked = current;
  acked.intents[0].killAcked = true;
  acked.intents[0].bootstrap.clear();
  ProdigyMasterAuthorityRuntimeState acknowledged = brain.masterAuthorityRuntimeState;
  suite.expect(prodigyStoreContainerRetirementJournalCarrier(
                   acknowledged.taskExecutions, acked, 2),
               "container_retirement_authority_ack_setup");
  acknowledged.generation += 1;
  Brain::PreparedMasterAuthorityRuntimeState prepared = {};
  const bool acceptedAck = brain.prepareReplicatedMasterAuthorityRuntimeState(acknowledged, prepared);
  suite.expect(acceptedAck, "container_retirement_authority_accepts_monotonic_ack");

  ProdigyMasterAuthorityRuntimeState futureGeneration = acknowledged;
  futureGeneration.generation += 2;
  ProdigyContainerRetirementJournal futureJournal = acked;
  auto futureIntent = containerRetirementAuthorityIntent(extraUUID, machineUUID);
  futureIntent.intentGeneration = futureGeneration.generation + 1;
  futureJournal.intents.push_back(std::move(futureIntent));
  suite.expect(prodigyWriteContainerRetirementJournalCarrier(
                   futureGeneration.taskExecutions.at(prodigyContainerRetirementJournalExecutionID), futureJournal, 3),
               "container_retirement_authority_future_intent_setup");
  suite.expect(rejectsIncoming(futureGeneration),
               "container_retirement_authority_rejects_future_intent_generation");

  // Preparation has no side effects. Make the acknowledged carrier the local
  // baseline before proving that later authority input cannot roll it back.
  brain.masterAuthorityRuntimeState = acknowledged;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = acknowledged.generation;

  ProdigyMasterAuthorityRuntimeState ackReversed = acknowledged;
  suite.expect(prodigyWriteContainerRetirementJournalCarrier(
                   ackReversed.taskExecutions.at(prodigyContainerRetirementJournalExecutionID), current, 3),
               "container_retirement_authority_ack_reverse_bytes_setup");
  ackReversed.generation += 1;
  suite.expect(rejectsIncoming(ackReversed), "container_retirement_authority_rejects_ack_reversal");

  ProdigyContainerRetirementJournal conflicted = acked;
  conflicted.intents[0].machineUUID += 1;
  ProdigyMasterAuthorityRuntimeState identityConflict = acknowledged;
  suite.expect(prodigyWriteContainerRetirementJournalCarrier(
                   identityConflict.taskExecutions.at(prodigyContainerRetirementJournalExecutionID), conflicted, 4),
               "container_retirement_authority_identity_conflict_bytes_setup");
  identityConflict.generation += 1;
  suite.expect(rejectsIncoming(identityConflict), "container_retirement_authority_rejects_identity_conflict");

  // The remaining bootstrap/package cases use the original pending source.
  brain.masterAuthorityRuntimeState.generation = 100;
  brain.masterAuthorityRuntimeState.taskExecutions.clear();
  suite.expect(containerRetirementInstallJournal(brain, current),
               "container_retirement_bootstrap_restores_pending_fixture");

  Machine machine = {};
  machine.uuid = machineUUID;
  Vector<String> bootstraps = {};
  NeuronContainerBootstrap restartable = {};
  restartable.plan.uuid = sourceUUID;
  restartable.plan.config.applicationID = 73;
  restartable.plan.config.versionID = 19;
  restartable.plan.config.type = ApplicationType::stateful;
  restartable.plan.isStateful = true;
  restartable.plan.restartOnFailure = true;
  String restartableBytes = {};
  BitseryEngine::serialize(restartableBytes, restartable);
  bootstraps.push_back(std::move(restartableBytes));
  const bool replaced = brain.mergeContainerRetirementBootstraps(&machine, bootstraps) && bootstraps.size() == 1;
  suite.expect(replaced, "container_retirement_bootstrap_replaces_restartable_source");
  NeuronContainerBootstrap adoption = {};
  suite.expect(replaced && BitseryEngine::deserializeSafe(bootstraps[0], adoption) &&
                   adoption.plan.uuid == sourceUUID && adoption.plan.restartOnFailure == false,
               "container_retirement_bootstrap_uses_adoption_only_source");

  ProdigyContainerRetirementJournal withExtra = current;
  withExtra.intents.push_back(containerRetirementAuthorityIntent(extraUUID, machineUUID));
  suite.expect(containerRetirementInstallJournal(brain, withExtra),
               "container_retirement_bootstrap_pending_setup");
  bootstraps.clear();
  suite.expect(brain.mergeContainerRetirementBootstraps(&machine, bootstraps) && bootstraps.size() == 2,
               "container_retirement_bootstrap_appends_missing_pending_source");

  ProdigyContainerRetirementJournal terminal = withExtra;
  for (auto& intent : terminal.intents)
  {
    intent.killAcked = true;
    intent.bootstrap.clear();
  }
  suite.expect(containerRetirementInstallJournal(brain, terminal),
               "container_retirement_bootstrap_terminal_setup");
  bootstraps.clear();
  suite.expect(brain.mergeContainerRetirementBootstraps(&machine, bootstraps) && bootstraps.empty(),
               "container_retirement_bootstrap_excludes_terminal_source");

  BrainReplicatedContainerRuntimeState pending = {};
  pending.machineUUID = machineUUID;
  pending.plan.uuid = sourceUUID;
  pending.plan.config.applicationID = 73;
  pending.plan.config.versionID = 19;
  brain.pendingReplicatedContainerRuntimeStates[pending.plan.config.deploymentID()].push_back(pending);
  ProdigyPersistentMasterAuthorityPackage package = {};
  brain.capturePersistentMasterAuthorityPackage(package);
  suite.expect(package.containerRuntimeStates.empty(),
               "container_retirement_package_filters_pending_runtime_source");
}

static void testContainerRetirementAuthorityQuarantinesDelayedRuntime(TestSuite& suite)
{
  ScopedFreshRing ring = {};
  constexpr uint16_t applicationID = 73;
  constexpr uint128_t machineUUID = uint128_t(0x730101);
  constexpr uint128_t sourceUUID = uint128_t(0x730111);
  constexpr uint128_t controlUUID = uint128_t(0x730112);

  TestBrain brain = {};
  Mesh mesh = {};
  brain.mesh = &mesh;
  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;
  brain.weAreMaster = false;
  brain.noMasterYet = false;
  brain.brainConfig.datacenterFragment = 1;
  brain.masterAuthorityRuntimeState.generation = 100;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = 100;

  Machine machine = {};
  machine.uuid = machineUUID;
  machine.private4 = 0x0a730101;
  machine.fragment = 1;
  machine.state = MachineState::healthy;
  machine.runtimeReady = true;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

  ApplicationDeployment deployment = {};
  seedStatefulDeployRequestPlan(deployment.plan, applicationID);
  deployment.plan.config.versionID = 19;
  deployment.nShardGroups = 1;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(applicationID, &deployment);

  auto runtimeState = [&](uint128_t containerUUID, uint16_t port) {
    BrainReplicatedContainerRuntimeState state = {};
    state.machineUUID = machine.uuid;
    state.machinePrivate4 = machine.private4;
    state.plan.uuid = containerUUID;
    state.plan.config = deployment.plan.config;
    state.plan.isStateful = true;
    state.plan.state = ContainerState::healthy;
    state.plan.runtimeReady = true;
    state.plan.fragment = uint8_t(containerUUID & 0xff);
    state.plan.createdAtMs = 731;
    const uint64_t service = (uint64_t(applicationID) << 48) | uint64_t(port);
    state.plan.advertisements.insert_or_assign(
        service, Advertisement(service, ContainerState::healthy, ContainerState::destroying, port));
    Subscription subscription = {};
    subscription.service = service + 0x1000000;
    subscription.nature = SubscriptionNature::all;
    subscription.startAt = ContainerState::healthy;
    subscription.stopAt = ContainerState::destroying;
    state.plan.subscriptions.insert_or_assign(subscription.service, subscription);
    return state;
  };

  const BrainReplicatedContainerRuntimeState oldHealthySource = runtimeState(sourceUUID, 19'181);
  const BrainReplicatedContainerRuntimeState unrelatedHealthyControl = runtimeState(controlUUID, 19'182);
  brain.applyReplicatedContainerRuntimeState(oldHealthySource);
  brain.applyReplicatedContainerRuntimeState(unrelatedHealthyControl);
  auto sourceIt = brain.containers.find(sourceUUID);
  auto controlIt = brain.containers.find(controlUUID);
  ContainerView *source = sourceIt != brain.containers.end() ? sourceIt->second : nullptr;
  ContainerView *control = controlIt != brain.containers.end() ? controlIt->second : nullptr;
  suite.expect(source != nullptr && control != nullptr &&
                   deployment.containers.contains(source) && deployment.containers.contains(control) &&
                   !source->advertisements.empty() && !control->advertisements.empty() &&
                   !source->subscriptions.empty() && source->advertisingOnPorts.contains(19'181),
               "container_retirement_runtime_ordinary_live_upserts_apply_before_authority_fence");

  ProdigyContainerRetirementJournal pendingJournal = {};
  pendingJournal.intents.push_back(containerRetirementAuthorityIntent(sourceUUID, machineUUID));
  ProdigyMasterAuthorityRuntimeState pendingAuthority = brain.masterAuthorityRuntimeState;
  pendingAuthority.generation = 101;
  suite.require(prodigyStoreContainerRetirementJournalCarrier(
                    pendingAuthority.taskExecutions, pendingJournal, 101),
                "container_retirement_runtime_pending_authority_setup");
  suite.require(brain.applyReplicatedMasterAuthorityRuntimeState(pendingAuthority, false),
                "container_retirement_runtime_pending_authority_applies");

  sourceIt = brain.containers.find(sourceUUID);
  source = sourceIt != brain.containers.end() ? sourceIt->second : nullptr;
  auto machineIndex = machine.containersByDeploymentID.find(deployment.plan.config.deploymentID());
  bool sourceIndexed = false;
  bool controlIndexed = false;
  if (machineIndex != machine.containersByDeploymentID.end())
  {
    for (ContainerView *indexed : machineIndex->second)
    {
      sourceIndexed = sourceIndexed || indexed == source;
      controlIndexed = controlIndexed || indexed == control;
    }
  }
  suite.expect(source != nullptr && source->state == ContainerState::destroying &&
                   source->runtimeReady == false && source->advertisements.empty() &&
                   source->subscriptions.empty() && source->advertisingOnPorts.empty() &&
                   deployment.containers.contains(source) == false &&
                   deployment.waitingOnContainers.contains(source) && sourceIndexed == false &&
                   controlIndexed && deployment.containers.contains(control) &&
                   !control->advertisements.empty() && control->advertisingOnPorts.contains(19'182),
               "container_retirement_runtime_pending_authority_quarantines_only_source_and_preserves_lifetime");

  ProdigyContainerRetirementJournal terminalJournal = pendingJournal;
  terminalJournal.intents[0].killAcked = true;
  terminalJournal.intents[0].bootstrap.clear();
  ProdigyMasterAuthorityRuntimeState terminalAuthority = brain.masterAuthorityRuntimeState;
  terminalAuthority.generation = 102;
  suite.require(prodigyStoreContainerRetirementJournalCarrier(
                    terminalAuthority.taskExecutions, terminalJournal, 102),
                "container_retirement_runtime_terminal_authority_setup");
  suite.require(brain.applyReplicatedMasterAuthorityRuntimeState(terminalAuthority, false),
                "container_retirement_runtime_terminal_authority_applies");

  brain.applyReplicatedContainerRuntimeState(oldHealthySource);
  sourceIt = brain.containers.find(sourceUUID);
  source = sourceIt != brain.containers.end() ? sourceIt->second : nullptr;
  suite.expect(source != nullptr && source->state == ContainerState::destroying &&
                   deployment.containers.contains(source) == false &&
                   source->advertisements.empty() && control != nullptr &&
                   deployment.containers.contains(control),
               "container_retirement_runtime_delayed_healthy_source_cannot_resurrect_after_terminal_authority");

  ProdigyPersistentMasterAuthorityPackage package = {};
  brain.capturePersistentMasterAuthorityPackage(package);
  bool capturedSource = false;
  for (const BrainReplicatedContainerRuntimeState& state : package.containerRuntimeStates)
  {
    capturedSource = capturedSource || state.plan.uuid == sourceUUID;
  }
  TestBrain restored = {};
  thisBrain = &restored;
  suite.expect(capturedSource == false && restored.applyPersistentMasterAuthorityPackage(package),
               "container_retirement_runtime_terminal_package_excludes_source_before_cold_restore");
  Machine restoredMachine = {};
  restoredMachine.uuid = machine.uuid;
  restoredMachine.private4 = machine.private4;
  restoredMachine.fragment = machine.fragment;
  restoredMachine.state = MachineState::healthy;
  restoredMachine.runtimeReady = true;
  restoredMachine.neuron.machine = &restoredMachine;
  ApplicationDeployment restoredDeployment = {};
  restoredDeployment.plan = deployment.plan;
  restoredDeployment.nShardGroups = 1;
  restored.machines.insert(&restoredMachine);
  restored.machinesByUUID.insert_or_assign(restoredMachine.uuid, &restoredMachine);
  restored.deployments.insert_or_assign(restoredDeployment.plan.config.deploymentID(), &restoredDeployment);
  restored.deploymentsByApp.insert_or_assign(applicationID, &restoredDeployment);
  restored.applyReplicatedContainerRuntimeState(oldHealthySource);
  suite.expect(restored.containers.contains(sourceUUID) == false,
               "container_retirement_runtime_cold_restored_terminal_journal_rejects_delayed_source");

  restored.deploymentsByApp.erase(applicationID);
  restored.deployments.erase(restoredDeployment.plan.config.deploymentID());
  restored.machinesByUUID.erase(restoredMachine.uuid);
  restored.machines.erase(&restoredMachine);
  thisBrain = &brain;
  if (source != nullptr)
  {
    deployment.waitingOnContainers.erase(source);
    brain.containers.erase(sourceUUID);
    delete source;
  }
  if (control != nullptr)
  {
    mesh.stopAllSubscriptions(control);
    mesh.stopAllAdvertisments(control);
    deployment.containers.erase(control);
    machine.removeContainerIndexEntry(control->deploymentID, control);
    brain.containers.erase(controlUUID);
    delete control;
  }
  brain.deploymentsByApp.erase(applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  brain.mesh = nullptr;
  thisBrain = previousBrain;
}

static void testContainerRetirementDurability(TestSuite& suite)
{
  ScopedFreshRing ring = {};
  ScopedSocketPair sockets = {};
  if (!suite.require(sockets.create(suite, "retirement_terminal_socket"), "retirement_terminal_socket_ready")) return;
  TestNeuron local = {};
  local.uuid = 0x730001;
  NeuronBase *previousNeuron = thisNeuron;
  thisNeuron = &local;
  StreamingTestBrain brain = {};
  brain.weAreMaster = true;
  brain.nBrains = 1;
  brain.hasAuthoritativeTopology = true;
  ClusterMachine member = {};
  member.uuid = local.uuid;
  member.isBrain = true;
  brain.authoritativeTopology.machines.push_back(member);
  brain.masterAuthorityRuntimeState.generation = 100;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = 100;
  Machine machine = {};
  machine.uuid = local.uuid;
  machine.neuron.machine = &machine;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = sockets.adoptLeftIntoFixedFileSlot();
  machine.neuron.connected = true;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);
  ProdigyContainerRetirementJournal journal = {};
  journal.intents.push_back(containerRetirementAuthorityIntent(0x730011, machine.uuid));
  suite.expect(containerRetirementInstallJournal(brain, journal), "retirement_terminal_pending_intent");
  suite.expect(brain.containerRetirementAuthorityAcknowledged(), "retirement_terminal_single_commissioned_owner");
  NeuronView impostor = {};
  impostor.machine = &machine;
  suite.expect(!brain.noteContainerRetirementTerminal(0x730011, &impostor), "retirement_terminal_rejects_noncurrent_stream");
  brain.holdRuntimePersistence = true;
  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;
  ApplicationDeployment deployment = {};
  seedStatefulDeployRequestPlan(deployment.plan, 73);
  deployment.plan.config.versionID = 19;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  ContainerView *waiting = new ContainerView();
  waiting->uuid = 0x730011;
  waiting->deploymentID = deployment.plan.config.deploymentID();
  waiting->applicationID = 73;
  waiting->machine = &machine;
  waiting->state = ContainerState::destroying;
  waiting->destructionWaiterDeploymentID = waiting->deploymentID;
  deployment.waitingOnContainers.insert_or_assign(waiting, ContainerState::destroyed);
  suite.expect(brain.noteContainerRetirementTerminal(0x730011, &machine.neuron) &&
                   brain.pendingRuntimePersistence.size() == 1 && !brain.masterAuthorityRuntimeStateDurable,
               "retirement_terminal_waits_for_authority_receipt");
  suite.expect(!brain.reconcileContainerRetirements(), "retirement_terminal_held_receipt_cannot_complete");
  suite.expect(deployment.waitingOnContainers.size() == 1, "retirement_terminal_retains_waiter_before_receipt");
  brain.finishRuntimePersistence(false);
  suite.expect(!brain.reconcileContainerRetirements(), "retirement_terminal_failed_receipt_cannot_complete");
  brain.retryMasterAuthorityRuntimeStatePersistence();
  suite.expect(brain.pendingRuntimePersistence.size() == 1, "retirement_terminal_existing_owner_retries_persistence");
  brain.finishRuntimePersistence(true);
  suite.expect(brain.reconcileContainerRetirements() &&
                   brain.statefulTopologyRetirementSettled(journal.intents[0].deploymentID, 211),
               "retirement_terminal_durable_receipt_allows_completion");
  suite.expect(deployment.waitingOnContainers.empty(), "retirement_terminal_completes_waiter_without_global_index");
  if (!deployment.waitingOnContainers.empty()) { deployment.waitingOnContainers.clear(); delete waiting; }
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisNeuron = previousNeuron;
  thisBrain = previousBrain;
}

static void testContainerRetirementPreKill(TestSuite& suite)
{
  ScopedFreshRing ring = {};
  TestNeuron local = {};
  local.uuid = 0x730101;
  NeuronBase *previousNeuron = thisNeuron;
  BrainBase *previousBrain = thisBrain;
  thisNeuron = &local;
  StreamingTestBrain brain = {};
  thisBrain = &brain;
  brain.weAreMaster = true;
  brain.nBrains = 1;
  brain.hasAuthoritativeTopology = true;
  ClusterMachine member = {};
  member.uuid = local.uuid;
  member.isBrain = true;
  brain.authoritativeTopology.machines.push_back(member);
  brain.masterAuthorityRuntimeState.generation = 100;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = 100;
  Machine machine = {};
  machine.uuid = local.uuid;
  ApplicationDeployment deployment = {};
  seedStatefulDeployRequestPlan(deployment.plan, 73);
  deployment.plan.config.versionID = 19;
  deployment.nShardGroups = 1;
  deployment.statefulWorkerTopologyUpgradePending = true;
  deployment.statefulWorkerTopologyUpgradePhase = StatefulWorkerTopologyUpgradePhase::blueDraining;
  deployment.statefulWorkerTopologyUpgradeOperationID = 211;
  deployment.statefulWorkerTopologyUpgradeSourceEpoch = 3;
  deployment.statefulWorkerTopologyUpgradeTargetEpoch = 4;
  deployment.statefulWorkerTopologyUpgradeSourceWorkerCount = 1;
  deployment.statefulWorkerTopologyUpgradeTargetWorkerCount = 2;
  deployment.statefulWorkerTopologyLockedShardGroups.insert(0);
  ContainerView source = {};
  configureStatefulTopologySourceContainer(source, deployment,
      StatefulMeshRoles::forShardGroup(deployment.plan.stateful, 73, 0), 0, uint128_t(0x730111));
  source.machine = &machine;
  source.fragment = 1;
  deployment.containers.insert(&source);
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.containers.insert_or_assign(source.uuid, &source);
  brain.holdRuntimePersistence = true;
  suite.expect(!brain.prepareStatefulTopologyRetirement(&deployment) &&
                   brain.pendingRuntimePersistence.size() == 1 && source.state == ContainerState::healthy &&
                   machine.neuron.wBuffer.empty(),
               "retirement_pre_kill_persists_intent_without_mutating_source");
  brain.finishRuntimePersistence(false);
  suite.expect(!brain.prepareStatefulTopologyRetirement(&deployment) && machine.neuron.wBuffer.empty(),
               "retirement_pre_kill_failed_persistence_blocks_destruction");
  brain.retryMasterAuthorityRuntimeStatePersistence();
  brain.finishRuntimePersistence(true);
  suite.expect(brain.prepareStatefulTopologyRetirement(&deployment),
               "retirement_pre_kill_durable_authority_admits_exact_sources");
  ProdigyContainerRetirementJournal journal = {};
  const bool decoded = brain.decodeContainerRetirementJournal(brain.masterAuthorityRuntimeState, journal);
  suite.expect(decoded && journal.intents.size() == 1 && journal.intents[0].containerUUID == source.uuid &&
                   journal.intents[0].machineUUID == machine.uuid && !journal.intents[0].killAcked,
               "retirement_pre_kill_captures_exact_source_and_machine");
  deployment.statefulWorkerTopologyUpgradePhaseChangedAtMs = 1000;
  suite.expect(brain.statefulTopologyRetirementStarted(deployment.plan.config.deploymentID(), 211) &&
                   !deployment.statefulWorkerTopologyUpgradeRollbackEligibleAt(1001),
               "retirement_pre_kill_intent_permanently_fences_clock_rollback");
  deployment.containers.erase(&source);
  brain.containers.erase(source.uuid);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  thisBrain = previousBrain;
  thisNeuron = previousNeuron;
}
