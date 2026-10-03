#pragma once

// Included after TestBrain/StreamingTestBrain/TestSuite and the serving
// authority helpers in prodigy_brain_replication_credentials_unit.cpp.
static void testStatefulServingResourceAdjustment(TestSuite& suite)
{
  ScopedFreshRing ring = {};
  TestNeuron local = {};
  local.uuid = 0x7a510001;
  NeuronBase *previousNeuron = thisNeuron;
  BrainBase *previousBrain = thisBrain;
  thisNeuron = &local;

  StreamingTestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.brainConfig.datacenterFragment = 1;
  thisBrain = &brain;
  brain.weAreMaster = true;
  brain.nBrains = 1;
  brain.hasAuthoritativeTopology = true;
  ClusterMachine self = {}; self.uuid = local.uuid; self.isBrain = true;
  brain.authoritativeTopology.machines.push_back(self);
  brain.masterAuthorityEpoch = 0x7a51;
  brain.masterAuthorityRuntimeState.generation = 70;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = 70;
  brain.holdRuntimePersistence = true;

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(0x7a51, 1);
  deployment.plan.isStateful = true;
  deployment.plan.config.type = ApplicationType::stateful;
  deployment.plan.config.nLogicalCores = 1;
  deployment.plan.config.memoryMB = 512;
  deployment.plan.config.storageMB = 1024;
  deployment.plan.stateful.allMasters = false;
  deployment.plan.stateful.clientPrefix = MeshServices::generateStatefulService(0x7a51, 1);
  deployment.plan.stateful.siblingPrefix = MeshServices::generateStatefulService(0x7a51, 2);
  deployment.plan.stateful.cousinPrefix = MeshServices::generateStatefulService(0x7a51, 3);
  deployment.plan.stateful.seedingPrefix = MeshServices::generateStatefulService(0x7a51, 4);
  deployment.plan.stateful.shardingPrefix = MeshServices::generateStatefulService(0x7a51, 5);
  deployment.nShardGroups = 1;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  Machine machines[3] = {};
  Rack racks[3] = {};
  ContainerView containers[3] = {};
  const ApplicationConfig base = deployment.plan.config;
  for (uint32_t i = 0; i < 3; ++i)
  {
    Machine& machine = machines[i];
    racks[i].uuid = 0x7a513000 + i;
    machine.rack = &racks[i];
    racks[i].machines.insert(&machine);
    brain.racks.insert_or_assign(racks[i].uuid, &racks[i]);
    machine.uuid = 0x7a511000 + i;
    machine.slug.assign("resource-authority"_ctv);
    machine.private4 = 0x0a7a5100 + i;
    machine.state = MachineState::healthy;
    machine.runtimeReady = true;
    machine.fragment = 100 + i;
    machine.totalLogicalCores = machine.ownedLogicalCores = 8;
    machine.totalMemoryMB = machine.ownedMemoryMB = 16'384;
    machine.totalStorageMB = machine.ownedStorageMB = 65'536;
    machine.nLogicalCores_available = 7;
    machine.memoryMB_available = 16'384 - int32_t(base.totalMemoryMB());
    machine.storageMB_available = 65'536 - int32_t(base.totalStorageMB());
    machine.neuron.machine = &machine;
    machine.neuron.isFixedFile = true;
    machine.neuron.fslot = int(100 + i);
    machine.neuron.connected = true;
    machine.neuron.pendingSend = true;
    machine.neuron.ioGeneration = 1;
    machine.neuron.artifactCapabilityPending = false;
    machine.neuron.artifactChunksEnabled = true;
    machine.neuron.verifiedInstalledBundleSHA256.assign(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv);
    machine.neuron.verifiedInstalledBundleIOGeneration = machine.neuron.ioGeneration;
    machine.neuron.verifiedInstalledBundleAuthorityEpoch = brain.masterAuthorityEpoch;
    brain.machines.insert(&machine);
    brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
    brain.neurons.insert(&machine.neuron);

    MachineConfig config = {};
    config.slug = machine.slug;
    config.nLogicalCores = 8;
    config.nMemoryMB = 16'384;
    config.nStorageMB = 65'536;
    brain.brainConfig.configBySlug.insert_or_assign(config.slug, config);

    ContainerView& container = containers[i];
    container.uuid = 0x7a512000 + i;
    container.deploymentID = deployment.plan.config.deploymentID();
    container.applicationID = deployment.plan.config.applicationID;
    container.machine = &machine;
    container.isStateful = true;
    container.shardGroup = 0;
    container.fragment = i + 1;
    container.state = ContainerState::healthy;
    container.runtimeReady = true;
    container.lifetime = ApplicationLifetime::base;
    container.runtime_nLogicalCores = uint16_t(applicationSharedCPUCoreHint(base));
    container.runtime_memoryMB = base.totalMemoryMB();
    container.runtime_storageMB = base.totalStorageMB();
    container.explicitStatefulMeshRoles = StatefulMeshRoles::forShardGroup(deployment.plan.stateful,
                                                                             deployment.plan.config.applicationID, 0);
    container.explicitStatefulTopology.shardGroup = 0;
    container.explicitStatefulTopology.topologyEpoch = 7;
    container.explicitStatefulTopology.sourceEpoch = 7;
    container.explicitStatefulTopology.targetEpoch = 7;
    container.explicitStatefulTopology.servingMode = StatefulTopologyServingMode::serve;
    if (i == 0) container.advertisements.emplace(container.explicitStatefulMeshRoles.client,
        Advertisement(container.explicitStatefulMeshRoles.client, ContainerState::healthy,
                      ContainerState::destroying, uint16_t(31000 + i)));
    brain.containers.insert_or_assign(container.uuid, &container);
    machine.upsertContainerIndexEntry(container.deploymentID, &container);
    deployment.containers.insert(&container);
    deployment.containersByShardGroup.insert(0, &container);
  }

  ProdigyStatefulServingAuthority authority = {};
  authority.deploymentID = deployment.plan.config.deploymentID();
  authority.applicationID = deployment.plan.config.applicationID;
  authority.operationID = 0x7a51;
  authority.revision = brain.masterAuthorityRuntimeState.generation;
  authority.phase = StatefulWorkerTopologyUpgradePhase::none;
  authority.sourceEpoch = 7;
  authority.targetEpoch = 7;
  authority.targetConfig = base;
  for (uint32_t i = 0; i < 3; ++i)
  {
    BrainReplicatedContainerRuntimeState state = {};
    suite.require(brain.captureReplicatedContainerRuntimeState(&containers[i], state),
                  "serving_resource_fixture_captures_exact_steady_member");
    state.machineUUID = machines[i].uuid;
    state.runtimeLogicalCores = containers[i].runtime_nLogicalCores;
    state.runtimeMemoryMB = containers[i].runtime_memoryMB;
    state.runtimeStorageMB = containers[i].runtime_storageMB;
    ProdigyStatefulServingAuthorityMember member = {};
    member.containerUUID = containers[i].uuid;
    member.machineUUID = machines[i].uuid;
    member.shardGroup = 0;
    member.advertiseClient = i == 0;
    suite.require(prodigyStatefulServingRuntimeDigest(state, member.planSHA256),
                  "serving_resource_fixture_hashes_exact_steady_member");
    authority.members.push_back(std::move(member));
    brain.statefulServingRuntimeStates.push_back(std::move(state));
  }
  suite.require(prodigyValidateStatefulServingAuthority(authority, brain.statefulServingRuntimeStates,
                                                         authority.revision),
                "serving_resource_fixture_validates_three_member_steady_authority");
  brain.masterAuthorityRuntimeState.statefulServingAuthorities.push_back(authority);
  suite.require(brain.containerRetirementAuthorityAcknowledged(),
                "serving_resource_fixture_has_commissioned_authority_ack");

  using Admission = BrainBase::StatefulServingResourceAdjustmentAdmission;
  ApplicationConfig desired = base;
  desired.memoryMB += 256;
  desired.storageMB += 512;
  // The extended request is allowed only on the same authenticated control
  // stream that supplied the installed-bundle capability witness.
  const String artifactWitness =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv;
  machines[0].neuron.verifiedInstalledBundleSHA256.clear();
  suite.expect(brain.prepareStatefulServingResourceAdjustment(&deployment, desired) == Admission::pending &&
                   brain.pendingRuntimePersistence.empty() && machines[0].neuron.wBuffer.empty() &&
                   machines[1].neuron.wBuffer.empty() && machines[2].neuron.wBuffer.empty(),
               "serving_resource_missing_bundle_witness_blocks_dispatch");
  machines[0].neuron.verifiedInstalledBundleSHA256.assign(artifactWitness);
  machines[0].neuron.verifiedInstalledBundleIOGeneration = machines[0].neuron.ioGeneration + 1;
  suite.expect(brain.prepareStatefulServingResourceAdjustment(&deployment, desired) == Admission::pending &&
                   brain.pendingRuntimePersistence.empty() && machines[0].neuron.wBuffer.empty() &&
                   machines[1].neuron.wBuffer.empty() && machines[2].neuron.wBuffer.empty(),
               "serving_resource_stale_bundle_io_witness_blocks_dispatch");
  machines[0].neuron.verifiedInstalledBundleIOGeneration = machines[0].neuron.ioGeneration;
  machines[0].neuron.verifiedInstalledBundleAuthorityEpoch = brain.masterAuthorityEpoch + 1;
  suite.expect(brain.prepareStatefulServingResourceAdjustment(&deployment, desired) == Admission::pending &&
                   brain.pendingRuntimePersistence.empty() && machines[0].neuron.wBuffer.empty() &&
                   machines[1].neuron.wBuffer.empty() && machines[2].neuron.wBuffer.empty(),
               "serving_resource_wrong_bundle_authority_witness_blocks_dispatch");
  machines[0].neuron.verifiedInstalledBundleAuthorityEpoch = brain.masterAuthorityEpoch;
  const uint32_t desiredTotalMemory = desired.totalMemoryMB();
  const uint32_t desiredTotalStorage = desired.totalStorageMB();
  const int32_t availableBefore[3] = {machines[0].memoryMB_available, machines[1].memoryMB_available,
                                      machines[2].memoryMB_available};
  suite.expect(brain.prepareStatefulServingResourceAdjustment(&deployment, desired) == Admission::pending &&
                   brain.pendingRuntimePersistence.size() == 1,
               "serving_resource_holds_exact_authority_target_before_persistence");
  bool stagedExact = brain.masterAuthorityRuntimeState.statefulServingAuthorities[0].targetConfig.memoryMB == desired.memoryMB &&
                     brain.masterAuthorityRuntimeState.statefulServingAuthorities[0].targetConfig.storageMB == desired.storageMB;
  for (uint32_t i = 0; i < 3; ++i)
  {
    String digest = {};
    stagedExact &= prodigyStatefulServingApplicationConfigEqual(brain.statefulServingRuntimeStates[i].plan.config, desired) &&
                   prodigyStatefulServingRuntimeDigest(brain.statefulServingRuntimeStates[i], digest) &&
                   digest.equals(brain.masterAuthorityRuntimeState.statefulServingAuthorities[0].members[i].planSHA256) &&
                   deployment.plan.config.memoryMB == base.memoryMB &&
                   containers[i].runtime_memoryMB == base.totalMemoryMB() &&
                   machines[i].neuron.wBuffer.empty() &&
                   machines[i].memoryMB_available < availableBefore[i];
  }
  suite.expect(stagedExact,
               "serving_resource_preack_seals_all_member_digests_reserves_capacity_without_runtime_mutation");

  brain.finishRuntimePersistence(false);
  suite.expect(deployment.plan.config.memoryMB == base.memoryMB &&
                   containers[0].runtime_memoryMB == base.totalMemoryMB() &&
                   machines[0].neuron.wBuffer.empty(),
               "serving_resource_failed_receipt_has_no_runtime_or_neuron_side_effect");
  brain.retryMasterAuthorityRuntimeStatePersistence();
  suite.expect(brain.pendingRuntimePersistence.size() == 1 && machines[0].neuron.wBuffer.empty(),
               "serving_resource_failed_receipt_retries_retained_exact_target");
  brain.finishRuntimePersistence(true);
  machines[0].neuron.verifiedInstalledBundleIOGeneration = machines[0].neuron.ioGeneration + 1;
  (void)brain.restoreStatefulServingDecision(&deployment);
  uint32_t supportedWitnessFrames = 0;
  for (uint32_t i = 1; i < 3; ++i)
    forEachMessageInBuffer(machines[i].neuron.wBuffer, [&](Message *message) {
      supportedWitnessFrames += NeuronTopic(message->topic) == NeuronTopic::adjustContainerResources;
    });
  suite.expect(machines[0].neuron.wBuffer.empty() && supportedWitnessFrames == 2 &&
                   containers[0].runtime_memoryMB == base.totalMemoryMB(),
               "serving_resource_stale_bundle_witness_skips_only_unsupported_machine");
  for (auto& machine : machines) machine.neuron.wBuffer.clear();
  machines[0].neuron.verifiedInstalledBundleIOGeneration = machines[0].neuron.ioGeneration;
  suite.expect(brain.restoreStatefulServingDecision(&deployment),
               "serving_resource_durable_receipt_restores_steady_target");

  auto countFrames = [&](NeuronTopic topic) -> uint32_t {
    uint32_t count = 0;
    for (auto& machine : machines)
      forEachMessageInBuffer(machine.neuron.wBuffer, [&](Message *message) {
        count += NeuronTopic(message->topic) == topic;
      });
    return count;
  };
  auto clearNeuronBuffers = [&]() -> void {
    for (auto& machine : machines) machine.neuron.wBuffer.clear();
  };
  // This is Neuron's authenticated resource receipt, not an inventory
  // substitute.  Its resource fields are the base config values on the wire.
  auto sendResourceReply = [&](uint32_t machineIndex, uint128_t uuid, uint16_t cores,
                               uint32_t memoryMB, uint32_t storageMB, bool success,
                               uint8_t observationVersion = 1) -> void {
    String reply = {};
    const uint32_t header = Message::appendHeader(reply, NeuronTopic::adjustContainerResources);
    Message::append(reply, observationVersion);
    Message::append(reply, uuid);
    Message::append(reply, cores);
    Message::append(reply, memoryMB);
    Message::append(reply, storageMB);
    Message::append(reply, success);
    Message::finish(reply, header);
    Message *message = reinterpret_cast<Message *>(reply.data());
    suite.expect(ProdigyIngressValidation::validateNeuronPayloadForBrain(
                     message->topic, message->args, message->terminal()) == (observationVersion == 1),
                 observationVersion == 1 ? "serving_resource_reply_validator_accepts_v1"
                                         : "serving_resource_reply_validator_rejects_unknown_version");
    brain.neuronHandler(&machines[machineIndex].neuron, message);
  };
  auto sendMalformedResourceReply = [&](uint32_t machineIndex, uint128_t uuid) -> void {
    String reply = {};
    const uint32_t header = Message::appendHeader(reply, NeuronTopic::adjustContainerResources);
    Message::append(reply, uint8_t(1));
    Message::append(reply, uuid);
    Message::append(reply, uint16_t(applicationSharedCPUCoreHint(desired)));
    Message::append(reply, desired.memoryMB);
    Message::append(reply, desired.storageMB);
    // Deliberately omit the required success byte.
    Message::finish(reply, header);
    Message *message = reinterpret_cast<Message *>(reply.data());
    suite.expect(ProdigyIngressValidation::validateNeuronPayloadForBrain(
                     message->topic, message->args, message->terminal()) == false,
                 "serving_resource_reply_validator_rejects_missing_success");
    brain.neuronHandler(&machines[machineIndex].neuron, message);
  };
  auto commandsCarry = [&](const ApplicationConfig& expected) -> bool {
    bool correct = true;
    for (uint32_t i = 0; i < 3; ++i)
      forEachMessageInBuffer(machines[i].neuron.wBuffer, [&](Message *message) {
        if (NeuronTopic(message->topic) != NeuronTopic::adjustContainerResources) return;
        uint8_t *args = message->args;
        correct &= ProdigyIngressValidation::validateNeuronPayloadForNeuron(
            message->topic, args, message->terminal());
        uint128_t uuid = 0; uint16_t cores = 0; uint32_t memory = 0, storage = 0;
        Message::extractArg<ArgumentNature::fixed>(args, uuid);
        Message::extractArg<ArgumentNature::fixed>(args, cores);
        Message::extractArg<ArgumentNature::fixed>(args, memory);
        Message::extractArg<ArgumentNature::fixed>(args, storage);
        bool downscale = false;
        uint32_t graceSeconds = 0;
        uint8_t requestObservation = 0;
        Message::extractArg<ArgumentNature::fixed>(args, downscale);
        Message::extractArg<ArgumentNature::fixed>(args, graceSeconds);
        Message::extractArg<ArgumentNature::fixed>(args, requestObservation);
        correct &= uuid == containers[i].uuid &&
                   cores == uint16_t(applicationSharedCPUCoreHint(expected)) &&
                   memory == expected.memoryMB && storage == expected.storageMB &&
                   requestObservation == 1;
      });
    return correct;
  };

  bool initialDispatch = deployment.plan.config.memoryMB == desired.memoryMB &&
                         deployment.plan.config.storageMB == desired.storageMB &&
                         countFrames(NeuronTopic::adjustContainerResources) == 3 &&
                         countFrames(NeuronTopic::stateUpload) == 0 &&
                         countFrames(NeuronTopic::resetSwitchboardState) == 0 &&
                         commandsCarry(desired);
  for (uint32_t i = 0; i < 3; ++i)
  {
    // Dispatch is a request only: real allocation remains the old observation.
    initialDispatch &= containers[i].runtime_memoryMB == base.totalMemoryMB() &&
                       containers[i].runtime_storageMB == base.totalStorageMB() &&
                       machines[i].runtimeReady;
  }
  suite.expect(initialDispatch,
               "serving_resource_ack_dispatches_base_delta_without_inventory_or_runtime_rewrite");

  const int32_t availableAfterDesiredReservation = machines[0].memoryMB_available;
  const int32_t storageAfterDesiredReservation = machines[0].storageMB_available;
  clearNeuronBuffers();
  suite.expect(brain.restoreStatefulServingDecision(&deployment),
               "serving_resource_restore_retries_while_resource_reply_is_lost");
  suite.expect(countFrames(NeuronTopic::adjustContainerResources) == 3 &&
                   countFrames(NeuronTopic::stateUpload) == 0 &&
                   countFrames(NeuronTopic::resetSwitchboardState) == 0 &&
                   commandsCarry(desired) &&
                   containers[0].runtime_memoryMB == base.totalMemoryMB() &&
                   machines[0].memoryMB_available == availableAfterDesiredReservation,
               "serving_resource_lost_reply_retries_idempotent_delta_without_capacity_change");

  // Receipt identity, owning connection, and exact wire shape are all checked
  // before an observation is accepted.
  clearNeuronBuffers();
  sendResourceReply(1, containers[0].uuid, uint16_t(applicationSharedCPUCoreHint(desired)),
                    desired.memoryMB, desired.storageMB, true);
  sendResourceReply(0, containers[0].uuid + 0x100, uint16_t(applicationSharedCPUCoreHint(desired)),
                    desired.memoryMB, desired.storageMB, true);
  sendMalformedResourceReply(0, containers[0].uuid);
  sendResourceReply(0, containers[0].uuid, uint16_t(applicationSharedCPUCoreHint(desired)),
                    desired.memoryMB, desired.storageMB, true, 2);
  machines[0].neuron.verifiedInstalledBundleIOGeneration = machines[0].neuron.ioGeneration + 1;
  sendResourceReply(0, containers[0].uuid, uint16_t(applicationSharedCPUCoreHint(desired)),
                    desired.memoryMB, desired.storageMB, true);
  machines[0].neuron.verifiedInstalledBundleIOGeneration = machines[0].neuron.ioGeneration;
  suite.expect(containers[0].runtime_memoryMB == base.totalMemoryMB() &&
                   machines[0].memoryMB_available == availableAfterDesiredReservation &&
                   countFrames(NeuronTopic::adjustContainerResources) == 0,
               "serving_resource_rejects_wrong_machine_uuid_and_unsupported_reply_version");

  // Failure reports the actual old allocation.  It remains observed, keeps the
  // reservation, and the normal restore path reissues the sealed desired delta.
  for (uint32_t i = 0; i < 3; ++i)
    sendResourceReply(i, containers[i].uuid, uint16_t(applicationSharedCPUCoreHint(base)),
                      base.memoryMB, base.storageMB, false);
  suite.expect(containers[0].runtime_memoryMB == base.totalMemoryMB() &&
                   machines[0].memoryMB_available == availableAfterDesiredReservation,
               "serving_resource_failed_reply_preserves_old_observation_and_capacity");
  clearNeuronBuffers();
  (void)brain.restoreStatefulServingDecision(&deployment);
  suite.expect(countFrames(NeuronTopic::adjustContainerResources) == 3 &&
                   commandsCarry(desired) &&
                   machines[0].memoryMB_available == availableAfterDesiredReservation,
               "serving_resource_failed_reply_retries_without_double_charge");

  // Only a matching successful receipt advances observed usage.
  clearNeuronBuffers();
  for (uint32_t i = 0; i < 3; ++i)
    sendResourceReply(i, containers[i].uuid, uint16_t(applicationSharedCPUCoreHint(desired)),
                      desired.memoryMB, desired.storageMB, true);
  (void)brain.restoreStatefulServingDecision(&deployment);
  bool desiredObserved = countFrames(NeuronTopic::adjustContainerResources) == 0;
  for (uint32_t i = 0; i < 3; ++i)
  {
    desiredObserved &= containers[i].runtime_memoryMB == desiredTotalMemory &&
                       containers[i].runtime_storageMB == desiredTotalStorage &&
                       machines[i].memoryMB_available == availableAfterDesiredReservation &&
                       machines[i].storageMB_available == storageAfterDesiredReservation;
  }
  suite.expect(desiredObserved,
               "serving_resource_successful_upscale_reply_updates_observed_runtime_once");

  // A failed observation may legitimately report no writable /storage volume.
  // It still records the filesystem allocation and retains the larger sealed
  // target reservation until an ordinary observation restores the prior fact.
  sendResourceReply(0, containers[0].uuid, uint16_t(applicationSharedCPUCoreHint(desired)),
                    desired.memoryMB, 0, false);
  suite.expect(containers[0].runtime_storageMB == desired.filesystemMB &&
                   machines[0].storageMB_available == storageAfterDesiredReservation,
               "serving_resource_zero_storage_failure_observes_filesystem_and_preserves_target_reservation");
  sendResourceReply(0, containers[0].uuid, uint16_t(applicationSharedCPUCoreHint(desired)),
                    desired.memoryMB, desired.storageMB, false);
  suite.expect(containers[0].runtime_storageMB == desiredTotalStorage &&
                   machines[0].storageMB_available == storageAfterDesiredReservation,
               "serving_resource_restores_positive_observation_after_zero_storage_failure");

  // A downscale reserves the old observed size through held and failed
  // persistence. It only releases after a matching successful reply.
  ApplicationConfig smaller = desired;
  smaller.memoryMB = base.memoryMB;
  smaller.storageMB = base.storageMB;
  brain.holdRuntimePersistence = true;
  suite.expect(brain.prepareStatefulServingResourceAdjustment(&deployment, smaller) == Admission::pending &&
                   brain.pendingRuntimePersistence.size() == 1 &&
                   machines[0].memoryMB_available == availableAfterDesiredReservation &&
                   machines[0].storageMB_available == storageAfterDesiredReservation,
               "serving_resource_downscale_stages_without_releasing_observed_capacity");
  brain.finishRuntimePersistence(false);
  suite.expect(containers[0].runtime_memoryMB == desiredTotalMemory &&
                   machines[0].memoryMB_available == availableAfterDesiredReservation &&
                   machines[0].neuron.wBuffer.empty(),
               "serving_resource_downscale_failed_persistence_keeps_old_observation_and_capacity");
  brain.retryMasterAuthorityRuntimeStatePersistence();
  suite.expect(brain.pendingRuntimePersistence.size() == 1,
               "serving_resource_downscale_failed_persistence_retains_retry");
  brain.finishRuntimePersistence(true);
  clearNeuronBuffers();
  suite.expect(brain.restoreStatefulServingDecision(&deployment),
               "serving_resource_downscale_durable_receipt_restores_target");
  bool downscaleDispatch = countFrames(NeuronTopic::adjustContainerResources) == 3 &&
                           countFrames(NeuronTopic::stateUpload) == 0 &&
                           countFrames(NeuronTopic::resetSwitchboardState) == 0 &&
                           commandsCarry(smaller);
  for (uint32_t i = 0; i < 3; ++i)
    downscaleDispatch &= containers[i].runtime_memoryMB == desiredTotalMemory;
  suite.expect(downscaleDispatch,
               "serving_resource_downscale_dispatch_preserves_observed_runtime_until_reply");

  // A failed downscale receipt still reports the larger allocation. It does
  // not release capacity and causes the retained target to be retried.
  for (uint32_t i = 0; i < 3; ++i)
    sendResourceReply(i, containers[i].uuid, uint16_t(applicationSharedCPUCoreHint(desired)),
                      desired.memoryMB, desired.storageMB, false);
  clearNeuronBuffers();
  (void)brain.restoreStatefulServingDecision(&deployment);
  suite.expect(countFrames(NeuronTopic::adjustContainerResources) == 3 &&
                   commandsCarry(smaller) &&
                   containers[0].runtime_memoryMB == desiredTotalMemory &&
                   machines[0].memoryMB_available == availableAfterDesiredReservation,
               "serving_resource_downscale_failed_reply_retries_without_early_release");

  clearNeuronBuffers();
  for (uint32_t i = 0; i < 3; ++i)
    sendResourceReply(i, containers[i].uuid, uint16_t(applicationSharedCPUCoreHint(smaller)),
                      smaller.memoryMB, smaller.storageMB, true);
  (void)brain.restoreStatefulServingDecision(&deployment);
  const int32_t availableAfterSmallerObservation = machines[0].memoryMB_available;
  const int32_t storageAfterSmallerObservation = machines[0].storageMB_available;
  bool smallerObserved = countFrames(NeuronTopic::adjustContainerResources) == 0;
  for (uint32_t i = 0; i < 3; ++i)
  {
    smallerObserved &= containers[i].runtime_memoryMB == base.totalMemoryMB() &&
                       containers[i].runtime_storageMB == base.totalStorageMB() &&
                       machines[i].memoryMB_available == availableBefore[i] &&
                       machines[i].storageMB_available == 65'536 - int32_t(base.totalStorageMB());
  }
  suite.expect(smallerObserved,
               "serving_resource_successful_smaller_reply_releases_capacity_exactly_once");

  clearNeuronBuffers();
  (void)brain.restoreStatefulServingDecision(&deployment);
  suite.expect(countFrames(NeuronTopic::adjustContainerResources) == 0 &&
                   machines[0].memoryMB_available == availableAfterSmallerObservation &&
                   machines[0].storageMB_available == storageAfterSmallerObservation,
               "serving_resource_smaller_reply_makes_restore_and_release_idempotent");

  // Replicated stale runtime keeps its existing projection rule: it may report
  // an old allocation, but cannot replace the sealed smaller desired config or
  // debit capacity a second time.
  BrainReplicatedContainerRuntimeState stale = brain.statefulServingRuntimeStates[0];
  stale.plan.config = desired;
  stale.runtimeLogicalCores = uint16_t(applicationSharedCPUCoreHint(desired));
  stale.runtimeMemoryMB = desiredTotalMemory;
  stale.runtimeStorageMB = desiredTotalStorage;
  brain.recoveringPersistedNeuronInventory = true;
  brain.applyReplicatedContainerRuntimeState(stale);
  brain.recoveringPersistedNeuronInventory = false;
  suite.expect(deployment.plan.config.memoryMB == smaller.memoryMB &&
                   machines[0].memoryMB_available == availableAfterSmallerObservation &&
                   machines[0].storageMB_available == storageAfterSmallerObservation,
               "serving_resource_cold_stale_runtime_cannot_revert_authority_or_double_charge");

  // The normal inventory path remains authoritative for an observed allocation.
  // Its stale large config is projected back to the smaller durable target,
  // while the physical large allocation retains the conservative reservation.
  ContainerPlan staleInventory = brain.statefulServingRuntimeStates[0].plan;
  staleInventory.config = desired;
  staleInventory.runtimeReady = true;
  String serializedStaleInventory = {};
  BitseryEngine::serialize(serializedStaleInventory, staleInventory);
  String staleInventoryUpload = {};
  const uint32_t staleInventoryHeader =
      Message::appendHeader(staleInventoryUpload, NeuronTopic::stateUpload);
  local_container_subnet6 staleInventoryNetwork = {};
  staleInventoryNetwork.dpfx = brain.brainConfig.datacenterFragment;
  staleInventoryNetwork.mpfx[2] = uint8_t(machines[0].fragment);
  Message::appendAlignedBuffer<Alignment::one>(
      staleInventoryUpload, reinterpret_cast<const uint8_t *>(&staleInventoryNetwork),
      sizeof(staleInventoryNetwork));
  Message::appendValue(staleInventoryUpload, serializedStaleInventory);
  Message::finish(staleInventoryUpload, staleInventoryHeader);
  brain.neuronHandler(&machines[0].neuron,
                      reinterpret_cast<Message *>(staleInventoryUpload.data()));
  suite.expect(deployment.plan.config.memoryMB == smaller.memoryMB &&
                   containers[0].runtime_memoryMB == desiredTotalMemory &&
                   containers[0].runtime_storageMB == desiredTotalStorage &&
                   machines[0].memoryMB_available == availableAfterDesiredReservation &&
                   machines[0].storageMB_available == storageAfterDesiredReservation,
               "serving_resource_stale_inventory_preserves_observed_large_allocation_under_smaller_authority");
  ApplicationConfig topologyChange = desired;
  uint32_t probeCores = desired.nLogicalCores;
  while (prodigyStatefulWorkerCountForLogicalCores(probeCores) ==
         prodigyStatefulWorkerCountForLogicalCores(desired.nLogicalCores)) ++probeCores;
  topologyChange.nLogicalCores = probeCores;
  ApplicationConfig nonResource = desired;
  nonResource.sTilKillable += 1;
  const uint64_t generation = brain.masterAuthorityRuntimeState.generation;
  suite.expect(brain.prepareStatefulServingResourceAdjustment(&deployment, topologyChange) == Admission::rejected &&
                   brain.prepareStatefulServingResourceAdjustment(&deployment, nonResource) == Admission::rejected &&
                   brain.masterAuthorityRuntimeState.generation == generation,
               "serving_resource_rejects_topology_and_nonresource_mutations_without_authority_change");

  for (uint32_t i = 0; i < 3; ++i)
  {
    deployment.containers.erase(&containers[i]);
    while (deployment.containersByShardGroup.eraseEntry(0, &containers[i])) {}
    machines[i].removeContainerIndexEntry(containers[i].deploymentID, &containers[i]);
    brain.containers.erase(containers[i].uuid);
    brain.neurons.erase(&machines[i].neuron);
    brain.machinesByUUID.erase(machines[i].uuid);
    brain.machines.erase(&machines[i]);
    brain.racks.erase(racks[i].uuid);
    racks[i].machines.erase(&machines[i]);
  }
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  thisBrain = previousBrain;
  thisNeuron = previousNeuron;
}
