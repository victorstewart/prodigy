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
