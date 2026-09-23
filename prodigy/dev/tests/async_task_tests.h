// Included by prodigy_brain_replication_credentials_unit.cpp after its shared
// TestBrain and TestSuite fixtures.

class AsyncTaskArtifactBrain final : public TestBrain {
public:
  String artifactRoot = {};

  const String *containerArtifactStoreRoot() const override
  {
    return artifactRoot.empty() ? nullptr : &artifactRoot;
  }
};

static bool beginAsyncTaskAdmission(
    TestSuite& suite, AsyncTaskArtifactBrain& brain, Mothership& mothership,
    ScopedAsyncMothershipRing& ring, uint16_t applicationID, uint64_t& executionID)
{
  String reserveFailure = {};
  if (!brain.reserveApplicationIDMapping("AsyncTaskAdmission"_ctv, applicationID, &reserveFailure))
  {
    suite.expect(false, "task_admission_reserves_application_identity");
    return false;
  }
  DeploymentPlan plan = {};
  seedDeployRequestPlan(plan, applicationID);
  plan.config.type = ApplicationType::task;
  plan.config.taskExecutionPolicy = TaskExecutionPolicy::runOnce;
  plan.stateless.nBase = 1;
  plan.canaryCount = 0;
  String taskPlanFailure = {};
  if (!Brain::validateTaskDeploymentPlan(plan, taskPlanFailure))
  {
    suite.expect(false, "task_admission_fixture_plan_is_valid");
    return false;
  }
  String containerBlob = prodigyDiscombobulatorBlobHeaderText();
  containerBlob.append("async-task-artifact"_ctv);
  String serialized = {};
  BitseryEngine::serialize(serialized, plan);
  String frame = {};
  brain.mothershipHandler(&mothership,
      buildMothershipMessage(frame, MothershipTopic::spinApplication, applicationID, serialized,
                             containerBlob));
  ring.runFor(500);
  executionID = plan.config.deploymentID();
  return brain.pendingRuntimePersistence.size() == 1 &&
         brain.masterAuthorityRuntimeState.taskExecutions.contains(executionID) &&
         brain.pendingMothershipSpinArtifacts.contains(executionID) && mothership.wBuffer.empty();
}

static void testAsyncTaskAdmissionDurability(TestSuite& suite)
{
  auto setup = [&](AsyncTaskArtifactBrain& brain, Mothership& mothership,
                   ScopedAsyncMothershipRing& ring, ScopedTempDir& store,
                   ScopedSocketPair& sockets, uint16_t applicationID, uint64_t& executionID) -> bool {
    (void)ring;
    if (!suite.require(store.valid(), "task_admission_private_artifact_store_created")) return false;
    brain.artifactRoot.assign(store.path.c_str());
    brain.weAreMaster = true;
    brain.noMasterYet = false;
    // Exercise admission independently of scheduling: absent follower receipts
    // keep the newly admitted task at the authoritative replication gate.
    brain.nBrains = 3;
    brain.ignited = true;
    brain.persistedMachineInventoryEnumerated = true;
    brain.holdRuntimePersistence = true;
    if (!sockets.create(suite, "task_admission_socket_pair")) return false;
    mothership.isFixedFile = false;
    mothership.fd = sockets.takeLeft();
    if (mothership.fd < 0 || !brain.activateMothershipConnection(&mothership)) return false;
    RingDispatcher::installMultiplexee(&mothership, &brain);
    return beginAsyncTaskAdmission(suite, brain, mothership, ring, applicationID, executionID);
  };

  {
    ScopedAsyncMothershipRing ring = {};
    ScopedTempDir store = {};
    ScopedSocketPair sockets = {};
    AsyncTaskArtifactBrain brain = {};
    Mothership mothership = {};
    uint64_t executionID = 0;
    if (suite.require(setup(brain, mothership, ring, store, sockets, 60'120, executionID),
                      "task_admission_failure_fixture_ready"))
    {
      suite.expect(mothership.wBuffer.empty() && !brain.deployments.contains(executionID),
                   "task_admission_holds_okay_and_provisioning_before_durable_receipt");
      brain.finishRuntimePersistence(false);
      suite.expect(!brain.masterAuthorityRuntimeState.taskExecutions.contains(executionID) &&
                       !brain.deployments.contains(executionID),
                   "task_admission_write_failure_rolls_back_candidate_without_provisioning");
    }
    if (brain.artifactIO) { (void)quiesceArtifactIOForTest(brain.artifactIO.get()); brain.artifactIO.reset(); }
    RingDispatcher::eraseMultiplexee(&mothership);
    brain.activeMotherships.erase(&mothership);
    if (mothership.fd >= 0) { ::close(mothership.fd); mothership.fd = -1; }
  }

  {
    ScopedAsyncMothershipRing ring = {};
    ScopedTempDir store = {};
    ScopedSocketPair sockets = {};
    AsyncTaskArtifactBrain brain = {};
    Mothership mothership = {};
    uint64_t executionID = 0;
    if (suite.require(setup(brain, mothership, ring, store, sockets, 60'121, executionID),
                      "task_admission_success_fixture_ready"))
    {
      brain.finishRuntimePersistence(true);
      suite.expect(brain.masterAuthorityRuntimeState.taskExecutions.contains(executionID) &&
                       brain.masterAuthorityRuntimeState.taskExecutions.at(executionID).state == TaskExecutionState::accepted,
                   "task_admission_receipt_preserves_accepted_execution");
      suite.expect(brain.deployments.contains(executionID),
                   "task_admission_durable_receipt_admits_deployment");
      uint32_t acknowledgments = 0;
      forEachMessageInBuffer(mothership.wBuffer, [&](Message *message) {
        if (MothershipTopic(message->topic) == MothershipTopic::spinApplication &&
            message->args[0] == uint8_t(SpinApplicationResponseCode::okay)) ++acknowledgments;
      });
      suite.expect(acknowledgments == 1, "task_admission_durable_receipt_releases_okay_once");
    }
    if (brain.artifactIO) { (void)quiesceArtifactIOForTest(brain.artifactIO.get()); brain.artifactIO.reset(); }
    RingDispatcher::eraseMultiplexee(&mothership);
    brain.activeMotherships.erase(&mothership);
    if (mothership.fd >= 0) { ::close(mothership.fd); mothership.fd = -1; }
  }

  {
    ScopedAsyncMothershipRing ring = {};
    ScopedTempDir store = {};
    ScopedSocketPair sockets = {};
    AsyncTaskArtifactBrain brain = {};
    Mothership mothership = {};
    uint64_t executionID = 0;
    if (suite.require(setup(brain, mothership, ring, store, sockets, 60'122, executionID),
                      "task_admission_stale_fixture_ready"))
    {
      ++brain.masterAuthorityEpoch;
      brain.finishRuntimePersistence(false);
      suite.expect(brain.masterAuthorityRuntimeState.taskExecutions.contains(executionID) &&
                       !brain.deployments.contains(executionID) && mothership.wBuffer.empty(),
                   "task_admission_stale_receipt_suppresses_provisioning_and_response");
    }
    if (brain.artifactIO) { (void)quiesceArtifactIOForTest(brain.artifactIO.get()); brain.artifactIO.reset(); }
    RingDispatcher::eraseMultiplexee(&mothership);
    brain.activeMotherships.erase(&mothership);
    if (mothership.fd >= 0) { ::close(mothership.fd); mothership.fd = -1; }
  }
}

static void testAsyncTaskTerminalDurability(TestSuite& suite)
{
  auto startTerminal = [](TestBrain& brain, uint16_t applicationID, uint32_t versionID) {
    ApplicationDeployment deployment = {};
    deployment.plan.config.applicationID = applicationID;
    deployment.plan.config.versionID = versionID;
    deployment.plan.config.type = ApplicationType::task;
    const uint64_t executionID = deployment.plan.config.deploymentID();
    TaskExecutionRecord record = {};
    record.executionID = executionID;
    record.applicationID = applicationID;
    record.versionID = versionID;
    record.policy = TaskExecutionPolicy::runOnce;
    record.state = TaskExecutionState::running;
    record.currentAttemptNumber = 1;
    brain.masterAuthorityRuntimeState.taskExecutions.insert_or_assign(executionID, record);
    ContainerView container = {};
    container.uuid = uint128_t(executionID) + 1;
    container.taskAttemptNumber = 1;
    TaskTermination termination = {};
    termination.kind = TaskTerminationKind::exited;
    termination.exitCode = 0;
    brain.noteTaskAttemptTerminal(&deployment, &container, termination);
    return executionID;
  };

  {
    TestBrain brain;
    brain.weAreMaster = true;
    brain.holdRuntimePersistence = true;
    const uint64_t executionID = startTerminal(brain, 60'101, 1);
    suite.expect(brain.pendingRuntimePersistence.size() == 1 &&
                     brain.masterAuthorityRuntimeState.taskExecutions.at(executionID).state == TaskExecutionState::succeeded,
                 "task_terminal_holds_ack_and_follow_up_until_durable_receipt");
    brain.finishRuntimePersistence(false);
    suite.expect(brain.masterAuthorityRuntimeState.taskExecutions.at(executionID).state == TaskExecutionState::running &&
                     !brain.masterAuthorityRuntimeStateDurable,
                 "task_terminal_write_failure_restores_running_attempt_without_ack");
  }

  {
    TestBrain brain;
    brain.weAreMaster = true;
    brain.holdRuntimePersistence = true;
    const uint64_t executionID = startTerminal(brain, 60'102, 1);
    brain.finishRuntimePersistence(true);
    suite.expect(brain.masterAuthorityRuntimeStateDurable &&
                     brain.masterAuthorityRuntimeState.taskExecutions.at(executionID).state == TaskExecutionState::succeeded,
                 "task_terminal_durable_receipt_commits_terminal_attempt_before_follow_up");
  }

  {
    TestBrain brain;
    brain.weAreMaster = true;
    brain.holdRuntimePersistence = true;
    const uint64_t executionID = startTerminal(brain, 60'103, 1);
    ++brain.masterAuthorityEpoch;
    brain.finishRuntimePersistence(false);
    suite.expect(brain.masterAuthorityRuntimeState.taskExecutions.at(executionID).state == TaskExecutionState::succeeded &&
                     brain.masterAuthorityRuntimeState.taskExecutions.at(executionID).currentAttemptNumber == 1,
                 "task_terminal_stale_epoch_failure_does_not_rollback_newer_authority_state");
  }

  {
    TestBrain brain;
    brain.weAreMaster = true;
    brain.holdRuntimePersistence = true;
    ApplicationDeployment deployment = {};
    deployment.plan.config.applicationID = 60'104;
    deployment.plan.config.versionID = 1;
    deployment.plan.config.type = ApplicationType::task;
    const uint64_t executionID = deployment.plan.config.deploymentID();
    TaskExecutionRecord record = {};
    record.executionID = executionID;
    record.applicationID = deployment.plan.config.applicationID;
    record.versionID = deployment.plan.config.versionID;
    record.policy = TaskExecutionPolicy::runOnce;
    record.state = TaskExecutionState::running;
    record.currentAttemptNumber = 1;
    brain.masterAuthorityRuntimeState.taskExecutions.insert_or_assign(executionID, record);
    Machine machine = {};
    machine.uuid = 0x60104;
    machine.neuron.ioGeneration = 41;
    brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
    ContainerView container = {};
    container.uuid = 0x60105;
    container.machine = &machine;
    container.taskAttemptNumber = 1;
    brain.deployments.insert_or_assign(executionID, &deployment);
    brain.containers.insert_or_assign(container.uuid, &container);
    TaskTermination termination = {};
    termination.kind = TaskTerminationKind::exited;
    brain.noteTaskAttemptTerminal(&deployment, &container, termination);
    machine.neuron.ioGeneration += 1;
    brain.finishRuntimePersistence(true);
    suite.expect(machine.neuron.wBuffer.empty() && brain.deployments.contains(executionID),
                 "task_terminal_reused_neuron_stream_suppresses_stale_ack_and_follow_up");
    brain.containers.erase(container.uuid);
    brain.deployments.erase(executionID);
    brain.machinesByUUID.erase(machine.uuid);
  }
}

static void runAsyncTaskTests(TestSuite& suite)
{
  testAsyncTaskAdmissionDurability(suite);
  testAsyncTaskTerminalDurability(suite);
}
