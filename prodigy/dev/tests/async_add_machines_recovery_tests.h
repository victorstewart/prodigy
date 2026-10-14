// Included after prodigy_brain_replication_credentials_unit.cpp shared fixtures.
class AsyncAddMachinesRecoveryBrain final : public ResumableAddMachinesBrain {
public:
  ClusterTopology pendingTopology = {};
  PersistenceCompletion pendingTopologyCompletion = {};

  void persistAuthoritativeClusterTopologyAsync(ClusterTopology topology,
                                                PersistenceCompletion completion) override
  {
    pendingTopology = std::move(topology);
    pendingTopologyCompletion = std::move(completion);
  }

  void finishTopologyPersistence(bool durable)
  {
    if (durable) authoritativeTopology = pendingTopology;
    auto completion = std::move(pendingTopologyCompletion);
    pendingTopologyCompletion = {};
    if (completion) completion(durable);
  }
};

static ProdigyPendingAddMachinesOperation makeAsyncRecoveryOperation(uint64_t operationID)
{
  ProdigyPendingAddMachinesOperation operation = {};
  operation.operationID = operationID;
  operation.request.clusterUUID = 0xadd01;
  operation.request.architecture = MachineCpuArchitecture::x86_64;
  operation.request.bootstrapSshUser.assign("root"_ctv);
  operation.request.bootstrapSshPrivateKeyPath.assign("/tmp/test-key"_ctv);
  operation.request.controlSocketPath.assign("/run/prodigy/control.sock"_ctv);
  operation.request.remoteProdigyPath.assign("/root/prodigy"_ctv);

  ClusterMachine machine = {};
  machine.uuid = uint128_t(0xadd10) + operationID;
  machine.source = ClusterMachineSource::adopted;
  machine.backing = ClusterMachineBacking::owned;
  machine.kind = MachineConfig::MachineKind::vm;
  machine.lifetime = MachineLifetime::owned;
  machine.ssh.address.assign("10.22.0.10"_ctv);
  machine.ssh.user.assign("root"_ctv);
  machine.ssh.privateKeyPath.assign("/tmp/test-key"_ctv);
  machine.ssh.hostPublicKeyOpenSSH.assign("ssh-ed25519 test-key"_ctv);
  prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses,
                                           "10.22.0.10"_ctv, 24, "10.22.0.1"_ctv);
  operation.plannedTopology.version = 1;
  operation.plannedTopology.machines.push_back(machine);
  operation.machinesToBootstrap.push_back(machine);
  return operation;
}

static void testAsyncAddMachinesRecoveryPersistence(TestSuite& suite)
{
  {
    ScopedRing ring;
    AsyncAddMachinesRecoveryBrain brain;
    brain.weAreMaster = true;
    brain.noMasterYet = false;
    brain.nBrains = 1;
    brain.holdRuntimePersistence = true;
    brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.push_back(
        makeAsyncRecoveryOperation(1));

    bool completed = false;
    bool success = false;
    brain.resumePendingAddMachinesOperationAsync(1, [&](bool durable) {
      completed = true;
      success = durable;
    });
    suite.expect(brain.bootstrappedMachines.empty() && !completed &&
                     brain.activeAddMachinesOperations.contains(1),
                 "async_addmachines_recovery_waits_for_refreshed_journal_receipt");

    bool duplicateCompleted = false;
    bool duplicateSuccess = true;
    brain.resumePendingAddMachinesOperationAsync(1, [&](bool durable) {
      duplicateCompleted = true;
      duplicateSuccess = durable;
    });
    suite.expect(duplicateCompleted && !duplicateSuccess,
                 "async_addmachines_recovery_rejects_second_inflight_resume");

    brain.finishRuntimePersistence(true);
    suite.expect(brain.bootstrappedMachines.size() == 1 && !completed &&
                     bool(brain.pendingTopologyCompletion),
                 "async_addmachines_recovery_bootstraps_only_after_journal_receipt");
    suite.expect(brain.authoritativeTopology.machines.empty(),
                 "async_addmachines_recovery_hides_topology_before_topology_receipt");

    brain.finishTopologyPersistence(true);
    suite.expect(!completed && brain.activeAddMachinesOperations.contains(1) &&
                     brain.pendingRuntimePersistence.size() == 1,
                 "async_addmachines_recovery_holds_completion_and_replay_fence_until_erase_receipt");
    brain.finishRuntimePersistence(true);
    suite.expect(completed && success && brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.empty(),
                 "async_addmachines_recovery_completes_after_durable_erase");
  }

  {
    ScopedRing ring;
    AsyncAddMachinesRecoveryBrain brain;
    brain.weAreMaster = true;
    brain.noMasterYet = false;
    brain.nBrains = 1;
    brain.holdRuntimePersistence = true;
    brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.push_back(
        makeAsyncRecoveryOperation(2));
    bool completed = false;
    bool success = true;
    brain.resumePendingAddMachinesOperationAsync(2, [&](bool durable) {
      completed = true;
      success = durable;
    });
    brain.finishRuntimePersistence(false);
    suite.expect(brain.bootstrappedMachines.empty() && !completed &&
                     brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.size() == 1,
                 "async_addmachines_recovery_write_failure_has_no_bootstrap_or_erase");
    brain.finishRuntimePersistence(true);
    suite.expect(completed && !success && brain.bootstrappedMachines.empty(),
                 "async_addmachines_recovery_write_failure_completes_after_failure_journal");
  }

  {
    ScopedRing ring;
    AsyncAddMachinesRecoveryBrain brain;
    brain.weAreMaster = true;
    brain.noMasterYet = false;
    brain.nBrains = 1;
    brain.holdRuntimePersistence = true;
    brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.push_back(
        makeAsyncRecoveryOperation(3));
    bool completed = false;
    brain.resumePendingAddMachinesOperationAsync(3, [&](bool) { completed = true; });
    ++brain.masterAuthorityEpoch;
    brain.finishRuntimePersistence(true);
    suite.expect(brain.bootstrappedMachines.empty() && !completed &&
                     !brain.activeAddMachinesOperations.contains(3),
                 "async_addmachines_recovery_stale_epoch_is_inert_and_releases_fence");
  }

  {
    ScopedRing ring;
    AsyncAddMachinesRecoveryBrain brain;
    brain.weAreMaster = true;
    brain.noMasterYet = false;
    brain.nBrains = 1;
    brain.holdRuntimePersistence = true;
    brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.push_back(
        makeAsyncRecoveryOperation(4));
    bool completed = false;
    bool success = true;
    brain.resumePendingAddMachinesOperationAsync(4, [&](bool durable) {
      completed = true;
      success = durable;
    });
    brain.finishRuntimePersistence(true);
    brain.finishTopologyPersistence(false);
    suite.expect(brain.authoritativeTopology.machines.empty() && !completed &&
                     brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.size() == 1,
                 "async_addmachines_recovery_topology_failure_does_not_publish_or_erase");
    brain.finishRuntimePersistence(true);
    suite.expect(completed && !success && brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.size() == 1,
                 "async_addmachines_recovery_topology_failure_retains_replay_journal");
  }

  {
    ScopedRing ring;
    AsyncAddMachinesRecoveryBrain brain;
    AutoProvisionBrainIaaS iaas = {};
    brain.iaas = &iaas;
    brain.weAreMaster = true;
    brain.noMasterYet = false;
    brain.nBrains = 1;
    brain.brainConfig.clusterUUID = 0xadd50;

    MachineConfig config = {};
    config.slug.assign("suspended-provider-vm"_ctv);
    config.kind = MachineConfig::MachineKind::vm;
    config.providerMachineType.assign("test-vm"_ctv);
    brain.brainConfig.configBySlug.insert_or_assign(config.slug, config);

    ProdigyPendingAddMachinesOperation operation = makeAsyncRecoveryOperation(5);
    operation.request.clusterUUID = brain.brainConfig.clusterUUID;
    operation.machinesToBootstrap.clear();
    brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.push_back(operation);

    ProdigyPendingAddMachinesProvisioningIntent intent = {};
    intent.operationID = operation.operationID;
    CreateMachinesInstruction instruction = {};
    instruction.kind = MachineConfig::MachineKind::vm;
    instruction.lifetime = MachineLifetime::ondemand;
    instruction.backing = ClusterMachineBacking::cloud;
    instruction.cloud.schema = config.slug;
    instruction.cloud.providerMachineType = config.providerMachineType;
    instruction.count = 1;
    instruction.isBrain = true;
    intent.instructions.push_back(instruction);
    brain.masterAuthorityRuntimeState.pendingAddMachinesProvisioningIntents.push_back(intent);

    iaas.suspendSpinWithFailure = true;
    bool completed = false;
    bool success = true;
    brain.resumePendingAddMachinesOperationAsync(5, [&](bool durable) {
      completed = true;
      success = durable;
    });
    suite.expect(!completed && iaas.suspendedSpinStack != nullptr &&
                     brain.activeAddMachinesOperations.contains(5),
                 "async_addmachines_recovery_waits_for_suspended_provider_failure");

    iaas.finishSuspendedSpinFailure();
    const ProdigyPendingAddMachinesOperation *retained = brain.findPendingAddMachinesOperation(5);
    suite.expect(completed && !success && iaas.suspendedSpinStack == nullptr &&
                     retained != nullptr && retained->lastFailure.equals(
                         "injected suspended provider failure"_ctv),
                 "async_addmachines_recovery_retires_provider_stack_after_resume");
  }
}
