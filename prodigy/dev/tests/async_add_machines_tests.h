// Included by prodigy_brain_replication_credentials_unit.cpp after its shared
// TestBrain, ResumableAddMachinesBrain, AutoProvisionBrainIaaS, and TestSuite
// fixtures.

// Isolate the external SSH resource probe; admission, journals, bootstrap
// ordering, topology publication, and responses still use Brain::addMachines.
class AsyncAdoptedMachinesBrain final : public ResumableAddMachinesBrain {
public:
  bool canSuspendRemoteBootstrap() const override { return false; }
  bool normalizeAdoptedClusterMachine(const ClusterMachine& requested, const String&,
                                      const String&, ClusterMachine& normalized,
                                      String& failure) const override
  {
    normalized = requested;
    failure.clear();
    return true;
  }
};

static ClusterMachine asyncAddMachinesSeedMachine(uint128_t uuid, const String& address)
{
  ClusterMachine machine = {};
  machine.uuid = uuid;
  machine.source = ClusterMachineSource::created;
  machine.backing = ClusterMachineBacking::cloud;
  machine.kind = MachineConfig::MachineKind::vm;
  machine.lifetime = MachineLifetime::ondemand;
  machine.isBrain = true;
  machine.cloud.schema.assign("seed-vm"_ctv);
  machine.cloud.providerMachineType.assign("seed-vm"_ctv);
  machine.cloud.cloudID.assign("async-addmachines-seed"_ctv);
  machine.ssh.address = address;
  machine.ssh.user.assign("root"_ctv);
  machine.ssh.privateKeyPath.assign("/tmp/test-key"_ctv);
  prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, address, 64);
  return machine;
}

static ClusterMachine asyncAddMachinesAdoptedWorker(uint128_t uuid, const String& address)
{
  ClusterMachine machine = {};
  machine.uuid = uuid;
  machine.source = ClusterMachineSource::adopted;
  machine.backing = ClusterMachineBacking::owned;
  machine.kind = MachineConfig::MachineKind::vm;
  machine.lifetime = MachineLifetime::owned;
  machine.isBrain = false;
  machine.ssh.address = address;
  machine.ssh.port = 22;
  machine.ssh.user.assign("root"_ctv);
  machine.ssh.privateKeyPath.assign("/tmp/test-key"_ctv);
  machine.ssh.hostPublicKeyOpenSSH.assign("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIasync-addmachines"_ctv);
  prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, address, 64);
  prodigyAppendUniqueClusterMachinePeerAddress(machine.peerAddresses, ClusterMachinePeerAddress {address, 64});
  machine.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
  return machine;
}

static AddMachines asyncAddMachinesAdoptedRequest(uint128_t clusterUUID, ClusterMachine worker)
{
  AddMachines request = {};
  request.clusterUUID = clusterUUID;
  request.bootstrapSshUser.assign("root"_ctv);
  request.bootstrapSshPrivateKeyPath.assign("/tmp/test-key"_ctv);
  request.controlSocketPath.assign("/run/prodigy/control.sock"_ctv);
  request.adoptedMachines.push_back(std::move(worker));
  return request;
}

static void configureAsyncAddMachinesBrain(ResumableAddMachinesBrain& brain, BrainIaaS& iaas,
                                           uint128_t clusterUUID, uint128_t seedUUID)
{
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.nBrains = 1;
  brain.brainConfig.clusterUUID = clusterUUID;
  brain.authoritativeTopology.version = 17;
  brain.authoritativeTopology.machines.push_back(
      asyncAddMachinesSeedMachine(seedUUID, "2001:db8:aa::10"_ctv));
}

static void testAsyncAddMachinesAdoptedJournalDurability(TestSuite& suite)
{
  {
    NoopBrainIaaS iaas = {};
    AsyncAdoptedMachinesBrain brain = {};
    configureAsyncAddMachinesBrain(brain, iaas, 0xaadd01, 0xaadd11);
    brain.holdRuntimePersistence = true;
    bool completed = false;
    AddMachines response = {};
    brain.addMachines(nullptr,
        asyncAddMachinesAdoptedRequest(brain.brainConfig.clusterUUID,
                                       asyncAddMachinesAdoptedWorker(0xaadd12, "2001:db8:aa::12"_ctv)),
        {}, nullptr, [&](AddMachines value) { completed = true; response = std::move(value); });

    suite.expect(brain.pendingRuntimePersistence.size() == 1 && brain.bootstrappedMachines.empty() && !completed,
                 "async_addmachines_adopted_holds_bootstrap_and_response_before_initial_journal_receipt");
    brain.finishRuntimePersistence(false);
    suite.expect(completed && !response.success && brain.bootstrappedMachines.empty() &&
                     brain.authoritativeTopology.machines.size() == 1 &&
                     brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.empty(),
                 "async_addmachines_adopted_initial_journal_failure_never_bootstraps_or_publishes_topology");
  }

  {
    NoopBrainIaaS iaas = {};
    AsyncAdoptedMachinesBrain brain = {};
    configureAsyncAddMachinesBrain(brain, iaas, 0xaadd02, 0xaadd21);
    brain.holdRuntimePersistence = true;
    bool completed = false;
    brain.addMachines(nullptr,
        asyncAddMachinesAdoptedRequest(brain.brainConfig.clusterUUID,
                                       asyncAddMachinesAdoptedWorker(0xaadd22, "2001:db8:aa::22"_ctv)),
        {}, nullptr, [&](AddMachines) { completed = true; });

    ++brain.masterAuthorityEpoch;
    brain.finishRuntimePersistence(true);
    suite.expect(!completed && brain.bootstrappedMachines.empty() && brain.authoritativeTopology.machines.size() == 1 &&
                     brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.size() == 1,
                 "async_addmachines_adopted_stale_initial_journal_receipt_never_bootstraps_or_replies");
  }
}

static void testAsyncAddMachinesFinalJournalDurability(TestSuite& suite)
{
  NoopBrainIaaS iaas = {};
  AsyncAdoptedMachinesBrain brain = {};
  configureAsyncAddMachinesBrain(brain, iaas, 0xaadd03, 0xaadd31);
  brain.holdRuntimePersistence = true;
  bool completed = false;
  AddMachines response = {};
  brain.addMachines(nullptr,
      asyncAddMachinesAdoptedRequest(brain.brainConfig.clusterUUID,
                                     asyncAddMachinesAdoptedWorker(0xaadd32, "2001:db8:aa::32"_ctv)),
      {}, nullptr, [&](AddMachines value) { completed = true; response = std::move(value); });

  if (!suite.require(brain.pendingRuntimePersistence.size() == 1,
                     "async_addmachines_final_journal_fixture_initial_receipt_held"))
  {
    return;
  }
  brain.finishRuntimePersistence(true);
  suite.expect(brain.bootstrappedMachines.size() == 1 && brain.authoritativeTopology.machines.size() == 2 &&
                   !completed && brain.pendingRuntimePersistence.size() == 1 &&
                   brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.empty(),
               "async_addmachines_final_journal_holds_success_response_until_erasure_receipt");
  brain.finishRuntimePersistence(true);
  suite.expect(completed && response.success && response.hasTopology && response.topology.machines.size() == 2 &&
                   brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.empty(),
               "async_addmachines_final_journal_durable_erasure_releases_success_response_once");
}

static void testAsyncAddMachinesProviderJournalDurability(TestSuite& suite)
{
 for (int outcome = 0; outcome < 3; ++outcome)
 {
  AutoProvisionBrainIaaS iaas = {};
  AsyncQueuedAddMachinesBrain brain = {};
  configureAsyncAddMachinesBrain(brain, iaas, 0xaadd04, 0xaadd41);
  iaas.observedBrain = &brain;
  brain.holdRuntimePersistence = true;

  MachineConfig workerConfig = {};
  workerConfig.kind = MachineConfig::MachineKind::vm;
  workerConfig.slug.assign("async-worker-vm"_ctv);
  workerConfig.providerMachineType.assign("async-worker-vm"_ctv);
  workerConfig.nLogicalCores = 2;
  workerConfig.nMemoryMB = 4096;
  workerConfig.nStorageMB = 32'768;
  brain.brainConfig.configBySlug.insert_or_assign(workerConfig.slug, workerConfig);

  AddMachines request = {};
  request.clusterUUID = brain.brainConfig.clusterUUID;
  request.bootstrapSshUser.assign("root"_ctv);
  request.bootstrapSshPrivateKeyPath.assign("/tmp/test-key"_ctv);
  request.controlSocketPath.assign("/run/prodigy/control.sock"_ctv);
  Brain::ManagedAddMachinesWork work = {};
  CreateMachinesInstruction instruction = {};
  instruction.backing = ClusterMachineBacking::cloud;
  instruction.kind = MachineConfig::MachineKind::vm;
  instruction.lifetime = MachineLifetime::ondemand;
  instruction.count = 1;
  instruction.isBrain = false;
  instruction.cloud.schema.assign("async-worker-vm"_ctv);
  work.createdMachines.push_back(instruction);
  iaas.snapshotsToReturn.push_back(
      makeMachineSnapshot("async-worker-vm"_ctv, "2001:db8:aa::42"_ctv, "async-worker-42"_ctv, 0xaadd42));

  bool completed = false; bool succeeded = false;
  brain.addMachines(nullptr, std::move(request), std::move(work), nullptr,
                    [&](AddMachines response) { completed = true; succeeded = response.success; });
  suite.expect(iaas.spinCalls == 0 && brain.pendingRuntimePersistence.size() == 1,
               "async_addmachines_provider_does_not_spin_before_initial_journal_receipt");
  brain.finishRuntimePersistence(true);
  suite.expect(iaas.spinCalls == 1 && iaas.sawPendingOperationDuringSpin,
               "async_addmachines_provider_spins_only_after_durable_initial_journal");

  suite.expect(brain.asyncQueuedMachines.empty() && brain.pendingRuntimePersistence.size() == 2,
               "async_addmachines_incremental_identity_holds_bootstrap_before_receipts");
  if (outcome == 2) ++brain.masterAuthorityEpoch;
  brain.finishRuntimePersistence(outcome != 0);
  suite.expect(brain.asyncQueuedMachines.empty(),
               "async_addmachines_accepted_identity_receipt_alone_cannot_bootstrap");
  brain.finishRuntimePersistence(outcome != 0);
  if (outcome == 1)
  {
    suite.expect(brain.asyncQueuedMachines.size() == 1 && brain.pendingBootstrap && !completed,
                 "async_addmachines_provisioned_identity_receipt_queues_bootstrap_once");
    brain.finishRuntimePersistence(true);
    auto *coordinator = brain.pendingBootstrap;
    if (suite.require(coordinator && coordinator->tasks.size() == 1,
                      "async_addmachines_incremental_coordinator_is_owned_until_completion"))
    {
      auto *task = coordinator->tasks[0];
      task->complete(true, String(), false);
      coordinator->closeHandler(task);
      suite.expect(!completed && brain.pendingRuntimePersistence.size() == 1,
                   "async_addmachines_incremental_success_waits_for_final_erase");
      brain.finishRuntimePersistence(true);
      suite.expect(completed && succeeded, "async_addmachines_incremental_durable_completion_succeeds");
    }
  }
  else
  {
    for (unsigned count = 0; count < 8 && !brain.pendingRuntimePersistence.empty(); ++count)
      brain.finishRuntimePersistence(false);
    suite.expect(brain.asyncQueuedMachines.empty() && !succeeded && (outcome == 2 ? !completed : completed),
                 "async_addmachines_failed_or_stale_identity_receipts_cannot_bootstrap_or_succeed");
  }
 }
}

static void runAsyncAddMachinesTests(TestSuite& suite)
{
  ScopedRing ring;
  testAsyncAddMachinesAdoptedJournalDurability(suite);
  testAsyncAddMachinesFinalJournalDurability(suite);
  testAsyncAddMachinesProviderJournalDurability(suite);
}
