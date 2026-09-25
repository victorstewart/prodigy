#define PRODIGY_RUNTIME_PERSISTENCE_UNIT
#include "../../prodigy.cpp"

#include <cstdio>

#include <prodigy/dev/tests/persistence_fixture.h>

class RuntimeTestNeuronIaaS final : public NeuronIaaS {
public:
  void gatherSelfData(CoroutineStack *, uint128_t& uuid, String& metro, bool& isBrain,
                      EthDevice& eth, IPAddress& private4) override
  {
    uuid = 0;
    metro.clear();
    isBrain = false;
    (void)eth;
    private4 = {};
  }
};

class ReceiptTestNeuron final : public Neuron {
public:
  RuntimeTestNeuronIaaS testIaaS;
  uint32_t submissions = 0;
  String targetOSID, targetOSVersionID, command;
  std::function<void(bool, String)> receipt;

  ReceiptTestNeuron() { iaas = &testIaaS; }
  void pushContainer(Container *) override {}
  void popContainer(Container *) override {}
  bool ensureHostNetworkingReady(String *failure = nullptr) override
  {
    if (failure) failure->clear();
    return true;
  }
  void downloadContainer(CoroutineStack *, uint64_t) override {}
  void startOperatingSystemUpdateAsync(String osID, String version, String update,
                                       std::function<void(bool, String)> completion) override
  {
    ++submissions;
    targetOSID = std::move(osID);
    targetOSVersionID = std::move(version);
    command = std::move(update);
    receipt = std::move(completion);
  }
};

template <typename... Args>
static Message *runtimePersistenceMessage(String& buffer, NeuronTopic topic, Args&&...args)
{
  buffer.clear();
  Message::construct(buffer, topic, std::forward<Args>(args)...);
  return reinterpret_cast<Message *>(buffer.data());
}

static ProdigyPersistentBootState runtimePersistenceBootState(void)
{
  ProdigyPersistentBootState boot = {};
  boot.bootstrapConfig.nodeRole = ProdigyBootstrapNodeRole::brain;
  boot.bootstrapSshUser.assign("bootstrap-user"_ctv);
  return boot;
}

static void testPersistentWriterDetachesViewBackedSchemaFields(TestSuite& suite)
{
  String backing = {};
  backing.assign("original-certificate"_ctv);
  ProdigyPersistentLocalBrainState state = {};
  state.transportTLS.localCertPem = String(const_cast<uint8_t *>(backing.data()), backing.size(), Copy::no, backing.size());

  const bool detached = ProdigyPersistentStateWriter::detach(state);
  backing.assign("mutated-certificate!"_ctv);
  suite.expect(detached && state.transportTLS.localCertPem.equals("original-certificate"_ctv),
               "runtime_persistence_writer_detaches_view_backed_local_state");

  String bootBacking = {};
  bootBacking.assign("bootstrap-user"_ctv);
  ProdigyPersistentBootState boot = {};
  boot.bootstrapSshUser = String(const_cast<uint8_t *>(bootBacking.data()), bootBacking.size(), Copy::no, bootBacking.size());
  const bool detachedBoot = ProdigyPersistentStateWriter::detach(boot);
  bootBacking.assign("changed-bootstrap"_ctv);
  suite.expect(detachedBoot && boot.bootstrapSshUser.equals("bootstrap-user"_ctv),
               "runtime_persistence_writer_detaches_view_backed_boot_state");

  String snapshotBacking = {};
  snapshotBacking.assign("snapshot-user"_ctv);
  ProdigyPersistentBrainSnapshot snapshot = {};
  snapshot.brainConfig.bootstrapSshUser = String(const_cast<uint8_t *>(snapshotBacking.data()), snapshotBacking.size(), Copy::no, snapshotBacking.size());
  const bool detachedSnapshot = ProdigyPersistentStateWriter::detach(snapshot);
  snapshotBacking.assign("changed-snapshot"_ctv);
  suite.expect(detachedSnapshot && snapshot.brainConfig.bootstrapSshUser.equals("snapshot-user"_ctv),
               "runtime_persistence_writer_detaches_view_backed_snapshot");

  String mapKeyBacking = {}, mapValueBacking = {};
  mapKeyBacking.assign("token"_ctv);
  mapValueBacking.assign("nested-secret"_ctv);
  String mapKey(const_cast<uint8_t *>(mapKeyBacking.data()), mapKeyBacking.size(), Copy::no, mapKeyBacking.size());
  String mapValue(const_cast<uint8_t *>(mapValueBacking.data()), mapValueBacking.size(), Copy::no, mapValueBacking.size());
  snapshot.brainConfig.dnsCredential.metadata.insert_or_assign(std::move(mapKey), std::move(mapValue));
  const bool detachedMap = ProdigyPersistentStateWriter::detach(snapshot);
  mapKeyBacking.assign("other"_ctv);
  mapValueBacking.assign("changed-secret"_ctv);
  const auto nested = snapshot.brainConfig.dnsCredential.metadata.find("token"_ctv);
  suite.expect(detachedMap && nested != snapshot.brainConfig.dnsCredential.metadata.end() &&
                   nested->second.equals("nested-secret"_ctv),
               "runtime_persistence_writer_detaches_nested_map_views");
}

static void testPersistentWriterRetainedAccountingChargesManyShortStrings(TestSuite& suite)
{
  ProdigyPersistentBrainSnapshot snapshot = {};
  for (uint32_t index = 0; index < 512; ++index)
  {
    String key = {}, value = {};
    key.snprintf<"key-{itoa}"_ctv>(index);
    value.snprintf<"value-{itoa}"_ctv>(index);
    snapshot.brainConfig.dnsCredential.metadata.insert_or_assign(std::move(key), std::move(value));
  }
  String wire = {};
  ProdigyPersistentBrainSnapshot wireCopy = snapshot;
  BitseryEngine::serialize(wire, wireCopy);
  const uint64_t oldFlatEstimate = 2 * sizeof(snapshot) + 3 * wire.size();
  const uint64_t retained = ProdigyPersistentStateWriter::retainedBytesFor(snapshot);
  suite.expect(retained > oldFlatEstimate && retained <= ProdigyPersistentStateWriter::maximumRetainedBytes,
               "runtime_persistence_writer_accounts_many_short_string_allocations");
}

static void testNeuronOSUpdateUsesOwnedReceiptDrivenRequest(TestSuite& suite)
{
  ReceiptTestNeuron neuron;
  String buffer = {};
  Message *message = runtimePersistenceMessage(buffer, NeuronTopic::updateOS,
                                               "ubuntu"_ctv, "24.04"_ctv, "update-command"_ctv);
  neuron.neuronHandler(message);
  buffer.clear();
  suite.expect(neuron.submissions == 1 && neuron.targetOSID.equals("ubuntu"_ctv) &&
                   neuron.targetOSVersionID.equals("24.04"_ctv) &&
                   neuron.command.equals("update-command"_ctv),
               "runtime_persistence_neuron_os_update_owns_request_before_receipt");
  suite.expect(bool(neuron.receipt), "runtime_persistence_neuron_os_update_retains_receipt_callback");
  if (neuron.receipt) neuron.receipt(false, "injected receipt failure"_ctv);
}

static void testRuntimeAwareBrainActivatesOnlyTheAsyncPersistenceOwner(TestSuite& suite)
{
  const ProdigyPersistentBootState boot = runtimePersistenceBootState();
  RuntimeAwareBrainIaaS iaas(nullptr, boot.bootstrapConfig, boot, {});
  uint32_t submissions = 0;
  uint32_t completions = 0;
  uint64_t retainedBytes = 0;
  iaas.setAsyncBootStatePersistence([&](ProdigyPersistentBootState submitted, uint64_t bytes,
                                        std::function<void(bool)> completion) {
    ++submissions;
    retainedBytes = bytes;
    suite.expect(submitted.bootstrapSshUser.equals("bootstrap-user"_ctv),
                 "runtime_persistence_brain_preserves_boot_state_payload");
    completion(true);
    ++completions;
    return true;
  });

  ProdigyBootstrapConfig changed = boot.bootstrapConfig;
  iaas.configureBootstrapTopology(changed);

  suite.expect(submissions == 1 && completions == 1,
               "runtime_persistence_brain_activation_submits_once");
  suite.expect(retainedBytes > sizeof(ProdigyPersistentBootState) &&
                   retainedBytes < ProdigyPersistentStateWriter::maximumRetainedBytes,
               "runtime_persistence_brain_measures_schema_without_encoding");
}

static void testRuntimeAwareNeuronActivatesOnlyTheAsyncPersistenceOwner(TestSuite& suite)
{
  const ProdigyPersistentBootState boot = runtimePersistenceBootState();
  RuntimeAwareNeuronIaaS iaas(nullptr, boot.bootstrapConfig, boot, {});
  uint32_t submissions = 0;
  uint64_t retainedBytes = 0;
  iaas.setAsyncBootStatePersistence([&](ProdigyPersistentBootState submitted, uint64_t bytes,
                                        std::function<void(bool)> completion) {
    ++submissions;
    retainedBytes = bytes;
    suite.expect(submitted.bootstrapSshUser.equals("bootstrap-user"_ctv),
                 "runtime_persistence_neuron_preserves_boot_state_payload");
    completion(true);
    return true;
  });

  ProdigyBootstrapConfig changed = boot.bootstrapConfig;
  iaas.configureBootstrapTopology(changed);

  suite.expect(submissions == 1,
               "runtime_persistence_neuron_activation_submits_once");
  suite.expect(retainedBytes > sizeof(ProdigyPersistentBootState) &&
                   retainedBytes < ProdigyPersistentStateWriter::maximumRetainedBytes,
               "runtime_persistence_neuron_measures_schema_without_encoding");
}

static void testBootPersistenceAdmissionRejectionHasNoReceipt(TestSuite& suite)
{
  // The live submission contract is deliberately asymmetric: false means the
  // caller retained ownership and therefore no completion may be delivered.
  livePersistentWriter.reset();
  bool helperReceipt = false;
  ProdigyPersistentBootState state = runtimePersistenceBootState();
  const uint64_t retainedBytes = ProdigyPersistentStateWriter::retainedBytesFor(state);
  const bool helperAdmitted = prodigySubmitLiveBootState(std::move(state), retainedBytes,
      [&](bool) { helperReceipt = true; });
  suite.expect(!helperAdmitted && !helperReceipt,
               "runtime_persistence_live_boot_rejection_has_no_receipt");

  const ProdigyPersistentBootState boot = runtimePersistenceBootState();
  RuntimeAwareBrainIaaS brain(nullptr, boot.bootstrapConfig, boot, {});
  uint32_t brainAdmissions = 0;
  uint32_t brainReceipts = 0;
  brain.setAsyncBootStatePersistence([&](ProdigyPersistentBootState, uint64_t,
                                         std::function<void(bool)> completion) {
    ++brainAdmissions;
    (void)completion;
    return false;
  });
  brain.configureBootstrapTopology(boot.bootstrapConfig);
  suite.expect(brainAdmissions == 1 && brainReceipts == 0,
               "runtime_persistence_brain_handles_boot_admission_rejection");

  RuntimeAwareNeuronIaaS neuron(nullptr, boot.bootstrapConfig, boot, {});
  uint32_t neuronAdmissions = 0;
  uint32_t neuronReceipts = 0;
  neuron.setAsyncBootStatePersistence([&](ProdigyPersistentBootState, uint64_t,
                                          std::function<void(bool)> completion) {
    ++neuronAdmissions;
    (void)completion;
    return false;
  });
  neuron.configureBootstrapTopology(boot.bootstrapConfig);
  suite.expect(neuronAdmissions == 1 && neuronReceipts == 0,
               "runtime_persistence_neuron_handles_boot_admission_rejection");
}

static void testProductionPersistenceAPI(TestSuite& suite)
{
  for (int failureMode = 0; failureMode < 3; ++failureMode)
  {
    PersistenceRing ring;
    ScopedPersistentRoot root;
    ProdigyPersistentStateStore store(root.path);
    auto io = ProdigyArtifactIO::startOwned();
    suite.expect(io != nullptr, "runtime_api_worker_starts");
    if (!io) continue;
    std::atomic<bool> release = false, entered = false;
    uint32_t ticks = 0, ownershipReceipts = 0, snapshotReceipts = 0;
    bool snapshotSucceeded = false, drainInsideCallback = true;
    bool localSaved = false, snapshotSaved = false, bootSaved = false;
    auto writer = std::make_shared<ProdigyPersistentStateWriter>(store, *io,
        [&](auto& backingStore, auto& request) {
          entered = true;
          while (!release.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
          if (request.writeLocalState)
          {
            request.result.durable = backingStore.saveLocalBrainState(request.localState, &request.result.failure);
            localSaved = request.result.durable;
          }
          else
          {
            if (failureMode == 1) { request.result.failure.assign("injected snapshot failure"_ctv); return; }
            request.result.snapshotDurable = backingStore.saveBrainSnapshot(request.snapshot, &request.result.failure);
            request.result.durable = request.result.snapshotDurable;
            snapshotSaved = request.result.snapshotDurable;
            if (failureMode == 2) { request.result.failure.assign("injected boot follow-up failure"_ctv); return; }
            request.result.bootStateDurable = backingStore.saveBootState(request.bootState, &request.result.failure);
            bootSaved = request.result.bootStateDurable;
          }
        });
    persistentLocalBrainState = {};
    persistentLocalBrainState.uuid = 0x9901;
    persistentBootState = {};
    persistedBrainSnapshot = {};
    havePersistedBrainSnapshot = false;
    ProdigyHostControlNetwork network;
    {
      ProdigyBrain brain(network, writer);
      brain.brainConfig.clusterUUID = 0x9902;
      brain.brainConfig.bootstrapSshUser.assign("candidate-bootstrap-user"_ctv);
      suite.expect(!brain.persistLocalRuntimeState(), "runtime_api_rejects_live_sync_call");
      suite.expect(brain.claimLocalClusterOwnershipAsync(0x9902, [&](bool owned) {
        ++ownershipReceipts;
        suite.expect(owned && persistentLocalBrainState.ownerClusterUUID == 0x9902,
                     "runtime_api_ownership_cache_follows_durable_receipt");
        brain.persistLocalRuntimeStateAsync([&](bool durable) {
          ++snapshotReceipts;
          snapshotSucceeded = durable;
          drainInsideCallback = writer->drainForExec();
          Ring::exit = true;
        });
      }), "runtime_api_ownership_admitted");
      suite.expect(ownershipReceipts == 0 && snapshotReceipts == 0,
                   "runtime_api_no_inline_success_for_pending_disk");
      ring.tickAction = [&] {
        ++ticks;
        if (ticks == 30) release = true;
        else if (ticks < 30) ring.armTick(5);
      };
      ring.armTick(5); ring.armDeadline(5000);
      Ring::start();
      release = true;
      suite.expect(!ring.timedOut && ticks == 30 && ownershipReceipts == 1 && snapshotReceipts == 1,
                   "runtime_api_ring_progress_and_reentrant_ownership_to_snapshot");
      suite.expect(snapshotSucceeded == (failureMode == 0) && !drainInsideCallback && writer->drainForExec(),
                   "runtime_api_durability_and_drain_follow_terminal_receipt");
      suite.expect(localSaved && snapshotSaved == (failureMode != 1) && bootSaved == (failureMode == 0) &&
                       havePersistedBrainSnapshot == (failureMode != 1),
                   "runtime_api_partial_commit_cache_matches_durable_records");
      if (failureMode == 0)
        suite.expect(persistentBootState.bootstrapSshUser.equals("candidate-bootstrap-user"_ctv),
                     "runtime_api_boot_cache_uses_candidate_configuration");
    }
    writer.reset();
    io->stop(); ring.drainStoppedIO(); io.reset();
    (void)network.shutdown();
    store.close();
    ProdigyPersistentStateStore reopened(root.path);
    ProdigyPersistentBrainSnapshot snapshot;
    String failure;
    suite.expect(reopened.loadBrainSnapshot(snapshot, &failure) == (failureMode != 1),
                 "runtime_api_reopen_matches_snapshot_durability");
    reopened.close();
  }
}

static void testProductionPersistenceAdmissionFromArtifactCompletion(TestSuite& suite)
{
  PersistenceRing ring;
  ScopedPersistentRoot root;
  ProdigyPersistentStateStore store(root.path);
  auto io = ProdigyArtifactIO::startOwned();
  suite.expect(io != nullptr, "runtime_artifact_completion_starts_shared_writer");
  if (!io) return;

  persistentLocalBrainState = {};
  persistentBootState = {};
  persistedBrainSnapshot = {};
  havePersistedBrainSnapshot = false;
  auto writer = std::make_shared<ProdigyPersistentStateWriter>(store, *io);
  ProdigyHostControlNetwork network;
  bool artifactPublished = false;
  bool receiptWasInline = false;
  bool receiptDelivered = false;
  bool durable = false;
  bool queued = false;
  {
    ProdigyBrain brain(network, writer);
    brain.brainConfig.clusterUUID = 0xA51EULL;
    brain.brainConfig.bootstrapSshUser.assign("artifact-receipt"_ctv);
    queued = io->submit(1, [] {}, [&] {
      artifactPublished = true;
      brain.persistLocalRuntimeStateAsync([&](bool result) {
        receiptDelivered = true;
        durable = result;
        Ring::exit = true;
      });
      receiptWasInline = receiptDelivered;
    }, [](std::exception_ptr) { Ring::exit = true; });
    ring.armDeadline(1000);
    Ring::start();
    suite.expect(queued && !ring.timedOut && artifactPublished && !receiptWasInline && receiptDelivered && durable && writer->drainForExec(),
                 "runtime_artifact_publish_completion_admits_production_snapshot_receipt");
  }
  writer.reset();
  io->stop();
  ring.drainStoppedIO();
  io.reset();
  (void)network.shutdown();
  store.close();
  ProdigyPersistentStateStore reopened(root.path);
  ProdigyPersistentBrainSnapshot persisted = {};
  String failure = {};
  suite.expect(reopened.loadBrainSnapshot(persisted, &failure) && persisted.brainConfig.clusterUUID == 0xA51EULL,
               "runtime_artifact_publish_receipt_reopens_production_snapshot");
  reopened.close();
}

static void testProductionUpdateProgressDefersReentrantPersistenceUntilArtifactLeaseReleases(TestSuite& suite)
{
  // The first durable receipt begins bundle progress.  Its ArtifactIO slot is
  // intentionally still retained while the callback runs; seven queued jobs
  // fill the remaining slots.  A nested snapshot must therefore be deferred
  // until this receipt returns, rather than being synchronously rejected and
  // permanently fencing the update.
  for (int nestedMode = 0; nestedMode < 3; ++nestedMode)
  {
    PersistenceRing ring;
    ScopedPersistentRoot root;
    ProdigyPersistentStateStore store(root.path);
    auto io = ProdigyArtifactIO::startOwned();
    suite.expect(io != nullptr, "runtime_reentrant_update_worker_starts");
    if (!io) continue;

    std::atomic<bool> firstCommitEntered = false;
    std::atomic<bool> allowFirstCommit = false;
    std::atomic<bool> releaseFillers = false;
    std::atomic<uint32_t> snapshotWrites = 0, bootWrites = 0;
    auto writer = std::make_shared<ProdigyPersistentStateWriter>(store, *io,
        [&](auto& backing, auto& request) {
          if (!request.writeSnapshot) return;
          const uint32_t write = ++snapshotWrites;
          if (write == 1)
          {
            firstCommitEntered = true;
            while (!allowFirstCommit.load())
              std::this_thread::sleep_for(std::chrono::milliseconds(1));
          }
          if (nestedMode == 1 && write == 2)
          {
            request.result.failure.assign("injected nested durable failure"_ctv);
            return;
          }
          request.result.snapshotDurable = backing.saveBrainSnapshot(request.snapshot, &request.result.failure);
          request.result.durable = request.result.snapshotDurable;
          if (request.result.snapshotDurable)
          {
            request.result.bootStateDurable = backing.saveBootState(request.bootState, &request.result.failure);
            if (request.result.bootStateDurable) ++bootWrites;
          }
        });

    persistentLocalBrainState = {};
    persistentBootState = {};
    persistedBrainSnapshot = {};
    havePersistedBrainSnapshot = false;
    ProdigyHostControlNetwork network;
    uint32_t fillersCompleted = 0, ticks = 0;
    bool fillersQueued = false, firstReceipt = false, firstDurable = false;
    bool noEarlyBundleSend = true, releasedFillers = false, epochInvalidated = false;
    uint32_t settledAtTick = 0;
    {
      ProdigyBrain brain(network, writer);
      brain.brainConfig.clusterUUID = 0xA5510000ULL + nestedMode;
      brain.brainConfig.bootstrapSshUser.assign("reentrant-update"_ctv);
      brain.updateSelfUseStagedBundleOnly = true;
      BrainView peer = {};
      peer.uuid = 0xA5511000ULL + nestedMode;
      peer.boottimens = 1;
      // A known but inactive peer makes a later transition observable without
      // allowing this focused persistence fixture to queue a fake socket send.
      brain.brains.insert(&peer);

      brain.persistLocalRuntimeStateAsync([&](bool durable) {
        firstReceipt = true;
        firstDurable = durable;
        if (!durable) return;
        brain.beginUpdateSelfBundle(1);
        noEarlyBundleSend = peer.wBuffer.empty() && brain.updateSelfBundleIssuedPeerKeys.empty();
        // The deferred initiation must be fenced by the same authority epoch
        // that owns the staged update, even though the original receipt was
        // durable.  This mode verifies the stale request remains fail-closed.
        if (nestedMode == 2)
        {
          brain.advanceMasterAuthorityEpoch();
          epochInvalidated = true;
        }
      });

      ring.tickAction = [&] {
        ++ticks;
        if (!fillersQueued && firstCommitEntered.load())
        {
          for (uint32_t index = 0; index < ProdigyArtifactIO::maximumJobs - 1; ++index)
          {
            const bool admitted = io->submit(1,
                [&] {
                  while (!releaseFillers.load())
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                },
                [&] { ++fillersCompleted; },
                [&](std::exception_ptr) { Ring::exit = true; });
            suite.expect(admitted, "runtime_reentrant_update_fills_remaining_artifact_slots");
          }
          fillersQueued = true;
          allowFirstCommit = true;
        }
        // After the first callback returns, the fixed path can admit the
        // nested save as slot eight.  Releasing these jobs then lets it reach
        // the worker without relying on a large snapshot or a timing race.
        if (firstReceipt && fillersQueued && !releasedFillers &&
            (brain.updateSelfPersistencePending != 0 || brain.updateSelfPersistenceFailed || ticks > 20))
        {
          releasedFillers = true;
          releaseFillers = true;
        }
        const bool nestedDone = nestedMode == 1 ? brain.updateSelfPersistenceFailed :
            (nestedMode == 2 || (brain.masterAuthorityRuntimeStateDurable &&
             brain.durableMasterAuthorityRuntimeStateGeneration == brain.masterAuthorityRuntimeState.generation));
        if (fillersCompleted == ProdigyArtifactIO::maximumJobs - 1 && firstReceipt && nestedDone)
        {
          // Successful continuations are intentionally one more Ring turn
          // removed from the persistence receipt.  Keep pumping past the
          // observed state so their timer and any ready work cannot retain
          // Brain during this fixture's teardown.
          if (settledAtTick == 0) settledAtTick = ticks;
          if (ticks - settledAtTick >= 5)
          {
            Ring::exit = true;
            return;
          }
        }
        ring.armTick(1);
      };
      ring.armTick(1);
      ring.armDeadline(3000);
      Ring::start();
      releaseFillers = true;

      suite.expect(!ring.timedOut && ticks > 1 && fillersQueued && fillersCompleted == ProdigyArtifactIO::maximumJobs - 1,
                   "runtime_reentrant_update_ring_remains_responsive_under_full_artifact_slots");
      suite.expect(firstReceipt && firstDurable && noEarlyBundleSend &&
                       brain.updateSelfState == Brain::UpdateSelfState::waitingForBundleEchos,
                   "runtime_reentrant_update_does_not_send_bundle_before_nested_receipt");
      const bool expectedFailure = nestedMode == 1;
      const bool epochStale = nestedMode == 2;
      suite.expect(brain.updateSelfPersistenceFailed == (expectedFailure || epochStale) &&
                       brain.updateSelfPersistencePending == 0,
                   "runtime_reentrant_update_fences_failed_or_stale_nested_receipt");
      suite.expect(snapshotWrites.load() == (epochStale ? 1u : 2u) &&
                       bootWrites.load() == (expectedFailure || epochStale ? 1u : 2u),
                   "runtime_reentrant_update_nested_snapshot_admission_or_stale_suppression");
      suite.expect(epochStale ? epochInvalidated && peer.wBuffer.empty() && brain.updateSelfBundleIssuedPeerKeys.empty() :
                       (expectedFailure || (brain.masterAuthorityRuntimeStateDurable &&
                        brain.durableMasterAuthorityRuntimeStateGeneration == brain.masterAuthorityRuntimeState.generation)),
                   "runtime_reentrant_update_epoch_invalidated_request_cannot_send_stale_bundle");
      brain.brains.erase(&peer);
    }
    writer.reset();
    io->stop();
    ring.drainStoppedIO();
    io.reset();
    (void)network.shutdown();
    store.close();
    persistentLocalBrainState = {};
    persistentBootState = {};
    persistedBrainSnapshot = {};
    havePersistedBrainSnapshot = false;
  }
}

static void testLargeMetricHistoryUsesImmutableAsyncCapture(TestSuite& suite)
{
  PersistenceRing ring;
  ScopedPersistentRoot root;
  ProdigyPersistentStateStore store(root.path);
  auto io = ProdigyArtifactIO::startOwned();
  suite.expect(io != nullptr, "metric_capture_worker_starts");
  if (!io) return;
  constexpr uint32_t seriesCount = 128, perSeries = 12'500;
  constexpr uint64_t sampleCount = uint64_t(seriesCount) * perSeries;
  const auto ringThread = std::this_thread::get_id();
  std::atomic<bool> entered = false, release = false;
  bool workerThread = false;
  auto writer = std::make_shared<ProdigyPersistentStateWriter>(store, *io,
      [&](auto& backing, auto& request) {
        workerThread = std::this_thread::get_id() != ringThread;
        entered = true;
        while (!release.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        request.result.snapshotDurable = backing.saveBrainSnapshot(request.snapshot, &request.result.failure);
        request.result.durable = request.result.snapshotDurable;
        if (request.result.snapshotDurable)
          request.result.bootStateDurable = backing.saveBootState(request.bootState, &request.result.failure);
      });
  persistentLocalBrainState = {};
  persistentBootState = {};
  persistedBrainSnapshot = {};
  havePersistedBrainSnapshot = false;
  ProdigyHostControlNetwork network;
  Vector<int64_t> captures, controls;
  uint32_t receipts = 0, heldTicks = 0;
  bool durable = false, allDeferred = true, allAdmissible = true;
  {
    ProdigyBrain brain(network, writer);
    brain.brainConfig.clusterUUID = 0xCA9701;
    for (uint64_t key = 1; key <= seriesCount; ++key)
      for (uint32_t i = 0; i < perSeries; ++i)
        brain.metrics.record(7, 0xABC, key, i, i);

    int64_t lastTick = 0;
    ring.tickAction = [&] {
      const auto now = std::chrono::steady_clock::now();
      const int64_t current = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
      if (lastTick) controls.push_back(current - lastTick);
      lastTick = current;
      if (captures.size() < 30)
      {
        {
          auto snapshot = brain.buildPersistentBrainSnapshot();
          const auto frozen = snapshot.metricCapture;
          auto copy = snapshot;
          allDeferred = allDeferred && frozen && frozen->sampleCount() == sampleCount &&
              copy.metricSamples.empty() && copy.metricCapture == frozen;
          allAdmissible = allAdmissible && ProdigyPersistentStateWriter::detach(copy) &&
              ProdigyPersistentStateWriter::retainedBytesFor(copy) > 0;
        }
        captures.push_back(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - now).count());
        ring.armTick(1);
        return;
      }
      if (!receipts && heldTicks == 0)
      {
        brain.persistLocalRuntimeStateAsync([&](bool result) {
          ++receipts;
          durable = result;
          Ring::exit = true;
        });
        suite.expect(receipts == 0, "metric_capture_no_inline_durable_ack");
        // An admitted snapshot must retain its exact samples through mutation,
        // expiry and destruction of all current live series.
        brain.metrics.record(7, 0xABC, 1, perSeries, -1);
        brain.metrics.trimRetention(perSeries + 1, 0);
        brain.metrics.clear();
        brain.metrics.record(9, 0xDEF, 2, 1, -2);
      }
      if (++heldTicks == 30) release = true;
      ring.armTick(5);
    };
    ring.armTick(1); ring.armDeadline(10'000);
    Ring::start();
    release = true;
    suite.expect(!ring.timedOut && captures.size() == 30 && controls.size() >= 30 &&
                     entered && workerThread && heldTicks >= 30 && receipts == 1 && durable && writer->drainForExec(),
                 "metric_capture_background_commit_progress_and_exact_receipt");
    suite.expect(allDeferred, "metric_capture_does_not_flatten_or_copy_history_on_ring");
    suite.expect(allAdmissible, "metric_capture_accounts_retained_graph_and_worker_encoding");
    auto sorted = captures;
    std::sort(sorted.begin(), sorted.end());
    const int64_t captureP95 = sorted.size() == 30 ? sorted[28] : INT64_MAX;
    suite.expect(captureP95 < 10'000, "metric_capture_submission_p95_under_10ms");
    auto controlSorted = controls;
    std::sort(controlSorted.begin(), controlSorted.end());
    const int64_t controlP95 = controlSorted.empty() ? INT64_MAX : controlSorted[(controlSorted.size() * 95 + 99) / 100 - 1];
    suite.expect(controlP95 < 10'000, "metric_capture_control_p95_under_10ms");
    std::printf("METRIC_CAPTURE samples=%llu captureP95Us=%lld controlP95Us=%lld captureUs=",
                (unsigned long long)sampleCount, (long long)captureP95, (long long)controlP95);
    for (auto us : captures) std::printf("%lld,", (long long)us);
    std::printf(" controlUs=");
    for (auto us : controls) std::printf("%lld,", (long long)us);
    std::printf("\n");
  }
  writer.reset(); io->stop(); ring.drainStoppedIO(); io.reset();
  (void)network.shutdown(); store.close();
  ProdigyPersistentStateStore reopened(root.path);
  ProdigyPersistentBrainSnapshot decoded;
  String failure;
  bool correct = reopened.loadBrainSnapshot(decoded, &failure) &&
      decoded.brainConfig.clusterUUID == 0xCA9701 && decoded.metricSamples.size() == sampleCount;
  std::array<uint32_t, seriesCount> counts = {};
  for (const auto& sample : decoded.metricSamples)
  {
    const bool valid = sample.deploymentID == 7 && sample.containerUUID == 0xABC &&
        sample.metricKey >= 1 && sample.metricKey <= seriesCount && sample.ms >= 0 &&
        sample.ms < perSeries && sample.value == float(sample.ms);
    correct = correct && valid;
    if (valid)
    {
      correct = correct && uint32_t(sample.ms) == counts[sample.metricKey - 1];
      ++counts[sample.metricKey - 1];
    }
  }
  for (auto count : counts) correct = correct && count == perSeries;
  suite.expect(correct, "metric_capture_reopens_exact_generation_after_live_mutation");
  reopened.close();
  persistedBrainSnapshot = {};
  havePersistedBrainSnapshot = false;
}

int main(void)
{
  TestSuite suite;
  if (const char *only = std::getenv("PRODIGY_TEST_ONLY"); only != nullptr &&
      std::strcmp(only, "reentrant-update-persistence") == 0)
  {
    testProductionUpdateProgressDefersReentrantPersistenceUntilArtifactLeaseReleases(suite);
    std::printf("REENTRANT_UPDATE_PERSISTENCE_RESULT failed_assertions=%d\n", suite.failed);
    return suite.failed == 0 ? 0 : 1;
  }
  testProductionUpdateProgressDefersReentrantPersistenceUntilArtifactLeaseReleases(suite);
  testLargeMetricHistoryUsesImmutableAsyncCapture(suite);
  testProductionPersistenceAPI(suite);
  testProductionPersistenceAdmissionFromArtifactCompletion(suite);
  testPersistentWriterDetachesViewBackedSchemaFields(suite);
  testPersistentWriterRetainedAccountingChargesManyShortStrings(suite);
  testNeuronOSUpdateUsesOwnedReceiptDrivenRequest(suite);
  testRuntimeAwareBrainActivatesOnlyTheAsyncPersistenceOwner(suite);
  testRuntimeAwareNeuronActivatesOnlyTheAsyncPersistenceOwner(suite);
  testBootPersistenceAdmissionRejectionHasNoReceipt(suite);
  return suite.failed == 0 ? 0 : 1;
}
