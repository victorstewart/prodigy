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

int main(void)
{
  TestSuite suite;
  testProductionPersistenceAPI(suite);
  testPersistentWriterDetachesViewBackedSchemaFields(suite);
  testPersistentWriterRetainedAccountingChargesManyShortStrings(suite);
  testNeuronOSUpdateUsesOwnedReceiptDrivenRequest(suite);
  testRuntimeAwareBrainActivatesOnlyTheAsyncPersistenceOwner(suite);
  testRuntimeAwareNeuronActivatesOnlyTheAsyncPersistenceOwner(suite);
  testBootPersistenceAdmissionRejectionHasNoReceipt(suite);
  return suite.failed == 0 ? 0 : 1;
}
