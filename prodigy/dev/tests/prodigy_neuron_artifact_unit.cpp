#include <includes.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/message.h>
#include <networking/multiplexer.h>
#include <networking/ring.h>
#include <prodigy/neuron/neuron.h>

#include <cstdlib>
#include <filesystem>
#include <functional>
#include <memory>
#include <vector>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <unistd.h>

class TestSuite {
public:
  int failed = 0;
  void expect(bool value, const char *name)
  {
    if (!value)
    {
      dprintf(STDERR_FILENO, "FAIL: %s\n", name);
      ++failed;
    }
  }
};

class ScopedArtifactStore {
public:
  String root = {};
  ScopedArtifactStore()
  {
    std::filesystem::create_directories(".run");
    char pattern[] = ".run/prodigy-neuron-artifact-XXXXXX";
    if (char *created = ::mkdtemp(pattern)) root.assign(created);
  }
  ~ScopedArtifactStore()
  {
    if (root.size()) std::filesystem::remove_all(root.c_str());
  }
};

class ArtifactRing final : public TimeoutDispatcher {
public:
  RingDispatcher dispatcher;
  TimeoutPacket deadline = {};
  bool timedOut = false;
  ArtifactRing()
  {
    Ring::interfacer = &dispatcher;
    Ring::lifecycler = &dispatcher;
    Ring::exit = false;
    Ring::shuttingDown = false;
    Ring::createRing(64, 128, 8, 2, -1, -1, 8);
    deadline.dispatcher = this;
  }
  ~ArtifactRing()
  {
    Ring::shutdownForExec();
    Ring::interfacer = nullptr;
    Ring::lifecycler = nullptr;
    RingDispatcher::dispatcher = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;
  }
  void arm(uint64_t ms)
  {
    deadline.clear();
    deadline.setTimeoutMs(ms);
    Ring::queueTimeout(&deadline);
  }
  void dispatchTimeout(TimeoutPacket *) override
  {
    timedOut = true;
    Ring::exit = true;
  }
};

class TestNeuron final : public Neuron {
public:
  String root = {};
  NeuronBrainControlStream *retained = nullptr;
  std::vector<NeuronBrainControlStream *> retired = {};
  uint32_t artifactFinishes = 0;
  bool lastArtifactAdopted = false;
  bool lastArtifactSourceCurrent = false;

  String containerArtifactStoreRoot(void) const override { return root; }
  void receivedContainerArtifactFinished(uint64_t, bool adopted, bool sourceCurrent) override
  {
    ++artifactFinishes;
    lastArtifactAdopted = adopted;
    lastArtifactSourceCurrent = sourceCurrent;
  }
  void pushContainer(Container *) override {}
  void popContainer(Container *) override {}
  void downloadContainer(CoroutineStack *, uint64_t) override {}
  bool ensureHostNetworkingReady(String *failure = nullptr) override
  {
    if (failure) failure->clear();
    return true;
  }

  bool startForArtifactTest(const String& storeRoot)
  {
    root.assign(storeRoot);
    artifactIO = ProdigyArtifactIO::startOwned();
    if (!artifactIO) return false;
    brain = new NeuronBrainControlStream();
    brain->connected = true;
    brain->fd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    return brain->fd >= 0;
  }

  bool submit(uint64_t deploymentID, String&& blob)
  {
    return queueReceivedContainerArtifact(brain, deploymentID, std::move(blob));
  }

  void replaceBrainWithoutClosing(void)
  {
    if (retained != nullptr) retired.push_back(retained);
    retained = brain;
    brain = new NeuronBrainControlStream();
    brain->connected = true;
    brain->fd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  }

  void retainPendingDownload(uint64_t deploymentID)
  {
    pendingContainerDownloads.insert(deploymentID, nullptr);
  }

  bool hasPendingDownload(uint64_t deploymentID)
  {
    return pendingContainerDownloads.contains(deploymentID);
  }

  bool stored(uint64_t deploymentID, const String& expectedBlob) const
  {
    String path = ContainerStore::pathForContainerImage(deploymentID, &root);
    struct stat metadata = {};
    if (::stat(path.c_str(), &metadata) != 0 || S_ISREG(metadata.st_mode) == false) return false;
    String storedBlob = {};
    Filesystem::openReadAtClose(-1, path, storedBlob);
    if (storedBlob.size() != expectedBlob.size()) return false;
    String expectedDigest = {};
    String storedDigest = {};
    return prodigyComputeSHA256Hex(expectedBlob, expectedDigest) &&
           prodigyComputeSHA256Hex(storedBlob, storedDigest) && expectedDigest == storedDigest;
  }

  bool artifactFinished(void) const { return artifactFinishes > 0; }

  bool quiesceArtifactIOForTest()
  {
    if (artifactIO == nullptr) return true;
    if (quiesceArtifactIOForBundleExec() == false) return false;
    artifactIO.reset();
    return true;
  }

  bool replacementQueuesPendingDownload(uint64_t deploymentID)
  {
    installedBundleDigest.assign("test-installed-bundle-digest"_ctv);
    installedBundleDigestReady = true;
    brain->pendingSend = true; // Inspect the same accepted-stream queue before I/O submission.
    queueAttestedInitialBrainControlFrames(brain);
    bool requested = false;
    uint64_t offset = 0;
    while (offset + Message::headerBytes <= brain->wBuffer.size())
    {
      Message *message = reinterpret_cast<Message *>(brain->wBuffer.data() + offset);
      if (message->size < Message::headerBytes || offset + message->size > brain->wBuffer.size()) return false;
      if (NeuronTopic(message->topic) == NeuronTopic::requestContainerBlob)
      {
        uint8_t *args = message->args;
        uint64_t receivedDeploymentID = 0;
        Message::extractArg<ArgumentNature::fixed>(args, receivedDeploymentID);
        requested = (receivedDeploymentID == deploymentID);
      }
      offset += message->size;
    }
    return offset == brain->wBuffer.size() && requested;
  }

  std::function<void(bool)> prepareWormholeOperationReply(SwitchboardWormholeOperation operation)
  {
    return wormholeOperationReply(std::move(operation));
  }

  std::function<void(bool)> prepareWormholeContainerRefresh(Container *container)
  {
    return wormholeContainerRefresh(container);
  }

  void trackContainerForReplyTest(Container *container)
  {
    containers.insert_or_assign(container->plan.uuid, container);
  }

  void untrackContainerForReplyTest(uint128_t uuid)
  {
    containers.erase(uuid);
  }

  void prepareContainerReplyBuffer(Container *container)
  {
    container->wBuffer.clear();
    container->pendingSend = true; // Inspect the queued container reply without I/O.
  }

  bool readContainerWormholeRefresh(Container *container, String& serialized) const
  {
    if (container == nullptr || container->wBuffer.size() < Message::headerBytes) return false;
    Message *message = reinterpret_cast<Message *>(container->wBuffer.data());
    if (message->size != container->wBuffer.size() || ContainerTopic(message->topic) != ContainerTopic::wormholesRefresh)
      return false;
    uint8_t *args = message->args;
    Message::extractToStringView(args, serialized);
    return true;
  }

  void prepareBrainReplyBuffer(void)
  {
    brain->wBuffer.clear();
    brain->pendingSend = true; // Keep the reply in the accepted-stream buffer for inspection.
  }

  bool readWormholeOperationReply(SwitchboardWormholeOperation& operation) const
  {
    if (brain == nullptr || brain->wBuffer.size() < Message::headerBytes) return false;
    Message *message = reinterpret_cast<Message *>(brain->wBuffer.data());
    if (message->size != brain->wBuffer.size() || NeuronTopic(message->topic) != NeuronTopic::openSwitchboardWormholes)
      return false;
    uint8_t *args = message->args;
    String serialized = {};
    Message::extractToStringView(args, serialized);
    return BitseryEngine::deserializeSafe(serialized, operation);
  }

  bool replyBufferEmpty(void) const { return brain == nullptr || brain->wBuffer.size() == 0; }

  void advanceBrainGenerationForReplyTest(void) { ++brain->ioGeneration; }
  void deactivateBrainForReplyTest(void) { brain->connected = false; }
  void reactivateBrainForReplyTest(void) { brain->connected = true; }
  void expireReplyLifetimeForTest(void) { asyncOperationLifetime.reset(); }
  void restoreReplyLifetimeForTest(void) { asyncOperationLifetime = std::make_shared<uint8_t>(0); }
  void prepareBrainForArtifactTest(void)
  {
    brain->wBuffer.clear();
    brain->pendingSend = false;
    brain->connected = true;
  }

  ~TestNeuron()
  {
    // main() keeps this owner alive until quiesceForExec observes the terminal
    // raw-poll cancellation CQE. Do not destroy it beside Ring shutdown.
    if (artifactIO != nullptr) std::abort();
    if (brain && brain->fd >= 0) ::close(brain->fd);
    if (retained && retained->fd >= 0) ::close(retained->fd);
    for (NeuronBrainControlStream *stream : retired)
    {
      if (stream && stream->fd >= 0) ::close(stream->fd);
      delete stream;
    }
    delete brain;
    delete retained;
    brain = nullptr;
    retained = nullptr;
  }
};

static bool loadFixture(String& blob)
{
  const char *path = ::getenv("PRODIGY_TEST_APP_ARTIFACT");
  if (path == nullptr || path[0] == '\0') return false;
  Filesystem::openReadAtClose(-1, String(path), blob);
  String header = {};
  String headerText = prodigyDiscombobulatorBlobHeaderText();
  header.assign(blob.substr(0, headerText.size(), Copy::yes));
  String failure = {};
  return blob.size() > headerText.size() && prodigyValidateDiscombobulatorBlobHeaderText(header, &failure);
}

static void runRingUntil(ArtifactRing& ring, const std::function<bool()>& done)
{
  Ring::exit = false;
  TimeoutPacket tick = {};
  class Tick final : public TimeoutDispatcher {
  public:
    TimeoutPacket *packet = nullptr;
    std::function<bool()> done = {};
    void dispatchTimeout(TimeoutPacket *) override
    {
      if (done()) { Ring::exit = true; return; }
      packet->clear();
      packet->setTimeoutMs(5);
      Ring::queueTimeout(packet);
    }
  } tickDispatcher;
  tick.dispatcher = &tickDispatcher;
  tickDispatcher.packet = &tick;
  tickDispatcher.done = done;
  tick.setTimeoutMs(5);
  Ring::queueTimeout(&tick);
  ring.arm(1500);
  Ring::start();
  Ring::exit = false;
}

int main()
{
  TestSuite suite = {};
  String fixture = {};
  const bool hasArtifactFixture = loadFixture(fixture);
  if (!hasArtifactFixture)
  {
    dprintf(STDERR_FILENO, "SKIP: neuron artifact fixture requires PRODIGY_TEST_APP_ARTIFACT; callback receipt cases remain active\n");
  }

  ScopedArtifactStore store = {};
  suite.expect(store.root.size() > 0, "neuron_artifact_private_store_created");
  if (store.root.size() == 0) return EXIT_FAILURE;

  ArtifactRing ring = {};
  TestNeuron neuron = {};
  const bool started = neuron.startForArtifactTest(store.root);
  suite.expect(started, "neuron_artifact_starts_worker_and_control_stream");
  if (started)
  {
    auto operation = [] {
      SwitchboardWormholeOperation value = {};
      value.containerID = 0x00a1b2c3;
      value.status = SwitchboardWormholeOperationStatus::applied;
      value.revision.assign("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv);
      value.desired.assign("requested-wormhole-state"_ctv);
      return value;
    };
    auto isExactReply = [&](SwitchboardWormholeOperationStatus expectedStatus) {
      SwitchboardWormholeOperation reply = {};
      return neuron.readWormholeOperationReply(reply) && reply.containerID == 0x00a1b2c3 &&
             reply.status == expectedStatus &&
             reply.revision.equal("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv) &&
             reply.desired.size() == 0;
    };

    neuron.prepareBrainReplyBuffer();
    auto heldSuccess = neuron.prepareWormholeOperationReply(operation());
    suite.expect(neuron.replyBufferEmpty(), "neuron_wormhole_reply_pending_callback_appends_no_reply_before_receipt");
    heldSuccess(true);
    suite.expect(isExactReply(SwitchboardWormholeOperationStatus::applied),
                 "neuron_wormhole_reply_success_sends_one_applied_exact_id_revision_empty_desired");

    neuron.prepareBrainReplyBuffer();
    auto heldFailure = neuron.prepareWormholeOperationReply(operation());
    heldFailure(false);
    suite.expect(isExactReply(SwitchboardWormholeOperationStatus::rollbackFailed),
                 "neuron_wormhole_reply_failure_sends_rollback_failed_not_applied");

    neuron.prepareBrainReplyBuffer();
    auto replaced = neuron.prepareWormholeOperationReply(operation());
    neuron.replaceBrainWithoutClosing();
    neuron.prepareBrainReplyBuffer();
    replaced(true);
    suite.expect(neuron.replyBufferEmpty(), "neuron_wormhole_reply_replaced_brain_suppresses_late_append");

    neuron.prepareBrainReplyBuffer();
    auto changedGeneration = neuron.prepareWormholeOperationReply(operation());
    neuron.advanceBrainGenerationForReplyTest();
    changedGeneration(true);
    suite.expect(neuron.replyBufferEmpty(), "neuron_wormhole_reply_generation_change_suppresses_late_append");

    neuron.prepareBrainReplyBuffer();
    auto inactive = neuron.prepareWormholeOperationReply(operation());
    neuron.deactivateBrainForReplyTest();
    inactive(true);
    suite.expect(neuron.replyBufferEmpty(), "neuron_wormhole_reply_inactive_stream_suppresses_late_append");
    neuron.reactivateBrainForReplyTest();

    neuron.prepareBrainReplyBuffer();
    auto expiredLifetime = neuron.prepareWormholeOperationReply(operation());
    neuron.expireReplyLifetimeForTest();
    expiredLifetime(true);
    suite.expect(neuron.replyBufferEmpty(), "neuron_wormhole_reply_expired_lifetime_suppresses_late_append");

    // The late callback retains the old weak lifetime. Restore a fresh owner
    // and a neutral stream before optional artifact cases use this fixture.
    neuron.restoreReplyLifetimeForTest();
    neuron.prepareBrainForArtifactTest();

    auto localContainer = std::make_unique<Container>();
    localContainer->fd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    localContainer->plan.uuid = uint128_t(0x00c0ffee);
    localContainer->plan.wormholes.emplace_back();
    localContainer->plan.wormholes.back().name.assign("current-wormhole"_ctv);
    localContainer->plan.wormholes.back().containerPort = 8443;
    localContainer->plan.wormholes.back().externalPort = 443;
    neuron.trackContainerForReplyTest(localContainer.get());
    String expectedWormholes = {};
    BitseryEngine::serialize(expectedWormholes, localContainer->plan.wormholes);

    neuron.prepareContainerReplyBuffer(localContainer.get());
    auto pendingRefresh = neuron.prepareWormholeContainerRefresh(localContainer.get());
    suite.expect(localContainer->wBuffer.size() == 0,
                 "neuron_wormhole_refresh_pending_callback_appends_no_container_frame_before_receipt");
    pendingRefresh(true);
    String receivedWormholes = {};
    suite.expect(neuron.readContainerWormholeRefresh(localContainer.get(), receivedWormholes) &&
                     receivedWormholes == expectedWormholes,
                 "neuron_wormhole_refresh_success_sends_exact_current_plan_serialization");

    neuron.prepareContainerReplyBuffer(localContainer.get());
    auto failedRefresh = neuron.prepareWormholeContainerRefresh(localContainer.get());
    failedRefresh(false);
    suite.expect(localContainer->wBuffer.size() == 0,
                 "neuron_wormhole_refresh_failed_receipt_suppresses_container_frame");

    neuron.prepareContainerReplyBuffer(localContainer.get());
    auto obsoleteContainer = neuron.prepareWormholeContainerRefresh(localContainer.get());
    neuron.untrackContainerForReplyTest(localContainer->plan.uuid);
    obsoleteContainer(true);
    suite.expect(localContainer->wBuffer.size() == 0,
                 "neuron_wormhole_refresh_obsolete_container_entry_suppresses_late_frame");
    neuron.trackContainerForReplyTest(localContainer.get());

    neuron.prepareContainerReplyBuffer(localContainer.get());
    auto changedContainerGeneration = neuron.prepareWormholeContainerRefresh(localContainer.get());
    ++localContainer->ioGeneration;
    changedContainerGeneration(true);
    suite.expect(localContainer->wBuffer.size() == 0,
                 "neuron_wormhole_refresh_container_generation_change_suppresses_late_frame");

    neuron.prepareContainerReplyBuffer(localContainer.get());
    auto pendingDestroy = neuron.prepareWormholeContainerRefresh(localContainer.get());
    localContainer->pendingDestroy = true;
    pendingDestroy(true);
    suite.expect(localContainer->wBuffer.size() == 0,
                 "neuron_wormhole_refresh_pending_destroy_suppresses_late_frame");
    localContainer->pendingDestroy = false;

    neuron.prepareContainerReplyBuffer(localContainer.get());
    auto replacedSourceBrain = neuron.prepareWormholeContainerRefresh(localContainer.get());
    neuron.replaceBrainWithoutClosing();
    replacedSourceBrain(true);
    suite.expect(localContainer->wBuffer.size() == 0,
                 "neuron_wormhole_refresh_replaced_source_brain_suppresses_late_frame");

    neuron.untrackContainerForReplyTest(localContainer->plan.uuid);
    if (localContainer->fd >= 0)
    {
      ::close(localContainer->fd);
      localContainer->fd = -1;
    }
    localContainer.reset();
    neuron.prepareBrainForArtifactTest();
    if (hasArtifactFixture)
    {
      constexpr uint64_t currentDeploymentID = 0xE71F01ULL;
      suite.expect(neuron.submit(currentDeploymentID, fixture.substr(0, fixture.size(), Copy::yes)),
                   "neuron_artifact_queues_current_stream_fixture");
      runRingUntil(ring, [&] { return neuron.artifactFinished(); });
      suite.expect(ring.timedOut == false && neuron.stored(currentDeploymentID, fixture),
                   "neuron_artifact_current_stream_prepares_publishes_and_adopts_fixture");
      suite.expect(neuron.artifactFinished() && neuron.lastArtifactAdopted && neuron.lastArtifactSourceCurrent,
                   "neuron_artifact_current_stream_completes_on_ring_after_durable_adoption");

      constexpr uint64_t staleDeploymentID = 0xE71F02ULL;
      ring.timedOut = false;
      neuron.artifactFinishes = 0;
      neuron.retainPendingDownload(staleDeploymentID);
      suite.expect(neuron.submit(staleDeploymentID, fixture.substr(0, fixture.size(), Copy::yes)),
                   "neuron_artifact_queues_stale_stream_fixture");
      neuron.replaceBrainWithoutClosing();
      runRingUntil(ring, [&] { return neuron.artifactFinished(); });
      suite.expect(ring.timedOut == false && neuron.stored(staleDeploymentID, fixture) == false &&
                       neuron.lastArtifactAdopted == false && neuron.lastArtifactSourceCurrent == false,
                   "neuron_artifact_stale_incarnation_suppresses_publish_and_adoption");
      suite.expect(neuron.hasPendingDownload(staleDeploymentID),
                   "neuron_artifact_replacement_retains_download_for_existing_reconnect_replay");
      suite.expect(neuron.replacementQueuesPendingDownload(staleDeploymentID),
                   "neuron_artifact_replacement_requeues_retained_download_on_accepted_control_stream");
    }
  }

  ring.timedOut = false;
  runRingUntil(ring, [&] { return neuron.quiesceArtifactIOForTest(); });
  suite.expect(ring.timedOut == false, "neuron_artifact_raw_poll_retired_before_ring_shutdown");
  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
