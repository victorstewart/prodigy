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

  ~TestNeuron()
  {
    // main() keeps this owner alive until quiesceForExec observes the terminal
    // raw-poll cancellation CQE. Do not destroy it beside Ring shutdown.
    if (artifactIO != nullptr) std::abort();
    if (brain && brain->fd >= 0) ::close(brain->fd);
    if (retained && retained->fd >= 0) ::close(retained->fd);
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
  if (!loadFixture(fixture))
  {
    dprintf(STDERR_FILENO, "SKIP: neuron artifact fixture requires PRODIGY_TEST_APP_ARTIFACT\n");
    return EXIT_SUCCESS;
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

  ring.timedOut = false;
  runRingUntil(ring, [&] { return neuron.quiesceArtifactIOForTest(); });
  suite.expect(ring.timedOut == false, "neuron_artifact_raw_poll_retired_before_ring_shutdown");
  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
