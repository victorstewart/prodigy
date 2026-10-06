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
  bool shutdown = false;
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
    shutdownRing();
    Ring::interfacer = nullptr;
    Ring::lifecycler = nullptr;
    RingDispatcher::dispatcher = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;
  }
  void shutdownRing()
  {
    if (shutdown == false)
    {
      Ring::shutdownForExec();
      shutdown = true;
    }
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

class SwitchboardRingTestAccess {
public:
  static const local_container_subnet6& subnet(const Switchboard& board)
  {
    return board.subnet;
  }
  static void setBoundaryConsumer(Switchboard& board, BPFProgram *router, EthDevice *ingress)
  {
    board.bpf_router = router;
    board.additionalIngressEth = ingress;
  }

  static bool hasAdditionalIngress(const Switchboard& board)
  {
    return board.additionalIngressEth != nullptr;
  }

  static bool retainedAdditionalIngressWitnessMatches(uint32_t witnessedProgramID,
                                                      uint32_t candidateProgramID,
                                                      uint32_t candidateMapCount,
                                                      uint32_t candidateType,
                                                      const char *candidateName,
                                                      uint8_t candidateTag)
  {
    Switchboard::RetainedAdditionalIngressXDPWitness witness = {};
    witness.programID = witnessedProgramID;
    witness.mapCount = candidateMapCount;
    witness.valid = true;
    memset(witness.tag, candidateTag, sizeof(witness.tag));

    struct bpf_prog_info info = {};
    info.id = candidateProgramID;
    info.type = candidateType;
    info.nr_map_ids = candidateMapCount;
    strncpy(reinterpret_cast<char *>(info.name), candidateName, BPF_OBJ_NAME_LEN - 1);
    memset(info.tag, candidateTag, sizeof(info.tag));
    return Switchboard::retainedAdditionalIngressProgramInfoMatches(witness, candidateProgramID, info);
  }

  static bool retainedAdditionalIngressMatchesCurrentFamily(uint32_t candidateProgramID,
                                                            uint32_t currentProgramID,
                                                            uint32_t candidateMapCount,
                                                            uint8_t candidateTag,
                                                            uint8_t currentTag)
  {
    struct bpf_prog_info candidate = {};
    candidate.id = candidateProgramID;
    candidate.type = BPF_PROG_TYPE_XDP;
    candidate.nr_map_ids = candidateMapCount;
    strncpy(reinterpret_cast<char *>(candidate.name), "bal_ingress", BPF_OBJ_NAME_LEN - 1);
    memset(candidate.tag, candidateTag, sizeof(candidate.tag));
    struct bpf_prog_info current = {};
    current.id = currentProgramID;
    current.type = BPF_PROG_TYPE_XDP;
    current.nr_map_ids = candidateMapCount;
    strncpy(reinterpret_cast<char *>(current.name), "bal_ingress", BPF_OBJ_NAME_LEN - 1);
    memset(current.tag, currentTag, sizeof(current.tag));
    return Switchboard::retainedAdditionalIngressProgramMatchesCurrentFamily(candidateProgramID, candidate, current);
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
  std::function<void(bool)> pendingRestoreCompletion = {};
  uint32_t restoreSubmissions = 0;
  uint32_t publishedContainers = 0;
  std::vector<std::unique_ptr<Container>> publishedContainerOwners = {};

  ProdigyHostTask<bool> restoreStateUploadNetworkAsync(
      Container *, CoroutineStack *, String *, std::function<bool()> current) override
  {
    co_return co_await ProdigyHostCompletion<bool>([this, current = std::move(current)](std::function<void(bool)> complete) mutable {
      restoreSubmissions += 1;
      pendingRestoreCompletion = [current = std::move(current), complete = std::move(complete)](bool value) mutable {
        complete(current() && value);
      };
    });
  }

  bool beginStateUploadRestoreForTest(std::unique_ptr<Container> container, uint64_t epoch)
  {
    (void)epoch;
    return beginStateUploadRestore(std::move(container), currentStateUploadRestoreRound());
  }

  bool admitRestoreReplayForTest(const ContainerPlan& plan)
  {
    return admitRepeatedStateUploadRestore(plan, {}, currentStateUploadRestoreRound());
  }
  bool restoreBarrierPendingForTest() const { return stateUploadRestoresPending(); }
  void fenceCurrentRestoreControlForTest() { fenceStateUploadRestoresForControl(brain); }
  void assignFragmentForLazySwitchboardTest(uint8_t datacenter, uint8_t machine0, uint8_t machine1, uint8_t machine2)
  {
    lcsubnet6.dpfx = datacenter;
    lcsubnet6.mpfx[0] = machine0;
    lcsubnet6.mpfx[1] = machine1;
    lcsubnet6.mpfx[2] = machine2;
  }
  Switchboard *createLazySwitchboardForTest() { return ensureSwitchboard(); }

  bool pendingStateUploadRestoreForTest(uint128_t uuid) const
  {
    return isPendingContainerLaunch(uuid);
  }

  bool retainedCandidatePreservedForTest(uint128_t uuid, pid_t pid) const
  {
    auto found = pendingStateUploadRestores.find(uuid);
    return found != pendingStateUploadRestores.end() && found->second != nullptr &&
           found->second->settled && found->second->container != nullptr &&
           found->second->container->pendingDestroy == false && found->second->container->pid == pid &&
           isPendingContainerLaunch(uuid);
  }

  String containerArtifactStoreRoot(void) const override { return root; }
  void receivedContainerArtifactFinished(uint64_t, bool adopted, bool sourceCurrent) override
  {
    ++artifactFinishes;
    lastArtifactAdopted = adopted;
    lastArtifactSourceCurrent = sourceCurrent;
  }
  void pushContainer(Container *container) override
  {
    ++publishedContainers;
    publishedContainerOwners.emplace_back(container);
  }
  void popContainer(Container *) override {}
  void downloadContainer(CoroutineStack *, uint64_t) override {}
  bool ensureHostNetworkingReady(String *failure = nullptr) override
  {
    if (failure) failure->clear();
    return true;
  }

  void releasePublishedContainersAfterRingShutdownForTest()
  {
    publishedContainerOwners.clear();
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

  bool buildContainerWormholeDesiredStateForTest(const ContainerPlan& plan,
                                                 const Vector<Wormhole>& wormholes,
                                                 SwitchboardWormholeDesiredState& desired)
  {
    return buildContainerWormholeDesiredState(plan, wormholes, desired);
  }

  bool strengthenWormholeDesiredStateForLocalPlanForTest(const ContainerPlan& plan,
                                                         SwitchboardWormholeDesiredState& desired)
  {
    return strengthenWormholeDesiredStateForLocalPlan(plan, desired);
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
  suite.expect(
      SwitchboardRingTestAccess::retainedAdditionalIngressWitnessMatches(
          10713, 10713, 12, BPF_PROG_TYPE_XDP, "bal_ingress", 0x5a),
      "neuron_retained_additional_ingress_accepts_exact_preexec_primary_xdp");
  suite.expect(
      SwitchboardRingTestAccess::retainedAdditionalIngressWitnessMatches(
          10713, 10923, 12, BPF_PROG_TYPE_XDP, "bal_ingress", 0x5a) == false,
      "neuron_retained_additional_ingress_rejects_reconnected_or_replaced_xdp");
  suite.expect(
      SwitchboardRingTestAccess::retainedAdditionalIngressWitnessMatches(
          10713, 10713, 12, BPF_PROG_TYPE_XDP, "foreign_xdp", 0x5a) == false,
      "neuron_retained_additional_ingress_rejects_unknown_xdp");
  suite.expect(
      SwitchboardRingTestAccess::retainedAdditionalIngressMatchesCurrentFamily(10713, 10923, 12, 0x5a, 0x5a),
      "neuron_retained_additional_ingress_accepts_orphaned_prior_family_after_exec");
  suite.expect(
      SwitchboardRingTestAccess::retainedAdditionalIngressMatchesCurrentFamily(10713, 10923, 12, 0x5a, 0x6b) == false,
      "neuron_retained_additional_ingress_rejects_foreign_compiled_family");
  {
    ArtifactRing lazySwitchboardRing = {};
    TestNeuron lazySwitchboardNeuron = {};
    lazySwitchboardNeuron.assignFragmentForLazySwitchboardTest(9, 4, 5, 6);
    Switchboard *lazySwitchboard = lazySwitchboardNeuron.createLazySwitchboardForTest();
    const local_container_subnet6& seeded = SwitchboardRingTestAccess::subnet(*lazySwitchboard);
    suite.expect(lazySwitchboard != nullptr && seeded.dpfx == 9 && seeded.mpfx[0] == 4 &&
                     seeded.mpfx[1] == 5 && seeded.mpfx[2] == 6,
                 "neuron_lazy_switchboard_receives_existing_fragment_before_optional_ingress");
    BPFProgram retainedRouter = {};
    EthDevice selectedIngress = {};
    SwitchboardRingTestAccess::setBoundaryConsumer(*lazySwitchboard, &retainedRouter, &selectedIngress);
    lazySwitchboard->resetState();
    suite.expect(lazySwitchboard->boundaryRouterProgram() == &retainedRouter,
                 "switchboard_reset_preserves_router_used_by_selected_ingress");
    SwitchboardRingTestAccess::setBoundaryConsumer(*lazySwitchboard, &retainedRouter, nullptr);
    lazySwitchboard->resetState();
    suite.expect(lazySwitchboard->boundaryRouterProgram() == nullptr,
                 "switchboard_reset_releases_router_without_remaining_consumers");
    SwitchboardRingTestAccess::setBoundaryConsumer(*lazySwitchboard, &retainedRouter, &selectedIngress);
    lazySwitchboardNeuron.detachAdditionalIngressForShutdown();
    suite.expect(SwitchboardRingTestAccess::hasAdditionalIngress(*lazySwitchboard) == false,
                 "neuron_shutdown_detaches_additional_ingress_before_guardian_exit");
    lazySwitchboardNeuron.detachAdditionalIngressForShutdown();
    suite.expect(SwitchboardRingTestAccess::hasAdditionalIngress(*lazySwitchboard) == false,
                 "neuron_shutdown_additional_ingress_detach_is_idempotent");
  }
  String fixture = {};
  const bool hasArtifactFixture = loadFixture(fixture);
  if (!hasArtifactFixture)
  {
    suite.expect(false, "neuron_artifact_fixture_requires_PRODIGY_TEST_APP_ARTIFACT");
  }

  ScopedArtifactStore store = {};
  suite.expect(store.root.size() > 0, "neuron_artifact_private_store_created");

  {
    TestNeuron restoreNeuron = {};
    auto first = std::make_unique<Container>();
    first->plan.uuid = uint128_t(0xA5510001);
    first->plan.fragment = 1;
    suite.expect(restoreNeuron.beginStateUploadRestoreForTest(std::move(first), 7) &&
                     restoreNeuron.restoreSubmissions == 1 &&
                     restoreNeuron.pendingStateUploadRestoreForTest(uint128_t(0xA5510001)),
                 "neuron_state_upload_restore_admission_retains_uuid_until_async_completion");

    auto duplicate = std::make_unique<Container>();
    duplicate->plan.uuid = uint128_t(0xA5510001);
    duplicate->plan.fragment = 1;
    suite.expect(restoreNeuron.beginStateUploadRestoreForTest(std::move(duplicate), 7) == false &&
                     restoreNeuron.restoreSubmissions == 1,
                 "neuron_state_upload_restore_duplicate_uuid_does_not_start_second_operation");

    suite.expect(bool(restoreNeuron.pendingRestoreCompletion),
                 "neuron_state_upload_restore_test_completion_is_held");
    restoreNeuron.pendingRestoreCompletion(true);
    suite.expect(restoreNeuron.pendingStateUploadRestoreForTest(uint128_t(0xA5510001)),
                 "neuron_state_upload_restore_stale_completion_preserves_retained_candidate");
  }
  {
    // A successful retry reaches the normal publication tail, which queues
    // retained-process observation on Ring even though this test does not run
    // the queued I/O.
    ArtifactRing restoreRing = {};
    TestNeuron failedRestore = {};
    failedRestore.replaceBrainWithoutClosing();
    auto candidate = std::make_unique<Container>();
    candidate->plan.uuid = uint128_t(0xA5510005);
    candidate->plan.fragment = 1;
    candidate->plan.restartOnFailure = true;
    // Keep this synthetic candidate outside process supervision: no real PID
    // can be observed if the publication path later acquires a pidfd seam.
    candidate->pid = -1;
    candidate->retainedPidfdWaitabilityFailed = true;
    ContainerPlan replay = candidate->plan;
    suite.expect(failedRestore.beginStateUploadRestoreForTest(std::move(candidate), 11) &&
                     bool(failedRestore.pendingRestoreCompletion),
                 "neuron_state_upload_restore_failure_admits_retained_candidate");
    auto failed = std::exchange(failedRestore.pendingRestoreCompletion, {});
    failed(false);
    suite.expect(failedRestore.restoreSubmissions == 1 && !failedRestore.restoreBarrierPendingForTest() &&
                     failedRestore.publishedContainers == 0 &&
                     failedRestore.retainedCandidatePreservedForTest(replay.uuid, -1),
                 "neuron_state_upload_restore_failure_preserves_live_process_and_launch_fence");
    suite.expect(failedRestore.admitRestoreReplayForTest(replay) &&
                     failedRestore.restoreSubmissions == 2 && failedRestore.restoreBarrierPendingForTest(),
                 "neuron_state_upload_restore_failure_retries_only_after_matching_authoritative_upload");
    auto succeeded = std::exchange(failedRestore.pendingRestoreCompletion, {});
    succeeded(true);
    suite.expect(failedRestore.publishedContainers == 1 &&
                     !failedRestore.pendingStateUploadRestoreForTest(replay.uuid),
                 "neuron_state_upload_restore_successful_retry_publishes_once");
    // The publication tail can leave Ring operations holding the raw wrapper.
    // Keep test ownership through Ring teardown, then release it explicitly.
    restoreRing.shutdownRing();
    failedRestore.releasePublishedContainersAfterRingShutdownForTest();
  }
  {
    TestNeuron replacementNeuron = {};
    replacementNeuron.replaceBrainWithoutClosing();
    auto candidate = std::make_unique<Container>();
    candidate->plan.uuid = uint128_t(0xA5510003);
    candidate->plan.fragment = 1;
    ContainerPlan replay = candidate->plan;
    suite.expect(replacementNeuron.beginStateUploadRestoreForTest(std::move(candidate), 9),
                 "neuron_state_upload_restore_replacement_admits_candidate");
    replacementNeuron.replaceBrainWithoutClosing();
    suite.expect(replacementNeuron.admitRestoreReplayForTest(replay),
                 "neuron_state_upload_restore_replacement_admits_exact_authoritative_plan");
    auto obsolete = std::exchange(replacementNeuron.pendingRestoreCompletion, {});
    obsolete(true);
    suite.expect(replacementNeuron.restoreSubmissions == 2 && bool(replacementNeuron.pendingRestoreCompletion) &&
                     replacementNeuron.restoreBarrierPendingForTest(),
                 "neuron_state_upload_restore_replacement_retries_without_releasing_reply_barrier");
    // A second replacement without a new state-upload request cannot silently
    // adopt the old request. It settles without publication or another retry.
    replacementNeuron.replaceBrainWithoutClosing();
    auto unrequested = std::exchange(replacementNeuron.pendingRestoreCompletion, {});
    unrequested(true);
    suite.expect(replacementNeuron.restoreSubmissions == 2 && !replacementNeuron.restoreBarrierPendingForTest() &&
                     replacementNeuron.pendingStateUploadRestoreForTest(replay.uuid),
                 "neuron_state_upload_restore_replacement_without_upload_cannot_authorize_retry");
    ContainerPlan divergent = replay;
    divergent.fragment += 1;
    suite.expect(!replacementNeuron.admitRestoreReplayForTest(divergent) && replacementNeuron.restoreSubmissions == 2,
                 "neuron_state_upload_restore_divergent_plan_cannot_resume_retained_candidate");
    suite.expect(replacementNeuron.admitRestoreReplayForTest(replay) && replacementNeuron.restoreSubmissions == 3 &&
                     replacementNeuron.restoreBarrierPendingForTest(),
                 "neuron_state_upload_restore_settled_candidate_resumes_only_after_matching_upload");
  }
  {
    TestNeuron retiredIdentity = {};
    retiredIdentity.replaceBrainWithoutClosing();
    auto candidate = std::make_unique<Container>();
    candidate->plan.uuid = uint128_t(0xA5510004);
    candidate->plan.fragment = 1;
    suite.expect(retiredIdentity.beginStateUploadRestoreForTest(std::move(candidate), 10),
                 "neuron_state_upload_restore_identity_fence_admits_candidate");
    retiredIdentity.fenceCurrentRestoreControlForTest();
    // Keep the exact pointer and numeric socket generation visible, as they
    // could be after allocator reuse. The retirement fence must still win.
    auto completion = std::exchange(retiredIdentity.pendingRestoreCompletion, {});
    completion(true);
    suite.expect(retiredIdentity.restoreSubmissions == 1 && !retiredIdentity.restoreBarrierPendingForTest() &&
                     retiredIdentity.pendingStateUploadRestoreForTest(uint128_t(0xA5510004)),
                 "neuron_state_upload_restore_retired_control_identity_cannot_authorize_completion");
  }
  {
    std::function<void(bool)> lateCompletion = {};
    {
      TestNeuron shutdownNeuron = {};
      auto candidate = std::make_unique<Container>();
      candidate->plan.uuid = uint128_t(0xA5510002);
      candidate->plan.fragment = 1;
      suite.expect(shutdownNeuron.beginStateUploadRestoreForTest(std::move(candidate), 8),
                   "neuron_state_upload_restore_shutdown_admits_owned_runner");
      lateCompletion = shutdownNeuron.pendingRestoreCompletion;
    }
    // The destroyed runner has detached its HostCompletion. A terminal
    // callback after Neuron destruction must be inert.
    if (lateCompletion) lateCompletion(true);
    suite.expect(bool(lateCompletion), "neuron_state_upload_restore_shutdown_late_completion_is_inert");
  }
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

    {
      const uint64_t cousinService = MeshServices::constrainPrefixToGroup(
          MeshServices::generateStatefulService(17, 3), 0);
      ContainerPlan protectedPlan = {};
      protectedPlan.isStateful = true;
      protectedPlan.statefulMeshRoles.cousin = cousinService;
      protectedPlan.advertisements.emplace(
          cousinService,
          Advertisement(cousinService, ContainerState::healthy, ContainerState::destroying, 8443));

      Wormhole direct = {};
      direct.name.assign("cousin-public"_ctv);
      direct.externalAddress = IPAddress("2001:db8::44", true);
      direct.externalPort = 443;
      direct.containerPort = 8443;
      direct.layer4 = IPPROTO_TCP;
      Vector<Wormhole> directWormholes = {direct};

      SwitchboardWormholeDesiredState localDesired = {};
      suite.expect(neuron.buildContainerWormholeDesiredStateForTest(protectedPlan, directWormholes, localDesired) &&
                       prodigyWormholeRequiresPairAdmission(localDesired, 8443, IPPROTO_TCP),
                   "neuron_wormhole_startup_derives_cousin_protection_from_plan_definition");

      SwitchboardWormholeDesiredState legacyFleet = {};
      legacyFleet.wormholes = directWormholes;
      String rawFleetBytes = {};
      suite.expect(prodigyEncodeWormholeDesiredState(legacyFleet, rawFleetBytes),
                   "neuron_wormhole_fleet_raw_state_has_canonical_legacy_bytes");
      suite.expect(neuron.strengthenWormholeDesiredStateForLocalPlanForTest(protectedPlan, legacyFleet) &&
                       prodigyWormholeRequiresPairAdmission(legacyFleet, 8443, IPPROTO_TCP),
                   "neuron_wormhole_fleet_legacy_state_is_strengthened_by_tracked_local_plan");
      String strengthenedFleetBytes = {};
      suite.expect(prodigyEncodeWormholeDesiredState(legacyFleet, strengthenedFleetBytes) &&
                       strengthenedFleetBytes.equals(rawFleetBytes) == false,
                   "neuron_wormhole_fleet_strengthening_requires_retry_with_protected_revision");

      Wormhole separatelyProtected = direct;
      separatelyProtected.name.assign("already-protected"_ctv);
      separatelyProtected.externalAddress = IPAddress("2001:db8::45", true);
      separatelyProtected.externalPort = 444;
      separatelyProtected.containerPort = 9443;
      legacyFleet = {};
      legacyFleet.wormholes = {direct, separatelyProtected};
      legacyFleet.pairAdmissionTCPPorts = {9443};
      suite.expect(neuron.strengthenWormholeDesiredStateForLocalPlanForTest(protectedPlan, legacyFleet) &&
                       legacyFleet.pairAdmissionTCPPorts.size() == 2 &&
                       legacyFleet.pairAdmissionTCPPorts[0] == 8443 && legacyFleet.pairAdmissionTCPPorts[1] == 9443,
                   "neuron_wormhole_local_protection_never_downgrades_live_fleet_profile");

      protectedPlan.advertisements.emplace(
          cousinService + 1,
          Advertisement(cousinService + 1, ContainerState::healthy, ContainerState::destroying, 8443));
      legacyFleet = {};
      legacyFleet.wormholes = directWormholes;
      suite.expect(!neuron.strengthenWormholeDesiredStateForLocalPlanForTest(protectedPlan, legacyFleet) &&
                       legacyFleet.pairAdmissionTCPPorts.empty(),
                   "neuron_wormhole_ambiguous_cousin_definition_rejects_before_switchboard_open");
    }
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
