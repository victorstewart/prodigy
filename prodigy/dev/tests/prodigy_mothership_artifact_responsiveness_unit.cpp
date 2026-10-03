#include <includes.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/message.h>
#include <networking/multiplexer.h>
#include <networking/ring.h>
#include <networking/time.h>
#include <prodigy/brain/brain.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

class TestSuite {
public:
  int failed = 0;

  void expect(bool value, const char *name)
  {
    if (value == false)
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
    char pattern[] = ".run/prodigy-mothership-artifact-XXXXXX";
    if (char *created = ::mkdtemp(pattern)) root.assign(created);
  }

  ~ScopedArtifactStore()
  {
    if (root.size())
    {
      std::error_code ignored;
      std::filesystem::remove_all(root.c_str(), ignored);
    }
  }
};

class ArtifactTestRing final : public TimeoutDispatcher {
public:
  RingDispatcher dispatcher;
  TimeoutPacket sample = {};
  TimeoutPacket deadline = {};
  TimeoutPacket quiesceRetry = {};
  TimeoutPacket quiesceDeadline = {};
  uint32_t samples = 0;
  uint32_t samplesWhileBlocked = 0;
  std::atomic<bool> *workerFinished = nullptr;
  std::function<void()> sampleAction = {};
  ProdigyArtifactIO *quiescingArtifactIO = nullptr;
  bool timedOut = false;
  bool quiesceTimedOut = false;
  bool quiesced = false;

  ArtifactTestRing()
  {
    Ring::interfacer = &dispatcher;
    Ring::lifecycler = &dispatcher;
    Ring::exit = false;
    Ring::shuttingDown = false;
    Ring::createRing(64, 128, 8, 2, -1, -1, 8);
    sample.dispatcher = this;
    deadline.dispatcher = this;
    quiesceRetry.dispatcher = this;
    quiesceDeadline.dispatcher = this;
  }

  ~ArtifactTestRing()
  {
    Ring::shutdownForExec();
    Ring::interfacer = nullptr;
    Ring::lifecycler = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;
    RingDispatcher::dispatcher = nullptr;
  }

  void arm(TimeoutPacket& packet, uint64_t ms)
  {
    packet.clear();
    packet.setTimeoutMs(ms);
    Ring::queueTimeout(&packet);
  }

  void dispatchTimeout(TimeoutPacket *packet) override
  {
    if (packet == &sample)
    {
      ++samples;
      if (workerFinished != nullptr && workerFinished->load() == false) ++samplesWhileBlocked;
      if (sampleAction) sampleAction();
      if (Ring::exit) return;
      if (samples < 30) arm(sample, 5);
      return;
    }
    if (packet == &deadline)
    {
      timedOut = true;
      Ring::exit = true;
    }
    if (packet == &quiesceRetry)
    {
      if (quiescingArtifactIO != nullptr && quiescingArtifactIO->quiesceForExec())
      {
        quiesced = true;
        Ring::exit = true;
      }
      else if (quiesceTimedOut == false)
      {
        arm(quiesceRetry, 1);
      }
    }
    if (packet == &quiesceDeadline)
    {
      quiesceTimedOut = true;
      Ring::exit = true;
    }
  }

  bool quiesceArtifactIO(ProdigyArtifactIO& io)
  {
    quiescingArtifactIO = &io;
    quiesced = false;
    quiesceTimedOut = false;
    arm(quiesceRetry, 1);
    arm(quiesceDeadline, 500);
    Ring::exit = false;
    Ring::start();
    Ring::exit = false;
    quiescingArtifactIO = nullptr;
    return quiesced && quiesceTimedOut == false;
  }
};

class ScopedUnixSocketPair final {
public:
  int local = -1;
  int remote = -1;

  bool create()
  {
    int pair[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) != 0) return false;
    local = pair[0];
    remote = pair[1];
    return true;
  }

  ~ScopedUnixSocketPair()
  {
    if (local >= 0) ::close(local);
    if (remote >= 0) ::close(remote);
  }
};

class ArtifactTestNeuron final : public NeuronBase {
public:
  String installedDigest = {};

  void pushContainer(Container *) override {}
  void popContainer(Container *) override {}
  bool ensureHostNetworkingReady(String *) override { return true; }
  void downloadContainer(CoroutineStack *, uint64_t) override {}
  const String *readyInstalledBundleDigest(void) const override
  {
    return installedDigest.empty() ? nullptr : &installedDigest;
  }
};

class ArtifactTestBrain final : public Brain {
public:
  String testStoreRoot = {};
  String testBundleStagePath = {};
  uint32_t persistCalls = 0;
  uint32_t transitionToNewBundleCalls = 0;

  const String *containerArtifactStoreRoot() const override
  {
    return &testStoreRoot;
  }

  String mothershipStagedBundlePath() const override
  {
    return testBundleStagePath;
  }

  bool persistLocalRuntimeState() override
  {
    ++persistCalls;
    return true;
  }

  void transitionToNewBundle(void) override { ++transitionToNewBundleCalls; }

  void pushSpinApplicationProgressToMothership(ApplicationDeployment *, const String&) override {}
  void spinApplicationFailed(ApplicationDeployment *, const String&) override {}
};

static Message *buildMothershipMessage(String& output, MothershipTopic topic, uint16_t applicationID, const String& serializedPlan, const String& blob)
{
  output.clear();
  Message::construct(output, topic, applicationID, serializedPlan, blob);
  return reinterpret_cast<Message *>(output.data());
}

static void seedPlan(DeploymentPlan& plan, uint16_t applicationID)
{
  plan.config.applicationID = applicationID;
  plan.config.versionID = 1;
  plan.config.nLogicalCores = 1;
  plan.config.memoryMB = 64;
  plan.config.filesystemMB = 64;
  plan.config.storageMB = 64;
  plan.canaryCount = 1;
  plan.stateless.nBase = 1;
  plan.stateless.maxPerRackRatio = 1.0f;
  plan.stateless.maxPerMachineRatio = 1.0f;
  plan.hasApiCredentialPolicy = true;
  plan.apiCredentialPolicy.applicationID = applicationID;
}

static bool loadDiscombobulatorFixture(String& blob)
{
  const char *path = ::getenv("PRODIGY_TEST_APP_ARTIFACT");
  if (path == nullptr || path[0] == '\0') return false;
  Filesystem::openReadAtClose(-1, String(path), blob);
  String header = {};
  String headerText = prodigyDiscombobulatorBlobHeaderText();
  header.assign(blob.substr(0, headerText.size(), Copy::yes));
  String failure = {};
  return blob.size() > headerText.size() &&
         prodigyValidateDiscombobulatorBlobHeaderText(header, &failure);
}

static bool storeContains(const String& root, uint64_t deploymentID)
{
  struct stat metadata = {};
  String path = ContainerStore::pathForContainerImage(deploymentID, &root);
  return ::stat(path.c_str(), &metadata) == 0;
}

static void testBlockedArtifactWorkerDoesNotBlockRingOrAdmitStaleRequest(TestSuite& suite)
{
  String blob = {};
  if (loadDiscombobulatorFixture(blob) == false)
  {
    suite.expect(false, "mothership_artifact_responsiveness_requires_PRODIGY_TEST_APP_ARTIFACT");
    return;
  }

  ScopedArtifactStore store = {};
  suite.expect(store.root.size() > 0, "mothership_artifact_private_store_created");
  if (store.root.size() == 0) return;

  ArtifactTestRing ring = {};
  ArtifactTestBrain brain = {};
  brain.testStoreRoot.assign(store.root);
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.ignited = true;
  brain.persistedMachineInventoryEnumerated = true;

  ScopedUnixSocketPair sockets = {};
  suite.expect(sockets.create(), "mothership_artifact_stale_socket_pair_created");
  if (sockets.local < 0) return;
  Mothership mothership = {};
  mothership.fd = sockets.local;
  mothership.isFixedFile = false;
  sockets.local = -1;
  suite.expect(brain.activateMothershipConnection(&mothership), "mothership_artifact_activates_stream_incarnation");

  constexpr uint16_t applicationID = 61'901;
  DeploymentPlan plan = {};
  seedPlan(plan, applicationID);
  String reservationFailure = {};
  suite.expect(brain.reserveApplicationIDMapping("ArtifactResponsiveness"_ctv, applicationID, &reservationFailure),
               "mothership_artifact_reserves_application_before_request");
  String serializedPlan = {};
  BitseryEngine::serialize(serializedPlan, plan);
  String request = {};
  Message *message = buildMothershipMessage(request, MothershipTopic::spinApplication, applicationID, serializedPlan, blob);

  FailedDeploymentRecord failed = {};
  brain.failedDeployments.insert_or_assign(plan.config.deploymentID(), failed);
  suite.expect(brain.ensureArtifactIO(), "mothership_artifact_starts_shared_worker");
  if (brain.artifactIO == nullptr) return;

  std::atomic<bool> blockerEntered = false;
  std::atomic<bool> blockerFinished = false;
  suite.expect(brain.artifactIO->submit(
                   1,
                   [&] {
                     blockerEntered = true;
                     std::this_thread::sleep_for(std::chrono::milliseconds(250));
                     blockerFinished = true;
                   },
                   [] {},
                   [](std::exception_ptr) {}),
               "mothership_artifact_queues_blocking_prior_worker_job");

  brain.mothershipHandler(&mothership, message);
  suite.expect(brain.pendingMothershipSpinArtifacts.contains(plan.config.deploymentID()),
               "mothership_artifact_keeps_request_pending_before_worker_receipt");
  suite.expect(brain.failedDeployments.contains(plan.config.deploymentID()),
               "mothership_artifact_preserves_durable_failed_record_before_publication");
  suite.expect(brain.deployments.contains(plan.config.deploymentID()) == false,
               "mothership_artifact_does_not_admit_before_worker_receipt");

  // The original stream incarnation is no longer authoritative before the
  // queued stage reaches the Ring.  It must produce neither an ACK nor launch.
  mothership.connectionIncarnation += 1;
  ring.workerFinished = &blockerFinished;
  ring.arm(ring.sample, 5);
  ring.arm(ring.deadline, 1'200);
  Ring::start();

  suite.expect(blockerEntered && blockerFinished && ring.samples >= 30 && ring.samplesWhileBlocked >= 30 && ring.timedOut,
               "mothership_artifact_blocked_worker_leaves_ring_timer_responsive");
  suite.expect(brain.pendingMothershipSpinArtifacts.contains(plan.config.deploymentID()) == false,
               "mothership_artifact_stale_incarnation_retires_pending_operation");
  suite.expect(mothership.wBuffer.empty() && brain.deployments.contains(plan.config.deploymentID()) == false,
               "mothership_artifact_stale_incarnation_suppresses_ack_and_launch");
  suite.expect(brain.failedDeployments.contains(plan.config.deploymentID()) &&
                   storeContains(store.root, plan.config.deploymentID()) == false,
               "mothership_artifact_stale_completion_preserves_admission_record_and_cleans_private_store");
  suite.expect(ring.quiesceArtifactIO(*brain.artifactIO), "mothership_artifact_quiesces_raw_poll_before_ring_teardown");
  if (ring.quiesced) brain.artifactIO.reset();
  brain.activeMotherships.erase(&mothership);
  mothership.fd = -1;
}

static void testAuthorityEpochChangeSuppressesPreparedArtifactAdmission(TestSuite& suite)
{
  String blob = {};
  if (loadDiscombobulatorFixture(blob) == false) return;

  ScopedArtifactStore store = {};
  if (store.root.size() == 0) return;
  ArtifactTestRing ring = {};
  ArtifactTestBrain brain = {};
  brain.testStoreRoot.assign(store.root);
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.ignited = true;
  brain.persistedMachineInventoryEnumerated = true;

  ScopedUnixSocketPair sockets = {};
  suite.expect(sockets.create(), "mothership_artifact_epoch_socket_pair_created");
  if (sockets.local < 0) return;
  Mothership mothership = {};
  mothership.fd = sockets.local;
  mothership.isFixedFile = false;
  sockets.local = -1;
  suite.expect(brain.activateMothershipConnection(&mothership), "mothership_artifact_epoch_activates_stream");

  constexpr uint16_t applicationID = 61'902;
  DeploymentPlan plan = {};
  seedPlan(plan, applicationID);
  String failure = {};
  suite.expect(brain.reserveApplicationIDMapping("ArtifactEpoch"_ctv, applicationID, &failure),
               "mothership_artifact_epoch_reserves_application");
  String serializedPlan = {};
  BitseryEngine::serialize(serializedPlan, plan);
  String request = {};
  brain.mothershipHandler(
      &mothership,
      buildMothershipMessage(request, MothershipTopic::spinApplication, applicationID, serializedPlan, blob));
  suite.expect(brain.pendingMothershipSpinArtifacts.contains(plan.config.deploymentID()),
               "mothership_artifact_epoch_request_is_pending_before_epoch_change");

  ++brain.masterAuthorityEpoch;
  ring.arm(ring.deadline, 700);
  Ring::start();

  suite.expect(brain.pendingMothershipSpinArtifacts.contains(plan.config.deploymentID()) == false &&
                   mothership.wBuffer.empty() && brain.deployments.contains(plan.config.deploymentID()) == false,
               "mothership_artifact_epoch_change_suppresses_publication_ack_and_launch");
  suite.expect(storeContains(store.root, plan.config.deploymentID()) == false,
               "mothership_artifact_epoch_change_cleans_unadopted_private_artifact");
  suite.expect(ring.quiesceArtifactIO(*brain.artifactIO), "mothership_artifact_quiesces_raw_poll_before_ring_teardown");
  if (ring.quiesced) brain.artifactIO.reset();
  brain.activeMotherships.erase(&mothership);
  mothership.fd = -1;
}

static void testCurrentArtifactPublishesAfterDurableAdmissionAndReplies(TestSuite& suite)
{
  String blob = {};
  if (loadDiscombobulatorFixture(blob) == false) return;

  ScopedArtifactStore store = {};
  if (store.root.size() == 0) return;
  ArtifactTestRing ring = {};
  ArtifactTestBrain brain = {};
  brain.testStoreRoot.assign(store.root);
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.ignited = true;
  brain.persistedMachineInventoryEnumerated = true;
  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  ScopedUnixSocketPair sockets = {};
  suite.expect(sockets.create(), "mothership_artifact_current_socket_pair_created");
  if (sockets.local < 0)
  {
    thisBrain = previousBrain;
    return;
  }
  Mothership mothership = {};
  mothership.fd = sockets.local;
  mothership.isFixedFile = false;
  sockets.local = -1;
  suite.expect(brain.activateMothershipConnection(&mothership), "mothership_artifact_current_activates_stream");
  RingDispatcher::installMultiplexee(&mothership, &brain);

  constexpr uint16_t applicationID = 61'903;
  DeploymentPlan plan = {};
  seedPlan(plan, applicationID);
  String failure = {};
  suite.expect(brain.reserveApplicationIDMapping("ArtifactCurrent"_ctv, applicationID, &failure),
               "mothership_artifact_current_reserves_application");
  String serializedPlan = {};
  BitseryEngine::serialize(serializedPlan, plan);
  String request = {};
  brain.mothershipHandler(
      &mothership,
      buildMothershipMessage(request, MothershipTopic::spinApplication, applicationID, serializedPlan, blob));
  suite.expect(brain.pendingMothershipSpinArtifacts.contains(plan.config.deploymentID()),
               "mothership_artifact_current_waits_for_worker_receipt_before_ack");

  String response = {};
  ring.sampleAction = [&] {
    uint8_t bytes[4096] = {};
    for (;;)
    {
      ssize_t received = ::recv(sockets.remote, bytes, sizeof(bytes), 0);
      if (received > 0)
      {
        response.append(bytes, uint64_t(received));
        continue;
      }
      break;
    }
    if (response.size() > 0) Ring::exit = true;
  };
  ring.arm(ring.sample, 5);
  ring.arm(ring.deadline, 1'200);
  Ring::start();

  SpinApplicationResponseCode responseCode = SpinApplicationResponseCode::invalidPlan;
  if (response.size() >= sizeof(Message))
  {
    Message *frame = reinterpret_cast<Message *>(response.data());
    if (MothershipTopic(frame->topic) == MothershipTopic::spinApplication)
    {
      uint8_t *args = frame->args;
      uint8_t raw = uint8_t(SpinApplicationResponseCode::invalidPlan);
      Message::extractArg<ArgumentNature::fixed>(args, raw);
      responseCode = SpinApplicationResponseCode(raw);
    }
  }
  suite.expect(ring.timedOut == false && responseCode == SpinApplicationResponseCode::okay,
               "mothership_artifact_current_replies_only_after_publish_and_durable_admission");
  suite.expect(brain.pendingMothershipSpinArtifacts.contains(plan.config.deploymentID()) == false &&
                   brain.deployments.contains(plan.config.deploymentID()) &&
                   storeContains(store.root, plan.config.deploymentID()),
               "mothership_artifact_current_adopts_exact_artifact_before_launch");
  suite.expect(ring.quiesceArtifactIO(*brain.artifactIO), "mothership_artifact_quiesces_raw_poll_before_ring_teardown");
  if (ring.quiesced) brain.artifactIO.reset();
  RingDispatcher::eraseMultiplexee(&mothership);
  brain.activeMotherships.erase(&mothership);
  mothership.fd = -1;
  thisBrain = previousBrain;
}

static void testLegacyAndAdmittedStaleUpdateArtifactFences(TestSuite& suite)
{
  ScopedArtifactStore store = {};
  suite.expect(store.root.size() > 0, "mothership_update_artifact_legacy_private_stage_root_created");
  if (store.root.size() == 0) return;
  ArtifactTestRing ring = {};
  ArtifactTestBrain brain = {};
  ArtifactTestNeuron localNeuron = {};
  localNeuron.uuid = uint128_t(0xA771);
  String sourceDigest = {};
  for (uint32_t index = 0; index < 64; ++index) sourceDigest.append('a');
  localNeuron.installedDigest.assign(sourceDigest);
  NeuronBase *previousNeuron = thisNeuron;
  thisNeuron = &localNeuron;
  brain.testBundleStagePath.assign(store.root);
  brain.testBundleStagePath.append("/bundle.tar.zst"_ctv);
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.nBrains = 1;
  brain.boottimens = 77;
  brain.brainConfig.clusterUUID = uint128_t(0xA772);
  brain.masterAuthorityRuntimeState.generation = 13;
  brain.masterAuthorityRuntimeStateDurable = true;
  brain.durableMasterAuthorityRuntimeStateGeneration = 13;
  Machine localMachine = {};
  localMachine.uuid = localNeuron.uuid;
  localMachine.isThisMachine = true;
  localMachine.isBrain = true;
  localMachine.state = MachineState::healthy;
  localMachine.runtimeReady = true;
  brain.machines.insert(&localMachine);
  brain.machinesByUUID.insert_or_assign(localMachine.uuid, &localMachine);
  brain.persistedMachineInventoryUploaded.insert(localMachine.uuid);
  brain.persistedMachineStateUploadPlansByMachine.insert_or_assign(localMachine.uuid, Vector<String>{});

  ScopedUnixSocketPair sockets = {};
  suite.expect(sockets.create(), "mothership_update_artifact_legacy_socket_pair_created");
  if (sockets.local < 0)
  {
    brain.machinesByUUID.erase(localMachine.uuid);
    brain.machines.erase(&localMachine);
    thisNeuron = previousNeuron;
    return;
  }
  Mothership mothership = {};
  mothership.fd = sockets.local;
  mothership.isFixedFile = false;
  sockets.local = -1;
  brain.mothership = &mothership;
  suite.expect(brain.activateMothershipConnection(&mothership), "mothership_update_artifact_legacy_activates_stream");
  if (brain.activeMotherships.contains(&mothership) == false)
  {
    brain.machinesByUUID.erase(localMachine.uuid);
    brain.machines.erase(&localMachine);
    thisNeuron = previousNeuron;
    return;
  }
  RingDispatcher::installMultiplexee(&mothership, &brain);
  String request = {};
  String bundle = "unit-update-artifact"_ctv;
  Message::construct(request, MothershipTopic::updateProdigy, bundle);
  brain.mothershipHandler(&mothership, reinterpret_cast<Message *>(request.data()));
  MothershipResponse response = {};
  bool rejected = false;
  if (mothership.wBuffer.size() >= sizeof(Message))
  {
    Message *frame = reinterpret_cast<Message *>(mothership.wBuffer.data());
    String serialized = {};
    uint8_t *args = frame->args;
    Message::extractToStringView(args, serialized);
    rejected = MothershipTopic(frame->topic) == MothershipTopic::updateProdigy &&
        args == frame->terminal() && BitseryEngine::deserializeSafe(serialized, response) &&
        !response.success && response.failure == "legacy updateProdigy is not an admission path"_ctv;
  }
  struct stat metadata = {};
  suite.expect(rejected && brain.pendingMothershipUpdateArtifact == nullptr &&
                   ::stat(brain.testBundleStagePath.c_str(), &metadata) != 0,
               "mothership_update_artifact_legacy_request_rejects_before_stage_or_transition");

  String target = "unit-admitted-update-artifact"_ctv;
  String targetDigest = {}, hashFailure = {}, contractDigest = {};
  suite.expect(prodigyComputeSHA256Hex(target, targetDigest, &hashFailure),
               "mothership_update_artifact_admitted_hashes_target");
  for (uint32_t index = 0; index < 64; ++index) contractDigest.append('b');
  ProdigyUpgradeAdmissionReportRequest capacityRequest = {};
  capacityRequest.operationID.assignItoh(uint128_t(1));
  capacityRequest.targetBundleSHA256.assign(targetDigest);
  capacityRequest.targetContractSHA256.assign(contractDigest);
  capacityRequest.requiredStagingBytes = 1;
  auto& observation = brain.upgradeAdmissionObservation;
  observation.receiptVersion = 1;
  observation.authorityGeneration = brain.masterAuthorityRuntimeState.generation;
  observation.nonce = 1;
  observation.requestedAtMs = Time::msSinceBoot();
  observation.capacityRequest = capacityRequest;
  observation.localCapacityMeasurementComplete = true;
  observation.localCapacityVerified = true;
  observation.localCapacityAvailableBytes = capacityRequest.requiredStagingBytes;
  MothershipUpgradeAdmissionReport report = {};
  brain.collectUpgradeAdmissionReport(report);
  suite.expect(report.observationComplete && report.stagingCapacityComplete &&
                   report.masterApprovedBundleSHA256 == sourceDigest,
               "mothership_update_artifact_admitted_fixture_has_fresh_complete_observation");
  ProdigyAdmittedUpdateRequest admitted = {};
  admitted.operationID.assign(capacityRequest.operationID);
  admitted.sourceBundleSHA256.assign(sourceDigest);
  admitted.targetBundleSHA256.assign(targetDigest);
  admitted.targetContractSHA256.assign(contractDigest);
  admitted.requiredStagingBytes = capacityRequest.requiredStagingBytes;
  admitted.authorityGeneration = report.authorityGeneration;
  admitted.masterUUID = report.masterUUID;
  admitted.masterBootNs = report.masterBootNs;
  admitted.receiptVersion = report.observationReceiptVersion;
  admitted.nonce = report.observationNonce;

  suite.expect(brain.ensureArtifactIO(), "mothership_update_artifact_admitted_starts_shared_worker");
  std::atomic<bool> blockerFinished = false;
  suite.expect(brain.artifactIO != nullptr && brain.artifactIO->submit(
                   1,
                   [&] { std::this_thread::sleep_for(std::chrono::milliseconds(180)); blockerFinished = true; },
                   [] {},
                   [](std::exception_ptr) {}),
               "mothership_update_artifact_admitted_queues_blocker");
  String serialized = {}, admittedFrame = {};
  BitseryEngine::serialize(serialized, admitted);
  Message::construct(admittedFrame, MothershipTopic::updateProdigyAdmitted, serialized, target);
  mothership.wBuffer.clear();
  brain.mothershipHandler(&mothership, reinterpret_cast<Message *>(admittedFrame.data()));
  suite.expect(brain.pendingMothershipUpdateArtifact != nullptr && mothership.wBuffer.empty(),
               "mothership_update_artifact_admitted_request_pending_before_epoch_change");
  ++brain.masterAuthorityEpoch;
  ring.workerFinished = &blockerFinished;
  ring.arm(ring.sample, 5);
  ring.arm(ring.deadline, 1'000);
  Ring::start();
  suite.expect(brain.pendingMothershipUpdateArtifact == nullptr && mothership.wBuffer.empty() &&
                   ::stat(brain.testBundleStagePath.c_str(), &metadata) != 0 &&
                   brain.transitionToNewBundleCalls == 0,
               "mothership_update_artifact_admitted_stale_epoch_suppresses_publish_ack_and_transition");
  suite.expect(ring.samplesWhileBlocked >= 20,
               "mothership_update_artifact_admitted_worker_keeps_ring_responsive");
  suite.expect(brain.artifactIO != nullptr && ring.quiesceArtifactIO(*brain.artifactIO),
               "mothership_update_artifact_admitted_quiesces_shared_worker");
  if (ring.quiesced) brain.artifactIO.reset();
  RingDispatcher::eraseMultiplexee(&mothership);
  brain.activeMotherships.erase(&mothership);
  mothership.fd = -1;
  brain.machinesByUUID.erase(localMachine.uuid);
  brain.machines.erase(&localMachine);
  thisNeuron = previousNeuron;
}

int main()
{
  TestSuite suite = {};
  testBlockedArtifactWorkerDoesNotBlockRingOrAdmitStaleRequest(suite);
  testAuthorityEpochChangeSuppressesPreparedArtifactAdmission(suite);
  testCurrentArtifactPublishesAfterDurableAdmissionAndReplies(suite);
  testLegacyAndAdmittedStaleUpdateArtifactFences(suite);
  return suite.failed == 0 ? 0 : 1;
}
