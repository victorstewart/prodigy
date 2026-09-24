#include <cstdint>
#include <time.h>

// Change only this fixture's wall-clock reads. Kernel Ring deadlines and the
// host/guest clocks remain untouched, so a clock correction is deterministic.
static int64_t peerTestRealtimeOffsetSeconds = 0;
static int peerTestClockGettime(clockid_t clock, struct timespec *value) noexcept
{
  const int result = ::clock_gettime(clock, value);
  if (result == 0 && clock == CLOCK_REALTIME) value->tv_sec += peerTestRealtimeOffsetSeconds;
  return result;
}
#define clock_gettime peerTestClockGettime
#include <prodigy/prodigy.h>
#include <prodigy/neuron.hub.h>
#include <prodigy/brain/brain.h>
#include <prodigy/persistent.writer.h>
#undef clock_gettime

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <thread>
#include <vector>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

using Clock = std::chrono::steady_clock;
static uint64_t micros(Clock::duration duration)
{
  return std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
}
class Suite {
public:
  int failed = 0;
  void expect(bool ok, const char *name)
  {
    dprintf(ok ? STDOUT_FILENO : STDERR_FILENO, "%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failed;
  }
};

class TestRing final : public TimeoutDispatcher {
public:
  RingDispatcher dispatcher;
  TimeoutPacket tick = {}, deadline = {}, drain = {};
  std::function<void()> onTick;
  bool timedOut = false;
  TestRing()
  {
    Ring::interfacer = &dispatcher; Ring::lifecycler = &dispatcher;
    Ring::exit = false; Ring::shuttingDown = false;
    Ring::createRing(64, 128, 8, 2, -1, -1, 8);
    tick.dispatcher = deadline.dispatcher = drain.dispatcher = this;
  }
  void arm(TimeoutPacket& packet, uint64_t ms)
  {
    packet.clear(); packet.setTimeoutMs(ms); Ring::queueTimeout(&packet);
  }
  void dispatchTimeout(TimeoutPacket *packet) override
  {
    if (packet == &tick && onTick) onTick();
    if (packet == &deadline) { timedOut = true; Ring::exit = true; }
    if (packet == &drain) Ring::exit = true;
  }
  void drainStoppedIO()
  {
    onTick = {}; arm(drain, 25); Ring::exit = false; Ring::start();
  }
  void shutdown()
  {
    Ring::shutdownForExec();
  }
  ~TestRing()
  {
    // Peer cleanup still uses the dispatcher after kernel Ring teardown.
    Ring::interfacer = nullptr; Ring::lifecycler = nullptr;
    RingDispatcher::dispatcher = nullptr;
  }
};

class LocalNeuron final : public NeuronBase {
public:
  void pushContainer(Container *) override {}
  void popContainer(Container *) override {}
  bool ensureHostNetworkingReady(String *) override { return false; }
  void downloadContainer(CoroutineStack *, uint64_t) override {}
};

enum class Scenario { success, snapshotFailure, bootFailure, epochChange, reusedConnection, ownershipFailure, ownershipEpochChange };
static const char *scenarioName(Scenario scenario)
{
  switch (scenario) {
    case Scenario::success: return "success";
    case Scenario::snapshotFailure: return "snapshot-failure";
    case Scenario::bootFailure: return "boot-failure";
    case Scenario::epochChange: return "authority-epoch-change";
    case Scenario::reusedConnection: return "disconnected-reused-connection";
    case Scenario::ownershipFailure: return "ownership-failure";
    case Scenario::ownershipEpochChange: return "ownership-epoch-change";
  }
  return "invalid";
}

class AsyncAuthorityBrain final : public Brain {
public:
  ProdigyPersistentStateWriter *writer = nullptr;
  std::atomic<bool> ownershipDurable = false, snapshotDurable = false, bootDurable = false;
  uint32_t applied = 0, claimCalls = 0, candidateCalls = 0, completions = 0;
  bool effectBeforeDurability = false;

  void respinApplication(ApplicationDeployment *) override {}
  void pushSpinApplicationProgressToMothership(ApplicationDeployment *, const String&) override {}
  void spinApplicationFailed(ApplicationDeployment *, const String&) override {}
  void spinApplicationFin(ApplicationDeployment *) override {}
  void onMasterAuthorityRuntimeStateApplied() override
  {
    ++applied;
    effectBeforeDurability |= !ownershipDurable || !snapshotDurable || !bootDurable;
  }
  bool usesAsyncMasterAuthorityPersistence() const override { return true; }
  bool claimLocalClusterOwnershipAsync(uint128_t clusterUUID, std::function<void(bool)> completion) override
  {
    ++claimCalls;
    ProdigyPersistentLocalBrainState local;
    local.uuid = selfBrainUUID(); local.ownerClusterUUID = clusterUUID;
    return writer->submitLocalBrainState(std::move(local), 4 * sizeof(local) + 4096,
        [this, completion = std::move(completion)](auto&& result) mutable {
          completion(result.durable); ++completions;
        });
  }
  bool persistMasterAuthorityTransitionCandidate(const ProdigyMasterAuthorityStateTransition& candidate,
                                                 std::function<void(bool)> completion) override
  {
    ++candidateCalls;
    effectBeforeDurability |= !ownershipDurable;
    ProdigyPersistentBrainSnapshot snapshot;
    snapshot.brainConfig = candidate.brainConfig;
    snapshot.masterAuthority.runtimeState = candidate.runtimeState;
    // This tiny fixture has one empty machine witness, no artifacts or secrets.
    const uint64_t retainedBytes = 4 * sizeof(snapshot) + 4 * sizeof(ProdigyPersistentBootState) + 65536;
    return writer->submitSnapshot(std::move(snapshot), {}, retainedBytes,
        [this, completion = std::move(completion)](auto&& result) mutable {
          completion(result.durable && result.snapshotDurable && result.bootStateDurable); ++completions;
        });
  }
  void persistLocalRuntimeStateAsync(PersistenceCompletion completion = {}) override
  {
    // Exercise the production master receipt shape: master changes snapshot the
    // current authority state before the writer can acknowledge it.
    ProdigyPersistentBrainSnapshot snapshot = {};
    snapshot.brainConfig = brainConfig;
    snapshot.masterAuthority.runtimeState = masterAuthorityRuntimeState;
    const uint64_t retainedBytes = 4 * sizeof(snapshot) + 4 * sizeof(ProdigyPersistentBootState) + 65536;
    const bool admitted = writer->submitSnapshot(std::move(snapshot), {}, retainedBytes,
        [completion](auto&& result) mutable {
          if (completion) completion(result.durable && result.snapshotDurable && result.bootStateDurable);
        });
    if (!admitted && completion) completion(false);
  }
};

// Both endpoints use the production framing parser, including partial/coalesced
// reads. The Ring endpoint is dispatched by Brain::recvHandler/sendHandler.
class PeerFixture {
public:
  BrainView peer, received;
  int fds[2] = {-1, -1};
  bool open(Brain& brain, uint128_t uuid, bool master)
  {
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds) != 0) return false;
    peer.fd = fds[0]; peer.fslot = Ring::adoptProcessFDIntoFixedFileSlot(fds[0], false);
    if (peer.fslot < 0) return false;
    peer.isFixedFile = true; peer.connected = true; peer.registrationFresh = true;
    peer.uuid = uuid; peer.boottimens = 1; peer.isMasterBrain = master;
    peer.existingMasterUUID = master ? uuid : uint128_t(0xCA11);
    brain.brains.insert(&peer);
    RingDispatcher::installMultiplexee(&peer, &brain);
    Ring::queueRecv(&peer);
    return true;
  }
  bool send(const String& frame)
  {
    return ::send(fds[1], frame.data(), frame.size(), MSG_NOSIGNAL) == ssize_t(frame.size());
  }
  template <typename Handler> bool read(Handler&& handler)
  {
    for (;;)
    {
      const ssize_t count = ::recv(fds[1], received.rBuffer.pTail(), received.rBuffer.remainingCapacity(), MSG_DONTWAIT);
      if (count < 0) return errno == EAGAIN || errno == EWOULDBLOCK;
      if (count == 0) return false;
      received.rBuffer.advance(count);
      bool failed = false;
      received.extractMessages<Message>([&](Message *message, bool&) { handler(message); },
          true, UINT32_MAX, 16, ProdigyWire::maxControlFrameBytes, failed);
      if (failed) return false;
    }
  }
  void closeAfterRingShutdown(Brain& brain)
  {
    brain.brains.erase(&peer); RingDispatcher::eraseMultiplexee(&peer);
    if (fds[0] >= 0) ::close(fds[0]);
    if (fds[1] >= 0) ::close(fds[1]);
  }
};

static int runScenario(Scenario scenario)
{
  Suite suite;
  dprintf(STDOUT_FILENO, "SCENARIO: %s\n", scenarioName(scenario));
  std::filesystem::create_directories(".run");
  char scratch[] = ".run/prodigy-brain-async-authority-XXXXXX";
  char *created = ::mkdtemp(scratch);
  suite.expect(created != nullptr, "private_store_created");
  if (!created) return 1;
  String path; path.assign(created);
  TestRing ring;
  ProdigyPersistentStateStore store(path);
  auto io = ProdigyArtifactIO::startOwned();
  suite.expect(io != nullptr, "artifact_worker_started");
  if (!io) return 1;
  LocalNeuron neuron; neuron.uuid = 0xF011; thisNeuron = &neuron;
  AsyncAuthorityBrain brain;
  brain.boottimens = 5; brain.noMasterYet = false; brain.brainConfig.clusterUUID = 0x42;
  const bool holdOwnership = scenario == Scenario::ownershipFailure || scenario == Scenario::ownershipEpochChange;
  std::atomic<bool> entered = false, release = false;
  std::atomic<uint64_t> actualHoldUs = 0;
  ProdigyPersistentStateWriter writer(store, *io, [&](auto& stateStore, auto& request) {
    if (request.writeLocalState == holdOwnership)
    {
      const auto started = Clock::now(); entered = true;
      // A bounded injected storage stall. The Ring releases it after 250 ms;
      // the deadline also prevents a broken fixture from stranding teardown.
      while (!release && Clock::now() - started < std::chrono::seconds(3))
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      actualHoldUs = micros(Clock::now() - started);
    }
    if (request.writeLocalState)
    {
      if (scenario == Scenario::ownershipFailure) { request.result.failure.assign("injected ownership write failure"_ctv); return; }
      request.result.durable = stateStore.saveLocalBrainState(request.localState, &request.result.failure);
      brain.ownershipDurable = request.result.durable;
      return;
    }
    if (scenario == Scenario::snapshotFailure) { request.result.failure.assign("injected snapshot write failure"_ctv); return; }
    if (!stateStore.saveBrainSnapshot(request.snapshot, &request.result.failure)) return;
    request.result.snapshotDurable = true; request.result.durable = true; brain.snapshotDurable = true;
    if (scenario == Scenario::bootFailure) { request.result.failure.assign("injected boot write failure"_ctv); return; }
    request.result.bootStateDurable = stateStore.saveBootState(request.bootState, &request.result.failure);
    brain.bootDurable = request.result.bootStateDurable;
  });
  brain.writer = &writer;
  PeerFixture authority, control;
  suite.expect(authority.open(brain, 0xCA11, true) && control.open(brain, 0xCA12, false), "ring_peer_connections_open");
  ProdigyMasterAuthorityStateTransition transition;
  transition.brainConfig.clusterUUID = 0x42; transition.runtimeState.generation = 1;
  ProdigyPersistentUpdateSelfMachineRecoveryWitness witness;
  witness.machineUUID = 0x99;
  transition.runtimeState.updateSelf.machineRecoveryWitnesses.push_back(witness);
  String serialized, expectedDigest, inbound;
  BitseryEngine::serialize(serialized, transition);
  prodigyComputeSHA256Hex(serialized, expectedDigest);
  Message::construct(inbound, BrainTopic::replicateMasterAuthorityState, serialized);
  suite.expect(authority.send(inbound), "replication_frame_sent_over_socket");

  const bool succeeds = scenario == Scenario::success;
  std::vector<uint64_t> heartbeatUs, timerUs;
  uint32_t acknowledgments = 0, blockedTicks = 0, heartbeatsDuringHold = 0;
  uint64_t pendingNonce = 0;
  bool earlyEffect = false, injected = false, wireValid = true, heldStarted = false, settled = false;
  auto heldAt = Clock::now(), heartbeatAt = heldAt, lastTick = heldAt, settledAt = heldAt;
  ring.onTick = [&] {
    const auto now = Clock::now();
    if (entered && !heldStarted) { heldStarted = true; heldAt = now; lastTick = now; }
    wireValid &= authority.read([&](Message *message) {
      if (BrainTopic(message->topic) != BrainTopic::replicateMasterAuthorityState) { wireValid = false; return; }
      uint8_t *args = message->args; String value;
      Message::extractToStringView(args, value);
      ProdigyMasterAuthorityStateTransitionAck ack;
      wireValid &= BitseryEngine::deserializeSafe(value, ack) && ack.generation == 1 &&
                   ack.peerUUID == neuron.uuid && ack.peerBootNs == brain.boottimens && ack.transitionDigest.equals(expectedDigest);
      ++acknowledgments;
      earlyEffect |= !brain.ownershipDurable || !brain.snapshotDurable || !brain.bootDurable || !brain.applied;
    });
    wireValid &= control.read([&](Message *message) {
      uint8_t *args = message->args; bool response = false; uint64_t nonce = 0;
      const bool valid = BrainTopic(message->topic) == BrainTopic::peerHeartbeat &&
          Message::extractArg<ArgumentNature::fixed>(args, response) && Message::extractArg<ArgumentNature::fixed>(args, nonce) &&
          response && pendingNonce != 0 && nonce == pendingNonce;
      wireValid &= valid;
      if (valid)
      {
        heartbeatUs.push_back(micros(now - heartbeatAt)); pendingNonce = 0;
        if (entered && !release) ++heartbeatsDuringHold;
      }
    });
    if (heldStarted && !release)
    {
      ++blockedTicks; timerUs.push_back(micros(now - lastTick)); lastTick = now;
      earlyEffect |= brain.applied != 0 || brain.masterAuthorityRuntimeStateDurable ||
          brain.masterAuthorityRuntimeState.generation != 0 || acknowledgments != 0 ||
          Brain::hasUpdateSelfRecoveryWitness(brain.capturePersistentUpdateSelfState());
      if (holdOwnership) earlyEffect |= brain.candidateCalls != 0;
      if (!injected)
      {
        if (scenario == Scenario::epochChange || scenario == Scenario::ownershipEpochChange) ++brain.masterAuthorityEpoch;
        if (scenario == Scenario::reusedConnection)
        {
          authority.peer.connected = false;
          ++authority.peer.ioGeneration; ++authority.peer.boottimens;
          authority.peer.connected = true; // same object and slot, new connection incarnation
        }
        injected = true;
      }
      if (heartbeatUs.size() < 30 && pendingNonce == 0)
      {
        String heartbeat; pendingNonce = heartbeatUs.size() + 1;
        Message::construct(heartbeat, BrainTopic::peerHeartbeat, false, pendingNonce);
        wireValid &= control.send(heartbeat); heartbeatAt = now;
      }
      if (now - heldAt >= std::chrono::milliseconds(250)) release = true;
    }
    if (release && !writer.hasPending() && !brain.pendingReplicatedMasterAuthorityTransition)
    {
      if (!settled) { settled = true; settledAt = now; }
      if (now - settledAt >= std::chrono::milliseconds(25)) { Ring::exit = true; return; }
    }
    ring.arm(ring.tick, 2);
  };
  ring.arm(ring.tick, 2); ring.arm(ring.deadline, 5000); Ring::start();
  release = true;
  suite.expect(!ring.timedOut && settled, "bounded_operation_completed");
  suite.expect(wireValid, "real_wire_frames_and_ack_identity_valid");
  suite.expect(actualHoldUs >= 250000 && blockedTicks >= 30, "disk_work_held_for_at_least_250ms");
  suite.expect(!earlyEffect && !brain.effectBeforeDurability, "no_ack_live_projection_or_recovery_hook_before_durability");
  const uint32_t expectedCandidates = holdOwnership ? 0 : 1;
  suite.expect(brain.claimCalls == 1 && brain.candidateCalls == expectedCandidates && brain.completions == 1 + expectedCandidates,
               "ownership_precedes_candidate_and_callbacks_complete");
  suite.expect(acknowledgments == (succeeds ? 1U : 0U) && brain.applied == (succeeds ? 1U : 0U) &&
                   brain.masterAuthorityRuntimeState.generation == (succeeds ? 1U : 0U) &&
                   brain.masterAuthorityRuntimeStateDurable == succeeds &&
                   Brain::hasUpdateSelfRecoveryWitness(brain.capturePersistentUpdateSelfState()) == succeeds,
               "only_current_fully_durable_transition_is_applied_and_acknowledged");
  auto percentile = [](std::vector<uint64_t> samples) -> uint64_t {
    if (samples.empty()) return 0;
    std::sort(samples.begin(), samples.end()); return samples[(samples.size() * 95 + 99) / 100 - 1];
  };
  const uint64_t maximum = heartbeatUs.empty() ? 0 : *std::max_element(heartbeatUs.begin(), heartbeatUs.end());
  suite.expect(heartbeatUs.size() == 30 && heartbeatsDuringHold == 30 && percentile(heartbeatUs) < 10000 && maximum < 50000,
               "thirty_heartbeats_progress_under_held_disk_work_p95_under_10ms_max_under_50ms");
  dprintf(1, "METRICS scenario=%s held_us=%llu heartbeat_n=%zu heartbeat_during_hold=%u heartbeat_p95_us=%llu heartbeat_max_us=%llu timer_n=%zu timer_p95_us=%llu ack=%u applied=%u\n",
      scenarioName(scenario), (unsigned long long)actualHoldUs.load(), heartbeatUs.size(), heartbeatsDuringHold,
      (unsigned long long)percentile(heartbeatUs), (unsigned long long)maximum, timerUs.size(),
      (unsigned long long)percentile(timerUs), acknowledgments, brain.applied);
  dprintf(1, "RAW_HEARTBEAT_US scenario=%s", scenarioName(scenario));
  for (auto value : heartbeatUs) dprintf(1, " %llu", (unsigned long long)value);
  dprintf(1, "\nRAW_TIMER_US scenario=%s", scenarioName(scenario));
  for (auto value : timerUs) dprintf(1, " %llu", (unsigned long long)value);
  dprintf(1, "\n");

  // Readback is deliberately after the sole store owner drains, and after a
  // close/reopen, so the assertion is against persisted records, not live fields.
  suite.expect(writer.drainForExec(), "writer_drained_before_store_readback");
  store.close();
  ProdigyPersistentBrainSnapshot recovered; String failure;
  const bool recoveredSnapshot = store.loadBrainSnapshot(recovered, &failure);
  const bool snapshotExpected = !holdOwnership && scenario != Scenario::snapshotFailure;
  suite.expect(recoveredSnapshot == snapshotExpected && (!recoveredSnapshot ||
      (recovered.masterAuthority.runtimeState.generation == 1 &&
       Brain::hasUpdateSelfRecoveryWitness(recovered.masterAuthority.runtimeState.updateSelf))), "snapshot_recovery_matches_actual_commit");
  ProdigyPersistentLocalBrainState recoveredLocal;
  failure.clear();
  const bool recoveredOwnership = store.loadLocalBrainState(recoveredLocal, &failure);
  suite.expect(recoveredOwnership == (scenario != Scenario::ownershipFailure) &&
      (!recoveredOwnership || (recoveredLocal.ownerClusterUUID == 0x42 && recoveredLocal.uuid == neuron.uuid)),
      "durable_cluster_ownership_survives_reopen");
  io->stop(); ring.drainStoppedIO(); ring.shutdown();
  authority.closeAfterRingShutdown(brain); control.closeAfterRingShutdown(brain);
  thisNeuron = nullptr; store.close();
  String secrets; resolveProdigyPersistentSecretsDBPath(path, secrets);
  std::error_code ignored;
  std::filesystem::remove_all(path.c_str(), ignored); std::filesystem::remove_all(secrets.c_str(), ignored);
  suite.expect(true, "fixture_store_worker_ring_and_peers_cleanly_stopped");
  return suite.failed ? 1 : 0;
}

class ClockProbeBrain final : public Brain {
public:
  BrainView *master = nullptr;
  bool masterClosed = false;
  void respinApplication(ApplicationDeployment *) override {}
  void pushSpinApplicationProgressToMothership(ApplicationDeployment *, const String&) override {}
  void spinApplicationFailed(ApplicationDeployment *, const String&) override {}
  void spinApplicationFin(ApplicationDeployment *) override {}
  void dispatchTimeout(TimeoutPacket *packet) override
  {
    Brain::dispatchTimeout(packet);
    if (master && master->queuedCloseTransportEpoch == master->transportEpoch)
    {
      masterClosed = true;
      // Stop before recovery changes the connection. The production close
      // decision is the observed failure, not an emulated test outcome.
      Ring::exit = true;
    }
  }
};

static int runHeartbeatClockStep(int64_t correctionSeconds, bool silenceMaster)
{
  Suite suite;
  TestRing ring;
  LocalNeuron neuron; neuron.uuid = 0xF013; thisNeuron = &neuron;
  ClockProbeBrain brain;
  brain.boottimens = 8; brain.noMasterYet = false; brain.nBrains = 3;
  brain.brainConfig.clusterUUID = 0x44;
  PeerFixture master, follower;
  suite.expect(master.open(brain, 0xCA21, true) && follower.open(brain, 0xCA22, false),
               "clock_step_real_ring_peers_open");
  master.peer.noteTransportActivated(); follower.peer.noteTransportActivated();
  brain.master = &master.peer;
  uint32_t masterProbes = 0, followerProbes = 0, liveMasterResponses = 0;
  bool corrected = false, wireValid = true, completedWindow = false;
  auto correctedAt = Clock::now(), lastMasterProbe = correctedAt;
  uint64_t remoteNonce = 0;
  ring.onTick = [&] {
    const auto now = Clock::now();
    auto readPeer = [&](PeerFixture& remote, uint32_t& probes, bool quiet) {
      return remote.read([&](Message *message) {
        uint8_t *args = message->args; bool response = false; uint64_t nonce = 0;
        if (BrainTopic(message->topic) != BrainTopic::peerHeartbeat ||
            !Message::extractArg<ArgumentNature::fixed>(args, response) ||
            !Message::extractArg<ArgumentNature::fixed>(args, nonce))
        { wireValid = false; return; }
        if (response) { ++liveMasterResponses; return; }
        ++probes;
        if (!quiet) {
          String echo; Message::construct(echo, BrainTopic::peerHeartbeat, true, nonce);
          wireValid &= remote.send(echo);
        }
      });
    };
    wireValid &= readPeer(master, masterProbes, corrected && silenceMaster);
    wireValid &= readPeer(follower, followerProbes, false);
    if (!corrected && master.peer.lastHeartbeatAckNonce > 0 && follower.peer.lastHeartbeatAckNonce > 0)
    {
      peerTestRealtimeOffsetSeconds = correctionSeconds;
      corrected = true; correctedAt = now; lastMasterProbe = now;
    }
    // A live master continues sending valid traffic after the correction.
    // This distinguishes false master loss from an actually silent endpoint.
    if (corrected && !silenceMaster && now - lastMasterProbe >= std::chrono::milliseconds(100))
    {
      String probe; Message::construct(probe, BrainTopic::peerHeartbeat, false, ++remoteNonce);
      wireValid &= master.send(probe); lastMasterProbe = now;
    }
    brain.runBrainPeerHeartbeatTick();
    if (corrected && now - correctedAt >= std::chrono::milliseconds(6200))
    { completedWindow = true; Ring::exit = true; return; }
    ring.arm(ring.tick, 10);
  };
  ring.arm(ring.tick, 1); ring.arm(ring.deadline, 8000); Ring::start();
  const uint64_t elapsedUs = micros(Clock::now() - correctedAt);
  peerTestRealtimeOffsetSeconds = 0;
  suite.expect(corrected && !ring.timedOut && wireValid, "clock_step_fixture_corrected_without_wire_errors");
  suite.expect(follower.peer.queuedCloseTransportEpoch == 0 && follower.peer.transportEpoch == 1,
               "clock_step_follower_pair_stays_open");
  if (silenceMaster)
  {
    suite.expect(brain.masterClosed && elapsedUs >= 4'900'000 && elapsedUs < 5'300'000,
                 "clock_step_silent_master_still_expires_at_five_seconds");
  }
  else
  {
    suite.expect(completedWindow && !brain.masterClosed && masterProbes >= 6 && liveMasterResponses >= 50,
                 "clock_step_live_master_keeps_probing_and_does_not_reconnect");
  }
  dprintf(1, "CLOCK_STEP seconds=%lld silent=%d master_probes=%u follower_probes=%u live_master_responses=%u elapsed_us=%llu master_close=%d\n",
          (long long)correctionSeconds, int(silenceMaster), masterProbes, followerProbes,
          liveMasterResponses, (unsigned long long)elapsedUs, int(brain.masterClosed));
  ring.onTick = {}; ring.shutdown();
  master.closeAfterRingShutdown(brain); follower.closeAfterRingShutdown(brain);
  thisNeuron = nullptr;
  return suite.failed ? 1 : 0;
}

static int runMasterAuthorityReplicationLoad()
{
  Suite suite;
  std::filesystem::create_directories(".run");
  char scratch[] = ".run/prodigy-brain-async-authority-master-XXXXXX";
  char *created = ::mkdtemp(scratch);
  suite.expect(created != nullptr, "master_replication_private_store_created");
  if (!created) return 1;
  String path; path.assign(created);
  TestRing ring;
  ProdigyPersistentStateStore store(path);
  auto io = ProdigyArtifactIO::startOwned();
  suite.expect(io != nullptr, "master_replication_artifact_worker_started");
  if (!io) return 1;
  LocalNeuron neuron; neuron.uuid = 0xF012; thisNeuron = &neuron;
  ProdigyPersistentStateWriter writer(store, *io);
  AsyncAuthorityBrain brain;
  brain.writer = &writer;
  brain.boottimens = 7;
  brain.noMasterYet = false;
  brain.weAreMaster = true;
  brain.nBrains = 2;
  brain.brainConfig.clusterUUID = 0x43;

  // Keep 13 live plans on the master and serialize corresponding public TLS
  // records. The synthetic PEM strings exercise authority serialization only;
  // this is not a deployed-plan or certificate-validation equivalent.
  std::vector<ApplicationDeployment *> deployments;
  for (uint16_t index = 0; index < 13; ++index)
  {
    auto *deployment = new ApplicationDeployment();
    deployment->plan.config.applicationID = uint16_t(50'000 + index);
    deployment->plan.config.versionID = 1;
    const uint64_t deploymentID = deployment->plan.config.deploymentID();
    brain.deployments.insert_or_assign(deploymentID, deployment);
    deployments.push_back(deployment);

    PublicTlsCertificateState certificate = {};
    certificate.spec.applicationID = deployment->plan.config.applicationID;
    certificate.spec.deploymentID = deploymentID;
    certificate.spec.wormholeName.assign("inbound"_ctv);
    certificate.spec.identityName.snprintf<"load-tls-{}"_ctv>(index);
    certificate.spec.domains.push_back("load.example.test"_ctv);
    certificate.identity.name = certificate.spec.identityName;
    certificate.identity.generation = 1;
    certificate.identity.certPem.assign("certificate-material-for-authority-replication-load"_ctv);
    certificate.identity.keyPem.assign("private-key-material-for-authority-replication-load"_ctv);
    certificate.identity.chainPem.assign("chain-material-for-authority-replication-load"_ctv);
    certificate.identity.dnsSans = certificate.spec.domains;
    certificate.generation = 1;
    brain.masterAuthorityRuntimeState.publicTlsCertificates.push_back(std::move(certificate));
  }

  PeerFixture peer;
  suite.expect(peer.open(brain, 0xCA13, false), "master_replication_ring_peer_open");
  std::vector<uint64_t> heartbeatUs, replicationUs;
  uint64_t pendingNonce = 0;
  uint32_t replicated = 0;
  bool wireValid = true, authorityMutationPending = false;
  auto heartbeatStarted = Clock::now();
  auto replicationStarted = heartbeatStarted;
  ring.onTick = [&] {
    const auto now = Clock::now();
    wireValid &= peer.read([&](Message *message) {
      uint8_t *args = message->args;
      if (BrainTopic(message->topic) == BrainTopic::peerHeartbeat)
      {
        bool response = false; uint64_t nonce = 0;
        const bool valid = Message::extractArg<ArgumentNature::fixed>(args, response) &&
                           Message::extractArg<ArgumentNature::fixed>(args, nonce) &&
                           response && nonce == pendingNonce;
        wireValid &= valid;
        if (valid) { heartbeatUs.push_back(micros(now - heartbeatStarted)); pendingNonce = 0; }
        return;
      }
      if (BrainTopic(message->topic) == BrainTopic::replicateMasterAuthorityState)
      {
        String serialized;
        Message::extractToStringView(args, serialized);
        ProdigyMasterAuthorityStateTransition transition = {};
        wireValid &= BitseryEngine::deserializeSafe(serialized, transition) &&
                     transition.runtimeState.publicTlsCertificates.size() == 13;
        replicationUs.push_back(micros(now - replicationStarted));
        ++replicated;
        authorityMutationPending = false;
      }
      else wireValid = false;
    });
    if (replicated < 30 && authorityMutationPending == false && writer.hasPending() == false)
    {
      replicationStarted = now;
      authorityMutationPending = true;
      brain.noteMasterAuthorityRuntimeStateChanged();
    }
    if (heartbeatUs.size() < 30 && pendingNonce == 0)
    {
      pendingNonce = heartbeatUs.size() + 1;
      String heartbeat;
      Message::construct(heartbeat, BrainTopic::peerHeartbeat, false, pendingNonce);
      wireValid &= peer.send(heartbeat);
      heartbeatStarted = now;
    }
    if (replicated >= 30 && heartbeatUs.size() >= 30 && writer.hasPending() == false) { Ring::exit = true; return; }
    ring.arm(ring.tick, 1);
  };
  ring.arm(ring.tick, 1); ring.arm(ring.deadline, 10'000); Ring::start();
  auto p95 = [](std::vector<uint64_t> samples) {
    std::sort(samples.begin(), samples.end());
    return samples.empty() ? uint64_t(0) : samples[(samples.size() * 95 + 99) / 100 - 1];
  };
  suite.expect(!ring.timedOut && replicated == 30 && heartbeatUs.size() == 30,
               "master_replication_thirty_authority_receipts_and_heartbeats_complete");
  suite.expect(wireValid && peer.peer.connected && peer.peer.queuedCloseTransportEpoch == 0 &&
                   peer.peer.processedCloseTransportEpoch == 0,
               "master_replication_keeps_peer_open_and_frames_valid");
  dprintf(1, "METRICS master_authority_replication deployments=13 public_tls=13 replication_n=%zu replication_p95_us=%llu heartbeat_n=%zu heartbeat_p95_us=%llu\n",
          replicationUs.size(), (unsigned long long)p95(replicationUs), heartbeatUs.size(),
          (unsigned long long)p95(heartbeatUs));
  dprintf(1, "RAW_MASTER_REPLICATION_US");
  for (uint64_t sample : replicationUs) dprintf(1, " %llu", (unsigned long long)sample);
  dprintf(1, "\nRAW_MASTER_HEARTBEAT_US");
  for (uint64_t sample : heartbeatUs) dprintf(1, " %llu", (unsigned long long)sample);
  dprintf(1, "\n");
  suite.expect(writer.drainForExec(), "master_replication_writer_drained");
  io->stop(); ring.drainStoppedIO(); ring.shutdown();
  peer.closeAfterRingShutdown(brain);
  for (ApplicationDeployment *deployment : deployments) delete deployment;
  brain.deployments.clear();
  thisNeuron = nullptr; store.close();
  String secrets; resolveProdigyPersistentSecretsDBPath(path, secrets);
  std::error_code ignored;
  std::filesystem::remove_all(path.c_str(), ignored); std::filesystem::remove_all(secrets.c_str(), ignored);
  return suite.failed ? 1 : 0;
}

int main()
{
  // Ring owns process-wide slots. Separate children give every case a fresh
  // Ring, Brain, writer failure latch, and private TidesDB directory.
  int failed = 0;
  for (Scenario scenario : {Scenario::success, Scenario::snapshotFailure, Scenario::bootFailure,
                           Scenario::epochChange, Scenario::reusedConnection,
                           Scenario::ownershipFailure, Scenario::ownershipEpochChange})
  {
    const pid_t child = ::fork();
    if (child == 0) ::_exit(runScenario(scenario));
    int status = 0;
    if (child < 0 || ::waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) ++failed;
  }
  for (auto [correction, quiet] : {std::pair<int64_t, bool>{-20, false}, {20, false}, {-20, true}})
  {
    const pid_t child = ::fork();
    if (child == 0) ::_exit(runHeartbeatClockStep(correction, quiet));
    int status = 0;
    if (child < 0 || ::waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) ++failed;
  }
  failed += runMasterAuthorityReplicationLoad() != 0;
  dprintf(1, "ASYNC_AUTHORITY_RESULT failed_scenarios=%d\n", failed);
  return failed ? 1 : 0;
}
