#include <prodigy/prodigy.h>
#include <prodigy/neuron.hub.h>
#include <prodigy/brain/brain.h>
#include <prodigy/persistent.writer.h>

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
  dprintf(1, "ASYNC_AUTHORITY_RESULT failed_scenarios=%d\n", failed);
  return failed ? 1 : 0;
}
