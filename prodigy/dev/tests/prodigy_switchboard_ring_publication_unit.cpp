#include <includes.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/message.h>
#include <networking/multiplexer.h>
#include <networking/ring.h>

#include <prodigy/artifact.io.h>
#include <prodigy/neuron/neuron.h>

#include <atomic>
#include <array>
#include <algorithm>
#include <cerrno>
#include <condition_variable>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>
#include <sys/eventfd.h>
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

static uint64_t timeoutCallbackSerial = 0;

class TestRingDispatcher final : public RingDispatcher {
public:
  void timeoutHandler(TimeoutPacket *packet, int result) override
  {
    ++timeoutCallbackSerial;
    RingDispatcher::timeoutHandler(packet, result);
  }
};

class TestRing final : public TimeoutDispatcher {
public:
  TestRingDispatcher dispatcher;
  TimeoutPacket tick = {};
  TimeoutPacket control = {};
  std::function<void()> tickAction = {};
  std::function<void()> controlAction = {};

  TestRing()
  {
    Ring::interfacer = &dispatcher;
    Ring::lifecycler = &dispatcher;
    Ring::exit = false;
    Ring::shuttingDown = false;
    Ring::createRing(64, 128, 8, 2, -1, -1, 8);
    tick.dispatcher = this;
    control.dispatcher = this;
  }

  ~TestRing()
  {
    Ring::shutdownForExec();
    Ring::interfacer = nullptr;
    Ring::lifecycler = nullptr;
    RingDispatcher::dispatcher = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;
  }

  void arm(TimeoutPacket& packet, uint64_t milliseconds)
  {
    packet.clear();
    packet.setTimeoutMs(milliseconds);
    Ring::queueTimeout(&packet);
  }

  void dispatchTimeout(TimeoutPacket *packet) override
  {
    if (packet == &tick && tickAction) tickAction();
    if (packet == &control && controlAction) controlAction();
  }

  bool runUntil(const std::function<bool()>& done, uint64_t timeoutMs = 1500)
  {
    bool timedOut = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    Ring::exit = false;
    tickAction = [&] {
      if (done())
      {
        Ring::exit = true;
        return;
      }
      if (std::chrono::steady_clock::now() >= deadline)
      {
        timedOut = true;
        Ring::exit = true;
        return;
      }
      arm(tick, 1);
    };
    arm(tick, 1);
    Ring::start();
    tickAction = {};
    Ring::exit = false;
    return !timedOut && done();
  }

  bool runUntilWithControl(const std::function<bool()>& done, std::vector<uint64_t>& controlIntervals,
                           uint64_t timeoutMs = 1500, const std::function<void()>& onControl = {})
  {
    bool timedOut = false;
    uint64_t previousControl = 0;
    const auto started = std::chrono::steady_clock::now();
    const auto deadline = started + std::chrono::milliseconds(timeoutMs);
    Ring::exit = false;
    controlAction = [&] {
      const uint64_t now = uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count());
      if (previousControl != 0) controlIntervals.push_back(now - previousControl);
      previousControl = now;
      if (onControl) onControl();
      if (!done() && std::chrono::steady_clock::now() < deadline) arm(control, 1);
    };
    tickAction = [&] {
      if (done())
      {
        Ring::exit = true;
        return;
      }
      if (std::chrono::steady_clock::now() >= deadline)
      {
        timedOut = true;
        Ring::exit = true;
        return;
      }
      arm(tick, 1);
    };
    arm(control, 1);
    arm(tick, 1);
    Ring::start();
    tickAction = {};
    controlAction = {};
    control.clear();
    Ring::exit = false;
    return !timedOut && done();
  }

};

struct FakeBPFKernel {
  static constexpr uint64_t quicSyscallCostUs = 50;
  uint64_t quicDelayUs = quicSyscallCostUs;
  struct Publication {
    int programFD = -1;
    uint32_t slot = 0;
    int innerFD = -1;
    container_id firstEntry = {};
    uint32_t updateCount = 0;
  };

  std::mutex mutex = {};
  std::condition_variable condition = {};
  bool holdInner = false;
  bool workerEntered = false;
  bool releaseInner = false;
  bool failInner = false;
  bool failOuter = false;
  bool failMetadata = false;
  bool failQuicLookup = false;
  bool failQuicUpdate = false;
  std::vector<int> createdInner = {};
  std::unordered_map<int, container_id> firstEntry = {};
  std::unordered_map<int, uint32_t> innerUpdates = {};
  std::vector<Publication> publications = {};

  struct QuicMap {
    uint32_t id = 0;
    std::array<quic_cid_aes_decrypt_state, MAX_PORTALS * 2> entries = {};
    std::vector<uint32_t> lookedUp = {};
    std::vector<uint32_t> updated = {};
  };
  std::unordered_map<uint32_t, QuicMap> quicMaps = {};
  uint32_t routerQuicMapID = 71001;
  uint32_t ingressQuicMapID = 71002;
  std::vector<uint32_t> quicOperationBatches = {};
  uint64_t lastQuicCallbackSerial = 0;
  uint32_t quicMapInfoQueries = 0;

  void reset(void)
  {
    std::lock_guard lock(mutex);
    quicDelayUs = quicSyscallCostUs;
    holdInner = false;
    workerEntered = false;
    releaseInner = false;
    failInner = false;
    failOuter = false;
    failMetadata = false;
    failQuicLookup = false;
    failQuicUpdate = false;
    createdInner.clear();
    firstEntry.clear();
    innerUpdates.clear();
    publications.clear();
    quicMaps.clear();
    routerQuicMapID = 71001;
    ingressQuicMapID = 71002;
    quicOperationBatches.clear();
    lastQuicCallbackSerial = 0;
    quicMapInfoQueries = 0;
  }

  uint32_t mapIDForFD(int fd) const
  {
    if (fd == 7021) return routerQuicMapID;
    if (fd == 7022) return ingressQuicMapID;
    return 0;
  }

  QuicMap& quicMapForFD(int fd)
  {
    const uint32_t id = mapIDForFD(fd);
    QuicMap& map = quicMaps[id];
    map.id = id;
    return map;
  }

  void replaceRouterQuicMap(uint32_t id)
  {
    std::lock_guard lock(mutex);
    routerQuicMapID = id;
    quicMaps[id].id = id;
  }

  void seedQuic(int fd, uint32_t index, const quic_cid_aes_decrypt_state& value)
  {
    std::lock_guard lock(mutex);
    quicMapForFD(fd).entries[index] = value;
  }

  void clearQuicTrace(void)
  {
    std::lock_guard lock(mutex);
    for (auto& [id, map] : quicMaps)
    {
      (void)id;
      map.lookedUp.clear();
      map.updated.clear();
    }
    quicOperationBatches.clear();
    lastQuicCallbackSerial = 0;
    quicMapInfoQueries = 0;
  }

  void noteQuicOperation(void)
  {
    if (quicOperationBatches.empty() || timeoutCallbackSerial != lastQuicCallbackSerial)
    {
      quicOperationBatches.push_back(0);
    }
    quicOperationBatches.back() += 1;
    lastQuicCallbackSerial = timeoutCallbackSerial;
  }

  uint32_t quicMapInfoCount(void)
  {
    std::lock_guard lock(mutex);
    return quicMapInfoQueries;
  }

  uint32_t largestQuicOperationBatch(void)
  {
    std::lock_guard lock(mutex);
    uint32_t largest = 0;
    for (uint32_t count : quicOperationBatches) largest = std::max(largest, count);
    return largest;
  }

  uint32_t quicUpdateCount(int fd)
  {
    std::lock_guard lock(mutex);
    return uint32_t(quicMapForFD(fd).updated.size());
  }

  uint32_t quicLookupCount(int fd)
  {
    std::lock_guard lock(mutex);
    return uint32_t(quicMapForFD(fd).lookedUp.size());
  }

  bool quicUpdatedIndex(int fd, uint32_t index)
  {
    std::lock_guard lock(mutex);
    const auto& updates = quicMapForFD(fd).updated;
    return std::find(updates.begin(), updates.end(), index) != updates.end();
  }

  bool quicEquals(int fd, uint32_t index, const quic_cid_aes_decrypt_state& expected)
  {
    std::lock_guard lock(mutex);
    return std::memcmp(&quicMapForFD(fd).entries[index], &expected, sizeof(expected)) == 0;
  }

  void hold(void)
  {
    std::lock_guard lock(mutex);
    holdInner = true;
    workerEntered = false;
    releaseInner = false;
  }

  bool entered(void)
  {
    std::lock_guard lock(mutex);
    return workerEntered;
  }

  void release(void)
  {
    {
      std::lock_guard lock(mutex);
      releaseInner = true;
    }
    condition.notify_all();
  }

  bool noPublication(void)
  {
    std::lock_guard lock(mutex);
    return publications.empty();
  }

  std::vector<Publication> published(void)
  {
    std::lock_guard lock(mutex);
    return publications;
  }

  void clearPublications(void)
  {
    std::lock_guard lock(mutex);
    publications.clear();
  }

  bool allCreatedInnerClosed(void)
  {
    std::lock_guard lock(mutex);
    for (int fd : createdInner)
    {
      if (fcntl(fd, F_GETFD) >= 0) return false;
    }
    return true;
  }

  static bool innerMapComplete(const Publication& publication)
  {
    return publication.updateCount == RING_SIZE;
  }

  static bool firstEntryEquals(const Publication& publication, uint8_t containerFragment)
  {
    return publication.firstEntry.hasID && publication.firstEntry.value[4] == containerFragment;
  }
};

static FakeBPFKernel fakeKernel = {};
static constexpr int routerRingMapFD = 7001;
static constexpr int ingressRingMapFD = 7002;
static constexpr int routerPortalMapFD = 7011;
static constexpr int ingressPortalMapFD = 7012;
static constexpr int routerQuicMapFD = 7021;
static constexpr int ingressQuicMapFD = 7022;

extern "C" int __wrap_bpf_map_create(enum bpf_map_type, const char *, __u32, __u32, __u32, const struct bpf_map_create_opts *)
{
  int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (fd >= 0)
  {
    std::lock_guard lock(fakeKernel.mutex);
    // eventfd numbers can be recycled after a stale result closes its map.
    // The maps below describe the current descriptor incarnation only; every
    // publication preserves its own immutable evidence before later reuse.
    fakeKernel.firstEntry.erase(fd);
    fakeKernel.innerUpdates.erase(fd);
    fakeKernel.createdInner.push_back(fd);
  }
  return fd;
}

extern "C" int __wrap_bpf_map_update_elem(int fd, const void *key, const void *value, __u64)
{
  if (fd == routerRingMapFD || fd == ingressRingMapFD)
  {
    const uint32_t slot = *reinterpret_cast<const uint32_t *>(key);
    const int innerFD = *reinterpret_cast<const int *>(value);
    std::lock_guard lock(fakeKernel.mutex);
    if (fakeKernel.failOuter && fd == ingressRingMapFD)
    {
      errno = EIO;
      return -1;
    }
    const auto entry = fakeKernel.firstEntry.find(innerFD);
    const auto updates = fakeKernel.innerUpdates.find(innerFD);
    fakeKernel.publications.push_back({fd, slot, innerFD,
                                       entry == fakeKernel.firstEntry.end() ? container_id{} : entry->second,
                                       updates == fakeKernel.innerUpdates.end() ? 0u : updates->second});
    return 0;
  }

  if (fd == routerPortalMapFD || fd == ingressPortalMapFD)
  {
    std::lock_guard lock(fakeKernel.mutex);
    if (fakeKernel.failMetadata)
    {
      errno = EIO;
      return -1;
    }
    return 0;
  }

  if (fd == routerQuicMapFD || fd == ingressQuicMapFD)
  {
    const uint32_t index = *reinterpret_cast<const uint32_t *>(key);
    const auto decodedValue = *reinterpret_cast<const quic_cid_aes_decrypt_state *>(value);
    if (fakeKernel.quicDelayUs) std::this_thread::sleep_for(std::chrono::microseconds(fakeKernel.quicDelayUs));
    std::lock_guard lock(fakeKernel.mutex);
    if (fakeKernel.failQuicUpdate)
    {
      errno = EIO;
      return -1;
    }
    auto& map = fakeKernel.quicMapForFD(fd);
    map.entries[index] = decodedValue;
    map.updated.push_back(index);
    fakeKernel.noteQuicOperation();
    return 0;
  }

  const uint32_t index = *reinterpret_cast<const uint32_t *>(key);
  const container_id entry = *reinterpret_cast<const container_id *>(value);
  std::unique_lock lock(fakeKernel.mutex);
  if (fakeKernel.holdInner && fakeKernel.releaseInner == false && index == 0)
  {
    fakeKernel.workerEntered = true;
    fakeKernel.condition.notify_all();
    fakeKernel.condition.wait(lock, [] { return fakeKernel.releaseInner; });
  }
  if (fakeKernel.failInner)
  {
    errno = EIO;
    return -1;
  }
  if (index == 0) fakeKernel.firstEntry.insert_or_assign(fd, entry);
  fakeKernel.innerUpdates[fd] += 1;
  return 0;
}

extern "C" struct bpf_map *__wrap_bpf_object__find_map_by_name(const struct bpf_object *object, const char *name)
{
  const uintptr_t program = reinterpret_cast<uintptr_t>(object);
  const bool rings = name != nullptr && std::strcmp(name, "cid_rings") == 0;
  const bool quic = name != nullptr && std::strcmp(name, "quic_cid_dec") == 0;
  if (program == routerRingMapFD) return reinterpret_cast<struct bpf_map *>(rings ? uintptr_t(routerRingMapFD) : quic ? uintptr_t(routerQuicMapFD) : uintptr_t(routerPortalMapFD));
  if (program == ingressRingMapFD) return reinterpret_cast<struct bpf_map *>(rings ? uintptr_t(ingressRingMapFD) : quic ? uintptr_t(ingressQuicMapFD) : uintptr_t(ingressPortalMapFD));
  return nullptr;
}

extern "C" int __wrap_bpf_map__fd(const struct bpf_map *map)
{
  return int(reinterpret_cast<uintptr_t>(map));
}

extern "C" int __wrap_bpf_map_get_info_by_fd(int fd, void *info, __u32 *infoLen)
{
  if ((fd == routerQuicMapFD || fd == ingressQuicMapFD) && info != nullptr && infoLen != nullptr && *infoLen >= sizeof(bpf_map_info))
  {
    if (fakeKernel.quicDelayUs) std::this_thread::sleep_for(std::chrono::microseconds(fakeKernel.quicDelayUs));
    std::lock_guard lock(fakeKernel.mutex);
    fakeKernel.quicMapInfoQueries += 1;
    fakeKernel.noteQuicOperation();
    auto *mapInfo = static_cast<bpf_map_info *>(info);
    *mapInfo = {};
    mapInfo->id = fakeKernel.mapIDForFD(fd);
    mapInfo->type = BPF_MAP_TYPE_ARRAY;
    mapInfo->key_size = sizeof(uint32_t);
    mapInfo->value_size = sizeof(quic_cid_aes_decrypt_state);
    mapInfo->max_entries = MAX_PORTALS * 2;
    return 0;
  }
  errno = EBADF;
  return -1;
}

extern "C" int __wrap_bpf_map_lookup_elem(int fd, const void *key, void *value)
{
  if ((fd == routerQuicMapFD || fd == ingressQuicMapFD) && key != nullptr && value != nullptr)
  {
    const uint32_t index = *static_cast<const uint32_t *>(key);
    if (fakeKernel.quicDelayUs) std::this_thread::sleep_for(std::chrono::microseconds(fakeKernel.quicDelayUs));
    std::lock_guard lock(fakeKernel.mutex);
    if (fakeKernel.failQuicLookup || index >= MAX_PORTALS * 2)
    {
      errno = EIO;
      return -1;
    }
    auto& map = fakeKernel.quicMapForFD(fd);
    *static_cast<quic_cid_aes_decrypt_state *>(value) = map.entries[index];
    map.lookedUp.push_back(index);
    fakeKernel.noteQuicOperation();
    return 0;
  }
  errno = EBADF;
  return -1;
}

class SwitchboardRingTestAccess {
public:
  static void installPrograms(Switchboard& board, BPFProgram& router, BPFProgram& ingress)
  {
    router.obj = reinterpret_cast<struct bpf_object *>(uintptr_t(routerRingMapFD));
    ingress.obj = reinterpret_cast<struct bpf_object *>(uintptr_t(ingressRingMapFD));
    board.bpf_router = &router;
    board.host_ingress = &ingress;
  }

  static SwitchboardPortal *addPortal(Switchboard& board, uint32_t containerID)
  {
    auto *portal = new SwitchboardPortal();
    portal->address = IPAddress("2001:db8::44", true);
    portal->port = 443;
    portal->proto = IPPROTO_TCP;
    portal->slot = 9;
    auto *wormhole = new switchboard_runtime::Wormhole();
    wormhole->containerID = containerID;
    wormhole->weight = 1;
    wormhole->portal = portal;
    portal->wormholes.insert(wormhole);
    board.portals.insert(portal);
    board.wormholesByContainer.emplace(containerID, wormhole);
    return portal;
  }

  static void replaceEndpoint(Switchboard& board, SwitchboardPortal *portal, uint32_t containerID)
  {
    for (auto *wormhole : portal->wormholes)
    {
      portal->wormholes.erase(wormhole);
      board.wormholesByContainer.eraseEntry(wormhole->containerID, wormhole);
      delete wormhole;
      break;
    }
    auto *wormhole = new switchboard_runtime::Wormhole();
    wormhole->containerID = containerID;
    wormhole->weight = 1;
    wormhole->portal = portal;
    portal->wormholes.insert(wormhole);
    board.wormholesByContainer.emplace(containerID, wormhole);
  }

  static bool generate(Switchboard& board, SwitchboardPortal *portal)
  {
    return board.generateRingForPortal(portal);
  }

  static void seedRevision(Switchboard& board, uint32_t containerID)
  {
    board.wormholeRevisionByContainer.insert_or_assign(containerID, "admitted"_ctv);
  }

  static bool revisionsEmpty(const Switchboard& board) { return board.wormholeRevisionByContainer.empty(); }

  static void installRouterOnly(Switchboard& board, BPFProgram& router)
  {
    router.obj = reinterpret_cast<struct bpf_object *>(uintptr_t(routerRingMapFD));
    board.bpf_router = &router;
    board.host_ingress = nullptr;
  }

  static void configureQuicPortal(SwitchboardPortal *portal, uint128_t first, uint128_t second)
  {
    portal->isQuic = true;
    portal->hasQuicCidKeyState = true;
    (void)wormholeQuicCidForceKeyMaterialPhase(first, 0);
    (void)wormholeQuicCidForceKeyMaterialPhase(second, 1);
    portal->quicCidKeyMaterialByIndex[0] = first;
    portal->quicCidKeyMaterialByIndex[1] = second;
  }

  static quic_cid_aes_decrypt_state quicState(uint128_t key)
  {
    quic_cid_aes_decrypt_state state = {};
    Switchboard::buildQuicCidDecryptState(key, state);
    return state;
  }

  static uint32_t quicIndex(const SwitchboardPortal *portal, uint128_t key)
  {
    return quicCidPortalDecryptMapIndex(portal->slot, wormholeQuicCidKeyMaterialPhase(key));
  }

  static void syncPeerRuntime(Switchboard& board, BPFProgram& peer)
  {
    board.syncPeerProgramRuntimeRouting(&peer);
  }

  static void syncQuicOnly(Switchboard& board)
  {
    board.syncAllPortalQuicCidDecryptStates();
  }

  static void detachRouterOnly(Switchboard& board, BPFProgram& router)
  {
    board.bpf_router = nullptr;
    board.host_ingress = nullptr;
    router.obj = nullptr;
  }

  static void detachFakePrograms(Switchboard& board, BPFProgram& router, BPFProgram& ingress)
  {
    board.bpf_router = nullptr;
    board.host_ingress = nullptr;
    router.obj = nullptr;
    ingress.obj = nullptr;
  }
};

static bool runQuicUntilSettled(TestRing& ring, bool& receipt, bool& receiptValue)
{
  return ring.runUntil([&] { return receipt; }, 1500) && receipt && receiptValue;
}

static void printSamples(const char *label, const std::vector<uint64_t>& samples)
{
  dprintf(STDERR_FILENO, "%s", label);
  for (uint64_t sample : samples) dprintf(STDERR_FILENO, "%llu,", static_cast<unsigned long long>(sample));
  dprintf(STDERR_FILENO, "\n");
}

static void runQuicCidResetCancelsPending(TestSuite& suite)
{
  TestRing ring = {};
  BPFProgram router = {};
  EthDevice eth = {};
  Switchboard board(eth);
  SwitchboardRingTestAccess::installRouterOnly(board, router);
  fakeKernel.reset();
  auto *portal = SwitchboardRingTestAccess::addPortal(board, 0x01020304u);
  SwitchboardRingTestAccess::configureQuicPortal(portal, uint128_t(0x6101), uint128_t(0x6202));
  bool receipt = false;
  bool receiptValue = true;
  board.whenRingsReady(319, [&](bool ready) { receipt = true; receiptValue = ready; });
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  suite.expect(fakeKernel.quicLookupCount(routerQuicMapFD) == 0 && fakeKernel.quicUpdateCount(routerQuicMapFD) == 0 && !receipt,
               "switchboard_quic_reset_fixture_defers_pending_work_before_ring_turn");
  board.resetState();
  const bool quiesceBlockedBeforeTerminalWake = !board.quiesceRingPreparationForExec();
  const bool quiescedAfterTerminalWake = ring.runUntil([&] { return board.quiesceRingPreparationForExec(); });
  suite.expect(receipt && !receiptValue && quiesceBlockedBeforeTerminalWake && quiescedAfterTerminalWake,
               "switchboard_quic_reset_cancels_pending_receipt_then_drains_terminal_wake_before_quiesce");
  suite.expect(fakeKernel.quicLookupCount(routerQuicMapFD) == 0 && fakeKernel.quicUpdateCount(routerQuicMapFD) == 0,
               "switchboard_quic_reset_prevents_late_map_mutation");
  suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_quic_fixture_drains_all_preparation_and_wakes_before_teardown");
  SwitchboardRingTestAccess::detachRouterOnly(board, router);
}

static void runQuicCidEmptyAdoptedMap(TestSuite& suite)
{
  TestRing ring = {};
  BPFProgram router = {};
  EthDevice eth = {};
  Switchboard board(eth);
  SwitchboardRingTestAccess::installRouterOnly(board, router);
  fakeKernel.reset();

  constexpr uint32_t staleIndex = 77;
  quic_cid_aes_decrypt_state stale = {};
  stale.rk[0] = 0xdecafbad;
  fakeKernel.seedQuic(routerQuicMapFD, staleIndex, stale);
  bool receipt = false;
  bool receiptValue = false;
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  board.whenRingsReady(320, [&](bool ready) { receipt = true; receiptValue = ready; });
  suite.expect(fakeKernel.quicLookupCount(routerQuicMapFD) == 0 && fakeKernel.quicUpdateCount(routerQuicMapFD) == 0 && !receipt,
               "switchboard_quic_empty_adopted_map_defers_scan_before_ring_turn");
  suite.expect(runQuicUntilSettled(ring, receipt, receiptValue) &&
                   fakeKernel.quicEquals(routerQuicMapFD, staleIndex, quic_cid_aes_decrypt_state{}) &&
                   fakeKernel.quicUpdateCount(routerQuicMapFD) == 1 && fakeKernel.largestQuicOperationBatch() <= 32,
               "switchboard_quic_empty_adopted_map_removes_stale_key_in_bounded_turns");
  suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_quic_fixture_drains_all_preparation_and_wakes_before_teardown");
  SwitchboardRingTestAccess::detachRouterOnly(board, router);
}

static void runQuicCidTwoProgramCoalescing(TestSuite& suite)
{
  TestRing ring = {};
  BPFProgram router = {}, ingress = {};
  EthDevice eth = {};
  Switchboard board(eth);
  SwitchboardRingTestAccess::installPrograms(board, router, ingress);
  fakeKernel.reset();

  auto *portal = SwitchboardRingTestAccess::addPortal(board, 0x11121314u);
  constexpr uint128_t firstKey = uint128_t(0x7101);
  constexpr uint128_t secondKey = uint128_t(0x7202);
  SwitchboardRingTestAccess::configureQuicPortal(portal, firstKey, secondKey);
  const uint32_t firstIndex = SwitchboardRingTestAccess::quicIndex(portal, portal->quicCidKeyMaterialByIndex[0]);
  const uint32_t secondIndex = SwitchboardRingTestAccess::quicIndex(portal, portal->quicCidKeyMaterialByIndex[1]);
  const uint32_t staleIndex = quicCidPortalDecryptMapIndex(portal->slot + 5, 0);
  const auto firstExpected = SwitchboardRingTestAccess::quicState(portal->quicCidKeyMaterialByIndex[0]);
  quic_cid_aes_decrypt_state stale = {};
  stale.rk[0] = 0xbeefcafe;
  for (int fd : {routerQuicMapFD, ingressQuicMapFD})
  {
    fakeKernel.seedQuic(fd, firstIndex, firstExpected);
    fakeKernel.seedQuic(fd, staleIndex, stale);
  }

  bool receipt = false;
  bool receiptValue = false;
  board.whenRingsReady(327, [&](bool ready) { receipt = true; receiptValue = ready; });
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  SwitchboardRingTestAccess::syncPeerRuntime(board, ingress);
  uint128_t latestSecond = uint128_t(0x7303);
  (void)wormholeQuicCidForceKeyMaterialPhase(latestSecond, 1);
  portal->quicCidKeyMaterialByIndex[1] = latestSecond;
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  SwitchboardRingTestAccess::syncPeerRuntime(board, ingress);
  suite.expect(fakeKernel.quicLookupCount(routerQuicMapFD) == 0 && fakeKernel.quicLookupCount(ingressQuicMapFD) == 0 &&
                   fakeKernel.quicUpdateCount(routerQuicMapFD) == 0 && fakeKernel.quicUpdateCount(ingressQuicMapFD) == 0 && !receipt,
               "switchboard_quic_two_program_requests_defer_and_coalesce_before_ring_turn");
  suite.expect(runQuicUntilSettled(ring, receipt, receiptValue) &&
                   fakeKernel.quicUpdateCount(routerQuicMapFD) == 2 && fakeKernel.quicUpdateCount(ingressQuicMapFD) == 2 &&
                   !fakeKernel.quicUpdatedIndex(routerQuicMapFD, firstIndex) && !fakeKernel.quicUpdatedIndex(ingressQuicMapFD, firstIndex) &&
                   fakeKernel.quicEquals(routerQuicMapFD, secondIndex, SwitchboardRingTestAccess::quicState(latestSecond)) &&
                   fakeKernel.quicEquals(ingressQuicMapFD, secondIndex, SwitchboardRingTestAccess::quicState(latestSecond)) &&
                   fakeKernel.quicEquals(routerQuicMapFD, staleIndex, quic_cid_aes_decrypt_state{}) &&
                   fakeKernel.quicEquals(ingressQuicMapFD, staleIndex, quic_cid_aes_decrypt_state{}),
               "switchboard_quic_two_programs_publish_only_latest_sparse_delta_to_router_and_ingress");
  const uint32_t initialMapInfoQueries = fakeKernel.quicMapInfoCount();
  suite.expect(initialMapInfoQueries >= 2 && initialMapInfoQueries <= (MAX_PORTALS * 4 / 32) + 12,
               "switchboard_quic_two_program_scan_bounds_map_identity_queries_by_turns_plus_programs");
  dprintf(STDERR_FILENO, "QUIC_RECONCILIATION_TWO_PROGRAM_METADATA_QUERIES=%u\n", initialMapInfoQueries);

  fakeKernel.clearQuicTrace();
  for (uint32_t request = 0; request < 30; ++request)
  {
    SwitchboardRingTestAccess::syncPeerRuntime(board, router);
    SwitchboardRingTestAccess::syncPeerRuntime(board, ingress);
  }
  suite.expect(fakeKernel.quicLookupCount(routerQuicMapFD) == 0 && fakeKernel.quicLookupCount(ingressQuicMapFD) == 0 &&
                   fakeKernel.quicUpdateCount(routerQuicMapFD) == 0 && fakeKernel.quicUpdateCount(ingressQuicMapFD) == 0 &&
                   fakeKernel.quicMapInfoCount() == 0,
               "switchboard_quic_two_program_unchanged_burst_skips_rescan_and_writes_after_convergence");

  uint128_t rotatedFirst = uint128_t(0x7404);
  (void)wormholeQuicCidForceKeyMaterialPhase(rotatedFirst, 0);
  portal->quicCidKeyMaterialByIndex[0] = rotatedFirst;
  receipt = false;
  receiptValue = false;
  board.whenRingsReady(328, [&](bool ready) { receipt = true; receiptValue = ready; });
  fakeKernel.clearQuicTrace();
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  SwitchboardRingTestAccess::syncPeerRuntime(board, ingress);
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  SwitchboardRingTestAccess::syncPeerRuntime(board, ingress);
  suite.expect(runQuicUntilSettled(ring, receipt, receiptValue) &&
                   fakeKernel.quicUpdateCount(routerQuicMapFD) == 1 && fakeKernel.quicUpdateCount(ingressQuicMapFD) == 1 &&
                   fakeKernel.quicEquals(routerQuicMapFD, firstIndex, SwitchboardRingTestAccess::quicState(rotatedFirst)) &&
                   fakeKernel.quicEquals(ingressQuicMapFD, firstIndex, SwitchboardRingTestAccess::quicState(rotatedFirst)),
               "switchboard_quic_two_program_latest_change_updates_one_slot_per_program_once");

  suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_quic_two_program_quiesces_before_ring_shutdown");
  suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_quic_fixture_drains_all_preparation_and_wakes_before_teardown");
  SwitchboardRingTestAccess::detachFakePrograms(board, router, ingress);
}

static void runQuicCidSparseReconciliation(TestSuite& suite)
{
  TestRing ring = {};
  BPFProgram router = {};
  EthDevice eth = {};
  Switchboard board(eth);
  SwitchboardRingTestAccess::installRouterOnly(board, router);
  fakeKernel.reset();

  auto *portal = SwitchboardRingTestAccess::addPortal(board, 0x01020304u);
  constexpr uint128_t firstKey = uint128_t(0x1001);
  constexpr uint128_t secondKey = uint128_t(0x2002);
  SwitchboardRingTestAccess::configureQuicPortal(portal, firstKey, secondKey);
  const uint32_t firstIndex = SwitchboardRingTestAccess::quicIndex(portal, portal->quicCidKeyMaterialByIndex[0]);
  const uint32_t secondIndex = SwitchboardRingTestAccess::quicIndex(portal, portal->quicCidKeyMaterialByIndex[1]);
  const uint32_t staleIndex = quicCidPortalDecryptMapIndex(portal->slot + 3, 0);
  quic_cid_aes_decrypt_state stale = {};
  stale.rk[0] = 0xfeedbeef;
  const auto firstExpected = SwitchboardRingTestAccess::quicState(portal->quicCidKeyMaterialByIndex[0]);
  fakeKernel.seedQuic(routerQuicMapFD, firstIndex, firstExpected);
  fakeKernel.seedQuic(routerQuicMapFD, staleIndex, stale);

  bool receipt = false;
  bool receiptValue = false;
  board.whenRingsReady(321, [&](bool ready) { receipt = true; receiptValue = ready; });
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  uint128_t coalesced = uint128_t(0x5005);
  (void)wormholeQuicCidForceKeyMaterialPhase(coalesced, 1);
  portal->quicCidKeyMaterialByIndex[1] = coalesced;
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  suite.expect(fakeKernel.quicLookupCount(routerQuicMapFD) == 0 && fakeKernel.quicUpdateCount(routerQuicMapFD) == 0 && !receipt,
               "switchboard_quic_reconcile_defers_and_coalesces_latest_desired_state_before_ring_turn");
  std::vector<uint64_t> controlIntervals = {};
  const bool initialSettled = ring.runUntilWithControl([&] { return receipt; }, controlIntervals, 1500);
  std::vector<uint64_t> sortedControl = controlIntervals;
  std::sort(sortedControl.begin(), sortedControl.end());
  const uint64_t controlP95 = sortedControl.empty() ? UINT64_MAX : sortedControl[(sortedControl.size() * 95) / 100];
  const uint64_t controlMax = sortedControl.empty() ? UINT64_MAX : sortedControl.back();
  suite.expect(initialSettled && receiptValue && controlIntervals.size() >= 30 && controlP95 < 10'000 && controlMax < 50'000 &&
                   fakeKernel.largestQuicOperationBatch() <= 32,
               "switchboard_quic_reconcile_keeps_30_control_intervals_under_10ms_p95_50ms_max");
  const auto secondExpected = SwitchboardRingTestAccess::quicState(coalesced);
  suite.expect(fakeKernel.quicEquals(routerQuicMapFD, firstIndex, firstExpected) &&
                   fakeKernel.quicEquals(routerQuicMapFD, secondIndex, secondExpected) &&
                   fakeKernel.quicEquals(routerQuicMapFD, staleIndex, quic_cid_aes_decrypt_state{}),
               "switchboard_quic_reconcile_preserves_desired_and_clears_adopted_stale_slot");
  suite.expect(fakeKernel.quicUpdateCount(routerQuicMapFD) == 2 && !fakeKernel.quicUpdatedIndex(routerQuicMapFD, firstIndex),
               "switchboard_quic_reconcile_keeps_adopted_valid_slot_and_updates_only_missing_stale_slots");
  const uint32_t initialScanReads = fakeKernel.quicLookupCount(routerQuicMapFD);
  const uint32_t initialSparseWrites = fakeKernel.quicUpdateCount(routerQuicMapFD);

  fakeKernel.clearQuicTrace();
  std::vector<uint64_t> unchangedRequestMicros = {};
  unchangedRequestMicros.reserve(30);
  for (uint32_t sample = 0; sample < 30; ++sample)
  {
    const auto began = std::chrono::steady_clock::now();
    SwitchboardRingTestAccess::syncPeerRuntime(board, router);
    unchangedRequestMicros.push_back(uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - began).count()));
  }
  const std::vector<uint64_t> unchangedRequestRaw = unchangedRequestMicros;
  std::sort(unchangedRequestMicros.begin(), unchangedRequestMicros.end());
  const uint64_t unchangedP95 = unchangedRequestMicros[(unchangedRequestMicros.size() * 95) / 100];
  suite.expect(fakeKernel.quicUpdateCount(routerQuicMapFD) == 0 && unchangedP95 < 10'000,
               "switchboard_quic_reconcile_unchanged_runtime_has_no_redundant_writes");

  uint128_t rotated = uint128_t(0x3003);
  (void)wormholeQuicCidForceKeyMaterialPhase(rotated, 0);
  portal->quicCidKeyMaterialByIndex[0] = rotated;
  receipt = false;
  receiptValue = false;
  board.whenRingsReady(322, [&](bool ready) { receipt = true; receiptValue = ready; });
  fakeKernel.clearQuicTrace();
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  suite.expect(runQuicUntilSettled(ring, receipt, receiptValue) && fakeKernel.quicUpdateCount(routerQuicMapFD) == 1 &&
                   fakeKernel.quicEquals(routerQuicMapFD, firstIndex, SwitchboardRingTestAccess::quicState(rotated)),
               "switchboard_quic_reconcile_rotates_only_changed_key_slot");

  uint128_t retryKey = uint128_t(0x4004);
  (void)wormholeQuicCidForceKeyMaterialPhase(retryKey, 1);
  portal->quicCidKeyMaterialByIndex[1] = retryKey;
  receipt = false;
  receiptValue = true;
  board.whenRingsReady(323, [&](bool ready) { receipt = true; receiptValue = ready; });
  fakeKernel.clearQuicTrace();
  fakeKernel.failQuicUpdate = true;
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  suite.expect(ring.runUntil([&] { return receipt; }, 1500) && !receiptValue,
               "switchboard_quic_reconcile_map_write_failure_rejects_readiness_receipt");
  fakeKernel.failQuicUpdate = false;
  receipt = false;
  receiptValue = false;
  board.whenRingsReady(324, [&](bool ready) { receipt = true; receiptValue = ready; });
  fakeKernel.clearQuicTrace();
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  suite.expect(runQuicUntilSettled(ring, receipt, receiptValue) && fakeKernel.quicUpdateCount(routerQuicMapFD) == 1 &&
                   fakeKernel.quicEquals(routerQuicMapFD, secondIndex, SwitchboardRingTestAccess::quicState(retryKey)),
               "switchboard_quic_reconcile_same_map_recovers_after_write_failure");

  // The FD remains stable while its kernel map identity changes, as happens
  // when a preattached program is replaced.  The old mirror must not be reused.
  fakeKernel.replaceRouterQuicMap(72001);
  receipt = false;
  receiptValue = false;
  board.whenRingsReady(325, [&](bool ready) { receipt = true; receiptValue = ready; });
  fakeKernel.clearQuicTrace();
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  suite.expect(runQuicUntilSettled(ring, receipt, receiptValue) &&
                   fakeKernel.quicUpdateCount(routerQuicMapFD) == 2,
               "switchboard_quic_reconcile_replaces_map_identity_despite_fd_reuse");

  portal->slot += 7;
  const uint32_t movedFirstIndex = SwitchboardRingTestAccess::quicIndex(portal, portal->quicCidKeyMaterialByIndex[0]);
  const uint32_t movedSecondIndex = SwitchboardRingTestAccess::quicIndex(portal, portal->quicCidKeyMaterialByIndex[1]);
  receipt = false;
  receiptValue = false;
  board.whenRingsReady(326, [&](bool ready) { receipt = true; receiptValue = ready; });
  fakeKernel.clearQuicTrace();
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  suite.expect(runQuicUntilSettled(ring, receipt, receiptValue) && fakeKernel.quicUpdateCount(routerQuicMapFD) == 4 &&
                   fakeKernel.quicEquals(routerQuicMapFD, firstIndex, quic_cid_aes_decrypt_state{}) &&
                   fakeKernel.quicEquals(routerQuicMapFD, secondIndex, quic_cid_aes_decrypt_state{}) &&
                   fakeKernel.quicEquals(routerQuicMapFD, movedFirstIndex, SwitchboardRingTestAccess::quicState(rotated)) &&
                   fakeKernel.quicEquals(routerQuicMapFD, movedSecondIndex, SwitchboardRingTestAccess::quicState(retryKey)),
               "switchboard_quic_reconcile_slot_move_clears_old_and_installs_new_slots_before_receipt");

  portal->hasQuicCidKeyState = false;
  receipt = false;
  receiptValue = false;
  board.whenRingsReady(326, [&](bool ready) { receipt = true; receiptValue = ready; });
  fakeKernel.clearQuicTrace();
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  suite.expect(runQuicUntilSettled(ring, receipt, receiptValue) && fakeKernel.quicUpdateCount(routerQuicMapFD) == 2 &&
                   fakeKernel.quicEquals(routerQuicMapFD, movedFirstIndex, quic_cid_aes_decrypt_state{}) &&
                   fakeKernel.quicEquals(routerQuicMapFD, movedSecondIndex, quic_cid_aes_decrypt_state{}),
               "switchboard_quic_reconcile_deletion_removes_only_prior_key_slots");

  dprintf(STDERR_FILENO,
          "QUIC_RECONCILIATION_SUMMARY artificial_syscall_cost_us=%llu control_samples=%zu control_p95_us=%llu control_max_us=%llu unchanged_samples=%zu unchanged_p95_us=%llu lookups=%u writes=%u\n",
          static_cast<unsigned long long>(FakeBPFKernel::quicSyscallCostUs),
          controlIntervals.size(),
          static_cast<unsigned long long>(controlP95),
          static_cast<unsigned long long>(controlMax),
          unchangedRequestMicros.size(),
          static_cast<unsigned long long>(unchangedP95),
          initialScanReads,
          initialSparseWrites);
  printSamples("QUIC_RECONCILIATION_CONTROL_RAW_US=", controlIntervals);
  printSamples("QUIC_RECONCILIATION_UNCHANGED_REQUEST_RAW_US=", unchangedRequestRaw);

  suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_quic_fixture_drains_all_preparation_and_wakes_before_teardown");
  SwitchboardRingTestAccess::detachRouterOnly(board, router);
}

static void runQuicCidMapReplacementDuringScan(TestSuite& suite)
{
  TestRing ring = {};
  BPFProgram router = {};
  EthDevice eth = {};
  Switchboard board(eth);
  SwitchboardRingTestAccess::installRouterOnly(board, router);
  fakeKernel.reset();
  quic_cid_aes_decrypt_state stale = {};
  stale.rk[0] = 0xf00dbabe;
  fakeKernel.seedQuic(routerQuicMapFD, 1000, stale);
  bool receipt = false, receiptValue = false, replaced = false;
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  board.whenRingsReady(330, [&](bool ready) { receipt = true; receiptValue = ready; });
  std::vector<uint64_t> intervals;
  const bool finished = ring.runUntilWithControl([&] { return receipt; }, intervals, 1500, [&] {
    if (!replaced && fakeKernel.quicLookupCount(routerQuicMapFD) >= 128)
    {
      suite.expect(!receipt, "switchboard_quic_replacement_scan_has_no_early_receipt");
      fakeKernel.replaceRouterQuicMap(73001);
      fakeKernel.seedQuic(routerQuicMapFD, 1200, stale);
      replaced = true;
    }
  });
  suite.expect(finished && replaced && receiptValue &&
                   fakeKernel.quicLookupCount(routerQuicMapFD) == MAX_PORTALS * 2 &&
                   fakeKernel.quicUpdateCount(routerQuicMapFD) == 1 &&
                   fakeKernel.quicEquals(routerQuicMapFD, 1200, quic_cid_aes_decrypt_state{}),
               "switchboard_quic_replacement_during_scan_prunes_abandoned_map_and_converges");
  suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_quic_fixture_drains_replacement_scan_before_teardown");
  SwitchboardRingTestAccess::detachRouterOnly(board, router);
}

static uint64_t currentThreadCpuNanos(void)
{
  timespec value = {};
  if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &value) != 0) std::abort();
  return uint64_t(value.tv_sec) * 1'000'000'000 + uint64_t(value.tv_nsec);
}

static void runQuicCidCpuWorkload(TestSuite& suite)
{
  // Keep syscall delay out of this workload so repeated key expansion and
  // desired-state traversal cannot hide behind injected kernel latency.
  constexpr uint32_t portalCount = 128;
  constexpr uint32_t sampleCount = 30;
  std::vector<uint64_t> coldCpu, warmCpu, coldWall, warmWall;
  for (uint32_t sample = 0; sample < sampleCount; ++sample)
  {
    TestRing ring = {};
    BPFProgram router = {}, ingress = {};
    EthDevice eth = {};
    Switchboard board(eth);
    SwitchboardRingTestAccess::installPrograms(board, router, ingress);
    fakeKernel.reset();
    fakeKernel.quicDelayUs = 0;
    for (uint32_t i = 0; i < portalCount; ++i)
    {
      auto *portal = SwitchboardRingTestAccess::addPortal(board, 0x03000000u + i);
      portal->slot = i;
      SwitchboardRingTestAccess::configureQuicPortal(portal, uint128_t(i + 1), uint128_t(i + 129));
    }
    for (bool cold : {true, false})
    {
      bool receipt = false, receiptValue = false;
      fakeKernel.clearQuicTrace();
      const uint64_t cpuStart = currentThreadCpuNanos();
      const auto wallStart = std::chrono::steady_clock::now();
      SwitchboardRingTestAccess::syncQuicOnly(board);
      board.whenRingsReady(340, [&](bool ready) { receipt = true; receiptValue = ready; });
      const bool ready = runQuicUntilSettled(ring, receipt, receiptValue);
      const uint64_t wallNanos = uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now() - wallStart).count());
      const uint64_t cpuNanos = currentThreadCpuNanos() - cpuStart;
      (cold ? coldCpu : warmCpu).push_back(cpuNanos);
      (cold ? coldWall : warmWall).push_back(wallNanos);
      suite.expect(ready, "switchboard_quic_cpu_workload_converges_before_receipt");
      for (int fd : {routerQuicMapFD, ingressQuicMapFD})
      {
        suite.expect(fakeKernel.quicLookupCount(fd) == (cold ? MAX_PORTALS * 2 : 0) &&
                         fakeKernel.quicUpdateCount(fd) == (cold ? portalCount * 2 : 0),
                     "switchboard_quic_cpu_workload_scans_once_then_skips_unchanged_maps");
      }
      suite.expect(fakeKernel.largestQuicOperationBatch() <= 32,
                   "switchboard_quic_cpu_workload_respects_total_syscall_budget");
    }
    suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
                 "switchboard_quic_cpu_workload_drains_before_teardown");
    SwitchboardRingTestAccess::detachFakePrograms(board, router, ingress);
  }
  dprintf(STDERR_FILENO, "QUIC_CPU_WORKLOAD portals=%u programs=2 samples=%u artificial_syscall_cost_us=0\n",
          portalCount, sampleCount);
  printSamples("QUIC_CPU_COLD_RAW_NS=", coldCpu);
  printSamples("QUIC_CPU_WARM_RAW_NS=", warmCpu);
  printSamples("QUIC_WALL_COLD_RAW_NS=", coldWall);
  printSamples("QUIC_WALL_WARM_RAW_NS=", warmWall);
}

static bool waitForWorkerGate(void)
{
  std::unique_lock lock(fakeKernel.mutex);
  return fakeKernel.condition.wait_for(lock, std::chrono::seconds(1), [] { return fakeKernel.workerEntered; });
}

static void runOwnerPublicationSuccess(TestSuite& suite)
{
  TestRing ring = {};
  BPFProgram router = {}, ingress = {};
  EthDevice eth = {};
  Switchboard board(eth);
  SwitchboardRingTestAccess::installPrograms(board, router, ingress);
  auto *portal = SwitchboardRingTestAccess::addPortal(board, 0x01020304u);
  fakeKernel.reset();
  fakeKernel.hold();
  bool brainReceipt = false, brainValue = false;
  int obsoleteRefreshes = 0, latestRefreshes = 0;
  bool latestRefreshValue = false;
  suite.expect(SwitchboardRingTestAccess::generate(board, portal), "switchboard_ring_owner_admits_held_generation");
  board.whenRingsReady(123, [&](bool ready) { brainReceipt = true; brainValue = ready; });
  board.whenRingsReady(123, [&](bool) { ++obsoleteRefreshes; }, Switchboard::RingConsumer::containerRefresh);
  board.whenRingsReady(123, [&](bool ready) { ++latestRefreshes; latestRefreshValue = ready; },
                       Switchboard::RingConsumer::containerRefresh);
  suite.expect(waitForWorkerGate() && !brainReceipt && obsoleteRefreshes == 0 && latestRefreshes == 0 &&
                   fakeKernel.noPublication(),
               "switchboard_ring_owner_never_publishes_or_receipts_before_preparation");
  fakeKernel.release();
  suite.expect(ring.runUntil([&] { return brainReceipt && latestRefreshes == 1; }) && brainValue &&
                   latestRefreshValue && obsoleteRefreshes == 0,
               "switchboard_ring_owner_keeps_brain_receipt_and_latest_container_refresh_separate");
  const auto published = fakeKernel.published();
  suite.expect(published.size() == 2 && published[0].innerFD == published[1].innerFD &&
                   FakeBPFKernel::firstEntryEquals(published[0], 0x01) &&
                   FakeBPFKernel::innerMapComplete(published[0]) &&
                   fcntl(published[0].innerFD, F_GETFD) >= 0,
               "switchboard_ring_owner_publishes_one_complete_inner_fd_to_all_programs");
  suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_ring_owner_quiesces_preparation_before_ring_shutdown");
  SwitchboardRingTestAccess::detachFakePrograms(board, router, ingress);
}

static void runOwnerStaleGeneration(TestSuite& suite)
{
  TestRing ring = {};
  BPFProgram router = {}, ingress = {};
  EthDevice eth = {};
  Switchboard board(eth);
  SwitchboardRingTestAccess::installPrograms(board, router, ingress);
  auto *portal = SwitchboardRingTestAccess::addPortal(board, 0x01020304u);
  fakeKernel.reset(); fakeKernel.hold();
  bool receipt = false, receiptValue = false;
  suite.expect(SwitchboardRingTestAccess::generate(board, portal), "switchboard_ring_owner_admits_first_generation");
  board.whenRingsReady(123, [&](bool ready) { receipt = true; receiptValue = ready; });
  suite.expect(waitForWorkerGate(), "switchboard_ring_owner_holds_first_generation");
  SwitchboardRingTestAccess::replaceEndpoint(board, portal, 0x05060708u);
  suite.expect(SwitchboardRingTestAccess::generate(board, portal), "switchboard_ring_owner_coalesces_new_generation_while_held");
  fakeKernel.release();
  suite.expect(ring.runUntil([&] { return receipt; }) && receiptValue,
               "switchboard_ring_owner_receipts_only_current_generation");
  const auto published = fakeKernel.published();
  bool onlyLatest = published.size() == 2;
  for (const auto& publication : published)
    onlyLatest = onlyLatest && FakeBPFKernel::firstEntryEquals(publication, 0x05) && FakeBPFKernel::innerMapComplete(publication);
  suite.expect(onlyLatest, "switchboard_ring_owner_never_publishes_stale_generation");
  suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_ring_owner_quiesces_preparation_before_ring_shutdown");
  SwitchboardRingTestAccess::detachFakePrograms(board, router, ingress);
}

static void runOwnerResetCancelsLateWorker(TestSuite& suite)
{
  TestRing ring = {};
  BPFProgram router = {}, ingress = {};
  EthDevice eth = {};
  Switchboard board(eth);
  SwitchboardRingTestAccess::installPrograms(board, router, ingress);
  auto *portal = SwitchboardRingTestAccess::addPortal(board, 0x01020304u);
  fakeKernel.reset(); fakeKernel.hold();
  bool brainReceipt = false, brainValue = true;
  bool refreshReceipt = false, refreshValue = true;
  suite.expect(SwitchboardRingTestAccess::generate(board, portal), "switchboard_ring_owner_admits_reset_candidate");
  board.whenRingsReady(123, [&](bool ready) { brainReceipt = true; brainValue = ready; });
  board.whenRingsReady(123, [&](bool ready) { refreshReceipt = true; refreshValue = ready; },
                       Switchboard::RingConsumer::containerRefresh);
  suite.expect(waitForWorkerGate(), "switchboard_ring_owner_holds_reset_candidate");
  SwitchboardRingTestAccess::detachFakePrograms(board, router, ingress);
  board.resetState();
  suite.expect(brainReceipt && !brainValue && refreshReceipt && !refreshValue && fakeKernel.noPublication(),
               "switchboard_ring_owner_reset_cancels_each_consumer_before_late_worker_result");
  fakeKernel.release();
  suite.expect(ring.runUntil([&] { return fakeKernel.allCreatedInnerClosed(); }, 1500),
               "switchboard_ring_owner_drains_late_reset_result");
  suite.expect(fakeKernel.allCreatedInnerClosed(), "switchboard_ring_owner_reset_closes_unpublished_late_inner_map");
  suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_ring_owner_reset_quiesces_preparation_before_ring_shutdown");
}

enum class PublicationFailure { Inner, Outer, Metadata };

static void runOwnerFailuresRetry(TestSuite& suite, PublicationFailure failure)
{
  TestRing ring = {};
  BPFProgram router = {}, ingress = {};
  EthDevice eth = {};
  Switchboard board(eth);
  SwitchboardRingTestAccess::installPrograms(board, router, ingress);
  auto *portal = SwitchboardRingTestAccess::addPortal(board, 0x01020304u);
  fakeKernel.reset();
  if (failure == PublicationFailure::Inner) fakeKernel.failInner = true;
  if (failure == PublicationFailure::Outer) fakeKernel.failOuter = true;
  if (failure == PublicationFailure::Metadata) fakeKernel.failMetadata = true;
  SwitchboardRingTestAccess::seedRevision(board, 123);
  bool failedReceipt = false, failedValue = true;
  suite.expect(SwitchboardRingTestAccess::generate(board, portal), "switchboard_ring_owner_admits_failure_candidate");
  board.whenRingsReady(123, [&](bool ready) { failedReceipt = true; failedValue = ready; });
  const bool failedAsExpected = ring.runUntil([&] { return failedReceipt; }) && !failedValue &&
                                SwitchboardRingTestAccess::revisionsEmpty(board);
  const bool noOuterPublication = fakeKernel.noPublication();
  suite.expect(failedAsExpected &&
                   (failure == PublicationFailure::Inner ? noOuterPublication : !noOuterPublication),
               failure == PublicationFailure::Inner ? "switchboard_ring_owner_inner_failure_reports_false_and_clears_revision" :
               failure == PublicationFailure::Outer ? "switchboard_ring_owner_outer_failure_reports_false_and_clears_revision" :
                                                    "switchboard_ring_owner_metadata_failure_reports_false_and_clears_revision");
  fakeKernel.failInner = false;
  fakeKernel.failOuter = false;
  fakeKernel.failMetadata = false;
  fakeKernel.clearPublications();
  bool retryReceipt = false, retryValue = false;
  suite.expect(SwitchboardRingTestAccess::generate(board, portal), "switchboard_ring_owner_retries_failed_generation");
  board.whenRingsReady(123, [&](bool ready) { retryReceipt = true; retryValue = ready; });
  suite.expect(ring.runUntil([&] { return retryReceipt; }) && retryValue && fakeKernel.published().size() == 2,
               failure == PublicationFailure::Inner ? "switchboard_ring_owner_inner_failure_retry_publishes" :
               failure == PublicationFailure::Outer ? "switchboard_ring_owner_outer_failure_retry_publishes" :
                                                    "switchboard_ring_owner_metadata_failure_retry_publishes");
  suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_ring_owner_quiesces_preparation_before_ring_shutdown");
  SwitchboardRingTestAccess::detachFakePrograms(board, router, ingress);
}

int main()
{
  TestSuite suite = {};
  runOwnerPublicationSuccess(suite);
  runOwnerStaleGeneration(suite);
  runOwnerResetCancelsLateWorker(suite);
  runOwnerFailuresRetry(suite, PublicationFailure::Inner);
  runOwnerFailuresRetry(suite, PublicationFailure::Outer);
  runOwnerFailuresRetry(suite, PublicationFailure::Metadata);
  runQuicCidResetCancelsPending(suite);
  runQuicCidEmptyAdoptedMap(suite);
  runQuicCidTwoProgramCoalescing(suite);
  runQuicCidSparseReconciliation(suite);
  runQuicCidMapReplacementDuringScan(suite);
  runQuicCidCpuWorkload(suite);
  dprintf(STDERR_FILENO, "QUIC_RECONCILIATION_RESULT failed_assertions=%d\n", suite.failed);
  return suite.failed == 0 ? 0 : 1;
}
