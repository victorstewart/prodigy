#include <includes.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/message.h>
#include <networking/multiplexer.h>
#include <networking/ring.h>

#include <prodigy/artifact.io.h>
#include <prodigy/neuron/neuron.h>

#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <mutex>
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

class TestRing final : public TimeoutDispatcher {
public:
  RingDispatcher dispatcher;
  TimeoutPacket tick = {};
  std::function<void()> tickAction = {};

  TestRing()
  {
    Ring::interfacer = &dispatcher;
    Ring::lifecycler = &dispatcher;
    Ring::exit = false;
    Ring::shuttingDown = false;
    Ring::createRing(64, 128, 8, 2, -1, -1, 8);
    tick.dispatcher = this;
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

};

struct FakeBPFKernel {
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
  std::vector<int> createdInner = {};
  std::unordered_map<int, container_id> firstEntry = {};
  std::unordered_map<int, uint32_t> innerUpdates = {};
  std::vector<Publication> publications = {};

  void reset(void)
  {
    std::lock_guard lock(mutex);
    holdInner = false;
    workerEntered = false;
    releaseInner = false;
    failInner = false;
    failOuter = false;
    failMetadata = false;
    createdInner.clear();
    firstEntry.clear();
    innerUpdates.clear();
    publications.clear();
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
  if (program == routerRingMapFD) return reinterpret_cast<struct bpf_map *>(rings ? uintptr_t(routerRingMapFD) : uintptr_t(routerPortalMapFD));
  if (program == ingressRingMapFD) return reinterpret_cast<struct bpf_map *>(rings ? uintptr_t(ingressRingMapFD) : uintptr_t(ingressPortalMapFD));
  return nullptr;
}

extern "C" int __wrap_bpf_map__fd(const struct bpf_map *map)
{
  return int(reinterpret_cast<uintptr_t>(map));
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

  static void detachFakePrograms(Switchboard& board, BPFProgram& router, BPFProgram& ingress)
  {
    board.bpf_router = nullptr;
    board.host_ingress = nullptr;
    router.obj = nullptr;
    ingress.obj = nullptr;
  }
};

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
  return suite.failed == 0 ? 0 : 1;
}
