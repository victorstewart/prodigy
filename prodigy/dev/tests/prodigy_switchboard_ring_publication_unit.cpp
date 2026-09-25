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
#include <map>
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
  uint64_t routingDelayUs = 0;
  uint32_t routingOperations = 0;
  uint32_t routingUpdates = 0;
  uint32_t routingDeletes = 0;
  std::unordered_map<int, uint32_t> routingLookups = {};
  bool failRouting = false;
  bool failRoutingLookup = false;
  bool failRoutingNext = false;
  bool failRoutingUpdate = false;
  bool failRoutingDelete = false;
  bool requireRetiredPortalsBeforeRingPublication = false;
  bool retiredPortalPresentAtRingPublication = false;
  std::vector<std::string> retiredPortalKeys = {};
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
  std::vector<uint32_t> combinedRoutingOperationBatches = {};
  uint64_t lastQuicCallbackSerial = 0;
  uint64_t lastCombinedRoutingCallbackSerial = 0;
  uint32_t quicMapInfoQueries = 0;
  std::unordered_map<uint32_t, std::map<std::string, std::string>> routingMaps = {};
  std::unordered_map<int, uint32_t> routingMapIDs = {};

  void reset(void)
  {
    std::lock_guard lock(mutex);
    quicDelayUs = quicSyscallCostUs;
    routingDelayUs = 0;
    routingOperations = 0;
    routingUpdates = routingDeletes = 0;
    routingLookups.clear();
    failRouting = false;
    failRoutingLookup = false;
    failRoutingNext = false;
    failRoutingUpdate = false;
    failRoutingDelete = false;
    requireRetiredPortalsBeforeRingPublication = false;
    retiredPortalPresentAtRingPublication = false;
    retiredPortalKeys.clear();
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
    combinedRoutingOperationBatches.clear();
    lastQuicCallbackSerial = 0;
    lastCombinedRoutingCallbackSerial = 0;
    quicMapInfoQueries = 0;
    routingMaps.clear();
    routingMapIDs.clear();
  }

  uint32_t mapIDForFD(int fd) const
  {
    if (fd == 7021) return routerQuicMapID;
    if (fd == 7022) return ingressQuicMapID;
    if (const auto found = routingMapIDs.find(fd); found != routingMapIDs.end()) return found->second;
    if (fd == 7001 || fd == 7002 || (fd >= 7011 && fd <= 7052)) return uint32_t(80000 + fd);
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

  void replaceRoutingMap(int fd, uint32_t id)
  {
    std::lock_guard lock(mutex);
    routingMapIDs.insert_or_assign(fd, id);
    routingMaps[id].clear();
  }

  void clearRoutingTrace(void)
  {
    std::lock_guard lock(mutex);
    routingOperations = routingUpdates = routingDeletes = 0;
    routingLookups.clear();
  }

  template <typename Key, typename Value>
  void seedRouting(int fd, const Key& key, const Value& value)
  {
    std::lock_guard lock(mutex);
    routingMaps[mapIDForFD(fd)].insert_or_assign(
        std::string(reinterpret_cast<const char*>(&key), sizeof(key)),
        std::string(reinterpret_cast<const char*>(&value), sizeof(value)));
  }

  template <typename Key>
  bool routingContains(int fd, const Key& key)
  {
    std::lock_guard lock(mutex);
    const auto map = routingMaps.find(mapIDForFD(fd));
    return map != routingMaps.end() && map->second.contains(std::string(reinterpret_cast<const char*>(&key), sizeof(key)));
  }

  void requirePortalRetirementBeforeRingPublication(const portal_definition& first,
                                                    const portal_definition& second)
  {
    std::lock_guard lock(mutex);
    requireRetiredPortalsBeforeRingPublication = true;
    retiredPortalPresentAtRingPublication = false;
    retiredPortalKeys = {
        std::string(reinterpret_cast<const char*>(&first), sizeof(first)),
        std::string(reinterpret_cast<const char*>(&second), sizeof(second))};
  }

  bool retiredPortalsAbsentAtAllRingPublications(void)
  {
    std::lock_guard lock(mutex);
    return !retiredPortalPresentAtRingPublication;
  }

  template <typename Key, typename Value>
  bool routingValueEquals(int fd, const Key& key, const Value& value)
  {
    std::lock_guard lock(mutex);
    const auto map = routingMaps.find(mapIDForFD(fd));
    if (map == routingMaps.end()) return false;
    const auto found = map->second.find(std::string(reinterpret_cast<const char*>(&key), sizeof(key)));
    return found != map->second.end() && found->second ==
        std::string(reinterpret_cast<const char*>(&value), sizeof(value));
  }

  uint32_t routingLookupCount(int fd)
  {
    std::lock_guard lock(mutex);
    return routingLookups[fd];
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
    combinedRoutingOperationBatches.clear();
    lastQuicCallbackSerial = 0;
    lastCombinedRoutingCallbackSerial = 0;
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
    noteCombinedRoutingOperation();
  }

  void noteRoutingOperation(void)
  {
    noteCombinedRoutingOperation();
  }

  void noteCombinedRoutingOperation(void)
  {
    if (combinedRoutingOperationBatches.empty() || timeoutCallbackSerial != lastCombinedRoutingCallbackSerial)
      combinedRoutingOperationBatches.push_back(0);
    combinedRoutingOperationBatches.back() += 1;
    lastCombinedRoutingCallbackSerial = timeoutCallbackSerial;
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

  uint32_t largestCombinedRoutingOperationBatch(void)
  {
    std::lock_guard lock(mutex);
    uint32_t largest = 0;
    for (uint32_t count : combinedRoutingOperationBatches) largest = std::max(largest, count);
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
static constexpr int routerTargetMapFD = 7031;
static constexpr int ingressTargetMapFD = 7032;
static constexpr int routerEgressMapFD = 7041;
static constexpr int ingressEgressMapFD = 7042;
static constexpr int routerEgress4MapFD = 7051;
static constexpr int ingressEgress4MapFD = 7052;

static bool isRoutingMapFD(int fd)
{
  return fd == routerPortalMapFD || fd == ingressPortalMapFD ||
         fd == routerTargetMapFD || fd == ingressTargetMapFD ||
         fd == routerEgressMapFD || fd == ingressEgressMapFD ||
         fd == routerEgress4MapFD || fd == ingressEgress4MapFD;
}

static size_t routingKeySize(int fd)
{
  if (fd == routerPortalMapFD || fd == ingressPortalMapFD) return sizeof(portal_definition);
  if (fd == routerTargetMapFD || fd == ingressTargetMapFD) return sizeof(switchboard_wormhole_target_key);
  if (fd == routerEgressMapFD || fd == ingressEgressMapFD) return sizeof(switchboard_wormhole_egress_key);
  return sizeof(switchboard_wormhole_egress4_key);
}

static size_t routingValueSize(int fd)
{
  if (fd == routerPortalMapFD || fd == ingressPortalMapFD) return sizeof(portal_meta);
  if (fd == routerTargetMapFD || fd == ingressTargetMapFD) return sizeof(__u16);
  return sizeof(switchboard_wormhole_egress_binding);
}

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
    fakeKernel.routingOperations += 1;
    fakeKernel.routingUpdates += 1;
    fakeKernel.noteRoutingOperation();
    if (fakeKernel.requireRetiredPortalsBeforeRingPublication)
    {
      const int portalFD = fd == routerRingMapFD ? routerPortalMapFD : ingressPortalMapFD;
      const auto maps = fakeKernel.routingMaps.find(fakeKernel.mapIDForFD(portalFD));
      if (maps != fakeKernel.routingMaps.end())
        for (const auto& retired : fakeKernel.retiredPortalKeys)
          if (maps->second.contains(retired)) fakeKernel.retiredPortalPresentAtRingPublication = true;
    }
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

  if (isRoutingMapFD(fd))
  {
    if (fakeKernel.routingDelayUs) std::this_thread::sleep_for(std::chrono::microseconds(fakeKernel.routingDelayUs));
    std::lock_guard lock(fakeKernel.mutex);
    fakeKernel.routingOperations += 1;
    fakeKernel.routingUpdates += 1;
    fakeKernel.noteRoutingOperation();
    if ((fakeKernel.failMetadata && (fd == routerPortalMapFD || fd == ingressPortalMapFD)) ||
        fakeKernel.failRouting || fakeKernel.failRoutingUpdate)
    {
      errno = EIO;
      return -1;
    }
    const std::string rawKey(static_cast<const char *>(key), routingKeySize(fd));
    const std::string rawValue(static_cast<const char *>(value), routingValueSize(fd));
    fakeKernel.routingMaps[fakeKernel.mapIDForFD(fd)].insert_or_assign(rawKey, rawValue);
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
  const bool targets = name != nullptr && std::strcmp(name, "wh_targets") == 0;
  const bool egress = name != nullptr && std::strcmp(name, "wh_egress") == 0;
  const bool egress4 = name != nullptr && std::strcmp(name, "wh_egress4") == 0;
  if (program == routerRingMapFD) return reinterpret_cast<struct bpf_map *>(rings ? uintptr_t(routerRingMapFD) : quic ? uintptr_t(routerQuicMapFD) : targets ? uintptr_t(routerTargetMapFD) : egress ? uintptr_t(routerEgressMapFD) : egress4 ? uintptr_t(routerEgress4MapFD) : uintptr_t(routerPortalMapFD));
  if (program == ingressRingMapFD) return reinterpret_cast<struct bpf_map *>(rings ? uintptr_t(ingressRingMapFD) : quic ? uintptr_t(ingressQuicMapFD) : targets ? uintptr_t(ingressTargetMapFD) : egress ? uintptr_t(ingressEgressMapFD) : egress4 ? uintptr_t(ingressEgress4MapFD) : uintptr_t(ingressPortalMapFD));
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
  if ((fd == routerRingMapFD || fd == ingressRingMapFD) && info != nullptr && infoLen != nullptr && *infoLen >= sizeof(bpf_map_info))
  {
    std::lock_guard lock(fakeKernel.mutex);
    fakeKernel.routingOperations += 1;
    fakeKernel.noteRoutingOperation();
    auto *mapInfo = static_cast<bpf_map_info *>(info);
    *mapInfo = {};
    mapInfo->id = fakeKernel.mapIDForFD(fd);
    mapInfo->type = BPF_MAP_TYPE_ARRAY_OF_MAPS;
    mapInfo->key_size = sizeof(uint32_t);
    mapInfo->value_size = sizeof(int);
    mapInfo->max_entries = MAX_PORTALS;
    return 0;
  }
  if (isRoutingMapFD(fd) && info != nullptr && infoLen != nullptr && *infoLen >= sizeof(bpf_map_info))
  {
    std::lock_guard lock(fakeKernel.mutex);
    fakeKernel.routingOperations += 1;
    fakeKernel.noteRoutingOperation();
    auto *mapInfo = static_cast<bpf_map_info *>(info);
    *mapInfo = {};
    mapInfo->id = fakeKernel.mapIDForFD(fd);
    mapInfo->type = BPF_MAP_TYPE_HASH;
    mapInfo->max_entries = 4096;
    if (fd == routerPortalMapFD || fd == ingressPortalMapFD)
    { mapInfo->key_size = sizeof(portal_definition); mapInfo->value_size = sizeof(portal_meta); }
    else if (fd == routerTargetMapFD || fd == ingressTargetMapFD)
    { mapInfo->key_size = sizeof(switchboard_wormhole_target_key); mapInfo->value_size = sizeof(__u16); }
    else if (fd == routerEgressMapFD || fd == ingressEgressMapFD)
    { mapInfo->key_size = sizeof(switchboard_wormhole_egress_key); mapInfo->value_size = sizeof(switchboard_wormhole_egress_binding); }
    else
    { mapInfo->key_size = sizeof(switchboard_wormhole_egress4_key); mapInfo->value_size = sizeof(switchboard_wormhole_egress_binding); }
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
  if (isRoutingMapFD(fd) && key != nullptr && value != nullptr)
  {
    std::lock_guard lock(fakeKernel.mutex);
    fakeKernel.routingOperations += 1;
    fakeKernel.noteRoutingOperation();
    fakeKernel.routingLookups[fd] += 1;
    if (fakeKernel.failRouting || fakeKernel.failRoutingLookup) { errno = EIO; return -1; }
    const auto& map = fakeKernel.routingMaps[fakeKernel.mapIDForFD(fd)];
    const auto found = map.find(std::string(static_cast<const char *>(key), routingKeySize(fd)));
    if (found == map.end()) { errno = ENOENT; return -1; }
    std::memcpy(value, found->second.data(), routingValueSize(fd));
    return 0;
  }
  errno = EBADF;
  return -1;
}

extern "C" int __wrap_bpf_map_get_next_key(int fd, const void *key, void *next)
{
  if (isRoutingMapFD(fd))
  {
    if (fakeKernel.routingDelayUs) std::this_thread::sleep_for(std::chrono::microseconds(fakeKernel.routingDelayUs));
    std::lock_guard lock(fakeKernel.mutex);
    fakeKernel.routingOperations += 1;
    fakeKernel.noteRoutingOperation();
    if (fakeKernel.failRouting || fakeKernel.failRoutingNext) { errno = EIO; return -1; }
    const auto& map = fakeKernel.routingMaps[fakeKernel.mapIDForFD(fd)];
    auto found = key == nullptr ? map.begin() : map.upper_bound(std::string(static_cast<const char *>(key), routingKeySize(fd)));
    if (found == map.end()) { errno = ENOENT; return -1; }
    std::memcpy(next, found->first.data(), routingKeySize(fd));
    return 0;
  }
  errno = EBADF;
  return -1;
}

extern "C" int __wrap_bpf_map_delete_elem(int fd, const void *key)
{
  if (isRoutingMapFD(fd))
  {
    if (fakeKernel.routingDelayUs) std::this_thread::sleep_for(std::chrono::microseconds(fakeKernel.routingDelayUs));
    std::lock_guard lock(fakeKernel.mutex);
    fakeKernel.routingOperations += 1;
    fakeKernel.routingDeletes += 1;
    fakeKernel.noteRoutingOperation();
    if (fakeKernel.failRouting || fakeKernel.failRoutingDelete) { errno = EIO; return -1; }
    auto& map = fakeKernel.routingMaps[fakeKernel.mapIDForFD(fd)];
    if (map.erase(std::string(static_cast<const char *>(key), routingKeySize(fd))) == 0) { errno = ENOENT; return -1; }
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
    portal->isQuic = false;
    portal->slot = 9;
    auto *wormhole = new switchboard_runtime::Wormhole();
    wormhole->containerID = containerID;
    wormhole->port = uint16_t(8000 + (containerID & 0xFF));
    wormhole->proto = IPPROTO_TCP;
    wormhole->ownerGeneration = 1;
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

  static bool targetKey(const Switchboard& board, const SwitchboardPortal *portal,
                        uint32_t containerID, switchboard_wormhole_target_key& key)
  {
    return board.buildWormholeTargetKey(portal, containerID, key);
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
  // Each active callback revalidates its current map once. The only extra
  // query is the transition to the second program within the same callback.
  // Count actual callbacks: elapsed-time yields need not consume all 32 ops.
  const size_t initialRoutingTurns = fakeKernel.quicOperationBatches.size();
  suite.expect(initialMapInfoQueries >= 2 && initialMapInfoQueries >= initialRoutingTurns &&
                   initialMapInfoQueries <= initialRoutingTurns + 1,
               "switchboard_quic_two_program_scan_bounds_map_identity_queries_by_turns_plus_programs");
  dprintf(STDERR_FILENO, "QUIC_RECONCILIATION_TWO_PROGRAM_METADATA_QUERIES=%u TURNS=%zu\n",
          initialMapInfoQueries, initialRoutingTurns);

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
  if (failure == PublicationFailure::Inner)
  {
    fakeKernel.failInner = true;
    fakeKernel.hold();
  }
  if (failure == PublicationFailure::Outer) fakeKernel.failOuter = true;
  if (failure == PublicationFailure::Metadata) fakeKernel.failMetadata = true;
  SwitchboardRingTestAccess::seedRevision(board, 123);
  bool failedReceipt = false, failedValue = true;
  suite.expect(SwitchboardRingTestAccess::generate(board, portal), "switchboard_ring_owner_admits_failure_candidate");
  board.whenRingsReady(123, [&](bool ready) { failedReceipt = true; failedValue = ready; });
  if (failure == PublicationFailure::Inner)
  {
    suite.expect(ring.runUntil([&] {
                   return fakeKernel.entered() &&
                          fakeKernel.quicLookupCount(routerQuicMapFD) == MAX_PORTALS * 2 &&
                          fakeKernel.quicLookupCount(ingressQuicMapFD) == MAX_PORTALS * 2;
                 }) && !failedReceipt,
                 "switchboard_ring_owner_delayed_failure_waits_until_quic_wake_finishes");
    fakeKernel.release();
  }
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
  const size_t expectedRetryPublications = failure == PublicationFailure::Inner ? 2 : 1;
  suite.expect(ring.runUntil([&] { return retryReceipt; }) && retryValue &&
                   fakeKernel.published().size() == expectedRetryPublications,
               failure == PublicationFailure::Inner ? "switchboard_ring_owner_inner_failure_retry_publishes" :
               failure == PublicationFailure::Outer ? "switchboard_ring_owner_outer_failure_retry_publishes" :
                                                    "switchboard_ring_owner_metadata_failure_retry_publishes");
  suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_ring_owner_quiesces_preparation_before_ring_shutdown");
  SwitchboardRingTestAccess::detachFakePrograms(board, router, ingress);
}

static void runNonQuicRoutingFanoutRequestDeferral(TestSuite& suite)
{
  TestRing ring = {};
  BPFProgram router = {}, ingress = {};
  EthDevice eth = {};
  Switchboard board(eth);
  SwitchboardRingTestAccess::installPrograms(board, router, ingress);
  fakeKernel.reset();
  fakeKernel.routingDelayUs = 150;
  for (uint32_t index = 0; index < 13; ++index)
  {
    auto *portal = SwitchboardRingTestAccess::addPortal(board, 0x03000000u + index);
    portal->slot = index;
    portal->port = uint16_t(40000 + index);
    suite.expect(SwitchboardRingTestAccess::generate(board, portal),
                 "switchboard_nonquic_fanout_admits_portal_ring");
  }
  bool receipt = false, receiptValue = false;
  std::vector<uint64_t> submissionIntervals = {};
  board.whenRingsReady(401, [&](bool ready) { receipt = true; receiptValue = ready; });
  for (uint32_t request = 0; request < 30; ++request)
  {
    const auto submitted = std::chrono::steady_clock::now();
    SwitchboardRingTestAccess::syncPeerRuntime(board, router);
    SwitchboardRingTestAccess::syncPeerRuntime(board, ingress);
    submissionIntervals.push_back(uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - submitted).count()));
  }
  suite.expect(fakeKernel.routingOperations == 0 && !receipt,
               "switchboard_nonquic_fanout_coalesces_requests_without_inline_map_work");
  std::vector<uint64_t> controlIntervals = {};
  const bool settled = ring.runUntilWithControl([&] { return receipt; }, controlIntervals, 1500);
  std::vector<uint64_t> sortedControlIntervals = controlIntervals;
  std::sort(sortedControlIntervals.begin(), sortedControlIntervals.end());
  const uint64_t p95 = sortedControlIntervals.empty() ? UINT64_MAX : sortedControlIntervals[(sortedControlIntervals.size() * 95) / 100];
  const uint64_t maximum = sortedControlIntervals.empty() ? UINT64_MAX : sortedControlIntervals.back();
  suite.expect(settled && receiptValue && controlIntervals.size() >= 30 && p95 < 10'000 && maximum < 50'000,
               "switchboard_nonquic_fanout_receipts_after_bounded_convergence_with_control_continuity");
  suite.expect(fakeKernel.largestCombinedRoutingOperationBatch() <= 32,
               "switchboard_nonquic_and_quic_share_at_most_thirty_two_map_operations_per_callback");
  dprintf(STDERR_FILENO, "NONQUIC_FANOUT_CONTROL_SAMPLES=%zu P95_US=%llu MAX_US=%llu OPS=%u\n",
          controlIntervals.size(), static_cast<unsigned long long>(p95), static_cast<unsigned long long>(maximum),
          fakeKernel.routingOperations);
  dprintf(STDERR_FILENO, "NONQUIC_FANOUT_MAX_COMBINED_OPERATIONS=%u\n", fakeKernel.largestCombinedRoutingOperationBatch());
  printSamples("NONQUIC_FANOUT_CONTROL_RAW_US=", controlIntervals);
  printSamples("NONQUIC_FANOUT_SUBMISSION_RAW_US=", submissionIntervals);
  fakeKernel.clearRoutingTrace();
  bool warmReceipt = false, warmValue = false;
  board.whenRingsReady(402, [&](bool ready) { warmReceipt = true; warmValue = ready; });
  for (uint32_t request = 0; request < 30; ++request)
  {
    SwitchboardRingTestAccess::syncPeerRuntime(board, router);
    SwitchboardRingTestAccess::syncPeerRuntime(board, ingress);
  }
  suite.expect(ring.runUntil([&] { return warmReceipt; }) && warmValue &&
                   fakeKernel.routingUpdates == 0 && fakeKernel.routingDeletes == 0,
               "switchboard_nonquic_fanout_warm_thirty_replays_make_zero_map_mutations");
  dprintf(STDERR_FILENO, "NONQUIC_FANOUT_WARM_UPDATES=%u DELETES=%u\n", fakeKernel.routingUpdates, fakeKernel.routingDeletes);
  suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_nonquic_fanout_drains_before_teardown");
  SwitchboardRingTestAccess::detachFakePrograms(board, router, ingress);
}

static void runNonQuicRoutingSlowMapDeadline(TestSuite& suite)
{
  constexpr uint32_t workloadCount = 30;
  constexpr uint32_t portalCount = 13;
  std::vector<uint64_t> controlIntervals = {};
  uint32_t completedWorkloads = 0;
  bool everyReceiptWasCurrent = true;
  bool everyReceiptObservedAppliedState = true;
  bool everyWorkloadDeferredItsReceipt = true;
  bool everyWorkloadRespectedOperationBudget = true;

  for (uint32_t workload = 0; workload < workloadCount; ++workload)
  {
    TestRing ring = {};
    BPFProgram router = {}, ingress = {};
    EthDevice eth = {};
    Switchboard board(eth);
    SwitchboardRingTestAccess::installPrograms(board, router, ingress);
    fakeKernel.reset();
    // The artificial delay covers the routing hash-map get-next, update, and
    // delete hooks.  Ring-array publication and map-info calls are not
    // delayed. A count-only 32-operation continuation still blocks the
    // control timer for roughly 32ms here; the elapsed deadline must yield.
    fakeKernel.routingDelayUs = 1'000;
    fakeKernel.quicDelayUs = 0;
    std::vector<std::pair<portal_definition, portal_meta>> expectedPortals = {};
    for (uint32_t index = 0; index < portalCount; ++index)
    {
      auto *portal = SwitchboardRingTestAccess::addPortal(board,
          0x03010000u + workload * portalCount + index);
      portal->slot = index;
      portal->port = uint16_t(41000 + index);
      suite.expect(SwitchboardRingTestAccess::generate(board, portal),
                   "switchboard_nonquic_slow_map_admits_portal_ring");
      expectedPortals.emplace_back(portal->generatePortalDefinition(),
          portal_meta{.flags = 0, .slot = portal->slot});
    }

    bool receipt = false, receiptValue = false;
    board.whenRingsReady(600 + workload, [&](bool ready) {
      receipt = true;
      receiptValue = ready;
    });
    SwitchboardRingTestAccess::syncPeerRuntime(board, router);
    SwitchboardRingTestAccess::syncPeerRuntime(board, ingress);
    const bool deferred = !receipt && fakeKernel.routingOperations == 0;
    everyWorkloadDeferredItsReceipt &= deferred;
    suite.expect(deferred,
                 "switchboard_nonquic_slow_map_does_not_ack_before_applied_reconciliation");

    std::vector<uint64_t> workloadControlIntervals = {};
    const bool settled = ring.runUntilWithControl([&] { return receipt; }, workloadControlIntervals, 1'500);
    controlIntervals.insert(controlIntervals.end(), workloadControlIntervals.begin(), workloadControlIntervals.end());
    const bool currentReceipt = settled && receiptValue;
    bool appliedCurrentState = currentReceipt;
    for (const auto& [definition, meta] : expectedPortals)
    {
      appliedCurrentState &= fakeKernel.routingValueEquals(routerPortalMapFD, definition, meta) &&
                             fakeKernel.routingValueEquals(ingressPortalMapFD, definition, meta);
    }
    const auto publications = fakeKernel.published();
    appliedCurrentState &= publications.size() == portalCount * 2;
    for (const auto& publication : publications)
      appliedCurrentState &= FakeBPFKernel::innerMapComplete(publication);
    everyReceiptWasCurrent &= currentReceipt;
    everyReceiptObservedAppliedState &= appliedCurrentState;
    everyWorkloadRespectedOperationBudget &= fakeKernel.largestCombinedRoutingOperationBatch() <= 32;
    suite.expect(currentReceipt,
                 "switchboard_nonquic_slow_map_receipt_waits_for_current_applied_reconciliation");
    suite.expect(appliedCurrentState,
                 "switchboard_nonquic_slow_map_receipt_observes_all_current_portal_maps_and_complete_rings");
    suite.expect(fakeKernel.largestCombinedRoutingOperationBatch() <= 32,
                 "switchboard_nonquic_slow_map_keeps_shared_map_operation_ceiling");
    completedWorkloads += currentReceipt ? 1 : 0;
    suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
                 "switchboard_nonquic_slow_map_drains_before_workload_teardown");
    SwitchboardRingTestAccess::detachFakePrograms(board, router, ingress);
  }

  std::vector<uint64_t> sortedControlIntervals = controlIntervals;
  std::sort(sortedControlIntervals.begin(), sortedControlIntervals.end());
  const uint64_t p95 = sortedControlIntervals.empty() ? UINT64_MAX :
      sortedControlIntervals[(sortedControlIntervals.size() * 95) / 100];
  const uint64_t maximum = sortedControlIntervals.empty() ? UINT64_MAX : sortedControlIntervals.back();
  const bool timingAndSamplingPassed = controlIntervals.size() >= workloadCount &&
                                       p95 < 3'000 && maximum < 50'000;
  const bool passed = completedWorkloads == workloadCount && everyReceiptWasCurrent &&
                      everyReceiptObservedAppliedState &&
                      everyWorkloadDeferredItsReceipt && everyWorkloadRespectedOperationBudget &&
                      timingAndSamplingPassed;
  suite.expect(passed,
               "switchboard_nonquic_slow_map_elapsed_deadline_preserves_control_p95");
  dprintf(STDERR_FILENO,
          "NONQUIC_SLOW_MAP_WORKLOADS=%u DELAY_US=1000 CONTROL_SAMPLES=%zu P95_US=%llu MAX_US=%llu FAILED=%u\n",
          completedWorkloads, controlIntervals.size(), static_cast<unsigned long long>(p95),
          static_cast<unsigned long long>(maximum), unsigned(!everyReceiptWasCurrent ||
          !everyReceiptObservedAppliedState || !everyWorkloadDeferredItsReceipt ||
          !everyWorkloadRespectedOperationBudget || completedWorkloads != workloadCount ||
          !timingAndSamplingPassed));
  printSamples("NONQUIC_SLOW_MAP_CONTROL_RAW_US=", controlIntervals);
}

static void runNonQuicRoutingAdoptionSupersessionAndReplacement(TestSuite& suite)
{
  TestRing ring = {};
  BPFProgram router = {}, ingress = {};
  EthDevice eth = {};
  Switchboard board(eth);
  SwitchboardRingTestAccess::installPrograms(board, router, ingress);
  fakeKernel.reset();
  auto *portal = SwitchboardRingTestAccess::addPortal(board, 0x03000101u);
  portal->slot = 41;
  suite.expect(SwitchboardRingTestAccess::generate(board, portal),
               "switchboard_nonquic_adoption_admits_portal_ring");
  const portal_definition desired = portal->generatePortalDefinition();
  portal_definition stale = desired;
  stale.port ^= 1;
  const portal_meta desiredMeta = {.flags = 0, .slot = portal->slot};
  const portal_meta staleMeta = {.flags = 0, .slot = 777};
  fakeKernel.seedRouting(routerPortalMapFD, desired, desiredMeta);
  fakeKernel.seedRouting(routerPortalMapFD, stale, staleMeta);

  bool adoptionReceipt = false, adoptionValue = false;
  board.whenRingsReady(510, [&](bool ready) { adoptionReceipt = true; adoptionValue = ready; });
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  SwitchboardRingTestAccess::syncPeerRuntime(board, ingress);
  suite.expect(ring.runUntil([&] { return adoptionReceipt; }) && adoptionValue &&
                   fakeKernel.routingValueEquals(routerPortalMapFD, desired, desiredMeta) &&
                   !fakeKernel.routingContains(routerPortalMapFD, stale),
               "switchboard_nonquic_adoption_preserves_valid_entry_and_deletes_stale_entry");

  // Replace an already converged map before seeding the next adoption; an
  // external edit to a still-owned identity does not invalidate its mirror.
  fakeKernel.replaceRoutingMap(routerPortalMapFD, 99000);
  fakeKernel.seedRouting(routerPortalMapFD, desired, desiredMeta);
  fakeKernel.seedRouting(routerPortalMapFD, stale, staleMeta);
  fakeKernel.routingDelayUs = 50;
  for (uint16_t index = 2; index < 42; ++index)
  {
    portal_definition extra = stale;
    extra.port ^= index;
    fakeKernel.seedRouting(routerPortalMapFD, extra, staleMeta);
  }
  fakeKernel.clearRoutingTrace();
  bool replacementReceipt = false, replacementValue = false;
  board.whenRingsReady(512, [&](bool ready) { replacementReceipt = true; replacementValue = ready; });
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  bool replacedDuringAdoption = false;
  std::vector<uint64_t> adoptionControl = {};
  suite.expect(ring.runUntilWithControl([&] { return replacementReceipt; }, adoptionControl, 1500, [&] {
                 if (!replacedDuringAdoption && fakeKernel.routingLookupCount(routerPortalMapFD) != 0)
                 {
                   fakeKernel.replaceRoutingMap(routerPortalMapFD, 99001);
                   fakeKernel.seedRouting(routerPortalMapFD, desired, desiredMeta);
                   fakeKernel.seedRouting(routerPortalMapFD, stale, staleMeta);
                   for (uint16_t index = 2; index < 42; ++index)
                   {
                     portal_definition extra = stale;
                     extra.port ^= index;
                     fakeKernel.seedRouting(routerPortalMapFD, extra, staleMeta);
                   }
                   SwitchboardRingTestAccess::syncPeerRuntime(board, router);
                   replacedDuringAdoption = true;
                 }
               }) && replacementValue && replacedDuringAdoption &&
                   fakeKernel.routingValueEquals(routerPortalMapFD, desired, desiredMeta) &&
                   !fakeKernel.routingContains(routerPortalMapFD, stale),
               "switchboard_nonquic_map_replacement_during_partial_adoption_reconciles_valid_and_stale_entries");

  bool obsoleteReceipt = false;
  bool latestReceipt = false, latestValue = false;
  board.whenRingsReady(511, [&](bool) { obsoleteReceipt = true; });
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  portal->port = 8443;
  const portal_definition replacement = portal->generatePortalDefinition();
  board.whenRingsReady(511, [&](bool ready) { latestReceipt = true; latestValue = ready; });
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  suite.expect(ring.runUntil([&] { return latestReceipt; }) && latestValue && !obsoleteReceipt &&
                   fakeKernel.routingContains(routerPortalMapFD, replacement) &&
                   !fakeKernel.routingContains(routerPortalMapFD, desired),
               "switchboard_nonquic_changed_state_supersedes_pending_receipt_with_latest_map_contents");

  suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_nonquic_adoption_drains_before_teardown");
  SwitchboardRingTestAccess::detachFakePrograms(board, router, ingress);
}

enum class RoutingFailure { Lookup, Next, Update, Delete };

static void runNonQuicRoutingFailureRetry(TestSuite& suite, RoutingFailure failure)
{
  TestRing ring = {};
  BPFProgram router = {}, ingress = {};
  EthDevice eth = {};
  Switchboard board(eth);
  SwitchboardRingTestAccess::installPrograms(board, router, ingress);
  fakeKernel.reset();
  auto *portal = SwitchboardRingTestAccess::addPortal(board, 0x03000201u);
  portal->slot = 51;
  suite.expect(SwitchboardRingTestAccess::generate(board, portal),
               "switchboard_nonquic_failure_admits_portal_ring");
  portal_definition stale = portal->generatePortalDefinition();
  stale.port ^= 1;
  fakeKernel.seedRouting(routerPortalMapFD, stale, portal_meta{.flags = 0, .slot = 778});
  fakeKernel.failRoutingLookup = failure == RoutingFailure::Lookup;
  fakeKernel.failRoutingNext = failure == RoutingFailure::Next;
  fakeKernel.failRoutingUpdate = failure == RoutingFailure::Update;
  fakeKernel.failRoutingDelete = failure == RoutingFailure::Delete;
  bool failedReceipt = false, failedValue = true;
  board.whenRingsReady(520, [&](bool ready) { failedReceipt = true; failedValue = ready; });
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  suite.expect(ring.runUntil([&] { return failedReceipt; }) && !failedValue,
               failure == RoutingFailure::Lookup ? "switchboard_nonquic_lookup_failure_returns_false_receipt" :
               failure == RoutingFailure::Next ? "switchboard_nonquic_getnext_failure_returns_false_receipt" :
               failure == RoutingFailure::Update ? "switchboard_nonquic_update_failure_returns_false_receipt" :
                                                    "switchboard_nonquic_delete_failure_returns_false_receipt");
  fakeKernel.clearRoutingTrace();
  const auto noRetryDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(10);
  suite.expect(ring.runUntil([&] { return std::chrono::steady_clock::now() >= noRetryDeadline; }, 100) &&
                   fakeKernel.routingOperations == 0,
               "switchboard_nonquic_failure_does_not_busy_retry_without_new_request");
  fakeKernel.failRoutingLookup = fakeKernel.failRoutingNext = false;
  fakeKernel.failRoutingUpdate = fakeKernel.failRoutingDelete = false;
  bool retryReceipt = false, retryValue = false;
  board.whenRingsReady(521, [&](bool ready) { retryReceipt = true; retryValue = ready; });
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  suite.expect(ring.runUntil([&] { return retryReceipt; }) && retryValue,
               "switchboard_nonquic_explicit_request_retries_failed_map_reconciliation");
  suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_nonquic_failure_retry_drains_before_teardown");
  SwitchboardRingTestAccess::detachFakePrograms(board, router, ingress);
}

static void runNonQuicRoutingCancellation(TestSuite& suite)
{
  TestRing ring = {};
  BPFProgram router = {}, ingress = {};
  EthDevice eth = {};
  Switchboard board(eth);
  SwitchboardRingTestAccess::installPrograms(board, router, ingress);
  fakeKernel.reset();
  auto *portal = SwitchboardRingTestAccess::addPortal(board, 0x03000301u);
  suite.expect(SwitchboardRingTestAccess::generate(board, portal),
               "switchboard_nonquic_cancellation_admits_portal_ring");
  bool receipt = false, receiptValue = true;
  board.whenRingsReady(530, [&](bool ready) { receipt = true; receiptValue = ready; });
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  board.resetState();
  const bool blocked = !board.quiesceRingPreparationForExec();
  suite.expect(receipt && !receiptValue && blocked &&
                   ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_nonquic_cancellation_fails_receipt_and_drains_terminal_wake");
  SwitchboardRingTestAccess::detachFakePrograms(board, router, ingress);
}

static void runNonQuicPortalRetirementBeforeRingReassignment(TestSuite& suite)
{
  TestRing ring = {};
  BPFProgram router = {}, ingress = {};
  EthDevice eth = {};
  Switchboard board(eth);
  SwitchboardRingTestAccess::installPrograms(board, router, ingress);
  fakeKernel.reset();
  auto *first = SwitchboardRingTestAccess::addPortal(board, 0x03000401u);
  auto *second = SwitchboardRingTestAccess::addPortal(board, 0x03000402u);
  first->slot = 9; first->port = 4401;
  second->slot = 10; second->port = 4402;
  suite.expect(SwitchboardRingTestAccess::generate(board, first) &&
                   SwitchboardRingTestAccess::generate(board, second),
               "switchboard_nonquic_retirement_admits_two_initial_portal_rings");
  const portal_definition firstDefinition = first->generatePortalDefinition();
  const portal_definition secondDefinition = second->generatePortalDefinition();
  bool initialReceipt = false, initialValue = false;
  board.whenRingsReady(540, [&](bool ready) { initialReceipt = true; initialValue = ready; });
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  SwitchboardRingTestAccess::syncPeerRuntime(board, ingress);
  suite.expect(ring.runUntil([&] { return initialReceipt; }) && initialValue,
               "switchboard_nonquic_retirement_publishes_initial_two_portal_state");

  fakeKernel.requirePortalRetirementBeforeRingPublication(firstDefinition, secondDefinition);
  std::swap(first->slot, second->slot);
  suite.expect(SwitchboardRingTestAccess::generate(board, first) &&
                   SwitchboardRingTestAccess::generate(board, second),
               "switchboard_nonquic_retirement_admits_swapped_slot_rings");
  bool obsoleteReceipt = false;
  bool receipt = false, receiptValue = false;
  board.whenRingsReady(541, [&](bool) { obsoleteReceipt = true; });
  board.whenRingsReady(541, [&](bool ready) { receipt = true; receiptValue = ready; });
  SwitchboardRingTestAccess::syncPeerRuntime(board, router);
  SwitchboardRingTestAccess::syncPeerRuntime(board, ingress);
  suite.expect(!receipt && ring.runUntil([&] { return receipt; }) && receiptValue && !obsoleteReceipt,
               "switchboard_nonquic_retirement_holds_latest_receipt_until_reassignment_converges");
  const portal_meta firstMeta = {.flags = 0, .slot = first->slot};
  const portal_meta secondMeta = {.flags = 0, .slot = second->slot};
  switchboard_wormhole_target_key firstTarget = {}, secondTarget = {};
  const bool targetsBuilt = SwitchboardRingTestAccess::targetKey(board, first, 0x03000401u, firstTarget) &&
                            SwitchboardRingTestAccess::targetKey(board, second, 0x03000402u, secondTarget);
  const __u16 firstPort = htons(uint16_t(8000 + (0x03000401u & 0xFF)));
  const __u16 secondPort = htons(uint16_t(8000 + (0x03000402u & 0xFF)));
  suite.expect(fakeKernel.retiredPortalsAbsentAtAllRingPublications() &&
                   fakeKernel.routingValueEquals(routerPortalMapFD, firstDefinition, firstMeta) &&
                   fakeKernel.routingValueEquals(routerPortalMapFD, secondDefinition, secondMeta) &&
                   targetsBuilt &&
                   fakeKernel.routingValueEquals(routerTargetMapFD, firstTarget, firstPort) &&
                   fakeKernel.routingValueEquals(routerTargetMapFD, secondTarget, secondPort),
               "switchboard_nonquic_retirement_removes_old_portals_before_cid_write_then_restores_final_portals_and_targets");
  suite.expect(ring.runUntil([&] { return board.quiesceRingPreparationForExec(); }),
               "switchboard_nonquic_retirement_drains_before_teardown");
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
  runNonQuicRoutingFanoutRequestDeferral(suite);
  runNonQuicRoutingSlowMapDeadline(suite);
  runNonQuicRoutingAdoptionSupersessionAndReplacement(suite);
  runNonQuicRoutingFailureRetry(suite, RoutingFailure::Lookup);
  runNonQuicRoutingFailureRetry(suite, RoutingFailure::Next);
  runNonQuicRoutingFailureRetry(suite, RoutingFailure::Update);
  runNonQuicRoutingFailureRetry(suite, RoutingFailure::Delete);
  runNonQuicRoutingCancellation(suite);
  runNonQuicPortalRetirementBeforeRingReassignment(suite);
  runQuicCidResetCancelsPending(suite);
  runQuicCidEmptyAdoptedMap(suite);
  runQuicCidTwoProgramCoalescing(suite);
  runQuicCidSparseReconciliation(suite);
  runQuicCidMapReplacementDuringScan(suite);
  runQuicCidCpuWorkload(suite);
  dprintf(STDERR_FILENO, "QUIC_RECONCILIATION_RESULT failed_assertions=%d\n", suite.failed);
  return suite.failed == 0 ? 0 : 1;
}
