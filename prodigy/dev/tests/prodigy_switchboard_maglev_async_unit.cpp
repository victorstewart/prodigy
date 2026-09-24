#include <includes.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/multiplexer.h>
#include <networking/ring.h>

#include <prodigy/artifact.io.h>
#include <switchboard/maglev.ring.prepare.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>
#include <unordered_map>

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

class TestRing final : public TimeoutDispatcher {
public:
  RingDispatcher dispatcher;
  TimeoutPacket tick = {}, deadline = {}, drain = {};
  std::function<void()> tickAction = {}, deadlineAction = {}, drainAction = {};
  bool shutdown = false;

  TestRing()
  {
    Ring::interfacer = &dispatcher;
    Ring::lifecycler = &dispatcher;
    Ring::exit = false;
    Ring::shuttingDown = false;
    Ring::createRing(64, 128, 8, 2, -1, -1, 8);
    tick.dispatcher = this;
    deadline.dispatcher = this;
    drain.dispatcher = this;
  }

  ~TestRing()
  {
    if (shutdown == false) Ring::shutdownForExec();
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
    if (packet == &tick && tickAction) tickAction();
    if (packet == &deadline && deadlineAction) deadlineAction();
    if (packet == &drain && drainAction) drainAction();
  }
};

class FakeMaglevMaps {
public:
  struct Map {
    std::array<container_id, RING_SIZE> entries = {};
  };

  std::mutex mutex = {};
  std::condition_variable condition = {};
  std::unordered_map<int, Map> maps = {};
  std::atomic<bool> enteredBlock = false;
  bool releaseBlock = false;
  uint32_t blockIndex = UINT32_MAX;
  uint32_t failIndex = UINT32_MAX;
  uint32_t updateCalls = 0;
  uint32_t closeCalls = 0;
  int nextFD = 101;

  SwitchboardMaglevMapBackend backend()
  {
    SwitchboardMaglevMapBackend value = {};
    value.createInnerMap = [this] {
      std::lock_guard lock(mutex);
      const int fd = nextFD++;
      maps.emplace(fd, Map {});
      return fd;
    };
    value.updateInnerMap = [this] (int fd, uint32_t index, const container_id& entry) {
      std::unique_lock lock(mutex);
      if (index == blockIndex && releaseBlock == false)
      {
        enteredBlock = true;
        condition.notify_all();
        condition.wait(lock, [&] { return releaseBlock; });
      }
      if (index == failIndex)
      {
        errno = EIO;
        return false;
      }
      auto found = maps.find(fd);
      if (found == maps.end()) return false;
      found->second.entries[index] = entry;
      ++updateCalls;
      return true;
    };
    value.closeInnerMap = [this] (int fd) {
      std::lock_guard lock(mutex);
      maps.erase(fd);
      ++closeCalls;
    };
    return value;
  }

  bool held(void)
  {
    std::lock_guard lock(mutex);
    return enteredBlock && releaseBlock == false;
  }

  void release(void)
  {
    {
      std::lock_guard lock(mutex);
      releaseBlock = true;
    }
    condition.notify_all();
  }

  bool hasEntry(int fd, uint32_t index, const container_id& expected)
  {
    std::lock_guard lock(mutex);
    auto found = maps.find(fd);
    return found != maps.end() && std::memcmp(&found->second.entries[index], &expected, sizeof(expected)) == 0;
  }

  uint32_t updates(void)
  {
    std::lock_guard lock(mutex);
    return updateCalls;
  }

  uint32_t closes(void)
  {
    std::lock_guard lock(mutex);
    return closeCalls;
  }

  bool empty(void)
  {
    std::lock_guard lock(mutex);
    return maps.empty();
  }
};

static SwitchboardMaglevRingPrepareRequest makeRequest(uint64_t generation, uint8_t datacenterPrefix)
{
  SwitchboardMaglevRingPrepareRequest request = {};
  request.generation = generation;
  request.datacenterPrefix = datacenterPrefix;
  request.endpoints = {
      {.num = 0x01020304u, .weight = 1, .hash = 0x12345678u},
      {.num = 0x05060708u, .weight = 3, .hash = 0x9abcdef0u},
  };
  return request;
}

static SwitchboardMaglevRingPrepareRequest makeEndpointRequest(uint64_t generation, size_t count)
{
  auto request = makeRequest(generation, 0xa5);
  request.endpoints.clear();
  request.endpoints.reserve(count);
  for (size_t index = 0; index < count; ++index)
  {
    request.endpoints.push_back({.num = uint32_t(index + 1), .weight = 1, .hash = uint64_t(index + 1)});
  }
  return request;
}

int main()
{
  TestSuite suite = {};
  auto markScenario = [&](const char *name, int failuresBefore) {
    dprintf(STDERR_FILENO, "SCENARIO name=%s result=%s\n", name,
            suite.failed == failuresBefore ? "PASS" : "FAIL");
  };

  // Preparing all 65,537 entries is held mid-worker. The Ring must continue
  // to dispatch its control tick until that immutable worker snapshot is let
  // through; publication belongs to the caller after this result arrives.
  // With PRODIGY_TEST_SYNCHRONOUS_MAGLEV_PREPARE this exact worker body runs on
  // the Ring thread; the watchdog opens the gate after 250 ms and this test
  // fails because no tick could have occurred while it was held.
  {
    const int failuresBefore = suite.failed;
    TestRing ring = {};
    auto executor = ProdigyArtifactIO::startOwned();
    FakeMaglevMaps maps = {};
    maps.blockIndex = RING_SIZE / 2;
    std::optional<std::vector<SwitchboardMaglevRingPrepareResult>> results = {};
    std::atomic<uint32_t> ticks = 0;
    uint32_t ticksWhileHeld = 0;
    std::vector<uint64_t> tickIntervalsUs = {};
    auto previousTick = std::chrono::steady_clock::now();
    bool timedOut = false;
    bool failed = false;
    const auto request = makeRequest(91, 0xa7);
    const auto expectedRing = MaglevHashV2::generateHashRingForEndpoints(request.endpoints);
#ifdef PRODIGY_TEST_SYNCHRONOUS_MAGLEV_PREPARE
    std::thread watchdog([&] {
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
      maps.release();
    });
#endif

    suite.expect(executor != nullptr, "switchboard_maglev_async_starts_artifact_executor");
    if (executor)
    {
      ring.tickAction = [&] {
        const auto now = std::chrono::steady_clock::now();
        tickIntervalsUs.push_back(uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(now - previousTick).count()));
        previousTick = now;
        ++ticks;
        if (maps.held())
        {
          ++ticksWhileHeld;
          if (ticksWhileHeld == 30) maps.release();
        }
        if (results.has_value()) Ring::exit = true;
        else ring.arm(ring.tick, 1);
      };
      ring.deadlineAction = [&] { timedOut = true; maps.release(); Ring::exit = true; };
      ring.arm(ring.tick, 1);
      ring.arm(ring.deadline, 1500);
      suite.expect(switchboardPrepareMaglevRingsAsync(
                       *executor, {request}, maps.backend(),
                       [&](std::vector<SwitchboardMaglevRingPrepareResult>&& completed) {
                         results.emplace(std::move(completed));
                         if (ticksWhileHeld >= 30) Ring::exit = true;
                       },
                       [&](std::exception_ptr) { failed = true; Ring::exit = true; }),
                   "switchboard_maglev_async_submits_one_batch_job");
      Ring::start();

      auto p95 = [](std::vector<uint64_t> samples) {
        std::sort(samples.begin(), samples.end());
        return samples.empty() ? UINT64_MAX : samples[(samples.size() * 95 + 99) / 100 - 1];
      };
      const uint64_t tickP95Us = p95(tickIntervalsUs);
      const uint64_t tickMaxUs = tickIntervalsUs.empty() ? UINT64_MAX :
          *std::max_element(tickIntervalsUs.begin(), tickIntervalsUs.end());
      dprintf(STDERR_FILENO,
              "METRICS scenario=maglev_async_prepare held_ticks=%u tick_n=%zu tick_p95_us=%llu tick_max_us=%llu raw_tick_intervals_us=[",
              ticksWhileHeld, tickIntervalsUs.size(), (unsigned long long)tickP95Us,
              (unsigned long long)tickMaxUs);
      for (size_t index = 0; index < tickIntervalsUs.size(); ++index)
      {
        dprintf(STDERR_FILENO, "%s%llu", index == 0 ? "" : ",", (unsigned long long)tickIntervalsUs[index]);
      }
      dprintf(STDERR_FILENO, "]\n");
      suite.expect(timedOut == false && failed == false && ticks.load() >= 30 &&
                       ticksWhileHeld >= 30 && results.has_value() && tickP95Us < 10'000 && tickMaxUs < 50'000,
                   "switchboard_maglev_async_keeps_30_ring_ticks_while_worker_is_held");
      suite.expect(results.has_value() && results->size() == 1 && (*results)[0].prepared(),
                   "switchboard_maglev_async_returns_prepared_inner_map_only_after_all_entries");
      if (results.has_value() && results->size() == 1 && (*results)[0].prepared())
      {
        const SwitchboardMaglevRingPrepareResult& result = (*results)[0];
        bool exact = result.generation == request.generation && result.ring == expectedRing;
        for (uint32_t index = 0; exact && index < RING_SIZE; ++index)
        {
          exact = maps.hasEntry(result.innerMapFD, index,
                                switchboardMaglevRingContainerID(request.datacenterPrefix, expectedRing[index]));
        }
        suite.expect(exact && maps.updates() == RING_SIZE,
                     "switchboard_maglev_async_translates_every_immutable_ring_entry");
      }
      results.reset();
      suite.expect(maps.closes() == 1, "switchboard_maglev_async_result_raii_closes_unpublished_inner_map");
      executor->stop();
      ring.drainAction = [] { Ring::exit = true; };
      Ring::exit = false;
      ring.arm(ring.drain, 10);
      Ring::start();
    }
#ifdef PRODIGY_TEST_SYNCHRONOUS_MAGLEV_PREPARE
    watchdog.join();
#endif
    markScenario("held-worker", failuresBefore);
  }

#ifdef PRODIGY_TEST_SYNCHRONOUS_MAGLEV_PREPARE
  // The fault-injection build intentionally proves this first assertion fails
  // when the identical worker body runs on the Ring thread. Do not enter the
  // later cancellation fixture, whose gate is intentionally Ring-driven.
  return suite.failed == 0 ? 0 : 1;
#endif

  // A failed entry leaves no usable result and closes its incomplete inner
  // map. The caller therefore has no object it could publish into cid_rings.
  {
    const int failuresBefore = suite.failed;
    TestRing ring = {};
    auto executor = ProdigyArtifactIO::startOwned();
    FakeMaglevMaps maps = {};
    maps.failIndex = 4096;
    std::optional<std::vector<SwitchboardMaglevRingPrepareResult>> results = {};
    bool timedOut = false;
    suite.expect(executor != nullptr, "switchboard_maglev_async_starts_failure_executor");
    if (executor)
    {
      suite.expect(switchboardPrepareMaglevRingsAsync(
                       *executor, {makeRequest(92, 0xa8)}, maps.backend(),
                       [&](std::vector<SwitchboardMaglevRingPrepareResult>&& completed) {
                         results.emplace(std::move(completed));
                         Ring::exit = true;
                       },
                       [&](std::exception_ptr) { Ring::exit = true; }),
                   "switchboard_maglev_async_submits_fixed_index_failure_job");
      ring.deadlineAction = [&] { timedOut = true; Ring::exit = true; };
      ring.arm(ring.deadline, 1500);
      Ring::start();
      suite.expect(timedOut == false && results.has_value() && results->size() == 1 &&
                       (*results)[0].innerMapFD == -1 &&
                       (*results)[0].error == SwitchboardMaglevRingPrepareResult::Error::updateInnerMap &&
                       (*results)[0].errorNumber == EIO,
                   "switchboard_maglev_async_fixed_index_failure_returns_no_publishable_result");
      suite.expect(maps.closes() == 1 && maps.empty(),
                   "switchboard_maglev_async_fixed_index_failure_closes_partial_inner_map");
      executor->stop();
      ring.drainAction = [] { Ring::exit = true; };
      Ring::exit = false;
      ring.arm(ring.drain, 10);
      Ring::start();
    }
    markScenario("fixed-index-failure", failuresBefore);
  }

#ifndef PRODIGY_TEST_SYNCHRONOUS_MAGLEV_PREPARE
  // Owner cancellation drops a late result. Its RAII result closes the map on
  // the worker side, and no Ring completion remains to publish stale state.
  {
    const int failuresBefore = suite.failed;
    TestRing ring = {};
    auto executor = ProdigyArtifactIO::startOwned();
    FakeMaglevMaps maps = {};
    maps.blockIndex = 1024;
    std::atomic<bool> cancellationReleased = false;
    uint32_t completions = 0;
    suite.expect(executor != nullptr, "switchboard_maglev_async_starts_cancellation_executor");
    if (executor)
    {
      const bool queued = switchboardPrepareMaglevRingsAsync(
          *executor, {makeRequest(93, 0xa9)}, maps.backend(),
          [&](std::vector<SwitchboardMaglevRingPrepareResult>&&) { ++completions; },
          [&](std::exception_ptr) { ++completions; });
      suite.expect(queued, "switchboard_maglev_async_submits_cancelable_job");
      if (queued)
      {
        std::unique_lock lock(maps.mutex);
        const bool entered = maps.condition.wait_for(lock, std::chrono::seconds(1), [&] { return maps.enteredBlock.load(); });
        lock.unlock();
        suite.expect(entered, "switchboard_maglev_async_cancellation_reaches_worker_gate");
        // Open the fake backend gate before joining the executor. This tests
        // cancellation cleanup without making stop() depend on test teardown.
        maps.release();
        cancellationReleased = true;
        executor->stop();
        suite.expect(cancellationReleased && completions == 0 && maps.closes() == 1 && maps.empty(),
                     "switchboard_maglev_async_cancellation_drops_and_closes_late_result");
      }
      ring.drainAction = [] { Ring::exit = true; };
      Ring::exit = false;
      ring.arm(ring.drain, 10);
      Ring::start();
    }
    markScenario("cancellation", failuresBefore);
  }
#endif

  // Endpoint cardinality is independent of batch cardinality: a portal may
  // have all 16,384 containers, while an ArtifactIO batch has at most 1,024
  // portal snapshots. The maximum request reaches the worker and preserves
  // its create errno; the over-limit request is rejected without a backend.
  {
    const int failuresBefore = suite.failed;
    SwitchboardMaglevMapBackend createFailure = {};
    uint32_t creates = 0;
    createFailure.createInnerMap = [&] {
      ++creates;
      errno = ENOSPC;
      return -1;
    };
    createFailure.updateInnerMap = [](int, uint32_t, const container_id&) { return false; };
    createFailure.closeInnerMap = [](int) {};
    const auto largest = makeEndpointRequest(94, MAX_CONTAINERS_PER_PORTAL);
    const auto largestResult = switchboardPrepareMaglevRingsWorker({largest}, createFailure);
    suite.expect(largestResult.size() == 1 && largestResult[0].generation == largest.generation &&
                     largestResult[0].error == SwitchboardMaglevRingPrepareResult::Error::createInnerMap &&
                     largestResult[0].errorNumber == ENOSPC && creates == 1,
                 "switchboard_maglev_async_accepts_16384_endpoint_portal_and_preserves_create_errno");

    const auto tooManyEndpoints = makeEndpointRequest(95, MAX_CONTAINERS_PER_PORTAL + 1);
    const auto rejectedEndpoint = switchboardPrepareMaglevRingsWorker({tooManyEndpoints}, createFailure);
    suite.expect(rejectedEndpoint.size() == 1 &&
                     rejectedEndpoint[0].error == SwitchboardMaglevRingPrepareResult::Error::invalidRequest &&
                     creates == 1,
                 "switchboard_maglev_async_rejects_more_than_16384_endpoints_without_backend_call");
    markScenario("endpoint-capacity", failuresBefore);
  }

  {
    const int failuresBefore = suite.failed;
    TestRing ring = {};
    auto executor = ProdigyArtifactIO::startOwned();
    std::vector<SwitchboardMaglevRingPrepareRequest> tooManyPortals = {};
    tooManyPortals.reserve(MAX_PORTALS + 1);
    for (uint32_t index = 0; index <= MAX_PORTALS; ++index) tooManyPortals.push_back(makeRequest(1000 + index, 0xa6));
    FakeMaglevMaps maps = {};
    bool callback = false;
    suite.expect(executor != nullptr &&
                     switchboardPrepareMaglevRingsAsync(*executor, std::move(tooManyPortals), maps.backend(),
                         [&](std::vector<SwitchboardMaglevRingPrepareResult>&&) { callback = true; },
                         [&](std::exception_ptr) { callback = true; }) == false &&
                     callback == false,
                 "switchboard_maglev_async_rejects_batch_larger_than_1024_before_worker_submission");
    if (executor)
    {
      executor->stop();
      ring.drainAction = [] { Ring::exit = true; };
      Ring::exit = false;
      ring.arm(ring.drain, 10);
      Ring::start();
    }
    markScenario("batch-capacity", failuresBefore);
  }

  return suite.failed == 0 ? 0 : 1;
}
