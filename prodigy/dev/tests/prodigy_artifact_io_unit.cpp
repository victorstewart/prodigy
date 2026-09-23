#include <includes.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/multiplexer.h>
#include <networking/ring.h>
#include <networking/time.h>
#include <prodigy/artifact.io.h>
#include <prodigy/containerstore.h>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <memory>
#include <thread>
#include <unistd.h>
#include <vector>

class ArtifactIOSuite {
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

class TemporaryArtifactDirectory {
public:
  String path = {};

  bool create()
  {
    std::filesystem::create_directories(".run");
    char pattern[] = ".run/prodigy-artifact-io-XXXXXX";
    char *created = ::mkdtemp(pattern);
    if (created == nullptr) return false;
    path.assign(created);
    return true;
  }

  ~TemporaryArtifactDirectory()
  {
    if (path.size()) std::filesystem::remove_all(path.c_str());
  }
};

class ArtifactIORing final : public TimeoutDispatcher {
public:
  RingDispatcher dispatcher;
  TimeoutPacket tick = {};
  TimeoutPacket deadline = {};
  TimeoutPacket drain = {};
  std::function<void()> tickAction = {};
  std::function<void()> deadlineAction = {};
  std::function<void()> drainAction = {};
  bool shutdown = false;

  ArtifactIORing()
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

  ~ArtifactIORing()
  {
    shutdownForExec();
    Ring::interfacer = nullptr;
    Ring::lifecycler = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;
    RingDispatcher::dispatcher = nullptr;
  }

  void shutdownForExec()
  {
    if (shutdown) return;
    Ring::shutdownForExec();
    shutdown = true;
  }

  void armTick(uint64_t ms)
  {
    tick.clear();
    tick.setTimeoutMs(ms);
    Ring::queueTimeout(&tick);
  }

  void armDeadline(uint64_t ms)
  {
    deadline.clear();
    deadline.setTimeoutMs(ms);
    Ring::queueTimeout(&deadline);
  }

  void armDrain(uint64_t ms)
  {
    drain.clear();
    drain.setTimeoutMs(ms);
    Ring::queueTimeout(&drain);
  }

  void dispatchTimeout(TimeoutPacket *packet) override
  {
    if (packet == &tick && tickAction) tickAction();
    if (packet == &deadline && deadlineAction) deadlineAction();
    if (packet == &drain && drainAction) drainAction();
  }
};

int main()
{
  ArtifactIOSuite suite;
  suite.expect(ProdigyArtifactIO::startOwned() == nullptr, "artifact_io_requires_an_initialized_ring");
  TemporaryArtifactDirectory storeRoot = {};
  suite.expect(storeRoot.create(), "artifact_io_temp_store_created");
  if (storeRoot.path.size() > 0)
  {
    constexpr uint64_t deploymentID = 0xA71F0ULL;
    String stagePath = storeRoot.path;
    stagePath.append("/.artifact-io-malformed.stage"_ctv);
    ContainerStore::PreparedAppArtifact prepared = {};
    String malformed = "not a Discombobulator artifact"_ctv;
    String digest = {};
    String failure = {};
    (void)prodigyComputeSHA256Hex(malformed, digest, &failure);
    suite.expect(ContainerStore::prepareAppArtifactAtPath(
                     prepared, deploymentID, stagePath, malformed, digest, malformed.size(), &failure, &storeRoot.path) == false,
                 "artifact_io_rejects_malformed_artifact_before_temporary_staging");
    suite.expect(prepared.prepared == false, "artifact_io_rejection_has_no_prepared_metadata");

    // Positive storage proof requires the packaged Discombobulator artifact,
    // never a hand-assembled header or synthetic rootfs. The Ring executor
    // tests below remain runnable when a build has not provided this fixture.
    const char *fixturePath = ::getenv("PRODIGY_TEST_APP_ARTIFACT");
    if (fixturePath == nullptr || fixturePath[0] == 0)
    {
      dprintf(STDERR_FILENO, "SKIP: artifact_io_positive_fixture_requires_PRODIGY_TEST_APP_ARTIFACT\n");
    }
    else
    {
      String artifactPath = {};
      artifactPath.assign(fixturePath);
      String blob = {};
      Filesystem::openReadAtClose(-1, artifactPath, blob);
      String artifactDigest = {};
      String fixtureFailure = {};
      String header = {};
      String headerText = prodigyDiscombobulatorBlobHeaderText();
      header.assign(blob.substr(0, headerText.size(), Copy::yes));
      const bool validFixture = blob.size() > 0 &&
          prodigyValidateDiscombobulatorBlobHeaderText(header, &fixtureFailure) &&
          prodigyComputeSHA256Hex(blob, artifactDigest, &fixtureFailure);
      suite.expect(validFixture, "artifact_io_positive_fixture_is_real_discombobulator_artifact");
      if (validFixture)
      {
        constexpr uint64_t publishDeploymentID = 0xA71F1ULL;
        String firstStage = storeRoot.path;
        firstStage.append("/.artifact-io-first.stage"_ctv);
        String duplicateStage = storeRoot.path;
        duplicateStage.append("/.artifact-io-duplicate.stage"_ctv);
        ContainerStore::PreparedAppArtifact first = {};
        suite.expect(ContainerStore::prepareAppArtifactAtPath(first, publishDeploymentID, firstStage, blob, artifactDigest, blob.size(), &fixtureFailure, &storeRoot.path) &&
                         ContainerStore::publishPreparedAppArtifact(first, &fixtureFailure) &&
                         first.reusedExisting == false && ContainerStore::adoptPreparedAppArtifact(first),
                     "artifact_io_publishes_real_fixture_from_temporary_stage");
        ContainerStore::PreparedAppArtifact duplicate = {};
        suite.expect(ContainerStore::prepareAppArtifactAtPath(duplicate, publishDeploymentID, duplicateStage, blob, artifactDigest, blob.size(), &fixtureFailure, &storeRoot.path) &&
                         ContainerStore::publishPreparedAppArtifact(duplicate, &fixtureFailure) && duplicate.reusedExisting &&
                         ContainerStore::adoptPreparedAppArtifact(duplicate),
                     "artifact_io_exact_duplicate_reuses_existing_temporary_inode");
        String publishedPath = {};
        publishedPath.assign(first.finalPath);
        const dev_t publishedDevice = first.publishedDevice;
        const ino_t publishedInode = first.publishedInode;
        ContainerStore::discardPreparedAppArtifact(first);
        ContainerStore::discardPreparedAppArtifact(duplicate);
        struct stat retained = {};
        suite.expect(::stat(publishedPath.c_str(), &retained) == 0 &&
                         retained.st_dev == publishedDevice && retained.st_ino == publishedInode,
                     "artifact_io_stale_cleanup_never_removes_published_temporary_inode");
      }
    }
  }

  {
    ProdigyArtifactIO io;
    std::atomic<bool> ran = false;
    suite.expect(io.submit(1, [&] { ran = true; }, [] {}, [](std::exception_ptr) {}) == false,
                 "artifact_io_refuses_submit_without_ring_start");
    suite.expect(ran == false, "artifact_io_submit_rejection_does_not_run_work");
    suite.expect(io.submit(ProdigyArtifactIO::maximumBytes + 1, [] {}, [] {}, [](std::exception_ptr) {}) == false,
                 "artifact_io_rejects_over_budget_work");
  }

  // A 250ms disk operation must not stall independent Ring control work. The
  // worker reports a thrown job through failure, and all retained jobs survive
  // queue/in-flight/completed accounting until their Ring callback releases it.
  {
    ArtifactIORing ring;
    auto io = ProdigyArtifactIO::startOwned();
    std::atomic<bool> blockedWorkDone = false;
    uint32_t controlSamples = 0;
    uint32_t completions = 0;
    uint32_t continuations = 0;
    uint32_t failures = 0;
    bool timedOut = false;
    std::vector<uint64_t> controlIntervalsUs = {};
    std::chrono::steady_clock::time_point previousControlSample = std::chrono::steady_clock::now();
    std::shared_ptr<uint8_t> callbackLifetime = std::make_shared<uint8_t>(1);
    std::weak_ptr<uint8_t> callbackLifetimeWeak = callbackLifetime;
    suite.expect(io != nullptr, "artifact_io_starts_with_independent_dispatcher");
    if (io)
    {
      auto finishWhenComplete = [&] {
        if (blockedWorkDone && failures == 1 && continuations == 1 && controlSamples == 30) Ring::exit = true;
      };
      suite.expect(io->submit(32, [&] {
                     std::this_thread::sleep_for(std::chrono::milliseconds(250));
                     blockedWorkDone = true;
                   }, [&, callbackLifetime = std::move(callbackLifetime)] {
                     ++completions;
                     suite.expect(io->continueWith([] {}, [&] { ++continuations; finishWhenComplete(); }, [&](std::exception_ptr) { ++failures; finishWhenComplete(); }),
                                  "artifact_io_completion_can_chain_without_second_capacity_lease");
                     suite.expect(callbackLifetimeWeak.expired() == false,
                                  "artifact_io_continuation_keeps_active_callback_captures_alive");
                     finishWhenComplete();
                   }, [&](std::exception_ptr) { ++failures; finishWhenComplete(); }),
                   "artifact_io_accepts_blocked_work");
      suite.expect(io->submit(64, [] { throw 7; }, [] {}, [&](std::exception_ptr) { ++failures; finishWhenComplete(); }),
                   "artifact_io_accepts_failure_work");
      ring.tickAction = [&] {
        const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
        controlIntervalsUs.push_back(uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(now - previousControlSample).count()));
        previousControlSample = now;
        ++controlSamples;
        if (controlSamples < 30) ring.armTick(5);
        finishWhenComplete();
      };
      ring.deadlineAction = [&] { timedOut = true; Ring::exit = true; };
      ring.armTick(5);
      ring.armDeadline(1500);
      Ring::start();
      suite.expect(timedOut == false && blockedWorkDone && completions == 1 && continuations == 1 && failures == 1 && controlSamples == 30,
                   "artifact_io_worker_does_not_block_30_ring_control_samples_and_reports_failure");
      std::vector<uint64_t> sortedControlIntervalsUs = controlIntervalsUs;
      std::sort(sortedControlIntervalsUs.begin(), sortedControlIntervalsUs.end());
      const uint64_t p95ControlIntervalUs = sortedControlIntervalsUs.empty() ? 0 : sortedControlIntervalsUs[(sortedControlIntervalsUs.size() * 95 + 99) / 100 - 1];
      dprintf(STDERR_FILENO, "artifact_io_250ms_worker_timer_samples_us=");
      for (uint64_t interval : controlIntervalsUs) dprintf(STDERR_FILENO, "%llu,", static_cast<unsigned long long>(interval));
      dprintf(STDERR_FILENO, " p95_us=%llu samples=%llu\n", static_cast<unsigned long long>(p95ControlIntervalUs), static_cast<unsigned long long>(controlIntervalsUs.size()));
      io->stop();
      ring.drainAction = [] { Ring::exit = true; };
      ring.armDrain(25);
      Ring::exit = false;
      Ring::start();
    }
  }

  // Stopping before the worker returns drops its late completion; Ring still
  // receives and retires the canceled raw-poll CQE after the owner is gone.
  {
    ArtifactIORing ring;
    auto io = ProdigyArtifactIO::startOwned();
    std::atomic<bool> entered = false;
    uint32_t lateCallbacks = 0;
    bool timedOut = false;
    suite.expect(io != nullptr, "artifact_io_starts_for_cancellation");
    if (io)
    {
      suite.expect(io->submit(1, [&] {
                     entered = true;
                     std::this_thread::sleep_for(std::chrono::milliseconds(250));
                   }, [&] { ++lateCallbacks; }, [&](std::exception_ptr) { ++lateCallbacks; }),
                   "artifact_io_accepts_cancelable_work");
      ring.tickAction = [&] {
        if (entered)
        {
          io->stop();
          Ring::exit = true;
        }
        else ring.armTick(1);
      };
      ring.deadlineAction = [&] { timedOut = true; Ring::exit = true; };
      ring.armTick(1);
      ring.armDeadline(400);
      Ring::start();
      ring.drainAction = [] { Ring::exit = true; };
      ring.armDrain(25);
      Ring::exit = false;
      Ring::start();
      suite.expect(timedOut == false && lateCallbacks == 0, "artifact_io_cancellation_drops_late_completion");
    }
  }

  // The unique owner may be destroyed while its raw poll cancellation is still
  // pending. A short Ring drain proves the retired opaque key is harmless.
  {
    ArtifactIORing ring;
    auto io = ProdigyArtifactIO::startOwned();
    std::atomic<bool> entered = false;
    suite.expect(io != nullptr, "artifact_io_starts_for_pending_owner_destruction");
    if (io)
    {
      suite.expect(io->submit(1, [&] { entered = true; std::this_thread::sleep_for(std::chrono::milliseconds(250)); }, [] {}, [](std::exception_ptr) {}),
                   "artifact_io_accepts_pending_destruction_work");
      while (entered == false) std::this_thread::yield();
      io.reset();
      ring.deadlineAction = [] { Ring::exit = true; };
      ring.armDeadline(25);
      Ring::start();
      suite.expect(true, "artifact_io_destruction_drains_terminal_raw_poll_without_parent_callback");
    }
  }

  // Bundle exec is only safe after the raw-poll cancellation CQE has returned
  // to Ring. A completion cannot make that request itself because the current
  // CQE remains tracked until rawFDPollHandler returns; the later timer retry
  // performs the cancellation and observes its terminal acknowledgement.
  {
    ArtifactIORing ring;
    auto io = ProdigyArtifactIO::startOwned();
    uint32_t completions = 0;
    bool completionDeferred = false;
    bool cancellationRequested = false;
    bool quiesced = false;
    bool timedOut = false;
    suite.expect(io != nullptr, "artifact_io_starts_for_exec_quiesce_barrier");
    if (io)
    {
      suite.expect(io->submit(1, [] {}, [&] {
                     ++completions;
                     completionDeferred = io->quiesceForExec() == false;
                   }, [](std::exception_ptr) {}),
                   "artifact_io_accepts_exec_quiesce_completion_work");
      ring.tickAction = [&] {
        if (completions == 0)
        {
          ring.armTick(1);
          return;
        }
        if (io->quiesceForExec())
        {
          quiesced = true;
          Ring::exit = true;
          return;
        }
        cancellationRequested = true;
        ring.armTick(1);
      };
      ring.deadlineAction = [&] { timedOut = true; Ring::exit = true; };
      ring.armTick(1);
      ring.armDeadline(400);
      Ring::start();
      suite.expect(timedOut == false && completions == 1 && completionDeferred && cancellationRequested && quiesced,
                   "artifact_io_exec_quiesce_waits_for_terminal_cancellation_cqe_after_completion");
      if (quiesced)
      {
        ring.shutdownForExec();
        suite.expect(true, "artifact_io_exec_quiesce_permits_ring_shutdown_after_terminal_cqe");
      }
      io->stop();
    }
  }

  // A canceled raw poll is only half of the exec barrier: the worker may still
  // own an in-flight disk operation. Hold one worker until the test has
  // observed the terminal CQE, then prove quiesce remains false until release.
  {
    ArtifactIORing ring;
    auto io = ProdigyArtifactIO::startOwned();
    std::atomic<bool> entered = false;
    std::atomic<bool> releaseWorker = false;
    bool cancellationRequested = false;
    bool cancellationAcknowledgedWhileWorkerBlocked = false;
    bool workerBlockedQuiesce = false;
    bool quiescedAfterWorkerExit = false;
    bool timedOut = false;
    suite.expect(io != nullptr, "artifact_io_starts_for_exec_worker_exit_barrier");
    if (io)
    {
      suite.expect(io->submit(1, [&] {
                     entered = true;
                     while (releaseWorker == false) std::this_thread::yield();
                   }, [] {}, [](std::exception_ptr) {}),
                   "artifact_io_accepts_blocked_exec_worker");
      ring.tickAction = [&] {
        if (entered == false)
        {
          ring.armTick(1);
          return;
        }
        if (cancellationRequested == false)
        {
          cancellationRequested = true;
          suite.expect(io->quiesceForExec() == false,
                       "artifact_io_exec_worker_barrier_requests_cancellation_first");
          ring.armTick(1);
          return;
        }
        if (cancellationAcknowledgedWhileWorkerBlocked == false)
        {
          if (io->execCancellationAcknowledgedForExec() == false)
          {
            ring.armTick(1);
            return;
          }
          cancellationAcknowledgedWhileWorkerBlocked = true;
          workerBlockedQuiesce = io->quiesceForExec() == false;
          releaseWorker = true;
          ring.armTick(1);
          return;
        }
        if (io->quiesceForExec())
        {
          quiescedAfterWorkerExit = true;
          Ring::exit = true;
          return;
        }
        ring.armTick(1);
      };
      ring.deadlineAction = [&] { timedOut = true; Ring::exit = true; };
      ring.armTick(1);
      ring.armDeadline(400);
      Ring::start();
      suite.expect(timedOut == false && cancellationRequested && cancellationAcknowledgedWhileWorkerBlocked &&
                       workerBlockedQuiesce && quiescedAfterWorkerExit,
                   "artifact_io_exec_quiesce_waits_for_worker_exit_after_terminal_cancellation_cqe");
      if (quiescedAfterWorkerExit)
      {
        ring.shutdownForExec();
        suite.expect(true, "artifact_io_exec_worker_exit_barrier_permits_ring_shutdown");
      }
      releaseWorker = true;
      io->stop();
    }
  }

  return suite.failed == 0 ? 0 : 1;
}
