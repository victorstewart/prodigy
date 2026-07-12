#include <atomic>
#include <cerrno>
#include <csignal>
#include <poll.h>
#include <thread>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <prodigy/mothership/mothership.ring.runtime.h>

class TestSuite
{
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    std::printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    failed += condition ? 0 : 1;
  }
};

class ScriptedJob final : public MothershipHostRuntimeJobBase
{
public:

  enum class Mode : uint8_t
  {
    inlineSuccess,
    deferredSuccess,
    error
  };

  Mode mode;
  CoroutineStack *invocationStack = nullptr;
  bool succeeded = false;
  int *destructions = nullptr;

  ScriptedJob(Mode requestedMode, int *requestedDestructions = nullptr)
      : mode(requestedMode),
        destructions(requestedDestructions)
  {}

  ~ScriptedJob()
  {
    if (destructions)
    {
      ++*destructions;
    }
  }

private:

  void invoke(ProdigyProviderServices, CoroutineStack *coro) override
  {
    invocationStack = coro;
    if (mode == Mode::deferredSuccess)
    {
      co_await coro->suspend();
    }
    succeeded = mode != Mode::error;
  }
};

class DeferredRingWake final : public TimeoutDispatcher
{
public:

  TimeoutPacket timeout;
  CoroutineStack *stack = nullptr;
  std::thread::id callbackThread;
  bool fired = false;

  void begin(CoroutineStack *requestedStack)
  {
    stack = requestedStack;
    timeout.setTimeoutUs(1000);
    timeout.dispatcher = this;
    Ring::queueTimeout(&timeout);
    co_await stack->suspend();
  }

  void dispatchTimeout(TimeoutPacket *packet) override
  {
    if (packet != &timeout)
    {
      std::abort();
    }
    fired = true;
    callbackThread = std::this_thread::get_id();
    stack->co_consume();
  }
};

static int ringSupport(void)
{
  struct io_uring probe = {};
  int result = io_uring_queue_init(2, &probe, 0);
  if (result == 0)
  {
    io_uring_queue_exit(&probe);
    return 1;
  }
  return (result == -ENOSYS || result == -EPERM || result == -EACCES) ? 0 : -1;
}

static bool waitForChild(pid_t child)
{
  int pidfd = int(syscall(SYS_pidfd_open, child, 0));
  if (pidfd < 0)
  {
    kill(child, SIGKILL);
    (void)waitpid(child, nullptr, 0);
    return false;
  }

  struct pollfd readiness = {.fd = pidfd, .events = POLLIN};
  int ready = 0;
  do
  {
    ready = poll(&readiness, 1, 5000);
  } while (ready < 0 && errno == EINTR);
  close(pidfd);
  if (ready <= 0)
  {
    kill(child, SIGKILL);
  }
  int status = 0;
  (void)waitpid(child, &status, 0);
  return ready > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool runActualRuntimeScenario(void)
{
  pid_t child = fork();
  if (child == 0)
  {
    const std::thread::id mainThread = std::this_thread::get_id();
    bool inlineRan = false;
    bool inlineOnWorker = false;
    bool servicesInjected = false;
    DeferredRingWake deferred = {};
    {
      MothershipHostRingRuntime runtime;
      inlineRan = runtime.run([&](ProdigyProviderServices services, CoroutineStack *) -> void {
        servicesInjected = services.http != nullptr;
        inlineOnWorker = std::this_thread::get_id() != mainThread;
      });
      bool deferredRan = runtime.run([&](ProdigyProviderServices services, CoroutineStack *coro) -> void {
        servicesInjected = servicesInjected && services.http != nullptr;
        deferred.begin(coro);
      });
      if (inlineRan == false || deferredRan == false)
      {
        _exit(3);
      }
    }
    _exit(inlineOnWorker && servicesInjected && deferred.fired &&
                  deferred.callbackThread != mainThread
              ? 0
              : 4);
  }
  if (child < 0)
  {
    return false;
  }
  return waitForChild(child);
}

int main(void)
{
  TestSuite suite = {};

  {
    ScriptedJob job(ScriptedJob::Mode::inlineSuccess);
    job.start({});
    suite.expect(job.completed() && job.succeeded,
                 "inline_job_completes_without_suspension");
  }

  {
    ScriptedJob job(ScriptedJob::Mode::deferredSuccess);
    job.start({});
    suite.expect(job.completed() == false && job.invocationStack != nullptr &&
                     job.invocationStack->hasSuspendedCoroutines(),
                 "deferred_job_keeps_stable_stack_until_resume");
    job.invocationStack->co_consume();
    suite.expect(job.completed() && job.succeeded &&
                     job.invocationStack->hasSuspendedCoroutines() == false,
                 "deferred_job_completes_after_resume");
  }

  {
    ScriptedJob job(ScriptedJob::Mode::error);
    job.start({});
    suite.expect(job.completed() && job.succeeded == false,
                 "error_job_retires_normally");
  }

  {
    MothershipHostRuntimeQueue queue;
    ScriptedJob first(ScriptedJob::Mode::deferredSuccess);
    ScriptedJob second(ScriptedJob::Mode::inlineSuccess);
    bool shouldStop = false;
    suite.expect(queue.submit(first), "single_slot_accepts_first_job");
    suite.expect(queue.submit(second) == false,
                 "single_slot_rejects_concurrent_job");
    suite.expect(queue.take(shouldStop) == &first && shouldStop == false,
                 "worker_takes_only_admitted_job");
    suite.expect(queue.complete() == false && queue.submit(second),
                 "single_slot_reopens_only_after_completion_boundary");
  }

  {
    MothershipHostRuntimeQueue queue;
    queue.stop();
    bool shouldStop = false;
    suite.expect(queue.take(shouldStop) == nullptr && shouldStop,
                 "idle_shutdown_stops_worker_without_job");
  }

  {
    int destructions = 0;
    {
      ScriptedJob job(ScriptedJob::Mode::inlineSuccess, &destructions);
      MothershipHostRuntimeQueue queue;
      suite.expect(queue.submit(job), "lifetime_job_admitted");
      bool shouldStop = false;
      ScriptedJob *active = static_cast<ScriptedJob *>(queue.take(shouldStop));
      active->start({});
      suite.expect(active->completed() && destructions == 0,
                   "job_remains_alive_through_dispatch");

      std::atomic<bool> waitReturned = false;
      std::thread waiter([&](void) -> void {
        active->wait();
        waitReturned = true;
      });
      std::this_thread::yield();
      suite.expect(waitReturned == false,
                   "job_waiter_blocks_before_retirement_boundary");
      queue.complete();
      active->retire();
      waiter.join();
      suite.expect(waitReturned && destructions == 0,
                   "job_waiter_wakes_at_retirement_boundary");
    }
    suite.expect(destructions == 1,
                 "job_destroys_only_after_retirement_and_waiter_return");
  }

  const int support = ringSupport();
  if (support == 0)
  {
    std::printf("SKIP: io_uring unavailable (ENOSYS/EPERM/EACCES)\n");
    return suite.failed == 0 ? 77 : 1;
  }
  suite.expect(support > 0, "io_uring_probe_has_no_unexpected_failure");
  suite.expect(support > 0 && runActualRuntimeScenario(),
               "real_runtime_runs_inline_and_ring_deferred_jobs_then_drains_network");

  return suite.failed == 0 ? 0 : 1;
}
