#pragma once

#include <condition_variable>
#include <cerrno>
#include <cstdlib>
#include <mutex>
#include <thread>
#include <utility>
#include <sys/eventfd.h>
#include <poll.h>
#include <unistd.h>

#include <networking/includes.h>
#include <prodigy/host.control.network.h>
#include <prodigy/iaas/iaas.h>

class MothershipHostRuntimeJobBase
{
private:

  std::mutex completionMutex;
  std::condition_variable completionCondition;
  bool complete = false;
  bool retired = false;

protected:

  CoroutineStack stack;

  virtual void invoke(ProdigyProviderServices services, CoroutineStack *coro) = 0;

public:

  virtual ~MothershipHostRuntimeJobBase() = default;

  void start(ProdigyProviderServices services)
  {
    if (uint32_t suspendIndex = stack.nextSuspendIndex(); stack.didSuspend([&](void) -> void {
          invoke(services, &stack);
        }))
    {
      co_await stack.suspendAtIndex(suspendIndex);
    }
    complete = true;
  }

  bool completed(void) const
  {
    return complete;
  }

  void retire(void)
  {
    std::lock_guard<std::mutex> lock(completionMutex);
    retired = true;
    completionCondition.notify_one();
  }

  void wait(void)
  {
    std::unique_lock<std::mutex> lock(completionMutex);
    completionCondition.wait(lock, [&](void) -> bool { return retired; });
  }
};

class MothershipHostRuntimeQueue final
{
private:

  std::mutex mutex;
  MothershipHostRuntimeJobBase *queued = nullptr;
  bool inFlight = false;
  bool stopping = false;

public:

  bool submit(MothershipHostRuntimeJobBase& job)
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (stopping || inFlight)
    {
      return false;
    }
    queued = &job;
    inFlight = true;
    return true;
  }

  MothershipHostRuntimeJobBase *take(bool& shouldStop)
  {
    std::lock_guard<std::mutex> lock(mutex);
    MothershipHostRuntimeJobBase *job = queued;
    queued = nullptr;
    shouldStop = stopping && job == nullptr;
    return job;
  }

  bool complete(void)
  {
    std::lock_guard<std::mutex> lock(mutex);
    inFlight = false;
    return stopping;
  }

  void stop(void)
  {
    std::lock_guard<std::mutex> lock(mutex);
    stopping = true;
  }
};

template <typename Function>
class MothershipHostRuntimeJob final : public MothershipHostRuntimeJobBase
{
private:

  Function function;

  void invoke(ProdigyProviderServices services, CoroutineStack *coro) override
  {
    function(services, coro);
  }

public:

  explicit MothershipHostRuntimeJob(Function&& requestedFunction)
      : function(std::move(requestedFunction))
  {}
};

class MothershipHostRingRuntime final
{
private:

  class Worker final : public RingMultiplexer
  {
  private:

    MothershipHostRingRuntime& owner;
    ProdigyHostControlNetwork& network;
    ProdigyProviderServices services;
    MothershipHostRuntimeJobBase *active = nullptr;
    Ring::RawPollTicket wakeTicket = Ring::invalidRawPollTicket;
    uint64_t wakeGeneration = 1;
    bool shutdownRequested = false;

    void advanceShutdown(void)
    {
      if (shutdownRequested && network.shutdown())
      {
        Ring::exit = true;
      }
    }

    void publishReadiness(void)
    {
      if (network.sessionReady())
      {
        owner.markReady();
      }
    }

    void arm(void)
    {
      wakeTicket = Ring::queueRawFDPoll(this, wakeGeneration, owner.wakeFD, POLLIN);
      if (wakeTicket == Ring::invalidRawPollTicket)
      {
        std::abort();
      }
    }

  public:

    Worker(MothershipHostRingRuntime& requestedOwner, ProdigyHostControlNetwork& requestedNetwork)
        : owner(requestedOwner),
          network(requestedNetwork),
          services({.http = network.http(), .delay = ProdigyHostDelayOperation::submission()})
    {
      RingDispatcher::installMultiplexee(this, this);
      RingDispatcher::installMultiplexer(this);
      arm();
      publishReadiness();
    }

    ~Worker()
    {
      if (network.shutdownSafe() == false)
      {
        std::abort();
      }
      RingDispatcher::eraseMultiplexer(this);
      RingDispatcher::eraseMultiplexee(this);
    }

    void rawFDPollHandler(void *pollOwner, uint64_t generation, uint64_t ticket, int result) override
    {
      if (pollOwner != this || generation != wakeGeneration || ticket != wakeTicket)
      {
        return;
      }

      wakeTicket = Ring::invalidRawPollTicket;
      uint64_t value = 0;
      while (::read(owner.wakeFD, &value, sizeof(value)) < 0 && errno == EINTR)
      {}
      if (result < 0 && result != -ECANCELED)
      {
        std::abort();
      }

      bool shouldStop = false;
      if (active == nullptr)
      {
        active = owner.jobs.take(shouldStop);
      }
      if (shouldStop)
      {
        shutdownRequested = true;
        advanceShutdown();
        return;
      }

      arm();
      if (active != nullptr)
      {
        active->start(services);
      }
    }

    void completionBatchHandler(uint32_t) override
    {
      publishReadiness();
      if (active != nullptr && active->completed())
      {
        MothershipHostRuntimeJobBase *completed = active;
        active = nullptr;
        if (owner.jobs.complete())
        {
          owner.wake();
        }
        completed->retire();
      }
      advanceShutdown();
    }
  };

  std::mutex startupMutex;
  std::condition_variable startupCondition;
  MothershipHostRuntimeQueue jobs;
  std::thread workerThread;
  int wakeFD = -1;
  bool started = false;
  bool startupFinished = false;
  bool ready = false;

  void markReady(void)
  {
    std::lock_guard<std::mutex> lock(startupMutex);
    if (startupFinished == false)
    {
      ready = true;
      startupFinished = true;
      startupCondition.notify_one();
    }
  }

  void wake(void)
  {
    const uint64_t value = 1;
    ssize_t written = 0;
    do
    {
      written = ::write(wakeFD, &value, sizeof(value));
    } while (written < 0 && errno == EINTR);
    if (written != sizeof(value))
    {
      std::abort();
    }
  }

  void workerMain(void)
  {
    RingDispatcher dispatcher;
    Ring::exit = false;
    Ring::shuttingDown = false;
    Ring::createRing(256, 512, 64, 16, -1, -1, 32, false, RingProcessIntegration::isolatedWorker);

    {
      ProdigyHostControlNetwork network(ProdigyDnsControlClientRole::mothership);
      if (network.ready() == false)
      {
        std::lock_guard<std::mutex> lock(startupMutex);
        std::fprintf(stderr,
                     "mothership DNS control-service configuration failed: %s\n",
                     network.failure().size() > 0
                         ? network.failure().c_str()
                         : "invalid DNS control bootstrap state");
        ready = false;
        startupFinished = true;
      }
      else
      {
        Worker worker(*this, network);
        Ring::start();
      }
      startupCondition.notify_one();
    }

    Ring::shutdownForExec();
  }

  bool ensureStarted(void)
  {
    std::unique_lock<std::mutex> lock(startupMutex);
    if (started == false)
    {
      wakeFD = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
      if (wakeFD < 0)
      {
        return false;
      }
      started = true;
      workerThread = std::thread([this](void) -> void { workerMain(); });
    }
    if (startupCondition.wait_for(
            lock,
            std::chrono::seconds(30),
            [this](void) -> bool { return startupFinished; }) == false)
    {
      std::fprintf(stderr,
                   "mothership DNS control service unavailable at the configured literal IPv6 endpoint\n");
      return false;
    }
    return ready;
  }

public:

  MothershipHostRingRuntime() = default;
  MothershipHostRingRuntime(const MothershipHostRingRuntime&) = delete;
  MothershipHostRingRuntime& operator=(const MothershipHostRingRuntime&) = delete;

  ~MothershipHostRingRuntime()
  {
    if (started)
    {
      jobs.stop();
      wake();
      workerThread.join();
      ::close(wakeFD);
    }
  }

  template <typename Function>
  bool run(Function&& function)
  {
    if (ensureStarted() == false)
    {
      return false;
    }

    MothershipHostRuntimeJob<Function> job(std::forward<Function>(function));
    if (jobs.submit(job) == false)
    {
      return false;
    }
    wake();
    job.wait();
    return true;
  }
};
