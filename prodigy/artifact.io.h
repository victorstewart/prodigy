#pragma once

#include <includes.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/multiplexer.h>
#include <networking/ring.h>

#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <sys/eventfd.h>
#include <sys/poll.h>
#include <thread>
#include <unistd.h>

// A bounded worker bridge for blocking preparation (disk, digests, private BPF
// maps). The worker owns only the
// closures supplied at submit time; it never reads mutable Ring-owner state.
// start(), stop(), submission, and destruction run on the Ring thread.
class ProdigyArtifactIO final : public RingInterface {
public:
  using Work = std::function<void()>;
  using Completion = std::function<void()>;
  using Failure = std::function<void(std::exception_ptr)>;

  static constexpr uint32_t maximumJobs = 8;
  static constexpr uint64_t maximumBytes = 512ULL * 1024ULL * 1024ULL;

private:
  struct Job {
    uint64_t generation = 0;
    uint64_t bytes = 0;
    Work work = {};
    Completion completion = {};
    Failure failure = {};
    std::exception_ptr exception = {};
  };

  std::mutex mutex;
  std::condition_variable condition;
  std::deque<Job> queued;
  std::deque<Job> completed;
  std::thread worker;
  int wakeFD = -1;
  Ring::RawPollTicket wakePoll = Ring::invalidRawPollTicket;
  uint64_t generation = 1;
  uint64_t retainedBytes = 0;
  uint32_t retainedJobs = 0;
  bool stopping = true;
  bool installed = false;
  bool execQuiescing = false;
  bool execCancellationAcknowledged = false;
  bool execQuiesced = false;
  bool workerExited = true;
  Job *callbackJob = nullptr;
  bool callbackContinuation = false;

  void releaseJobLocked(const Job& job)
  {
    retainedBytes -= job.bytes;
    --retainedJobs;
  }

  void signalRing()
  {
    uint64_t one = 1;
    while (::write(wakeFD, &one, sizeof(one)) < 0 && errno == EINTR) {}
  }

  void workerMain()
  {
    for (;;)
    {
      Job job = {};
      {
        std::unique_lock lock(mutex);
        condition.wait(lock, [this] { return stopping || queued.empty() == false; });
        if (stopping && queued.empty())
        {
          workerExited = true;
          return;
        }
        job = std::move(queued.front());
        queued.pop_front();
      }

      try
      {
        job.work();
      }
      catch (...)
      {
        job.exception = std::current_exception();
      }

      {
        std::lock_guard lock(mutex);
        if (stopping || job.generation != generation)
        {
          releaseJobLocked(job);
          continue;
        }
        completed.push_back(std::move(job));
      }
      signalRing();
    }
  }

  void armWakePoll()
  {
    if (stopping == false && wakeFD >= 0 && wakePoll == Ring::invalidRawPollTicket)
    {
      wakePoll = Ring::queueRawFDPoll(this, generation, wakeFD, POLLIN);
    }
  }

  void drainWakeFD()
  {
    uint64_t ignored = 0;
    for (;;)
    {
      ssize_t result = ::read(wakeFD, &ignored, sizeof(ignored));
      if (result == sizeof(ignored) || (result < 0 && errno == EINTR)) continue;
      break;
    }
  }

public:
  ProdigyArtifactIO() = default;
  ProdigyArtifactIO(const ProdigyArtifactIO&) = delete;
  ProdigyArtifactIO& operator=(const ProdigyArtifactIO&) = delete;

  ~ProdigyArtifactIO() { stop(); }

  // A convenient unique-owner entry point for Brain and Neuron. The owner may
  // be destroyed while a raw poll CQE is pending: stop() first removes this
  // independent multiplexee, so Ring treats the later opaque owner value as a
  // retired key and never dereferences this object.
  static std::unique_ptr<ProdigyArtifactIO> startOwned()
  {
    auto owner = std::make_unique<ProdigyArtifactIO>();
    return owner->start() ? std::move(owner) : nullptr;
  }

  bool start()
  {
    if (stopping == false) return true;
    if (Ring::getRingFD() <= 0 || Ring::interfacer == nullptr) return false;
    wakeFD = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (wakeFD < 0) return false;
    stopping = false;
    execQuiescing = false;
    execCancellationAcknowledged = false;
    execQuiesced = false;
    RingDispatcher::installMultiplexee(this, this);
    installed = true;
    {
      std::lock_guard lock(mutex);
      workerExited = false;
    }
    worker = std::thread([this] { workerMain(); });
    armWakePoll();
    if (wakePoll != Ring::invalidRawPollTicket) return true;
    stop();
    return false;
  }

  bool submit(uint64_t bytes, Work work, Completion completion, Failure failure)
  {
    if (work == nullptr || completion == nullptr || failure == nullptr || bytes > maximumBytes) return false;
    std::lock_guard lock(mutex);
    if (stopping || retainedJobs == maximumJobs || retainedBytes > maximumBytes - bytes) return false;
    queued.push_back({.generation = generation, .bytes = bytes, .work = std::move(work), .completion = std::move(completion), .failure = std::move(failure)});
    retainedBytes += bytes;
    ++retainedJobs;
    condition.notify_one();
    return true;
  }

  // Ring-callback only. Replaces the current job in-place and preserves its
  // queue slot and byte lease, so prepare->publish cannot temporarily count
  // one artifact twice or be rejected when all eight slots are occupied.
  // A callback may request one continuation; fresh submit() calls remain
  // capacity-gated.
  bool continueWith(Work work, Completion completion, Failure failure)
  {
    if (callbackJob == nullptr || callbackContinuation || stopping || work == nullptr || completion == nullptr || failure == nullptr) return false;
    callbackJob->work = std::move(work);
    callbackJob->completion = std::move(completion);
    callbackJob->failure = std::move(failure);
    callbackJob->exception = {};
    callbackContinuation = true;
    return true;
  }

  // Ring-thread only. Exposed for the focused cancellation-barrier regression
  // to distinguish the raw-poll acknowledgement from worker termination.
  bool execCancellationAcknowledgedForExec() const { return execCancellationAcknowledged; }

  // Ring-thread only. Bundle exec must not tear down the Ring while its raw
  // poll still has a live tracking entry. Request cancellation once, keep this
  // endpoint and ticket installed until the terminal CQE reaches
  // rawFDPollHandler() and workerMain(), then return true only on a later
  // Ring-owned retry.
  // Calling this from a completion is deliberately deferred: that CQE itself
  // remains tracked until the current handler returns. This exec-only barrier
  // intentionally does not change stop()/destructor's eager-retirement path.
  bool quiesceForExec()
  {
    if (callbackJob != nullptr) return false;
    if (execQuiesced) return true;
    if (execQuiescing)
    {
      if (execCancellationAcknowledged == false) return false;
      {
        std::lock_guard lock(mutex);
        if (workerExited == false) return false;
      }
      // workerExited is written while holding mutex immediately before
      // workerMain returns, so this join cannot wait for in-progress work.
      if (worker.joinable()) worker.join();
      if (wakeFD >= 0)
      {
        ::close(wakeFD);
        wakeFD = -1;
      }
      if (installed)
      {
        RingDispatcher::eraseMultiplexee(this);
        installed = false;
      }
      execQuiesced = true;
      return true;
    }
    if (stopping)
    {
      return wakePoll == Ring::invalidRawPollTicket;
    }

    execQuiescing = true;
    {
      std::lock_guard lock(mutex);
      stopping = true;
      ++generation;
      for (const Job& job : queued) releaseJobLocked(job);
      queued.clear();
      for (const Job& job : completed) releaseJobLocked(job);
      completed.clear();
    }
    condition.notify_all();
    if (wakePoll == Ring::invalidRawPollTicket)
    {
      execCancellationAcknowledged = true;
      return false;
    }
    (void)Ring::cancelRawFDPoll(wakePoll);
    return false;
  }

  // This is deliberately installed as its own RingDispatcher endpoint; Brain
  // and Neuron never delegate raw poll callbacks for artifact I/O.
  void rawFDPollHandler(void *owner, uint64_t callbackGeneration, uint64_t ticket, int result) override
  {
    if (owner != this || ticket != wakePoll) return;
    wakePoll = Ring::invalidRawPollTicket;
    if (execQuiescing)
    {
      // This CQE, whether cancellation won or readiness raced it, is the
      // terminal acknowledgement for the raw poll submitted before exec.
      execCancellationAcknowledged = true;
      return;
    }
    if (callbackGeneration != generation || stopping) return;
    if (result >= 0) drainWakeFD();

    std::deque<Job> ready;
    {
      std::lock_guard lock(mutex);
      ready.swap(completed);
    }
    for (Job& job : ready)
    {
      // A callback may stop this owner; do not call another retained parent
      // closure after that point.
      callbackJob = &job;
      callbackContinuation = false;
      if (stopping == false && job.generation == generation)
      {
        // continueWith replaces the next callback in job. Move the active
        // closure out first so its captures remain alive until it returns.
        Completion completion = std::move(job.completion);
        Failure failure = std::move(job.failure);
        if (job.exception) failure(job.exception);
        else completion();
      }
      callbackJob = nullptr;
      std::lock_guard lock(mutex);
      if (callbackContinuation && stopping == false && job.generation == generation)
      {
        queued.push_back(std::move(job));
        condition.notify_one();
      }
      else
      {
        releaseJobLocked(job);
      }
    }
    armWakePoll();
  }

  // Ring-thread only. It drops queued and late completions, erases the raw
  // dispatch mapping before freeing this object, joins the sole worker, then
  // closes the eventfd. The terminal canceled CQE may arrive later and is
  // safely ignored by RingDispatcher because the opaque key is no longer
  // registered.
  void stop()
  {
    if (stopping == false)
    {
      std::lock_guard lock(mutex);
      stopping = true;
      ++generation;
      for (const Job& job : queued) releaseJobLocked(job);
      queued.clear();
      for (const Job& job : completed) releaseJobLocked(job);
      completed.clear();
    }
    if (wakePoll != Ring::invalidRawPollTicket) (void)Ring::cancelRawFDPoll(wakePoll);
    wakePoll = Ring::invalidRawPollTicket;
    if (installed)
    {
      RingDispatcher::eraseMultiplexee(this);
      installed = false;
    }
    condition.notify_all();
    if (worker.joinable()) worker.join();
    if (wakeFD >= 0)
    {
      ::close(wakeFD);
      wakeFD = -1;
    }
  }

  void cancel() { stop(); }
};
