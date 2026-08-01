#pragma once

#include <cerrno>
#include <cstdint>
#include <cstdlib>

#include <networking/includes.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/multiplexer.h>
#include <networking/ring.h>

class MachinePingerTimer final {
public:

  struct Submission {

    void *context = nullptr;
    void (*queue)(void *context, TimeoutPacket *packet) = nullptr;
    void (*cancel)(void *context, TimeoutPacket *packet) = nullptr;
  };

  using Tick = void (*)(void *context);
  using Failure = void (*)(void *context, int result);

private:

  class Completion final : public RingInterface {
  public:

    MachinePingerTimer *timer;
    TimeoutPacket packet;

    Completion(MachinePingerTimer& requestedTimer, uint64_t timeoutMs)
        : timer(&requestedTimer)
    {
      packet.originator = this;
      packet.setTimeoutMs(timeoutMs);
      RingDispatcher::installMultiplexee(this, this);
    }

    void timeoutHandler(TimeoutPacket *completedPacket, int result) override
    {
      if (completedPacket != &packet)
      {
        return;
      }

      if (result == -ETIME)
      {
        MachinePingerTimer *owner = timer;
        if (owner != nullptr &&
            owner->active == this &&
            owner->wanted &&
            owner->cancelling == false)
        {
          Tick tick = owner->tick;
          void *context = owner->tickContext;
          tick(context);
        }
        return;
      }

      MachinePingerTimer *owner = timer;
      timer = nullptr;
      RingDispatcher::eraseMultiplexee(this);
      if (owner != nullptr)
      {
        owner->completed(this, result);
      }
      delete this;
    }
  };

  Submission ring;
  void *tickContext;
  Tick tick;
  Failure failure;
  uint64_t timeoutMs;
  Completion *active = nullptr;
  bool wanted = false;
  bool cancelling = false;

  static void queue(void *, TimeoutPacket *packet)
  {
    Ring::queueTimeoutMultishot(packet);
  }

  static void cancel(void *, TimeoutPacket *packet)
  {
    Ring::queueCancelTimeoutMultishot(packet);
  }

  void arm(void)
  {
    if (wanted == false || active != nullptr)
    {
      return;
    }

    active = new Completion(*this, timeoutMs);
    ring.queue(ring.context, &active->packet);
  }

  void completed(Completion *completion, int result)
  {
    if (completion != active)
    {
      return;
    }

    active = nullptr;
    cancelling = false;
    if (result == -ECANCELED)
    {
      arm();
      return;
    }

    wanted = false;
    Failure failed = failure;
    void *context = tickContext;
    failed(context, result);
  }

public:

  static Submission submission(void)
  {
    return {nullptr, queue, cancel};
  }

  MachinePingerTimer(
      void *context,
      Tick requestedTick,
      Failure requestedFailure,
      uint64_t requestedTimeoutMs)
      : MachinePingerTimer(
            submission(),
            context,
            requestedTick,
            requestedFailure,
            requestedTimeoutMs)
  {}

  MachinePingerTimer(
      Submission requestedRing,
      void *context,
      Tick requestedTick,
      Failure requestedFailure,
      uint64_t requestedTimeoutMs)
      : ring(requestedRing),
        tickContext(context),
        tick(requestedTick),
        failure(requestedFailure),
        timeoutMs(requestedTimeoutMs)
  {
    if (ring.queue == nullptr ||
        ring.cancel == nullptr ||
        tick == nullptr ||
        failure == nullptr ||
        timeoutMs == 0)
    {
      std::abort();
    }
  }

  ~MachinePingerTimer()
  {
    wanted = false;
    if (active == nullptr)
    {
      return;
    }

    Completion *orphan = active;
    active = nullptr;
    orphan->timer = nullptr;
    if (cancelling == false)
    {
      cancelling = true;
      ring.cancel(ring.context, &orphan->packet);
    }
  }

  MachinePingerTimer(const MachinePingerTimer&) = delete;
  MachinePingerTimer& operator=(const MachinePingerTimer&) = delete;

  void start(void)
  {
    wanted = true;
    arm();
  }

  void stop(void)
  {
    wanted = false;
    if (active == nullptr || cancelling)
    {
      return;
    }

    cancelling = true;
    ring.cancel(ring.context, &active->packet);
  }

  bool isIdle(void) const
  {
    return active == nullptr;
  }

  bool isCancelling(void) const
  {
    return cancelling;
  }
};
