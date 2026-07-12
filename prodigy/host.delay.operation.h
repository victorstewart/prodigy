#pragma once

#include <networking/stream.h>
#include <networking/coroutinestack.h>
#include <networking/ring.h>

class ProdigyHostDelayOperation final
{
public:

  struct Submission
  {
    void *context = nullptr;
    void (*queue)(void *context, TimeoutPacket *packet) = nullptr;
    void (*cancel)(void *context, TimeoutPacket *packet) = nullptr;
  };

private:

  class Completion final : public TimeoutDispatcher
  {
  public:

    ProdigyHostDelayOperation *operation;
    Submission ring;
    TimeoutPacket packet;

    Completion(ProdigyHostDelayOperation& requestedOperation,
               Submission requestedRing,
               uint64_t microseconds)
        : operation(&requestedOperation),
          ring(requestedRing)
    {
      packet.setTimeoutUs(microseconds);
      packet.dispatcher = this;
    }

    void dispatchTimeout(TimeoutPacket *completedPacket) override
    {
      if (completedPacket != &packet)
      {
        return;
      }

      ProdigyHostDelayOperation *const completedOperation = operation;
      operation = nullptr;
      if (completedOperation)
      {
        completedOperation->completed(this);
      }
      delete this;
    }

    void abandon(void)
    {
      operation = nullptr;
      ring.cancel(ring.context, &packet);
    }
  };

  Submission ring;
  CoroutineStack *stack = nullptr;
  Completion *pending = nullptr;
  bool complete = false;
  bool wakeArmed = false;

  static void queueRingTimeout(void *, TimeoutPacket *packet)
  {
    Ring::queueTimeout(packet);
  }

  static void cancelRingTimeout(void *, TimeoutPacket *packet)
  {
    Ring::queueCancelTimeout(packet);
  }

  void completed(Completion *completion)
  {
    if (completion != pending || complete)
    {
      return;
    }

    pending = nullptr;
    complete = true;
    const bool wake = wakeArmed;
    wakeArmed = false;
    CoroutineStack *const wakeStack = wake ? stack : nullptr;
    if (wakeStack)
    {
      wakeStack->co_consume();
    }
  }

  void disarm(void)
  {
    Completion *const active = pending;
    pending = nullptr;
    complete = false;
    wakeArmed = false;
    if (active)
    {
      active->abandon();
    }
  }

public:

  static Submission submission(void)
  {
    return {nullptr, queueRingTimeout, cancelRingTimeout};
  }

  explicit ProdigyHostDelayOperation(CoroutineStack& stack)
      : ProdigyHostDelayOperation(submission(), stack)
  {}

  ProdigyHostDelayOperation(Submission ring, CoroutineStack& stack)
      : ring(ring),
        stack(&stack)
  {}

  ~ProdigyHostDelayOperation()
  {
    disarm();
  }

  ProdigyHostDelayOperation(const ProdigyHostDelayOperation&) = delete;
  ProdigyHostDelayOperation& operator=(const ProdigyHostDelayOperation&) = delete;

  bool scheduleUs(uint64_t microseconds)
  {
    if (pending || complete || ring.queue == nullptr || ring.cancel == nullptr)
    {
      return false;
    }
    if (microseconds == 0)
    {
      complete = true;
      return true;
    }

    pending = new Completion(*this, ring, microseconds);
    ring.queue(ring.context, &pending->packet);
    return true;
  }

  bool mustSuspend(void)
  {
    if (!pending)
    {
      return false;
    }
    wakeArmed = true;
    return true;
  }

  bool hasCompleted(void) const
  {
    return complete;
  }

  bool takeCompletion(void)
  {
    const bool wasComplete = complete;
    complete = false;
    return wasComplete;
  }

  void abandon(void)
  {
    disarm();
  }
};
