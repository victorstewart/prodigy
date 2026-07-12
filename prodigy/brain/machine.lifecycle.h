#pragma once

#include <types/types.containers.h>
#include <networking/coroutinestack.h>
#include <prodigy/iaas/iaas.h>

class ProdigyBrainMachineLifecycleCoordinator final
{
public:

  enum class Action : uint8_t
  {
    hardReboot,
    destroy
  };

  class Completion
  {
  public:

    void *context = nullptr;
    void (*function)(void *, Action, uint128_t, const String&, const String&) = nullptr;

    explicit operator bool() const
    {
      return function != nullptr;
    }
  };

  constexpr static uint32_t maximumQueuedOperations = 256;

private:

  class Request
  {
  public:

    Action action = Action::destroy;
    uint128_t uuid = 0;
    String cloudID;
  };

  BrainIaaS *provider = nullptr;
  Completion completion;
  CoroutineStack coroutine;
  Vector<Request> requests;
  uint32_t nextRequest = 0;
  bool active = false;

  void run(void)
  {
    active = true;
    while (nextRequest < requests.size())
    {
      Request request = std::move(requests[nextRequest++]);
      String failure;
      if (request.action == Action::hardReboot)
      {
        if (uint32_t suspendIndex = coroutine.nextSuspendIndex(); coroutine.didSuspend([&](void) -> void {
              provider->hardRebootMachine(&coroutine, request.cloudID, failure);
            }))
        {
          co_await coroutine.suspendAtIndex(suspendIndex);
        }
      }
      else
      {
        if (uint32_t suspendIndex = coroutine.nextSuspendIndex(); coroutine.didSuspend([&](void) -> void {
              provider->destroyMachine(&coroutine, request.cloudID, failure);
            }))
        {
          co_await coroutine.suspendAtIndex(suspendIndex);
        }
      }

      if (completion)
      {
        completion.function(completion.context,
                            request.action,
                            request.uuid,
                            request.cloudID,
                            failure);
      }
    }
    requests.clear();
    nextRequest = 0;
    provider = nullptr;
    active = false;
  }

public:

  ProdigyBrainMachineLifecycleCoordinator() = default;

  explicit ProdigyBrainMachineLifecycleCoordinator(Completion completion)
      : completion(completion)
  {}

  void configureCompletion(Completion requestedCompletion)
  {
    completion = requestedCompletion;
  }

  bool enqueue(BrainIaaS& requestedProvider,
               Action action,
               uint128_t uuid,
               const String& cloudID)
  {
    if (cloudID.empty() || requests.size() - nextRequest >= maximumQueuedOperations ||
        (provider != nullptr && provider != &requestedProvider))
    {
      return false;
    }
    requests.push_back({action, uuid, cloudID});
    if (active == false)
    {
      provider = &requestedProvider;
      run();
    }
    return true;
  }

  bool hasActiveOperation(void) const
  {
    return active;
  }

  uint32_t queuedOperations(void) const
  {
    return uint32_t(requests.size() - nextRequest);
  }
};
