#pragma once

#include <prodigy/iaas/iaas.h>
#include <prodigy/brain/machine.h>

static inline void mothershipDestroyProviderMachines(CoroutineStack *coro,
                                                     BrainIaaS& iaas,
                                                     const Vector<String>& cloudIDs,
                                                     bool& destroyed,
                                                     String *failure = nullptr)
{
  destroyed = false;
  if (failure)
  {
    failure->clear();
  }

  for (const String& cloudID : cloudIDs)
  {
    if (cloudID.size() == 0)
    {
      if (failure)
      {
        failure->assign("cloudID required"_ctv);
      }
      co_return;
    }

    String operationFailure;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          iaas.destroyMachine(coro, cloudID, operationFailure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (operationFailure.empty() == false)
    {
      if (failure)
      {
        *failure = std::move(operationFailure);
      }
      co_return;
    }
  }

  destroyed = true;
}

// Precondition: the selected provider's machine lifecycle implementation completes inline.
static inline bool mothershipDestroyProviderMachinesInline(BrainIaaS& iaas,
                                                           const Vector<String>& cloudIDs,
                                                           String *failure = nullptr)
{
  CoroutineStack coro;
  bool destroyed = false;
  mothershipDestroyProviderMachines(&coro, iaas, cloudIDs, destroyed, failure);
  coro.co_consume();
  return destroyed;
}

static inline void mothershipDestroyProviderClusterMachines(CoroutineStack *coro,
                                                            BrainIaaS& iaas,
                                                            const String& clusterUUID,
                                                            uint32_t& destroyed,
                                                            bool& completed,
                                                            String *failure = nullptr)
{
  completed = false;
  if (failure)
  {
    failure->clear();
  }
  destroyed = 0;

  if (clusterUUID.size() == 0)
  {
    if (failure)
    {
      failure->assign("clusterUUID required"_ctv);
    }
    co_return;
  }

  String error = {};
  if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
        iaas.destroyClusterMachines(coro, clusterUUID, destroyed, error);
      }))
  {
    co_await coro->suspendAtIndex(suspendIndex);
  }
  if (error.size() > 0)
  {
    if (failure)
    {
      *failure = error;
    }
    co_return;
  }

  completed = true;
}

// Precondition: the selected provider's cluster lifecycle implementation completes inline.
static inline bool mothershipDestroyProviderClusterMachinesInline(BrainIaaS& iaas,
                                                                  const String& clusterUUID,
                                                                  uint32_t& destroyed,
                                                                  String *failure = nullptr)
{
  CoroutineStack coro;
  bool completed = false;
  mothershipDestroyProviderClusterMachines(&coro, iaas, clusterUUID, destroyed, completed, failure);
  coro.co_consume();
  return completed;
}
