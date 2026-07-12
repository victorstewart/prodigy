#pragma once

#include <prodigy/iaas/gcp/gcp.compute.transaction.h>

class GcpMachineLifecycleTransaction final
{
public:

  enum class Action : uint8_t
  {
    reset,
    destroy
  };

  constexpr static uint32_t maximumPages = GcpComputeTransaction::maximumPages;
  constexpr static uint32_t maximumInstances = GcpComputeTransaction::maximumInstances;
  constexpr static uint32_t maximumObservations = GcpComputeTransaction::maximumObservations;
  constexpr static uint32_t maximumPageTokenBytes = GcpComputeTransaction::maximumPageTokenBytes;
  constexpr static uint64_t pollDelayUs = GcpComputeTransaction::pollDelayUs;
  constexpr static size_t responseBytes = GcpComputeTransaction::responseBytes;

private:

  GcpComputeTransaction compute;

  static void appendPartial(const String& name, String& failure)
  {
    failure.append("; gcp machine lifecycle cloud state may be partial for: "_ctv);
    failure.append(name);
  }

  void verifyDestroyed(CoroutineStack *coro,
                       const String& name,
                       const String& cloudID,
                       String& failure)
  {
    for (uint32_t observation = 0; observation < maximumObservations; ++observation)
    {
      bool exists = false;
      bool matches = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            compute.observeIdentity(coro, name, cloudID, exists, matches, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (failure.empty() == false || exists == false || matches == false)
      {
        co_return;
      }
      if (observation + 1 >= maximumObservations || compute.canWait() == false)
      {
        failure.assign("gcp machine lifecycle destroy visibility deadline exceeded"_ctv);
        co_return;
      }
      bool delayComplete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            compute.wait(coro, delayComplete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (delayComplete == false)
      {
        failure.assign("gcp machine lifecycle delay failed"_ctv);
        co_return;
      }
    }
  }

public:

  GcpMachineLifecycleTransaction(ProdigyHostHttpOperation::Submission http,
                                 ProdigyHostDelayOperation::Submission delay,
                                 String project,
                                 String zone,
                                 String token,
                                 MultiCurlClient::TimePoint deadline)
      : compute(http,
                delay,
                std::move(project),
                std::move(zone),
                std::move(token),
                deadline)
  {}

  void run(CoroutineStack *coro, Action action, const String& cloudID, String& failure)
  {
    String targetCloudID;
    targetCloudID.assign(cloudID);
    failure.clear();
    if (coro == nullptr || compute.runtimeAvailable() == false)
    {
      failure.assign("gcp machine lifecycle runtime unavailable"_ctv);
      co_return;
    }
    if (compute.identityAvailable() == false || targetCloudID.empty())
    {
      failure.assign("gcp machine lifecycle identity unavailable"_ctv);
      co_return;
    }
    if (compute.expired())
    {
      failure.assign("gcp machine lifecycle deadline exceeded"_ctv);
      co_return;
    }

    // Resolve and revalidate the immutable provider ID before mutating the named instance.
    String name;
    bool discoveryComplete = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          compute.resolveName(coro, targetCloudID, name, discoveryComplete, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (failure.empty() == false || discoveryComplete == false)
    {
      if (failure.empty())
      {
        failure.assign("gcp machine lifecycle instance discovery failed"_ctv);
      }
      co_return;
    }
    if (name.empty())
    {
      if (action == Action::reset)
      {
        failure.assign("gcp machine lifecycle target not found"_ctv);
      }
      co_return;
    }

    bool exists = false;
    bool matches = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          compute.observeIdentity(coro, name, targetCloudID, exists, matches, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (failure.empty() == false)
    {
      co_return;
    }
    if (exists == false)
    {
      if (action == Action::reset)
      {
        failure.assign("gcp machine lifecycle target disappeared before reset"_ctv);
      }
      co_return;
    }
    if (matches == false)
    {
      failure.assign("gcp machine lifecycle target identity changed before mutation"_ctv);
      co_return;
    }

    // Reset and delete target only the name whose immutable provider ID was revalidated above.
    String mutationUrl = compute.instancesUrl(&name);
    if (action == Action::reset)
    {
      mutationUrl.append("/reset"_ctv);
    }
    MultiCurlClient::Result mutationResult;
    bool mutationComplete = false;
    const MultiCurlClient::Method method = action == Action::reset ?
        MultiCurlClient::Method::post : MultiCurlClient::Method::delete_;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          compute.submit(coro,
                         compute.request(method, std::move(mutationUrl)),
                         mutationResult,
                         mutationComplete);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (mutationComplete == false)
    {
      failure.assign("gcp machine lifecycle mutation submission failed"_ctv);
      co_return;
    }
    if (action == Action::destroy && mutationResult.status == MultiCurlClient::Status::success &&
        mutationResult.statusCode == 404)
    {
      co_return;
    }
    if (mutationResult.status != MultiCurlClient::Status::success ||
        mutationResult.statusCode < 200 || mutationResult.statusCode >= 300)
    {
      String operation;
      operation.assign(action == Action::reset ? "gcp machine reset" : "gcp machine destroy");
      GcpComputeTransaction::assignRequestFailure(mutationResult, operation, failure);
      if (GcpComputeTransaction::mutationMayBeAccepted(mutationResult))
      {
        appendPartial(name, failure);
      }
      co_return;
    }

    String operationName;
    if (GcpComputeTransaction::parseOperationName(mutationResult.body, operationName, failure) == false)
    {
      appendPartial(name, failure);
      co_return;
    }

    GcpComputeTransaction::OperationState state = GcpComputeTransaction::OperationState::invalid;
    bool operationMissing = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          compute.pollOperation(coro, operationName, state, operationMissing, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (state == GcpComputeTransaction::OperationState::failed)
    {
      co_return;
    }
    if (operationMissing && action == Action::reset)
    {
      failure.assign("gcp machine reset operation disappeared"_ctv);
      appendPartial(name, failure);
      co_return;
    }
    if (operationMissing == false && state != GcpComputeTransaction::OperationState::done)
    {
      appendPartial(name, failure);
      co_return;
    }
    if (action == Action::destroy)
    {
      failure.clear();
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            verifyDestroyed(coro, name, targetCloudID, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (failure.empty() == false)
      {
        appendPartial(name, failure);
      }
    }
  }
};
