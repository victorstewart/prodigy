#pragma once

#include <types/types.containers.h>
#include <networking/coroutinestack.h>
#include <prodigy/iaas/iaas.h>

class ProdigyBrainElasticAddressCoordinator final
{
public:

  enum class Action : uint8_t
  {
    prepareAssignment,
    applyAssignment,
    compensateAssignment,
    release
  };

  class Completion
  {
  public:

    void *context = nullptr;
    void (*function)(void *, uint64_t, Action, ProviderElasticAddressPlan&&,
                     ProviderElasticAddressAssignment&&, String&&) = nullptr;

    explicit operator bool() const
    {
      return function != nullptr;
    }
  };

  constexpr static uint32_t maximumQueuedOperations = 256;

private:

  class Operation
  {
  public:

    uint64_t id = 0;
    Action action = Action::prepareAssignment;
    uint128_t transactionNonce = 0;
    ProviderElasticAddressRequest request;
    ProviderElasticAddressPlan plan;
    ProviderElasticAddressRelease release;
  };

  BrainIaaS *provider = nullptr;
  Completion completion;
  CoroutineStack coroutine;
  Vector<Operation> operations;
  uint64_t lastOperationID = 0;
  uint32_t nextOperation = 0;
  bool active = false;

  static void copy(String& target, const String& source)
  {
    target.assign(source);
  }

  static void copy(ProviderElasticAddressRequest& target,
                   const ProviderElasticAddressRequest& source)
  {
    target.family = source.family;
    target.intent = source.intent;
    target.deliveryPrefix = source.deliveryPrefix;
    copy(target.cloudID, source.cloudID);
    copy(target.requestedAddress, source.requestedAddress);
    copy(target.providerPool, source.providerPool);
  }

  static void copy(ProviderElasticAddressRelease& target,
                   const ProviderElasticAddressRelease& source)
  {
    target.kind = source.kind;
    target.assignedPrefix = source.assignedPrefix;
    target.transactionNonce = source.transactionNonce;
    target.releaseOnRemove = source.releaseOnRemove;
    copy(target.allocationID, source.allocationID);
    copy(target.associationID, source.associationID);
  }

  static void copy(ProviderElasticAddressPlan& target,
                   const ProviderElasticAddressPlan& source)
  {
    target.opaque.assign(source.opaque);
  }

  bool accepts(BrainIaaS& requestedProvider, uint64_t operationID) const
  {
    return operationID != 0 && operationID > lastOperationID &&
           operations.size() - nextOperation < maximumQueuedOperations &&
           (provider == nullptr || provider == &requestedProvider);
  }

  bool start(BrainIaaS& requestedProvider, Operation&& operation)
  {
    if (active == false && requestedProvider.beginElasticAddressOperationBatch() == false)
    {
      return false;
    }
    lastOperationID = operation.id;
    operations.push_back(std::move(operation));
    if (active == false)
    {
      provider = &requestedProvider;
      run();
    }
    return true;
  }

  void run(void)
  {
    active = true;
    while (nextOperation < operations.size())
    {
      Operation operation = std::move(operations[nextOperation++]);
      ProviderElasticAddressPlan plan;
      ProviderElasticAddressAssignment assignment;
      String failure;
      if (operation.action == Action::prepareAssignment)
      {
        if (uint32_t suspendIndex = coroutine.nextSuspendIndex(); coroutine.didSuspend([&](void) -> void {
              provider->prepareProviderElasticAddress(&coroutine,
                                                      operation.request,
                                                      operation.transactionNonce,
                                                      plan,
                                                      failure);
            }))
        {
          co_await coroutine.suspendAtIndex(suspendIndex);
        }
      }
      else if (operation.action == Action::applyAssignment)
      {
        if (uint32_t suspendIndex = coroutine.nextSuspendIndex(); coroutine.didSuspend([&](void) -> void {
              provider->applyProviderElasticAddress(&coroutine,
                                                    operation.plan,
                                                    assignment,
                                                    failure);
            }))
        {
          co_await coroutine.suspendAtIndex(suspendIndex);
        }
      }
      else if (operation.action == Action::compensateAssignment)
      {
        if (uint32_t suspendIndex = coroutine.nextSuspendIndex(); coroutine.didSuspend([&](void) -> void {
              provider->compensateProviderElasticAddress(&coroutine,
                                                         operation.plan,
                                                         failure);
            }))
        {
          co_await coroutine.suspendAtIndex(suspendIndex);
        }
      }
      else
      {
        if (uint32_t suspendIndex = coroutine.nextSuspendIndex(); coroutine.didSuspend([&](void) -> void {
              provider->releaseProviderElasticAddress(&coroutine,
                                                      operation.release,
                                                      failure);
            }))
        {
          co_await coroutine.suspendAtIndex(suspendIndex);
        }
      }

      if (completion)
      {
        completion.function(completion.context,
                            operation.id,
                            operation.action,
                            std::move(plan),
                            std::move(assignment),
                            std::move(failure));
      }
    }
    BrainIaaS *completedProvider = provider;
    operations.clear();
    nextOperation = 0;
    provider = nullptr;
    active = false;
    completedProvider->endElasticAddressOperationBatch();
  }

public:

  ProdigyBrainElasticAddressCoordinator() = default;

  explicit ProdigyBrainElasticAddressCoordinator(Completion requestedCompletion)
      : completion(requestedCompletion)
  {}

  void configureCompletion(Completion requestedCompletion)
  {
    completion = requestedCompletion;
  }

  bool enqueue(BrainIaaS& requestedProvider,
               uint64_t operationID,
               const ProviderElasticAddressRequest& request,
               uint128_t transactionNonce)
  {
    if (accepts(requestedProvider, operationID) == false || request.cloudID.empty() ||
        transactionNonce == 0 ||
        (request.family != ExternalAddressFamily::ipv4 && request.family != ExternalAddressFamily::ipv6) ||
        elasticPrefixIntentIsValid(request.intent) == false)
    {
      return false;
    }

    Operation operation;
    operation.id = operationID;
    operation.action = Action::prepareAssignment;
    operation.transactionNonce = transactionNonce;
    copy(operation.request, request);
    return start(requestedProvider, std::move(operation));
  }

  bool enqueue(BrainIaaS& requestedProvider,
               uint64_t operationID,
               Action action,
               const ProviderElasticAddressPlan& plan,
               const ProviderElasticAddressRequest& request,
               uint128_t transactionNonce)
  {
    if ((action != Action::applyAssignment && action != Action::compensateAssignment) ||
        accepts(requestedProvider, operationID) == false || plan.opaque.empty() ||
        plan.opaque.size() > ProviderElasticAddressPlan::maximumBytes ||
        transactionNonce == 0 ||
        requestedProvider.validateProviderElasticAddressPlan(plan, request, transactionNonce) == false)
    {
      return false;
    }

    Operation operation;
    operation.id = operationID;
    operation.action = action;
    operation.transactionNonce = transactionNonce;
    copy(operation.request, request);
    copy(operation.plan, plan);
    return start(requestedProvider, std::move(operation));
  }

  bool enqueue(BrainIaaS& requestedProvider,
               uint64_t operationID,
               const ProviderElasticAddressRelease& release)
  {
    if (accepts(requestedProvider, operationID) == false ||
        release.kind != RoutablePrefixKind::elastic || release.transactionNonce == 0)
    {
      return false;
    }

    Operation operation;
    operation.id = operationID;
    operation.action = Action::release;
    copy(operation.release, release);
    return start(requestedProvider, std::move(operation));
  }

  bool hasActiveOperation(void) const
  {
    return active;
  }

  uint32_t queuedOperations(void) const
  {
    return uint32_t(operations.size() - nextOperation);
  }
};
