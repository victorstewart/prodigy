#pragma once

#include <openssl/crypto.h>

#include <prodigy/dns.provider.h>

class ProdigyBrainDNSOperationCoordinator final
{
public:

  enum class Action : uint8_t
  {
    upsert,
    remove,
    presentTXT,
    cleanupTXT
  };

  class Ticket
  {
  public:

    uint64_t identifier = 0;
    uint64_t generation = 0;

    explicit operator bool(void) const
    {
      return identifier != 0 && generation != 0;
    }
  };

  class Completion
  {
  public:

    void *context = nullptr;
    void (*function)(void *, Ticket, Action, uint64_t, bool, String&&) = nullptr;

    explicit operator bool(void) const
    {
      return function != nullptr;
    }
  };

  class CredentialLookup
  {
  public:

    void *context = nullptr;
    const ApiCredential *(*function)(void *, uint16_t, const String&) = nullptr;

    explicit operator bool(void) const
    {
      return function != nullptr;
    }
  };

  constexpr static uint32_t maximumQueuedOperations = 256;
  constexpr static uint64_t maximumPropagationDelayUs = 300ULL * 1000 * 1000;

private:

  class Operation
  {
  public:

    Ticket ticket;
    Action action = Action::upsert;
    uint64_t owner = 0;
    uint64_t propagationDelayUs = 0;
    ProdigyDNSProvider *provider = nullptr;
    uint16_t applicationID = 0;
    uint64_t credentialGeneration = 0;
    String credentialName;
    ProdigyDNSRecordBinding record;
  };

  ProdigyHostDelayOperation::Submission delay;
  CredentialLookup credentialLookup;
  Completion completion;
  CoroutineStack coroutine;
  Vector<Operation> operations;
  uint32_t nextOperation = 0;
  uint64_t nextIdentifier = 1;
  uint64_t generation = 1;
  bool active = false;
  bool stopping = false;

  static void copy(String& target, const String& source)
  {
    target.assign(source);
  }

  static void copy(ProdigyDNSRecordBinding& target, const ProdigyDNSRecordBinding& source)
  {
    copy(target.provider, source.provider);
    copy(target.credentialName, source.credentialName);
    copy(target.zone, source.zone);
    copy(target.name, source.name);
    copy(target.type, source.type);
    target.ttl = source.ttl;
    target.values.clear();
    target.values.reserve(source.values.size());
    for (const String& value : source.values)
    {
      String& copied = target.values.emplace_back();
      copy(copied, value);
    }
  }

  static void copy(ApiCredential& target, const ApiCredential& source)
  {
    copy(target.name, source.name);
    copy(target.provider, source.provider);
    target.generation = source.generation;
    target.expiresAtMs = source.expiresAtMs;
    target.activeFromMs = source.activeFromMs;
    target.sunsetAtMs = source.sunsetAtMs;
    copy(target.material, source.material);
    target.metadata.clear();
    for (const auto& [key, value] : source.metadata)
    {
      String copiedKey;
      String copiedValue;
      copy(copiedKey, key);
      copy(copiedValue, value);
      target.metadata.insert_or_assign(std::move(copiedKey), std::move(copiedValue));
    }
  }

  static void cleanse(ApiCredential& credential)
  {
    if (credential.material.data() != nullptr)
    {
      OPENSSL_cleanse(credential.material.data(), size_t(credential.material.reservedBytes()));
    }
    credential.material.reset();
    for (auto& [key, value] : credential.metadata)
    {
      (void)key;
      if (value.data() != nullptr)
      {
        OPENSSL_cleanse(value.data(), size_t(value.reservedBytes()));
      }
      value.reset();
    }
    credential.metadata.clear();
  }

  Ticket mintTicket(void)
  {
    Ticket ticket {nextIdentifier++, generation};
    if (nextIdentifier == 0)
    {
      nextIdentifier = 1;
      if (++generation == 0)
      {
        generation = 1;
      }
    }
    return ticket;
  }

  void complete(Operation& operation, bool success, String&& failure)
  {
    if (completion)
    {
      completion.function(completion.context,
                          operation.ticket,
                          operation.action,
                          operation.owner,
                          success,
                          std::move(failure));
    }
  }

  void cancelQueued(void)
  {
    while (nextOperation < operations.size())
    {
      Operation& operation = operations[nextOperation++];
      String failure = "DNS operation canceled during shutdown"_ctv;
      complete(operation, false, std::move(failure));
    }
  }

  void run(void)
  {
    active = true;
    while (nextOperation < operations.size())
    {
      Operation operation = std::move(operations[nextOperation++]);
      String failure;
      bool success = false;
      ApiCredential credential;
      const ApiCredential *currentCredential = credentialLookup ?
                                                   credentialLookup.function(credentialLookup.context,
                                                                             operation.applicationID,
                                                                             operation.credentialName) :
                                                   nullptr;
      if (currentCredential == nullptr ||
          (operation.credentialGeneration != 0 && currentCredential->generation != operation.credentialGeneration))
      {
        if (currentCredential == nullptr)
        {
          failure.assign("DNS credential is no longer registered"_ctv);
        }
        else
        {
          failure.assign("DNS credential generation changed before dispatch"_ctv);
        }
      }
      else
      {
        copy(credential, *currentCredential);
        switch (operation.action)
        {
          case Action::upsert:
            success = co_await operation.provider->upsert(&coroutine, operation.record, credential, failure);
            break;
          case Action::remove:
            success = co_await operation.provider->remove(&coroutine, operation.record, credential, failure);
            break;
          case Action::presentTXT:
            success = co_await operation.provider->presentTXT(&coroutine, operation.record, credential, failure);
            break;
          case Action::cleanupTXT:
            success = co_await operation.provider->cleanupTXT(&coroutine, operation.record, credential, failure);
            break;
        }
      }

      if (success && operation.propagationDelayUs > 0)
      {
        ProdigyHostDelayOperation wait(delay, coroutine);
        if (wait.scheduleUs(operation.propagationDelayUs) == false)
        {
          success = false;
          failure.assign("DNS propagation delay submission failed"_ctv);
        }
        else
        {
          if (wait.mustSuspend())
          {
            co_await coroutine.suspend();
          }
          success = wait.takeCompletion();
          if (success == false)
          {
            failure.assign("DNS propagation delay canceled"_ctv);
          }
        }
      }
      cleanse(credential);
      complete(operation, success, std::move(failure));
      if (stopping)
      {
        cancelQueued();
        break;
      }
    }
    operations.clear();
    nextOperation = 0;
    active = false;
  }

public:

  void configureDelay(ProdigyHostDelayOperation::Submission requestedDelay)
  {
    delay = requestedDelay;
  }

  void configure(CredentialLookup requestedCredentialLookup,
                 Completion requestedCompletion)
  {
    credentialLookup = requestedCredentialLookup;
    completion = requestedCompletion;
  }

  bool canEnqueue(uint32_t count = 1) const
  {
    return stopping == false && count <= maximumQueuedOperations - uint32_t(operations.size() - nextOperation);
  }

  Ticket enqueue(ProdigyDNSProvider& requestedProvider,
                 Action action,
                 const ProdigyDNSRecordBinding& record,
                 uint16_t applicationID,
                 uint64_t credentialGeneration,
                 uint64_t owner = 0,
                 uint64_t propagationDelayUs = 0)
  {
    if (canEnqueue() == false ||
        propagationDelayUs > maximumPropagationDelayUs)
    {
      return {};
    }

    Operation operation;
    operation.ticket = mintTicket();
    operation.action = action;
    operation.owner = owner;
    operation.propagationDelayUs = propagationDelayUs;
    operation.provider = &requestedProvider;
    operation.applicationID = applicationID;
    operation.credentialGeneration = credentialGeneration;
    copy(operation.credentialName, record.credentialName);
    copy(operation.record, record);
    const Ticket ticket = operation.ticket;
    operations.push_back(std::move(operation));
    if (active == false)
    {
      run();
    }
    return ticket;
  }

  void shutdown(void)
  {
    stopping = true;
    if (active == false)
    {
      cancelQueued();
      operations.clear();
      nextOperation = 0;
    }
  }

  bool shutdownSafe(void) const
  {
    return stopping && active == false && operations.empty();
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
