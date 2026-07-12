#pragma once

#include <networking/multi.curl.client.h>
#include <networking/coroutinestack.h>

struct ProdigyHostHttpSubmission
{
  using Ticket = MultiCurlClient::Ticket;
  using Request = MultiCurlClient::Request;
  using Callback = MultiCurlClient::Callback;

  void *context = nullptr;
  Ticket (*submit)(void *context, Request&& request, Callback callback) = nullptr;
  // Every accepted nonzero ticket owns one terminal callback, including after cancellation.
  bool (*cancel)(void *context, Ticket ticket) = nullptr;

  explicit operator bool(void) const
  {
    return submit != nullptr && cancel != nullptr;
  }
};

class ProdigyHostHttpOperation final
{
public:

  using Ticket = MultiCurlClient::Ticket;
  using Request = MultiCurlClient::Request;
  using Result = MultiCurlClient::Result;
  using Callback = MultiCurlClient::Callback;
  using Submission = ProdigyHostHttpSubmission;

private:

  struct Completion
  {
    ProdigyHostHttpOperation *owner = nullptr;
    Ticket ticket;
    Ticket inlineTicket;
    Result inlineResult;
    bool submitting = false;
    bool inlineCompletion = false;
    bool pending = true;

    static void completed(void *context, Ticket ticket, Result&& result)
    {
      Completion *completion = static_cast<Completion *>(context);
      if (completion->owner)
      {
        completion->owner->completed(*completion, ticket, std::move(result));
      }
      else if (completion->pending && completion->ticket && ticket &&
               completion->ticket.identifier == ticket.identifier &&
               completion->ticket.generation == ticket.generation)
      {
        completion->pending = false;
        delete completion;
      }
    }
  };

  Submission client;
  CoroutineStack *stack = nullptr;
  Completion *completion = nullptr;
  Result result;
  bool pending = false;
  bool complete = false;
  bool wakeArmed = false;

  static bool sameTicket(Ticket left, Ticket right)
  {
    return left.identifier == right.identifier && left.generation == right.generation;
  }

  static Ticket submitToClient(void *context, Request&& request, Callback callback)
  {
    return static_cast<MultiCurlClient *>(context)->submit(std::move(request), callback);
  }

  static bool cancelClient(void *context, Ticket ticket)
  {
    return static_cast<MultiCurlClient *>(context)->cancel(ticket);
  }

  void settle(Completion& settled, Result&& completedResult)
  {
    if (&settled != completion || settled.pending == false)
    {
      return;
    }
    settled.pending = false;
    result = std::move(completedResult);
    pending = false;
    complete = true;
    const bool wake = wakeArmed;
    wakeArmed = false;
    CoroutineStack *const wakeStack = wake ? stack : nullptr;
    if (wakeStack)
    {
      wakeStack->co_consume();
    }
  }

  void completed(Completion& completedState, Ticket ticket, Result&& completedResult)
  {
    if (&completedState != completion || completedState.pending == false || !ticket)
    {
      return;
    }
    if (completedState.submitting)
    {
      if (completedState.inlineCompletion == false)
      {
        completedState.inlineTicket = ticket;
        completedState.inlineResult = std::move(completedResult);
        completedState.inlineCompletion = true;
      }
      return;
    }
    if (sameTicket(completedState.ticket, ticket))
    {
      settle(completedState, std::move(completedResult));
    }
  }

  void disarm(void)
  {
    Completion *const active = completion;
    completion = nullptr;
    result = {};
    pending = false;
    complete = false;
    wakeArmed = false;
    if (active == nullptr)
    {
      return;
    }
    if (active->pending && active->ticket && client.cancel)
    {
      active->owner = nullptr;
      (void)client.cancel(client.context, active->ticket);
      return;
    }
    delete active;
  }

public:

  static Submission submission(MultiCurlClient& client)
  {
    return {&client, submitToClient, cancelClient};
  }

  ProdigyHostHttpOperation(MultiCurlClient& client, CoroutineStack& stack)
      : ProdigyHostHttpOperation(submission(client), stack)
  {}

  ProdigyHostHttpOperation(Submission client, CoroutineStack& stack)
      : client(client),
        stack(&stack)
  {}

  ~ProdigyHostHttpOperation()
  {
    disarm();
  }

  ProdigyHostHttpOperation(const ProdigyHostHttpOperation&) = delete;
  ProdigyHostHttpOperation& operator=(const ProdigyHostHttpOperation&) = delete;

  bool submit(Request request)
  {
    if (pending || complete || completion || !client)
    {
      return false;
    }

    completion = new Completion();
    completion->owner = this;
    completion->submitting = true;
    pending = true;
    const Ticket ticket = client.submit(client.context,
                                        std::move(request),
                                        {completion, Completion::completed});
    completion->submitting = false;
    if (!ticket)
    {
      completion->pending = false;
      result = {};
      result.status = MultiCurlClient::Status::initializationFailure;
      pending = false;
      complete = true;
      return true;
    }

    completion->ticket = ticket;
    if (completion->inlineCompletion && sameTicket(completion->inlineTicket, ticket))
    {
      settle(*completion, std::move(completion->inlineResult));
    }
    else
    {
      completion->inlineTicket = {};
      completion->inlineResult = {};
      completion->inlineCompletion = false;
    }
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

  bool hasResult(void) const
  {
    return complete;
  }

  Result takeResult(void)
  {
    complete = false;
    return std::move(result);
  }

  void abandon(void)
  {
    disarm();
  }
};
class ProdigyHostHttpBatchOperation final
{
public:

  using Ticket = ProdigyHostHttpOperation::Ticket;
  using Request = ProdigyHostHttpOperation::Request;
  using Result = ProdigyHostHttpOperation::Result;
  using Callback = ProdigyHostHttpOperation::Callback;
  using Submission = ProdigyHostHttpOperation::Submission;

private:

  struct Entry
  {
    ProdigyHostHttpBatchOperation *owner = nullptr;
    uint32_t index = 0;
    Ticket ticket;
    Ticket inlineTicket;
    Result inlineResult;
    bool submitting = false;
    bool inlineCompletion = false;
    bool pending = true;

    static void completed(void *context, Ticket ticket, Result&& result)
    {
      Entry *entry = static_cast<Entry *>(context);
      if (entry->owner)
      {
        entry->owner->completed(*entry, ticket, std::move(result));
      }
      else if (entry->pending && entry->ticket && ticket &&
               entry->ticket.identifier == ticket.identifier &&
               entry->ticket.generation == ticket.generation)
      {
        entry->pending = false;
        delete entry;
      }
    }
  };

  Submission client;
  CoroutineStack *stack = nullptr;
  Vector<Entry *> entries;
  Vector<Result> results;
  uint32_t remaining = 0;
  bool wakeArmed = false;
  bool submitted = false;
  bool taken = false;

  static bool sameTicket(Ticket left, Ticket right)
  {
    return left.identifier == right.identifier && left.generation == right.generation;
  }

  void settle(Entry& entry, Result&& result)
  {
    if (entry.pending == false)
    {
      return;
    }
    entry.pending = false;
    entry.ticket = {};
    results[entry.index] = std::move(result);
    if (remaining > 0)
    {
      --remaining;
    }
    if (remaining == 0 && wakeArmed)
    {
      wakeArmed = false;
      CoroutineStack *const wakeStack = stack;
      if (wakeStack)
      {
        wakeStack->co_consume();
      }
    }
  }

  void completed(Entry& entry, Ticket ticket, Result&& result)
  {
    if (entry.pending == false || !ticket)
    {
      return;
    }
    if (entry.submitting)
    {
      if (entry.inlineCompletion == false)
      {
        entry.inlineTicket = ticket;
        entry.inlineResult = std::move(result);
        entry.inlineCompletion = true;
      }
      return;
    }
    if (sameTicket(entry.ticket, ticket))
    {
      settle(entry, std::move(result));
    }
  }

  void abandon(void)
  {
    wakeArmed = false;
    stack = nullptr;
    for (uint32_t index = 0; index < entries.size(); ++index)
    {
      Entry *entry = entries[index];
      entries[index] = nullptr;
      if (entry == nullptr)
      {
        continue;
      }
      if (entry->pending && entry->ticket && client.cancel)
      {
        entry->owner = nullptr;
        (void)client.cancel(client.context, entry->ticket);
      }
      else
      {
        delete entry;
      }
    }
    entries.clear();
    results.clear();
    remaining = 0;
  }

public:

  ProdigyHostHttpBatchOperation(Submission client, CoroutineStack& stack)
      : client(client),
        stack(&stack)
  {}

  ~ProdigyHostHttpBatchOperation()
  {
    abandon();
  }

  ProdigyHostHttpBatchOperation(const ProdigyHostHttpBatchOperation&) = delete;
  ProdigyHostHttpBatchOperation& operator=(const ProdigyHostHttpBatchOperation&) = delete;

  bool submit(Vector<Request> requests)
  {
    if (submitted || requests.size() > uint64_t(UINT32_MAX) ||
        client.submit == nullptr || client.cancel == nullptr)
    {
      return false;
    }
    submitted = true;
    remaining = uint32_t(requests.size());
    entries.resize(requests.size(), nullptr);
    results.resize(requests.size());
    for (uint32_t index = 0; index < requests.size(); ++index)
    {
      Entry *entry = new Entry();
      entry->owner = this;
      entry->index = index;
      entries[index] = entry;
    }
    for (uint32_t index = 0; index < requests.size(); ++index)
    {
      Entry& entry = *entries[index];
      entry.submitting = true;
      const Ticket ticket = client.submit(client.context,
                                          std::move(requests[index]),
                                          {&entry, Entry::completed});
      entry.submitting = false;
      if (ticket && entry.inlineCompletion && sameTicket(ticket, entry.inlineTicket))
      {
        entry.ticket = ticket;
        settle(entry, std::move(entry.inlineResult));
      }
      else if (ticket)
      {
        entry.ticket = ticket;
        entry.inlineTicket = {};
        entry.inlineResult = {};
        entry.inlineCompletion = false;
      }
      else
      {
        Result result = {};
        result.status = MultiCurlClient::Status::initializationFailure;
        settle(entry, std::move(result));
      }
    }
    return true;
  }

  bool mustSuspend(void)
  {
    if (remaining == 0)
    {
      return false;
    }
    wakeArmed = true;
    return true;
  }

  uint32_t pendingCount(void) const
  {
    return remaining;
  }

  bool takeResults(Vector<Result>& output)
  {
    if (submitted == false || remaining != 0 || taken == true)
    {
      return false;
    }
    output = std::move(results);
    taken = true;
    return true;
  }
};
