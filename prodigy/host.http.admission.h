#pragma once

#include <prodigy/host.delay.operation.h>
#include <prodigy/host.http.operation.h>

class ProdigyHostHttpAdmission final
{
public:

  using Ticket = ProdigyHostHttpOperation::Ticket;
  using Request = ProdigyHostHttpOperation::Request;
  using Result = ProdigyHostHttpOperation::Result;
  using Callback = ProdigyHostHttpOperation::Callback;
  using Submission = ProdigyHostHttpOperation::Submission;

  constexpr static uint32_t defaultCapacity = 64;
  constexpr static uint32_t defaultMaximumQueuedRequests = 256;
  constexpr static uint64_t defaultMaximumQueuedBytes = 64 * 1024 * 1024;

private:

  struct Entry
  {
    ProdigyHostHttpAdmission *owner = nullptr;
    Entry *newer = nullptr;
    Entry *older = nullptr;
    Ticket ticket;
    Ticket clientTicket;
    Ticket inlineTicket;
    Request request;
    Callback callback;
    Result inlineResult;
    uint64_t bytes = 0;
    bool queued = false;
    bool active = false;
    bool submitting = false;
    bool inlineCompletion = false;

    static void completed(void *context, Ticket ticket, Result&& result)
    {
      Entry *entry = static_cast<Entry *>(context);
      entry->owner->completed(*entry, ticket, std::move(result));
    }
  };

  class DeadlineWake final : public TimeoutDispatcher
  {
  public:

    ProdigyHostHttpAdmission *owner;
    ProdigyHostDelayOperation::Submission ring;
    TimeoutPacket packet;

    DeadlineWake(ProdigyHostHttpAdmission& requestedOwner,
                 ProdigyHostDelayOperation::Submission requestedRing,
                 uint64_t microseconds)
        : owner(&requestedOwner),
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
      ProdigyHostHttpAdmission *const completedOwner = owner;
      owner = nullptr;
      if (completedOwner)
      {
        completedOwner->deadlineExpired(this);
      }
      delete this;
    }

    void abandon(void)
    {
      owner = nullptr;
      ring.cancel(ring.context, &packet);
    }
  };

  Submission client;
  ProdigyHostDelayOperation::Submission ring;
  bytell_hash_map<uint64_t, Entry *> entries;
  Entry *oldest = nullptr;
  Entry *newest = nullptr;
  DeadlineWake *deadlineWake = nullptr;
  MultiCurlClient::TimePoint armedDeadline = MultiCurlClient::TimePoint::max();
  uint64_t nextIdentifier = 1;
  uint64_t nextGeneration = 1;
  uint64_t queuedBytes = 0;
  uint32_t queuedRequests = 0;
  uint32_t active = 0;
  uint32_t capacity;
  uint32_t maximumQueuedRequests;
  uint64_t maximumQueuedBytes;
  bool dispatching = false;
  bool refillRequested = false;
  bool stopping = false;
  uint32_t callbackDepth = 0;

  static bool sameTicket(Ticket left, Ticket right)
  {
    return left.identifier == right.identifier && left.generation == right.generation;
  }

  static uint64_t advance(uint64_t& value)
  {
    uint64_t result = value++;
    if (result == 0)
    {
      result = value++;
    }
    if (value == 0)
    {
      value = 1;
    }
    return result;
  }

  static void addBytes(uint64_t& total, uint64_t bytes)
  {
    total = bytes > UINT64_MAX - total ? UINT64_MAX : total + bytes;
  }

  static uint64_t requestBytes(const Request& request)
  {
    uint64_t bytes = 0;
    addBytes(bytes, request.url.size());
    addBytes(bytes, request.resolveHost.size());
    addBytes(bytes, request.authority.size());
    addBytes(bytes, request.body.size());
    addBytes(bytes, request.originPolicy.requiredScheme.size());
    addBytes(bytes, request.originPolicy.requiredHost.size());
    addBytes(bytes, request.originPolicy.requiredAuthority.size());
    addBytes(bytes, request.originPolicy.requiredService.size());
    addBytes(bytes, request.originPolicy.requiredResolveHost.size());
    addBytes(bytes, request.caFile.size());
    addBytes(bytes, request.caPath.size());
    addBytes(bytes, request.caBlob.size());
    addBytes(bytes, request.clientCertificateFile.size());
    addBytes(bytes, request.clientKeyFile.size());
    addBytes(bytes, request.clientCertificateBlob.size());
    addBytes(bytes, request.clientKeyBlob.size());
    for (const MultiCurlClient::Header& header : request.headers)
    {
      addBytes(bytes, header.name.size());
      addBytes(bytes, header.value.size());
    }
    return bytes;
  }

  Ticket issueTicket(void)
  {
    const uint32_t maximumRequests = capacity + maximumQueuedRequests;
    for (uint32_t attempt = 0; attempt <= maximumRequests; ++attempt)
    {
      Ticket ticket {advance(nextIdentifier), advance(nextGeneration)};
      if (entries.contains(ticket.identifier) == false)
      {
        return ticket;
      }
    }
    return {};
  }

  static Ticket submit(void *context, Request&& request, Callback callback)
  {
    return static_cast<ProdigyHostHttpAdmission *>(context)->submit(std::move(request), callback);
  }

  static bool cancel(void *context, Ticket ticket)
  {
    return static_cast<ProdigyHostHttpAdmission *>(context)->cancel(ticket);
  }

  void deliver(Callback callback, Ticket ticket, Result&& result)
  {
    if (callback)
    {
      ++callbackDepth;
      callback.function(callback.context, ticket, std::move(result));
      --callbackDepth;
    }
  }

  void enqueue(Entry& entry)
  {
    entry.queued = true;
    entry.older = newest;
    if (newest)
    {
      newest->newer = &entry;
    }
    else
    {
      oldest = &entry;
    }
    newest = &entry;
    ++queuedRequests;
    queuedBytes += entry.bytes;
  }

  void unlink(Entry& entry)
  {
    if (entry.queued == false)
    {
      return;
    }
    if (entry.newer)
    {
      entry.newer->older = entry.older;
    }
    else
    {
      newest = entry.older;
    }
    if (entry.older)
    {
      entry.older->newer = entry.newer;
    }
    else
    {
      oldest = entry.newer;
    }
    entry.newer = nullptr;
    entry.older = nullptr;
    entry.queued = false;
    --queuedRequests;
    queuedBytes -= entry.bytes;
  }

  void disarmDeadline(void)
  {
    DeadlineWake *const wake = deadlineWake;
    deadlineWake = nullptr;
    armedDeadline = MultiCurlClient::TimePoint::max();
    if (wake)
    {
      wake->abandon();
    }
  }

  void armDeadline(void)
  {
    MultiCurlClient::TimePoint earliest = MultiCurlClient::TimePoint::max();
    for (Entry *entry = oldest; entry; entry = entry->newer)
    {
      earliest = std::min(earliest, entry->request.overallDeadline);
    }
    if (earliest == armedDeadline)
    {
      return;
    }
    disarmDeadline();
    if (earliest == MultiCurlClient::TimePoint::max())
    {
      return;
    }
    const MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now();
    const uint64_t microseconds = earliest <= now ? 1 :
        uint64_t(std::max<int64_t>(1,
            std::chrono::duration_cast<std::chrono::microseconds>(earliest - now).count()));
    deadlineWake = new DeadlineWake(*this, ring, microseconds);
    armedDeadline = earliest;
    ring.queue(ring.context, &deadlineWake->packet);
  }

  void finish(Entry& entry, Result&& result)
  {
    const Ticket ticket = entry.ticket;
    const Callback callback = entry.callback;
    Result completedResult = std::move(result);
    unlink(entry);
    if (entry.active && active > 0)
    {
      --active;
    }
    entries.erase(ticket.identifier);
    delete &entry;
    deliver(callback, ticket, std::move(completedResult));
    refill();
  }

  void completed(Entry& entry, Ticket ticket, Result&& result)
  {
    if (!ticket)
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
    if (entry.active && sameTicket(entry.clientTicket, ticket))
    {
      finish(entry, std::move(result));
    }
  }

  void dispatch(Entry& entry)
  {
    unlink(entry);
    entry.active = true;
    entry.submitting = true;
    ++active;
    const Ticket ticket = client.submit(client.context,
                                        std::move(entry.request),
                                        {&entry, Entry::completed});
    entry.submitting = false;
    if (entry.inlineCompletion && ticket && sameTicket(entry.inlineTicket, ticket))
    {
      entry.clientTicket = ticket;
      finish(entry, std::move(entry.inlineResult));
      return;
    }
    if (!ticket)
    {
      Result result;
      result.status = MultiCurlClient::Status::initializationFailure;
      finish(entry, std::move(result));
      return;
    }
    entry.clientTicket = ticket;
    entry.inlineTicket = {};
    entry.inlineResult = {};
    entry.inlineCompletion = false;
  }

  void refill(void)
  {
    if (dispatching)
    {
      refillRequested = true;
      return;
    }
    dispatching = true;
    do
    {
      refillRequested = false;
      while (!stopping && active < capacity && oldest)
      {
        dispatch(*oldest);
      }
    } while (refillRequested);
    armDeadline();
    dispatching = false;
  }

  void deadlineExpired(DeadlineWake *wake)
  {
    if (wake != deadlineWake)
    {
      return;
    }
    deadlineWake = nullptr;
    armedDeadline = MultiCurlClient::TimePoint::max();
    const MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now();
    Vector<Ticket> expired;
    expired.reserve(queuedRequests);
    for (Entry *entry = oldest; entry; entry = entry->newer)
    {
      if (entry->request.overallDeadline <= now)
      {
        expired.push_back(entry->ticket);
      }
    }
    const bool wasDispatching = dispatching;
    dispatching = true;
    for (Ticket ticket : expired)
    {
      auto position = entries.find(ticket.identifier);
      if (position != entries.end() && sameTicket(position->second->ticket, ticket) &&
          position->second->queued && position->second->request.overallDeadline <= now)
      {
        Result result;
        result.status = MultiCurlClient::Status::deadlineExceeded;
        finish(*position->second, std::move(result));
      }
    }
    dispatching = wasDispatching;
    if (wasDispatching == false)
    {
      refill();
    }
  }

public:

  ProdigyHostHttpAdmission(Submission client,
                           ProdigyHostDelayOperation::Submission ring,
                           uint32_t capacity = defaultCapacity,
                           uint32_t maximumQueuedRequests = defaultMaximumQueuedRequests,
                           uint64_t maximumQueuedBytes = defaultMaximumQueuedBytes)
      : client(client),
        ring(ring),
        capacity(capacity),
        maximumQueuedRequests(maximumQueuedRequests),
        maximumQueuedBytes(maximumQueuedBytes)
  {
    if (!client || ring.queue == nullptr || ring.cancel == nullptr || capacity == 0 ||
        maximumQueuedRequests > UINT32_MAX - capacity || maximumQueuedBytes == 0)
    {
      std::abort();
    }
    entries.reserve(capacity + maximumQueuedRequests);
  }

  ~ProdigyHostHttpAdmission()
  {
    if (entries.empty() == false || deadlineWake || callbackDepth != 0)
    {
      std::abort();
    }
  }

  ProdigyHostHttpAdmission(const ProdigyHostHttpAdmission&) = delete;
  ProdigyHostHttpAdmission& operator=(const ProdigyHostHttpAdmission&) = delete;

  Submission submission(void)
  {
    return {this, submit, cancel};
  }

  // Callbacks may reenter this admission owner and may destroy their consuming
  // operation, but the admission owner must outlive the callback and every
  // accepted request. Destruction is valid only after shutdownSafe().

  Ticket submit(Request request, Callback callback)
  {
    const Ticket ticket = issueTicket();
    if (!ticket)
    {
      return {};
    }
    Result rejected;
    if (stopping)
    {
      rejected.status = MultiCurlClient::Status::shutdown;
      deliver(callback, ticket, std::move(rejected));
      return ticket;
    }
    if (request.overallDeadline <= MultiCurlClient::Clock::now())
    {
      rejected.status = MultiCurlClient::Status::deadlineExceeded;
      deliver(callback, ticket, std::move(rejected));
      return ticket;
    }

    const uint64_t bytes = requestBytes(request);
    const bool waits = dispatching || active >= capacity || oldest != nullptr;
    if (waits && (queuedRequests >= maximumQueuedRequests ||
                  bytes > maximumQueuedBytes - std::min(queuedBytes, maximumQueuedBytes)))
    {
      rejected.status = MultiCurlClient::Status::overloaded;
      deliver(callback, ticket, std::move(rejected));
      return ticket;
    }

    Entry *entry = new Entry();
    entry->owner = this;
    entry->ticket = ticket;
    entry->request = std::move(request);
    entry->callback = callback;
    entry->bytes = bytes;
    entries.emplace(ticket.identifier, entry);
    enqueue(*entry);
    refill();
    return ticket;
  }

  bool cancel(Ticket ticket)
  {
    auto position = entries.find(ticket.identifier);
    if (position == entries.end() || !sameTicket(position->second->ticket, ticket))
    {
      return false;
    }
    Entry *entry = position->second;
    if (entry->active)
    {
      return entry->clientTicket && client.cancel(client.context, entry->clientTicket);
    }
    Result result;
    result.status = MultiCurlClient::Status::canceled;
    finish(*entry, std::move(result));
    return true;
  }

  void shutdown(void)
  {
    if (stopping)
    {
      return;
    }
    stopping = true;
    disarmDeadline();
    Vector<Ticket> tickets;
    tickets.reserve(queuedRequests);
    for (Entry *entry = oldest; entry; entry = entry->newer)
    {
      tickets.push_back(entry->ticket);
    }
    const bool wasDispatching = dispatching;
    dispatching = true;
    for (Ticket ticket : tickets)
    {
      auto position = entries.find(ticket.identifier);
      if (position != entries.end() && sameTicket(position->second->ticket, ticket) &&
          position->second->queued)
      {
        Result result;
        result.status = MultiCurlClient::Status::shutdown;
        finish(*position->second, std::move(result));
      }
    }
    dispatching = wasDispatching;
  }

  bool shutdownSafe(void) const
  {
    return stopping && entries.empty() && callbackDepth == 0;
  }

  uint32_t pendingCount(void) const
  {
    return uint32_t(entries.size());
  }

  uint32_t activeCount(void) const
  {
    return active;
  }

  uint32_t queuedCount(void) const
  {
    return queuedRequests;
  }

  uint64_t retainedQueuedBytes(void) const
  {
    return queuedBytes;
  }
};
