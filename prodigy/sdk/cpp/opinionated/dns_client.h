// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "dns_wire.h"

#include <networking/async.dns.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <utility>

namespace ProdigySDK::Opinionated::Dns {
class Client final : public AsyncDnsClient {
public:

  static constexpr std::size_t maximumPendingRequests = 64;

  struct Transport {
    void *context = nullptr;
    bool (*send)(void *context,
                 std::uint64_t service,
                 const std::uint8_t *data,
                 std::size_t size) = nullptr;
    void (*deadlineChanged)(void *context, TimePoint deadline) = nullptr;

    explicit operator bool(void) const
    {
      return send != nullptr;
    }
  };

  // The client, transport context, and callback contexts must outlive every
  // callback. Callbacks may reenter the client but must not destroy it.
  // Transport generations are nonzero and must increase for every replacement
  // transport, including after service reselection.

private:

  struct Pending {
    Ticket ticket;
    Callback callback;
    String hostname;
    String service;
    Family family = Family::any;
    std::uint64_t transportGeneration = 0;
    TimePoint deadline;
  };

  class ExternalCall {
  private:

    Client& client;

  public:

    explicit ExternalCall(Client& owner)
        : client(owner)
    {
      client.externalCallDepth += 1;
    }

    ~ExternalCall()
    {
      client.externalCallDepth -= 1;
    }
  };

  Transport transport;
  std::uint64_t service = 0;
  std::uint16_t applicationID = 0;
  std::uint64_t transportGeneration = 0;
  std::uint64_t nextIdentifier = 1;
  std::uint64_t nextGeneration = 1;
  bool connected = false;
  bool authenticated = false;
  bool echoSent = false;
  bool stopping = false;
  std::size_t externalCallDepth = 0;
  Session expectedChallenge;
  bytell_hash_map<std::uint64_t, Pending> pending;

  static std::uint64_t advance(std::uint64_t& value)
  {
    std::uint64_t result = value++;
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

  Ticket issueTicket(void)
  {
    for (std::size_t attempt = 0; attempt <= maximumPendingRequests; attempt += 1)
    {
      Ticket ticket {advance(nextIdentifier), advance(nextGeneration)};
      if (pending.contains(ticket.identifier) == false)
      {
        return ticket;
      }
    }
    return {};
  }

  static AsyncDnsResolver::Status resolverStatus(ResolveStatus status)
  {
    using Status = AsyncDnsResolver::Status;
    switch (status)
    {
      case ResolveStatus::success:
        return Status::success;
      case ResolveStatus::canceled:
        return Status::canceled;
      case ResolveStatus::deadlineExceeded:
        return Status::deadlineExceeded;
      case ResolveStatus::invalidHostname:
        return Status::invalidHostname;
      case ResolveStatus::invalidService:
        return Status::invalidService;
      case ResolveStatus::singleLabelRejected:
        return Status::singleLabelRejected;
      case ResolveStatus::unsupportedFamily:
        return Status::unsupportedFamily;
      case ResolveStatus::notFound:
        return Status::notFound;
      case ResolveStatus::noData:
        return Status::noData;
      case ResolveStatus::tooManyAnswers:
        return Status::tooManyAnswers;
      case ResolveStatus::overloaded:
        return Status::overloaded;
      case ResolveStatus::backendFailure:
        return Status::backendFailure;
      case ResolveStatus::shutdown:
        return Status::shutdown;
    }
    return Status::backendFailure;
  }

  static Dns::Family wireFamily(AsyncDnsResolver::Family family)
  {
    switch (family)
    {
      case AsyncDnsResolver::Family::any:
        return Dns::Family::any;
      case AsyncDnsResolver::Family::ipv4:
        return Dns::Family::ipv4;
      case AsyncDnsResolver::Family::ipv6:
        return Dns::Family::ipv6;
    }
    return Dns::Family::any;
  }

  static std::uint16_t servicePort(const String& normalizedService)
  {
    std::uint32_t port = 0;
    for (std::uint8_t byte : normalizedService)
    {
      port = port * 10 + std::uint32_t(byte - '0');
    }
    return std::uint16_t(port);
  }

  void deliver(Callback callback, Ticket ticket, AsyncDnsResolver::Result result)
  {
    if (callback)
    {
      ExternalCall external(*this);
      callback.function(callback.context, ticket, std::move(result));
    }
  }

  void publishDeadline(void)
  {
    if (transport.deadlineChanged)
    {
      ExternalCall external(*this);
      transport.deadlineChanged(transport.context, earliestDeadline());
    }
  }

  bool send(const String& frame)
  {
    if (!transport || !connected || service == 0)
    {
      return false;
    }
    ExternalCall external(*this);
    return transport.send(transport.context, service, frame.data(), frame.size());
  }

  bool activeSession(void) const
  {
    return ready() && connected && authenticated;
  }

  void sendCancel(Ticket ticket)
  {
    Cancel cancelPayload {ticket.identifier, ticket.generation};
    String frame;
    if (authenticated && encodeCancel(cancelPayload, frame))
    {
      (void)send(frame);
    }
  }

  bool exactSession(const Session& session) const
  {
    return session.applicationID == expectedChallenge.applicationID &&
           session.service == expectedChallenge.service &&
           session.nonce == expectedChallenge.nonce &&
           session.generation == expectedChallenge.generation;
  }

  bool handleSession(const std::uint8_t *data, std::size_t size)
  {
    Session session;
    if (!parseSession(data, size, session) || session.service != service ||
        session.applicationID != applicationID || authenticated)
    {
      return false;
    }

    if (echoSent)
    {
      if (session.phase != SessionPhase::serviceAck || !exactSession(session))
      {
        return false;
      }
      echoSent = false;
      authenticated = true;
      replayPending();
      return true;
    }

    if (session.phase != SessionPhase::serviceChallenge || expectedChallenge.nonce != 0)
    {
      return false;
    }

    expectedChallenge = session;
    echoSent = true;
    session.phase = SessionPhase::applicationEcho;
    String frame;
    if (!encodeSession(session, frame) || !send(frame))
    {
      expectedChallenge = {};
      echoSent = false;
      return false;
    }
    return true;
  }

  bool validAddressSet(const Pending& request, const Resolve& response) const
  {
    for (const Address& address : response.addresses)
    {
      if ((request.family == AsyncDnsResolver::Family::ipv4 &&
           address.family != Dns::Family::ipv4) ||
          (request.family == AsyncDnsResolver::Family::ipv6 &&
           address.family != Dns::Family::ipv6))
      {
        return false;
      }
    }
    return true;
  }

  static AsyncDnsResolver::Address resolverAddress(const Address& address,
                                                   std::uint16_t port)
  {
    AsyncDnsResolver::Address resolved;
    resolved.ttlSeconds = address.ttlSeconds;
    if (address.family == Dns::Family::ipv4)
    {
      sockaddr_in value {};
      value.sin_family = AF_INET;
      value.sin_port = htons(port);
      std::memcpy(&value.sin_addr, address.bytes, sizeof(value.sin_addr));
      std::memcpy(&resolved.storage, &value, sizeof(value));
      resolved.length = sizeof(value);
    }
    else
    {
      sockaddr_in6 value {};
      value.sin6_family = AF_INET6;
      value.sin6_port = htons(port);
      std::memcpy(&value.sin6_addr, address.bytes, sizeof(value.sin6_addr));
      std::memcpy(&resolved.storage, &value, sizeof(value));
      resolved.length = sizeof(value);
    }
    return resolved;
  }

  bool handleResolve(const std::uint8_t *data, std::size_t size)
  {
    Resolve response;
    if (!parseResolveResult(data, size, response))
    {
      return false;
    }

    auto position = pending.find(response.requestID);
    if (position == pending.end() ||
        position->second.ticket.generation != response.generation ||
        position->second.transportGeneration != transportGeneration)
    {
      return true;
    }
    if (!validAddressSet(position->second, response))
    {
      return false;
    }

    Pending request = position->second;
    pending.erase(position);
    publishDeadline();
    AsyncDnsResolver::Result result;
    result.status = resolverStatus(response.status);
    result.canonicalName = std::move(response.canonicalName);
    result.canonicalNameTtlSeconds = response.canonicalNameTtlSeconds;
    result.timeouts = response.timeouts;
    result.addresses.reserve(response.addresses.size());
    for (const Address& address : response.addresses)
    {
      result.addresses.push_back(resolverAddress(address, servicePort(request.service)));
    }
    deliver(request.callback, request.ticket, std::move(result));
    return true;
  }

  void complete(Ticket ticket, AsyncDnsResolver::Status status)
  {
    auto position = pending.find(ticket.identifier);
    if (position == pending.end() || position->second.ticket.generation != ticket.generation)
    {
      return;
    }
    Callback callback = position->second.callback;
    pending.erase(position);
    publishDeadline();
    AsyncDnsResolver::Result result;
    result.status = status;
    deliver(callback, ticket, std::move(result));
  }

  bool cancelPending(Ticket ticket, AsyncDnsResolver::Status status)
  {
    auto position = pending.find(ticket.identifier);
    if (position == pending.end() || position->second.ticket.generation != ticket.generation)
    {
      return false;
    }
    Callback callback = position->second.callback;
    const bool cancelRemote = position->second.transportGeneration == transportGeneration &&
                              activeSession();
    pending.erase(position);
    if (cancelRemote)
    {
      sendCancel(ticket);
    }
    publishDeadline();
    AsyncDnsResolver::Result result;
    result.status = status;
    deliver(callback, ticket, std::move(result));
    return true;
  }

  void completeAll(AsyncDnsResolver::Status status)
  {
    struct Completion {
      Ticket ticket;
      Callback callback;
    };
    Vector<Completion> completions;
    completions.reserve(pending.size());
    for (const auto& [identifier, request] : pending)
    {
      (void)identifier;
      completions.push_back({request.ticket, request.callback});
    }
    pending.clear();
    publishDeadline();
    for (const Completion& completion : completions)
    {
      AsyncDnsResolver::Result result;
      result.status = status;
      deliver(completion.callback, completion.ticket, std::move(result));
    }
  }

  void detachPending(void)
  {
    for (auto& [identifier, request] : pending)
    {
      (void)identifier;
      request.transportGeneration = 0;
    }
  }

  bool sendPending(Ticket ticket, TimePoint now)
  {
    auto position = pending.find(ticket.identifier);
    if (position == pending.end() ||
        position->second.ticket.generation != ticket.generation ||
        !activeSession())
    {
      return false;
    }
    Pending& request = position->second;
    if (request.deadline <= now)
    {
      return cancelPending(ticket, AsyncDnsResolver::Status::deadlineExceeded);
    }

    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        request.deadline - now);
    Resolve framePayload;
    framePayload.requestID = ticket.identifier;
    framePayload.generation = ticket.generation;
    framePayload.deadlineMilliseconds = std::uint32_t(
        std::clamp<std::int64_t>(remaining.count(),
                                 1,
                                 std::int64_t(maximumDeadlineMilliseconds)));
    framePayload.family = wireFamily(request.family);
    framePayload.hostname = request.hostname;
    String frame;
    if (!encodeResolveRequest(framePayload, frame))
    {
      complete(ticket, AsyncDnsResolver::Status::backendFailure);
      return false;
    }

    const std::uint64_t sentGeneration = transportGeneration;
    request.transportGeneration = sentGeneration;
    const bool sent = send(frame);
    position = pending.find(ticket.identifier);
    if (position == pending.end() || position->second.ticket.generation != ticket.generation)
    {
      return sent;
    }
    if (!sent && transportGeneration == sentGeneration &&
        position->second.transportGeneration == sentGeneration)
    {
      connected = false;
      authenticated = false;
      echoSent = false;
      expectedChallenge = {};
      detachPending();
    }
    return sent;
  }

  void replayPending(void)
  {
    Vector<Ticket> tickets;
    tickets.reserve(pending.size());
    for (const auto& [identifier, request] : pending)
    {
      (void)identifier;
      tickets.push_back(request.ticket);
    }
    const TimePoint now = AsyncDnsResolver::Clock::now();
    for (Ticket ticket : tickets)
    {
      if (!activeSession())
      {
        break;
      }
      (void)sendPending(ticket, now);
    }
  }

public:

  explicit Client(Transport requestedTransport)
      : transport(requestedTransport)
  {
    pending.reserve(maximumPendingRequests);
  }

  ~Client()
  {
    if (externalCallDepth != 0 || !pending.empty())
    {
      std::abort();
    }
  }

  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;

  bool selectService(std::uint64_t selectedService,
                     std::uint16_t selectedApplicationID)
  {
    if (stopping || selectedService == 0 || selectedApplicationID == 0)
    {
      return false;
    }
    if (service == selectedService && applicationID == selectedApplicationID)
    {
      return true;
    }
    service = selectedService;
    applicationID = selectedApplicationID;
    connected = false;
    authenticated = false;
    echoSent = false;
    expectedChallenge = {};
    detachPending();
    return true;
  }

  bool transportConnected(std::uint64_t connectedService,
                          std::uint64_t generation)
  {
    if (stopping || service == 0 || connectedService != service || generation == 0)
    {
      return false;
    }
    if (generation == transportGeneration)
    {
      return connected;
    }
    if (generation < transportGeneration)
    {
      return false;
    }
    transportGeneration = generation;
    connected = true;
    authenticated = false;
    echoSent = false;
    expectedChallenge = {};
    detachPending();
    return true;
  }

  bool serviceLost(std::uint64_t lostService,
                   std::uint64_t generation)
  {
    if (service == 0 || lostService != service || generation == 0 ||
        generation != transportGeneration)
    {
      return false;
    }
    connected = false;
    authenticated = false;
    echoSent = false;
    expectedChallenge = {};
    detachPending();
    return true;
  }

  bool handleFrame(std::uint64_t sourceService,
                   std::uint64_t generation,
                   const std::uint8_t *data,
                   std::size_t size)
  {
    if (stopping || !connected || sourceService != service || generation == 0 ||
        generation != transportGeneration)
    {
      return false;
    }
    Topic topic;
    if (!frameTopic(data, size, topic))
    {
      return false;
    }
    if (topic == Topic::session)
    {
      return handleSession(data, size);
    }
    if (!authenticated)
    {
      return false;
    }
    if (topic == Topic::resolve)
    {
      return handleResolve(data, size);
    }
    Cancel cancel;
    return parseCancel(data, size, cancel);
  }

  bool ready(void) const override
  {
    return !stopping && transport && service != 0 && applicationID != 0;
  }

  bool sessionReady(void) const
  {
    return activeSession();
  }

  Ticket resolve(const String& hostname,
                 const String& requestedService,
                 AsyncDnsResolver::Family family,
                 Callback callback,
                 TimePoint deadline = TimePoint::max()) override
  {
    const Ticket ticket = issueTicket();
    if (!ticket)
    {
      AsyncDnsResolver::Result result;
      result.status = AsyncDnsResolver::Status::overloaded;
      deliver(callback, ticket, std::move(result));
      return ticket;
    }

    if (stopping)
    {
      AsyncDnsResolver::Result result;
      result.status = AsyncDnsResolver::Status::shutdown;
      deliver(callback, ticket, std::move(result));
      return ticket;
    }

    AsyncDnsResolver::NormalizedQuery normalized =
        AsyncDnsResolver::normalize(hostname, requestedService, family, true);
    if (!normalized.valid())
    {
      AsyncDnsResolver::Result result;
      result.status = normalized.status;
      deliver(callback, ticket, std::move(result));
      return ticket;
    }
    if (normalized.numeric)
    {
      AsyncDnsResolver::Result result;
      result.status = AsyncDnsResolver::Status::success;
      result.canonicalName = normalized.hostname;
      result.canonicalNameTtlSeconds = std::numeric_limits<std::uint32_t>::max();
      result.addresses.push_back(normalized.numericAddress);
      deliver(callback, ticket, std::move(result));
      return ticket;
    }

    const TimePoint now = AsyncDnsResolver::Clock::now();
    if (deadline <= now)
    {
      AsyncDnsResolver::Result result;
      result.status = AsyncDnsResolver::Status::deadlineExceeded;
      deliver(callback, ticket, std::move(result));
      return ticket;
    }
    if (!ready())
    {
      AsyncDnsResolver::Result result;
      result.status = AsyncDnsResolver::Status::backendFailure;
      deliver(callback, ticket, std::move(result));
      return ticket;
    }
    if (pending.size() >= maximumPendingRequests)
    {
      AsyncDnsResolver::Result result;
      result.status = AsyncDnsResolver::Status::overloaded;
      deliver(callback, ticket, std::move(result));
      return ticket;
    }

    const TimePoint boundedDeadline = std::min(
        deadline,
        now + std::chrono::milliseconds(maximumDeadlineMilliseconds));
    Pending request;
    request.ticket = ticket;
    request.callback = callback;
    request.hostname = std::move(normalized.hostname);
    request.service = std::move(normalized.service);
    request.family = normalized.family;
    request.deadline = boundedDeadline;
    pending.emplace(ticket.identifier, std::move(request));
    publishDeadline();
    if (activeSession())
    {
      (void)sendPending(ticket, now);
    }
    return ticket;
  }

  bool cancel(Ticket ticket) override
  {
    return cancelPending(ticket, AsyncDnsResolver::Status::canceled);
  }

  TimePoint earliestDeadline(void) const
  {
    TimePoint deadline = TimePoint::max();
    for (const auto& [identifier, request] : pending)
    {
      (void)identifier;
      deadline = std::min(deadline, request.deadline);
    }
    return deadline;
  }

  std::size_t expireDeadlines(TimePoint now = AsyncDnsResolver::Clock::now())
  {
    Vector<Ticket> expired;
    expired.reserve(pending.size());
    for (const auto& [identifier, request] : pending)
    {
      (void)identifier;
      if (request.deadline <= now)
      {
        expired.push_back(request.ticket);
      }
    }
    std::size_t completed = 0;
    for (Ticket ticket : expired)
    {
      completed += cancelPending(ticket, AsyncDnsResolver::Status::deadlineExceeded);
    }
    return completed;
  }

  void shutdown(void)
  {
    if (stopping)
    {
      return;
    }
    stopping = true;
    connected = false;
    authenticated = false;
    echoSent = false;
    expectedChallenge = {};
    completeAll(AsyncDnsResolver::Status::shutdown);
  }

  std::size_t pendingCount(void) const
  {
    return pending.size();
  }
};
} // namespace ProdigySDK::Opinionated::Dns
