// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

#include "../opinionated/dns_client.h"

#include <arpa/inet.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>

namespace {
using namespace ProdigySDK::Opinionated;

struct Suite {
  std::size_t failures = 0;

  void expect(bool condition, const char *name)
  {
    if (!condition)
    {
      failures += 1;
      std::cerr << "FAIL: " << name << '\n';
    }
  }
};

struct FakeTransport {
  Vector<String> frames;
  Dns::Client *client = nullptr;
  std::uint64_t service = 0;
  AsyncDnsResolver::TimePoint deadline = AsyncDnsResolver::TimePoint::max();
  bool accept = true;
  bool expireDuringSend = false;

  static bool send(void *context,
                   std::uint64_t service,
                   const std::uint8_t *data,
                   std::size_t size)
  {
    FakeTransport& transport = *static_cast<FakeTransport *>(context);
    transport.service = service;
    if (!transport.accept)
    {
      return false;
    }
    String frame;
    frame.assign(data, size);
    transport.frames.push_back(std::move(frame));
    if (transport.expireDuringSend)
    {
      transport.client->expireDeadlines(AsyncDnsResolver::TimePoint::max());
    }
    return true;
  }

  static void deadlineChanged(void *context, AsyncDnsResolver::TimePoint deadline)
  {
    static_cast<FakeTransport *>(context)->deadline = deadline;
  }
};

struct Completion {
  std::size_t calls = 0;
  AsyncDnsResolver::Ticket ticket;
  AsyncDnsResolver::Result result;

  static void receive(void *context,
                      AsyncDnsResolver::Ticket ticket,
                      AsyncDnsResolver::Result&& result)
  {
    Completion& completion = *static_cast<Completion *>(context);
    completion.calls += 1;
    completion.ticket = ticket;
    completion.result = std::move(result);
  }
};

Dns::Session authenticate(Dns::Client& client,
                          FakeTransport& transport,
                          Suite& suite,
                          std::uint64_t service,
                          std::uint16_t applicationID,
                          std::uint64_t transportGeneration)
{
  Dns::Session challenge;
  challenge.phase = Dns::SessionPhase::serviceChallenge;
  challenge.applicationID = applicationID;
  challenge.service = service;
  challenge.nonce = 0x1122334455667788ULL;
  challenge.generation = 0x8877665544332211ULL;
  String frame;
  transport.frames.clear();
  suite.expect(Dns::encodeSession(challenge, frame), "encode session challenge");
  suite.expect(client.handleFrame(
                   service, transportGeneration, frame.data(), frame.size()),
               "accept session challenge");
  suite.expect(transport.frames.size() == 1, "emit exactly one session echo");
  Dns::Session echo;
  suite.expect(Dns::parseSession(transport.frames[0].data(), transport.frames[0].size(), echo),
               "parse session echo");
  suite.expect(echo.phase == Dns::SessionPhase::applicationEcho &&
                   echo.nonce == challenge.nonce && echo.generation == challenge.generation,
               "echo exact challenge");

  transport.frames.clear();
  challenge.phase = Dns::SessionPhase::serviceAck;
  suite.expect(Dns::encodeSession(challenge, frame), "encode session ack");
  suite.expect(client.handleFrame(service,
                                  transportGeneration,
                                  frame.data(),
                                  frame.size()),
               "accept exact session ack");
  suite.expect(client.ready() && client.sessionReady(), "client authenticated");
  return challenge;
}

void testWire(Suite& suite)
{
  Dns::Resolve request;
  request.requestID = 7;
  request.generation = 9;
  request.deadlineMilliseconds = 2500;
  request.family = Dns::Family::any;
  request.hostname = "service.example";
  String frame;
  suite.expect(Dns::encodeResolveRequest(request, frame), "encode resolve request");
  Dns::Resolve parsedRequest;
  suite.expect(Dns::parseResolveRequest(frame.data(), frame.size(), parsedRequest),
               "parse resolve request");
  suite.expect(parsedRequest.requestID == request.requestID &&
                   parsedRequest.generation == request.generation &&
                   parsedRequest.hostname == request.hostname,
               "resolve request roundtrip");

  request.status = Dns::ResolveStatus::success;
  suite.expect(!Dns::encodeResolveRequest(request, frame),
               "request rejects result status");
  request.status = Dns::ResolveStatus::backendFailure;
  request.canonicalName = "other.example";
  suite.expect(!Dns::encodeResolveRequest(request, frame),
               "request rejects result metadata");

  Dns::Resolve result;
  result.requestID = 11;
  result.generation = 13;
  result.status = Dns::ResolveStatus::success;
  result.canonicalName = "canonical.example";
  result.canonicalNameTtlSeconds = 45;
  Dns::Address address4;
  address4.family = Dns::Family::ipv4;
  address4.ttlSeconds = 30;
  address4.bytes[0] = 1;
  address4.bytes[1] = 2;
  address4.bytes[2] = 3;
  address4.bytes[3] = 4;
  result.addresses.push_back(address4);
  suite.expect(Dns::encodeResolveResult(result, frame), "encode resolve result");
  Dns::Resolve parsedResult;
  suite.expect(Dns::parseResolveResult(frame.data(), frame.size(), parsedResult),
               "parse resolve result");
  suite.expect(parsedResult.addresses.size() == 1 &&
                   parsedResult.addresses[0].ttlSeconds == 30,
               "resolve result roundtrip");

  result.deadlineMilliseconds = 1;
  suite.expect(!Dns::encodeResolveResult(result, frame),
               "result rejects request deadline");
  result.deadlineMilliseconds = 0;
  result.hostname = "request.example";
  suite.expect(!Dns::encodeResolveResult(result, frame),
               "result rejects request hostname");
  result.hostname.clear();
  result.family = Dns::Family::ipv4;
  suite.expect(!Dns::encodeResolveResult(result, frame),
               "result rejects request family");
  result.family = Dns::Family::any;
  result.canonicalNameTtlSeconds = 0;
  suite.expect(!Dns::encodeResolveResult(result, frame),
               "canonical name requires positive ttl");
  result.canonicalNameTtlSeconds = 45;
  result.addresses[0].bytes[4] = 1;
  suite.expect(!Dns::encodeResolveResult(result, frame),
               "ipv4 encoder rejects hidden bytes");
  result.addresses[0].bytes[4] = 0;
  suite.expect(Dns::encodeResolveResult(result, frame), "re-encode canonical ipv4");
  const std::size_t recordOffset = Dns::headerBytes + 28 + result.canonicalName.size();
  frame[recordOffset + 8 + 4] = 1;
  suite.expect(!Dns::parseResolveResult(frame.data(), frame.size(), parsedResult),
               "ipv4 parser rejects hidden bytes");

  suite.expect(Dns::encodeResolveResult(result, frame), "restore resolve result");
  for (std::size_t size = 0; size < frame.size(); size += 1)
  {
    Dns::Resolve hostile;
    suite.expect(!Dns::parseResolveResult(frame.data(), size, hostile),
                 "truncated resolve result rejected");
  }
  String reservedMutation = frame;
  reservedMutation[7] = 1;
  suite.expect(!Dns::parseResolveResult(
                   reservedMutation.data(), reservedMutation.size(), parsedResult),
               "nonzero header flags rejected");

  Dns::Resolve failure;
  failure.requestID = 21;
  failure.generation = 23;
  failure.status = Dns::ResolveStatus::notFound;
  suite.expect(Dns::encodeResolveResult(failure, frame), "encode negative result");
  frame[36] = 1;
  suite.expect(!Dns::parseResolveResult(frame.data(), frame.size(), parsedResult),
               "negative result rejects canonical ttl");

  while (result.addresses.size() <= Dns::maximumAnswers)
  {
    result.addresses.push_back(address4);
  }
  suite.expect(!Dns::encodeResolveResult(result, frame), "answer 33 rejected");

  Dns::Cancel cancel {17, 19};
  suite.expect(Dns::encodeCancel(cancel, frame), "encode cancel");
  Dns::Cancel parsedCancel;
  suite.expect(Dns::parseCancel(frame.data(), frame.size(), parsedCancel) &&
                   parsedCancel.requestID == cancel.requestID &&
                   parsedCancel.generation == cancel.generation,
               "cancel roundtrip");
  Dns::Topic oversizedTopic;
  suite.expect(!Dns::frameTopic(frame.data(), std::numeric_limits<std::size_t>::max(), oversizedTopic),
               "oversized hostile frame rejected without pointer overflow");

  std::uint32_t random = 0x9e3779b9;
  for (std::size_t iteration = 0; iteration < 2000; iteration += 1)
  {
    random = random * 1664525u + 1013904223u;
    String hostile;
    hostile.resize(random % (Dns::maximumResolveFrameBytes + 1));
    for (std::size_t index = 0; index < hostile.size(); index += 1)
    {
      random = random * 1664525u + 1013904223u;
      hostile[index] = std::uint8_t(random >> 24);
    }
    Dns::Topic hostileTopic;
    Dns::Resolve hostileResolve;
    Dns::Cancel hostileCancel;
    Dns::Session hostileSession;
    (void)Dns::frameTopic(hostile.data(), hostile.size(), hostileTopic);
    (void)Dns::parseResolveRequest(hostile.data(), hostile.size(), hostileResolve);
    (void)Dns::parseResolveResult(hostile.data(), hostile.size(), hostileResolve);
    (void)Dns::parseCancel(hostile.data(), hostile.size(), hostileCancel);
    (void)Dns::parseSession(hostile.data(), hostile.size(), hostileSession);
  }
}

void testClient(Suite& suite)
{
  static_assert(Dns::Client::maximumPendingRequests == 64);
  constexpr std::uint64_t service = 0x1100000000000001ULL;
  constexpr std::uint16_t applicationID = 17;
  constexpr std::uint64_t firstTransportGeneration = 1;
  FakeTransport transport;
  Dns::Client client({&transport, FakeTransport::send, FakeTransport::deadlineChanged});
  transport.client = &client;
  suite.expect(client.selectService(service, applicationID), "select resolver service");
  suite.expect(client.ready() && !client.sessionReady(),
               "configured client accepts work before authentication");

  Completion queued;
  const auto queuedTicket = client.resolve(
      String("Queued.Example"),
      String("8443"),
      AsyncDnsResolver::Family::ipv6,
      {&queued, Completion::receive},
      AsyncDnsResolver::Clock::now() + std::chrono::seconds(5));
  suite.expect(bool(queuedTicket) && queued.calls == 0 && client.pendingCount() == 1 &&
                   transport.frames.empty(),
               "disconnected named lookup remains pending without transport output");
  suite.expect(!client.transportConnected(service, 0),
               "zero transport generation rejected");
  suite.expect(client.transportConnected(service, firstTransportGeneration),
               "connect resolver transport");
  authenticate(client, transport, suite, service, applicationID, firstTransportGeneration);
  suite.expect(transport.frames.size() == 1, "authentication replays queued lookup once");
  Dns::Resolve queuedRequest;
  suite.expect(Dns::parseResolveRequest(
                   transport.frames[0].data(), transport.frames[0].size(), queuedRequest) &&
                   queuedRequest.requestID == queuedTicket.identifier &&
                   queuedRequest.generation == queuedTicket.generation &&
                   queuedRequest.hostname == "queued.example"_ctv &&
                   queuedRequest.family == Dns::Family::ipv6 &&
                   queuedRequest.deadlineMilliseconds > 0,
               "replay owns normalized hostname family and remaining deadline");

  Dns::Resolve queuedResponse;
  queuedResponse.requestID = queuedRequest.requestID;
  queuedResponse.generation = queuedRequest.generation;
  queuedResponse.status = Dns::ResolveStatus::success;
  Dns::Address queuedAddress;
  queuedAddress.family = Dns::Family::ipv6;
  queuedAddress.ttlSeconds = 15;
  queuedAddress.bytes[15] = 1;
  queuedResponse.addresses.push_back(queuedAddress);
  String frame;
  suite.expect(Dns::encodeResolveResult(queuedResponse, frame) &&
                   client.handleFrame(service,
                                      firstTransportGeneration,
                                      frame.data(),
                                      frame.size()) &&
                   queued.calls == 1 && queued.result.succeeded(),
               "replayed queued lookup completes exactly once");
  suite.expect(queued.result.addresses.size() == 1,
               "queued lookup returns one address");
  if (queued.result.addresses.size() == 1)
  {
    const sockaddr_in6 *queued6 = reinterpret_cast<const sockaddr_in6 *>(
        &queued.result.addresses[0].storage);
    suite.expect(ntohs(queued6->sin6_port) == 8443,
                 "queued lookup retains normalized service port");
  }

  transport.frames.clear();
  Completion named;
  const auto namedTicket = client.resolve(
      String("image.example"),
      String("443"),
      AsyncDnsResolver::Family::any,
      {&named, Completion::receive},
      AsyncDnsResolver::Clock::now() + std::chrono::seconds(5));
  suite.expect(bool(namedTicket) && named.calls == 0, "named lookup pending asynchronously");
  suite.expect(transport.frames.size() == 1, "named lookup emits one request");
  Dns::Resolve request;
  suite.expect(Dns::parseResolveRequest(
                   transport.frames[0].data(), transport.frames[0].size(), request),
               "parse emitted named request");
  suite.expect(request.hostname == "image.example"_ctv &&
                   request.requestID == namedTicket.identifier &&
                   request.generation == namedTicket.generation,
               "named request exact identity");

  Dns::Resolve response;
  response.requestID = request.requestID;
  response.generation = request.generation;
  response.status = Dns::ResolveStatus::success;
  response.canonicalName = "cdn.example";
  response.canonicalNameTtlSeconds = 60;
  Dns::Address address4;
  address4.family = Dns::Family::ipv4;
  address4.ttlSeconds = 30;
  address4.bytes[0] = 203;
  address4.bytes[1] = 0;
  address4.bytes[2] = 113;
  address4.bytes[3] = 10;
  response.addresses.push_back(address4);
  response.generation += 1;
  suite.expect(Dns::encodeResolveResult(response, frame), "encode stale generation");
  suite.expect(client.handleFrame(
                   service, firstTransportGeneration, frame.data(), frame.size()) &&
                   named.calls == 0 && client.pendingCount() == 1,
               "stale generation cannot complete request");
  response.generation -= 1;
  suite.expect(Dns::encodeResolveResult(response, frame), "encode service result");
  suite.expect(client.handleFrame(
                   service, firstTransportGeneration, frame.data(), frame.size()),
               "handle service result");
  suite.expect(named.calls == 1 && named.result.succeeded() &&
                   named.result.addresses.size() == 1,
               "named completion exactly once");
  const sockaddr_in *resolved4 = reinterpret_cast<const sockaddr_in *>(
      &named.result.addresses[0].storage);
  suite.expect(named.result.addresses[0].length == sizeof(sockaddr_in) &&
                   ntohs(resolved4->sin_port) == 443,
               "client stamps requested port");

  Completion repeated;
  transport.frames.clear();
  const std::size_t requestsBeforeRepeat = transport.frames.size();
  const auto repeatedTicket = client.resolve(
      String("image.example"),
      String("80"),
      AsyncDnsResolver::Family::ipv4,
      {&repeated, Completion::receive},
      AsyncDnsResolver::Clock::now() + std::chrono::seconds(5));
  suite.expect(transport.frames.size() == requestsBeforeRepeat + 1,
               "repeat emits a new service request without cache");
  suite.expect(client.cancel(repeatedTicket), "cancel exact pending ticket");
  suite.expect(repeated.calls == 1 &&
                   repeated.result.status == AsyncDnsResolver::Status::canceled,
               "cancel completes before return");
  suite.expect(transport.frames.size() == requestsBeforeRepeat + 2,
               "cancel emits one service operation");
  Dns::Cancel cancel;
  suite.expect(Dns::parseCancel(transport.frames.back().data(),
                                transport.frames.back().size(),
                                cancel) &&
                   cancel.requestID == repeatedTicket.identifier &&
                   cancel.generation == repeatedTicket.generation,
               "cancel exact identity");
  suite.expect(!client.cancel(repeatedTicket) && repeated.calls == 1,
               "repeated cancellation cannot complete twice");

  Completion numeric;
  const std::size_t framesBeforeNumeric = transport.frames.size();
  client.resolve(String("192.0.2.8"),
                 String("8443"),
                 AsyncDnsResolver::Family::ipv4,
                 {&numeric, Completion::receive});
  suite.expect(numeric.calls == 1 && numeric.result.succeeded() &&
                   transport.frames.size() == framesBeforeNumeric,
               "numeric literal bypasses DNS service");
  const sockaddr_in *numeric4 = reinterpret_cast<const sockaddr_in *>(
      &numeric.result.addresses[0].storage);
  suite.expect(ntohs(numeric4->sin_port) == 8443, "numeric literal port stamped");

  Completion invalid;
  client.resolve(String("singlelabel"),
                 String("443"),
                 AsyncDnsResolver::Family::any,
                 {&invalid, Completion::receive});
  suite.expect(invalid.calls == 1 &&
                   invalid.result.status == AsyncDnsResolver::Status::singleLabelRejected &&
                   transport.frames.size() == framesBeforeNumeric,
               "invalid hostname rejected locally");

  Completion invalidService;
  client.resolve(String("valid.example"),
                 String("not-a-port"),
                 AsyncDnsResolver::Family::any,
                 {&invalidService, Completion::receive});
  suite.expect(invalidService.calls == 1 &&
                   invalidService.result.status == AsyncDnsResolver::Status::invalidService &&
                   transport.frames.size() == framesBeforeNumeric,
               "invalid service rejected locally");

  Completion deadline;
  transport.frames.clear();
  const std::size_t framesBeforeDeadline = transport.frames.size();
  const auto deadlineTicket = client.resolve(
      String("deadline.example"),
      String("443"),
      AsyncDnsResolver::Family::any,
      {&deadline, Completion::receive},
      AsyncDnsResolver::Clock::now() + std::chrono::milliseconds(5));
  suite.expect(bool(deadlineTicket) && deadline.calls == 0, "deadline request pending");
  suite.expect(client.expireDeadlines(AsyncDnsResolver::Clock::now() +
                                     std::chrono::seconds(1)) == 1,
               "expire exact deadline");
  suite.expect(deadline.calls == 1 &&
                   deadline.result.status == AsyncDnsResolver::Status::deadlineExceeded,
               "deadline completion exactly once");
  suite.expect(transport.frames.size() == framesBeforeDeadline + 2,
               "deadline emits resolve then exact cancel");
  suite.expect(Dns::parseCancel(transport.frames.back().data(),
                                transport.frames.back().size(),
                                cancel) &&
                   cancel.requestID == deadlineTicket.identifier &&
                   cancel.generation == deadlineTicket.generation,
               "deadline cancel exact identity");

  Completion reentrantDeadline;
  transport.frames.clear();
  const std::size_t framesBeforeReentrantDeadline = transport.frames.size();
  transport.expireDuringSend = true;
  client.resolve(String("reentrant-deadline.example"),
                 String("443"),
                 AsyncDnsResolver::Family::any,
                 {&reentrantDeadline, Completion::receive},
                 AsyncDnsResolver::Clock::now() + std::chrono::seconds(5));
  transport.expireDuringSend = false;
  suite.expect(reentrantDeadline.calls == 1 &&
                   reentrantDeadline.result.status ==
                       AsyncDnsResolver::Status::deadlineExceeded,
               "transport reentrant expiration completes exactly once");
  suite.expect(transport.frames.size() == framesBeforeReentrantDeadline + 2,
               "transport reentrant expiration emits resolve then cancel");

  transport.frames.clear();
  Completion reconnect;
  const auto reconnectTicket = client.resolve(
      String("Reconnect.Example"),
      String("9443"),
      AsyncDnsResolver::Family::ipv4,
      {&reconnect, Completion::receive},
      AsyncDnsResolver::Clock::now() + std::chrono::seconds(5));
  Dns::Resolve originalRequest;
  suite.expect(transport.frames.size() == 1 &&
                   Dns::parseResolveRequest(transport.frames[0].data(),
                                            transport.frames[0].size(),
                                            originalRequest),
               "parse request before transport replacement");
  const std::size_t framesBeforeReconnect = transport.frames.size();
  constexpr std::uint64_t secondTransportGeneration = 2;
  suite.expect(client.transportConnected(service, secondTransportGeneration),
               "replace connected transport");
  suite.expect(!client.transportConnected(service, firstTransportGeneration),
               "stale transport connection cannot replace current transport");
  suite.expect(reconnect.calls == 0 && client.pendingCount() == 1 && client.ready() &&
                   !client.sessionReady(),
               "transport replacement detaches pending request without completion");
  suite.expect(transport.frames.size() == framesBeforeReconnect,
               "transport replacement emits nothing before authentication");
  transport.frames.clear();
  Dns::Session staleChallenge;
  staleChallenge.phase = Dns::SessionPhase::serviceChallenge;
  staleChallenge.applicationID = applicationID;
  staleChallenge.service = service;
  staleChallenge.nonce = 0xaaaabbbbccccddddULL;
  staleChallenge.generation = 0x1111222233334444ULL;
  suite.expect(Dns::encodeSession(staleChallenge, frame), "encode stale challenge");
  suite.expect(!client.handleFrame(
                   service, firstTransportGeneration, frame.data(), frame.size()) &&
                   !client.sessionReady() && transport.frames.empty(),
               "stale transport challenge cannot authenticate replacement");
  suite.expect(!client.serviceLost(service, firstTransportGeneration) &&
                   !client.sessionReady(),
               "stale transport loss cannot retire replacement");
  authenticate(client, transport, suite, service, applicationID, secondTransportGeneration);
  suite.expect(transport.frames.size() == 1, "new authenticated transport replays once");
  Dns::Resolve replacementRequest;
  suite.expect(Dns::parseResolveRequest(transport.frames[0].data(),
                                        transport.frames[0].size(),
                                        replacementRequest) &&
                   replacementRequest.requestID == reconnectTicket.identifier &&
                   replacementRequest.generation == reconnectTicket.generation &&
                   replacementRequest.hostname == originalRequest.hostname &&
                   replacementRequest.family == originalRequest.family &&
                   replacementRequest.deadlineMilliseconds > 0 &&
                   replacementRequest.deadlineMilliseconds <=
                       originalRequest.deadlineMilliseconds,
               "replay preserves identity and owned query with remaining budget");
  Dns::Resolve staleResult;
  staleResult.requestID = replacementRequest.requestID;
  staleResult.generation = replacementRequest.generation;
  staleResult.status = Dns::ResolveStatus::notFound;
  suite.expect(Dns::encodeResolveResult(staleResult, frame), "encode stale transport result");
  suite.expect(!client.handleFrame(
                   service, firstTransportGeneration, frame.data(), frame.size()) &&
                   reconnect.calls == 0 && client.pendingCount() == 1 &&
                   client.sessionReady(),
               "stale transport result cannot complete replacement request");
  suite.expect(client.handleFrame(
                   service, secondTransportGeneration, frame.data(), frame.size()) &&
                   reconnect.calls == 1 &&
                   reconnect.result.status == AsyncDnsResolver::Status::notFound,
               "current transport result completes replacement request");
  suite.expect(client.handleFrame(
                   service, secondTransportGeneration, frame.data(), frame.size()) &&
                   reconnect.calls == 1,
               "duplicate current-generation result cannot complete twice");

  transport.frames.clear();
  Completion lost;
  const auto lostTicket = client.resolve(
      String("lost.example"),
      String("443"),
      AsyncDnsResolver::Family::any,
      {&lost, Completion::receive},
      AsyncDnsResolver::Clock::now() + std::chrono::seconds(5));
  suite.expect(client.serviceLost(service, secondTransportGeneration),
               "service loss accepted");
  suite.expect(lost.calls == 0 && client.pendingCount() == 1 && client.ready() &&
                   !client.sessionReady(),
               "service loss retains pending request and closes only session gate");
  const std::size_t framesBeforeLostCancel = transport.frames.size();
  suite.expect(client.cancel(lostTicket) && lost.calls == 1 &&
                   lost.result.status == AsyncDnsResolver::Status::canceled &&
                   transport.frames.size() == framesBeforeLostCancel,
               "disconnected cancellation completes locally exactly once");

  Completion disconnectedNumeric;
  client.resolve(String("2001:db8::8"),
                 String("443"),
                 AsyncDnsResolver::Family::ipv6,
                 {&disconnectedNumeric, Completion::receive});
  suite.expect(disconnectedNumeric.calls == 1 && disconnectedNumeric.result.succeeded() &&
                   transport.frames.size() == framesBeforeLostCancel,
               "numeric lookup remains local while disconnected");

  Completion disconnectedDeadline;
  const auto disconnectedDeadlineTicket = client.resolve(
      String("disconnected-deadline.example"),
      String("443"),
      AsyncDnsResolver::Family::any,
      {&disconnectedDeadline, Completion::receive},
      AsyncDnsResolver::Clock::now() + std::chrono::milliseconds(2));
  suite.expect(bool(disconnectedDeadlineTicket) &&
                   client.expireDeadlines(AsyncDnsResolver::Clock::now() +
                                          std::chrono::seconds(1)) == 1 &&
                   disconnectedDeadline.calls == 1 &&
                   disconnectedDeadline.result.status ==
                       AsyncDnsResolver::Status::deadlineExceeded &&
                   transport.frames.size() == framesBeforeLostCancel,
               "disconnected deadline completes once without remote cancel");

  Completion reselection;
  const auto reselectionTicket = client.resolve(
      String("reselection.example"),
      String("443"),
      AsyncDnsResolver::Family::any,
      {&reselection, Completion::receive},
      AsyncDnsResolver::Clock::now() + std::chrono::seconds(5));
  constexpr std::uint64_t replacementService = service + 1;
  constexpr std::uint16_t replacementApplicationID = applicationID + 1;
  suite.expect(client.selectService(replacementService, replacementApplicationID) &&
                   reselection.calls == 0 && client.pendingCount() == 1,
               "service reselection retains pending request");
  constexpr std::uint64_t thirdTransportGeneration = 3;
  suite.expect(client.transportConnected(replacementService, thirdTransportGeneration),
               "connect replacement service");
  authenticate(client,
               transport,
               suite,
               replacementService,
               replacementApplicationID,
               thirdTransportGeneration);
  Dns::Resolve reselectionRequest;
  suite.expect(transport.frames.size() == 1 &&
                   Dns::parseResolveRequest(transport.frames[0].data(),
                                            transport.frames[0].size(),
                                            reselectionRequest) &&
                   reselectionRequest.requestID == reselectionTicket.identifier,
               "replacement service replays retained request once");
  Dns::Resolve reselectionResult;
  reselectionResult.requestID = reselectionTicket.identifier;
  reselectionResult.generation = reselectionTicket.generation;
  reselectionResult.status = Dns::ResolveStatus::noData;
  suite.expect(Dns::encodeResolveResult(reselectionResult, frame) &&
                   client.handleFrame(replacementService,
                                      thirdTransportGeneration,
                                      frame.data(),
                                      frame.size()) &&
                   reselection.calls == 1 &&
                   reselection.result.status == AsyncDnsResolver::Status::noData,
               "replacement service completes retained request");

  transport.frames.clear();
  transport.accept = false;
  Completion sendFailure;
  const auto sendFailureTicket = client.resolve(
      String("send-failure.example"),
      String("443"),
      AsyncDnsResolver::Family::any,
      {&sendFailure, Completion::receive},
      AsyncDnsResolver::Clock::now() + std::chrono::seconds(5));
  transport.accept = true;
  suite.expect(bool(sendFailureTicket) && sendFailure.calls == 0 &&
                   client.pendingCount() == 1 && !client.sessionReady(),
               "failed transport send detaches request without completion");
  constexpr std::uint64_t fourthTransportGeneration = 4;
  suite.expect(client.transportConnected(replacementService, fourthTransportGeneration),
               "replace transport after send failure");
  authenticate(client,
               transport,
               suite,
               replacementService,
               replacementApplicationID,
               fourthTransportGeneration);
  suite.expect(transport.frames.size() == 1, "send failure request replayed once");
  Dns::Resolve sendFailureRequest;
  suite.expect(Dns::parseResolveRequest(transport.frames[0].data(),
                                        transport.frames[0].size(),
                                        sendFailureRequest),
               "parse replay after send failure");
  Dns::Resolve sendFailureResult;
  sendFailureResult.requestID = sendFailureTicket.identifier;
  sendFailureResult.generation = sendFailureTicket.generation;
  sendFailureResult.status = Dns::ResolveStatus::notFound;
  suite.expect(Dns::encodeResolveResult(sendFailureResult, frame) &&
                   client.handleFrame(replacementService,
                                      fourthTransportGeneration,
                                      frame.data(),
                                      frame.size()) &&
                   sendFailure.calls == 1,
               "send failure replay completes exactly once");

  suite.expect(client.serviceLost(replacementService, fourthTransportGeneration),
               "disconnect before bounded overflow test");
  Completion bounded[Dns::Client::maximumPendingRequests];
  for (std::size_t index = 0; index < Dns::Client::maximumPendingRequests; index += 1)
  {
    String hostname;
    hostname.snprintf<"bounded-{itoa}.example"_ctv>(index);
    const auto ticket = client.resolve(
        hostname,
        String("443"),
        AsyncDnsResolver::Family::any,
        {&bounded[index], Completion::receive},
        AsyncDnsResolver::Clock::now() + std::chrono::seconds(5));
    suite.expect(bool(ticket) && bounded[index].calls == 0,
                 "bounded disconnected request accepted");
  }
  Completion overflow;
  const auto overflowTicket = client.resolve(
      String("overflow.example"),
      String("443"),
      AsyncDnsResolver::Family::any,
      {&overflow, Completion::receive},
      AsyncDnsResolver::Clock::now() + std::chrono::seconds(5));
  suite.expect(bool(overflowTicket) && overflow.calls == 1 &&
                   overflow.result.status == AsyncDnsResolver::Status::overloaded &&
                   client.pendingCount() == Dns::Client::maximumPendingRequests,
               "bounded overflow completes exactly once without admission");

  client.shutdown();
  client.shutdown();
  for (const Completion& completion : bounded)
  {
    suite.expect(completion.calls == 1 &&
                     completion.result.status == AsyncDnsResolver::Status::shutdown,
                 "shutdown completes each retained request exactly once");
  }
  suite.expect(overflow.calls == 1 && client.pendingCount() == 0 &&
                   !client.ready() && !client.sessionReady(),
               "shutdown is idempotent and closes configured readiness");
  Completion stopped;
  client.resolve(String("stopped.example"),
                 String("443"),
                 AsyncDnsResolver::Family::any,
                 {&stopped, Completion::receive});
  suite.expect(stopped.calls == 1 &&
                   stopped.result.status == AsyncDnsResolver::Status::shutdown,
               "resolve after shutdown reports shutdown");
}
} // namespace

int main(void)
{
  Suite suite;
  testWire(suite);
  testClient(suite);
  if (suite.failures != 0)
  {
    std::cerr << suite.failures << " DNS SDK checks failed\n";
    return 1;
  }
  std::cout << "opinionated DNS SDK passed\n";
  return 0;
}
