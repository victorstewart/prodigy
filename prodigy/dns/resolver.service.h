#pragma once

#include <networking/multiplexer.h>
#include <networking/pool.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/ring.h>
#include <prodigy/dns/resolver.config.h>
#include <prodigy/dns/resolver.h>

namespace ProdigyDns
{

constexpr static size_t maximumStreams = 1024;
constexpr static size_t maximumRequestsPerStream = 64;
constexpr static size_t maximumRequests = 1024;
constexpr static uint32_t initialReadBufferBytes = 4096;
constexpr static uint32_t initialWriteBufferBytes = 4096;
constexpr static uint32_t authenticationTimeoutMilliseconds = 5000;
constexpr static uint32_t shutdownPollMilliseconds = 10;
constexpr static uint32_t maximumShutdownMilliseconds = 30000;
constexpr static uint32_t maximumEncryptedFrameBytes =
    (uint32_t(sizeof(uint32_t) + sizeof(uint128_t) + sizeof(uint32_t) + 16 +
              Wire::maximumResolveFrameBytes) +
     15u) &
    ~15u;
constexpr static uint32_t maximumQueuedCiphertextBytes = 64 * 1024;

inline uint64_t encryptedFrameBytes(uint64_t plaintextBytes)
{
   constexpr uint64_t envelopeBytes =
       sizeof(uint32_t) + sizeof(uint128_t) + sizeof(uint32_t) + 16;
   return (envelopeBytes + plaintextBytes + 15u) & ~uint64_t(15u);
}

inline bool canQueueFrame(uint64_t outstandingBytes, uint64_t plaintextBytes)
{
   const uint64_t frameBytes = encryptedFrameBytes(plaintextBytes);
   return frameBytes <= maximumEncryptedFrameBytes &&
          outstandingBytes <= maximumQueuedCiphertextBytes - frameBytes;
}

struct PendingRequest;

class Stream final : public AegisStream
{
public:

   bool identified = false;
   bool authenticated = false;
   uint64_t sessionNonce = 0;
   uint64_t sessionGeneration = 0;
   int64_t authenticationDeadlineNs = 0;
   bytell_hash_map<uint64_t, PendingRequest *> requests;

   void prepare(uint64_t advertisedService, int acceptedSlot)
   {
      AegisStream::reset();
      identified = false;
      authenticated = false;
      sessionNonce = 0;
      sessionGeneration = 0;
      authenticationDeadlineNs =
          AegisStream::monotonicNowNs() +
          int64_t(authenticationTimeoutMilliseconds) * 1'000'000;
      requests.clear();
      role = ServiceRole::advertiser;
      service = advertisedService;
      fslot = acceptedSlot;
      isFixedFile = true;
      if (rBuffer.remainingCapacity() == 0)
      {
         rBuffer.reserve(initialReadBufferBytes);
      }
      if (wBuffer.remainingCapacity() == 0)
      {
         wBuffer.reserve(initialWriteBufferBytes);
      }
      Ring::publishSocketGeneration(this);
   }

   void clearForPool(void)
   {
      requests.clear();
      identified = false;
      authenticated = false;
      sessionNonce = 0;
      sessionGeneration = 0;
      authenticationDeadlineNs = 0;
      AegisStream::reset();
   }
};

struct PendingRequest
{
   class Service *owner = nullptr;
   Stream *stream = nullptr;
   uint64_t requestID = 0;
   uint64_t generation = 0;
   AsyncDnsResolver::Ticket backendTicket;
   AsyncDnsResolver::Result result;
   bool completionReady = false;

   void reset(void)
   {
      owner = nullptr;
      stream = nullptr;
      requestID = 0;
      generation = 0;
      backendTicket = {};
      result = {};
      completionReady = false;
   }
};

inline bool exactSessionEcho(const Wire::Session& expected,
                             const Wire::Session& received)
{
   return received.phase == Wire::SessionPhase::applicationEcho &&
          received.applicationID == expected.applicationID &&
          received.service == expected.service &&
          received.nonce == expected.nonce &&
          received.generation == expected.generation;
}

class PairingRegistry
{
public:

   enum class Activation : uint8_t
   {
      accepted,
      alreadyPresent,
      collision,
      full
   };

   struct ActivationResult
   {
      Activation status = Activation::full;
      Stream *displacedOwner = nullptr;
   };

private:

   struct Entry
   {
      uint128_t secret = 0;
      Stream *owner = nullptr;
   };

   bytell_hash_map<uint64_t, Entry> entries;
   size_t capacity;

public:

   explicit PairingRegistry(size_t capacity = maximumStreams)
       : capacity(capacity)
   {
      entries.reserve(capacity);
   }

   ActivationResult activate(uint64_t hash, uint128_t secret)
   {
      auto existing = entries.find(hash);
      if (existing != entries.end())
      {
         if (existing->second.secret == secret)
         {
            return {Activation::alreadyPresent, nullptr};
         }
         Stream *owner = existing->second.owner;
         entries.erase(existing);
         return {Activation::collision, owner};
      }
      if (entries.size() >= capacity)
      {
         return {Activation::full, nullptr};
      }
      entries.emplace(hash, Entry {secret, nullptr});
      return {Activation::accepted, nullptr};
   }

   Stream *deactivate(uint64_t hash, uint128_t secret)
   {
      auto existing = entries.find(hash);
      if (existing == entries.end() || existing->second.secret != secret)
      {
         return nullptr;
      }
      Stream *owner = existing->second.owner;
      entries.erase(existing);
      return owner;
   }

   bool claim(uint64_t hash, Stream *owner, uint128_t& secret)
   {
      auto existing = entries.find(hash);
      if (existing == entries.end() || owner == nullptr ||
          (existing->second.owner != nullptr && existing->second.owner != owner))
      {
         secret = 0;
         return false;
      }
      existing->second.owner = owner;
      secret = existing->second.secret;
      return true;
   }

   bool release(uint64_t hash, uint128_t secret, Stream *owner)
   {
      auto existing = entries.find(hash);
      if (existing == entries.end() || existing->second.secret != secret ||
          existing->second.owner != owner)
      {
         return false;
      }
      existing->second.owner = nullptr;
      return true;
   }
};

class Service final : public RingMultiplexer, public TimeoutDispatcher
{
private:

   RuntimeConfig runtime;
   Resolver resolver;
   TCPSocket listener;
   Pool<Stream, false, true> streamPool;
   Pool<PendingRequest, false, true> requestPool;
   PairingRegistry pairings;
   Vector<PendingRequest *> stagedCompletions;
   Vector<PendingRequest *> drainingCompletions;
   TimeoutPacket completionWake;
   TimeoutPacket shutdownWake;
   bool completionWakeQueued = false;
   bool shutdownWakeQueued = false;
   bool listenerLive = false;
   bool stopping = false;
   int64_t shutdownDeadlineNs = 0;

   static uint64_t secureNonzero64(void)
   {
      uint64_t value = 0;
      while (value == 0)
      {
         value = Crypto::secureRandomNumber<uint64_t>();
      }
      return value;
   }

   Wire::Session expectedSession(const Stream& stream) const
   {
      Wire::Session session;
      session.phase = Wire::SessionPhase::serviceChallenge;
      session.applicationID = runtime.applicationID;
      session.service = runtime.service;
      session.nonce = stream.sessionNonce;
      session.generation = stream.sessionGeneration;
      return session;
   }

   void queueCompletionWake(void)
   {
      if (completionWakeQueued || stopping)
      {
         return;
      }
      completionWake.clear();
      completionWake.setTimeoutUs(1);
      completionWake.dispatcher = this;
      completionWakeQueued = true;
      Ring::queueTimeout(&completionWake);
   }

   void stageCompletion(PendingRequest *request,
                        AsyncDnsResolver::Ticket ticket,
                        AsyncDnsResolver::Result&& result)
   {
      if (request == nullptr || request->owner != this || request->completionReady)
      {
         return;
      }
      request->backendTicket = ticket;
      request->result = std::move(result);
      request->completionReady = true;
      stagedCompletions.push_back(request);
      queueCompletionWake();
   }

   static void resolverCompleted(void *context,
                                 AsyncDnsResolver::Ticket ticket,
                                 AsyncDnsResolver::Result&& result)
   {
      PendingRequest *request = static_cast<PendingRequest *>(context);
      if (request && request->owner)
      {
         request->owner->stageCompletion(request, ticket, std::move(result));
      }
   }

   void eraseIndexes(PendingRequest *request, bool preserveStream)
   {
      if (request == nullptr)
      {
         return;
      }

      if (request->stream)
      {
         auto position = request->stream->requests.find(request->requestID);
         if (position != request->stream->requests.end() &&
             position->second == request)
         {
            request->stream->requests.erase(position);
         }
         if (preserveStream == false)
         {
            request->stream = nullptr;
         }
      }
   }

   void releaseRequest(PendingRequest *request)
   {
      request->reset();
      requestPool.relinquish(request);
   }

   void cancelRequest(PendingRequest *request)
   {
      if (request == nullptr)
      {
         return;
      }
      eraseIndexes(request, false);
      if (request->completionReady == false && resolver.cancel(request->backendTicket) == false)
      {
         AsyncDnsResolver::Result result;
         result.status = AsyncDnsResolver::Status::canceled;
         stageCompletion(request, request->backendTicket, std::move(result));
      }
   }

   void cancelStreamRequests(Stream *stream)
   {
      if (stream == nullptr || stream->requests.empty())
      {
         return;
      }

      Vector<PendingRequest *> requests;
      requests.reserve(stream->requests.size());
      for (const auto& [requestID, request] : stream->requests)
      {
         (void)requestID;
         requests.push_back(request);
      }
      for (PendingRequest *request : requests)
      {
         cancelRequest(request);
      }
   }

   void queueSend(Stream *stream)
   {
      if (stream && stream->wBuffer.outstandingBytes() > 0 &&
          Ring::socketIsClosing(stream) == false)
      {
         Ring::queueSend(stream);
      }
   }

   bool queueFrame(Stream *stream, const String& plaintext)
   {
      if (stream == nullptr || Ring::socketIsClosing(stream))
      {
         return false;
      }
      const uint64_t before = stream->wBuffer.outstandingBytes();
      const uint64_t encryptedBytes = encryptedFrameBytes(plaintext.size());
      if (canQueueFrame(before, plaintext.size()) == false)
      {
         return false;
      }
      stream->encrypt(plaintext);
      if (stream->wBuffer.outstandingBytes() != before + encryptedBytes)
      {
         return false;
      }
      queueSend(stream);
      return true;
   }

   bool sendSession(Stream *stream, Wire::SessionPhase phase)
   {
      Wire::Session session = expectedSession(*stream);
      session.phase = phase;
      String frame;
      return Wire::encodeSession(session, frame) && queueFrame(stream, frame);
   }

   void closeStream(Stream *stream)
   {
      if (stream == nullptr || Ring::socketIsClosing(stream))
      {
         return;
      }
      cancelStreamRequests(stream);
      stream->authenticated = false;
      Ring::queueCancelAll(stream);
      Ring::queueClose(stream);
   }

   bool identify(Stream *stream)
   {
      if (stream->rBuffer.outstandingBytes() < sizeof(uint64_t))
      {
         return false;
      }

      uint64_t hash = 0;
      memcpy(&hash, stream->rBuffer.pHead(), sizeof(hash));
      uint128_t secret = 0;
      if (pairings.claim(hash, stream, secret) == false)
      {
         closeStream(stream);
         return false;
      }

      stream->rBuffer.consume(sizeof(hash), true);
      stream->secret = secret;
      stream->identified = true;
      stream->sessionNonce = secureNonzero64();
      stream->sessionGeneration = secureNonzero64();
      if (sendSession(stream, Wire::SessionPhase::serviceChallenge) == false)
      {
         closeStream(stream);
         return false;
      }
      return true;
   }

   bool handleSession(Stream *stream, const uint8_t *data, size_t size)
   {
      Wire::Session received;
      const Wire::Session expected = expectedSession(*stream);
      if (Wire::parseSession(data, size, received) == false ||
          exactSessionEcho(expected, received) == false)
      {
         return false;
      }

      stream->authenticated = true;
      stream->authenticationDeadlineNs = 0;
      return sendSession(stream, Wire::SessionPhase::serviceAck);
   }

   bool handleResolve(Stream *stream, const uint8_t *data, size_t size)
   {
      Wire::Resolve request;
      if (Wire::parseResolveRequest(data, size, request) == false ||
          stream->requests.size() >= maximumRequestsPerStream ||
          stream->requests.contains(request.requestID) ||
          stream->wBuffer.outstandingBytes() >
              maximumQueuedCiphertextBytes - maximumEncryptedFrameBytes)
      {
         return false;
      }

      PendingRequest *pending = requestPool.get();
      if (pending == nullptr)
      {
         return false;
      }
      pending->reset();
      pending->owner = this;
      pending->stream = stream;
      pending->requestID = request.requestID;
      pending->generation = request.generation;
      stream->requests.insert_or_assign(request.requestID, pending);

      AsyncDnsResolver::Callback callback;
      callback.context = pending;
      callback.function = resolverCompleted;
      pending->backendTicket = resolver.resolve(request, callback);

      if (pending->completionReady == false)
      {
         if (!pending->backendTicket)
         {
            AsyncDnsResolver::Result result;
            result.status = AsyncDnsResolver::Status::backendFailure;
            stageCompletion(pending, pending->backendTicket, std::move(result));
         }
      }
      return true;
   }

   bool handleCancel(Stream *stream, const uint8_t *data, size_t size)
   {
      Wire::Cancel cancel;
      if (Wire::parseCancel(data, size, cancel) == false)
      {
         return false;
      }

      auto position = stream->requests.find(cancel.requestID);
      if (position == stream->requests.end() ||
          position->second->generation != cancel.generation)
      {
         return true;
      }
      cancelRequest(position->second);
      return true;
   }

   bool handlePlaintext(Stream *stream, const String& plaintext)
   {
      Wire::Topic topic;
      if (Wire::frameTopic(plaintext.data(), plaintext.size(), topic) == false)
      {
         return false;
      }
      if (stream->authenticated == false)
      {
         return topic == Wire::Topic::session &&
                handleSession(stream, plaintext.data(), plaintext.size());
      }
      if (topic == Wire::Topic::resolve)
      {
         return handleResolve(stream, plaintext.data(), plaintext.size());
      }
      if (topic == Wire::Topic::cancel)
      {
         return handleCancel(stream, plaintext.data(), plaintext.size());
      }
      return false;
   }

   void drainCompletions(bool completionWakeArrived)
   {
      if (completionWakeArrived)
      {
         completionWakeQueued = false;
      }
      drainingCompletions.clear();
      drainingCompletions.swap(stagedCompletions);

      for (PendingRequest *request : drainingCompletions)
      {
         Stream *stream = request->stream;
         const bool deliver = stream && stream->authenticated &&
                              Ring::socketIsClosing(stream) == false;
         eraseIndexes(request, true);

         if (deliver)
         {
            String frame;
            if (Resolver::encodeResult(request->requestID,
                                       request->generation,
                                       std::move(request->result),
                                       frame))
            {
               if (queueFrame(stream, frame) == false)
               {
                  closeStream(stream);
               }
            }
            else
            {
               closeStream(stream);
            }
         }
         releaseRequest(request);
      }
      drainingCompletions.clear();

      if (stagedCompletions.empty() == false)
      {
         queueCompletionWake();
      }
   }

   bool shutdownDrained(void)
   {
      return listenerLive == false && streamPool.outstandingCount() == 0 &&
             requestPool.outstandingCount() == 0 &&
             stagedCompletions.empty() && drainingCompletions.empty() &&
             completionWakeQueued == false && shutdownWakeQueued == false &&
             resolver.shutdownSafe();
   }

   void armShutdownWake(void)
   {
      if (shutdownWakeQueued)
      {
         return;
      }
      shutdownWake.clear();
      shutdownWake.setTimeoutMs(shutdownPollMilliseconds);
      shutdownWake.dispatcher = this;
      shutdownWakeQueued = true;
      Ring::queueTimeout(&shutdownWake);
   }

   void pollShutdown(void)
   {
      if (shutdownDrained())
      {
         Ring::exit = true;
         return;
      }
      if (AegisStream::monotonicNowNs() >= shutdownDeadlineNs)
      {
         std::abort();
      }
      armShutdownWake();
   }

public:

   explicit Service(RuntimeConfig requested)
       : runtime(std::move(requested)),
         resolver(runtime.resolver, std::move(runtime.backend)),
         streamPool(maximumStreams),
         requestPool(maximumRequests)
   {
      stagedCompletions.reserve(maximumRequests);
      drainingCompletions.reserve(maximumRequests);
      completionWake.dispatcher = this;
      shutdownWake.dispatcher = this;
      RingDispatcher::installMultiplexer(this);
   }

   bool start(void)
   {
      if (resolver.initializationStatus() !=
          RingAsyncDnsResolver::InitializationStatus::ready)
      {
         return false;
      }

      listener.setIPVersion(AF_INET6);
      const int enabled = 1;
      if (setsockopt(listener.fd,
                     IPPROTO_IPV6,
                     IPV6_V6ONLY,
                     &enabled,
                     sizeof(enabled)) != 0)
      {
         return false;
      }
      listener.setSaddr(runtime.listenAddress, runtime.listenPort);
      listener.bindThenListen();
      Ring::installFDIntoFixedFileSlot(&listener);
      RingDispatcher::installMultiplexee(&listener, this);
      listenerLive = true;
      Ring::queueAccept(&listener);
      return true;
   }

   void pairing(uint128_t secret, uint64_t service, bool activate)
   {
      if (secret == 0 || service != runtime.service)
      {
         return;
      }

      const uint64_t hash = AegisStream::generateSecretServiceHash(secret, service);
      if (activate)
      {
         const PairingRegistry::ActivationResult result =
             pairings.activate(hash, secret);
         if (result.displacedOwner)
         {
            closeStream(result.displacedOwner);
         }
         return;
      }

      if (Stream *stream = pairings.deactivate(hash, secret))
      {
         if (streamPool.contains(stream))
         {
            closeStream(stream);
         }
      }
   }

   void shutdown(void)
   {
      if (stopping)
      {
         return;
      }
      stopping = true;
      shutdownDeadlineNs =
          AegisStream::monotonicNowNs() +
          int64_t(maximumShutdownMilliseconds) * 1'000'000;

      Vector<Stream *> streams;
      streamPool.forOutstanding([&](Stream *stream) {
         streams.push_back(stream);
      });
      for (Stream *stream : streams)
      {
         cancelStreamRequests(stream);
         closeStream(stream);
      }
      (void)resolver.shutdown();
      drainCompletions(false);

      if (listenerLive && Ring::socketIsClosing(&listener) == false)
      {
         Ring::queueCancelAll(&listener);
         Ring::queueClose(&listener);
      }
      pollShutdown();
   }

   void dispatchTimeout(TimeoutPacket *packet) override
   {
      if (packet == &completionWake)
      {
         drainCompletions(true);
         if (stopping)
         {
            pollShutdown();
         }
      }
      else if (packet == &shutdownWake)
      {
         shutdownWakeQueued = false;
         drainCompletions(false);
         pollShutdown();
      }
   }

   void acceptHandler(void *socket, int fslot) override
   {
      if (socket != &listener)
      {
         return;
      }
      if (stopping == false && fslot >= 0)
      {
         Stream *stream = streamPool.get();
         if (stream)
         {
            stream->prepare(runtime.service, fslot);
            RingDispatcher::installMultiplexee(stream, this);
            Ring::queueRecv(stream, authenticationTimeoutMilliseconds);
         }
         else
         {
            Ring::queueCloseRaw(fslot);
         }
      }
      else if (fslot >= 0)
      {
         Ring::queueCloseRaw(fslot);
      }

      if (stopping == false && listenerLive)
      {
         Ring::queueAccept(&listener);
      }
   }

   void recvHandler(void *socket, int result) override
   {
      Stream *stream = static_cast<Stream *>(socket);
      if (streamPool.contains(stream) == false)
      {
         return;
      }
      stream->pendingRecv = false;
      if (result <= 0 || stopping)
      {
         closeStream(stream);
         return;
      }
      stream->rBuffer.advance(result);

      if (stream->identified == false && identify(stream) == false)
      {
         if (Ring::socketIsClosing(stream) == false)
         {
            const int64_t remainingNs =
                stream->authenticationDeadlineNs - AegisStream::monotonicNowNs();
            if (remainingNs <= 0)
            {
               closeStream(stream);
            }
            else
            {
               Ring::queueRecv(stream, (remainingNs + 999'999) / 1'000'000);
            }
         }
         return;
      }

      bool failed = false;
      static thread_local String plaintext;
      stream->extractMessages<AegisMessage>(
          [&](AegisMessage *message, bool& stop) {
             if (stream->decrypt(message, plaintext) == false ||
                 handlePlaintext(stream, plaintext) == false)
             {
                failed = true;
                stop = true;
             }
             plaintext.clear();
          },
          true,
          UINT32_MAX,
          AegisStream::minMessageSize,
          maximumEncryptedFrameBytes,
          failed);

      if (failed)
      {
         closeStream(stream);
      }
      else if (Ring::socketIsClosing(stream) == false)
      {
         if (stream->authenticated)
         {
            Ring::queueRecv(stream);
         }
         else
         {
            const int64_t remainingNs =
                stream->authenticationDeadlineNs - AegisStream::monotonicNowNs();
            if (remainingNs <= 0)
            {
               closeStream(stream);
            }
            else
            {
               Ring::queueRecv(stream, (remainingNs + 999'999) / 1'000'000);
            }
         }
      }
   }

   void sendHandler(void *socket, int result) override
   {
      Stream *stream = static_cast<Stream *>(socket);
      if (streamPool.contains(stream) == false)
      {
         return;
      }

      const bool wasPending = stream->pendingSend;
      stream->pendingSend = false;
      stream->pendingSendBytes = 0;
      if (wasPending == false)
      {
         return;
      }
      stream->wBuffer.noteSendCompleted();
      if (result <= 0)
      {
         closeStream(stream);
         return;
      }
      stream->wBuffer.consume(uint32_t(result), true);
      queueSend(stream);
   }

   void closeHandler(void *socket) override
   {
      if (socket == &listener)
      {
         listenerLive = false;
         RingDispatcher::eraseMultiplexee(&listener);
         return;
      }

      Stream *stream = static_cast<Stream *>(socket);
      if (streamPool.contains(stream) == false)
      {
         return;
      }
      cancelStreamRequests(stream);
      RingDispatcher::eraseMultiplexee(stream);
      if (stream->secret != 0)
      {
         const uint64_t hash = AegisStream::generateSecretServiceHash(
             stream->secret, stream->service);
         (void)pairings.release(hash, stream->secret, stream);
      }
      stream->clearForPool();
      streamPool.relinquish(stream);
   }
};

} // namespace ProdigyDns
