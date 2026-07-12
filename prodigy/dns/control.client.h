#pragma once

#include <networking/multiplexer.h>
#include <networking/stream.h>
#include <networking/ring.h>
#include <prodigy/dns/control.bootstrap.h>
#include <prodigy/sdk/cpp/opinionated/dns_client.h>
#include <services/time.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <utility>
#include <unistd.h>

namespace ProdigyDns
{

class ControlClient final : public RingMultiplexer, public TimeoutDispatcher
{
private:

   using Client = ProdigySDK::Opinionated::Dns::Client;
   using TimePoint = AsyncDnsResolver::TimePoint;

   constexpr static uint32_t initialBufferBytes = 4096;
   constexpr static uint32_t connectTimeoutMilliseconds = 5000;
   constexpr static uint32_t minimumReconnectMilliseconds = 100;
   constexpr static uint32_t maximumReconnectMilliseconds = 5000;

   ControlBootstrap bootstrap;
   AegisStream stream;
   Client client;
   TimeoutPacket deadlineTimer;
   TimeoutPacket reconnectTimer;
   TimePoint armedDeadline = TimePoint::max();
   uint64_t generationCounter = 0;
   uint64_t activeGeneration = 0;
   uint32_t reconnectMilliseconds = minimumReconnectMilliseconds;
   bool configured = false;
   bool connected = false;
   bool closing = false;
   bool deadlineTimerArmed = false;
   bool deadlineTimerCancellationRequested = false;
   bool reconnectTimerArmed = false;
   bool stopping = false;

   static uint64_t encryptedFrameBytes(uint64_t plaintextBytes)
   {
      constexpr uint64_t overhead = sizeof(uint32_t) + 16 +
                                    sizeof(uint32_t) + 16;
      return (overhead + plaintextBytes + 15) & ~uint64_t(15);
   }

   uint64_t nextGeneration(void)
   {
      generationCounter += 1;
      if (generationCounter == 0)
      {
         generationCounter = 1;
      }
      return generationCounter;
   }

   static bool sendFrame(void *context,
                         uint64_t service,
                         const uint8_t *data,
                         size_t size)
   {
      ControlClient& owner = *static_cast<ControlClient *>(context);
      const uint64_t frameBytes = encryptedFrameBytes(size);
      if (owner.stopping || owner.connected == false ||
          owner.activeGeneration == 0 || service != owner.bootstrap.service ||
          data == nullptr || size == 0 || frameBytes > 64 * 1024 ||
          owner.stream.wBuffer.outstandingBytes() > 64 * 1024 - frameBytes)
      {
         return false;
      }

      String plaintext;
      plaintext.assign(data, size);
      const uint64_t before = owner.stream.wBuffer.outstandingBytes();
      owner.stream.encrypt(plaintext);
      if (owner.stream.wBuffer.outstandingBytes() <= before)
      {
         return false;
      }
      if (owner.stream.pendingSend == false)
      {
         Ring::queueSend(&owner.stream);
      }
      return true;
   }

   static void deadlineChanged(void *context, TimePoint)
   {
      static_cast<ControlClient *>(context)->refreshDeadlineTimer();
   }

   void loseTransport(void)
   {
      const uint64_t generation = activeGeneration;
      activeGeneration = 0;
      connected = false;
      if (generation != 0)
      {
         (void)client.serviceLost(bootstrap.service, generation);
      }
   }

   void closeTransport(void)
   {
      loseTransport();
      if (closing == false && stream.isFixedFile &&
          Ring::socketIsClosing(&stream) == false)
      {
         closing = true;
         Ring::queueCancelAll(&stream);
         Ring::queueClose(&stream);
      }
      else if (closing == false)
      {
         scheduleReconnect();
      }
   }

   void armDeadlineTimer(TimePoint deadline)
   {
      auto delay = std::chrono::duration_cast<std::chrono::microseconds>(
          deadline - AsyncDnsResolver::Clock::now());
      if (delay <= std::chrono::microseconds::zero())
      {
         delay = std::chrono::milliseconds(1);
      }
      deadlineTimer.clear();
      deadlineTimer.setTimeoutUs(uint64_t(delay.count()));
      armedDeadline = deadline;
      deadlineTimerArmed = true;
      Ring::queueTimeout(&deadlineTimer);
   }

   void refreshDeadlineTimer(void)
   {
      const TimePoint required = stopping ? TimePoint::max()
                                          : client.earliestDeadline();
      if (deadlineTimerArmed == false)
      {
         if (required != TimePoint::max())
         {
            armDeadlineTimer(required);
         }
         return;
      }
      if (deadlineTimerCancellationRequested == false &&
          required != armedDeadline)
      {
         deadlineTimerCancellationRequested = true;
         Ring::queueCancelTimeout(&deadlineTimer);
      }
   }

   void scheduleReconnect(void)
   {
      if (stopping || configured == false || reconnectTimerArmed || closing)
      {
         return;
      }
      reconnectTimer.clear();
      reconnectTimer.setTimeoutMs(reconnectMilliseconds);
      reconnectTimerArmed = true;
      Ring::queueTimeout(&reconnectTimer);
      reconnectMilliseconds = std::min(maximumReconnectMilliseconds,
                                       reconnectMilliseconds * 2);
   }

   void connect(void)
   {
      if (stopping || configured == false || closing || connected ||
          stream.isFixedFile)
      {
         return;
      }

      stream.setIPVersion(AF_INET6);
      stream.setKeepaliveTimeoutSeconds(15);
      stream.setDaddr(bootstrap.endpoint, bootstrap.port);
      if (Ring::tryInstallFDIntoFixedFileSlot(&stream) == false)
      {
         if (stream.fd >= 0)
         {
            ::close(stream.fd);
            stream.fd = -1;
         }
         scheduleReconnect();
         return;
      }
      if (Ring::queueConnect(&stream, connectTimeoutMilliseconds) == false)
      {
         closeTransport();
      }
   }

public:

   explicit ControlClient(ControlBootstrap requested,
                          int64_t nowMs = Time::now<TimeResolution::ms>())
       : bootstrap(std::move(requested)),
         client({this, sendFrame, deadlineChanged})
   {
      String ignoredFailure;
      configured = bootstrap.valid(nowMs, &ignoredFailure) &&
                   client.selectService(bootstrap.service,
                                        MeshRegistry::DNS::applicationID);
      stream.secret = bootstrap.secret;
      stream.service = bootstrap.service;
      stream.role = ServiceRole::subscriber;
      stream.rBuffer.reserve(initialBufferBytes);
      stream.wBuffer.reserve(initialBufferBytes);
      deadlineTimer.dispatcher = this;
      reconnectTimer.dispatcher = this;
      RingDispatcher::installMultiplexer(this);
      RingDispatcher::installMultiplexee(&stream, this);
      connect();
   }

   ~ControlClient()
   {
      if (shutdownSafe() == false)
      {
         std::abort();
      }
      RingDispatcher::eraseMultiplexee(&stream);
      RingDispatcher::eraseMultiplexer(this);
      OPENSSL_cleanse(&bootstrap.secret, sizeof(bootstrap.secret));
      stream.secret = 0;
   }

   ControlClient(const ControlClient&) = delete;
   ControlClient& operator=(const ControlClient&) = delete;

   bool ready(void) const
   {
      return configured && client.ready() && stopping == false;
   }

   bool sessionReady(void) const
   {
      return ready() && client.sessionReady();
   }

   AsyncDnsClient& resolver(void)
   {
      return client;
   }

   void dispatchTimeout(TimeoutPacket *packet) override
   {
      if (packet == &deadlineTimer)
      {
         deadlineTimerArmed = false;
         deadlineTimerCancellationRequested = false;
         armedDeadline = TimePoint::max();
         deadlineTimer.clear();
         if (stopping == false)
         {
            (void)client.expireDeadlines();
         }
         refreshDeadlineTimer();
      }
      else if (packet == &reconnectTimer)
      {
         reconnectTimerArmed = false;
         reconnectTimer.clear();
         connect();
      }
   }

   void connectHandler(void *socket, int result) override
   {
      if (socket != &stream || stopping || closing)
      {
         return;
      }
      if (result != 0)
      {
         closeTransport();
         return;
      }

      stream.setConnected();
      connected = true;
      reconnectMilliseconds = minimumReconnectMilliseconds;
      activeGeneration = nextGeneration();
      if (client.transportConnected(bootstrap.service, activeGeneration) == false)
      {
         closeTransport();
         return;
      }

      const uint64_t hash = AegisStream::generateSecretServiceHash(
          bootstrap.secret, bootstrap.service);
      stream.wBuffer.append(hash);
      Ring::queueSend(&stream);
      Ring::queueRecv(&stream);
   }

   void recvHandler(void *socket, int result) override
   {
      if (socket != &stream || stopping || closing)
      {
         return;
      }
      stream.pendingRecv = false;
      if (result <= 0)
      {
         closeTransport();
         return;
      }
      stream.rBuffer.advance(result);

      bool failed = false;
      static thread_local String plaintext;
      stream.extractMessages<AegisMessage>(
          [&](AegisMessage *message, bool& stop) {
             if (stream.decrypt(message, plaintext) == false ||
                 client.handleFrame(bootstrap.service, activeGeneration,
                                    plaintext.data(), plaintext.size()) == false)
             {
                failed = true;
                stop = true;
             }
             plaintext.clear();
          },
          true,
          UINT32_MAX,
          AegisStream::minMessageSize,
          AegisStream::maxMessageSize,
          failed);

      if (failed)
      {
         closeTransport();
      }
      else
      {
         Ring::queueRecv(&stream);
      }
   }

   void sendHandler(void *socket, int result) override
   {
      if (socket != &stream)
      {
         return;
      }
      const bool wasPending = stream.pendingSend;
      stream.pendingSend = false;
      stream.pendingSendBytes = 0;
      if (wasPending == false)
      {
         return;
      }
      stream.wBuffer.noteSendCompleted();
      if (result <= 0)
      {
         stream.wBuffer.clear();
         closeTransport();
         return;
      }
      stream.wBuffer.consume(uint32_t(result), true);
      if (stream.wBuffer.outstandingBytes() > 0)
      {
         Ring::queueSend(&stream);
      }
   }

   void closeHandler(void *socket) override
   {
      if (socket != &stream)
      {
         return;
      }
      loseTransport();
      closing = false;
      stream.isFixedFile = false;
      stream.fd = -1;
      stream.resetSubscriberTransportState();
      stream.secret = bootstrap.secret;
      stream.service = bootstrap.service;
      stream.role = ServiceRole::subscriber;
      stream.rBuffer.reserve(initialBufferBytes);
      stream.wBuffer.reserve(initialBufferBytes);
      scheduleReconnect();
   }

   bool shutdown(void)
   {
      if (stopping == false)
      {
         stopping = true;
         client.shutdown();
         if (reconnectTimerArmed)
         {
            Ring::queueCancelTimeout(&reconnectTimer);
         }
         refreshDeadlineTimer();
         closeTransport();
      }
      return shutdownSafe();
   }

   bool shutdownSafe(void) const
   {
      return stopping && client.pendingCount() == 0 &&
             deadlineTimerArmed == false && reconnectTimerArmed == false &&
             closing == false && stream.isFixedFile == false;
   }
};

} // namespace ProdigyDns
