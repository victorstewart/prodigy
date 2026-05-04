// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../aegis_session.h"
#include "../neuron_hub.h"

#include <includes.h>
#include <services/crypto.h>

#include <chrono>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

namespace ProdigySDK::Opinionated
{
   class AegisStream
   {
   public:

      static inline constexpr std::size_t inboundQueuedAtCompactHeadThreshold = 1024;

      Buffer rBuffer;
      Buffer wBuffer;
      AegisSession session;
      std::vector<std::int64_t> inboundQueuedAtNs;
      std::size_t inboundQueuedAtHead = 0;

      AegisStream() = default;

      explicit AegisStream(const AdvertisementPairing& pairing)
      {
         bind(pairing);
      }

      explicit AegisStream(const SubscriptionPairing& pairing)
      {
         bind(pairing);
      }

      void bind(const AdvertisementPairing& pairing)
      {
         session = AegisSession::fromAdvertisement(pairing);
      }

      void bind(const SubscriptionPairing& pairing)
      {
         session = AegisSession::fromSubscription(pairing);
      }

      std::uint64_t pairingHash() const
      {
         return session.pairingHash();
      }

      Bytes tfoData(std::span<const std::uint8_t> aux = {}) const
      {
         return session.buildTFOData(aux);
      }

      std::span<const std::uint8_t> queuedOutboundBytesView(void) const
      {
         return std::span<const std::uint8_t>(wBuffer.pHead(), wBuffer.outstandingBytes());
      }

      void appendInbound(std::span<const std::uint8_t> bytes)
      {
         if (bytes.empty() == false)
         {
            rBuffer.append(bytes.data(), bytes.size());
         }
      }

      bool queueEncrypted(std::span<const std::uint8_t> plaintext)
      {
         const std::size_t frameBytes = AegisSession::frameBytesForPlaintext(plaintext.size());
         if (wBuffer.need(frameBytes) == false)
         {
            return false;
         }

         U128 nonce{};
         fillNonce(nonce);
         std::span<std::uint8_t> frame(wBuffer.pTail(), frameBytes);
         if (session.encryptWithNonceInto(plaintext, nonce, frame) != Result::ok)
         {
            return false;
         }

         wBuffer.advance(frameBytes);
         return true;
      }

      void reset(void)
      {
         rBuffer.reset();
         wBuffer.reset();
         session = AegisSession {};
         inboundQueuedAtNs.clear();
         inboundQueuedAtHead = 0;
      }

      std::uint32_t pendingInboundQueuedTimestamps(void) const
      {
         if (inboundQueuedAtHead >= inboundQueuedAtNs.size())
         {
            return 0;
         }

         return static_cast<std::uint32_t>(inboundQueuedAtNs.size() - inboundQueuedAtHead);
      }

      bool popInboundQueuedTimestamp(std::int64_t& queuedAtNs)
      {
         if (inboundQueuedAtHead >= inboundQueuedAtNs.size())
         {
            return false;
         }

         queuedAtNs = inboundQueuedAtNs[inboundQueuedAtHead++];
         compactInboundQueuedTimestampsIfNeeded();
         return true;
      }

      bool stampQueuedInboundMessages(void)
      {
         bool failed = false;
         const std::size_t completeMessagesNow = countCompleteFrames(failed);
         if (failed)
         {
            return false;
         }

         const std::size_t stampedMessages = pendingInboundQueuedTimestamps();
         if (completeMessagesNow > stampedMessages)
         {
            const std::int64_t queuedAtNs = monotonicNowNs();
            const std::size_t toStamp = completeMessagesNow - stampedMessages;
            inboundQueuedAtNs.reserve(inboundQueuedAtNs.size() + toStamp);
            for (std::size_t index = 0; index < toStamp; index += 1)
            {
               inboundQueuedAtNs.push_back(queuedAtNs);
            }
         }
         else if (stampedMessages > completeMessagesNow)
         {
            inboundQueuedAtHead += (stampedMessages - completeMessagesNow);
            compactInboundQueuedTimestampsIfNeeded();
         }

         return true;
      }

      std::optional<Bytes> dequeueInboundPlaintext(
         bool *failedOut = nullptr,
         std::int64_t *queuedAtNsOut = nullptr)
      {
         bool failed = false;
         const std::optional<std::size_t> completeFrameBytes = peekCompleteFrameBytes(failed);
         if (failedOut != nullptr)
         {
            *failedOut = failed;
         }

         if (completeFrameBytes.has_value() == false || failed)
         {
            return std::nullopt;
         }

         Bytes plaintext;
         const std::span<const std::uint8_t> frame(rBuffer.pHead(), *completeFrameBytes);
         if (session.decryptInto(frame, plaintext) != Result::ok)
         {
            if (failedOut != nullptr)
            {
               *failedOut = true;
            }

            return std::nullopt;
         }

         if (queuedAtNsOut != nullptr)
         {
            std::int64_t queuedAtNs = 0;
            if (popInboundQueuedTimestamp(queuedAtNs))
            {
               *queuedAtNsOut = queuedAtNs;
            }
            else
            {
               *queuedAtNsOut = 0;
            }
         }

         rBuffer.consume(*completeFrameBytes, true);
         return plaintext;
      }

   private:

      static std::uint32_t readU32LE(const std::uint8_t *data)
      {
         return std::uint32_t(data[0])
            | (std::uint32_t(data[1]) << 8)
            | (std::uint32_t(data[2]) << 16)
            | (std::uint32_t(data[3]) << 24);
      }

      static void fillNonce(U128& nonce)
      {
         const uint128_t nonceValue = Crypto::secureRandomNumber<uint128_t>();
         static_assert(sizeof(nonceValue) == sizeof(U128));
         std::memcpy(nonce.data(), &nonceValue, nonce.size());
      }

      static std::int64_t monotonicNowNs(void)
      {
         using namespace std::chrono;
         return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
      }

      void compactInboundQueuedTimestampsIfNeeded(void)
      {
         if (inboundQueuedAtHead == 0)
         {
            return;
         }

         if (inboundQueuedAtHead >= inboundQueuedAtNs.size())
         {
            inboundQueuedAtNs.clear();
            inboundQueuedAtHead = 0;
            return;
         }

         if (inboundQueuedAtHead < inboundQueuedAtCompactHeadThreshold &&
             (inboundQueuedAtHead * 2) < inboundQueuedAtNs.size())
         {
            return;
         }

         inboundQueuedAtNs.erase(
            inboundQueuedAtNs.begin(),
            inboundQueuedAtNs.begin() + static_cast<std::ptrdiff_t>(inboundQueuedAtHead));
         inboundQueuedAtHead = 0;
      }

      std::size_t countCompleteFrames(bool& failed) const
      {
         failed = false;
         std::size_t count = 0;
         const std::uint8_t *cursor = rBuffer.pHead();
         std::size_t remaining = rBuffer.outstandingBytes();

         while (remaining >= sizeof(std::uint32_t))
         {
            const std::uint32_t frameBytes = readU32LE(cursor);
            if (frameBytes < AegisSession::minFrameBytes ||
                frameBytes > AegisSession::maxFrameBytes ||
                (frameBytes % AegisSession::alignment) != 0)
            {
               failed = true;
               return count;
            }

            if (remaining < frameBytes)
            {
               return count;
            }

            AegisFrameHeader header;
            if (AegisSession::decodeFrameHeader(
                   std::span<const std::uint8_t>(cursor, frameBytes),
                   header) != Result::ok)
            {
               failed = true;
               return count;
            }

            count += 1;
            cursor += frameBytes;
            remaining -= frameBytes;
         }

         return count;
      }

      std::optional<std::size_t> peekCompleteFrameBytes(bool& failed)
      {
         failed = false;
         if (rBuffer.outstandingBytes() < sizeof(std::uint32_t))
         {
            return std::nullopt;
         }

         const std::uint32_t frameBytes = readU32LE(rBuffer.pHead());
         if (frameBytes < AegisSession::minFrameBytes ||
             frameBytes > AegisSession::maxFrameBytes ||
             (frameBytes % AegisSession::alignment) != 0)
         {
            failed = true;
            return std::nullopt;
         }

         if (rBuffer.outstandingBytes() < frameBytes)
         {
            rBuffer.reserve(frameBytes);
            return std::nullopt;
         }

         AegisFrameHeader header;
         if (AegisSession::decodeFrameHeader(
                std::span<const std::uint8_t>(rBuffer.pHead(), frameBytes),
                header) != Result::ok)
         {
            failed = true;
            return std::nullopt;
         }

         return frameBytes;
      }
   };
}
