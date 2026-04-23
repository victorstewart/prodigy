// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "neuron_hub.h"

#include <aegis/aegis.h>
#include <aegis/aegis128l.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <random>
#include <span>
#include <vector>

extern "C" std::uint64_t gxhash64(const void *buf, size_t len, std::int64_t seed);

namespace ProdigySDK
{
   enum class ServiceRole : std::uint8_t
   {
      none = 0,
      advertiser = 1,
      subscriber = 2,
   };

   struct AegisFrameHeader
   {
      std::uint32_t size = 0;
      U128 nonce{};
      std::uint32_t encryptedDataSize = 0;
   };

   class AegisSession
   {
   public:

      static constexpr std::size_t alignment = 16;
      static constexpr std::size_t headerBytes = 24;
      static constexpr std::size_t maxFrameBytes = 2 * 1024 * 1024;
      static constexpr std::size_t minFrameBytes = 48;
      static constexpr std::size_t nonceBytes = 16;
      static constexpr std::int64_t pairingHashSeed = 0x4d595df4d0f33173LL;
      static constexpr std::size_t tagBytes = 16;

      U128 secret{};
      std::uint64_t service = 0;
      ServiceRole role = ServiceRole::none;

      static AegisSession fromAdvertisement(const AdvertisementPairing& pairing)
      {
         AegisSession session;
         session.secret = pairing.secret;
         session.service = pairing.service;
         session.role = ServiceRole::advertiser;
         return session;
      }

      static AegisSession fromSubscription(const SubscriptionPairing& pairing)
      {
         AegisSession session;
         session.secret = pairing.secret;
         session.service = pairing.service;
         session.role = ServiceRole::subscriber;
         return session;
      }

      static std::size_t frameBytesForPlaintext(std::size_t plaintextBytes)
      {
         const std::size_t encryptedDataBytes = plaintextBytes + tagBytes;
         return roundUpToAlignment(headerBytes + encryptedDataBytes);
      }

      std::uint64_t pairingHash(void) const
      {
         std::array<std::uint8_t, 24> input{};
         std::memcpy(input.data(), secret.data(), secret.size());
         writeU64LE(input.data() + secret.size(), service);
         return gxhash64(input.data(), input.size(), pairingHashSeed);
      }

      Bytes buildTFOData(std::span<const std::uint8_t> aux = {}) const
      {
         Bytes out;
         buildTFODataInto(aux, out);
         return out;
      }

      void buildTFODataInto(std::span<const std::uint8_t> aux, Bytes& out) const
      {
         out.clear();
         out.reserve(sizeof(std::uint64_t) + aux.size());
         appendU64LE(out, pairingHash());
         out.insert(out.end(), aux.begin(), aux.end());
      }

      Result encryptInto(std::span<const std::uint8_t> plaintext, Bytes& outFrame) const
      {
         outFrame.resize(frameBytesForPlaintext(plaintext.size()));
         return encryptInto(plaintext, std::span<std::uint8_t>(outFrame.data(), outFrame.size()));
      }

      Result encryptInto(
         std::span<const std::uint8_t> plaintext,
         std::span<std::uint8_t> outFrame,
         U128 *nonceOut = nullptr) const
      {
         U128 nonce{};
         fillRandom(nonce);
         if (nonceOut != nullptr)
         {
            *nonceOut = nonce;
         }

         return encryptWithNonceInto(plaintext, nonce, outFrame);
      }

      Result encryptWithNonceInto(
         std::span<const std::uint8_t> plaintext,
         const U128& nonce,
         Bytes& outFrame) const
      {
         outFrame.resize(frameBytesForPlaintext(plaintext.size()));
         return encryptWithNonceInto(
            plaintext,
            nonce,
            std::span<std::uint8_t>(outFrame.data(), outFrame.size()));
      }

      Result encryptWithNonceInto(
         std::span<const std::uint8_t> plaintext,
         const U128& nonce,
         std::span<std::uint8_t> outFrame) const
      {
         const std::size_t encryptedDataBytes = plaintext.size() + tagBytes;
         const std::size_t frameBytes = frameBytesForPlaintext(plaintext.size());
         if (validateFrameBytes(frameBytes) != Result::ok)
         {
            return Result::argument;
         }

         if (outFrame.size() != frameBytes)
         {
            return Result::argument;
         }

         const auto frameBytesU32 = static_cast<std::uint32_t>(frameBytes);
         const auto encryptedDataBytesU32 = static_cast<std::uint32_t>(encryptedDataBytes);

         writeU32LE(outFrame.data(), frameBytesU32);
         std::memcpy(outFrame.data() + 4, nonce.data(), nonce.size());
         writeU32LE(outFrame.data() + 20, encryptedDataBytesU32);

         const auto *plaintextBytes =
            plaintext.empty() ? static_cast<const std::uint8_t *>(nullptr) : plaintext.data();
         aegis128l_encrypt(
            outFrame.data() + headerBytes,
            tagBytes,
            plaintextBytes,
            plaintext.size(),
            outFrame.data(),
            sizeof(std::uint32_t),
            nonce.data(),
            secret.data());

         const std::size_t paddingBytes = frameBytes - (headerBytes + encryptedDataBytes);
         if (paddingBytes > 0)
         {
            std::memset(
               outFrame.data() + headerBytes + encryptedDataBytes,
               0,
               paddingBytes);
         }

         return Result::ok;
      }

      Result decryptInto(
         std::span<const std::uint8_t> frame,
         Bytes& plaintext,
         AegisFrameHeader *headerOut = nullptr) const
      {
         AegisFrameHeader header;
         Result result = decodeFrameHeader(frame, header);
         if (result != Result::ok)
         {
            plaintext.clear();
            return result;
         }

         const std::size_t encryptedDataBytes = header.encryptedDataSize;
         const std::size_t plaintextBytes = encryptedDataBytes - tagBytes;
         plaintext.resize(plaintextBytes);

         auto *plaintextBuffer =
            plaintext.empty() ? static_cast<std::uint8_t *>(nullptr) : plaintext.data();
         const int decryptResult = aegis128l_decrypt(
            plaintextBuffer,
            frame.data() + headerBytes,
            encryptedDataBytes,
            tagBytes,
            frame.data(),
            sizeof(std::uint32_t),
            header.nonce.data(),
            secret.data());
         if (decryptResult != 0)
         {
            plaintext.clear();
            return Result::protocol;
         }

         if (headerOut != nullptr)
         {
            *headerOut = header;
         }

         return Result::ok;
      }

      static Result decodeFrameHeader(std::span<const std::uint8_t> frame, AegisFrameHeader& header)
      {
         if (frame.size() < headerBytes)
         {
            return Result::again;
         }

         header.size = readU32LE(frame.data());
         if (validateFrameBytes(header.size) != Result::ok)
         {
            return Result::protocol;
         }

         if (frame.size() < header.size)
         {
            return Result::again;
         }

         if (frame.size() != header.size)
         {
            return Result::protocol;
         }

         std::memcpy(header.nonce.data(), frame.data() + 4, header.nonce.size());
         header.encryptedDataSize = readU32LE(frame.data() + 20);
         if (header.encryptedDataSize < tagBytes)
         {
            return Result::protocol;
         }

         const std::size_t maxEncryptedDataBytes = header.size - headerBytes;
         if (header.encryptedDataSize > maxEncryptedDataBytes)
         {
            return Result::protocol;
         }

         return Result::ok;
      }

   private:

      static void appendU64LE(Bytes& out, std::uint64_t value)
      {
         const std::size_t offset = out.size();
         out.resize(offset + sizeof(std::uint64_t));
         writeU64LE(out.data() + offset, value);
      }

      static void fillRandom(U128& nonce)
      {
         thread_local std::random_device randomDevice;
         for (std::uint8_t& byte : nonce)
         {
            byte = static_cast<std::uint8_t>(randomDevice());
         }
      }

      static std::uint32_t readU32LE(const std::uint8_t *data)
      {
         return std::uint32_t(data[0])
            | (std::uint32_t(data[1]) << 8)
            | (std::uint32_t(data[2]) << 16)
            | (std::uint32_t(data[3]) << 24);
      }

      static std::size_t roundUpToAlignment(std::size_t size)
      {
         return (size + (alignment - 1)) & ~(alignment - 1);
      }

      static Result validateFrameBytes(std::size_t frameBytes)
      {
         if (frameBytes < minFrameBytes || frameBytes > maxFrameBytes)
         {
            return Result::protocol;
         }

         if ((frameBytes % alignment) != 0)
         {
            return Result::protocol;
         }

         if (frameBytes > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
         {
            return Result::protocol;
         }

         return Result::ok;
      }

      static void writeU32LE(std::uint8_t *data, std::uint32_t value)
      {
         data[0] = static_cast<std::uint8_t>(value & 0xffu);
         data[1] = static_cast<std::uint8_t>((value >> 8) & 0xffu);
         data[2] = static_cast<std::uint8_t>((value >> 16) & 0xffu);
         data[3] = static_cast<std::uint8_t>((value >> 24) & 0xffu);
      }

      static void writeU64LE(std::uint8_t *data, std::uint64_t value)
      {
         for (std::size_t index = 0; index < sizeof(value); index += 1)
         {
            data[index] = static_cast<std::uint8_t>((value >> (index * 8u)) & 0xffu);
         }
      }
   };
}
