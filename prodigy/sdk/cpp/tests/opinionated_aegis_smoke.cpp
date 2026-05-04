// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

#include "../aegis_session.h"
#include "../opinionated/aegis_stream.h"
#include "../opinionated/pairings.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

namespace
{
   std::vector<std::uint8_t> readFixture(const char *name)
   {
      const std::filesystem::path path = std::filesystem::path(PRODIGY_SDK_FIXTURES_DIR) / name;
      std::ifstream input(path, std::ios::binary);
      if (input.good() == false)
      {
         return {};
      }

      return std::vector<std::uint8_t>(
         std::istreambuf_iterator<char>(input),
         std::istreambuf_iterator<char>());
   }

   ProdigySDK::SubscriptionPairing makeSubscriptionPairing(void)
   {
      ProdigySDK::SubscriptionPairing pairing;
      pairing.secret = ProdigySDK::U128 {
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
      };
      pairing.address = ProdigySDK::U128 {
         0xfd, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      };
      pairing.service = 0x2233000000001001ULL;
      pairing.port = 3210;
      pairing.applicationID = 0x2233;
      pairing.activate = true;
      return pairing;
   }
}

int main(void)
{
   const ProdigySDK::SubscriptionPairing pairing = makeSubscriptionPairing();
   const std::array<std::uint8_t, 9> plaintext {
      'f', 'r', 'a', 'm', 'e', '-', 'o', 'n', 'e'
   };
   const std::vector<std::uint8_t> fixtureHash = readFixture("aegis.hash.demo.bin");
   const std::vector<std::uint8_t> fixtureTfo = readFixture("aegis.tfo.demo.bin");
   const std::vector<std::uint8_t> fixtureFrame = readFixture("aegis.frame.demo.bin");

   ProdigySDK::ContainerParameters parameters;
   parameters.subscriptionPairings.push_back(pairing);

   ProdigySDK::Opinionated::PairingBook book;
   const auto actions = book.seedFromParameters(parameters);
   if (actions.size() != 1 ||
       actions.front().kind != ProdigySDK::Opinionated::ActivationActionKind::connectSubscriber ||
       actions.front().subscription.has_value() == false)
   {
      std::cerr << "pairing book failed to seed subscriber activation" << std::endl;
      return 1;
   }

   const ProdigySDK::AegisSession session = ProdigySDK::AegisSession::fromSubscription(pairing);
   const std::array<std::uint8_t, 10> aux {
      'm', 'e', 's', 'h', '-', 'a', 'e', 'g', 'i', 's'
   };
   const auto tfoData = session.buildTFOData(aux);
   if (fixtureHash.size() != sizeof(std::uint64_t) ||
       fixtureTfo.empty() ||
       fixtureFrame.empty() ||
       fixtureTfo != tfoData)
   {
      std::cerr << "portable session tfo/hash fixture mismatch" << std::endl;
      return 1;
   }

   const std::uint64_t pairingHash = session.pairingHash();
   std::array<std::uint8_t, sizeof(std::uint64_t)> pairingHashBytes {};
   for (std::size_t index = 0; index < pairingHashBytes.size(); index += 1)
   {
      pairingHashBytes[index] = static_cast<std::uint8_t>((pairingHash >> (index * 8u)) & 0xffu);
   }

   if (std::memcmp(fixtureHash.data(), pairingHashBytes.data(), pairingHashBytes.size()) != 0)
   {
      std::cerr << "portable session pairing hash fixture mismatch" << std::endl;
      return 1;
   }

   const std::array<std::uint8_t, 16> fixtureNonce {
      0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
      0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
   };
   ProdigySDK::Bytes deterministicFrame;
   if (session.encryptWithNonceInto(plaintext, fixtureNonce, deterministicFrame) != ProdigySDK::Result::ok ||
       deterministicFrame != fixtureFrame)
   {
      std::cerr << "portable session encrypted fixture mismatch" << std::endl;
      return 1;
   }

   ProdigySDK::Bytes deterministicPlaintext;
   if (session.decryptInto(fixtureFrame, deterministicPlaintext) != ProdigySDK::Result::ok ||
       deterministicPlaintext.size() != plaintext.size() ||
       std::memcmp(deterministicPlaintext.data(), plaintext.data(), plaintext.size()) != 0)
   {
      std::cerr << "portable session decrypt mismatch" << std::endl;
      return 1;
   }

   ProdigySDK::Opinionated::AegisStream writer(*actions.front().subscription);
   ProdigySDK::Opinionated::AegisStream reader(*actions.front().subscription);

   if (writer.queueEncrypted(plaintext) == false)
   {
      std::cerr << "failed to queue outbound aegis frame" << std::endl;
      return 1;
   }

   const std::span<const std::uint8_t> outbound = writer.queuedOutboundBytesView();
   if (outbound.empty())
   {
      std::cerr << "missing outbound aegis frame" << std::endl;
      return 1;
   }

   reader.appendInbound(outbound);
   if (reader.stampQueuedInboundMessages() == false)
   {
      std::cerr << "failed to stamp inbound aegis frame" << std::endl;
      return 1;
   }

   std::int64_t queuedAtNs = 0;
   auto decrypted = reader.dequeueInboundPlaintext(nullptr, &queuedAtNs);
   if (decrypted.has_value() == false)
   {
      std::cerr << "failed to decrypt inbound aegis frame" << std::endl;
      return 1;
   }

   if (decrypted->size() != plaintext.size() ||
       std::memcmp(decrypted->data(), plaintext.data(), plaintext.size()) != 0)
   {
      std::cerr << "decrypted plaintext mismatch" << std::endl;
      return 1;
   }

   if (queuedAtNs <= 0)
   {
      std::cerr << "missing inbound queue timestamp" << std::endl;
      return 1;
   }

   const auto streamTfoData = writer.tfoData();
   if (streamTfoData.size() != sizeof(std::uint64_t))
   {
      std::cerr << "unexpected tfo size" << std::endl;
      return 1;
   }

   std::cout << "pairing_hash=" << writer.pairingHash() << std::endl;
   return 0;
}
