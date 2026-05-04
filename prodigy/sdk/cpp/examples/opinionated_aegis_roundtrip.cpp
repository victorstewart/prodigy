// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

#include "../opinionated/aegis_stream.h"
#include "../opinionated/pairings.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <string>

namespace
{
   ProdigySDK::SubscriptionPairing demoPairing(void)
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
   ProdigySDK::ContainerParameters parameters;
   parameters.subscriptionPairings.push_back(demoPairing());

   ProdigySDK::Opinionated::PairingBook book;
   for (const ProdigySDK::Opinionated::ActivationAction& action : book.seedFromParameters(parameters))
   {
      if (action.kind != ProdigySDK::Opinionated::ActivationActionKind::connectSubscriber ||
          action.subscription.has_value() == false)
      {
         continue;
      }

      ProdigySDK::Opinionated::AegisStream writer(*action.subscription);
      ProdigySDK::Opinionated::AegisStream reader(*action.subscription);

      const auto tfoData = writer.tfoData(
         std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>("mesh-aegis"),
            sizeof("mesh-aegis") - 1));
      std::cout << "pairing_hash=0x" << std::hex << writer.pairingHash()
                << std::dec << " tfo_bytes=" << tfoData.size() << std::endl;

      const std::array<std::uint8_t, 34> plaintext {
         'p', 'i', 'n', 'g', ' ', 'f', 'r', 'o', 'm', ' ',
         'p', 'r', 'o', 'd', 'i', 'g', 'y', '-', 's', 'd',
         'k', '-', 'o', 'p', 'i', 'n', 'i', 'o', 'n', 'a',
         't', 'e', 'd', '!'
      };
      if (writer.queueEncrypted(plaintext) == false)
      {
         std::cerr << "failed to queue outbound aegis frame" << std::endl;
         return 1;
      }

      reader.appendInbound(writer.queuedOutboundBytesView());
      if (reader.stampQueuedInboundMessages() == false)
      {
         std::cerr << "failed to stamp inbound aegis frame" << std::endl;
         return 1;
      }

      std::optional<ProdigySDK::Bytes> inbound = reader.dequeueInboundPlaintext();
      if (inbound.has_value() == false)
      {
         std::cerr << "missing decrypted plaintext" << std::endl;
         return 1;
      }

      std::cout.write(
         reinterpret_cast<const char *>(inbound->data()),
         static_cast<std::streamsize>(inbound->size()));
      std::cout << std::endl;
      return 0;
   }

   std::cerr << "missing connect-subscriber activation" << std::endl;
   return 1;
}
