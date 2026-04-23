// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

#include "../aegis_session.h"
#include "../neuron_hub.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>

int main(void)
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

   const ProdigySDK::AegisSession writer = ProdigySDK::AegisSession::fromSubscription(pairing);
   const ProdigySDK::AegisSession reader = ProdigySDK::AegisSession::fromSubscription(pairing);
   const ProdigySDK::U128 nonce = {
      0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
      0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
   };
   const std::array<std::uint8_t, 21> plaintext {
      'p', 'i', 'n', 'g', ' ', 'f', 'r', 'o', 'm', ' ',
      'p', 'r', 'o', 'd', 'i', 'g', 'y', '-', 's', 'd',
      'k',
   };
   const std::array<std::uint8_t, 10> aux {
      'm', 'e', 's', 'h', '-', 'a', 'e', 'g', 'i', 's',
   };

   const ProdigySDK::Bytes tfoData = writer.buildTFOData(aux);
   ProdigySDK::Bytes frame;
   if (writer.encryptWithNonceInto(plaintext, nonce, frame) != ProdigySDK::Result::ok)
   {
      std::cerr << "failed to encrypt aegis frame" << std::endl;
      return 1;
   }

   ProdigySDK::AegisFrameHeader header;
   ProdigySDK::Bytes decrypted;
   if (reader.decryptInto(frame, decrypted, &header) != ProdigySDK::Result::ok)
   {
      std::cerr << "failed to decrypt aegis frame" << std::endl;
      return 1;
   }

   if (decrypted.size() != plaintext.size()
      || std::equal(decrypted.begin(), decrypted.end(), plaintext.begin()) == false)
   {
      std::cerr << "decrypted plaintext mismatch" << std::endl;
      return 1;
   }

   std::cout << "pairing_hash=0x" << std::hex << writer.pairingHash()
             << std::dec << " tfo_bytes=" << tfoData.size()
             << " frame_bytes=" << header.size << std::endl;
   std::cout.write(
      reinterpret_cast<const char *>(decrypted.data()),
      static_cast<std::streamsize>(decrypted.size()));
   std::cout << std::endl;
   return 0;
}
