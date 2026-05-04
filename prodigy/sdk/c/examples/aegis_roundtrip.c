/* Copyright 2026 Victor Stewart */
/* SPDX-License-Identifier: Apache-2.0 */

#include "../prodigy_neuron_hub.h"

#include <string.h>

int main(void)
{
   static const uint8_t secret[16] = {
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
   };
   static const uint8_t address[16] = {
      0xfd, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
   };
   static const uint8_t nonce_bytes[16] = {
      0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
      0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
   };
   static const uint8_t plaintext[] = {'f', 'r', 'a', 'm', 'e', '-', 'o', 'n', 'e'};
   static const uint8_t aux[] = {'m', 'e', 's', 'h', '-', 'a', 'e', 'g', 'i', 's'};

   prodigy_subscription_pairing pairing;
   prodigy_aegis_session session;
   prodigy_u128 nonce;
   prodigy_bytes tfo_data;
   prodigy_bytes encrypted_frame;
   prodigy_bytes decrypted_plaintext;
   prodigy_aegis_frame_header header;

   memset(&pairing, 0, sizeof(pairing));
   memset(&tfo_data, 0, sizeof(tfo_data));
   memset(&encrypted_frame, 0, sizeof(encrypted_frame));
   memset(&decrypted_plaintext, 0, sizeof(decrypted_plaintext));
   memset(&header, 0, sizeof(header));

   memcpy(pairing.secret.bytes, secret, sizeof(secret));
   memcpy(pairing.address.bytes, address, sizeof(address));
   pairing.service = 0x2233000000001001ULL;
   pairing.port = 3210u;
   pairing.application_id = 0x2233u;
   pairing.activate = 1u;

   session = prodigy_aegis_session_from_subscription(&pairing);
   if (prodigy_aegis_build_tfo_data(&session, aux, sizeof(aux), &tfo_data) != PRODIGY_RESULT_OK)
   {
      return 1;
   }

   memcpy(nonce.bytes, nonce_bytes, sizeof(nonce_bytes));
   if (prodigy_aegis_encrypt_with_nonce(&session, plaintext, sizeof(plaintext), &nonce, &encrypted_frame) != PRODIGY_RESULT_OK)
   {
      prodigy_bytes_free(&tfo_data);
      return 1;
   }

   if (prodigy_aegis_decrypt(&session, encrypted_frame.data, encrypted_frame.size, &decrypted_plaintext, &header) != PRODIGY_RESULT_OK)
   {
      prodigy_bytes_free(&tfo_data);
      prodigy_bytes_free(&encrypted_frame);
      return 1;
   }

   if (decrypted_plaintext.size != sizeof(plaintext) || memcmp(decrypted_plaintext.data, plaintext, sizeof(plaintext)) != 0)
   {
      prodigy_bytes_free(&tfo_data);
      prodigy_bytes_free(&encrypted_frame);
      prodigy_bytes_free(&decrypted_plaintext);
      return 1;
   }

   prodigy_bytes_free(&tfo_data);
   prodigy_bytes_free(&encrypted_frame);
   prodigy_bytes_free(&decrypted_plaintext);
   return 0;
}
