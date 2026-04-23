/* Copyright 2026 Victor Stewart */
/* SPDX-License-Identifier: Apache-2.0 */

#include "prodigy_neuron_hub.h"

#include <aegis/aegis.h>
#include <aegis/aegis128l.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

struct prodigy_neuron_hub
{
   int fd;
   void *context;
   prodigy_neuron_hub_callbacks callbacks;
   prodigy_container_parameters parameters;
   uint8_t preserve_fd;
   uint8_t stop_requested;
};

typedef struct prodigy_reader
{
   const uint8_t *cursor;
   const uint8_t *terminal;
} prodigy_reader;

static const uint8_t prodigy_container_parameters_magic[8] = {'P', 'R', 'D', 'P', 'A', 'R', '0', '1'};
static const uint8_t prodigy_credential_bundle_magic[8] = {'P', 'R', 'D', 'B', 'U', 'N', '0', '1'};
static const uint8_t prodigy_credential_delta_magic[8] = {'P', 'R', 'D', 'D', 'E', 'L', '0', '1'};

extern uint64_t gxhash64(const void *buf, size_t len, int64_t seed);

static void *prodigy_calloc_array(size_t count, size_t item_size)
{
   if (count == 0 || item_size == 0)
   {
      return NULL;
   }

   if (count > (SIZE_MAX / item_size))
   {
      return NULL;
   }

   return calloc(count, item_size);
}

static prodigy_result prodigy_copy_bytes(prodigy_bytes *target, const uint8_t *data, size_t size)
{
   if (target == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   target->data = NULL;
   target->size = 0;

   if (size == 0)
   {
      return PRODIGY_RESULT_OK;
   }

   target->data = (uint8_t *)malloc(size);
   if (target->data == NULL)
   {
      return PRODIGY_RESULT_MEMORY;
   }

   memcpy(target->data, data, size);
   target->size = size;
   return PRODIGY_RESULT_OK;
}

static void prodigy_write_u32_le(uint8_t *data, uint32_t value)
{
   data[0] = (uint8_t)(value & 0xffu);
   data[1] = (uint8_t)((value >> 8) & 0xffu);
   data[2] = (uint8_t)((value >> 16) & 0xffu);
   data[3] = (uint8_t)((value >> 24) & 0xffu);
}

static void prodigy_write_u64_le(uint8_t *data, uint64_t value)
{
   size_t index = 0;
   for (index = 0; index < sizeof(uint64_t); index += 1)
   {
      data[index] = (uint8_t)((value >> (index * 8u)) & 0xffu);
   }
}

static uint32_t prodigy_read_u32_le(const uint8_t *data)
{
   return (uint32_t)data[0]
      | ((uint32_t)data[1] << 8)
      | ((uint32_t)data[2] << 16)
      | ((uint32_t)data[3] << 24);
}

static size_t prodigy_aegis_round_up_to_alignment(size_t size)
{
   return (size + (PRODIGY_AEGIS_ALIGNMENT - 1u)) & ~(PRODIGY_AEGIS_ALIGNMENT - 1u);
}

static prodigy_result prodigy_aegis_validate_frame_bytes(size_t frame_bytes)
{
   if (frame_bytes < PRODIGY_AEGIS_MIN_FRAME_BYTES || frame_bytes > PRODIGY_AEGIS_MAX_FRAME_BYTES)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   if ((frame_bytes % PRODIGY_AEGIS_ALIGNMENT) != 0u)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   if (frame_bytes > (size_t)UINT32_MAX)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_fill_random_bytes(uint8_t *data, size_t size)
{
   size_t offset = 0;

   while (offset < size)
   {
      ssize_t generated = getrandom(data + offset, size - offset, 0);
      if (generated < 0)
      {
         if (errno == EINTR)
         {
            continue;
         }

         return PRODIGY_RESULT_IO;
      }

      offset += (size_t)generated;
   }

   return PRODIGY_RESULT_OK;
}

prodigy_aegis_session prodigy_aegis_session_from_advertisement(
   const prodigy_advertisement_pairing *pairing)
{
   prodigy_aegis_session session;
   memset(&session, 0, sizeof(session));

   if (pairing == NULL)
   {
      return session;
   }

   session.secret = pairing->secret;
   session.service = pairing->service;
   session.role = PRODIGY_SERVICE_ROLE_ADVERTISER;
   return session;
}

prodigy_aegis_session prodigy_aegis_session_from_subscription(
   const prodigy_subscription_pairing *pairing)
{
   prodigy_aegis_session session;
   memset(&session, 0, sizeof(session));

   if (pairing == NULL)
   {
      return session;
   }

   session.secret = pairing->secret;
   session.service = pairing->service;
   session.role = PRODIGY_SERVICE_ROLE_SUBSCRIBER;
   return session;
}

uint64_t prodigy_aegis_pairing_hash(const prodigy_aegis_session *session)
{
   uint8_t input[24];

   if (session == NULL)
   {
      return 0;
   }

   memcpy(input, session->secret.bytes, sizeof(session->secret.bytes));
   prodigy_write_u64_le(input + sizeof(session->secret.bytes), session->service);
   return gxhash64(input, sizeof(input), PRODIGY_AEGIS_PAIRING_HASH_SEED);
}

prodigy_result prodigy_aegis_build_tfo_data(
   const prodigy_aegis_session *session,
   const uint8_t *aux,
   size_t aux_size,
   prodigy_bytes *tfo_data)
{
   uint64_t pairing_hash = 0;

   if (session == NULL || tfo_data == NULL || (aux == NULL && aux_size != 0u))
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   tfo_data->data = (uint8_t *)malloc(sizeof(uint64_t) + aux_size);
   if (tfo_data->data == NULL)
   {
      tfo_data->size = 0;
      return PRODIGY_RESULT_MEMORY;
   }

   pairing_hash = prodigy_aegis_pairing_hash(session);
   prodigy_write_u64_le(tfo_data->data, pairing_hash);
   if (aux_size > 0u)
   {
      memcpy(tfo_data->data + sizeof(uint64_t), aux, aux_size);
   }

   tfo_data->size = sizeof(uint64_t) + aux_size;
   return PRODIGY_RESULT_OK;
}

prodigy_result prodigy_aegis_frame_bytes_for_plaintext(
   size_t plaintext_size,
   size_t *frame_size)
{
   size_t encrypted_data_size = 0;
   size_t computed_frame_size = 0;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (frame_size == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   if (plaintext_size > (SIZE_MAX - PRODIGY_AEGIS_TAG_BYTES))
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   encrypted_data_size = plaintext_size + PRODIGY_AEGIS_TAG_BYTES;
   if (encrypted_data_size > (SIZE_MAX - PRODIGY_AEGIS_HEADER_BYTES))
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   computed_frame_size = prodigy_aegis_round_up_to_alignment(PRODIGY_AEGIS_HEADER_BYTES + encrypted_data_size);
   result = prodigy_aegis_validate_frame_bytes(computed_frame_size);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   *frame_size = computed_frame_size;
   return PRODIGY_RESULT_OK;
}

prodigy_result prodigy_aegis_encrypt(
   const prodigy_aegis_session *session,
   const uint8_t *plaintext,
   size_t plaintext_size,
   prodigy_bytes *frame,
   prodigy_u128 *nonce_out)
{
   prodigy_u128 nonce;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (session == NULL || frame == NULL || (plaintext == NULL && plaintext_size != 0u))
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   result = prodigy_fill_random_bytes(nonce.bytes, sizeof(nonce.bytes));
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   if (nonce_out != NULL)
   {
      *nonce_out = nonce;
   }

   return prodigy_aegis_encrypt_with_nonce(session, plaintext, plaintext_size, &nonce, frame);
}

prodigy_result prodigy_aegis_encrypt_with_nonce(
   const prodigy_aegis_session *session,
   const uint8_t *plaintext,
   size_t plaintext_size,
   const prodigy_u128 *nonce,
   prodigy_bytes *frame)
{
   size_t frame_size = 0;
   size_t encrypted_data_size = 0;
   size_t padding_size = 0;
   uint8_t *plaintext_bytes = (uint8_t *)plaintext;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (session == NULL || nonce == NULL || frame == NULL || (plaintext == NULL && plaintext_size != 0u))
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   result = prodigy_aegis_frame_bytes_for_plaintext(plaintext_size, &frame_size);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   encrypted_data_size = plaintext_size + PRODIGY_AEGIS_TAG_BYTES;
   frame->data = (uint8_t *)malloc(frame_size);
   if (frame->data == NULL)
   {
      frame->size = 0;
      return PRODIGY_RESULT_MEMORY;
   }

   prodigy_write_u32_le(frame->data, (uint32_t)frame_size);
   memcpy(frame->data + 4u, nonce->bytes, sizeof(nonce->bytes));
   prodigy_write_u32_le(frame->data + 20u, (uint32_t)encrypted_data_size);
   aegis128l_encrypt(
      frame->data + PRODIGY_AEGIS_HEADER_BYTES,
      PRODIGY_AEGIS_TAG_BYTES,
      plaintext_size == 0u ? NULL : plaintext_bytes,
      plaintext_size,
      frame->data,
      sizeof(uint32_t),
      nonce->bytes,
      session->secret.bytes);

   padding_size = frame_size - (PRODIGY_AEGIS_HEADER_BYTES + encrypted_data_size);
   if (padding_size > 0u)
   {
      memset(
         frame->data + PRODIGY_AEGIS_HEADER_BYTES + encrypted_data_size,
         0,
         padding_size);
   }

   frame->size = frame_size;
   return PRODIGY_RESULT_OK;
}

prodigy_result prodigy_aegis_decode_frame_header(
   const uint8_t *frame,
   size_t frame_size,
   prodigy_aegis_frame_header *header)
{
   size_t max_encrypted_data_size = 0;

   if (frame == NULL || header == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   if (frame_size < PRODIGY_AEGIS_HEADER_BYTES)
   {
      return PRODIGY_RESULT_AGAIN;
   }

   header->size = prodigy_read_u32_le(frame);
   if (prodigy_aegis_validate_frame_bytes((size_t)header->size) != PRODIGY_RESULT_OK)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   if (frame_size < (size_t)header->size)
   {
      return PRODIGY_RESULT_AGAIN;
   }

   if (frame_size != (size_t)header->size)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   memcpy(header->nonce.bytes, frame + 4u, sizeof(header->nonce.bytes));
   header->encrypted_data_size = prodigy_read_u32_le(frame + 20u);
   if (header->encrypted_data_size < PRODIGY_AEGIS_TAG_BYTES)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   max_encrypted_data_size = (size_t)header->size - PRODIGY_AEGIS_HEADER_BYTES;
   if ((size_t)header->encrypted_data_size > max_encrypted_data_size)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   return PRODIGY_RESULT_OK;
}

prodigy_result prodigy_aegis_decrypt(
   const prodigy_aegis_session *session,
   const uint8_t *frame,
   size_t frame_size,
   prodigy_bytes *plaintext,
   prodigy_aegis_frame_header *header_out)
{
   prodigy_aegis_frame_header header;
   size_t plaintext_size = 0;
   int decrypt_result = 0;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (session == NULL || frame == NULL || plaintext == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   result = prodigy_aegis_decode_frame_header(frame, frame_size, &header);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   plaintext_size = (size_t)header.encrypted_data_size - PRODIGY_AEGIS_TAG_BYTES;
   plaintext->data = (uint8_t *)malloc(plaintext_size == 0u ? 1u : plaintext_size);
   if (plaintext->data == NULL)
   {
      plaintext->size = 0;
      return PRODIGY_RESULT_MEMORY;
   }

   decrypt_result = aegis128l_decrypt(
      plaintext_size == 0u ? NULL : plaintext->data,
      frame + PRODIGY_AEGIS_HEADER_BYTES,
      header.encrypted_data_size,
      PRODIGY_AEGIS_TAG_BYTES,
      frame,
      sizeof(uint32_t),
      header.nonce.bytes,
      session->secret.bytes);
   if (decrypt_result != 0)
   {
      free(plaintext->data);
      plaintext->data = NULL;
      plaintext->size = 0;
      return PRODIGY_RESULT_PROTOCOL;
   }

   plaintext->size = plaintext_size;
   if (header_out != NULL)
   {
      *header_out = header;
   }

   return PRODIGY_RESULT_OK;
}

void prodigy_bytes_free(prodigy_bytes *value)
{
   if (value == NULL)
   {
      return;
   }

   free(value->data);
   value->data = NULL;
   value->size = 0;
}

void prodigy_message_frame_free(prodigy_message_frame *frame)
{
   if (frame == NULL)
   {
      return;
   }

   prodigy_bytes_free(&frame->payload);
   frame->topic = PRODIGY_CONTAINER_TOPIC_NONE;
}

static void prodigy_tls_identity_free(prodigy_tls_identity *identity)
{
   size_t index = 0;

   if (identity == NULL)
   {
      return;
   }

   prodigy_bytes_free(&identity->name);
   prodigy_bytes_free(&identity->cert_pem);
   prodigy_bytes_free(&identity->key_pem);
   prodigy_bytes_free(&identity->chain_pem);

   for (index = 0; index < identity->dns_san_count; index += 1)
   {
      prodigy_bytes_free(&identity->dns_sans[index]);
   }
   free(identity->dns_sans);
   identity->dns_sans = NULL;
   identity->dns_san_count = 0;

   free(identity->ip_sans);
   identity->ip_sans = NULL;
   identity->ip_san_count = 0;

   for (index = 0; index < identity->tag_count; index += 1)
   {
      prodigy_bytes_free(&identity->tags[index]);
   }
   free(identity->tags);
   identity->tags = NULL;
   identity->tag_count = 0;
}

static void prodigy_api_credential_free(prodigy_api_credential *credential)
{
   size_t index = 0;

   if (credential == NULL)
   {
      return;
   }

   prodigy_bytes_free(&credential->name);
   prodigy_bytes_free(&credential->provider);
   prodigy_bytes_free(&credential->material);

   for (index = 0; index < credential->metadata_count; index += 1)
   {
      prodigy_bytes_free(&credential->metadata[index].key);
      prodigy_bytes_free(&credential->metadata[index].value);
   }

   free(credential->metadata);
   credential->metadata = NULL;
   credential->metadata_count = 0;
}

void prodigy_credential_bundle_free(prodigy_credential_bundle *bundle)
{
   size_t index = 0;

   if (bundle == NULL)
   {
      return;
   }

   for (index = 0; index < bundle->tls_identity_count; index += 1)
   {
      prodigy_tls_identity_free(&bundle->tls_identities[index]);
   }
   free(bundle->tls_identities);
   bundle->tls_identities = NULL;
   bundle->tls_identity_count = 0;

   for (index = 0; index < bundle->api_credential_count; index += 1)
   {
      prodigy_api_credential_free(&bundle->api_credentials[index]);
   }
   free(bundle->api_credentials);
   bundle->api_credentials = NULL;
   bundle->api_credential_count = 0;

   bundle->bundle_generation = 0;
}

void prodigy_credential_delta_free(prodigy_credential_delta *delta)
{
   size_t index = 0;

   if (delta == NULL)
   {
      return;
   }

   for (index = 0; index < delta->updated_tls_count; index += 1)
   {
      prodigy_tls_identity_free(&delta->updated_tls[index]);
   }
   free(delta->updated_tls);
   delta->updated_tls = NULL;
   delta->updated_tls_count = 0;

   for (index = 0; index < delta->removed_tls_name_count; index += 1)
   {
      prodigy_bytes_free(&delta->removed_tls_names[index]);
   }
   free(delta->removed_tls_names);
   delta->removed_tls_names = NULL;
   delta->removed_tls_name_count = 0;

   for (index = 0; index < delta->updated_api_count; index += 1)
   {
      prodigy_api_credential_free(&delta->updated_api[index]);
   }
   free(delta->updated_api);
   delta->updated_api = NULL;
   delta->updated_api_count = 0;

   for (index = 0; index < delta->removed_api_name_count; index += 1)
   {
      prodigy_bytes_free(&delta->removed_api_names[index]);
   }
   free(delta->removed_api_names);
   delta->removed_api_names = NULL;
   delta->removed_api_name_count = 0;

   prodigy_bytes_free(&delta->reason);
   delta->bundle_generation = 0;
}

void prodigy_container_parameters_free(prodigy_container_parameters *parameters)
{
   if (parameters == NULL)
   {
      return;
   }

   free(parameters->advertises);
   parameters->advertises = NULL;
   parameters->advertise_count = 0;

   free(parameters->subscription_pairings);
   parameters->subscription_pairings = NULL;
   parameters->subscription_pairing_count = 0;

   free(parameters->advertisement_pairings);
   parameters->advertisement_pairings = NULL;
   parameters->advertisement_pairing_count = 0;

   free(parameters->flags);
   parameters->flags = NULL;
   parameters->flag_count = 0;

   if (parameters->has_credential_bundle)
   {
      prodigy_credential_bundle_free(&parameters->credential_bundle);
   }
   memset(parameters, 0, sizeof(*parameters));
}

void prodigy_frame_decoder_init(prodigy_frame_decoder *decoder)
{
   if (decoder == NULL)
   {
      return;
   }

   memset(decoder, 0, sizeof(*decoder));
}

void prodigy_frame_decoder_free(prodigy_frame_decoder *decoder)
{
   if (decoder == NULL)
   {
      return;
   }

   free(decoder->data);
   decoder->data = NULL;
   decoder->size = 0;
   decoder->capacity = 0;
}

static void prodigy_reader_init(prodigy_reader *reader, const uint8_t *data, size_t size)
{
   reader->cursor = data;
   reader->terminal = data + size;
}

static size_t prodigy_reader_remaining(const prodigy_reader *reader)
{
   return (size_t)(reader->terminal - reader->cursor);
}

static prodigy_result prodigy_read_exact_bytes(prodigy_reader *reader, uint8_t *output, size_t size)
{
   if (prodigy_reader_remaining(reader) < size)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   if (size > 0)
   {
      memcpy(output, reader->cursor, size);
   }

   reader->cursor += size;
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_read_u8(prodigy_reader *reader, uint8_t *value)
{
   return prodigy_read_exact_bytes(reader, value, 1);
}

static prodigy_result prodigy_read_bool(prodigy_reader *reader, uint8_t *value)
{
   prodigy_result result = prodigy_read_u8(reader, value);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   if (*value > 1)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_read_u16(prodigy_reader *reader, uint16_t *value)
{
   uint8_t bytes[2] = {0};
   prodigy_result result = prodigy_read_exact_bytes(reader, bytes, sizeof(bytes));
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   *value = (uint16_t)(bytes[0] | ((uint16_t)bytes[1] << 8));
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_read_u32(prodigy_reader *reader, uint32_t *value)
{
   uint8_t bytes[4] = {0};
   prodigy_result result = prodigy_read_exact_bytes(reader, bytes, sizeof(bytes));
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   *value = (uint32_t)bytes[0]
      | ((uint32_t)bytes[1] << 8)
      | ((uint32_t)bytes[2] << 16)
      | ((uint32_t)bytes[3] << 24);
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_read_i32(prodigy_reader *reader, int32_t *value)
{
   uint32_t raw = 0;
   prodigy_result result = prodigy_read_u32(reader, &raw);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   *value = (int32_t)raw;
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_read_u64(prodigy_reader *reader, uint64_t *value)
{
   uint8_t bytes[8] = {0};
   prodigy_result result = prodigy_read_exact_bytes(reader, bytes, sizeof(bytes));
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   *value = (uint64_t)bytes[0]
      | ((uint64_t)bytes[1] << 8)
      | ((uint64_t)bytes[2] << 16)
      | ((uint64_t)bytes[3] << 24)
      | ((uint64_t)bytes[4] << 32)
      | ((uint64_t)bytes[5] << 40)
      | ((uint64_t)bytes[6] << 48)
      | ((uint64_t)bytes[7] << 56);
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_read_i64(prodigy_reader *reader, int64_t *value)
{
   uint64_t raw = 0;
   prodigy_result result = prodigy_read_u64(reader, &raw);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   *value = (int64_t)raw;
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_read_u128(prodigy_reader *reader, prodigy_u128 *value)
{
   return prodigy_read_exact_bytes(reader, value->bytes, sizeof(value->bytes));
}

static prodigy_result prodigy_read_owned_bytes(prodigy_reader *reader, prodigy_bytes *value)
{
   uint32_t length = 0;
   prodigy_result result = prodigy_read_u32(reader, &length);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   if (prodigy_reader_remaining(reader) < length)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   result = prodigy_copy_bytes(value, reader->cursor, (size_t)length);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   reader->cursor += length;
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_read_magic(prodigy_reader *reader, const uint8_t magic[8])
{
   if (prodigy_reader_remaining(reader) < 8)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   if (memcmp(reader->cursor, magic, 8) != 0)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   reader->cursor += 8;
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_read_ip_address(prodigy_reader *reader, prodigy_ip_address *address)
{
   prodigy_result result = prodigy_read_exact_bytes(reader, address->bytes, sizeof(address->bytes));
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   return prodigy_read_bool(reader, &address->is_ipv6);
}

static prodigy_result prodigy_read_ip_prefix(prodigy_reader *reader, prodigy_ip_prefix *prefix)
{
   prodigy_result result = prodigy_read_ip_address(reader, &prefix->address);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   return prodigy_read_u8(reader, &prefix->cidr);
}

static prodigy_result prodigy_read_string_array(prodigy_reader *reader, prodigy_bytes **values, size_t *count)
{
   uint32_t raw_count = 0;
   size_t index = 0;
   prodigy_bytes *buffer = NULL;
   prodigy_result result = prodigy_read_u32(reader, &raw_count);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   *values = NULL;
   *count = (size_t)raw_count;
   if (*count == 0)
   {
      return PRODIGY_RESULT_OK;
   }

   buffer = (prodigy_bytes *)prodigy_calloc_array(*count, sizeof(*buffer));
   if (buffer == NULL)
   {
      return PRODIGY_RESULT_MEMORY;
   }

   for (index = 0; index < *count; index += 1)
   {
      result = prodigy_read_owned_bytes(reader, &buffer[index]);
      if (result != PRODIGY_RESULT_OK)
      {
         for (index = 0; index < *count; index += 1)
         {
            prodigy_bytes_free(&buffer[index]);
         }
         free(buffer);
         return result;
      }
   }

   *values = buffer;
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_read_ip_address_array(prodigy_reader *reader, prodigy_ip_address **values, size_t *count)
{
   uint32_t raw_count = 0;
   size_t index = 0;
   prodigy_result result = prodigy_read_u32(reader, &raw_count);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   *values = NULL;
   *count = (size_t)raw_count;
   if (*count == 0)
   {
      return PRODIGY_RESULT_OK;
   }

   *values = (prodigy_ip_address *)prodigy_calloc_array(*count, sizeof(**values));
   if (*values == NULL)
   {
      return PRODIGY_RESULT_MEMORY;
   }

   for (index = 0; index < *count; index += 1)
   {
      result = prodigy_read_ip_address(reader, &(*values)[index]);
      if (result != PRODIGY_RESULT_OK)
      {
         free(*values);
         *values = NULL;
         *count = 0;
         return result;
      }
   }

   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_read_tls_identity(prodigy_reader *reader, prodigy_tls_identity *identity)
{
   prodigy_result result = PRODIGY_RESULT_OK;

   memset(identity, 0, sizeof(*identity));

   result = prodigy_read_owned_bytes(reader, &identity->name);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_u64(reader, &identity->generation);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_i64(reader, &identity->not_before_ms);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_i64(reader, &identity->not_after_ms);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_owned_bytes(reader, &identity->cert_pem);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_owned_bytes(reader, &identity->key_pem);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_owned_bytes(reader, &identity->chain_pem);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_string_array(reader, &identity->dns_sans, &identity->dns_san_count);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_ip_address_array(reader, &identity->ip_sans, &identity->ip_san_count);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_string_array(reader, &identity->tags, &identity->tag_count);
   return result;
}

static prodigy_result prodigy_read_api_credential(prodigy_reader *reader, prodigy_api_credential *credential)
{
   uint32_t metadata_count = 0;
   size_t index = 0;
   prodigy_result result = PRODIGY_RESULT_OK;

   memset(credential, 0, sizeof(*credential));

   result = prodigy_read_owned_bytes(reader, &credential->name);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_owned_bytes(reader, &credential->provider);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_u64(reader, &credential->generation);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_i64(reader, &credential->expires_at_ms);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_i64(reader, &credential->active_from_ms);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_i64(reader, &credential->sunset_at_ms);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_owned_bytes(reader, &credential->material);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_u32(reader, &metadata_count);
   if (result != PRODIGY_RESULT_OK) return result;

   credential->metadata_count = (size_t)metadata_count;
   if (credential->metadata_count == 0)
   {
      return PRODIGY_RESULT_OK;
   }

   credential->metadata = (prodigy_string_pair *)prodigy_calloc_array(credential->metadata_count, sizeof(*credential->metadata));
   if (credential->metadata == NULL)
   {
      return PRODIGY_RESULT_MEMORY;
   }

   for (index = 0; index < credential->metadata_count; index += 1)
   {
      result = prodigy_read_owned_bytes(reader, &credential->metadata[index].key);
      if (result != PRODIGY_RESULT_OK) return result;
      result = prodigy_read_owned_bytes(reader, &credential->metadata[index].value);
      if (result != PRODIGY_RESULT_OK) return result;
   }

   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_decode_credential_bundle_fields(prodigy_reader *reader, prodigy_credential_bundle *bundle)
{
   uint32_t tls_count = 0;
   uint32_t api_count = 0;
   size_t index = 0;
   prodigy_result result = PRODIGY_RESULT_OK;

   memset(bundle, 0, sizeof(*bundle));

   result = prodigy_read_u32(reader, &tls_count);
   if (result != PRODIGY_RESULT_OK) return result;
   bundle->tls_identity_count = (size_t)tls_count;
   if (bundle->tls_identity_count > 0)
   {
      bundle->tls_identities = (prodigy_tls_identity *)prodigy_calloc_array(bundle->tls_identity_count, sizeof(*bundle->tls_identities));
      if (bundle->tls_identities == NULL)
      {
         return PRODIGY_RESULT_MEMORY;
      }

      for (index = 0; index < bundle->tls_identity_count; index += 1)
      {
         result = prodigy_read_tls_identity(reader, &bundle->tls_identities[index]);
         if (result != PRODIGY_RESULT_OK) return result;
      }
   }

   result = prodigy_read_u32(reader, &api_count);
   if (result != PRODIGY_RESULT_OK) return result;
   bundle->api_credential_count = (size_t)api_count;
   if (bundle->api_credential_count > 0)
   {
      bundle->api_credentials = (prodigy_api_credential *)prodigy_calloc_array(bundle->api_credential_count, sizeof(*bundle->api_credentials));
      if (bundle->api_credentials == NULL)
      {
         return PRODIGY_RESULT_MEMORY;
      }

      for (index = 0; index < bundle->api_credential_count; index += 1)
      {
         result = prodigy_read_api_credential(reader, &bundle->api_credentials[index]);
         if (result != PRODIGY_RESULT_OK) return result;
      }
   }

   return prodigy_read_u64(reader, &bundle->bundle_generation);
}

static prodigy_result prodigy_decode_credential_delta_fields(prodigy_reader *reader, prodigy_credential_delta *delta)
{
   uint32_t updated_tls_count = 0;
   uint32_t updated_api_count = 0;
   size_t index = 0;
   prodigy_result result = PRODIGY_RESULT_OK;

   memset(delta, 0, sizeof(*delta));

   result = prodigy_read_u64(reader, &delta->bundle_generation);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_u32(reader, &updated_tls_count);
   if (result != PRODIGY_RESULT_OK) return result;

   delta->updated_tls_count = (size_t)updated_tls_count;
   if (delta->updated_tls_count > 0)
   {
      delta->updated_tls = (prodigy_tls_identity *)prodigy_calloc_array(delta->updated_tls_count, sizeof(*delta->updated_tls));
      if (delta->updated_tls == NULL)
      {
         return PRODIGY_RESULT_MEMORY;
      }

      for (index = 0; index < delta->updated_tls_count; index += 1)
      {
         result = prodigy_read_tls_identity(reader, &delta->updated_tls[index]);
         if (result != PRODIGY_RESULT_OK) return result;
      }
   }

   result = prodigy_read_string_array(reader, &delta->removed_tls_names, &delta->removed_tls_name_count);
   if (result != PRODIGY_RESULT_OK) return result;

   result = prodigy_read_u32(reader, &updated_api_count);
   if (result != PRODIGY_RESULT_OK) return result;
   delta->updated_api_count = (size_t)updated_api_count;
   if (delta->updated_api_count > 0)
   {
      delta->updated_api = (prodigy_api_credential *)prodigy_calloc_array(delta->updated_api_count, sizeof(*delta->updated_api));
      if (delta->updated_api == NULL)
      {
         return PRODIGY_RESULT_MEMORY;
      }

      for (index = 0; index < delta->updated_api_count; index += 1)
      {
         result = prodigy_read_api_credential(reader, &delta->updated_api[index]);
         if (result != PRODIGY_RESULT_OK) return result;
      }
   }

   result = prodigy_read_string_array(reader, &delta->removed_api_names, &delta->removed_api_name_count);
   if (result != PRODIGY_RESULT_OK) return result;

   return prodigy_read_owned_bytes(reader, &delta->reason);
}

prodigy_result prodigy_decode_credential_bundle(
   const uint8_t *data,
   size_t size,
   prodigy_credential_bundle *bundle)
{
   prodigy_reader reader;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (data == NULL || bundle == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   prodigy_reader_init(&reader, data, size);
   result = prodigy_read_magic(&reader, prodigy_credential_bundle_magic);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_decode_credential_bundle_fields(&reader, bundle);
   if (result != PRODIGY_RESULT_OK)
   {
      prodigy_credential_bundle_free(bundle);
      return result;
   }

   if (prodigy_reader_remaining(&reader) != 0)
   {
      prodigy_credential_bundle_free(bundle);
      return PRODIGY_RESULT_PROTOCOL;
   }

   return PRODIGY_RESULT_OK;
}

prodigy_result prodigy_decode_credential_delta(
   const uint8_t *data,
   size_t size,
   prodigy_credential_delta *delta)
{
   prodigy_reader reader;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (data == NULL || delta == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   prodigy_reader_init(&reader, data, size);
   result = prodigy_read_magic(&reader, prodigy_credential_delta_magic);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_decode_credential_delta_fields(&reader, delta);
   if (result != PRODIGY_RESULT_OK)
   {
      prodigy_credential_delta_free(delta);
      return result;
   }

   if (prodigy_reader_remaining(&reader) != 0)
   {
      prodigy_credential_delta_free(delta);
      return PRODIGY_RESULT_PROTOCOL;
   }

   return PRODIGY_RESULT_OK;
}

prodigy_result prodigy_decode_container_parameters(
   const uint8_t *data,
   size_t size,
   prodigy_container_parameters *parameters)
{
   prodigy_reader reader;
   uint32_t count = 0;
   size_t index = 0;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (data == NULL || parameters == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   memset(parameters, 0, sizeof(*parameters));
   prodigy_reader_init(&reader, data, size);

   result = prodigy_read_magic(&reader, prodigy_container_parameters_magic);
   if (result != PRODIGY_RESULT_OK) return result;
   result = prodigy_read_u128(&reader, &parameters->uuid);
   if (result != PRODIGY_RESULT_OK) goto fail;
   result = prodigy_read_u32(&reader, &parameters->memory_mb);
   if (result != PRODIGY_RESULT_OK) goto fail;
   result = prodigy_read_u32(&reader, &parameters->storage_mb);
   if (result != PRODIGY_RESULT_OK) goto fail;
   result = prodigy_read_u16(&reader, &parameters->logical_cores);
   if (result != PRODIGY_RESULT_OK) goto fail;
   result = prodigy_read_i32(&reader, &parameters->neuron_fd);
   if (result != PRODIGY_RESULT_OK) goto fail;
   result = prodigy_read_i32(&reader, &parameters->low_cpu);
   if (result != PRODIGY_RESULT_OK) goto fail;
   result = prodigy_read_i32(&reader, &parameters->high_cpu);
   if (result != PRODIGY_RESULT_OK) goto fail;

   result = prodigy_read_u32(&reader, &count);
   if (result != PRODIGY_RESULT_OK) goto fail;
   parameters->advertise_count = (size_t)count;
   if (parameters->advertise_count > 0)
   {
      parameters->advertises = (prodigy_advertised_port *)prodigy_calloc_array(parameters->advertise_count, sizeof(*parameters->advertises));
      if (parameters->advertises == NULL)
      {
         result = PRODIGY_RESULT_MEMORY;
         goto fail;
      }

      for (index = 0; index < parameters->advertise_count; index += 1)
      {
         result = prodigy_read_u64(&reader, &parameters->advertises[index].service);
         if (result != PRODIGY_RESULT_OK) goto fail;
         result = prodigy_read_u16(&reader, &parameters->advertises[index].port);
         if (result != PRODIGY_RESULT_OK) goto fail;
      }
   }

   result = prodigy_read_u32(&reader, &count);
   if (result != PRODIGY_RESULT_OK) goto fail;
   parameters->subscription_pairing_count = (size_t)count;
   if (parameters->subscription_pairing_count > 0)
   {
      parameters->subscription_pairings = (prodigy_subscription_pairing *)prodigy_calloc_array(
         parameters->subscription_pairing_count,
         sizeof(*parameters->subscription_pairings));
      if (parameters->subscription_pairings == NULL)
      {
         result = PRODIGY_RESULT_MEMORY;
         goto fail;
      }

      for (index = 0; index < parameters->subscription_pairing_count; index += 1)
      {
         result = prodigy_read_u128(&reader, &parameters->subscription_pairings[index].secret);
         if (result != PRODIGY_RESULT_OK) goto fail;
         result = prodigy_read_u128(&reader, &parameters->subscription_pairings[index].address);
         if (result != PRODIGY_RESULT_OK) goto fail;
         result = prodigy_read_u64(&reader, &parameters->subscription_pairings[index].service);
         if (result != PRODIGY_RESULT_OK) goto fail;
         result = prodigy_read_u16(&reader, &parameters->subscription_pairings[index].port);
         if (result != PRODIGY_RESULT_OK) goto fail;
         parameters->subscription_pairings[index].application_id = (uint16_t)(parameters->subscription_pairings[index].service >> 48);
         parameters->subscription_pairings[index].activate = 1;
      }
   }

   result = prodigy_read_u32(&reader, &count);
   if (result != PRODIGY_RESULT_OK) goto fail;
   parameters->advertisement_pairing_count = (size_t)count;
   if (parameters->advertisement_pairing_count > 0)
   {
      parameters->advertisement_pairings = (prodigy_advertisement_pairing *)prodigy_calloc_array(
         parameters->advertisement_pairing_count,
         sizeof(*parameters->advertisement_pairings));
      if (parameters->advertisement_pairings == NULL)
      {
         result = PRODIGY_RESULT_MEMORY;
         goto fail;
      }

      for (index = 0; index < parameters->advertisement_pairing_count; index += 1)
      {
         result = prodigy_read_u128(&reader, &parameters->advertisement_pairings[index].secret);
         if (result != PRODIGY_RESULT_OK) goto fail;
         result = prodigy_read_u128(&reader, &parameters->advertisement_pairings[index].address);
         if (result != PRODIGY_RESULT_OK) goto fail;
         result = prodigy_read_u64(&reader, &parameters->advertisement_pairings[index].service);
         if (result != PRODIGY_RESULT_OK) goto fail;
         parameters->advertisement_pairings[index].application_id = (uint16_t)(parameters->advertisement_pairings[index].service >> 48);
         parameters->advertisement_pairings[index].activate = 1;
      }
   }

   result = prodigy_read_ip_prefix(&reader, &parameters->private6);
   if (result != PRODIGY_RESULT_OK) goto fail;
   result = prodigy_read_bool(&reader, &parameters->just_crashed);
   if (result != PRODIGY_RESULT_OK) goto fail;
   result = prodigy_read_u8(&reader, &parameters->datacenter_unique_tag);
   if (result != PRODIGY_RESULT_OK) goto fail;

   result = prodigy_read_u32(&reader, &count);
   if (result != PRODIGY_RESULT_OK) goto fail;
   parameters->flag_count = (size_t)count;
   if (parameters->flag_count > 0)
   {
      parameters->flags = (uint64_t *)prodigy_calloc_array(parameters->flag_count, sizeof(*parameters->flags));
      if (parameters->flags == NULL)
      {
         result = PRODIGY_RESULT_MEMORY;
         goto fail;
      }

      for (index = 0; index < parameters->flag_count; index += 1)
      {
         result = prodigy_read_u64(&reader, &parameters->flags[index]);
         if (result != PRODIGY_RESULT_OK) goto fail;
      }
   }

   result = prodigy_read_bool(&reader, &parameters->has_credential_bundle);
   if (result != PRODIGY_RESULT_OK) goto fail;
   if (parameters->has_credential_bundle)
   {
      result = prodigy_decode_credential_bundle_fields(&reader, &parameters->credential_bundle);
      if (result != PRODIGY_RESULT_OK) goto fail;
   }

   if (prodigy_reader_remaining(&reader) != 0)
   {
      result = PRODIGY_RESULT_PROTOCOL;
      goto fail;
   }

   return PRODIGY_RESULT_OK;

fail:
   prodigy_container_parameters_free(parameters);
   return result;
}

static prodigy_result prodigy_read_all_fd(int fd, uint8_t **data, size_t *size)
{
   uint8_t *buffer = NULL;
   size_t used = 0;
   size_t capacity = 4096;

   if (data == NULL || size == NULL || fd < 0)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   buffer = (uint8_t *)malloc(capacity);
   if (buffer == NULL)
   {
      return PRODIGY_RESULT_MEMORY;
   }

   for (;;)
   {
      ssize_t rc = read(fd, buffer + used, capacity - used);
      if (rc == 0)
      {
         *data = buffer;
         *size = used;
         return PRODIGY_RESULT_OK;
      }

      if (rc < 0)
      {
         if (errno == EINTR)
         {
            continue;
         }

         free(buffer);
         return PRODIGY_RESULT_IO;
      }

      used += (size_t)rc;
      if (used == capacity)
      {
         uint8_t *next = NULL;
         if (capacity > (SIZE_MAX / 2))
         {
            free(buffer);
            return PRODIGY_RESULT_MEMORY;
         }

         capacity *= 2;
         next = (uint8_t *)realloc(buffer, capacity);
         if (next == NULL)
         {
            free(buffer);
            return PRODIGY_RESULT_MEMORY;
         }

         buffer = next;
      }
   }
}

static void prodigy_close_fd(int fd)
{
   if (fd < 0)
   {
      return;
   }

   while (close(fd) < 0)
   {
      if (errno != EINTR)
      {
         break;
      }
   }
}

static prodigy_result prodigy_load_container_parameters_from_process(
   int argc,
   char **argv,
   prodigy_container_parameters *parameters)
{
   const char *fd_env = getenv("PRODIGY_PARAMS_FD");
   uint8_t *buffer = NULL;
   size_t size = 0;
   prodigy_result result = PRODIGY_RESULT_PROTOCOL;

   if (parameters == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   if (fd_env != NULL && fd_env[0] != '\0')
   {
      long fd = strtol(fd_env, NULL, 10);
      int params_fd = -1;
      if (fd < 0 || fd > INT_MAX)
      {
         return PRODIGY_RESULT_ARGUMENT;
      }

      params_fd = (int)fd;
      if (lseek(params_fd, 0, SEEK_SET) < 0 && errno != ESPIPE && errno != EINVAL)
      {
         prodigy_close_fd(params_fd);
         return PRODIGY_RESULT_IO;
      }
      result = prodigy_read_all_fd(params_fd, &buffer, &size);
      prodigy_close_fd(params_fd);
      if (result != PRODIGY_RESULT_OK)
      {
         return result;
      }

      result = prodigy_decode_container_parameters(buffer, size, parameters);
      free(buffer);
      return result;
   }

   if (argc > 1 && argv != NULL && argv[1] != NULL)
   {
      size = strlen(argv[1]);
      return prodigy_decode_container_parameters((const uint8_t *)argv[1], size, parameters);
   }

   return PRODIGY_RESULT_ARGUMENT;
}

static prodigy_result prodigy_read_exact_fd(int fd, uint8_t *buffer, size_t size)
{
   size_t offset = 0;

   while (offset < size)
   {
      ssize_t rc = read(fd, buffer + offset, size - offset);
      if (rc == 0)
      {
         return (offset == 0) ? PRODIGY_RESULT_EOF : PRODIGY_RESULT_IO;
      }

      if (rc < 0)
      {
         if (errno == EINTR)
         {
            continue;
         }

         return PRODIGY_RESULT_IO;
      }

      offset += (size_t)rc;
   }

   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_write_all_fd(int fd, const uint8_t *buffer, size_t size)
{
   size_t offset = 0;

   while (offset < size)
   {
      ssize_t rc = write(fd, buffer + offset, size - offset);
      if (rc < 0)
      {
         if (errno == EINTR)
         {
            continue;
         }

         return PRODIGY_RESULT_IO;
      }

      offset += (size_t)rc;
   }

   return PRODIGY_RESULT_OK;
}

static void prodigy_write_u16_le(uint8_t *buffer, uint16_t value)
{
   buffer[0] = (uint8_t)(value & 0xffu);
   buffer[1] = (uint8_t)((value >> 8) & 0xffu);
}

static int prodigy_valid_topic(uint16_t topic)
{
   return topic <= (uint16_t)PRODIGY_CONTAINER_TOPIC_CREDENTIALS_REFRESH;
}

prodigy_result prodigy_build_message_frame(
   prodigy_container_topic topic,
   const uint8_t *payload,
   size_t payload_size,
   prodigy_bytes *frame)
{
   uint8_t *encoded = NULL;
   size_t frame_size = 0;
   size_t padding = 0;

   if (frame == NULL || (payload == NULL && payload_size > 0))
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   frame->data = NULL;
   frame->size = 0;

   padding = (16u - ((8u + payload_size) & 15u)) & 15u;
   frame_size = 8u + payload_size + padding;
   if (frame_size > UINT32_MAX)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   encoded = (uint8_t *)calloc(1, frame_size);
   if (encoded == NULL)
   {
      return PRODIGY_RESULT_MEMORY;
   }

   prodigy_write_u32_le(encoded, (uint32_t)frame_size);
   prodigy_write_u16_le(encoded + 4, (uint16_t)topic);
   encoded[6] = (uint8_t)padding;
   encoded[7] = 8u;
   if (payload_size > 0)
   {
      memcpy(encoded + 8, payload, payload_size);
   }

   frame->data = encoded;
   frame->size = frame_size;
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_encode_metric_pairs(
   const prodigy_metric_pair *metrics,
   size_t metric_count,
   prodigy_bytes *payload)
{
   uint8_t *encoded = NULL;
   size_t payload_size = metric_count * 16u;
   size_t index = 0;

   if (payload == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   payload->data = NULL;
   payload->size = 0;

   if (metric_count > 0 && metrics == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   if (metric_count > 0 && metric_count > (SIZE_MAX / 16u))
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   if (payload_size == 0)
   {
      return PRODIGY_RESULT_OK;
   }

   encoded = (uint8_t *)malloc(payload_size);
   if (encoded == NULL)
   {
      return PRODIGY_RESULT_MEMORY;
   }

   for (index = 0; index < metric_count; index += 1)
   {
      prodigy_write_u64_le(encoded + (index * 16u), metrics[index].key);
      prodigy_write_u64_le(encoded + (index * 16u) + 8u, metrics[index].value);
   }

   payload->data = encoded;
   payload->size = payload_size;
   return PRODIGY_RESULT_OK;
}

prodigy_result prodigy_build_ready_frame(prodigy_bytes *frame)
{
   return prodigy_build_message_frame(PRODIGY_CONTAINER_TOPIC_HEALTHY, NULL, 0, frame);
}

prodigy_result prodigy_build_statistics_frame(
   const prodigy_metric_pair *metrics,
   size_t metric_count,
   prodigy_bytes *frame)
{
   prodigy_bytes payload;
   prodigy_result result = PRODIGY_RESULT_OK;

   memset(&payload, 0, sizeof(payload));
   result = prodigy_encode_metric_pairs(metrics, metric_count, &payload);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   result = prodigy_build_message_frame(
      PRODIGY_CONTAINER_TOPIC_STATISTICS,
      payload.data,
      payload.size,
      frame);
   prodigy_bytes_free(&payload);
   return result;
}

prodigy_result prodigy_build_resource_delta_ack_frame(
   uint8_t accepted,
   prodigy_bytes *frame)
{
   uint8_t payload = (accepted != 0) ? 1u : 0u;
   return prodigy_build_message_frame(PRODIGY_CONTAINER_TOPIC_RESOURCE_DELTA_ACK, &payload, 1u, frame);
}

prodigy_result prodigy_build_credentials_refresh_ack_frame(prodigy_bytes *frame)
{
   return prodigy_build_message_frame(PRODIGY_CONTAINER_TOPIC_CREDENTIALS_REFRESH, NULL, 0, frame);
}

prodigy_result prodigy_parse_message_frame(
   const uint8_t *data,
   size_t size,
   prodigy_message_frame *frame)
{
   uint32_t frame_size = 0;
   uint16_t topic = 0;
   uint8_t padding = 0;
   uint8_t header_size = 0;
   size_t payload_size = 0;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (data == NULL || frame == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   memset(frame, 0, sizeof(*frame));
   if (size < 8u)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   frame_size = (uint32_t)data[0]
      | ((uint32_t)data[1] << 8)
      | ((uint32_t)data[2] << 16)
      | ((uint32_t)data[3] << 24);
   topic = (uint16_t)(data[4] | ((uint16_t)data[5] << 8));
   padding = data[6];
   header_size = data[7];

   if (header_size != 8u || frame_size != size || frame_size < 8u || (frame_size & 15u) != 0u)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }
   if (prodigy_valid_topic(topic) == 0)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }
   if ((size_t)padding > (size - 8u))
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   payload_size = size - 8u - (size_t)padding;
   frame->topic = (prodigy_container_topic)topic;
   result = prodigy_copy_bytes(&frame->payload, data + 8u, payload_size);
   if (result != PRODIGY_RESULT_OK)
   {
      prodigy_message_frame_free(frame);
   }

   return result;
}

prodigy_result prodigy_frame_decoder_feed(
   prodigy_frame_decoder *decoder,
   const uint8_t *data,
   size_t size)
{
   uint8_t *next = NULL;
   size_t required = 0;

   if (decoder == NULL || (data == NULL && size > 0))
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   if (size == 0)
   {
      return PRODIGY_RESULT_OK;
   }

   if (decoder->size > (SIZE_MAX - size))
   {
      return PRODIGY_RESULT_MEMORY;
   }

   required = decoder->size + size;
   if (required > decoder->capacity)
   {
      size_t capacity = (decoder->capacity == 0) ? 1024u : decoder->capacity;
      while (capacity < required)
      {
         if (capacity > (SIZE_MAX / 2u))
         {
            return PRODIGY_RESULT_MEMORY;
         }
         capacity *= 2u;
      }

      next = (uint8_t *)realloc(decoder->data, capacity);
      if (next == NULL)
      {
         return PRODIGY_RESULT_MEMORY;
      }

      decoder->data = next;
      decoder->capacity = capacity;
   }

   memcpy(decoder->data + decoder->size, data, size);
   decoder->size += size;
   return PRODIGY_RESULT_OK;
}

prodigy_result prodigy_frame_decoder_next(
   prodigy_frame_decoder *decoder,
   prodigy_message_frame *frame)
{
   uint32_t frame_size = 0;

   if (decoder == NULL || frame == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   memset(frame, 0, sizeof(*frame));
   if (decoder->size < 8u)
   {
      return PRODIGY_RESULT_AGAIN;
   }

   frame_size = (uint32_t)decoder->data[0]
      | ((uint32_t)decoder->data[1] << 8)
      | ((uint32_t)decoder->data[2] << 16)
      | ((uint32_t)decoder->data[3] << 24);
   if (frame_size > decoder->size)
   {
      return PRODIGY_RESULT_AGAIN;
   }

   if (prodigy_parse_message_frame(decoder->data, frame_size, frame) != PRODIGY_RESULT_OK)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   decoder->size -= frame_size;
   if (decoder->size > 0)
   {
      memmove(decoder->data, decoder->data + frame_size, decoder->size);
   }

   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_send_frame(
   prodigy_neuron_hub *hub,
   prodigy_container_topic topic,
   const uint8_t *payload,
   size_t payload_size)
{
   prodigy_bytes frame;
   prodigy_result result = PRODIGY_RESULT_OK;

   memset(&frame, 0, sizeof(frame));

   if (hub == NULL || hub->fd < 0)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   result = prodigy_build_message_frame(topic, payload, payload_size, &frame);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   result = prodigy_write_all_fd(hub->fd, frame.data, frame.size);
   prodigy_bytes_free(&frame);
   return result;
}

prodigy_result prodigy_neuron_hub_handle_message_frame(
   prodigy_neuron_hub *hub,
   const prodigy_message_frame *frame,
   prodigy_message_frame *automatic_response)
{
   prodigy_reader reader;
   prodigy_result result = PRODIGY_RESULT_OK;
   const uint8_t *payload = NULL;
   size_t payload_size = 0;

   if (hub == NULL || frame == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   payload = frame->payload.data;
   payload_size = frame->payload.size;
   if (automatic_response != NULL)
   {
      memset(automatic_response, 0, sizeof(*automatic_response));
      automatic_response->topic = PRODIGY_CONTAINER_TOPIC_NONE;
   }

   prodigy_reader_init(&reader, payload, payload_size);

   switch (frame->topic)
   {
      case PRODIGY_CONTAINER_TOPIC_NONE:
      {
         if (payload_size != 0)
         {
            return PRODIGY_RESULT_PROTOCOL;
         }

         if (hub->callbacks.end_of_dynamic_args != NULL)
         {
            hub->callbacks.end_of_dynamic_args(hub->context, hub);
         }
         return PRODIGY_RESULT_OK;
      }
      case PRODIGY_CONTAINER_TOPIC_PING:
      {
         if (payload_size != 0)
         {
            return PRODIGY_RESULT_PROTOCOL;
         }

         if (automatic_response != NULL)
         {
            automatic_response->topic = PRODIGY_CONTAINER_TOPIC_PING;
         }
         return PRODIGY_RESULT_OK;
      }
      case PRODIGY_CONTAINER_TOPIC_PONG:
      case PRODIGY_CONTAINER_TOPIC_HEALTHY:
      {
         return (payload_size == 0) ? PRODIGY_RESULT_OK : PRODIGY_RESULT_PROTOCOL;
      }
      case PRODIGY_CONTAINER_TOPIC_STOP:
      {
         if (payload_size != 0)
         {
            return PRODIGY_RESULT_PROTOCOL;
         }

         hub->stop_requested = 1;
         if (hub->callbacks.begin_shutdown != NULL)
         {
            hub->callbacks.begin_shutdown(hub->context, hub);
         }
         return PRODIGY_RESULT_OK;
      }
      case PRODIGY_CONTAINER_TOPIC_ADVERTISEMENT_PAIRING:
      {
         prodigy_advertisement_pairing pairing;
         memset(&pairing, 0, sizeof(pairing));
         result = prodigy_read_u128(&reader, &pairing.secret);
         if (result != PRODIGY_RESULT_OK) return result;
         result = prodigy_read_u128(&reader, &pairing.address);
         if (result != PRODIGY_RESULT_OK) return result;
         result = prodigy_read_u64(&reader, &pairing.service);
         if (result != PRODIGY_RESULT_OK) return result;
         result = prodigy_read_u16(&reader, &pairing.application_id);
         if (result != PRODIGY_RESULT_OK) return result;
         result = prodigy_read_bool(&reader, &pairing.activate);
         if (result != PRODIGY_RESULT_OK) return result;
         if (prodigy_reader_remaining(&reader) != 0) return PRODIGY_RESULT_PROTOCOL;
         if (hub->callbacks.advertisement_pairing != NULL)
         {
            hub->callbacks.advertisement_pairing(hub->context, hub, &pairing);
         }
         return PRODIGY_RESULT_OK;
      }
      case PRODIGY_CONTAINER_TOPIC_SUBSCRIPTION_PAIRING:
      {
         prodigy_subscription_pairing pairing;
         memset(&pairing, 0, sizeof(pairing));
         result = prodigy_read_u128(&reader, &pairing.secret);
         if (result != PRODIGY_RESULT_OK) return result;
         result = prodigy_read_u128(&reader, &pairing.address);
         if (result != PRODIGY_RESULT_OK) return result;
         result = prodigy_read_u64(&reader, &pairing.service);
         if (result != PRODIGY_RESULT_OK) return result;
         result = prodigy_read_u16(&reader, &pairing.port);
         if (result != PRODIGY_RESULT_OK) return result;
         result = prodigy_read_u16(&reader, &pairing.application_id);
         if (result != PRODIGY_RESULT_OK) return result;
         result = prodigy_read_bool(&reader, &pairing.activate);
         if (result != PRODIGY_RESULT_OK) return result;
         if (prodigy_reader_remaining(&reader) != 0) return PRODIGY_RESULT_PROTOCOL;
         if (hub->callbacks.subscription_pairing != NULL)
         {
            hub->callbacks.subscription_pairing(hub->context, hub, &pairing);
         }
         return PRODIGY_RESULT_OK;
      }
      case PRODIGY_CONTAINER_TOPIC_RESOURCE_DELTA:
      {
         prodigy_resource_delta delta;
         memset(&delta, 0, sizeof(delta));
         result = prodigy_read_u16(&reader, &delta.logical_cores);
         if (result != PRODIGY_RESULT_OK) return result;
         result = prodigy_read_u32(&reader, &delta.memory_mb);
         if (result != PRODIGY_RESULT_OK) return result;
         result = prodigy_read_u32(&reader, &delta.storage_mb);
         if (result != PRODIGY_RESULT_OK) return result;
         result = prodigy_read_bool(&reader, &delta.is_downscale);
         if (result != PRODIGY_RESULT_OK) return result;
         result = prodigy_read_u32(&reader, &delta.grace_seconds);
         if (result != PRODIGY_RESULT_OK) return result;
         if (prodigy_reader_remaining(&reader) != 0) return PRODIGY_RESULT_PROTOCOL;
         if (hub->callbacks.resource_delta != NULL)
         {
            hub->callbacks.resource_delta(hub->context, hub, &delta);
         }
         return PRODIGY_RESULT_OK;
      }
      case PRODIGY_CONTAINER_TOPIC_DATACENTER_UNIQUE_TAG:
      {
         uint8_t tag = 0;
         result = prodigy_read_u8(&reader, &tag);
         if (result != PRODIGY_RESULT_OK) return result;
         if (prodigy_reader_remaining(&reader) != 0) return PRODIGY_RESULT_PROTOCOL;
         hub->parameters.datacenter_unique_tag = tag;
         return PRODIGY_RESULT_OK;
      }
      case PRODIGY_CONTAINER_TOPIC_MESSAGE:
      {
         if (hub->callbacks.message_from_prodigy != NULL)
         {
            hub->callbacks.message_from_prodigy(hub->context, hub, payload, payload_size);
         }
         return PRODIGY_RESULT_OK;
      }
      case PRODIGY_CONTAINER_TOPIC_STATISTICS:
      {
         return ((payload_size & 15u) == 0u) ? PRODIGY_RESULT_OK : PRODIGY_RESULT_PROTOCOL;
      }
      case PRODIGY_CONTAINER_TOPIC_RESOURCE_DELTA_ACK:
      {
         uint8_t accepted = 0;
         result = prodigy_read_bool(&reader, &accepted);
         if (result != PRODIGY_RESULT_OK) return result;
         return (prodigy_reader_remaining(&reader) == 0) ? PRODIGY_RESULT_OK : PRODIGY_RESULT_PROTOCOL;
      }
      case PRODIGY_CONTAINER_TOPIC_CREDENTIALS_REFRESH:
      {
         prodigy_credential_delta delta;
         if (payload_size == 0)
         {
            return PRODIGY_RESULT_OK;
         }

         result = prodigy_decode_credential_delta(payload, payload_size, &delta);
         if (result != PRODIGY_RESULT_OK)
         {
            return result;
         }

         if (hub->callbacks.credentials_refresh != NULL)
         {
            hub->callbacks.credentials_refresh(hub->context, hub, &delta);
         }
         prodigy_credential_delta_free(&delta);
         return PRODIGY_RESULT_OK;
      }
      default:
      {
         return PRODIGY_RESULT_PROTOCOL;
      }
   }
}

prodigy_neuron_hub *prodigy_neuron_hub_create(
   const prodigy_neuron_hub_callbacks *callbacks,
   void *context,
   const prodigy_neuron_hub_options *options)
{
   prodigy_neuron_hub *hub = NULL;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (options == NULL || options->abi_version != PRODIGY_NEURON_HUB_ABI_VERSION)
   {
      return NULL;
   }

   hub = (prodigy_neuron_hub *)calloc(1, sizeof(*hub));
   if (hub == NULL)
   {
      return NULL;
   }
   hub->fd = -1;

   hub->context = context;
   hub->preserve_fd = options->preserve_neuron_fd;
   if (callbacks != NULL)
   {
      hub->callbacks = *callbacks;
   }

   result = prodigy_load_container_parameters_from_process(options->argc, options->argv, &hub->parameters);
   if (result != PRODIGY_RESULT_OK)
   {
      prodigy_neuron_hub_destroy(hub);
      return NULL;
   }

   hub->fd = (options->neuron_fd_override >= 0) ? options->neuron_fd_override : hub->parameters.neuron_fd;
   if (hub->fd < 0)
   {
      prodigy_neuron_hub_destroy(hub);
      return NULL;
   }

   return hub;
}

prodigy_neuron_hub *prodigy_neuron_hub_create_from_process(
   const prodigy_neuron_hub_callbacks *callbacks,
   void *context,
   int argc,
   char **argv)
{
   prodigy_neuron_hub_options options;

   memset(&options, 0, sizeof(options));
   options.abi_version = PRODIGY_NEURON_HUB_ABI_VERSION;
   options.argc = argc;
   options.argv = argv;
   options.neuron_fd_override = -1;
   options.preserve_neuron_fd = 0;
   return prodigy_neuron_hub_create(callbacks, context, &options);
}

void prodigy_neuron_hub_destroy(prodigy_neuron_hub *hub)
{
   if (hub == NULL)
   {
      return;
   }

   if (hub->preserve_fd == 0)
   {
      prodigy_close_fd(hub->fd);
   }
   hub->fd = -1;
   prodigy_container_parameters_free(&hub->parameters);
   free(hub);
}

int prodigy_neuron_hub_fd(const prodigy_neuron_hub *hub)
{
   return (hub == NULL) ? -1 : hub->fd;
}

const prodigy_container_parameters *prodigy_neuron_hub_parameters(const prodigy_neuron_hub *hub)
{
   return (hub == NULL) ? NULL : &hub->parameters;
}

prodigy_result prodigy_neuron_hub_run_once(prodigy_neuron_hub *hub)
{
   uint8_t header[8] = {0};
   uint8_t *frame_bytes = NULL;
   uint32_t frame_size = 0;
   uint8_t padding = 0;
   uint8_t header_size = 0;
   size_t payload_and_padding = 0;
   prodigy_message_frame frame;
   prodigy_message_frame automatic_response;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (hub == NULL || hub->fd < 0)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   memset(&frame, 0, sizeof(frame));
   memset(&automatic_response, 0, sizeof(automatic_response));

   result = prodigy_read_exact_fd(hub->fd, header, sizeof(header));
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   frame_size = (uint32_t)header[0]
      | ((uint32_t)header[1] << 8)
      | ((uint32_t)header[2] << 16)
      | ((uint32_t)header[3] << 24);
   padding = header[6];
   header_size = header[7];

   if (header_size != 8u || frame_size < 8u || (frame_size & 15u) != 0u)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   payload_and_padding = (size_t)frame_size - 8u;
   if ((size_t)padding > payload_and_padding || padding > 15u)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   frame_bytes = (uint8_t *)malloc(frame_size);
   if (frame_bytes == NULL)
   {
      return PRODIGY_RESULT_MEMORY;
   }
   memcpy(frame_bytes, header, sizeof(header));

   result = prodigy_read_exact_fd(hub->fd, frame_bytes + 8u, payload_and_padding);
   if (result != PRODIGY_RESULT_OK)
   {
      free(frame_bytes);
      return result;
   }

   result = prodigy_parse_message_frame(frame_bytes, frame_size, &frame);
   free(frame_bytes);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   result = prodigy_neuron_hub_handle_message_frame(hub, &frame, &automatic_response);
   prodigy_message_frame_free(&frame);
   if (result != PRODIGY_RESULT_OK)
   {
      prodigy_message_frame_free(&automatic_response);
      return result;
   }

   if (automatic_response.topic != PRODIGY_CONTAINER_TOPIC_NONE)
   {
      result = prodigy_send_frame(
         hub,
         automatic_response.topic,
         automatic_response.payload.data,
         automatic_response.payload.size);
   }
   prodigy_message_frame_free(&automatic_response);
   return result;
}

prodigy_result prodigy_neuron_hub_run_forever(prodigy_neuron_hub *hub)
{
   prodigy_result result = PRODIGY_RESULT_OK;

   if (hub == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   hub->stop_requested = 0;
   while (hub->stop_requested == 0)
   {
      result = prodigy_neuron_hub_run_once(hub);
      if (result != PRODIGY_RESULT_OK)
      {
         return result;
      }
   }

   return PRODIGY_RESULT_OK;
}

prodigy_result prodigy_neuron_hub_signal_ready(prodigy_neuron_hub *hub)
{
   prodigy_bytes frame;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (hub == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   memset(&frame, 0, sizeof(frame));
   result = prodigy_build_ready_frame(&frame);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   result = prodigy_write_all_fd(hub->fd, frame.data, frame.size);
   prodigy_bytes_free(&frame);
   return result;
}

prodigy_result prodigy_neuron_hub_publish_statistic(
   prodigy_neuron_hub *hub,
   uint64_t metric_key,
   uint64_t metric_value)
{
   prodigy_metric_pair pair;
   pair.key = metric_key;
   pair.value = metric_value;
   return prodigy_neuron_hub_publish_statistics(hub, &pair, 1);
}

prodigy_result prodigy_neuron_hub_publish_statistics(
   prodigy_neuron_hub *hub,
   const prodigy_metric_pair *metrics,
   size_t metric_count)
{
   prodigy_bytes frame;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (hub == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   memset(&frame, 0, sizeof(frame));
   result = prodigy_build_statistics_frame(metrics, metric_count, &frame);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   result = prodigy_write_all_fd(hub->fd, frame.data, frame.size);
   prodigy_bytes_free(&frame);
   return result;
}

prodigy_result prodigy_neuron_hub_acknowledge_resource_delta(
   prodigy_neuron_hub *hub,
   uint8_t accepted)
{
   prodigy_bytes frame;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (hub == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   memset(&frame, 0, sizeof(frame));
   result = prodigy_build_resource_delta_ack_frame(accepted, &frame);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   result = prodigy_write_all_fd(hub->fd, frame.data, frame.size);
   prodigy_bytes_free(&frame);
   return result;
}

prodigy_result prodigy_neuron_hub_acknowledge_credentials_refresh(
   prodigy_neuron_hub *hub)
{
   prodigy_bytes frame;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (hub == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   memset(&frame, 0, sizeof(frame));
   result = prodigy_build_credentials_refresh_ack_frame(&frame);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   result = prodigy_write_all_fd(hub->fd, frame.data, frame.size);
   prodigy_bytes_free(&frame);
   return result;
}
