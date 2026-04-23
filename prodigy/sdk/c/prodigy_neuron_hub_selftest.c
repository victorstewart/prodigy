/* Copyright 2026 Victor Stewart */
/* SPDX-License-Identifier: Apache-2.0 */

#define _POSIX_C_SOURCE 200809L

#include "prodigy_neuron_hub.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef PRODIGY_SDK_FIXTURES_DIR
#define PRODIGY_SDK_FIXTURES_DIR "prodigy/sdk/fixtures"
#endif

typedef struct test_buffer
{
   uint8_t bytes[2048];
   size_t size;
} test_buffer;

typedef struct callback_state
{
   int shutdown_count;
   int resource_delta_count;
   int credential_refresh_count;
   int message_count;
   prodigy_resource_delta last_resource_delta;
   uint64_t last_bundle_generation;
   size_t last_reason_size;
   size_t last_message_size;
} callback_state;

static void fail_message(const char *message)
{
   fprintf(stderr, "%s\n", message);
   exit(1);
}

static void expect_true(int condition, const char *message)
{
   if (!condition)
   {
      fail_message(message);
   }
}

static void expect_bytes_equal(
   const uint8_t *actual,
   size_t actual_size,
   const uint8_t *expected,
   size_t expected_size,
   const char *message)
{
   if (actual_size != expected_size)
   {
      fail_message(message);
   }

   if (actual_size > 0 && memcmp(actual, expected, actual_size) != 0)
   {
      fail_message(message);
   }
}

static uint8_t *read_fixture_file(const char *path, size_t *size)
{
   FILE *input = NULL;
   long file_size = 0;
   uint8_t *buffer = NULL;

   input = fopen(path, "rb");
   if (input == NULL)
   {
      fail_message("failed to open fixture");
   }

   if (fseek(input, 0, SEEK_END) != 0)
   {
      fclose(input);
      fail_message("failed to seek fixture");
   }

   file_size = ftell(input);
   if (file_size < 0)
   {
      fclose(input);
      fail_message("failed to measure fixture");
   }

   if (fseek(input, 0, SEEK_SET) != 0)
   {
      fclose(input);
      fail_message("failed to rewind fixture");
   }

   buffer = (uint8_t *)malloc((size_t)file_size);
   if (buffer == NULL)
   {
      fclose(input);
      fail_message("failed to allocate fixture buffer");
   }

   if ((size_t)file_size > 0 && fread(buffer, 1, (size_t)file_size, input) != (size_t)file_size)
   {
      free(buffer);
      fclose(input);
      fail_message("failed to read fixture");
   }

   fclose(input);
   *size = (size_t)file_size;
   return buffer;
}

static uint8_t *read_fixture_named(const char *name, size_t *size)
{
   char path[512];
   int written = snprintf(path, sizeof(path), "%s/%s", PRODIGY_SDK_FIXTURES_DIR, name);
   if (written <= 0 || (size_t)written >= sizeof(path))
   {
      fail_message("fixture path too long");
   }

   return read_fixture_file(path, size);
}

static void append_u8(test_buffer *buffer, uint8_t value)
{
   buffer->bytes[buffer->size] = value;
   buffer->size += 1;
}

static void append_u16(test_buffer *buffer, uint16_t value)
{
   append_u8(buffer, (uint8_t)(value & 0xffu));
   append_u8(buffer, (uint8_t)((value >> 8) & 0xffu));
}

static void append_u32(test_buffer *buffer, uint32_t value)
{
   append_u8(buffer, (uint8_t)(value & 0xffu));
   append_u8(buffer, (uint8_t)((value >> 8) & 0xffu));
   append_u8(buffer, (uint8_t)((value >> 16) & 0xffu));
   append_u8(buffer, (uint8_t)((value >> 24) & 0xffu));
}

static void append_u64(test_buffer *buffer, uint64_t value)
{
   size_t index = 0;
   for (index = 0; index < 8; index += 1)
   {
      append_u8(buffer, (uint8_t)((value >> (index * 8)) & 0xffu));
   }
}

static void append_i32(test_buffer *buffer, int32_t value)
{
   append_u32(buffer, (uint32_t)value);
}

static void append_bytes(test_buffer *buffer, const uint8_t *bytes, size_t size)
{
   memcpy(buffer->bytes + buffer->size, bytes, size);
   buffer->size += size;
}

static void append_magic(test_buffer *buffer, const char text[8])
{
   append_bytes(buffer, (const uint8_t *)text, 8);
}

static void append_string(test_buffer *buffer, const char *text)
{
   size_t size = strlen(text);
   append_u32(buffer, (uint32_t)size);
   append_bytes(buffer, (const uint8_t *)text, size);
}

static void append_sequence(test_buffer *buffer, uint8_t start)
{
   uint8_t bytes[16];
   size_t index = 0;
   for (index = 0; index < sizeof(bytes); index += 1)
   {
      bytes[index] = (uint8_t)(start + index);
   }

   append_bytes(buffer, bytes, sizeof(bytes));
}

static void append_ip_prefix(test_buffer *buffer, const uint8_t address[16], uint8_t cidr)
{
   append_bytes(buffer, address, 16);
   append_u8(buffer, 1);
   append_u8(buffer, cidr);
}

static void append_frame(test_buffer *buffer, uint16_t topic, const uint8_t *payload, size_t payload_size)
{
   size_t padding = (16u - ((8u + payload_size) & 15u)) & 15u;
   size_t frame_size = 8u + payload_size + padding;

   append_u32(buffer, (uint32_t)frame_size);
   append_u16(buffer, topic);
   append_u8(buffer, (uint8_t)padding);
   append_u8(buffer, 8u);
   if (payload_size > 0)
   {
      append_bytes(buffer, payload, payload_size);
   }

   while ((buffer->size & 15u) != 0u)
   {
      append_u8(buffer, 0);
   }
}

static void begin_shutdown(void *context, prodigy_neuron_hub *hub)
{
   callback_state *state = (callback_state *)context;
   (void)hub;
   state->shutdown_count += 1;
}

static void resource_delta(
   void *context,
   prodigy_neuron_hub *hub,
   const prodigy_resource_delta *delta)
{
   callback_state *state = (callback_state *)context;
   (void)hub;
   state->resource_delta_count += 1;
   state->last_resource_delta = *delta;
}

static void credentials_refresh(
   void *context,
   prodigy_neuron_hub *hub,
   const prodigy_credential_delta *delta)
{
   callback_state *state = (callback_state *)context;
   (void)hub;
   state->credential_refresh_count += 1;
   state->last_bundle_generation = delta->bundle_generation;
   state->last_reason_size = delta->reason.size;
}

static void message_from_prodigy(
   void *context,
   prodigy_neuron_hub *hub,
   const uint8_t *payload,
   size_t payload_size)
{
   callback_state *state = (callback_state *)context;
   (void)hub;
   (void)payload;
   state->message_count += 1;
   state->last_message_size = payload_size;
}

static void write_all(int fd, const uint8_t *bytes, size_t size)
{
   size_t offset = 0;
   while (offset < size)
   {
      ssize_t written = write(fd, bytes + offset, size - offset);
      if (written <= 0)
      {
         fail_message("write failed");
      }

      offset += (size_t)written;
   }
}

static void read_all(int fd, uint8_t *bytes, size_t size)
{
   size_t offset = 0;
   while (offset < size)
   {
      ssize_t received = read(fd, bytes + offset, size - offset);
      if (received <= 0)
      {
         fail_message("read failed");
      }

      offset += (size_t)received;
   }
}

static void read_and_expect_topic(int fd, uint16_t expected_topic, uint8_t expected_first_payload, int expect_payload)
{
   uint8_t header[8];
   uint8_t payload[32];
   uint32_t frame_size = 0;
   size_t payload_and_padding = 0;
   size_t payload_size = 0;

   read_all(fd, header, sizeof(header));
   frame_size = (uint32_t)header[0]
      | ((uint32_t)header[1] << 8)
      | ((uint32_t)header[2] << 16)
      | ((uint32_t)header[3] << 24);
   expect_true(frame_size >= 8u, "frame size too small");
   expect_true((uint16_t)(header[4] | ((uint16_t)header[5] << 8)) == expected_topic, "unexpected topic");
   expect_true(header[7] == 8u, "unexpected header size");
   payload_and_padding = (size_t)frame_size - 8u;
   expect_true(payload_and_padding <= sizeof(payload), "frame too large for test buffer");
   read_all(fd, payload, payload_and_padding);
   payload_size = payload_and_padding - header[6];
   if (expect_payload)
   {
      expect_true(payload_size > 0, "missing payload");
      expect_true(payload[0] == expected_first_payload, "unexpected payload byte");
   }
   else
   {
      expect_true(payload_size == 0, "unexpected payload");
   }
}

int main(void)
{
   static const uint8_t private6[16] = {0xfdu};
   static const uint8_t message_payload[5] = {'h', 'e', 'l', 'l', 'o'};
   static const uint8_t aegis_secret[16] = {
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
   };
   static const uint8_t aegis_address[16] = {
      0xfd, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
   };
   static const uint8_t aegis_nonce[16] = {
      0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
      0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
   };
   static const uint8_t aegis_plaintext[] = {'f', 'r', 'a', 'm', 'e', '-', 'o', 'n', 'e'};
   static const uint8_t aegis_aux[] = {'m', 'e', 's', 'h', '-', 'a', 'e', 'g', 'i', 's'};
   uint8_t *fixture_bundle = NULL;
   uint8_t *fixture_parameters = NULL;
   uint8_t *fixture_delta = NULL;
   uint8_t *fixture_ping = NULL;
   uint8_t *fixture_ready = NULL;
   uint8_t *fixture_statistics = NULL;
   uint8_t *fixture_resource_delta_ack = NULL;
   uint8_t *fixture_credentials_refresh_ack = NULL;
   uint8_t *fixture_aegis_hash = NULL;
   uint8_t *fixture_aegis_tfo = NULL;
   uint8_t *fixture_aegis_frame = NULL;
   size_t fixture_bundle_size = 0;
   size_t fixture_parameters_size = 0;
   size_t fixture_delta_size = 0;
   size_t fixture_ping_size = 0;
   size_t fixture_ready_size = 0;
   size_t fixture_statistics_size = 0;
   size_t fixture_resource_delta_ack_size = 0;
   size_t fixture_credentials_refresh_ack_size = 0;
   size_t fixture_aegis_hash_size = 0;
   size_t fixture_aegis_tfo_size = 0;
   size_t fixture_aegis_frame_size = 0;

   char fd_text[32];
   char *argv[] = {(char *)"selftest", NULL};
   int bootstrap_pipe[2] = {-1, -1};
   int sockets[2] = {-1, -1};
   test_buffer bootstrap = {{0}, 0};
   test_buffer credential_delta = {{0}, 0};
   test_buffer frame = {{0}, 0};
   callback_state state;
   prodigy_neuron_hub_callbacks callbacks;
   prodigy_neuron_hub_options options;
   prodigy_neuron_hub *hub = NULL;
   prodigy_credential_bundle bundle;
   prodigy_container_parameters decoded;
   prodigy_credential_delta delta;
   prodigy_bytes ping_bytes;
   prodigy_bytes ready_bytes;
   prodigy_bytes statistics_bytes;
   prodigy_bytes resource_delta_ack_bytes;
   prodigy_bytes credentials_refresh_ack_bytes;
   prodigy_frame_decoder decoder;
   prodigy_message_frame decoded_ping;
   prodigy_message_frame built_frame;
   prodigy_message_frame automatic_response;
   prodigy_subscription_pairing aegis_pairing;
   prodigy_aegis_session aegis_session;
   prodigy_u128 nonce;
   prodigy_bytes tfo_data;
   prodigy_bytes encrypted_frame;
   prodigy_bytes decrypted_plaintext;
   prodigy_aegis_frame_header aegis_header;
   uint64_t pairing_hash = 0;

   memset(&state, 0, sizeof(state));
   memset(&callbacks, 0, sizeof(callbacks));
   memset(&options, 0, sizeof(options));
   memset(&bundle, 0, sizeof(bundle));
   memset(&decoded, 0, sizeof(decoded));
   memset(&delta, 0, sizeof(delta));
   memset(&ping_bytes, 0, sizeof(ping_bytes));
   memset(&ready_bytes, 0, sizeof(ready_bytes));
   memset(&statistics_bytes, 0, sizeof(statistics_bytes));
   memset(&resource_delta_ack_bytes, 0, sizeof(resource_delta_ack_bytes));
   memset(&credentials_refresh_ack_bytes, 0, sizeof(credentials_refresh_ack_bytes));
   memset(&decoder, 0, sizeof(decoder));
   memset(&decoded_ping, 0, sizeof(decoded_ping));
   memset(&built_frame, 0, sizeof(built_frame));
   memset(&automatic_response, 0, sizeof(automatic_response));
   memset(&aegis_pairing, 0, sizeof(aegis_pairing));
   memset(&tfo_data, 0, sizeof(tfo_data));
   memset(&encrypted_frame, 0, sizeof(encrypted_frame));
   memset(&decrypted_plaintext, 0, sizeof(decrypted_plaintext));
   memset(&aegis_header, 0, sizeof(aegis_header));

   fixture_bundle = read_fixture_named("startup.credential_bundle.full.bin", &fixture_bundle_size);
   fixture_parameters = read_fixture_named("startup.container_parameters.full.bin", &fixture_parameters_size);
   fixture_delta = read_fixture_named("startup.credential_delta.full.bin", &fixture_delta_size);
   fixture_ping = read_fixture_named("frame.ping.empty.bin", &fixture_ping_size);
   fixture_ready = read_fixture_named("frame.healthy.empty.bin", &fixture_ready_size);
   fixture_statistics = read_fixture_named("frame.statistics.demo.bin", &fixture_statistics_size);
   fixture_resource_delta_ack = read_fixture_named("frame.resource_delta_ack.accepted.bin", &fixture_resource_delta_ack_size);
   fixture_credentials_refresh_ack = read_fixture_named("frame.credentials_refresh_ack.empty.bin", &fixture_credentials_refresh_ack_size);
   fixture_aegis_hash = read_fixture_named("aegis.hash.demo.bin", &fixture_aegis_hash_size);
   fixture_aegis_tfo = read_fixture_named("aegis.tfo.demo.bin", &fixture_aegis_tfo_size);
   fixture_aegis_frame = read_fixture_named("aegis.frame.demo.bin", &fixture_aegis_frame_size);

   expect_true(
      prodigy_decode_credential_bundle(
         fixture_bundle,
         fixture_bundle_size,
         &bundle) == PRODIGY_RESULT_OK,
      "credential bundle fixture decode failed");
   expect_true(bundle.bundle_generation == 101u, "unexpected fixture bundle generation");
   expect_true(bundle.tls_identity_count == 1u, "unexpected fixture tls identity count");
   expect_true(bundle.api_credential_count == 1u, "unexpected fixture api credential count");
   prodigy_credential_bundle_free(&bundle);

   append_magic(&credential_delta, "PRDDEL01");
   append_u64(&credential_delta, 7);
   append_u32(&credential_delta, 0);
   append_u32(&credential_delta, 1);
   append_string(&credential_delta, "old-cert");
   append_u32(&credential_delta, 0);
   append_u32(&credential_delta, 1);
   append_string(&credential_delta, "old-token");
   append_string(&credential_delta, "rotation");

   expect_true(
      prodigy_decode_credential_delta(
         credential_delta.bytes,
         credential_delta.size,
         &delta) == PRODIGY_RESULT_OK,
      "credential delta decode failed");
   expect_true(delta.bundle_generation == 7, "unexpected delta bundle generation");
   expect_true(delta.removed_tls_name_count == 1, "unexpected tls removal count");
   expect_true(delta.removed_api_name_count == 1, "unexpected api removal count");
   prodigy_credential_delta_free(&delta);

   append_magic(&bootstrap, "PRDPAR01");
   append_sequence(&bootstrap, 0);
   append_u32(&bootstrap, 1024);
   append_u32(&bootstrap, 2048);
   append_u16(&bootstrap, 3);
   append_i32(&bootstrap, 9);
   append_i32(&bootstrap, 1);
   append_i32(&bootstrap, 3);
   append_u32(&bootstrap, 1);
   append_u64(&bootstrap, 0x1122334455667788ULL);
   append_u16(&bootstrap, 19111);
   append_u32(&bootstrap, 1);
   append_sequence(&bootstrap, 16);
   append_sequence(&bootstrap, 32);
   append_u64(&bootstrap, 0x1234000000000001ULL);
   append_u16(&bootstrap, 3210);
   append_u32(&bootstrap, 1);
   append_sequence(&bootstrap, 48);
   append_sequence(&bootstrap, 64);
   append_u64(&bootstrap, 0x5678000000000002ULL);
   append_ip_prefix(&bootstrap, private6, 64);
   append_u8(&bootstrap, 0);
   append_u8(&bootstrap, 17);
   append_u32(&bootstrap, 2);
   append_u64(&bootstrap, 44);
   append_u64(&bootstrap, 55);
   append_u8(&bootstrap, 0);

   expect_true(
      prodigy_decode_container_parameters(
         bootstrap.bytes,
         bootstrap.size,
         &decoded) == PRODIGY_RESULT_OK,
      "container parameters decode failed");
   expect_true(decoded.memory_mb == 1024, "unexpected memory");
   expect_true(decoded.subscription_pairings[0].application_id == 0x1234u, "unexpected subscription application id");
   expect_true(decoded.advertisement_pairings[0].application_id == 0x5678u, "unexpected advertisement application id");
   prodigy_container_parameters_free(&decoded);

   expect_true(
      prodigy_decode_container_parameters(
         fixture_parameters,
         fixture_parameters_size,
         &decoded) == PRODIGY_RESULT_OK,
      "container parameters fixture decode failed");
   expect_true(decoded.memory_mb == 1536u, "unexpected fixture memory");
   expect_true(decoded.subscription_pairings[0].application_id == 0x2233u, "unexpected fixture subscription application id");
   expect_true(decoded.advertisement_pairings[0].application_id == 0x3344u, "unexpected fixture advertisement application id");
   expect_true(decoded.datacenter_unique_tag == 23u, "unexpected fixture datacenter tag");
   expect_true(decoded.has_credential_bundle == 1u, "missing fixture credential bundle");
   expect_true(decoded.credential_bundle.bundle_generation == 101u, "unexpected embedded fixture bundle generation");
   prodigy_container_parameters_free(&decoded);

   expect_true(
      prodigy_decode_credential_delta(
         fixture_delta,
         fixture_delta_size,
         &delta) == PRODIGY_RESULT_OK,
      "credential delta fixture decode failed");
   expect_true(delta.bundle_generation == 102u, "unexpected fixture delta bundle generation");
   expect_true(delta.removed_tls_name_count == 1u, "unexpected fixture tls removal count");
   expect_true(delta.removed_api_name_count == 1u, "unexpected fixture api removal count");
   expect_true(delta.reason.size == 16u, "unexpected fixture reason size");
   prodigy_credential_delta_free(&delta);

   memcpy(aegis_pairing.secret.bytes, aegis_secret, sizeof(aegis_secret));
   memcpy(aegis_pairing.address.bytes, aegis_address, sizeof(aegis_address));
   aegis_pairing.service = 0x2233000000001001ULL;
   aegis_pairing.port = 3210u;
   aegis_pairing.application_id = 0x2233u;
   aegis_pairing.activate = 1u;
   aegis_session = prodigy_aegis_session_from_subscription(&aegis_pairing);

   pairing_hash = prodigy_aegis_pairing_hash(&aegis_session);
   append_u64(&frame, pairing_hash);
   expect_true(fixture_aegis_hash_size == sizeof(pairing_hash), "unexpected aegis hash fixture size");
   expect_bytes_equal(
      frame.bytes,
      sizeof(pairing_hash),
      fixture_aegis_hash,
      fixture_aegis_hash_size,
      "aegis pairing hash mismatch");
   frame.size = 0;

   expect_true(
      prodigy_aegis_build_tfo_data(&aegis_session, aegis_aux, sizeof(aegis_aux), &tfo_data) == PRODIGY_RESULT_OK,
      "aegis tfo build failed");
   expect_bytes_equal(
      tfo_data.data,
      tfo_data.size,
      fixture_aegis_tfo,
      fixture_aegis_tfo_size,
      "aegis tfo mismatch");
   prodigy_bytes_free(&tfo_data);

   memcpy(nonce.bytes, aegis_nonce, sizeof(aegis_nonce));
   expect_true(
      prodigy_aegis_encrypt_with_nonce(
         &aegis_session,
         aegis_plaintext,
         sizeof(aegis_plaintext),
         &nonce,
         &encrypted_frame) == PRODIGY_RESULT_OK,
      "aegis encrypt failed");
   expect_bytes_equal(
      encrypted_frame.data,
      encrypted_frame.size,
      fixture_aegis_frame,
      fixture_aegis_frame_size,
      "aegis frame mismatch");

   expect_true(
      prodigy_aegis_decrypt(
         &aegis_session,
         fixture_aegis_frame,
         fixture_aegis_frame_size,
         &decrypted_plaintext,
         &aegis_header) == PRODIGY_RESULT_OK,
      "aegis decrypt failed");
   expect_bytes_equal(
      decrypted_plaintext.data,
      decrypted_plaintext.size,
      aegis_plaintext,
      sizeof(aegis_plaintext),
      "aegis plaintext mismatch");
   expect_true(aegis_header.size == fixture_aegis_frame_size, "unexpected aegis frame size");
   expect_true(aegis_header.encrypted_data_size == sizeof(aegis_plaintext) + PRODIGY_AEGIS_TAG_BYTES, "unexpected aegis encrypted payload size");
   prodigy_bytes_free(&encrypted_frame);
   prodigy_bytes_free(&decrypted_plaintext);

   expect_true(pipe(bootstrap_pipe) == 0, "pipe failed");
   expect_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0, "socketpair failed");

   write_all(bootstrap_pipe[1], fixture_parameters, fixture_parameters_size);
   expect_true(close(bootstrap_pipe[1]) == 0, "close bootstrap writer failed");
   bootstrap_pipe[1] = -1;

   snprintf(fd_text, sizeof(fd_text), "%d", bootstrap_pipe[0]);
   expect_true(setenv("PRODIGY_PARAMS_FD", fd_text, 1) == 0, "setenv failed");

   callbacks.begin_shutdown = begin_shutdown;
   callbacks.resource_delta = resource_delta;
   callbacks.credentials_refresh = credentials_refresh;
   callbacks.message_from_prodigy = message_from_prodigy;

   options.abi_version = PRODIGY_NEURON_HUB_ABI_VERSION;
   options.argc = 1;
   options.argv = argv;
   options.neuron_fd_override = sockets[0];
   options.preserve_neuron_fd = 1;

   hub = prodigy_neuron_hub_create(&callbacks, &state, &options);
   expect_true(hub != NULL, "hub creation failed");
   expect_true(unsetenv("PRODIGY_PARAMS_FD") == 0, "unsetenv failed");

   expect_true(
      prodigy_build_message_frame(
         PRODIGY_CONTAINER_TOPIC_PING,
         NULL,
         0,
         &ping_bytes) == PRODIGY_RESULT_OK,
      "build ping frame failed");
   expect_bytes_equal(
      ping_bytes.data,
      ping_bytes.size,
      fixture_ping,
      fixture_ping_size,
      "built ping frame fixture mismatch");
   prodigy_frame_decoder_init(&decoder);
   expect_true(
      prodigy_frame_decoder_feed(&decoder, ping_bytes.data, 5u) == PRODIGY_RESULT_OK,
      "feed partial ping failed");
   expect_true(
      prodigy_frame_decoder_next(&decoder, &decoded_ping) == PRODIGY_RESULT_AGAIN,
      "partial ping should not produce a frame");
   expect_true(
      prodigy_frame_decoder_feed(
         &decoder,
         ping_bytes.data + 5u,
         ping_bytes.size - 5u) == PRODIGY_RESULT_OK,
      "feed final ping failed");
   expect_true(
      prodigy_frame_decoder_next(&decoder, &decoded_ping) == PRODIGY_RESULT_OK,
      "final ping should produce a frame");
   expect_true(
      prodigy_neuron_hub_handle_message_frame(hub, &decoded_ping, &automatic_response) == PRODIGY_RESULT_OK,
      "handle message frame failed");
   expect_true(automatic_response.topic == PRODIGY_CONTAINER_TOPIC_PING, "unexpected automatic ping response topic");
   expect_true(automatic_response.payload.size == 0u, "automatic ping response payload should be empty");
   prodigy_message_frame_free(&decoded_ping);
   prodigy_message_frame_free(&automatic_response);
   prodigy_frame_decoder_free(&decoder);
   prodigy_bytes_free(&ping_bytes);

   expect_true(prodigy_build_ready_frame(&ready_bytes) == PRODIGY_RESULT_OK, "build ready frame failed");
   expect_bytes_equal(
      ready_bytes.data,
      ready_bytes.size,
      fixture_ready,
      fixture_ready_size,
      "built ready frame fixture mismatch");
   expect_true(
      prodigy_parse_message_frame(ready_bytes.data, ready_bytes.size, &built_frame) == PRODIGY_RESULT_OK,
      "parse ready frame failed");
   expect_true(built_frame.topic == PRODIGY_CONTAINER_TOPIC_HEALTHY, "unexpected ready frame topic");
   expect_true(built_frame.payload.size == 0u, "ready frame should have empty payload");
   prodigy_message_frame_free(&built_frame);
   prodigy_bytes_free(&ready_bytes);

   {
      static const prodigy_metric_pair demo_metrics[2] = {
         {1u, 2u},
         {3u, 4u},
      };
      expect_true(
         prodigy_build_statistics_frame(demo_metrics, 2u, &statistics_bytes) == PRODIGY_RESULT_OK,
         "build statistics frame failed");
   }
   expect_bytes_equal(
      statistics_bytes.data,
      statistics_bytes.size,
      fixture_statistics,
      fixture_statistics_size,
      "built statistics frame fixture mismatch");
   expect_true(
      prodigy_parse_message_frame(statistics_bytes.data, statistics_bytes.size, &built_frame) == PRODIGY_RESULT_OK,
      "parse statistics frame failed");
   expect_true(built_frame.topic == PRODIGY_CONTAINER_TOPIC_STATISTICS, "unexpected statistics frame topic");
   expect_true(built_frame.payload.size == 32u, "statistics frame payload should be 32 bytes");
   expect_true(built_frame.payload.data[0] == 1u, "unexpected first statistics key byte");
   expect_true(built_frame.payload.data[8] == 2u, "unexpected first statistics value byte");
   expect_true(built_frame.payload.data[16] == 3u, "unexpected second statistics key byte");
   expect_true(built_frame.payload.data[24] == 4u, "unexpected second statistics value byte");
   prodigy_message_frame_free(&built_frame);
   prodigy_bytes_free(&statistics_bytes);

   expect_true(
      prodigy_build_resource_delta_ack_frame(1u, &resource_delta_ack_bytes) == PRODIGY_RESULT_OK,
      "build resource delta ack frame failed");
   expect_bytes_equal(
      resource_delta_ack_bytes.data,
      resource_delta_ack_bytes.size,
      fixture_resource_delta_ack,
      fixture_resource_delta_ack_size,
      "built resource delta ack frame fixture mismatch");
   expect_true(
      prodigy_parse_message_frame(
         resource_delta_ack_bytes.data,
         resource_delta_ack_bytes.size,
         &built_frame) == PRODIGY_RESULT_OK,
      "parse resource delta ack frame failed");
   expect_true(
      built_frame.topic == PRODIGY_CONTAINER_TOPIC_RESOURCE_DELTA_ACK,
      "unexpected resource delta ack frame topic");
   expect_true(built_frame.payload.size == 1u, "resource delta ack payload should be one byte");
   expect_true(built_frame.payload.data[0] == 1u, "resource delta ack payload should accept");
   prodigy_message_frame_free(&built_frame);
   prodigy_bytes_free(&resource_delta_ack_bytes);

   expect_true(
      prodigy_build_credentials_refresh_ack_frame(&credentials_refresh_ack_bytes) == PRODIGY_RESULT_OK,
      "build credentials refresh ack frame failed");
   expect_bytes_equal(
      credentials_refresh_ack_bytes.data,
      credentials_refresh_ack_bytes.size,
      fixture_credentials_refresh_ack,
      fixture_credentials_refresh_ack_size,
      "built credentials refresh ack frame fixture mismatch");
   expect_true(
      prodigy_parse_message_frame(
         credentials_refresh_ack_bytes.data,
         credentials_refresh_ack_bytes.size,
         &built_frame) == PRODIGY_RESULT_OK,
      "parse credentials refresh ack frame failed");
   expect_true(
      built_frame.topic == PRODIGY_CONTAINER_TOPIC_CREDENTIALS_REFRESH,
      "unexpected credentials refresh ack frame topic");
   expect_true(built_frame.payload.size == 0u, "credentials refresh ack payload should be empty");
   prodigy_message_frame_free(&built_frame);
   prodigy_bytes_free(&credentials_refresh_ack_bytes);

   frame.size = 0;
   append_frame(&frame, PRODIGY_CONTAINER_TOPIC_PING, NULL, 0);
   write_all(sockets[1], frame.bytes, frame.size);
   expect_true(prodigy_neuron_hub_run_once(hub) == PRODIGY_RESULT_OK, "ping run_once failed");
   read_and_expect_topic(sockets[1], PRODIGY_CONTAINER_TOPIC_PING, 0, 0);

   frame.size = 0;
   append_u8(&frame, 44);
   {
      test_buffer tag_frame = {{0}, 0};
      append_frame(&tag_frame, PRODIGY_CONTAINER_TOPIC_DATACENTER_UNIQUE_TAG, frame.bytes, frame.size);
      write_all(sockets[1], tag_frame.bytes, tag_frame.size);
   }
   expect_true(prodigy_neuron_hub_run_once(hub) == PRODIGY_RESULT_OK, "tag run_once failed");
   expect_true(prodigy_neuron_hub_parameters(hub)->datacenter_unique_tag == 44, "tag not updated");

   frame.size = 0;
   append_u16(&frame, 5);
   append_u32(&frame, 1536);
   append_u32(&frame, 4096);
   append_u8(&frame, 1);
   append_u32(&frame, 22);
   {
      test_buffer delta_frame = {{0}, 0};
      append_frame(&delta_frame, PRODIGY_CONTAINER_TOPIC_RESOURCE_DELTA, frame.bytes, frame.size);
      write_all(sockets[1], delta_frame.bytes, delta_frame.size);
   }
   expect_true(prodigy_neuron_hub_run_once(hub) == PRODIGY_RESULT_OK, "resource delta run_once failed");
   expect_true(state.resource_delta_count == 1, "resource delta callback missing");
   expect_true(state.last_resource_delta.logical_cores == 5, "unexpected logical cores");
   expect_true(state.last_resource_delta.is_downscale == 1, "unexpected downscale bit");

   frame.size = 0;
   append_frame(&frame, PRODIGY_CONTAINER_TOPIC_MESSAGE, message_payload, sizeof(message_payload));
   write_all(sockets[1], frame.bytes, frame.size);
   expect_true(prodigy_neuron_hub_run_once(hub) == PRODIGY_RESULT_OK, "message run_once failed");
   expect_true(state.message_count == 1, "message callback missing");
   expect_true(state.last_message_size == sizeof(message_payload), "unexpected message size");

   frame.size = 0;
   append_frame(&frame, PRODIGY_CONTAINER_TOPIC_CREDENTIALS_REFRESH, credential_delta.bytes, credential_delta.size);
   write_all(sockets[1], frame.bytes, frame.size);
   expect_true(prodigy_neuron_hub_run_once(hub) == PRODIGY_RESULT_OK, "credential refresh run_once failed");
   expect_true(state.credential_refresh_count == 1, "credential refresh callback missing");
   expect_true(state.last_bundle_generation == 7, "unexpected callback bundle generation");
   expect_true(state.last_reason_size == 8, "unexpected callback reason size");

   expect_true(prodigy_neuron_hub_signal_ready(hub) == PRODIGY_RESULT_OK, "signal_ready failed");
   read_and_expect_topic(sockets[1], PRODIGY_CONTAINER_TOPIC_HEALTHY, 0, 0);

   expect_true(prodigy_neuron_hub_publish_statistic(hub, 1, 2) == PRODIGY_RESULT_OK, "publish_statistic failed");
   read_and_expect_topic(sockets[1], PRODIGY_CONTAINER_TOPIC_STATISTICS, 1, 1);

   expect_true(prodigy_neuron_hub_acknowledge_resource_delta(hub, 1) == PRODIGY_RESULT_OK, "resource delta ack failed");
   read_and_expect_topic(sockets[1], PRODIGY_CONTAINER_TOPIC_RESOURCE_DELTA_ACK, 1, 1);

   expect_true(prodigy_neuron_hub_acknowledge_credentials_refresh(hub) == PRODIGY_RESULT_OK, "credentials refresh ack failed");
   read_and_expect_topic(sockets[1], PRODIGY_CONTAINER_TOPIC_CREDENTIALS_REFRESH, 0, 0);

   frame.size = 0;
   append_frame(&frame, PRODIGY_CONTAINER_TOPIC_STOP, NULL, 0);
   write_all(sockets[1], frame.bytes, frame.size);
   expect_true(prodigy_neuron_hub_run_once(hub) == PRODIGY_RESULT_OK, "stop run_once failed");
   expect_true(state.shutdown_count == 1, "shutdown callback missing");

   prodigy_neuron_hub_destroy(hub);
   hub = NULL;
   expect_true(close(sockets[0]) == 0, "close preserved hub socket failed");
   sockets[0] = -1;
   expect_true(close(sockets[1]) == 0, "close peer socket failed");
   sockets[1] = -1;
   free(fixture_bundle);
   free(fixture_parameters);
   free(fixture_delta);
   free(fixture_ping);
   free(fixture_ready);
   free(fixture_statistics);
   free(fixture_resource_delta_ack);
   free(fixture_credentials_refresh_ack);
   free(fixture_aegis_hash);
   free(fixture_aegis_tfo);
   free(fixture_aegis_frame);
   puts("c neuron_hub self-test passed");
   return 0;
}
