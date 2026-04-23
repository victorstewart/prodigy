/* Copyright 2026 Victor Stewart */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PRODIGY_NEURON_HUB_H
#define PRODIGY_NEURON_HUB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PRODIGY_NEURON_HUB_SDK_VERSION_MAJOR 1u
#define PRODIGY_NEURON_HUB_SDK_VERSION_MINOR 0u
#define PRODIGY_NEURON_HUB_SDK_VERSION_PATCH 0u
#define PRODIGY_NEURON_HUB_SDK_VERSION_STRING "1.0.0"
#define PRODIGY_NEURON_HUB_WIRE_SERIES "WIRE_V1"
#define PRODIGY_NEURON_HUB_WIRE_PROTOCOL_VERSION 1u
#define PRODIGY_NEURON_HUB_ABI_VERSION 2u
#define PRODIGY_AEGIS_ALIGNMENT 16u
#define PRODIGY_AEGIS_HEADER_BYTES 24u
#define PRODIGY_AEGIS_MAX_FRAME_BYTES (2u * 1024u * 1024u)
#define PRODIGY_AEGIS_MIN_FRAME_BYTES 48u
#define PRODIGY_AEGIS_NONCE_BYTES 16u
#define PRODIGY_AEGIS_PAIRING_HASH_SEED INT64_C(0x4d595df4d0f33173)
#define PRODIGY_AEGIS_TAG_BYTES 16u

typedef enum prodigy_result
{
   PRODIGY_RESULT_AGAIN = 1,
   PRODIGY_RESULT_OK = 0,
   PRODIGY_RESULT_EOF = -1,
   PRODIGY_RESULT_IO = -2,
   PRODIGY_RESULT_PROTOCOL = -3,
   PRODIGY_RESULT_ARGUMENT = -4,
   PRODIGY_RESULT_MEMORY = -5
} prodigy_result;

typedef enum prodigy_container_topic
{
   PRODIGY_CONTAINER_TOPIC_NONE = 0,
   PRODIGY_CONTAINER_TOPIC_PING = 1,
   PRODIGY_CONTAINER_TOPIC_PONG = 2,
   PRODIGY_CONTAINER_TOPIC_STOP = 3,
   PRODIGY_CONTAINER_TOPIC_ADVERTISEMENT_PAIRING = 4,
   PRODIGY_CONTAINER_TOPIC_SUBSCRIPTION_PAIRING = 5,
   PRODIGY_CONTAINER_TOPIC_HEALTHY = 6,
   PRODIGY_CONTAINER_TOPIC_MESSAGE = 7,
   PRODIGY_CONTAINER_TOPIC_RESOURCE_DELTA = 8,
   PRODIGY_CONTAINER_TOPIC_DATACENTER_UNIQUE_TAG = 9,
   PRODIGY_CONTAINER_TOPIC_STATISTICS = 10,
   PRODIGY_CONTAINER_TOPIC_RESOURCE_DELTA_ACK = 11,
   PRODIGY_CONTAINER_TOPIC_CREDENTIALS_REFRESH = 12
} prodigy_container_topic;

typedef struct prodigy_neuron_hub prodigy_neuron_hub;

typedef struct prodigy_u128
{
   uint8_t bytes[16];
} prodigy_u128;

typedef struct prodigy_bytes
{
   uint8_t *data;
   size_t size;
} prodigy_bytes;

typedef struct prodigy_message_frame
{
   prodigy_container_topic topic;
   prodigy_bytes payload;
} prodigy_message_frame;

typedef struct prodigy_frame_decoder
{
   uint8_t *data;
   size_t size;
   size_t capacity;
} prodigy_frame_decoder;

typedef struct prodigy_ip_address
{
   uint8_t bytes[16];
   uint8_t is_ipv6;
} prodigy_ip_address;

typedef struct prodigy_ip_prefix
{
   prodigy_ip_address address;
   uint8_t cidr;
} prodigy_ip_prefix;

typedef struct prodigy_string_pair
{
   prodigy_bytes key;
   prodigy_bytes value;
} prodigy_string_pair;

typedef struct prodigy_advertised_port
{
   uint64_t service;
   uint16_t port;
} prodigy_advertised_port;

typedef struct prodigy_advertisement_pairing
{
   prodigy_u128 secret;
   prodigy_u128 address;
   uint64_t service;
   uint16_t application_id;
   uint8_t activate;
} prodigy_advertisement_pairing;

typedef struct prodigy_subscription_pairing
{
   prodigy_u128 secret;
   prodigy_u128 address;
   uint64_t service;
   uint16_t port;
   uint16_t application_id;
   uint8_t activate;
} prodigy_subscription_pairing;

typedef enum prodigy_service_role
{
   PRODIGY_SERVICE_ROLE_NONE = 0,
   PRODIGY_SERVICE_ROLE_ADVERTISER = 1,
   PRODIGY_SERVICE_ROLE_SUBSCRIBER = 2
} prodigy_service_role;

typedef struct prodigy_aegis_frame_header
{
   uint32_t size;
   prodigy_u128 nonce;
   uint32_t encrypted_data_size;
} prodigy_aegis_frame_header;

typedef struct prodigy_aegis_session
{
   prodigy_u128 secret;
   uint64_t service;
   prodigy_service_role role;
} prodigy_aegis_session;

typedef struct prodigy_resource_delta
{
   uint16_t logical_cores;
   uint32_t memory_mb;
   uint32_t storage_mb;
   uint8_t is_downscale;
   uint32_t grace_seconds;
} prodigy_resource_delta;

typedef struct prodigy_metric_pair
{
   uint64_t key;
   uint64_t value;
} prodigy_metric_pair;

typedef struct prodigy_tls_identity
{
   prodigy_bytes name;
   uint64_t generation;
   int64_t not_before_ms;
   int64_t not_after_ms;
   prodigy_bytes cert_pem;
   prodigy_bytes key_pem;
   prodigy_bytes chain_pem;
   prodigy_bytes *dns_sans;
   size_t dns_san_count;
   prodigy_ip_address *ip_sans;
   size_t ip_san_count;
   prodigy_bytes *tags;
   size_t tag_count;
} prodigy_tls_identity;

typedef struct prodigy_api_credential
{
   prodigy_bytes name;
   prodigy_bytes provider;
   uint64_t generation;
   int64_t expires_at_ms;
   int64_t active_from_ms;
   int64_t sunset_at_ms;
   prodigy_bytes material;
   prodigy_string_pair *metadata;
   size_t metadata_count;
} prodigy_api_credential;

typedef struct prodigy_credential_bundle
{
   prodigy_tls_identity *tls_identities;
   size_t tls_identity_count;
   prodigy_api_credential *api_credentials;
   size_t api_credential_count;
   uint64_t bundle_generation;
} prodigy_credential_bundle;

typedef struct prodigy_credential_delta
{
   uint64_t bundle_generation;
   prodigy_tls_identity *updated_tls;
   size_t updated_tls_count;
   prodigy_bytes *removed_tls_names;
   size_t removed_tls_name_count;
   prodigy_api_credential *updated_api;
   size_t updated_api_count;
   prodigy_bytes *removed_api_names;
   size_t removed_api_name_count;
   prodigy_bytes reason;
} prodigy_credential_delta;

typedef struct prodigy_container_parameters
{
   prodigy_u128 uuid;
   uint32_t memory_mb;
   uint32_t storage_mb;
   uint16_t logical_cores;
   int32_t neuron_fd;
   int32_t low_cpu;
   int32_t high_cpu;
   prodigy_advertised_port *advertises;
   size_t advertise_count;
   prodigy_subscription_pairing *subscription_pairings;
   size_t subscription_pairing_count;
   prodigy_advertisement_pairing *advertisement_pairings;
   size_t advertisement_pairing_count;
   prodigy_ip_prefix private6;
   uint8_t just_crashed;
   uint8_t datacenter_unique_tag;
   uint64_t *flags;
   size_t flag_count;
   uint8_t has_credential_bundle;
   prodigy_credential_bundle credential_bundle;
} prodigy_container_parameters;

typedef struct prodigy_neuron_hub_callbacks
{
   void (*end_of_dynamic_args)(void *context, prodigy_neuron_hub *hub);
   void (*begin_shutdown)(void *context, prodigy_neuron_hub *hub);
   void (*advertisement_pairing)(
      void *context,
      prodigy_neuron_hub *hub,
      const prodigy_advertisement_pairing *pairing);
   void (*subscription_pairing)(
      void *context,
      prodigy_neuron_hub *hub,
      const prodigy_subscription_pairing *pairing);
   void (*resource_delta)(
      void *context,
      prodigy_neuron_hub *hub,
      const prodigy_resource_delta *delta);
   void (*credentials_refresh)(
      void *context,
      prodigy_neuron_hub *hub,
      const prodigy_credential_delta *delta);
   void (*message_from_prodigy)(
      void *context,
      prodigy_neuron_hub *hub,
      const uint8_t *payload,
      size_t payload_size);
} prodigy_neuron_hub_callbacks;

typedef struct prodigy_neuron_hub_options
{
   uint32_t abi_version;
   int argc;
   char **argv;
   int neuron_fd_override;
   uint8_t preserve_neuron_fd;
} prodigy_neuron_hub_options;

void prodigy_bytes_free(prodigy_bytes *value);
void prodigy_message_frame_free(prodigy_message_frame *frame);
void prodigy_credential_bundle_free(prodigy_credential_bundle *bundle);
void prodigy_credential_delta_free(prodigy_credential_delta *delta);
void prodigy_container_parameters_free(prodigy_container_parameters *parameters);

void prodigy_frame_decoder_init(prodigy_frame_decoder *decoder);
void prodigy_frame_decoder_free(prodigy_frame_decoder *decoder);

prodigy_aegis_session prodigy_aegis_session_from_advertisement(
   const prodigy_advertisement_pairing *pairing);

prodigy_aegis_session prodigy_aegis_session_from_subscription(
   const prodigy_subscription_pairing *pairing);

uint64_t prodigy_aegis_pairing_hash(const prodigy_aegis_session *session);

prodigy_result prodigy_aegis_build_tfo_data(
   const prodigy_aegis_session *session,
   const uint8_t *aux,
   size_t aux_size,
   prodigy_bytes *tfo_data);

prodigy_result prodigy_aegis_frame_bytes_for_plaintext(
   size_t plaintext_size,
   size_t *frame_size);

prodigy_result prodigy_aegis_encrypt(
   const prodigy_aegis_session *session,
   const uint8_t *plaintext,
   size_t plaintext_size,
   prodigy_bytes *frame,
   prodigy_u128 *nonce_out);

prodigy_result prodigy_aegis_encrypt_with_nonce(
   const prodigy_aegis_session *session,
   const uint8_t *plaintext,
   size_t plaintext_size,
   const prodigy_u128 *nonce,
   prodigy_bytes *frame);

prodigy_result prodigy_aegis_decode_frame_header(
   const uint8_t *frame,
   size_t frame_size,
   prodigy_aegis_frame_header *header);

prodigy_result prodigy_aegis_decrypt(
   const prodigy_aegis_session *session,
   const uint8_t *frame,
   size_t frame_size,
   prodigy_bytes *plaintext,
   prodigy_aegis_frame_header *header_out);

prodigy_result prodigy_frame_decoder_feed(
   prodigy_frame_decoder *decoder,
   const uint8_t *data,
   size_t size);

prodigy_result prodigy_frame_decoder_next(
   prodigy_frame_decoder *decoder,
   prodigy_message_frame *frame);

prodigy_result prodigy_parse_message_frame(
   const uint8_t *data,
   size_t size,
   prodigy_message_frame *frame);

prodigy_result prodigy_build_message_frame(
   prodigy_container_topic topic,
   const uint8_t *payload,
   size_t payload_size,
   prodigy_bytes *frame);

prodigy_result prodigy_build_ready_frame(prodigy_bytes *frame);

prodigy_result prodigy_build_statistics_frame(
   const prodigy_metric_pair *metrics,
   size_t metric_count,
   prodigy_bytes *frame);

prodigy_result prodigy_build_resource_delta_ack_frame(
   uint8_t accepted,
   prodigy_bytes *frame);

prodigy_result prodigy_build_credentials_refresh_ack_frame(prodigy_bytes *frame);

prodigy_result prodigy_decode_container_parameters(
   const uint8_t *data,
   size_t size,
   prodigy_container_parameters *parameters);

prodigy_result prodigy_decode_credential_bundle(
   const uint8_t *data,
   size_t size,
   prodigy_credential_bundle *bundle);

prodigy_result prodigy_decode_credential_delta(
   const uint8_t *data,
   size_t size,
   prodigy_credential_delta *delta);

prodigy_neuron_hub *prodigy_neuron_hub_create(
   const prodigy_neuron_hub_callbacks *callbacks,
   void *context,
   const prodigy_neuron_hub_options *options);

prodigy_neuron_hub *prodigy_neuron_hub_create_from_process(
   const prodigy_neuron_hub_callbacks *callbacks,
   void *context,
   int argc,
   char **argv);

void prodigy_neuron_hub_destroy(prodigy_neuron_hub *hub);

int prodigy_neuron_hub_fd(const prodigy_neuron_hub *hub);

const prodigy_container_parameters *prodigy_neuron_hub_parameters(
   const prodigy_neuron_hub *hub);

prodigy_result prodigy_neuron_hub_handle_message_frame(
   prodigy_neuron_hub *hub,
   const prodigy_message_frame *frame,
   prodigy_message_frame *automatic_response);

prodigy_result prodigy_neuron_hub_run_once(prodigy_neuron_hub *hub);
prodigy_result prodigy_neuron_hub_run_forever(prodigy_neuron_hub *hub);

prodigy_result prodigy_neuron_hub_signal_ready(prodigy_neuron_hub *hub);

prodigy_result prodigy_neuron_hub_publish_statistic(
   prodigy_neuron_hub *hub,
   uint64_t metric_key,
   uint64_t metric_value);

prodigy_result prodigy_neuron_hub_publish_statistics(
   prodigy_neuron_hub *hub,
   const prodigy_metric_pair *metrics,
   size_t metric_count);

prodigy_result prodigy_neuron_hub_acknowledge_resource_delta(
   prodigy_neuron_hub *hub,
   uint8_t accepted);

prodigy_result prodigy_neuron_hub_acknowledge_credentials_refresh(
   prodigy_neuron_hub *hub);

#ifdef __cplusplus
}
#endif

#endif
