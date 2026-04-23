/* Copyright 2026 Victor Stewart */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PRODIGY_IO_URING_REACTOR_H
#define PRODIGY_IO_URING_REACTOR_H

#include "prodigy_neuron_hub.h"

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum prodigy_io_uring_neuron_event
{
   PRODIGY_IO_URING_NEURON_EVENT_SHUTDOWN = 1,
   PRODIGY_IO_URING_NEURON_EVENT_CLOSED = 2
} prodigy_io_uring_neuron_event;

typedef enum prodigy_io_uring_reactor_event_kind
{
   PRODIGY_IO_URING_REACTOR_EVENT_APP = 1,
   PRODIGY_IO_URING_REACTOR_EVENT_NEURON = 2
} prodigy_io_uring_reactor_event_kind;

typedef struct prodigy_io_uring_reactor_event
{
   prodigy_io_uring_reactor_event_kind kind;
   uint64_t app_event;
   prodigy_io_uring_neuron_event neuron_event;
} prodigy_io_uring_reactor_event;

typedef struct prodigy_io_uring_reactor prodigy_io_uring_reactor;

typedef struct prodigy_io_uring_neuron_handle
{
   prodigy_io_uring_reactor *reactor;
   size_t index;
   uint8_t ready_sent;
} prodigy_io_uring_neuron_handle;

prodigy_io_uring_reactor *prodigy_io_uring_reactor_create(void);
void prodigy_io_uring_reactor_destroy(prodigy_io_uring_reactor *reactor);

prodigy_result prodigy_io_uring_reactor_attach_neuron(
   prodigy_io_uring_reactor *reactor,
   prodigy_neuron_hub *hub,
   uint8_t auto_ack_resource_delta,
   uint8_t auto_ack_credentials_refresh,
   prodigy_io_uring_neuron_handle *handle);

prodigy_result prodigy_io_uring_reactor_attach_neuron_with_auto_acks(
   prodigy_io_uring_reactor *reactor,
   prodigy_neuron_hub *hub,
   prodigy_io_uring_neuron_handle *handle);

prodigy_result prodigy_io_uring_reactor_once_writable(
   prodigy_io_uring_reactor *reactor,
   int fd,
   uint64_t app_event);

prodigy_result prodigy_io_uring_reactor_once_readable(
   prodigy_io_uring_reactor *reactor,
   int fd,
   uint64_t app_event);

prodigy_result prodigy_io_uring_reactor_next(
   prodigy_io_uring_reactor *reactor,
   prodigy_io_uring_reactor_event *event);

prodigy_result prodigy_io_uring_neuron_ready(
   prodigy_io_uring_neuron_handle *handle);

prodigy_result prodigy_io_uring_parse_ipv6_socket_address(
   const char *address_text,
   uint16_t port,
   struct sockaddr_in6 *address);

#ifdef __cplusplus
}
#endif

#endif
