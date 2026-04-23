/* Copyright 2026 Victor Stewart */
/* SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "prodigy_io_uring_reactor.h"

#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <liburing.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum prodigy_io_uring_operation
{
   PRODIGY_IO_URING_OPERATION_NEURON_RECV = 1,
   PRODIGY_IO_URING_OPERATION_NEURON_SEND = 2,
   PRODIGY_IO_URING_OPERATION_WATCH_POLL = 3
};

typedef struct prodigy_io_uring_neuron_source
{
   prodigy_neuron_hub *hub;
   prodigy_frame_decoder decoder;
   int fd;
   uint8_t auto_ack_resource_delta;
   uint8_t auto_ack_credentials_refresh;
   uint8_t read_buffer[4096];
} prodigy_io_uring_neuron_source;

typedef struct prodigy_io_uring_send_op
{
   int fd;
   prodigy_bytes frame;
} prodigy_io_uring_send_op;

typedef struct prodigy_io_uring_watch_op
{
   int fd;
   uint64_t app_event;
   unsigned poll_mask;
} prodigy_io_uring_watch_op;

struct prodigy_io_uring_reactor
{
   struct io_uring ring;
   uint8_t initialized;
   prodigy_io_uring_neuron_source *neurons;
   size_t neuron_count;
   prodigy_io_uring_send_op **sends;
   size_t send_count;
   prodigy_io_uring_watch_op **watches;
   size_t watch_count;
};

static uint64_t prodigy_io_uring_pack_user_data(
   enum prodigy_io_uring_operation operation,
   size_t index)
{
   return (((uint64_t)index) << 8u) | (uint64_t)operation;
}

static enum prodigy_io_uring_operation prodigy_io_uring_unpack_operation(uint64_t user_data)
{
   return (enum prodigy_io_uring_operation)(user_data & 0xffu);
}

static size_t prodigy_io_uring_unpack_index(uint64_t user_data)
{
   return (size_t)(user_data >> 8u);
}

static prodigy_result prodigy_io_uring_set_nonblocking(int fd)
{
   int flags = 0;

   flags = fcntl(fd, F_GETFL, 0);
   if (flags < 0)
   {
      return PRODIGY_RESULT_IO;
   }

   if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
   {
      return PRODIGY_RESULT_IO;
   }

   return PRODIGY_RESULT_OK;
}

prodigy_result prodigy_io_uring_parse_ipv6_socket_address(
   const char *address_text,
   uint16_t port,
   struct sockaddr_in6 *address)
{
   if (address_text == NULL || address == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   memset(address, 0, sizeof(*address));
   address->sin6_family = AF_INET6;
   address->sin6_port = htons(port);
   return (inet_pton(AF_INET6, address_text, &address->sin6_addr) == 1)
      ? PRODIGY_RESULT_OK
      : PRODIGY_RESULT_ARGUMENT;
}

static prodigy_result prodigy_io_uring_append_neuron(
   prodigy_io_uring_reactor *reactor,
   const prodigy_io_uring_neuron_source *source,
   size_t *index_out)
{
   prodigy_io_uring_neuron_source *next = NULL;

   next = (prodigy_io_uring_neuron_source *)realloc(
      reactor->neurons,
      (reactor->neuron_count + 1u) * sizeof(*reactor->neurons));
   if (next == NULL)
   {
      return PRODIGY_RESULT_MEMORY;
   }

   reactor->neurons = next;
   reactor->neurons[reactor->neuron_count] = *source;
   *index_out = reactor->neuron_count;
   reactor->neuron_count += 1u;
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_io_uring_append_send(
   prodigy_io_uring_reactor *reactor,
   prodigy_io_uring_send_op *send,
   size_t *index_out)
{
   prodigy_io_uring_send_op **next = NULL;

   next = (prodigy_io_uring_send_op **)realloc(
      reactor->sends,
      (reactor->send_count + 1u) * sizeof(*reactor->sends));
   if (next == NULL)
   {
      return PRODIGY_RESULT_MEMORY;
   }

   reactor->sends = next;
   reactor->sends[reactor->send_count] = send;
   *index_out = reactor->send_count;
   reactor->send_count += 1u;
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_io_uring_append_watch(
   prodigy_io_uring_reactor *reactor,
   prodigy_io_uring_watch_op *watch,
   size_t *index_out)
{
   prodigy_io_uring_watch_op **next = NULL;

   next = (prodigy_io_uring_watch_op **)realloc(
      reactor->watches,
      (reactor->watch_count + 1u) * sizeof(*reactor->watches));
   if (next == NULL)
   {
      return PRODIGY_RESULT_MEMORY;
   }

   reactor->watches = next;
   reactor->watches[reactor->watch_count] = watch;
   *index_out = reactor->watch_count;
   reactor->watch_count += 1u;
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_io_uring_arm_watch(
   prodigy_io_uring_reactor *reactor,
   prodigy_io_uring_watch_op *watch,
   size_t index)
{
   struct io_uring_sqe *sqe = NULL;

   sqe = io_uring_get_sqe(&reactor->ring);
   if (sqe == NULL)
   {
      return PRODIGY_RESULT_IO;
   }

   io_uring_prep_poll_add(sqe, watch->fd, watch->poll_mask | POLLERR | POLLHUP);
   io_uring_sqe_set_data64(
      sqe,
      prodigy_io_uring_pack_user_data(PRODIGY_IO_URING_OPERATION_WATCH_POLL, index));
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_io_uring_arm_neuron_recv(
   prodigy_io_uring_reactor *reactor,
   size_t neuron_index)
{
   struct io_uring_sqe *sqe = NULL;
   prodigy_io_uring_neuron_source *source = NULL;

   if (reactor == NULL || neuron_index >= reactor->neuron_count)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   sqe = io_uring_get_sqe(&reactor->ring);
   if (sqe == NULL)
   {
      return PRODIGY_RESULT_IO;
   }

   source = &reactor->neurons[neuron_index];
   io_uring_prep_recv(
      sqe,
      source->fd,
      source->read_buffer,
      (unsigned)sizeof(source->read_buffer),
      0);
   io_uring_sqe_set_data64(
      sqe,
      prodigy_io_uring_pack_user_data(PRODIGY_IO_URING_OPERATION_NEURON_RECV, neuron_index));
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_io_uring_queue_send_bytes(
   prodigy_io_uring_reactor *reactor,
   int fd,
   prodigy_bytes *frame)
{
   prodigy_io_uring_send_op *send = NULL;
   struct io_uring_sqe *sqe = NULL;
   size_t index = 0;
   prodigy_result result = PRODIGY_RESULT_OK;

   send = (prodigy_io_uring_send_op *)calloc(1, sizeof(*send));
   if (send == NULL)
   {
      return PRODIGY_RESULT_MEMORY;
   }

   send->fd = fd;
   send->frame = *frame;
   frame->data = NULL;
   frame->size = 0;

   result = prodigy_io_uring_append_send(reactor, send, &index);
   if (result != PRODIGY_RESULT_OK)
   {
      prodigy_bytes_free(&send->frame);
      free(send);
      return result;
   }

   sqe = io_uring_get_sqe(&reactor->ring);
   if (sqe == NULL)
   {
      prodigy_bytes_free(&send->frame);
      free(send);
      reactor->sends[index] = NULL;
      return PRODIGY_RESULT_IO;
   }

   io_uring_prep_send(sqe, send->fd, send->frame.data, (unsigned)send->frame.size, 0);
   io_uring_sqe_set_data64(
      sqe,
      prodigy_io_uring_pack_user_data(PRODIGY_IO_URING_OPERATION_NEURON_SEND, index));
   return PRODIGY_RESULT_OK;
}

static prodigy_result prodigy_io_uring_queue_ready(
   prodigy_io_uring_reactor *reactor,
   size_t neuron_index)
{
   prodigy_bytes frame;
   memset(&frame, 0, sizeof(frame));
   if (prodigy_build_ready_frame(&frame) != PRODIGY_RESULT_OK)
   {
      return PRODIGY_RESULT_MEMORY;
   }
   return prodigy_io_uring_queue_send_bytes(reactor, reactor->neurons[neuron_index].fd, &frame);
}

static prodigy_result prodigy_io_uring_queue_resource_delta_ack(
   prodigy_io_uring_reactor *reactor,
   size_t neuron_index,
   uint8_t accepted)
{
   prodigy_bytes frame;
   memset(&frame, 0, sizeof(frame));
   if (prodigy_build_resource_delta_ack_frame(accepted, &frame) != PRODIGY_RESULT_OK)
   {
      return PRODIGY_RESULT_MEMORY;
   }
   return prodigy_io_uring_queue_send_bytes(reactor, reactor->neurons[neuron_index].fd, &frame);
}

static prodigy_result prodigy_io_uring_queue_credentials_refresh_ack(
   prodigy_io_uring_reactor *reactor,
   size_t neuron_index)
{
   prodigy_bytes frame;
   memset(&frame, 0, sizeof(frame));
   if (prodigy_build_credentials_refresh_ack_frame(&frame) != PRODIGY_RESULT_OK)
   {
      return PRODIGY_RESULT_MEMORY;
   }
   return prodigy_io_uring_queue_send_bytes(reactor, reactor->neurons[neuron_index].fd, &frame);
}

static prodigy_result prodigy_io_uring_handle_frame(
   prodigy_io_uring_reactor *reactor,
   size_t neuron_index,
   const prodigy_message_frame *frame,
   prodigy_io_uring_reactor_event *event)
{
   prodigy_io_uring_neuron_source *source = NULL;
   prodigy_message_frame automatic_response;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (reactor == NULL || frame == NULL || event == NULL || neuron_index >= reactor->neuron_count)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   source = &reactor->neurons[neuron_index];
   memset(&automatic_response, 0, sizeof(automatic_response));
   automatic_response.topic = PRODIGY_CONTAINER_TOPIC_NONE;

   result = prodigy_neuron_hub_handle_message_frame(source->hub, frame, &automatic_response);
   if (result != PRODIGY_RESULT_OK)
   {
      prodigy_message_frame_free(&automatic_response);
      return result;
   }

   if (automatic_response.topic != PRODIGY_CONTAINER_TOPIC_NONE)
   {
      prodigy_bytes frame_bytes;
      memset(&frame_bytes, 0, sizeof(frame_bytes));
      result = prodigy_build_message_frame(
         automatic_response.topic,
         automatic_response.payload.data,
         automatic_response.payload.size,
         &frame_bytes);
      prodigy_message_frame_free(&automatic_response);
      if (result != PRODIGY_RESULT_OK)
      {
         return result;
      }

      result = prodigy_io_uring_queue_send_bytes(reactor, source->fd, &frame_bytes);
      if (result != PRODIGY_RESULT_OK)
      {
         return result;
      }
   }
   else
   {
      prodigy_message_frame_free(&automatic_response);
   }

   if (frame->topic == PRODIGY_CONTAINER_TOPIC_RESOURCE_DELTA && source->auto_ack_resource_delta)
   {
      result = prodigy_io_uring_queue_resource_delta_ack(reactor, neuron_index, 1u);
      if (result != PRODIGY_RESULT_OK)
      {
         return result;
      }
   }

   if (frame->topic == PRODIGY_CONTAINER_TOPIC_CREDENTIALS_REFRESH &&
      frame->payload.size > 0 &&
      source->auto_ack_credentials_refresh)
   {
      result = prodigy_io_uring_queue_credentials_refresh_ack(reactor, neuron_index);
      if (result != PRODIGY_RESULT_OK)
      {
         return result;
      }
   }

   if (frame->topic == PRODIGY_CONTAINER_TOPIC_STOP)
   {
      event->kind = PRODIGY_IO_URING_REACTOR_EVENT_NEURON;
      event->neuron_event = PRODIGY_IO_URING_NEURON_EVENT_SHUTDOWN;
      return PRODIGY_RESULT_OK;
   }

   return PRODIGY_RESULT_AGAIN;
}

prodigy_io_uring_reactor *prodigy_io_uring_reactor_create(void)
{
   prodigy_io_uring_reactor *reactor = NULL;

   reactor = (prodigy_io_uring_reactor *)calloc(1, sizeof(*reactor));
   if (reactor == NULL)
   {
      return NULL;
   }

   if (io_uring_queue_init(64, &reactor->ring, 0) != 0)
   {
      free(reactor);
      return NULL;
   }

   reactor->initialized = 1u;
   return reactor;
}

void prodigy_io_uring_reactor_destroy(prodigy_io_uring_reactor *reactor)
{
   size_t index = 0;

   if (reactor == NULL)
   {
      return;
   }

   for (index = 0; index < reactor->neuron_count; index += 1u)
   {
      prodigy_frame_decoder_free(&reactor->neurons[index].decoder);
   }
   free(reactor->neurons);

   for (index = 0; index < reactor->send_count; index += 1u)
   {
      if (reactor->sends[index] != NULL)
      {
         prodigy_bytes_free(&reactor->sends[index]->frame);
         free(reactor->sends[index]);
      }
   }
   free(reactor->sends);

   for (index = 0; index < reactor->watch_count; index += 1u)
   {
      free(reactor->watches[index]);
   }
   free(reactor->watches);

   if (reactor->initialized)
   {
      io_uring_queue_exit(&reactor->ring);
   }
   free(reactor);
}

prodigy_result prodigy_io_uring_reactor_attach_neuron(
   prodigy_io_uring_reactor *reactor,
   prodigy_neuron_hub *hub,
   uint8_t auto_ack_resource_delta,
   uint8_t auto_ack_credentials_refresh,
   prodigy_io_uring_neuron_handle *handle)
{
   prodigy_io_uring_neuron_source source;
   size_t index = 0;
   prodigy_result result = PRODIGY_RESULT_OK;
   int fd = -1;

   if (reactor == NULL || hub == NULL || handle == NULL || reactor->initialized == 0)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   fd = prodigy_neuron_hub_fd(hub);
   if (fd < 0)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   result = prodigy_io_uring_set_nonblocking(fd);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   memset(&source, 0, sizeof(source));
   source.hub = hub;
   source.fd = fd;
   source.auto_ack_resource_delta = auto_ack_resource_delta;
   source.auto_ack_credentials_refresh = auto_ack_credentials_refresh;
   prodigy_frame_decoder_init(&source.decoder);

   result = prodigy_io_uring_append_neuron(reactor, &source, &index);
   if (result != PRODIGY_RESULT_OK)
   {
      prodigy_frame_decoder_free(&source.decoder);
      return result;
   }

   handle->reactor = reactor;
   handle->index = index;
   handle->ready_sent = 0;
   return prodigy_io_uring_arm_neuron_recv(reactor, index);
}

prodigy_result prodigy_io_uring_reactor_attach_neuron_with_auto_acks(
   prodigy_io_uring_reactor *reactor,
   prodigy_neuron_hub *hub,
   prodigy_io_uring_neuron_handle *handle)
{
   return prodigy_io_uring_reactor_attach_neuron(reactor, hub, 1u, 1u, handle);
}

prodigy_result prodigy_io_uring_reactor_once_writable(
   prodigy_io_uring_reactor *reactor,
   int fd,
   uint64_t app_event)
{
   prodigy_io_uring_watch_op *watch = NULL;
   size_t index = 0;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (reactor == NULL || reactor->initialized == 0 || fd < 0)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   watch = (prodigy_io_uring_watch_op *)calloc(1, sizeof(*watch));
   if (watch == NULL)
   {
      return PRODIGY_RESULT_MEMORY;
   }

   watch->fd = fd;
   watch->app_event = app_event;
   watch->poll_mask = POLLOUT;
   result = prodigy_io_uring_append_watch(reactor, watch, &index);
   if (result != PRODIGY_RESULT_OK)
   {
      free(watch);
      return result;
   }

   result = prodigy_io_uring_arm_watch(reactor, watch, index);
   if (result != PRODIGY_RESULT_OK)
   {
      free(watch);
      reactor->watches[index] = NULL;
      return result;
   }

   return PRODIGY_RESULT_OK;
}

prodigy_result prodigy_io_uring_reactor_once_readable(
   prodigy_io_uring_reactor *reactor,
   int fd,
   uint64_t app_event)
{
   prodigy_io_uring_watch_op *watch = NULL;
   size_t index = 0;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (reactor == NULL || reactor->initialized == 0 || fd < 0)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   watch = (prodigy_io_uring_watch_op *)calloc(1, sizeof(*watch));
   if (watch == NULL)
   {
      return PRODIGY_RESULT_MEMORY;
   }

   watch->fd = fd;
   watch->app_event = app_event;
   watch->poll_mask = POLLIN;
   result = prodigy_io_uring_append_watch(reactor, watch, &index);
   if (result != PRODIGY_RESULT_OK)
   {
      free(watch);
      return result;
   }

   result = prodigy_io_uring_arm_watch(reactor, watch, index);
   if (result != PRODIGY_RESULT_OK)
   {
      free(watch);
      reactor->watches[index] = NULL;
      return result;
   }

   return PRODIGY_RESULT_OK;
}

prodigy_result prodigy_io_uring_reactor_next(
   prodigy_io_uring_reactor *reactor,
   prodigy_io_uring_reactor_event *event)
{
   struct io_uring_cqe *cqe = NULL;
   enum prodigy_io_uring_operation operation;
   size_t index = 0;
   int result = 0;

   if (reactor == NULL || event == NULL || reactor->initialized == 0)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   memset(event, 0, sizeof(*event));

   while (1)
   {
      if (io_uring_submit(&reactor->ring) < 0)
      {
         return PRODIGY_RESULT_IO;
      }

      if (io_uring_wait_cqe(&reactor->ring, &cqe) < 0 || cqe == NULL)
      {
         return PRODIGY_RESULT_IO;
      }

      result = cqe->res;
      operation = prodigy_io_uring_unpack_operation(io_uring_cqe_get_data64(cqe));
      index = prodigy_io_uring_unpack_index(io_uring_cqe_get_data64(cqe));
      io_uring_cqe_seen(&reactor->ring, cqe);

      switch (operation)
      {
         case PRODIGY_IO_URING_OPERATION_NEURON_RECV:
         {
            prodigy_io_uring_neuron_source *source = NULL;
            prodigy_result feed_result = PRODIGY_RESULT_OK;

            if (index >= reactor->neuron_count)
            {
               return PRODIGY_RESULT_PROTOCOL;
            }

            source = &reactor->neurons[index];
            if (result == 0)
            {
               event->kind = PRODIGY_IO_URING_REACTOR_EVENT_NEURON;
               event->neuron_event = PRODIGY_IO_URING_NEURON_EVENT_CLOSED;
               return PRODIGY_RESULT_OK;
            }

            if (result < 0)
            {
               if (result == -EAGAIN || result == -EINTR)
               {
                  feed_result = prodigy_io_uring_arm_neuron_recv(reactor, index);
                  if (feed_result != PRODIGY_RESULT_OK)
                  {
                     return feed_result;
                  }
                  continue;
               }

               return PRODIGY_RESULT_IO;
            }

            feed_result = prodigy_frame_decoder_feed(
               &source->decoder,
               source->read_buffer,
               (size_t)result);
            if (feed_result != PRODIGY_RESULT_OK)
            {
               return feed_result;
            }

            while (1)
            {
               prodigy_message_frame frame;
               prodigy_result handle_result = PRODIGY_RESULT_OK;

               memset(&frame, 0, sizeof(frame));
               feed_result = prodigy_frame_decoder_next(&source->decoder, &frame);
               if (feed_result == PRODIGY_RESULT_AGAIN)
               {
                  break;
               }

               if (feed_result != PRODIGY_RESULT_OK)
               {
                  return feed_result;
               }

               handle_result = prodigy_io_uring_handle_frame(reactor, index, &frame, event);
               prodigy_message_frame_free(&frame);
               if (handle_result == PRODIGY_RESULT_OK)
               {
                  return PRODIGY_RESULT_OK;
               }

               if (handle_result != PRODIGY_RESULT_AGAIN)
               {
                  return handle_result;
               }
            }

            feed_result = prodigy_io_uring_arm_neuron_recv(reactor, index);
            if (feed_result != PRODIGY_RESULT_OK)
            {
               return feed_result;
            }
            break;
         }
         case PRODIGY_IO_URING_OPERATION_NEURON_SEND:
         {
            if (index >= reactor->send_count || reactor->sends[index] == NULL)
            {
               return PRODIGY_RESULT_PROTOCOL;
            }

            prodigy_bytes_free(&reactor->sends[index]->frame);
            free(reactor->sends[index]);
            reactor->sends[index] = NULL;

            if (result < 0)
            {
               return PRODIGY_RESULT_IO;
            }
            break;
         }
         case PRODIGY_IO_URING_OPERATION_WATCH_POLL:
         {
            prodigy_io_uring_watch_op *watch = NULL;
            int socket_error = 0;
            socklen_t socket_error_size = sizeof(socket_error);

            if (index >= reactor->watch_count || reactor->watches[index] == NULL)
            {
               return PRODIGY_RESULT_PROTOCOL;
            }

            watch = reactor->watches[index];
            reactor->watches[index] = NULL;

            if (result < 0)
            {
               free(watch);
               return PRODIGY_RESULT_IO;
            }

            if (watch->poll_mask == POLLOUT)
            {
               if (getsockopt(watch->fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_size) != 0)
               {
                  free(watch);
                  return PRODIGY_RESULT_IO;
               }

               if (socket_error != 0)
               {
                  free(watch);
                  errno = socket_error;
                  return PRODIGY_RESULT_IO;
               }
            }

            event->kind = PRODIGY_IO_URING_REACTOR_EVENT_APP;
            event->app_event = watch->app_event;
            free(watch);
            return PRODIGY_RESULT_OK;
         }
      }
   }
}

prodigy_result prodigy_io_uring_neuron_ready(
   prodigy_io_uring_neuron_handle *handle)
{
   prodigy_result result = PRODIGY_RESULT_OK;

   if (handle == NULL || handle->reactor == NULL || handle->index >= handle->reactor->neuron_count)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   if (handle->ready_sent)
   {
      return PRODIGY_RESULT_OK;
   }

   result = prodigy_io_uring_queue_ready(handle->reactor, handle->index);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   handle->ready_sent = 1u;
   return PRODIGY_RESULT_OK;
}
