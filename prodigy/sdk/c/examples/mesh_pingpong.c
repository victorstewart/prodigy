/* SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE

#include "../prodigy_io_uring_reactor.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum
{
   MESH_PINGPONG_EVENT_ACCEPT = 1u,
   MESH_PINGPONG_EVENT_CONNECTED = 2u,
   MESH_PINGPONG_EVENT_STREAM_READABLE = 3u
};

enum mesh_pingpong_role
{
   MESH_PINGPONG_ROLE_ADVERTISER = 1,
   MESH_PINGPONG_ROLE_SUBSCRIBER = 2
};

typedef struct mesh_pingpong_state
{
   prodigy_neuron_hub *hub;
   prodigy_io_uring_reactor *reactor;
   prodigy_io_uring_neuron_handle neuron;
   enum mesh_pingpong_role role;
   uint16_t listen_port;
   int listener_fd;
   int stream_fd;
   uint8_t listener_armed;
   uint8_t connect_pending;
   uint8_t stream_armed;
   uint8_t ready_sent;
   uint64_t pairing_events;
   uint64_t resource_delta_events;
   uint64_t credential_refresh_events;
   prodigy_result callback_result;
} mesh_pingpong_state;

static const unsigned mesh_pingpong_rounds = 3u;
static const uint64_t stat_pairing_activity = UINT64_C(1);
static const uint64_t stat_resource_activity = UINT64_C(2);
static const uint64_t stat_credential_activity = UINT64_C(3);
static const uint64_t stat_startup_pairings = UINT64_C(4);

static void mesh_pingpong_close_fd(int *fd)
{
   if (fd == NULL || *fd < 0)
   {
      return;
   }

   close(*fd);
   *fd = -1;
}

static uint64_t mesh_pingpong_stat_key(
   uint64_t slot,
   uint8_t datacenter_unique_tag)
{
   return (slot << 8u) | (uint64_t)datacenter_unique_tag;
}

static prodigy_result mesh_pingpong_publish_stat(
   mesh_pingpong_state *state,
   uint64_t slot,
   uint64_t value)
{
   const prodigy_container_parameters *parameters = NULL;

   if (state == NULL || state->hub == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   parameters = prodigy_neuron_hub_parameters(state->hub);
   if (parameters == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   return prodigy_neuron_hub_publish_statistic(
      state->hub,
      mesh_pingpong_stat_key(slot, parameters->datacenter_unique_tag),
      value);
}

static void mesh_pingpong_note_callback_result(
   mesh_pingpong_state *state,
   prodigy_result result)
{
   if (state == NULL
      || state->callback_result != PRODIGY_RESULT_OK
      || result == PRODIGY_RESULT_OK)
   {
      return;
   }

   state->callback_result = result;
}

static prodigy_result mesh_pingpong_note_pairing(mesh_pingpong_state *state)
{
   if (state == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   state->pairing_events += 1u;
   return mesh_pingpong_publish_stat(state, stat_pairing_activity, state->pairing_events);
}

static prodigy_result mesh_pingpong_note_resource_delta(mesh_pingpong_state *state)
{
   prodigy_result result = PRODIGY_RESULT_OK;

   if (state == NULL || state->hub == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   state->resource_delta_events += 1u;
   result = mesh_pingpong_publish_stat(
      state,
      stat_resource_activity,
      state->resource_delta_events);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   return prodigy_neuron_hub_acknowledge_resource_delta(state->hub, 1u);
}

static prodigy_result mesh_pingpong_note_credentials_refresh(mesh_pingpong_state *state)
{
   prodigy_result result = PRODIGY_RESULT_OK;

   if (state == NULL || state->hub == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   state->credential_refresh_events += 1u;
   result = mesh_pingpong_publish_stat(
      state,
      stat_credential_activity,
      state->credential_refresh_events);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   return prodigy_neuron_hub_acknowledge_credentials_refresh(state->hub);
}

static prodigy_result mesh_pingpong_private6_address(
   const prodigy_container_parameters *parameters,
   struct in6_addr *address)
{
   if (parameters == NULL || address == NULL || parameters->private6.address.is_ipv6 == 0)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   memcpy(address->s6_addr, parameters->private6.address.bytes, sizeof(address->s6_addr));
   return PRODIGY_RESULT_OK;
}

static prodigy_result mesh_pingpong_send_line(int fd, const char *text)
{
   size_t size = strlen(text);
   size_t offset = 0;

   while (offset < size)
   {
      ssize_t written = send(fd, text + offset, size - offset, MSG_NOSIGNAL);
      if (written < 0)
      {
         if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
         {
            continue;
         }

         return PRODIGY_RESULT_IO;
      }

      offset += (size_t)written;
   }

   return PRODIGY_RESULT_OK;
}

static prodigy_result mesh_pingpong_arm_stream(mesh_pingpong_state *state)
{
   prodigy_result result = PRODIGY_RESULT_OK;

   if (state == NULL || state->stream_fd < 0)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   result = prodigy_io_uring_reactor_once_readable(
      state->reactor,
      state->stream_fd,
      MESH_PINGPONG_EVENT_STREAM_READABLE);
   if (result == PRODIGY_RESULT_OK)
   {
      state->stream_armed = 1u;
   }
   return result;
}

static prodigy_result mesh_pingpong_signal_ready(mesh_pingpong_state *state)
{
   prodigy_result result = PRODIGY_RESULT_OK;

   if (state == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   if (state->ready_sent != 0)
   {
      return PRODIGY_RESULT_OK;
   }

   result = prodigy_io_uring_neuron_ready(&state->neuron);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   state->ready_sent = 1u;
   return PRODIGY_RESULT_OK;
}

static prodigy_result mesh_pingpong_open_listener(mesh_pingpong_state *state)
{
   const prodigy_container_parameters *parameters = NULL;
   struct sockaddr_in6 local;
   int fd = -1;
   int one = 1;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (state == NULL || state->hub == NULL || state->listener_fd >= 0 || state->listen_port == 0u)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   parameters = prodigy_neuron_hub_parameters(state->hub);
   if (parameters == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   memset(&local, 0, sizeof(local));
   local.sin6_family = AF_INET6;
   local.sin6_port = htons(state->listen_port);
   result = mesh_pingpong_private6_address(parameters, &local.sin6_addr);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP);
   if (fd < 0)
   {
      return PRODIGY_RESULT_IO;
   }

   if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, (socklen_t)sizeof(one)) != 0
      || setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, (socklen_t)sizeof(one)) != 0
      || bind(fd, (const struct sockaddr *)&local, (socklen_t)sizeof(local)) != 0
      || listen(fd, 4) != 0)
   {
      close(fd);
      return PRODIGY_RESULT_IO;
   }

   state->listener_fd = fd;
   result = prodigy_io_uring_reactor_once_readable(
      state->reactor,
      state->listener_fd,
      MESH_PINGPONG_EVENT_ACCEPT);
   if (result != PRODIGY_RESULT_OK)
   {
      mesh_pingpong_close_fd(&state->listener_fd);
      return result;
   }

   state->listener_armed = 1u;
   return PRODIGY_RESULT_OK;
}

static prodigy_result mesh_pingpong_start_connect(
   mesh_pingpong_state *state,
   const prodigy_subscription_pairing *pairing)
{
   const prodigy_container_parameters *parameters = NULL;
   struct sockaddr_in6 local;
   struct sockaddr_in6 remote;
   int fd = -1;
   int one = 1;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (state == NULL || state->hub == NULL || pairing == NULL || pairing->activate == 0)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   if (state->stream_fd >= 0 || state->connect_pending != 0 || state->ready_sent != 0)
   {
      return PRODIGY_RESULT_OK;
   }

   parameters = prodigy_neuron_hub_parameters(state->hub);
   if (parameters == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   memset(&local, 0, sizeof(local));
   memset(&remote, 0, sizeof(remote));

   local.sin6_family = AF_INET6;
   result = mesh_pingpong_private6_address(parameters, &local.sin6_addr);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   remote.sin6_family = AF_INET6;
   remote.sin6_port = htons(pairing->port);
   memcpy(&remote.sin6_addr, pairing->address.bytes, sizeof(pairing->address.bytes));

   fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP);
   if (fd < 0)
   {
      return PRODIGY_RESULT_IO;
   }

   if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, (socklen_t)sizeof(one)) != 0
      || bind(fd, (const struct sockaddr *)&local, (socklen_t)sizeof(local)) != 0)
   {
      close(fd);
      return PRODIGY_RESULT_IO;
   }

   if (connect(fd, (const struct sockaddr *)&remote, (socklen_t)sizeof(remote)) != 0
      && errno != EINPROGRESS)
   {
      close(fd);
      return PRODIGY_RESULT_IO;
   }

   result = prodigy_io_uring_reactor_once_writable(
      state->reactor,
      fd,
      MESH_PINGPONG_EVENT_CONNECTED);
   if (result != PRODIGY_RESULT_OK)
   {
      close(fd);
      return result;
   }

   state->stream_fd = fd;
   state->connect_pending = 1u;
   return PRODIGY_RESULT_OK;
}

static prodigy_result mesh_pingpong_handle_advertisement_pairing(
   mesh_pingpong_state *state,
   const prodigy_advertisement_pairing *pairing)
{
   prodigy_result result = PRODIGY_RESULT_OK;

   if (state == NULL || pairing == NULL || state->role != MESH_PINGPONG_ROLE_ADVERTISER)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   result = mesh_pingpong_note_pairing(state);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   if (pairing->activate == 0 || state->listener_fd >= 0)
   {
      return PRODIGY_RESULT_OK;
   }

   return mesh_pingpong_open_listener(state);
}

static prodigy_result mesh_pingpong_handle_subscription_pairing(
   mesh_pingpong_state *state,
   const prodigy_subscription_pairing *pairing)
{
   prodigy_result result = PRODIGY_RESULT_OK;

   if (state == NULL || pairing == NULL || state->role != MESH_PINGPONG_ROLE_SUBSCRIBER)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   result = mesh_pingpong_note_pairing(state);
   if (result != PRODIGY_RESULT_OK)
   {
      return result;
   }

   if (pairing->activate == 0)
   {
      return PRODIGY_RESULT_OK;
   }

   return mesh_pingpong_start_connect(state, pairing);
}

static void mesh_pingpong_begin_shutdown(void *context, prodigy_neuron_hub *hub)
{
   mesh_pingpong_state *state = (mesh_pingpong_state *)context;
   (void)hub;
   if (state == NULL)
   {
      return;
   }

   mesh_pingpong_close_fd(&state->listener_fd);
   mesh_pingpong_close_fd(&state->stream_fd);
}

static void mesh_pingpong_end_of_dynamic_args(void *context, prodigy_neuron_hub *hub)
{
   mesh_pingpong_state *state = (mesh_pingpong_state *)context;
   const prodigy_container_parameters *parameters = prodigy_neuron_hub_parameters(hub);

   if (state == NULL || parameters == NULL)
   {
      return;
   }

   mesh_pingpong_note_callback_result(
      state,
      mesh_pingpong_publish_stat(
         state,
         stat_startup_pairings,
         (uint64_t)(parameters->advertisement_pairing_count + parameters->subscription_pairing_count)));
}

static void mesh_pingpong_advertisement_pairing(
   void *context,
   prodigy_neuron_hub *hub,
   const prodigy_advertisement_pairing *pairing)
{
   mesh_pingpong_state *state = (mesh_pingpong_state *)context;
   prodigy_result result = PRODIGY_RESULT_OK;
   (void)hub;
   if (state == NULL)
   {
      return;
   }

   mesh_pingpong_note_callback_result(state, mesh_pingpong_note_pairing(state));
   result = mesh_pingpong_handle_advertisement_pairing(state, pairing);
   mesh_pingpong_note_callback_result(state, result);
}

static void mesh_pingpong_subscription_pairing(
   void *context,
   prodigy_neuron_hub *hub,
   const prodigy_subscription_pairing *pairing)
{
   mesh_pingpong_state *state = (mesh_pingpong_state *)context;
   prodigy_result result = PRODIGY_RESULT_OK;
   (void)hub;
   if (state == NULL)
   {
      return;
   }

   mesh_pingpong_note_callback_result(state, mesh_pingpong_note_pairing(state));
   result = mesh_pingpong_handle_subscription_pairing(state, pairing);
   mesh_pingpong_note_callback_result(state, result);
}

static void mesh_pingpong_resource_delta(
   void *context,
   prodigy_neuron_hub *hub,
   const prodigy_resource_delta *delta)
{
   mesh_pingpong_state *state = (mesh_pingpong_state *)context;
   (void)hub;
   (void)delta;
   if (state == NULL)
   {
      return;
   }

   mesh_pingpong_note_callback_result(state, mesh_pingpong_note_resource_delta(state));
}

static void mesh_pingpong_credentials_refresh(
   void *context,
   prodigy_neuron_hub *hub,
   const prodigy_credential_delta *delta)
{
   mesh_pingpong_state *state = (mesh_pingpong_state *)context;
   (void)hub;
   (void)delta;
   if (state == NULL)
   {
      return;
   }

   mesh_pingpong_note_callback_result(state, mesh_pingpong_note_credentials_refresh(state));
}

static prodigy_result mesh_pingpong_handle_accept(mesh_pingpong_state *state)
{
   int accepted = -1;

   if (state == NULL || state->listener_fd < 0)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   state->listener_armed = 0u;
   accepted = accept4(state->listener_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
   if (accepted < 0)
   {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
      {
         return prodigy_io_uring_reactor_once_readable(
            state->reactor,
            state->listener_fd,
            MESH_PINGPONG_EVENT_ACCEPT);
      }

      return PRODIGY_RESULT_IO;
   }

   mesh_pingpong_close_fd(&state->stream_fd);
   state->stream_fd = accepted;
   return mesh_pingpong_arm_stream(state);
}

static prodigy_result mesh_pingpong_handle_connected(mesh_pingpong_state *state)
{
   if (state == NULL || state->stream_fd < 0)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   state->connect_pending = 0u;
   if (mesh_pingpong_send_line(state->stream_fd, "ping 1\n") != PRODIGY_RESULT_OK)
   {
      return PRODIGY_RESULT_IO;
   }

   return mesh_pingpong_arm_stream(state);
}

static prodigy_result mesh_pingpong_handle_stream(mesh_pingpong_state *state)
{
   char buffer[128];
   ssize_t received = 0;
   unsigned round = 0;

   if (state == NULL || state->stream_fd < 0)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   state->stream_armed = 0u;
   received = recv(state->stream_fd, buffer, sizeof(buffer) - 1u, 0);
   if (received < 0)
   {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
      {
         return mesh_pingpong_arm_stream(state);
      }

      return PRODIGY_RESULT_IO;
   }

   if (received == 0)
   {
      return PRODIGY_RESULT_EOF;
   }

   buffer[received] = '\0';

   if (state->role == MESH_PINGPONG_ROLE_ADVERTISER)
   {
      char reply[32];

      if (sscanf(buffer, "ping %u", &round) != 1)
      {
         return PRODIGY_RESULT_PROTOCOL;
      }

      snprintf(reply, sizeof(reply), "pong %u\n", round);
      if (mesh_pingpong_send_line(state->stream_fd, reply) != PRODIGY_RESULT_OK)
      {
         return PRODIGY_RESULT_IO;
      }

      if (round >= mesh_pingpong_rounds)
      {
         return mesh_pingpong_signal_ready(state);
      }

      return mesh_pingpong_arm_stream(state);
   }

   if (sscanf(buffer, "pong %u", &round) != 1)
   {
      return PRODIGY_RESULT_PROTOCOL;
   }

   if (round >= mesh_pingpong_rounds)
   {
      return mesh_pingpong_signal_ready(state);
   }

   {
      char next_ping[32];
      snprintf(next_ping, sizeof(next_ping), "ping %u\n", round + 1u);
      if (mesh_pingpong_send_line(state->stream_fd, next_ping) != PRODIGY_RESULT_OK)
      {
         return PRODIGY_RESULT_IO;
      }
   }

   return mesh_pingpong_arm_stream(state);
}

static prodigy_result mesh_pingpong_apply_initial_pairings(mesh_pingpong_state *state)
{
   const prodigy_container_parameters *parameters = NULL;
   size_t index = 0;
   prodigy_result result = PRODIGY_RESULT_OK;

   if (state == NULL || state->hub == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   parameters = prodigy_neuron_hub_parameters(state->hub);
   if (parameters == NULL)
   {
      return PRODIGY_RESULT_ARGUMENT;
   }

   if (state->role == MESH_PINGPONG_ROLE_ADVERTISER)
   {
      for (index = 0; index < parameters->advertisement_pairing_count; index += 1u)
      {
         result = mesh_pingpong_handle_advertisement_pairing(
            state,
            &parameters->advertisement_pairings[index]);
         if (result != PRODIGY_RESULT_OK && result != PRODIGY_RESULT_ARGUMENT)
         {
            return result;
         }
      }
      return PRODIGY_RESULT_OK;
   }

   for (index = 0; index < parameters->subscription_pairing_count; index += 1u)
   {
      result = mesh_pingpong_handle_subscription_pairing(
         state,
         &parameters->subscription_pairings[index]);
      if (result != PRODIGY_RESULT_OK && result != PRODIGY_RESULT_ARGUMENT)
      {
         return result;
      }
   }

   return PRODIGY_RESULT_OK;
}

static int run(int argc, char **argv)
{
   mesh_pingpong_state state;
   prodigy_neuron_hub_callbacks callbacks;
   prodigy_io_uring_reactor_event event;
   const prodigy_container_parameters *parameters = NULL;
   prodigy_result result = PRODIGY_RESULT_OK;

   memset(&state, 0, sizeof(state));
   memset(&callbacks, 0, sizeof(callbacks));
   memset(&event, 0, sizeof(event));

   state.listener_fd = -1;
   state.stream_fd = -1;
   state.callback_result = PRODIGY_RESULT_OK;

   callbacks.end_of_dynamic_args = mesh_pingpong_end_of_dynamic_args;
   callbacks.begin_shutdown = mesh_pingpong_begin_shutdown;
   callbacks.advertisement_pairing = mesh_pingpong_advertisement_pairing;
   callbacks.subscription_pairing = mesh_pingpong_subscription_pairing;
   callbacks.resource_delta = mesh_pingpong_resource_delta;
   callbacks.credentials_refresh = mesh_pingpong_credentials_refresh;

   state.hub = prodigy_neuron_hub_create_from_process(&callbacks, &state, argc, argv);
   state.reactor = prodigy_io_uring_reactor_create();
   if (state.hub == NULL || state.reactor == NULL)
   {
      prodigy_io_uring_reactor_destroy(state.reactor);
      prodigy_neuron_hub_destroy(state.hub);
      return 1;
   }

   parameters = prodigy_neuron_hub_parameters(state.hub);
   if (parameters == NULL)
   {
      prodigy_io_uring_reactor_destroy(state.reactor);
      prodigy_neuron_hub_destroy(state.hub);
      return 1;
   }

   if (parameters->advertise_count > 0u)
   {
      state.role = MESH_PINGPONG_ROLE_ADVERTISER;
      state.listen_port = parameters->advertises[0].port;
   }
   else
   {
      state.role = MESH_PINGPONG_ROLE_SUBSCRIBER;
   }

   result = prodigy_io_uring_reactor_attach_neuron(
      state.reactor,
      state.hub,
      0u,
      0u,
      &state.neuron);
   if (result != PRODIGY_RESULT_OK)
   {
      mesh_pingpong_close_fd(&state.listener_fd);
      mesh_pingpong_close_fd(&state.stream_fd);
      prodigy_io_uring_reactor_destroy(state.reactor);
      prodigy_neuron_hub_destroy(state.hub);
      return 1;
   }

   result = mesh_pingpong_apply_initial_pairings(&state);
   if (result != PRODIGY_RESULT_OK)
   {
      mesh_pingpong_close_fd(&state.listener_fd);
      mesh_pingpong_close_fd(&state.stream_fd);
      prodigy_io_uring_reactor_destroy(state.reactor);
      prodigy_neuron_hub_destroy(state.hub);
      return 1;
   }

   while ((result = prodigy_io_uring_reactor_next(state.reactor, &event)) == PRODIGY_RESULT_OK)
   {
      if (state.callback_result != PRODIGY_RESULT_OK)
      {
         result = state.callback_result;
         break;
      }

      if (event.kind == PRODIGY_IO_URING_REACTOR_EVENT_APP)
      {
         switch (event.app_event)
         {
            case MESH_PINGPONG_EVENT_ACCEPT:
            {
               result = mesh_pingpong_handle_accept(&state);
               break;
            }
            case MESH_PINGPONG_EVENT_CONNECTED:
            {
               result = mesh_pingpong_handle_connected(&state);
               break;
            }
            case MESH_PINGPONG_EVENT_STREAM_READABLE:
            {
               result = mesh_pingpong_handle_stream(&state);
               break;
            }
            default:
            {
               result = PRODIGY_RESULT_PROTOCOL;
               break;
            }
         }

         if (result == PRODIGY_RESULT_EOF)
         {
            mesh_pingpong_close_fd(&state.stream_fd);
            result = PRODIGY_RESULT_OK;
            continue;
         }

         if (result != PRODIGY_RESULT_OK)
         {
            break;
         }

         continue;
      }

      if (event.kind == PRODIGY_IO_URING_REACTOR_EVENT_NEURON
         && (event.neuron_event == PRODIGY_IO_URING_NEURON_EVENT_SHUTDOWN
            || event.neuron_event == PRODIGY_IO_URING_NEURON_EVENT_CLOSED))
      {
         result = PRODIGY_RESULT_OK;
         break;
      }
   }

   mesh_pingpong_close_fd(&state.listener_fd);
   mesh_pingpong_close_fd(&state.stream_fd);
   prodigy_io_uring_reactor_destroy(state.reactor);
   prodigy_neuron_hub_destroy(state.hub);
   return (result == PRODIGY_RESULT_OK) ? 0 : 1;
}

int main(int argc, char **argv)
{
   int exit_code = run(argc, argv);
   if (exit_code != 0)
   {
      fprintf(stderr, "mesh_pingpong failed\n");
   }
   return exit_code;
}
