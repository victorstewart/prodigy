# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import ipaddress
import socket
from enum import Enum, auto

from prodigy_sdk import (
   AegisSession,
   AdvertisementPairing,
   AsyncioNeuron,
   AsyncioReactor,
   ContainerParameters,
   CredentialDelta,
   DefaultDispatch,
   MetricPair,
   NeuronHub,
   NeuronEvent,
   ReactorEvent,
   ResourceDelta,
   SubscriptionPairing,
   TlsIdentity,
)

PING_COUNT = 3
PING_TIMEOUT_SECONDS = 5.0
CONNECT_TIMEOUT_SECONDS = 10.0
STAT_PAIRINGS = 1
STAT_ACTIVE_PAIRINGS = 2
STAT_RESOURCE_DELTAS = 3
STAT_CREDENTIAL_REFRESHES = 4
STAT_DATACENTER_TAG = 5


class Role(Enum):
   ADVERTISER = auto()
   SUBSCRIBER = auto()


def advertisement_key(pairing: AdvertisementPairing) -> tuple[int, int, bytes]:
   return pairing.service, pairing.application_id, pairing.address.bytes


def subscription_key(pairing: SubscriptionPairing) -> tuple[int, int, int, bytes]:
   return pairing.service, pairing.port, pairing.application_id, pairing.address.bytes


class MeshDispatch(DefaultDispatch):
   def __init__(self) -> None:
      self.advertisements: asyncio.Queue[AdvertisementPairing] = asyncio.Queue()
      self.subscriptions: asyncio.Queue[SubscriptionPairing] = asyncio.Queue()
      self.pairing_events = 0
      self.resource_delta_events = 0
      self.credentials_refresh_events = 0
      self._active_advertisements: dict[tuple[int, int, bytes], AdvertisementPairing] = {}
      self._active_subscriptions: dict[tuple[int, int, int, bytes], SubscriptionPairing] = {}
      self._tls_identities: dict[str, TlsIdentity] = {}

   def seed(self, parameters: ContainerParameters) -> None:
      if parameters.credential_bundle is not None:
         self._tls_identities = {identity.name: identity for identity in parameters.credential_bundle.tls_identities}
      for pairing in parameters.advertisement_pairings:
         self._track_advertisement(pairing)
      for pairing in parameters.subscription_pairings:
         self._track_subscription(pairing)

   def publish_stats(self, hub: NeuronHub) -> None:
      hub.publish_statistics([
         MetricPair(STAT_PAIRINGS, self.pairing_events),
         MetricPair(STAT_ACTIVE_PAIRINGS, len(self._active_advertisements) + len(self._active_subscriptions)),
         MetricPair(STAT_RESOURCE_DELTAS, self.resource_delta_events),
         MetricPair(STAT_CREDENTIAL_REFRESHES, self.credentials_refresh_events),
         MetricPair(STAT_DATACENTER_TAG, hub.parameters.datacenter_unique_tag),
      ])

   def advertisement_pairing(self, hub: NeuronHub, pairing: AdvertisementPairing) -> None:
      self._track_advertisement(pairing)
      self.publish_stats(hub)

   def subscription_pairing(self, hub: NeuronHub, pairing: SubscriptionPairing) -> None:
      self._track_subscription(pairing)
      self.publish_stats(hub)

   def resource_delta(self, hub: NeuronHub, delta: ResourceDelta) -> None:
      del delta
      self.resource_delta_events += 1
      hub.acknowledge_resource_delta(True)
      self.publish_stats(hub)

   def credentials_refresh(self, hub: NeuronHub, delta: CredentialDelta) -> None:
      for name in delta.removed_tls_names:
         self._tls_identities.pop(name, None)
      for identity in delta.updated_tls:
         self._tls_identities[identity.name] = identity
      self.credentials_refresh_events += 1
      hub.acknowledge_credentials_refresh()
      self.publish_stats(hub)

   def advertisement_for_peer(self, peer_address: str | None) -> AdvertisementPairing | None:
      if peer_address is not None:
         try:
            address = ipaddress.IPv6Address(peer_address.split("%", 1)[0]).packed
         except ValueError:
            address = b""
         if address:
            for pairing in self._active_advertisements.values():
               if pairing.address.bytes == address:
                  return pairing
      return next(iter(self._active_advertisements.values()), None)

   def _track_advertisement(self, pairing: AdvertisementPairing) -> None:
      self.pairing_events += 1
      if pairing.activate:
         self._active_advertisements[advertisement_key(pairing)] = pairing
         self.advertisements.put_nowait(pairing)
      else:
         self._active_advertisements.pop(advertisement_key(pairing), None)

   def _track_subscription(self, pairing: SubscriptionPairing) -> None:
      self.pairing_events += 1
      if pairing.activate:
         self._active_subscriptions[subscription_key(pairing)] = pairing
         self.subscriptions.put_nowait(pairing)
      else:
         self._active_subscriptions.pop(subscription_key(pairing), None)


async def next_active_pairing(queue: "asyncio.Queue[AdvertisementPairing | SubscriptionPairing]") -> AdvertisementPairing | SubscriptionPairing:
   while True:
      pairing = await queue.get()
      if pairing.activate:
         return pairing


async def start_advertiser_server(
   port: int,
   dispatch: MeshDispatch,
) -> tuple[asyncio.AbstractServer, asyncio.Future[Role]]:
   loop = asyncio.get_running_loop()
   completed: asyncio.Future[Role] = loop.create_future()

   async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
      try:
         peer = writer.get_extra_info("peername")
         peer_address = peer[0] if isinstance(peer, tuple) and peer else None
         pairing = dispatch.advertisement_for_peer(peer_address)
         if pairing is None:
            return
         session = AegisSession.from_advertisement(pairing)
         for index in range(PING_COUNT):
            frame = await asyncio.wait_for(read_aegis_frame(reader), timeout=PING_TIMEOUT_SECONDS)
            plaintext, _ = session.decrypt(frame)
            if plaintext != f"ping {index}\n".encode():
               raise RuntimeError(f"unexpected ping payload {plaintext!r}")
            writer.write(session.encrypt(f"pong {index}\n".encode()))
            await writer.drain()
         if not completed.done():
            completed.set_result(Role.ADVERTISER)
      except BaseException as error:
         if not completed.done():
            completed.set_exception(error)
      finally:
         writer.close()
         await writer.wait_closed()

   server = await asyncio.start_server(handle, host="::", port=port, family=socket.AF_INET6)
   return server, completed


async def run_advertiser_server(server: asyncio.AbstractServer, completed: asyncio.Future[Role]) -> Role:
   try:
      return await completed
   finally:
      server.close()
      await server.wait_closed()


async def run_subscriber(pairing: SubscriptionPairing) -> Role:
   loop = asyncio.get_running_loop()
   deadline = loop.time() + CONNECT_TIMEOUT_SECONDS
   session = AegisSession.from_subscription(pairing)
   last_error: BaseException | None = None

   while loop.time() < deadline:
      writer: asyncio.StreamWriter | None = None
      try:
         reader, writer = await asyncio.wait_for(
            asyncio.open_connection(str(pairing.ipv6_addr()), pairing.port, family=socket.AF_INET6),
            timeout=1.0,
         )
         for index in range(PING_COUNT):
            writer.write(session.encrypt(f"ping {index}\n".encode()))
            await writer.drain()
            frame = await asyncio.wait_for(read_aegis_frame(reader), timeout=PING_TIMEOUT_SECONDS)
            plaintext, _ = session.decrypt(frame)
            if plaintext != f"pong {index}\n".encode():
               raise RuntimeError(f"unexpected pong payload {plaintext!r}")
         return Role.SUBSCRIBER
      except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionRefusedError, OSError, RuntimeError) as error:
         last_error = error
         await asyncio.sleep(0.25)
      finally:
         if writer is not None:
            writer.close()
            await writer.wait_closed()

   raise RuntimeError(f"timed out connecting to [{pairing.ipv6_addr()}]:{pairing.port}") from last_error


async def main() -> None:
   dispatch = MeshDispatch()
   reactor = AsyncioReactor()
   async_neuron = AsyncioNeuron.from_env_or_argv(dispatch)
   neuron = reactor.attach_neuron(async_neuron)
   parameters = neuron.parameters()
   dispatch.seed(parameters)
   dispatch.publish_stats(async_neuron.hub)
   role = Role.ADVERTISER if parameters.advertises else Role.SUBSCRIBER

   pairing_seen = False
   mesh_complete = False
   mesh_started = role is Role.ADVERTISER
   ready_sent = False

   if role is Role.ADVERTISER:
      server, completed = await start_advertiser_server(
         parameters.advertises[0].port,
         dispatch,
      )
      await neuron.ready()
      ready_sent = True
      reactor.source(next_active_pairing(dispatch.advertisements))
      reactor.source(run_advertiser_server(server, completed))
   else:
      reactor.source(next_active_pairing(dispatch.subscriptions))

   while True:
      event = await reactor.next()
      match event:
         case ReactorEvent(app=AdvertisementPairing()):
            pairing_seen = True
         case ReactorEvent(app=SubscriptionPairing() as pairing):
            pairing_seen = True
            if role is Role.SUBSCRIBER and not mesh_started:
               mesh_started = True
               reactor.source(run_subscriber(pairing))
         case ReactorEvent(app=Role.ADVERTISER | Role.SUBSCRIBER):
            mesh_complete = True
         case ReactorEvent(neuron=NeuronEvent.SHUTDOWN | NeuronEvent.CLOSED):
            return

      if not ready_sent and pairing_seen and mesh_complete:
         await neuron.ready()
         ready_sent = True


async def read_aegis_frame(reader: asyncio.StreamReader) -> bytes:
   prefix = await reader.readexactly(4)
   size = int.from_bytes(prefix, "little")
   if size < 48 or size > (2 * 1024 * 1024) or (size % 16) != 0:
      raise RuntimeError(f"invalid Aegis frame size {size}")
   return prefix + await reader.readexactly(size - 4)

if __name__ == "__main__":
   asyncio.run(main())
