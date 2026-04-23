# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import socket
import struct

import neuron_hub as prodigy


def fixture_bytes(name: str) -> bytes:
   return (Path(__file__).resolve().parent.parent.parent / "fixtures" / name).read_bytes()


def encode_demo_current_container_parameters() -> bytes:
   writer = prodigy._Writer()
   writer.raw(b"PRDPAR01")
   writer.raw(bytes(range(16)))
   writer.u32(1024)
   writer.u32(2048)
   writer.u16(3)
   writer.raw(struct.pack("<i", 9))
   writer.raw(struct.pack("<i", 1))
   writer.raw(struct.pack("<i", 3))
   writer.u32(1)
   writer.u64(0x1122334455667788)
   writer.u16(19111)
   writer.u32(1)
   writer.raw(bytes(range(16, 32)))
   writer.raw(bytes(range(32, 48)))
   writer.u64(0x1234000000000001)
   writer.u16(3210)
   writer.u32(1)
   writer.raw(bytes(range(48, 64)))
   writer.raw(bytes(range(64, 80)))
   writer.u64(0x5678000000000002)
   writer.raw(bytes([0xFD]) + (b"\0" * 15))
   writer.boolean(True)
   writer.u8(64)
   writer.boolean(False)
   writer.u8(17)
   writer.u32(2)
   writer.u64(44)
   writer.u64(55)
   writer.boolean(False)
   return writer.finish()


def demo_subscription_pairing() -> prodigy.SubscriptionPairing:
   return prodigy.SubscriptionPairing(
      secret=prodigy.U128(
         bytes=bytes([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
         ])
      ),
      address=prodigy.U128(
         bytes=bytes([
            0xFD, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
         ])
      ),
      service=0x2233000000001001,
      port=3210,
      application_id=0x2233,
      activate=True,
   )


def test_fixture_decoders() -> prodigy.ContainerParameters:
   bundle = prodigy.decode_credential_bundle(fixture_bytes("startup.credential_bundle.full.bin"))
   assert bundle.bundle_generation == 101
   assert bundle.tls_identities[0].name == "demo-cert"
   assert bundle.api_credentials[0].metadata["scope"] == "demo"

   delta = prodigy.decode_credential_delta(fixture_bytes("startup.credential_delta.full.bin"))
   assert delta.bundle_generation == 102
   assert delta.removed_tls_names == ["legacy-cert"]
   assert delta.removed_api_names == ["legacy-token"]
   assert delta.reason == "fixture-rotation"

   params = prodigy.decode_container_parameters(fixture_bytes("startup.container_parameters.full.bin"))
   assert params.memory_mb == 1536
   assert params.advertises[0].port == 24001
   assert params.subscription_pairings[0].application_id == 0x2233
   assert params.advertisement_pairings[0].application_id == 0x3344
   assert params.datacenter_unique_tag == 23
   assert params.credential_bundle is not None
   assert params.credential_bundle.bundle_generation == 101

   current_params = prodigy.decode_container_parameters(encode_demo_current_container_parameters())
   assert current_params.memory_mb == 1024
   assert current_params.just_crashed is False
   return params


def test_frame_helpers(params: prodigy.ContainerParameters) -> None:
   frame = fixture_bytes("frame.resource_delta_ack.accepted.bin")
   size, topic, padding, header_size = prodigy._FRAME_HEADER.unpack(frame[:prodigy._FRAME_HEADER.size])
   assert size == len(frame)
   assert topic == int(prodigy.ContainerTopic.RESOURCE_DELTA_ACK)
   assert header_size == prodigy._FRAME_HEADER.size
   assert padding == len(frame) - prodigy._FRAME_HEADER.size - 1
   assert prodigy._decode_metric_pairs(fixture_bytes("payload.statistics.demo.bin")) == [
      prodigy.MetricPair(1, 2),
      prodigy.MetricPair(3, 4),
   ]
   assert prodigy.build_ready_frame() == fixture_bytes("frame.healthy.empty.bin")
   assert prodigy.build_statistics_frame([prodigy.MetricPair(1, 2), prodigy.MetricPair(3, 4)]) == fixture_bytes("frame.statistics.demo.bin")
   assert prodigy.build_resource_delta_ack_frame(True) == fixture_bytes("frame.resource_delta_ack.accepted.bin")
   assert prodigy.build_credentials_refresh_ack_frame() == fixture_bytes("frame.credentials_refresh_ack.empty.bin")

   decoder = prodigy.FrameDecoder()
   ping = prodigy.build_message_frame(prodigy.ContainerTopic.PING)
   assert decoder.feed(ping[:3]) == []
   decoded = decoder.feed(ping[3:])
   assert len(decoded) == 1

   class Dispatch(prodigy.NeuronHubDispatch):
      def begin_shutdown(self, hub: prodigy.NeuronHub) -> None:
         del hub

   borrowed_fd = os.open(os.devnull, os.O_RDONLY)
   hub = prodigy.NeuronHub.borrowed_transport(Dispatch(), params, fd=borrowed_fd)
   hub.close()
   os.fstat(borrowed_fd)
   outbound = hub.handle_frame(decoded[0])
   assert outbound == [prodigy.MessageFrame(prodigy.ContainerTopic.PING, b"")]
   os.close(borrowed_fd)


def test_aegis_vectors() -> None:
   session = prodigy.AegisSession.from_subscription(demo_subscription_pairing())
   assert session.pairing_hash().to_bytes(8, "little") == fixture_bytes("aegis.hash.demo.bin")
   assert session.build_tfo_data(b"mesh-aegis") == fixture_bytes("aegis.tfo.demo.bin")

   frame = session.encrypt_with_nonce(
      b"frame-one",
      prodigy.U128(bytes=bytes([
         0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
         0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
      ])),
   )
   assert frame == fixture_bytes("aegis.frame.demo.bin")

   plaintext, header = session.decrypt(frame)
   assert plaintext == b"frame-one"
   assert header.size == len(frame)
   assert header.encrypted_data_size == len(b"frame-one") + prodigy.AEGIS_TAG_BYTES

   malformed = bytearray(frame)
   malformed[0] = 0
   try:
      prodigy.decode_aegis_frame_header(bytes(malformed))
   except prodigy.ProtocolError:
      pass
   else:
      raise AssertionError("decode_aegis_frame_header accepted malformed frame")


async def test_reactor(params: prodigy.ContainerParameters) -> None:
   reactor = prodigy.AsyncioReactor()
   app_event = object()
   source_event = object()
   neuron_a, neuron_b = socket.socketpair()
   try:
      neuron_a.setblocking(False)
      neuron_b.setblocking(False)
      handle = reactor.attach_neuron(
         prodigy.AsyncioNeuron(prodigy.DefaultDispatch(), params, fd=neuron_a.detach()).with_auto_acks()
      )
      reactor.source(asyncio.sleep(0, result=source_event))
      event = await reactor.next()
      assert event.app is source_event
      reactor.once(app_event, asyncio.sleep(0))
      event = await reactor.next()
      assert event.app is app_event
      await handle.ready()
      frame = await asyncio.wait_for(
         asyncio.get_running_loop().sock_recv(neuron_b, 16),
         timeout=1.0,
      )
      assert prodigy.parse_message_frame(frame).topic == prodigy.ContainerTopic.HEALTHY
      neuron_b.sendall(prodigy.build_message_frame(prodigy.ContainerTopic.STOP))
      event = await reactor.next()
      assert event.neuron == prodigy.NeuronEvent.SHUTDOWN
   finally:
      neuron_b.close()


def main() -> None:
   params = test_fixture_decoders()
   test_frame_helpers(params)
   test_aegis_vectors()
   asyncio.run(test_reactor(params))
   print("python prodigy-sdk tests passed")


if __name__ == "__main__":
   main()
