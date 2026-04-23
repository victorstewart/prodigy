# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import abc
import asyncio
import ipaddress
import os
import socket
import struct
import sys
from dataclasses import dataclass, field
from enum import Enum, IntEnum, auto
from typing import Any, Awaitable, Iterable

from gxhash import GxHash64
from pyaegis import Aegis128L

SDK_VERSION = "1.0.0"
WIRE_SERIES = "WIRE_V1"
WIRE_PROTOCOL_VERSION = 1
AEGIS_ALIGNMENT = 16
AEGIS_HEADER_BYTES = 24
AEGIS_MAX_FRAME_BYTES = 2 * 1024 * 1024
AEGIS_MIN_FRAME_BYTES = 48
AEGIS_NONCE_BYTES = 16
AEGIS_PAIRING_HASH_SEED = 0x4D595DF4D0F33173
AEGIS_TAG_BYTES = 16


class ProtocolError(RuntimeError):
   pass


@dataclass(frozen=True)
class U128:
   bytes: bytes

   def __post_init__(self) -> None:
      if len(self.bytes) != 16:
         raise ValueError("u128 values must be 16 bytes")


@dataclass(frozen=True)
class IPAddress:
   address: bytes
   is_ipv6: bool

   def __post_init__(self) -> None:
      if len(self.address) != 16:
         raise ValueError("IP addresses must be 16 bytes")


@dataclass(frozen=True)
class IPPrefix:
   address: bytes
   cidr: int
   is_ipv6: bool

   def __post_init__(self) -> None:
      if len(self.address) != 16:
         raise ValueError("IP prefixes must be 16 bytes")


@dataclass(frozen=True)
class AdvertisedPort:
   service: int
   port: int


@dataclass(frozen=True)
class AdvertisementPairing:
   secret: U128
   address: U128
   service: int
   application_id: int
   activate: bool

   def ipv6_addr(self) -> ipaddress.IPv6Address:
      return ipaddress.IPv6Address(self.address.bytes)


@dataclass(frozen=True)
class SubscriptionPairing:
   secret: U128
   address: U128
   service: int
   port: int
   application_id: int
   activate: bool

   def ipv6_addr(self) -> ipaddress.IPv6Address:
      return ipaddress.IPv6Address(self.address.bytes)


@dataclass(frozen=True)
class ResourceDelta:
   logical_cores: int
   memory_mb: int
   storage_mb: int
   is_downscale: bool
   grace_seconds: int


@dataclass(frozen=True)
class MetricPair:
   key: int
   value: int


class ServiceRole(IntEnum):
   NONE = 0
   ADVERTISER = 1
   SUBSCRIBER = 2


@dataclass(frozen=True)
class MessageFrame:
   topic: "ContainerTopic"
   payload: bytes


@dataclass(frozen=True)
class TlsIdentity:
   name: str
   generation: int
   not_before_ms: int
   not_after_ms: int
   cert_pem: str
   key_pem: str
   chain_pem: str
   dns_sans: list[str] = field(default_factory=list)
   ip_sans: list[IPAddress] = field(default_factory=list)
   tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ApiCredential:
   name: str
   provider: str
   generation: int
   expires_at_ms: int
   active_from_ms: int
   sunset_at_ms: int
   material: str
   metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CredentialBundle:
   tls_identities: list[TlsIdentity] = field(default_factory=list)
   api_credentials: list[ApiCredential] = field(default_factory=list)
   bundle_generation: int = 0


@dataclass(frozen=True)
class CredentialDelta:
   bundle_generation: int = 0
   updated_tls: list[TlsIdentity] = field(default_factory=list)
   removed_tls_names: list[str] = field(default_factory=list)
   updated_api: list[ApiCredential] = field(default_factory=list)
   removed_api_names: list[str] = field(default_factory=list)
   reason: str = ""


@dataclass
class ContainerParameters:
   uuid: U128
   memory_mb: int
   storage_mb: int
   logical_cores: int
   neuron_fd: int
   low_cpu: int
   high_cpu: int
   advertises: list[AdvertisedPort] = field(default_factory=list)
   subscription_pairings: list[SubscriptionPairing] = field(default_factory=list)
   advertisement_pairings: list[AdvertisementPairing] = field(default_factory=list)
   private6: IPPrefix | None = None
   just_crashed: bool = False
   datacenter_unique_tag: int = 0
   flags: list[int] = field(default_factory=list)
   credential_bundle: CredentialBundle | None = None


@dataclass(frozen=True)
class AegisFrameHeader:
   size: int
   nonce: U128
   encrypted_data_size: int


@dataclass(frozen=True)
class AegisSession:
   secret: U128
   service: int
   role: ServiceRole = ServiceRole.NONE

   @classmethod
   def from_advertisement(cls, pairing: AdvertisementPairing) -> "AegisSession":
      return cls(secret=pairing.secret, service=pairing.service, role=ServiceRole.ADVERTISER)

   @classmethod
   def from_subscription(cls, pairing: SubscriptionPairing) -> "AegisSession":
      return cls(secret=pairing.secret, service=pairing.service, role=ServiceRole.SUBSCRIBER)

   def pairing_hash(self) -> int:
      data = self.secret.bytes + struct.pack("<Q", self.service)
      return GxHash64(seed=AEGIS_PAIRING_HASH_SEED).hash(data)

   def build_tfo_data(self, aux: bytes = b"") -> bytes:
      return struct.pack("<Q", self.pairing_hash()) + aux

   def encrypt(
      self,
      plaintext: bytes,
      *,
      nonce: U128 | None = None,
      into: bytearray | None = None,
   ) -> bytes:
      if nonce is None:
         nonce = U128(os.urandom(AEGIS_NONCE_BYTES))
      return self.encrypt_with_nonce(plaintext, nonce, into=into)

   def encrypt_with_nonce(
      self,
      plaintext: bytes,
      nonce: U128,
      *,
      into: bytearray | None = None,
   ) -> bytes:
      frame_bytes = aegis_frame_bytes_for_plaintext(len(plaintext))
      _validate_aegis_frame_bytes(frame_bytes)

      frame = into if into is not None else bytearray(frame_bytes)
      if len(frame) < frame_bytes:
         raise ValueError("provided Aegis output buffer is too small")

      encrypted_data_size = len(plaintext) + AEGIS_TAG_BYTES
      struct.pack_into("<I", frame, 0, frame_bytes)
      frame[4:20] = nonce.bytes
      struct.pack_into("<I", frame, 20, encrypted_data_size)

      _AEGIS_128L.encrypt(
         self.secret.bytes,
         nonce.bytes,
         plaintext,
         bytes(memoryview(frame)[:4]),
         into=memoryview(frame)[AEGIS_HEADER_BYTES:AEGIS_HEADER_BYTES + encrypted_data_size],
      )
      if frame_bytes > (AEGIS_HEADER_BYTES + encrypted_data_size):
         frame[AEGIS_HEADER_BYTES + encrypted_data_size:frame_bytes] = b"\0" * (
            frame_bytes - (AEGIS_HEADER_BYTES + encrypted_data_size)
         )
      return bytes(memoryview(frame)[:frame_bytes])

   def decrypt(self, frame: bytes, *, into: bytearray | None = None) -> tuple[bytes, AegisFrameHeader]:
      header = decode_aegis_frame_header(frame)
      plaintext = _AEGIS_128L.decrypt(
         self.secret.bytes,
         header.nonce.bytes,
         frame[AEGIS_HEADER_BYTES:AEGIS_HEADER_BYTES + header.encrypted_data_size],
         frame[:4],
         into=into,
      )
      return plaintext, header


class ContainerTopic(IntEnum):
   NONE = 0
   PING = 1
   PONG = 2
   STOP = 3
   ADVERTISEMENT_PAIRING = 4
   SUBSCRIPTION_PAIRING = 5
   HEALTHY = 6
   MESSAGE = 7
   RESOURCE_DELTA = 8
   DATACENTER_UNIQUE_TAG = 9
   STATISTICS = 10
   RESOURCE_DELTA_ACK = 11
   CREDENTIALS_REFRESH = 12


_CONTAINER_PARAMETERS_MAGIC = b"PRDPAR01"
_CREDENTIAL_BUNDLE_MAGIC = b"PRDBUN01"
_CREDENTIAL_DELTA_MAGIC = b"PRDDEL01"
_FRAME_HEADER = struct.Struct("<I H B B")
_METRIC_PAIR = struct.Struct("<Q Q")
_AEGIS_128L = Aegis128L(AEGIS_TAG_BYTES)


class _Reader:
   def __init__(self, data: bytes):
      self._data = memoryview(data)
      self._offset = 0

   def remaining(self) -> int:
      return len(self._data) - self._offset

   def done(self) -> bool:
      return self.remaining() == 0

   def raw(self, count: int) -> bytes:
      if count < 0 or count > self.remaining():
         raise ProtocolError("truncated payload")
      start = self._offset
      self._offset += count
      return bytes(self._data[start:self._offset])

   def expect(self, marker: bytes) -> None:
      if self.raw(len(marker)) != marker:
         raise ProtocolError("unexpected magic")

   def u8(self) -> int:
      return self.raw(1)[0]

   def boolean(self) -> bool:
      value = self.u8()
      if value not in (0, 1):
         raise ProtocolError("invalid boolean")
      return bool(value)

   def u16(self) -> int:
      return struct.unpack("<H", self.raw(2))[0]

   def u32(self) -> int:
      return struct.unpack("<I", self.raw(4))[0]

   def i32(self) -> int:
      return struct.unpack("<i", self.raw(4))[0]

   def u64(self) -> int:
      return struct.unpack("<Q", self.raw(8))[0]

   def i64(self) -> int:
      return struct.unpack("<q", self.raw(8))[0]

   def u128(self) -> U128:
      return U128(self.raw(16))

   def string(self) -> str:
      return self.raw(self.u32()).decode("utf-8")


class _Writer:
   def __init__(self):
      self._parts: list[bytes] = []

   def raw(self, value: bytes) -> None:
      self._parts.append(value)

   def u8(self, value: int) -> None:
      self.raw(struct.pack("<B", value))

   def boolean(self, value: bool) -> None:
      self.u8(1 if value else 0)

   def u16(self, value: int) -> None:
      self.raw(struct.pack("<H", value))

   def u32(self, value: int) -> None:
      self.raw(struct.pack("<I", value))

   def u64(self, value: int) -> None:
      self.raw(struct.pack("<Q", value))

   def string(self, value: str) -> None:
      encoded = value.encode("utf-8")
      self.u32(len(encoded))
      self.raw(encoded)

   def finish(self) -> bytes:
      return b"".join(self._parts)


def _decode_ip_address(reader: _Reader) -> IPAddress:
   return IPAddress(reader.raw(16), reader.boolean())


def _decode_ip_prefix(reader: _Reader) -> IPPrefix:
   address = _decode_ip_address(reader)
   return IPPrefix(address.address, reader.u8(), address.is_ipv6)


def _decode_string_array(reader: _Reader) -> list[str]:
   return [reader.string() for _ in range(reader.u32())]


def _decode_ip_address_array(reader: _Reader) -> list[IPAddress]:
   return [_decode_ip_address(reader) for _ in range(reader.u32())]


def _decode_tls_identity(reader: _Reader) -> TlsIdentity:
   return TlsIdentity(
      name=reader.string(),
      generation=reader.u64(),
      not_before_ms=reader.i64(),
      not_after_ms=reader.i64(),
      cert_pem=reader.string(),
      key_pem=reader.string(),
      chain_pem=reader.string(),
      dns_sans=_decode_string_array(reader),
      ip_sans=_decode_ip_address_array(reader),
      tags=_decode_string_array(reader),
   )


def _decode_api_credential(reader: _Reader) -> ApiCredential:
   metadata: dict[str, str] = {}
   name = reader.string()
   provider = reader.string()
   generation = reader.u64()
   expires_at_ms = reader.i64()
   active_from_ms = reader.i64()
   sunset_at_ms = reader.i64()
   material = reader.string()
   for _ in range(reader.u32()):
      key = reader.string()
      metadata[key] = reader.string()
   return ApiCredential(
      name=name,
      provider=provider,
      generation=generation,
      expires_at_ms=expires_at_ms,
      active_from_ms=active_from_ms,
      sunset_at_ms=sunset_at_ms,
      material=material,
      metadata=metadata,
   )


def _decode_credential_bundle_fields(reader: _Reader) -> CredentialBundle:
   tls_identities = [_decode_tls_identity(reader) for _ in range(reader.u32())]
   api_credentials = [_decode_api_credential(reader) for _ in range(reader.u32())]
   return CredentialBundle(
      tls_identities=tls_identities,
      api_credentials=api_credentials,
      bundle_generation=reader.u64(),
   )


def decode_credential_bundle(data: bytes) -> CredentialBundle:
   reader = _Reader(data)
   reader.expect(_CREDENTIAL_BUNDLE_MAGIC)
   bundle = _decode_credential_bundle_fields(reader)
   if not reader.done():
      raise ProtocolError("credential bundle has trailing bytes")
   return bundle


def decode_credential_delta(data: bytes) -> CredentialDelta:
   reader = _Reader(data)
   reader.expect(_CREDENTIAL_DELTA_MAGIC)
   delta = CredentialDelta(
      bundle_generation=reader.u64(),
      updated_tls=[_decode_tls_identity(reader) for _ in range(reader.u32())],
      removed_tls_names=_decode_string_array(reader),
      updated_api=[_decode_api_credential(reader) for _ in range(reader.u32())],
      removed_api_names=_decode_string_array(reader),
      reason=reader.string(),
   )
   if not reader.done():
      raise ProtocolError("credential delta has trailing bytes")
   return delta


def decode_container_parameters(data: bytes) -> ContainerParameters:
   reader = _Reader(data)
   reader.expect(_CONTAINER_PARAMETERS_MAGIC)

   params = ContainerParameters(
      uuid=reader.u128(),
      memory_mb=reader.u32(),
      storage_mb=reader.u32(),
      logical_cores=reader.u16(),
      neuron_fd=reader.i32(),
      low_cpu=reader.i32(),
      high_cpu=reader.i32(),
   )

   params.advertises = [AdvertisedPort(reader.u64(), reader.u16()) for _ in range(reader.u32())]
   params.subscription_pairings = [
      SubscriptionPairing(
         secret=reader.u128(),
         address=reader.u128(),
         service=(service := reader.u64()),
         port=reader.u16(),
         application_id=(service >> 48) & 0xFFFF,
         activate=True,
      )
      for _ in range(reader.u32())
   ]
   params.advertisement_pairings = [
      AdvertisementPairing(
         secret=reader.u128(),
         address=reader.u128(),
         service=(service := reader.u64()),
         application_id=(service >> 48) & 0xFFFF,
         activate=True,
      )
      for _ in range(reader.u32())
   ]
   params.private6 = _decode_ip_prefix(reader)
   params.just_crashed = reader.boolean()
   params.datacenter_unique_tag = reader.u8()
   params.flags = [reader.u64() for _ in range(reader.u32())]
   if reader.boolean():
      params.credential_bundle = _decode_credential_bundle_fields(reader)
   if not reader.done():
      raise ProtocolError("container parameters have trailing bytes")
   return params


def _read_all(fd: int) -> bytes:
   chunks: list[bytes] = []
   while True:
      chunk = os.read(fd, 65536)
      if not chunk:
         return b"".join(chunks)
      chunks.append(chunk)


def load_container_parameters_from_env_or_argv(
   argv: list[str] | None = None,
   env: dict[str, str] | None = None,
) -> ContainerParameters:
   if env is None:
      env = os.environ
   if argv is None:
      argv = sys.argv

   fd_text = env.get("PRODIGY_PARAMS_FD")
   if fd_text:
      fd = int(fd_text)
      try:
         os.lseek(fd, 0, os.SEEK_SET)
         return decode_container_parameters(_read_all(fd))
      finally:
         try:
            os.close(fd)
         except OSError:
            pass

   if len(argv) > 1:
      return decode_container_parameters(os.fsencode(argv[1]))

   raise ProtocolError("missing PRODIGY_PARAMS_FD and argv bootstrap payload")


def _read_exact(fd: int, count: int) -> bytes:
   data = bytearray()
   while len(data) < count:
      chunk = os.read(fd, count - len(data))
      if not chunk:
         raise EOFError("socket closed")
      data.extend(chunk)
   return bytes(data)


def _write_all(fd: int, data: bytes) -> None:
   view = memoryview(data)
   total = 0
   while total < len(view):
      written = os.write(fd, view[total:])
      if written <= 0:
         raise OSError("short write")
      total += written


def _build_frame(topic: ContainerTopic, payload: bytes = b"") -> bytes:
   padding = (-(_FRAME_HEADER.size + len(payload))) % 16
   size = _FRAME_HEADER.size + len(payload) + padding
   return _FRAME_HEADER.pack(size, int(topic), padding, _FRAME_HEADER.size) + payload + (b"\0" * padding)


def build_message_frame(topic: ContainerTopic, payload: bytes = b"") -> bytes:
   return _build_frame(topic, payload)


def build_ready_frame() -> bytes:
   return build_message_frame(ContainerTopic.HEALTHY)


def build_statistics_frame(metrics: Iterable[MetricPair]) -> bytes:
   return build_message_frame(ContainerTopic.STATISTICS, _encode_metric_pairs(metrics))


def build_resource_delta_ack_frame(accepted: bool) -> bytes:
   return build_message_frame(ContainerTopic.RESOURCE_DELTA_ACK, struct.pack("<B", 1 if accepted else 0))


def build_credentials_refresh_ack_frame() -> bytes:
   return build_message_frame(ContainerTopic.CREDENTIALS_REFRESH)


def aegis_frame_bytes_for_plaintext(plaintext_bytes: int) -> int:
   return (AEGIS_HEADER_BYTES + plaintext_bytes + AEGIS_TAG_BYTES + (AEGIS_ALIGNMENT - 1)) & ~(AEGIS_ALIGNMENT - 1)


def decode_aegis_frame_header(frame: bytes) -> AegisFrameHeader:
   if len(frame) < AEGIS_HEADER_BYTES:
      raise ProtocolError("Aegis frame is truncated")

   (size,) = struct.unpack_from("<I", frame, 0)
   _validate_aegis_frame_bytes(size)
   if len(frame) != size:
      raise ProtocolError("Aegis frame byte length does not match declared size")

   nonce = U128(bytes(frame[4:20]))
   (encrypted_data_size,) = struct.unpack_from("<I", frame, 20)
   if encrypted_data_size < AEGIS_TAG_BYTES:
      raise ProtocolError("Aegis encrypted payload is smaller than the authentication tag")
   if encrypted_data_size > (size - AEGIS_HEADER_BYTES):
      raise ProtocolError("Aegis encrypted payload exceeds the declared frame size")

   return AegisFrameHeader(
      size=size,
      nonce=nonce,
      encrypted_data_size=encrypted_data_size,
   )


def _validate_aegis_frame_bytes(frame_bytes: int) -> None:
   if frame_bytes < AEGIS_MIN_FRAME_BYTES:
      raise ProtocolError("Aegis frame is smaller than the minimum supported size")
   if frame_bytes > AEGIS_MAX_FRAME_BYTES:
      raise ProtocolError("Aegis frame exceeds the maximum supported size")
   if frame_bytes % AEGIS_ALIGNMENT != 0:
      raise ProtocolError("Aegis frame is not aligned to 16 bytes")


def parse_message_frame(data: bytes) -> MessageFrame:
   if len(data) < _FRAME_HEADER.size:
      raise ProtocolError("truncated frame")

   size, topic_raw, padding, header_size = _FRAME_HEADER.unpack(data[:_FRAME_HEADER.size])
   if header_size != _FRAME_HEADER.size:
      raise ProtocolError("unexpected frame header size")
   if size < header_size or size != len(data):
      raise ProtocolError("invalid frame size")
   if size % 16 != 0:
      raise ProtocolError("frame is not 16-byte padded")

   body = data[header_size:]
   if padding > len(body):
      raise ProtocolError("invalid frame padding")

   try:
      topic = ContainerTopic(topic_raw)
   except ValueError as exc:
      raise ProtocolError(f"unknown topic {topic_raw}") from exc

   return MessageFrame(topic, body[: len(body) - padding])


class FrameDecoder:
   def __init__(self) -> None:
      self._buffer = bytearray()

   def feed(self, data: bytes) -> list[MessageFrame]:
      self._buffer.extend(data)
      frames: list[MessageFrame] = []
      while True:
         frame = self._try_pop_frame()
         if frame is None:
            return frames
         frames.append(frame)

   def _try_pop_frame(self) -> MessageFrame | None:
      if len(self._buffer) < _FRAME_HEADER.size:
         return None

      size, topic_raw, padding, header_size = _FRAME_HEADER.unpack(self._buffer[:_FRAME_HEADER.size])
      if header_size != _FRAME_HEADER.size:
         raise ProtocolError("unexpected frame header size")
      if size < header_size:
         raise ProtocolError("invalid frame size")
      if size % 16 != 0:
         raise ProtocolError("frame is not 16-byte padded")
      if size > len(self._buffer):
         return None

      frame = bytes(self._buffer[:size])
      del self._buffer[:size]
      return parse_message_frame(frame)


def _read_frame(fd: int) -> tuple[ContainerTopic, bytes]:
   size, topic_raw, padding, header_size = _FRAME_HEADER.unpack(_read_exact(fd, _FRAME_HEADER.size))
   if header_size != _FRAME_HEADER.size:
      raise ProtocolError("unexpected frame header size")
   if size < header_size or padding >= size - header_size + 1:
      raise ProtocolError("invalid frame size")
   if size % 16 != 0:
      raise ProtocolError("frame is not 16-byte padded")

   body = _read_exact(fd, size - header_size)
   payload_size = size - header_size - padding
   if payload_size < 0:
      raise ProtocolError("negative payload size")
   try:
      topic = ContainerTopic(topic_raw)
   except ValueError as exc:
      raise ProtocolError(f"unknown topic {topic_raw}") from exc
   return topic, body[:payload_size]


def _encode_metric_pairs(metrics: Iterable[MetricPair]) -> bytes:
   writer = _Writer()
   for metric in metrics:
      writer.u64(metric.key)
      writer.u64(metric.value)
   return writer.finish()


def _decode_metric_pairs(payload: bytes) -> list[MetricPair]:
   if len(payload) % _METRIC_PAIR.size != 0:
      raise ProtocolError("statistics payload is not pair aligned")
   return [
      MetricPair(*_METRIC_PAIR.unpack_from(payload, offset))
      for offset in range(0, len(payload), _METRIC_PAIR.size)
   ]


class NeuronHubDispatch(abc.ABC):
   def end_of_dynamic_args(self, hub: "NeuronHub") -> None:
      del hub

   @abc.abstractmethod
   def begin_shutdown(self, hub: "NeuronHub") -> None:
      raise NotImplementedError

   def advertisement_pairing(self, hub: "NeuronHub", pairing: AdvertisementPairing) -> None:
      del hub, pairing

   def subscription_pairing(self, hub: "NeuronHub", pairing: SubscriptionPairing) -> None:
      del hub, pairing

   def resource_delta(self, hub: "NeuronHub", delta: ResourceDelta) -> None:
      del hub, delta

   def credentials_refresh(self, hub: "NeuronHub", delta: CredentialDelta) -> None:
      del hub, delta

   def message_from_prodigy(self, hub: "NeuronHub", payload: bytes) -> None:
      del hub, payload


class DefaultDispatch(NeuronHubDispatch):
   def begin_shutdown(self, hub: "NeuronHub") -> None:
      del hub


class NeuronHub:
   def __init__(
      self,
      dispatch: NeuronHubDispatch,
      parameters: ContainerParameters,
      fd: int | None = None,
      owns_transport: bool = True,
   ):
      self.dispatch = dispatch
      self.parameters = parameters
      self.fd = parameters.neuron_fd if fd is None else fd
      self._owns_transport = owns_transport
      if self.fd < 0:
         raise ValueError("invalid neuron fd")

   @classmethod
   def from_env_or_argv(
      cls,
      dispatch: NeuronHubDispatch,
      argv: list[str] | None = None,
      env: dict[str, str] | None = None,
      fd: int | None = None,
   ) -> "NeuronHub":
      return cls(dispatch, load_container_parameters_from_env_or_argv(argv=argv, env=env), fd=fd)

   @classmethod
   def for_event_loop(
      cls,
      dispatch: NeuronHubDispatch,
      parameters: ContainerParameters,
      fd: int | None = None,
   ) -> "NeuronHub":
      return cls.borrowed_transport(dispatch, parameters, fd=fd)

   @classmethod
   def borrowed_transport(
      cls,
      dispatch: NeuronHubDispatch,
      parameters: ContainerParameters,
      fd: int | None = None,
   ) -> "NeuronHub":
      return cls(dispatch, parameters, fd=fd, owns_transport=False)

   @classmethod
   def from_env_or_argv_for_event_loop(
      cls,
      dispatch: NeuronHubDispatch,
      argv: list[str] | None = None,
      env: dict[str, str] | None = None,
      fd: int | None = None,
   ) -> "NeuronHub":
      return cls.from_env_or_argv_borrowed_transport(
         dispatch,
         argv=argv,
         env=env,
         fd=fd,
      )

   @classmethod
   def from_env_or_argv_borrowed_transport(
      cls,
      dispatch: NeuronHubDispatch,
      argv: list[str] | None = None,
      env: dict[str, str] | None = None,
      fd: int | None = None,
   ) -> "NeuronHub":
      return cls.borrowed_transport(
         dispatch,
         load_container_parameters_from_env_or_argv(argv=argv, env=env),
         fd=fd,
      )

   def close(self) -> None:
      if self._owns_transport:
         os.close(self.fd)

   def _send(self, topic: ContainerTopic, payload: bytes = b"") -> None:
      _write_all(self.fd, _build_frame(topic, payload))

   def send_frame(self, frame: MessageFrame) -> None:
      self._send(frame.topic, frame.payload)

   def signal_ready(self) -> None:
      self._send(ContainerTopic.HEALTHY)

   def publish_statistic(self, metric: MetricPair) -> None:
      self.publish_statistics([metric])

   def publish_statistics(self, metrics: Iterable[MetricPair]) -> None:
      self._send(ContainerTopic.STATISTICS, _encode_metric_pairs(metrics))

   def acknowledge_resource_delta(self, accepted: bool) -> None:
      self._send(ContainerTopic.RESOURCE_DELTA_ACK, struct.pack("<B", 1 if accepted else 0))

   def acknowledge_credentials_refresh(self) -> None:
      self._send(ContainerTopic.CREDENTIALS_REFRESH)

   def handle_frame(self, frame: MessageFrame) -> list[MessageFrame]:
      topic = frame.topic
      payload = frame.payload
      outbound: list[MessageFrame] = []
      if topic == ContainerTopic.NONE:
         self.dispatch.end_of_dynamic_args(self)
      elif topic == ContainerTopic.PING:
         outbound.append(MessageFrame(ContainerTopic.PING, b""))
      elif topic == ContainerTopic.STOP:
         self.dispatch.begin_shutdown(self)
      elif topic == ContainerTopic.ADVERTISEMENT_PAIRING:
         reader = _Reader(payload)
         pairing = AdvertisementPairing(
            secret=reader.u128(),
            address=reader.u128(),
            service=reader.u64(),
            application_id=reader.u16(),
            activate=reader.boolean(),
         )
         if not reader.done():
            raise ProtocolError("advertisement pairing has trailing bytes")
         self.dispatch.advertisement_pairing(self, pairing)
      elif topic == ContainerTopic.SUBSCRIPTION_PAIRING:
         reader = _Reader(payload)
         pairing = SubscriptionPairing(
            secret=reader.u128(),
            address=reader.u128(),
            service=reader.u64(),
            port=reader.u16(),
            application_id=reader.u16(),
            activate=reader.boolean(),
         )
         if not reader.done():
            raise ProtocolError("subscription pairing has trailing bytes")
         self.dispatch.subscription_pairing(self, pairing)
      elif topic == ContainerTopic.RESOURCE_DELTA:
         reader = _Reader(payload)
         delta = ResourceDelta(
            logical_cores=reader.u16(),
            memory_mb=reader.u32(),
            storage_mb=reader.u32(),
            is_downscale=reader.boolean(),
            grace_seconds=reader.u32(),
         )
         if not reader.done():
            raise ProtocolError("resource delta has trailing bytes")
         self.dispatch.resource_delta(self, delta)
      elif topic == ContainerTopic.DATACENTER_UNIQUE_TAG:
         reader = _Reader(payload)
         self.parameters.datacenter_unique_tag = reader.u8()
         if not reader.done():
            raise ProtocolError("datacenter tag has trailing bytes")
      elif topic == ContainerTopic.MESSAGE:
         self.dispatch.message_from_prodigy(self, payload)
      elif topic == ContainerTopic.CREDENTIALS_REFRESH:
         if payload:
            self.dispatch.credentials_refresh(self, decode_credential_delta(payload))
      elif topic in (ContainerTopic.PONG, ContainerTopic.HEALTHY, ContainerTopic.STATISTICS, ContainerTopic.RESOURCE_DELTA_ACK):
         pass
      else:
         raise ProtocolError(f"unsupported inbound topic {int(topic)}")
      return outbound

   def run_once(self) -> ContainerTopic:
      frame = MessageFrame(*_read_frame(self.fd))
      for outbound in self.handle_frame(frame):
         self.send_frame(outbound)
      return frame.topic

   def run_forever(self) -> None:
      while True:
         self.run_once()


class NeuronEvent(Enum):
   SHUTDOWN = auto()
   CLOSED = auto()


@dataclass(frozen=True)
class ReactorEvent:
   app: Any | None = None
   neuron: NeuronEvent | None = None


class ReactorSink:
   def __init__(self, queue: asyncio.Queue[ReactorEvent | BaseException]):
      self._queue = queue

   async def app(self, event: Any) -> None:
      await self._queue.put(ReactorEvent(app=event))

   async def _neuron(self, event: NeuronEvent) -> None:
      await self._queue.put(ReactorEvent(neuron=event))

   async def _error(self, error: BaseException) -> None:
      await self._queue.put(error)


class AsyncioReactor:
   def __init__(self):
      self._queue: asyncio.Queue[ReactorEvent | BaseException] = asyncio.Queue()

   def sink(self) -> ReactorSink:
      return ReactorSink(self._queue)

   def source(self, awaitable: Awaitable[Any]) -> asyncio.Task[None]:
      async def _runner() -> None:
         sink = self.sink()
         try:
            await sink.app(await awaitable)
         except BaseException as error:
            await sink._error(error)

      return asyncio.create_task(_runner())

   def once(self, event: Any, awaitable: Awaitable[Any]) -> asyncio.Task[None]:
      async def _emit() -> Any:
         await awaitable
         return event

      return self.source(_emit())

   def attach_neuron(self, neuron: "AsyncioNeuron") -> "AsyncioNeuronHandle":
      return neuron._attach(self.sink())

   async def next(self) -> ReactorEvent:
      event = await self._queue.get()
      if isinstance(event, BaseException):
         raise event
      return event


class _AsyncioDispatchAdapter(NeuronHubDispatch):
   def __init__(self, inner: NeuronHubDispatch):
      self._inner = inner
      self.owner: AsyncioNeuron | None = None

   def end_of_dynamic_args(self, hub: NeuronHub) -> None:
      self._inner.end_of_dynamic_args(hub)

   def begin_shutdown(self, hub: NeuronHub) -> None:
      if self.owner is not None:
         self.owner._shutdown_requested = True
      self._inner.begin_shutdown(hub)

   def advertisement_pairing(self, hub: NeuronHub, pairing: AdvertisementPairing) -> None:
      self._inner.advertisement_pairing(hub, pairing)

   def subscription_pairing(self, hub: NeuronHub, pairing: SubscriptionPairing) -> None:
      self._inner.subscription_pairing(hub, pairing)

   def resource_delta(self, hub: NeuronHub, delta: ResourceDelta) -> None:
      if self.owner is not None and self.owner._auto_ack_resource_delta is not None:
         hub.acknowledge_resource_delta(self.owner._auto_ack_resource_delta)
      self._inner.resource_delta(hub, delta)

   def credentials_refresh(self, hub: NeuronHub, delta: CredentialDelta) -> None:
      if self.owner is not None and self.owner._auto_ack_credentials_refresh:
         hub.acknowledge_credentials_refresh()
      self._inner.credentials_refresh(hub, delta)

   def message_from_prodigy(self, hub: NeuronHub, payload: bytes) -> None:
      self._inner.message_from_prodigy(hub, payload)


class AsyncioNeuron:
   def __init__(self, dispatch: NeuronHubDispatch, parameters: ContainerParameters, fd: int | None = None):
      self._dispatch = _AsyncioDispatchAdapter(dispatch)
      self.hub = NeuronHub.borrowed_transport(self._dispatch, parameters, fd=fd)
      self._dispatch.owner = self
      self._socket = socket.socket(fileno=self.hub.fd)
      self._socket.setblocking(False)
      self._decoder = FrameDecoder()
      self._shutdown_requested = False
      self._auto_ack_resource_delta: bool | None = None
      self._auto_ack_credentials_refresh = False

   @classmethod
   def from_env_or_argv(
      cls,
      dispatch: NeuronHubDispatch,
      argv: list[str] | None = None,
      env: dict[str, str] | None = None,
      fd: int | None = None,
   ) -> "AsyncioNeuron":
      return cls(dispatch, load_container_parameters_from_env_or_argv(argv=argv, env=env), fd=fd)

   def with_resource_delta_ack(self, accepted: bool) -> "AsyncioNeuron":
      self._auto_ack_resource_delta = accepted
      return self

   def with_credentials_refresh_ack(self) -> "AsyncioNeuron":
      self._auto_ack_credentials_refresh = True
      return self

   def with_auto_acks(self) -> "AsyncioNeuron":
      return self.with_resource_delta_ack(True).with_credentials_refresh_ack()

   def parameters(self) -> ContainerParameters:
      return self.hub.parameters

   async def _run(self, commands: "asyncio.Queue[str]", sink: ReactorSink) -> None:
      loop = asyncio.get_running_loop()
      while True:
         recv_task = asyncio.create_task(loop.sock_recv(self._socket, 4096))
         command_task = asyncio.create_task(commands.get())
         done, pending = await asyncio.wait(
            {recv_task, command_task},
            return_when=asyncio.FIRST_COMPLETED,
         )
         for task in pending:
            task.cancel()

         if recv_task in done:
            data = recv_task.result()
            if not data:
               await sink._neuron(NeuronEvent.CLOSED)
               return
            for frame in self._decoder.feed(data):
               for outbound in self.hub.handle_frame(frame):
                  self.hub.send_frame(outbound)
            if self._shutdown_requested:
               await sink._neuron(NeuronEvent.SHUTDOWN)
               return

         if command_task in done:
            if command_task.result() == "ready":
               self.hub.signal_ready()

   def _attach(self, sink: ReactorSink) -> "AsyncioNeuronHandle":
      commands: asyncio.Queue[str] = asyncio.Queue()

      async def _runner() -> None:
         try:
            await self._run(commands, sink)
         except BaseException as error:
            await sink._error(error)

      asyncio.create_task(_runner())
      return AsyncioNeuronHandle(self.hub.parameters, commands)


class AsyncioNeuronHandle:
   def __init__(self, parameters: ContainerParameters, commands: "asyncio.Queue[str]"):
      self._parameters = parameters
      self._commands = commands
      self._ready_sent = False

   def parameters(self) -> ContainerParameters:
      return self._parameters

   async def ready(self) -> None:
      if self._ready_sent:
         return
      await self._commands.put("ready")
      self._ready_sent = True
