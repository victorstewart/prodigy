// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

import * as fs from "node:fs"
import * as net from "node:net"
import { randomBytes } from "node:crypto"
import process from "node:process"
import { aegis128l } from "aegis-ts/aegis128l.js"

export const SDK_VERSION = "1.0.0"
export const WIRE_SERIES = "WIRE_V1"
export const WIRE_PROTOCOL_VERSION = 1
export const AEGIS_ALIGNMENT = 16
export const AEGIS_HEADER_BYTES = 24
export const AEGIS_MAX_FRAME_BYTES = 2 * 1024 * 1024
export const AEGIS_MIN_FRAME_BYTES = 48
export const AEGIS_NONCE_BYTES = 16
export const AEGIS_PAIRING_HASH_SEED = 0x4d595df4d0f33173n
export const AEGIS_TAG_BYTES = 16

const CONTAINER_PARAMETERS_MAGIC = Buffer.from("PRDPAR01", "ascii")
const CREDENTIAL_BUNDLE_MAGIC = Buffer.from("PRDBUN01", "ascii")
const CREDENTIAL_DELTA_MAGIC = Buffer.from("PRDDEL01", "ascii")
const FRAME_HEADER_SIZE = 8
const FRAME_ALIGNMENT = 16
const METRIC_PAIR_SIZE = 16

export class ProtocolError extends Error
{
   constructor(message: string)
   {
      super(message)
      this.name = "ProtocolError"
   }
}

export class U128
{
   readonly bytes: Uint8Array

   constructor(bytes: Uint8Array)
   {
      if (bytes.length !== 16)
      {
         throw new TypeError("u128 values must be 16 bytes")
      }

      this.bytes = Uint8Array.from(bytes)
   }
}

export class IPAddress
{
   readonly address: Uint8Array
   readonly isIPv6: boolean

   constructor(address: Uint8Array, isIPv6: boolean)
   {
      if (address.length !== 16)
      {
         throw new TypeError("IP addresses must be 16 bytes")
      }

      this.address = Uint8Array.from(address)
      this.isIPv6 = isIPv6
   }
}

export class IPPrefix
{
   readonly address: Uint8Array
   readonly cidr: number
   readonly isIPv6: boolean

   constructor(address: Uint8Array, cidr: number, isIPv6: boolean)
   {
      if (address.length !== 16)
      {
         throw new TypeError("IP prefixes must be 16 bytes")
      }

      this.address = Uint8Array.from(address)
      this.cidr = cidr
      this.isIPv6 = isIPv6
   }
}

export interface AdvertisedPort
{
   service: bigint
   port: number
}

export interface AdvertisementPairing
{
   secret: U128
   address: U128
   service: bigint
   applicationId: number
   activate: boolean
}

export interface SubscriptionPairing
{
   secret: U128
   address: U128
   service: bigint
   port: number
   applicationId: number
   activate: boolean
}

export interface ResourceDelta
{
   logicalCores: number
   memoryMB: number
   storageMB: number
   isDownscale: boolean
   graceSeconds: number
}

export interface MetricPair
{
   key: bigint
   value: bigint
}

export interface TlsIdentity
{
   name: string
   generation: bigint
   notBeforeMs: bigint
   notAfterMs: bigint
   certPEM: string
   keyPEM: string
   chainPEM: string
   dnsSANs: string[]
   ipSANs: IPAddress[]
   tags: string[]
}

export interface ApiCredential
{
   name: string
   provider: string
   generation: bigint
   expiresAtMs: bigint
   activeFromMs: bigint
   sunsetAtMs: bigint
   material: string
   metadata: Map<string, string>
}

export interface CredentialBundle
{
   tlsIdentities: TlsIdentity[]
   apiCredentials: ApiCredential[]
   bundleGeneration: bigint
}

export interface CredentialDelta
{
   bundleGeneration: bigint
   updatedTLS: TlsIdentity[]
   removedTLSNames: string[]
   updatedAPI: ApiCredential[]
   removedAPINames: string[]
   reason: string
}

export interface ContainerParameters
{
   uuid: U128
   memoryMB: number
   storageMB: number
   logicalCores: number
   neuronFD: number
   lowCPU: number
   highCPU: number
   advertises: AdvertisedPort[]
   subscriptionPairings: SubscriptionPairing[]
   advertisementPairings: AdvertisementPairing[]
   private6: IPPrefix
   justCrashed: boolean
   datacenterUniqueTag: number
   flags: bigint[]
   credentialBundle: CredentialBundle | null
}

export const ServiceRole =
{
   None: 0,
   Advertiser: 1,
   Subscriber: 2
} as const

export type ServiceRole = (typeof ServiceRole)[keyof typeof ServiceRole]

export interface AegisFrameHeader
{
   size: number
   nonce: U128
   encryptedDataSize: number
}

export class AegisSession
{
   readonly secret: U128
   readonly service: bigint
   readonly role: ServiceRole

   constructor(secret: U128, service: bigint, role: ServiceRole = ServiceRole.None)
   {
      this.secret = secret
      this.service = service
      this.role = role
   }

   static fromAdvertisement(pairing: AdvertisementPairing): AegisSession
   {
      return new AegisSession(pairing.secret, pairing.service, ServiceRole.Advertiser)
   }

   static fromSubscription(pairing: SubscriptionPairing): AegisSession
   {
      return new AegisSession(pairing.secret, pairing.service, ServiceRole.Subscriber)
   }

   pairingHash(): bigint
   {
      const input = Buffer.allocUnsafe(24)
      input.set(this.secret.bytes, 0)
      input.writeBigUInt64LE(this.service, 16)
      return gxhash24(input)
   }

   buildTFOData(aux: Uint8Array = Buffer.alloc(0)): Buffer
   {
      const out = Buffer.allocUnsafe(8 + aux.length)
      out.writeBigUInt64LE(this.pairingHash(), 0)
      out.set(aux, 8)
      return out
   }

   encrypt(plaintext: Uint8Array, nonce = new U128(randomBytes(AEGIS_NONCE_BYTES))): Buffer
   {
      const frame = Buffer.allocUnsafe(aegisFrameBytesForPlaintext(plaintext.length))
      return this.encryptInto(plaintext, frame, nonce)
   }

   encryptInto(plaintext: Uint8Array, out: Uint8Array, nonce = new U128(randomBytes(AEGIS_NONCE_BYTES))): Buffer
   {
      const frameBytes = aegisFrameBytesForPlaintext(plaintext.length)
      validateAegisFrameBytes(frameBytes)
      if (out.length < frameBytes)
      {
         throw new RangeError(`Aegis output buffer too small: have ${out.length}, need ${frameBytes}`)
      }

      const frame = Buffer.from(out.buffer, out.byteOffset, frameBytes)
      frame.writeUInt32LE(frameBytes, 0)
      frame.set(nonce.bytes, 4)
      frame.writeUInt32LE(plaintext.length + AEGIS_TAG_BYTES, 20)

      const ciphertext = Buffer.from(
         aegis128l(
            this.secret.bytes,
            nonce.bytes,
            frame.subarray(0, 4),
            { tagLength: AEGIS_TAG_BYTES }
         ).encrypt(plaintext)
      )
      ciphertext.copy(frame, AEGIS_HEADER_BYTES)
      frame.fill(0, AEGIS_HEADER_BYTES + ciphertext.length, frameBytes)
      return frame
   }

   decrypt(frameBytes: Uint8Array): { plaintext: Buffer, header: AegisFrameHeader }
   {
      const header = decodeAegisFrameHeader(frameBytes)
      const frame = Buffer.from(frameBytes)
      const plaintext = Buffer.from(
         aegis128l(
            this.secret.bytes,
            header.nonce.bytes,
            frame.subarray(0, 4),
            { tagLength: AEGIS_TAG_BYTES }
         ).decrypt(frame.subarray(AEGIS_HEADER_BYTES, AEGIS_HEADER_BYTES + header.encryptedDataSize))
      )
      return { plaintext, header }
   }
}

export const ContainerTopic =
{
   None: 0,
   Ping: 1,
   Pong: 2,
   Stop: 3,
   AdvertisementPairing: 4,
   SubscriptionPairing: 5,
   Healthy: 6,
   Message: 7,
   ResourceDelta: 8,
   DatacenterUniqueTag: 9,
   Statistics: 10,
   ResourceDeltaAck: 11,
   CredentialsRefresh: 12
} as const

export type ContainerTopic = (typeof ContainerTopic)[keyof typeof ContainerTopic]

export interface MessageFrame
{
   topic: ContainerTopic
   payload: Buffer
}

function parseTopic(value: number): ContainerTopic
{
   switch (value)
   {
      case ContainerTopic.None:
      case ContainerTopic.Ping:
      case ContainerTopic.Pong:
      case ContainerTopic.Stop:
      case ContainerTopic.AdvertisementPairing:
      case ContainerTopic.SubscriptionPairing:
      case ContainerTopic.Healthy:
      case ContainerTopic.Message:
      case ContainerTopic.ResourceDelta:
      case ContainerTopic.DatacenterUniqueTag:
      case ContainerTopic.Statistics:
      case ContainerTopic.ResourceDeltaAck:
      case ContainerTopic.CredentialsRefresh:
      {
         return value
      }
      default:
      {
         throw new ProtocolError(`unknown topic ${value}`)
      }
   }
}

class Reader
{
   private readonly data: Buffer
   private offset = 0

   constructor(data: Uint8Array)
   {
      this.data = Buffer.from(data)
   }

   done(): boolean
   {
      return this.offset === this.data.length
   }

   raw(count: number): Buffer
   {
      if (count < 0 || this.offset + count > this.data.length)
      {
         throw new ProtocolError("truncated payload")
      }

      const start = this.offset
      this.offset += count
      return this.data.subarray(start, this.offset)
   }

   expect(marker: Uint8Array): void
   {
      if (!this.raw(marker.length).equals(Buffer.from(marker)))
      {
         throw new ProtocolError("unexpected magic")
      }
   }

   u8(): number
   {
      return this.raw(1)[0]
   }

   boolean(): boolean
   {
      const value = this.u8()
      if (value !== 0 && value !== 1)
      {
         throw new ProtocolError("invalid boolean")
      }

      return value === 1
   }

   u16(): number
   {
      return this.raw(2).readUInt16LE(0)
   }

   u32(): number
   {
      return this.raw(4).readUInt32LE(0)
   }

   i32(): number
   {
      return this.raw(4).readInt32LE(0)
   }

   u64(): bigint
   {
      return this.raw(8).readBigUInt64LE(0)
   }

   i64(): bigint
   {
      return this.raw(8).readBigInt64LE(0)
   }

   u128(): U128
   {
      return new U128(this.raw(16))
   }

   string(): string
   {
      return this.raw(this.u32()).toString("utf8")
   }
}

class Writer
{
   private readonly parts: Buffer[] = []

   raw(value: Uint8Array): void
   {
      this.parts.push(Buffer.from(value))
   }

   u8(value: number): void
   {
      const buffer = Buffer.allocUnsafe(1)
      buffer[0] = value & 0xff
      this.parts.push(buffer)
   }

   boolean(value: boolean): void
   {
      this.u8(value ? 1 : 0)
   }

   u16(value: number): void
   {
      const buffer = Buffer.allocUnsafe(2)
      buffer.writeUInt16LE(value, 0)
      this.parts.push(buffer)
   }

   u32(value: number): void
   {
      const buffer = Buffer.allocUnsafe(4)
      buffer.writeUInt32LE(value, 0)
      this.parts.push(buffer)
   }

   i32(value: number): void
   {
      const buffer = Buffer.allocUnsafe(4)
      buffer.writeInt32LE(value, 0)
      this.parts.push(buffer)
   }

   u64(value: bigint): void
   {
      const buffer = Buffer.allocUnsafe(8)
      buffer.writeBigUInt64LE(value, 0)
      this.parts.push(buffer)
   }

   i64(value: bigint): void
   {
      const buffer = Buffer.allocUnsafe(8)
      buffer.writeBigInt64LE(value, 0)
      this.parts.push(buffer)
   }

   string(value: string): void
   {
      const encoded = Buffer.from(value, "utf8")
      this.u32(encoded.length)
      this.raw(encoded)
   }

   finish(): Buffer
   {
      return Buffer.concat(this.parts)
   }
}

function decodeIPAddress(reader: Reader): IPAddress
{
   return new IPAddress(reader.raw(16), reader.boolean())
}

function decodeIPPrefix(reader: Reader): IPPrefix
{
   const address = decodeIPAddress(reader)
   return new IPPrefix(address.address, reader.u8(), address.isIPv6)
}

function decodeStringArray(reader: Reader): string[]
{
   const values: string[] = []
   const count = reader.u32()
   for (let index = 0; index < count; index += 1)
   {
      values.push(reader.string())
   }

   return values
}

function decodeIPAddressArray(reader: Reader): IPAddress[]
{
   const values: IPAddress[] = []
   const count = reader.u32()
   for (let index = 0; index < count; index += 1)
   {
      values.push(decodeIPAddress(reader))
   }

   return values
}

function decodeTLSIdentity(reader: Reader): TlsIdentity
{
   return {
      name: reader.string(),
      generation: reader.u64(),
      notBeforeMs: reader.i64(),
      notAfterMs: reader.i64(),
      certPEM: reader.string(),
      keyPEM: reader.string(),
      chainPEM: reader.string(),
      dnsSANs: decodeStringArray(reader),
      ipSANs: decodeIPAddressArray(reader),
      tags: decodeStringArray(reader)
   }
}

function decodeApiCredential(reader: Reader): ApiCredential
{
   const metadata = new Map<string, string>()
   const name = reader.string()
   const provider = reader.string()
   const generation = reader.u64()
   const expiresAtMs = reader.i64()
   const activeFromMs = reader.i64()
   const sunsetAtMs = reader.i64()
   const material = reader.string()
   const metadataCount = reader.u32()

   for (let index = 0; index < metadataCount; index += 1)
   {
      metadata.set(reader.string(), reader.string())
   }

   return {
      name,
      provider,
      generation,
      expiresAtMs,
      activeFromMs,
      sunsetAtMs,
      material,
      metadata
   }
}

function decodeCredentialBundleFields(reader: Reader): CredentialBundle
{
   const tlsIdentities: TlsIdentity[] = []
   const apiCredentials: ApiCredential[] = []
   const tlsCount = reader.u32()

   for (let index = 0; index < tlsCount; index += 1)
   {
      tlsIdentities.push(decodeTLSIdentity(reader))
   }

   const apiCount = reader.u32()
   for (let index = 0; index < apiCount; index += 1)
   {
      apiCredentials.push(decodeApiCredential(reader))
   }

   return {
      tlsIdentities,
      apiCredentials,
      bundleGeneration: reader.u64()
   }
}

export function decodeCredentialBundle(data: Uint8Array): CredentialBundle
{
   const reader = new Reader(data)
   reader.expect(CREDENTIAL_BUNDLE_MAGIC)
   const bundle = decodeCredentialBundleFields(reader)
   if (!reader.done())
   {
      throw new ProtocolError("credential bundle has trailing bytes")
   }

   return bundle
}

export function decodeCredentialDelta(data: Uint8Array): CredentialDelta
{
   const reader = new Reader(data)
   reader.expect(CREDENTIAL_DELTA_MAGIC)
   const delta: CredentialDelta = {
      bundleGeneration: reader.u64(),
      updatedTLS: [],
      removedTLSNames: [],
      updatedAPI: [],
      removedAPINames: [],
      reason: ""
   }
   const updatedTLSCount = reader.u32()

   for (let index = 0; index < updatedTLSCount; index += 1)
   {
      delta.updatedTLS.push(decodeTLSIdentity(reader))
   }

   delta.removedTLSNames = decodeStringArray(reader)

   const updatedAPICount = reader.u32()
   for (let index = 0; index < updatedAPICount; index += 1)
   {
      delta.updatedAPI.push(decodeApiCredential(reader))
   }

   delta.removedAPINames = decodeStringArray(reader)
   delta.reason = reader.string()

   if (!reader.done())
   {
      throw new ProtocolError("credential delta has trailing bytes")
   }

   return delta
}

export function decodeContainerParameters(data: Uint8Array): ContainerParameters
{
   const reader = new Reader(data)
   reader.expect(CONTAINER_PARAMETERS_MAGIC)

   const parameters: ContainerParameters = {
      uuid: reader.u128(),
      memoryMB: reader.u32(),
      storageMB: reader.u32(),
      logicalCores: reader.u16(),
      neuronFD: reader.i32(),
      lowCPU: reader.i32(),
      highCPU: reader.i32(),
      advertises: [],
      subscriptionPairings: [],
      advertisementPairings: [],
      private6: new IPPrefix(new Uint8Array(16), 0, false),
      justCrashed: false,
      datacenterUniqueTag: 0,
      flags: [],
      credentialBundle: null
   }
   const advertiseCount = reader.u32()

   for (let index = 0; index < advertiseCount; index += 1)
   {
      parameters.advertises.push({
         service: reader.u64(),
         port: reader.u16()
      })
   }

   const subscriptionPairingCount = reader.u32()
   for (let index = 0; index < subscriptionPairingCount; index += 1)
   {
      const secret = reader.u128()
      const address = reader.u128()
      const service = reader.u64()
      parameters.subscriptionPairings.push({
         secret,
         address,
         service,
         port: reader.u16(),
         applicationId: Number((service >> 48n) & 0xffffn),
         activate: true
      })
   }

   const advertisementPairingCount = reader.u32()
   for (let index = 0; index < advertisementPairingCount; index += 1)
   {
      const secret = reader.u128()
      const address = reader.u128()
      const service = reader.u64()
      parameters.advertisementPairings.push({
         secret,
         address,
         service,
         applicationId: Number((service >> 48n) & 0xffffn),
         activate: true
      })
   }

   parameters.private6 = decodeIPPrefix(reader)
   parameters.justCrashed = reader.boolean()
   parameters.datacenterUniqueTag = reader.u8()

   const flagCount = reader.u32()
   for (let index = 0; index < flagCount; index += 1)
   {
      parameters.flags.push(reader.u64())
   }

   if (reader.boolean())
   {
      parameters.credentialBundle = decodeCredentialBundleFields(reader)
   }

   if (!reader.done())
   {
      throw new ProtocolError("container parameters have trailing bytes")
   }

   return parameters
}

function readAllFromFD(fd: number): Buffer
{
   if (fd < 0)
   {
      throw new ProtocolError(`invalid fd ${fd}`)
   }

   const chunks: Buffer[] = []
   let position = 0
   for (;;)
   {
      const buffer = Buffer.allocUnsafe(65536)
      const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, position)
      if (bytesRead === 0)
      {
         return Buffer.concat(chunks)
      }

      chunks.push(buffer.subarray(0, bytesRead))
      position += bytesRead
   }
}

export function loadContainerParametersFromEnvOrArgv(
   argv: string[] = process.argv,
   env: NodeJS.ProcessEnv = process.env): ContainerParameters
{
   const fdText = env.PRODIGY_PARAMS_FD
   if (fdText)
   {
      const fd = Number.parseInt(fdText, 10)
      if (!Number.isInteger(fd))
      {
         throw new ProtocolError(`invalid PRODIGY_PARAMS_FD ${fdText}`)
      }

      try
      {
         return decodeContainerParameters(readAllFromFD(fd))
      }
      finally
      {
         fs.closeSync(fd)
      }
   }

   if (argv.length > 2)
   {
      return decodeContainerParameters(Buffer.from(argv[2], "latin1"))
   }

   throw new ProtocolError("missing PRODIGY_PARAMS_FD and argv bootstrap payload")
}

function readExact(fd: number, size: number): Buffer
{
   const buffer = Buffer.allocUnsafe(size)
   let offset = 0
   while (offset < size)
   {
      const bytesRead = fs.readSync(fd, buffer, offset, size - offset, null)
      if (bytesRead === 0)
      {
         throw new ProtocolError("socket closed")
      }

      offset += bytesRead
   }

   return buffer
}

function writeAll(fd: number, data: Uint8Array): void
{
   let offset = 0
   const buffer = Buffer.from(data)
   while (offset < buffer.length)
   {
      const bytesWritten = fs.writeSync(fd, buffer, offset, buffer.length - offset)
      if (bytesWritten <= 0)
      {
         throw new ProtocolError("short write")
      }

      offset += bytesWritten
   }
}

export function buildMessageFrame(topic: ContainerTopic, payload: Uint8Array = Buffer.alloc(0)): Buffer
{
   const padding = (FRAME_ALIGNMENT - ((FRAME_HEADER_SIZE + payload.length) % FRAME_ALIGNMENT)) % FRAME_ALIGNMENT
   const size = FRAME_HEADER_SIZE + payload.length + padding
   const frame = Buffer.alloc(size)

   frame.writeUInt32LE(size, 0)
   frame.writeUInt16LE(topic, 4)
   frame[6] = padding
   frame[7] = FRAME_HEADER_SIZE
   Buffer.from(payload).copy(frame, FRAME_HEADER_SIZE)
   return frame
}

export function buildReadyFrame(): Buffer
{
   return buildMessageFrame(ContainerTopic.Healthy)
}

export function buildStatisticsFrame(metrics: Iterable<MetricPair>): Buffer
{
   return buildMessageFrame(ContainerTopic.Statistics, encodeMetricPairs(metrics))
}

export function buildResourceDeltaAckFrame(accepted: boolean): Buffer
{
   return buildMessageFrame(ContainerTopic.ResourceDeltaAck, Buffer.from([accepted ? 1 : 0]))
}

export function buildCredentialsRefreshAckFrame(): Buffer
{
   return buildMessageFrame(ContainerTopic.CredentialsRefresh)
}

export function aegisFrameBytesForPlaintext(plaintextBytes: number): number
{
   return (AEGIS_HEADER_BYTES + plaintextBytes + AEGIS_TAG_BYTES + (AEGIS_ALIGNMENT - 1)) & ~(AEGIS_ALIGNMENT - 1)
}

export function decodeAegisFrameHeader(frameBytes: Uint8Array): AegisFrameHeader
{
   const frame = Buffer.from(frameBytes)
   if (frame.length < AEGIS_HEADER_BYTES)
   {
      throw new ProtocolError("Aegis frame is truncated")
   }

   const size = frame.readUInt32LE(0)
   validateAegisFrameBytes(size)
   if (frame.length !== size)
   {
      throw new ProtocolError("Aegis frame byte length does not match declared size")
   }

   const encryptedDataSize = frame.readUInt32LE(20)
   if (encryptedDataSize < AEGIS_TAG_BYTES)
   {
      throw new ProtocolError("Aegis encrypted payload is smaller than the authentication tag")
   }
   if (encryptedDataSize > (size - AEGIS_HEADER_BYTES))
   {
      throw new ProtocolError("Aegis encrypted payload exceeds the declared frame size")
   }

   return {
      size,
      nonce: new U128(frame.subarray(4, 20)),
      encryptedDataSize,
   }
}

function validateAegisFrameBytes(frameBytes: number): void
{
   if (frameBytes < AEGIS_MIN_FRAME_BYTES)
   {
      throw new ProtocolError("Aegis frame is smaller than the minimum supported size")
   }
   if (frameBytes > AEGIS_MAX_FRAME_BYTES)
   {
      throw new ProtocolError("Aegis frame exceeds the maximum supported size")
   }
   if (frameBytes % AEGIS_ALIGNMENT !== 0)
   {
      throw new ProtocolError("Aegis frame is not aligned to 16 bytes")
   }
}

export function parseMessageFrame(data: Uint8Array): MessageFrame
{
   const frame = Buffer.from(data)
   if (frame.length < FRAME_HEADER_SIZE)
   {
      throw new ProtocolError("truncated frame")
   }

   const size = frame.readUInt32LE(0)
   const topic = parseTopic(frame.readUInt16LE(4))
   const padding = frame[6]
   const headerSize = frame[7]

   if (headerSize !== FRAME_HEADER_SIZE)
   {
      throw new ProtocolError(`unexpected frame header size ${headerSize}`)
   }

   if (size < FRAME_HEADER_SIZE || size % FRAME_ALIGNMENT !== 0)
   {
      throw new ProtocolError("invalid frame size")
   }

   if (size !== frame.length)
   {
      throw new ProtocolError("frame size does not match buffer length")
   }

   const bodyLength = size - FRAME_HEADER_SIZE
   if (padding > bodyLength)
   {
      throw new ProtocolError("invalid frame padding")
   }

   return {
      topic,
      payload: Buffer.from(frame.subarray(FRAME_HEADER_SIZE, size - padding))
   }
}

export class FrameDecoder
{
   private readonly buffer: number[] = []

   feed(data: Uint8Array): MessageFrame[]
   {
      for (const byte of data)
      {
         this.buffer.push(byte)
      }

      const frames: MessageFrame[] = []
      for (;;)
      {
         const frame = this.tryPopFrame()
         if (frame === null)
         {
            return frames
         }
         frames.push(frame)
      }
   }

   private tryPopFrame(): MessageFrame | null
   {
      if (this.buffer.length < FRAME_HEADER_SIZE)
      {
         return null
      }

      const header = Buffer.from(this.buffer.slice(0, FRAME_HEADER_SIZE))
      const size = header.readUInt32LE(0)
      const headerSize = header[7]
      if (headerSize !== FRAME_HEADER_SIZE)
      {
         throw new ProtocolError(`unexpected frame header size ${headerSize}`)
      }
      if (size < FRAME_HEADER_SIZE || size % FRAME_ALIGNMENT !== 0)
      {
         throw new ProtocolError("invalid frame size")
      }
      if (size > this.buffer.length)
      {
         return null
      }

      const frame = Buffer.from(this.buffer.splice(0, size))
      return parseMessageFrame(frame)
   }
}

function readMessageFrame(fd: number): MessageFrame
{
   const header = readExact(fd, FRAME_HEADER_SIZE)
   const size = header.readUInt32LE(0)
   const padding = header[6]
   const headerSize = header[7]

   if (headerSize !== FRAME_HEADER_SIZE)
   {
      throw new ProtocolError(`unexpected frame header size ${headerSize}`)
   }

   if (size < FRAME_HEADER_SIZE || size % FRAME_ALIGNMENT !== 0)
   {
      throw new ProtocolError("invalid frame size")
   }

   const bodyLength = size - FRAME_HEADER_SIZE
   if (padding > bodyLength)
   {
      throw new ProtocolError("invalid frame padding")
   }

   const body = readExact(fd, bodyLength)
   return parseMessageFrame(Buffer.concat([header, body]))
}

function encodeMetricPairs(metrics: Iterable<MetricPair>): Buffer
{
   const writer = new Writer()
   for (const metric of metrics)
   {
      writer.u64(metric.key)
      writer.u64(metric.value)
   }

   return writer.finish()
}

export function decodeMetricPairs(payload: Uint8Array): MetricPair[]
{
   const buffer = Buffer.from(payload)
   if (buffer.length % METRIC_PAIR_SIZE !== 0)
   {
      throw new ProtocolError("statistics payload is not pair aligned")
   }

   const metrics: MetricPair[] = []
   for (let offset = 0; offset < buffer.length; offset += METRIC_PAIR_SIZE)
   {
      metrics.push({
         key: buffer.readBigUInt64LE(offset),
         value: buffer.readBigUInt64LE(offset + 8)
      })
   }

   return metrics
}

function decodeAdvertisementPairingPayload(payload: Uint8Array): AdvertisementPairing
{
   const reader = new Reader(payload)
   const pairing: AdvertisementPairing = {
      secret: reader.u128(),
      address: reader.u128(),
      service: reader.u64(),
      applicationId: reader.u16(),
      activate: reader.boolean()
   }

   if (!reader.done())
   {
      throw new ProtocolError("advertisement pairing has trailing bytes")
   }

   return pairing
}

function decodeSubscriptionPairingPayload(payload: Uint8Array): SubscriptionPairing
{
   const reader = new Reader(payload)
   const pairing: SubscriptionPairing = {
      secret: reader.u128(),
      address: reader.u128(),
      service: reader.u64(),
      port: reader.u16(),
      applicationId: reader.u16(),
      activate: reader.boolean()
   }

   if (!reader.done())
   {
      throw new ProtocolError("subscription pairing has trailing bytes")
   }

   return pairing
}

function decodeResourceDeltaPayload(payload: Uint8Array): ResourceDelta
{
   const reader = new Reader(payload)
   const delta: ResourceDelta = {
      logicalCores: reader.u16(),
      memoryMB: reader.u32(),
      storageMB: reader.u32(),
      isDownscale: reader.boolean(),
      graceSeconds: reader.u32()
   }

   if (!reader.done())
   {
      throw new ProtocolError("resource delta has trailing bytes")
   }

   return delta
}

export class NeuronHubDispatch
{
   endOfDynamicArgs(_hub: NeuronHub): void
   {
   }

   beginShutdown(_hub: NeuronHub): void
   {
   }

   advertisementPairing(_hub: NeuronHub, _pairing: AdvertisementPairing): void
   {
   }

   subscriptionPairing(_hub: NeuronHub, _pairing: SubscriptionPairing): void
   {
   }

   resourceDelta(_hub: NeuronHub, _delta: ResourceDelta): void
   {
   }

   credentialsRefresh(_hub: NeuronHub, _delta: CredentialDelta): void
   {
   }

   messageFromProdigy(_hub: NeuronHub, _payload: Buffer): void
   {
   }
}

export class DefaultDispatch extends NeuronHubDispatch
{
}

export class NeuronHub
{
   readonly dispatch: NeuronHubDispatch
   readonly fd: number
   readonly ownsTransport: boolean
   parameters: ContainerParameters

   constructor(
      dispatch: NeuronHubDispatch,
      parameters: ContainerParameters,
      fd: number | null = null,
      ownsTransport = true)
   {
      this.dispatch = dispatch
      this.parameters = parameters
      this.fd = fd ?? parameters.neuronFD
      this.ownsTransport = ownsTransport
      if (this.fd < 0)
      {
         throw new ProtocolError("invalid neuron fd")
      }
   }

   static fromEnvOrArgv(
      dispatch: NeuronHubDispatch,
      argv: string[] = process.argv,
      env: NodeJS.ProcessEnv = process.env,
      fd: number | null = null): NeuronHub
   {
      return new NeuronHub(dispatch, loadContainerParametersFromEnvOrArgv(argv, env), fd)
   }

   static forEventLoop(
      dispatch: NeuronHubDispatch,
      parameters: ContainerParameters,
      fd: number | null = null): NeuronHub
   {
      return NeuronHub.borrowedTransport(dispatch, parameters, fd)
   }

   static borrowedTransport(
      dispatch: NeuronHubDispatch,
      parameters: ContainerParameters,
      fd: number | null = null): NeuronHub
   {
      return new NeuronHub(dispatch, parameters, fd, false)
   }

   static fromEnvOrArgvForEventLoop(
      dispatch: NeuronHubDispatch,
      argv: string[] = process.argv,
      env: NodeJS.ProcessEnv = process.env,
      fd: number | null = null): NeuronHub
   {
      return NeuronHub.fromEnvOrArgvBorrowedTransport(dispatch, argv, env, fd)
   }

   static fromEnvOrArgvBorrowedTransport(
      dispatch: NeuronHubDispatch,
      argv: string[] = process.argv,
      env: NodeJS.ProcessEnv = process.env,
      fd: number | null = null): NeuronHub
   {
      return NeuronHub.borrowedTransport(dispatch, loadContainerParametersFromEnvOrArgv(argv, env), fd)
   }

   close(): void
   {
      if (this.ownsTransport)
      {
         fs.closeSync(this.fd)
      }
   }

   private send(topic: ContainerTopic, payload: Uint8Array = Buffer.alloc(0)): void
   {
      this.sendEncoded(buildMessageFrame(topic, payload))
   }

   private sendEncoded(frame: Uint8Array): void
   {
      writeAll(this.fd, frame)
   }

   sendFrame(frame: MessageFrame): void
   {
      this.send(frame.topic, frame.payload)
   }

   signalReady(): void
   {
      this.sendEncoded(buildReadyFrame())
   }

   publishStatistic(metric: MetricPair): void
   {
      this.publishStatistics([metric])
   }

   publishStatistics(metrics: Iterable<MetricPair>): void
   {
      this.sendEncoded(buildStatisticsFrame(metrics))
   }

   acknowledgeResourceDelta(accepted: boolean): void
   {
      this.sendEncoded(buildResourceDeltaAckFrame(accepted))
   }

   acknowledgeCredentialsRefresh(): void
   {
      this.sendEncoded(buildCredentialsRefreshAckFrame())
   }

   handleFrame(frame: MessageFrame): MessageFrame[]
   {
      const outbound: MessageFrame[] = []

      switch (frame.topic)
      {
         case ContainerTopic.None:
         {
            this.dispatch.endOfDynamicArgs(this)
            break
         }
         case ContainerTopic.Ping:
         {
            outbound.push({
               topic: ContainerTopic.Ping,
               payload: Buffer.alloc(0)
            })
            break
         }
         case ContainerTopic.Pong:
         case ContainerTopic.Healthy:
         case ContainerTopic.Statistics:
         case ContainerTopic.ResourceDeltaAck:
         {
            break
         }
         case ContainerTopic.Stop:
         {
            this.dispatch.beginShutdown(this)
            break
         }
         case ContainerTopic.AdvertisementPairing:
         {
            this.dispatch.advertisementPairing(this, decodeAdvertisementPairingPayload(frame.payload))
            break
         }
         case ContainerTopic.SubscriptionPairing:
         {
            this.dispatch.subscriptionPairing(this, decodeSubscriptionPairingPayload(frame.payload))
            break
         }
         case ContainerTopic.ResourceDelta:
         {
            this.dispatch.resourceDelta(this, decodeResourceDeltaPayload(frame.payload))
            break
         }
         case ContainerTopic.DatacenterUniqueTag:
         {
            const reader = new Reader(frame.payload)
            this.parameters.datacenterUniqueTag = reader.u8()
            if (!reader.done())
            {
               throw new ProtocolError("datacenter tag has trailing bytes")
            }
            break
         }
         case ContainerTopic.Message:
         {
            this.dispatch.messageFromProdigy(this, Buffer.from(frame.payload))
            break
         }
         case ContainerTopic.CredentialsRefresh:
         {
            if (frame.payload.length > 0)
            {
               this.dispatch.credentialsRefresh(this, decodeCredentialDelta(frame.payload))
            }
            break
         }
         default:
         {
            throw new ProtocolError(`unsupported inbound topic ${frame.topic}`)
         }
      }

      return outbound
   }

   runOnce(): ContainerTopic
   {
      const frame = readMessageFrame(this.fd)
      for (const outbound of this.handleFrame(frame))
      {
         this.sendFrame(outbound)
      }

      return frame.topic
   }

   runForever(): never
   {
      for (;;)
      {
         this.runOnce()
      }
   }
}

export const NeuronEvent = {
   Shutdown: "shutdown",
   Closed: "closed"
} as const

export type NeuronEvent = (typeof NeuronEvent)[keyof typeof NeuronEvent]

export type ReactorEvent<E> =
   | { app: E, neuron?: undefined }
   | { neuron: NeuronEvent, app?: undefined }

class AsyncQueue<T>
{
   private readonly values: T[] = []
   private readonly waiters: ((value: T) => void)[] = []

   push(value: T): void
   {
      const waiter = this.waiters.shift()
      if (waiter !== undefined)
      {
         waiter(value)
         return
      }

      this.values.push(value)
   }

   next(): Promise<T>
   {
      const value = this.values.shift()
      if (value !== undefined)
      {
         return Promise.resolve(value)
      }

      return new Promise((resolve) => {
         this.waiters.push(resolve)
      })
   }
}

export class ReactorSink<E>
{
   private readonly queue: AsyncQueue<ReactorEvent<E> | Error>

   constructor(queue: AsyncQueue<ReactorEvent<E> | Error>)
   {
      this.queue = queue
   }

   app(event: E): void
   {
      this.queue.push({ app: event })
   }

   neuron(event: NeuronEvent): void
   {
      this.queue.push({ neuron: event })
   }

   error(error: unknown): void
   {
      this.queue.push(error instanceof Error ? error : new Error(String(error)))
   }
}

export class Reactor<E>
{
   private readonly queue = new AsyncQueue<ReactorEvent<E> | Error>()

   sink(): ReactorSink<E>
   {
      return new ReactorSink(this.queue)
   }

   once(event: E, promise: PromiseLike<unknown>): void
   {
      const sink = this.sink()
      Promise.resolve(promise).then(
         () => sink.app(event),
         (error: unknown) => sink.error(error),
      )
   }

   attachNeuron(neuron: AsyncNeuron): AsyncNeuronHandle
   {
      return neuron.attach(this.sink())
   }

   async next(): Promise<ReactorEvent<E>>
   {
      const event = await this.queue.next()
      if (event instanceof Error)
      {
         throw event
      }

      return event
   }

   async *events(): AsyncGenerator<ReactorEvent<E>, never, void>
   {
      for (;;)
      {
         yield await this.next()
      }
   }

   [Symbol.asyncIterator](): AsyncGenerator<ReactorEvent<E>, never, void>
   {
      return this.events()
   }
}

class NodeNeuronDispatch extends NeuronHubDispatch
{
   owner: AsyncNeuron | null = null
   private readonly inner: NeuronHubDispatch

   constructor(inner: NeuronHubDispatch)
   {
      super()
      this.inner = inner
   }

   override endOfDynamicArgs(hub: NeuronHub): void
   {
      this.inner.endOfDynamicArgs(hub)
   }

   override beginShutdown(hub: NeuronHub): void
   {
      if (this.owner !== null)
      {
         this.owner.shutdownRequested = true
      }
      this.inner.beginShutdown(hub)
   }

   override advertisementPairing(hub: NeuronHub, pairing: AdvertisementPairing): void
   {
      this.inner.advertisementPairing(hub, pairing)
   }

   override subscriptionPairing(hub: NeuronHub, pairing: SubscriptionPairing): void
   {
      this.inner.subscriptionPairing(hub, pairing)
   }

   override resourceDelta(hub: NeuronHub, delta: ResourceDelta): void
   {
      if (this.owner !== null && this.owner.autoAckResourceDelta !== null)
      {
         hub.acknowledgeResourceDelta(this.owner.autoAckResourceDelta)
      }
      this.inner.resourceDelta(hub, delta)
   }

   override credentialsRefresh(hub: NeuronHub, delta: CredentialDelta): void
   {
      if (this.owner?.autoAckCredentialsRefresh === true)
      {
         hub.acknowledgeCredentialsRefresh()
      }
      this.inner.credentialsRefresh(hub, delta)
   }

   override messageFromProdigy(hub: NeuronHub, payload: Buffer): void
   {
      this.inner.messageFromProdigy(hub, payload)
   }
}

export class AsyncNeuron
{
   readonly hub: NeuronHub
   private readonly dispatch: NodeNeuronDispatch
   private readonly decoder = new FrameDecoder()
   private readonly socket: net.Socket
   shutdownRequested = false
   autoAckResourceDelta: boolean | null = null
   autoAckCredentialsRefresh = false

   constructor(dispatch: NeuronHubDispatch, parameters: ContainerParameters, fd: number | null = null)
   {
      this.dispatch = new NodeNeuronDispatch(dispatch)
      this.hub = NeuronHub.borrowedTransport(this.dispatch, parameters, fd)
      this.dispatch.owner = this
      this.socket = new net.Socket({
         fd: this.hub.fd,
         readable: true,
         writable: true,
      })
   }

   static fromEnvOrArgv(
      dispatch: NeuronHubDispatch,
      argv: string[] = process.argv,
      env: NodeJS.ProcessEnv = process.env,
      fd: number | null = null): AsyncNeuron
   {
      return new AsyncNeuron(dispatch, loadContainerParametersFromEnvOrArgv(argv, env), fd)
   }

   static fromProcess(
      dispatch: NeuronHubDispatch,
      argv: string[] = process.argv,
      env: NodeJS.ProcessEnv = process.env,
      fd: number | null = null): AsyncNeuron
   {
      return AsyncNeuron.fromEnvOrArgv(dispatch, argv, env, fd)
   }

   withResourceDeltaAck(accepted: boolean): this
   {
      this.autoAckResourceDelta = accepted
      return this
   }

   withCredentialsRefreshAck(): this
   {
      this.autoAckCredentialsRefresh = true
      return this
   }

   withAutoAcks(): this
   {
      return this.withResourceDeltaAck(true).withCredentialsRefreshAck()
   }

   attach<E>(sink: ReactorSink<E>): AsyncNeuronHandle
   {
      const cleanup = (): void =>
      {
         this.socket.removeAllListeners("data")
         this.socket.removeAllListeners("close")
         this.socket.removeAllListeners("error")
      }

      this.socket.on("data", (chunk: Buffer) => {
         try
         {
            for (const frame of this.decoder.feed(chunk))
            {
               for (const outbound of this.hub.handleFrame(frame))
               {
                  this.hub.sendFrame(outbound)
               }
            }
            if (this.shutdownRequested)
            {
               cleanup()
               sink.neuron(NeuronEvent.Shutdown)
            }
         }
         catch (error)
         {
            cleanup()
            sink.error(error)
         }
      })

      this.socket.once("close", () => {
         cleanup()
         sink.neuron(NeuronEvent.Closed)
      })
      this.socket.once("error", (error) => {
         cleanup()
         sink.error(error)
      })

      return new AsyncNeuronHandle(this.hub.parameters, this.hub)
   }
}

export class AsyncNeuronHandle
{
   private readySent = false
   private readonly parametersValue: ContainerParameters
   private readonly hub: NeuronHub

   constructor(
      parametersValue: ContainerParameters,
      hub: NeuronHub)
   {
      this.parametersValue = parametersValue
      this.hub = hub
   }

   parameters(): ContainerParameters
   {
      return this.parametersValue
   }

   private6Address(): string
   {
      if (!this.parametersValue.private6.isIPv6)
      {
         throw new ProtocolError("container does not have a private IPv6 address")
      }

      return formatIPv6Address(this.parametersValue.private6.address)
   }

   private6Addr(): string
   {
      return this.private6Address()
   }

   async ready(): Promise<void>
   {
      if (this.readySent)
      {
         return
      }

      this.hub.signalReady()
      this.readySent = true
   }
}

export { Reactor as NodeReactor, AsyncNeuron as NodeNeuron, AsyncNeuronHandle as NodeNeuronHandle }

export function formatIPv6Address(bytes: Uint8Array): string
{
   const groups: string[] = []
   for (let index = 0; index < 16; index += 2)
   {
      groups.push(((bytes[index] << 8) | bytes[index + 1]).toString(16))
   }

   return groups.join(":").replace(/(^|:)0(:0)+(:|$)/, "::")
}

export function sameIPv6Address(left: string, right: string): boolean
{
   const leftGroups = expandIPv6(left)
   const rightGroups = expandIPv6(right)
   if (leftGroups === null || rightGroups === null)
   {
      return false
   }

   return leftGroups.every((value, index) => value === rightGroups[index])
}

function expandIPv6(value: string): number[] | null
{
   if (net.isIP(value) !== 6)
   {
      return null
   }

   const sides = value.toLowerCase().split("::")
   if (sides.length > 2)
   {
      return null
   }

   const parseSide = (text: string): number[] => {
      if (text.length === 0)
      {
         return []
      }

      return text.split(":").map((field) => Number.parseInt(field || "0", 16))
   }

   const head = parseSide(sides[0] ?? "")
   const tail = parseSide(sides[1] ?? "")
   const zeroes = new Array(Math.max(0, 8 - head.length - tail.length)).fill(0)
   const expanded = sides.length === 1 ? head : head.concat(zeroes, tail)
   return expanded.length === 8 ? expanded : null
}

const AEGIS_PAIRING_HASH_KEYS = Uint32Array.of(
   0xF2784542, 0xB09D3E21, 0x89C222E5, 0xFC3BC28E,
   0x03FCE279, 0xCB6B2E9B, 0xB361DC58, 0x39132BD9,
   0xD0012E32, 0x689D2B7D, 0x5544B1B7, 0xC78B122B,
)

const AES_SBOX = Uint8Array.of(
   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
   0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
   0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
   0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
   0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
   0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
   0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
   0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
   0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
   0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
   0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
   0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
   0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
   0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
   0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
   0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)

function gxhash24(input: Buffer): bigint
{
   const partial = new Uint8Array(16)
   partial.set(input.subarray(0, 8))
   for (let index = 0; index < partial.length; index += 1)
   {
      partial[index] = (partial[index] + 8) & 0xff
   }

   const v0 = Uint8Array.from(input.subarray(8, 24))
   const key0 = loadAegisPairingHashKey(0)
   const key4 = loadAegisPairingHashKey(4)
   const key8 = loadAegisPairingHashKey(8)
   const seedVector = packRepeatedI64(AEGIS_PAIRING_HASH_SEED)

   let hash = aesEncryptLast(partial, aesEncrypt(aesEncrypt(v0, key0), key4))
   hash = aesEncrypt(hash, seedVector)
   hash = aesEncrypt(hash, key0)
   hash = aesEncrypt(hash, key4)
   hash = aesEncryptLast(hash, key8)
   return readBigUInt64LE(hash, 0)
}

function loadAegisPairingHashKey(offset: number): Uint8Array
{
   const key = Buffer.allocUnsafe(16)
   for (let index = 0; index < 4; index += 1)
   {
      key.writeUInt32LE(AEGIS_PAIRING_HASH_KEYS[offset + index]!, index * 4)
   }
   return key
}

function packRepeatedI64(value: bigint): Uint8Array
{
   const out = Buffer.allocUnsafe(16)
   out.writeBigInt64LE(value, 0)
   out.writeBigInt64LE(value, 8)
   return out
}

function aesEncrypt(state: Uint8Array, roundKey: Uint8Array): Uint8Array
{
   return addRoundKey(mixColumns(shiftRows(subBytes(state))), roundKey)
}

function aesEncryptLast(state: Uint8Array, roundKey: Uint8Array): Uint8Array
{
   return addRoundKey(shiftRows(subBytes(state)), roundKey)
}

function subBytes(state: Uint8Array): Uint8Array
{
   const out = Uint8Array.from(state)
   for (let index = 0; index < out.length; index += 1)
   {
      out[index] = AES_SBOX[out[index]!]!
   }
   return out
}

function shiftRows(state: Uint8Array): Uint8Array
{
   const out = new Uint8Array(16)
   for (let row = 0; row < 4; row += 1)
   {
      for (let column = 0; column < 4; column += 1)
      {
         const sourceColumn = (column + row) & 3
         out[row + (4 * column)] = state[row + (4 * sourceColumn)]!
      }
   }
   return out
}

function mixColumns(state: Uint8Array): Uint8Array
{
   const out = Uint8Array.from(state)
   for (let column = 0; column < 4; column += 1)
   {
      const offset = column * 4
      const s0 = out[offset + 0]!
      const s1 = out[offset + 1]!
      const s2 = out[offset + 2]!
      const s3 = out[offset + 3]!
      out[offset + 0] = gmul2(s0) ^ gmul3(s1) ^ s2 ^ s3
      out[offset + 1] = s0 ^ gmul2(s1) ^ gmul3(s2) ^ s3
      out[offset + 2] = s0 ^ s1 ^ gmul2(s2) ^ gmul3(s3)
      out[offset + 3] = gmul3(s0) ^ s1 ^ s2 ^ gmul2(s3)
   }
   return out
}

function addRoundKey(state: Uint8Array, roundKey: Uint8Array): Uint8Array
{
   const out = Uint8Array.from(state)
   for (let index = 0; index < out.length; index += 1)
   {
      out[index] ^= roundKey[index]!
   }
   return out
}

function gmul2(value: number): number
{
   return (value & 0x80) !== 0 ? (((value << 1) ^ 0x11b) & 0xff) : ((value << 1) & 0xff)
}

function gmul3(value: number): number
{
   return gmul2(value) ^ value
}

function readBigUInt64LE(bytes: Uint8Array, offset: number): bigint
{
   const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
   return view.getBigUint64(offset, true)
}
