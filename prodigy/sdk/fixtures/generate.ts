import * as assert from "node:assert/strict"
import { createHash } from "node:crypto"
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"

import {
   buildMessageFrame,
   ContainerTopic,
   decodeContainerParameters,
   decodeCredentialBundle,
   decodeCredentialDelta,
   decodeMetricPairs,
   parseMessageFrame
} from "../typescript/neuron_hub.ts"

const FIXTURE_DIR = path.dirname(fileURLToPath(import.meta.url))
const VERSIONING_PATH = path.join(FIXTURE_DIR, "..", "versioning.json")

type FixtureKind = "startup" | "payload" | "frame" | "aegis"

interface VersioningPolicy
{
   wireSeries: string
   wireProtocolVersion: number
   fixtureManifestVersion: number
   fixtureCorpusVersion: number
   containerParametersMagic: string
   credentialBundleMagic: string
   credentialDeltaMagic: string
   policy: {
      breakingWireChangesRequireNewWireSeries: boolean
      nonBreakingWireByteChangesRequireWireProtocolVersionBump: boolean
      fixtureByteChangesRequireFixtureCorpusVersionBump: boolean
      manifestShapeChangesRequireFixtureManifestVersionBump: boolean
   }
}

interface TLSFixture
{
   name: string
   generation: bigint
   notBeforeMs: bigint
   notAfterMs: bigint
   certPEM: string
   keyPEM: string
   chainPEM: string
   dnsSANs: string[]
   ipSANs: Uint8Array[]
   tags: string[]
}

interface APIFixture
{
   name: string
   provider: string
   generation: bigint
   expiresAtMs: bigint
   activeFromMs: bigint
   sunsetAtMs: bigint
   material: string
   metadata: Array<[string, string]>
}

interface BundleFixture
{
   tlsIdentities: TLSFixture[]
   apiCredentials: APIFixture[]
   bundleGeneration: bigint
}

interface DeltaFixture
{
   bundleGeneration: bigint
   updatedTLS: TLSFixture[]
   removedTLSNames: string[]
   updatedAPI: APIFixture[]
   removedAPINames: string[]
   reason: string
}

interface FixtureEntry
{
   description: string
   file: string
   kind: FixtureKind
   name: string
   sha256: string
   size: number
   topic?: string
}

interface FixtureManifest
{
   manifestVersion: number
   wireSeries: string
   wireProtocolVersion: number
   fixtureCorpusVersion: number
   containerParametersMagic: string
   credentialBundleMagic: string
   credentialDeltaMagic: string
   policy: VersioningPolicy["policy"]
   fixtures: FixtureEntry[]
}

const VERSIONING = JSON.parse(fs.readFileSync(VERSIONING_PATH, "utf8")) as VersioningPolicy
const CONTAINER_PARAMETERS_MAGIC = Buffer.from(VERSIONING.containerParametersMagic, "ascii")
const CREDENTIAL_BUNDLE_MAGIC = Buffer.from(VERSIONING.credentialBundleMagic, "ascii")
const CREDENTIAL_DELTA_MAGIC = Buffer.from(VERSIONING.credentialDeltaMagic, "ascii")

class Writer
{
   private readonly parts: Buffer[] = []

   raw(bytes: Uint8Array): void
   {
      this.parts.push(Buffer.from(bytes))
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

function writeU128(writer: Writer, bytes: Uint8Array): void
{
   assert.equal(bytes.length, 16)
   writer.raw(bytes)
}

function writeIPAddress(writer: Writer, address: Uint8Array, isIPv6: boolean): void
{
   assert.equal(address.length, 16)
   writer.raw(address)
   writer.boolean(isIPv6)
}

function writeIPPrefix(writer: Writer, address: Uint8Array, cidr: number, isIPv6: boolean): void
{
   writeIPAddress(writer, address, isIPv6)
   writer.u8(cidr)
}

function writeStringArray(writer: Writer, values: string[]): void
{
   writer.u32(values.length)
   for (const value of values)
   {
      writer.string(value)
   }
}

function writeIPAddressArray(writer: Writer, values: Uint8Array[]): void
{
   writer.u32(values.length)
   for (const value of values)
   {
      writeIPAddress(writer, value, true)
   }
}

function writeTLSIdentity(writer: Writer, identity: TLSFixture): void
{
   writer.string(identity.name)
   writer.u64(identity.generation)
   writer.i64(identity.notBeforeMs)
   writer.i64(identity.notAfterMs)
   writer.string(identity.certPEM)
   writer.string(identity.keyPEM)
   writer.string(identity.chainPEM)
   writeStringArray(writer, identity.dnsSANs)
   writeIPAddressArray(writer, identity.ipSANs)
   writeStringArray(writer, identity.tags)
}

function writeAPICredential(writer: Writer, credential: APIFixture): void
{
   writer.string(credential.name)
   writer.string(credential.provider)
   writer.u64(credential.generation)
   writer.i64(credential.expiresAtMs)
   writer.i64(credential.activeFromMs)
   writer.i64(credential.sunsetAtMs)
   writer.string(credential.material)
   writer.u32(credential.metadata.length)
   for (const [key, value] of credential.metadata)
   {
      writer.string(key)
      writer.string(value)
   }
}

function encodeCredentialBundleFields(bundle: BundleFixture): Buffer
{
   const writer = new Writer()
   writer.u32(bundle.tlsIdentities.length)
   for (const identity of bundle.tlsIdentities)
   {
      writeTLSIdentity(writer, identity)
   }

   writer.u32(bundle.apiCredentials.length)
   for (const credential of bundle.apiCredentials)
   {
      writeAPICredential(writer, credential)
   }

   writer.u64(bundle.bundleGeneration)
   return writer.finish()
}

function encodeCredentialBundle(bundle: BundleFixture): Buffer
{
   const writer = new Writer()
   writer.raw(CREDENTIAL_BUNDLE_MAGIC)
   writer.raw(encodeCredentialBundleFields(bundle))
   return writer.finish()
}

function encodeCredentialDelta(delta: DeltaFixture): Buffer
{
   const writer = new Writer()
   writer.raw(CREDENTIAL_DELTA_MAGIC)
   writer.u64(delta.bundleGeneration)
   writer.u32(delta.updatedTLS.length)
   for (const identity of delta.updatedTLS)
   {
      writeTLSIdentity(writer, identity)
   }

   writeStringArray(writer, delta.removedTLSNames)
   writer.u32(delta.updatedAPI.length)
   for (const credential of delta.updatedAPI)
   {
      writeAPICredential(writer, credential)
   }

   writeStringArray(writer, delta.removedAPINames)
   writer.string(delta.reason)
   return writer.finish()
}

function encodeContainerParameters(bundle: BundleFixture): Buffer
{
   const writer = new Writer()
   writer.raw(CONTAINER_PARAMETERS_MAGIC)
   writeU128(writer, Uint8Array.from(Array.from({ length: 16 }, (_value, index) => 0xa0 + index)))
   writer.u32(1536)
   writer.u32(4096)
   writer.u16(5)
   writer.i32(11)
   writer.i32(2)
   writer.i32(4)

   writer.u32(1)
   writer.u64(0x445566778899aabbn)
   writer.u16(24001)

   writer.u32(1)
   writeU128(writer, Uint8Array.from(Array.from({ length: 16 }, (_value, index) => 0x10 + index)))
   writeU128(writer, Uint8Array.from(Array.from({ length: 16 }, (_value, index) => 0x20 + index)))
   writer.u64(0x2233000000001001n)
   writer.u16(3210)

   writer.u32(1)
   writeU128(writer, Uint8Array.from(Array.from({ length: 16 }, (_value, index) => 0x30 + index)))
   writeU128(writer, Uint8Array.from(Array.from({ length: 16 }, (_value, index) => 0x40 + index)))
   writer.u64(0x3344000000002002n)

   writeIPPrefix(writer, Buffer.concat([Buffer.from([0xfd, 0x42]), Buffer.alloc(14)]), 64, true)
   writer.boolean(false)
   writer.u8(23)
   writer.u32(3)
   writer.u64(44n)
   writer.u64(55n)
   writer.u64(66n)
   writer.boolean(true)
   writer.raw(encodeCredentialBundleFields(bundle))
   return writer.finish()
}

function encodeResourceDeltaPayload(): Buffer
{
   const writer = new Writer()
   writer.u16(6)
   writer.u32(2048)
   writer.u32(8192)
   writer.boolean(false)
   writer.u32(45)
   return writer.finish()
}

function encodeAdvertisementPairingPayload(): Buffer
{
   const writer = new Writer()
   writeU128(writer, Uint8Array.from(Array.from({ length: 16 }, (_value, index) => 0x51 + index)))
   writeU128(writer, Uint8Array.from(Array.from({ length: 16 }, (_value, index) => 0x61 + index)))
   writer.u64(0x5566000000003003n)
   writer.u16(0x5566)
   writer.boolean(true)
   return writer.finish()
}

function encodeSubscriptionPairingPayload(): Buffer
{
   const writer = new Writer()
   writeU128(writer, Uint8Array.from(Array.from({ length: 16 }, (_value, index) => 0x71 + index)))
   writeU128(writer, Uint8Array.from(Array.from({ length: 16 }, (_value, index) => 0x81 + index)))
   writer.u64(0x6677000000004004n)
   writer.u16(8123)
   writer.u16(0x6677)
   writer.boolean(true)
   return writer.finish()
}

function encodeStatisticsPayload(): Buffer
{
   const writer = new Writer()
   writer.u64(1n)
   writer.u64(2n)
   writer.u64(3n)
   writer.u64(4n)
   return writer.finish()
}

function fixtureTLSIdentity(): TLSFixture
{
   return {
      name: "demo-cert",
      generation: 11n,
      notBeforeMs: 1710000000000n,
      notAfterMs: 1810000000000n,
      certPEM: "-----BEGIN CERTIFICATE-----\nDEMO\n-----END CERTIFICATE-----\n",
      keyPEM: "-----BEGIN PRIVATE KEY-----\nDEMO\n-----END PRIVATE KEY-----\n",
      chainPEM: "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n",
      dnsSANs: ["demo.internal", "demo.prodigy.invalid"],
      ipSANs: [Buffer.concat([Buffer.from([0x20, 0x01, 0x0d, 0xb8, 0, 1]), Buffer.alloc(10)])],
      tags: ["default", "fixture"]
   }
}

function fixtureAPICredential(): APIFixture
{
   return {
      name: "demo-token",
      provider: "fixture-provider",
      generation: 22n,
      expiresAtMs: 1910000000000n,
      activeFromMs: 1710000000000n,
      sunsetAtMs: 1920000000000n,
      material: "token-material-123",
      metadata: [
         ["scope", "demo"],
         ["region", "ord"]
      ]
   }
}

function buildBundleFixture(): BundleFixture
{
   return {
      tlsIdentities: [fixtureTLSIdentity()],
      apiCredentials: [fixtureAPICredential()],
      bundleGeneration: 101n
   }
}

function buildDeltaFixture(): DeltaFixture
{
   return {
      bundleGeneration: 102n,
      updatedTLS: [{
         ...fixtureTLSIdentity(),
         generation: 12n,
         tags: ["rotated", "fixture"]
      }],
      removedTLSNames: ["legacy-cert"],
      updatedAPI: [{
         ...fixtureAPICredential(),
         generation: 23n,
         material: "token-material-456"
      }],
      removedAPINames: ["legacy-token"],
      reason: "fixture-rotation"
   }
}

function sha256(bytes: Uint8Array): string
{
   return createHash("sha256").update(bytes).digest("hex")
}

function writeFixture(
   entries: FixtureEntry[],
   name: string,
   kind: FixtureKind,
   description: string,
   bytes: Buffer,
   topic?: string): void
{
   const file = `${name}.bin`
   fs.writeFileSync(path.join(FIXTURE_DIR, file), bytes)
   entries.push({
      description,
      file,
      kind,
      name,
      sha256: sha256(bytes),
      size: bytes.length,
      ...(topic ? { topic } : {})
   })
}

function main(): void
{
   const entries: FixtureEntry[] = []
   const bundle = buildBundleFixture()
   const delta = buildDeltaFixture()
   const credentialBundleBytes = encodeCredentialBundle(bundle)
   const credentialDeltaBytes = encodeCredentialDelta(delta)
   const containerParametersBytes = encodeContainerParameters(bundle)
   const resourceDeltaPayload = encodeResourceDeltaPayload()
   const advertisementPairingPayload = encodeAdvertisementPairingPayload()
   const subscriptionPairingPayload = encodeSubscriptionPairingPayload()
   const datacenterUniqueTagPayload = Buffer.from([23])
   const statisticsPayload = encodeStatisticsPayload()
   const resourceDeltaAckPayload = Buffer.from([1])
   const messagePayload = Buffer.from("hello-prodigy", "utf8")

   const frames = [
      {
         bytes: buildMessageFrame(ContainerTopic.Ping),
         description: "Empty ping frame",
         kind: "frame" as const,
         name: "frame.ping.empty",
         topic: "ping"
      },
      {
         bytes: buildMessageFrame(ContainerTopic.Stop),
         description: "Empty stop frame",
         kind: "frame" as const,
         name: "frame.stop.empty",
         topic: "stop"
      },
      {
         bytes: buildMessageFrame(ContainerTopic.Healthy),
         description: "Empty healthy frame",
         kind: "frame" as const,
         name: "frame.healthy.empty",
         topic: "healthy"
      },
      {
         bytes: buildMessageFrame(ContainerTopic.Message, messagePayload),
         description: "Opaque message frame",
         kind: "frame" as const,
         name: "frame.message.demo",
         topic: "message"
      },
      {
         bytes: buildMessageFrame(ContainerTopic.ResourceDelta, resourceDeltaPayload),
         description: "Resource delta frame",
         kind: "frame" as const,
         name: "frame.resource_delta.scale_up",
         topic: "resourceDelta"
      },
      {
         bytes: buildMessageFrame(ContainerTopic.AdvertisementPairing, advertisementPairingPayload),
         description: "Advertisement pairing frame",
         kind: "frame" as const,
         name: "frame.advertisement_pairing.activate",
         topic: "advertisementPairing"
      },
      {
         bytes: buildMessageFrame(ContainerTopic.SubscriptionPairing, subscriptionPairingPayload),
         description: "Subscription pairing frame",
         kind: "frame" as const,
         name: "frame.subscription_pairing.activate",
         topic: "subscriptionPairing"
      },
      {
         bytes: buildMessageFrame(ContainerTopic.DatacenterUniqueTag, datacenterUniqueTagPayload),
         description: "Datacenter unique tag frame",
         kind: "frame" as const,
         name: "frame.datacenter_unique_tag.23",
         topic: "datacenterUniqueTag"
      },
      {
         bytes: buildMessageFrame(ContainerTopic.Statistics, statisticsPayload),
         description: "Statistics frame",
         kind: "frame" as const,
         name: "frame.statistics.demo",
         topic: "statistics"
      },
      {
         bytes: buildMessageFrame(ContainerTopic.ResourceDeltaAck, resourceDeltaAckPayload),
         description: "Accepted resource delta ack frame",
         kind: "frame" as const,
         name: "frame.resource_delta_ack.accepted",
         topic: "resourceDeltaAck"
      },
      {
         bytes: buildMessageFrame(ContainerTopic.CredentialsRefresh, credentialDeltaBytes),
         description: "Credential refresh frame with full delta payload",
         kind: "frame" as const,
         name: "frame.credentials_refresh.full",
         topic: "credentialsRefresh"
      },
      {
         bytes: buildMessageFrame(ContainerTopic.CredentialsRefresh),
         description: "Empty credentials refresh ack frame",
         kind: "frame" as const,
         name: "frame.credentials_refresh_ack.empty",
         topic: "credentialsRefresh"
      }
   ]

   writeFixture(entries, "startup.container_parameters.full", "startup", "ContainerParameters fixture with embedded credential bundle", containerParametersBytes)
   writeFixture(entries, "startup.credential_bundle.full", "startup", "Standalone CredentialBundle fixture", credentialBundleBytes)
   writeFixture(entries, "startup.credential_delta.full", "startup", "Standalone CredentialDelta fixture", credentialDeltaBytes)
   writeFixture(entries, "payload.resource_delta.scale_up", "payload", "Packed resource delta payload", resourceDeltaPayload, "resourceDelta")
   writeFixture(entries, "payload.advertisement_pairing.activate", "payload", "Packed advertisement pairing payload", advertisementPairingPayload, "advertisementPairing")
   writeFixture(entries, "payload.subscription_pairing.activate", "payload", "Packed subscription pairing payload", subscriptionPairingPayload, "subscriptionPairing")
   writeFixture(entries, "payload.datacenter_unique_tag.23", "payload", "Single-byte datacenter tag payload", datacenterUniqueTagPayload, "datacenterUniqueTag")
   writeFixture(entries, "payload.statistics.demo", "payload", "Packed metric pairs payload", statisticsPayload, "statistics")
   writeFixture(entries, "payload.resource_delta_ack.accepted", "payload", "Single-byte accepted ack payload", resourceDeltaAckPayload, "resourceDeltaAck")
   writeFixture(entries, "payload.credentials_refresh.full", "payload", "Credential refresh payload using CredentialDelta bytes", credentialDeltaBytes, "credentialsRefresh")

   for (const frame of frames)
   {
      writeFixture(entries, frame.name, frame.kind, frame.description, frame.bytes, frame.topic)
   }

   const decodedBundle = decodeCredentialBundle(credentialBundleBytes)
   assert.equal(decodedBundle.tlsIdentities[0]?.name, "demo-cert")
   assert.equal(decodedBundle.apiCredentials[0]?.metadata.get("scope"), "demo")

   const decodedDelta = decodeCredentialDelta(credentialDeltaBytes)
   assert.equal(decodedDelta.reason, "fixture-rotation")
   assert.deepEqual(decodedDelta.removedTLSNames, ["legacy-cert"])

   const decodedParameters = decodeContainerParameters(containerParametersBytes)
   assert.equal(decodedParameters.datacenterUniqueTag, 23)
   assert.equal(decodedParameters.flags.length, 3)
   assert.equal(decodedParameters.credentialBundle?.bundleGeneration, 101n)

   const parsedStatistics = decodeMetricPairs(statisticsPayload)
   assert.deepEqual(parsedStatistics, [
      { key: 1n, value: 2n },
      { key: 3n, value: 4n }
   ])

   for (const frame of frames)
   {
      const parsed = parseMessageFrame(frame.bytes)
      assert.equal(parsed.topic, frame.bytes.readUInt16LE(4))
      if (frame.name === "frame.statistics.demo")
      {
         assert.deepEqual(decodeMetricPairs(parsed.payload), parsedStatistics)
      }
   }

   entries.sort((left, right) => left.name.localeCompare(right.name))
   const manifest: FixtureManifest = {
      manifestVersion: VERSIONING.fixtureManifestVersion,
      wireSeries: VERSIONING.wireSeries,
      wireProtocolVersion: VERSIONING.wireProtocolVersion,
      fixtureCorpusVersion: VERSIONING.fixtureCorpusVersion,
      containerParametersMagic: VERSIONING.containerParametersMagic,
      credentialBundleMagic: VERSIONING.credentialBundleMagic,
      credentialDeltaMagic: VERSIONING.credentialDeltaMagic,
      policy: VERSIONING.policy,
      fixtures: entries
   }
   fs.writeFileSync(path.join(FIXTURE_DIR, "manifest.json"), `${JSON.stringify(manifest, null, 3)}\n`)
   console.log(`generated ${entries.length} fixtures in ${FIXTURE_DIR}`)
}

main()
