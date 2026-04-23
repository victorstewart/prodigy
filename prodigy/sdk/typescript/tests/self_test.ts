// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

import * as assert from "node:assert/strict"
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"

import * as sdk from "../neuron_hub.ts"

function fixtureBytes(name: string): Buffer
{
   return fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "fixtures", name))
}

function encodeCurrentDemoContainerParameters(): Buffer
{
   const parts: Buffer[] = []
   const pushU8 = (value: number): void => parts.push(Buffer.from([value]))
   const pushBool = (value: boolean): void => pushU8(value ? 1 : 0)
   const pushU16 = (value: number): void => {
      const bytes = Buffer.allocUnsafe(2)
      bytes.writeUInt16LE(value, 0)
      parts.push(bytes)
   }
   const pushU32 = (value: number): void => {
      const bytes = Buffer.allocUnsafe(4)
      bytes.writeUInt32LE(value, 0)
      parts.push(bytes)
   }
   const pushI32 = (value: number): void => {
      const bytes = Buffer.allocUnsafe(4)
      bytes.writeInt32LE(value, 0)
      parts.push(bytes)
   }
   const pushU64 = (value: bigint): void => {
      const bytes = Buffer.allocUnsafe(8)
      bytes.writeBigUInt64LE(value, 0)
      parts.push(bytes)
   }

   parts.push(Buffer.from("PRDPAR01", "ascii"))
   parts.push(Buffer.from(Array.from({ length: 16 }, (_value, index) => index)))
   pushU32(1024)
   pushU32(2048)
   pushU16(3)
   pushI32(9)
   pushI32(1)
   pushI32(3)
   pushU32(1)
   pushU64(0x1122334455667788n)
   pushU16(19111)
   pushU32(1)
   parts.push(Buffer.from(Array.from({ length: 16 }, (_value, index) => 16 + index)))
   parts.push(Buffer.from(Array.from({ length: 16 }, (_value, index) => 32 + index)))
   pushU64(0x1234000000000001n)
   pushU16(3210)
   pushU32(1)
   parts.push(Buffer.from(Array.from({ length: 16 }, (_value, index) => 48 + index)))
   parts.push(Buffer.from(Array.from({ length: 16 }, (_value, index) => 64 + index)))
   pushU64(0x5678000000000002n)
   parts.push(Buffer.concat([Buffer.from([0xfd]), Buffer.alloc(15)]))
   pushBool(true)
   pushU8(64)
   pushBool(false)
   pushU8(17)
   pushU32(2)
   pushU64(44n)
   pushU64(55n)
   pushBool(false)
   return Buffer.concat(parts)
}

function demoSubscriptionPairing(): sdk.SubscriptionPairing
{
   return {
      secret: new sdk.U128(Uint8Array.from([
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
      ])),
      address: new sdk.U128(Uint8Array.from([
         0xfd, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      ])),
      service: 0x2233000000001001n,
      port: 3210,
      applicationId: 0x2233,
      activate: true,
   }
}

async function main(): Promise<void>
{
   const bundle = sdk.decodeCredentialBundle(fixtureBytes("startup.credential_bundle.full.bin"))
   assert.equal(bundle.bundleGeneration, 101n)
   assert.equal(bundle.tlsIdentities[0]?.name, "demo-cert")
   assert.equal(bundle.apiCredentials[0]?.metadata.get("scope"), "demo")

   const delta = sdk.decodeCredentialDelta(fixtureBytes("startup.credential_delta.full.bin"))
   assert.equal(delta.bundleGeneration, 102n)
   assert.deepEqual(delta.removedTLSNames, ["legacy-cert"])
   assert.deepEqual(delta.removedAPINames, ["legacy-token"])
   assert.equal(delta.reason, "fixture-rotation")

   const parameters = sdk.decodeContainerParameters(fixtureBytes("startup.container_parameters.full.bin"))
   assert.equal(parameters.memoryMB, 1536)
   assert.equal(parameters.advertises[0]?.port, 24001)
   assert.equal(parameters.subscriptionPairings[0]?.applicationId, 0x2233)
   assert.equal(parameters.advertisementPairings[0]?.applicationId, 0x3344)
   assert.equal(parameters.datacenterUniqueTag, 23)
   assert.equal(parameters.credentialBundle?.bundleGeneration, 101n)

   const currentParameters = sdk.decodeContainerParameters(encodeCurrentDemoContainerParameters())
   assert.equal(currentParameters.memoryMB, 1024)
   assert.equal(currentParameters.justCrashed, false)

   const frame = fixtureBytes("frame.resource_delta_ack.accepted.bin")
   assert.equal(frame.readUInt32LE(0), frame.length)
   assert.equal(frame.readUInt16LE(4), sdk.ContainerTopic.ResourceDeltaAck)
   assert.equal(frame[7], 8)
   assert.equal(frame[6], frame.length - 8 - 1)

   const parsed = sdk.parseMessageFrame(frame)
   assert.equal(parsed.topic, sdk.ContainerTopic.ResourceDeltaAck)
   assert.equal(parsed.payload[0], 1)

   assert.deepEqual(sdk.decodeMetricPairs(fixtureBytes("payload.statistics.demo.bin")), [
      { key: 1n, value: 2n },
      { key: 3n, value: 4n },
   ])
   assert.deepEqual(sdk.buildReadyFrame(), fixtureBytes("frame.healthy.empty.bin"))
   assert.deepEqual(sdk.buildStatisticsFrame([{ key: 1n, value: 2n }, { key: 3n, value: 4n }]), fixtureBytes("frame.statistics.demo.bin"))
   assert.deepEqual(sdk.buildResourceDeltaAckFrame(true), fixtureBytes("frame.resource_delta_ack.accepted.bin"))
   assert.deepEqual(sdk.buildCredentialsRefreshAckFrame(), fixtureBytes("frame.credentials_refresh_ack.empty.bin"))

   const decoder = new sdk.FrameDecoder()
   const ping = sdk.buildMessageFrame(sdk.ContainerTopic.Ping)
   assert.deepEqual(decoder.feed(ping.subarray(0, 5)), [])
   const decoded = decoder.feed(ping.subarray(5))
   assert.equal(decoded.length, 1)
   const borrowedFD = fs.openSync("/dev/null", "r")
   const hub = sdk.NeuronHub.borrowedTransport(new sdk.NeuronHubDispatch(), parameters, borrowedFD)
   hub.close()
   fs.fstatSync(borrowedFD)
   assert.deepEqual(hub.handleFrame(decoded[0]!), [{
      topic: sdk.ContainerTopic.Ping,
      payload: Buffer.alloc(0),
   }])
   fs.closeSync(borrowedFD)

   const session = sdk.AegisSession.fromSubscription(demoSubscriptionPairing())
   assert.equal(session.pairingHash(), fixtureBytes("aegis.hash.demo.bin").readBigUInt64LE(0))
   assert.deepEqual(session.buildTFOData(Buffer.from("mesh-aegis", "ascii")), fixtureBytes("aegis.tfo.demo.bin"))
   const deterministicFrame = session.encrypt(
      Buffer.from("frame-one", "ascii"),
      new sdk.U128(Uint8Array.from([
         0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
         0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
      ]))
   )
   assert.deepEqual(deterministicFrame, fixtureBytes("aegis.frame.demo.bin"))
   const decrypted = session.decrypt(deterministicFrame)
   assert.deepEqual(decrypted.plaintext, Buffer.from("frame-one", "ascii"))
   assert.equal(decrypted.header.encryptedDataSize, "frame-one".length + sdk.AEGIS_TAG_BYTES)

   const malformed = Buffer.from(deterministicFrame)
   malformed[0] = 0
   assert.throws(() => sdk.decodeAegisFrameHeader(malformed))

   const reactor = new sdk.Reactor<string>()
   reactor.once("probe-ready", Promise.resolve())
   assert.deepEqual(await reactor.next(), { app: "probe-ready" })

   reactor.sink().neuron(sdk.NeuronEvent.Shutdown)
   const iterator = reactor[Symbol.asyncIterator]()
   assert.deepEqual((await iterator.next()).value, { neuron: sdk.NeuronEvent.Shutdown })

   console.log("typescript prodigy-sdk tests passed")
}

await main()
