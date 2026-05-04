// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

import { AegisSession, U128 } from "../neuron_hub.ts"
import type { ContainerParameters } from "../neuron_hub.ts"

const pairing = {
   secret: new U128(Uint8Array.from([
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
   ])),
   address: new U128(Uint8Array.from([
      0xfd, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
   ])),
   service: 0x2233000000001001n,
   port: 3210,
   applicationId: 0x2233,
   activate: true,
}

const parameters: ContainerParameters = {
   uuid: new U128(new Uint8Array(16)),
   memoryMB: 0,
   storageMB: 0,
   logicalCores: 0,
   neuronFD: -1,
   lowCPU: 0,
   highCPU: 0,
   advertises: [],
   subscriptionPairings: [pairing],
   advertisementPairings: [],
   private6: { address: new Uint8Array(16), cidr: 0, isIPv6: true },
   justCrashed: false,
   datacenterUniqueTag: 0,
   flags: [],
   credentialBundle: null,
}

const writer = AegisSession.fromSubscription(parameters.subscriptionPairings[0]!)
const reader = AegisSession.fromSubscription(parameters.subscriptionPairings[0]!)
const tfoData = writer.buildTFOData(Buffer.from("mesh-aegis", "ascii"))
const frame = writer.encrypt(Buffer.from("ping from prodigy-sdk", "ascii"))
const { plaintext } = reader.decrypt(frame)

console.log(`pairing_hash=0x${writer.pairingHash().toString(16)} tfo_bytes=${tfoData.length}`)
console.log(plaintext.toString("utf8"))
