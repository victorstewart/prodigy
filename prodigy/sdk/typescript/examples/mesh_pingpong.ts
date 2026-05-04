// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

import * as net from "node:net"
import process from "node:process"

import {
   AegisSession,
   type AdvertisementPairing,
   AsyncNeuron,
   type ContainerParameters,
   type CredentialDelta,
   DefaultDispatch,
   formatIPv6Address,
   type NeuronHub,
   NeuronEvent,
   Reactor,
   type ResourceDelta,
   type ReactorSink,
   sameIPv6Address,
   type SubscriptionPairing,
} from "../neuron_hub.ts"

const EXCHANGE_COUNT = 3
const CONNECT_TIMEOUT_MS = 2_000
const RETRY_DELAY_MS = 250
const STAT_PAIRINGS = 1n
const STAT_ACTIVE_PAIRINGS = 2n
const STAT_RESOURCE_DELTAS = 3n
const STAT_CREDENTIAL_REFRESHES = 4n
const STAT_DATACENTER_TAG = 5n

const Event = {
   PairingsChanged: "pairings-changed",
   MeshReady: "mesh-ready",
} as const

type Event = (typeof Event)[keyof typeof Event]
type Role = "advertiser" | "subscriber"

class PairingDispatch extends DefaultDispatch
{
   readonly advertisementPairings: AdvertisementPairing[] = []
   readonly subscriptionPairings: SubscriptionPairing[] = []
   private readonly onPairingsChanged: () => void
   private pairingEvents = 0
   private resourceDeltaEvents = 0
   private credentialsRefreshEvents = 0

   constructor(onPairingsChanged: () => void)
   {
      super()
      this.onPairingsChanged = onPairingsChanged
   }

   seed(parameters: ContainerParameters): void
   {
      this.advertisementPairings.length = 0
      this.subscriptionPairings.length = 0
      this.pairingEvents = 0
      this.resourceDeltaEvents = 0
      this.credentialsRefreshEvents = 0
      for (const pairing of parameters.advertisementPairings)
      {
         this.applyAdvertisementPairing(pairing)
      }
      for (const pairing of parameters.subscriptionPairings)
      {
         this.applySubscriptionPairing(pairing)
      }
   }

   publishStats(hub: NeuronHub): void
   {
      hub.publishStatistics([
         { key: STAT_PAIRINGS, value: BigInt(this.pairingEvents) },
         { key: STAT_ACTIVE_PAIRINGS, value: BigInt(this.advertisementPairings.length + this.subscriptionPairings.length) },
         { key: STAT_RESOURCE_DELTAS, value: BigInt(this.resourceDeltaEvents) },
         { key: STAT_CREDENTIAL_REFRESHES, value: BigInt(this.credentialsRefreshEvents) },
         { key: STAT_DATACENTER_TAG, value: BigInt(hub.parameters.datacenterUniqueTag) },
      ])
   }

   override advertisementPairing(hub: NeuronHub, pairing: AdvertisementPairing): void
   {
      this.applyAdvertisementPairing(pairing)
      this.publishStats(hub)
      this.onPairingsChanged()
   }

   override subscriptionPairing(hub: NeuronHub, pairing: SubscriptionPairing): void
   {
      this.applySubscriptionPairing(pairing)
      this.publishStats(hub)
      this.onPairingsChanged()
   }

   override resourceDelta(hub: NeuronHub, _delta: ResourceDelta): void
   {
      this.resourceDeltaEvents += 1
      hub.acknowledgeResourceDelta(true)
      this.publishStats(hub)
   }

   override credentialsRefresh(hub: NeuronHub, _delta: CredentialDelta): void
   {
      this.credentialsRefreshEvents += 1
      hub.acknowledgeCredentialsRefresh()
      this.publishStats(hub)
   }

   private applyAdvertisementPairing(pairing: AdvertisementPairing): void
   {
      this.pairingEvents += 1
      if (pairing.activate)
      {
         upsertAdvertisementPairing(this.advertisementPairings, pairing)
         return
      }

      removeAdvertisementPairing(this.advertisementPairings, pairing)
   }

   private applySubscriptionPairing(pairing: SubscriptionPairing): void
   {
      this.pairingEvents += 1
      if (pairing.activate)
      {
         upsertSubscriptionPairing(this.subscriptionPairings, pairing)
         return
      }

      removeSubscriptionPairing(this.subscriptionPairings, pairing)
   }
}

class MeshPingPong
{
   private readonly dispatch: PairingDispatch
   private readonly sink: ReactorSink<Event>
   private readonly role: Role
   private readonly localPrivate6Address: string
   private readonly listenPort: number
   private server: net.Server | null = null
   private ready = false
   private connectInFlight = false

   constructor(
      parameters: ContainerParameters,
      dispatch: PairingDispatch,
      sink: ReactorSink<Event>,
      localPrivate6Address: string,
   )
   {
      this.dispatch = dispatch
      this.sink = sink
      this.localPrivate6Address = localPrivate6Address
      this.role = inferRole(parameters)
      this.listenPort = parameters.advertises[0]?.port ?? 0
   }

   async start(): Promise<void>
   {
      if (this.role !== "advertiser")
      {
         return
      }

      const server = net.createServer((socket) => {
         void this.handleInbound(socket)
      })

      server.on("error", (error) => {
         this.sink.error(error)
      })

      await new Promise<void>((resolve, reject) => {
         const fail = (error: unknown): void =>
         {
            server.removeListener("listening", succeed)
            reject(error instanceof Error ? error : new Error(String(error)))
         }

         const succeed = (): void =>
         {
            server.removeListener("error", fail)
            resolve()
         }

         server.once("error", fail)
         server.once("listening", succeed)
         server.listen({
            host: "::",
            ipv6Only: true,
            port: this.listenPort,
         })
      })

      this.server = server
   }

   async close(): Promise<void>
   {
      const server = this.server
      this.server = null
      if (server === null)
      {
         return
      }

      await new Promise<void>((resolve) => {
         server.close(() => resolve())
      })
   }

   refresh(): void
   {
      if (this.ready || this.role !== "subscriber" || this.connectInFlight)
      {
         return
      }

      const pairing = this.dispatch.subscriptionPairings[0]
      if (pairing === undefined)
      {
         return
      }

      this.connectInFlight = true
      void this.runSubscriber(pairing)
   }

   private async handleInbound(socket: net.Socket): Promise<void>
   {
      if (!this.acceptsRemote(socket.remoteAddress))
      {
         socket.destroy()
         return
      }

      const pairing = this.dispatch.advertisementPairings[0]
      if (pairing === undefined)
      {
         socket.destroy()
         return
      }

      try
      {
         await servePingPong(socket, AegisSession.fromAdvertisement(pairing))
         this.signalMeshReady()
      }
      catch
      {
      }
      finally
      {
         socket.destroy()
      }
   }

   private acceptsRemote(remoteAddress: string | undefined): boolean
   {
      if (remoteAddress === undefined)
      {
         return false
      }

      if (this.dispatch.advertisementPairings.length === 0)
      {
         return true
      }

      return this.dispatch.advertisementPairings.some((pairing) =>
         sameIPv6Address(remoteAddress, formatIPv6Address(pairing.address.bytes)),
      )
   }

   private async runSubscriber(pairing: SubscriptionPairing): Promise<void>
   {
      let socket: net.Socket | null = null
      const session = AegisSession.fromSubscription(pairing)

      try
      {
         socket = await connectMeshPeer(
            formatIPv6Address(pairing.address.bytes),
            pairing.port,
            this.localPrivate6Address,
            CONNECT_TIMEOUT_MS,
         )
         await drivePingPong(socket, session)
         this.signalMeshReady()
      }
      catch
      {
         if (!this.ready)
         {
            setTimeout(() => {
               this.sink.app(Event.PairingsChanged)
            }, RETRY_DELAY_MS)
         }
      }
      finally
      {
         this.connectInFlight = false
         socket?.destroy()
      }
   }

   private signalMeshReady(): void
   {
      if (this.ready)
      {
         return
      }

      this.ready = true
      this.sink.app(Event.MeshReady)
   }
}

async function main(): Promise<void>
{
   const reactor = new Reactor<Event>()
   const sink = reactor.sink()
   const dispatch = new PairingDispatch(() => {
      sink.app(Event.PairingsChanged)
   })
   const asyncNeuron = AsyncNeuron.fromProcess(dispatch)
   const neuron = reactor.attachNeuron(asyncNeuron)
   const role = inferRole(neuron.parameters())
   let readySent = false

   dispatch.seed(neuron.parameters())
   dispatch.publishStats(asyncNeuron.hub)

   const mesh = new MeshPingPong(
      neuron.parameters(),
      dispatch,
      sink,
      neuron.private6Address(),
   )

   await mesh.start()
   if (role === "advertiser")
   {
      await neuron.ready()
      readySent = true
   }
   sink.app(Event.PairingsChanged)

   for await (const event of reactor)
   {
      if (event.neuron !== undefined)
      {
         if (event.neuron === NeuronEvent.Shutdown || event.neuron === NeuronEvent.Closed)
         {
            await mesh.close()
            return
         }

         continue
      }

      if (event.app === Event.PairingsChanged)
      {
         mesh.refresh()
         continue
      }

      if (event.app === Event.MeshReady && !readySent)
      {
         await neuron.ready()
         readySent = true
      }
   }
}

function inferRole(parameters: ContainerParameters): Role
{
   return parameters.advertises.length > 0 ? "advertiser" : "subscriber"
}

function upsertAdvertisementPairing(pairings: AdvertisementPairing[], next: AdvertisementPairing): void
{
   const key = advertisementPairingKey(next)
   const index = pairings.findIndex((value) => advertisementPairingKey(value) === key)
   if (index >= 0)
   {
      pairings[index] = next
      return
   }

   pairings.push(next)
}

function removeAdvertisementPairing(pairings: AdvertisementPairing[], target: AdvertisementPairing): void
{
   const key = advertisementPairingKey(target)
   const index = pairings.findIndex((value) => advertisementPairingKey(value) === key)
   if (index >= 0)
   {
      pairings.splice(index, 1)
   }
}

function upsertSubscriptionPairing(pairings: SubscriptionPairing[], next: SubscriptionPairing): void
{
   const key = subscriptionPairingKey(next)
   const index = pairings.findIndex((value) => subscriptionPairingKey(value) === key)
   if (index >= 0)
   {
      pairings[index] = next
      return
   }

   pairings.push(next)
}

function removeSubscriptionPairing(pairings: SubscriptionPairing[], target: SubscriptionPairing): void
{
   const key = subscriptionPairingKey(target)
   const index = pairings.findIndex((value) => subscriptionPairingKey(value) === key)
   if (index >= 0)
   {
      pairings.splice(index, 1)
   }
}

function advertisementPairingKey(pairing: AdvertisementPairing): string
{
   return `${pairing.service}:${pairing.applicationId}:${formatIPv6Address(pairing.address.bytes)}`
}

function subscriptionPairingKey(pairing: SubscriptionPairing): string
{
   return `${pairing.service}:${pairing.port}:${pairing.applicationId}:${formatIPv6Address(pairing.address.bytes)}`
}

async function connectMeshPeer(
   host: string,
   port: number,
   localAddress: string,
   timeoutMs: number,
): Promise<net.Socket>
{
   return await new Promise((resolve, reject) => {
      const socket = net.createConnection({
         family: 6,
         host,
         port,
         localAddress,
      })

      const fail = (error: unknown): void =>
      {
         socket.destroy()
         reject(error instanceof Error ? error : new Error(String(error)))
      }

      socket.setTimeout(timeoutMs, () => fail(new Error("mesh connect timeout")))
      socket.once("error", fail)
      socket.once("connect", () => {
         socket.setTimeout(0)
         socket.removeListener("error", fail)
         resolve(socket)
      })
   })
}

async function servePingPong(socket: net.Socket, session: AegisSession): Promise<void>
{
   const reader = new FrameReader(socket)

   for (let round = 1; round <= EXCHANGE_COUNT; round += 1)
   {
      const { plaintext } = session.decrypt(await reader.next())
      if (plaintext.equals(Buffer.from(`ping ${round}\n`, "utf8")) === false)
      {
         throw new Error(`unexpected ping payload ${plaintext.toString("utf8")}`)
      }

      await writeFrame(socket, session.encrypt(Buffer.from(`pong ${round}\n`, "utf8")))
   }
}

async function drivePingPong(socket: net.Socket, session: AegisSession): Promise<void>
{
   const reader = new FrameReader(socket)

   for (let round = 1; round <= EXCHANGE_COUNT; round += 1)
   {
      await writeFrame(socket, session.encrypt(Buffer.from(`ping ${round}\n`, "utf8")))
      const { plaintext } = session.decrypt(await reader.next())
      if (plaintext.equals(Buffer.from(`pong ${round}\n`, "utf8")) === false)
      {
         throw new Error(`unexpected pong payload ${plaintext.toString("utf8")}`)
      }
   }
}

class FrameReader
{
   private readonly socket: net.Socket
   private buffer = Buffer.alloc(0)

   constructor(socket: net.Socket)
   {
      this.socket = socket
   }

   async next(): Promise<Buffer>
   {
      for (;;)
      {
         if (this.buffer.length >= 4)
         {
            const frameBytes = this.buffer.readUInt32LE(0)
            if (frameBytes < 48 || frameBytes > (2 * 1024 * 1024) || (frameBytes % 16) !== 0)
            {
               throw new Error(`invalid Aegis frame size ${frameBytes}`)
            }
            if (this.buffer.length >= frameBytes)
            {
               const frame = this.buffer.subarray(0, frameBytes)
               this.buffer = this.buffer.subarray(frameBytes)
               return Buffer.from(frame)
            }
         }

         this.buffer = Buffer.concat([this.buffer, await readChunk(this.socket)])
      }
   }
}

async function readChunk(socket: net.Socket): Promise<Buffer>
{
   return await new Promise((resolve, reject) => {
      const onData = (chunk: Buffer): void =>
      {
         cleanup()
         resolve(Buffer.from(chunk))
      }

      const onClose = (): void =>
      {
         cleanup()
         reject(new Error("socket closed"))
      }

      const onError = (error: Error): void =>
      {
         cleanup()
         reject(error)
      }

      const cleanup = (): void =>
      {
         socket.removeListener("data", onData)
         socket.removeListener("close", onClose)
         socket.removeListener("end", onClose)
         socket.removeListener("error", onError)
      }

      socket.once("data", onData)
      socket.once("close", onClose)
      socket.once("end", onClose)
      socket.once("error", onError)
   })
}

async function writeFrame(socket: net.Socket, frame: Buffer): Promise<void>
{
   await new Promise<void>((resolve, reject) => {
      const onError = (error: Error): void =>
      {
         cleanup()
         reject(error)
      }

      const cleanup = (): void =>
      {
         socket.removeListener("error", onError)
      }

      socket.once("error", onError)
      socket.write(frame, (error?: Error | null) => {
         if (error !== undefined && error !== null)
         {
            cleanup()
            reject(error)
            return
         }

         cleanup()
         resolve()
      })
   })
}

await main().catch((error: unknown) => {
   console.error(error)
   process.exitCode = 1
})
