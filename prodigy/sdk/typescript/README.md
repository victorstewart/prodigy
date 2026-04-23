# prodigy-sdk

Transport-neutral TypeScript SDK for the Prodigy neuron/container control protocol.

- SDK version: `1.0.0`
- Wire series: `WIRE_V1`
- Wire protocol version: `1`

The package does not impose a runtime framework. Consumers keep stream ownership and can integrate the decoder and frame builders into their own event loop, worker, or socket abstraction.

For a concise Node async shape, use `Reactor` plus `AsyncNeuron`. For paired services, use `AegisSession` to turn `subscriptionPairing` / `advertisementPairing` secrets into transport-neutral pairing hashes, TFO bytes, and encrypted frames.

The mesh pingpong example uses the neuron socket as one reactor source and pairings as the trigger for the application’s own IPv6 server/client work:

```ts
const reactor = new Reactor<Event>()
const sink = reactor.sink()
const dispatch = new PairingDispatch(() => {
   sink.app(Event.PairingsChanged)
})
const neuron = reactor.attachNeuron(
   AsyncNeuron.fromProcess(dispatch).withAutoAcks(),
)
dispatch.seed(neuron.parameters())

for await (const event of reactor)
{
   if (event.neuron !== undefined)
   {
      if (event.neuron === NeuronEvent.Shutdown || event.neuron === NeuronEvent.Closed)
      {
         return
      }

      continue
   }

   if (event.app === Event.PairingsChanged)
   {
      mesh.refresh()
      continue
   }

   if (event.app === Event.MeshReady)
   {
      await neuron.ready()
   }
}
```

Example files:

- `examples/aegis_roundtrip.ts`
  Standalone Aegis quickstart with pairing hash, TFO bytes, and one encrypt/decrypt cycle.
- `examples/mesh_pingpong.ts`
  Current control-plane reference example with startup pairings, live updates, ACK policy, and ready signaling. This example expects Prodigy runtime startup state or a deployment-plan-driven bring-up.
- `examples/mesh_pingpong.advertiser.deployment.plan.v1.json`
- `examples/mesh_pingpong.subscriber.deployment.plan.v1.json`

Verification:

- `npm run build`
- `npm run self-test`
- `node --experimental-strip-types examples/aegis_roundtrip.ts`

Licensed under Apache-2.0.
