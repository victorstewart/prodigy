# prodigy-sdk (Go)

Transport-neutral Go module for the Prodigy neuron/container control protocol.

- SDK version: `1.0.0`
- Wire series: `WIRE_V1`
- Wire protocol version: `1`

The module keeps socket ownership external by default so applications can integrate the decoder and frame builders into their own netpoll or goroutine model.

For ergonomic goroutine-based integration, the module now also includes:

- `Reactor[T]` for generic app/neuron event multiplexing
- `Reactor.Sink()` for feeding app events back into the same reactor from pairing callbacks or other goroutines
- `AttachNeuron(...)` for treating an initialized `NeuronHub` as one reactor source
- `SubscriptionPairing.Target()` and `AdvertisementPairing.PeerAddr()` for turning pairing payloads into `netip` addresses
- `AegisSession` for transport-neutral paired-service encrypt/decrypt, pairing hash derivation, and TFO payload construction
- `examples/aegis_roundtrip/main.go` for the minimal pairing-driven secure exchange example
- `examples/mesh_pingpong/main.go` for the minimal service-mesh pingpong example
- `examples/mesh_pingpong.advertiser.deployment.plan.v1.json` and `examples/mesh_pingpong.subscriber.deployment.plan.v1.json` for the matching mesh plans

Recommended example order:

1. `examples/aegis_roundtrip/main.go`
   Standalone Aegis quickstart with pairing hash, TFO bytes, and one encrypt/decrypt cycle.
2. `examples/mesh_pingpong/main.go`
   Current control-plane reference example with startup pairings, live updates, ACK policy, and ready signaling. This example expects Prodigy runtime startup state or a deployment-plan-driven bring-up.

Example shape:

```go
reactor := neuronhub.NewReactor[meshEvent]()
dispatch := &meshDispatch{sink: reactor.Sink()}
hub, _ := neuronhub.NewNeuronHub(dispatch, nil)
neuron, _ := reactor.AttachNeuron(hub.WithAutoAcks())

reactor.Once(meshEvent{Kind: eventSubscriberPong}, func() error {
   return runSubscriberPing(pairing)
})
```

Verification:

- `go test ./...`
- `go run ./examples/aegis_roundtrip`
- `go run ./examples/mesh_pingpong`

Licensed under Apache-2.0.
