# prodigy-sdk

Rust SDK for the Prodigy neuron/container control protocol and paired-service Aegis helpers.

- SDK version: `1.0.0`
- Wire series: `WIRE_V1`
- Wire protocol version: `1`

The crate keeps transport ownership with the caller by default. Borrowed-fd integration is the primary model; blocking helpers remain optional convenience paths.

The crate surface is split into:

- transport-neutral control-plane types and `NeuronHub`
- portable Aegis helpers under `prodigy_sdk::aegis`
- opinionated pairing-driven helpers under `prodigy_sdk::opinionated`
- optional Tokio integration under `prodigy_sdk::tokio_support`

Core features:

- `DefaultDispatch` for no-op callback handling
- `NeuronHub::handle_bytes(...)` for decode-and-dispatch in one step
- `NeuronHub::with_resource_delta_ack(...)` and `NeuronHub::with_credentials_refresh_ack()` for common control-plane ACK policy
- `NeuronHub::queue_ready()` plus `NeuronHub::drain_outbound_bytes()` for ready/queued outbound writes without manual frame building
- `aegis::AegisSession` for pairing hash, TFO bytes, and AEGIS-128L frame encode/decode
- `opinionated::AegisStream` and `opinionated::PairingBook` for the higher-level paired-service flow
- `tokio_support::TokioReactor` and `TokioNeuron::with_auto_acks()` behind the optional `tokio` feature for a reactor-style Tokio integration where the neuron socket is just one event source among others

Licensed under Apache-2.0.

Recommended example order:

- [`examples/aegis_roundtrip.rs`](./examples/aegis_roundtrip.rs)
  Current transport-neutral Aegis quickstart. It starts from a `SubscriptionPairing`, builds TFO bytes, encrypts one frame, and decrypts it on the peer side.
- [`examples/mesh_pingpong.rs`](./examples/mesh_pingpong.rs)
  Current control-plane reference example using startup pairings, live updates, explicit ACKs, and ready signaling. This example expects Prodigy runtime startup state or a deployment-plan-driven bring-up.
- [`examples/opinionated_aegis_roundtrip.rs`](./examples/opinionated_aegis_roundtrip.rs)
  Higher-level paired-service example using `PairingBook` and `AegisStream`.

Build the transport-neutral Aegis example with:

`cargo run --example aegis_roundtrip`

Build the mesh example binary with:

`cargo build --example mesh_pingpong --features tokio`

Build the opinionated Aegis example with:

`cargo run --example opinionated_aegis_roundtrip`
