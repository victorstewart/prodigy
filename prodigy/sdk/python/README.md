# prodigy-sdk

Transport-neutral Python SDK for the Prodigy neuron/container control protocol.

- SDK version: `1.0.0`
- Wire series: `WIRE_V1`
- Wire protocol version: `1`

The package is intentionally runtime-neutral. Applications keep ownership of the socket and feed bytes into the decoder from their own `asyncio`, selector, thread, or process model.

For ergonomic `asyncio` integration, the package now also includes:

- `AsyncioReactor` for generic app/neuron event multiplexing
- `AsyncioNeuron` for treating the neuron socket as one reactor source
- `AegisSession` for transport-neutral paired-service encrypt/decrypt, pairing hash derivation, and TFO payload construction
- `examples/aegis_roundtrip.py` for a minimal pairing-driven secure exchange example
- `examples/async_mesh_pingpong.py` for a single-binary advertiser/subscriber mesh pairing example that reacts to pairing callbacks and exchanges IPv6 ping/pong traffic before signaling ready

Recommended example order:

1. `examples/aegis_roundtrip.py`
   Standalone Aegis quickstart with pairing hash, TFO bytes, and one encrypt/decrypt cycle.
2. `examples/async_mesh_pingpong.py`
   Current control-plane reference example with startup pairings, live updates, ACK policy, and ready signaling. This example expects Prodigy runtime startup state or a deployment-plan-driven bring-up.

Verification:

- `PYTHONPATH=. python tests/test_neuron_hub.py`
- `PYTHONPATH=. python examples/aegis_roundtrip.py`
- `PYTHONPATH=. python examples/async_mesh_pingpong.py`

Licensed under Apache-2.0.
