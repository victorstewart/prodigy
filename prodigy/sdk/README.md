# Prodigy SDK

Every Prodigy workload must implement the versioned Neuron/container protocol: startup state, live topology and pairing updates, resource and credential changes, and explicit readiness reporting are part of the workload contract. The SDKs are optional convenience implementations; any language may implement the public protocol directly.

## Run an example

Start with an Aegis roundtrip in your language. These examples are standalone: they do not need a Prodigy runtime, startup state, or privileged environment.

| Language | Start here | Run command |
|---|---|---|
| C | [example](c/examples/aegis_roundtrip.c) | See [C SDK](c/README.md) |
| C++ | [example](cpp/examples/aegis_roundtrip.cpp) | See [C++ SDK](cpp/README.md) |
| Rust | [example](rust/examples/aegis_roundtrip.rs) | `cargo run --example aegis_roundtrip` from `sdk/rust/` |
| Go | [example](go/examples/aegis_roundtrip/main.go) | `go run ./examples/aegis_roundtrip` from `sdk/go/` |
| Python | [example](python/examples/aegis_roundtrip.py) | `PYTHONPATH=. python examples/aegis_roundtrip.py` from `sdk/python/` |
| TypeScript | [example](typescript/examples/aegis_roundtrip.ts) | See [TypeScript SDK](typescript/README.md) |

Next, read your language's mesh example. It is the runtime-integrated reference: every deployed workload must load startup parameters from `PRODIGY_PARAMS_FD` or `argv[1]`, seed local state, handle live pairing changes, apply resource and credential updates, and send `healthy` only after it is ready. Mesh examples need a real Prodigy deployment; they are not a substitute for the standalone first run.

Public-ingress plans currently use a full startup payload the public C++ reader
does not accept. The [HTTP example](../../examples/hello-prodigy/README.md) uses
the matching native runtime implementation. Check the [startup writer
boundary](WIRE.md#containerparameters) before choosing an integration path.

## Use an SDK in an application

The shared lifecycle is short:

1. Load packed `PRDPAR01` `ContainerParameters`, preferring `PRODIGY_PARAMS_FD`, then `argv[1]`.
2. Seed local state from initial pairings before consuming live control frames.
3. Incrementally decode the shared framed control stream.
4. Apply pairing, resource, and credentials callbacks; acknowledge updates according to the contract.
5. Signal healthy only when the application can safely serve.

For the precise meanings, use [INTERFACES.md](INTERFACES.md). For callback and ACK behavior, use the compact [CONTRACT.md](CONTRACT.md). For bytes, parser invariants, and versioned encodings, use [WIRE.md](WIRE.md). Paired-service Aegis behavior and vectors live in [AEGIS.md](AEGIS.md).

## Implement or maintain an SDK

The canonical implementation order is: primitive readers/writers, startup loading, incremental frame decoder, transport-neutral handler, shared fixtures, mesh example, then optional runtime adapters. Keep transport ownership external by default; adapters may sit above that core surface.

The protocol favors borrowed transport, incremental parsing of arbitrary chunks, packed binary frames, bounded hot-path allocation, and batching. This is a performance policy for SDK implementers, not a requirement for application authors to understand before their first example.

Use the [fixtures](fixtures/README.md) and `compatibility_matrix.sh` when changing an SDK or protocol surface. The matrix verifies fixtures, version metadata, language implementations, and installed C/C++ consumer boundaries. Version and release details live in [VERSIONING.md](VERSIONING.md) and [PUBLISHING.md](PUBLISHING.md); implementation sequencing notes remain in [NATIVE_ROADMAP.md](NATIVE_ROADMAP.md).

## Scope

`AegisHub` is outside SDK scope. SDKs do not require C++ object layouts, Bitsery, runtime-private headers, or a specific reactor, scheduler, or async framework. Prodigy-managed container-to-container traffic is IPv6-only, and SDKs must not introduce a parallel control plane.
