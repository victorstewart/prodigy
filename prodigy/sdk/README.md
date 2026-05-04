# Prodigy SDK

This directory contains the canonical Prodigy SDK contract, fixtures, and reference implementations for the neuron `<->` container protocol.

If you are implementing a new SDK in another language, start here:

1. [`INTERFACES.md`](./INTERFACES.md)
2. [`WIRE.md`](./WIRE.md)
3. [`AEGIS.md`](./AEGIS.md)
4. [`CONTRACT.md`](./CONTRACT.md)
5. the shared fixtures under [`fixtures/`](./fixtures/)
6. the mesh examples listed below

The goal is that a new SDK author should be able to implement the protocol directly from those documents plus the examples, without reverse-engineering monorepo-private C++ code.

## Performance Policy

All SDKs should be written with maximal performance in mind.

- borrowed transport must be a first-class path
- decoding must work incrementally on arbitrary byte chunks
- control frames and payloads stay binary and packed
- copies and allocations on the hot path should be minimized
- batching should be preserved for:
  - multi-frame reads
  - queued outbound responses
  - multi-metric statistics frames

The transport-neutral layer should stay framework-agnostic. Optional reactor or runtime adapters are fine, but they should sit on top of the core protocol surface.

## What Lives Here

- [`INTERFACES.md`](./INTERFACES.md): canonical semantic contract and implementer guide
- [`WIRE.md`](./WIRE.md): packed byte encodings and parser invariants
- [`AEGIS.md`](./AEGIS.md): paired-service Aegis session contract and deterministic vectors
- [`CONTRACT.md`](./CONTRACT.md): callback and lifecycle summary
- [`VERSIONING.md`](./VERSIONING.md): version and bump policy
- [`versioning.json`](./versioning.json): machine-readable version metadata
- [`fixtures/`](./fixtures/): shared binary fixtures and manifest
- language SDKs under `c/`, `cpp/`, `rust/`, `go/`, `python/`, and `typescript/`
- language quickstarts:
  - [`c/README.md`](./c/README.md)
  - [`cpp/README.md`](./cpp/README.md)
  - [`rust/README.md`](./rust/README.md)
  - [`go/README.md`](./go/README.md)
  - [`python/README.md`](./python/README.md)
  - [`typescript/README.md`](./typescript/README.md)

## Authoritative Examples

Use the standalone Aegis examples first, then move to the mesh/control examples, then use the opinionated wrappers where that language has them:

- C:
  - start here: [`c/examples/aegis_roundtrip.c`](./c/examples/aegis_roundtrip.c)
  - then: [`c/examples/mesh_pingpong.c`](./c/examples/mesh_pingpong.c)
- C++:
  - start here: [`cpp/examples/aegis_roundtrip.cpp`](./cpp/examples/aegis_roundtrip.cpp)
  - then: [`cpp/examples/io_uring_mesh_pingpong.cpp`](./cpp/examples/io_uring_mesh_pingpong.cpp)
  - higher-level wrapper: [`cpp/examples/opinionated_aegis_roundtrip.cpp`](./cpp/examples/opinionated_aegis_roundtrip.cpp)
- Rust:
  - start here: [`rust/examples/aegis_roundtrip.rs`](./rust/examples/aegis_roundtrip.rs)
  - then: [`rust/examples/mesh_pingpong.rs`](./rust/examples/mesh_pingpong.rs)
  - higher-level wrapper: [`rust/examples/opinionated_aegis_roundtrip.rs`](./rust/examples/opinionated_aegis_roundtrip.rs)
- Go:
  - start here: [`go/examples/aegis_roundtrip/main.go`](./go/examples/aegis_roundtrip/main.go)
  - then: [`go/examples/mesh_pingpong/main.go`](./go/examples/mesh_pingpong/main.go)
- Python:
  - start here: [`python/examples/aegis_roundtrip.py`](./python/examples/aegis_roundtrip.py)
  - then: [`python/examples/async_mesh_pingpong.py`](./python/examples/async_mesh_pingpong.py)
- TypeScript:
  - start here: [`typescript/examples/aegis_roundtrip.ts`](./typescript/examples/aegis_roundtrip.ts)
  - then: [`typescript/examples/mesh_pingpong.ts`](./typescript/examples/mesh_pingpong.ts)

The standalone Aegis examples are intentionally runnable without Prodigy runtime startup state. The mesh examples are the current end-to-end control-plane references and show how to:

- load startup parameters from `PRODIGY_PARAMS_FD` or `argv[1]`
- seed local state from startup pairings
- process live pairing updates on the shared control stream
- ACK `resourceDelta` and `credentialsRefresh`
- send `healthy` only after the container is ready

## Legacy Compatibility Notes

Current packed startup writers no longer emit:

- `public6`
- `requires_public4`
- `requires_public6`

The checked-in SDK examples are hard-cut over to the current startup contract. If a downstream runtime still needs those legacy public-egress fields, treat that as an out-of-tree compatibility layer rather than part of the main SDK contract.

## Implementation Order For A New SDK

1. Implement the primitive readers and writers from [`WIRE.md`](./WIRE.md).
2. Implement startup loading with the exact precedence in [`INTERFACES.md`](./INTERFACES.md).
3. Implement the incremental control-frame decoder.
4. Implement the transport-neutral frame handler and outbound helpers.
5. Pass the fixture corpus for startup objects, payloads, and full frames.
6. Match one of the mesh examples.
7. Match the deterministic Aegis vectors in [`AEGIS.md`](./AEGIS.md) if the SDK implements paired-service support.
8. Only then add optional opinionated stream layers.

## Current Boundaries

- `AegisHub` is intentionally out of SDK scope.
- The C SDK ships as its own package surface in this repo: `ProdigySDKC`.
- The installed C++ package exports `Prodigy::SdkCpp` and `Prodigy::SdkCppOpinionated`.
- The transport-neutral C++ SDK now always includes the portable Aegis session surface and its Aegis/gxhash dependencies.
- The opinionated C++ SDK may reuse existing repo-native code when that preserves the fast path, but its installed package boundary now resolves Basics, Aegis, and gxhash through the SDK's shipped depofile inventory instead of assuming monorepo-local targets.
- `cpp/io_uring_reactor.h` remains a source/build-tree header because it still lacks its own installed liburing-backed consumer target.
- Rust gets both transport-neutral and opinionated surfaces, but the opinionated Rust layer should still be an idiomatic clean-room implementation.

## Supporting Files

- [`CMakeLists.txt`](./CMakeLists.txt): standalone install and export package for C and C++ SDK artifacts
- [`LICENSE`](./LICENSE): Apache-2.0 license text
- [`compatibility_matrix.sh`](./compatibility_matrix.sh): fixture-backed local compatibility runner
- [`NATIVE_ROADMAP.md`](./NATIVE_ROADMAP.md): implementation sequencing notes
- [`PUBLISHING.md`](./PUBLISHING.md): release channel and artifact model for each SDK language

Run the compatibility matrix from the Prodigy repo root with:

```bash
prodigy/sdk/compatibility_matrix.sh
```

That command configures the standalone SDK build in `./.run/`, checks fixture/version metadata, verifies that `fixtures/generate.ts` reproduces the checked-in corpus without diff, checks that SDK release and wire-version metadata stay aligned across headers/manifests/READMEs, and runs the checked-in C, C++, Rust, Go, Python, and TypeScript verification paths against the shared corpus.
It also installs the SDK to a temporary prefix, proves both downstream package boundaries (`find_package(ProdigySDKC)` and `find_package(ProdigySDK)`), builds installed consumers against the C Aegis API plus the base and opinionated C++ targets, and runs release-packaging checks for Rust, Python, and TypeScript.
