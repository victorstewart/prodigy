# Native Runtime Roadmap

This is the implementation order for full transport-agnostic runtimes in C, C++, Rust, Go, Python, and TypeScript, alongside the existing Ring-backed C++ implementation.

## Phase 1

Complete.

- explicit startup bootstrap wire codec
- explicit `CredentialBundle` wire codec
- explicit `CredentialDelta` wire codec
- legacy Bitsery read fallback during rollout

## Phase 2

Complete for the currently defined container-facing topics.

Switch neuron control-topic payloads to packed `WIRE_V1` encoding in C++:

1. `resourceDelta` complete
2. `advertisementPairing` complete
3. `subscriptionPairing` complete
4. `credentialsRefresh` complete
5. `datacenterUniqueTag` already explicit as one byte
6. `statistics` already explicit as packed metric pairs
7. `resourceDeltaAck` already explicit as one byte

Required Prodigy-private C++ touch points:

- [`neuron/neuron.h`](../neuron/neuron.h)
- [`neuron/containers.h`](../neuron/containers.h)
- [`ingress.validation.h`](../ingress.validation.h)
- new adversarial and round-trip fixtures under `prodigy/dev/tests`

## Phase 3

Complete for local execution.

Build conformance assets.

- golden binary fixtures for startup payloads
- golden binary fixtures for each control-topic payload
- cross-language fixture readers
- one compatibility matrix that proves legacy C++ and native runtimes interoperate during rollout

Current state:

- shared fixture corpus now exists under `prodigy/sdk/fixtures`
- generator and manifest are checked in
- wire and fixture bump policy now lives in `prodigy/sdk/VERSIONING.md` and `prodigy/sdk/versioning.json`
- per-language fixture consumers now exist for C, C++, Rust, Go, Python, and TypeScript
- `sdk/compatibility_matrix.sh` now runs the shared fixture corpus across all six transport-agnostic runtimes plus the legacy Ring-backed Prodigy C++ path

## Phase 4

Complete.

Protocol SDKs now exist in:

- C: public API plus `.c` implementation and standalone self-test
- C++: standard-library-only transport-agnostic header plus fixture-backed unit coverage
- Rust: transport-agnostic SDK with unit tests
- Go: transport-agnostic SDK implementation
- Python: transport-agnostic SDK with self-test
- TypeScript: transport-agnostic Node SDK with self-test

Owned blocking helpers exist where convenient, but borrowed external transport remains the primary integration model.

## Phase 5

Complete for local language-level verification.

Deliverables:

- per-language readers over the same bytes
- compatibility tests against the same binary corpus

## Phase 6

Add ergonomic wrappers where useful.

Deliverables:

- Rust async wrapper if needed
- Go channel/concurrency wrapper if needed
- Python `asyncio` wrapper if needed
- TypeScript stream/worker wrapper if needed
- C++ wrapper helpers if needed, separate from `networking/neuron.hub.h`
- C convenience helpers only if they do not obscure the ABI

## Definition Of Done

We are done when:

- all six transport-agnostic language runtimes can parse `ContainerParameters`
- all six can receive and emit every control topic defined in `WIRE_V1`
- all six pass the same fixture corpus
- the legacy Ring-backed C++ implementation is verified against the same bytes
- no language implementation depends on reproducing C++ alignment behavior
