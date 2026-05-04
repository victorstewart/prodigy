# Prodigy Interfaces

Canonical SDK contract and implementer guide for writing Prodigy runtimes in any language.

## Status

- Document version: `2`
- Wire series: `WIRE_V1`
- Protocol version: `1`

Latest writer and launcher references:

- [`../wire.h`](../wire.h): packed startup, credential, and control-payload writers/readers
- [`../neuron/containers.h`](../neuron/containers.h): startup payload selection and `PRODIGY_PARAMS_FD` handoff

If this file conflicts with older examples or older SDK readers, treat this file plus [`WIRE.md`](./WIRE.md) and the current writers above as authoritative. Historical `public6` bootstrap fields are not part of the latest contract.

## Scope

This file defines the SDK-facing Prodigy interfaces:

- startup bootstrap objects
- neuron `<->` container control stream frames
- control-topic payload semantics
- credential object encodings
- pairing payloads
- paired-service Aegis session contract
- SDK design rules needed for cross-language implementations

This file does not define:

- Mothership CLI or deployment-plan JSON
- internal Brain/Neuron/Mothership RPCs
- legacy Bitsery bootstrap details for wormholes and whiteholes
- `AegisHub`

## Authoritative Sources And Precedence

Use the sources in this order:

1. [`INTERFACES.md`](./INTERFACES.md) for semantic contract and lifecycle rules.
2. [`WIRE.md`](./WIRE.md) for byte layout, parser invariants, and exact field order.
3. [`AEGIS.md`](./AEGIS.md) for the paired-service Aegis contract and deterministic vectors.
4. [`../wire.h`](../wire.h) and [`../neuron/containers.h`](../neuron/containers.h) for the currently emitted bytes.
5. Checked-in examples for integration shape and expected usage patterns.

Examples are usage references, not wire-format authorities. If an example disagrees with the canonical docs or current writers, the example is stale.

## Performance Rules

Every SDK should be written with maximal performance in mind within its language boundary.

- Treat caller-owned transport as a first-class path. A borrowed socket/stream integration should not be a second-class feature.
- Support incremental frame decoding from arbitrary byte chunks. Do not require callers to hand the SDK one whole frame at a time.
- Minimize copies and allocations on the hot path. Borrow frame payload bytes when the language makes that safe and ergonomic.
- Reuse decode buffers, outbound scratch buffers, and metric/frame containers when practical.
- Keep the control protocol binary. Do not add JSON, reflection, or dynamic schema layers on the hot path.
- Preserve batching opportunities:
  - one read may yield many frames
  - one handler pass may queue many outbound frames
  - one statistics frame may carry many metric pairs
- Zero-fill tail padding on writes so fixtures remain deterministic.
- Avoid runtime-imposed event loops in the transport-neutral layer. The core SDK should compose cleanly with the host language's fastest mainstream I/O model.

## Common Encoding Rules

All scalar fields are little-endian.

- `u8`: 1 byte
- `u16`: 2 bytes
- `u32`: 4 bytes
- `u64`: 8 bytes
- `i32`: 4 bytes two's-complement
- `i64`: 8 bytes two's-complement
- `u128`: 16 bytes little-endian
- `bool`: `u8`, where `0` is false and `1` is true
- `bytes`: `u32 length` followed by raw bytes
- `string`: `bytes`, UTF-8 by convention
- `array<T>`: `u32 count` followed by `count` encoded elements
- `map<string,string>`: `u32 count` followed by repeated `string key, string value`

The protocol never uses host alignment, native `bool`, compiler padding, or object layout as wire semantics.

## Bootstrap Objects

### `IPAddress`

Field order:

1. `address: u128`
2. `is_ipv6: bool`

### `IPPrefix`

Field order:

1. `address: u128`
2. `is_ipv6: bool`
3. `cidr: u8`

### `TlsIdentity`

Field order:

1. `name: string`
2. `generation: u64`
3. `not_before_ms: i64`
4. `not_after_ms: i64`
5. `cert_pem: string`
6. `key_pem: string`
7. `chain_pem: string`
8. `dns_sans: array<string>`
9. `ip_sans: array<IPAddress>`
10. `tags: array<string>`

### `ApiCredential`

Field order:

1. `name: string`
2. `provider: string`
3. `generation: u64`
4. `expires_at_ms: i64`
5. `active_from_ms: i64`
6. `sunset_at_ms: i64`
7. `material: string`
8. `metadata: map<string,string>`

### `CredentialBundle`

Magic: `PRDBUN01`

Field order:

1. `tls_identities: array<TlsIdentity>`
2. `api_credentials: array<ApiCredential>`
3. `bundle_generation: u64`

### `CredentialDelta`

Magic: `PRDDEL01`

Field order:

1. `bundle_generation: u64`
2. `updated_tls: array<TlsIdentity>`
3. `removed_tls_names: array<string>`
4. `updated_api: array<ApiCredential>`
5. `removed_api_names: array<string>`
6. `reason: string`

### `ContainerParameters`

Magic: `PRDPAR01`

Bootstrap acquisition precedence:

1. If `PRODIGY_PARAMS_FD` is present and non-empty, parse it as a decimal file descriptor, read the full blob from that inherited fd, and decode it.
2. Otherwise, if `argv[1]` exists, decode the raw bytes of `argv[1]`.
3. Otherwise, bootstrap is missing and startup must fail.

Latest startup field order:

1. `uuid: u128`
2. `memory_mb: u32`
3. `storage_mb: u32`
4. `logical_cores: u16`
5. `neuron_fd: i32`
6. `low_cpu: i32`
7. `high_cpu: i32`
8. `advertises: array<{ service: u64, port: u16 }>`
9. `subscription_pairings: array<{ secret: u128, address: u128, service: u64, port: u16 }>`
10. `advertisement_pairings: array<{ secret: u128, address: u128, service: u64 }>`
11. `private6: IPPrefix`
12. `just_crashed: bool`
13. `datacenter_unique_tag: u8`
14. `flags: array<u64>`
15. `has_credential_bundle: bool`
16. `credential_bundle` if present

Startup pairing rules:

- bootstrap pairings do not carry `application_id`
- bootstrap readers infer `application_id` from the top 16 bits of `service`
- bootstrap pairings imply `activate = true`

Startup state rules:

- seed your local pairing state from the startup pairing arrays before processing live control frames
- `private6` is the container's private IPv6 prefix for mesh traffic and local binding decisions
- `datacenter_unique_tag` is mutable state and may later be updated by a control frame

Current scope note:

- if a startup payload needs `wormholes` or `whiteholes`, the runtime still falls back to legacy Bitsery bootstrap instead of this packed startup blob

Compatibility note:

- historical readers and fixtures may have included `public6`, `requires_public4`, and `requires_public6` between `private6` and `just_crashed`
- the current `ProdigyWire::serializeContainerParameters(...)` writer does not emit those fields
- new SDKs should implement the latest shape above; legacy fallback is optional compatibility behavior, not part of the primary contract

## Control Socket Frame

The neuron `<->` container control stream uses one shared outer frame:

1. `size: u32`
2. `topic: u16`
3. `padding: u8`
4. `header_size: u8`
5. `payload: bytes`
6. `tail_padding: bytes`

Frame rules:

- `header_size` is always `8`
- `size` includes header, payload, and tail padding
- `padding` is the number of tail bytes after the payload
- frames are padded to a 16-byte boundary
- payload bytes are packed with no internal alignment gaps
- writers should zero-fill tail padding bytes
- readers may ignore tail padding contents after validating the declared layout

Recommended incremental parse algorithm:

1. Wait until at least 8 bytes are available.
2. Read `size` and `header_size`.
3. Reject the frame if:
   - `header_size != 8`
   - `size < 8`
   - `size % 16 != 0`
4. If fewer than `size` bytes are currently buffered, wait for more bytes.
5. Read `topic` and `padding`.
6. Reject the frame if:
   - `topic` is not a defined control topic
   - `padding > size - 8`
7. Payload bytes are `size - 8 - padding`.
8. Dispatch the payload and drop exactly `size` bytes from the buffer.

Recommended frame build algorithm:

1. Compute `base_size = 8 + payload_size`.
2. Compute `padding = (16 - (base_size % 16)) % 16`.
3. Emit `size = base_size + padding`.
4. Emit `topic`, `padding`, and `header_size = 8`.
5. Emit payload bytes.
6. Emit `padding` zero bytes.

## Control Topics

Topic values:

- `0`: `none`
- `1`: `ping`
- `2`: `pong`
- `3`: `stop`
- `4`: `advertisementPairing`
- `5`: `subscriptionPairing`
- `6`: `healthy`
- `7`: `message`
- `8`: `resourceDelta`
- `9`: `datacenterUniqueTag`
- `10`: `statistics`
- `11`: `resourceDeltaAck`
- `12`: `credentialsRefresh`

Inbound semantics for the shared frame handler:

- `none`
  - payload: empty
  - meaning: end-of-dynamic-args sentinel
  - handler behavior: notify the `endOfDynamicArgs`-style callback
- `ping`
  - payload: empty
  - meaning: keepalive
  - handler behavior: return exactly one empty `ping` response frame and do not surface a callback by default
- `pong`
  - payload: empty
  - meaning: protocol housekeeping only
  - handler behavior: no-op
- `stop`
  - payload: empty
  - meaning: begin shutdown
  - handler behavior: mark local shutdown state and notify the `beginShutdown`-style callback
- `advertisementPairing`
  - payload: packed `AdvertisementPairing`
  - handler behavior: decode and notify the advertisement-pairing callback
- `subscriptionPairing`
  - payload: packed `SubscriptionPairing`
  - handler behavior: decode and notify the subscription-pairing callback
- `healthy`
  - payload: empty
  - meaning: normally outbound from container to neuron
  - handler behavior: no-op if observed on the inbound parser path
- `message`
  - payload: opaque bytes
  - handler behavior: deliver exactly as bytes to the application callback
- `resourceDelta`
  - payload: packed `ResourceDelta`
  - handler behavior: decode and notify the resource-delta callback
  - ack behavior: either the application explicitly sends `resourceDeltaAck`, or the SDK may auto-queue one if configured to do so
- `datacenterUniqueTag`
  - payload: exactly one byte
  - handler behavior: update cached `parameters.datacenter_unique_tag`
  - no application callback is required
- `statistics`
  - payload: repeated packed metric pairs
  - meaning: normally outbound from container to neuron
  - handler behavior: no-op if observed on the inbound parser path
- `resourceDeltaAck`
  - payload: exactly one byte
  - meaning: normally outbound from container to neuron
  - handler behavior: no-op if observed on the inbound parser path
- `credentialsRefresh`
  - payload: either empty or packed `CredentialDelta`
  - handler behavior:
    - empty payload means ack/no-op
    - non-empty payload must decode to `CredentialDelta` and notify the credentials-refresh callback
  - ack behavior: if the SDK offers auto-ack policy, it should queue an empty outbound `credentialsRefresh` frame after a successful callback

## Control Payloads

### `resourceDelta`

Field order:

1. `logical_cores: u16`
2. `memory_mb: u32`
3. `storage_mb: u32`
4. `is_downscale: bool`
5. `grace_seconds: u32`

### `advertisementPairing`

Field order:

1. `secret: u128`
2. `address: u128`
3. `service: u64`
4. `application_id: u16`
5. `activate: bool`

### `subscriptionPairing`

Field order:

1. `secret: u128`
2. `address: u128`
3. `service: u64`
4. `port: u16`
5. `application_id: u16`
6. `activate: bool`

### `datacenterUniqueTag`

Field order:

1. `datacenter_unique_tag: u8`

### `statistics`

Payload is repeated packed pairs until payload end:

1. `metric_key: u64`
2. `metric_value: u64`

Payload length must be a multiple of 16 bytes.

### `resourceDeltaAck`

Field order:

1. `accepted: bool`

### `credentialsRefresh`

- neuron -> container: raw `CredentialDelta` blob including `PRDDEL01`
- container -> neuron: empty payload means ack

### `message`

- opaque payload
- SDKs should not impose a second schema on it

## Implementation Recipe

This is the intended order for a clean-room SDK implementation.

1. Implement the primitive readers and writers from [`WIRE.md`](./WIRE.md).
2. Implement `ContainerParameters`, `CredentialBundle`, and `CredentialDelta` decoding.
3. Implement startup loading with the exact precedence:
   - `PRODIGY_PARAMS_FD`
   - `argv[1]`
   - fail if neither exists
4. Implement the outer control-frame decoder as an incremental parser over arbitrary byte chunks.
5. Implement a transport-neutral frame handler with the topic semantics above.
6. Expose outbound helpers for:
   - `healthy`
   - `statistics`
   - `resourceDeltaAck`
   - empty `credentialsRefresh` ack
7. Seed local pairing state from startup pairings before processing live pairing updates.
8. Treat automatic responses as a separate output stream from the parser:
   - `ping` echo
   - optional auto-queued acks
9. Add examples that show:
   - borrowed transport integration
   - startup-seeded pairings
   - live pairing updates
   - explicit or configured ack behavior
   - ready signaling
10. Only after the control contract is correct should you add the optional Aegis helper layer.

## Aegis Paired-Service Interface

Pairing events are not sufficient by themselves. For paired-service traffic, the SDK contract also needs an Aegis session layer.

### Pairing Semantics

- `advertisementPairing` authorizes the advertiser side for `(secret, service)`
- `subscriptionPairing` authorizes the subscriber side to connect to `(address, port)` for `(secret, service)`
- `activate = true` means add or refresh the pairing
- `activate = false` means revoke the pairing

### Pairing Hash

Derive the pairing hash from:

1. `secret` as 16 little-endian bytes
2. `service` as 8 little-endian bytes
3. `gxhash64(input[24], seed=0x4d595df4d0f33173)`

This hash must be stable across processes and languages.

### TCP Fast Open Data

The base Aegis TFO payload is:

1. `pairing_hash: u64`
2. optional implementation-specific auxiliary bytes

### Aegis Frame

Algorithm: `AEGIS-128L`

Base frame layout:

1. `size: u32`
2. `nonce: bytes[16]`
3. `encrypted_data_size: u32`
4. `ciphertext_plus_tag: bytes[encrypted_data_size]`
5. `tail_padding: zero-filled bytes to 16-byte alignment`

Rules:

- `min_frame_size = 48`
- `max_frame_size = 2 MiB`
- `encrypted_data_size = plaintext_size + 16`
- `encrypted_data_size` must be at least `16`
- associated data is the 4-byte little-endian `size`
- key is the 16-byte pairing `secret`
- nonce is a fresh 16-byte cryptographically random value per frame
- nonce reuse with the same `secret` is forbidden
- writers pad the full frame to a 16-byte boundary with zero bytes
- readers must reject malformed size, tag, or alignment combinations

Validation rules for decrypt:

- reject if `size < 24`
- reject if `size < min_frame_size` or `size > max_frame_size`
- reject if `size % 16 != 0`
- reject if `encrypted_data_size < 16`
- reject if `encrypted_data_size > size - 24`
- reject if authentication fails

### SDK Boundary

- transport-neutral SDKs should expose caller-owned Aegis session or codec helpers
- opinionated SDKs may expose a convenience `AegisStream`-style wrapper
- `AegisHub` is out of SDK scope

## Authoritative Examples

These are the current examples new SDK authors should copy first:

- C: [`c/examples/mesh_pingpong.c`](./c/examples/mesh_pingpong.c)
- C++: [`cpp/examples/io_uring_mesh_pingpong.cpp`](./cpp/examples/io_uring_mesh_pingpong.cpp)
- Rust: [`rust/examples/mesh_pingpong.rs`](./rust/examples/mesh_pingpong.rs)
- Go: [`go/examples/mesh_pingpong/main.go`](./go/examples/mesh_pingpong/main.go)
- Python: [`python/examples/async_mesh_pingpong.py`](./python/examples/async_mesh_pingpong.py)
- TypeScript: [`typescript/examples/mesh_pingpong.ts`](./typescript/examples/mesh_pingpong.ts)

Those examples demonstrate the current intended model:

- startup pairings are seeded into local state before live updates
- pairings drive IPv6 mesh connect or listen decisions
- `resourceDelta` and `credentialsRefresh` are explicitly acked
- `healthy` is sent only after the container is ready

Legacy compatibility note:

- older public-egress examples are no longer checked in because the packed startup writer no longer emits `public6`, `requires_public4`, or `requires_public6`

## Conformance Checklist

An SDK implementation is conformant when it can:

- decode `ContainerParameters`
- decode `CredentialBundle`
- decode `CredentialDelta`
- load startup parameters from `PRODIGY_PARAMS_FD` first and `argv[1]` second
- parse and build control frames incrementally
- handle all current control topics with the semantics in this file
- maintain cached `datacenter_unique_tag` state from bootstrap and live updates
- publish `healthy`, `statistics`, `resourceDeltaAck`, and empty `credentialsRefresh` ack frames
- decode packed pairing, resource, and credential payloads
- optionally implement legacy compatibility payloads only as an out-of-tree extension if a downstream runtime still requires them
- if it implements Aegis support, match the pairing-hash, TFO, frame, and encrypt/decrypt rules above
- pass the shared fixture corpus and the mesh example smoke path for that language

## Supporting Documents

- [`AEGIS.md`](./AEGIS.md): paired-service session contract and deterministic vectors
- [`WIRE.md`](./WIRE.md): packed byte encodings and parser invariants
- [`CONTRACT.md`](./CONTRACT.md): callback and lifecycle mapping
- [`VERSIONING.md`](./VERSIONING.md): bump rules for wire bytes and fixture corpus changes
