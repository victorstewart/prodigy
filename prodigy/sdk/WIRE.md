# Prodigy Wire

Document version: `3`

Wire series: `WIRE_V1`

This document defines the packed wire format native C, C++, Rust, Go, Python, and TypeScript runtimes should target.

For the canonical SDK contract surface, including callback semantics, pairing rules, and Aegis session rules, see [`INTERFACES.md`](./INTERFACES.md).

## Status

Current authoritative emitters and readers live in:

- [`../wire.h`](../wire.h)
- [`../neuron/containers.h`](../neuron/containers.h)

If this file conflicts with an older SDK or an older fixture, the current writers above win.

## Encoding Rules

All scalar fields are little-endian.

- `u8`: 1 byte
- `u16`: 2 bytes
- `u32`: 4 bytes
- `u64`: 8 bytes
- `i32`: 4 bytes two's-complement
- `i64`: 8 bytes two's-complement
- `u128`: 16 bytes little-endian
- `bool`: encoded as `u8`, where `0` is false and `1` is true
- `bytes`: `u32 length` followed by `length` raw bytes
- `string`: `bytes`, UTF-8 by convention
- `array<T>`: `u32 count` followed by `count` encoded elements
- `map<string,string>`: `u32 count` followed by repeated `string key, string value`

The wire format never uses host alignment, native `bool`, native `int`, or compiler padding as protocol semantics.

## Startup Objects

### `ContainerParameters`

Magic: `PRDPAR01`

Readers must reject any startup payload whose magic is not `PRDPAR01`.

Field order:

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
11. `private6: { address: u128, is_ipv6: bool, cidr: u8 }`
12. `just_crashed: bool`
13. `datacenter_unique_tag: u8`
14. `flags: array<u64>`
15. `has_credential_bundle: bool`
16. `credential_bundle` if present

Bootstrap loading precedence:

1. `PRODIGY_PARAMS_FD`
2. `argv[1]`
3. fail if neither is present

Bootstrap pairing rules:

- startup pairings do not carry `application_id`
- startup readers infer `application_id` from the top 16 bits of `service`
- startup pairings imply `activate = true`

Current writer boundary:

- startup data, including `wormholes` and `whiteholes`, is serialized as `PRDPAR01`

Compatibility note:

- some historical SDKs and historical fixtures carried `public6`, `requires_public4`, and `requires_public6` between `private6` and `just_crashed`
- current `ProdigyWire::serializeContainerParameters(...)` writers do not emit those fields
- those fields are not part of the latest wire contract

### `CredentialBundle`

Magic: `PRDBUN01`

Readers must reject any credential bundle whose magic is not `PRDBUN01`.

Field order:

1. `tls_identities: array<TlsIdentity>`
2. `api_credentials: array<ApiCredential>`
3. `bundle_generation: u64`
4. `tls_resumption_snapshots: array<TlsResumptionSnapshot>`

### `CredentialDelta`

Magic: `PRDDEL01`

Readers must reject any credential delta whose magic is not `PRDDEL01`.

Field order:

1. `bundle_generation: u64`
2. `updated_tls: array<TlsIdentity>`
3. `removed_tls_names: array<string>`
4. `updated_api: array<ApiCredential>`
5. `removed_api_names: array<string>`
6. `reason: string`
7. `updated_resumption_snapshots: array<TlsResumptionSnapshot>`
8. `removed_resumption_wormhole_names: array<string>`

### `TlsResumptionSnapshot`

Field order:

1. `generation: u64`
2. `wormhole_name: string`
3. `key_ring: array<TlsResumptionKeyEpoch>`

The delivered snapshot is keyed by `wormhole_name` and only carries the key epochs for that declared wormhole. Application IDs, deployment IDs, ports, SNI/ALPN declarations, and policy metadata are not part of the SDK delivery contract. Key material is secret and must not be logged.

### `TlsResumptionApplyAck`

Magic: `PRDACK01`

Legacy container-to-neuron credential-refresh ACKs may carry this payload when only resumption snapshots or deltas were applied.

Field order:

1. `results: array<TlsResumptionApplyResult>`

### `TlsResumptionApplyResult`

Field order:

1. `wormhole_name: string`
2. `generation: u64`
3. `success: bool`
4. `failure_reason: string`

This ACK result must never include ticket values, key IDs, master secrets, TLS private keys, API credential material, or other secret material.

### `CredentialApplyAck`

Magic: `PRDCAC01`

Container-to-neuron credential-refresh ACKs should carry this payload when the application wants to report TLS identity apply success or rejection, optionally alongside resumption results.

Field order:

1. `tls_results: array<TlsIdentityApplyResult>`
2. `resumption_results: array<TlsResumptionApplyResult>`

### `TlsIdentityApplyResult`

Field order:

1. `identity_name: string`
2. `generation: u64`
3. `success: bool`
4. `failure_reason: string`

## Control Socket Frame

The neuron `<->` container control stream keeps one shared outer frame:

1. `size: u32`
2. `topic: u16`
3. `padding: u8`
4. `header_size: u8`
5. `payload: bytes`
6. `tail_padding: padding bytes`

Header rules:

- `header_size` is always `8`
- `size` includes header, payload, and tail padding
- `padding` is the number of tail bytes after the payload
- `size` must be a multiple of 16
- payload bytes are packed with no internal alignment gaps
- writers should zero-fill tail padding bytes

Parser requirements:

1. Wait until at least 8 bytes are buffered.
2. Read `size` and `header_size`.
3. Reject the frame if:
   - `header_size != 8`
   - `size < 8`
   - `size % 16 != 0`
4. Wait until `size` bytes are buffered.
5. Read `topic` and `padding`.
6. Reject the frame if:
   - `topic` is not a defined control topic
   - `padding > size - 8`
7. Payload length is `size - 8 - padding`.
8. Parse exactly that payload region and ignore the tail padding bytes after validation.

Builder requirements:

1. Compute `base_size = 8 + payload_size`.
2. Compute `padding = (16 - (base_size % 16)) % 16`.
3. Emit `size = base_size + padding`.
4. Emit `topic`, `padding`, and `header_size = 8`.
5. Emit payload bytes.
6. Emit `padding` zero bytes.

## Topics

### Neuron -> Container

#### `none`

Payload: empty

#### `ping`

Payload: empty

#### `stop`

Payload: empty

#### `resourceDelta`

Payload:

1. `logical_cores: u16`
2. `memory_mb: u32`
3. `storage_mb: u32`
4. `is_downscale: bool`
5. `grace_seconds: u32`

Packed payload length: 15 bytes

#### `advertisementPairing`

Payload:

1. `secret: u128`
2. `address: u128`
3. `service: u64`
4. `application_id: u16`
5. `activate: bool`

Packed payload length: 43 bytes

#### `subscriptionPairing`

Payload:

1. `secret: u128`
2. `address: u128`
3. `service: u64`
4. `port: u16`
5. `application_id: u16`
6. `activate: bool`

Packed payload length: 45 bytes

#### `datacenterUniqueTag`

Payload:

1. `datacenter_unique_tag: u8`

Packed payload length: 1 byte

#### `message`

Payload: raw remaining frame payload

This stays opaque to the SDK layer.

#### `credentialsRefresh`

Payload: raw `CredentialDelta` blob encoded with `PRDDEL01`

No extra length prefix is needed inside the frame because frame size already bounds the payload.

### Container -> Neuron

#### `ping`

Payload: empty

#### `healthy`

Payload: empty

#### `statistics`

Payload: repeated packed pairs until payload end:

1. `metric_key: u64`
2. `metric_value: u64`

Payload length must be a multiple of 16 bytes.

#### `resourceDeltaAck`

Payload:

1. `accepted: bool`

Packed payload length: 1 byte

#### `credentialsRefresh`

Payload: empty, raw `CredentialApplyAck` encoded with `PRDCAC01`, or raw legacy `TlsResumptionApplyAck` encoded with `PRDACK01`

Empty payload is accepted only as a success ACK for a non-resumption credential refresh. `CredentialApplyAck` reports TLS identity apply success or rejection. A typed resumption result is required when acknowledging TLS resumption snapshots or deltas, because resumption readiness depends on `wormhole_name`, generation, and success/failure.

## Validation Requirements

These checks should be enforced even in high-performance implementations.

- bootstrap decode must consume the full input blob
- credential decode must consume the full input blob
- control frame decode must reject invalid `topic`, `header_size`, `padding`, or `size`
- `datacenterUniqueTag` payload length must be exactly 1 byte
- `resourceDeltaAck` payload length must be exactly 1 byte
- `statistics` payload length must be a multiple of 16 bytes
- `credentialsRefresh` payload is either:
  - from neuron to container: a full `PRDDEL01` blob
  - from container to neuron: empty success ACK, `PRDCAC01` credential apply ACK, or legacy `PRDACK01` resumption apply ACK

## Performance Notes

The wire format is designed so high-performance SDKs can stay simple:

- fixed 8-byte outer header
- 16-byte frame alignment
- packed payloads with no C++ layout dependencies
- count-prefixed collections for single-pass decode
- no alternate control-plane serialization

Recommended implementation tactics:

- parse directly from a reusable byte buffer
- expose builder helpers for common outbound frames instead of rebuilding them by hand in every example
- avoid per-field heap allocation where the language provides slices, views, or borrowed strings
- keep a borrowed-transport integration path available even if the SDK also offers owned convenience loops

## Compatibility Notes

Compatibility behavior may exist in older SDKs, but it is not part of the latest wire contract:

- historical startup readers may have accepted `public6`, `requires_public4`, and `requires_public6`
- older out-of-tree integrations may still use `public6` startup paths
- new SDKs should target the current packed startup shape and reject removed bootstrap/control payload variants

## Supporting Documents

- [`INTERFACES.md`](./INTERFACES.md): semantic contract, lifecycle rules, and Aegis session rules
- [`CONTRACT.md`](./CONTRACT.md): callback mapping and handler behavior summary
- [`VERSIONING.md`](./VERSIONING.md): bump rules for wire bytes and fixture corpus changes
