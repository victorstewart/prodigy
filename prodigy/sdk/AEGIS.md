# Prodigy Aegis Contract

Canonical reference for the Prodigy paired-service Aegis layer.

Use this file together with [`INTERFACES.md`](./INTERFACES.md), [`WIRE.md`](./WIRE.md), the shared fixtures under [`fixtures/`](./fixtures/), and the checked-in examples when implementing a new SDK.

## Status

- Document version: `1`
- Wire series: `WIRE_V1`
- Protocol version: `1`
- Fixture corpus version: `2`

## Scope

This file defines:

- pairing hash derivation
- TCP Fast Open payload semantics
- AEGIS-128L frame layout
- encrypt/decrypt rules
- the intended SDK layering between transport-neutral and opinionated surfaces
- deterministic Aegis fixture vectors

This file does not define:

- control-plane frame topics
- startup object encoding outside pairing-related fields
- `AegisHub`
- socket ownership or runtime orchestration

## Layering

Every language SDK should treat the Aegis contract as a layer above the transport-neutral Prodigy control protocol.

- transport-neutral layer:
  - caller-owned transport
  - pairing hash derivation
  - TFO payload construction
  - AEGIS-128L frame encode/decode
  - encrypt/decrypt helpers
- opinionated layer:
  - pairing-driven activation helpers
  - stream-oriented wrapper with queueing and timestamp sidecars where useful
  - no `AegisHub`

Current Tier 1 SDK shapes:

- C:
  - transport-neutral control and paired-service surface in [`c/prodigy_neuron_hub.h`](./c/prodigy_neuron_hub.h)
- Rust:
  - `prodigy_sdk::aegis::AegisSession`
  - `prodigy_sdk::opinionated::AegisStream`
  - `prodigy_sdk::opinionated::PairingBook`
- C++:
  - transport-neutral control surface in [`cpp/neuron_hub.h`](./cpp/neuron_hub.h)
  - transport-neutral paired-service surface in [`cpp/aegis_session.h`](./cpp/aegis_session.h)
  - opinionated Aegis wrapper in [`cpp/opinionated/aegis_stream.h`](./cpp/opinionated/aegis_stream.h)

## Pairing Semantics

Pairings carry the minimum material required for a secure paired-service session:

- `secret: u128`
- `service: u64`
- subscriber pairings additionally carry:
  - `address: u128`
  - `port: u16`

Behavior:

- `advertisementPairing` authorizes the advertiser side for `(secret, service)`
- `subscriptionPairing` authorizes the subscriber side to connect to `(address, port)` for `(secret, service)`
- `activate = true` adds or refreshes the pairing
- `activate = false` revokes the pairing

## Pairing Hash

The pairing hash is the stable 64-bit identifier derived from:

1. `secret` as 16 little-endian bytes
2. `service` as 8 little-endian bytes
3. `gxhash64(input[24], seed=0x4d595df4d0f33173)`

This hash must be byte-for-byte stable across languages and processes.

## TCP Fast Open Payload

The base TFO payload is:

1. `pairing_hash: u64`
2. optional implementation-specific auxiliary bytes

The SDK must not reinterpret or transform auxiliary bytes. They are appended verbatim after the 8-byte pairing hash.

## Aegis Frame

Algorithm: `AEGIS-128L`

Frame layout:

1. `size: u32`
2. `nonce: bytes[16]`
3. `encrypted_data_size: u32`
4. `ciphertext_plus_tag: bytes[encrypted_data_size]`
5. `tail_padding: zero-filled bytes to 16-byte alignment`

Constants:

- `alignment = 16`
- `header_bytes = 24`
- `tag_bytes = 16`
- `min_frame_size = 48`
- `max_frame_size = 2 MiB`

Frame rules:

- `encrypted_data_size = plaintext_size + 16`
- `encrypted_data_size` must be at least `16`
- `size` includes header, ciphertext, tag, and tail padding
- `size` must be a multiple of `16`
- writers zero-fill tail padding bytes
- readers validate declared `size` against the actual available frame bytes before decrypting

## Encrypt Rules

Inputs:

- key: 16-byte pairing `secret`
- nonce: fresh random 16-byte value per frame
- plaintext: arbitrary byte string
- associated data: 4-byte little-endian `size`

Algorithm:

1. `encrypted_data_size = plaintext_size + 16`
2. `size = align16(24 + encrypted_data_size)`
3. write `size`, `nonce`, and `encrypted_data_size`
4. encrypt the plaintext with `AEGIS-128L`
5. append the 16-byte authentication tag
6. append zero bytes until the whole frame length is a multiple of 16

Nonce reuse with the same `secret` is forbidden.

## Decrypt Rules

Reject before decrypting if:

- the frame has fewer than `24` bytes
- `size < 48`
- `size > 2 MiB`
- `size % 16 != 0`
- actual frame byte length does not equal `size`
- `encrypted_data_size < 16`
- `encrypted_data_size > size - 24`

On decrypt:

- associated data is the 4-byte little-endian `size`
- ciphertext length is `encrypted_data_size - 16`
- the final 16 bytes of `ciphertext_plus_tag` are the authentication tag
- authentication failure is fatal for that frame

## Performance Rules

All SDKs should keep the Aegis path hot:

- caller-owned output buffers should be a first-class path
- encrypt/decrypt should support in-place or caller-provided scratch buffers when the language allows it
- avoid heap churn for one-frame encode/decode loops
- opinionated stream helpers may queue frames, but they should not hide avoidable extra copies
- do not insert text encodings, JSON layers, or schema reflection on the paired-service hot path

## Deterministic Fixture Vectors

These fixtures are the canonical deterministic test vectors for the Aegis layer:

- hash fixture:
  - file: [`fixtures/aegis.hash.demo.bin`](./fixtures/aegis.hash.demo.bin)
  - input:
    - `secret = 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f`
    - `service = 0x2233000000001001`
  - bytes:
    - `b1 9c 73 61 44 a9 d1 5b`
- TFO fixture:
  - file: [`fixtures/aegis.tfo.demo.bin`](./fixtures/aegis.tfo.demo.bin)
  - bytes:
    - pairing hash above, followed by ASCII `mesh-aegis`
- frame fixture:
  - file: [`fixtures/aegis.frame.demo.bin`](./fixtures/aegis.frame.demo.bin)
  - plaintext: ASCII `frame-one`
  - nonce:
    - `80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f`

SDK tests should validate against these files directly rather than copying ad hoc byte strings into each runtime.

## Example Flow

The intended paired-service flow is:

1. decode startup `ContainerParameters`
2. seed local pairing state from startup pairings
3. process live pairing updates on the shared control stream
4. when a pairing activates:
   - derive or construct an `AegisSession`
   - build TFO bytes if the runtime uses Fast Open
   - encrypt and decrypt paired-service frames with that session
5. when a pairing deactivates:
   - drop local pairing state
   - stop using the corresponding session

Reference examples:

- C transport-neutral Aegis example:
  - [`c/examples/aegis_roundtrip.c`](./c/examples/aegis_roundtrip.c)
- C++ transport-neutral Aegis example:
  - [`cpp/examples/aegis_roundtrip.cpp`](./cpp/examples/aegis_roundtrip.cpp)
- C++ opinionated Aegis example:
  - [`cpp/examples/opinionated_aegis_roundtrip.cpp`](./cpp/examples/opinionated_aegis_roundtrip.cpp)
- Rust transport-neutral Aegis example:
  - [`rust/examples/aegis_roundtrip.rs`](./rust/examples/aegis_roundtrip.rs)
- Rust opinionated example:
  - [`rust/examples/opinionated_aegis_roundtrip.rs`](./rust/examples/opinionated_aegis_roundtrip.rs)
- Go transport-neutral Aegis example:
  - [`go/examples/aegis_roundtrip/main.go`](./go/examples/aegis_roundtrip/main.go)
- Python transport-neutral Aegis example:
  - [`python/examples/aegis_roundtrip.py`](./python/examples/aegis_roundtrip.py)
- TypeScript transport-neutral Aegis example:
  - [`typescript/examples/aegis_roundtrip.ts`](./typescript/examples/aegis_roundtrip.ts)
- Rust control-plane example:
  - [`rust/examples/mesh_pingpong.rs`](./rust/examples/mesh_pingpong.rs)
- C++ control-plane example:
  - [`cpp/examples/io_uring_mesh_pingpong.cpp`](./cpp/examples/io_uring_mesh_pingpong.cpp)

## Conformance Checklist

An Aegis-capable SDK is conformant when it can:

- derive the pairing hash exactly
- build the base TFO payload exactly
- encode and decode AEGIS-128L frames with the exact layout above
- reject malformed frame size and authentication combinations
- pass the deterministic Aegis fixture vectors
- match the checked-in paired-service example behavior for that language
