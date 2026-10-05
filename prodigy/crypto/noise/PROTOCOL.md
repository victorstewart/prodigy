# Internal authenticated AEGIS profile, version 1

This document describes the implemented connection profile. It does not claim
production qualification or a formal cryptographic audit. Runtime rollout is
gated by the existing cluster credential and membership owner.

## Trust and handshake

The credential owner supplies a 32-byte scoped authentication key, approved
local and peer identities, and a canonical credential context. These are
long-term authentication inputs; they are not traffic keys or deterministic
ephemeral private keys. A Neuron receives only its own node credential. Pair
roots and internal cluster authority roots use separate derivation domains.

An incoming connection may first exchange a public credential hint. Its frame
is eight bytes (`P`, `G`, `A`, version 1, two-byte big-endian length, two zero
reserved bytes), followed by 1–512 bytes. The credential owner must validate
the hint against current local authorization. Lookup success grants no peer
identity, membership, or application access.

`ProdigyTransportTLSStream` binds a domain label, initiator UUID, responder
UUID, length-prefixed credential context, and both exact public hints in
initiator/responder order. UUIDs are 16-byte big-endian values; lengths are
eight-byte big-endian values. `ProdigyAegisSession` then binds the exact record
profile label and length-prefixed stream context as the Noise prologue.

The pinned Snow backend implements
`Noise_NNpsk0_25519_ChaChaPoly_SHA256`. Each side exchanges exactly one 48-byte
empty-payload handshake message. The backend generates fresh X25519 private
ephemerals with checked OS randomness. Low-order public keys yielding an
all-zero shared result are rejected. No application handshake payload, 0-RTT,
resumption, deterministic ephemeral, or alternate suite is exposed by the C ABI.

After the handshake, Snow's secret Split outputs `k1` and `k2` are exported
once, and the handshake state is erased. The public handshake hash is a salt
and channel binding; it is never used as secret input key material. Each Split
key passes through HKDF-SHA256 to produce a 16-byte AEGIS-128L key, with the
handshake hash as salt and the NUL-terminated
`prodigy/noise-to-aegis128l/record-v1` label plus a direction byte as information.
Direction 0 uses `k1` for initiator-to-responder; direction 1 uses `k2` for the
reverse direction. This post-handshake AEGIS profile is a Prodigy construction,
not a standard Noise cipher suite.

## Records and connection lifecycle

Every record has a 16-byte header: version (1 byte), type (1), direction (1),
reserved zero (1), plaintext length (4, big-endian), and sequence number
(8, big-endian). The complete header followed by the 32-byte handshake hash is
AEGIS associated data. Ciphertext follows, ending in a 16-byte tag.

Types are confirmation (0), application (1), and close (2). Confirmation and
close have empty payloads. Application payloads are limited to 64 KiB per
record. A nonce is eight zero bytes followed by the sequence number. Each
direction has a distinct fresh key and its own strictly increasing sequence.
No session sends or accepts 2^32 records. Reordering, replay, bad direction,
reserved bits, invalid lengths, authentication failure, or sequence exhaustion
terminates the connection; the owner cannot discard a record and resume it.

Each side must send and authenticate the other's sequence-zero AEGIS
confirmation before application records are accepted or a peer UUID is
published. Replaying a captured first Noise message may provoke a bounded
response, but a fresh responder ephemeral prevents replaying an old session's
confirmation or application records. Existing connection deadlines and
admission limits remain the runtime owner's responsibility.

Close ends the entire connection; this profile does not support independent
half-close semantics. Reset starts a new transport generation and erases session
keys, proof state, and active plaintext buffers. No TLS or plaintext fallback
is attempted after selecting this profile.

## Verification boundaries

The wrapper tests and retained upstream vectors check the Noise backend.
The C++ session tests check identity and context binding, confirmation, tamper,
reflection, replay, restart, framing, and partial socket I/O. The existing
io_uring transport fixture exercises large transfers through the ordinary
stream owner. These do not replace membership/quorum, rotation/revocation,
failover, offline enrollment, or mixed-version runtime tests.

The benchmark compares CPU work through an in-memory stream pump; it does not
measure cluster throughput, network latency, or provisioning performance.
