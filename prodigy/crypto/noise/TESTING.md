# Intended verification

Run the wrapper tests from this directory:

```sh
cargo test --manifest-path prodigy/crypto/noise/Cargo.toml
```

Run Snow's retained source-level unit tests against the feature subset used by
Prodigy:

```sh
cargo test --manifest-path prodigy/crypto/noise/vendor/snow/Cargo.toml --lib \
  --no-default-features \
  --features default-resolver,use-curve25519,use-chacha20poly1305,use-sha2,use-getrandom,risky-raw-split
```

Build the C ABI artifacts:

```sh
cargo build --manifest-path prodigy/crypto/noise/Cargo.toml --release
```

The wrapper tests cover successful exchange, wrong PSK, wrong prologue,
tampering, order failures, replay producing a distinct responder session,
one-shot export, output clearing before a failed export, and terminal cleanup on
export/free. Snow's source-level unit tests cover the retained cryptographic
resolver and protocol-building primitives.
