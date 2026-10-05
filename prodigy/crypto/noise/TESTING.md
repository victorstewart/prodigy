# Intended verification

Run the wrapper tests from this directory:

```sh
cargo test --manifest-path prodigy/crypto/noise/Cargo.toml
```

Run Snow's retained upstream general and vector tests with the same pinned source:

```sh
cargo test --manifest-path prodigy/crypto/noise/vendor/snow/Cargo.toml --features vector-tests
```

Build the C ABI artifacts:

```sh
cargo build --manifest-path prodigy/crypto/noise/Cargo.toml --release
```

The wrapper tests cover successful exchange, wrong PSK, wrong prologue,
tampering, order failures, replay producing a distinct responder session,
one-shot export, output clearing before a failed export, and terminal cleanup on
export/free. The pinned Snow vector suite supplies protocol interoperability
coverage.
