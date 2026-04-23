# Prodigy SDK Fixtures

This directory holds the shared binary fixture corpus for the native SDK runtimes.

## Format

- `manifest.json` is the versioned index.
- `.bin` files are raw wire bytes.
- `../versioning.json` is the source of truth for fixture and wire version metadata.
- The manifest records `manifestVersion`, `wireSeries`, `wireProtocolVersion`, `fixtureCorpusVersion`, the startup object magic tags, the declared bump policy, and the per-fixture kind/topic/size/`sha256` entries.

## Scope

The corpus currently includes:

- startup objects
- standalone credential objects
- control-topic payloads
- full outer frames with deterministic zero-filled padding
- deterministic Aegis vectors for paired-service SDK layers

## Regeneration

Run the control-plane fixture generator:

```bash
node --experimental-strip-types prodigy/sdk/fixtures/generate.ts
```

The generator rewrites `manifest.json`, validates the emitted control-plane bytes with the TypeScript runtime, and refreshes the checked-in startup/control `.bin` files.

The Aegis fixtures are deterministic vectors validated by the Rust SDK tests:

- `aegis.hash.demo.bin`
- `aegis.tfo.demo.bin`
- `aegis.frame.demo.bin`

Those vectors are specified in [`../AEGIS.md`](../AEGIS.md).

If fixture bytes, manifest shape, or startup magic tags change, bump the appropriate field in [`../versioning.json`](../versioning.json) first. The policy is documented in [`../VERSIONING.md`](../VERSIONING.md).

After regenerating fixtures, re-run the shared compatibility matrix from the Prodigy repo root:

```bash
prodigy/sdk/compatibility_matrix.sh
```

That command is the canonical local conformance pass for the checked-in SDK implementations. It also reruns `fixtures/generate.ts` and fails closed if regeneration would change the checked-in corpus.

## Intended Consumers

Each runtime test layer should read these files directly instead of re-embedding its own demo blobs.

- C: standalone self-test or future unit harness
- Rust: unit tests
- Go: package tests
- Python: self-test or pytest
- TypeScript: Node self-test or future test runner
