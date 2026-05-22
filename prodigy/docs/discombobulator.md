# Discombobulator

Discombobulator implements Prodigy's container runtime and app-container artifact contract.

Prodigy does not treat arbitrary launch metadata, Btrfs receive payloads, rootfs trees, or compressed blobs as valid deployment inputs. Application containers must be built by Discombobulator for the supported versioned app-container contract.

## Source

```text
prodigy/discombobulator/
```

Repository path:

```text
https://github.com/victorstewart/prodigy/tree/main/prodigy/discombobulator
```

## Build

```bash
cargo build --release --manifest-path prodigy/discombobulator/Cargo.toml
```

The normal Prodigy build should also build Discombobulator automatically.

## Artifact rule

A valid app-container blob must start with the supported versioned Discombobulator contract header before the zstd payload.

Runtime-facing paths should fail closed when an app artifact cannot prove it was produced by Discombobulator for the supported contract. `mothership` should reject deployment blobs whose header, digest, or size is unsupported or mismatched. Prodigy/Neuron should verify and skip the header before zstd/Btrfs receive.

Tests may construct malformed artifacts to prove rejection behavior. Successful runtime and deployment tests should use Discombobulator-built artifacts.

## Relationship to Prodigy

Discombobulator is the container-runtime side of the architecture. The rest of Prodigy remains responsible for machine lifecycle, cluster formation, runtime state, provider control, placement, routing, health, credentials, and application deployment flow.
