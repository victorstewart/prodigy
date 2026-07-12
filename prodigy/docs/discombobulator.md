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

## Flat runtime bundles

`bundle flat` can carry already-built Discombobulator container blobs alongside the main runtime binary:

```bash
discombobulator bundle flat \
  --binary ./prodigy \
  --build-dir ./build \
  --container-artifact ./artifacts/dns-resolver.container.zst \
  --container-artifact ./artifacts/another.container.zst \
  --container-plan ./plans/dns-resolver.deployment.plan.v1.json \
  --output ./prodigy.bundle.tar.zst
```

Each `--container-artifact` is resolved to an explicitly named regular file with a supported Discombobulator container contract header, so ordinary `./` and `../` source paths work. Every artifact must have a normal nonempty basename, and destination basenames must be unique. Accepted blobs are confined to `containers/<basename>`, copied byte-for-byte, and normalized to mode `0644`; they are data artifacts, so the bundler neither marks them executable nor scans them for runtime libraries.

Each `--container-plan` must be a regular `.json` file no larger than 1 MiB whose root is an object. Validated plans are copied byte-for-byte to `containers/plans/<basename>` with mode `0644`.

Relative to the installed Prodigy root, the bundle exposes the built-in DNS resolver at:

- `containers/prodigy-dns-resolver.<arch>.container.zst`
- `containers/plans/prodigy-dns-resolver.deployment.plan.v1.json`

The bundle packages these files but does not deploy them automatically. An operator deploys the service through the normal Mothership path:

```bash
mothership deploy "$TARGET" "$(cat containers/plans/prodigy-dns-resolver.deployment.plan.v1.json)" "containers/prodigy-dns-resolver.${ARCH}.container.zst"
```

## Host HTTP boundary

Discombobulator runs on an operator/build host before a target cluster and its DNS service need
exist. Its OCI registry client is therefore an explicit blocking tooling exception, not a network
stack available to deployed applications or containers. Registry HTTPS uses WebPKI verification,
a 10-second connect deadline, a 15-minute whole-request deadline, at most five redirects with no
HTTPS downgrade, and bounded manifest, config, layer, token, and error bodies. Plain HTTP is
accepted only for a loopback registry used by local tests. Downloaded OCI manifests and blobs are
verified against their declared SHA-256 digests before use, and diagnostics never print registry
credentials, bearer tokens, or response bodies.

The non-Linux portable builder may download the rustup installer only when its cached Cargo binary
is absent. That HTTPS-only download has explicit connect/overall deadlines, three redirects, and a
2-MiB cap; it is written to a temporary file and size-checked before execution. Neither tooling
exception changes Prodigy application DNS, service-mesh, or container networking policy.

## Relationship to Prodigy

Discombobulator is the container-runtime side of the architecture. The rest of Prodigy remains responsible for machine lifecycle, cluster formation, runtime state, provider control, placement, routing, health, credentials, and application deployment flow.
