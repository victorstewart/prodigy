# Build container artifacts with Discombobulator

Discombobulator is Prodigy's container builder and artifact-contract implementation. A deployment accepts a Discombobulator-built app-container blob, not an arbitrary rootfs, launch metadata file, Btrfs payload, or compressed archive.

## Build the tool

From the repository root:

```bash
cargo build --release --manifest-path prodigy/discombobulator/Cargo.toml
```

The source is under [`prodigy/discombobulator/`](../discombobulator/) and on [GitHub](https://github.com/victorstewart/prodigy/tree/main/prodigy/discombobulator). The normal Prodigy build is intended to build the tool too; see [Build Prodigy](build.md) for the current status of that entrypoint.

## Build an application artifact

Set the build description, named context, and output to real paths. The CLI owns this shape:

```bash
BUILD_FILE="$PWD/Prodigyfile"
APP_CONTEXT="$PWD/app"
ARTIFACT="$PWD/out/my-app.container.zst"
discombobulator build \
  --file "$BUILD_FILE" \
  --context "app=$APP_CONTEXT" \
  --output "$ARTIFACT" \
  --kind app
```

`--file` and `--context` must point to a real Discombobulator build description and build context. This page deliberately does not invent one: use a checked-in workload example or your project's build description. The resulting blob is the input to `mothership deploy` together with a deployment plan. The artifact contract fails closed when its header, digest, or size is unsupported or mismatched.

## Deployment handoff

The application plan and artifact are separate inputs. `mothership deploy` accepts inline JSON, standard input, or `@path`, so a plan file can be passed directly:

```bash
CLUSTER_NAME=example-test
PLAN_FILE="$PWD/plan.json"
mothership deploy "$CLUSTER_NAME" "@$PLAN_FILE" "$ARTIFACT"
```

`createCluster` uses the same JSON-input convention.

## Bundle a runtime

`bundle flat` packages an already-built Prodigy binary, its build directory, optional eBPF/tool binaries, and already-built container artifacts:

```bash
discombobulator bundle flat \
  --binary ./prodigy \
  --build-dir ./build \
  --container-artifact ./artifacts/example.container.zst \
  --container-plan ./plans/example.deployment.plan.json \
  --output ./prodigy.bundle.tar.zst
```

Every included artifact must already have the supported Discombobulator header. Plans must be JSON objects no larger than 1 MiB. The bundle copies artifacts to `containers/` and plans to `containers/plans/`; it does not deploy them. Flat bundles currently require Linux.

## Tooling network boundary

Discombobulator runs on the operator/build host. Its OCI client is a bounded tooling exception: HTTPS with WebPKI verification, timeouts, redirect limits, size bounds, and SHA-256 verification of declared OCI content. Plain HTTP is only accepted for a loopback test registry. This does not grant deployed containers a separate DNS or network policy.
