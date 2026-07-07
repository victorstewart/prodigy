# Apple Containerization Kernel Profile

This folder contains Prodigy's reproducible kernel profile for running Prodigy
development guests under Apple Containerization on Apple Silicon.

It does not vendor Apple's Containerization repository and it does not commit a
kernel binary. Instead, it pins the upstream checkout, applies the Prodigy
kernel config fragment, and builds a native `arm64` Apple-container kernel under
the repo-local `.run/` work root.

## What This Builds

The profile currently targets:

| Item | Value |
|---|---|
| Upstream | `https://github.com/apple/containerization.git` |
| Upstream commit | `d992a1996dd9e08482f0690917bec9cdbf995823` |
| Target arch | `arm64` |
| Kernel source used by upstream at this ref | Linux `6.18.5` |
| Default output | `.run/apple-container-kernel/containerization/bin/vmlinux-arm64` |

The required Prodigy options are kept in
[`prodigy-arm64.config.fragment`](prodigy-arm64.config.fragment).

## Why This Exists

Prodigy runtime work needs a native arm64 Linux guest on Apple Silicon with the
same kernel features expected by the real Linux deployment path:

| Feature | Required options |
|---|---|
| BPF execution support | `CONFIG_BPF_JIT=y` |
| Apple/container networking support | `CONFIG_NETKIT=y` |
| Prodigy container storage | `CONFIG_BTRFS_FS=y`, `CONFIG_BTRFS_FS_POSIX_ACL=y` |
| Btrfs compression/dependencies | `CONFIG_RAID6_PQ=y`, `CONFIG_XOR_BLOCKS=y`, `CONFIG_ZSTD_*` |
| Sandbox APIs used by modern runtimes | `CONFIG_SECURITY=y`, `CONFIG_SECURITY_LANDLOCK=y`, `CONFIG_LSM=...landlock...` |

This is an Apple Containerization kernel profile only. Prodigy container
artifacts are still built by Discombobulator.

## Prerequisites

- macOS on Apple Silicon.
- Apple `container` CLI installed and usable by the current user.
- `git`, `make`, and the build dependencies expected by Apple's
  Containerization kernel makefile.
- Enough disk, CPU, and memory for a Linux kernel build.
- Optional: `cctl`, if you want to register the built kernel with Apple
  Containerization after the build.

## Build

From the Prodigy repository root:

```bash
prodigy/dev/apple-container-kernel/build.sh
```

The script clones Apple's Containerization repository into:

```text
.run/apple-container-kernel/containerization
```

It then checks out the pinned upstream commit, applies
`prodigy-arm64.config.fragment` to `kernel/config-arm64`, and runs:

```bash
make -C .run/apple-container-kernel/containerization/kernel TARGET_ARCH=arm64
```

The expected kernel output is:

```text
.run/apple-container-kernel/containerization/bin/vmlinux-arm64
```

Useful environment overrides:

| Variable | Meaning |
|---|---|
| `PRODIGY_APPLE_CONTAINER_KERNEL_WORK_ROOT` | Override the `.run/apple-container-kernel` work directory. |
| `PRODIGY_APPLE_CONTAINERIZATION_REPO` | Override the Apple Containerization Git remote. |
| `PRODIGY_APPLE_CONTAINER_KERNEL_TARGET_ARCH` | Target architecture. Only `arm64` is supported by this profile. |
| `PRODIGY_APPLE_CONTAINER_KERNEL_SKIP_BUILD=1` | Clone, pin, and patch the config without invoking the kernel build. |

## Register The Kernel

After a successful build, register the image with the local Apple
Containerization tooling if your install exposes `cctl`:

```bash
cctl kernel create --name prodigy-apple-container-arm64 .run/apple-container-kernel/containerization/bin/vmlinux-arm64:arm64
```

The exact active-kernel selection command can vary with the Apple
Containerization tool version. Keep the registered name distinct from Apple's
default kernel so test guests can opt into this Prodigy profile explicitly.

## Verify

Verify a source config, a guest `/proc/config.gz`, or a copied config file:

```bash
prodigy/dev/apple-container-kernel/verify.sh .run/apple-container-kernel/containerization/kernel/config-arm64
```

Inside a running guest with `/proc/config.gz` available:

```bash
prodigy/dev/apple-container-kernel/verify.sh
```

This is a static config check. It does not run Prodigy, load BPF, attach BPF,
create network devices, or mutate host networking.

## Runtime Safety

Prodigy runtime validation that can touch namespaces, BPF, mounts, cgroups, or
container networking must still run inside a disposable isolated guest or VM.
Do not attach BPF programs to host interfaces, and do not run Prodigy
networking tests in the host network namespace.

This kernel profile is one prerequisite for native Apple Silicon development;
it is not a substitute for the runtime isolation rules in the repository root
`AGENTS.md`.
