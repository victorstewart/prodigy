# Apple Containerization Kernel Profile

This folder contains Prodigy's reproducible Linux 7 kernel profile for running
Prodigy development guests with Apple Containers on Apple Silicon.

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
| Kernel source | Linux `7.1.3` |
| Kernel source SHA-256 | `be41c068e88f5242a19bccdbffbe077b18c47b45f627e2325504b4fab79dd1dc` |
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

It then checks out the pinned Apple kernel profile, applies
`prodigy-arm64.config.fragment`, verifies the pinned Linux source checksum, and
builds it in the cached `kernel-build:0.1` image with Apple Containers.

The output and its declared-input digest are cached. A repeated invocation
returns immediately unless the build script, Apple ref, Linux version,
checksum, architecture, or Prodigy config fragment changed.

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

## Run With The Kernel

Select the kernel explicitly for a disposable Apple Container:

```bash
container run --rm \
  --kernel .run/apple-container-kernel/containerization/bin/vmlinux-arm64 \
  <other-options> <image> <command>
```

Do not replace the system default: keeping selection explicit prevents an
unrelated container from inheriting Prodigy's privileged runtime kernel.

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
container networking must run inside a disposable Apple Container on this Mac.
Do not attach BPF programs to host interfaces, and do not run Prodigy
networking tests in the host network namespace.

OrbStack, QEMU, TCG, Docker Desktop, and implicit runtime fallback are not
permitted local Linux virtualization paths. This kernel profile is one
prerequisite for native Apple Silicon development; it is not a substitute for
the runtime isolation rules in the repository root `AGENTS.md`.
