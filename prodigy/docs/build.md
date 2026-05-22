# Build from source

Prodigy is currently source-built. Binary releases are not published yet.

## Clone

```bash
git clone https://github.com/victorstewart/prodigy.git
cd prodigy
```

## Requirements

- Linux for runtime, container, namespace, cgroup, BPF, and filesystem work.
- CMake.
- A C++20-capable compiler.
- Rust and Cargo.
- Root or equivalent capabilities plus a proven isolation boundary for system/runtime tests.
- Provider CLIs only when running cloud runbooks: `aws`, `az`, `gcloud`, or `curl`/`jq` for Vultr.

## Runtime networking prerequisite

Enable TCP Fast Open before running Prodigy hosts:

```bash
sudo sysctl -w net.ipv4.tcp_fastopen=3
```

Persist it with a sysctl configuration entry:

```text
net.ipv4.tcp_fastopen = 3
```

This enables Linux client and server TFO support. Kernel enablement is necessary but not a substitute for the runtime using TFO-capable socket/listener behavior where required.

## Discombobulator

Discombobulator implements Prodigy's container runtime and app-artifact contract.

Build it directly with Cargo:

```bash
cargo build --release --manifest-path prodigy/discombobulator/Cargo.toml
```

The Prodigy build should also build Discombobulator automatically. If you build Discombobulator separately, keep the resulting binary version aligned with the Prodigy runtime that will consume the generated app-container blobs.

## Prodigy runtime and `mothership`

The current public tree exposes the Prodigy C++/CMake/Depos project configuration through:

```text
depos.project.cmake
depofiles/
prodigy/mothership/
prodigy/brain/
prodigy/neuron/
prodigy/iaas/
```

Use the build entrypoint maintained by the repository or CI for your branch. Do not publish an invented one-line command unless it is also exercised by CI.

The root README should be updated to show the exact command once the repository exposes a stable top-level build wrapper or root CMake entrypoint.

## Recommended release-build contract

When stabilizing the build entrypoint, make it satisfy this contract:

1. resolve the Depos dependency graph from committed recipes only;
2. build the Prodigy runtime;
3. build `mothership`;
4. build Discombobulator;
5. place operator-facing binaries under a predictable output directory, such as `dist/`;
6. fail closed if dependency resolution or artifact verification fails.

Recommended final shape:

```bash
./tools/build-release.sh
```

Expected outputs:

```text
dist/prodigy
dist/mothership
dist/discombobulator
```

The placeholder above should be replaced by the exact command used by CI.

## Privileged test warning

Runtime tests can manipulate Linux network namespaces, bridges, veth pairs, BPF/XDP/TC hooks, cgroups, loop devices, Btrfs images, bind mounts, and container roots. Root or equivalent capabilities are not sufficient by themselves.

Run those tests only in a disposable VM or another proven isolation boundary unless the harness proves complete namespace and capability containment before touching system-level state. Host runs must fail closed before risky work unless PID, mount, network, IPC, UTS, cgroup, and user namespace isolation are active; host-root `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_BPF`, and `CAP_SYS_MODULE` are not retained outside the boundary; host `/containers`, `/mnt`, `/sys/fs/bpf`, `/sys/fs/cgroup`, and `/proc/sys` are not mutated; the run has a hard timeout and bounded cleanup plan; swap is active; and `RuntimeWatchdogSec` is active on `/dev/watchdog0`.
