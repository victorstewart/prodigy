# Build Prodigy

Prodigy is source-built. There are no published binary releases yet. The future distribution location is the [GitHub Releases page](https://github.com/victorstewart/prodigy/releases); an evaluation bundle may accompany a checkout while that distribution path is being established.

## Choose a build path

| Goal | Current path |
|---|---|
| Run an SDK example | Follow the language command in the [SDK quickstart](../sdk/README.md). No privileged runtime is required. |
| Build a container artifact | Build Discombobulator with Cargo, then follow [its artifact guide](discombobulator.md). |
| Build Prodigy and Mothership | Run `tools/build-evaluation.sh`; it remains candidate documentation until clean-room verification is recorded. |
| Run a test cluster | Use the [test-cluster boundary](../dev/tests/manual/test/README.md), never an ambient host. |

Clone the source:

```bash
git clone https://github.com/victorstewart/prodigy.git
cd prodigy
```

## Requirements

- CMake and Clang for the Prodigy/Mothership build (the pinned development image provides the tested toolchain).
- Rust and Cargo for Discombobulator; `curl` and `sha256sum` for the pinned Depos bootstrap.
- Linux for runtime, container, namespace, cgroup, BPF, and filesystem work.
- Provider CLIs only for cloud runbooks: `aws`, `az`, `gcloud`, or `curl`/`jq` for Vultr.

Build Discombobulator directly:

```bash
cargo build --release --manifest-path prodigy/discombobulator/Cargo.toml
```

The C++ project uses committed Depos recipes and configuration under `depos.project.cmake`, `depofiles/`, and `prodigy/{mothership,brain,neuron,iaas}/`. The repository wrapper is `tools/build-evaluation.sh`; package its output with `tools/package-evaluation.sh`. Treat both as candidate interfaces until their clean-room result is recorded.

## Runtime prerequisites

Prodigy runtime and test-cluster paths require Linux kernel 7.0 or newer. Hosts that run Prodigy need TCP Fast Open enabled:

```bash
sudo sysctl -w net.ipv4.tcp_fastopen=3
```

Persist it through your host sysctl configuration:

```text
net.ipv4.tcp_fastopen = 3
```

Kernel enablement permits TFO; runtime paths must still use TFO-capable sockets where required.

## Enter the macOS development guest

Source builds and privileged evaluation packaging run in the required Apple Containers Linux guest, not on macOS. Use your own instance file rather than a maintainer-specific path:

```bash
APPLE_LINUX_DEV_LAUNCHER=/path/to/apple-linux-dev/bin/dev-container
INSTANCE=/path/to/your-prodigy-instance.json
"$APPLE_LINUX_DEV_LAUNCHER" exec "$INSTANCE" -- env \
  PRODIGY_DEV_TEST_BOUNDARY=apple-container \
  PRODIGY_DEV_APPLE_CONTAINER_ID="$(jq -r .name "$INSTANCE")" \
  bash
```

Inside that shell, navigate to the mounted checkout and run `tools/build-evaluation.sh` and `tools/package-evaluation.sh`. The selected instance must satisfy the Apple Container and guest-only authorization checks enforced by the test launcher; those instance flags never authorize macOS BPF operations.

## Privileged test boundary

Runtime tests may manipulate network namespaces, bridges, veth pairs, BPF/XDP/TC hooks, cgroups, loop devices, Btrfs images, bind mounts, and container roots. Root privileges alone are insufficient.

On macOS, enter through [`prodigy_dev_test_cluster.sh`](../dev/tests/prodigy_dev_test_cluster.sh), which selects the approved Apple Container boundary. On an ordinary Linux workstation, use a KVM-accelerated disposable guest; a dedicated sacrificial runner may provide the required marker. The [test-cluster guide](../dev/tests/manual/test/README.md) owns those instructions and cleanup behavior. Do not run privileged test clusters directly on an unverified host.
