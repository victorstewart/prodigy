# Install an evaluation bundle

The evaluation bundle is a local release candidate. **There is no published
binary download yet.** Its HTTP walkthrough is still being validated; check
[current status](status.md) before starting. Contributors can build the candidate
using the steps below.

## Prerequisites

| Platform | Required environment |
|---|---|
| Apple Silicon Mac | Apple Containers running; the pinned `apple-linux-dev` launcher and a compatible instance; Python 3.9+ and `jq` on the Mac |
| Linux | Linux 7.0 or newer inside the approved disposable KVM guest, or an administrator-provisioned sacrificial runner; Bash, Python 3.9+, and `systemd-detect-virt` |

The [test-cluster boundary guide](../../dev/tests/manual/test/README.md) owns the
instance and Linux marker requirements. An arbitrary Linux workstation is not a
supported privileged evaluation target. A compatible guest must provide the
runtime's kernel features and userspace; matching CLI libraries ship in the
bundle.

On macOS, the instance must mount the directory containing the unpacked bundle
and carry the prescribed guest-only BPF authorization. The launcher checks the
pinned guest and creates a temporary route for `198.18.0.0/16`; macOS may ask for
administrator authentication to add and remove that route. It rejects conflicting
routes. No cloud account is needed.

## Build a candidate

Use a complete source checkout and the [contributor build requirements](../build.md).
The wrapper builds the runtime, tools, and both example versions. It fetches the
checksum-pinned Depos CMake module if missing; CMake resolves the declared build
dependencies. It does not install system packages.

On a Mac, select your existing compatible instance and enter its guest:

```bash
export APPLE_LINUX_DEV_LAUNCHER=/path/to/apple-linux-dev/bin/dev-container
export PRODIGY_APPLE_CONTAINER_INSTANCE=/path/to/your-prodigy-instance.json
"$APPLE_LINUX_DEV_LAUNCHER" ensure "$PRODIGY_APPLE_CONTAINER_INSTANCE"
"$APPLE_LINUX_DEV_LAUNCHER" exec "$PRODIGY_APPLE_CONTAINER_INSTANCE" -- env \
  PRODIGY_DEV_TEST_BOUNDARY=apple-container \
  PRODIGY_DEV_APPLE_CONTAINER_ID="$(jq -r .name "$PRODIGY_APPLE_CONTAINER_INSTANCE")" \
  bash
```

Navigate to the checkout mounted inside the guest. On Linux, enter the approved
disposable boundary first. Then build and package:

```bash
tools/build-evaluation.sh
tools/package-evaluation.sh
```

The package command prints the archive path under `.run/releases/`; a SHA-256
sidecar accompanies it. It also leaves an unpacked copy under `.run/evaluation/`.
The name has this form:

```text
prodigy-evaluation-0.1.0-eval.<commit>[.dirty.<digest>]-<arch>.tar.gz
```

The optional `.dirty.<digest>` identifies uncommitted source changes. Architecture
is `aarch64` or `x86_64`; a build only produces its own architecture. The manifest
records source identity and checksums. Repackaging does not overwrite an existing
candidate.

## Start the evaluation

Change to the unpacked package directory and follow [Run your first service](first-service.md).
On macOS, run its `./try-prodigy` from the Mac terminal with the two exported
launcher variables above. Keep the bundle in the instance's mounted directory.

On Linux, run from inside the approved guest. The command removes its cluster
when it ends; the external guest owner remains responsible for stopping or
destroying that Linux guest. On macOS, the launcher also stops the selected Apple
Container. Clean installation and a fully automatic Linux host launcher remain
release gates.
