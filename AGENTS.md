# Prodigy Host Safety Rules

## Container Artifact Rule

Discombobulator is the only valid way to produce a Prodigy container artifact.
Any app container passed to Mothership/Brain/Neuron runtime paths must come from
a Discombobulator `--kind app` build. Do not hand-author launch metadata, Btrfs
receive payloads, rootfs trees, `.zst` blobs, or test fixtures as substitutes
for real runtime deployment artifacts.

Runtime paths must fail closed when an app artifact cannot prove it was produced
by Discombobulator for the supported app-container contract. Every `--kind app`
blob must start with the versioned Discombobulator contract header before the
zstd payload. Mothership must reject deployment blobs whose header, digest, or
size is unsupported or mismatched; Prodigy/Neuron must verify and skip that
header before zstd/Btrfs receive. Tests may construct malformed artifacts only
to prove that rejection behavior; successful runtime/deployment tests must use
Discombobulator-built artifacts.

## Test Harness Ownership Rule

This is a hard architecture boundary. Mothership owns test-cluster desired
state and lifecycle, including the virtual datacenter and its fake machines.
Typed C++ Mothership code owns requests, topology, bundle approval and
installation, boot state, lifecycle, and provider authorization. A
Mothership-owned Bash provider implements only the Linux namespace, fake-root,
link, route, cgroup, Btrfs, and external-boundary plumbing behind that typed
interface. Its tracked Bash source is generated into Mothership at build time
and executed from a sealed anonymous file; do not ship a mutable provider
sidecar, add a runtime provider search path, or duplicate the script as
hand-maintained C++ text. It must not call back into a hidden Mothership
operation. Do not expose that host-level authority through the Brain runtime
provider factory. Mothership must never call a test harness to implement
cluster creation.

The harness is an external client of that system. It may request creation and
configuration through Mothership, schedule work through Mothership, perform
read-only observation, and request explicit fault injection through the test
provider. It must not create, provision, install, launch, or network fake
machines or virtual datacenters.

A test cluster is a reusable disposable cluster type, not one hard-coded test.
Automated harness scenarios and deliberate operator experiments may both deploy
Discombobulator-built workloads into it through Mothership. Keep the harness an
automated scenario driver; use Mothership's ordinary operations for interactive
experiments instead of adding an infrastructure shell or direct machine access
to the harness.

`deploymentMode: "test"` is the official virtual-datacenter cluster type and is
distinct from the single local Prodigy/Brain development cluster. Test clusters
must be created through `mothership createCluster`. Mothership must use its
production-equivalent distribution, installation, bootstrap, and configuration
paths to install Prodigy on every fake machine. The test-cluster provider's
machine execution/filesystem boundary may support those paths, but the harness
must not unpack, stage, install, launch, or update Prodigy itself.

Once Prodigy starts, ordinary cluster configuration, service/application ID
reservation, scheduling, deployment, updates, lifecycle control, and reports
must flow through Mothership. A harness must never compensate for missing
Brain, Neuron, or Switchboard behavior by directly changing runtime state.

In particular, harnesses must not:

- attach, detach, replace, or preattach Prodigy XDP/TCX/netkit programs;
- write or delete Prodigy BPF map entries;
- enable a special preattached-program runtime mode;
- unpack, copy, stage, install, launch, restart, or update Prodigy on a fake
  machine;
- inject pairings or mutate container lifecycle, mounts, cgroups, routes, or
  runtime-owned interfaces after startup;
- repair or synchronize Brain, Neuron, Switchboard, or container state.

Harnesses may pass paths to built artifacts because test artifacts are not
necessarily installed system-wide. Prodigy remains responsible for selecting
interfaces, attaching programs, opening the live program's maps, initializing
and synchronizing those maps, and failing closed when any step fails. Direct
inspection is read-only and must assert the state Prodigy created. Fault
injection may disrupt the disposable environment but must never repair the
cluster. Keep a source-contract test that rejects forbidden ownership leakage.

On this Apple machine, all privileged Linux runtime verification must use Apple
Containers exclusively. Do not use QEMU, TCG, OrbStack, Docker, or a fallback
virtualization backend. Inventory Apple Containers before launch, stop stale
duplicates, and keep at most one bounded Prodigy/Nametag Linux container
running. Reuse that container and its caches; stop it when Linux-only or
privileged verification finishes.

Host-boundary selection belongs to
`prodigy/dev/tests/prodigy_dev_test_cluster.sh`, outside the Linux-only harness.
On Darwin it must positively verify and enter the selected Apple Container; the
harness must not orchestrate Apple Containers itself. The Apple Container is
already the hardware-virtualized Linux guest; never nest another VM inside it.
On Linux, compilation and ordinary unit tests may run natively, but privileged
test clusters require a KVM-accelerated QEMU guest or an administrator-provisioned,
root-owned sacrificial-host marker. Never use QEMU TCG. An ordinary Linux
workstation must use the KVM guest; dedicated sacrificial CI may opt into native
execution with that marker.

Cleanup follows the same ownership. Mothership must remove the test cluster and
all provider-created processes, namespaces, links, mounts, cgroups, and storage
on every harness exit. Keep immutable OCI/qcow2 bases, the pinned kernel,
host-mounted caches, and still-valid build outputs. Reuse one guest only within
one serial test batch. After preserving required evidence under `.run/`, the
Darwin launcher must stop and delete the Apple Container and its writable layer
even after failure or interruption. A Linux VM's external creator must destroy
its QEMU process and per-run overlay after the in-guest launcher returns; do not
make the harness call a hypervisor or power off its containing host. Native
disposable CI must verify the same provider-resource cleanup before reuse.

## Critical Runtime Test Rule

This repo contains code and test harnesses that can manipulate Linux network
namespaces, bridges, veth pairs, BPF/XDP/TC hooks, cgroups/cpuset state, loop
devices, Btrfs images, bind mounts, and container roots.

Prodigy dynamic/runtime/system tests may run directly on the physical host
`wizard` only when the harness proves complete isolation before it touches
system-level state. That means the test must enter disposable namespaces first
and must fail closed before creating links, mounts, cgroups, containers, BPF
state, or other runtime resources if isolation cannot be proven.

A namespace-contained host run must verify and record all of the following
before starting the risky portion of the test:

- `RuntimeWatchdogSec` is active on `/dev/watchdog0`.
- Swap is active.
- The test has a hard timeout and bounded resource envelope.
- PID, mount, network, IPC, UTS, cgroup, and user namespace isolation is active.
- The process does not retain host-root `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`,
  `CAP_BPF`, or `CAP_SYS_MODULE` outside the isolated namespace boundary.
- Host network namespace, host interfaces, host routes, host firewall rules, and
  host BPF hooks are not targets.
- Cgroup/cpuset writes are confined to a delegated subtree and cannot rewrite
  host scheduler domains.
- Loop devices, block devices, and mounted filesystems are private to the
  sandbox or explicitly emulated; host `/containers`, `/mnt`, `/sys/fs/bpf`,
  `/sys/fs/cgroup`, and `/proc/sys` must not be mutated.
- Cleanup of netns, links, loop devices, mounts, and preserved roots is planned.

If a test needs real BPF/XDP/TC attachment, host-interface networking, host
cgroup/cpuset mutation, real loop/block-device filesystems, or privileged
mount/cgroup operations that cannot be fully contained by the checks above, run
it inside a disposable VM or another sacrificial machine boundary instead.

If any required check cannot be proven, stop before running the test.
