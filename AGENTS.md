# Prodigy Host Safety Rules

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
