# Runtime constraints and operations

This page is the short runtime reference. Follow task pages for procedures: [private machines](run-clusters/private-machines.md), [cloud](run-clusters/cloud.md), [inspection and update](run-clusters/inspect-and-update.md), and [removal](run-clusters/remove-cluster.md).

## Startup and state

Prodigy requires Linux kernel 7.0 or newer and fails closed on older kernels. First boot receives a seed through `--boot-json` or `--boot-json-path`; later boots load TidesDB state, normally from `/var/lib/prodigy/state`. A seed includes bootstrap peers, node role, and a control-socket path. Runtime network paths are explicit: `PRODIGY_HOST_INGRESS_EBPF`, optional `--netdev`, `--tunnel-ebpf`/`PRODIGY_TUNNEL_EBPF`, and internal state FDs for transitions.

## Capacity and isolation

Production placement reserves 2 logical CPU cores, 4 GiB memory, and 4 GiB storage by default. Non-production smoke clusters may use `"resourceReservation": "smoke"`. Btrfs-backed `/containers` can use squota for storage limits and metrics. Containers run behind a seccomp floor that denies host-control operations including BPF, mount/namespace mutation, module loading, and host-time control.

Runtime tests manipulate namespaces, BPF, cgroups, mounts, and containers. On macOS use the approved Apple Container launcher; on Linux use the supported disposable boundary. The [test-cluster manual flow](../dev/tests/manual/test/README.md) owns setup and cleanup.

## Updates and special modes

`updateProdigy` uses an approved bundle and waits for cluster control-path recovery. Update execution requires the configured Brain and switch majorities. Bundle approval, credentials, and identity are in [Security](security.md).

`mothershipConnectivity.kind=tunnelProvider` is a master-Brain system-container mode, never a normal application deployment. It has private namespaces, no capabilities, a read-only rootfs, gateway-mediated control, and allowlist-only egress; misconfiguration fails closed rather than falling back to SSH.

For packet-path assumptions see [network packet budgets](network-packet-budgets.md); for application protocol and readiness see [workload lifecycle](understand/workload-lifecycle.md).
