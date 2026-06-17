#Runtime startup and state

This document captures the runtime startup contract, persistent - state behavior, local / test cluster notes, and runtime update workflow.

                                                                                                                  ##Startup seed

                                                                                                                      On first boot,
    Prodigy can be seeded by either :

```text-- boot - json-- boot - json - path
```

    The boot seed is persist -
    only.Later boots load local state from TidesDB.

        Default local state path :

```text /
        var / lib / prodigy / state
```

        A first -
    boot seed must include :

    -bootstrap peers;
- node role;
- control socket path.

Runtime environment fields are optional and can be supplied when the deployment needs them.

Remote bootstrap uploads the boot seed and invokes Prodigy with `--boot-json-path`. Control can happen through a local Unix socket or through SSH stream-local forwarding.

## Runtime inputs

Runtime paths that affect host networking must be explicit so a node cannot silently boot with the wrong packet path:

- `PRODIGY_HOST_INGRESS_EBPF`: absolute path to the host ingress router eBPF object loaded at TCX ingress on the host NIC. Without it, the neuron exits early.
- `--netdev=...`: optional primary host network device override. If unset, Prodigy autodetects the primary non-loopback interface from the routing table and interface addresses.
- `--tunnel-ebpf=...` or `PRODIGY_TUNNEL_EBPF`: development-binary tunnel-to-NIC eBPF object path.
- `PRODIGY_NEURON_STATE_FD` and `PRODIGY_BRAIN_STATE_FD`: internal fast-restore memfd descriptors used by update and transition logic.

## Local and fake clusters

For development, use Prodigy's local/test modes instead of paying cloud latency and cloud cost for every iteration.

Persistent fake clusters are supported through `mothership createCluster` with:

```json
{
  "deploymentMode": "test"
}
```

The raw fake-cluster harness is intentionally lower-level. Prefer the Mothership path when you want a persistent cluster record and normal cluster operations.

## Self-update

Prodigy includes an explicit runtime update operation:

```bash
./mothership updateProdigy \
  '<local|cluster-name|cluster-uuid>' \
  './dist/prodigy-approved-bundle'
```

The command is intended to push an exact approved runtime bundle and reject incompatible bundles. This is the foundation for rapid swarm fanout updates: one orchestrator updates the runtime that is itself responsible for the machines and containers.

Update orchestration controls are part of brain configuration:

- `maxOSDrains` bounds concurrent OS update drains and defaults to `1`.
- `machineUpdateCadenceMins` defaults to `15`. The active master waits at least this long after becoming active, then starts one machine update per cadence tick.
- VM reimages from `MachineConfig.vmImageURI` changes run before in-place OS updates.
- In-place OS updates require `osUpdatesEnabled=true` and full `osUpdatePolicies[]` coverage for every controlled machine's `/etc/os-release` `ID`.
- Neuron runs the matching policy command with `PRODIGY_TARGET_OS_ID`, `PRODIGY_TARGET_OS_VERSION_ID`, `PRODIGY_CURRENT_OS_ID`, and `PRODIGY_CURRENT_OS_VERSION_ID` set. Prodigy does not infer distro package-manager commands.

Mutating actions execute only when more than half of the expected brains are present, registered, and non-quarantined, and a majority of metro switches are reachable. Non-active masters remain read-only. Brains must compute the same expected brain count from provider listings or majority decisions can diverge.

## Machine health and replacement

Prodigy treats hardware failure as a normal orchestration event.

The runtime tracks machine reachability and local machine state. Provider adapters can then translate runtime observations into provider-specific action:

1. mark the machine unhealthy;
2. report or annotate the machine with the cloud provider when supported;
3. remove or quarantine the bad machine;
4. replace capacity from the provider API;
5. rejoin the new machine to the cluster;
6. let workloads reseed or rebalance.

This matters for hourly, on-demand, and spot-style fleets: failed or reclaimed machines should not leave the operator with a manual repair checklist.

## Resource model

Prodigy schedules against an explicit machine budget. Current safe defaults reserve capacity for the OS and Prodigy itself so containers cannot starve the machine:

| Reserved by default | Amount |
|---|---:|
| Logical CPU | 2 logical cores |
| Memory | 4 GiB |
| Storage | 4 GiB |

These defaults are intentionally conservative and may be lowered as runtime footprint measurements mature.
Non-production demo/smoke clusters can set `"resourceReservation": "smoke"`
at `createCluster` time to reserve zero CPU, memory, and storage for placement
accounting. The default is `"production"` and remains the only production mode.

Capacity accounting:

```text
usable_cpu      = provider_cpu      - reserved_cpu
usable_memory   = provider_memory   - reserved_memory
usable_storage  = provider_storage  - reserved_storage
container_budget <= usable_machine_budget
```

Operating principles:

- no separate managed control plane required for the basic model;
- no mandatory service-mesh sidecars for every process;
- explicit capacity reservation so overload behavior is predictable;
- cloud - provider lifecycle control so unused machines can be removed quickly;
- pricing and recommendation paths designed around provider machine offers, including hourly/on-demand and spot-style markets, with reserved-capacity support handled by provider adapters as available.

## Storage quotas

Hosts that back `/containers` with Btrfs can use squota for per-container storage limits and utilization metrics.

Requirements:

- Linux kernel `>= 6.7`;
- recent `btrfs - progs` with squota support;
- `btrfs quota enable -s /containers` at bootstrap.

Neuron reads referenced bytes and limits through `libbtrfsutil` for `storageUtilPct`. If squota is unavailable, storage utilization metrics are disabled while CPU and memory metrics continue.

## Autoscaling

Prodigy local metrics use deterministic `uint64_t` metric keys. Containers emit batched samples through `ContainerTopic::statistics`;
Neuron forwards them to Brain as `NeuronTopic::containerStatistics`; Brain keeps raw per-container samples in memory and computes scaler values over each scaler's `lookbackSeconds` window.

Horizontal scalers are available for stateless and stateful deployments. Stateful deployments never autoscale down.

Vertical scalers are stateful-only and scale up only. Brain clamps per-instance CPU, memory, and storage to configured caps, verifies the resulting shape fits at least one known machine schema, and then either adjusts cgroups/Btrfs limits in place or respins the deployment if current machines cannot fit the increase.

## Container syscall floor

Prodigy applies a hard seccomp deny floor for kernel-control and host-observation syscalls such as `bpf`, `ptrace`, `process_vm_*`, `process_madvise`, `kcmp`, `pidfd_*`, mount or namespace mutation, module loading, keyring mutation, kernel log access, host time control, accounting, quota control, and related host-control operations.

Shared CPU mode also denies `sched_setaffinity` so workloads cannot self-pin. Review the deny floor when upgrading the supported Linux syscall surface.
