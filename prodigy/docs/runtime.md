Prodigy Runtime Requirements
============================

Environment variables and/or CLI flags must provide the runtime paths for eBPF programs and network devices. Hardcoded defaults are removed to avoid silent misconfiguration.

Required
- `PRODIGY_HOST_INGRESS_EBPF`: Absolute path to the host ingress router eBPF object (loaded at TCX ingress on the host NIC). Without this, the neuron exits early.
- `--netdev=...`: Optional primary host network device override. If unset, Prodigy autodetects the primary non-loopback interface from the routing table/interface addresses.

Development tunnel (dev binary)
- Provide the tunnel-to-NIC eBPF object path via either:
  - CLI flag: `--tunnel-ebpf=/path/to/tunnel_to_nic.ebpf.o`, or
  - Env var: `PRODIGY_TUNNEL_EBPF=/path/to/tunnel_to_nic.ebpf.o`

Optional
- `PRODIGY_NEURON_STATE_FD` / `PRODIGY_BRAIN_STATE_FD`: Internal fast-restore memfd descriptors (set by the update/transition logic).

Notes
- For production, ensure Cloudflared is installed at the configured path and credentials/tokens are provisioned out-of-band.
- The brain’s OS update drain concurrency can be configured via the BrainConfig (serialized from mothership): `maxOSDrains`.
  - Default: `maxOSDrains=1` (upper bound; updates start serially by cadence).
 - Machine update cadence: `machineUpdateCadenceMins` (default 15). The master waits at least this long after becoming active, then starts exactly one machine update per cadence tick.
- VM reimages vs OS updates:
  - VM reimages (triggered by updating a `MachineConfig.vmImageURI`) always run before OS updates.
  - OS updates only run when the mothership sets a target Clear Linux VERSION_ID; the brain enqueues only machines reporting a lower `VERSION_ID`.
  - VM inclusion for OS-target campaigns is explicit: the mothership must pass `includeVMs=true` to include VMs; otherwise only bare metal is updated.
   - Disable Clear Linux automatic updates on all machines so restarts do not cause unintended upgrades:
     - `swupd autoupdate --disable`
     - Mask any auto-update systemd units/timers if present.
 - Majority-present gating: Mutating actions execute only when more than half of the expected brains are present (registered and non-quarantined) and a majority of metro switches are reachable. Non-active masters remain read-only; state changes resume automatically after healing.
 - Membership consistency: All brains must compute the same expected brain count (N) from IaaS listing (same labels/zone selectors). Divergent N values can break majority decisions.
- Mothership queries: Use `MothershipTopic::isActiveMaster` to query whether a brain is currently the active master (returns a single byte: 1 or 0). Mutating requests (e.g., `spinApplication`, config updates) will reject when not active.

## Storage Quotas (Btrfs squota)

- Requirements: Linux kernel >= 6.7 and recent btrfs-progs with squota support.
- Enable at bootstrap on hosts that back `/containers` with btrfs:
  - `btrfs quota enable -s /containers`
- Behavior: Per-container subvolumes are assigned limits; Neuron reads referenced bytes and limits via libbtrfsutil for `storageUtilPct` metrics.
- Fallback: If squota is unavailable, storage utilization metrics are disabled; CPU and Memory metrics continue to function.

## Autoscaling (Local Metrics)

This cluster uses Local metrics (from Neuron) for autoscaling decisions.

- Metric Keys:
  - All autoscale metrics are keyed as `uint64_t`.
  - Use `ProdigyMetrics::metricKeyForName(...)` for deterministic name-to-key mapping across container, neuron, and brain.
  - Built-in and application-specific metrics use the same key space.

- Metric Pipeline:
  - Containers emit batched samples via `ContainerTopic::statistics` (`metricKey(8), metricValue(8)` pairs), typically through `Statistics`.
  - Neuron forwards each batch to the controlling brain via `NeuronTopic::containerStatistics` with `deploymentID`, `containerUUID`, and `sampleTimeMs`.
  - The Brain stores raw per-container samples in-memory (retention window), then computes scaler values over each scaler's `lookbackSeconds` window.
  - For ingress latency scalers (`ProdigyMetrics::runtimeIngressQueueWaitCompositeName`, `ProdigyMetrics::runtimeIngressHandlerCompositeName`), Brain aggregates fine histogram bucket counts across all containers in the deployment and computes the requested percentile from the combined distribution (cluster-composite percentile).

### Horizontal Scalers (stateless or stateful)

Schema (`horizontalScalers[]`):
- `name`: metric name; converted to key with `ProdigyMetrics::metricKeyForName(name)`
  - Recommended ingress latency metric name: `ProdigyMetrics::runtimeIngressQueueWaitCompositeName` (or `ProdigyMetrics::runtimeIngressHandlerCompositeName` for handler latency).
  - Symbolic aliases are accepted: `ScalingDimension::runtimeIngressQueueWaitComposite` and `ScalingDimension::runtimeIngressHandlerComposite`.
- `percentile`: floating percentile in `(0, 100]` (for example `90`, `95`, `99.5`)
- `lookbackSeconds`: explicit lookback window in seconds
- `threshold` (double): breach threshold for the chosen direction
- `direction`: `upscale | downscale`
- `lifetime`: `ApplicationLifetime::base | surge`

Behavior:
- Each scaler compares its computed percentile value to `threshold`.
- `direction=upscale` triggers when `value >= threshold`; `direction=downscale` triggers when `value <= threshold`.
- Base and surge targets are adjusted independently by scaler lifetime, one step per autoscale tick.
- Stateful safety rule: stateful deployments never autoscale down; only scale-up actions are applied.

### Vertical Scalers (stateful only)

Schema (`verticalScalers[]`):
- `resource`: `ScalingDimension::cpu | ScalingDimension::memory | ScalingDimension::storage`
- `name`: metric name; converted to key with `ProdigyMetrics::metricKeyForName(name)`
- `percentile`: floating percentile in `(0, 100]`
- `lookbackSeconds`
- `threshold` (double)
- `direction`: `upscale | downscale` (stateful deploy validation rejects `downscale`)
- `increment` (positive integer)

Caps and fit checks:
- Optional per-instance caps:
  - `stateful.maxCoresPerInstance`, `stateful.maxMemoryMBPerInstance`, `stateful.maxStorageMBPerInstance`
  - Defaults: derived from the largest machine config known to the cluster
- Before applying vertical deltas, the Brain clamps to caps and verifies the post-scale per-instance shape fits at least one machine config known to the cluster.

In-Place Adjust vs Respin:
- When all hosting machines have sufficient free resources, the Brain attempts an in-place increase:
  - Sends `NeuronTopic::adjustContainerResources` per container with new absolute cores/memory/storage values.
  - Neuron updates cgroups for CPU and Memory, and attempts to update the btrfs qgroup limit (if available); the container receives a `resourcesUpdated` advisory via `ContainerTopic::message`.
- If any machine cannot accommodate the increase, the Brain falls back to respinning the deployment with the new per-instance sizes.
- Stateful safety rule: vertical autoscaling for stateful deployments is scale-up only; downscale signals are ignored.
- Deployment validation rule: stateful plans that set `direction=downscale` are rejected by mothership deploy parsing.
- Dev IaaS: The development IaaS driver does not provision hardware; provider-backed capacity changes are no-ops in dev. Use it only for local multi-brain/neuron logic and application testing.
- Syscall policy: Prodigy applies a hard seccomp deny floor for kernel-control and host-observation syscalls such as `bpf`, `ptrace`, `process_vm_*`, `process_madvise`, `kcmp`, `pidfd_*`, mount/namespace mutation, module loading, keyring mutation, kernel log access, host time control, accounting, quota control, and related host-control operations. Shared CPU mode adds `sched_setaffinity` to that deny floor so workloads cannot self-pin. When upgrading the Linux version, review the kernel's supported syscall surface and update the deny floor accordingly.
