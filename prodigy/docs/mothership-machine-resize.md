# Mothership VM resource maintenance

`resizeKvmMachine` coordinates one explicitly approved, grow-only KVM guest
resize through the pinned external supervisor. Its private JSON plan binds the
cluster and target guest UUID, controller and guest machine IDs, expected guest
boot ID, pinned hypervisor SSH host key, supervisor/config/ingress-policy
paths and SHA-256 digests, unit, current PID/start time, requested CPU and
memory, and an operation ID. Mothership verifies every machine and deployment
before and after the resize. It invokes supervisor `preflight`, then `prepare`,
submits a delayed guest-local guarded poweroff, and only then invokes `resize`.
The command expects the supervisor's exact terminal receipt and never invokes
QEMU or systemd on the hypervisor itself.

Run it from a controller other than the target guest. A resize restarts that
guest; it has no drain or zero-downtime guarantee. Use one invocation at a
time and observe the successful postflight report before the next guest.

`growContainerPool <clusterUUID> <machineUUID> <sizeGiB>` grows only the
selected VM's `/containers` loop-backed Btrfs pool. It uses the existing
Mothership SSH identity and rejects non-VM targets or any backing store that
does not prove Prodigy ownership. It neither changes the host disk nor adds a
runtime protocol.
