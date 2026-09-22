# Mothership control-state migration from TidesDB 9 to 10

Use the successor Mothership binary and its Discombobulator-built runtime bundle.
A v10 reader must never open the original v9 directories. This command supports
one registered three-Brain cluster: the two Mothership registries and each Brain's
state and secrets databases. It preserves all existing keys and values, including
empty column families. It supports the existing Prodigy default-comparator,
non-expiring control-state contract; it is not a general TTL database converter.

Prepare an owned, mode-0600 JSON file with these fields:

- `schemaVersion`: `1`.
- `clusterUUID`, `operationID`: nonzero hexadecimal UUID strings.
- `operationRoot`: a new absolute private evidence directory. Use only letters,
  digits, slash, dot, underscore, and hyphen; no symlinks.
- `registryRoot`: the selected Mothership registry directory, also supplied in
  `PRODIGY_MOTHERSHIP_TIDESDB_PATH`.
- `bundlePath`: the approved successor bundle, with its SHA256 sidecar.
- `runtimeRoot`: the registered installation directory, not its `prodigy` file.
- `statePath`, `secretsPath`: the two existing Brain database directories.
- `expectedOldRuntimeSHA256`, `expectedOldBundleSHA256`: verified current hashes.
- `machines`: exactly three objects containing `machineUUID`, `linuxMachineID`,
  and `sshAddress`. They must match the registered SSH authorities and guests.

Run:

```
PRODIGY_MOTHERSHIP_TIDESDB_PATH=<registryRoot> <successor-mothership> migrateTidesDB9To10 <plan-file>
```

Mothership locks the old registry, validates migrated private registry copies,
resolves existing SSH authority, and verifies all old/new runtime identities.
It installs a durable systemd startup fence before stopping `prodigy.service` on
any machine. Application container leaves remain outside that service's cgroup;
their PID/start-time identities are checked before and after quiescence and before
activation. No original database is exported in place.

All eight private copies must pass export, import, close/reopen, and exact logical
readback before the first database rename. Original directories are retained with
an operation-specific `.tidesdb9-...` suffix. Every database swap is checkpointed;
a lost checkpoint after either rename is recoverable. All three runtime trees
must be installed and verified before the durable activation boundary is crossed
and service startup fences are released.

After an interruption, inspect the operation receipt and logs, then rerun the
same immutable plan. Partial source-copy or runtime-copy directories fail closed;
do not delete them or replace live databases manually. Before activation, the
explicit recovery operation is:

```
PRODIGY_MOTHERSHIP_TIDESDB_PATH=<registryRoot> <successor-mothership> migrateTidesDB9To10 <plan-file> rollback
```

Rollback retains prepared v10 data and restores the old databases and runtimes
before starting any old Brain. After activation may have admitted new writes,
rollback is rejected: resume forward with the successor owner. Never select the
old Mothership binary against the now-v10 live registry.

Successful migration reports `applicationHealthAttested=0`. Separately verify
fresh Mothership reports against direct processes, container identities, memory
limits, crashes, and OOM events. Keep private exports, receipts, original databases,
and old runtime directories through that qualification. The operation-specific
systemd drop-in is inert after its fence marker is removed; retain it with the
recovery evidence until a separately authorized cleanup.
