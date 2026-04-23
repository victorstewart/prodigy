# Test Cluster Manual Flow

This directory is the operator bundle for the first-class Mothership `deploymentMode: "test"` cluster type.

## Goal

Create and manage a persistent fake Prodigy cluster through Mothership instead of invoking the persistent netns harness directly.

The `test` cluster type is the preferred operator entrypoint for:

- local fake clusters on the current host
- fake clusters hosted on a remote machine over SSH

The raw harness remains available underneath for low-level debugging and test development.

## Local host example

Edit the workspace/name fields if needed, then create the cluster:

```bash
./build-prodigy-dev-clang-owned/mothership createCluster "$(cat prodigy/dev/tests/manual/test/create_cluster.test.local.template.json)"
```

Fetch the live cluster-wide status report:

```bash
./build-prodigy-dev-clang-owned/mothership clusterReport test-local-3brain
```

Remove the cluster and tear down the fake machines:

```bash
./build-prodigy-dev-clang-owned/mothership removeCluster test-local-3brain
```

## Remote SSH host example

Edit the SSH host fields, remote key path, remote Prodigy path, and workspace root, then create the cluster:

```bash
./build-prodigy-dev-clang-owned/mothership createCluster "$(cat prodigy/dev/tests/manual/test/create_cluster.test.remote_ssh.template.json)"
```

Inspect or remove it the same way:

```bash
./build-prodigy-dev-clang-owned/mothership clusterReport test-remote-3brain
./build-prodigy-dev-clang-owned/mothership removeCluster test-remote-3brain
```

## Notes

- `nBrains` remains the top-level cluster field.
- `test.machineCount` can be greater than `nBrains`; the extra fake machines boot as neurons instead of brains.
- `controls` are auto-derived from `test.workspaceRoot`; do not include them in the request.
- Local test clusters are providerless and use a direct local unix socket.
- Remote test clusters are providerless and use SSH to start/stop the remote runner, then SSH-proxied remote unix-socket control.
- `clusterReport` is the live machine/application status view for the cluster.
- Use `setTestClusterMachineCount` to resize a test cluster; it only mutates `machineCount` and still rejects shapes below `nBrains`.
- If you need direct harness flags, fault injection, one-shot deployment smoke flows, or low-level namespace debugging, use [prodigy_dev_netns_harness.sh](/root/prodigy/prodigy/dev/tests/prodigy_dev_netns_harness.sh) directly.
