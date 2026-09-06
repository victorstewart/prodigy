# Run the first service

This tutorial uses the packaged evaluation bundle. Complete [Install an evaluation bundle](install.md), then change to the unpacked package root.

> Verified inside the prepared Apple Containers AArch64 guest on 2026-09-06.
> Clean-machine installation, Mac-host access, and the Linux host launcher remain
> release gates; see [current status](status.md).

Start the disposable one-machine, one-Brain test cluster in the foreground:

```bash
./try-prodigy
```

In a second terminal, from the same package root, request the HTTP service:

```bash
curl --noproxy "*" http://198.18.0.10:8080/
```

The v1 response is:

```text
hello from Prodigy v1
```

Inspect the running cluster and application:

```bash
./try-prodigy status
```

Update the evaluation application, then request the endpoint again:

```bash
./try-prodigy update
curl --noproxy "*" http://198.18.0.10:8080/
```

The response is now:

```text
hello from Prodigy v2
```

Return to the foreground terminal and press Ctrl-C. The launcher removes the test cluster; on macOS it also stops the selected Apple Container. Continue with [Build a first application](../build-applications/first-application.md) to create a workload that implements the required protocol.

[Read the verified terminal transcript](first-service-transcript.md).

## What the launcher does

Mothership is the operator CLI. The evaluation client calls its ordinary
operations in order: `createCluster @cluster.json`, `clusterReport`,
`reserveApplicationID`, `reserveServiceID`, `registerRoutableSubnet`, and
`deploy` with the resolved plan file and a Discombobulator-built artifact.
It waits for the real HTTP response and retrieves `applicationReport`.
The update repeats `deploy` with application version two.

Mothership owns installation on the test machine, scheduling, routing, runtime
state, and cluster removal. The launcher does not provision a second cluster
implementation. Generated inputs and bounded operation logs are kept in the
printed `.run/evaluation/hello-…` evidence directory.

Startup waits are bounded, and the foreground session ends after 30 minutes.
Failure and interruption call `removeCluster`. On macOS the host launcher also
removes its temporary route and stops its Apple Container. On Linux the external
guest owner must stop or destroy the containing guest after the session returns.
See [Mothership commands](../reference/cli.md) for ordinary cluster operation.
