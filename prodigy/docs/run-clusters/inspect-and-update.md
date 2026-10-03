# Inspect and update a cluster

Set a real stored cluster name, application name, and approved runtime input before operating on a cluster:

```bash
CLUSTER_NAME=example-test
APPLICATION_NAME=my-app
UPDATE_INPUT="$PWD/prodigy.aarch64.bundle.tar.zst"
mothership clusterReport "$CLUSTER_NAME"
mothership applicationReport "$CLUSTER_NAME" "$APPLICATION_NAME"
mothership containerLogs "$CLUSTER_NAME" "$APPLICATION_NAME"
```

Stage a runtime update with an approved binary or bundle:

```bash
mothership updateProdigy "$CLUSTER_NAME" "$UPDATE_INPUT" --brain-concurrency 1
```

`--brain-concurrency` accepts `1` or `2` and defaults to `1`. It limits follower Brain upgrades in progress; the current master hands off and upgrades last. A follower must rejoin with the expected bundle, recover its owned container inventory, and acknowledge the current durable authority before its slot can be reused. Worker Neurons remain serial. The selected limit is durable for the operation; a retry must use the same bundle and limit.

Both the installed master and its Brain peers must support this option (binary version 21 or newer). Mothership checks the installed versions before submitting an update. A new bundle cannot change an older master's rollout behavior, and the command never falls back to a legacy simultaneous update. Upgrading a legacy fleet first requires a separately qualified bootstrap or maintenance procedure; retained-fleet recovery stops all selected runtimes and is not a serial bootstrap.

Mothership resolves the target architecture and rejects unsupported or unapproved bundle input before it contacts the cluster. A staging response does not attest workload health. After an update, wait for `clusterReport` to show all expected runtimes and applications healthy, then verify the application's normal traffic path. Concurrency `2` can temporarily leave a three-Brain cluster with only its incumbent master; neither setting alone guarantees uninterrupted application service. The proposed evaluation shorthand, `./try-prodigy update`, is candidate-only until a clean-room result is recorded.

Runtime update safeguards, OS-update policies, and majority requirements are documented in [Runtime and operations](../runtime.md). Bundle approval is covered by [Security](../security.md).
