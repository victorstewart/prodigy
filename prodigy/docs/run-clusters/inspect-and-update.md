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
mothership updateProdigy "$CLUSTER_NAME" "$UPDATE_INPUT"
```

Mothership resolves the target architecture and rejects unsupported or unapproved bundle input before it contacts the cluster. After an update, wait for `clusterReport` to show recovery; the existing test harness uses that evidence. The proposed evaluation shorthand, `./try-prodigy update`, is candidate-only until a clean-room result is recorded.

Runtime update safeguards, OS-update policies, and majority requirements are documented in [Runtime and operations](../runtime.md). Bundle approval is covered by [Security](../security.md).
