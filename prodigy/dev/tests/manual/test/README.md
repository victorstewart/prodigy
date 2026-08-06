# Test Cluster Manual Flow

This directory is the operator bundle for the first-class Mothership `deploymentMode: "test"` cluster type.

## Goal

Create and manage a persistent fake Prodigy cluster through Mothership. A test
cluster can host automated validation or operator-chosen, Discombobulator-built
experimental workloads; it is not itself a single test.

The `test` cluster type creates the virtual datacenter, fake machines, networking, installation, and Prodigy processes on the Linux host running Mothership. To host a test cluster on another machine, run Mothership on that machine.

The automated harness is only a Mothership client and assertion driver. It asks
Mothership to create the cluster, schedule work, report state, inject declared
faults, and remove the cluster. It never provisions the virtual datacenter or
installs Prodigy directly.

From macOS, enter through `prodigy_dev_test_cluster.sh`; it selects or creates
the approved reusable Apple Container instance before invoking the harness.
Apple Containers is already the VM boundary, so there is no nested guest. On an
ordinary Linux workstation, use a QEMU guest with KVM hardware acceleration and
an immutable base plus per-run overlay; never use TCG. A dedicated sacrificial
Linux runner may instead provide the root-owned disposable-environment marker.
Native compilation and unit tests do not require this launcher.

Mothership removes the test cluster on harness exit. Required reports and
failure logs are first preserved under the host-mounted `.run/` root. The
Darwin launcher then stops the thin Apple Container instance on success,
failure, or interruption while retaining that instance, the base image, kernel,
dependency caches, and valid build outputs. A Linux VM runner likewise deletes
the per-run overlay after the in-guest command returns; that outer VM lifecycle
intentionally remains outside the harness.

```bash
prodigy/dev/tests/prodigy_dev_test_cluster.sh \
  .run/release/prodigy \
  --mothership-bin=.run/release/mothership
```

For a retained test deployment created by a separate command in the Apple
guest, start the route owner on macOS before deploying and leave it running:

```bash
prodigy/dev/tests/prodigy_dev_test_cluster.sh --hold-apple-route
```

The owner keeps the approved Apple Container and its synthetic `/16` host route
alive until interrupted. On exit it deletes only a route it added, then stops
the guest. It fails closed when the synthetic prefix already contains a
more-specific route or its exact route points at another gateway.

## Example

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

## Notes

- `nBrains` remains the top-level cluster field.
- `test.machineCount` can be greater than `nBrains`; the extra fake machines boot as neurons instead of brains.
- `controls` are auto-derived from `test.workspaceRoot`; do not include them in the request.
- Test clusters use the virtual-datacenter provider embedded in Mothership; no provider script is installed beside the binary.
- `clusterReport` is the live machine/application status view for the cluster.
- Use `setTestClusterMachineCount` to resize a test cluster; it only mutates `machineCount` and still rejects shapes below `nBrains`.
- Test harnesses are external clients: they may ask Mothership to create, inspect, resize, fault, and remove clusters, but must not provision or repair virtual-datacenter infrastructure directly.
