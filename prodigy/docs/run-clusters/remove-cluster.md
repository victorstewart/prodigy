# Remove a cluster

Set `CLUSTER_NAME` to a real stored cluster name or UUID, then remove it through Mothership:

```bash
CLUSTER_NAME=example-test
mothership removeCluster "$CLUSTER_NAME"
```

For test clusters, Mothership owns removal of provider-created processes, namespaces, links, mounts, cgroups, and storage. The test launcher preserves required evidence under `.run/` and then stops the selected Apple Container on macOS or returns to the Linux boundary owner. Do not repair or remove virtual-datacenter state directly.

Cloud cleanup requires the provider runbook's residual-resource checks after `removeCluster`. The cluster is not considered clean merely because the command returned; follow the runbook for disks, addresses, templates, NICs, and provider-specific resources.
