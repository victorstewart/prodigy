# Configuration reference

A test-cluster request needs a name, `deploymentMode: "test"`, a Brain count, a machine schema, and a `test` object with an absolute workspace root and machine count. The count must be at least the Brain count, and local/test architecture must match Mothership. The maintained [test template](../../dev/tests/manual/test/create_cluster.test.local.template.json) is canonical.

Application plans are separate from cluster configuration. They describe the deployment and pair with a Discombobulator app artifact. Every deployed application must implement the Neuron/container protocol; SDKs are optional language implementations. Use the checked-in SDK mesh plans as references, and use [Discombobulator](../discombobulator.md) for artifact requirements.

Runtime paths, TCP Fast Open, capacity reservation, Btrfs quotas, OS-update policy, and tunnel-provider mode are documented in [Runtime](../runtime.md). Provider fields belong in the [cloud runbooks](../run-clusters/cloud.md), not generic cluster templates.
