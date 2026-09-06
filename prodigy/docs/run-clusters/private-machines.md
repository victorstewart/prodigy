# Run on private or existing cloud machines

Use a `deploymentMode: "remote"` cluster to adopt machines that already exist. This is separate from the disposable `deploymentMode: "test"` cluster: the test path creates its own virtual datacenter and never adopts a local host or a remote machine. `deploymentMode: "local"` has local-membership semantics and is not the private-machine path.

The canonical inventory shape is the checked-in [adopted AWS machine template](../../dev/tests/manual/aws/create_cluster.remote.machines.aws.template.json). Its `machines[]` entry is the provider-neutral part of the remote inventory: it records whether the machine is a Brain, its SSH endpoint, its private and public addresses, and its ownership mode. The AWS-specific `cloud` object identifies the existing provider machine. Use the matching [AWS manual flow](../../dev/tests/manual/aws/README.md) for the current managed and adopted AWS prerequisites.

For every adopted machine, Mothership requires:

- `source: "adopted"` and an SSH address. If `ssh.address` is omitted, the first listed private address is used, then the first public address.
- An SSH user and private-key path, either per machine or through `bootstrapSshUser` and `bootstrapSshPrivateKeyPath`. Remote bootstrap currently requires the `root` user.
- `ssh.hostPublicKeyOpenSSH`, pinned for that exact machine. Add it to the checked-in template before use; current source validation rejects an adopted machine without it.
- Accurate `addresses.private` and/or `addresses.public` entries when they are the cluster's reachable addresses. Each entry supplies `address`, `cidr`, and `gateway`.

The remote cluster envelope is not provider-free today. Source validation requires `provider` to be `aws`, `gcp`, `azure`, or `vultr`, plus a named provider credential and a supported target architecture, even when the adopted machine itself uses `backing: "owned"`. A cloud-backed adopted machine additionally needs its provider `cloud` identity. This is the current limitation for entirely private, provider-independent inventory.

The template is a source-backed starting point, not an externally validated private-machine runbook. Fill its `REPLACE_*` values, pin every SSH host key, and review the provider-specific prerequisites before creating a remote cluster. Mothership then owns installation, bootstrap, configuration, deployment, reporting, and removal; do not use the local disposable test launcher to install or mutate the adopted hosts.
