# AWS Manual Cluster Flow

This directory is the operator bundle for live AWS cluster bring-up tests.

<!-- Keep the cheap cloud runbooks visible during manual test work.
     Reuse these current recipes before starting a new multicloud timing wave:
     prodigy/docs/runbooks/aws.3brain.cheap.md
     prodigy/docs/runbooks/azure.3brain.cheap.md
     prodigy/docs/runbooks/gcp.3brain.cheap.md
     prodigy/docs/runbooks/vultr.3brain.cheap.md -->

## Goal

Create EC2 instances with `remote` `machineSchemas` or with manually adopted machines, then
use `clusterReport` to inspect the live cluster-wide machine and application status.

## Credential format

Managed remote AWS clusters now use:

- controller/seed bootstrap auth through EC2 IMDS (`awsImds` provider credential mode)
- an attached EC2 instance profile for the running Prodigy brains

Mothership and Prodigy on EC2 both use IMDSv2 temporary credentials from
attached instance profiles. Prodigy does not receive a long-lived AWS secret
through cluster runtime state.

## One-time setup

1. Create a named provider credential:

```bash
./build-prodigy-dev-clang-owned/mothership createProviderCredential "$(cat prodigy/dev/tests/manual/aws/create_provider_credential.aws.template.json)"
```

2. Create the cluster and let Mothership provision the initial EC2 instances:

```bash
./build-prodigy-dev-clang-owned/mothership createCluster "$(cat prodigy/dev/tests/manual/aws/create_cluster.remote.schemas.aws.template.json)"
```

3. Fetch the live cluster-wide status report:

```bash
./build-prodigy-dev-clang-owned/mothership clusterReport aws-managed-test
```

## Notes

- The checked-in AWS templates are pinned to low-cost stock recipes only. For live AWS runs in this repo, keep instance types on `t3.micro` or `t2.micro` only unless the user explicitly approves a more expensive size.
- The cluster JSON now also requires:
  - `aws.instanceProfileName` or `aws.instanceProfileArn`
- That instance profile must already exist and be attachable to EC2 instances created by the local bootstrap identity.

## Current AWS assumptions

- The current AWS `remote` create path with `machineSchemas` now manages an internal per-region launch template behind the scenes:
  - `prodigy-bootstrap-<region>`
  - version `$Default`
- That internal launch template now also carries the configured EC2 instance profile for managed remote AWS clusters.
- Prodigy keeps owning:
  - instance type
  - AMI
  - bootstrap `UserData`
  - Prodigy/cluster tags
  - spot vs on-demand
  - block-device size overrides
- The internal launch template now carries the deterministic bootstrap networking:
  - subnet within the default VPC
  - managed `prodigy-bootstrap-ssh` security group with inbound TCP 22
  - `AssociatePublicIpAddress=true` on the primary interface
- This remains an internal implementation detail. The user-facing `createCluster` JSON does not expose launch-template fields.

## Practical test guidance

- If you already have reachable EC2 instances, prefer starting with `remote` and adopted `machines`.
- If you want to test `remote` with `machineSchemas`, use an account/subnet setup where:
  - launched instances in the default VPC receive a reachable public IPv4 address, or Mothership has direct private-network reachability
- The next AWS schema cut should add explicit network placement and security-group controls so `remote` machine-schema bring-up does not depend on account defaults.
