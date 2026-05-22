# IaaS adapters

IaaS adapters connect Prodigy's machine-control model to provider APIs.

Adapters can be written for any cloud or infrastructure API that can create machines, attach metadata or identity, report machine state, and destroy capacity.

Prodigy ships adapters for:

```text
AWS
GCP
Azure
Vultr
```

## What adapters provide

Adapters provide the provider-facing machinery needed to translate Prodigy cluster intent into infrastructure actions:

- provider machine offers and pricing metadata;
- credential and scope handling;
- instance creation and deletion;
- bootstrap metadata and identity attachment;
- provider-native tags, labels, or resource grouping;
- image and machine-type selection;
- cleanup of instances, disks, IPs, templates, NICs, VPCs, and related artifacts where applicable;
- provider-specific error normalization;
- failure reporting or annotation when the provider supports it.

## What adapters require

A provider adapter generally requires:

- a provider scope, such as region, zone, project, subscription, account, or resource group;
- credentials with enough permission to create and remove requested capacity;
- a machine image or image family;
- a machine schema describing desired capacity and budget;
- bootstrap access sufficient for the initial Prodigy install;
- enough provider metadata to tag, discover, and clean up resources from a run.

## Responsibility boundary

Adapters are responsible for translating Prodigy's desired machine state into provider-specific API calls.

Adapters are not responsible for:

- application logic;
- workload health semantics;
- SDK or wire protocol behavior;
- database membership correctness;
- deciding when an application is ready to serve.

Those concerns live in the Prodigy runtime, the workload protocol, and the application itself.

## Provider implementation notes

GCP uses a strict bootstrap/runtime split. Local `mothership` uses a bootstrap auth profile for Compute Engine API calls, while created GCE machines run with an attached user-managed service account. The running GCP brain uses metadata-server tokens; bootstrap GCP tokens must not be persisted into cluster state or copied into first-boot JSON.

Supported GCP bootstrap profile modes:

- `staticMaterial` for an explicit bearer token escape hatch;
- `gcloud`, resolved through `gcloud auth print-access-token`;
- `gcloudImpersonation`, resolved through `gcloud auth print-access-token --impersonate-service-account=...`;
- `externalAccountFile`, resolved through `gcloud auth application-default print-access-token` with `GOOGLE_APPLICATION_CREDENTIALS` pointing at the external-account JSON.

Remote GCP clusters stay schema-driven. `providerCredentialName` names the local bootstrap profile; `gcp.serviceAccountEmail` is required for managed remote GCP schemas with positive budget; `gcp.network` defaults to `global/networks/default`; and `propagateProviderCredentialToProdigy` must remain `false` for the normal attached-service-account path. Managed remote GCP capacity uses Prodigy-managed Compute Engine instance templates, with per-machine create-time overrides for machine type, image, boot disk size, brain label/metadata, and merged startup script.

Vultr uses the shared runtime boot path. Mothership uploads first-boot state with `--boot-json-path`; the node reloads from local TidesDB state; provider credential material lives in replicated runtime state when the Vultr control path needs it.

Vultr auto-provisioning supports `vm` and `bareMetal`. Created machines use a managed private VPC per region with description `prodigy-managed-vpc-<region>` and explicit `/20` headroom. Mixed VM and bare-metal private deployments must attach both sides to that managed VPC.

Vultr bare-metal BGP behavior fetches MD5 and ASN through `GET https://api.vultr.com/v2/account/bgp`, peers with `169.254.1.1` and `2001:19f0:ffff::1` using TTL `2`, uses TCP-MD5, and announces provider-driven communities such as `20473:6000` for iBGP-only reachability. MD5 keys must not be logged and should be zeroized after socket option application.

## Provider-specific docs

| Provider | Runbook |
|---|---|
| AWS | [`runbooks/aws.3brain.cheap.md`](runbooks/aws.3brain.cheap.md) |
| Azure | [`runbooks/azure.3brain.cheap.md`](runbooks/azure.3brain.cheap.md) |
| GCP | [`runbooks/gcp.3brain.cheap.md`](runbooks/gcp.3brain.cheap.md) |
| Vultr | [`runbooks/vultr.3brain.cheap.md`](runbooks/vultr.3brain.cheap.md) |
