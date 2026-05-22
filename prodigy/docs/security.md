# Security model

Prodigy minimizes credential spread and keeps bootstrap authority explicit.

## Core rules

- Remote cluster control is SSH key-only.
- Local provider credentials are used for bootstrap.
- Runtime machines should use provider-native identity where available.
- Application containers receive only the credentials explicitly delivered through the runtime protocol.
- Provider adapters should operate with the least authority needed to create, repair, and destroy machines in their cluster scope.

## Provider identity model

| Provider | Runtime identity model |
|---|---|
| AWS | EC2 instance profiles / IMDS rather than long-lived static AWS keys. |
| Azure | Cluster-scoped user-assigned managed identity rather than copied local Azure credentials. |
| GCP | Attached service account rather than propagated local `gcloud` user credential. |
| Vultr | Static API-key material; keep it local, ignored, restricted by source IP where possible, and scoped to dedicated automation use. |

## Bootstrap credentials

Bootstrap credentials should be treated as operator credentials, not application credentials. They are used to create provider resources, attach machine identity, install Prodigy, and form the initial cluster.

After bootstrap, runtime machines should rely on provider-native identity where the provider supports it.

## Application credentials

Application containers should receive only credentials explicitly delivered through the runtime protocol. The credential set should match the application service identity and should not inherit broad provider bootstrap authority by default.

## Bundle update signatures

Prodigy update bundles are intended to be signed with Ed25519 before in-place rollout. CI should produce the bundle plus a raw 64-byte `prodigy.sig`; the master Brain should attach the bundle and signature when pushing to peers; receivers should verify the signature against a pinned public key before writing and transitioning to the new bundle.

The pinned-key path is not currently wired into the shipping Prodigy build. Do not treat bundle-signature verification as active until that verification path is connected to the update flow.

Signature verification still matters when the transport is private: VPNs and SSH protect transport and identity, but signatures also catch insider mistakes and payload corruption before a fleet update.

## SSH access hardening

Managed remote cluster control is SSH key-only today. Production hardening paths include:

- OpenSSH CA-signed user certificates with short lifetimes and constrained sudoers entries for lifecycle commands.
- Provider command-session systems such as GCP OS Login or AWS SSM-style APIs, so lifecycle work can use centralized IAM and audit logs instead of inbound SSH.

## Cleanup and residual resources

Provider cleanup should remove or account for:

- instances;
- volumes/disks;
- templates;
- NICs;
- IP addresses;
- VPCs/VNets/subnets;
- resource groups or tags used for run ownership.

Runbooks should record post-cleanup checks for residual resources.
