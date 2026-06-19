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

## Mothership tunnel-provider boundary

Cluster records may choose `mothershipConnectivity.kind=ssh` or `tunnelProvider`. Omitted connectivity is SSH. A `tunnelProvider` cluster never falls back to SSH; if the tunnel is unavailable, commands fail closed until the tunnel spec is corrected through an available control path or out-of-band host access.

A tunnel-provider artifact must carry the `PRODIGY-DISCOMBOBULATOR-MOTHERSHIP-TUNNEL-PROVIDER` contract header. Normal app-container blobs are rejected for this role. Create-time preflight hashes and locally stages the verified blob by system-container kind and digest before normal cluster standup. Seed configure uploads that verified blob to Brain, which stores and peer-replicates it through the typed `ContainerStore` system-artifact path; repeated configure/apply of the same digest is idempotent. The system path revalidates kind, digest, size, and contract before returning bytes for launch. The persisted cluster record stores artifact digest, size, dial config, one TCP egress endpoint, and bounded resource shape; it must not store the local create-time blob path.

Tunnel-provider cluster metadata must also include generated gateway client auth material for the external `mothership` process: a dedicated root certificate, client certificate, and client private key. Create-time seed configure sends the gateway-side root/server keys to Brain through a separate auth topic, and Brain persistent state stores those keys through the secrets DB, separate from application credentials, provider credentials, and transport TLS. Brain stores the runtime connectivity shape in a separate secret-free `mothership_connectivity` record; client auth private keys stay in the local cluster registry, not in that runtime record. Runtime reconciliation refuses to advance toward provider launch until Brain has configured gateway auth.

Tunnel-provider hardening is fixed by the runtime launch path. It rejects application credentials, provider credentials, TLS vault material, mesh identity, wormholes, whiteholes, overlay attachment, host networking, pairings, admin capabilities, raw sockets, mutable mounts, host-observation syscalls, the normal Neuron SDK socket, and raw host mothership socket mounts. It requires private namespaces, read-only rootfs, tmpfs writable state, minimal `/dev`, no-new-privileges, an empty capability set, host-control seccomp denial, spec-derived resource limits, gateway-mediated socket access, allowlist-only egress, private/local/metadata egress denial, and arbitrary-DNS denial. The raw mothership Unix socket is mediated by gateway authentication before control-plane bytes pass through. Ordinary app fragment allocation excludes the reserved tunnel-provider fragment, and active-master state upload treats that fragment as system state. The concrete gateway listener restricts the socket inode and accepted peer credentials to the provider's mapped UID.

Tunnel egress is allowlist-only. Registry validation accepts only a public literal IPv4 TCP endpoint and rejects private, local, metadata, multicast, reserved, IPv6, and hostname egress targets. Runtime launch loads that exact tuple into the container egress BPF map. The egress router drops all allowlist-only traffic that misses that tuple, including arbitrary DNS, private/local/cluster destinations, wrong ports, and wrong protocols.

Cluster report may show tunnel connectivity kind, runtime booleans, generation, and last failure. Tunnel health means the gateway authenticated a Prodigy client and opened the raw control socket; it is not sourced from the ordinary app SDK health path. Reports must not show tunnel private keys, certificates, client auth material, gateway server keys, provider credentials, artifact digests, or application credentials.

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
