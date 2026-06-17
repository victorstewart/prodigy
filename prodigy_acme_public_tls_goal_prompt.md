# /goal: Master-brain-managed public and private TLS lifecycle for wormholes

Implement public TLS certificate issuance, distribution, hot refresh, and
renewal for Prodigy wormholes using Certbot as the ACME engine and Prodigy as
the control plane. In the same lifecycle pass, make Prodigy-managed private
TLS vault factories rotate and redistribute their root/intermediate/leaf
material on the same actual-lifetime schedule.

This is a production control-plane feature. It is not a Certbot timer setup, not
an nginx-style deploy hook, and not a DNS-provider demo. The master brain owns
the lifecycle. Certbot is only the public-ACME protocol subprocess; private
roots, intermediates, and leaf certs are generated and rotated by Prodigy.

## Non-Negotiable Surface Constraint

All code written for this goal must be the tersest, most elegant, most minimal
LOC +/- implementation that is still correct, testable, and production-grade.

- Prefer extending current Prodigy DNS, credential, TLS identity, persistence,
  and credential-delta surfaces over inventing parallel systems.
- Add a new type, helper, command, enum, or file only when it removes real
  complexity or enforces a necessary boundary.
- Keep Certbot integration thin: spawn Certbot, satisfy hooks, import lineage,
  validate material, and distribute `TlsIdentity`.
- Keep DNS-01 TXT handling separate from routable-address DNS leases.
- Put public ACME certs and private Prodigy CA certs under one master-brain
  certificate lifecycle scheduler.
- Do not add provider-specific policy knobs beyond what ACME DNS-01 needs.
- Do not expose DNS provider credentials or ACME account material to
  application containers.
- Every line must earn its weight. End with a density pass that deletes
  redundant helpers, fixtures, wrappers, and compatibility aliases.

## Current Context To Verify First

Start from `origin/main` at or after commit `e04ec4c`:
`Redesign routable prefixes and DNS providers`.

Inspect these files before editing:

- `prodigy/dns.provider.h`
- `prodigy/dns.providers.h`
- `prodigy/dns/provider.http.h`
- `prodigy/dns/cloudflare/cloudflare.h`
- `prodigy/dns/route53/route53.h`
- `prodigy/dns/gcp/gcp.h`
- `prodigy/dns/azure/azure.h`
- `prodigy/dns/vultr/vultr.h`
- `prodigy/types.h`
- `prodigy/brain/brain.h`
- `prodigy/brain/deployments.h`
- `prodigy/persistent.state.h`
- `prodigy/mothership/mothership.cpp`
- `prodigy/mothership/mothership.deployment.plan.helpers.h`
- `prodigy/docs/dns-providers.md`
- SDK credential-bundle and credential-delta code under `prodigy/sdk/`
- Focused tests under `prodigy/dev/tests/prodigy_*wire*`,
  `prodigy_*credential*`, `prodigy_*deployments*`,
  `prodigy_*provider*`, and `prodigy_*dns*` if present.

Current facts to preserve:

- `ProdigyDNSProvider` currently supports DNS-backed wormhole address records:
  `upsert(record, credential)` and `remove(record, credential)`.
- `ProdigyDNSRecordBinding` has `values`, but helper/provider code is currently
  single-value and conflict-oriented. ACME TXT needs exact-value add/remove
  semantics at a shared `_acme-challenge` name.
- Wormhole DNS bindings are modeled as `RoutableResourceLeaseKind::dnsRecord`
  and are coupled to a concrete routable `IPAddress`. ACME DNS-01 records are
  temporary validation records and must not consume routable-resource ownership.
- `CredentialBundle` and `CredentialDelta` already carry `TlsIdentity`.
- `TlsIdentity` already has `name`, `generation`, `notBeforeMs`, `notAfterMs`,
  `certPem`, `keyPem`, `chainPem`, DNS SANs, IP SANs, and tags.
- Existing internal TLS issuance generates per-container private certs from a
  Prodigy vault factory. Public Let's Encrypt certs are different: one issued
  public cert/key must be shared across every container in the deployment that
  owns the wormhole.
- `ApplicationTlsVaultFactory` stores Prodigy-managed private root and
  intermediate material plus `defaultLeafValidityDays`. That material must be
  scheduled lifecycle state, not a static factory blob.
- TLS resumption is already master-brain-owned, persisted in replicated master
  authority state, pushed via credential deltas, and ACKed by containers. Public
  TLS and private TLS factory rotation should follow the same control-plane
  lifecycle shape.

External facts to verify against primary docs:

- Certbot manual DNS hooks receive `CERTBOT_IDENTIFIER` and
  `CERTBOT_VALIDATION`, and cleanup receives `CERTBOT_AUTH_OUTPUT`.
  See: https://eff-certbot.readthedocs.io/en/stable/using.html#pre-and-post-validation-hooks
- Certbot deploy hooks receive `RENEWED_LINEAGE` and `RENEWED_DOMAINS` after a
  successful issuance or renewal.
  See: https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates
- Certbot lineage files live under the selected config dir's `live/<cert-name>`;
  `privkey.pem` is the private key and `fullchain.pem` is leaf plus
  intermediates.
  See: https://eff-certbot.readthedocs.io/en/stable/using.html#where-are-my-certificates
- Let's Encrypt DNS-01 requires a TXT value at
  `_acme-challenge.<identifier>` and permits multiple TXT records at the same
  name, including wildcard plus apex overlap.
  See: https://letsencrypt.org/docs/challenge-types/
- Let's Encrypt recommends renewing 90-day certs every 60 days and is moving
  toward shorter lifetimes; acceptable fallback behavior includes renewal at
  about two thirds of the actual certificate lifetime.
  See: https://letsencrypt.org/docs/faq/ and
  https://letsencrypt.org/2025/12/02/from-90-to-45

## Product Contract

A deployment author can request a public TLS certificate directly on a wormhole:

The cluster must already have one DNS provider and ACME account contact enabled
at cluster creation:

```json
{
  "dnsProvider": "cloudflare",
  "dnsProviderCredentialName": "prod-dns",
  "acme": {
    "accountEmail": "ops@example.com",
    "termsAgreed": true
  }
}
```

When ACME is enabled, Prodigy must bring the ACME engine. Do not assume or
trust a host-installed `certbot`. The supported initial runtime is
`acme.certbotInstall="bundle"` normalized by cluster creation to
`/opt/prodigy/certbot/bin/certbot` with bundled `certbot==5.6.0`.

```json
{
  "wormholes": [
    {
      "name": "api",
      "source": "registeredRoutablePrefix",
      "routablePrefixUUID": "00000000000000000000000000dd4401",
      "externalAddress": "203.0.113.10",
      "externalPort": 443,
      "containerPort": 8443,
      "layer4": "tcp",
      "dns": {
        "provider": "cloudflare",
        "credentialName": "prod-dns",
        "zone": "example.com",
        "name": "api.example.com.",
        "ttl": 300
      },
      "publicTLS": {
        "enabled": true,
        "identityName": "api-public",
        "issuer": "letsencrypt",
        "domains": ["api.example.com"],
        "keyType": "ecdsa",
        "staging": false,
        "renewAfterLifetimePermille": 667
      }
    }
  ]
}
```

Defaults:

- `publicTLS.enabled=false`.
- If `publicTLS=true` or `enabled=true`, `identityName` defaults to the wormhole
  name plus `-public`.
- `domains` defaults to the resolved wormhole DNS name.
- `issuer` is only `letsencrypt` for this goal.
- `keyType` defaults to `ecdsa`.
- `renewAfterLifetimePermille` defaults to `667`.
- DNS-01 TTL defaults to the wormhole DNS TTL or a small bounded ACME default.
- Staging must be easy to enable for tests but must never silently replace a
  production cert.
- Public ACME issuance requires cluster-level `acme.accountEmail` and
  `acme.termsAgreed=true`; never fall back to unsafe no-email registration.

Admission requirements:

- Public TLS requires a DNS-backed wormhole. Reject if the wormhole has no DNS
  name, no DNS provider, no DNS credential, or no zone after resolving
  `dns.bindingName`.
- Reject IP SANs for Let's Encrypt DNS-01 in this goal. DNS-01 validates DNS
  names, not IP addresses.
- Every requested domain must be covered by the configured DNS zone and by the
  credential containment metadata.
- Wildcards are allowed only with DNS-01. Canonicalize `*.example.com` to the
  challenge name `_acme-challenge.example.com`.
- Do not require public certs to be tied to routable-resource DNS leases beyond
  the fact that the wormhole itself must have a stable DNS resource.

Private TLS contract:

- Existing deployment `tls` policy and `ApplicationTlsVaultFactory` users must
  become scheduled lifecycle participants automatically when Prodigy owns the
  factory material.
- A private generated vault factory owns root/intermediate generation,
  validity, next rotation time, and derived leaf generations.
- The deployment author should not need a second declaration to get private leaf
  refresh; declaring private TLS issuance already implies scheduled
  root/intermediate/leaf refresh.
- Imported private CA material is not silently treated as Prodigy-rotatable.
  Either import it as external/manual lifecycle material or provide an explicit
  managed rotation path.
- Private and public TLS identities may coexist on one deployment. Keep identity
  names unique and push only the identities required by each container.

## Best Architecture

Use this ownership model:

```text
deployment plan
  -> wormhole.publicTLS spec
  -> master brain validates DNS/resource/credential containment
  -> master brain creates or resumes a public cert state
  -> master brain runs Certbot at scheduled lifecycle points
  -> Certbot calls Prodigy DNS-01 hooks
  -> master brain imports the Certbot lineage
  -> master brain stores one shared TlsIdentity generation
  -> master brain pushes CredentialDelta.updatedTls to live containers
  -> containers/apps hot-swap TLS identity for new handshakes
```

The systemd Certbot timer must not be the source of truth. Disable or ignore
ambient timers for Prodigy-managed lineages. The master brain should invoke
Certbot itself from a deterministic lifecycle function, with per-cert locks and
cluster-owned Certbot directories under a Prodigy path such as:

```text
/var/lib/prodigy/certbot/<clusterUUID>/config
/var/lib/prodigy/certbot/<clusterUUID>/work
/var/log/prodigy/certbot/<clusterUUID>
```

The master brain may use Certbot deploy hooks as the success callback, but the
hook must re-enter Prodigy over a local control socket. It must not mutate app
servers directly. If simpler and equally safe, the parent master-brain process
may import the lineage immediately after a successful Certbot exit and keep the
deploy hook as a recovery path; do not implement both paths unless tests prove a
real need.

## Required Data Model

Add the smallest state needed to represent public certs.

Suggested shape, adjust to fit local code:

```cpp
class PublicTlsCertificateSpec {
  uint16_t applicationID;
  uint64_t deploymentID;
  String wormholeName;
  String identityName;
  Vector<String> domains;
  String issuer;
  bool staging;
  String dnsProvider;
  String dnsCredentialName;
  String dnsZone;
  uint32_t dnsTTL;
  uint16_t renewAfterLifetimePermille;
};

class PublicTlsCertificateState {
  PublicTlsCertificateSpec spec;
  TlsIdentity identity;
  String certbotCertName;
  String lineagePath;
  uint64_t generation;
  int64_t nextRenewAtMs;
  int64_t lastAttemptMs;
  int64_t lastSuccessMs;
  String lastFailure;
};
```

Prefer reusing `TlsIdentity` for the actual cert/key/chain payload. Add only the
metadata needed for scheduling, reconciliation, and admission.

Persistence rules:

- Public cert private keys are secrets and must follow the existing
  public-snapshot plus secrets-DB split in `persistent.state.h`.
- Public cert state must replicate to follower brains so failover can continue
  renewal and distribution.
- The next master must resume from persisted state, validate the current
  lineage/material, and continue scheduling without issuing duplicate orders.
- Do not persist DNS provider credentials inside the public cert object; refer
  to the existing cluster/app DNS credential by name.

Generation rules:

- Each successfully imported lineage increments the public cert generation.
- `CredentialBundle.bundleGeneration` must reflect the newest relevant public
  TLS generation so containers can order deltas.
- Same deployment/wormhole identity gets the same cert/key in every container.
- Deployment upgrades may retain the cert when the public TLS spec is
  compatible and ownership lineage matches.

## Private TLS Vault Lifecycle

Private Prodigy-managed TLS must use the same scheduler, generation,
persistence, replication, distribution, and ACK model as public ACME certs.
This applies when Prodigy owns the private root/intermediate material used to
generate leaf certificates.

Required behavior:

- Replace split cadence concepts with one actual-lifetime schedule for public
  and private certs. Default to renewal/rotation when about two thirds of the
  current material lifetime has been consumed.
- Hard-cut any private TLS lead-percent surface to the shared
  `renewAfterLifetimePermille` model. Do not leave private TLS on a different
  timing policy.
- Track root, intermediate, and generated leaf `notBefore`/`notAfter` values.
  Compute the next private TLS rotation from the shortest relevant live
  lifetime unless a narrower field earns its existence.
- For generated private vault factories, the master brain mints a new
  root/intermediate generation and new derived leaf identities at the scheduled
  lifecycle point.
- Imported/private authority material can still mint and automatically refresh
  generated leaf identities on the same schedule; only imported root or
  intermediate authority renewal is operator-owned and must fail explicitly
  until refreshed.
- Imported private root/intermediate material must either carry parseable
  validity windows and rotate through the same scheduler, or be explicitly
  marked external/manual. External/manual private CA material must not pretend
  to be Prodigy-managed rotation.
- Private root and intermediate private keys are secrets and stay in the
  existing secrets persistence path.
- Private root/intermediate public certs and derived private leaf identities
  must be redistributed to every affected container through the credential
  bundle/delta path.
- If existing `TlsIdentity.chainPem` can carry the required intermediate/root
  public certs for applications, reuse it. If applications also need a trust
  anchor bundle for peer verification, add the smallest credential-bundle field
  that carries only the required public trust material.
- Keep the previous private CA generation accepted until every live affected
  container ACKs the new material or until the old material approaches expiry.
- New containers must receive the newest private root/intermediate/leaf
  generation in startup `CredentialBundle`.
- Private leaf refresh must not happen only on container restart. Live
  containers must receive new private leaf identities via
  `CredentialDelta.updatedTls`.
- Public ACME certs and private CA-backed certs may share scheduling code, ACK
  bookkeeping, and density-audited helpers, but must keep issuer-specific
  operations separate: Certbot/DNS-01 for public, Prodigy CA generation for
  private.

Tests must cover private TLS too:

- Private generated root/intermediate rotation at two thirds of actual lifetime.
- Private leaf refresh via `CredentialDelta.updatedTls` without container
  restart.
- Startup bundles include the newest private CA and leaf generation.
- Old private CA generation remains accepted during rollout overlap.
- Imported/manual private CA material is rejected from managed rotation unless
  it declares an explicit external/manual lifecycle.

## DNS-01 Provider Contract

Do not bend the existing address-record DNS path into ACME TXT semantics. Add a
minimal exact TXT challenge operation to `ProdigyDNSProvider`, for example:

```cpp
class ProdigyDNSChallengeTXT {
  String provider;
  String credentialName;
  String zone;
  String name;
  String value;
  uint32_t ttl;
};

class ProdigyDNSChallengeHandle {
  String providerRecordID;
  bool createdRecord;
};

virtual bool presentTXT(
    const ProdigyDNSChallengeTXT& challenge,
    const ApiCredential& credential,
    ProdigyDNSChallengeHandle& handle,
    String& failure) = 0;

virtual bool cleanupTXT(
    const ProdigyDNSChallengeTXT& challenge,
    const ProdigyDNSChallengeHandle& handle,
    const ApiCredential& credential,
    String& failure) = 0;
```

Provider semantics:

- Cloudflare and Vultr can usually create one TXT record per validation value
  and delete by returned record ID. If lookup is needed, delete only an exact
  matching TXT value.
- Route53, GCP Cloud DNS, and Azure DNS may be recordset-shaped. Read current
  TXT values, add the exact new value if absent, and write the union. Cleanup
  removes only the exact value and deletes the recordset only if no values
  remain.
- Azure must support TXT recordsets explicitly; do not reuse A/AAAA JSON.
- Route53 TXT quoting/escaping must be correct and round-trip tested.
- Cleanup must be idempotent. Missing exact value is success.
- Same-name/different-value is not conflict for ACME.
- Existing A/AAAA wormhole DNS behavior must remain conflict-safe.
- GCP Cloud DNS and Azure DNS must not rely on a months-long static bearer
  token for unattended ACME renewal. Accept static `material` for tests/manual
  use, but support a credential metadata refresh command that prints a fresh
  provider bearer token for each DNS operation.

Visibility:

- The auth hook must not return until the TXT value is likely visible.
- Prefer a small DNS TXT resolver helper that queries the authoritative path or
  configured recursive resolvers until the exact value appears, bounded by a
  timeout.
- If no robust resolver helper exists yet, wait for a bounded provider-specific
  propagation delay, but isolate that as an implementation detail and document
  it as weaker than authoritative visibility.

Credential containment:

Represent DNS credential scope with explicit metadata and validate it at
admission and hook time:

- `native-exact`: credential may write only listed record FQDNs, including
  `_acme-challenge.<domain>`.
- `native-zone`: credential may write under listed DNS zones.
- `native-account`: broad provider account credential; allow only with explicit
  metadata and cluster-owner intent.
- `webhook-exact`: optional future containment mode where Prodigy calls a narrow
  external hook/API that can only present/cleanup exact challenge records.

Do not deliver any DNS credential to containers.

## Certbot Integration

Provide three thin hook entrypoints, implemented as Prodigy commands or tiny
wrappers around Prodigy's local control socket:

```text
prodigy acme-present-dns-01
prodigy acme-cleanup-dns-01
prodigy acme-import-lineage
```

Hook environment:

- `CERTBOT_IDENTIFIER`: domain being validated.
- `CERTBOT_VALIDATION`: TXT value.
- `CERTBOT_AUTH_OUTPUT`: opaque handle returned by present hook, available to
  cleanup.
- `RENEWED_LINEAGE`: Certbot live directory for import.
- `RENEWED_DOMAINS`: domains on the renewed cert.

The master brain should launch the Prodigy-managed Certbot roughly as:

```sh
/opt/prodigy/certbot/bin/certbot certonly \
  --manual \
  --preferred-challenges dns \
  --manual-auth-hook /usr/lib/prodigy/acme-present-dns-01 \
  --manual-cleanup-hook /usr/lib/prodigy/acme-cleanup-dns-01 \
  --deploy-hook /usr/lib/prodigy/acme-import-lineage \
  --cert-name "$CERT_NAME" \
  --key-type ecdsa \
  --email "$ACME_ACCOUNT_EMAIL" \
  --non-interactive \
  --agree-tos \
  --config-dir "$PRODIGY_CERTBOT_CONFIG_DIR" \
  --work-dir "$PRODIGY_CERTBOT_WORK_DIR" \
  --logs-dir "$PRODIGY_CERTBOT_LOGS_DIR" \
  -d "$DOMAIN_1" \
  -d "$DOMAIN_2"
```

The master brain must inject Prodigy-specific hook context through environment
variables or an on-disk root-owned context file under the Certbot work dir:

```text
PRODIGY_CONTROL_SOCKET
PRODIGY_CLUSTER_UUID
PRODIGY_ACME_CERT_NAME
PRODIGY_ACME_APPLICATION_ID
PRODIGY_ACME_DEPLOYMENT_ID
PRODIGY_ACME_WORMHOLE_NAME
```

Never parse arbitrary untrusted hook input into shell commands. Build argv
arrays directly for Certbot and for Prodigy hook commands.

## Import And Validation

On successful issuance or renewal:

1. Read `$RENEWED_LINEAGE/fullchain.pem`.
2. Read `$RENEWED_LINEAGE/privkey.pem`.
3. Split leaf cert from intermediates.
4. Parse with OpenSSL.
5. Verify the private key matches the leaf certificate.
6. Verify DNS SANs exactly cover the public TLS spec.
7. Reject unexpected IP SANs.
8. Verify `notBefore`/`notAfter` and compute milliseconds using non-deprecated
   OpenSSL APIs.
9. Verify server-auth suitability.
10. Store a new `TlsIdentity` generation with:
    - `certPem`: leaf cert;
    - `keyPem`: private key;
    - `chainPem`: intermediates;
    - `dnsSans`: requested domains;
    - `tags`: at least `public`, `letsencrypt`, and `wormhole:<name>`.
11. Persist and replicate state.
12. Push `CredentialDelta.updatedTls` to every live container in the owning
    deployment.

Existing connections keep running. New handshakes must use the newest
`TlsIdentity` after the application/SDK applies the delta.

## Distribution And ACKs

Reuse `CredentialBundle` and `CredentialDelta.updatedTls` for the wire payload.
For private TLS, the refreshed payload must include the new private leaf
identity and whatever root/intermediate public material the application needs to
serve or trust that identity.

Add the smallest acknowledgement model needed to distinguish these states:

- cert issued but not yet pushed;
- pushed to Neuron;
- delivered to container;
- SDK/app applied or rejected the TLS identity.

If the current `NeuronTopic::refreshContainerCredentials` ACK only carries
resumption results, either extend it to a generic credential apply ACK or add a
small TLS identity apply result. Do not duplicate the whole credential bundle in
the ACK.

The master brain must:

- push the same `TlsIdentity` generation to every live container in the
  deployment;
- push refreshed private leaf identities and private CA public material to every
  affected container on the same schedule;
- include the current public cert in startup `CredentialBundle` for new
  containers;
- include the current private root/intermediate/leaf generation in startup
  `CredentialBundle` for new containers that use private TLS;
- retry stale containers;
- mark a generation stale if containers fail to ACK within a bounded window;
- keep the previous generation available until either all live containers ACK or
  the old cert approaches expiry.

SDKs must continue to expose credential refresh callbacks. Native examples and
docs must show replacing the in-memory TLS context for new handshakes while
leaving existing connections alone.

## Renewal Scheduler

The master brain owns renewal timing for public ACME certificates and private
Prodigy-managed roots/intermediates/leaves.

- Compute renewal time from the actual imported certificate:
  `notBefore + (notAfter - notBefore) * renewAfterLifetimePermille / 1000`.
- Default `renewAfterLifetimePermille=667`.
- Use the same calculation for private generated root/intermediate/leaf
  material, based on the shortest relevant current lifetime.
- Add bounded jitter so clusters do not all renew at identical times.
- Retry failures with bounded exponential backoff and clear operator-visible
  status.
- Do not wait until Certbot's default "close to expiry" threshold if Prodigy's
  schedule says renewal is due.
- Do not rely on system Certbot timers.
- Leave room for future ACME ARI support, but do not implement ARI unless the
  current Certbot version and docs make it cheap and testable.

On master failover:

- follower brains must have enough replicated state to know the current cert,
  current generation, next renewal time, and any failed attempt status;
- the new master must acquire the per-cert lock before invoking Certbot;
- it must not double-issue if another master attempt completed and replicated a
  newer generation.

## Deployment Lifecycle

Admission:

- Validate public TLS at deployment plan parse/admission time.
- Resolve `dns.bindingName` before deriving public cert domains.
- Reject missing DNS provider, DNS credential, DNS zone, DNS name, or invalid
  credential containment.
- Reject public TLS for non-DNS wormholes.
- Reject unsupported issuers.

Upgrade:

- If the same application lineage keeps the same `identityName` and same domain
  set, transfer cert ownership to the new deployment.
- If domains change, issue a new cert before cutting traffic when possible.
- Never let two unrelated live deployments own the same public TLS identity.

Removal:

- Stop scheduling renewals for removed deployments.
- Keep the cert only if another live deployment in the same lineage still owns
  it.
- Do not revoke Let's Encrypt certs on normal deployment removal.
- Clean pending ACME TXT challenges best-effort.

## Tests And Verification

Unit tests:

- Public TLS config parsing defaults and rejections.
- Private TLS vault lifecycle parsing/defaults and conversion away from any
  split cadence.
- Wildcard challenge-name canonicalization.
- Domain/zone containment.
- Credential containment modes.
- Exact TXT add/remove semantics with multiple same-name values.
- Provider-specific TXT JSON/body generation for Cloudflare, Route53, GCP,
  Azure, and Vultr.
- Route53 TXT escaping.
- Azure TXT recordset shape.
- Cert import validation: key matches, SAN exact, wrong key rejected, wrong SAN
  rejected, invalid chain rejected, NotBefore/NotAfter parsed without
  deprecated OpenSSL APIs.
- Renewal time calculation at exactly two thirds of observed lifetime.
- Private root/intermediate/leaf rotation time calculation at exactly two
  thirds of observed lifetime.
- Master failover replication restores public cert state and next renewal time.
- Master failover replication restores private CA state, derived leaf state, and
  next rotation time.
- `CredentialDelta.updatedTls` pushes the same cert/key generation to every
  container in a deployment.
- `CredentialDelta.updatedTls` refreshes private generated leaf identities
  without container restart.
- Startup `CredentialBundle` includes current public cert.
- Startup `CredentialBundle` includes current private root/intermediate/leaf
  generation for private TLS users.
- ACK/stale transitions.

Integration tests:

- Certbot dry-run against Let's Encrypt staging if network and credentials are
  available; otherwise guarded skip with explicit reason.
- Fake DNS provider test that captures present/cleanup hooks and proves two
  simultaneous values at one `_acme-challenge` name survive exact cleanup.
- Dev/test cluster path that requests publicTLS with a fake DNS provider and
  imports a generated local fixture cert without contacting Let's Encrypt.

Safety:

- Do not run host-network/BPF/cgroup/mount tests on the physical host unless the
  harness proves the AGENTS.md isolation checklist.
- Certbot tests must use isolated config/work/log dirs under `.run/`.
- No test code in production files.

Suggested verification commands:

```sh
cmake --build .run/build-prodigy-depos --target \
  mothership prodigy prodigy_wire_unit \
  prodigy_brain_replication_credentials_unit \
  prodigy_deployments_unit prodigy_provider_elastic_address_unit \
  -j$(nproc)

ctest --test-dir .run/build-prodigy-depos \
  -R '^(prodigy_dev_wire_unit|prodigy_brain_replication_credentials_unit|prodigy_dev_deployments_unit|prodigy_provider_elastic_address_unit)$' \
  --output-on-failure -j$(nproc)

git diff --check

rg -n 'X509_cmp_.*time|ASN1_TIME_cmp_.*time_t|certbot[[:space:]]+renew[[:space:]]+-q|systemctl.*cert.*bot|cron.*cert.*bot' prodigy
```

## Implementation Phases

1. Plan and ledger
   - Create or resume `.experiments/acme-public-tls.md`.
   - Create `.tasks/plan-acme-public-tls-implementation.md`.
   - Record exact current branch, commit, build dir, Certbot version, and
     OpenSSL version.

2. Public TLS plan schema
   - Add minimal `publicTLS` config to wormholes.
   - Parse deployment JSON with defaults.
   - Validate DNS-backed domain requirements.
   - Unit-test parser/admission behavior.

3. ACME TXT DNS provider interface
   - Add exact TXT present/cleanup methods.
   - Implement Cloudflare, Route53, GCP, Azure, and Vultr.
   - Keep existing A/AAAA DNS binding behavior unchanged.
   - Unit-test multi-value exact cleanup.

4. Master public cert state
   - Add public cert state and private TLS lifecycle state to master authority
     runtime/persistence with secret split for private keys.
   - Replicate public cert state, private root/intermediate state, derived leaf
     generations, and scheduling metadata to follower brains.
   - Restore on boot/failover.

5. Certbot runner and hooks
   - Add cluster-level ACME account contact config and require TOS agreement.
   - Add master-brain subprocess runner with argv-only execution.
   - Add present/cleanup/import hook commands or wrappers.
   - Use isolated Certbot dirs.
   - Guard staging/live behavior.

6. Import and validation
   - Parse fullchain/key.
   - Validate key/SAN/validity/EKU.
   - Store `TlsIdentity`.
   - Compute next renewal from actual lifetime.
   - Add matching validation helpers for private root/intermediate/leaf
     material and avoid deprecated OpenSSL time APIs.

7. Distribution and ACK
   - Include public certs and private root/intermediate/leaf material in startup
     `CredentialBundle`.
   - Push `CredentialDelta.updatedTls` to live containers for public and
     private leaf refresh.
   - Add minimal TLS identity apply ACK/stale state.
   - Update SDK fixtures/code only as much as the wire contract requires.

8. Renewal lifecycle
   - Add scheduler tick on master brain.
   - Renew public ACME certs and rotate private generated
     root/intermediate/leaf material after two thirds of actual lifetime with
     jitter/backoff.
   - Resume safely after failover.
   - Keep prior generation until rollout is safe.

9. Docs
   - Update DNS provider docs with ACME credential containment.
   - Add public wormhole TLS deployment-plan examples.
   - Document Certbot ownership: master brain runs it; system timers are not the
     control plane.

10. Density and bug audit
   - Remove stale aliases, duplicated parsing, unused helpers, and broad knobs.
   - Run focused build/tests and stale-symbol scans.
   - Fix every deprecation warning in touched scope.

## Acceptance Criteria

- A DNS-backed wormhole can declaratively request a Let's Encrypt public TLS
  cert in deployment JSON.
- The master brain issues the cert through Certbot DNS-01 using Prodigy's DNS
  provider interface.
- ACME TXT challenge records support multiple same-name values and exact-value
  cleanup.
- The imported cert/key is validated before persistence.
- The same public cert/key generation is distributed to every container in the
  owning deployment.
- Prodigy-managed private root/intermediate material and all derived private
  leaf identities rotate on the same two-thirds consumed-lifetime schedule and
  redistribute through the same credential lifecycle.
- Live credential refresh delivers `CredentialDelta.updatedTls`; new handshakes
  can use the new identity without killing existing connections.
- Live private TLS refresh also uses `CredentialDelta.updatedTls`; private leaf
  certs are not refreshed only by restarting containers.
- Renewal is master-brain scheduled at about two thirds of the cert's actual
  lifetime, with retries and failover continuity.
- Private generated CA material keeps previous generations available during
  rollout overlap until ACKed or near expiry.
- DNS credentials and ACME account material never reach application containers.
- Focused unit/integration tests pass or explicitly skip only when external
  credentials/network are unavailable.
- Final diff has no stale Certbot timer ownership, no deprecated OpenSSL calls,
  no test code mixed into production files, and no unearned public surface.
