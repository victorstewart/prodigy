# DNS Providers

Cluster DNS is for wormholes that should be reachable by a stable name instead
of only by a claimed routable IP. When enabled, Prodigy treats the DNS record as
an owned routable resource next to the claimed address: deployments cannot claim
the same DNS identity unless they are the same lineage upgrade, and record
creation/removal is staged with the address lease.

## Enable DNS For A Cluster

Create or reference one provider credential, then select exactly one DNS
provider on the cluster. `dnsProvider` is a cluster-creation choice like the
infrastructure `provider`; it cannot be changed after the cluster exists. Rotate
secrets by updating/replacing the referenced provider credential, not by moving
the cluster to a different DNS provider.

```json
{
  "name": "prod-dns",
  "provider": "cloudflare",
  "mode": "staticMaterial",
  "material": "cloudflare-api-token",
  "allowPropagateToProdigy": true
}
```

```json
{
  "name": "prod",
  "deploymentMode": "remote",
  "provider": "vultr",
  "providerCredentialName": "prod-vultr",
  "dnsProvider": "cloudflare",
  "dnsProviderCredentialName": "prod-dns",
  "acme": {
    "accountEmail": "ops@example.com",
    "termsAgreed": true
  }
}
```

Inline creation uses the same credential shape:

```json
{
  "name": "prod",
  "dnsProvider": "route53",
  "dnsProviderCredentialOverride": {
    "provider": "route53",
    "mode": "staticMaterial",
    "material": "AKIA...:secret[:session-token]",
    "allowPropagateToProdigy": true,
    "metadata": {
      "region": "us-east-1"
    }
  }
}
```

DNS credentials use the existing Mothership provider credential registry:
`createProviderCredential`, `pullProviderCredential`,
`pullProviderCredentials`, and `removeProviderCredential`.

`acme.accountEmail` and `acme.termsAgreed=true` enable master-brain-managed
Let's Encrypt public TLS for DNS-backed wormholes. ACME requires cluster DNS and
is selected at cluster creation; change account contact by creating a new
cluster, not by mutating the existing cluster record.

Certbot runs under Prodigy's control. The generated certonly command uses
isolated cluster config/work/log directories, `--no-directory-hooks`, and these
manual DNS-01 hooks:

- `/usr/lib/prodigy/acme-present-dns-01`
- `/usr/lib/prodigy/acme-cleanup-dns-01`
- `/usr/lib/prodigy/acme-import-lineage`

The installed hook wrappers exec `mothership acme-present-dns-01`,
`mothership acme-cleanup-dns-01`, and `mothership acme-import-lineage`.
Remote bootstrap does not trust a host `certbot`. For ACME-enabled clusters,
the Prodigy bundle carries `prodigy.certbot-5.6.0.wheelhouse.tar.zst`; bootstrap
creates `/opt/prodigy/certbot`, installs `certbot==5.6.0` from that wheelhouse,
verifies the version, and the Brain runs `/opt/prodigy/certbot/bin/certbot`.
The same bundle carries `mothership`; the Brain passes its absolute path as
`PRODIGY_MOTHERSHIP` for hook execution. Prodigy passes the cluster socket,
cert name, application ID, deployment ID, and wormhole name in environment
variables; Certbot supplies
`CERTBOT_IDENTIFIER`, `CERTBOT_VALIDATION`, `RENEWED_LINEAGE`, and
`RENEWED_DOMAINS`. Present/cleanup hooks mutate only the exact DNS-01 TXT
value and never create routable address leases. The lineage import hook reads
`fullchain.pem` and `privkey.pem`, validates the key, DNS SANs, and certificate
lifetime, stores the new TLS generation, and distributes the same public
identity to live and future containers through `CredentialDelta.updatedTls`.
After presenting a DNS-01 TXT value, the hook waits for bounded DNS propagation
before returning. Set credential metadata `acmePropagationDelayMs` only when an
operator needs to override the default TTL-bounded wait, or to `0` for fake DNS
tests.

Prodigy-managed private TLS vaults use the same actual-lifetime renewal
calculation as public certificates. Vault upsert records root, intermediate,
and generated-leaf lifetimes, then computes the next refresh from the earliest
two-thirds-lifetime deadline plus bounded deterministic jitter. Refreshed
private leafs are distributed through the existing `CredentialDelta.updatedTls`
path. Deployment-level `tls.leafValidityDays` overrides shorten that leaf
schedule for the shared vault. Managed private vaults rotate root/intermediate
material when those authorities reach their renewal deadline; imported/manual
vaults still refresh generated leafs automatically, but record a failure when
imported authority material reaches its renewal deadline until the operator
refreshes that material.

The master brain owns renewal. Its periodic lifecycle tick starts Certbot
asynchronously for due public certificates so DNS and import hooks can call
back into Mothership without deadlocking the control loop. The deploy hook must
import the lineage; a Certbot exit without import leaves the certificate state
failed for bounded exponential retry/backoff instead of silently accepting stale
material.
If master ownership changes while Certbot is in flight, the new master first
checks the deterministic Certbot lineage path and imports any completed lineage
before spawning a replacement process.
Public and private TLS identity refreshes are pushed through
`CredentialDelta.updatedTls`; a container's empty credentials-refresh ACK marks
those non-resumption identity generations fresh, and application reports expose
fresh/stale/pending TLS identity container counts.
TLS applications must install refreshed public or private identities for future
handshakes before ACKing; existing connections keep their current TLS context.

## Credential Shape

All runtime DNS credentials must allow Prodigy propagation because Brain applies
records after it claims a routable address.

Public ACME DNS-01 credentials also need explicit containment metadata:

- `metadata.dnsScope`: `native-exact`, `native-zone`, `native-account`, or
  `webhook-exact`
- `metadata.dnsRecords`: comma/space-separated `_acme-challenge...` FQDNs for
  `native-exact` or `webhook-exact`
- `metadata.dnsZones`: comma/space-separated DNS zones for `native-zone`
- `metadata.dnsAccountScopeAccepted=true`: required for `native-account`

The wormhole `dns.zone` remains the provider-specific zone identifier used by
the DNS API; ACME DNS-name containment comes from `dnsRecords` or `dnsZones`.
Use `native-account` only for provider-native credentials already constrained
to the right account or project, and only with the explicit account-scope
marker. Missing containment metadata fails closed.

Cloudflare:
- `provider`: `cloudflare`
- `material`: API token with DNS edit access to the target zone
- Wormhole `dns.zone`: Cloudflare zone ID

Route53:
- `provider`: `route53`
- `material`: AWS credential material accepted by Prodigy AWS signing
- `metadata.region`: optional, defaults to `us-east-1`
- Wormhole `dns.zone`: hosted zone ID, with or without `/hostedzone/`

GCP Cloud DNS:
- `provider`: `gcp-cloud-dns`
- `material`: OAuth bearer access token for Cloud DNS, or bootstrap token when
  `metadata.bearerRefreshCommand` is set
- `metadata.project`: Google Cloud project ID
- `metadata.bearerRefreshCommand`: optional command run by the master brain for
  each DNS operation; it must print a fresh Cloud DNS bearer token
- Wormhole `dns.zone`: Cloud DNS managed zone name or ID

Azure DNS:
- `provider`: `azure-dns`
- `material`: Azure Resource Manager bearer access token, or bootstrap token
  when `metadata.bearerRefreshCommand` is set
- `metadata.subscriptionID`: Azure subscription ID
- `metadata.resourceGroup`: DNS zone resource group
- `metadata.bearerRefreshCommand`: optional command run by the master brain for
  each DNS operation; it must print a fresh ARM bearer token
- Wormhole `dns.zone`: Azure DNS zone name

Vultr DNS:
- `provider`: `vultr-dns`
- `material`: Vultr personal access token
- Wormhole `dns.zone`: Vultr domain name

## Deployment Plan

Wormhole DNS is declarative. The wormhole must claim an address from a
registered routable prefix; then DNS can attach a record to that claimed address:

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
        "zone": "023e105f4ecef8ad9ca31a8372d0c353",
        "name": "api.example.com.",
        "ttl": 300
      },
      "publicTLS": {
        "enabled": true,
        "identityName": "api-public",
        "issuer": "letsencrypt",
        "domains": ["api.example.com"],
        "keyType": "ecdsa",
        "renewAfterLifetimePermille": 667
      }
    }
  ]
}
```

Private managed TLS uses the same scheduler after a Prodigy-owned vault factory
exists for the application:

```json
{
  "applicationID": 42,
  "mode": "generate",
  "scheme": "p256",
  "defaultLeafValidityDays": 15
}
```

```json
{
  "tls": {
    "applicationID": 42,
    "enablePerContainerLeafs": true,
    "leafValidityDays": 15,
    "identityNames": ["inbound_server_tls"],
    "dnsSans": ["api.example.com"]
  },
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
        "zone": "023e105f4ecef8ad9ca31a8372d0c353",
        "name": "api.example.com.",
        "ttl": 300
      },
      "publicTLS": {
        "enabled": true,
        "identityName": "api-public",
        "issuer": "letsencrypt",
        "domains": ["api.example.com"],
        "keyType": "ecdsa"
      }
    }
  ]
}
```

If an operator already created a DNS binding with `upsertDNSBinding`, the
deployment can consume it without restating the IP:

```json
{
  "wormholes": [
    {
      "name": "api",
      "externalPort": 443,
      "containerPort": 8443,
      "layer4": "tcp",
      "dns": {
        "bindingName": "api-binding"
      }
    }
  ]
}
```

Inline `dns` records are deployment-owned and removed with the deployment.
`dns.bindingName` consumes an operator-owned binding until `deleteDNSBinding`
removes it. Use cluster DNS for public API names, customer-facing wormholes, or
any route Prodigy should own. Skip it for internal-only tests, raw-IP testing,
or when DNS is managed outside Prodigy.

## Provider-Backed Issuance Verification

Final ACME verification requires a disposable DNS name under a zone controlled
by one supported provider. Do this against Let's Encrypt staging first by
setting `wormhole.publicTLS.staging=true`.

Required inputs:

- a Prodigy cluster created with `dnsProvider`, `dnsProviderCredentialName`,
  `acme.accountEmail`, and `acme.termsAgreed=true`
- a provider credential whose DNS permissions can edit the target zone
- a deployment built from a real Discombobulator `--kind app` artifact
- a DNS-backed wormhole with `publicTLS.enabled=true`

Remote bootstrap installs Prodigy's hook wrappers at the paths configured for
Certbot, normally:

```text
/usr/lib/prodigy/acme-present-dns-01
/usr/lib/prodigy/acme-cleanup-dns-01
/usr/lib/prodigy/acme-import-lineage
```

The wrappers exec `PRODIGY_MOTHERSHIP`; standalone dev runs must set it to the
intended `mothership` binary. Managed clusters receive the bundled path from
the Brain.

Then deploy the DNS-backed wormhole plan. The master brain should start
Certbot with Prodigy's own due-time policy, the auth hook should publish only
the exact `_acme-challenge` TXT value, the cleanup hook should remove only that
value, and the deploy hook should import `fullchain.pem` plus `privkey.pem`.

Pass criteria:

- `applicationReport` shows the deployment healthy and TLS identity counts with
  no stale containers after ACKs drain
- `pullRoutableResourceLeases` shows the wormhole address and DNS record leases,
  but no ACME TXT lease
- provider DNS no longer contains the temporary `_acme-challenge` TXT value
- the imported public identity generation has non-empty cert/key/chain material
  and a future `nextRenewAtMs`

The guarded CTest `prodigy_dev_acme_staging_smoke` runs the Certbot staging
path when these variables point at a prepared Prodigy public TLS state:

```text
PRODIGY_ACME_STAGING_DOMAIN
PRODIGY_ACME_ACCOUNT_EMAIL
PRODIGY_CLUSTER_UUID
PRODIGY_ACME_CERT_NAME
PRODIGY_ACME_APPLICATION_ID
PRODIGY_ACME_DEPLOYMENT_ID
PRODIGY_ACME_WORMHOLE_NAME
PRODIGY_MOTHERSHIP_SOCKET or PRODIGY_ACME_TARGET
```

If any required external input is missing, the test exits 77 and reports the
missing inputs instead of pretending live issuance was verified.
