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
  "dnsProviderCredentialName": "prod-dns"
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

## Credential Shape

All runtime DNS credentials must allow Prodigy propagation because Brain applies
records after it claims a routable address.

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
- `material`: OAuth bearer access token for Cloud DNS
- `metadata.project`: Google Cloud project ID
- Wormhole `dns.zone`: Cloud DNS managed zone name or ID

Azure DNS:
- `provider`: `azure-dns`
- `material`: Azure Resource Manager bearer access token
- `metadata.subscriptionID`: Azure subscription ID
- `metadata.resourceGroup`: DNS zone resource group
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
