# Run in the cloud

Cloud clusters are created through Mothership provider adapters. Each adapter needs a provider scope, credentials, a machine image, a machine schema, and bootstrap access. Mothership owns provider lifecycle and cleanup; workload containers do not receive provider authority by default.

Choose the provider-specific runbook:

- [AWS](../runbooks/aws.3brain.cheap.md)
- [Azure](../runbooks/azure.3brain.cheap.md)
- [GCP](../runbooks/gcp.3brain.cheap.md)
- [Vultr](../runbooks/vultr.3brain.cheap.md)

Runbooks cover prerequisite permissions, create operations, health checks, cleanup, and residual-resource verification. See [IaaS adapters](../iaas-adapters.md) for responsibility boundaries and [Security](../security.md) for credentials and bootstrap identity.
