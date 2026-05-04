GCP IaaS Integration

Overview

Prodigy on GCP now uses a strict bootstrap/runtime split:

- The local `mothership` process uses a GCP bootstrap auth profile to call the
  Compute Engine API and create the first VM.
- Created GCE VMs run with an attached user-managed service account.
- The running Prodigy brain on GCE uses metadata-server tokens for the rest of
  its lifetime.
- No bootstrap GCP token is persisted into cluster state or copied into the
  first-boot JSON.

Bootstrap Auth

Mothership stores named provider auth profiles through
`createProviderCredential [json]`.

For GCP, the supported profile modes are:

- `staticMaterial`
  - existing escape hatch for an explicit bearer token
- `gcloud`
  - resolves a short-lived bootstrap token by running
    `gcloud auth print-access-token`
- `gcloudImpersonation`
  - resolves a short-lived bootstrap token by running
    `gcloud auth print-access-token --impersonate-service-account=...`
- `externalAccountFile`
  - resolves a short-lived bootstrap token by running
    `gcloud auth application-default print-access-token` with
    `GOOGLE_APPLICATION_CREDENTIALS` pointed at the external-account JSON

For refreshable GCP modes, Mothership validates the profile once when it
builds the local provisioning runtime environment, then reruns the same local
auth command on demand before later provider API use. If that refresh fails,
the command fails clearly and tells the operator to refresh or reauthenticate
the local bootstrap profile.

Example bootstrap auth profiles:

```json
{
  "name": "gcp-prod-bootstrap",
  "provider": "gcp",
  "mode": "gcloud",
  "scope": "projects/example/zones/us-central1-a",
  "allowPropagateToProdigy": false
}
```

```json
{
  "name": "gcp-prod-bootstrap",
  "provider": "gcp",
  "mode": "gcloudImpersonation",
  "impersonateServiceAccount": "bootstrap@example.iam.gserviceaccount.com",
  "scope": "projects/example/zones/us-central1-a",
  "allowPropagateToProdigy": false
}
```

```json
{
  "name": "gcp-prod-bootstrap",
  "provider": "gcp",
  "mode": "externalAccountFile",
  "credentialPath": "/etc/prodigy/gcp-external-account.json",
  "scope": "projects/example/zones/us-central1-a",
  "allowPropagateToProdigy": false
}
```

Cluster Contract

Remote GCP clusters stay schema-driven. `machineConfigs` are gone.

The GCP-specific cluster fields are:

- `provider="gcp"`
- `providerCredentialName`
  - names the local Mothership bootstrap auth profile
- `gcp.serviceAccountEmail`
  - required for managed remote GCP schemas with `budget > 0`
- optional `gcp.network`
  - defaults to `global/networks/default`
- optional `gcp.subnetwork`
- `propagateProviderCredentialToProdigy`
  - must remain `false` for the normal GCP attached-service-account path

Example `createCluster` shape:

```json
{
  "name": "gcp-prod",
  "deploymentMode": "remote",
  "provider": "gcp",
  "providerScope": "projects/example/zones/us-central1-a",
  "providerCredentialName": "gcp-prod-bootstrap",
  "gcp": {
    "serviceAccountEmail": "prodigy-brain@example.iam.gserviceaccount.com",
    "network": "global/networks/default",
    "subnetwork": ""
  },
  "controls": [
    {
      "kind": "unixSocket",
      "path": "/run/prodigy/control.sock"
    }
  ],
  "nBrains": 3,
  "bootstrapSshPrivateKeyPath": "/root/.ssh/id_ed25519",
  "remoteProdigyPath": "/root/prodigy",
  "desiredEnvironment": "gcp",
  "machineSchemas": [
    {
      "schema": "gcp-brain-vm",
      "kind": "vm",
      "lifetime": "ondemand",
      "vmImageURI": "projects/example/global/images/prodigy-brain",
      "providerMachineType": "e2-medium",
      "budget": 3
    },
    {
      "schema": "gcp-worker-vm",
      "kind": "vm",
      "lifetime": "spot",
      "vmImageURI": "projects/example/global/images/prodigy-worker",
      "providerMachineType": "e2-medium",
      "budget": 20
    }
  ]
}
```

Managed Template Model

For managed remote GCP capacity, Mothership creates and maintains the required
Compute Engine instance templates itself.

Rules:

- this cut uses one shared standard template and one shared spot template per
  cluster
- operators do not need to precreate separate brain and worker templates
- positive-budget managed GCP schemas must share that template contract
- template names are auto-generated from the cluster UUID when omitted

The shared managed template is the authoritative source for:

- attached service account
- OAuth scope
- network and subnetwork
- tags
- other persistent GCE template properties

Per-machine create-time overrides still come from the schema:

- `providerMachineType`
- `vmImageURI`
- boot disk size
- `brain=true|false` label and metadata
- merged `startup-script` when bootstrap SSH is configured

Runtime Auth On The VM

The running GCP brain does not use the bootstrap profile.

Runtime behavior stays:

- managed GCP runtime strips any bootstrap credential material before it
  reaches Prodigy
- the running brain fetches a short-lived token from the metadata server

Metadata endpoints used on GCE:

- instance ID:
  `http://metadata.google.internal/computeMetadata/v1/instance/id`
- zone:
  `http://metadata.google.internal/computeMetadata/v1/instance/zone`
- service-account token:
  `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`

All metadata requests must include:

- `Metadata-Flavor: Google`

Operator Notes

- `providerCredentialName` is now best understood as a bootstrap auth profile,
  not necessarily a stored raw secret.
- Managed remote GCP clusters must not set
  `propagateProviderCredentialToProdigy=true`.
- Brain machines are intended to keep the privileged attached service account.
  Normal workload scheduling excludes `isBrain` machines by default.

Current Status

- `GcpNeuronIaaS` self-discovers from the metadata server.
- `GcpBrainIaaS` creates VMs from instance templates and applies per-create
  image, machine-type, and `brain` overrides.
- Mothership resolves GCP bootstrap tokens locally from the configured auth
  profile, refreshes them on demand for later local provider API calls, and
  does not persist them into runtime boot state.
