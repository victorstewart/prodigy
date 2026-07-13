# GCP cheap 3-brain cluster runbook

This runbook creates a cheap 3-machine / 3-brain Prodigy cluster on GCP, polls it, and removes it.

Validated cheap shape: `e2-medium`
Validated zone: `us-central1-a`
Required image contract: Linux kernel 7.0 or newer
Validated auth mode: local `gcloud` bootstrap auth, then attached service account for runtime auth

Keep early test runs short. Instances, disks, static IPs, templates, and VPC resources can continue to bill depending on provider behavior.

## Requirements

- Built `mothership` and `prodigy` from this repository.
- Local `gcloud` CLI.
- Authenticated GCP project.
- Runtime service account.
- Bootstrap SSH private key.
- Machine image that boots Linux kernel 7.0 or newer.
- TCP Fast Open enabled on target hosts.

## Required GCP permissions

Bootstrap identity:

```text
roles/compute.instanceAdmin.v1 on the target project
roles/iam.serviceAccountUser on the runtime service account
```

`createCluster` preflight checks the bootstrap identity for these project permissions and reports every missing permission returned by GCP:

```text
compute.disks.create
compute.disks.delete
compute.instanceTemplates.create
compute.instanceTemplates.delete
compute.instanceTemplates.get
compute.instanceTemplates.useReadOnly
compute.instances.create
compute.instances.delete
compute.instances.get
compute.instances.list
compute.instances.setLabels
compute.instances.setMetadata
compute.instances.setServiceAccount
compute.machineTypes.get
compute.networks.get
compute.subnetworks.get
compute.subnetworks.use
compute.subnetworks.useExternalIp
compute.zones.get
```

It also checks `iam.serviceAccounts.actAs` on `gcp.serviceAccountEmail`.

Runtime service account:

```text
Compute permissions required for Prodigy scale-out, replacement, and cleanup in the target project
```

For the validated live-run model, the runtime service account is created ahead of time and attached to the Prodigy machines.

## Authenticate locally

```bash
export MOTHERSHIP="${MOTHERSHIP:-./mothership}"
export RUN_ID="${RUN_ID:-$(date -u +%Y%m%d-%H%M%S)}"
export GCP_PROJECT="REPLACE_GCP_PROJECT"
export GCP_ZONE="${GCP_ZONE:-us-central1-a}"
export GCP_RUNTIME_SERVICE_ACCOUNT="REPLACE_RUNTIME_SERVICE_ACCOUNT@${GCP_PROJECT}.iam.gserviceaccount.com"
export GCP_PROVIDER_SCOPE="projects/${GCP_PROJECT}/zones/${GCP_ZONE}"
export BOOTSTRAP_SSH_KEY="REPLACE_PATH_TO_BOOTSTRAP_PRIVATE_KEY"

gcloud auth login
gcloud config set project "${GCP_PROJECT}"
gcloud config set compute/zone "${GCP_ZONE}"
gcloud auth list
gcloud iam service-accounts list --project "${GCP_PROJECT}"
```

## Create cluster

```bash
cat > gcp.cluster.json <<JSON
{
  "name": "gcp-3brain-${RUN_ID}",
  "deploymentMode": "remote",
  "provider": "gcp",
  "providerScope": "${GCP_PROVIDER_SCOPE}",
  "providerCredentialName": "gcp-3brain-${RUN_ID}-credential",
  "providerCredentialOverride": {
    "name": "gcp-3brain-${RUN_ID}-credential",
    "provider": "gcp",
    "mode": "gcloud",
    "scope": "${GCP_PROVIDER_SCOPE}",
    "allowPropagateToProdigy": false
  },
  "gcp": {
    "serviceAccountEmail": "${GCP_RUNTIME_SERVICE_ACCOUNT}",
    "network": "global/networks/default",
    "subnetwork": ""
  },
  "controls": [
    {
      "kind": "unixSocket",
      "path": "/run/prodigy/control.sock"
    }
  ],
  "architecture": "x86_64",
  "nBrains": 3,
  "machineSchemas": [
    {
      "schema": "e2-medium",
      "kind": "vm",
      "lifetime": "ondemand",
      "vmImageURI": "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64",
      "providerMachineType": "e2-medium",
      "budget": 3
    }
  ],
  "bootstrapSshUser": "root",
  "bootstrapSshPrivateKeyPath": "${BOOTSTRAP_SSH_KEY}",
  "remoteProdigyPath": "/root/prodigy",
  "desiredEnvironment": "gcp"
}
JSON

time "${MOTHERSHIP}" createCluster "$(cat gcp.cluster.json)"
"${MOTHERSHIP}" clusterReport "gcp-3brain-${RUN_ID}"
```

## Remove cluster

```bash
time "${MOTHERSHIP}" removeCluster "gcp-3brain-${RUN_ID}"
```

## Cleanup verification

If a run is interrupted, inspect and remove leftover provider artifacts such as instance templates, disks, static IPs, or VPC objects created for the run.

```bash
gcloud compute instances list --project "${GCP_PROJECT}" --filter="name~gcp-3brain-${RUN_ID}"
gcloud compute disks list --project "${GCP_PROJECT}" --filter="name~gcp-3brain-${RUN_ID}"
gcloud compute instance-templates list --project "${GCP_PROJECT}" --filter="name~gcp-3brain-${RUN_ID}"
gcloud compute addresses list --project "${GCP_PROJECT}" --filter="name~gcp-3brain-${RUN_ID}"
```
