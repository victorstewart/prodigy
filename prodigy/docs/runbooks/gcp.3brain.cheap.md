GCP Cheap 3-Brain Runbook

Scope

- Bring up a fresh remote `3`-machine `3`-brain Prodigy cluster on GCP.
- Use the cheapest currently requested x86 machine type for this repo’s live GCP work.

Cheapest Requested Shape

- `e2-medium`

Auth Contract

- Use local `gcloud` bootstrap auth.
- Provider credential mode:
  - `gcloud`
- Runtime auth on created VMs comes from the attached service account.
- Do not propagate local bootstrap credentials into runtime state.

Known Good Project And Zone

- Project:
  - `prodigy-test-260321-0240-1bcc`
- Zone:
  - `us-central1-a`

Known Runtime Service Account

- `prodigy-machine@prodigy-test-260321-0240-1bcc.iam.gserviceaccount.com`

Recommended Image URI

- `projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64`

Bootstrap Precheck

```bash
gcloud auth list
gcloud config set project prodigy-test-260321-0240-1bcc
gcloud config set compute/zone us-central1-a
gcloud iam service-accounts list --project=prodigy-test-260321-0240-1bcc
```

Cluster JSON Shape

```json
{
  "name": "gcp-3brain-run",
  "deploymentMode": "remote",
  "provider": "gcp",
  "providerScope": "projects/prodigy-test-260321-0240-1bcc/zones/us-central1-a",
  "providerCredentialName": "gcp-3brain-run-credential",
  "providerCredentialOverride": {
    "name": "gcp-3brain-run-credential",
    "provider": "gcp",
    "mode": "gcloud",
    "scope": "projects/prodigy-test-260321-0240-1bcc/zones/us-central1-a",
    "allowPropagateToProdigy": false
  },
  "gcp": {
    "serviceAccountEmail": "prodigy-machine@prodigy-test-260321-0240-1bcc.iam.gserviceaccount.com",
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
  "bootstrapSshPrivateKeyPath": "/root/.ssh/id_rsa",
  "remoteProdigyPath": "/root/prodigy",
  "desiredEnvironment": "gcp"
}
```

How To Run

1. Reauth `gcloud` if necessary.
2. Run `mothership createCluster` with the inline `gcloud` credential override above.
3. Poll `clusterReport` until all `3` brains are healthy.
4. Run `removeCluster`.
5. Delete any instance templates created by the run that `removeCluster` does not clean up automatically.

Timing Artifacts To Capture

- `createCluster.timed.out`
- `health.timed.out`
- `clusterReport.final.out`
- `seed.journal`
- child journals if scale-out stalls

Cleanup Commands

```bash
gcloud compute instances list --project=prodigy-test-260321-0240-1bcc
gcloud compute instance-templates list --project=prodigy-test-260321-0240-1bcc
```

Current Caveat

- As of `2026-03-24`, GCP’s Ubuntu 24.04 x86 family string for this runbook is `ubuntu-2404-lts-amd64`; the older `ubuntu-2404-lts` family path is stale and fails before provider launch.
- The remaining GCP work is now optimization and A/B comparison, not correctness. The `20260324-100700` rerun reached healthy on the first `clusterReport` attempt and completed `removeCluster` successfully.

Latest Measured Checkpoint

- Latest healthy run:
  - [/root/nametag/.mothership-live-gcp-3brain-matrix-20260324-100700/createCluster.timed.out](/root/nametag/.mothership-live-gcp-3brain-matrix-20260324-100700/createCluster.timed.out)
  - [/root/nametag/.mothership-live-gcp-3brain-matrix-20260324-100700/createCluster.out](/root/nametag/.mothership-live-gcp-3brain-matrix-20260324-100700/createCluster.out)
  - [/root/nametag/.mothership-live-gcp-3brain-matrix-20260324-100700/health.timed.out](/root/nametag/.mothership-live-gcp-3brain-matrix-20260324-100700/health.timed.out)
  - [/root/nametag/.mothership-live-gcp-3brain-matrix-20260324-100700/clusterReport.final.out](/root/nametag/.mothership-live-gcp-3brain-matrix-20260324-100700/clusterReport.final.out)
  - [/root/nametag/.mothership-live-gcp-3brain-matrix-20260324-100700/removeCluster.timed.out](/root/nametag/.mothership-live-gcp-3brain-matrix-20260324-100700/removeCluster.timed.out)
- First `upsertMachineSchemas` request envelope: about `59.322s`
- First healthy `clusterReport` attempt: about `2.430s`
- Cleanup result:
  - `removeCluster success=1 removed=1 ... destroyedCreatedCloudMachines=3`
  - direct post-run GCP recheck showed zero remaining instances and zero remaining Prodigy instance templates
