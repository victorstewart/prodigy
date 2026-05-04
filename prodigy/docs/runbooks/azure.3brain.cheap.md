Azure Cheap 3-Brain Runbook

Scope

- Bring up a fresh remote `3`-machine `3`-brain Prodigy cluster on Azure.
- Keep the VM size at the cheapest viable x86 option that actually fits the current subscription quota.

Cheapest Viable Shape Right Now

- Preferred when quota exists: `Standard_B2als_v2`
- Current practical shape in this subscription: `Standard_D2als_v6`

Why `Standard_D2als_v6`

- As of `2026-03-24`, `northcentralus` shows:
  - `standardBasv2Family = 0`
  - `standardDalv6Family = 10`
- That means `B2als_v2` cannot currently support a `3 x 2-vCPU` run here, while `D2als_v6` can.

Auth Contract

- Preferred local bootstrap auth:
  - provider credential mode `azureCli`
- CLI-free local bootstrap alternative:
  - provider credential mode `staticMaterial`
  - material can be either a raw ARM access token or JSON with `tenantId`, `clientId`, and `clientSecret`
- Runtime auth on created VMs comes from the cluster-scoped user-assigned managed identity.
- Azure CLI is local bootstrap tooling only. Do not ship `az` to the remote Prodigy machines.
- Do not propagate local Azure secrets into runtime state.

Provider Scope

- Azure provider scope must be:
  - `subscriptions/<subscription-id>/resourceGroups/<resource-group>/locations/<location>`

Known Good Region

- `northcentralus`

Known Good Ubuntu Image

- Known working URN from the earlier live proof:
  - `Canonical:ubuntu-24_04-lts:server:24.04.202404230`
- If you want to re-resolve:

```bash
/root/.local/azure-cli-venv/bin/az vm image list \
  --location northcentralus \
  --publisher Canonical \
  --offer ubuntu-24_04-lts \
  --sku server \
  --all \
  --query '[-1].urn' -o tsv
```

Create A Fresh Resource Group

```bash
RUN_RG="prodigy-live-azure-3brain-$(date -u +%Y%m%d-%H%M%S)"
/root/.local/azure-cli-venv/bin/az group create \
  --name "${RUN_RG}" \
  --location northcentralus
```

Cluster JSON Shape

```json
{
  "name": "azure-3brain-run",
  "deploymentMode": "remote",
  "provider": "azure",
  "providerScope": "subscriptions/877d99ab-4469-40eb-9cd1-5e1871ef9169/resourceGroups/RUN_RG/locations/northcentralus",
  "providerCredentialName": "azure-3brain-run-credential",
  "providerCredentialOverride": {
    "name": "azure-3brain-run-credential",
    "provider": "azure",
    "mode": "azureCli",
    "scope": "subscriptions/877d99ab-4469-40eb-9cd1-5e1871ef9169/resourceGroups/RUN_RG/locations/northcentralus",
    "allowPropagateToProdigy": false
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
      "schema": "Standard_D2als_v6",
      "kind": "vm",
      "lifetime": "ondemand",
      "vmImageURI": "Canonical:ubuntu-24_04-lts:server:24.04.202404230",
      "providerMachineType": "Standard_D2als_v6",
      "budget": 3
    }
  ],
  "bootstrapSshUser": "root",
  "bootstrapSshPrivateKeyPath": "/root/.ssh/id_rsa",
  "remoteProdigyPath": "/root/prodigy",
  "desiredEnvironment": "azure"
}
```

How To Run

1. Create a fresh Azure resource group for the run.
2. Use either `azureCli` bootstrap auth from the local host or a `staticMaterial` provider credential with a pre-resolved ARM token or service-principal JSON.
3. Run `mothership createCluster` with the JSON above.
4. Poll `clusterReport` until `topologyMachines: 3` and all brains are healthy.
5. Run `removeCluster`.
6. Delete the whole Azure resource group after the run, even if `removeCluster` succeeded, so any straggler NICs/disks/identities are forced out.

Timing Artifacts To Capture

- `createCluster.timed.out`
- `health.timed.out`
- `clusterReport.final.out`
- `seed.journal`
- follower journals if cluster health stalls

Cleanup

```bash
/root/.local/azure-cli-venv/bin/az group delete \
  --name "${RUN_RG}" \
  --yes \
  --no-wait
```

Current Caveats

- `Standard_B2als_v2` remains blocked by family quota in this subscription.
- The current cheap Azure runbook therefore standardizes on `Standard_D2als_v6` until Basv2 quota exists.
- Fresh Azure seed VMs can briefly race managed-identity readiness. The current repo retries IMDS token acquisition instead of failing immediately on a missing `access_token`.

Latest Measured Result

- Latest healthy `3`-brain live run:
  - [/root/nametag/.mothership-live-azure-3brain-matrix-20260324-070044/createCluster.timed.out](/root/nametag/.mothership-live-azure-3brain-matrix-20260324-070044/createCluster.timed.out)
  - [/root/nametag/.mothership-live-azure-3brain-matrix-20260324-070044/health.timed.out](/root/nametag/.mothership-live-azure-3brain-matrix-20260324-070044/health.timed.out)
  - [/root/nametag/.mothership-live-azure-3brain-matrix-20260324-070044/clusterReport.final.out](/root/nametag/.mothership-live-azure-3brain-matrix-20260324-070044/clusterReport.final.out)
- `createCluster` wall time: `67.23s`
- `clusterReport` healthy convergence: first poll attempt
