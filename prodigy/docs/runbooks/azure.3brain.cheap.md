# Azure cheap 3-brain cluster runbook

This runbook creates a cheap 3-machine / 3-brain Prodigy cluster on Azure, polls it, and removes it.

Validated practical shape: `Standard_D2als_v6`
Preferred cheaper shape when quota exists: `Standard_B2als_v2`
Validated region: `northcentralus`
Validated auth mode: local `az` CLI bootstrap auth, then cluster-scoped user-assigned managed identity for runtime auth

Keep early test runs short. Public IP addresses, disks, NICs, and resource groups can continue to bill depending on provider behavior.

## Requirements

- Built `mothership` and `prodigy` from this repository.
- Local Azure CLI.
- Authenticated subscription.
- Bootstrap SSH private key.
- TCP Fast Open enabled on target hosts.

## Required Azure permissions

For the low-friction path, use `Owner` or `Contributor` plus enough RBAC administration to assign roles. Plain `Contributor` is not enough because it normally excludes `Microsoft.Authorization/roleAssignments/write`.

For a tighter split:

```text
Contributor or equivalent Compute/Network/Disk permissions on the target resource group
Managed Identity Contributor to create/delete user-assigned managed identities
Managed Identity Operator to assign a user-assigned identity to VMs
Virtual Machine Contributor to create/update VMs that carry that identity
```

`createCluster` preflight checks the target resource group for these ARM actions and reports every missing action:

```text
Microsoft.Authorization/roleAssignments/read
Microsoft.Authorization/roleAssignments/write
Microsoft.Compute/skus/read
Microsoft.Compute/virtualMachines/delete
Microsoft.Compute/virtualMachines/read
Microsoft.Compute/virtualMachines/restart/action
Microsoft.Compute/virtualMachines/write
Microsoft.ManagedIdentity/userAssignedIdentities/read
Microsoft.ManagedIdentity/userAssignedIdentities/write
Microsoft.Network/networkInterfaces/delete
Microsoft.Network/networkInterfaces/read
Microsoft.Network/networkInterfaces/write
Microsoft.Network/networkSecurityGroups/read
Microsoft.Network/networkSecurityGroups/write
Microsoft.Network/publicIPAddresses/delete
Microsoft.Network/publicIPAddresses/read
Microsoft.Network/publicIPAddresses/write
Microsoft.Network/virtualNetworks/read
Microsoft.Network/virtualNetworks/write
Microsoft.Resources/subscriptions/resourceGroups/read
Microsoft.Resources/subscriptions/resourceGroups/write
```

## Authenticate locally

```bash
export MOTHERSHIP="${MOTHERSHIP:-./mothership}"
export RUN_ID="${RUN_ID:-$(date -u +%Y%m%d-%H%M%S)}"
export AZURE_SUBSCRIPTION_ID="REPLACE_AZURE_SUBSCRIPTION_ID"
export AZURE_LOCATION="${AZURE_LOCATION:-northcentralus}"
export RUN_RG="prodigy-${RUN_ID}"
export AZURE_MANAGED_IDENTITY_NAME="prodigy-${RUN_ID}-controller"
export AZURE_MANAGED_IDENTITY_ID="/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${RUN_RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${AZURE_MANAGED_IDENTITY_NAME}"
export AZURE_PROVIDER_SCOPE="subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${RUN_RG}/locations/${AZURE_LOCATION}"
export BOOTSTRAP_SSH_KEY="REPLACE_PATH_TO_BOOTSTRAP_PRIVATE_KEY"

az login
az account set --subscription "${AZURE_SUBSCRIPTION_ID}"
az account show --query '{tenantId:tenantId, subscription:id, user:user.name}' -o json
az group create --name "${RUN_RG}" --location "${AZURE_LOCATION}"
```

## Create cluster

```bash
cat > azure.cluster.json <<JSON
{
  "name": "azure-3brain-${RUN_ID}",
  "deploymentMode": "remote",
  "provider": "azure",
  "providerScope": "${AZURE_PROVIDER_SCOPE}",
  "providerCredentialName": "azure-3brain-${RUN_ID}-credential",
  "providerCredentialOverride": {
    "name": "azure-3brain-${RUN_ID}-credential",
    "provider": "azure",
    "mode": "azureCli",
    "scope": "${AZURE_PROVIDER_SCOPE}",
    "allowPropagateToProdigy": false
  },
  "azure": {
    "managedIdentityResourceID": "${AZURE_MANAGED_IDENTITY_ID}"
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
  "bootstrapSshPrivateKeyPath": "${BOOTSTRAP_SSH_KEY}",
  "remoteProdigyPath": "/root/prodigy",
  "desiredEnvironment": "azure"
}
JSON

time "${MOTHERSHIP}" createCluster "$(cat azure.cluster.json)"
"${MOTHERSHIP}" clusterReport "azure-3brain-${RUN_ID}"
```

## Remove cluster

```bash
time "${MOTHERSHIP}" removeCluster "azure-3brain-${RUN_ID}"
az group delete --name "${RUN_RG}" --yes --no-wait
```

## Cleanup verification

```bash
az resource list \
  --resource-group "${RUN_RG}" \
  --output table
```

If the resource group was deleted asynchronously, poll until it no longer appears:

```bash
az group exists --name "${RUN_RG}"
```
