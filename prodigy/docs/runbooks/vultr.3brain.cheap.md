# Vultr cheap 3-brain cluster runbook

This runbook creates a cheap 3-machine / 3-brain Prodigy cluster on Vultr, polls it, and removes it.

Validated cheap shape: `vx1-g-2c-8g`
Validated region: `ewr`
Validated image: `os:2284`
Validated auth mode: static Vultr API key in a local ignored environment file

Keep early test runs short. Instances, VPCs, block storage, snapshots, and IP addresses can continue to bill depending on provider behavior.

## Requirements

- Built `mothership` and `prodigy` from this repository.
- Vultr API key.
- `curl` and `jq` for local API checks.
- Bootstrap SSH private key.
- TCP Fast Open enabled on target hosts.

## Required Vultr permissions

Vultr API keys are account-level credentials. Store them carefully, restrict allowed source IPs through Vultr API access controls where possible, and prefer a dedicated account/sub-account for automation.

The Prodigy Vultr path needs API access to manage:

```text
instances
VPCs / private networking
SSH keys or bootstrap metadata used by the run
block storage cleanup checks, when applicable
account metadata required by the provider adapter
```

## Authenticate locally

```bash
export MOTHERSHIP="${MOTHERSHIP:-./mothership}"
export RUN_ID="${RUN_ID:-$(date -u +%Y%m%d-%H%M%S)}"
export BOOTSTRAP_SSH_KEY="REPLACE_PATH_TO_BOOTSTRAP_PRIVATE_KEY"

cat > .env.vultr <<'EOF_VULTR'
export VULTR_API_KEY='REPLACE_ME'
EOF_VULTR

chmod 0600 .env.vultr
source .env.vultr

curl -fsS \
  -H "Authorization: Bearer ${VULTR_API_KEY}" \
  https://api.vultr.com/v2/account | jq .
```

## Create cluster

The Vultr runbook uses propagated static credential material because runtime machines need provider API access for the Vultr control path.

```bash
cat > vultr.cluster.json <<JSON
{
  "name": "vultr-3brain-${RUN_ID}",
  "deploymentMode": "remote",
  "provider": "vultr",
  "architecture": "x86_64",
  "providerScope": "ewr",
  "providerCredentialName": "vultr-3brain-${RUN_ID}-credential",
  "providerCredentialOverride": {
    "name": "vultr-3brain-${RUN_ID}-credential",
    "provider": "vultr",
    "mode": "staticMaterial",
    "material": "${VULTR_API_KEY}",
    "scope": "ewr",
    "allowPropagateToProdigy": true
  },
  "propagateProviderCredentialToProdigy": true,
  "controls": [
    {
      "kind": "unixSocket",
      "path": "/run/prodigy/control.sock"
    }
  ],
  "nBrains": 3,
  "machineSchemas": [
    {
      "schema": "vx1-g-2c-8g",
      "kind": "vm",
      "lifetime": "ondemand",
      "vmImageURI": "os:2284",
      "providerMachineType": "vx1-g-2c-8g",
      "budget": 3
    }
  ],
  "bootstrapSshUser": "root",
  "bootstrapSshPrivateKeyPath": "${BOOTSTRAP_SSH_KEY}",
  "remoteProdigyPath": "/root/prodigy",
  "desiredEnvironment": "vultr"
}
JSON

time "${MOTHERSHIP}" createCluster "$(cat vultr.cluster.json)"
"${MOTHERSHIP}" clusterReport "vultr-3brain-${RUN_ID}"
```

## Remove cluster

```bash
time "${MOTHERSHIP}" removeCluster "vultr-3brain-${RUN_ID}"
```

## Cleanup verification

```bash
python - <<'PY_VULTR_CLEANUP'
import os, urllib.request
key = os.environ['VULTR_API_KEY']
for path in ['instances', 'blocks', 'vpcs']:
    req = urllib.request.Request(
        f'https://api.vultr.com/v2/{path}',
        headers={'Authorization': f'Bearer {key}'},
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        print(path, r.read().decode())
PY_VULTR_CLEANUP
```
