Vultr Cheap 3-Brain Runbook

Scope

- Bring up a fresh remote `3`-machine `3`-brain Prodigy cluster on Vultr.
- Use the cheapest validated VM shape for this repo’s Vultr live work.

Cheapest Validated Shape

- `vx1-g-2c-8g`

Auth Contract

- Vultr automation is API-key based.
- In this repo, Vultr uses propagated static credential material.
- Keep the key only in a local ignored shell file such as `.env.vultr`.

Expected Local Credential File

```bash
export VULTR_API_KEY='REPLACE_ME'
```

Important Networking Contract

- VM-to-VM private networking on Vultr requires VPC attachment.
- If the deployment mixes VMs and bare metal, both sides must be attached to the same VPC for private east-west communication.
- Size the VPC subnet with headroom for the largest cluster you might ever place there.

Known Good Image And Scope

- Region:
  - `ewr`
- Image:
  - `os:2284`

Cluster JSON Shape

```json
{
  "name": "vultr-3brain-run",
  "deploymentMode": "remote",
  "provider": "vultr",
  "architecture": "x86_64",
  "providerScope": "ewr",
  "providerCredentialName": "vultr-3brain-run-credential",
  "providerCredentialOverride": {
    "name": "vultr-3brain-run-credential",
    "provider": "vultr",
    "mode": "staticMaterial",
    "material": "REPLACE_WITH_VULTR_API_KEY",
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
  "bootstrapSshPrivateKeyPath": "/root/.ssh/id_rsa",
  "remoteProdigyPath": "/root/prodigy",
  "desiredEnvironment": "vultr"
}
```

How To Run

1. `source .env.vultr`
2. Confirm the account is clean before launch:
   - `instances=0`
   - `blocks=0`
   - `vpcs=0`
3. Run `mothership createCluster` with the JSON above.
4. Poll `clusterReport` until all `3` brains are healthy.
5. Run `removeCluster`.
6. Recheck `instances`, `blocks`, and `vpcs`.

Timing Artifacts To Capture

- `createCluster.timed.out`
- `health.timed.out`
- `clusterReport.final.out`
- `seed.journal`
- follower journals if scale-out stalls

Cleanup Checks

```bash
python - <<'PY'
import os, json, urllib.request
key = os.environ['VULTR_API_KEY']
for path in ['instances', 'blocks', 'vpcs']:
   req = urllib.request.Request(
      f'https://api.vultr.com/v2/{path}',
      headers={'Authorization': f'Bearer {key}'},
   )
   with urllib.request.urlopen(req, timeout=20) as r:
      print(path, r.read().decode())
PY
```

Current Caveats

- Vultr VPC creation has intermittently failed with a generic `vultr vpc create failed` error even when the equivalent direct API call succeeds.
- If that recurs, inspect the run artifact and confirm whether precreating the expected managed VPC is still required as a temporary workaround.
- Older healthy runs exposed a teardown bug where `removeCluster` hung and left a VM plus the managed VPC behind.
- The latest rerun below completed `removeCluster` successfully and ended with a direct clean Vultr API recheck, but keep the final cleanup recheck in the loop because this provider has been flaky.

Latest Measured Result

- Latest healthy `3`-brain live run:
  - [/root/nametag/.mothership-live-vultr-3brain-stream-20260326-170053/createCluster.timed.out](/root/nametag/.mothership-live-vultr-3brain-stream-20260326-170053/createCluster.timed.out)
  - [/root/nametag/.mothership-live-vultr-3brain-stream-20260326-170053/health.timed.out](/root/nametag/.mothership-live-vultr-3brain-stream-20260326-170053/health.timed.out)
  - [/root/nametag/.mothership-live-vultr-3brain-stream-20260326-170053/clusterReport.final.out](/root/nametag/.mothership-live-vultr-3brain-stream-20260326-170053/clusterReport.final.out)
  - [/root/nametag/.mothership-live-vultr-3brain-stream-20260326-170053/removeCluster.timed.out](/root/nametag/.mothership-live-vultr-3brain-stream-20260326-170053/removeCluster.timed.out)
  - [/root/nametag/.mothership-live-vultr-3brain-stream-20260326-170053/postCleanup.final.instances.json](/root/nametag/.mothership-live-vultr-3brain-stream-20260326-170053/postCleanup.final.instances.json)
  - [/root/nametag/.mothership-live-vultr-3brain-stream-20260326-170053/postCleanup.final.blocks.json](/root/nametag/.mothership-live-vultr-3brain-stream-20260326-170053/postCleanup.final.blocks.json)
  - [/root/nametag/.mothership-live-vultr-3brain-stream-20260326-170053/postCleanup.final.vpcs.json](/root/nametag/.mothership-live-vultr-3brain-stream-20260326-170053/postCleanup.final.vpcs.json)
- `createCluster` wall time: about `108.733s`
- `clusterReport` healthy convergence: first poll attempt, about `4.069s` after `createCluster` returned
- `removeCluster`: about `73.161s`
- This run still required precreating the expected managed VPC before `createCluster`.
