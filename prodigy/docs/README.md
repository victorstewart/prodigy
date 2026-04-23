Prodigy Runtime and Ops Notes

This document captures the active Prodigy startup contract, control-socket behavior, and the Mothership log streaming protocol.

<!-- Keep the cheap 3-brain cloud runbooks in sync with live validation work.
     Reuse these files before starting a new AWS/Azure/GCP/Vultr bring-up wave:
     docs/runbooks/aws.3brain.cheap.md
     docs/runbooks/azure.3brain.cheap.md
     docs/runbooks/gcp.3brain.cheap.md
     docs/runbooks/vultr.3brain.cheap.md -->

Cloud Runbooks

- Cheap `3`-brain `3`-machine live recipes now live in:
  - [/root/prodigy/prodigy/docs/runbooks/aws.3brain.cheap.md](/root/prodigy/prodigy/docs/runbooks/aws.3brain.cheap.md)
  - [/root/prodigy/prodigy/docs/runbooks/azure.3brain.cheap.md](/root/prodigy/prodigy/docs/runbooks/azure.3brain.cheap.md)
  - [/root/prodigy/prodigy/docs/runbooks/gcp.3brain.cheap.md](/root/prodigy/prodigy/docs/runbooks/gcp.3brain.cheap.md)
  - [/root/prodigy/prodigy/docs/runbooks/vultr.3brain.cheap.md](/root/prodigy/prodigy/docs/runbooks/vultr.3brain.cheap.md)

Networking

- Packet-size overhead and MTU tuning notes for external ingress, cross-machine overlay transit, and container internet egress now live in:
  - [/root/prodigy/prodigy/docs/network-packet-budgets.md](/root/prodigy/prodigy/docs/network-packet-budgets.md)

Persistent Fake Clusters

- For a persistent local fake cluster or a persistent fake cluster hosted on a remote SSH machine, prefer `mothership createCluster` with `deploymentMode: "test"`.
- Manual sample payloads live in [manual/test/README.md](/root/prodigy/prodigy/dev/tests/manual/test/README.md).
- The raw [prodigy_dev_netns_harness.sh](/root/prodigy/prodigy/dev/tests/prodigy_dev_netns_harness.sh) entrypoint is now the low-level runner underneath that cluster type.
- Invoke the raw harness directly only for low-level debugging, isolated harness development, or the existing fault/deployment matrix scripts that intentionally exercise harness-only behavior.

Startup State

- First boot is seeded by `--boot-json=<inline-json>` or `--boot-json-path=<path>`.
- `--persist-only` can be combined with either boot-state flag to seed or refresh local state without starting the full runtime.
- Later boots load from the local TidesDB state database.
- The persistent state DB defaults to `/var/lib/prodigy/state`.
- Optional local override for testing: `PRODIGY_STATE_DB`.
- The first-boot JSON requires:
  - `bootstrapPeers`
  - `nodeRole`
  - `controlSocketPath`
- Optional first-boot JSON:
  - `runtimeEnvironment`
    - `kind`
    - `providerScope`
    - `providerCredentialMaterial`
      Managed cloud runtime strips this before Prodigy keeps boot state.

Neuron Environment Overrides

- `--netdev=...`: Optional network device override. If unset, Prodigy autodetects the primary non-loopback interface from the routing table/interface addresses.
- PRODIGY_MOTHERSHIP_SOCKET: internal process override for the control socket path. `prodigy` seeds this from stored boot state before Brain startup.

Mothership Control Transport

- Local control: direct unix socket to the control path stored in local Prodigy state.
- Remote control: SSH to a managed cluster machine, then streamlocal into the configured Prodigy unix socket.
- Mothership’s remote bootstrap path uploads the first-boot seed as a file and invokes Prodigy with `--boot-json-path`.

Log Streaming Protocol (Brain ↔ Mothership)

- MothershipTopic::pullContainerLogs and stopContainerLogs control server-side log streaming.
- Brain sends frames via MothershipTopic::streamContainerLogs with payload:
  - containerUUID(16), stream(1), seq(4), chunk{4}
  - stream == 0 → stdout; stream == 1 → stderr; stream == 255 → error frame (no log data).
  - For error frames, seq carries an error code (1: containerNotFound, 2: invalidLookback, 3: invalidStreams), and chunk contains the error message.
- The mothership prints errors as:
  - [logs][<uuid>] ERROR code=<code>: <message>
- Normal frames print with stream and sequence metadata:
  - [logs][<uuid>][stdout|stderr][<seq>] <chunk>

SSH Access

- Managed remote cluster control is SSH key-only.
- Mothership authenticates to remote machines by SSH key and then talks to Prodigy over the local unix socket.
- There is no password-auth escape hatch in the active code path.

Pinger & Compaction Scaling Defaults

- ICMP Pinger:
  - Base interval remains 250ms, but per-tick sends are capped to 64 to avoid ring starvation; remaining hosts are sent in subsequent ticks.
  - For >256 peers, expect ~1–2s sweep times (steady-state reachability remains accurate for election decisions).
  - Consider marking hosts unreachable only after N missed cycles (e.g., 3) to reduce false negatives; can be tuned later.

- Deployment drain/compaction:
  - Suggested defaults (to implement cluster-wide):
    - Max concurrent drains per rack: 1
    - Max cluster-wide drains: 3–5
    - Max compactions orchestrated across apps: 2–3
  - Rationale: bound resource contention, preserve surge headroom, reduce blast radius, and provide steady rebalancing.
Container Parameter Passing

- Neuron now passes container parameters via a memfd to avoid ARG_MAX and embedded NUL issues.
- The child receives an env var `PRODIGY_PARAMS_FD` set to an inherited descriptor number containing Bitsery‑serialized `ContainerParameters`.
- Application bootstrap should first check `PRODIGY_PARAMS_FD`, falling back to `argv[1]` (legacy) if not set.
