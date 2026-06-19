# Tunnel Provider Refactor Test Matrix

## Safe Unit/Fuzz Tests Run In 16-vCPU VM

| Command | Result |
|---|---|
| `git diff --check` | pass |
| `prodigy_mothership_unix_connect_unit` | pass |
| `prodigy_mothership_cluster_registry_unit` | pass |
| `prodigy_persistent_state_unit` | pass |
| `prodigy_brain_replication_credentials_unit` | pass |
| `prodigy_deployments_unit` | pass |
| `prodigy_bundle_artifact_unit` | pass |
| `cargo test --all-targets` in `prodigy/discombobulator` | pass |

## Privileged Tests Run In VM

| Command | Result |
|---|---|
| `PRODIGY_DEV_ALLOW_BPF_ATTACH=1 ./prodigy_switchboard_whitehole_unit` | pass |
| `PRODIGY_DEV_ALLOW_BPF_ATTACH=1 ./prodigy_container_overlay_sync_unit` | pass |

## Privileged Tests Not Run

- Full physical-host runtime matrix.
- Live tunnel-provider cluster create/failover smoke.
- Gateway throughput/latency benchmarks.
- Packet-path instruction/map-cost comparison against `main`.

Reason: the focused VM verification proved the touched unit/BPF paths, but the original goal's full runtime and performance matrix was not executed in this continuation.

## Static Evidence Only

- Built-in provider moved to test fixture target.
- Source-IP-only NAT code removed.
- Product LOC gate met.
- Remote branch head matches local head.
