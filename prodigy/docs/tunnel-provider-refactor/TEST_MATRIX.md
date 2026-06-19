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
| `cmake --build .run/phase-runtime --target prodigy mothership prodigy_brain_replication_credentials_unit prodigy_brain_topic_fuzz -j16` | pass |
| `.run/phase-runtime/prodigy_brain_replication_credentials_unit` | pass |
| `.run/phase-runtime/prodigy_brain_topic_fuzz -runs=100000` | pass |
| `cmake --build .run/phase-runtime --target prodigy_brain_replication_credentials_unit -j16` | pass |
| `.run/phase-runtime/prodigy_brain_replication_credentials_unit` after system-kind upload identity change | pass |
| `cmake --build .run/phase-runtime --target prodigy -j16` | pass |
| `.run/phase-runtime/prodigy_brain_replication_credentials_unit` after health-aging change | pass |
| `cmake --build .run/phase-runtime --target prodigy -j16` after health-aging change | pass |
| `cmake -S prodigy/dev -B .run/build-cgroup -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++` | pass |
| `cmake --build .run/build-cgroup --target prodigy mothership prodigy_mothership_unix_connect_unit prodigy_brain_replication_credentials_unit --parallel 16` | pass |
| `.run/build-cgroup/prodigy_mothership_unix_connect_unit` after gateway cgroup identity/densification change | pass |
| `.run/build-cgroup/prodigy_brain_replication_credentials_unit` after gateway cgroup identity/densification change | pass |
| `cmake --build .run/build-cgroup --target prodigy mothership prodigy_mothership_unix_connect_unit prodigy_brain_replication_credentials_unit --parallel 16` after cached gateway TLS context change | pass |
| `.run/build-cgroup/prodigy_mothership_unix_connect_unit` after cached gateway TLS context change | pass |
| `.run/build-cgroup/prodigy_brain_replication_credentials_unit` after cached gateway TLS context change | pass |
| `cmake --build .run/build-cgroup --target prodigy mothership prodigy_mothership_unix_connect_unit prodigy_brain_replication_credentials_unit prodigy_mothership_cluster_registry_unit --parallel 16` after cached tunnel-client TLS context change | pass |
| `.run/build-cgroup/prodigy_mothership_cluster_registry_unit` after cached tunnel-client TLS context change | pass |

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
- Running provider report/reconcile skips artifact presence/load in focused counter tests.
- Provider state upload is keyed by `SystemContainerKind`, not the reserved fragment alone.
- Provider health ages out from one historical authenticated session in focused Brain tests.
- Gateway accepts only after provider launch and rejects Unix peers outside the launched provider cgroup.
- Gateway server TLS context is cached before accept-loop start and reused for authenticated control sessions.
- Tunnel gateway client TLS context is cached at cluster configuration and reused across reconnects.
- Remote branch head matches local head.
