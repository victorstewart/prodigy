# Tunnel Provider Runtime Refactor Report

This report records the current branch state. It is not a claim that the
original downloaded goal is fully complete; later user direction hard-cut legacy
compatibility and source-NAT work that the original file requested.

## Commits

- Base: `aeff7aa7bd99ed41b46ab6ee3ea2a3e5338d0d65` (`origin/main`)
- Draft feature baseline: `240a63381c344402f757cfa3f14f7875bf1eaf2c`
- Branch: `origin/work/tunnel-provider-runtime-hardcut`

## Line Counts

Code diff scope is `depofiles ebpf enums prodigy switchboard` against `origin/main`,
excluding evidence artifacts under `prodigy/docs/tunnel-provider-refactor/*`.

| State | Files | Insertions | Deletions |
|---|---:|---:|---:|
| Draft feature baseline | 52 | 7437 | 434 |
| Current branch | 57 | 5775 | 870 |

Category ledger:

| Category | Draft net | Current net | Net removed |
|---|---:|---:|---:|
| Production | +4883 | +2899 | 1984 |
| Tests | +2081 | +1969 | 112 |
| Docs | +30 | +28 | 2 |
| Build metadata | +9 | +9 | 0 |

The current project gate command, excluding evidence artifacts, reports
`+5775 -870 net +4905` across 57 files. The full diff including evidence
artifacts is intentionally larger because this report and ledger are tracked.

## Lines Removed By Subsystem

- Provider binary: moved out of product code to `prodigy/dev/tests/mothership_tunnel_provider_fixture.cpp`.
- Runtime state: deleted generation SHA fingerprinting and derived `running`/`healthy` fields.
- Schema boundary: removed OpenSSL/auth helpers, egress helpers, runtime policy, and Brain runtime state from `mothership.cluster.types.h`.
- Network path: deleted source-address-only NAT/reply state and dead IPv6 allowlist plumbing.
- Control activation: collapsed split artifact/auth/connectivity configure into one Mothership desired-state request, artifact-by-digest backfill, and master-authority state replication.
- Parser/compatibility surface: removed enum-qualified JSON compatibility spellings and speculative QUIC/multi-egress surface.
- Tests: tabled and compressed several tunnel/gateway/system-egress assertions while keeping focused coverage.
- Runtime phase: replaced diagnostic-prefix control flow with explicit `TunnelProviderPhase` transitions and bounded retry state.
- Gateway TLS: moved server/client context construction out of session connect loops and shared the SSL_CTX certificate setup/peer-authorization helper.
- System launch contract: deleted mutable `ContainerPlan` env/socket fields and the redundant provider-kind runtime env; Neuron now derives the fixed socket graft and provider env from `SystemContainerKind`.
- Gateway implementation: moved socket/TLS/proxy code from the public header into a compiled runtime and deleted the session-result carrier.
- System egress plan: replaced the variable-length `ContainerPlan` egress host/port pair and Neuron-side parser state with a prevalidated numeric `SystemContainerEgressPolicy`; text is rendered only at the provider env boundary.
- Artifact launch boundary: removed the full verified artifact load/copy from Brain reconcile and deleted the artifact blob parameter from Brain/Prodigy provider launch hooks.
- System plan boundary: folded kind, artifact reference, egress tuple, and fixed runtime resources into one typed `SystemContainerRuntimePlan`, so provider launch no longer seeds fake stateless-application config fields.
- System artifact verification: `ContainerStore::systemVerify` now validates digest/size and reads only the fixed contract header instead of loading the whole artifact a second time for header validation; `systemLoadVerified` no longer reparses that header after loading bytes already verified by key and size.
- Create auth boundary: removed server auth from `MothershipTunnelProviderSpec`; gateway server auth is create-only hook input and only the client auth persists.
- Gateway I/O retry path: TLS accept/read/write now treats OpenSSL `WANT_READ`/`WANT_WRITE` as bounded wait states and drains buffered TLS plaintext before polling the socket again.
- Gateway health event: the runtime now marks provider health when authenticated TLS opens the guarded control socket, not after the proxy loop exits.
- Brain reconcile artifact surface: hard-cut the speculative vector of system artifact refs to the single supported system artifact reference.
- Prodigy launch hook surface: collapsed five one-use gateway/provider launch helpers into the single Brain `startMothershipTunnelProviderRuntime`/`stopMothershipTunnelProviderRuntime` boundary.
- Mothership control surface: deleted the unreachable direct TCP client stage and the disabled Brain TCP listener; supported control ingress is local Unix, SSH-forwarded Unix, or tunnel gateway.
- System artifact store surface: collapsed single-use private system-store wrappers into the public store/verify/load boundary and deleted the product provider-header validator that existed only for tests.
- Provider egress spec: hard-cut persisted text host/port fields to one numeric `SystemContainerEgressPolicy`; create JSON text is parsed once at the boundary, and runtime launch copies the numeric tuple.
- Brain desired-state commit: deleted the capture/sync/prepared-apply wrappers so one helper owns the tunnel desired-state mutation, runtime stop/reset, reconcile, and optional master-authority persistence.
- System artifact store API: deleted redundant actual digest/byte out-params from `ContainerStore::systemStore`; callers already hold the enforced key.
- Artifact create preflight: deleted duplicate Mothership-side provider header validation; `ContainerStore::systemStore` owns the system artifact contract boundary.
- System artifact ingest: create-time provider preflight now hands the blob to a content-addressed system-store boundary, which computes the artifact key once and atomically writes under that key; expected-key replication verifies digest/size in memory before writing.

See `LINE_LEDGER.tsv` for per-path numbers.

## Surviving Feature-Specific Surface

- `MothershipTunnelProviderSpec`: persisted operator-facing endpoint metadata, artifact identity, numeric egress policy, and client auth.
- Brain-owned anonymous runtime state: phase, local provider UUID, retry count/deadline, and bounded diagnostic text.
- `SystemContainerKind::mothershipTunnelProvider`: typed runtime identity for system container launch.
- `mothership.tunnel.gateway.h`: compact public declarations for listener, proxy helpers, and `MothershipTunnelGatewayRuntime`.
- `mothership.tunnel.gateway.cpp`: owns the Unix socket, TLS, proxy, and runtime accept-loop implementation.
- `ContainerPlan::system`: typed system-container kind, artifact reference, live numeric egress tuple, and fixed runtime resources; socket grafting and launch env are derived by Neuron.
- Brain still has separate artifact-byte transport because followers must receive artifact bytes before activating the desired state carried in `ProdigyMasterAuthorityRuntimeState`.

## Release Blockers

Fixed or hard-cut:

- Built-in tunnel provider is no longer production code.
- Source-address-only NAT was removed; current system egress is a single public IPv4 TCP allowlist.
- No-op runtime state no longer serializes/hashes the spec on every reconcile.
- Running-provider reconcile/report returns before artifact presence/load work; focused counters cover this path.
- Provider health/status no longer carries redundant derived report fields.
- Provider failure no longer disables a generation by matching a diagnostic string prefix; it enters explicit backoff and can retry.
- Provider health now ages out after a bounded control-session TTL instead of staying healthy forever after one session.
- Uploaded provider state is intercepted by `SystemContainerKind::mothershipTunnelProvider`, not by the reserved fragment alone.
- Gateway accept now starts only after the launched provider cgroup is known, and each Unix peer must match the provider UID plus that exact cgroup before TLS/control proxying.
- Gateway TLS server context is configured once at gateway start instead of reparsing root/server PEM and round-tripping peer certificates on every accepted session.
- Tunnel gateway clients cache parsed client TLS context at cluster configuration, no longer store the raw client auth bundle on `MothershipSocket`, and reuse that context across reconnects.
- Tunnel endpoint input is hard-cut to public IPv4 literal TCP.
- Cluster schema types no longer own certificate parsing/generation, egress policy helpers, runtime policy, or Brain runtime state.
- Tunnel desired state is folded into `ProdigyMasterAuthorityRuntimeState`; the old dedicated Brain topic and persistent record are deleted.
- `providerContainerBlobPath` is create-only parser output, not a member of the persisted/runtime tunnel-provider spec.
- Tunnel gateway server auth is create-only launch input, not persisted/runtime provider spec state.
- System-provider launch no longer serializes env or socket paths through `ContainerPlan`; the provider-kind env check is deleted because kind is already proven by artifact header and typed launch state.
- System-provider fixed resources are no longer serialized as mutable plan state; `ContainerPlan` derives the single supported system kind's CPU, memory, filesystem, and stop-timeout limits directly.
- ProdigyBrain no longer owns gateway thread, active FD, stop flag, or failure counter state directly; it owns one `MothershipTunnelGatewayRuntime`.
- System-provider egress no longer serializes a textual host through `ContainerPlan` or reparses that host in Neuron; Prodigy launch validates the public IPv4 literal once and Neuron derives the BPF allowlist key from numeric plan data.
- Tunnel-provider launch no longer loads the full system artifact into a `String` or passes artifact bytes through the Brain/Prodigy launch hook.
- Tunnel-provider launch no longer populates `ApplicationConfig` type/version/artifact/resource fields for the system container; Neuron consumes `ContainerPlan::system` for system artifact verification, extraction limits, cgroups, kill timeout, and egress.
- System artifact presence/verification no longer allocates a full artifact blob just to validate the contract header; full blob reads remain only for explicit artifact transfer/load paths.
- Gateway proxy sessions set socket receive/send timeouts and enforce a bounded idle poll timeout; focused coverage proves an authenticated idle session closes only after the guarded control socket opens.
- Gateway TLS accept/read/write handles OpenSSL retry states under the same bounded idle timeout instead of failing a healthy session on `WANT_READ`/`WANT_WRITE`.
- Gateway runtime health no longer depends on a mutable session-result struct or a clean proxy-loop exit; the authenticated control-open event is the only health callback.
- Brain reconcile now advertises one system artifact reference instead of a vector, matching the single supported `SystemContainerKind`.
- Tunnel activation now hard-rejects connected Brain peers below the current binary protocol, and the new system-artifact replication topic is not sent to old peers.
- Brain artifact ingress validation now matches the actual `sha256, bytes, blob` wire payload instead of a stale kind-prefixed intermediate shape.
- The single-use connectivity runtime-config builder wrapper is deleted; create-time tunnel activation now copies, strips, and validates the runtime connectivity inline.
- `MothershipConnectivityRuntimeConfig` is deleted; the runtime path now uses the same canonical `MothershipConnectivity` model after explicitly stripping Mothership-only fields.
- Prodigy tunnel-provider launch no longer exposes separate prepare/start/stop helper methods for the gateway and provider instance; the single runtime hook owns validation, listener creation, provider launch, cgroup capture, gateway start, and cleanup ordering.
- `MothershipSocket::stageTcp` is deleted; cluster control targets now resolve only to local Unix, SSH-forwarded Unix, or tunnel gateway transports.
- The Brain TCP Mothership listener is deleted; master control ingress arms only the Unix socket.
- `ContainerStore` no longer carries private forwarding helpers for the single system artifact kind, and the tunnel-provider header validator is test-local instead of exported as production API.
- Tunnel-provider persisted/runtime spec carries numeric egress policy, not text host/port, so runtime launch no longer reparses egress.
- Brain tunnel desired-state application now has one commit boundary after create/runtime sanitization; there is no separate prepared-state sync wrapper.
- System artifact store no longer reports digest/size copies from the write path; create preflight records the already computed enforced key.
- Tunnel-provider create preflight no longer validates the same provider header before calling the system artifact store; invalid kind/version/payload errors come from the store boundary.
- System artifact load no longer validates the same provider header after `systemVerify`; the load path checks that the full read returns the verified byte count.
- System artifact ingest no longer hashes once in Mothership, hashes again inside `ContainerStore::systemStore`, then rehashes the written file; the system-store boundary owns key computation/validation and writes atomically.

Superseded by later user direction:

- Legacy raw cluster record migration was not implemented; compatibility was hard-cut.
- Tuple-safe NAT collision tests are not applicable to the current no-NAT allowlist design.

Still open relative to the original goal:

- Gateway I/O is bounded by socket/idle timeouts and handles OpenSSL retry states, but is not a full nonblocking backpressure/half-close state machine.
- Artifact envelope is integrity/type declaration, not signed trusted provenance.
- System-container plan state is down to the required artifact reference and numeric egress tuple.
- Full rolling-upgrade protocol gating remains incomplete; this branch now gates tunnel activation and the new artifact topic on the bumped Brain binary version, but broader mixed-binary behavior is not fully proven.

## State And Transport

Current state uses the compact `TunnelProviderPhase` enum, but not the full requested lifecycle implementation:

```text
connectivity kind != tunnelProvider -> disabled
not active master -> disabled
missing auth/artifact -> awaitingMaterial
artifact/auth/spec present -> awaitingSession
authenticated control session -> healthy until TTL expires
provider failure -> backoff with retry deadline
```

Transport remains:

```text
Mothership client -> local Unix / SSH / tunnel TLS gateway -> Mothership control socket
```

## Artifact Trust Model

Current artifact handling proves bounded identity/integrity/type declaration for the supported system artifact. It does not prove trusted builder provenance with a configured Ed25519 signing key. Documentation must not claim provenance stronger than this.

## Packet Path

Current design removes the source-IP-only NAT path and keeps system-provider egress to one IPv4 TCP endpoint allowlist. Ordinary unrelated host ingress no longer pays the deleted system-NAT lookup. Collision proof is by absence of provider NAT/reply translation state in the current branch, not by a tuple-safe NAT implementation.

## Compatibility And Rolling Upgrade

- Omitted connectivity still means SSH.
- Tunnel desired state persists inside the Brain snapshot. The old dedicated `mothership_tunnel_provider_state` record is intentionally deleted after the hard-cut instruction.
- Tunnel-provider activation is rejected while any connected Brain peer advertises an older binary version, and the new `replicateSystemContainerArtifact` topic is not queued to old peers.
- Broader mixed-version behavior is still not fully proven relative to the downloaded goal.

## Tests Run

All commands below were run inside the 16-vCPU `wizard-local` VM guest.

- `nproc`, `nproc --all`, and `grep Cpus_allowed_list /proc/self/status` proved `16`, `16`, and `0-15`.
- `CC=clang CXX=clang++ cmake -S prodigy/dev -B .run/tunnel-provider-latest -DCMAKE_BUILD_TYPE=Release`
- `cmake --build .run/tunnel-provider-latest --target prodigy mothership prodigy_brain_replication_credentials_unit prodigy_persistent_state_unit prodigy_brain_topic_fuzz -j16`
- `./prodigy_persistent_state_unit`
- `./prodigy_brain_replication_credentials_unit`
- `./prodigy_brain_topic_fuzz -runs=100000`
- `CC=clang CXX=clang++ cmake -S prodigy/dev -B .run/phase-runtime -DCMAKE_BUILD_TYPE=Release`
- `cmake --build .run/phase-runtime --target prodigy mothership prodigy_brain_replication_credentials_unit prodigy_brain_topic_fuzz -j16`
- `./prodigy_brain_replication_credentials_unit`
- `./prodigy_brain_topic_fuzz -runs=100000`
- Repeated `cmake --build .run/phase-runtime --target prodigy_brain_replication_credentials_unit -j16`, `./prodigy_brain_replication_credentials_unit`, and `cmake --build .run/phase-runtime --target prodigy -j16` after the system-kind upload identity and health-aging slices.
- In fresh VM worktree `/work/prodigy-verify-cgroup-9YBkT2` at `e24d08e` plus the cgroup-gateway patch: `git diff --check`; `cmake -S prodigy/dev -B .run/build-cgroup -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++`; `cmake --build .run/build-cgroup --target prodigy mothership prodigy_mothership_unix_connect_unit prodigy_brain_replication_credentials_unit --parallel 16`; `.run/build-cgroup/prodigy_mothership_unix_connect_unit`; `.run/build-cgroup/prodigy_brain_replication_credentials_unit`.
- After replacing manual cgroup file syscalls with the existing bounded file-read helper in the same VM worktree: `git diff --check`; incremental `cmake --build .run/build-cgroup --target prodigy mothership prodigy_mothership_unix_connect_unit prodigy_brain_replication_credentials_unit --parallel 16`; `.run/build-cgroup/prodigy_mothership_unix_connect_unit`; `.run/build-cgroup/prodigy_brain_replication_credentials_unit`.
- After caching gateway TLS context and consolidating client/server SSL_CTX certificate setup in the same VM worktree: `git diff --check`; incremental `cmake --build .run/build-cgroup --target prodigy mothership prodigy_mothership_unix_connect_unit prodigy_brain_replication_credentials_unit --parallel 16`; `.run/build-cgroup/prodigy_mothership_unix_connect_unit`; `.run/build-cgroup/prodigy_brain_replication_credentials_unit`.
- After caching the tunnel gateway client TLS context and deleting the duplicate client-auth validator: `git diff --check`; incremental `cmake --build .run/build-cgroup --target prodigy mothership prodigy_mothership_unix_connect_unit prodigy_brain_replication_credentials_unit prodigy_mothership_cluster_registry_unit --parallel 16`; `.run/build-cgroup/prodigy_mothership_unix_connect_unit`; `.run/build-cgroup/prodigy_brain_replication_credentials_unit`; `.run/build-cgroup/prodigy_mothership_cluster_registry_unit`.
- After deleting mutable system-provider env/socket launch fields from `ContainerPlan`: `git diff --check`; incremental `cmake --build .run/build-cgroup --target prodigy mothership prodigy_mothership_unix_connect_unit prodigy_brain_replication_credentials_unit prodigy_container_overlay_sync_unit prodigy_persistent_state_unit prodigy_mothership_cluster_registry_unit --parallel 16`; `.run/build-cgroup/prodigy_mothership_unix_connect_unit`; `.run/build-cgroup/prodigy_brain_replication_credentials_unit`; `PRODIGY_DEV_ALLOW_BPF_ATTACH=1 .run/build-cgroup/prodigy_container_overlay_sync_unit`; `.run/build-cgroup/prodigy_persistent_state_unit`; `.run/build-cgroup/prodigy_mothership_cluster_registry_unit`.
- After moving gateway socket/TLS/proxy implementation out of the public header: `git diff --check`; incremental `cmake --build .run/build-cgroup --target prodigy prodigy_mothership_unix_connect_unit --parallel 16`; `.run/build-cgroup/prodigy_mothership_unix_connect_unit`.
- After replacing textual system egress in `ContainerPlan` with a numeric policy tuple in fresh VM worktree `/work/prodigy-verify-egress-CNEz6U`: `git diff --check`; `cmake -S prodigy/dev -B .run/build-egress -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++`; `cmake --build .run/build-egress --target prodigy mothership prodigy_container_overlay_sync_unit prodigy_mothership_cluster_registry_unit prodigy_brain_replication_credentials_unit --parallel 16`; `.run/build-egress/prodigy_mothership_cluster_registry_unit`; `PRODIGY_DEV_ALLOW_BPF_ATTACH=1 .run/build-egress/prodigy_container_overlay_sync_unit`.
- After deleting the provider launch artifact blob path in the same fresh VM worktree: `git diff --check`; `cmake --build .run/build-egress --target prodigy prodigy_brain_replication_credentials_unit --parallel 16`; `.run/build-egress/prodigy_brain_replication_credentials_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test and after the focused unit.
- After replacing provider fake app config with `SystemContainerRuntimePlan`: `git diff --check`; `cmake --build .run/build-egress --target prodigy prodigy_brain_replication_credentials_unit prodigy_container_overlay_sync_unit prodigy_persistent_state_unit --parallel 16`; `.run/build-egress/prodigy_persistent_state_unit`; `.run/build-egress/prodigy_brain_replication_credentials_unit`; `PRODIGY_DEV_ALLOW_BPF_ATTACH=1 .run/build-egress/prodigy_container_overlay_sync_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test and after the focused units.
- After bounding system artifact header verification: `git diff --check`; `cmake --build .run/build-egress --target prodigy prodigy_deployments_unit prodigy_brain_replication_credentials_unit --parallel 16`; `.run/build-egress/prodigy_deployments_unit`; `.run/build-egress/prodigy_brain_replication_credentials_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test and after the focused units.
- After bounding gateway proxy socket/idle waits: `git diff --check`; `cmake --build .run/build-egress --target prodigy prodigy_mothership_unix_connect_unit --parallel 16`; `.run/build-egress/prodigy_mothership_unix_connect_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test.
- After deleting mutable system-provider resource fields: `git diff --check`; `cmake --build .run/build-egress --target prodigy prodigy_brain_replication_credentials_unit prodigy_persistent_state_unit prodigy_mothership_unix_connect_unit --parallel 16`; `.run/build-egress/prodigy_brain_replication_credentials_unit`; `.run/build-egress/prodigy_persistent_state_unit`; `.run/build-egress/prodigy_mothership_unix_connect_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test.
- After removing the create-only provider blob path from the runtime spec: `git diff --check`; `cmake --build .run/build-egress --target prodigy prodigy_mothership_unix_connect_unit prodigy_mothership_cluster_registry_unit --parallel 16`; `.run/build-egress/prodigy_mothership_unix_connect_unit`; `.run/build-egress/prodigy_mothership_cluster_registry_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test.
- After removing create-only gateway server auth from the runtime spec: `git diff --check`; `cmake --build .run/build-egress --target prodigy prodigy_mothership_unix_connect_unit prodigy_mothership_cluster_registry_unit prodigy_brain_replication_credentials_unit --parallel 16`; `.run/build-egress/prodigy_mothership_unix_connect_unit`; `.run/build-egress/prodigy_mothership_cluster_registry_unit`; `.run/build-egress/prodigy_brain_replication_credentials_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test.
- After handling OpenSSL gateway retry states and deleting the dead runtime-config ownership helper: `git diff --check`; `cmake --build .run/build-egress --target prodigy prodigy_mothership_unix_connect_unit prodigy_brain_replication_credentials_unit --parallel 16`; `.run/build-egress/prodigy_mothership_unix_connect_unit`; `.run/build-egress/prodigy_brain_replication_credentials_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test.
- After densifying the gateway retry path and deleting a trivial cluster-connectivity wrapper: `git diff --check`; `cmake --build .run/build-egress --target prodigy prodigy_mothership_unix_connect_unit --parallel 16`; `.run/build-egress/prodigy_mothership_unix_connect_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test.
- After deleting the gateway session-result carrier and making authenticated control-open the health callback: `git diff --check`; `cmake --build .run/build-egress --target prodigy prodigy_mothership_unix_connect_unit prodigy_brain_replication_credentials_unit prodigy_mothership_cluster_registry_unit --parallel 16`; `.run/build-egress/prodigy_mothership_unix_connect_unit`; `.run/build-egress/prodigy_brain_replication_credentials_unit`; `.run/build-egress/prodigy_mothership_cluster_registry_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before and after build/test.
- After hard-cutting Brain reconcile to one system artifact reference: `git diff --check`; `cmake --build .run/build-egress --target prodigy prodigy_brain_replication_credentials_unit prodigy_brain_topic_fuzz --parallel 16`; `.run/build-egress/prodigy_brain_replication_credentials_unit`; `.run/build-egress/prodigy_brain_topic_fuzz -runs=100000`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before and after build/test.
- After bumping the binary protocol and gating tunnel activation/artifact replication from old Brain peers: `git diff --check`; `cmake --build .run/build-egress --target prodigy prodigy_brain_replication_credentials_unit prodigy_brain_topic_fuzz --parallel 16`; `.run/build-egress/prodigy_brain_replication_credentials_unit`; `.run/build-egress/prodigy_brain_topic_fuzz -runs=100000`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test and after the focused runs.
- After deleting the single-use runtime-connectivity builder wrapper: `git diff --check`; `cmake --build .run/build-egress --target prodigy prodigy_mothership_cluster_registry_unit --parallel 16`; `.run/build-egress/prodigy_mothership_cluster_registry_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test and after the focused unit.
- After deleting the `MothershipConnectivityRuntimeConfig` alias: `git diff --check`; `cmake --build .run/build-egress --target prodigy mothership prodigy_brain_replication_credentials_unit prodigy_persistent_state_unit prodigy_mothership_cluster_registry_unit --parallel 16`; `.run/build-egress/prodigy_brain_replication_credentials_unit`; `.run/build-egress/prodigy_persistent_state_unit`; `.run/build-egress/prodigy_mothership_cluster_registry_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test and after the focused units.
- After collapsing Prodigy's one-use tunnel gateway/provider launch helpers: `git diff --check`; `cmake --build .run/build-egress --target prodigy prodigy_brain_replication_credentials_unit prodigy_mothership_unix_connect_unit --parallel 16`; `.run/build-egress/prodigy_brain_replication_credentials_unit`; `.run/build-egress/prodigy_mothership_unix_connect_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test and after the focused units.
- After deleting the unreachable direct TCP control stage and defaulting Brain's no-op control ingress hook: `git diff --check`; `cmake --build .run/build-egress --target prodigy mothership prodigy_brain_replication_credentials_unit prodigy_persistent_state_unit prodigy_brain_config_ssh_replication_unit prodigy_brain_ipv6_topology_unit prodigy_brain_master_uuid_unit prodigy_brain_overlay_hosted_ingress_unit prodigy_mothership_unix_connect_unit --parallel 16`; `.run/build-egress/prodigy_brain_replication_credentials_unit`; `.run/build-egress/prodigy_persistent_state_unit`; `.run/build-egress/prodigy_brain_config_ssh_replication_unit`; `.run/build-egress/prodigy_brain_ipv6_topology_unit`; `.run/build-egress/prodigy_brain_master_uuid_unit`; `.run/build-egress/prodigy_brain_overlay_hosted_ingress_unit`; `.run/build-egress/prodigy_mothership_unix_connect_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test and after the focused units.
- After deleting the disabled Brain TCP Mothership listener: `git diff --check`; `cmake --build .run/build-egress --target prodigy mothership prodigy_brain_replication_credentials_unit prodigy_persistent_state_unit prodigy_brain_config_ssh_replication_unit prodigy_brain_master_uuid_unit prodigy_mothership_unix_connect_unit --parallel 16`; `.run/build-egress/prodigy_brain_replication_credentials_unit`; `.run/build-egress/prodigy_persistent_state_unit`; `.run/build-egress/prodigy_brain_config_ssh_replication_unit`; `.run/build-egress/prodigy_brain_master_uuid_unit`; `.run/build-egress/prodigy_mothership_unix_connect_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test and after the focused units.
- After flattening the system artifact store helpers in fresh VM worktree `/work/prodigy-verify-system-artifact-HJV8QE`: `git diff --check`; `cmake -S prodigy/dev -B .run/build-system-artifact -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++`; `cmake --build .run/build-system-artifact --target prodigy mothership prodigy_deployments_unit prodigy_brain_replication_credentials_unit prodigy_mothership_unix_connect_unit --parallel 16`; `.run/build-system-artifact/prodigy_deployments_unit`; `.run/build-system-artifact/prodigy_brain_replication_credentials_unit`; `.run/build-system-artifact/prodigy_mothership_unix_connect_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before build/test and after the focused units.
- After hard-cutting provider egress from persisted text fields to numeric policy in fresh VM worktree `/work/prodigy-verify-numeric-egress-Kwi2Rh`: `git diff --check`; `cmake -S prodigy/dev -B .run/build-numeric-egress -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++`; `cmake --build .run/build-numeric-egress --target prodigy mothership prodigy_mothership_unix_connect_unit prodigy_mothership_cluster_registry_unit prodigy_brain_replication_credentials_unit prodigy_persistent_state_unit --parallel 16`; `.run/build-numeric-egress/prodigy_mothership_cluster_registry_unit`; `.run/build-numeric-egress/prodigy_mothership_unix_connect_unit`; `.run/build-numeric-egress/prodigy_brain_replication_credentials_unit`; `.run/build-numeric-egress/prodigy_persistent_state_unit`. The first cluster-registry unit run exposed that `0.0.0.0` is now numeric-unconfigured instead of a persisted denied address; that stale case was removed, the unit was rebuilt, and all focused units then exited 0. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before and after build/test.
- After collapsing Brain tunnel desired-state commit wrappers in the same VM worktree: `git diff --check`; incremental `cmake --build .run/build-numeric-egress --target prodigy mothership prodigy_brain_replication_credentials_unit prodigy_persistent_state_unit prodigy_brain_topic_fuzz --parallel 16`; `.run/build-numeric-egress/prodigy_brain_replication_credentials_unit`; `.run/build-numeric-egress/prodigy_persistent_state_unit`; `.run/build-numeric-egress/prodigy_brain_topic_fuzz -runs=100000`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before and after build/test.
- After collapsing the redundant `ContainerStore::systemStore` output API in the same VM worktree: `git diff --check`; incremental `cmake --build .run/build-numeric-egress --target prodigy mothership prodigy_deployments_unit prodigy_mothership_unix_connect_unit prodigy_brain_replication_credentials_unit --parallel 16`; `.run/build-numeric-egress/prodigy_deployments_unit`; `.run/build-numeric-egress/prodigy_mothership_unix_connect_unit`; `.run/build-numeric-egress/prodigy_brain_replication_credentials_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` after build/test.
- After deleting duplicate Mothership-side provider artifact header validation: `git diff --check`; incremental `cmake --build .run/build-numeric-egress --target prodigy mothership prodigy_mothership_unix_connect_unit --parallel 16`; `.run/build-numeric-egress/prodigy_mothership_unix_connect_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before and after build/test.
- After removing duplicate post-load system artifact header validation: `git diff --check`; incremental `cmake --build .run/build-numeric-egress --target prodigy mothership prodigy_deployments_unit prodigy_brain_replication_credentials_unit --parallel 16`; `.run/build-numeric-egress/prodigy_deployments_unit`; `.run/build-numeric-egress/prodigy_brain_replication_credentials_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before and after build/test.
- After moving system artifact ingest to a content-addressed store boundary and adding digest-mismatch coverage: `git diff --check`; incremental `cmake --build .run/build-numeric-egress --target prodigy mothership prodigy_deployments_unit prodigy_mothership_unix_connect_unit prodigy_brain_replication_credentials_unit --parallel 16`; `.run/build-numeric-egress/prodigy_deployments_unit`; `.run/build-numeric-egress/prodigy_mothership_unix_connect_unit`; `.run/build-numeric-egress/prodigy_brain_replication_credentials_unit`. The guest proved `nproc=16`, `nproc_all=16`, and `Cpus_allowed_list: 0-15` before and after build/test.

Earlier validation on the same branch also covered the broader build/test matrix:
cluster registry, deployments, bundle artifact, BPF attach units, host/container
eBPF targets, the tunnel-provider fixture, and Discombobulator `cargo test
--all-targets`.

## Measurements

Recorded binary/object sizes from the VM RelWithDebInfo build:

| Artifact | Bytes |
|---|---:|
| `prodigy` | 88061376 |
| `mothership` | 58234336 |
| `mothership-tunnel-provider` test fixture | 1396360 |
| `prodigy_bundle_artifact_unit` | 8208752 |
| `prodigy_brain_replication_credentials_unit` | 73003720 |
| `host.ingress.router.ebpf.o` | 454296 |
| `container.egress.router.ebpf.o` | 427800 |

Focused unit counters now prove that a running provider report/reconcile performs no artifact presence check, and that provider launch performs no artifact load after the artifact is present. Static code evidence shows `systemVerify` reads only the fixed header after digest/size verification; explicit artifact transfer/load paths still read the full blob. System artifact ingest now hashes the in-memory blob once, checks any supplied expected key before writing, and atomically writes without a post-write file rehash.

Not measured: clean build wall time, incremental cluster-type fanout, gateway throughput/latency, 100k reconcile counters, artifact byte-copy counters, and BPF instruction deltas against `main`.

## Remaining Risks

- Full original definition of done is not met.
- Runtime health now has an explicit phase enum and TTL aging; jittered timer-driven retry remains incomplete.
- Control-plane activation is one Mothership configure request plus artifact-first Brain replication and a master-authority desired-state transition.
- Gateway I/O/deadline behavior is covered by focused tests; backpressure and half-close behavior are not a full nonblocking state-machine proof.
- Artifact provenance remains weaker than the signed-envelope design requested in the original goal.
