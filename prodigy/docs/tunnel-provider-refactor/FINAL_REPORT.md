# Tunnel Provider Runtime Refactor Report

This report records the current branch state. It is not a claim that the
original downloaded goal is fully complete; later user direction hard-cut legacy
compatibility and source-NAT work that the original file requested.

## Commits

- Base: `aeff7aa7bd99ed41b46ab6ee3ea2a3e5338d0d65` (`origin/main`)
- Draft feature baseline: `240a63381c344402f757cfa3f14f7875bf1eaf2c`
- Branch: `origin/work/tunnel-provider-runtime-hardcut`

## Line Counts

Code diff scope is `prodigy ebpf switchboard` against `origin/main`,
excluding evidence artifacts under `prodigy/docs/tunnel-provider-refactor/*`.

| State | Files | Insertions | Deletions |
|---|---:|---:|---:|
| Draft feature baseline | 52 | 7437 | 434 |
| Current branch | 55 | 5756 | 526 |

Category ledger:

| Category | Draft net | Current net | Net removed |
|---|---:|---:|---:|
| Production | +4883 | +3207 | 1676 |
| Tests | +2081 | +1988 | 93 |
| Docs | +30 | +28 | 2 |
| Build metadata | +9 | +7 | 2 |

The current project gate command, excluding evidence artifacts, reports
`+5756 -526 net +5230` across 55 files. The full diff including evidence
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

See `LINE_LEDGER.tsv` for per-path numbers.

## Surviving Feature-Specific Surface

- `MothershipTunnelProviderSpec`: persisted operator-facing tunnel metadata and client auth.
- Brain-owned anonymous runtime state: phase, local provider UUID, retry count/deadline, and bounded diagnostic text.
- `SystemContainerKind::mothershipTunnelProvider`: typed runtime identity for system container launch.
- `mothership.tunnel.gateway.h`: still contains gateway implementation; it was reduced but remains a large header.
- `ContainerPlan` system fields: still carries system-container kind/socket/egress data; this is not the full dedicated plan extension requested by the original goal.
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
- Tunnel endpoint input is hard-cut to public IPv4 literal TCP.
- Cluster schema types no longer own certificate parsing/generation, egress policy helpers, runtime policy, or Brain runtime state.
- Tunnel desired state is folded into `ProdigyMasterAuthorityRuntimeState`; the old dedicated Brain topic and persistent record are deleted.

Superseded by later user direction:

- Legacy raw cluster record migration was not implemented; compatibility was hard-cut.
- Tuple-safe NAT collision tests are not applicable to the current no-NAT allowlist design.

Still open relative to the original goal:

- Gateway implementation is still header-heavy and blocking-oriented.
- Artifact envelope is integrity/type declaration, not signed trusted provenance.
- Dedicated system-container plan extension is incomplete.
- Full rolling-upgrade protocol gating is not implemented.

## State And Transport

Current state uses the compact `TunnelProviderPhase` enum, but not the full requested lifecycle implementation:

```text
connectivity kind != tunnelProvider -> disabled
not active master -> disabled
missing auth/artifact -> awaitingMaterial
artifact/auth/spec present -> starting -> awaitingSession
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
- Rolling mixed-version protocol gates are not proven. Unknown topic handling and activation gating remain open relative to the downloaded goal.

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

Focused unit counters now prove that a running provider report/reconcile performs no artifact presence check and no artifact load in the tested path.

Not measured: clean build wall time, incremental cluster-type fanout, gateway throughput/latency, 100k reconcile counters, artifact byte-copy counters, and BPF instruction deltas against `main`.

## Remaining Risks

- Full original definition of done is not met.
- Runtime health now has an explicit phase enum and TTL aging; jittered timer-driven retry remains incomplete.
- Control-plane activation is one Mothership configure request plus artifact-first Brain replication and a master-authority desired-state transition.
- Gateway I/O/deadline/backpressure behavior is covered by focused tests but not a full nonblocking state-machine proof.
- Artifact provenance remains weaker than the signed-envelope design requested in the original goal.
