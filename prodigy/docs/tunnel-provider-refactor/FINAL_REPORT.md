# Tunnel Provider Runtime Refactor Report

This report records the current pushed branch state. It is not a claim that the
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
| Current branch | 52 | 5864 | 493 |

Category ledger:

| Category | Draft net | Current net | Net removed |
|---|---:|---:|---:|
| Production | +4883 | +3302 | 1581 |
| Tests | +2081 | +2034 | 47 |
| Docs | +30 | +28 | 2 |
| Build metadata | +9 | +7 | 2 |

The prior project gate command, which counts Discombobulator test/build changes
inside the production bucket, reports `production +3851 -461 net +3390`.
The full diff including evidence artifacts is `60 files, 6249 insertions, 493
deletions`.

## Lines Removed By Subsystem

- Provider binary: moved out of product code to `prodigy/dev/tests/mothership_tunnel_provider_fixture.cpp`.
- Runtime state: deleted generation SHA fingerprinting and derived `running`/`healthy` fields.
- Schema boundary: removed OpenSSL/auth helpers, egress helpers, runtime policy, and Brain runtime state from `mothership.cluster.types.h`.
- Network path: deleted source-address-only NAT/reply state and dead IPv6 allowlist plumbing.
- Parser/compatibility surface: removed enum-qualified JSON compatibility spellings and speculative QUIC/multi-egress surface.
- Tests: tabled and compressed several tunnel/gateway/system-egress assertions while keeping focused coverage.

See `LINE_LEDGER.tsv` for per-path numbers.

## Surviving Feature-Specific Surface

- `MothershipTunnelProviderSpec`: persisted operator-facing tunnel metadata and client auth.
- Brain-owned anonymous runtime state: local provider UUID plus bounded diagnostic text.
- `SystemContainerKind::mothershipTunnelProvider`: typed runtime identity for system container launch.
- `mothership.tunnel.gateway.h`: still contains gateway implementation; it was reduced but remains a large header.
- `ContainerPlan` system fields: still carries system-container kind/socket/egress data; this is not the full dedicated plan extension requested by the original goal.
- Mothership/Brain configuration topics for artifact, gateway auth, and connectivity still exist.

## Release Blockers

Fixed or hard-cut:

- Built-in tunnel provider is no longer production code.
- Source-address-only NAT was removed; current system egress is a single public IPv4 TCP allowlist.
- No-op runtime state no longer serializes/hashes the spec on every reconcile.
- Provider health/status no longer carries redundant derived report fields.
- Tunnel endpoint input is hard-cut to public IPv4 literal TCP.
- Cluster schema types no longer own certificate parsing/generation, egress policy helpers, runtime policy, or Brain runtime state.

Superseded by later user direction:

- Legacy raw cluster record migration was not implemented; compatibility was hard-cut.
- Tuple-safe NAT collision tests are not applicable to the current no-NAT allowlist design.

Still open relative to the original goal:

- Three partial tunnel Mothership topics and three Brain replication topics remain.
- Desired state is not fully folded into `ProdigyMasterAuthorityRuntimeState`.
- Gateway implementation is still header-heavy and blocking-oriented.
- Artifact envelope is integrity/type declaration, not signed trusted provenance.
- Dedicated system-container plan extension is incomplete.
- Full rolling-upgrade protocol gating is not implemented.

## State And Transport

Current state is compact but not the full requested enum state machine:

```text
connectivity kind != tunnelProvider -> stop local provider
not active master -> stop local provider
missing auth/artifact -> no launch, record failure
artifact/auth/spec present -> launch typed system container and gateway
authenticated control session -> clear failure text
provider failure -> clear local UUID and record failure
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
- Existing branch-format tunnel records are current for this branch.
- Legacy pre-branch raw record migration is intentionally not present after the hard-cut instruction.
- Rolling mixed-version protocol gates are not proven. Unknown topic handling and activation gating remain open relative to the downloaded goal.

## Tests Run

All commands below were run inside the 16-vCPU `wizard-local` VM guest.

- `git diff --check`
- `cmake --build .run/tunnel-provider-latest --parallel 16 --target prodigy_mothership_unix_connect_unit prodigy_mothership_cluster_registry_unit prodigy_persistent_state_unit prodigy_brain_replication_credentials_unit prodigy_container_overlay_sync_unit prodigy_switchboard_whitehole_unit prodigy_deployments_unit prodigy_bundle_artifact_unit prodigy_mothership_tunnel_provider host_ingress_router container_egress_router`
- `./prodigy_mothership_unix_connect_unit`
- `./prodigy_mothership_cluster_registry_unit`
- `./prodigy_persistent_state_unit`
- `./prodigy_brain_replication_credentials_unit`
- `./prodigy_deployments_unit`
- `./prodigy_bundle_artifact_unit`
- `PRODIGY_DEV_ALLOW_BPF_ATTACH=1 ./prodigy_switchboard_whitehole_unit`
- `PRODIGY_DEV_ALLOW_BPF_ATTACH=1 ./prodigy_container_overlay_sync_unit`
- `cargo test --all-targets` in `prodigy/discombobulator`

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

Not measured: clean build wall time, incremental cluster-type fanout, gateway throughput/latency, 100k reconcile counters, artifact byte-copy counters, and BPF instruction deltas against `main`.

## Remaining Risks

- Full original definition of done is not met.
- Runtime health is still represented by failure text rather than a compact explicit phase enum.
- Control-plane activation remains multi-topic and can still have partial-state edge cases.
- Gateway I/O/deadline/backpressure behavior is covered by focused tests but not a full nonblocking state-machine proof.
- Artifact provenance remains weaker than the signed-envelope design requested in the original goal.
