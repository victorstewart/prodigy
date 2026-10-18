# Nametag stateful multicluster qualification

This specification freezes the bounded functional profile and its verification
gates. It does not qualify a runtime, authorize a live deployment or cutover,
resume the paused dev recovery, or authorize provider purchases. A component
test proves only its named invariant. The existing [upgrade and relocation
guide](upgrade-and-relocation.md) remains the source of prior qualification and
its exclusions.

## Topology and classification

Use two independent clusters with separate Brain authorities, membership,
credentials, private prefixes, storage and lifecycle ownership. Deterministic
qualification uses two three-Brain `deploymentMode: "test"` clusters created by
Mothership in one verified disposable guest. Freeze their exact identities,
membership, plans, artifacts, capacity and declared directed COUSIN permissions
before the first mutation. A network bridge provides reachability, never shared
quorum, scheduling, database authority or permission to copy controller state.

| Nametag owner | Application ID | Frozen behavior |
| --- | ---: | --- |
| Hot | 3 | Selected movable data owner; requires its own admitted data-transfer and writer-fence proof. |
| Cold | 4 | Selected movable data owner; requires its own admitted data-transfer and writer-fence proof. |
| Truth | 10 | Retained at source; reject a move request explicitly. |
| Radar | 5 | Retained at source; reject a move request explicitly. |
| Pulse | 2 | Retained at source; reject a move request explicitly. |

The classification selects implementation and qualification scope; it is not
evidence that Hot or Cold already moves safely. Retained services remain
accessible only through their existing declared service and authenticated
COUSIN permissions. Admission must reject retained-owner movement before target
launch, data export, writer fencing or endpoint effects. Unknown applications,
versions, mapping profiles and credential capabilities fail closed. The phase
does not migrate all Nametag state, add steady-state WAN replication, or merge
independent authorities. Run the matrix separately for Hot and Cold using one
shared manifest, fixture and evidence model.

The selected shared contract is `StatefulTopology`'s explicit
`applicationDataAuthority` mode, contract v1. It binds operation, source, target,
local and write-owner cluster UUIDs; `authorityEpoch`; and mode
`retainedSource|catchupOnly|writeOwner|fenced`. SHA-256 fields bind the contract,
shard manifest, snapshot boundary and required applied watermark. The
authenticated runtime receipt echoes that identity and adds `ready` plus
snapshot, applied and fence SHA-256 receipts. Readiness alone cannot advance
ownership. Existing serving modes retain their wire encodings; enable this
mode only after the exact-build capability gate. Its dispatch and authenticated
application proof channel require qualification before use.
Each bidirectional operation uses one topic and shared payload type; direction
supplies request/response role semantics.

## Transition requirements

The following names describe required semantic receipts, not new CLI commands
or a claim that every transition has an implementation. Mothership owns one
durable operation and its start, status, resume, abort and recovery. Each Brain
retains authority over its local runtime, discovery, credentials and storage.
Extend those owners; the harness must not become a migration controller.

1. **TargetAdmissionReceipt.** Persist an immutable operation binding source
   and target cluster, application/version, shard/range mapping, source and
   successor cohort, artifact/contract/plan digests, credential metadata, capability
   acknowledgements and rollback boundary. Require fresh authenticated
   observations, adequate overlap capacity and healthy retained dependencies.
   The same operation and inputs replay idempotently; changed inputs conflict.
2. **Target preparation prerequisite.** Verify the actual Discombobulator bytes
   and committed target plan before publication and launch. Admit target members
   as catchup only: no client advertisement, independent writes or promotion from a
   generic healthy report. Bind acknowledgements to current connection,
   cluster, machine, process incarnation and authority generation.
3. **SnapshotBoundaryReceipt and AppliedCatchupReceipt.** The application's
   existing data owner exports a consistent snapshot and ordered change history,
   with durable checkpoint, sequence/watermark, range and digest identities. It authenticates the exact
   destination and restores through its ordinary import/seeding owner. The
   harness never copies database files, volumes, runtime trees or Brain state.
   A target ACK means the declared checkpoint is usable after its promised
   recovery class; receipt of bytes alone is insufficient.
4. **SourceFenceReceipt.** Persist and replicate an operation-bound fence
   covering every selected source writer and shard before granting a successor
   writer. Drain in-flight writes through the last acknowledged sequence and bind that
   watermark to the fence. Observe the fence at every old serving path. An
   unreachable writer, missing ACK, stale ownership generation or uncertain
   fence blocks promotion; a lease timeout or empty inventory alone is not a
   terminal writer fence. Unselected applications continue under their owners.
5. **TargetOwnershipReceipt.** Revalidate the entire declared destination
   cohort and retained dependencies. Require a fresh AppliedCatchupReceipt at
   the final source-fenced watermark; every selected shard must match its count
   and canonical digest. Durably bind successor ownership to the exact
   predecessor fence and machine identities. Only then may the existing
   serving/discovery owner grant the target writer and advertise it. No source
   and destination may acknowledge conflicting writes concurrently.
6. **RouteSelectionReceipt.** Persist the exact endpoint/route generation and
   ownership decision before externally visible selection. Retain an
   acknowledged client-operation history across selection and existing-flow
   drain. A client ACK is attributed to one writer generation. Delayed source
   registration, healthy upserts, seed completions and route replays cannot
   restore the old writer or replace the recorded desired serving cohort.
7. **SourceRetirementReceipt.** Require fresh target readiness, observed source
   drain and the exact durable retirement fence. Use the existing Brain/Neuron
   retirement journal and authenticated terminal receipts. Persist and
   replicate terminal acknowledgement before claiming success. Recovery may
   adopt a still-existing fenced source for destruction; it must not restart
   a missing retired source or create a replacement source UUID.
8. **Closed.** Retain terminal operation, ownership and retirement identities;
   remove only operation-owned temporary transport and provider resources.
   Exact retries return the durable result. Stale generations and altered
   receipts remain rejected after cleanup and cold recovery.

Every receipt binds the prior receipt, operation and immutable inputs. Recheck
authority, capabilities, identities and source state after asynchronous work.
Persist failure/compensation intent before effects and resume through the same
owner after a crash. A successful handshake authenticates a credential; it
does not attest executable bytes or prove rotation/revocation handling.

The selected production-pair extension uses intent v7 / record v3, preserving
legacy intent v6 / record v2. Its explicit phases are
`targetAdmitted -> snapshotVerified -> catchupVerified -> sourceWriterFenced ->
targetOwnershipActive -> transitApplied`. These names describe candidate
control-plane transitions; a unit pass cannot replace the authenticated
application receipts or prove data transfer and enforced fencing.

Abort before source fencing removes the catchup target and temporary resources
through ordinary owners, preserving the source writer. After fencing, resuming
source writes requires a separately durable cancellation that proves the target
never acquired writer authority and grants source ownership in a new authority
epoch. After target promotion or cutover, do not unfence the source or reverse
the endpoint by script. A supported reverse
transfer needs its own admitted operation and predecessor/successor fences;
otherwise reject rollback explicitly and retain the recoverable recorded state.
No irreversible live cutover is authorized by this specification.

## Finite matrix and workload oracle

Freeze the actual durable-boundary list before executing. It must include
admission, artifact proof/publication/fsync, authority and recovery commits,
data snapshot/checkpoint and tail watermark, source fence, target readiness and
writer grant, cutover, terminal retirement and compensation where implemented.
Split independently durable steps into separate entries. Let **N** be this
fixed list's length, with owner and typed before/after trigger for each entry.
A missing observable trigger blocks that entry; elapsed offsets and stage-log
matches cannot substitute. Do not change N to hide a failed boundary.

| Group | Cases | Pass condition |
| --- | ---: | --- |
| Nominal | 1 | Full selected-owner operation, retained dependencies and exact data oracle pass. |
| Durable restart | 2N | Crash the responsible owner immediately before and after each receipt; recover the exact operation or reject safely without unrelated effects. |
| Partition | 3 | Both directions, source-to-target only, target-to-source only; installation/restoration witnessed, independent quorums and eventual recovery. |
| Replay and delay | 3 | Duplicate current frame, stale generation and delayed pre-cutover frame delivered after cutover: one effect or explicit rejection, never stale serving resurrection. |
| Master/coordinator loss | 3 | Source master, target master and Mothership: preserve operation, writer fence and recorded desired cohort. |
| Credentials | 4 | Rotation, expiry, revocation/reconnect and stale credential-generation replay through existing startup/refresh owners. |
| Ownership and rollback | 5 | Stale shard owner, stale seed/cutover receipt, concurrent old/new writer attempt, pre-cutover abort and post-cutover rollback request; no duplicate writer or unsupported rollback effects. |

This is **19 + 2N cases per selected owner**, with one bounded attempt per
frozen case. A failed case remains failed; a materially changed artifact or
diagnosis may justify a named rerun with both receipts retained. Do not expand
this into a product of every fault and every transition. Classifier rejection
for Truth, Radar, Pulse and unknown profiles is a mandatory shared admission
unit table, not a hidden additional runtime campaign.

Use one deterministic dataset and operation ledger for both owners, adapting
only their existing public operation semantics. Include distinct key/range
coverage, binary and empty values, updates, deletes and tombstones, conditional
or non-idempotent operations where supported, and a fixed seeded operation
order. An independent client oracle records operation ID, intended inputs,
sequence, writer generation, request time, exact ACK/result and failure. Resolve
ambiguous unacknowledged outcomes through existing idempotency/readback rules;
never count them as successful or blindly replay non-idempotent writes.

At each durable checkpoint and after recovery, compare exact key and live-value
counts, deleted-key absence, canonical per-range digests and a merged digest
against the oracle's acknowledged history. Define serialization, key order,
digest algorithm and TTL clock treatment before running. Observe through public
application reads; healthy replicas, counters or identical copied files alone
cannot prove data correctness. No acknowledged write may disappear, duplicate,
change value or reappear after deletion within the declared semantics. Verify
retained owners remain source-owned and their data matches their own
acknowledged history, including ordinary concurrent writes; this operation
must not move or unexpectedly mutate it.

## Evidence, isolation and lifecycle

Extend the existing shared primitive manifest and evidence model. Each case
records source/dependency/toolchain/config identities; exact binary, artifact,
contract and plan digests; cluster/machine/application/version/container IDs;
operation and shard/range mappings; process/boot identities; authority versions,
nonces and receipt chain; typed trigger; monotonic fault interval and witnessed
restoration; complete request/ACK history; oracle counts/digests; and explicit
pass, fail or blocked claim. Keep raw evidence under the task's `.run/` owner.
Do not invent a separate receipt schema or runner per case or database.

Credential evidence contains identifiers, scope, version/epoch, expiry,
acknowledgement, rejection reason and hashes of non-secret contracts only.
Never record material, bearer values, private keys, session tokens or their
derivatives. Mothership registration, Brain policy/startup/delta delivery,
Neuron acknowledgement and the existing service consumer remain the only
credential path. Rotation of a provider credential is a separate external
action; a local fake credential test cannot qualify it.

All successful workload artifacts must be Discombobulator `--kind app` outputs
with supported header, digest and size proof. Mothership creates/configures
both test clusters, installs runtime artifacts, deploys workloads, injects
typed faults and owns cleanup. The harness submits requests and makes read-only
observations. It must not repair state, attach BPF, edit maps/routes/cgroups,
restart processes, copy controller/runtime roots or construct substitute blobs.

On this Mac use only the pinned Arch Linux ARM Apple Container through
`~/apple-linux-dev/bin/dev-container` and the existing Darwin test launcher.
Inventory instances, resolve the exact external declaration and lifecycle
owner, and reuse one compatible guest. Record the approved image/kernel,
instance label, resource envelope, boot ID, host and guest network namespace
identities and selected guest-owned interfaces before runtime/BPF work. Fail
closed on ambiguity or host overlap. Never nest a VM or substitute another
runtime. Existing unrelated instances are not task cleanup targets.

Mothership cleanup must account for both clusters, endpoint/COUSIN permissions,
routes, processes, namespaces, links, BPF hooks, mounts, cgroups, sockets and
temporary storage on success, failure and interruption. Preserve exact
pre-existing identities and immutable caches/artifacts. Record before/after
inventory and cleanup receipt digests, including residual resources and their
owner. Preserve evidence before the Darwin launcher stops this serial batch's
guest. Provider cleanup needs provider observations, not only local absence.

## Public dev and blocked gates

A future authorized persistent dev deployment must preserve the enrolled
`vultr-ewr` relay and current lease keeper. Never acquire a competing lease or
replace the public path with local-only smoke evidence. Reconcile Andrew and
Victor through Nametag's existing `dev_sample_profiles` fixture; bind homepage
and renderer to Victor's current public ID. Verify public homepage, both
profile URLs and their images, bootstrap and login through the relay alongside
healthy Mothership reports. Keep credential material out of public receipts.
See Nametag's `tools/demo-deployment.md` for the existing fixture and relay owner.

The following gates remain explicit until new exact-input evidence closes them:

- Nametag's retained `.run/cluster-recovery-20261017/recovery-checkpoint.json`
  from 2026-10-17 is paused and unhealthy:
  master runtime30 not ready, candidate 0/0, public 504/timeouts; relay retained
  and renewing. This historical receipt is not current live observation. Dev
  recovery needs its own bounded authorized coordinator action and healthy
  public baseline before any cutover. Do not reset accounts/data or blindly
  restart the master to satisfy this phase.
- Existing pair faults provide directed DROP. Their `delayMs` schedules fault
  onset; it is not packet latency. Typed packet delay/loss/reorder support and
  witnessed runtime qualification remain blocked. Message replay/delay fixtures
  do not close those network gates.
- Cross-machine writer/volume fences and each selected owner's data-transfer
  contract require implementation and the matrix above. Pure state transitions,
  transport passes and stateless P6/G5/G6 evidence cannot qualify them.
- Runtime19b first-hop continuity, real-provider networking/capacity/cleanup,
  live credential transitions and public Nametag continuity need their own
  exact-route evidence and authority. No irreversible live cutover, provider
  mutation, purchase or production transport flip is included here.

Close this phase only with every declared functional gate accounted for and
the remaining live gates stated as blocked or pending. Do not describe source
retention, an explicit rejection, or a planned transition as completed movement.
