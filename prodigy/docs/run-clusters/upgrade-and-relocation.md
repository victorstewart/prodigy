# Upgrade and relocation qualification

This is a qualification guide for the current candidate. It does not authorize
an update, cluster creation, provider action, or workload move. A passing unit
test is evidence for its named invariant only; it is never real-provider or
workload-continuity evidence.

Mothership is the coordinator across registered clusters, including every migration.
It owns the durable operation and commands source and destination Brains through
their authenticated control paths. Each Brain remains responsible for its own
runtime, routing, credentials, discovery and storage fences. Migration start,
status, resume, abort and crash recovery must use this same Mothership owner;
neither a test harness nor a separate migration controller may take that authority.
A network bridge grants reachability only and never transfers ownership.

## Candidate behavior

Bundle approval owns the bytes. It extracts `containers/plans/upgrade-compatibility.json`
from an approved bundle, computes the embedded contract and component hashes, and
rejects a contract whose declarations do not match those computed values. The
read-only command is:

```bash
mothership inspectUpgradeBundle ./prodigy.aarch64.bundle.tar.zst
```

Ordinary local builds produce the explicit `local-build-unqualified` / `unsupported`
contract. A release build can classify an already-qualified compatibility claim only
by supplying `-DPRODIGY_UPGRADE_RELEASE_POLICY=/absolute/policy.json` at CMake
configure time. That policy must name the target release and architecture, every
compatibility axis, rollback and migration protocol, resource minima, and exact
source-release contract/prodigy/Mothership hashes. The generator computes the target
component hashes from the binaries it actually packages; a policy cannot supply or
override them. Omitted, malformed, incomplete, unknown-axis, wrong-architecture, or
non-one-to-one source policies fail closed or retain the unsupported local contract.

GitHub Release metadata is a distribution classification record, not update
authorization. A future publisher should upload a versioned metadata asset that
binds the tag and immutable source revision to each architecture's bundle SHA-256,
embedded-contract SHA-256, and computed component hashes, alongside the bundle and
checksum. The current candidate has no publisher-signature verifier or configured
publisher trust root; local artifact approval proves bytes are mutually consistent,
not that a release publisher authorized them. Do not mark a policy qualified until
the source compatibility matrix and the route-specific qualification below are
recorded. The exact-source policy must declare `transportIdentityMode: "preserveClusterIdentity"`
for an in-place rollout. Current commissioned-peer mTLS observations are checked
separately; they do not prove CA overlap/rotation or executable attestation.
Per-member capacity observations bind the operation, target bundle and contract,
and required staging bytes. Each asynchronous probe measures the staging and
installation-parent filesystems, including where replacement roots are created.
Aggregate schedulable storage is not accepted as update capacity evidence.

`planUpgrade` consumes an approved target plus a fresh typed Brain observation.
Mothership persists an immutable operation-keyed admission record before dispatch.
The admitted request binds operation ID, source and target bundle digests, target
contract digest, authority generation, master UUID and boot time, and the current
observation receipt version and nonce. Brain rechecks those facts, every observed
peer's installed source digest, target bytes, and the extracted embedded target
contract before publication. It repeats the authority/source check after
asynchronous artifact proof. Legacy `updateProdigy` is rejected as an admission
bypass; admitted success and failure replies use `updateProdigyAdmitted`.
Registration of an older peer also cannot trigger an automatic bundle push or
restart. That previous version-based path bypassed both admission and serial
follower coordination and has been removed.

Protocol version 21 introduces the capability and upgrade-observation topics.
Versions 19 and 20 reject unknown topics, so the candidate sends neither topic to
those peers. They remain required commissioned members when computing complete
admission; skipping an unsupported message does not remove a peer from the gate.
A version-21 registration alone grants no feature: support still needs an explicit
acknowledgement on the current authenticated connection.

The current update owner has serial follower behavior and durable authority/recovery
receipts. This is an implementation prerequisite, not a completed live rollout
qualification. The observation proves current commissioned-peer transport identity
under the configured transport and a fresh local receipt; it does **not** prove a
candidate trust-root transition, a future CA rotation, or executable attestation.
A successful target-bound capacity probe supplies a point-in-time minimum across
the relevant filesystems; it does not reserve that space. Installed bundle digest
is an installed byte identity, not proof that an uncompromised executable is running.

An empty isolated test cluster has a narrow mechanics-qualification path. Mothership
derives eligibility from its registered `deploymentMode: "test"` configuration with
no external IPv4 boundary and a fresh zero-workload observation. It does not claim
a public application baseline. Brain checks the empty-workload condition again
before publication, including admitted plans and pending artifact requests. A late
workload fences the operation. Workload-bearing and production clusters still
require public-continuity evidence, which the candidate does not yet collect.
This path and the new capacity observations await C++ and real-runtime qualification.

Placement policy is a durable, operation-keyed authority record for one selected
application successor. It carries a canonical eligible-machine UUID set and is
accepted only after every commissioned peer explicitly acknowledges the capability.
It supports a newer, stateless, constructive successor only. The successor's
`nFitOnMachine` consults the restored policy; unrelated applications retain normal
scheduling. Policy admission rejects stateful requests. A policy is therefore a
placement prerequisite, not a complete LAN-to-cloud migration state machine and not
a zero-downtime guarantee for arbitrary applications.

The planner may describe `sameLogicalRollout`, `logicalClusterRelocation`, or
`separateClusterMigration`. Its receipt list and input hash are planning evidence;
they do not create a gateway, bridge two clusters, shift traffic, replicate an
application, or retire a source. Independent-cluster migration remains unavailable
until an application-specific bridge, identity/credential transfer procedure,
fencing, and cutover owner exist.

## Stateful source retirement

The existing Brain authority and deployment lifecycle owners now retain a durable
retirement journal for each source container of a stateful topology change. Before
sending a destructive command, the current master must durably store the exact
source identity and receive the same authority digest from every commissioned
Brain. Every peer must prove support for the journal on its current authenticated
connection. A mixed fleet without that support cannot activate this operation.

A Neuron kill acknowledgement first becomes a new durable authority revision.
Normal destruction completion waits for that revision's peer acknowledgements.
Recovery may adopt an existing source process for destruction, but its saved
bootstrap forbids restarting a missing source. Pending and terminal journal entries
exclude the source from runtime package capture and reject delayed healthy upserts.
Follower quarantine removes routing, scheduling and serving declarations while
retaining the object needed by the destruction receipt owner. Terminal entries are
not garbage-collected: the 4096-entry limit fails closed until a generation-fenced
runtime tombstone protocol permits safe compaction. Targets that cannot read the
journal cannot receive an upgrade while it is present.

This protects retirement within one cluster. It does not transfer application data,
volume ownership or credentials to another cluster. The earlier four-case local runtime
matrix exercised even/odd core changes, controller crashes, and a five-minute
healthy hold, but a later exact-artifact crash rehearsal failed. A bounded trace
found that the matrix's numeric role prefixes collapsed to one service identity.
Those earlier passes do not qualify service ownership. Collision rejection at
Mothership/Brain admission and service construction now has passing regressions.
The corrected crash rehearsal exposed a second failure: cutover selects one client
advertiser, but recovery restores older catchup plans with no client advertiser.
The candidate now binds the exact serving cohort, machine identities, selected
client, topology and desired configuration to the existing authority receipt
before cutover effects. The decision survives transition clearing; delayed runtime
reports preserve observed liveness and allocation without replacing that desired
state. Desired plans and retirement bootstraps use the existing private snapshot
sidecar, with strict matching to the public authority identity. Initial green
launches are admitted serially as catchup-only members. Recovery waits for pending
authority materialization and fresh inventory before scheduling missing targets.

Corrected crash and four-case rehearsals have passed on their recorded artifacts.
Later changes still require qualification on their own exact artifacts. Neither
this matrix nor its counters establishes acknowledged application-write continuity
or cross-cluster migration safety.

Steady memory/storage adjustments also use the durable serving decision. Capacity
reserves the larger of desired and observed allocations until Neuron reports the
applied result. An optional versioned reply on the existing resource command avoids
resetting routing merely to observe a resource change. The extended command requires
the existing current-connection, current-authority witness for an installed bundle
identical to the Brain's measured bundle. Unsupported or mixed bundle identities
remain blocked; this is not a claim of general mixed-version resource compatibility.
Legacy commands omit the observation request and receive no new reply. Lost replies
retain the reservation and use the existing desired-state retry owner.

Ordinary new-UUID replacement within a sealed steady deployment is still rejected.
Enabling it requires a durable predecessor/successor binding and a machine-bound
terminal fence; missing inventory and generic destruction callbacks are insufficient.
Same-machine Neuron stop/drain/storage handoff is an existing execution primitive,
but cross-machine writer/volume fencing remains unimplemented. These limitations
must remain visible in release qualification and cannot be bypassed by a harness.

## First hop from runtime19b

Live revision `4ba7a897dce60b9c3f52bf196fbbe1053b199a8a` restarts every follower
in one update continuation. Adding Brains does not create a canary: ordinary
bootstrap uses that old runtime's artifact, and the updater still transitions every
follower. Its authority-transfer command is internal to the update and follows the
follower transitions. The candidate's serial updater cannot change this first hop.

Existing retained-fleet recovery also cannot substitute for a single-member live
update. It requires stopped controllers and sealed inventories for the whole fleet.
The local test-provider checkpoint path permits a worker or sole Brain, not one
member of a live three-Brain cluster. Ordinary remote bootstrap stops the service
and rewrites its installation/configuration without a retained-process adoption
receipt. None of these paths proves a first hop with continuous controller quorum.
Production admission must keep that requirement distinct from uninterrupted
application traffic, and neither property may be inferred from a staged bundle.
For the Nametag rollout, both are required: continuous controller quorum and
uninterrupted application service. The next feasibility gate is a Mothership-owned
single-Brain retained-runtime replacement using the existing retained-recovery
owner. This mechanism does not yet exist as a qualified command. It must preserve
application processes, storage, Neuron adoption and routing, support durable resume,
and prove old/new protocol and leadership compatibility. New-only state stays
dormant throughout the mixed-version period. Qualify followers individually, then
the master through a proven handoff, while measuring both quorum and traffic.

Production stays on runtime19b until a qualified route satisfies both requirements.
Full independent-cluster migration remains separate required work; it is not
automatically the smallest first hop. If retained replacement cannot satisfy its
gates, compare a concrete migration route. A controller gap is not a fallback.

## Existing automated evidence

Run these only against the exact candidate build being qualified.

| Evidence | Target or selector | What it covers | What it does not cover |
| --- | --- | --- | --- |
| Contract parser and pure planner | `prodigy_mothership_upgrade_contract_unit` | computed contract/component binding; unsupported/incompatible rejection; planner route selection and stated preconditions | live report facts, persistence, dispatch, provider networking, application behavior |
| Admission registry | `prodigy_mothership_upgrade_admission_registry_unit` | immutable operation identity, replay/resume, changed-observation recording, conflicting target rejection | Brain dispatch or crash recovery across real processes |
| Wire framing | `prodigy_wire_unit` | valid/truncated/trailing framing for observation, capability, admitted-update, and placement topics | semantic behavior after decoding |
| Observation and admitted-update fences | `PRODIGY_TEST_UPGRADE_ADMISSION_OBSERVATION_ONLY=1 prodigy_brain_replication_credentials_unit` | nonce/master/boot/generation/transport/staleness rejection; admitted request fence and async contract-proof rejection | positive staging and update on a real bundle/fleet |
| Placement policy | `PRODIGY_TEST_ONLY=placement-policy prodigy_brain_replication_credentials_unit` | durable-before-success ordering; failure rollback; idempotent replay/conflict; capability guard; restored selected-app eligibility; stateful rejection | actual workload movement, traffic cutover, provider capacity |
| Container retirement journal | `prodigy_container_retirement_unit` and `prodigy_container_retirement_authority_unit` | immutable source identity; monotonic terminal acknowledgement; durability failures; adoption-only recovery; pending/terminal quarantine and delayed-report rejection; cold package restoration; valid unordered-map bootstrap encodings | cross-cluster storage/volume fencing, WAN behavior, production traffic continuity |
| Serial-update harness contract | `prodigy_dev_serial_upgrade_runtime_qualification_unit` | launcher and receipt-contract checks | a completed serial update on a real cluster |
| Provider host runtime | `prodigy_mothership_host_runtime_unit` | bounded host-Ring execution and deferred provider operation sequencing | a provider API result, VM lifecycle, routes, or cleanup on an account |

The existing `prodigy_dev_os_update_reimage_matrix.sh` is not currently a valid
reimage qualification path. Its timeout switches are parsed but unused, the
provider does not propagate its fake OS identity and deadline controls, and no
typed Mothership test-provider reboot/reimage operation exists. Passing unit OS
policy tests or an incidental log match does not close this runtime gate.

The full `prodigy_brain_replication_credentials_unit` also contains authority,
credential, artifact, state-upload, and recovery fixtures. Treat its results as
component evidence, not a substitute for a full workload history.

## Reusable local two-cluster qualification

### Shared TCP endpoint prerequisite

The `pair-endpoint` runtime scenario now exercises one declared IPv4/TCP endpoint
across two independent three-Brain test clusters. Mothership binds the operation
to both cluster/runtime identities, exact deployment plan and artifact digests,
and the provider-owned endpoint before creating its boundary. The boundary routes
new connections to the selected cluster while retaining existing connections on
their original cluster. An unsupported or failed conntrack observation blocks
drain; it is never interpreted as zero source connections. The provider journals
its namespace, link and route ownership for cleanup, including a dead supervisor.

The observed 2026-10-03 run completed in 152.49 seconds: 31 source requests and five
target requests succeeded, with the same held source connection spanning target
traffic. Actual source flows reached zero before the explicit supervisor crash
and subsequent cleanup. Creating both clusters took 8.63 seconds; selecting the
target took 0.17 seconds. Most elapsed time was waiting for source TCP conntrack
entries to expire. Mothership removed both clusters and the launcher stopped the
Apple Container. The request-history validator also rejects wrong deployment
identity, missing requests and absent overlap. Registry, command/report and
ownership checks, the focused identity fixture, and the full credentials suite
passed on the checkpoint's corresponding binaries.

This is a narrow endpoint prerequisite. The destination in this scenario is
deployed separately, and no source deployment retirement occurs. It does not
qualify a durable paired migration, rollback, crash-time traffic continuity,
stateful data, WAN routing, public TLS, HTTP/2 or HTTP/3. The next gate must bind
target admission durably before launch and use authenticated source termination
receipts before claiming retirement. Production migration remains unavailable.

The current coexistence scenario has passed a real local run with two independent
three-Brain clusters, exact installed-bundle observations, separate cluster UUIDs,
trust roots, private prefixes and eight network namespace identities. It observed
33 healthy reports from one cluster during the other's bounded link-fault command,
then removed both through Mothership. This is lifecycle/isolation evidence only:
it carries no application, inter-cluster link, volume transfer or client traffic.
The hardware-before-admission readiness defect was subsequently repaired in
`10b0226`, with focused regression evidence. The pair scenario must be rerun on the
final candidate; the earlier lifecycle pass does not qualify later code changes.

During the fault window, the scenario calls Mothership's existing `clusterReport local`
at the provider-published control socket. Named-target reports also write refresh
state to Mothership's registry; concurrent CLI processes currently fail fast on a
TidesDB lock. The scenario does not qualify concurrent registry command handling.
A migration operation must remain under one durable Mothership coordinator and
must explicitly handle busy/retry outcomes in any external invocation layer.

Before a cloud attempt, run deterministic qualification using two distinct
`deploymentMode: "test"` clusters created, configured, faulted, and removed only by
Mothership on one disposable VM. The test provider must give them separate network
boundaries, authorities, storage/data ownership, machine identities, and lifecycle
receipts. The harness may request ordinary Mothership operations and typed provider
fault injection; it must not create the clusters, preattach networking, copy runtime
state, or repair lifecycle after a fault.

This pair is the reusable integration environment for migration between independent
cluster authorities. A same-cluster rollout uses one authority; relocating that
logical cluster uses source and destination machine pools admitted to that same
authority through ordinary membership operations. It must not target a machine UUID
owned by the other independent cluster. Use a Discombobulator-built stateless
workload first, then only a declared replicated stateful profile. Record both cluster IDs, application/version/operation IDs,
authority and receipt identities, artifact and contract digests, selected source and
destination machine UUIDs, and Mothership cleanup receipts. Exercise typed virtual
datacenter faults: full and one-way/asymmetric partitions, packet loss/reordering,
endpoint withdrawal, destination/source process crash, and restart around every
durable phase. Verify that no cross-cluster controller storage, runtime tree, BPF
state, container root, or volume is copied by the harness.

A local pass proves deterministic control-plane and provider-boundary behavior only.
It does not prove WAN routing, public DNS, cloud NAT, capacity, image behavior, or
Vultr cleanup. Those remain real-provider gates below.

## Required qualification matrix

Every route needs a real Discombobulator-built workload and an evidence bundle that
identifies candidate bundle digests, source/target cluster UUIDs, machine UUIDs,
operation IDs, contracts, receipt versions/nonces, timestamps, and cleanup results.
Repeat each durable phase with an injected crash before and after its durable receipt:
admission record, artifact proof/publication/fsync, authority/recovery receipt,
successor readiness, traffic cutover receipt, and source retirement. Resume must
either converge to the exact recorded operation or fail closed without moving an
unrelated application.

| Route | Candidate support | Required local and real qualification; stop gates |
| --- | --- | --- |
| In-place, same logical cluster | Typed admission plus serial follower prerequisite exists. | In one disposable cluster, qualify admitted update and serial follower recovery under crash/partition faults; the separate coexistence scenario checks that faults do not affect an adjacent independent cluster. Then run the route on the intended logical cluster: stateless service continuity first, followed by a stateful profile only after its replication/fencing contract exists. Verify follower-at-a-time update, quorum throughout, authority handoff, restart/resume, rollback boundary from the contract, and source/target installed-byte observations. Test full and asymmetric partitions, stale/replayed observation/registration/update frames, old or disconnected peer capability, wrong cluster/role/UUID, expired/revoked/rotated credentials, and CA/leaf rotation. Stop on any duplicate writer, lost durable receipt, unbounded retry, or admission after stale evidence. |
| Same logical cluster, LAN to cloud; cloud to cloud | Placement policy can constrain a stateless constructive successor. No relocation coordinator or traffic-move protocol exists. | First demonstrate selected-app-only placement between two admitted machine pools under the same cluster authority, with typed network faults between the pools. The two-independent-cluster scenario qualifies the separate-cluster route below. Before a real LAN-to-Vultr or cloud-to-cloud application move, prove scoped L3/L4 control and service paths, no host-network mutation, NAT directionality, IPv4/IPv6 routes, MTU/PMTU, DNS TTL/caching, TLS/SNI/client identity, service discovery, and endpoint reachability in both directions. Hold overlap capacity for destination-before-source retirement. Verify source stays live until destination health and client continuity are observed. Repeat partitions (including one-way/asymmetric), source/destination crash at each receipt, stale peer identity, credential rotation/revocation, and provider cleanup. Stateful and arbitrary-app zero-downtime moves are blocked: require a declared bridge, replicated volume history, writer lease/fence, promotion, rollback, and source-retirement proof. |
| Independent new cluster | Planner can reject/describe this route; no authority migration or application bridge is implemented. | Block execution. Use the local two-cluster matrix only to develop and fault a future typed bridge owner. That owner must create both clusters through Mothership, preserve application identity and credentials through their owners, prove client endpoint transition, and forbid copying controller storage, runtime trees, BPF state, or container state. For a stateful workload, retain one writer and a complete container-plus-volume history across pause, sync, promotion, rollback boundary, source crash, and destination crash. |

For every route, record request/response topic identities and peer TLS verification
results. Key possession authenticates the peer credential; it does not attest to the
binary. Do not infer expiry, revocation, rotation, or compromise resistance from a
successful handshake alone.

Virtual datacenter and unit evidence can exercise deterministic failures, but cannot
qualify WAN routing, provider NAT, real DNS propagation, cloud capacity, VM/image
behavior, host-key trust, or provider cleanup. Those require bounded real-provider
evidence for the exact route and candidate.

Geographically distributed clusters with ongoing per-datacenter database replicas
are explicitly future scope. Migration can supply reusable identity, network,
replication and ownership-transfer mechanisms, but a one-time handoff does not
qualify steady-state WAN consistency, quorum placement, disaster failover or latency.
