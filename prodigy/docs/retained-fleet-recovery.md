# Retained-fleet recovery after the TidesDB format migration

This explicit Mothership command repairs lost ownership for the frozen three-host
fleet: 23 canonical containers selected from the last verified healthy deployment
and the exact surviving extras recorded in its sealed manifest. It is not a general reset.
All lifecycle operations remain inside Mothership. Discombobulator supplies the
approved runtime bundle. Never restore the v9 databases after v10 writers started.

```sh
mothership recoverRetainedFleet PRIVATE_PLAN prepare
mothership recoverRetainedFleet PRIVATE_PLAN retire-extras-preactivation
mothership recoverRetainedFleet PRIVATE_PLAN recover
```

The private schema-v1 plan uses the migration plan fields and adds
`retainedRecoveryMode: true`, `retainedManifestPath`, and
`retainedManifestSHA256`. Its expected old runtime/bundle hashes identify the
currently installed v10 runtime. Use a new operation ID and operation root.
Run on the selected seed with the normal commissioned registry and outer
Mothership client lock; no other Mothership process may own that registry.

The private manifest binds cluster and successor bundle, and exactly three
machine entries. Each machine has `machineUUID`, `machineFragment`, and `records`.
Each process record has hexadecimal `uuid`, numeric `pid`, decimal-string `start`
(from /proc start ticks), `exeSHA256`, `paramsSHA256`, `paramsPath`, `canonical`,
and `createdAtMs` (recovery observation time, not the original scheduler time).
Parameter files contain credentials and must remain private.

Mothership verifies the exact process inventory, cgroups, executable hashes and
live memfd parameter hashes. It stages the approved bundle, fences and stops only
prodigy.service, and retains every container process. It copies the six v10
state/secret databases and prepares witnesses on private paired copies using the
existing StateStore. The seed's saved deployment plans are authoritative; existing
replica plans must agree exactly, and only missing plans may be filled.

The reconstruction supports ordinary base containers and stable shard-zero
stateful replicas. It preserves resources, addresses, ports, credentials and
launch pairings, restores omitted compact-wire CPU fields from deployment
configuration, and rebuilds service definitions through the normal scheduler
owner. Containers start as scheduled and unready. Normal readiness, mesh and
bundle-attestation checks must establish their actual health.

The seed seals one set of serialized recovery witnesses, bound to the immutable
request digest, and supplies those exact bytes to every Brain. Verification
compares unordered maps by keys and values; ordered fields and sealed witness
bytes remain exact. Private-copy readback must match before six atomic directory swaps. Original v10
directories and the previous runtime are retained. The existing durable lifecycle
receipt records each swap and crosses the activation boundary before any new
writer starts. Repeat the same immutable command after interruption; do not
replace its plan or silently roll back after activation.

Before activation, a stopped operation can use a separately approved repair-tool
bundle without changing its plan or deployment bundle:

`mothership recoverRetainedFleet PRIVATE_PLAN recover REPAIR_TOOL_BUNDLE`

Use action `prepare` in place of `recover` to stop after all private copies pass
readback, before any original directory is renamed or runtime activated.

The repair bundle must be produced by Discombobulator and contain the exact
Mothership executing the command. Mothership stages and verifies the entire tool
bundle on each selected guest. This option requires the existing writer fences
and quiesced receipt; it cannot authorize a new deployment identity or roll back
activated writers. A previously prepared private copy may be rewritten only when
its decoded witnesses and all other snapshot content match the sealed request.

The internal `prepareRetainedRecoveryLocal REQUEST STATE prepare|verify
[PREVIOUS_BUNDLE_SHA256]` command is invoked by the staged Mothership against
private copies. It is not a substitute for the fenced fleet operation.

A contained normal update can be replaced while it is still collecting bundle
echoes for the exact approved successor, with no exec, reboot, registration, or
handoff evidence. Followers may instead retain the previous recovery envelope;
Mothership binds that case to the installed predecessor digest in the sealed plan.
Preparation rechecks the stopped runtime and exact retained process inventory,
then validates each saved transaction before replacing it with fresh witnesses.
An already prepared envelope for this request remains an idempotent retry; an
interrupted normal update or predecessor envelope advances the generation once.

A cold Neuron now refuses to upload authoritative inventory or accept a launch
while any populated container cgroup lacks a matching live owner. Therefore
retire the sealed extras before activation. `retire-extras-preactivation` requires
all three Brains stopped and fenced, all six originals unswapped, and freshly
verified prepared copies. Mothership verifies all canonical process identities
across the fleet before signaling any extra. Interrupted retirement resumes only
against the same sealed remaining processes and checks the exact canonical 23
before recording completion. It does not start a Brain or delete application data.

If the existing preactivation plan names an older runtime, seal a successor plan
with a new operation ID/root and corrected Discombobulator bundle. Keep the same
cluster, machine, database, registry and old-runtime identities and the same
process records. Invoke:

```sh
mothership recoverRetainedFleet OLD_PLAN supersede-preactivation SUCCESSOR_PLAN
mothership recoverRetainedFleet SUCCESSOR_PLAN prepare
mothership recoverRetainedFleet SUCCESSOR_PLAN retire-extras-preactivation
mothership recoverRetainedFleet SUCCESSOR_PLAN recover
```

Supersession preserves the old plan, receipt, copies and prepared databases. It
blocks old-plan reentry, stages the successor, installs all successor fences
before removing any predecessor fence, and never starts a process. Retry the
same supersession command after interruption. The successor prepares its own
copies because recovery witnesses bind the deployment bundle digest.

For a legacy recovery already activated without the cold-inventory guard,
`retire-extras` remains available after canonical health is independently proven.
Its private `OPERATION_ROOT/canonical-health-attestation` contains plan SHA,
newline, manifest SHA, newline.

Only the 11 recorded stateless extras can be retired. Mothership rechecks each
PID/start/executable/cgroup/parameter identity through a pidfd before signaling;
no application directories are deleted. Reverify three Brains, 13 services,
exactly 23 matching processes and three Hot replicas with 3 GiB limits and no
observed crashes/OOMs. No recovery-command success is an application-health claim.

If activation fails qualification, `contain-active` fences and stops only the
three Brains, preserving current v10 databases and all container processes.
It verifies the installed runtime against the activated operation receipt.
Do not roll back databases after activation.

A contained operation can then use `supersede-preactivation` with a fresh plan
whose expected old hashes identify that activated runtime. The successor must
preserve every canonical process identity; its separately sealed extras may
differ. Mothership verifies the complete current inventory before handing over
fences. The successor copies current live v10 databases, preserving intervening
writes, and prepares new witnesses before any further activation.

## Retrying a failed first stateful replacement

If an accepted `recoverMaterializedStatefulDeployment` operation stopped its
first predecessor but the replacement failed before health, retain both surviving
replicas and the stopped predecessor's storage. Correct the application artifact
through Discombobulator. Install the supporting runtime on all Brains before
authorizing a retry; accepting a retry writes version-four authority state.

Use `mothership recoverMaterializedStatefulDeployment TARGET JSON` with the
original `applicationName`, `applicationID`, `activeVersionID`,
`successorVersionID`, `successorBlobSHA256`, and `operationID`, plus:

- `retryFailedSuccessor: true`, `replacementSuccessorVersionID`, and
  `replacementSuccessorBlobSHA256` identifying the corrected artifact;
- canonical hexadecimal `sourceContainerUUID`, `failedSuccessorContainerUUID`,
  and `sourceMachineUUID`;
- numeric `sourceDevice`, `sourceInode`, `sourceUID`, `sourceGID`, and `sourcePID`,
  and `captureSHA256` binding the original Neuron handoff receipt.

Then submit that exact corrected plan and artifact through ordinary Mothership
deployment. A repeated recovery request must preserve every identity above.
Neuron derives paths itself and rejects a live source PID, populated predecessor
cgroup, changed source identity, or mismatched receipt. Its existing reflink
handoff preserves the original data and fails rather than copying sparse data
densely on an unsupported filesystem.

Brain durably assigns one replacement UUID before dispatch. Neither surviving
predecessor is replaced until that first replica reports health. The existing
serial recovery owner then completes the other two replacements. Command
acceptance, successful copying, and a running process do not prove application
health or logical data equality; verify those independently before declaring
recovery complete. A failed private capture remains preserved and requires
investigation rather than automatic overwrite.
