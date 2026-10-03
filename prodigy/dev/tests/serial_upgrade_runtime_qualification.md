# Mixed-version serial-upgrade runtime qualification

## Status

This is a **blocked scenario specification**, not a runnable qualification yet. It
uses only Mothership test-cluster operations and Discombobulator app artifacts.
It does not authorize direct guest, machine, network, process, or filesystem
control.

The serial-normal driver has pre-dispatch `planUpgrade` admission and
concurrent Mothership application probes, but admission remains blocked as
described below. A true `live19b -> candidate`, receipt-gated
faults, and a post-exec digest-mismatch gate still require the owner changes
listed below.

## Current driver limit

`prodigy_dev_serial_upgrade_runtime_qualification.sh` submits source and target
bundles through `planUpgrade` and the admitted update path. It also requests
Mothership application reports and probes during the update. The current planner
rejects execution because live overlap capacity, target trust compatibility and
public continuity evidence have no implemented owner yet. An unsupported local
build cannot satisfy admission. No same-release or mixed-release runtime update
has passed this driver; its shell contract tests do not establish such a pass.

The driver must use the application's actual client endpoint. A machine address
and port do not identify an isolated application's endpoint. The existing
placement scenario proves placement and retirement through reports only, and
provides no uninterrupted client-traffic evidence.

The `follower-link-reconnect` case exits 77 until a typed per-member rollout
receipt is available. It must not infer that receipt from a stage string or a
fixed sleep.

## Required qualification once admission is available

Inputs are a source release pair, target release pair, one signed/approved
target bundle, and a Discombobulator-built stateless ping application. The
scenario must use the Mothership-owned test provider throughout.

1. Bootstrap three Brains on the admitted source release. Deploy the app through
   `mothership deploy`. Start a continuous Mothership `probeTestCluster`
   sample stream and record successful and failed samples, plus
   `applicationReport` snapshots. Require at least one healthy deployment
   before upgrade.

2. Submit the approved target with `updateProdigy`. Capture typed upgrade
   receipts, rather than infer ordering from sleeps. Require:
   `bundleStaged`, exactly one `followerTransitionIssued`, that follower's
   authenticated registration, verified target installed-bundle digest, state
   upload, and durable authority ACK before issuing the other follower. The
   report must identify peer/machine and monotonically ordered receipt IDs.

3. At `follower1Ready`, run one bounded `faultTestCluster` link flap against
   follower 1. In a separate run, crash the current controller at the same
   receipt. Require no second follower transition before the affected
   controller/reconnect path has re-established the first follower's digest,
   inventory, and authority receipt. The app probe stream may have bounded
   failures during a deliberate partition, but it must regain service and the
   application report must not become failed.

4. At the same first-follower gate, inject a test-provider-owned
   `postExecBundleDigestMismatch` for follower 1. Require no
   `follower2TransitionIssued`, no `masterTransferred`, and an explicit
   mismatch reason. Clear the bounded fault only through its Mothership
   operation; then require a fresh matching registration, inventory upload,
   and durable ACK before progress.

5. Permit follower 2 only after step 2's predicates repeat. Require
   `masterTransferred` only after both followers are ready, then require the
   old master to restart and the final cluster report to show all three
   Brains healthy and reporting the verified target installed-bundle digest. Require the probe stream to contain
   successes before and after the handoff and the application report to remain
   non-failed.

The candidate Brain already has diagnostic events for follower send, follower
reboot, and relinquish
([brain.h](../../brain/brain.h),
[brain.h](../../brain/brain.h),
[brain.h](../../brain/brain.h)).
They are useful diagnostics, but not a typed runtime-qualification interface.

## Blocking gaps and smallest owner changes

1. **Mixed release admission / first hop.** The harness rejects a bootstrap
   Prodigy that is not the sibling of its Mothership
   ([harness](../../dev/tests/prodigy_dev_netns_harness.sh)).
   `updateProdigy` also accepts only a bundle compiled into that Mothership's
   approval contract
   ([mothership.cpp](../../mothership/mothership.cpp)).
   Add a typed source/target admission record and a source-release-compatible
   Mothership path before attempting `live19b -> candidate`. Do not weaken
   the sibling or approval checks in a scenario script.

2. **Event-driven scheduling.** The harness now runs concurrent probes while
   `updateProdigy` is outstanding, but cannot safely schedule a fault at a
   durable follower receipt. Its existing generic fault sequence still starts
   after recovery
   ([harness](../../dev/tests/prodigy_dev_netns_harness.sh),
   [same file](../../dev/tests/prodigy_dev_netns_harness.sh)).
   Extend Mothership's typed rollout reporting and then add a receipt wait and
   a fault action keyed to that receipt. It should still invoke only
   `faultTestCluster` and `probeTestCluster`.

3. **Typed proof.** `clusterReport` currently lets the harness count healthy
   and runtime-ready machines, while the Brain's stage presentation is
   descriptive. Add typed per-member fields: source/target bundle digest,
   authenticated registration incarnation, inventory-upload receipt,
   authority-ACK generation/digest, and transition sequence. These fields are
   needed to prove the canary and to select the controller fault target.

4. **Digest mismatch fault.** Existing `faultTestCluster` exposes only
   `link|crash|flap`
   ([mothership.cpp](../../mothership/mothership.cpp)).
   `recoverTestClusterBundle` cannot replace a Brain in a three-Brain
   cluster: recovery only admits a worker after all Brains
   ([recovery header](../../mothership/mothership.virtual.datacenter.recovery.h)).
   Add a bounded Mothership test-provider bundle-digest observation fault that cannot
   be reached in production and is cleared by a new authenticated registration.
   It must not be implemented as harness filesystem mutation.

5. **Continuity evidence.** The normal driver now collects bounded Mothership
   probe and application-report samples while `updateProdigy` runs. The older
   `deploy_ping_after_fault` path remains later than its generic fault sequence
   ([harness](../../dev/tests/prodigy_dev_netns_harness.sh),
   [same file](../../dev/tests/prodigy_dev_netns_harness.sh)).
   The event-driven extension must run probes and application reports during
   the update and preserve their timestamped outcomes.

Until those five items exist, this scenario must remain an unqualified plan.
The current serial coordinator's gating is covered by focused unit tests, but
that is not a mixed-version test-cluster qualification.
