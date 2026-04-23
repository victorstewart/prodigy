Prodigy Binary Rollouts — Canaries, Shadow Master, and Rollback (Future Work)

Overview
- Purpose: Capture considered designs to make brain/neuron binary rollouts safer, observable, and reversible with minimal runtime and code impact.
- Scope: Canary strategies, rollback mechanics, observability/criteria, and an alternative “shadow master” approach that exercises master logic without touching live brains.

Goals
- Catch bad binaries before master duties are impacted.
- Keep rollouts safe, observable, and reversible.
- Avoid large refactors; keep runtime overhead near zero outside rollout windows.

Core Constraints (Today)
- Master-only code paths: Some logic only runs on the active master; non-master peers won’t exercise that path.
- Majority-present gating: Mutations execute only with majority-present and metro-majority conditions.
- Existing building blocks:
  - Signed binary preflight (version gating removed to allow rollbacks).
  - RollingUpdateState orchestrator (peers → neurons → forfeit → self).
  - Neuron transition pacing with watchdogs.

Canary Strategies (ordered by complexity/risk)
1) Peer Canary + Soak (non-master only)
- Flow:
  - Stage new binary everywhere (prepare).
  - Transition a single non-master peer (the “canary peer”).
  - Soak for X minutes (e.g., 30) monitoring:
    - Stability: crashes, reconnect loops, watchdog timeouts.
    - Protocol health: peer connections to master/brains (interop).
  - If healthy → transition remaining peers (not master), then neurons, then master last.
  - If unhealthy → roll back only the canary peer; abort rollout.
- Minimal changes:
  - Add CanarySoak stage to RollingUpdateState:
    - Select canaryPeer from present, non-quarantined peers.
    - Start soakTimer; advance only after timer + healthy status.
  - Preserve previous binary on peers so rollback is a simple re-exec to previous.
- Pros: Simple, low risk; validates interop and non-master path.
- Cons: Does not exercise master-only code; some bugs may only appear after master transition.

2) Peer Canary + Shadow Master (recommended for master-risk)
- Idea: The canary peer runs master decision logic in a read-only “shadow mode”.
- Flow:
  - Same as #1, but during soak the canary peer runs decision loops against live inputs without emitting mutations.
  - Optionally stream “decision digests” or divergence counters to mothership; or just log them.
  - If shadow is healthy and divergence == 0 → proceed; else rollback canary and abort.
- Minimal changes:
  - Add a shadowMasterMode flag on Brain (or a small shim) where decision “emits” go to a no-op metrics sink.
  - Mutations already gated by isActiveMaster(); shadow executes the rest.
- Pros: Exercises master logic safely with modest changes.
- Cons: Requires careful routing of emit points to a no-op/metrics sink.

3) Synthetic Master Replay (offline/in-process)
- Idea: Capture a window of master inputs (messages/events), replay into a sandboxed shadow thread.
- Pros: No live impact; very low runtime cost.
- Cons: Timing drift; may miss interaction/race issues.

4) Canary Master (controlled cutover)
- Temporarily promote the canary to master under strict gating (maintenance window/limited scope).
- Pros: Exercises true master code.
- Cons: Operationally heavy; higher risk; generally not recommended.

Rollback Mechanics (Keep It Simple)
- Today: Transition reinstalls `/root/prodigy.bundle.new.tar.zst` into `/root/prodigy`, replacing the old root in place.
- Proposed:
  - Before install: preserve the previous `/root/prodigy` root or bundle as `/root/prodigy.prev`.
  - Reinstall the new bundle into `/root/prodigy` (as done today).
  - Add `BrainTopic::transitionToPreviousBundle` and NeuronTopic equivalent (fast-restore to previous) for targeted rollback.
- Rollback triggers (canary phase):
  - Crash loops or transition watchdogs.
  - Peer reconnect flapping / protocol failures.
  - (If shadow) divergence counters above threshold.
- Scope: For canary failure, revert only the canary peer and abort rollout.

Protocol/Interop
- Maintain backward-compatible on-wire formats within a minor window where possible (old master ↔ new peer).
- Versions: Signed preflight remains; numeric targetVersion is optional (version gating removed to allow rollbacks).

Observability & Success Criteria
- Soak success signals:
  - No crashes; transition watchdogs clean.
  - Stable peer connections; healthy registrations/heartbeats.
  - If shadow enabled: zero decision-divergence and no invariant violations.
- Mothership lines: “canary start”, “canary pass/fail”, durations, reasons.

Minimal Code Impact Summary
- Add CanarySoak stage to RollingUpdateState:
  - Fields: canaryPeer, soakUntilMs, pass/fail.
  - Stage order: Prepare → CanarySoak → TransitionPeers → TransitionNeurons → Forfeit → Self.
- Add rollback capability:
  - Preserve /root/prodigy.prev before applying new.
  - Add Brain/Neuron topics to transition to previous binary on command.
- Optional (shadow mode):
  - Introduce shadowMasterMode; route decision emits to metrics/no-op.

Performance Considerations
- Soak consumes time, not significant CPU.
- Shadow mode incurs CPU on one peer; negligible network unless streaming digests.
- No steady-state impact after rollout completes.

Phased Adoption (Low Risk)
- Phase 1:
  - CanarySoak stage + timer.
  - Preserve previous binary + rollback topics.
  - Use stability/health as pass criteria (no shadow).
- Phase 2 (if needed):
  - Add shadowMasterMode + divergence metrics.
  - Optional “decision checksum” stream (shadow → mothership) to detect drift cheaply.

When Canaries Don’t Suffice
- Bugs that manifest only under real master load or rare races may still slip. The right complement is strong pre-deploy testing (fuzz, heavy integration tests, chaos in staging).

Alternative: Promote a Neuron to Shadow Master (without touching brains)
- Objectives: Exercise master-only control-plane logic before risking the actual master; avoid modifying brain membership.
- Two designs:

  A) Shadow Master as a Sidecar Container
  - A dedicated “shadow-master” process runs as a container managed by a neuron on any machine.
  - It does not register as a brain; no elections or IaaS control.
  - Ingests state via mothership (existing pullClusterReport/pullApplicationReport; optional future stream).
  - Runs master decision engine locally with emit=no-op; exports a “divergence score” and invariant counters.
  - Canary gating: require zero divergence for the soak window; if failed, stop rollout.
  - Minimal changes: tiny binary linking decision core + ingest adapter; optional mothership streaming endpoint.

  B) Embedded Shadow Master in Neuron
  - Enable with a runtime flag; neuron spins a background thread for shadow logic.
  - Same ingest/emit model; reports metrics to mothership.
  - Pros: No container orchestration; Cons: slightly increases neuron complexity/CPU during soak windows.

Choosing Between A vs B
- Prefer strong isolation → Sidecar (A).
- Prefer fewer moving parts → Embedded (B), but keep off by default.

Rollback With Shadow Plan
- Preserve /root/prodigy.prev; add transition-to-previous topics for brains/neurons.
- If shadow metrics fail: stop rollout; nothing to revert on brains (they were untouched).
- If any peers had transitioned (more advanced flows), roll back only those peers.

What This Solves/Prevents
- Early detection of bad binaries without risking master.
- Protocol-level interop issues caught by canary peer before cluster-wide impact.
- With shadow: master decision logic is exercised against live inputs; catches algorithmic or policy regressions pre-cutover.

Open Questions / Next Considerations
- How strict should “divergence == 0” be (tolerances, categories)?
- Is a compact “decision digest” emitted by master desirable (to compare shadow vs master cheaply)?
- Do we need a minimal on-wire compatibility window policy across versions?

Proposed Next Steps (when we return)
1) Implement CanarySoak stage + timer in RollingUpdateState (no-op emit path optional).
2) Add binary preservation (/root/prodigy.prev + prev.sig) and transition-to-previous topics for brains/neurons.
3) (Optional) Draft shadowMasterMode interfaces:
   - Emit shim (no-op sink) for decision pipelines.
   - Ingest adapter from mothership reports → decision core inputs.
   - Minimal metrics: divergence score + invariant counters.
