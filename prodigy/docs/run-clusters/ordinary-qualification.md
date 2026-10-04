# Ordinary operation qualification checkpoint

This checkpoint adds bounded ordinary-traffic observation and repairs test
fixtures. It does not qualify ordinary runtime stability or geographic routing.

The client-only scenario requests one three-Brain test cluster through
Mothership, deploys the real Discombobulator standard pingpong artifact, and
specifies 600 requests before and after one controller fault followed by a
20-minute, 48,000-request soak. Mothership owns traffic probes, faults and cleanup.
The probe records every scheduled attempt, including failures, with bounded
output and runtime. Resource snapshots are read-only and explicitly identify
unavailable counters.

The transferred candidate is based on `8efd4f7` with Basics `0.4.13-rc.1`.
The immutable baseline is `5271013` with Basics `0.4.12`; this is not a
source-only comparison. Three slow-map samples per identity passed the unchanged
p95 < 3000 us and maximum < 50000 us gates. Baseline p95 was
1334/1322/1327 us; candidate p95 was 1341/1324/1317 us. Nineteen focused tests,
the corrected full deployment unit, full credentials, and TCX retention passed.
The final deployment-unit receipt records exit 0, 87.734 seconds, and XML 1/1.

The baseline failed resource-readiness bootstrap before deployment or traffic;
the exact cause remains unproven. Candidate bootstrap passed, but the runtime
rejected the frozen host-network application profile. No ordinary traffic,
controller-failover traffic or 20-minute soak has run at this checkpoint.
Mothership cleanup passed for those attempts. There is no comparative throughput,
resource-stability or general performance claim. Replacing the baseline and
amending the host-network profile remain explicit qualification decisions.

The preserved transfer and exact receipts are under
`/Users/victorstewart/prodigy-evidence/platform-completion-transfer-20261004`.
P6's separately completed local stateless migration remains qualified at
`8efd4f7`; these ordinary results neither replace nor broaden that evidence.

## Bug provenance

- The two recovery fixtures lacked the Brain context required by the operation
  they exercised. Their earliest verified retained revision is `d75ab35`,
  **2026-04-11**. Earlier provenance cannot be established because that initial
  checkpoint explicitly has no prior tracked history. `df17b623` on 2026-05-22
  only reformatted the fixtures. The launch-fence check in `8efd4f7` on
  **2026-10-03** exposed the invalid contexts; this repair supplies the existing
  `TestBrain`, Ring and plan fixtures without weakening production admission.
- Provider output capture and its independently hardcoded 64 KiB post-exit
  limit originated in `8efd4f7`, **2026-10-03**. A descendant could retain stdout
  after the direct child exited without being terminated by capture cleanup.
  The new large traffic receipt stream also exposed the duplicated limit.
  Capture now honors one bounded per-call limit, retains the bounded prefix on
  failure, and terminates the traffic probe's process group on timeout.

Author and committer dates agree for the cited origin and exposing commits.
