# /goal: Prodigy resumption key-ring corrective hardening and shrink pass

Execute a focused corrective pass over the current per-wormhole TLS session
resumption key-ring work in `victorstewart/prodigy`.

This goal is not a new feature expansion. It is a hardening, simplification,
line-reduction, and proof pass over the existing worktree. Keep the design terse:
fewest files, fewest knobs, fewest public APIs, no compatibility surface, and no
speculative extension points.

## Hard Boundaries

1. Hard-cut all Prodigy resumption wire/tag/versioning back to V1. This has not
   shipped, so there is no reason to carry V2/V3 tags or migration behavior.
   There must be one current format only.
2. Do not add backward compatibility. Delete stale compatibility paths instead
   of preserving them.
3. The SDKs must only deliver TLS session-resumption key material marked by
   wormhole. Application code owns all TLS/QUIC stack integration and policy
   beyond receiving the wormhole-marked keys.
4. 0-RTT remains out of scope. Do not reintroduce local anti-replay, early-data
   policy knobs, or "safe early data" profiles.
5. Keep per-wormhole opt-in as the only product model. No deployment-wide or
   application-wide key-sharing scopes.

## Required Work

### A. Hard-Cut Wire Tags To V1

- Change core wire tags in `prodigy/wire.h` from `PRDPAR02`,
  `PRDBUN02`, and `PRDDEL02` to the single current V1 tags.
- Change SDK/versioning/docs/fixtures to the same V1 tags and
  `wireProtocolVersion: 1`.
- Remove any V2/V3 naming, docs, fixture metadata, and tests that imply a
  migration path.
- Add a compatibility-matrix assertion that reads `prodigy/wire.h` and proves
  it matches `prodigy/sdk/versioning.json`.

### B. Fix ACK Parsing And SDK Count Bounds

- In `prodigy/brain/brain.h`, make refresh-credential ACK handling strict:
  empty payload means generic non-resumption ACK; non-empty invalid
  `TlsResumptionApplyAck` payload is a protocol error, not a generic ACK.
- In the C++ SDK, add one collection-count bound equivalent to the core/C SDK
  bound and use it for all decoded vector/count fields, including resumption
  snapshots, key rings, resumption ACKs, TLS/API credentials, pairings, and flags.

### C. Wire And Config Hardening

- In `prodigy/wire.h`, validate `TlsResumptionKeyRole` and
  `TlsResumptionProtocol` before appending them to wire output. Bad in-memory
  state must fail serialization early.
- In `prodigy/mothership/mothership.deployment.plan.helpers.h`, keep
  `wormhole.tlsResumption` hard-cut to the supported fields (`sniNames` and
  `alpns`) and reject removed timing-policy fields as unsupported input.
- Add focused tests for the failure cases above.

### D. Prove, Trim, Reprove The Guarded Readiness Probe

- Run the guarded VM E2E readiness smoke before trimming, inside an authorized
  isolated VM boundary with `PRODIGY_DEV_ALLOW_BPF_ATTACH=1`.
- The run must prove TCP+TLS full/resumed handshakes and UDP+QUIC full/resumed
  handshakes with picoquic.
- After the first passing VM proof, heavily trim
  `prodigy/dev/tests/resumption_readiness_probe_container.cpp` and the smoke
  script:
  - remove transient debug branches and excessive diagnostic dumps;
  - remove duplicated cert/client/server scaffolding where a small helper is
    clearer;
  - keep only the evidence needed to prove the actual deployment/container
    path;
  - preserve fail-closed host-safety guards.
- Rerun the guarded VM E2E readiness smoke after trimming.

### E. Shrink SDK Resumption Surface To Delivery Only

- Remove public SDK-owned resumption registries, ticket issuance helpers,
  OpenSSL adapters, picoquic adapters, and policy/application behavior unless a
  minimal raw-delivery primitive truly needs them.
- SDK contract: decode and deliver wormhole-marked resumption key snapshots and
  encode resumption ACKs. The application does everything else.
- Keep secret handling explicit and minimal. Do not log ticket key material.

### F. Remove Rust Formatting Churn

- Revert the rustfmt-wide churn in `prodigy/sdk/rust/neuron_hub.rs`.
- Reapply only semantic Rust SDK changes needed for the current V1 wire format
  and resumption key delivery contract.
- Keep any formatting-only Rust changes out of this feature diff.

### G. Runtime Terseness And Cleanup

- Add one `mintNextTlsResumptionGeneration()` helper in `prodigy/brain/brain.h`
  and replace repeated increment/wrap logic.
- Collapse snapshot-delta and removal-delta container fanout into one helper
  that serializes a `CredentialDelta` and sends it to eligible containers.
- Evaluate folding ACK state into per-wormhole resumption state only if it
  deletes meaningful cleanup code. If it does not reduce net complexity, leave
  it alone.
- Replace `ProdigyTransportTLSRuntime` heap allocation for its static ticket
  context with inline/static storage and remove the allocation failure branch.

### H. Strengthen Compatibility Matrix

- Extend `prodigy/sdk/compatibility_matrix.sh` so it directly validates
  `prodigy/wire.h` magic constants against `prodigy/sdk/versioning.json`.
- The matrix must fail if core runtime tags and SDK/fixture tags diverge.

### I. Final Full E2E Run

- After all blockers and shrink work are complete, run the guarded full E2E
  readiness smoke in the authorized isolated VM boundary:

```bash
PRODIGY_DEV_ALLOW_BPF_ATTACH=1 \
  prodigy/dev/tests/prodigy_dev_resumption_readiness_smoke.sh
```

- Report exact command, environment boundary, result, and artifact/log paths.
- If the run cannot be executed safely on the current host, stop and state the
  missing VM/isolation condition instead of faking proof.

## Verification Checklist

- `git diff --check`
- `bash -n prodigy/dev/tests/prodigy_dev_resumption_readiness_smoke.sh`
- Focused build for touched C/C++ targets with `-j$(nproc)`.
- Focused unit tests for wire, parser, Brain credential ACK/lifecycle, SDK C++,
  SDK compatibility matrix, persistent state, and transport TLS.
- Rust SDK check/test if the local toolchain supports it.
- Guarded VM E2E before probe trimming.
- Guarded VM E2E after probe trimming.

## Completion Criteria

The goal is complete only when:

1. Wire/versioning is hard-cut to one V1 format across core, SDKs, docs, and
   fixtures.
2. SDK public resumption scope is delivery-only and wormhole-marked.
3. ACK parsing, wire validation, parser bounds, and SDK count bounds are strict.
4. The probe is materially smaller after a real passing VM proof.
5. The final guarded VM E2E passes after trimming.
6. The final response includes LOC before/after for this corrective pass and
   names any remaining cleanup candidates.
