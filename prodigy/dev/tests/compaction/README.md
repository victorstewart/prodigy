# Bounded constructive compaction experiment

This is a planner-only experiment. It calls the existing
`ApplicationDeployment::compact(deltas, false)` for the baseline and tests a
bounded search for an ordered sequence of constructive moves. It never creates
deployment work, starts a server or Ring, moves a live container, or launches a
cluster. The production planner is unchanged.

The witness has three hosts with these CPU/memory capacities:

| Host | Capacity | Resident workload | Initially free |
| --- | --- | --- | --- |
| A | 4 cores / 4096 MB | X: 2 cores / 4096 MB | 2 cores / 0 MB |
| B | 3 cores / 4096 MB | Y: 1 core / 2048 MB | 2 cores / 2048 MB |
| C | 1 core / 2048 MB | None | 1 core / 2048 MB |

The pending application requires 4 cores / 4096 MB. A cannot move X directly
to either recipient. Moving Y from B to C first makes room for X on B, freeing
A for the pending instance. Each destination has capacity before its source is
credited, so this sequence needs no destruction-first move or temporary extra
machine.

The candidate uses iterative deepening for the fewest moves in its bounded
neighborhood: at most three machines, six resident containers, three moves, and
2,048 expanded search nodes across all depths. Each resident can move only once.
Node exhaustion and unsupported inputs are explicit results. A failed search
does not prove global infeasibility.

Eligibility, quiescence, readiness, compatibility, external placement, scalar
resource fit and rack/machine concentration checks reuse their production
owners. Speculative concentration counts are applied only to disposable fixture
objects and immediately restored. Destination slot reservations are conservative:
the experiment does not reuse slots freed by earlier moves. It admits one
pending stateless base instance and rejects GPU/stateful target placement;
donors must be movable stateless workloads configured for constructive moves.
Production scheduling would need to represent dependencies across deployments
before consuming such a sequential proposal. This experiment provides no live
scheduling or recovery guarantee.

On macOS, run Linux commands only inside a verified pinned Apple Linux guest,
using an external instance config and `~/apple-linux-dev/bin/dev-container`.
Configure the existing dev CMake project with the guest's pinned Depos settings:

```sh
cmake -S prodigy/dev -B .run/compaction/release -G Ninja \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Release -DPROJECT_ENABLE_TESTS=ON
cmake --build .run/compaction/release --target prodigy_compaction_search_unit -j4
ctest --test-dir .run/compaction/release \
  -R '^prodigy_compaction_search_unit$' --output-on-failure
taskset -c 0 .run/compaction/release/prodigy_compaction_search_unit --benchmark \
  > .run/compaction/benchmark.csv
```

The target shares the existing dev dependency graph and exported Depos targets.
Its Clang-only `-fno-access-control` option allows calling the private dry-run
compactor without changing the production API. For sanitizers, configure another
task-owned build with `-fsanitize=address,undefined -fno-omit-frame-pointer` in
both C++ and linker flags and `-DPRODIGY_BASICS_MIMALLOC_MODE=NONE`.

The benchmark measures planning quality and planner time, including speculative
state setup and search, but excluding fixture construction. The baseline is the
current greedy compactor plus the ordinary direct-fit check. The candidate keeps
that answer when successful and searches only after failure. The target is to
admit the named two-move witness while preserving existing successes and meeting
2 ms p95 planner time on each small fixture. The benchmark varies the candidate
neighborhood across all six machine orders and both donor orders for the
witness, direct-fit, one-move and impossible controls: 48 rows of 30 samples,
alternating A/B timing order. The production baseline retains its own internal
ordering and is timed again alongside each candidate query on the same fixture.
CSV workload suffixes identify candidate-order permutations, not distinct
baseline orders or independent placement fixtures. It retains individual
measurements and search counts. The CSV `moves` column counts search-proposal
moves only; baseline successes skip search and therefore report zero there.
Returned proposal destruction and fixture construction are outside the timer;
baseline input setup and speculative search-state setup are included. Candidate
input lists are prepared before the timer, as part of the supplied neighborhood.
Evaluate at most three mechanisms; this phase uses one bounded search mechanism.
The task's `.run/compaction-*` directory owns disposable build state and retained
evidence. Stop the guest after the Linux slice ends.

## Observed comparison, 2026-10-27

Baseline source: `5ab14781ec45c02108711ae1bbebb6e3e8966e95`. Release build,
Clang 22.1.6, GNU C++26, `-O2`, pinned Arch Linux ARM Apple Container on an
Apple M2 Max (4 guest CPUs, 8 GiB RAM), pinned to guest CPU 0;
30 individual paired queries for each of 12 candidate orders per fixture.
The admission counts below are repeatability samples of four constructed
fixtures, not a production workload distribution.

| Fixture | Baseline admissions | Candidate admissions | Worst candidate-order p95 |
| --- | ---: | ---: | ---: |
| Two-move witness | 0/360 | 360/360 | 16.250 us |
| Direct fit | 360/360 | 360/360 | 0.583 us |
| One-move fit | 360/360 | 360/360 | 7.708 us |
| Impossible (5-core target) | 0/360 | 0/360 | 35.625 us |

Every witness proposal is Y: B→C followed by X: A→B, then target admission on A,
with six expanded nodes. The witness median planner time is 1.833 us for the
baseline and 7.042 us for the candidate including the baseline attempt. This is
a planning-quality improvement on the witness, with additional computation;
it is not a speedup or a claim of production-wide capacity savings.

The run explicitly selected Basics 0.4.12 and used the workspace's existing
upstream TidesDB 10.0.1.20260919.210236 recipe. That pre-existing local dependency
override is not part of this experiment's commit; no database path is exercised.
Raw CSV, configure commands, registry identities and validation logs are retained
under `.run/compaction-search-20261027/` on the test machine.

The isolated CTest passed in Release and with AddressSanitizer plus
UndefinedBehaviorSanitizer (leak detection enabled, mimalloc disabled for the
sanitizer build). The benchmark's admission, exact witness sequence, fixture
preservation and per-row latency checks passed for all 1,440 paired samples.

Two pre-existing dependency recipes needed repairs to reach these checks:

- libseccomp: retain shipped generated files after staging changes mtimes.
  The timestamp-sensitive recipe is first verified in `f8db33db` (2026-04-23).
- nghttp2: use its CMake build to avoid regeneration by versioned Autotools.
  The Autotools recipe is first verified in `f8db33db` (2026-04-23); the current
  1.69.0 pin arrived in `9eda4055` (2026-05-22).

The exact first failing revisions are not established: these failures depend
on source-staging timestamps, and were exposed by this fresh dependency build.
Both repairs preserve the existing pinned upstream versions and checksums.
