# Prodigy dependency startup and fault recovery

Merged revisions [43ad5cb](https://github.com/victorstewart/prodigy/commit/43ad5cbca393a0b9a334e0bd5633a3ed53436c48), [00b4a61](https://github.com/victorstewart/prodigy/commit/00b4a61ede6c40b699068e121644edd7f61fe8e0) and [7f9c9db](https://github.com/victorstewart/prodigy/commit/7f9c9dba0a07e00eae86e15b122063a207ab7df4).

## Measurement

Mothership created three Brain machines in its test datacenter inside the pinned ARM64 Apple Linux guest. Discombobulator built the Rust SDK application. The two deployment plans reserve a named service and run an advertiser and a subscriber. The subscriber binds its private IPv6 address, accepts a pairing from Neuron, exchanges three TCP ping/pong rounds, then signals healthy. A timestamp in the subscriber and an independent Mothership application report provide separate data and control observations. Fresh clusters and deployment IDs prevent cached success from satisfying these checks.

The workload has one stateless service dependency. Its serving operation is three short messages. Database startup, durable database writes, migrations, failover of a stateful writer and a wide fan-out graph are outside these measurements.

Baseline runtime and Mothership are identical throughout. The SDK links into the application artifact. Artifact hashes, both application plans, machine identities, endpoint logs and cluster removal receipts are in each trial directory.

## Startup

At d734e33, Mothership accepted the advertiser in 46 ms. The Rust decoder read the wrong offsets in the Neuron startup projection. Six crashes, zero healthy instances and no dependency exchange were observed through the 42-second window. With only the decoder repaired, the advertiser was healthy in 571 ms in the instrumented run. The subscriber remained running with zero crashes but received no pairing for 68.8 s. The Tokio example had reported application health without declaring runtime readiness, which Brain requires before releasing a pairing. These runs are right-censored. There is no finite speedup denominator or stock-main chaos baseline.

The successful cross-machine experiment alternated serial and overlapping placement submissions. Each trial used a fresh three-machine cluster with two isolated logical cores requested per application. Both actual endpoints were verified on different machines. In both variants Mothership acknowledged each plan and reported both applications healthy. One immutable app (SHA-256 0fc25ad10d1d790d505af8b10c3b3e709f38cccf920f1844fb448df82ca8f557) served all six trials. The component program, plan, fault hold and socket exchange were identical. Each operator acceptance returned after submission. The serial control waited for advertiser health before submitting the subscriber. The overlapping variant submitted it immediately after advertiser acceptance. Figures are medians with full observed ranges, three trials per variant.

| Elapsed time | Serial | Overlapping |
|---|---:|---:|
| Cluster create to all three machines ready | 2,376 ms (2,336–2,571) | 2,334 ms (2,332–2,890) |
| Advertiser submit to acceptance | 35 ms (34–42) | 40 ms (32–54) |
| Advertiser submit to subscriber submit | 490 ms (416–513) | 44 ms (35–59) |
| Subscriber submit to its first successful exchange | 388 ms (379–666) | 411 ms (380–446) |
| First deploy to first successful exchange | 892 ms (804–1,156) | 455 ms (415–505) |
| First deploy to both reported healthy | 918 ms (820–1,206) | 506 ms (467–564) |
| Cluster create to both applications reported healthy | 3,558 ms (3,218–3,684) | 2,908 ms (2,861–3,525) |

The median submission gap fell by 446 ms. First payload moved forward by 437 ms. The sample size supports reporting the observed ranges. Reports poll at roughly 100 ms plus CLI latency, so the payload timestamp is the more precise startup measure. The tracked SDK matrix also checks both applications after submission and retains its ordinary health polling cadence.

## Chaos

Mothership injected each fault after a complete exchange. The analysis uses the provider’s actual down/up timestamps for link faults, selected machine boot time for crashes, subscriber payload timestamps for service, and repeated three-member, single-master, runtime-ready reports for stable control-plane confirmation. The one-second application probe and roughly half-second control polls limit resolution. A healthy report alone never proves that service returned.

For six cross-machine advertiser-link cuts, the provider held the link down for about 12 seconds. No dependency exchange completed during any witnessed down interval. The serial runs observed the first exchange 361, 714 and 2,705 ms after link restoration. The overlapping runs observed 364, 681 and 684 ms. The 2,705 ms case also isolated the current master. A new master was observed 7.07 s after link-down. Stable control plus fresh data was confirmed in 13.77–17.04 s from link-down across the six runs. The placement/order experiment does not establish improved link failover latency.

A separate disk-backed trial crashed the master hosting both processes for a requested 12 s. Another master was visible at 2.34 s, the selected machine’s new boot was at 12.23 s, the first fresh payload at 12.81 s and stable cluster plus application recovery at 14.41 s. In another run the workloads were on a different node and sent twelve successful application heartbeats during the master hold. Machine failover and application outage depend on placement.

Six further trials crashed the advertiser’s machine while the subscriber lived on a different machine. The probe followed live Neuron pairing activations and removals so it could try a replacement endpoint. A preliminary probe pinned its first endpoint and continued dialing a retired address after Brain delivered the replacement. We excluded that probe from crash-recovery timings. Both submission orders in the corrected trial used the same app digest, `829934613ba2db33bdbfb420abac66f75d254bef1533442902e35fb496ab2789`. They used the checked-in SDK matrix's submission and health-polling functions.

| Advertiser crash while machine held down for 12 s | Trials | Observed recovery stages measured from provider crash |
|---|---:|---|
| Advertiser on a follower | 4 | Replacement artifact materialization observed on another machine at 2.222–2.295 s. First payload at the replacement address at 2.533–2.597 s. |
| Advertiser on the master | 2 | Another master visible at 2.308–2.318 s. Original machine boot at 12.324–12.357 s. First payload on the original endpoint at 13.548–13.792 s. |
| Stable cluster and fresh payload confirmed | 6 | All three original machine UUIDs, the changed boot identity and a single master confirmed in 13.817–14.525 s. |

Both submission orders had two follower crashes and one master crash. Median crash-to-first-payload was 2.587 s with serial submission and 2.597 s with overlapping submission. Placement accounted for the large observed difference. On the master-loss path, Brain's `finalizePersistedNeuronInventoryRecovery` checks that every live machine has supplied authoritative inventory before scheduling resumes. The stage traces establish when the endpoint returned. They do not identify the exact inventory check outstanding on each turn.

| Trial | Submit order | First payload after deploy | First payload after crash | Advertiser hosted on |
|---:|---|---:|---:|---|
| 1 | Serial | 1000 ms | 2,533 ms | Follower |
| 2 | Overlapping | 431 ms | 2,539 ms | Follower |
| 3 | Serial | 954 ms | 2,587 ms | Follower |
| 4 | Overlapping | 452 ms | 13,548 ms | Master |
| 5 | Serial | 987 ms | 13,792 ms | Master |
| 6 | Overlapping | 445 ms | 2,597 ms | Follower |

With the SDK matrix’s ordinary polling cadence, median first payload went from 987 to 445 ms and both observed healthy went from 1,178 to 650 ms across this second set of deployments.

## Evidence and checks

The disk-backed trial paired-order/3 suffered a guest block-device write error at 106.378 s of guest uptime. Linux forced the provider’s loop-backed Btrfs filesystem read-only at 106.381 s. Brain subsequently logged repeated rejected snapshot writes. This occurred during the link cut, after down at 99.57 s and before up at 111.58 s. Its link result is excluded from the performance comparison. Mothership removed the cluster. For the six controlled split-placement trials, only Mothership’s scratch image backing changed to a bounded private 2 GiB tmpfs in the enclosing guest. Mothership still created, installed and faulted the same machine filesystems and programs. These timings do not characterize physical disk durability.

The pinned guest used `archlinuxarm-toolchain:cmake-4.4.0`, image `527a25740563a9c1f4938eb0b753aee01130ceda609a824793ba3340ae704b45`, ten allocated CPUs and 24 GiB of memory. Each of the three test machines was configured with four logical cores, 8,192 MiB of memory and 8,192 MiB of storage. Prodigy binary SHA-256 was `7b8d4f8108b7b5055eb31de166d15b28159e79cb8eeccb202f3b7382691ffa68`. Mothership binary SHA-256 was `a10b067a56ccc1f3320d66d303b0e100322138c204825c7f0b87c7d59186f8c5`.

Mothership accepted the two example plans with `deploy <cluster> <plan-json> <app-blob> --submit-only`. The observer used `applicationReport`, `clusterReport` and `containerLogs`. After the first verified exchange, it called `faultTestCluster <cluster> link|crash <advertiser-machine-index> 12000 0 0 0`. Every controlled trial recorded a successful `removeCluster`, verified that the provider manifest disappeared, and completed guest cleanup through the official boundary launcher. Mothership owns machine creation, installation, start, fault injection and removal.

Raw run directories in the measurement checkout are under `.run/e2e-app-recovery-20261118/guest-files/runs/`. The two controlled series are `cross-placement/1..6` and `ram-matrix-pairs/1..6`. Each contains the application and cluster reports, deployment inputs, timestamped payload evidence, direct fault witnesses and cleanup receipts.

The Rust SDK suite with Tokio enabled passed 21/21 on Linux ARM64. Shell syntax and git diff whitespace checks passed. At that revision the dependency-materialization CMake check failed at line 95 on both trees. Commit fd36cc1 subsequently repaired the check. The preceding trials used the in-container Rust SDK. The native C++ trials appear below.

| Cause | Origin | Fix |
|---|---|---|
| Deployment and task suffix omitted by Rust | b79f40d, 2026-06-23 | 43ad5cb |
| Child-cgroup vector omitted by Rust | baf0ed2, 2026-07-11 | 43ad5cb |
| Tokio exposes only the health signal | f8db33d, 2026-04-23 | 00b4a61 |
| Mesh runner waits for advertiser health before subscriber submission | b768168, 2026-05-04 | 7f9c9db |

## Control-plane persistence and container launch

The three-machine test above supplied the runtime baseline. We compared the same Rust app artifact in three deployments and advertiser-machine crashes on each build. The original Brain logged 92, 90 and 92 rejected ordinary snapshot submissions because all eight job slots were occupied. It had already captured the control model, accounted its size and detached the snapshot for the writer. Commit e665cc6 checks for a full job queue first and uses the existing candidate submission path for exact byte admission. Receipt-bearing calls still return failure immediately on rejection. Ordinary calls schedule a single retry which captures the latest state after capacity returns.

A Linux ARM64 benchmark filled the real ArtifactIO queue with eight held jobs and invoked the production Brain method 100 times per run. It used two peer records and 192 metric observations. The explicit failure receipt and subsequent durable generation 117 were checked on each run. With tracing disabled and stderr on guest tmpfs, the three baseline batches took 1.251, 0.922 and 0.888 ms in total. The changed batches took 0.021, 0.006 and 0.006 ms. Median per-call time across the middle run went from 8.17 µs to 0.041 µs. This includes the cost of the old synchronous rejection diagnostic. Normal cluster measurements showed little change.

| Event from start of first deploy, median of three | Baseline | Snapshot change |
|---|---:|---:|
| First verified Rust dependency reply | 429 ms | 428 ms |
| Both apps observed healthy | 651 ms | 644 ms |
| First verified reply after advertiser-follower crash, measured from fault onset | 2,570 ms | 2,519 ms |

In three further successful deployments, gated Neuron timestamps separated storage, clone, identity, netkit, egress and ingress setup. In the first, the advertiser reached rootfs-ready at 144 ms, storage-ready at 144 ms, clone and identity at 147 ms, and host networking at 148 ms. Egress was installed at 298 ms and ingress at 407 ms. The process-started marker was at 407 ms, with Brain health at 411 ms. The subscriber showed the same pattern. A separate diagnostic deployment was accepted but never reached launch within the health observation window. Only one follower's metadata echo was observed per deployment there. The provider removed that cluster and the three independently recreated clusters completed. Its missing latency is excluded from the successful timing distribution.

We also deployed three Rust advertisers with one per machine and one subscriber, verified placement through Mothership, then crashed the master for 12 s. When the subscriber lived on another machine it produced 12 successful replies during the outage, the first at 650 ms. The first two samples placed the subscriber on the master. Their first fresh replies came at 14.08 and 12.88 s. The surviving-subscriber observation does not identify which advertiser served its pre-fault connection. With a sole advertiser on the failed master, the new master still requires authoritative live-machine inventory before scheduling. Election and serving recovery are distinct events.

The full runtime-persistence unit suite passed on ARM64 after commit 5958040 corrected the event-ring fixture in the inventory diagnostic test. Its constructor previously aborted before the assertions on both the baseline and the snapshot-change build. The dependency check passed for version-first and namespace-first manifests, with separate rejection cases for stale versions and duplicate records.

## Native C++ HTTP dependency

The advertiser was the repository's `hello_prodigy_v1` executable. A second C++ application used `NeuronHub` and `Ring`, subscribed to the advertiser, opened an IPv6 TCP connection, requested `GET /healthz`, and required both HTTP 200 and the exact v1 response body. It declared runtime readiness when it could receive a pairing and application health after its first valid response. Mothership deployed them on different machines in a three-machine test cluster. We used an internal service advertisement on port 8080 so the subscriber exercised a real mesh pairing. The example's public-ingress plan was outside this measurement. The probe runs once per second after success and retries after a failure or pairing change. Timings are first witnessed responses at that cadence.

The original ARM64 example executable requested `/lib/ld-linux-aarch64.so.1`. Its `FROM scratch` build failed Discombobulator's target-runtime closure check before either application could run. Commit `797bc27` introduced this combination on 2026-09-06. The stricter target-workspace closure in `2b49ffe` on 2026-10-31 exposed it. Commit `ab9b583` made v1 and v2 self-contained. Both packaged through the real `--kind app` path. All native timing controls use a packageable static executable.

The original recipe also copied 1,077,928 bytes of router objects into the build workspace. Inspection of both Discombobulator Btrfs send streams showed that the original length was 8,386,579 bytes and the shortened recipe produced 8,386,087. Both streams wrote the same 8,375,168-byte executable and 134-byte launch metadata. The old artifact retained two extra directories. The compressed artifacts were 3,234,271 and 3,234,130 bytes. Removing those build inputs saved 141 bytes on the wire in this build. Neuron obtains the live routers from its runtime bundle.

Commit `f81f5c8` lets the linker discard unused sections and strips the copy shipped in the app. The local executable retains its symbols. Link-time section removal alone produced a 3,186,593-byte v1 artifact. Stripping the shipping copy brought it to 2,869,233 bytes, 11.3% below the static control. The executable inside went from 8,375,168 to 6,896,056 bytes. v2 also packaged successfully. The comparison used the same subscriber bytes throughout.

| Native C++ event, median (range), three deployments per column | Baseline runtime, full app | Updated runtime, full app | Updated runtime, smaller app |
|---|---:|---:|---:|
| Create cluster to three machines reported ready | 2,467 (2,354–2,580) ms | 2,358 (2,344–2,457) ms | 2,399 (2,367–2,402) ms |
| Deploy to first verified HTTP response | 688 (446–688) ms | 447 (398–711) ms | 696 (694–717) ms |
| Deploy to both applications reported healthy | 1,167 (677–1,206) ms | 658 (651–936) ms | 715 (715–1,200) ms |
| Create cluster to both applications reported healthy | 3,639 (3,246–3,816) ms | 3,181 (3,062–3,366) ms | 3,186 (3,180–3,635) ms |

In the three smaller-app runs the master was elected 1,022–1,026 ms after cluster creation. The last Neuron inventory was ready at 1,542–1,591 ms. Brain recorded the last Neuron runtime-ready at 2,220–2,227 ms. One additional updated-runtime run timed out during cluster configuration at 120 seconds, before application submission. Its missing startup latency is excluded.

The timing difference between deployments depended on when Brain dispatched the subscriber. In the two fastest updated-runtime controls it dispatched the subscriber at 103 and 105 ms after initial deploy, while the advertiser was still starting. In the 711 ms control it dispatched at 402 ms, after the advertiser process started at 382 ms. All three smaller-app trials had this latter ordering. This experiment establishes a byte saving. It does not establish a reduction in end-to-end startup latency. Across the updated launches, the measured egress setup took 137–167 ms and the following ingress setup took 104–128 ms, including replacement launches.

Two additional diagnostic runs used the Brain readiness markers in `2143bc4` and timed the actual libbpf calls on the Neuron launch path. Each included an initial advertiser, a subscriber and an advertiser replacement, giving 12 direction-specific object loads. Opening an ELF took 0.267–0.831 ms. Each successful object load took 90.8–134.9 ms, including 0.80–1.09 ms in map creation and 0.031–0.052 ms in BTF loads. The kernel program-load calls consumed **1,320.756 of 1,336.896 ms (98.8%)** inside the object loads. This includes verification and other kernel load work. The measurements do not separate verifier and JIT time. The declared-network ingress program reuses a flow map pinned by egress, so parallelizing both complete loads would change their dependency ordering.

### Native recovery from advertiser failure

Mothership held the advertised machine down for 12 seconds. Of nine ordinary runs, seven lost an advertiser on a follower. The first confirmed HTTP response at a different address came at 12.220–12.483 s. The other two lost an advertiser on the master. Their first responses came at 12.807 and 13.001 s. All nine runs verified a fresh payload and a stable recovered cluster. Two more instrumented follower crashes reproduced the control-plane delay.

| Time from crash | Diagnostic 1 | Diagnostic 2 |
|---|---:|---:|
| Replacement healthy and Neuron receives runtime-ready | 2,543 ms | 2,417 ms |
| Brain records readiness held for Switchboard wormhole acknowledgements | 2,543 ms | 2,417 ms |
| Acknowledgements complete and Brain releases runtime readiness | 12,411 ms | 12,336 ms |
| Subscriber receives activation and verifies the HTTP response | 12,411 ms | 12,337 ms |

Hello reports healthy before it reports runtime-ready. For a stateless deployment, health starts a fleet Switchboard transaction, including when the desired external route set is empty. Brain retains the subsequent runtime-ready notification until the tracked machines acknowledge the routing revision. The native subscriber's old endpoint attempts timed out in roughly a quarter of a second. After activation it verified the replacement response in 0 and 1 ms. The roughly ten-second interval was spent waiting for routing acknowledgements. The Rust advertiser reports runtime readiness before application health. In those runs the subscriber received its pairing before health started the routing transaction. The two workloads followed different recovery paths. The fleet contract explicitly covers empty revisions and disconnected live machines. Container route IDs include a reusable eight-bit fragment. Bypassing the withdrawal acknowledgement on an empty plan would need independent evidence that the ID has no stale route.

Mothership issued successful removal receipts for all 11 completed native test clusters. The full-app harness also emitted a shell diagnostic after the third updated-runtime control finished. The three individual exit codes, payload checks and removal receipts were verified. The separate 120-second configuration timeout produced no completed-cluster receipt. The disposable guest for that failed batch stopped through the boundary launcher. This workload covers one internal HTTP dependency and advertiser-machine failure. A database election, log catch-up or storage promotion would add its own recovery work.
