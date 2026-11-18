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

The Rust SDK suite with Tokio enabled passed 21/21 on Linux ARM64. Shell syntax and git diff whitespace checks passed. The existing dependency-materialization CMake source check fails at line 95 looking for a masque_tunnel version string on both d734e33 and the changed tree. The language exercised end-to-end here was Rust.

| Cause | Origin | Fix |
|---|---|---|
| Deployment and task suffix omitted by Rust | b79f40d, 2026-06-23 | 43ad5cb |
| Child-cgroup vector omitted by Rust | baf0ed2, 2026-07-11 | 43ad5cb |
| Tokio exposes only the health signal | f8db33d, 2026-04-23 | 00b4a61 |
| Mesh runner waits for advertiser health before subscriber submission | b768168, 2026-05-04 | 7f9c9db |
