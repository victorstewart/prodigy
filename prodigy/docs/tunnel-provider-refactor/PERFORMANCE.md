# Tunnel Provider Refactor Performance Evidence

## Verified

- 16-vCPU VM guest confirmed with `nproc`.
- Focused C++ target build completed with `--parallel 16`.
- BPF object builds completed for host ingress and container egress routers.
- Focused BPF runtime tests passed under `PRODIGY_DEV_ALLOW_BPF_ATTACH=1`.

## Size Snapshot

RelWithDebInfo artifacts from `.run/tunnel-provider-latest`:

| Artifact | Bytes |
|---|---:|
| `prodigy` | 88061376 |
| `mothership` | 58234336 |
| `mothership-tunnel-provider` test fixture | 1396360 |
| `host.ingress.router.ebpf.o` | 454296 |
| `container.egress.router.ebpf.o` | 427800 |

## Not Yet Measured

- Clean build wall time.
- Incremental build after touching `mothership.cluster.types.h`.
- Before/after binary and object sizes against the draft feature baseline.
- 100,000 no-op reconcile counter proof.
- Artifact ingest byte/hash/signature counters.
- Gateway throughput and request latency.
- BPF instruction counts and map-operation counts against `main`.

These are remaining evidence gaps relative to the downloaded goal.
