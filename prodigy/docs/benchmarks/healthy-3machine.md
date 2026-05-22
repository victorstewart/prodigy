# Time to healthy 3-machine cluster

This benchmark measures the time from `mothership createCluster` to the first healthy confirmation reported by the cluster for cheap 3-machine / 3-brain clusters.

These are project benchmark artifacts, not vendor-certified third-party benchmarks. They are useful because they expose where time is spent: most live cloud runs are dominated by provider wait time, not Prodigy runtime work.

## Fresh March 27, 2026 runs

| Rank | Cloud | Machine shape | `createCluster` | First healthy confirmation | Create -> first healthy | Provider wait | Notes |
|---:|---|---:|---:|---:|---:|---:|---|
| 1 | AWS | `t3.micro` | 62.491s | 1.917s | 64.408s | 68.475% | Cleanup was clean; `removeCluster` completed in 5.004s. |
| 2 | Azure | `Standard_D2als_v6` | 93.368s | 1.723s | 95.091s | 89.895% | Provider wait dominated the run. |
| 3 | GCP | `e2-medium` | 98.427s | 1.995s | 100.422s | 86.035% | Provider wait dominated the run. |
| 4 | Vultr | `vx1-g-2c-8g` | 112.081s | 1.722s | 113.803s | 94.995% | VPC/network setup is part of the cloud path. |

## Best healthy timings currently on record

| Cloud | Best `createCluster` | Best create -> first healthy | Notes |
|---|---:|---:|---|
| AWS | 57.708s | 59.278s | Best overall observed path. |
| Vultr | 63.682s | 65.843s | Best Vultr path was materially faster than the freshest rerun. |
| Azure | 67.230s | 95.091s | 67.230s is the best create time on record; 95.091s is the freshest normalized create-to-healthy result. |
| GCP | 98.427s | 100.422s | Freshest healthy run is also the best currently listed. |

## AWS phase attribution

From `.mothership-live-aws-3brain-matrix-20260327-010815/createCluster.out`:

| Phase | Time | Attribution |
|---|---:|---|
| Overall | 62.491s create / 64.408s create-to-healthy | 68.475% provider wait, 31.525% runtime-owned |
| `createSeedMachine` | 9.314s | 99.993% provider wait |
| `bootstrapRemoteSeed` | 18.793s | 95.784% runtime-owned |
| `configureSeedCluster` | 0.700s | 100.000% runtime-owned |
| `upsertMachineSchemas` | 30.516s | 100.000% provider wait |

## AWS cleanup verification

From the same run:

```text
.mothership-live-aws-3brain-matrix-20260327-010815/postCleanup.instances.json
.mothership-live-aws-3brain-matrix-20260327-010815/postCleanup.volumes.json
```

## Interpretation

Prodigy's local runtime path is already short enough that the cloud provider is usually the bottleneck. That is the right performance profile for an orchestrator that provisions real machines: optimize the runtime until provider wait dominates, then make provider wait visible and attributable.

## Benchmark matrix to keep fixed

| Benchmark | Measure |
|---|---|
| 3-machine create time | `time mothership createCluster ...` |
| First healthy confirmation | First cluster report showing all expected machines and brains healthy |
| Removal time | `time mothership removeCluster ...` |
| Provider wait percentage | Time blocked on provider APIs or instance readiness |
| Runtime-owned percentage | Time spent in Prodigy bootstrap/configuration work |
| Residual cloud resources | Instances, disks/volumes, templates, NICs, IPs, VPCs, and resource groups after cleanup |
| Cost comparison | Same machine shape, same region, same duration, same workload set, compared against Kubernetes/Nomad/ECS-style deployments |

## Artifact requirements

When adding a new benchmark, commit or record:

- command;
- provider;
- region/zone;
- machine shape;
- image;
- Prodigy build identifier;
- raw output path;
- cleanup proof;
- residual resource check.
