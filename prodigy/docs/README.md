# Prodigy documentation

This directory holds operational documentation that should not live in the root README.

## Core docs

| Topic | Document |
|---|---|
| Build | [`build.md`](build.md) |
| Runtime startup and state | [`runtime.md`](runtime.md) |
| Security model | [`security.md`](security.md) |
| Discombobulator | [`discombobulator.md`](discombobulator.md) |
| IaaS adapters | [`iaas-adapters.md`](iaas-adapters.md) |
| Packet budgets | [`network-packet-budgets.md`](network-packet-budgets.md) |

## Cloud runbooks

| Provider | Runbook |
|---|---|
| AWS | [`runbooks/aws.3brain.cheap.md`](runbooks/aws.3brain.cheap.md) |
| Azure | [`runbooks/azure.3brain.cheap.md`](runbooks/azure.3brain.cheap.md) |
| GCP | [`runbooks/gcp.3brain.cheap.md`](runbooks/gcp.3brain.cheap.md) |
| Vultr | [`runbooks/vultr.3brain.cheap.md`](runbooks/vultr.3brain.cheap.md) |

## Benchmarks

| Benchmark | Document |
|---|---|
| 3-machine create-to-healthy | [`benchmarks/healthy-3machine.md`](benchmarks/healthy-3machine.md) |

## SDK and workload protocol

The workload/runtime protocol is documented under [`../sdk/`](../sdk/). Start with:

```text
prodigy/sdk/INTERFACES.md
prodigy/sdk/WIRE.md
prodigy/sdk/CONTRACT.md
prodigy/sdk/fixtures/
```
