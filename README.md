<p align="center">
  <img src="assets/prodigy-logo.avif" alt="Prodigy logo" width="260">
</p>

# Prodigy

**A vertically integrated orchestration runtime for containers, machines, agents, databases, and high-density services.**

Prodigy manages machine lifecycle, container lifecycle, cluster membership, routing, placement, bootstrap, health, and runtime updates as one coordinated system.

Package your workload, provide a deployment plan, and Prodigy can provision machines, install itself, seed the cluster, place containers, route traffic, monitor health, and replace failed capacity.

Prodigy supports the same programming model across:

- local development;
- private infrastructure;
- cloud infrastructure.

## Build from source

Prodigy is currently source-built. Binary releases are not published yet.

```bash
git clone https://github.com/victorstewart/prodigy.git
cd prodigy
```

Requirements:

- Linux kernel 7.0 or newer for runtime/container/networking work;
- CMake;
- a C++20-capable toolchain;
- Rust and Cargo for Discombobulator;
- root or equivalent capabilities plus a proven isolation boundary for local networking, namespace, container, cgroup, BPF, and filesystem tests.

Discombobulator, Prodigy's container-runtime artifact builder, can be built directly:

```bash
cargo build --release --manifest-path prodigy/discombobulator/Cargo.toml
```

The Prodigy runtime and `mothership` use the repository's C++/CMake/Depos project configuration. See [`prodigy/docs/build.md`](prodigy/docs/build.md) for the full build contract and the current build-entrypoint notes.

For native Apple Silicon development under Apple Containerization, see
[`prodigy/dev/apple-container-kernel/`](prodigy/dev/apple-container-kernel/)
for the pinned arm64 kernel profile with Prodigy's BPF, Netkit, Btrfs, and
Landlock requirements.

Runtime networking requirement:

```bash
sudo sysctl -w net.ipv4.tcp_fastopen=3
```

For persistence, set this in the host sysctl configuration:

```text
net.ipv4.tcp_fastopen = 3
```

TCP Fast Open must be enabled on hosts that run Prodigy. The kernel setting enables client and server support; the runtime path must also use TFO-capable sockets where required.

Privileged runtime tests can touch host networking, BPF, cgroups, loop devices, mounts, and container roots. Run those tests only inside a disposable VM or another harness that proves namespace, cgroup, capability, and filesystem containment before touching system-level state.

## What Prodigy provides

| Capability | Meaning |
|---|---|
| Integrated runtime | One runtime owns local control, state, networking, containers, health, and updates. |
| Machine + container orchestration | Prodigy can create machines, bootstrap them, form a cluster, and place containers. |
| Runtime/workload protocol | Containers receive startup state, topology, resource changes, credentials, and health handshakes through a versioned protocol. |
| Cloud-aware capacity | IaaS adapters acquire, tag, account for, repair, and destroy provider machines. |
| Stateful-system support | Databases can use Prodigy for seeding, peer updates, placement, health, repair, and replacement. |
| Local-to-datacenter model | The same control model supports local development, private infrastructure, and cloud clusters. |

Prodigy also offers per-wormhole TLS session-resumption key-ring distribution for resumed TCP+TLS/QUIC traffic. A deployment opts in on each declared wormhole rather than globally, and Prodigy distributes that wormhole's resumption keys to healthy containers serving it so valid resumed traffic does not need affinity to the original container that issued a ticket. 0-RTT is not supported until Prodigy has a deployment-wide replay-prevention boundary. Switchboard remains routing-only: it does not inspect TLS tickets and does not store TLS ticket secrets. These TLS resumption ticket keys are separate from QUIC CID routing keys, TLS certificate keys, and API credentials.

## Architecture

Prodigy is organized around six cooperating pieces.

### Mothership

`mothership` is the operator and automation client. It creates provider credentials, creates clusters, inspects cluster reports, updates machine schemas, deploys applications, updates Prodigy itself, and removes clusters.

Common commands:

```bash
./mothership createProviderCredential '<provider credential json>'
./mothership createCluster '<cluster json>'
./mothership clusterReport '<local|cluster-name|cluster-uuid>'
./mothership upsertMachineSchemas '<cluster-name|cluster-uuid>' '<schema json>'
./mothership deltaMachineBudget '<cluster-name|cluster-uuid>' '<budget delta json>'
./mothership deploy '<target>' '<deployment plan json>' '<container blob path>'
./mothership applicationReport '<target>' '<application name>'
./mothership updateProdigy '<target>' '<path to prodigy binary or bundle>'
./mothership removeCluster '<cluster-name|cluster-uuid>'
./mothership removeProviderCredential '<credential name>'
```

### Brain

A brain participates in cluster control. A minimal remote cluster commonly uses three brains across three machines. Prodigy can also run as one brain and one container for small or local cases.

### Neuron / container protocol

Neuron is the runtime side of Prodigy's workload interface.

Applications communicate with Prodigy over a Unix socket injected into the container's namespace. The protocol is a versioned wire protocol, so any language can implement it directly from the protocol documents and fixtures.

The SDKs are convenience implementations, not a requirement. Current SDKs include:

```text
C
C++
Rust
Go
Python
TypeScript
```

Containers use the protocol to receive startup parameters, seed local state, process peer and pairing updates, acknowledge resource and credential updates, and report healthy only after the workload is actually ready.

Protocol and SDK materials live under:

```text
prodigy/sdk/
```

Start with:

```text
prodigy/sdk/INTERFACES.md
prodigy/sdk/WIRE.md
prodigy/sdk/CONTRACT.md
prodigy/sdk/fixtures/
```

The SDK contract is performance-oriented: borrowed transport, incremental decoding, packed binary frames, minimal hot-path allocation, batching, and framework-independent protocol surfaces.

### Discombobulator

Discombobulator implements Prodigy's container runtime and artifact contract. Prodigy uses Discombobulator-produced app-container blobs rather than treating arbitrary rootfs trees, launch metadata, Btrfs payloads, or compressed archives as valid deployment inputs.

Discombobulator is built alongside Prodigy and can also be built directly with Cargo:

```bash
cargo build --release --manifest-path prodigy/discombobulator/Cargo.toml
```

Source:

```text
prodigy/discombobulator/
```

Repository path:

```text
https://github.com/victorstewart/prodigy/tree/main/prodigy/discombobulator
```

See [`prodigy/docs/discombobulator.md`](prodigy/docs/discombobulator.md).

### IaaS adapters

IaaS adapters connect Prodigy's machine-control model to provider APIs.

Adapters can be written for any cloud or infrastructure API that can create machines, attach metadata or identity, report machine state, and destroy capacity. Prodigy ships adapters for:

```text
AWS
GCP
Azure
Vultr
```

Adapters provide:

- provider machine offers and pricing metadata;
- credential and scope handling;
- instance creation and deletion;
- bootstrap metadata and identity attachment;
- provider-native tags, labels, or resource grouping;
- cleanup of instances, disks, IPs, templates, NICs, VPCs, and related artifacts where applicable;
- failure reporting or annotation when the provider supports it.

Adapters require:

- a provider scope, such as region, zone, project, subscription, account, or resource group;
- credentials with enough permission to create and remove the requested capacity;
- a machine image or image family;
- a machine schema describing desired capacity and budget;
- bootstrap access sufficient for the initial Prodigy install.

Adapters are responsible for translating Prodigy's desired machine state into provider-specific API calls. They are not responsible for application logic, workload health semantics, or SDK protocol behavior.

See [`prodigy/docs/iaas-adapters.md`](prodigy/docs/iaas-adapters.md).

## Deploy an application

A Prodigy deployment consists of a deployment plan and a Discombobulator-produced container blob.

```bash
./mothership deploy \
  '<local|cluster-name|cluster-uuid>' \
  "$(cat deployment.plan.json)" \
  './dist/my-agent.prodigy-blob'

./mothership applicationReport \
  '<local|cluster-name|cluster-uuid>' \
  'my-agent'
```

Minimal stateless plan:

```json
{
  "config": {
    "type": "ApplicationType::stateless",
    "applicationID": "my-agent",
    "versionID": 1,
    "architecture": "x86_64",
    "nLogicalCores": 1,
    "nMemoryMB": 512,
    "nStorageMB": 512,
    "msTilHealthy": 5000
  }
}
```

For stateful systems, include the resource, placement, service identity, address, credential, and health requirements your Prodigy build expects. The runtime uses the plan to place containers, deliver startup parameters, and track health.

## Cloud quick starts

Provider-specific runbooks live in [`prodigy/docs/runbooks/`](prodigy/docs/runbooks/):

| Provider | Runbook |
|---|---|
| AWS | [`aws.3brain.cheap.md`](prodigy/docs/runbooks/aws.3brain.cheap.md) |
| Azure | [`azure.3brain.cheap.md`](prodigy/docs/runbooks/azure.3brain.cheap.md) |
| GCP | [`gcp.3brain.cheap.md`](prodigy/docs/runbooks/gcp.3brain.cheap.md) |
| Vultr | [`vultr.3brain.cheap.md`](prodigy/docs/runbooks/vultr.3brain.cheap.md) |

Each runbook covers credentials, required permissions, machine shape, image selection, cluster creation, health checks, cleanup, and residual-resource verification.

## Design position

Kubernetes is the default general-purpose orchestrator for a reason: it has a broad ecosystem, a mature API model, and a large operational community. Prodigy is optimized for a different point in the design space: a lightweight, vertically integrated runtime for agents, infrastructure services, and datacenter-scale systems that benefit from orchestrator/workload co-design.

| Area | Kubernetes-style stack | Prodigy |
|---|---|---|
| System shape | Many cooperating components. | One integrated runtime per machine plus `mothership`. |
| Machine lifecycle | Usually schedules onto existing nodes or delegates node creation. | Machine creation, bootstrap, placement, repair, and removal are part of the orchestrator. |
| Workload integration | Generic app model plus probes, services, sidecars, and controllers. | Workloads can speak a runtime protocol for startup, health, topology, resources, and credentials. |
| Best fit | Broad cloud-native platforms and ecosystem compatibility. | Agents, databases, infrastructure services, local datacenter simulation, and high-density runtimes. |

The key tradeoff: Kubernetes maximizes ecosystem compatibility; Prodigy maximizes integrated control.

## Time to healthy 3-machine cluster

Fresh March 27, 2026 runs of cheap 3-machine / 3-brain clusters:

| Cloud | Machine shape | Create -> first healthy |
|---|---:|---:|
| AWS | `t3.micro` | 64.408s |
| Azure | `Standard_D2als_v6` | 95.091s |
| GCP | `e2-medium` | 100.422s |
| Vultr | `vx1-g-2c-8g` | 113.803s |

These are project benchmark artifacts, not vendor-certified third-party benchmarks. They are useful because they separate provider wait from runtime-owned work.

See [`prodigy/docs/benchmarks/healthy-3machine.md`](prodigy/docs/benchmarks/healthy-3machine.md) for raw commands, provider-wait attribution, image/shape notes, and cleanup proof.

## Security model

Prodigy minimizes credential spread and keeps bootstrap authority explicit.

- Remote cluster control is SSH key-only.
- Local provider credentials are used for bootstrap.
- Runtime machines should use provider-native identity where available.
- Application containers receive only the credentials explicitly delivered through the runtime protocol.
- Provider-specific credential handling is documented in each cloud runbook.

See [`prodigy/docs/security.md`](prodigy/docs/security.md).

## Building databases with Prodigy

Database authors usually rebuild the same orchestration substrate: machine selection, bootstrap, seeding, peer lists, membership changes, routing, credentials, health, repair, replacement, shard movement, and rolling updates.

Prodigy gives database processes a runtime protocol and cluster substrate for those concerns, so the database can focus on storage, replication, consistency, and query behavior.

A typical Prodigy-native database flow:

1. package the database binary and files;
2. deploy a seed member;
3. receive startup parameters and persistent-state paths;
4. receive peer/topology updates;
5. report healthy only when serving safely;
6. let Prodigy add, replace, and rehydrate capacity as supported by the provider adapter.

## Networking

Prodigy's packet path is designed to keep same-machine routing at zero additional L3 bytes and bound common cross-machine paths to small, explicit overheads.

See [`prodigy/docs/network-packet-budgets.md`](prodigy/docs/network-packet-budgets.md).

## Documentation

| Topic | Document |
|---|---|
| Build | [`prodigy/docs/build.md`](prodigy/docs/build.md) |
| SDK and protocol | [`prodigy/sdk/README.md`](prodigy/sdk/README.md) |
| Wire protocol | [`prodigy/sdk/WIRE.md`](prodigy/sdk/WIRE.md) |
| Runtime startup/state | [`prodigy/docs/runtime.md`](prodigy/docs/runtime.md) |
| Security | [`prodigy/docs/security.md`](prodigy/docs/security.md) |
| Discombobulator | [`prodigy/docs/discombobulator.md`](prodigy/docs/discombobulator.md) |
| IaaS adapters | [`prodigy/docs/iaas-adapters.md`](prodigy/docs/iaas-adapters.md) |
| Packet budgets | [`prodigy/docs/network-packet-budgets.md`](prodigy/docs/network-packet-budgets.md) |
| AWS runbook | [`prodigy/docs/runbooks/aws.3brain.cheap.md`](prodigy/docs/runbooks/aws.3brain.cheap.md) |
| Azure runbook | [`prodigy/docs/runbooks/azure.3brain.cheap.md`](prodigy/docs/runbooks/azure.3brain.cheap.md) |
| GCP runbook | [`prodigy/docs/runbooks/gcp.3brain.cheap.md`](prodigy/docs/runbooks/gcp.3brain.cheap.md) |
| Vultr runbook | [`prodigy/docs/runbooks/vultr.3brain.cheap.md`](prodigy/docs/runbooks/vultr.3brain.cheap.md) |

## Repository layout

```text
prodigy/
  brain/              cluster-control logic
  dev/                development helpers
  discombobulator/    container runtime and app-artifact builder
  docs/               runbooks, packet budgets, operational notes
  iaas/               cloud provider adapters
  logging/            runtime logging
  mothership/         operator client and automation entry point
  neuron/             container-side runtime logic
  sdk/                protocol contracts, fixtures, and language SDKs

eBPF, networking, services, and switchboard modules live at repository top level.
```

## Project status

Prodigy is an early systems project. Front-page claims should stay measurable:

- time to healthy 3-machine cluster;
- provider wait versus runtime-owned time;
- runtime footprint per machine;
- packet overhead on common paths;
- residual cloud resources after cleanup;
- cost for a fixed workload set versus comparable orchestrator deployments;
- machine failure detection and replacement time;
- deployment time for a fixed app artifact.

When adding a benchmark, commit the raw artifact path, command, provider region, machine shape, image, and cleanup proof.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
