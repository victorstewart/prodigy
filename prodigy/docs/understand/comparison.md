# Choosing Prodigy, Kubernetes, or Nomad

These systems solve related scheduling problems with different workload and operator boundaries. This is a model comparison, not a speed, footprint, or availability claim.

| Area | Kubernetes | Nomad | Prodigy |
|---|---|---|---|
| Unit submitted by an operator | API objects that describe Pods and related resources | A jobspec that describes jobs, groups, and tasks | A deployment plan plus a Discombobulator-built app artifact |
| Cluster roles | Control plane manages Nodes; kubelet and a container runtime run Pods on Nodes | Servers schedule jobs; clients register resources and execute allocations | Mothership operates clusters; Brain and Neuron coordinate control and workload runtime |
| Workload integration | A workload runs in a Pod; application protocol integration is application-specific | A job defines tasks and their drivers; application protocol integration is application-specific | Every deployed workload implements the Neuron/container protocol; a language SDK is optional |
| Primary references | [Kubernetes architecture](https://kubernetes.io/docs/concepts/architecture/) and [Nodes](https://kubernetes.io/docs/concepts/architecture/nodes/) | [Nomad architecture](https://developer.hashicorp.com/nomad/docs/architecture) and [job specification](https://developer.hashicorp.com/nomad/docs/job-specification) | [Architecture](architecture.md), [workload lifecycle](workload-lifecycle.md), and [SDK contract](../../sdk/CONTRACT.md) |

Kubernetes is a strong fit when its API ecosystem and operational model match the application. Nomad is a strong fit when its job, server, and client model and supported task drivers match the application. Prodigy is a fit when mandatory workload participation in its lifecycle protocol is acceptable and coordinated machine, placement, networking, health, and update control is central to the system.

Review each project's official documentation before selecting an operational model. Prodigy's [benchmark record](../benchmarks/healthy-3machine.md) and [packet budgets](../network-packet-budgets.md) state this project's measured claims and assumptions separately.
