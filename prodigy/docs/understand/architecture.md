# Architecture

Prodigy has four user-facing pieces. Mothership is the operator client: it creates and reports on clusters, deploys application artifacts, and stages runtime updates. Brain participates in cluster control. Neuron is the machine-side workload runtime. Discombobulator builds the versioned application artifacts that Mothership deployment accepts.

Provider adapters translate desired machine state into cloud API operations. Every deployed application must implement the Neuron/container protocol; SDKs are optional language implementations, and applications may implement the public protocol directly. The system keeps control, placement, networking, health, and update decisions coordinated, while workloads retain their own application semantics.

Use [IaaS adapters](../iaas-adapters.md), [Runtime](../runtime.md), and the [SDK contract](../../sdk/CONTRACT.md) for detailed boundaries.
