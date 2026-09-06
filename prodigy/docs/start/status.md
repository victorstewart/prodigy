# Current status and requirements

Prodigy is early-stage software for evaluation. It combines machine provisioning,
application scheduling, routing, and lifecycle management. Every workload must
implement its runtime protocol, through an SDK or a direct implementation.
Existing OCI images require adaptation.

Last checked: 2026-09-06.

## Evaluation availability

The repository builds a versioned evaluation archive containing matching Linux
binaries, two Discombobulator-built HTTP application artifacts, deployment plans,
and `try-prodigy`. There is no published download yet. The [installation
guide](install.md) describes the contributor build path while release validation
is underway.

| Check | Current evidence |
|---|---|
| Linux AArch64 compilation and real artifact builds | Passed in the pinned Apple Containers development guest |
| JSON file, stdin, and inline CLI inputs | Focused CLI regression test passes |
| Bundle integrity and rejection checks | Passed locally |
| Cluster creation and cleanup through Mothership | Passed, including SIGINT of the foreground client |
| HTTP response, status, and v1 → v2 update | Passed in the prepared Apple Containers AArch64 guest |
| HTTP health, HEAD, 404, and idle-client timeout | Passed against the running v2 service |
| Clean Apple Silicon and Linux installation | Not yet verified; x86_64 was not exercised |
| Linux host guest provisioning and shutdown | External guest owner required; automatic host flow remains a release gate |
| Published release download | Not yet available |

The first successful run reached an HTTP response in 4.072 seconds after the
evaluation client started **inside an already running guest**. This excludes
installation, compilation, packaging, and guest startup.

The example uses the native protocol hub because the public C++ SDK does not
accept the full startup payload used for public ingress. See the [SDK writer
boundary](../../sdk/WIRE.md#containerparameters).

The [recorded transcript](first-service-transcript.md) shows start, status, update,
a v2 HTTP request, and interruption cleanup from a fresh evaluation session.

These observations use a prepared development environment. They do not establish
clean-machine installation, production readiness, or installation speed. No
“in five minutes” claim is made.

## Environment

Runtime evaluation requires Linux 7.0 or newer and the documented disposable
boundary. Apple Silicon uses the pinned Apple Containers environment; ordinary
Linux workstations require a KVM guest. A dedicated sacrificial Linux runner may
use the administrator-provisioned marker. The launcher rejects an unsupported
boundary before cluster creation. See [installation prerequisites](install.md).

Application versions and runtime versions are separate: `try-prodigy update`
changes the HTTP application; `mothership updateProdigy` updates the orchestrator.
For operational commands see [inspect and update](../run-clusters/inspect-and-update.md).

## Supporting evidence

The [three-machine benchmark record](../benchmarks/healthy-3machine.md) describes
its own workload and conditions. It is historical evidence, not a guarantee for
an arbitrary cluster. [Packet budgets](../network-packet-budgets.md) document
network assumptions. The [Kubernetes and Nomad comparison](../understand/comparison.md)
explains workload compatibility and ecosystem tradeoffs.
