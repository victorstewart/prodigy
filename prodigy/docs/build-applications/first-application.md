# Build a first application

[`examples/hello-prodigy`](../../../examples/hello-prodigy/) is the included
stateless HTTP application. It listens on dual-stack port
`8080`; `GET /` and `GET /healthz` return a versioned response. Its v1 artifact
returns `hello from Prodigy v1`; deploying v2 is an application update that
returns v2.

The container protocol is mandatory. `hello_prodigy.cpp` uses Prodigy’s native
`NeuronHub` and event ring to load startup state, open its listener, and report
readiness. It continues processing shutdown, resource, and credential messages
while a bounded HTTP worker serves requests. Merely linking an SDK does not
implement this protocol.

This example is built against the matching runtime source. Public-ingress plans
currently receive full startup data that the public C++ SDK reader does not
accept; the example therefore uses the existing native implementation. See the
[SDK startup compatibility boundary](../../sdk/WIRE.md#containerparameters).

## Build the included example

Enter the approved Linux guest described in [Install an evaluation
bundle](../start/install.md). The wrapper checks the boundary, refuses macOS and
unverified Linux, and does not install packages.

```bash
tools/build-evaluation.sh .run/evaluation-build
```

For a new build directory, the wrapper selects Clang and the release Basics
source mode. It preserves the compiler and dependency choices in an existing
CMake cache. The command builds the approved runtime bundle plus real
Discombobulator `--kind app` artifacts; it does not start a cluster.

```text
.run/evaluation-build/examples/hello-prodigy/hello_prodigy_v1
.run/evaluation-build/examples/hello-prodigy/hello_prodigy_v2
.run/evaluation-build/evaluation-assets/hello-prodigy-v1.<arch>.container.zst
.run/evaluation-build/evaluation-assets/hello-prodigy-v2.<arch>.container.zst
.run/evaluation-build/evaluation-assets/hello-prodigy-v1.deployment.plan.v1.json
.run/evaluation-build/evaluation-assets/hello-prodigy-v2.deployment.plan.v1.json
```

Do not substitute a root filesystem archive or a handcrafted compressed blob for
the `.container.zst` artifact.

## Change the response

The CMake target compiles the same source twice: `HELLO_PRODIGY_VERSION` is
`v1` for `hello_prodigy_v1` and `v2` for `hello_prodigy_v2`. Edit the response
logic, rebuild, and keep the resulting v1 and v2 artifacts separate. The plans
request one logical core, 128 MiB memory, and 64 MiB each of filesystem and
storage; both map public TCP port `8080` to the container port.

## Reserve identities and deploy

Mothership owns identity reservation, public-prefix registration, and
deployment. The checked-in plans are templates: their symbolic application,
service, and routable-prefix values become IDs returned by Mothership. Against
an existing disposable test cluster, use the same operations as the included
evaluation session (`tools/evaluation/session.py`):

```bash
MOTHERSHIP=.run/evaluation-build/mothership
CLUSTER=your-disposable-test-cluster

"$MOTHERSHIP" reserveApplicationID "$CLUSTER" '{"applicationName":"HelloProdigy"}'
APP_ID=1 # Replace with the appID printed by reserveApplicationID.
SERVICE_JSON="$(python3 -c 'import json,sys; print(json.dumps({"applicationName":"HelloProdigy","applicationID":int(sys.argv[1]),"serviceName":"http","kind":"stateless"}))' "$APP_ID")"
"$MOTHERSHIP" reserveServiceID "$CLUSTER" "$SERVICE_JSON"
"$MOTHERSHIP" registerRoutableSubnet "$CLUSTER" '{"name":"hello-prodigy-public-ipv4","kind":"BGP","prefix":"198.18.0.10/32","usage":"wormholes","ingressScope":"singleMachine"}'
```

Replace `APP_ID` with the `appID` from the first response and record the UUID
from the final response. Copy the v1 plan and set `config.applicationID`,
`config.architecture`, and `wormholes[0].routablePrefixUUID` to those real
values. Deploy the resolved plan and real artifact through Mothership:

```bash
PLAN=.run/evaluation-build/evaluation-assets/hello-prodigy-v1.deployment.plan.v1.json
ARCH="$(uname -m)"
ARTIFACT=".run/evaluation-build/evaluation-assets/hello-prodigy-v1.${ARCH}.container.zst"
"$MOTHERSHIP" deploy "$CLUSTER" "@$PLAN" "$ARTIFACT"
```

The expected response after a healthy deployment is `hello from Prodigy v1` at
`http://198.18.0.10:8080/`. This response and the application update were verified inside the prepared
Apple Containers AArch64 guest. Use `./try-prodigy` from a packaged evaluation bundle for
the bounded disposable flow and its evidence.

## Cleanup and next steps

Remove an experiment through Mothership:

```bash
"$MOTHERSHIP" removeCluster "$CLUSTER"
```

For the included demo, Ctrl-C in the foreground `./try-prodigy` session removes
its cluster. Before cleanup, use `./try-prodigy update` to deploy v2. Read the
[Discombobulator artifact guide](../discombobulator.md) before packaging a new
workload.
