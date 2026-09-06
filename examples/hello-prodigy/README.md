# Hello Prodigy

Hello Prodigy is the included stateless HTTP example. It listens on the
dual-stack port `8080`, accepts bounded HTTP/1.0 and HTTP/1.1
`GET` and `HEAD` requests, and serves `/` and `/healthz`.

The build produces two real Discombobulator `--kind app` artifacts. Their
visible responses are `hello from Prodigy v1` and `hello from Prodigy v2`.
The source uses Prodigy’s native `NeuronHub` and event ring, signals readiness
after its listener opens, and handles shutdown, resource, and credential
messages while a bounded HTTP worker serves requests. It is built against the
matching runtime source because public ingress currently uses full startup data
that the public C++ SDK reader does not accept.

## Build

Enter the approved Linux guest described in [Install an evaluation
bundle](../../prodigy/docs/start/install.md), then run from the repository root:

```bash
tools/build-evaluation.sh .run/evaluation-build
```

The generated inputs are in `.run/evaluation-build/evaluation-assets/`:

```text
hello-prodigy-v1.<arch>.container.zst
hello-prodigy-v2.<arch>.container.zst
hello-prodigy-v1.deployment.plan.v1.json
hello-prodigy-v2.deployment.plan.v1.json
```

`tools/package-evaluation.sh .run/evaluation-build` creates a local review
archive in `.run/releases/`; it does not publish anything.

## Deploy versions

Mothership reserves the `HelloProdigy` application ID and `http` stateless
service, registers `hello-prodigy-public-ipv4`, and materializes the symbolic
plan values before deployment. `tools/evaluation/session.py` follows that flow.
Deploy v1 first; deploy v2 with its v2 artifact as an application update, not a
runtime update. Once live, the expected endpoint is
`http://198.18.0.10:8080/`; v1 and the v2 update were verified inside the prepared Apple Containers
AArch64 guest on 2026-09-06. See the [current status](../../prodigy/docs/start/status.md)
for clean-installation and host-access limits.

See [Build a first application](../../prodigy/docs/build-applications/first-application.md)
for the Mothership commands, plan materialization, and cleanup.
