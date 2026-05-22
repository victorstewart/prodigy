# Cloud runbook conventions

Provider-specific runbooks are intentionally separate from the root README.

Each cheap 3-machine / 3-brain runbook should cover:

- validated machine shape;
- provider scope;
- authentication mode;
- required permissions;
- provider credential creation;
- cluster JSON;
- create command;
- health/report command;
- removal command;
- residual-resource verification.

## Assumptions

Runbooks assume:

- `mothership` and `prodigy` have been built from this repository;
- `./mothership` points to the operator binary or `MOTHERSHIP` is set explicitly;
- a bootstrap SSH private key exists and the configured bootstrap user can install/run Prodigy;
- TCP Fast Open is enabled on target hosts;
- provider CLIs are authenticated locally before cluster creation.

## Local operator variable

Use this only inside runbooks or scripts that need a configurable operator path:

```bash
MOTHERSHIP="${MOTHERSHIP:-./mothership}"
```

Avoid putting generic shell scaffolding in the root README.
