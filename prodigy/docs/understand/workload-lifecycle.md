# Workload lifecycle

Mothership deploys a Discombobulator-built artifact with a deployment plan. Prodigy places and starts the container, then supplies packed startup parameters through `PRODIGY_PARAMS_FD` or `argv[1]`. Every deployed workload must seed local state from initial pairings before consuming the shared control stream.

During its life, the workload receives pairing, resource, and credential updates. It must acknowledge updates as required by the contract and report healthy only after it can safely serve. A stop event begins shutdown. This required protocol is Prodigy's workload integration boundary; the SDK choice is optional.

Read [SDK quickstart](../../sdk/README.md) for examples, [INTERFACES](../../sdk/INTERFACES.md) for semantics, [CONTRACT](../../sdk/CONTRACT.md) for callbacks, and [WIRE](../../sdk/WIRE.md) for encodings.
