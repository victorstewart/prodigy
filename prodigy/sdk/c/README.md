# C SDK

`prodigy_neuron_hub.h` is the full C SDK surface. It covers:

- transport-neutral startup decode and control-frame handling
- outbound ACK, ready, and statistics helpers
- portable paired-service Aegis helpers for pairing hash, TFO bytes, and frame encrypt/decrypt

Start here:

1. [`examples/aegis_roundtrip.c`](./examples/aegis_roundtrip.c)
   Small standalone paired-service example using `prodigy_aegis_session`, deterministic TFO bytes, and one encrypt/decrypt cycle.
2. [`examples/mesh_pingpong.c`](./examples/mesh_pingpong.c)
   Current control-plane reference example that loads startup state, reacts to live pairings, ACKs `resourceDelta` and `credentialsRefresh`, and only signals ready after the IPv6 mesh exchange succeeds. This example expects Prodigy runtime startup state or a deployment-plan-driven bring-up.

Installed-package boundary:

- `find_package(ProdigySDKC REQUIRED CONFIG)`
- link `Prodigy::SdkC`
- the installed package bootstraps its Aegis and gxhash dependencies through the SDK's shipped depofile inventory

Supporting files:

- [`examples/README.md`](./examples/README.md)
- [`../INTERFACES.md`](../INTERFACES.md)
- [`../WIRE.md`](../WIRE.md)
- [`../AEGIS.md`](../AEGIS.md)
