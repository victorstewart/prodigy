# C Examples

- `aegis_roundtrip.c`: minimal paired-service Aegis roundtrip example using `prodigy_aegis_session`, deterministic TFO bytes, and one encrypt/decrypt cycle.
- `mesh_pingpong.c`: one binary that runs as either advertiser or subscriber from startup state, reacts to mesh pairings, exchanges a few IPv6 ping/pong rounds, and signals ready on success.
- `mesh_pingpong.advertiser.deployment.plan.v1.json`: advertiser plan using symbolic application and service references for the advertiser's `clients` service.
- `mesh_pingpong.subscriber.deployment.plan.v1.json`: subscriber plan using symbolic application and service references for the advertiser's `clients` service.

Symbolic references are resolved by mothership as lookups, not implicit creation:

- application: `${application:ExampleName}`
- service: `${service:ExampleName/clients}`

Reserve them first:

```sh
./mothership reserveApplicationID dev '{"applicationName":"ExampleName"}'
./mothership reserveServiceID dev '{"applicationName":"ExampleName","serviceName":"clients","kind":"stateless"}'
```
