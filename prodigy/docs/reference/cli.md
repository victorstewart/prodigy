# Mothership CLI reference

Run `mothership help` for the complete command list. The core lifecycle commands are:

```text
createCluster [json|-|@path]
clusterReport [target]
deploy [target] [json|-|@path] [container blob]
applicationReport [target] [application]
containerLogs [target] [application] [maximum bytes]
updateProdigy [target] [binary or bundle]
removeCluster [name|clusterUUID]
```

Targets are `local`, a cluster name, or a cluster UUID where supported. JSON arguments accept inline content, `-` for standard input, or `@path`. Use `@file` in scripts to avoid shell quoting and preserve plan readability.

Additional commands manage provider credentials, machine schemas, budgets, application/service ID reservations, routable subnets, DNS bindings, TLS vault factories, and API credentials. Follow the task pages before invoking those operations.
