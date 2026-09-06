# First-service transcript

Recorded on 2026-09-06 inside the prepared Apple Containers AArch64 Linux
guest. This shows real command output, with the status report shortened to its
application version, state, health, and crash count. Installation and guest
startup are not shown. The animation pauses between steps for readability.

```text
$ ./try-prodigy
Starting a disposable one-machine Prodigy cluster…
hello from Prodigy v1

Service: http://198.18.0.10:8080/
In another terminal: ./try-prodigy status
Then: ./try-prodigy update
Press Ctrl-C here to remove the demo. Sessions end automatically after 30 minutes.
$ ./try-prodigy status
Application: HelloProdigy
versionID: 1
state: DeploymentState::running
nHealthy: 1
nCrashes: 0
Service: http://198.18.0.10:8080/
$ ./try-prodigy update
Deploying application version two…
hello from Prodigy v2
$ curl --noproxy "*" --fail --silent --show-error http://198.18.0.10:8080/
hello from Prodigy v2
^C  # foreground terminal
Removing the demo through Mothership…
Demo removed.
```

[Terminal event recording](../../../assets/try-prodigy.cast) ·
[Run the tutorial](first-service.md) · [Current status](status.md)
