# Contributing

Start with a focused issue or pull request against the smallest affected subsystem. Explain the observed behavior, the intended behavior, and the verification you ran. Preserve unrelated work in a dirty tree.

Runtime, network, BPF, cgroup, mount, and container changes require the documented disposable boundary; see [Build and test safety](prodigy/docs/build.md) and the [test-cluster manual flow](prodigy/dev/tests/manual/test/README.md). Do not run privileged test clusters directly on a general-purpose host.

For documentation, follow the task-page map in [docs](prodigy/docs/README.md). Keep current guides separate from historical evidence: [tunnel-provider records](prodigy/docs/archive/tunnel-provider-refactor/) are archived records, not implementation instructions.

Open discussion and bug reports through [GitHub Issues](https://github.com/victorstewart/prodigy/issues). Security-sensitive reports belong in the [security reporting guide](SECURITY.md).
