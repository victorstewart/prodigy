# SDK Publishing

This repo ships all Prodigy SDKs from one source tree, but each language should be published through its canonical distribution channel:

- C: GitHub release asset pair
  - `prodigy-sdk-c.DepoFile`
  - `prodigy-sdk-c-<version>.tar.gz`
- C++: GitHub release asset pair
  - `prodigy-sdk-cpp.DepoFile`
  - `prodigy-sdk-cpp-<version>.tar.gz`
- Rust: `crates.io`
- Go: repo subdirectory tags like `sdk/go/v1.0.0`
- Python: PyPI
- TypeScript: npm as `@victorstewart/prodigy-sdk`

Important current package contract:

- `Prodigy::SdkCpp` is the base C++ SDK and already includes the portable Aegis surface.
- `Prodigy::SdkCppAegis` is intentionally gone.
- `Prodigy::SdkCppOpinionated` is the higher-level C++ wrapper layer.

## C And C++ Release Assets

Generate detached `depos` assets plus SDK-only tarballs with:

```bash
bash prodigy/sdk/tools/prepare_release_assets.sh
```

That workflow:

- configures and builds the standalone SDK
- stages separate C and C++ SDK package trees under `.run/`
- writes `prodigy-sdk-c.DepoFile` and `prodigy-sdk-cpp.DepoFile`
- produces `prodigy-sdk-c-<version>.tar.gz` and `prodigy-sdk-cpp-<version>.tar.gz`

The tarballs are intentionally SDK-only:

- headers
- static library for C
- CMake package config/export files
- detached depofile inventory needed by the package
- relevant docs, fixtures, and examples

They do not contain the full Prodigy repo or runtime source tree.

## Rust

Publish [`rust/Cargo.toml`](./rust/Cargo.toml) to `crates.io`.

`docs.rs` is the canonical hosted docs path. The crate metadata already carries:

- repository
- homepage
- documentation

## Go

Keep the module in this repo at [`go/go.mod`](./go/go.mod) and publish with subdirectory-prefixed tags:

```text
sdk/go/v1.0.0
```

Consumers install through the module path already in the repo:

```text
github.com/victorstewart/prodigy/sdk/go
```

## Python

Publish [`python/pyproject.toml`](./python/pyproject.toml) to PyPI as the primary distribution channel.

## TypeScript

Publish [`typescript/package.json`](./typescript/package.json) to npm as:

```text
@victorstewart/prodigy-sdk
```
