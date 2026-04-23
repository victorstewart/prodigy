# Prodigy SDK Versioning

This file defines the explicit versioning policy for the native SDK wire format and the checked-in fixture corpus.

The machine-readable source of truth is [`versioning.json`](/root/prodigy/prodigy/sdk/versioning.json).

## Version Axes

- `sdkVersion`
  This is the user-visible SDK release version shared across the checked-in language packages, headers, and READMEs.
  Bump this when the published SDK surface changes in a way that should be reflected across package metadata and install consumers.
- `wireSeries`
  This is the named wire family, for example `WIRE_V1`.
  Change this only for an intentionally incompatible protocol generation.
- `wireProtocolVersion`
  This is the revision number inside one wire series.
  Bump this whenever emitted or accepted wire bytes change, even if rollout compatibility is preserved.
- `fixtureManifestVersion`
  This is the schema version of `fixtures/manifest.json`.
  Bump this whenever the JSON shape of the manifest changes.
- `fixtureCorpusVersion`
  This is the revision number for the checked-in binary corpus.
  Bump this whenever any `.bin` fixture changes bytes or when fixtures are added or removed.

## Required Rules

- Do not silently drift language package versions.
  If the shared SDK release version changes, update `sdkVersion` and keep headers, package manifests, and language READMEs aligned with it.
- Do not silently change wire bytes.
  If bytes on the wire change, bump `wireProtocolVersion`.
- Do not silently change fixture bytes.
  If any checked-in fixture changes, bump `fixtureCorpusVersion`.
- Do not silently change manifest structure.
  If `fixtures/manifest.json` changes shape, bump `fixtureManifestVersion`.
- Do not reuse a `wireSeries` name for an incompatible protocol.
  A breaking generation gets a new series such as `WIRE_V2`.

## Enforcement

- [`fixtures/generate.ts`](/root/prodigy/prodigy/sdk/fixtures/generate.ts) reads `versioning.json` and writes those values into `fixtures/manifest.json`.
- [`compatibility_matrix.sh`](/root/prodigy/prodigy/sdk/compatibility_matrix.sh) checks that `versioning.json` and `fixtures/manifest.json` agree before running language tests.
- [`compatibility_matrix.sh`](/root/prodigy/prodigy/sdk/compatibility_matrix.sh) also checks that `sdkVersion`, `wireSeries`, and `wireProtocolVersion` stay aligned across the language SDK manifests, public constants, and checked-in READMEs.
- The version metadata is checked into git, so any version change is visible in review.
