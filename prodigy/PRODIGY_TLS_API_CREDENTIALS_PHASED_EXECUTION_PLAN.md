# Prodigy TLS + API Credential Distribution and Refresh

## Phased Execution Plan

## Document Metadata
| Field | Value |
|---|---|
| Plan owner | Prodigy Control Plane Team |
| Primary consumers | Brain, Neuron, Application Server, Networking, Security, SRE |
| Scope | App-scoped TLS vault factories, app-scoped API credential registries, per-container TLS certs, API key distribution, on-demand client cert minting, live refresh, rotation and revocation |
| Certificate validity policy | Deployment-plan-defined inbound leaf validity (default 15 days) |
| Last updated | 2026-03-02 |
| Status | Execution-ready design plan |

## 1. Goals
1. Eliminate hardcoded TLS credentials and API keys from application containers.
2. Make Prodigy the source of truth for credential issuance, distribution, refresh, and revocation.
3. Support multiple TLS identities and multiple API credentials per container.
4. Ensure safe runtime refresh with acknowledgement and rollback.
5. Ensure inbound TLS certificate lifecycle is automated with deployment-plan-defined leaf validity and proactive renewal.
6. Ensure observability and auditability for all secret lifecycle events.
7. Add alternate TLS `MothershipTopic` flow to create/persist a vault factory per `applicationID`.
8. Support dual root/intermediate key source modes: Prodigy-generated or caller-provided import.
9. Allow deployment plans to opt all containers in an application into per-container leaf issuance.
10. Add API-key registration `MothershipTopic` so API credentials are stored once in Prodigy and referenced by deployment intent.
11. Add `MothershipTopic` flow for on-demand client certificate minting for workloads that do not receive client certs by default.

## 2. Non-Goals
1. Building an external public PKI service.
2. Replacing all existing outbound auth patterns in a single release.
3. Rotating third-party provider credentials inside provider systems automatically on day one.
4. Changing application business logic unrelated to credential loading and refresh.

## 3. Current-State Constraints and Gaps
1. Runtime TLS issuance exists in primitives but is not wired end-to-end in orchestration.
2. Deployment TLS config parsing exists but is fail-closed and not represented in plan schema.
3. Container boot parameters do not include TLS or API secret material.
4. Container runtime topics do not include credential refresh and ack semantics.
5. Application server consumes hardcoded cert paths and hardcoded Telnyx bearer token.
6. Application server has TLS write helper (`tlsIdentityReceived`) but no control-plane path invoking it.
7. TCP and QUIC TLS contexts are initialized once with no formal hot-reload flow.
8. No persisted per-`applicationID` TLS vault factory abstraction exists.
9. No explicit control-plane API exists to generate/import root+intermediate and bind to application identity.
10. No explicit control-plane API exists to register API credential material by `applicationID` and logical key.
11. No explicit control-plane API exists to mint client TLS certs on demand from an existing app vault factory.

## 4. Target End-State Architecture
1. Brain owns credential policy and lifecycle scheduling.
2. Mothership owns app-level TLS vault factory lifecycle keyed by `applicationID`.
3. Mothership owns app-level API credential registry keyed by `applicationID` and credential name.
4. Vault factory supports two key-source modes: `generate` and `import`.
5. In `generate` mode, Prodigy generates root+intermediate and returns them in the upsert response.
6. In `import` mode, caller supplies root+intermediate material for validation and persistence.
7. API credential registry supports upsert/update/revoke per logical key and provider metadata.
8. Brain issues per-container leaves from the persisted vault factory when deployment policy requires it.
9. Brain selects API credentials requested by deployment policy and stages them into boot bundles and runtime deltas.
10. Deployment admission hard-fails if referenced TLS vault factory does not already exist; auto-create is forbidden.
11. Deployment admission hard-fails if any referenced API credential name is not already registered for the `applicationID`.
12. Deployment-managed container credential bundles are server-certificate oriented by default.
13. Client TLS certificates are minted only through explicit control-plane requests on a dedicated `MothershipTopic`.
14. Neuron receives credential deltas from Brain and reliably relays to containers.
15. Container receives initial boot credential bundle from `ContainerParameters`.
16. Container receives runtime credential refresh deltas through explicit `ContainerTopic` messages.
17. Container applies credential updates atomically and acks by emitting `ContainerTopic::credentialsRefresh` with no payload.
18. Application server routes all credential reads through a local in-memory credential registry keyed by logical name.
19. Reload pipelines exist for TCP TLS context, QUIC engine cert state, and outbound HTTP authorization headers.

## 5. Canonical Credential Model

### 5.1 New Types
1. `TlsIdentity`
2. `ApiCredential`
3. `CredentialBundle`
4. `CredentialDelta`
5. `CredentialApplyResult`
6. `ApplicationTlsVaultFactory`
7. `TlsVaultFactoryUpsertRequest`
8. `TlsVaultFactoryUpsertResponse`
9. `DeploymentTlsIssuancePolicy`
10. `ApplicationApiCredentialSet`
11. `ApiCredentialSetUpsertRequest`
12. `ApiCredentialSetUpsertResponse`
13. `DeploymentApiCredentialPolicy`
14. `ClientTlsMintRequest`
15. `ClientTlsMintResponse`

### 5.2 `TlsIdentity` fields
| Field | Type | Description |
|---|---|---|
| `name` | `String` | Logical identity name, example `inbound_server_tls`, `apns_client_tls` |
| `generation` | `uint64_t` | Monotonic version |
| `notBeforeMs` | `int64_t` | Validity start |
| `notAfterMs` | `int64_t` | Validity end |
| `certPem` | `String` | Leaf cert PEM |
| `keyPem` | `String` | Private key PEM |
| `chainPem` | `String` | Intermediate chain PEM |
| `dnsSans` | `Vector<String>` | SAN DNS entries |
| `ipSans` | `Vector<IPAddress>` | SAN IP entries |
| `tags` | `Vector<String>` | Policy labels and usage hints |

### 5.3 `ApiCredential` fields
| Field | Type | Description |
|---|---|---|
| `name` | `String` | Logical key, example `telnyx_bearer` |
| `provider` | `String` | `telnyx`, `stripe`, `internal`, etc |
| `generation` | `uint64_t` | Monotonic version |
| `expiresAtMs` | `int64_t` | Expiry timestamp, `0` for non-expiring |
| `activeFromMs` | `int64_t` | Not-before for cutover |
| `sunsetAtMs` | `int64_t` | Optional old generation sunset |
| `material` | `String` | Token or serialized provider-specific payload |
| `metadata` | `bytell_hash_map<String, String>` | Non-secret usage hints |

### 5.4 `CredentialBundle` fields
| Field | Type | Description |
|---|---|---|
| `tlsIdentities` | `Vector<TlsIdentity>` | Full snapshot |
| `apiCredentials` | `Vector<ApiCredential>` | Full snapshot |
| `bundleGeneration` | `uint64_t` | Bundle-level monotonic generation |

### 5.5 `CredentialDelta` fields
| Field | Type | Description |
|---|---|---|
| `bundleGeneration` | `uint64_t` | New bundle generation |
| `updatedTls` | `Vector<TlsIdentity>` | Upserts |
| `removedTlsNames` | `Vector<String>` | Deletes |
| `updatedApi` | `Vector<ApiCredential>` | Upserts |
| `removedApiNames` | `Vector<String>` | Deletes |
| `reason` | `String` | `renewal`, `manual-rotate`, `revoke`, `provider-rollover` |

### 5.6 `ApplicationTlsVaultFactory` fields
| Field | Type | Description |
|---|---|---|
| `applicationID` | `UUID` | Stable app identity key |
| `factoryGeneration` | `uint64_t` | Monotonic vault factory version |
| `keySourceMode` | `String` | `generate` or `import` |
| `rootCertPem` | `String` | Root CA PEM (encrypted at rest) |
| `rootKeyPem` | `String` | Root key PEM (encrypted at rest) |
| `intermediateCertPem` | `String` | Intermediate CA PEM (encrypted at rest) |
| `intermediateKeyPem` | `String` | Intermediate key PEM (encrypted at rest) |
| `defaultLeafValidityMs` | `int64_t` | Default leaf lifetime |
| `renewLeadPercent` | `uint8_t` | Lead percent before expiry, default `10` |
| `createdAtMs` | `int64_t` | Creation timestamp |
| `updatedAtMs` | `int64_t` | Last mutation timestamp |

### 5.7 `TlsVaultFactoryUpsertRequest` fields
| Field | Type | Description |
|---|---|---|
| `applicationID` | `UUID` | Target application |
| `mode` | `String` | `generate` or `import` |
| `importRootCertPem` | `String` | Required for `import` |
| `importRootKeyPem` | `String` | Required for `import` |
| `importIntermediateCertPem` | `String` | Required for `import` |
| `importIntermediateKeyPem` | `String` | Required for `import` |
| `defaultLeafValidityMs` | `int64_t` | Requested default validity |
| `renewLeadPercent` | `uint8_t` | Requested renewal lead percent |

### 5.8 `TlsVaultFactoryUpsertResponse` fields
| Field | Type | Description |
|---|---|---|
| `applicationID` | `UUID` | Target application |
| `factoryGeneration` | `uint64_t` | Persisted version |
| `created` | `bool` | `true` on initial create |
| `mode` | `String` | Effective mode |
| `generatedRootCertPem` | `String` | Present only when `mode=generate` and create/update generated new root |
| `generatedRootKeyPem` | `String` | Present only when `mode=generate` and create/update generated new root |
| `generatedIntermediateCertPem` | `String` | Present only when `mode=generate` and create/update generated new intermediate |
| `generatedIntermediateKeyPem` | `String` | Present only when `mode=generate` and create/update generated new intermediate |
| `effectiveLeafValidityMs` | `int64_t` | Persisted default validity |
| `effectiveRenewLeadPercent` | `uint8_t` | Persisted lead percent |

### 5.9 `DeploymentTlsIssuancePolicy` fields
| Field | Type | Description |
|---|---|---|
| `applicationID` | `UUID` | Must map to pre-existing vault factory; hard fail if missing |
| `enablePerContainerLeafs` | `bool` | If `true`, all deployment containers receive unique leaves |
| `leafValidityMs` | `int64_t` | Optional override per deployment |
| `renewLeadPercent` | `uint8_t` | Optional override, default `10` |
| `identityNames` | `Vector<String>` | Inbound/outbound identities covered by policy |

### 5.10 `ApplicationApiCredentialSet` fields
| Field | Type | Description |
|---|---|---|
| `applicationID` | `UUID` | Stable app identity key |
| `setGeneration` | `uint64_t` | Monotonic set version |
| `credentials` | `Vector<ApiCredential>` | Upserted API credentials |
| `createdAtMs` | `int64_t` | Creation timestamp |
| `updatedAtMs` | `int64_t` | Last mutation timestamp |

### 5.11 `ApiCredentialSetUpsertRequest` fields
| Field | Type | Description |
|---|---|---|
| `applicationID` | `UUID` | Target application |
| `upsertCredentials` | `Vector<ApiCredential>` | Add/update credentials by logical name |
| `removeCredentialNames` | `Vector<String>` | Optional deletes |
| `reason` | `String` | `manual`, `provider-rollover`, `bootstrap` |

### 5.12 `ApiCredentialSetUpsertResponse` fields
| Field | Type | Description |
|---|---|---|
| `applicationID` | `UUID` | Target application |
| `setGeneration` | `uint64_t` | Persisted set generation |
| `updatedNames` | `Vector<String>` | Successfully upserted names |
| `removedNames` | `Vector<String>` | Successfully removed names |

### 5.13 `DeploymentApiCredentialPolicy` fields
| Field | Type | Description |
|---|---|---|
| `applicationID` | `UUID` | Must map to pre-existing API credential set; hard fail if missing |
| `requiredCredentialNames` | `Vector<String>` | Logical keys to distribute to every container; hard fail if any name is not registered |
| `refreshPushEnabled` | `bool` | If `true`, runtime updates are pushed to live containers |

### 5.14 `ClientTlsMintRequest` fields
| Field | Type | Description |
|---|---|---|
| `applicationID` | `UUID` | Must map to pre-existing vault factory; hard fail if missing |
| `name` | `String` | Logical identity name for minted client cert |
| `subjectCommonName` | `String` | Subject CN |
| `dnsSans` | `Vector<String>` | Optional SAN DNS entries |
| `ipSans` | `Vector<IPAddress>` | Optional SAN IP entries |
| `validityMs` | `int64_t` | Requested client cert lifetime (bounded by policy) |
| `tags` | `Vector<String>` | Usage labels, example `mtls-client`, `apns-client` |
| `reason` | `String` | `manual`, `bootstrap`, `rotate`, `replace` |

### 5.15 `ClientTlsMintResponse` fields
| Field | Type | Description |
|---|---|---|
| `applicationID` | `UUID` | Target application |
| `name` | `String` | Logical identity name |
| `generation` | `uint64_t` | Minted identity generation |
| `notBeforeMs` | `int64_t` | Validity start |
| `notAfterMs` | `int64_t` | Validity end |
| `certPem` | `String` | Minted client leaf cert |
| `keyPem` | `String` | Minted private key |
| `chainPem` | `String` | Chain PEM for trust path |
| `issuerFactoryGeneration` | `uint64_t` | Factory generation used for issuance |

## 6. Certificate Lifecycle Policy

### 6.1 Application inbound TLS policy
1. Leaf validity is sourced from deployment policy (`leafValidityMs`/days), default 15 days when not overridden.
2. Renewal scheduling starts when 10% of lifetime remains.
3. Renewal trigger formula: `renewAtMs = notAfterMs - ceil((notAfterMs - notBeforeMs) * 0.10)`.
4. For the default 15-day validity, renewal starts at day 13.5 (about 36 hours before expiry).
5. Per-container jitter window is constrained inside the final 10% window.
6. Retry interval on failure = 15 minutes.
7. Escalation threshold = remaining lifetime <= 2%.
8. Emergency issuance path bypasses normal jitter.

### 6.2 Overlap policy
1. Previous generation remains accepted for configurable overlap.
2. Default overlap = 24 hours for inbound server certs.
3. On successful apply+ack, Brain may shorten overlap if deployment requires fast cutover.

### 6.3 Revocation policy
1. Revocation event emits credential delta with `reason=revoke`.
2. Container removes revoked generation and confirms removal.
3. Brain marks container non-compliant if ack missing beyond timeout.

### 6.4 Client certificate mint policy
1. Deployment-managed containers are server-cert by default and do not auto-receive client cert identities.
2. Client cert issuance requires explicit `MothershipTopic::mintClientTlsIdentity` request.
3. Mint request hard-fails if `applicationID` has no pre-existing vault factory.
4. Minted client cert validity is bounded by vault policy and request validation rules.

## 7. API Credential Lifecycle Policy
1. Credentials are logical-name keyed and generation-based.
2. Rotation supports overlap with `activeFromMs` and optional `sunsetAtMs`.
3. Each provider can define refresh strategy.
4. Non-expiring secrets still receive periodic re-issue cadence for hygiene.
5. Emergency revoke path invalidates generation immediately and emits delta.
6. API credentials are registered in Mothership per `applicationID` through explicit upsert topic calls.
7. Deployment plan declares required API credential names; Brain distributes only referenced keys.
8. When registered key material changes, Brain emits runtime credential deltas to all live containers in scope.
9. Deployment admission hard-fails if any required API credential name is missing from the registered set.
10. Missing required API credentials never use fail-open behavior.

## 8. Protocol and Control-Plane Changes

### 8.1 Enum additions
1. Add `NeuronTopic::refreshContainerCredentials`.
2. Add `ContainerTopic::credentialsRefresh`.
3. Add `MothershipTopic::upsertTlsVaultFactory`.
4. Add `MothershipTopic::upsertApiCredentialSet`.
5. Add `MothershipTopic::mintClientTlsIdentity`.

### 8.2 Message payload contracts
1. `MothershipTopic::upsertTlsVaultFactory` is bidirectional:
   1. caller -> Mothership payload: `(TlsVaultFactoryUpsertRequest)`,
   2. Mothership -> caller payload: `(TlsVaultFactoryUpsertResponse)`.
2. `MothershipTopic::upsertApiCredentialSet` is bidirectional:
   1. caller -> Mothership payload: `(ApiCredentialSetUpsertRequest)`,
   2. Mothership -> caller payload: `(ApiCredentialSetUpsertResponse)`.
3. `MothershipTopic::mintClientTlsIdentity` is bidirectional:
   1. caller -> Mothership payload: `(ClientTlsMintRequest)`,
   2. Mothership -> caller payload: `(ClientTlsMintResponse)`.
4. Request vs response is determined by direction of flow, not by separate topics.
5. Brain pulls or subscribes to vault factory metadata by `applicationID`.
6. Brain pulls or subscribes to API credential set metadata by `applicationID`.
7. Brain -> Neuron: `(containerUUID, credentialDelta)`.
8. Neuron -> Container: `(credentialDelta)`.
9. Container -> Neuron ack: `ContainerTopic::credentialsRefresh` with empty payload.
10. Neuron infers acked generation from the latest pending delta for that container stream.
11. Neuron -> Brain ack relay: `(containerUUID, bundleGeneration, success, failureReason, hash)` where failure is timeout/no-ack or apply-failure signals observed before ack.

### 8.3 Reliability and replay semantics
1. Neuron queues outbound credential deltas when container stream unavailable.
2. Latest generation supersedes stale queued generations for same credential name.
3. Ack timeout triggers redelivery with backoff.
4. Duplicate delta delivery must be idempotent in container apply path.
5. The same `ContainerTopic::credentialsRefresh` topic is bidirectional:
   1. with payload = refresh delta (Neuron -> Container),
   2. without payload = ack (Container -> Neuron).

## 9. Data-Plane Application Behavior Requirements
1. App loads all credentials from in-memory credential manager.
2. File writes are atomic (`tmp`, `fsync`, `rename`) with `0600` for private keys.
3. App updates credential registry first, then updates protocol engines.
4. If one subsystem apply fails, app reports partial failure and keeps old generation active.
5. App emits metrics and logs for apply latency and result.

## 10. Phase Plan

## Phase 0: Foundation and Safety Rails
| Item | Detail |
|---|---|
| Objective | Establish schema, feature flags, and test harness scaffolding without enabling runtime behavior |
| Duration estimate | 3 to 5 days |
| Dependencies | None |
| Code areas | `prodigy/types.h`, `enums/enums.datacenter.h`, `networking/neuron.hub.h` |
| Tasks | Add new credential structs with Bitsery serialization. Add enum values for refresh topics, including bidirectional no-payload ack semantics on `ContainerTopic::credentialsRefresh`. Add feature flags: `PRODIGY_ENABLE_CREDENTIALS_BOOT`, `PRODIGY_ENABLE_CREDENTIALS_REFRESH`. Add compile-time defaults OFF. |
| Deliverables | Buildable schema/enum changes with no behavior change |
| Exit criteria | Existing workloads unchanged with flags OFF |
| Rollback | Revert schema and enum additions as one patchset |

## Phase 1: Deployment Schema and Mothership Wiring
| Item | Detail |
|---|---|
| Objective | Add app-level TLS vault factory and API credential registration APIs, then wire deployment config to issuance/distribution policy |
| Duration estimate | 4 to 6 days |
| Dependencies | Phase 0 |
| Code areas | `prodigy/mothership/mothership.cpp`, `prodigy/types.h` |
| Tasks | Add `MothershipTopic::upsertTlsVaultFactory` handler keyed by `applicationID`. Implement `mode=generate` path that creates root+intermediate and returns them in response. Implement `mode=import` path that validates caller material and persists it. Persist vault factory metadata and encrypted key material. Add `MothershipTopic::upsertApiCredentialSet` handler keyed by `applicationID`; persist API credentials by logical name with generation semantics. Add `MothershipTopic::mintClientTlsIdentity` handler that mints client cert/key/chain from pre-existing vault factory and returns material to caller. Convert existing `tls` parse path from fail-closed to real plan assignment. Add deployment policy flags: `enablePerContainerLeafs`, `leafValidityMs`, `renewLeadPercent`, `applicationID`. Add deployment API credential policy flags: `requiredCredentialNames`, `refreshPushEnabled`. Validate names, validity windows, SAN limits, provider constraints, and existence of app vault factory and app API credential set. Hard-fail deployment admission on unresolved references. Auto-creating vault factories or API keys from deployment parsing is forbidden. Persist into `DeploymentPlan` and `ContainerPlan`. |
| Deliverables | End-to-end config parse to in-memory plan objects |
| Exit criteria | `DeploymentPlan` and `ContainerPlan` contain validated credential intent data and app vault/API credential references; unresolved references are rejected with hard-fail errors |
| Rollback | Keep parser accepted but gated by feature flag fallback to old behavior |

## Phase 2: Issuance Service in Brain
| Item | Detail |
|---|---|
| Objective | Operationalize certificate issuance with deployment-plan-defined leaf policy |
| Duration estimate | 5 to 8 days |
| Dependencies | Phase 1 |
| Code areas | `prodigy/vault.h`, Brain orchestration files under `prodigy/brain/` |
| Tasks | Create brain-side credential issuer module using persisted `ApplicationTlsVaultFactory` per `applicationID`. If `enablePerContainerLeafs=true`, issue unique per-container leafs for configured identities. Parameterize leaf days to 15 default with per-deployment override. Store issuance metadata and generation index per `(containerUUID, identityName)`. Add renewal scheduler with 10%-remaining trigger and bounded jitter. Implement on-demand client cert mint path servicing `MothershipTopic::mintClientTlsIdentity` requests. |
| Deliverables | Issuer + scheduler + metadata registry |
| Exit criteria | Brain can mint generation N+1 and stage delta for target containers |
| Rollback | Disable scheduler and hold previous generation active |

## Phase 3: Boot-Time Credential Bundle Delivery
| Item | Detail |
|---|---|
| Objective | Deliver initial credential snapshot through `ContainerParameters` at startup |
| Duration estimate | 4 to 6 days |
| Dependencies | Phase 1, Phase 2 |
| Code areas | `prodigy/types.h`, `prodigy/neuron/containers.h`, `networking/neuron.hub.h` |
| Tasks | Add `CredentialBundle` to `ContainerParameters`. Populate in Neuron before memfd serialization. When per-container leaf issuance is enabled, embed container-unique server cert/key/chain material generated from app vault factory. Select and embed only API credentials listed in deployment `requiredCredentialNames`. Deserialize in container bootstrap path. Add invariants and size limits for bundle payload. |
| Deliverables | Container receives credentials at boot without post-boot dependency |
| Exit criteria | App can start with credentials solely from bundle when fallback files absent |
| Rollback | Maintain fallback to existing path-based TLS files while bundle feature flag off |

## Phase 4: Runtime Refresh Transport (Brain -> Neuron -> Container)
| Item | Detail |
|---|---|
| Objective | Add reliable TLS/API credential refresh channel with acknowledgements |
| Duration estimate | 6 to 9 days |
| Dependencies | Phase 0, Phase 2 |
| Code areas | `enums/enums.datacenter.h`, `prodigy/neuron/neuron.h`, `networking/neuron.hub.h` |
| Tasks | Implement refresh message construction in Brain for both TLS and API key updates, relay and queueing in Neuron, dispatch in container `NeuronHub`. Implement bidirectional `ContainerTopic::credentialsRefresh` handling where empty payload means ack. Infer acked generation from pending state and relay ack telemetry to Brain. Add dedupe and replay semantics. Ensure API credential set updates from Mothership fan out as runtime push deltas to all active containers in matching deployments. |
| Deliverables | Runtime credential delta transport |
| Exit criteria | Successful refresh on live container and ack visible at Brain |
| Rollback | Disable refresh topic handlers via feature flag |

## Phase 5: Application Server Credential Manager
| Item | Detail |
|---|---|
| Objective | Replace hardcoded credential use with logical-name registry |
| Duration estimate | 5 to 8 days |
| Dependencies | Phase 3, Phase 4 |
| Code areas | `application/application.server.cpp`, `networking/h2nb.client.h`, `application/quic.clientHub.h`, `application/tcp.clientHub.h`, `networking/tls.h` |
| Tasks | Add app-local credential manager map keyed by name and generation. Feed it from boot bundle and runtime deltas. Replace Telnyx hardcoded bearer with lookup `telnyx_bearer`. Replace inbound TLS file path constants with identity `inbound_server_tls`. Replace APNS path assumptions with identity `apns_client_tls`. |
| Deliverables | App server consumes credentials by logical name only |
| Exit criteria | No hardcoded API key literals and no hardcoded TLS identity selection |
| Rollback | Keep current literals behind fallback env flag for emergency rollback only |

## Phase 6: Live Reload for Inbound TLS (TCP + QUIC)
| Item | Detail |
|---|---|
| Objective | Apply new TLS generations without full container restart |
| Duration estimate | 8 to 12 days |
| Dependencies | Phase 5 |
| Code areas | `networking/tls.h`, `application/tcp.clientHub.h`, `networking/quic.h`, `application/quic.clientHub.h`, `application/application.server.cpp` |
| Tasks | Implement hot context replacement for TCP TLS singleton with generation pinning for existing connections. Implement QUIC engine drain-and-swap using old engine for existing sessions and new engine for new accepts. Add bounded drain timeout and forced close policy. |
| Deliverables | Stable live reload pipeline |
| Exit criteria | New inbound handshakes use generation N+1 while existing sessions remain stable |
| Rollback | Revert to restart-required apply mode via runtime flag |

## Phase 7: API Credential Refresh and Outbound Client Reload
| Item | Detail |
|---|---|
| Objective | Refresh registered API tokens and client TLS identities live |
| Duration estimate | 5 to 8 days |
| Dependencies | Phase 5 |
| Code areas | `networking/h2nb.client.h`, application operations that construct outbound requests |
| Tasks | Bind outbound auth header population to credential manager lookup per request. Implement APNS client TLS context refresh path. Add provider-specific adapters for token formats. When `MothershipTopic::upsertApiCredentialSet` updates material, publish runtime push to target containers and verify apply ack. Ensure stale in-flight requests complete with previous generation safely. |
| Deliverables | Outbound auth and outbound TLS refresh without restart |
| Exit criteria | Telnyx and APNS credential rollovers succeed in live canary |
| Rollback | Keep previous generation active and disable outbound refresh pipeline |

## Phase 8: Security Hardening and Auditability
| Item | Detail |
|---|---|
| Objective | Enforce secure handling, observability, and compliance controls |
| Duration estimate | 4 to 6 days |
| Dependencies | Phase 4, Phase 5 |
| Code areas | Brain scheduler, Neuron relay, app server apply path, logging/metrics modules |
| Tasks | Redact secret material in logs. Add event audit records for issue/distribute/apply/revoke. Enforce max payload sizes and schema validation guardrails. Add checksum/hash validation at each hop. Add strict file permission checks and key zeroization where practical. |
| Deliverables | Security posture suitable for production operation |
| Exit criteria | Security review checklist passed |
| Rollback | Keep strict mode warnings-only during initial deployment window |

## Phase 9: Canary, Progressive Rollout, and Deletion of Legacy Paths
| Item | Detail |
|---|---|
| Objective | Move from compatibility mode to mandatory Prodigy-managed credentials |
| Duration estimate | 7 to 14 days |
| Dependencies | Phase 6, Phase 7, Phase 8 |
| Code areas | Deployment toggles, app server fallback paths, release automation |
| Tasks | Roll out by environment and percentage. Track SLOs for handshake success, refresh success, and ack latency. Validate vault factory upsert flows (`generate` and `import`), API credential set upsert flows, and client cert mint flows in canary before global enablement. Remove hardcoded literals and legacy file assumptions after two stable rotation cycles. |
| Deliverables | Full migration complete |
| Exit criteria | 100% production workloads on Prodigy-managed credential lifecycle |
| Rollback | Percentage rollback by deployment group; restore previous generation and disable refresh topics |

## 11. Detailed Work Breakdown by System

### 11.1 Types and serialization
1. Add `TlsIdentity`, `ApiCredential`, `CredentialBundle`, `CredentialDelta`, `ApplicationTlsVaultFactory`, `TlsVaultFactoryUpsertRequest`, `TlsVaultFactoryUpsertResponse`, `DeploymentTlsIssuancePolicy`, `ApplicationApiCredentialSet`, `ApiCredentialSetUpsertRequest`, `ApiCredentialSetUpsertResponse`, `DeploymentApiCredentialPolicy`, `ClientTlsMintRequest`, and `ClientTlsMintResponse` to `prodigy/types.h`.
2. Add Bitsery serializers adjacent to existing plan/parameter serializers.
3. Add upper bounds for container sizes and string lengths to prevent oversized memfd payloads.

### 11.2 Enums and protocol
1. Add new `NeuronTopic` and `ContainerTopic` values in `enums/enums.datacenter.h`.
2. Add strict payload parsing with bounded extraction in `networking/neuron.hub.h`.
3. Add unknown-generation and stale-generation handling semantics.
4. Add single-topic bidirectional payload contract for app vault factory upsert.
5. Add single-topic bidirectional payload contract for app API credential set upsert.
6. Add single-topic bidirectional payload contract for on-demand client cert minting.
7. Add authz checks so only authorized callers can mutate vault factory or API credential set for an `applicationID` and request client cert minting.
8. Enforce deployment admission hard-fail when references to vault factory/API credential set are unresolved.

### 11.3 Brain credential scheduler
1. Create schedule index keyed by `containerUUID` and credential identity name.
2. Compute next renewal at `notAfterMs - ceil((notAfterMs - notBeforeMs) * renewLeadPercent / 100) - jitter`.
3. Trigger immediate replacement for revoked identities.
4. Publish deltas through Neuron channel with retry tracking.
5. Read issuance policy from deployment plan (`enablePerContainerLeafs`, `leafValidityMs`, `renewLeadPercent`).
6. Track API credential set generation per `applicationID` and push deltas when set generation changes.
7. Filter pushed API credentials to deployment `requiredCredentialNames`.
8. Handle synchronous/on-demand client cert mint requests from `MothershipTopic::mintClientTlsIdentity`.

### 11.4 Neuron relay
1. Maintain pending credential delta queue per container similar to pairing queue strategy.
2. Deduplicate by identity name and generation.
3. Replay pending updates on reconnect.
4. Forward ack telemetry to Brain.

### 11.5 App server apply engine
1. Add `CredentialManager` structure in application server process.
2. Implement idempotent apply by generation.
3. Call `tlsIdentityReceived` for file persistence only as transitional path.
4. Add direct in-memory apply for TLS contexts and outbound auth.

### 11.6 Live reload specifics
1. TCP TLS: provide atomic swap for shared context handle.
2. QUIC: maintain dual-engine epoch for drain window and promote new engine as active acceptor.
3. Outbound HTTP2: read token at request-serialization time, not one-time at boot.
4. APNS client cert: support SSL context rebuild on generation update.

## 12. Testing Strategy

## 12.1 Unit tests
1. Serialization round-trip for all new credential structs.
2. Generation ordering and stale-update rejection.
3. Delta merge and delete semantics.
4. Renewal scheduler timing calculations around day boundaries, percent-lead triggers, and jitter.
5. Vault factory create/update tests for both modes: `generate` and `import`.
6. Validation tests that `import` rejects incomplete root/intermediate bundles.
7. API credential set upsert merge/delete behavior by logical name.
8. Deployment API policy validation for `requiredCredentialNames` existence.
9. Deployment TLS policy validation hard-fails when `applicationID` has no pre-existing vault factory.
10. Client cert mint request validation hard-fails when vault factory is missing.

## 12.2 Integration tests
1. Boot bundle delivery from Brain to container through memfd path.
2. Runtime refresh with Neuron disconnect/reconnect replay.
3. Ack timeout and redelivery behavior.
4. Multi-identity apply where one identity succeeds and one fails.
5. `MothershipTopic::upsertTlsVaultFactory` round trip with persisted reload across process restart.
6. DeploymentPlan with `enablePerContainerLeafs=true` yields unique cert serials per container.
7. `MothershipTopic::upsertApiCredentialSet` round trip with persisted reload across process restart.
8. DeploymentPlan `requiredCredentialNames` distribution includes only declared API keys.
9. API credential set update pushes refresh delta to live containers and receives ack.
10. DeploymentPlan admission fails when referenced vault factory is absent.
11. DeploymentPlan admission fails when any required API key name is absent.
12. `MothershipTopic::mintClientTlsIdentity` round trip returns cert/key/chain for valid request.

## 12.3 End-to-end tests
1. Inbound TLS rotation test across two generations without process restart.
2. QUIC new-connection handshake switches to generation N+1 while old sessions continue.
3. Telnyx token rotation while request traffic is live.
4. APNS client cert rotation while push traffic is live.
5. 10%-remaining auto-renew event triggers issuance and successful delta apply before expiry.
6. Minted client cert can complete an outbound mTLS handshake in integration environment.

## 12.4 Chaos and failure tests
1. Neuron crash during refresh fanout.
2. Container restart between delta receive and apply ack.
3. Corrupted PEM payload detection.
4. Expired cert delivered accidentally and rejection path.

## 13. Observability and SLOs

### 13.1 Metrics
1. `credentials_issue_success_total`
2. `credentials_issue_failure_total`
3. `credentials_refresh_sent_total`
4. `credentials_refresh_ack_success_total`
5. `credentials_refresh_ack_failure_total`
6. `credentials_apply_latency_ms`
7. `tls_identity_days_to_expiry`
8. `credentials_pending_queue_depth`
9. `api_credential_set_upsert_total`
10. `api_credential_set_upsert_failure_total`
11. `api_credential_distribution_fanout_total`
12. `client_tls_mint_success_total`
13. `client_tls_mint_failure_total`

### 13.2 Logs
1. Issue event with identity name, generation, notAfter.
2. Distribution event with container UUID and delta generation.
3. Apply event with subsystem, success, and failure reason.
4. Revocation event with reason code.
5. No log entries may include raw private keys or raw token material.
6. API credential set upsert event with `applicationID`, updated names, removed names, and set generation.
7. Client cert mint event with `applicationID`, identity name, generation, and notAfter.

### 13.3 Alerts
1. Any identity inside final 10% lifetime window with no pending successful renewal ack.
2. Refresh ack failure rate above threshold for 10 minutes.
3. Pending queue depth above threshold per container.
4. Inbound TLS handshake failure spike correlated with generation cutover.
5. Deployment has missing required API credential names at boot planning time.
6. Deployment references a TLS vault factory that does not exist at admission time.

## 14. Security Controls
1. Secrets never committed to repository and never emitted in plain logs.
2. Private key files written with mode `0600` and owned by container process user.
3. Memory handling minimizes plaintext lifetime for key material.
4. All credential updates carry generation and integrity hash.
5. Brain-side issuance keys protected and access-audited.
6. Revocation workflow available for emergency credential compromise.
7. Vault factory key material encrypted at rest with strict access control and audit trail.
8. `mode=generate` responses containing root/intermediate keys are one-time visibility events and must be redacted from logs.
9. API credential material encrypted at rest and never returned by read/list APIs without explicit secret-access authorization.
10. Client cert mint responses containing private keys are one-time visibility events and must be redacted from logs.

## 15. Backward Compatibility and Migration
1. Maintain compatibility mode where legacy hardcoded paths still work until Phase 9 completion.
2. Introduce progressive rollout flags per deployment.
3. Maintain old generation overlap until new generation confirmed active.
4. Remove fallback paths only after two successful full rotation cycles in production.

## 16. Runbooks

### 16.1 Manual certificate rotate
1. Operator requests manual rotate for identity.
2. Brain issues generation N+1 immediately.
3. Brain sends delta to target containers.
4. Confirm ack success and generation promotion.
5. Sunset N after overlap window.

### 16.2 Create or update app TLS vault factory
1. Caller sends `MothershipTopic::upsertTlsVaultFactory` with `applicationID` and `mode`.
2. If `mode=generate`, Prodigy creates root+intermediate and returns them in response.
3. If `mode=import`, Prodigy validates supplied root+intermediate then persists encrypted.
4. Brain/Deployment validation confirms factory availability for all deployments using that `applicationID`.

### 16.3 Create or update app API credential set
1. Caller sends `MothershipTopic::upsertApiCredentialSet` with `applicationID` and credential upserts/removals.
2. Prodigy validates provider metadata, logical name uniqueness, and generation monotonicity.
3. Prodigy persists set and returns `setGeneration` plus updated/removed names.
4. Brain fans out runtime delta to live containers in deployments requiring those names.
5. Verify container apply ack for new API generation.

### 16.4 Mint client TLS certificate on demand
1. Caller sends `MothershipTopic::mintClientTlsIdentity` with `applicationID`, identity metadata, and requested validity.
2. Prodigy hard-fails if no pre-existing vault factory exists for that `applicationID`.
3. Prodigy mints client cert/key/chain and returns response payload on the same topic (reverse direction).
4. Caller stores/distributes minted material via approved secret channels.

### 16.5 Emergency revoke and replace
1. Mark generation compromised.
2. Brain issues replacement generation immediately.
3. Brain sends revoke+replace delta with urgent priority.
4. Validate apply ack and force drain non-compliant containers.

### 16.6 Provider API key emergency swap
1. Insert replacement `ApiCredential` generation with `activeFromMs=now`.
2. Deliver refresh delta.
3. Confirm outbound request auth success.
4. Set immediate sunset on compromised generation.

## 17. Risks and Mitigations
| Risk | Impact | Mitigation |
|---|---|---|
| QUIC hot reload complexity | Connection instability during cutover | Dual-engine drain-and-swap, bounded drain timeout, canary first |
| Large credential payloads in memfd | Startup failure or latency | strict size limits, compression optional, split across delta updates |
| Ack loss causing repeated refresh loops | Control-plane churn | generation dedupe and idempotent apply semantics |
| Provider-specific token semantics | Outbound auth breakage | provider adapter interface and staged canaries |
| Operator error in SAN/policy config | Handshake failures | parser validation and pre-issuance policy checks |
| Mishandled factory key import | CA trust breakage | strict PEM/key pair validation and signed test issuance before accept |
| Generated root/intermediate leakage | catastrophic compromise | one-time response visibility, transport encryption, redaction, audit |
| API key over-distribution to containers | secret exposure blast radius | strict `requiredCredentialNames` filtering and deny-by-default policy |
| API key refresh fanout storm | control-plane/backpressure risk | bounded batching, queue limits, and backoff with dedupe |
| Minted client key leakage in response path | client identity compromise | strict authz, one-time response visibility, redaction, and audit |

## 18. Acceptance Criteria for Full Completion
1. No hardcoded API key strings in application runtime path.
2. No mandatory dependency on static cert files for inbound TLS startup.
3. Automatic deployment-plan-defined certificate lifecycle (default 15 days) with proactive renewal and successful apply acknowledgements.
4. Runtime refresh works for multiple TLS identities and multiple API credentials per container.
5. QUIC and TCP inbound TLS can move to new generations without required container restart.
6. End-to-end observability, audit logs, and alerting are active and verified.
7. App-level vault factory exists and is persisted per `applicationID`.
8. Both factory modes (`generate`, `import`) are validated and production-ready.
9. Deployments with per-container issuance flag produce unique leaf certs and rotate at 10%-remaining threshold.
10. API credential registration topic persists keys per `applicationID` and deployment references control per-container distribution.
11. API credential updates trigger runtime refresh push and successful container ack.
12. Deployment admission hard-fails when vault factory or required API key references are unresolved; no auto-create/fail-open path exists.
13. `MothershipTopic::mintClientTlsIdentity` supports on-demand client certificate minting from pre-existing vault factories.

## 19. Suggested Execution Order
1. Complete Phases 0 through 3 before touching live reload.
2. Complete Phase 4 transport reliability before enabling any credential rotation in production.
3. Complete Phase 5 consumer abstraction before removing hardcoded credentials.
4. Execute Phase 6 and Phase 7 in canary waves.
5. Run Phase 8 security hardening before broad production rollout.
6. Use Phase 9 to retire legacy behavior deliberately and safely.

## 20. Immediate Next Actions
1. Approve credential data model names and enum additions.
2. Approve protocol payload contracts for refresh and ack.
3. Approve single-topic bidirectional contract for `MothershipTopic::upsertTlsVaultFactory` and authz model.
4. Approve single-topic bidirectional contract for `MothershipTopic::upsertApiCredentialSet` and authz model.
5. Approve single-topic bidirectional contract for `MothershipTopic::mintClientTlsIdentity` and authz model.
6. Approve renewal policy values: `renewLeadPercent=10`, escalation at <=2% remaining, 24h overlap default.
7. Begin Phase 0 implementation branch with schema and flags only.
