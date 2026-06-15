# /goal: Prodigy routable-prefix redesign and DNS provider integration

Execute a hard-cut redesign of Prodigy's routable-prefix registry and routable
address consumption model, then add a
minimal DNS provider layer and integrate DNS-backed wormhole ingress. This is a
real runtime/control-plane feature, not a documentation-only pass.

Keep the implementation small, explicit, and production-oriented. Prefer
deleting obsolete address modes over adapting them. Do not preserve backward
compatibility for old address-first routable semantics unless a currently
persisted production state proves that migration is required.

## Minimal Surface Contract

All code written for this goal must be the tersest, most elegant, most minimal
LOC +/- surface possible for a correct production implementation.

- Prefer deleting or simplifying old address paths before adding new code.
- Prefer extending existing coherent modules over creating new files.
- Add a helper, type, enum, or abstraction only when it removes real duplication,
  enforces a necessary boundary, or materially reduces complexity.
- Keep provider implementations thin and boring: no common framework unless it
  deletes more code than it adds across real providers.
- Do not add speculative knobs, migration compatibility, provider policy
  extensions, or future-proofing seams.
- At every phase, report net LOC change for touched production and test files,
  explain why each new public surface exists, and name any code deleted.
- Before final completion, do a staff-level surface-area audit and remove any
  code, config, command, or test fixture that does not earn its maintenance cost.

## Hard Boundaries

1. Replace the current routable-resource kinds with exactly two supported
   routable-prefix registration concepts:
   - `elastic`: a provider-acquired address registered as a host prefix
     (`/32` for IPv4, `/128` for IPv6) unless the provider truthfully returns a
     wider routed prefix.
   - `BGP`: an operator-provided subnet/prefix that Prodigy is allowed to
     announce/route through the switchboard fleet.
2. Register routable inventory as `IPPrefix`, but consume wormhole ingress as
   concrete `IPAddress`. A registered `/24` or `/48` is inventory; a wormhole
   gets one address from it.
3. Whiteholes also consume from registered routable `IPPrefix` inventory, but
   their live resource is an `IPAddress:sourcePort` pair. Whiteholes may share
   the same `IPAddress`; Prodigy must choose and reserve unique IP:port pairs.
4. Consumed ingress/egress resources are owned while live. This applies to
   concrete wormhole `IPAddress` values, whitehole `IPAddress:sourcePort` pairs,
   and DNS names with attached concrete addresses. No two different live
   deployments may own the same DNS name, the same consumed wormhole
   `IPAddress`, or the same consumed whitehole IP:port pair. Deployment upgrades
   may transfer ownership within the same application lineage, but that
   exception must be explicit and atomic.
5. Accept and store registered IPv4/IPv6 prefixes such as `/32`, `/128`, `/24`,
   `/48`, and provider-accepted variants. Accept bare IP literals only at
   registration parser/API edges and canonicalize them immediately to host
   prefixes. Convert host prefixes back to concrete `IPAddress` only when a
   wormhole, whitehole, or DNS binding consumes an address.
6. Do not let DNS bindings target arbitrary machine public addresses by default.
   Production DNS-backed ingress must target an address allocated from registered
   routable inventory with a clear fleet ingress contract.
7. DNS for wormholes must be zero-effort and declarative from the deployment
   plan JSON. If a wormhole declares DNS provider/config, Prodigy first claims
   the concrete `IPAddress`, then creates or updates the DNS record for that
   claimed address. If no DNS provider/config is declared, the wormhole remains
   address-only.
8. Do not conflate DNS with packet routing. DNS publishes names to routable
   addresses; switchboard and overlay routing decide packet delivery after
   ingress.
9. Keep DNS v1 to add/upsert and remove records only. No weighted, latency,
   geolocation, proxying, health-check, ALIAS/ANAME, or provider-specific policy
   surface in the first pass.
10. Test/dev clusters must continue to work without real DNS or cloud address
   allocation. Dev IaaS must provide deterministic fake routable behavior for
   existing tests.
11. Any runtime/system tests that touch host networking, BPF, cgroups, mounts, or
   namespaces must obey `AGENTS.md` host-safety rules. Stop before unsafe host
   mutation.

## Current Code To Inspect First

- `prodigy/types.h`
- `prodigy/routable.address.helpers.h`
- `prodigy/brain/brain.h`
- `prodigy/brain/deployments.h`
- `prodigy/iaas/iaas.h`
- `prodigy/iaas/dev/dev.h`
- `prodigy/iaas/aws/aws.h`
- `prodigy/iaas/gcp/gcp.h`
- `prodigy/iaas/azure/azure.h`
- `prodigy/iaas/vultr/vultr.h`
- `prodigy/iaas/runtime/runtime.h`
- `prodigy/mothership/mothership.cpp`
- `prodigy/mothership/mothership.provider.credential.types.h`
- `prodigy/mothership/mothership.provider.credentials.h`
- `prodigy/dev/tests/*routable*`
- `prodigy/dev/tests/*provider*`
- `prodigy/dev/tests/*deployments*`
- `prodigy/dev/tests/*switchboard*`

Before editing, trace all callers and persistence/wire serialization for
`RegisteredRoutableAddress`, `RoutableAddressRegistration`, wormholes with
registered addresses, provider elastic-address functions, and the replacement
prefix-registration/address-consumption model.

Current implementation anchors to verify during the goal:

- `DeploymentPlan` already carries serialized `wormholes` and `whiteholes`.
- Mothership deployment-plan JSON currently parses wormholes from
  `externalAddress` or `routableAddressUUID`; there is no inline DNS declaration
  yet.
- Whitehole runtime state already carries `sourcePort`; preserve and harden that
  IP:port identity instead of inventing a separate whitehole routing concept.

## Required Work

### A. Redesign The Routable Prefix And Address Model

- Replace the existing address-source/kind model with registered prefixes and
  consumed addresses using the supported registration concepts:
  `elastic` and `BGP`.
- Preserve the stored facts that still matter:
  - stable registered-prefix UUID;
  - name;
  - owner `machineUUID` when the registered prefix is single-machine owned;
  - concrete canonical registered `IPPrefix`;
  - address family inferred from the prefix;
  - provider allocation/association metadata for elastic host prefixes;
  - release/cleanup behavior;
  - explicit ingress scope;
  - owner application/deployment identity for consumed live wormhole addresses
    and whitehole address/port pairs;
  - parent prefix identity when a consumed resource is allocated from a larger
    BGP prefix.
- Add an ingress-scope concept or equivalent invariant:
  - `singleMachine`: traffic is expected to land on one owner machine.
  - `switchboardFleet`: traffic may land on any participating switchboard.
- Require DNS-managed production bindings to target `switchboardFleet` unless
  the caller explicitly opts into `singleMachine` behavior.
- Delete obsolete address kinds such as generic `testFakeAddress`,
  `anyHostPublicAddress`, and old registered-address source semantics after the
  new model replaces their behavior.
- Keep `IPPrefix` as the registered inventory type. Keep `IPAddress` as the
  wormhole/DNS consumption type and `(IPAddress, sourcePort)` as the whitehole
  consumption type. Do not make wormholes or whiteholes request arbitrary
  non-host prefixes.
- If a registration API accepts a plain IP for ergonomics, convert it to a host
  `IPPrefix` before registry validation and persistence.

### B. BGP Prefix Registration

- Add a mothership registration path for `BGP` prefixes.
- `BGP` entries are operator-provided: do not ask cloud providers to
  allocate them.
- Validate prefix family and CIDR strictly.
- Validate that production DNS use requires a fleet-routable prefix/address
  allocation path.
- Ensure switchboard state sync and overlay routes still converge after adding,
  changing, or removing these entries.
- Preserve support for non-host prefixes. A `/24` or `/48` must be represented
  as a prefix, not collapsed into one host address.
- Treat larger BGP prefixes as allocatable inventory when requested. For example,
  a registered `/24` can supply individual IPv4 addresses and a registered `/48`
  can supply individual IPv6 addresses.
- Never distribute the same concrete BGP-backed address to different live
  deployments.

### C. Elastic Prefix Registration

- Redesign the provider API around elastic-prefix intent:
  - `any`: select an existing provider-owned address that can be attached or
    used, then register it as a host prefix.
  - `create`: allocate a new provider address.
  - `anyOrCreate`: use an existing address if possible, otherwise allocate one.
- Every elastic result must be an `IPPrefix`. A traditional elastic IPv4 address
  is `/32`; an IPv6 elastic address is `/128`; a provider-routed prefix may use
  its actual CIDR only if the provider API proves that prefix is routable.
- If the active provider cannot satisfy the request, fail with a concrete
  provider-derived error.
- Keep provider cleanup explicit. If Prodigy created the address, removal should
  release it when configured to do so. If Prodigy selected an existing address,
  removal must not accidentally delete it.
- AWS, GCP, and Azure already have elastic/public IP attach logic. Refactor those
  paths into the new intent model with the smallest possible surface.
- Decide and document what Vultr supports. If Vultr lacks compatible elastic IP
  semantics, fail explicitly instead of faking it.

### D. Dev/Test And Single-Machine Behavior

- Implement dev IaaS behavior so test clusters can continue to register fake
  routable prefixes without cloud credentials.
- Preserve current fake-address semantics as host prefixes that yield concrete
  `IPAddress` wormhole assignments through the new
  `elastic` or `BGP` model, whichever is cleaner and more truthful.
- In one-machine dev/local clusters, allow DNS or routable-prefix registration
  to use that machine's host prefix and concrete address when the requested
  ingress scope is explicitly `singleMachine`.
- Do not allow that shortcut to masquerade as switchboard-fleet ingress.

### E. Routable Resource Ownership And Allocation

- Add a minimal ownership model for consumed routable resources. The owner must
  include enough identity to distinguish applications, live deployments, and
  upgrade lineage.
- Owned resources include concrete wormhole `IPAddress` values, whitehole
  `IPAddress:sourcePort` pairs, and DNS names that resolve to attached routable
  addresses.
- A wormhole may only consume a raw routable address or DNS-backed ingress
  address after ownership is reserved for its deployment.
- Reject any reservation where the requested `IPAddress` is already owned by a
  different live deployment for wormhole ingress.
- A whitehole may only consume a routable source address after Prodigy chooses a
  unique source port for that address and reserves the `IPAddress:sourcePort`
  pair for its deployment.
- Whiteholes may share the same `IPAddress` across deployments and containers.
  The conflict key is the IP:port pair, not the IP alone.
- Every consumed `IPAddress` must be contained in exactly one selected
  registered `IPPrefix` inventory entry, unless a deliberate operator-owned
  exception is explicitly modeled.
- Define prefix intersection precisely:
  - normalize every raw address as a prefix (`/32` for IPv4, `/128` for IPv6)
    and canonicalize every prefix by family, network bytes, and CIDR before
    comparison;
  - prefixes of different address families never intersect;
  - two same-family prefixes intersect iff their canonical numeric ranges overlap:
    `aStart <= bEnd && bStart <= aEnd`;
  - handle `/0`, `/32`, and `/128` without shift overflow; prefer mask/range
    helpers already present in the codebase over ad hoc string comparison.
- Use that prefix logic for registered inventory validation, address containment
  checks, and prefix/address allocation. Use concrete address equality for live
  wormhole ownership and concrete IP:port equality for live whitehole ownership.
- Reject any reservation where the requested DNS record identity is already owned
  by a different live deployment, even if the requested target address differs.
- For DNS-backed ingress, reserve both the DNS record identity and the underlying
  concrete routable address. Both reservations transfer together during an allowed
  upgrade handoff.
- For BGP parent prefixes, allocate owned concrete addresses without duplication.
  The allocator must understand prefix containment and intersection; string
  equality is not enough.
- Treat registered BGP parent prefixes as inventory, not deployment ownership,
  unless a deployment explicitly reserves the whole parent prefix.
- If a whole parent prefix is reserved by a deployment, no address from it may be
  allocated to another live deployment. If any address from a prefix is live, the
  parent may not be granted wholesale to another deployment.
- Deployment upgrades may transfer ownership from the old deployment to the new
  deployment only within the same application lineage. Make this a deliberate
  handoff path, not a general overlap exception.
- Release ownership only after the deployment no longer serves traffic through
  the wormhole. Failed upgrades must leave ownership with the still-live
  deployment.
- Keep ownership state small and auditable. Do not add a general resource manager
  if focused registered-prefix inventory plus consumed-address/IP-port ownership
  is enough.
- Add tests proving no duplicate wormhole address consumption, no duplicate
  whitehole IP:port consumption, shared whitehole IPs with distinct ports,
  address containment in registered prefixes, whole-prefix reservation exclusion,
  release on destruction, and transfer on upgrade.

### F. DNS Provider Interface

- Add a small provider-neutral DNS interface. Keep v1 to:
  - upsert a complete recordset;
  - delete a recordset.
- Model record identity as `(zone, name, type)` and model values as a vector so
  recordset-based providers are natural.
- Support only `A`, `AAAA`, `CNAME`, and `TXT` initially.
- Include TTL.
- Make upsert replace the complete recordset for `(zone, name, type)`.
- Make deletes idempotent only when the provider clearly treats missing records
  as harmless; otherwise preserve provider failures.
- Return provider error bodies/messages in operator-visible failures, without
  logging credential material.

### G. DNS Provider Implementations

Implement the provider interface for:

- Cloudflare DNS.
- AWS Route53.
- GCP Cloud DNS.
- Azure DNS.
- Vultr DNS if Vultr exposes a compatible DNS API. If not, implement an explicit
  unsupported provider failure with tests.

Each implementation must:

- authenticate through the new DNS credential path;
- validate required provider scope/config such as zone ID, managed zone,
  resource group, subscription, or domain;
- handle provider "zone/domain not found" and permission failures cleanly;
- avoid leaking credentials in logs, errors, persistent state, or test output;
- parse enough provider response data to prove the requested upsert/delete
  completed or failed.

### H. DNS Credentials And Configuration

- Add a way to register DNS provider credentials independently of compute
  provider credentials.
- Do not assume DNS provider equals cluster IaaS provider.
- Reuse existing provider credential registry patterns where this reduces net
  code, but do not overload `MothershipClusterProvider` if it forces compute and
  DNS into the same enum semantics.
- Support at least static token/material credentials for every DNS provider in
  v1.
- If CLI-driven credentials are reused for AWS/GCP/Azure, keep refresh behavior
  explicit and test credential/provider mismatch failures.
- Store only the minimum DNS provider config needed to perform record changes.

### I. DNS Binding Model

- Add a persisted DNS binding that references a registered routable prefix by
  UUID/name and a concrete `IPAddress` allocated from that prefix.
- The primary creation path is declarative deployment-plan JSON, not a separate
  preflight operator workflow. A wormhole may include an optional DNS declaration
  with provider/config reference, zone, record name/FQDN, type or family-inferred
  type, and TTL.
- Materialize the DNS binding only after the wormhole address claim succeeds.
  The binding's target address must be the claimed `IPAddress`; do not let plan
  JSON specify a DNS value that diverges from the claimed address.
- Required fields:
  - binding UUID;
  - binding name;
  - owner application/deployment identity when the DNS binding is consumed by a
    live wormhole;
  - DNS provider;
  - DNS credential/config reference;
  - zone;
  - FQDN/record name;
  - record type;
  - TTL;
  - registered routable prefix UUID/name;
  - consumed concrete `IPAddress` value;
  - desired values derived from the consumed address;
  - last applied status/failure if the local model already has an equivalent
    operator-visible status pattern.
- Reject DNS bindings whose consumed address is not contained in the referenced
  registered prefix.
- Reject DNS bindings whose consumed address cannot be represented by the
  requested record type (`A` for IPv4, `AAAA` for IPv6).
- Reject DNS bindings whose referenced routable resource is not owned by a live
  deployment or an explicitly operator-owned ingress resource.
- Reject DNS bindings whose FQDN/record identity is owned by a different live
  deployment.
- Reject DNS bindings that target `singleMachine` ingress unless the request
  explicitly opts into single-machine DNS.
- On registered prefix mutation/removal, reconcile or invalidate dependent DNS
  bindings deterministically.

### J. Deployment Plan Declarative DNS

- Add an optional `dns` block to each deployment-plan wormhole JSON entry. Keep
  it minimal:
  - DNS provider;
  - DNS credential/config reference;
  - zone;
  - FQDN/record name;
  - optional record type, otherwise infer `A` from IPv4 and `AAAA` from IPv6;
  - TTL.
- Do not require a separate Mothership DNS-binding command before deployment.
  A deployment plan with a wormhole DNS block is enough to claim the address,
  create/update the DNS binding, and apply the provider record.
- Keep the plan declarative: the JSON declares the desired DNS name for the
  wormhole, not the final DNS record value. Prodigy derives the value from the
  claimed `IPAddress`.
- Stage this in a strict order:
  1. validate the deployment plan and DNS declaration shape;
  2. claim/reserve the wormhole `IPAddress`;
  3. claim/reserve the DNS record identity;
  4. materialize or update the persisted DNS binding to point at the claimed
     address;
  5. apply the provider DNS record;
  6. publish wormhole/switchboard/container state.
- If DNS apply fails after address claim, fail the deployment operation and
  release any newly staged address/DNS claims. During an upgrade, do not release
  ownership held by the still-live previous deployment.
- Make the declarative path idempotent for retries and upgrades. Reapplying the
  same deployment lineage should update the owned DNS binding, not create a
  duplicate DNS resource or steal another deployment's name.
- Add deployment-plan parser and roundtrip tests for inline wormhole DNS.

### K. Mothership Commands

Add focused CLI/API operations for:

- registering/updating a routable prefix;
- unregistering a routable prefix;
- listing routable prefixes;
- listing routable ownership/leases;
- registering DNS provider credentials/config;
- upserting a DNS binding for operator/debug/backfill use;
- deleting a DNS binding;
- listing DNS bindings.

Keep JSON fields boring and explicit. Reject unknown fields. Print useful
success/failure output including provider failure messages, record identity,
registered prefix UUID/name, consumed address, whitehole source port when
applicable, and resolved values.

### L. Wormhole Integration

- Update wormhole ingress resolution so a wormhole can reference ingress by:
  - explicit `IPAddress` where allowed by the new model;
  - registered routable prefix UUID/name plus address-selection intent, resolving
    to one concrete `IPAddress` contained in that prefix;
  - DNS binding UUID/name.
- Before opening a wormhole on a routable address or DNS binding, reserve
  ownership for the deployment and reject duplicate live address ownership.
- If the deployment-plan wormhole includes DNS provider/config, execute the
  sequence in this order: claim address, reserve DNS name ownership, create or
  update the DNS binding against the claimed address, apply the provider DNS
  record, then publish the wormhole/switchboard state.
- Make declarative DNS idempotent across deployment upgrades. Re-applying the
  same plan should update the existing owned DNS binding rather than allocate a
  second DNS resource.
- For DNS-backed wormholes, reserve the DNS name and its attached routable
  address as one ingress ownership unit.
- If a wormhole references DNS, resolve that DNS binding to the underlying
  registered routable prefix and concrete consumed ingress address.
- Reject DNS references whose record is not applied or whose underlying address
  is missing.
- Keep switchboard runtime routing based on concrete routable addresses and
  container/wormhole state, not DNS text.
- Add tests proving DNS-backed wormhole config routes through the same
  switchboard state as direct registered-prefix/address config.

### M. Whitehole Integration

- Update whitehole source resolution so whiteholes consume addresses from the
  same registered routable `IPPrefix` inventory as wormholes.
- Prodigy, not the container, must choose the concrete whitehole source
  `IPAddress:sourcePort` pair.
- Allow multiple whiteholes to share the same `IPAddress` when their source ports
  differ.
- Reject any live whitehole lease that would duplicate an existing
  `IPAddress:sourcePort` pair owned by a different live deployment.
- Inject the complete whitehole source identity into switchboard state:
  `IPAddress` plus `sourcePort`. Do not inject or key whitehole state by address
  alone.
- When a container receives a whitehole IP:port pair, it must bind that assigned
  source port when creating the socket. Do not let the container use an ephemeral
  source port after Prodigy reserved a specific pair.
- Treat source-port bind failure as a whitehole readiness failure with an
  operator-visible error.
- Add tests proving same-IP/different-port sharing, duplicate IP:port rejection,
  switchboard IP:port state propagation, and container socket bind behavior.

### N. Lease, Staging, And Lifecycle Semantics

- Add durable lease state for every consumed routable resource:
  - wormhole address leases;
  - whitehole IP:port leases;
  - DNS record identity leases;
  - provider-created elastic prefix/address allocations.
- Key leases by application identity, deployment identity, upgrade lineage,
  resource kind, declared wormhole/whitehole name, registered prefix identity,
  concrete address, source port when present, and DNS record identity when
  present.
- Make allocation deterministic and idempotent. Retrying the same deployment plan
  must reuse an existing staged/live lease for the same lineage instead of
  choosing a different address, source port, or DNS name.
- Treat `any` address selection as "choose once, then pin the lease." It must not
  mean "pick a different free address on every retry."
- Keep provider/DNS side effects behind durable staged operations. A Brain crash,
  master failover, or restart after address claim but before DNS apply/publish
  must either resume idempotently or roll back only newly staged resources.
- Ensure there is one effective writer for lease allocation and provider side
  effects. Multi-brain failover must not allocate duplicate addresses, duplicate
  whitehole IP:port pairs, or apply DNS twice under different ownership.
- If provider DNS apply succeeds but runtime publish fails, recover deterministically:
  either resume publish from durable staged state or revert the newly applied DNS
  record and release newly staged claims. Do not leave orphan DNS ownership.
- If a deployment plan removes a wormhole DNS block, removes the wormhole, or the
  deployment is destroyed, delete/reconcile the DNS record and release the
  address/DNS lease only after traffic no longer depends on it.
- If provider DNS deletion fails, keep a visible pending-cleanup/failure state;
  do not silently drop ownership and leak an unmanaged provider record.
- Reject provider-side DNS records that already exist but are not owned/imported
  by Prodigy unless an explicit operator backfill/adopt/replace command is used.
- Canonicalize DNS record identity before ownership checks: provider, zone, name,
  and type must compare in one normalized form.
- Whitehole IP:port uniqueness is cluster-wide for the selected routable address
  and source port, independent of transport. If transport-specific sharing is ever
  desired, it must be a deliberate product change, not an accident of key shape.

### O. Failure Modes

Add tests and operator-visible errors for:

- DNS provider credential missing.
- DNS provider credential belongs to the wrong provider.
- provider authentication failure.
- provider authorization failure.
- domain/zone does not exist in the account.
- deployment-plan wormhole DNS block is malformed.
- deployment-plan wormhole DNS block omits required provider/config, zone, name,
  or TTL fields.
- deployment-plan wormhole DNS block tries to set record values directly instead
  of deriving them from the claimed address.
- unsupported record type.
- invalid TTL.
- DNS record already exists provider-side but is not owned/imported by Prodigy.
- DNS record identity differs only by case, trailing dot, or other normalizable
  spelling.
- DNS binding points at a missing registered routable prefix.
- DNS binding or DNS-backed wormhole attempts to reuse a DNS name owned by a
  different live deployment.
- DNS-backed wormhole reserves a DNS name but cannot reserve its attached
  routable address.
- DNS binding points at a single-machine address without explicit opt-in.
- DNS binding points at an address incompatible with the selected record type.
- DNS binding points at an address outside the referenced registered prefix.
- DNS provider apply fails after address claim; newly staged address/DNS claims
  must be released without touching the still-live deployment on upgrade.
- DNS provider apply succeeds but runtime state publish fails.
- DNS provider delete fails after a deployment removes a DNS-backed wormhole.
- Brain restart or master failover occurs between address claim, DNS apply, and
  runtime publish.
- retrying the same deployment plan chooses a different address, source port, or
  DNS ownership for the same lineage.
- concurrent deployments allocate the same wormhole address or whitehole IP:port
  pair.
- elastic prefix requested from a provider that does not support it.
- elastic `any` finds no usable provider address/prefix.
- elastic `create` fails provider-side.
- BGP prefix has invalid CIDR or family.
- registered routable prefix intersects incompatible registered inventory.
- requested routable address is outside registered inventory.
- requested routable address is already owned by a different live deployment.
- requested parent BGP prefix contains live address allocations.
- whitehole cannot find any registered prefix that can supply a source address.
- whitehole source address is outside registered inventory.
- whitehole cannot allocate a unique source port on the selected address.
- whitehole attempts to reuse an `IPAddress:sourcePort` pair owned by a different
  live deployment, even if transport differs.
- switchboard whitehole state is missing the source port or keys only by address.
- container receives a whitehole source port but opens the socket without binding
  that source port.
- container cannot bind its assigned whitehole source port.
- deployment upgrade attempts to transfer ownership across applications.
- failed deployment upgrade releases ownership from the still-live deployment.
- deletion of a registered prefix with dependent DNS bindings or live address
  allocations.

### P. Cleanup And Deletion

- Delete stale tests and helper paths for removed address kinds.
- Delete compatibility shims for the old address-first routable model.
- Remove any helper that only hides a boolean or moves complexity around.
- Keep every new helper justified by real duplication or boundary clarity.
- Keep test code under `tests/`; do not intermingle test-only logic with
  production paths.

## Verification Checklist

Run the smallest checks after each phase, then broaden before completion:

- `git diff --check`
- `cmake --build .run/build-prodigy-depos --target <focused-targets> -j$(nproc)`
- Focused unit tests for:
  - registered-prefix serialization and parsing;
  - prefix registration/update/removal;
  - routable address/IP-port ownership reservation, release, and upgrade
    transfer;
  - DNS name ownership reservation and attached-address reservation;
  - prefix intersection: exact match, disjoint adjacent ranges, parent/child
    overlap, IPv4-vs-IPv6 non-overlap, `/0`, `/32`, and `/128`;
  - BGP prefix inventory overlap rejection;
  - concrete address containment in registered prefixes;
  - duplicate concrete address consumption rejection;
  - whitehole IP:port allocation from registered prefixes;
  - whitehole same-IP/different-port sharing;
  - duplicate whitehole IP:port rejection;
  - switchboard whitehole source state includes both IP address and source port;
  - container whitehole socket creation binds the assigned source port;
  - provider elastic intent mapping;
  - dev IaaS fake address behavior;
  - DNS provider request/response parsing;
  - DNS credential validation;
  - deterministic lease reuse for deployment-plan retries;
  - single-writer lease allocation under master failover/restart;
  - durable staged operation recovery at each address/DNS/publish boundary;
  - DNS record cleanup when a DNS-backed wormhole is removed or destroyed;
  - rejection of provider-side DNS records not owned/imported by Prodigy;
  - canonical DNS record identity comparison;
  - deployment-plan wormhole DNS parser validation and serialization roundtrip;
  - declarative DNS address-claim -> DNS-apply -> state-publish ordering;
  - declarative DNS retry/upgrade idempotency;
  - declarative DNS failure cleanup after provider errors;
  - DNS binding validation and persistence;
  - wormhole resolution through DNS bindings;
  - switchboard state sync after prefix/address/IP-port/DNS changes.
- Existing deployment and switchboard tests touched by the model change.
- Provider-specific unit tests for AWS, GCP, Azure, Cloudflare, and Vultr
  unsupported-or-supported DNS behavior.
- Manual/provider integration tests only when credentials and safe provider
  scopes are explicitly available. Do not fake provider success.

## Goal Ledger Requirements

Because this is `/goal` work, maintain `.experiments/<goal-slug>.md` exactly as
the workspace instructions require. Every experiment must include hypothesis,
commands, parameters, environment, observed result, artifacts, decision, next
step, and root-cause/autopsy notes for failures or negative results.

Use the ledger to separate:

- model redesign work;
- routable address ownership and BGP address allocation work;
- whitehole IP:port allocation and source-port binding work;
- each provider implementation;
- DNS credential work;
- declarative deployment-plan DNS work;
- DNS binding/wormhole integration;
- provider live tests, if any;
- final cleanup and proof.

## Completion Criteria

The goal is complete only when:

1. The old address-first routable model is replaced by `elastic` and `BGP`
   prefix registration plus concrete `IPAddress` consumption.
2. Registered routable inventory is stored as canonical `IPPrefix`.
3. Wormholes consume individual `IPAddress` values contained in registered
   inventory; they do not request arbitrary non-host prefixes.
4. Whiteholes consume `IPAddress:sourcePort` pairs contained in registered
   inventory; they may share the same address when source ports differ.
5. Consumed resources are owned while live, including raw wormhole addresses,
   whitehole IP:port pairs, and DNS names with attached addresses.
6. Identical consumed wormhole addresses, identical whitehole IP:port pairs, and
   identical DNS names cannot be distributed to different live deployments.
7. BGP parent prefixes can safely allocate owned individual addresses such as
   IPv4 `/32` or IPv6 `/128` host addresses without duplication.
8. Switchboard whitehole state includes the full source identity, IP address plus
   source port, not just the IP address.
9. Containers that receive a whitehole IP:port pair bind that assigned source
   port when creating the socket.
10. Deployment upgrades transfer raw-address, whitehole IP:port, and DNS-backed
   ownership within the same application lineage without releasing the still-live
   deployment on failure.
11. Dev/test clusters still pass through deterministic fake/single-machine
   behavior without weakening production ingress rules.
12. Elastic address acquisition supports `any`, `create`, and `anyOrCreate`
   where the provider can truthfully support them.
13. DNS provider credentials/config are independent of compute provider
   credentials.
14. Cloudflare, Route53, GCP Cloud DNS, Azure DNS, and Vultr DNS
   supported-or-explicitly-unsupported behavior is implemented and tested.
15. DNS bindings persist, reconcile, fail clearly, and can feed wormhole address
   resolution.
16. Deployment-plan JSON can declaratively attach DNS to a wormhole with no
   separate operator preflight step: Prodigy claims the address, applies the DNS
   record to that address if a DNS provider/config is declared, and publishes
   runtime state only after success.
17. Declarative DNS retries and same-lineage upgrades update the owned DNS
   binding idempotently instead of duplicating resources or stealing names.
18. DNS provider failure after address claim releases newly staged address/DNS
   ownership without disturbing the still-live deployment during upgrade.
19. Lease allocation is durable and idempotent across retries, restarts, and
   master failover; the same deployment lineage does not churn addresses,
   whitehole ports, or DNS ownership.
20. Removing DNS from a plan, removing a wormhole, or destroying a deployment
   reconciles provider DNS and releases leases only after traffic no longer
   depends on them.
21. Existing provider-side DNS records are not overwritten unless Prodigy owns
   them or an explicit operator adopt/replace path is used.
22. Production DNS bindings cannot silently target non-fleet ingress.
23. The final diff passes a minimal-surface audit: no unused compatibility paths,
   no avoidable abstraction, no duplicated provider scaffolding, and no stale
   address-model code remains in touched scope.
24. Focused unit tests and relevant existing deployment/switchboard tests pass.
25. The final response reports exact commands run, results, LOC +/-, public
   surface added, cleanup performed,
   and any remaining cleanup candidates.
