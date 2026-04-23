Vultr IaaS

Overview
- Prodigy now uses the shared runtime boot path: Mothership uploads first-boot state and seeds the node with `--boot-json-path`, then the node reloads from local TidesDB state.
- Vultr behavior is runtime-selected rather than coming from a separate provider-specific entrypoint.

Requirements
- Runtime environment state:
  - provider credential material is part of Prodigy runtime state, not a process env var contract
  - provider scope carries the metro/region selection when needed

Neuron (on server)
- BGP:
  - Fetches MD5 and ASN via `GET https://api.vultr.com/v2/account/bgp` using the configured runtime credential material.
  - Peering neighbors (bare metal):
    - IPv4: `169.254.1.1`
    - IPv6: `2001:19f0:ffff::1`
    - Multihop (TTL): `2` for both families
  - Wires peers into BGPHub with TCP-MD5 enabled; sets per‑peer hop limit at socket level (IPv4 `IP_TTL`, IPv6 `IPV6_UNICAST_HOPS`).
  - Provider‑driven BGP communities:
    - iBGP (stay within Vultr network): `20473:6000`
    - eBGP: none by default (announces globally). See “AS20473 BGP Communities Customer Guide” for advanced actions (blackhole, IXP controls, prepends).
  - Announces prefixes by calling provider‑driven community path.

Brain (control plane)
- Auto-provisioning supports both `vm` and `bareMetal`.
- Created Vultr machines use an explicit managed private VPC per region for east-west traffic.
  - Description format: `prodigy-managed-vpc-<region>`
  - Subnet sizing: explicit `/20` headroom per region for mixed brain/worker replacement and future VM expansion
  - Mixed VM + Bare Metal private deployments must attach both sides to that same managed VPC.
- `spinMachines` creates the requested Vultr resource kind with region, plan (from `MachineConfig.slug`), hostname, tags, and then waits for SSH + private peer addressing before returning a ready machine snapshot.
- `getMachines`/`getBrains`: populate uuid, creation time, private4, gateway, brain tag, and rack UUID from Vultr’s machine details.
- Ops:
  - Hard reboot: POST `/v2/<resource>/{id}/reboot`
  - Destroy: DELETE `/v2/<resource>/{id}`
  - Hardware failure: POST `/v2/support/tickets`

Notes
- Neighbors are static for bare metal as documented; MD5 is fetched from the account API. Keep an eye on Vultr docs for any changes.
- Local ASN: currently hardcoded in BGP OPEN (no 4‑octet support enabled yet).
- Communities reference:
  - AS20473 guide: https://github.com/vultr/vultr-docs/tree/main/faq/as20473-bgp-customer-guide#readme
  - Docs page: https://docs.vultr.com/products/network/bgp/asn-information/as20473

Validation Checklist (Phase 6)
- Ensure Vultr credential material is present in replicated runtime state when the Vultr IaaS path is used.
- Brain (master):
  - `getMachines` returns machines where `private4` and `gatewayPrivate4` are non-zero for all entries (detail endpoint fallback used automatically when listing lacks fields).
  - `rackUUID` is non-zero and stable across runs (from Vultr fields).
  - `spinMachines` successfully creates bare-metal with `plan=MachineConfig.slug` in `region=metro` and tags applied.
  - `hardRebootMachine` reboots the expected server; `destroyMachine` removes it; `reportHardwareFailure` opens a ticket.
- Neuron:
  - Fetches MD5 + ASN via `/v2/account/bgp`; establishes sessions to `169.254.1.1` (v4) and `2001:19f0:ffff::1` (v6) with TTL=2.
  - Announces local prefixes using provider iBGP community `20473:6000`.
  - MD5 rotation hook available: re‑fetch `/v2/account/bgp` and update keys on live peers.
  - On account/BGP failure, Neuron reports a hardwareFailure to Brain for drain→reboot→escalation.
- Security:
  - MD5 keys never logged; stored in-memory and zeroized when applying setsockopt.
  - Ensure CI does not output secrets (environment variables masked).
