# Network packet budgets

Prodigy's packet path is designed to keep same-machine routing at zero additional L3 bytes and bound common cross-machine paths to small, explicit overheads.

| Path | Same machine | Cross machine |
|---|---:|---:|
| Public ingress to container | +0 L3 bytes | +40 L3 bytes |
| Private container-to-container over IPv6 | +0 L3 bytes | +40 L3 bytes |
| Private container-to-container over IPv4 | +0 L3 bytes | +20 L3 bytes |
| Container egress to internet | +0 L3 bytes | Provider path dependent |

These budgets exclude VLAN tags, Ethernet FCS, and provider-specific encapsulation. If the provider path adds encapsulation, account for that below the Prodigy packet budget.

The packet-budget constants are pinned by:

- `switchboard/common/structs.h`
- `prodigy/dev/tests/prodigy_switchboard_overlay_route_unit.cpp`

If a switchboard path changes header growth, update the shared helper constants, this document, and the focused regression together.

## TCP Fast Open

Hosts that run Prodigy must have TCP Fast Open enabled:

```bash
sudo sysctl -w net.ipv4.tcp_fastopen=3
```

Persist it with:

```text
net.ipv4.tcp_fastopen = 3
```

Kernel support is necessary but not sufficient for every path; the runtime and listener path must also use TFO-capable socket behavior where required.

## Interpretation

Same-machine paths are expected to avoid extra L3 overhead because traffic does not need a cross-machine tunnel. Cross-machine paths account for the Prodigy overlay/routing overhead visible above the provider network path.

Provider networks can add their own encapsulation or MTU constraints. Those provider-specific costs should be measured separately so Prodigy packet-budget claims remain attributable.

## Tuning formulas

- Cross-machine public ingress over Prodigy's IPv6 underlay requires `external_packet_l3_bytes + 40`.
- Private container traffic over the IPv6 overlay requires `inner_container_l3_bytes + 40`.
- Private container traffic over the IPv4 overlay requires `inner_container_l3_bytes + 20`.
- If sizing at Ethernet-frame level instead of L3 MTU, add `14` bytes for the Linux-visible Ethernet header, then add VLAN and FCS bytes separately.

Worked examples:

- `interContainerMTU = 9000` with IPv6 overlay requires at least `9040` bytes of underlay L3 MTU, or `9054` Ethernet-frame bytes before VLAN/FCS.
- A `1500`-byte internet packet sent across cross-machine public ingress requires at least `1540` bytes of underlay L3 MTU.

Current caveat: the `interContainerMTU` gate runs before route classification in the container egress program. Public internet egress still has to fit the configured L3 limit even though the public path itself adds `0` bytes.

## Source paths

- Public ingress local-vs-remote split:
  - `switchboard/kernel/balancer.ebpf.c`
  - `switchboard/kernel/encap.h`
- Cross-machine private overlay encapsulation:
  - `switchboard/kernel/egress.routing.h`
- Container public egress rewrite:
  - `switchboard/kernel/container.egress.router.ebpf.c`
  - `switchboard/kernel/egress.routing.h`
