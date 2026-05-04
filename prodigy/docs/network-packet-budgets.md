Prodigy Network Packet Budgets
==============================

This page records the packet bytes Prodigy adds on the maintained ingress and
egress paths so network engineers can size underlay MTUs and frame budgets
correctly.

The numbers below are pinned by:

- `switchboard/common/structs.h`
- `prodigy/dev/tests/prodigy_switchboard_overlay_route_unit.cpp`

If a switchboard path changes its header growth, update the shared helper
constants, this document, and the focused regression together.

## Fixed Header Sizes

- Ethernet header visible in Linux packet memory: `14` bytes
- IPv4 header added by Prodigy overlay: `20` bytes
- IPv6 header added by Prodigy overlay: `40` bytes
- These values do not include VLAN tags, Ethernet FCS, or provider-side
  encapsulation outside Prodigy.

## External Ingress To A Container

Same-machine delivery:

- Public ingress that lands on the same machine as the destination container is
  rewritten in place.
- Prodigy adds `0` L3 bytes on this path.

Cross-machine delivery:

- If public ingress lands on a different machine, the balancer prepends one
  outer IPv6 header before sending the packet across the datacenter underlay.
- Prodigy adds `40` L3 bytes on this path.
- Underlay L3 requirement: `external_packet_l3_bytes + 40`

## Private Container To Container Transit

Same-machine delivery:

- Direct redirect into the destination container ingress.
- Prodigy adds `0` L3 bytes.

Cross-machine delivery:

- IPv6 overlay route: add one outer IPv6 header, so Prodigy adds `40` L3 bytes.
- IPv4 overlay route: add one outer IPv4 header, so Prodigy adds `20` L3 bytes.
- Underlay L3 requirement:
  - IPv6 overlay: `inner_container_l3_bytes + 40`
  - IPv4 overlay: `inner_container_l3_bytes + 20`

## Container To Internet Egress

- Public egress rewrites the source address and source port in place before the
  packet leaves the machine.
- Prodigy adds `0` L3 bytes on the public internet egress path.
- This does not mean jumbo public internet packets are safe. Public transports
  still need an internet-safe PMTU or packet-size policy above Prodigy.

Current caveat:

- The `interContainerMTU` gate runs before route classification in the
  container egress program.
- That means public internet egress still has to fit the configured L3 limit
  even though the public path itself adds `0` bytes.

## Tuning Formulas

- To carry an external packet of size `P` through cross-machine public ingress
  over Prodigy's IPv6 underlay, the underlay L3 MTU must be at least `P + 40`.
- To carry a private container packet of size `C` across machines over the IPv6
  overlay, the underlay L3 MTU must be at least `C + 40`.
- To carry the same private packet over the IPv4 overlay, the underlay L3 MTU
  must be at least `C + 20`.
- If you budget at full Ethernet-frame size instead of L3 MTU, add another
  `14` bytes for the Linux-visible Ethernet header, then add VLAN and FCS bytes
  separately if your fabric uses them.

Worked examples:

- `interContainerMTU = 9000` with IPv6 overlay requires at least `9040` bytes
  of underlay L3 MTU, or `9054` Ethernet-frame bytes before VLAN/FCS.
- A `1500`-byte internet packet sent across cross-machine public ingress
  requires at least `1540` bytes of underlay L3 MTU.

## Source Paths

- Public ingress local-vs-remote split:
  - `switchboard/kernel/balancer.ebpf.c`
  - `switchboard/kernel/encap.h`
- Cross-machine private overlay encapsulation:
  - `switchboard/kernel/egress.routing.h`
- Container public egress rewrite:
  - `switchboard/kernel/container.egress.router.ebpf.c`
  - `switchboard/kernel/egress.routing.h`
