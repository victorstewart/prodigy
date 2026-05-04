#pragma once

#include <switchboard/common/constants.h>
#include <switchboard/common/structs.h>

// we'll take fixed size container subnets for each machine
// so all we need to do is delete the unnecessary bits and
// then hash the prefix
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct portal_definition);
  __type(value, struct portal_meta);
  __uint(max_entries, MAX_PORTALS);
  __uint(map_flags, NO_FLAGS);
} external_portals SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct switchboard_wormhole_target_key);
  __type(value, __u16);
  __uint(max_entries, MAX_PORTALS * 256);
  __uint(map_flags, NO_FLAGS);
} wormhole_target_ports SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct switchboard_wormhole_egress_key);
  __type(value, struct switchboard_wormhole_egress_binding);
  __uint(max_entries, MAX_PORTALS * 256);
  __uint(map_flags, NO_FLAGS);
} wormhole_egress_bindings SEC(".maps");
