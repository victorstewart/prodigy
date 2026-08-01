#pragma once

#include <switchboard/common/constants.h>
#include <switchboard/common/structs.h>
#include <switchboard/kernel/structs.h>

// Dynamic reverse-flow state is pinned once per machine and reused by host
// ingress and every container netkit program. Unconfirmed owners live only in
// the bounded LRU; a valid reverse packet promotes them into the non-evicting
// established map, so an ingress flood cannot evict durable ownership.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct switchboard_wormhole_flow_key);
  __type(value, struct switchboard_wormhole_flow);
  __uint(max_entries, WORMHOLE_PENDING_FLOW_MAX_ENTRIES);
} wh_pending SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct switchboard_wormhole_flow_key);
  __type(value, struct switchboard_wormhole_flow);
  __uint(max_entries, WORMHOLE_FLOW_MAX_ENTRIES);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} wh_flows SEC(".maps");
