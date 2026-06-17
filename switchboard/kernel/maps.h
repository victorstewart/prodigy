#pragma once

#include <switchboard/common/constants.h>
#include <switchboard/common/structs.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct portal_definition);
  __type(value, struct portal_meta);
  __uint(max_entries, MAX_PORTALS);
} ext_portals SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct switchboard_owned_routable_prefix4_key);
  __type(value, __u8);
  __uint(max_entries, MAX_OWNED_ROUTABLE_PREFIXES);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} owned_pfx4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct switchboard_owned_routable_prefix6_key);
  __type(value, __u8);
  __uint(max_entries, MAX_OWNED_ROUTABLE_PREFIXES);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} owned_pfx6 SEC(".maps");

struct portal_ring {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, RING_SIZE);
  __type(key, __u32);
  __type(value, struct container_id);
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, MAX_PORTALS);
  __array(values, struct portal_ring);
} cid_rings SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct switchboard_wormhole_target_key);
  __type(value, __u16);
  __uint(max_entries, MAX_PORTALS * 256);
} wh_targets SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct switchboard_wormhole_egress_key);
  __type(value, struct switchboard_wormhole_egress_binding);
  __uint(max_entries, MAX_PORTALS * 256);
} wh_egress SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct switchboard_wormhole_egress4_key);
  __type(value, struct switchboard_wormhole_egress_binding);
  __uint(max_entries, MAX_PORTALS * 256);
} wh_egress4 SEC(".maps");

// src address to container address suffix
struct {
  __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
  __type(key, struct flow_key);
  __type(value, struct container_id);
  __uint(max_entries, LRU_SIZE);
} lru_mapping SEC(".maps");
