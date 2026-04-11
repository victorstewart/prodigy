#pragma once

#include <switchboard/common/constants.h>
#include <switchboard/common/structs.h>

struct {
   __uint(type, BPF_MAP_TYPE_LPM_TRIE);
   __type(key, struct switchboard_overlay_prefix4_key);
   __type(value, __u8);
   __uint(max_entries, MAX_OWNED_ROUTABLE_PREFIXES);
   __uint(map_flags, BPF_F_NO_PREALLOC);
} overlay_routable_prefixes4 SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_LPM_TRIE);
   __type(key, struct switchboard_overlay_prefix6_key);
   __type(value, __u8);
   __uint(max_entries, MAX_OWNED_ROUTABLE_PREFIXES);
   __uint(map_flags, BPF_F_NO_PREALLOC);
} overlay_routable_prefixes6 SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_LPM_TRIE);
   __type(key, struct switchboard_overlay_prefix4_key);
   __type(value, struct switchboard_overlay_hosted_ingress_route4);
   __uint(max_entries, MAX_OWNED_ROUTABLE_PREFIXES);
   __uint(map_flags, BPF_F_NO_PREALLOC);
} overlay_hosted_ingress_routes4 SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_LPM_TRIE);
   __type(key, struct switchboard_overlay_prefix6_key);
   __type(value, struct switchboard_overlay_hosted_ingress_route6);
   __uint(max_entries, MAX_OWNED_ROUTABLE_PREFIXES);
   __uint(map_flags, BPF_F_NO_PREALLOC);
} overlay_hosted_ingress_routes6 SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_HASH);
   __type(key, struct switchboard_overlay_machine_route_key);
   __type(value, struct switchboard_overlay_machine_route);
   __uint(max_entries, 1024);
} overlay_machine_routes_full SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_HASH);
   __type(key, struct switchboard_overlay_machine_route_key);
   __type(value, struct switchboard_overlay_machine_route);
   __uint(max_entries, 256);
} overlay_machine_routes_low8 SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __type(key, __u32);
   __type(value, struct switchboard_overlay_config);
   __uint(max_entries, 1);
} overlay_config_map SEC(".maps");
