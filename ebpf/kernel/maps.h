#pragma once

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct local_container_subnet6);
  __uint(max_entries, 1);
} lc_subnet SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct mac);
  __uint(max_entries, 1);
} mac_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct mac);
  __uint(max_entries, 1);
} gw_mac_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct container_network_policy);
  __uint(max_entries, 1);
} ct_net_policy SEC(".maps");
