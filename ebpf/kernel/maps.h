#pragma once

struct {
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __type(key, __u32);
   __type(value, struct local_container_subnet6);
   __uint(max_entries, 1);
} local_container_subnet_map SEC(".maps");

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
} gateway_mac_map SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __type(key, __u32);
   __type(value, struct container_network_policy);
   __uint(max_entries, 1);
} container_network_policy_map SEC(".maps");
