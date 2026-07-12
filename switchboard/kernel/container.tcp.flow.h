#pragma once

#include <switchboard/kernel/flow.h>

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct flow_key);
  __type(value, struct container_tcp_flow);
  __uint(max_entries, CONTAINER_TCP_FLOWS_MAP_ENTRIES);
} ct_tcp_flows SEC(".maps");

__attribute__((__always_inline__)) static inline bool containerTCPFlowCurrent(const struct flow_key *flow, bool closing, bool reset)
{
  struct container_tcp_flow *state = bpf_map_lookup_elem(&ct_tcp_flows, flow);
  __u64 now = bpf_ktime_get_ns();
  if (state == NULL)
  {
    return false;
  }
  if (state->expiresAtNs <= now)
  {
    bpf_map_delete_elem(&ct_tcp_flows, flow);
    return false;
  }
  if (reset)
  {
    bpf_map_delete_elem(&ct_tcp_flows, flow);
  }
  else
  {
    state->expiresAtNs = now + (closing ? CONTAINER_TCP_FLOW_CLOSE_NS : CONTAINER_TCP_FLOW_IDLE_NS);
  }
  return true;
}

__attribute__((__always_inline__)) static inline bool containerAuthorizeTCPFlow(const struct flow_key *flow)
{
  struct container_tcp_flow state = {
      .expiresAtNs = bpf_ktime_get_ns() + CONTAINER_TCP_FLOW_IDLE_NS,
  };
  return bpf_map_update_elem(&ct_tcp_flows, flow, &state, BPF_ANY) == 0;
}
