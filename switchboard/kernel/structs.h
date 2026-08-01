#pragma once

// flow metadata
struct flow_key {
  union {
    __be32 src;
    __be32 srcv6[4];
  };
  union {
    __be32 dst;
    __be32 dstv6[4];
  };
  union {
    __u32 ports;
    __u16 port16[2];
  };
  __u8 proto;
};

struct switchboard_wormhole_flow_key {
  struct flow_key flow;
  __u64 owner_generation;
};

static inline struct switchboard_wormhole_flow_key switchboardWormholeFlowMapKey(const struct flow_key *flow,
                                                                                  __u64 owner_generation)
{
  struct switchboard_wormhole_flow_key key = {};
  if (flow != 0)
  {
    key.flow = *flow;
  }
  key.owner_generation = owner_generation;
  return key;
}

// client's packet metadata
struct packet_description {
  struct flow_key flow;
  __u8 flags;
};
