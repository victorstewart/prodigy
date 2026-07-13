#pragma once

#include <switchboard/kernel/flow.h>
#include <switchboard/kernel/whitehole.maps.h>

__attribute__((__always_inline__)) static inline bool whitehole_binding_lookup(__u8 proto, bool is_ipv6, const void *address, __be16 port, struct switchboard_whitehole_binding *binding)
{
  if (address == NULL || binding == NULL || port == 0)
  {
    return false;
  }

  struct portal_definition key = {};
  if (is_ipv6)
  {
    bpf_memcpy(key.addr6, address, sizeof(key.addr6));
  }
  else
  {
    bpf_memcpy(&key.addr4, address, sizeof(key.addr4));
  }

  key.port = port;
  key.proto = proto;

  struct switchboard_whitehole_binding *found = bpf_map_lookup_elem(&whiteholes, &key);
  if (found == NULL)
  {
    return false;
  }

  bpf_memcpy(binding, found, sizeof(*binding));
  return true;
}

__attribute__((__always_inline__)) static inline bool whitehole_binding_matches(const struct switchboard_whitehole_binding *lhs, const struct switchboard_whitehole_binding *rhs)
{
  if (lhs == NULL || rhs == NULL)
  {
    return false;
  }

  return lhs->nonce == rhs->nonce && lhs->container.hasID == rhs->container.hasID && bpf_memcmp(lhs->container.value, rhs->container.value, sizeof(lhs->container.value)) == 0;
}

__attribute__((noinline)) static bool whitehole_reply_binding_lookup(const struct flow_key *flow,
                                                                      const struct switchboard_whitehole_binding *current,
                                                                      struct switchboard_whitehole_binding *binding)
{
  if (flow == NULL || current == NULL || binding == NULL)
  {
    return false;
  }
  struct switchboard_whitehole_reply *reply = bpf_map_lookup_elem(&white_replies, flow);
  __u64 now = bpf_ktime_get_ns();
  if (reply == NULL)
  {
    return false;
  }
  if (reply->expiresAtNs <= now || whitehole_binding_matches(current, &reply->binding) == false)
  {
    bpf_map_delete_elem(&white_replies, flow);
    return false;
  }
  reply->expiresAtNs = now + WHITEHOLE_REPLY_IDLE_NS;
  bpf_memcpy(binding, &reply->binding, sizeof(*binding));
  return true;
}
