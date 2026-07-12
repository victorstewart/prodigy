#pragma once

#include <switchboard/kernel/structs.h>

__attribute__((__always_inline__)) static inline void reverse_flow_key(const struct flow_key *forward, struct flow_key *reverse)
{
  if (forward == NULL || reverse == NULL)
  {
    return;
  }

  bpf_memset(reverse, 0, sizeof(*reverse));
  bpf_memcpy(reverse->srcv6, forward->dstv6, sizeof(reverse->srcv6));
  bpf_memcpy(reverse->dstv6, forward->srcv6, sizeof(reverse->dstv6));
  reverse->port16[0] = forward->port16[1];
  reverse->port16[1] = forward->port16[0];
  reverse->proto = forward->proto;
}
