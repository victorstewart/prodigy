#pragma once

#include <switchboard/kernel/structs.h>
#include <switchboard/kernel/whitehole.maps.h>

__attribute__((__always_inline__))
static inline void reverse_flow_key(const struct flow_key *forward, struct flow_key *reverse)
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

__attribute__((__always_inline__))
static inline bool whitehole_binding_lookup(__u8 proto, bool is_ipv6, const void *address, __be16 port, struct switchboard_whitehole_binding *binding)
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

   struct switchboard_whitehole_binding *found = bpf_map_lookup_elem(&whitehole_bindings, &key);
   if (found == NULL)
   {
      return false;
   }

   bpf_memcpy(binding, found, sizeof(*binding));
   return true;
}

__attribute__((__always_inline__))
static inline bool whitehole_binding_matches(const struct switchboard_whitehole_binding *lhs, const struct switchboard_whitehole_binding *rhs)
{
   if (lhs == NULL || rhs == NULL)
   {
      return false;
   }

   return lhs->nonce == rhs->nonce
      && lhs->container.hasID == rhs->container.hasID
      && bpf_memcmp(lhs->container.value, rhs->container.value, sizeof(lhs->container.value)) == 0;
}
