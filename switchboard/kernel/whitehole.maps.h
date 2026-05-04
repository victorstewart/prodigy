#pragma once

#include <switchboard/common/constants.h>
#include <switchboard/common/structs.h>
#include <switchboard/kernel/structs.h>

struct {
   __uint(type, BPF_MAP_TYPE_HASH);
   __type(key, struct portal_definition);
   __type(value, struct switchboard_whitehole_binding);
   __uint(max_entries, MAX_WHITEHOLE_BINDINGS);
} whitehole_bindings SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_LRU_HASH);
   __type(key, struct flow_key);
   __type(value, struct switchboard_whitehole_binding);
   __uint(max_entries, WHITEHOLE_REPLY_LRU_SIZE);
} whitehole_reply_flows SEC(".maps");
