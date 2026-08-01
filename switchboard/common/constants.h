#include <macros/quic.h>

#pragma once

// consistent hashing ring size
// clang-format off
#define RING_SIZE 65537 // when we made this 65536 there was an infinite loop in while (ring[cur] > 0) after 32768
// clang-format on
#define MAX_PORTALS 1024
#define MAX_CONTAINERS_PER_PORTAL (1 << 14) // aka 16,384 application servers, this should be plenty fine for a long time

// the LRU is only for TCP... so it can be VERY small
#define LRU_SIZE 5000

// portal_meta flags
// use quic's connection id for the hash calculation
#define F_QUIC_PORTAL (1 << 0)

#define MAX_OWNED_ROUTABLE_PREFIXES 256
#define MAX_WHITEHOLE_BINDINGS 8192
// clang-format off
#define WHITEHOLE_REPLY_LRU_SIZE 16384
#define WHITEHOLE_REPLY_IDLE_NS (300ULL * 1000ULL * 1000ULL * 1000ULL)
#ifndef WORMHOLE_FLOW_MAX_ENTRIES
#define WORMHOLE_FLOW_MAX_ENTRIES (1U << 20)
#endif
#ifndef WORMHOLE_PENDING_FLOW_MAX_ENTRIES
#define WORMHOLE_PENDING_FLOW_MAX_ENTRIES (1U << 16)
#endif
#define WORMHOLE_FLOW_GC_BATCH_SIZE 16384U
#define WORMHOLE_FLOW_GC_INTERVAL_MS 100U
#define WORMHOLE_FLOW_RECLAIM_GRACE_NS (1000ULL * 1000ULL * 1000ULL)
#define WORMHOLE_FLOW_EMBRYONIC_NS (30ULL * 1000ULL * 1000ULL * 1000ULL)
#define WORMHOLE_FLOW_TCP_ESTABLISHED_NS (5ULL * 24ULL * 60ULL * 60ULL * 1000ULL * 1000ULL * 1000ULL)
#define WORMHOLE_FLOW_UDP_IDLE_NS (300ULL * 1000ULL * 1000ULL * 1000ULL)
#define WORMHOLE_FLOW_CLOSE_NS (15ULL * 1000ULL * 1000ULL * 1000ULL)
#define WORMHOLE_PUBLIC_INGRESS_L3_MTU 1500U
// clang-format on

#define SWITCHBOARD_WORMHOLE_SKB_MARK 0x57584d01U
#define SWITCHBOARD_WORMHOLE_REPLY_VALIDATED_SKB_MARK 0x57584d02U
#define SWITCHBOARD_OVERLAY_LOCAL_XDP_META_MAGIC 0x4f564c31U
#define SWITCHBOARD_WORMHOLE_GRE_FLAGS 0x3000U
#define SWITCHBOARD_WORMHOLE_OVERLAY_VERSION 1U

// packet_description flags:
// tcp packet had syn flag set (tcp initial packet)
#define F_SYN_SET (1 << 0)

#define INIT_JHASH_SEED 0x4a5b6c7d
#define INIT_JHASH_SEED_V6 0xe8f9a0b1
