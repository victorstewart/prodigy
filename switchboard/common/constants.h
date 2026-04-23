#include <macros/quic.h>

#pragma once

// consistent hashing ring size
#define RING_SIZE 65537 // when we made this 65536 there was an infinite loop in while (ring[cur] > 0) after 32768
#define MAX_PORTALS 1024
#define MAX_CONTAINERS_PER_PORTAL (1 << 14) // aka 16,384 application servers, this should be plenty fine for a long time

// the LRU is only for TCP... so it can be VERY small
#define LRU_SIZE 5000

// portal_meta flags
// use quic's connection id for the hash calculation
#define F_QUIC_PORTAL (1 << 0)

#define MAX_OWNED_ROUTABLE_PREFIXES 256
#define MAX_WHITEHOLE_BINDINGS 8192
#define WHITEHOLE_REPLY_LRU_SIZE 16384

// packet_description flags:
// tcp packet had syn flag set (tcp initial packet)
#define F_SYN_SET (1 << 0)

#define INIT_JHASH_SEED 0x4a5b6c7d
#define INIT_JHASH_SEED_V6 0xe8f9a0b1
