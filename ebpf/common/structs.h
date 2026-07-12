#include <linux/types.h>
#include <macros/datacenter.h>

#pragma once

#ifndef QUIC_CID_LEN
#define QUIC_CID_LEN 16
#endif

struct mac {
  __u8 mac[6];
};

struct ipaddr {
  union {
    __u8 v4[4];
    __u8 v6[16];
  };
};

struct container_network_subnet6_prefix {
  __u8 value[11];
};

static struct container_network_subnet6_prefix container_network_subnet6 = {
    .value = CONTAINER_NETWORK_SUBNET6};

struct local_container_subnet6 {
  __u8 dpfx; // 1 byte for datacenter
  __u8 mpfx[3]; // 3 bytes for the machine
};

struct container_network_policy {
  __u8 requiresPublic4;
  __u8 requiresPublic6;
  __u8 mode;
  __u8 containerFragment;
  __u32 interContainerMTU;
};

enum {
  CONTAINER_NETWORK_DENY = 0,
  CONTAINER_NETWORK_UNRESTRICTED = 1,
  CONTAINER_NETWORK_DESTINATION_ALLOWLIST = 2,
  CONTAINER_NETWORK_DECLARED_ONLY = 3,
};

#define CONTAINER_EGRESS_ALLOWLIST_MAX_ENTRIES 1

struct container_egress_allow_key {
  __u8 proto;
  __u8 reserved;
  __be16 port;
  __be32 addr;
};

#define CONTAINER_SERVICE_PAIRINGS_MAX_ENTRIES (16 * 1024)
#define CONTAINER_TCP_FLOWS_MAX_ENTRIES (16 * 1024)
#ifndef PRODIGY_DECLARED_NETWORK_MAPS
#define PRODIGY_DECLARED_NETWORK_MAPS 0
#endif
#if PRODIGY_DECLARED_NETWORK_MAPS
#define CONTAINER_SERVICE_PAIRINGS_MAP_ENTRIES CONTAINER_SERVICE_PAIRINGS_MAX_ENTRIES
#define CONTAINER_TCP_FLOWS_MAP_ENTRIES CONTAINER_TCP_FLOWS_MAX_ENTRIES
#else
#define CONTAINER_SERVICE_PAIRINGS_MAP_ENTRIES 1
#define CONTAINER_TCP_FLOWS_MAP_ENTRIES 1
#endif
#define CONTAINER_TCP_FLOW_IDLE_NS (300ULL * 1000ULL * 1000ULL * 1000ULL)
#define CONTAINER_TCP_FLOW_CLOSE_NS (15ULL * 1000ULL * 1000ULL * 1000ULL)

struct container_service_peer {
  __u8 address[16];
  __be16 port;
};

struct container_tcp_flow {
  __u64 expiresAtNs;
};

struct quic_long_header {
  __u8 flags;
  __u32 version;
  // Post draft-22: Dest Conn Id Len (8 bits)
  __u8 conn_id_lens;
  __u8 dst_cid[QUIC_CID_LEN];
} __attribute__((__packed__));

struct quic_short_header {
  __u8 flags;
  __u8 cid[QUIC_CID_LEN];
} __attribute__((__packed__));
