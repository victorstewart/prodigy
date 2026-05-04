#include <linux/types.h>
#include <macros/datacenter.h>

#pragma once

#define QUIC_CID_LEN 16

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
    .value = CONTAINER_NETWORK_SUBNET6
};

struct local_container_subnet6 {
	__u8 dpfx; 	  // 1 byte for datacenter
	__u8 mpfx[3];	  // 3 bytes for the machine
};

struct container_network_policy {
   __u8 requiresPublic4;
   __u8 requiresPublic6;
   __u16 reserved;
   __u32 interContainerMTU;
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
