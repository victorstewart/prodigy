#pragma once

// Prodigy currently hardcodes these QUIC v1 packet and CID constants.
#define QUIC_V1_LONG_HEADER 0x80
#define QUIC_V1_SHORT_HEADER 0x00

// Long header packet types use the aligned packet-type bits.
#define QUIC_V1_CLIENT_INITIAL 0x00
#define QUIC_V1_0RTT 0x10
#define QUIC_V1_HANDSHAKE 0x20
#define QUIC_V1_RETRY 0x30
#define QUIC_V1_PACKET_TYPE_MASK 0x30

// Require connection IDs to be at least this long before attempting Prodigy's CID parsing.
#define QUIC_V1_MIN_CID_LEN 8
#define QUIC_CID_VERSION 0x1
#define QUIC_V1_CID_TAG_SEED0 0x6f9d5a1cu
#define QUIC_V1_CID_TAG_SEED1 0x91b34e27u
#define QUIC_V1_CID_TAG_CONTEXT0 0x51
#define QUIC_V1_CID_TAG_CONTEXT1 0x43
#define QUIC_V1_CID_TAG_CONTEXT2 0x31
