#pragma once

#include <switchboard/kernel/jhash.h>

#ifndef QUIC_V1_CID_TAG_SEED0
#define QUIC_V1_CID_TAG_SEED0 0x6f9d5a1cu
#endif

#ifndef QUIC_V1_CID_TAG_SEED1
#define QUIC_V1_CID_TAG_SEED1 0x91b34e27u
#endif

#ifndef QUIC_V1_CID_TAG_CONTEXT0
#define QUIC_V1_CID_TAG_CONTEXT0 0x51
#endif

#ifndef QUIC_V1_CID_TAG_CONTEXT1
#define QUIC_V1_CID_TAG_CONTEXT1 0x43
#endif

#ifndef QUIC_V1_CID_TAG_CONTEXT2
#define QUIC_V1_CID_TAG_CONTEXT2 0x31
#endif

#define QUIC_CID_CONTAINER_ID_OFFSET 1
#define QUIC_CID_NONCE_OFFSET 6
#define QUIC_CID_TAG_OFFSET 10
#define QUIC_CID_TAG_LEN 6
#define QUIC_CID_DESTINATION_KEY_LEN 17
#define QUIC_CID_DESTINATION_FAMILY_IPV4 0x04
#define QUIC_CID_DESTINATION_FAMILY_IPV6 0x06

__attribute__((__always_inline__))
static inline void quicCidBuildIPv4DestinationKey(__u8 destination_key[QUIC_CID_DESTINATION_KEY_LEN], __be32 destination_address_network_order)
{
   destination_key[0] = QUIC_CID_DESTINATION_FAMILY_IPV4;
   __builtin_memset(destination_key + 1, 0, 16);
   __builtin_memcpy(destination_key + 13, &destination_address_network_order, sizeof(destination_address_network_order));
}

__attribute__((__always_inline__))
static inline void quicCidBuildIPv6DestinationKey(__u8 destination_key[QUIC_CID_DESTINATION_KEY_LEN], const __be32 destination_address_network_order[4])
{
   destination_key[0] = QUIC_CID_DESTINATION_FAMILY_IPV6;
   __builtin_memcpy(destination_key + 1, destination_address_network_order, 16);
}

__attribute__((__always_inline__))
static inline void quicCidDeriveTagFromDestinationKey(__u8 tag[QUIC_CID_TAG_LEN], __u8 cidv, const __u8 container_id[5], __u32 nonce, const __u8 destination_key[QUIC_CID_DESTINATION_KEY_LEN], __u16 destination_port_network_order, __u8 proto)
{
   __u8 auth_block[33];
   const __u8 *nonce_bytes = (const __u8 *)&nonce;
   const __u8 *port_bytes = (const __u8 *)&destination_port_network_order;

   auth_block[0] = cidv;
   auth_block[1] = container_id[0];
   auth_block[2] = container_id[1];
   auth_block[3] = container_id[2];
   auth_block[4] = container_id[3];
   auth_block[5] = container_id[4];
   auth_block[6] = nonce_bytes[0];
   auth_block[7] = nonce_bytes[1];
   auth_block[8] = nonce_bytes[2];
   auth_block[9] = nonce_bytes[3];
   __builtin_memcpy(auth_block + 10, destination_key, QUIC_CID_DESTINATION_KEY_LEN);
   auth_block[27] = port_bytes[0];
   auth_block[28] = port_bytes[1];
   auth_block[29] = proto;
   auth_block[30] = QUIC_V1_CID_TAG_CONTEXT0;
   auth_block[31] = QUIC_V1_CID_TAG_CONTEXT1;
   auth_block[32] = QUIC_V1_CID_TAG_CONTEXT2;

   __u32 hash0 = jhash(auth_block, sizeof(auth_block), QUIC_V1_CID_TAG_SEED0);
   __u32 hash1 = jhash(auth_block, sizeof(auth_block), QUIC_V1_CID_TAG_SEED1);

   tag[0] = (__u8)(hash0 >> 24);
   tag[1] = (__u8)(hash0 >> 16);
   tag[2] = (__u8)(hash0 >> 8);
   tag[3] = (__u8)(hash0);
   tag[4] = (__u8)(hash1 >> 24);
   tag[5] = (__u8)(hash1 >> 16);
}

__attribute__((__always_inline__))
static inline void quicCidDeriveTagForIPv4(__u8 tag[QUIC_CID_TAG_LEN], __u8 cidv, const __u8 container_id[5], __u32 nonce, __be32 destination_address_network_order, __u16 destination_port_network_order, __u8 proto)
{
   __u8 destination_key[QUIC_CID_DESTINATION_KEY_LEN];
   quicCidBuildIPv4DestinationKey(destination_key, destination_address_network_order);
   quicCidDeriveTagFromDestinationKey(tag, cidv, container_id, nonce, destination_key, destination_port_network_order, proto);
}

__attribute__((__always_inline__))
static inline void quicCidDeriveTagForIPv6(__u8 tag[QUIC_CID_TAG_LEN], __u8 cidv, const __u8 container_id[5], __u32 nonce, const __be32 destination_address_network_order[4], __u16 destination_port_network_order, __u8 proto)
{
   __u8 destination_key[QUIC_CID_DESTINATION_KEY_LEN];
   quicCidBuildIPv6DestinationKey(destination_key, destination_address_network_order);
   quicCidDeriveTagFromDestinationKey(tag, cidv, container_id, nonce, destination_key, destination_port_network_order, proto);
}

__attribute__((__always_inline__))
static inline bool quicCidTagMatches(const __u8 lhs[QUIC_CID_TAG_LEN], const __u8 rhs[QUIC_CID_TAG_LEN])
{
   return lhs[0] == rhs[0] &&
          lhs[1] == rhs[1] &&
          lhs[2] == rhs[2] &&
          lhs[3] == rhs[3] &&
          lhs[4] == rhs[4] &&
          lhs[5] == rhs[5];
}

__attribute__((__always_inline__))
static inline __u8 quicCidEncryptedKeyIndex(const __u8 encrypted_cid[16])
{
   return (encrypted_cid[0] >> 7) & 0x01;
}

__attribute__((__always_inline__))
static inline __u32 quicCidPortalDecryptMapIndex(__u32 portal_slot, __u8 key_index)
{
   return (portal_slot * 2U) + ((__u32)(key_index & 0x01));
}
