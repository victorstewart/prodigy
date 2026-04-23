#include <ebpf/kernel/aes.h>

#include <switchboard/common/constants.h>
#include <switchboard/common/quic.cid.h>

#pragma once

struct quic_parse_result {
   struct container_id containerID;
   bool is_initial;
};

struct {
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __type(key, __u32);
   __type(value, struct aes_decrypt_state);
   __uint(max_entries, MAX_PORTALS * 2);
} quic_cid_aes_decrypt_map SEC(".maps");

__attribute__((__always_inline__)) 
static inline bool parse_quic(struct container_id *containerID, const struct portal_meta *portal_meta, void *data, void *data_end, bool is_ipv6, const struct flow_key *flow) 
{
   containerID->hasID = false;
   bool allow_hash_fallback = false;

   if (portal_meta == NULL)
   {
      return false;
   }

   __u64 off = calc_offset(is_ipv6);

   // offset points to the beginning of transport header (udp) of quic's packet
   /*                                      |QUIC PKT TYPE|           */
   if ((data + off + sizeof(struct udphdr) + sizeof(__u8)) > data_end) return false;

   __u8 *quic_data = data + off + sizeof(struct udphdr);
   __u8 *pkt_type = quic_data;
   __u8 *encrypted_cid = NULL;

   if ((*pkt_type & QUIC_V1_LONG_HEADER) == QUIC_V1_LONG_HEADER) 
   {
      // packet with long header
      if ((void *)(quic_data + sizeof(struct quic_long_header)) > data_end) return false;

      struct quic_long_header *lheader = (struct quic_long_header *)quic_data;
      __u8 packet_type = (*pkt_type & QUIC_V1_PACKET_TYPE_MASK);

      // Post draft version 22, this byte is the conn id length of dest conn id
      if (lheader->conn_id_lens < QUIC_V1_MIN_CID_LEN) return false;

      if (packet_type == QUIC_V1_RETRY)
      {
         return false; // client should never send Retry packets to the server
      }

      if (packet_type == QUIC_V1_CLIENT_INITIAL || packet_type == QUIC_V1_0RTT)
      {
         allow_hash_fallback = true;
      }

      encrypted_cid = lheader->dst_cid;
   } 
   else 
   {
      if ((void *)(quic_data + sizeof(struct quic_short_header)) > data_end) return false;

      struct quic_short_header *sheader = (struct quic_short_header *)quic_data;
      
      encrypted_cid = sheader->cid;
   }

   // we need to use a sequential nonce... to garauntee that we don't repeat cids... so we need enough bytes to last us the lifetime of the key...
   // if we have to build infrastructure to rotate keys, then we might as well just set that time frame to stick with a 3 byte nonce
   //
   // say we have 50,000 clients, that's 335 connection IDs per user. but also depends not only on simultaneous connections per connection establishments over key lifetime.
   // 
   // it really depends on how many unique users connection per interval, how many cids each consumes per interval, how many application servers we have, how many bits in the sequenitally increasing nonce...

   // let's take a situation in which this will really matter: with scale. say 1M+ users.
   // say we support 50% of users online at once. so 500,000. then we need at least 25 application servers
   // handling 20,000 each (maybe we'll limit to 10,000 but 20,000 provides fewer cids for this thought experiment).
   //
   // if we have 25 applications servers and a 24 bit nonce, that gives us 419,430,400 cids per key rotation interval.
   //
   // assume 500K daily active users, using 8 each? we'd have 838 cids per user, exhausting only 1% of our cid space.
   // and if we choose a random starting nonce value then loop on overflow... we're probably gold.
   //
   // but every time their ip address changes their cid must change.... and especially if they're bluetooth waking up to push changes to us.. 
   // we could be consuming 100s per day per USER, not active user. then factor in wifi cellular crossovers. so maybe 100 a day is more accurate.
   // but that's stll only 11.9% of our cid space consumed... and it will vary normally by user so... even if we cycle once per day this is probably fine.

   /*
      +-------------------------+
      |        CID Schema       |
      |   +-----------------+   |
      |   |   CID Version   |   |
      |   |    (1 byte)     |   |
      |   +-----------------+   |
      |   |   container_id  |   |
      |   |    (5 bytes)    |   |
      |   +-----------------+   |
      |   |      nonce      |   |
      |   |    (4 bytes)    |   |
      |   +-----------------+   |
      |   |  verify tag     |   |
      |   |    (6 bytes)    |   |
      |   +-----------------+   |
      |        16 bytes         |
      +-------------------------+
   */

   if (encrypted_cid)
   {
      if ((void *)(encrypted_cid + 16) <= data_end)
      {
         __u8 key_index = quicCidEncryptedKeyIndex(encrypted_cid);
         __u32 decrypt_index = quicCidPortalDecryptMapIndex(portal_meta->slot, key_index);
         struct aes_decrypt_state *aes_state = bpf_map_lookup_elem(&quic_cid_aes_decrypt_map, &decrypt_index);
             
         if (aes_state)
         {
            __u8 cid[16];
            aesDecrypt(aes_state, encrypted_cid, cid);

            __u8 cidv = cid[0];

            if (cidv == QUIC_CID_VERSION) 
            {
               __u32 nonce = 0;
               __u8 expected_tag[QUIC_CID_TAG_LEN];
               const __u8 *cid_tag = cid + QUIC_CID_TAG_OFFSET;

               __builtin_memcpy(&nonce, cid + QUIC_CID_NONCE_OFFSET, sizeof(nonce));
               if (is_ipv6)
               {
                  quicCidDeriveTagForIPv6(expected_tag, cidv, cid + QUIC_CID_CONTAINER_ID_OFFSET, nonce, flow->dstv6, flow->port16[1], IPPROTO_UDP);
               }
               else
               {
                  quicCidDeriveTagForIPv4(expected_tag, cidv, cid + QUIC_CID_CONTAINER_ID_OFFSET, nonce, flow->dst, flow->port16[1], IPPROTO_UDP);
               }

               if (quicCidTagMatches(expected_tag, cid_tag))
               {
                  // network byte order on purpose
                  containerID->value[0] = cid[1];
                  containerID->value[1] = cid[2];
                  containerID->value[2] = cid[3];
                  containerID->value[3] = cid[4];
                  containerID->value[4] = cid[5];

                  containerID->hasID = true;
               }
            } 
         }
      }
   }

   return allow_hash_fallback;
}
