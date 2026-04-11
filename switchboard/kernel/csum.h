#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <stdbool.h>

#include <switchboard/common/checksum.h>

#include <bpf/bpf_endian.h>
#ifndef __cplusplus
#include <bpf/bpf_helpers.h>
#endif

#pragma once

__attribute__((__always_inline__)) 
static inline __u16 csum_fold_helper(__u64 csum) 
{
	int i;
	
#pragma unroll
  	for (i = 0; i < 4; i++) 
  	{
    	if (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
  	}

  	return ~csum;
}

__attribute__((__always_inline__)) 
static inline void ipv4_csum_inline(void* iph, __u64* csum) 
{
 	__u16* next_iph_u16 = (__u16*)iph;

#pragma clang loop unroll(full)
  	for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) 
  	{
    	*csum += *next_iph_u16++;
  	}

  	*csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__))
static inline __u16 replace_l4_checksum(__u16 checksum, const void *old_value, const void *new_value, __u32 size)
{
   return replace_l4_checksum_portable(checksum, old_value, new_value, size);
}

__attribute__((__always_inline__))
static inline int replace_l4_checksum_word16_skb(struct __sk_buff *skb, __u32 checksumOffset, __be16 oldValue, __be16 newValue, __u64 extraFlags)
{
   return bpf_l4_csum_replace(skb, checksumOffset, oldValue, newValue, extraFlags | sizeof(__be16));
}

__attribute__((__always_inline__))
static inline int replace_l4_checksum_word32_skb(struct __sk_buff *skb, __u32 checksumOffset, __be32 oldValue, __be32 newValue, __u64 extraFlags)
{
   return bpf_l4_csum_replace(skb, checksumOffset, oldValue, newValue, extraFlags | sizeof(__be32));
}

__attribute__((__always_inline__))
static inline bool replace_l4_checksum_ipv6_address_skb(struct __sk_buff *skb,
   __u32 checksumOffset,
   const void *oldValue,
   const void *newValue)
{
   const __be32 *oldWords = (const __be32 *)oldValue;
   const __be32 *newWords = (const __be32 *)newValue;

#pragma unroll
   for (int index = 0; index < 4; index += 1)
   {
      if (oldWords[index] == newWords[index])
      {
         continue;
      }

      if (replace_l4_checksum_word32_skb(skb,
            checksumOffset,
            oldWords[index],
            newWords[index],
            BPF_F_PSEUDO_HDR | BPF_F_IPV6) != 0)
      {
         return false;
      }
   }

   return true;
}

// Wormhole ingress/egress only handles native external packets on the portal
// path, but QUIC/TLS first-flight packets can legitimately exceed a single
// 1500-byte MTU. Keep the verifier-visible checksum walk bounded, but large
// enough for the observed 2047-byte QUIC transport segment on the live path.
#define SWITCHBOARD_WORMHOLE_CHECKSUM_HELPER_CHUNK_BYTES 512u

__attribute__((__always_inline__))
static inline bool accumulate_packet_checksum_bytes(__u32 *csum, const void *value, __u16 byteCount, const void *data_end)
{
   __u16 boundedByteCount = byteCount;
   const __u8 *bytes = (const __u8 *)value;
   if (boundedByteCount > SWITCHBOARD_MAX_WORMHOLE_CHECKSUM_BYTES
      || (const void *)(bytes + boundedByteCount) > data_end)
   {
      return false;
   }

#pragma unroll
   for (int iteration = 0; iteration < (SWITCHBOARD_MAX_WORMHOLE_CHECKSUM_BYTES / SWITCHBOARD_WORMHOLE_CHECKSUM_HELPER_CHUNK_BYTES); iteration++)
   {
      const __u16 chunkOffset = (__u16)(iteration * SWITCHBOARD_WORMHOLE_CHECKSUM_HELPER_CHUNK_BYTES);
      const __u16 processedBytes = (__u16)(boundedByteCount & ~(__u16)(SWITCHBOARD_WORMHOLE_CHECKSUM_HELPER_CHUNK_BYTES - 1u));

      if (chunkOffset >= processedBytes)
      {
         break;
      }

      const __u8 *chunk = bytes + chunkOffset;
      if ((const void *)(chunk + SWITCHBOARD_WORMHOLE_CHECKSUM_HELPER_CHUNK_BYTES) > data_end)
      {
         return false;
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)chunk, SWITCHBOARD_WORMHOLE_CHECKSUM_HELPER_CHUNK_BYTES, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
   }

   __u16 tailOffset = (__u16)(boundedByteCount & ~(__u16)(SWITCHBOARD_WORMHOLE_CHECKSUM_HELPER_CHUNK_BYTES - 1u));
   __u16 remaining = (__u16)(boundedByteCount - tailOffset);

   if (remaining & 256u)
   {
      const __u8 *chunk = bytes + tailOffset;
      if ((const void *)(chunk + 256) > data_end)
      {
         return false;
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)chunk, 256, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
      tailOffset = (__u16)(tailOffset + 256);
   }

   if (remaining & 128u)
   {
      const __u8 *chunk = bytes + tailOffset;
      if ((const void *)(chunk + 128) > data_end)
      {
         return false;
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)chunk, 128, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
      tailOffset = (__u16)(tailOffset + 128);
   }

   if (remaining & 64u)
   {
      const __u8 *chunk = bytes + tailOffset;
      if ((const void *)(chunk + 64) > data_end)
      {
         return false;
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)chunk, 64, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
      tailOffset = (__u16)(tailOffset + 64);
   }

   if (remaining & 32u)
   {
      const __u8 *chunk = bytes + tailOffset;
      if ((const void *)(chunk + 32) > data_end)
      {
         return false;
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)chunk, 32, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
      tailOffset = (__u16)(tailOffset + 32);
   }

   if (remaining & 16u)
   {
      const __u8 *chunk = bytes + tailOffset;
      if ((const void *)(chunk + 16) > data_end)
      {
         return false;
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)chunk, 16, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
      tailOffset = (__u16)(tailOffset + 16);
   }

   if (remaining & 8u)
   {
      const __u8 *chunk = bytes + tailOffset;
      if ((const void *)(chunk + 8) > data_end)
      {
         return false;
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)chunk, 8, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
      tailOffset = (__u16)(tailOffset + 8);
   }

   if (remaining & 4u)
   {
      const __u8 *chunk = bytes + tailOffset;
      if ((const void *)(chunk + 4) > data_end)
      {
         return false;
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)chunk, 4, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
      tailOffset = (__u16)(tailOffset + 4);
   }

   __u16 tailBytes = (__u16)(boundedByteCount - tailOffset);
   if (tailBytes > 0)
   {
      __u8 finalWord[4] = {};
      const __u8 *chunk = bytes + tailOffset;
      if ((const void *)(chunk + 1) > data_end)
      {
         return false;
      }

      finalWord[0] = chunk[0];
      if (tailBytes > 1)
      {
         if ((const void *)(chunk + 2) > data_end)
         {
            return false;
         }

         finalWord[1] = chunk[1];
      }

      if (tailBytes > 2)
      {
         if ((const void *)(chunk + 3) > data_end)
         {
            return false;
         }

         finalWord[2] = chunk[2];
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)finalWord, 4, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
   }

   return true;
}

__attribute__((__always_inline__))
static inline bool accumulate_fixed_checksum_words(__u32 *csum, const void *value, __u32 byteCount)
{
   if (csum == NULL || value == NULL || (byteCount & 3u) != 0)
   {
      return false;
   }

   __s64 next = bpf_csum_diff(0, 0, (__be32 *)value, byteCount, *csum);
   if (next < 0)
   {
      return false;
   }

   *csum = (__u32)next;
   return true;
}

__attribute__((__always_inline__))
static inline bool accumulate_skb_checksum_bytes(struct __sk_buff *skb, __u32 *csum, __u32 byteOffset, __u16 byteCount)
{
   __u16 boundedByteCount = byteCount;
   __u32 currentOffset = byteOffset;
   __u8 chunk[SWITCHBOARD_WORMHOLE_SKB_CHECKSUM_CHUNK_BYTES] = {};

   if (skb == NULL || csum == NULL || boundedByteCount > SWITCHBOARD_MAX_WORMHOLE_CHECKSUM_BYTES)
   {
      return false;
   }

   for (int iteration = 0; iteration < (SWITCHBOARD_MAX_WORMHOLE_CHECKSUM_BYTES / SWITCHBOARD_WORMHOLE_SKB_CHECKSUM_CHUNK_BYTES); iteration += 1)
   {
      if (boundedByteCount < SWITCHBOARD_WORMHOLE_SKB_CHECKSUM_CHUNK_BYTES)
      {
         break;
      }

      if (bpf_skb_load_bytes(skb, currentOffset, chunk, SWITCHBOARD_WORMHOLE_SKB_CHECKSUM_CHUNK_BYTES) != 0)
      {
         return false;
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)chunk, SWITCHBOARD_WORMHOLE_SKB_CHECKSUM_CHUNK_BYTES, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
      currentOffset += SWITCHBOARD_WORMHOLE_SKB_CHECKSUM_CHUNK_BYTES;
      boundedByteCount = (__u16)(boundedByteCount - SWITCHBOARD_WORMHOLE_SKB_CHECKSUM_CHUNK_BYTES);
   }

   if (boundedByteCount & 64u)
   {
      if (bpf_skb_load_bytes(skb, currentOffset, chunk, 64) != 0)
      {
         return false;
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)chunk, 64, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
      currentOffset += 64u;
      boundedByteCount = (__u16)(boundedByteCount - 64u);
   }

   if (boundedByteCount & 32u)
   {
      if (bpf_skb_load_bytes(skb, currentOffset, chunk, 32) != 0)
      {
         return false;
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)chunk, 32, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
      currentOffset += 32u;
      boundedByteCount = (__u16)(boundedByteCount - 32u);
   }

   if (boundedByteCount & 16u)
   {
      if (bpf_skb_load_bytes(skb, currentOffset, chunk, 16) != 0)
      {
         return false;
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)chunk, 16, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
      currentOffset += 16u;
      boundedByteCount = (__u16)(boundedByteCount - 16u);
   }

   if (boundedByteCount & 8u)
   {
      if (bpf_skb_load_bytes(skb, currentOffset, chunk, 8) != 0)
      {
         return false;
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)chunk, 8, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
      currentOffset += 8u;
      boundedByteCount = (__u16)(boundedByteCount - 8u);
   }

   if (boundedByteCount & 4u)
   {
      if (bpf_skb_load_bytes(skb, currentOffset, chunk, 4) != 0)
      {
         return false;
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)chunk, 4, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
      currentOffset += 4u;
      boundedByteCount = (__u16)(boundedByteCount - 4u);
   }

   if (boundedByteCount > 0u)
   {
      __u8 tailWord[4] = {};
      if (boundedByteCount == 1u)
      {
         if (bpf_skb_load_bytes(skb, currentOffset, tailWord, 1) != 0)
         {
            return false;
         }
      }
      else if (boundedByteCount == 2u)
      {
         if (bpf_skb_load_bytes(skb, currentOffset, tailWord, 2) != 0)
         {
            return false;
         }
      }
      else if (boundedByteCount == 3u)
      {
         if (bpf_skb_load_bytes(skb, currentOffset, tailWord, 3) != 0)
         {
            return false;
         }
      }
      else
      {
         return false;
      }

      __s64 next = bpf_csum_diff(0, 0, (__be32 *)tailWord, 4, *csum);
      if (next < 0)
      {
         return false;
      }

      *csum = (__u32)next;
   }

   return true;
}

__attribute__((__always_inline__))
static inline bool compute_ipv6_transport_checksum_skb(
   __u16 *checksumOut,
   struct __sk_buff *skb,
   __u32 transportOffset,
   __u16 segmentSize,
   __u16 checksumByteOffset,
   const __be32 srcv6[4],
   const __be32 dstv6[4],
   __u8 nextHeader)
{
   __u16 boundedSegmentSize = segmentSize;
   __u16 boundedChecksumByteOffset = checksumByteOffset;
   __u16 prefixBytes = 0;
   __u16 suffixBytes = 0;
   __u16 suffixOffset = 0;

   if (checksumOut == NULL || skb == NULL)
   {
      return false;
   }

   if (boundedSegmentSize > SWITCHBOARD_MAX_WORMHOLE_CHECKSUM_BYTES)
   {
      return false;
   }

   suffixOffset = (__u16)(boundedChecksumByteOffset + 2u);
   if (boundedSegmentSize < suffixOffset)
   {
      return false;
   }

   prefixBytes = boundedChecksumByteOffset;
   suffixBytes = (__u16)(boundedSegmentSize - suffixOffset);

   __u8 lengthBytes[4] = {
      (__u8)((boundedSegmentSize >> 24) & 0xffu),
      (__u8)((boundedSegmentSize >> 16) & 0xffu),
      (__u8)((boundedSegmentSize >> 8) & 0xffu),
      (__u8)(boundedSegmentSize & 0xffu)
   };
   __u8 nextHeaderBytes[4] = {0, 0, 0, nextHeader};

   __u32 csum = 0;
   if (accumulate_fixed_checksum_words(&csum, srcv6, 16) == false
      || accumulate_fixed_checksum_words(&csum, dstv6, 16) == false
      || accumulate_fixed_checksum_words(&csum, lengthBytes, sizeof(lengthBytes)) == false
      || accumulate_fixed_checksum_words(&csum, nextHeaderBytes, sizeof(nextHeaderBytes)) == false)
   {
      return false;
   }

   if (prefixBytes > 0 && accumulate_skb_checksum_bytes(skb, &csum, transportOffset, prefixBytes) == false)
   {
      return false;
   }

   if (suffixBytes > 0
      && accumulate_skb_checksum_bytes(
         skb,
         &csum,
         transportOffset + suffixOffset,
         suffixBytes) == false)
   {
      return false;
   }

   __u16 folded = fold_l4_checksum_sum16(csum);
   *checksumOut = normalize_l4_checksum_word16(bpf_htons((__u16)(~folded & 0xffffu)));
   return true;
}

__attribute__((__always_inline__))
static inline bool compute_ipv6_transport_checksum_in_packet(
   __u16 *checksumOut,
   const void *segment,
   __u16 segmentSize,
   __u16 checksumByteOffset,
   const __be32 srcv6[4],
   const __be32 dstv6[4],
   __u8 nextHeader,
   const void *data_end)
{
   __u16 boundedSegmentSize = segmentSize;
   __u16 boundedChecksumByteOffset = checksumByteOffset;
   __u16 prefixBytes = 0;
   __u16 suffixBytes = 0;
   __u16 suffixOffset = 0;

   if (checksumOut == NULL || segment == NULL)
   {
      return false;
   }

   if (boundedSegmentSize > SWITCHBOARD_MAX_WORMHOLE_CHECKSUM_BYTES
      || (const void *)((const __u8 *)segment + boundedSegmentSize) > data_end)
   {
      return false;
   }

   suffixOffset = (__u16)(boundedChecksumByteOffset + 2u);
   if (boundedSegmentSize < suffixOffset)
   {
      return false;
   }

   prefixBytes = boundedChecksumByteOffset;
   suffixBytes = (__u16)(boundedSegmentSize - suffixOffset);

   __u8 lengthBytes[4] = {
      (__u8)((boundedSegmentSize >> 24) & 0xffu),
      (__u8)((boundedSegmentSize >> 16) & 0xffu),
      (__u8)((boundedSegmentSize >> 8) & 0xffu),
      (__u8)(boundedSegmentSize & 0xffu)
   };
   __u8 nextHeaderBytes[4] = {0, 0, 0, nextHeader};

   __u32 csum = 0;
   if (accumulate_fixed_checksum_words(&csum, srcv6, 16) == false
      || accumulate_fixed_checksum_words(&csum, dstv6, 16) == false
      || accumulate_fixed_checksum_words(&csum, lengthBytes, sizeof(lengthBytes)) == false
      || accumulate_fixed_checksum_words(&csum, nextHeaderBytes, sizeof(nextHeaderBytes)) == false)
   {
      return false;
   }

   if (prefixBytes > 0 && accumulate_packet_checksum_bytes(&csum, segment, prefixBytes, data_end) == false)
   {
      return false;
   }

   if (suffixBytes > 0
      && accumulate_packet_checksum_bytes(
         &csum,
         (const __u8 *)segment + suffixOffset,
         suffixBytes,
         data_end) == false)
   {
      return false;
   }

   __u16 folded = fold_l4_checksum_sum16(csum);
   *checksumOut = normalize_l4_checksum_word16(bpf_htons((__u16)(~folded & 0xffffu)));
   return true;
}

__attribute__((__always_inline__))
static inline bool recompute_ipv6_transport_checksum_in_packet(
   __u16 *checksumField,
   const void *segment,
   __u16 segmentSize,
   __u16 checksumByteOffset,
   const __be32 srcv6[4],
   const __be32 dstv6[4],
   __u8 nextHeader,
   const void *data_end)
{
   __u16 recomputed = 0;
   if (checksumField == NULL
      || compute_ipv6_transport_checksum_in_packet(
         &recomputed,
         segment,
         segmentSize,
         checksumByteOffset,
         srcv6,
         dstv6,
         nextHeader,
         data_end) == false)
   {
      return false;
   }

   *checksumField = recomputed;
   return true;
}

__attribute__((__always_inline__))
static inline bool store_recomputed_ipv6_transport_checksum_skb(struct __sk_buff *skb, __u8 nextHeader)
{
   void *data = (void *)(long)skb->data;
   void *data_end = (void *)(long)skb->data_end;
   struct switchboard_ipv6_skb_layout layout = {};
   struct ipv6hdr ip6h = {};
   if (switchboardResolveIPv6SKBLayout(data, data_end, skb->protocol, &layout) == false
      || bpf_skb_load_bytes(skb, layout.l3Offset, &ip6h, sizeof(ip6h)) != 0)
   {
      return false;
   }

   __u16 transportBytes = bpf_ntohs(ip6h.payload_len);
   const __u64 rewriteFlags = switchboardPacketRewriteManualChecksumStoreFlags();
   __u16 checksum = 0;

   if (nextHeader == IPPROTO_UDP)
   {
      if (transportBytes < sizeof(struct udphdr))
      {
         return false;
      }

      if (compute_ipv6_transport_checksum_skb(
            &checksum,
            skb,
            layout.transportOffset,
            transportBytes,
            __builtin_offsetof(struct udphdr, check),
            ip6h.saddr.s6_addr32,
            ip6h.daddr.s6_addr32,
            IPPROTO_UDP) == false)
      {
         return false;
      }

      const __u64 checksumOffset = layout.transportOffset + __builtin_offsetof(struct udphdr, check);
      return bpf_skb_store_bytes(skb, checksumOffset, &checksum, sizeof(checksum), rewriteFlags) == 0;
   }

   if (nextHeader == IPPROTO_TCP)
   {
      if (transportBytes < sizeof(struct tcphdr))
      {
         return false;
      }

      if (compute_ipv6_transport_checksum_skb(
            &checksum,
            skb,
            layout.transportOffset,
            transportBytes,
            __builtin_offsetof(struct tcphdr, check),
            ip6h.saddr.s6_addr32,
            ip6h.daddr.s6_addr32,
            IPPROTO_TCP) == false)
      {
         return false;
      }

      const __u64 checksumOffset = layout.transportOffset + __builtin_offsetof(struct tcphdr, check);
      return bpf_skb_store_bytes(skb, checksumOffset, &checksum, sizeof(checksum), rewriteFlags) == 0;
   }

   return false;
}
