// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>

// Live public QUIC reply rewrites now reach a 2050-byte UDP transport segment.
// Keep the ceiling exact so the helper loop bounds stay tight while the
// maintained battery's current packet still fits.
#define SWITCHBOARD_MAX_WORMHOLE_CHECKSUM_BYTES 2050u
#define SWITCHBOARD_WORMHOLE_SKB_CHECKSUM_CHUNK_BYTES 128u

__attribute__((__always_inline__))
static inline __u32 switchboardManualChecksumMaxBytes(void)
{
   return SWITCHBOARD_MAX_WORMHOLE_CHECKSUM_BYTES;
}

__attribute__((__always_inline__))
static inline __u32 switchboardManualChecksumSKBChunkBytes(void)
{
   return SWITCHBOARD_WORMHOLE_SKB_CHECKSUM_CHUNK_BYTES;
}

struct switchboard_ipv6_skb_layout
{
   __u64 l3Offset;
   __u64 transportOffset;
   __u64 sourceAddressOffset;
   __u64 destAddressOffset;
   __u64 sourcePortOffset;
   __u64 destPortOffset;
};

__attribute__((__always_inline__))
static inline bool switchboardResolveIPv6SKBLayout(const void *data,
   const void *data_end,
   __be16 protocol,
   struct switchboard_ipv6_skb_layout *layout)
{
   if (data == 0 || data_end == 0 || layout == 0 || protocol != bpf_htons(ETH_P_IPV6))
   {
      if (layout != 0)
      {
         __builtin_memset(layout, 0, sizeof(*layout));
      }
      return false;
   }

   __builtin_memset(layout, 0, sizeof(*layout));

   const struct ethhdr *eth = (const struct ethhdr *)data;
   if ((const void *)(eth + 1) <= data_end && eth->h_proto == protocol)
   {
      layout->l3Offset = sizeof(struct ethhdr);
   }

   if ((const void *)((const __u8 *)data + layout->l3Offset + sizeof(struct ipv6hdr)) > data_end)
   {
      __builtin_memset(layout, 0, sizeof(*layout));
      return false;
   }

   layout->transportOffset = layout->l3Offset + sizeof(struct ipv6hdr);
   layout->sourceAddressOffset = layout->l3Offset + __builtin_offsetof(struct ipv6hdr, saddr);
   layout->destAddressOffset = layout->l3Offset + __builtin_offsetof(struct ipv6hdr, daddr);
   layout->sourcePortOffset = layout->transportOffset;
   layout->destPortOffset = layout->transportOffset + sizeof(__be16);
   return true;
}

__attribute__((__always_inline__))
static inline __u16 normalize_l4_checksum_word16(__u16 checksum)
{
   return checksum == 0 ? 0xffff : checksum;
}

__attribute__((__always_inline__))
static inline __u64 switchboardPacketRewriteStoreFlags(void)
{
   // skb packet rewrites must keep both the stored bytes and skb checksum
   // metadata coherent so checksum-offloaded / GSO traffic survives later
   // segmentation and transmission.
   return BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH;
}

__attribute__((__always_inline__))
static inline __u64 switchboardPacketRewriteManualChecksumStoreFlags(void)
{
   // When a path recomputes the full transport checksum from the mutated
   // packet bytes, keep the final checksum-word store from layering helper
   // incremental checksum updates on top of the full recompute.
   return BPF_F_INVALIDATE_HASH;
}

__attribute__((__always_inline__))
static inline __u64 switchboardPacketRewriteManualChecksumDataStoreFlags(void)
{
   // Large UDP_SEGMENT / GRO packets can survive the full checksum rewrite only
   // if the intermediate tuple-byte stores still keep skb checksum/GSO
   // metadata coherent. Only the final checksum-word write should skip helper
   // incremental checksum updates.
   return switchboardPacketRewriteStoreFlags();
}

__attribute__((__always_inline__))
static inline __u64 switchboardAdjustRoomPreserveOffloadFlags(void)
{
   // Non-encap grow/shrink paths still need to preserve both checksum and GSO
   // metadata so the kernel can keep tracking an existing super-packet.
   return BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET;
}

__attribute__((__always_inline__))
static inline __u64 switchboardOverlayEncapAdjustRoomFlagsIPv6(void)
{
   // Once we wrap an inner packet in outer L3, preserving the inner UDP GSO
   // metadata lets the kernel segment the encapsulated packet into multiple
   // bogus partial inner datagrams. Keep checksum state, but force the outer
   // overlay packet to travel as one packet.
   return BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 | BPF_F_ADJ_ROOM_NO_CSUM_RESET;
}

__attribute__((__always_inline__))
static inline __u64 switchboardOverlayEncapAdjustRoomFlagsIPv4(void)
{
   return BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_NO_CSUM_RESET;
}

__attribute__((__always_inline__))
static inline __u16 fold_l4_checksum_sum16(__u64 csum)
{
   // Keep the fold verifier-friendly for eBPF callers by using a bounded
   // carry collapse instead of an open-ended loop.
   csum = (csum & 0xffffu) + (csum >> 16);
   csum = (csum & 0xffffu) + (csum >> 16);
   csum = (csum & 0xffffu) + (csum >> 16);
   csum = (csum & 0xffffu) + (csum >> 16);

   return (__u16)(csum & 0xffffu);
}

__attribute__((__always_inline__))
static inline __u64 checksum_word_accumulate_network_order(const void *value, __u32 byteCount)
{
   const __u8 *bytes = (const __u8 *)value;
   __u64 sum = 0;

   for (__u32 index = 0; index + 1 < byteCount; index += 2)
   {
      sum += (((__u64)bytes[index]) << 8) | ((__u64)bytes[index + 1]);
   }

   if (byteCount & 0x01u)
   {
      sum += ((__u64)bytes[byteCount - 1]) << 8;
   }

   return sum;
}

__attribute__((__always_inline__))
static inline __u16 checksum_word_sum_network_order(const void *value, __u32 byteCount)
{
   return fold_l4_checksum_sum16(checksum_word_accumulate_network_order(value, byteCount));
}

__attribute__((__always_inline__))
static inline __u16 checksum_word_sum_network_order_zeroed_word16(const void *value, __u32 byteCount, __u32 zeroWordByteOffset)
{
   const __u8 *bytes = (const __u8 *)value;
   __u64 sum = 0;

#pragma clang loop unroll(disable)
   for (__u32 index = 0; index < byteCount; index += 2)
   {
      if (index == zeroWordByteOffset)
      {
         continue;
      }

      __u8 low = 0;
      if (index + 1 < byteCount)
      {
         low = bytes[index + 1];
      }

      sum += (((__u64)bytes[index]) << 8) | ((__u64)low);
   }

   return fold_l4_checksum_sum16(sum);
}

__attribute__((__always_inline__))
static inline __u16 compute_ipv6_transport_checksum_portable(
   const void *srcv6,
   const void *dstv6,
   __u8 nextHeader,
   const void *segment,
   __u32 segmentSize,
   __u32 checksumByteOffset)
{
   __u8 lengthBytes[4] = {
      (__u8)((segmentSize >> 24) & 0xffu),
      (__u8)((segmentSize >> 16) & 0xffu),
      (__u8)((segmentSize >> 8) & 0xffu),
      (__u8)(segmentSize & 0xffu)
   };
   __u8 nextHeaderBytes[4] = {0, 0, 0, nextHeader};

   __u64 csum = 0;
   csum += checksum_word_accumulate_network_order(srcv6, 16);
   csum += checksum_word_accumulate_network_order(dstv6, 16);
   csum += checksum_word_accumulate_network_order(lengthBytes, sizeof(lengthBytes));
   csum += checksum_word_accumulate_network_order(nextHeaderBytes, sizeof(nextHeaderBytes));
   csum += checksum_word_sum_network_order_zeroed_word16(segment, segmentSize, checksumByteOffset);

   __u16 folded = fold_l4_checksum_sum16(csum);
   return normalize_l4_checksum_word16(bpf_htons((__u16)(~folded & 0xffffu)));
}

__attribute__((__always_inline__))
static inline __u16 replace_l4_checksum_portable(__u16 checksum, const void *old_value, const void *new_value, __u32 size)
{
   __u64 csum = (~(__u64)bpf_ntohs(checksum)) & 0xffffu;
   __u16 old_sum = checksum_word_sum_network_order(old_value, size);
   __u16 new_sum = checksum_word_sum_network_order(new_value, size);
   csum += (~(__u64)old_sum) & 0xffffu;
   csum += (__u64)new_sum;

   __u16 folded = fold_l4_checksum_sum16(csum);
   return normalize_l4_checksum_word16(bpf_htons((__u16)(~folded & 0xffffu)));
}

__attribute__((__always_inline__))
static inline __u16 replace_l4_checksum_word16(__u16 checksum, __u16 old_value_network_order, __u16 new_value_network_order)
{
   __u32 csum = (~(__u32)bpf_ntohs(checksum)) & 0xffffu;
   csum += (~(__u32)bpf_ntohs(old_value_network_order)) & 0xffffu;
   csum += (__u32)bpf_ntohs(new_value_network_order);
   csum = (csum & 0xffffu) + (csum >> 16);
   csum = (csum & 0xffffu) + (csum >> 16);
   return normalize_l4_checksum_word16(bpf_htons((__u16)(~csum & 0xffffu)));
}
