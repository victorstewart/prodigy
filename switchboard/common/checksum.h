// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>

struct switchboard_ipv6_skb_layout {
  __u64 l3Offset;
  __u64 transportOffset;
  __u64 sourceAddressOffset;
  __u64 destAddressOffset;
  __u64 sourcePortOffset;
  __u64 destPortOffset;
};

__attribute__((__always_inline__)) static inline bool switchboardResolveIPv6SKBLayout(const void *data,
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

__attribute__((__always_inline__)) static inline __u16 normalize_l4_checksum_word16(__u16 checksum)
{
  return checksum == 0 ? 0xffff : checksum;
}

__attribute__((__always_inline__)) static inline __u64 switchboardPacketRewriteStoreFlags(void)
{
  // skb packet rewrites must keep both the stored bytes and skb checksum
  // metadata coherent so checksum-offloaded / GSO traffic survives later
  // segmentation and transmission.
  return BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH;
}

__attribute__((__always_inline__)) static inline __u64 switchboardAdjustRoomPreserveOffloadFlags(void)
{
  // Non-encap grow/shrink paths still need to preserve both checksum and GSO
  // metadata so the kernel can keep tracking an existing super-packet.
  return BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET;
}

__attribute__((__always_inline__)) static inline __u64 switchboardOverlayEncapAdjustRoomFlagsIPv6(void)
{
  // Once we wrap an inner packet in outer L3, preserving the inner UDP GSO
  // metadata lets the kernel segment the encapsulated packet into multiple
  // bogus partial inner datagrams. Keep checksum state, but force the outer
  // overlay packet to travel as one packet.
  return BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 | BPF_F_ADJ_ROOM_NO_CSUM_RESET;
}

__attribute__((__always_inline__)) static inline __u64 switchboardOverlayEncapAdjustRoomFlagsIPv4(void)
{
  return BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_NO_CSUM_RESET;
}

__attribute__((__always_inline__)) static inline __u16 fold_l4_checksum_sum16(__u64 csum)
{
  // Keep the fold verifier-friendly for eBPF callers by using a bounded
  // carry collapse instead of an open-ended loop.
  csum = (csum & 0xffffu) + (csum >> 16);
  csum = (csum & 0xffffu) + (csum >> 16);
  csum = (csum & 0xffffu) + (csum >> 16);
  csum = (csum & 0xffffu) + (csum >> 16);

  return (__u16)(csum & 0xffffu);
}

__attribute__((__always_inline__)) static inline __u64 checksum_word_accumulate_network_order(const void *value, __u32 byteCount)
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

__attribute__((__always_inline__)) static inline __u16 checksum_word_sum_network_order(const void *value, __u32 byteCount)
{
  return fold_l4_checksum_sum16(checksum_word_accumulate_network_order(value, byteCount));
}

__attribute__((__always_inline__)) static inline __u16 replace_l4_checksum_portable(__u16 checksum, const void *old_value, const void *new_value, __u32 size)
{
  __u64 csum = (~(__u64)bpf_ntohs(checksum)) & 0xffffu;
  __u16 old_sum = checksum_word_sum_network_order(old_value, size);
  __u16 new_sum = checksum_word_sum_network_order(new_value, size);
  csum += (~(__u64)old_sum) & 0xffffu;
  csum += (__u64)new_sum;

  __u16 folded = fold_l4_checksum_sum16(csum);
  return normalize_l4_checksum_word16(bpf_htons((__u16)(~folded & 0xffffu)));
}

__attribute__((__always_inline__)) static inline __u16 replace_l4_checksum_word16(__u16 checksum, __u16 old_value_network_order, __u16 new_value_network_order)
{
  __u32 csum = (~(__u32)bpf_ntohs(checksum)) & 0xffffu;
  csum += (~(__u32)bpf_ntohs(old_value_network_order)) & 0xffffu;
  csum += (__u32)bpf_ntohs(new_value_network_order);
  csum = (csum & 0xffffu) + (csum >> 16);
  csum = (csum & 0xffffu) + (csum >> 16);
  return normalize_l4_checksum_word16(bpf_htons((__u16)(~csum & 0xffffu)));
}
