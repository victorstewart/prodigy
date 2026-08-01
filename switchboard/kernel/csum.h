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

__attribute__((__always_inline__)) static inline __u16 csum_fold_helper(__u64 csum)
{
  int i;

#pragma unroll
  for (i = 0; i < 4; i++)
  {
    if (csum >> 16)
    {
      csum = (csum & 0xffff) + (csum >> 16);
    }
  }

  return ~csum;
}

__attribute__((__always_inline__)) static inline void ipv4_csum_inline(void *iph, __u64 *csum)
{
  __u16 *next_iph_u16 = (__u16 *)iph;

#pragma clang loop unroll(full)
  for (int i = 0; i < sizeof(struct iphdr) >> 1; i++)
  {
    *csum += *next_iph_u16++;
  }

  *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__)) static inline __u16 replace_l4_checksum(__u16 checksum, const void *old_value, const void *new_value, __u32 size)
{
  return replace_l4_checksum_portable(checksum, old_value, new_value, size);
}

__attribute__((__always_inline__)) static inline int replace_l4_checksum_word16_skb(struct __sk_buff *skb, __u32 checksumOffset, __be16 oldValue, __be16 newValue, __u64 extraFlags)
{
  return bpf_l4_csum_replace(skb, checksumOffset, oldValue, newValue, extraFlags | sizeof(__be16));
}

__attribute__((__always_inline__)) static inline int replace_l4_checksum_word32_skb(struct __sk_buff *skb, __u32 checksumOffset, __be32 oldValue, __be32 newValue, __u64 extraFlags)
{
  return bpf_l4_csum_replace(skb, checksumOffset, oldValue, newValue, extraFlags | sizeof(__be32));
}

__attribute__((__always_inline__)) static inline bool replace_l4_checksum_ipv6_address_skb(struct __sk_buff *skb,
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
