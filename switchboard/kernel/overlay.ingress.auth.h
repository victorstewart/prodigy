#pragma once

#include <switchboard/common/local_container_subnet.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct switchboard_overlay_ingress_peer4_key);
  __type(value, __u8);
  __uint(max_entries, 1024);
} ovl_peer4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct switchboard_overlay_ingress_peer6_key);
  __type(value, __u8);
  __uint(max_entries, 1024);
} ovl_peer6 SEC(".maps");

__attribute__((__always_inline__)) static inline bool overlayIngressPeerAuthorizedIPv4(__be32 source, __be32 destination)
{
  struct switchboard_overlay_ingress_peer4_key key = {
      .source = source,
      .destination = destination,
  };
  return bpf_map_lookup_elem(&ovl_peer4, &key) != NULL;
}

__attribute__((__always_inline__)) static inline bool overlayLocalIngressMetadataAuthorized(const struct __sk_buff *skb)
{
  if (skb == NULL)
  {
    return false;
  }
  void *data = (void *)(long)skb->data;
  __u32 *marker = (void *)(long)skb->data_meta;
  return (void *)(marker + 1) <= data && *marker == SWITCHBOARD_OVERLAY_LOCAL_XDP_META_MAGIC;
}

__attribute__((__always_inline__)) static inline bool overlayIngressPeerAuthorizedIPv6(const struct __sk_buff *skb,
                                                                                        const __u8 source[16],
                                                                                        const __u8 destination[16],
                                                                                        const struct local_container_subnet6 *localSubnet)
{
  if (source == NULL || destination == NULL)
  {
    return false;
  }

  if (localSubnet != NULL &&
      bpf_memcmp(source, container_network_subnet6.value, sizeof(container_network_subnet6.value)) == 0 &&
      bpf_memcmp(destination, container_network_subnet6.value, sizeof(container_network_subnet6.value)) == 0 &&
      bpf_memcmp(source + 11, localSubnet, sizeof(*localSubnet)) == 0 && source[15] == 0 &&
      bpf_memcmp(destination + 11, localSubnet, sizeof(*localSubnet)) == 0 &&
      overlayLocalIngressMetadataAuthorized(skb))
  {
    return true;
  }

  struct switchboard_overlay_ingress_peer6_key key = {};
  bpf_memcpy(key.source, source, sizeof(key.source));
  bpf_memcpy(key.destination, destination, sizeof(key.destination));
  return bpf_map_lookup_elem(&ovl_peer6, &key) != NULL;
}
