#pragma once

__attribute__((__always_inline__)) 
static inline void bpf_memset(void *dest, __u32 val, __u32 len) 
{
   __u8 *ptr = dest;
   
   for (__u32 i = 0; i < len; i++) 
   {
      ptr[i] = val;
   }
}

__attribute__((__always_inline__)) 
static inline void bpf_memcpy(void *dest, const void *src, __u32 len) 
{
   const __u8 *s = src;
   __u8 *d = dest;

   for (__u32 i = 0; i < len; i++) 
   {
      d[i] = s[i];
   }
}

__attribute__((__always_inline__)) 
static inline int bpf_memcmp(const void *s1, const void *s2, __u32 n) 
{
   const __u8 *us1 = s1, *us2 = s2;
   
   while (n-- != 0) 
   {
      if (*us1 != *us2) return (*us1 < *us2) ? -1 : 1;
      us1++;
      us2++;
   }
   
   return 0;
}

__attribute__((__always_inline__))
static inline void null_mac_addresses(struct ethhdr *eth)
{
   __u8 null_mac[6] = {};
   
   bpf_memcpy(eth->h_source, null_mac, 6);
   bpf_memcpy(eth->h_dest, null_mac, 6);
}

__attribute__((__always_inline__))
static inline bool from_us_to_gateway(struct ethhdr *eth)
{
   __u32 zeroidx = 0;

   struct mac *mac = bpf_map_lookup_elem(&mac_map, &zeroidx);
   if (!mac) return false;

   struct mac *gateway_mac = bpf_map_lookup_elem(&gateway_mac_map, &zeroidx);
   if (!gateway_mac) return false;

   bpf_memcpy(eth->h_source, mac, 6);
   bpf_memcpy(eth->h_dest, gateway_mac, 6);

   return true;
}

__attribute__((__always_inline__))
static inline bool from_us_to_overlay_next_hop(struct ethhdr *eth, const __u8 next_hop_mac[6])
{
   __u32 zeroidx = 0;

   struct mac *mac = bpf_map_lookup_elem(&mac_map, &zeroidx);
   if (!mac || next_hop_mac == NULL)
   {
      return false;
   }

   bpf_memcpy(eth->h_source, mac, 6);
   bpf_memcpy(eth->h_dest, next_hop_mac, 6);
   return true;
}

__attribute__((__always_inline__))
static inline bool containerRequiresPublic4(void)
{
   __u32 zeroidx = 0;
   struct container_network_policy *policy = bpf_map_lookup_elem(&container_network_policy_map, &zeroidx);
   if (!policy) return false;
   return (policy->requiresPublic4 != 0);
}

__attribute__((__always_inline__))
static inline bool containerRequiresPublic6(void)
{
   __u32 zeroidx = 0;
   struct container_network_policy *policy = bpf_map_lookup_elem(&container_network_policy_map, &zeroidx);
   if (!policy) return false;
   return (policy->requiresPublic6 != 0);
}

__attribute__((__always_inline__))
static inline __u32 containerInterContainerMTU(void)
{
   __u32 zeroidx = 0;
   struct container_network_policy *policy = bpf_map_lookup_elem(&container_network_policy_map, &zeroidx);
   if (!policy) return 0;
   return policy->interContainerMTU;
}
