#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef DEV_FAKE_IPV4_SUBNET
#define DEV_FAKE_IPV4_SUBNET 0xC6120000u /* 198.18.0.0 */
#endif

#ifndef DEV_FAKE_IPV4_MASK
#define DEV_FAKE_IPV4_MASK 0xFFFF0000u /* /16 */
#endif

#ifndef DEV_BOUNDARY_TRANSLATED_IPV4
#define DEV_BOUNDARY_TRANSLATED_IPV4 0xAC1F0002u /* 172.31.0.2 */
#endif

#ifndef DEV_NAT_PORT_MIN
#define DEV_NAT_PORT_MIN 20000u
#endif

#ifndef DEV_NAT_PORT_MAX
#define DEV_NAT_PORT_MAX 60999u
#endif

#ifndef IP_MF
#define IP_MF 0x2000
#endif

#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

struct flow4_key
{
   __be32 src_ip;
   __be32 dst_ip;
   __be16 src_port;
   __be16 dst_port;
   __u8 proto;
   __u8 padding[3];
};

struct reverse4_key
{
   __be16 nat_port;
   __u8 proto;
   __u8 padding;
};

struct nat4_binding
{
   __be32 fake_ip;
   __be16 fake_port;
   __be16 nat_port;
   __be32 remote_ip;
   __be16 remote_port;
   __u8 proto;
   __u8 padding[5];
   __u64 updated_ns;
};

struct
{
   __uint(type, BPF_MAP_TYPE_LRU_HASH);
   __uint(max_entries, 262144);
   __type(key, struct flow4_key);
   __type(value, struct nat4_binding);
} nat4_forward SEC(".maps");

struct
{
   __uint(type, BPF_MAP_TYPE_LRU_HASH);
   __uint(max_entries, 262144);
   __type(key, struct reverse4_key);
   __type(value, struct nat4_binding);
} nat4_reverse SEC(".maps");

struct
{
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __uint(max_entries, 1);
   __type(key, __u32);
   __type(value, __u32);
} nat4_port_cursor SEC(".maps");

struct
{
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __uint(max_entries, 16);
   __type(key, __u32);
   __type(value, __u64);
} nat4_stats SEC(".maps");

static __always_inline void bump_nat4_stat(__u32 index)
{
   __u64 *slot = bpf_map_lookup_elem(&nat4_stats, &index);
   if (slot)
   {
      __sync_fetch_and_add(slot, 1);
   }
}

static __always_inline bool is_fake_ipv4(__be32 address)
{
   __be32 subnet = bpf_htonl(DEV_FAKE_IPV4_SUBNET);
   __be32 mask = bpf_htonl(DEV_FAKE_IPV4_MASK);
   return (address & mask) == subnet;
}

static __always_inline bool parse_ipv4_l4(struct __sk_buff *skb, struct iphdr **iph_out, __u32 *l4_offset_out, __u8 *proto_out, __be16 *src_port_out, __be16 *dst_port_out, __u32 *l4_checksum_offset_out, bool *udp_checksum_present_out)
{
   void *data = (void *)(long)skb->data;
   void *data_end = (void *)(long)skb->data_end;

   struct ethhdr *eth = data;
   if ((void *)(eth + 1) > data_end)
   {
      return false;
   }

   if (eth->h_proto != bpf_htons(ETH_P_IP))
   {
      return false;
   }

   struct iphdr *iph = (void *)(eth + 1);
   if ((void *)(iph + 1) > data_end)
   {
      return false;
   }

   if (iph->ihl != 5)
   {
      return false;
   }

   if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
   {
      return false;
   }

   __u32 l4_offset = sizeof(struct ethhdr) + sizeof(struct iphdr);

   if (iph->protocol == IPPROTO_TCP)
   {
      struct tcphdr *tcp = (void *)iph + sizeof(struct iphdr);
      if ((void *)(tcp + 1) > data_end)
      {
         return false;
      }

      *proto_out = IPPROTO_TCP;
      *src_port_out = tcp->source;
      *dst_port_out = tcp->dest;
      *l4_checksum_offset_out = l4_offset + offsetof(struct tcphdr, check);
      *udp_checksum_present_out = true;
   }
   else if (iph->protocol == IPPROTO_UDP)
   {
      struct udphdr *udp = (void *)iph + sizeof(struct iphdr);
      if ((void *)(udp + 1) > data_end)
      {
         return false;
      }

      *proto_out = IPPROTO_UDP;
      *src_port_out = udp->source;
      *dst_port_out = udp->dest;
      *l4_checksum_offset_out = l4_offset + offsetof(struct udphdr, check);
      *udp_checksum_present_out = (udp->check != 0);
   }
   else
   {
      return false;
   }

   *iph_out = iph;
   *l4_offset_out = l4_offset;
   return true;
}

static __always_inline bool pick_nat_port(__u8 proto, __be16 *nat_port_out)
{
   __u32 zero = 0;
   __u32 *cursor = bpf_map_lookup_elem(&nat4_port_cursor, &zero);
   __u32 base = (cursor && *cursor > 0) ? *cursor : DEV_NAT_PORT_MIN;
   __u32 span = (DEV_NAT_PORT_MAX - DEV_NAT_PORT_MIN + 1);

#pragma clang loop unroll(full)
   for (int offset = 0; offset < 256; ++offset)
   {
      __u32 candidate = DEV_NAT_PORT_MIN + ((base + (__u32)offset) % span);

      struct reverse4_key reverse_key = {};
      reverse_key.nat_port = bpf_htons((__u16)candidate);
      reverse_key.proto = proto;

      if (bpf_map_lookup_elem(&nat4_reverse, &reverse_key) == NULL)
      {
         if (cursor)
         {
            *cursor = candidate + 1;
            if (*cursor > DEV_NAT_PORT_MAX)
            {
               *cursor = DEV_NAT_PORT_MIN;
            }
         }

         *nat_port_out = reverse_key.nat_port;
         return true;
      }
   }

   return false;
}

static __always_inline int rewrite_ipv4_addr(struct __sk_buff *skb, __u32 ip_offset, __u32 l4_checksum_offset, bool update_l4_checksum, bool rewrite_source, __be32 old_ip, __be32 new_ip)
{
   __u32 ip_field_offset = ip_offset + (rewrite_source ? offsetof(struct iphdr, saddr) : offsetof(struct iphdr, daddr));

   if (bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check), old_ip, new_ip, sizeof(__be32)) != 0)
   {
      return TC_ACT_SHOT;
   }

   if (bpf_skb_store_bytes(skb, ip_field_offset, &new_ip, sizeof(new_ip), 0) != 0)
   {
      return TC_ACT_SHOT;
   }

   if (update_l4_checksum)
   {
      if (bpf_l4_csum_replace(skb, l4_checksum_offset, old_ip, new_ip, BPF_F_PSEUDO_HDR | sizeof(__be32)) != 0)
      {
         return TC_ACT_SHOT;
      }
   }

   return TC_ACT_OK;
}

static __always_inline int rewrite_l4_port(struct __sk_buff *skb, __u32 l4_offset, __u32 l4_checksum_offset, bool update_l4_checksum, bool rewrite_source, __be16 old_port, __be16 new_port)
{
   __u32 port_offset = l4_offset + (rewrite_source ? 0u : 2u);

   if (bpf_skb_store_bytes(skb, port_offset, &new_port, sizeof(new_port), 0) != 0)
   {
      return TC_ACT_SHOT;
   }

   if (update_l4_checksum)
   {
      if (bpf_l4_csum_replace(skb, l4_checksum_offset, old_port, new_port, sizeof(__be16)) != 0)
      {
         return TC_ACT_SHOT;
      }
   }

   return TC_ACT_OK;
}

SEC("tc/egress")
int fake_ipv4_boundary_nat_egress(struct __sk_buff *skb)
{
   struct iphdr *iph = NULL;
   __u32 l4_offset = 0;
   __u8 proto = 0;
   __be16 src_port = 0;
   __be16 dst_port = 0;
   __u32 l4_checksum_offset = 0;
   bool update_l4_checksum = false;

   if (!parse_ipv4_l4(skb, &iph, &l4_offset, &proto, &src_port, &dst_port, &l4_checksum_offset, &update_l4_checksum))
   {
      return TC_ACT_OK;
   }

   bump_nat4_stat(0);

   if (!is_fake_ipv4(iph->saddr))
   {
      return TC_ACT_OK;
   }

   bump_nat4_stat(1);

   struct flow4_key flow = {};
   flow.src_ip = iph->saddr;
   flow.dst_ip = iph->daddr;
   flow.src_port = src_port;
   flow.dst_port = dst_port;
   flow.proto = proto;

   struct nat4_binding *existing = bpf_map_lookup_elem(&nat4_forward, &flow);
   struct nat4_binding binding = {};

   if (existing != NULL)
   {
      binding = *existing;
      binding.updated_ns = bpf_ktime_get_ns();
      bump_nat4_stat(2);
   }
   else
   {
      __be16 selected_nat_port = 0;
      if (!pick_nat_port(proto, &selected_nat_port))
      {
         bump_nat4_stat(14);
         return TC_ACT_OK;
      }

      binding.fake_ip = iph->saddr;
      binding.fake_port = src_port;
      binding.nat_port = selected_nat_port;
      binding.remote_ip = iph->daddr;
      binding.remote_port = dst_port;
      binding.proto = proto;
      binding.updated_ns = bpf_ktime_get_ns();
      bump_nat4_stat(3);
   }

   struct reverse4_key reverse_key = {};
   reverse_key.nat_port = binding.nat_port;
   reverse_key.proto = binding.proto;

   bpf_map_update_elem(&nat4_forward, &flow, &binding, BPF_ANY);
   bpf_map_update_elem(&nat4_reverse, &reverse_key, &binding, BPF_ANY);

   __be32 translated_ip = bpf_htonl(DEV_BOUNDARY_TRANSLATED_IPV4);

   int action = rewrite_ipv4_addr(skb, sizeof(struct ethhdr), l4_checksum_offset, update_l4_checksum, true, iph->saddr, translated_ip);
   if (action != TC_ACT_OK)
   {
      bump_nat4_stat(4);
      return action;
   }

   if (binding.nat_port != src_port)
   {
      action = rewrite_l4_port(skb, l4_offset, l4_checksum_offset, update_l4_checksum, true, src_port, binding.nat_port);
      if (action != TC_ACT_OK)
      {
         bump_nat4_stat(15);
         return action;
      }
   }

   bump_nat4_stat(5);
   return TC_ACT_OK;
}

SEC("tc/ingress")
int fake_ipv4_boundary_nat_ingress(struct __sk_buff *skb)
{
   struct iphdr *iph = NULL;
   __u32 l4_offset = 0;
   __u8 proto = 0;
   __be16 src_port = 0;
   __be16 dst_port = 0;
   __u32 l4_checksum_offset = 0;
   bool update_l4_checksum = false;

   if (!parse_ipv4_l4(skb, &iph, &l4_offset, &proto, &src_port, &dst_port, &l4_checksum_offset, &update_l4_checksum))
   {
      return TC_ACT_OK;
   }

   bump_nat4_stat(7);

   __be32 translated_ip = bpf_htonl(DEV_BOUNDARY_TRANSLATED_IPV4);
   if (iph->daddr != translated_ip)
   {
      return TC_ACT_OK;
   }

   bump_nat4_stat(8);

   struct reverse4_key reverse_key = {};
   reverse_key.nat_port = dst_port;
   reverse_key.proto = proto;

   struct nat4_binding *binding = bpf_map_lookup_elem(&nat4_reverse, &reverse_key);
   if (binding == NULL)
   {
      bump_nat4_stat(9);
      return TC_ACT_OK;
   }

   struct nat4_binding updated_binding = *binding;
   updated_binding.updated_ns = bpf_ktime_get_ns();
   bpf_map_update_elem(&nat4_reverse, &reverse_key, &updated_binding, BPF_ANY);

   if (binding->remote_ip != iph->saddr || binding->remote_port != src_port)
   {
      bump_nat4_stat(12);
      return TC_ACT_OK;
   }

   int action = rewrite_ipv4_addr(skb, sizeof(struct ethhdr), l4_checksum_offset, update_l4_checksum, false, iph->daddr, binding->fake_ip);
   if (action != TC_ACT_OK)
   {
      bump_nat4_stat(10);
      return action;
   }

   if (binding->nat_port != binding->fake_port)
   {
      action = rewrite_l4_port(skb, l4_offset, l4_checksum_offset, update_l4_checksum, false, binding->nat_port, binding->fake_port);
      if (action != TC_ACT_OK)
      {
         bump_nat4_stat(13);
         return action;
      }
   }

   bump_nat4_stat(11);
   return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
