#include <linux/tcp.h>
#include <linux/udp.h>

#include <asm/byteorder.h> // __constant_htonl

#include <ebpf/kernel/includes.h>

#include <switchboard/common/constants.h>
#include <switchboard/common/balancer.policy.h>
#include <switchboard/common/structs.h>

#include <switchboard/kernel/jhash.h>
#include <switchboard/kernel/csum.h>
#include <switchboard/kernel/services.h>
#include <switchboard/kernel/structs.h>
#include <switchboard/kernel/maps.h>
#include <switchboard/kernel/layer4.h>
#include <switchboard/kernel/encap.h>
#include <switchboard/kernel/quic.h>
#include <switchboard/kernel/portal.routing.h>
#include <switchboard/kernel/whitehole.routing.h>

#ifndef NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
#define NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE 0
#endif

#if !PRODIGY_DEBUG
// Keep balancer buildable when debug packet tracing maps/hooks are compiled out.
struct packet {
   bool balancer;
   bool localDelivery;
   struct container_id containerID;
};

__attribute__((__always_inline__))
static inline struct packet *getPacket(void)
{
   return NULL;
}

__attribute__((__always_inline__))
static inline void setCheckpoint(const char *reading)
{
   (void)reading;
}

__attribute__((__always_inline__))
static inline int setInstruction(int instruction)
{
   return instruction;
}

__attribute__((__always_inline__))
static inline void logXDP(struct xdp_md *xdp)
{
   (void)xdp;
}
#endif

__attribute__((__always_inline__))
static inline bool containsContainerNetworkIPv6(const __u32 dstv6[4])
{
   const __u8 *bytes = (const __u8 *)dstv6;
   return bytes[0] == container_network_subnet6.value[0]
      && bytes[1] == container_network_subnet6.value[1]
      && bytes[2] == container_network_subnet6.value[2]
      && bytes[3] == container_network_subnet6.value[3]
      && bytes[4] == container_network_subnet6.value[4]
      && bytes[5] == container_network_subnet6.value[5]
      && bytes[6] == container_network_subnet6.value[6]
      && bytes[7] == container_network_subnet6.value[7]
      && bytes[8] == container_network_subnet6.value[8]
      && bytes[9] == container_network_subnet6.value[9]
      && bytes[10] == container_network_subnet6.value[10];
}

__attribute__((__always_inline__))
static inline bool ownedRoutablePrefixesContainIPv4(__be32 dest_ip)
{
   struct switchboard_owned_routable_prefix4_key key = {
      .prefixlen = 32,
      .addr = dest_ip,
   };

   return bpf_map_lookup_elem(&owned_routable_prefixes4, &key) != NULL;
}

__attribute__((__always_inline__))
static inline bool ownedRoutablePrefixesContainIPv6(const __u32 dstv6[4])
{
   struct switchboard_owned_routable_prefix6_key key = {
      .prefixlen = 128,
   };
   bpf_memcpy(key.addr, dstv6, sizeof(key.addr));

   return bpf_map_lookup_elem(&owned_routable_prefixes6, &key) != NULL;
}

__attribute__((__always_inline__))
static inline int ourSubnetsContainDaddr(struct ethhdr *eth, void *data_end)
{
   if ((void *)(eth + 1) > data_end)
   {
      return 0;
   }

   if (eth->h_proto == BE_ETH_P_IP)
   {
      struct iphdr *iph = (struct iphdr *)(eth + 1);

      if ((void *)(iph + 1) > data_end)
      {
         return 0;
      }

      __u32 dest_ip = iph->daddr;
      return ownedRoutablePrefixesContainIPv4(dest_ip) ? 1 : 0;
   }
   else if (eth->h_proto == BE_ETH_P_IPV6)
   {
      struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);

      if ((void *)(ip6h + 1) > data_end)
      {
         return 0;
      }

      return (containsContainerNetworkIPv6(ip6h->daddr.s6_addr32) || ownedRoutablePrefixesContainIPv6(ip6h->daddr.s6_addr32)) ? 1 : 0;
   }

   return 0;
}

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
struct
{
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __uint(max_entries, 16);
   __type(key, __u32);
   __type(value, __u64);
} dev_fake_route_stats SEC(".maps");

__attribute__((__always_inline__))
static inline void bump_dev_fake_route_stat(__u32 index)
{
   __u64 *slot = bpf_map_lookup_elem(&dev_fake_route_stats, &index);
   if (slot)
   {
      __sync_fetch_and_add(slot, 1);
   }
}

__attribute__((__always_inline__))
static inline bool set_container_id_from_routable_ipv4(struct container_id *containerID, __be32 dst, const struct local_container_subnet6 *localcontainersubnet6)
{
   const __u8 *dst_bytes = (const __u8 *)&dst;
   __u8 machine_fragment = dst_bytes[2];
   __u8 container_fragment = dst_bytes[3];

   if (localcontainersubnet6 == NULL || machine_fragment == 0 || container_fragment == 0)
   {
      return false;
   }

   containerID->value[0] = localcontainersubnet6->dpfx;
   containerID->value[1] = localcontainersubnet6->mpfx[0];
   containerID->value[2] = localcontainersubnet6->mpfx[1];
   containerID->value[3] = machine_fragment;
   containerID->value[4] = container_fragment;
   containerID->hasID = true;

   return true;
}

__attribute__((__always_inline__))
static inline bool set_container_id_from_routable_ipv6(struct container_id *containerID, const __u32 dstv6[4], const struct local_container_subnet6 *localcontainersubnet6)
{
   const __u8 *bytes = (const __u8 *)dstv6;
   __u8 datacenter_fragment = bytes[11];
   __u8 machine_fragment0 = bytes[12];
   __u8 machine_fragment1 = bytes[13];
   __u8 machine_fragment2 = bytes[14];
   __u8 container_fragment = bytes[15];

   if (localcontainersubnet6 == NULL || datacenter_fragment == 0 || container_fragment == 0)
   {
      return false;
   }

   containerID->value[0] = datacenter_fragment;
   containerID->value[1] = machine_fragment0;
   containerID->value[2] = machine_fragment1;
   containerID->value[3] = machine_fragment2;
   containerID->value[4] = container_fragment;
   containerID->hasID = true;

   return true;
}
#endif

#define XDP_CONTINUE 999

__attribute__((__always_inline__)) 
static inline int process_l3_headers(struct packet_description *pckt, __u64 off, __u16 *packet_len, void *data, void *data_end, bool is_ipv6) 
{
   if (is_ipv6) 
   {
      struct ipv6hdr *ip6h = data + off;

      if ((void *)(ip6h + 1) > data_end) return XDP_DROP;

      if (ip6h->nexthdr == IPPROTO_TCP || ip6h->nexthdr == IPPROTO_UDP)
      {
         pckt->flow.proto = ip6h->nexthdr;
         *packet_len = bpf_ntohs(ip6h->payload_len) + sizeof(struct ipv6hdr);
         bpf_memcpy(pckt->flow.srcv6, ip6h->saddr.s6_addr32, 16);
         bpf_memcpy(pckt->flow.dstv6, ip6h->daddr.s6_addr32, 16);
      }
      else if (switchboardBalancerPassesIPv6ToKernel(ip6h->nexthdr))
      {
         return XDP_PASS;
      }
      // drop fragments and IPv6 extension headers the balancer does not own.
      else return XDP_DROP; 
   } 
   else 
   {
      struct iphdr *iph = data + off;

      if ((void *)(iph + 1) > data_end) return XDP_DROP;
    
      // ihl contains len of ipv4 header in 32bit words
      if (iph->ihl != 5) return XDP_DROP; // drop ipv4 headers that contain ip options

      if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
      {
         pckt->flow.proto = iph->protocol;
         *packet_len = bpf_ntohs(iph->tot_len);
         pckt->flow.src = iph->saddr;
         pckt->flow.dst = iph->daddr;
      }
      else if (iph->protocol == IPPROTO_ICMP)
      {
         __be32 subnet_mask = __constant_htonl(0xFF000000); // 255.0.0.0 in network byte order
         __be32 subnet = __constant_htonl(0x0A000000); // 10.0.0.0 in network byte order

         if ((iph->saddr & subnet_mask) == subnet) // within 10.0.0.0/8 so either came from another machine, or switch or router
         {
            return XDP_PASS; // pass to kernel
         }

         return XDP_DROP;
      }
      else return XDP_DROP; // drop fragments
   }

   return XDP_CONTINUE;
}

__attribute__((__always_inline__)) 
static inline int process_packet(struct xdp_md *xdp, __u64 off, bool is_ipv6) 
{
   void *data = (void *)(long)xdp->data;
   void *data_end = (void *)(long)xdp->data_end;
   __u32 zeroidx = 0;

   struct container_id containerID = { .value = {0}, .hasID = false };

   struct packet_description pckt = {};
   __u16 packet_len;

   int action = process_l3_headers(&pckt, off, &packet_len, data, data_end, is_ipv6);

   if (action != XDP_CONTINUE) return action;

   if (pckt.flow.proto == IPPROTO_TCP) 
   {
      if (!parse_tcp(data, data_end, is_ipv6, &pckt)) return XDP_DROP;
   } 
   else // we already dropped any other protocols in process_l3_headers so must be UDP
   {
      if (!parse_udp(data, data_end, is_ipv6, &pckt)) return XDP_DROP;
   } 

   struct switchboard_whitehole_binding whitehole_binding = {};
   bool whitehole_bound = whitehole_binding_lookup(pckt.flow.proto,
      is_ipv6,
      is_ipv6 ? (const void *)pckt.flow.dstv6 : (const void *)&pckt.flow.dst,
      pckt.flow.port16[1],
      &whitehole_binding);

   if (whitehole_bound)
   {
      struct switchboard_whitehole_binding *reply_binding = bpf_map_lookup_elem(&whitehole_reply_flows, &pckt.flow);
      if (whitehole_binding_matches(&whitehole_binding, reply_binding) == false)
      {
         return XDP_DROP;
      }

      bpf_memcpy(&containerID, &reply_binding->container, sizeof(containerID));
   }

   struct portal_definition portal = {}; 
   
   if (is_ipv6) bpf_memcpy(portal.addr6, pckt.flow.dstv6, 16);
   else         portal.addr4 = pckt.flow.dst;

   portal.port = pckt.flow.port16[1];
   portal.proto = pckt.flow.proto;

   struct portal_meta *portal_meta = NULL;
   if (whitehole_bound == false)
   {
      portal_meta = bpf_map_lookup_elem(&external_portals, &portal); // check if this is an open portal
   }
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
   struct local_container_subnet6 *localcontainersubnet6 = bpf_map_lookup_elem(&local_container_subnet_map, &zeroidx);
   bool direct_fake_delivery = false;

   if (!portal_meta && !is_ipv6 && localcontainersubnet6 && ownedRoutablePrefixesContainIPv4(pckt.flow.dst))
   {
      direct_fake_delivery = set_container_id_from_routable_ipv4(&containerID, pckt.flow.dst, localcontainersubnet6);
      if (direct_fake_delivery)
      {
         bump_dev_fake_route_stat(0);
      }
   }
   else if (!portal_meta && is_ipv6 && localcontainersubnet6 && ownedRoutablePrefixesContainIPv6(pckt.flow.dstv6))
   {
      direct_fake_delivery = set_container_id_from_routable_ipv6(&containerID, pckt.flow.dstv6, localcontainersubnet6);
      if (direct_fake_delivery)
      {
         bump_dev_fake_route_stat(1);
      }
   }
#endif

   // this isn't a /32 or /128 we balance, so pass to kernel 
   // possibly contained witin a prefix we own, destined for a container using a unicast as a public address
   // or could be container to container traffic
   // or inter neuron traffic over the private ipv4..
   // or junk.. regardless pass it to the kernel

   setCheckpoint("process_packet: checkpoint 1"); // they're being passed right here... which means a problem with the external_portals

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
   if (!portal_meta && !direct_fake_delivery && !whitehole_bound) 
#else
   if (!portal_meta && !whitehole_bound) 
#endif
   {
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
      bump_dev_fake_route_stat(2);
#endif
      setCheckpoint("process_packet: !portal_meta");
      return XDP_PASS; 
   }

   struct packet *pkt = getPacket();

   if (pkt) pkt->balancer = true;

   setCheckpoint("process_packet: checkpoint 2");

#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
   if (!direct_fake_delivery)
   {
#endif
   if (whitehole_bound)
   {
      // no additional action here
   }
   else if (portal_meta->flags & F_QUIC_PORTAL)
   {
      setCheckpoint("process_packet: isQuic");

      bool allow_hash_fallback = parse_quic(&containerID, portal_meta, data, data_end, is_ipv6, &pckt.flow);

      if (containerID.hasID) 
      {
         // no action here
      }
      else if (allow_hash_fallback == false) // only Initial and 0-RTT may fall back to tuple hashing
      {
         return XDP_DROP; // either packet too short or connectionID too short
      }
   }
   else if (!(pckt.flags & F_SYN_SET)) // TCP, so check in lru_cache
   {
      switchboardConnectionTableLookup(&containerID, &pckt);
   }

   setCheckpoint("process_packet: checkpoint 3");

   if (containerID.hasID == false) 
   {
      if (portal_meta == NULL)
      {
         setInstruction(XDP_DROP);
         return XDP_DROP;
      }

      switchboardSelectContainer(&containerID, &pckt, portal_meta, is_ipv6);

      if (containerID.hasID == false) 
      {
         setInstruction(XDP_DROP);
         return XDP_DROP;
      }
   }
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
   }
#endif

   if (pkt) bpf_memcpy(&pkt->containerID, &containerID, sizeof(struct container_id));

   if (portal_meta != NULL && is_ipv6)
   {
      __u16 target_port = 0;
      if (switchboardLookupWormholeTargetPort(portal_meta->slot, &containerID, &target_port) == false
         || switchboardRewriteWormholeIPv6Target(data, data_end, &pckt, &containerID, target_port) == false)
      {
         setInstruction(XDP_DROP);
         return XDP_DROP;
      }
   }

   setCheckpoint("process_packet: checkpoint 4");

#if !NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
   struct local_container_subnet6 *localcontainersubnet6 = bpf_map_lookup_elem(&local_container_subnet_map, &zeroidx);
#endif

   if (localcontainersubnet6)
   {
      bool localDelivery = (bpf_memcmp(containerID.value, localcontainersubnet6, 4) == 0);

      if (pkt) pkt->localDelivery = localDelivery;

      setCheckpoint("process_packet: checkpoint 6");

      // Same-machine delivery does not need overlay encapsulation. Keep the
      // packet native and let host_ingress_router redirect it to the target
      // container using the already-selected destination prefix/address.
      if (localDelivery)
      {
         setInstruction(XDP_PASS);
         logXDP(xdp);
         return XDP_PASS;
      }

      // Cross-machine delivery leaves this NIC toward the overlay, so we wrap
      // the native packet in an outer IPv6 header here.
      if (!encap_v6(xdp, localDelivery, localcontainersubnet6, &containerID, packet_len, is_ipv6)) 
      {
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
         if (direct_fake_delivery)
         {
            bump_dev_fake_route_stat(3);
         }
#endif
         setInstruction(XDP_DROP);
         return XDP_DROP;
      }

      setCheckpoint("process_packet: checkpoint 7");

      setCheckpoint("process_packet: checkpoint 8");

      setInstruction(XDP_TX);
#if NAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE
      if (direct_fake_delivery)
      {
         bump_dev_fake_route_stat(5);
      }
#endif
      logXDP(xdp);
      return XDP_TX; // send encapsulated packet back out the interface to the router
   }

   setCheckpoint("process_packet: end");

   setInstruction(XDP_PASS);
   return XDP_PASS;
}

SEC("xdp")
int balancer_ingress(struct xdp_md *xdp) 
{
   logXDP(xdp);

   void *data = (void *)(long)xdp->data;
   void *data_end = (void *)(long)xdp->data_end;

   bool destination_is_ours = (ourSubnetsContainDaddr((struct ethhdr *)data, data_end) == 1);

   if (destination_is_ours)
   {
      if (data + sizeof(struct ethhdr) > data_end) return XDP_DROP;

      struct ethhdr *eth = data;

      __u32 eth_proto = eth->h_proto;

      if (eth_proto == BE_ETH_P_IP) 
      {
         return process_packet(xdp, sizeof(struct ethhdr), false);
      } 
      else if (eth_proto == BE_ETH_P_IPV6) 
      {
         return process_packet(xdp, sizeof(struct ethhdr), true);
      } 
   }

   return XDP_PASS;
}
