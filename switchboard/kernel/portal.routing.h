#pragma once

#include <switchboard/common/constants.h>
#include <switchboard/common/local_container_subnet.h>
#include <switchboard/kernel/jhash.h>
#include <switchboard/kernel/services.h>
#include <switchboard/kernel/layer4.h>
#include <switchboard/kernel/csum.h>
#include <switchboard/kernel/maps.h>
#include <switchboard/kernel/quic.h>
#include <switchboard/kernel/structs.h>

enum
{
   SWITCHBOARD_PORTAL_TARGET_NONE = 0,
   SWITCHBOARD_PORTAL_TARGET_RESOLVED = 1,
   SWITCHBOARD_PORTAL_TARGET_DROP = -1,
};

__attribute__((__always_inline__))
static inline __u32 switchboardPacketHash(struct packet_description *pckt, bool hash16Bytes)
{
   if (hash16Bytes)
   {
      return jhash_2words(jhash(pckt->flow.srcv6, 16, INIT_JHASH_SEED_V6), pckt->flow.ports, INIT_JHASH_SEED);
   }

   return jhash_2words(pckt->flow.src, pckt->flow.ports, INIT_JHASH_SEED);
}

__attribute__((__always_inline__))
static inline void switchboardConnectionTableLookup(struct container_id *containerID, struct packet_description *pckt)
{
   struct container_id *tentativeContainerID = bpf_map_lookup_elem(&percpu_lru_mapping, &pckt->flow);

   if (tentativeContainerID)
   {
      bpf_memcpy(containerID, tentativeContainerID, sizeof(struct container_id));
   }
}

__attribute__((__always_inline__))
static inline void switchboardSelectContainer(struct container_id *containerID,
   struct packet_description *pckt,
   struct portal_meta *portalMeta,
   bool isIPv6)
{
   __u32 hashringIndex = portalMeta->slot;
   __u32 *hashringID = bpf_map_lookup_elem(&container_id_hash_rings, &hashringIndex);

   if (hashringID)
   {
      __u32 slot = switchboardPacketHash(pckt, isIPv6) % RING_SIZE;
      struct container_id *tentativeContainerID = bpf_map_lookup_elem(hashringID, &slot);

      if (tentativeContainerID)
      {
         bpf_memcpy(containerID, tentativeContainerID, sizeof(struct container_id));

         if (pckt->flow.proto == IPPROTO_TCP)
         {
            bpf_map_update_elem(&percpu_lru_mapping, &pckt->flow, containerID, BPF_ANY);
         }
      }
   }
}

__attribute__((__always_inline__))
static inline bool switchboardLookupWormholeTargetPort(__u32 slot, const struct container_id *containerID, __u16 *targetPort)
{
   if (containerID == NULL || targetPort == NULL || containerID->hasID == false)
   {
      return false;
   }

   struct switchboard_wormhole_target_key key = {
      .slot = slot,
   };
   bpf_memcpy(key.container, containerID->value, sizeof(key.container));

   __u16 *value = bpf_map_lookup_elem(&wormhole_target_ports, &key);
   if (value == NULL || *value == 0)
   {
      return false;
   }

   *targetPort = *value;
   return true;
}

__attribute__((__always_inline__))
static inline int switchboardResolveExternalPortalTarget(void *data,
   void *data_end,
   bool isIPv6,
   struct packet_description *pckt,
   struct container_id *containerID,
   struct portal_meta **portalMetaOut)
{
   if (pckt == NULL || containerID == NULL)
   {
      return SWITCHBOARD_PORTAL_TARGET_DROP;
   }

   struct portal_definition portal = {};
   if (isIPv6)
   {
      bpf_memcpy(portal.addr6, pckt->flow.dstv6, sizeof(portal.addr6));
   }
   else
   {
      portal.addr4 = pckt->flow.dst;
   }
   portal.port = pckt->flow.port16[1];
   portal.proto = pckt->flow.proto;

   struct portal_meta *portalMeta = bpf_map_lookup_elem(&external_portals, &portal);
   if (portalMeta == NULL)
   {
      return SWITCHBOARD_PORTAL_TARGET_NONE;
   }

   if (portalMetaOut)
   {
      *portalMetaOut = portalMeta;
   }

   if (portalMeta->flags & F_QUIC_PORTAL)
   {
      bool allowHashFallback = parse_quic(containerID, portalMeta, data, data_end, isIPv6, &pckt->flow);
      if (containerID->hasID == false && allowHashFallback == false)
      {
         return SWITCHBOARD_PORTAL_TARGET_DROP;
      }
   }
   else if ((pckt->flags & F_SYN_SET) == 0)
   {
      switchboardConnectionTableLookup(containerID, pckt);
   }

   if (containerID->hasID == false)
   {
      switchboardSelectContainer(containerID, pckt, portalMeta, isIPv6);
      if (containerID->hasID == false)
      {
         return SWITCHBOARD_PORTAL_TARGET_DROP;
      }
   }

   return SWITCHBOARD_PORTAL_TARGET_RESOLVED;
}

__attribute__((__always_inline__))
static inline bool switchboardRewriteWormholeIPv6Target(void *data,
   void *data_end,
   struct packet_description *pckt,
   const struct container_id *containerID,
   __u16 targetPort)
{
   if (containerID == NULL || pckt == NULL || containerID->hasID == false)
   {
      return false;
   }

   __u64 l4Off = calc_offset(true);
   struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
   if ((void *)(ip6h + 1) > data_end)
   {
      return false;
   }

   __u16 transportBytes = (__u16)((const __u8 *)data_end - ((const __u8 *)data + l4Off));
   __u16 payloadBytes = (__u16)bpf_ntohs(ip6h->payload_len);
   if (transportBytes != payloadBytes)
   {
      return false;
   }

   __u8 newAddr6[16] = {};
   if (switchboardBuildContainerNetworkIPv6(newAddr6, containerID) == false)
   {
      return false;
   }

   if (pckt->flow.proto == IPPROTO_UDP)
   {
      struct udphdr *udph = data + l4Off;
      if ((void *)(udph + 1) > data_end)
      {
         return false;
      }

      if (udph->dest != targetPort)
      {
         udph->dest = targetPort;
      }

      if (recompute_ipv6_transport_checksum_in_packet(
            &udph->check,
            udph,
            transportBytes,
            __builtin_offsetof(struct udphdr, check),
            ip6h->saddr.s6_addr32,
            (__be32 *)newAddr6,
            IPPROTO_UDP,
            data_end) == false)
      {
         return false;
      }
   }
   else if (pckt->flow.proto == IPPROTO_TCP)
   {
      struct tcphdr *tcph = data + l4Off;
      if ((void *)(tcph + 1) > data_end)
      {
         return false;
      }

      if (tcph->dest != targetPort)
      {
         tcph->dest = targetPort;
      }

      if (recompute_ipv6_transport_checksum_in_packet(
            &tcph->check,
            tcph,
            transportBytes,
            __builtin_offsetof(struct tcphdr, check),
            ip6h->saddr.s6_addr32,
            (__be32 *)newAddr6,
            IPPROTO_TCP,
            data_end) == false)
      {
         return false;
      }
   }
   else
   {
      return false;
   }

   bpf_memcpy(ip6h->daddr.s6_addr, newAddr6, sizeof(newAddr6));
   bpf_memcpy(pckt->flow.dstv6, newAddr6, sizeof(newAddr6));
   pckt->flow.port16[1] = targetPort;

   return true;
}

__attribute__((__always_inline__))
static inline bool switchboardRewriteWormholeIPv6TargetSKB(struct __sk_buff *skb,
   struct packet_description *pckt,
   const struct container_id *containerID,
   __u16 targetPort)
{
   void *data = (void *)(long)skb->data;
   void *data_end = (void *)(long)skb->data_end;
   struct switchboard_ipv6_skb_layout layout = {};
   if (containerID == NULL || pckt == NULL || containerID->hasID == false)
   {
      return false;
   }

   __u8 newAddr6[16] = {};
   if (switchboardBuildContainerNetworkIPv6(newAddr6, containerID) == false)
   {
      return false;
   }

   if (switchboardResolveIPv6SKBLayout(data, data_end, skb->protocol, &layout) == false)
   {
      return false;
   }

   const __u64 rewriteFlags = switchboardPacketRewriteManualChecksumDataStoreFlags();
   __be16 oldTargetPort = pckt->flow.port16[1];

   if (pckt->flow.proto != IPPROTO_UDP && pckt->flow.proto != IPPROTO_TCP)
   {
      return false;
   }

   if (oldTargetPort != targetPort
      && bpf_skb_store_bytes(skb, layout.destPortOffset, &targetPort, sizeof(targetPort), rewriteFlags) != 0)
   {
      return false;
   }

   if (bpf_skb_store_bytes(skb, layout.destAddressOffset, newAddr6, sizeof(newAddr6), rewriteFlags) != 0)
   {
      return false;
   }

   if (store_recomputed_ipv6_transport_checksum_skb(skb, pckt->flow.proto) == false)
   {
      return false;
   }

   bpf_memcpy(pckt->flow.dstv6, newAddr6, sizeof(newAddr6));
   pckt->flow.port16[1] = targetPort;
   return true;
}
