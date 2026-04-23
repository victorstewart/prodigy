#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>

#include <ebpf/common/debug.h>

#pragma once

struct {
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __type(key, __u32);
   __type(value, __u32);
   __uint(max_entries, 1);
} packet_counter_map SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __type(key, __u32);
   __type(value, struct packet);
   __uint(max_entries, 256);
} packet_map SEC(".maps");

__attribute__((__always_inline__)) 
static inline struct packet_frame * getFrame(struct packet *pkt)
{
   switch (pkt->nFrames)
   {
      case 0:
      {
         pkt->nFrames = 1;
         return &pkt->frames[0];
      }
      case 1:
      {
         pkt->nFrames = 2;
         return &pkt->frames[1];
      }
      case 2:
      {
         pkt->nFrames = 3;
         return &pkt->frames[2];
      }
      case 3:
      {
         pkt->nFrames = 4;
         return &pkt->frames[3];
      }
      default:
      {
         return NULL;
      }
   }
}

__attribute__((__always_inline__)) 
static inline void logTcpFrame(struct tcphdr *tcp, struct packet *pkt, void *data_end)
{
   struct packet_frame *frame = getFrame(pkt);
   if (!frame) return;
   frame->type = is_tcp_frame;
   frame->tcp.seq = tcp->seq;
   frame->tcp.ack_seq = tcp->ack_seq;
   frame->tcp.sport = tcp->source;
   frame->tcp.dport = tcp->dest;
   frame->tcp.window = tcp->window;
   frame->tcp.isSyn = tcp->syn;
   frame->tcp.isAck = tcp->ack;
   frame->tcp.isFin = tcp->fin;
   frame->tcp.isRst = tcp->rst;

   void *payload = (void *)(tcp + 1);

   if (data_end > payload)
   {
      // pkt.payload.len = bpf_ntohs(ip6->payload_len) - sizeof(struct tcphdr);
      frame->tcp.payload_len = data_end - payload;

      // if (pkt.payload.len < sizeof(pkt.payload.string))
      // {
      //    bpf_memcpy(pkt.payload.string, payload, pkt.payload.len);
      // }
   }
}

__attribute__((__always_inline__)) 
static inline void logUdpFrame(struct udphdr *udp, struct packet *pkt, void *data_end)
{
   struct packet_frame *frame = getFrame(pkt);
   if (!frame) return;
   frame->type = is_udp_frame;
   frame->udp.sport = udp->source;
   frame->udp.dport = udp->dest;
   frame->udp.payload_len = udp->len;
}

__attribute__((__always_inline__)) 
static inline void logIcmp6Frame(struct icmp6hdr *icmp6, struct packet *pkt, void *data_end)
{
   struct packet_frame *frame = getFrame(pkt);
   if (!frame) return;
   frame->type = is_icmp6_frame;
   frame->icmp6.type = icmp6->icmp6_type;
   frame->icmp6.code = icmp6->icmp6_code;
}

__attribute__((__always_inline__)) 
static inline void logIpFrame(struct iphdr *ip, struct packet *pkt, void *data_end)
{
   struct packet_frame *frame = getFrame(pkt);
   if (!frame) return;
   frame->type = is_ip_frame;
   frame->ip.proto = ip->protocol;
   bpf_memcpy(frame->ip.src, &ip->saddr, 4);
   bpf_memcpy(frame->ip.dest, &ip->daddr, 4);

   switch (ip->protocol)
   {
      case IPPROTO_TCP:
      {
         struct tcphdr *tcph = (struct tcphdr *)(ip + 1);

         if ((void *)(tcph + 1) <= data_end)
         {
            logTcpFrame(tcph, pkt, data_end);
         }

         break;
      }
      case IPPROTO_UDP:
      {
         struct udphdr *udp = (struct udphdr *)(ip + 1);

         if ((void *)(udp + 1) <= data_end)
         {
            logUdpFrame(udp, pkt, data_end);
         }

         break;
      }
      default: break;
   }
}

__attribute__((__always_inline__)) 
static inline void logIpFrameHeader(struct iphdr *ip, struct packet *pkt)
{
   struct packet_frame *frame = getFrame(pkt);
   if (!frame) return;
   frame->type = is_ip_frame;
   frame->ip.proto = ip->protocol;
   bpf_memcpy(frame->ip.src, &ip->saddr, 4);
   bpf_memcpy(frame->ip.dest, &ip->daddr, 4);
}

__attribute__((__always_inline__)) 
static inline void logIp6Frame(struct ipv6hdr *ip6, struct packet *pkt, void *data_end)
{
   struct packet_frame *frame = getFrame(pkt);
   if (!frame) return;
   frame->type = is_ip6_frame;
   frame->ip6.proto = ip6->nexthdr;
   bpf_memcpy(frame->ip6.src, &ip6->saddr, 16);
   bpf_memcpy(frame->ip6.dest, &ip6->daddr, 16);

   switch (ip6->nexthdr)
   {
      case IPPROTO_TCP:
      {
         struct tcphdr *tcph = (struct tcphdr *)(ip6 + 1);

         if ((void *)(tcph + 1) <= data_end)
         {
            logTcpFrame(tcph, pkt, data_end);
         }

         break;
      }
      case IPPROTO_ICMPV6:
      {
         struct icmp6hdr *icmp6 = (struct icmp6hdr *)(ip6 + 1);

         if ((void *)(icmp6 + 1) <= data_end)
         {
            logIcmp6Frame(icmp6, pkt, data_end);
         }

         break;
      }
      case IPPROTO_IPV6:
      {
         struct ipv6hdr *inner_ip6 = (struct ipv6hdr *)(ip6 + 1);

         if ((void *)(inner_ip6 + 1) <= data_end)
         {
            logIp6Frame(inner_ip6, pkt, data_end);
         }

         break;
      }
      case IPPROTO_UDP:
      {
         struct udphdr *udp = (struct udphdr *)(ip6 + 1);

         if ((void *)(udp + 1) <= data_end)
         {
            logUdpFrame(udp, pkt, data_end);
         }

         break;
      }
      case IPPROTO_IPIP:
      {
         struct iphdr *ip = (struct iphdr *)(ip6 + 1);

         if ((void *)(ip + 1) <= data_end)
         {
            logIpFrame(ip, pkt, data_end);
         }

         break;
      }
      case 0: 
      {
         struct ipv6_opt_hdr *opt = (struct ipv6_opt_hdr *)(ip6 + 1);

         if ((void *)(opt + 1) <= data_end)
         {
            frame->ip6.proto = opt->nexthdr;

            if (frame->ip6.proto == IPPROTO_ICMPV6)
            {
               struct icmp6hdr *icmp6 = (struct icmp6hdr *)(opt + 1);

               if ((void *)(icmp6 + 1) <= data_end)
               {
                  logIcmp6Frame(icmp6, pkt, data_end);
               }
            }
         }
         break;
      }
      default: break;
   }
}

__attribute__((__always_inline__)) 
static inline void logIp6FrameHeader(struct ipv6hdr *ip6, struct packet *pkt)
{
   struct packet_frame *frame = getFrame(pkt);
   if (!frame) return;
   frame->type = is_ip6_frame;
   frame->ip6.proto = ip6->nexthdr;
   bpf_memcpy(frame->ip6.src, &ip6->saddr, 16);
   bpf_memcpy(frame->ip6.dest, &ip6->daddr, 16);
}

__attribute__((__always_inline__)) 
static inline void logEthFrame(struct ethhdr *eth, struct packet *pkt, void *data_end)
{
   struct packet_frame *frame = getFrame(pkt);
   if (!frame) return;

   frame->type = is_eth_frame;
   frame->eth.proto = eth->h_proto;
   bpf_memcpy(frame->eth.src, eth->h_source, 6);
   bpf_memcpy(frame->eth.dest, eth->h_dest, 6);

   if (eth->h_proto == BE_ETH_P_IPV6) 
   {
      struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);

      if ((void *)(ip6 + 1) <= data_end)
      {
         logIp6Frame(ip6, pkt, data_end);
      }
   }
   else if (eth->h_proto == BE_ETH_P_IP)
   {
      struct iphdr *ip = (struct iphdr *)(eth + 1);

      if ((void *)(ip + 1) <= data_end)
      {
         logIpFrame(ip, pkt, data_end);
      }
   }
}

__attribute__((__always_inline__)) 
static inline void logEthFrameShallow(struct ethhdr *eth, struct packet *pkt, void *data_end)
{
   struct packet_frame *frame = getFrame(pkt);
   if (!frame) return;

   frame->type = is_eth_frame;
   frame->eth.proto = eth->h_proto;
   bpf_memcpy(frame->eth.src, eth->h_source, 6);
   bpf_memcpy(frame->eth.dest, eth->h_dest, 6);

   if (eth->h_proto == BE_ETH_P_IPV6)
   {
      struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);

      if ((void *)(ip6 + 1) <= data_end)
      {
         logIp6FrameHeader(ip6, pkt);
      }
   }
   else if (eth->h_proto == BE_ETH_P_IP)
   {
      struct iphdr *ip = (struct iphdr *)(eth + 1);

      if ((void *)(ip + 1) <= data_end)
      {
         logIpFrameHeader(ip, pkt);
      }
   }
}

__attribute__((__always_inline__)) 
static inline void logPacket(struct ethhdr *eth, void *data_end)
{
   __u32 zeroidx = 0;
   __u32 *count = bpf_map_lookup_elem(&packet_counter_map, &zeroidx);

   __u32 packetIndex = 0;

   if (count)
   {
      packetIndex = *count;
      if (packetIndex > 255) return;
   }

   struct packet *pkt = bpf_map_lookup_elem(&packet_map, &packetIndex);

   if (pkt)
   {
      if (eth && data_end)
      {
         if ((void *)(eth + 1) <= data_end)
         {
            pkt->nFrames = 0;
            pkt->index = packetIndex;
            pkt->redirectIfIdx = 0;
            pkt->checkpoint.len = 0;

            logEthFrame(eth, pkt, data_end);

            bpf_map_update_elem(&packet_map, &packetIndex, pkt, BPF_ANY);

            packetIndex += 1;
            bpf_map_update_elem(&packet_counter_map, &zeroidx, &packetIndex, BPF_ANY);
         }
      }
   }
}

__attribute__((__always_inline__)) 
static inline void logPacketShallow(struct ethhdr *eth, void *data_end)
{
   __u32 zeroidx = 0;
   __u32 *count = bpf_map_lookup_elem(&packet_counter_map, &zeroidx);

   __u32 packetIndex = 0;

   if (count)
   {
      packetIndex = *count;
      if (packetIndex > 255) return;
   }

   struct packet *pkt = bpf_map_lookup_elem(&packet_map, &packetIndex);

   if (pkt)
   {
      if (eth && data_end)
      {
         if ((void *)(eth + 1) <= data_end)
         {
            pkt->nFrames = 0;
            pkt->index = packetIndex;
            pkt->redirectIfIdx = 0;
            pkt->checkpoint.len = 0;

            logEthFrameShallow(eth, pkt, data_end);

            bpf_map_update_elem(&packet_map, &packetIndex, pkt, BPF_ANY);

            packetIndex += 1;
            bpf_map_update_elem(&packet_counter_map, &zeroidx, &packetIndex, BPF_ANY);
         }
      }
   }
}

__attribute__((__always_inline__)) 
static inline void logXDP(struct xdp_md *ctx)
{
   struct ethhdr *eth = NULL;
   void *data_end = NULL;

   if (ctx)
   {
      eth = (struct ethhdr *)(long)ctx->data;
      data_end = (void *)(long)ctx->data_end;
   }

   logPacketShallow(eth, data_end);
}

__attribute__((__always_inline__)) 
static inline void logSKB(struct __sk_buff *skb)
{
   struct ethhdr *eth = NULL;
   void *data_end = NULL;

   if (skb)
   {
      eth = (struct ethhdr *)(long)skb->data;
      data_end = (void *)(long)skb->data_end;
   }

   logPacketShallow(eth, data_end);
}

__attribute__((__always_inline__)) 
static inline struct packet* getPacket(void)
{
   __u32 zeroidx = 0;
   __u32 *count = bpf_map_lookup_elem(&packet_counter_map, &zeroidx);

   if (count)
   {
      if (*count < 256)
      {
         __u32 packetIndex = *count - 1;

         return bpf_map_lookup_elem(&packet_map, &packetIndex);
      }
   }

   return NULL;
}

__attribute__((__always_inline__)) 
static inline void logPacketRedirectIfIdx(__u32 ifidx)
{
   struct packet *pkt = getPacket();

   if (pkt) 
   {
      pkt->redirectIfIdx = ifidx;
   }
}

__attribute__((__always_inline__)) 
static inline void setBufferOnPacket(__u8 *data, __u32 data_len)
{
   if (data_len <= 32)
   {
      struct packet *pkt = getPacket();

      if (pkt) 
      {
         pkt->buffer.len = data_len;
         bpf_memcpy(pkt->buffer.string, data, pkt->buffer.len);
      }
   }
}

__attribute__((__always_inline__)) 
static inline void setCheckpoint(const char *reading)
{
   struct packet *pkt = getPacket();

   if (pkt) 
   {
      pkt->checkpoint.len = 32;
      // pkt->checkpoint.len = sizeof(*value); // this refuses to work so... and somehow this doesn't crash so whatever?
      bpf_memcpy(pkt->checkpoint.string, reading, pkt->checkpoint.len);
   }
}

__attribute__((__always_inline__)) 
static inline int setInstruction(int instruction)
{
   struct packet *pkt = getPacket();

   if (pkt) 
   {
      pkt->instruction = instruction;
   }

   return instruction;
}
