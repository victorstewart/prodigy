#pragma once

__attribute__((__always_inline__)) 
static inline bool parse_tcp(void *data, void *data_end, bool is_ipv6, struct packet_description *pckt) 
{
  	struct tcphdr *tcp = data + calc_offset(is_ipv6);

  	if ((void *)(tcp + 1) > data_end) return false;

  	if (tcp->syn) pckt->flags |= F_SYN_SET;

   pckt->flow.port16[0] = tcp->source;
   pckt->flow.port16[1] = tcp->dest;

  	return true;
}

__attribute__((__always_inline__)) 
static inline bool parse_udp(void *data, void *data_end, bool is_ipv6, struct packet_description *pckt) 
{
  	struct udphdr *udp = data + calc_offset(is_ipv6);

  	if ((void *)(udp + 1) > data_end) return false;

   pckt->flow.port16[0] = udp->source;
   pckt->flow.port16[1] = udp->dest;
  
  	return true;
}
