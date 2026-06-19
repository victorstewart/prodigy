#pragma once

struct switchboard_l4_ports {
  __be16 source;
  __be16 dest;
  __u32 checksumOffset;
  bool udpChecksumPresent;
};

__attribute__((__always_inline__)) static inline bool switchboard_parse_l4_ports(void *l4, void *data_end, __u8 proto, __u32 l4Offset, struct switchboard_l4_ports *ports)
{
  if (ports == NULL)
  {
    return false;
  }
  ports->source = 0;
  ports->dest = 0;
  ports->checksumOffset = 0;
  ports->udpChecksumPresent = true;

  if (proto == IPPROTO_TCP)
  {
    struct tcphdr *tcp = l4;
    if ((void *)(tcp + 1) > data_end)
    {
      return false;
    }
    ports->source = tcp->source;
    ports->dest = tcp->dest;
    ports->checksumOffset = l4Offset + __builtin_offsetof(struct tcphdr, check);
    return true;
  }
  if (proto == IPPROTO_UDP)
  {
    struct udphdr *udp = l4;
    if ((void *)(udp + 1) > data_end)
    {
      return false;
    }
    ports->source = udp->source;
    ports->dest = udp->dest;
    ports->checksumOffset = l4Offset + __builtin_offsetof(struct udphdr, check);
    ports->udpChecksumPresent = (udp->check != 0);
    return true;
  }
  return false;
}
