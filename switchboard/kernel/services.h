#pragma once

__attribute__((__always_inline__)) 
static inline __u64 calc_offset(bool is_ipv6) 
{
	__u64 off = sizeof(struct ethhdr);

  	if (is_ipv6) 
  	{
   	off += sizeof(struct ipv6hdr);
  	} 
  	else 
  	{
    	off += sizeof(struct iphdr);
  	}
  
  	return off;
}