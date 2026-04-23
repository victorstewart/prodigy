#pragma once

#include <switchboard/common/local_container_subnet.h>

struct {
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __type(key, __u32); 		// local machines are assigned a /120, so 1 byte variable.. aka 256 possible container addresses
   __type(value, __u32);	// ifidx of container's host side primary netkit device
   __uint(max_entries, 256); 
} container_device_map SEC(".maps");

__attribute__((__always_inline__)) 
static inline bool localSubnetContainsDaddr(__be8 *addr6)
{
	__u32 zeroidx = 0;
   struct local_container_subnet6 *localsubnet6 = bpf_map_lookup_elem(&local_container_subnet_map, &zeroidx);

   if (localsubnet6)
   {
   	return switchboardContainerIPv6TargetsLocalMachine(addr6, localsubnet6);
   }

   return false;
}

__attribute__((__always_inline__)) 
static inline int redirectToContainer(__be8 *addr6, bool is_ingress) // addr6 is the entire ipv6 destination address of the packet
{
	__u32 container_index = addr6[15]; // this effectively becomes little endian.. but as long as we submit ours in userspace in little endian also then it's fine

	struct packet *pkt = getPacket();
   if (pkt) pkt->containerID.value[4] = container_index; // obviously we left the local subnet bytes 0 here

	__u32 *primary_device_idx = bpf_map_lookup_elem(&container_device_map, &container_index); // look up container's primary netkit device for this address

	if (primary_device_idx) // host-side primary netkit device for the destination container
	{
		logPacketRedirectIfIdx(*primary_device_idx);

		if (is_ingress) // redirecting from host NIC into the host-side primary netkit hook
		{
			return setInstruction(bpf_redirect(*primary_device_idx, 0));
		}
		else // redirecting from a container toward another container
		{
			// From container egress, forward toward the destination host-side primary
			// netkit device so the receiving container's primary hook owns ingress.
			return setInstruction(bpf_redirect(*primary_device_idx, 0));
		}
	}
	// Fail closed when the destination fragment has no subscribed container device.
	// Containers always live in private network namespaces, so there is no
	// host-stack fallback for container-subnet addresses.

	return NETKIT_DROP;
}

__attribute__((__always_inline__)) 
static inline bool isULA(__be8 *addr6)
{
	return (addr6[0] == 0xfd);
}

__attribute__((__always_inline__)) 
static inline bool isMulticast(__be8 *addr6)
{
	return (addr6[0] == 0xff);
}

__attribute__((__always_inline__))
static inline int redirectL2ToNIC(struct __sk_buff *skb, struct ethhdr *eth)
{
	setCheckpoint("redirectToNIC: checkpoint 1");

	__u32 zeroidx = 0; // NIC is container 0, unused address
	__u32 *nic_idx = bpf_map_lookup_elem(&container_device_map, &zeroidx); // look up container's primary netkit device for this address

	if (!nic_idx) return NETKIT_DROP;

	setCheckpoint("redirectToNIC: checkpoint 2");

	if (from_us_to_gateway(eth) == false) return NETKIT_DROP;

	setCheckpoint("redirectToNIC: checkpoint 3");
	logSKB(skb);

	return bpf_redirect(*nic_idx, 0);
}

__attribute__((__always_inline__))
static inline int redirectL3ToNIC(struct __sk_buff *skb, __be16 protocol)
{
	setCheckpoint("redirectToNIC: checkpoint 1");

	__u32 zeroidx = 0; // NIC is container 0, unused address
	__u32 *nic_idx = bpf_map_lookup_elem(&container_device_map, &zeroidx);
	if (!nic_idx) return NETKIT_DROP;

	setCheckpoint("redirectToNIC: checkpoint 2");

	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = (struct ethhdr *)(long)skb->data;
	if ((void *)(eth + 1) > data_end) return NETKIT_DROP;

	// NETKIT_L3 skbs already expose an ETH_HLEN placeholder with h_proto set.
	// Prepending another Ethernet header leaves a stale placeholder between the
	// rewritten L2 header and the IP packet on NIC egress.
	if (from_us_to_gateway(eth) == false) return NETKIT_DROP;

	eth->h_proto = protocol;

	setCheckpoint("redirectToNIC: checkpoint 3");
	logPacketRedirectIfIdx(*nic_idx);
	logSKB(skb);

	return setInstruction(bpf_redirect(*nic_idx, 0));
}
