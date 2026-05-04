#include <arpa/inet.h>

#pragma once

class MeshNode {
public:

	int32_t remainingSubscriberCapacity; // prediction based on subscriber count and normalized stress
	uint16_t applicationID; // to provide cross application exclusion when needed

	bytell_hash_subset<uint64_t, MeshNode *> subscribedTo;
	bytell_hash_subset<uint64_t, MeshNode *> advertisingTo;

	bytell_hash_map<uint64_t, Subscription> subscriptions;
   bytell_hash_map<uint64_t, Advertisement> advertisements;

	uint128_t meshAddress; // container-network IPv6, used for all subscriptions and advertisements

	void setMeshAddress(const struct container_network_subnet6_prefix& subnet, uint8_t datacenterFragment, uint32_t machineFragment, uint8_t containerFragment)
	{
		// Assemble IPv6 address bytes: 11-byte container-network prefix, 1-byte datacenter fragment,
		// 3-byte machine fragment, 1-byte container fragment.
		uint8_t *p = reinterpret_cast<uint8_t *>(&meshAddress);
		memcpy(p + 0, subnet.value, 11);
		p[11] = datacenterFragment;
		p[12] = static_cast<uint8_t>((machineFragment >> 16) & 0xFF);
		p[13] = static_cast<uint8_t>((machineFragment >> 8) & 0xFF);
		p[14] = static_cast<uint8_t>(machineFragment & 0xFF);
		p[15] = containerFragment;
	}

	virtual uint128_t pairingAddress(void) const
	{
		return meshAddress;
	}

	virtual void advertisementPairing(uint128_t secret, uint128_t address, uint64_t service, uint16_t applicationID, bool activate) = 0; // sent to advertiser
	virtual void subscriptionPairing(uint128_t secret, uint128_t address, uint64_t service, uint16_t port, uint16_t applicationID, bool activate) = 0; // sent to subscriber
};
