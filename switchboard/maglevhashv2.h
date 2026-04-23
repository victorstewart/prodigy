#pragma once

class MaglevHashV2 {
private:

	static constexpr uint32_t kDefaultChRingSize = 65537;

	struct Endpoint {

		uint32_t num;
	  	uint32_t weight;
	  	uint64_t hash;
	};

	static uint64_t rotl64(uint64_t x, int8_t r) 
	{
  		return (x << r) | (x >> (64 - r));
	}

	static uint64_t MurmurHash3_x64_64(const uint64_t& A, const uint64_t& B, const uint32_t seed) 
	{
		uint64_t h1 = seed;
	  	uint64_t h2 = seed;

	  	uint64_t c1 = 0x87c37b91114253d5llu;
	  	uint64_t c2 = 0x4cf5ad432745937fllu;

	  	//----------
	  	// body

	  	uint64_t k1 = A;
	  	uint64_t k2 = B;

	  	k1 *= c1;
	  	k1 = rotl64(k1, 31);
	  	k1 *= c2;
	  	h1 ^= k1;

	  	h1 = rotl64(h1, 27);
	  	h1 += h2;
	  	h1 = h1 * 5 + 0x52dce729;

	  	k2 *= c2;
	  	k2 = rotl64(k2, 33);
	  	k2 *= c1;
	  	h2 ^= k2;

	  	h2 = rotl64(h2, 31);
	  	h2 += h1;
	  	h2 = h2 * 5 + 0x38495ab5;

	  	//----------
	  	// finalization

	  	h1 ^= 16;
	  	h2 ^= 16;

	  	h1 += h2;
	  	h2 += h1;

	  	h1 ^= h1 >> 33;
	  	h1 *= 0xff51afd7ed558ccdllu;
	  	h1 ^= h1 >> 33;
	  	h1 *= 0xc4ceb9fe1a85ec53llu;
	  	h1 ^= h1 >> 33;

	  	h2 ^= h2 >> 33;
	  	h2 *= 0xff51afd7ed558ccdllu;
	  	h2 ^= h2 >> 33;
	  	h2 *= 0xc4ceb9fe1a85ec53llu;
	  	h2 ^= h2 >> 33;

	  	h1 += h2;

	  	return h1;
	}

	static void genMaglevPermutation(std::vector<uint32_t>& permutation, const Endpoint& endpoint, const uint32_t pos, const uint32_t ring_size) 
	{
		constexpr uint32_t kHashSeed0 = 0;
		constexpr uint32_t kHashSeed1 = 2307;
		constexpr uint32_t kHashSeed2 = 42;
		constexpr uint32_t kHashSeed3 = 2718281828;

  		auto offset_hash = MurmurHash3_x64_64(endpoint.hash, kHashSeed2, kHashSeed0);

  		auto offset = offset_hash % ring_size;

  		auto skip_hash = MurmurHash3_x64_64(endpoint.hash, kHashSeed3, kHashSeed1);

  		auto skip = (skip_hash % (ring_size - 1)) + 1;

  		permutation[2 * pos] = offset;
  		permutation[2 * pos + 1] = skip;
	}

	static std::array<uint32_t, RING_SIZE> generateHashRingForEndpoints(const std::vector<Endpoint>& endpoints)
	{
		std::array<uint32_t, RING_SIZE> ring;
		ring.fill(0);

		uint64_t highestWeight = 1;
		for (const Endpoint& endpoint : endpoints)
		{
			if (endpoint.weight > highestWeight) highestWeight = endpoint.weight;
		}

		uint32_t runs = 0;
  		std::vector<uint32_t> permutation(endpoints.size() * 2, 0);
  		std::vector<uint32_t> next(endpoints.size(), 0);
  		std::vector<uint64_t> cum_weight(endpoints.size(), 0);

  		for (uint32_t pos = 0; pos < endpoints.size(); pos++)
  		{
    		genMaglevPermutation(permutation, endpoints[pos], pos, RING_SIZE);
  		}

  		for (;;) 
  		{
    		for (uint32_t pos = 0; pos < endpoints.size(); pos++)
    		{
    			const Endpoint& endpoint = endpoints[pos];

      		cum_weight[pos] += endpoint.weight;

      		if (cum_weight[pos] >= highestWeight) // so with all weights equal this always triggers on the first endpoint
      		{
        			cum_weight[pos] -= highestWeight;
        			auto offset = permutation[2 * pos]; // and positiont here always 0
        			auto skip = permutation[2 * pos + 1];
        			auto cur = (offset + next[pos] * skip) % RING_SIZE;
        			
        			while (ring[cur] > 0) // we switch the terminal factor to 0, because that's our never value
        			{
          			next[pos] += 1;
          			cur = (offset + next[pos] * skip) % RING_SIZE;
        			}
        		
        			ring[cur] = endpoint.num;
        			next[pos] += 1;
        			runs++;

        			if (runs == RING_SIZE) return ring;
      		}
    		}
  		}

  		return ring;
	}	

public:

	static std::array<uint32_t, RING_SIZE> generateHashRingForPortal(Portal *portal)
	{
		std::vector<Endpoint> endpoints;

		for (const auto *wormhole : portal->wormholes)
		{
			Endpoint& endpoint = endpoints.emplace_back();
			endpoint.num = wormhole->containerID; // 4 least signifcant bytes of container ULA address in network byte order
			endpoint.weight = wormhole->weight > 0 ? wormhole->weight : 1;
			endpoint.hash = wormhole->hash();
		}

		return generateHashRingForEndpoints(endpoints);
	}
};
