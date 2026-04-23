#pragma once

#include <array>
#include <bit>
#include <cstdint>
#include <queue>

class Mesh {
private:

	struct ServicePairing {

		MeshNode *advertiser;
		MeshNode *subscriber;
		uint64_t service;

		struct Material
		{
			std::uintptr_t advertiser;
			std::uintptr_t subscriber;
			uint64_t service;
		};

		ServicePairing(MeshNode *_advertiser, MeshNode *_subscriber, uint64_t _service) noexcept : advertiser(_advertiser), subscriber(_subscriber), service(_service) {}

		uint64_t hash(void) const noexcept
		{
			Material material {
				reinterpret_cast<std::uintptr_t>(advertiser),
				reinterpret_cast<std::uintptr_t>(subscriber),
				service
			};

			auto words = std::bit_cast<std::array<uint64_t, 3>>(material);
			return Hasher::hash<Hasher::SeedPolicy::thread_shared>(reinterpret_cast<const uint8_t *>(words.data()), sizeof(words));
		}

		bool equals(const ServicePairing &other) const noexcept
		{
			return (advertiser == other.advertiser && subscriber == other.subscriber && service == other.service);
		}
	};

	struct PairingState
	{
		uint128_t secret = 0;
		uint16_t advertiserPort = 0;
	};

	cppsort::verge_adapter<cppsort::ska_sorter> sorter;

	// Max-heap entry for 'any' advertisers per service
	struct AnyEntry {

		int32_t capacity;
		MeshNode *node;

		AnyEntry(int32_t c, MeshNode *n) : capacity(c), node(n) {}
	};

	struct AnyCmp {

		bool operator()(const AnyEntry &a, const AnyEntry &b) const
		{
			if (a.capacity != b.capacity) return a.capacity < b.capacity; // max-heap by capacity
			return a.node < b.node;
		}
	};

	// Min/max-heap entry for 'some' subscribers per service
	struct SomeEntry {

		uint32_t count;
		MeshNode *node;
		uint32_t epoch;

		SomeEntry(uint32_t c, MeshNode *n, uint32_t e) : count(c), node(n), epoch(e) {}
	};

	struct SomeCmp {

		bool operator()(const SomeEntry &a, const SomeEntry &b) const
		{
			if (a.count != b.count) return a.count > b.count; // min-heap by count
			if (a.epoch != b.epoch) return a.epoch < b.epoch; // prefer latest epoch
			return a.node > b.node;
		}
	};

	struct SomeMaxCmp {

		bool operator()(const SomeEntry &a, const SomeEntry &b) const
		{
			if (a.count != b.count) return a.count < b.count; // max-heap by count
			if (a.epoch != b.epoch) return a.epoch < b.epoch;
			return a.node < b.node;
		}
	};

	alignas(64) bytell_hash_subset<uint64_t, MeshNode *> 	  anySubscribers;
	alignas(64) bytell_hash_subvector<uint64_t, MeshNode *> someSubscribers; // vector so we can sort them
	alignas(64) bytell_hash_subset<uint64_t, MeshNode *> 	  allSubscribers;

	alignas(64) bytell_hash_map<ServicePairing, PairingState> pairingSecrets;

	alignas(64) bytell_hash_subvector<uint64_t, MeshNode *> advertising;

	// Per-service count of 'any' subscribers per advertiser to avoid repeated scans
	alignas(64) bytell_hash_map<uint64_t, bytell_hash_map<MeshNode *, uint32_t>> anyCounts;
	alignas(64) bytell_hash_map<uint64_t, std::priority_queue<AnyEntry, Vector<AnyEntry>, AnyCmp>> anyMaxHeaps;

	// Per-service count of 'some' subscriptions per subscriber and a lazy min-heap to pick least loaded
	alignas(64) bytell_hash_map<uint64_t, bytell_hash_map<MeshNode *, uint32_t>> someCounts;
	alignas(64) bytell_hash_map<uint64_t, std::priority_queue<SomeEntry, Vector<SomeEntry>, SomeCmp>> someMinHeaps;
	alignas(64) bytell_hash_map<uint64_t, std::priority_queue<SomeEntry, Vector<SomeEntry>, SomeMaxCmp>> someMaxHeaps;
	alignas(64) bytell_hash_map<uint64_t, uint32_t> someHeapEpochs;

	static bool vectorHasNode(const Vector<MeshNode *>& nodes, MeshNode *node)
	{
		for (MeshNode *entry : nodes)
		{
			if (entry == node)
			{
				return true;
			}
		}

		return false;
	}

	bool someHasSubscriber(uint64_t service, MeshNode *subscriber)
	{
		auto it = someSubscribers.find(service);
		if (it == someSubscribers.end())
		{
			return false;
		}

		return vectorHasNode(it->second, subscriber);
	}

	void someEraseSubscriberAll(uint64_t service, MeshNode *subscriber)
	{
		while (someSubscribers.eraseEntry(service, subscriber)) {}
	}

	uint16_t advertiserPortOrZero(MeshNode *advertiser, uint64_t service)
	{
		auto it = advertiser->advertisements.find(service);
		if (it == advertiser->advertisements.end())
		{
			return 0;
		}

		return it->second.port;
	}

	int32_t advertiserRemainingCapacityForService(MeshNode *advertiser, uint64_t service)
	{
		if (advertiser == nullptr)
		{
			return 0;
		}

		auto advertisementIt = advertiser->advertisements.find(service);
		if (advertisementIt == advertiser->advertisements.end())
		{
			return advertiser->remainingSubscriberCapacity;
		}

		const ServiceUserCapacity& userCapacity = advertisementIt->second.userCapacity;
		if (userCapacity.minimum == 0 && userCapacity.maximum == 0)
		{
			return advertiser->remainingSubscriberCapacity;
		}

		uint32_t plannedCapacity = serviceUserCapacityPlanningWeight(userCapacity);
		uint32_t currentUsers = advertiser->advertisingTo.countEntriesFor(service);
		int64_t remaining = int64_t(plannedCapacity) - int64_t(currentUsers);
		if (remaining > INT32_MAX) return INT32_MAX;
		if (remaining < INT32_MIN) return INT32_MIN;
		return int32_t(remaining);
	}

	template <typename Fn>
	void forEachAdvertiserForSubscription(uint64_t subscriptionService, Fn&& fn)
	{
		if (MeshServices::isPrefix(subscriptionService))
		{
			for (const auto& [advertisedService, advertisers] : advertising)
			{
				if (MeshRegistry::prefixContains(subscriptionService, advertisedService) == false)
				{
					continue;
				}

				for (MeshNode *advertiser : advertisers)
				{
					fn(advertisedService, advertiser);
				}
			}

			return;
		}

		if (auto it = advertising.find(subscriptionService); it != advertising.end())
		{
			for (MeshNode *advertiser : it->second)
			{
				fn(subscriptionService, advertiser);
			}
		}
	}

	uint32_t subscriberPairingCountForService(MeshNode *subscriber, uint64_t subscriptionService)
	{
		if (MeshServices::isPrefix(subscriptionService) == false)
		{
			return subscriber->subscribedTo.countEntriesFor(subscriptionService);
		}

		uint32_t count = 0;
		for (const auto& [pairedService, advertisers] : subscriber->subscribedTo)
		{
			if (MeshRegistry::prefixContains(subscriptionService, pairedService))
			{
				count += uint32_t(advertisers.size());
			}
		}

		return count;
	}

	bool pickBestAnyAdvertiser(uint64_t subscriptionService, MeshNode *subscriber, uint64_t& selectedService, MeshNode *&selectedAdvertiser)
	{
		selectedService = 0;
		selectedAdvertiser = nullptr;

		bool found = false;
		int32_t bestCapacity = 0;

		forEachAdvertiserForSubscription(subscriptionService, [&] (uint64_t matchedService, MeshNode *candidate) -> void {
			if (candidate == subscriber)
			{
				return;
			}

			int32_t capacity = advertiserRemainingCapacityForService(candidate, matchedService);
			if (found == false || capacity > bestCapacity || (capacity == bestCapacity && candidate < selectedAdvertiser))
			{
				selectedService = matchedService;
				selectedAdvertiser = candidate;
				bestCapacity = capacity;
				found = true;
			}
		});

		return found;
	}

	uint64_t subscriptionServiceForPairing(MeshNode *subscriber, uint64_t pairingService)
	{
		if (subscriber->subscriptions.find(pairingService) != subscriber->subscriptions.end())
		{
			return pairingService;
		}

		if (MeshServices::isShard(pairingService))
		{
			uint64_t prefixService = MeshServices::convertShardToPrefix(pairingService);
			if (subscriber->subscriptions.find(prefixService) != subscriber->subscriptions.end())
			{
				return prefixService;
			}
		}

		return 0;
	}

	Vector<uint64_t> pairedServicesForSubscription(MeshNode *subscriber, uint64_t subscriptionService)
	{
		Vector<uint64_t> pairedServices;

		if (MeshServices::isPrefix(subscriptionService) == false)
		{
			if (subscriber->subscribedTo.countEntriesFor(subscriptionService) > 0)
			{
				pairedServices.push_back(subscriptionService);
			}

			return pairedServices;
		}

		for (const auto& [pairedService, advertisers] : subscriber->subscribedTo)
		{
			(void)advertisers;
			if (MeshRegistry::prefixContains(subscriptionService, pairedService))
			{
				pairedServices.push_back(pairedService);
			}
		}

		return pairedServices;
	}

	void someIncrement(uint64_t service, MeshNode *subscriber)
	{
		auto &map = someCounts[service];
		uint32_t cnt = 0;
		if (auto it = map.find(subscriber); it != map.end())
		{
			cnt = it->second;
		}
		cnt += 1;
		map.insert_or_assign(subscriber, cnt);
		pushSomeEntry(service, subscriber, cnt);
		enforceSomeHeapBudget(service);
	}

	void someDecrement(uint64_t service, MeshNode *subscriber)
	{
		auto sit = someCounts.find(service);
		if (sit == someCounts.end()) return;
		auto &map = sit->second;
		auto it = map.find(subscriber);
		if (it == map.end()) return;
		uint32_t cnt = (it->second > 0 ? (it->second - 1) : 0);
		map.insert_or_assign(subscriber, cnt);
		pushSomeEntry(service, subscriber, cnt);
		enforceSomeHeapBudget(service);
	}

	void noteAnyCapacity(uint64_t service, MeshNode *advertiser)
	{
		if (!advertising.hasEntryFor(service, advertiser))
		{
			return;
		}
		anyMaxHeaps[service].emplace(advertiserRemainingCapacityForService(advertiser, service), advertiser);
	}

	void pushSomeEntry(uint64_t service, MeshNode *subscriber, uint32_t count)
	{
		uint32_t epoch = someHeapEpochs[service];
		someMinHeaps[service].emplace(count, subscriber, epoch);
		someMaxHeaps[service].emplace(count, subscriber, epoch);
	}

	void rebuildSomeHeaps(uint64_t service)
	{
		auto sit = someCounts.find(service);
		if (sit == someCounts.end())
		{
			someMinHeaps.erase(service);
			someMaxHeaps.erase(service);
			someHeapEpochs.erase(service);
			return;
		}

		uint32_t epoch = ++someHeapEpochs[service];
		std::priority_queue<SomeEntry, Vector<SomeEntry>, SomeCmp> minHeap;
		std::priority_queue<SomeEntry, Vector<SomeEntry>, SomeMaxCmp> maxHeap;

		for (const auto &kv : sit->second)
		{
			MeshNode *node = kv.first;
			uint32_t count = kv.second;
			minHeap.emplace(count, node, epoch);
			maxHeap.emplace(count, node, epoch);
		}

		someMinHeaps[service].swap(minHeap);
		someMaxHeaps[service].swap(maxHeap);
	}

	void enforceSomeHeapBudget(uint64_t service)
	{
		auto sit = someCounts.find(service);
		if (sit == someCounts.end())
		{
			return;
		}

		size_t active = sit->second.size();
		if (active == 0)
		{
			rebuildSomeHeaps(service);
			return;
		}

		size_t limit = active * 4;
		auto mit = someMinHeaps.find(service);
		auto xit = someMaxHeaps.find(service);
		size_t minSize = (mit != someMinHeaps.end()) ? mit->second.size() : 0;
		size_t maxSize = (xit != someMaxHeaps.end()) ? xit->second.size() : 0;
		if (minSize > limit || maxSize > limit)
		{
			rebuildSomeHeaps(service);
		}
	}

	MeshNode * pickBestAny(uint64_t service)
	{
		auto hit = anyMaxHeaps.find(service);
		if (hit == anyMaxHeaps.end()) return nullptr;
		auto &heap = hit->second;
		while (!heap.empty())
		{
			AnyEntry top = heap.top();
			if (!advertising.hasEntryFor(service, top.node))
			{
				heap.pop();
				continue;
			}
			int32_t current = advertiserRemainingCapacityForService(top.node, service);
			if (top.capacity != current)
			{
				heap.pop();
				heap.emplace(current, top.node);
				continue;
			}
			return top.node;
		}
		return nullptr;
	}

	void pairUnpairedAnySubscribers(uint64_t service)
	{
		auto subsIt = anySubscribers.find(service);
		if (subsIt == anySubscribers.end()) return;

		for (MeshNode *subscriber : subsIt->second)
		{
			if (subscriber == nullptr) continue;
			if (subscriberPairingCountForService(subscriber, service) > 0) continue;

			uint64_t matchedService = 0;
			MeshNode *best = nullptr;
			bool hasBest = pickBestAnyAdvertiser(service, subscriber, matchedService, best);
			if (hasBest == false)
			{
				continue;
			}
			if (best == nullptr) continue;

			createPairing(best, subscriber, matchedService, true /* notifyAdvertiser */, true /* notifySubscriber */);
		}
	}

	MeshNode * pickLeastLoadedSome(uint64_t service)
	{
		auto hit = someMinHeaps.find(service);
		if (hit == someMinHeaps.end()) return nullptr;
		auto &heap = hit->second;
		auto sit = someCounts.find(service);
		if (sit == someCounts.end()) return nullptr;
		auto &map = sit->second;
		uint32_t epoch = someHeapEpochs[service];
		while (!heap.empty())
		{
			SomeEntry top = heap.top();
			if (top.epoch != epoch)
			{
				heap.pop();
				continue;
			}
			auto it = map.find(top.node);
			if (it != map.end() && it->second == top.count)
			{
				return top.node;
			}
			heap.pop();
		}
		return nullptr;
	}

	MeshNode * pickMostLoadedSome(uint64_t service)
	{
		auto hit = someMaxHeaps.find(service);
		if (hit == someMaxHeaps.end()) return nullptr;
		auto &heap = hit->second;
		auto sit = someCounts.find(service);
		if (sit == someCounts.end()) return nullptr;
		auto &map = sit->second;
		uint32_t epoch = someHeapEpochs[service];
		while (!heap.empty())
		{
			SomeEntry top = heap.top();
			if (top.epoch != epoch)
			{
				heap.pop();
				continue;
			}
			auto it = map.find(top.node);
			if (it != map.end() && it->second == top.count)
			{
				return top.node;
			}
			heap.pop();
		}
		return nullptr;
	}

	// Rebuild per-service 'any' subscriber counts from current pairingSecrets snapshot.
		void rebuildAnyCounts(void)
		{
			anyCounts.clear();
		for (const auto& kv : pairingSecrets)
		{
			const ServicePairing &sp = kv.first;
			MeshNode *adv = sp.advertiser;
			MeshNode *sub = sp.subscriber;
			uint64_t service = sp.service;
			uint64_t subscriptionService = subscriptionServiceForPairing(sub, service);
			if (subscriptionService == 0)
			{
				continue;
			}

			auto it = sub->subscriptions.find(subscriptionService);
			if (it != sub->subscriptions.end() && it->second.nature == SubscriptionNature::any)
			{
				anyCounts[subscriptionService][adv] += 1;
			}
		}
	}

	void createPairing(MeshNode *advertiser, MeshNode *subscriber, uint64_t service, bool notifyAdvertiser, bool notifySubscriber)
	{	
		if (advertiser == subscriber)
		{
			return;
		}

		if (auto existing = pairingSecrets.find(ServicePairing{advertiser, subscriber, service}); existing != pairingSecrets.end())
		{
			uint128_t secret = existing->second.secret;
			uint16_t advertiserPort = advertiserPortOrZero(advertiser, service);
			if (advertiserPort != 0)
			{
				existing->second.advertiserPort = advertiserPort;
			}
			else
			{
				advertiserPort = existing->second.advertiserPort;
			}
			bool hadAdvertiserEdge = advertiser->advertisingTo.hasEntryFor(service, subscriber);
			bool hadSubscriberEdge = subscriber->subscribedTo.hasEntryFor(service, advertiser);
			if (hadAdvertiserEdge == false) advertiser->advertisingTo.insert(service, subscriber);
			if (hadSubscriberEdge == false) subscriber->subscribedTo.insert(service, advertiser);
			if (notifyAdvertiser && hadAdvertiserEdge == false) advertiser->advertisementPairing(secret, subscriber->pairingAddress(), service, subscriber->applicationID, true);
			if (notifySubscriber && hadSubscriberEdge == false) subscriber->subscriptionPairing(secret, advertiser->pairingAddress(), service, advertiserPort, advertiser->applicationID, true);
			return;
		}

		// the orchestrator will always take action to ensure capacity is scaled such that this never happens. but if it ever did just let it go negative temporarily
		--advertiser->remainingSubscriberCapacity;

		uint128_t secret = Random::generateNumberWithNBits<128, uint128_t>();
		uint16_t advertiserPort = advertiserPortOrZero(advertiser, service);
		pairingSecrets.insert_or_assign(ServicePairing{advertiser, subscriber, service}, PairingState{secret, advertiserPort});

		advertiser->advertisingTo.insert(service, subscriber);
			// secret(16) address(16) service(8) activate(1)
		if (notifyAdvertiser) advertiser->advertisementPairing(secret, subscriber->pairingAddress(), service, subscriber->applicationID, true);


		subscriber->subscribedTo.insert(service, advertiser);
			// secret(16) address(16) service(8) port(2) activate(1)
		if (notifySubscriber) subscriber->subscriptionPairing(secret, advertiser->pairingAddress(), service, advertiserPort, advertiser->applicationID, true);

		// Track 'any' counts incrementally to avoid counting scans during rebalances
		uint64_t subscriptionService = subscriptionServiceForPairing(subscriber, service);
		if (subscriptionService != 0)
		{
			auto it = subscriber->subscriptions.find(subscriptionService);
			if (it->second.nature == SubscriptionNature::any)
			{
				anyCounts[subscriptionService][advertiser] += 1;
			}
			else if (it->second.nature == SubscriptionNature::exclusiveSome)
			{
				someIncrement(subscriptionService, subscriber);
			}
		}

		noteAnyCapacity(service, advertiser);
	}

	static void traceDestroyPairing(
		const char *reason,
		MeshNode *advertiser,
		MeshNode *subscriber,
		uint64_t service,
		uint128_t secret,
		uint16_t advertiserPort,
		bool notifyAdvertiser,
		bool notifySubscriber,
		bool eraseFromAdvertiser,
		bool eraseFromSubscriber)
	{
		basics_log(
			"mesh destroyPairing reason=%s service=%llu advertiser=%p advertiserApp=%u subscriber=%p subscriberApp=%u port=%u notifyAdvertiser=%d notifySubscriber=%d eraseFromAdvertiser=%d eraseFromSubscriber=%d secretLo=%llu secretHi=%llu\n",
			(reason ? reason : "unspecified"),
			(unsigned long long)service,
			static_cast<void *>(advertiser),
			unsigned(advertiser ? advertiser->applicationID : 0),
			static_cast<void *>(subscriber),
			unsigned(subscriber ? subscriber->applicationID : 0),
			unsigned(advertiserPort),
			int(notifyAdvertiser),
			int(notifySubscriber),
			int(eraseFromAdvertiser),
			int(eraseFromSubscriber),
			(unsigned long long)uint64_t(secret),
			(unsigned long long)uint64_t(secret >> 64));
		std::fprintf(stderr,
			"mesh destroyPairing reason=%s service=%llu advertiser=%p advertiserApp=%u subscriber=%p subscriberApp=%u port=%u notifyAdvertiser=%d notifySubscriber=%d eraseFromAdvertiser=%d eraseFromSubscriber=%d secretLo=%llu secretHi=%llu\n",
			(reason ? reason : "unspecified"),
			(unsigned long long)service,
			static_cast<void *>(advertiser),
			unsigned(advertiser ? advertiser->applicationID : 0),
			static_cast<void *>(subscriber),
			unsigned(subscriber ? subscriber->applicationID : 0),
			unsigned(advertiserPort),
			int(notifyAdvertiser),
			int(notifySubscriber),
			int(eraseFromAdvertiser),
			int(eraseFromSubscriber),
			(unsigned long long)uint64_t(secret),
			(unsigned long long)uint64_t(secret >> 64));
		std::fflush(stderr);
	}

	void destroyPairing(const char *reason, MeshNode *advertiser, MeshNode *subscriber, uint64_t service, bool notifyAdvertiser, bool notifySubscriber, bool eraseFromAdvertiser, bool eraseFromSubscriber)
	{
		auto pairingIt = pairingSecrets.find(ServicePairing{advertiser, subscriber, service});

		if (pairingIt == pairingSecrets.end())
		{
			// No active pairing; nothing to do
			return;
		}

		++advertiser->remainingSubscriberCapacity;

		uint128_t oldSecret = pairingIt->second.secret;
		uint16_t advertiserPort = pairingIt->second.advertiserPort;
		traceDestroyPairing(reason, advertiser, subscriber, service, oldSecret, advertiserPort, notifyAdvertiser, notifySubscriber, eraseFromAdvertiser, eraseFromSubscriber);

		pairingSecrets.erase(pairingIt);

		if (eraseFromAdvertiser) advertiser->advertisingTo.eraseEntry(service, subscriber);
			// secret(16) service(8) activate(1)
		if (notifyAdvertiser) advertiser->advertisementPairing(oldSecret, subscriber->pairingAddress(), service, subscriber->applicationID, false);

		
		if (eraseFromSubscriber) subscriber->subscribedTo.eraseEntry(service, advertiser);
			// secret(16) address(16) service(8) port(2) activate(1)
		if (notifySubscriber) subscriber->subscriptionPairing(oldSecret, advertiser->pairingAddress(), service, advertiserPort, advertiser->applicationID, false);

		// Track 'any' counts decrementally
		uint64_t subscriptionService = subscriptionServiceForPairing(subscriber, service);
		if (subscriptionService != 0)
		{
			auto it = subscriber->subscriptions.find(subscriptionService);
			if (it->second.nature == SubscriptionNature::any)
			{
				auto &svcMap = anyCounts[subscriptionService];
				auto acIt = svcMap.find(advertiser);
				if (acIt != svcMap.end())
				{
					if (acIt->second > 0) acIt->second -= 1;
					if (acIt->second == 0) svcMap.erase(acIt);
				}
			}
			else if (it->second.nature == SubscriptionNature::exclusiveSome)
			{
				someDecrement(subscriptionService, subscriber);
			}
		}

		noteAnyCapacity(service, advertiser);
	}

	struct BootingPairing {

		MeshNode *advertiser;
		MeshNode *subscriber;

		uint64_t service;
		uint128_t subscriberAddress;
		uint128_t advertiserAddress;
		uint16_t advertisingPort;

		BootingPairing(MeshNode *_advertiser, MeshNode * _subscriber, uint64_t _service) : advertiser(_advertiser), subscriber(_subscriber), service(_service) {}
		BootingPairing() = default;
	};

	bytell_hash_map<uint128_t, BootingPairing> bootingPairings; // gathering these when a new brain feeds on neurons

	void logPairing(uint128_t secret, MeshNode *advertiser, const AdvertisementPairing *advertisement, MeshNode *subscriber, const SubscriptionPairing *subscription)
	{
		BootingPairing& pairing = bootingPairings[secret];

		if (advertiser)
		{
			pairing.advertiser = advertiser;
			if (advertisement)
			{
				pairing.service = advertisement->service;
				pairing.subscriberAddress = advertisement->address;
			}
		}

		if (subscriber)
		{
			pairing.subscriber = subscriber;
			if (subscription)
			{
				if (!advertisement)
				{
					pairing.service = subscription->service;
				}
				pairing.advertiserAddress = subscription->address;
				pairing.advertisingPort = subscription->port;
			}
		}
	}

public:

	uint128_t pairingSecretFor(MeshNode *advertiser, MeshNode *subscriber, uint64_t service)
	{
		if (auto it = pairingSecrets.find(ServicePairing{advertiser, subscriber, service}); it != pairingSecrets.end())
		{
			return it->second.secret;
		}

		return 0;
	}

	void logAdvertisementPairing(uint128_t secret, MeshNode *advertiser, const AdvertisementPairing& pairing)
	{
		logPairing(secret, advertiser, &pairing, nullptr, nullptr);
	}

	void logSubscriptionPairing(uint128_t secret, MeshNode *subscriber, const SubscriptionPairing& pairing)
	{
		logPairing(secret, nullptr, nullptr, subscriber, &pairing);
	}

	void unifyPairingHalves(void) // when brain feeds on all neurons to reconstruct the mesh
	{
		for (auto& [secret, pairing] : bootingPairings)
		{
			if (!pairing.advertiser || !pairing.subscriber) // one or both halves is broken
			{
				if (pairing.advertiser && !pairing.subscriber)
				{
					basics_log(
						"mesh brokenHalfRecovery reason=advertiser-without-subscriber service=%llu advertiser=%p advertiserApp=%u secretLo=%llu secretHi=%llu\n",
						(unsigned long long)pairing.service,
						static_cast<void *>(pairing.advertiser),
						unsigned(pairing.advertiser->applicationID),
						(unsigned long long)uint64_t(secret),
						(unsigned long long)uint64_t(secret >> 64));
					std::fprintf(stderr,
						"mesh brokenHalfRecovery reason=advertiser-without-subscriber service=%llu advertiser=%p advertiserApp=%u secretLo=%llu secretHi=%llu\n",
						(unsigned long long)pairing.service,
						static_cast<void *>(pairing.advertiser),
						unsigned(pairing.advertiser->applicationID),
						(unsigned long long)uint64_t(secret),
						(unsigned long long)uint64_t(secret >> 64));
					std::fflush(stderr);
					pairing.advertiser->advertisementPairing(secret, pairing.subscriberAddress, pairing.service, pairing.advertiser->applicationID, false);
				}

				if (pairing.subscriber && !pairing.advertiser)
				{
					basics_log(
						"mesh brokenHalfRecovery reason=subscriber-without-advertiser service=%llu subscriber=%p subscriberApp=%u port=%u secretLo=%llu secretHi=%llu\n",
						(unsigned long long)pairing.service,
						static_cast<void *>(pairing.subscriber),
						unsigned(pairing.subscriber->applicationID),
						unsigned(pairing.advertisingPort),
						(unsigned long long)uint64_t(secret),
						(unsigned long long)uint64_t(secret >> 64));
					std::fprintf(stderr,
						"mesh brokenHalfRecovery reason=subscriber-without-advertiser service=%llu subscriber=%p subscriberApp=%u port=%u secretLo=%llu secretHi=%llu\n",
						(unsigned long long)pairing.service,
						static_cast<void *>(pairing.subscriber),
						unsigned(pairing.subscriber->applicationID),
						unsigned(pairing.advertisingPort),
						(unsigned long long)uint64_t(secret),
						(unsigned long long)uint64_t(secret >> 64));
					std::fflush(stderr);
					pairing.subscriber->subscriptionPairing(secret, pairing.advertiserAddress, pairing.service, pairing.advertisingPort, pairing.subscriber->applicationID, false);

					// this won't work unless we seed every advertisers 

					uint64_t subscriptionService = subscriptionServiceForPairing(pairing.subscriber, pairing.service);
					if (subscriptionService != 0)
					{
						auto subsIt = pairing.subscriber->subscriptions.find(subscriptionService);
						Subscription& subscription = subsIt->second;
						if (subscription.nature == SubscriptionNature::any)
						{
							// give it another
							subscribe(subscriptionService, pairing.subscriber, subscription.nature, true);
						}
					}
				}
			}
			else // two halves, good to go
			{
				pairing.advertiser->advertisingTo.insert(pairing.service, pairing.subscriber);
				pairing.subscriber->subscribedTo.insert(pairing.service, pairing.advertiser);

				pairingSecrets.insert_or_assign(
					ServicePairing{pairing.advertiser, pairing.subscriber, pairing.service},
					PairingState{secret, pairing.advertisingPort});
			}
			}

		bootingPairings.clear();

			// Pairing secrets and adjacency sets have been reconstructed; rebuild anyCounts to match.
			rebuildAnyCounts();
			anyMaxHeaps.clear();
		for (const auto& kv : advertising)
		{
			uint64_t service = kv.first;
			const Vector<MeshNode *>& advs = kv.second;
			for (MeshNode *adv : advs)
			{
				noteAnyCapacity(service, adv);
			}
		}

			// Rebuild someCounts/someMinHeaps/someMaxHeaps from current subscriptions
			someCounts.clear();
			someMinHeaps.clear();
			someMaxHeaps.clear();
			someHeapEpochs.clear();
		for (const auto& kv : someSubscribers)
		{
			uint64_t service = kv.first;
			const Vector<MeshNode *>& subs = kv.second;
			auto &counts = someCounts[service];
			for (MeshNode *sub : subs)
			{
				uint32_t cnt = subscriberPairingCountForService(sub, service);
				counts.insert_or_assign(sub, cnt);
			}
			rebuildSomeHeaps(service);
		}
	}

	void logSubscription(MeshNode *subscriber, uint64_t service, SubscriptionNature nature)
	{
		switch (nature)
		{
			case SubscriptionNature::any:
			{
				anySubscribers.insert(service, subscriber);
				pairUnpairedAnySubscribers(service);
				break;
			}
		case SubscriptionNature::exclusiveSome:
		{
				if (someHasSubscriber(service, subscriber) == false)
				{
					someSubscribers.insert(service, subscriber);
				}
						// initialize someCounts and heap with current count for this subscriber
						uint32_t cnt = subscriberPairingCountForService(subscriber, service);
						someCounts[service].insert_or_assign(subscriber, cnt);
						if (someHeapEpochs.contains(service) == false) someHeapEpochs.insert_or_assign(service, 0u);
						pushSomeEntry(service, subscriber, cnt);
						enforceSomeHeapBudget(service);
						uint64_t matchedService = 0;
						MeshNode *bestAdvertiser = nullptr;
						if (pickBestAnyAdvertiser(service, subscriber, matchedService, bestAdvertiser))
						{
							createPairing(bestAdvertiser, subscriber, matchedService, true /* notifyAdvertiser */, true /* notifySubscriber */);
						}
						break;
					}
				case SubscriptionNature::all:
				{
					allSubscribers.insert(service, subscriber);

					forEachAdvertiserForSubscription(service, [&] (uint64_t matchedService, MeshNode *advertiser) -> void {
						createPairing(advertiser, subscriber, matchedService, true /* notifyAdvertiser */, true /* notifySubscriber */);
					});
					break;
				}
				case SubscriptionNature::none: break;
			}
	}

	void logAdvertisement(MeshNode *advertiser, uint64_t service)
	{
		if (advertising.hasEntryFor(service, advertiser))
		{
			return;
		}

		advertising.insert(service, advertiser);
		noteAnyCapacity(service, advertiser);
		pairUnpairedAnySubscribers(service);

		if (MeshServices::isShard(service))
		{
			uint64_t prefixService = MeshServices::convertShardToPrefix(service);
			pairUnpairedAnySubscribers(prefixService);
		}

		if (auto someIt = someSubscribers.find(service); someIt != someSubscribers.end())
		{
			(void)someIt;
			MeshNode *bestSub = pickLeastLoadedSome(service);
			if (bestSub)
			{
				createPairing(advertiser, bestSub, service, true /* notifyAdvertiser */, true /* notifySubscriber */);
			}
		}

		allSubscribers.forEntries(service, [&] (MeshNode *subscriber) -> void {

			createPairing(advertiser, subscriber, service, true /* notifyAdvertiser */, true /* notifySubscriber */);
		});

		if (MeshServices::isShard(service))
		{
			uint64_t prefixService = MeshServices::convertShardToPrefix(service);
			allSubscribers.forEntries(prefixService, [&] (MeshNode *subscriber) -> void {
				createPairing(advertiser, subscriber, service, true /* notifyAdvertiser */, true /* notifySubscriber */);
			});
		}
	}

	void subscribe(uint64_t service, MeshNode *subscriber, SubscriptionNature nature, bool notifySubscriber)
	{
		Vector<MeshNode *>& advertisers = advertising.entriesFor(service);
		if (advertisers.empty())
		{
			advertisers.reserve(8);
		}

		// it could maybe be possible subscribers would be created before any
		// advertisers. or if the advertisers had transient lifetimes and the
		// subscribers were long lived and doing something like monitoring
		
		switch (nature)
		{
				case SubscriptionNature::any: // each subscriber gets one advertiser
			{
				// if a pairing breaks, and a subscriber was subscribed any, it'll run through this path again, but of course this set operation is fine
				anySubscribers.insert(service, subscriber);
				if (subscriberPairingCountForService(subscriber, service) > 0)
				{
					break;
				}

				uint64_t matchedService = 0;
				MeshNode *best = nullptr;
				if (pickBestAnyAdvertiser(service, subscriber, matchedService, best))
				{
					createPairing(best, subscriber, matchedService, true /* notifyAdvertiser */, notifySubscriber);
				}
				break;
			}
		case SubscriptionNature::exclusiveSome: // evenly distribute subscribers over advertisers
		{
			Vector<MeshNode *>& somes = someSubscribers.entriesFor(service);
			if (somes.empty())
			{
				somes.reserve(8);
				}
					bool trackedSubscriber = vectorHasNode(somes, subscriber);
					if (MeshServices::isPrefix(service))
					{
						if (trackedSubscriber == false)
						{
							somes.push_back(subscriber);
						}

						auto &counts = someCounts[service];
						if (someHeapEpochs.contains(service) == false) someHeapEpochs.insert_or_assign(service, 0u);
						counts.insert_or_assign(subscriber, subscriberPairingCountForService(subscriber, service));
						pushSomeEntry(service, subscriber, counts[subscriber]);
						enforceSomeHeapBudget(service);

						if (subscriberPairingCountForService(subscriber, service) == 0)
						{
							uint64_t matchedService = 0;
							MeshNode *best = nullptr;
							if (pickBestAnyAdvertiser(service, subscriber, matchedService, best))
							{
								createPairing(best, subscriber, matchedService, true /* notifyAdvertiser */, notifySubscriber);
							}
						}
						break;
					}
						auto &counts = someCounts[service];
						if (someHeapEpochs.contains(service) == false) someHeapEpochs.insert_or_assign(service, 0u);
						if (counts.contains(subscriber) == false) counts.insert_or_assign(subscriber, subscriber->subscribedTo.countEntriesFor(service));
						pushSomeEntry(service, subscriber, counts[subscriber]);
						enforceSomeHeapBudget(service);

				if (trackedSubscriber == false && advertisers.size() > 0 && !somes.empty())
				{
					uint32_t targetSubscribers = static_cast<uint32_t>(somes.size() + 1);
					uint32_t highTarget = advertisers.size() / targetSubscribers;
					if ((advertisers.size() % targetSubscribers) != 0)
					{
						highTarget += 1;
					}

					while (true)
					{
						MeshNode *donor = pickMostLoadedSome(service);
						if (!donor || donor == subscriber)
						{
							break;
						}

						auto donorCountIt = counts.find(donor);
						uint32_t donorLoad = (donorCountIt != counts.end()) ? donorCountIt->second : donor->subscribedTo.countEntriesFor(service);

						auto subIt = counts.find(subscriber);
						uint32_t subscriberLoad = (subIt != counts.end()) ? subIt->second : 0;

						MeshNode *least = pickLeastLoadedSome(service);
						auto leastIt = (least ? counts.find(least) : counts.end());
						uint32_t minLoad = (leastIt != counts.end()) ? leastIt->second : subscriberLoad;

						if (donorLoad <= minLoad + 1)
						{
							break;
						}

						if (subscriberLoad >= highTarget)
						{
							break;
						}

					bytell_hash_set<MeshNode *>& donorSet = donor->subscribedTo.entriesFor(service);
						auto advIt = donorSet.begin();
						if (advIt == donorSet.end())
						{
							break;
						}

						MeshNode *adv = *advIt;
						destroyPairing("exclusiveSome-rebalance-donor", adv, donor, service, true /* notifyAdvertiser */, notifySubscriber, true /* eraseFromAdvertiser */, false /* eraseFromSubscriber */);
						donorSet.erase(advIt);
						createPairing(adv, subscriber, service, true /* notifyAdvertiser */, notifySubscriber);
					}

					enforceSomeHeapBudget(service);
				}
				else if (trackedSubscriber && subscriber->subscribedTo.countEntriesFor(service) == 0 && advertisers.size() > 0)
				{
					MeshNode *advertiser = advertisers.front();
					createPairing(advertiser, subscriber, service, true /* notifyAdvertiser */, notifySubscriber);
				}

			if (trackedSubscriber == false)
			{
				somes.push_back(subscriber);
			}
			break;
	}
		case SubscriptionNature::all: // each subscriber gets every advertiser
		{
			allSubscribers.insert(service, subscriber);

				forEachAdvertiserForSubscription(service, [&] (uint64_t matchedService, MeshNode *advertiser) -> void {
					createPairing(advertiser, subscriber, matchedService, true /* notifyAdvertiser */, notifySubscriber);
				});

				break;
			}
			case SubscriptionNature::none: break;
		}
	}

	void stopSubscription(uint64_t service, MeshNode *subscriber, SubscriptionNature nature, bool notifySubscriber)
	{
		switch (nature)
		{
			case SubscriptionNature::any:
			{
				anySubscribers.eraseEntry(service, subscriber);
				break;
			}
			case SubscriptionNature::exclusiveSome:
			{
				// by nature these continue many fewer subscribers, so this should be fast even if it iterates over entries
				someEraseSubscriberAll(service, subscriber);

				if (MeshServices::isPrefix(service))
				{
					Vector<uint64_t> pairedServices = pairedServicesForSubscription(subscriber, service);
					for (uint64_t pairedService : pairedServices)
					{
						subscriber->subscribedTo.eraseAllEntriesAfter(pairedService, [&] (MeshNode *advertiser) -> void {

								destroyPairing("stopSubscription-exclusiveSome-prefix", advertiser, subscriber, pairedService, true /* notifyAdvertiser */, notifySubscriber, true /* eraseFromAdvertiser */, false /* eraseFromSubscriber */);
						});
					}

					if (auto sit = someCounts.find(service); sit != someCounts.end())
					{
						sit->second.erase(subscriber);
						enforceSomeHeapBudget(service);
					}
					break;
				}

				// distribute it's advertisers to the others
				Vector<MeshNode *>& somes = someSubscribers.entriesFor(service);

				if (somes.empty())
				{
					subscriber->subscribedTo.eraseAllEntriesAfter(service, [&] (MeshNode *advertiser) -> void {

							destroyPairing("stopSubscription-exclusiveSome-last", advertiser, subscriber, service, true /* notifyAdvertiser */, notifySubscriber, true /* eraseFromAdvertiser */, false /* eraseFromSubscriber */);
					});

					if (auto sit = someCounts.find(service); sit != someCounts.end())
					{
						sit->second.erase(subscriber);
						enforceSomeHeapBudget(service);
					}
					break;
				}

				uint32_t recipientIndex = 0;

				subscriber->subscribedTo.eraseAllEntriesAfter(service, [&] (MeshNode *advertiser) -> void {

						destroyPairing("stopSubscription-exclusiveSome-redistribute", advertiser, subscriber, service, true /* notifyAdvertiser */, notifySubscriber, true /* eraseFromAdvertiser */, false /* eraseFromSubscriber */);

					createPairing(advertiser, somes[recipientIndex], service, true /* notifyAdvertiser */, notifySubscriber);

					recipientIndex = (recipientIndex + 1) % somes.size();
				});

				if (auto sit = someCounts.find(service); sit != someCounts.end())
				{
					sit->second.erase(subscriber);
					enforceSomeHeapBudget(service);
				}

				break;
			}
			case SubscriptionNature::all:
			{	
				allSubscribers.eraseEntry(service, subscriber);
				break;
			}
			case SubscriptionNature::none: break;
		}

		if (nature != SubscriptionNature::exclusiveSome)
		{
			Vector<uint64_t> pairedServices = pairedServicesForSubscription(subscriber, service);
			for (uint64_t pairedService : pairedServices)
			{
				subscriber->subscribedTo.eraseAllEntriesAfter(pairedService, [&] (MeshNode *advertiser) -> void {

						destroyPairing("stopSubscription", advertiser, subscriber, pairedService, true /* notifyAdvertiser */, notifySubscriber, true /* eraseFromAdvertiser */, false /* eraseFromSubscriber */);
				});
			}
		}
	}

	// never notifies the subscriber, because this is only called when we purposely destroy a container
	void stopAllSubscriptions(MeshNode *subscriber)
	{
		for (const auto& [service, subscription] : subscriber->subscriptions)
		{
			stopSubscription(service, subscriber, subscription.nature, false);
		}
	}

	bool isAdvertising(uint64_t service, MeshNode *advertiser)
	{
		return advertising.hasEntryFor(service, advertiser);
	}

	void advertise(uint64_t service, MeshNode *advertiser, uint16_t port, bool notifyAdvertiser)
	{
		(void)port;
		if (advertising.hasEntryFor(service, advertiser))
		{
			return;
		}

		// Established `any` subscriptions stay pinned until their advertiser
		// actually goes away. A new advertiser only picks up future or currently
		// unpaired subscribers, which avoids tearing down healthy live streams just
		// to rebalance load.
		
		advertising.emplace(service, advertiser);
		noteAnyCapacity(service, advertiser);
		pairUnpairedAnySubscribers(service);

		if (MeshServices::isShard(service))
		{
			pairUnpairedAnySubscribers(MeshServices::convertShardToPrefix(service));
		}

		if (auto someIt = someSubscribers.find(service); someIt != someSubscribers.end()) // some subscribers split the advertisers equally
		{
			MeshNode *bestSub = pickLeastLoadedSome(service);
			if (bestSub)
			{
					createPairing(advertiser, bestSub, service, notifyAdvertiser, true /* notifySubscriber */);
				}
			}

			allSubscribers.forEntries(service, [&] (MeshNode *subscriber) -> void {

				createPairing(advertiser, subscriber, service, notifyAdvertiser, true /* notifySubscriber */);
			});

			if (MeshServices::isShard(service))
			{
				uint64_t prefixService = MeshServices::convertShardToPrefix(service);
				allSubscribers.forEntries(prefixService, [&] (MeshNode *subscriber) -> void {
					createPairing(advertiser, subscriber, service, notifyAdvertiser, true /* notifySubscriber */);
				});
			}
		}

	void stopAdvertisement(uint64_t service, MeshNode *advertiser, bool notifyAdvertiser)
	{
		advertising.eraseEntry(service, advertiser);

		advertiser->advertisingTo.eraseAllEntriesAfter(service, [&] (MeshNode *subscriber) -> void {

	   	destroyPairing("stopAdvertisement", advertiser, subscriber, service, notifyAdvertiser, true /* notifySubscriber */, false /* eraseFromAdvertiser */, true /* eraseFromSubscriber */);

		   	SubscriptionNature nature = SubscriptionNature::none;
		   	uint64_t subscriptionService = subscriptionServiceForPairing(subscriber, service);
		   	if (subscriptionService != 0)
		   	{
		   		auto subscriptionIt = subscriber->subscriptions.find(subscriptionService);
		   		nature = subscriptionIt->second.nature;
		   	}

		   	switch (nature)
		   	{
		   		case SubscriptionNature::any:
		   		{
		   			subscribe(subscriptionService, subscriber, SubscriptionNature::any, true);
		   			break;
		   		}
		   		case SubscriptionNature::exclusiveSome: // only load balancers at the moment
		   		{
		   			subscribe(subscriptionService, subscriber, SubscriptionNature::exclusiveSome, true);
		   			break;
		   		}
		   		case SubscriptionNature::all:
		   		{
	   			// do nothing
	   			break;
	   		}
	   		case SubscriptionNature::none: break;
	   	}
		});
	}

	void stopAllAdvertisments(MeshNode *advertiser) // either machine died or container was destroyed
	{
		for (const auto& [service, advertisement] : advertiser->advertisements)
		{
			stopAdvertisement(service, advertiser, false);
		}
	}
};
