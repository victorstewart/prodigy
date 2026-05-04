#include <networking/includes.h>
#include <services/debug.h>
#include <cpp-sort/adapters/verge_adapter.h>
#include <cpp-sort/sorters/ska_sorter.h>
#include <services/prodigy.h>
#include <prodigy/types.h>

struct container_network_subnet6_prefix
{
   uint8_t value[11];
};

#include <prodigy/brain/mesh.node.h>
#include <prodigy/brain/mesh.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

class TestSuite
{
public:
   int failed = 0;

   void expect(bool condition, const char *name)
   {
      if (condition)
      {
         basics_log("PASS: %s\n", name);
      }
      else
      {
         std::fprintf(stderr, "FAIL: %s\n", name);
         std::fflush(stderr);
         basics_log("FAIL: %s\n", name);
         failed += 1;
      }
   }
};

class TestMeshNode final : public MeshNode
{
public:
   uint32_t advertisementActivateCalls = 0;
   uint32_t advertisementDeactivateCalls = 0;
   uint32_t subscriptionActivateCalls = 0;
   uint32_t subscriptionDeactivateCalls = 0;
   uint16_t lastSubscriptionActivatePort = 0;
   uint16_t lastSubscriptionDeactivatePort = 0;

   void advertisementPairing(uint128_t, uint128_t, uint64_t, uint16_t, bool activate) override
   {
      if (activate) advertisementActivateCalls += 1;
      else          advertisementDeactivateCalls += 1;
   }

   void subscriptionPairing(uint128_t, uint128_t, uint64_t, uint16_t port, uint16_t, bool activate) override
   {
      if (activate)
      {
         subscriptionActivateCalls += 1;
         lastSubscriptionActivatePort = port;
      }
      else
      {
         subscriptionDeactivateCalls += 1;
         lastSubscriptionDeactivatePort = port;
      }
   }
};

static constexpr uint64_t meshService = 0xA11CEULL;
static constexpr uint16_t meshPort = 19111;

static std::vector<uint16_t> computeJumpHashBucketsForKeys(const std::vector<uint128_t>& keys, int64_t threadSeed)
{
   Hasher::setThreadSeed(threadSeed);

   std::vector<uint16_t> buckets;
   buckets.reserve(keys.size());

   for (const uint128_t& key : keys)
   {
      uint128_t workingKey = key;
      buckets.push_back(jump_consistent_hash(reinterpret_cast<uint8_t *>(&workingKey), sizeof(workingKey)));
   }

   return buckets;
}

static void initNode(TestMeshNode& node, uint16_t applicationID, uint128_t meshAddress, int32_t capacity = 64)
{
   node.applicationID = applicationID;
   node.meshAddress = meshAddress;
   node.remainingSubscriberCapacity = capacity;
}

static void testJumpConsistentHashStableAcrossThreadSeeds(TestSuite& suite)
{
   const int64_t originalGlobalSeed = Hasher::globalSeed();
   const int64_t originalThreadSeed = Hasher::threadSeed();
   Hasher::setGlobalSeed(0x02468ACE13579BDFLL);

   std::vector<uint128_t> keys;
   keys.push_back(uint128_t(11329350464516745216ULL) | (uint128_t(13213379408606233272ULL) << 64));
   keys.push_back(uint128_t(5743192639385774080ULL) | (uint128_t(14767483417386435866ULL) << 64));

   for (uint64_t index = 0; index < 32; ++index)
   {
      const uint64_t low = 0x3000000000000000ULL + (index * 0x9E3779B185EBCA87ULL);
      const uint64_t high = 0x4000000000000000ULL + (index * 0xC2B2AE3D27D4EB4FULL);
      keys.push_back(uint128_t(low) | (uint128_t(high) << 64));
   }

   const std::vector<uint16_t> reference = computeJumpHashBucketsForKeys(keys, 111);

   std::vector<uint16_t> workerBucketsA;
   std::thread workerA([&]() -> void {
      workerBucketsA = computeJumpHashBucketsForKeys(keys, 222);
   });
   workerA.join();

   std::vector<uint16_t> workerBucketsB;
   std::thread workerB([&]() -> void {
      workerBucketsB = computeJumpHashBucketsForKeys(keys, 333);
   });
   workerB.join();

   suite.expect(workerBucketsA == reference, "mesh_jump_hash_stable_across_thread_seed_a");
   suite.expect(workerBucketsB == reference, "mesh_jump_hash_stable_across_thread_seed_b");

   Hasher::setGlobalSeed(originalGlobalSeed);
   Hasher::setThreadSeed(originalThreadSeed);
}

static void testJumpConsistentHashStableAcrossDefaultGlobalSeed(TestSuite& suite)
{
   const int64_t originalGlobalSeed = Hasher::globalSeed();
   const int64_t originalThreadSeed = Hasher::threadSeed();

   suite.expect(Hasher::globalSeed() == Hasher::defaultGlobalSeed(), "mesh_jump_hash_default_global_seed");

   std::vector<uint128_t> keys;
   keys.push_back(uint128_t(211519444849527808ULL) | (uint128_t(12949714390353147497ULL) << 64));
   keys.push_back(uint128_t(17135719469053349632ULL) | (uint128_t(10903082970765322110ULL) << 64));

   const std::vector<uint16_t> reference = computeJumpHashBucketsForKeys(keys, 444);

   std::vector<uint16_t> workerBuckets;
   std::thread worker([&]() -> void {
      workerBuckets = computeJumpHashBucketsForKeys(keys, 555);
   });
   worker.join();

   suite.expect(workerBuckets == reference, "mesh_jump_hash_default_global_seed_stable_across_threads");

   Hasher::setGlobalSeed(originalGlobalSeed);
   Hasher::setThreadSeed(originalThreadSeed);
}

static void configureAdvertisement(TestMeshNode& node, uint64_t service, uint16_t port)
{
   node.advertisements.insert_or_assign(service, Advertisement(service, ContainerState::scheduled, ContainerState::destroying, port));
}

static void configureSubscription(TestMeshNode& node, uint64_t service, SubscriptionNature nature)
{
   node.subscriptions.insert_or_assign(service, Subscription(service, ContainerState::scheduled, ContainerState::destroying, nature));
}

template <size_t NAdvertisers, size_t NSubscribers>
static bool validateMeshInvariants(
   Mesh& mesh,
   uint64_t service,
   const std::array<TestMeshNode *, NAdvertisers>& advertisers,
   const std::array<TestMeshNode *, NSubscribers>& subscribers,
   char *error,
   size_t errorCapacity)
{
   uint32_t nAdvertising = 0;
   for (TestMeshNode *advertiser : advertisers)
   {
      if (mesh.isAdvertising(service, advertiser))
      {
         nAdvertising += 1;
      }
   }

   for (TestMeshNode *subscriber : subscribers)
   {
      if (subscriber->subscriptions.contains(service) == false)
      {
         std::snprintf(error, errorCapacity, "subscriber %u missing subscription map entry", unsigned(subscriber->applicationID));
         return false;
      }

      auto nature = subscriber->subscriptions[service].nature;
      uint32_t nLinks = subscriber->subscribedTo.countEntriesFor(service);

      switch (nature)
      {
         case SubscriptionNature::any:
         {
            if (nLinks > 1)
            {
               std::snprintf(error, errorCapacity, "any subscriber %u has %u links", unsigned(subscriber->applicationID), unsigned(nLinks));
               return false;
            }
            break;
         }
         case SubscriptionNature::exclusiveSome:
         {
            if (nLinks > nAdvertising)
            {
               std::snprintf(error, errorCapacity, "exclusiveSome subscriber %u has %u links (advertisers=%u)", unsigned(subscriber->applicationID), unsigned(nLinks), unsigned(nAdvertising));
               return false;
            }
            break;
         }
         case SubscriptionNature::all:
         {
            if (nLinks != nAdvertising)
            {
               std::snprintf(error, errorCapacity, "all subscriber %u has %u links (advertisers=%u)", unsigned(subscriber->applicationID), unsigned(nLinks), unsigned(nAdvertising));
               return false;
            }
            break;
         }
         case SubscriptionNature::none:
         {
            if (nLinks != 0)
            {
               std::snprintf(error, errorCapacity, "none subscriber %u has %u links", unsigned(subscriber->applicationID), unsigned(nLinks));
               return false;
            }
            break;
         }
      }

      auto& linkedAdvertisers = subscriber->subscribedTo.entriesFor(service);
      for (MeshNode *linkedAdvertiserBase : linkedAdvertisers)
      {
         auto *linkedAdvertiser = static_cast<TestMeshNode *>(linkedAdvertiserBase);
         if (linkedAdvertiser->advertisingTo.hasEntryFor(service, subscriber) == false)
         {
            std::snprintf(error, errorCapacity, "asymmetric link sub=%u adv=%u missing adv->sub edge", unsigned(subscriber->applicationID), unsigned(linkedAdvertiser->applicationID));
            return false;
         }

         if (mesh.pairingSecretFor(linkedAdvertiser, subscriber, service) == 0)
         {
            std::snprintf(error, errorCapacity, "missing pairing secret sub=%u adv=%u", unsigned(subscriber->applicationID), unsigned(linkedAdvertiser->applicationID));
            return false;
         }
      }
   }

   for (TestMeshNode *advertiser : advertisers)
   {
      auto& linkedSubscribers = advertiser->advertisingTo.entriesFor(service);
      for (MeshNode *linkedSubscriberBase : linkedSubscribers)
      {
         auto *linkedSubscriber = static_cast<TestMeshNode *>(linkedSubscriberBase);
         if (linkedSubscriber->subscribedTo.hasEntryFor(service, advertiser) == false)
         {
            std::snprintf(error, errorCapacity, "asymmetric link adv=%u sub=%u missing sub->adv edge", unsigned(advertiser->applicationID), unsigned(linkedSubscriber->applicationID));
            return false;
         }
      }
   }

   return true;
}

static void testAnyAndRebalancePaths(TestSuite& suite)
{
   Mesh mesh;
   TestMeshNode a1;
   TestMeshNode a2;
   TestMeshNode s1;
   TestMeshNode s2;
   TestMeshNode s3;

   initNode(a1, 1, 0x01);
   initNode(a2, 2, 0x02);
   initNode(s1, 11, 0x11);
   initNode(s2, 12, 0x12);
   initNode(s3, 13, 0x13);

   configureAdvertisement(a1, meshService, meshPort);
   configureAdvertisement(a2, meshService, meshPort);
   configureSubscription(s1, meshService, SubscriptionNature::any);
   configureSubscription(s2, meshService, SubscriptionNature::any);
   configureSubscription(s3, meshService, SubscriptionNature::any);

   mesh.advertise(meshService, &a1, meshPort, true);
   mesh.subscribe(meshService, &s1, SubscriptionNature::any, true);
   mesh.subscribe(meshService, &s2, SubscriptionNature::any, true);

   suite.expect(a1.advertisingTo.countEntriesFor(meshService) == 2, "mesh_any_initially_single_advertiser_takes_all");
   suite.expect(s1.subscribedTo.countEntriesFor(meshService) == 1, "mesh_any_subscriber1_has_single_link");
   suite.expect(s2.subscribedTo.countEntriesFor(meshService) == 1, "mesh_any_subscriber2_has_single_link");

   mesh.advertise(meshService, &a2, meshPort, true);

   uint32_t a1Load = a1.advertisingTo.countEntriesFor(meshService);
   uint32_t a2Load = a2.advertisingTo.countEntriesFor(meshService);
   suite.expect(a1Load == 2 && a2Load == 0, "mesh_any_existing_pairings_stay_pinned_when_new_advertiser_arrives");
   suite.expect(s1.subscriptionDeactivateCalls == 0 && s2.subscriptionDeactivateCalls == 0, "mesh_any_new_advertiser_does_not_deactivate_live_subscribers");

   mesh.subscribe(meshService, &s3, SubscriptionNature::any, true);
   suite.expect(s3.subscribedTo.hasEntryFor(meshService, &a2), "mesh_any_new_subscriber_prefers_fresh_capacity_after_new_advertiser");
   suite.expect(a2.advertisingTo.countEntriesFor(meshService) == 1, "mesh_any_new_advertiser_serves_future_subscribers");

   mesh.stopAdvertisement(meshService, &a1, true);
   suite.expect(a1.advertisingTo.countEntriesFor(meshService) == 0, "mesh_any_stopAdvertisement_clears_old_advertiser_links");
   suite.expect(s1.subscribedTo.hasEntryFor(meshService, &a2), "mesh_any_subscriber1_resubscribed_after_advertiser_stop");
   suite.expect(s2.subscribedTo.hasEntryFor(meshService, &a2), "mesh_any_subscriber2_resubscribed_after_advertiser_stop");
   suite.expect(s3.subscribedTo.hasEntryFor(meshService, &a2), "mesh_any_subscriber3_stays_on_surviving_advertiser_after_stop");

   mesh.stopSubscription(meshService, &s2, SubscriptionNature::any, true);
   suite.expect(s2.subscribedTo.countEntriesFor(meshService) == 0, "mesh_any_stopSubscription_clears_links");
   suite.expect(a2.advertisingTo.hasEntryFor(meshService, &s2) == false, "mesh_any_stopSubscription_removes_reverse_edge");
}

static void testAnyUnpairedStartupPath(TestSuite& suite)
{
   Mesh mesh;
   TestMeshNode a1;
   TestMeshNode a2;
   TestMeshNode s1;

   initNode(a1, 21, 0x21);
   initNode(a2, 22, 0x22);
   initNode(s1, 31, 0x31);

   configureAdvertisement(a1, meshService, meshPort);
   configureAdvertisement(a2, meshService, meshPort);
   configureSubscription(s1, meshService, SubscriptionNature::any);

   mesh.subscribe(meshService, &s1, SubscriptionNature::any, true);
   mesh.advertise(meshService, &a1, meshPort, true);
   suite.expect(s1.subscribedTo.countEntriesFor(meshService) == 1, "mesh_any_single_advertiser_startup_pairs_immediately");
   suite.expect(s1.subscribedTo.hasEntryFor(meshService, &a1), "mesh_any_single_advertiser_startup_links_first_advertiser");

   mesh.advertise(meshService, &a2, meshPort, true);
   suite.expect(s1.subscribedTo.countEntriesFor(meshService) == 1, "mesh_any_second_advertiser_keeps_single_link");
}

static void testStopAdvertisementPreservesSubscriberDeactivatePort(TestSuite& suite)
{
   Mesh mesh;
   TestMeshNode advertiser;
   TestMeshNode subscriber;

   initNode(advertiser, 32, 0x32);
   initNode(subscriber, 33, 0x33);

   configureAdvertisement(advertiser, meshService, meshPort);
   configureSubscription(subscriber, meshService, SubscriptionNature::all);

   mesh.advertise(meshService, &advertiser, meshPort, true);
   mesh.subscribe(meshService, &subscriber, SubscriptionNature::all, true);

   suite.expect(subscriber.subscriptionActivateCalls == 1, "mesh_stopAdvertisement_port_activate_delivered_once");
   suite.expect(subscriber.lastSubscriptionActivatePort == meshPort, "mesh_stopAdvertisement_port_activate_uses_advertised_port");

   advertiser.advertisements.erase(meshService);
   mesh.stopAdvertisement(meshService, &advertiser, true);

   suite.expect(subscriber.subscriptionDeactivateCalls == 1, "mesh_stopAdvertisement_port_deactivate_delivered_once");
   suite.expect(subscriber.lastSubscriptionDeactivatePort == meshPort, "mesh_stopAdvertisement_port_deactivate_preserves_original_port");
}

static void testExclusiveSomePaths(TestSuite& suite)
{
   Mesh mesh;
   TestMeshNode a1;
   TestMeshNode a2;
   TestMeshNode a3;
   TestMeshNode a4;
   TestMeshNode s1;
   TestMeshNode s2;

   initNode(a1, 41, 0x41);
   initNode(a2, 42, 0x42);
   initNode(a3, 43, 0x43);
   initNode(a4, 44, 0x44);
   initNode(s1, 51, 0x51);
   initNode(s2, 52, 0x52);

   configureAdvertisement(a1, meshService, meshPort);
   configureAdvertisement(a2, meshService, meshPort);
   configureAdvertisement(a3, meshService, meshPort);
   configureAdvertisement(a4, meshService, meshPort);
   configureSubscription(s1, meshService, SubscriptionNature::exclusiveSome);
   configureSubscription(s2, meshService, SubscriptionNature::exclusiveSome);

   mesh.subscribe(meshService, &s1, SubscriptionNature::exclusiveSome, true);
   mesh.advertise(meshService, &a1, meshPort, true);
   mesh.advertise(meshService, &a2, meshPort, true);
   mesh.advertise(meshService, &a3, meshPort, true);
   mesh.advertise(meshService, &a4, meshPort, true);

   suite.expect(s1.subscribedTo.countEntriesFor(meshService) == 4, "mesh_some_single_subscriber_initially_takes_all");

   mesh.subscribe(meshService, &s2, SubscriptionNature::exclusiveSome, true);

   uint32_t s1Load = s1.subscribedTo.countEntriesFor(meshService);
   uint32_t s2Load = s2.subscribedTo.countEntriesFor(meshService);
   suite.expect(s1Load == 2 && s2Load == 2, "mesh_some_rebalances_from_donor_on_new_subscriber");

   mesh.stopSubscription(meshService, &s1, SubscriptionNature::exclusiveSome, true);
   suite.expect(s1.subscribedTo.countEntriesFor(meshService) == 0, "mesh_some_stopSubscription_clears_removed_subscriber");
   suite.expect(s2.subscribedTo.countEntriesFor(meshService) == 4, "mesh_some_stopSubscription_redistributes_to_remaining_subscribers");

   mesh.stopSubscription(meshService, &s2, SubscriptionNature::exclusiveSome, true);
   suite.expect(s2.subscribedTo.countEntriesFor(meshService) == 0, "mesh_some_stopSubscription_last_subscriber_clears_all_links");
   suite.expect(a1.advertisingTo.countEntriesFor(meshService) == 0, "mesh_some_advertiser1_cleared_after_last_subscriber_stop");
   suite.expect(a2.advertisingTo.countEntriesFor(meshService) == 0, "mesh_some_advertiser2_cleared_after_last_subscriber_stop");
   suite.expect(a3.advertisingTo.countEntriesFor(meshService) == 0, "mesh_some_advertiser3_cleared_after_last_subscriber_stop");
   suite.expect(a4.advertisingTo.countEntriesFor(meshService) == 0, "mesh_some_advertiser4_cleared_after_last_subscriber_stop");
}

static void testAllAndStopAllPaths(TestSuite& suite)
{
   Mesh mesh;
   TestMeshNode a1;
   TestMeshNode a2;
   TestMeshNode s1;
   TestMeshNode s2;

   initNode(a1, 61, 0x61);
   initNode(a2, 62, 0x62);
   initNode(s1, 71, 0x71);
   initNode(s2, 72, 0x72);

   configureAdvertisement(a1, meshService, meshPort);
   configureAdvertisement(a2, meshService, meshPort);
   configureSubscription(s1, meshService, SubscriptionNature::all);
   configureSubscription(s2, meshService, SubscriptionNature::all);

   mesh.advertise(meshService, &a1, meshPort, true);
   mesh.advertise(meshService, &a2, meshPort, true);
   mesh.subscribe(meshService, &s1, SubscriptionNature::all, true);
   mesh.subscribe(meshService, &s2, SubscriptionNature::all, true);

   suite.expect(s1.subscribedTo.countEntriesFor(meshService) == 2, "mesh_all_subscriber1_links_to_all_advertisers");
   suite.expect(s2.subscribedTo.countEntriesFor(meshService) == 2, "mesh_all_subscriber2_links_to_all_advertisers");

   mesh.stopAdvertisement(meshService, &a1, true);
   suite.expect(s1.subscribedTo.countEntriesFor(meshService) == 1, "mesh_all_stopAdvertisement_removes_subscriber1_edge");
   suite.expect(s2.subscribedTo.countEntriesFor(meshService) == 1, "mesh_all_stopAdvertisement_removes_subscriber2_edge");

   mesh.stopAllSubscriptions(&s1);
   suite.expect(s1.subscribedTo.countEntriesFor(meshService) == 0, "mesh_stopAllSubscriptions_removes_all_edges");

   mesh.stopAllAdvertisments(&a2);
   suite.expect(s2.subscribedTo.countEntriesFor(meshService) == 0, "mesh_stopAllAdvertisments_removes_all_reverse_edges");
   suite.expect(mesh.isAdvertising(meshService, &a2) == false, "mesh_stopAllAdvertisments_marks_not_advertising");
}

static void testAllSubscriptionSkipsSelfPairing(TestSuite& suite)
{
   Mesh mesh;
   TestMeshNode replicaA;
   TestMeshNode replicaB;
   TestMeshNode replicaC;

   initNode(replicaA, 81, 0x81);
   initNode(replicaB, 82, 0x82);
   initNode(replicaC, 83, 0x83);

   for (TestMeshNode *replica : {&replicaA, &replicaB, &replicaC})
   {
      configureAdvertisement(*replica, meshService, meshPort);
      configureSubscription(*replica, meshService, SubscriptionNature::all);
   }

   mesh.advertise(meshService, &replicaA, meshPort, true);
   mesh.advertise(meshService, &replicaB, meshPort, true);
   mesh.advertise(meshService, &replicaC, meshPort, true);
   mesh.subscribe(meshService, &replicaA, SubscriptionNature::all, true);
   mesh.subscribe(meshService, &replicaB, SubscriptionNature::all, true);
   mesh.subscribe(meshService, &replicaC, SubscriptionNature::all, true);

   suite.expect(replicaA.subscribedTo.countEntriesFor(meshService) == 2, "mesh_all_self_subscriber_a_links_only_remote_advertisers");
   suite.expect(replicaB.subscribedTo.countEntriesFor(meshService) == 2, "mesh_all_self_subscriber_b_links_only_remote_advertisers");
   suite.expect(replicaC.subscribedTo.countEntriesFor(meshService) == 2, "mesh_all_self_subscriber_c_links_only_remote_advertisers");
   suite.expect(replicaA.subscribedTo.hasEntryFor(meshService, &replicaA) == false, "mesh_all_self_subscriber_a_no_self_edge");
   suite.expect(replicaB.subscribedTo.hasEntryFor(meshService, &replicaB) == false, "mesh_all_self_subscriber_b_no_self_edge");
   suite.expect(replicaC.subscribedTo.hasEntryFor(meshService, &replicaC) == false, "mesh_all_self_subscriber_c_no_self_edge");
}

static void testAllStatefulStartupSequencePairsEveryReplica(TestSuite& suite)
{
   Mesh mesh;
   TestMeshNode replicaA;
   TestMeshNode replicaB;
   TestMeshNode replicaC;

   initNode(replicaA, 91, 0x91);
   initNode(replicaB, 92, 0x92);
   initNode(replicaC, 93, 0x93);

   auto scheduleReplica = [&] (TestMeshNode& replica) -> void {
      configureAdvertisement(replica, meshService, meshPort);
      configureSubscription(replica, meshService, SubscriptionNature::all);
      mesh.advertise(meshService, &replica, meshPort, false);
      mesh.subscribe(meshService, &replica, SubscriptionNature::all, false);
   };

   scheduleReplica(replicaA);
   scheduleReplica(replicaB);
   scheduleReplica(replicaC);

   suite.expect(replicaA.subscribedTo.countEntriesFor(meshService) == 2, "mesh_all_startup_sequence_a_subscribes_to_two_peers");
   suite.expect(replicaB.subscribedTo.countEntriesFor(meshService) == 2, "mesh_all_startup_sequence_b_subscribes_to_two_peers");
   suite.expect(replicaC.subscribedTo.countEntriesFor(meshService) == 2, "mesh_all_startup_sequence_c_subscribes_to_two_peers");
   suite.expect(replicaA.advertisingTo.countEntriesFor(meshService) == 2, "mesh_all_startup_sequence_a_advertises_to_two_peers");
   suite.expect(replicaB.advertisingTo.countEntriesFor(meshService) == 2, "mesh_all_startup_sequence_b_advertises_to_two_peers");
   suite.expect(replicaC.advertisingTo.countEntriesFor(meshService) == 2, "mesh_all_startup_sequence_c_advertises_to_two_peers");
}

static void testUnifyPairingHalvesPaths(TestSuite& suite)
{
   Mesh mesh;
   TestMeshNode advertiser;
   TestMeshNode subscriber;
   TestMeshNode subscriberOnlyHalf;

   initNode(advertiser, 81, 0x81);
   initNode(subscriber, 82, 0x82);
   initNode(subscriberOnlyHalf, 83, 0x83);

   configureAdvertisement(advertiser, meshService, meshPort);
   configureSubscription(subscriber, meshService, SubscriptionNature::any);
   configureSubscription(subscriberOnlyHalf, meshService, SubscriptionNature::any);

   mesh.logAdvertisement(&advertiser, meshService);
   mesh.logSubscription(&subscriber, meshService, SubscriptionNature::any);
   mesh.logSubscription(&subscriberOnlyHalf, meshService, SubscriptionNature::any);

   uint128_t goodSecret = 111;
   mesh.logAdvertisementPairing(goodSecret, &advertiser, AdvertisementPairing(goodSecret, subscriber.meshAddress, meshService));
   mesh.logSubscriptionPairing(goodSecret, &subscriber, SubscriptionPairing(goodSecret, advertiser.meshAddress, meshService, meshPort));

   uint128_t advertiserOnlySecret = 222;
   mesh.logAdvertisementPairing(advertiserOnlySecret, &advertiser, AdvertisementPairing(advertiserOnlySecret, subscriberOnlyHalf.meshAddress, meshService));

   uint128_t subscriberOnlySecret = 333;
   mesh.logSubscriptionPairing(subscriberOnlySecret, &subscriberOnlyHalf, SubscriptionPairing(subscriberOnlySecret, advertiser.meshAddress, meshService, meshPort));

   mesh.unifyPairingHalves();

   suite.expect(mesh.pairingSecretFor(&advertiser, &subscriber, meshService) == goodSecret, "mesh_unify_keeps_complete_pairing_secret");
   suite.expect(advertiser.advertisementDeactivateCalls >= 1, "mesh_unify_deactivates_advertiser_only_half");
   suite.expect(subscriberOnlyHalf.subscriptionDeactivateCalls >= 1, "mesh_unify_deactivates_subscriber_only_half");
   suite.expect(subscriberOnlyHalf.subscribedTo.countEntriesFor(meshService) >= 1, "mesh_unify_repairs_subscriber_only_half_with_any_resubscribe");
}

static uint64_t nextRandom(uint64_t& state)
{
   state = (state * 6364136223846793005ULL) + 1442695040888963407ULL;
   return state;
}

static void setSubscriberNature(Mesh& mesh, TestMeshNode& subscriber, uint64_t service, SubscriptionNature nextNature)
{
   SubscriptionNature currentNature = SubscriptionNature::none;
   if (auto it = subscriber.subscriptions.find(service); it != subscriber.subscriptions.end())
   {
      currentNature = it->second.nature;
   }

   if (currentNature != SubscriptionNature::none)
   {
      mesh.stopSubscription(service, &subscriber, currentNature, true);
   }

   configureSubscription(subscriber, service, nextNature);

   if (nextNature != SubscriptionNature::none)
   {
      mesh.subscribe(service, &subscriber, nextNature, true);
   }
}

static void testMeshRandomWalkSmoke(TestSuite& suite)
{
   constexpr uint32_t nSeeds = 12;
   constexpr uint32_t nSteps = 400;

   for (uint32_t seed = 1; seed <= nSeeds; ++seed)
   {
      Mesh mesh;
      std::array<TestMeshNode, 3> advertisers{};
      std::array<TestMeshNode, 4> subscribers{};
      std::array<TestMeshNode *, 3> advertiserRefs{};
      std::array<TestMeshNode *, 4> subscriberRefs{};

      for (uint32_t i = 0; i < advertisers.size(); ++i)
      {
         initNode(advertisers[i], uint16_t(100 + i), uint128_t(0x1000 + i));
         configureAdvertisement(advertisers[i], meshService, uint16_t(meshPort + i));
         advertiserRefs[i] = &advertisers[i];
      }

      for (uint32_t i = 0; i < subscribers.size(); ++i)
      {
         initNode(subscribers[i], uint16_t(200 + i), uint128_t(0x2000 + i));
         configureSubscription(subscribers[i], meshService, SubscriptionNature::none);
         subscriberRefs[i] = &subscribers[i];
      }

      uint64_t rng = (uint64_t(seed) << 32) ^ 0xA5A5A5A5ULL;
      bool failedSeed = false;

      for (uint32_t step = 0; step < nSteps; ++step)
      {
         uint32_t op = uint32_t(nextRandom(rng) % 8);

         if (op == 0 || op == 1)
         {
            uint32_t idx = uint32_t(nextRandom(rng) % advertisers.size());
            TestMeshNode& advertiser = advertisers[idx];

            if (mesh.isAdvertising(meshService, &advertiser))
            {
               mesh.stopAdvertisement(meshService, &advertiser, true);
            }
            else
            {
               mesh.advertise(meshService, &advertiser, advertiser.advertisements[meshService].port, true);
            }
         }
         else
         {
            uint32_t idx = uint32_t(nextRandom(rng) % subscribers.size());
            uint32_t naturePick = uint32_t(nextRandom(rng) % 4);
            SubscriptionNature nextNature = SubscriptionNature::none;

            switch (naturePick)
            {
               case 0: nextNature = SubscriptionNature::any; break;
               case 1: nextNature = SubscriptionNature::exclusiveSome; break;
               case 2: nextNature = SubscriptionNature::all; break;
               default: nextNature = SubscriptionNature::none; break;
            }

            setSubscriberNature(mesh, subscribers[idx], meshService, nextNature);
         }

         char invariantError[256] = {0};
         if (validateMeshInvariants(mesh, meshService, advertiserRefs, subscriberRefs, invariantError, sizeof(invariantError)) == false)
         {
            char name[96];
            std::snprintf(name, sizeof(name), "mesh_random_walk_seed_%u_step_%u", seed, step);
            suite.expect(false, name);
            basics_log("DETAIL: %s\n", invariantError);
            failedSeed = true;
            break;
         }
      }

      if (failedSeed == false)
      {
         char name[64];
         std::snprintf(name, sizeof(name), "mesh_random_walk_seed_%u", seed);
         suite.expect(true, name);
      }
   }
}

int main(void)
{
   TestSuite suite;

   testJumpConsistentHashStableAcrossThreadSeeds(suite);
   testJumpConsistentHashStableAcrossDefaultGlobalSeed(suite);
   testAnyAndRebalancePaths(suite);
   testAnyUnpairedStartupPath(suite);
   testStopAdvertisementPreservesSubscriberDeactivatePort(suite);
   testExclusiveSomePaths(suite);
   testAllAndStopAllPaths(suite);
   testAllSubscriptionSkipsSelfPairing(suite);
   testAllStatefulStartupSequencePairsEveryReplica(suite);
   testUnifyPairingHalvesPaths(suite);
   testMeshRandomWalkSmoke(suite);

   if (suite.failed > 0)
   {
      std::fprintf(stderr, "FAIL: mesh unit test failures=%d\n", suite.failed);
      std::fflush(stderr);
      basics_log("FAIL: mesh unit test failures=%d\n", suite.failed);
      return EXIT_FAILURE;
   }

   basics_log("PASS: mesh unit suite\n");
   return EXIT_SUCCESS;
}
