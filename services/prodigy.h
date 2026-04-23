// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <networking/includes.h>
#include <types/types.containers.h>

#define nShardsPerStatefulApplication 1'024

static uint16_t jump_consistent_hash(uint8_t *key, uint64_t keySize)
{
   // Shard routing must stay stable across threads, brains, and processes.
   uint64_t keyHash = Hasher::hash<Hasher::SeedPolicy::global_shared>(key, keySize);

   int64_t b = -1;
   int64_t j = 0;

   while (j < nShardsPerStatefulApplication)
   {
      b = j;
      keyHash = keyHash * 2862933555777941757ULL + 1;
      j = (b + 1) * (double(1LL << 31) / double((keyHash >> 33) + 1));
   }

   return uint16_t(b);
}

class MeshServices
{
private:

   static constexpr uint64_t groupBitmask = (1ull << 10) - 1;

public:

   static consteval uint64_t generateStatelessService(uint16_t applicationID, uint8_t serviceID)
   {
      return uint64_t(applicationID) << 48 | uint64_t(serviceID) << 40;
   }

   static consteval uint64_t generateStatefulService(uint16_t applicationID, uint8_t serviceID)
   {
      return uint64_t(applicationID) << 48 | uint64_t(serviceID) << 40 | groupBitmask;
   }

   static uint16_t getGroup(uint64_t service)
   {
      return static_cast<uint16_t>(service & groupBitmask) - 1;
   }

   static bool isPrefix(uint64_t service)
   {
      return (groupBitmask == static_cast<uint16_t>(service & groupBitmask));
   }

   static bool isShard(uint64_t service)
   {
      return isPrefix(service) == false && static_cast<uint16_t>(service & groupBitmask) > 0;
   }

   static uint64_t convertShardToPrefix(uint64_t shard)
   {
      return shard | groupBitmask;
   }

   static bool prefixContainsShard(uint64_t prefix, uint64_t service)
   {
      return prefix == convertShardToPrefix(service);
   }

   static uint64_t constrainPrefixToGroup(uint64_t prefix, uint16_t group)
   {
      group += 1;
      prefix &= ~groupBitmask;

      return prefix | group;
   }
};

namespace MeshRegistry
{
   namespace Brain
   {
      constexpr uint16_t applicationID = 0;
   }

   namespace Pulse
   {
      constexpr uint16_t applicationID = 2;
      constexpr uint64_t clients = MeshServices::generateStatefulService(applicationID, 1);
      constexpr uint64_t siblings = MeshServices::generateStatefulService(applicationID, 2);
      constexpr uint64_t seeding = MeshServices::generateStatefulService(applicationID, 3);
      constexpr uint64_t seeders = MeshServices::generateStatefulService(applicationID, 4);
   }

   namespace Truth
   {
      constexpr uint16_t applicationID = 10;
      constexpr uint64_t clients = MeshServices::generateStatefulService(applicationID, 1);
      constexpr uint64_t siblings = MeshServices::generateStatefulService(applicationID, 2);
      constexpr uint64_t seeding = MeshServices::generateStatefulService(applicationID, 3);
      constexpr uint64_t seeders = MeshServices::generateStatefulService(applicationID, 4);
   }

   namespace Hot
   {
      constexpr uint16_t applicationID = 3;
      constexpr uint64_t clients = MeshServices::generateStatefulService(applicationID, 1);
      constexpr uint64_t siblings = MeshServices::generateStatefulService(applicationID, 2);
      constexpr uint64_t cousins = MeshServices::generateStatefulService(applicationID, 3);
      constexpr uint64_t seeding = MeshServices::generateStatefulService(applicationID, 4);
      constexpr uint64_t sharding = MeshServices::generateStatefulService(applicationID, 5);
   }

   namespace Cold
   {
      constexpr uint16_t applicationID = 4;
      constexpr uint64_t clients = MeshServices::generateStatefulService(applicationID, 1);
      constexpr uint64_t siblings = MeshServices::generateStatefulService(applicationID, 2);
      constexpr uint64_t cousins = MeshServices::generateStatefulService(applicationID, 3);
      constexpr uint64_t seeding = MeshServices::generateStatefulService(applicationID, 4);
      constexpr uint64_t sharding = MeshServices::generateStatefulService(applicationID, 5);
   }

   namespace Radar
   {
      constexpr uint16_t applicationID = 5;
      constexpr uint64_t clients = MeshServices::generateStatefulService(applicationID, 1);
      constexpr uint64_t siblings = MeshServices::generateStatefulService(applicationID, 2);
      constexpr uint64_t seeding = MeshServices::generateStatefulService(applicationID, 3);
   }

   namespace Nametag
   {
      constexpr uint16_t applicationID = 6;
   }

   namespace Telnyx
   {
      constexpr uint16_t applicationID = 7;
      constexpr uint64_t clients = MeshServices::generateStatefulService(applicationID, 1);
   }

   namespace AppleNotifs
   {
      constexpr uint16_t applicationID = 8;
      constexpr uint64_t clients = MeshServices::generateStatefulService(applicationID, 1);
   }

   namespace Timezone
   {
      constexpr uint16_t applicationID = 9;
      constexpr uint64_t clients = MeshServices::generateStatefulService(applicationID, 1);
   }

   static inline uint16_t getGroup(uint64_t service)
   {
      return MeshServices::getGroup(service);
   }

   static inline bool prefixContains(uint64_t prefix, uint64_t service)
   {
      return MeshServices::prefixContainsShard(prefix, service);
   }

   static inline bytell_hash_map<String, uint64_t> serviceMappings = [] (void) -> auto {
      bytell_hash_map<String, uint64_t> mappings;

      mappings["MeshRegistry::Pulse::clients"] = Pulse::clients;
      mappings["MeshRegistry::Pulse::siblings"] = Pulse::siblings;
      mappings["MeshRegistry::Pulse::seeders"] = Pulse::seeders;
      mappings["MeshRegistry::Pulse::seeding"] = Pulse::seeding;
      mappings["MeshRegistry::Pulse::seeding"] = Pulse::seeding;

      mappings["MeshRegistry::Truth::clients"] = Truth::clients;
      mappings["MeshRegistry::Truth::siblings"] = Truth::siblings;
      mappings["MeshRegistry::Truth::seeders"] = Truth::seeders;
      mappings["MeshRegistry::Truth::seeding"] = Truth::seeding;

      mappings["MeshRegistry::Hot::clients"] = Hot::clients;
      mappings["MeshRegistry::Hot::siblings"] = Hot::siblings;
      mappings["MeshRegistry::Hot::cousins"] = Hot::cousins;
      mappings["MeshRegistry::Hot::seeding"] = Hot::seeding;
      mappings["MeshRegistry::Hot::sharding"] = Hot::sharding;

      mappings["MeshRegistry::Hot::clients"] = Hot::clients;
      mappings["MeshRegistry::Hot::siblings"] = Hot::siblings;
      mappings["MeshRegistry::Hot::cousins"] = Hot::cousins;
      mappings["MeshRegistry::Hot::seeding"] = Hot::seeding;
      mappings["MeshRegistry::Hot::sharding"] = Hot::sharding;

      mappings["MeshRegistry::Cold::clients"] = Cold::clients;
      mappings["MeshRegistry::Cold::siblings"] = Cold::siblings;
      mappings["MeshRegistry::Cold::cousins"] = Cold::cousins;
      mappings["MeshRegistry::Cold::seeding"] = Cold::seeding;
      mappings["MeshRegistry::Cold::sharding"] = Cold::sharding;

      mappings["MeshRegistry::Radar::clients"] = Radar::clients;
      mappings["MeshRegistry::Radar::siblings"] = Radar::siblings;
      mappings["MeshRegistry::Radar::seeding"] = Radar::seeding;

      mappings["MeshRegistry::Telnyx::clients"] = Telnyx::clients;
      mappings["MeshRegistry::AppleNotifs::clients"] = AppleNotifs::clients;
      mappings["MeshRegistry::Timezone::clients"] = Timezone::clients;

      return mappings;
   }();

   static inline bytell_hash_map<String, uint16_t> applicationIDMappings = [] (void) -> auto {
      bytell_hash_map<String, uint16_t> mappings;

      mappings["Pulse"_ctv] = Pulse::applicationID;
      mappings["Truth"_ctv] = Truth::applicationID;
      mappings["Hot"_ctv] = Hot::applicationID;
      mappings["Cold"_ctv] = Cold::applicationID;
      mappings["Radar"_ctv] = Radar::applicationID;
      mappings["Nametag"_ctv] = Nametag::applicationID;
      mappings["Telnyx"_ctv] = Telnyx::applicationID;
      mappings["AppleNotifs"_ctv] = AppleNotifs::applicationID;
      mappings["Timezone"_ctv] = Timezone::applicationID;

      return mappings;
   }();

   static inline bytell_hash_map<uint16_t, String> applicationNameMappings = [] (void) -> auto {
      bytell_hash_map<uint16_t, String> mappings;

      mappings[Pulse::applicationID] = "Pulse"_ctv;
      mappings[Truth::applicationID] = "Truth"_ctv;
      mappings[Hot::applicationID] = "Hot"_ctv;
      mappings[Cold::applicationID] = "Cold"_ctv;
      mappings[Radar::applicationID] = "Radar"_ctv;
      mappings[Nametag::applicationID] = "Nametag"_ctv;
      mappings[Telnyx::applicationID] = "Telnyx"_ctv;
      mappings[AppleNotifs::applicationID] = "AppleNotifs"_ctv;
      mappings[Timezone::applicationID] = "Timezone"_ctv;

      return mappings;
   }();
}
