#pragma once

#include <algorithm>

#include <prodigy/types.h>

static inline const char *routableAddressKindName(RoutableAddressKind kind)
{
   switch (kind)
   {
      case RoutableAddressKind::testFakeAddress:
      {
         return "testFakeAddress";
      }
      case RoutableAddressKind::anyHostPublicAddress:
      {
         return "anyHostPublicAddress";
      }
      case RoutableAddressKind::providerElasticAddress:
      {
         return "providerElasticAddress";
      }
   }

   return "testFakeAddress";
}

static inline bool parseRoutableAddressKind(const String& value, RoutableAddressKind& kind)
{
   if (value.equal("testFakeAddress"_ctv) || value.equal("RoutableAddressKind::testFakeAddress"_ctv))
   {
      kind = RoutableAddressKind::testFakeAddress;
      return true;
   }

   if (value.equal("anyHostPublicAddress"_ctv) || value.equal("routeToAny"_ctv) || value.equal("RoutableAddressKind::anyHostPublicAddress"_ctv))
   {
      kind = RoutableAddressKind::anyHostPublicAddress;
      return true;
   }

   if (value.equal("providerElasticAddress"_ctv) || value.equal("elasticAddress"_ctv) || value.equal("RoutableAddressKind::providerElasticAddress"_ctv))
   {
      kind = RoutableAddressKind::providerElasticAddress;
      return true;
   }

   return false;
}

static inline bool registeredRoutableAddressMatchesUUID(const RegisteredRoutableAddress& address, uint128_t uuid)
{
   return uuid != 0 && address.uuid == uuid;
}

static inline bool registeredRoutableAddressMatchesName(const RegisteredRoutableAddress& address, const String& name)
{
   return name.size() > 0 && address.name.equals(name);
}

static inline bool registeredRoutableAddressMatchesIdentity(const RegisteredRoutableAddress& address, const String& name, uint128_t uuid)
{
   return registeredRoutableAddressMatchesUUID(address, uuid)
      || registeredRoutableAddressMatchesName(address, name);
}

static inline RegisteredRoutableAddress *findRegisteredRoutableAddress(Vector<RegisteredRoutableAddress>& addresses, const String& name, uint128_t uuid)
{
   for (RegisteredRoutableAddress& address : addresses)
   {
      if (registeredRoutableAddressMatchesIdentity(address, name, uuid))
      {
         return &address;
      }
   }

   return nullptr;
}

static inline const RegisteredRoutableAddress *findRegisteredRoutableAddress(const Vector<RegisteredRoutableAddress>& addresses, uint128_t uuid)
{
   for (const RegisteredRoutableAddress& address : addresses)
   {
      if (registeredRoutableAddressMatchesUUID(address, uuid))
      {
         return &address;
      }
   }

   return nullptr;
}

static inline bool makeHostedIngressPrefixForAddress(const IPAddress& address, IPPrefix& prefix)
{
   if (address.isNull())
   {
      prefix = {};
      return false;
   }

   prefix = {};
   prefix.network = address;
   prefix.cidr = address.is6 ? 128 : 32;
   prefix.canonicalize();
   return true;
}

static inline bool registeredRoutableAddressEquals(const RegisteredRoutableAddress& lhs, const RegisteredRoutableAddress& rhs)
{
   return lhs.uuid == rhs.uuid
      && lhs.name.equals(rhs.name)
      && lhs.kind == rhs.kind
      && lhs.family == rhs.family
      && lhs.machineUUID == rhs.machineUUID
      && lhs.address.equals(rhs.address)
      && lhs.providerPool.equals(rhs.providerPool)
      && lhs.providerAllocationID.equals(rhs.providerAllocationID)
      && lhs.providerAssociationID.equals(rhs.providerAssociationID)
      && lhs.releaseOnRemove == rhs.releaseOnRemove;
}

static inline bool registeredRoutableAddressPresent(const Vector<RegisteredRoutableAddress>& addresses, const IPAddress& candidate)
{
   for (const RegisteredRoutableAddress& address : addresses)
   {
      if (address.address.equals(candidate))
      {
         return true;
      }
   }

   return false;
}

static inline const RegisteredRoutableAddress *findRegisteredRoutableAddressByConcreteAddress(const Vector<RegisteredRoutableAddress>& addresses, const IPAddress& candidate)
{
   for (const RegisteredRoutableAddress& address : addresses)
   {
      if (address.address.equals(candidate))
      {
         return &address;
      }
   }

   return nullptr;
}

static inline bool allocateCandidateAddressFromPrefix(const IPPrefix& prefix, uint64_t hostValue, IPAddress& address)
{
   if (prefix.network.isNull())
   {
      address = {};
      return false;
   }

   address = prefix.network;
   if (address.is6 == false)
   {
      uint8_t hostBits = uint8_t(32 - std::min<uint8_t>(prefix.cidr, 32));
      if (hostBits == 0)
      {
         return false;
      }

      uint64_t limit = (hostBits >= 32) ? uint64_t(UINT32_MAX) : ((uint64_t(1) << hostBits) - 1);
      if (hostValue == 0 || hostValue > limit)
      {
         return false;
      }

      uint32_t network = ntohl(prefix.network.v4);
      uint32_t mask = (hostBits >= 32) ? UINT32_MAX : ((uint32_t(1) << hostBits) - 1u);
      network |= (uint32_t(hostValue) & mask);
      address.v4 = htonl(network);
      return true;
   }

   uint8_t hostBits = uint8_t(128 - std::min<uint8_t>(prefix.cidr, 128));
   if (hostBits == 0)
   {
      return false;
   }

   uint8_t usableBits = std::min<uint8_t>(hostBits, 64);
   uint64_t limit = (usableBits >= 64) ? UINT64_MAX : ((uint64_t(1) << usableBits) - 1);
   if (hostValue == 0 || hostValue > limit)
   {
      return false;
   }

   uint64_t tail = 0;
   for (uint32_t index = 0; index < 8; ++index)
   {
      tail = (tail << 8) | uint64_t(prefix.network.v6[8 + index]);
   }

   uint64_t mask = (usableBits >= 64) ? UINT64_MAX : ((uint64_t(1) << usableBits) - 1);
   tail |= (hostValue & mask);

   for (int index = 15; index >= 8; --index)
   {
      address.v6[index] = uint8_t(tail & 0xFFu);
      tail >>= 8;
   }

   return true;
}

static inline bool allocateUniqueRegisteredAddressFromPrefix(const IPPrefix& prefix, const Vector<RegisteredRoutableAddress>& existing, IPAddress& address)
{
   address = {};
   if (prefix.network.isNull())
   {
      return false;
   }

   uint8_t totalBits = prefix.network.is6 ? 128 : 32;
   if (prefix.cidr >= totalBits)
   {
      return false;
   }

   uint8_t hostBits = uint8_t(totalBits - prefix.cidr);
   uint64_t maxAttempts = 65535;
   if (hostBits < 16)
   {
      maxAttempts = (uint64_t(1) << hostBits) - 1;
   }

   if (maxAttempts == 0)
   {
      return false;
   }

   for (uint64_t hostValue = 1; hostValue <= maxAttempts; ++hostValue)
   {
      IPAddress candidate = {};
      if (allocateCandidateAddressFromPrefix(prefix, hostValue, candidate) == false)
      {
         continue;
      }

      if (prefix.containsAddress(candidate) == false)
      {
         continue;
      }

      if (registeredRoutableAddressPresent(existing, candidate))
      {
         continue;
      }

      address = candidate;
      return true;
   }

   return false;
}

static inline bool resolveWormholeRegisteredRoutableAddress(const Vector<RegisteredRoutableAddress>& addresses, Wormhole& wormhole, String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   if (wormhole.source != ExternalAddressSource::registeredRoutableAddress)
   {
      if (failure)
      {
         failure->assign("wormhole source is not registeredRoutableAddress"_ctv);
      }

      return false;
   }

   if (wormhole.routableAddressUUID == 0)
   {
      if (failure)
      {
         failure->assign("wormhole source=registeredRoutableAddress requires routableAddressUUID"_ctv);
      }

      return false;
   }

   const RegisteredRoutableAddress *registeredAddress = findRegisteredRoutableAddress(addresses, wormhole.routableAddressUUID);
   if (registeredAddress == nullptr)
   {
      if (failure)
      {
         failure->assign("wormhole routableAddressUUID is not registered"_ctv);
      }

      return false;
   }

   if (registeredAddress->address.isNull())
   {
      if (failure)
      {
         failure->assign("registered routable address has no concrete address"_ctv);
      }

      return false;
   }

   wormhole.externalAddress = registeredAddress->address;
   return true;
}
