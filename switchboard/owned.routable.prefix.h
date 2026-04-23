#pragma once

#include <arpa/inet.h>
#include <cstring>

#include <prodigy/types.h>
#include <switchboard/common/structs.h>

static inline bool switchboardOwnedRoutablePrefix4Equals(const switchboard_owned_routable_prefix4_key& lhs, const switchboard_owned_routable_prefix4_key& rhs)
{
   return lhs.prefixlen == rhs.prefixlen
      && lhs.addr == rhs.addr;
}

static inline bool switchboardOwnedRoutablePrefix6Equals(const switchboard_owned_routable_prefix6_key& lhs, const switchboard_owned_routable_prefix6_key& rhs)
{
   return lhs.prefixlen == rhs.prefixlen
      && memcmp(lhs.addr, rhs.addr, sizeof(lhs.addr)) == 0;
}

static inline void switchboardMaskIPv6PrefixBytes(uint8_t address[16], uint8_t prefixLength)
{
   if (prefixLength >= 128)
   {
      return;
   }

   uint8_t fullBytes = uint8_t(prefixLength / 8);
   uint8_t trailingBits = uint8_t(prefixLength % 8);

   if (trailingBits > 0 && fullBytes < 16)
   {
      address[fullBytes] &= uint8_t(0xffu << (8 - trailingBits));
      fullBytes += 1;
   }

   for (uint8_t index = fullBytes; index < 16; ++index)
   {
      address[index] = 0;
   }
}

static inline switchboard_owned_routable_prefix4_key switchboardMakeOwnedRoutablePrefix4Key(const IPPrefix& prefix)
{
   switchboard_owned_routable_prefix4_key key = {};
   key.prefixlen = prefix.cidr;

   uint32_t hostOrder = ntohl(prefix.network.v4);
   uint32_t mask = 0;
   if (prefix.cidr > 0)
   {
      mask = (prefix.cidr == 32) ? 0xffffffffu : (0xffffffffu << (32 - prefix.cidr));
   }

   key.addr = htonl(hostOrder & mask);
   return key;
}

static inline switchboard_owned_routable_prefix6_key switchboardMakeOwnedRoutablePrefix6Key(const IPPrefix& prefix)
{
   switchboard_owned_routable_prefix6_key key = {};
   key.prefixlen = prefix.cidr;
   memcpy(key.addr, prefix.network.v6, sizeof(key.addr));
   switchboardMaskIPv6PrefixBytes(key.addr, prefix.cidr);
   return key;
}

template <typename Prefix4Key, typename Prefix6Key, typename Make4, typename Make6, typename Eq4, typename Eq6>
static inline void switchboardBuildPrefixKeys(const Vector<IPPrefix>& prefixes,
   Vector<Prefix4Key>& ipv4Keys,
   Vector<Prefix6Key>& ipv6Keys,
   Make4&& make4,
   Make6&& make6,
   Eq4&& eq4,
   Eq6&& eq6)
{
   ipv4Keys.clear();
   ipv6Keys.clear();

   for (const IPPrefix& prefix : prefixes)
   {
      if (prefix.network.is6)
      {
         Prefix6Key key = make6(prefix);

         bool duplicate = false;
         for (const Prefix6Key& existing : ipv6Keys)
         {
            if (eq6(existing, key))
            {
               duplicate = true;
               break;
            }
         }

         if (duplicate == false)
         {
            ipv6Keys.push_back(key);
         }
      }
      else
      {
         Prefix4Key key = make4(prefix);

         bool duplicate = false;
         for (const Prefix4Key& existing : ipv4Keys)
         {
            if (eq4(existing, key))
            {
               duplicate = true;
               break;
            }
         }

         if (duplicate == false)
         {
            ipv4Keys.push_back(key);
         }
      }
   }
}

static inline void switchboardBuildOwnedRoutablePrefixKeys(const Vector<IPPrefix>& prefixes,
   Vector<switchboard_owned_routable_prefix4_key>& ipv4Keys,
   Vector<switchboard_owned_routable_prefix6_key>& ipv6Keys)
{
   switchboardBuildPrefixKeys(prefixes,
      ipv4Keys,
      ipv6Keys,
      [] (const IPPrefix& prefix) -> switchboard_owned_routable_prefix4_key {

         return switchboardMakeOwnedRoutablePrefix4Key(prefix);
      },
      [] (const IPPrefix& prefix) -> switchboard_owned_routable_prefix6_key {

         return switchboardMakeOwnedRoutablePrefix6Key(prefix);
      },
      [] (const switchboard_owned_routable_prefix4_key& lhs, const switchboard_owned_routable_prefix4_key& rhs) -> bool {

         return switchboardOwnedRoutablePrefix4Equals(lhs, rhs);
      },
      [] (const switchboard_owned_routable_prefix6_key& lhs, const switchboard_owned_routable_prefix6_key& rhs) -> bool {

         return switchboardOwnedRoutablePrefix6Equals(lhs, rhs);
      });
}

static inline void switchboardBuildOwnedRoutablePrefixKeys(const Vector<DistributableExternalSubnet>& subnets,
   Vector<switchboard_owned_routable_prefix4_key>& ipv4Keys,
   Vector<switchboard_owned_routable_prefix6_key>& ipv6Keys)
{
   Vector<IPPrefix> prefixes;
   prefixes.reserve(subnets.size());
   for (const DistributableExternalSubnet& subnet : subnets)
   {
      prefixes.push_back(subnet.subnet);
   }

   switchboardBuildOwnedRoutablePrefixKeys(prefixes, ipv4Keys, ipv6Keys);
}
