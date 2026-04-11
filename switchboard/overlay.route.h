#pragma once

#include <sys/socket.h>
#include <cstdlib>
#include <cstring>

#include <prodigy/types.h>
#include <switchboard/common/structs.h>
#include <switchboard/owned.routable.prefix.h>

static inline bool switchboardOverlayPrefix4Equals(const switchboard_overlay_prefix4_key& lhs, const switchboard_overlay_prefix4_key& rhs)
{
   return lhs.prefixlen == rhs.prefixlen
      && lhs.addr == rhs.addr;
}

static inline bool switchboardOverlayPrefix6Equals(const switchboard_overlay_prefix6_key& lhs, const switchboard_overlay_prefix6_key& rhs)
{
   return lhs.prefixlen == rhs.prefixlen
      && std::memcmp(lhs.addr, rhs.addr, sizeof(lhs.addr)) == 0;
}

static inline switchboard_overlay_prefix4_key switchboardMakeOverlayPrefix4Key(const IPPrefix& prefix)
{
   switchboard_overlay_prefix4_key key = {};
   switchboard_owned_routable_prefix4_key owned = switchboardMakeOwnedRoutablePrefix4Key(prefix);
   key.prefixlen = owned.prefixlen;
   key.addr = owned.addr;
   return key;
}

static inline switchboard_overlay_prefix6_key switchboardMakeOverlayPrefix6Key(const IPPrefix& prefix)
{
   switchboard_overlay_prefix6_key key = {};
   switchboard_owned_routable_prefix6_key owned = switchboardMakeOwnedRoutablePrefix6Key(prefix);
   key.prefixlen = owned.prefixlen;
   std::memcpy(key.addr, owned.addr, sizeof(key.addr));
   return key;
}

static inline void switchboardBuildOverlayPrefixKeys(const Vector<IPPrefix>& prefixes,
   Vector<switchboard_overlay_prefix4_key>& ipv4Keys,
   Vector<switchboard_overlay_prefix6_key>& ipv6Keys)
{
   switchboardBuildPrefixKeys(prefixes,
      ipv4Keys,
      ipv6Keys,
      [] (const IPPrefix& prefix) -> switchboard_overlay_prefix4_key {

         return switchboardMakeOverlayPrefix4Key(prefix);
      },
      [] (const IPPrefix& prefix) -> switchboard_overlay_prefix6_key {

         return switchboardMakeOverlayPrefix6Key(prefix);
      },
      [] (const switchboard_overlay_prefix4_key& lhs, const switchboard_overlay_prefix4_key& rhs) -> bool {

         return switchboardOverlayPrefix4Equals(lhs, rhs);
      },
      [] (const switchboard_overlay_prefix6_key& lhs, const switchboard_overlay_prefix6_key& rhs) -> bool {

         return switchboardOverlayPrefix6Equals(lhs, rhs);
      });
}

static inline bool switchboardOverlayMachineRouteKeyEquals(const switchboard_overlay_machine_route_key& lhs, const switchboard_overlay_machine_route_key& rhs)
{
   return lhs.fragment == rhs.fragment;
}

static inline void switchboardBuildOverlayHostedIngressRouteEntries(const Vector<SwitchboardOverlayHostedIngressRoute>& routes,
   Vector<std::pair<switchboard_overlay_prefix4_key, switchboard_overlay_hosted_ingress_route4>>& ipv4Entries,
   Vector<std::pair<switchboard_overlay_prefix6_key, switchboard_overlay_hosted_ingress_route6>>& ipv6Entries)
{
   ipv4Entries.clear();
   ipv6Entries.clear();

   for (const SwitchboardOverlayHostedIngressRoute& route : routes)
   {
      if (route.machineFragment == 0 || route.prefix.network.isNull())
      {
         continue;
      }

      if (route.prefix.network.is6)
      {
         switchboard_overlay_prefix6_key key = switchboardMakeOverlayPrefix6Key(route.prefix);
         bool updated = false;
         for (auto& existing : ipv6Entries)
         {
            if (switchboardOverlayPrefix6Equals(existing.first, key))
            {
               existing.second.machine_fragment = route.machineFragment;
               updated = true;
               break;
            }
         }

         if (updated == false)
         {
            switchboard_overlay_hosted_ingress_route6 value = {};
            value.machine_fragment = route.machineFragment;
            ipv6Entries.emplace_back(key, value);
         }
      }
      else
      {
         switchboard_overlay_prefix4_key key = switchboardMakeOverlayPrefix4Key(route.prefix);
         bool updated = false;
         for (auto& existing : ipv4Entries)
         {
            if (switchboardOverlayPrefix4Equals(existing.first, key))
            {
               existing.second.machine_fragment = route.machineFragment;
               updated = true;
               break;
            }
         }

         if (updated == false)
         {
            switchboard_overlay_hosted_ingress_route4 value = {};
            value.machine_fragment = route.machineFragment;
            ipv4Entries.emplace_back(key, value);
         }
      }
   }
}

static inline bool switchboardOverlayMachineRouteEquals(const switchboard_overlay_machine_route& lhs, const switchboard_overlay_machine_route& rhs)
{
   return lhs.family == rhs.family
      && lhs.use_gateway_mac == rhs.use_gateway_mac
      && lhs.next_hop4 == rhs.next_hop4
      && lhs.source4 == rhs.source4
      && std::memcmp(lhs.next_hop_mac, rhs.next_hop_mac, sizeof(lhs.next_hop_mac)) == 0
      && std::memcmp(lhs.next_hop6, rhs.next_hop6, sizeof(lhs.next_hop6)) == 0
      && std::memcmp(lhs.source6, rhs.source6, sizeof(lhs.source6)) == 0;
}

static inline switchboard_overlay_machine_route_key switchboardMakeOverlayMachineRouteKey(uint32_t fragment)
{
   switchboard_overlay_machine_route_key key = {};
   key.fragment = fragment;
   return key;
}

static inline bool switchboardParseMACLiteral(const String& text, uint8_t bytes[6])
{
   if (bytes == nullptr || text.size() != 17)
   {
      return false;
   }

   auto hexNibble = [] (char byte, uint8_t& nibble) -> bool {

      if (byte >= '0' && byte <= '9')
      {
         nibble = uint8_t(byte - '0');
         return true;
      }

      if (byte >= 'a' && byte <= 'f')
      {
         nibble = uint8_t(10 + (byte - 'a'));
         return true;
      }

      if (byte >= 'A' && byte <= 'F')
      {
         nibble = uint8_t(10 + (byte - 'A'));
         return true;
      }

      return false;
   };

   for (uint32_t index = 0; index < 6; ++index)
   {
      uint64_t offset = uint64_t(index) * 3u;
      if ((index < 5 && text[offset + 2] != ':') || (index == 5 && (offset + 2) != text.size()))
      {
         return false;
      }

      uint8_t high = 0;
      uint8_t low = 0;
      if (hexNibble(char(text[offset]), high) == false
         || hexNibble(char(text[offset + 1]), low) == false)
      {
         return false;
      }

      bytes[index] = uint8_t((high << 4) | low);
   }

   return true;
}

static inline bool switchboardBuildOverlayMachineRouteValue(const SwitchboardOverlayMachineRoute& route, switchboard_overlay_machine_route& value)
{
   value = {};

   if (route.machineFragment == 0 || route.nextHop.isNull() || route.sourceAddress.isNull())
   {
      return false;
   }

   if (route.nextHop.is6 != route.sourceAddress.is6)
   {
      return false;
   }

   value.family = route.nextHop.is6 ? SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6 : SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV4;
   value.use_gateway_mac = route.useGatewayMAC ? 1u : 0u;

   if (route.useGatewayMAC == false)
   {
      if (switchboardParseMACLiteral(route.nextHopMAC, value.next_hop_mac) == false)
      {
         return false;
      }
   }

   if (route.nextHop.is6)
   {
      std::memcpy(value.next_hop6, route.nextHop.v6, sizeof(value.next_hop6));
      std::memcpy(value.source6, route.sourceAddress.v6, sizeof(value.source6));
   }
   else
   {
      value.next_hop4 = route.nextHop.v4;
      value.source4 = route.sourceAddress.v4;
   }

   return true;
}
