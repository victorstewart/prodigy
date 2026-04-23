#pragma once

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <cerrno>
#include <cstring>
#include <cstdlib>

#include <prodigy/types.h>

static inline bool prodigyParsePeerAddressCIDRLiteral(const String& literal, ClusterMachinePeerAddress& candidate)
{
   candidate = {};

   if (literal.size() == 0)
   {
      return false;
   }

   uint64_t slashOffset = literal.size();
   for (uint64_t index = literal.size(); index > 0; --index)
   {
      if (literal[index - 1] == '/')
      {
         slashOffset = index - 1;
         break;
      }
   }

   String addressText = {};
   if (slashOffset < literal.size())
   {
      addressText.assign(literal.substr(0, slashOffset, Copy::yes));

      String prefixText = {};
      prefixText.assign(literal.substr(slashOffset + 1, literal.size() - slashOffset - 1, Copy::yes));
      char *tail = nullptr;
      errno = 0;
      unsigned long long parsedCidr = std::strtoull(prefixText.c_str(), &tail, 10);
      if (errno != 0 || tail == prefixText.c_str() || (tail && *tail != '\0') || parsedCidr > 255ull)
      {
         return false;
      }

      candidate.cidr = uint8_t(parsedCidr);
   }
   else
   {
      addressText.assign(literal);
   }

   candidate.address = addressText;
   ClusterMachinePeerAddress normalized = {};
   if (prodigyNormalizeClusterMachinePeerAddress(candidate, normalized) == false)
   {
      return false;
   }

   candidate = normalized;
   return true;
}

static inline uint8_t prodigyPrefixLengthFromSockaddrNetmask(const struct sockaddr *netmask)
{
   if (netmask == nullptr)
   {
      return 0;
   }

   if (netmask->sa_family == AF_INET)
   {
      const struct sockaddr_in *in4 = reinterpret_cast<const struct sockaddr_in *>(netmask);
      uint32_t mask = ntohl(in4->sin_addr.s_addr);
      uint8_t prefixLength = 0;
      while (mask & 0x80000000u)
      {
         prefixLength += 1;
         mask <<= 1;
      }
      return prefixLength;
   }

   if (netmask->sa_family == AF_INET6)
   {
      const struct sockaddr_in6 *in6 = reinterpret_cast<const struct sockaddr_in6 *>(netmask);
      uint8_t prefixLength = 0;
      for (uint32_t index = 0; index < 16; ++index)
      {
         uint8_t byte = in6->sin6_addr.s6_addr[index];
         while (byte & 0x80u)
         {
            prefixLength += 1;
            byte <<= 1;
         }

         if (byte != 0)
         {
            break;
         }
      }

      return prefixLength;
   }

   return 0;
}

static inline void prodigyCollectLocalPeerAddressCandidates(const String& preferredInterface, const IPAddress& fallbackPrivate4, Vector<ClusterMachinePeerAddress>& candidates)
{
   candidates.clear();

   auto collect = [&] (bool preferredOnly) -> void
   {
      struct ifaddrs *interfaces = nullptr;
      if (getifaddrs(&interfaces) != 0 || interfaces == nullptr)
      {
         return;
      }

      for (const struct ifaddrs *ifa = interfaces; ifa != nullptr; ifa = ifa->ifa_next)
      {
         if (ifa->ifa_addr == nullptr || ifa->ifa_name == nullptr || (ifa->ifa_flags & IFF_LOOPBACK) != 0)
         {
            continue;
         }

         if (preferredOnly
            && preferredInterface.size() > 0
            && (std::strncmp(reinterpret_cast<const char *>(preferredInterface.data()), ifa->ifa_name, preferredInterface.size()) != 0
               || ifa->ifa_name[preferredInterface.size()] != '\0'))
         {
            continue;
         }

         ClusterMachinePeerAddress candidate = {};
         if (ifa->ifa_addr->sa_family == AF_INET)
         {
            const struct sockaddr_in *in4 = reinterpret_cast<const struct sockaddr_in *>(ifa->ifa_addr);
            candidate.address.assign(inet_ntoa(in4->sin_addr));
            candidate.cidr = prodigyPrefixLengthFromSockaddrNetmask(ifa->ifa_netmask);
         }
         else if (ifa->ifa_addr->sa_family == AF_INET6)
         {
            const struct sockaddr_in6 *in6 = reinterpret_cast<const struct sockaddr_in6 *>(ifa->ifa_addr);
            if ((in6->sin6_addr.s6_addr[0] == 0xfe && (in6->sin6_addr.s6_addr[1] & 0xc0) == 0x80))
            {
               continue;
            }

            IPAddress address = {};
            memcpy(address.v6, &in6->sin6_addr, sizeof(in6->sin6_addr));
            address.is6 = true;
            if (ClusterMachine::renderIPAddressLiteral(address, candidate.address) == false)
            {
               continue;
            }

            candidate.cidr = prodigyPrefixLengthFromSockaddrNetmask(ifa->ifa_netmask);
         }
         else
         {
            continue;
         }

         prodigyAppendUniqueClusterMachinePeerAddress(candidates, candidate);
      }

      freeifaddrs(interfaces);
   };

   if (preferredInterface.size() > 0)
   {
      collect(true);
   }

   if (candidates.empty())
   {
      collect(false);
   }

   if (fallbackPrivate4.v4 != 0)
   {
      String private4Text = {};
      if (ClusterMachine::renderIPAddressLiteral(fallbackPrivate4, private4Text))
      {
         prodigyAppendUniqueClusterMachinePeerAddress(candidates, ClusterMachinePeerAddress{private4Text, 0});
      }
   }
}

static inline bool prodigyResolvePreferredLocalSourceAddress(
   const Vector<ClusterMachinePeerAddress>& localCandidates,
   const ClusterMachinePeerAddress& remoteCandidate,
   IPAddress& sourceAddress,
   String *sourceAddressText = nullptr)
{
   sourceAddress = {};
   if (sourceAddressText)
   {
      sourceAddressText->clear();
   }

   IPAddress remoteAddress = {};
   if (ClusterMachine::parseIPAddressLiteral(remoteCandidate.address, remoteAddress) == false)
   {
      return false;
   }

   bool remoteIsPrivate = prodigyClusterMachinePeerAddressIsPrivate(remoteCandidate);
   String remotePrivateSubnet = {};
   bool haveRemotePrivateSubnet = prodigyClusterMachinePeerAddressSubnetKey(remoteCandidate, remotePrivateSubnet, true);
   String remoteSubnet = {};
   bool haveRemoteSubnet = prodigyClusterMachinePeerAddressSubnetKey(remoteCandidate, remoteSubnet, false);

   int bestScore = -1;
   for (const ClusterMachinePeerAddress& localCandidate : localCandidates)
   {
      IPAddress localAddress = {};
      if (ClusterMachine::parseIPAddressLiteral(localCandidate.address, localAddress) == false)
      {
         continue;
      }

      if (localAddress.is6 != remoteAddress.is6)
      {
         continue;
      }

      int score = 10;
      bool localIsPrivate = prodigyClusterMachinePeerAddressIsPrivate(localCandidate);
      if (localIsPrivate == remoteIsPrivate)
      {
         score += 20;
      }

      String localPrivateSubnet = {};
      if (haveRemotePrivateSubnet
         && prodigyClusterMachinePeerAddressSubnetKey(localCandidate, localPrivateSubnet, true)
         && localPrivateSubnet.equals(remotePrivateSubnet))
      {
         score += 100;
      }

      String localSubnet = {};
      if (haveRemoteSubnet
         && prodigyClusterMachinePeerAddressSubnetKey(localCandidate, localSubnet, false)
         && localSubnet.equals(remoteSubnet))
      {
         score += 40;
      }

      if (score > bestScore)
      {
         bestScore = score;
         sourceAddress = localAddress;
         if (sourceAddressText)
         {
            sourceAddressText->assign(localCandidate.address);
         }
      }
   }

   return bestScore >= 0;
}
