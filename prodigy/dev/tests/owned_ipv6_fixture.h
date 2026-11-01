#pragma once

#include <networking/includes.h>
#include <cstring>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>

// Pure socket fixtures must use an address the test process already owns. Never
// configure interfaces or silently substitute loopback for the private path.
static inline bool prodigyTestOwnedULA(IPAddress& address)
{
  address = {};
  ifaddrs *interfaces = nullptr;
  if (getifaddrs(&interfaces) != 0) return false;
  for (auto *item = interfaces; item; item = item->ifa_next) {
    if (!item->ifa_addr || item->ifa_addr->sa_family != AF_INET6 ||
        !(item->ifa_flags & IFF_UP) || (item->ifa_flags & IFF_LOOPBACK)) continue;
    const auto& candidate = *reinterpret_cast<const sockaddr_in6 *>(item->ifa_addr);
    if (candidate.sin6_scope_id != 0 || (candidate.sin6_addr.s6_addr[0] & 0xfeu) != 0xfcu) continue;
    address.is6 = true;
    std::memcpy(address.v6, candidate.sin6_addr.s6_addr, 16);
    break;
  }
  freeifaddrs(interfaces);
  return !address.isNull();
}
