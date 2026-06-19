#pragma once

#include <arpa/inet.h>
#include <cstdint>

#include <networking/ip.h>
#include <services/prodigy.h>

static inline bool prodigySystemEgressIPv4HostAddressIsDenied(uint32_t address)
{
  return isRFC1918Private4(htonl(address)) ||
      (address >> 24) == 0 ||
      (address >> 24) == 127 ||
      (address >> 24) >= 224 ||
      (address & 0xffff0000u) == 0xa9fe0000u ||
      (address & 0xffc00000u) == 0x64400000u ||
      (address & 0xffffff00u) == 0xc0000000u ||
      (address & 0xffffff00u) == 0xc0000200u ||
      (address & 0xffffff00u) == 0xc0586300u ||
      (address & 0xfffe0000u) == 0xc6120000u ||
      (address & 0xffffff00u) == 0xc6336400u ||
      (address & 0xffffff00u) == 0xcb007100u;
}

static inline bool prodigySystemEgressIPv4Literal(const String& host, uint32_t& address)
{
  String ownedHost = {};
  ownedHost.assign(host);
  struct in_addr ipv4 = {};
  if (inet_pton(AF_INET, ownedHost.c_str(), &ipv4) != 1)
  {
    address = 0;
    return false;
  }
  address = ntohl(ipv4.s_addr);
  return true;
}
