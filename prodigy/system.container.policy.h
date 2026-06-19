#pragma once

#include <arpa/inet.h>
#include <cstdint>

#include <networking/ip.h>
#include <services/prodigy.h>

constexpr static auto mothershipTunnelProviderMothershipSocketPath = "/run/prodigy/mothership.sock"_ctv;
constexpr static auto mothershipTunnelProviderHostGatewaySocketPath = "/run/prodigy/mothership-tunnel-gateway.sock"_ctv;

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
  ownedHost.assign(host.data(), host.size());
  struct in_addr ipv4 = {};
  if (inet_pton(AF_INET, ownedHost.c_str(), &ipv4) != 1)
  {
    address = 0;
    return false;
  }
  address = ntohl(ipv4.s_addr);
  return true;
}

static inline bool prodigySystemEgressPublicIPv4Literal(const String& host, uint32_t& address)
{
  return prodigySystemEgressIPv4Literal(host, address) &&
         prodigySystemEgressIPv4HostAddressIsDenied(address) == false;
}

static inline bool prodigySystemEgressIPv4Text(uint32_t address, String& text)
{
  char buffer[INET_ADDRSTRLEN] = {};
  in_addr ipv4 = {};
  ipv4.s_addr = htonl(address);
  if (inet_ntop(AF_INET, &ipv4, buffer, sizeof(buffer)) == nullptr)
  {
    text.clear();
    return false;
  }
  text.assign(buffer);
  return true;
}
