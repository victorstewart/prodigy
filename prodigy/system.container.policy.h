#pragma once

#include <arpa/inet.h>
#include <cstdint>

#include <networking/ip.h>
#include <services/prodigy.h>
#include <switchboard/common/public.destination.h>

constexpr static auto mothershipTunnelProviderMothershipSocketPath = "/run/prodigy/mothership.sock"_ctv;
constexpr static auto mothershipTunnelProviderHostGatewaySocketPath = "/run/prodigy/mothership-tunnel-gateway.sock"_ctv;

static inline bool prodigySystemEgressIPv4HostAddressIsDenied(uint32_t address)
{
  return switchboardPublicDestinationIPv4(htonl(address)) == false;
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
