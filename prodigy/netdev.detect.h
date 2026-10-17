#pragma once

#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/route.h>

#include <fstream>
#include <sstream>

static inline String& prodigyPrimaryNetworkDeviceOverrideStorage(void)
{
  static String deviceName = {};
  return deviceName;
}

static inline void prodigySetPrimaryNetworkDeviceOverride(const String& deviceName)
{
  String& configuredDevice = prodigyPrimaryNetworkDeviceOverrideStorage();
  configuredDevice.clear();
  configuredDevice.assign(deviceName);
}

static inline void prodigySetPrimaryNetworkDeviceOverride(const char *deviceName)
{
  String& configuredDevice = prodigyPrimaryNetworkDeviceOverrideStorage();
  configuredDevice.clear();

  if (deviceName && deviceName[0] != '\0')
  {
    configuredDevice.assign(deviceName);
  }
}

static inline bool prodigyGetPrimaryNetworkDeviceOverride(String& deviceName)
{
  const String& configuredDevice = prodigyPrimaryNetworkDeviceOverrideStorage();
  if (configuredDevice.size() == 0)
  {
    return false;
  }

  deviceName.assign(configuredDevice);
  return true;
}

static inline bool prodigyInterfaceMatchesAddressPolicy(const struct ifaddrs *ifa, bool requirePrivate10, uint32_t *ipv4Out = nullptr)
{
  if (ifa == nullptr || ifa->ifa_name == nullptr || ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET || (ifa->ifa_flags & IFF_LOOPBACK) != 0)
  {
    return false;
  }

  const struct sockaddr_in *address = reinterpret_cast<const struct sockaddr_in *>(ifa->ifa_addr);
  uint32_t private4 = address->sin_addr.s_addr;
  uint32_t hostOrder = ntohl(private4);

  if (requirePrivate10 && (hostOrder & 0xFF000000u) != 0x0A000000u)
  {
    return false;
  }

  if (ipv4Out)
  {
    *ipv4Out = private4;
  }

  return true;
}

static inline bool prodigyFindGlobalIPv6Address(
    const struct ifaddrs *interfaces, const String& deviceName, IPAddress& global6)
{
  global6 = {};
  if (deviceName.empty())
  {
    return false;
  }

  for (const struct ifaddrs *ifa = interfaces; ifa != nullptr; ifa = ifa->ifa_next)
  {
    const size_t interfaceNameLength = ifa->ifa_name == nullptr ? 0 : std::strlen(ifa->ifa_name);
    if (ifa->ifa_name == nullptr || deviceName.size() != interfaceNameLength ||
        std::memcmp(deviceName.data(), ifa->ifa_name, interfaceNameLength) != 0 ||
        ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET6)
    {
      continue;
    }

    const struct sockaddr_in6 *address =
        reinterpret_cast<const struct sockaddr_in6 *>(ifa->ifa_addr);
    if ((address->sin6_addr.s6_addr[0] & 0xe0u) != 0x20u)
    {
      continue;
    }

    memcpy(global6.v6, address->sin6_addr.s6_addr, sizeof(global6.v6));
    global6.is6 = true;
    return true;
  }

  return false;
}

static inline IPAddress prodigyGetGlobalIPv6Address(const String& deviceName)
{
  IPAddress global6 = {};
  struct ifaddrs *interfaces = nullptr;
  if (getifaddrs(&interfaces) == 0 && interfaces != nullptr)
  {
    (void)prodigyFindGlobalIPv6Address(interfaces, deviceName, global6);
    freeifaddrs(interfaces);
  }
  return global6;
}

static inline bool prodigyResolvePrimaryNetworkDevice(String& deviceName)
{
  if (prodigyGetPrimaryNetworkDeviceOverride(deviceName))
  {
    return true;
  }

  auto interfaceHasUsableIPv4 = [](const std::string& candidate, bool requirePrivate10) -> bool {
    struct ifaddrs *interfaces = nullptr;
    if (getifaddrs(&interfaces) != 0 || interfaces == nullptr)
    {
      return false;
    }

    bool found = false;
    for (const struct ifaddrs *ifa = interfaces; ifa != nullptr; ifa = ifa->ifa_next)
    {
      if (ifa->ifa_name == nullptr || candidate != ifa->ifa_name)
      {
        continue;
      }

      if (prodigyInterfaceMatchesAddressPolicy(ifa, requirePrivate10))
      {
        found = true;
        break;
      }
    }

    freeifaddrs(interfaces);
    return found;
  };

  std::ifstream routeFile("/proc/net/route");
  if (routeFile.is_open())
  {
    std::string line;
    std::getline(routeFile, line);

    while (std::getline(routeFile, line))
    {
      std::istringstream stream(line);
      std::string ifaceName;
      std::string destinationHex;
      std::string gatewayHex;
      unsigned long flags = 0;

      if (!(stream >> ifaceName >> destinationHex >> gatewayHex >> std::hex >> flags))
      {
        continue;
      }

      if (destinationHex != "00000000" || (flags & RTF_UP) == 0)
      {
        continue;
      }

      if (interfaceHasUsableIPv4(ifaceName, true) || interfaceHasUsableIPv4(ifaceName, false))
      {
        deviceName.assign(ifaceName.c_str());
        return true;
      }
    }
  }

  struct ifaddrs *interfaces = nullptr;
  if (getifaddrs(&interfaces) != 0 || interfaces == nullptr)
  {
    return false;
  }

  std::string fallback;
  for (const struct ifaddrs *ifa = interfaces; ifa != nullptr; ifa = ifa->ifa_next)
  {
    if (prodigyInterfaceMatchesAddressPolicy(ifa, true))
    {
      deviceName.assign(ifa->ifa_name);
      freeifaddrs(interfaces);
      return true;
    }

    if (fallback.empty() && prodigyInterfaceMatchesAddressPolicy(ifa, false))
    {
      fallback.assign(ifa->ifa_name);
    }
  }

  freeifaddrs(interfaces);

  if (fallback.empty() == false)
  {
    deviceName.assign(fallback.c_str());
    return true;
  }

  return false;
}
