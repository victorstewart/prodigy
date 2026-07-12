#pragma once

#include <linux/types.h>
#include <macros/datacenter.h>

// IANA IPv4 Address Space and Special-Purpose registries, 2025-10-09.
static inline bool switchboardPublicDestinationIPv4(__be32 address)
{
  const __u8 *octets = (const __u8 *)&address;
  const __u8 a = octets[0], b = octets[1], c = octets[2];

  if (a == 192 && b == 0 && c == 0 && (octets[3] == 9 || octets[3] == 10))
  {
    return true;
  }

  if (a == 0 || a == 10 || a == 127 || a >= 224 ||
      (a == 100 && (b & 0xc0u) == 0x40u) ||
      (a == 169 && b == 254) ||
      (a == 168 && b == 63 && c == 129 && octets[3] == 16) ||
      (a == 172 && (b & 0xf0u) == 16u) ||
      (a == 192 && ((b == 0 && c == 0) ||
                    (b == 0 && c == 2) ||
                    (b == 88 && c == 99) ||
                    b == 168)) ||
      (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100))) ||
      (a == 203 && b == 0 && c == 113))
  {
    return false;
  }

  return a <= 223;
}

static inline __u16 switchboardIPv6Word(const __u8 address[16], __u8 index)
{
  return ((__u16)address[index * 2u] << 8u) | address[index * 2u + 1u];
}

static inline __be32 switchboardEmbeddedIPv4(const __u8 address[16])
{
  __be32 embedded = 0;
  __u8 *bytes = (__u8 *)&embedded;
  for (__u8 index = 0; index < 4; ++index)
  {
    bytes[index] = address[index + 12];
  }
  return embedded;
}

static inline bool switchboardContainerDestinationIPv6(const __u8 address[16])
{
  static const __u8 prefix[11] = CONTAINER_NETWORK_SUBNET6;
  for (__u8 index = 0; index < sizeof(prefix); ++index)
  {
    if (address[index] != prefix[index])
    {
      return false;
    }
  }
  return true;
}

// IANA IPv6 Global Unicast and Special-Purpose registries, 2025-10-10.
// Unlisted 2000::/3 space is reserved, so this is intentionally an allocation
// whitelist rather than a broad global-unicast test.
static inline bool switchboardPublicDestinationIPv6(const __u8 address[16])
{
  if (switchboardContainerDestinationIPv6(address))
  {
    return false;
  }

  const __u16 first = switchboardIPv6Word(address, 0);
  const __u16 second = switchboardIPv6Word(address, 1);
  if (((first == 0 && second == 0 && switchboardIPv6Word(address, 2) == 0 &&
        switchboardIPv6Word(address, 3) == 0 && switchboardIPv6Word(address, 4) == 0 &&
        switchboardIPv6Word(address, 5) == 0xffffu)) ||
      (first == 0x0064u && second == 0xff9bu && switchboardIPv6Word(address, 2) == 0 &&
       switchboardIPv6Word(address, 3) == 0 && switchboardIPv6Word(address, 4) == 0 &&
       switchboardIPv6Word(address, 5) == 0))
  {
    return switchboardPublicDestinationIPv4(switchboardEmbeddedIPv4(address));
  }
  bool allocated = false;

  if (first == 0x2001u &&
      ((second == 0x0001u && switchboardIPv6Word(address, 2) == 0 &&
        switchboardIPv6Word(address, 3) == 0 && switchboardIPv6Word(address, 4) == 0 &&
        switchboardIPv6Word(address, 5) == 0 && switchboardIPv6Word(address, 6) == 0 &&
        switchboardIPv6Word(address, 7) >= 1 && switchboardIPv6Word(address, 7) <= 3) ||
       second == 0x0003u ||
       (second == 0x0004u && switchboardIPv6Word(address, 2) == 0x0112u)))
  {
    return true;
  }

  if (first == 0x2001u)
  {
    allocated = ((second & 0xfe00u) == 0x0200u) ||
                ((second & 0xfe00u) == 0x0400u) ||
                ((second & 0xfe00u) == 0x0600u) ||
                ((second & 0xfc00u) == 0x0800u) ||
                ((second & 0xfe00u) == 0x0c00u) ||
                ((second & 0xfe00u) == 0x0e00u) ||
                ((second & 0xfe00u) == 0x1200u) ||
                ((second & 0xfc00u) == 0x1400u) ||
                ((second & 0xfe00u) == 0x1800u) ||
                ((second & 0xfe00u) == 0x1a00u) ||
                ((second & 0xfc00u) == 0x1c00u) ||
                ((second & 0xe000u) == 0x2000u) ||
                (second >= 0x4000u && second <= 0x4dffu) ||
                ((second & 0xf000u) == 0x5000u) ||
                ((second & 0xe000u) == 0x8000u) ||
                ((second & 0xf000u) == 0xa000u) ||
                ((second & 0xf000u) == 0xb000u);

    // Documentation is a special-purpose sub-prefix of 2001:c00::/23.
    if (second == 0x0db8u)
    {
      return false;
    }
  }
  else if (first == 0x2003u)
  {
    allocated = (second & 0xc000u) == 0;
  }
  else if ((first >= 0x2400u && first <= 0x241fu) ||
           (first >= 0x2600u && first <= 0x260fu) ||
           (first == 0x2610u && second <= 0x01ffu) ||
           (first == 0x2620u && second <= 0x01ffu) ||
           (first >= 0x2630u && first <= 0x263fu) ||
           (first >= 0x2800u && first <= 0x280fu) ||
           (first >= 0x2a00u && first <= 0x2a1fu) ||
           (first >= 0x2c00u && first <= 0x2c0fu))
  {
    allocated = true;
  }

  // 2001::/23 and 2002::/16 are non-global special-purpose space apart from
  // the exact globally reachable protocol assignments above.
  if (first == 0x2002u)
  {
    return false;
  }

  return allocated;
}
