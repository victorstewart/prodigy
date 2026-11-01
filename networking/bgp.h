#pragma once

#include <array>
#include <cstring>
#ifdef __linux__
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#endif

class IPAddress;

enum class BGPState : uint8_t {

  idle = 0,
  opensent,
  openconfirm,
  established,
  failed
};

constexpr static uint16_t BGP_AFI_IPV6 = 2;
constexpr static uint8_t BGP_SAFI_UNICAST = 1;
constexpr static uint32_t BGP_IPV6_UNICAST_IMPORT_MAX_NLRI = 128;
// CONNECT-IP forwards the connector's inner packet once before delivery.
constexpr static uint8_t BGP_PRIVATE_MASQUE_HOP_LIMIT = 2;
#ifdef __linux__
static inline bool bgpConfigurePrivateMasqueHopLimit(int fd)
{
  const int hopLimit = BGP_PRIVATE_MASQUE_HOP_LIMIT;
  return fd >= 0 && setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hopLimit, sizeof(hopLimit)) == 0;
}
#endif

// This is a pure desired-state transition.  The owner of a BGP session uses
// it to make announcement and withdrawal reconciliation idempotent without
// letting a control-plane projection send on a socket itself.
enum class BGPIPv6UnicastAdvertisementAction : uint8_t { none = 0, announce, withdraw };

static inline bool bgpIPv6UnicastAdvertisementActionValid(BGPIPv6UnicastAdvertisementAction action)
{
  return action == BGPIPv6UnicastAdvertisementAction::none ||
      action == BGPIPv6UnicastAdvertisementAction::announce ||
      action == BGPIPv6UnicastAdvertisementAction::withdraw;
}

static inline BGPIPv6UnicastAdvertisementAction bgpIPv6UnicastAdvertisementTransition(
    bool currentlyAdvertised, bool shouldAdvertise)
{
  if (currentlyAdvertised == shouldAdvertise) return BGPIPv6UnicastAdvertisementAction::none;
  return shouldAdvertise ? BGPIPv6UnicastAdvertisementAction::announce :
      BGPIPv6UnicastAdvertisementAction::withdraw;
}

struct BGPIPv6UnicastImport {
  std::array<uint8_t, 16> prefix = {};
  std::array<uint8_t, 16> nextHop = {};
  uint8_t cidr = 0;
  bool withdrawn = false;
};

using BGPIPv6UnicastImportObserver = void (*)(void *, const BGPIPv6UnicastImport&);
// State changes are emitted by the hub, rather than inferred by an owner from
// socket lifetime.  A route imported from a session must disappear as soon as
// that session stops being established.
using BGPSessionStateObserver = void (*)(void *, const IPAddress&, bool established);

static inline bool bgpIPv6UnicastNextHopValid(const uint8_t *nextHop)
{
  if (nextHop == nullptr || nextHop[0] == 0xff || (nextHop[0] == 0xfe && (nextHop[1] & 0xc0u) == 0x80u)) return false;
  uint8_t aggregate = 0;
  for (uint32_t index = 0; index < 16; ++index) aggregate |= nextHop[index];
  return aggregate != 0;
}

static inline bool bgpDecodeCanonicalIPv6NLRI(const uint8_t *&cursor, const uint8_t *tail,
                                              BGPIPv6UnicastImport& imported)
{
  if (cursor == tail) return false;
  imported.cidr = *cursor++;
  if (imported.cidr > 128) return false;
  const uint8_t bytes = uint8_t((imported.cidr + 7) / 8);
  if (size_t(tail - cursor) < bytes) return false;
  imported.prefix = {};
  if (bytes != 0) std::memcpy(imported.prefix.data(), cursor, bytes);
  if ((imported.cidr & 7u) != 0 && (imported.prefix[bytes - 1] & uint8_t((1u << (8u - (imported.cidr & 7u))) - 1u)) != 0) return false;
  cursor += bytes;
  return true;
}

// Parses only MP_REACH_NLRI and MP_UNREACH_NLRI IPv6-unicast attributes from
// one BGP UPDATE body. It is deliberately observer-only: no kernel route or
// peer state is changed. Results are emitted only after the entire UPDATE is
// structurally valid, preventing partial imports from malformed messages.
static inline bool bgpObserveIPv6UnicastUpdate(const uint8_t *body, size_t length,
                                               BGPIPv6UnicastImportObserver observer, void *context)
{
  if (body == nullptr || observer == nullptr || length < 4) return false;
  const uint8_t *cursor = body, *tail = body + length;
  auto read16 = [&](uint16_t& value) -> bool {
    if (size_t(tail - cursor) < 2) return false;
    value = uint16_t(cursor[0]) << 8 | uint16_t(cursor[1]); cursor += 2; return true;
  };
  uint16_t withdrawnLength = 0, attributesLength = 0;
  if (!read16(withdrawnLength) || size_t(tail - cursor) < withdrawnLength) return false;
  // IPv6-only import sessions must not silently skip legacy IPv4 NLRI. A
  // nonempty section would otherwise invalidate the whole-UPDATE fence.
  if (withdrawnLength != 0) return false;
  cursor += withdrawnLength; // legacy IPv4 withdrawn NLRI
  if (!read16(attributesLength) || size_t(tail - cursor) < attributesLength) return false;
  const uint8_t *attributesTail = cursor + attributesLength;
  std::array<BGPIPv6UnicastImport, BGP_IPV6_UNICAST_IMPORT_MAX_NLRI> imports = {};
  uint32_t count = 0;
  auto append = [&](const BGPIPv6UnicastImport& imported) -> bool {
    if (count >= imports.size()) return false;
    imports[count++] = imported; return true;
  };
  while (cursor < attributesTail)
  {
    if (size_t(attributesTail - cursor) < 3) return false;
    const uint8_t flags = *cursor++, type = *cursor++;
    uint16_t attributeLength = *cursor++;
    if (flags & 0x10u) { if (size_t(attributesTail - cursor) < 1) return false; attributeLength = uint16_t(attributeLength) << 8 | *cursor++; }
    if (size_t(attributesTail - cursor) < attributeLength) return false;
    const uint8_t *attributeTail = cursor + attributeLength;
    if (type == 14 || type == 15)
    {
      if (size_t(attributeTail - cursor) < 3) return false;
      const uint16_t afi = uint16_t(cursor[0]) << 8 | uint16_t(cursor[1]); cursor += 2;
      const uint8_t safi = *cursor++;
      if (afi == BGP_AFI_IPV6 && safi == BGP_SAFI_UNICAST)
      {
        BGPIPv6UnicastImport imported = {}; imported.withdrawn = type == 15;
        if (type == 14)
        {
          if (cursor == attributeTail) return false;
          const uint8_t nextHopLength = *cursor++;
          if ((nextHopLength != 16 && nextHopLength != 32) || size_t(attributeTail - cursor) < size_t(nextHopLength) + 1) return false;
          std::memcpy(imported.nextHop.data(), cursor, imported.nextHop.size());
          if (!bgpIPv6UnicastNextHopValid(imported.nextHop.data())) return false;
          cursor += nextHopLength;
          if (*cursor++ != 0) return false;
        }
        while (cursor < attributeTail) { BGPIPv6UnicastImport next = imported; if (!bgpDecodeCanonicalIPv6NLRI(cursor, attributeTail, next) || !append(next)) return false; }
      }
    }
    cursor = attributeTail;
  }
  // The legacy IPv4 NLRI tail follows the attribute block. Reject it rather
  // than accepting a partially validated UPDATE on an IPv6 import session.
  if (attributesTail != tail) return false;
  for (uint32_t index = 0; index < count; ++index) observer(context, imports[index]);
  return true;
}

// https://datatracker.ietf.org/doc/html/rfc4271
#ifdef __linux__
#include <netinet/tcp.h> // TCP_MD5SIG
#include <services/debug.h>
#endif
#include <netinet/in.h>

template <typename T> requires (std::is_integral_v<std::remove_reference_t<T>>)
constexpr static inline T reverseByteOrder(T value)
{
  T reversed = 0;

  for (size_t i = 0; i < sizeof(T); i += 1)
  {
    reversed <<= 8;
    reversed |= (value & 0xFF);
    value >>= 8;
  }

  return reversed;
}

class BGPPrivateListener;

class BGPPeer : public StreamBase, public TCPSocket {
private:

  uint8_t nBytesForCIDR(uint8_t cidr)
  {
    uint8_t nBytes = cidr / 8;
    if ((cidr % 8) > 0)
    {
      nBytes += 1;
    }

    return nBytes;
  }

  void printMessage(const String& message) // auto assume the message is valid
  {
    uint8_t *cursor = message.data();
    const uint8_t *tail = message.pTail();

    // basics_log_hex("message:", cursor, tail - cursor);

    auto extractLambda = [&]<typename T, bool reverse = true, typename Lambda>(Lambda&& lambda) -> void {
      T value;
      memcpy(&value, cursor, sizeof(T));
      if constexpr (reverse && sizeof(T) > 1)
      {
        value = reverseByteOrder(value);
      }
      cursor += sizeof(T);
      lambda(value);
    };

    auto extract = [&]<typename T, bool reverse = true>(void) -> T {
      T value;
      memcpy(&value, cursor, sizeof(T));
      if constexpr (reverse && sizeof(T) > 1)
      {
        value = reverseByteOrder(value);
      }
      cursor += sizeof(T);
      return value;
    };

    auto extractPrint = [&]<typename T>(const char *format) -> void {
      extractLambda.template operator()<T>([&](T value) -> void {
        basics_log(format, value);
      });
    };

    auto extractPrintAFI = [&](const char *shift) -> uint16_t {
      uint16_t value = 0;

      extractLambda.template operator()<uint16_t>([&](uint16_t AFI) -> void {
        switch (AFI)
        {
          case 1:
            {
              basics_log("%sAFI: IPv4\n", shift);
              break;
            }
          case 2:
            {
              basics_log("%sAFI: IPv6\n", shift);
              break;
            }
          default:
            {
              basics_log("%sAFI: other = %hu\n", shift, AFI);
              break;
            }
        }

        value = AFI;
      });

      return value;
    };

    auto extractPrintSAFI = [&](const char *shift) -> void {
      extractLambda.template operator()<uint8_t>([&](uint8_t SAFI) -> void {
        switch (SAFI)
        {
          case 1:
            {
              basics_log("%sSAFI: unicast\n", shift);
              break;
            }
          case 2:
            {
              basics_log("%sSAFI: multicast\n", shift);
              break;
            }
          default:
            {
              basics_log("%sSAFI: other = %hhu\n", shift, SAFI);
              break;
            }
        }
      });
    };

    cursor += 16; // marker

    uint16_t message_len = extract.template operator()<uint16_t>();
    uint8_t message_type = extract.template operator()<uint8_t>();

    switch (message_type)
    {
      case 1: // Open
        {
          basics_log("Open Message\n");

          extractPrint.template operator()<uint8_t>("\tVersion: %hhu\n");
          extractPrint.template operator()<uint16_t>("\tASN: %hu\n");
          extractPrint.template operator()<uint16_t>("\tHold Time: %hu\n");

          extractLambda.template operator()<struct in_addr, false>([&](struct in_addr bgpid) -> void {
            basics_log("\tBGP ID: %s\n", inet_ntoa(bgpid));
          });

          uint8_t options_len = extract.template operator()<uint8_t>();

          if (options_len > 0)
          {
            uint8_t optional_code = extract.template operator()<uint8_t>();
            uint8_t optional_len = extract.template operator()<uint8_t>();

            if (optional_code == 2) // capbilities
            {
              do
              {
                uint8_t capability_code = extract.template operator()<uint8_t>();
                uint8_t capability_len = extract.template operator()<uint8_t>();

                // ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:39:01:04:ff:fa:00:b4:56:6d:0d:13:1c:02:1a:02:00:46:00:41:04:00:00:ff:fa:01:04:00:02:00:01:40:02:41:2c:45:04:00:02:01:01

                // https://www.rfc-editor.org/rfc/rfc2918.html
                // "This capability is advertised using the Capability code 2 and Capability length 0"
                switch (capability_code)
                {
                  case 1:
                    {
                      basics_log("\tMP-BGP\n");

                      extractPrintAFI("\t\t");

                      cursor += 1; // reserved

                      extractPrintSAFI("\t\t");
                      break;
                    }
                  case 2:
                    {
                      basics_log("\tRoute Refresh\n");
                      break;
                    }
                  case 3:
                    {
                      basics_log("\tOutbound Route Filtering\n");
                      break;
                    }
                  case 5:
                    {
                      basics_log("\tExtended Next Hop Encoding\n");
                      break;
                    }
                  case 6:
                    {
                      basics_log("\tBGP Extended Message\n");
                      break;
                    }
                  case 7:
                    {
                      basics_log("\tBGPsec\n");
                      break;
                    }
                  case 8:
                    {
                      basics_log("\tMultiple Labels\n");
                      break;
                    }
                  case 9:
                    {
                      basics_log("\tBGP Role\n");
                      break;
                    }
                  case 64:
                    {
                      basics_log("\tGraceful Restart\n");
                      break;
                    }
                  case 65:
                    {
                      basics_log("\t4-octet AS number\n");
                      break;
                    }
                  case 67:
                    {
                      basics_log("\tDynamic Capability\n");
                      break;
                    }
                  case 68:
                    {
                      basics_log("\tMultisession BGP\n");
                      break;
                    }
                  case 69:
                    {
                      basics_log("\tADD-PATH\n");
                      break;
                    }
                  case 70:
                    {
                      basics_log("\tEnhanced Route Refresh\n");
                      break;
                    }
                  case 71:
                    {
                      basics_log("\tLong-Lived Graceful Restart\n");
                      break;
                    }
                  case 72:
                    {
                      basics_log("\tRouting Policy Distribution\n");
                      break;
                    }
                  case 73:
                    {
                      basics_log("\tFQDN\n");
                      break;
                    }
                  case 74:
                    {
                      basics_log("\tBFD\n");
                      break;
                    }
                  case 75:
                    {
                      basics_log("\tSoftware Version \n");
                      break;
                    }
                  case 76:
                    {
                      basics_log("\tPATHS-LIMIT\n");
                      break;
                    }
                  default:
                    {
                      basics_log("\tother capability = %hhu\n", capability_code);
                      break;
                    }
                }

                switch (capability_code)
                {
                  case 1:
                    {
                      break;
                    }
                  default:
                    {
                      cursor += capability_len;
                      break;
                    }
                }

              } while (cursor < tail);
            }
            else
            {
              cursor += optional_len;
            }
          }

          break;
        }
      case 2: // Update
        {
          basics_log("Update Message:\n");
          uint16_t withdrawn_len = extract.template operator()<uint16_t>();

          if (withdrawn_len > 0)
          {
            const uint8_t *withdrawn_tail = cursor + withdrawn_len;

            basics_log("\tWithdrawn IPv4 Routes:\n");

            do
            {
              uint8_t cidr = extract.template operator()<uint8_t>();

              struct in_addr prefix = {};

              if (cidr > 0)
              {
                uint8_t byte_len = cidr / 8;
                if (cidr % 8 > 0)
                {
                  byte_len += 1;
                }

                memcpy(&prefix, cursor, byte_len);
                cursor += byte_len;
              }

              basics_log("\t\t%s/%s\n", inet_ntoa(prefix), cidr);

            } while (cursor < withdrawn_tail);
          }

          uint16_t pathattributes_len = extract.template operator()<uint16_t>();

          if (pathattributes_len > 0)
          {
            const uint8_t *pathattributes_tail = cursor + pathattributes_len;

            basics_log("\tPath Attributes:\n");

            auto printFlags = [](uint8_t flags) -> void {
              basics_log("\t\t\tFlags: ");

              if (flags & 0x80)
              {
                basics_log("Optional ");
              }
              if (flags & 0x40)
              {
                basics_log("Transitive ");
              }
              if (flags & 0x20)
              {
                basics_log("Partial ");
              }
              if (flags & 0x10)
              {
                basics_log("Extended Length ");
              }

              basics_log("\n");
            };

            do
            {
              uint8_t flags = extract.template operator()<uint8_t>();
              uint8_t type_code = extract.template operator()<uint8_t>();
              uint8_t attrib_len = extract.template operator()<uint8_t>();

              switch (type_code)
              {
                case 1:
                  {
                    basics_log("\t\tORIGIN:\n");
                    printFlags(flags);

                    extractLambda.template operator()<uint8_t>([&](uint8_t origin) -> void {
                      switch (origin)
                      {
                        case 0:
                          {
                            basics_log("\t\t\tIGP");
                            break;
                          }
                        case 1:
                          {
                            basics_log("\t\t\tEGP");
                            break;
                          }
                        case 2:
                          {
                            basics_log("\t\t\tIncomplete");
                            break;
                          }
                      }

                      basics_log("\n");
                    });

                    basics_log("\n");

                    break;
                  }
                case 2:
                  {
                    basics_log("\t\tAS_PATH:\n");
                    printFlags(flags);

                    extractLambda.template operator()<uint8_t>([&](uint8_t sequence) -> void {
                      switch (sequence)
                      {
                        case 1:
                          {
                            basics_log("\t\t\tAS_SET");
                            break;
                          }
                        case 2:
                          {
                            basics_log("\t\t\tAS_SEQUENCE");
                            break;
                          }
                      }

                      basics_log("\n");
                    });

                    uint8_t nASNs = extract.template operator()<uint8_t>();

                    do
                    {
                      extractPrint.template operator()<uint16_t>("\t\t\t%hu\n");

                    } while (--nASNs > 0);

                    basics_log("\n");

                    break;
                  }
                case 3:
                  {
                    basics_log("\t\tNEXT_HOP:\n"); // ipv4 only
                    printFlags(flags);

                    extractLambda.template operator()<struct in_addr, false>([&](struct in_addr next_hop) -> void {
                      basics_log("\t\t\t%s\n", inet_ntoa(next_hop));
                    });

                    basics_log("\n");

                    break;
                  }
                case 4:
                  {
                    basics_log("\t\tMULTI_EXIT_DISC:\n");
                    cursor += attrib_len;
                    break;
                  }
                case 5:
                  {
                    basics_log("\t\tLOCAL_PREF:\n");
                    cursor += attrib_len;
                    break;
                  }
                case 6:
                  {
                    basics_log("\t\tATOMIC_AGGREGATE:\n");
                    cursor += attrib_len;
                    break;
                  }
                case 7:
                  {
                    basics_log("\t\tAGGREGATOR:\n"); // ipv4 only
                    cursor += attrib_len;
                    break;
                  }
                case 8:
                  {
                    basics_log("\t\tCOMMUNITY:\n");

                    cursor += attrib_len;
                    break;
                  }
                case 14: // Optional + Transitive, ipv6 only. requires ORIGIN and AS_PATH. and no NEXT_HOP
                  {
                    basics_log("\t\tMP_REACH_NLRI:\n");
                    printFlags(flags);

                    uint8_t *attrib_tail = cursor + attrib_len;

                    uint16_t AFI = extractPrintAFI("\t\t\t");
                    extractPrintSAFI("\t\t\t");

                    uint8_t next_hop_len = extract.template operator()<uint8_t>();

                    if (AFI == 2) // ipv6
                    {
                      char str[INET6_ADDRSTRLEN];
                      inet_ntop(AF_INET6, cursor, str, INET6_ADDRSTRLEN);

                      basics_log("\t\t\tNext Hop: %s\n", str);
                    }

                    cursor += next_hop_len;

                    cursor += 1; // reserved

                    do
                    {
                      uint8_t cidr = extract.template operator()<uint8_t>();
                      uint8_t nlri_len = nBytesForCIDR(cidr);

                      if (AFI == 2) // ipv6
                      {
                        uint8_t address[16];
                        memset(address, 0, 16);
                        memcpy(address, cursor, nlri_len);

                        char str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);
                        basics_log("\t\t\tNLRI: %s/%hhu\n", str, cidr);
                      }

                      cursor += nlri_len;

                    } while (cursor < attrib_tail);

                    break;
                  }
                case 15: // Optional + Non-Transitive, ipv6 only. requires no other path attributes
                  {
                    basics_log("\t\tMP_UNREACH_NLRI:\n");
                    printFlags(flags);

                    uint8_t *attrib_tail = cursor + attrib_len;

                    uint16_t AFI = extractPrintAFI("\t\t\t");
                    extractPrintSAFI("\t\t\t");

                    while (cursor < attrib_tail)
                    {
                      uint8_t cidr = extract.template operator()<uint8_t>();
                      uint8_t nlri_len = nBytesForCIDR(cidr);

                      if (AFI == 2) // ipv6
                      {
                        uint8_t address[16];
                        memset(address, 0, 16);
                        memcpy(address, cursor, nlri_len);

                        char str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);
                        basics_log("\t\t\tNLRI: %s/%hhu\n", str, cidr);
                      }

                      cursor += nlri_len;
                    }

                    break;
                  }
                default:
                  {
                    basics_log("\t\tother path attribute = %hhu\n", type_code);
                    cursor += attrib_len;
                    break;
                  }
              }

            } while (cursor < pathattributes_tail);
          }

          uint32_t total_nlri_len = message_len - 23 - pathattributes_len - withdrawn_len;

          if (total_nlri_len > 0) // ipv4 only
          {
            basics_log("\nNLRI:\n");

            do
            {
              uint8_t cidr = extract.template operator()<uint8_t>();
              uint8_t nlri_len = nBytesForCIDR(cidr);

              uint8_t address[4];
              memset(address, 0, 4);
              memcpy(address, cursor, nlri_len);

              char str[INET_ADDRSTRLEN];
              inet_ntop(AF_INET, address, str, INET_ADDRSTRLEN);
              basics_log("\t\t%s/%hhu\n", str, cidr);

              cursor += nlri_len;

            } while (cursor < tail);
          }

          break;
        }
      case 3: // Notification
        {
          basics_log("Notification Message\n");

          uint8_t error_code = extract.template operator()<uint8_t>();
          uint8_t error_subcode = extract.template operator()<uint8_t>();

          switch (error_code)
          {
            case 1:
              {
                basics_log("\tMessage Header Error\n");

                switch (error_subcode)
                {
                  case 1:
                    {
                      basics_log("\tConnection Not Synchronized\n");
                      break;
                    }
                  case 2:
                    {
                      basics_log("\tBad Message Length\n");
                      break;
                    }
                  case 3:
                    {
                      basics_log("\tBad Message Type\n");
                      break;
                    }
                  default:
                    {
                      basics_log("\tother error subcode = %hhu\n", error_subcode);
                      break;
                    }
                }

                break;
              }
            case 2:
              {
                basics_log("\tOpen Message Error\n");

                switch (error_subcode)
                {
                  case 1:
                    {
                      basics_log("\tUnsupported Version Number\n");
                      break;
                    }
                  case 2:
                    {
                      basics_log("\tBad Peer AS\n");
                      break;
                    }
                  case 3:
                    {
                      basics_log("\tBad BGP Identifier\n");
                      break;
                    }
                  case 4:
                    {
                      basics_log("\tUnsupported Optional Parameter\n");
                      break;
                    }
                  case 6:
                    {
                      basics_log("\tUnacceptable Hold Time\n");
                      break;
                    }
                  case 7:
                    {
                      basics_log("\tUnsupported Capability\n");
                      break;
                    }
                  default:
                    {
                      basics_log("\tother error subcode = %hhu\n", error_subcode);
                      break;
                    }
                }

                break;
              }
            case 3:
              {
                basics_log("\tUpdate Message Error\n");

                switch (error_subcode)
                {
                  case 1:
                    {
                      basics_log("\tMalformed Attribute List\n");
                      break;
                    }
                  case 2:
                    {
                      basics_log("\tUnrecognized Well-known Attribute\n");
                      break;
                    }
                  case 3:
                    {
                      basics_log("\tMissing Well-known Attribute\n");
                      break;
                    }
                  case 4:
                    {
                      basics_log("\tAttribute Flags Error\n");
                      break;
                    }
                  case 5:
                    {
                      basics_log("\tAttribute Length Error\n");
                      break;
                    }
                  case 6:
                    {
                      basics_log("\tInvalid ORIGIN Attribute\n");
                      break;
                    }
                  case 8:
                    {
                      basics_log("\tInvalid NEXT_HOP Attribute\n");
                      break;
                    }
                  case 9:
                    {
                      basics_log("\tOptional Attribute Error\n");
                      break;
                    }
                  case 10:
                    {
                      basics_log("\tInvalid Network Field\n");
                      break;
                    }
                  case 11:
                    {
                      basics_log("\tMalformed AS_PATH\n");
                      break;
                    }
                  default:
                    {
                      basics_log("\tother error subcode = %hhu\n", error_subcode);
                      break;
                    }
                }

                break;
              }
            case 4:
              {
                basics_log("\tHold Timer Expired\n");
                break;
              }
            case 5:
              {
                basics_log("\tFinite State Machine Error\n");
                break;
              }
            case 6:
              {
                basics_log("\tCease\n");
                break;
              }
            default:
              {
                basics_log("\tother error = %hhu\n", error_code);
                break;
              }
          }

          break;
        }
      case 4: // Keepalive
        {
          basics_log("Keepalive Message\n");

          // A KEEPALIVE message consists of only the message header and has a length of 19 octets.
          break;
        }
      default:
        break;
    }
  }

  constexpr static uint8_t marker[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

public:
  uint16_t fillOpenMesage(Buffer& wBuffer, uint32_t bgpid, bool is6, uint16_t localASN)
  {
    // if (is6)
    // {
    // 	// for ipv6 we need to lie to it and mimic it's open message for it to accept us... whatever
    // 	static constexpr uint8_t data[] = {
    //     	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    //     	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    //     	0x00, 0x39, 0x01, 0x04, 0x8c, 0x1e, 0x00, 0xb4,
    //     	0x0a, 0x0c, 0xe8, 0x81, 0x1c, 0x02, 0x1a, 0x02,
    //     	0x00, 0x46, 0x00, 0x41, 0x04, 0x00, 0x00, 0x8c,
    //     	0x1e, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x40,
    //     	0x02, 0x41, 0x2c, 0x45, 0x04, 0x00, 0x02, 0x01,
    //     	0x01
    // 	};
    //  ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:39:01:04:8c:1e:00:b4:0a:0c:e8:81:1c:02:1a:02:00:46:00:41:04:00:00:8c:1e:01:04:00:02:00:01:40:02:41:2c:45:04:00:02:01:01"
    //  ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:25:01:04:8c:1e:00:b4:0a:0c:e8:81:06:02:06:01:04:00:02:00:01
    //
    // 	wBuffer.append(data, sizeof(data));
    // 	return sizeof(data);
    // }

    // If one of the Optional Parameters in the OPEN message is recognized, but is malformed, then the Error Subcode MUST be set to 0

    uint32_t header_offset = wBuffer.size();

    wBuffer.append(marker, sizeof(marker));

    wBuffer.advance(2); // message_len

    // 01:04:00:02:00:01

    wBuffer.append(uint8_t(0x01)); // Open
    wBuffer.append(uint8_t(0x04)); // BGP version 4
    wBuffer.append(reverseByteOrder(localASN)); // our ASN
    wBuffer.append(reverseByteOrder(uint16_t(180))); // hold time
    wBuffer.append(bgpid);

    uint32_t optional_params_len_idx = wBuffer.size();
    wBuffer.advance(1);

    wBuffer.append(uint8_t(0x02)); // Capabilities Optional Parameter

    uint32_t capability_list_len_idx = wBuffer.size();
    wBuffer.advance(1);

    // // route refresh
    // wBuffer.append(uint8_t(0x02));
    // wBuffer.append(uint8_t(0x00));

    // // enhanced route refresh
    // wBuffer.append(uint8_t(0x46));
    // wBuffer.append(uint8_t(0x00));

    // // 4 octet asns
    // wBuffer.append(uint8_t(0x41));
    // wBuffer.append(uint8_t(0x04));
    // wBuffer.append(uint8_t(0x00));
    // wBuffer.append(uint8_t(0x00));
    // wBuffer.append(uint8_t(0x8c));
    // wBuffer.append(uint8_t(0x1e));

    // MP-BGP
    wBuffer.append(uint8_t(0x01)); // MP-BGP
    wBuffer.append(uint8_t(0x04)); // option length

    if (is6)
    {
      wBuffer.append(reverseByteOrder(uint16_t(0x02))); // AFI = ipv6
    }
    else
    {
      wBuffer.append(reverseByteOrder(uint16_t(0x01))); // AFI = ipv4
    }

    wBuffer.append(uint8_t(0x00)); // reserved
    wBuffer.append(uint8_t(0x01)); // SAFI = unicast

    // Graceful Restart
    wBuffer.append(uint8_t(0x40)); // Graceful Restart
    wBuffer.append(uint8_t(0x02)); // option length

    // setting the top bit to 1 signifies we restarted so don't wait for end of rib message
    // before sending us routes
    wBuffer.append(reverseByteOrder(uint16_t(0b0000'0001'0010'1100))); // bottom 12 bits are timeout but they're ignored

    // leftmost bit most significant

    // additional paths
    // wBuffer.append(uint8_t(0x45));
    // wBuffer.append(uint8_t(0x04));
    // wBuffer.append(uint8_t(0x00));
    // wBuffer.append(uint8_t(0x01));
    // wBuffer.append(uint8_t(0x01));
    // wBuffer.append(uint8_t(0x01));

    wBuffer[capability_list_len_idx] = uint8_t(wBuffer.size() - capability_list_len_idx - 1); // -1 because don't include itself in the length
    wBuffer[optional_params_len_idx] = uint8_t(wBuffer.size() - optional_params_len_idx - 1); // -1 because don't include itself in the length

    uint16_t hlen = wBuffer.size() - header_offset;
    uint16_t nlen = reverseByteOrder(hlen);
    memcpy(wBuffer.data() + header_offset + sizeof(marker), &nlen, 2);

    return hlen;
  }

  void fillAnnouncePrefixMessage(String& message, const IPPrefix& prefix, const IPAddress& gateway, bool globally, uint32_t community = 0)
  {
    String cidr_string;
    cidr_string.assignItoa(prefix.cidr);

    char prefix_string[INET6_ADDRSTRLEN];
    char gateway_string[INET6_ADDRSTRLEN];

    int af = prefix.network.is6 ? AF_INET6 : AF_INET;

    inet_ntop(af, prefix.network.v6, prefix_string, INET6_ADDRSTRLEN);
    inet_ntop(af, gateway.v6, gateway_string, INET6_ADDRSTRLEN);

    // basics_log("fillAnnouncePrefixMessage: prefix %s/%s via gateway %s\n", prefix_string, cidr_string.c_str(), gateway_string);

    message.append(marker, sizeof(marker));
    message.advance(2); // message length

    message.append(uint8_t(0x02)); // Update

    message.append(uint16_t(0x00)); // withdrawn length 0

    uint32_t total_attributes_len_idx = message.size();
    message.append(uint16_t(0x00));

    // ORIGIN
    message.append(uint8_t(0b0100'0000)); // transitive
    message.append(uint8_t(0x01)); // origin
    message.append(uint8_t(0x01));
    message.append(uint8_t(0x0)); // IGP, all routes we announce were learned internally

    // AS_PATH
    message.append(uint8_t(0b0100'0000)); // transitive
    message.append(uint8_t(0x02)); // as_path
    message.append(uint8_t(0x04));
    message.append(uint8_t(0x02)); // AS_SEQUENCE
    message.append(uint8_t(0x01)); // 1 ASN to follow
    message.append(reverseByteOrder(localASN)); // our ASN

    if (prefix.network.is6)
    {
      // MP_REACH_NLRI
      message.append(uint8_t(0b1000'0000)); // optional + transitive
      message.append(uint8_t(0x0e)); // MP_REACH_NLRI
      uint32_t attrib_len_idx = message.size();
      message.append(uint8_t(0x00));

      message.append(reverseByteOrder(uint16_t(0x02))); // AFI == ipv6
      message.append(uint8_t(0x01)); // SAFI == unicast

      message.append(uint8_t(0x10)); // 16, length of gateway address
      message.append(gateway.v6, 0x10);

      message.append(uint8_t(0x00)); // reserved

      message.append(uint8_t(prefix.cidr));
      message.append(prefix.network.v6, nBytesForCIDR(prefix.cidr));

      message[attrib_len_idx] = uint8_t(message.size() - attrib_len_idx - 1);
    }
    else
    {
      // NEXT_HOP
      message.append(uint8_t(0b0100'0000)); // transitive
      message.append(uint8_t(0x03)); // next_hop
      message.append(uint8_t(0x04)); // len
      message.append(gateway.v6, 4); // next hop address ipv4
    }

    if (community > 0)
    {
      // COMMUNITY
      message.append(uint8_t(0b1100'0000)); // optional + transitive
      message.append(uint8_t(0x08)); // COMMUNITY
      message.append(uint8_t(0x04)); // only one community so len always 4
      message.append(reverseByteOrder(uint32_t(community)));
    }

    uint16_t len = reverseByteOrder(uint16_t(message.size() - total_attributes_len_idx - 2)); // -2 -> don't count this length in the total length
    memcpy(message.data() + total_attributes_len_idx, &len, 2);

    if (prefix.network.is6 == false)
    {
      message.append(uint8_t(prefix.cidr));
      message.append(prefix.network.v6, nBytesForCIDR(prefix.cidr));
    }

    uint16_t hlen = message.size();
    uint16_t nlen = reverseByteOrder(hlen);
    memcpy(message.data() + sizeof(marker), &nlen, 2);
  }

private:
  uint16_t fillWithdrawPrefixMessage(Buffer& wBuffer, const IPPrefix& prefix)
  {
    uint32_t header_offset = wBuffer.size();

    wBuffer.append(marker, sizeof(marker));
    wBuffer.advance(2); // message len

    wBuffer.append(uint8_t(0x02)); // Update

    if (prefix.network.is6)
    {
      wBuffer.append(uint16_t(0x00)); // withdrawn length 0
    }
    else
    {
      wBuffer.append(uint8_t(prefix.cidr));
      wBuffer.append(prefix.network.v6, nBytesForCIDR(prefix.cidr));
    }

    uint32_t total_attributes_len_idx = wBuffer.size();
    wBuffer.advance(2);

    if (prefix.network.is6)
    {
      // MP_UNREACH_NLRI
      wBuffer.append(uint8_t(0b1100'0000)); // optional + transitive
      wBuffer.append(uint8_t(0x0f)); // MP_UNREACH_NLRI

      uint32_t attrib_len_idx = wBuffer.size();
      wBuffer.append(uint8_t(0x00));

      wBuffer.append(reverseByteOrder(uint16_t(0x02))); // AFI == ipv6
      wBuffer.append(uint8_t(0x01)); // SAFI == unicast

      wBuffer.append(uint8_t(prefix.cidr));
      wBuffer.append(prefix.network.v6, nBytesForCIDR(prefix.cidr));

      wBuffer[attrib_len_idx] = uint8_t(wBuffer.size() - attrib_len_idx - 1);
    }

    uint16_t len = reverseByteOrder(uint16_t(wBuffer.size() - total_attributes_len_idx - 2)); // -2 -> don't count this length in the total length
    memcpy(wBuffer.data() + total_attributes_len_idx, &len, 2);

    uint16_t hlen = wBuffer.size();
    uint16_t nlen = reverseByteOrder(hlen);
    memcpy(wBuffer.data() + header_offset + sizeof(marker), &nlen, 2);

    return hlen;
  }

  uint16_t fillEndOfRibMessage(Buffer& wBuffer)
  {
    wBuffer.append(marker, sizeof(marker));
    wBuffer.append(reverseByteOrder(uint16_t(0x17))); // message_len = 23
    wBuffer.append(uint8_t(0x02)); // Update
    wBuffer.append(uint16_t(0x00)); // withdrawn length 0
    wBuffer.append(uint16_t(0x00)); // attributes length 0

    return 23;
  }

  void fillKeepaliveMessage(Buffer& wBuffer)
  {
    constexpr uint8_t keepalive[19] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x13, 0x04};
    wBuffer.append(keepalive, 19);
  }

  void pushRoutes(void)
  {
    for (const auto& [prefix, message] : routes)
    {
      printMessage(message);
      wBuffer.need(message.size());
      wBuffer.append(message);
    }

    wBuffer.need(23);
    fillEndOfRibMessage(wBuffer);

    Ring::queueSend(this);
  }

  bytell_hash_map<IPPrefix, String> routes;

  int64_t lastTime = 0;
  int64_t firstTime = 0;

public:

  uint32_t bgpid;
  uint16_t peerASN = 0;
  uint16_t localASN = 35'870;
  IPAddress peerAddress = {};
  BGPState state = BGPState::idle;
  uint32_t reconnectFailures = 0;
  bool is6;
  uint8_t hopLimit {0}; // 0 = use system default
  // Imports remain disabled unless the explicit peer owner supplies an
  // observer. Provider BGP sessions therefore preserve their advertise-only
  // behavior by default.
  BGPIPv6UnicastImportObserver ipv6UnicastImportObserver = nullptr;
  void *ipv6UnicastImportContext = nullptr;
  BGPSessionStateObserver sessionStateObserver = nullptr;
  void *sessionStateContext = nullptr;

  // Private cross-cluster peers live in the MASQUE gateway's network
  // namespace.  Retaining that namespace descriptor makes reconnects create
  // their sockets in the same namespace instead of silently falling back to
  // host routing.  Provider peers leave this unset and preserve the historic
  // path.
  int transportNetworkNamespaceFD = -1;
  String transportInterface = {};
  IPAddress transportSourceAddress = {};
  bool strictPrivateTransport = false;
  // A peer accepted by a private listener is never eligible for the active
  // reconnect path.  Its listener owns admission and re-arms accept after the
  // child has fully closed.
  BGPPrivateListener *passiveOwner = nullptr;

  bool configurePrivateTransport(int networkNamespaceFD, const String& interface,
                                 const IPAddress& sourceAddress)
  {
#ifdef __linux__
    if (networkNamespaceFD < 0 || interface.size() == 0 || interface.size() >= IFNAMSIZ ||
        !sourceAddress.is6 || sourceAddress.isNull()) return false;
    const int retained = ::fcntl(networkNamespaceFD, F_DUPFD_CLOEXEC, 3);
    if (retained < 0) return false;
    if (transportNetworkNamespaceFD >= 0) ::close(transportNetworkNamespaceFD);
    transportNetworkNamespaceFD = retained;
    transportInterface.assign(interface);
    transportSourceAddress = sourceAddress;
    strictPrivateTransport = true;
    return true;
#else
    (void)networkNamespaceFD; (void)interface; (void)sourceAddress;
    return false;
#endif
  }

  void setIPv6UnicastImportObserver(BGPIPv6UnicastImportObserver observer, void *context)
  {
    ipv6UnicastImportObserver = observer;
    ipv6UnicastImportContext = context;
  }

  void setSessionStateObserver(BGPSessionStateObserver observer, void *context)
  { sessionStateObserver = observer; sessionStateContext = context; }
  void notifySessionState(bool established)
  { if (sessionStateObserver) sessionStateObserver(sessionStateContext, peerAddress, established); }

  void clearSessionBuffers(void)
  {
    rBuffer.clear();
    wBuffer.clear();
  }

  void adoptAcceptedPrivateSocket(
      int acceptedSlot, uint32_t localBGPID, uint16_t expectedPeerASN, uint16_t selectedLocalASN,
      const IPAddress& localAddress, const IPAddress& expectedPeerAddress,
      BGPIPv6UnicastImportObserver importObserver, void *importContext,
      BGPSessionStateObserver stateObserver, void *stateContext,
      BGPPrivateListener *owner)
  {
    domain = AF_INET6;
    type = SOCK_STREAM;
    protocol = IPPROTO_TCP;
    bgpid = localBGPID;
    peerASN = expectedPeerASN;
    localASN = selectedLocalASN;
    peerAddress = expectedPeerAddress;
    is6 = true;
    setSaddr(localAddress, 179);
    setDaddr(expectedPeerAddress, 179);
    fslot = acceptedSlot;
    isFixedFile = true;
    passiveOwner = owner;
    setIPv6UnicastImportObserver(importObserver, importContext);
    setSessionStateObserver(stateObserver, stateContext);
  }

  // TCP-MD5 authentication (RFC 2385) support
  String md5Key; // stored in-memory only; do not log
  bool hasMD5 = false;

#ifdef __linux__
  void applyMD5ToSocket()
  {
    if (!hasMD5 || fd < 0)
    {
      return;
    }

    struct tcp_md5sig opt = {};
    // Copy destination address for matching
    memcpy(&opt.tcpm_addr, daddr<struct sockaddr_storage>(), sizeof(struct sockaddr_storage));
    // Prefixlen: 32 for IPv4, 128 for IPv6
    if (is6)
    {
      opt.tcpm_prefixlen = 128;
    }
    else
    {
      opt.tcpm_prefixlen = 32;
    }
    // Key
    opt.tcpm_keylen = (uint32_t)std::min<size_t>(md5Key.size(), TCP_MD5SIG_MAXKEYLEN);
    memcpy(opt.tcpm_key, md5Key.data(), opt.tcpm_keylen);
    // Apply to this socket
    if (setsockopt(fd, SOL_TCP, TCP_MD5SIG, &opt, sizeof(opt)) != 0)
    {
      const int failure = errno;
      std::fprintf(stderr, "BGP TCP-MD5 socket configuration failed errno=%d\n", failure);
    }
    // Zeroize local copy of key buffer used for setsockopt stack struct
    memset(opt.tcpm_key, 0, sizeof(opt.tcpm_key));
  }
#else
  void applyMD5ToSocket() {}
#endif

  void setMD5Password(const String& key)
  {
    md5Key = key;
    hasMD5 = (md5Key.size() > 0);
    applyMD5ToSocket(); // if socket and daddr are ready, apply immediately
  }

  void setHopLimit(uint8_t ttl)
  {
    hopLimit = ttl;
    // addPeer() creates the socket before it supplies the provider-specific
    // hop limit. Apply it to that first socket as well as later recreations.
    if (fd >= 0 && hopLimit > 0)
    {
      int v = hopLimit;
      const int result = is6
          ? setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &v, sizeof(v))
          : setsockopt(fd, IPPROTO_IP, IP_TTL, &v, sizeof(v));
      if (result != 0)
      {
        const int failure = errno;
        std::fprintf(stderr, "BGP hop-limit socket configuration failed family=%s errno=%d\n",
                     is6 ? "ipv6" : "ipv4", failure);
      }
    }
  }

  void sendOpen(void)
  {
    wBuffer.need(128);

    uint32_t len = fillOpenMesage(wBuffer, bgpid, is6, localASN);

    String message;
    message.setInvariant(wBuffer.pTail() - len, len);
    printMessage(message);

    Ring::queueSend(this);
    state = BGPState::opensent;
  }

  void sendKeepalive(void)
  {
    int64_t timeNow = Time::now<TimeResolution::sec>();

    if (firstTime == 0)
    {
      firstTime = timeNow;
      lastTime = timeNow;
    }

    lastTime = timeNow;

    wBuffer.need(19);
    fillKeepaliveMessage(wBuffer);
    Ring::queueSend(this);
  }

  void announcePrefix(const IPPrefix& prefix, const IPAddress& gateway, bool globally, uint32_t community = 0)
  {
    String& message = routes[prefix];
    message.clear();
    message.reserve(128);
    fillAnnouncePrefixMessage(message, prefix, gateway, globally, community);

    if (state == BGPState::established)
    {
      printMessage(message);

      wBuffer.need(message.size());
      wBuffer.append(message);
      Ring::queueSend(this);
    }
  }

  void announceAnycastPrefix(const IPPrefix& prefix, const IPAddress& gateway)
  {
    announcePrefix(prefix, gateway, true, 0);
  }

  void announceLocalPrefix(const IPPrefix& prefix, const IPAddress& gateway)
  {
    announcePrefix(prefix, gateway, false, 0);
  }

  void withdrawPrefix(const IPPrefix& prefix)
  {
    routes.erase(prefix);

    if (state == BGPState::established)
    {
      wBuffer.need(128);

      uint32_t len = fillWithdrawPrefixMessage(wBuffer, prefix);

      String message;
      message.setInvariant(wBuffer.pTail() - len, len);

      printMessage(message);
      Ring::queueSend(this);
    }
  }

  static bool openASNMatches(const uint8_t *open, size_t length, uint16_t expectedASN)
  {
    return open != nullptr && length >= 29 &&
        (expectedASN == 0 || (uint16_t(open[20]) << 8 | uint16_t(open[21])) == expectedASN);
  }

  bool handleMessage(void)
  {
    while (rBuffer.outstandingBytes() >= 18)
    {
      // messages are not aligned, so we can't make any assumptions

      uint8_t *cursor = rBuffer.pHead();

      uint16_t message_len = (uint16_t)(cursor[16] << 8 | cursor[17]);

      if (message_len < 19)
      {
        std::fprintf(stderr, "BGP message rejected: invalid length %hu\n", message_len);
        state = BGPState::failed;
        notifySessionState(false);
        Ring::queueClose(this);
        return false;
      }

      if (rBuffer.outstandingBytes() < message_len) return true;
      {
        String message;
        message.setInvariant(cursor, message_len);
        printMessage(message);

        cursor += 18;
        uint8_t message_type = *cursor;

        switch (message_type)
        {
          case 1: // Open
            {
              if (message_len < 29)
              {
                state = BGPState::failed;
                notifySessionState(false);
                Ring::queueClose(this);
                return false;
              }
              const uint8_t *open = message.data();
              const uint16_t openedASN = uint16_t(open[20]) << 8 | uint16_t(open[21]);
              if (!openASNMatches(open, message_len, peerASN))
              {
                std::fprintf(stderr, "BGP OPEN rejected expected peer AS=%hu received AS=%hu\n", peerASN, openedASN);
                state = BGPState::failed;
                notifySessionState(false);
                Ring::queueClose(this);
                return false;
              }
              sendKeepalive();
              state = BGPState::openconfirm;

              break;
            }
          case 2: // Update
            {
              if (ipv6UnicastImportObserver != nullptr && message_len >= 19)
              {
                // The observer sees only a wholly valid MP IPv6-unicast
                // UPDATE and cannot install routes through this parser path.
                (void)bgpObserveIPv6UnicastUpdate(message.data() + 19, message_len - 19,
                                                   ipv6UnicastImportObserver, ipv6UnicastImportContext);
              }
              break;
            }
          case 3: // Notification
            {
              // we might receive these if an error, they'll already be printed though
              state = BGPState::failed;
              notifySessionState(false);
              Ring::queueClose(this);
              return false;
            }
          case 4: // Keepalive
            {
              if (state == BGPState::openconfirm)
              {
                state = BGPState::established;
                reconnectFailures = 0;
                basics_log("BGP peer session established\n");
                notifySessionState(true);
                pushRoutes();
              }
              else
              {
                // something is screwed up with our timer but if we send keepalives when we get one we should be good and never expire
                sendKeepalive();
              }

              break;
            }
          default:
            {
              // ipc_printf("handleMessage: unknown/bad message_type = %hhu\n", message_type);
              break;
            }
        }

        rBuffer.consume(message_len, false);
      }
    }
    return true;
  }

  void goIdle(void)
  {
    state = BGPState::idle;
  }

  BGPPeer()
  {
    rBuffer.reserve(4_KB);
    wBuffer.reserve(4_KB);
  }

  ~BGPPeer()
  {
#ifdef __linux__
    if (transportNetworkNamespaceFD >= 0) ::close(transportNetworkNamespaceFD);
#endif
    transportNetworkNamespaceFD = -1;
  }

  void createSocket(void) override
  {
#ifdef __linux__
    if (strictPrivateTransport)
    {
      const int callerNamespace = ::open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
      if (callerNamespace < 0 || transportNetworkNamespaceFD < 0 ||
          ::setns(transportNetworkNamespaceFD, CLONE_NEWNET) != 0)
      {
        if (callerNamespace >= 0) ::close(callerNamespace);
        fd = -1;
        return;
      }
      TCPSocket::createSocket();
      const bool restored = ::setns(callerNamespace, CLONE_NEWNET) == 0;
      ::close(callerNamespace);
      // Continuing the Neuron event loop in a container namespace could
      // route unrelated control traffic through the tunnel.  Fail hard if
      // the kernel cannot restore the caller namespace.
      if (!restored) std::abort();
      return;
    }
#endif
    TCPSocket::createSocket();
  }

  // Ensure MD5 is re-applied on socket recreation
  void configureSocket(void) override
  {
    TCPSocket::configureSocket();
    if (strictPrivateTransport)
    {
#ifdef __linux__
      const bool boundToTunnel = fd >= 0 &&
          ::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                       transportInterface.c_str(), socklen_t(transportInterface.size() + 1)) == 0;
      sockaddr_in6 source = {};
      source.sin6_family = AF_INET6;
      std::memcpy(&source.sin6_addr, transportSourceAddress.v6, sizeof(source.sin6_addr));
      const bool sourceBound = boundToTunnel &&
          ::bind(fd, reinterpret_cast<const sockaddr *>(&source), sizeof(source)) == 0;
      if (!sourceBound)
      {
        const int failure = errno;
        if (fd >= 0) ::close(fd);
        fd = -1;
        std::fprintf(stderr,
                     "private BGP socket tunnel bind failed interface=%s errno=%d\n",
                     transportInterface.c_str(), failure);
        return;
      }
#else
      if (fd >= 0) ::close(fd);
      fd = -1;
      return;
#endif
    }
    applyMD5ToSocket();
    if (hopLimit > 0)
    {
      int v = hopLimit;
      const int result = is6
          ? setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &v, sizeof(v))
          : setsockopt(fd, IPPROTO_IP, IP_TTL, &v, sizeof(v));
      if (result != 0)
      {
        const int failure = errno;
        std::fprintf(stderr, "BGP hop-limit socket reconfiguration failed family=%s errno=%d\n",
                     is6 ? "ipv6" : "ipv4", failure);
      }
    }
  }
};

// The private cross-cluster listener is deliberately separate from BGPPeer.
// TCP-MD5 authenticates the SYN, so it must be configured on the listening
// socket before bind/listen; applying it only to an accepted child is too late.
class BGPPrivateListener final : public TCPSocket {
public:
  int transportNetworkNamespaceFD = -1;
  String transportInterface = {};
  IPAddress localAddress = {};
  IPAddress peerAddress = {};
  uint16_t peerASN = 0;
  uint16_t localASN = 35'870;
  uint32_t localBGPID = 0;
  String md5Key = {};
  BGPIPv6UnicastImportObserver ipv6UnicastImportObserver = nullptr;
  void *ipv6UnicastImportContext = nullptr;
  BGPSessionStateObserver sessionStateObserver = nullptr;
  void *sessionStateContext = nullptr;
  bytell_hash_map<IPPrefix, IPAddress> localPrefixes = {};
  BGPPeer *acceptedPeer = nullptr;
  bool acceptPending = false;
  bool closing = false;

private:
  bool transportConfigured = false;

  void createSocket(void) override
  {
#ifdef __linux__
    transportConfigured = false;
    const int callerNamespace = ::open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    if (callerNamespace < 0 || transportNetworkNamespaceFD < 0 ||
        ::setns(transportNetworkNamespaceFD, CLONE_NEWNET) != 0)
    {
      if (callerNamespace >= 0) ::close(callerNamespace);
      fd = -1;
      return;
    }
    TCPSocket::createSocket();
    const bool restored = ::setns(callerNamespace, CLONE_NEWNET) == 0;
    ::close(callerNamespace);
    // Continuing the event loop in the gateway namespace could redirect
    // unrelated control traffic.  Restoration failure is unrecoverable.
    if (!restored) std::abort();
#else
    fd = -1;
#endif
  }

  void configureSocket(void) override
  {
    TCPSocket::configureSocket();
#ifdef __linux__
    if (fd < 0 || transportInterface.size() == 0 ||
        transportInterface.size() >= IFNAMSIZ || !peerAddress.is6 ||
        peerAddress.isNull() || md5Key.size() == 0 ||
        md5Key.size() > TCP_MD5SIG_MAXKEYLEN)
    {
      if (fd >= 0) ::close(fd);
      fd = -1;
      return;
    }

    const int ipv6Only = 1;
    bool configured =
        bgpConfigurePrivateMasqueHopLimit(fd) &&
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                     &ipv6Only, sizeof(ipv6Only)) == 0 &&
        ::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                     transportInterface.c_str(),
                     socklen_t(transportInterface.size() + 1)) == 0;

    struct tcp_md5sig option = {};
    auto *peer = reinterpret_cast<struct sockaddr_in6 *>(&option.tcpm_addr);
    peer->sin6_family = AF_INET6;
    std::memcpy(&peer->sin6_addr, peerAddress.v6, sizeof(peer->sin6_addr));
    option.tcpm_prefixlen = 128;
    option.tcpm_keylen = uint32_t(md5Key.size());
    std::memcpy(option.tcpm_key, md5Key.data(), option.tcpm_keylen);
    configured = configured &&
        ::setsockopt(fd, SOL_TCP, TCP_MD5SIG, &option, sizeof(option)) == 0;
    std::memset(option.tcpm_key, 0, sizeof(option.tcpm_key));
    if (!configured)
    {
      const int failure = errno;
      ::close(fd);
      fd = -1;
      std::fprintf(stderr,
                   "private BGP listener tunnel/authentication configuration failed interface=%s errno=%d\n",
                   transportInterface.c_str(), failure);
      return;
    }
    transportConfigured = true;
#else
    if (fd >= 0) ::close(fd);
    fd = -1;
#endif
  }

public:
  bool start(int networkNamespaceFD, const String& interface,
             const IPAddress& local, const IPAddress& peer,
             const String& password)
  {
#ifdef __linux__
    constexpr static uint16_t BGP_PORT = 179;
    if (networkNamespaceFD < 0 || interface.size() == 0 ||
        interface.size() >= IFNAMSIZ || !local.is6 || !peer.is6 ||
        local.isNull() || peer.isNull() || local.equals(peer) ||
        password.size() == 0 || password.size() > TCP_MD5SIG_MAXKEYLEN)
      return false;
    const int retained = ::fcntl(networkNamespaceFD, F_DUPFD_CLOEXEC, 3);
    if (retained < 0) return false;
    transportNetworkNamespaceFD = retained;
    transportInterface.assign(interface);
    localAddress = local;
    peerAddress = peer;
    md5Key = password;
    domain = AF_INET6;
    type = SOCK_STREAM;
    protocol = IPPROTO_TCP;
    createSocket();
    if (fd < 0 || !transportConfigured) return false;
    setSaddr(localAddress, BGP_PORT);
    setDaddr(peerAddress, BGP_PORT);
    setDatacenterCongestion();
    if (::bind(fd, saddr<struct sockaddr>(), saddrLen) != 0 ||
        ::listen(fd, SOMAXCONN) != 0)
    {
      const int failure = errno;
      ::close(fd);
      fd = -1;
      std::fprintf(stderr,
                   "private BGP listener bind/listen failed interface=%s errno=%d\n",
                   transportInterface.c_str(), failure);
      return false;
    }
    return true;
#else
    (void)networkNamespaceFD; (void)interface; (void)local; (void)peer;
    (void)password;
    return false;
#endif
  }

  bool accepts(const struct sockaddr_storage& remote, socklen_t length) const
  {
    if (length < sizeof(struct sockaddr_in6) || remote.ss_family != AF_INET6)
      return false;
    const auto *address = reinterpret_cast<const struct sockaddr_in6 *>(&remote);
    return std::memcmp(&address->sin6_addr, peerAddress.v6,
                       sizeof(address->sin6_addr)) == 0;
  }

  void rememberLocalPrefix(const IPPrefix& prefix, const IPAddress& gateway)
  { localPrefixes.insert_or_assign(prefix, gateway); }

  void forgetPrefix(const IPPrefix& prefix) { localPrefixes.erase(prefix); }

  ~BGPPrivateListener()
  {
#ifdef __linux__
    if (transportNetworkNamespaceFD >= 0) ::close(transportNetworkNamespaceFD);
#endif
    transportNetworkNamespaceFD = -1;
    if (md5Key.size() != 0) std::memset(md5Key.data(), 0, md5Key.size());
  }
};

class BGPHub : public RingInterface {
private:

  bytell_hash_set<BGPPeer *> peers;
  bytell_hash_set<BGPPrivateListener *> privateListeners;
  bytell_hash_set<BGPPrivateListener *> retiringPrivateListeners;
  bool shuttingDown = false;
  TimeoutPacket reconnectTimer = {};
  bool reconnectTimerQueued = false;
  bool reconnectTimerCancellationQueued = false;

  void queuePrivateAccept(BGPPrivateListener *listener)
  {
    if (listener == nullptr || listener->closing || listener->acceptPending ||
        listener->acceptedPeer != nullptr || !privateListeners.contains(listener) ||
        Ring::socketIsClosing(listener)) return;
    listener->acceptPending = true;
    Ring::queueAccept(listener, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
  }

  void retirePrivateListener(BGPPrivateListener *listener)
  {
    if (listener == nullptr || !privateListeners.contains(listener)) return;
    listener->closing = true;
    privateListeners.erase(listener);
    retiringPrivateListeners.insert(listener);
    if (listener->acceptedPeer != nullptr)
    {
      BGPPeer *peer = listener->acceptedPeer;
      listener->acceptedPeer = nullptr;
      peer->passiveOwner = nullptr;
      if (peers.contains(peer)) peers.erase(peer);
      peer->notifySessionState(false);
      if (!Ring::socketIsClosing(peer)) Ring::queueClose(peer);
    }
    if (!Ring::socketIsClosing(listener)) Ring::queueClose(listener);
  }

  void scheduleReconnect(BGPPeer *peer)
  {
    if (shuttingDown || reconnectTimerQueued)
    {
      return;
    }

    if (peer->reconnectFailures < 7)
    {
      peer->reconnectFailures += 1;
    }
    reconnectTimer.clear();
    reconnectTimer.originator = this;
    reconnectTimer.setTimeoutMs(reconnectDelayMs(peer->reconnectFailures));
    reconnectTimerQueued = true;
    reconnectTimerCancellationQueued = false;
    RingDispatcher::installMultiplexee(this, this);
    basics_log("BGP peer reconnect scheduled failures=%u delayMs=%u\n",
               unsigned(peer->reconnectFailures),
               unsigned(reconnectDelayMs(peer->reconnectFailures)));
    Ring::queueTimeout(&reconnectTimer);
  }

public:

  uint32_t ourBGPID;
  uint16_t ourASN = 35'870;

  constexpr static uint32_t reconnectDelayMs(uint32_t failures)
  {
    constexpr uint32_t initialDelayMs = 1000;
    constexpr uint32_t maximumExponent = 6;
    const uint32_t exponent = failures > 0 ? std::min(failures - 1, maximumExponent) : 0;
    return initialDelayMs << exponent;
  }

  void addPeer(uint16_t peerASN, const IPAddress& peerAddress, const IPAddress& srcAddress)
  {
    constexpr static uint16_t BGP_PORT = 179;

    BGPPeer *peer = new BGPPeer();
    peer->bgpid = ourBGPID;
    peer->peerASN = peerASN;
    peer->peerAddress = peerAddress;

    if (peerAddress.is6)
    {
      peer->is6 = true;
      peer->setIPVersion(AF_INET6);
      peer->setDaddr(peerAddress, BGP_PORT);
    }
    else
    {
      peer->is6 = false;
      peer->setIPVersion(AF_INET);
      peer->setDaddr(peerAddress, BGP_PORT);
    }

    peer->setSaddr(srcAddress);
    peer->setDatacenterCongestion();

    peers.insert(peer);

    RingDispatcher::installMultiplexee(peer, this);
    Ring::installFDIntoFixedFileSlot(peer);
    Ring::queueConnect(peer);
  }

  void addPeer(uint16_t peerASN, const IPAddress& peerAddress, const IPAddress& srcAddress, const String& md5Password)
  {
    constexpr static uint16_t BGP_PORT = 179;

    BGPPeer *peer = new BGPPeer();
    peer->bgpid = ourBGPID;
    peer->peerASN = peerASN;
    peer->peerAddress = peerAddress;

    if (peerAddress.is6)
    {
      peer->is6 = true;
      peer->setIPVersion(AF_INET6);
      peer->setDaddr(peerAddress, BGP_PORT);
    }
    else
    {
      peer->is6 = false;
      peer->setIPVersion(AF_INET);
      peer->setDaddr(peerAddress, BGP_PORT);
    }

    peer->setSaddr(srcAddress);
    peer->setDatacenterCongestion();
    peer->setMD5Password(md5Password);

    peers.insert(peer);

    RingDispatcher::installMultiplexee(peer, this);
    Ring::installFDIntoFixedFileSlot(peer);
    Ring::queueConnect(peer);
  }

  void addPeer(uint16_t peerASN, const IPAddress& peerAddress, const IPAddress& srcAddress, const String& md5Password, uint8_t hopLimit)
  {
    addPeer(peerASN, peerAddress, srcAddress, md5Password, hopLimit, nullptr, nullptr, nullptr, nullptr);
  }

  // Cross-cluster owners must explicitly opt into UPDATE observation. The
  // established provider overload above deliberately remains advertise-only.
  bool addPeer(uint16_t peerASN, const IPAddress& peerAddress, const IPAddress& srcAddress, const String& md5Password, uint8_t hopLimit,
               BGPIPv6UnicastImportObserver importObserver, void *importContext,
               BGPSessionStateObserver stateObserver = nullptr, void *stateContext = nullptr,
               int networkNamespaceFD = -1, const String *boundInterface = nullptr)
  {
    constexpr static uint16_t BGP_PORT = 179;

    BGPPeer *peer = new BGPPeer();
    peer->bgpid = ourBGPID;
    peer->peerASN = peerASN;
    peer->peerAddress = peerAddress;

    peer->localASN = ourASN;
    const bool strictPrivateTransport = networkNamespaceFD >= 0 || boundInterface != nullptr;
    if (strictPrivateTransport &&
        (networkNamespaceFD < 0 || boundInterface == nullptr ||
         !peer->configurePrivateTransport(networkNamespaceFD, *boundInterface, srcAddress)))
    {
      delete peer;
      return false;
    }

    if (peerAddress.is6)
    {
      peer->is6 = true;
      peer->setIPVersion(AF_INET6);
      peer->setDaddr(peerAddress, BGP_PORT);
    }
    else
    {
      peer->is6 = false;
      peer->setIPVersion(AF_INET);
      peer->setDaddr(peerAddress, BGP_PORT);
    }

    if (!strictPrivateTransport) peer->setSaddr(srcAddress);
    if (peer->fd < 0)
    {
      delete peer;
      return false;
    }
    peer->setDatacenterCongestion();
    peer->setMD5Password(md5Password);
    peer->setHopLimit(hopLimit);
    peer->setIPv6UnicastImportObserver(importObserver, importContext);
    peer->setSessionStateObserver(stateObserver, stateContext);

    peers.insert(peer);

    RingDispatcher::installMultiplexee(peer, this);
    Ring::installFDIntoFixedFileSlot(peer);
    Ring::queueConnect(peer);
    return true;
  }

  // The MASQUE listener side owns the passive TCP/179 half of the private BGP
  // session.  It binds only the exact inside address in the exact gateway
  // namespace/TUN and authenticates the remote inside address at the SYN.
  bool listenPrivatePeer(
      uint16_t peerASN, const IPAddress& peerAddress,
      const IPAddress& localAddress, const String& md5Password,
      BGPIPv6UnicastImportObserver importObserver, void *importContext,
      BGPSessionStateObserver stateObserver, void *stateContext,
      int networkNamespaceFD, const String& boundInterface)
  {
    if (!peerAddress.is6 || !localAddress.is6 || peerASN == 0 ||
        networkNamespaceFD < 0 || boundInterface.size() == 0) return false;
    for (BGPPrivateListener *existing : privateListeners)
      if (existing->peerAddress.equals(peerAddress)) return false;
    for (BGPPeer *existing : peers)
      if (existing->peerAddress.equals(peerAddress)) return false;

    BGPPrivateListener *listener = new BGPPrivateListener();
    listener->peerASN = peerASN;
    listener->localBGPID = ourBGPID;
    listener->localASN = ourASN;
    listener->ipv6UnicastImportObserver = importObserver;
    listener->ipv6UnicastImportContext = importContext;
    listener->sessionStateObserver = stateObserver;
    listener->sessionStateContext = stateContext;
    if (!listener->start(networkNamespaceFD, boundInterface, localAddress,
                         peerAddress, md5Password))
    {
      delete listener;
      return false;
    }

    privateListeners.insert(listener);
    RingDispatcher::installMultiplexee(listener, this);
    Ring::installFDIntoFixedFileSlot(listener);
    queuePrivateAccept(listener);
    return true;
  }

  void withdrawPeer(const IPAddress& peerAddress)
  {
    for (auto it = privateListeners.begin(); it != privateListeners.end(); ++it)
    {
      BGPPrivateListener *listener = *it;
      if (listener->peerAddress.equals(peerAddress))
      {
        retirePrivateListener(listener);
        break;
      }
    }
    for (auto it = peers.begin(); it != peers.end(); it++)
    {
      BGPPeer *peer = *it;

      if (peer->is6 == peerAddress.is6)
      {
        if (peer->daddrEqual(peerAddress))
        {
          peers.erase(it);
          Ring::queueClose(peer);
          break;
        }
      }
    }
  }

  void withdrawPrefix(const IPPrefix& prefix)
  {
    for (BGPPrivateListener *listener : privateListeners)
      listener->forgetPrefix(prefix);
    for (BGPPeer *peer : peers)
    {
      if (prefix.network.is6 == peer->is6)
      {
        peer->withdrawPrefix(prefix);
      }
    }
  }

  void announceAnycastPrefix(const IPPrefix& prefix, const IPAddress& gateway)
  {
    for (BGPPeer *peer : peers)
    {
      if (prefix.network.is6 == peer->is6)
      {
        peer->announceAnycastPrefix(prefix, gateway);
      }
    }
  }

  void announceLocalPrefix(const IPPrefix& prefix, const IPAddress& gateway)
  {
    for (BGPPrivateListener *listener : privateListeners)
      if (prefix.network.is6) listener->rememberLocalPrefix(prefix, gateway);
    for (BGPPeer *peer : peers)
    {
      if (prefix.network.is6 == peer->is6)
      {
        peer->announceLocalPrefix(prefix, gateway);
      }
    }
  }

  // Provider-driven community: announce a prefix with a specific 32-bit community
  void announceWithCommunity(const IPPrefix& prefix, const IPAddress& gateway, uint32_t community)
  {
    for (BGPPeer *peer : peers)
    {
      if (prefix.network.is6 == peer->is6)
      {
        peer->announcePrefix(prefix, gateway, false, community);
      }
    }
  }

  void acceptHandler(void *socket, int fslot) override
  {
    BGPPrivateListener *listener = nullptr;
    for (BGPPrivateListener *candidate : privateListeners)
    {
      if (static_cast<void *>(candidate) == socket) { listener = candidate; break; }
    }
    if (listener == nullptr)
    {
      // A close/withdraw can retire the listener while an accept completion is
      // already in flight.  Such a child belongs to no current authority.
      if (fslot >= 0) Ring::queueCloseRaw(fslot);
      return;
    }

    listener->acceptPending = false;
    if (fslot < 0)
    {
      queuePrivateAccept(listener);
      return;
    }

    struct sockaddr_storage remote = {};
    socklen_t remoteLength = 0;
    const bool exactPeer = Ring::takeAcceptedPeerAddress(
        fslot, remote, remoteLength) && listener->accepts(remote, remoteLength);
    if (!exactPeer || listener->closing || listener->acceptedPeer != nullptr)
    {
      Ring::queueCloseRaw(fslot);
      queuePrivateAccept(listener);
      return;
    }

    BGPPeer *peer = new BGPPeer();
    peer->adoptAcceptedPrivateSocket(
        fslot, listener->localBGPID, listener->peerASN, listener->localASN,
        listener->localAddress, listener->peerAddress,
        listener->ipv6UnicastImportObserver,
        listener->ipv6UnicastImportContext,
        listener->sessionStateObserver, listener->sessionStateContext,
        listener);
    listener->acceptedPeer = peer;
    peers.insert(peer);
    RingDispatcher::installMultiplexee(peer, this);
    for (const auto& [prefix, gateway] : listener->localPrefixes)
      peer->announceLocalPrefix(prefix, gateway);
    peer->sendOpen();
    Ring::queueRecv(peer);
  }

  void connectHandler(void *socket, int result) override
  {
    BGPPeer *peer = static_cast<BGPPeer *>(socket);

    if (result == 0)
    {
      basics_log("BGP peer TCP connected\n");
      peer->sendOpen();
      Ring::queueRecv(peer);
    }
    else
    {
      peer->state = BGPState::failed;
      if (peer->sessionStateObserver) peer->sessionStateObserver(peer->sessionStateContext, peer->peerAddress, false);
      basics_log("BGP peer TCP connect failed result=%d\n", result);
      Ring::queueClose(peer);
    }
  }

  void recvHandler(void *socket, int result) override
  {
    BGPPeer *peer = static_cast<BGPPeer *>(socket);
    peer->pendingRecv = false;

    if (peers.contains(peer)) // otherwise being withdrawn
    {
      if (result > 0)
      {
        peer->rBuffer.advance(result);
        if (peer->handleMessage()) Ring::queueRecv(peer);
      }
      else if (result == 0)
      {
        peer->state = BGPState::failed;
        if (peer->sessionStateObserver) peer->sessionStateObserver(peer->sessionStateContext, peer->peerAddress, false);
        Ring::queueClose(peer);
      }
      else if (result != -9)
      {
        peer->state = BGPState::failed;
        if (peer->sessionStateObserver) peer->sessionStateObserver(peer->sessionStateContext, peer->peerAddress, false);
        Ring::queueClose(peer);
      }
    }
  }

  void sendHandler(void *socket, int result) override
  {
    BGPPeer *peer = static_cast<BGPPeer *>(socket);

    peer->pendingSend = false;
    peer->pendingSendBytes = 0;

    if (peers.contains(peer)) // otherwise being withdrawn
    {
      if (result > 0)
      {
        peer->wBuffer.consume(result, true);
        peer->wBuffer.noteSendCompleted();

        if (peer->wBuffer.outstandingBytes() > 0)
        {
          Ring::queueSend(peer);
        }
      }
      else if (result != -9)
      {
        peer->wBuffer.noteSendCompleted();
        peer->state = BGPState::failed;
        if (peer->sessionStateObserver) peer->sessionStateObserver(peer->sessionStateContext, peer->peerAddress, false);
        Ring::queueClose(peer);
      }
      else
      {
        peer->wBuffer.noteSendCompleted();
      }
    }
    else
    {
      peer->wBuffer.noteSendCompleted();
    }
  }

  virtual void hasShutdownBGP(void) = 0;

  // Update MD5 key on all peers (used for key rotation)
  void updateAllPeersMD5(const String& key)
  {
    for (BGPPeer *peer : peers)
    {
      peer->setMD5Password(key);
    }
  }

  void closeHandler(void *socket) override
  {
    for (auto it = retiringPrivateListeners.begin();
         it != retiringPrivateListeners.end(); ++it)
    {
      BGPPrivateListener *listener = *it;
      if (static_cast<void *>(listener) != socket) continue;
      retiringPrivateListeners.erase(it);
      RingDispatcher::eraseMultiplexee(listener);
      delete listener;
      if (shuttingDown && peers.empty() && privateListeners.empty() &&
          retiringPrivateListeners.empty() && !reconnectTimerQueued) hasShutdownBGP();
      return;
    }

    for (auto it = privateListeners.begin(); it != privateListeners.end(); ++it)
    {
      BGPPrivateListener *listener = *it;
      if (static_cast<void *>(listener) != socket) continue;
      privateListeners.erase(it);
      listener->closing = true;
      if (listener->acceptedPeer != nullptr)
      {
        BGPPeer *accepted = listener->acceptedPeer;
        listener->acceptedPeer = nullptr;
        accepted->passiveOwner = nullptr;
        if (peers.contains(accepted)) peers.erase(accepted);
        accepted->notifySessionState(false);
        if (!Ring::socketIsClosing(accepted)) Ring::queueClose(accepted);
      }
      RingDispatcher::eraseMultiplexee(listener);
      delete listener;
      if (shuttingDown && peers.empty() && privateListeners.empty() &&
          retiringPrivateListeners.empty() && !reconnectTimerQueued) hasShutdownBGP();
      return;
    }

    BGPPeer *peer = static_cast<BGPPeer *>(socket);

    if (peers.contains(peer)) // otherwise being withdrawn
    {
      if (peer->passiveOwner != nullptr)
      {
        BGPPrivateListener *listener = peer->passiveOwner;
        peer->passiveOwner = nullptr;
        if (listener->acceptedPeer == peer) listener->acceptedPeer = nullptr;
        peers.erase(peer);
        peer->notifySessionState(false);
        RingDispatcher::eraseMultiplexee(peer);
        delete peer;
        queuePrivateAccept(listener);
      }
      else if (shuttingDown)
      {
        peers.erase(peer);
        RingDispatcher::eraseMultiplexee(peer);
        delete peer;
        if (peers.empty() && privateListeners.empty() &&
            retiringPrivateListeners.empty() && !reconnectTimerQueued)
        {
          hasShutdownBGP();
        }
      }
      else
      {
        peer->state = BGPState::failed;
        if (peer->sessionStateObserver) peer->sessionStateObserver(peer->sessionStateContext, peer->peerAddress, false);
        scheduleReconnect(peer);
      }
    }
    else
    {
      RingDispatcher::eraseMultiplexee(peer);
      delete peer;
    }
  }

  void timeoutHandler(TimeoutPacket *packet, int result) override
  {
    if (packet != &reconnectTimer)
    {
      return;
    }

    reconnectTimerQueued = false;
    reconnectTimerCancellationQueued = false;
    RingDispatcher::eraseMultiplexee(this);
    if (result == -ECANCELED || shuttingDown)
    {
      if (shuttingDown && peers.empty() && privateListeners.empty() &&
          retiringPrivateListeners.empty()) hasShutdownBGP();
      return;
    }

    for (BGPPeer *peer : peers)
    {
      if (peer->state == BGPState::failed)
      {
        basics_log("BGP peer reconnect attempt failures=%u\n", unsigned(peer->reconnectFailures));
        // The closed TCP session may have left a partial frame or unsent data.
        peer->clearSessionBuffers();
        peer->recreateSocket();
        Ring::installFDIntoFixedFileSlot(peer);
        Ring::queueConnect(peer);
      }
    }
  }

  void shutdown(void)
  {
    shuttingDown = true;

    if (reconnectTimerQueued && !reconnectTimerCancellationQueued)
    {
      reconnectTimerCancellationQueued = true;
      Ring::queueCancelTimeout(&reconnectTimer);
    }

    while (!privateListeners.empty())
      retirePrivateListener(*privateListeners.begin());

    for (BGPPeer *peer : peers)
    {
      if (peer->fslot > -1)
      {
        Ring::queueClose(peer);
        peer->state = BGPState::failed;
      }
    }
  }
};
