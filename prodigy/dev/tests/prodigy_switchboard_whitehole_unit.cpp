#include <limits.h>
#include <networking/includes.h>
#include <services/debug.h>

#include <ebpf/common/structs.h>
#include <ebpf/program.h>

#include <bpf/bpf.h>
#include <switchboard/common/checksum.h>
#include <switchboard/common/constants.h>
#include <switchboard/common/local_container_subnet.h>
#include <switchboard/common/structs.h>
#include <switchboard/kernel/structs.h>
#include <switchboard/overlay.route.h>
#include <switchboard/whitehole.route.h>
#include <prodigy/quic.cid.generator.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <array>
#include <vector>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <linux/pkt_cls.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifndef PRODIGY_TEST_BINARY_DIR
#define PRODIGY_TEST_BINARY_DIR ""
#endif

class TestSuite {
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    if (condition)
    {
      std::fprintf(stderr, "PASS: %s\n", name);
    }
    else
    {
      std::fprintf(stderr, "FAIL: %s\n", name);
      failed += 1;
    }
  }
};

static uint32_t programMapID(BPFProgram& program, StringType auto&& mapName)
{
  uint32_t id = 0;

  program.openMap(mapName, [&](int mapFD) -> void {
    if (mapFD < 0)
    {
      return;
    }

    struct bpf_map_info info = {};
    __u32 infoLen = sizeof(info);
    if (bpf_map_get_info_by_fd(mapFD, &info, &infoLen) == 0)
    {
      id = info.id;
    }
  });

  return id;
}

static bool objectWhiteholeMapsUseAllocation(struct bpf_object *object, bool sparse, uint32_t maxEntries)
{
  static constexpr std::array<const char *, 3> mapNames = {"wh_targets", "wh_egress", "wh_egress4"};
  for (const char *mapName : mapNames)
  {
    struct bpf_map *map = object ? bpf_object__find_map_by_name(object, mapName) : nullptr;
    if (map == nullptr ||
        ((bpf_map__map_flags(map) & BPF_F_NO_PREALLOC) != 0) != sparse ||
        bpf_map__max_entries(map) != maxEntries)
    {
      return false;
    }
  }
  return true;
}

static void verifyDevelopmentWhiteholeMapAllocation(TestSuite& suite)
{
  String objectPath = {};
  objectPath.assign(PRODIGY_TEST_BINARY_DIR);
  objectPath.append("/host.ingress.router.ebpf.o"_ctv);

  const char *savedDevMode = std::getenv("PRODIGY_DEV_MODE");
  String savedDevModeText = {};
  if (savedDevMode)
  {
    savedDevModeText.assign(savedDevMode);
  }

  ::unsetenv("PRODIGY_DEV_MODE");
  struct bpf_object *productionObject = bpf_object__open_file(objectPath.c_str(), nullptr);
  if (libbpf_get_error(productionObject))
  {
    productionObject = nullptr;
  }
  switchboardConfigureDevelopmentWhiteholeMapAllocation(productionObject);
  suite.expect(objectWhiteholeMapsUseAllocation(productionObject, false, MAX_PORTALS * 256),
               "switchboard_production_whitehole_maps_retain_capacity_and_preallocation");
  if (productionObject)
  {
    bpf_object__close(productionObject);
  }

  ::setenv("PRODIGY_DEV_MODE", "1", 1);
  struct bpf_object *developmentObject = bpf_object__open_file(objectPath.c_str(), nullptr);
  if (libbpf_get_error(developmentObject))
  {
    developmentObject = nullptr;
  }
  switchboardConfigureDevelopmentWhiteholeMapAllocation(developmentObject);
  suite.expect(objectWhiteholeMapsUseAllocation(developmentObject, true, switchboardDevelopmentWhiteholeMapEntries),
               "switchboard_development_whitehole_maps_use_bounded_sparse_allocation");
  if (developmentObject)
  {
    bpf_object__close(developmentObject);
  }

  savedDevMode ? ::setenv("PRODIGY_DEV_MODE", savedDevModeText.c_str(), 1) : ::unsetenv("PRODIGY_DEV_MODE");
}

static IPPrefix makePrefix(const char *cidr)
{
  const char *slash = std::strrchr(cidr, '/');
  if (slash == nullptr)
  {
    std::fprintf(stderr, "unable to parse cidr: %s\n", cidr);
    std::abort();
  }

  String addressText = {};
  addressText.assign(cidr, uint64_t(slash - cidr));

  bool is6 = std::strchr(addressText.c_str(), ':') != nullptr;
  IPPrefix prefix(addressText.c_str(), is6, uint8_t(std::strtoul(slash + 1, nullptr, 10)));
  return prefix;
}

template <typename Key, typename Value>
static bool updateProgramMapElement(BPFProgram& program, StringType auto&& mapName, const Key& key, const Value& value)
{
  bool updated = false;
  program.openMap(mapName, [&](int mapFD) -> void {
    if (mapFD < 0)
    {
      return;
    }

    updated = (bpf_map_update_elem(mapFD, &key, &value, BPF_ANY) == 0);
  });

  return updated;
}

template <typename Key, typename Value>
static bool lookupProgramMapElement(BPFProgram& program, StringType auto&& mapName, const Key& key, Value& value)
{
  bool found = false;
  program.openMap(mapName, [&](int mapFD) -> void {
    found = mapFD >= 0 && bpf_map_lookup_elem(mapFD, &key, &value) == 0;
  });
  return found;
}

static bool installOverlayIngressPeerIPv4(BPFProgram& program, __be32 source, __be32 destination)
{
  switchboard_overlay_ingress_peer4_key key = {
      .source = source,
      .destination = destination,
  };
  __u8 present = 1;
  return updateProgramMapElement(program, "ovl_peer4"_ctv, key, present);
}

static bool installOverlayIngressPeerIPv6(BPFProgram& program, const uint8_t source[16], const uint8_t destination[16])
{
  switchboard_overlay_ingress_peer6_key key = {};
  std::memcpy(key.source, source, sizeof(key.source));
  std::memcpy(key.destination, destination, sizeof(key.destination));
  __u8 present = 1;
  return updateProgramMapElement(program, "ovl_peer6"_ctv, key, present);
}

template <typename Key>
static void clearProgramMap(BPFProgram& program, StringType auto&& mapName)
{
  program.openMap(mapName, [&](int mapFD) -> void {
    Key key = {};
    while (mapFD >= 0 && bpf_map_get_next_key(mapFD, nullptr, &key) == 0)
    {
      (void)bpf_map_delete_elem(mapFD, &key);
    }
  });
}

static void parseIPv6Bytes(const char *text, uint8_t out[16])
{
  if (inet_pton(AF_INET6, text, out) != 1)
  {
    std::fprintf(stderr, "unable to parse IPv6 address: %s\n", text);
    std::abort();
  }
}

static in_addr parseIPv4Address(const char *text)
{
  in_addr address = {};
  if (inet_pton(AF_INET, text, &address) != 1)
  {
    std::fprintf(stderr, "unable to parse IPv4 address: %s\n", text);
    std::abort();
  }
  return address;
}

static void makeContainerIPv6(uint8_t address[16],
                              uint8_t datacenterPrefix,
                              uint8_t machinePrefix0,
                              uint8_t machinePrefix1,
                              uint8_t machinePrefix2,
                              uint8_t containerFragment)
{
  std::memcpy(address, container_network_subnet6.value, sizeof(container_network_subnet6.value));
  address[11] = datacenterPrefix;
  address[12] = machinePrefix0;
  address[13] = machinePrefix1;
  address[14] = machinePrefix2;
  address[15] = containerFragment;
}

static std::vector<uint8_t> makeIPv6InIPv6EthernetFrame(const uint8_t outerSrc[16],
                                                        const uint8_t outerDst[16],
                                                        const uint8_t innerSrc[16],
                                                        const uint8_t innerDst[16])
{
  std::vector<uint8_t> frame(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct ipv6hdr));
  std::memset(frame.data(), 0, frame.size());

  struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(frame.data());
  eth->h_proto = htons(ETH_P_IPV6);

  struct ipv6hdr *outer6 = reinterpret_cast<struct ipv6hdr *>(frame.data() + sizeof(struct ethhdr));
  outer6->version = 6;
  outer6->nexthdr = IPPROTO_IPV6;
  outer6->hop_limit = 64;
  outer6->payload_len = htons(sizeof(struct ipv6hdr));
  std::memcpy(outer6->saddr.s6_addr, outerSrc, sizeof(outer6->saddr.s6_addr));
  std::memcpy(outer6->daddr.s6_addr, outerDst, sizeof(outer6->daddr.s6_addr));

  struct ipv6hdr *inner6 = outer6 + 1;
  inner6->version = 6;
  inner6->nexthdr = IPPROTO_NONE;
  inner6->hop_limit = 64;
  inner6->payload_len = 0;
  std::memcpy(inner6->saddr.s6_addr, innerSrc, sizeof(inner6->saddr.s6_addr));
  std::memcpy(inner6->daddr.s6_addr, innerDst, sizeof(inner6->daddr.s6_addr));
  return frame;
}

static std::vector<uint8_t> makeICMPv6InIPv6EthernetFrame(const uint8_t outerSrc[16],
                                                          const uint8_t outerDst[16],
                                                          const uint8_t innerSrc[16],
                                                          const uint8_t innerDst[16])
{
  std::vector<uint8_t> frame(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct ipv6hdr) + sizeof(struct icmp6_hdr));
  std::memset(frame.data(), 0, frame.size());

  struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(frame.data());
  eth->h_proto = htons(ETH_P_IPV6);

  struct ipv6hdr *outer6 = reinterpret_cast<struct ipv6hdr *>(frame.data() + sizeof(struct ethhdr));
  outer6->version = 6;
  outer6->nexthdr = IPPROTO_IPV6;
  outer6->hop_limit = 64;
  outer6->payload_len = htons(sizeof(struct ipv6hdr) + sizeof(struct icmp6_hdr));
  std::memcpy(outer6->saddr.s6_addr, outerSrc, sizeof(outer6->saddr.s6_addr));
  std::memcpy(outer6->daddr.s6_addr, outerDst, sizeof(outer6->daddr.s6_addr));

  struct ipv6hdr *inner6 = outer6 + 1;
  inner6->version = 6;
  inner6->nexthdr = IPPROTO_ICMPV6;
  inner6->hop_limit = 64;
  inner6->payload_len = htons(sizeof(struct icmp6_hdr));
  std::memcpy(inner6->saddr.s6_addr, innerSrc, sizeof(inner6->saddr.s6_addr));
  std::memcpy(inner6->daddr.s6_addr, innerDst, sizeof(inner6->daddr.s6_addr));

  struct icmp6_hdr *icmp6 = reinterpret_cast<struct icmp6_hdr *>(inner6 + 1);
  icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
  icmp6->icmp6_code = 0;
  icmp6->icmp6_id = htons(0x1203);
  icmp6->icmp6_seq = htons(0x0042);
  return frame;
}

static uint16_t checksumIPv6Transport(const uint8_t src[16],
                                      const uint8_t dst[16],
                                      uint8_t nextHeader,
                                      const void *transport,
                                      size_t transportSize);

static std::vector<uint8_t> makeUDPv6InIPv6EthernetFrame(const uint8_t outerSrc[16],
                                                         const uint8_t outerDst[16],
                                                         const uint8_t innerSrc[16],
                                                         const uint8_t innerDst[16],
                                                         uint16_t sourcePort,
                                                         uint16_t destPort,
                                                         const std::vector<uint8_t>& payload)
{
  std::vector<uint8_t> frame(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr) + payload.size());
  std::memset(frame.data(), 0, frame.size());

  struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(frame.data());
  eth->h_proto = htons(ETH_P_IPV6);

  struct ipv6hdr *outer6 = reinterpret_cast<struct ipv6hdr *>(frame.data() + sizeof(struct ethhdr));
  outer6->version = 6;
  outer6->nexthdr = IPPROTO_IPV6;
  outer6->hop_limit = 64;
  outer6->payload_len = htons(sizeof(struct ipv6hdr) + sizeof(struct udphdr) + payload.size());
  std::memcpy(outer6->saddr.s6_addr, outerSrc, sizeof(outer6->saddr.s6_addr));
  std::memcpy(outer6->daddr.s6_addr, outerDst, sizeof(outer6->daddr.s6_addr));

  struct ipv6hdr *inner6 = outer6 + 1;
  inner6->version = 6;
  inner6->nexthdr = IPPROTO_UDP;
  inner6->hop_limit = 64;
  inner6->payload_len = htons(sizeof(struct udphdr) + payload.size());
  std::memcpy(inner6->saddr.s6_addr, innerSrc, sizeof(inner6->saddr.s6_addr));
  std::memcpy(inner6->daddr.s6_addr, innerDst, sizeof(inner6->daddr.s6_addr));

  struct udphdr *udp = reinterpret_cast<struct udphdr *>(inner6 + 1);
  udp->source = htons(sourcePort);
  udp->dest = htons(destPort);
  udp->len = htons(sizeof(struct udphdr) + payload.size());

  if (payload.empty() == false)
  {
    std::memcpy(reinterpret_cast<uint8_t *>(udp + 1), payload.data(), payload.size());
  }

  udp->check = checksumIPv6Transport(inner6->saddr.s6_addr,
                                     inner6->daddr.s6_addr,
                                     IPPROTO_UDP,
                                     udp,
                                     sizeof(struct udphdr) + payload.size());
  return frame;
}

static std::vector<uint8_t> makeUDPv4QuicEthernetFrame(const struct in_addr& source,
                                                       const struct in_addr& destination,
                                                       uint16_t sourcePort,
                                                       uint16_t destinationPort,
                                                       const ProdigyQuicCID& cid)
{
  std::vector<uint8_t> frame(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct quic_long_header) + 1);
  std::memset(frame.data(), 0, frame.size());

  struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(frame.data());
  eth->h_proto = htons(ETH_P_IP);

  struct iphdr *ip4 = reinterpret_cast<struct iphdr *>(frame.data() + sizeof(struct ethhdr));
  ip4->version = 4;
  ip4->ihl = 5;
  ip4->ttl = 64;
  ip4->protocol = IPPROTO_UDP;
  ip4->tot_len = htons(uint16_t(frame.size() - sizeof(struct ethhdr)));
  ip4->saddr = source.s_addr;
  ip4->daddr = destination.s_addr;

  struct udphdr *udp = reinterpret_cast<struct udphdr *>(ip4 + 1);
  udp->source = htons(sourcePort);
  udp->dest = htons(destinationPort);
  udp->len = htons(uint16_t(sizeof(struct udphdr) + sizeof(struct quic_long_header) + 1));

  struct quic_long_header *quic = reinterpret_cast<struct quic_long_header *>(udp + 1);
  quic->flags = QUIC_V1_LONG_HEADER | QUIC_V1_CLIENT_INITIAL;
  quic->version = 1;
  quic->conn_id_lens = cid.id_len;
  std::memcpy(quic->dst_cid, cid.id, cid.id_len);
  *(reinterpret_cast<uint8_t *>(quic + 1)) = 0;

  return frame;
}

static std::vector<uint8_t> makeUDPv4QuicInIPv6EthernetFrame(const uint8_t outerSrc[16],
                                                             const uint8_t outerDst[16],
                                                             const struct in_addr& innerSource,
                                                             const struct in_addr& innerDestination,
                                                             uint16_t sourcePort,
                                                             uint16_t destinationPort,
                                                             const ProdigyQuicCID& cid)
{
  std::vector<uint8_t> inner = makeUDPv4QuicEthernetFrame(innerSource, innerDestination, sourcePort, destinationPort, cid);
  size_t innerSize = inner.size() - sizeof(struct ethhdr);
  std::vector<uint8_t> frame(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + innerSize);
  std::memset(frame.data(), 0, frame.size());

  struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(frame.data());
  eth->h_proto = htons(ETH_P_IPV6);

  struct ipv6hdr *outer6 = reinterpret_cast<struct ipv6hdr *>(frame.data() + sizeof(struct ethhdr));
  outer6->version = 6;
  outer6->nexthdr = IPPROTO_IPIP;
  outer6->hop_limit = 64;
  outer6->payload_len = htons(innerSize);
  std::memcpy(outer6->saddr.s6_addr, outerSrc, sizeof(outer6->saddr.s6_addr));
  std::memcpy(outer6->daddr.s6_addr, outerDst, sizeof(outer6->daddr.s6_addr));
  std::memcpy(outer6 + 1, inner.data() + sizeof(struct ethhdr), innerSize);
  return frame;
}

static uint16_t foldChecksum(uint32_t sum)
{
  while (sum >> 16)
  {
    sum = (sum & 0xffffu) + (sum >> 16);
  }

  uint16_t checksum = static_cast<uint16_t>(~sum & 0xffffu);
  return checksum == 0 ? 0xffffu : checksum;
}

static uint16_t checksumBytes(const void *data, size_t size)
{
  const uint8_t *bytes = static_cast<const uint8_t *>(data);
  uint32_t sum = 0;

  for (size_t index = 0; index + 1 < size; index += 2)
  {
    sum += static_cast<uint32_t>(bytes[index] << 8 | bytes[index + 1]);
  }

  if (size & 1U)
  {
    sum += static_cast<uint32_t>(bytes[size - 1] << 8);
  }

  return foldChecksum(sum);
}

static uint16_t checksumIPv6Transport(const uint8_t src[16],
                                      const uint8_t dst[16],
                                      uint8_t nextHeader,
                                      const void *transport,
                                      size_t transportSize)
{
  uint32_t sum = 0;

  auto accumulate = [&](const void *data, size_t size) -> void {
    const uint8_t *bytes = static_cast<const uint8_t *>(data);
    for (size_t index = 0; index + 1 < size; index += 2)
    {
      sum += static_cast<uint32_t>(bytes[index] << 8 | bytes[index + 1]);
    }

    if (size & 1U)
    {
      sum += static_cast<uint32_t>(bytes[size - 1] << 8);
    }
  };

  accumulate(src, 16);
  accumulate(dst, 16);

  uint8_t lengthBytes[4] = {
      static_cast<uint8_t>((transportSize >> 24) & 0xffU),
      static_cast<uint8_t>((transportSize >> 16) & 0xffU),
      static_cast<uint8_t>((transportSize >> 8) & 0xffU),
      static_cast<uint8_t>(transportSize & 0xffU)};
  accumulate(lengthBytes, sizeof(lengthBytes));

  uint8_t nextHeaderBytes[4] = {0, 0, 0, nextHeader};
  accumulate(nextHeaderBytes, sizeof(nextHeaderBytes));
  accumulate(transport, transportSize);

  return foldChecksum(sum);
}

static uint16_t replaceChecksumIPv6AddressIncremental(uint16_t checksum, const uint8_t oldValue[16], const uint8_t newValue[16])
{
  uint16_t updated = checksum;
  for (size_t offset = 0; offset < 16; offset += sizeof(uint32_t))
  {
    updated = replace_l4_checksum_portable(updated, oldValue + offset, newValue + offset, sizeof(uint32_t));
  }

  return updated;
}

static std::vector<uint8_t> makeIPv4L4EthernetFrame(const struct in_addr& source,
                                                    const struct in_addr& destination,
                                                    uint8_t proto,
                                                    uint16_t sourcePort,
                                                    uint16_t destinationPort,
                                                    size_t payloadBytes = 0)
{
  const size_t l4Size = (proto == IPPROTO_TCP) ? sizeof(struct tcphdr) : sizeof(struct udphdr);
  std::vector<uint8_t> frame(sizeof(struct ethhdr) + sizeof(struct iphdr) + l4Size + payloadBytes);
  std::memset(frame.data(), 0, frame.size());

  struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(frame.data());
  eth->h_proto = htons(ETH_P_IP);

  struct iphdr *ip4 = reinterpret_cast<struct iphdr *>(frame.data() + sizeof(struct ethhdr));
  ip4->version = 4;
  ip4->ihl = 5;
  ip4->ttl = 64;
  ip4->protocol = proto;
  ip4->tot_len = htons(uint16_t(frame.size() - sizeof(struct ethhdr)));
  ip4->saddr = source.s_addr;
  ip4->daddr = destination.s_addr;

  if (proto == IPPROTO_TCP)
  {
    struct tcphdr *tcp = reinterpret_cast<struct tcphdr *>(ip4 + 1);
    tcp->source = htons(sourcePort);
    tcp->dest = htons(destinationPort);
    tcp->doff = 5;
    tcp->syn = 1;
  }
  else
  {
    struct udphdr *udp = reinterpret_cast<struct udphdr *>(ip4 + 1);
    udp->source = htons(sourcePort);
    udp->dest = htons(destinationPort);
    udp->len = htons(static_cast<uint16_t>(sizeof(struct udphdr) + payloadBytes));
  }

  return frame;
}

static std::vector<uint8_t> makeIPv4ICMPEthernetFrame(const struct in_addr& source, const struct in_addr& destination)
{
  std::vector<uint8_t> frame(sizeof(struct ethhdr) + sizeof(struct iphdr) + 8);
  std::memset(frame.data(), 0, frame.size());

  struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(frame.data());
  eth->h_proto = htons(ETH_P_IP);

  struct iphdr *ip4 = reinterpret_cast<struct iphdr *>(frame.data() + sizeof(struct ethhdr));
  ip4->version = 4;
  ip4->ihl = 5;
  ip4->ttl = 64;
  ip4->protocol = IPPROTO_ICMP;
  ip4->tot_len = htons(uint16_t(frame.size() - sizeof(struct ethhdr)));
  ip4->saddr = source.s_addr;
  ip4->daddr = destination.s_addr;
  return frame;
}

static std::vector<uint8_t> makeIPv6L4EthernetFrame(const uint8_t source[16],
                                                    const uint8_t destination[16],
                                                    uint8_t proto,
                                                    uint16_t sourcePort,
                                                    uint16_t destinationPort,
                                                    size_t payloadBytes = 0)
{
  const size_t l4Size = (proto == IPPROTO_TCP) ? sizeof(struct tcphdr) : sizeof(struct udphdr);
  std::vector<uint8_t> frame(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + l4Size + payloadBytes);
  std::memset(frame.data(), 0, frame.size());

  struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(frame.data());
  eth->h_proto = htons(ETH_P_IPV6);

  struct ipv6hdr *ip6 = reinterpret_cast<struct ipv6hdr *>(frame.data() + sizeof(struct ethhdr));
  ip6->version = 6;
  ip6->nexthdr = proto;
  ip6->hop_limit = 64;
  ip6->payload_len = htons(l4Size + payloadBytes);
  std::memcpy(ip6->saddr.s6_addr, source, sizeof(ip6->saddr.s6_addr));
  std::memcpy(ip6->daddr.s6_addr, destination, sizeof(ip6->daddr.s6_addr));

  if (proto == IPPROTO_TCP)
  {
    struct tcphdr *tcp = reinterpret_cast<struct tcphdr *>(ip6 + 1);
    tcp->source = htons(sourcePort);
    tcp->dest = htons(destinationPort);
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->check = checksumIPv6Transport(ip6->saddr.s6_addr, ip6->daddr.s6_addr, IPPROTO_TCP, tcp, sizeof(*tcp) + payloadBytes);
  }
  else
  {
    struct udphdr *udp = reinterpret_cast<struct udphdr *>(ip6 + 1);
    udp->source = htons(sourcePort);
    udp->dest = htons(destinationPort);
    udp->len = htons(sizeof(struct udphdr) + payloadBytes);
    udp->check = checksumIPv6Transport(ip6->saddr.s6_addr, ip6->daddr.s6_addr, IPPROTO_UDP, udp, sizeof(*udp) + payloadBytes);
  }

  return frame;
}

static std::vector<uint8_t> makeWormholeIPv6OverlayFrame(const std::vector<uint8_t>& inner,
                                                         const uint8_t container[5])
{
  const size_t added = sizeof(struct ipv6hdr) + sizeof(struct switchboard_wormhole_overlay_header);
  std::vector<uint8_t> frame(inner.size() + added);
  std::memset(frame.data(), 0, frame.size());
  std::memcpy(frame.data(), inner.data(), sizeof(struct ethhdr));
  std::memcpy(frame.data() + sizeof(struct ethhdr) + added,
              inner.data() + sizeof(struct ethhdr),
              inner.size() - sizeof(struct ethhdr));

  struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(frame.data());
  eth->h_proto = htons(ETH_P_IPV6);
  struct ipv6hdr *outer = reinterpret_cast<struct ipv6hdr *>(eth + 1);
  outer->version = 6;
  outer->nexthdr = IPPROTO_GRE;
  outer->hop_limit = 64;
  outer->payload_len = htons(static_cast<uint16_t>(sizeof(struct switchboard_wormhole_overlay_header) + inner.size() - sizeof(struct ethhdr)));
  parseIPv6Bytes("fd00:10::a", outer->saddr.s6_addr);
  parseIPv6Bytes("fd00:10::b", outer->daddr.s6_addr);

  container_id selected = {};
  selected.hasID = true;
  std::memcpy(selected.value, container, sizeof(selected.value));
  switchboard_wormhole_overlay_header *provenance = reinterpret_cast<switchboard_wormhole_overlay_header *>(outer + 1);
  const struct ethhdr *innerEth = reinterpret_cast<const struct ethhdr *>(inner.data());
  switchboardBuildWormholeOverlayHeader(provenance, &selected, innerEth->h_proto == htons(ETH_P_IPV6));
  return frame;
}

static std::vector<uint8_t> makeIPv6TCPPortalFrameWithOptionsAndPayload(const uint8_t source[16],
                                                                        const uint8_t destination[16],
                                                                        uint16_t sourcePort,
                                                                        uint16_t destinationPort,
                                                                        size_t tcpOptionsBytes,
                                                                        size_t payloadBytes)
{
  if ((tcpOptionsBytes & 3u) != 0 || tcpOptionsBytes > 40)
  {
    std::fprintf(stderr, "invalid tcp option byte count: %zu\n", tcpOptionsBytes);
    std::abort();
  }

  const size_t tcpHeaderBytes = sizeof(struct tcphdr) + tcpOptionsBytes;
  std::vector<uint8_t> frame(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + tcpHeaderBytes + payloadBytes);
  std::memset(frame.data(), 0, frame.size());

  struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(frame.data());
  eth->h_proto = htons(ETH_P_IPV6);

  struct ipv6hdr *ip6 = reinterpret_cast<struct ipv6hdr *>(frame.data() + sizeof(struct ethhdr));
  ip6->version = 6;
  ip6->nexthdr = IPPROTO_TCP;
  ip6->hop_limit = 64;
  ip6->payload_len = htons(static_cast<uint16_t>(tcpHeaderBytes + payloadBytes));
  std::memcpy(ip6->saddr.s6_addr, source, sizeof(ip6->saddr.s6_addr));
  std::memcpy(ip6->daddr.s6_addr, destination, sizeof(ip6->daddr.s6_addr));

  struct tcphdr *tcp = reinterpret_cast<struct tcphdr *>(ip6 + 1);
  tcp->source = htons(sourcePort);
  tcp->dest = htons(destinationPort);
  tcp->seq = htonl(0x19283746);
  tcp->ack_seq = htonl(0x91827364);
  tcp->doff = static_cast<uint16_t>(tcpHeaderBytes / 4u);
  tcp->ack = 1;
  tcp->psh = 1;
  tcp->window = htons(4096);

  uint8_t *options = reinterpret_cast<uint8_t *>(tcp + 1);
  for (size_t index = 0; index < tcpOptionsBytes; index += 1)
  {
    options[index] = 1u;
  }

  uint8_t *payload = reinterpret_cast<uint8_t *>(tcp) + tcpHeaderBytes;
  for (size_t index = 0; index < payloadBytes; index += 1)
  {
    payload[index] = static_cast<uint8_t>((index * 43u + 29u) & 0xffu);
  }

  tcp->check = htons(checksumIPv6Transport(ip6->saddr.s6_addr,
                                           ip6->daddr.s6_addr,
                                           IPPROTO_TCP,
                                           tcp,
                                           tcpHeaderBytes + payloadBytes));
  return frame;
}

static bool installSingleContainerPortalRing(BPFProgram& program, uint32_t slot, const uint8_t container[5])
{
  int ringFD = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(container_id), RING_SIZE, nullptr);
  if (ringFD < 0)
  {
    return false;
  }

  container_id entry = {};
  entry.hasID = true;
  std::memcpy(entry.value, container, sizeof(entry.value));

  bool ringFilled = true;
  for (uint32_t index = 0; index < RING_SIZE; ++index)
  {
    if (bpf_map_update_elem(ringFD, &index, &entry, BPF_ANY) != 0)
    {
      ringFilled = false;
      break;
    }
  }

  bool outerUpdated = false;
  if (ringFilled)
  {
    program.openMap("cid_rings"_ctv, [&](int mapFD) -> void {
      outerUpdated = mapFD >= 0 && bpf_map_update_elem(mapFD, &slot, &ringFD, BPF_ANY) == 0;
    });
  }

  close(ringFD);
  return ringFilled && outerUpdated;
}

static bool installWormholeExposure(BPFProgram& program,
                                    const portal_definition& portal,
                                    bool ipv6,
                                    const uint8_t container[5],
                                    __be16 targetPort,
                                    __u64 ownerGeneration)
{
  switchboard_wormhole_egress_binding binding = {};
  binding.port = portal.port;
  binding.proto = portal.proto;
  binding.owner_generation = ownerGeneration;

  if (ipv6)
  {
    std::memcpy(binding.addr6, portal.addr6, sizeof(binding.addr6));
    binding.is_ipv6 = 1;

    switchboard_wormhole_egress_key key = {};
    std::memcpy(key.container, container, sizeof(key.container));
    key.port = targetPort;
    key.proto = portal.proto;
    return updateProgramMapElement(program, "wh_egress"_ctv, key, binding);
  }

  binding.addr4 = portal.addr4;
  switchboard_wormhole_egress4_key key = {};
  key.addr = portal.addr4;
  key.port = targetPort;
  key.proto = portal.proto;
  return updateProgramMapElement(program, "wh_egress4"_ctv, key, binding);
}

static void exerciseHostIngressGenericPortal(TestSuite& suite, bool ipv6, uint8_t proto)
{
  String ingressObjectPath = {};
  ingressObjectPath.assign(PRODIGY_TEST_BINARY_DIR);
  ingressObjectPath.append("/host.ingress.router.dev.ebpf.o"_ctv);

  BPFProgram ingressProgram = {};
  suite.expect(ingressProgram.load(ingressObjectPath, "host_ingress"_ctv),
               ipv6
                   ? (proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv6_tcp_portal_loads_program" : "switchboard_host_ingress_ipv6_udp_portal_loads_program")
                   : (proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv4_tcp_portal_loads_program" : "switchboard_host_ingress_ipv4_udp_portal_loads_program"));

  if (ingressProgram.prog_fd < 0)
  {
    return;
  }

  local_container_subnet6 localSubnet = {};
  localSubnet.dpfx = 0x01;
  localSubnet.mpfx[0] = 0x52;
  localSubnet.mpfx[1] = 0xdf;
  localSubnet.mpfx[2] = 0x39;
  ingressProgram.setArrayElement("lc_subnet"_ctv, 0, localSubnet);

  constexpr uint8_t containerFragment = 0x4e;
  uint32_t redirectIfidx = 93;
  ingressProgram.setArrayElement("ct_dev_map"_ctv, containerFragment, redirectIfidx);

  uint8_t containerID[5] = {localSubnet.dpfx, localSubnet.mpfx[0], localSubnet.mpfx[1], localSubnet.mpfx[2], containerFragment};
  portal_meta meta = {};
  meta.flags = 0;
  meta.slot = ipv6 ? (proto == IPPROTO_TCP ? 13u : 12u) : (proto == IPPROTO_TCP ? 11u : 10u);

  suite.expect(installSingleContainerPortalRing(ingressProgram, meta.slot, containerID),
               ipv6
                   ? (proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv6_tcp_portal_installs_ring" : "switchboard_host_ingress_ipv6_udp_portal_installs_ring")
                   : (proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv4_tcp_portal_installs_ring" : "switchboard_host_ingress_ipv4_udp_portal_installs_ring"));

  const uint16_t externalPortHost = proto == IPPROTO_TCP ? 443 : 4443;
  const uint16_t containerPortHost = proto == IPPROTO_TCP ? 18'443 : 18'444;
  portal_definition portal = {};
  portal.port = htons(externalPortHost);
  portal.proto = proto;

  struct in_addr external4 = {};
  struct in_addr client4 = {};
  uint8_t external6[16] = {};
  uint8_t client6[16] = {};
  if (ipv6)
  {
    suite.expect(inet_pton(AF_INET6, "2001:db8:100::44", external6) == 1,
                 proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv6_tcp_portal_external_parses" : "switchboard_host_ingress_ipv6_udp_portal_external_parses");
    suite.expect(inet_pton(AF_INET6, "2001:db8:200::99", client6) == 1,
                 proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv6_tcp_portal_client_parses" : "switchboard_host_ingress_ipv6_udp_portal_client_parses");
    std::memcpy(portal.addr6, external6, sizeof(portal.addr6));
  }
  else
  {
    suite.expect(inet_pton(AF_INET, "198.18.0.1", &external4) == 1,
                 proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv4_tcp_portal_external_parses" : "switchboard_host_ingress_ipv4_udp_portal_external_parses");
    suite.expect(inet_pton(AF_INET, "203.0.113.99", &client4) == 1,
                 proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv4_tcp_portal_client_parses" : "switchboard_host_ingress_ipv4_udp_portal_client_parses");
    portal.addr4 = external4.s_addr;
  }

  bool portalUpdated = false;
  ingressProgram.openMap("ext_portals"_ctv, [&](int mapFD) -> void {
    portalUpdated = mapFD >= 0 && bpf_map_update_elem(mapFD, &portal, &meta, BPF_ANY) == 0;
  });
  suite.expect(portalUpdated,
               ipv6
                   ? (proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv6_tcp_portal_installs_portal" : "switchboard_host_ingress_ipv6_udp_portal_installs_portal")
                   : (proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv4_tcp_portal_installs_portal" : "switchboard_host_ingress_ipv4_udp_portal_installs_portal"));

  switchboard_wormhole_target_key targetKey = {};
  targetKey.slot = meta.slot;
  std::memcpy(targetKey.container, containerID, sizeof(targetKey.container));
  uint16_t targetPort = htons(containerPortHost);
  bool targetUpdated = false;
  ingressProgram.openMap("wh_targets"_ctv, [&](int mapFD) -> void {
    targetUpdated = mapFD >= 0 && bpf_map_update_elem(mapFD, &targetKey, &targetPort, BPF_ANY) == 0;
  });
  suite.expect(targetUpdated,
               ipv6
                   ? (proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv6_tcp_portal_installs_target_port" : "switchboard_host_ingress_ipv6_udp_portal_installs_target_port")
                   : (proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv4_tcp_portal_installs_target_port" : "switchboard_host_ingress_ipv4_udp_portal_installs_target_port"));
  suite.expect(installWormholeExposure(ingressProgram, portal, ipv6, containerID, targetPort, meta.slot + 1u),
               ipv6
                   ? (proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv6_tcp_portal_installs_exposure" : "switchboard_host_ingress_ipv6_udp_portal_installs_exposure")
                   : (proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv4_tcp_portal_installs_exposure" : "switchboard_host_ingress_ipv4_udp_portal_installs_exposure"));

  std::vector<uint8_t> frame = ipv6
                                   ? makeIPv6L4EthernetFrame(client6, external6, proto, 49'152, externalPortHost)
                                   : makeIPv4L4EthernetFrame(client4, external4, proto, 49'152, externalPortHost);
  std::vector<uint8_t> output(frame.size());
  LIBBPF_OPTS(bpf_test_run_opts, opts,
              .data_in = frame.data(),
              .data_out = output.data(),
              .data_size_in = static_cast<__u32>(frame.size()),
              .data_size_out = static_cast<__u32>(output.size()),
              .repeat = 1, );

  int runResult = bpf_prog_test_run_opts(ingressProgram.prog_fd, &opts);
  suite.expect(runResult == 0,
               ipv6
                   ? (proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv6_tcp_portal_test_run_succeeds" : "switchboard_host_ingress_ipv6_udp_portal_test_run_succeeds")
                   : (proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv4_tcp_portal_test_run_succeeds" : "switchboard_host_ingress_ipv4_udp_portal_test_run_succeeds"));
  suite.expect(opts.retval == TC_ACT_REDIRECT,
               ipv6
                   ? (proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv6_tcp_portal_redirects_to_container" : "switchboard_host_ingress_ipv6_udp_portal_redirects_to_container")
                   : (proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv4_tcp_portal_redirects_to_container" : "switchboard_host_ingress_ipv4_udp_portal_redirects_to_container"));

  if (runResult == 0)
  {
    const struct ethhdr *outEth = reinterpret_cast<const struct ethhdr *>(output.data());
    if (ipv6 && opts.data_size_out >= sizeof(struct ethhdr) + sizeof(struct ipv6hdr))
    {
      const struct ipv6hdr *outIP = reinterpret_cast<const struct ipv6hdr *>(output.data() + sizeof(struct ethhdr));
      makeContainerIPv6(external6, localSubnet.dpfx, localSubnet.mpfx[0], localSubnet.mpfx[1], localSubnet.mpfx[2], containerFragment);
      suite.expect(outEth->h_proto == htons(ETH_P_IPV6),
                   proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv6_tcp_portal_preserves_ethertype" : "switchboard_host_ingress_ipv6_udp_portal_preserves_ethertype");
      suite.expect(std::memcmp(outIP->daddr.s6_addr, external6, sizeof(outIP->daddr.s6_addr)) == 0,
                   proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv6_tcp_portal_rewrites_destination" : "switchboard_host_ingress_ipv6_udp_portal_rewrites_destination");
      if (proto == IPPROTO_TCP)
      {
        const struct tcphdr *outTCP = reinterpret_cast<const struct tcphdr *>(outIP + 1);
        suite.expect(outTCP->dest == targetPort, "switchboard_host_ingress_ipv6_tcp_portal_rewrites_container_port");
      }
      else
      {
        const struct udphdr *outUDP = reinterpret_cast<const struct udphdr *>(outIP + 1);
        suite.expect(outUDP->dest == targetPort, "switchboard_host_ingress_ipv6_udp_portal_rewrites_container_port");
      }
    }
    else if (!ipv6 && opts.data_size_out >= sizeof(struct ethhdr) + sizeof(struct iphdr))
    {
      const struct iphdr *outIP = reinterpret_cast<const struct iphdr *>(output.data() + sizeof(struct ethhdr));
      suite.expect(outEth->h_proto == htons(ETH_P_IP),
                   proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv4_tcp_portal_preserves_ethertype" : "switchboard_host_ingress_ipv4_udp_portal_preserves_ethertype");
      suite.expect(outIP->daddr == external4.s_addr,
                   proto == IPPROTO_TCP ? "switchboard_host_ingress_ipv4_tcp_portal_preserves_external_destination" : "switchboard_host_ingress_ipv4_udp_portal_preserves_external_destination");
      if (proto == IPPROTO_TCP)
      {
        const struct tcphdr *outTCP = reinterpret_cast<const struct tcphdr *>(outIP + 1);
        suite.expect(outTCP->dest == targetPort, "switchboard_host_ingress_ipv4_tcp_portal_rewrites_container_port");
      }
      else
      {
        const struct udphdr *outUDP = reinterpret_cast<const struct udphdr *>(outIP + 1);
        suite.expect(outUDP->dest == targetPort, "switchboard_host_ingress_ipv4_udp_portal_rewrites_container_port");
      }
    }
  }

  ingressProgram.close();
}

static void exerciseHostIngressIPv6TCPPortalBrowserSizedPayload(TestSuite& suite)
{
  const char *label = "switchboard_host_ingress_ipv6_tcp_portal_browser_sized_payload";
  auto expectNamed = [&](bool condition, const char *suffix) -> void {
    char name[256] = {};
    std::snprintf(name, sizeof(name), "%s_%s", label, suffix);
    suite.expect(condition, name);
  };

  String ingressObjectPath = {};
  ingressObjectPath.assign(PRODIGY_TEST_BINARY_DIR);
  ingressObjectPath.append("/host.ingress.router.dev.ebpf.o"_ctv);

  BPFProgram ingressProgram = {};
  expectNamed(ingressProgram.load(ingressObjectPath, "host_ingress"_ctv), "loads_program");
  if (ingressProgram.prog_fd < 0)
  {
    return;
  }

  local_container_subnet6 localSubnet = {};
  localSubnet.dpfx = 0x01;
  localSubnet.mpfx[0] = 0x52;
  localSubnet.mpfx[1] = 0xdf;
  localSubnet.mpfx[2] = 0x39;
  ingressProgram.setArrayElement("lc_subnet"_ctv, 0, localSubnet);

  constexpr uint8_t containerFragment = 0x62;
  uint32_t redirectIfidx = 94;
  ingressProgram.setArrayElement("ct_dev_map"_ctv, containerFragment, redirectIfidx);

  uint8_t containerID[5] = {localSubnet.dpfx, localSubnet.mpfx[0], localSubnet.mpfx[1], localSubnet.mpfx[2], containerFragment};
  portal_meta meta = {};
  meta.flags = 0;
  meta.slot = 14u;
  expectNamed(installSingleContainerPortalRing(ingressProgram, meta.slot, containerID), "installs_ring");

  uint8_t external6[16] = {};
  uint8_t client6[16] = {};
  expectNamed(inet_pton(AF_INET6, "2602:fac0:0:12ab:34cd::1", external6) == 1, "external_address_parses");
  expectNamed(inet_pton(AF_INET6, "2001:db8:100::1", client6) == 1, "client_address_parses");

  portal_definition portal = {};
  std::memcpy(portal.addr6, external6, sizeof(portal.addr6));
  portal.port = htons(444);
  portal.proto = IPPROTO_TCP;
  expectNamed(updateProgramMapElement(ingressProgram, "ext_portals"_ctv, portal, meta), "installs_portal");

  switchboard_wormhole_target_key targetKey = {};
  targetKey.slot = meta.slot;
  std::memcpy(targetKey.container, containerID, sizeof(targetKey.container));
  uint16_t targetPort = htons(8444);
  expectNamed(updateProgramMapElement(ingressProgram, "wh_targets"_ctv, targetKey, targetPort), "installs_target_port");
  expectNamed(installWormholeExposure(ingressProgram, portal, true, containerID, targetPort, meta.slot + 1u),
              "installs_exposure");

  std::vector<uint8_t> frame = makeIPv6TCPPortalFrameWithOptionsAndPayload(
      client6,
      external6,
      42'186,
      444,
      12,
      2020);
  expectNamed(frame.size() == 2106u, "matches_failed_browser_frame_size");

  std::vector<uint8_t> output(frame.size());
  LIBBPF_OPTS(bpf_test_run_opts, opts,
              .data_in = frame.data(),
              .data_out = output.data(),
              .data_size_in = static_cast<__u32>(frame.size()),
              .data_size_out = static_cast<__u32>(output.size()),
              .repeat = 1, );

  int runResult = bpf_prog_test_run_opts(ingressProgram.prog_fd, &opts);
  expectNamed(runResult == 0, "test_run_succeeds");
  expectNamed(opts.retval == TC_ACT_REDIRECT, "redirects_to_container");

  if (runResult == 0 && opts.data_size_out >= sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct tcphdr))
  {
    const struct ethhdr *outEth = reinterpret_cast<const struct ethhdr *>(output.data());
    const struct ipv6hdr *outIP = reinterpret_cast<const struct ipv6hdr *>(output.data() + sizeof(struct ethhdr));
    const struct tcphdr *outTCP = reinterpret_cast<const struct tcphdr *>(outIP + 1);
    uint8_t expectedDestination[16] = {};
    std::memcpy(expectedDestination, external6, sizeof(expectedDestination));
    makeContainerIPv6(expectedDestination, localSubnet.dpfx, localSubnet.mpfx[0], localSubnet.mpfx[1], localSubnet.mpfx[2], containerFragment);

    expectNamed(outEth->h_proto == htons(ETH_P_IPV6), "preserves_ethertype");
    expectNamed(std::memcmp(outIP->daddr.s6_addr, expectedDestination, sizeof(outIP->daddr.s6_addr)) == 0, "rewrites_destination");
    expectNamed(outTCP->dest == targetPort, "rewrites_container_port");
    expectNamed(ntohs(outIP->payload_len) == 2052u, "preserves_tcp_segment_size");

    std::vector<uint8_t> expectedSegment(reinterpret_cast<const uint8_t *>(outTCP),
                                         reinterpret_cast<const uint8_t *>(outTCP) + ntohs(outIP->payload_len));
    reinterpret_cast<struct tcphdr *>(expectedSegment.data())->check = 0;
    uint16_t expectedChecksum = htons(checksumIPv6Transport(outIP->saddr.s6_addr,
                                                            outIP->daddr.s6_addr,
                                                            IPPROTO_TCP,
                                                            expectedSegment.data(),
                                                            expectedSegment.size()));
    expectNamed(outTCP->check == expectedChecksum, "recomputes_transport_checksum");
  }

  ingressProgram.close();
}

static void exerciseHostIngressPlainLocalIPv6(TestSuite& suite, uint8_t proto)
{
  const char *label = proto == IPPROTO_TCP
                          ? "switchboard_host_ingress_plain_local_ipv6_tcp"
                          : "switchboard_host_ingress_plain_local_ipv6_udp";
  auto expectNamed = [&](bool condition, const char *suffix) -> void {
    char name[256] = {};
    std::snprintf(name, sizeof(name), "%s_%s", label, suffix);
    suite.expect(condition, name);
  };

  String ingressObjectPath = {};
  ingressObjectPath.assign(PRODIGY_TEST_BINARY_DIR);
  ingressObjectPath.append("/host.ingress.router.ebpf.o"_ctv);

  BPFProgram ingressProgram = {};
  expectNamed(ingressProgram.load(ingressObjectPath, "host_ingress"_ctv), "loads_program");
  if (ingressProgram.prog_fd < 0)
  {
    return;
  }

  local_container_subnet6 localSubnet = {};
  localSubnet.dpfx = 0x01;
  localSubnet.mpfx[0] = 0x52;
  localSubnet.mpfx[1] = 0xdf;
  localSubnet.mpfx[2] = 0x39;
  ingressProgram.setArrayElement("lc_subnet"_ctv, 0, localSubnet);

  constexpr uint8_t containerFragment = 0x4e;
  uint32_t redirectIfidx = 7;
  ingressProgram.setArrayElement("ct_dev_map"_ctv, containerFragment, redirectIfidx);

  uint8_t source6[16] = {0x26, 0x02, 0xfa, 0xc0, 0, 0, 0x12, 0xab, 0xff, 0xff, 0, 0, 0, 0, 0, 0x01};
  uint8_t destination6[16] = {};
  makeContainerIPv6(destination6, localSubnet.dpfx, localSubnet.mpfx[0], localSubnet.mpfx[1], localSubnet.mpfx[2], containerFragment);

  std::vector<uint8_t> frame = makeIPv6L4EthernetFrame(source6, destination6, proto, 49'152, 18'403);
  std::vector<uint8_t> output(frame.size());
  LIBBPF_OPTS(bpf_test_run_opts, opts,
              .data_in = frame.data(),
              .data_out = output.data(),
              .data_size_in = static_cast<__u32>(frame.size()),
              .data_size_out = static_cast<__u32>(output.size()),
              .repeat = 1, );

  int runResult = bpf_prog_test_run_opts(ingressProgram.prog_fd, &opts);
  expectNamed(runResult == 0, "test_run_succeeds");
  expectNamed(opts.retval == TC_ACT_REDIRECT, "redirects_to_container_before_overlay_pull");
  expectNamed(opts.data_size_out == frame.size(), "preserves_packet_size");

  if (runResult == 0 && opts.data_size_out >= sizeof(struct ethhdr) + sizeof(struct ipv6hdr))
  {
    const struct ethhdr *outEth = reinterpret_cast<const struct ethhdr *>(output.data());
    const struct ipv6hdr *outIPv6 = reinterpret_cast<const struct ipv6hdr *>(output.data() + sizeof(struct ethhdr));
    expectNamed(outEth->h_proto == htons(ETH_P_IPV6), "preserves_ethertype");
    expectNamed(std::memcmp(outIPv6->daddr.s6_addr, destination6, sizeof(destination6)) == 0, "preserves_destination");
    expectNamed(outIPv6->nexthdr == proto, "preserves_protocol");
  }

  ingressProgram.close();
}

static void exerciseHostIngressHostedIngressRoute(TestSuite& suite, bool ipv6, uint8_t proto)
{
  const char *label = ipv6
                          ? (proto == IPPROTO_TCP ? "switchboard_host_ingress_hosted_ingress_ipv6_tcp" : "switchboard_host_ingress_hosted_ingress_ipv6_udp")
                          : (proto == IPPROTO_TCP ? "switchboard_host_ingress_hosted_ingress_ipv4_tcp" : "switchboard_host_ingress_hosted_ingress_ipv4_udp");
  auto expectNamed = [&](bool condition, const char *suffix) -> void {
    char name[256] = {};
    std::snprintf(name, sizeof(name), "%s_%s", label, suffix);
    suite.expect(condition, name);
  };

  String ingressObjectPath = {};
  ingressObjectPath.assign(PRODIGY_TEST_BINARY_DIR);
  ingressObjectPath.append("/host.ingress.router.ebpf.o"_ctv);

  BPFProgram ingressProgram = {};
  expectNamed(ingressProgram.load(ingressObjectPath, "host_ingress"_ctv), "loads_program");
  if (ingressProgram.prog_fd < 0)
  {
    return;
  }

  mac localMAC = {};
  localMAC.mac[0] = 0x02;
  localMAC.mac[1] = 0x42;
  localMAC.mac[2] = 0xac;
  localMAC.mac[3] = 0x11;
  localMAC.mac[4] = 0x00;
  localMAC.mac[5] = 0x0a;
  ingressProgram.setArrayElement("mac_map"_ctv, 0, localMAC);

  mac gatewayMAC = {};
  gatewayMAC.mac[0] = 0x02;
  gatewayMAC.mac[1] = 0x42;
  gatewayMAC.mac[2] = 0xac;
  gatewayMAC.mac[3] = 0x11;
  gatewayMAC.mac[4] = 0x00;
  gatewayMAC.mac[5] = 0x01;
  ingressProgram.setArrayElement("gw_mac_map"_ctv, 0, gatewayMAC);

  const uint32_t machineFragment = 0x000002u;
  if (ipv6)
  {
    switchboard_overlay_hosted_ingress_route6 hosted = {};
    hosted.machine_fragment = machineFragment;
    switchboard_overlay_prefix6_key hostedKey = switchboardMakeOverlayPrefix6Key(makePrefix("2001:db8::1/128"));
    expectNamed(updateProgramMapElement(ingressProgram, "ovl_host6"_ctv, hostedKey, hosted),
                "sets_hosted_route");
  }
  else
  {
    switchboard_overlay_hosted_ingress_route4 hosted = {};
    hosted.machine_fragment = machineFragment;
    switchboard_overlay_prefix4_key hostedKey = switchboardMakeOverlayPrefix4Key(makePrefix("198.18.0.1/32"));
    expectNamed(updateProgramMapElement(ingressProgram, "ovl_host4"_ctv, hostedKey, hosted),
                "sets_hosted_route");
  }

  switchboard_overlay_machine_route route = {};
  route.family = SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6;
  route.use_gateway_mac = 1;
  parseIPv6Bytes("fd00:10::a", route.source6);
  parseIPv6Bytes("fd00:10::b", route.next_hop6);
  switchboard_overlay_machine_route_key routeKey = switchboardMakeOverlayMachineRouteKey(machineFragment);
  expectNamed(updateProgramMapElement(ingressProgram, "ovl_mach_full"_ctv, routeKey, route),
              "sets_machine_route");

  struct in_addr source4 = {};
  struct in_addr destination4 = {};
  uint8_t source6[16] = {};
  uint8_t destination6[16] = {};
  std::vector<uint8_t> frame;
  if (ipv6)
  {
    parseIPv6Bytes("2001:db8::77", source6);
    parseIPv6Bytes("2001:db8::1", destination6);
    frame = makeIPv6L4EthernetFrame(source6, destination6, proto, 49'152, 443);
  }
  else
  {
    expectNamed(inet_pton(AF_INET, "198.18.0.77", &source4) == 1, "parses_source");
    expectNamed(inet_pton(AF_INET, "198.18.0.1", &destination4) == 1, "parses_destination");
    frame = makeIPv4L4EthernetFrame(source4, destination4, proto, 49'152, 443);
  }

  std::vector<uint8_t> output(frame.size() + sizeof(struct ipv6hdr) + 64u);
  LIBBPF_OPTS(bpf_test_run_opts, opts,
              .data_in = frame.data(),
              .data_out = output.data(),
              .data_size_in = static_cast<__u32>(frame.size()),
              .data_size_out = static_cast<__u32>(output.size()),
              .repeat = 1, );

  int runResult = bpf_prog_test_run_opts(ingressProgram.prog_fd, &opts);
  expectNamed(runResult == 0, "test_run_succeeds");
  expectNamed(opts.retval == TC_ACT_OK, "returns_ok_after_encap");
  expectNamed(opts.data_size_out == frame.size() + sizeof(struct ipv6hdr), "adds_outer_ipv6_header");

  if (runResult == 0 && opts.data_size_out >= frame.size() + sizeof(struct ipv6hdr))
  {
    const struct ethhdr *outEth = reinterpret_cast<const struct ethhdr *>(output.data());
    const struct ipv6hdr *outer6 = reinterpret_cast<const struct ipv6hdr *>(output.data() + sizeof(struct ethhdr));
    uint8_t expectedOuterSrc[16] = {};
    uint8_t expectedOuterDst[16] = {};
    parseIPv6Bytes("fd00:10::a", expectedOuterSrc);
    parseIPv6Bytes("fd00:10::b", expectedOuterDst);

    expectNamed(outEth->h_proto == htons(ETH_P_IPV6), "sets_outer_ipv6_ethertype");
    expectNamed(outer6->nexthdr == (ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP), "sets_outer_next_header");
    expectNamed(std::memcmp(outer6->saddr.s6_addr, expectedOuterSrc, sizeof(expectedOuterSrc)) == 0, "sets_outer_source");
    expectNamed(std::memcmp(outer6->daddr.s6_addr, expectedOuterDst, sizeof(expectedOuterDst)) == 0, "sets_outer_destination");

    if (ipv6)
    {
      const struct ipv6hdr *inner6 = outer6 + 1;
      expectNamed(std::memcmp(inner6->daddr.s6_addr, destination6, sizeof(destination6)) == 0,
                  "preserves_inner_destination");
      expectNamed(inner6->nexthdr == proto, "preserves_inner_protocol");
    }
    else
    {
      const struct iphdr *inner4 = reinterpret_cast<const struct iphdr *>(outer6 + 1);
      expectNamed(inner4->daddr == destination4.s_addr, "preserves_inner_destination");
      expectNamed(inner4->protocol == proto, "preserves_inner_protocol");
    }
  }

  ingressProgram.close();
}

static void exerciseHostIngressRemotePortalRoute(TestSuite& suite, bool ipv6, uint8_t proto, bool ipv6Underlay)
{
  char label[128] = {};
  std::snprintf(label,
                sizeof(label),
                "switchboard_host_ingress_remote_portal_ipv%u_%s_ipv%u_underlay",
                ipv6 ? 6u : 4u,
                proto == IPPROTO_TCP ? "tcp" : "udp",
                ipv6Underlay ? 6u : 4u);
  auto expectNamed = [&](bool condition, const char *suffix) -> void {
    char name[256] = {};
    std::snprintf(name, sizeof(name), "%s_%s", label, suffix);
    suite.expect(condition, name);
  };

  String ingressObjectPath = {};
  ingressObjectPath.assign(PRODIGY_TEST_BINARY_DIR);
  ingressObjectPath.append("/host.ingress.router.dev.ebpf.o"_ctv);

  BPFProgram ingressProgram = {};
  expectNamed(ingressProgram.load(ingressObjectPath, "host_ingress"_ctv), "loads_program");
  if (ingressProgram.prog_fd < 0)
  {
    return;
  }

  local_container_subnet6 localSubnet = {};
  localSubnet.dpfx = 0x01;
  localSubnet.mpfx[0] = 0x52;
  localSubnet.mpfx[1] = 0xdf;
  localSubnet.mpfx[2] = 0x39;
  ingressProgram.setArrayElement("lc_subnet"_ctv, 0, localSubnet);

  constexpr uint32_t remoteMachineFragment = 0x0016255bu;
  uint8_t remoteContainerID[5] = {0x01, 0x16, 0x25, 0x5b, 0x4e};
  portal_meta meta = {};
  meta.slot = ipv6 ? (proto == IPPROTO_TCP ? 23u : 22u) : (proto == IPPROTO_TCP ? 21u : 20u);
  expectNamed(installSingleContainerPortalRing(ingressProgram, meta.slot, remoteContainerID),
              "installs_remote_target_ring");

  const uint16_t externalPortHost = proto == IPPROTO_TCP ? 443 : 4443;
  portal_definition portal = {};
  portal.port = htons(externalPortHost);
  portal.proto = proto;

  struct in_addr external4 = {};
  struct in_addr client4 = {};
  uint8_t external6[16] = {};
  uint8_t client6[16] = {};
  if (ipv6)
  {
    expectNamed(inet_pton(AF_INET6, "2001:db8:100::44", external6) == 1, "parses_external");
    expectNamed(inet_pton(AF_INET6, "2001:db8:200::99", client6) == 1, "parses_client");
    std::memcpy(portal.addr6, external6, sizeof(portal.addr6));

    switchboard_overlay_hosted_ingress_route6 hosted = {};
    hosted.machine_fragment = remoteMachineFragment;
    switchboard_overlay_prefix6_key hostedKey = switchboardMakeOverlayPrefix6Key(makePrefix("2001:db8:100::44/128"));
    expectNamed(updateProgramMapElement(ingressProgram, "ovl_host6"_ctv, hostedKey, hosted),
                "sets_hosted_route");
  }
  else
  {
    expectNamed(inet_pton(AF_INET, "198.18.0.1", &external4) == 1, "parses_external");
    expectNamed(inet_pton(AF_INET, "203.0.113.99", &client4) == 1, "parses_client");
    portal.addr4 = external4.s_addr;

    switchboard_overlay_hosted_ingress_route4 hosted = {};
    hosted.machine_fragment = remoteMachineFragment;
    switchboard_overlay_prefix4_key hostedKey = switchboardMakeOverlayPrefix4Key(makePrefix("198.18.0.1/32"));
    expectNamed(updateProgramMapElement(ingressProgram, "ovl_host4"_ctv, hostedKey, hosted),
                "sets_hosted_route");
  }

  expectNamed(updateProgramMapElement(ingressProgram, "ext_portals"_ctv, portal, meta),
              "installs_portal");
  switchboard_wormhole_target_key targetKey = {};
  targetKey.slot = meta.slot;
  std::memcpy(targetKey.container, remoteContainerID, sizeof(targetKey.container));
  __be16 targetPort = htons(proto == IPPROTO_TCP ? 18'443 : 18'444);
  expectNamed(updateProgramMapElement(ingressProgram, "wh_targets"_ctv, targetKey, targetPort),
              "installs_selected_target_binding");

  switchboard_overlay_machine_route route = {};
  route.family = ipv6Underlay ? SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6 : SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV4;
  route.use_gateway_mac = 1;
  if (ipv6Underlay)
  {
    parseIPv6Bytes("fd00:10::a", route.source6);
    parseIPv6Bytes("fd00:10::b", route.next_hop6);
  }
  else
  {
    route.source4 = parseIPv4Address("192.0.2.10").s_addr;
    route.next_hop4 = parseIPv4Address("192.0.2.11").s_addr;
  }
  switchboard_overlay_machine_route_key routeKey = switchboardMakeOverlayMachineRouteKey(remoteMachineFragment);
  expectNamed(updateProgramMapElement(ingressProgram, "ovl_mach_full"_ctv, routeKey, route),
              "sets_machine_route");

  std::vector<uint8_t> frame = ipv6
                                   ? makeIPv6L4EthernetFrame(client6, external6, proto, 49'152, externalPortHost)
                                   : makeIPv4L4EthernetFrame(client4, external4, proto, 49'152, externalPortHost);
  size_t outerBytes = ipv6Underlay ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
  std::vector<uint8_t> output(frame.size() + outerBytes + sizeof(struct switchboard_wormhole_overlay_header) + 64u);
  LIBBPF_OPTS(bpf_test_run_opts, opts,
              .data_in = frame.data(),
              .data_out = output.data(),
              .data_size_in = static_cast<__u32>(frame.size()),
              .data_size_out = static_cast<__u32>(output.size()),
              .repeat = 1, );

  int runResult = bpf_prog_test_run_opts(ingressProgram.prog_fd, &opts);
  expectNamed(runResult == 0, "test_run_succeeds");
  expectNamed(opts.retval == TC_ACT_OK, "returns_ok_after_overlay_encap");
  expectNamed(opts.data_size_out == frame.size() + outerBytes + sizeof(struct switchboard_wormhole_overlay_header), "adds_exact_underlay_and_provenance_headers");

  if (runResult == 0 && opts.data_size_out >= frame.size() + outerBytes + sizeof(struct switchboard_wormhole_overlay_header))
  {
    const struct ethhdr *outEth = reinterpret_cast<const struct ethhdr *>(output.data());
    const struct switchboard_wormhole_overlay_header *provenance = nullptr;
    if (ipv6Underlay)
    {
      const struct ipv6hdr *outer6 = reinterpret_cast<const struct ipv6hdr *>(outEth + 1);
      uint8_t expectedOuterSrc[16] = {};
      uint8_t expectedOuterDst[16] = {};
      parseIPv6Bytes("fd00:10::a", expectedOuterSrc);
      parseIPv6Bytes("fd00:10::b", expectedOuterDst);
      expectNamed(outEth->h_proto == htons(ETH_P_IPV6), "sets_outer_ipv6_ethertype");
      expectNamed(outer6->nexthdr == IPPROTO_GRE, "sets_keyed_gre_outer_protocol");
      expectNamed(std::memcmp(outer6->saddr.s6_addr, expectedOuterSrc, sizeof(expectedOuterSrc)) == 0,
                  "sets_outer_source");
      expectNamed(std::memcmp(outer6->daddr.s6_addr, expectedOuterDst, sizeof(expectedOuterDst)) == 0,
                  "sets_outer_destination");
      provenance = reinterpret_cast<const struct switchboard_wormhole_overlay_header *>(outer6 + 1);
    }
    else
    {
      const struct iphdr *outer4 = reinterpret_cast<const struct iphdr *>(outEth + 1);
      expectNamed(outEth->h_proto == htons(ETH_P_IP), "sets_outer_ipv4_ethertype");
      expectNamed(outer4->protocol == IPPROTO_GRE, "sets_keyed_gre_outer_protocol");
      expectNamed(outer4->saddr == route.source4, "sets_outer_source");
      expectNamed(outer4->daddr == route.next_hop4, "sets_outer_destination");
      provenance = reinterpret_cast<const struct switchboard_wormhole_overlay_header *>(outer4 + 1);
    }
    expectNamed(switchboardWormholeOverlayHeaderValid(provenance), "writes_valid_provenance_header");
    expectNamed(provenance->reserved == 0, "omits_host_local_portal_slot");
    expectNamed(std::memcmp(provenance->container, remoteContainerID, sizeof(remoteContainerID)) == 0,
                "preserves_selected_container");

    if (ipv6)
    {
      const struct ipv6hdr *inner6 = reinterpret_cast<const struct ipv6hdr *>(provenance + 1);
      expectNamed(std::memcmp(inner6->daddr.s6_addr, external6, sizeof(external6)) == 0,
                  "preserves_inner_destination");
      expectNamed(inner6->nexthdr == proto, "preserves_inner_protocol");
    }
    else
    {
      const struct iphdr *inner4 = reinterpret_cast<const struct iphdr *>(provenance + 1);
      expectNamed(inner4->daddr == external4.s_addr, "preserves_inner_destination");
      expectNamed(inner4->protocol == proto, "preserves_inner_protocol");
    }
  }

  auto runRemoteBoundary = [&](size_t l3Bytes, uint32_t expectedAction, const char *suffix) -> void {
    const size_t ipBytes = ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
    const size_t transportBytes = proto == IPPROTO_TCP ? sizeof(struct tcphdr) : sizeof(struct udphdr);
    const size_t payloadBytes = l3Bytes - ipBytes - transportBytes;
    std::vector<uint8_t> boundaryFrame = ipv6
                                             ? makeIPv6L4EthernetFrame(client6, external6, proto, 49'153, externalPortHost, payloadBytes)
                                             : makeIPv4L4EthernetFrame(client4, external4, proto, 49'153, externalPortHost, payloadBytes);
    std::vector<uint8_t> boundaryOutput(boundaryFrame.size() + outerBytes + sizeof(struct switchboard_wormhole_overlay_header) + 64u);
    LIBBPF_OPTS(bpf_test_run_opts, boundaryOpts,
                .data_in = boundaryFrame.data(),
                .data_out = boundaryOutput.data(),
                .data_size_in = static_cast<__u32>(boundaryFrame.size()),
                .data_size_out = static_cast<__u32>(boundaryOutput.size()),
                .repeat = 1, );
    int boundaryResult = bpf_prog_test_run_opts(ingressProgram.prog_fd, &boundaryOpts);
    char resultName[256] = {};
    std::snprintf(resultName, sizeof(resultName), "%s_test_run_succeeds", suffix);
    expectNamed(boundaryResult == 0, resultName);
    char actionName[256] = {};
    std::snprintf(actionName, sizeof(actionName), "%s_action_matches", suffix);
    expectNamed(boundaryOpts.retval == expectedAction, actionName);
  };
  runRemoteBoundary(WORMHOLE_PUBLIC_INGRESS_L3_MTU,
                    TC_ACT_OK,
                    "accepts_exact_1500_byte_host_remote_encap_boundary");
  runRemoteBoundary(WORMHOLE_PUBLIC_INGRESS_L3_MTU + 1u,
                    TC_ACT_SHOT,
                    "rejects_host_remote_encap_above_supported_boundary");

  String targetObjectPath = {};
  targetObjectPath.assign(PRODIGY_TEST_BINARY_DIR);
  targetObjectPath.append("/host.ingress.router.dev.ebpf.o"_ctv);
  BPFProgram targetProgram = {};
  expectNamed(targetProgram.load(targetObjectPath, "host_ingress"_ctv), "target_loads_program");
  if (runResult == 0 && targetProgram.prog_fd >= 0)
  {
    local_container_subnet6 targetSubnet = {};
    targetSubnet.dpfx = remoteContainerID[0];
    std::memcpy(targetSubnet.mpfx, remoteContainerID + 1, sizeof(targetSubnet.mpfx));
    targetProgram.setArrayElement("lc_subnet"_ctv, 0, targetSubnet);
    uint32_t targetIfidx = 97;
    targetProgram.setArrayElement("ct_dev_map"_ctv, remoteContainerID[4], targetIfidx);
    expectNamed(ipv6Underlay
                    ? installOverlayIngressPeerIPv6(targetProgram, route.source6, route.next_hop6)
                    : installOverlayIngressPeerIPv4(targetProgram, route.source4, route.next_hop4),
                "target_authorizes_exact_overlay_peer");
    expectNamed(updateProgramMapElement(targetProgram, "ext_portals"_ctv, portal, meta), "target_installs_portal");
    expectNamed(updateProgramMapElement(targetProgram, "wh_targets"_ctv, targetKey, targetPort), "target_installs_selected_binding");
    expectNamed(installWormholeExposure(targetProgram, portal, ipv6, remoteContainerID, targetPort, meta.slot + 1u),
                "target_installs_exposure");

    std::vector<uint8_t> targetOutput(output.size());
    LIBBPF_OPTS(bpf_test_run_opts, targetOpts,
                .data_in = output.data(),
                .data_out = targetOutput.data(),
                .data_size_in = opts.data_size_out,
                .data_size_out = static_cast<__u32>(targetOutput.size()),
                .repeat = 1, );
    int targetRunResult = bpf_prog_test_run_opts(targetProgram.prog_fd, &targetOpts);
    expectNamed(targetRunResult == 0, "target_test_run_succeeds");
    expectNamed(targetOpts.retval == TC_ACT_REDIRECT, "target_redirects_exact_selected_container_without_ring");
    expectNamed(targetOpts.data_size_out == frame.size(), "target_strips_underlay_and_provenance");
    if (targetRunResult == 0 && targetOpts.data_size_out >= sizeof(struct ethhdr) + (ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr)))
    {
      const struct ethhdr *targetEth = reinterpret_cast<const struct ethhdr *>(targetOutput.data());
      if (ipv6)
      {
        uint8_t canonical[16] = {};
        makeContainerIPv6(canonical,
                          remoteContainerID[0],
                          remoteContainerID[1],
                          remoteContainerID[2],
                          remoteContainerID[3],
                          remoteContainerID[4]);
        const struct ipv6hdr *target6 = reinterpret_cast<const struct ipv6hdr *>(targetEth + 1);
        const __be16 deliveredPort = proto == IPPROTO_TCP
                                         ? reinterpret_cast<const struct tcphdr *>(target6 + 1)->dest
                                         : reinterpret_cast<const struct udphdr *>(target6 + 1)->dest;
        expectNamed(targetEth->h_proto == htons(ETH_P_IPV6), "target_restores_ipv6_ethertype");
        expectNamed(std::memcmp(target6->daddr.s6_addr, canonical, sizeof(canonical)) == 0, "target_delivers_canonical_private6_destination");
        expectNamed(deliveredPort == targetPort, "target_delivers_selected_container_port");
      }
      else
      {
        const struct iphdr *target4 = reinterpret_cast<const struct iphdr *>(targetEth + 1);
        const __be16 deliveredPort = proto == IPPROTO_TCP
                                         ? reinterpret_cast<const struct tcphdr *>(target4 + 1)->dest
                                         : reinterpret_cast<const struct udphdr *>(target4 + 1)->dest;
        expectNamed(targetEth->h_proto == htons(ETH_P_IP), "target_restores_ipv4_ethertype");
        expectNamed(target4->daddr == external4.s_addr, "target_preserves_ipv4_external_destination");
        expectNamed(deliveredPort == targetPort, "target_delivers_selected_container_port");
      }
    }
  }
  targetProgram.close();

  ingressProgram.close();
}

static void exerciseBalancerRemotePortalRoutesWithOverlay(TestSuite& suite)
{
  const char *label = "switchboard_balancer_remote_ipv4_tcp_portal_overlay";
  auto expectNamed = [&](bool condition, const char *suffix) -> void {
    char name[256] = {};
    std::snprintf(name, sizeof(name), "%s_%s", label, suffix);
    suite.expect(condition, name);
  };

  String balancerObjectPath = {};
  balancerObjectPath.assign(PRODIGY_TEST_BINARY_DIR);
  balancerObjectPath.append("/balancer.ebpf.o"_ctv);

  BPFProgram balancerProgram = {};
  expectNamed(balancerProgram.load(balancerObjectPath, "bal_ingress"_ctv), "loads_program");
  if (balancerProgram.prog_fd < 0)
  {
    return;
  }

  local_container_subnet6 localSubnet = {};
  localSubnet.dpfx = 0x01;
  localSubnet.mpfx[0] = 0x52;
  localSubnet.mpfx[1] = 0xdf;
  localSubnet.mpfx[2] = 0x39;
  balancerProgram.setArrayElement("lc_subnet"_ctv, 0, localSubnet);

  mac localMAC = {};
  localMAC.mac[0] = 0x02;
  localMAC.mac[1] = 0x42;
  localMAC.mac[2] = 0xac;
  localMAC.mac[3] = 0x11;
  localMAC.mac[4] = 0x00;
  localMAC.mac[5] = 0x0a;
  balancerProgram.setArrayElement("mac_map"_ctv, 0, localMAC);

  mac gatewayMAC = {};
  gatewayMAC.mac[0] = 0x02;
  gatewayMAC.mac[1] = 0x42;
  gatewayMAC.mac[2] = 0xac;
  gatewayMAC.mac[3] = 0x11;
  gatewayMAC.mac[4] = 0x00;
  gatewayMAC.mac[5] = 0x01;
  balancerProgram.setArrayElement("gw_mac_map"_ctv, 0, gatewayMAC);

  struct in_addr external4 = {};
  struct in_addr client4 = {};
  expectNamed(inet_pton(AF_INET, "198.18.0.1", &external4) == 1, "parses_external");
  expectNamed(inet_pton(AF_INET, "203.0.113.99", &client4) == 1, "parses_client");

  switchboard_owned_routable_prefix4_key ownedKey = {};
  ownedKey.prefixlen = 32;
  ownedKey.addr = external4.s_addr;
  __u8 present = 1;
  expectNamed(updateProgramMapElement(balancerProgram, "owned_pfx4"_ctv, ownedKey, present),
              "sets_owned_external_prefix");

  portal_definition portal = {};
  portal.addr4 = external4.s_addr;
  portal.port = htons(443);
  portal.proto = IPPROTO_TCP;

  portal_meta meta = {};
  meta.slot = 31;
  expectNamed(updateProgramMapElement(balancerProgram, "ext_portals"_ctv, portal, meta),
              "installs_external_portal");

  uint8_t remoteContainerID[5] = {0x01, 0x16, 0x25, 0x5b, 0x4e};
  expectNamed(installSingleContainerPortalRing(balancerProgram, meta.slot, remoteContainerID),
              "installs_remote_target_ring");
  switchboard_wormhole_target_key targetKey = {};
  targetKey.slot = meta.slot;
  std::memcpy(targetKey.container, remoteContainerID, sizeof(targetKey.container));
  __be16 targetPort = htons(8443);
  expectNamed(updateProgramMapElement(balancerProgram, "wh_targets"_ctv, targetKey, targetPort),
              "installs_selected_target_binding");

  switchboard_overlay_machine_route route = {};
  route.family = SWITCHBOARD_OVERLAY_ROUTE_FAMILY_IPV6;
  route.use_gateway_mac = 1;
  parseIPv6Bytes("fd00:10::a", route.source6);
  parseIPv6Bytes("fd00:10::b", route.next_hop6);
  switchboard_overlay_machine_route_key routeKey = switchboardMakeOverlayMachineRouteKey(0x0016255bu);
  expectNamed(updateProgramMapElement(balancerProgram, "ovl_mach_full"_ctv, routeKey, route),
              "sets_machine_route");

  std::vector<uint8_t> frame = makeIPv4L4EthernetFrame(client4, external4, IPPROTO_TCP, 49'152, 443);
  std::vector<uint8_t> output(frame.size() + sizeof(struct ipv6hdr) + sizeof(struct switchboard_wormhole_overlay_header) + 64u);
  LIBBPF_OPTS(bpf_test_run_opts, opts,
              .data_in = frame.data(),
              .data_out = output.data(),
              .data_size_in = static_cast<__u32>(frame.size()),
              .data_size_out = static_cast<__u32>(output.size()),
              .repeat = 1, );

  int runResult = bpf_prog_test_run_opts(balancerProgram.prog_fd, &opts);
  expectNamed(runResult == 0, "test_run_succeeds");
  expectNamed(opts.retval == XDP_TX, "routes_remote_portal_to_overlay");
  expectNamed(opts.data_size_out == frame.size() + sizeof(struct ipv6hdr) + sizeof(struct switchboard_wormhole_overlay_header), "adds_outer_ipv6_and_provenance_headers");

  if (runResult == 0 && opts.data_size_out >= frame.size() + sizeof(struct ipv6hdr) + sizeof(struct switchboard_wormhole_overlay_header))
  {
    const struct ethhdr *outEth = reinterpret_cast<const struct ethhdr *>(output.data());
    const struct ipv6hdr *outer6 = reinterpret_cast<const struct ipv6hdr *>(output.data() + sizeof(struct ethhdr));
    const struct switchboard_wormhole_overlay_header *provenance = reinterpret_cast<const struct switchboard_wormhole_overlay_header *>(outer6 + 1);
    const struct iphdr *inner4 = reinterpret_cast<const struct iphdr *>(provenance + 1);
    uint8_t expectedOuterSrc[16] = {};
    uint8_t expectedOuterDst[16] = {};
    parseIPv6Bytes("fd00:10::a", expectedOuterSrc);
    parseIPv6Bytes("fd00:10::b", expectedOuterDst);

    expectNamed(outEth->h_proto == htons(ETH_P_IPV6), "sets_outer_ipv6_ethertype");
    expectNamed(outer6->nexthdr == IPPROTO_GRE, "sets_keyed_gre_outer_protocol");
    expectNamed(std::memcmp(outer6->saddr.s6_addr, expectedOuterSrc, sizeof(expectedOuterSrc)) == 0,
                "sets_outer_source");
    expectNamed(std::memcmp(outer6->daddr.s6_addr, expectedOuterDst, sizeof(expectedOuterDst)) == 0,
                "sets_outer_destination");
    expectNamed(switchboardWormholeOverlayHeaderValid(provenance), "writes_valid_provenance_header");
    expectNamed(provenance->protocol == htons(ETH_P_IP), "preserves_ipv4_inner_protocol_identity");
    expectNamed(provenance->reserved == 0, "omits_host_local_portal_slot");
    expectNamed(std::memcmp(provenance->container, remoteContainerID, sizeof(remoteContainerID)) == 0,
                "preserves_selected_container");
    expectNamed(inner4->daddr == external4.s_addr, "preserves_external_destination");
    expectNamed(inner4->protocol == IPPROTO_TCP, "preserves_protocol");
  }

  auto runBoundary = [&](size_t l3Bytes, uint32_t expectedAction, const char *suffix) -> void {
    size_t payloadBytes = l3Bytes - sizeof(struct iphdr) - sizeof(struct tcphdr);
    std::vector<uint8_t> boundaryFrame = makeIPv4L4EthernetFrame(client4, external4, IPPROTO_TCP, 49'153, 443, payloadBytes);
    std::vector<uint8_t> boundaryOutput(boundaryFrame.size() + switchboardPacketBudgetExternalIngressRemoteDeliveryAddedBytes() + 64u);
    LIBBPF_OPTS(bpf_test_run_opts, boundaryOpts,
                .data_in = boundaryFrame.data(),
                .data_out = boundaryOutput.data(),
                .data_size_in = static_cast<__u32>(boundaryFrame.size()),
                .data_size_out = static_cast<__u32>(boundaryOutput.size()),
                .repeat = 1, );
    int boundaryResult = bpf_prog_test_run_opts(balancerProgram.prog_fd, &boundaryOpts);
    char resultName[256] = {};
    std::snprintf(resultName, sizeof(resultName), "%s_test_run_succeeds", suffix);
    expectNamed(boundaryResult == 0, resultName);
    char actionName[256] = {};
    std::snprintf(actionName, sizeof(actionName), "%s_action_matches", suffix);
    expectNamed(boundaryOpts.retval == expectedAction, actionName);
  };
  runBoundary(WORMHOLE_PUBLIC_INGRESS_L3_MTU, XDP_TX, "accepts_exact_1500_byte_public_l3_boundary");
  runBoundary(WORMHOLE_PUBLIC_INGRESS_L3_MTU + 1u, XDP_DROP, "rejects_public_l3_above_supported_boundary");

  balancerProgram.close();
}

static void exerciseWormholeSharedFlowOwnership(TestSuite& suite)
{
  const char *label = "switchboard_wormhole_shared_flow_ownership";
  auto expectNamed = [&](bool condition, const char *suffix) -> void {
    char name[256] = {};
    std::snprintf(name, sizeof(name), "%s_%s", label, suffix);
    suite.expect(condition, name);
  };

  String hostPath = {};
  hostPath.assign(PRODIGY_TEST_BINARY_DIR);
  hostPath.append("/host.ingress.router.ebpf.o"_ctv);
  String ingressPath = {};
  ingressPath.assign(PRODIGY_TEST_BINARY_DIR);
  ingressPath.append("/container.ingress.router.ebpf.o"_ctv);
  String egressPath = {};
  egressPath.assign(PRODIGY_TEST_BINARY_DIR);
  egressPath.append("/container.egress.router.ebpf.o"_ctv);

  BPFProgram host = {};
  expectNamed(host.load(hostPath, "host_ingress"_ctv), "loads_host_ingress");
  if (host.prog_fd < 0)
  {
    return;
  }

  uint32_t testIfindex = uint32_t(::getpid()) ^ 0x57484f4cu;
  String establishedPinPath = {};
  String pendingPinPath = {};
  switchboardWormholeFlowPinPath(establishedPinPath, testIfindex);
  switchboardWormholePendingFlowPinPath(pendingPinPath, testIfindex);
  (void)unlink(establishedPinPath.c_str());
  (void)unlink(pendingPinPath.c_str());
  expectNamed(switchboardPinWormholeFlowMaps(&host, testIfindex), "pins_host_flow_maps");

  bool ingressReused = false;
  BPFProgram ingress = {};
  bool ingressLoaded = ingress.load(ingressPath,
                                    "ct_ingress"_ctv,
                                    [&](struct bpf_object *obj, Vector<int>& innerMapFDs) -> void {
                                      ingressReused = switchboardReusePinnedWormholeFlowMaps(obj, testIfindex, innerMapFDs);
                                    });
  expectNamed(ingressLoaded && ingressReused, "loads_container_ingress_with_shared_flow_map");

  bool egressReused = false;
  BPFProgram egress = {};
  bool egressLoaded = egress.load(egressPath,
                                  "ct_egress"_ctv,
                                  [&](struct bpf_object *obj, Vector<int>& innerMapFDs) -> void {
                                    egressReused = switchboardReusePinnedWormholeFlowMaps(obj, testIfindex, innerMapFDs);
                                  });
  expectNamed(egressLoaded && egressReused, "loads_container_egress_with_shared_flow_map");
  if (ingress.prog_fd < 0 || egress.prog_fd < 0)
  {
    (void)unlink(establishedPinPath.c_str());
    (void)unlink(pendingPinPath.c_str());
    host.close();
    ingress.close();
    egress.close();
    return;
  }

  uint32_t hostMapID = programMapID(host, "wh_flows"_ctv);
  uint32_t hostPendingMapID = programMapID(host, "wh_pending"_ctv);
  expectNamed(hostMapID != 0 && programMapID(ingress, "wh_flows"_ctv) == hostMapID && programMapID(egress, "wh_flows"_ctv) == hostMapID &&
                  hostPendingMapID != 0 && programMapID(ingress, "wh_pending"_ctv) == hostPendingMapID && programMapID(egress, "wh_pending"_ctv) == hostPendingMapID,
              "shares_pending_and_established_maps_across_all_three_programs");
  bool establishedMapContract = false;
  bool pendingMapContract = false;
  host.openMap("wh_flows"_ctv, [&](int mapFD) -> void {
    establishedMapContract = switchboardWormholeEstablishedFlowMapCompatibleFD(mapFD);
  });
  host.openMap("wh_pending"_ctv, [&](int mapFD) -> void {
    pendingMapContract = switchboardWormholePendingFlowMapCompatibleFD(mapFD);
  });
  expectNamed(establishedMapContract && pendingMapContract,
              "uses_bounded_lru_pending_and_non_evicting_established_map_contracts");

  const uint8_t selected[5] = {0x01, 0x16, 0x25, 0x5b, 0x4e};
  local_container_subnet6 subnet = {};
  subnet.dpfx = selected[0];
  std::memcpy(subnet.mpfx, selected + 1, sizeof(subnet.mpfx));
  host.setArrayElement("lc_subnet"_ctv, 0, subnet);
  ingress.setArrayElement("lc_subnet"_ctv, 0, subnet);
  egress.setArrayElement("lc_subnet"_ctv, 0, subnet);
  uint32_t containerIfindex = 97;
  host.setArrayElement("ct_dev_map"_ctv, selected[4], containerIfindex);

  container_network_policy policy = {};
  policy.mode = CONTAINER_NETWORK_UNRESTRICTED;
  policy.containerFragment = selected[4];
  policy.interContainerMTU = 9000;
  policy.requiresPublic4 = 1;
  ingress.setArrayElement("ct_net_policy"_ctv, 0, policy);
  egress.setArrayElement("ct_net_policy"_ctv, 0, policy);
  uint32_t nicIfindex = 77;
  egress.setArrayElement("ct_dev_map"_ctv, 0, nicIfindex);
  mac sourceMAC = {{0x02, 0x42, 0xac, 0x11, 0x00, 0x0a}};
  mac gatewayMAC = {{0x02, 0x42, 0xac, 0x11, 0x00, 0x01}};
  egress.setArrayElement("mac_map"_ctv, 0, sourceMAC);
  egress.setArrayElement("gw_mac_map"_ctv, 0, gatewayMAC);

  uint8_t client[16] = {};
  uint8_t external[16] = {};
  uint8_t external2[16] = {};
  uint8_t peer[16] = {};
  uint8_t server[16] = {};
  parseIPv6Bytes("2001:db8:200::99", client);
  parseIPv6Bytes("2001:db8:100::44", external);
  parseIPv6Bytes("2001:db8:100::45", external2);
  makeContainerIPv6(peer, selected[0], selected[1], selected[2], selected[3], uint8_t(selected[4] + 1));
  makeContainerIPv6(server, selected[0], selected[1], selected[2], selected[3], selected[4]);

  auto installPortal = [&](const uint8_t address[16], uint16_t externalPort, uint16_t targetPort, uint32_t slot, uint8_t protocol = IPPROTO_UDP) -> switchboard_wormhole_egress_binding {
    portal_definition portal = {};
    std::memcpy(portal.addr6, address, sizeof(portal.addr6));
    portal.port = htons(externalPort);
    portal.proto = protocol;
    portal_meta meta = {};
    meta.slot = slot;
    expectNamed(updateProgramMapElement(host, "ext_portals"_ctv, portal, meta), "installs_portal");
    switchboard_wormhole_target_key target = {};
    target.slot = slot;
    std::memcpy(target.container, selected, sizeof(target.container));
    __be16 translatedPort = htons(targetPort);
    expectNamed(updateProgramMapElement(host, "wh_targets"_ctv, target, translatedPort), "installs_exact_portal_target");

    switchboard_wormhole_egress_key exposure = {};
    std::memcpy(exposure.container, selected, sizeof(exposure.container));
    exposure.port = translatedPort;
    exposure.proto = protocol;
    switchboard_wormhole_egress_binding binding = {};
    std::memcpy(binding.addr6, address, sizeof(binding.addr6));
    binding.port = portal.port;
    binding.proto = portal.proto;
    binding.is_ipv6 = 1;
    binding.owner_generation = slot + 1u;
    expectNamed(updateProgramMapElement(host, "wh_egress"_ctv, exposure, binding), "installs_host_exposure");
    expectNamed(updateProgramMapElement(ingress, "wh_egress"_ctv, exposure, binding), "installs_ingress_exposure");
    expectNamed(updateProgramMapElement(egress, "wh_egress"_ctv, exposure, binding), "installs_egress_exposure");
    return binding;
  };

  switchboard_wormhole_egress_binding binding = installPortal(external, 443, 8443, 41);
  switchboard_wormhole_egress_binding binding2 = installPortal(external2, 4443, 9443, 42);
  std::vector<uint8_t> publicInner = makeIPv6L4EthernetFrame(client, external, IPPROTO_UDP, 49'152, 443);
  std::vector<uint8_t> publicOverlay = makeWormholeIPv6OverlayFrame(publicInner, selected);
  std::vector<uint8_t> privateIngress = makeIPv6L4EthernetFrame(client, server, IPPROTO_UDP, 49'152, 8443);
  std::vector<uint8_t> reply = makeIPv6L4EthernetFrame(server, client, IPPROTO_UDP, 8443, 49'152);

  auto makeReplyKey = [&](uint16_t sourcePort) -> flow_key {
    flow_key key = {};
    std::memcpy(key.srcv6, server, sizeof(key.srcv6));
    std::memcpy(key.dstv6, client, sizeof(key.dstv6));
    key.port16[0] = htons(sourcePort);
    key.port16[1] = htons(49'152);
    key.proto = IPPROTO_UDP;
    return key;
  };
  flow_key replyKey = makeReplyKey(8443);
  flow_key replyKey2 = makeReplyKey(9443);

  auto runHost = [&](const std::vector<uint8_t>& frame, std::vector<uint8_t>& output) -> uint32_t {
    output.resize(frame.size());
    LIBBPF_OPTS(bpf_test_run_opts, opts,
                .data_in = frame.data(),
                .data_out = output.data(),
                .data_size_in = static_cast<__u32>(frame.size()),
                .data_size_out = static_cast<__u32>(output.size()),
                .repeat = 1, );
    if (bpf_prog_test_run_opts(host.prog_fd, &opts) != 0)
    {
      return UINT32_MAX;
    }
    output.resize(opts.data_size_out);
    return opts.retval;
  };
  auto runNetkit = [&](BPFProgram& program, const std::vector<uint8_t>& frame, uint32_t mark, std::vector<uint8_t>& output) -> uint32_t {
    output.resize(frame.size() + 64u);
    struct __sk_buff context = {};
    context.mark = mark;
    LIBBPF_OPTS(bpf_test_run_opts, opts,
                .data_in = frame.data(),
                .data_out = output.data(),
                .data_size_in = static_cast<__u32>(frame.size()),
                .data_size_out = static_cast<__u32>(output.size()),
                .ctx_in = &context,
                .ctx_size_in = sizeof(context),
                .repeat = 1, );
    if (bpf_prog_test_run_opts(program.prog_fd, &opts) != 0)
    {
      return UINT32_MAX;
    }
    output.resize(opts.data_size_out);
    return opts.retval;
  };
  auto clearWormholeFlows = [&]() -> void {
    clearProgramMap<switchboard_wormhole_flow_key>(host, "wh_pending"_ctv);
    clearProgramMap<switchboard_wormhole_flow_key>(host, "wh_flows"_ctv);
  };
  switchboard_wormhole_flow_key ownerKey = switchboardWormholeFlowMapKey(&replyKey, binding.owner_generation);
  switchboard_wormhole_flow_key ownerKey2 = switchboardWormholeFlowMapKey(&replyKey2, binding2.owner_generation);

  std::vector<uint8_t> hostOutput = {};
  std::vector<uint8_t> packetOutput = {};
  clearWormholeFlows();
  expectNamed(runHost(publicOverlay, hostOutput) == TC_ACT_SHOT,
              "rejects_forged_provenance_from_unauthorized_overlay_peer");
  switchboard_wormhole_flow unauthorized = {};
  expectNamed(lookupProgramMapElement(host, "wh_pending"_ctv, ownerKey, unauthorized) == false,
              "unauthorized_provenance_cannot_claim_reverse_tuple");
  uint8_t overlaySource[16] = {};
  uint8_t overlayDestination[16] = {};
  parseIPv6Bytes("fd00:10::a", overlaySource);
  parseIPv6Bytes("fd00:10::b", overlayDestination);
  expectNamed(installOverlayIngressPeerIPv6(host, overlaySource, overlayDestination),
              "authorizes_exact_overlay_peer_pair");
  expectNamed(runHost(publicOverlay, hostOutput) == TC_ACT_REDIRECT, "public_first_is_admitted");
  switchboard_wormhole_flow firstPublic = {};
  expectNamed(lookupProgramMapElement(host, "wh_pending"_ctv, ownerKey, firstPublic) &&
                  firstPublic.disposition == SWITCHBOARD_WORMHOLE_FLOW_PUBLIC &&
                  firstPublic.phase == SWITCHBOARD_WORMHOLE_FLOW_PENDING,
              "public_first_claims_pending_reverse_tuple");
  expectNamed(runNetkit(ingress, hostOutput, SWITCHBOARD_WORMHOLE_SKB_MARK, packetOutput) == NETKIT_PASS,
              "same_public_binding_refreshes_through_container_ingress");
  switchboard_wormhole_flow refreshed = {};
  expectNamed(lookupProgramMapElement(host, "wh_pending"_ctv, ownerKey, refreshed) &&
                  refreshed.phase == SWITCHBOARD_WORMHOLE_FLOW_PENDING &&
                  refreshed.expiresAtNs == firstPublic.expiresAtNs,
              "inbound_only_traffic_cannot_extend_pending_owner");

  std::vector<uint8_t> alreadyPublicReply = makeIPv6L4EthernetFrame(external, client, IPPROTO_UDP, 8443, 49'152);
  expectNamed(runNetkit(egress, alreadyPublicReply, 0, packetOutput) == NETKIT_PASS,
              "public_address_reply_resolves_canonical_flow_owner");
  if (packetOutput.size() >= sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr))
  {
    const struct ipv6hdr *rewritten6 = reinterpret_cast<const struct ipv6hdr *>(packetOutput.data() + sizeof(struct ethhdr));
    const struct udphdr *rewrittenUDP = reinterpret_cast<const struct udphdr *>(rewritten6 + 1);
    expectNamed(std::memcmp(rewritten6->saddr.s6_addr, external, sizeof(external)) == 0 && rewrittenUDP->source == htons(443),
                "public_address_reply_restores_advertised_source_port");
  }
  expectNamed(runNetkit(ingress, privateIngress, 0, packetOutput) == NETKIT_DROP,
              "public_first_rejects_aliasing_private_flow");

  clearWormholeFlows();
  expectNamed(runNetkit(ingress, privateIngress, 0, packetOutput) == NETKIT_PASS,
              "private_first_is_admitted");
  switchboard_wormhole_flow firstPrivate = {};
  expectNamed(lookupProgramMapElement(host, "wh_pending"_ctv, ownerKey, firstPrivate) && firstPrivate.disposition == SWITCHBOARD_WORMHOLE_FLOW_PRIVATE,
              "private_first_claims_exact_reverse_tuple");
  expectNamed(runHost(publicOverlay, hostOutput) == TC_ACT_SHOT,
              "private_first_rejects_aliasing_public_flow");

  switchboard_wormhole_egress_key mixedFamilyExposure = {};
  std::memcpy(mixedFamilyExposure.container, selected, sizeof(mixedFamilyExposure.container));
  mixedFamilyExposure.port = htons(8444);
  mixedFamilyExposure.proto = IPPROTO_TCP;
  switchboard_wormhole_egress_binding mixedFamilyBinding = {};
  mixedFamilyBinding.addr4 = parseIPv4Address("198.18.0.1").s_addr;
  mixedFamilyBinding.owner_generation = 46;
  mixedFamilyBinding.port = htons(444);
  mixedFamilyBinding.proto = IPPROTO_TCP;
  expectNamed(updateProgramMapElement(host, "wh_egress"_ctv, mixedFamilyExposure, mixedFamilyBinding) &&
                  updateProgramMapElement(ingress, "wh_egress"_ctv, mixedFamilyExposure, mixedFamilyBinding) &&
                  updateProgramMapElement(egress, "wh_egress"_ctv, mixedFamilyExposure, mixedFamilyBinding),
              "installs_ipv4_public_binding_for_ipv6_private_service");

  std::vector<uint8_t> mixedFamilyIngress = makeIPv6L4EthernetFrame(peer, server, IPPROTO_TCP, 49'156, 8444);
  std::vector<uint8_t> mixedFamilyReply = makeIPv6L4EthernetFrame(server, peer, IPPROTO_TCP, 8444, 49'156);
  struct tcphdr *mixedFamilyReplyTCP = reinterpret_cast<struct tcphdr *>(mixedFamilyReply.data() + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
  mixedFamilyReplyTCP->ack = 1;
  mixedFamilyReplyTCP->ack_seq = htonl(1);
  mixedFamilyReplyTCP->check = 0;
  mixedFamilyReplyTCP->check = checksumIPv6Transport(server,
                                                     peer,
                                                     IPPROTO_TCP,
                                                     mixedFamilyReplyTCP,
                                                     sizeof(*mixedFamilyReplyTCP));
  flow_key mixedFamilyReplyKey = {};
  std::memcpy(mixedFamilyReplyKey.srcv6, server, sizeof(mixedFamilyReplyKey.srcv6));
  std::memcpy(mixedFamilyReplyKey.dstv6, peer, sizeof(mixedFamilyReplyKey.dstv6));
  mixedFamilyReplyKey.port16[0] = htons(8444);
  mixedFamilyReplyKey.port16[1] = htons(49'156);
  mixedFamilyReplyKey.proto = IPPROTO_TCP;
  switchboard_wormhole_flow_key mixedFamilyOwnerKey =
      switchboardWormholeFlowMapKey(&mixedFamilyReplyKey, mixedFamilyBinding.owner_generation);

  clearWormholeFlows();
  expectNamed(runNetkit(ingress, mixedFamilyIngress, 0, packetOutput) == NETKIT_PASS,
              "ipv4_public_binding_admits_private_ipv6_syn");
  switchboard_wormhole_flow mixedFamilyPrivate = {};
  expectNamed(lookupProgramMapElement(host, "wh_pending"_ctv, mixedFamilyOwnerKey, mixedFamilyPrivate) &&
                  mixedFamilyPrivate.disposition == SWITCHBOARD_WORMHOLE_FLOW_PRIVATE &&
                  mixedFamilyPrivate.phase == SWITCHBOARD_WORMHOLE_FLOW_PENDING,
              "ipv4_public_binding_records_private_ipv6_owner");
  expectNamed(runNetkit(egress, mixedFamilyReply, 0, packetOutput) == NETKIT_PASS &&
                  packetOutput.size() == mixedFamilyReply.size() &&
                  std::memcmp(packetOutput.data(), mixedFamilyReply.data(), mixedFamilyReply.size()) == 0,
              "ipv4_public_binding_preserves_private_ipv6_syn_ack");
  switchboard_wormhole_flow mixedFamilyReverse = {};
  expectNamed(lookupProgramMapElement(host, "wh_pending"_ctv, mixedFamilyOwnerKey, mixedFamilyReverse) &&
                  mixedFamilyReverse.disposition == SWITCHBOARD_WORMHOLE_FLOW_PRIVATE &&
                  mixedFamilyReverse.phase == SWITCHBOARD_WORMHOLE_FLOW_REVERSE_SEEN,
              "private_ipv6_syn_ack_advances_exact_owner");

  std::vector<uint8_t> mixedFamilyAck = makeIPv6L4EthernetFrame(peer, server, IPPROTO_TCP, 49'156, 8444);
  struct ipv6hdr *mixedFamilyAckIPv6 = reinterpret_cast<struct ipv6hdr *>(mixedFamilyAck.data() + sizeof(struct ethhdr));
  struct tcphdr *mixedFamilyAckTCP = reinterpret_cast<struct tcphdr *>(mixedFamilyAckIPv6 + 1);
  mixedFamilyAckTCP->syn = 0;
  mixedFamilyAckTCP->ack = 1;
  mixedFamilyAckTCP->ack_seq = htonl(2);
  mixedFamilyAckTCP->check = 0;
  mixedFamilyAckTCP->check = checksumIPv6Transport(mixedFamilyAckIPv6->saddr.s6_addr,
                                                  mixedFamilyAckIPv6->daddr.s6_addr,
                                                  IPPROTO_TCP,
                                                  mixedFamilyAckTCP,
                                                  sizeof(*mixedFamilyAckTCP));
  expectNamed(runNetkit(ingress, mixedFamilyAck, 0, packetOutput) == NETKIT_DROP &&
                  lookupProgramMapElement(host, "wh_flows"_ctv, mixedFamilyOwnerKey, mixedFamilyReverse) == false,
              "private_ipv6_wrong_ack_cannot_promote_owner");

  mixedFamilyAckTCP->ack_seq = htonl(1);
  mixedFamilyAckTCP->check = 0;
  mixedFamilyAckTCP->check = checksumIPv6Transport(mixedFamilyAckIPv6->saddr.s6_addr,
                                                  mixedFamilyAckIPv6->daddr.s6_addr,
                                                  IPPROTO_TCP,
                                                  mixedFamilyAckTCP,
                                                  sizeof(*mixedFamilyAckTCP));
  expectNamed(runNetkit(ingress, mixedFamilyAck, 0, packetOutput) == NETKIT_PASS,
              "private_ipv6_correct_ack_promotes_owner");
  switchboard_wormhole_flow mixedFamilyEstablished = {};
  expectNamed(lookupProgramMapElement(host, "wh_flows"_ctv, mixedFamilyOwnerKey, mixedFamilyEstablished) &&
                  mixedFamilyEstablished.phase == SWITCHBOARD_WORMHOLE_FLOW_ESTABLISHED &&
                  lookupProgramMapElement(host, "wh_pending"_ctv, mixedFamilyOwnerKey, mixedFamilyReverse) == false,
              "private_ipv6_ack_moves_owner_to_established_map");

  std::vector<uint8_t> mixedFamilyPayload = makeIPv6L4EthernetFrame(peer, server, IPPROTO_TCP, 49'156, 8444, 1551);
  struct ipv6hdr *mixedFamilyPayloadIPv6 = reinterpret_cast<struct ipv6hdr *>(mixedFamilyPayload.data() + sizeof(struct ethhdr));
  struct tcphdr *mixedFamilyPayloadTCP = reinterpret_cast<struct tcphdr *>(mixedFamilyPayloadIPv6 + 1);
  mixedFamilyPayloadTCP->syn = 0;
  mixedFamilyPayloadTCP->ack = 1;
  mixedFamilyPayloadTCP->ack_seq = htonl(1);
  mixedFamilyPayloadTCP->check = 0;
  mixedFamilyPayloadTCP->check = checksumIPv6Transport(mixedFamilyPayloadIPv6->saddr.s6_addr,
                                                      mixedFamilyPayloadIPv6->daddr.s6_addr,
                                                      IPPROTO_TCP,
                                                      mixedFamilyPayloadTCP,
                                                      sizeof(*mixedFamilyPayloadTCP) + 1551);
  expectNamed(runNetkit(ingress, mixedFamilyPayload, 0, packetOutput) == NETKIT_PASS,
              "private_ipv6_established_ack_payload_is_admitted");

  clearWormholeFlows();
  switchboard_wormhole_flow invalidMixedFamilyPublic = {};
  invalidMixedFamilyPublic.binding = mixedFamilyBinding;
  std::memcpy(invalidMixedFamilyPublic.container, selected, sizeof(invalidMixedFamilyPublic.container));
  invalidMixedFamilyPublic.disposition = SWITCHBOARD_WORMHOLE_FLOW_PUBLIC;
  invalidMixedFamilyPublic.phase = SWITCHBOARD_WORMHOLE_FLOW_PENDING;
  invalidMixedFamilyPublic.expiresAtNs = UINT64_MAX;
  expectNamed(updateProgramMapElement(host, "wh_pending"_ctv, mixedFamilyOwnerKey, invalidMixedFamilyPublic),
              "seeds_ipv4_backed_public_ipv6_owner");
  expectNamed(runNetkit(egress, mixedFamilyReply, 0, packetOutput) == NETKIT_DROP,
              "ipv4_binding_cannot_rewrite_public_ipv6_reply");
  switchboard_wormhole_flow unchangedMixedFamilyPublic = {};
  expectNamed(lookupProgramMapElement(host, "wh_pending"_ctv, mixedFamilyOwnerKey, unchangedMixedFamilyPublic) &&
                  unchangedMixedFamilyPublic.transition == invalidMixedFamilyPublic.transition &&
                  unchangedMixedFamilyPublic.expiresAtNs == invalidMixedFamilyPublic.expiresAtNs,
              "rejected_public_family_mismatch_preserves_owner_state");

  clearWormholeFlows();
  std::vector<uint8_t> publicInner2 = makeIPv6L4EthernetFrame(client, external2, IPPROTO_UDP, 49'152, 4443);
  std::vector<uint8_t> publicOverlay2 = makeWormholeIPv6OverlayFrame(publicInner2, selected);
  expectNamed(runHost(publicOverlay, hostOutput) == TC_ACT_REDIRECT && runHost(publicOverlay2, packetOutput) == TC_ACT_REDIRECT,
              "distinct_portals_with_distinct_targets_are_admitted");
  switchboard_wormhole_flow distinct1 = {};
  switchboard_wormhole_flow distinct2 = {};
  expectNamed(lookupProgramMapElement(host, "wh_pending"_ctv, ownerKey, distinct1) &&
                  lookupProgramMapElement(host, "wh_pending"_ctv, ownerKey2, distinct2) &&
                  std::memcmp(&distinct1.binding, &binding, sizeof(binding)) == 0 &&
                  std::memcmp(&distinct2.binding, &binding2, sizeof(binding2)) == 0,
              "distinct_portals_preserve_exact_reverse_bindings");

  uint8_t externalTCP[16] = {};
  parseIPv6Bytes("2001:db8:100::46", externalTCP);
  switchboard_wormhole_egress_binding tcpBinding = installPortal(externalTCP, 443, 10'443, 44, IPPROTO_TCP);
  std::vector<uint8_t> publicTCPInner = makeIPv6L4EthernetFrame(client, externalTCP, IPPROTO_TCP, 49'155, 443);
  std::vector<uint8_t> publicTCPOverlay = makeWormholeIPv6OverlayFrame(publicTCPInner, selected);
  std::vector<uint8_t> tcpReply = makeIPv6L4EthernetFrame(server, client, IPPROTO_TCP, 10'443, 49'155);
  struct tcphdr *tcpReplyHeader = reinterpret_cast<struct tcphdr *>(tcpReply.data() + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
  tcpReplyHeader->ack = 1;
  flow_key tcpReplyKey = {};
  std::memcpy(tcpReplyKey.srcv6, server, sizeof(tcpReplyKey.srcv6));
  std::memcpy(tcpReplyKey.dstv6, client, sizeof(tcpReplyKey.dstv6));
  tcpReplyKey.port16[0] = htons(10'443);
  tcpReplyKey.port16[1] = htons(49'155);
  tcpReplyKey.proto = IPPROTO_TCP;
  switchboard_wormhole_flow_key tcpOwnerKey = switchboardWormholeFlowMapKey(&tcpReplyKey, tcpBinding.owner_generation);

  clearWormholeFlows();
  expectNamed(runHost(publicTCPOverlay, hostOutput) == TC_ACT_REDIRECT &&
                  runNetkit(ingress, hostOutput, SWITCHBOARD_WORMHOLE_SKB_MARK, packetOutput) == NETKIT_PASS,
              "tcp_first_direction_is_admitted");
  switchboard_wormhole_flow pendingTCP = {};
  expectNamed(lookupProgramMapElement(host, "wh_pending"_ctv, tcpOwnerKey, pendingTCP) &&
                  pendingTCP.phase == SWITCHBOARD_WORMHOLE_FLOW_PENDING &&
                  std::memcmp(&pendingTCP.binding, &tcpBinding, sizeof(tcpBinding)) == 0,
              "tcp_first_direction_uses_pending_owner");
  expectNamed(runHost(publicTCPOverlay, hostOutput) == TC_ACT_REDIRECT,
              "tcp_retransmit_is_admitted");
  switchboard_wormhole_flow retransmittedTCP = {};
  expectNamed(lookupProgramMapElement(host, "wh_pending"_ctv, tcpOwnerKey, retransmittedTCP) &&
                  retransmittedTCP.expiresAtNs == pendingTCP.expiresAtNs,
              "tcp_retransmit_cannot_extend_pending_deadline");
  expectNamed(runNetkit(egress, tcpReply, 0, packetOutput) == NETKIT_PASS,
              "tcp_syn_ack_is_admitted");
  switchboard_wormhole_flow reverseSeenTCP = {};
  expectNamed(lookupProgramMapElement(host, "wh_pending"_ctv, tcpOwnerKey, reverseSeenTCP) &&
                  reverseSeenTCP.phase == SWITCHBOARD_WORMHOLE_FLOW_REVERSE_SEEN &&
                  lookupProgramMapElement(host, "wh_flows"_ctv, tcpOwnerKey, reverseSeenTCP) == false,
              "tcp_syn_ack_remains_pending_until_client_ack");
  std::vector<uint8_t> wrongTCPInner = publicTCPInner;
  struct ipv6hdr *wrongTCPIPv6 = reinterpret_cast<struct ipv6hdr *>(wrongTCPInner.data() + sizeof(struct ethhdr));
  struct tcphdr *wrongTCPHeader = reinterpret_cast<struct tcphdr *>(wrongTCPIPv6 + 1);
  wrongTCPHeader->syn = 0;
  wrongTCPHeader->ack = 1;
  wrongTCPHeader->ack_seq = htonl(2);
  wrongTCPHeader->check = 0;
  wrongTCPHeader->check = checksumIPv6Transport(wrongTCPIPv6->saddr.s6_addr,
                                                wrongTCPIPv6->daddr.s6_addr,
                                                IPPROTO_TCP,
                                                wrongTCPHeader,
                                                sizeof(*wrongTCPHeader));
  std::vector<uint8_t> wrongTCPOverlay = makeWormholeIPv6OverlayFrame(wrongTCPInner, selected);
  expectNamed(runHost(wrongTCPOverlay, hostOutput) == TC_ACT_REDIRECT &&
                  runNetkit(ingress, hostOutput, SWITCHBOARD_WORMHOLE_SKB_MARK, packetOutput) == NETKIT_DROP &&
                  lookupProgramMapElement(host, "wh_flows"_ctv, tcpOwnerKey, reverseSeenTCP) == false,
              "tcp_wrong_client_ack_cannot_promote_or_pass_pending_owner");
  struct tcphdr *tcpClientHeader = reinterpret_cast<struct tcphdr *>(publicTCPInner.data() + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
  tcpClientHeader->syn = 0;
  tcpClientHeader->ack = 1;
  tcpClientHeader->ack_seq = htonl(1);
  tcpClientHeader->check = 0;
  tcpClientHeader->check = checksumIPv6Transport(reinterpret_cast<struct ipv6hdr *>(publicTCPInner.data() + sizeof(struct ethhdr))->saddr.s6_addr,
                                                 reinterpret_cast<struct ipv6hdr *>(publicTCPInner.data() + sizeof(struct ethhdr))->daddr.s6_addr,
                                                 IPPROTO_TCP,
                                                 tcpClientHeader,
                                                 sizeof(*tcpClientHeader));
  publicTCPOverlay = makeWormholeIPv6OverlayFrame(publicTCPInner, selected);
  expectNamed(runHost(publicTCPOverlay, hostOutput) == TC_ACT_REDIRECT &&
                  runNetkit(ingress, hostOutput, SWITCHBOARD_WORMHOLE_SKB_MARK, packetOutput) == NETKIT_PASS,
              "tcp_client_ack_promotes_owner");
  switchboard_wormhole_flow establishedTCP = {};
  expectNamed(lookupProgramMapElement(host, "wh_flows"_ctv, tcpOwnerKey, establishedTCP) &&
                  establishedTCP.phase == SWITCHBOARD_WORMHOLE_FLOW_ESTABLISHED &&
                  establishedTCP.expiresAtNs > pendingTCP.expiresAtNs &&
                  lookupProgramMapElement(host, "wh_pending"_ctv, tcpOwnerKey, reverseSeenTCP) == false,
              "tcp_client_ack_moves_owner_to_established_map");

  tcpClientHeader->fin = 1;
  tcpClientHeader->check = 0;
  tcpClientHeader->check = checksumIPv6Transport(reinterpret_cast<struct ipv6hdr *>(publicTCPInner.data() + sizeof(struct ethhdr))->saddr.s6_addr,
                                                 reinterpret_cast<struct ipv6hdr *>(publicTCPInner.data() + sizeof(struct ethhdr))->daddr.s6_addr,
                                                 IPPROTO_TCP,
                                                 tcpClientHeader,
                                                 sizeof(*tcpClientHeader));
  publicTCPOverlay = makeWormholeIPv6OverlayFrame(publicTCPInner, selected);
  expectNamed(runHost(publicTCPOverlay, hostOutput) == TC_ACT_REDIRECT &&
                  runNetkit(ingress, hostOutput, SWITCHBOARD_WORMHOLE_SKB_MARK, packetOutput) == NETKIT_PASS,
              "tcp_fin_is_admitted_for_established_owner");
  switchboard_wormhole_flow closingTCP = {};
  expectNamed(lookupProgramMapElement(host, "wh_flows"_ctv, tcpOwnerKey, closingTCP) &&
                  closingTCP.phase == SWITCHBOARD_WORMHOLE_FLOW_ESTABLISHED_CLOSING &&
                  closingTCP.expiresAtNs < establishedTCP.expiresAtNs,
              "tcp_fin_latches_short_owner_retirement");

  tcpClientHeader->fin = 0;
  tcpClientHeader->check = 0;
  tcpClientHeader->check = checksumIPv6Transport(reinterpret_cast<struct ipv6hdr *>(publicTCPInner.data() + sizeof(struct ethhdr))->saddr.s6_addr,
                                                 reinterpret_cast<struct ipv6hdr *>(publicTCPInner.data() + sizeof(struct ethhdr))->daddr.s6_addr,
                                                 IPPROTO_TCP,
                                                 tcpClientHeader,
                                                 sizeof(*tcpClientHeader));
  publicTCPOverlay = makeWormholeIPv6OverlayFrame(publicTCPInner, selected);
  expectNamed(runHost(publicTCPOverlay, hostOutput) == TC_ACT_REDIRECT &&
                  runNetkit(ingress, hostOutput, SWITCHBOARD_WORMHOLE_SKB_MARK, packetOutput) == NETKIT_PASS,
              "tcp_post_fin_packet_remains_admitted_during_retirement");
  switchboard_wormhole_flow retiringTCP = {};
  expectNamed(lookupProgramMapElement(host, "wh_flows"_ctv, tcpOwnerKey, retiringTCP) &&
                  retiringTCP.phase == SWITCHBOARD_WORMHOLE_FLOW_ESTABLISHED_CLOSING &&
                  retiringTCP.expiresAtNs == closingTCP.expiresAtNs,
              "tcp_post_fin_packet_cannot_reextend_latched_retirement");

  clearWormholeFlows();
  expectNamed(runNetkit(egress, reply, 0, packetOutput) == NETKIT_DROP,
              "missing_reply_owner_fails_closed");
  switchboard_wormhole_flow expired = {};
  expired.binding = binding;
  expired.disposition = SWITCHBOARD_WORMHOLE_FLOW_PUBLIC;
  expired.phase = SWITCHBOARD_WORMHOLE_FLOW_ESTABLISHED;
  expired.expiresAtNs = 1;
  expectNamed(updateProgramMapElement(host, "wh_flows"_ctv, ownerKey, expired), "seeds_expired_reply_owner");
  expectNamed(runNetkit(egress, reply, 0, packetOutput) == NETKIT_DROP,
              "expired_reply_owner_fails_closed");
  expectNamed(runHost(publicOverlay, hostOutput) == TC_ACT_SHOT,
              "expired_owner_blocks_packet_side_resurrection");
  switchboard_wormhole_flow stillExpired = {};
  expectNamed(lookupProgramMapElement(host, "wh_flows"_ctv, ownerKey, stillExpired) &&
                  std::memcmp(&stillExpired, &expired, sizeof(expired)) == 0,
              "expired_owner_remains_unchanged_until_gc");
  SwitchboardWormholeFlowGCCursor expiryCursor = {};
  uint32_t expiryDeleted = 0;
  expectNamed(switchboardCleanupExpiredWormholeFlows(&host, 2, expiryCursor, &expiryDeleted) && expiryDeleted == 0 &&
                  lookupProgramMapElement(host, "wh_flows"_ctv, ownerKey, stillExpired),
              "gc_retains_logically_expired_owner_during_execution_grace");
  expiryCursor = {};
  expectNamed(switchboardCleanupExpiredWormholeFlows(&host,
                                                     WORMHOLE_FLOW_RECLAIM_GRACE_NS + 2,
                                                     expiryCursor,
                                                     &expiryDeleted) &&
                  expiryDeleted == 1,
              "gc_releases_expired_owner_after_execution_grace");
  expectNamed(runHost(publicOverlay, hostOutput) == TC_ACT_REDIRECT,
              "identical_public_ingress_claims_tuple_only_after_gc");
  expectNamed(runNetkit(ingress, hostOutput, SWITCHBOARD_WORMHOLE_SKB_MARK, packetOutput) == NETKIT_PASS,
              "validates_relearned_public_owner_at_socket_boundary");
  expectNamed(runNetkit(egress, reply, 0, packetOutput) == NETKIT_PASS,
              "public_reply_passes_to_host_after_exact_owner_lookup");
  if (packetOutput.size() >= sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr))
  {
    const struct ipv6hdr *rewritten6 = reinterpret_cast<const struct ipv6hdr *>(packetOutput.data() + sizeof(struct ethhdr));
    const struct udphdr *rewrittenUDP = reinterpret_cast<const struct udphdr *>(rewritten6 + 1);
    expectNamed(std::memcmp(rewritten6->saddr.s6_addr, external, sizeof(external)) == 0 && rewrittenUDP->source == htons(443),
                "public_reply_restores_exact_external_source_tuple");
  }
  switchboard_wormhole_flow refreshedOwner = {};
  expectNamed(lookupProgramMapElement(host, "wh_pending"_ctv, ownerKey, refreshedOwner) &&
                  refreshedOwner.phase == SWITCHBOARD_WORMHOLE_FLOW_REVERSE_SEEN &&
                  refreshedOwner.expiresAtNs > firstPublic.expiresAtNs,
              "udp_reverse_reply_refreshes_pending_owner");

  clearWormholeFlows();
  switchboard_wormhole_flow expiredPending = {};
  expiredPending.binding = binding;
  std::memcpy(expiredPending.container, selected, sizeof(selected));
  expiredPending.disposition = SWITCHBOARD_WORMHOLE_FLOW_PUBLIC;
  expiredPending.phase = SWITCHBOARD_WORMHOLE_FLOW_PENDING;
  expiredPending.expiresAtNs = 1;
  expectNamed(updateProgramMapElement(host, "wh_pending"_ctv, ownerKey, expiredPending),
              "seeds_expired_pending_owner");
  expectNamed(runHost(publicOverlay, hostOutput) == TC_ACT_SHOT,
              "expired_pending_owner_blocks_packet_side_replacement");
  switchboard_wormhole_flow retainedPending = {};
  expectNamed(lookupProgramMapElement(host, "wh_pending"_ctv, ownerKey, retainedPending) &&
                  std::memcmp(&retainedPending, &expiredPending, sizeof(expiredPending)) == 0,
              "expired_pending_owner_remains_unchanged_until_gc");
  SwitchboardWormholeFlowGCCursor pendingExpiryCursor = {};
  uint32_t pendingExpiryDeleted = 0;
  expectNamed(switchboardCleanupExpiredWormholeFlows(&host, 2, pendingExpiryCursor, &pendingExpiryDeleted) &&
                  pendingExpiryDeleted == 0 &&
                  lookupProgramMapElement(host, "wh_pending"_ctv, ownerKey, retainedPending),
              "gc_retains_logically_expired_pending_owner_during_execution_grace");
  pendingExpiryCursor = {};
  expectNamed(switchboardCleanupExpiredWormholeFlows(&host,
                                                     WORMHOLE_FLOW_RECLAIM_GRACE_NS + 2,
                                                     pendingExpiryCursor,
                                                     &pendingExpiryDeleted) &&
                  pendingExpiryDeleted == 1 &&
                  lookupProgramMapElement(host, "wh_pending"_ctv, ownerKey, retainedPending) == false,
              "gc_releases_expired_pending_owner_after_execution_grace");
  expectNamed(runHost(publicOverlay, hostOutput) == TC_ACT_REDIRECT &&
                  lookupProgramMapElement(host, "wh_pending"_ctv, ownerKey, retainedPending) &&
                  retainedPending.expiresAtNs > expiredPending.expiresAtNs,
              "identical_public_ingress_reclaims_pending_tuple_only_after_gc");

  clearWormholeFlows();
  switchboard_wormhole_flow staleOwner = {};
  staleOwner.binding = binding;
  std::memcpy(staleOwner.container, selected, sizeof(selected));
  staleOwner.disposition = SWITCHBOARD_WORMHOLE_FLOW_PUBLIC;
  staleOwner.phase = SWITCHBOARD_WORMHOLE_FLOW_ESTABLISHED;
  staleOwner.expiresAtNs = UINT64_MAX;
  expectNamed(updateProgramMapElement(host, "wh_flows"_ctv, ownerKey, staleOwner),
              "seeds_previous_generation_owner");
  switchboard_wormhole_egress_key exposure = {};
  std::memcpy(exposure.container, selected, sizeof(exposure.container));
  exposure.port = htons(8443);
  exposure.proto = IPPROTO_UDP;
  switchboard_wormhole_egress_binding replacementBinding = binding;
  ++replacementBinding.owner_generation;
  expectNamed(updateProgramMapElement(host, "wh_egress"_ctv, exposure, replacementBinding) &&
                  updateProgramMapElement(ingress, "wh_egress"_ctv, exposure, replacementBinding) &&
                  updateProgramMapElement(egress, "wh_egress"_ctv, exposure, replacementBinding),
              "reopens_same_tuple_with_new_owner_generation");
  switchboard_wormhole_flow_key replacementOwnerKey =
      switchboardWormholeFlowMapKey(&replyKey, replacementBinding.owner_generation);
  switchboard_wormhole_flow replacementOwner = {};
  expectNamed(runHost(publicOverlay, hostOutput) == TC_ACT_REDIRECT &&
                  lookupProgramMapElement(host, "wh_pending"_ctv, replacementOwnerKey, replacementOwner) &&
                  lookupProgramMapElement(host, "wh_flows"_ctv, ownerKey, staleOwner),
              "new_generation_claims_same_tuple_without_deleting_old_owner");
  expectNamed(updateProgramMapElement(host, "wh_egress"_ctv, exposure, binding) &&
                  updateProgramMapElement(ingress, "wh_egress"_ctv, exposure, binding) &&
                  updateProgramMapElement(egress, "wh_egress"_ctv, exposure, binding),
              "restores_original_test_binding");
  clearWormholeFlows();

  struct in_addr client4 = parseIPv4Address("203.0.113.99");
  struct in_addr external4 = parseIPv4Address("198.18.0.1");
  portal_definition portal4 = {};
  portal4.addr4 = external4.s_addr;
  portal4.port = htons(443);
  portal4.proto = IPPROTO_UDP;
  portal_meta meta4 = {};
  meta4.slot = 43;
  expectNamed(updateProgramMapElement(host, "ext_portals"_ctv, portal4, meta4),
              "installs_ipv4_portal");
  switchboard_wormhole_target_key target4 = {};
  target4.slot = meta4.slot;
  std::memcpy(target4.container, selected, sizeof(target4.container));
  expectNamed(updateProgramMapElement(host, "wh_targets"_ctv, target4, htons(8443)),
              "installs_ipv4_exact_portal_target");
  uint8_t replica2[5] = {selected[0], selected[1], selected[2], selected[3], uint8_t(selected[4] + 1)};
  switchboard_wormhole_target_key target4Replica2 = {};
  target4Replica2.slot = meta4.slot;
  std::memcpy(target4Replica2.container, replica2, sizeof(target4Replica2.container));
  uint32_t replica2Ifindex = containerIfindex + 1;
  host.setArrayElement("ct_dev_map"_ctv, replica2[4], replica2Ifindex);
  expectNamed(updateProgramMapElement(host, "wh_targets"_ctv, target4Replica2, htons(8443)),
              "installs_ipv4_second_replica_target");
  switchboard_wormhole_egress4_key exposure4 = {};
  exposure4.addr = external4.s_addr;
  exposure4.port = htons(8443);
  exposure4.proto = IPPROTO_UDP;
  switchboard_wormhole_egress_binding binding4 = {};
  binding4.addr4 = external4.s_addr;
  binding4.port = portal4.port;
  binding4.proto = portal4.proto;
  binding4.owner_generation = 44;
  expectNamed(updateProgramMapElement(host, "wh_egress4"_ctv, exposure4, binding4) &&
                  updateProgramMapElement(ingress, "wh_egress4"_ctv, exposure4, binding4) &&
                  updateProgramMapElement(egress, "wh_egress4"_ctv, exposure4, binding4),
              "installs_ipv4_shared_exposure_binding");

  std::vector<uint8_t> publicInner4 = makeIPv4L4EthernetFrame(client4, external4, IPPROTO_UDP, 49'154, 443);
  std::vector<uint8_t> publicOverlay4 = makeWormholeIPv6OverlayFrame(publicInner4, selected);
  std::vector<uint8_t> publicOverlay4Replica2 = makeWormholeIPv6OverlayFrame(publicInner4, replica2);
  std::vector<uint8_t> privateIngress4 = makeIPv4L4EthernetFrame(client4, external4, IPPROTO_UDP, 49'154, 8443);
  std::vector<uint8_t> reply4 = makeIPv4L4EthernetFrame(external4, client4, IPPROTO_UDP, 8443, 49'154);
  std::vector<uint8_t> firstFragment4 = privateIngress4;
  reinterpret_cast<struct iphdr *>(firstFragment4.data() + sizeof(struct ethhdr))->frag_off = htons(IP_MF);
  std::vector<uint8_t> laterFragment4 = privateIngress4;
  reinterpret_cast<struct iphdr *>(laterFragment4.data() + sizeof(struct ethhdr))->frag_off = htons(1);
  expectNamed(runNetkit(ingress, firstFragment4, 0, packetOutput) == NETKIT_DROP &&
                  runNetkit(ingress, firstFragment4, SWITCHBOARD_WORMHOLE_SKB_MARK, packetOutput) == NETKIT_DROP,
              "ipv4_mf_fragment_drops_at_private_and_public_ingress_boundaries");
  expectNamed(runNetkit(ingress, laterFragment4, 0, packetOutput) == NETKIT_DROP &&
                  runNetkit(ingress, laterFragment4, SWITCHBOARD_WORMHOLE_SKB_MARK, packetOutput) == NETKIT_DROP,
              "ipv4_nonzero_offset_fragment_drops_at_private_and_public_ingress_boundaries");
  expectNamed(runNetkit(egress, firstFragment4, 0, packetOutput) == NETKIT_DROP &&
                  runNetkit(egress, laterFragment4, 0, packetOutput) == NETKIT_DROP,
              "ipv4_fragments_drop_before_wormhole_reply_fallthrough");
  std::vector<uint8_t> icmp4 = makeIPv4ICMPEthernetFrame(client4, external4);
  expectNamed(runNetkit(ingress, icmp4, 0, packetOutput) == NETKIT_PASS &&
                  runNetkit(ingress, icmp4, SWITCHBOARD_WORMHOLE_SKB_MARK, packetOutput) == NETKIT_DROP,
              "ipv4_non_l4_traffic_preserves_ordinary_path_but_rejects_public_wormhole_mark");
  std::vector<uint8_t> icmp6 = makeIPv6L4EthernetFrame(client, server, IPPROTO_UDP, 49'154, 8443);
  reinterpret_cast<struct ipv6hdr *>(icmp6.data() + sizeof(struct ethhdr))->nexthdr = IPPROTO_ICMPV6;
  expectNamed(runNetkit(ingress, icmp6, 0, packetOutput) == NETKIT_PASS &&
                  runNetkit(ingress, icmp6, SWITCHBOARD_WORMHOLE_SKB_MARK, packetOutput) == NETKIT_DROP,
              "ipv6_non_l4_traffic_preserves_ordinary_path_but_rejects_public_wormhole_mark");
  flow_key replyKey4 = {};
  replyKey4.src = external4.s_addr;
  replyKey4.dst = client4.s_addr;
  replyKey4.port16[0] = htons(8443);
  replyKey4.port16[1] = htons(49'154);
  replyKey4.proto = IPPROTO_UDP;
  switchboard_wormhole_flow_key ownerKey4 = switchboardWormholeFlowMapKey(&replyKey4, binding4.owner_generation);

  clearWormholeFlows();
  expectNamed(runHost(publicOverlay4, hostOutput) == TC_ACT_REDIRECT &&
                  runNetkit(ingress, hostOutput, SWITCHBOARD_WORMHOLE_SKB_MARK, packetOutput) == NETKIT_PASS,
              "ipv4_public_first_is_admitted_across_shared_map");
  switchboard_wormhole_flow public4 = {};
  expectNamed(lookupProgramMapElement(host, "wh_pending"_ctv, ownerKey4, public4) &&
                  public4.disposition == SWITCHBOARD_WORMHOLE_FLOW_PUBLIC &&
                  runNetkit(ingress, privateIngress4, 0, packetOutput) == NETKIT_DROP,
              "ipv4_public_first_rejects_aliasing_private_flow");
  expectNamed(runHost(publicOverlay4Replica2, packetOutput) == TC_ACT_SHOT,
              "ipv4_first_replica_owner_rejects_second_replica_alias");

  clearWormholeFlows();
  expectNamed(runHost(publicOverlay4Replica2, hostOutput) == TC_ACT_REDIRECT &&
                  runHost(publicOverlay4, packetOutput) == TC_ACT_SHOT,
              "ipv4_second_replica_owner_rejects_first_replica_alias");

  clearWormholeFlows();
  expectNamed(runNetkit(ingress, privateIngress4, 0, packetOutput) == NETKIT_PASS &&
                  runHost(publicOverlay4, hostOutput) == TC_ACT_SHOT,
              "ipv4_private_first_rejects_aliasing_public_flow");

  switchboard_wormhole_egress4_key tcpExposure4 = exposure4;
  tcpExposure4.port = htons(8444);
  tcpExposure4.proto = IPPROTO_TCP;
  switchboard_wormhole_egress_binding tcpBinding4 = binding4;
  tcpBinding4.port = htons(444);
  tcpBinding4.proto = IPPROTO_TCP;
  tcpBinding4.owner_generation = 45;
  expectNamed(updateProgramMapElement(host, "wh_egress4"_ctv, tcpExposure4, tcpBinding4) &&
                  updateProgramMapElement(ingress, "wh_egress4"_ctv, tcpExposure4, tcpBinding4) &&
                  updateProgramMapElement(egress, "wh_egress4"_ctv, tcpExposure4, tcpBinding4),
              "installs_ipv4_tcp_shared_exposure_binding");

  std::vector<uint8_t> privateTCP4 = makeIPv4L4EthernetFrame(client4, external4, IPPROTO_TCP, 49'157, 8444);
  std::vector<uint8_t> privateTCPReply4 = makeIPv4L4EthernetFrame(external4, client4, IPPROTO_TCP, 8444, 49'157);
  struct tcphdr *privateTCPReplyHeader4 = reinterpret_cast<struct tcphdr *>(privateTCPReply4.data() + sizeof(struct ethhdr) + sizeof(struct iphdr));
  privateTCPReplyHeader4->ack = 1;
  privateTCPReplyHeader4->ack_seq = htonl(1);
  flow_key privateTCPReplyKey4 = {};
  privateTCPReplyKey4.src = external4.s_addr;
  privateTCPReplyKey4.dst = client4.s_addr;
  privateTCPReplyKey4.port16[0] = htons(8444);
  privateTCPReplyKey4.port16[1] = htons(49'157);
  privateTCPReplyKey4.proto = IPPROTO_TCP;
  switchboard_wormhole_flow_key privateTCPOwnerKey4 =
      switchboardWormholeFlowMapKey(&privateTCPReplyKey4, tcpBinding4.owner_generation);

  clearWormholeFlows();
  expectNamed(runNetkit(ingress, privateTCP4, 0, packetOutput) == NETKIT_PASS,
              "private_ipv4_syn_is_admitted");
  switchboard_wormhole_flow privateTCPPending4 = {};
  expectNamed(lookupProgramMapElement(host, "wh_pending"_ctv, privateTCPOwnerKey4, privateTCPPending4) &&
                  privateTCPPending4.phase == SWITCHBOARD_WORMHOLE_FLOW_PENDING &&
                  runNetkit(egress, privateTCPReply4, 0, packetOutput) == NETKIT_PASS,
              "private_ipv4_syn_ack_advances_owner");

  std::vector<uint8_t> privateTCPAck4 = makeIPv4L4EthernetFrame(client4, external4, IPPROTO_TCP, 49'157, 8444);
  struct tcphdr *privateTCPAckHeader4 = reinterpret_cast<struct tcphdr *>(privateTCPAck4.data() + sizeof(struct ethhdr) + sizeof(struct iphdr));
  privateTCPAckHeader4->syn = 0;
  privateTCPAckHeader4->ack = 1;
  privateTCPAckHeader4->ack_seq = htonl(2);
  expectNamed(runNetkit(ingress, privateTCPAck4, 0, packetOutput) == NETKIT_DROP,
              "private_ipv4_wrong_ack_cannot_promote_owner");
  privateTCPAckHeader4->ack_seq = htonl(1);
  expectNamed(runNetkit(ingress, privateTCPAck4, 0, packetOutput) == NETKIT_PASS,
              "private_ipv4_correct_ack_promotes_owner");
  switchboard_wormhole_flow privateTCPEstablished4 = {};
  expectNamed(lookupProgramMapElement(host, "wh_flows"_ctv, privateTCPOwnerKey4, privateTCPEstablished4) &&
                  privateTCPEstablished4.phase == SWITCHBOARD_WORMHOLE_FLOW_ESTABLISHED &&
                  lookupProgramMapElement(host, "wh_pending"_ctv, privateTCPOwnerKey4, privateTCPPending4) == false,
              "private_ipv4_ack_moves_owner_to_established_map");

  std::vector<uint8_t> privateTCPPayload4 = makeIPv4L4EthernetFrame(client4, external4, IPPROTO_TCP, 49'157, 8444, 1551);
  struct tcphdr *privateTCPPayloadHeader4 = reinterpret_cast<struct tcphdr *>(privateTCPPayload4.data() + sizeof(struct ethhdr) + sizeof(struct iphdr));
  privateTCPPayloadHeader4->syn = 0;
  privateTCPPayloadHeader4->ack = 1;
  privateTCPPayloadHeader4->ack_seq = htonl(1);
  expectNamed(runNetkit(ingress, privateTCPPayload4, 0, packetOutput) == NETKIT_PASS,
              "private_ipv4_established_ack_payload_is_admitted");

  clearWormholeFlows();
  expectNamed(runHost(publicOverlay4, hostOutput) == TC_ACT_REDIRECT &&
                  runNetkit(ingress, hostOutput, SWITCHBOARD_WORMHOLE_SKB_MARK, packetOutput) == NETKIT_PASS,
              "ipv4_public_reply_establishes_first_replica_owner");
  policy.containerFragment = replica2[4];
  egress.setArrayElement("ct_net_policy"_ctv, 0, policy);
  expectNamed(runNetkit(egress, reply4, 0, packetOutput) == NETKIT_DROP,
              "ipv4_second_replica_cannot_consume_first_replica_owner");
  policy.containerFragment = selected[4];
  egress.setArrayElement("ct_net_policy"_ctv, 0, policy);
  expectNamed(runNetkit(egress, reply4, 0, packetOutput) == NETKIT_PASS,
              "ipv4_public_reply_uses_exact_reverse_owner");
  if (packetOutput.size() >= sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
  {
    const struct iphdr *rewritten4 = reinterpret_cast<const struct iphdr *>(packetOutput.data() + sizeof(struct ethhdr));
    const struct udphdr *rewrittenUDP4 = reinterpret_cast<const struct udphdr *>(rewritten4 + 1);
    expectNamed(rewritten4->saddr == external4.s_addr && rewrittenUDP4->source == htons(443),
                "ipv4_public_reply_restores_exact_external_source_tuple");
  }

  clearWormholeFlows();
  switchboard_wormhole_flow live = expired;
  live.expiresAtNs = UINT64_MAX;
  expectNamed(updateProgramMapElement(host, "wh_flows"_ctv, ownerKey, expired) &&
                  updateProgramMapElement(host, "wh_flows"_ctv, ownerKey2, live),
              "seeds_gc_expired_and_live_owners");
  SwitchboardWormholeFlowGCCursor gcCursor = {};
  uint32_t deleted = 0;
  expectNamed(switchboardCleanupExpiredWormholeFlows(&host,
                                                     WORMHOLE_FLOW_RECLAIM_GRACE_NS + 2,
                                                     gcCursor,
                                                     &deleted) &&
                  deleted == 1,
              "gc_deletes_only_expired_owner");
  switchboard_wormhole_flow remaining = {};
  expectNamed(lookupProgramMapElement(host, "wh_flows"_ctv, ownerKey, remaining) == false &&
                  lookupProgramMapElement(host, "wh_flows"_ctv, ownerKey2, remaining),
              "gc_preserves_live_owner");

  clearWormholeFlows();
  (void)unlink(establishedPinPath.c_str());
  (void)unlink(pendingPinPath.c_str());
  host.close();
  ingress.close();
  egress.close();
}

static void exerciseWormholeTCPPromotionMapFull(TestSuite& suite)
{
  String objectPath = {};
  objectPath.assign(PRODIGY_TEST_BINARY_DIR);
  objectPath.append("/container.ingress.router.wormhole-full.ebpf.o"_ctv);
  BPFProgram ingress = {};
  suite.expect(ingress.load(objectPath, "ct_ingress"_ctv),
               "switchboard_wormhole_tcp_map_full_loads_bounded_program");
  if (ingress.prog_fd < 0)
  {
    return;
  }

  const uint8_t container[5] = {0x01, 0x16, 0x25, 0x5b, 0x4e};
  local_container_subnet6 subnet = {};
  subnet.dpfx = container[0];
  std::memcpy(subnet.mpfx, container + 1, sizeof(subnet.mpfx));
  ingress.setArrayElement("lc_subnet"_ctv, 0, subnet);
  container_network_policy policy = {};
  policy.mode = CONTAINER_NETWORK_UNRESTRICTED;
  policy.containerFragment = container[4];
  ingress.setArrayElement("ct_net_policy"_ctv, 0, policy);

  uint8_t client[16] = {};
  uint8_t server[16] = {};
  parseIPv6Bytes("2001:db8:200::99", client);
  makeContainerIPv6(server, container[0], container[1], container[2], container[3], container[4]);
  switchboard_wormhole_egress_key exposure = {};
  std::memcpy(exposure.container, container, sizeof(exposure.container));
  exposure.port = htons(10'443);
  exposure.proto = IPPROTO_TCP;
  switchboard_wormhole_egress_binding binding = {};
  parseIPv6Bytes("2001:db8:100::46", reinterpret_cast<uint8_t *>(binding.addr6));
  binding.port = htons(443);
  binding.proto = IPPROTO_TCP;
  binding.is_ipv6 = 1;
  binding.owner_generation = 77;
  suite.expect(updateProgramMapElement(ingress, "wh_egress"_ctv, exposure, binding),
               "switchboard_wormhole_tcp_map_full_installs_binding");

  flow_key reply = {};
  std::memcpy(reply.srcv6, server, sizeof(reply.srcv6));
  std::memcpy(reply.dstv6, client, sizeof(reply.dstv6));
  reply.port16[0] = htons(10'443);
  reply.port16[1] = htons(49'155);
  reply.proto = IPPROTO_TCP;
  switchboard_wormhole_flow_key ownerKey = switchboardWormholeFlowMapKey(&reply, binding.owner_generation);
  switchboard_wormhole_flow pending = {};
  pending.binding = binding;
  std::memcpy(pending.container, container, sizeof(pending.container));
  pending.disposition = SWITCHBOARD_WORMHOLE_FLOW_PUBLIC;
  pending.phase = SWITCHBOARD_WORMHOLE_FLOW_REVERSE_SEEN;
  pending.expectedAck = htonl(1);
  pending.expiresAtNs = UINT64_MAX;
  suite.expect(updateProgramMapElement(ingress, "wh_pending"_ctv, ownerKey, pending),
               "switchboard_wormhole_tcp_map_full_seeds_pending_handshake");

  switchboard_wormhole_flow_key fillerKey = ownerKey;
  fillerKey.owner_generation = 78;
  switchboard_wormhole_flow filler = pending;
  filler.phase = SWITCHBOARD_WORMHOLE_FLOW_ESTABLISHED;
  suite.expect(updateProgramMapElement(ingress, "wh_flows"_ctv, fillerKey, filler),
               "switchboard_wormhole_tcp_map_full_fills_established_map");

  std::vector<uint8_t> frame = makeIPv6L4EthernetFrame(client, server, IPPROTO_TCP, 49'155, 10'443);
  struct ipv6hdr *ip6 = reinterpret_cast<struct ipv6hdr *>(frame.data() + sizeof(struct ethhdr));
  struct tcphdr *tcp = reinterpret_cast<struct tcphdr *>(ip6 + 1);
  tcp->syn = 0;
  tcp->ack = 1;
  tcp->ack_seq = htonl(1);
  tcp->check = 0;
  tcp->check = checksumIPv6Transport(ip6->saddr.s6_addr, ip6->daddr.s6_addr, IPPROTO_TCP, tcp, sizeof(*tcp));

  std::vector<uint8_t> output(frame.size() + 64u);
  struct __sk_buff context = {};
  context.mark = SWITCHBOARD_WORMHOLE_SKB_MARK;
  LIBBPF_OPTS(bpf_test_run_opts, opts,
              .data_in = frame.data(),
              .data_out = output.data(),
              .data_size_in = static_cast<__u32>(frame.size()),
              .data_size_out = static_cast<__u32>(output.size()),
              .ctx_in = &context,
              .ctx_size_in = sizeof(context),
              .repeat = 1, );
  switchboard_wormhole_flow retained = {};
  suite.expect(bpf_prog_test_run_opts(ingress.prog_fd, &opts) == 0 && opts.retval == NETKIT_DROP,
               "switchboard_wormhole_tcp_map_full_drops_ack_when_promotion_cannot_commit");
  suite.expect(lookupProgramMapElement(ingress, "wh_pending"_ctv, ownerKey, retained) &&
                   lookupProgramMapElement(ingress, "wh_flows"_ctv, ownerKey, retained) == false,
               "switchboard_wormhole_tcp_map_full_preserves_pending_without_false_establishment");
  ingress.close();
}

static void exerciseBalancerOwnedRoutableMissPassesToKernel(TestSuite& suite)
{
  const char *label = "switchboard_balancer_owned_routable_miss_passes_to_kernel";
  auto expectNamed = [&](bool condition, const char *suffix) -> void {
    char name[256] = {};
    std::snprintf(name, sizeof(name), "%s_%s", label, suffix);
    suite.expect(condition, name);
  };

  String balancerObjectPath = {};
  balancerObjectPath.assign(PRODIGY_TEST_BINARY_DIR);
  balancerObjectPath.append("/balancer.ebpf.o"_ctv);

  BPFProgram balancerProgram = {};
  expectNamed(balancerProgram.load(balancerObjectPath, "bal_ingress"_ctv), "loads_program");
  if (balancerProgram.prog_fd < 0)
  {
    return;
  }

  struct in_addr external4 = {};
  struct in_addr client4 = {};
  expectNamed(inet_pton(AF_INET, "198.18.0.1", &external4) == 1, "parses_external");
  expectNamed(inet_pton(AF_INET, "203.0.113.99", &client4) == 1, "parses_client");

  switchboard_owned_routable_prefix4_key ownedKey = {};
  ownedKey.prefixlen = 32;
  ownedKey.addr = external4.s_addr;
  __u8 present = 1;
  expectNamed(updateProgramMapElement(balancerProgram, "owned_pfx4"_ctv, ownedKey, present),
              "sets_owned_external_prefix");

  auto runPassCase = [&](const char *suffix, const std::vector<uint8_t>& frame) -> void {
    std::vector<uint8_t> output(frame.size() + 64u);
    LIBBPF_OPTS(bpf_test_run_opts, opts,
                .data_in = frame.data(),
                .data_out = output.data(),
                .data_size_in = static_cast<__u32>(frame.size()),
                .data_size_out = static_cast<__u32>(output.size()),
                .repeat = 1, );

    int runResult = bpf_prog_test_run_opts(balancerProgram.prog_fd, &opts);
    expectNamed(runResult == 0, suffix);
    char passName[128] = {};
    std::snprintf(passName, sizeof(passName), "%s_returns_xdp_pass", suffix);
    expectNamed(opts.retval == XDP_PASS, passName);
  };

  runPassCase("tcp_no_portal", makeIPv4L4EthernetFrame(client4, external4, IPPROTO_TCP, 49'152, 22));
  runPassCase("icmp", makeIPv4ICMPEthernetFrame(client4, external4));

  balancerProgram.close();
}

int main(int argc, char **argv)
{
  if (argc == 2 && std::strcmp(argv[1], "--development-map-allocation-only") == 0)
  {
    TestSuite suite = {};
    verifyDevelopmentWhiteholeMapAllocation(suite);
    return suite.failed == 0 ? 0 : 1;
  }

  if (const char *allow = std::getenv("PRODIGY_DEV_ALLOW_BPF_ATTACH"); allow == nullptr || std::strcmp(allow, "1") != 0)
  {
    std::fprintf(stderr, "SKIP: switchboard whitehole unit loads BPF programs; set PRODIGY_DEV_ALLOW_BPF_ATTACH=1 only inside an authorized isolated VM\n");
    return 77;
  }

  TestSuite suite = {};
  verifyDevelopmentWhiteholeMapAllocation(suite);

  Whitehole whitehole = {};
  whitehole.transport = ExternalAddressTransport::quic;
  whitehole.family = ExternalAddressFamily::ipv6;
  whitehole.source = ExternalAddressSource::registeredRoutablePrefix;
  whitehole.hasAddress = true;
  whitehole.address = IPAddress("2001:db8::44", true);
  whitehole.sourcePort = 5353;
  whitehole.bindingNonce = 0x12345678u;

  local_container_subnet6 subnet = {};
  subnet.dpfx = 0x7A;
  subnet.mpfx[0] = 0x01;
  subnet.mpfx[1] = 0x02;
  subnet.mpfx[2] = 0x03;

  uint32_t containerID = 0x01020304u;
  portal_definition key = {};
  switchboard_whitehole_binding value = {};
  suite.expect(switchboardBuildWhiteholeBinding(whitehole, containerID, subnet, key, value), "switchboard_whitehole_binding_builds");
  suite.expect(key.port == htons(whitehole.sourcePort), "switchboard_whitehole_binding_stores_network_order_port");
  suite.expect(ntohs(key.port) == whitehole.sourcePort, "switchboard_whitehole_binding_roundtrips_port");
  suite.expect(key.proto == IPPROTO_UDP, "switchboard_whitehole_binding_maps_quic_to_udp");
  suite.expect(std::memcmp(key.addr6, whitehole.address.v6, sizeof(key.addr6)) == 0, "switchboard_whitehole_binding_preserves_address");
  suite.expect(value.nonce == whitehole.bindingNonce, "switchboard_whitehole_binding_preserves_nonce");
  suite.expect(value.container.hasID, "switchboard_whitehole_binding_sets_container_has_id");
  suite.expect(value.container.value[0] == subnet.dpfx, "switchboard_whitehole_binding_sets_datacenter_prefix");
  suite.expect(value.container.value[1] == 0x04 && value.container.value[2] == 0x03 && value.container.value[3] == 0x02 && value.container.value[4] == 0x01, "switchboard_whitehole_binding_sets_container_suffix");

  String pinPath = {};
  switchboardWhiteholeReplyFlowPinPath(pinPath, 17);
  suite.expect(pinPath == "/sys/fs/bpf/prodigy_whitehole_reply_flows_17"_ctv, "switchboard_whitehole_pin_path_uses_interface_index");

  {
    String egressObjectPath = {};
    egressObjectPath.assign(PRODIGY_TEST_BINARY_DIR);
    egressObjectPath.append("/host.egress.router.ebpf.o"_ctv);

    String ingressObjectPath = {};
    ingressObjectPath.assign(PRODIGY_TEST_BINARY_DIR);
    ingressObjectPath.append("/host.ingress.router.ebpf.o"_ctv);

    uint32_t testIfindex = uint32_t(::getpid());
    String sharedWhiteholePinPath = {};
    switchboardWhiteholeReplyFlowPinPath(sharedWhiteholePinPath, testIfindex);
    (void)unlink(sharedWhiteholePinPath.c_str());

    BPFProgram egressProgram = {};
    suite.expect(egressProgram.load(egressObjectPath, "host_egress"_ctv), "switchboard_whitehole_reply_flow_reuse_loads_host_egress_program");

    bool pinnedReplyMap = switchboardPinWhiteholeReplyFlowMap(&egressProgram, testIfindex);
    suite.expect(pinnedReplyMap, "switchboard_whitehole_reply_flow_reuse_pins_egress_reply_map_before_ingress_load");

    bool reusedPinnedReplyMap = false;
    BPFProgram ingressProgram = {};
    bool ingressLoaded = ingressProgram.load(ingressObjectPath,
                                             "host_ingress"_ctv,
                                             [&](struct bpf_object *obj, Vector<int>& inner_map_fds) -> void {
                                               reusedPinnedReplyMap = switchboardReusePinnedWhiteholeReplyFlowMap(obj, testIfindex, inner_map_fds);
                                             });
    suite.expect(ingressLoaded, "switchboard_whitehole_reply_flow_reuse_loads_host_ingress_program");
    suite.expect(reusedPinnedReplyMap, "switchboard_whitehole_reply_flow_reuse_reuses_pinned_map_for_ingress_program");

    uint32_t egressReplyMapID = programMapID(egressProgram, "white_replies"_ctv);
    uint32_t ingressReplyMapID = programMapID(ingressProgram, "white_replies"_ctv);
    suite.expect(egressReplyMapID != 0, "switchboard_whitehole_reply_flow_reuse_resolves_egress_map_id");
    suite.expect(ingressReplyMapID == egressReplyMapID, "switchboard_whitehole_reply_flow_reuse_shares_reply_flow_map_between_egress_and_ingress");

    if (ingressLoaded)
    {
      suite.expect(programMapID(ingressProgram, "ext_portals"_ctv) != 0,
                   "switchboard_host_ingress_production_has_portal_map");
      suite.expect(programMapID(ingressProgram, "wh_targets"_ctv) != 0,
                   "switchboard_host_ingress_production_has_wormhole_target_port_map");
      suite.expect(programMapID(ingressProgram, "quic_cid_dec"_ctv) != 0,
                   "switchboard_host_ingress_production_has_quic_decrypt_map");
    }

    (void)unlink(sharedWhiteholePinPath.c_str());
  }

  {
    String ingressObjectPath = {};
    ingressObjectPath.assign(PRODIGY_TEST_BINARY_DIR);
    ingressObjectPath.append("/host.ingress.router.dev.ebpf.o"_ctv);

    BPFProgram ingressProgram = {};
    suite.expect(ingressProgram.load(ingressObjectPath, "host_ingress"_ctv),
                 "switchboard_host_ingress_ipv4_quic_portal_loads_host_ingress_program");

    if (ingressProgram.prog_fd >= 0)
    {
      local_container_subnet6 localSubnet = {};
      localSubnet.dpfx = 0x01;
      localSubnet.mpfx[0] = 0x52;
      localSubnet.mpfx[1] = 0xdf;
      localSubnet.mpfx[2] = 0x39;
      ingressProgram.setArrayElement("lc_subnet"_ctv, 0, localSubnet);

      uint32_t redirectIfidx = 91;
      ingressProgram.setArrayElement("ct_dev_map"_ctv, 0x4e, redirectIfidx);

      struct in_addr externalAddress = {};
      struct in_addr clientAddress = {};
      suite.expect(inet_pton(AF_INET, "198.18.0.1", &externalAddress) == 1,
                   "switchboard_host_ingress_ipv4_quic_portal_external_address_parses");
      suite.expect(inet_pton(AF_INET, "203.0.113.99", &clientAddress) == 1,
                   "switchboard_host_ingress_ipv4_quic_portal_client_address_parses");

      uint8_t key[16] = {
          0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
          0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01};
      ProdigyQuicCidEncryptor encryptor = {};
      suite.expect(encryptor.setKey(key),
                   "switchboard_host_ingress_ipv4_quic_portal_encryptor_accepts_key");

      uint8_t cidContainer[5] = {localSubnet.dpfx, localSubnet.mpfx[0], localSubnet.mpfx[1], localSubnet.mpfx[2], 0x4e};
      struct sockaddr_in cidDestination = {};
      cidDestination.sin_family = AF_INET;
      cidDestination.sin_addr = externalAddress;
      cidDestination.sin_port = htons(18'443);

      uint32_t nonceCursor = 1;
      ProdigyQuicCID cid = prodigyGenerateQuicCID(encryptor,
                                                  cidContainer,
                                                  &nonceCursor,
                                                  reinterpret_cast<const struct sockaddr *>(&cidDestination),
                                                  0);
      suite.expect(cid.id_len == 16,
                   "switchboard_host_ingress_ipv4_quic_portal_generates_cid");

      portal_definition portal = {};
      portal.addr4 = externalAddress.s_addr;
      portal.port = htons(18'443);
      portal.proto = IPPROTO_UDP;

      portal_meta meta = {};
      meta.flags = F_QUIC_PORTAL;
      meta.slot = 7;

      bool portalUpdated = false;
      ingressProgram.openMap("ext_portals"_ctv, [&](int mapFD) -> void {
        portalUpdated = mapFD >= 0 && bpf_map_update_elem(mapFD, &portal, &meta, BPF_ANY) == 0;
      });
      suite.expect(portalUpdated,
                   "switchboard_host_ingress_ipv4_quic_portal_installs_portal");

      switchboard_wormhole_target_key targetKey = {};
      targetKey.slot = meta.slot;
      std::memcpy(targetKey.container, cidContainer, sizeof(targetKey.container));
      uint16_t targetPort = htons(19'443);

      bool targetUpdated = false;
      ingressProgram.openMap("wh_targets"_ctv, [&](int mapFD) -> void {
        targetUpdated = mapFD >= 0 && bpf_map_update_elem(mapFD, &targetKey, &targetPort, BPF_ANY) == 0;
      });
      suite.expect(targetUpdated,
                   "switchboard_host_ingress_ipv4_quic_portal_installs_target_port");
      suite.expect(installWormholeExposure(ingressProgram, portal, false, cidContainer, targetPort, meta.slot + 1u),
                   "switchboard_host_ingress_ipv4_quic_portal_installs_exposure");

      struct
      {
        uint32_t rk[44];
      } aesState = {};
      suite.expect(prodigyBuildQuicCidDecryptRoundKeys(key, aesState.rk),
                   "switchboard_host_ingress_ipv4_quic_portal_builds_decrypt_state");

      uint32_t decryptIndex = quicCidPortalDecryptMapIndex(meta.slot, 0);
      bool decryptUpdated = false;
      ingressProgram.openMap("quic_cid_dec"_ctv, [&](int mapFD) -> void {
        decryptUpdated = mapFD >= 0 && bpf_map_update_elem(mapFD, &decryptIndex, &aesState, BPF_ANY) == 0;
      });
      suite.expect(decryptUpdated,
                   "switchboard_host_ingress_ipv4_quic_portal_installs_decrypt_state");

      std::vector<uint8_t> frame = makeUDPv4QuicEthernetFrame(clientAddress, externalAddress, 49'152, 18'443, cid);
      std::vector<uint8_t> output(frame.size());
      LIBBPF_OPTS(bpf_test_run_opts, opts,
                  .data_in = frame.data(),
                  .data_out = output.data(),
                  .data_size_in = static_cast<__u32>(frame.size()),
                  .data_size_out = static_cast<__u32>(output.size()),
                  .repeat = 1, );

      int runResult = bpf_prog_test_run_opts(ingressProgram.prog_fd, &opts);
      suite.expect(runResult == 0,
                   "switchboard_host_ingress_ipv4_quic_portal_test_run_succeeds");
      suite.expect(opts.retval == TC_ACT_REDIRECT,
                   "switchboard_host_ingress_ipv4_quic_portal_redirects_to_container");

      if (runResult == 0 && opts.data_size_out >= sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
      {
        const struct ethhdr *outEth = reinterpret_cast<const struct ethhdr *>(output.data());
        const struct iphdr *outIP = reinterpret_cast<const struct iphdr *>(output.data() + sizeof(struct ethhdr));
        const struct udphdr *outUDP = reinterpret_cast<const struct udphdr *>(outIP + 1);
        suite.expect(outEth->h_proto == htons(ETH_P_IP),
                     "switchboard_host_ingress_ipv4_quic_portal_preserves_ipv4_ethertype");
        suite.expect(outIP->daddr == externalAddress.s_addr,
                     "switchboard_host_ingress_ipv4_quic_portal_preserves_external_destination");
        suite.expect(outUDP->dest == targetPort,
                     "switchboard_host_ingress_ipv4_quic_portal_rewrites_container_port");
      }

      ingressProgram.close();
    }
  }

  {
    String ingressObjectPath = {};
    ingressObjectPath.assign(PRODIGY_TEST_BINARY_DIR);
    ingressObjectPath.append("/host.ingress.router.dev.ebpf.o"_ctv);

    BPFProgram ingressProgram = {};
    suite.expect(ingressProgram.load(ingressObjectPath, "host_ingress"_ctv),
                 "switchboard_host_ingress_decapped_ipv4_quic_portal_loads_host_ingress_program");

    if (ingressProgram.prog_fd >= 0)
    {
      local_container_subnet6 localSubnet = {};
      localSubnet.dpfx = 0x01;
      localSubnet.mpfx[0] = 0x52;
      localSubnet.mpfx[1] = 0xdf;
      localSubnet.mpfx[2] = 0x39;
      ingressProgram.setArrayElement("lc_subnet"_ctv, 0, localSubnet);

      uint32_t redirectIfidx = 92;
      ingressProgram.setArrayElement("ct_dev_map"_ctv, 0x4e, redirectIfidx);

      struct in_addr externalAddress = {};
      struct in_addr clientAddress = {};
      suite.expect(inet_pton(AF_INET, "198.18.0.1", &externalAddress) == 1,
                   "switchboard_host_ingress_decapped_ipv4_quic_portal_external_address_parses");
      suite.expect(inet_pton(AF_INET, "203.0.113.99", &clientAddress) == 1,
                   "switchboard_host_ingress_decapped_ipv4_quic_portal_client_address_parses");

      uint8_t key[16] = {
          0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
          0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01};
      ProdigyQuicCidEncryptor encryptor = {};
      suite.expect(encryptor.setKey(key),
                   "switchboard_host_ingress_decapped_ipv4_quic_portal_encryptor_accepts_key");

      uint8_t cidContainer[5] = {localSubnet.dpfx, localSubnet.mpfx[0], localSubnet.mpfx[1], localSubnet.mpfx[2], 0x4e};
      struct sockaddr_in cidDestination = {};
      cidDestination.sin_family = AF_INET;
      cidDestination.sin_addr = externalAddress;
      cidDestination.sin_port = htons(443);

      uint32_t nonceCursor = 2;
      ProdigyQuicCID cid = prodigyGenerateQuicCID(encryptor,
                                                  cidContainer,
                                                  &nonceCursor,
                                                  reinterpret_cast<const struct sockaddr *>(&cidDestination),
                                                  0);
      suite.expect(cid.id_len == 16,
                   "switchboard_host_ingress_decapped_ipv4_quic_portal_generates_cid");

      portal_definition portal = {};
      portal.addr4 = externalAddress.s_addr;
      portal.port = htons(443);
      portal.proto = IPPROTO_UDP;

      portal_meta meta = {};
      meta.flags = F_QUIC_PORTAL;
      meta.slot = 9;

      bool portalUpdated = false;
      ingressProgram.openMap("ext_portals"_ctv, [&](int mapFD) -> void {
        portalUpdated = mapFD >= 0 && bpf_map_update_elem(mapFD, &portal, &meta, BPF_ANY) == 0;
      });
      suite.expect(portalUpdated,
                   "switchboard_host_ingress_decapped_ipv4_quic_portal_installs_portal");

      switchboard_wormhole_target_key targetKey = {};
      targetKey.slot = meta.slot;
      std::memcpy(targetKey.container, cidContainer, sizeof(targetKey.container));
      uint16_t targetPort = htons(19'443);

      bool targetUpdated = false;
      ingressProgram.openMap("wh_targets"_ctv, [&](int mapFD) -> void {
        targetUpdated = mapFD >= 0 && bpf_map_update_elem(mapFD, &targetKey, &targetPort, BPF_ANY) == 0;
      });
      suite.expect(targetUpdated,
                   "switchboard_host_ingress_decapped_ipv4_quic_portal_installs_target_port");
      suite.expect(installWormholeExposure(ingressProgram, portal, false, cidContainer, targetPort, meta.slot + 1u),
                   "switchboard_host_ingress_decapped_ipv4_quic_portal_installs_exposure");

      struct
      {
        uint32_t rk[44];
      } aesState = {};
      suite.expect(prodigyBuildQuicCidDecryptRoundKeys(key, aesState.rk),
                   "switchboard_host_ingress_decapped_ipv4_quic_portal_builds_decrypt_state");

      uint32_t decryptIndex = quicCidPortalDecryptMapIndex(meta.slot, 0);
      bool decryptUpdated = false;
      ingressProgram.openMap("quic_cid_dec"_ctv, [&](int mapFD) -> void {
        decryptUpdated = mapFD >= 0 && bpf_map_update_elem(mapFD, &decryptIndex, &aesState, BPF_ANY) == 0;
      });
      suite.expect(decryptUpdated,
                   "switchboard_host_ingress_decapped_ipv4_quic_portal_installs_decrypt_state");

      uint8_t outerSrc[16] = {0xfd, 0x00, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a};
      uint8_t outerDst[16] = {0xfd, 0x00, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b};
      suite.expect(installOverlayIngressPeerIPv6(ingressProgram, outerSrc, outerDst),
                   "switchboard_host_ingress_decapped_ipv4_quic_portal_authorizes_exact_overlay_peer");
      std::vector<uint8_t> frame = makeUDPv4QuicInIPv6EthernetFrame(outerSrc,
                                                                    outerDst,
                                                                    clientAddress,
                                                                    externalAddress,
                                                                    49'152,
                                                                    443,
                                                                    cid);
      std::vector<uint8_t> output(frame.size());
      LIBBPF_OPTS(bpf_test_run_opts, opts,
                  .data_in = frame.data(),
                  .data_out = output.data(),
                  .data_size_in = static_cast<__u32>(frame.size()),
                  .data_size_out = static_cast<__u32>(output.size()),
                  .repeat = 1, );

      int runResult = bpf_prog_test_run_opts(ingressProgram.prog_fd, &opts);
      suite.expect(runResult == 0,
                   "switchboard_host_ingress_decapped_ipv4_quic_portal_test_run_succeeds");
      suite.expect(opts.retval == TC_ACT_REDIRECT,
                   "switchboard_host_ingress_decapped_ipv4_quic_portal_redirects_to_container");
      suite.expect(opts.data_size_out == (frame.size() - sizeof(struct ipv6hdr)),
                   "switchboard_host_ingress_decapped_ipv4_quic_portal_decaps_outer_ipv6_before_redirect");

      if (runResult == 0 && opts.data_size_out >= sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
      {
        const struct ethhdr *outEth = reinterpret_cast<const struct ethhdr *>(output.data());
        const struct iphdr *outIP = reinterpret_cast<const struct iphdr *>(output.data() + sizeof(struct ethhdr));
        const struct udphdr *outUDP = reinterpret_cast<const struct udphdr *>(outIP + 1);
        suite.expect(outEth->h_proto == htons(ETH_P_IP),
                     "switchboard_host_ingress_decapped_ipv4_quic_portal_preserves_ipv4_ethertype");
        suite.expect(outIP->daddr == externalAddress.s_addr,
                     "switchboard_host_ingress_decapped_ipv4_quic_portal_preserves_external_destination");
        suite.expect(outUDP->dest == targetPort,
                     "switchboard_host_ingress_decapped_ipv4_quic_portal_rewrites_container_port");
      }

      ingressProgram.close();
    }
  }

  {
    String ingressObjectPath = {};
    ingressObjectPath.assign(PRODIGY_TEST_BINARY_DIR);
    ingressObjectPath.append("/host.ingress.router.ebpf.o"_ctv);

    BPFProgram ingressProgram = {};
    suite.expect(ingressProgram.load(ingressObjectPath, "host_ingress"_ctv),
                 "switchboard_host_ingress_overlay_local_delivery_loads_host_ingress_program");

    if (ingressProgram.prog_fd >= 0)
    {
      local_container_subnet6 localSubnet = {};
      localSubnet.dpfx = 0x01;
      localSubnet.mpfx[0] = 0x6e;
      localSubnet.mpfx[1] = 0xa2;
      localSubnet.mpfx[2] = 0x7b;
      ingressProgram.setArrayElement("lc_subnet"_ctv, 0, localSubnet);

      uint32_t redirectIfidx = 77;
      ingressProgram.setArrayElement("ct_dev_map"_ctv, 0x7e, redirectIfidx);

      uint8_t outerSrc[16] = {0xfd, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b};
      uint8_t outerDst[16] = {0xfd, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c};
      uint8_t innerSrc[16] = {};
      uint8_t innerDst[16] = {};
      makeContainerIPv6(innerSrc, 0x01, 0x16, 0x25, 0x5b, 0x09);
      makeContainerIPv6(innerDst, 0x01, localSubnet.mpfx[0], localSubnet.mpfx[1], localSubnet.mpfx[2], 0x7e);
      suite.expect(installOverlayIngressPeerIPv6(ingressProgram, outerSrc, outerDst),
                   "switchboard_host_ingress_overlay_local_delivery_authorizes_exact_overlay_peer");

      std::vector<uint8_t> frame = makeIPv6InIPv6EthernetFrame(outerSrc, outerDst, innerSrc, innerDst);
      std::vector<uint8_t> output(frame.size());
      LIBBPF_OPTS(bpf_test_run_opts, opts,
                  .data_in = frame.data(),
                  .data_out = output.data(),
                  .data_size_in = static_cast<__u32>(frame.size()),
                  .data_size_out = static_cast<__u32>(output.size()),
                  .repeat = 1, );

      int runResult = bpf_prog_test_run_opts(ingressProgram.prog_fd, &opts);
      suite.expect(runResult == 0, "switchboard_host_ingress_overlay_local_delivery_test_run_succeeds");
      suite.expect(opts.retval == TC_ACT_REDIRECT,
                   "switchboard_host_ingress_overlay_local_delivery_redirects_to_container");
      suite.expect(opts.data_size_out == (frame.size() - sizeof(struct ipv6hdr)),
                   "switchboard_host_ingress_overlay_local_delivery_decaps_outer_ipv6_before_redirect");

      if (runResult == 0 && opts.data_size_out >= (sizeof(struct ethhdr) + sizeof(struct ipv6hdr)))
      {
        const struct ethhdr *outEth = reinterpret_cast<const struct ethhdr *>(output.data());
        suite.expect(outEth->h_proto == htons(ETH_P_IPV6),
                     "switchboard_host_ingress_overlay_local_delivery_preserves_inner_ethertype");

        const struct ipv6hdr *outIPv6 = reinterpret_cast<const struct ipv6hdr *>(output.data() + sizeof(struct ethhdr));
        suite.expect(std::memcmp(outIPv6->daddr.s6_addr, innerDst, sizeof(outIPv6->daddr.s6_addr)) == 0,
                     "switchboard_host_ingress_overlay_local_delivery_preserves_inner_ipv6_destination");
        suite.expect(outIPv6->nexthdr == IPPROTO_NONE,
                     "switchboard_host_ingress_overlay_local_delivery_preserves_inner_next_header");
      }

      ingressProgram.close();
    }
  }

  exerciseHostIngressGenericPortal(suite, false, IPPROTO_UDP);
  exerciseHostIngressGenericPortal(suite, false, IPPROTO_TCP);
  exerciseHostIngressGenericPortal(suite, true, IPPROTO_UDP);
  exerciseHostIngressGenericPortal(suite, true, IPPROTO_TCP);
  exerciseHostIngressIPv6TCPPortalBrowserSizedPayload(suite);
  exerciseHostIngressHostedIngressRoute(suite, false, IPPROTO_UDP);
  exerciseHostIngressHostedIngressRoute(suite, false, IPPROTO_TCP);
  exerciseHostIngressHostedIngressRoute(suite, true, IPPROTO_UDP);
  exerciseHostIngressHostedIngressRoute(suite, true, IPPROTO_TCP);
  exerciseHostIngressRemotePortalRoute(suite, false, IPPROTO_UDP, false);
  exerciseHostIngressRemotePortalRoute(suite, false, IPPROTO_TCP, true);
  exerciseHostIngressRemotePortalRoute(suite, true, IPPROTO_UDP, false);
  exerciseHostIngressRemotePortalRoute(suite, true, IPPROTO_TCP, true);
  exerciseBalancerOwnedRoutableMissPassesToKernel(suite);
  exerciseBalancerRemotePortalRoutesWithOverlay(suite);
  exerciseWormholeSharedFlowOwnership(suite);
  exerciseWormholeTCPPromotionMapFull(suite);
  exerciseHostIngressPlainLocalIPv6(suite, IPPROTO_UDP);
  exerciseHostIngressPlainLocalIPv6(suite, IPPROTO_TCP);
  {
    String ingressObjectPath = {};
    ingressObjectPath.assign(PRODIGY_TEST_BINARY_DIR);
    ingressObjectPath.append("/host.ingress.router.ebpf.o"_ctv);

    BPFProgram ingressProgram = {};
    suite.expect(ingressProgram.load(ingressObjectPath, "host_ingress"_ctv),
                 "switchboard_host_ingress_overlay_local_delivery_live_packet_loads_host_ingress_program");

    if (ingressProgram.prog_fd >= 0)
    {
      local_container_subnet6 localSubnet = {};
      localSubnet.dpfx = 0x01;
      localSubnet.mpfx[0] = 0x52;
      localSubnet.mpfx[1] = 0xdf;
      localSubnet.mpfx[2] = 0x39;
      ingressProgram.setArrayElement("lc_subnet"_ctv, 0, localSubnet);

      uint32_t redirectIfidx = 7;
      ingressProgram.setArrayElement("ct_dev_map"_ctv, 0x4e, redirectIfidx);

      uint8_t outerSrc[16] = {0xfd, 0x00, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a};
      uint8_t outerDst[16] = {0xfd, 0x00, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b};
      uint8_t innerSrc[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0xac, 0xbe, 0xa0, 0xd2};
      uint8_t innerDst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x52, 0xdf, 0x39, 0x4e};
      suite.expect(installOverlayIngressPeerIPv6(ingressProgram, outerSrc, outerDst),
                   "switchboard_host_ingress_overlay_local_delivery_live_packet_authorizes_exact_overlay_peer");

      std::vector<uint8_t> frame = makeICMPv6InIPv6EthernetFrame(outerSrc, outerDst, innerSrc, innerDst);
      std::vector<uint8_t> output(frame.size());
      LIBBPF_OPTS(bpf_test_run_opts, opts,
                  .data_in = frame.data(),
                  .data_out = output.data(),
                  .data_size_in = static_cast<__u32>(frame.size()),
                  .data_size_out = static_cast<__u32>(output.size()),
                  .repeat = 1, );

      int runResult = bpf_prog_test_run_opts(ingressProgram.prog_fd, &opts);
      suite.expect(runResult == 0, "switchboard_host_ingress_overlay_local_delivery_live_packet_test_run_succeeds");
      suite.expect(opts.retval == TC_ACT_REDIRECT,
                   "switchboard_host_ingress_overlay_local_delivery_live_packet_redirects_to_container");
      suite.expect(opts.data_size_out == (frame.size() - sizeof(struct ipv6hdr)),
                   "switchboard_host_ingress_overlay_local_delivery_live_packet_decaps_outer_ipv6_before_redirect");

      if (runResult == 0 && opts.data_size_out >= (sizeof(struct ethhdr) + sizeof(struct ipv6hdr)))
      {
        const struct ethhdr *outEth = reinterpret_cast<const struct ethhdr *>(output.data());
        suite.expect(outEth->h_proto == htons(ETH_P_IPV6),
                     "switchboard_host_ingress_overlay_local_delivery_live_packet_preserves_inner_ethertype");

        const struct ipv6hdr *outIPv6 = reinterpret_cast<const struct ipv6hdr *>(output.data() + sizeof(struct ethhdr));
        suite.expect(std::memcmp(outIPv6->daddr.s6_addr, innerDst, sizeof(outIPv6->daddr.s6_addr)) == 0,
                     "switchboard_host_ingress_overlay_local_delivery_live_packet_preserves_inner_ipv6_destination");
        suite.expect(outIPv6->nexthdr == IPPROTO_ICMPV6,
                     "switchboard_host_ingress_overlay_local_delivery_live_packet_preserves_inner_next_header");
      }

      ingressProgram.close();
    }
  }

  {
    String ingressObjectPath = {};
    ingressObjectPath.assign(PRODIGY_TEST_BINARY_DIR);
    ingressObjectPath.append("/container.ingress.router.ebpf.o"_ctv);

    BPFProgram ingressProgram = {};
    suite.expect(ingressProgram.load(ingressObjectPath, "ct_ingress"_ctv),
                 "switchboard_container_ingress_overlay_delivery_loads_program");

    if (ingressProgram.prog_fd >= 0)
    {
      container_network_policy networkPolicy = {};
      networkPolicy.mode = CONTAINER_NETWORK_UNRESTRICTED;
      ingressProgram.setArrayElement("ct_net_policy"_ctv, 0, networkPolicy);

      uint8_t outerSrc[16] = {0xfd, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b};
      uint8_t outerDst[16] = {0xfd, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c};
      uint8_t innerSrc[16] = {};
      uint8_t innerDst[16] = {};
      makeContainerIPv6(innerSrc, 0x01, 0x16, 0x25, 0x5b, 0x09);
      makeContainerIPv6(innerDst, 0x01, 0x6e, 0xa2, 0x7b, 0x7e);

      std::vector<uint8_t> frame = makeIPv6InIPv6EthernetFrame(outerSrc, outerDst, innerSrc, innerDst);
      std::vector<uint8_t> output(frame.size());
      LIBBPF_OPTS(bpf_test_run_opts, opts,
                  .data_in = frame.data(),
                  .data_out = output.data(),
                  .data_size_in = static_cast<__u32>(frame.size()),
                  .data_size_out = static_cast<__u32>(output.size()),
                  .repeat = 1, );

      int runResult = bpf_prog_test_run_opts(ingressProgram.prog_fd, &opts);
      suite.expect(runResult == 0, "switchboard_container_ingress_overlay_delivery_test_run_succeeds");
      suite.expect(opts.retval == 0, "switchboard_container_ingress_overlay_delivery_passes_inner_packet");
      suite.expect(opts.data_size_out == (frame.size() - sizeof(struct ipv6hdr)),
                   "switchboard_container_ingress_overlay_delivery_decaps_outer_ipv6");

      if (runResult == 0 && opts.data_size_out >= (sizeof(struct ethhdr) + sizeof(struct ipv6hdr)))
      {
        const struct ethhdr *outEth = reinterpret_cast<const struct ethhdr *>(output.data());
        const struct ipv6hdr *outIPv6 = reinterpret_cast<const struct ipv6hdr *>(output.data() + sizeof(struct ethhdr));
        suite.expect(outEth->h_proto == htons(ETH_P_IPV6),
                     "switchboard_container_ingress_overlay_delivery_preserves_inner_ethertype");
        suite.expect(std::memcmp(outIPv6->daddr.s6_addr, innerDst, sizeof(outIPv6->daddr.s6_addr)) == 0,
                     "switchboard_container_ingress_overlay_delivery_preserves_inner_ipv6_destination");
        suite.expect(outIPv6->nexthdr == IPPROTO_NONE,
                     "switchboard_container_ingress_overlay_delivery_preserves_inner_next_header");
      }

      ingressProgram.close();
    }
  }

  suite.expect((switchboardPacketRewriteStoreFlags() & BPF_F_RECOMPUTE_CSUM) != 0, "switchboard_packet_rewrite_store_flags_recompute_checksum");
  suite.expect((switchboardPacketRewriteStoreFlags() & BPF_F_INVALIDATE_HASH) != 0, "switchboard_packet_rewrite_store_flags_invalidate_hash");
  suite.expect((switchboardAdjustRoomPreserveOffloadFlags() & BPF_F_ADJ_ROOM_NO_CSUM_RESET) != 0, "switchboard_adjust_room_preserves_checksum_offload");
  suite.expect((switchboardAdjustRoomPreserveOffloadFlags() & BPF_F_ADJ_ROOM_FIXED_GSO) != 0, "switchboard_adjust_room_preserves_gso");
  suite.expect((switchboardOverlayEncapAdjustRoomFlagsIPv6() & BPF_F_ADJ_ROOM_ENCAP_L3_IPV6) != 0, "switchboard_overlay_encap_ipv6_sets_l3_flag");
  suite.expect((switchboardOverlayEncapAdjustRoomFlagsIPv6() & BPF_F_ADJ_ROOM_NO_CSUM_RESET) != 0, "switchboard_overlay_encap_ipv6_preserves_checksum_offload");
  suite.expect((switchboardOverlayEncapAdjustRoomFlagsIPv6() & BPF_F_ADJ_ROOM_FIXED_GSO) == 0, "switchboard_overlay_encap_ipv6_clears_gso");
  suite.expect((switchboardOverlayEncapAdjustRoomFlagsIPv4() & BPF_F_ADJ_ROOM_ENCAP_L3_IPV4) != 0, "switchboard_overlay_encap_ipv4_sets_l3_flag");
  suite.expect((switchboardOverlayEncapAdjustRoomFlagsIPv4() & BPF_F_ADJ_ROOM_NO_CSUM_RESET) != 0, "switchboard_overlay_encap_ipv4_preserves_checksum_offload");
  suite.expect((switchboardOverlayEncapAdjustRoomFlagsIPv4() & BPF_F_ADJ_ROOM_FIXED_GSO) == 0, "switchboard_overlay_encap_ipv4_clears_gso");

  {
    uint8_t wormholeSource[16] = {};
    std::memcpy(wormholeSource, container_network_subnet6.value, sizeof(container_network_subnet6.value));
    wormholeSource[11] = 0x7a;
    wormholeSource[12] = 0x01;
    wormholeSource[13] = 0x02;
    wormholeSource[14] = 0x03;
    wormholeSource[15] = 0x11;

    uint8_t internalDestination[16] = {};
    std::memcpy(internalDestination, container_network_subnet6.value, sizeof(container_network_subnet6.value));
    internalDestination[11] = 0x7a;
    internalDestination[12] = 0x01;
    internalDestination[13] = 0x02;
    internalDestination[14] = 0x03;
    internalDestination[15] = 0x22;

    uint8_t remoteMachineDestination[16] = {};
    std::memcpy(remoteMachineDestination, container_network_subnet6.value, sizeof(container_network_subnet6.value));
    remoteMachineDestination[11] = 0x7a;
    remoteMachineDestination[12] = 0x09;
    remoteMachineDestination[13] = 0x08;
    remoteMachineDestination[14] = 0x07;
    remoteMachineDestination[15] = 0x33;

    local_container_subnet6 localSubnet = {};
    localSubnet.dpfx = 0x7a;
    localSubnet.mpfx[0] = 0x01;
    localSubnet.mpfx[1] = 0x02;
    localSubnet.mpfx[2] = 0x03;

    uint8_t externalDestination[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77};
    uint8_t externalSource[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x44};

    suite.expect(switchboardWormholeSourceRewriteEligibleIPv6(wormholeSource, internalDestination), "switchboard_wormhole_rewrite_allows_internal_destination");
    suite.expect(switchboardContainerIPv6TargetsLocalMachine(internalDestination, &localSubnet), "switchboard_wormhole_rewrite_internal_destination_is_same_machine");
    suite.expect(switchboardContainerIPv6TargetsRemoteMachine(remoteMachineDestination, &localSubnet), "switchboard_wormhole_rewrite_remote_destination_is_other_machine");
    suite.expect(switchboardWormholeSourceRewriteEligibleIPv6(wormholeSource, remoteMachineDestination), "switchboard_wormhole_rewrite_allows_remote_machine_container_destination");
    suite.expect(switchboardWormholeSourceRewriteEligibleIPv6(wormholeSource, externalDestination), "switchboard_wormhole_rewrite_allows_external_destination");
    suite.expect(switchboardWormholeSourceRewriteEligibleIPv6(externalSource, internalDestination) == false, "switchboard_wormhole_rewrite_rejects_non_container_source");
  }

  {
    uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0, 0, 0, 0x0b};
    uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x84, 0x43};
    uint8_t rewrittenSrc[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0xb1, 0x31, 0xc7, 0xcb};
    uint8_t payload[8] = {'w', 'o', 'r', 'm', 'h', 'o', 'l', 'e'};

    struct udphdr udp = {};
    udp.source = htons(8443);
    udp.dest = htons(35'076);
    udp.len = htons(sizeof(udp) + sizeof(payload));

    uint8_t udpSegment[sizeof(udp) + sizeof(payload)] = {};
    memcpy(udpSegment, &udp, sizeof(udp));
    memcpy(udpSegment + sizeof(udp), payload, sizeof(payload));
    reinterpret_cast<struct udphdr *>(udpSegment)->check = htons(checksumIPv6Transport(src, dst, IPPROTO_UDP, udpSegment, sizeof(udpSegment)));

    struct udphdr updatedUDP = *reinterpret_cast<struct udphdr *>(udpSegment);
    uint16_t originalUDPChecksum = updatedUDP.check;
    uint16_t rewrittenUDPPort = htons(443);
    updatedUDP.check = replace_l4_checksum_word16(updatedUDP.check, updatedUDP.source, rewrittenUDPPort);
    updatedUDP.check = replaceChecksumIPv6AddressIncremental(updatedUDP.check, src, rewrittenSrc);
    updatedUDP.source = rewrittenUDPPort;

    uint8_t expectedUDPSegment[sizeof(updatedUDP) + sizeof(payload)] = {};
    memcpy(expectedUDPSegment, &updatedUDP, sizeof(updatedUDP));
    memcpy(expectedUDPSegment + sizeof(updatedUDP), payload, sizeof(payload));
    reinterpret_cast<struct udphdr *>(expectedUDPSegment)->check = 0;
    uint16_t expectedUDPChecksum = htons(checksumIPv6Transport(rewrittenSrc, dst, IPPROTO_UDP, expectedUDPSegment, sizeof(expectedUDPSegment)));

    suite.expect(originalUDPChecksum != expectedUDPChecksum, "switchboard_wormhole_udp_source_rewrite_changes_checksum");
    suite.expect(updatedUDP.check == expectedUDPChecksum, "switchboard_wormhole_udp_source_rewrite_matches_full_checksum");
  }

  {
    uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0, 0, 0, 0x0b};
    uint8_t dst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x6e, 0x1f, 0xdd, 0x55};
    uint8_t rewrittenSrc[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc};

    constexpr size_t payloadSize = 2037;
    std::vector<uint8_t> payload(payloadSize);
    for (size_t index = 0; index < payload.size(); index += 1)
    {
      payload[index] = static_cast<uint8_t>((index * 37u + 11u) & 0xffu);
    }

    struct udphdr udp = {};
    udp.source = htons(8443);
    udp.dest = htons(34'267);
    udp.len = htons(sizeof(udp) + payload.size());

    std::vector<uint8_t> udpSegment(sizeof(udp) + payload.size());
    std::memcpy(udpSegment.data(), &udp, sizeof(udp));
    std::memcpy(udpSegment.data() + sizeof(udp), payload.data(), payload.size());
    reinterpret_cast<struct udphdr *>(udpSegment.data())->check = htons(checksumIPv6Transport(src, dst, IPPROTO_UDP, udpSegment.data(), udpSegment.size()));

    struct udphdr updatedUDP = *reinterpret_cast<struct udphdr *>(udpSegment.data());
    uint16_t originalUDPChecksum = updatedUDP.check;
    uint16_t rewrittenUDPPort = htons(443);
    updatedUDP.check = replace_l4_checksum_word16(updatedUDP.check, updatedUDP.source, rewrittenUDPPort);
    updatedUDP.check = replaceChecksumIPv6AddressIncremental(updatedUDP.check, src, rewrittenSrc);
    updatedUDP.source = rewrittenUDPPort;

    std::vector<uint8_t> expectedUDPSegment(sizeof(updatedUDP) + payload.size());
    std::memcpy(expectedUDPSegment.data(), &updatedUDP, sizeof(updatedUDP));
    std::memcpy(expectedUDPSegment.data() + sizeof(updatedUDP), payload.data(), payload.size());
    reinterpret_cast<struct udphdr *>(expectedUDPSegment.data())->check = 0;
    uint16_t expectedUDPChecksum = htons(checksumIPv6Transport(rewrittenSrc, dst, IPPROTO_UDP, expectedUDPSegment.data(), expectedUDPSegment.size()));

    suite.expect(originalUDPChecksum != expectedUDPChecksum, "switchboard_wormhole_udp_large_source_rewrite_changes_checksum");
    suite.expect(updatedUDP.check == expectedUDPChecksum, "switchboard_wormhole_udp_large_source_rewrite_matches_full_checksum");
  }

  {
    uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x44};
    uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0, 0, 0, 0x0b};
    uint8_t rewrittenDst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x01, 0x1f, 0x63, 0x5b};
    uint8_t payload[8] = {'i', 'n', 'g', 'r', 'e', 's', 's', '!'};

    struct udphdr udp = {};
    udp.source = htons(51'515);
    udp.dest = htons(443);
    udp.len = htons(sizeof(udp) + sizeof(payload));

    uint8_t udpSegment[sizeof(udp) + sizeof(payload)] = {};
    memcpy(udpSegment, &udp, sizeof(udp));
    memcpy(udpSegment + sizeof(udp), payload, sizeof(payload));
    reinterpret_cast<struct udphdr *>(udpSegment)->check = htons(checksumIPv6Transport(src, dst, IPPROTO_UDP, udpSegment, sizeof(udpSegment)));

    struct udphdr updatedUDP = *reinterpret_cast<struct udphdr *>(udpSegment);
    uint16_t originalUDPChecksum = updatedUDP.check;
    updatedUDP.check = replaceChecksumIPv6AddressIncremental(updatedUDP.check, dst, rewrittenDst);
    updatedUDP.check = replace_l4_checksum_word16(updatedUDP.check, updatedUDP.dest, htons(8443));
    updatedUDP.dest = htons(8443);

    uint8_t expectedUDPSegment[sizeof(updatedUDP) + sizeof(payload)] = {};
    memcpy(expectedUDPSegment, &updatedUDP, sizeof(updatedUDP));
    memcpy(expectedUDPSegment + sizeof(updatedUDP), payload, sizeof(payload));
    reinterpret_cast<struct udphdr *>(expectedUDPSegment)->check = 0;
    uint16_t expectedUDPChecksum = htons(checksumIPv6Transport(src, rewrittenDst, IPPROTO_UDP, expectedUDPSegment, sizeof(expectedUDPSegment)));

    suite.expect(originalUDPChecksum != expectedUDPChecksum, "switchboard_wormhole_udp_ipv6_target_rewrite_changes_checksum");
    suite.expect(updatedUDP.check == expectedUDPChecksum, "switchboard_wormhole_udp_ipv6_target_rewrite_matches_full_checksum");
  }

  {
    uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77};
    uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x19, 0x84};

    struct tcphdr tcp = {};
    tcp.source = htons(8443);
    tcp.dest = htons(50'000);
    tcp.seq = htonl(0x11223344);
    tcp.ack_seq = htonl(0x55667788);
    tcp.doff = sizeof(tcp) / 4;
    tcp.syn = 1;
    tcp.ack = 1;
    tcp.window = htons(4096);

    uint8_t tcpSegment[sizeof(tcp)] = {};
    memcpy(tcpSegment, &tcp, sizeof(tcp));
    reinterpret_cast<struct tcphdr *>(tcpSegment)->check = htons(checksumIPv6Transport(src, dst, IPPROTO_TCP, tcpSegment, sizeof(tcpSegment)));

    struct tcphdr updatedTCP = *reinterpret_cast<struct tcphdr *>(tcpSegment);
    uint16_t originalTCPChecksum = updatedTCP.check;
    uint16_t rewrittenTCPPort = htons(443);
    updatedTCP.check = replace_l4_checksum_word16(updatedTCP.check, updatedTCP.source, rewrittenTCPPort);
    updatedTCP.source = rewrittenTCPPort;

    uint8_t expectedTCPSegment[sizeof(updatedTCP)] = {};
    memcpy(expectedTCPSegment, &updatedTCP, sizeof(updatedTCP));
    reinterpret_cast<struct tcphdr *>(expectedTCPSegment)->check = 0;
    uint16_t expectedTCPChecksum = htons(checksumIPv6Transport(src, dst, IPPROTO_TCP, expectedTCPSegment, sizeof(expectedTCPSegment)));

    suite.expect(originalTCPChecksum != expectedTCPChecksum, "switchboard_wormhole_tcp_port_rewrite_changes_checksum");
    suite.expect(updatedTCP.check == expectedTCPChecksum, "switchboard_wormhole_tcp_port_rewrite_matches_full_checksum");
  }

  {
    uint8_t src[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x01, 0x1f, 0x63, 0x5b};
    uint8_t rewrittenSrc[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0, 0, 0, 0x0b};
    uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77};

    struct tcphdr tcp = {};
    tcp.source = htons(8443);
    tcp.dest = htons(50'000);
    tcp.seq = htonl(0x11223344);
    tcp.ack_seq = htonl(0x55667788);
    tcp.doff = sizeof(tcp) / 4;
    tcp.syn = 1;
    tcp.ack = 1;
    tcp.window = htons(4096);

    uint8_t tcpSegment[sizeof(tcp)] = {};
    memcpy(tcpSegment, &tcp, sizeof(tcp));
    reinterpret_cast<struct tcphdr *>(tcpSegment)->check = htons(checksumIPv6Transport(src, dst, IPPROTO_TCP, tcpSegment, sizeof(tcpSegment)));

    struct tcphdr updatedTCP = *reinterpret_cast<struct tcphdr *>(tcpSegment);
    uint16_t originalTCPChecksum = updatedTCP.check;
    updatedTCP.check = replace_l4_checksum_portable(updatedTCP.check, src, rewrittenSrc, sizeof(rewrittenSrc));
    updatedTCP.check = replace_l4_checksum_word16(updatedTCP.check, updatedTCP.source, htons(443));
    updatedTCP.source = htons(443);

    uint8_t expectedTCPSegment[sizeof(updatedTCP)] = {};
    memcpy(expectedTCPSegment, &updatedTCP, sizeof(updatedTCP));
    reinterpret_cast<struct tcphdr *>(expectedTCPSegment)->check = 0;
    uint16_t expectedTCPChecksum = htons(checksumIPv6Transport(rewrittenSrc, dst, IPPROTO_TCP, expectedTCPSegment, sizeof(expectedTCPSegment)));

    suite.expect(originalTCPChecksum != expectedTCPChecksum, "switchboard_wormhole_tcp_ipv6_source_rewrite_changes_checksum");
    suite.expect(updatedTCP.check == expectedTCPChecksum, "switchboard_wormhole_tcp_ipv6_source_rewrite_matches_full_checksum");
  }

  {
    uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x44};
    uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0, 0, 0, 0x0b};
    uint8_t rewrittenDst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x01, 0x1f, 0x63, 0x5b};
    uint8_t payload[12] = {'p', 'a', 'r', 't', 'i', 'a', 'l', '-', 'u', 'd', 'p', '!'};

    struct udphdr udp = {};
    udp.source = htons(51'515);
    udp.dest = htons(443);
    udp.len = htons(sizeof(udp) + sizeof(payload));
    udp.check = 0;

    uint8_t rewrittenSegment[sizeof(udp) + sizeof(payload)] = {};
    memcpy(rewrittenSegment, &udp, sizeof(udp));
    memcpy(rewrittenSegment + sizeof(udp), payload, sizeof(payload));
    reinterpret_cast<struct udphdr *>(rewrittenSegment)->check =
        htons(checksumIPv6Transport(src, dst, IPPROTO_UDP, rewrittenSegment, sizeof(rewrittenSegment)));
    reinterpret_cast<struct udphdr *>(rewrittenSegment)->dest = htons(8443);

    uint8_t expectedSegment[sizeof(rewrittenSegment)] = {};
    memcpy(expectedSegment, rewrittenSegment, sizeof(expectedSegment));
    reinterpret_cast<struct udphdr *>(expectedSegment)->check = 0;
    uint16_t expectedChecksum = htons(checksumIPv6Transport(src, rewrittenDst, IPPROTO_UDP, expectedSegment, sizeof(expectedSegment)));

    struct udphdr incremental = *reinterpret_cast<struct udphdr *>(rewrittenSegment);
    incremental.check = replace_l4_checksum_portable(incremental.check, dst, rewrittenDst, sizeof(rewrittenDst));
    incremental.check = replace_l4_checksum_word16(incremental.check, htons(443), htons(8443));

    suite.expect(incremental.check == expectedChecksum, "switchboard_wormhole_udp_incremental_rewrite_matches_expected_checksum");
  }

  {
    uint8_t rewrittenSrc[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0, 0, 0, 0x0b};
    uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77};
    uint8_t src[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x01, 0x1f, 0x63, 0x5b};

    struct tcphdr tcp = {};
    tcp.source = htons(8443);
    tcp.dest = htons(50'000);
    tcp.seq = htonl(0xCAFEBABEu);
    tcp.ack_seq = htonl(0x10203040u);
    tcp.doff = sizeof(tcp) / 4;
    tcp.syn = 1;
    tcp.window = htons(8192);
    tcp.check = 0;

    uint8_t rewrittenSegment[sizeof(tcp)] = {};
    memcpy(rewrittenSegment, &tcp, sizeof(tcp));
    reinterpret_cast<struct tcphdr *>(rewrittenSegment)->check =
        htons(checksumIPv6Transport(src, dst, IPPROTO_TCP, rewrittenSegment, sizeof(rewrittenSegment)));
    reinterpret_cast<struct tcphdr *>(rewrittenSegment)->source = htons(443);

    uint8_t expectedSegment[sizeof(rewrittenSegment)] = {};
    memcpy(expectedSegment, rewrittenSegment, sizeof(expectedSegment));
    reinterpret_cast<struct tcphdr *>(expectedSegment)->check = 0;
    uint16_t expectedChecksum = htons(checksumIPv6Transport(rewrittenSrc, dst, IPPROTO_TCP, expectedSegment, sizeof(expectedSegment)));

    struct tcphdr incremental = *reinterpret_cast<struct tcphdr *>(rewrittenSegment);
    incremental.check = replace_l4_checksum_portable(incremental.check, src, rewrittenSrc, sizeof(rewrittenSrc));
    incremental.check = replace_l4_checksum_word16(incremental.check, htons(8443), htons(443));

    suite.expect(incremental.check == expectedChecksum, "switchboard_wormhole_tcp_incremental_rewrite_matches_expected_checksum");
  }

  {
    uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
    uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b};
    uint8_t rewrittenDst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x12, 0xc3, 0x87, 0x62};
    std::array<uint8_t, 1232> payload = {};

    for (size_t index = 0; index < payload.size(); ++index)
    {
      payload[index] = static_cast<uint8_t>((index * 17u + 3u) & 0xffu);
    }

    struct udphdr udp = {};
    udp.source = htons(47'957);
    udp.dest = htons(443);
    udp.len = htons(sizeof(udp) + payload.size());

    std::array<uint8_t, sizeof(udp) + payload.size()> originalSegment = {};
    memcpy(originalSegment.data(), &udp, sizeof(udp));
    memcpy(originalSegment.data() + sizeof(udp), payload.data(), payload.size());
    reinterpret_cast<struct udphdr *>(originalSegment.data())->check = htons(checksumIPv6Transport(
        src,
        dst,
        IPPROTO_UDP,
        originalSegment.data(),
        originalSegment.size()));

    std::array<uint8_t, originalSegment.size()> rewrittenSegment = originalSegment;
    reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->dest = htons(8443);

    std::array<uint8_t, originalSegment.size()> expectedSegment = rewrittenSegment;
    reinterpret_cast<struct udphdr *>(expectedSegment.data())->check = 0;
    uint16_t expectedChecksum = htons(checksumIPv6Transport(
        src,
        rewrittenDst,
        IPPROTO_UDP,
        expectedSegment.data(),
        expectedSegment.size()));

    struct udphdr incremental = *reinterpret_cast<const struct udphdr *>(originalSegment.data());
    incremental.check = replace_l4_checksum_portable(incremental.check, dst, rewrittenDst, sizeof(rewrittenDst));
    incremental.check = replace_l4_checksum_word16(incremental.check, htons(443), htons(8443));
    suite.expect(incremental.check == expectedChecksum, "switchboard_wormhole_udp_quic_portal_incremental_rewrite_matches_expected_checksum");
  }

  {
    uint8_t rewrittenSrc[16] = {0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b};
    uint8_t dst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x9e, 0x98, 0xca, 0xc3};
    uint8_t src[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0xcc, 0x5a, 0xb2, 0x89};
    std::array<uint8_t, 2037> payload = {};

    for (size_t index = 0; index < payload.size(); ++index)
    {
      payload[index] = static_cast<uint8_t>((index * 13u + 7u) & 0xffu);
    }

    struct udphdr udp = {};
    udp.source = htons(8443);
    udp.dest = htons(42'264);
    udp.len = htons(sizeof(udp) + payload.size());
    udp.check = 0;

    std::array<uint8_t, sizeof(udp) + payload.size()> rewrittenSegment = {};
    memcpy(rewrittenSegment.data(), &udp, sizeof(udp));
    memcpy(rewrittenSegment.data() + sizeof(udp), payload.data(), payload.size());
    reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->check = htons(checksumIPv6Transport(
        src, dst, IPPROTO_UDP, rewrittenSegment.data(), rewrittenSegment.size()));
    reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->source = htons(443);

    std::array<uint8_t, rewrittenSegment.size()> expectedSegment = rewrittenSegment;
    reinterpret_cast<struct udphdr *>(expectedSegment.data())->check = 0;
    uint16_t expectedChecksum = htons(checksumIPv6Transport(
        rewrittenSrc,
        dst,
        IPPROTO_UDP,
        expectedSegment.data(),
        expectedSegment.size()));

    struct udphdr incremental = *reinterpret_cast<const struct udphdr *>(rewrittenSegment.data());
    incremental.check = replace_l4_checksum_portable(incremental.check, src, rewrittenSrc, sizeof(rewrittenSrc));
    incremental.check = replace_l4_checksum_word16(incremental.check, htons(8443), htons(443));

    suite.expect(rewrittenSegment.size() == 2045u, "switchboard_wormhole_udp_quic_source_rewrite_segment_size_matches_live_path");
    suite.expect(incremental.check == expectedChecksum, "switchboard_wormhole_udp_quic_source_incremental_rewrite_matches_expected_checksum");
  }

  {
    uint8_t rewrittenSrc[16] = {0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a};
    uint8_t dst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0xda, 0x7b, 0xae, 0x2c};
    uint8_t src[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x8e, 0xdc, 0x41, 0x3a};
    std::array<uint8_t, 2035> payload = {};

    for (size_t index = 0; index < payload.size(); ++index)
    {
      payload[index] = static_cast<uint8_t>((index * 13u + 31u) & 0xffu);
    }

    struct udphdr udp = {};
    udp.source = htons(8443);
    udp.dest = htons(35'644);
    udp.len = htons(sizeof(udp) + payload.size());
    udp.check = 0;

    std::array<uint8_t, sizeof(udp) + payload.size()> rewrittenSegment = {};
    memcpy(rewrittenSegment.data(), &udp, sizeof(udp));
    memcpy(rewrittenSegment.data() + sizeof(udp), payload.data(), payload.size());
    reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->check = htons(checksumIPv6Transport(
        src, dst, IPPROTO_UDP, rewrittenSegment.data(), rewrittenSegment.size()));
    reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->source = htons(443);

    std::array<uint8_t, rewrittenSegment.size()> expectedSegment = rewrittenSegment;
    reinterpret_cast<struct udphdr *>(expectedSegment.data())->check = 0;
    uint16_t expectedChecksum = htons(checksumIPv6Transport(
        rewrittenSrc,
        dst,
        IPPROTO_UDP,
        expectedSegment.data(),
        expectedSegment.size()));

    struct udphdr incremental = *reinterpret_cast<const struct udphdr *>(rewrittenSegment.data());
    incremental.check = replace_l4_checksum_portable(incremental.check, src, rewrittenSrc, sizeof(rewrittenSrc));
    incremental.check = replace_l4_checksum_word16(incremental.check, htons(8443), htons(443));

    suite.expect(rewrittenSegment.size() == 2043u, "switchboard_wormhole_udp_quic_source_rewrite_application_reply_segment_size_matches_capture");
    suite.expect(incremental.check == expectedChecksum, "switchboard_wormhole_udp_quic_source_incremental_rewrite_matches_application_reply_capture");
  }

  {
    uint8_t rewrittenSrc[16] = {0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b};
    uint8_t dst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0xa8, 0xe8, 0x59, 0x6f};
    uint8_t src[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x71, 0x1f, 0x40, 0x89};
    std::array<uint8_t, 2042> payload = {};

    for (size_t index = 0; index < payload.size(); ++index)
    {
      payload[index] = static_cast<uint8_t>((index * 17u + 19u) & 0xffu);
    }

    struct udphdr udp = {};
    udp.source = htons(8443);
    udp.dest = htons(52'262);
    udp.len = htons(sizeof(udp) + payload.size());
    udp.check = 0;

    std::array<uint8_t, sizeof(udp) + payload.size()> rewrittenSegment = {};
    memcpy(rewrittenSegment.data(), &udp, sizeof(udp));
    memcpy(rewrittenSegment.data() + sizeof(udp), payload.data(), payload.size());
    reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->check = htons(checksumIPv6Transport(
        src, dst, IPPROTO_UDP, rewrittenSegment.data(), rewrittenSegment.size()));
    reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->source = htons(443);

    std::array<uint8_t, rewrittenSegment.size()> expectedSegment = rewrittenSegment;
    reinterpret_cast<struct udphdr *>(expectedSegment.data())->check = 0;
    uint16_t expectedChecksum = htons(checksumIPv6Transport(
        rewrittenSrc,
        dst,
        IPPROTO_UDP,
        expectedSegment.data(),
        expectedSegment.size()));

    struct udphdr incremental = *reinterpret_cast<const struct udphdr *>(rewrittenSegment.data());
    incremental.check = replace_l4_checksum_portable(incremental.check, src, rewrittenSrc, sizeof(rewrittenSrc));
    incremental.check = replace_l4_checksum_word16(incremental.check, htons(8443), htons(443));

    suite.expect(rewrittenSegment.size() == 2050u, "switchboard_wormhole_udp_quic_source_rewrite_current_live_segment_size_matches_capture");
    suite.expect(incremental.check == expectedChecksum, "switchboard_wormhole_udp_quic_source_incremental_rewrite_matches_expected_checksum_at_current_live_size");
  }

  {
    uint8_t rewrittenSrc[16] = {0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c};
    uint8_t dst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x69, 0x06, 0x98, 0x73};
    uint8_t src[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x69, 0x06, 0x98, 0xb8};
    std::array<uint8_t, 2041> payload = {};

    for (size_t index = 0; index < payload.size(); ++index)
    {
      payload[index] = static_cast<uint8_t>((index * 19u + 5u) & 0xffu);
    }

    struct udphdr udp = {};
    udp.source = htons(8443);
    udp.dest = htons(33'543);
    udp.len = htons(sizeof(udp) + payload.size());
    udp.check = 0;

    std::array<uint8_t, sizeof(udp) + payload.size()> rewrittenSegment = {};
    memcpy(rewrittenSegment.data(), &udp, sizeof(udp));
    memcpy(rewrittenSegment.data() + sizeof(udp), payload.data(), payload.size());
    reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->check = htons(checksumIPv6Transport(
        src, dst, IPPROTO_UDP, rewrittenSegment.data(), rewrittenSegment.size()));
    reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->source = htons(443);

    std::array<uint8_t, rewrittenSegment.size()> expectedSegment = rewrittenSegment;
    reinterpret_cast<struct udphdr *>(expectedSegment.data())->check = 0;
    uint16_t expectedChecksum = htons(checksumIPv6Transport(
        rewrittenSrc,
        dst,
        IPPROTO_UDP,
        expectedSegment.data(),
        expectedSegment.size()));

    struct udphdr incremental = *reinterpret_cast<const struct udphdr *>(rewrittenSegment.data());
    incremental.check = replace_l4_checksum_portable(incremental.check, src, rewrittenSrc, sizeof(rewrittenSrc));
    incremental.check = replace_l4_checksum_word16(incremental.check, htons(8443), htons(443));

    suite.expect(rewrittenSegment.size() == 2049u, "switchboard_wormhole_udp_quic_source_rewrite_same_machine_public_reply_segment_size_matches_capture");
    suite.expect(incremental.check == expectedChecksum, "switchboard_wormhole_udp_quic_source_incremental_rewrite_matches_same_machine_public_reply_capture");
  }

  {
    uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x21};
    uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x45};
    uint8_t rewrittenDst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x01, 0xa5, 0x77, 0x62};
    std::array<uint8_t, 8192> payload = {};

    for (size_t index = 0; index < payload.size(); ++index)
    {
      payload[index] = static_cast<uint8_t>((index * 29u + 11u) & 0xffu);
    }

    struct udphdr udp = {};
    udp.source = htons(53'001);
    udp.dest = htons(443);
    udp.len = htons(sizeof(udp) + payload.size());

    std::array<uint8_t, sizeof(udp) + payload.size()> rewrittenSegment = {};
    memcpy(rewrittenSegment.data(), &udp, sizeof(udp));
    memcpy(rewrittenSegment.data() + sizeof(udp), payload.data(), payload.size());
    reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->check = htons(checksumIPv6Transport(
        src, dst, IPPROTO_UDP, rewrittenSegment.data(), rewrittenSegment.size()));
    reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->dest = htons(8443);

    std::array<uint8_t, rewrittenSegment.size()> expectedSegment = rewrittenSegment;
    reinterpret_cast<struct udphdr *>(expectedSegment.data())->check = 0;
    uint16_t expectedChecksum = htons(checksumIPv6Transport(
        src,
        rewrittenDst,
        IPPROTO_UDP,
        expectedSegment.data(),
        expectedSegment.size()));

    struct udphdr incremental = *reinterpret_cast<const struct udphdr *>(rewrittenSegment.data());
    incremental.check = replace_l4_checksum_portable(incremental.check, dst, rewrittenDst, sizeof(rewrittenDst));
    incremental.check = replace_l4_checksum_word16(incremental.check, htons(443), htons(8443));
    suite.expect(rewrittenSegment.size() > 4096u, "switchboard_wormhole_udp_incremental_rewrite_covers_jumbo_segment");
    suite.expect(incremental.check == expectedChecksum, "switchboard_wormhole_udp_jumbo_incremental_rewrite_matches_expected_checksum");
  }

  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
