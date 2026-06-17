#pragma once

#include <array>
#include <services/debug.h>
#include <memory>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdarg.h>

#include <macros/bytes.h>
#include <services/bitsery.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/msg.h>
#include <networking/pool.h>
#include <networking/socket.h>
#include <networking/eth.h>

#include <ebpf/interface.h>
#include <ebpf/common/structs.h>

#include <prodigy/quic.cid.generator.h>
#include <prodigy/neuron/base.h>
#include <prodigy/neuron/containers.h>
#include <prodigy/netdev.detect.h>
#include <prodigy/types.h>
#include <switchboard/common/constants.h>
#include <switchboard/common/quic.cid.h>
#include <switchboard/common/structs.h>
#include <switchboard/owned.routable.prefix.h>
#include <switchboard/whitehole.route.h>

#ifndef NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE
#define NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE 0
#endif

struct quic_cid_aes_decrypt_state {

  uint32_t rk[44];
};

namespace switchboard_runtime {
class Wormhole;
} // namespace switchboard_runtime

class SwitchboardPortal {
public:

  IPAddress address;
  uint16_t port;
  uint8_t proto;
  bool isQuic;

  bytell_hash_set<switchboard_runtime::Wormhole *> wormholes;
  bool hasQuicCidKeyState = false;
  // QUIC CID keys are Switchboard routing metadata only. They are unrelated to
  // TLS resumption ticket keys and must not be used for TLS ticket encryption.
  uint128_t quicCidKeyMaterialByIndex[2] = {};
  std::array<uint32_t, RING_SIZE> hashRing;
  uint32_t slot;

  uint64_t hash(void) const
  {
    const uint8_t *start = reinterpret_cast<const uint8_t *>(&address);
    const uint8_t *end = reinterpret_cast<const uint8_t *>(&wormholes);
    return Hasher::hash<Hasher::SeedPolicy::thread_shared>(start, static_cast<uint64_t>(end - start));
  }

  bool equals(const SwitchboardPortal& lhs) const
  {
    return memcmp(&address, &lhs.address, reinterpret_cast<const uint8_t *>(&wormholes) - reinterpret_cast<const uint8_t *>(&address)) == 0;
  }

  portal_definition generatePortalDefinition(void) const
  {
    portal_definition portalDef = {};

    memcpy(portalDef.addr6, address.v6, 16);
    portalDef.port = switchboardPortalKeyPort(port);
    portalDef.proto = proto;

    return portalDef;
  }

  SwitchboardPortal()
  {
    hashRing.fill(-1);
  }
};

using Portal = SwitchboardPortal;

class SwitchboardWormholeEgressBindingEntry {
public:

  switchboard_wormhole_egress_key key = {};
  switchboard_wormhole_egress_binding binding = {};
};

class SwitchboardWormholeEgress4BindingEntry {
public:

  switchboard_wormhole_egress4_key key = {};
  switchboard_wormhole_egress_binding binding = {};
};

static inline bool switchboardBuildWormholeEgressBinding(const IPAddress& externalAddress,
                                                         uint16_t externalPort,
                                                         uint8_t proto,
                                                         switchboard_wormhole_egress_binding& binding)
{
  if (externalPort == 0 || proto == 0)
  {
    binding = {};
    return false;
  }

  binding = {};
  binding.port = htons(externalPort);
  binding.proto = proto;
  binding.is_ipv6 = externalAddress.is6 ? 1 : 0;
  std::memcpy(binding.addr6, externalAddress.v6, sizeof(binding.addr6));
  return true;
}

static inline bool switchboardWormholeEgressKeysEqual(const switchboard_wormhole_egress_key& lhs,
                                                      const switchboard_wormhole_egress_key& rhs)
{
  return std::memcmp(&lhs, &rhs, sizeof(lhs)) == 0;
}

static inline bool switchboardWormholeEgress4KeysEqual(const switchboard_wormhole_egress4_key& lhs,
                                                       const switchboard_wormhole_egress4_key& rhs)
{
  return std::memcmp(&lhs, &rhs, sizeof(lhs)) == 0;
}

static inline bool switchboardWormholeEgressDesiredContainsKey(const Vector<SwitchboardWormholeEgressBindingEntry>& desiredBindings,
                                                               const switchboard_wormhole_egress_key& key)
{
  for (const SwitchboardWormholeEgressBindingEntry& desired : desiredBindings)
  {
    if (switchboardWormholeEgressKeysEqual(desired.key, key))
    {
      return true;
    }
  }

  return false;
}

static inline bool switchboardWormholeEgress4DesiredContainsKey(const Vector<SwitchboardWormholeEgress4BindingEntry>& desiredBindings,
                                                                const switchboard_wormhole_egress4_key& key)
{
  for (const SwitchboardWormholeEgress4BindingEntry& entry : desiredBindings)
  {
    if (switchboardWormholeEgress4KeysEqual(entry.key, key))
    {
      return true;
    }
  }

  return false;
}

template <typename UpsertFn, typename DeleteFn>
static inline void switchboardReconcileWormholeEgressBindings(const Vector<switchboard_wormhole_egress_key>& existingKeys,
                                                              const Vector<SwitchboardWormholeEgressBindingEntry>& desiredBindings,
                                                              UpsertFn&& upsert,
                                                              DeleteFn&& remove)
{
  for (const SwitchboardWormholeEgressBindingEntry& desired : desiredBindings)
  {
    upsert(desired);
  }

  for (const switchboard_wormhole_egress_key& existingKey : existingKeys)
  {
    if (switchboardWormholeEgressDesiredContainsKey(desiredBindings, existingKey) == false)
    {
      remove(existingKey);
    }
  }
}

template <typename UpsertFn, typename DeleteFn>
static inline void switchboardReconcileWormholeEgress4Bindings(const Vector<switchboard_wormhole_egress4_key>& existingKeys,
                                                               const Vector<SwitchboardWormholeEgress4BindingEntry>& desiredBindings,
                                                               UpsertFn&& upsert,
                                                               DeleteFn&& remove)
{
  for (const SwitchboardWormholeEgress4BindingEntry& desired : desiredBindings)
  {
    upsert(desired);
  }

  for (const switchboard_wormhole_egress4_key& existingKey : existingKeys)
  {
    if (switchboardWormholeEgress4DesiredContainsKey(desiredBindings, existingKey) == false)
    {
      remove(existingKey);
    }
  }
}

static inline void switchboardSyncWormholeEgressBindingsForProgram(BPFProgram *program,
                                                                   const Vector<SwitchboardWormholeEgressBindingEntry>& desiredBindings,
                                                                   uint32_t ifidx,
                                                                   const char *scope)
{
  if (program == nullptr)
  {
    return;
  }

  program->openMap("wh_egress"_ctv, [&](int map_fd) -> void {
    if (map_fd < 0)
    {
      basics_log("Switchboard missing %s wh_egress map ifidx=%u\n",
                 (scope ? scope : "egress"),
                 ifidx);
      return;
    }

    Vector<switchboard_wormhole_egress_key> existingKeys = {};
    switchboard_wormhole_egress_key currentKey = {};
    switchboard_wormhole_egress_key nextKey = {};
    bool haveCurrentKey = false;

    int nextResult = 0;
    errno = 0;
    while ((nextResult = bpf_map_get_next_key(map_fd, haveCurrentKey ? &currentKey : nullptr, &nextKey)) == 0)
    {
      existingKeys.push_back(nextKey);
      currentKey = nextKey;
      haveCurrentKey = true;
    }
    if (nextResult != 0 && errno != ENOENT)
    {
      basics_log("Switchboard %s wh_egress get_next failed ifidx=%u errno=%d\n",
                 (scope ? scope : "egress"),
                 ifidx,
                 errno);
    }

    switchboardReconcileWormholeEgressBindings(existingKeys, desiredBindings, [&](const SwitchboardWormholeEgressBindingEntry& desired) -> void {
      if (bpf_map_update_elem(map_fd, &desired.key, &desired.binding, BPF_ANY) != 0)
      {
        basics_log("Switchboard %s wh_egress update failed ifidx=%u errno=%d port=%u proto=%u\n",
                   (scope ? scope : "egress"),
                   ifidx,
                   errno,
                   unsigned(ntohs(desired.key.port)),
                   unsigned(desired.key.proto));
      }
    },
                                               [&](const switchboard_wormhole_egress_key& staleKey) -> void {
                                                 if (bpf_map_delete_elem(map_fd, &staleKey) != 0)
                                                 {
                                                   basics_log("Switchboard %s wh_egress delete failed ifidx=%u errno=%d port=%u proto=%u\n",
                                                              (scope ? scope : "egress"),
                                                              ifidx,
                                                              errno,
                                                              unsigned(ntohs(staleKey.port)),
                                                              unsigned(staleKey.proto));
                                                 }
                                               });
  });
}

static inline void switchboardSyncWormholeEgress4BindingsForProgram(BPFProgram *program,
                                                                    const Vector<SwitchboardWormholeEgress4BindingEntry>& desiredBindings,
                                                                    uint32_t ifidx,
                                                                    const char *scope)
{
  if (program == nullptr)
  {
    return;
  }

  program->openMap("wh_egress4"_ctv, [&](int map_fd) -> void {
    if (map_fd < 0)
    {
      basics_log("Switchboard missing %s wh_egress4 map ifidx=%u\n",
                 (scope ? scope : "egress4"),
                 ifidx);
      return;
    }

    Vector<switchboard_wormhole_egress4_key> existingKeys = {};
    switchboard_wormhole_egress4_key currentKey = {};
    switchboard_wormhole_egress4_key nextKey = {};
    bool haveCurrentKey = false;

    int nextResult = 0;
    errno = 0;
    while ((nextResult = bpf_map_get_next_key(map_fd, haveCurrentKey ? &currentKey : nullptr, &nextKey)) == 0)
    {
      existingKeys.push_back(nextKey);
      currentKey = nextKey;
      haveCurrentKey = true;
    }
    if (nextResult != 0 && errno != ENOENT)
    {
      basics_log("Switchboard %s wh_egress4 get_next failed ifidx=%u errno=%d\n",
                 (scope ? scope : "egress4"),
                 ifidx,
                 errno);
    }

    switchboardReconcileWormholeEgress4Bindings(existingKeys, desiredBindings, [&](const SwitchboardWormholeEgress4BindingEntry& desired) -> void {
      if (bpf_map_update_elem(map_fd, &desired.key, &desired.binding, BPF_ANY) != 0)
      {
        basics_log("Switchboard %s wh_egress4 update failed ifidx=%u errno=%d port=%u proto=%u\n",
                   (scope ? scope : "egress4"),
                   ifidx,
                   errno,
                   unsigned(ntohs(desired.key.port)),
                   unsigned(desired.key.proto));
      }
    },
                                                [&](const switchboard_wormhole_egress4_key& staleKey) -> void {
                                                  if (bpf_map_delete_elem(map_fd, &staleKey) != 0)
                                                  {
                                                    basics_log("Switchboard %s wh_egress4 delete failed ifidx=%u errno=%d port=%u proto=%u\n",
                                                               (scope ? scope : "egress4"),
                                                               ifidx,
                                                               errno,
                                                               unsigned(ntohs(staleKey.port)),
                                                               unsigned(staleKey.proto));
                                                  }
                                                });
  });
}

namespace switchboard_runtime {
class Wormhole {
public:

  uint32_t containerID;
  uint16_t port;
  uint8_t proto;
  ServiceUserCapacity userCapacity;
  uint32_t weight = 1;
  SwitchboardPortal *portal;

  uint64_t hash(void) const
  {
    const uint8_t *start = reinterpret_cast<const uint8_t *>(&containerID);
    const uint8_t *end = reinterpret_cast<const uint8_t *>(&portal) + sizeof(portal);
    return Hasher::hash<Hasher::SeedPolicy::thread_shared>(start, static_cast<uint64_t>(end - start));
  }

  bool equals(const Wormhole& lhs) const
  {
    return (containerID == lhs.containerID) && (port == lhs.port) && (proto == lhs.proto);
  }
};

class Whitehole {
public:

  uint32_t containerID = 0;
  IPAddress address = {};
  uint16_t port = 0;
  uint8_t proto = 0;
  uint64_t nonce = 0;

  uint64_t hash(void) const
  {
    const uint8_t *start = reinterpret_cast<const uint8_t *>(&containerID);
    const uint8_t *end = reinterpret_cast<const uint8_t *>(&nonce) + sizeof(nonce);
    return Hasher::hash<Hasher::SeedPolicy::thread_shared>(start, static_cast<uint64_t>(end - start));
  }

  bool equals(const Whitehole& lhs) const
  {
    return containerID == lhs.containerID && port == lhs.port && proto == lhs.proto && nonce == lhs.nonce && address.equals(lhs.address);
  }
};
} // namespace switchboard_runtime

#include <switchboard/maglevhashv2.h>

class Switchboard {
private:

  EthDevice& eth;
  BPFProgram *bpf_router = nullptr;
#if NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE
  BPFProgram *host_ingress = nullptr;
#endif
  BPFProgram *host_egress = nullptr;
  struct local_container_subnet6 subnet = {};

  Vector<IPPrefix> announcingPrefixes;
  Vector<DistributableExternalSubnet> routableSubnets;
  Vector<IPPrefix> hostedIngressPrefixes;
  Vector<switchboard_owned_routable_prefix4_key> installedOwnedRoutablePrefixes4;
  Vector<switchboard_owned_routable_prefix6_key> installedOwnedRoutablePrefixes6;
  Vector<portal_definition> installedWhiteholeBindingKeys;

  bytell_hash_set<SwitchboardPortal *> portals;
  bytell_hash_subset<uint32_t, switchboard_runtime::Wormhole *> wormholesByContainer;
  bytell_hash_subset<uint32_t, switchboard_runtime::Whitehole *> whiteholesByContainer;
  Vector<uint32_t> portalSlots;

  static void appendAttachLog(const char *message)
  {
    if (message == nullptr)
    {
      return;
    }

    int fd = open("/switchboard.attach.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0)
    {
      return;
    }

    (void)write(fd, message, strlen(message));
    (void)write(fd, "\n", 1);
    (void)close(fd);
  }

  static void appendAttachLogf(const char *format, ...)
  {
    if (format == nullptr)
    {
      return;
    }

    char line[512] = {};
    va_list args;
    va_start(args, format);
    (void)vsnprintf(line, sizeof(line), format, args);
    va_end(args);

    appendAttachLog(line);
  }

  static __u32 kernelMapIDForFD(int fd)
  {
    if (fd < 0)
    {
      return 0;
    }

    struct bpf_map_info info = {};
    __u32 infoLen = sizeof(info);
    if (bpf_map_get_info_by_fd(fd, &info, &infoLen) != 0)
    {
      return 0;
    }

    return info.id;
  }

  static bool fileReadable(const char *path)
  {
    return (path && path[0] && access(path, R_OK) == 0);
  }

  static bool parseDefaultRouteDevice(String& deviceName)
  {
    FILE *routes = fopen("/proc/net/route", "r");
    if (routes == nullptr)
    {
      return false;
    }

    char line[512] = {};
    if (fgets(line, sizeof(line), routes) == nullptr)
    {
      fclose(routes);
      return false;
    }

    while (fgets(line, sizeof(line), routes) != nullptr)
    {
      char iface[IF_NAMESIZE] = {};
      char destination[32] = {};
      char gateway[32] = {};
      unsigned int flags = 0;

      if (sscanf(line, "%15s %31s %31s %x", iface, destination, gateway, &flags) < 4)
      {
        continue;
      }

      if (strcmp(destination, "00000000") == 0 && (flags & RTF_UP))
      {
        deviceName.assign(iface);
        fclose(routes);
        return true;
      }
    }

    fclose(routes);
    return false;
  }

  static bool resolveBoundaryDevice(String& deviceName)
  {
    if (const char *switchboardNetdev = getenv("SWITCHBOARD_NETDEV"); switchboardNetdev && switchboardNetdev[0])
    {
      deviceName.assign(switchboardNetdev);
      return true;
    }

    if (prodigyGetPrimaryNetworkDeviceOverride(deviceName))
    {
      return true;
    }

    return prodigyResolvePrimaryNetworkDevice(deviceName) || parseDefaultRouteDevice(deviceName);
  }

  static String resolveBalancerObjectPath(void)
  {
    String resolvedPath;

    if (const char *overridePath = getenv("SWITCHBOARD_BALANCER_OBJ"); fileReadable(overridePath))
    {
      resolvedPath.assign(overridePath);
      return resolvedPath;
    }

    if (fileReadable("/root/balancer.ebpf.o"))
    {
      resolvedPath.assign("/root/balancer.ebpf.o");
      return resolvedPath;
    }

    if (fileReadable("/root/prodigy/balancer.ebpf.o"))
    {
      resolvedPath.assign("/root/prodigy/balancer.ebpf.o");
      return resolvedPath;
    }

    if (fileReadable("balancer.ebpf.o"))
    {
      resolvedPath.assign("balancer.ebpf.o");
      return resolvedPath;
    }

    resolvedPath.assign("balancer.ebpf.o");
    return resolvedPath;
  }

  static bool usePreattachedXDPProgram(void)
  {
    if (const char *mode = getenv("SWITCHBOARD_USE_PREATTACHED_XDP"); mode && mode[0] == '1' && mode[1] == '\0')
    {
      return true;
    }

    return false;
  }

  static bool detachCurrentXDP(EthDevice& eth)
  {
    constexpr static uint32_t xdpQueryModes[] = {
        XDP_FLAGS_DRV_MODE,
        XDP_FLAGS_SKB_MODE,
        0};

    uint32_t currentProgID = 0;
    uint32_t detachFlags = 0;
    bool foundXDP = false;

    for (uint32_t queryFlags : xdpQueryModes)
    {
      currentProgID = 0;
      int queryResult = bpf_xdp_query_id(eth.ifidx, queryFlags, &currentProgID);
      if (queryResult != 0)
      {
        basics_log("Switchboard detachCurrentXDP query failed ifidx=%u flags=0x%x result=%d errno=%d\n",
                   eth.ifidx,
                   queryFlags,
                   queryResult,
                   errno);
        continue;
      }

      if (currentProgID != 0)
      {
        detachFlags = (queryFlags & XDP_FLAGS_MODES);
        foundXDP = true;
        break;
      }
    }

    if (foundXDP == false)
    {
      return true;
    }

    int detachResult = bpf_xdp_detach(eth.ifidx, detachFlags, nullptr);
    if (detachResult != 0)
    {
      basics_log("Switchboard detachCurrentXDP failed ifidx=%u prog_id=%u flags=0x%x rc=%d errno=%d\n",
                 eth.ifidx,
                 currentProgID,
                 detachFlags,
                 detachResult,
                 errno);
      return false;
    }

    return true;
  }

  static void appendCurrentXDPState(EthDevice& eth, StringType auto&& balancerObjectPath, const char *stage)
  {
    __u32 drvProgID = 0;
    __u32 skbProgID = 0;
    __u32 anyProgID = 0;
    int drvRC = bpf_xdp_query_id(eth.ifidx, XDP_FLAGS_DRV_MODE, &drvProgID);
    int skbRC = bpf_xdp_query_id(eth.ifidx, XDP_FLAGS_SKB_MODE, &skbProgID);
    int anyRC = bpf_xdp_query_id(eth.ifidx, 0, &anyProgID);
    if (drvRC != 0 || skbRC != 0 || anyRC != 0)
    {
      basics_log("Switchboard XDP state query failed stage=%s ifidx=%u drvRC=%d skbRC=%d anyRC=%d errno=%d\n",
                 (stage ? stage : "unknown"),
                 eth.ifidx,
                 drvRC,
                 skbRC,
                 anyRC,
                 errno);
    }

    appendAttachLogf(
        "Switchboard XDP state stage=%s ifidx=%u path=%s readable=%d drvRC=%d drvProg=%u skbRC=%d skbProg=%u anyRC=%d anyProg=%u errno=%d",
        (stage ? stage : "unknown"),
        eth.ifidx,
        balancerObjectPath.c_str(),
        fileReadable(balancerObjectPath.c_str()) ? 1 : 0,
        drvRC,
        drvProgID,
        skbRC,
        skbProgID,
        anyRC,
        anyProgID,
        errno);
  }

  static void ensureBPFMemlockLimit(void)
  {
    struct rlimit limit = {};
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;

    if (setrlimit(RLIMIT_MEMLOCK, &limit) != 0)
    {
      basics_log("Switchboard setrlimit(RLIMIT_MEMLOCK) failed errno=%d\n", errno);
      char line[128] = {};
      (void)snprintf(line, sizeof(line), "Switchboard setrlimit memlock failed errno=%d", errno);
      appendAttachLog(line);
    }
  }

  static void buildQuicCidDecryptState(uint128_t keyMaterial, quic_cid_aes_decrypt_state& aesState)
  {
    aesState = {};

    uint8_t key[16] = {};
    wormholeQuicCidExtractKeyBytes(keyMaterial, key);
    if (prodigyBuildQuicCidDecryptRoundKeys(key, aesState.rk) == false)
    {
      basics_log("Switchboard OpenSSL decrypt key setup failed\n");
    }
  }

  template <typename Key>
  static void clearHashMapFD(int mapFD, const char *mapName)
  {
    if (mapFD < 0)
    {
      basics_log("Switchboard clearHashMapFD missing map=%s\n", (mapName ? mapName : "hash"));
      return;
    }

    Key nextKey = {};
    int nextResult = 0;
    errno = 0;
    while ((nextResult = bpf_map_get_next_key(mapFD, nullptr, &nextKey)) == 0)
    {
      Key deleteKey = nextKey;
      if (bpf_map_delete_elem(mapFD, &deleteKey) != 0)
      {
        basics_log("Switchboard clearHashMapFD delete failed map=%s errno=%d\n",
                   (mapName ? mapName : "hash"),
                   errno);
        break;
      }
    }
    if (nextResult != 0 && errno != ENOENT)
    {
      basics_log("Switchboard clearHashMapFD get_next failed map=%s errno=%d\n",
                 (mapName ? mapName : "hash"),
                 errno);
    }
  }

  void clearPortalQuicCidDecryptStateForProgram(BPFProgram *program, uint32_t portalSlot) const
  {
    if (program == nullptr)
    {
      return;
    }

    quic_cid_aes_decrypt_state emptyState = {};
    program->openMap("quic_cid_dec"_ctv, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        basics_log("Switchboard missing quic_cid_dec\n");
        return;
      }

      for (uint8_t keyIndex = 0; keyIndex < 2; ++keyIndex)
      {
        uint32_t mapIndex = quicCidPortalDecryptMapIndex(portalSlot, keyIndex);
        if (bpf_map_update_elem(map_fd, &mapIndex, &emptyState, BPF_ANY) != 0)
        {
          basics_log("Switchboard decrypt-state clear failed (%d)\n", errno);
        }
      }
    });
  }

  void clearPortalQuicCidDecryptState(uint32_t portalSlot)
  {
    clearPortalQuicCidDecryptStateForProgram(bpf_router, portalSlot);
  }

  void installPortalQuicCidDecryptStateForProgram(BPFProgram *program, const SwitchboardPortal *portal) const
  {
    if (program == nullptr || portal == nullptr || portal->isQuic == false || portal->hasQuicCidKeyState == false)
    {
      return;
    }

    program->openMap("quic_cid_dec"_ctv, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        basics_log("Switchboard missing quic_cid_dec\n");
        return;
      }

      for (uint8_t keyIndex = 0; keyIndex < 2; ++keyIndex)
      {
        quic_cid_aes_decrypt_state aesState = {};
        // This BPF map holds only QUIC CID routing decrypt state, never TLS
        // session-resumption ticket material.
        uint128_t keyMaterial = portal->quicCidKeyMaterialByIndex[keyIndex];
        buildQuicCidDecryptState(keyMaterial, aesState);

        uint32_t mapIndex = quicCidPortalDecryptMapIndex(portal->slot, wormholeQuicCidKeyMaterialPhase(keyMaterial));
        if (bpf_map_update_elem(map_fd, &mapIndex, &aesState, BPF_ANY) != 0)
        {
          basics_log("Switchboard decrypt-state update failed (%d)\n", errno);
        }
      }
    });
  }

  void installPortalQuicCidDecryptState(const SwitchboardPortal *portal)
  {
    installPortalQuicCidDecryptStateForProgram(bpf_router, portal);
  }

  template <typename Callback>
  void forEachActivePeerProgram(Callback&& callback) const
  {
    if (thisNeuron == nullptr)
    {
      return;
    }

    for (const auto& [uuid, container] : thisNeuron->containers)
    {
      (void)uuid;

      if (container == nullptr || container->plan.useHostNetworkNamespace || container->netdevs.areActive() == false || container->peer_program == nullptr)
      {
        continue;
      }

      callback(container->peer_program);
    }
  }

  void syncAllPortalQuicCidDecryptStates(void)
  {
    if (bpf_router == nullptr)
    {
      return;
    }

    for (SwitchboardPortal *portal : portals)
    {
      if (portal == nullptr || portal->isQuic == false)
      {
        continue;
      }

      if (portal->hasQuicCidKeyState)
      {
        installPortalQuicCidDecryptState(portal);
      }
      else
      {
        clearPortalQuicCidDecryptState(portal->slot);
      }
    }
  }

  bool buildContainerIDStruct(uint32_t containerKey, container_id& id) const
  {
    if (containerKey == 0)
    {
      id = {};
      return false;
    }

    id = {};
    id.hasID = true;
    id.value[0] = subnet.dpfx;
    id.value[1] = static_cast<uint8_t>((containerKey >> 16) & 0xFF);
    id.value[2] = static_cast<uint8_t>((containerKey >> 8) & 0xFF);
    id.value[3] = static_cast<uint8_t>(containerKey & 0xFF);
    id.value[4] = static_cast<uint8_t>((containerKey >> 24) & 0xFF);
    return true;
  }

  bool buildWormholeTargetKey(const SwitchboardPortal *portal, uint32_t containerKey, switchboard_wormhole_target_key& key) const
  {
    if (portal == nullptr)
    {
      key = {};
      return false;
    }

    container_id id = {};
    if (buildContainerIDStruct(containerKey, id) == false)
    {
      key = {};
      return false;
    }

    key = {};
    key.slot = portal->slot;
    std::memcpy(key.container, id.value, sizeof(key.container));
    return true;
  }

  bool buildWormholeEgressKey(uint32_t containerKey, uint16_t containerPort, uint8_t proto, switchboard_wormhole_egress_key& key) const
  {
    container_id id = {};
    if (buildContainerIDStruct(containerKey, id) == false || containerPort == 0 || proto == 0)
    {
      key = {};
      return false;
    }

    // This key has padding bytes in its C layout. Zero the full object so
    // userspace map updates byte-match the BPF-side lookup key, which also
    // clears the whole struct before populating fields.
    std::memset(&key, 0, sizeof(key));
    std::memcpy(key.container, id.value, sizeof(key.container));
    key.port = htons(containerPort);
    key.proto = proto;
    return true;
  }

  bool buildWormholeEgress4Key(const IPAddress& externalAddress,
                               uint16_t containerPort,
                               uint8_t proto,
                               switchboard_wormhole_egress4_key& key) const
  {
    if (externalAddress.is6 || externalAddress.v4 == 0 || containerPort == 0 || proto == 0)
    {
      key = {};
      return false;
    }

    key = {};
    key.addr = externalAddress.v4;
    key.port = htons(containerPort);
    key.proto = proto;
    return true;
  }

  void collectWormholeEgressBindingEntries(Vector<SwitchboardWormholeEgressBindingEntry>& desiredBindings,
                                           Vector<SwitchboardWormholeEgress4BindingEntry>& desiredBindings4)
  {
    desiredBindings.clear();
    desiredBindings4.clear();

    for (const auto& [containerID, wormholes] : wormholesByContainer)
    {
      (void)containerID;

      for (switchboard_runtime::Wormhole *wormhole : wormholes)
      {
        if (wormhole == nullptr || wormhole->portal == nullptr)
        {
          continue;
        }

        SwitchboardWormholeEgressBindingEntry desired = {};
        if (buildWormholeEgressKey(wormhole->containerID, wormhole->port, wormhole->proto, desired.key) == false || switchboardBuildWormholeEgressBinding(wormhole->portal->address,
                                                                                                                                                          wormhole->portal->port,
                                                                                                                                                          wormhole->proto,
                                                                                                                                                          desired.binding) == false)
        {
          continue;
        }

        desiredBindings.push_back(desired);

        SwitchboardWormholeEgress4BindingEntry desired4 = {};
        if (buildWormholeEgress4Key(wormhole->portal->address,
                                    wormhole->port,
                                    wormhole->proto,
                                    desired4.key) &&
            switchboardBuildWormholeEgressBinding(wormhole->portal->address,
                                                  wormhole->portal->port,
                                                  wormhole->proto,
                                                  desired4.binding))
        {
          desiredBindings4.push_back(desired4);
        }
      }
    }
  }

  BPFProgram *findLocalContainerPeerEgressProgram(uint32_t containerKey) const
  {
    if (thisNeuron == nullptr)
    {
      return nullptr;
    }

    uint8_t fragment = static_cast<uint8_t>((containerKey >> 24) & 0xFF);
    BPFProgram *fallbackProgram = nullptr;

    for (const auto& [uuid, container] : thisNeuron->containers)
    {
      (void)uuid;

      if (container == nullptr || container->plan.fragment != fragment)
      {
        continue;
      }

      if (container->plan.useHostNetworkNamespace)
      {
        fallbackProgram = host_egress;
        continue;
      }

      if (container->netdevs.areActive() && container->peer_program != nullptr)
      {
        return container->peer_program;
      }
    }

    return fallbackProgram;
  }

  bool installWormholeEgressBindingForProgram(BPFProgram *program,
                                              const switchboard_wormhole_egress_key& egressKey,
                                              const switchboard_wormhole_egress_binding& binding,
                                              uint32_t containerID,
                                              uint16_t port,
                                              uint8_t proto,
                                              const char *scope) const
  {
    if (program == nullptr)
    {
      return false;
    }

    bool updated = false;
    program->openMap("wh_egress"_ctv, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        basics_log("Switchboard missing %s wh_egress map ifidx=%u\n",
                   (scope ? scope : "egress"),
                   eth.ifidx);
        return;
      }

      if (bpf_map_update_elem(map_fd, &egressKey, &binding, BPF_ANY) != 0)
      {
        basics_log("Switchboard %s wh_egress update failed ifidx=%u errno=%d containerID=%u port=%u proto=%u\n",
                   (scope ? scope : "egress"),
                   eth.ifidx,
                   errno,
                   containerID,
                   unsigned(port),
                   unsigned(proto));
        return;
      }

      updated = true;
    });

    return updated;
  }

  void removeWormholeEgressBindingForProgram(BPFProgram *program,
                                             const switchboard_wormhole_egress_key& egressKey) const
  {
    if (program == nullptr)
    {
      return;
    }

    program->openMap("wh_egress"_ctv, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        basics_log("Switchboard missing wh_egress map for delete ifidx=%u\n", eth.ifidx);
        return;
      }

      if (bpf_map_delete_elem(map_fd, &egressKey) != 0)
      {
        basics_log("Switchboard wh_egress delete failed ifidx=%u errno=%d port=%u proto=%u\n",
                   eth.ifidx,
                   errno,
                   unsigned(ntohs(egressKey.port)),
                   unsigned(egressKey.proto));
      }
    });
  }

  bool installWormholeTargetBinding(const SwitchboardPortal *portal, const switchboard_runtime::Wormhole *wormhole, const Wormhole& requestedWormhole)
  {
    if (bpf_router == nullptr || portal == nullptr || wormhole == nullptr)
    {
      return false;
    }

    switchboard_wormhole_target_key targetKey = {};
    switchboard_wormhole_egress_key egressKey = {};
    if (buildWormholeTargetKey(portal, wormhole->containerID, targetKey) == false)
    {
      return false;
    }

    const __u16 containerPort = htons(wormhole->port);
    switchboard_wormhole_egress_binding binding = {};
    if (switchboardBuildWormholeEgressBinding(wormholeSwitchboardAddress(requestedWormhole),
                                              requestedWormhole.externalPort,
                                              requestedWormhole.layer4,
                                              binding) == false)
    {
      return false;
    }

    bool targetUpdated = false;
    bpf_router->openMap("wh_targets"_ctv, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        basics_log("Switchboard missing wh_targets map ifidx=%u\n", eth.ifidx);
        return;
      }

      if (bpf_map_update_elem(map_fd, &targetKey, &containerPort, BPF_ANY) != 0)
      {
        basics_log("Switchboard wh_targets update failed ifidx=%u errno=%d slot=%u containerID=%u\n",
                   eth.ifidx,
                   errno,
                   unsigned(portal->slot),
                   wormhole->containerID);
        return;
      }

      targetUpdated = true;
    });
    if (targetUpdated == false)
    {
      return false;
    }

    if (buildWormholeEgressKey(wormhole->containerID, wormhole->port, requestedWormhole.layer4, egressKey) == false)
    {
      return false;
    }

    if (installWormholeEgressBindingForProgram(host_egress,
                                               egressKey,
                                               binding,
                                               wormhole->containerID,
                                               wormhole->port,
                                               requestedWormhole.layer4,
                                               "host-egress") == false)
    {
      return false;
    }

    BPFProgram *peerProgram = findLocalContainerPeerEgressProgram(wormhole->containerID);
    if (peerProgram != nullptr && peerProgram != host_egress)
    {
      return installWormholeEgressBindingForProgram(peerProgram,
                                                    egressKey,
                                                    binding,
                                                    wormhole->containerID,
                                                    wormhole->port,
                                                    requestedWormhole.layer4,
                                                    "container-egress");
    }

    return true;
  }

  void removeWormholeTargetBinding(const switchboard_runtime::Wormhole *wormhole)
  {
    if (bpf_router == nullptr || wormhole == nullptr || wormhole->portal == nullptr)
    {
      return;
    }

    switchboard_wormhole_target_key targetKey = {};
    switchboard_wormhole_egress_key egressKey = {};
    if (buildWormholeTargetKey(wormhole->portal, wormhole->containerID, targetKey) == false)
    {
      return;
    }

    bpf_router->openMap("wh_targets"_ctv, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        basics_log("Switchboard missing wh_targets map for delete ifidx=%u\n", eth.ifidx);
        return;
      }

      if (bpf_map_delete_elem(map_fd, &targetKey) != 0)
      {
        basics_log("Switchboard wh_targets delete failed ifidx=%u errno=%d slot=%u containerID=%u\n",
                   eth.ifidx,
                   errno,
                   unsigned(targetKey.slot),
                   wormhole->containerID);
      }
    });

    if (buildWormholeEgressKey(wormhole->containerID, wormhole->port, wormhole->proto, egressKey))
    {
      removeWormholeEgressBindingForProgram(host_egress, egressKey);

      BPFProgram *peerProgram = findLocalContainerPeerEgressProgram(wormhole->containerID);
      if (peerProgram != nullptr && peerProgram != host_egress)
      {
        removeWormholeEgressBindingForProgram(peerProgram, egressKey);
      }
    }
  }

  void syncBoundaryMaps(void)
  {
    if (bpf_router == nullptr)
    {
      return;
    }

    appendAttachLogf("Switchboard syncBoundaryMaps ifidx=%u dpfx=%u mpfx=%u.%u.%u",
                     eth.ifidx,
                     unsigned(subnet.dpfx),
                     unsigned(subnet.mpfx[0]),
                     unsigned(subnet.mpfx[1]),
                     unsigned(subnet.mpfx[2]));

    uint32_t zeroidx = 0;

    bpf_router->openMap("lc_subnet"_ctv, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        basics_log("Switchboard missing lc_subnet\n");
        appendAttachLogf("Switchboard missing lc_subnet ifidx=%u", eth.ifidx);
        return;
      }

      if (bpf_map_update_elem(map_fd, &zeroidx, &subnet, BPF_ANY) != 0)
      {
        basics_log("Switchboard lc_subnet update failed ifidx=%u errno=%d\n",
                   eth.ifidx,
                   errno);
        appendAttachLogf("Switchboard lc_subnet update failed ifidx=%u errno=%d",
                         eth.ifidx,
                         errno);
      }
      else
      {
        struct local_container_subnet6 observed = {};
        if (bpf_map_lookup_elem(map_fd, &zeroidx, &observed) != 0)
        {
          basics_log("Switchboard lc_subnet lookup failed ifidx=%u errno=%d\n", eth.ifidx, errno);
        }
        appendAttachLogf("Switchboard lc_subnet updated ifidx=%u map_id=%u wrote=%u.%u.%u.%u read=%u.%u.%u.%u",
                         eth.ifidx,
                         kernelMapIDForFD(map_fd),
                         unsigned(subnet.dpfx),
                         unsigned(subnet.mpfx[0]),
                         unsigned(subnet.mpfx[1]),
                         unsigned(subnet.mpfx[2]),
                         unsigned(observed.dpfx),
                         unsigned(observed.mpfx[0]),
                         unsigned(observed.mpfx[1]),
                         unsigned(observed.mpfx[2]));
      }
    });

    bpf_router->openMap("mac_map"_ctv, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        basics_log("Switchboard missing mac_map\n");
        appendAttachLogf("Switchboard missing mac_map ifidx=%u", eth.ifidx);
        return;
      }

      if (bpf_map_update_elem(map_fd, &zeroidx, eth.mac, BPF_ANY) != 0)
      {
        basics_log("Switchboard mac_map update failed ifidx=%u errno=%d\n",
                   eth.ifidx,
                   errno);
        appendAttachLogf("Switchboard mac_map update failed ifidx=%u errno=%d",
                         eth.ifidx,
                         errno);
      }
      else
      {
        appendAttachLogf("Switchboard mac_map updated ifidx=%u map_id=%u",
                         eth.ifidx,
                         kernelMapIDForFD(map_fd));
      }
    });

    bpf_router->openMap("gw_mac_map"_ctv, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        basics_log("Switchboard missing gw_mac_map\n");
        appendAttachLogf("Switchboard missing gw_mac_map ifidx=%u", eth.ifidx);
        return;
      }

      if (bpf_map_update_elem(map_fd, &zeroidx, eth.gateway_mac, BPF_ANY) != 0)
      {
        basics_log("Switchboard gw_mac_map update failed ifidx=%u errno=%d\n",
                   eth.ifidx,
                   errno);
        appendAttachLogf("Switchboard gw_mac_map update failed ifidx=%u errno=%d",
                         eth.ifidx,
                         errno);
      }
      else
      {
        appendAttachLogf("Switchboard gw_mac_map updated ifidx=%u map_id=%u",
                         eth.ifidx,
                         kernelMapIDForFD(map_fd));
      }
    });

    syncOwnedRoutablePrefixMaps();
    syncAllPortalQuicCidDecryptStates();
  }

  static void applyPortalQuicCidStateFromWormhole(SwitchboardPortal *portal, const Wormhole& wormhole)
  {
    if (portal == nullptr || wormholeUsesQuicCidEncryption(wormhole) == false || wormhole.hasQuicCidKeyState == false)
    {
      return;
    }

    portal->hasQuicCidKeyState = true;
    portal->quicCidKeyMaterialByIndex[0] = wormhole.quicCidKeyState.keyMaterialByIndex[0];
    portal->quicCidKeyMaterialByIndex[1] = wormhole.quicCidKeyState.keyMaterialByIndex[1];
  }

  template <typename Key, typename Equals>
  static bool ownedRoutablePrefixKeyPresent(const Vector<Key>& keys, const Key& needle, Equals&& equals)
  {
    for (const Key& candidate : keys)
    {
      if (equals(candidate, needle))
      {
        return true;
      }
    }

    return false;
  }

  template <typename Key, typename Equals>
  void syncOwnedRoutablePrefixMap(StringType auto&& mapName, Vector<Key>& installedKeys, const Vector<Key>& desiredKeys, Equals&& equals)
  {
    if (bpf_router == nullptr)
    {
      return;
    }

    bpf_router->openMap(mapName, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        basics_log("Switchboard missing map %s\n", mapName.c_str());
        appendAttachLogf("Switchboard missing map ifidx=%u map=%s",
                         eth.ifidx,
                         mapName.c_str());
        return;
      }

      appendAttachLogf("Switchboard syncOwnedRoutablePrefixMap ifidx=%u map=%s map_id=%u desired=%u installed=%u",
                       eth.ifidx,
                       mapName.c_str(),
                       kernelMapIDForFD(map_fd),
                       unsigned(desiredKeys.size()),
                       unsigned(installedKeys.size()));

      for (const Key& existing : installedKeys)
      {
        if (ownedRoutablePrefixKeyPresent(desiredKeys, existing, equals) == false)
        {
          if (bpf_map_delete_elem(map_fd, &existing) != 0)
          {
            basics_log("Switchboard owned-routable delete failed map=%s ifidx=%u errno=%d\n",
                       mapName.c_str(),
                       eth.ifidx,
                       errno);
            appendAttachLogf("Switchboard owned-routable delete failed ifidx=%u map=%s errno=%d",
                             eth.ifidx,
                             mapName.c_str(),
                             errno);
          }
        }
      }

      __u8 present = 1;
      for (const Key& desired : desiredKeys)
      {
        if (ownedRoutablePrefixKeyPresent(installedKeys, desired, equals) == false)
        {
          if (bpf_map_update_elem(map_fd, &desired, &present, BPF_ANY) != 0)
          {
            basics_log("Switchboard owned-routable update failed map=%s ifidx=%u errno=%d\n",
                       mapName.c_str(),
                       eth.ifidx,
                       errno);
            appendAttachLogf("Switchboard owned-routable update failed ifidx=%u map=%s errno=%d",
                             eth.ifidx,
                             mapName.c_str(),
                             errno);
          }
        }
      }
    });

    installedKeys = desiredKeys;
  }

  void syncOwnedRoutablePrefixMaps(void)
  {
    Vector<IPPrefix> desiredPrefixes = {};
    desiredPrefixes.reserve(routableSubnets.size() + hostedIngressPrefixes.size());
    for (const DistributableExternalSubnet& subnet : routableSubnets)
    {
      desiredPrefixes.push_back(distributableExternalSubnetSwitchboardSubnet(subnet));
    }
    for (const IPPrefix& prefix : hostedIngressPrefixes)
    {
      desiredPrefixes.push_back(prefix);
    }

    Vector<switchboard_owned_routable_prefix4_key> desiredPrefixes4;
    Vector<switchboard_owned_routable_prefix6_key> desiredPrefixes6;
    switchboardBuildOwnedRoutablePrefixKeys(desiredPrefixes, desiredPrefixes4, desiredPrefixes6);

    syncOwnedRoutablePrefixMap("owned_pfx4"_ctv,
                               installedOwnedRoutablePrefixes4,
                               desiredPrefixes4,
                               [](const switchboard_owned_routable_prefix4_key& lhs, const switchboard_owned_routable_prefix4_key& rhs) -> bool {
                                 return switchboardOwnedRoutablePrefix4Equals(lhs, rhs);
                               });

    syncOwnedRoutablePrefixMap("owned_pfx6"_ctv,
                               installedOwnedRoutablePrefixes6,
                               desiredPrefixes6,
                               [](const switchboard_owned_routable_prefix6_key& lhs, const switchboard_owned_routable_prefix6_key& rhs) -> bool {
                                 return switchboardOwnedRoutablePrefix6Equals(lhs, rhs);
                               });
  }

  template <typename Equals>
  static bool whiteholeBindingKeyPresent(const Vector<portal_definition>& keys, const portal_definition& needle, Equals&& equals)
  {
    for (const portal_definition& candidate : keys)
    {
      if (equals(candidate, needle))
      {
        return true;
      }
    }

    return false;
  }

  void syncWhiteholeBindingsMap(void)
  {
    if (bpf_router == nullptr)
    {
      return;
    }

    Vector<std::pair<portal_definition, switchboard_whitehole_binding>> desiredEntries = {};
    Vector<portal_definition> desiredKeys = {};

    for (const auto& [containerID, bindings] : whiteholesByContainer)
    {
      (void)containerID;
      for (switchboard_runtime::Whitehole *binding : bindings)
      {
        if (binding == nullptr)
        {
          continue;
        }

        portal_definition key = {};
        switchboard_whitehole_binding value = {};
        Whitehole whitehole = {};
        whitehole.address = binding->address;
        whitehole.sourcePort = binding->port;
        whitehole.transport = (binding->proto == IPPROTO_UDP) ? ExternalAddressTransport::quic : ExternalAddressTransport::tcp;
        whitehole.bindingNonce = binding->nonce;
        if (switchboardBuildWhiteholeBinding(whitehole, binding->containerID, subnet, key, value) == false)
        {
          continue;
        }

        desiredEntries.emplace_back(key, value);
        desiredKeys.push_back(key);
      }
    }

    bpf_router->openMap("whiteholes"_ctv, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        basics_log("Switchboard missing whiteholes map\n");
        return;
      }

      for (const portal_definition& existing : installedWhiteholeBindingKeys)
      {
        if (whiteholeBindingKeyPresent(desiredKeys, existing, switchboardPortalDefinitionEquals) == false)
        {
          if (bpf_map_delete_elem(map_fd, &existing) != 0)
          {
            basics_log("Switchboard whiteholes delete failed ifidx=%u errno=%d\n", eth.ifidx, errno);
          }
        }
      }

      for (const auto& entry : desiredEntries)
      {
        if (bpf_map_update_elem(map_fd, &entry.first, &entry.second, BPF_ANY) != 0)
        {
          basics_log("Switchboard whiteholes update failed ifidx=%u errno=%d\n", eth.ifidx, errno);
        }
      }
    });

    installedWhiteholeBindingKeys = desiredKeys;
  }

  bool ensureBoundaryRouterConfigured(void)
  {
    if (subnet.dpfx == 0)
    {
      appendAttachLog("Switchboard missing local subnet");
      return false;
    }

    if (eth.ifidx == 0)
    {
      String boundaryDevice;
      if (resolveBoundaryDevice(boundaryDevice) == false)
      {
        basics_log("Switchboard unable to resolve boundary netdev\n");
        appendAttachLog("Switchboard resolveBoundaryDevice failed");
        return false;
      }

      eth.setDevice(boundaryDevice);
    }

    if (eth.ifidx == 0)
    {
      appendAttachLog("Switchboard eth.ifidx=0");
      return false;
    }

    if (bpf_router == nullptr)
    {
      String balancerObjectPath = resolveBalancerObjectPath();
      bool preattachedMode = usePreattachedXDPProgram();

      auto attachBalancer = [&](uint32_t flags) -> BPFProgram * {
        auto attachedProgramID = [&](void) -> __u32 {
          __u32 prog_id = 0;
          const uint32_t queryFlags = (flags & XDP_FLAGS_MODES);
          int queryResult = bpf_xdp_query_id(eth.ifidx, queryFlags, &prog_id);
          if (queryResult != 0)
          {
            basics_log("Switchboard bpf_xdp_query_id failed ifidx=%u flags=0x%x result=%d errno=%d\n",
                       eth.ifidx,
                       queryFlags,
                       queryResult,
                       errno);
            return 0;
          }
          if (prog_id == 0)
          {
            return 0;
          }

          return prog_id;
        };

        BPFProgram *program = eth.attachXDP(balancerObjectPath, "bal_ingress"_ctv, flags,
                                            [&](struct bpf_object *obj, Vector<int>& inner_map_fds) -> void {
                                              int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(container_id), RING_SIZE, nullptr);
                                              if (inner_map_fd < 0)
                                              {
                                                basics_log("Switchboard cid_rings inner map create failed ifidx=%u errno=%d\n", eth.ifidx, errno);
                                                return;
                                              }

                                              struct bpf_map *ringsMap = bpf_object__find_map_by_name(obj, "cid_rings");
                                              if (ringsMap == nullptr)
                                              {
                                                basics_log("Switchboard missing cid_rings map while seeding balancer ifidx=%u\n", eth.ifidx);
                                                ::close(inner_map_fd);
                                                return;
                                              }
                                              if (bpf_map__set_inner_map_fd(ringsMap, inner_map_fd) != 0)
                                              {
                                                basics_log("Switchboard cid_rings inner fd setup failed ifidx=%u errno=%d\n", eth.ifidx, errno);
                                                ::close(inner_map_fd);
                                                return;
                                              }

                                              inner_map_fds.push_back(inner_map_fd);

                                              String pinPath = {};
                                              switchboardWhiteholeReplyFlowPinPath(pinPath, eth.ifidx);
                                              int pinnedWhiteholeReplyFD = bpf_obj_get(pinPath.c_str());
                                              if (pinnedWhiteholeReplyFD >= 0)
                                              {
                                                if (struct bpf_map *replyMap = bpf_object__find_map_by_name(obj, "white_replies"))
                                                {
                                                  if (bpf_map__reuse_fd(replyMap, pinnedWhiteholeReplyFD) != 0)
                                                  {
                                                    basics_log("Switchboard white_replies reuse fd failed ifidx=%u errno=%d\n", eth.ifidx, errno);
                                                    ::close(pinnedWhiteholeReplyFD);
                                                    return;
                                                  }
                                                }
                                                else
                                                {
                                                  basics_log("Switchboard missing white_replies map while seeding balancer ifidx=%u\n", eth.ifidx);
                                                  ::close(pinnedWhiteholeReplyFD);
                                                  return;
                                                }

                                                inner_map_fds.push_back(pinnedWhiteholeReplyFD);
                                              }
                                              else
                                              {
                                                basics_log("Switchboard white_replies pinned map unavailable ifidx=%u path=%s errno=%d\n",
                                                           eth.ifidx,
                                                           pinPath.c_str(),
                                                           errno);
                                              }
                                            });

        if (program == nullptr)
        {
          return attachedProgramID() ? eth.loadPreattachedProgram(BPF_XDP, balancerObjectPath) : nullptr;
        }

        // Some kernels report generic XDP only when queried with
        // XDP_FLAGS_SKB_MODE. Validate against the attach mode; otherwise a
        // successful generic attach can be mistaken for failure and leave
        // the live balancer without Switchboard-managed routing maps.
        if (attachedProgramID() == 0)
        {
          eth.detachXDP();
          return nullptr;
        }

        return program;
      };

      if (preattachedMode)
      {
        appendCurrentXDPState(eth, balancerObjectPath, "before-preattached-load");
        bpf_router = eth.loadPreattachedProgram(BPF_XDP, balancerObjectPath);
        if (bpf_router == nullptr)
        {
          basics_log("Switchboard failed to load preattached balancer XDP program ifidx=%u path=%s errno=%d\n",
                     eth.ifidx,
                     balancerObjectPath.c_str(),
                     errno);
          appendCurrentXDPState(eth, balancerObjectPath, "after-preattached-load-failure");
          appendAttachLog("Switchboard failed to load preattached balancer XDP program");
          return false;
        }
      }
      else if (bpf_router == nullptr)
      {
        ensureBPFMemlockLimit();

        appendCurrentXDPState(eth, balancerObjectPath, "before-managed-attach");
        bpf_router = attachBalancer(XDP_FLAGS_DRV_MODE);
        if (bpf_router == nullptr)
        {
          appendCurrentXDPState(eth, balancerObjectPath, "after-managed-attach-drv-failure");
          bpf_router = attachBalancer(XDP_FLAGS_SKB_MODE);
        }

        if (bpf_router == nullptr)
        {
          appendCurrentXDPState(eth, balancerObjectPath, "after-managed-attach-skb-failure");
          appendAttachLog("Switchboard failed to attach balancer XDP program");
          return false;
        }
      }

      installedOwnedRoutablePrefixes4.clear();
      installedOwnedRoutablePrefixes6.clear();
    }

    syncBoundaryMaps();
    return true;
  }

  void maybeDetachBoundaryRouter(void)
  {
    if (bpf_router == nullptr)
    {
      return;
    }

    if (!portals.empty())
    {
      return;
    }

    if (whiteholesByContainer.isEmpty() == false)
    {
      return;
    }

    if (!announcingPrefixes.empty())
    {
      return;
    }

    eth.detachXDP();
    bpf_router = nullptr;
    installedOwnedRoutablePrefixes4.clear();
    installedOwnedRoutablePrefixes6.clear();
    installedWhiteholeBindingKeys.clear();
  }

  bool syncPortalDefinitionForProgram(BPFProgram *program, const SwitchboardPortal *portal) const
  {
    if (program == nullptr || portal == nullptr)
    {
      return false;
    }

    portal_definition portalDef = portal->generatePortalDefinition();
    portal_meta meta = {};
    meta.flags = portal->isQuic ? F_QUIC_PORTAL : 0;
    meta.slot = portal->slot;

    bool updated = false;
    program->openMap("ext_portals"_ctv, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        basics_log("Switchboard missing ext_portals map ifidx=%u\n", eth.ifidx);
        appendAttachLogf("Switchboard missing ext_portals map ifidx=%u", eth.ifidx);
        return;
      }

      if (bpf_map_update_elem(map_fd, &portalDef, &meta, BPF_ANY) != 0)
      {
        basics_log("Switchboard ext_portals update failed ifidx=%u errno=%d port=%u proto=%u\n",
                   eth.ifidx,
                   errno,
                   unsigned(portal->port),
                   unsigned(portal->proto));
        appendAttachLogf("Switchboard ext_portals update failed ifidx=%u errno=%d port=%u proto=%u",
                         eth.ifidx,
                         errno,
                         unsigned(portal->port),
                         unsigned(portal->proto));
        return;
      }

      updated = true;
    });

    return updated;
  }

  void removePortalDefinitionForProgram(BPFProgram *program, const SwitchboardPortal *portal) const
  {
    if (program == nullptr || portal == nullptr)
    {
      return;
    }

    portal_definition portalDef = portal->generatePortalDefinition();
    program->openMap("ext_portals"_ctv, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        basics_log("Switchboard missing ext_portals map for delete ifidx=%u\n", eth.ifidx);
        return;
      }

      if (bpf_map_delete_elem(map_fd, &portalDef) != 0)
      {
        basics_log("Switchboard ext_portals delete failed ifidx=%u errno=%d port=%u proto=%u\n",
                   eth.ifidx,
                   errno,
                   unsigned(portal->port),
                   unsigned(portal->proto));
      }
    });
  }

  bool generateRingForPortalOnProgram(BPFProgram *program, SwitchboardPortal *portal)
  {
    if (portal == nullptr || program == nullptr)
    {
      return false;
    }

    std::array<uint32_t, RING_SIZE> newRing = MaglevHashV2::generateHashRingForPortal(portal);

    int hashring_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(container_id), RING_SIZE, nullptr);
    if (hashring_fd < 0)
    {
      basics_log("Switchboard inner ring map create failed (%d)\n", errno);
      return false;
    }

    bool ok = true;
    for (uint32_t index = 0; index < RING_SIZE; ++index)
    {
      container_id entry = {};
      uint32_t containerKey = newRing[index];

      if (containerKey != 0)
      {
        uint8_t containerFragment = static_cast<uint8_t>((containerKey >> 24) & 0xFF);
        uint8_t machineByte0 = static_cast<uint8_t>((containerKey >> 16) & 0xFF);
        uint8_t machineByte1 = static_cast<uint8_t>((containerKey >> 8) & 0xFF);
        uint8_t machineByte2 = static_cast<uint8_t>(containerKey & 0xFF);

        entry.hasID = true;
        entry.value[0] = subnet.dpfx;
        entry.value[1] = machineByte0;
        entry.value[2] = machineByte1;
        entry.value[3] = machineByte2;
        entry.value[4] = containerFragment;
      }

      if (bpf_map_update_elem(hashring_fd, &index, &entry, BPF_ANY) != 0)
      {
        basics_log("Switchboard inner ring update failed (%d)\n", errno);
        ok = false;
        break;
      }
    }

    if (ok)
    {
      program->openMap("cid_rings"_ctv, [&](int map_fd) -> void {
        if (map_fd < 0)
        {
          basics_log("Switchboard missing cid_rings map ifidx=%u\n", eth.ifidx);
          ok = false;
          return;
        }

        if (bpf_map_update_elem(map_fd, &portal->slot, &hashring_fd, BPF_ANY) != 0)
        {
          basics_log("Switchboard outer ring update failed (%d)\n", errno);
          ok = false;
        }
      });
    }

    close(hashring_fd);
    if (ok)
    {
      portal->hashRing = newRing;
    }
    return ok;
  }

  bool generateRingForPortal(SwitchboardPortal *portal)
  {
    return generateRingForPortalOnProgram(bpf_router, portal);
  }

  bool syncPortalTargetBindingsForProgram(BPFProgram *program, const char *scope)
  {
    if (program == nullptr)
    {
      return false;
    }

    bool ok = true;
    program->openMap("wh_targets"_ctv, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        basics_log("Switchboard missing wh_targets map scope=%s ifidx=%u\n", (scope ? scope : "portal-sync"), eth.ifidx);
        ok = false;
        return;
      }

      for (const auto& [containerID, wormholes] : wormholesByContainer)
      {
        (void)containerID;

        for (switchboard_runtime::Wormhole *wormhole : wormholes)
        {
          if (wormhole == nullptr || wormhole->portal == nullptr)
          {
            continue;
          }

          switchboard_wormhole_target_key targetKey = {};
          if (buildWormholeTargetKey(wormhole->portal, wormhole->containerID, targetKey) == false)
          {
            ok = false;
            continue;
          }

          const __u16 containerPort = htons(wormhole->port);
          if (bpf_map_update_elem(map_fd, &targetKey, &containerPort, BPF_ANY) != 0)
          {
            basics_log("Switchboard wh_targets sync update failed scope=%s ifidx=%u errno=%d slot=%u containerID=%u\n",
                       (scope ? scope : "portal-sync"),
                       eth.ifidx,
                       errno,
                       unsigned(targetKey.slot),
                       wormhole->containerID);
            ok = false;
          }
        }
      }
    });

    return ok;
  }

  void syncPeerProgramRuntimeRouting(BPFProgram *program)
  {
    if (program == nullptr)
    {
      return;
    }

    program->openMap("ext_portals"_ctv, [&](int map_fd) -> void {
      clearHashMapFD<portal_definition>(map_fd, "ext_portals");
    });

    program->openMap("wh_targets"_ctv, [&](int map_fd) -> void {
      clearHashMapFD<switchboard_wormhole_target_key>(map_fd, "wh_targets");
    });

    program->openMap("quic_cid_dec"_ctv, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        return;
      }

      quic_cid_aes_decrypt_state emptyState = {};
      for (uint32_t mapIndex = 0; mapIndex < (MAX_PORTALS * 2); ++mapIndex)
      {
        if (bpf_map_update_elem(map_fd, &mapIndex, &emptyState, BPF_ANY) != 0)
        {
          basics_log("Switchboard quic_cid_dec clear failed scope=peer-runtime-sync ifidx=%u errno=%d index=%u\n",
                     eth.ifidx,
                     errno,
                     mapIndex);
        }
      }
    });

    for (SwitchboardPortal *portal : portals)
    {
      syncPortalDefinitionForProgram(program, portal);
      if (generateRingForPortalOnProgram(program, portal) == false)
      {
        basics_log("Switchboard peer-runtime-sync cid_rings install failed ifidx=%u slot=%u\n", eth.ifidx, unsigned(portal->slot));
      }
      installPortalQuicCidDecryptStateForProgram(program, portal);
    }

    (void)syncPortalTargetBindingsForProgram(program, "peer-runtime-sync");

    Vector<SwitchboardWormholeEgressBindingEntry> desiredBindings = {};
    Vector<SwitchboardWormholeEgress4BindingEntry> desiredBindings4 = {};
    collectWormholeEgressBindingEntries(desiredBindings, desiredBindings4);
    switchboardSyncWormholeEgressBindingsForProgram(program, desiredBindings, eth.ifidx, "peer-runtime-sync");
    switchboardSyncWormholeEgress4BindingsForProgram(program, desiredBindings4, eth.ifidx, "peer-runtime-sync");
  }

  // Every Switchboard entry point must carry the same portal, target, and
  // overlay routing state. Packets may enter through any Switchboard instance;
  // the selected final destination must not depend on that entry point.
  void syncHostIngressPortalRouting(void)
  {
#if NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE
    if (host_ingress == nullptr)
    {
      return;
    }

    host_ingress->openMap("ext_portals"_ctv, [&](int map_fd) -> void {
      clearHashMapFD<portal_definition>(map_fd, "ext_portals");
    });

    host_ingress->openMap("wh_targets"_ctv, [&](int map_fd) -> void {
      clearHashMapFD<switchboard_wormhole_target_key>(map_fd, "wh_targets");
    });

    host_ingress->openMap("quic_cid_dec"_ctv, [&](int map_fd) -> void {
      if (map_fd < 0)
      {
        return;
      }

      quic_cid_aes_decrypt_state emptyState = {};
      for (uint32_t mapIndex = 0; mapIndex < (MAX_PORTALS * 2); ++mapIndex)
      {
        if (bpf_map_update_elem(map_fd, &mapIndex, &emptyState, BPF_ANY) != 0)
        {
          basics_log("Switchboard quic_cid_dec clear failed scope=host-ingress-sync ifidx=%u errno=%d index=%u\n",
                     eth.ifidx,
                     errno,
                     mapIndex);
        }
      }
    });

    for (SwitchboardPortal *portal : portals)
    {
      syncPortalDefinitionForProgram(host_ingress, portal);
      if (generateRingForPortalOnProgram(host_ingress, portal) == false)
      {
        basics_log("Switchboard host-ingress-sync cid_rings install failed ifidx=%u slot=%u\n", eth.ifidx, unsigned(portal->slot));
      }
      installPortalQuicCidDecryptStateForProgram(host_ingress, portal);
    }

    (void)syncPortalTargetBindingsForProgram(host_ingress, "host-ingress-sync");
#endif
  }

  void syncAllPeerProgramRuntimeRouting(void)
  {
    forEachActivePeerProgram([&](BPFProgram *program) -> void {
      syncPeerProgramRuntimeRouting(program);
    });
  }

  void closeWormhole(switchboard_runtime::Wormhole *wormhole)
  {
    if (wormhole == nullptr)
    {
      return;
    }

    SwitchboardPortal *portal = wormhole->portal;
    removeWormholeTargetBinding(wormhole);
    portal->wormholes.erase(wormhole);

    if (portal->wormholes.empty())
    {
      if (bpf_router)
      {
        removePortalDefinitionForProgram(bpf_router, portal);
      }

      clearPortalQuicCidDecryptState(portal->slot);
      portalSlots.push_back(portal->slot);
      portals.erase(portal);
      forEachActivePeerProgram([&](BPFProgram *program) -> void {
        removePortalDefinitionForProgram(program, portal);
        clearPortalQuicCidDecryptStateForProgram(program, portal->slot);
      });
      delete portal;
    }
    else
    {
      generateRingForPortal(portal);
    }

    syncAllPeerProgramRuntimeRouting();
    syncHostIngressPortalRouting();
    delete wormhole;
  }

  void replaceTrackedRoutableSubnets(const Vector<DistributableExternalSubnet>& desiredSubnets)
  {
    routableSubnets.clear();

    for (const DistributableExternalSubnet& subnet : desiredSubnets)
    {
      routableSubnets.push_back(subnet);
    }

    rebuildAnnouncingPrefixes();
  }

  void rebuildAnnouncingPrefixes(void)
  {
    announcingPrefixes.clear();

    for (const DistributableExternalSubnet& subnet : routableSubnets)
    {
      announcingPrefixes.push_back(distributableExternalSubnetSwitchboardSubnet(subnet));
    }

    for (const IPPrefix& prefix : hostedIngressPrefixes)
    {
      announcingPrefixes.push_back(prefix);
    }
  }

public:

  explicit Switchboard(EthDevice& thisEth)
      : eth(thisEth)
  {
    portalSlots.reserve(MAX_PORTALS);
    for (uint32_t i = 0; i < MAX_PORTALS; i++)
    {
      portalSlots.push_back(i);
    }
  }

  ~Switchboard()
  {
    resetState();
  }

  void setHostEgressRouter(BPFProgram *program)
  {
    host_egress = program;

    Vector<SwitchboardWormholeEgressBindingEntry> desiredBindings = {};
    Vector<SwitchboardWormholeEgress4BindingEntry> desiredBindings4 = {};
    collectWormholeEgressBindingEntries(desiredBindings, desiredBindings4);
    switchboardSyncWormholeEgressBindingsForProgram(host_egress, desiredBindings, eth.ifidx, "host-egress-sync");
    switchboardSyncWormholeEgress4BindingsForProgram(host_egress, desiredBindings4, eth.ifidx, "host-egress-sync");
  }

  void setHostIngressRouter(BPFProgram *program)
  {
#if NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE
    host_ingress = program;
    syncHostIngressPortalRouting();
#else
    (void)program;
#endif
  }

  void syncPeerProgramRuntimeState(BPFProgram *program)
  {
    syncPeerProgramRuntimeRouting(program);
  }

  BPFProgram *boundaryRouterProgram(void)
  {
    return bpf_router;
  }

  void setLocalContainerSubnet(const struct local_container_subnet6& newSubnet)
  {
    subnet = newSubnet;
    appendAttachLogf("Switchboard setLocalContainerSubnet ifidx=%u dpfx=%u mpfx=%u.%u.%u",
                     eth.ifidx,
                     unsigned(subnet.dpfx),
                     unsigned(subnet.mpfx[0]),
                     unsigned(subnet.mpfx[1]),
                     unsigned(subnet.mpfx[2]));
    syncBoundaryMaps();

    for (SwitchboardPortal *portal : portals)
    {
      if (generateRingForPortal(portal) == false)
      {
        basics_log("Switchboard setLocalContainerSubnet cid_rings refresh failed ifidx=%u slot=%u\n",
                   eth.ifidx,
                   portal ? unsigned(portal->slot) : 0);
      }
    }

    syncHostIngressPortalRouting();
    syncAllPeerProgramRuntimeRouting();
  }

  void resetState(void)
  {
    while (wormholesByContainer.size() > 0)
    {
      auto it = wormholesByContainer.begin();
      closeWormholesToContainer(it->first);
    }

    while (whiteholesByContainer.size() > 0)
    {
      auto it = whiteholesByContainer.begin();
      closeWhiteholesToContainer(it->first);
    }

    Vector<DistributableExternalSubnet> noSubnets;
    hostedIngressPrefixes.clear();
    replaceTrackedRoutableSubnets(noSubnets);
    maybeDetachBoundaryRouter();
  }

  void setRoutableSubnets(const Vector<DistributableExternalSubnet>& desiredSubnets)
  {
    replaceTrackedRoutableSubnets(desiredSubnets);
    appendAttachLogf("Switchboard setRoutableSubnets ifidx=%u count=%u announcing=%u",
                     eth.ifidx,
                     unsigned(routableSubnets.size()),
                     unsigned(announcingPrefixes.size()));
    syncOwnedRoutablePrefixMaps();

    maybeDetachBoundaryRouter();
  }

  void setHostedIngressPrefixes(const Vector<IPPrefix>& desiredPrefixes)
  {
    hostedIngressPrefixes = desiredPrefixes;
    basics_log("Switchboard setHostedIngressPrefixes count=%u\n", unsigned(hostedIngressPrefixes.size()));
    appendAttachLogf("Switchboard setHostedIngressPrefixes ifidx=%u count=%u",
                     eth.ifidx,
                     unsigned(hostedIngressPrefixes.size()));
    rebuildAnnouncingPrefixes();
    syncOwnedRoutablePrefixMaps();
    maybeDetachBoundaryRouter();
  }

  void closeWormholesToContainer(uint32_t containerID)
  {
    if (auto it = wormholesByContainer.find(containerID); it != wormholesByContainer.end())
    {
      for (switchboard_runtime::Wormhole *wormhole : it->second)
      {
        closeWormhole(wormhole);
      }

      wormholesByContainer.erase(it);
    }

    maybeDetachBoundaryRouter();
  }

  void closeWhiteholesToContainer(uint32_t containerID)
  {
    if (auto it = whiteholesByContainer.find(containerID); it != whiteholesByContainer.end())
    {
      for (switchboard_runtime::Whitehole *whitehole : it->second)
      {
        delete whitehole;
      }

      whiteholesByContainer.erase(it);
      syncWhiteholeBindingsMap();
    }

    maybeDetachBoundaryRouter();
  }

  bool openWormhole(uint32_t containerID, const Wormhole& requestedWormhole)
  {
    if (ensureBoundaryRouterConfigured() == false)
    {
      basics_log("Switchboard openWormhole boundary-router-unavailable containerID=%u port=%u proto=%u\n",
                 containerID,
                 unsigned(requestedWormhole.externalPort),
                 unsigned(requestedWormhole.layer4));
      return false;
    }

    SwitchboardPortal *portal = nullptr;
    const IPAddress& switchboardAddress = wormholeSwitchboardAddress(requestedWormhole);
    bool createdPortal = false;

    SwitchboardPortal query;
    query.address = switchboardAddress;
    query.port = requestedWormhole.externalPort;
    query.proto = requestedWormhole.layer4;
    query.isQuic = requestedWormhole.isQuic;

    if (auto it = portals.find(&query); it != portals.end())
    {
      portal = *it;
      applyPortalQuicCidStateFromWormhole(portal, requestedWormhole);
    }
    else
    {
      bool prefixAnnounced = false;
      for (const IPPrefix& prefix : announcingPrefixes)
      {
        if (prefix.containsAddress(switchboardAddress))
        {
          prefixAnnounced = true;
          break;
        }
      }

      if (prefixAnnounced == false)
      {
        basics_log("Switchboard openWormhole prefix-not-announced containerID=%u port=%u proto=%u announcing=%u\n",
                   containerID,
                   unsigned(requestedWormhole.externalPort),
                   unsigned(requestedWormhole.layer4),
                   unsigned(announcingPrefixes.size()));
        return false;
      }

      portal = new SwitchboardPortal();
      portal->address = switchboardAddress;
      portal->port = requestedWormhole.externalPort;
      portal->proto = requestedWormhole.layer4;
      portal->isQuic = requestedWormhole.isQuic;
      portal->slot = portalSlots.back();
      portalSlots.pop_back();
      applyPortalQuicCidStateFromWormhole(portal, requestedWormhole);

      portals.insert(portal);
      createdPortal = true;

      if (syncPortalDefinitionForProgram(bpf_router, portal) == false)
      {
        basics_log("Switchboard openWormhole failed required ext_portals install ifidx=%u containerID=%u slot=%u port=%u proto=%u\n",
                   eth.ifidx,
                   containerID,
                   unsigned(portal->slot),
                   unsigned(portal->port),
                   unsigned(portal->proto));
        appendAttachLogf("Switchboard openWormhole failed required ext_portals install ifidx=%u containerID=%u slot=%u port=%u proto=%u",
                         eth.ifidx,
                         containerID,
                         unsigned(portal->slot),
                         unsigned(portal->port),
                         unsigned(portal->proto));
        portals.erase(portal);
        portalSlots.push_back(portal->slot);
        delete portal;
        return false;
      }

      basics_log("Switchboard openWormhole portal-installed containerID=%u slot=%u port=%u proto=%u quic=%u\n",
                 containerID,
                 unsigned(portal->slot),
                 unsigned(portal->port),
                 unsigned(portal->proto),
                 unsigned(portal->isQuic));
    }

    if (portal->isQuic && portal->hasQuicCidKeyState)
    {
      installPortalQuicCidDecryptState(portal);
    }

    switchboard_runtime::Wormhole *wormhole = new switchboard_runtime::Wormhole();
    wormhole->containerID = containerID;
    wormhole->port = requestedWormhole.containerPort;
    wormhole->proto = requestedWormhole.layer4;
    wormhole->userCapacity = requestedWormhole.userCapacity;
    wormhole->weight = serviceUserCapacityPlanningWeight(requestedWormhole.userCapacity);
    wormhole->portal = portal;

    if (installWormholeTargetBinding(portal, wormhole, requestedWormhole) == false)
    {
      basics_log("Switchboard openWormhole failed required target/egress map install ifidx=%u containerID=%u slot=%u port=%u proto=%u\n",
                 eth.ifidx,
                 containerID,
                 unsigned(portal->slot),
                 unsigned(portal->port),
                 unsigned(portal->proto));
      appendAttachLogf("Switchboard openWormhole failed required target/egress map install ifidx=%u containerID=%u slot=%u port=%u proto=%u",
                       eth.ifidx,
                       containerID,
                       unsigned(portal->slot),
                       unsigned(portal->port),
                       unsigned(portal->proto));
      removeWormholeTargetBinding(wormhole);
      if (createdPortal)
      {
        removePortalDefinitionForProgram(bpf_router, portal);
        portals.erase(portal);
        portalSlots.push_back(portal->slot);
        delete portal;
      }
      delete wormhole;
      return false;
    }

    wormholesByContainer.emplace(containerID, wormhole);
    portal->wormholes.insert(wormhole);

    if (generateRingForPortal(portal) == false)
    {
      basics_log("Switchboard openWormhole failed required cid_rings install ifidx=%u containerID=%u slot=%u port=%u proto=%u\n",
                 eth.ifidx,
                 containerID,
                 unsigned(portal->slot),
                 unsigned(portal->port),
                 unsigned(portal->proto));
      appendAttachLogf("Switchboard openWormhole failed required cid_rings install ifidx=%u containerID=%u slot=%u port=%u proto=%u",
                       eth.ifidx,
                       containerID,
                       unsigned(portal->slot),
                       unsigned(portal->port),
                       unsigned(portal->proto));
      closeWormhole(wormhole);
      return false;
    }

    syncHostIngressPortalRouting();
    syncAllPeerProgramRuntimeRouting();
    return true;
  }

  void openWormholes(uint32_t containerID, const Vector<Wormhole>& wormholes)
  {
    appendAttachLogf("Switchboard openWormholes begin ifidx=%u containerID=%u requested=%u announcing=%u dpfx=%u",
                     eth.ifidx,
                     containerID,
                     unsigned(wormholes.size()),
                     unsigned(announcingPrefixes.size()),
                     unsigned(subnet.dpfx));
    if (wormholesByContainer.contains(containerID))
    {
      closeWormholesToContainer(containerID);
    }

    uint32_t opened = 0;
    for (const Wormhole& wormhole : wormholes)
    {
      opened += openWormhole(containerID, wormhole) ? 1U : 0U;
    }

    basics_log("Switchboard openWormholes containerID=%u requested=%u opened=%u\n",
               containerID,
               unsigned(wormholes.size()),
               unsigned(opened));
    if (opened != uint32_t(wormholes.size()))
    {
      basics_log("Switchboard openWormholes failed containerID=%u requested=%u opened=%u ifidx=%u\n",
                 containerID,
                 unsigned(wormholes.size()),
                 unsigned(opened),
                 eth.ifidx);
    }
    appendAttachLogf("Switchboard openWormholes done ifidx=%u containerID=%u requested=%u opened=%u",
                     eth.ifidx,
                     containerID,
                     unsigned(wormholes.size()),
                     unsigned(opened));
  }

  bool openWhitehole(uint32_t containerID, const Whitehole& whitehole)
  {
    if (ensureBoundaryRouterConfigured() == false)
    {
      return false;
    }

    portal_definition key = {};
    switchboard_whitehole_binding binding = {};
    if (switchboardBuildWhiteholeBinding(whitehole, containerID, subnet, key, binding) == false)
    {
      return false;
    }

    bool prefixAnnounced = false;
    for (const IPPrefix& prefix : announcingPrefixes)
    {
      if (prefix.containsAddress(whitehole.address))
      {
        prefixAnnounced = true;
        break;
      }
    }

    if (prefixAnnounced == false)
    {
      return false;
    }

    switchboard_runtime::Whitehole *tracked = new switchboard_runtime::Whitehole();
    tracked->containerID = containerID;
    tracked->address = whitehole.address;
    tracked->port = whitehole.sourcePort;
    tracked->proto = switchboardTransportProtocol(whitehole.transport);
    tracked->nonce = whitehole.bindingNonce;
    whiteholesByContainer.emplace(containerID, tracked);
    syncWhiteholeBindingsMap();
    return true;
  }

  void openWhiteholes(uint32_t containerID, const Vector<Whitehole>& whiteholes)
  {
    if (whiteholesByContainer.contains(containerID))
    {
      closeWhiteholesToContainer(containerID);
    }

    for (const Whitehole& whitehole : whiteholes)
    {
      if (whitehole.hasAddress == false || whitehole.sourcePort == 0 || whitehole.bindingNonce == 0)
      {
        continue;
      }

      (void)openWhitehole(containerID, whitehole);
    }
  }
};
