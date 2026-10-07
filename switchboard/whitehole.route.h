#pragma once

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <array>
#include <mutex>
#include <services/bitsery.h>
#include <services/debug.h>
#include <unistd.h>

#include <ebpf/common/structs.h>

#include <prodigy/types.h>
#include <switchboard/common/constants.h>
#include <switchboard/common/structs.h>
#include <switchboard/kernel/structs.h>

static constexpr uint32_t switchboardDevelopmentWhiteholeMapEntries = 4096;

static inline void switchboardConfigureDevelopmentWhiteholeMapAllocation(struct bpf_object *object)
{
  const char *devMode = std::getenv("PRODIGY_DEV_MODE");
  if (object == nullptr || devMode == nullptr || std::strcmp(devMode, "1") != 0)
  {
    return;
  }

  static constexpr std::array<const char *, 3> mapNames = {"wh_targets", "wh_egress", "wh_egress4"};
  for (const char *mapName : mapNames)
  {
    struct bpf_map *map = bpf_object__find_map_by_name(object, mapName);
    if (map &&
        (bpf_map__set_max_entries(map, switchboardDevelopmentWhiteholeMapEntries) != 0 ||
         bpf_map__set_map_flags(map, bpf_map__map_flags(map) | BPF_F_NO_PREALLOC) != 0))
    {
      basics_log("Switchboard failed to configure bounded sparse development map name=%s errno=%d\n", mapName, errno);
    }
  }
}

static constexpr bool switchboardPortalCountWithinCapacity(uint64_t count)
{
  return count <= MAX_PORTALS;
}

static String switchboardSerializeWormholeFleet(const Vector<Wormhole>& wormholes)
{
  Vector<Wormhole> copy = wormholes;
  String serialized = {};
  BitseryEngine::serialize(serialized, copy);
  return serialized;
}

template <typename Open, typename Restore, typename Close>
static SwitchboardWormholeOperationStatus switchboardReplaceWormholesTransaction(const Vector<Wormhole>& previous,
                                                                                  const Vector<Wormhole>& desired,
                                                                                  Open&& open,
                                                                                  Restore&& restore,
                                                                                  Close&& close)
{
  close();
  for (const Wormhole& wormhole : desired)
  {
    if (open(wormhole))
    {
      continue;
    }

    close();
    for (const Wormhole& prior : previous)
    {
      if (restore(prior) == false)
      {
        close();
        return SwitchboardWormholeOperationStatus::rollbackFailed;
      }
    }
    return SwitchboardWormholeOperationStatus::rejected;
  }
  return SwitchboardWormholeOperationStatus::applied;
}

template <typename Open, typename Close>
static SwitchboardWormholeOperationStatus switchboardReplaceWormholesTransaction(const Vector<Wormhole>& previous,
                                                                                  const Vector<Wormhole>& desired,
                                                                                  Open&& open,
                                                                                  Close&& close)
{
  return switchboardReplaceWormholesTransaction(previous, desired, open, open, close);
}

struct SwitchboardWormholeFlowMapGCCursor {
  switchboard_wormhole_flow_key batch = {};
  switchboard_wormhole_flow_key deferred = {};
  bool active = false;
  bool deferredExpired = false;
};

struct SwitchboardWormholeFlowGCCursor {
  SwitchboardWormholeFlowMapGCCursor established = {};
  SwitchboardWormholeFlowMapGCCursor pending = {};
};

struct SwitchboardPairAdmissionGCCursor {
  switchboard_pair_admission_grant_key grantBatch = {};
  switchboard_pair_admission_route_key routeBatch = {};
  bool grantActive = false;
  bool routeActive = false;
};

static inline bool switchboardPortalDefinitionEquals(const portal_definition& lhs, const portal_definition& rhs)
{
  return lhs.port == rhs.port && lhs.proto == rhs.proto && std::memcmp(lhs.addr6, rhs.addr6, sizeof(lhs.addr6)) == 0;
}

static inline bool switchboardWhiteholeBindingEquals(const switchboard_whitehole_binding& lhs, const switchboard_whitehole_binding& rhs)
{
  return lhs.nonce == rhs.nonce && lhs.container.hasID == rhs.container.hasID && std::memcmp(lhs.container.value, rhs.container.value, sizeof(lhs.container.value)) == 0;
}

static inline uint8_t switchboardTransportProtocol(ExternalAddressTransport transport)
{
  return (transport == ExternalAddressTransport::quic) ? uint8_t(IPPROTO_UDP) : uint8_t(IPPROTO_TCP);
}

static inline uint16_t switchboardPortalKeyPort(uint16_t hostPort)
{
  return htons(hostPort);
}

static inline bool switchboardMakeWhiteholeBindingKey(const IPAddress& address, uint16_t sourcePort, ExternalAddressTransport transport, portal_definition& key)
{
  key = {};
  if (address.isNull() || sourcePort == 0)
  {
    return false;
  }

  std::memcpy(key.addr6, address.v6, sizeof(key.addr6));
  key.port = switchboardPortalKeyPort(sourcePort);
  key.proto = switchboardTransportProtocol(transport);
  return true;
}

static inline bool switchboardBuildWhiteholeBindingValue(uint32_t containerID, const local_container_subnet6& subnet, uint64_t nonce, switchboard_whitehole_binding& binding)
{
  binding = {};
  if (subnet.dpfx == 0 || containerID == 0 || nonce == 0)
  {
    return false;
  }

  binding.container.hasID = true;
  binding.container.value[0] = subnet.dpfx;
  binding.container.value[1] = uint8_t((containerID >> 16) & 0xffu);
  binding.container.value[2] = uint8_t((containerID >> 8) & 0xffu);
  binding.container.value[3] = uint8_t(containerID & 0xffu);
  binding.container.value[4] = uint8_t((containerID >> 24) & 0xffu);
  binding.nonce = nonce;
  return true;
}

static inline bool switchboardBuildWhiteholeBinding(const Whitehole& whitehole,
                                                    uint32_t containerID,
                                                    const local_container_subnet6& subnet,
                                                    portal_definition& key,
                                                    switchboard_whitehole_binding& binding)
{
  if (switchboardMakeWhiteholeBindingKey(whitehole.address, whitehole.sourcePort, whitehole.transport, key) == false)
  {
    return false;
  }

  return switchboardBuildWhiteholeBindingValue(containerID, subnet, whitehole.bindingNonce, binding);
}

static inline void switchboardWhiteholeReplyFlowPinPath(String& path, uint32_t ifindex)
{
  path.snprintf<"/sys/fs/bpf/prodigy_whitehole_reply_flows_{itoa}"_ctv>(ifindex);
}

static inline void switchboardWormholeFlowPinPath(String& path, uint32_t ifindex)
{
  path.snprintf<"/sys/fs/bpf/prodigy_wormhole_flows_{itoa}"_ctv>(ifindex);
}

static inline void switchboardWormholePendingFlowPinPath(String& path, uint32_t ifindex)
{
  path.snprintf<"/sys/fs/bpf/prodigy_wormhole_pending_flows_{itoa}"_ctv>(ifindex);
}

static inline void switchboardPairAdmissionGrantPinPath(String& path, uint32_t ifindex)
{
  path.snprintf<"/sys/fs/bpf/prodigy_pair_admission_grants_{itoa}"_ctv>(ifindex);
}

static inline void switchboardPairAdmissionRoutePinPath(String& path, uint32_t ifindex)
{
  path.snprintf<"/sys/fs/bpf/prodigy_pair_admission_routes_{itoa}"_ctv>(ifindex);
}

static inline uint32_t switchboardKernelMapID(int fd)
{
  struct bpf_map_info info = {};
  __u32 bytes = sizeof(info);
  return fd >= 0 && bpf_map_get_info_by_fd(fd, &info, &bytes) == 0 ? uint32_t(info.id) : 0u;
}

static inline bool switchboardWormholeEstablishedFlowMapCompatibleFD(int fd)
{
  struct bpf_map_info info = {};
  __u32 bytes = sizeof(info);
  return fd >= 0 && bpf_map_get_info_by_fd(fd, &info, &bytes) == 0 &&
         info.type == BPF_MAP_TYPE_HASH &&
         info.key_size == sizeof(switchboard_wormhole_flow_key) &&
         info.value_size == sizeof(switchboard_wormhole_flow) &&
         info.max_entries == WORMHOLE_FLOW_MAX_ENTRIES &&
         (info.map_flags & BPF_F_NO_PREALLOC) != 0;
}

static inline bool switchboardWormholePendingFlowMapCompatibleFD(int fd)
{
  struct bpf_map_info info = {};
  __u32 bytes = sizeof(info);
  return fd >= 0 && bpf_map_get_info_by_fd(fd, &info, &bytes) == 0 &&
         info.type == BPF_MAP_TYPE_LRU_HASH &&
         info.key_size == sizeof(switchboard_wormhole_flow_key) &&
         info.value_size == sizeof(switchboard_wormhole_flow) &&
         info.max_entries == WORMHOLE_PENDING_FLOW_MAX_ENTRIES;
}

static inline bool switchboardPairAdmissionGrantMapCompatibleFD(int fd)
{
  struct bpf_map_info info = {};
  __u32 bytes = sizeof(info);
  return fd >= 0 && bpf_map_get_info_by_fd(fd, &info, &bytes) == 0 && info.type == BPF_MAP_TYPE_HASH &&
         info.key_size == sizeof(switchboard_pair_admission_grant_key) &&
         info.value_size == sizeof(switchboard_pair_admission_grant) && info.max_entries == WORMHOLE_PENDING_FLOW_MAX_ENTRIES &&
         (info.map_flags & BPF_F_NO_PREALLOC) != 0;
}

static inline bool switchboardPairAdmissionRouteMapCompatibleFD(int fd)
{
  struct bpf_map_info info = {};
  __u32 bytes = sizeof(info);
  return fd >= 0 && bpf_map_get_info_by_fd(fd, &info, &bytes) == 0 && info.type == BPF_MAP_TYPE_HASH &&
         info.key_size == sizeof(switchboard_pair_admission_route_key) &&
         info.value_size == sizeof(switchboard_pair_admission_route_policy) && info.max_entries == 1024;
}

static inline bool switchboardPinnedWormholeFlowMapsCompatible(uint32_t ifindex)
{
  if (ifindex == 0)
  {
    return false;
  }
  String establishedPath = {};
  String pendingPath = {};
  String grantPath = {};
  String routePath = {};
  switchboardWormholeFlowPinPath(establishedPath, ifindex);
  switchboardWormholePendingFlowPinPath(pendingPath, ifindex);
  switchboardPairAdmissionGrantPinPath(grantPath, ifindex);
  switchboardPairAdmissionRoutePinPath(routePath, ifindex);
  int establishedFD = bpf_obj_get(establishedPath.c_str());
  int pendingFD = bpf_obj_get(pendingPath.c_str());
  int grantFD = bpf_obj_get(grantPath.c_str());
  int routeFD = bpf_obj_get(routePath.c_str());
  bool compatible = switchboardWormholeEstablishedFlowMapCompatibleFD(establishedFD) &&
                    switchboardWormholePendingFlowMapCompatibleFD(pendingFD) &&
                    switchboardPairAdmissionGrantMapCompatibleFD(grantFD) &&
                    switchboardPairAdmissionRouteMapCompatibleFD(routeFD);
  if (establishedFD >= 0)
  {
    ::close(establishedFD);
  }
  if (pendingFD >= 0)
  {
    ::close(pendingFD);
  }
  if (grantFD >= 0) ::close(grantFD);
  if (routeFD >= 0) ::close(routeFD);
  return compatible;
}

template <typename Program>
static inline bool switchboardProgramHasCompatibleWormholeFlowMaps(Program *program)
{
  bool established = false;
  bool pending = false;
  bool grants = false;
  bool routes = false;
  if (program)
  {
    program->openMap("wh_flows"_ctv, [&](int mapFD) -> void {
      established = switchboardWormholeEstablishedFlowMapCompatibleFD(mapFD);
    });
    program->openMap("wh_pending"_ctv, [&](int mapFD) -> void {
      pending = switchboardWormholePendingFlowMapCompatibleFD(mapFD);
    });
    program->openMap("wh_pair_grants"_ctv, [&](int mapFD) -> void {
      grants = switchboardPairAdmissionGrantMapCompatibleFD(mapFD);
    });
    program->openMap("wh_pair_routes"_ctv, [&](int mapFD) -> void {
      routes = switchboardPairAdmissionRouteMapCompatibleFD(mapFD);
    });
  }
  return established && pending && grants && routes;
}

template <typename Program>
static inline bool switchboardCleanupExpiredWormholeFlowMap(Program *program,
                                                             const char *mapName,
                                                             bool (*compatible)(int),
                                                             uint64_t reclaimBeforeNs,
                                                             SwitchboardWormholeFlowMapGCCursor& cursor,
                                                             uint32_t& deleted)
{
  bool cleaned = false;
  program->openMap(String(mapName), [&](int mapFD) -> void {
    if (compatible(mapFD) == false)
    {
      return;
    }

    static thread_local std::array<switchboard_wormhole_flow_key, WORMHOLE_FLOW_GC_BATCH_SIZE> keys = {};
    static thread_local std::array<switchboard_wormhole_flow, WORMHOLE_FLOW_GC_BATCH_SIZE> values = {};
    switchboard_wormhole_flow_key nextBatch = {};
    __u32 count = WORMHOLE_FLOW_GC_BATCH_SIZE;
    errno = 0;
    int result = bpf_map_lookup_batch(mapFD,
                                      cursor.active ? &cursor.batch : nullptr,
                                      &nextBatch,
                                      keys.data(),
                                      values.data(),
                                      &count,
                                      nullptr);
    int lookupErrno = errno;
    // Packet paths never replace an expired key. Physical deletion trails the
    // logical deadline by a full non-sleeping BPF execution grace, then re-reads
    // under the single-sweeper lock so a completed pre-deadline refresh wins.
    if (result != 0 && lookupErrno != ENOENT)
    {
      if (cursor.deferredExpired)
      {
        switchboard_wormhole_flow current = {};
        if (bpf_map_lookup_elem(mapFD, &cursor.deferred, &current) == 0 && current.expiresAtNs <= reclaimBeforeNs)
        {
          deleted += bpf_map_delete_elem(mapFD, &cursor.deferred) == 0 ? 1u : 0u;
        }
      }
      cursor = {};
      basics_log("Switchboard %s batch gc failed errno=%d\n", mapName, lookupErrno);
      return;
    }

    if (cursor.deferredExpired)
    {
      switchboard_wormhole_flow current = {};
      if (bpf_map_lookup_elem(mapFD, &cursor.deferred, &current) == 0 && current.expiresAtNs <= reclaimBeforeNs)
      {
        deleted += bpf_map_delete_elem(mapFD, &cursor.deferred) == 0 ? 1u : 0u;
      }
    }
    cursor.deferredExpired = false;

    const bool more = result == 0 && count != 0;
    for (__u32 index = 0; index < count; ++index)
    {
      if (values[index].expiresAtNs > reclaimBeforeNs)
      {
        continue;
      }

      if (more && index + 1 == count)
      {
        cursor.deferred = keys[index];
        cursor.deferredExpired = true;
      }
      else
      {
        switchboard_wormhole_flow current = {};
        if (bpf_map_lookup_elem(mapFD, &keys[index], &current) == 0 && current.expiresAtNs <= reclaimBeforeNs)
        {
          deleted += bpf_map_delete_elem(mapFD, &keys[index]) == 0 ? 1u : 0u;
        }
      }
    }

    cursor.active = more;
    if (more)
    {
      cursor.batch = nextBatch;
    }
    cleaned = true;
  });
  return cleaned;
}

template <typename Program>
static inline bool switchboardCleanupExpiredWormholeFlows(Program *program,
                                                          uint64_t nowNs,
                                                          SwitchboardWormholeFlowGCCursor& cursor,
                                                          uint32_t *deletedCount = nullptr)
{
  if (program == nullptr || nowNs == 0)
  {
    return false;
  }

  // Conditional hash deletion is unavailable. One process-wide sweeper avoids
  // an ABA where a second cursor could delete a live owner reinserted by BPF.
  static std::mutex sweepMutex;
  const std::lock_guard<std::mutex> sweepGuard(sweepMutex);
  const uint64_t reclaimBeforeNs = nowNs > WORMHOLE_FLOW_RECLAIM_GRACE_NS
                                       ? nowNs - WORMHOLE_FLOW_RECLAIM_GRACE_NS
                                       : 0;

  uint32_t deleted = 0;
  bool establishedCleaned = switchboardCleanupExpiredWormholeFlowMap(program,
                                                                      "wh_flows",
                                                                      switchboardWormholeEstablishedFlowMapCompatibleFD,
                                                                      reclaimBeforeNs,
                                                                      cursor.established,
                                                                      deleted);
  bool pendingCleaned = switchboardCleanupExpiredWormholeFlowMap(program,
                                                                  "wh_pending",
                                                                  switchboardWormholePendingFlowMapCompatibleFD,
                                                                  reclaimBeforeNs,
                                                                  cursor.pending,
                                                                  deleted);

  if (deletedCount)
  {
    *deletedCount = deleted;
  }
  return establishedCleaned && pendingCleaned;
}

template <typename Program>
static inline bool switchboardCleanupExpiredPairAdmissionMaps(Program *program,
                                                              uint64_t nowNs,
                                                              SwitchboardPairAdmissionGCCursor& cursor,
                                                              uint32_t *deletedCount = nullptr)
{
  if (program == nullptr || nowNs == 0)
  {
    return false;
  }
  uint32_t deleted = 0;
  bool grantsCleaned = false;
  bool routesCleaned = false;
  program->openMap("wh_pair_routes"_ctv, [&](int routeFD) -> void {
    if (switchboardPairAdmissionRouteMapCompatibleFD(routeFD) == false) return;
    program->openMap("wh_pair_grants"_ctv, [&](int mapFD) -> void {
      if (switchboardPairAdmissionGrantMapCompatibleFD(mapFD) == false) return;
      static thread_local std::array<switchboard_pair_admission_grant_key, WORMHOLE_FLOW_GC_BATCH_SIZE> keys = {};
      static thread_local std::array<switchboard_pair_admission_grant, WORMHOLE_FLOW_GC_BATCH_SIZE> values = {};
      switchboard_pair_admission_grant_key next = {};
      __u32 count = WORMHOLE_FLOW_GC_BATCH_SIZE;
      int result = bpf_map_lookup_batch(mapFD, cursor.grantActive ? &cursor.grantBatch : nullptr, &next,
                                        keys.data(), values.data(), &count, nullptr);
      if (result != 0 && errno != ENOENT) return;
      for (__u32 i = 0; i < count; ++i)
      {
        const switchboard_pair_admission_grant& grant = values[i];
        const __u32 state = grant.state;
        // Pending grants inherit the exact route policy's renewable lease;
        // their immutable initial expiry is only the installation fence.
        // Never retain malformed consumption states, and retain a consumed
        // grant only for its separately bounded established-session window.
        bool reclaim = state == SWITCHBOARD_PAIR_ADMISSION_CONSUMED ? grant.consumed_expires_at_ns <= nowNs
                                                                     : state != SWITCHBOARD_PAIR_ADMISSION_PENDING;
        switchboard_pair_admission_route_key routeKey = {grant.pair_uuid_hi, grant.pair_uuid_lo, grant.route_uuid_hi, grant.route_uuid_lo};
        switchboard_pair_admission_route_policy route = {};
        bool routeCurrent = bpf_map_lookup_elem(routeFD, &routeKey, &route) == 0 &&
                            route.expires_at_ns > nowNs && route.state != SWITCHBOARD_PAIR_ADMISSION_ROUTE_REVOKED &&
                            route.route_generation == grant.route_generation && route.root_generation == grant.root_generation &&
                            route.key_epoch == grant.key_epoch;
        if (reclaim || routeCurrent == false)
          deleted += bpf_map_delete_elem(mapFD, &keys[i]) == 0 ? 1u : 0u;
      }
      cursor.grantActive = result == 0 && count != 0;
      if (cursor.grantActive) cursor.grantBatch = next;
      grantsCleaned = true;
    });
  });
  program->openMap("wh_pair_routes"_ctv, [&](int mapFD) -> void {
    if (switchboardPairAdmissionRouteMapCompatibleFD(mapFD) == false) return;
    static thread_local std::array<switchboard_pair_admission_route_key, 1024> keys = {};
    static thread_local std::array<switchboard_pair_admission_route_policy, 1024> values = {};
    switchboard_pair_admission_route_key next = {};
    __u32 count = 1024;
    int result = bpf_map_lookup_batch(mapFD, cursor.routeActive ? &cursor.routeBatch : nullptr, &next,
                                      keys.data(), values.data(), &count, nullptr);
    if (result != 0 && errno != ENOENT) return;
    for (__u32 i = 0; i < count; ++i)
      if (values[i].expires_at_ns <= nowNs) deleted += bpf_map_delete_elem(mapFD, &keys[i]) == 0 ? 1u : 0u;
    cursor.routeActive = result == 0 && count != 0;
    if (cursor.routeActive) cursor.routeBatch = next;
    routesCleaned = true;
  });
  if (deletedCount) *deletedCount = deleted;
  return grantsCleaned && routesCleaned;
}

template <typename Program>
static inline bool switchboardPinProgramMap(Program *program, uint32_t ifindex, const char *mapName, void (*pinPath)(String&, uint32_t))
{
  if (program == nullptr || ifindex == 0)
  {
    return false;
  }

  bool pinned = false;
  String path = {};
  pinPath(path, ifindex);
  int existingFD = bpf_obj_get(path.c_str());
  uint32_t existingID = switchboardKernelMapID(existingFD);

  program->openMap(String(mapName), [&](int map_fd) -> void {
    if (map_fd < 0)
    {
      basics_log("Switchboard missing %s map for pin ifidx=%u\n", mapName, ifindex);
      return;
    }

    if (existingID != 0 && existingID == switchboardKernelMapID(map_fd))
    {
      pinned = true;
      return;
    }
    (void)unlink(path.c_str());
    int result = bpf_obj_pin(map_fd, path.c_str());
    pinned = (result == 0);
    if (result != 0)
    {
      basics_log("Switchboard %s pin failed ifidx=%u path=%s errno=%d\n",
                 mapName,
                 ifindex,
                 path.c_str(),
                 errno);
    }
  });

  if (existingFD >= 0)
  {
    ::close(existingFD);
  }

  return pinned;
}

static inline bool switchboardReusePinnedProgramMap(struct bpf_object *obj, uint32_t ifindex, const char *mapName, void (*pinPath)(String&, uint32_t), Vector<int>& inner_map_fds)
{
  if (obj == nullptr || ifindex == 0)
  {
    return false;
  }

  String path = {};
  pinPath(path, ifindex);

  int pinnedMapFD = bpf_obj_get(path.c_str());
  if (pinnedMapFD < 0)
  {
    basics_log("Switchboard %s pinned map open failed ifidx=%u path=%s errno=%d\n",
               mapName,
               ifindex,
               path.c_str(),
               errno);
    return false;
  }

  struct bpf_map *map = bpf_object__find_map_by_name(obj, mapName);
  if (map == nullptr)
  {
    basics_log("Switchboard %s map missing while reusing pinned fd ifidx=%u\n", mapName, ifindex);
    ::close(pinnedMapFD);
    return false;
  }

  if (bpf_map__reuse_fd(map, pinnedMapFD) != 0)
  {
    basics_log("Switchboard %s map reuse failed ifidx=%u fd=%d errno=%d\n",
               mapName,
               ifindex,
               pinnedMapFD,
               errno);
    ::close(pinnedMapFD);
    return false;
  }

  inner_map_fds.push_back(pinnedMapFD);
  return true;
}

template <typename Program>
static inline bool switchboardProgramUsesPinnedMap(Program *program,
                                                   uint32_t ifindex,
                                                   const char *mapName,
                                                   void (*pinPath)(String&, uint32_t))
{
  if (program == nullptr || ifindex == 0)
  {
    return false;
  }

  String path = {};
  pinPath(path, ifindex);
  int pinnedFD = bpf_obj_get(path.c_str());
  uint32_t pinnedID = switchboardKernelMapID(pinnedFD);
  uint32_t programID = 0;
  program->openMap(String(mapName), [&](int mapFD) -> void {
    programID = switchboardKernelMapID(mapFD);
  });
  if (pinnedFD >= 0)
  {
    ::close(pinnedFD);
  }
  return pinnedID != 0 && pinnedID == programID;
}

template <typename Program>
static inline bool switchboardPinWhiteholeReplyFlowMap(Program *program, uint32_t ifindex)
{
  return switchboardPinProgramMap(program, ifindex, "white_replies", switchboardWhiteholeReplyFlowPinPath);
}

static inline bool switchboardReusePinnedWhiteholeReplyFlowMap(struct bpf_object *obj, uint32_t ifindex, Vector<int>& inner_map_fds)
{
  return switchboardReusePinnedProgramMap(obj, ifindex, "white_replies", switchboardWhiteholeReplyFlowPinPath, inner_map_fds);
}
template <typename Program>
static inline bool switchboardPinWormholeFlowMaps(Program *program, uint32_t ifindex)
{
  return switchboardProgramHasCompatibleWormholeFlowMaps(program) &&
         switchboardPinProgramMap(program, ifindex, "wh_flows", switchboardWormholeFlowPinPath) &&
         switchboardPinProgramMap(program, ifindex, "wh_pending", switchboardWormholePendingFlowPinPath) &&
         switchboardPinProgramMap(program, ifindex, "wh_pair_grants", switchboardPairAdmissionGrantPinPath) &&
         switchboardPinProgramMap(program, ifindex, "wh_pair_routes", switchboardPairAdmissionRoutePinPath);
}

static inline bool switchboardReusePinnedWormholeFlowMaps(struct bpf_object *obj, uint32_t ifindex, Vector<int>& inner_map_fds)
{
  if (switchboardPinnedWormholeFlowMapsCompatible(ifindex) == false)
  {
    return false;
  }
  return switchboardReusePinnedProgramMap(obj, ifindex, "wh_flows", switchboardWormholeFlowPinPath, inner_map_fds) &&
         switchboardReusePinnedProgramMap(obj, ifindex, "wh_pending", switchboardWormholePendingFlowPinPath, inner_map_fds) &&
         switchboardReusePinnedProgramMap(obj, ifindex, "wh_pair_grants", switchboardPairAdmissionGrantPinPath, inner_map_fds) &&
         switchboardReusePinnedProgramMap(obj, ifindex, "wh_pair_routes", switchboardPairAdmissionRoutePinPath, inner_map_fds);
}

template <typename Program>
static inline bool switchboardProgramUsesPinnedWormholeFlowMaps(Program *program, uint32_t ifindex)
{
  return switchboardProgramHasCompatibleWormholeFlowMaps(program) &&
         switchboardProgramUsesPinnedMap(program, ifindex, "wh_flows", switchboardWormholeFlowPinPath) &&
         switchboardProgramUsesPinnedMap(program, ifindex, "wh_pending", switchboardWormholePendingFlowPinPath) &&
         switchboardProgramUsesPinnedMap(program, ifindex, "wh_pair_grants", switchboardPairAdmissionGrantPinPath) &&
         switchboardProgramUsesPinnedMap(program, ifindex, "wh_pair_routes", switchboardPairAdmissionRoutePinPath);
}
