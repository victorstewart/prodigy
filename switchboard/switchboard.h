#pragma once

#include <algorithm>
#include <array>
#include <cstring>
#include <services/debug.h>
#include <memory>
#include <utility>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/resource.h>
#include <sys/random.h>
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
#include <prodigy/bundle.artifact.h>
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

static inline bool switchboardAssignDeterministicPortalSlots(
    Vector<SwitchboardPortal *>& ordered,
    Vector<uint32_t>& freeSlots)
{
  std::sort(ordered.begin(), ordered.end(), [](const SwitchboardPortal *lhs, const SwitchboardPortal *rhs) {
    int addressOrder = std::memcmp(lhs->address.v6, rhs->address.v6, sizeof(lhs->address.v6));
    if (addressOrder != 0)
    {
      return addressOrder < 0;
    }
    if (lhs->address.is6 != rhs->address.is6)
    {
      return lhs->address.is6 < rhs->address.is6;
    }
    if (lhs->port != rhs->port)
    {
      return lhs->port < rhs->port;
    }
    if (lhs->proto != rhs->proto)
    {
      return lhs->proto < rhs->proto;
    }
    return lhs->isQuic < rhs->isQuic;
  });

  bool changed = false;
  for (uint32_t index = 0; index < ordered.size(); ++index)
  {
    const uint32_t slot = uint32_t(MAX_PORTALS - 1u - index);
    changed = changed || ordered[index]->slot != slot;
    ordered[index]->slot = slot;
  }

  freeSlots.clear();
  freeSlots.reserve(MAX_PORTALS - ordered.size());
  for (uint32_t slot = 0; slot < MAX_PORTALS - ordered.size(); ++slot)
  {
    freeSlots.push_back(slot);
  }
  return changed;
}

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

static inline bool switchboardGenerateWormholeOwnerGeneration(uint64_t& generation)
{
  do
  {
    uint8_t *output = reinterpret_cast<uint8_t *>(&generation);
    size_t remaining = sizeof(generation);
    while (remaining > 0)
    {
      ssize_t bytes = getrandom(output, remaining, 0);
      if (bytes < 0)
      {
        if (errno == EINTR)
        {
          continue;
        }
        generation = 0;
        return false;
      }
      if (bytes == 0)
      {
        generation = 0;
        return false;
      }
      output += bytes;
      remaining -= size_t(bytes);
    }
  } while (generation == 0);
  return true;
}

static inline bool switchboardBuildWormholeEgressBinding(const IPAddress& externalAddress,
                                                         uint16_t externalPort,
                                                         uint8_t proto,
                                                         uint64_t ownerGeneration,
                                                         switchboard_wormhole_egress_binding& binding)
{
  if (externalPort == 0 || proto == 0 || ownerGeneration == 0)
  {
    binding = {};
    return false;
  }

  binding = {};
  binding.port = htons(externalPort);
  binding.proto = proto;
  binding.is_ipv6 = externalAddress.is6 ? 1 : 0;
  binding.owner_generation = ownerGeneration;
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
  uint64_t ownerGeneration = 0;
  ::Wormhole definition = {};
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
#include <switchboard/maglev.ring.prepare.h>
#include <unordered_map>

class Switchboard {
  friend class SwitchboardRingTestAccess;
public:
  enum class RingConsumer : uint32_t { brainReceipt, containerRefresh };
private:

  EthDevice& eth;
  BPFProgram *bpf_router = nullptr;
  BPFProgram *host_ingress = nullptr;
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
  bytell_hash_map<uint32_t, String> wormholeRevisionByContainer;
  bytell_hash_subset<uint32_t, switchboard_runtime::Whitehole *> whiteholesByContainer;
  Vector<uint32_t> portalSlots;

  // Desired routing remains Ring-owned. The worker sees only copied endpoints
  // and creates private inner maps; the current owner alone publishes them.
  struct PortalRingState {
    uint64_t generation = 0;
    uint8_t datacenterPrefix = 0;
    std::vector<MaglevHashV2::Endpoint> endpoints;
    std::shared_ptr<SwitchboardMaglevRingPrepareResult> prepared;
    bool failed = false;
  };
  std::unordered_map<SwitchboardPortal *, PortalRingState> portalRings;
  std::unique_ptr<ProdigyArtifactIO> ringPreparation;
  std::shared_ptr<uint8_t> ringPreparationLifetime = std::make_shared<uint8_t>(0);
  std::unordered_map<uint64_t, std::function<void(bool)>> ringWaiters;
  uint64_t nextRingGeneration = 1;
  bool ringPreparationInFlight = false;
  bool resettingRings = false;
  bool ringPreparationQuiescing = false;

  // QUIC CID state belongs to the same desired/published owner as portal
  // rings.  A program identity is the kernel map ID, never a reused C++
  // pointer.  The initial scan is deliberately bounded: a preattached ARRAY
  // can contain stale decrypt keys that must be removed before an applied
  // routing receipt is emitted.
  static constexpr uint32_t quicCidMapEntries = MAX_PORTALS * 2;
  // Bounds map-ID metadata, BPF map lookup, and BPF map update syscalls per
  // Ring turn.
  static constexpr uint32_t quicCidReconcileOperationsPerTurn = 32;
  struct QuicCidProgramState {
    // Store only observed non-zero slots.  The initial scan proves every
    // omitted slot is zero, avoiding a 2,048-entry resident copy per peer.
    bytell_hash_map<uint32_t, quic_cid_aes_decrypt_state> published = {};
    uint32_t scanCursor = 0;
    Vector<uint32_t> dirtyIndices = {};
    uint32_t dirtyCursor = 0;
    uint64_t desiredGeneration = 0;
    bool scanned = false;
    bool failed = false;
  };
  std::unordered_map<uint32_t, QuicCidProgramState> quicCidPrograms;
  bool quicCidDiscoveryFailed = false;
  bool quicCidReconciliationDirty = false;
  // Rebuilt once when a coalesced request reaches the Ring, never for every
  // bounded continuation.  Only non-zero desired slots are retained.
  bytell_hash_map<uint32_t, quic_cid_aes_decrypt_state> quicCidDesired = {};
  bool quicCidDesiredRefreshPending = false;
  uint64_t quicCidDesiredGeneration = 1;
  // The cursor is an index into a fresh, per-callback program list.  It never
  // retains a BPFProgram pointer past that callback; kernel map identities are
  // retained only until the entire sweep can safely prune removed maps.
  uint32_t quicCidProgramSweepCursor = 0;
  uint32_t quicCidProgramSweepCount = 0;
  bool quicCidProgramSweepComplete = false;
  bytell_hash_set<uint32_t> quicCidSweepActiveMapIDs = {};

  struct QuicCidReconcileWakeLifetime {
    uint32_t pending = 0;
  };
  std::shared_ptr<QuicCidReconcileWakeLifetime> quicCidReconcileWakeLifetime =
      std::make_shared<QuicCidReconcileWakeLifetime>();

  class QuicCidReconcileWake final : public TimeoutDispatcher {
  public:
    Switchboard *owner = nullptr;
    std::shared_ptr<QuicCidReconcileWakeLifetime> lifetime;
    TimeoutPacket packet = {};
    QuicCidReconcileWake(Switchboard *requestedOwner,
                          std::shared_ptr<QuicCidReconcileWakeLifetime> requestedLifetime)
        : owner(requestedOwner), lifetime(std::move(requestedLifetime))
    {
      lifetime->pending += 1;
      packet.dispatcher = this;
    }

    void cancel(void)
    {
      owner = nullptr;
      Ring::queueCancelTimeout(&packet);
    }

    void dispatchTimeout(TimeoutPacket *completedPacket) override
    {
      if (completedPacket != &packet) return;
      Switchboard *completedOwner = owner;
      if (completedOwner) completedOwner->quicCidReconcileWake = nullptr;
      if (lifetime && lifetime->pending > 0) lifetime->pending -= 1;
      delete this;
      if (completedOwner) completedOwner->continueQuicCidReconciliation();
    }
  };
  QuicCidReconcileWake *quicCidReconcileWake = nullptr;

  static bool sameRingEndpoints(const std::vector<MaglevHashV2::Endpoint>& a,
                                const std::vector<MaglevHashV2::Endpoint>& b)
  {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
      if (a[i].num != b[i].num || a[i].weight != b[i].weight || a[i].hash != b[i].hash) return false;
    return true;
  }

  bool publishPreparedRing(BPFProgram *program, SwitchboardPortal *portal,
                           const SwitchboardMaglevRingPrepareResult& prepared)
  {
    if (program == nullptr || !prepared.prepared()) return false;
    bool ok = false;
    program->openMap("cid_rings"_ctv, [&](int mapFD) {
      if (mapFD >= 0 && bpf_map_update_elem(mapFD, &portal->slot, &prepared.innerMapFD, BPF_ANY) == 0)
        ok = true;
      else
        basics_log("Switchboard outer ring publication failed ifidx=%u slot=%u errno=%d\n",
                   eth.ifidx, unsigned(portal->slot), errno);
    });
    return ok;
  }

  void settleRingWaiters()
  {
    if (ringPreparationInFlight) return;
    if (quicCidReconciliationReady() == false)
    {
      if (quicCidReconciliationFailed())
      {
        auto failed = std::move(ringWaiters);
        ringWaiters.clear();
        for (auto& [id, completion] : failed) { (void)id; completion(false); }
      }
      return;
    }
    bool ok = true;
    for (const auto& [portal, state] : portalRings)
    {
      (void)portal;
      if (!state.failed && (!state.prepared || state.prepared->generation != state.generation)) return;
      ok = ok && !state.failed;
    }
    // A failed asynchronous publication can have reached some programs. It is
    // not a successful transaction or a proven rollback; force a fresh retry.
    if (!ok) wormholeRevisionByContainer.clear();
    auto ready = std::move(ringWaiters);
    ringWaiters.clear();
    for (auto& [id, completion] : ready) { (void)id; completion(ok); }
  }

  void preparePendingRings()
  {
    if (ringPreparationInFlight || resettingRings || ringPreparationQuiescing) return;
    std::vector<SwitchboardMaglevRingPrepareRequest> requests;
    for (const auto& [portal, state] : portalRings)
    {
      (void)portal;
      if (!state.failed && (!state.prepared || state.prepared->generation != state.generation))
      {
        requests.push_back({state.generation, state.datacenterPrefix, state.endpoints});
        if (requests.size() == 8) break; // bound one worker/completion batch
      }
    }
    if (requests.empty()) { settleRingWaiters(); return; }
    if (!ringPreparation) ringPreparation = ProdigyArtifactIO::startOwned();
    auto failed = [this]() {
      ringPreparationInFlight = false;
      for (auto& [portal, state] : portalRings)
      {
        (void)portal;
        if (!state.prepared || state.prepared->generation != state.generation) state.failed = true;
      }
      basics_log("Switchboard ring preparation failed ifidx=%u\n", eth.ifidx);
      settleRingWaiters();
    };
    if (!ringPreparation) { failed(); return; }
    const std::weak_ptr<uint8_t> lifetime = ringPreparationLifetime;
    ringPreparationInFlight = true;
    if (!switchboardPrepareMaglevRingsAsync(*ringPreparation, std::move(requests),
        switchboardDefaultMaglevMapBackend(),
        [this, lifetime](std::vector<SwitchboardMaglevRingPrepareResult>&& results) {
          if (lifetime.expired()) return;
          ringPreparationInFlight = false;
          for (auto& result : results)
          {
            for (auto& [portal, state] : portalRings)
            {
              if (state.generation != result.generation) continue;
              if (!result.prepared())
              {
                state.failed = true;
                basics_log("Switchboard inner ring preparation failed ifidx=%u slot=%u error=%u errno=%d\n",
                           eth.ifidx, unsigned(portal->slot), unsigned(result.error), result.errorNumber);
                break;
              }
              auto prepared = std::make_shared<SwitchboardMaglevRingPrepareResult>(std::move(result));
              state.prepared = prepared;
              bool ok = syncPortalDefinitionForProgram(bpf_router, portal);
              if (host_ingress) ok = syncPortalDefinitionForProgram(host_ingress, portal) && ok;
              forEachActivePeerProgram([&](BPFProgram *program) {
                ok = syncPortalDefinitionForProgram(program, portal) && ok;
              });
              state.failed = !ok;
              if (ok) portal->hashRing = prepared->ring;
              break;
            }
          }
          preparePendingRings();
        },
        [lifetime, failed](std::exception_ptr) { if (!lifetime.expired()) failed(); })) failed();
  }


  // Portal slots cross the machine boundary in overlay packets.  They must
  // therefore depend on the portal set, not on each node's replay order.
  bool assignDeterministicPortalSlots(void)
  {
    Vector<SwitchboardPortal *> ordered = {};
    ordered.reserve(portals.size());
    for (SwitchboardPortal *portal : portals)
    {
      if (portal != nullptr)
      {
        ordered.push_back(portal);
      }
    }
    return switchboardAssignDeterministicPortalSlots(ordered, portalSlots);
  }

#if PRODIGY_DEBUG
  static void appendAttachLogImpl(const char *message)
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

  static void appendAttachLogfImpl(const char *format, ...)
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

    appendAttachLogImpl(line);
  }
#endif

#if PRODIGY_DEBUG
#define appendAttachLog(...) appendAttachLogImpl(__VA_ARGS__)
#define appendAttachLogf(...) appendAttachLogfImpl(__VA_ARGS__)
#else
#define appendAttachLog(...) ((void)0)
#define appendAttachLogf(...) ((void)0)
#endif

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

#if PRODIGY_DEBUG
  static void appendCurrentXDPStateImpl(EthDevice& eth, StringType auto&& balancerObjectPath, const char *stage)
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
#define appendCurrentXDPState(...) appendCurrentXDPStateImpl(__VA_ARGS__)
#else
#define appendCurrentXDPState(...) ((void)0)
#endif

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

  bool refreshQuicCidDesired(void)
  {
    bytell_hash_map<uint32_t, quic_cid_aes_decrypt_state> desired = {};
    for (const SwitchboardPortal *portal : portals)
    {
      if (portal == nullptr || portal->isQuic == false || portal->hasQuicCidKeyState == false)
      {
        continue;
      }
      for (uint8_t keyIndex = 0; keyIndex < 2; ++keyIndex)
      {
        const uint128_t keyMaterial = portal->quicCidKeyMaterialByIndex[keyIndex];
        const uint32_t mapIndex = quicCidPortalDecryptMapIndex(
            portal->slot, wormholeQuicCidKeyMaterialPhase(keyMaterial));
        if (mapIndex >= quicCidMapEntries) continue;
        quic_cid_aes_decrypt_state state = {};
        buildQuicCidDecryptState(keyMaterial, state);
        desired.insert_or_assign(mapIndex, state);
      }
    }

    if (desired.size() == quicCidDesired.size())
    {
      bool unchanged = true;
      for (const auto& [index, state] : desired)
      {
        const auto current = quicCidDesired.find(index);
        if (current == quicCidDesired.end() ||
            std::memcmp(&current->second, &state, sizeof(state)) != 0)
        {
          unchanged = false;
          break;
        }
      }
      if (unchanged) return false;
    }

    quicCidDesired = std::move(desired);
    if (quicCidDesiredGeneration < UINT64_MAX) quicCidDesiredGeneration += 1;
    return true;
  }

  void collectActiveQuicCidPrograms(Vector<BPFProgram *>& programs) const
  {
    auto add = [&programs](BPFProgram *program) {
      if (program != nullptr && std::find(programs.begin(), programs.end(), program) == programs.end())
      {
        programs.push_back(program);
      }
    };
    add(bpf_router);
    add(host_ingress);
    forEachActivePeerProgram([&add](BPFProgram *program) { add(program); });
  }

  bool quicCidProgramConverged(const QuicCidProgramState& state) const
  {
    return state.scanned && !state.failed &&
           state.desiredGeneration == quicCidDesiredGeneration &&
           state.dirtyCursor == state.dirtyIndices.size();
  }

  void refreshQuicCidProgramDirtyIndices(QuicCidProgramState& state)
  {
    if (!state.scanned || state.desiredGeneration == quicCidDesiredGeneration) return;
    state.dirtyIndices.clear();
    for (const auto& [index, desired] : quicCidDesired)
    {
      const auto observed = state.published.find(index);
      if (observed == state.published.end() ||
          std::memcmp(&observed->second, &desired, sizeof(desired)) != 0)
      {
        state.dirtyIndices.push_back(index);
      }
    }
    for (const auto& [index, observed] : state.published)
    {
      (void)observed;
      if (quicCidDesired.contains(index) == false) state.dirtyIndices.push_back(index);
    }
    state.dirtyCursor = 0;
    state.desiredGeneration = quicCidDesiredGeneration;
  }

  bool reconcileQuicCidProgram(BPFProgram *program,
                               uint32_t& remaining,
                               bytell_hash_set<uint32_t>& activeMapIDs)
  {
    if (program == nullptr) return true;
    bool complete = false;
    uint32_t resolvedMapID = 0;
    program->openMap("quic_cid_dec"_ctv, [this, &complete, &resolvedMapID, &remaining, &activeMapIDs](int mapFD) {
      if (mapFD < 0)
      {
        basics_log("Switchboard missing quic_cid_dec during reconciliation ifidx=%u\n", eth.ifidx);
        quicCidDiscoveryFailed = true;
        complete = true;
        return;
      }
      if (remaining == 0) return;
      remaining -= 1; // map-ID metadata lookup
      const uint32_t mapID = kernelMapIDForFD(mapFD);
      if (mapID == 0)
      {
        basics_log("Switchboard quic_cid_dec identity lookup failed ifidx=%u fd=%d\n", eth.ifidx, mapFD);
        quicCidDiscoveryFailed = true;
        complete = true;
        return;
      }
      resolvedMapID = mapID;
      QuicCidProgramState& state = quicCidPrograms[mapID];
      while (remaining > 0 && state.scanned == false)
      {
        quic_cid_aes_decrypt_state observed = {};
        errno = 0;
        remaining -= 1;
        if (bpf_map_lookup_elem(mapFD, &state.scanCursor, &observed) != 0)
        {
          basics_log("Switchboard quic_cid_dec read failed ifidx=%u map=%u index=%u errno=%d\n",
                     eth.ifidx, mapID, state.scanCursor, errno);
          state.failed = true;
          return;
        }
        const quic_cid_aes_decrypt_state empty = {};
        if (std::memcmp(&observed, &empty, sizeof(empty)) != 0)
        {
          state.published.insert_or_assign(state.scanCursor, observed);
        }
        state.scanCursor += 1;
        if (state.scanCursor == quicCidMapEntries)
        {
          state.scanned = true;
          refreshQuicCidProgramDirtyIndices(state);
        }
      }
      refreshQuicCidProgramDirtyIndices(state);
      while (remaining > 0 && state.dirtyCursor < state.dirtyIndices.size())
      {
        const uint32_t index = state.dirtyIndices[state.dirtyCursor];
        const auto desired = quicCidDesired.find(index);
        const quic_cid_aes_decrypt_state empty = {};
        const quic_cid_aes_decrypt_state& expected =
            desired == quicCidDesired.end() ? empty : desired->second;
        errno = 0;
        remaining -= 1;
        if (bpf_map_update_elem(mapFD, &index, &expected, BPF_ANY) != 0)
        {
          basics_log("Switchboard quic_cid_dec reconcile update failed ifidx=%u map=%u index=%u errno=%d\n",
                     eth.ifidx, mapID, index, errno);
          state.failed = true;
          return;
        }
        if (desired == quicCidDesired.end()) state.published.erase(index);
        else state.published.insert_or_assign(index, expected);
        state.dirtyCursor += 1;
      }
    });
    if (resolvedMapID == 0) return complete;
    const auto state = quicCidPrograms.find(resolvedMapID);
    complete = state != quicCidPrograms.end() && quicCidProgramConverged(state->second);
    // A map replaced during its initial scan never joined this completed
    // sweep. Retaining its partial mirror would keep readiness false forever.
    if (complete) activeMapIDs.insert(resolvedMapID);
    return complete;
  }

  bool quicCidProgramStatesConverged(void) const
  {
    if (quicCidDiscoveryFailed || quicCidProgramSweepComplete == false) return false;
    for (const auto& [mapID, state] : quicCidPrograms)
    {
      (void)mapID;
      if (!quicCidProgramConverged(state)) return false;
    }
    return true;
  }

  bool quicCidReconciliationReady(void) const
  {
    return quicCidReconciliationDirty == false && quicCidProgramStatesConverged();
  }

  bool quicCidReconciliationFailed(void) const
  {
    if (quicCidDiscoveryFailed) return true;
    for (const auto& [mapID, state] : quicCidPrograms)
    {
      (void)mapID;
      if (state.failed) return true;
    }
    return false;
  }

  void continueQuicCidReconciliation(void)
  {
    if (resettingRings || ringPreparationQuiescing) return;
    quicCidDiscoveryFailed = false;
    if (quicCidDesiredRefreshPending)
    {
      quicCidDesiredRefreshPending = false;
      (void)refreshQuicCidDesired();
    }
    Vector<BPFProgram *> programs = {};
    collectActiveQuicCidPrograms(programs);
    if (quicCidProgramSweepCount != programs.size())
    {
      quicCidProgramSweepCursor = 0;
      quicCidProgramSweepComplete = false;
      quicCidSweepActiveMapIDs.clear();
    }
    quicCidProgramSweepCount = programs.size();
    uint32_t remaining = quicCidReconcileOperationsPerTurn;
    while (quicCidProgramSweepCursor < programs.size() && remaining > 0)
    {
      if (reconcileQuicCidProgram(programs[quicCidProgramSweepCursor], remaining,
                                  quicCidSweepActiveMapIDs) == false)
      {
        break;
      }
      quicCidProgramSweepCursor += 1;
      if (quicCidReconciliationFailed()) break;
    }
    if (quicCidProgramSweepCursor == programs.size())
    {
      for (auto it = quicCidPrograms.begin(); it != quicCidPrograms.end();)
      {
        if (quicCidSweepActiveMapIDs.contains(it->first) == false) it = quicCidPrograms.erase(it);
        else ++it;
      }
      quicCidProgramSweepComplete = true;
    }
    quicCidReconciliationDirty = quicCidProgramStatesConverged() == false;
    if (quicCidReconciliationReady() == false && quicCidReconciliationFailed() == false)
    {
      if (quicCidReconcileWake == nullptr)
      {
        quicCidReconcileWake = new QuicCidReconcileWake(this, quicCidReconcileWakeLifetime);
        quicCidReconcileWake->packet.setTimeoutUs(1);
        Ring::queueTimeout(&quicCidReconcileWake->packet);
      }
    }
    settleRingWaiters();
  }

  void requestQuicCidReconciliation(void)
  {
    // A fresh runtime-routing request is the explicit retry boundary for a
    // prior map failure.  Timer-driven continuation deliberately leaves a
    // failure sticky, so a bad map cannot busy-loop BPF syscalls.  Re-scan on
    // a new request because the active map may have been replaced meanwhile.
    if (quicCidReconciliationFailed())
    {
      quicCidDiscoveryFailed = false;
      for (auto& [mapID, state] : quicCidPrograms)
      {
        (void)mapID;
        if (state.failed == false) continue;
        state = {};
      }
    }
    quicCidDesiredRefreshPending = true;
    quicCidReconciliationDirty = true;
    quicCidProgramSweepCursor = 0;
    quicCidProgramSweepCount = 0;
    quicCidProgramSweepComplete = false;
    quicCidSweepActiveMapIDs.clear();
    if (resettingRings || ringPreparationQuiescing || quicCidReconcileWake != nullptr) return;
    quicCidReconcileWake = new QuicCidReconcileWake(this, quicCidReconcileWakeLifetime);
    quicCidReconcileWake->packet.setTimeoutUs(1);
    Ring::queueTimeout(&quicCidReconcileWake->packet);
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
    requestQuicCidReconciliation();
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
                                                                                                                                                          wormhole->ownerGeneration,
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
                                                  wormhole->ownerGeneration,
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
                                              wormhole->ownerGeneration,
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

  static bool ownedRoutablePrefix4KeyLess(const switchboard_owned_routable_prefix4_key& lhs, const switchboard_owned_routable_prefix4_key& rhs)
  {
    if (lhs.prefixlen != rhs.prefixlen)
    {
      return lhs.prefixlen < rhs.prefixlen;
    }

    return lhs.addr < rhs.addr;
  }

  static bool ownedRoutablePrefix6KeyLess(const switchboard_owned_routable_prefix6_key& lhs, const switchboard_owned_routable_prefix6_key& rhs)
  {
    if (lhs.prefixlen != rhs.prefixlen)
    {
      return lhs.prefixlen < rhs.prefixlen;
    }

    return std::memcmp(lhs.addr, rhs.addr, sizeof(lhs.addr)) < 0;
  }

  template <typename Key, typename Less>
  void syncOwnedRoutablePrefixMap(StringType auto&& mapName, Vector<Key>& installedKeys, const Vector<Key>& desiredKeys, Less&& less)
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

      Vector<Key> installedSorted = installedKeys;
      Vector<Key> desiredSorted = desiredKeys;
      std::sort(installedSorted.begin(), installedSorted.end(), less);
      std::sort(desiredSorted.begin(), desiredSorted.end(), less);

      auto installedIt = installedSorted.begin();
      auto desiredIt = desiredSorted.begin();
      __u8 present = 1;
      while (installedIt != installedSorted.end() || desiredIt != desiredSorted.end())
      {
        if (installedIt == installedSorted.end())
        {
          if (bpf_map_update_elem(map_fd, &(*desiredIt), &present, BPF_ANY) != 0)
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
          ++desiredIt;
          continue;
        }

        if (desiredIt == desiredSorted.end())
        {
          if (bpf_map_delete_elem(map_fd, &(*installedIt)) != 0)
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
          ++installedIt;
          continue;
        }

        if (less(*installedIt, *desiredIt))
        {
          if (bpf_map_delete_elem(map_fd, &(*installedIt)) != 0)
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
          ++installedIt;
          continue;
        }

        if (less(*desiredIt, *installedIt))
        {
          if (bpf_map_update_elem(map_fd, &(*desiredIt), &present, BPF_ANY) != 0)
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
          ++desiredIt;
          continue;
        }

        ++installedIt;
        ++desiredIt;
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
                               ownedRoutablePrefix4KeyLess);

    syncOwnedRoutablePrefixMap("owned_pfx6"_ctv,
                               installedOwnedRoutablePrefixes6,
                               desiredPrefixes6,
                               ownedRoutablePrefix6KeyLess);
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
                                              switchboardConfigureDevelopmentWhiteholeMapAllocation(obj);
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

  bool syncPortalDefinitionForProgram(BPFProgram *program, SwitchboardPortal *portal)
  {
    if (program == nullptr || portal == nullptr)
    {
      return false;
    }

    auto ring = portalRings.find(portal);
    if (ring == portalRings.end() || !ring->second.prepared ||
        ring->second.prepared->generation != ring->second.generation)
      return true; // desired definition is published by the prepared-map completion
    if (ring->second.failed) return false;
    if (!publishPreparedRing(program, portal, *ring->second.prepared))
    { ring->second.failed = true; return false; }

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

    if (!updated) ring->second.failed = true;
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
    if (portal == nullptr || program == nullptr || resettingRings || ringPreparationQuiescing) return false;
    std::vector<MaglevHashV2::Endpoint> endpoints;
    endpoints.reserve(portal->wormholes.size());
    for (const auto *wormhole : portal->wormholes)
      endpoints.push_back({wormhole->containerID, wormhole->weight ? wormhole->weight : 1, wormhole->hash()});
    auto& state = portalRings[portal];
    if (state.generation == 0 || state.datacenterPrefix != subnet.dpfx ||
        !sameRingEndpoints(state.endpoints, endpoints) || state.failed)
    {
      state.generation = nextRingGeneration++;
      state.datacenterPrefix = subnet.dpfx;
      state.endpoints = std::move(endpoints);
      state.failed = false;
    }
    if (state.prepared && state.prepared->generation == state.generation)
    {
      const bool ok = publishPreparedRing(program, portal, *state.prepared);
      state.failed = !ok;
      return ok;
    }
    preparePendingRings();
    // This is admission only. Neuron waits for whenRingsReady before sending
    // an applied receipt; no incomplete inner map is ever published.
    return !state.failed;
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

    for (SwitchboardPortal *portal : portals)
    {
      syncPortalDefinitionForProgram(program, portal);
      if (generateRingForPortalOnProgram(program, portal) == false)
      {
        basics_log("Switchboard peer-runtime-sync cid_rings install failed ifidx=%u slot=%u\n", eth.ifidx, unsigned(portal->slot));
      }
    }

    requestQuicCidReconciliation();

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

    for (SwitchboardPortal *portal : portals)
    {
      syncPortalDefinitionForProgram(host_ingress, portal);
      if (generateRingForPortalOnProgram(host_ingress, portal) == false)
      {
        basics_log("Switchboard host-ingress-sync cid_rings install failed ifidx=%u slot=%u\n", eth.ifidx, unsigned(portal->slot));
      }
    }

    requestQuicCidReconciliation();

    (void)syncPortalTargetBindingsForProgram(host_ingress, "host-ingress-sync");

    Vector<SwitchboardWormholeEgressBindingEntry> desiredBindings = {};
    Vector<SwitchboardWormholeEgress4BindingEntry> desiredBindings4 = {};
    collectWormholeEgressBindingEntries(desiredBindings, desiredBindings4);
    switchboardSyncWormholeEgressBindingsForProgram(host_ingress, desiredBindings, eth.ifidx, "host-ingress-sync");
    switchboardSyncWormholeEgress4BindingsForProgram(host_ingress, desiredBindings4, eth.ifidx, "host-ingress-sync");
  }

  void syncAllPeerProgramRuntimeRouting(void)
  {
    forEachActivePeerProgram([&](BPFProgram *program) -> void {
      syncPeerProgramRuntimeRouting(program);
    });
  }

  void syncAllContainerProgramRuntimeState(void)
  {
    if (thisNeuron == nullptr)
    {
      return;
    }

    for (const auto& [uuid, container] : thisNeuron->containers)
    {
      (void)uuid;
      if (container == nullptr || container->plan.useHostNetworkNamespace || container->netdevs.areActive() == false ||
          container->peer_program == nullptr || container->primary_program == nullptr)
      {
        continue;
      }
      syncContainerProgramRuntimeState(container->peer_program, container->primary_program);
    }
  }

  void closeWormhole(switchboard_runtime::Wormhole *wormhole)
  {
    if (wormhole == nullptr)
    {
      return;
    }

    SwitchboardPortal *portal = wormhole->portal;
    wormholesByContainer.eraseEntry(wormhole->containerID, wormhole);
    removeWormholeTargetBinding(wormhole);
    portal->wormholes.erase(wormhole);

    if (portal->wormholes.empty())
    {
      if (bpf_router)
      {
        removePortalDefinitionForProgram(bpf_router, portal);
      }

      portals.erase(portal);
      forEachActivePeerProgram([&](BPFProgram *program) -> void {
        removePortalDefinitionForProgram(program, portal);
      });
      portalRings.erase(portal);
      delete portal;
      requestQuicCidReconciliation();
      if (assignDeterministicPortalSlots())
      {
        syncPeerProgramRuntimeRouting(bpf_router);
        syncAllPeerProgramRuntimeRouting();
      }
    }
    else
    {
      generateRingForPortal(portal);
    }

    syncAllContainerProgramRuntimeState();
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

  void whenRingsReady(uint32_t containerID, std::function<void(bool)> completion,
                      RingConsumer consumer = RingConsumer::brainReceipt)
  {
    const uint64_t key = uint64_t(containerID) | (uint64_t(consumer) << 32);
    if (ringPreparationQuiescing || resettingRings ||
        (ringWaiters.size() >= 2 * MAX_CONTAINERS_PER_PORTAL && !ringWaiters.contains(key)))
    { completion(false); return; }
    // Each consumer retains only its latest request. Application refreshes
    // must not replace the Brain's independent routing acknowledgment.
    ringWaiters.insert_or_assign(key, std::move(completion));
    requestQuicCidReconciliation();
    settleRingWaiters();
  }

  bool quiesceRingPreparationForExec()
  {
    ringPreparationQuiescing = true;
    ringWaiters.clear();
    if (QuicCidReconcileWake *wake = std::exchange(quicCidReconcileWake, nullptr)) wake->cancel();
    const bool preparationQuiesced = !ringPreparation || ringPreparation->quiesceForExec();
    return preparationQuiesced && quicCidReconcileWakeLifetime->pending == 0;
  }

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
    ringPreparationLifetime.reset();
    ringPreparationQuiescing = true;
    ringWaiters.clear();
    if (QuicCidReconcileWake *wake = std::exchange(quicCidReconcileWake, nullptr)) wake->cancel();
    ringPreparation.reset();
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
    host_ingress = program;
    syncHostIngressPortalRouting();
  }

  void syncContainerProgramRuntimeState(BPFProgram *peerProgram, BPFProgram *primaryProgram)
  {
    syncPeerProgramRuntimeRouting(peerProgram);

    Vector<SwitchboardWormholeEgressBindingEntry> desiredBindings = {};
    Vector<SwitchboardWormholeEgress4BindingEntry> desiredBindings4 = {};
    collectWormholeEgressBindingEntries(desiredBindings, desiredBindings4);
    switchboardSyncWormholeEgressBindingsForProgram(primaryProgram,
                                                    desiredBindings,
                                                    eth.ifidx,
                                                    "container-ingress-sync");
    switchboardSyncWormholeEgress4BindingsForProgram(primaryProgram,
                                                     desiredBindings4,
                                                     eth.ifidx,
                                                     "container-ingress-sync");
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
    resettingRings = true;
    if (QuicCidReconcileWake *wake = std::exchange(quicCidReconcileWake, nullptr)) wake->cancel();
    quicCidPrograms.clear();
    quicCidDiscoveryFailed = false;
    quicCidReconciliationDirty = false;
    quicCidDesired.clear();
    quicCidDesiredRefreshPending = false;
    quicCidProgramSweepCursor = 0;
    quicCidProgramSweepCount = 0;
    quicCidProgramSweepComplete = false;
    quicCidSweepActiveMapIDs.clear();
    portalRings.clear();
    auto canceled = std::move(ringWaiters);
    ringWaiters.clear();
    for (auto& [id, completion] : canceled) { (void)id; completion(false); }
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
    resettingRings = false;
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
    appendAttachLogf("Switchboard setHostedIngressPrefixes ifidx=%u count=%u",
                     eth.ifidx,
                     unsigned(hostedIngressPrefixes.size()));
    rebuildAnnouncingPrefixes();
    syncOwnedRoutablePrefixMaps();
    maybeDetachBoundaryRouter();
  }

  void closeWormholesToContainer(uint32_t containerID)
  {
    for (RingConsumer consumer : {RingConsumer::brainReceipt, RingConsumer::containerRefresh})
    {
      const uint64_t key = uint64_t(containerID) | (uint64_t(consumer) << 32);
      if (auto waiting = ringWaiters.find(key); waiting != ringWaiters.end())
      {
        auto completion = std::move(waiting->second);
        ringWaiters.erase(waiting);
        completion(false);
      }
    }
    wormholeRevisionByContainer.erase(containerID);
    if (auto it = wormholesByContainer.find(containerID); it != wormholesByContainer.end())
    {
      Vector<switchboard_runtime::Wormhole *> closingWormholes;
      for (switchboard_runtime::Wormhole *wormhole : it->second)
      {
        closingWormholes.push_back(wormhole);
      }

      wormholesByContainer.erase(it);

      for (switchboard_runtime::Wormhole *wormhole : closingWormholes)
      {
        closeWormhole(wormhole);
      }
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
    if (switchboardPacketBudgetExternalIngressUnderlayMTUValid(eth.mtu) == false)
    {
      basics_log("Switchboard openWormhole underlay mtu too small ifidx=%u mtu=%u required=%u containerID=%u\n",
                 eth.ifidx,
                 unsigned(eth.mtu),
                 unsigned(switchboardPacketBudgetExternalIngressRequiredUnderlayMTU()),
                 containerID);
      return false;
    }

    if (auto existing = wormholesByContainer.find(containerID); existing != wormholesByContainer.end())
    {
      for (const switchboard_runtime::Wormhole *wormhole : existing->second)
      {
        if (wormhole != nullptr && wormhole->port == requestedWormhole.containerPort &&
            wormhole->proto == requestedWormhole.layer4)
        {
          return false;
        }
      }
    }

    uint64_t ownerGeneration = 0;
    if (switchboardGenerateWormholeOwnerGeneration(ownerGeneration) == false)
    {
      basics_log("Switchboard openWormhole owner generation failed containerID=%u errno=%d\n", containerID, errno);
      return false;
    }

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
      if (portalSlots.empty() || switchboardPortalCountWithinCapacity(portals.size() + 1) == false)
      {
        basics_log("Switchboard openWormhole portal capacity exhausted containerID=%u ifidx=%u capacity=%u\n",
                   containerID,
                   eth.ifidx,
                   unsigned(MAX_PORTALS));
        return false;
      }
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
      (void)assignDeterministicPortalSlots();
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
        portalRings.erase(portal);
        delete portal;
        (void)assignDeterministicPortalSlots();
        syncPeerProgramRuntimeRouting(bpf_router);
        syncAllPeerProgramRuntimeRouting();
        return false;
      }

    }

    requestQuicCidReconciliation();

    switchboard_runtime::Wormhole *wormhole = new switchboard_runtime::Wormhole();
    wormhole->containerID = containerID;
    wormhole->port = requestedWormhole.containerPort;
    wormhole->proto = requestedWormhole.layer4;
    wormhole->userCapacity = requestedWormhole.userCapacity;
    wormhole->weight = serviceUserCapacityPlanningWeight(requestedWormhole.userCapacity);
    wormhole->ownerGeneration = ownerGeneration;
    wormhole->definition = requestedWormhole;
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
        portalRings.erase(portal);
        delete portal;
        (void)assignDeterministicPortalSlots();
        syncPeerProgramRuntimeRouting(bpf_router);
        syncAllPeerProgramRuntimeRouting();
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

    if (createdPortal)
    {
      syncPeerProgramRuntimeRouting(bpf_router);
    }
    syncHostIngressPortalRouting();
    syncAllPeerProgramRuntimeRouting();
    return true;
  }

  SwitchboardWormholeOperationStatus openWormholes(uint32_t containerID, const Vector<Wormhole>& wormholes)
  {
    appendAttachLogf("Switchboard openWormholes begin ifidx=%u containerID=%u requested=%u announcing=%u dpfx=%u",
                     eth.ifidx,
                     containerID,
                     unsigned(wormholes.size()),
                     unsigned(announcingPrefixes.size()),
                     unsigned(subnet.dpfx));
    if (wormholeTargetBindingsUnique(wormholes) == false)
    {
      basics_log("Switchboard openWormholes rejected duplicate target containerID=%u ifidx=%u\n",
                 containerID,
                 eth.ifidx);
      return SwitchboardWormholeOperationStatus::rejected;
    }
    String desiredBytes = switchboardSerializeWormholeFleet(wormholes);
    String desiredRevision = {};
    if (prodigyComputeWormholeDesiredStateRevision(containerID, desiredBytes, desiredRevision) == false)
    {
      basics_log("Switchboard openWormholes failed desired-state digest containerID=%u ifidx=%u\n", containerID, eth.ifidx);
      return SwitchboardWormholeOperationStatus::rejected;
    }
    if (auto applied = wormholeRevisionByContainer.find(containerID);
        applied != wormholeRevisionByContainer.end() && applied->second.equals(desiredRevision))
    {
      return SwitchboardWormholeOperationStatus::applied;
    }
    Vector<Wormhole> previous = {};
    String previousRevision = {};
    if (auto applied = wormholeRevisionByContainer.find(containerID); applied != wormholeRevisionByContainer.end())
    {
      previousRevision = applied->second;
    }
    if (auto existing = wormholesByContainer.find(containerID); existing != wormholesByContainer.end())
    {
      previous.reserve(existing->second.size());
      for (const switchboard_runtime::Wormhole *wormhole : existing->second)
      {
        if (wormhole != nullptr)
        {
          previous.push_back(wormhole->definition);
        }
      }
    }
    SwitchboardWormholeOperationStatus status = switchboardReplaceWormholesTransaction(
        previous,
        wormholes,
        [&](const Wormhole& wormhole) -> bool { return openWormhole(containerID, wormhole); },
        [&]() -> void { closeWormholesToContainer(containerID); });
    if (status != SwitchboardWormholeOperationStatus::applied)
    {
      if (status == SwitchboardWormholeOperationStatus::rejected)
      {
        if (previousRevision.empty())
        {
          String previousBytes = switchboardSerializeWormholeFleet(previous);
          (void)prodigyComputeWormholeDesiredStateRevision(containerID, previousBytes, previousRevision);
        }
        if (previousRevision.empty() == false)
        {
          wormholeRevisionByContainer.insert_or_assign(containerID, std::move(previousRevision));
        }
      }
      if (status == SwitchboardWormholeOperationStatus::rollbackFailed)
      {
        basics_log("Switchboard openWormholes rollback failed containerID=%u previous=%u ifidx=%u\n",
                   containerID, unsigned(previous.size()), eth.ifidx);
      }
      basics_log("Switchboard openWormholes transaction rolled back containerID=%u requested=%u ifidx=%u\n",
                 containerID, unsigned(wormholes.size()), eth.ifidx);
      return status;
    }
    wormholeRevisionByContainer.insert_or_assign(containerID, std::move(desiredRevision));
    appendAttachLogf("Switchboard openWormholes done ifidx=%u containerID=%u requested=%u opened=%u",
                     eth.ifidx,
                     containerID,
                     unsigned(wormholes.size()),
                     unsigned(wormholes.size()));
    return SwitchboardWormholeOperationStatus::applied;
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

#undef appendCurrentXDPState
#undef appendAttachLogf
#undef appendAttachLog
