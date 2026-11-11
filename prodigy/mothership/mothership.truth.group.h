#pragma once

#include <prodigy/mothership/truth.placement.selector.h>

// Stored once at the registry that owns global Truth placement. The projection
// describes container bindings. Raft alone changes the roles they exercise.
struct MothershipTruthGroup {
  uint32_t version = 3;
  uint64_t revision = 0, graceMs = 0;
  TruthGlobalMembershipProjection group;
  Vector<uint128_t> sites;
  struct Missing { int32_t id = 0; uint64_t sinceMs = 0; };
  Vector<Missing> missing;
  TruthGlobalMember outgoing, incoming;
  bool cleanup = false;
  Vector<TruthGlobalMember> retiredBindings;
  // Raft replacement is complete before its old process can necessarily be
  // reached. Keep physical cleanup separate from the next membership change;
  // the retained binding remains the sole owner of each exact endpoint.
  Vector<int32_t> pendingRetirementIDs;
};
template<class S> static void serialize(S&& s, MothershipTruthGroup::Missing& v) {
  s.value4b(v.id); s.value8b(v.sinceMs);
}
template<class S> static void serialize(S&& s, MothershipTruthGroup& v) {
  s.value4b(v.version); s.value8b(v.revision); s.value8b(v.graceMs); s.object(v.group);
  s.container(v.sites,64,[](auto& nested, uint128_t& site) { nested.value16b(site); }); s.container(v.missing,3); s.object(v.outgoing); s.object(v.incoming); s.value1b(v.cleanup);
  if (v.version >= 2) s.container(v.retiredBindings, 256);
  if (v.version >= 3) s.container4b(v.pendingRetirementIDs, 256);
}

struct MothershipTruthGrant {
  uint32_t version = 1;
  uint128_t membershipUUID = 0, operationUUID = 0, localClusterUUID = 0, containerUUID = 0, bootNonce = 0;
  uint64_t deploymentID = 0;
  int32_t memberID = 0;
};
template<class S> static void serialize(S&& s, MothershipTruthGrant& v) {
  s.value4b(v.version); s.value16b(v.membershipUUID); s.value16b(v.operationUUID); s.value16b(v.localClusterUUID);
  s.value16b(v.containerUUID); s.value16b(v.bootNonce); s.value8b(v.deploymentID); s.value4b(v.memberID);
}

static inline bool mothershipTruthGroupValid(const MothershipTruthGroup& state) {
  if ((state.version < 1 || state.version > 3) || (state.version == 1 && !state.retiredBindings.empty()) ||
      (state.version < 3 && !state.pendingRetirementIDs.empty()) ||
      !state.revision || !state.graceMs || state.sites.empty() || state.sites.size() > 64 ||
      !state.sites.front() || !std::is_sorted(state.sites.begin(), state.sites.end()) ||
      std::adjacent_find(state.sites.begin(), state.sites.end()) != state.sites.end() ||
      !prodigyTruthGlobalMembershipProjectionValid(state.group) ||
      state.retiredBindings.size() > state.group.retiredMemberIDs.size() ||
      state.pendingRetirementIDs.size() > state.retiredBindings.size()) return false;
  int32_t previous = 0;
  for (const auto& binding : state.retiredBindings) {
    if (binding.memberID <= previous || !binding.containerUUID || !binding.privateIPv6.is6 || binding.privateIPv6.isNull() ||
        binding.role != TruthGlobalMemberRole::voter ||
        !std::binary_search(state.sites.begin(), state.sites.end(), binding.clusterUUID) ||
        !std::binary_search(state.group.retiredMemberIDs.begin(), state.group.retiredMemberIDs.end(), binding.memberID))
      return false;
    previous = binding.memberID;
  }
  previous = 0;
  for (int32_t id : state.pendingRetirementIDs) {
    if (id <= previous || std::none_of(state.retiredBindings.begin(), state.retiredBindings.end(),
        [&](const auto& binding) { return binding.memberID == id; })) return false;
    previous = id;
  }
  return true;
}

// The caller has certified a committed successor that no longer contains this
// member. Preserve its exact cleanup obligation even if its site is offline.
static inline bool mothershipTruthDeferRetirement(MothershipTruthGroup& state, const TruthGlobalMember& retired) {
  auto& ids = state.group.retiredMemberIDs;
  if (!std::binary_search(ids.begin(), ids.end(), retired.memberID)) return false;
  auto position = std::lower_bound(state.retiredBindings.begin(), state.retiredBindings.end(), retired.memberID,
      [](const auto& member, int32_t id) { return member.memberID < id; });
  if (position != state.retiredBindings.end() && position->memberID == retired.memberID) {
    if (position->containerUUID != retired.containerUUID || position->clusterUUID != retired.clusterUUID ||
        !position->privateIPv6.equals(retired.privateIPv6) || position->role != retired.role) return false;
  } else state.retiredBindings.insert(position, retired);
  auto pending = std::lower_bound(state.pendingRetirementIDs.begin(), state.pendingRetirementIDs.end(), retired.memberID);
  if (pending == state.pendingRetirementIDs.end() || *pending != retired.memberID) {
    if (state.pendingRetirementIDs.size() == 256) return false;
    state.pendingRetirementIDs.insert(pending, retired.memberID);
  }
  state.version = 3;
  state.incoming = {}; state.outgoing = {}; state.cleanup = false;
  return true;
}

template<class Retire>
static bool mothershipTruthRetryRetirements(MothershipTruthGroup& state,
    const Vector<TruthGlobalMember>& committed, Retire&& retire, bool& changed) {
  changed = false;
  for (auto pending = state.pendingRetirementIDs.begin(); pending != state.pendingRetirementIDs.end();) {
    auto binding = std::find_if(state.retiredBindings.begin(), state.retiredBindings.end(),
        [&](const auto& member) { return member.memberID == *pending; });
    if (binding == state.retiredBindings.end() || std::any_of(committed.begin(), committed.end(),
        [&](const auto& member) { return member.memberID == *pending; })) return false;
    if (!retire(*binding)) { ++pending; continue; }
    pending = state.pendingRetirementIDs.erase(pending);
    changed = true;
  }
  return true;
}

// Qualified private routes must connect every cross-site member pair. A route
// covers all source members but only its exact destination endpoint.
static inline bool mothershipTruthPrivateRoutesCoverMembers(const Vector<CousinRouteRecord>& routes,
    const Vector<TruthGlobalMember>& members, uint128_t first, uint128_t second) {
  for (const auto& a : members) if (a.clusterUUID == first)
    for (const auto& b : members) if (b.clusterUUID == second)
      if (std::count_if(routes.begin(), routes.end(), [&](const auto& route) {
        return (route.sourceClusterUUID == first && route.destinationClusterUUID == second &&
                route.destinationPublicAddress.equals(b.privateIPv6)) ||
               (route.sourceClusterUUID == second && route.destinationClusterUUID == first &&
                route.destinationPublicAddress.equals(a.privateIPv6));
      }) != 1) return false;
  return true;
}

// A current binding wins over a retired address that a site has reused.
static inline bool mothershipTruthRetiredRouteEndpoint(const MothershipTruthGroup& state,
    const Vector<TruthGlobalMember>& committed, uint128_t site, const IPAddress& address) {
  const auto matches = [&](const auto& member) {
    return member.clusterUUID == site && member.privateIPv6.equals(address);
  };
  if (std::any_of(committed.begin(), committed.end(), matches)) return false;
  return (state.outgoing.memberID && matches(state.outgoing)) ||
         std::any_of(state.retiredBindings.begin(), state.retiredBindings.end(), matches);
}

static inline bool mothershipTruthPrivateRouteRetirementRequired(const MothershipTruthGroup& state,
    const Vector<TruthGlobalMember>& committed, const CousinRouteRecord& route, bool installedDestination) {
  return (cousinRouteTerminal(route) || installedDestination) &&
      mothershipTruthRetiredRouteEndpoint(state,committed,route.destinationClusterUUID,route.destinationPublicAddress);
}
