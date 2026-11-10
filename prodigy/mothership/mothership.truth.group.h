#pragma once

#include <prodigy/mothership/truth.placement.selector.h>

// Stored once at the registry that owns global Truth placement. The projection
// describes container bindings. Raft alone changes the roles they exercise.
struct MothershipTruthGroup {
  uint32_t version = 2;
  uint64_t revision = 0, graceMs = 0;
  TruthGlobalMembershipProjection group;
  Vector<uint128_t> sites;
  struct Missing { int32_t id = 0; uint64_t sinceMs = 0; };
  Vector<Missing> missing;
  TruthGlobalMember outgoing, incoming;
  bool cleanup = false;
  Vector<TruthGlobalMember> retiredBindings;
};
template<class S> static void serialize(S&& s, MothershipTruthGroup::Missing& v) {
  s.value4b(v.id); s.value8b(v.sinceMs);
}
template<class S> static void serialize(S&& s, MothershipTruthGroup& v) {
  s.value4b(v.version); s.value8b(v.revision); s.value8b(v.graceMs); s.object(v.group);
  s.container(v.sites,64,[](auto& nested, uint128_t& site) { nested.value16b(site); }); s.container(v.missing,3); s.object(v.outgoing); s.object(v.incoming); s.value1b(v.cleanup);
  if (v.version == 2) s.container(v.retiredBindings, 256);
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
  if ((state.version != 1 && state.version != 2) || (state.version == 1 && !state.retiredBindings.empty()) ||
      !state.revision || !state.graceMs || state.sites.empty() || state.sites.size() > 64 ||
      !state.sites.front() || !std::is_sorted(state.sites.begin(), state.sites.end()) ||
      std::adjacent_find(state.sites.begin(), state.sites.end()) != state.sites.end() ||
      !prodigyTruthGlobalMembershipProjectionValid(state.group) ||
      state.retiredBindings.size() > state.group.retiredMemberIDs.size()) return false;
  int32_t previous = 0;
  for (const auto& binding : state.retiredBindings) {
    if (binding.memberID <= previous || !binding.containerUUID || !binding.privateIPv6.is6 || binding.privateIPv6.isNull() ||
        binding.role != TruthGlobalMemberRole::voter ||
        !std::binary_search(state.sites.begin(), state.sites.end(), binding.clusterUUID) ||
        !std::binary_search(state.group.retiredMemberIDs.begin(), state.group.retiredMemberIDs.end(), binding.memberID))
      return false;
    previous = binding.memberID;
  }
  return true;
}

// The COUSIN route is exact to a site and an address. Prefer a live owner's
// binding over any matching tombstone if the site has since reused an address.
static inline bool mothershipTruthReplacementRouteEndpoint(const MothershipTruthGroup& state,
    const Vector<TruthGlobalMember>& committed, uint128_t site, const IPAddress& address) {
  if (site != state.incoming.clusterUUID) return false;
  const auto matches = [&](const auto& member) {
    return member.clusterUUID == site && member.privateIPv6.equals(address);
  };
  for (const auto& member : committed)
    if (matches(member)) return member.memberID == state.incoming.memberID &&
                               member.containerUUID == state.incoming.containerUUID;
  return (state.outgoing.memberID && matches(state.outgoing)) ||
         std::any_of(state.retiredBindings.begin(), state.retiredBindings.end(), matches);
}
