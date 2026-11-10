#pragma once

#include <prodigy/mothership/truth.placement.selector.h>

// Stored once at the registry that owns global Truth placement. The projection
// describes container bindings. Raft alone changes the roles they exercise.
struct MothershipTruthGroup {
  uint32_t version = 1;
  uint64_t revision = 0, graceMs = 0;
  TruthGlobalMembershipProjection group;
  Vector<uint128_t> sites;
  struct Missing { int32_t id = 0; uint64_t sinceMs = 0; };
  Vector<Missing> missing;
  TruthGlobalMember outgoing, incoming;
  bool cleanup = false;
};
template<class S> static void serialize(S&& s, MothershipTruthGroup::Missing& v) {
  s.value4b(v.id); s.value8b(v.sinceMs);
}
template<class S> static void serialize(S&& s, MothershipTruthGroup& v) {
  s.value4b(v.version); s.value8b(v.revision); s.value8b(v.graceMs); s.object(v.group);
  s.container(v.sites,64,[](auto& nested, uint128_t& site) { nested.value16b(site); }); s.container(v.missing,3); s.object(v.outgoing); s.object(v.incoming); s.value1b(v.cleanup);
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
  return state.version == 1 && state.revision && state.graceMs && !state.sites.empty() && state.sites.size() <= 64 &&
      std::is_sorted(state.sites.begin(),state.sites.end()) && state.sites.front() &&
      std::adjacent_find(state.sites.begin(),state.sites.end()) == state.sites.end() &&
      prodigyTruthGlobalMembershipProjectionValid(state.group);
}
