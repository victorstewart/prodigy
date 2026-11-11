#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <vector>

namespace ProdigyTruthPlacement {
using ClusterID = __uint128_t;
using MemberID = int32_t;

struct Voter {
  MemberID id;
  ClusterID cluster;
  bool reachable;
  uint64_t missingSinceMs;
};

enum class Action { wait, addLearner, removeVoter, promoteLearner, retireContainer };

// One committed operation at a time. The owner persists this binding so a
// retry, restart or change in eligible sites cannot allocate a second learner.
struct Replacement {
  MemberID oldID;
  MemberID newID;
  ClusterID target;
};
struct Decision {
  Action action = Action::wait;
  Replacement replacement{};
};

inline std::vector<ClusterID> eligibleSites(std::vector<ClusterID> sites) {
  std::sort(sites.begin(), sites.end());
  sites.erase(std::remove(sites.begin(), sites.end(), ClusterID(0)), sites.end());
  sites.erase(std::unique(sites.begin(), sites.end()), sites.end());
  return sites;
}

// Genesis is separate from repair. Only the durable owner of a new group may
// call this, so loss of every heartbeat never looks like an empty deployment.
inline std::array<ClusterID,3> initial(std::vector<ClusterID> sites) {
  sites = eligibleSites(std::move(sites));
  if (sites.empty()) return {};
  return {sites[0], sites[1 % sites.size()], sites[2 % sites.size()]};
}

// The control-plane caller obtains voters, learner presence and catch-up from
// the same committed Truth configuration. A site heartbeat alone cannot count
// as a vote. Rebalancing preserves an already well-spread group.
inline Decision next(const std::vector<Voter>& voters, std::vector<ClusterID> sites,
                     uint64_t configIndex, MemberID highestAllocated, uint64_t nowMs, uint64_t graceMs,
                     const Replacement* pending = nullptr, bool learnerPresent = false, bool learnerCaughtUp = false) {
  if (!configIndex || voters.size() < 2 || voters.size() > 3) return {};
  sites = eligibleSites(std::move(sites));
  unsigned reachable = 0;
  for (const auto& v : voters) {
    if (v.id <= 0 || !v.cluster || v.id > highestAllocated ||
        std::count_if(voters.begin(), voters.end(), [&](const Voter& other){return other.id == v.id;}) != 1) return {};
    reachable += v.reachable;
  }
  if (reachable < 2) return {};

  if (pending) {
    if (!pending->target || pending->oldID <= 0 || pending->newID <= pending->oldID ||
        pending->newID > highestAllocated) return {};
    auto match = [&](MemberID id) {
      return std::find_if(voters.begin(), voters.end(), [&](const Voter& v){return v.id == id;});
    };
    const bool oldPresent = match(pending->oldID) != voters.end();
    const auto replacement = match(pending->newID);
    if (replacement != voters.end()) {
      if (!oldPresent && replacement->cluster == pending->target && voters.size() == 3)
        return {Action::retireContainer, *pending};
      return {};
    }
    if (!learnerPresent) return oldPresent ? Decision{Action::addLearner, *pending} : Decision{};
    if (!learnerCaughtUp) return {};
    // Removing a live voter must leave both remaining committed voters live.
    if (oldPresent && reachable - unsigned(match(pending->oldID)->reachable) < 2) return {};
    return {oldPresent ? Action::removeVoter : Action::promoteLearner, *pending};
  }

  if (sites.empty() || voters.size() != 3 || learnerPresent || highestAllocated == std::numeric_limits<MemberID>::max())
    return {};
  auto occupancy = [&](ClusterID site) {
    return std::count_if(voters.begin(), voters.end(), [&](const Voter& v){return v.cluster == site && v.reachable;});
  };
  const auto target = *std::min_element(sites.begin(), sites.end(), [&](ClusterID a, ClusterID b) {
    return occupancy(a) < occupancy(b);
  });
  const Voter* old = nullptr;
  for (const auto& v : voters) {
    if (!v.reachable) {
      if (!v.missingSinceMs || nowMs < v.missingSinceMs || nowMs - v.missingSinceMs < graceMs) return {};
      old = &v;
      break;
    }
    if (occupancy(v.cluster) > occupancy(target) + 1 &&
        (!old || occupancy(v.cluster) > occupancy(old->cluster) ||
         (occupancy(v.cluster) == occupancy(old->cluster) && v.id > old->id)))
      old = &v;
  }
  if (!old) return {};
  return {Action::addLearner, {old->id, highestAllocated+1, target}};
}
}
