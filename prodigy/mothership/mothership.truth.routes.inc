#pragma once

#include <prodigy/types.h>

// Permissions bind deployments on a cluster pair. The resulting authenticated
// sibling session binds both individual containers and the current Raft group.
// Included in Mothership. Route and permission UUIDs, ingress endpoints, and
// pair epochs are operator-/registry-owned, so this reconciler never mints
// them. It finds only existing contracts, then invokes the normal authenticated
// Brain observation owner for both halves before considering a remote Truth
// member connectable.
bool reconcileTruthSiblingRoutes(const MothershipTruthGroup& state,
                                 const std::vector<uint128_t>& eligible,
                                 String& failure)
{
  std::vector<std::pair<uint128_t,uint128_t>> required;
  for (const auto& a : state.group.members) for (const auto& b : state.group.members) {
    if (a.clusterUUID >= b.clusterUUID) continue;
    const auto pair = std::make_pair(a.clusterUUID,b.clusterUUID);
    if (std::find(required.begin(),required.end(),pair)==required.end()) required.push_back(pair);
  }
  if (required.empty()) return true;
  const auto eligibleSite = [&](uint128_t site) {
    return std::find(eligible.begin(), eligible.end(), site) != eligible.end();
  };
  const int64_t now = Time::now<TimeResolution::ms>();
  Vector<uint16_t> applications;
  applications.push_back(MeshRegistry::Truth::applicationID);
  Vector<CousinRouteRecord> candidates;
  {
    auto registry = openClusterRegistry();
    for (const auto site : eligible) {
      Vector<CousinRouteRecord> siteCandidates;
      if (!registry.listNametagSeedSuccessorRouteCandidates(site, applications, now, siteCandidates, &failure)) return false;
      for (const auto& route : siteCandidates)
        if (std::none_of(candidates.begin(), candidates.end(), [&](const auto& r){ return r.routeUUID == route.routeUUID; }))
          candidates.push_back(route);
    }
  }
  const auto routeMatches = [](const CousinRouteRecord& route,
                               const std::pair<uint128_t,uint128_t>& need) {
    const bool forward = route.sourceClusterUUID == need.first &&
                         route.destinationClusterUUID == need.second;
    const bool reverse = route.sourceClusterUUID == need.second &&
                         route.destinationClusterUUID == need.first;
    if (!(forward || reverse) || !cousinRouteAllowsNewAdmissionAt(route, Time::now<TimeResolution::ms>()) ||
        route.sourceApplicationID != MeshRegistry::Truth::applicationID ||
        route.destinationApplicationID != MeshRegistry::Truth::applicationID ||
        route.sourceCousinServicePrefix != MeshRegistry::Truth::siblings ||
        route.destinationCousinServicePrefix != MeshRegistry::Truth::siblings ||
        !route.slots.contains(0)) return false;
    for (uint16_t slot = 1; slot < CousinRouteSlotBitmap::slotCount; ++slot)
      if (route.slots.contains(slot)) return false;
    return true;
  };
  const auto permissionMatches = [&](const ProdigyLocalCousinServicePermission& permission,
                                     const CousinRouteRecord& route, CousinRouteHalf half) {
    const bool source = half == CousinRouteHalf::source;
    return permission.localHalf == half && permission.state == ProdigyLocalCousinServicePermissionState::active &&
        permission.localClusterUUID == (source ? route.sourceClusterUUID : route.destinationClusterUUID) &&
        permission.peerClusterUUID == (source ? route.destinationClusterUUID : route.sourceClusterUUID) &&
        permission.localApplicationID == MeshRegistry::Truth::applicationID &&
        permission.peerApplicationID == MeshRegistry::Truth::applicationID &&
        permission.purpose == ProdigyCousinServicePurpose::sibling &&
        permission.localCousinServicePrefix == MeshRegistry::Truth::siblings &&
        permission.peerCousinServicePrefix == MeshRegistry::Truth::siblings &&
        permission.authorizedService == MeshServices::constrainPrefixToGroup(MeshRegistry::Truth::siblings, 0) &&
        permission.destinationShardGroup == 0 && permission.destinationShardGroups == 1 && permission.slots.contains(0) &&
        permission.localDeploymentID == state.group.deploymentID && permission.peerDeploymentID == state.group.deploymentID;
  };
  for (const auto& need : required) {
    if (!eligibleSite(need.first) || !eligibleSite(need.second)) continue;
    uint32_t exact = 0;
    for (const auto& candidate : candidates) {
      if (!routeMatches(candidate, need)) continue;
      MothershipProdigyCluster source = {}, destination = {};
      {
        auto registry = openClusterRegistry();
        if (!loadCousinRouteClusters(registry, candidate, source, destination, failure)) return false;
      }
      ProdigyLocalCousinServicePermissionResponse sourcePermission = {}, destinationPermission = {};
      if (!readLocalCousinServicePermission(source, candidate.sourcePermissionUUID, sourcePermission, failure) ||
          !readLocalCousinServicePermission(destination, candidate.destinationPermissionUUID, destinationPermission, failure)) return false;
      if (!permissionMatches(sourcePermission.permission, candidate, CousinRouteHalf::source) ||
          !permissionMatches(destinationPermission.permission, candidate, CousinRouteHalf::destination) ||
          !prodigyCousinServicePermissionPeerScopeMatches(sourcePermission.permission, destinationPermission.permission)) continue;
      CousinRouteApplyReceipt sourceReceipt = {}, destinationReceipt = {};
      {
        auto registry = openClusterRegistry();
        if (!registry.loadCurrentCousinRouteApplyReceipt(candidate.routeUUID, CousinRouteHalf::source, sourceReceipt, &failure) ||
            !registry.loadCurrentCousinRouteApplyReceipt(candidate.routeUUID, CousinRouteHalf::destination, destinationReceipt, &failure)) return false;
      }
      ProdigyCousinRouteResponse sourceRoute = {}, destinationRoute = {};
      if (!observeCousinRouteSide(source, candidate, CousinRouteHalf::source, sourceRoute, failure) ||
          !observeCousinRouteSide(destination, candidate, CousinRouteHalf::destination, destinationRoute, failure) ||
          !sourceRoute.found || !sourceRoute.qualified || !destinationRoute.found || !destinationRoute.qualified ||
          !cousinRouteExactMatches(sourceRoute.route, candidate) || !cousinRouteExactMatches(destinationRoute.route, candidate) ||
          !cousinRouteApplyReceiptExactMatches(sourceRoute.applyReceipt, sourceReceipt) ||
          !cousinRouteApplyReceiptExactMatches(destinationRoute.applyReceipt, destinationReceipt) ||
          sourcePermission.currentAuthorityGeneration != sourceRoute.currentAuthorityGeneration ||
          destinationPermission.currentAuthorityGeneration != destinationRoute.currentAuthorityGeneration ||
          sourcePermission.currentMasterUUID != sourceRoute.currentMasterUUID ||
          destinationPermission.currentMasterUUID != destinationRoute.currentMasterUUID ||
          sourcePermission.currentMasterBootNs != sourceRoute.currentMasterBootNs ||
          destinationPermission.currentMasterBootNs != destinationRoute.currentMasterBootNs) return false;
      ++exact;
    }
    if (exact != 1) {
      failure.assign("Truth needs exactly one qualified app-10 sibling COUSIN contract per eligible cluster pair; install two slot/group-0/1 permissions and one active cousinRoute with current receipts"_ctv);
      return false;
    }
  }
  return true;
}
