#pragma once

#include <prodigy/types.h>

static bool truthSiblingRouteSlotZero(const CousinRouteRecord& route)
{
  if (!cousinRouteAllowsNewAdmissionAt(route, Time::now<TimeResolution::ms>()) ||
      route.sourceApplicationID != MeshRegistry::Truth::applicationID ||
      route.destinationApplicationID != MeshRegistry::Truth::applicationID ||
      route.sourceCousinServicePrefix != MeshRegistry::Truth::siblings ||
      route.destinationCousinServicePrefix != MeshRegistry::Truth::siblings || !route.slots.contains(0)) return false;
  for (uint16_t slot = 1; slot < CousinRouteSlotBitmap::slotCount; ++slot)
    if (route.slots.contains(slot)) return false;
  return true;
}

static bool truthSiblingPermissionMatches(const ProdigyLocalCousinServicePermission& permission,
                                          const CousinRouteRecord& route, CousinRouteHalf half,
                                          uint64_t deploymentID)
{
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
      permission.localDeploymentID == deploymentID && permission.peerDeploymentID == deploymentID;
}

// A test carrier starts with an explicitly admitted exact service tuple.
// Replacement can allocate further declared Whiteholes in the same deployment.
// Extend only that admitted service through the normal typed authorization and
// provider owner, keeping all existing tuples available during the transition.
bool reconcileTruthTestServiceTransits(const MothershipTruthGroup& state,
                                      const CousinRouteRecord& route,
                                      const MothershipProdigyCluster& source,
                                      String& failure)
{
  MothershipClusterPairEnrollmentIntent intent; bool found = false;
  {
    auto registry = openClusterRegistry();
    if (!registry.findClusterPairTestControlBoundary(route.pairUUID, intent, found, &failure)) return false;
  }
  if (!found) return true;
  auto seed = std::find_if(intent.testControlServiceTransits.begin(), intent.testControlServiceTransits.end(), [&](const auto& transit) {
    return transit.sourceClusterUUID == route.sourceClusterUUID && transit.destinationClusterUUID == route.destinationClusterUUID &&
        transit.sourcePermissionUUID == route.sourcePermissionUUID && transit.destinationPermissionUUID == route.destinationPermissionUUID &&
        transit.sourceDeploymentID == state.group.deploymentID && transit.destinationDeploymentID == state.group.deploymentID && transit.sourceSlot == 0;
  });
  if (seed == intent.testControlServiceTransits.end()) return true;
  const auto admittedService = *seed;
  RoutableResourceLeaseReport leases;
  if (!readRoutableResourceLeases(source, leases, failure)) return false;
  Vector<MothershipPairControlServiceTransit> missing, active;
  for (const auto& lease : leases.leases) {
    if (lease.kind != RoutableResourceLeaseKind::whiteholeAddressPort || lease.owner.deploymentID != state.group.deploymentID) continue;
    auto transit = admittedService;
    transit.sourceWhiteholeAddress = lease.address; transit.sourceTCPPort = lease.sourcePort;
    active.push_back(transit);
    if (std::any_of(intent.testControlServiceTransits.begin(), intent.testControlServiceTransits.end(), [&](const auto& existing) {
      return mothershipPairControlServiceTransitSameFlow(existing, transit);
    })) continue;
    missing.push_back(transit);
  }
  if (missing.empty()) {
    Vector<String> arguments; String receipt;
    if (mothershipPairControlBoundaryArguments(intent.testControlBoundary, "query"_ctv, arguments, &failure) &&
        mothershipRunVirtualDatacenterProvider(std::move(arguments), &receipt, &failure) &&
        mothershipPairControlBoundaryPreparedReceiptValid(intent.testControlBoundary, receipt, intent.testControlServiceTransits)) return true;
    // Admission is durable before the provider runs. Replay active tuples if
    // an earlier invocation stopped between intent persistence and preparation.
    missing = std::move(active); failure.clear();
  }
  TestPairLifecycleLock lock;
  if (!lockTestPairLifecycle(lock, failure)) return false;
  for (auto& transit : missing) {
    if (!validatePairControlServiceTransit(intent, transit, failure)) return false;
    {
      auto registry = openClusterRegistry();
      if (!registry.recordClusterPairTestControlServiceTransit(intent.operationUUID, transit, intent, &failure)) return false;
    }
    Vector<String> arguments;
    if (!mothershipPairControlServiceTransitArguments(intent.testControlBoundary, transit, arguments, &failure) ||
        !mothershipRunVirtualDatacenterProvider(std::move(arguments), &failure)) return false;
  }
  Vector<String> arguments; String receipt;
  return mothershipPairControlBoundaryArguments(intent.testControlBoundary, "query"_ctv, arguments, &failure) &&
      mothershipRunVirtualDatacenterProvider(std::move(arguments), &receipt, &failure) &&
      mothershipPairControlBoundaryPreparedReceiptValid(intent.testControlBoundary, receipt, intent.testControlServiceTransits);
}

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
    return (forward || reverse) && truthSiblingRouteSlotZero(route);
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
      if (!truthSiblingPermissionMatches(sourcePermission.permission, candidate, CousinRouteHalf::source, state.group.deploymentID) ||
          !truthSiblingPermissionMatches(destinationPermission.permission, candidate, CousinRouteHalf::destination, state.group.deploymentID) ||
          !prodigyCousinServicePermissionPeerScopeMatches(sourcePermission.permission, destinationPermission.permission)) continue;
      // Other pair installations can advance an authority revision while this
      // route stays qualified. Recover through the existing owner so its
      // authenticated live receipts are current before checking the witnesses.
      ProdigyCousinRouteResponse sourceRoute = {}, destinationRoute = {};
      if (!applyCousinRoute(candidate, source, destination, sourceRoute, destinationRoute, failure)) {
        if (failure.empty()) failure.assign("Truth sibling route receipt recovery failed"_ctv);
        return false;
      }
      CousinRouteApplyReceipt sourceReceipt = {}, destinationReceipt = {};
      {
        auto registry = openClusterRegistry();
        if (!registry.loadCurrentCousinRouteApplyReceipt(candidate.routeUUID, CousinRouteHalf::source, sourceReceipt, &failure) ||
            !registry.loadCurrentCousinRouteApplyReceipt(candidate.routeUUID, CousinRouteHalf::destination, destinationReceipt, &failure)) return false;
      }
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
          destinationPermission.currentMasterBootNs != destinationRoute.currentMasterBootNs) {
        if (failure.empty()) failure.assign("Truth sibling route permission, authority, or durable receipt changed during recovery; retry reconciliation"_ctv);
        return false;
      }
      if (!reconcileTruthTestServiceTransits(state, candidate, source, failure)) return false;
      ++exact;
    }
    if (exact != 1) {
      failure.assign("Truth needs exactly one qualified app-10 sibling COUSIN contract per eligible cluster pair; install two slot/group-0/1 permissions and one active cousinRoute with current receipts"_ctv);
      return false;
    }
  }
  return true;
}

// A private v3 route binds an authenticated counterpart's exact mesh address
// and service port.  A voter replacement changes that endpoint while retaining
// the permission-bound route scope.  Advance the existing route UUID only
// after the new binding is in the majority-certified Truth report; the route
// registry then fences the transition on receipts for the prior generation.
bool reconcileTruthReplacementRoute(const MothershipTruthGroup& state,
                                    const ProdigyTruthGlobalControl& leader,
                                    const std::vector<uint128_t>& eligible,
                                    String& failure)
{
  failure.clear();
  if (!mothershipTruthGroupValid(state) || !prodigyTruthControlReportValid(leader) ||
      leader.membershipUUID != state.group.membershipUUID ||
      leader.operationUUID != state.group.operationUUID ||
      leader.deploymentID != state.group.deploymentID ||
      leader.generation != state.group.generation ||
      leader.committedConfigIndex < state.group.expectedCommittedConfigIndex ||
      (leader.committedConfigIndex == state.group.expectedCommittedConfigIndex &&
       leader.committedConfigSHA256 != state.group.expectedCommittedConfigSHA256) ||
      leader.memberID != leader.leaderMemberID)
  {
    failure.assign("Truth replacement route requires the matching certified leader projection"_ctv);
    return false;
  }

  const TruthGlobalMember& incoming = state.incoming;
  if (incoming.memberID == 0) return true;
  if (std::find(eligible.begin(), eligible.end(), incoming.clusterUUID) == eligible.end()) return true;
  const auto projected = std::find_if(state.group.members.begin(), state.group.members.end(), [&](const auto& member) {
    return member.memberID == incoming.memberID && member.clusterUUID == incoming.clusterUUID &&
        member.containerUUID == incoming.containerUUID && member.privateIPv6.equals(incoming.privateIPv6);
  });
  const auto committed = std::find_if(leader.members.begin(), leader.members.end(), [&](const auto& member) {
    return member.memberID == incoming.memberID && member.clusterUUID == incoming.clusterUUID &&
        member.containerUUID == incoming.containerUUID && member.privateIPv6.equals(incoming.privateIPv6) &&
        (member.role == TruthGlobalMemberRole::learner || member.role == TruthGlobalMemberRole::voter);
  });
  if (projected == state.group.members.end()) {
    failure.assign("Truth replacement endpoint is not the exact committed incoming member"_ctv);
    return false;
  }
  // The placement is projected before Raft admits its learner.  Defer until
  // this majority-certified report proves the exact binding, so route setup
  // cannot become an add-learner prerequisite.
  if (committed == leader.members.end()) return true;

  const auto leaderMember = std::find_if(leader.members.begin(), leader.members.end(), [&](const auto& member) {
    return member.memberID == leader.memberID && member.role == TruthGlobalMemberRole::voter;
  });
  if (leaderMember == leader.members.end()) {
    failure.assign("Truth replacement route report does not identify a voter leader"_ctv);
    return false;
  }

  Vector<uint16_t> applications;
  applications.push_back(MeshRegistry::Truth::applicationID);
  Vector<CousinRouteRecord> candidates;
  const int64_t now = Time::now<TimeResolution::ms>();
  {
    auto registry = openClusterRegistry();
    for (uint128_t site : eligible) {
      Vector<CousinRouteRecord> siteCandidates;
      if (!registry.listNametagSeedSuccessorRouteCandidates(site, applications, now, siteCandidates, &failure)) return false;
      for (const auto& route : siteCandidates)
        if (std::none_of(candidates.begin(), candidates.end(), [&](const auto& prior) { return prior.routeUUID == route.routeUUID; }))
          candidates.push_back(route);
    }
  }

  const auto routeMatches = [&](const CousinRouteRecord& route) {
    if (route.version != 3 || route.endpointKind != CousinRouteEndpointKind::privateContainer ||
        !truthSiblingRouteSlotZero(route)) return false;
    return route.destinationClusterUUID == incoming.clusterUUID;
  };
  for (const auto& route : candidates) {
    if (!routeMatches(route) || !mothershipTruthReplacementRouteEndpoint(state, leader.members,
        route.destinationClusterUUID, route.destinationPublicAddress)) continue;
    MothershipProdigyCluster source = {}, destination = {};
    {
      auto registry = openClusterRegistry();
      if (!loadCousinRouteClusters(registry, route, source, destination, failure)) return false;
    }
    if (std::find(eligible.begin(), eligible.end(), source.clusterUUID) == eligible.end()) continue;
    ProdigyLocalCousinServicePermissionResponse sourcePermission = {}, destinationPermission = {};
    if (!readLocalCousinServicePermission(source, route.sourcePermissionUUID, sourcePermission, failure) ||
        !readLocalCousinServicePermission(destination, route.destinationPermissionUUID, destinationPermission, failure) ||
        !truthSiblingPermissionMatches(sourcePermission.permission, route, CousinRouteHalf::source, state.group.deploymentID) ||
        !truthSiblingPermissionMatches(destinationPermission.permission, route, CousinRouteHalf::destination, state.group.deploymentID) ||
        !prodigyCousinServicePermissionPeerScopeMatches(sourcePermission.permission, destinationPermission.permission))
    {
      if (failure.empty()) failure.assign("Truth replacement route permission does not match the committed app-10 sibling group"_ctv);
      return false;
    }

    ProdigyCousinDiscoveryQuery query = {};
    query.permissionUUID = route.sourcePermissionUUID;
    query.slot = 0;
    ProdigyCousinDiscoveryResponse discovery = {};
    if (!configureControlTarget(source.name.c_str(), &failure) ||
        !requestTopicRoundTrip(MothershipTopic::pullCousinCounterparts, query, discovery, failure) ||
        discovery.protocolVersion != ProdigyCousinDiscoveryResponse::version || !discovery.success)
    {
      if (failure.empty()) failure.assign("Truth replacement route counterpart discovery is unavailable"_ctv);
      return false;
    }
    const ProdigyCousinCounterpart* fresh = nullptr;
    for (const auto& counterpart : discovery.records) {
      if (counterpart.containerUUID != incoming.containerUUID || !counterpart.publicAddress.equals(incoming.privateIPv6) ||
          counterpart.routablePrefixUUID != 0 || counterpart.wormholeRevision.size() != 0 || counterpart.shardGroup != 0 ||
          counterpart.shardGroups != 1 || counterpart.service != MeshServices::constrainPrefixToGroup(MeshRegistry::Truth::siblings, 0) ||
          counterpart.servicePort == 0 || counterpart.publicTCPPort != counterpart.servicePort ||
          !prodigyCousinCounterpartMatchesPermission(counterpart, sourcePermission.permission, 0, true) ||
          !prodigyLocalCousinServicePermissionEqual(counterpart.permission, destinationPermission.permission)) continue;
      if (fresh != nullptr) {
        failure.assign("Truth replacement route has ambiguous fresh committed counterpart"_ctv);
        return false;
      }
      fresh = &counterpart;
    }
    if (fresh == nullptr) {
      failure.assign("Truth replacement route has no authenticated fresh committed counterpart"_ctv);
      return false;
    }

    CousinRouteRecord desired = route;
    if (!route.destinationPublicAddress.equals(fresh->publicAddress) || route.destinationTCPPort != fresh->publicTCPPort) {
      if (route.generation == UINT64_MAX || RAND_priv_bytes(reinterpret_cast<unsigned char*>(&desired.operationUUID),
                                                             sizeof(desired.operationUUID)) != 1 || !desired.operationUUID) {
        failure.assign("Truth replacement route cannot allocate a successor operation"_ctv);
        return false;
      }
      desired.generation++;
      desired.destinationPublicAddress = fresh->publicAddress;
      desired.destinationTCPPort = fresh->publicTCPPort;
      desired.priorOperationUUIDs.clear();
      bool resumed = false;
      CousinRouteRecord recorded = {};
      auto registry = openClusterRegistry();
      if (!registry.recordCousinRoute(desired, recorded, resumed, &failure)) return false;
      desired = std::move(recorded);
    }

    ProdigyCousinRouteResponse sourceRoute = {}, destinationRoute = {};
    if (!applyCousinRoute(desired, source, destination, sourceRoute, destinationRoute, failure)) return false;
  }
  return true;
}
