#pragma once

#include <prodigy/types.h>

static bool truthSiblingRouteSlotZero(const CousinRouteRecord& route, bool includeTerminal = false)
{
  if (!(includeTerminal && cousinRouteTerminal(route) ? cousinRouteStructurallyValid(route) :
        cousinRouteAllowsNewAdmissionAt(route, Time::now<TimeResolution::ms>())) ||
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
// Included in Mothership. Permissions, ingress scopes, and pair epochs are
// operator-/registry-owned. Reconciliation invokes the normal authenticated
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
    uint32_t publicRoutes = 0;
    Vector<CousinRouteRecord> privateRoutes;
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
      if (candidate.version == 3 && candidate.endpointKind == CousinRouteEndpointKind::privateContainer)
        privateRoutes.push_back(candidate);
      else ++publicRoutes;
    }
    if (publicRoutes ? (publicRoutes != 1 || !privateRoutes.empty()) :
        (privateRoutes.empty() || !mothershipTruthPrivateRoutesCoverMembers(privateRoutes,state.group.members,need.first,need.second))) {
      failure.assign("Truth needs one qualified public sibling contract or exact private routes covering every member on each eligible cluster pair"_ctv);
      return false;
    }
  }
  return true;
}

// Preserve each current private endpoint while adding independently authorized
// routes for other committed members. A learner is covered after Raft admits
// it, before catch-up can require its own cross-site connection.
bool reconcileTruthMemberRoutes(const MothershipTruthGroup& state,
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
    failure.assign("Truth member routes require the matching certified leader projection"_ctv);
    return false;
  }
  for (const auto& member : leader.members)
    if (std::none_of(state.group.members.begin(),state.group.members.end(),[&](const auto& projected) {
      return projected.memberID == member.memberID && projected.clusterUUID == member.clusterUUID &&
          projected.containerUUID == member.containerUUID && projected.privateIPv6.equals(member.privateIPv6);
    })) { failure.assign("Truth route member is not an exact projected binding"_ctv); return false; }

  Vector<uint16_t> applications;
  applications.push_back(MeshRegistry::Truth::applicationID);
  Vector<CousinRouteRecord> candidates, contracts;
  const int64_t now = Time::now<TimeResolution::ms>();
  {
    auto registry = openClusterRegistry();
    for (uint128_t site : eligible) {
      Vector<CousinRouteRecord> siteCandidates;
      if (!registry.listNametagSeedSuccessorRouteCandidates(site, applications, now, siteCandidates, &failure, true)) return false;
      for (const auto& route : siteCandidates)
        if (std::none_of(candidates.begin(), candidates.end(), [&](const auto& prior) { return prior.routeUUID == route.routeUUID; }))
          candidates.push_back(route);
    }
  }
  const auto eligibleSite = [&](uint128_t site) {
    return std::find(eligible.begin(),eligible.end(),site) != eligible.end();
  };
  const auto sameContract = [](const CousinRouteRecord& a,const CousinRouteRecord& b) {
    auto normalized = b; normalized.routeUUID = a.routeUUID;
    return cousinRouteScopeMatches(a,normalized) && a.keyEpoch == b.keyEpoch && a.rootGeneration == b.rootGeneration;
  };
  for (const auto& route : candidates) {
    if (route.version != 3 || route.endpointKind != CousinRouteEndpointKind::privateContainer ||
        !truthSiblingRouteSlotZero(route) || !eligibleSite(route.sourceClusterUUID) || !eligibleSite(route.destinationClusterUUID)) continue;
    if (std::none_of(contracts.begin(),contracts.end(),[&](const auto& contract) { return sameContract(contract,route); }))
      contracts.push_back(route);
  }
  for (const auto& contract : contracts) {
    MothershipProdigyCluster source = {}, destination = {};
    {
      auto registry = openClusterRegistry();
      if (!loadCousinRouteClusters(registry, contract, source, destination, failure)) return false;
    }
    ProdigyLocalCousinServicePermissionResponse sourcePermission = {}, destinationPermission = {};
    if (!readLocalCousinServicePermission(source, contract.sourcePermissionUUID, sourcePermission, failure) ||
        !readLocalCousinServicePermission(destination, contract.destinationPermissionUUID, destinationPermission, failure)) return false;
    if (!truthSiblingPermissionMatches(sourcePermission.permission, contract, CousinRouteHalf::source, state.group.deploymentID) ||
        !truthSiblingPermissionMatches(destinationPermission.permission, contract, CousinRouteHalf::destination, state.group.deploymentID) ||
        !prodigyCousinServicePermissionPeerScopeMatches(sourcePermission.permission, destinationPermission.permission)) continue;

    ProdigyCousinDiscoveryQuery query = {};
    query.permissionUUID = contract.sourcePermissionUUID; query.slot = 0;
    ProdigyCousinDiscoveryResponse discovery = {};
    if (!configureControlTarget(source.name.c_str(), &failure) ||
        !requestTopicRoundTrip(MothershipTopic::pullCousinCounterparts, query, discovery, failure) ||
        discovery.protocolVersion != ProdigyCousinDiscoveryResponse::version || !discovery.success) return false;

    bool installedDestination = false;
    for (const auto& member : leader.members) {
      if (member.clusterUUID != contract.destinationClusterUUID) continue;
      const ProdigyCousinCounterpart* fresh = nullptr;
      for (const auto& counterpart : discovery.records) {
        if (counterpart.containerUUID != member.containerUUID || !counterpart.publicAddress.equals(member.privateIPv6) ||
            counterpart.routablePrefixUUID != 0 || !counterpart.wormholeRevision.empty() || counterpart.shardGroup != 0 ||
            counterpart.shardGroups != 1 || counterpart.service != MeshServices::constrainPrefixToGroup(MeshRegistry::Truth::siblings, 0) ||
            !counterpart.servicePort || counterpart.publicTCPPort != counterpart.servicePort ||
            !prodigyCousinCounterpartMatchesPermission(counterpart, sourcePermission.permission, 0, true) ||
            !prodigyLocalCousinServicePermissionEqual(counterpart.permission, destinationPermission.permission)) continue;
        if (fresh) { failure.assign("Truth member route has ambiguous authenticated counterparts"_ctv); return false; }
        fresh = &counterpart;
      }
      if (!fresh) {
        // A missing voter must not veto its own replacement. Its established
        // exact route stays intact while the ordinary grace policy runs.
        if (member.role == TruthGlobalMemberRole::voter &&
            !std::binary_search(leader.reachableMemberIDs.begin(),leader.reachableMemberIDs.end(),member.memberID)) continue;
        failure.assign("Truth member route awaits its authenticated committed counterpart"_ctv); return false;
      }
      CousinRouteRecord desired = contract;
      desired.destinationPublicAddress = fresh->publicAddress;
      desired.destinationTCPPort = fresh->publicTCPPort;
      const CousinRouteRecord* existing = nullptr;
      for (const auto& route : candidates) {
        if (!truthSiblingRouteSlotZero(route) || !cousinRoutePeerRangeScopeMatches(route,desired)) continue;
        if (existing) { failure.assign("Truth member endpoint has ambiguous route owners"_ctv); return false; }
        existing = &route;
      }
      if (existing) desired = *existing;
      else {
        if (RAND_priv_bytes(reinterpret_cast<unsigned char*>(&desired.routeUUID),sizeof(desired.routeUUID)) != 1 || !desired.routeUUID ||
            RAND_priv_bytes(reinterpret_cast<unsigned char*>(&desired.operationUUID),sizeof(desired.operationUUID)) != 1 || !desired.operationUUID)
        { failure.assign("Truth member route cannot allocate its durable identity"_ctv); return false; }
        desired.generation = 1; desired.priorOperationUUIDs.clear();
        // Inherit the admitted scope, epoch, MTU and remaining lifetime. Adding
        // a member cannot renew or widen the operator's authorization.
        bool resumed = false; CousinRouteRecord recorded;
        {
          auto registry = openClusterRegistry();
          if (!registry.recordCousinRoute(desired,recorded,resumed,&failure)) return false;
        }
        desired = std::move(recorded);
        candidates.push_back(desired);
      }
      ProdigyCousinRouteResponse sourceRoute = {}, destinationRoute = {};
      if (!applyCousinRoute(desired,source,destination,sourceRoute,destinationRoute,failure)) return false;
      installedDestination = true;
    }

    // Keep the sole active contract for an empty destination as the admitted
    // template for its return; membership/session identity checks fence the
    // retired process. Once a committed endpoint is installed, obsolete exact
    // routes can become terminal. Terminal records only finish their receipts;
    // they never authorize or seed another active route.
    for (auto& route : candidates) {
      if (!sameContract(contract,route) || !truthSiblingRouteSlotZero(route,true) ||
          !mothershipTruthPrivateRouteRetirementRequired(state,leader.members,route,installedDestination)) continue;
      CousinRouteRecord desired = route;
      if (!cousinRouteTerminal(desired)) {
        if (desired.generation == UINT64_MAX ||
            RAND_priv_bytes(reinterpret_cast<unsigned char*>(&desired.operationUUID),sizeof(desired.operationUUID)) != 1 || !desired.operationUUID)
        { failure.assign("Truth retired route cannot allocate its withdrawal"_ctv); return false; }
        ++desired.generation; desired.state = CousinRouteState::withdrawn;
        desired.withdrawalGeneration = desired.generation; desired.withdrawnAtMs = now;
        desired.priorOperationUUIDs.clear();
        bool resumed = false; CousinRouteRecord recorded;
        {
          auto registry = openClusterRegistry();
          if (!registry.recordCousinRoute(desired,recorded,resumed,&failure)) return false;
        }
        desired = std::move(recorded); route = desired;
      }
      ProdigyCousinRouteResponse sourceRoute = {}, destinationRoute = {};
      if (!applyCousinRoute(desired,source,destination,sourceRoute,destinationRoute,failure)) return false;
    }
  }
  return true;
}
