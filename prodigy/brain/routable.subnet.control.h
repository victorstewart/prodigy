#pragma once

inline void prodigyOwnDistributableExternalSubnet(const DistributableExternalSubnet& source,
                                                  DistributableExternalSubnet& target)
{
  target = {};
  target.uuid = source.uuid;
  target.name.assign(source.name);
  target.kind = source.kind;
  target.subnet = source.subnet;
  target.deliverySubnet = source.deliverySubnet;
  target.routing = source.routing;
  target.usage = source.usage;
  target.ingressScope = source.ingressScope;
  target.machineUUID = source.machineUUID;
  target.providerPool.assign(source.providerPool);
  target.providerAllocationID.assign(source.providerAllocationID);
  target.providerAssociationID.assign(source.providerAssociationID);
  target.releaseOnRemove = source.releaseOnRemove;
}

inline bool prodigyDistributableExternalSubnetsExactlyMatch(const DistributableExternalSubnet& left,
                                                            const DistributableExternalSubnet& right)
{
  return left.uuid == right.uuid && left.name.equals(right.name) && left.kind == right.kind &&
         left.subnet.equals(right.subnet) && left.deliverySubnet.equals(right.deliverySubnet) &&
         left.routing == right.routing && left.usage == right.usage &&
         left.ingressScope == right.ingressScope && left.machineUUID == right.machineUUID &&
         left.providerPool.equals(right.providerPool) &&
         left.providerAllocationID.equals(right.providerAllocationID) &&
         left.providerAssociationID.equals(right.providerAssociationID) &&
         left.releaseOnRemove == right.releaseOnRemove;
}

inline void prodigyOwnRoutableSubnetRegistration(const RoutableSubnetRegistration& source,
                                                  RoutableSubnetRegistration& target)
{
  target = {};
  prodigyOwnDistributableExternalSubnet(source.subnet, target.subnet);
  target.family = source.family;
  target.elasticIntent = source.elasticIntent;
  target.requestedAddress.assign(source.requestedAddress);
  target.success = source.success;
  target.created = source.created;
  target.failure.assign(source.failure);
}

inline void prodigyOwnRoutableSubnetUnregistration(const RoutableSubnetUnregistration& source,
                                                    RoutableSubnetUnregistration& target)
{
  target = {};
  target.name.assign(source.name);
  target.success = source.success;
  target.removed = source.removed;
  target.failure.assign(source.failure);
}

inline void prodigyElasticAddressRequestFromPendingAssignment(
    const ProdigyPendingElasticAddressAssignment& assignment,
    ProviderElasticAddressRequest& request)
{
  request = {};
  request.cloudID.assign(assignment.machineCloudID);
  request.family = assignment.registration.family;
  request.intent = assignment.registration.elasticIntent;
  request.requestedAddress.assign(assignment.registration.requestedAddress);
  request.providerPool.assign(assignment.registration.subnet.providerPool);
  request.deliveryPrefix = assignment.expectedDeliveryPrefix;
}

inline bool Brain::elasticAddressReplyStreamIsCurrent(const PendingElasticAddressControlOperation& operation)
{
  Mothership *stream = operation.mothership;
  if (stream == nullptr || activeMotherships.contains(stream) == false ||
      stream->connectionIncarnation != operation.mothershipIncarnation ||
      closingMotherships.contains(stream) || Ring::socketIsClosing(stream) ||
      streamIsActive(stream) == false)
  {
    return false;
  }
  return true;
}

inline void Brain::sendRoutableSubnetRegistrationResponse(Mothership *stream,
                                                           const RoutableSubnetRegistration& response)
{
  String serialized;
  BitseryEngine::serialize(serialized, response);
  Message::construct(stream->wBuffer, MothershipTopic::registerRoutableSubnet, serialized);
}

inline void Brain::sendRoutableSubnetUnregistrationResponse(Mothership *stream,
                                                             const RoutableSubnetUnregistration& response)
{
  String serialized;
  BitseryEngine::serialize(serialized, response);
  Message::construct(stream->wBuffer, MothershipTopic::unregisterRoutableSubnet, serialized);
}

inline void Brain::sendRoutableSubnetRegistrationResponse(const PendingElasticAddressControlOperation& operation,
                                                           const RoutableSubnetRegistration& response)
{
  if (elasticAddressReplyStreamIsCurrent(operation))
  {
    sendRoutableSubnetRegistrationResponse(operation.mothership, response);
    (void)flushActiveMothershipSendBuffer(operation.mothership,
                                          "register-routable-subnet-complete");
  }
}

inline void Brain::sendRoutableSubnetUnregistrationResponse(const PendingElasticAddressControlOperation& operation,
                                                             const RoutableSubnetUnregistration& response)
{
  if (elasticAddressReplyStreamIsCurrent(operation))
  {
    sendRoutableSubnetUnregistrationResponse(operation.mothership, response);
    (void)flushActiveMothershipSendBuffer(operation.mothership,
                                          "unregister-routable-subnet-complete");
  }
}

inline void Brain::commitRoutableSubnetRegistryChangeAsync(PersistenceCompletion completion)
{
  commitMasterAuthorityStateChangeAsync(
      [this, completion = std::move(completion)](bool durable) mutable {
        if (durable)
        {
          refreshAllDeploymentRegisteredRoutablePrefixWormholes();
          sendNeuronSwitchboardRoutableSubnets();
          sendNeuronSwitchboardHostedIngressPrefixes();
          sendNeuronSwitchboardOverlayRoutes();
        }
        if (completion) completion(durable);
      });
}

inline bool Brain::routableSubnetOperationPending(const String& name, uint128_t uuid) const
{
  for (const auto& [operationID, operation] : pendingElasticAddressControlOperations)
  {
    (void)operationID;
    const DistributableExternalSubnet& pending =
        operation.action != ProdigyBrainElasticAddressCoordinator::Action::release
            ? operation.registration.subnet
            : operation.releasedPrefix;
    if (pending.name.equals(name) || (uuid != 0 && pending.uuid == uuid))
    {
      return true;
    }
  }
  for (const ProdigyPendingElasticAddressRelease& release : masterAuthorityRuntimeState.pendingElasticAddressReleases)
  {
    if (release.prefix.name.equals(name) || (uuid != 0 && release.prefix.uuid == uuid))
    {
      return true;
    }
  }
  for (const ProdigyPendingElasticAddressAssignment& assignment : masterAuthorityRuntimeState.pendingElasticAddressAssignments)
  {
    if (assignment.registration.subnet.name.equals(name) ||
        (uuid != 0 && assignment.registration.subnet.uuid == uuid))
    {
      return true;
    }
  }
  return false;
}

inline bool Brain::routablePrefixReleasePending(uint128_t uuid) const
{
  if (uuid == 0)
  {
    return false;
  }
  for (const auto& [operationID, operation] : pendingElasticAddressControlOperations)
  {
    (void)operationID;
    if (operation.action == ProdigyBrainElasticAddressCoordinator::Action::release &&
        operation.releasedPrefix.uuid == uuid)
    {
      return true;
    }
  }
  for (const ProdigyPendingElasticAddressRelease& release : masterAuthorityRuntimeState.pendingElasticAddressReleases)
  {
    if (release.prefix.uuid == uuid)
    {
      return true;
    }
  }
  return false;
}

inline bool Brain::validatePendingElasticAddressOperations(
    const ProdigyMasterAuthorityRuntimeState& state,
    const BrainConfig *candidateBrainConfig) const
{
  constexpr uint32_t maximumPending = ProdigyBrainElasticAddressCoordinator::maximumQueuedOperations;
  constexpr uint32_t maximumNameBytes = 255;
  constexpr uint32_t maximumProviderFieldBytes = 4_KB;
  constexpr uint32_t maximumFailureBytes = 4_KB;
  constexpr uint32_t maximumRecordedAttempts = 1'000'000;
  if (state.pendingElasticAddressAssignments.size() + state.pendingElasticAddressReleases.size() > maximumPending ||
      state.nextPendingElasticAddressOperationID == 0)
  {
    return false;
  }

  bytell_hash_set<uint64_t> operationIDs;
  bytell_hash_set<uint128_t> prefixUUIDs;
  bytell_hash_set<String> prefixNames;
  const BrainConfig& registry = candidateBrainConfig ? *candidateBrainConfig : brainConfig;
  uint64_t greatestOperationID = 0;
  for (const ProdigyPendingElasticAddressAssignment& assignment : state.pendingElasticAddressAssignments)
  {
    const RoutableSubnetRegistration& registration = assignment.registration;
    const DistributableExternalSubnet& prefix = registration.subnet;
    if (assignment.version != ProdigyPendingElasticAddressAssignment::currentVersion ||
        assignment.operationID == 0 || operationIDs.insert(assignment.operationID).second == false ||
        assignment.transitionGeneration == 0 || assignment.transitionGeneration > state.generation ||
        assignment.transactionNonce == 0 || assignment.machineUUID == 0 ||
        assignment.machineCloudID.empty() || assignment.machineCloudID.size() > maximumProviderFieldBytes ||
        assignment.expectedDeliveryPrefix.network.isNull() ||
        assignment.expectedDeliveryPrefix.cidr != (assignment.expectedDeliveryPrefix.network.is6 ? 128 : 32) ||
        assignment.expectedDeliveryPrefix.equals(assignment.expectedDeliveryPrefix.canonicalized()) == false ||
        prefix.uuid == 0 || prefixUUIDs.insert(prefix.uuid).second == false ||
        prefix.name.empty() || prefix.name.size() > maximumNameBytes ||
        prefixNames.insert(prefix.name).second == false || prefix.kind != RoutablePrefixKind::elastic ||
        prefix.subnet.network.isNull() == false || prefix.deliverySubnet.network.isNull() == false ||
        prefix.routing != ExternalSubnetRouting::switchboardBGP ||
        externalSubnetUsageIsValid(prefix.usage) == false ||
        prefix.ingressScope != RoutableIngressScope::singleMachine ||
        prefix.machineUUID != assignment.machineUUID ||
        prefix.providerPool.size() > maximumProviderFieldBytes ||
        prefix.providerAllocationID.empty() == false || prefix.providerAssociationID.empty() == false ||
        prefix.releaseOnRemove ||
        (registration.family != ExternalAddressFamily::ipv4 && registration.family != ExternalAddressFamily::ipv6) ||
        elasticPrefixIntentIsValid(registration.elasticIntent) == false ||
        registration.requestedAddress.size() > maximumProviderFieldBytes ||
        registration.success || registration.created || registration.failure.empty() == false ||
        assignment.providerPlan.empty() ||
        assignment.providerPlan.size() > ProviderElasticAddressPlan::maximumBytes ||
        assignment.providerPlanBindingDigest.size() != 64 ||
        assignment.attempts > maximumRecordedAttempts || assignment.nextAttemptMs < 0 ||
        assignment.lastFailure.size() > maximumFailureBytes)
    {
      return false;
    }
    greatestOperationID = std::max(greatestOperationID, assignment.operationID);
    ProviderElasticAddressPlan providerPlan;
    providerPlan.opaque.assign(assignment.providerPlan);
    ProviderElasticAddressRequest providerRequest;
    prodigyElasticAddressRequestFromPendingAssignment(assignment, providerRequest);
    if (prodigyValidateElasticAddressPlanBinding(providerPlan,
                                                providerRequest,
                                                assignment.transactionNonce,
                                                assignment.providerPlanBindingDigest) == false)
    {
      return false;
    }
    for (const DistributableExternalSubnet& existing : registry.distributableExternalSubnets)
    {
      if (existing.uuid == prefix.uuid || existing.name.equals(prefix.name))
      {
        return false;
      }
    }
  }
  for (const ProdigyPendingElasticAddressRelease& release : state.pendingElasticAddressReleases)
  {
    const DistributableExternalSubnet& prefix = release.prefix;
    const bool prefixIs6 = prefix.subnet.network.is6;
    const uint8_t expectedCidr = prefixIs6 ? 128 : 32;
    if (release.version != ProdigyPendingElasticAddressRelease::currentVersion ||
        release.operationID == 0 || operationIDs.insert(release.operationID).second == false ||
        release.transitionGeneration == 0 || release.transitionGeneration > state.generation ||
        release.transactionNonce == 0 ||
        prefix.uuid == 0 || prefixUUIDs.insert(prefix.uuid).second == false ||
        prefix.name.empty() || prefix.name.size() > maximumNameBytes ||
        prefixNames.insert(prefix.name).second == false || prefix.kind != RoutablePrefixKind::elastic ||
        prefix.subnet.network.isNull() || prefix.subnet.cidr != expectedCidr ||
        prefix.deliverySubnet.network.isNull() ||
        prefix.deliverySubnet.network.is6 != prefixIs6 ||
        prefix.deliverySubnet.cidr != expectedCidr ||
        prefix.subnet.equals(prefix.subnet.canonicalized()) == false ||
        prefix.deliverySubnet.equals(prefix.deliverySubnet.canonicalized()) == false ||
        prefix.routing != ExternalSubnetRouting::switchboardBGP ||
        externalSubnetUsageIsValid(prefix.usage) == false ||
        prefix.ingressScope != RoutableIngressScope::singleMachine || prefix.machineUUID == 0 ||
        prefix.providerPool.size() > maximumProviderFieldBytes ||
        prefix.providerAllocationID.empty() ||
        prefix.providerAllocationID.size() > maximumProviderFieldBytes ||
        prefix.providerAssociationID.empty() ||
        prefix.providerAssociationID.size() > maximumProviderFieldBytes ||
        (prefix.releaseOnRemove && prefix.providerAllocationID.empty()) ||
        release.attempts > maximumRecordedAttempts || release.nextAttemptMs < 0 ||
        release.lastFailure.size() > maximumFailureBytes)
    {
      return false;
    }

    greatestOperationID = std::max(greatestOperationID, release.operationID);
    for (const DistributableExternalSubnet& existing : registry.distributableExternalSubnets)
    {
      if (existing.uuid == prefix.uuid || existing.name.equals(prefix.name))
      {
        return false;
      }
    }
  }
  return greatestOperationID < state.nextPendingElasticAddressOperationID;
}

inline void Brain::captureDurableElasticAddressOperations(void)
{
  durableElasticOperationTransitions.clear();
  for (const ProdigyPendingElasticAddressAssignment& assignment : masterAuthorityRuntimeState.pendingElasticAddressAssignments)
  {
    durableElasticOperationTransitions.emplace(assignment.operationID, assignment.transitionGeneration);
  }
  for (const ProdigyPendingElasticAddressRelease& release : masterAuthorityRuntimeState.pendingElasticAddressReleases)
  {
    durableElasticOperationTransitions.emplace(release.operationID, release.transitionGeneration);
  }
}

inline bool Brain::configurePendingElasticAddressReleaseFence(
    const ProdigyMasterAuthorityRuntimeState& state)
{
  if (iaas == nullptr)
  {
    return true;
  }
  if (state.pendingElasticAddressAssignments.empty() &&
      state.pendingElasticAddressReleases.empty())
  {
    return iaas->setElasticAddressReleaseFenceActive(false);
  }
  if (iaas->supportsTransactionalElasticAddresses() == false)
  {
    return false;
  }
  return iaas->setElasticAddressReleaseFenceActive(true);
}

inline bool Brain::quarantinePendingElasticAddressReleasePrefixes(const ProdigyMasterAuthorityRuntimeState& state)
{
  bool changed = false;
  for (const ProdigyPendingElasticAddressRelease& release : state.pendingElasticAddressReleases)
  {
    for (auto it = brainConfig.distributableExternalSubnets.begin();
         it != brainConfig.distributableExternalSubnets.end();)
    {
      if (it->uuid == release.prefix.uuid || it->name.equals(release.prefix.name))
      {
        it = brainConfig.distributableExternalSubnets.erase(it);
        changed = true;
      }
      else
      {
        ++it;
      }
    }
  }

  if (changed)
  {
    refreshAllDeploymentRegisteredRoutablePrefixWormholes();
    sendNeuronSwitchboardRoutableSubnets();
    sendNeuronSwitchboardHostedIngressPrefixes();
    sendNeuronSwitchboardOverlayRoutes();
  }
  return true;
}

inline bool Brain::replicatedRuntimeStateCoversPendingElasticAddressOperations(
    const ProdigyMasterAuthorityRuntimeState& incoming) const
{
  ProdigyMasterAuthorityRuntimeState expected = incoming;
  expected.updateSelf = {};
  ProdigyMasterAuthorityRuntimeState observed = masterAuthorityRuntimeState;
  observed.updateSelf = {};
  if (masterAuthorityRuntimeStateDurable == false ||
      durableMasterAuthorityRuntimeStateGeneration != incoming.generation ||
      observed != expected ||
      updateSelfRecoveryWitnessMatches(capturePersistentUpdateSelfState(), incoming.updateSelf) == false)
  {
    return false;
  }
  return true;
}

inline void Brain::noteMasterAuthorityTransitionSentToPeer(
    BrainView *peer,
    const ProdigyMasterAuthorityRuntimeState& state,
    const String& transitionDigest)
{
  if (!peerCanReceiveMasterAuthorityState(peer)) return;

  MasterAuthorityReplicationPeerState& tracking = masterAuthorityReplicationByPeer[peer];
  if (!tracking.matchesPeer(peer))
  {
    tracking = {};
    tracking.uuid = peer->uuid;
    tracking.bootNs = peer->boottimens;
    tracking.ioGeneration = peer->ioGeneration;
    tracking.transportEpoch = peer->transportEpoch;
    tracking.fileSlot = peer->fslot;
  }

  bytell_hash_set<uint64_t> liveOperationIDs;
  for (const ProdigyPendingElasticAddressAssignment& assignment : state.pendingElasticAddressAssignments)
  {
    liveOperationIDs.insert(assignment.operationID);
  }
  for (const ProdigyPendingElasticAddressRelease& release : state.pendingElasticAddressReleases)
  {
    liveOperationIDs.insert(release.operationID);
  }
  for (auto it = tracking.acknowledgedElasticOperationIDs.begin();
       it != tracking.acknowledgedElasticOperationIDs.end();)
  {
    if (liveOperationIDs.contains(*it))
    {
      ++it;
    }
    else
    {
      it = tracking.acknowledgedElasticOperationIDs.erase(it);
    }
  }
  for (auto generationIt = tracking.sentElasticOperationIDsByGeneration.begin();
       generationIt != tracking.sentElasticOperationIDsByGeneration.end();)
  {
    bytell_hash_set<uint64_t>& sent = generationIt->second;
    for (auto operationIt = sent.begin(); operationIt != sent.end();)
    {
      if (liveOperationIDs.contains(*operationIt))
      {
        ++operationIt;
      }
      else
      {
        operationIt = sent.erase(operationIt);
      }
    }
    // An empty operation set still carries an ordinary authority revision.
    // Keep its digest until acknowledgment or the existing bounded-history cap.
    ++generationIt;
  }

  bytell_hash_set<uint64_t>& operationIDs =
      tracking.sentElasticOperationIDsByGeneration[state.generation];
  operationIDs = liveOperationIDs;
  if (transitionDigest.size() != 64)
  {
    tracking.sentElasticOperationIDsByGeneration.erase(state.generation);
    tracking.sentTransitionDigestsByGeneration.erase(state.generation);
    return;
  }
  String ownedTransitionDigest;
  ownedTransitionDigest.assign(transitionDigest);
  tracking.sentTransitionDigestsByGeneration.insert_or_assign(
      state.generation,
      std::move(ownedTransitionDigest));

  while (tracking.sentElasticOperationIDsByGeneration.size() >
         ProdigyBrainElasticAddressCoordinator::maximumQueuedOperations)
  {
    auto oldest = tracking.sentElasticOperationIDsByGeneration.begin();
    for (auto it = tracking.sentElasticOperationIDsByGeneration.begin();
         it != tracking.sentElasticOperationIDsByGeneration.end(); ++it)
    {
      if (it->first < oldest->first)
      {
        oldest = it;
      }
    }
    const uint64_t oldestGeneration = oldest->first;
    tracking.sentElasticOperationIDsByGeneration.erase(oldest);
    tracking.sentTransitionDigestsByGeneration.erase(oldestGeneration);
  }
}

inline void Brain::acknowledgeMasterAuthorityTransition(
    BrainView *peer,
    const ProdigyMasterAuthorityStateTransitionAck& acknowledgement)
{
  if (!peerCanReceiveMasterAuthorityState(peer) ||
      acknowledgement.peerUUID != peer->uuid || acknowledgement.peerBootNs != peer->boottimens)
  {
    return;
  }
  auto trackingIt = masterAuthorityReplicationByPeer.find(peer);
  if (trackingIt == masterAuthorityReplicationByPeer.end())
  {
    return;
  }
  MasterAuthorityReplicationPeerState& tracking = trackingIt->second;
  if (!tracking.matchesPeer(peer))
  {
    masterAuthorityReplicationByPeer.erase(trackingIt);
    return;
  }
  auto digestIt = tracking.sentTransitionDigestsByGeneration.find(acknowledgement.generation);
  if (digestIt == tracking.sentTransitionDigestsByGeneration.end() ||
      acknowledgement.transitionDigest.size() != 64 ||
      digestIt->second.equals(acknowledgement.transitionDigest) == false)
  {
    return;
  }
  if (acknowledgement.generation >= tracking.acknowledgedGeneration)
  {
    tracking.acknowledgedGeneration = acknowledgement.generation;
    tracking.acknowledgedTransitionDigest.assign(acknowledgement.transitionDigest);
  }
  auto sentIt = tracking.sentElasticOperationIDsByGeneration.find(acknowledgement.generation);
  if (sentIt != tracking.sentElasticOperationIDsByGeneration.end())
  {
    for (uint64_t operationID : sentIt->second)
    {
      tracking.acknowledgedElasticOperationIDs.insert(operationID);
    }
    tracking.sentElasticOperationIDsByGeneration.erase(sentIt);
  }
  tracking.sentTransitionDigestsByGeneration.erase(digestIt);
  reconcilePendingElasticAddressAssignments();
  reconcilePendingElasticAddressReleases();
  reapRetiringMachines();
  maybeTransitionFollowersForUpdateSelf();
  maybeRelinquishMasterForUpdateSelf();
}

inline void Brain::sendMasterAuthorityTransitionAcknowledgement(
    BrainView *peer,
    uint64_t generation,
    const String& transitionDigest)
{
  if (peer == nullptr || peerSocketActive(peer) == false || transitionDigest.size() != 64)
  {
    return;
  }
  ProdigyMasterAuthorityStateTransitionAck acknowledgement = {};
  acknowledgement.generation = generation;
  acknowledgement.peerUUID = selfBrainUUID();
  acknowledgement.peerBootNs = boottimens;
  acknowledgement.transitionDigest.assign(transitionDigest);
  if (acknowledgement.peerUUID == 0 || acknowledgement.peerBootNs == 0)
  {
    return;
  }
  String serialized;
  BitseryEngine::serialize(serialized, acknowledgement);
  Message::construct(peer->wBuffer, BrainTopic::replicateMasterAuthorityState, serialized);
  Ring::queueSend(peer);
}

inline bool Brain::pendingElasticAddressOperationHasMajority(uint64_t operationID,
                                                             uint64_t transitionGeneration)
{
  const uint32_t required = std::max<uint32_t>(1, uint32_t(nBrains / 2) + 1);
  auto localIt = durableElasticOperationTransitions.find(operationID);
  const uint128_t localUUID = selfBrainUUID();
  uint32_t durable = localUUID != 0 && masterAuthorityRuntimeStateDurable &&
                             durableMasterAuthorityRuntimeStateGeneration >= transitionGeneration &&
                             localIt != durableElasticOperationTransitions.end() &&
                             localIt->second == transitionGeneration
                         ? 1 : 0;
  bytell_hash_set<uint128_t> countedPeerUUIDs;
  if (localUUID != 0)
  {
    countedPeerUUIDs.insert(localUUID);
  }
  bytell_hash_map<uint128_t, int64_t> latestPeerBootByUUID;
  for (BrainView *peer : brains)
  {
    if (peer == nullptr || peer->quarantined || peer->registrationFresh == false ||
        peer->uuid == 0 || peer->boottimens == 0 || peerSocketActive(peer) == false ||
        (peer->transportTLSEnabled() &&
         (peer->isTLSNegotiated() == false || peer->tlsPeerVerified == false ||
          peer->tlsPeerUUID != peer->uuid)))
    {
      continue;
    }
    int64_t& latestBoot = latestPeerBootByUUID[peer->uuid];
    latestBoot = std::max(latestBoot, peer->boottimens);
  }
  for (BrainView *peer : brains)
  {
    if (peer == nullptr || peer->quarantined || peer->registrationFresh == false ||
        peer->uuid == 0 || peer->boottimens == 0 || peerSocketActive(peer) == false ||
        (peer->transportTLSEnabled() &&
         (peer->isTLSNegotiated() == false || peer->tlsPeerVerified == false ||
          peer->tlsPeerUUID != peer->uuid)))
    {
      continue;
    }
    auto trackingIt = masterAuthorityReplicationByPeer.find(peer);
    if (trackingIt == masterAuthorityReplicationByPeer.end())
    {
      continue;
    }
    const MasterAuthorityReplicationPeerState& tracking = trackingIt->second;
    if (tracking.uuid == peer->uuid && tracking.bootNs == peer->boottimens &&
        latestPeerBootByUUID[tracking.uuid] == tracking.bootNs &&
        tracking.acknowledgedGeneration >= transitionGeneration &&
        tracking.acknowledgedElasticOperationIDs.contains(operationID) &&
        countedPeerUUIDs.insert(tracking.uuid).second)
    {
      durable += 1;
      if (durable >= required)
      {
        return true;
      }
    }
  }
  return durable >= required;
}

inline ProdigyPendingElasticAddressAssignment *Brain::findPendingElasticAddressAssignment(
    uint64_t operationID)
{
  for (ProdigyPendingElasticAddressAssignment& assignment : masterAuthorityRuntimeState.pendingElasticAddressAssignments)
  {
    if (assignment.operationID == operationID)
    {
      return &assignment;
    }
  }
  return nullptr;
}

inline const ProdigyPendingElasticAddressAssignment *Brain::findPendingElasticAddressAssignment(
    uint64_t operationID) const
{
  for (const ProdigyPendingElasticAddressAssignment& assignment : masterAuthorityRuntimeState.pendingElasticAddressAssignments)
  {
    if (assignment.operationID == operationID)
    {
      return &assignment;
    }
  }
  return nullptr;
}

inline ProdigyPendingElasticAddressRelease *Brain::findPendingElasticAddressRelease(
    uint64_t operationID)
{
  for (ProdigyPendingElasticAddressRelease& release : masterAuthorityRuntimeState.pendingElasticAddressReleases)
  {
    if (release.operationID == operationID)
    {
      return &release;
    }
  }
  return nullptr;
}

inline const ProdigyPendingElasticAddressRelease *Brain::findPendingElasticAddressRelease(
    uint64_t operationID) const
{
  for (const ProdigyPendingElasticAddressRelease& release : masterAuthorityRuntimeState.pendingElasticAddressReleases)
  {
    if (release.operationID == operationID)
    {
      return &release;
    }
  }
  return nullptr;
}

inline void Brain::commitPendingElasticAddressStateChangeAsync(
    PersistenceCompletion completion, bool advanceGeneration)
{
  commitMasterAuthorityStateChangeAsync(std::move(completion), advanceGeneration);
}

inline bool Brain::reserveElasticAddressControlOperationIDs(uint32_t count,
                                                            uint64_t& firstOperationID)
{
  uint64_t& next = masterAuthorityRuntimeState.nextPendingElasticAddressOperationID;
  if (count == 0 || next == 0 || masterAuthorityRuntimeState.generation == UINT64_MAX ||
      uint64_t(count) > UINT64_MAX - next)
  {
    firstOperationID = 0;
    return false;
  }
  firstOperationID = next;
  next += count;
  return true;
}

inline bool Brain::nextElasticAddressControlOperationID(uint64_t& operationID)
{
  return reserveElasticAddressControlOperationIDs(1, operationID);
}

inline uint32_t Brain::pendingElasticAddressLogicalOperationCount(void) const
{
  uint32_t count = masterAuthorityRuntimeState.pendingElasticAddressAssignments.size() +
                   masterAuthorityRuntimeState.pendingElasticAddressReleases.size();
  for (const auto& [operationID, control] : pendingElasticAddressControlOperations)
  {
    (void)operationID;
    if (findPendingElasticAddressAssignment(control.sagaOperationID) == nullptr &&
        findPendingElasticAddressRelease(control.sagaOperationID) == nullptr)
    {
      count += 1;
    }
  }
  return count;
}

inline bool Brain::elasticAddressSagaFencesRuntimeEnvironment(
    const ProdigyRuntimeEnvironmentConfig& requested) const
{
  return (masterAuthorityRuntimeState.pendingElasticAddressAssignments.empty() == false ||
          masterAuthorityRuntimeState.pendingElasticAddressReleases.empty() == false) &&
         (requested == brainConfig.runtimeEnvironment) == false;
}

inline bool Brain::enqueueElasticAddressAssignment(
    Mothership *stream,
    BrainIaaS& provider,
    const RoutableSubnetRegistration& request,
    uint128_t machineUUID,
    const String& machineCloudID,
    const IPPrefix& deliveryPrefix)
{
  struct Completion {
    bool called = false;
    bool durable = false;
  };
  std::shared_ptr<Completion> completion = std::make_shared<Completion>();
  enqueueElasticAddressAssignmentAsync(stream, provider, request, machineUUID, machineCloudID,
                                       deliveryPrefix, [completion](bool durable) {
    completion->called = true;
    completion->durable = durable;
  });
  return completion->called && completion->durable;
}

inline void Brain::enqueueElasticAddressAssignmentAsync(
    Mothership *stream,
    BrainIaaS& provider,
    RoutableSubnetRegistration request,
    uint128_t machineUUID,
    String machineCloudID,
    IPPrefix deliveryPrefix,
    PersistenceCompletion completion)
{
  if (provider.supportsTransactionalElasticAddresses() == false ||
      pendingElasticAddressLogicalOperationCount() >=
          ProdigyBrainElasticAddressCoordinator::maximumQueuedOperations ||
      masterAuthorityRuntimeState.generation >= UINT64_MAX - 3)
  {
    if (completion) completion(false);
    return;
  }

  uint64_t operationID = 0;
  if (nextElasticAddressControlOperationID(operationID) == false)
  {
    if (completion) completion(false);
    return;
  }

  uint128_t transactionNonce = Random::generateNumberWithNBits<128, uint128_t>();
  if (transactionNonce == 0)
  {
    transactionNonce = uint128_t(operationID) << 64 | operationID;
  }
  const uint64_t authorityEpoch = masterAuthorityEpoch;
  const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
  const uint64_t mothershipIncarnation = stream == nullptr ? 0 : stream->connectionIncarnation;
  commitPendingElasticAddressStateChangeAsync(
      [this, stream, &provider, request = std::move(request), machineUUID,
       machineCloudID = std::move(machineCloudID), deliveryPrefix, operationID,
       transactionNonce, authorityEpoch, operationGeneration, mothershipIncarnation,
       completion = std::move(completion)](bool durable) mutable {
        const bool current = durable && weAreMaster && masterAuthorityEpoch == authorityEpoch &&
                             masterAuthorityRuntimeState.generation == operationGeneration;
        if (!current)
        {
          if (masterAuthorityEpoch == authorityEpoch &&
              masterAuthorityRuntimeState.generation == operationGeneration &&
              masterAuthorityRuntimeState.nextPendingElasticAddressOperationID == operationID + 1)
          {
            masterAuthorityRuntimeState.nextPendingElasticAddressOperationID = operationID;
          }
          if (completion) completion(false);
          return;
        }

        if (provider.setElasticAddressReleaseFenceActive(true) == false)
        {
          if (completion) completion(false);
          return;
        }

        PendingElasticAddressControlOperation pending;
        pending.mothership = stream;
        pending.provider = &provider;
        pending.action = ProdigyBrainElasticAddressCoordinator::Action::prepareAssignment;
        pending.operationID = operationID;
        pending.sagaOperationID = operationID;
        pending.transactionNonce = transactionNonce;
        pending.mothershipIncarnation = mothershipIncarnation;
        pending.authorityEpoch = authorityEpoch;
        pending.machineUUID = machineUUID;
        pending.machineCloudID.assign(machineCloudID);
        pending.expectedDeliveryPrefix = deliveryPrefix;
        prodigyOwnRoutableSubnetRegistration(request, pending.registration);
        pendingElasticAddressControlOperations.emplace(operationID, std::move(pending));

        ProviderElasticAddressRequest providerRequest;
        providerRequest.cloudID.assign(machineCloudID);
        providerRequest.family = request.family;
        providerRequest.intent = request.elasticIntent;
        providerRequest.requestedAddress.assign(request.requestedAddress);
        providerRequest.providerPool.assign(request.subnet.providerPool);
        providerRequest.deliveryPrefix = deliveryPrefix;
        if (elasticAddressOperations.enqueue(provider, operationID, providerRequest, transactionNonce))
        {
          if (completion) completion(true);
          return;
        }

        pendingElasticAddressControlOperations.erase(operationID);
        if (masterAuthorityRuntimeState.pendingElasticAddressAssignments.empty() &&
            masterAuthorityRuntimeState.pendingElasticAddressReleases.empty())
        {
          (void)provider.setElasticAddressReleaseFenceActive(false);
        }
        if (completion) completion(false);
      });
}

inline bool Brain::enqueueElasticAddressRelease(
    Mothership *stream,
    BrainIaaS& provider,
    const RoutableSubnetUnregistration& request,
    const DistributableExternalSubnet& prefix)
{
  struct Completion {
    bool called = false;
    bool durable = false;
  };
  std::shared_ptr<Completion> completion = std::make_shared<Completion>();
  enqueueElasticAddressReleaseAsync(stream, provider, request, prefix, [completion](bool durable) {
    completion->called = true;
    completion->durable = durable;
  });
  return completion->called && completion->durable;
}

inline void Brain::enqueueElasticAddressReleaseAsync(
    Mothership *stream,
    BrainIaaS& provider,
    RoutableSubnetUnregistration request,
    DistributableExternalSubnet prefix,
    PersistenceCompletion completion)
{
  if (provider.supportsTransactionalElasticAddresses() == false ||
      pendingElasticAddressLogicalOperationCount() >=
          ProdigyBrainElasticAddressCoordinator::maximumQueuedOperations ||
      masterAuthorityRuntimeState.generation >= UINT64_MAX - 2)
  {
    if (completion) completion(false);
    return;
  }

  uint64_t operationID = 0;
  if (nextElasticAddressControlOperationID(operationID) == false)
  {
    if (completion) completion(false);
    return;
  }

  PendingElasticAddressControlOperation pending;
  pending.mothership = stream;
  pending.provider = &provider;
  pending.action = ProdigyBrainElasticAddressCoordinator::Action::release;
  pending.operationID = operationID;
  pending.sagaOperationID = operationID;
  pending.mothershipIncarnation = stream == nullptr ? 0 : stream->connectionIncarnation;
  pending.authorityEpoch = masterAuthorityEpoch;
  prodigyOwnRoutableSubnetUnregistration(request, pending.unregistration);
  prodigyOwnDistributableExternalSubnet(prefix, pending.releasedPrefix);
  pendingElasticAddressControlOperations.emplace(operationID, std::move(pending));

  ProdigyPendingElasticAddressRelease release;
  release.operationID = operationID;
  release.transitionGeneration = masterAuthorityRuntimeState.generation + 1;
  release.transactionNonce = Random::generateNumberWithNBits<128, uint128_t>();
  if (release.transactionNonce == 0)
  {
    release.transactionNonce = uint128_t(operationID) << 64 | operationID;
  }
  prodigyOwnDistributableExternalSubnet(prefix, release.prefix);
  masterAuthorityRuntimeState.pendingElasticAddressReleases.push_back(std::move(release));
  (void)quarantinePendingElasticAddressReleasePrefixes(masterAuthorityRuntimeState);
  const uint64_t authorityEpoch = masterAuthorityEpoch;
  const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
  commitPendingElasticAddressStateChangeAsync(
      [this, &provider, operationID, authorityEpoch, operationGeneration,
       completion = std::move(completion)](bool durable) mutable {
        const bool current = durable && weAreMaster && masterAuthorityEpoch == authorityEpoch &&
                             masterAuthorityRuntimeState.generation == operationGeneration;
        if (!current)
        {
          if (completion) completion(false);
          return;
        }
        if (provider.setElasticAddressReleaseFenceActive(true) == false)
        {
          if (completion) completion(false);
          return;
        }
        reconcilePendingElasticAddressReleases();
        if (completion) completion(true);
      });
}

inline void Brain::completeElasticAddressAssignment(
    PendingElasticAddressControlOperation& operation,
    ProviderElasticAddressPlan&& plan,
    ProviderElasticAddressAssignment&& assignment,
    String&& failure)
{
  RoutableSubnetRegistration response;
  prodigyOwnRoutableSubnetRegistration(operation.registration, response);
  response.success = false;
  response.created = false;
  response.failure = std::move(failure);

  if (operation.authorityEpoch != masterAuthorityEpoch || weAreMaster == false)
  {
    if (operation.provider != nullptr)
    {
      const bool fenceNeeded =
          masterAuthorityRuntimeState.pendingElasticAddressAssignments.empty() == false ||
          masterAuthorityRuntimeState.pendingElasticAddressReleases.empty() == false;
      (void)operation.provider->setElasticAddressReleaseFenceActive(fenceNeeded);
    }
    return;
  }
  if (operation.action == ProdigyBrainElasticAddressCoordinator::Action::prepareAssignment)
  {
    ProviderElasticAddressRequest providerRequest;
    providerRequest.cloudID.assign(operation.machineCloudID);
    providerRequest.family = operation.registration.family;
    providerRequest.intent = operation.registration.elasticIntent;
    providerRequest.requestedAddress.assign(operation.registration.requestedAddress);
    providerRequest.providerPool.assign(operation.registration.subnet.providerPool);
    providerRequest.deliveryPrefix = operation.expectedDeliveryPrefix;
    String planBindingDigest;
    if (response.failure.empty() == false || operation.provider == nullptr ||
        masterAuthorityRuntimeState.generation >= UINT64_MAX - 2 ||
        plan.opaque.empty() || plan.opaque.size() > ProviderElasticAddressPlan::maximumBytes ||
        operation.provider->validateProviderElasticAddressPlan(plan,
                                                               providerRequest,
                                                               operation.transactionNonce) == false ||
        prodigyComputeElasticAddressPlanBindingDigest(plan,
                                                      providerRequest,
                                                      operation.transactionNonce,
                                                      planBindingDigest) == false)
    {
      if (response.failure.empty())
      {
        response.failure.assign("provider elastic address plan is malformed"_ctv);
      }
      sendRoutableSubnetRegistrationResponse(operation, response);
      if (operation.provider != nullptr &&
          masterAuthorityRuntimeState.pendingElasticAddressAssignments.empty() &&
          masterAuthorityRuntimeState.pendingElasticAddressReleases.empty())
      {
        (void)operation.provider->setElasticAddressReleaseFenceActive(false);
      }
      return;
    }

    ProdigyPendingElasticAddressAssignment durable;
    durable.operationID = operation.sagaOperationID;
    durable.transitionGeneration = masterAuthorityRuntimeState.generation + 1;
    durable.transactionNonce = operation.transactionNonce;
    durable.machineUUID = operation.machineUUID;
    durable.machineCloudID.assign(operation.machineCloudID);
    durable.expectedDeliveryPrefix = operation.expectedDeliveryPrefix;
    prodigyOwnRoutableSubnetRegistration(operation.registration, durable.registration);
    durable.providerPlan = std::move(plan.opaque);
    durable.providerPlanBindingDigest = std::move(planBindingDigest);
    masterAuthorityRuntimeState.pendingElasticAddressAssignments.push_back(std::move(durable));
    operation.operationID = 0;
    operation.providerOperationEnqueued = false;
    operation.action = ProdigyBrainElasticAddressCoordinator::Action::applyAssignment;
    const uint64_t sagaOperationID = operation.sagaOperationID;
    const uint64_t authorityEpoch = operation.authorityEpoch;
    const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
    pendingElasticAddressControlOperations.emplace(sagaOperationID, std::move(operation));
    commitPendingElasticAddressStateChangeAsync(
        [this, sagaOperationID, authorityEpoch, operationGeneration](bool durable) {
          if (durable && weAreMaster && masterAuthorityEpoch == authorityEpoch &&
              masterAuthorityRuntimeState.generation == operationGeneration &&
              findPendingElasticAddressAssignment(sagaOperationID) != nullptr)
          {
            reconcilePendingElasticAddressAssignments();
          }
        });
    return;
  }

  ProdigyPendingElasticAddressAssignment *durable =
      findPendingElasticAddressAssignment(operation.sagaOperationID);
  if (durable == nullptr || durable->compensating)
  {
    reconcilePendingElasticAddressAssignments();
    return;
  }

  auto retainReplyForRetry = [&]() {
    const uint64_t sagaOperationID = operation.sagaOperationID;
    operation.operationID = 0;
    operation.providerOperationEnqueued = false;
    pendingElasticAddressControlOperations.insert_or_assign(sagaOperationID,
                                                            std::move(operation));
  };
  auto compensate = [&](const String& reason) {
    durable->compensating = true;
    durable->lastFailure.assign(reason);
    durable->nextAttemptMs = Time::now<TimeResolution::ms>();
    retainReplyForRetry();
    const uint64_t sagaOperationID = durable->operationID;
    const uint64_t authorityEpoch = masterAuthorityEpoch;
    const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
    commitPendingElasticAddressStateChangeAsync(
        [this, sagaOperationID, authorityEpoch, operationGeneration](bool durable) {
          if (durable && weAreMaster && masterAuthorityEpoch == authorityEpoch &&
              masterAuthorityRuntimeState.generation == operationGeneration &&
              findPendingElasticAddressAssignment(sagaOperationID) != nullptr)
          {
            reconcilePendingElasticAddressAssignments();
          }
        });
  };
  if (response.failure.empty() == false)
  {
    compensate(response.failure);
    return;
  }

  Machine *machine = findMachineByUUID(operation.machineUUID);
  if (machine == nullptr || machine->uuid != operation.machineUUID ||
      machine->cloudID.equals(operation.machineCloudID) == false)
  {
    compensate("target machine identity changed while provider assignment was pending"_ctv);
    return;
  }

  IPPrefix currentDeliveryPrefix;
  if (prodigyMachinePrivateAddressHostPrefix(*machine,
                                             operation.registration.family,
                                             currentDeliveryPrefix) == false ||
      currentDeliveryPrefix.equals(operation.expectedDeliveryPrefix) == false)
  {
    compensate("target machine delivery prefix changed while provider assignment was pending"_ctv);
    return;
  }

  const bool assignedFamilyMatches = assignment.assignedPrefix.network.is6 ==
                                     (operation.registration.family == ExternalAddressFamily::ipv6);
  const uint8_t expectedCidr = assignment.assignedPrefix.network.is6 ? 128 : 32;
  if (assignment.assignedPrefix.network.isNull() || assignedFamilyMatches == false ||
      assignment.assignedPrefix.cidr != expectedCidr || assignment.associationID.empty() ||
      (assignment.releaseOnRemove && assignment.allocationID.empty()) ||
      assignment.deliveryPrefix.equals(operation.expectedDeliveryPrefix) == false)
  {
    compensate("provider elastic address assignment is malformed"_ctv);
    return;
  }

  response.subnet.subnet = assignment.assignedPrefix;
  response.subnet.deliverySubnet = assignment.deliveryPrefix;
  response.subnet.providerAllocationID.assign(assignment.allocationID);
  response.subnet.providerAssociationID.assign(assignment.associationID);
  response.subnet.releaseOnRemove = assignment.releaseOnRemove;
  response.subnet.subnet.canonicalize();
  response.subnet.deliverySubnet.canonicalize();
  if (routableExternalSubnetHasSupportedBreadth(response.subnet) == false)
  {
    compensate("routable prefix CIDR is invalid"_ctv);
    return;
  }

  for (const DistributableExternalSubnet& existing : brainConfig.distributableExternalSubnets)
  {
    bool sameName = existing.name.equals(response.subnet.name);
    bool sameUUID = existing.uuid == response.subnet.uuid;
    if (sameName || sameUUID)
    {
      if (sameName && sameUUID)
      {
        compensate("routable prefix changed while provider assignment was pending"_ctv);
      }
      else
      {
        compensate("routable prefix name/UUID changed while provider assignment was pending"_ctv);
      }
      return;
    }
    if (ipPrefixesOverlap(existing.subnet, response.subnet.subnet))
    {
      response.failure.snprintf<"routable prefix overlaps existing prefix '{}'"_ctv>(existing.name);
      compensate(response.failure);
      return;
    }
  }

  DistributableExternalSubnet stored;
  prodigyOwnDistributableExternalSubnet(response.subnet, stored);
  brainConfig.distributableExternalSubnets.push_back(std::move(stored));
  ProdigyPendingElasticAddressAssignment saved = std::move(*durable);
  for (auto it = masterAuthorityRuntimeState.pendingElasticAddressAssignments.begin();
       it != masterAuthorityRuntimeState.pendingElasticAddressAssignments.end(); ++it)
  {
    if (it->operationID == saved.operationID)
    {
      masterAuthorityRuntimeState.pendingElasticAddressAssignments.erase(it);
      break;
    }
  }
  const uint64_t sagaOperationID = saved.operationID;
  const uint64_t authorityEpoch = operation.authorityEpoch;
  const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
  const uint128_t storedUUID = response.subnet.uuid;
  commitPendingElasticAddressStateChangeAsync(
      [this, operation = std::move(operation), response = std::move(response),
       saved = std::move(saved), sagaOperationID, authorityEpoch, operationGeneration,
       storedUUID](bool durable) mutable {
        if (!durable || weAreMaster == false || masterAuthorityEpoch != authorityEpoch ||
            masterAuthorityRuntimeState.generation != operationGeneration)
        {
          if (masterAuthorityEpoch == authorityEpoch &&
              masterAuthorityRuntimeState.generation == operationGeneration)
          {
            for (auto it = brainConfig.distributableExternalSubnets.begin();
                 it != brainConfig.distributableExternalSubnets.end(); ++it)
            {
              if (it->uuid == storedUUID)
              {
                brainConfig.distributableExternalSubnets.erase(it);
                break;
              }
            }
            if (findPendingElasticAddressAssignment(sagaOperationID) == nullptr)
            {
              masterAuthorityRuntimeState.pendingElasticAddressAssignments.push_back(std::move(saved));
            }
            operation.operationID = 0;
            operation.providerOperationEnqueued = false;
            pendingElasticAddressControlOperations.insert_or_assign(sagaOperationID, std::move(operation));
          }
          return;
        }
        refreshAllDeploymentRegisteredRoutablePrefixWormholes();
        sendNeuronSwitchboardRoutableSubnets();
        sendNeuronSwitchboardHostedIngressPrefixes();
        sendNeuronSwitchboardOverlayRoutes();
        (void)configurePendingElasticAddressReleaseFence(masterAuthorityRuntimeState);
        response.success = true;
        response.created = true;
        response.failure.clear();
        sendRoutableSubnetRegistrationResponse(operation, response);
      });
}

inline void Brain::completeElasticAddressCompensation(PendingElasticAddressControlOperation& operation,
                                                       String&& failure)
{
  if (operation.authorityEpoch != masterAuthorityEpoch || weAreMaster == false)
  {
    if (operation.provider != nullptr)
    {
      const bool fenceNeeded =
          masterAuthorityRuntimeState.pendingElasticAddressAssignments.empty() == false ||
          masterAuthorityRuntimeState.pendingElasticAddressReleases.empty() == false;
      (void)operation.provider->setElasticAddressReleaseFenceActive(fenceNeeded);
    }
    return;
  }
  ProdigyPendingElasticAddressAssignment *durable =
      findPendingElasticAddressAssignment(operation.sagaOperationID);
  if (durable == nullptr || durable->compensating == false)
  {
    return;
  }
  auto retainReplyForRetry = [&]() {
    const uint64_t sagaOperationID = operation.sagaOperationID;
    operation.operationID = 0;
    operation.providerOperationEnqueued = false;
    pendingElasticAddressControlOperations.insert_or_assign(sagaOperationID,
                                                            std::move(operation));
  };
  if (failure.empty() == false)
  {
    durable->lastFailure.assign(failure);
    const uint32_t shift = std::min<uint32_t>(durable->attempts ? durable->attempts - 1 : 0, 6);
    durable->nextAttemptMs = Time::now<TimeResolution::ms>() +
                             std::min<int64_t>(5'000LL << shift, 5 * 60 * 1000LL);
    retainReplyForRetry();
    const uint64_t sagaOperationID = durable->operationID;
    const uint64_t authorityEpoch = masterAuthorityEpoch;
    const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
    commitPendingElasticAddressStateChangeAsync(
        [this, sagaOperationID, authorityEpoch, operationGeneration](bool durable) {
          if (durable && weAreMaster && masterAuthorityEpoch == authorityEpoch &&
              masterAuthorityRuntimeState.generation == operationGeneration &&
              findPendingElasticAddressAssignment(sagaOperationID) != nullptr)
          {
            reconcilePendingElasticAddressAssignments();
          }
        });
    return;
  }

  RoutableSubnetRegistration response;
  prodigyOwnRoutableSubnetRegistration(durable->registration, response);
  if (durable->lastFailure.empty())
  {
    response.failure.assign("provider elastic address assignment rolled back"_ctv);
  }
  else
  {
    response.failure.assign(durable->lastFailure);
  }
  ProdigyPendingElasticAddressAssignment saved = std::move(*durable);
  for (auto it = masterAuthorityRuntimeState.pendingElasticAddressAssignments.begin();
       it != masterAuthorityRuntimeState.pendingElasticAddressAssignments.end(); ++it)
  {
    if (it->operationID == saved.operationID)
    {
      masterAuthorityRuntimeState.pendingElasticAddressAssignments.erase(it);
      break;
    }
  }
  const uint64_t sagaOperationID = saved.operationID;
  const uint64_t authorityEpoch = operation.authorityEpoch;
  const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
  commitPendingElasticAddressStateChangeAsync(
      [this, operation = std::move(operation), response = std::move(response),
       saved = std::move(saved), sagaOperationID, authorityEpoch, operationGeneration](bool durable) mutable {
        if (!durable || weAreMaster == false || masterAuthorityEpoch != authorityEpoch ||
            masterAuthorityRuntimeState.generation != operationGeneration)
        {
          if (masterAuthorityEpoch == authorityEpoch &&
              masterAuthorityRuntimeState.generation == operationGeneration &&
              findPendingElasticAddressAssignment(sagaOperationID) == nullptr)
          {
            masterAuthorityRuntimeState.pendingElasticAddressAssignments.push_back(std::move(saved));
            operation.operationID = 0;
            operation.providerOperationEnqueued = false;
            pendingElasticAddressControlOperations.insert_or_assign(sagaOperationID, std::move(operation));
          }
          return;
        }
        (void)configurePendingElasticAddressReleaseFence(masterAuthorityRuntimeState);
        sendRoutableSubnetRegistrationResponse(operation, response);
      });
}

inline void Brain::reconcilePendingElasticAddressAssignments(void)
{
  if (weAreMaster == false || iaas == nullptr ||
      iaas->supportsTransactionalElasticAddresses() == false ||
      configurePendingElasticAddressReleaseFence(masterAuthorityRuntimeState) == false ||
      masterAuthorityRuntimeState.generation >= UINT64_MAX - 1)
  {
    return;
  }
  if (masterAuthorityRuntimeStateDurable == false)
  {
    const uint64_t authorityEpoch = masterAuthorityEpoch;
    const uint64_t operationGeneration = masterAuthorityRuntimeState.generation;
    commitPendingElasticAddressStateChangeAsync(
        [this, authorityEpoch, operationGeneration](bool durable) {
          if (durable && weAreMaster && masterAuthorityEpoch == authorityEpoch &&
              masterAuthorityRuntimeState.generation == operationGeneration)
          {
            reconcilePendingElasticAddressAssignments();
          }
        }, false);
    return;
  }

  const int64_t nowMs = Time::now<TimeResolution::ms>();
  Vector<uint64_t> sagaIDs;
  for (const ProdigyPendingElasticAddressAssignment& assignment : masterAuthorityRuntimeState.pendingElasticAddressAssignments)
  {
    sagaIDs.push_back(assignment.operationID);
  }
  for (uint64_t sagaID : sagaIDs)
  {
    ProdigyPendingElasticAddressAssignment *assignment = findPendingElasticAddressAssignment(sagaID);
    if (assignment == nullptr || assignment->nextAttemptMs > nowMs ||
        pendingElasticAddressOperationHasMajority(sagaID, assignment->transitionGeneration) == false)
    {
      continue;
    }
    ProviderElasticAddressPlan plan;
    plan.opaque.assign(assignment->providerPlan);
    ProviderElasticAddressRequest providerRequest;
    prodigyElasticAddressRequestFromPendingAssignment(*assignment, providerRequest);
    if (prodigyValidateElasticAddressPlanBinding(plan,
                                                providerRequest,
                                                assignment->transactionNonce,
                                                assignment->providerPlanBindingDigest) == false ||
        iaas->validateProviderElasticAddressPlan(plan,
                                                providerRequest,
                                                assignment->transactionNonce) == false)
    {
      continue;
    }
    Machine *machine = findMachineByUUID(assignment->machineUUID);
    IPPrefix delivery;
    if (assignment->compensating == false &&
        (machine == nullptr || machine->cloudID.equals(assignment->machineCloudID) == false ||
         prodigyMachinePrivateAddressHostPrefix(*machine, assignment->registration.family, delivery) == false ||
         delivery.equals(assignment->expectedDeliveryPrefix) == false))
    {
      if (assignment->compensating == false)
      {
        assignment->compensating = true;
        assignment->lastFailure.assign("elastic assignment target identity changed before apply"_ctv);
        assignment->nextAttemptMs = nowMs;
        const uint64_t authorityEpoch = masterAuthorityEpoch;
        const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
        commitPendingElasticAddressStateChangeAsync(
            [this, sagaID, authorityEpoch, operationGeneration](bool durable) {
              if (durable && weAreMaster && masterAuthorityEpoch == authorityEpoch &&
                  masterAuthorityRuntimeState.generation == operationGeneration &&
                  findPendingElasticAddressAssignment(sagaID) != nullptr)
              {
                reconcilePendingElasticAddressAssignments();
              }
            });
        return;
      }
      continue;
    }
    bool alreadyEnqueued = false;
    for (const auto& [operationID, control] : pendingElasticAddressControlOperations)
    {
      (void)operationID;
      if (control.sagaOperationID == sagaID && control.providerOperationEnqueued)
      {
        alreadyEnqueued = true;
        break;
      }
    }
    if (alreadyEnqueued)
    {
      continue;
    }

    uint64_t attemptID = 0;
    if (nextElasticAddressControlOperationID(attemptID) == false)
    {
      return;
    }
    assignment->attempts = std::min<uint32_t>(assignment->attempts + 1, 1'000'000);
    const uint64_t authorityEpoch = masterAuthorityEpoch;
    const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
    commitPendingElasticAddressStateChangeAsync(
        [this, sagaID, attemptID, authorityEpoch, operationGeneration](bool durable) {
          if (durable && weAreMaster && masterAuthorityEpoch == authorityEpoch &&
              masterAuthorityRuntimeState.generation == operationGeneration)
          {
            ProdigyPendingElasticAddressAssignment *current =
                findPendingElasticAddressAssignment(sagaID);
            if (current == nullptr) return;
            ProviderElasticAddressPlan currentPlan;
            currentPlan.opaque.assign(current->providerPlan);
            ProviderElasticAddressRequest currentRequest;
            prodigyElasticAddressRequestFromPendingAssignment(*current, currentRequest);
            PendingElasticAddressControlOperation control;
            auto waiting = pendingElasticAddressControlOperations.find(sagaID);
            if (waiting != pendingElasticAddressControlOperations.end())
            {
              control = std::move(waiting->second);
              pendingElasticAddressControlOperations.erase(waiting);
            }
            else
            {
              control.sagaOperationID = sagaID;
              control.machineUUID = current->machineUUID;
              control.machineCloudID.assign(current->machineCloudID);
              control.expectedDeliveryPrefix = current->expectedDeliveryPrefix;
              prodigyOwnRoutableSubnetRegistration(current->registration, control.registration);
            }
            control.operationID = attemptID;
            control.provider = iaas;
            control.authorityEpoch = authorityEpoch;
            control.providerOperationEnqueued = true;
            control.action = current->compensating
                                 ? ProdigyBrainElasticAddressCoordinator::Action::compensateAssignment
                                 : ProdigyBrainElasticAddressCoordinator::Action::applyAssignment;
            pendingElasticAddressControlOperations.emplace(attemptID, std::move(control));
            if (elasticAddressOperations.enqueue(*iaas, attemptID,
                                                current->compensating
                                                    ? ProdigyBrainElasticAddressCoordinator::Action::compensateAssignment
                                                    : ProdigyBrainElasticAddressCoordinator::Action::applyAssignment,
                                                currentPlan, currentRequest,
                                                current->transactionNonce) == false)
            {
              auto rejected = pendingElasticAddressControlOperations.find(attemptID);
              if (rejected != pendingElasticAddressControlOperations.end())
              {
                PendingElasticAddressControlOperation retry = std::move(rejected->second);
                pendingElasticAddressControlOperations.erase(rejected);
                retry.operationID = 0;
                retry.providerOperationEnqueued = false;
                pendingElasticAddressControlOperations.emplace(sagaID, std::move(retry));
              }
            }
          }
        });
    return;

  }
}

inline void Brain::reconcilePendingElasticAddressReleases(void)
{
  if (weAreMaster == false || iaas == nullptr ||
      iaas->supportsTransactionalElasticAddresses() == false ||
      configurePendingElasticAddressReleaseFence(masterAuthorityRuntimeState) == false ||
      masterAuthorityRuntimeState.generation >= UINT64_MAX - 1)
  {
    return;
  }
  if (masterAuthorityRuntimeStateDurable == false)
  {
    const uint64_t authorityEpoch = masterAuthorityEpoch;
    const uint64_t operationGeneration = masterAuthorityRuntimeState.generation;
    commitPendingElasticAddressStateChangeAsync(
        [this, authorityEpoch, operationGeneration](bool durable) {
          if (durable && weAreMaster && masterAuthorityEpoch == authorityEpoch &&
              masterAuthorityRuntimeState.generation == operationGeneration)
          {
            reconcilePendingElasticAddressReleases();
          }
        }, false);
    return;
  }

  const int64_t nowMs = Time::now<TimeResolution::ms>();
  Vector<uint64_t> sagaOperationIDs;
  sagaOperationIDs.reserve(masterAuthorityRuntimeState.pendingElasticAddressReleases.size());
  for (const ProdigyPendingElasticAddressRelease& release : masterAuthorityRuntimeState.pendingElasticAddressReleases)
  {
    sagaOperationIDs.push_back(release.operationID);
  }

  for (uint64_t sagaOperationID : sagaOperationIDs)
  {
    ProdigyPendingElasticAddressRelease *release = findPendingElasticAddressRelease(sagaOperationID);
    if (release == nullptr || release->nextAttemptMs > nowMs ||
        pendingElasticAddressOperationHasMajority(release->operationID,
                                                 release->transitionGeneration) == false)
    {
      continue;
    }

    auto pendingIt = pendingElasticAddressControlOperations.end();
    for (auto it = pendingElasticAddressControlOperations.begin();
         it != pendingElasticAddressControlOperations.end(); ++it)
    {
      if (it->second.action == ProdigyBrainElasticAddressCoordinator::Action::release &&
          it->second.sagaOperationID == sagaOperationID)
      {
        pendingIt = it;
        break;
      }
    }
    if (pendingIt != pendingElasticAddressControlOperations.end() &&
        pendingIt->second.providerOperationEnqueued)
    {
      continue;
    }

    bool stillRegistered = false;
    for (const DistributableExternalSubnet& active : brainConfig.distributableExternalSubnets)
    {
      if (active.uuid == release->prefix.uuid || active.name.equals(release->prefix.name))
      {
        stillRegistered = true;
        break;
      }
    }
    if (stillRegistered)
    {
      release->lastFailure.assign("routable prefix quarantine was not preserved"_ctv);
      release->nextAttemptMs = nowMs + 5'000;
      const uint64_t authorityEpoch = masterAuthorityEpoch;
      const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
      commitPendingElasticAddressStateChangeAsync(
          [this, sagaOperationID, authorityEpoch, operationGeneration](bool durable) {
            if (durable && weAreMaster && masterAuthorityEpoch == authorityEpoch &&
                masterAuthorityRuntimeState.generation == operationGeneration &&
                findPendingElasticAddressRelease(sagaOperationID) != nullptr)
            {
              reconcilePendingElasticAddressReleases();
            }
          });
      return;
    }

    if (routablePrefixHasOwnedResourceLease(release->prefix.uuid))
    {
      release->attempts = std::min<uint32_t>(release->attempts + 1, 1'000'000);
      const uint32_t shift = std::min<uint32_t>(release->attempts - 1, 6);
      release->nextAttemptMs = nowMs + std::min<int64_t>(5'000LL << shift, 5 * 60 * 1000LL);
      release->lastFailure.assign("routable prefix acquired owned resources while cleanup was pending"_ctv);
      if (pendingIt != pendingElasticAddressControlOperations.end())
      {
        RoutableSubnetUnregistration response;
        prodigyOwnRoutableSubnetUnregistration(pendingIt->second.unregistration, response);
        response.failure = release->lastFailure;
        sendRoutableSubnetUnregistrationResponse(pendingIt->second, response);
        pendingElasticAddressControlOperations.erase(pendingIt);
      }
      const uint64_t authorityEpoch = masterAuthorityEpoch;
      const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
      commitPendingElasticAddressStateChangeAsync(
          [this, sagaOperationID, authorityEpoch, operationGeneration](bool durable) {
            if (durable && weAreMaster && masterAuthorityEpoch == authorityEpoch &&
                masterAuthorityRuntimeState.generation == operationGeneration &&
                findPendingElasticAddressRelease(sagaOperationID) != nullptr)
            {
              reconcilePendingElasticAddressReleases();
            }
          });
      return;
    }

    uint64_t attemptOperationID = 0;
    if (nextElasticAddressControlOperationID(attemptOperationID) == false)
    {
      return;
    }
    const uint64_t authorityEpoch = masterAuthorityEpoch;
    const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
    commitPendingElasticAddressStateChangeAsync(
        [this, sagaOperationID, attemptOperationID, authorityEpoch, operationGeneration](bool durable) {
          if (durable && weAreMaster && masterAuthorityEpoch == authorityEpoch &&
              masterAuthorityRuntimeState.generation == operationGeneration)
          {
            ProdigyPendingElasticAddressRelease *current =
                findPendingElasticAddressRelease(sagaOperationID);
            if (current == nullptr) return;
            PendingElasticAddressControlOperation pending;
            for (auto it = pendingElasticAddressControlOperations.begin();
                 it != pendingElasticAddressControlOperations.end(); ++it)
            {
              if (it->second.action == ProdigyBrainElasticAddressCoordinator::Action::release &&
                  it->second.sagaOperationID == sagaOperationID)
              {
                pending = std::move(it->second);
                pendingElasticAddressControlOperations.erase(it);
                break;
              }
            }
            if (pending.sagaOperationID == 0)
            {
              pending.action = ProdigyBrainElasticAddressCoordinator::Action::release;
              pending.sagaOperationID = sagaOperationID;
              pending.unregistration.name.assign(current->prefix.name);
              prodigyOwnDistributableExternalSubnet(current->prefix, pending.releasedPrefix);
            }
            pending.operationID = attemptOperationID;
            pending.authorityEpoch = authorityEpoch;
            pending.provider = iaas;
            pending.providerOperationEnqueued = true;
            pendingElasticAddressControlOperations.emplace(attemptOperationID, std::move(pending));
            ProviderElasticAddressRelease providerRelease;
            providerRelease.assignedPrefix = current->prefix.subnet;
            providerRelease.transactionNonce = current->transactionNonce;
            providerRelease.allocationID.assign(current->prefix.providerAllocationID);
            providerRelease.associationID.assign(current->prefix.providerAssociationID);
            providerRelease.releaseOnRemove = current->prefix.releaseOnRemove;
            if (elasticAddressOperations.enqueue(*iaas, attemptOperationID, providerRelease) == false)
            {
              auto rejected = pendingElasticAddressControlOperations.find(attemptOperationID);
              if (rejected != pendingElasticAddressControlOperations.end())
              {
                PendingElasticAddressControlOperation retry = std::move(rejected->second);
                pendingElasticAddressControlOperations.erase(rejected);
                retry.operationID = 0;
                retry.providerOperationEnqueued = false;
                pendingElasticAddressControlOperations.emplace(sagaOperationID, std::move(retry));
              }
            }
          }
        });
    return;

  }
}

inline void Brain::completeElasticAddressRelease(PendingElasticAddressControlOperation& operation,
                                                 String&& failure)
{
  RoutableSubnetUnregistration response;
  prodigyOwnRoutableSubnetUnregistration(operation.unregistration, response);
  response.success = false;
  response.removed = false;
  response.failure = std::move(failure);

  if (operation.authorityEpoch != masterAuthorityEpoch || weAreMaster == false)
  {
    if (operation.provider != nullptr)
    {
      const bool fenceNeeded =
          masterAuthorityRuntimeState.pendingElasticAddressAssignments.empty() == false ||
          masterAuthorityRuntimeState.pendingElasticAddressReleases.empty() == false;
      (void)operation.provider->setElasticAddressReleaseFenceActive(fenceNeeded);
    }
    return;
  }
  ProdigyPendingElasticAddressRelease *release =
      findPendingElasticAddressRelease(operation.sagaOperationID);
  if (release == nullptr ||
      prodigyDistributableExternalSubnetsExactlyMatch(release->prefix, operation.releasedPrefix) == false)
  {
    return;
  }
  (void)quarantinePendingElasticAddressReleasePrefixes(masterAuthorityRuntimeState);
  if (response.failure.empty() == false)
  {
    if (masterAuthorityRuntimeState.generation < UINT64_MAX)
    {
      release->attempts = std::min<uint32_t>(release->attempts + 1, 1'000'000);
      const uint32_t shift = std::min<uint32_t>(release->attempts - 1, 6);
      release->nextAttemptMs = Time::now<TimeResolution::ms>() +
                               std::min<int64_t>(5'000LL << shift, 5 * 60 * 1000LL);
      release->lastFailure = response.failure;
      const uint64_t authorityEpoch = operation.authorityEpoch;
      const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
      commitPendingElasticAddressStateChangeAsync(
          [this, operation = std::move(operation), response = std::move(response),
           authorityEpoch, operationGeneration](bool durable) mutable {
            if (durable && weAreMaster && masterAuthorityEpoch == authorityEpoch &&
                masterAuthorityRuntimeState.generation == operationGeneration)
            {
              sendRoutableSubnetUnregistrationResponse(operation, response);
            }
          });
      return;
    }
    return;
  }
  if (masterAuthorityRuntimeState.generation == UINT64_MAX)
  {
    response.failure.assign("master-authority runtime generation exhausted after provider cleanup"_ctv);
    sendRoutableSubnetUnregistrationResponse(operation, response);
    return;
  }

  ProdigyPendingElasticAddressRelease saved;
  for (auto it = masterAuthorityRuntimeState.pendingElasticAddressReleases.begin();
       it != masterAuthorityRuntimeState.pendingElasticAddressReleases.end(); ++it)
  {
    if (it->operationID == operation.sagaOperationID)
    {
      saved = std::move(*it);
      masterAuthorityRuntimeState.pendingElasticAddressReleases.erase(it);
      break;
    }
  }
  const uint64_t sagaOperationID = saved.operationID;
  const uint64_t authorityEpoch = operation.authorityEpoch;
  const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
  commitPendingElasticAddressStateChangeAsync(
      [this, operation = std::move(operation), response = std::move(response),
       saved = std::move(saved), sagaOperationID, authorityEpoch, operationGeneration](bool durable) mutable {
        if (!durable || weAreMaster == false || masterAuthorityEpoch != authorityEpoch ||
            masterAuthorityRuntimeState.generation != operationGeneration)
        {
          if (masterAuthorityEpoch == authorityEpoch &&
              masterAuthorityRuntimeState.generation == operationGeneration &&
              findPendingElasticAddressRelease(sagaOperationID) == nullptr)
          {
            masterAuthorityRuntimeState.pendingElasticAddressReleases.push_back(std::move(saved));
            operation.operationID = 0;
            operation.providerOperationEnqueued = false;
            pendingElasticAddressControlOperations.insert_or_assign(sagaOperationID, std::move(operation));
          }
          return;
        }
        (void)configurePendingElasticAddressReleaseFence(masterAuthorityRuntimeState);
        response.success = true;
        response.removed = true;
        sendRoutableSubnetUnregistrationResponse(operation, response);
      });
}

inline void Brain::elasticAddressOperationCompleted(
    void *context,
    uint64_t operationID,
    ProdigyBrainElasticAddressCoordinator::Action action,
    ProviderElasticAddressPlan&& plan,
    ProviderElasticAddressAssignment&& assignment,
    String&& failure)
{
  Brain& owner = *static_cast<Brain *>(context);
  auto pendingIt = owner.pendingElasticAddressControlOperations.find(operationID);
  if (pendingIt == owner.pendingElasticAddressControlOperations.end())
  {
    if (failure.empty() == false)
    {
      basics_log("provider elastic address cleanup failed operation=%llu action=%u error=%.*s\n",
                 (unsigned long long)operationID,
                 unsigned(action),
                 int(failure.size()),
                 reinterpret_cast<const char *>(failure.data()));
    }
    return;
  }

  PendingElasticAddressControlOperation pending = std::move(pendingIt->second);
  owner.pendingElasticAddressControlOperations.erase(pendingIt);
  if (pending.action != action)
  {
    return;
  }
  if (action == ProdigyBrainElasticAddressCoordinator::Action::prepareAssignment ||
      action == ProdigyBrainElasticAddressCoordinator::Action::applyAssignment)
  {
    owner.completeElasticAddressAssignment(pending,
                                           std::move(plan),
                                           std::move(assignment),
                                           std::move(failure));
  }
  else if (action == ProdigyBrainElasticAddressCoordinator::Action::compensateAssignment)
  {
    owner.completeElasticAddressCompensation(pending, std::move(failure));
  }
  else
  {
    owner.completeElasticAddressRelease(pending, std::move(failure));
  }
}

inline void Brain::handleRegisterRoutableSubnet(Mothership *stream, uint8_t *args)
{
  String serializedRequest;
  Message::extractToStringView(args, serializedRequest);
  RoutableSubnetRegistration request;
  RoutableSubnetRegistration response;

  if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
  {
    response.failure.assign("invalid subnet payload"_ctv);
  }
  else if (request.subnet.name.empty())
  {
    response.failure.assign("name required"_ctv);
  }
  else if (externalSubnetUsageIsValid(request.subnet.usage) == false)
  {
    response.failure.assign("usage invalid"_ctv);
  }
  else if (routablePrefixKindIsValid(request.subnet.kind) == false)
  {
    response.failure.assign("kind invalid"_ctv);
  }
  else if (routableIngressScopeIsValid(request.subnet.ingressScope) == false)
  {
    response.failure.assign("ingressScope invalid"_ctv);
  }
  else if (request.subnet.ingressScope == RoutableIngressScope::switchboardFleet && request.subnet.machineUUID != 0)
  {
    response.failure.assign("switchboardFleet routable prefix must not set machineUUID"_ctv);
  }
  else if (request.subnet.ingressScope == RoutableIngressScope::switchboardFleet && environmentBGPEnabled() == false)
  {
    response.failure.assign("switchboardFleet routable prefix registration requires bgp-enabled environment"_ctv);
  }
  else if (request.subnet.routing != ExternalSubnetRouting::switchboardBGP)
  {
    response.failure.assign("routable prefix registration only supports BGP"_ctv);
  }
  else if (request.subnet.kind == RoutablePrefixKind::elastic && request.subnet.ingressScope != RoutableIngressScope::singleMachine)
  {
    response.failure.assign("elastic routable prefixes require singleMachine ingressScope"_ctv);
  }
  else if (request.subnet.kind == RoutablePrefixKind::elastic && elasticPrefixIntentIsValid(request.elasticIntent) == false)
  {
    response.failure.assign("elasticIntent invalid"_ctv);
  }
  else if (request.subnet.kind == RoutablePrefixKind::elastic && request.subnet.subnet.network.isNull() == false)
  {
    response.failure.assign("elastic routable prefixes must be provider allocated"_ctv);
  }
  else if (request.subnet.kind == RoutablePrefixKind::elastic &&
           request.family != ExternalAddressFamily::ipv4 && request.family != ExternalAddressFamily::ipv6)
  {
    response.failure.assign("elastic routable prefix family invalid"_ctv);
  }
  else if (request.subnet.kind == RoutablePrefixKind::BGP &&
           (request.requestedAddress.empty() == false || request.subnet.providerPool.empty() == false))
  {
    response.failure.assign("BGP routable prefixes do not accept provider fields"_ctv);
  }
  else if (routableSubnetOperationPending(request.subnet.name, request.subnet.uuid))
  {
    response.failure.assign("routable prefix operation pending"_ctv);
  }
  else
  {
    if (request.subnet.kind == RoutablePrefixKind::elastic)
    {
      for (const DistributableExternalSubnet& existing : brainConfig.distributableExternalSubnets)
      {
        if ((request.subnet.uuid != 0 && existing.uuid == request.subnet.uuid) ||
            existing.name.equals(request.subnet.name))
        {
          if (existing.kind != RoutablePrefixKind::elastic ||
              (request.subnet.uuid != 0 && existing.uuid != request.subnet.uuid))
          {
            response.failure.assign("routable prefix already exists with different configuration; unregister it first"_ctv);
          }
          else
          {
            prodigyOwnDistributableExternalSubnet(existing, request.subnet);
            response.success = true;
            response.created = false;
          }
          break;
        }
      }
    }

    Machine *owner = nullptr;
    if (response.success == false && response.failure.empty() &&
        request.subnet.ingressScope == RoutableIngressScope::singleMachine)
    {
      owner = request.subnet.machineUUID == 0 ? nullptr : findMachineByUUID(request.subnet.machineUUID);
      if (request.subnet.machineUUID == 0)
      {
        for (Machine *machine : machines)
        {
          if (machine == nullptr || machine->uuid == 0)
          {
            continue;
          }
          if (owner != nullptr)
          {
            response.failure.assign("singleMachine routable prefix requires machineUUID when multiple machines exist"_ctv);
            break;
          }
          owner = machine;
        }
      }
      if (response.failure.empty() && owner == nullptr)
      {
        response.failure.assign("singleMachine routable prefix machineUUID is not registered"_ctv);
      }
      else if (response.failure.empty())
      {
        request.subnet.machineUUID = owner->uuid;
      }
    }

    if (request.subnet.kind == RoutablePrefixKind::elastic && response.success == false && response.failure.empty())
    {
      if (iaas == nullptr)
      {
        response.failure.assign("elastic routable prefix requires active iaas runtime"_ctv);
      }
      else if (iaas->supportsTransactionalElasticAddresses() == false)
      {
        response.failure.assign("active iaas runtime does not support transactional elastic addresses"_ctv);
      }
      else if (owner == nullptr || owner->cloudID.empty())
      {
        response.failure.assign("elastic routable prefix requires a cloud-backed target machine"_ctv);
      }
      else if (neuronControlStreamActive(owner) == false)
      {
        response.failure.assign("target machine neuron control stream is not active"_ctv);
      }
      else
      {
        if (request.subnet.uuid == 0)
        {
          request.subnet.uuid = Random::generateNumberWithNBits<128, uint128_t>();
        }
        IPPrefix deliveryPrefix;
        if (prodigyMachinePrivateAddressHostPrefix(*owner, request.family, deliveryPrefix) == false)
        {
          response.failure.assign("target machine delivery prefix is unavailable"_ctv);
        }
        else
        {
          const uint64_t mothershipIncarnation = stream->connectionIncarnation;
          const uint64_t authorityEpoch = masterAuthorityEpoch;
          RoutableSubnetRegistration replyRequest;
          prodigyOwnRoutableSubnetRegistration(request, replyRequest);
          enqueueElasticAddressAssignmentAsync(
              stream, *iaas, std::move(request), owner->uuid, owner->cloudID, deliveryPrefix,
              [this, stream, mothershipIncarnation, authorityEpoch,
               request = std::move(replyRequest)](bool durable) mutable {
                if (durable || weAreMaster == false || masterAuthorityEpoch != authorityEpoch) return;
                RoutableSubnetRegistration response;
                prodigyOwnRoutableSubnetRegistration(request, response);
                response.failure.assign("failed to persist elastic routable prefix operation"_ctv);
                PendingElasticAddressControlOperation operation;
                operation.mothership = stream;
                operation.mothershipIncarnation = mothershipIncarnation;
                sendRoutableSubnetRegistrationResponse(operation, response);
              });
          return;
        }
      }
    }

    if (request.subnet.kind != RoutablePrefixKind::elastic && response.success == false && response.failure.empty())
    {
      request.subnet.subnet.canonicalize();
      request.subnet.deliverySubnet.canonicalize();
      if (routableExternalSubnetHasSupportedBreadth(request.subnet) == false)
      {
        response.failure.assign("routable prefix CIDR is invalid"_ctv);
      }

      for (const DistributableExternalSubnet& existing : brainConfig.distributableExternalSubnets)
      {
        if (response.failure.empty() == false || existing.name.equals(request.subnet.name))
        {
          continue;
        }
        if (ipPrefixesOverlap(existing.subnet, request.subnet.subnet))
        {
          response.failure.snprintf<"routable prefix overlaps existing prefix '{}'"_ctv>(existing.name);
          break;
        }
      }

      if (response.failure.empty())
      {
        BrainConfig previousConfig;
        ownBrainConfig(brainConfig, previousConfig);
        ProdigyMasterAuthorityRuntimeState previousRuntimeState = masterAuthorityRuntimeState;
        const bool previousDurable = masterAuthorityRuntimeStateDurable;
        const uint64_t previousDurableGeneration = durableMasterAuthorityRuntimeStateGeneration;
        bool replaced = false;
        for (DistributableExternalSubnet& existing : brainConfig.distributableExternalSubnets)
        {
          if (existing.name.equals(request.subnet.name))
          {
            if (request.subnet.uuid == 0)
            {
              request.subnet.uuid = existing.uuid;
            }
            prodigyOwnDistributableExternalSubnet(request.subnet, existing);
            replaced = true;
            break;
          }
        }
        if (replaced == false)
        {
          if (request.subnet.uuid == 0)
          {
            request.subnet.uuid = Random::generateNumberWithNBits<128, uint128_t>();
          }
          DistributableExternalSubnet stored;
          prodigyOwnDistributableExternalSubnet(request.subnet, stored);
          brainConfig.distributableExternalSubnets.push_back(std::move(stored));
        }
        const uint64_t authorityEpoch = masterAuthorityEpoch;
        const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
        const uint64_t mothershipIncarnation = stream->connectionIncarnation;
        RoutableSubnetRegistration deferredResponse;
        prodigyOwnRoutableSubnetRegistration(request, deferredResponse);
        commitRoutableSubnetRegistryChangeAsync(
            [this, stream, mothershipIncarnation, authorityEpoch, operationGeneration,
             response = std::move(deferredResponse), previousConfig = std::move(previousConfig),
             previousRuntimeState = std::move(previousRuntimeState), previousDurable,
             previousDurableGeneration, replaced](bool durable) mutable {
              PendingElasticAddressControlOperation reply;
              reply.mothership = stream;
              reply.mothershipIncarnation = mothershipIncarnation;
              if (durable && weAreMaster && masterAuthorityEpoch == authorityEpoch &&
                  masterAuthorityRuntimeState.generation == operationGeneration)
              {
                response.success = true;
                response.created = !replaced;
              }
              else
              {
                if (masterAuthorityEpoch == authorityEpoch &&
                    masterAuthorityRuntimeState.generation == operationGeneration)
                {
                  brainConfig = std::move(previousConfig);
                  masterAuthorityRuntimeState = std::move(previousRuntimeState);
                  masterAuthorityRuntimeStateDurable = previousDurable;
                  durableMasterAuthorityRuntimeStateGeneration = previousDurableGeneration;
                }
                response.failure.assign("failed to persist routable prefix registry transition"_ctv);
              }
              sendRoutableSubnetRegistrationResponse(reply, response);
            });
        return;
      }
    }
  }

  response.subnet = request.subnet;
  response.family = request.family;
  response.elasticIntent = request.elasticIntent;
  response.requestedAddress = request.requestedAddress;
  sendRoutableSubnetRegistrationResponse(stream, response);
}

inline void Brain::handleUnregisterRoutableSubnet(Mothership *stream, uint8_t *args)
{
  String serializedRequest;
  Message::extractToStringView(args, serializedRequest);
  RoutableSubnetUnregistration request;
  RoutableSubnetUnregistration response;

  if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
  {
    response.failure.assign("invalid unregister payload"_ctv);
  }
  else if (request.name.empty())
  {
    response.failure.assign("name required"_ctv);
  }
  else if (routableSubnetOperationPending(request.name))
  {
    response.failure.assign("routable prefix operation pending"_ctv);
  }
  else
  {
    response.name.assign(request.name);
    auto match = brainConfig.distributableExternalSubnets.end();
    for (auto it = brainConfig.distributableExternalSubnets.begin();
         it != brainConfig.distributableExternalSubnets.end(); ++it)
    {
      if (it->name.equals(request.name))
      {
        match = it;
        break;
      }
    }

    if (match == brainConfig.distributableExternalSubnets.end())
    {
      response.success = true;
    }
    else if (routablePrefixHasOwnedResourceLease(match->uuid))
    {
      response.failure.assign("routable prefix has owned resources"_ctv);
    }
    else if (match->kind == RoutablePrefixKind::elastic)
    {
      if (iaas == nullptr)
      {
        response.failure.assign("provider elastic prefix cleanup requires active iaas runtime"_ctv);
      }
      else if (iaas->supportsTransactionalElasticAddresses() == false)
      {
        response.failure.assign("active iaas runtime does not support transactional elastic addresses"_ctv);
      }
      else
      {
        const uint64_t mothershipIncarnation = stream->connectionIncarnation;
        const uint64_t authorityEpoch = masterAuthorityEpoch;
        RoutableSubnetUnregistration replyRequest;
        prodigyOwnRoutableSubnetUnregistration(request, replyRequest);
        enqueueElasticAddressReleaseAsync(
            stream, *iaas, std::move(request), *match,
            [this, stream, mothershipIncarnation, authorityEpoch,
             request = std::move(replyRequest)](bool durable) mutable {
              if (durable || weAreMaster == false || masterAuthorityEpoch != authorityEpoch ||
                  routableSubnetOperationPending(request.name)) return;
              RoutableSubnetUnregistration response;
              prodigyOwnRoutableSubnetUnregistration(request, response);
              response.failure.assign("failed to persist elastic routable prefix operation"_ctv);
              PendingElasticAddressControlOperation operation;
              operation.mothership = stream;
              operation.mothershipIncarnation = mothershipIncarnation;
              sendRoutableSubnetUnregistrationResponse(operation, response);
            });
        return;
      }
    }
    else
    {
      BrainConfig previousConfig;
      ownBrainConfig(brainConfig, previousConfig);
      ProdigyMasterAuthorityRuntimeState previousRuntimeState = masterAuthorityRuntimeState;
      const bool previousDurable = masterAuthorityRuntimeStateDurable;
      const uint64_t previousDurableGeneration = durableMasterAuthorityRuntimeStateGeneration;
      brainConfig.distributableExternalSubnets.erase(match);
      const uint64_t authorityEpoch = masterAuthorityEpoch;
      const uint64_t operationGeneration = masterAuthorityRuntimeState.generation + 1;
      const uint64_t mothershipIncarnation = stream->connectionIncarnation;
      RoutableSubnetUnregistration deferredResponse;
      prodigyOwnRoutableSubnetUnregistration(request, deferredResponse);
      commitRoutableSubnetRegistryChangeAsync(
          [this, stream, mothershipIncarnation, authorityEpoch, operationGeneration,
           response = std::move(deferredResponse), previousConfig = std::move(previousConfig),
           previousRuntimeState = std::move(previousRuntimeState), previousDurable,
           previousDurableGeneration](bool durable) mutable {
            PendingElasticAddressControlOperation reply;
            reply.mothership = stream;
            reply.mothershipIncarnation = mothershipIncarnation;
            if (durable && weAreMaster && masterAuthorityEpoch == authorityEpoch &&
                masterAuthorityRuntimeState.generation == operationGeneration)
            {
              response.success = true;
              response.removed = true;
            }
            else
            {
              if (masterAuthorityEpoch == authorityEpoch &&
                  masterAuthorityRuntimeState.generation == operationGeneration)
              {
                masterAuthorityRuntimeState = std::move(previousRuntimeState);
                masterAuthorityRuntimeStateDurable = previousDurable;
                durableMasterAuthorityRuntimeStateGeneration = previousDurableGeneration;
                brainConfig = std::move(previousConfig);
              }
              response.failure.assign("failed to persist routable prefix registry transition"_ctv);
            }
            sendRoutableSubnetUnregistrationResponse(reply, response);
          });
      return;
    }
  }

  if (response.name.empty())
  {
    response.name.assign(request.name);
  }
  sendRoutableSubnetUnregistrationResponse(stream, response);
}
