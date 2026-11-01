#pragma once

static ProdigyCousinDiscoveryPublication buildDiscoveryPublication(uint128_t nodeUUID,
                                                                  uint128_t sourceClusterUUID,
                                                                  uint128_t peerClusterUUID,
                                                                  uint128_t pairUUID,
                                                                  uint64_t rootGeneration,
                                                                  uint64_t keyEpoch,
                                                                  uint64_t projectionGeneration)
{
  ProdigyCousinDiscoveryPublication publication = {};
  publication.nodeUUID = nodeUUID;
  publication.projectionGeneration = projectionGeneration;
  auto& snapshot = publication.snapshot;
  snapshot.pairUUID = pairUUID;
  snapshot.sourceClusterUUID = sourceClusterUUID;
  snapshot.peerClusterUUID = peerClusterUUID;
  snapshot.rootGeneration = rootGeneration;
  snapshot.keyEpoch = keyEpoch;
  snapshot.authorityGeneration = projectionGeneration;
  ProdigyCousinCounterpart counterpart = {};
  counterpart.permission.permissionUUID = 0x7e01;
  counterpart.permission.pairUUID = pairUUID;
  counterpart.permission.logicalWorkloadUUID = 0x7e02;
  counterpart.permission.logicalServiceUUID = 0x7e03;
  counterpart.permission.localClusterUUID = sourceClusterUUID;
  counterpart.permission.peerClusterUUID = peerClusterUUID;
  counterpart.permission.localHalf = CousinRouteHalf::destination;
  counterpart.permission.localApplicationID = 7;
  counterpart.permission.peerApplicationID = 19;
  counterpart.permission.localCousinServicePrefix = MeshServices::generateStatefulService(7, 3);
  counterpart.permission.peerCousinServicePrefix = MeshServices::generateStatefulService(19, 3);
  counterpart.permission.slots.insert(3);
  counterpart.permission.localDeploymentID = 0x7000000000001;
  for (uint32_t index = 0; index < 64; ++index) {
    counterpart.permission.canonicalPlanSHA256.append('a'); counterpart.permission.artifactSHA256.append('b');
  }
  counterpart.permission.artifactBytes = 1;
  counterpart.permission.generation = 1;
  counterpart.permission.acceptedAuthorityGeneration = projectionGeneration;
  counterpart.permission.state = ProdigyLocalCousinServicePermissionState::active;
  counterpart.containerUUID = 0x7e04;
  counterpart.nodeUUID = nodeUUID;
  counterpart.containerID = 9;
  counterpart.shardGroups = 2;
  counterpart.shardGroup = statefulServiceGroupOwnerForSlot(3, counterpart.shardGroups);
  counterpart.service = MeshServices::constrainPrefixToGroup(counterpart.permission.localCousinServicePrefix,
                                                               counterpart.shardGroup);
  counterpart.servicePort = 9443;
  for (uint16_t slot = 0; slot < nStatefulServiceGroupSlots; ++slot)
    if (counterpart.permission.slots.contains(slot) &&
        statefulServiceGroupOwnerForSlot(slot, counterpart.shardGroups) == counterpart.shardGroup)
      counterpart.ownedSlots.insert(slot);
  counterpart.routablePrefixUUID = 0x7e05;
  counterpart.publicAddress = IPAddress("fd00:ffff:1234::7", true);
  counterpart.publicTCPPort = 8443;
  for (uint32_t index = 0; index < 64; ++index) counterpart.wormholeRevision.append('c');
  snapshot.records.push_back(std::move(counterpart));
  return publication;
}

static ProdigyCousinSessionControl buildSessionControl(const ProdigyCousinCounterpart& destination,
                                                       uint64_t rootGeneration, uint64_t keyEpoch,
                                                       uint128_t sessionUUID = 0x7f01, uint128_t requestUUID = 0x7f02)
{
  ProdigyCousinSessionControl control = {};
  control.kind = ProdigyCousinSessionControlKind::propose;
  auto& session = control.session;
  session.sessionUUID = sessionUUID; session.requestUUID = requestUUID;
  session.rootGeneration = rootGeneration; session.keyEpoch = keyEpoch; session.slot = 3;
  session.destination = destination;
  session.sourcePermission = destination.permission;
  session.sourcePermission.permissionUUID = 0x7f03;
  session.sourcePermission.localHalf = CousinRouteHalf::source;
  std::swap(session.sourcePermission.localClusterUUID, session.sourcePermission.peerClusterUUID);
  std::swap(session.sourcePermission.localApplicationID, session.sourcePermission.peerApplicationID);
  std::swap(session.sourcePermission.localCousinServicePrefix, session.sourcePermission.peerCousinServicePrefix);
  session.sourcePermission.localDeploymentID = uint64_t(session.sourcePermission.localApplicationID) << 48 | 1;
  session.sourceContainerUUID = 0x7f04; session.sourceNodeUUID = uint128_t(0x111); session.sourceContainerID = 0x01020304;
  session.sourceShardGroups = 2; session.sourceShardGroup = statefulServiceGroupOwnerForSlot(3, 2);
  session.sourceService = MeshServices::constrainPrefixToGroup(session.sourcePermission.localCousinServicePrefix,
                                                                 session.sourceShardGroup);
  session.sourceBindingNonce = 1; session.sourceAddress = localTestAddress; session.sourceTCPPort = 40001;
  return control;
}

static CousinRouteRecord buildRouteForSession(const ProdigyCousinSessionRecord& session)
{
  CousinRouteRecord route = {};
  route.routeUUID = 0x7f10; route.operationUUID = 0x7f11;
  route.pairUUID = session.sourcePermission.pairUUID;
  route.logicalWorkloadUUID = session.sourcePermission.logicalWorkloadUUID;
  route.logicalServiceUUID = session.sourcePermission.logicalServiceUUID;
  route.sourceClusterUUID = session.sourcePermission.localClusterUUID;
  route.sourceApplicationID = session.sourcePermission.localApplicationID;
  route.sourceCousinServicePrefix = session.sourcePermission.localCousinServicePrefix;
  route.destinationClusterUUID = session.destination.permission.localClusterUUID;
  route.destinationApplicationID = session.destination.permission.localApplicationID;
  route.destinationCousinServicePrefix = session.destination.permission.localCousinServicePrefix;
  route.slots.insert(session.slot);
  route.destinationRoutablePrefixUUID = session.destination.routablePrefixUUID;
  route.destinationPublicAddress = session.destination.publicAddress;
  route.destinationTCPPort = session.destination.publicTCPPort;
  route.sourcePermissionUUID = session.sourcePermission.permissionUUID;
  route.destinationPermissionUUID = session.destination.permission.permissionUUID;
  route.transportProtocol = IPPROTO_TCP;
  route.destinationCIDR = 128;
  route.pathMTU = cousinRouteMinimumPathMTU;
  route.generation = 3; route.issuedAtMs = 1000; route.expiresAtMs = 60000;
  route.keyEpoch = session.keyEpoch; route.rootGeneration = session.rootGeneration;
  route.state = CousinRouteState::active;
  return route;
}


static ProdigyCousinSessionLocalCommand fixture(CousinRouteHalf half, uint128_t sessionUUID = 0x7f01,
                                                uint128_t requestUUID = 0x7f02)
{
  auto publication = buildDiscoveryPublication(0x222, 0x300, 0x200, 0x100, 7, 9, 11);
  auto session = buildSessionControl(publication.snapshot.records[0], 7, 9, sessionUUID, requestUUID).session;
  session.destination.publicAddress = localTestAddress;
  session.destination.publicTCPPort = 49192;
  const CousinRouteRecord route = buildRouteForSession(session);
  if (!prodigyCousinSessionRouteBindingForRoute(route, session.route)) session.protocolVersion = 0;
  ProdigyCousinSessionLocalCommand command = {};
  command.session = session; command.requestUUID = session.requestUUID; command.localHalf = half;
  command.kind = half == CousinRouteHalf::source ? ProdigyCousinSessionLocalKind::activate : ProdigyCousinSessionLocalKind::install;
  command.validForMs = ProdigyCousinSessionLeaseMs;
  ClusterPairRoot root = {};
  root.pairUUID = 0x100; root.firstClusterUUID = 0x200; root.secondClusterUUID = 0x300; root.rootGeneration = 7;
  for (unsigned i = 0; i < root.root.size(); ++i) root.root[i] = uint8_t(i + 1);
  ClusterPairKeyContext context = {}; ClusterPairDerivedKey key = {};
  expect(prodigyCousinSessionKeyContext(session, context) && clusterPairDeriveKey(root, context, key) && key.size == 32,
         "native_session_derives_purpose_scoped_32_byte_key");
  std::memcpy(command.psk.data(), key.bytes.data(), 32);
  prodigyCousinSessionDigest(session, command.canonicalContext);
  return command;
}

static ProdigyCousinSessionLocalCommand purposeFixture(CousinRouteHalf half,
    ProdigyCousinServicePurpose purpose, bool nat = false, uint16_t destinationApp = 10,
    uint16_t group = 0, uint16_t groups = 1, uint128_t sessionUUID = 0x7f01, uint128_t permissionUUID = 0)
{
  auto command = fixture(half, sessionUUID, sessionUUID + 1);
  auto& session = command.session;
  auto& source = session.sourcePermission; auto& destination = session.destination.permission;
  source.protocolVersion = destination.protocolVersion = 3; source.purpose = destination.purpose = purpose;
  if (permissionUUID != 0) source.permissionUUID = permissionUUID;
  else if (purpose == ProdigyCousinServicePurpose::clientAuthority) source.permissionUUID += destinationApp;
  source.localApplicationID = destination.peerApplicationID = purpose == ProdigyCousinServicePurpose::clientAuthority ? 6 : 2;
  source.peerApplicationID = destination.localApplicationID = purpose == ProdigyCousinServicePurpose::clientAuthority ? destinationApp : 2;
  source.localCousinServicePrefix = destination.peerCousinServicePrefix = purpose == ProdigyCousinServicePurpose::clientAuthority ?
      MeshServices::generateStatefulService(6, 1) : purpose == ProdigyCousinServicePurpose::sibling ? MeshRegistry::Pulse::siblings : MeshRegistry::Pulse::seeding;
  source.peerCousinServicePrefix = destination.localCousinServicePrefix = purpose == ProdigyCousinServicePurpose::clientAuthority ?
      prodigyCousinClientAuthorityPrefix(destinationApp) : source.localCousinServicePrefix;
  source.localDeploymentID = destination.peerDeploymentID = uint64_t(source.localApplicationID) << 48 | 1;
  destination.localDeploymentID = source.peerDeploymentID = uint64_t(destination.localApplicationID) << 48 | 2;
  source.peerCanonicalPlanSHA256 = destination.canonicalPlanSHA256; source.peerArtifactSHA256 = destination.artifactSHA256; source.peerArtifactBytes = destination.artifactBytes;
  destination.peerCanonicalPlanSHA256 = source.canonicalPlanSHA256; destination.peerArtifactSHA256 = source.artifactSHA256; destination.peerArtifactBytes = source.artifactBytes;
  source.baselineLogicalCores = destination.baselineLogicalCores = 2;
  source.baselineMemoryMB = destination.baselineMemoryMB = 1024; source.baselineStorageMB = destination.baselineStorageMB = 4096;
  source.destinationShardGroup = destination.destinationShardGroup = group;
  source.destinationShardGroups = destination.destinationShardGroups = groups;
  source.slots = {};
  for (uint16_t slot = 0; slot < CousinRouteSlotBitmap::slotCount; ++slot)
    if (statefulServiceGroupOwnerForSlot(slot, groups) == group) { source.slots.insert(slot); session.slot = slot; break; }
  destination.slots = source.slots;
  session.sourceShardGroup = 0; session.destination.shardGroup = group;
  session.sourceShardGroups = 1; session.destination.shardGroups = groups;
  session.sourceService = MeshServices::constrainPrefixToGroup(source.localCousinServicePrefix, 0);
  session.destination.service = source.authorizedService = destination.authorizedService =
      MeshServices::constrainPrefixToGroup(destination.localCousinServicePrefix, group);
  session.destination.ownedSlots = source.slots;
  if (nat) {
    source.transportSourcePolicy = destination.transportSourcePolicy = ProdigyCousinTransportSourcePolicy::authenticatedNAT;
    session.destination.publicAddress = IPAddress("2001:db8:1234::2", true);
    if (half == CousinRouteHalf::destination) { command.protocolVersion = 2; command.authenticatedSourceAddress = IPAddress("2001:db8:ffff::1", true); }
  }
  auto route = buildRouteForSession(session);
  expect(prodigyCousinSessionRouteBindingForRoute(route, session.route), "v3_session_preserves_route_binding_owner");
  ClusterPairRoot root = {}; root.pairUUID = source.pairUUID; root.firstClusterUUID = source.localClusterUUID;
  root.secondClusterUUID = destination.localClusterUUID; root.rootGeneration = session.rootGeneration;
  for (unsigned i = 0; i < root.root.size(); ++i) root.root[i] = uint8_t(i + 1);
  ClusterPairKeyContext context = {}; ClusterPairDerivedKey key = {};
  expect(prodigyCousinSessionKeyContext(session, context) && clusterPairDeriveKey(root, context, key) && key.size == 32,
      "v3_purpose_scope_derives_full_32_byte_psk");
  std::memcpy(command.psk.data(), key.bytes.data(), 32); prodigyCousinSessionDigest(session, command.canonicalContext);
  return command;
}

