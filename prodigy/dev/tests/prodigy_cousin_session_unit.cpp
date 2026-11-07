#include <prodigy/cousin.session.client.h>
#include <prodigy/ingress.validation.h>
#include "owned_ipv6_fixture.h"
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <netinet/tcp.h>
#include <unistd.h>

static unsigned failures = 0;
static IPAddress localTestAddress = {};
static void expect(bool value, const char *name)
{
  std::printf("%s: %s\n", value ? "PASS" : "FAIL", name);
  if (!value) ++failures;
}

#include "cousin_session_fixture.h"
#include "cousin_session_fixture.h"

static bool pump(ProdigyCousinSessionStream& from, ProdigyCousinSessionStream& to)
{
  if (!from.prepareTransportTLSSend()) return false;
  if (from.nBytesToSend()) {
    const auto sent = send(from.fd, from.pBytesToSend(), std::min(from.nBytesToSend(), 17u), MSG_NOSIGNAL);
    if (sent > 0) from.consumeSentBytes(uint32_t(sent), false);
    else if (sent < 0 && errno != EAGAIN && errno != EINTR) return false;
  }
  if (!to.rBuffer.need(31)) return false;
  const auto count = recv(to.fd, to.rBuffer.pTail(), 31, MSG_DONTWAIT);
  if (count > 0) return to.decryptTransportTLS(uint32_t(count));
  return count < 0 && (errno == EAGAIN || errno == EINTR);
}

int main()
{
  const char *only = std::getenv("PRODIGY_TEST_ONLY");
  if (!prodigyTestOwnedULA(localTestAddress)) {
    std::fprintf(stderr, "SKIP: session socket fixture requires an already assigned non-loopback IPv6 ULA\n");
    return 77;
  }
  {
    // Capacity required by the fixed three-site cohort: ordinary sessions,
    // retained source pulls, and two remote App6 instances at each peer.
    auto first = fixture(CousinRouteHalf::destination, 0x8100, 0x9100);
    ProdigyCousinSessionClient owner(first.session.destination.containerUUID);
    bool admitted = true;
    for (uint32_t index = 0; index < 148; ++index) {
      auto command = fixture(CousinRouteHalf::destination, 0x8100 + index, 0x9100 + index);
      admitted = owner.applyCommand(command) && admitted;
    }
    expect(admitted, "three_site_source_cohort_fits_bounded_session_owner");
  }
  {
    ProdigyCousinAdmissionAck ack = {};
    ack.leaseGeneration = 1; ack.sessionUUID = 17; ack.containerID = 18;
    expect(!prodigyCousinAdmissionAckValid(ack), "legacy_admission_ack_rejects_empty_revision");
    ack.protocolVersion = ProdigyCousinAdmissionAck::privateContainerVersion;
    expect(prodigyCousinAdmissionAckValid(ack), "private_admission_ack_accepts_empty_revision");
    ack.wormholeRevision = String("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    expect(!prodigyCousinAdmissionAckValid(ack), "private_admission_ack_rejects_wormhole_revision");
    ack.protocolVersion = ProdigyCousinAdmissionAck::version;
    expect(prodigyCousinAdmissionAckValid(ack), "legacy_admission_ack_preserves_revision");
  }
  for (auto purpose : {ProdigyCousinServicePurpose::seeding, ProdigyCousinServicePurpose::clientAuthority}) {
    auto session = purposeFixture(CousinRouteHalf::source, purpose).session;
    session.protocolVersion = ProdigyCousinSessionPrivateContainerProtocolVersion;
    session.sourceCarrier.clusterUUID = session.sourcePermission.localClusterUUID;
    session.sourceCarrier.nodeUUID = session.sourceNodeUUID;
    session.sourceCarrier.address = localTestAddress; session.sourceCarrier.port = 315;
    session.destinationCarrier.clusterUUID = session.destination.permission.localClusterUUID;
    session.destinationCarrier.nodeUUID = session.destination.nodeUUID;
    session.destinationCarrier.address = IPAddress("2001:db8:1::9", true); session.destinationCarrier.port = 315;
    session.destination.routablePrefixUUID = 0;
    session.destination.wormholeRevision.clear();
    session.destination.publicTCPPort = session.destination.servicePort;
    CousinRouteRecord route = buildRouteForSession(session);
    route.version = 3; route.endpointKind = CousinRouteEndpointKind::privateContainer;
    route.destinationRoutablePrefixUUID = 0; route.destinationCIDR = 128;
    expect(prodigyCousinSessionRouteBindingForRoute(route, session.route) &&
           prodigyCousinSessionRecordValid(session), "private_seed_session_binds_private_route");
    auto changed = session;
    changed.transport = ProdigyCousinSessionTransport::reverseCarrier;
    expect(!prodigyCousinSessionRecordValid(changed), "private_session_never_uses_control_carrier_for_payload");
    changed = session;
    changed.destination.publicTCPPort++;
    expect(!prodigyCousinSessionRecordValid(changed), "private_seed_session_rejects_changed_destination_port");
    changed = session;
    changed.protocolVersion = ProdigyCousinSessionProtocolVersion;
    expect(!prodigyCousinSessionRecordValid(changed), "legacy_session_rejects_private_route");
  }
  {
    ProdigyCousinCarrierFrame frame = {};
    frame.kind = ProdigyCousinCarrierKind::data; frame.sessionUUID = 0x9001;
    frame.leaseGeneration = 3; frame.sequence = 7; frame.credits = 1;
    frame.payload.assign("bounded reverse carrier"_ctv);
    String encoded = {}; ProdigyCousinCarrierFrame decoded = {};
    expect(prodigyCousinCarrierFrameValid(frame) && BitseryEngine::serialize(encoded, frame) &&
        BitseryEngine::deserializeSafe(encoded, decoded) && prodigyCousinCarrierFrameValid(decoded),
        "reverse_carrier_schema_accepts_bounded_data_frame");
    frame.payload.reserve(ProdigyCousinCarrierMaximumPayloadBytes + 1);
    for (uint32_t i = 0; i <= ProdigyCousinCarrierMaximumPayloadBytes; ++i) frame.payload.append('x');
    expect(!prodigyCousinCarrierFrameValid(frame), "reverse_carrier_schema_rejects_oversize_payload");
    frame.payload.clear(); frame.kind = ProdigyCousinCarrierKind::fin; frame.credits = 1;
    expect(!prodigyCousinCarrierFrameValid(frame), "reverse_carrier_schema_rejects_terminal_credit");
  }
  {
    auto command = purposeFixture(CousinRouteHalf::source, ProdigyCousinServicePurpose::clientAuthority,
                                  false, 3, 1, 4, 0x9002);
    auto& session = command.session;
    session.protocolVersion = ProdigyCousinSessionProtocolVersion;
    session.transport = ProdigyCousinSessionTransport::reverseCarrier;
    session.sourceCarrier.clusterUUID = session.sourcePermission.localClusterUUID;
    session.sourceCarrier.nodeUUID = session.sourceNodeUUID; session.sourceCarrier.address = localTestAddress;
    session.sourceCarrier.port = 315;
    session.destinationCarrier.clusterUUID = session.destination.permission.localClusterUUID;
    session.destinationCarrier.nodeUUID = session.destination.nodeUUID;
    session.destinationCarrier.address = IPAddress("2001:db8:1::9", true); session.destinationCarrier.port = 315;
    session.carrierConnectionID = 0x9004;
    String digest = {}, changed = {}; ClusterPairKeyContext before = {}, after = {};
    expect(prodigyCousinReverseCarrierSessionValid(session) && prodigyCousinSessionDigest(session, digest) &&
        prodigyCousinSessionKeyContext(session, before), "reverse_carrier_requires_app6_hot_lan_to_global_binding");
    ++session.carrierConnectionID;
    expect(prodigyCousinSessionDigest(session, changed) && digest == changed,
        "reverse_carrier_local_connection_counter_does_not_enter_shared_kdf_identity");
    ++session.destinationCarrier.port;
    expect(prodigyCousinSessionDigest(session, changed) && digest != changed &&
        prodigyCousinSessionKeyContext(session, after) && before.channelIdentity != after.channelIdentity,
        "reverse_carrier_pair_endpoint_change_rekeys_session_context");
    std::swap(session.sourceCarrier.address, session.destinationCarrier.address);
    expect(prodigyCousinReverseCarrierSessionValid(session),
        "reverse_carrier_accepts_lan_pair_control_initiator_in_either_logical_data_direction");
    // The preceding swap puts the global address on sourceCarrier.  Remove
    // that endpoint too: reverse carrier requires exactly one global peer.
    session.sourceCarrier.address = localTestAddress;
    session.destinationCarrier.address = localTestAddress;
    expect(!prodigyCousinReverseCarrierSessionValid(session),
        "reverse_carrier_rejects_pair_control_without_one_global_peer_endpoint");
    auto truth = purposeFixture(CousinRouteHalf::source, ProdigyCousinServicePurpose::clientAuthority,
                                false, 10, 0, 1, 0x9003).session;
    truth.protocolVersion = ProdigyCousinSessionProtocolVersion;
    truth.transport = ProdigyCousinSessionTransport::reverseCarrier;
    truth.sourceCarrier.clusterUUID = truth.sourcePermission.localClusterUUID;
    truth.sourceCarrier.nodeUUID = truth.sourceNodeUUID; truth.sourceCarrier.address = localTestAddress; truth.sourceCarrier.port = 315;
    truth.destinationCarrier.clusterUUID = truth.destination.permission.localClusterUUID;
    truth.destinationCarrier.nodeUUID = truth.destination.nodeUUID;
    truth.destinationCarrier.address = IPAddress("2001:db8:1::10", true); truth.destinationCarrier.port = 315;
    truth.carrierConnectionID = 0x9005;
    expect(prodigyCousinReverseCarrierSessionValid(truth),
        "reverse_carrier_allows_singleton_truth_writer_only_at_group_zero");
    truth.destination.shardGroups = 2;
    expect(!prodigyCousinReverseCarrierSessionValid(truth),
        "reverse_carrier_rejects_sharded_truth_writer");
  }
  {
    auto initial = purposeFixture(CousinRouteHalf::source, ProdigyCousinServicePurpose::clientAuthority);
    ProdigyCousinSessionClient owner(initial.session.sourceContainerUUID);
    expect(owner.applyCommand(initial), "one_app6_whitehole_installs_exact_truth_service");
    auto duplicate = purposeFixture(CousinRouteHalf::source, ProdigyCousinServicePurpose::clientAuthority, false, 10, 0, 1, 0x8101, 0x9911);
    expect(prodigyCousinSessionLocalCommandValid(duplicate) && !owner.applyCommand(duplicate),
        "second_permission_uuid_cannot_duplicate_same_remote_database_service_lease");
    for (uint16_t app : {2, 3, 4, 5}) {
      auto other = purposeFixture(CousinRouteHalf::source, ProdigyCousinServicePurpose::clientAuthority, false, app, 0, 1, 0x8201 + app * 2);
      expect(owner.applyCommand(other), "one_app6_whitehole_allows_distinct_exact_database_service_leases");
    }
  }
  for (uint16_t app : {2, 3, 4, 5, 10}) {
    const bool sharded = app == 3 || app == 4;
    for (uint16_t group : {uint16_t(0), uint16_t(sharded ? 2 : 0)}) {
      const uint16_t groups = sharded ? 4 : 1;
      auto source = purposeFixture(CousinRouteHalf::source, ProdigyCousinServicePurpose::clientAuthority, false, app, group, groups);
      auto destination = purposeFixture(CousinRouteHalf::destination, ProdigyCousinServicePurpose::clientAuthority, false, app, group, groups);
      expect(prodigyCousinSessionLocalCommandValid(source) && prodigyCousinSessionLocalCommandValid(destination) && source.psk == destination.psk &&
          source.session.sourceShardGroup == 0 && source.session.sourceShardGroups == 1 &&
          source.session.destination.shardGroup == group && source.session.destination.shardGroups == groups,
          "client_authority_sessions_cover_all_databases_and_exact_nonzero_hot_cold_shards");
      auto route = buildRouteForSession(source.session);
      expect(prodigyCousinAutomaticSessionDesired(source.session.sourcePermission, route, true, 1, 2000),
          "automatic_client_authority_session_uses_permission_owned_nonzero_logical_slot");
      String bytes = {}; ProdigyCousinSessionLocalCommand decoded = {};
      expect(BitseryEngine::serialize(bytes, source) && BitseryEngine::deserializeSafe(bytes, decoded) &&
          prodigyCousinSessionLocalCommandValid(decoded) && decoded.canonicalContext == source.canonicalContext &&
          decoded.session.sourcePermission.destinationShardGroup == group && decoded.session.sourcePermission.destinationShardGroups == groups,
          "client_authority_command_wire_preserves_exact_database_topology_and_context");
      auto wrong = source.session; ++wrong.destination.permission.destinationShardGroups;
      expect(!prodigyCousinSessionRecordValid(wrong), "client_authority_session_rejects_peer_topology_substitution");
      wrong = source.session; wrong.destination.service = MeshServices::constrainPrefixToGroup(wrong.destination.permission.localCousinServicePrefix, group + 1);
      expect(!prodigyCousinSessionRecordValid(wrong), "client_authority_session_rejects_other_remote_shard_service");
      wrong = source.session; wrong.sourceShardGroup = 1; wrong.sourceShardGroups = 2;
      expect(!prodigyCousinSessionRecordValid(wrong), "client_authority_app6_source_remains_group_zero_of_one");
      auto withdrawn = route; withdrawn.state = CousinRouteState::withdrawn; withdrawn.withdrawalGeneration = withdrawn.generation; withdrawn.withdrawnAtMs = 2000;
      expect(!prodigyCousinSessionCurrentForRoute(source.session, withdrawn, 2000), "each_database_client_session_fails_closed_on_route_withdrawal");
    }
  }
  for (auto purpose : {ProdigyCousinServicePurpose::clientAuthority, ProdigyCousinServicePurpose::sibling, ProdigyCousinServicePurpose::seeding}) {
    auto source = purposeFixture(CousinRouteHalf::source, purpose);
    auto destination = purposeFixture(CousinRouteHalf::destination, purpose);
    auto route = buildRouteForSession(source.session);
    expect(prodigyCousinSessionLocalCommandValid(source) && prodigyCousinSessionLocalCommandValid(destination) && source.psk == destination.psk,
        "nonlegacy_purpose_has_exact_authenticated_source_and_destination_commands");
    expect(prodigyCousinAutomaticSessionDesired(source.session.sourcePermission, route, true, 1, 2000) &&
        !prodigyCousinAutomaticSessionDesired(source.session.sourcePermission, route, false, 1, 2000) &&
        !prodigyCousinAutomaticSessionDesired(source.session.sourcePermission, route, true, 0, 2000) &&
        !prodigyCousinAutomaticSessionDesired(source.session.sourcePermission, route, true, 2, 2000),
        "automatic_session_requires_exact_live_plan_service_and_unique_usable_whitehole");
    auto withdrawn = route; withdrawn.state = CousinRouteState::withdrawn; withdrawn.withdrawalGeneration = withdrawn.generation; withdrawn.withdrawnAtMs = 2000;
    expect(!prodigyCousinAutomaticSessionDesired(source.session.sourcePermission, withdrawn, true, 1, 2000) &&
        !prodigyCousinSessionCurrentForRoute(source.session, withdrawn, 2000), "withdrawal_clears_desired_and_current_nonlegacy_session");
    auto revoked = source.session.sourcePermission; revoked.state = ProdigyLocalCousinServicePermissionState::revoked; revoked.generation = 2;
    expect(!prodigyCousinAutomaticSessionDesired(revoked, route, true, 1, 2000), "permission_revoke_clears_automatic_desire");
    auto wrong = source.session; wrong.destination.permission.peerArtifactBytes++;
    expect(!prodigyCousinSessionRecordValid(wrong), "session_rejects_peer_artifact_identity_substitution");
    wrong = source.session; wrong.sourceShardGroups = 2;
    expect(!prodigyCousinSessionRecordValid(wrong), "nonlegacy_session_rejects_multiple_source_groups");
    ProdigyCousinSessionClient owner(source.session.sourceContainerUUID);
    expect(owner.applyCommand(source), "automatic_source_uses_existing_local_lease_owner");
    auto renew = source; renew.kind = ProdigyCousinSessionLocalKind::renew; renew.leaseGeneration = 2; renew.psk[31] ^= 1;
    expect(!owner.applyCommand(renew), "nonlegacy_renew_authenticates_final_psk_byte");
  }
  {
    auto source = purposeFixture(CousinRouteHalf::source, ProdigyCousinServicePurpose::clientAuthority, true);
    auto destination = purposeFixture(CousinRouteHalf::destination, ProdigyCousinServicePurpose::clientAuthority, true);
    String immutableBefore = {}, immutableAfter = {}, encoded = {}; prodigyCousinSessionDigest(source.session, immutableBefore);
    expect(prodigyCousinSessionLocalCommandValid(source) && prodigyCousinSessionLocalCommandValid(destination) &&
        source.psk == destination.psk && source.canonicalContext == destination.canonicalContext,
        "nat_two_tuple_projection_preserves_immutable_session_and_full_psk_context");
    ProdigyCousinSessionLocalCommand decoded = {};
    expect(BitseryEngine::serialize(encoded, destination) && BitseryEngine::deserializeSafe(encoded, decoded) &&
        prodigyCousinSessionLocalCommandValid(decoded) && decoded.authenticatedSourceAddress.equals(destination.authenticatedSourceAddress),
        "nat_v2_destination_projection_roundtrip");
    sockaddr_storage observed = {}; auto& peer = reinterpret_cast<sockaddr_in6&>(observed);
    peer.sin6_family = AF_INET6; peer.sin6_port = htons(source.session.sourceTCPPort);
    std::memcpy(&peer.sin6_addr, destination.authenticatedSourceAddress.v6, 16);
    expect(prodigyCousinSessionObservedSourceMatches(observed, sizeof(peer), source.session, destination.authenticatedSourceAddress) &&
        !prodigyCousinSessionObservedSourceMatches(observed, sizeof(peer), source.session), "nat_requires_exact_authenticated_external_address_not_wildcard");
    ++peer.sin6_port;
    expect(!prodigyCousinSessionObservedSourceMatches(observed, sizeof(peer), source.session, destination.authenticatedSourceAddress),
        "nat_source_port_translation_fails_closed");
    --peer.sin6_port; peer.sin6_addr.s6_addr[15] ^= 1;
    expect(!prodigyCousinSessionObservedSourceMatches(observed, sizeof(peer), source.session, destination.authenticatedSourceAddress),
        "nat_external_address_substitution_fails_closed");
    auto noEvidence = destination; noEvidence.protocolVersion = 1; noEvidence.authenticatedSourceAddress = {};
    expect(!prodigyCousinSessionLocalCommandValid(noEvidence), "nat_destination_cannot_install_without_observed_socket_evidence");
    ProdigyCousinSessionReceipt receipt = {};
    receipt.protocolVersion = 2; receipt.projectionGeneration = 1; receipt.connectionID = 1; receipt.sequence = 1;
    receipt.remoteEndpoint.clusterUUID = source.session.sourcePermission.localClusterUUID;
    receipt.remoteEndpoint.nodeUUID = source.session.sourceNodeUUID; receipt.remoteEndpoint.address = source.session.sourceAddress; receipt.remoteEndpoint.port = 15315;
    receipt.localEndpoint.clusterUUID = destination.session.destination.permission.localClusterUUID;
    receipt.localEndpoint.nodeUUID = destination.session.destination.nodeUUID; receipt.localEndpoint.address = destination.session.destination.publicAddress; receipt.localEndpoint.port = 15315;
    receipt.control.session = source.session; receipt.authenticatedSourceAddress = destination.authenticatedSourceAddress;
    ProdigyCousinSessionReceipt decodedReceipt = {}; encoded.clear();
    expect(prodigyCousinSessionReceiptValid(receipt) && BitseryEngine::serialize(encoded, receipt) &&
        BitseryEngine::deserializeSafe(encoded, decodedReceipt) && prodigyCousinSessionReceiptValid(decodedReceipt),
        "nat_v2_local_receipt_binds_exact_initiator_carrier_and_observed_ipv6");
    auto missing = receipt; missing.protocolVersion = 1; missing.authenticatedSourceAddress = {};
    expect(!prodigyCousinSessionReceiptValid(missing), "nat_propose_requires_local_authenticated_socket_observation");
    auto wrongNode = receipt; ++wrongNode.remoteEndpoint.nodeUUID;
    expect(!prodigyCousinSessionReceiptValid(wrongNode), "nat_receipt_requires_source_container_node_as_authenticated_initiator");
    ProdigyCousinAdmissionCommand admission = {}; admission.protocolVersion = 2; admission.session = source.session;
    admission.validForMs = ProdigyCousinSessionLeaseMs; admission.authenticatedSourceAddress = destination.authenticatedSourceAddress;
    expect(prodigyCousinAdmissionCommandValid(admission), "nat_kernel_command_uses_exact_destination_only_source_projection");
    admission.authenticatedSourceAddress = {};
    expect(!prodigyCousinAdmissionCommandValid(admission), "nat_kernel_command_rejects_missing_source_projection");
    auto ipv4 = source.session; ipv4.sourceAddress = IPAddress("192.0.2.1", false);
    expect(!prodigyCousinSessionRecordValid(ipv4), "nat_policy_never_admits_ipv4");
    auto localDestination = source.session; localDestination.destination.publicAddress = IPAddress("fd00:ffff:1234::2", true);
    expect(!prodigyCousinSessionRecordValid(localDestination), "nat_requires_global_ipv6_destination");
    ProdigyCousinSessionClient owner(destination.session.destination.containerUUID);
    expect(owner.applyCommand(destination), "nat_destination_installs_existing_private_lease");
    auto renew = destination; renew.kind = ProdigyCousinSessionLocalKind::renew; renew.leaseGeneration = 2;
    renew.authenticatedSourceAddress = IPAddress("2001:db8:ffff::9", true);
    expect(!owner.applyCommand(renew), "nat_renew_cannot_change_authenticated_carrier_address");
    prodigyCousinSessionDigest(destination.session, immutableAfter);
    expect(immutableBefore == immutableAfter, "observed_nat_projection_never_restamps_session_kdf");
    for (bool wrongLastByte : {false, true}) {
      auto serverCommand = destination;
      if (wrongLastByte) serverCommand.psk[31] ^= 1;
      ProdigyCousinSessionClient clientOwner(source.session.sourceContainerUUID), serverOwner(destination.session.destination.containerUUID);
      ProdigyCousinSessionStream client, server;
      client.rBuffer.reserve(8192); client.wBuffer.reserve(8192); server.rBuffer.reserve(8192); server.wBuffer.reserve(8192);
      int pair[2] = {-1, -1};
      bool prepared = clientOwner.applyCommand(source) && serverOwner.applyCommand(serverCommand) &&
          socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, pair) == 0 &&
          clientOwner.prepareOutbound(source.session.sessionUUID, client);
      if (prepared) { ::close(client.fd); client.fd = pair[0]; pair[0] = -1; server.fd = pair[1]; pair[1] = -1; }
      peer.sin6_port = htons(source.session.sourceTCPPort); std::memcpy(&peer.sin6_addr, destination.authenticatedSourceAddress.v6, 16);
      prepared = prepared && serverOwner.prepareInbound(server, observed, sizeof(peer));
      bool progressed = prepared;
      for (unsigned i = 0; progressed && i < 10000 && (!client.isTransportNegotiated() || !server.isTransportNegotiated()); ++i)
        progressed = pump(client, server) && pump(server, client);
      const bool negotiated = progressed && client.isTransportNegotiated() && server.isTransportNegotiated();
      expect(prepared && (wrongLastByte ? !negotiated && server.rBuffer.size() == 0 : negotiated), wrongLastByte ?
          "nat_handshake_rejects_wrong_final_psk_byte_before_payload" : "nat_two_tuple_candidates_still_require_complete_fresh_aegis_handshake");
      if (client.fd >= 0) { ::close(client.fd); client.fd = -1; }
      if (server.fd >= 0) { ::close(server.fd); server.fd = -1; }
      for (int fd : pair) if (fd >= 0) ::close(fd);
    }
  }
  auto source = fixture(CousinRouteHalf::source), destination = fixture(CousinRouteHalf::destination);
  const CousinRouteRecord liveRoute = buildRouteForSession(source.session);
  expect(prodigyCousinSessionCurrentForRoute(source.session, liveRoute, 2000),
         "v2_session_binds_exact_live_route_authority");
  expect(prodigyCousinSessionCanOpenForRoute(source.session, liveRoute, 2000),
         "exact_active_route_can_open_new_session");
  {
    auto legacy = source.session;
    legacy.protocolVersion = ProdigyCousinSessionLegacyProtocolVersion;
    legacy.route = {};
    String legacyWire = {}; ProdigyCousinSessionRecord decoded = {};
    expect(prodigyCousinSessionRecordValid(legacy) && BitseryEngine::serialize(legacyWire, legacy) &&
             BitseryEngine::deserializeSafe(legacyWire, decoded) && decoded.protocolVersion == 1 &&
             prodigyCousinSessionRecordValid(decoded) && !prodigyCousinSessionCurrentForRoute(decoded, liveRoute, 2000),
           "v1_session_codec_remains_decodable_but_is_not_current_route_authority");
  }
  {
    auto stale = liveRoute; ++stale.generation;
    expect(!prodigyCousinSessionCurrentForRoute(source.session, stale, 2000),
           "session_rejects_stale_route_generation");
    auto replaced = liveRoute; replaced.operationUUID++; ++replaced.generation;
    expect(!prodigyCousinSessionCurrentForRoute(source.session, replaced, 2000),
           "session_rejects_replaced_route_operation");
    auto draining = liveRoute;
    draining.operationUUID++;
    draining.priorOperationUUIDs.push_back(liveRoute.operationUUID);
    ++draining.generation;
    draining.state = CousinRouteState::draining;
    expect(prodigyCousinSessionCurrentForRoute(source.session, draining, 2000),
           "prior_active_session_survives_immediate_same_scope_draining_update");
    expect(!prodigyCousinSessionCanOpenForRoute(source.session, draining, 2000),
           "draining_successor_denies_new_session_from_prior_authority");
    expect(!prodigyCousinSessionCurrentForRoute(source.session, draining, liveRoute.expiresAtMs),
           "draining_route_does_not_extend_original_session_expiry");
    auto revived = draining; revived.state = CousinRouteState::active;
    expect(!prodigyCousinSessionCurrentForRoute(source.session, revived, 2000),
           "active_revival_cannot_preserve_prior_session");
    auto epochChanged = draining; ++epochChanged.keyEpoch;
    expect(!prodigyCousinSessionCurrentForRoute(source.session, epochChanged, 2000),
           "epoch_change_invalidates_prior_session");
    auto scopeChanged = draining; ++scopeChanged.logicalServiceUUID;
    expect(!prodigyCousinSessionCurrentForRoute(source.session, scopeChanged, 2000),
           "scope_change_invalidates_prior_session");
    auto withdrawn = liveRoute; withdrawn.state = CousinRouteState::withdrawn;
    withdrawn.withdrawalGeneration = withdrawn.generation; withdrawn.withdrawnAtMs = 2000;
    expect(!prodigyCousinSessionCurrentForRoute(source.session, withdrawn, 2000),
           "session_rejects_withdrawn_route");
    auto revoked = withdrawn; revoked.state = CousinRouteState::revoked;
    expect(!prodigyCousinSessionCurrentForRoute(source.session, revoked, 2000),
           "session_rejects_revoked_route");
    auto tampered = source.session; tampered.route.authorizationSHA256[0] = '0';
    expect(!prodigyCousinSessionRecordValid(tampered) || !prodigyCousinSessionCurrentForRoute(tampered, liveRoute, 2000),
           "session_rejects_tampered_route_binding");
  }
  expect(prodigyCousinSessionLocalCommandValid(source) && prodigyCousinSessionLocalCommandValid(destination) &&
         source.psk == destination.psk && source.session.sourceService != source.session.destination.service,
         "asymmetric_service_ids_share_only_canonical_session_key");
  String encoded = {}; ProdigyCousinSessionLocalCommand decoded = {};
  expect(BitseryEngine::serialize(encoded, source) && BitseryEngine::deserializeSafe(encoded, decoded) &&
         prodigyCousinSessionLocalCommandValid(decoded) && decoded.psk == source.psk,
         "private_command_bounded_codec_roundtrip");
  auto altered = source; altered.session.sourceTCPPort++;
  expect(!prodigyCousinSessionLocalCommandValid(altered), "tuple_change_invalidates_context");
  altered = source; altered.session.slot = nStatefulServiceGroupSlots;
  expect(!prodigyCousinSessionRecordValid(altered.session), "unowned_slot_rejected");
  altered = source; altered.session.sourceAddress = IPAddress("::1", true);
  expect(!prodigyCousinSessionRecordValid(altered.session), "loopback_source_rejected");
  {
    String frame = {};
    Message::construct(frame, ContainerTopic::cousinSessionRequest, encoded);
    auto *message = reinterpret_cast<Message *>(frame.data());
    expect(ProdigyIngressValidation::validateContainerPayloadForNeuron(message->topic, message->args, message->terminal()),
           "bounded_app_request_reaches_typed_handler");
    String oversized = {}; oversized.reserve(ProdigyCousinSessionMaximumBytes + 1);
    for (unsigned i = 0; i <= ProdigyCousinSessionMaximumBytes; ++i) oversized.append(uint8_t(0));
    frame.clear(); Message::construct(frame, ContainerTopic::cousinSessionRequest, oversized);
    message = reinterpret_cast<Message *>(frame.data());
    expect(!ProdigyIngressValidation::validateContainerPayloadForNeuron(message->topic, message->args, message->terminal()),
           "oversized_app_session_request_rejected_before_decode");
    frame.clear(); Message::construct(frame, NeuronTopic::cousinSessionAck, uint128_t(7), encoded);
    message = reinterpret_cast<Message *>(frame.data());
    expect(ProdigyIngressValidation::validateNeuronPayloadForBrain(message->topic, message->args, message->terminal()) &&
           !ProdigyIngressValidation::validateNeuronPayloadForBrain(message->topic, message->args, message->terminal() - 1),
           "forwarded_ack_requires_container_identity_and_complete_payload");
  }
  {
    ProdigyCousinSessionClient owner(source.session.sourceContainerUUID);
    auto shortLease = source; shortLease.validForMs = 1;
    expect(owner.applyCommand(shortLease), "short_lease_install");
    usleep(3000);
    shortLease.kind = ProdigyCousinSessionLocalKind::renew; shortLease.leaseGeneration = 2;
    expect(!owner.applyCommand(shortLease), "expired_lease_cannot_be_resurrected_by_renewal");
  }
  {
    ProdigyCousinSessionClient wrong(source.session.sourceContainerUUID + 1);
    expect(!wrong.applyCommand(source), "wrong_application_identity_rejected");
  }
  ProdigyCousinSessionClient clientOwner(source.session.sourceContainerUUID), serverOwner(destination.session.destination.containerUUID);
  expect(clientOwner.applyCommand(source) && serverOwner.applyCommand(destination), "both_private_owners_apply_session");
  auto duplicate = source; duplicate.session.sessionUUID++; duplicate.session.requestUUID++; duplicate.requestUUID++;
  prodigyCousinSessionDigest(duplicate.session, duplicate.canonicalContext);
  expect(!clientOwner.applyCommand(duplicate), "one_active_session_per_whitehole_binding");
  auto renewed = source; renewed.kind = ProdigyCousinSessionLocalKind::renew; renewed.leaseGeneration = 2;
  expect(clientOwner.applyCommand(renewed), "exact_lease_renewal");
  expect(!clientOwner.applyCommand(renewed), "stale_renewal_generation_rejected");
  renewed.leaseGeneration = 3; renewed.psk[0] ^= 1;
  expect(!clientOwner.applyCommand(renewed), "renewal_cannot_change_psk");

  const int listener = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
  sockaddr_in6 address = {}; address.sin6_family = AF_INET6;
  address.sin6_port = htons(destination.session.destination.publicTCPPort);
  std::memcpy(&address.sin6_addr, destination.session.destination.publicAddress.v6, 16);
  const int one = 1;
  bool ok = listener >= 0 && setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0 &&
      bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0 && listen(listener, 2) == 0;
  ProdigyCousinSessionStream client, server;
  expect(!client.observeNegotiatedGuard().valid(), "unnegotiated_stream_has_no_guard_observation");
  client.rBuffer.reserve(8192); server.rBuffer.reserve(8192);
  client.wBuffer.reserve(8192); server.wBuffer.reserve(8192);
  ok = ok && clientOwner.prepareOutbound(source.session.sessionUUID, client);
  if (ok) {
    const int connected = connect(client.fd, client.daddr<sockaddr>(), client.daddrLen);
    ok = connected == 0 || errno == EINPROGRESS;
  }
  sockaddr_storage observed = {}; socklen_t observedLength = sizeof(observed);
  if (ok) { server.fd = accept4(listener, reinterpret_cast<sockaddr *>(&observed), &observedLength, SOCK_CLOEXEC | SOCK_NONBLOCK); ok = server.fd >= 0; }
  if (ok) ok = setsockopt(client.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0 &&
      setsockopt(server.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0;
  expect(ok && reinterpret_cast<sockaddr_in6&>(observed).sin6_port == htons(source.session.sourceTCPPort) &&
         std::memcmp(&reinterpret_cast<sockaddr_in6&>(observed).sin6_addr, source.session.sourceAddress.v6, 16) == 0,
         "native_connect_binds_allocated_whitehole_tuple");
  ok = ok && serverOwner.prepareInbound(server, observed, observedLength);
  for (unsigned i = 0; ok && i < 10000 && (!client.isTransportNegotiated() || !server.isTransportNegotiated()); ++i)
    ok = pump(client, server) && pump(server, client);
  expect(ok && client.isTransportNegotiated() && server.isTransportNegotiated() &&
         client.tlsPeerUUID == source.session.destination.containerUUID && server.tlsPeerUUID == source.session.sourceContainerUUID,
         "native_session_fresh_authenticated_x25519_aegis_handshake");
  const auto guardObservation = client.observeNegotiatedGuard();
  expect(guardObservation.valid() && guardObservation.current(), "negotiated_guard_observation_is_current");
  auto witnessedRenewal = source; witnessedRenewal.kind = ProdigyCousinSessionLocalKind::renew;
  witnessedRenewal.leaseGeneration = 3;
  expect(clientOwner.applyCommand(witnessedRenewal) && guardObservation.current(),
         "negotiated_guard_survives_exact_monotonic_renewal");
  const String payload = "offline COUSIN payload"_ctv;
  if (ok) client.wBuffer.append(payload);
  for (unsigned i = 0; ok && i < 10000 && server.rBuffer.size() < payload.size(); ++i)
    ok = pump(client, server) && pump(server, client);
  expect(ok && server.rBuffer.size() == payload.size() && std::memcmp(server.rBuffer.data(), payload.data(), payload.size()) == 0,
         "authenticated_application_payload_over_native_tcp");
  ProdigyCousinSessionStream repeated;
  expect(!clientOwner.prepareOutbound(source.session.sessionUUID, repeated), "session_cannot_open_second_connection");
  auto revoke = source; revoke.kind = ProdigyCousinSessionLocalKind::revoke; revoke.psk.fill(0); revoke.canonicalContext.clear();
  expect(!clientOwner.applyCommand(revoke) && client.isTransportNegotiated(), "stale_revoke_cannot_close_renewed_generation");
  expect(guardObservation.current(), "stale_revoke_preserves_observed_guard");
  revoke.leaseGeneration = 3;
  expect(clientOwner.applyCommand(revoke) && !client.isTransportNegotiated() && !client.prepareTransportTLSSend() &&
         !client.decryptTransportTLS(0) && client.nBytesToSend() == 0 && client.pBytesToSend() == nullptr,
         "revocation_closes_send_receive_and_queued_ciphertext");
  expect(guardObservation.valid() && !guardObservation.current(), "exact_observed_guard_withdrawn_after_revoke");
  expect(!clientOwner.applyCommand(source), "retired_session_rejects_replayed_generation_one_activate");
  {
    ProdigyCousinSessionClient reorderedOwner(source.session.sourceContainerUUID);
    auto terminal = source; terminal.kind = ProdigyCousinSessionLocalKind::revoke; terminal.psk.fill(0); terminal.canonicalContext.clear();
    expect(reorderedOwner.applyCommand(terminal) && !reorderedOwner.applyCommand(source),
        "revoke_before_activate_tombstone_rejects_delayed_initial_command");
  }
  ProdigyCousinSessionStream unowned, fixed;
  fixed.isFixedFile = true; fixed.fd = 42;
  expect(!unowned.abortOwnedSocket() && !fixed.abortOwnedSocket() && fixed.fd == 42,
         "abortive_close_rejects_unowned_and_ring_fixed_descriptors");
  fixed.fd = -1;
  bool inboundClosed = false;
  serverOwner.onSessionClosed = [&](uint128_t sessionUUID) {
    if (server.sessionUUID() == sessionUUID)
      inboundClosed = server.abortOwnedSocket();
  };
  auto revokeDestination = destination;
  revokeDestination.kind = ProdigyCousinSessionLocalKind::revoke;
  revokeDestination.psk.fill(0); revokeDestination.canonicalContext.clear();
  expect(serverOwner.applyCommand(revokeDestination) &&
         server.sessionUUID() == destination.session.sessionUUID && inboundClosed && server.fd == -1,
         "destination_revocation_identifies_and_aborts_the_exact_accepted_stream");
  bool peerReset = false;
  for (unsigned attempt = 0; client.fd >= 0 && attempt < 500; ++attempt) {
    char byte = 0;
    const ssize_t received = recv(client.fd, &byte, sizeof(byte), MSG_DONTWAIT);
    if (received < 0 && errno == ECONNRESET) { peerReset = true; break; }
    if (received == 0 || (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) break;
    usleep(100);
  }
  expect(peerReset, "retired_inbound_socket_resets_peer_instead_of_leaving_a_fin_wait_tuple");
  expect(client.abortOwnedSocket() && client.fd == -1,
         "revoked_fixed_whitehole_outbound_uses_abortive_owner_close");
  if (server.fd >= 0) (void)server.abortOwnedSocket();
  auto reconnectSource = fixture(CousinRouteHalf::source, 0x7f11, 0x7f12);
  auto reconnectDestination = fixture(CousinRouteHalf::destination, 0x7f11, 0x7f12);
  ProdigyCousinSessionClient reconnectClientOwner(reconnectSource.session.sourceContainerUUID);
  ProdigyCousinSessionClient reconnectServerOwner(reconnectDestination.session.destination.containerUUID);
  ProdigyCousinSessionStream reconnectClient, reconnectServer;
  reconnectClient.rBuffer.reserve(8192); reconnectServer.rBuffer.reserve(8192);
  reconnectClient.wBuffer.reserve(8192); reconnectServer.wBuffer.reserve(8192);
  bool reconnected = reconnectClientOwner.applyCommand(reconnectSource) &&
      reconnectServerOwner.applyCommand(reconnectDestination) &&
      reconnectClientOwner.prepareOutbound(reconnectSource.session.sessionUUID, reconnectClient);
  if (reconnected) {
    const int connected = connect(reconnectClient.fd, reconnectClient.daddr<sockaddr>(), reconnectClient.daddrLen);
    reconnected = connected == 0 || errno == EINPROGRESS;
  }
  sockaddr_storage reconnectObserved = {}; socklen_t reconnectObservedLength = sizeof(reconnectObserved);
  if (reconnected) {
    reconnectServer.fd = accept4(listener, reinterpret_cast<sockaddr *>(&reconnectObserved), &reconnectObservedLength,
                                 SOCK_CLOEXEC | SOCK_NONBLOCK);
    reconnected = reconnectServer.fd >= 0 &&
        reconnectServerOwner.prepareInbound(reconnectServer, reconnectObserved, reconnectObservedLength);
  }
  expect(reconnected, "abortive_close_releases_fixed_tuple_before_kernel_tcp_timeout");
  if (reconnected) reconnected = setsockopt(reconnectClient.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0 &&
      setsockopt(reconnectServer.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0;
  for (unsigned i = 0; reconnected && i < 10000 &&
       (!reconnectClient.isTransportNegotiated() || !reconnectServer.isTransportNegotiated()); ++i)
    reconnected = pump(reconnectClient, reconnectServer) && pump(reconnectServer, reconnectClient);
  expect(reconnected && reconnectSource.session.sessionUUID != source.session.sessionUUID &&
         reconnectObserved.ss_family == AF_INET6 &&
         reinterpret_cast<sockaddr_in6&>(reconnectObserved).sin6_port == htons(reconnectSource.session.sourceTCPPort) &&
         std::memcmp(&reinterpret_cast<sockaddr_in6&>(reconnectObserved).sin6_addr,
                     reconnectSource.session.sourceAddress.v6, 16) == 0 &&
         reconnectClient.isTransportNegotiated() && reconnectServer.isTransportNegotiated() &&
         reconnectClient.tlsPeerUUID == reconnectDestination.session.destination.containerUUID &&
         reconnectServer.tlsPeerUUID == reconnectSource.session.sourceContainerUUID,
         "abortive_close_allows_immediate_fresh_same_whitehole_tuple_reconnect");
  if (reconnectClient.fd >= 0) { close(reconnectClient.fd); reconnectClient.fd = -1; }
  if (reconnectServer.fd >= 0) { close(reconnectServer.fd); reconnectServer.fd = -1; }
  if (listener >= 0) close(listener);
  return failures ? 1 : 0;
}
