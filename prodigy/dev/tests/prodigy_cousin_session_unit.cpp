#include <prodigy/cousin.session.client.h>
#include <prodigy/ingress.validation.h>
#include <cstdio>
#include <cerrno>
#include <netinet/tcp.h>
#include <unistd.h>

static unsigned failures = 0;
static void expect(bool value, const char *name)
{
  std::printf("%s: %s\n", value ? "PASS" : "FAIL", name);
  if (!value) ++failures;
}

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
                                                       uint64_t rootGeneration, uint64_t keyEpoch)
{
  ProdigyCousinSessionControl control = {};
  control.kind = ProdigyCousinSessionControlKind::propose;
  auto& session = control.session;
  session.sessionUUID = 0x7f01; session.requestUUID = 0x7f02;
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
  session.sourceBindingNonce = 1; session.sourceAddress = IPAddress("fd00:ffff:1234::1", true); session.sourceTCPPort = 40001;
  return control;
}


static ProdigyCousinSessionLocalCommand fixture(CousinRouteHalf half)
{
  auto publication = buildDiscoveryPublication(0x222, 0x300, 0x200, 0x100, 7, 9, 11);
  auto session = buildSessionControl(publication.snapshot.records[0], 7, 9).session;
  session.destination.publicAddress = IPAddress("fd00:ffff:1234::2", true);
  session.destination.publicTCPPort = 49192;
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
  auto source = fixture(CousinRouteHalf::source), destination = fixture(CousinRouteHalf::destination);
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
  client.rBuffer.reserve(8192); server.rBuffer.reserve(8192);
  client.wBuffer.reserve(8192); server.wBuffer.reserve(8192);
  ok = ok && clientOwner.prepareOutbound(source.session.sessionUUID, client);
  if (ok) {
    const int connected = connect(client.fd, client.daddr<sockaddr>(), client.daddrLen);
    ok = connected == 0 || errno == EINPROGRESS;
  }
  sockaddr_storage observed = {}; socklen_t observedLength = sizeof(observed);
  if (ok) { server.fd = accept4(listener, reinterpret_cast<sockaddr *>(&observed), &observedLength, SOCK_CLOEXEC | SOCK_NONBLOCK); ok = server.fd >= 0; }
  if (listener >= 0) close(listener);
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
  const String payload = "offline COUSIN payload"_ctv;
  if (ok) client.wBuffer.append(payload);
  for (unsigned i = 0; ok && i < 10000 && server.rBuffer.size() < payload.size(); ++i)
    ok = pump(client, server) && pump(server, client);
  expect(ok && server.rBuffer.size() == payload.size() && std::memcmp(server.rBuffer.data(), payload.data(), payload.size()) == 0,
         "authenticated_application_payload_over_native_tcp");
  ProdigyCousinSessionStream repeated;
  expect(!clientOwner.prepareOutbound(source.session.sessionUUID, repeated), "session_cannot_open_second_connection");
  auto revoke = source; revoke.kind = ProdigyCousinSessionLocalKind::revoke; revoke.psk.fill(0); revoke.canonicalContext.clear();
  expect(clientOwner.applyCommand(revoke) && !client.isTransportNegotiated() && !client.prepareTransportTLSSend() &&
         !client.decryptTransportTLS(0) && client.nBytesToSend() == 0 && client.pBytesToSend() == nullptr,
         "revocation_closes_send_receive_and_queued_ciphertext");
  if (client.fd >= 0) { close(client.fd); client.fd = -1; }
  if (server.fd >= 0) { close(server.fd); server.fd = -1; }
  return failures ? 1 : 0;
}
