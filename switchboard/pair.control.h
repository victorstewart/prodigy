#pragma once

#include <algorithm>
#include <functional>
#include <array>
#include <memory>
#include <vector>
#include <services/time.h>
#include <prodigy/transport.tls.h>
#include <networking/multiplexer.h>
#include <networking/ring.h>
#include <prodigy/cluster.pair.projection.h>
#include <prodigy/cousin.discovery.h>
#include <prodigy/cousin.session.h>

// Neuron owns this Switchboard control component. Its input is an already
// durable, node-scoped credential projection; it never possesses a pair root
// or carries application traffic. The first control record is a fixed hello.
static inline bool switchboardPairControlSafeObservedIPv6Peer(const sockaddr_storage& peer, socklen_t length)
{
  if (peer.ss_family != AF_INET6 || length != sizeof(sockaddr_in6)) return false;
  const uint8_t *address = reinterpret_cast<const sockaddr_in6&>(peer).sin6_addr.s6_addr;
  const bool unspecified = std::all_of(address, address + 16, [](uint8_t byte) { return byte == 0; });
  const bool loopback = std::all_of(address, address + 15, [](uint8_t byte) { return byte == 0; }) && address[15] == 1;
  const bool mappedV4 = std::all_of(address, address + 10, [](uint8_t byte) { return byte == 0; }) &&
                        address[10] == 0xff && address[11] == 0xff;
  const bool linkLocal = address[0] == 0xfe && (address[1] & 0xc0u) == 0x80u;
  return !unspecified && !loopback && !mappedV4 && !linkLocal && address[0] != 0xff;
}

static inline IPAddress switchboardPairControlOutboundSourceAddress(
    const ProdigyLocalClusterPairControlCredential& credential)
{
  // NAT may translate the address observed by the responder, but the local
  // socket still has to use the admitted initiator address.  In particular,
  // do not let Linux choose an unrelated address on a multi-address VM.
  return credential.initiator.address;
}

// Called only after the accepted connection's full credential handshake and
// record authentication. This projects socket evidence, never peer payload.
static inline bool switchboardPairControlProjectObservedSessionSource(
    ProdigyCousinSessionReceipt& receipt, const ProdigyLocalClusterPairControlCredential& credential,
    const sockaddr_storage& observed, socklen_t observedLength)
{
  const auto& session = receipt.control.session;
  if (session.sourcePermission.transportSourcePolicy != ProdigyCousinTransportSourcePolicy::authenticatedNAT ||
      session.sourcePermission.localClusterUUID != receipt.remoteEndpoint.clusterUUID) return true;
  if (receipt.localEndpoint != credential.responder || receipt.remoteEndpoint != credential.initiator ||
      !clusterPairControlEndpointNATCompatibleOutbound(credential.initiator, credential.responder) ||
      credential.pairUUID != session.sourcePermission.pairUUID || credential.rootGeneration != session.rootGeneration ||
      credential.keyEpoch != session.keyEpoch || receipt.remoteEndpoint.nodeUUID != session.sourceNodeUUID ||
      !switchboardPairControlSafeObservedIPv6Peer(observed, observedLength)) return false;
  IPAddress address = {}; address.is6 = true;
  std::memcpy(address.v6, &reinterpret_cast<const sockaddr_in6&>(observed).sin6_addr, 16);
  if (!prodigyCousinGlobalIPv6AddressValid(address)) return false;
  receipt.protocolVersion = 2; receipt.authenticatedSourceAddress = address;
  return true;
}

// A prepared pair may receive the new wire format; only an active pair may send it.
// The projection itself is validated when installed, including its credentials.
static inline bool switchboardPairControlPrivateDiscoveryAllowed(
    const ProdigyLocalClusterPairControlProjection& projection, uint128_t pairUUID,
    uint64_t rootGeneration, uint128_t peerClusterUUID, bool outgoing)
{
  if (projection.protocolVersion != ProdigyLocalClusterPairControlProjection::privateDiscoveryVersion ||
      pairUUID == 0 || rootGeneration == 0 || peerClusterUUID == 0) return false;
  for (const auto& status : projection.privateDiscoveryStatuses)
    if (status.pairUUID == pairUUID && status.rootGeneration == rootGeneration &&
        status.peerClusterUUID == peerClusterUUID && status.activationUUID != 0 &&
        (status.phase == ProdigyPairPrivateDiscoveryPhase::active ||
         (!outgoing && status.phase == ProdigyPairPrivateDiscoveryPhase::prepared))) return true;
  return false;
}

template <typename Socket>
static inline bool switchboardPairControlBindOutboundSource(
    Socket& socket, const ProdigyLocalClusterPairControlCredential& credential)
{
  socket.setSaddr(switchboardPairControlOutboundSourceAddress(credential), 0);
  return socket.fd >= 0 && Ring::bindSourceAddressBeforeFixedFileInstall(&socket);
}

class SwitchboardPairControlRuntime final : public RingInterface {
  static constexpr uint32_t helloBytes = 68;
  static constexpr uint32_t epochRecordBytes = 4 + 8 + ProdigyClusterPairEpochStatusBytes;
  static constexpr uint32_t discoveryRecordHeaderBytes = 4 + 8 + 4;
  static constexpr uint32_t helloRecordType = 1, epochRecordType = 2, discoveryRecordType = 3, sessionRecordType = 4,
      carrierRecordType = 5;
  static constexpr uint32_t sessionRecordHeaderBytes = 4 + 8 + 4;
  static constexpr uint32_t carrierRecordHeaderBytes = 4 + 4;
  static constexpr size_t maximumPendingSessionRecords = ProdigyCousinSessionMaximumRecords;
  static constexpr size_t maximumSockets = ProdigyLocalClusterPairControlProjectionMaximumCredentials + 16;
  static constexpr int64_t handshakeTimeoutMs = 10000, idleTimeoutMs = 15000, helloIntervalMs = 3000;
  struct Listener : TCPSocket {
    ClusterPairControlEndpoint endpoint;
    bool closing = false, accepting = false;
  };
  struct Connection : ProdigyTransportTLSStream {
    struct CarrierFlow {
      uint128_t sessionUUID = 0;
      uint64_t leaseGeneration = 0;
      uint64_t receivedSequence = 0, sentSequence = 0;
      uint32_t receivedCredits = 0, sentCredits = 0;
      bool receivedClosed = false, sentClosed = false;
      bool openedSent = false, openedReceived = false, ackedSent = false, ackedReceived = false;
    };
    struct CarrierTombstone {
      uint128_t sessionUUID = 0;
      uint64_t leaseGeneration = 0;
    };
    ProdigyLocalClusterPairControlCredential credential;
    ClusterPairControlEndpoint local, remote;
    sockaddr_storage observedPeer = {};
    socklen_t observedPeerLength = 0;
    bool closing = false, connected = false, selected = false, ready = false;
    uint64_t connectionID = 0;
    uint64_t sentSequence = 0, receivedSequence = 0, sentStatusSequence = 0, receivedStatusSequence = 0;
    uint64_t sentDiscoverySequence = 0, receivedDiscoverySequence = 0;
    uint64_t sentSessionSequence = 0, receivedSessionSequence = 0;
    std::vector<String> pendingSessionRecords = {};
    uint32_t pendingSessionBytes = 0;
    std::vector<String> pendingCarrierRecords = {};
    uint32_t pendingCarrierBytes = 0;
    std::vector<CarrierFlow> carrierFlows = {};
    std::vector<CarrierTombstone> carrierTombstones = {};
    bool remoteDiscoveryPresent = false;
    ProdigyCousinDiscoverySnapshot remoteDiscovery = {};
    int64_t remoteDiscoveryExpiresAt = 0;
    int64_t createdAt = 0, lastReceiveAt = 0, lastHelloAt = 0, lastStatusAt = 0, lastDiscoveryAt = 0;
  };
  static bool carrierFlowGenerationRetired(Connection& connection, uint128_t sessionUUID, uint64_t leaseGeneration)
  {
    auto found = std::find_if(connection.carrierTombstones.begin(), connection.carrierTombstones.end(),
        [&](const auto& value) { return value.sessionUUID == sessionUUID; });
    if (found == connection.carrierTombstones.end()) return false;
    // This is deliberately read-only: an unadmitted newer open may not erase
    // the replay fence for an older generation.
    return leaseGeneration <= found->leaseGeneration;
  }
  static bool retireCarrierFlowGeneration(Connection& connection, uint128_t sessionUUID, uint64_t leaseGeneration)
  {
    auto found = std::find_if(connection.carrierTombstones.begin(), connection.carrierTombstones.end(),
        [&](const auto& value) { return value.sessionUUID == sessionUUID; });
    if (found != connection.carrierTombstones.end()) {
      found->leaseGeneration = std::max(found->leaseGeneration, leaseGeneration); return true;
    }
    // Never evict a replay fence. Reconnecting the authenticated carrier is
    // the only bounded recovery once its tombstone ledger is exhausted.
    if (connection.carrierTombstones.size() >= ProdigyCousinSessionMaximumRecords) return false;
    connection.carrierTombstones.push_back({sessionUUID, leaseGeneration});
    return true;
  }
  static bool carrierFlowCanRetire(const Connection& connection, uint128_t sessionUUID)
  {
    return std::any_of(connection.carrierTombstones.begin(), connection.carrierTombstones.end(),
        [&](const auto& value) { return value.sessionUUID == sessionUUID; }) ||
        connection.carrierTombstones.size() < ProdigyCousinSessionMaximumRecords;
  }
  struct LocalDiscoveryPublication {
    ProdigyCousinDiscoveryPublication publication = {};
    bool withdrawing = false;
    int64_t expiresAt = 0;
  };
  ProdigyLocalClusterPairControlProjection projection;
  std::vector<LocalDiscoveryPublication> discoveryPublications;
  uint64_t nextConnectionID = 1;
  std::vector<std::unique_ptr<Listener>> listeners;
  std::vector<std::unique_ptr<Connection>> connections;
  TimeoutPacket tick;
  bool started = false, stopping = false, tickPending = false, tickCancelPending = false;
  size_t acceptsPending = 0;

  static bool sameCredential(const ProdigyLocalClusterPairControlCredential& a,
                             const ProdigyLocalClusterPairControlCredential& b)
  {
    return a.pairUUID == b.pairUUID && a.rootGeneration == b.rootGeneration && a.keyEpoch == b.keyEpoch &&
        a.initiator == b.initiator && a.responder == b.responder && a.localClaim == b.localClaim &&
        a.remoteClaim == b.remoteClaim && a.canonicalContext == b.canonicalContext &&
        CRYPTO_memcmp(a.psk, b.psk, sizeof(a.psk)) == 0;
  }
  bool isLocal(const ClusterPairControlEndpoint& endpoint) const
  { return endpoint.clusterUUID == projection.localClusterUUID && endpoint.nodeUUID == projection.nodeUUID; }
  bool approved(const Connection& connection) const
  {
    return connection.selected && std::any_of(projection.credentials.begin(), projection.credentials.end(),
        [&](const auto& credential) { return sameCredential(credential, connection.credential); });
  }
  bool ownsListenerEndpoint(const ClusterPairControlEndpoint& endpoint) const
  {
    return std::any_of(projection.credentials.begin(), projection.credentials.end(),
        [&](const auto& credential) { return isLocal(credential.responder) && credential.responder == endpoint; });
  }
  Listener *listenerFor(void *socket)
  { for (auto& listener : listeners) if (listener.get() == socket) return listener.get(); return nullptr; }
  Connection *connectionFor(void *socket)
  { for (auto& connection : connections) if (connection.get() == socket) return connection.get(); return nullptr; }
  bool discoveryMatchesConnection(const ProdigyCousinDiscoverySnapshot& snapshot,
                                  const Connection& connection, bool outgoing) const
  {
    return snapshot.pairUUID == connection.credential.pairUUID &&
        snapshot.rootGeneration == connection.credential.rootGeneration &&
        snapshot.keyEpoch == connection.credential.keyEpoch &&
        snapshot.sourceClusterUUID == (outgoing ? connection.local.clusterUUID : connection.remote.clusterUUID) &&
        snapshot.peerClusterUUID == (outgoing ? connection.remote.clusterUUID : connection.local.clusterUUID);
  }
  const LocalDiscoveryPublication *localDiscoveryFor(const Connection& connection) const
  {
    for (const auto& candidate : discoveryPublications)
      if (candidate.expiresAt > Time::msSinceBoot() &&
          candidate.publication.nodeUUID == projection.nodeUUID &&
          candidate.publication.projectionGeneration == projection.committedAuthorityGeneration &&
          discoveryMatchesConnection(candidate.publication.snapshot, connection, true)) return &candidate;
    return nullptr;
  }
  void emitDiscoveryWithdrawal(Connection& connection)
  {
    if (!connection.remoteDiscoveryPresent) return;
    connection.remoteDiscoveryPresent = false;
    connection.remoteDiscoveryExpiresAt = 0;
    if (!onDiscoverySnapshot) return;
    ProdigyCousinDiscoveryReceipt receipt = {};
    receipt.localEndpoint = connection.local;
    receipt.remoteEndpoint = connection.remote;
    receipt.wireEpoch = connection.credential.keyEpoch;
    receipt.projectionGeneration = projection.committedAuthorityGeneration;
    receipt.connectionID = connection.connectionID;
    receipt.sequence = connection.receivedDiscoverySequence;
    receipt.withdrawn = true;
    receipt.snapshot = connection.remoteDiscovery;
    receipt.snapshot.records.clear();
    onDiscoverySnapshot(receipt);
  }
  void emitSessionDisconnect(Connection& connection)
  {
    if (!onSessionControl) return;
    ProdigyCousinSessionReceipt receipt = {};
    receipt.localEndpoint = connection.local; receipt.remoteEndpoint = connection.remote;
    receipt.projectionGeneration = projection.committedAuthorityGeneration;
    receipt.connectionID = connection.connectionID; receipt.disconnected = true;
    onSessionControl(receipt);
  }
  void flushSessionControl(Connection& connection)
  {
    if (!approved(connection) || connection.closing || !connection.ready || connection.pendingSend ||
        connection.wBuffer.outstandingBytes() != 0 || connection.pendingSessionRecords.empty()) return;
    String record = std::move(connection.pendingSessionRecords.front());
    connection.pendingSessionRecords.erase(connection.pendingSessionRecords.begin());
    connection.pendingSessionBytes -= uint32_t(record.size());
    if (!connection.wBuffer.need(record.size())) { retire(connection); return; }
    connection.wBuffer.append(record); Ring::queueSend(&connection);
  }
  void flushCarrierFrame(Connection& connection)
  {
    // Session control (including revoke/reset control) always drains first.
    if (!approved(connection) || connection.closing || !connection.ready || connection.pendingSend ||
        connection.wBuffer.outstandingBytes() != 0 || !connection.pendingSessionRecords.empty() ||
        connection.pendingCarrierRecords.empty()) return;
    String record = std::move(connection.pendingCarrierRecords.front());
    connection.pendingCarrierRecords.erase(connection.pendingCarrierRecords.begin());
    connection.pendingCarrierBytes -= uint32_t(record.size());
    if (!connection.wBuffer.need(record.size())) { retire(connection); return; }
    connection.wBuffer.append(record); Ring::queueSend(&connection);
  }
  bool receiveCarrierFrame(Connection& connection, const uint8_t *payload, uint32_t payloadBytes)
  {
    if (!approved(connection) || !connection.ready || !connection.isTransportNegotiated() ||
        !connection.tlsPeerVerified || connection.tlsPeerUUID != connection.remote.nodeUUID || payloadBytes == 0 ||
        payloadBytes > ProdigyCousinCarrierMaximumPayloadBytes + 128) return false;
    String encoded = {}; ProdigyCousinCarrierFrame frame = {};
    if (!encoded.reserve(payloadBytes)) return false;
    encoded.append(payload, payloadBytes);
    if (!BitseryEngine::deserializeSafe(encoded, frame) || !prodigyCousinCarrierFrameValid(frame)) return false;
    auto flow = std::find_if(connection.carrierFlows.begin(), connection.carrierFlows.end(), [&](const auto& value) {
      return value.sessionUUID == frame.sessionUUID;
    });
    Connection::CarrierFlow before = {};
    const bool createdFlow = flow == connection.carrierFlows.end();
    if (flow == connection.carrierFlows.end()) {
      // Only an initial open may allocate state. Its advertised window grants
      // this receiver permission to send; it never authorizes its sender.
      if (frame.kind != ProdigyCousinCarrierKind::open || frame.sequence != 1 ||
          carrierFlowGenerationRetired(connection, frame.sessionUUID, frame.leaseGeneration) ||
          connection.carrierFlows.size() >= ProdigyCousinSessionMaximumRecords) return false;
      Connection::CarrierFlow created = {};
      created.sessionUUID = frame.sessionUUID; created.leaseGeneration = frame.leaseGeneration;
      created.receivedSequence = frame.sequence; created.sentCredits = frame.credits;
      created.openedReceived = true;
      connection.carrierFlows.push_back(created);
    } else {
      before = *flow;
      if (flow->leaseGeneration != frame.leaseGeneration || flow->receivedClosed) return false;
      const bool dataReady = (flow->openedSent && flow->ackedReceived) ||
          (flow->openedReceived && flow->ackedSent);
      if (frame.kind == ProdigyCousinCarrierKind::openAck) {
        // The peer may acknowledge exactly once, on its independent first
        // sequence number, after this side sent an open.
        if (!flow->openedSent || flow->ackedReceived || frame.sequence != 1 || flow->receivedSequence != 0) return false;
        flow->ackedReceived = true;
        flow->sentCredits = frame.credits;
        flow->receivedSequence = frame.sequence;
      } else {
        if (frame.sequence != flow->receivedSequence + 1) return false;
        switch (frame.kind) {
        case ProdigyCousinCarrierKind::data:
          if (!dataReady || flow->receivedCredits == 0 || frame.credits != flow->receivedCredits - 1) return false;
          --flow->receivedCredits; break;
        case ProdigyCousinCarrierKind::window:
          // A remote window grants this local sender more allowance.
          if (!dataReady || frame.credits <= flow->sentCredits) return false;
          flow->sentCredits = frame.credits; break;
        case ProdigyCousinCarrierKind::fin:
          if (!dataReady) return false;
          [[fallthrough]];
        case ProdigyCousinCarrierKind::reset:
          flow->receivedClosed = true; break;
        case ProdigyCousinCarrierKind::open:
          return false;
        case ProdigyCousinCarrierKind::openAck: return false;
        }
        flow->receivedSequence = frame.sequence;
      }
    }
    connection.lastReceiveAt = Time::msSinceBoot();
    if (!onCarrierFrame || !onCarrierFrame(connection.local, connection.remote, connection.connectionID, frame)) {
      if (createdFlow) connection.carrierFlows.pop_back(); else *flow = before;
      return false;
    }
    // A reset permits a fresh authenticated open for the next lease generation.
    // A graceful flow is reusable only once both halves have closed.
    flow = std::find_if(connection.carrierFlows.begin(), connection.carrierFlows.end(), [&](const auto& value) {
      return value.sessionUUID == frame.sessionUUID;
    });
    if (flow != connection.carrierFlows.end() &&
        (frame.kind == ProdigyCousinCarrierKind::reset || (flow->receivedClosed && flow->sentClosed))) {
      if (!retireCarrierFlowGeneration(connection, flow->sessionUUID, flow->leaseGeneration)) {
        retire(connection); return false;
      }
      connection.carrierFlows.erase(flow);
    }
    return true;
  }
  bool receiveSessionControl(Connection& connection, const uint8_t *payload, uint32_t payloadBytes)
  {
    const uint8_t *cursor = payload, *end = payload + payloadBytes;
    uint64_t sequence = 0; uint32_t encodedBytes = 0;
    if (!approved(connection) || !connection.ready || !connection.isTransportNegotiated() ||
        !connection.tlsPeerVerified || connection.tlsPeerUUID != connection.remote.nodeUUID ||
        !clusterPairControlReadU64BE(cursor, end, sequence) || sequence == 0 || sequence <= connection.receivedSessionSequence ||
        !clusterPairControlReadU32BE(cursor, end, encodedBytes) || encodedBytes == 0 ||
        encodedBytes > ProdigyCousinSessionMaximumBytes || encodedBytes != uint32_t(end - cursor)) return false;
    String encoded = {}; ProdigyCousinSessionControl control = {};
    if (!encoded.reserve(encodedBytes)) return false;
    encoded.append(cursor, encodedBytes);
    if (!BitseryEngine::deserializeSafe(encoded, control) || !prodigyCousinSessionControlValid(control) ||
        !prodigyCousinSessionControlFromCluster(control, connection.remote.clusterUUID) ||
        control.session.sourcePermission.pairUUID != connection.credential.pairUUID ||
        control.session.rootGeneration != connection.credential.rootGeneration ||
        control.session.keyEpoch != connection.credential.keyEpoch) return false;
    connection.receivedSessionSequence = sequence; connection.lastReceiveAt = Time::msSinceBoot();
    if (onSessionControl) {
      ProdigyCousinSessionReceipt receipt = {};
      receipt.localEndpoint = connection.local; receipt.remoteEndpoint = connection.remote;
      receipt.projectionGeneration = projection.committedAuthorityGeneration;
      receipt.connectionID = connection.connectionID; receipt.sequence = sequence; receipt.control = std::move(control);
      if (!switchboardPairControlProjectObservedSessionSource(receipt, connection.credential,
            connection.observedPeer, connection.observedPeerLength) || !prodigyCousinSessionReceiptValid(receipt)) return false;
      onSessionControl(receipt);
    }
    return true;
  }
  void queueDiscoverySnapshot(Connection& connection, int64_t now)
  {
    if (!approved(connection) || connection.closing || !connection.connected || !connection.ready ||
        !connection.isTransportNegotiated() || !connection.tlsPeerVerified ||
        connection.tlsPeerUUID != connection.remote.nodeUUID || connection.pendingSend ||
        connection.wBuffer.outstandingBytes() != 0 ||
        (connection.lastDiscoveryAt != 0 && now - connection.lastDiscoveryAt < helloIntervalMs)) return;
    const LocalDiscoveryPublication *publication = localDiscoveryFor(connection);
    if (!publication) return;
    String payload = {};
    auto snapshot = publication->publication.snapshot;
    if (snapshot.protocolVersion == ProdigyCousinDiscoverySnapshot::privateContainerVersion &&
        !switchboardPairControlPrivateDiscoveryAllowed(projection, connection.credential.pairUUID,
            connection.credential.rootGeneration, connection.remote.clusterUUID, true)) {
      Vector<ProdigyCousinCounterpart> external = {};
      for (const auto& record : snapshot.records)
        if (record.routablePrefixUUID != 0) external.push_back(record);
      snapshot.records = std::move(external);
      snapshot.protocolVersion = ProdigyCousinDiscoverySnapshot::version;
    }
    BitseryEngine::serialize(payload, snapshot);
    if (payload.size() == 0 || payload.size() > ProdigyCousinDiscoveryMaximumBytes ||
        connection.sentDiscoverySequence == UINT64_MAX ||
        !connection.wBuffer.need(discoveryRecordHeaderBytes + payload.size())) { retire(connection); return; }
    String record = {};
    if (!record.reserve(discoveryRecordHeaderBytes + payload.size())) { retire(connection); return; }
    clusterPairControlAppendU32BE(record, discoveryRecordType);
    clusterPairKeyAppendU64BE(record, ++connection.sentDiscoverySequence);
    clusterPairControlAppendU32BE(record, uint32_t(payload.size()));
    record.append(payload.data(), payload.size());
    if (record.size() != discoveryRecordHeaderBytes + payload.size()) { retire(connection); return; }
    connection.wBuffer.append(record);
    connection.lastDiscoveryAt = now;
    Ring::queueSend(&connection);
  }
  bool receiveDiscoverySnapshot(Connection& connection, const uint8_t *payload, uint32_t payloadBytes)
  {
    const uint8_t *cursor = payload;
    const uint8_t *end = payload + payloadBytes;
    uint64_t sequence = 0;
    uint32_t encodedBytes = 0;
    ProdigyCousinDiscoverySnapshot snapshot = {};
    if (!approved(connection) || !connection.ready || !connection.isTransportNegotiated() ||
        !connection.tlsPeerVerified || connection.tlsPeerUUID != connection.remote.nodeUUID ||
        !clusterPairControlReadU64BE(cursor, end, sequence) || sequence == 0 ||
        sequence <= connection.receivedDiscoverySequence ||
        !clusterPairControlReadU32BE(cursor, end, encodedBytes) || encodedBytes > ProdigyCousinDiscoveryMaximumBytes ||
        encodedBytes != uint32_t(end - cursor)) return false;
    String encoded = {};
    if (!encoded.reserve(encodedBytes)) return false;
    encoded.append(cursor, encodedBytes);
    if (!BitseryEngine::deserializeSafe(encoded, snapshot) || !prodigyCousinDiscoverySnapshotValid(snapshot) ||
        !discoveryMatchesConnection(snapshot, connection, false) ||
        (snapshot.protocolVersion == ProdigyCousinDiscoverySnapshot::privateContainerVersion &&
         !switchboardPairControlPrivateDiscoveryAllowed(projection, connection.credential.pairUUID,
             connection.credential.rootGeneration, connection.remote.clusterUUID, false))) return false;
    connection.receivedDiscoverySequence = sequence;
    connection.lastReceiveAt = Time::msSinceBoot();
    connection.remoteDiscovery = snapshot;
    connection.remoteDiscoveryPresent = !snapshot.records.empty();
    connection.remoteDiscoveryExpiresAt = connection.remoteDiscoveryPresent ?
        connection.lastReceiveAt + ProdigyCousinDiscoveryMaximumAgeMs : 0;
    if (onDiscoverySnapshot)
    {
      ProdigyCousinDiscoveryReceipt receipt = {};
      receipt.localEndpoint = connection.local;
      receipt.remoteEndpoint = connection.remote;
      receipt.wireEpoch = connection.credential.keyEpoch;
      receipt.projectionGeneration = projection.committedAuthorityGeneration;
      receipt.connectionID = connection.connectionID;
      receipt.sequence = sequence;
      receipt.withdrawn = snapshot.records.empty();
      receipt.snapshot = std::move(snapshot);
      onDiscoverySnapshot(receipt);
    }
    return true;
  }
  void retire(Connection& connection)
  {
    if (connection.closing) return;
    if (connection.ready)
      std::fprintf(stderr, "switchboard pair-control closed local=%016llx%016llx peer=%016llx%016llx pair=%016llx%016llx rootGeneration=%llu keyEpoch=%llu\n",
          (unsigned long long)(projection.nodeUUID >> 64), (unsigned long long)projection.nodeUUID,
          (unsigned long long)(connection.remote.nodeUUID >> 64), (unsigned long long)connection.remote.nodeUUID,
          (unsigned long long)(connection.credential.pairUUID >> 64), (unsigned long long)connection.credential.pairUUID,
          (unsigned long long)connection.credential.rootGeneration, (unsigned long long)connection.credential.keyEpoch);
    emitDiscoveryWithdrawal(connection);
    emitSessionDisconnect(connection);
    connection.pendingSessionRecords.clear(); connection.pendingSessionBytes = 0;
    connection.pendingCarrierRecords.clear(); connection.pendingCarrierBytes = 0;
    connection.carrierFlows.clear(); connection.carrierTombstones.clear();
    connection.closing = true; connection.ready = false;
    Ring::queueClose(&connection);
  }
  void retire(Listener& listener)
  {
    if (listener.closing) return;
    listener.closing = true;
    Ring::queueClose(&listener);
  }
  bool duplicate(const Connection& connection) const
  {
    return std::any_of(connections.begin(), connections.end(), [&](const auto& other) {
      return other.get() != &connection && other->selected && !other->closing &&
          sameCredential(other->credential, connection.credential);
    });
  }
  static bool adoptProcessSocket(SocketBase& socket)
  {
    // The generic pointer installer tolerates source-bind failure. Callers
    // prove the approved source binding first.
    if (socket.fd < 0) return false;
    const int slot = Ring::adoptProcessFDIntoFixedFileSlot(socket.fd);
    if (slot < 0) { ::close(socket.fd); socket.fd = -1; return false; }
    socket.fslot = slot; socket.isFixedFile = true; return true;
  }
  void armAccept(Listener& listener)
  {
    if (stopping || listener.closing || listener.accepting || connections.size() + acceptsPending >= maximumSockets) return;
    listener.accepting = true; ++acceptsPending;
    Ring::queueAccept(&listener, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
  }
  void armTick()
  {
    if (!started || stopping || tickPending || projection.protocolVersion == 0) return;
    tick.clear(); tick.originator = this; tick.setTimeoutMs(1000);
    tickPending = true; Ring::queueTimeout(&tick);
  }
  bool selectIncoming(Connection& connection, const String& remoteClaim, String& localClaim,
                      std::array<uint8_t, 32>& key, String& context, uint128_t& peerUUID)
  {
    if (stopping || connection.closing || !switchboardPairControlSafeObservedIPv6Peer(connection.observedPeer, connection.observedPeerLength)) return false;
    const ProdigyLocalClusterPairControlCredential *selected = nullptr;
    for (const auto& candidate : projection.credentials)
      if (candidate.remoteClaim == remoteClaim && candidate.responder == connection.local && isLocal(candidate.responder))
      { if (selected) return false; selected = &candidate; }
    const bool natCompatible = selected && clusterPairControlEndpointNATCompatibleOutbound(selected->initiator, selected->responder);
    if (!selected || (!natCompatible && std::memcmp(selected->initiator.address.v6,
        &reinterpret_cast<const sockaddr_in6&>(connection.observedPeer).sin6_addr, 16) != 0)) return false;
    connection.credential = *selected; connection.remote = selected->initiator; connection.selected = true;
    if (duplicate(connection)) return false;
    localClaim = selected->localClaim; context = selected->canonicalContext;
    std::memcpy(key.data(), selected->psk, key.size()); peerUUID = selected->initiator.nodeUUID;
    return true;
  }
  bool statusMatchesConnection(const ProdigyClusterPairEpochStatus& status, const Connection& connection) const
  {
    return prodigyClusterPairEpochStatusValid(status) && status.pairUUID == connection.credential.pairUUID &&
        status.rootGeneration == connection.credential.rootGeneration && status.sourceClusterUUID == connection.local.clusterUUID &&
        status.peerClusterUUID == connection.remote.clusterUUID && prodigyClusterPairEpochStatusAllowsWireEpoch(status, connection.credential.keyEpoch);
  }
  void queueEpochStatus(Connection& connection, int64_t now)
  {
    if (!approved(connection) || connection.closing || !connection.connected || !connection.ready ||
        !connection.isTransportNegotiated() || !connection.tlsPeerVerified ||
        connection.tlsPeerUUID != connection.remote.nodeUUID ||
        (connection.lastStatusAt != 0 && now - connection.lastStatusAt < helloIntervalMs) ||
        connection.pendingSend || connection.wBuffer.outstandingBytes() != 0) return;
    const ProdigyClusterPairEpochStatus *status = nullptr;
    for (const auto& candidate : projection.epochStatuses)
      if (statusMatchesConnection(candidate, connection)) { if (status) { retire(connection); return; } status = &candidate; }
    if (!status) return;
    String record = {};
    if (connection.sentStatusSequence == UINT64_MAX || !record.reserve(epochRecordBytes)) { retire(connection); return; }
    clusterPairControlAppendU32BE(record, epochRecordType);
    clusterPairKeyAppendU64BE(record, ++connection.sentStatusSequence);
    if (!prodigyClusterPairEpochStatusAppend(record, *status) || record.size() != epochRecordBytes ||
        !connection.wBuffer.need(epochRecordBytes)) { retire(connection); return; }
    connection.wBuffer.append(record); connection.lastStatusAt = now;
    Ring::queueSend(&connection);
  }
  bool receiveEpochStatus(Connection& connection, const uint8_t *payload)
  {
    const uint8_t *cursor = payload;
    const uint8_t *end = payload + 8 + ProdigyClusterPairEpochStatusBytes;
    uint64_t sequence = 0;
    ProdigyClusterPairEpochStatus status = {};
    if (!approved(connection) || !connection.ready || !connection.isTransportNegotiated() || !connection.tlsPeerVerified ||
        connection.tlsPeerUUID != connection.remote.nodeUUID ||
        !clusterPairControlReadU64BE(cursor, end, sequence) || sequence == 0 || sequence <= connection.receivedStatusSequence ||
        !prodigyClusterPairEpochStatusParse(cursor, end - cursor, status) ||
        status.pairUUID != connection.credential.pairUUID || status.rootGeneration != connection.credential.rootGeneration ||
        status.sourceClusterUUID != connection.remote.clusterUUID || status.peerClusterUUID != connection.local.clusterUUID ||
        !prodigyClusterPairEpochStatusAllowsWireEpoch(status, connection.credential.keyEpoch)) return false;
    connection.receivedStatusSequence = sequence;
    connection.lastReceiveAt = Time::msSinceBoot();
    if (onEpochStatus)
    {
      ProdigyClusterPairEpochReceipt receipt = {};
      receipt.localEndpoint = connection.local;
      receipt.remoteEndpoint = connection.remote;
      receipt.wireEpoch = connection.credential.keyEpoch;
      receipt.projectionGeneration = projection.committedAuthorityGeneration;
      receipt.status = std::move(status);
      onEpochStatus(receipt);
    }
    return true;
  }
  void queueHello(Connection& connection, int64_t now)
  {
    if (!approved(connection) || connection.closing || !connection.connected || !connection.isTransportNegotiated() ||
        !connection.tlsPeerVerified || connection.tlsPeerUUID != connection.remote.nodeUUID) return;
    if (connection.lastHelloAt != 0 && now - connection.lastHelloAt < helloIntervalMs) return;
    // A stalled sender retains at most one hello in addition to its current
    // encrypted send. Backpressure never creates an unbounded control queue.
    if (connection.pendingSend || connection.wBuffer.outstandingBytes() != 0) return;
    if (connection.sentSequence == UINT64_MAX) { retire(connection); return; }
    String hello;
    if (!hello.reserve(helloBytes)) { retire(connection); return; }
    clusterPairControlAppendU32BE(hello, helloRecordType);
    clusterPairKeyAppendU128BE(hello, connection.credential.pairUUID);
    clusterPairKeyAppendU64BE(hello, connection.credential.rootGeneration);
    clusterPairKeyAppendU64BE(hello, connection.credential.keyEpoch);
    clusterPairKeyAppendU128BE(hello, projection.nodeUUID);
    clusterPairKeyAppendU64BE(hello, ++connection.sentSequence);
    clusterPairKeyAppendU64BE(hello, projection.committedAuthorityGeneration);
    if (hello.size() != helloBytes || !connection.wBuffer.need(helloBytes)) { retire(connection); return; }
    connection.wBuffer.append(hello); connection.lastHelloAt = now;
    Ring::queueSend(&connection);
  }
  bool receiveHello(Connection& connection, const uint8_t *cursor)
  {
    const uint8_t *end = cursor + helloBytes;
    uint32_t version = 0; uint128_t pair = 0, peer = 0;
    uint64_t root = 0, epoch = 0, sequence = 0, foreignGeneration = 0;
    if (!approved(connection) || !connection.isTransportNegotiated() || !connection.tlsPeerVerified ||
        connection.tlsPeerUUID != connection.remote.nodeUUID ||
        !clusterPairControlReadU32BE(cursor, end, version) || version != 1 ||
        !clusterPairControlReadU128BE(cursor, end, pair) || !clusterPairControlReadU64BE(cursor, end, root) ||
        !clusterPairControlReadU64BE(cursor, end, epoch) || !clusterPairControlReadU128BE(cursor, end, peer) ||
        !clusterPairControlReadU64BE(cursor, end, sequence) || !clusterPairControlReadU64BE(cursor, end, foreignGeneration) ||
        cursor != end || pair != connection.credential.pairUUID || root != connection.credential.rootGeneration ||
        epoch != connection.credential.keyEpoch || peer != connection.remote.nodeUUID ||
        sequence <= connection.receivedSequence || foreignGeneration == 0) return false;
    connection.receivedSequence = sequence; connection.lastReceiveAt = Time::msSinceBoot();
    if (!connection.ready)
    {
      connection.ready = true;
      std::fprintf(stderr, "switchboard pair-control ready local=%016llx%016llx peer=%016llx%016llx pair=%016llx%016llx rootGeneration=%llu keyEpoch=%llu\n",
          (unsigned long long)(projection.nodeUUID >> 64), (unsigned long long)projection.nodeUUID,
          (unsigned long long)(peer >> 64), (unsigned long long)peer,
          (unsigned long long)(pair >> 64), (unsigned long long)pair,
          (unsigned long long)root, (unsigned long long)epoch);
    }
    return true;
  }
  void createListener(const ClusterPairControlEndpoint& endpoint)
  {
    auto listener = std::make_unique<Listener>(); listener->endpoint = endpoint;
    listener->setIPVersion(AF_INET6); listener->setNonBlocking(); listener->setSaddr(endpoint.address, endpoint.port);
    const int onlyIPv6 = 1;
    if (listener->fd < 0 || setsockopt(listener->fd, IPPROTO_IPV6, IPV6_V6ONLY, &onlyIPv6, sizeof(onlyIPv6)) != 0 ||
        ::bind(listener->fd, listener->saddr<sockaddr>(), listener->saddrLen) != 0 || ::listen(listener->fd, 16) != 0)
    { if (listener->fd >= 0) ::close(listener->fd); listener->fd = -1; return; }
    if (!adoptProcessSocket(*listener)) return;
    auto *owned = listener.get(); listeners.push_back(std::move(listener));
    RingDispatcher::installMultiplexee(owned, this); armAccept(*owned);
  }
  void createOutbound(const ProdigyLocalClusterPairControlCredential& credential)
  {
    if (connections.size() + acceptsPending >= maximumSockets) return;
    auto connection = std::make_unique<Connection>();
    connection->credential = credential; connection->local = credential.initiator; connection->remote = credential.responder;
    if (nextConnectionID == 0 || nextConnectionID == UINT64_MAX) return;
    connection->selected = true; connection->connectionID = nextConnectionID++; connection->createdAt = Time::msSinceBoot();
    connection->setIPVersion(AF_INET6); connection->setNonBlocking();
    connection->setDaddr(connection->remote.address, connection->remote.port);
    if (!switchboardPairControlBindOutboundSource(*connection, credential))
    { if (connection->fd >= 0) ::close(connection->fd); connection->fd = -1; return; }
    if (!adoptProcessSocket(*connection)) return;
    connection->rBuffer.reserve(ProdigyCousinDiscoveryMaximumBytes + 128); connection->wBuffer.reserve(ProdigyCousinDiscoveryMaximumBytes + 128);
    auto *owned = connection.get(); connections.push_back(std::move(connection));
    RingDispatcher::installMultiplexee(owned, this);
    if (!owned->beginTransportAEGISWithPrelude(false, projection.nodeUUID, credential.localClaim,
        [this, owned](const String& claim, std::array<uint8_t, 32>& key, String& context, uint128_t& peer) {
          if (stopping || owned->closing || !approved(*owned) || claim != owned->credential.remoteClaim) return false;
          std::memcpy(key.data(), owned->credential.psk, key.size()); context = owned->credential.canonicalContext;
          peer = owned->remote.nodeUUID; return true;
        })) { retire(*owned); return; }
    Ring::queueConnect(owned);
  }
  void reconcile()
  {
    if (!started || stopping || projection.protocolVersion == 0) return;
    const int64_t now = Time::msSinceBoot();
    for (auto& publication : discoveryPublications)
      if (publication.expiresAt <= now && !publication.withdrawing)
      {
        publication.publication.snapshot.records.clear();
        publication.withdrawing = true;
        publication.expiresAt = now + helloIntervalMs;
      }
    discoveryPublications.erase(std::remove_if(discoveryPublications.begin(), discoveryPublications.end(),
        [&](const auto& publication) { return publication.expiresAt <= now && publication.withdrawing; }),
        discoveryPublications.end());
    for (auto& listener : listeners)
      if (!listener->closing && !ownsListenerEndpoint(listener->endpoint)) retire(*listener);
    for (auto& connection : connections)
    {
      if (connection->closing) continue;
      if ((connection->selected && !approved(*connection)) ||
          (!connection->ready && now - connection->createdAt >= handshakeTimeoutMs) ||
          (connection->ready && now - connection->lastReceiveAt >= idleTimeoutMs)) { retire(*connection); continue; }
      if (connection->remoteDiscoveryPresent && connection->remoteDiscoveryExpiresAt <= now) emitDiscoveryWithdrawal(*connection);
      queueHello(*connection, now);
      queueEpochStatus(*connection, now);
      queueDiscoverySnapshot(*connection, now);
      flushSessionControl(*connection); flushCarrierFrame(*connection);
    }
    for (const auto& credential : projection.credentials)
    {
      if (isLocal(credential.responder) && std::none_of(listeners.begin(), listeners.end(),
          [&](const auto& listener) { return listener->endpoint == credential.responder; })) createListener(credential.responder);
      if (isLocal(credential.initiator) && std::none_of(connections.begin(), connections.end(),
          [&](const auto& connection) { return connection->selected && sameCredential(connection->credential, credential); }))
        createOutbound(credential);
    }
    for (auto& listener : listeners) armAccept(*listener);
  }
public:
  std::function<void(const ProdigyClusterPairEpochReceipt&)> onEpochStatus;
  std::function<void(const ProdigyCousinDiscoveryReceipt&)> onDiscoverySnapshot;
  std::function<void(const ProdigyCousinSessionReceipt&)> onSessionControl;
  std::function<bool(const ClusterPairControlEndpoint&, const ClusterPairControlEndpoint&, uint64_t,
                     const ProdigyCousinCarrierFrame&)> onCarrierFrame;

  bool sendSessionControl(const ProdigyCousinSessionPublication& publication)
  {
    if (stopping || !prodigyCousinSessionPublicationValid(publication) ||
        publication.projectionGeneration != projection.committedAuthorityGeneration ||
        publication.nodeUUID != projection.nodeUUID) return false;
    Connection *selected = nullptr;
    for (auto& candidate : connections) {
      if (candidate->closing || !candidate->ready || candidate->connectionID != publication.connectionID ||
          candidate->local != publication.localEndpoint || candidate->remote != publication.remoteEndpoint) continue;
      if (selected) return false; selected = candidate.get();
    }
    if (!selected || !approved(*selected) || publication.control.session.sourcePermission.pairUUID != selected->credential.pairUUID ||
        publication.control.session.rootGeneration != selected->credential.rootGeneration ||
        publication.control.session.keyEpoch != selected->credential.keyEpoch) return false;
    String encoded = {}; auto control = publication.control;
    if (!BitseryEngine::serialize(encoded, control) || encoded.empty() || encoded.size() > ProdigyCousinSessionMaximumBytes ||
        selected->sentSessionSequence == UINT64_MAX || selected->pendingSessionRecords.size() >= maximumPendingSessionRecords ||
        encoded.size() > UINT32_MAX - sessionRecordHeaderBytes ||
        selected->pendingSessionBytes > maximumPendingSessionRecords * ProdigyCousinSessionMaximumBytes - encoded.size() - sessionRecordHeaderBytes) return false;
    String record = {}; if (!record.reserve(sessionRecordHeaderBytes + encoded.size())) return false;
    clusterPairControlAppendU32BE(record, sessionRecordType); clusterPairKeyAppendU64BE(record, ++selected->sentSessionSequence);
    clusterPairControlAppendU32BE(record, uint32_t(encoded.size())); record.append(encoded.data(), encoded.size());
    if (record.size() != sessionRecordHeaderBytes + encoded.size()) return false;
    selected->pendingSessionBytes += uint32_t(record.size()); selected->pendingSessionRecords.push_back(std::move(record));
    flushSessionControl(*selected); return true;
  }

  bool sendCarrierFrame(const ProdigyCousinSessionRecord& session,
                        const ClusterPairControlEndpoint& local, const ClusterPairControlEndpoint& remote,
                        uint64_t localConnectionID, const ProdigyCousinCarrierFrame& frame)
  {
    if (stopping || !prodigyCousinReverseCarrierSessionValid(session) || !prodigyCousinCarrierFrameValid(frame) ||
        frame.sessionUUID != session.sessionUUID ||
        !((local == session.sourceCarrier && remote == session.destinationCarrier) ||
          (local == session.destinationCarrier && remote == session.sourceCarrier))) return false;
    Connection *selected = nullptr;
    for (auto& candidate : connections) {
      if (candidate->closing || !candidate->ready || candidate->connectionID != localConnectionID ||
          candidate->local != local || candidate->remote != remote) continue;
      if (selected) return false; selected = candidate.get();
    }
    if (!selected || !approved(*selected)) return false;
    auto flow = std::find_if(selected->carrierFlows.begin(), selected->carrierFlows.end(), [&](const auto& value) {
      return value.sessionUUID == frame.sessionUUID;
    });
    Connection::CarrierFlow updated = {};
    bool installFlow = false, eraseFlow = false;
    if (flow == selected->carrierFlows.end()) {
      if ((frame.kind != ProdigyCousinCarrierKind::open && frame.kind != ProdigyCousinCarrierKind::openAck) ||
          selected->carrierFlows.size() >= ProdigyCousinSessionMaximumRecords) return false;
      if (frame.kind != ProdigyCousinCarrierKind::open || frame.sequence != 1 ||
          carrierFlowGenerationRetired(*selected, frame.sessionUUID, frame.leaseGeneration)) return false;
      updated.sessionUUID = frame.sessionUUID; updated.leaseGeneration = frame.leaseGeneration;
      updated.sentSequence = frame.sequence; updated.receivedCredits = frame.credits;
      updated.openedSent = true;
      installFlow = true;
    } else {
      if (flow->leaseGeneration != frame.leaseGeneration || flow->sentClosed) return false;
      updated = *flow;
      const bool dataReady = (updated.openedSent && updated.ackedReceived) ||
          (updated.openedReceived && updated.ackedSent);
      if (frame.kind == ProdigyCousinCarrierKind::openAck) {
        if (!updated.openedReceived || updated.ackedSent || frame.sequence != 1 || updated.sentSequence != 0) return false;
        updated.ackedSent = true;
        updated.receivedCredits = frame.credits;
        updated.sentSequence = frame.sequence;
      } else {
        if (frame.sequence != updated.sentSequence + 1) return false;
        switch (frame.kind) {
        case ProdigyCousinCarrierKind::data:
          if (!dataReady || updated.sentCredits == 0 || frame.credits != updated.sentCredits - 1) return false;
          --updated.sentCredits; break;
        case ProdigyCousinCarrierKind::window:
          // A local window grants the peer receive allowance, not this sender.
          if (!dataReady || frame.credits <= updated.receivedCredits) return false;
          updated.receivedCredits = frame.credits; break;
        case ProdigyCousinCarrierKind::fin:
          if (!dataReady) return false;
          [[fallthrough]];
        case ProdigyCousinCarrierKind::reset:
          updated.sentClosed = true; break;
        case ProdigyCousinCarrierKind::open:
          return false;
        case ProdigyCousinCarrierKind::openAck: return false;
        }
        updated.sentSequence = frame.sequence;
      }
      eraseFlow = frame.kind == ProdigyCousinCarrierKind::reset ||
          (updated.receivedClosed && updated.sentClosed);
    }
    if (eraseFlow && !carrierFlowCanRetire(*selected, flow->sessionUUID)) {
      retire(*selected); return false;
    }
    String encoded = {}; auto copy = frame;
    if (!BitseryEngine::serialize(encoded, copy) || encoded.empty() ||
        encoded.size() > ProdigyCousinCarrierMaximumPayloadBytes + 128 ||
        selected->pendingCarrierRecords.size() >= maximumPendingSessionRecords ||
        encoded.size() > UINT32_MAX - carrierRecordHeaderBytes ||
        selected->pendingCarrierBytes > maximumPendingSessionRecords *
            (ProdigyCousinCarrierMaximumPayloadBytes + carrierRecordHeaderBytes + 128) - encoded.size() - carrierRecordHeaderBytes)
      return false;
    String record = {}; if (!record.reserve(carrierRecordHeaderBytes + encoded.size())) return false;
    clusterPairControlAppendU32BE(record, carrierRecordType);
    clusterPairControlAppendU32BE(record, uint32_t(encoded.size())); record.append(encoded.data(), encoded.size());
    if (record.size() != carrierRecordHeaderBytes + encoded.size()) return false;
    selected->pendingCarrierBytes += uint32_t(record.size()); selected->pendingCarrierRecords.push_back(std::move(record));
    // Commit flow state only after every serialization and bounded-queue check
    // succeeded. A rejected enqueue must be safely retryable with the same frame.
    if (installFlow) selected->carrierFlows.push_back(updated);
    else if (eraseFlow) {
      if (!retireCarrierFlowGeneration(*selected, flow->sessionUUID, flow->leaseGeneration)) { retire(*selected); return false; }
      selected->carrierFlows.erase(flow);
    }
    else *flow = updated;
    flushSessionControl(*selected); flushCarrierFrame(*selected); return true;
  }

  bool installDiscoverySnapshot(const ProdigyCousinDiscoveryPublication& publication)
  {
    if (stopping || !prodigyCousinDiscoveryPublicationValid(publication) ||
        publication.nodeUUID != projection.nodeUUID ||
        publication.projectionGeneration != projection.committedAuthorityGeneration ||
        publication.snapshot.authorityGeneration < projection.committedAuthorityGeneration) return false;
    bool authorized = false;
    for (const auto& credential : projection.credentials)
      if ((isLocal(credential.initiator) || isLocal(credential.responder)) &&
          publication.snapshot.pairUUID == credential.pairUUID &&
          publication.snapshot.rootGeneration == credential.rootGeneration &&
          publication.snapshot.keyEpoch == credential.keyEpoch &&
          publication.snapshot.sourceClusterUUID == projection.localClusterUUID &&
          publication.snapshot.peerClusterUUID != projection.localClusterUUID &&
          (publication.snapshot.peerClusterUUID == credential.initiator.clusterUUID ||
           publication.snapshot.peerClusterUUID == credential.responder.clusterUUID)) { authorized = true; break; }
    if (!authorized) return false;
    LocalDiscoveryPublication *existing = nullptr;
    for (auto& candidate : discoveryPublications)
      if (candidate.publication.snapshot.pairUUID == publication.snapshot.pairUUID &&
          candidate.publication.snapshot.rootGeneration == publication.snapshot.rootGeneration &&
          candidate.publication.snapshot.keyEpoch == publication.snapshot.keyEpoch) { existing = &candidate; break; }
    if (!existing && discoveryPublications.size() >= ProdigyCousinDiscoveryMaximumPairs) return false;
    const int64_t now = Time::msSinceBoot();
    if (existing) { existing->publication = publication; existing->withdrawing = false; existing->expiresAt = now + ProdigyCousinDiscoveryMaximumAgeMs; }
    else discoveryPublications.push_back({publication, false, now + ProdigyCousinDiscoveryMaximumAgeMs});
    for (auto& connection : connections)
      if (!connection->closing && discoveryMatchesConnection(publication.snapshot, *connection, true))
        connection->lastDiscoveryAt = 0;
    armTick(); return true;
  }

  // The owner calls quiesce until true before destruction or process exec.
  ~SwitchboardPairControlRuntime()
  {
    if (started && (!connections.empty() || !listeners.empty() || tickPending) && !Ring::shuttingDown) std::abort();
    if (started && RingDispatcher::dispatcher) RingDispatcher::eraseMultiplexee(this);
  }
  bool installProjection(const ProdigyLocalClusterPairControlProjection& next)
  {
    if (stopping || !prodigyLocalClusterPairControlProjectionValid(next, true)) return false;
    if (projection.protocolVersion != 0 && (next.localClusterUUID != projection.localClusterUUID ||
        next.nodeUUID != projection.nodeUUID || next.committedAuthorityGeneration < projection.committedAuthorityGeneration ||
        (next.committedAuthorityGeneration == projection.committedAuthorityGeneration &&
         !prodigyLocalClusterPairControlProjectionEqual(next, projection)))) return false;
    for (auto& connection : connections) emitDiscoveryWithdrawal(*connection);
    discoveryPublications.clear();
    projection = next;
    // Revoke before returning the durable installation receipt. New connection
    // attempts wait for the common tick, which also bounds reconnect frequency.
    for (auto& connection : connections)
      if (!connection->closing && (!connection->selected || !approved(*connection))) retire(*connection);
    for (auto& listener : listeners)
      if (!listener->closing && !ownsListenerEndpoint(listener->endpoint)) retire(*listener);
    armTick(); return true;
  }
  bool start()
  {
    if (started || stopping) return false;
    started = true; RingDispatcher::installMultiplexee(this, this); armTick(); return true;
  }
  uint32_t readyCount() const
  { return uint32_t(std::count_if(connections.begin(), connections.end(), [](const auto& c) { return c->ready && !c->closing; })); }
  bool quiesce()
  {
    stopping = true;
    if (tickPending && !tickCancelPending) { tickCancelPending = true; Ring::queueCancelTimeout(&tick); }
    for (auto& connection : connections) retire(*connection);
    for (auto& listener : listeners) retire(*listener);
    return connections.empty() && listeners.empty() && !tickPending;
  }
  void acceptHandler(void *socket, int slot) override
  {
    auto *listener = listenerFor(socket);
    if (!listener) std::abort();
    if (listener->accepting) { listener->accepting = false; --acceptsPending; }
    if (slot >= 0)
    {
      auto connection = std::make_unique<Connection>();
      connection->fslot = slot; connection->isFixedFile = true; connection->isNonBlocking = true;
      const bool connectionIDExhausted = nextConnectionID == 0 || nextConnectionID == UINT64_MAX;
      connection->connected = true; connection->connectionID = connectionIDExhausted ? UINT64_MAX : nextConnectionID++;
      connection->local = listener->endpoint; connection->createdAt = Time::msSinceBoot();
      const bool captured = Ring::takeAcceptedPeerAddress(slot, connection->observedPeer, connection->observedPeerLength);
      connection->rBuffer.reserve(ProdigyCousinDiscoveryMaximumBytes + 128); connection->wBuffer.reserve(ProdigyCousinDiscoveryMaximumBytes + 128);
      auto *owned = connection.get(); connections.push_back(std::move(connection));
      RingDispatcher::installMultiplexee(owned, this);
      if (connectionIDExhausted || !captured || stopping || listener->closing || !owned->beginTransportAEGISWithDeferredServerPrelude(
          projection.nodeUUID, [this, owned](const String& remote, String& local, std::array<uint8_t,32>& key, String& context, uint128_t& peer) {
            return selectIncoming(*owned, remote, local, key, context, peer);
          })) retire(*owned);
      else Ring::queueRecv(owned);
    }
    armAccept(*listener);
  }
  void connectHandler(void *socket, int result) override
  {
    auto *connection = connectionFor(socket);
    if (!connection || connection->closing) return;
    if (result != 0 || stopping || !approved(*connection)) { retire(*connection); return; }
    connection->connected = true;
    Ring::queueRecv(connection); Ring::queueSend(connection);
  }
  void recvHandler(void *socket, int result) override
  {
    auto *connection = connectionFor(socket);
    if (!connection || connection->closing || !connection->pendingRecv) return;
    connection->pendingRecv = false;
    if (result <= 0 || uint64_t(result) > connection->rBuffer.remainingCapacity() ||
        !connection->decryptTransportTLS(uint32_t(result))) { retire(*connection); return; }
    while (connection->rBuffer.outstandingBytes() >= sizeof(uint32_t))
    {
      const uint8_t *frame = connection->rBuffer.pHead();
      const uint8_t *terminal = frame + connection->rBuffer.outstandingBytes();
      uint32_t type = 0;
      if (!clusterPairControlReadU32BE(frame, terminal, type)) { retire(*connection); return; }
      uint32_t bytes = type == helloRecordType ? helloBytes : type == epochRecordType ? epochRecordBytes : 0;
      if (type == discoveryRecordType)
      {
        if (connection->rBuffer.outstandingBytes() < discoveryRecordHeaderBytes) break;
        const uint8_t *cursor = frame + sizeof(uint64_t);
        uint32_t encodedBytes = 0;
        if (!clusterPairControlReadU32BE(cursor, terminal, encodedBytes) ||
            encodedBytes > ProdigyCousinDiscoveryMaximumBytes ||
            encodedBytes > UINT32_MAX - discoveryRecordHeaderBytes) { retire(*connection); return; }
        bytes = discoveryRecordHeaderBytes + encodedBytes;
      }
      else if (type == sessionRecordType)
      {
        if (connection->rBuffer.outstandingBytes() < sessionRecordHeaderBytes) break;
        // `clusterPairControlReadU32BE` advanced frame past the type above.
        // The length follows the eight-byte sequence, not another type field.
        const uint8_t *cursor = frame + sizeof(uint64_t); uint32_t encodedBytes = 0;
        if (!clusterPairControlReadU32BE(cursor, terminal, encodedBytes) || encodedBytes == 0 ||
            encodedBytes > ProdigyCousinSessionMaximumBytes || encodedBytes > UINT32_MAX - sessionRecordHeaderBytes) { retire(*connection); return; }
        bytes = sessionRecordHeaderBytes + encodedBytes;
      }
      else if (type == carrierRecordType)
      {
        if (connection->rBuffer.outstandingBytes() < carrierRecordHeaderBytes) break;
        const uint8_t *cursor = frame; uint32_t encodedBytes = 0;
        if (!clusterPairControlReadU32BE(cursor, terminal, encodedBytes) || encodedBytes == 0 ||
            encodedBytes > ProdigyCousinCarrierMaximumPayloadBytes + 128 ||
            encodedBytes > UINT32_MAX - carrierRecordHeaderBytes) { retire(*connection); return; }
        bytes = carrierRecordHeaderBytes + encodedBytes;
      }
      if (bytes == 0) { retire(*connection); return; }
      if (connection->rBuffer.outstandingBytes() < bytes) break;
      const uint8_t *record = connection->rBuffer.pHead();
      if ((type == helloRecordType && !receiveHello(*connection, record)) ||
          (type == epochRecordType && !receiveEpochStatus(*connection, record + sizeof(uint32_t))) ||
          (type == discoveryRecordType && !receiveDiscoverySnapshot(*connection, record + sizeof(uint32_t), bytes - sizeof(uint32_t))) ||
          (type == sessionRecordType && !receiveSessionControl(*connection, record + sizeof(uint32_t), bytes - sizeof(uint32_t))) ||
          (type == carrierRecordType && !receiveCarrierFrame(*connection, record + carrierRecordHeaderBytes,
                                                               bytes - carrierRecordHeaderBytes)))
      { retire(*connection); return; }
      connection->rBuffer.consume(bytes, true);
    }
    const int64_t now = Time::msSinceBoot();
    queueHello(*connection, now);
    queueEpochStatus(*connection, now);
    queueDiscoverySnapshot(*connection, now);
    flushSessionControl(*connection); flushCarrierFrame(*connection);
    if (connection->closing) return;
    if (connection->needsTransportTLSSendKick()) Ring::queueSend(connection);
    Ring::queueRecv(connection);
  }
  void sendHandler(void *socket, int result) override
  {
    auto *connection = connectionFor(socket);
    if (!connection || connection->closing || !connection->pendingSend) return;
    connection->pendingSend = false;
    const uint32_t submitted = connection->pendingSendBytes; connection->pendingSendBytes = 0;
    if (result <= 0 || uint32_t(result) > submitted) { connection->noteSendCompleted(); retire(*connection); return; }
    connection->consumeSentBytes(uint32_t(result), false); connection->noteSendCompleted();
    const int64_t now = Time::msSinceBoot();
    queueHello(*connection, now);
    queueEpochStatus(*connection, now);
    queueDiscoverySnapshot(*connection, now);
    flushSessionControl(*connection); flushCarrierFrame(*connection);
    if (!connection->closing && (connection->needsTransportTLSSendKick() || connection->wBuffer.outstandingBytes()))
      Ring::queueSend(connection);
  }
  void closeHandler(void *socket) override
  {
    // Ring dispatches this only after the close and every operation from the
    // retired socket generation have drained. No handler resets/reuses it.
    if (auto *listener = listenerFor(socket))
    {
      if (listener->accepting) { listener->accepting = false; --acceptsPending; }
      RingDispatcher::eraseMultiplexee(listener);
      listeners.erase(std::remove_if(listeners.begin(), listeners.end(), [&](const auto& item) { return item.get() == listener; }), listeners.end());
    }
    else if (auto *connection = connectionFor(socket))
    {
      RingDispatcher::eraseMultiplexee(connection);
      connections.erase(std::remove_if(connections.begin(), connections.end(), [&](const auto& item) { return item.get() == connection; }), connections.end());
    }
  }
  void timeoutHandler(TimeoutPacket *packet, int result) override
  {
    if (packet != &tick) return;
    tickPending = false; tickCancelPending = false;
    if (!stopping && result != -ECANCELED) { reconcile(); armTick(); }
  }
};
