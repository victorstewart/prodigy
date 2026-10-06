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

// Neuron owns this Switchboard control component. Its input is an already
// durable, node-scoped credential projection; it never possesses a pair root
// or carries application traffic. The first control record is a fixed hello.
class SwitchboardPairControlRuntime final : public RingInterface {
  static constexpr uint32_t helloBytes = 68;
  static constexpr uint32_t epochRecordBytes = 4 + 8 + ProdigyClusterPairEpochStatusBytes;
  static constexpr uint32_t discoveryRecordHeaderBytes = 4 + 8 + 4;
  static constexpr uint32_t helloRecordType = 1, epochRecordType = 2, discoveryRecordType = 3;
  static constexpr size_t maximumSockets = ProdigyLocalClusterPairControlProjectionMaximumCredentials + 16;
  static constexpr int64_t handshakeTimeoutMs = 10000, idleTimeoutMs = 15000, helloIntervalMs = 3000;
  struct Listener : TCPSocket {
    ClusterPairControlEndpoint endpoint;
    bool closing = false, accepting = false;
  };
  struct Connection : ProdigyTransportTLSStream {
    ProdigyLocalClusterPairControlCredential credential;
    ClusterPairControlEndpoint local, remote;
    sockaddr_storage observedPeer = {};
    socklen_t observedPeerLength = 0;
    bool closing = false, connected = false, selected = false, ready = false;
    uint64_t connectionID = 0;
    uint64_t sentSequence = 0, receivedSequence = 0, sentStatusSequence = 0, receivedStatusSequence = 0;
    uint64_t sentDiscoverySequence = 0, receivedDiscoverySequence = 0;
    bool remoteDiscoveryPresent = false;
    ProdigyCousinDiscoverySnapshot remoteDiscovery = {};
    int64_t remoteDiscoveryExpiresAt = 0;
    int64_t createdAt = 0, lastReceiveAt = 0, lastHelloAt = 0, lastStatusAt = 0, lastDiscoveryAt = 0;
  };
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
        !discoveryMatchesConnection(snapshot, connection, false)) return false;
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
    // The generic pointer installer tolerates source-bind failure. This
    // carrier must prove its approved source binding before fixed-file adoption.
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
    if (stopping || connection.closing || connection.observedPeer.ss_family != AF_INET6 ||
        connection.observedPeerLength != sizeof(sockaddr_in6)) return false;
    const ProdigyLocalClusterPairControlCredential *selected = nullptr;
    for (const auto& candidate : projection.credentials)
      if (candidate.remoteClaim == remoteClaim && candidate.responder == connection.local && isLocal(candidate.responder))
      { if (selected) return false; selected = &candidate; }
    if (!selected || std::memcmp(selected->initiator.address.v6,
        &reinterpret_cast<const sockaddr_in6&>(connection.observedPeer).sin6_addr, 16) != 0) return false;
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
    connection->setSaddr(connection->local.address, 0); connection->setDaddr(connection->remote.address, connection->remote.port);
    if (connection->fd < 0 || !Ring::bindSourceAddressBeforeFixedFileInstall(connection.get()))
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
      if (bytes == 0) { retire(*connection); return; }
      if (connection->rBuffer.outstandingBytes() < bytes) break;
      const uint8_t *record = connection->rBuffer.pHead();
      if ((type == helloRecordType && !receiveHello(*connection, record)) ||
          (type == epochRecordType && !receiveEpochStatus(*connection, record + sizeof(uint32_t))) ||
          (type == discoveryRecordType && !receiveDiscoverySnapshot(*connection, record + sizeof(uint32_t), bytes - sizeof(uint32_t))))
      { retire(*connection); return; }
      connection->rBuffer.consume(bytes, true);
    }
    const int64_t now = Time::msSinceBoot();
    queueHello(*connection, now);
    queueEpochStatus(*connection, now);
    queueDiscoverySnapshot(*connection, now);
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
