#pragma once

#include <algorithm>
#include <array>
#include <memory>
#include <vector>
#include <services/time.h>
#include <prodigy/transport.tls.h>
#include <networking/multiplexer.h>
#include <networking/ring.h>
#include <prodigy/cluster.pair.projection.h>

// Neuron owns this Switchboard control component. Its input is an already
// durable, node-scoped credential projection; it never possesses a pair root
// or carries application traffic. The first control record is a fixed hello.
class SwitchboardPairControlRuntime final : public RingInterface {
  static constexpr uint32_t helloBytes = 68;
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
    uint64_t sentSequence = 0, receivedSequence = 0;
    int64_t createdAt = 0, lastReceiveAt = 0, lastHelloAt = 0;
  };
  ProdigyLocalClusterPairControlProjection projection;
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
  void retire(Connection& connection)
  {
    if (connection.closing) return;
    if (connection.ready)
      std::fprintf(stderr, "switchboard pair-control closed local=%016llx%016llx peer=%016llx%016llx pair=%016llx%016llx\n",
          (unsigned long long)(projection.nodeUUID >> 64), (unsigned long long)projection.nodeUUID,
          (unsigned long long)(connection.remote.nodeUUID >> 64), (unsigned long long)connection.remote.nodeUUID,
          (unsigned long long)(connection.credential.pairUUID >> 64), (unsigned long long)connection.credential.pairUUID);
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
    clusterPairControlAppendU32BE(hello, 1);
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
    connection->selected = true; connection->createdAt = Time::msSinceBoot();
    connection->setIPVersion(AF_INET6); connection->setNonBlocking();
    connection->setSaddr(connection->local.address, 0); connection->setDaddr(connection->remote.address, connection->remote.port);
    if (connection->fd < 0 || !Ring::bindSourceAddressBeforeFixedFileInstall(connection.get()))
    { if (connection->fd >= 0) ::close(connection->fd); connection->fd = -1; return; }
    if (!adoptProcessSocket(*connection)) return;
    connection->rBuffer.reserve(8192); connection->wBuffer.reserve(4096);
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
    for (auto& listener : listeners)
      if (!listener->closing && !ownsListenerEndpoint(listener->endpoint)) retire(*listener);
    for (auto& connection : connections)
    {
      if (connection->closing) continue;
      if ((connection->selected && !approved(*connection)) ||
          (!connection->ready && now - connection->createdAt >= handshakeTimeoutMs) ||
          (connection->ready && now - connection->lastReceiveAt >= idleTimeoutMs)) { retire(*connection); continue; }
      queueHello(*connection, now);
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
      connection->connected = true; connection->local = listener->endpoint; connection->createdAt = Time::msSinceBoot();
      const bool captured = Ring::takeAcceptedPeerAddress(slot, connection->observedPeer, connection->observedPeerLength);
      connection->rBuffer.reserve(8192); connection->wBuffer.reserve(4096);
      auto *owned = connection.get(); connections.push_back(std::move(connection));
      RingDispatcher::installMultiplexee(owned, this);
      if (!captured || stopping || listener->closing || !owned->beginTransportAEGISWithDeferredServerPrelude(
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
    while (connection->rBuffer.outstandingBytes() >= helloBytes)
    {
      if (!receiveHello(*connection, connection->rBuffer.pHead())) { retire(*connection); return; }
      connection->rBuffer.consume(helloBytes, true);
    }
    queueHello(*connection, Time::msSinceBoot());
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
    queueHello(*connection, Time::msSinceBoot());
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
