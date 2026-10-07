#pragma once

#include <services/time.h>
#include <prodigy/cousin.session.h>
#include <prodigy/transport.tls.h>
#include <networking/ring.h>
#include <memory>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// Native application credential owner. The NeuronHub callback applies commands
// here before acknowledging them. No enrollment root is exposed to this owner.
struct ProdigyCousinSessionLease {
  ProdigyCousinSessionLocalCommand command = {};
  int64_t deadline = 0;
  bool live = true;
  bool claimed = false;
  bool current() const { return live && Time::msSinceBoot() < deadline; }
  void revoke() { live = false; OPENSSL_cleanse(command.psk.data(), command.psk.size()); }
};

class ProdigyCousinSessionClient;
class ProdigyCousinSessionStream : public ProdigyTransportTLSStream {
  friend class ProdigyCousinSessionClient;
  std::weak_ptr<ProdigyCousinSessionLease> lease;
  int64_t pendingDeadline = 0;
  bool resolving = false;
  bool authorized() const
  {
    if (resolving) return Time::msSinceBoot() < pendingDeadline;
    auto current = lease.lock();
    return current && current->current();
  }
  bool guard()
  {
    if (authorized()) return true;
    ProdigyTransportTLSStream::clearQueuedSendBytes();
    return false;
  }
public:
  // These entry points must remain on the concrete stream in the receive owner.
  // Ring's virtual send interface is guarded as well, including queued ciphertext.
  bool prepareTransportTLSSend() { return guard() && ProdigyTransportTLSStream::prepareTransportTLSSend(); }
  bool decryptTransportTLS(uint32_t bytes)
  {
    return guard() && ProdigyTransportTLSStream::decryptTransportTLS(bytes) && guard();
  }
  bool isTransportNegotiated() const { return authorized() && ProdigyTransportTLSStream::isTransportNegotiated(); }
  uint32_t nBytesToSend() override { return guard() ? ProdigyTransportTLSStream::nBytesToSend() : 0; }
  uint8_t *pBytesToSend() override { return guard() ? ProdigyTransportTLSStream::pBytesToSend() : nullptr; }
  uint64_t queuedSendOutstandingBytes() const override
  { return authorized() ? ProdigyTransportTLSStream::queuedSendOutstandingBytes() : 0; }
  uint128_t sessionUUID() const
  { auto current = lease.lock(); return current ? current->command.session.sessionUUID : 0; }
  // Ring owns a fixed descriptor. An application-owned outbound stream may
  // abort its ordinary descriptor when its fixed source tuple must be reused.
  bool abortOwnedSocket()
  {
    if (isFixedFile || fd < 0) return false;
    const int ownedFD = fd;
    fd = -1;
    struct linger terminal = {};
    terminal.l_onoff = 1;
    const bool configured = ::setsockopt(ownedFD, SOL_SOCKET, SO_LINGER, &terminal, sizeof(terminal)) == 0;
    const bool closed = ::close(ownedFD) == 0;
    return configured && closed;
  }
};

class ProdigyCousinSessionClient {
  struct State {
    uint128_t containerUUID = 0;
    std::vector<std::shared_ptr<ProdigyCousinSessionLease>> leases;
    ~State() { for (auto& lease : leases) lease->revoke(); }
  };
  std::shared_ptr<State> state;

  static String prelude(uint128_t session, CousinRouteHalf half)
  {
    // Fixed public lookup hint; the secure transport authenticates both exact
    // preludes in its fresh X25519 handshake before releasing application bytes.
    String value = {};
    value.reserve(24);
    value.append("PRDCS\x01"_ctv);
    value.append(uint8_t(half));
    for (unsigned i = 0; i < 16; ++i) value.append(uint8_t(session >> (i * 8)));
    return value;
  }
  static bool readPrelude(const String& value, uint128_t& session)
  {
    session = 0;
    if (value.size() != 23 || std::memcmp(value.data(), "PRDCS\x01", 6) != 0 ||
        value.data()[6] != uint8_t(CousinRouteHalf::source)) return false;
    for (unsigned i = 0; i < 16; ++i) session |= uint128_t(value.data()[7 + i]) << (i * 8);
    return session != 0;
  }
  static bool observedSourceMatches(const sockaddr_storage& observed, socklen_t length,
                                    const ProdigyCousinSessionRecord& session)
  {
    if (length < sizeof(sockaddr_in6) || observed.ss_family != AF_INET6) return false;
    const auto& peer = reinterpret_cast<const sockaddr_in6&>(observed);
    return peer.sin6_scope_id == 0 && ntohs(peer.sin6_port) == session.sourceTCPPort &&
        std::memcmp(&peer.sin6_addr, session.sourceAddress.v6, 16) == 0;
  }
public:
  // The socket owner closes matching live streams when this fires. Guards also
  // enforce the lease independently if the event loop has not polled yet.
  std::function<void(uint128_t)> onSessionClosed;
  explicit ProdigyCousinSessionClient(uint128_t containerUUID) : state(std::make_shared<State>())
  { state->containerUUID = containerUUID; }
  ProdigyCousinSessionClient(const ProdigyCousinSessionClient&) = delete;
  ProdigyCousinSessionClient& operator=(const ProdigyCousinSessionClient&) = delete;

  void expire()
  {
    std::vector<uint128_t> expired;
    for (auto it = state->leases.begin(); it != state->leases.end();) {
      if ((*it)->current()) { ++it; continue; }
      expired.push_back((*it)->command.session.sessionUUID);
      (*it)->revoke(); it = state->leases.erase(it);
    }
    for (auto session : expired) if (onSessionClosed) onSessionClosed(session);
  }
  bool applyCommand(const ProdigyCousinSessionLocalCommand& command)
  {
    if (!prodigyCousinSessionLocalCommandValid(command) || state->containerUUID == 0) return false;
    if (command.kind == ProdigyCousinSessionLocalKind::reject) return true;
    const auto& session = command.session;
    if ((command.localHalf == CousinRouteHalf::source ? session.sourceContainerUUID :
         session.destination.containerUUID) != state->containerUUID) return false;
    expire();
    auto found = std::find_if(state->leases.begin(), state->leases.end(), [&](const auto& lease) {
      return lease->command.session.sessionUUID == session.sessionUUID;
    });
    if (command.kind == ProdigyCousinSessionLocalKind::revoke) {
      if (found == state->leases.end()) return true;
      if ((*found)->command.localHalf != command.localHalf ||
          !prodigyCousinSessionExact((*found)->command.session, session)) return false;
      (*found)->revoke(); state->leases.erase(found);
      if (onSessionClosed) onSessionClosed(session.sessionUUID);
      return true;
    }
    if (found != state->leases.end()) {
      auto& lease = **found;
      if (command.kind != ProdigyCousinSessionLocalKind::renew || !lease.current() ||
          lease.command.leaseGeneration == UINT64_MAX || command.leaseGeneration != lease.command.leaseGeneration + 1 ||
          command.localHalf != lease.command.localHalf || !prodigyCousinSessionExact(lease.command.session, session) ||
          command.canonicalContext != lease.command.canonicalContext ||
          CRYPTO_memcmp(command.psk.data(), lease.command.psk.data(), command.psk.size()) != 0) return false;
      lease.command.leaseGeneration = command.leaseGeneration;
      lease.deadline = Time::msSinceBoot() + command.validForMs;
      return true;
    }
    if (command.kind == ProdigyCousinSessionLocalKind::renew || command.leaseGeneration != 1 ||
        state->leases.size() >= ProdigyCousinSessionMaximumRecords) return false;
    if (command.localHalf == CousinRouteHalf::source) {
      for (const auto& lease : state->leases)
        if (lease->command.localHalf == CousinRouteHalf::source &&
            lease->command.session.sourceBindingNonce == session.sourceBindingNonce) return false;
    }
    auto lease = std::make_shared<ProdigyCousinSessionLease>();
    lease->command = command; lease->deadline = Time::msSinceBoot() + command.validForMs;
    state->leases.push_back(std::move(lease));
    return true;
  }

  // Call before registering the descriptor or asking Ring to connect. The
  // allocated Whitehole source tuple is part of both admission and the KDF.
  bool prepareOutbound(uint128_t sessionUUID, ProdigyCousinSessionStream& stream)
  {
    expire();
    if (stream.isFixedFile || stream.transportEncryptionEnabled()) return false;
    auto found = std::find_if(state->leases.begin(), state->leases.end(), [&](const auto& lease) {
      return lease->command.session.sessionUUID == sessionUUID;
    });
    if (found == state->leases.end() || (*found)->claimed ||
        (*found)->command.localHalf != CousinRouteHalf::source) return false;
    auto lease = *found;
    const auto& session = lease->command.session;
    stream.setIPVersion(AF_INET6); stream.setNonBlocking();
    stream.setSaddr(session.sourceAddress, session.sourceTCPPort);
    stream.setDaddr(session.destination.publicAddress, session.destination.publicTCPPort);
    if (stream.fd < 0 || !Ring::bindSourceAddressBeforeFixedFileInstall(&stream)) return false;
    lease->claimed = true; stream.lease = lease; stream.resolving = false;
    std::weak_ptr<ProdigyCousinSessionLease> weak = lease;
    return stream.beginTransportAEGISWithPrelude(false, state->containerUUID,
        prelude(sessionUUID, CousinRouteHalf::source),
        [weak](const String& peer, std::array<uint8_t, 32>& key, String& context, uint128_t& peerUUID) {
          auto lease = weak.lock();
          if (!lease || !lease->current() ||
              peer != prelude(lease->command.session.sessionUUID, CousinRouteHalf::destination)) return false;
          key = lease->command.psk; context = lease->command.canonicalContext;
          peerUUID = lease->command.session.destination.containerUUID; return true;
        });
  }

  // observedPeer must be the accepted peer returned by the socket/Ring owner,
  // never a value decoded from the peer's public lookup hint.
  bool prepareInbound(ProdigyCousinSessionStream& stream, const sockaddr_storage& observedPeer, socklen_t length)
  {
    expire();
    if (state->containerUUID == 0 || stream.transportEncryptionEnabled() ||
        length < sizeof(sockaddr_in6) || observedPeer.ss_family != AF_INET6) return false;
    stream.resolving = true; stream.pendingDeadline = Time::msSinceBoot() + ProdigyCousinSessionPendingMs;
    std::weak_ptr<State> weak = state;
    return stream.beginTransportAEGISWithDeferredServerPrelude(state->containerUUID,
        [weak, &stream, observedPeer, length](const String& peer, String& local, std::array<uint8_t, 32>& key,
                                           String& context, uint128_t& peerUUID) {
          auto owner = weak.lock(); uint128_t sessionUUID = 0;
          if (!owner || !readPrelude(peer, sessionUUID)) return false;
          for (auto& lease : owner->leases) {
            if (lease->command.session.sessionUUID != sessionUUID) continue;
            if (!lease->current() || lease->claimed || lease->command.localHalf != CousinRouteHalf::destination ||
                !observedSourceMatches(observedPeer, length, lease->command.session)) return false;
            lease->claimed = true; stream.lease = lease; stream.resolving = false;
            key = lease->command.psk; context = lease->command.canonicalContext;
            peerUUID = lease->command.session.sourceContainerUUID;
            local = prelude(sessionUUID, CousinRouteHalf::destination); return true;
          }
          return false;
        });
  }
};
