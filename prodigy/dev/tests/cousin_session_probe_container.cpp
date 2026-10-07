// Native COUSIN session probe.  It deliberately consumes only the private
// NeuronHub command surface and the allocated container network projection.
#include <networking/includes.h>
#include <services/bitsery.h>
#include <services/time.h>
#include <networking/ip.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/pool.h>
#include <networking/ring.h>
#include <networking/time.h>
#include <services/filesystem.h>
#include <prodigy/neuron.hub.h>
#include <prodigy/cousin.session.client.h>

#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <memory>
#include <sys/socket.h>
#include <unistd.h>

namespace {
constexpr auto probeConfigPath = "/cousin-probe-config"_ctv;
constexpr auto probePayload = "COUSIN-native-session-probe-v1"_ctv;
constexpr uint32_t tickMs = 20;
constexpr uint32_t requestRetryMs = 5000;
constexpr uint32_t maximumRequests = 64;
constexpr int64_t maximumDurationMs = 180000;
constexpr uint32_t echoIntervalMs = 2000;
constexpr int64_t maximumSessionDurationMs = 30000;

bool parseHex128(const String& text, uint128_t& value)
{
  value = 0;
  if (text.empty() || text.size() > 32) return false;
  for (uint8_t byte : text) {
    uint8_t digit = 0;
    if (byte >= '0' && byte <= '9') digit = byte - '0';
    else if (byte >= 'a' && byte <= 'f') digit = byte - 'a' + 10;
    else if (byte >= 'A' && byte <= 'F') digit = byte - 'A' + 10;
    else return false;
    value = (value << 4) | digit;
  }
  return value != 0;
}

bool readPermissionUUID(uint128_t& permissionUUID)
{
  String value = {};
  Filesystem::openReadAtClose(-1, probeConfigPath, value);
  while (!value.empty() && (value[value.size() - 1] == '\n' || value[value.size() - 1] == '\r')) value.resize(value.size() - 1);
  return parseHex128(value, permissionUUID);
}

bool validSourceWhitehole(const Whitehole& value)
{
  return whiteholeDeclarationValid(value) && value.hasAddress && value.address.is6 && !value.address.isNull() &&
      value.transport == ExternalAddressTransport::tcp && value.sourcePort != 0 && value.bindingNonce != 0;
}
} // namespace

class CousinSessionProbeContainer final : public NeuronHubDispatch, public TimeoutDispatcher {
  std::unique_ptr<NeuronHub> hub;
  std::unique_ptr<ProdigyCousinSessionClient> sessions;
  TimeoutPacket tick = {};
  bool tickQueued = false;
  bool source = false;
  uint128_t permissionUUID = 0;
  const Whitehole *sourceWhitehole = nullptr;
  uint128_t nextRequestUUID = 1;
  uint128_t activeRequestUUID = 0;
  uint128_t activeSessionUUID = 0;
  uint128_t inboundSessionUUID = 0;
  bool applyingRevocation = false;
  uint64_t outboundLeaseGeneration = 0;
  bool outboundCloseNotified = false;
  int listener = -1;
  std::unique_ptr<ProdigyCousinSessionStream> outbound;
  std::unique_ptr<ProdigyCousinSessionStream> inbound;
  bool payloadQueued = false;
  uint32_t echoRound = 0;
  uint32_t requestAttempts = 0;
  int64_t startedAtMs = 0;
  int64_t nextRequestAtMs = 0;
  int64_t nextEchoAtMs = 0;
  int64_t outboundStartedAtMs = 0;
  bool lifecycleProfile = false;
  int64_t firstPayloadAtMs = 0;
  int64_t nextScaleMetricAtMs = 0;

  void closeStream(std::unique_ptr<ProdigyCousinSessionStream>& stream)
  {
    if (!stream) return;
    if (stream->fd >= 0) ::close(stream->fd);
    stream.reset();
    payloadQueued = false;
  }

  void failClosed(const char *reason)
  {
    std::printf("cousin_session_probe.fail %s\n", reason);
    closeStream(outbound); closeStream(inbound);
  }

  void armTick()
  {
    if (tickQueued) return;
    tick.clear(); tick.dispatcher = this; tick.setTimeoutMs(tickMs);
    tickQueued = true; Ring::queueTimeout(&tick);
  }

  bool drive(ProdigyCousinSessionStream& stream)
  {
    if (!stream.prepareTransportTLSSend()) return false;
    if (stream.encryptedBytesToSend()) {
      ssize_t sent = ::send(stream.fd, stream.pBytesToSend(), stream.encryptedBytesToSend(), MSG_NOSIGNAL);
      if (sent > 0) stream.consumeSentBytes(uint32_t(sent), false);
      else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
    }
    if (!stream.rBuffer.need(8192)) return false;
    ssize_t received = ::recv(stream.fd, stream.rBuffer.pTail(), 8192, 0);
    if (received > 0) return stream.decryptTransportTLS(uint32_t(received));
    return received == 0 ? false : errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
  }

  bool startListener(const ProdigyCousinSessionLocalCommand& command)
  {
    if (listener >= 0) return true;
    listener = ::socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    int enabled = 1;
    sockaddr_in6 address = {}; address.sin6_family = AF_INET6;
    address.sin6_port = htons(command.session.destination.servicePort);
    return listener >= 0 && ::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) == 0 &&
        ::bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0 && ::listen(listener, 16) == 0;
  }

  void acceptInbound()
  {
    if (listener < 0 || inbound) return;
    sockaddr_storage peer = {}; socklen_t peerLength = sizeof(peer);
    int accepted = ::accept4(listener, reinterpret_cast<sockaddr *>(&peer), &peerLength, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (accepted < 0) return;
    auto stream = std::make_unique<ProdigyCousinSessionStream>();
    stream->fd = accepted; stream->isNonBlocking = true; stream->rBuffer.reserve(8192); stream->wBuffer.reserve(8192);
    if (!sessions->prepareInbound(*stream, peer, peerLength)) { ::close(accepted); return; }
    inbound = std::move(stream);
  }

  void notifyOutboundFailure()
  {
    if (outbound && !outboundCloseNotified && hub && activeSessionUUID != 0 && outboundLeaseGeneration != 0) {
      outboundCloseNotified = true;
      (void)hub->closeCousinSession(activeSessionUUID, outboundLeaseGeneration);
    }
    if (outbound) (void)outbound->abortOwnedSocket();
    closeStream(outbound); activeSessionUUID = 0;
  }

  void requestIfNeeded()
  {
    const int64_t now = Time::msSinceBoot();
    if (!source || outbound || !sourceWhitehole || permissionUUID == 0 || now < nextRequestAtMs ||
        requestAttempts >= maximumRequests || now - startedAtMs > (lifecycleProfile ? 360000 : maximumDurationMs)) return;
    ProdigyCousinSessionRequest request = {};
    request.requestUUID = ++nextRequestUUID;
    request.permissionUUID = permissionUUID;
    request.bindingNonce = sourceWhitehole->bindingNonce;
    request.slot = 0; // First probe profile has one configured stateful shard owner.
    ++requestAttempts;
    nextRequestAtMs = now + requestRetryMs;
    char sourceAddress[INET6_ADDRSTRLEN] = {};
    if (!::inet_ntop(AF_INET6, sourceWhitehole->address.v6, sourceAddress, sizeof(sourceAddress))) return;
    std::printf("cousin_session_probe.request source=%s sourcePort=%u request=%016llx%016llx attempt=%u monotonicMs=%lld wallMs=%lld\n",
               sourceAddress, unsigned(sourceWhitehole->sourcePort),
               (unsigned long long)(request.requestUUID >> 64), (unsigned long long)request.requestUUID,
               unsigned(requestAttempts), (long long)now, (long long)Time::now<TimeResolution::ms>());
    if (!hub->requestCousinSession(request)) failClosed("request_enqueue");
  }

  bool openOutbound(const ProdigyCousinSessionLocalCommand& command)
  {
    if (!source || outbound || command.kind != ProdigyCousinSessionLocalKind::activate) return false;
    auto stream = std::make_unique<ProdigyCousinSessionStream>();
    stream->rBuffer.reserve(8192); stream->wBuffer.reserve(8192);
    errno = 0;
    if (!sessions->prepareOutbound(command.session.sessionUUID, *stream)) {
      std::printf("cousin_session_probe.transportFailure operation=prepareOutbound errno=%d monotonicMs=%lld\n",
                  errno, (long long)Time::msSinceBoot());
      if (stream->fd >= 0) ::close(stream->fd);
      return false;
    }
    int result = ::connect(stream->fd, stream->daddr<sockaddr>(), stream->daddrLen);
    if (result != 0 && errno != EINPROGRESS) {
      std::printf("cousin_session_probe.transportFailure operation=connect errno=%d monotonicMs=%lld\n",
                  errno, (long long)Time::msSinceBoot());
      ::close(stream->fd); stream->fd = -1; return false;
    }
    outbound = std::move(stream); payloadQueued = false;
    activeRequestUUID = command.requestUUID; activeSessionUUID = command.session.sessionUUID;
    outboundLeaseGeneration = command.leaseGeneration;
    outboundCloseNotified = false; nextEchoAtMs = Time::msSinceBoot();
    outboundStartedAtMs = nextEchoAtMs;
    std::printf("cousin_session_probe.activate request=%016llx%016llx session=%016llx%016llx generation=%llu monotonicMs=%lld\n",
               (unsigned long long)(command.requestUUID >> 64), (unsigned long long)command.requestUUID,
               (unsigned long long)(command.session.sessionUUID >> 64), (unsigned long long)command.session.sessionUUID,
               (unsigned long long)command.leaseGeneration, (long long)nextEchoAtMs);
    std::printf("cousin_session_probe.binding session=%016llx%016llx sourceGroups=%u destinationGroups=%u sourceGroup=%u destinationGroup=%u slot=%u destination=%016llx%016llx monotonicMs=%lld\n",
               (unsigned long long)(command.session.sessionUUID >> 64), (unsigned long long)command.session.sessionUUID,
               unsigned(command.session.sourceShardGroups), unsigned(command.session.destination.shardGroups),
               unsigned(command.session.sourceShardGroup), unsigned(command.session.destination.shardGroup),
               unsigned(command.session.slot),
               (unsigned long long)(command.session.destination.containerUUID >> 64),
               (unsigned long long)command.session.destination.containerUUID, (long long)nextEchoAtMs);
    return true;
  }

public:
  void beginShutdown() override { failClosed("shutdown"); }

  void resourceDelta(uint16_t cores, uint32_t memoryMB, uint32_t storageMB, bool downscale, uint32_t) override
  {
    // This fixed-buffer probe accepts the declared memory-only growth through
    // the ordinary application ACK. Neuron owns the resource change itself.
    const bool accepted = lifecycleProfile && !downscale && cores == 1 && memoryMB == 384 && storageMB == 64;
    hub->acknowledgeResourceDelta(accepted);
    std::printf("cousin_session_probe.resources uuid=%016llx%016llx cores=%u memoryMB=%u storageMB=%u downscale=%u accepted=%u monotonicMs=%lld\n",
               (unsigned long long)(hub->parameters.uuid >> 64), (unsigned long long)hub->parameters.uuid,
               unsigned(cores), unsigned(memoryMB), unsigned(storageMB), unsigned(downscale), unsigned(accepted),
               (long long)Time::msSinceBoot());
  }

  bool cousinSessionCommand(const ProdigyCousinSessionLocalCommand& command) override
  {
    if (!sessions) return false;
    applyingRevocation = command.kind == ProdigyCousinSessionLocalKind::revoke;
    const bool applied = sessions->applyCommand(command);
    applyingRevocation = false;
    if (!applied) return false;
    const int64_t now = Time::msSinceBoot();
    if (command.kind == ProdigyCousinSessionLocalKind::renew) {
      std::printf("cousin_session_probe.renew request=%016llx%016llx session=%016llx%016llx generation=%llu monotonicMs=%lld\n",
                 (unsigned long long)(command.requestUUID >> 64), (unsigned long long)command.requestUUID,
                 (unsigned long long)(command.session.sessionUUID >> 64), (unsigned long long)command.session.sessionUUID,
                 (unsigned long long)command.leaseGeneration, (long long)now);
    } else if (command.kind == ProdigyCousinSessionLocalKind::revoke) {
      std::printf("cousin_session_probe.revoke request=%016llx%016llx session=%016llx%016llx generation=%llu monotonicMs=%lld\n",
                 (unsigned long long)(command.requestUUID >> 64), (unsigned long long)command.requestUUID,
                 (unsigned long long)(command.session.sessionUUID >> 64), (unsigned long long)command.session.sessionUUID,
                 (unsigned long long)command.leaseGeneration, (long long)now);
    } else if (command.kind == ProdigyCousinSessionLocalKind::reject) {
      std::printf("cousin_session_probe.reject request=%016llx%016llx generation=%llu monotonicMs=%lld\n",
                 (unsigned long long)(command.requestUUID >> 64), (unsigned long long)command.requestUUID,
                 (unsigned long long)command.leaseGeneration, (long long)now);
    }
    if (command.localHalf == CousinRouteHalf::source && activeSessionUUID == command.session.sessionUUID)
      outboundLeaseGeneration = command.leaseGeneration;
    if (command.kind == ProdigyCousinSessionLocalKind::revoke) return true;
    if (command.kind == ProdigyCousinSessionLocalKind::install && command.localHalf == CousinRouteHalf::destination)
      return startListener(command);
    if (command.kind == ProdigyCousinSessionLocalKind::activate && command.localHalf == CousinRouteHalf::source)
      return openOutbound(command);
    return true;
  }

  void dispatchTimeout(TimeoutPacket *packet) override
  {
    if (packet != &tick) return;
    tickQueued = false;
    if (!sessions) return;
    sessions->expire();
    acceptInbound();
    if (outbound && !drive(*outbound)) notifyOutboundFailure();
    if (inbound && !drive(*inbound)) closeStream(inbound);
    if (inbound) inboundSessionUUID = inbound->sessionUUID();
    const int64_t now = Time::msSinceBoot();
    // Keep each connection attempt bounded and exercise fresh requests after
    // setup completes, including when an earlier request raced the offline marker.
    if (outbound && now - outboundStartedAtMs >= maximumSessionDurationMs) notifyOutboundFailure();
    if (outbound && outbound->isTransportNegotiated()) {
      if (!payloadQueued && now >= nextEchoAtMs) { outbound->wBuffer.append(probePayload); payloadQueued = true; }
      if (payloadQueued && outbound->rBuffer.size() == probePayload.size() &&
          std::memcmp(outbound->rBuffer.data(), probePayload.data(), probePayload.size()) == 0) {
        outbound->rBuffer.clear(); payloadQueued = false; nextEchoAtMs = now + echoIntervalMs; ++echoRound;
        std::printf("cousin_session_probe.round request=%016llx%016llx peer=%016llx%016llx session=%016llx%016llx round=%u monotonicMs=%lld wallMs=%lld payload=exact\n",
                   (unsigned long long)(activeRequestUUID >> 64), (unsigned long long)activeRequestUUID,
                   (unsigned long long)(outbound->tlsPeerUUID >> 64), (unsigned long long)outbound->tlsPeerUUID,
                   (unsigned long long)(outbound->sessionUUID() >> 64), (unsigned long long)outbound->sessionUUID(),
                   unsigned(echoRound), (long long)now, (long long)Time::now<TimeResolution::ms>());
      }
    }
    if (inbound && inbound->isTransportNegotiated() && inbound->rBuffer.size() == probePayload.size() &&
        std::memcmp(inbound->rBuffer.data(), probePayload.data(), probePayload.size()) == 0) {
      inbound->rBuffer.clear(); inbound->wBuffer.append(probePayload);
      if (firstPayloadAtMs == 0) firstPayloadAtMs = now;
      std::printf("cousin_session_probe.echo peer=%016llx%016llx session=%016llx%016llx payload=exact\n",
                 (unsigned long long)(inbound->tlsPeerUUID >> 64), (unsigned long long)inbound->tlsPeerUUID,
                 (unsigned long long)(inbound->sessionUUID() >> 64), (unsigned long long)inbound->sessionUUID());
    }
    if (lifecycleProfile && !source && firstPayloadAtMs != 0 &&
        now >= firstPayloadAtMs + 60000 && now >= nextScaleMetricAtMs) {
      // An application metric exercises the installed ordinary local scaler,
      // including while the external pair boundary is partitioned.
      hub->publishStatistic(ProdigyMetrics::metricKeyForName("cousin.probe.scale"_ctv), uint64_t(1));
      nextScaleMetricAtMs = now + 1000;
      std::printf("cousin_session_probe.scaleMetric monotonicMs=%lld\n", (long long)now);
    }
    requestIfNeeded(); armTick();
  }

  void prepare(int argc, char **argv)
  {
    Ring::createRing(128, 256, 512, 128, -1, -1, 0);
    hub = std::make_unique<NeuronHub>(this); hub->fillFromMainArgs(argc, argv); hub->afterRing();
    uint32_t matches = 0;
    for (const Whitehole& whitehole : hub->parameters.whiteholes)
      if (validSourceWhitehole(whitehole)) { sourceWhitehole = &whitehole; ++matches; }
    if (matches > 1) { failClosed("ambiguous_source_whiteholes"); std::exit(EXIT_FAILURE); }
    source = matches == 1;
    const char *lifecycle = std::getenv("COUSIN_PROBE_LIFECYCLE");
    lifecycleProfile = lifecycle && std::strcmp(lifecycle, "1") == 0;
    if (source && !readPermissionUUID(permissionUUID)) { failClosed("source_config"); std::exit(EXIT_FAILURE); }
    startedAtMs = Time::msSinceBoot();
    sessions = std::make_unique<ProdigyCousinSessionClient>(hub->parameters.uuid);
    sessions->onSessionClosed = [this](uint128_t sessionUUID) {
      std::printf("cousin_session_probe.closed session=%016llx%016llx monotonicMs=%lld\n",
                 (unsigned long long)(sessionUUID >> 64), (unsigned long long)sessionUUID,
                 (long long)Time::msSinceBoot());
      if (outbound && activeSessionUUID == sessionUUID) {
        if (!applyingRevocation) notifyOutboundFailure();
        else {
          (void)outbound->abortOwnedSocket();
          closeStream(outbound); activeSessionUUID = 0;
        }
      }
      if (inbound && inboundSessionUUID == sessionUUID) closeStream(inbound);
    };
    hub->signalReady(); hub->signalRuntimeReady(); armTick();
    std::printf("cousin_session_probe.ready uuid=%016llx%016llx deployment=%llu source=%u group=%u workers=%u cores=%u memoryMB=%u storageMB=%u monotonicMs=%lld\n",
               (unsigned long long)(hub->parameters.uuid >> 64), (unsigned long long)hub->parameters.uuid,
               (unsigned long long)hub->parameters.deploymentID, unsigned(source),
               unsigned(hub->parameters.statefulTopology.shardGroup), unsigned(hub->parameters.statefulTopology.workerCount),
               unsigned(hub->parameters.nLogicalCores), unsigned(hub->parameters.memoryMB), unsigned(hub->parameters.storageMB),
               (long long)startedAtMs);
  }

  void start() { Ring::start(); }
  ~CousinSessionProbeContainer() { if (listener >= 0) ::close(listener); }
};

int main(int argc, char **argv)
{
  std::setvbuf(stdout, nullptr, _IOLBF, 0);
  CousinSessionProbeContainer app;
  app.prepare(argc, argv);
  app.start();
  return 0;
}
