#include <limits.h>
#include <networking/includes.h>
#include <services/debug.h>
#include <services/bitsery.h>
#include <services/crypto.h>
#include <services/filesystem.h>
#include <services/time.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/pool.h>
#include <networking/ring.h>
#include <prodigy/neuron.hub.h>
#include <prodigy/quic.cid.generator.h>

#include <algorithm>
#include <atomic>
#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <poll.h>
#include <picoquic.h>
#include <picoquic_internal.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include <openssl/pem.h>

namespace {
constexpr static const char *kEvidencePath = "/resumption_readiness_probe_evidence.log";
constexpr static const char *kBundledQuicCertPath = "/root/resumption_quic.cert.pem";
constexpr static const char *kBundledQuicKeyPath = "/root/resumption_quic.key.pem";
constexpr static uint64_t kQuicStreamID = 0;

struct ProbePicoquicTicketKey {
  uint8_t bytes[32] = {};
  size_t size = 0;
  uint64_t generation = 0;

  void clear(void)
  {
    OPENSSL_cleanse(bytes, sizeof(bytes));
    size = 0;
    generation = 0;
  }
};

void appendEvidence(const char *stage, const char *detail = nullptr)
{
  int fd = open(kEvidencePath, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
  if (fd < 0)
  {
    return;
  }

  if (stage != nullptr && *stage)
  {
    (void)write(fd, stage, std::strlen(stage));
  }
  if (detail != nullptr && *detail)
  {
    constexpr static char separator = ' ';
    (void)write(fd, &separator, 1);
    (void)write(fd, detail, std::strlen(detail));
  }

  constexpr static char newline = '\n';
  (void)write(fd, &newline, 1);
  close(fd);
}

bool bytesAllZero(const uint8_t *bytes, size_t size)
{
  return std::find_if(bytes, bytes + size, [](uint8_t byte) {
           return byte != 0;
         }) == bytes + size;
}

const TlsResumptionSnapshot *snapshotForWormhole(const CredentialBundle& bundle, const String& wormholeName)
{
  for (const TlsResumptionSnapshot& snapshot : bundle.tlsResumptionSnapshots)
  {
    if (snapshot.wormholeName.equal(wormholeName))
    {
      return &snapshot;
    }
  }

  return nullptr;
}

bool snapshotHasUsableKeyRing(const TlsResumptionSnapshot& snapshot)
{
  for (const TlsResumptionKeyEpoch& epoch : snapshot.keyRing)
  {
    if (epoch.generation != 0 &&
        bytesAllZero(epoch.keyID, sizeof(epoch.keyID)) == false &&
        bytesAllZero(epoch.masterSecret, sizeof(epoch.masterSecret)) == false &&
        epoch.acceptUntilMs > 0)
    {
      return true;
    }
  }

  return false;
}

int64_t tlsNowMs(void *)
{
  return Time::now<TimeResolution::ms>();
}

int tcpTlsServerNameCallback(SSL *ssl, int *, void *)
{
  (void)ssl;
  return SSL_TLSEXT_ERR_OK;
}

int selectTcpTlsAlpn(
    SSL *ssl,
    const unsigned char **out,
    unsigned char *outlen,
    const unsigned char *in,
    unsigned int inlen,
    void *arg)
{
  const String *expected = reinterpret_cast<const String *>(arg);
  (void)ssl;
  if (expected == nullptr || expected->size() == 0)
  {
    return SSL_TLSEXT_ERR_NOACK;
  }

  for (unsigned int offset = 0; offset < inlen;)
  {
    const unsigned int length = in[offset];
    offset += 1;
    if (length <= inlen - offset &&
        length == expected->size() &&
        std::memcmp(in + offset, expected->data(), expected->size()) == 0)
    {
      *out = in + offset;
      *outlen = static_cast<unsigned char>(length);
      return SSL_TLSEXT_ERR_OK;
    }

    offset += length;
  }

  return SSL_TLSEXT_ERR_NOACK;
}

bool selectPicoquicTicketKey(
    const ProdigyResumptionRegistry& registry,
    const String& wormholeName,
    ProbePicoquicTicketKey& key,
    std::string& failure)
{
  key.clear();
  const int64_t nowMs = tlsNowMs(nullptr);
  const TlsResumptionSnapshot *snapshot = registry.find(wormholeName);
  if (snapshot == nullptr)
  {
    failure = "picoquic_resumption_snapshot_missing";
    return false;
  }

  const TlsResumptionKeyEpoch *epoch = registry.currentIssueKey(wormholeName, nowMs);
  if (epoch == nullptr)
  {
    failure = "picoquic_issue_key_not_ready";
    return false;
  }

  String deriveFailure = {};
  if (prodigyTlsResumptionDeriveQuicTicketKey(*epoch, key.bytes, &deriveFailure) == false)
  {
    failure = deriveFailure.c_str();
    key.clear();
    return false;
  }

  key.size = sizeof(key.bytes);
  key.generation = snapshot->generation;
  failure.clear();
  return true;
}

socklen_t sockaddrLength(const sockaddr_storage& address)
{
  if (address.ss_family == AF_INET)
  {
    return sizeof(sockaddr_in);
  }
  if (address.ss_family == AF_INET6)
  {
    return sizeof(sockaddr_in6);
  }
  return sizeof(sockaddr_storage);
}

bool setNonBlocking(int fd)
{
  int flags = fcntl(fd, F_GETFL, 0);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

int openUdpSocket(uint16_t port, std::string& failure)
{
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
  {
    failure = "udp_socket_failed";
    return -1;
  }

  int enableReuse = 1;
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enableReuse, sizeof(enableReuse));
  sockaddr_in bindAddress = {};
  bindAddress.sin_family = AF_INET;
  bindAddress.sin_addr.s_addr = htonl(INADDR_ANY);
  bindAddress.sin_port = htons(port);
  if (bind(fd, reinterpret_cast<const sockaddr *>(&bindAddress), sizeof(bindAddress)) != 0 ||
      setNonBlocking(fd) == false)
  {
    failure = "udp_bind_failed";
    close(fd);
    return -1;
  }

  return fd;
}

void renderQuicCidHex(const ProdigyQuicCID& cid, std::string& output)
{
  constexpr static char digits[] = "0123456789abcdef";

  output.clear();
  output.reserve(size_t(cid.id_len) * 2);
  for (uint8_t index = 0; index < cid.id_len; index += 1)
  {
    output.push_back(digits[(cid.id[index] >> 4) & 0x0f]);
    output.push_back(digits[cid.id[index] & 0x0f]);
  }
}

int hexNibble(char ch)
{
  if (ch >= '0' && ch <= '9')
  {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f')
  {
    return 10 + ch - 'a';
  }
  if (ch >= 'A' && ch <= 'F')
  {
    return 10 + ch - 'A';
  }
  return -1;
}

bool parsePicoquicConnectionIDHex(const char *hex, picoquic_connection_id_t& cid)
{
  cid = {};
  if (hex == nullptr)
  {
    return true;
  }

  const size_t hexLen = std::strlen(hex);
  if ((hexLen & 1u) != 0 || hexLen / 2 > sizeof(cid.id))
  {
    return false;
  }

  cid.id_len = uint8_t(hexLen / 2);
  for (size_t index = 0; index < cid.id_len; index += 1)
  {
    const int hi = hexNibble(hex[index * 2]);
    const int lo = hexNibble(hex[index * 2 + 1]);
    if (hi < 0 || lo < 0)
    {
      cid = {};
      return false;
    }
    cid.id[index] = uint8_t((hi << 4) | lo);
  }

  return true;
}

template <class Done>
bool runPicoquicUdpLoop(
    picoquic_quic_t *quic,
    int fd,
    uint64_t maxDurationUs,
    Done done,
    std::string& failure)
{
  const uint64_t deadline = picoquic_current_time() + maxDurationUs;
  while (picoquic_current_time() < deadline)
  {
    if (done())
    {
      failure.clear();
      return true;
    }

    uint64_t now = picoquic_current_time();
    for (;;)
    {
      uint8_t receiveBuffer[PICOQUIC_MAX_PACKET_SIZE] = {};
      sockaddr_storage from = {};
      sockaddr_storage to = {};
      socklen_t fromLen = sizeof(from);
      socklen_t toLen = sizeof(to);
      (void)getsockname(fd, reinterpret_cast<sockaddr *>(&to), &toLen);
      ssize_t received = recvfrom(fd, receiveBuffer, sizeof(receiveBuffer), 0, reinterpret_cast<sockaddr *>(&from), &fromLen);
      if (received < 0)
      {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          break;
        }
        if (errno == EINTR)
        {
          continue;
        }
        failure = "udp_recv_failed";
        return false;
      }
      if (received > 0 &&
          picoquic_incoming_packet(
              quic,
              receiveBuffer,
              size_t(received),
              reinterpret_cast<sockaddr *>(&from),
              reinterpret_cast<sockaddr *>(&to),
              0,
              0,
              now) != 0)
      {
        failure = "picoquic_incoming_packet_failed";
        return false;
      }
    }

    for (uint32_t sendCount = 0; sendCount < 16; sendCount += 1)
    {
      uint8_t sendBuffer[PICOQUIC_MAX_PACKET_SIZE] = {};
      size_t sendLength = 0;
      sockaddr_storage to = {};
      sockaddr_storage from = {};
      int ifIndex = 0;
      picoquic_connection_id_t logCID = {};
      picoquic_cnx_t *lastConnection = nullptr;
      if (picoquic_prepare_next_packet(
              quic,
              now,
              sendBuffer,
              sizeof(sendBuffer),
              &sendLength,
              &to,
              &from,
              &ifIndex,
              &logCID,
              &lastConnection) != 0)
      {
        failure = "picoquic_prepare_next_packet_failed";
        return false;
      }
      if (sendLength == 0)
      {
        break;
      }

      const ssize_t sent = sendto(fd, sendBuffer, sendLength, 0, reinterpret_cast<sockaddr *>(&to), sockaddrLength(to));
      const int sendErrno = sent < 0 ? errno : 0;

      if (sent < 0 &&
          sendErrno != EAGAIN &&
          sendErrno != EWOULDBLOCK &&
          sendErrno != EINTR)
      {
        failure = "udp_send_failed";
        return false;
      }
    }

    if (done())
    {
      failure.clear();
      return true;
    }

    now = picoquic_current_time();
    uint64_t wake = picoquic_get_next_wake_time(quic, now);
    int timeoutMs = 10;
    if (wake > now)
    {
      uint64_t deltaMs = (wake - now) / 1000;
      if (deltaMs < uint64_t(timeoutMs))
      {
        timeoutMs = int(deltaMs);
      }
    }

    pollfd descriptor = {};
    descriptor.fd = fd;
    descriptor.events = POLLIN;
    (void)poll(&descriptor, 1, timeoutMs);
  }

  failure = "picoquic_udp_loop_timeout";
  return false;
}
} // namespace

class ResumptionReadinessProbeContainer final : public NeuronHubDispatch {
private:

  std::unique_ptr<NeuronHub> neuronHub;
  std::atomic<bool> stopRequested {false};
  std::mutex probeTlsResumptionMutex;
  ProdigyResumptionRegistry probeTlsResumptionRegistry;
  CredentialBundle probeCredentialBundle;
  std::thread tcpTlsThread;
  std::thread quicThread;
  int tcpTlsFD = -1;
  SSL_CTX *tcpTlsContext = nullptr;
  ProdigyOpenSSLTlsTicketContext tcpTlsTicketContext = {};
  ProdigyOpenSSLTlsTicketBinding tcpTlsBindingTemplate = {};
  String tcpTlsExpectedAlpn;
  String quicWormholeName;
  String quicSni;
  String quicAlpn;
  uint16_t quicContainerPort = 0;
  ProdigyQuicCidEncryptor quicCidEncryptor;
  sockaddr_storage quicCidDestination = {};
  uint8_t quicCidContainerID[5] = {};
  uint8_t quicCidActiveKeyIndex = 0;
  uint32_t quicCidNonceCursor = 1;
  bool quicCidGeneratorReady = false;

  struct QuicConnectionState {
    bool canRespond = false;
    bool responded = false;
    uint64_t receivedBytes = 0;
    uint64_t streamID = 0;
  };

  bytell_hash_map<picoquic_cnx_t *, QuicConnectionState> quicConnections;

  bool validateWormholeSnapshot(const Wormhole& wormhole, uint32_t& tcpCount, uint32_t& quicCount, std::string& failure)
  {
    if (wormhole.hasTlsResumptionConfig == false)
    {
      return true;
    }

    if (wormhole.name.size() == 0)
    {
      failure = "resumption_wormhole_missing_name";
      return false;
    }
    if (neuronHub->parameters.hasCredentialBundle == false)
    {
      failure = "resumption_wormhole_missing_credential_bundle";
      return false;
    }

    const TlsResumptionSnapshot *snapshot = snapshotForWormhole(neuronHub->parameters.credentialBundle, wormhole.name);
    if (snapshot == nullptr)
    {
      failure = "resumption_snapshot_missing";
      return false;
    }
    if (snapshot->wormholeName.equal(wormhole.name) == false ||
        snapshotHasUsableKeyRing(*snapshot) == false)
    {
      failure = "resumption_snapshot_mismatch";
      return false;
    }

    if (wormholeSupportsTlsResumption(wormhole) == false)
    {
      failure = "resumption_snapshot_protocol_mismatch";
      return false;
    }

    const TlsResumptionSnapshot *registrySnapshot = neuronHub->tlsResumptionRegistry.find(snapshot->wormholeName);
    if (registrySnapshot == nullptr || registrySnapshot->generation != snapshot->generation)
    {
      failure = "resumption_registry_missing_snapshot";
      return false;
    }

    if (wormhole.layer4 == IPPROTO_TCP)
    {
      tcpCount += 1;
    }
    else
    {
      quicCount += 1;
    }

    return true;
  }

  bool validateResumptionReadiness(std::string& failure)
  {
    if (!neuronHub)
    {
      failure = "missing_neuron_hub";
      return false;
    }

    uint32_t tcpCount = 0;
    uint32_t quicCount = 0;
    for (const Wormhole& wormhole : neuronHub->parameters.wormholes)
    {
      if (validateWormholeSnapshot(wormhole, tcpCount, quicCount, failure) == false)
      {
        return false;
      }
    }

    if (tcpCount == 0)
    {
      failure = "missing_tcp_tls_resumption_wormhole";
      return false;
    }
    if (quicCount == 0)
    {
      failure = "missing_udp_quic_resumption_wormhole";
      return false;
    }

    char detail[96] = {};
    std::snprintf(detail, sizeof(detail), "tcp=%u quic=%u", unsigned(tcpCount), unsigned(quicCount));
    appendEvidence("probe.all_ok", detail);
    basics_log("probe.all_ok %s\n", detail);
    return true;
  }

  const Wormhole *findTcpTlsResumptionWormhole(void) const
  {
    if (!neuronHub)
    {
      return nullptr;
    }

    for (const Wormhole& wormhole : neuronHub->parameters.wormholes)
    {
      if (wormhole.hasTlsResumptionConfig &&
          wormhole.layer4 == IPPROTO_TCP)
      {
        return &wormhole;
      }
    }

    return nullptr;
  }

  const Wormhole *findQuicResumptionWormhole(void) const
  {
    if (!neuronHub)
    {
      return nullptr;
    }

    for (const Wormhole& wormhole : neuronHub->parameters.wormholes)
    {
      if (wormhole.hasTlsResumptionConfig &&
          wormhole.layer4 == IPPROTO_UDP &&
          wormhole.isQuic)
      {
        return &wormhole;
      }
    }

    return nullptr;
  }

  bool configureTcpTlsContext(const Wormhole& wormhole, std::string& failure)
  {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == nullptr)
    {
      failure = "failed_to_allocate_tcp_tls_context";
      return false;
    }

    const bool configured =
        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1 &&
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1 &&
        SSL_CTX_use_certificate_file(ctx, kBundledQuicCertPath, SSL_FILETYPE_PEM) == 1 &&
        SSL_CTX_use_PrivateKey_file(ctx, kBundledQuicKeyPath, SSL_FILETYPE_PEM) == 1 &&
        SSL_CTX_check_private_key(ctx) == 1;
    if (configured == false)
    {
      SSL_CTX_free(ctx);
      failure = "failed_to_configure_tcp_tls_certificate";
      return false;
    }

    static const unsigned char sessionIDContext[] = "prodigy-resumption-readiness-tcp";
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_num_tickets(ctx, 1);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    if (SSL_CTX_set_session_id_context(ctx, sessionIDContext, sizeof(sessionIDContext) - 1) != 1)
    {
      SSL_CTX_free(ctx);
      failure = "failed_to_configure_tcp_tls_session_context";
      return false;
    }

    tcpTlsExpectedAlpn = wormhole.tlsResumption.alpns.size() > 0 ? wormhole.tlsResumption.alpns[0] : String();
    SSL_CTX_set_tlsext_servername_callback(ctx, tcpTlsServerNameCallback);
    SSL_CTX_set_alpn_select_cb(ctx, selectTcpTlsAlpn, &tcpTlsExpectedAlpn);

    tcpTlsTicketContext = {};
    tcpTlsTicketContext.registry = &probeTlsResumptionRegistry;
    tcpTlsTicketContext.nowMsCallback = tlsNowMs;
    tcpTlsTicketContext.renewBeforeMs = 30'000;
    String tlsFailure = {};
    if (prodigyInstallOpenSSLTlsResumptionTicketKeyCallback(ctx, &tcpTlsTicketContext, &tlsFailure) == false)
    {
      SSL_CTX_free(ctx);
      failure = tlsFailure.c_str();
      return false;
    }

    tcpTlsBindingTemplate = {};
    tcpTlsBindingTemplate.wormholeName = wormhole.name;

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
      SSL_CTX_free(ctx);
      failure = "tcp_tls_socket_failed";
      return false;
    }

    int enableReuse = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enableReuse, sizeof(enableReuse));
    sockaddr_in bindAddress = {};
    bindAddress.sin_family = AF_INET;
    bindAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    bindAddress.sin_port = htons(wormhole.containerPort);
    if (bind(fd, reinterpret_cast<const sockaddr *>(&bindAddress), sizeof(bindAddress)) != 0 ||
        listen(fd, 32) != 0)
    {
      close(fd);
      SSL_CTX_free(ctx);
      failure = "tcp_tls_bind_or_listen_failed";
      return false;
    }

    tcpTlsContext = ctx;
    tcpTlsFD = fd;

    char detail[256] = {};
    std::snprintf(detail,
                  sizeof(detail),
                  "%.*s containerPort=%u",
                  int(wormhole.name.size()),
                  reinterpret_cast<const char *>(wormhole.name.data()),
                  unsigned(wormhole.containerPort));
    basics_log("probe.tcp_tls.listen %s\n", detail);
    return true;
  }

  bool prepareTcpTlsServer(std::string& failure)
  {
    const Wormhole *wormhole = findTcpTlsResumptionWormhole();
    if (wormhole == nullptr)
    {
      failure = "tcp_tls_wormhole_missing";
      return false;
    }

    if (configureTcpTlsContext(*wormhole, failure) == false)
    {
      return false;
    }

    tcpTlsThread = std::thread([this]() {
      serveTcpTls();
    });
    return true;
  }

  bool preparePicoquicServer(std::string& failure)
  {
    const Wormhole *wormhole = findQuicResumptionWormhole();
    if (wormhole == nullptr)
    {
      failure = "picoquic_wormhole_missing";
      return false;
    }

    quicWormholeName = wormhole->name;
    quicSni = wormhole->tlsResumption.sniNames.size() > 0 ? wormhole->tlsResumption.sniNames[0] : String();
    quicAlpn = wormhole->tlsResumption.alpns.size() > 0 ? wormhole->tlsResumption.alpns[0] : String();
    quicContainerPort = wormhole->containerPort;
    if (appendPicoquicClientRoutingCid(*wormhole, failure) == false)
    {
      return false;
    }

    quicThread = std::thread([this]() {
      servePicoquic();
    });
    return true;
  }

  bool appendPicoquicClientRoutingCid(const Wormhole& wormhole, std::string& failure)
  {
    quicCidGeneratorReady = false;
    quicCidNonceCursor = 1;

    if (wormhole.hasQuicCidKeyState == false)
    {
      failure = "picoquic_wormhole_missing_cid_key_state";
      return false;
    }
    if (wormhole.externalAddress.is6 || wormhole.externalPort == 0)
    {
      failure = "picoquic_wormhole_must_be_ipv4";
      return false;
    }
    if (neuronHub->parameters.private6.network.is6 == false)
    {
      failure = "picoquic_container_private6_missing";
      return false;
    }

    uint8_t containerID[5] = {};
    memcpy(containerID, neuronHub->parameters.private6.network.v6 + 11, sizeof(containerID));

    sockaddr_in destination = {};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(wormhole.externalPort);
    memcpy(&destination.sin_addr.s_addr, &wormhole.externalAddress.v4, sizeof(destination.sin_addr.s_addr));

    const uint8_t activeKeyIndex = wormhole.quicCidKeyState.activeKeyIndex & 0x01;
    uint8_t key[16] = {};
    memcpy(key, &wormhole.quicCidKeyState.keyMaterialByIndex[activeKeyIndex], sizeof(key));

    if (quicCidEncryptor.setKey(key) == false)
    {
      OPENSSL_cleanse(key, sizeof(key));
      failure = "picoquic_cid_cipher_init_failed";
      return false;
    }
    OPENSSL_cleanse(key, sizeof(key));

    memcpy(quicCidContainerID, containerID, sizeof(quicCidContainerID));
    memcpy(&quicCidDestination, &destination, sizeof(destination));
    quicCidActiveKeyIndex = activeKeyIndex;
    quicCidGeneratorReady = true;

    ProdigyQuicCID cid = generatePicoquicRoutingCid();
    if (cid.id_len == 0)
    {
      quicCidGeneratorReady = false;
      failure = "picoquic_cid_generation_failed";
      return false;
    }

    std::string cidHex;
    renderQuicCidHex(cid, cidHex);
    appendEvidence("probe.quic.cid", cidHex.c_str());
    basics_log("probe.quic.cid %s\n", cidHex.c_str());
    return true;
  }

  ProdigyQuicCID generatePicoquicRoutingCid(void)
  {
    if (quicCidGeneratorReady == false)
    {
      return {};
    }

    return prodigyGenerateQuicCID(
        quicCidEncryptor,
        quicCidContainerID,
        &quicCidNonceCursor,
        reinterpret_cast<const sockaddr *>(&quicCidDestination),
        quicCidActiveKeyIndex);
  }

  static void picoquicConnectionIDCallback(
      picoquic_quic_t *,
      picoquic_connection_id_t,
      picoquic_connection_id_t,
      void *callbackCtx,
      picoquic_connection_id_t *returned)
  {
    ResumptionReadinessProbeContainer *self = static_cast<ResumptionReadinessProbeContainer *>(callbackCtx);
    if (self == nullptr || returned == nullptr)
    {
      return;
    }

    ProdigyQuicCID cid = self->generatePicoquicRoutingCid();
    if (cid.id_len == 0 || cid.id_len > sizeof(returned->id))
    {
      return;
    }

    returned->id_len = cid.id_len;
    memcpy(returned->id, cid.id, cid.id_len);
    if (cid.id_len < sizeof(returned->id))
    {
      memset(returned->id + cid.id_len, 0, sizeof(returned->id) - cid.id_len);
    }
  }

  void serveTcpTls(void)
  {
    while (stopRequested.load(std::memory_order_relaxed) == false)
    {
      pollfd descriptor = {};
      descriptor.fd = tcpTlsFD;
      descriptor.events = POLLIN;
      int ready = poll(&descriptor, 1, 500);
      if (ready < 0)
      {
        if (errno == EINTR)
        {
          continue;
        }
        return;
      }
      if (ready == 0 || (descriptor.revents & POLLIN) == 0)
      {
        continue;
      }

      sockaddr_in source = {};
      socklen_t sourceLen = sizeof(source);
      int accepted = accept4(tcpTlsFD, reinterpret_cast<sockaddr *>(&source), &sourceLen, SOCK_CLOEXEC);
      if (accepted < 0)
      {
        if (errno == EINTR)
        {
          continue;
        }
        continue;
      }

      handleTcpTlsConnection(accepted);
    }
  }

  void handleTcpTlsConnection(int accepted)
  {
    timeval timeout = {};
    timeout.tv_sec = 8;
    (void)setsockopt(accepted, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(accepted, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    SSL *ssl = SSL_new(tcpTlsContext);
    if (ssl == nullptr)
    {
      close(accepted);
      return;
    }

    ProdigyOpenSSLTlsTicketBinding binding = tcpTlsBindingTemplate;
    String failure = {};
    if (SSL_set_fd(ssl, accepted) != 1 ||
        prodigyBindOpenSSLTlsResumptionTicketContext(ssl, &binding, &failure) == false)
    {
      SSL_free(ssl);
      close(accepted);
      return;
    }
    if (SSL_accept(ssl) != 1)
    {
      SSL_free(ssl);
      close(accepted);
      return;
    }
    const bool ticketRequested = SSL_new_session_ticket(ssl) == 1;

    std::string request;
    {
      char buffer[4096] = {};
      int readBytes = SSL_read(ssl, buffer, sizeof(buffer));
      if (readBytes > 0)
      {
        request.append(buffer, size_t(readBytes));
      }
    }

    const bool resumed = SSL_session_reused(ssl) == 1;
    const char *kind = resumed ? "resumed" : "full";
    char detail[384] = {};
    std::snprintf(detail,
                  sizeof(detail),
                  "%s bytes=%zu pid=%d issued=%llu accepted=%llu fallback=%llu ticketRequested=%u",
                  kind,
                  request.size(),
                  int(getpid()),
                  (unsigned long long)tcpTlsTicketContext.issuedTickets,
                  (unsigned long long)tcpTlsTicketContext.acceptedTickets,
                  (unsigned long long)tcpTlsTicketContext.fallbackTickets,
                  unsigned(ticketRequested));
    appendEvidence("probe.tcp_tls.connection", detail);
    basics_log("probe.tcp_tls.connection %s\n", detail);

    std::string response = "tcp-tls-ok ";
    response += kind;
    response += "\n";
    (void)SSL_write(ssl, response.data(), int(response.size()));
    (void)SSL_shutdown(ssl);
    SSL_free(ssl);
    close(accepted);
  }

  static int picoquicServerCallback(
      picoquic_cnx_t *cnx,
      uint64_t streamID,
      uint8_t *bytes,
      size_t length,
      picoquic_call_back_event_t event,
      void *callbackCtx,
      void *)
  {
    ResumptionReadinessProbeContainer *self = static_cast<ResumptionReadinessProbeContainer *>(callbackCtx);
    return self == nullptr ? 0 : self->handlePicoquicServerEvent(cnx, streamID, bytes, length, event);
  }

  int handlePicoquicServerEvent(
      picoquic_cnx_t *cnx,
      uint64_t streamID,
      uint8_t *,
      size_t length,
      picoquic_call_back_event_t event)
  {
    if (cnx == nullptr)
    {
      return 0;
    }

    QuicConnectionState& state = quicConnections[cnx];
    switch (event)
    {
      case picoquic_callback_almost_ready:
        state.canRespond = true;
        break;
      case picoquic_callback_ready:
        state.canRespond = true;
        break;
      case picoquic_callback_stream_data:
      case picoquic_callback_stream_fin:
        {
          if (length > 0)
          {
            state.streamID = streamID;
            state.receivedBytes += length;
          }
        }
        break;
      case picoquic_callback_close:
      case picoquic_callback_application_close:
      case picoquic_callback_stateless_reset:
        {
          basics_log("probe.quic.close state=%d\n", int(picoquic_get_cnx_state(cnx)));
          quicConnections.erase(cnx);
          return 0;
        }
      default:
        break;
    }

    const picoquic_state_enum connectionState = picoquic_get_cnx_state(cnx);
    if (connectionState == picoquic_state_server_false_start ||
        connectionState == picoquic_state_server_almost_ready ||
        connectionState == picoquic_state_ready)
    {
      state.canRespond = true;
    }

    if (state.canRespond && state.receivedBytes > 0 && state.responded == false)
    {
      const bool resumed = picoquic_tls_is_psk_handshake(cnx) != 0;
      const char *kind = resumed ? "resumed" : "full";
      char detail[320] = {};
      std::snprintf(detail,
                    sizeof(detail),
                    "%s bytes=%llu pid=%d sni=%.*s alpn=%.*s",
                    kind,
                    (unsigned long long)state.receivedBytes,
                    int(getpid()),
                    int(quicSni.size()),
                    reinterpret_cast<const char *>(quicSni.data()),
                    int(quicAlpn.size()),
                    reinterpret_cast<const char *>(quicAlpn.data()));
      appendEvidence("probe.quic.connection", detail);
      basics_log("probe.quic.connection %s\n", detail);

      std::string response = "quic-ok ";
      response += kind;
      response += "\n";
      if (picoquic_add_to_stream(
              cnx,
              state.streamID,
              reinterpret_cast<const uint8_t *>(response.data()),
              response.size(),
              1) != 0)
      {
        basics_log("probe.quic.response_fail\n");
        return -1;
      }
      state.responded = true;
    }

    return 0;
  }

  void servePicoquic(void)
  {
    ProbePicoquicTicketKey ticketKey;
    std::string failure;
    while (stopRequested.load(std::memory_order_relaxed) == false)
    {
      {
        std::lock_guard<std::mutex> lock(probeTlsResumptionMutex);
        if (selectPicoquicTicketKey(
                probeTlsResumptionRegistry,
                quicWormholeName,
                ticketKey,
                failure))
        {
          break;
        }
      }
      usleep(100'000);
    }
    if (stopRequested.load(std::memory_order_relaxed))
    {
      ticketKey.clear();
      return;
    }
    std::string certPath = kBundledQuicCertPath;
    std::string keyPath = kBundledQuicKeyPath;
    if (access(certPath.c_str(), R_OK) != 0 || access(keyPath.c_str(), R_OK) != 0)
    {
      ticketKey.clear();
      return;
    }

    picoquic_quic_t *quic = picoquic_create(
        8,
        certPath.c_str(),
        keyPath.c_str(),
        nullptr,
        quicAlpn.c_str(),
        picoquicServerCallback,
        this,
        picoquicConnectionIDCallback,
        this,
        nullptr,
        picoquic_current_time(),
        nullptr,
        nullptr,
        ticketKey.bytes,
        ticketKey.size);
    if (quic == nullptr)
    {
      ticketKey.clear();
      return;
    }
    if (picoquic_set_default_connection_id_length(quic, QUIC_CID_LEN) != 0)
    {
      picoquic_free(quic);
      ticketKey.clear();
      return;
    }

    int fd = openUdpSocket(quicContainerPort, failure);
    if (fd >= 0)
    {
      char detail[256] = {};
      std::snprintf(detail,
                    sizeof(detail),
                    "%.*s containerPort=%u generation=%llu",
                    int(quicWormholeName.size()),
                    reinterpret_cast<const char *>(quicWormholeName.data()),
                    unsigned(quicContainerPort),
                    (unsigned long long)ticketKey.generation);
      appendEvidence("probe.quic.listen", detail);
      basics_log("probe.quic.listen %s\n", detail);

      (void)runPicoquicUdpLoop(
          quic,
          fd,
          24ull * 60ull * 60ull * 1'000'000ull,
          [&]() {
            return stopRequested.load(std::memory_order_relaxed);
          },
          failure);
      close(fd);
    }
    picoquic_free(quic);
    ticketKey.clear();
  }

  void cleanupTcpTls(void)
  {
    if (tcpTlsFD >= 0)
    {
      shutdown(tcpTlsFD, SHUT_RDWR);
      close(tcpTlsFD);
      tcpTlsFD = -1;
    }
    if (tcpTlsThread.joinable())
    {
      tcpTlsThread.join();
    }
    if (tcpTlsContext != nullptr)
    {
      SSL_CTX_free(tcpTlsContext);
      tcpTlsContext = nullptr;
    }
    if (quicThread.joinable())
    {
      quicThread.join();
    }
  }

public:

  ~ResumptionReadinessProbeContainer()
  {
    beginShutdown();
    cleanupTcpTls();
  }

  void beginShutdown(void) override
  {
    stopRequested.store(true, std::memory_order_relaxed);
    if (tcpTlsFD >= 0)
    {
      shutdown(tcpTlsFD, SHUT_RDWR);
      close(tcpTlsFD);
      tcpTlsFD = -1;
    }
  }

  void endOfDynamicArgs(void) override
  {
  }

  void credentialsRefresh(const CredentialDelta& delta) override
  {
    TlsResumptionApplyAck localApply = {};
    {
      std::lock_guard<std::mutex> lock(probeTlsResumptionMutex);
      (void)applyCredentialDeltaResumptionLocally(probeTlsResumptionRegistry, probeCredentialBundle, delta, localApply);
    }

    for (const TlsResumptionSnapshot& snapshot : delta.updatedResumptionSnapshots)
    {
      bool issueReady = false;
      {
        std::lock_guard<std::mutex> lock(probeTlsResumptionMutex);
        issueReady = probeTlsResumptionRegistry.currentIssueKey(snapshot.wormholeName, tlsNowMs(nullptr)) != nullptr;
      }
      String containerUUIDText = neuronHub ? String(neuronHub->parameters.uuid) : String();
      char detail[256] = {};
      const bool applySuccess = std::all_of(
          localApply.results.begin(),
          localApply.results.end(),
          [](const TlsResumptionApplyResult& result) {
            return result.success;
          });
      std::snprintf(detail,
                    sizeof(detail),
                    "%.*s generation=%llu reason=%.*s applySuccess=%u issueReady=%u containerUUID=%.*s",
                    int(snapshot.wormholeName.size()),
                    reinterpret_cast<const char *>(snapshot.wormholeName.data()),
                    (unsigned long long)snapshot.generation,
                    int(delta.reason.size()),
                    reinterpret_cast<const char *>(delta.reason.data()),
                    unsigned(applySuccess),
                    unsigned(issueReady),
                    int(containerUUIDText.size()),
                    reinterpret_cast<const char *>(containerUUIDText.data()));
      appendEvidence("probe.resumption_delta", detail);
      basics_log("probe.resumption_delta %s\n", detail);
    }
  }

  void prepare(int argc, char *argv[])
  {
    int evidenceFD = open(kEvidencePath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (evidenceFD >= 0)
    {
      close(evidenceFD);
    }

    Ring::createRing(64, 128, 512, 128, -1, -1, 0);

    neuronHub = std::make_unique<NeuronHub>(this);
    neuronHub->fillFromMainArgs(argc, argv);
    neuronHub->afterRing();

    std::string failure;
    if (neuronHub->parameters.hasCredentialBundle)
    {
      TlsResumptionApplyAck initialApply = {};
      std::lock_guard<std::mutex> lock(probeTlsResumptionMutex);
      probeCredentialBundle = neuronHub->parameters.credentialBundle;
      if (applyCredentialBundleResumptionLocally(probeTlsResumptionRegistry, probeCredentialBundle, initialApply) &&
          std::any_of(
              initialApply.results.begin(),
              initialApply.results.end(),
              [](const TlsResumptionApplyResult& result) {
                return result.success == false;
              }))
      {
        failure = "probe_resumption_registry_initial_apply_failed";
        basics_log("ResumptionReadinessProbeContainer::prepare failed detail=%s\n", failure.c_str());
        std::fflush(stdout);
        std::fflush(stderr);
        std::exit(EXIT_FAILURE);
      }
    }

    if (validateResumptionReadiness(failure) == false)
    {
      basics_log("ResumptionReadinessProbeContainer::prepare failed detail=%s\n", failure.c_str());
      std::fflush(stdout);
      std::fflush(stderr);
      std::exit(EXIT_FAILURE);
    }

    if (prepareTcpTlsServer(failure) == false)
    {
      basics_log("ResumptionReadinessProbeContainer::prepare tcp tls failed detail=%s\n", failure.c_str());
      std::fflush(stdout);
      std::fflush(stderr);
      std::exit(EXIT_FAILURE);
    }

    if (preparePicoquicServer(failure) == false)
    {
      basics_log("ResumptionReadinessProbeContainer::prepare picoquic failed detail=%s\n", failure.c_str());
      std::fflush(stdout);
      std::fflush(stderr);
      std::exit(EXIT_FAILURE);
    }

    neuronHub->signalReady();
    neuronHub->signalRuntimeReady();
  }

  void start(void)
  {
    Ring::start();
  }
};

struct PicoquicClientContext {
  picoquic_quic_t *quic = nullptr;
  picoquic_cnx_t *connection = nullptr;
  std::string ticketPath;
  std::string postReadyPayload;
  std::string received;
  bool sentPostReadyPayload = false;
};

static bool fileNonEmpty(const std::string& path)
{
  struct stat st = {};
  return stat(path.c_str(), &st) == 0 && st.st_size > 0;
}

static int picoquicClientCallback(
    picoquic_cnx_t *,
    uint64_t streamID,
    uint8_t *bytes,
    size_t length,
    picoquic_call_back_event_t event,
    void *callbackCtx,
    void *)
{
  PicoquicClientContext *context = static_cast<PicoquicClientContext *>(callbackCtx);
  if (context == nullptr)
  {
    return 0;
  }

  switch (event)
  {
    case picoquic_callback_almost_ready:
    case picoquic_callback_ready:
      if (context->connection != nullptr &&
          context->postReadyPayload.empty() == false &&
          context->sentPostReadyPayload == false)
      {
        context->sentPostReadyPayload = true;
        const int sendResult = picoquic_add_to_stream(
            context->connection,
            kQuicStreamID,
            reinterpret_cast<const uint8_t *>(context->postReadyPayload.data()),
            context->postReadyPayload.size(),
            1);
        if (sendResult != 0)
        {
          return -1;
        }
      }
      break;
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
      if (bytes != nullptr && length > 0)
      {
        context->received.append(reinterpret_cast<const char *>(bytes), length);
      }
      break;
    default:
      break;
  }

  return 0;
}

static int runPicoquicClientMode(int argc, char *argv[])
{
  if (argc != 10)
  {
    std::fprintf(stderr, "usage: %s --picoquic-client <ipv4> <port> <ticket-file> <payload> <full|resumed> <local-port> <initial-cid-hex> <root-cert>\n", argv[0]);
    return 2;
  }

  const char *host = argv[2];
  const uint16_t port = uint16_t(std::strtoul(argv[3], nullptr, 10));
  const char *ticketPath = argv[4];
  const char *payload = argv[5];
  const bool expectResumed = std::strcmp(argv[6], "resumed") == 0;
  if (expectResumed == false && std::strcmp(argv[6], "full") != 0)
  {
    std::fprintf(stderr, "invalid picoquic client mode\n");
    return 2;
  }
  const uint16_t localPort = uint16_t(std::strtoul(argv[7], nullptr, 10));
  const char *initialCidHex = argv[8];
  const char *rootCertPath = argv[9];

  sockaddr_in serverAddress = {};
  serverAddress.sin_family = AF_INET;
  serverAddress.sin_port = htons(port);
  if (inet_pton(AF_INET, host, &serverAddress.sin_addr) != 1)
  {
    std::fprintf(stderr, "invalid picoquic IPv4 target\n");
    return 2;
  }

  picoquic_connection_id_t initialConnectionID {};
  if (parsePicoquicConnectionIDHex(initialCidHex, initialConnectionID) == false)
  {
    std::fprintf(stderr, "invalid picoquic initial connection ID\n");
    return 2;
  }

  PicoquicClientContext context;
  context.postReadyPayload = payload;
  context.quic = picoquic_create(
      1,
      nullptr,
      nullptr,
      rootCertPath,
      "h3",
      picoquicClientCallback,
      &context,
      nullptr,
      nullptr,
      nullptr,
      picoquic_current_time(),
      nullptr,
      ticketPath,
      nullptr,
      0);
  if (context.quic == nullptr)
  {
    std::fprintf(stderr, "failed to create picoquic client context\n");
    return 1;
  }

  context.connection = picoquic_create_cnx(
      context.quic,
      initialConnectionID,
      picoquic_null_connection_id,
      reinterpret_cast<const sockaddr *>(&serverAddress),
      picoquic_current_time(),
      0,
      "quic.resumption.test",
      "h3",
      1);
  if (context.connection == nullptr)
  {
    std::fprintf(stderr, "failed to create picoquic client connection\n");
    picoquic_free(context.quic);
    return 1;
  }
  picoquic_set_callback(context.connection, picoquicClientCallback, &context);

  if (picoquic_start_client_cnx(context.connection) != 0)
  {
    std::fprintf(stderr, "failed to start picoquic client connection\n");
    picoquic_free(context.quic);
    return 1;
  }

  std::string failure;
  int fd = openUdpSocket(localPort, failure);
  if (fd < 0)
  {
    std::fprintf(stderr, "failed to open picoquic client UDP socket: %s\n", failure.c_str());
    picoquic_free(context.quic);
    return 1;
  }

  const bool loopResult = runPicoquicUdpLoop(
      context.quic,
      fd,
      30ull * 1'000'000ull,
      [&]() {
        if (context.received.find("quic-ok ") == std::string::npos)
        {
          return false;
        }
        return expectResumed ||
               (picoquic_save_session_tickets(context.quic, ticketPath) == 0 && fileNonEmpty(ticketPath));
      },
      failure);
  close(fd);
  if (loopResult == false)
  {
    std::fprintf(stderr, "picoquic UDP loop failed: %s\n", failure.c_str());
    std::fprintf(stderr, "picoquic-close state=%d\n", context.connection == nullptr ? -1 : int(picoquic_get_cnx_state(context.connection)));
    picoquic_free(context.quic);
    return 1;
  }

  if (expectResumed == false)
  {
    (void)picoquic_save_session_tickets(context.quic, ticketPath);
  }

  const bool resumed = picoquic_tls_is_psk_handshake(context.connection) != 0;
  if (resumed != expectResumed)
  {
    std::fprintf(stderr, "picoquic client unexpected psk state expected=%d actual=%d response=%s\n", int(expectResumed), int(resumed), context.received.c_str());
    picoquic_free(context.quic);
    return 1;
  }
  std::string expectedResponse = "quic-ok ";
  expectedResponse += expectResumed ? "resumed" : "full";
  if (context.received.find(expectedResponse) == std::string::npos)
  {
    std::fprintf(stderr, "picoquic client missing expected response: %s\n", context.received.c_str());
    picoquic_free(context.quic);
    return 1;
  }
  if (expectResumed == false && fileNonEmpty(ticketPath) == false)
  {
    std::fprintf(stderr, "picoquic client did not save a non-empty ticket store\n");
    picoquic_free(context.quic);
    return 1;
  }

  std::printf("quic-client-ok %s", context.received.c_str());
  picoquic_free(context.quic);
  return 0;
}

int main(int argc, char *argv[])
{
  if (argc > 1 && std::strcmp(argv[1], "--picoquic-client") == 0)
  {
    return runPicoquicClientMode(argc, argv);
  }

  ResumptionReadinessProbeContainer container;
  container.prepare(argc, argv);
  container.start();
  return 0;
}
