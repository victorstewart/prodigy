#include <includes.h>
#include <prodigy/transport.artifact.h>
#include <prodigy/transport.tls.h>
#include <prodigy/bundle.artifact.h>
#include <services/debug.h>
#include <services/crypto.h>
#include <services/bitsery.h>
#include <services/filesystem.h>
#include <networking/message.h>
#include <networking/multiplexer.h>
#include <networking/ring.h>

#include <algorithm>
#include <chrono>

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

class TestSuite {
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    if (condition)
    {
      basics_log("PASS: %s\n", name);
    }
    else
    {
      std::fprintf(stderr, "FAIL: %s\n", name);
      failed += 1;
    }
  }
};

static void reserveTransportStream(ProdigyTransportTLSStream& stream)
{
  stream.rBuffer.reserve(8192);
  stream.wBuffer.reserve(16'384);
}

static bool setNonBlocking(int fd)
{
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0)
  {
    return false;
  }

  return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool createConnectedLoopbackTCPPair(int& clientFD, int& serverFD)
{
  clientFD = -1;
  serverFD = -1;

  int listenerFD = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listenerFD < 0)
  {
    return false;
  }

  int reuse = 1;
  (void)setsockopt(listenerFD, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  struct sockaddr_in listenerAddress = {};
  listenerAddress.sin_family = AF_INET;
  listenerAddress.sin_port = 0;
  listenerAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(listenerFD, reinterpret_cast<const struct sockaddr *>(&listenerAddress), sizeof(listenerAddress)) != 0 || listen(listenerFD, 1) != 0)
  {
    close(listenerFD);
    return false;
  }

  socklen_t listenerAddressLen = sizeof(listenerAddress);
  if (getsockname(listenerFD, reinterpret_cast<struct sockaddr *>(&listenerAddress), &listenerAddressLen) != 0)
  {
    close(listenerFD);
    return false;
  }

  clientFD = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (clientFD < 0)
  {
    close(listenerFD);
    return false;
  }

  if (connect(clientFD, reinterpret_cast<const struct sockaddr *>(&listenerAddress), sizeof(listenerAddress)) != 0)
  {
    close(clientFD);
    clientFD = -1;
    close(listenerFD);
    return false;
  }

  serverFD = accept4(listenerFD, nullptr, nullptr, SOCK_CLOEXEC);
  close(listenerFD);
  if (serverFD < 0)
  {
    close(clientFD);
    clientFD = -1;
    return false;
  }

  if (setNonBlocking(clientFD) == false || setNonBlocking(serverFD) == false)
  {
    close(clientFD);
    close(serverFD);
    clientFD = -1;
    serverFD = -1;
    return false;
  }

  return true;
}

class TransportTLSRingInterface final : public RingInterface {
public:

  TestSuite *suite = nullptr;
  ProdigyTransportTLSStream client = {};
  ProdigyTransportTLSStream server = {};
  TimeoutPacket deadline = {};
  String expectedPayload = {};
  bool completed = false;
  bool deadlineFired = false;

  explicit TransportTLSRingInterface(TestSuite& testSuite)
      : suite(&testSuite)
  {
    deadline.setTimeoutMs(10'000);
  }

  void fail(const char *name)
  {
    suite->expect(false, name);
    Ring::exit = true;
  }

  void maybeQueueSend(ProdigyTransportTLSStream& stream)
  {
    if (stream.pendingSend == false && stream.needsTransportTLSSendKick())
    {
      Ring::queueSend(&stream);
    }
  }

  void maybeQueueRecv(ProdigyTransportTLSStream& stream)
  {
    if (stream.pendingRecv == false)
    {
      Ring::queueRecv(&stream);
    }
  }

  void recvHandler(void *socket, int result) override
  {
    ProdigyTransportTLSStream *stream =
        (socket == &client)   ? &client
        : (socket == &server) ? &server
                              : nullptr;
    if (stream == nullptr)
    {
      return;
    }

    stream->pendingRecv = false;
    if (result <= 0)
    {
      fail((stream == &client) ? "ring_tls_client_recv_positive" : "ring_tls_server_recv_positive");
      return;
    }

    if (stream->decryptTransportTLS(uint32_t(result)) == false)
    {
      fail((stream == &client) ? "ring_tls_client_recv_decrypts" : "ring_tls_server_recv_decrypts");
      return;
    }

    maybeQueueSend(*stream);
    maybeQueueRecv(*stream);

    if (stream == &server && server.rBuffer.outstandingBytes() >= expectedPayload.size())
    {
      suite->expect(server.rBuffer.outstandingBytes() == expectedPayload.size(), "ring_tls_server_receives_expected_plaintext_bytes");
      suite->expect(
          server.rBuffer.outstandingBytes() == expectedPayload.size() && std::memcmp(server.rBuffer.pHead(), expectedPayload.data(), expectedPayload.size()) == 0,
          "ring_tls_server_plaintext_matches_payload");
      completed = true;
      Ring::exit = true;
    }
  }

  void sendHandler(void *socket, int result) override
  {
    ProdigyTransportTLSStream *stream =
        (socket == &client)   ? &client
        : (socket == &server) ? &server
                              : nullptr;
    if (stream == nullptr || stream->pendingSend == false)
    {
      return;
    }

    uint32_t submittedBytes = stream->pendingSendBytes;
    stream->pendingSend = false;
    stream->pendingSendBytes = 0;

    if (result <= 0 || submittedBytes == 0 || uint32_t(result) > submittedBytes)
    {
      stream->noteSendCompleted();
      fail((stream == &client) ? "ring_tls_client_send_positive" : "ring_tls_server_send_positive");
      return;
    }

    stream->consumeSentBytes(uint32_t(result), false);
    stream->noteSendCompleted();
    maybeQueueSend(*stream);
  }

  void timeoutHandler(TimeoutPacket *packet, int result) override
  {
    if (packet != &deadline)
    {
      return;
    }

    deadlineFired = true;
    suite->expect(result == -ETIME, "ring_tls_deadline_times_out_with_etime");
    Ring::exit = true;
  }
};

static bool pumpTransportBytes(ProdigyTransportTLSStream& from, ProdigyTransportTLSStream& to)
{
  uint32_t bytes = from.nBytesToSend();
  if (bytes == 0)
  {
    return false;
  }

  if (to.rBuffer.remainingCapacity() < bytes)
  {
    to.rBuffer.reserve(to.rBuffer.size() + bytes);
  }

  from.noteSendQueued();
  std::memcpy(to.rBuffer.pTail(), from.pBytesToSend(), bytes);
  if (to.decryptTransportTLS(bytes) == false)
  {
    from.noteSendCompleted();
    return false;
  }

  from.consumeSentBytes(bytes, false);
  from.noteSendCompleted();
  return true;
}

constexpr static uint32_t boundedPlaintextSendBudget = (64u * 1024u);

static bool pumpTransportBytesLimited(ProdigyTransportTLSStream& from, ProdigyTransportTLSStream& to, uint32_t maximumBytes)
{
  const uint32_t available = from.nBytesToSend();
  if (available == 0 || maximumBytes == 0)
  {
    return false;
  }

  const uint32_t bytes = std::min(available, maximumBytes);
  if (to.rBuffer.remainingCapacity() < bytes)
  {
    to.rBuffer.reserve(to.rBuffer.size() + bytes);
  }

  from.noteSendQueued();
  std::memcpy(to.rBuffer.pTail(), from.pBytesToSend(), bytes);
  if (to.decryptTransportTLS(bytes) == false)
  {
    from.noteSendCompleted();
    return false;
  }

  from.consumeSentBytes(bytes, false);
  from.noteSendCompleted();
  return true;
}

static bool drainEncryptedTransportBytes(ProdigyTransportTLSStream& from, String& encrypted)
{
  bool drainedAny = false;

  for (uint32_t round = 0; round < 128; ++round)
  {
    uint32_t bytes = from.nBytesToSend();
    if (bytes == 0)
    {
      break;
    }

    from.noteSendQueued();
    encrypted.append(from.pBytesToSend(), bytes);
    from.consumeSentBytes(bytes, false);
    from.noteSendCompleted();
    drainedAny = true;
  }

  return drainedAny;
}

static bool completeTransportHandshake(ProdigyTransportTLSStream& client, ProdigyTransportTLSStream& server, uint32_t maxRounds = 128)
{
  for (uint32_t round = 0; round < maxRounds; ++round)
  {
    bool progressed = false;
    progressed = pumpTransportBytes(client, server) || progressed;
    progressed = pumpTransportBytes(server, client) || progressed;

    if (client.isTLSNegotiated() && server.isTLSNegotiated())
    {
      return true;
    }

    if (progressed == false)
    {
      break;
    }
  }

  return false;
}

static bool configureTransportRuntimeForNode(
    uint128_t nodeUUID,
    const String& rootCertPem,
    const String& rootKeyPem,
    const String& localCertPem,
    const String& localKeyPem,
    String *failure = nullptr,
    const ProdigyTransportTLSResumptionConfig *resumption = nullptr)
{
  ProdigyTransportTLSBootstrap bootstrap = {};
  bootstrap.uuid = nodeUUID;
  bootstrap.transport.generation = 1;
  bootstrap.transport.clusterRootCertPem = rootCertPem;
  bootstrap.transport.clusterRootKeyPem = rootKeyPem;
  bootstrap.transport.localCertPem = localCertPem;
  bootstrap.transport.localKeyPem = localKeyPem;
  if (resumption)
  {
    return ProdigyTransportTLSRuntime::configure(bootstrap, *resumption, failure);
  }

  return ProdigyTransportTLSRuntime::configure(bootstrap, failure);
}

static EVP_MAC_CTX *makeTransportTlsHmacContextForTest(void)
{
  EVP_MAC *mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  if (mac == nullptr)
  {
    return nullptr;
  }

  EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
  EVP_MAC_free(mac);
  return ctx;
}

static TlsResumptionKeyEpoch makeTransportTlsResumptionEpoch(uint8_t seed)
{
  TlsResumptionKeyEpoch epoch = {};
  epoch.generation = 90;
  epoch.role = TlsResumptionKeyRole::issueAndAccept;
  for (uint32_t index = 0; index < sizeof(epoch.keyID); index += 1)
  {
    epoch.keyID[index] = uint8_t(seed + index);
  }
  for (uint32_t index = 0; index < sizeof(epoch.masterSecret); index += 1)
  {
    epoch.masterSecret[index] = uint8_t(0x80u + seed + index);
  }
  epoch.issueUntilMs = 200'000;
  epoch.acceptUntilMs = 300'000;
  return epoch;
}

static TlsResumptionSnapshot makeTransportTlsResumptionSnapshot(void)
{
  TlsResumptionSnapshot snapshot = {};
  snapshot.generation = 90;
  snapshot.wormholeName.assign("public-api-tcp"_ctv);
  snapshot.keyRing.push_back(makeTransportTlsResumptionEpoch(5));
  return snapshot;
}

static ProdigyOpenSSLTlsTicketBinding makeTransportTlsResumptionBinding(void)
{
  ProdigyOpenSSLTlsTicketBinding binding = {};
  binding.wormholeName.assign("public-api-tcp"_ctv);
  binding.nowMs = 120'000;
  return binding;
}

static bool streamBufferEquals(StreamBuffer& buffer, const String& expected)
{
  return buffer.outstandingBytes() == expected.size() && std::memcmp(buffer.pHead(), expected.data(), expected.size()) == 0;
}

static bool pumpTransportUntilPlaintext(
    ProdigyTransportTLSStream& first,
    ProdigyTransportTLSStream& second,
    StreamBuffer& expectedSink,
    const String& expected,
    uint32_t maxRounds = 128)
{
  for (uint32_t round = 0; round < maxRounds; ++round)
  {
    bool progressed = false;
    progressed = pumpTransportBytes(first, second) || progressed;
    progressed = pumpTransportBytes(second, first) || progressed;

    if (streamBufferEquals(expectedSink, expected))
    {
      return true;
    }

    if (progressed == false)
    {
      break;
    }
  }

  return false;
}

static void queueStringMessage(ProdigyTransportTLSStream& stream, uint16_t topic, const String& payload)
{
  Message::construct(stream.wBuffer, topic, payload);
}

static bool collectStringMessages(
    ProdigyTransportTLSStream& stream,
    Vector<uint16_t>& topics,
    Vector<String>& payloads,
    bool& parseFailed)
{
  parseFailed = false;
  stream.extractMessages<Message>([&](Message *message) -> void {
    uint8_t *args = message->args;
    String payload = {};
    Message::extractToString(args, payload);
    topics.push_back(message->topic);
    payloads.push_back(payload);
  },
                                  true, UINT32_MAX, 16, UINT32_MAX, parseFailed);

  return parseFailed == false;
}

static void runFixedSlotRingTransportTLSPayload(TestSuite& suite,
                                                const String& rootCertPem,
                                                const String& rootKeyPem,
                                                const String& clientCertPem,
                                                const String& clientKeyPem,
                                                const String& serverCertPem,
                                                const String& serverKeyPem,
                                                uint128_t clientUUID,
                                                uint128_t serverUUID)
{
  int clientFD = -1;
  int serverFD = -1;
  suite.expect(createConnectedLoopbackTCPPair(clientFD, serverFD), "ring_tls_creates_connected_loopback_pair");
  if (clientFD < 0 || serverFD < 0)
  {
    return;
  }

  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;
  Ring::createRing(128, 256, 16, 4, -1, -1, 16);

  TransportTLSRingInterface interfacer(suite);
  reserveTransportStream(interfacer.client);
  reserveTransportStream(interfacer.server);

  interfacer.client.fd = clientFD;
  interfacer.client.isNonBlocking = true;
  interfacer.server.fd = serverFD;
  interfacer.server.isNonBlocking = true;

  int clientFslot = Ring::adoptProcessFDIntoFixedFileSlot(clientFD, false);
  int serverFslot = Ring::adoptProcessFDIntoFixedFileSlot(serverFD, false);
  suite.expect(clientFslot >= 0, "ring_tls_client_fixed_slot_adopted");
  suite.expect(serverFslot >= 0, "ring_tls_server_fixed_slot_adopted");
  if (clientFslot < 0 || serverFslot < 0)
  {
    close(clientFD);
    close(serverFD);
    Ring::shutdownForExec();
    Ring::interfacer = nullptr;
    Ring::lifecycler = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;
    return;
  }

  interfacer.client.isFixedFile = true;
  interfacer.client.fslot = clientFslot;
  interfacer.server.isFixedFile = true;
  interfacer.server.fslot = serverFslot;

  String failure = {};
  suite.expect(
      configureTransportRuntimeForNode(clientUUID, rootCertPem, rootKeyPem, clientCertPem, clientKeyPem, &failure),
      "ring_tls_configure_client_runtime");
  suite.expect(failure.size() == 0, "ring_tls_configure_client_runtime_clears_failure");
  suite.expect(interfacer.client.beginTransportTLS(false), "ring_tls_begin_client");

  suite.expect(
      configureTransportRuntimeForNode(serverUUID, rootCertPem, rootKeyPem, serverCertPem, serverKeyPem, &failure),
      "ring_tls_configure_server_runtime");
  suite.expect(failure.size() == 0, "ring_tls_configure_server_runtime_clears_failure");
  suite.expect(interfacer.server.beginTransportTLS(true), "ring_tls_begin_server");

  const uint32_t payloadBytes = 8u * 1024u * 1024u;
  interfacer.expectedPayload.reserve(payloadBytes);
  for (uint32_t index = 0; index < payloadBytes; ++index)
  {
    interfacer.expectedPayload.append(uint8_t('a' + (index % 23u)));
  }
  interfacer.client.wBuffer.append(interfacer.expectedPayload);

  Ring::interfacer = &interfacer;
  Ring::queueTimeout(&interfacer.deadline);
  interfacer.maybeQueueRecv(interfacer.client);
  interfacer.maybeQueueRecv(interfacer.server);
  interfacer.maybeQueueSend(interfacer.client);
  interfacer.maybeQueueSend(interfacer.server);
  Ring::start();

  Ring::shutdownForExec();
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;

  suite.expect(interfacer.deadlineFired == false, "ring_tls_payload_completes_before_deadline");
  suite.expect(interfacer.completed, "ring_tls_payload_completes");

  close(clientFD);
  close(serverFD);
}

static void appendDeterministicPayload(String& payload, uint32_t payloadBytes)
{
  payload.clear();
  payload.reserve(payloadBytes);
  for (uint32_t index = 0; index < payloadBytes; ++index)
  {
    payload.append(uint8_t('a' + (index % 23u)));
  }
}

class AcceptedFixedFileSenderInterface final : public RingInterface {
public:

  TCPSocket listener = {};
  TCPStream accepted = {};
  TimeoutPacket deadline = {};
  String payload = {};
  bool completed = false;
  bool failed = false;
  const char *failureReason = nullptr;
  uint32_t maxSegmentSize = 0;

  AcceptedFixedFileSenderInterface()
  {
    deadline.setTimeoutMs(15'000);
  }

  void fail(const char *reason)
  {
    if (failed == false)
    {
      failed = true;
      failureReason = reason;
    }

    Ring::exit = true;
  }

  void start(const char *bindIP, uint16_t port, uint32_t payloadBytes, uint32_t _maxSegmentSize)
  {
    maxSegmentSize = _maxSegmentSize;
    appendDeterministicPayload(payload, payloadBytes);

    listener.setIPVersion(AF_INET);
    listener.setSaddr(IPAddress(bindIP, false), port);
    listener.bindThenListen();

    Ring::installFDIntoFixedFileSlot(&listener);
    RingDispatcher::installMultiplexee(&listener, this);
    Ring::queueAccept(&listener);
    Ring::queueTimeout(&deadline);
  }

  void acceptHandler(void *socket, int fslot) override
  {
    if (socket != static_cast<void *>(&listener))
    {
      return;
    }

    if (fslot < 0)
    {
      fail("accepted_fixed_file_sender_accept");
      return;
    }

    accepted.fslot = fslot;
    accepted.isFixedFile = true;
    accepted.isNonBlocking = true;
    accepted.rBuffer.reserve(8192);
    accepted.wBuffer.reserve(payload.size() + 8192u);
    accepted.wBuffer.append(payload);

    RingDispatcher::installMultiplexee(&accepted, this);
    Ring::queueSetSockOptRaw(&accepted, SOL_TCP, TCP_CONGESTION, "dctcp", socklen_t(strlen("dctcp")), "accepted fixed-file sender congestion");
    Ring::queueSetSockOptInt(&accepted, SOL_TCP, TCP_USER_TIMEOUT, 8000, "accepted fixed-file sender user-timeout");
    if (maxSegmentSize > 0)
    {
      Ring::queueSetSockOptInt(&accepted, SOL_TCP, TCP_MAXSEG, int(maxSegmentSize), "accepted fixed-file sender tcp maxseg");
    }

    Ring::queueSend(&accepted);
    Ring::submitPending();
  }

  void sendHandler(void *socket, int result) override
  {
    if (socket != static_cast<void *>(&accepted) || accepted.pendingSend == false)
    {
      return;
    }

    uint32_t submittedBytes = accepted.pendingSendBytes;
    accepted.pendingSend = false;
    accepted.pendingSendBytes = 0;

    if (result <= 0 || submittedBytes == 0 || uint32_t(result) > submittedBytes)
    {
      accepted.noteSendCompleted();
      fail("accepted_fixed_file_sender_send");
      return;
    }

    accepted.consumeSentBytes(uint32_t(result), false);
    accepted.noteSendCompleted();
    if (accepted.wBuffer.outstandingBytes() > 0)
    {
      Ring::queueSend(&accepted);
      return;
    }

    completed = true;
    Ring::exit = true;
  }

  void closeHandler(void *socket) override
  {
    if (socket == static_cast<void *>(&accepted))
    {
      RingDispatcher::eraseMultiplexee(&accepted);
      if (completed == false)
      {
        fail("accepted_fixed_file_sender_close");
      }
      return;
    }

    if (socket == static_cast<void *>(&listener))
    {
      RingDispatcher::eraseMultiplexee(&listener);
    }
  }

  void timeoutHandler(TimeoutPacket *packet, int result) override
  {
    if (packet != &deadline)
    {
      return;
    }

    (void)result;
    fail("accepted_fixed_file_sender_timeout");
  }
};

static int runAcceptedFixedFileSenderServer(const char *bindIP, uint16_t port, uint32_t payloadBytes, uint32_t maxSegmentSize)
{
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;
  Ring::createRing(64, 128, 16, 4, -1, -1, 8);

  AcceptedFixedFileSenderInterface interfacer = {};
  Ring::interfacer = &interfacer;
  interfacer.start(bindIP, port, payloadBytes, maxSegmentSize);
  Ring::start();

  Ring::shutdownForExec();
  Ring::interfacer = nullptr;
  Ring::lifecycler = nullptr;
  Ring::exit = false;
  Ring::shuttingDown = false;

  if (interfacer.completed == false || interfacer.failed)
  {
    std::fprintf(stderr,
                 "accepted_fixed_file_sender_server failed reason=%s payloadBytes=%u port=%u mss=%u completed=%d failed=%d\n",
                 (interfacer.failureReason ? interfacer.failureReason : "unknown"),
                 payloadBytes,
                 unsigned(port),
                 maxSegmentSize,
                 int(interfacer.completed),
                 int(interfacer.failed));
    std::fflush(stderr);
    return EXIT_FAILURE;
  }

  std::fprintf(stderr,
               "accepted_fixed_file_sender_server ok payloadBytes=%u port=%u mss=%u\n",
               payloadBytes,
               unsigned(port),
               maxSegmentSize);
  std::fflush(stderr);
  return EXIT_SUCCESS;
}

static void runBoundedPlaintextSendCase(
    TestSuite& suite,
    uint128_t clientUUID,
    uint128_t serverUUID,
    const String& rootCertPem,
    const String& rootKeyPem,
    const String& clientCertPem,
    const String& clientKeyPem,
    const String& serverCertPem,
    const String& serverKeyPem,
    String& failure)
{
  // A multi-MiB queued payload must encrypt one bounded plaintext chunk per
  // send kick.  An unrelated TLS stream must still make progress while the
  // first stream has ciphertext partially in flight.
  suite.expect(configureTransportRuntimeForNode(clientUUID, rootCertPem, rootKeyPem, clientCertPem, clientKeyPem, &failure), "reconfigure_transport_runtime_client_bounded_plaintext");
  ProdigyTransportTLSStream bulkClient = {};
  reserveTransportStream(bulkClient);
  suite.expect(bulkClient.beginTransportTLS(false), "begin_transport_tls_client_bounded_plaintext");
  suite.expect(configureTransportRuntimeForNode(serverUUID, rootCertPem, rootKeyPem, serverCertPem, serverKeyPem, &failure), "reconfigure_transport_runtime_server_bounded_plaintext");
  ProdigyTransportTLSStream bulkServer = {};
  reserveTransportStream(bulkServer);
  suite.expect(bulkServer.beginTransportTLS(true), "begin_transport_tls_server_bounded_plaintext");
  suite.expect(completeTransportHandshake(bulkClient, bulkServer), "complete_transport_tls_handshake_bounded_plaintext");
  bulkServer.rBuffer.clear();

  suite.expect(configureTransportRuntimeForNode(clientUUID, rootCertPem, rootKeyPem, clientCertPem, clientKeyPem, &failure), "reconfigure_transport_runtime_client_interleaved_stream");
  ProdigyTransportTLSStream controlClient = {};
  reserveTransportStream(controlClient);
  suite.expect(controlClient.beginTransportTLS(false), "begin_transport_tls_client_interleaved_stream");
  suite.expect(configureTransportRuntimeForNode(serverUUID, rootCertPem, rootKeyPem, serverCertPem, serverKeyPem, &failure), "reconfigure_transport_runtime_server_interleaved_stream");
  ProdigyTransportTLSStream controlServer = {};
  reserveTransportStream(controlServer);
  suite.expect(controlServer.beginTransportTLS(true), "begin_transport_tls_server_interleaved_stream");
  suite.expect(completeTransportHandshake(controlClient, controlServer), "complete_transport_tls_handshake_interleaved_stream");
  controlServer.rBuffer.clear();

  String bulkPayload = {};
  bulkPayload.reserve((3u * 1024u * 1024u));
  for (uint32_t index = 0; index < (3u * 1024u * 1024u); ++index)
  {
    bulkPayload.append(uint8_t(index));
  }
  bulkClient.wBuffer.append(bulkPayload);
  uint32_t firstBulkCiphertext = bulkClient.nBytesToSend();
  suite.expect(firstBulkCiphertext > 0, "bounded_plaintext_first_ciphertext_ready");
  suite.expect(
      bulkClient.wBuffer.outstandingBytes() == bulkPayload.size() - boundedPlaintextSendBudget,
      "bounded_plaintext_first_kick_consumes_exact_budget");

  uint32_t partialBulkCompletion = firstBulkCiphertext / 2;
  if (partialBulkCompletion == 0)
  {
    partialBulkCompletion = 1;
  }
  suite.expect(pumpTransportBytesLimited(bulkClient, bulkServer, partialBulkCompletion), "bounded_plaintext_partial_ciphertext_completion_decrypts");
  suite.expect(
      bulkClient.wBuffer.outstandingBytes() == bulkPayload.size() - boundedPlaintextSendBudget,
      "bounded_plaintext_partial_ciphertext_does_not_consume_next_chunk");

  String controlPayload = "independent control stream progresses while bulk ciphertext is in flight"_ctv;
  controlClient.wBuffer.append(controlPayload);
  suite.expect(pumpTransportUntilPlaintext(controlClient, controlServer, controlServer.rBuffer, controlPayload), "bounded_plaintext_interleaved_stream_delivers_control");
  suite.expect(streamBufferEquals(controlServer.rBuffer, controlPayload), "bounded_plaintext_interleaved_stream_preserves_control_bytes");

  bool bulkDelivered = false;
  for (uint32_t round = 0; round < 2048; ++round)
  {
    bool progressed = pumpTransportBytesLimited(bulkClient, bulkServer, 4096);
    if (streamBufferEquals(bulkServer.rBuffer, bulkPayload))
    {
      bulkDelivered = true;
      break;
    }
    if (progressed == false)
    {
      break;
    }
  }
  suite.expect(bulkDelivered, "bounded_plaintext_multimegabyte_payload_delivers");
  suite.expect(streamBufferEquals(bulkServer.rBuffer, bulkPayload), "bounded_plaintext_multimegabyte_payload_bytes_and_order_match");

}

static bool consumeArtifactInterleaveMessages(
    ProdigyArtifactStream& stream,
    uint32_t& controlCount,
    Vector<String>& completed,
    String& failure)
{
  bool parseFailed = false;
  stream.extractMessages<Message>([&](Message *message) -> void {
    if (message->topic == ProdigyBulkTransfer::fragmentTopic)
    {
      auto result = stream.artifacts.consume(message, [&](String&& frame) { completed.push_back(std::move(frame)); }, &failure);
      if (result == ProdigyBulkTransfer::ConsumeResult::invalid) parseFailed = true;
      return;
    }
    if (message->topic == 0x3101u) ++controlCount;
    else { failure.assign("unexpected same-stream artifact interleave topic"_ctv); parseFailed = true; }
  }, true, UINT32_MAX, 16, ProdigyWire::maxControlFrameBytes, parseFailed);
  return parseFailed == false && failure.size() == 0;
}

static void runArtifactInterleaveCase(
    TestSuite& suite,
    uint128_t clientUUID,
    uint128_t serverUUID,
    const String& rootCertPem,
    const String& rootKeyPem,
    const String& clientCertPem,
    const String& clientKeyPem,
    const String& serverCertPem,
    const String& serverKeyPem,
    String& failure)
{
  suite.expect(configureTransportRuntimeForNode(clientUUID, rootCertPem, rootKeyPem, clientCertPem, clientKeyPem, &failure), "artifact_interleave_configure_client");
  ProdigyArtifactStream client = {};
  reserveTransportStream(client);
  client.artifactChunksEnabled = true;
  suite.expect(client.beginTransportTLS(false), "artifact_interleave_begin_client_tls");
  suite.expect(configureTransportRuntimeForNode(serverUUID, rootCertPem, rootKeyPem, serverCertPem, serverKeyPem, &failure), "artifact_interleave_configure_server");
  ProdigyArtifactStream server = {};
  reserveTransportStream(server);
  server.artifactChunksEnabled = true;
  suite.expect(server.beginTransportTLS(true), "artifact_interleave_begin_server_tls");
  suite.expect(completeTransportHandshake(client, server), "artifact_interleave_complete_tls_handshake");
  server.rBuffer.clear();

  String opaque = {};
  opaque.reserve(64u * 1024u * 1024u);
  for (uint32_t index = 0; index < 64u * 1024u * 1024u; ++index) opaque.append(uint8_t(index));
  String artifactFrame = {};
  Message::construct(artifactFrame, uint16_t(0x3100u), opaque);
  const uint64_t expectedArtifactFrameBytes = artifactFrame.size();
  String expectedArtifactFrameDigest = {};
  suite.expect(prodigyComputeSHA256Hex(artifactFrame, expectedArtifactFrameDigest, &failure), "artifact_interleave_hashes_opaque_frame");
  String queueFailure = {};
  suite.expect(client.queueArtifactMessage(std::move(artifactFrame), &queueFailure), "artifact_interleave_queues_64mib_opaque_frame");

  uint32_t controls = 0;
  uint32_t probesIssued = 0;
  Vector<String> completed = {};
  String receiveFailure = {};
  std::vector<uint64_t> probeDurationsUs = {};
  std::vector<std::chrono::steady_clock::time_point> probeStarts = {};
  bool parseProgress = true;
  bool senderBounded = true;
  for (uint32_t round = 0; round < 200000 && completed.empty(); ++round)
  {
    const bool issueProbe = probesIssued < 30 && client.hasBufferedTransportCiphertext() == false && client.wBuffer.outstandingBytes() == 0;
    std::chrono::steady_clock::time_point probeStart = {};
    if (issueProbe)
    {
      // nBytesToSend appends exactly one opaque fragment. The control frame is
      // then queued behind a deliberately partial ciphertext send on the same
      // TLS stream, so it must be parsed before the next artifact fragment.
      (void)client.nBytesToSend();
      String probe = {};
      probe.snprintf<"probe-{itoa}"_ctv>(uint64_t(probesIssued));
      Message::construct(client.wBuffer, uint16_t(0x3101u), probe);
      probeStart = std::chrono::steady_clock::now();
      probeStarts.push_back(probeStart);
      ++probesIssued;
    }

    const uint32_t controlsBefore = controls;
    bool progressed = pumpTransportBytesLimited(client, server, 4096);
    progressed = pumpTransportBytesLimited(server, client, 4096) || progressed;
    parseProgress = consumeArtifactInterleaveMessages(server, controls, completed, receiveFailure) && parseProgress;
    for (uint32_t completedProbe = controlsBefore; completedProbe < controls; ++completedProbe)
    {
      probeDurationsUs.push_back(uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - probeStarts[completedProbe]).count()));
    }
    senderBounded = client.wBuffer.reservedBytes() <= (ProdigyBulkTransfer::maximumFragmentBytes * 2u) && senderBounded;
    if (receiveFailure.size() > 0 || progressed == false) break;
  }

  suite.expect(parseProgress, "artifact_interleave_parse_progress");
  suite.expect(senderBounded, "artifact_interleave_sender_buffer_stays_fragment_bounded");
  suite.expect(probesIssued == 30 && controls == 30, "artifact_interleave_all_30_same_stream_controls_processed_before_artifact_completion");
  suite.expect(completed.size() == 1, "artifact_interleave_reconstructs_exactly_one_opaque_frame");
  if (completed.size() == 1)
  {
    const Message *message = reinterpret_cast<const Message *>(completed[0].data());
    String completedDigest = {};
    suite.expect(prodigyComputeSHA256Hex(completed[0], completedDigest, &failure) &&
                     message->topic == 0x3100u && completed[0].size() == expectedArtifactFrameBytes && completedDigest.equals(expectedArtifactFrameDigest),
                 "artifact_interleave_reconstructed_frame_bytes_and_topic_match");
  }
  std::vector<uint64_t> sorted = probeDurationsUs;
  std::sort(sorted.begin(), sorted.end());
  const uint64_t p95Us = sorted.empty() ? UINT64_MAX : sorted[(sorted.size() * 95 + 99) / 100 - 1];
  std::fprintf(stderr, "artifact_interleave_probe_us=");
  for (uint64_t duration : probeDurationsUs) std::fprintf(stderr, "%llu,", static_cast<unsigned long long>(duration));
  std::fprintf(stderr, " p95_us=%llu samples=%llu\n", static_cast<unsigned long long>(p95Us), static_cast<unsigned long long>(probeDurationsUs.size()));
  suite.expect(probeDurationsUs.size() == 30 && p95Us < 100'000, "artifact_interleave_30_probe_p95_under_100ms");

  // On the same TLS stream, reset a partially received transfer. Its remaining
  // old-ID fragment is rejected, while the following transfer gets a newer ID
  // and reconstructs normally.
  String stalePayload = {};
  stalePayload.reserve(128u * 1024u);
  for (uint32_t index = 0; index < 128u * 1024u; ++index) stalePayload.append(uint8_t(0xa0u + index));
  String staleFrame = {};
  Message::construct(staleFrame, uint16_t(0x3100u), stalePayload);
  suite.expect(client.queueArtifactMessage(std::move(staleFrame), &queueFailure), "artifact_interleave_queues_partial_reset_transfer");
  Vector<String> resetCompleted = {};
  String resetFailure = {};
  for (uint32_t round = 0; round < 1000 && server.artifacts.pendingIncomingReservedBytes() == 0; ++round)
  {
    (void)pumpTransportBytesLimited(client, server, 4096);
    (void)consumeArtifactInterleaveMessages(server, controls, resetCompleted, resetFailure);
  }
  suite.expect(server.artifacts.pendingIncomingReservedBytes() > 0, "artifact_interleave_receives_partial_transfer_before_reset");
  server.artifacts.reset();
  suite.expect(server.artifacts.pendingIncomingReservedBytes() == 0, "artifact_interleave_reset_drops_stale_fragment_reservation");
  bool staleRejected = false;
  for (uint32_t round = 0; round < 1000 && staleRejected == false; ++round)
  {
    (void)pumpTransportBytesLimited(client, server, 4096);
    String oldFailure = {};
    staleRejected = consumeArtifactInterleaveMessages(server, controls, resetCompleted, oldFailure) == false;
  }
  suite.expect(staleRejected, "artifact_interleave_reset_rejects_stale_old_transfer_fragment");
  for (uint32_t round = 0; round < 1000 && (client.artifacts.hasOutbound() || client.hasBufferedTransportCiphertext() || client.wBuffer.outstandingBytes() > 0); ++round)
  {
    (void)pumpTransportBytesLimited(client, server, 4096);
    String ignoredOldFailure = {};
    (void)consumeArtifactInterleaveMessages(server, controls, resetCompleted, ignoredOldFailure);
  }
  suite.expect(client.artifacts.hasOutbound() == false && client.hasBufferedTransportCiphertext() == false && client.wBuffer.outstandingBytes() == 0,
               "artifact_interleave_drains_rejected_old_transfer_before_new_id");

  String freshFrame = {};
  Message::construct(freshFrame, uint16_t(0x3100u), "fresh-transfer-after-reset"_ctv);
  suite.expect(client.queueArtifactMessage(std::move(freshFrame), &queueFailure), "artifact_interleave_queues_newer_transfer_after_reset");
  resetFailure.clear();
  for (uint32_t round = 0; round < 1000 && resetCompleted.empty(); ++round)
  {
    (void)pumpTransportBytesLimited(client, server, 4096);
    (void)consumeArtifactInterleaveMessages(server, controls, resetCompleted, resetFailure);
  }
  suite.expect(resetFailure.size() == 0 && resetCompleted.size() == 1, "artifact_interleave_new_transfer_id_completes_after_stale_reset");
}

int main(int argc, char **argv)
{
  if (argc > 1 && std::strcmp(argv[1], "--accepted-send-server") == 0)
  {
    if (argc < 5)
    {
      std::fprintf(stderr,
                   "usage: %s --accepted-send-server <bind-ipv4> <port> <payload-bytes> [tcp-maxseg]\n",
                   argv[0]);
      return EXIT_FAILURE;
    }

    const long portValue = std::strtol(argv[3], nullptr, 10);
    const unsigned long payloadValue = std::strtoul(argv[4], nullptr, 10);
    const unsigned long maxSegmentValue = (argc >= 6) ? std::strtoul(argv[5], nullptr, 10) : 0ul;
    if (portValue <= 0 || portValue > UINT16_MAX || payloadValue == 0 || payloadValue > UINT32_MAX || maxSegmentValue > UINT32_MAX)
    {
      std::fprintf(stderr, "accepted sender helper received invalid numeric arguments\n");
      return EXIT_FAILURE;
    }

    return runAcceptedFixedFileSenderServer(
        argv[2],
        uint16_t(portValue),
        uint32_t(payloadValue),
        uint32_t(maxSegmentValue));
  }

  const bool boundedSendOnly = argc > 1 && std::strcmp(argv[1], "--bounded-send") == 0;
  const bool artifactInterleaveOnly = argc > 1 && std::strcmp(argv[1], "--artifact-interleave") == 0;

  TestSuite suite;
  String failure = {};

  ProdigyTransportTLSRuntime::clear();

  ProdigyTransportTLSStream unconfigured = {};
  reserveTransportStream(unconfigured);
  suite.expect(unconfigured.beginTransportTLS(false) == false, "begin_transport_tls_requires_configured_runtime");

  String rootCertPem = {};
  String rootKeyPem = {};
  suite.expect(Vault::generateTransportRootCertificateEd25519(rootCertPem, rootKeyPem, &failure), "generate_transport_root_certificate");
  suite.expect(failure.size() == 0, "generate_transport_root_certificate_clears_failure");

  const uint128_t clientUUID = (uint128_t(0x1111222233334444ULL) << 64) | uint128_t(0x5555666677778888ULL);
  const uint128_t serverUUID = (uint128_t(0x9999AAAABBBBCCCCULL) << 64) | uint128_t(0xDDDDEEEEFFFF0001ULL);

  String clientCertPem = {};
  String clientKeyPem = {};
  String serverCertPem = {};
  String serverKeyPem = {};
  Vector<String> serverIPs = {};
  serverIPs.push_back("fd00:10::29"_ctv);
  serverIPs.push_back("2602:fac0:0:12ab:34cd::29"_ctv);

  suite.expect(Vault::generateTransportNodeCertificateEd25519(
                   rootCertPem, rootKeyPem, clientUUID, {}, clientCertPem, clientKeyPem, &failure),
               "generate_transport_client_certificate");
  suite.expect(failure.size() == 0, "generate_transport_client_certificate_clears_failure");
  suite.expect(Vault::generateTransportNodeCertificateEd25519(
                   rootCertPem, rootKeyPem, serverUUID, serverIPs, serverCertPem, serverKeyPem, &failure),
               "generate_transport_server_certificate");
  suite.expect(failure.size() == 0, "generate_transport_server_certificate_clears_failure");

  X509 *clientCert = VaultPem::x509FromPem(clientCertPem);
  X509 *serverCert = VaultPem::x509FromPem(serverCertPem);
  uint128_t extractedClientUUID = 0;
  uint128_t extractedServerUUID = 0;
  suite.expect(Vault::extractTransportCertificateUUID(clientCert, extractedClientUUID), "extract_client_transport_certificate_uuid");
  suite.expect(extractedClientUUID == clientUUID, "extract_client_transport_certificate_uuid_matches");
  suite.expect(Vault::extractTransportCertificateUUID(serverCert, extractedServerUUID), "extract_server_transport_certificate_uuid");
  suite.expect(extractedServerUUID == serverUUID, "extract_server_transport_certificate_uuid_matches");
  suite.expect(clientCert != nullptr && X509_get_signature_nid(clientCert) == NID_ED25519, "client_transport_certificate_signature_is_ed25519");
  suite.expect(serverCert != nullptr && X509_get_signature_nid(serverCert) == NID_ED25519, "server_transport_certificate_signature_is_ed25519");
  EVP_PKEY *clientPublicKey = (clientCert ? X509_get_pubkey(clientCert) : nullptr);
  EVP_PKEY *serverPublicKey = (serverCert ? X509_get_pubkey(serverCert) : nullptr);
  suite.expect(clientPublicKey != nullptr && EVP_PKEY_base_id(clientPublicKey) == EVP_PKEY_ED25519, "client_transport_certificate_key_is_ed25519");
  suite.expect(serverPublicKey != nullptr && EVP_PKEY_base_id(serverPublicKey) == EVP_PKEY_ED25519, "server_transport_certificate_key_is_ed25519");
  if (clientPublicKey)
  {
    EVP_PKEY_free(clientPublicKey);
  }
  if (serverPublicKey)
  {
    EVP_PKEY_free(serverPublicKey);
  }
  if (clientCert)
  {
    X509_free(clientCert);
  }
  if (serverCert)
  {
    X509_free(serverCert);
  }

  if (boundedSendOnly)
  {
    runBoundedPlaintextSendCase(
        suite,
        clientUUID,
        serverUUID,
        rootCertPem,
        rootKeyPem,
        clientCertPem,
        clientKeyPem,
        serverCertPem,
        serverKeyPem,
        failure);
    ProdigyTransportTLSRuntime::clear();
    return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
  }

  if (artifactInterleaveOnly)
  {
    runArtifactInterleaveCase(suite, clientUUID, serverUUID, rootCertPem, rootKeyPem, clientCertPem, clientKeyPem, serverCertPem, serverKeyPem, failure);
    ProdigyTransportTLSRuntime::clear();
    return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
  }

  TlsResumptionSnapshot resumptionSnapshot = makeTransportTlsResumptionSnapshot();
  ProdigyResumptionRegistry resumptionRegistry = {};
  suite.expect(resumptionRegistry.applySnapshot(resumptionSnapshot), "transport_tls_resumption_registry_applies_snapshot");
  ProdigyOpenSSLTlsTicketBinding resumptionBinding = makeTransportTlsResumptionBinding();

  suite.expect(configureTransportRuntimeForNode(serverUUID, rootCertPem, rootKeyPem, serverCertPem, serverKeyPem, &failure),
               "configure_transport_runtime_resumption_without_registry");
  suite.expect(failure.size() == 0, "configure_transport_runtime_resumption_without_registry_clears_failure");
  ProdigyTransportTLSStream missingResumptionRuntime = {};
  reserveTransportStream(missingResumptionRuntime);
  suite.expect(
      missingResumptionRuntime.beginTransportTLS(true, &resumptionBinding) == false,
      "begin_transport_tls_resumption_binding_requires_configured_registry");
  suite.expect(
      missingResumptionRuntime.transportTLSResumptionBindingConfigured() == false,
      "begin_transport_tls_resumption_binding_failure_clears_stream_binding");

  ProdigyTransportTLSResumptionConfig resumptionConfig = {};
  resumptionConfig.registry = &resumptionRegistry;
  resumptionConfig.renewBeforeMs = 30'000;
  suite.expect(configureTransportRuntimeForNode(serverUUID, rootCertPem, rootKeyPem, serverCertPem, serverKeyPem, &failure, &resumptionConfig),
               "configure_transport_runtime_with_resumption_registry");
  suite.expect(failure.size() == 0, "configure_transport_runtime_with_resumption_registry_clears_failure");
  suite.expect(ProdigyTransportTLSRuntime::resumptionConfigured(), "transport_tls_runtime_reports_resumption_configured");
  suite.expect(
      ProdigyTransportTLSRuntime::resumptionTicketContext() != nullptr &&
          ProdigyTransportTLSRuntime::resumptionTicketContext()->registry == &resumptionRegistry,
      "transport_tls_runtime_owns_resumption_ticket_context");

  ProdigyTransportTLSStream resumptionServer = {};
  reserveTransportStream(resumptionServer);
  suite.expect(resumptionServer.beginTransportTLS(true, &resumptionBinding), "begin_transport_tls_server_with_resumption_binding");
  suite.expect(resumptionServer.transportTLSResumptionBindingConfigured(), "transport_tls_stream_stores_resumption_binding");
  ProdigyOpenSSLTlsTicketBinding *boundResumption = prodigyOpenSSLTlsTicketBindingForSSL(resumptionServer.ssl);
  suite.expect(
      boundResumption != nullptr &&
          boundResumption->wormholeName.equal(resumptionBinding.wormholeName),
      "transport_tls_stream_binds_wormhole_resumption_metadata_to_ssl");

  unsigned char issuedKeyName[16] = {};
  unsigned char issuedIV[EVP_MAX_IV_LENGTH] = {};
  EVP_CIPHER_CTX *issuedCipher = EVP_CIPHER_CTX_new();
  EVP_MAC_CTX *issuedMac = makeTransportTlsHmacContextForTest();
  suite.expect(issuedCipher != nullptr && issuedMac != nullptr, "transport_tls_resumption_allocates_ticket_crypto");
  int issueResult = (resumptionServer.ssl && issuedCipher && issuedMac)
                        ? prodigyOpenSSLTlsTicketKeyCallback(resumptionServer.ssl, issuedKeyName, issuedIV, issuedCipher, issuedMac, 1)
                        : -1;
  suite.expect(issueResult == 1, "transport_tls_resumption_callback_issues_from_stream_binding");
  suite.expect(
      std::memcmp(issuedKeyName, resumptionSnapshot.keyRing[0].keyID, sizeof(issuedKeyName)) == 0,
      "transport_tls_resumption_callback_uses_wormhole_key");
  suite.expect(
      ProdigyTransportTLSRuntime::resumptionTicketContext() != nullptr &&
          ProdigyTransportTLSRuntime::resumptionTicketContext()->issuedTickets == 1 &&
          ProdigyTransportTLSRuntime::resumptionTicketContext()->fallbackTickets == 0,
      "transport_tls_resumption_callback_counts_issue");
  if (issuedMac)
  {
    EVP_MAC_CTX_free(issuedMac);
  }
  if (issuedCipher)
  {
    EVP_CIPHER_CTX_free(issuedCipher);
  }

  ProdigyTransportTLSRuntime::clear();
  suite.expect(ProdigyTransportTLSRuntime::resumptionConfigured() == false, "transport_tls_runtime_clear_resets_resumption");

  suite.expect(configureTransportRuntimeForNode(clientUUID, rootCertPem, rootKeyPem, clientCertPem, clientKeyPem, &failure), "configure_transport_runtime_client");
  suite.expect(failure.size() == 0, "configure_transport_runtime_client_clears_failure");
  ProdigyTransportTLSStream client = {};
  reserveTransportStream(client);
  suite.expect(client.beginTransportTLS(false), "begin_transport_tls_client");

  suite.expect(configureTransportRuntimeForNode(serverUUID, rootCertPem, rootKeyPem, serverCertPem, serverKeyPem, &failure), "configure_transport_runtime_server");
  suite.expect(failure.size() == 0, "configure_transport_runtime_server_clears_failure");
  ProdigyTransportTLSStream server = {};
  reserveTransportStream(server);
  suite.expect(server.beginTransportTLS(true), "begin_transport_tls_server");

  suite.expect(completeTransportHandshake(client, server), "complete_transport_tls_handshake");
  suite.expect(client.isTLSNegotiated(), "client_transport_tls_negotiated");
  suite.expect(server.isTLSNegotiated(), "server_transport_tls_negotiated");
  suite.expect(client.ssl != nullptr && SSL_version(client.ssl) == TLS1_3_VERSION, "client_transport_tls_uses_tls13");
  suite.expect(server.ssl != nullptr && SSL_version(server.ssl) == TLS1_3_VERSION, "server_transport_tls_uses_tls13");

  uint128_t clientPeerUUID = 0;
  uint128_t serverPeerUUID = 0;
  suite.expect(ProdigyTransportTLSRuntime::extractPeerUUID(client.ssl, clientPeerUUID), "client_extracts_peer_uuid_after_handshake");
  suite.expect(clientPeerUUID == serverUUID, "client_extracts_server_uuid");
  suite.expect(ProdigyTransportTLSRuntime::extractPeerUUID(server.ssl, serverPeerUUID), "server_extracts_peer_uuid_after_handshake");
  suite.expect(serverPeerUUID == clientUUID, "server_extracts_client_uuid");

  String clientPayload = "brain-to-neuron tls payload"_ctv;
  client.wBuffer.append(clientPayload);
  suite.expect(pumpTransportBytes(client, server), "pump_client_payload_over_tls");
  suite.expect(streamBufferEquals(server.rBuffer, clientPayload), "server_receives_client_payload_plaintext");
  server.rBuffer.consume(server.rBuffer.outstandingBytes(), true);

  String serverPayload = "brain-to-brain tls payload"_ctv;
  server.wBuffer.append(serverPayload);
  suite.expect(pumpTransportBytes(server, client), "pump_server_payload_over_tls");
  suite.expect(streamBufferEquals(client.rBuffer, serverPayload), "client_receives_server_payload_plaintext");

  suite.expect(configureTransportRuntimeForNode(clientUUID, rootCertPem, rootKeyPem, clientCertPem, clientKeyPem, &failure), "reconfigure_transport_runtime_client_reconnect");
  suite.expect(failure.size() == 0, "reconfigure_transport_runtime_client_reconnect_clears_failure");
  client.reset();
  suite.expect(client.ssl == nullptr && client.transportTLSEnabled() == false, "reset_transport_tls_client_destroys_retired_session");
  suite.expect(client.beginTransportTLS(false), "begin_transport_tls_client_reconnect");

  suite.expect(configureTransportRuntimeForNode(serverUUID, rootCertPem, rootKeyPem, serverCertPem, serverKeyPem, &failure), "reconfigure_transport_runtime_server_reconnect");
  suite.expect(failure.size() == 0, "reconfigure_transport_runtime_server_reconnect_clears_failure");
  server.reset();
  suite.expect(server.ssl == nullptr && server.transportTLSEnabled() == false, "reset_transport_tls_server_destroys_retired_session");
  suite.expect(server.beginTransportTLS(true), "begin_transport_tls_server_reconnect");

  suite.expect(completeTransportHandshake(client, server), "complete_transport_tls_reconnect_handshake");
  suite.expect(client.isTLSNegotiated(), "client_transport_tls_reconnect_negotiated");
  suite.expect(server.isTLSNegotiated(), "server_transport_tls_reconnect_negotiated");
  suite.expect(ProdigyTransportTLSRuntime::extractPeerUUID(client.ssl, clientPeerUUID), "client_extracts_peer_uuid_after_reconnect");
  suite.expect(clientPeerUUID == serverUUID, "client_extracts_server_uuid_after_reconnect");
  suite.expect(ProdigyTransportTLSRuntime::extractPeerUUID(server.ssl, serverPeerUUID), "server_extracts_peer_uuid_after_reconnect");
  suite.expect(serverPeerUUID == clientUUID, "server_extracts_client_uuid_after_reconnect");

  String reconnectPayload = "brain reconnect tls payload"_ctv;
  client.wBuffer.append(reconnectPayload);
  suite.expect(pumpTransportBytes(client, server), "pump_client_reconnect_payload_over_tls");
  suite.expect(streamBufferEquals(server.rBuffer, reconnectPayload), "server_receives_client_reconnect_payload_plaintext");

  suite.expect(configureTransportRuntimeForNode(clientUUID, rootCertPem, rootKeyPem, clientCertPem, clientKeyPem, &failure), "reconfigure_transport_runtime_client_prequeued");
  suite.expect(failure.size() == 0, "reconfigure_transport_runtime_client_prequeued_clears_failure");
  ProdigyTransportTLSStream prequeuedClient = {};
  reserveTransportStream(prequeuedClient);
  suite.expect(prequeuedClient.beginTransportTLS(false), "begin_transport_tls_client_prequeued");

  suite.expect(configureTransportRuntimeForNode(serverUUID, rootCertPem, rootKeyPem, serverCertPem, serverKeyPem, &failure), "reconfigure_transport_runtime_server_prequeued");
  suite.expect(failure.size() == 0, "reconfigure_transport_runtime_server_prequeued_clears_failure");
  ProdigyTransportTLSStream prequeuedServer = {};
  reserveTransportStream(prequeuedServer);
  suite.expect(prequeuedServer.beginTransportTLS(true), "begin_transport_tls_server_prequeued");

  String prequeuedClientPayload = "client payload queued before handshake"_ctv;
  String prequeuedServerPayload = "server payload queued before handshake"_ctv;
  prequeuedClient.wBuffer.append(prequeuedClientPayload);
  prequeuedServer.wBuffer.append(prequeuedServerPayload);

  suite.expect(completeTransportHandshake(prequeuedClient, prequeuedServer), "complete_transport_tls_handshake_with_prequeued_payloads");
  suite.expect(prequeuedClient.isTLSNegotiated(), "client_transport_tls_negotiated_with_prequeued_payloads");
  suite.expect(prequeuedServer.isTLSNegotiated(), "server_transport_tls_negotiated_with_prequeued_payloads");

  prequeuedClient.rBuffer.clear();
  prequeuedServer.rBuffer.clear();
  suite.expect(pumpTransportUntilPlaintext(prequeuedClient, prequeuedServer, prequeuedServer.rBuffer, prequeuedClientPayload), "pump_client_prequeued_payload_after_handshake");
  suite.expect(streamBufferEquals(prequeuedServer.rBuffer, prequeuedClientPayload), "server_receives_client_prequeued_payload_plaintext");
  prequeuedServer.rBuffer.consume(prequeuedServer.rBuffer.outstandingBytes(), true);

  suite.expect(pumpTransportUntilPlaintext(prequeuedServer, prequeuedClient, prequeuedClient.rBuffer, prequeuedServerPayload), "pump_server_prequeued_payload_after_handshake");
  suite.expect(streamBufferEquals(prequeuedClient.rBuffer, prequeuedServerPayload), "client_receives_server_prequeued_payload_plaintext");

  suite.expect(configureTransportRuntimeForNode(clientUUID, rootCertPem, rootKeyPem, clientCertPem, clientKeyPem, &failure), "reconfigure_transport_runtime_client_framed_messages");
  suite.expect(failure.size() == 0, "reconfigure_transport_runtime_client_framed_messages_clears_failure");
  ProdigyTransportTLSStream framedClient = {};
  reserveTransportStream(framedClient);
  suite.expect(framedClient.beginTransportTLS(false), "begin_transport_tls_client_framed_messages");

  suite.expect(configureTransportRuntimeForNode(serverUUID, rootCertPem, rootKeyPem, serverCertPem, serverKeyPem, &failure), "reconfigure_transport_runtime_server_framed_messages");
  suite.expect(failure.size() == 0, "reconfigure_transport_runtime_server_framed_messages_clears_failure");
  ProdigyTransportTLSStream framedServer = {};
  reserveTransportStream(framedServer);
  suite.expect(framedServer.beginTransportTLS(true), "begin_transport_tls_server_framed_messages");

  String framedPayloadA = "registration frame queued before first tls flight"_ctv;
  String framedPayloadB = "peerAddressCandidates frame queued during encrypted send"_ctv;
  queueStringMessage(framedClient, 0x1001u, framedPayloadA);
  uint32_t firstFlightBytes = framedClient.nBytesToSend();
  suite.expect(firstFlightBytes > 0, "framed_messages_first_tls_flight_bytes_ready");
  framedClient.noteSendQueued();
  queueStringMessage(framedClient, 0x1002u, framedPayloadB);

  if (framedServer.rBuffer.remainingCapacity() < firstFlightBytes)
  {
    framedServer.rBuffer.reserve(framedServer.rBuffer.size() + firstFlightBytes);
  }

  std::memcpy(framedServer.rBuffer.pTail(), framedClient.pBytesToSend(), firstFlightBytes);
  suite.expect(framedServer.decryptTransportTLS(firstFlightBytes), "framed_messages_first_tls_flight_decrypts");
  framedClient.consumeSentBytes(firstFlightBytes, false);
  framedClient.noteSendCompleted();

  Vector<uint16_t> framedTopics = {};
  Vector<String> framedPayloads = {};
  bool framedParseFailed = false;
  bool framedMessagesDelivered = false;
  for (uint32_t round = 0; round < 128; ++round)
  {
    suite.expect(collectStringMessages(framedServer, framedTopics, framedPayloads, framedParseFailed), "framed_messages_server_parse_progress");
    if (framedParseFailed)
    {
      break;
    }

    if (framedTopics.size() >= 2)
    {
      framedMessagesDelivered = true;
      break;
    }

    bool progressed = false;
    progressed = pumpTransportBytes(framedClient, framedServer) || progressed;
    progressed = pumpTransportBytes(framedServer, framedClient) || progressed;
    if (progressed == false)
    {
      break;
    }
  }

  suite.expect(framedParseFailed == false, "framed_messages_parse_never_fails_after_tls");
  suite.expect(framedMessagesDelivered, "framed_messages_deliver_both_messages");
  suite.expect(framedTopics.size() == 2, "framed_messages_exactly_two_messages_arrive");
  suite.expect(framedPayloads.size() == 2, "framed_messages_exactly_two_payloads_arrive");
  if (framedTopics.size() >= 2 && framedPayloads.size() >= 2)
  {
    suite.expect(framedTopics[0] == 0x1001u, "framed_messages_first_topic_matches");
    suite.expect(framedPayloads[0].equals(framedPayloadA), "framed_messages_first_payload_matches");
    suite.expect(framedTopics[1] == 0x1002u, "framed_messages_second_topic_matches");
    suite.expect(framedPayloads[1].equals(framedPayloadB), "framed_messages_second_payload_matches");
  }

  suite.expect(configureTransportRuntimeForNode(clientUUID, rootCertPem, rootKeyPem, clientCertPem, clientKeyPem, &failure), "reconfigure_transport_runtime_client_pending_plaintext");
  suite.expect(failure.size() == 0, "reconfigure_transport_runtime_client_pending_plaintext_clears_failure");
  ProdigyTransportTLSStream pendingClient = {};
  reserveTransportStream(pendingClient);
  suite.expect(pendingClient.beginTransportTLS(false), "begin_transport_tls_client_pending_plaintext");

  suite.expect(configureTransportRuntimeForNode(serverUUID, rootCertPem, rootKeyPem, serverCertPem, serverKeyPem, &failure), "reconfigure_transport_runtime_server_pending_plaintext");
  suite.expect(failure.size() == 0, "reconfigure_transport_runtime_server_pending_plaintext_clears_failure");
  ProdigyTransportTLSStream pendingServer = {};
  reserveTransportStream(pendingServer);
  suite.expect(pendingServer.beginTransportTLS(true), "begin_transport_tls_server_pending_plaintext");

  suite.expect(completeTransportHandshake(pendingClient, pendingServer), "complete_transport_tls_handshake_pending_plaintext");

  String pendingPayloadA = "registration-like frame"_ctv;
  String pendingPayloadB = {};
  String pendingPayloadBBacking = {};
  pendingPayloadBBacking.reserve(16'148);
  for (uint32_t i = 0; i < 16'148; ++i)
  {
    pendingPayloadBBacking.append(uint8_t('x'));
  }
  pendingPayloadB = pendingPayloadBBacking;

  queueStringMessage(pendingClient, 0x2001u, pendingPayloadA);
  queueStringMessage(pendingClient, 0x2002u, pendingPayloadB);

  String encryptedBurst = {};
  suite.expect(drainEncryptedTransportBytes(pendingClient, encryptedBurst), "pending_plaintext_client_encrypts_burst");
  suite.expect(encryptedBurst.size() > 0, "pending_plaintext_encrypted_burst_nonempty");

  if (pendingServer.rBuffer.remainingCapacity() < encryptedBurst.size())
  {
    pendingServer.rBuffer.reserve(pendingServer.rBuffer.size() + encryptedBurst.size());
  }

  std::memcpy(pendingServer.rBuffer.pTail(), encryptedBurst.data(), encryptedBurst.size());
  suite.expect(pendingServer.decryptTransportTLS(uint32_t(encryptedBurst.size())), "pending_plaintext_single_decrypt_drains_tls");

  Vector<uint16_t> pendingTopics = {};
  Vector<String> pendingPayloads = {};
  bool pendingParseFailed = false;
  suite.expect(collectStringMessages(pendingServer, pendingTopics, pendingPayloads, pendingParseFailed), "pending_plaintext_parse_progress");
  suite.expect(pendingParseFailed == false, "pending_plaintext_parse_never_fails");
  suite.expect(pendingTopics.size() == 2, "pending_plaintext_two_messages_arrive_without_extra_recv");
  suite.expect(pendingPayloads.size() == 2, "pending_plaintext_two_payloads_arrive_without_extra_recv");
  if (pendingTopics.size() >= 2 && pendingPayloads.size() >= 2)
  {
    suite.expect(pendingTopics[0] == 0x2001u, "pending_plaintext_first_topic_matches");
    suite.expect(pendingPayloads[0].equals(pendingPayloadA), "pending_plaintext_first_payload_matches");
    suite.expect(pendingTopics[1] == 0x2002u, "pending_plaintext_second_topic_matches");
    suite.expect(pendingPayloads[1].equals(pendingPayloadB), "pending_plaintext_second_payload_matches");
  }

  runBoundedPlaintextSendCase(
      suite,
      clientUUID,
      serverUUID,
      rootCertPem,
      rootKeyPem,
      clientCertPem,
      clientKeyPem,
      serverCertPem,
      serverKeyPem,
      failure);

  runArtifactInterleaveCase(
      suite,
      clientUUID,
      serverUUID,
      rootCertPem,
      rootKeyPem,
      clientCertPem,
      clientKeyPem,
      serverCertPem,
      serverKeyPem,
      failure);

  ProdigyTransportTLSRuntime::clear();
  runFixedSlotRingTransportTLSPayload(
      suite,
      rootCertPem,
      rootKeyPem,
      clientCertPem,
      clientKeyPem,
      serverCertPem,
      serverKeyPem,
      clientUUID,
      serverUUID);

  ProdigyTransportTLSRuntime::clear();

  if (suite.failed != 0)
  {
    basics_log("transport_tls_unit failed=%d\n", suite.failed);
    return EXIT_FAILURE;
  }

  basics_log("transport_tls_unit ok\n");
  return EXIT_SUCCESS;
}
