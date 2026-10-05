#include <prodigy/transport.tls.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures = 0;
static void expect(bool ok, const char *name)
{
  std::printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
  if (!ok) ++failures;
}
static std::array<uint8_t, 32> testPSK()
{
  std::array<uint8_t, 32> key = {};
  for (unsigned i = 0; i < key.size(); ++i) key[i] = uint8_t(0x40 + i);
  return key;
}
static bool establish(ProdigyAegisSession& client, ProdigyAegisSession& server)
{
  const auto psk = testPSK();
  const String context = "test-cluster/node-1-brain/node-2-neuron/epoch-7"_ctv;
  std::array<uint8_t, 48> first = {}, second = {};
  if (!client.begin(psk.data(), context, true) || !server.begin(psk.data(), context, false) ||
      !client.writeHandshake(first) || !server.readHandshake(first.data(), first.size()) ||
      !server.writeHandshake(second) || !client.readHandshake(second.data(), second.size())) return false;
  if (!client.handshakeComplete() || !server.handshakeComplete() || client.authenticated() || server.authenticated()) return false;
  String clientConfirmation = {}, serverConfirmation = {}, plain = {};
  ProdigyAegisSession::Record type;
  return client.encrypt(ProdigyAegisSession::Record::confirmation, nullptr, 0, clientConfirmation) &&
         server.encrypt(ProdigyAegisSession::Record::confirmation, nullptr, 0, serverConfirmation) &&
         client.decrypt(serverConfirmation.data(), serverConfirmation.size(), type, plain) &&
         type == ProdigyAegisSession::Record::confirmation && plain.empty() &&
         server.decrypt(clientConfirmation.data(), clientConfirmation.size(), type, plain) &&
         client.authenticated() && server.authenticated();
}
static bool connectedPair(int& first, int& second)
{
  first = second = -1;
  const int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener < 0) return false;
  sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  socklen_t length = sizeof(address);
  bool ok = bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0 &&
            listen(listener, 1) == 0 && getsockname(listener, reinterpret_cast<sockaddr *>(&address), &length) == 0;
  if (ok)
  {
    first = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ok = first >= 0 && connect(first, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0;
  }
  if (ok) { second = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK); ok = second >= 0; }
  close(listener);
  if (ok) ok = fcntl(first, F_SETFL, fcntl(first, F_GETFL, 0) | O_NONBLOCK) == 0;
  const int one = 1;
  if (ok) ok = setsockopt(first, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0 &&
               setsockopt(second, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0;
  if (!ok)
  {
    if (first >= 0) close(first);
    if (second >= 0) close(second);
    first = second = -1;
  }
  return ok;
}
static bool pumpSocket(ProdigyTransportTLSStream& source, ProdigyTransportTLSStream& target,
                       uint32_t sendLimit = 4093, uint32_t receiveLimit = 2053)
{
  if (!source.prepareTransportTLSSend()) return false;
  if (source.encryptedBytesToSend() != 0)
  {
    const uint32_t count = std::min(source.encryptedBytesToSend(), sendLimit);
    const ssize_t sent = send(source.fd, source.pBytesToSend(), count, MSG_NOSIGNAL);
    if (sent > 0) source.consumeSentBytes(uint32_t(sent), false);
    else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
  }
  if (!target.rBuffer.need(receiveLimit)) return false;
  const ssize_t received = recv(target.fd, target.rBuffer.pTail(), receiveLimit, 0);
  if (received > 0) return target.decryptTransportTLS(uint32_t(received));
  return received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
}

int main()
{
  const auto psk = testPSK();
  {
    ProdigyAegisSession client, server;
    expect(establish(client, server), "fresh_noise_and_mutual_aegis_confirmation");
    String frame = {}, plain = {};
    const String message = "authenticated application bytes"_ctv;
    ProdigyAegisSession::Record kind;
    expect(client.encrypt(ProdigyAegisSession::Record::application, message.data(), message.size(), frame) &&
               server.decrypt(frame.data(), frame.size(), kind, plain) && plain == message,
           "directional_application_record_roundtrip");
    expect(!server.decrypt(frame.data(), frame.size(), kind, plain) && plain.empty() && server.failedClosed(),
           "record_replay_closes_session_and_clears_output");
    expect(!server.decrypt(frame.data(), frame.size(), kind, plain), "failed_session_cannot_resume");
  }
  for (unsigned negative = 0; negative < 4; ++negative)
  {
    ProdigyAegisSession client, server;
    expect(establish(client, server), "negative_record_fixture");
    String frame = {}, second = {}, plain = "old plaintext"_ctv;
    ProdigyAegisSession::Record kind;
    client.encrypt(ProdigyAegisSession::Record::application, psk.data(), psk.size(), frame);
    if (negative == 0) frame.data()[frame.size() - 1] ^= 1;
    if (negative == 1) frame.data()[2] ^= 1;
    if (negative == 2) frame.data()[3] = 1;
    if (negative == 3)
    {
      client.encrypt(ProdigyAegisSession::Record::application, psk.data(), psk.size(), second);
      frame = std::move(second);
    }
    expect(!server.decrypt(frame.data(), frame.size(), kind, plain) && server.failedClosed() && plain.empty(),
           "tamper_reflection_reserved_bits_or_reordering_fail_closed");
  }
  for (unsigned negative = 0; negative < 3; ++negative)
  {
    ProdigyAegisSession client, server;
    auto wrongPSK = psk;
    String context = "cluster-A/brain-1/neuron-2/epoch-3"_ctv;
    String otherContext = context;
    if (negative == 0) wrongPSK[0] ^= 1;
    if (negative == 1) otherContext = "cluster-B/brain-1/neuron-2/epoch-3"_ctv;
    if (negative == 2) otherContext = "cluster-A/neuron-1/brain-2/epoch-3"_ctv;
    std::array<uint8_t, 48> first = {};
    expect(client.begin(psk.data(), context, true) && server.begin(wrongPSK.data(), otherContext, false) &&
               client.writeHandshake(first) && !server.readHandshake(first.data(), first.size()) && server.failedClosed(),
           "wrong_psk_cluster_or_role_binding_rejected");
  }
  {
    ProdigyAegisSession client, firstServer, replayServer;
    const String context = "replay-isolation-test"_ctv;
    std::array<uint8_t, 48> first = {}, response = {}, freshResponse = {};
    bool ok = client.begin(psk.data(), context, true) && firstServer.begin(psk.data(), context, false) &&
              replayServer.begin(psk.data(), context, false) && client.writeHandshake(first) &&
              firstServer.readHandshake(first.data(), first.size()) && replayServer.readHandshake(first.data(), first.size()) &&
              firstServer.writeHandshake(response) && replayServer.writeHandshake(freshResponse) && response != freshResponse &&
              client.readHandshake(response.data(), response.size());
    String confirmation = {}, unused = {}, plain = {};
    ProdigyAegisSession::Record kind;
    ok = ok && client.encrypt(ProdigyAegisSession::Record::confirmation, nullptr, 0, confirmation) &&
         replayServer.encrypt(ProdigyAegisSession::Record::confirmation, nullptr, 0, unused);
    expect(ok && !replayServer.decrypt(confirmation.data(), confirmation.size(), kind, plain),
           "replayed_first_handshake_cannot_replay_session_confirmation");
  }
  {
    ProdigyAegisSession client, server, newClient, newServer;
    expect(establish(client, server) && establish(newClient, newServer), "restart_session_fixture");
    String frame = {}, plain = {};
    ProdigyAegisSession::Record kind;
    client.encrypt(ProdigyAegisSession::Record::application, psk.data(), psk.size(), frame);
    expect(!newServer.decrypt(frame.data(), frame.size(), kind, plain), "old_session_record_rejected_after_restart");
    expect(client.encrypt(ProdigyAegisSession::Record::close, nullptr, 0, frame) &&
               !client.encrypt(ProdigyAegisSession::Record::application, psk.data(), psk.size(), plain),
           "authenticated_close_prevents_further_application_records");
  }
  {
    ProdigyTransportTLSStream client, server;
    client.rBuffer.reserve(8192); server.rBuffer.reserve(8192);
    client.wBuffer.reserve(16 * 1024); server.wBuffer.reserve(16 * 1024);
    const String context = "tcp/cluster-1/brain-11/neuron-22/epoch-1"_ctv;
    bool ok = client.beginTransportAEGIS(false, psk.data(), context, 11, 22) &&
              server.beginTransportAEGIS(true, psk.data(), context, 22, 11) && connectedPair(client.fd, server.fd);
    for (unsigned i = 0; ok && i < 10000 && (!client.isTransportNegotiated() || !server.isTransportNegotiated()); ++i)
      ok = pumpSocket(client, server, 7, 5) && pumpSocket(server, client, 11, 3);
    expect(ok && client.isTransportNegotiated() && server.isTransportNegotiated() &&
               client.tlsPeerVerified && client.tlsPeerUUID == 22 && server.tlsPeerVerified && server.tlsPeerUUID == 11 &&
               !client.transportTLSEnabled() && client.transportAEGISEnabled(),
           "tcp_fragmented_handshake_uses_existing_stream_and_bound_peer_identity");
    String payload = {};
    payload.reserve(200000);
    for (unsigned i = 0; i < 200000; ++i) payload.append(uint8_t(i));
    ok = ok && client.wBuffer.need(payload.size());
    if (ok) client.wBuffer.append(payload);
    for (unsigned i = 0; ok && i < 10000 && server.rBuffer.outstandingBytes() < payload.size(); ++i)
      ok = pumpSocket(client, server);
    expect(ok && server.rBuffer.outstandingBytes() == payload.size() &&
               std::memcmp(server.rBuffer.pHead(), payload.data(), payload.size()) == 0,
           "tcp_partial_writes_multiple_records_preserve_application_bytes");
    ok = server.rBuffer.need(32);
    if (ok) std::memset(server.rBuffer.pTail(), 0, 32);
    expect(ok && !server.decryptTransportTLS(32) && server.rBuffer.outstandingBytes() == 0 &&
               !server.tlsPeerVerified, "terminal_record_failure_discards_previously_buffered_plaintext");
    if (client.fd >= 0) { close(client.fd); client.fd = -1; }
    if (server.fd >= 0) { close(server.fd); server.fd = -1; }
    client.reset(); server.reset();
    expect(!client.transportEncryptionEnabled() && !server.tlsPeerVerified && client.rBuffer.empty() &&
               server.rBuffer.empty(), "stream_reset_clears_session_and_plaintext_generation");
  }
  {
    ProdigyTransportTLSStream client, server;
    const String context = "identical-credential-context"_ctv;
    bool ok = client.beginTransportAEGIS(false, psk.data(), context, 11, 22) &&
              server.beginTransportAEGIS(true, psk.data(), context, 22, 99) && connectedPair(client.fd, server.fd);
    bool rejected = false;
    for (unsigned i = 0; ok && i < 1000; ++i)
      if (!pumpSocket(client, server) || !pumpSocket(server, client)) { rejected = true; break; }
    expect(ok && rejected && !server.tlsPeerVerified && !server.isTransportNegotiated(),
           "stream_asserted_peer_uuid_is_bound_even_when_credential_context_omits_it");
    if (client.fd >= 0) { close(client.fd); client.fd = -1; }
    if (server.fd >= 0) { close(server.fd); server.fd = -1; }
  }
  for (unsigned variant = 0; variant < 3; ++variant)
  {
    ProdigyTransportTLSStream client, server;
    const String clientHint = "public-node-11/role-brain/epoch-9"_ctv;
    const String serverHint = "public-node-22/role-neuron/epoch-9"_ctv;
    auto clientResolver = [&](const String& hint, std::array<uint8_t, 32>& key, String& context, uint128_t& peer) {
      if (hint != serverHint) return false;
      key = psk; context.assign("credential-owner-authorized-purpose"_ctv); peer = 22; return true;
    };
    auto serverResolver = [&](const String& hint, std::array<uint8_t, 32>& key, String& context, uint128_t& peer) {
      if (variant == 1 || (variant == 0 && hint != clientHint)) return false;
      key = psk; context.assign("credential-owner-authorized-purpose"_ctv); peer = 11; return true;
    };
    bool ok = client.beginTransportAEGISWithPrelude(false, 11, clientHint, clientResolver) &&
              server.beginTransportAEGISWithPrelude(true, 22, serverHint, serverResolver) &&
              !client.tlsPeerVerified && !server.tlsPeerVerified && connectedPair(client.fd, server.fd);
    if (ok && variant == 2)
    {
      ok = client.prepareTransportTLSSend() && client.encryptedBytesToSend() > 8;
      if (ok) client.pBytesToSend()[8] ^= 1;
    }
    bool rejected = false;
    for (unsigned i = 0; ok && i < 10000 && (!client.isTransportNegotiated() || !server.isTransportNegotiated()); ++i)
      if (!pumpSocket(client, server, 7, 5) || !pumpSocket(server, client, 11, 3)) { rejected = true; break; }
    if (variant == 0)
      expect(ok && !rejected && client.isTransportNegotiated() && server.isTransportNegotiated() &&
                 client.tlsPeerUUID == 22 && server.tlsPeerUUID == 11,
             "bounded_public_prelude_lookup_then_mutual_identity_proof");
    else
      expect(ok && rejected && !server.tlsPeerVerified && !server.isTransportNegotiated(),
             "unauthorized_or_transcript_tampered_public_prelude_fails_closed");
    if (client.fd >= 0) { close(client.fd); client.fd = -1; }
    if (server.fd >= 0) { close(server.fd); server.fd = -1; }
  }
  for (unsigned variant = 0; variant < 4; ++variant)
  {
    ProdigyTransportTLSStream client, server;
    client.rBuffer.reserve(8192); server.rBuffer.reserve(8192);
    client.wBuffer.reserve(16 * 1024); server.wBuffer.reserve(16 * 1024);
    const String clientHint = variant == 1 ? String("unapproved-client-claim"_ctv) : String("pair-9/client-11"_ctv);
    const String selectedServerHint = "pair-9/server-22"_ctv;
    auto clientResolver = [&](const String& hint, std::array<uint8_t, 32>& key, String& context, uint128_t& peer) {
      if (hint != selectedServerHint) return false;
      key = psk; context.assign("pair-carrier/deferred-selection"_ctv); peer = 22; return true;
    };
    auto deferredServerResolver = [&](const String& hint, String& localHint,
                                      std::array<uint8_t, 32>& key, String& context, uint128_t& peer) {
      if (variant == 1 || hint != "pair-9/client-11"_ctv) return false;
      if (variant == 2) { localHint.resize(513); return true; }
      localHint.assign(selectedServerHint); key = psk;
      context.assign("pair-carrier/deferred-selection"_ctv); peer = 11; return true;
    };
    const bool successVariant = variant == 0 || variant == 3;
    bool ok = client.beginTransportAEGISWithPrelude(false, 11, clientHint, clientResolver) &&
              server.beginTransportAEGISWithDeferredServerPrelude(22, deferredServerResolver) &&
              connectedPair(client.fd, server.fd);
    if (ok && successVariant)
      expect(client.prepareTransportTLSSend() && client.encryptedBytesToSend() == 8 + clientHint.size(),
             "fixed_prelude_initiator_first_flight_is_pga_only_until_peer_claim_resolves");
    const String early = "must-not-arrive-before-auth"_ctv;
    if (ok && successVariant) ok = client.wBuffer.need(early.size());
    if (ok && successVariant) client.wBuffer.append(early);
    bool rejected = false, earlyLeak = false;
    const uint32_t clientSend = variant == 3 ? 8192 : 5, serverRecv = variant == 3 ? 8192 : 3;
    const uint32_t serverSend = variant == 3 ? 8192 : 7, clientRecv = variant == 3 ? 8192 : 4;
    for (unsigned i = 0; ok && i < 10000 && (!client.isTransportNegotiated() || !server.isTransportNegotiated()); ++i)
    {
      if (!pumpSocket(client, server, clientSend, serverRecv)) { rejected = true; break; }
      if (!server.isTransportNegotiated() && !server.rBuffer.empty()) earlyLeak = true;
      if (!pumpSocket(server, client, serverSend, clientRecv)) { rejected = true; break; }
    }
    if (successVariant)
    {
      expect(ok && !rejected && client.isTransportNegotiated() && server.isTransportNegotiated() &&
                 client.tlsPeerUUID == 22 && server.tlsPeerUUID == 11 && !earlyLeak,
             variant == 3 ? "deferred_server_prelude_coalesced_handshake_withholds_unauthenticated_application"
                          : "deferred_server_prelude_fragmented_handshake_withholds_unauthenticated_application");
      for (unsigned i = 0; ok && i < 10000 && server.rBuffer.outstandingBytes() < early.size(); ++i)
        ok = pumpSocket(client, server, clientSend, serverRecv) && pumpSocket(server, client, serverSend, clientRecv);
      expect(ok && server.rBuffer.outstandingBytes() == early.size() &&
                 std::memcmp(server.rBuffer.pHead(), early.data(), early.size()) == 0,
             "deferred_server_prelude_releases_queued_application_only_after_mutual_confirmation");
    }
    else
    {
      expect(ok && rejected && !server.tlsPeerVerified && !server.isTransportNegotiated(),
             variant == 1 ? "deferred_server_prelude_rejects_unknown_public_claim"
                          : "deferred_server_prelude_rejects_oversized_selected_local_claim");
    }
    if (client.fd >= 0) { close(client.fd); client.fd = -1; }
    if (server.fd >= 0) { close(server.fd); server.fd = -1; }
  }
  return failures == 0 ? 0 : 1;
}
