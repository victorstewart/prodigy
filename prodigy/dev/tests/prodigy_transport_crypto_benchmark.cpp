// CPU-only transport crypto comparison for the pinned guest. This uses an
// in-memory stream pump: it measures neither sockets, routing, scheduling, nor
// cluster behavior. Certificate generation and global TLS context parsing are
// completed before each timed handshake. Timed handshake boundaries are from
// the first in-memory handshake pump through authenticated peer-ID validation.
// Timed steady-state boundaries are from the first queued 4 KiB application
// record through validation of the final delivered payload.
#include <prodigy/transport.tls.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>

constexpr uint32_t samples = 100;
constexpr uint32_t records = 1000;
constexpr uint32_t payloadBytes = 4096;
constexpr uint128_t clientUUID = (uint128_t(0x1111222233334444ULL) << 64) | uint128_t(0x5555666677778888ULL);
constexpr uint128_t serverUUID = (uint128_t(0x9999AAAABBBBCCCCULL) << 64) | uint128_t(0xDDDDEEEEFFFF0001ULL);

struct Credentials {
  String rootCert, rootKey, clientCert, clientKey, serverCert, serverKey;
};

static bool configure(uint128_t uuid, const Credentials& credentials, bool client)
{
  ProdigyTransportTLSBootstrap bootstrap = {};
  bootstrap.uuid = uuid;
  bootstrap.transport.generation = 1;
  bootstrap.transport.clusterRootCertPem = credentials.rootCert;
  bootstrap.transport.clusterRootKeyPem = credentials.rootKey;
  bootstrap.transport.localCertPem = client ? credentials.clientCert : credentials.serverCert;
  bootstrap.transport.localKeyPem = client ? credentials.clientKey : credentials.serverKey;
  String failure = {};
  return ProdigyTransportTLSRuntime::configure(bootstrap, &failure) && failure.empty();
}

static void reserve(ProdigyTransportTLSStream& stream)
{
  stream.rBuffer.reserve(256 * 1024);
  stream.wBuffer.reserve(256 * 1024);
}

static bool pump(ProdigyTransportTLSStream& from, ProdigyTransportTLSStream& to, uint64_t& wireBytes)
{
  const uint32_t bytes = from.nBytesToSend();
  if (bytes == 0) return false;
  if (to.rBuffer.remainingCapacity() < bytes && !to.rBuffer.reserve(to.rBuffer.size() + bytes)) return false;
  from.noteSendQueued();
  std::memcpy(to.rBuffer.pTail(), from.pBytesToSend(), bytes);
  const bool ok = to.decryptTransportTLS(bytes);
  from.consumeSentBytes(bytes, false);
  from.noteSendCompleted();
  if (ok) wireBytes += bytes;
  return ok;
}

static bool complete(ProdigyTransportTLSStream& client, ProdigyTransportTLSStream& server, uint64_t& wireBytes)
{
  for (unsigned round = 0; round != 256; ++round)
  {
    bool progressed = false;
    if (client.needsTransportTLSSendKick() || client.nBytesToSend() != 0)
    {
      if (!pump(client, server, wireBytes)) return false;
      progressed = true;
    }
    if (server.needsTransportTLSSendKick() || server.nBytesToSend() != 0)
    {
      if (!pump(server, client, wireBytes)) return false;
      progressed = true;
    }
    uint128_t clientPeer = 0, serverPeer = 0;
    if (client.isTransportNegotiated() && server.isTransportNegotiated() &&
        client.extractAuthenticatedPeerUUID(clientPeer) && server.extractAuthenticatedPeerUUID(serverPeer))
      return clientPeer == serverUUID && serverPeer == clientUUID;
    if (!progressed) return false;
  }
  return false;
}

static bool beginTLS(ProdigyTransportTLSStream& client, ProdigyTransportTLSStream& server, const Credentials& credentials)
{
  client.reset(); server.reset(); reserve(client); reserve(server);
  return configure(clientUUID, credentials, true) && client.beginTransportTLS(false) &&
         configure(serverUUID, credentials, false) && server.beginTransportTLS(true);
}

static bool beginAEGIS(ProdigyTransportTLSStream& client, ProdigyTransportTLSStream& server, const std::array<uint8_t, 32>& psk)
{
  client.reset(); server.reset(); reserve(client); reserve(server);
  const String context = "benchmark/authorized-cluster-pair/workload/service/slot-range/epoch-1"_ctv;
  return client.beginTransportAEGIS(false, psk.data(), context, clientUUID, serverUUID) &&
         server.beginTransportAEGIS(true, psk.data(), context, serverUUID, clientUUID);
}

template <typename Begin>
static bool handshakeSamples(Begin begin, bool reconnect, std::vector<uint64_t>& elapsed, std::vector<uint64_t>& wire)
{
  ProdigyTransportTLSStream reusedClient = {}, reusedServer = {};
  for (unsigned sample = 0; sample != samples; ++sample)
  {
    ProdigyTransportTLSStream coldClient = {}, coldServer = {};
    ProdigyTransportTLSStream& client = reconnect ? reusedClient : coldClient;
    ProdigyTransportTLSStream& server = reconnect ? reusedServer : coldServer;
    if (!begin(client, server)) return false; // setup/context parsing intentionally excluded.
    uint64_t bytes = 0;
    const auto start = std::chrono::steady_clock::now();
    const bool ok = complete(client, server, bytes);
    const auto stop = std::chrono::steady_clock::now();
    if (!ok) return false;
    elapsed.push_back(uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count()));
    wire.push_back(bytes);
  }
  return true;
}

template <typename Begin>
static bool steady(Begin begin, uint64_t& elapsedMicroseconds, uint64_t& wireBytes)
{
  ProdigyTransportTLSStream client = {}, server = {};
  if (!begin(client, server) || !complete(client, server, wireBytes)) return false;
  String payload = {};
  if (!payload.reserve(payloadBytes)) return false;
  for (uint32_t i = 0; i != payloadBytes; ++i) payload.append(uint8_t(i));
  wireBytes = 0; // Handshake is deliberately excluded from steady-state measurement.
  const auto start = std::chrono::steady_clock::now();
  for (unsigned record = 0; record != records; ++record)
  {
    if (!client.wBuffer.need(payload.size())) return false;
    client.wBuffer.append(payload);
    for (unsigned round = 0; round != 64 && server.rBuffer.outstandingBytes() < payload.size(); ++round)
      if (!pump(client, server, wireBytes)) return false;
    if (server.rBuffer.outstandingBytes() != payload.size() ||
        std::memcmp(server.rBuffer.pHead(), payload.data(), payload.size()) != 0) return false;
    server.rBuffer.consume(server.rBuffer.outstandingBytes(), true);
  }
  const auto stop = std::chrono::steady_clock::now();
  elapsedMicroseconds = uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count());
  return true;
}

static uint64_t percentile(std::vector<uint64_t> values, unsigned numerator)
{
  std::sort(values.begin(), values.end());
  return values[(values.size() - 1) * numerator / 100];
}

static uint64_t medianWire(std::vector<uint64_t> values) { return percentile(std::move(values), 50); }

static bool makeCredentials(Credentials& out)
{
  String failure = {};
  if (!Vault::generateTransportRootCertificateEd25519(out.rootCert, out.rootKey, &failure) || !failure.empty()) return false;
  if (!Vault::generateTransportNodeCertificateEd25519(out.rootCert, out.rootKey, clientUUID, {}, out.clientCert, out.clientKey, &failure) || !failure.empty()) return false;
  return Vault::generateTransportNodeCertificateEd25519(out.rootCert, out.rootKey, serverUUID, {}, out.serverCert, out.serverKey, &failure) && failure.empty();
}

static void printProfile(const char *name, const std::vector<uint64_t>& cold, const std::vector<uint64_t>& reconnect,
                         const std::vector<uint64_t>& coldWire, const std::vector<uint64_t>& reconnectWire,
                         uint64_t steadyUs, uint64_t steadyWire)
{
  const double mib = double(records * payloadBytes) / (1024.0 * 1024.0);
  const double mibps = steadyUs == 0 ? 0.0 : mib * 1000000.0 / double(steadyUs);
  std::printf("{\"profile\":\"%s\",\"workload\":\"pinned_guest_in_memory_stream_pump_cpu_only\",\"cold\":{\"samples\":100,\"p50_us\":%llu,\"p95_us\":%llu,\"wire_bytes_p50\":%llu},\"reconnect\":{\"samples\":100,\"p50_us\":%llu,\"p95_us\":%llu,\"wire_bytes_p50\":%llu},\"steady\":{\"records\":1000,\"record_payload_bytes\":4096,\"total_us\":%llu,\"wire_bytes\":%llu,\"mibps\":%.3f}}\n",
              name, (unsigned long long)percentile(cold, 50), (unsigned long long)percentile(cold, 95), (unsigned long long)medianWire(coldWire),
              (unsigned long long)percentile(reconnect, 50), (unsigned long long)percentile(reconnect, 95), (unsigned long long)medianWire(reconnectWire),
              (unsigned long long)steadyUs, (unsigned long long)steadyWire, mibps);
}

int main()
{
  Credentials credential = {};
  if (!makeCredentials(credential)) return 1; // certificate generation excluded from all timing.
  std::array<uint8_t, 32> psk = {};
  for (unsigned i = 0; i != psk.size(); ++i) psk[i] = uint8_t(0x80 + i);

  auto tls = [&](ProdigyTransportTLSStream& client, ProdigyTransportTLSStream& server) { return beginTLS(client, server, credential); };
  auto aegis = [&](ProdigyTransportTLSStream& client, ProdigyTransportTLSStream& server) { return beginAEGIS(client, server, psk); };
  std::vector<uint64_t> tlsCold, tlsReconnect, tlsColdWire, tlsReconnectWire, aegisCold, aegisReconnect, aegisColdWire, aegisReconnectWire;
  uint64_t tlsSteadyUs = 0, tlsSteadyWire = 0, aegisSteadyUs = 0, aegisSteadyWire = 0;
  const bool ok = handshakeSamples(tls, false, tlsCold, tlsColdWire) && handshakeSamples(tls, true, tlsReconnect, tlsReconnectWire) &&
                  handshakeSamples(aegis, false, aegisCold, aegisColdWire) && handshakeSamples(aegis, true, aegisReconnect, aegisReconnectWire) &&
                  steady(tls, tlsSteadyUs, tlsSteadyWire) && steady(aegis, aegisSteadyUs, aegisSteadyWire);
  OPENSSL_cleanse(psk.data(), psk.size());
  if (!ok) return 1;
  printProfile("tls13_ed25519_x25519", tlsCold, tlsReconnect, tlsColdWire, tlsReconnectWire, tlsSteadyUs, tlsSteadyWire);
  printProfile("noise_nnpsk0_x25519_aegis128l", aegisCold, aegisReconnect, aegisColdWire, aegisReconnectWire, aegisSteadyUs, aegisSteadyWire);
  return 0;
}
