// G6 physical-boundary probe.  This binary never changes routes, DNS, BPF, or
// host networking; it only opens application sockets and writes JSONL results.
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

namespace {
bool sha256(const char *value) {
  if (!value || std::strlen(value) != 64) return false;
  for (const char *p = value; *p; ++p)
    if (!std::strchr("0123456789abcdef", *p)) return false;
  return true;
}
std::string json(const char *value) {
  std::string result = "\"";
  for (; value && *value; ++value) {
    if (*value == '\\' || *value == '\"') result += '\\';
    if (static_cast<unsigned char>(*value) < 0x20) return "\"invalid-control-character\"";
    result += *value;
  }
  return result + "\"";
}
long long monotonicNs() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
}
std::string timestamp() {
  std::time_t now = std::time(nullptr); char buffer[32] = {};
  std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&now));
  return buffer;
}
void emit(const char *method, const char *status, const std::string& detail) {
  const char *commit = std::getenv("G6_PROBE_CANDIDATE_COMMIT");
  const char *artifact = std::getenv("G6_PROBE_ARTIFACT_SHA256");
  const char *row = std::getenv("G6_PROBE_ROW");
  if (!commit || std::strlen(commit) != 40 || !sha256(artifact) || !row || !*row) {
    std::fprintf(stderr, "G6 probe requires G6_PROBE_CANDIDATE_COMMIT, G6_PROBE_ARTIFACT_SHA256, and G6_PROBE_ROW\n");
    std::exit(2);
  }
  std::printf("{\"artifactSHA256\":%s,\"candidateCommit\":%s,\"detail\":%s,\"method\":%s,\"monotonicNs\":%lld,\"observedAt\":%s,\"row\":%s,\"schemaVersion\":1,\"status\":%s}\n",
      json(artifact).c_str(), json(commit).c_str(), detail.c_str(), json(method).c_str(), monotonicNs(),
      json(timestamp().c_str()).c_str(), json(row).c_str(), json(status).c_str());
  std::fflush(stdout);
}
int connectTcp(const char *host, const char *port, int family) {
  addrinfo hints = {}; hints.ai_family = family; hints.ai_socktype = SOCK_STREAM;
  addrinfo *answers = nullptr;
  if (getaddrinfo(host, port, &hints, &answers) != 0) return -1;
  int fd = -1;
  for (addrinfo *answer = answers; answer; answer = answer->ai_next) {
    fd = socket(answer->ai_family, answer->ai_socktype | SOCK_CLOEXEC, answer->ai_protocol);
    if (fd >= 0 && connect(fd, answer->ai_addr, answer->ai_addrlen) == 0) break;
    if (fd >= 0) close(fd); fd = -1;
  }
  freeaddrinfo(answers); return fd;
}
std::string tcpDetail(const char *host, const char *port, int family, size_t bytes, bool reverse,
                      bool& passed) {
  passed = false;
  int fd = connectTcp(host, port, family);
  if (fd < 0) return "{\"connectSucceeded\":false,\"family\":" + std::to_string(family) + "}";
  std::vector<char> payload(bytes, 'p'); ssize_t written = send(fd, payload.data(), payload.size(), MSG_NOSIGNAL);
  std::vector<char> response(bytes); ssize_t received = written > 0 ? recv(fd, response.data(), response.size(), 0) : -1;
  sockaddr_storage local = {}, peer = {}; socklen_t localLength = sizeof(local), peerLength = sizeof(peer);
  (void)getsockname(fd, reinterpret_cast<sockaddr*>(&local), &localLength);
  (void)getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &peerLength);
  close(fd);
  passed = written == static_cast<ssize_t>(bytes) && received == static_cast<ssize_t>(bytes) &&
      response == payload;
  return "{\"connectSucceeded\":true,\"family\":" + std::to_string(family) +
      ",\"payloadBytes\":" + std::to_string(bytes) + ",\"payloadMatched\":" + (passed ? "true" : "false") +
      ",\"receivedBytes\":" + std::to_string(received < 0 ? 0 : received) +
      ",\"reverseIngress\":" + (reverse ? "true" : "false") + ",\"role\":\"client\",\"sentBytes\":" + std::to_string(written < 0 ? 0 : written) + "}";
}
int tcp(const char *method, int argc, char **argv, bool reverse) {
  if (argc != 5) return 2;
  const int family = std::strcmp(argv[2], "4") == 0 ? AF_INET : std::strcmp(argv[2], "6") == 0 ? AF_INET6 : 0;
  if (!family) return 2;
  char *end = nullptr; const unsigned long bytes = std::strtoul(argv[4], &end, 10);
  if (!end || *end || bytes == 0 || bytes > 1024 * 1024) return 2;
  bool passed = false;
  const std::string detail = tcpDetail(argv[1], argv[3], family, bytes, reverse, passed);
  emit(method, passed ? "pass" : "fail", detail);
  return passed ? 0 : 1;
}
int unprovenTcp(const char *method, const char *reason, int argc, char **argv, bool reverse) {
  if (argc != 5) return 2;
  const int family = std::strcmp(argv[2], "4") == 0 ? AF_INET : std::strcmp(argv[2], "6") == 0 ? AF_INET6 : 0;
  if (!family) return 2;
  char *end = nullptr; const unsigned long bytes = std::strtoul(argv[4], &end, 10);
  if (!end || *end || bytes == 0 || bytes > 1024 * 1024) return 2;
  bool connected = false;
  std::string detail = tcpDetail(argv[1], argv[3], family, bytes, reverse, connected);
  if (!detail.empty() && detail.back() == '}') detail.pop_back();
  detail += ",\"reason\":" + json(reason) + "}";
  emit(method, connected ? "unproven" : "fail", detail);
  return 1;
}
int server(int argc, char **argv) {
  if (argc != 3) return 2;
  const int family = std::strcmp(argv[1], "4") == 0 ? AF_INET : std::strcmp(argv[1], "6") == 0 ? AF_INET6 : 0;
  if (!family) return 2;
  char *end = nullptr; const unsigned long port = std::strtoul(argv[2], &end, 10);
  if (!end || *end || port == 0 || port > 65535) return 2;
  int listener = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0); int enabled = 1;
  if (listener < 0 || setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) return 1;
  sockaddr_storage address = {}; address.ss_family = family;
  if (family == AF_INET) reinterpret_cast<sockaddr_in*>(&address)->sin_port = htons(port);
  else reinterpret_cast<sockaddr_in6*>(&address)->sin6_port = htons(port);
  if (bind(listener, reinterpret_cast<sockaddr*>(&address), family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6)) != 0 || listen(listener, 1) != 0) { close(listener); return 1; }
  int peer = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC); close(listener);
  char buffer[65536]; ssize_t received = peer >= 0 ? recv(peer, buffer, sizeof(buffer), 0) : -1;
  ssize_t sent = received > 0 ? send(peer, buffer, size_t(received), MSG_NOSIGNAL) : -1;
  if (peer >= 0) close(peer);
  emit("tcp-connect-bidirectional", received > 0 && sent == received ? "pass" : "fail",
       "{\"family\":" + std::to_string(family) + ",\"receivedBytes\":" + std::to_string(received > 0 ? received : 0) +
       ",\"role\":\"server\",\"sentBytes\":" + std::to_string(sent > 0 ? sent : 0) + "}");
  return received > 0 && sent == received ? 0 : 1;
}
int dns(int argc, char **argv) {
  if (argc != 2) return 2;
  addrinfo hints = {}; hints.ai_socktype = SOCK_STREAM; addrinfo *answers = nullptr;
  const int result = getaddrinfo(argv[1], nullptr, &hints, &answers);
  int addresses = 0; for (addrinfo *p = answers; p; p = p->ai_next) ++addresses;
  if (answers) freeaddrinfo(answers);
  // libc does not expose TTL or whether an answer was cache-served.  Do not claim it.
  emit("dns-ttl-cache-expiry", "unproven", "{\"addresses\":" + std::to_string(addresses) +
      ",\"getaddrinfoStatus\":" + std::to_string(result) + ",\"reason\":\"libc-does-not-expose-dns-ttl-or-cache-state\"}");
  return 1;
}
int tls(int argc, char **argv) {
  if (argc != 4) return 2;
  const char *cert = std::getenv("G6_PROBE_TLS_CERT"); const char *key = std::getenv("G6_PROBE_TLS_KEY");
  const char *ca = std::getenv("G6_PROBE_TLS_CA");
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) { emit("tls13-sni-mutual-identity", "fail", "{\"reason\":\"ssl-context\"}"); return 1; }
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION); SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  bool configured = cert && key && ca && SSL_CTX_use_certificate_chain_file(ctx, cert) == 1 &&
      SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) == 1 && SSL_CTX_load_verify_locations(ctx, ca, nullptr) == 1;
  int fd = configured ? connectTcp(argv[1], argv[2], AF_UNSPEC) : -1; SSL *ssl = fd >= 0 ? SSL_new(ctx) : nullptr;
  int ok = ssl ? (SSL_set_tlsext_host_name(ssl, argv[3]) == 1 && SSL_set_fd(ssl, fd) == 1 && SSL_connect(ssl) == 1) : 0;
  const char *version = ok ? SSL_get_version(ssl) : "";
  // A client-side handshake proves neither that the peer required this identity nor its semantic authorization.
  std::string detail = "{\"clientCertificateConfigured\":" + std::string(configured ? "true" : "false") +
      ",\"negotiatedVersion\":" + json(version) + ",\"serverAcceptedClientIdentity\":null,\"sni\":" + json(argv[3]) + "}";
  if (ssl) SSL_free(ssl); if (fd >= 0) close(fd); SSL_CTX_free(ctx);
  emit("tls13-sni-mutual-identity", ok ? "unproven" : "fail", detail); return 1;
}
}
int main(int argc, char **argv) {
  if (argc < 2) return 2;
  if (std::strcmp(argv[1], "tcp") == 0) return tcp("tcp-connect-bidirectional", argc - 1, argv + 1, false);
  if (std::strcmp(argv[1], "server") == 0) return server(argc - 1, argv + 1);
  if (std::strcmp(argv[1], "ipv4") == 0) return tcp("tcp-ipv4", argc - 1, argv + 1, false);
  if (std::strcmp(argv[1], "ipv6") == 0) return unprovenTcp("cousin-ipv6-session", "raw-ipv6-tcp-does-not-prove-cousin", argc - 1, argv + 1, false);
  if (std::strcmp(argv[1], "pmtu") == 0) return unprovenTcp("tcp-payload-path-mtu", "tcp-echo-does-not-prove-kernel-path-mtu", argc - 1, argv + 1, false);
  if (std::strcmp(argv[1], "reverse") == 0) return unprovenTcp("ingress-relay-reverse-connect", "outbound-connect-does-not-prove-relay-ingress-traversal", argc - 1, argv + 1, true);
  if (std::strcmp(argv[1], "dns") == 0) return dns(argc - 1, argv + 1);
  if (std::strcmp(argv[1], "tls") == 0) return tls(argc - 1, argv + 1);
  return 2;
}
