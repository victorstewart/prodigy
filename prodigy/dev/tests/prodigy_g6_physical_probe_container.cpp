// G6 physical-boundary probe.  This binary never changes routes, DNS, BPF, or
// host networking; it only opens application sockets and writes JSONL results.
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
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
constexpr int kSocketDeadlineMs = 5000;
bool nonblocking(int fd) { int flags = fcntl(fd, F_GETFL); return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0; }
bool waitFd(int fd, short events, int timeoutMs = kSocketDeadlineMs) { pollfd p = {}; p.fd = fd; p.events = events; while (true) { int rc = poll(&p, 1, timeoutMs); if (rc > 0) return (p.revents & events) != 0; if (rc == 0 || errno != EINTR) return false; } }
bool connectTimed(int fd, const sockaddr *address, socklen_t length) { if (!nonblocking(fd)) return false; if (connect(fd, address, length) == 0) return true; if (errno != EINPROGRESS || !waitFd(fd, POLLOUT)) return false; int error = 0; socklen_t errorLength = sizeof(error); return getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errorLength) == 0 && error == 0; }
bool sslConnectTimed(SSL *ssl) { for (;;) { int rc = SSL_connect(ssl); if (rc == 1) return true; int error = SSL_get_error(ssl, rc); if (error == SSL_ERROR_WANT_READ && waitFd(SSL_get_fd(ssl), POLLIN)) continue; if (error == SSL_ERROR_WANT_WRITE && waitFd(SSL_get_fd(ssl), POLLOUT)) continue; return false; } }
bool sendAll(int fd, const std::string& value);
bool receiveExact(int fd, const std::string& expected);
bool sha256(const char *value) {
  if (!value || std::strlen(value) != 64) return false;
  for (const char *p = value; *p; ++p)
    if (!std::strchr("0123456789abcdef", *p)) return false;
  return true;
}
bool byoIpv6(const char *value) {
  in6_addr address = {};
  return value && inet_pton(AF_INET6, value, &address) == 1 &&
      address.s6_addr[0] == 0x26 && address.s6_addr[1] == 0x02 &&
      address.s6_addr[2] == 0xfa && address.s6_addr[3] == 0xc0 &&
      address.s6_addr[4] == 0x00;
}
std::string ipv6Address(const sockaddr_storage& address) {
  char text[INET6_ADDRSTRLEN] = {};
  return address.ss_family == AF_INET6 &&
      inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(&address)->sin6_addr,
                text, sizeof(text)) ? text : "";
}
std::string normalizedIpv6(const char *value) {
  in6_addr address = {}; char text[INET6_ADDRSTRLEN] = {};
  return value && inet_pton(AF_INET6, value, &address) == 1 &&
      inet_ntop(AF_INET6, &address, text, sizeof(text)) ? text : "";
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
    if (fd >= 0 && connectTimed(fd, answer->ai_addr, answer->ai_addrlen)) break;
    if (fd >= 0) close(fd); fd = -1;
  }
  freeaddrinfo(answers); return fd;
}
std::string tcpDetail(const char *host, const char *port, int family, size_t bytes, bool reverse,
                      bool& passed) {
  passed = false;
  int fd = connectTcp(host, port, family);
  if (fd < 0) return "{\"connectSucceeded\":false,\"family\":" + std::to_string(family) + "}";
  std::vector<char> payload(bytes, 'p'); const std::string request(payload.begin(), payload.end());
  const bool written = sendAll(fd, request); std::string response(bytes, '\0'); const bool received = written && receiveExact(fd, response);
  sockaddr_storage local = {}, peer = {}; socklen_t localLength = sizeof(local), peerLength = sizeof(peer);
  (void)getsockname(fd, reinterpret_cast<sockaddr*>(&local), &localLength);
  (void)getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &peerLength);
  close(fd);
  passed = written && received && response == request;
  return "{\"connectSucceeded\":true,\"family\":" + std::to_string(family) +
      ",\"payloadBytes\":" + std::to_string(bytes) + ",\"payloadMatched\":" + (passed ? "true" : "false") +
      ",\"receivedBytes\":" + std::to_string(received ? bytes : 0) +
      ",\"reverseIngress\":" + (reverse ? "true" : "false") + ",\"role\":\"client\",\"sentBytes\":" + std::to_string(written ? bytes : 0) + "}";
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
bool sendAll(int fd, const std::string& value) {
  size_t offset = 0;
  while (offset < value.size()) {
    if (!waitFd(fd, POLLOUT)) return false;
    const ssize_t sent = send(fd, value.data() + offset, value.size() - offset, MSG_NOSIGNAL);
    if (sent < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    if (sent <= 0) return false;
    offset += static_cast<size_t>(sent);
  }
  return true;
}
bool receiveExact(int fd, const std::string& expected) {
  std::string received(expected.size(), '\0'); size_t offset = 0;
  while (offset < received.size()) {
    if (!waitFd(fd, POLLIN)) return false;
    const ssize_t count = recv(fd, &received[offset], received.size() - offset, 0);
    if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    if (count <= 0) return false;
    offset += static_cast<size_t>(count);
  }
  return received == expected;
}
int ipv6Ingress(int argc, char **argv) {
  // This command is for an observer outside the Prodigy network.  The deployed
  // Wormhole application must implement this exact request/response protocol.
  if (argc != 4 || !byoIpv6(argv[1]) || !sha256(argv[3])) return 2;
  char *end = nullptr; const unsigned long port = std::strtoul(argv[2], &end, 10);
  if (!end || *end || port == 0 || port > 65535) return 2;
  const std::string request = "PRODIGY_G6_IPV6_INGRESS_CHALLENGE " + std::string(argv[3]) + "\n";
  const std::string response = "PRODIGY_G6_IPV6_INGRESS_RESPONSE " + std::string(argv[3]) + "\n";
  int fd = connectTcp(argv[1], argv[2], AF_INET6); sockaddr_storage peer = {}; socklen_t peerLength = sizeof(peer);
  const bool peerKnown = fd >= 0 && getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &peerLength) == 0;
  const std::string peerAddress = peerKnown ? ipv6Address(peer) : "";
  const std::string targetAddress = normalizedIpv6(argv[1]);
  const bool passed = fd >= 0 && peerKnown && peerAddress == targetAddress && sendAll(fd, request) && receiveExact(fd, response);
  if (fd >= 0) close(fd);
  emit("byo-ipv6-wormhole-ingress", passed ? "pass" : "fail",
       "{\"challenge\":" + json(argv[3]) + ",\"challengeMatched\":" + (passed ? "true" : "false") +
       ",\"family\":10,\"peerAddress\":" + json(peerAddress.c_str()) + ",\"peerIsByoPrefix\":" +
       (byoIpv6(peerAddress.c_str()) ? "true" : "false") + ",\"targetAddress\":" + json(targetAddress.c_str()) +
       ",\"targetPort\":" + std::to_string(port) + "}");
  return passed ? 0 : 1;
}
int whiteholeEgress(int argc, char **argv) {
  // An Internet-reachable observer listens while the Whitehole application
  // connects out, receives a challenge, and returns its matching response.
  if (argc != 4 || !byoIpv6(argv[3]) || !sha256(argv[2])) return 2;
  char *end = nullptr; const unsigned long port = std::strtoul(argv[1], &end, 10);
  if (!end || *end || port == 0 || port > 65535) return 2;
  int listener = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0); int enabled = 1;
  if (listener < 0 || setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0 ||
      setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled)) != 0) return 1;
  sockaddr_in6 address = {}; address.sin6_family = AF_INET6; address.sin6_port = htons(port);
  if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 || listen(listener, 1) != 0) { close(listener); return 1; }
  sockaddr_storage peer = {}; socklen_t peerLength = sizeof(peer); int fd = waitFd(listener, POLLIN) ? accept4(listener, reinterpret_cast<sockaddr*>(&peer), &peerLength, SOCK_CLOEXEC | SOCK_NONBLOCK) : -1; close(listener);
  const std::string peerAddress = fd >= 0 ? ipv6Address(peer) : "";
  const std::string expectedSourceAddress = normalizedIpv6(argv[3]);
  const std::string request = "PRODIGY_G6_WHITEHOLE_EGRESS_CHALLENGE " + std::string(argv[2]) + "\n";
  const std::string response = "PRODIGY_G6_WHITEHOLE_EGRESS_RESPONSE " + std::string(argv[2]) + "\n";
  const bool passed = fd >= 0 && peerAddress == expectedSourceAddress && sendAll(fd, request) && receiveExact(fd, response);
  if (fd >= 0) close(fd);
  emit("byo-ipv6-whitehole-egress-source", passed ? "pass" : "fail",
       "{\"challenge\":" + json(argv[2]) + ",\"challengeMatched\":" + (passed ? "true" : "false") +
       ",\"expectedSourceAddress\":" + json(expectedSourceAddress.c_str()) + ",\"family\":10,\"peerAddress\":" + json(peerAddress.c_str()) +
       ",\"peerIsByoPrefix\":" + (byoIpv6(peerAddress.c_str()) ? "true" : "false") + ",\"listenPort\":" + std::to_string(port) + "}");
  return passed ? 0 : 1;
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
  int peer = waitFd(listener, POLLIN) ? accept4(listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK) : -1; close(listener);
  char buffer[65536]; ssize_t received = peer >= 0 && waitFd(peer, POLLIN) ? recv(peer, buffer, sizeof(buffer), 0) : -1;
  const bool sent = received > 0 && sendAll(peer, std::string(buffer, size_t(received)));
  if (peer >= 0) close(peer);
  emit("tcp-connect-bidirectional", received > 0 && sent ? "pass" : "fail",
       "{\"family\":" + std::to_string(family) + ",\"receivedBytes\":" + std::to_string(received > 0 ? received : 0) +
       ",\"role\":\"server\",\"sentBytes\":" + std::to_string(sent ? received : 0) + "}");
  return received > 0 && sent ? 0 : 1;
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
  int ok = ssl ? (SSL_set_tlsext_host_name(ssl, argv[3]) == 1 && SSL_set_fd(ssl, fd) == 1 && sslConnectTimed(ssl)) : 0;
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
  if (std::strcmp(argv[1], "ipv6-ingress") == 0) return ipv6Ingress(argc - 1, argv + 1);
  if (std::strcmp(argv[1], "whitehole-egress") == 0) return whiteholeEgress(argc - 1, argv + 1);
  if (std::strcmp(argv[1], "pmtu") == 0) return unprovenTcp("tcp-payload-path-mtu", "tcp-echo-does-not-prove-kernel-path-mtu", argc - 1, argv + 1, false);
  if (std::strcmp(argv[1], "reverse") == 0) return unprovenTcp("ingress-relay-reverse-connect", "outbound-connect-does-not-prove-relay-ingress-traversal", argc - 1, argv + 1, true);
  if (std::strcmp(argv[1], "dns") == 0) return dns(argc - 1, argv + 1);
  if (std::strcmp(argv[1], "tls") == 0) return tls(argc - 1, argv + 1);
  return 2;
}
