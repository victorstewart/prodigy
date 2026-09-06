// SPDX-License-Identifier: Apache-2.0
#include <networking/includes.h>
#include <services/debug.h>
#include <services/bitsery.h>
#include <services/crypto.h>
#include <services/filesystem.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/pool.h>
#include <networking/ring.h>
#include <prodigy/neuron.hub.h>

#include <arpa/inet.h>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <poll.h>
#include <string>
#include <thread>
#include <unistd.h>

#ifndef HELLO_PRODIGY_VERSION
#define HELLO_PRODIGY_VERSION "development"
#endif

namespace {
constexpr uint16_t kPort = 8080;
constexpr size_t kMaxRequestBytes = 8192;
constexpr int kPollIntervalMs = 250;

std::string makeResponse(const char *status, const std::string& body, bool includeBody)
{
  return std::string("HTTP/1.1 ") + status + "\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: " +
      std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + (includeBody ? body : "");
}
}

class HelloProdigy final : public NeuronHubDispatch {
  std::unique_ptr<NeuronHub> neuronHub;
  std::atomic<bool> stopRequested {false};
  std::thread worker;
  int listener = -1;

  void closeListener()
  {
    if (listener >= 0) { close(listener); listener = -1; }
  }

  bool openListener()
  {
    listener = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
    if (listener < 0) { std::perror("hello-prodigy socket"); return false; }
    const int reuse = 1;
    const int dualStack = 0;
    sockaddr_in6 address = {};
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_any;
    address.sin6_port = htons(kPort);
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ||
        setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, &dualStack, sizeof(dualStack)) ||
        bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) || listen(listener, 16))
    {
      std::perror("hello-prodigy bind/listen");
      closeListener();
      return false;
    }
    return true;
  }

  void reply(int client, const char *status, const std::string& body, bool includeBody = true)
  {
    const std::string wire = makeResponse(status, body, includeBody);
    for (size_t offset = 0; offset < wire.size();)
    {
      const ssize_t sent = send(client, wire.data() + offset, wire.size() - offset, MSG_NOSIGNAL);
      if (sent > 0) { offset += size_t(sent); continue; }
      if (sent < 0 && errno == EINTR) continue;
      return;
    }
  }

  void serveClient(int client)
  {
    std::string request;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (request.find("\r\n\r\n") == std::string::npos && request.size() < kMaxRequestBytes && !stopRequested.load())
    {
      const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
      if (remaining <= 0) return;
      pollfd descriptor = {client, POLLIN, 0};
      const int ready = poll(&descriptor, 1, int(remaining));
      if (ready <= 0) { if (ready < 0 && errno == EINTR) continue; return; }
      char bytes[1024];
      const size_t capacity = std::min(sizeof(bytes), kMaxRequestBytes - request.size());
      const ssize_t received = recv(client, bytes, capacity, 0);
      if (received <= 0) { if (received < 0 && errno == EINTR) continue; return; }
      request.append(bytes, size_t(received));
    }
    if (request.find("\r\n\r\n") == std::string::npos) { reply(client, "413 Payload Too Large", "request headers exceed 8192 bytes\n"); return; }
    const size_t end = request.find("\r\n"), first = request.find(' ');
    const size_t second = first == std::string::npos ? std::string::npos : request.find(' ', first + 1);
    if (end == std::string::npos || first == std::string::npos || second == std::string::npos) { reply(client, "400 Bad Request", "malformed HTTP request\n"); return; }
    const std::string method = request.substr(0, first);
    const std::string path = request.substr(first + 1, second - first - 1);
    const std::string version = request.substr(second + 1, end - second - 1);
    if (version != "HTTP/1.0" && version != "HTTP/1.1") { reply(client, "400 Bad Request", "unsupported HTTP version\n"); return; }
    const bool head = method == "HEAD";
    if (method != "GET" && !head) { reply(client, "405 Method Not Allowed", "use GET or HEAD\n", !head); return; }
    if (path == "/" || path == "/healthz") { reply(client, "200 OK", "hello from Prodigy " HELLO_PRODIGY_VERSION "\n", !head); return; }
    reply(client, "404 Not Found", "not found\n", !head);
  }

  void serveHTTP()
  {
    while (!stopRequested.load(std::memory_order_relaxed))
    {
      pollfd descriptor = {listener, POLLIN, 0};
      const int ready = poll(&descriptor, 1, kPollIntervalMs);
      if (ready <= 0) { if (ready < 0 && errno != EINTR) std::perror("hello-prodigy poll"); continue; }
      const int client = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
      if (client < 0) { if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) std::perror("hello-prodigy accept"); continue; }
      serveClient(client);
      close(client);
    }
  }

public:
  ~HelloProdigy()
  {
    stopRequested.store(true, std::memory_order_relaxed);
    if (worker.joinable()) worker.join();
    closeListener();
  }
  void beginShutdown() override { stopRequested.store(true, std::memory_order_relaxed); }
  void resourceDelta(uint16_t, uint32_t, uint32_t, bool, uint32_t) override { if (neuronHub) neuronHub->acknowledgeResourceDelta(true); }
  void credentialsRefresh(const CredentialDelta&) override { if (neuronHub) neuronHub->acknowledgeCredentialsRefresh(); }

  bool prepare(int argc, char *argv[])
  {
    Ring::createRing(64, 128, 512, 128, -1, -1, 0);
    neuronHub = std::make_unique<NeuronHub>(this);
    neuronHub->fillFromMainArgs(argc, argv);
    neuronHub->afterRing();
    if (!openListener()) return false;
    neuronHub->signalReady();
    neuronHub->signalRuntimeReady();
    worker = std::thread([this] { serveHTTP(); });
    return true;
  }
  void run()
  {
    Ring::start();
    stopRequested.store(true, std::memory_order_relaxed);
    if (worker.joinable()) worker.join();
    closeListener();
  }
};

int main(int argc, char *argv[])
{
  HelloProdigy application;
  if (!application.prepare(argc, argv)) return 1;
  application.run();
  return 0;
}
