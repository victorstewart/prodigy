#pragma once

#include <atomic>
#include <cstdint>
#include <thread>
#include <sys/types.h>

#include <services/prodigy.h>

struct MothershipTunnelGatewayAuth;
class MothershipTunnelGatewayTLSContext;

struct MothershipTunnelGatewayUnixListener {
  String path;
  int fd = -1;

  MothershipTunnelGatewayUnixListener(void) = default;
  MothershipTunnelGatewayUnixListener(const MothershipTunnelGatewayUnixListener&) = delete;
  MothershipTunnelGatewayUnixListener& operator=(const MothershipTunnelGatewayUnixListener&) = delete;

  ~MothershipTunnelGatewayUnixListener();
  void close(void);
};

using MothershipTunnelGatewayFailureCallback = void (*)(void *context, uint64_t failures, String& failure);
using MothershipTunnelGatewaySessionCallback = void (*)(void *context);

struct MothershipTunnelGatewayRuntime {
  MothershipTunnelGatewayUnixListener listener;
  std::thread thread;
  std::atomic<bool> stopRequested = false;
  std::atomic<int> activeStreamFD = -1;
  std::atomic<uint64_t> failureCount = 0;

  MothershipTunnelGatewayRuntime(void) = default;
  MothershipTunnelGatewayRuntime(const MothershipTunnelGatewayRuntime&) = delete;
  MothershipTunnelGatewayRuntime& operator=(const MothershipTunnelGatewayRuntime&) = delete;
  ~MothershipTunnelGatewayRuntime();

  bool start(
      const String& controlSocketPath,
      const MothershipTunnelGatewayAuth& gatewayAuth,
      const String& expectedProviderCgroup,
      void *callbackContext,
      MothershipTunnelGatewaySessionCallback sessionCallback,
      MothershipTunnelGatewayFailureCallback failureCallback,
      String *failure = nullptr);
  void stop(void);
};

bool mothershipTunnelGatewayCreateUnixListener(const String& socketPath, MothershipTunnelGatewayUnixListener& listener, String *failure = nullptr);
bool mothershipTunnelGatewayPeerCgroupAllowed(pid_t peerPid, const String& expectedCgroup, String *failure = nullptr);
bool mothershipTunnelGatewayAcceptUnixStream(int listenerFD, int& streamFD, String *failure = nullptr, const String& expectedCgroup = ""_ctv);
bool mothershipTunnelGatewayOpenUnixControlSocket(const String& socketPath, int& fd, String *failure = nullptr);
bool mothershipTunnelGatewayProxyAuthenticatedControlStream(
    int streamFD,
    const String& controlSocketPath,
    const MothershipTunnelGatewayTLSContext& tlsContext,
    String *failure = nullptr,
    int idleTimeoutMs = 120'000,
    void *callbackContext = nullptr,
    MothershipTunnelGatewaySessionCallback sessionCallback = nullptr);
