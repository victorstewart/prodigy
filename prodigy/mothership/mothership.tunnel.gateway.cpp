#include <prodigy/mothership/mothership.tunnel.gateway.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <utility>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <prodigy/container.contract.h>
#include <prodigy/mothership/mothership.tunnel.auth.h>

static bool mothershipTunnelGatewayFail(String *failure, const auto& text)
{
  if (failure)
  {
    failure->assign(text);
  }
  return false;
}

static bool mothershipTunnelGatewayFailErrno(String *failure, const auto& text)
{
  if (failure)
  {
    failure->assign(text);
    failure->append(": "_ctv);
    failure->append(String(std::strerror(errno)));
  }
  return false;
}

static bool mothershipTunnelGatewayOk(String *failure)
{
  if (failure)
  {
    failure->clear();
  }
  return true;
}

MothershipTunnelGatewayUnixListener::~MothershipTunnelGatewayUnixListener()
{
  close();
}

void MothershipTunnelGatewayUnixListener::close(void)
{
  if (fd >= 0)
  {
    ::close(fd);
    fd = -1;
  }
  if (path.size() > 0)
  {
    (void)::unlink(path.c_str());
    path.clear();
  }
}

static bool mothershipTunnelGatewayUnixAddress(const String& socketPath, sockaddr_un& address, socklen_t& addressLen, const char *label, String *failure = nullptr)
{
  String ownedPath = {};
  ownedPath.assign(socketPath);
  if (ownedPath.size() == 0 || ownedPath.size() >= sizeof(address.sun_path))
  {
    String message = {};
    message.snprintf<"mothership tunnel gateway {} socket path invalid"_ctv>(String(label));
    return mothershipTunnelGatewayFail(failure, message);
  }

  address = {};
  address.sun_family = AF_UNIX;
  std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", ownedPath.c_str());
  addressLen = socklen_t(sizeof(address.sun_family) + std::strlen(address.sun_path));
  return true;
}

bool mothershipTunnelGatewayCreateUnixListener(const String& socketPath, MothershipTunnelGatewayUnixListener& listener, String *failure)
{
  listener.close();
  String ownedPath = {};
  ownedPath.assign(socketPath);

  std::error_code createError;
  std::filesystem::path parent = std::filesystem::path(ownedPath.c_str()).parent_path();
  if (parent.empty() == false)
  {
    std::filesystem::create_directories(parent, createError);
    if (createError)
    {
      String message = {};
      message.snprintf<"mothership tunnel gateway socket directory create failed: {}"_ctv>(String(createError.message().c_str()));
      return mothershipTunnelGatewayFail(failure, message);
    }
  }

  sockaddr_un address = {};
  socklen_t addressLen = 0;
  if (mothershipTunnelGatewayUnixAddress(ownedPath, address, addressLen, "listen", failure) == false)
  {
    return false;
  }

  listener.fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener.fd < 0)
  {
    return mothershipTunnelGatewayFailErrno(failure, "mothership tunnel gateway socket create failed"_ctv);
  }

  (void)::unlink(ownedPath.c_str());
  if (::bind(listener.fd, reinterpret_cast<sockaddr *>(&address), addressLen) != 0 || ::listen(listener.fd, SOMAXCONN) != 0)
  {
    mothershipTunnelGatewayFailErrno(failure, "mothership tunnel gateway socket listen failed"_ctv);
    (void)::unlink(ownedPath.c_str());
    listener.close();
    return false;
  }
  if (::chown(ownedPath.c_str(), prodigyMothershipTunnelProviderRuntimeUID, prodigyMothershipTunnelProviderRuntimeUID) != 0 || ::chmod(ownedPath.c_str(), S_IRUSR | S_IWUSR) != 0)
  {
    mothershipTunnelGatewayFailErrno(failure, "mothership tunnel gateway socket ownership failed"_ctv);
    (void)::unlink(ownedPath.c_str());
    listener.close();
    return false;
  }

  listener.path = std::move(ownedPath);
  return mothershipTunnelGatewayOk(failure);
}

bool mothershipTunnelGatewayPeerCgroupAllowed(pid_t peerPid, const String& expectedCgroup, String *failure)
{
  if (expectedCgroup.size() == 0)
  {
    return true;
  }
  if (peerPid <= 0)
  {
    return mothershipTunnelGatewayFail(failure, "mothership tunnel gateway peer pid invalid"_ctv);
  }

  String path = {};
  path.snprintf<"/proc/{itoa}/cgroup"_ctv>(uint64_t(peerPid));
  String actual = {};
  Filesystem::openReadAtClose(-1, path, actual, 512);

  String expected = {};
  expected.assign("0::"_ctv);
  expected.append(expectedCgroup);
  expected.append("\n"_ctv);
  if (actual.equal(expected) == false)
  {
    return mothershipTunnelGatewayFail(failure, "mothership tunnel gateway peer cgroup rejected"_ctv);
  }

  return mothershipTunnelGatewayOk(failure);
}

static bool mothershipTunnelGatewayPeerAllowed(int streamFD, String *failure = nullptr, const String& expectedCgroup = ""_ctv)
{
  if (streamFD < 0)
  {
    return mothershipTunnelGatewayFail(failure, "mothership tunnel gateway peer fd required"_ctv);
  }

#ifdef SO_PEERCRED
  struct ucred peer = {};
  socklen_t peerLen = sizeof(peer);
  if (::getsockopt(streamFD, SOL_SOCKET, SO_PEERCRED, &peer, &peerLen) != 0 || peerLen < sizeof(peer))
  {
    return mothershipTunnelGatewayFailErrno(failure, "mothership tunnel gateway peer credential read failed"_ctv);
  }
  if (peer.uid != uid_t(prodigyMothershipTunnelProviderRuntimeUID))
  {
    return mothershipTunnelGatewayFail(failure, "mothership tunnel gateway peer credentials rejected"_ctv);
  }
  if (mothershipTunnelGatewayPeerCgroupAllowed(peer.pid, expectedCgroup, failure) == false)
  {
    return false;
  }
#else
  return mothershipTunnelGatewayFail(failure, "mothership tunnel gateway peer credentials unsupported"_ctv);
#endif

  return mothershipTunnelGatewayOk(failure);
}

bool mothershipTunnelGatewayAcceptUnixStream(int listenerFD, int& streamFD, String *failure, const String& expectedCgroup)
{
  streamFD = -1;
  for (;;)
  {
#if defined(__linux__)
    streamFD = ::accept4(listenerFD, nullptr, nullptr, SOCK_CLOEXEC);
#else
    streamFD = ::accept(listenerFD, nullptr, nullptr);
    if (streamFD >= 0)
    {
      (void)::fcntl(streamFD, F_SETFD, FD_CLOEXEC);
    }
#endif
    if (streamFD >= 0)
    {
      break;
    }
    if (errno == EINTR)
    {
      continue;
    }
    return mothershipTunnelGatewayFailErrno(failure, "mothership tunnel gateway accept failed"_ctv);
  }

  if (mothershipTunnelGatewayPeerAllowed(streamFD, failure, expectedCgroup) == false)
  {
    ::close(streamFD);
    streamFD = -1;
    return false;
  }
  return true;
}

bool mothershipTunnelGatewayOpenUnixControlSocket(const String& socketPath, int& fd, String *failure)
{
  fd = -1;
  String ownedPath = {};
  ownedPath.assign(socketPath);

  sockaddr_un address = {};
  socklen_t addressLen = 0;
  if (mothershipTunnelGatewayUnixAddress(ownedPath, address, addressLen, "control", failure) == false)
  {
    return false;
  }

  fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
  {
    return mothershipTunnelGatewayFailErrno(failure, "mothership tunnel gateway control socket create failed"_ctv);
  }
  if (::connect(fd, reinterpret_cast<sockaddr *>(&address), addressLen) != 0)
  {
    mothershipTunnelGatewayFailErrno(failure, "mothership tunnel gateway control socket connect failed"_ctv);
    ::close(fd);
    fd = -1;
    return false;
  }

  return mothershipTunnelGatewayOk(failure);
}

static bool mothershipTunnelGatewaySetTimeout(int fd, int timeoutMs, String *failure = nullptr)
{
  timeval timeout = {timeoutMs / 1000, (timeoutMs % 1000) * 1000};
  if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 && ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0)
  {
    return true;
  }
  return mothershipTunnelGatewayFailErrno(failure, "mothership tunnel gateway socket timeout setup failed"_ctv);
}

static bool mothershipTunnelGatewayWaitFD(int fd, short events, int timeoutMs, String *failure = nullptr)
{
  pollfd descriptor = {fd, events, 0};
  int ready = 0;
  do
  {
    descriptor.revents = 0;
    ready = ::poll(&descriptor, 1, timeoutMs);
  } while (ready < 0 && errno == EINTR);
  if (ready > 0)
  {
    return (descriptor.revents & events) != 0
               ? true
               : mothershipTunnelGatewayFail(failure, "mothership tunnel gateway proxy peer closed"_ctv);
  }
  return ready == 0
             ? mothershipTunnelGatewayFail(failure, "mothership tunnel gateway proxy idle timeout"_ctv)
             : mothershipTunnelGatewayFailErrno(failure, "mothership tunnel gateway proxy poll failed"_ctv);
}

static int mothershipTunnelGatewayTLSRetry(SSL *tls, int rc, int timeoutMs, const auto& failureText, String *failure = nullptr)
{
  int error = SSL_get_error(tls, rc);
  if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
  {
    return mothershipTunnelGatewayWaitFD(SSL_get_fd(tls), error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, timeoutMs, failure) ? 1 : -1;
  }
  if (error == SSL_ERROR_ZERO_RETURN)
  {
    return 0;
  }
  mothershipTunnelGatewayFail(failure, failureText);
  return -1;
}

static bool mothershipTunnelGatewayWriteAllFD(int fd, const uint8_t *buffer, size_t bytes, String *failure = nullptr)
{
  while (bytes > 0)
  {
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif
    ssize_t rc = ::send(fd, buffer, bytes, flags);
    if (rc > 0)
    {
      buffer += size_t(rc);
      bytes -= size_t(rc);
      continue;
    }
    if (rc < 0 && errno == EINTR)
    {
      continue;
    }
    return mothershipTunnelGatewayFailErrno(failure, "mothership tunnel gateway control write failed"_ctv);
  }

  return mothershipTunnelGatewayOk(failure);
}

static bool mothershipTunnelGatewayWriteAllTLS(SSL *tls, const uint8_t *buffer, size_t bytes, int idleTimeoutMs, String *failure = nullptr)
{
  while (bytes > 0)
  {
    int chunk = int(std::min<size_t>(bytes, INT_MAX));
    int rc = SSL_write(tls, buffer, chunk);
    if (rc > 0)
    {
      buffer += size_t(rc);
      bytes -= size_t(rc);
      continue;
    }
    int retry = mothershipTunnelGatewayTLSRetry(tls, rc, idleTimeoutMs, "mothership tunnel gateway TLS write failed"_ctv, failure);
    if (retry > 0)
    {
      continue;
    }
    return retry == 0 ? mothershipTunnelGatewayFail(failure, "mothership tunnel gateway TLS closed during write"_ctv) : false;
  }

  return mothershipTunnelGatewayOk(failure);
}

static bool mothershipTunnelGatewayProxyLoop(SSL *tls, int controlFD, int idleTimeoutMs, String *failure = nullptr)
{
  uint8_t buffer[16 * 1024];
  for (;;)
  {
    pollfd descriptors[2] = {};
    descriptors[0].fd = SSL_get_fd(tls);
    descriptors[0].events = POLLIN;
    descriptors[1].fd = controlFD;
    descriptors[1].events = POLLIN;

    bool tlsReadable = SSL_pending(tls) > 0;
    if (tlsReadable == false)
    {
      int ready = ::poll(descriptors, 2, idleTimeoutMs);
      if (ready == 0)
      {
        return mothershipTunnelGatewayFail(failure, "mothership tunnel gateway proxy idle timeout"_ctv);
      }
      if (ready < 0)
      {
        if (errno == EINTR)
        {
          continue;
        }
        return mothershipTunnelGatewayFailErrno(failure, "mothership tunnel gateway proxy poll failed"_ctv);
      }
      tlsReadable = (descriptors[0].revents & POLLIN) != 0;
    }

    if (tlsReadable)
    {
      int rc = SSL_read(tls, buffer, sizeof(buffer));
      if (rc > 0)
      {
        if (mothershipTunnelGatewayWriteAllFD(controlFD, buffer, size_t(rc), failure) == false)
        {
          return false;
        }
      }
      else
      {
        int retry = mothershipTunnelGatewayTLSRetry(tls, rc, idleTimeoutMs, "mothership tunnel gateway TLS read failed"_ctv, failure);
        if (retry > 0)
        {
          continue;
        }
        return retry == 0 ? true : false;
      }
    }
    else if (descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL))
    {
      return true;
    }

    if (descriptors[1].revents & POLLIN)
    {
      ssize_t rc = ::recv(controlFD, buffer, sizeof(buffer), 0);
      if (rc > 0)
      {
        if (mothershipTunnelGatewayWriteAllTLS(tls, buffer, size_t(rc), idleTimeoutMs, failure) == false)
        {
          return false;
        }
      }
      else if (rc == 0)
      {
        return true;
      }
      else if (errno != EINTR)
      {
        return mothershipTunnelGatewayFailErrno(failure, "mothership tunnel gateway control read failed"_ctv);
      }
    }
    else if (descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL))
    {
      return true;
    }
  }
}

bool mothershipTunnelGatewayProxyAuthenticatedControlStream(
    int streamFD,
    const String& controlSocketPath,
    const MothershipTunnelGatewayTLSContext& tlsContext,
    MothershipTunnelGatewaySessionResult *sessionResult,
    String *failure,
    int idleTimeoutMs)
{
  MothershipTunnelGatewaySessionResult result = {};
  auto publish = [&]() {
    if (sessionResult)
    {
      *sessionResult = result;
    }
  };
  publish();
  auto fail = [&](auto&& text) -> bool {
    publish();
    return mothershipTunnelGatewayFail(failure, text);
  };

  if (streamFD < 0)
  {
    return fail("mothership tunnel gateway stream fd required"_ctv);
  }
  if (tlsContext.configured() == false)
  {
    return fail("mothership tunnel gateway TLS context missing"_ctv);
  }
  idleTimeoutMs = std::max(idleTimeoutMs, 1);
  if (mothershipTunnelGatewaySetTimeout(streamFD, idleTimeoutMs, failure) == false)
  {
    publish();
    return false;
  }
  std::unique_ptr<SSL, decltype(&SSL_free)> tls(nullptr, SSL_free);
  std::unique_ptr<X509, decltype(&X509_free)> clientCert(nullptr, X509_free);
  int controlFD = -1;
  auto closeControl = [&]() {
    if (controlFD >= 0)
    {
      ::close(controlFD);
      controlFD = -1;
    }
  };
  tls.reset(SSL_new(tlsContext.context.get()));
  if (tls == nullptr || SSL_set_fd(tls.get(), streamFD) != 1)
  {
    return fail("mothership tunnel gateway TLS accept failed"_ctv);
  }
  for (;;)
  {
    int rc = SSL_accept(tls.get());
    if (rc == 1)
    {
      break;
    }
    int retry = mothershipTunnelGatewayTLSRetry(tls.get(), rc, idleTimeoutMs, "mothership tunnel gateway TLS accept failed"_ctv, failure);
    if (retry <= 0)
    {
      publish();
      return retry == 0 ? fail("mothership tunnel gateway TLS accept failed"_ctv) : false;
    }
  }
  if (SSL_get_verify_result(tls.get()) != X509_V_OK)
  {
    return fail("mothership tunnel gateway TLS accept failed"_ctv);
  }
  clientCert.reset(SSL_get1_peer_certificate(tls.get()));
  if (tlsContext.authorizeClientCertificate(clientCert.get(), failure) == false)
  {
    publish();
    return false;
  }
  result.authenticated = true;
  if (mothershipTunnelGatewayOpenUnixControlSocket(controlSocketPath, controlFD, failure) == false)
  {
    publish();
    return false;
  }
  if (mothershipTunnelGatewaySetTimeout(controlFD, idleTimeoutMs, failure) == false)
  {
    closeControl();
    publish();
    return false;
  }
  result.openedControlSocket = true;
  bool ok = mothershipTunnelGatewayProxyLoop(tls.get(), controlFD, idleTimeoutMs, failure);
  closeControl();
  publish();
  return ok ? mothershipTunnelGatewayOk(failure) : false;
}

MothershipTunnelGatewayRuntime::~MothershipTunnelGatewayRuntime()
{
  stop();
}

static void mothershipTunnelGatewayRuntimeReportFailure(
    MothershipTunnelGatewayRuntime *runtime,
    void *callbackContext,
    MothershipTunnelGatewayFailureCallback failureCallback,
    String failure)
{
  uint64_t failures = runtime->failureCount.fetch_add(1) + 1;
  if (failureCallback && (failures <= 8 || (failures % 1024) == 0))
  {
    failureCallback(callbackContext, failures, failure);
  }
}

bool MothershipTunnelGatewayRuntime::start(
    const String& controlSocketPath,
    const MothershipTunnelGatewayAuth& gatewayAuth,
    const String& expectedProviderCgroup,
    void *callbackContext,
    MothershipTunnelGatewaySessionCallback sessionCallback,
    MothershipTunnelGatewayFailureCallback failureCallback,
    String *failure)
{
  if (listener.fd < 0 || expectedProviderCgroup.size() == 0)
  {
    return mothershipTunnelGatewayFail(failure, "mothership tunnel gateway provider identity missing"_ctv);
  }
  int listenerFD = listener.fd;
  String ownedControlSocketPath = controlSocketPath;
  auto gatewayTLS = std::make_unique<MothershipTunnelGatewayTLSContext>();
  if (gatewayTLS->configure(gatewayAuth, failure) == false)
  {
    return false;
  }
  stopRequested.store(false);
  activeStreamFD.store(-1);
  failureCount.store(0);
  thread = std::thread([this, listenerFD, ownedControlSocketPath, gatewayTLS = std::move(gatewayTLS), expectedProviderCgroup, callbackContext, sessionCallback, failureCallback]() {
    auto reportFailure = [&](String failure) {
      if (stopRequested.load() == false)
      {
        mothershipTunnelGatewayRuntimeReportFailure(this, callbackContext, failureCallback, std::move(failure));
      }
    };
    while (stopRequested.load() == false)
    {
      pollfd descriptor = {};
      descriptor.fd = listenerFD;
      descriptor.events = POLLIN;
      int ready = ::poll(&descriptor, 1, 100);
      if (ready == 0 || (ready < 0 && errno == EINTR))
      {
        continue;
      }
      if (ready < 0)
      {
        String pollFailure = {};
        pollFailure.snprintf<"mothership tunnel gateway poll failed: {}"_ctv>(String(std::strerror(errno)));
        reportFailure(std::move(pollFailure));
        break;
      }
      if ((descriptor.revents & POLLIN) == 0)
      {
        if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        {
          reportFailure(String("mothership tunnel gateway listener closed"));
          break;
        }
        continue;
      }
      int streamFD = -1;
      String sessionFailure = {};
      if (mothershipTunnelGatewayAcceptUnixStream(listenerFD, streamFD, &sessionFailure, expectedProviderCgroup) == false)
      {
        reportFailure(std::move(sessionFailure));
        continue;
      }
      activeStreamFD.store(streamFD);
      MothershipTunnelGatewaySessionResult sessionResult = {};
      bool ok = mothershipTunnelGatewayProxyAuthenticatedControlStream(streamFD, ownedControlSocketPath, *gatewayTLS, &sessionResult, &sessionFailure);
      if (ok && sessionCallback)
      {
        sessionCallback(callbackContext, sessionResult);
      }
      (void)::shutdown(streamFD, SHUT_RDWR);
      ::close(streamFD);
      int expectedStreamFD = streamFD;
      (void)activeStreamFD.compare_exchange_strong(expectedStreamFD, -1);
      if (ok == false)
      {
        reportFailure(std::move(sessionFailure));
      }
    }
  });
  return mothershipTunnelGatewayOk(failure);
}

void MothershipTunnelGatewayRuntime::stop(void)
{
  stopRequested.store(true);
  int streamFD = activeStreamFD.load();
  if (streamFD >= 0)
  {
    (void)::shutdown(streamFD, SHUT_RDWR);
  }
  listener.close();
  if (thread.joinable())
  {
    thread.join();
  }
  activeStreamFD.store(-1);
}
