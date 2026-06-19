#pragma once

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
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <prodigy/mothership/mothership.cluster.types.h>

class MothershipTunnelGatewaySessionResult {
public:

  bool authenticated = false;
  bool openedControlSocket = false;
};

class MothershipTunnelGatewayUnixListener {
public:

  String path;
  int fd = -1;

  MothershipTunnelGatewayUnixListener(void) = default;
  MothershipTunnelGatewayUnixListener(const MothershipTunnelGatewayUnixListener&) = delete;
  MothershipTunnelGatewayUnixListener& operator=(const MothershipTunnelGatewayUnixListener&) = delete;

  ~MothershipTunnelGatewayUnixListener()
  {
    close();
  }

  void close(void)
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
};

static inline bool mothershipTunnelGatewayUnixAddress(const String& socketPath, sockaddr_un& address, socklen_t& addressLen, const char *label, String *failure = nullptr)
{
  String ownedPath = {};
  ownedPath.assign(socketPath);
  if (ownedPath.size() == 0 || ownedPath.size() >= sizeof(address.sun_path))
  {
    if (failure)
    {
      failure->snprintf<"mothership tunnel gateway {} socket path invalid"_ctv>(String(label));
    }
    return false;
  }

  address = {};
  address.sun_family = AF_UNIX;
  std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", ownedPath.c_str());
  addressLen = socklen_t(sizeof(address.sun_family) + std::strlen(address.sun_path));
  return true;
}

static inline bool mothershipTunnelGatewayCreateUnixListener(const String& socketPath, MothershipTunnelGatewayUnixListener& listener, String *failure = nullptr)
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
      if (failure)
      {
        failure->snprintf<"mothership tunnel gateway socket directory create failed: {}"_ctv>(String(createError.message().c_str()));
      }
      return false;
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
    if (failure)
    {
      failure->snprintf<"mothership tunnel gateway socket create failed: {}"_ctv>(String(std::strerror(errno)));
    }
    return false;
  }

  (void)::unlink(ownedPath.c_str());
  if (::bind(listener.fd, reinterpret_cast<sockaddr *>(&address), addressLen) != 0 || ::listen(listener.fd, SOMAXCONN) != 0)
  {
    if (failure)
    {
      failure->snprintf<"mothership tunnel gateway socket listen failed: {}"_ctv>(String(std::strerror(errno)));
    }
    (void)::unlink(ownedPath.c_str());
    listener.close();
    return false;
  }
  if (::chown(ownedPath.c_str(), prodigyMothershipTunnelProviderRuntimeUID, prodigyMothershipTunnelProviderRuntimeUID) != 0 || ::chmod(ownedPath.c_str(), S_IRUSR | S_IWUSR) != 0)
  {
    if (failure)
    {
      failure->snprintf<"mothership tunnel gateway socket ownership failed: {}"_ctv>(String(std::strerror(errno)));
    }
    (void)::unlink(ownedPath.c_str());
    listener.close();
    return false;
  }

  listener.path = std::move(ownedPath);
  if (failure)
  {
    failure->clear();
  }
  return true;
}

static inline bool mothershipTunnelGatewayPeerAllowed(int streamFD, String *failure = nullptr)
{
  if (streamFD < 0)
  {
    if (failure)
    {
      failure->assign("mothership tunnel gateway peer fd required"_ctv);
    }
    return false;
  }

#ifdef SO_PEERCRED
  struct ucred peer = {};
  socklen_t peerLen = sizeof(peer);
  if (::getsockopt(streamFD, SOL_SOCKET, SO_PEERCRED, &peer, &peerLen) != 0 || peerLen < sizeof(peer))
  {
    if (failure)
    {
      failure->snprintf<"mothership tunnel gateway peer credential read failed: {}"_ctv>(String(std::strerror(errno)));
    }
    return false;
  }
  if (peer.uid != uid_t(prodigyMothershipTunnelProviderRuntimeUID))
  {
    if (failure)
    {
      failure->assign("mothership tunnel gateway peer credentials rejected"_ctv);
    }
    return false;
  }
#else
  if (failure)
  {
    failure->assign("mothership tunnel gateway peer credentials unsupported"_ctv);
  }
  return false;
#endif

  if (failure)
  {
    failure->clear();
  }
  return true;
}

static inline bool mothershipTunnelGatewayAcceptUnixStream(int listenerFD, int& streamFD, String *failure = nullptr)
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
    if (failure)
    {
      failure->snprintf<"mothership tunnel gateway accept failed: {}"_ctv>(String(std::strerror(errno)));
    }
    return false;
  }

  if (mothershipTunnelGatewayPeerAllowed(streamFD, failure) == false)
  {
    ::close(streamFD);
    streamFD = -1;
    return false;
  }
  return true;
}

static inline bool mothershipTunnelGatewayOpenUnixControlSocket(const String& socketPath, int& fd, String *failure = nullptr)
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
    if (failure)
    {
      failure->snprintf<"mothership tunnel gateway control socket create failed: {}"_ctv>(String(std::strerror(errno)));
    }
    return false;
  }
  if (::connect(fd, reinterpret_cast<sockaddr *>(&address), addressLen) != 0)
  {
    if (failure)
    {
      failure->snprintf<"mothership tunnel gateway control socket connect failed: {}"_ctv>(String(std::strerror(errno)));
    }
    ::close(fd);
    fd = -1;
    return false;
  }

  if (failure)
  {
    failure->clear();
  }
  return true;
}

static inline bool mothershipTunnelGatewayWriteAllFD(int fd, const uint8_t *buffer, size_t bytes, String *failure = nullptr)
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
    if (failure)
    {
      failure->snprintf<"mothership tunnel gateway control write failed: {}"_ctv>(String(std::strerror(errno)));
    }
    return false;
  }

  if (failure)
  {
    failure->clear();
  }
  return true;
}

static inline bool mothershipTunnelGatewayWriteAllTLS(SSL *tls, const uint8_t *buffer, size_t bytes, String *failure = nullptr)
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
    if (failure)
    {
      failure->assign("mothership tunnel gateway TLS write failed"_ctv);
    }
    return false;
  }

  if (failure)
  {
    failure->clear();
  }
  return true;
}

static inline bool mothershipTunnelGatewayProxyLoop(SSL *tls, int tlsFD, int controlFD, MothershipTunnelGatewaySessionResult& result, String *failure = nullptr)
{
  uint8_t buffer[16 * 1024];
  for (;;)
  {
    pollfd descriptors[2] = {};
    descriptors[0].fd = tlsFD;
    descriptors[0].events = POLLIN;
    descriptors[1].fd = controlFD;
    descriptors[1].events = POLLIN;

    int ready = ::poll(descriptors, 2, -1);
    if (ready < 0)
    {
      if (errno == EINTR)
      {
        continue;
      }
      if (failure)
      {
        failure->snprintf<"mothership tunnel gateway proxy poll failed: {}"_ctv>(String(std::strerror(errno)));
      }
      return false;
    }

    if (descriptors[0].revents & POLLIN)
    {
      int rc = SSL_read(tls, buffer, sizeof(buffer));
      if (rc > 0)
      {
        if (mothershipTunnelGatewayWriteAllFD(controlFD, buffer, size_t(rc), failure) == false)
        {
          return false;
        }
      }
      else if (SSL_get_error(tls, rc) == SSL_ERROR_ZERO_RETURN)
      {
        return true;
      }
      else
      {
        if (failure)
        {
          failure->assign("mothership tunnel gateway TLS read failed"_ctv);
        }
        return false;
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
        if (mothershipTunnelGatewayWriteAllTLS(tls, buffer, size_t(rc), failure) == false)
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
        if (failure)
        {
          failure->snprintf<"mothership tunnel gateway control read failed: {}"_ctv>(String(std::strerror(errno)));
        }
        return false;
      }
    }
    else if (descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL))
    {
      return true;
    }
  }
}

static inline bool mothershipTunnelGatewayProxyAuthenticatedControlStream(
    int streamFD,
    const String& controlSocketPath,
    const MothershipTunnelGatewayAuth& auth,
    MothershipTunnelGatewaySessionResult *sessionResult = nullptr,
    String *failure = nullptr)
{
  MothershipTunnelGatewaySessionResult result = {};
  if (sessionResult)
  {
    *sessionResult = result;
  }
  auto fail = [&](auto&& text) -> bool {
    if (failure)
    {
      failure->assign(text);
    }
    if (sessionResult)
    {
      *sessionResult = result;
    }
    return false;
  };

  if (streamFD < 0)
  {
    return fail("mothership tunnel gateway stream fd required"_ctv);
  }
  if (mothershipTunnelGatewayAuthMaterialValid(auth, failure) == false)
  {
    return false;
  }

  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(nullptr, SSL_CTX_free);
  std::unique_ptr<SSL, decltype(&SSL_free)> tls(nullptr, SSL_free);
  std::unique_ptr<X509, decltype(&X509_free)> root(nullptr, X509_free);
  std::unique_ptr<X509, decltype(&X509_free)> serverCert(nullptr, X509_free);
  std::unique_ptr<X509, decltype(&X509_free)> clientCert(nullptr, X509_free);
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> serverKey(nullptr, EVP_PKEY_free);
  int controlFD = -1;
  auto closeControl = [&]() {
    if (controlFD >= 0)
    {
      ::close(controlFD);
      controlFD = -1;
    }
  };

  root.reset(VaultPem::x509FromPem(auth.rootCertPem));
  serverCert.reset(VaultPem::x509FromPem(auth.serverCertPem));
  serverKey.reset(VaultPem::privateKeyFromPem(auth.serverKeyPem));
  context.reset(SSL_CTX_new(TLS_server_method()));
  X509_STORE *store = context ? SSL_CTX_get_cert_store(context.get()) : nullptr;
  if (root == nullptr || serverCert == nullptr || serverKey == nullptr || store == nullptr ||
      X509_STORE_add_cert(store, root.get()) != 1 ||
      SSL_CTX_use_certificate(context.get(), serverCert.get()) != 1 ||
      SSL_CTX_use_PrivateKey(context.get(), serverKey.get()) != 1 ||
      SSL_CTX_check_private_key(context.get()) != 1 ||
      SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_ciphersuites(context.get(), "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256") != 1)
  {
    return fail("mothership tunnel gateway TLS context setup failed"_ctv);
  }
  SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

  tls.reset(SSL_new(context.get()));
  if (tls == nullptr || SSL_set_fd(tls.get(), streamFD) != 1 || SSL_accept(tls.get()) != 1 || SSL_get_verify_result(tls.get()) != X509_V_OK)
  {
    return fail("mothership tunnel gateway TLS accept failed"_ctv);
  }

  clientCert.reset(SSL_get1_peer_certificate(tls.get()));
  String clientCertPem = {};
  if (VaultPem::x509ToPem(clientCert.get(), clientCertPem) == false ||
      mothershipTunnelGatewayAuthorizeClientCertificate(auth, clientCertPem, failure) == false)
  {
    if (sessionResult)
    {
      *sessionResult = result;
    }
    return false;
  }
  result.authenticated = true;

  if (mothershipTunnelGatewayOpenUnixControlSocket(controlSocketPath, controlFD, failure) == false)
  {
    if (sessionResult)
    {
      *sessionResult = result;
    }
    return false;
  }
  result.openedControlSocket = true;

  bool ok = mothershipTunnelGatewayProxyLoop(tls.get(), streamFD, controlFD, result, failure);
  closeControl();
  if (sessionResult)
  {
    *sessionResult = result;
  }
  if (ok && failure)
  {
    failure->clear();
  }
  return ok;
}
