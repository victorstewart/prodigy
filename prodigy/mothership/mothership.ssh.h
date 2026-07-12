#pragma once

#include <libssh2/libssh2.h>

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <networking/includes.h>
#include <networking/ssh.h>

#include <prodigy/iaas/bootstrap.ssh.h>
#include <prodigy/mothership/mothership.cluster.types.h>

static inline bool mothershipEnsureLibssh2(void)
{
  static bool initialized = []() -> bool {
    return (libssh2_init(0) == 0);
  }();

  return initialized;
}

static inline bool mothershipOpenNumericConnectedSocket(const String& address, uint16_t port, int& fdOut)
{
  fdOut = -1;
  String addressText = address;

  struct sockaddr_storage destination = {};
  socklen_t destinationLength = 0;
  struct sockaddr_in *destination4 = reinterpret_cast<struct sockaddr_in *>(&destination);
  struct sockaddr_in6 *destination6 = reinterpret_cast<struct sockaddr_in6 *>(&destination);
  if (inet_pton(AF_INET, addressText.c_str(), &destination4->sin_addr) == 1)
  {
    destination4->sin_family = AF_INET;
    destination4->sin_port = htons(port);
    destinationLength = sizeof(*destination4);
  }
  else if (inet_pton(AF_INET6, addressText.c_str(), &destination6->sin6_addr) == 1)
  {
    destination6->sin6_family = AF_INET6;
    destination6->sin6_port = htons(port);
    destinationLength = sizeof(*destination6);
  }
  else
  {
    errno = EINVAL;
    return false;
  }

  auto connectWithTimeout = [](int fd, const struct sockaddr *sockaddrPtr, socklen_t sockaddrLen) -> bool {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
    {
      return false;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
    {
      return false;
    }

    if (::connect(fd, sockaddrPtr, sockaddrLen) == 0)
    {
      (void)fcntl(fd, F_SETFL, flags);
      return true;
    }

    if (errno != EINPROGRESS && errno != EWOULDBLOCK)
    {
      (void)fcntl(fd, F_SETFL, flags);
      return false;
    }

    struct pollfd descriptor = {};
    descriptor.fd = fd;
    descriptor.events = POLLOUT;
    if (::poll(&descriptor, 1, 10'000) <= 0)
    {
      errno = ETIMEDOUT;
      (void)fcntl(fd, F_SETFL, flags);
      return false;
    }

    int socketError = 0;
    socklen_t socketErrorSize = sizeof(socketError);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &socketErrorSize) != 0)
    {
      (void)fcntl(fd, F_SETFL, flags);
      return false;
    }

    if (socketError != 0)
    {
      errno = socketError;
      (void)fcntl(fd, F_SETFL, flags);
      return false;
    }

    (void)fcntl(fd, F_SETFL, flags);
    return true;
  };

  int fd = ::socket(destination.ss_family, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0)
  {
    return false;
  }

  if (connectWithTimeout(fd, reinterpret_cast<const struct sockaddr *>(&destination), destinationLength))
  {
    fdOut = fd;
    return true;
  }

  ::close(fd);
  return false;
}

static inline void mothershipCloseSSHSession(LIBSSH2_SESSION *& session, int& fd)
{
  if (session != nullptr)
  {
    (void)libssh2_session_disconnect(session, "Normal Shutdown");
    libssh2_session_free(session);
    session = nullptr;
  }

  if (fd >= 0)
  {
    ::close(fd);
    fd = -1;
  }
}

static inline bool mothershipConnectSSHSession(
    const MothershipProdigyClusterMachine& machine,
    LIBSSH2_SESSION *& session,
    int& fd,
    String *failure = nullptr,
    const Vault::SSHKeyPackage *sshKeyPackage = nullptr,
    const String *sshKeyPackagePrivateKeyPath = nullptr)
{
  session = nullptr;
  fd = -1;
  if (machine.ssh.hostPublicKeyOpenSSH.size() == 0)
  {
    if (failure)
    {
      failure->assign("missing ssh host public key"_ctv);
    }
    return false;
  }

  String sshUser = {};
  sshUser.assign(machine.ssh.user);
  String sshPrivateKeyPath = {};
  sshPrivateKeyPath.assign(machine.ssh.privateKeyPath);

  if (mothershipEnsureLibssh2() == false)
  {
    if (failure)
    {
      failure->assign("failed to initialize libssh2");
    }
    return false;
  }

  if (mothershipOpenNumericConnectedSocket(machine.ssh.address, machine.ssh.port, fd) == false)
  {
    if (failure)
    {
      failure->snprintf<"failed to connect to ssh address {}:{itoa}"_ctv>(machine.ssh.address, unsigned(machine.ssh.port));
    }
    return false;
  }

  session = libssh2_session_init();
  if (session == nullptr)
  {
    if (failure)
    {
      failure->assign("failed to initialize ssh session");
    }
    ::close(fd);
    fd = -1;
    return false;
  }

  libssh2_session_set_blocking(session, 1);
  if (libssh2_session_method_pref(session, LIBSSH2_METHOD_HOSTKEY, "ssh-ed25519") != 0)
  {
    if (failure)
    {
      failure->assign("failed to prefer ed25519 ssh host key");
    }
    mothershipCloseSSHSession(session, fd);
    return false;
  }

  if (libssh2_session_handshake(session, fd) != 0)
  {
    if (failure)
    {
      failure->assign("ssh handshake failed");
    }
    mothershipCloseSSHSession(session, fd);
    return false;
  }

  if (verifySSHSessionHostKey(machine.ssh.address, machine.ssh.port, machine.ssh.hostPublicKeyOpenSSH, session, failure) == false)
  {
    mothershipCloseSSHSession(session, fd);
    return false;
  }

  bool useKeyPackage = sshKeyPackage != nullptr && sshKeyPackagePrivateKeyPath != nullptr && prodigyBootstrapSSHKeyPackageConfigured(*sshKeyPackage) && (machine.ssh.privateKeyPath.size() == 0 || machine.ssh.privateKeyPath.equals(*sshKeyPackagePrivateKeyPath) || ::access(sshPrivateKeyPath.c_str(), R_OK) != 0);

  if (useKeyPackage)
  {
    Vault::SSHKeyPackage keyPackage = *sshKeyPackage;
    if (Vault::validateSSHKeyPackageEd25519(keyPackage, failure) == false)
    {
      keyPackage.clear();
      mothershipCloseSSHSession(session, fd);
      return false;
    }

    if (libssh2_userauth_publickey_frommemory(
            session,
            sshUser.c_str(),
            sshUser.size(),
            reinterpret_cast<const char *>(keyPackage.publicKeyOpenSSH.data()),
            keyPackage.publicKeyOpenSSH.size(),
            reinterpret_cast<const char *>(keyPackage.privateKeyOpenSSH.data()),
            keyPackage.privateKeyOpenSSH.size(),
            nullptr) != 0)
    {
      if (failure)
      {
        failure->assign("ssh public key auth failed");
      }
      keyPackage.clear();
      mothershipCloseSSHSession(session, fd);
      return false;
    }

    keyPackage.clear();
  }
  else if (libssh2_userauth_publickey_fromfile(session, sshUser.c_str(), nullptr, sshPrivateKeyPath.c_str(), nullptr) != 0)
  {
    if (failure)
    {
      failure->assign("ssh public key auth failed");
    }
    mothershipCloseSSHSession(session, fd);
    return false;
  }

  if (failure)
  {
    failure->clear();
  }
  return true;
}
