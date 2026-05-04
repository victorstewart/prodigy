#pragma once

#include <libssh2.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <networking/includes.h>
#include <networking/ssh.h>

#include <prodigy/iaas/bootstrap.ssh.h>
#include <prodigy/mothership/mothership.cluster.types.h>

static inline bool mothershipEnsureLibssh2(void)
{
   static bool initialized = [] () -> bool {
      return (libssh2_init(0) == 0);
   }();

   return initialized;
}

static inline bool mothershipOpenConnectedSocket(const String& address, uint16_t port, int& fdOut)
{
   fdOut = -1;
   String addressText = address;

   char portText[16] = {0};
   std::snprintf(portText, sizeof(portText), "%u", unsigned(port));

   struct addrinfo hints = {};
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_protocol = IPPROTO_TCP;

   struct addrinfo *results = nullptr;
   if (getaddrinfo(addressText.c_str(), portText, &hints, &results) != 0)
   {
      return false;
   }

   auto connectWithTimeout = [] (int fd, const struct sockaddr *sockaddrPtr, socklen_t sockaddrLen) -> bool {

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

   for (struct addrinfo *candidate = results; candidate != nullptr; candidate = candidate->ai_next)
   {
      int fd = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
      if (fd < 0)
      {
         continue;
      }

      if (connectWithTimeout(fd, candidate->ai_addr, candidate->ai_addrlen))
      {
         fdOut = fd;
         freeaddrinfo(results);
         return true;
      }

      ::close(fd);
   }

   freeaddrinfo(results);
   return false;
}

static inline void mothershipCloseSSHSession(LIBSSH2_SESSION *&session, int& fd)
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
   LIBSSH2_SESSION *&session,
   int& fd,
   String *failure = nullptr,
   const Vault::SSHKeyPackage *sshKeyPackage = nullptr,
   const String *sshKeyPackagePrivateKeyPath = nullptr)
{
   session = nullptr;
   fd = -1;
   if (machine.ssh.hostPublicKeyOpenSSH.size() == 0)
   {
      if (failure) failure->assign("missing ssh host public key"_ctv);
      return false;
   }

   String sshUser = {};
   sshUser.assign(machine.ssh.user);
   String sshPrivateKeyPath = {};
   sshPrivateKeyPath.assign(machine.ssh.privateKeyPath);

   if (mothershipEnsureLibssh2() == false)
   {
      if (failure) failure->assign("failed to initialize libssh2");
      return false;
   }

   if (mothershipOpenConnectedSocket(machine.ssh.address, machine.ssh.port, fd) == false)
   {
      if (failure) failure->snprintf<"failed to connect to ssh address {}:{}"_ctv>(machine.ssh.address, unsigned(machine.ssh.port));
      return false;
   }

   session = libssh2_session_init();
   if (session == nullptr)
   {
      if (failure) failure->assign("failed to initialize ssh session");
      ::close(fd);
      fd = -1;
      return false;
   }

   libssh2_session_set_blocking(session, 1);

   if (libssh2_session_handshake(session, fd) != 0)
   {
      if (failure) failure->assign("ssh handshake failed");
      mothershipCloseSSHSession(session, fd);
      return false;
   }

   if (verifySSHSessionHostKey(machine.ssh.address, machine.ssh.port, machine.ssh.hostPublicKeyOpenSSH, session, failure) == false)
   {
      mothershipCloseSSHSession(session, fd);
      return false;
   }

   bool useKeyPackage = sshKeyPackage != nullptr
      && sshKeyPackagePrivateKeyPath != nullptr
      && prodigyBootstrapSSHKeyPackageConfigured(*sshKeyPackage)
      && (machine.ssh.privateKeyPath.size() == 0
         || machine.ssh.privateKeyPath.equals(*sshKeyPackagePrivateKeyPath)
         || ::access(sshPrivateKeyPath.c_str(), R_OK) != 0);

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
         if (failure) failure->assign("ssh public key auth failed");
         keyPackage.clear();
         mothershipCloseSSHSession(session, fd);
         return false;
      }

      keyPackage.clear();
   }
   else if (libssh2_userauth_publickey_fromfile(session, sshUser.c_str(), nullptr, sshPrivateKeyPath.c_str(), nullptr) != 0)
   {
      if (failure) failure->assign("ssh public key auth failed");
      mothershipCloseSSHSession(session, fd);
      return false;
   }

   if (failure) failure->clear();
   return true;
}
