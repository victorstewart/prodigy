#pragma once

#include <libssh2/libssh2.h>
#include <libssh2/libssh2_sftp.h>

#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <networking/includes.h>
#include <services/bitsery.h>
#include <services/filesystem.h>
#include <services/crypto.h>
#include <services/time.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/socket.h>
#include <networking/pool.h>
#include <macros/bytes.h>
#include <networking/stream.h>
#include <networking/ring.h>
#include <networking/ssh.h>
#include <networking/reconnector.h>

#include <prodigy/brain/timing.knobs.h>
#include <prodigy/bundle.artifact.h>
#include <prodigy/iaas/bootstrap.ssh.h>
#include <prodigy/peer.address.helpers.h>
#include <prodigy/persistent.state.h>
#include <services/vault.h>

static inline bool prodigyEnsureLibssh2(void)
{
   static bool initialized = [] () -> bool {

      return libssh2_init(0) == 0;
   }();

   return initialized;
}

static inline void prodigyCloseBlockingSSHSession(LIBSSH2_SESSION *&session, int& fd)
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

static inline bool prodigyOpenConnectedSocket(const String& address, uint16_t port, int& fdOut)
{
   fdOut = -1;

   String addressText = {};
   addressText.assign(address);
   char portText[16] = {};
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

static inline bool prodigyConnectBlockingSSHSession(
   const String& sshAddress,
   uint16_t sshPort,
   const String& sshHostPublicKeyOpenSSH,
   const String& sshUser,
   const String& sshPrivateKeyPath,
   const Vault::SSHKeyPackage *sshKeyPackage,
   LIBSSH2_SESSION *&session,
   int& fd,
   String *failure = nullptr)
{
   session = nullptr;
   fd = -1;

   if (prodigyEnsureLibssh2() == false)
   {
      if (failure) failure->assign("failed to initialize libssh2"_ctv);
      return false;
   }

   if (prodigyOpenConnectedSocket(sshAddress, sshPort, fd) == false)
   {
      if (failure) failure->snprintf<"failed to connect to ssh address {}:{}"_ctv>(sshAddress, unsigned(sshPort));
      return false;
   }

   session = libssh2_session_init();
   if (session == nullptr)
   {
      if (failure) failure->assign("failed to initialize ssh session"_ctv);
      ::close(fd);
      fd = -1;
      return false;
   }

   libssh2_session_set_blocking(session, 1);

   if (libssh2_session_handshake(session, fd) != 0)
   {
      if (failure) failure->assign("ssh handshake failed"_ctv);
      prodigyCloseBlockingSSHSession(session, fd);
      return false;
   }

   if (verifySSHSessionHostKey(sshAddress, sshPort, sshHostPublicKeyOpenSSH, session, failure) == false)
   {
      prodigyCloseBlockingSSHSession(session, fd);
      return false;
   }

   String sshUserText = {};
   sshUserText.assign(sshUser);

   bool useKeyPackage = sshKeyPackage != nullptr && prodigyBootstrapSSHKeyPackageConfigured(*sshKeyPackage);
   if (useKeyPackage)
   {
      Vault::SSHKeyPackage keyPackage = *sshKeyPackage;
      if (Vault::validateSSHKeyPackageEd25519(keyPackage, failure) == false)
      {
         keyPackage.clear();
         prodigyCloseBlockingSSHSession(session, fd);
         return false;
      }

      if (libssh2_userauth_publickey_frommemory(
            session,
            sshUserText.c_str(),
            sshUserText.size(),
            reinterpret_cast<const char *>(keyPackage.publicKeyOpenSSH.data()),
            keyPackage.publicKeyOpenSSH.size(),
            reinterpret_cast<const char *>(keyPackage.privateKeyOpenSSH.data()),
            keyPackage.privateKeyOpenSSH.size(),
            nullptr) != 0)
      {
         if (failure) failure->assign("ssh public key auth failed"_ctv);
         keyPackage.clear();
         prodigyCloseBlockingSSHSession(session, fd);
         return false;
      }

      keyPackage.clear();
   }
   else
   {
      String sshPrivateKeyPathText = {};
      sshPrivateKeyPathText.assign(sshPrivateKeyPath);
      if (libssh2_userauth_publickey_fromfile(session, sshUserText.c_str(), nullptr, sshPrivateKeyPathText.c_str(), nullptr) != 0)
      {
         if (failure) failure->assign("ssh public key auth failed"_ctv);
         prodigyCloseBlockingSSHSession(session, fd);
         return false;
      }
   }

   if (failure) failure->clear();
   return true;
}

static inline bool prodigyConnectBlockingSSHSession(
   const String& sshAddress,
   uint16_t sshPort,
   const String& sshHostPublicKeyOpenSSH,
   const String& sshUser,
   const String& sshPrivateKeyPath,
   LIBSSH2_SESSION *&session,
   int& fd,
   String *failure = nullptr)
{
   return prodigyConnectBlockingSSHSession(sshAddress, sshPort, sshHostPublicKeyOpenSSH, sshUser, sshPrivateKeyPath, nullptr, session, fd, failure);
}

static inline bool prodigyRunBlockingSSHCommand(LIBSSH2_SESSION *session, int fd, const String& command, String *output, String *failure, int timeoutMs = 120'000);

static inline bool prodigyRunBlockingSSHCommand(LIBSSH2_SESSION *session, int fd, const String& command, String *failure = nullptr, int timeoutMs = 120'000)
{
   return prodigyRunBlockingSSHCommand(session, fd, command, nullptr, failure, timeoutMs);
}

static inline bool prodigyWaitForBlockingSSHSessionIO(LIBSSH2_SESSION *session, int fd, int timeoutMs)
{
   if (session == nullptr || fd < 0)
   {
      return false;
   }

   struct pollfd descriptor = {};
   descriptor.fd = fd;

   int directions = libssh2_session_block_directions(session);
   if (directions & LIBSSH2_SESSION_BLOCK_INBOUND)
   {
      descriptor.events |= POLLIN;
   }

   if (directions & LIBSSH2_SESSION_BLOCK_OUTBOUND)
   {
      descriptor.events |= POLLOUT;
   }

   if (descriptor.events == 0)
   {
      descriptor.events = POLLIN | POLLOUT;
   }

   return (::poll(&descriptor, 1, timeoutMs) > 0);
}

static inline bool prodigyCloseBlockingSSHChannel(LIBSSH2_SESSION *session, int fd, LIBSSH2_CHANNEL *channel, const String& command, int timeoutMs, String *failure = nullptr)
{
   if (channel == nullptr)
   {
      if (failure) failure->clear();
      return true;
   }

   libssh2_session_set_blocking(session, 0);

   int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(timeoutMs);

   auto awaitChannelOp = [&] (auto&& operation, const char *phase) -> bool {
      String phaseText = {};
      if (phase != nullptr)
      {
         phaseText.assign(phase);
      }

      while (true)
      {
         int rc = operation(channel);
         if (rc == 0)
         {
            return true;
         }

         if (rc != LIBSSH2_ERROR_EAGAIN)
         {
            if (failure) failure->snprintf<"failed to {} remote command {}"_ctv>(phaseText, command);
            return false;
         }

         int64_t nowMs = Time::now<TimeResolution::ms>();
         if (nowMs >= deadlineMs)
         {
            if (failure) failure->snprintf<"timed out while trying to {} remote command {}"_ctv>(phaseText, command);
            return false;
         }

         int remainingMs = int(deadlineMs - nowMs);
         if (prodigyWaitForBlockingSSHSessionIO(session, fd, remainingMs) == false)
         {
            if (failure) failure->snprintf<"timed out while waiting for ssh io to {} remote command {}"_ctv>(phaseText, command);
            return false;
         }
      }
   };

   bool ok = awaitChannelOp([] (LIBSSH2_CHANNEL *activeChannel) -> int {
      return libssh2_channel_send_eof(activeChannel);
   }, "send eof for")
      && awaitChannelOp([] (LIBSSH2_CHANNEL *activeChannel) -> int {
         return libssh2_channel_wait_eof(activeChannel);
      }, "wait for eof from")
      && awaitChannelOp([] (LIBSSH2_CHANNEL *activeChannel) -> int {
         return libssh2_channel_close(activeChannel);
      }, "close ssh channel for");

   libssh2_session_set_blocking(session, 1);
   if (ok && failure)
   {
      failure->clear();
   }

   return ok;
}

static inline bool prodigyRunBlockingSSHCommand(LIBSSH2_SESSION *session, int fd, const String& command, String *output, String *failure, int timeoutMs)
{
   String commandText = {};
   commandText.assign(command);
   if (output)
   {
      output->clear();
   }

   LIBSSH2_CHANNEL *channel = libssh2_channel_open_session(session);
   if (channel == nullptr)
   {
      if (failure) failure->assign("failed to open ssh exec channel"_ctv);
      return false;
   }

   if (libssh2_channel_exec(channel, commandText.c_str()) != 0)
   {
      if (failure) failure->snprintf<"failed to execute remote command {}"_ctv>(command);
      libssh2_channel_free(channel);
      return false;
   }

   libssh2_session_set_blocking(session, 0);

   char scratch[1024];
   String stderrOutput = {};
   int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(timeoutMs);
   while (true)
   {
      bool progressed = false;

      while (true)
      {
         ssize_t readBytes = libssh2_channel_read(channel, scratch, sizeof(scratch));
         if (readBytes > 0)
         {
            if (output)
            {
               output->append(reinterpret_cast<const uint8_t *>(scratch), uint64_t(readBytes));
            }

            progressed = true;
            continue;
         }

         if (readBytes == LIBSSH2_ERROR_EAGAIN)
         {
            break;
         }

         if (readBytes < 0)
         {
            if (failure) failure->snprintf<"failed to read remote command stdout: {}"_ctv>(command);
            (void)prodigyCloseBlockingSSHChannel(session, fd, channel, command, timeoutMs, nullptr);
            libssh2_channel_free(channel);
            return false;
         }

         break;
      }

      while (true)
      {
         ssize_t readBytes = libssh2_channel_read_stderr(channel, scratch, sizeof(scratch));
         if (readBytes > 0)
         {
            stderrOutput.append(reinterpret_cast<const uint8_t *>(scratch), uint64_t(readBytes));
            progressed = true;
            continue;
         }

         if (readBytes == LIBSSH2_ERROR_EAGAIN)
         {
            break;
         }

         if (readBytes < 0)
         {
            if (failure) failure->snprintf<"failed to read remote command stderr: {}"_ctv>(command);
            (void)prodigyCloseBlockingSSHChannel(session, fd, channel, command, timeoutMs, nullptr);
            libssh2_channel_free(channel);
            return false;
         }

         break;
      }

      if (libssh2_channel_eof(channel))
      {
         break;
      }

      if (progressed)
      {
         continue;
      }

      int64_t nowMs = Time::now<TimeResolution::ms>();
      if (nowMs >= deadlineMs)
      {
         if (failure) failure->snprintf<"remote command timed out after {itoa}ms: {}"_ctv>(uint64_t(timeoutMs), command);
         (void)prodigyCloseBlockingSSHChannel(session, fd, channel, command, timeoutMs, nullptr);
         libssh2_channel_free(channel);
         return false;
      }

      int remainingMs = int(deadlineMs - nowMs);
      if (prodigyWaitForBlockingSSHSessionIO(session, fd, remainingMs) == false)
      {
         if (failure) failure->snprintf<"remote command timed out after {itoa}ms waiting for ssh io: {}"_ctv>(uint64_t(timeoutMs), command);
         (void)prodigyCloseBlockingSSHChannel(session, fd, channel, command, timeoutMs, nullptr);
         libssh2_channel_free(channel);
         return false;
      }
   }

   bool closeOk = prodigyCloseBlockingSSHChannel(session, fd, channel, command, timeoutMs, failure);
   int exitStatus = libssh2_channel_get_exit_status(channel);
   libssh2_channel_free(channel);
   if (closeOk == false)
   {
      return false;
   }

   if (exitStatus != 0)
   {
      if (failure)
      {
         if (stderrOutput.size() > 0)
         {
            failure->snprintf<"remote command failed: {} stderr: {}"_ctv>(command, stderrOutput);
         }
         else if (output && output->size() > 0)
         {
            failure->snprintf<"remote command failed: {} stdout: {}"_ctv>(command, *output);
         }
         else
         {
            failure->snprintf<"remote command failed: {}"_ctv>(command);
         }
      }

      return false;
   }

   if (failure) failure->clear();
   return true;
}

class ProdigyRemoteMachineResources
{
public:

   uint32_t totalLogicalCores = 0;
   uint32_t totalMemoryMB = 0;
   uint32_t totalStorageMB = 0;
   Vector<ClusterMachinePeerAddress> peerAddresses;

   bool operator==(const ProdigyRemoteMachineResources& other) const
   {
      if (totalLogicalCores != other.totalLogicalCores
         || totalMemoryMB != other.totalMemoryMB
         || totalStorageMB != other.totalStorageMB
         || peerAddresses.size() != other.peerAddresses.size())
      {
         return false;
      }

      for (uint32_t index = 0; index < peerAddresses.size(); ++index)
      {
         if (peerAddresses[index] != other.peerAddresses[index])
         {
            return false;
         }
      }

      return true;
   }

   bool operator!=(const ProdigyRemoteMachineResources& other) const
   {
      return (*this == other) == false;
   }
};

static inline bool prodigyResolveClusterMachineSSHAddress(const ClusterMachine& clusterMachine, String& sshAddress);

static inline void prodigyRenderRemoteMachineResourceProbeCommand(String& command)
{
   command.assign(
      "set -eu; "
      "cores=$(getconf _NPROCESSORS_ONLN); "
      "mem_kb=0; "
      "while IFS=' ' read -r key value unit; do "
      "if [ \"$key\" = \"MemTotal:\" ]; then mem_kb=$value; break; fi; "
      "done < /proc/meminfo; "
      "storage_mb=$(df -Pm /var/lib/prodigy 2>/dev/null | sed -n '2p' | tr -s ' ' | cut -d ' ' -f 2); "
      "if [ -z \"$storage_mb\" ]; then storage_mb=$(df -Pm / 2>/dev/null | sed -n '2p' | tr -s ' ' | cut -d ' ' -f 2); fi; "
      "printf '%s\\n%s\\n%s\\n' \"$cores\" \"$((mem_kb / 1024))\" \"$storage_mb\"; "
      "{ "
      "ip -o -4 addr show scope global 2>/dev/null | while read -r idx dev fam local rest; do "
      "addr=${local%/*}; cidr=${local#*/}; "
      "gw=$(ip -o -4 route show default dev \"$dev\" 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++) if($i==\"via\"){print $(i+1); exit}}'); "
      "printf '%s|%s|%s\\n' \"$addr\" \"$cidr\" \"$gw\"; "
      "done; "
      "ip -o -6 addr show scope global 2>/dev/null | while read -r idx dev fam local rest; do "
      "addr=${local%/*}; case \"$addr\" in fe80:*) continue ;; esac; cidr=${local#*/}; "
      "gw=$(ip -o -6 route show default dev \"$dev\" 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++) if($i==\"via\"){print $(i+1); exit}}'); "
      "printf '%s|%s|%s\\n' \"$addr\" \"$cidr\" \"$gw\"; "
      "done; "
      "} | awk '!seen[$0]++'"_ctv
   );
}

static inline bool prodigyParseUnsignedDecimalString(const String& value, uint32_t& parsed)
{
   uint64_t start = 0;
   while (start < value.size() && std::isspace(unsigned(value[start])))
   {
      start += 1;
   }

   uint64_t end = value.size();
   while (end > start && std::isspace(unsigned(value[end - 1])))
   {
      end -= 1;
   }

   if (start >= end)
   {
      return false;
   }

   String owned = {};
   owned.assign(value.substr(start, end - start, Copy::yes));
   char *tail = nullptr;
   errno = 0;
   unsigned long long parsedValue = std::strtoull(owned.c_str(), &tail, 10);
   if (errno != 0 || tail == owned.c_str())
   {
      return false;
   }

   while (tail && *tail != '\0' && std::isspace(unsigned(*tail)))
   {
      tail += 1;
   }

   if (tail == nullptr || *tail != '\0' || parsedValue > uint64_t(UINT32_MAX))
   {
      return false;
   }

   parsed = uint32_t(parsedValue);
   return true;
}

static inline bool prodigyParseRemoteMachineResourceAddressLine(const String& line, ClusterMachinePeerAddress& candidate)
{
   candidate = {};

   uint64_t firstDelimiter = line.size();
   uint64_t secondDelimiter = line.size();
   for (uint64_t index = 0; index < line.size(); ++index)
   {
      if (line[index] != '|')
      {
         continue;
      }

      if (firstDelimiter == line.size())
      {
         firstDelimiter = index;
      }
      else
      {
         secondDelimiter = index;
         break;
      }
   }

   if (firstDelimiter == line.size() || secondDelimiter == line.size() || secondDelimiter <= firstDelimiter)
   {
      return false;
   }

   String addressText = {};
   String cidrText = {};
   String gatewayText = {};
   addressText.assign(line.substr(0, firstDelimiter, Copy::yes));
   cidrText.assign(line.substr(firstDelimiter + 1, secondDelimiter - firstDelimiter - 1, Copy::yes));
   gatewayText.assign(line.substr(secondDelimiter + 1, line.size() - secondDelimiter - 1, Copy::yes));

   int64_t cidr = 0;
   char *tail = nullptr;
   errno = 0;
   unsigned long long parsedCidr = std::strtoull(cidrText.c_str(), &tail, 10);
   if (errno != 0 || tail == cidrText.c_str() || (tail && *tail != '\0') || parsedCidr > 255ull)
   {
      return false;
   }
   cidr = int64_t(parsedCidr);

   candidate.address = addressText;
   candidate.cidr = uint8_t(cidr);
   candidate.gateway = gatewayText;
   ClusterMachinePeerAddress normalized = {};
   if (prodigyNormalizeClusterMachinePeerAddress(candidate, normalized) == false)
   {
      return false;
   }

   candidate = normalized;
   return true;
}

static inline bool prodigyParseRemoteMachineResources(const String& output, ProdigyRemoteMachineResources& resources, String *failure = nullptr)
{
   if (failure) failure->clear();
   resources = {};

   uint64_t offset = 0;
   Vector<String> lines;
   uint32_t index = 0;
   while (offset < output.size())
   {
      uint64_t lineStart = offset;
      while (offset < output.size() && output[offset] != '\n')
      {
         offset += 1;
      }

      uint64_t lineEnd = offset;
      if (offset < output.size() && output[offset] == '\n')
      {
         offset += 1;
      }

      while (lineStart < lineEnd && std::isspace(unsigned(output[lineStart])))
      {
         lineStart += 1;
      }

      while (lineEnd > lineStart && std::isspace(unsigned(output[lineEnd - 1])))
      {
         lineEnd -= 1;
      }

      if (lineStart == lineEnd)
      {
         continue;
      }

      String line = {};
      line.assign(output.substr(lineStart, lineEnd - lineStart, Copy::yes));
      lines.push_back(line);
      index += 1;
   }

   if (index < 3)
   {
      if (failure) failure->assign("remote resource probe returned fewer than 3 numeric lines"_ctv);
      return false;
   }

   if (prodigyParseUnsignedDecimalString(lines[0], resources.totalLogicalCores) == false
      || prodigyParseUnsignedDecimalString(lines[1], resources.totalMemoryMB) == false
      || prodigyParseUnsignedDecimalString(lines[2], resources.totalStorageMB) == false)
   {
      if (failure) failure->assign("remote resource probe returned invalid numeric output"_ctv);
      return false;
   }

   if (resources.totalLogicalCores == 0 || resources.totalMemoryMB == 0 || resources.totalStorageMB == 0)
   {
      if (failure) failure->assign("remote resource probe returned zero resources"_ctv);
      return false;
   }

   for (uint32_t lineIndex = 3; lineIndex < lines.size(); ++lineIndex)
   {
      ClusterMachinePeerAddress candidate = {};
      if (prodigyParseRemoteMachineResourceAddressLine(lines[lineIndex], candidate))
      {
         prodigyAppendUniqueClusterMachinePeerAddress(resources.peerAddresses, candidate);
      }
   }

   return true;
}

static inline bool prodigyProbeRemoteMachineResources(const ClusterMachine& clusterMachine, ProdigyRemoteMachineResources& resources, String *failure = nullptr)
{
   if (failure) failure->clear();
   resources = {};

   String label = {};
   clusterMachine.renderIdentityLabel(label);

   String sshAddress;
   if (prodigyResolveClusterMachineSSHAddress(clusterMachine, sshAddress) == false)
   {
      if (failure) failure->snprintf<"machine '{}' has no ssh address"_ctv>(label);
      return false;
   }

   if (clusterMachine.ssh.user.size() == 0)
   {
      if (failure) failure->snprintf<"machine '{}' has no ssh user"_ctv>(label);
      return false;
   }

   if (clusterMachine.ssh.hostPublicKeyOpenSSH.size() == 0)
   {
      if (failure) failure->snprintf<"machine '{}' has no ssh.hostPublicKeyOpenSSH"_ctv>(label);
      return false;
   }

   if (clusterMachine.ssh.privateKeyPath.size() == 0)
   {
      if (failure) failure->snprintf<"machine '{}' has no sshPrivateKeyPath"_ctv>(label);
      return false;
   }

   LIBSSH2_SESSION *session = nullptr;
   int fd = -1;
   if (prodigyConnectBlockingSSHSession(
         sshAddress,
         clusterMachine.ssh.port > 0 ? clusterMachine.ssh.port : 22,
         clusterMachine.ssh.hostPublicKeyOpenSSH,
         clusterMachine.ssh.user,
         clusterMachine.ssh.privateKeyPath,
         session,
         fd,
         failure) == false)
   {
      return false;
   }

   String command;
   prodigyRenderRemoteMachineResourceProbeCommand(command);

   String output;
   bool success = prodigyRunBlockingSSHCommand(session, fd, command, &output, failure)
      && prodigyParseRemoteMachineResources(output, resources, failure);
   prodigyCloseBlockingSSHSession(session, fd);
   return success;
}

static inline bool prodigyUploadLocalFileToSSHSession(LIBSSH2_SESSION *session, int fd, const String& localPath, const String& remotePath, long permissions, String *failure = nullptr, int timeoutMs = 120'000)
{
   String localPathText = {};
   localPathText.assign(localPath);
   FILE *localFile = std::fopen(localPathText.c_str(), "rb");
   if (localFile == nullptr)
   {
      if (failure) failure->snprintf<"failed to open local file {}"_ctv>(localPath);
      return false;
   }

   LIBSSH2_SFTP *sftp = libssh2_sftp_init(session);
   if (sftp == nullptr)
   {
      std::fclose(localFile);
      if (failure) failure->assign("failed to initialize ssh sftp session"_ctv);
      return false;
   }

   String remotePathText = {};
   remotePathText.assign(remotePath);
   LIBSSH2_SFTP_HANDLE *handle = libssh2_sftp_open(sftp, remotePathText.c_str(), LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, permissions);
   if (handle == nullptr)
   {
      libssh2_sftp_shutdown(sftp);
      std::fclose(localFile);
      if (failure) failure->snprintf<"failed to open remote file {}"_ctv>(remotePath);
      return false;
   }

   bool success = true;
   ssize_t lastWriteResult = 0;
   // Bundle upload dominates the per-machine post-SSH path, so keep each
   // libssh2 SFTP write large to reduce round trips on the hot path.
   char buffer[1_MB];
   int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(timeoutMs);
   while (success)
   {
      size_t readBytes = std::fread(buffer, 1, sizeof(buffer), localFile);
      if (readBytes == 0)
      {
         break;
      }

      size_t written = 0;
      while (written < readBytes)
      {
         ssize_t result = libssh2_sftp_write(handle, buffer + written, readBytes - written);
         if (result == LIBSSH2_ERROR_EAGAIN)
         {
            int64_t nowMs = Time::now<TimeResolution::ms>();
            if (nowMs >= deadlineMs || prodigyWaitForBlockingSSHSessionIO(session, fd, int(deadlineMs - nowMs)) == false)
            {
               lastWriteResult = result;
               success = false;
               break;
            }

            continue;
         }

         if (result <= 0)
         {
            lastWriteResult = result;
            success = false;
            break;
         }

         written += size_t(result);
         deadlineMs = Time::now<TimeResolution::ms>() + int64_t(timeoutMs);
      }

      if (readBytes < sizeof(buffer) && std::feof(localFile))
      {
         break;
      }
   }

   bool localReadError = (std::ferror(localFile) != 0);
   uint64_t sftpError = libssh2_sftp_last_error(sftp);
   int sessionError = libssh2_session_last_errno(session);
   libssh2_sftp_close(handle);
   libssh2_sftp_shutdown(sftp);
   std::fclose(localFile);

   if (success == false && failure)
   {
      failure->snprintf<"failed to upload local file {} writeResult={} sessionErr={} sftpErr={itoa} localReadErr={}"_ctv>(localPath, int64_t(lastWriteResult), sessionError, sftpError, localReadError ? 1 : 0);
   }

   return success;
}

class ProdigyRemoteBootstrapPlan
{
public:

   MachineCpuArchitecture architecture = MachineCpuArchitecture::unknown;
   ClusterMachineSSH ssh;
   Vault::SSHKeyPackage bootstrapSshKeyPackage;
   String remoteBootstrapSSHPrivateKeyPath;
   String remoteBootstrapSSHPublicKeyPath;
   String localBundlePath;
   ProdigyInstallRootPaths installPaths;
   String remoteStagePayloadPath;
   String remoteUnitPath;
   String remoteUnitTempPath;
   String controlSocketDirectory;
   String bootstrapSSHDirectory;
   String bootJSON;
   String remoteBootJSONPath;
   String mkdirCommand;
   String installCommand;
   String stopCommand;
   String systemdUnit;
   String remoteTransportTLSJSONPath;
   String transportTLSJSON;
   uint64_t connectRetryBudgetMs = 0;
};

class ProdigyRemoteBootstrapClusterTransportTLSState
{
public:

   String rootCertPem;
   String rootKeyPem;
   bytell_hash_map<String, uint128_t> uuidsByMachineKey;
};

static inline bytell_hash_map<uint64_t, ProdigyRemoteBootstrapClusterTransportTLSState> prodigyRemoteBootstrapClusterTransportTLSStateByKey;

static inline uint64_t prodigyMeasureLocalFileSize(const String& path)
{
   String pathText = {};
   pathText.assign(path);

   struct stat status = {};
   if (::stat(pathText.c_str(), &status) != 0 || status.st_size < 0)
   {
      return 0;
   }

   return uint64_t(status.st_size);
}

static inline void prodigyLogRemoteBootstrapStep(const char *stage, const char *step, const ProdigyRemoteBootstrapPlan& plan, const String *detail = nullptr)
{
   std::fprintf(stderr,
      "prodigy remote-bootstrap %s step=%s ssh=%.*s:%u user=%.*s installRoot=%.*s remoteBundle=%.*s remoteUnit=%.*s detail=%.*s\n",
      stage,
      step,
      int(plan.ssh.address.size()),
      reinterpret_cast<const char *>(plan.ssh.address.data()),
      unsigned(plan.ssh.port),
      int(plan.ssh.user.size()),
      reinterpret_cast<const char *>(plan.ssh.user.data()),
      int(plan.installPaths.installRoot.size()),
      reinterpret_cast<const char *>(plan.installPaths.installRoot.data()),
      int(plan.installPaths.bundleTempPath.size()),
      reinterpret_cast<const char *>(plan.installPaths.bundleTempPath.data()),
      int(plan.remoteUnitPath.size()),
      reinterpret_cast<const char *>(plan.remoteUnitPath.data()),
      (detail ? int(detail->size()) : 0),
      (detail ? reinterpret_cast<const char *>(detail->data()) : ""));
   std::fflush(stderr);
}

static inline uint64_t prodigyRemoteBootstrapHashBytes(const uint8_t *bytes, uint64_t size)
{
   uint64_t hash = 1469598103934665603ULL;
   for (uint64_t index = 0; index < size; ++index)
   {
      hash ^= uint64_t(bytes[index]);
      hash *= 1099511628211ULL;
   }

   return hash;
}

static inline uint64_t prodigyRemoteBootstrapClusterKey(const ClusterTopology& topology)
{
   ClusterTopology normalized = topology;
   prodigyNormalizeClusterTopologyPeerAddresses(normalized);
   String serialized = {};
   BitseryEngine::serialize(serialized, normalized);
   return prodigyRemoteBootstrapHashBytes(serialized.data(), serialized.size());
}

static inline void prodigyRenderRemoteBootstrapMachineKey(const ClusterMachine& clusterMachine, String& key)
{
   key.clear();
   if (clusterMachine.uuid != 0)
   {
      key.assignItoh(clusterMachine.uuid);
      return;
   }

   if (clusterMachine.cloud.cloudID.size() > 0)
   {
      key.append("cloud:"_ctv);
      key.append(clusterMachine.cloud.cloudID);
      return;
   }

   key.append(clusterMachine.cloud.cloudID);
   key.append("|"_ctv);
   key.append(clusterMachine.ssh.address);
   key.append("|"_ctv);
   key.append(clusterMachine.cloud.schema);

   for (const ClusterMachineAddress& address : clusterMachine.addresses.privateAddresses)
   {
      key.append("|"_ctv);
      key.append(address.address);
   }

   for (const ClusterMachineAddress& address : clusterMachine.addresses.publicAddresses)
   {
      key.append("|"_ctv);
      key.append(address.address);
   }
}

static inline uint128_t prodigyResolveRemoteBootstrapMachineUUID(
   ProdigyRemoteBootstrapClusterTransportTLSState& clusterTLS,
   const ClusterMachine& clusterMachine)
{
   if (clusterMachine.uuid != 0)
   {
      return clusterMachine.uuid;
   }

   String key = {};
   prodigyRenderRemoteBootstrapMachineKey(clusterMachine, key);
   if (auto it = clusterTLS.uuidsByMachineKey.find(key); it != clusterTLS.uuidsByMachineKey.end())
   {
      return it->second;
   }

   uint128_t uuid = Random::generateNumberWithNBits<128, uint128_t>();
   clusterTLS.uuidsByMachineKey.insert_or_assign(key, uuid);
   return uuid;
}

static inline ProdigyRemoteBootstrapClusterTransportTLSState *prodigyResolveRemoteBootstrapClusterTLSState(uint128_t clusterUUID, const ClusterTopology& topology, String *failure = nullptr)
{
   if (ProdigyTransportTLSRuntime::configured() && ProdigyTransportTLSRuntime::canMintForCluster())
   {
      static ProdigyRemoteBootstrapClusterTransportTLSState runtimeState = {};
      const ProdigyTransportTLSBootstrap& bootstrap = ProdigyTransportTLSRuntime::state();
      runtimeState.rootCertPem = bootstrap.transport.clusterRootCertPem;
      runtimeState.rootKeyPem = bootstrap.transport.clusterRootKeyPem;
      return &runtimeState;
   }

   uint64_t clusterKey = (clusterUUID != 0)
      ? uint64_t(clusterUUID ^ (clusterUUID >> 64))
      : prodigyRemoteBootstrapClusterKey(topology);
   auto it = prodigyRemoteBootstrapClusterTransportTLSStateByKey.find(clusterKey);
   if (it == prodigyRemoteBootstrapClusterTransportTLSStateByKey.end())
   {
      ProdigyRemoteBootstrapClusterTransportTLSState state = {};
      it = prodigyRemoteBootstrapClusterTransportTLSStateByKey.insert_or_assign(clusterKey, state).first;
   }

   if (it->second.rootCertPem.size() == 0 || it->second.rootKeyPem.size() == 0)
   {
      if (Vault::generateTransportRootCertificateEd25519(it->second.rootCertPem, it->second.rootKeyPem, failure) == false)
      {
         return nullptr;
      }
   }

   if (failure) failure->clear();
   return &it->second;
}

static inline void prodigyCollectRemoteBootstrapNodeIPAddresses(const ClusterMachine& clusterMachine, Vector<String>& addresses)
{
   addresses.clear();

   Vector<ClusterMachinePeerAddress> candidates = {};
   prodigyCollectClusterMachinePeerAddresses(clusterMachine, candidates);
   for (const ClusterMachinePeerAddress& candidate : candidates)
   {
      Vault::appendUniqueIPLiteral(addresses, candidate.address);
   }

   Vault::appendUniqueIPLiteral(addresses, clusterMachine.ssh.address);
}

static inline bool prodigyBuildRemoteBootstrapTransportTLSState(
   const ClusterMachine& clusterMachine,
   const ClusterTopology& topology,
   ProdigyPersistentLocalBrainState& localState,
   ClusterTopology& bootTopology,
   String *failure = nullptr)
{
   if (failure) failure->clear();

   uint128_t ownerClusterUUID = localState.ownerClusterUUID;

   ProdigyRemoteBootstrapClusterTransportTLSState *clusterTLS = prodigyResolveRemoteBootstrapClusterTLSState(ownerClusterUUID, topology, failure);
   if (clusterTLS == nullptr)
   {
      return false;
   }

   bootTopology = topology;
   bool foundLocalMachine = false;
   for (const ClusterMachine& machine : bootTopology.machines)
   {
      if (machine.sameIdentityAs(clusterMachine))
      {
         foundLocalMachine = true;
         break;
      }
   }
   if (foundLocalMachine == false)
   {
      bootTopology.machines.push_back(clusterMachine);
   }

   for (ClusterMachine& machine : bootTopology.machines)
   {
      machine.uuid = prodigyResolveRemoteBootstrapMachineUUID(*clusterTLS, machine);
   }

   uint128_t localUUID = 0;
   for (const ClusterMachine& machine : bootTopology.machines)
   {
      if (machine.sameIdentityAs(clusterMachine))
      {
         localUUID = machine.uuid;
         break;
      }
   }

   if (localUUID == 0)
   {
      if (failure) failure->assign("failed to resolve bootstrap uuid for machine"_ctv);
      return false;
   }

   localState = {};
   localState.uuid = localUUID;
   localState.ownerClusterUUID = ownerClusterUUID;

   if (clusterTLS->rootCertPem.size() == 0 || clusterTLS->rootKeyPem.size() == 0)
   {
      if (clusterMachine.isBrain && clusterTopologyBrainCount(bootTopology) <= 1)
      {
         if (failure) failure->clear();
         return true;
      }

      if (failure) failure->assign("transport tls issuer unavailable for multi-node bootstrap"_ctv);
      return false;
   }

   Vector<String> ipAddresses;
   prodigyCollectRemoteBootstrapNodeIPAddresses(clusterMachine, ipAddresses);

   localState.transportTLS.generation = 1;
   localState.transportTLS.clusterRootCertPem = clusterTLS->rootCertPem;
   if (clusterMachine.isBrain)
   {
      localState.transportTLS.clusterRootKeyPem = clusterTLS->rootKeyPem;
   }

   if (Vault::generateTransportNodeCertificateEd25519(
         clusterTLS->rootCertPem,
         clusterTLS->rootKeyPem,
         localUUID,
         ipAddresses,
         localState.transportTLS.localCertPem,
         localState.transportTLS.localKeyPem,
         failure) == false)
   {
      return false;
   }

   return true;
}

static inline void renderProdigySystemdUnit(const String& remoteBinaryPath, const String& remoteLibraryDirectory, const String& controlSocketDirectory, String& unit)
{
   unit.clear();
   unit.append("[Unit]\n"_ctv);
   unit.append("Description=Prodigy\n"_ctv);
   unit.append("After=network-online.target\n"_ctv);
   unit.append("Wants=network-online.target\n\n"_ctv);
   unit.append("[Service]\n"_ctv);
   unit.append("Type=simple\n"_ctv);
   unit.append("Environment=LD_LIBRARY_PATH="_ctv);
   unit.append(remoteLibraryDirectory);
   unit.append("\n"_ctv);
   unit.append("ExecStartPre=/usr/bin/mkdir -p "_ctv);
   unit.append(controlSocketDirectory);
   unit.append(" /var/lib/prodigy "_ctv);
   unit.append(remoteLibraryDirectory);
   unit.append("\n"_ctv);
   unit.append("ExecStart="_ctv);
   unit.append(remoteBinaryPath);
   unit.append("\n"_ctv);
   unit.append("Restart=always\n"_ctv);
   unit.append("RestartSec=1\n\n"_ctv);
   unit.append("[Install]\n"_ctv);
   unit.append("WantedBy=multi-user.target\n"_ctv);
}

static inline void prodigyAppendRemoteControlSocketWaitCommand(String& command, const String& controlSocketPath, uint32_t timeoutSeconds = prodigyRemoteBootstrapControlSocketWaitSeconds)
{
   String pythonScript = {};
   String probeTimeoutMs = {};
   probeTimeoutMs.assignItoa(prodigyRemoteBootstrapControlSocketProbeTimeoutMs);
   String probeSleepMs = {};
   probeSleepMs.assignItoa(prodigyRemoteBootstrapControlSocketProbeSleepMs);
   pythonScript.append(
      "import socket,sys,time\n"
      "path=sys.argv[1]\n"
      "deadline=time.monotonic()+float(sys.argv[2])\n"
      "last='socket unavailable'\n"
      "probe_timeout_ms="_ctv);
   pythonScript.append(probeTimeoutMs);
   pythonScript.append(
      "\n"
      "probe_sleep_ms="_ctv);
   pythonScript.append(probeSleepMs);
   pythonScript.append(
      "\n"
      "while time.monotonic()<deadline:\n"
      "    sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
      "    sock.settimeout(probe_timeout_ms / 1000.0)\n"
      "    try:\n"
      "        sock.connect(path)\n"
      "    except OSError as exc:\n"
      "        last=str(exc)\n"
      "        sock.close()\n"
      "        time.sleep(probe_sleep_ms / 1000.0)\n"
      "        continue\n"
      "    sock.close()\n"
      "    raise SystemExit(0)\n"
      "sys.stderr.write('timed out waiting for prodigy control socket ' + path + ': ' + last + '\\n')\n"
      "raise SystemExit(1)\n"_ctv);

   command.append("python3 -c "_ctv);
   prodigyAppendShellSingleQuoted(command, pythonScript);
   command.append(" "_ctv);
   prodigyAppendShellSingleQuoted(command, controlSocketPath);
   command.append(" "_ctv);
   String timeoutText = {};
   timeoutText.assignItoa(timeoutSeconds);
   command.append(timeoutText);
}

static inline void prodigyAppendRemoteBootstrapSocketFailureDiagnostics(String& command)
{
   String diagnosticCommand = {};
   diagnosticCommand.append(
      "exec 1>&2; "
      "printf \"\\n%s\\n\" \"=== systemctl ===\"; systemctl status prodigy --no-pager -l || true; "
      "printf \"\\n%s\\n\" \"=== journalctl ===\"; journalctl -u prodigy -n 120 --no-pager || true; "
      "printf \"\\n%s\\n\" \"=== socket ===\"; ls -ld /run/prodigy /run/prodigy/control.sock || true; "
      "printf \"\\n%s\\n\" \"=== unix listeners ===\"; ss -xlpn | grep prodigy || true; "
      "printf \"\\n%s\\n\" \"=== tcp listeners ===\"; ss -ltnp | grep prodigy || true; "
      "printf \"\\n%s\\n\" \"=== ps ===\"; ps -ef | grep \"[p]rodigy\" || true"_ctv);

   command.append("timeout "_ctv);
   String timeoutSeconds = {};
   timeoutSeconds.assignItoa(prodigyRemoteBootstrapSocketDiagnosticsTimeoutSeconds);
   command.append(timeoutSeconds);
   command.append("s sh -lc "_ctv);
   prodigyAppendShellSingleQuoted(command, diagnosticCommand);
}

static inline bool prodigyResolveClusterMachineSSHAddress(const ClusterMachine& clusterMachine, String& sshAddress)
{
   sshAddress.assign(clusterMachine.ssh.address);
   if (sshAddress.size() == 0)
   {
      if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(clusterMachine.addresses.privateAddresses); privateAddress != nullptr)
      {
         sshAddress.assign(privateAddress->address);
      }
      else if (const ClusterMachineAddress *publicAddress = prodigyFirstClusterMachineAddress(clusterMachine.addresses.publicAddresses); publicAddress != nullptr)
      {
         sshAddress.assign(publicAddress->address);
      }
   }

   return sshAddress.size() > 0;
}

static inline bool prodigyResolveClusterMachineInternalSSHAddress(const ClusterMachine& clusterMachine, String& sshAddress)
{
   sshAddress.clear();

   // Once bootstrap is running from an already-live cluster machine, prefer the
   // target's private route so seed-to-peer bundle transfer stays on the
   // provider network instead of hairpinning over the public SSH endpoint.
   if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(clusterMachine.addresses.privateAddresses); privateAddress != nullptr)
   {
      sshAddress.assign(privateAddress->address);
      return true;
   }

   return prodigyResolveClusterMachineSSHAddress(clusterMachine, sshAddress);
}

static inline void prodigyRenderClusterTopologyBootstrapPeers(const ClusterMachine& localMachine, const ClusterTopology& topology, Vector<ProdigyBootstrapConfig::BootstrapPeer>& peers)
{
   peers.clear();

   ClusterTopology normalizedTopology = topology;
   prodigyNormalizeClusterTopologyPeerAddresses(normalizedTopology);
   for (const ClusterMachine& clusterMachine : normalizedTopology.machines)
   {
      if (clusterMachine.isBrain == false)
      {
         continue;
      }

      if (clusterMachine.sameIdentityAs(localMachine))
      {
         continue;
      }

      ProdigyBootstrapConfig::BootstrapPeer peer = {};
      peer.isBrain = true;
      Vector<ClusterMachinePeerAddress> candidates = {};
      prodigyCollectClusterMachinePeerAddresses(clusterMachine, candidates);
      for (const ClusterMachinePeerAddress& candidate : candidates)
      {
         if (candidate.address.size() > 0)
         {
            peer.addresses.push_back(candidate);
         }
      }

      prodigyAppendUniqueBootstrapPeer(peers, peer);
   }

   std::sort(peers.begin(), peers.end(), prodigyBootstrapPeerComesBefore);
}

static inline bool prodigyRemoteBootstrapShouldAwaitControlSocket(const ClusterMachine& clusterMachine, const ProdigyPersistentBootState& bootState)
{
   if (clusterMachine.isBrain == false)
   {
      return false;
   }

   // Only the bootstrap controller that starts without any peer brains
   // self-elects immediately and exposes the mothership Unix socket during the
   // install step. Followers and workers can be healthy without that socket.
   return bootState.bootstrapConfig.bootstrapPeers.empty();
}

static inline bool prodigyBuildRemoteBootstrapPlan(const ClusterMachine& clusterMachine, const AddMachines& request, const ClusterTopology& topology, const ProdigyRuntimeEnvironmentConfig& runtimeEnvironment, ProdigyRemoteBootstrapPlan& plan, String *failure = nullptr)
{
   plan = {};
   if (failure) failure->clear();
   String label = {};
   clusterMachine.renderIdentityLabel(label);

   if (request.controlSocketPath.size() == 0)
   {
      if (failure) failure->assign("addMachines controlSocketPath required"_ctv);
      return false;
   }

   if (request.clusterUUID == 0)
   {
      if (failure) failure->assign("addMachines clusterUUID required"_ctv);
      return false;
   }

   if (prodigyMachineCpuArchitectureSupportedTarget(request.architecture) == false)
   {
      if (failure) failure->assign("addMachines architecture required"_ctv);
      return false;
   }

   if (request.remoteProdigyPath.size() == 0)
   {
      if (failure) failure->assign("addMachines remoteProdigyPath required"_ctv);
      return false;
   }

   if (prodigyResolveClusterMachineSSHAddress(clusterMachine, plan.ssh.address) == false)
   {
      if (failure) failure->snprintf<"machine '{}' has no ssh address"_ctv>(label);
      return false;
   }

   if (clusterMachine.ssh.user.size() == 0)
   {
      if (failure) failure->snprintf<"machine '{}' has no ssh user"_ctv>(label);
      return false;
   }

   if (clusterMachine.ssh.hostPublicKeyOpenSSH.size() == 0)
   {
      if (failure) failure->snprintf<"machine '{}' has no ssh.hostPublicKeyOpenSSH"_ctv>(label);
      return false;
   }

   if (clusterMachine.ssh.privateKeyPath.size() == 0
      && prodigyBootstrapSSHKeyPackageConfigured(request.bootstrapSshKeyPackage) == false)
   {
      if (failure) failure->snprintf<"machine '{}' has no sshPrivateKeyPath"_ctv>(label);
      return false;
   }

   plan.architecture = request.architecture;
   plan.ssh.port = clusterMachine.ssh.port > 0 ? clusterMachine.ssh.port : 22;
   plan.ssh.user = clusterMachine.ssh.user;
   plan.ssh.privateKeyPath = clusterMachine.ssh.privateKeyPath;
   plan.ssh.hostPublicKeyOpenSSH = clusterMachine.ssh.hostPublicKeyOpenSSH;
   plan.bootstrapSshKeyPackage = request.bootstrapSshKeyPackage;
   String localExecutablePath = {};
   (void)prodigyResolveCurrentExecutablePath(localExecutablePath);
   if (prodigyResolvePreferredBootstrapBundleArtifact(localExecutablePath, plan.architecture, request.remoteProdigyPath, plan.localBundlePath, failure) == false)
   {
      return false;
   }

   if (failure != nullptr)
   {
      failure->clear();
   }
   plan.remoteUnitPath.assign("/etc/systemd/system/prodigy.service"_ctv);
   plan.connectRetryBudgetMs = uint64_t(clusterMachine.source == ClusterMachineSource::created ? Time::minsToMs(10) : Time::minsToMs(2));

   ProdigyPersistentLocalBrainState localState = {};
   localState.ownerClusterUUID = request.clusterUUID;
   ClusterTopology bootTopology = {};
   if (prodigyBuildRemoteBootstrapTransportTLSState(clusterMachine, topology, localState, bootTopology, failure) == false)
   {
      return false;
   }

   ProdigyPersistentBootState bootState = {};
   prodigyRenderClusterTopologyBootstrapPeers(clusterMachine, bootTopology, bootState.bootstrapConfig.bootstrapPeers);
   bootState.bootstrapConfig.nodeRole = clusterMachine.isBrain ? ProdigyBootstrapNodeRole::brain : ProdigyBootstrapNodeRole::neuron;
   bootState.bootstrapConfig.controlSocketPath = request.controlSocketPath;
   bootState.bootstrapSshUser = request.bootstrapSshUser;
   bootState.bootstrapSshKeyPackage = request.bootstrapSshKeyPackage;
   bootState.bootstrapSshHostKeyPackage = request.bootstrapSshHostKeyPackage;
   bootState.bootstrapSshPrivateKeyPath = request.bootstrapSshPrivateKeyPath;
   ProdigyRuntimeEnvironmentConfig effectiveRuntimeEnvironment = runtimeEnvironment;
   // First boot only needs provider identity so the node can derive self metadata.
   // Hold back provider secrets until the live control socket is reachable and
   // Mothership can push the full runtime environment over configure.
   // `clear()` on a view-backed String leaves the old capacity in place, which
   // can revive the prior length on a later copy. Hard-reset the secret field
   // before serializing first-boot state.
   effectiveRuntimeEnvironment.providerCredentialMaterial.reset();
   effectiveRuntimeEnvironment.aws.bootstrapCredentialRefreshCommand.reset();
   effectiveRuntimeEnvironment.aws.bootstrapCredentialRefreshFailureHint.reset();
   effectiveRuntimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand.reset();
   effectiveRuntimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint.reset();
   effectiveRuntimeEnvironment.azure.bootstrapAccessTokenRefreshCommand.reset();
   effectiveRuntimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint.reset();
   prodigyApplyInternalRuntimeEnvironmentDefaults(effectiveRuntimeEnvironment);
   prodigyOwnRuntimeEnvironmentConfig(effectiveRuntimeEnvironment, bootState.runtimeEnvironment);
   bootState.initialTopology = bootTopology;
   renderProdigyPersistentBootStateJSON(bootState, plan.bootJSON);
   renderProdigyPersistentLocalBrainStateJSON(localState, plan.transportTLSJSON);

   prodigyBuildInstallRootPaths(request.remoteProdigyPath, plan.installPaths);

   String remoteRootParent = {};
   prodigyDirname(request.remoteProdigyPath, remoteRootParent);

   plan.remoteUnitTempPath.assign(remoteRootParent);
   if (plan.remoteUnitTempPath.size() > 0 && plan.remoteUnitTempPath[plan.remoteUnitTempPath.size() - 1] != '/')
   {
      plan.remoteUnitTempPath.append('/');
   }
   plan.remoteUnitTempPath.append("prodigy.service.tmp"_ctv);
   plan.remoteStagePayloadPath.assign("/tmp/prodigy.remote-bootstrap.payload.tar"_ctv);
   plan.remoteBootJSONPath.assign("/var/lib/prodigy/boot.json"_ctv);
   plan.remoteTransportTLSJSONPath.assign("/var/lib/prodigy/transport.tls.json"_ctv);

   plan.installPaths.bundleTempPath.assign(remoteRootParent);
   if (plan.installPaths.bundleTempPath.size() > 0 && plan.installPaths.bundleTempPath[plan.installPaths.bundleTempPath.size() - 1] != '/')
   {
      plan.installPaths.bundleTempPath.append('/');
   }
   plan.installPaths.bundleTempPath.append("prodigy.bundle.tar.zst"_ctv);
   plan.installPaths.bundleTempPath.append(".tmp"_ctv);

   if (prodigyBootstrapSSHKeyPackageConfigured(request.bootstrapSshKeyPackage))
   {
      plan.remoteBootstrapSSHPrivateKeyPath.assign(request.bootstrapSshPrivateKeyPath);
      plan.remoteBootstrapSSHPublicKeyPath.snprintf<"{}.pub"_ctv>(request.bootstrapSshPrivateKeyPath);
      prodigyDirname(plan.remoteBootstrapSSHPrivateKeyPath, plan.bootstrapSSHDirectory);
      if (plan.bootstrapSSHDirectory.size() == 0)
      {
         if (failure) failure->assign("bootstrapSshPrivateKeyPath must include a directory"_ctv);
         return false;
      }
   }

   prodigyDirname(request.controlSocketPath, plan.controlSocketDirectory);
   renderProdigySystemdUnit(plan.installPaths.binaryPath, plan.installPaths.libraryDirectory, plan.controlSocketDirectory, plan.systemdUnit);

   plan.mkdirCommand.assign("mkdir -p "_ctv);
   prodigyAppendShellSingleQuoted(plan.mkdirCommand, remoteRootParent);
   plan.mkdirCommand.append(" /var/lib/prodigy"_ctv);
   if (plan.controlSocketDirectory.size() > 0)
   {
      plan.mkdirCommand.append(" "_ctv);
      prodigyAppendShellSingleQuoted(plan.mkdirCommand, plan.controlSocketDirectory);
   }
   if (plan.bootstrapSSHDirectory.size() > 0)
   {
      plan.mkdirCommand.append(" "_ctv);
      prodigyAppendShellSingleQuoted(plan.mkdirCommand, plan.bootstrapSSHDirectory);
      plan.mkdirCommand.append(" && chmod 700 "_ctv);
      prodigyAppendShellSingleQuoted(plan.mkdirCommand, plan.bootstrapSSHDirectory);
   }
   plan.mkdirCommand.append(
      " || { rc=$?; (id || true) >&2; (pwd || true) >&2; (ls -ld / /root /var/lib /run || true) >&2; exit $rc; }"_ctv);

   String tempBundlePath = {};
   prodigyResolveInstalledBundlePathForRoot(plan.installPaths.installRootTemp, tempBundlePath);
   String tempBundleSHA256Path = {};
   prodigyResolveBundleSHA256Path(tempBundlePath, tempBundleSHA256Path);

   plan.installCommand.assign("set -eu; systemctl stop prodigy || true; if ! command -v zstd >/dev/null 2>&1; then if command -v apt-get >/dev/null 2>&1; then export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y zstd; else echo 'missing zstd decompressor on remote host' >&2; exit 1; fi; fi; "_ctv);
   plan.installCommand.append(plan.mkdirCommand);
   plan.installCommand.append("; tar --no-same-owner --same-permissions -xf "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.remoteStagePayloadPath);
   plan.installCommand.append(" -C /; rm -f "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.remoteStagePayloadPath);
   plan.installCommand.append("; rm -rf "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.installPaths.installRootTemp);
   plan.installCommand.append(" "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.installPaths.installRootPrevious);
   plan.installCommand.append("; mkdir -p "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.installPaths.installRootTemp);
   plan.installCommand.append("; tar --zstd -xf "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.installPaths.bundleTempPath);
   plan.installCommand.append(" -C "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.installPaths.installRootTemp);
   plan.installCommand.append("; install -m 0644 "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.installPaths.bundleTempPath);
   plan.installCommand.append(" "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, tempBundlePath);
   plan.installCommand.append("; install -m 0644 "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.installPaths.bundleSHA256TempPath);
   plan.installCommand.append(" "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, tempBundleSHA256Path);
   plan.installCommand.append("; mv "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.remoteUnitTempPath);
   plan.installCommand.append(" "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.remoteUnitPath);
   plan.installCommand.append("; if [ -e "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.installPaths.installRoot);
   plan.installCommand.append(" ]; then mv "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.installPaths.installRoot);
   plan.installCommand.append(" "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.installPaths.installRootPrevious);
   plan.installCommand.append("; fi; mv "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.installPaths.installRootTemp);
   plan.installCommand.append(" "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.installPaths.installRoot);
   plan.installCommand.append("; "_ctv);
   plan.installCommand.append("LD_LIBRARY_PATH="_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.installPaths.libraryDirectory);
   plan.installCommand.append(" "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.installPaths.binaryPath);
   plan.installCommand.append(" --persist-only --reset-brain-snapshot --boot-json-path="_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.remoteBootJSONPath);
   plan.installCommand.append(" --transport-tls-json-path="_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.remoteTransportTLSJSONPath);
   plan.installCommand.append(" && rm -f "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.remoteBootJSONPath);
   plan.installCommand.append(" "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.remoteTransportTLSJSONPath);
   plan.installCommand.append(" && if command -v ufw >/dev/null 2>&1 && ufw status | grep -F 'Status: active' >/dev/null 2>&1; then ufw allow 312/tcp >/dev/null 2>&1 || true; ufw allow 313/tcp >/dev/null 2>&1 || true; fi && systemctl daemon-reload && systemctl enable prodigy && systemctl restart prodigy"_ctv);
   if (prodigyRemoteBootstrapShouldAwaitControlSocket(clusterMachine, bootState))
   {
      plan.installCommand.append(" && "_ctv);
      prodigyAppendRemoteControlSocketWaitCommand(plan.installCommand, request.controlSocketPath);
      plan.installCommand.append(" || { "_ctv);
      prodigyAppendRemoteBootstrapSocketFailureDiagnostics(plan.installCommand);
      plan.installCommand.append("; exit 1; }"_ctv);
   }
   plan.installCommand.append(" && rm -rf "_ctv);
   prodigyAppendShellSingleQuoted(plan.installCommand, plan.installPaths.installRootPrevious);

   plan.stopCommand.assign("systemctl stop prodigy || true"_ctv);
   return true;
}

class ProdigyPreparedRemoteBootstrapPlan
{
public:

   ClusterMachine clusterMachine = {};
   ProdigyRemoteBootstrapPlan plan = {};
   String bundleSHA256 = {};
   String bundleSHA256Content = {};
   uint64_t bundleBytes = 0;
   String localStagePayloadDirectoryPath = {};
   String localStagePayloadPath = {};
   uint64_t stagePayloadBytes = 0;
};

class ProdigyRemoteBootstrapBundleApprovalCache
{
public:

   String localBundlePath = {};
   String bundleSHA256 = {};
   String bundleSHA256Content = {};
   uint64_t bundleBytes = 0;
};

static inline bool prodigyEnsureLocalDirectoryPath(const String& path, mode_t permissions, String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   if (path.size() == 0 || path.equal("."_ctv))
   {
      return true;
   }

   String pathText = {};
   pathText.assign(path);
   std::error_code error = {};
   std::filesystem::create_directories(std::filesystem::path(pathText.c_str()), error);
   if (error)
   {
      if (failure)
      {
         String errorText = {};
         errorText.assign(error.message().c_str());
         failure->snprintf<"failed to create local directory {} error={}"_ctv>(path, errorText);
      }
      return false;
   }

   if (::chmod(pathText.c_str(), permissions) != 0)
   {
      if (failure)
      {
         failure->snprintf<"failed to chmod local directory {} errno={itoa}"_ctv>(path, uint64_t(errno));
      }
      return false;
   }

   return true;
}

static inline bool prodigyWriteLocalFile(const String& path, const uint8_t *bytes, uint64_t size, mode_t permissions, String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   String parent = {};
   prodigyDirname(path, parent);
   if (prodigyEnsureLocalDirectoryPath(parent, 0755, failure) == false)
   {
      return false;
   }

   String pathText = {};
   pathText.assign(path);
   int fd = ::open(pathText.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, permissions);
   if (fd < 0)
   {
      if (failure)
      {
         failure->snprintf<"failed to open local file {} errno={itoa}"_ctv>(path, uint64_t(errno));
      }
      return false;
   }

   uint64_t offset = 0;
   while (offset < size)
   {
      ssize_t result = ::write(fd, bytes + offset, size_t(size - offset));
      if (result <= 0)
      {
         if (failure)
         {
            failure->snprintf<"failed to write local file {} errno={itoa}"_ctv>(path, uint64_t(errno));
         }
         ::close(fd);
         return false;
      }

      offset += uint64_t(result);
   }

   if (::fchmod(fd, permissions) != 0)
   {
      if (failure)
      {
         failure->snprintf<"failed to chmod local file {} errno={itoa}"_ctv>(path, uint64_t(errno));
      }
      ::close(fd);
      return false;
   }

   if (::close(fd) != 0)
   {
      if (failure)
      {
         failure->snprintf<"failed to close local file {} errno={itoa}"_ctv>(path, uint64_t(errno));
      }
      return false;
   }

   return true;
}

static inline bool prodigyWriteLocalFile(const String& path, const String& content, mode_t permissions, String *failure = nullptr)
{
   return prodigyWriteLocalFile(path, content.data(), content.size(), permissions, failure);
}

static inline bool prodigyBuildRemoteBootstrapStagePath(const String& stagingRoot, const String& remoteAbsolutePath, String& stagedPath, String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   stagedPath.clear();
   if (remoteAbsolutePath.size() == 0 || remoteAbsolutePath[0] != '/')
   {
      if (failure)
      {
         failure->snprintf<"remote bootstrap stage path must be absolute: {}"_ctv>(remoteAbsolutePath);
      }
      return false;
   }

   stagedPath.assign(stagingRoot);
   if (stagedPath.size() > 0 && stagedPath[stagedPath.size() - 1] != '/')
   {
      stagedPath.append('/');
   }
   stagedPath.append(remoteAbsolutePath.substr(1, remoteAbsolutePath.size() - 1, Copy::yes));
   return true;
}

static inline bool prodigyStageRemoteBootstrapLinkedFile(const String& stagingRoot, const String& remoteAbsolutePath, const String& localSourcePath, String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   String stagedPath = {};
   if (prodigyBuildRemoteBootstrapStagePath(stagingRoot, remoteAbsolutePath, stagedPath, failure) == false)
   {
      return false;
   }

   String parent = {};
   prodigyDirname(stagedPath, parent);
   if (prodigyEnsureLocalDirectoryPath(parent, 0755, failure) == false)
   {
      return false;
   }

   String stagedPathText = {};
   stagedPathText.assign(stagedPath);
   (void)::unlink(stagedPathText.c_str());

   String localSourcePathText = {};
   localSourcePathText.assign(localSourcePath);
   if (::symlink(localSourcePathText.c_str(), stagedPathText.c_str()) != 0)
   {
      if (failure)
      {
         failure->snprintf<"failed to stage remote bootstrap file local={} remote={} errno={itoa}"_ctv>(
            localSourcePath,
            remoteAbsolutePath,
            uint64_t(errno));
      }
      return false;
   }

   return true;
}

static inline void prodigyCleanupPreparedRemoteBootstrapPayload(ProdigyPreparedRemoteBootstrapPlan& prepared)
{
   if (prepared.localStagePayloadDirectoryPath.size() > 0)
   {
      std::error_code error = {};
      std::filesystem::remove_all(std::filesystem::path(prepared.localStagePayloadDirectoryPath.c_str()), error);
   }

   prepared.localStagePayloadDirectoryPath.clear();
   prepared.localStagePayloadPath.clear();
   prepared.stagePayloadBytes = 0;
}

static inline bool prodigyBuildPreparedRemoteBootstrapPayload(ProdigyPreparedRemoteBootstrapPlan& prepared, String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   prodigyCleanupPreparedRemoteBootstrapPayload(prepared);

   char payloadScratch[] = "/tmp/prodigy-remote-bootstrap-XXXXXX";
   char *payloadDirectory = ::mkdtemp(payloadScratch);
   if (payloadDirectory == nullptr)
   {
      if (failure)
      {
         failure->snprintf<"failed to create local remote-bootstrap staging directory errno={itoa}"_ctv>(uint64_t(errno));
      }
      return false;
   }

   prepared.localStagePayloadDirectoryPath.assign(payloadDirectory);

   auto failBuild = [&] () -> bool {

      prodigyCleanupPreparedRemoteBootstrapPayload(prepared);
      return false;
   };

   String stagingRoot = {};
   stagingRoot.snprintf<"{}/root"_ctv>(prepared.localStagePayloadDirectoryPath);
   if (prodigyEnsureLocalDirectoryPath(stagingRoot, 0755, failure) == false)
   {
      return failBuild();
   }

   if (prepared.plan.bootstrapSSHDirectory.size() > 0)
   {
      String stagedBootstrapSSHDirectory = {};
      if (prodigyBuildRemoteBootstrapStagePath(stagingRoot, prepared.plan.bootstrapSSHDirectory, stagedBootstrapSSHDirectory, failure) == false)
      {
         return failBuild();
      }
      if (prodigyEnsureLocalDirectoryPath(stagedBootstrapSSHDirectory, 0700, failure) == false)
      {
         return failBuild();
      }
   }

   if (prodigyBootstrapSSHKeyPackageConfigured(prepared.plan.bootstrapSshKeyPackage))
   {
      String stagedPath = {};
      if (prodigyBuildRemoteBootstrapStagePath(stagingRoot, prepared.plan.remoteBootstrapSSHPrivateKeyPath, stagedPath, failure) == false
         || prodigyWriteLocalFile(stagedPath, prepared.plan.bootstrapSshKeyPackage.privateKeyOpenSSH, 0600, failure) == false)
      {
         return failBuild();
      }

      if (prodigyBuildRemoteBootstrapStagePath(stagingRoot, prepared.plan.remoteBootstrapSSHPublicKeyPath, stagedPath, failure) == false
         || prodigyWriteLocalFile(stagedPath, prepared.plan.bootstrapSshKeyPackage.publicKeyOpenSSH, 0644, failure) == false)
      {
         return failBuild();
      }
   }

   if (prodigyStageRemoteBootstrapLinkedFile(stagingRoot, prepared.plan.installPaths.bundleTempPath, prepared.plan.localBundlePath, failure) == false)
   {
      return failBuild();
   }

   String stagedPath = {};
   if (prodigyBuildRemoteBootstrapStagePath(stagingRoot, prepared.plan.installPaths.bundleSHA256TempPath, stagedPath, failure) == false
      || prodigyWriteLocalFile(stagedPath, prepared.bundleSHA256Content, 0644, failure) == false)
   {
      return failBuild();
   }

   if (prodigyBuildRemoteBootstrapStagePath(stagingRoot, prepared.plan.remoteBootJSONPath, stagedPath, failure) == false
      || prodigyWriteLocalFile(stagedPath, prepared.plan.bootJSON, 0600, failure) == false)
   {
      return failBuild();
   }

   if (prodigyBuildRemoteBootstrapStagePath(stagingRoot, prepared.plan.remoteTransportTLSJSONPath, stagedPath, failure) == false
      || prodigyWriteLocalFile(stagedPath, prepared.plan.transportTLSJSON, 0600, failure) == false)
   {
      return failBuild();
   }

   if (prodigyBuildRemoteBootstrapStagePath(stagingRoot, prepared.plan.remoteUnitTempPath, stagedPath, failure) == false
      || prodigyWriteLocalFile(stagedPath, prepared.plan.systemdUnit, 0644, failure) == false)
   {
      return failBuild();
   }

   prepared.localStagePayloadPath.snprintf<"{}/remote-bootstrap-payload.tar"_ctv>(prepared.localStagePayloadDirectoryPath);

   String archiveCommand = {};
   archiveCommand.assign("tar --dereference -cf "_ctv);
   prodigyAppendShellSingleQuoted(archiveCommand, prepared.localStagePayloadPath);
   archiveCommand.append(" -C "_ctv);
   prodigyAppendShellSingleQuoted(archiveCommand, stagingRoot);
   archiveCommand.append(" ."_ctv);
   if (prodigyRunLocalShellCommand(archiveCommand, failure) == false)
   {
      return failBuild();
   }

   std::error_code cleanupError = {};
   std::filesystem::remove_all(std::filesystem::path(stagingRoot.c_str()), cleanupError);

   prepared.stagePayloadBytes = prodigyMeasureLocalFileSize(prepared.localStagePayloadPath);
   if (prepared.stagePayloadBytes == 0)
   {
      if (failure)
      {
         failure->snprintf<"remote bootstrap payload archive is empty: {}"_ctv>(prepared.localStagePayloadPath);
      }
      return failBuild();
   }

   return true;
}

static inline bool prodigyPrepareRemoteBootstrapPlan(
   const ClusterMachine& clusterMachine,
   const ProdigyRemoteBootstrapPlan& plan,
   ProdigyPreparedRemoteBootstrapPlan& prepared,
   ProdigyRemoteBootstrapBundleApprovalCache *bundleApprovalCache,
   String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   prepared = {};
   prepared.clusterMachine = clusterMachine;
   prepared.plan = plan;
   if (bundleApprovalCache != nullptr
      && bundleApprovalCache->localBundlePath.size() > 0
      && bundleApprovalCache->localBundlePath.equals(plan.localBundlePath)
      && bundleApprovalCache->bundleSHA256.size() > 0)
   {
      prepared.bundleBytes = bundleApprovalCache->bundleBytes;
      prepared.bundleSHA256 = bundleApprovalCache->bundleSHA256;
      prepared.bundleSHA256Content = bundleApprovalCache->bundleSHA256Content;
      return prodigyBuildPreparedRemoteBootstrapPayload(prepared, failure);
   }

   prepared.bundleBytes = prodigyMeasureLocalFileSize(plan.localBundlePath);
   if (prodigyApproveBundleArtifact(plan.localBundlePath, prepared.bundleSHA256, failure) == false)
   {
      return false;
   }

   prepared.bundleSHA256Content.assign(prepared.bundleSHA256);
   prepared.bundleSHA256Content.append('\n');
   if (bundleApprovalCache != nullptr)
   {
      bundleApprovalCache->localBundlePath = plan.localBundlePath;
      bundleApprovalCache->bundleBytes = prepared.bundleBytes;
      bundleApprovalCache->bundleSHA256 = prepared.bundleSHA256;
      bundleApprovalCache->bundleSHA256Content = prepared.bundleSHA256Content;
   }
   return prodigyBuildPreparedRemoteBootstrapPayload(prepared, failure);
}

static inline bool prodigyPrepareRemoteBootstrapPlan(const ClusterMachine& clusterMachine, const ProdigyRemoteBootstrapPlan& plan, ProdigyPreparedRemoteBootstrapPlan& prepared, String *failure = nullptr)
{
   return prodigyPrepareRemoteBootstrapPlan(clusterMachine, plan, prepared, nullptr, failure);
}

class ProdigyRemoteBootstrapCoordinator : public RingInterface, public CoroutineStack
{
public:

   static void resumeCoordinatorOnce(ProdigyRemoteBootstrapCoordinator *coordinator)
   {
      if (coordinator == nullptr || coordinator->hasSuspendedCoroutines() == false)
      {
         return;
      }

      coordinator->runNextSuspended();
   }

   class Task final : public SSHClient, public Reconnector
   {
   public:

      using SSHClient::executeCommand;
      using SSHClient::nextSuspendIndex;
      using SSHClient::suspendAtIndex;
      using SSHClient::uploadFile;
      using TCPSocket::setDatacenterCongestion;
      using TCPSocket::setIPVersion;
      using IPSocket::setDaddr;
      using Reconnector::attemptConnect;
      using Reconnector::attemptForMs;
      using Reconnector::connectAttemptFailed;
      using Reconnector::connectAttemptSucceded;
      using Reconnector::connectTimeoutMs;
      using Reconnector::nDefaultAttemptsBudget;
      using Reconnector::shouldReconnect;

      enum class Phase : uint8_t
      {
         connecting,
         authenticating,
         running,
         done
      };

      ProdigyRemoteBootstrapCoordinator *coordinator = nullptr;
      ProdigyPreparedRemoteBootstrapPlan prepared = {};
      uint32_t index = 0;
      Phase phase = Phase::connecting;
      bool done = false;
      bool success = false;
      bool socketInstalled = false;
      bool closeCounted = false;
      String failure = {};
      String activeStep = {};

      void reset(void) override
      {
         SSHClient::reset();
         Reconnector::reset();
         phase = Phase::connecting;
         done = false;
         success = false;
         socketInstalled = false;
         closeCounted = false;
         failure.clear();
         activeStep.clear();
      }

      void complete(bool ok, const String& finalFailure, bool queueCloseIfNeeded)
      {
         if (done)
         {
            return;
         }

         done = true;
         success = ok;
         phase = Phase::done;
         failure = finalFailure;
         prodigyCleanupPreparedRemoteBootstrapPayload(prepared);
         if (coordinator != nullptr)
         {
            coordinator->pendingTasks = (coordinator->pendingTasks > 0 ? coordinator->pendingTasks - 1 : 0);
         }

         if (socketInstalled && closeCounted == false && queueCloseIfNeeded && Ring::socketIsClosing(this) == false)
         {
            Ring::queueClose(this);
         }

         if (coordinator != nullptr)
         {
            coordinator->maybeStopRingLoop();
            resumeCoordinatorOnce(coordinator);
         }
      }

      void recordConnectFailure(const String& connectFailure, bool queueCloseIfNeeded)
      {
         prodigyLogRemoteBootstrapStep("failed", "connect", prepared.plan, &connectFailure);
         String finalFailure = {};
         finalFailure.snprintf<"failed to connect over ssh: {}"_ctv>(connectFailure);
         complete(false, finalFailure, queueCloseIfNeeded);
      }

      bool retryConnectFailure(const String& connectFailure)
      {
         if (connectAttemptFailed())
         {
            recordConnectFailure(connectFailure, true);
            return false;
         }

         phase = Phase::connecting;
         activeStep.assign("connect"_ctv);
         if (socketInstalled && Ring::socketIsClosing(this) == false)
         {
            Ring::queueClose(this);
         }
         return true;
      }

      void recordStepFailure(const char *step)
      {
         String stepFailure = {};
         stepFailure.assign(lastFailure);
         prodigyLogRemoteBootstrapStep("failed", step, prepared.plan, &stepFailure);
         String finalFailure = {};
         finalFailure.assign("remote bootstrap "_ctv);
         finalFailure.append(step);
         finalFailure.append(" failed: "_ctv);
         finalFailure.append(stepFailure);
         complete(false, finalFailure, true);
      }

      void start(void)
      {
         activeStep.assign("connect"_ctv);
         prodigyLogRemoteBootstrapStep("start", "connect", prepared.plan, nullptr);

         IPAddress sshAddress = {};
         if (ClusterMachine::parseIPAddressLiteral(prepared.plan.ssh.address, sshAddress) == false)
         {
            String connectFailure = {};
            connectFailure.snprintf<"invalid ssh address {}"_ctv>(prepared.plan.ssh.address);
            recordConnectFailure(connectFailure, false);
            return;
         }

         setIPVersion(sshAddress.is6 ? AF_INET6 : AF_INET);
         setDatacenterCongestion();
         setDaddr(sshAddress, prepared.plan.ssh.port);
         RingDispatcher::installMultiplexee(this, coordinator);
         socketInstalled = true;
         closeCounted = false;
         if (coordinator != nullptr)
         {
            coordinator->openSockets += 1;
         }

         connectTimeoutMs = prodigyRemoteBootstrapSSHRetrySleepMs;
         nDefaultAttemptsBudget = 1;
         attemptForMs(int64_t(prepared.plan.connectRetryBudgetMs));
         String detail = {};
         detail.snprintf<"fd={itoa} fslot={itoa} fixed={itoa} timeoutMs={itoa} retryBudgetMs={itoa}"_ctv>(
            int64_t(fd),
            int64_t(fslot),
            int64_t(isFixedFile),
            int64_t(connectTimeoutMs),
            int64_t(prepared.plan.connectRetryBudgetMs));
         prodigyLogRemoteBootstrapStep("queue", "connect", prepared.plan, &detail);
         attemptConnect();
      }

      void runCommandStep(const char *step, const String& command, int timeoutMs = 120'000)
      {
         activeStep.assign(step);
         prodigyLogRemoteBootstrapStep("start", step, prepared.plan, nullptr);
         SSHCommandResult commandResult = {};
         uint32_t suspendIndex = nextSuspendIndex();
         executeCommand(command, commandResult, timeoutMs);
         if (suspendIndex < nextSuspendIndex())
         {
            co_await suspendAtIndex(suspendIndex);
         }

         if (failed)
         {
            recordStepFailure(step);
            co_return;
         }

         prodigyLogRemoteBootstrapStep("ok", step, prepared.plan, nullptr);
      }

      void uploadFileStep(const char *step, const String& localPath, const String& remotePath, long permissions)
      {
         activeStep.assign(step);
         String detail = {};
         detail.snprintf<"local={} remote={} bytes={itoa} mode={itoa}"_ctv>(
            localPath,
            remotePath,
            prodigyMeasureLocalFileSize(localPath),
            uint64_t(permissions));
         prodigyLogRemoteBootstrapStep("start", step, prepared.plan, &detail);
         uint32_t suspendIndex = nextSuspendIndex();
         uploadFile(localPath, remotePath, permissions);
         if (suspendIndex < nextSuspendIndex())
         {
            co_await suspendAtIndex(suspendIndex);
         }

         if (failed)
         {
            recordStepFailure(step);
            co_return;
         }

         prodigyLogRemoteBootstrapStep("ok", step, prepared.plan, &detail);
      }

      void runPlan(void)
      {
         phase = Phase::authenticating;
         activeStep.assign("connect"_ctv);
         configureExpectedHostKey(prepared.plan.ssh.address, prepared.plan.ssh.port, prepared.plan.ssh.hostPublicKeyOpenSSH);
         uint32_t suspendIndex = nextSuspendIndex();
         if (prodigyBootstrapSSHKeyPackageConfigured(prepared.plan.bootstrapSshKeyPackage))
         {
            authenticate(prepared.plan.ssh.user, prepared.plan.bootstrapSshKeyPackage);
         }
         else
         {
            authenticate(prepared.plan.ssh.user, prepared.plan.ssh.privateKeyPath);
         }
         if (suspendIndex < nextSuspendIndex())
         {
            co_await suspendAtIndex(suspendIndex);
         }

         if (failed)
         {
            if (retryConnectFailure(lastFailure))
            {
               co_return;
            }
            co_return;
         }

         connectAttemptSucceded();
         prodigyLogRemoteBootstrapStep("ok", "connect", prepared.plan, nullptr);
         String bundleDetail = {};
         bundleDetail.snprintf<"localBundle={} bytes={itoa} sha256={}"_ctv>(prepared.plan.localBundlePath, prepared.bundleBytes, prepared.bundleSHA256);
         prodigyLogRemoteBootstrapStep("ok", "resolve-bundle", prepared.plan, &bundleDetail);
         phase = Phase::running;

         suspendIndex = nextSuspendIndex();
         uploadFileStep("upload-stage-payload", prepared.localStagePayloadPath, prepared.plan.remoteStagePayloadPath, 0600);
         if (suspendIndex < nextSuspendIndex())
         {
            co_await suspendAtIndex(suspendIndex);
         }
         if (done) co_return;

         suspendIndex = nextSuspendIndex();
         runCommandStep("install", prepared.plan.installCommand, 600'000);
         if (suspendIndex < nextSuspendIndex())
         {
            co_await suspendAtIndex(suspendIndex);
         }
         if (done) co_return;

         prodigyLogRemoteBootstrapStep("ok", "complete", prepared.plan, nullptr);
         complete(true, String(), true);
      }
   };

   Vector<Task *> tasks = {};
   uint32_t pendingTasks = 0;
   uint32_t openSockets = 0;
   bool stopRingLoopOnCompletion = false;

   ~ProdigyRemoteBootstrapCoordinator()
   {
      for (Task *task : tasks)
      {
         if (task == nullptr)
         {
            continue;
         }

         if (RingDispatcher::dispatcher != nullptr)
         {
            RingDispatcher::eraseMultiplexee(task);
         }

         delete task;
      }

      tasks.clear();
   }

   void maybeStopRingLoop(void)
   {
      if (stopRingLoopOnCompletion && pendingTasks == 0 && openSockets == 0)
      {
         Ring::exit = true;
      }
   }

   void execute(const Vector<ProdigyPreparedRemoteBootstrapPlan>& preparedPlans)
   {
      for (uint32_t index = 0; index < preparedPlans.size(); ++index)
      {
         startPreparedPlan(preparedPlans[index]);
      }

      awaitCompletion();
   }

   void startPreparedPlan(const ProdigyPreparedRemoteBootstrapPlan& preparedPlan)
   {
      Task *task = new Task();
      task->coordinator = this;
      task->prepared = preparedPlan;
      task->index = uint32_t(tasks.size());
      tasks.push_back(task);
      pendingTasks += 1;
      task->start();
   }

   void awaitCompletion(void)
   {
      while (pendingTasks > 0 || openSockets > 0)
      {
         co_await suspend();
      }
   }

   template <typename RollbackFn>
   bool finalize(Vector<ClusterMachine> *bootstrappedMachines, RollbackFn&& rollbackFn, String& failure)
   {
      failure.clear();
      if (bootstrappedMachines != nullptr)
      {
         bootstrappedMachines->clear();
      }

      bool failed = false;
      for (Task *task : tasks)
      {
         if (task == nullptr)
         {
            continue;
         }

         if (task->success)
         {
            if (bootstrappedMachines != nullptr)
            {
               bootstrappedMachines->push_back(task->prepared.clusterMachine);
            }

            continue;
         }

         if (failed == false)
         {
            failure.assign(task->failure);
            failed = true;
         }
      }

      if (failed == false)
      {
         return true;
      }

      if (bootstrappedMachines != nullptr)
      {
         for (const ClusterMachine& clusterMachine : *bootstrappedMachines)
         {
            rollbackFn(clusterMachine);
         }
      }

      return false;
   }

   void connectHandler(void *socket, int result) override
   {
      Task *task = static_cast<Task *>(socket);
      if (task == nullptr || task->done)
      {
         return;
      }

      String detail = {};
      detail.snprintf<"result={itoa} fd={itoa} fslot={itoa} fixed={itoa} phase={itoa}"_ctv>(
         int64_t(result),
         int64_t(task->fd),
         int64_t(task->fslot),
         int64_t(task->isFixedFile),
         int64_t(task->phase));
      prodigyLogRemoteBootstrapStep("cqe", "connect", task->prepared.plan, &detail);

      if (result == 0)
      {
         task->setConnected();
         task->runPlan();
         return;
      }

      String connectFailure = {};
      connectFailure.snprintf<"ssh tcp connect failed result={}"_ctv>(int64_t(result));
      if (task->connectAttemptFailed())
      {
         task->recordConnectFailure(connectFailure, true);
         return;
      }

      if (Ring::socketIsClosing(task) == false)
      {
         Ring::queueClose(task);
      }
   }

   void pollHandler(void *socket, int result) override
   {
      Task *task = static_cast<Task *>(socket);
      if (task == nullptr || task->done)
      {
         return;
      }

      String detail = {};
      detail.snprintf<"result={itoa} phase={itoa} activeStep={}"_ctv>(
         int64_t(result),
         int64_t(task->phase),
         task->activeStep);
      prodigyLogRemoteBootstrapStep("cqe", "poll", task->prepared.plan, &detail);

      if (result < 0)
      {
         task->failed = true;
         task->lastFailure.snprintf<"ssh io wait failed result={}"_ctv>(int64_t(result));
      }

      task->co_consume();
   }

   void closeHandler(void *socket) override
   {
      Task *task = static_cast<Task *>(socket);
      if (task == nullptr)
      {
         return;
      }

      String detail = {};
      detail.snprintf<"phase={itoa} activeStep={} reconnectAfterClose={itoa} openSockets={itoa}"_ctv>(
         int64_t(task->phase),
         task->activeStep,
         int64_t(task->reconnectAfterClose),
         int64_t(openSockets));
      prodigyLogRemoteBootstrapStep("cqe", "close", task->prepared.plan, &detail);

      if (task->socketInstalled && task->closeCounted == false)
      {
         task->closeCounted = true;
         task->socketInstalled = false;
         openSockets = (openSockets > 0 ? openSockets - 1 : 0);
      }

      maybeStopRingLoop();

      if (task->done)
      {
         resumeCoordinatorOnce(this);
         return;
      }

      if (task->phase == Task::Phase::connecting && task->shouldReconnect())
      {
         prodigyLogRemoteBootstrapStep("retry", "connect", task->prepared.plan, nullptr);
         task->recreateSocket();
         task->socketInstalled = true;
         task->closeCounted = false;
         openSockets += 1;
         task->attemptConnect();
         return;
      }

      String failure = {};
      if (task->activeStep.size() > 0)
      {
         failure.snprintf<"remote bootstrap transport closed during {}"_ctv>(task->activeStep);
      }
      else
      {
         failure.assign("remote bootstrap transport closed"_ctv);
      }

      task->complete(false, failure, false);
   }
};

static inline bool prodigyExecutePreparedRemoteBootstrapPlans(
   const Vector<ProdigyPreparedRemoteBootstrapPlan>& preparedPlans,
   Vector<ClusterMachine> *bootstrappedMachines,
   String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   if (bootstrappedMachines != nullptr)
   {
      bootstrappedMachines->clear();
   }

   RingDispatcher temporaryDispatcher;
   RingDispatcher *previousDispatcher = RingDispatcher::dispatcher;
   RingDispatcher *activeDispatcher = previousDispatcher;
   bool installedTemporaryDispatcher = false;
   if (activeDispatcher == nullptr)
   {
      activeDispatcher = &temporaryDispatcher;
      RingDispatcher::dispatcher = activeDispatcher;
      installedTemporaryDispatcher = true;
   }

   Ring::interfacer = activeDispatcher;
   Ring::lifecycler = activeDispatcher;

   if (Ring::getRingFD() <= 0)
   {
      Ring::createRing(128, 128, 8192, 2048, -1, -1, 0);
   }

   ProdigyRemoteBootstrapCoordinator coordinator = {};
   coordinator.stopRingLoopOnCompletion = true;
   coordinator.execute(preparedPlans);
   if (coordinator.pendingTasks > 0 || coordinator.openSockets > 0)
   {
      Ring::exit = false;
      Ring::start();
      Ring::exit = false;
   }

   auto rollback = [] (const ClusterMachine&) -> void {
   };
   String localFailure = {};
   bool ok = coordinator.finalize(bootstrappedMachines, rollback, localFailure);

   if (installedTemporaryDispatcher)
   {
      RingDispatcher::dispatcher = previousDispatcher;
      Ring::interfacer = previousDispatcher;
      Ring::lifecycler = previousDispatcher;
   }

   if (ok == false)
   {
      if (failure)
      {
         failure->assign(localFailure);
      }
      return false;
   }

   if (failure)
   {
      failure->clear();
   }
   return true;
}

static inline bool prodigyExecuteRemoteBootstrapPlan(const ProdigyRemoteBootstrapPlan& plan, String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   ProdigyPreparedRemoteBootstrapPlan prepared = {};
   if (prodigyPrepareRemoteBootstrapPlan(ClusterMachine(), plan, prepared, failure) == false)
   {
      return false;
   }

   Vector<ProdigyPreparedRemoteBootstrapPlan> preparedPlans = {};
   preparedPlans.push_back(std::move(prepared));
   return prodigyExecutePreparedRemoteBootstrapPlans(preparedPlans, nullptr, failure);
}
