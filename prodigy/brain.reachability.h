#pragma once

#include <cerrno>
#include <csignal>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/wait.h>

#include <prodigy/remote.bootstrap.h>

static inline void prodigyRenderBrainReachabilityLabel(const ClusterMachine& machine, String& label)
{
   if (machine.ssh.address.size() > 0)
   {
      label.assign(machine.ssh.address);
      return;
   }

   if (machine.addresses.privateAddresses.empty() == false)
   {
      label.assign(machine.addresses.privateAddresses[0].address);
      return;
   }

   if (machine.addresses.publicAddresses.empty() == false)
   {
      label.assign(machine.addresses.publicAddresses[0].address);
      return;
   }

   machine.renderIdentityLabel(label);
}

static inline bool prodigySockaddrToIPAddress(const struct sockaddr *sockaddr, IPAddress& address, String *text = nullptr)
{
   if (sockaddr == nullptr)
   {
      return false;
   }

   char buffer[INET6_ADDRSTRLEN] = {};

   if (sockaddr->sa_family == AF_INET)
   {
      const struct sockaddr_in *in4 = reinterpret_cast<const struct sockaddr_in *>(sockaddr);
      address = {};
      address.v4 = in4->sin_addr.s_addr;
      address.is6 = false;

      if (text)
      {
         if (inet_ntop(AF_INET, &in4->sin_addr, buffer, sizeof(buffer)) == nullptr)
         {
            text->clear();
         }
         else
         {
            text->assign(buffer);
         }
      }

      return true;
   }

   if (sockaddr->sa_family == AF_INET6)
   {
      const struct sockaddr_in6 *in6 = reinterpret_cast<const struct sockaddr_in6 *>(sockaddr);
      const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&in6->sin6_addr);
      static constexpr uint8_t v4MappedPrefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};

      if (memcmp(bytes, v4MappedPrefix, sizeof(v4MappedPrefix)) == 0)
      {
         address = {};
         memcpy(&address.v4, bytes + 12, sizeof(address.v4));
         address.is6 = false;

         if (text)
         {
            if (inet_ntop(AF_INET, &address.v4, buffer, sizeof(buffer)) == nullptr)
            {
               text->clear();
            }
            else
            {
               text->assign(buffer);
            }
         }

         return true;
      }

      address = {};
      memcpy(address.v6, &in6->sin6_addr, sizeof(in6->sin6_addr));
      address.is6 = true;

      if (text)
      {
         if (inet_ntop(AF_INET6, &in6->sin6_addr, buffer, sizeof(buffer)) == nullptr)
         {
            text->clear();
         }
         else
         {
            text->assign(buffer);
         }
      }

      return true;
   }

   return false;
}

static inline void prodigyBuildReachabilityProbeCommand(const String& address, bool is6, String& command)
{
   command.assign("set +e; LC_ALL=C ping "_ctv);
   if (is6)
   {
      command.append("-6 "_ctv);
   }
   else
   {
      command.append("-4 "_ctv);
   }
   command.append("-n -c 1 -W 2 -- "_ctv);
   prodigyAppendShellSingleQuoted(command, address);
   command.append(" 2>&1; rc=$?; printf '\\n__PRODIGY_PING_RC__=%s\\n' \"$rc\"; exit 0"_ctv);
}

static inline bool prodigyTrimmedCommandOutputWithoutMarker(const String& output, String& trimmed)
{
   trimmed.clear();

   String ownedOutput = {};
   ownedOutput.assign(output);
   const char *marker = std::strstr(ownedOutput.c_str(), "__PRODIGY_PING_RC__=");
   uint64_t length = marker ? uint64_t(marker - ownedOutput.c_str()) : ownedOutput.size();

   uint64_t start = 0;
   while (start < length && std::isspace(unsigned(ownedOutput[start])))
   {
      start += 1;
   }

   uint64_t end = length;
   while (end > start && std::isspace(unsigned(ownedOutput[end - 1])))
   {
      end -= 1;
   }

   if (end <= start)
   {
      return false;
   }

   trimmed.assign(ownedOutput.substr(start, end - start, Copy::yes));
   return true;
}

static inline bool prodigyParseReachabilityProbeOutput(const String& output, bool& reachable, uint32_t& latencyMs, String *failure = nullptr)
{
   reachable = false;
   latencyMs = 0;
   if (failure) failure->clear();

   String ownedOutput = {};
   ownedOutput.assign(output);
   const char *marker = std::strstr(ownedOutput.c_str(), "__PRODIGY_PING_RC__=");
   if (marker == nullptr)
   {
      if (failure) failure->assign("reachability probe output missing rc marker"_ctv);
      return false;
   }

   char *tail = nullptr;
   const char *rcText = marker + std::strlen("__PRODIGY_PING_RC__=");
   errno = 0;
   unsigned long rc = std::strtoul(rcText, &tail, 10);
   if (errno != 0 || tail == rcText)
   {
      if (failure) failure->assign("reachability probe rc marker malformed"_ctv);
      return false;
   }

   if (rc != 0)
   {
      String trimmed = {};
      if (failure && prodigyTrimmedCommandOutputWithoutMarker(output, trimmed))
      {
         *failure = trimmed;
      }
      else if (failure)
      {
         failure->snprintf<"ping exited with rc={itoa}"_ctv>(uint32_t(rc));
      }

      reachable = false;
      latencyMs = 0;
      return true;
   }

   const char *timeMarker = std::strstr(ownedOutput.c_str(), "time=");
   if (timeMarker == nullptr)
   {
      if (failure) failure->assign("reachability probe output missing latency"_ctv);
      return false;
   }

   errno = 0;
   double latencyValue = std::strtod(timeMarker + 5, &tail);
   if (errno != 0 || tail == timeMarker + 5)
   {
      if (failure) failure->assign("reachability probe latency malformed"_ctv);
      return false;
   }

   reachable = true;
   latencyMs = latencyValue <= 0.0 ? 0u : uint32_t(std::lround(latencyValue));
   return true;
}

static inline bool prodigyRunBlockingLocalCommandCaptureStdout(const String& command, String& output, String *failure = nullptr)
{
   output.clear();
   if (failure) failure->clear();

   struct sigaction currentSigChld = {};
   if (::sigaction(SIGCHLD, nullptr, &currentSigChld) == 0
      && currentSigChld.sa_handler == SIG_IGN)
   {
      struct sigaction defaultSigChld = {};
      ::sigemptyset(&defaultSigChld.sa_mask);
      defaultSigChld.sa_handler = SIG_DFL;
      defaultSigChld.sa_flags = 0;
      (void)::sigaction(SIGCHLD, &defaultSigChld, nullptr);
   }

   String ownedCommand = {};
   ownedCommand.assign(command);
   FILE *pipe = ::popen(ownedCommand.c_str(), "r");
   if (pipe == nullptr)
   {
      if (failure) failure->assign("failed to launch local command"_ctv);
      return false;
   }

   char buffer[4096];
   while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr)
   {
      output.append(buffer);
   }

   int rc = ::pclose(pipe);
   int savedErrno = errno;
   if (rc < 0)
   {
      if (failure) failure->snprintf<"failed to reap local command: {}"_ctv>(String(strerror(savedErrno)));
      return false;
   }

   if (WIFEXITED(rc))
   {
      if (WEXITSTATUS(rc) == 0)
      {
         return true;
      }

      if (failure) failure->snprintf<"local command exited with status {itoa}"_ctv>(uint32_t(WEXITSTATUS(rc)));
      return false;
   }

   if (WIFSIGNALED(rc))
   {
      if (failure) failure->snprintf<"local command terminated by signal {itoa}"_ctv>(uint32_t(WTERMSIG(rc)));
      return false;
   }

   if (failure) failure->snprintf<"local command ended with unexpected wait status {itoa}"_ctv>(uint32_t(rc));
   return false;
}

static inline bool prodigyProbeReachabilityLocally(const String& targetAddress, BrainReachabilityProbeResult& result, String *failure = nullptr)
{
   result.reachable = false;
   result.latencyMs = 0;
   result.failure.clear();

   IPAddress resolvedAddress = {};
   if (ClusterMachine::parseIPAddressLiteral(targetAddress, resolvedAddress) == false)
   {
      if (failure) failure->assign("target address must be a literal ipv4 or ipv6 address"_ctv);
      return false;
   }

   String command = {};
   prodigyBuildReachabilityProbeCommand(targetAddress, resolvedAddress.is6, command);

   String output = {};
   if (prodigyRunBlockingLocalCommandCaptureStdout(command, output, failure) == false)
   {
      return false;
   }

   if (prodigyParseReachabilityProbeOutput(output, result.reachable, result.latencyMs, &result.failure) == false)
   {
      if (failure) *failure = result.failure;
      return false;
   }

   if (failure) failure->clear();
   return true;
}

static inline bool prodigyProbeReachabilityOverSSH(const ClusterMachine& sourceMachine, const String& targetAddress, BrainReachabilityProbeResult& result, String *failure = nullptr)
{
   result.reachable = false;
   result.latencyMs = 0;
   result.failure.clear();

   String sshAddress = {};
   if (prodigyResolveClusterMachineSSHAddress(sourceMachine, sshAddress) == false)
   {
      if (failure) failure->assign("source brain has no ssh address"_ctv);
      return false;
   }

   if (sourceMachine.ssh.hostPublicKeyOpenSSH.size() == 0)
   {
      if (failure) failure->assign("source brain has no ssh.hostPublicKeyOpenSSH"_ctv);
      return false;
   }

   LIBSSH2_SESSION *session = nullptr;
   int fd = -1;
   if (prodigyConnectBlockingSSHSession(
         sshAddress,
         sourceMachine.ssh.port > 0 ? sourceMachine.ssh.port : 22,
         sourceMachine.ssh.hostPublicKeyOpenSSH,
         sourceMachine.ssh.user,
         sourceMachine.ssh.privateKeyPath,
         session,
         fd,
         failure) == false)
   {
      return false;
   }

   String command = {};
   IPAddress resolvedAddress = {};
   if (ClusterMachine::parseIPAddressLiteral(targetAddress, resolvedAddress) == false)
   {
      if (failure) failure->assign("target address must be a literal ipv4 or ipv6 address"_ctv);
      prodigyCloseBlockingSSHSession(session, fd);
      return false;
   }

   prodigyBuildReachabilityProbeCommand(targetAddress, resolvedAddress.is6, command);

   String output = {};
   bool ok = prodigyRunBlockingSSHCommand(session, fd, command, &output, failure, 8'000);
   prodigyCloseBlockingSSHSession(session, fd);
   if (ok == false)
   {
      return false;
   }

   if (prodigyParseReachabilityProbeOutput(output, result.reachable, result.latencyMs, &result.failure) == false)
   {
      if (failure) *failure = result.failure;
      return false;
   }

   if (failure) failure->clear();
   return true;
}

template <typename ProbeFn>
static inline bool prodigyProbeAddressFromClusterBrains(const Vector<ClusterMachine>& sourceBrains, const String& targetAddress, ProbeFn&& probeFn, Vector<BrainReachabilityProbeResult>& results, String& failure)
{
   results.clear();
   failure.clear();

   bool allReachable = true;

   for (const ClusterMachine& sourceBrain : sourceBrains)
   {
      BrainReachabilityProbeResult result = {};
      prodigyRenderBrainReachabilityLabel(sourceBrain, result.brainLabel);

      String probeFailure = {};
      if (probeFn(sourceBrain, targetAddress, result, probeFailure) == false)
      {
         result.reachable = false;
         result.latencyMs = 0;
         result.failure = probeFailure.size() > 0 ? probeFailure : "reachability probe failed"_ctv;
      }

      if (result.reachable == false)
      {
         allReachable = false;
      }

      results.push_back(std::move(result));
   }

   if (allReachable == false)
   {
      failure.assign("candidate brain address is not reachable from all existing brains"_ctv);
   }

   return allReachable;
}
