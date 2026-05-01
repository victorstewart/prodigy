#pragma once

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <random>
#include <simdjson.h>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>

#include <prodigy/bundle.artifact.h>
#include <prodigy/machine.hardware.types.h>
#include <services/filesystem.h>
#include <services/time.h>

class ProdigyMachineHardwareCollectorOptions
{
public:

   uint32_t cpuBenchmarkWarmupSeconds = 1;
   uint32_t cpuBenchmarkSeconds = 3;
   uint32_t memoryBenchmarkWarmupSeconds = 1;
   uint32_t memoryBenchmarkIterations = 3;
   uint32_t diskBenchmarkSeconds = 2;
   uint32_t diskBenchmarkLimit = 2;
   uint32_t internetBenchmarkTimeoutSeconds = 30;
   bool collectOptionalBenchmarks = true;
};

static inline int64_t prodigyMonotonicNs(void)
{
   struct timespec ts = {};
   clock_gettime(CLOCK_MONOTONIC, &ts);
   return Time::secToNs(ts.tv_sec) + int64_t(ts.tv_nsec);
}

static inline bool prodigyStringStartsWith(const String& text, const char *prefix)
{
   if (prefix == nullptr)
   {
      return false;
   }

   size_t prefixLength = std::strlen(prefix);
   if (text.size() < prefixLength)
   {
      return false;
   }

   return std::memcmp(text.data(), prefix, prefixLength) == 0;
}

static inline bool prodigyStringContains(const String& text, const char *needle)
{
   if (needle == nullptr)
   {
      return false;
   }

   String owned = {};
   owned.assign(text);
   return std::strstr(owned.c_str(), needle) != nullptr;
}

static inline void prodigyPushUniqueString(Vector<String>& values, const String& value)
{
   if (value.size() == 0)
   {
      return;
   }

   for (const String& existing : values)
   {
      if (existing.equals(value))
      {
         return;
      }
   }

   values.push_back(value);
}

static inline bool prodigyParseIPAddressLiteral(const String& text, IPAddress& address)
{
   address = {};
   String owned = {};
   owned.assign(text);
   if (inet_pton(AF_INET, owned.c_str(), address.v6) == 1)
   {
      address.is6 = false;
      return true;
   }

   if (inet_pton(AF_INET6, owned.c_str(), address.v6) == 1)
   {
      address.is6 = true;
      return true;
   }

   address = {};
   return false;
}

static inline void prodigyComputePrefixNetwork(const IPAddress& address, uint8_t cidr, IPPrefix& prefix)
{
   prefix = {};
   prefix.network = address;
   prefix.cidr = cidr;

   if (address.is6 == false)
   {
      uint32_t hostOrder = ntohl(address.v4);
      uint32_t mask = (cidr == 0) ? 0 : (0xFFFFFFFFu << (32 - cidr));
      prefix.network.v4 = htonl(hostOrder & mask);
      return;
   }

   uint32_t bitsRemaining = cidr;
   for (uint32_t i = 0; i < 16; ++i)
   {
      if (bitsRemaining >= 8)
      {
         bitsRemaining -= 8;
         continue;
      }

      if (bitsRemaining == 0)
      {
         prefix.network.v6[i] = 0;
         continue;
      }

      uint8_t mask = uint8_t(0xFFu << (8 - bitsRemaining));
      prefix.network.v6[i] &= mask;
      bitsRemaining = 0;
   }
}

static inline void prodigyTrimString(String& text)
{
   uint64_t start = 0;
   while (start < text.size() && std::isspace(unsigned(text[start])))
   {
      start += 1;
   }

   uint64_t end = text.size();
   while (end > start && std::isspace(unsigned(text[end - 1])))
   {
      end -= 1;
   }

   if (start == 0 && end == text.size())
   {
      return;
   }

   if (end <= start)
   {
      text.clear();
      return;
   }

   text.assign(text.substr(start, end - start, Copy::yes));
}

static inline bool prodigyReadTextFile(const String& path, String& output)
{
   output.clear();
   String ownedPath = {};
   ownedPath.assign(path);
   Filesystem::openReadAtClose(-1, ownedPath, output);
   prodigyTrimString(output);
   return output.size() > 0;
}

static inline void prodigyEraseFileBestEffort(const String& path)
{
   String ownedPath = {};
   ownedPath.assign(path);
   Filesystem::eraseFile(ownedPath);
}

static inline void prodigyEnsureMachineHardwareCommandSigchldWaitable(void)
{
   // Guardian can leave SIGCHLD ignored; popen/pclose need it waitable.
   struct sigaction currentSigChld = {};
   if (::sigaction(SIGCHLD, nullptr, &currentSigChld) != 0)
   {
      return;
   }

   if (currentSigChld.sa_handler != SIG_IGN)
   {
      return;
   }

   struct sigaction defaultSigChld = {};
   ::sigemptyset(&defaultSigChld.sa_mask);
   defaultSigChld.sa_handler = SIG_DFL;
   defaultSigChld.sa_flags = 0;
   (void)::sigaction(SIGCHLD, &defaultSigChld, nullptr);
}

static inline bool prodigyDecodeMachineHardwareCommandStatus(int rawStatus, int savedErrno, int *exitStatus = nullptr, String *failure = nullptr)
{
   if (exitStatus) *exitStatus = -1;
   if (failure) failure->clear();

   if (rawStatus < 0)
   {
      if (failure) failure->snprintf<"failed to reap local command: {}"_ctv>(String(strerror(savedErrno)));
      return false;
   }

   if (WIFEXITED(rawStatus))
   {
      int code = WEXITSTATUS(rawStatus);
      if (exitStatus) *exitStatus = code;
      if (code == 0)
      {
         return true;
      }

      if (failure) failure->snprintf<"local command exited with status {itoa}"_ctv>(uint32_t(code));
      return false;
   }

   if (WIFSIGNALED(rawStatus))
   {
      int signalNumber = WTERMSIG(rawStatus);
      if (exitStatus) *exitStatus = 128 + signalNumber;
      if (failure) failure->snprintf<"local command terminated by signal {itoa}"_ctv>(uint32_t(signalNumber));
      return false;
   }

   if (exitStatus) *exitStatus = rawStatus;
   if (failure) failure->snprintf<"local command ended with unexpected wait status {itoa}"_ctv>(uint32_t(rawStatus));
   return false;
}

static inline bool prodigyRunBlockingLocalCommandCaptureStdout(const String& command, String& output, int *exitStatus = nullptr, String *failure = nullptr)
{
   output.clear();
   if (exitStatus) *exitStatus = -1;
   if (failure) failure->clear();

   prodigyEnsureMachineHardwareCommandSigchldWaitable();

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
   return prodigyDecodeMachineHardwareCommandStatus(rc, savedErrno, exitStatus, failure);
}

static inline void prodigyAppendCommandPrefix(String& command, uint32_t timeoutSeconds);
static inline void prodigyAppendMachineHardwareShellSingleQuoted(String& command, const String& text);

static inline bool prodigyResolveSystemToolPath(const String& toolName, String& toolPath)
{
   toolPath.clear();

   String command = {};
   prodigyAppendCommandPrefix(command, 2);
   String inner = {};
   inner.append("command -v "_ctv);
   inner.append(toolName);
   prodigyAppendMachineHardwareShellSingleQuoted(command, inner);

   String output = {};
   if (prodigyRunBlockingLocalCommandCaptureStdout(command, output) == false)
   {
      return false;
   }

   prodigyTrimString(output);
   if (output.size() == 0)
   {
      return false;
   }

   toolPath.assign(output);
   return true;
}

static inline bool prodigyResolveMachineHardwareToolPath(const String& toolName, String& toolPath)
{
   toolPath.clear();

   String executablePath = {};
   if (prodigyResolveCurrentExecutablePath(executablePath))
   {
      if (prodigyResolveBundledToolPathForExecutable(executablePath, toolName, toolPath))
      {
         return true;
      }
   }

   return prodigyResolveSystemToolPath(toolName, toolPath);
}

static inline bool prodigyResolveMachineHardwareToolCommand(const String& toolName, String& toolCommand)
{
   toolCommand.clear();

   String toolPath = {};
   if (prodigyResolveMachineHardwareToolPath(toolName, toolPath) == false)
   {
      return false;
   }

   prodigyAppendMachineHardwareShellSingleQuoted(toolCommand, toolPath);
   return true;
}

static inline bool prodigyResolveMachineHardwareCommandHomeDirectory(String& homeDirectory)
{
   homeDirectory.clear();

   const char *home = std::getenv("HOME");
   if (home != nullptr && home[0] != '\0')
   {
      homeDirectory.assign(home);
      return true;
   }

   struct passwd *user = ::getpwuid(::geteuid());
   if (user != nullptr && user->pw_dir != nullptr && user->pw_dir[0] != '\0')
   {
      homeDirectory.assign(user->pw_dir);
      return true;
   }

   return false;
}

static inline bool prodigyResolveMachineHardwareCommandConfigHome(String& configHome)
{
   configHome.clear();

   const char *xdgConfigHome = std::getenv("XDG_CONFIG_HOME");
   if (xdgConfigHome != nullptr && xdgConfigHome[0] != '\0')
   {
      configHome.assign(xdgConfigHome);
      return true;
   }

   String homeDirectory = {};
   if (prodigyResolveMachineHardwareCommandHomeDirectory(homeDirectory) == false)
   {
      return false;
   }

   configHome.assign(homeDirectory);
   if (configHome.size() > 0 && configHome[configHome.size() - 1] != '/')
   {
      configHome.append('/');
   }
   configHome.append(".config"_ctv);
   return true;
}

static inline bool prodigyResolveOfficialSpeedtestCommand(String& toolCommand)
{
   toolCommand.clear();

   String toolPath = {};
   if (prodigyResolveMachineHardwareToolPath("speedtest"_ctv, toolPath) == false)
   {
      return false;
   }

   String versionCommand = {};
   prodigyAppendCommandPrefix(versionCommand, 2);

   String inner = {};
   prodigyAppendMachineHardwareShellSingleQuoted(inner, toolPath);
   inner.append(" --version"_ctv);
   prodigyAppendMachineHardwareShellSingleQuoted(versionCommand, inner);

   String versionOutput = {};
   if (prodigyRunBlockingLocalCommandCaptureStdout(versionCommand, versionOutput) == false
      || prodigyStringContains(versionOutput, "Speedtest by Ookla") == false)
   {
      return false;
   }

   prodigyAppendMachineHardwareShellSingleQuoted(toolCommand, toolPath);
   return true;
}

static inline void prodigyRecordMachineToolCapture(
   Vector<MachineToolCapture>& captures,
   const String& tool,
   const String& phase,
   const String& command,
   const String& output,
   bool attempted,
   bool succeeded,
   int exitCode,
   const String& failure = {}
)
{
   MachineToolCapture& capture = captures.emplace_back();
   capture.tool.assign(tool);
   capture.phase.assign(phase);
   capture.command.assign(command);
   capture.output.assign(output);
   capture.failure.assign(failure);
   capture.attempted = attempted;
   capture.succeeded = succeeded;
   capture.exitCode = exitCode;
}

static inline bool prodigyRunRecordedLocalCommand(
   const String& tool,
   const String& phase,
   const String& command,
   Vector<MachineToolCapture>& captures,
   String& output,
   int *exitStatus = nullptr,
   String *failure = nullptr
)
{
   String commandFailure = {};
   bool ok = prodigyRunBlockingLocalCommandCaptureStdout(command, output, exitStatus, &commandFailure);
   if (failure)
   {
      failure->assign(commandFailure);
   }

   prodigyRecordMachineToolCapture(
      captures,
      tool,
      phase,
      command,
      output,
      true,
      ok,
      exitStatus ? *exitStatus : (ok ? 0 : -1),
      commandFailure
   );
   return ok;
}

static inline void prodigyAppendCommandPrefix(String& command, uint32_t timeoutSeconds)
{
   command.assign("env"_ctv);

   String homeDirectory = {};
   if (prodigyResolveMachineHardwareCommandHomeDirectory(homeDirectory))
   {
      command.append(" HOME="_ctv);
      prodigyAppendMachineHardwareShellSingleQuoted(command, homeDirectory);
   }

   String configHome = {};
   if (prodigyResolveMachineHardwareCommandConfigHome(configHome))
   {
      command.append(" XDG_CONFIG_HOME="_ctv);
      prodigyAppendMachineHardwareShellSingleQuoted(command, configHome);
   }

   command.snprintf_add<" timeout --preserve-status -k 1s {itoa}s sh -lc "_ctv>(timeoutSeconds);
}

static inline void prodigyAppendMachineHardwareShellSingleQuoted(String& command, const String& text)
{
   command.append("'"_ctv);
   for (uint64_t i = 0; i < text.size(); ++i)
   {
      if (text[i] == '\'')
      {
         command.append("'\\''"_ctv);
      }
      else
      {
         command.append(text[i]);
      }
   }
   command.append("'"_ctv);
}

static inline bool prodigyReadCPUModelName(String& model)
{
   String cpuinfo = {};
   if (prodigyReadTextFile("/proc/cpuinfo"_ctv, cpuinfo) == false)
   {
      return false;
   }

   String ownedCpuinfo = {};
   ownedCpuinfo.assign(cpuinfo);
   const char *start = std::strstr(ownedCpuinfo.c_str(), "model name");
   if (start == nullptr)
   {
      start = std::strstr(ownedCpuinfo.c_str(), "Hardware");
   }

   if (start == nullptr)
   {
      return false;
   }

   const char *colon = std::strchr(start, ':');
   if (colon == nullptr)
   {
      return false;
   }

   const char *end = std::strchr(colon + 1, '\n');
   if (end == nullptr)
   {
      end = ownedCpuinfo.c_str() + ownedCpuinfo.size();
   }

   model.assign(colon + 1, uint64_t(end - (colon + 1)));
   prodigyTrimString(model);
   return model.size() > 0;
}

static inline bool prodigyReadFirstCpuinfoField(const String& cpuinfo, const char *fieldName, String& value)
{
   value.clear();

   String ownedCpuinfo = {};
   ownedCpuinfo.assign(cpuinfo);
   const char *cursor = ownedCpuinfo.c_str();
   if (cursor == nullptr)
   {
      return false;
   }

   size_t fieldLength = std::strlen(fieldName);
   while (*cursor != '\0')
   {
      const char *lineEnd = std::strchr(cursor, '\n');
      if (lineEnd == nullptr)
      {
         lineEnd = cursor + std::strlen(cursor);
      }

      const char *lineStart = cursor;
      while (lineStart < lineEnd && std::isspace(unsigned(*lineStart)))
      {
         lineStart += 1;
      }

      const char *colon = std::find(lineStart, lineEnd, ':');
      if (colon != lineEnd)
      {
         size_t keyLength = size_t(colon - lineStart);
         while (keyLength > 0 && std::isspace(unsigned(lineStart[keyLength - 1])))
         {
            keyLength -= 1;
         }

         if (keyLength == fieldLength && std::memcmp(lineStart, fieldName, fieldLength) == 0)
         {
            const char *fieldValue = colon + 1;
            while (fieldValue < lineEnd && std::isspace(unsigned(*fieldValue)))
            {
               fieldValue += 1;
            }

            value.assign(fieldValue, uint64_t(lineEnd - fieldValue));
            prodigyTrimString(value);
            return value.size() > 0;
         }
      }

      cursor = (*lineEnd == '\0') ? lineEnd : (lineEnd + 1);
   }

   return false;
}

static inline void prodigyParseCpuinfoFeatureList(const String& featureLine, Vector<String>& features)
{
   uint64_t start = 0;
   while (start < featureLine.size())
   {
      while (start < featureLine.size() && std::isspace(unsigned(featureLine[start])))
      {
         start += 1;
      }

      uint64_t end = start;
      while (end < featureLine.size() && std::isspace(unsigned(featureLine[end])) == 0)
      {
         end += 1;
      }

      if (end > start)
      {
         prodigyPushUniqueString(features, featureLine.substr(start, end - start, Copy::yes));
      }

      start = end + 1;
   }
}

static inline MachineCpuArchitecture prodigyParseCpuArchitecture(const String& machine)
{
   if (machine.equal("x86_64"_ctv) || machine.equal("amd64"_ctv))
   {
      return MachineCpuArchitecture::x86_64;
   }

   if (machine.equal("aarch64"_ctv) || machine.equal("arm64"_ctv))
   {
      return MachineCpuArchitecture::aarch64;
   }

   if (prodigyStringStartsWith(machine, "arm"))
   {
      return MachineCpuArchitecture::arm;
   }

   if (machine.equal("riscv64"_ctv))
   {
      return MachineCpuArchitecture::riscv64;
   }

   return MachineCpuArchitecture::unknown;
}

static inline void prodigyPopulateCpuIdentityFromCpuinfo(const String& machine, const String& cpuinfo, MachineCpuHardwareProfile& cpu)
{
   cpu.architecture = prodigyParseCpuArchitecture(machine);
   cpu.architectureVersion.assign(machine);

   String field = {};
   if (prodigyReadFirstCpuinfoField(cpuinfo, "vendor_id", field))
   {
      cpu.vendor.assign(field);
   }
   else if (prodigyReadFirstCpuinfoField(cpuinfo, "CPU implementer", field))
   {
      cpu.vendor.assign(field);
   }

   if (prodigyReadFirstCpuinfoField(cpuinfo, "CPU architecture", field))
   {
      if (cpu.architecture == MachineCpuArchitecture::aarch64 || cpu.architecture == MachineCpuArchitecture::arm)
      {
         cpu.architectureVersion.assign("armv"_ctv);
         cpu.architectureVersion.append(field);
      }
      else
      {
         cpu.architectureVersion.assign(field);
      }
   }

   if (prodigyReadFirstCpuinfoField(cpuinfo, "flags", field))
   {
      prodigyParseCpuinfoFeatureList(field, cpu.isaFeatures);
   }

   if (prodigyReadFirstCpuinfoField(cpuinfo, "Features", field))
   {
      prodigyParseCpuinfoFeatureList(field, cpu.isaFeatures);
   }
}

static inline void prodigyCollectCpuIdentity(MachineCpuHardwareProfile& cpu)
{
   String cpuinfo = {};
   (void)prodigyReadTextFile("/proc/cpuinfo"_ctv, cpuinfo);

   String machine = {};
   struct utsname uts = {};
   if (uname(&uts) == 0)
   {
      machine.assign(uts.machine);
   }

   prodigyPopulateCpuIdentityFromCpuinfo(machine, cpuinfo, cpu);
}

class ProdigyCpuInventorySnapshot
{
public:

   MachineCpuArchitecture architecture = MachineCpuArchitecture::unknown;
   String architectureVersion;
   String vendor;
   String model;
   Vector<String> isaFeatures;
   uint32_t logicalCores = 0;
   uint32_t physicalCores = 0;
   uint32_t sockets = 0;
   uint32_t numaNodes = 0;
   uint32_t threadsPerCore = 0;
   uint32_t l3CacheMB = 0;
   Vector<uint32_t> onlineCpuIds;
};

static inline bool prodigyParseUnsignedDecimalText(const String& text, uint32_t& value)
{
   value = 0;
   if (text.size() == 0)
   {
      return false;
   }

   String owned = {};
   owned.assign(text);
   char *tail = nullptr;
   errno = 0;
   unsigned long parsed = std::strtoul(owned.c_str(), &tail, 10);
   if (errno != 0 || tail == owned.c_str())
   {
      return false;
   }

   while (tail && *tail != '\0' && std::isspace(unsigned(*tail)))
   {
      tail += 1;
   }

   if (tail == nullptr || *tail != '\0')
   {
      return false;
   }

   value = uint32_t(parsed);
   return true;
}

static inline void prodigyNormalizeLscpuFieldName(String& field)
{
   prodigyTrimString(field);
   if (field.size() > 0 && field[field.size() - 1] == ':')
   {
      field.resize(field.size() - 1);
   }
}

static inline uint32_t prodigyParseLscpuCacheMB(const String& text)
{
   String owned = {};
   owned.assign(text);
   char *tail = nullptr;
   double value = std::strtod(owned.c_str(), &tail);
   if (tail == owned.c_str())
   {
      return 0;
   }

   while (tail && *tail != '\0' && std::isspace(unsigned(*tail)))
   {
      tail += 1;
   }

   if (tail == nullptr)
   {
      return 0;
   }

   if (std::strncmp(tail, "MiB", 3) == 0 || std::strncmp(tail, "MB", 2) == 0)
   {
      return uint32_t(std::lround(value));
   }

   if (std::strncmp(tail, "GiB", 3) == 0 || std::strncmp(tail, "GB", 2) == 0)
   {
      return uint32_t(std::lround(value * 1024.0));
   }

   if (std::strncmp(tail, "KiB", 3) == 0 || std::strncmp(tail, "KB", 2) == 0)
   {
      return uint32_t(std::lround(value / 1024.0));
   }

   return uint32_t(std::lround(value));
}

static inline bool prodigyParseLscpuJSON(const String& json, ProdigyCpuInventorySnapshot& snapshot)
{
   snapshot = {};

   simdjson::dom::parser parser;
   simdjson::dom::element doc;
   if (parser.parse(json.data(), json.size()).get(doc))
   {
      return false;
   }

   simdjson::dom::array rows;
   if (doc["lscpu"].get_array().get(rows))
   {
      return false;
   }

   for (simdjson::dom::element row : rows)
   {
      simdjson::dom::element fieldNode;
      simdjson::dom::element dataNode;
      if (row["field"].get(fieldNode) != simdjson::SUCCESS || row["data"].get(dataNode) != simdjson::SUCCESS)
      {
         continue;
      }

      if (fieldNode.type() != simdjson::dom::element_type::STRING || dataNode.type() != simdjson::dom::element_type::STRING)
      {
         continue;
      }

      String field = {};
      String data = {};
      field.assign(fieldNode.get_c_str());
      data.assign(dataNode.get_c_str());
      prodigyNormalizeLscpuFieldName(field);
      prodigyTrimString(data);

      if (field.equal("Architecture"_ctv))
      {
         snapshot.architectureVersion.assign(data);
         snapshot.architecture = prodigyParseCpuArchitecture(data);
      }
      else if (field.equal("Vendor ID"_ctv) || field.equal("Vendor"_ctv))
      {
         snapshot.vendor.assign(data);
      }
      else if (field.equal("Model name"_ctv))
      {
         snapshot.model.assign(data);
      }
      else if (field.equal("Flags"_ctv) || field.equal("Features"_ctv))
      {
         prodigyParseCpuinfoFeatureList(data, snapshot.isaFeatures);
      }
      else if (field.equal("CPU(s)"_ctv))
      {
         (void)prodigyParseUnsignedDecimalText(data, snapshot.logicalCores);
      }
      else if (field.equal("Thread(s) per core"_ctv))
      {
         (void)prodigyParseUnsignedDecimalText(data, snapshot.threadsPerCore);
      }
      else if (field.equal("Socket(s)"_ctv))
      {
         (void)prodigyParseUnsignedDecimalText(data, snapshot.sockets);
      }
      else if (field.equal("NUMA node(s)"_ctv))
      {
         (void)prodigyParseUnsignedDecimalText(data, snapshot.numaNodes);
      }
      else if (field.equal("L3 cache"_ctv))
      {
         snapshot.l3CacheMB = prodigyParseLscpuCacheMB(data);
      }
   }

   return true;
}

static inline bool prodigyParseLscpuTopologyCSV(const String& csv, ProdigyCpuInventorySnapshot& snapshot)
{
   Vector<String> uniqueCores;
   Vector<String> uniqueSockets;
   Vector<String> uniqueNodes;

   uint64_t start = 0;
   while (start < csv.size())
   {
      uint64_t end = start;
      while (end < csv.size() && csv[end] != '\n')
      {
         end += 1;
      }

      if (end > start && csv[start] != '#')
      {
         String line = csv.substr(start, end - start, Copy::yes);
         Vector<String> columns = {};
         uint64_t columnStart = 0;
         while (columnStart <= line.size())
         {
            uint64_t columnEnd = columnStart;
            while (columnEnd < line.size() && line[columnEnd] != ',')
            {
               columnEnd += 1;
            }

            columns.push_back(line.substr(columnStart, columnEnd - columnStart, Copy::yes));
            if (columnEnd >= line.size())
            {
               break;
            }

            columnStart = columnEnd + 1;
         }

         if (columns.size() >= 5)
         {
            uint32_t cpuID = 0;
            bool online = (columns[1].equal("Y"_ctv)
               || columns[1].equal("y"_ctv)
               || columns[1].equal("1"_ctv)
               || columns[1].equal("yes"_ctv)
               || columns[1].equal("YES"_ctv)
               || columns[1].equal("true"_ctv)
               || columns[1].equal("TRUE"_ctv));
            if (prodigyParseUnsignedDecimalText(columns[0], cpuID) && online)
            {
               snapshot.onlineCpuIds.push_back(cpuID);

               String socketCore = {};
               socketCore.assign(columns[3]);
               socketCore.append(':');
               socketCore.append(columns[4]);
               prodigyPushUniqueString(uniqueCores, socketCore);
               prodigyPushUniqueString(uniqueSockets, columns[3]);
               prodigyPushUniqueString(uniqueNodes, columns[2]);
            }
         }
      }

      start = end + 1;
   }

   if (snapshot.onlineCpuIds.size() > 0)
   {
      snapshot.logicalCores = snapshot.onlineCpuIds.size();
   }
   snapshot.physicalCores = uniqueCores.size();
   if (snapshot.sockets == 0)
   {
      snapshot.sockets = uniqueSockets.size();
   }
   if (snapshot.numaNodes == 0)
   {
      snapshot.numaNodes = uniqueNodes.size();
   }

   return snapshot.logicalCores > 0;
}

static inline void prodigyBuildCpuListString(const Vector<uint32_t>& cpuIDs, String& cpuList)
{
   cpuList.clear();
   for (uint32_t index = 0; index < cpuIDs.size(); ++index)
   {
      if (index > 0)
      {
         cpuList.append(',');
      }

      String segment = {};
      segment.snprintf<"{itoa}"_ctv>(cpuIDs[index]);
      cpuList.append(segment);
   }
}

static inline bool prodigyParseSysbenchCpuOutput(const String& output, uint64_t& score, String *failure = nullptr)
{
   score = 0;
   if (failure) failure->clear();

   String owned = {};
   owned.assign(output);
   const char *text = owned.c_str();
   if (text == nullptr)
   {
      if (failure) failure->assign("sysbench output empty"_ctv);
      return false;
   }

   const char *eventsPerSecond = std::strstr(text, "events per second:");
   if (eventsPerSecond != nullptr)
   {
      score = uint64_t(std::llround(std::strtod(eventsPerSecond + std::strlen("events per second:"), nullptr)));
      return score > 0;
   }

   const char *totalTime = std::strstr(text, "total time:");
   const char *totalEvents = std::strstr(text, "total number of events:");
   if (totalTime != nullptr && totalEvents != nullptr)
   {
      double seconds = std::strtod(totalTime + std::strlen("total time:"), nullptr);
      double events = std::strtod(totalEvents + std::strlen("total number of events:"), nullptr);
      if (seconds > 0.0 && events > 0.0)
      {
         score = uint64_t(std::llround(events / seconds));
         return score > 0;
      }
   }

   if (failure) failure->assign("sysbench output malformed"_ctv);
   return false;
}

static inline bool prodigyRunSysbenchCpuBenchmark(
   const String& cpuList,
   uint32_t threads,
   const String& phase,
   MachineCpuHardwareProfile& cpu,
   const ProdigyMachineHardwareCollectorOptions& options,
   uint64_t& score,
   String *failure = nullptr
)
{
   score = 0;
   if (failure) failure->clear();

   String sysbenchCommand = {};
   if (prodigyResolveMachineHardwareToolCommand("sysbench"_ctv, sysbenchCommand) == false)
   {
      if (failure) failure->assign("sysbench unavailable"_ctv);
      return false;
   }

   String tasksetCommand = {};
   bool haveTaskset = prodigyResolveSystemToolPath("taskset"_ctv, tasksetCommand);

   String command = {};
   prodigyAppendCommandPrefix(command, options.cpuBenchmarkWarmupSeconds + options.cpuBenchmarkSeconds + 2);

   String inner = {};
   if (haveTaskset && cpuList.size() > 0)
   {
      prodigyAppendMachineHardwareShellSingleQuoted(inner, tasksetCommand);
      inner.append(" -c "_ctv);
      prodigyAppendMachineHardwareShellSingleQuoted(inner, cpuList);
      inner.append(' ');
   }

   inner.append(sysbenchCommand);
   inner.snprintf_add<" cpu --threads={itoa} --warmup-time={itoa} --time={itoa} --cpu-max-prime=20000 run"_ctv>(
      threads > 0 ? threads : 1,
      options.cpuBenchmarkWarmupSeconds,
      options.cpuBenchmarkSeconds
   );
   prodigyAppendMachineHardwareShellSingleQuoted(command, inner);

   String output = {};
   int rc = -1;
   String commandFailure = {};
   if (prodigyRunRecordedLocalCommand("sysbench"_ctv, phase, command, cpu.captures, output, &rc, &commandFailure) == false)
   {
      if (failure) failure->assign(commandFailure);
      return false;
   }

   if (prodigyParseSysbenchCpuOutput(output, score, failure) == false)
   {
      return false;
   }

   return true;
}

static inline void prodigyCollectCpuHardwareProfile(MachineCpuHardwareProfile& cpu, const ProdigyMachineHardwareCollectorOptions& options)
{
   cpu = {};

   ProdigyCpuInventorySnapshot snapshot = {};

   String command = {};
   prodigyAppendCommandPrefix(command, 4);
   prodigyAppendMachineHardwareShellSingleQuoted(command, "lscpu -J"_ctv);
   String lscpuJSON = {};
   if (prodigyRunRecordedLocalCommand("lscpu"_ctv, "inventory-json"_ctv, command, cpu.captures, lscpuJSON))
   {
      (void)prodigyParseLscpuJSON(lscpuJSON, snapshot);
   }

   command.clear();
   prodigyAppendCommandPrefix(command, 4);
   prodigyAppendMachineHardwareShellSingleQuoted(command, "lscpu -p=cpu,online,node,socket,core"_ctv);
   String lscpuTopology = {};
   if (prodigyRunRecordedLocalCommand("lscpu"_ctv, "inventory-topology"_ctv, command, cpu.captures, lscpuTopology))
   {
      (void)prodigyParseLscpuTopologyCSV(lscpuTopology, snapshot);
   }

   cpu.architecture = snapshot.architecture;
   cpu.architectureVersion.assign(snapshot.architectureVersion);
   cpu.vendor.assign(snapshot.vendor);
   cpu.model.assign(snapshot.model);
   cpu.isaFeatures = snapshot.isaFeatures;
   cpu.logicalCores = snapshot.logicalCores;
   cpu.physicalCores = snapshot.physicalCores;
   cpu.sockets = snapshot.sockets;
   cpu.numaNodes = snapshot.numaNodes;
   cpu.threadsPerCore = snapshot.threadsPerCore;
   cpu.l3CacheMB = snapshot.l3CacheMB;

   if (cpu.model.size() == 0)
   {
      prodigyReadCPUModelName(cpu.model);
   }

   if (cpu.logicalCores == 0)
   {
      cpu.logicalCores = std::max<uint32_t>(1, std::thread::hardware_concurrency());
   }

   if (cpu.architecture == MachineCpuArchitecture::unknown || cpu.vendor.size() == 0 || cpu.isaFeatures.size() == 0)
   {
      prodigyCollectCpuIdentity(cpu);
   }

   if (options.collectOptionalBenchmarks == false)
   {
      return;
   }

   String singleCpuList = {};
   if (snapshot.onlineCpuIds.size() > 0)
   {
      singleCpuList.snprintf<"{itoa}"_ctv>(snapshot.onlineCpuIds[0]);
   }

   String multiCpuList = {};
   prodigyBuildCpuListString(snapshot.onlineCpuIds, multiCpuList);

   String failure = {};
   (void)prodigyRunSysbenchCpuBenchmark(singleCpuList, 1, "single-thread"_ctv, cpu, options, cpu.singleThreadScore, &failure);
   (void)prodigyRunSysbenchCpuBenchmark(multiCpuList, cpu.logicalCores, "all-logicals"_ctv, cpu, options, cpu.multiThreadScore, &failure);
}

static inline MachineMemoryTechnology prodigyParseMemoryTechnology(const String& text)
{
   String owned = {};
   owned.assign(text);
   const char *cstring = owned.c_str();
   if (cstring == nullptr)
   {
      return MachineMemoryTechnology::unknown;
   }

   if (std::strstr(cstring, "DDR5") != nullptr)
   {
      return MachineMemoryTechnology::ddr5;
   }

   if (std::strstr(cstring, "DDR4") != nullptr)
   {
      return MachineMemoryTechnology::ddr4;
   }

   return MachineMemoryTechnology::unknown;
}

static inline uint32_t prodigyParseMemorySizeMB(const String& text)
{
   if (text.size() == 0 || text.equal("No Module Installed"_ctv))
   {
      return 0;
   }

   String owned = {};
   owned.assign(text);
   char *end = nullptr;
   uint64_t value = std::strtoull(owned.c_str(), &end, 10);
   if (end == nullptr)
   {
      return 0;
   }

   while (*end != '\0' && std::isspace(unsigned(*end)))
   {
      end += 1;
   }

   if (std::strncmp(end, "GB", 2) == 0)
   {
      return uint32_t(value * 1024ULL);
   }

   if (std::strncmp(end, "MB", 2) == 0)
   {
      return uint32_t(value);
   }

   return uint32_t(value);
}

static inline uint32_t prodigyParseMemorySpeedMTps(const String& text)
{
   if (text.size() == 0)
   {
      return 0;
   }

   String owned = {};
   owned.assign(text);
   return uint32_t(std::strtoul(owned.c_str(), nullptr, 10));
}

static inline void prodigyParseDmidecodeMemoryDevices(const String& text, MachineMemoryHardwareProfile& memory)
{
   uint64_t start = 0;
   while (start < text.size())
   {
      uint64_t end = start;
      while (end < text.size())
      {
         if (text[end] == '\n' && end + 1 < text.size() && text[end + 1] == '\n')
         {
            break;
         }

         end += 1;
      }

      String section = text.substr(start, end - start, Copy::yes);
      prodigyTrimString(section);
      if (prodigyStringStartsWith(section, "Memory Device"))
      {
         MachineMemoryModuleHardwareProfile module = {};
         String field = {};

         if (prodigyReadFirstCpuinfoField(section, "Locator", field))
         {
            module.locator.assign(field);
         }
         else if (prodigyReadFirstCpuinfoField(section, "Bank Locator", field))
         {
            module.locator.assign(field);
         }

         if (prodigyReadFirstCpuinfoField(section, "Manufacturer", field))
         {
            module.manufacturer.assign(field);
         }

         if (prodigyReadFirstCpuinfoField(section, "Part Number", field))
         {
            module.partNumber.assign(field);
         }

         if (prodigyReadFirstCpuinfoField(section, "Serial Number", field))
         {
            module.serial.assign(field);
         }

         if (prodigyReadFirstCpuinfoField(section, "Size", field))
         {
            module.sizeMB = prodigyParseMemorySizeMB(field);
         }

         if (prodigyReadFirstCpuinfoField(section, "Speed", field))
         {
            module.speedMTps = prodigyParseMemorySpeedMTps(field);
         }

         if (prodigyReadFirstCpuinfoField(section, "Type", field))
         {
            module.technology = prodigyParseMemoryTechnology(field);
            if (memory.technology == MachineMemoryTechnology::unknown)
            {
               memory.technology = module.technology;
            }
         }

         if (module.sizeMB > 0)
         {
            memory.modules.push_back(std::move(module));
         }
      }

      start = (end < text.size()) ? (end + 2) : text.size();
   }

   if (memory.technology == MachineMemoryTechnology::unknown)
   {
      memory.technology = prodigyParseMemoryTechnology(text);
   }
}

static inline void prodigyCollectMemoryDmiProfile(MachineMemoryHardwareProfile& memory)
{
   String command = {};
   prodigyAppendCommandPrefix(command, 3);
   prodigyAppendMachineHardwareShellSingleQuoted(command, "if command -v dmidecode >/dev/null 2>&1; then dmidecode -t memory; elif [ -r /sys/firmware/dmi/tables/DMI ]; then strings /sys/firmware/dmi/tables/DMI; else exit 127; fi"_ctv);

   String output = {};
   int rc = -1;
   if (prodigyRunRecordedLocalCommand("dmidecode"_ctv, "inventory"_ctv, command, memory.captures, output, &rc) == false)
   {
      return;
   }

   prodigyParseDmidecodeMemoryDevices(output, memory);
}

static inline bool prodigyParseLastFloatingValueFromLine(const String& line, double& value)
{
   value = 0.0;
   if (line.size() == 0)
   {
      return false;
   }

   String owned = {};
   owned.assign(line);
   const char *cursor = owned.c_str() + owned.size();
   while (cursor > owned.c_str() && std::isspace(unsigned(*(cursor - 1))))
   {
      cursor -= 1;
   }

   while (cursor > owned.c_str())
   {
      const char *tokenStart = cursor - 1;
      while (tokenStart > owned.c_str() && std::isspace(unsigned(*(tokenStart - 1))) == 0)
      {
         tokenStart -= 1;
      }

      String token = {};
      token.assign(tokenStart, uint64_t(cursor - tokenStart));
      char *tail = nullptr;
      double parsed = std::strtod(token.c_str(), &tail);
      if (tail && tail != token.c_str() && *tail == '\0')
      {
         value = parsed;
         return true;
      }
      cursor = tokenStart;
      while (cursor > owned.c_str() && std::isspace(unsigned(*(cursor - 1))))
      {
         cursor -= 1;
      }
   }

   return false;
}

static inline bool prodigyParseLatMemRdOutput(const String& output, uint32_t& latencyNs)
{
   latencyNs = 0;

   uint64_t start = 0;
   String lastDataLine = {};
   while (start < output.size())
   {
      uint64_t end = start;
      while (end < output.size() && output[end] != '\n')
      {
         end += 1;
      }

      if (end > start && output[start] != '"' && output[start] != '#')
      {
         lastDataLine.assign(output.substr(start, end - start, Copy::yes));
         prodigyTrimString(lastDataLine);
      }

      start = end + 1;
   }

   double parsed = 0.0;
   if (prodigyParseLastFloatingValueFromLine(lastDataLine, parsed) == false || parsed <= 0.0)
   {
      return false;
   }

   latencyNs = uint32_t(std::lround(parsed));
   return true;
}

static inline bool prodigyParseBwMemOutput(const String& output, uint32_t& bandwidthMBps)
{
   bandwidthMBps = 0;

   uint64_t start = 0;
   String lastDataLine = {};
   while (start < output.size())
   {
      uint64_t end = start;
      while (end < output.size() && output[end] != '\n')
      {
         end += 1;
      }

      if (end > start && output[start] != '#')
      {
         lastDataLine.assign(output.substr(start, end - start, Copy::yes));
         prodigyTrimString(lastDataLine);
      }

      start = end + 1;
   }

   double parsed = 0.0;
   if (prodigyParseLastFloatingValueFromLine(lastDataLine, parsed) == false || parsed <= 0.0)
   {
      return false;
   }

   bandwidthMBps = uint32_t(std::lround(parsed));
   return true;
}

static inline uint32_t prodigyDetermineMemoryProbeMB(const MachineCpuHardwareProfile& cpu, const MachineMemoryHardwareProfile& memory)
{
   uint32_t probeMB = cpu.l3CacheMB > 0 ? (cpu.l3CacheMB * 4) : 512;
   if (probeMB < 512)
   {
      probeMB = 512;
   }

   if (probeMB > 2048)
   {
      probeMB = 2048;
   }

   if (memory.totalMB > 0)
   {
      probeMB = std::min<uint32_t>(probeMB, std::max<uint32_t>(128, memory.totalMB / 2));
   }

   return probeMB;
}

static inline void prodigyCollectMemoryHardwareProfile(MachineMemoryHardwareProfile& memory, const MachineCpuHardwareProfile& cpu, const ProdigyMachineHardwareCollectorOptions& options)
{
   memory = {};
   memory.totalMB = uint32_t(sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) / (1024ULL * 1024ULL));
   prodigyCollectMemoryDmiProfile(memory);

   if (options.collectOptionalBenchmarks == false)
   {
      return;
   }

   const uint32_t probeMB = prodigyDetermineMemoryProbeMB(cpu, memory);
   const uint32_t bwThreads = std::max<uint32_t>(1, cpu.physicalCores > 0 ? cpu.physicalCores : cpu.logicalCores);

   String latMemCommand = {};
   String bwMemCommand = {};
   if (prodigyResolveMachineHardwareToolCommand("lat_mem_rd"_ctv, latMemCommand) == false
      || prodigyResolveMachineHardwareToolCommand("bw_mem"_ctv, bwMemCommand) == false)
   {
      return;
   }

   String command = {};
   prodigyAppendCommandPrefix(command, options.memoryBenchmarkWarmupSeconds + options.memoryBenchmarkIterations + 2);
   String inner = {};
   inner.append(latMemCommand);
   inner.snprintf_add<" -P 1 -W {itoa} -N {itoa} {itoa} 128"_ctv>(
      options.memoryBenchmarkWarmupSeconds,
      options.memoryBenchmarkIterations,
      probeMB
   );
   prodigyAppendMachineHardwareShellSingleQuoted(command, inner);

   String output = {};
   if (prodigyRunRecordedLocalCommand("lat_mem_rd"_ctv, "latency"_ctv, command, memory.captures, output))
   {
      (void)prodigyParseLatMemRdOutput(output, memory.latencyNs);
   }

   command.clear();
   prodigyAppendCommandPrefix(command, options.memoryBenchmarkWarmupSeconds + options.memoryBenchmarkIterations + 2);
   inner.clear();
   inner.append(bwMemCommand);
   inner.snprintf_add<" -P {itoa} -W {itoa} -N {itoa} {itoa} cp"_ctv>(
      bwThreads,
      options.memoryBenchmarkWarmupSeconds,
      options.memoryBenchmarkIterations,
      probeMB
   );
   prodigyAppendMachineHardwareShellSingleQuoted(command, inner);

   output.clear();
   uint32_t bandwidth = 0;
   if (prodigyRunRecordedLocalCommand("bw_mem"_ctv, "bandwidth"_ctv, command, memory.captures, output) && prodigyParseBwMemOutput(output, bandwidth))
   {
      memory.readBandwidthMBps = bandwidth;
      memory.writeBandwidthMBps = bandwidth;
   }
}

class ProdigyLsblkRow
{
public:

   String name;
   String kernelName;
   String path;
   String model;
   String serial;
    String wwn;
   String type;
   String transport;
   String mountPath;
   String parentName;
   uint32_t logicalSectorBytes = 0;
   uint32_t physicalSectorBytes = 0;
   bool rotational = false;
   uint64_t sizeBytes = 0;
};

static inline bool prodigyParseLsblkPairsLine(const String& line, ProdigyLsblkRow& row)
{
   row = {};

   uint64_t i = 0;
   while (i < line.size())
   {
      while (i < line.size() && std::isspace(unsigned(line[i])))
      {
         i += 1;
      }

      if (i >= line.size())
      {
         break;
      }

      uint64_t keyStart = i;
      while (i < line.size() && line[i] != '=')
      {
         i += 1;
      }

      if (i >= line.size())
      {
         break;
      }

      String key = line.substr(keyStart, i - keyStart, Copy::yes);
      i += 1;
      if (i >= line.size() || line[i] != '"')
      {
         return false;
      }
      i += 1;

      String value = {};
      while (i < line.size())
      {
         if (line[i] == '"')
         {
            i += 1;
            break;
         }

         if (line[i] == '\\' && i + 1 < line.size())
         {
            i += 1;
         }

         value.append(line[i]);
         i += 1;
      }

      if (key.equal("NAME"_ctv)) row.name = value;
      else if (key.equal("MODEL"_ctv)) row.model = value;
      else if (key.equal("SERIAL"_ctv)) row.serial = value;
      else if (key.equal("TYPE"_ctv)) row.type = value;
      else if (key.equal("TRAN"_ctv)) row.transport = value;
      else if (key.equal("MOUNTPOINT"_ctv)) row.mountPath = value;
      else if (key.equal("PKNAME"_ctv)) row.parentName = value;
      else if (key.equal("ROTA"_ctv)) row.rotational = value.equal("1"_ctv);
      else if (key.equal("SIZE"_ctv))
      {
         String ownedValue = {};
         ownedValue.assign(value);
         row.sizeBytes = std::strtoull(ownedValue.c_str(), nullptr, 10);
      }
   }

   return row.name.size() > 0;
}

static inline MachineDiskBus prodigyParseDiskBus(const String& transport, const String& name)
{
   if (transport.equal("nvme"_ctv) || prodigyStringStartsWith(name, "nvme"))
   {
      return MachineDiskBus::pcie;
   }

   if (transport.equal("sata"_ctv) || transport.equal("ata"_ctv))
   {
      return MachineDiskBus::sata;
   }

   if (transport.equal("virtio"_ctv))
   {
      return MachineDiskBus::virtio;
   }

   if (transport.equal("usb"_ctv))
   {
      return MachineDiskBus::usb;
   }

   if (transport.equal("sas"_ctv) || transport.equal("scsi"_ctv))
   {
      return MachineDiskBus::scsi;
   }

   return MachineDiskBus::unknown;
}

static inline MachineDiskKind prodigyParseDiskKind(const ProdigyLsblkRow& row)
{
   if (row.transport.equal("nvme"_ctv) || prodigyStringStartsWith(row.name, "nvme"))
   {
      return MachineDiskKind::nvme;
   }

   if (row.rotational)
   {
      return MachineDiskKind::hdd;
   }

   return MachineDiskKind::ssd;
}

static inline MachineDiskFormFactor prodigyParseDiskFormFactor(const ProdigyLsblkRow& row)
{
   if (prodigyStringContains(row.model, "M.2") || prodigyStringContains(row.model, "2280") || prodigyStringContains(row.model, "22110"))
   {
      return MachineDiskFormFactor::m2;
   }

   if (prodigyStringContains(row.model, "U.2") || prodigyStringContains(row.model, "U2"))
   {
      return MachineDiskFormFactor::u2;
   }

   if (prodigyStringContains(row.model, "AIC") || prodigyStringContains(row.model, "Add-In") || prodigyStringContains(row.model, "HHHL"))
   {
      return MachineDiskFormFactor::addin;
   }

   if (row.transport.equal("sata"_ctv) || row.transport.equal("ata"_ctv))
   {
      if (prodigyStringContains(row.model, "2.5") || prodigyStringContains(row.model, "2,5"))
      {
         return MachineDiskFormFactor::sata25;
      }

      if (prodigyStringContains(row.model, "3.5") || prodigyStringContains(row.model, "3,5"))
      {
         return MachineDiskFormFactor::sata35;
      }
   }

   return MachineDiskFormFactor::unknown;
}

static inline bool prodigyParseLsblkJSON(const String& json, Vector<ProdigyLsblkRow>& rows)
{
   rows.clear();

   simdjson::dom::parser parser;
   simdjson::dom::element doc;
   if (parser.parse(json.data(), json.size()).get(doc))
   {
      return false;
   }

   simdjson::dom::array blockdevices;
   if (doc["blockdevices"].get_array().get(blockdevices))
   {
      return false;
   }

   std::function<void(simdjson::dom::element, const String&)> visitNode = [&] (simdjson::dom::element node, const String& parentName) -> void {
      ProdigyLsblkRow row = {};
      row.parentName.assign(parentName);

      simdjson::dom::element value;
      if (node["name"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING) row.name.assign(value.get_c_str());
      if (node["kname"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING) row.kernelName.assign(value.get_c_str());
      if (node["path"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING) row.path.assign(value.get_c_str());
      if (node["model"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING) row.model.assign(value.get_c_str());
      if (node["serial"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING) row.serial.assign(value.get_c_str());
      if (node["wwn"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING) row.wwn.assign(value.get_c_str());
      if (node["type"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING) row.type.assign(value.get_c_str());
      if (node["tran"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING) row.transport.assign(value.get_c_str());
      uint64_t numericValue = 0;
      if (node["rota"].get_uint64().get(numericValue) == simdjson::SUCCESS) row.rotational = (numericValue != 0);
      (void)node["size"].get_uint64().get(row.sizeBytes);
      if (node["log-sec"].get_uint64().get(numericValue) == simdjson::SUCCESS) row.logicalSectorBytes = uint32_t(numericValue);
      if (node["phy-sec"].get_uint64().get(numericValue) == simdjson::SUCCESS) row.physicalSectorBytes = uint32_t(numericValue);

      if (node["mountpoints"].get(value) == simdjson::SUCCESS)
      {
         if (value.type() == simdjson::dom::element_type::ARRAY)
         {
            for (simdjson::dom::element mountpoint : value.get_array())
            {
               if (mountpoint.type() == simdjson::dom::element_type::STRING)
               {
                  String text = {};
                  text.assign(mountpoint.get_c_str());
                  prodigyTrimString(text);
                  if (text.size() > 0)
                  {
                     row.mountPath.assign(text);
                     break;
                  }
               }
            }
         }
      }

      if (row.name.size() > 0)
      {
         rows.push_back(row);
      }

      if (node["children"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::ARRAY)
      {
         for (simdjson::dom::element child : value.get_array())
         {
            visitNode(child, row.name);
         }
      }
   };

   for (simdjson::dom::element device : blockdevices)
   {
      visitNode(device, ""_ctv);
   }

   return rows.size() > 0;
}

static inline uint32_t prodigyParsePcieGeneration(const String& speedText)
{
   String owned = {};
   owned.assign(speedText);
   double gtps = std::strtod(owned.c_str(), nullptr);
   if (gtps >= 60.0) return 6;
   if (gtps >= 30.0) return 5;
   if (gtps >= 15.0) return 4;
   if (gtps >= 7.5) return 3;
   if (gtps >= 4.5) return 2;
   if (gtps >= 2.0) return 1;
   return 0;
}

static inline uint32_t prodigyParsePcieLanes(const String& widthText)
{
   if (widthText.size() == 0)
   {
      return 0;
   }

   String owned = {};
   owned.assign(widthText);
   const char *text = owned.c_str();
   if (text == nullptr)
   {
      return 0;
   }

   while (*text == 'x' || *text == 'X' || std::isspace(unsigned(*text)))
   {
      text += 1;
   }

   return uint32_t(std::strtoul(text, nullptr, 10));
}

static inline void prodigyPopulateDiskPcieLink(const String& diskName, MachineDiskHardwareProfile& disk)
{
   String path = {};
   String speed = {};
   String width = {};

   path.snprintf<"/sys/block/{}/device/current_link_speed"_ctv>(diskName);
   bool haveSpeed = prodigyReadTextFile(path, speed);

   path.snprintf<"/sys/block/{}/device/current_link_width"_ctv>(diskName);
   bool haveWidth = prodigyReadTextFile(path, width);

   if (haveSpeed == false)
   {
      path.snprintf<"/sys/block/{}/device/device/current_link_speed"_ctv>(diskName);
      haveSpeed = prodigyReadTextFile(path, speed);
   }

   if (haveWidth == false)
   {
      path.snprintf<"/sys/block/{}/device/device/current_link_width"_ctv>(diskName);
      haveWidth = prodigyReadTextFile(path, width);
   }

   if (haveSpeed)
   {
      disk.pcieLink.assign(speed);
      disk.pcieGeneration = prodigyParsePcieGeneration(speed);
      if (haveWidth)
      {
         disk.pcieLink.append(" "_ctv);
         disk.pcieLink.append(width);
         disk.pcieLanes = prodigyParsePcieLanes(width);
      }
   }
}

static inline void prodigyBuildDiskInventoryLsblkCommand(String& command)
{
   command.clear();
   prodigyAppendCommandPrefix(command, 4);
   prodigyAppendMachineHardwareShellSingleQuoted(command, "lsblk -J -e7 -b --output NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,ROTA,TRAN,LOG-SEC,PHY-SEC,MOUNTPOINTS"_ctv);
}

static inline bool prodigyCollectDiskInventory(Vector<MachineDiskHardwareProfile>& disks, Vector<MachineToolCapture>& captures)
{
   disks.clear();

   String command = {};
   prodigyBuildDiskInventoryLsblkCommand(command);

   String output = {};
   if (prodigyRunRecordedLocalCommand("lsblk"_ctv, "inventory"_ctv, command, captures, output) == false)
   {
      return false;
   }

   Vector<ProdigyLsblkRow> rows;
   if (prodigyParseLsblkJSON(output, rows) == false)
   {
      return false;
   }

   for (const ProdigyLsblkRow& row : rows)
   {
      if (row.type.equal("disk"_ctv) == false)
      {
         continue;
      }

      MachineDiskHardwareProfile disk = {};
      disk.name.assign(row.name);
      disk.path.assign(row.path);
      disk.model.assign(row.model);
      disk.serial.assign(row.serial);
      disk.wwn.assign(row.wwn);
      disk.kind = prodigyParseDiskKind(row);
      disk.bus = prodigyParseDiskBus(row.transport, row.name);
      disk.formFactor = prodigyParseDiskFormFactor(row);
      disk.logicalSectorBytes = row.logicalSectorBytes;
      disk.physicalSectorBytes = row.physicalSectorBytes;
      disk.sizeMB = row.sizeBytes / (1024ULL * 1024ULL);
      disk.mountPath.assign(row.mountPath);

      if (disk.bus == MachineDiskBus::pcie)
      {
         prodigyPopulateDiskPcieLink(row.name, disk);
      }

      disks.push_back(std::move(disk));
   }

   for (const ProdigyLsblkRow& row : rows)
   {
      if (row.mountPath.size() == 0)
      {
         continue;
      }

      for (MachineDiskHardwareProfile& disk : disks)
      {
         if (disk.name.equals(row.name) || (row.parentName.size() > 0 && disk.name.equals(row.parentName)))
         {
            if (disk.mountPath.size() == 0)
            {
               disk.mountPath.assign(row.mountPath);
            }
         }
      }
   }

   return disks.size() > 0;
}

static inline bool prodigyParseFioBenchmarkJSON(const String& json, MachineDiskBenchmarkProfile& benchmark, bool sequentialPhase)
{
   simdjson::dom::parser parser;
   simdjson::dom::element doc;
   if (parser.parse(json.data(), json.size()).get(doc))
   {
      benchmark.failure.assign("fio output malformed"_ctv);
      return false;
   }

   simdjson::dom::array jobs;
   if (doc["jobs"].get_array().get(jobs))
   {
      benchmark.failure.assign("fio jobs missing"_ctv);
      return false;
   }

   if (jobs.begin() == jobs.end())
   {
      benchmark.failure.assign("fio jobs empty"_ctv);
      return false;
   }

   simdjson::dom::element job = *jobs.begin();
   uint64_t readBwBytes = 0;
   uint64_t writeBwBytes = 0;
   double readIops = 0;
   double writeIops = 0;
   double readLatNs = 0;
   double writeLatNs = 0;

   auto parseLatencyPercentileUs = [] (simdjson::dom::element node, const char *label, uint32_t& out) -> void {
      simdjson::dom::element latNode;
      if (node["clat_ns"].get(latNode) != simdjson::SUCCESS && node["lat_ns"].get(latNode) != simdjson::SUCCESS)
      {
         return;
      }

      simdjson::dom::element percentileNode;
      if (latNode["percentile"].get(percentileNode) != simdjson::SUCCESS)
      {
         return;
      }

      double value = 0.0;
      if (percentileNode[label].get_double().get(value) != simdjson::SUCCESS)
      {
         uint64_t integerValue = 0;
         if (percentileNode[label].get_uint64().get(integerValue) == simdjson::SUCCESS)
         {
            value = double(integerValue);
         }
      }

      if (value > 0.0)
      {
         out = uint32_t(std::lround(value / 1000.0));
      }
   };

   simdjson::dom::element readNode;
   if (job["read"].get(readNode) == simdjson::SUCCESS)
   {
      (void)readNode["bw_bytes"].get_uint64().get(readBwBytes);
      (void)readNode["iops"].get_double().get(readIops);
      if (sequentialPhase == false)
      {
         parseLatencyPercentileUs(readNode, "50.000000", benchmark.randomReadLatencyP50Us);
         parseLatencyPercentileUs(readNode, "95.000000", benchmark.randomReadLatencyP95Us);
         parseLatencyPercentileUs(readNode, "99.000000", benchmark.randomReadLatencyP99Us);
         parseLatencyPercentileUs(readNode, "99.900000", benchmark.randomReadLatencyP999Us);
      }
   }

   simdjson::dom::element writeNode;
   if (job["write"].get(writeNode) == simdjson::SUCCESS)
   {
      (void)writeNode["bw_bytes"].get_uint64().get(writeBwBytes);
      (void)writeNode["iops"].get_double().get(writeIops);
      if (sequentialPhase == false)
      {
         parseLatencyPercentileUs(writeNode, "50.000000", benchmark.randomWriteLatencyP50Us);
         parseLatencyPercentileUs(writeNode, "95.000000", benchmark.randomWriteLatencyP95Us);
         parseLatencyPercentileUs(writeNode, "99.000000", benchmark.randomWriteLatencyP99Us);
         parseLatencyPercentileUs(writeNode, "99.900000", benchmark.randomWriteLatencyP999Us);
      }
   }

   if (sequentialPhase)
   {
      benchmark.sequentialReadMBps = uint32_t(readBwBytes / (1024ULL * 1024ULL));
      benchmark.sequentialWriteMBps = uint32_t(writeBwBytes / (1024ULL * 1024ULL));
   }
   else
   {
      benchmark.randomReadIops = uint32_t(std::lround(readIops));
      benchmark.randomWriteIops = uint32_t(std::lround(writeIops));
   }

   return true;
}

static inline bool prodigyBenchmarkDiskAtMountPathWithFio(const String& mountPath, const ProdigyMachineHardwareCollectorOptions& options, MachineDiskBenchmarkProfile& benchmark)
{
   if (mountPath.size() == 0)
   {
      benchmark.failure.assign("no writable mount path"_ctv);
      return false;
   }

   String fioCommand = {};
   if (prodigyResolveMachineHardwareToolCommand("fio"_ctv, fioCommand) == false)
   {
      benchmark.failure.assign("fio unavailable"_ctv);
      return false;
   }

   String filePath = {};
   filePath.snprintf<"{}/.prodigy-fio-{itoa}"_ctv>(mountPath, uint32_t(getpid()));

   auto runFioPhase = [&] (const char *rw, const char *bs, uint32_t ioDepth, bool sequentialPhase) -> bool {
      String command = {};
      prodigyAppendCommandPrefix(command, options.diskBenchmarkSeconds + 4);
      String inner = {};
      inner.append(fioCommand);
      inner.snprintf_add<" --name=prodigy --filename={}"_ctv>(filePath);
      inner.snprintf_add<" --rw={}"_ctv>(String(rw));
      inner.snprintf_add<" --bs={}"_ctv>(String(bs));
      inner.snprintf_add<" --size=64M --ioengine=libaio --direct=1 --runtime={itoa} --time_based=1 --iodepth={itoa} --numjobs=1 --group_reporting=1 --output-format=json+"_ctv>(
         options.diskBenchmarkSeconds,
         ioDepth
      );
      if (sequentialPhase == false)
      {
         inner.append(" --lat_percentiles=1 --percentile_list=50:95:99:99.9"_ctv);
      }
      prodigyAppendMachineHardwareShellSingleQuoted(command, inner);

      String output = {};
      int rc = -1;
      String failure = {};
      String phase = sequentialPhase ? String(rw) : String(rw);
      if (prodigyRunRecordedLocalCommand("fio"_ctv, phase, command, benchmark.captures, output, &rc, &failure) == false)
      {
         benchmark.failure = failure.size() > 0 ? failure : "fio phase failed"_ctv;
         return false;
      }

      if (prodigyParseFioBenchmarkJSON(output, benchmark, sequentialPhase) == false)
      {
         return false;
      }

      return true;
   };

   if (runFioPhase("read", "1M", 32, true) == false)
   {
      prodigyEraseFileBestEffort(filePath);
      return false;
   }

   if (runFioPhase("write", "1M", 32, true) == false)
   {
      prodigyEraseFileBestEffort(filePath);
      return false;
   }

   if (runFioPhase("randread", "4k", 1, false) == false)
   {
      prodigyEraseFileBestEffort(filePath);
      return false;
   }

   if (runFioPhase("randwrite", "4k", 1, false) == false)
   {
      prodigyEraseFileBestEffort(filePath);
      return false;
   }

   prodigyEraseFileBestEffort(filePath);
   benchmark.failure.clear();
   return true;
}

static inline void prodigyCollectDiskBenchmarks(Vector<MachineDiskHardwareProfile>& disks, const ProdigyMachineHardwareCollectorOptions& options)
{
   uint32_t benchmarked = 0;
   for (MachineDiskHardwareProfile& disk : disks)
   {
      disk.benchmark = {};

      if (disk.mountPath.size() == 0)
      {
         disk.benchmark.failure.assign("no writable mount path"_ctv);
         continue;
      }

      if (benchmarked >= options.diskBenchmarkLimit)
      {
         disk.benchmark.failure.assign("benchmark skipped due to time budget"_ctv);
         continue;
      }

      (void)prodigyBenchmarkDiskAtMountPathWithFio(disk.mountPath, options, disk.benchmark);
      benchmarked += 1;
   }
}

class ProdigyNicGatewayMapping
{
public:

   String ifname;
   bool is6 = false;
   IPAddress gateway;
};

class ProdigyPciDescription
{
public:

   String busAddress;
   String vendor;
   String model;
};

static inline void prodigyParseLspciMachineReadableLine(const String& line, ProdigyPciDescription& descriptor)
{
   descriptor = {};
   uint64_t cursor = 0;

   while (cursor < line.size() && std::isspace(unsigned(line[cursor])) == 0)
   {
      descriptor.busAddress.append(line[cursor]);
      cursor += 1;
   }

   Vector<String> quotedFields;
   while (cursor < line.size())
   {
      while (cursor < line.size() && line[cursor] != '"')
      {
         cursor += 1;
      }

      if (cursor >= line.size())
      {
         break;
      }

      cursor += 1;
      String field = {};
      while (cursor < line.size())
      {
         if (line[cursor] == '"')
         {
            cursor += 1;
            break;
         }

         if (line[cursor] == '\\' && cursor + 1 < line.size())
         {
            cursor += 1;
         }

         field.append(line[cursor]);
         cursor += 1;
      }

      quotedFields.push_back(std::move(field));
   }

   if (quotedFields.size() >= 3)
   {
      descriptor.vendor.assign(quotedFields[1]);
      descriptor.model.assign(quotedFields[2]);
   }
}

static inline void prodigyCollectPciDescriptions(Vector<ProdigyPciDescription>& descriptors, Vector<MachineToolCapture>* captures = nullptr)
{
   descriptors.clear();

   String command = {};
   prodigyAppendCommandPrefix(command, 4);
   prodigyAppendMachineHardwareShellSingleQuoted(command, "if command -v lspci >/dev/null 2>&1; then lspci -D -mm; else exit 127; fi"_ctv);

   String output = {};
   if ((captures && prodigyRunRecordedLocalCommand("lspci"_ctv, "inventory"_ctv, command, *captures, output) == false)
      || (captures == nullptr && prodigyRunBlockingLocalCommandCaptureStdout(command, output) == false))
   {
      return;
   }

   uint64_t start = 0;
   while (start < output.size())
   {
      uint64_t end = start;
      while (end < output.size() && output[end] != '\n')
      {
         end += 1;
      }

      if (end > start)
      {
         ProdigyPciDescription descriptor = {};
         prodigyParseLspciMachineReadableLine(output.substr(start, end - start, Copy::yes), descriptor);
         if (descriptor.busAddress.size() > 0)
         {
            descriptors.push_back(std::move(descriptor));
         }
      }

      start = end + 1;
   }
}

static inline const ProdigyPciDescription *prodigyFindPciDescription(const Vector<ProdigyPciDescription>& descriptors, const String& busAddress)
{
   for (const ProdigyPciDescription& descriptor : descriptors)
   {
      if (descriptor.busAddress.equals(busAddress))
      {
         return &descriptor;
      }
   }

   return nullptr;
}

static inline void prodigyApplyPciDescriptionToNic(const ProdigyPciDescription& descriptor, MachineNicHardwareProfile& nic)
{
   nic.vendor.assign(descriptor.vendor);
   nic.model.assign(descriptor.model);
}

static inline void prodigyPopulateNicPciIdentity(const String& nicName, MachineNicHardwareProfile& nic, const Vector<ProdigyPciDescription>& pciDescriptions)
{
   String path = {};
   path.snprintf<"/sys/class/net/{}/device/vendor"_ctv>(nicName);
   (void)prodigyReadTextFile(path, nic.vendorID);

   path.snprintf<"/sys/class/net/{}/device/device"_ctv>(nicName);
   (void)prodigyReadTextFile(path, nic.deviceID);

   path.snprintf<"/sys/class/net/{}/device"_ctv>(nicName);
   char busPath[PATH_MAX] = {};
   String ownedPath = {};
   ownedPath.assign(path);
   ssize_t length = readlink(ownedPath.c_str(), busPath, sizeof(busPath) - 1);
   if (length > 0)
   {
      busPath[length] = '\0';
      const char *slash = std::strrchr(busPath, '/');
      nic.busAddress.assign(slash ? slash + 1 : busPath);
   }

   if (const ProdigyPciDescription *descriptor = prodigyFindPciDescription(pciDescriptions, nic.busAddress))
   {
      prodigyApplyPciDescriptionToNic(*descriptor, nic);
   }
}

static inline MachineNicHardwareProfile *prodigyFindNicByName(Vector<MachineNicHardwareProfile>& nics, const String& ifname)
{
   for (MachineNicHardwareProfile& nic : nics)
   {
      if (nic.name.equals(ifname))
      {
         return &nic;
      }
   }

   return nullptr;
}

static inline const ProdigyNicGatewayMapping *prodigyFindNicGateway(const Vector<ProdigyNicGatewayMapping>& gateways, const String& ifname, bool is6)
{
   for (const ProdigyNicGatewayMapping& gateway : gateways)
   {
      if (gateway.ifname.equals(ifname) && gateway.is6 == is6)
      {
         return &gateway;
      }
   }

   return nullptr;
}

static inline bool prodigyPopulateNicSubnetsFromJSON(Vector<MachineNicHardwareProfile>& nics, const String& addressOutput, const String& routeOutput)
{
   Vector<ProdigyNicGatewayMapping> gateways;
   if (routeOutput.size() > 0)
   {
      simdjson::dom::parser routeParser;
      simdjson::dom::element routeDoc;
      if (routeParser.parse(routeOutput.data(), routeOutput.size()).get(routeDoc) == simdjson::SUCCESS && routeDoc.type() == simdjson::dom::element_type::ARRAY)
      {
         for (simdjson::dom::element route : routeDoc.get_array())
         {
            String ifname = {};
            String dst = {};
            String gatewayText = {};

            simdjson::dom::element value;
            if (route["dev"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING)
            {
               ifname.assign(value.get_c_str());
            }
            if (route["dst"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING)
            {
               dst.assign(value.get_c_str());
            }
            if (route["gateway"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING)
            {
               gatewayText.assign(value.get_c_str());
            }

            if (ifname.size() == 0 || gatewayText.size() == 0)
            {
               continue;
            }

            if (dst.equal("default"_ctv) == false && dst.equal("::/0"_ctv) == false)
            {
               continue;
            }

            ProdigyNicGatewayMapping mapping = {};
            mapping.ifname.assign(ifname);
            if (prodigyParseIPAddressLiteral(gatewayText, mapping.gateway) == false)
            {
               continue;
            }
            mapping.is6 = mapping.gateway.is6;
            gateways.push_back(std::move(mapping));
         }
      }
   }

   simdjson::dom::parser addressParser;
   simdjson::dom::element addressDoc;
   if (addressParser.parse(addressOutput.data(), addressOutput.size()).get(addressDoc))
   {
      return false;
   }

   if (addressDoc.type() != simdjson::dom::element_type::ARRAY)
   {
      return false;
   }

   for (simdjson::dom::element iface : addressDoc.get_array())
   {
      String ifname = {};
      simdjson::dom::element ifnameValue;
      if (iface["ifname"].get(ifnameValue) != simdjson::SUCCESS || ifnameValue.type() != simdjson::dom::element_type::STRING)
      {
         continue;
      }

      ifname.assign(ifnameValue.get_c_str());
      MachineNicHardwareProfile *nic = prodigyFindNicByName(nics, ifname);
      if (nic == nullptr)
      {
         continue;
      }

      simdjson::dom::array addrInfo;
      if (iface["addr_info"].get_array().get(addrInfo))
      {
         continue;
      }

      for (simdjson::dom::element addr : addrInfo)
      {
         String family = {};
         String local = {};
         uint64_t prefixLength = 0;
         simdjson::dom::element value;

         if (addr["family"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING)
         {
            family.assign(value.get_c_str());
         }
         if (addr["local"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING)
         {
            local.assign(value.get_c_str());
         }
         if (addr["prefixlen"].get_uint64().get(prefixLength))
         {
            continue;
         }

         if (local.size() == 0 || (family.equal("inet"_ctv) == false && family.equal("inet6"_ctv) == false))
         {
            continue;
         }

         MachineNicSubnetHardwareProfile subnet = {};
         if (prodigyParseIPAddressLiteral(local, subnet.address) == false)
         {
            continue;
         }

         prodigyComputePrefixNetwork(subnet.address, uint8_t(prefixLength), subnet.subnet);
         if (const ProdigyNicGatewayMapping *gateway = prodigyFindNicGateway(gateways, ifname, subnet.address.is6))
         {
            subnet.gateway = gateway->gateway;
         }

         nic->subnets.push_back(std::move(subnet));
      }
   }

   return true;
}

static inline bool prodigyPopulateNicsFromIpLinkJSON(Vector<MachineNicHardwareProfile>& nics, const String& output)
{
   nics.clear();

   simdjson::dom::parser parser;
   simdjson::dom::element doc;
   if (parser.parse(output.data(), output.size()).get(doc))
   {
      return false;
   }

   if (doc.type() != simdjson::dom::element_type::ARRAY)
   {
      return false;
   }

   for (simdjson::dom::element iface : doc.get_array())
   {
      String ifname = {};
      String mac = {};
      String operstate = {};

      simdjson::dom::element value;
      if (iface["ifname"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING)
      {
         ifname.assign(value.get_c_str());
      }
      if (iface["address"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING)
      {
         mac.assign(value.get_c_str());
      }
      if (iface["operstate"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING)
      {
         operstate.assign(value.get_c_str());
      }

      if (ifname.size() == 0 || ifname.equal("lo"_ctv))
      {
         continue;
      }

      MachineNicHardwareProfile& nic = nics.emplace_back();
      nic.name.assign(ifname);
      nic.mac.assign(mac);
      nic.up = (operstate.equal("UP"_ctv) || operstate.equal("up"_ctv));
   }

   return nics.empty() == false;
}

static inline void prodigyParseEthtoolOutput(const String& output, MachineNicHardwareProfile& nic)
{
   String field = {};
   if (prodigyReadFirstCpuinfoField(output, "Speed", field))
   {
      String owned = {};
      owned.assign(field);
      uint64_t speed = std::strtoull(owned.c_str(), nullptr, 10);
      if (speed > 0 && speed <= UINT32_MAX)
      {
         nic.linkSpeedMbps = uint32_t(speed);
      }
   }
}

static inline void prodigyParseEthtoolDriverInfoOutput(const String& output, MachineNicHardwareProfile& nic)
{
   String field = {};
   if (prodigyReadFirstCpuinfoField(output, "driver", field))
   {
      nic.driver.assign(field);
   }
   if (prodigyReadFirstCpuinfoField(output, "bus-info", field))
   {
      nic.busAddress.assign(field);
   }
}

static inline bool prodigyCollectNicSubnets(Vector<MachineNicHardwareProfile>& nics, Vector<MachineToolCapture>& captures)
{
   String command = {};
   prodigyAppendCommandPrefix(command, 4);
   prodigyAppendMachineHardwareShellSingleQuoted(command, "ip -j address show"_ctv);

   String addressOutput = {};
   if (prodigyRunRecordedLocalCommand("ip"_ctv, "addr-show"_ctv, command, captures, addressOutput) == false)
   {
      return false;
   }

   command.clear();
   prodigyAppendCommandPrefix(command, 4);
   prodigyAppendMachineHardwareShellSingleQuoted(command, "ip -j route show table all"_ctv);

   String routeOutput = {};
   (void)prodigyRunRecordedLocalCommand("ip"_ctv, "route-show"_ctv, command, captures, routeOutput);
   return prodigyPopulateNicSubnetsFromJSON(nics, addressOutput, routeOutput);
}

static inline void prodigyCollectNicInventory(MachineNetworkHardwareProfile& network)
{
   network.nics.clear();
   Vector<ProdigyPciDescription> pciDescriptions;
   prodigyCollectPciDescriptions(pciDescriptions, &network.captures);

   String command = {};
   prodigyAppendCommandPrefix(command, 4);
   prodigyAppendMachineHardwareShellSingleQuoted(command, "ip -j link show"_ctv);
   String output = {};
   if (prodigyRunRecordedLocalCommand("ip"_ctv, "link-show"_ctv, command, network.captures, output))
   {
      (void)prodigyPopulateNicsFromIpLinkJSON(network.nics, output);
   }

   String ethtoolCommand = {};
   bool haveEthtool = prodigyResolveSystemToolPath("ethtool"_ctv, ethtoolCommand);
   for (MachineNicHardwareProfile& nic : network.nics)
   {
      prodigyPopulateNicPciIdentity(nic.name, nic, pciDescriptions);

      if (haveEthtool == false)
      {
         continue;
      }

      String inner = {};
      prodigyAppendMachineHardwareShellSingleQuoted(inner, ethtoolCommand);
      inner.append(' ');
      prodigyAppendMachineHardwareShellSingleQuoted(inner, nic.name);

      command.clear();
      prodigyAppendCommandPrefix(command, 4);
      prodigyAppendMachineHardwareShellSingleQuoted(command, inner);
      output.clear();
      if (prodigyRunRecordedLocalCommand("ethtool"_ctv, "link"_ctv, command, nic.captures, output))
      {
         prodigyParseEthtoolOutput(output, nic);
      }

      inner.clear();
      prodigyAppendMachineHardwareShellSingleQuoted(inner, ethtoolCommand);
      inner.append(" -i "_ctv);
      prodigyAppendMachineHardwareShellSingleQuoted(inner, nic.name);

      command.clear();
      prodigyAppendCommandPrefix(command, 4);
      prodigyAppendMachineHardwareShellSingleQuoted(command, inner);
      output.clear();
      if (prodigyRunRecordedLocalCommand("ethtool"_ctv, "driver"_ctv, command, nic.captures, output))
      {
         prodigyParseEthtoolDriverInfoOutput(output, nic);
      }
   }

   (void)prodigyCollectNicSubnets(network.nics, network.captures);
}

static inline bool prodigyParseIperf3JSON(const String& output, uint32_t& sentMbps, uint32_t& receivedMbps)
{
   sentMbps = 0;
   receivedMbps = 0;

   simdjson::dom::parser parser;
   simdjson::dom::element doc;
   if (parser.parse(output.data(), output.size()).get(doc))
   {
      return false;
   }

   simdjson::dom::element endNode;
   if (doc["end"].get(endNode) != simdjson::SUCCESS)
   {
      return false;
   }

   auto parseMbps = [] (simdjson::dom::element node) -> uint32_t {
      double bitsPerSecond = 0.0;
      if (node["bits_per_second"].get_double().get(bitsPerSecond) != simdjson::SUCCESS)
      {
         uint64_t integerValue = 0;
         if (node["bits_per_second"].get_uint64().get(integerValue) == simdjson::SUCCESS)
         {
            bitsPerSecond = double(integerValue);
         }
      }

      if (bitsPerSecond <= 0.0)
      {
         return 0;
      }

      return uint32_t(std::lround(bitsPerSecond / 1000000.0));
   };

   simdjson::dom::element sentNode;
   if (endNode["sum_sent"].get(sentNode) == simdjson::SUCCESS)
   {
      sentMbps = parseMbps(sentNode);
   }

   simdjson::dom::element receivedNode;
   if (endNode["sum_received"].get(receivedNode) == simdjson::SUCCESS)
   {
      receivedMbps = parseMbps(receivedNode);
   }

   return sentMbps > 0 || receivedMbps > 0;
}

static inline bool prodigyParseSpeedtestJSON(
   const String& output,
   uint32_t& latencyMs,
   uint32_t& downloadMbps,
   uint32_t& uploadMbps,
   String *serverName = nullptr,
   String *interfaceName = nullptr,
   IPAddress *sourceAddress = nullptr
)
{
   latencyMs = 0;
   downloadMbps = 0;
   uploadMbps = 0;
   if (serverName) serverName->clear();
   if (interfaceName) interfaceName->clear();
   if (sourceAddress) *sourceAddress = {};

   simdjson::dom::parser parser;
   simdjson::dom::element doc;
   if (parser.parse(output.data(), output.size()).get(doc))
   {
      return false;
   }

   auto parseDoubleValue = [] (simdjson::dom::element object, const char *field, double& value) -> bool {
      value = 0.0;
      simdjson::dom::element node;
      if (object[field].get(node) != simdjson::SUCCESS)
      {
         return false;
      }

      if (node.get_double().get(value) == simdjson::SUCCESS)
      {
         return true;
      }

      uint64_t unsignedValue = 0;
      if (node.get_uint64().get(unsignedValue) == simdjson::SUCCESS)
      {
         value = double(unsignedValue);
         return true;
      }

      int64_t signedValue = 0;
      if (node.get_int64().get(signedValue) == simdjson::SUCCESS)
      {
         value = double(signedValue);
         return true;
      }

      return false;
   };

   simdjson::dom::element pingNode;
   simdjson::dom::element downloadNode;
   simdjson::dom::element uploadNode;
   if (doc["ping"].get(pingNode) != simdjson::SUCCESS
      || doc["download"].get(downloadNode) != simdjson::SUCCESS
      || doc["upload"].get(uploadNode) != simdjson::SUCCESS)
   {
      return false;
   }

   double pingLatency = 0.0;
   double downloadBytesPerSecond = 0.0;
   double uploadBytesPerSecond = 0.0;
   if (parseDoubleValue(pingNode, "latency", pingLatency) == false
      || parseDoubleValue(downloadNode, "bandwidth", downloadBytesPerSecond) == false
      || parseDoubleValue(uploadNode, "bandwidth", uploadBytesPerSecond) == false)
   {
      return false;
   }

   if (pingLatency <= 0.0 || downloadBytesPerSecond <= 0.0 || uploadBytesPerSecond <= 0.0)
   {
      return false;
   }

   latencyMs = std::max<uint32_t>(1, uint32_t(std::lround(pingLatency)));
   downloadMbps = std::max<uint32_t>(1, uint32_t(std::lround((downloadBytesPerSecond * 8.0) / 1000000.0)));
   uploadMbps = std::max<uint32_t>(1, uint32_t(std::lround((uploadBytesPerSecond * 8.0) / 1000000.0)));

   if (serverName)
   {
      simdjson::dom::element serverNode;
      if (doc["server"].get(serverNode) == simdjson::SUCCESS)
      {
         simdjson::dom::element value;
         String name = {};
         String location = {};
         String host = {};
         if (serverNode["name"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING)
         {
            name.assign(value.get_c_str());
         }
         if (serverNode["location"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING)
         {
            location.assign(value.get_c_str());
         }
         if (serverNode["host"].get(value) == simdjson::SUCCESS && value.type() == simdjson::dom::element_type::STRING)
         {
            host.assign(value.get_c_str());
         }

         if (name.size() > 0 && location.size() > 0)
         {
            serverName->assign(name);
            serverName->append(" / "_ctv);
            serverName->append(location);
         }
         else if (name.size() > 0)
         {
            serverName->assign(name);
         }
         else if (location.size() > 0)
         {
            serverName->assign(location);
         }
         else if (host.size() > 0)
         {
            serverName->assign(host);
         }
      }
   }

   simdjson::dom::element interfaceNode;
   if (doc["interface"].get(interfaceNode) == simdjson::SUCCESS)
   {
      simdjson::dom::element value;

      if (interfaceName
         && interfaceNode["name"].get(value) == simdjson::SUCCESS
         && value.type() == simdjson::dom::element_type::STRING)
      {
         interfaceName->assign(value.get_c_str());
      }

      auto parseIPAddressField = [&] (const char *field, IPAddress *target) -> void {

         if (target == nullptr)
         {
            return;
         }

         simdjson::dom::element node;
         if (interfaceNode[field].get(node) != simdjson::SUCCESS || node.type() != simdjson::dom::element_type::STRING)
         {
            return;
         }

         String text = {};
         text.assign(node.get_c_str());
         IPAddress parsed = {};
         struct in_addr address4 = {};
         struct in6_addr address6 = {};
         if (inet_pton(AF_INET, text.c_str(), &address4) == 1)
         {
            parsed = {};
            parsed.v4 = address4.s_addr;
            parsed.is6 = false;
            *target = parsed;
         }
         else if (inet_pton(AF_INET6, text.c_str(), &address6) == 1)
         {
            parsed = {};
            memcpy(parsed.v6, &address6, sizeof(address6));
            parsed.is6 = true;
            *target = parsed;
         }
      };

      parseIPAddressField("internalIp", sourceAddress);
   }

   return true;
}

static inline void prodigyTagInternetReachableNicSubnets(MachineNetworkHardwareProfile& network)
{
   for (MachineNicHardwareProfile& nic : network.nics)
   {
      for (MachineNicSubnetHardwareProfile& subnet : nic.subnets)
      {
         subnet.internetReachable = false;
      }
   }

   if (network.internet.sourceAddress.isNull())
   {
      return;
   }

   auto markMatchingSubnet = [&] (bool requireInterfaceName) -> bool {

      for (MachineNicHardwareProfile& nic : network.nics)
      {
         if (requireInterfaceName
            && network.internet.interfaceName.size() > 0
            && nic.name.equals(network.internet.interfaceName) == false)
         {
            continue;
         }

         for (MachineNicSubnetHardwareProfile& subnet : nic.subnets)
         {
            if (subnet.address.equals(network.internet.sourceAddress))
            {
               subnet.internetReachable = true;
               return true;
            }
         }
      }

      return false;
   };

   if (network.internet.interfaceName.size() > 0 && markMatchingSubnet(true))
   {
      return;
   }

   (void)markMatchingSubnet(false);
}

static inline void prodigyCollectInternetNetworkBenchmark(MachineInternetBenchmarkProfile& benchmark, const ProdigyMachineHardwareCollectorOptions& options)
{
   benchmark = {};

   String speedtestCommand = {};
   if (prodigyResolveOfficialSpeedtestCommand(speedtestCommand) == false)
   {
      benchmark.attempted = true;
      benchmark.failure.assign("official speedtest unavailable"_ctv);
      return;
   }

   benchmark.attempted = true;

   String command = {};
   prodigyAppendCommandPrefix(command, options.internetBenchmarkTimeoutSeconds + 2);

   String inner = {};
   inner.append(speedtestCommand);
   inner.append(" --accept-license --accept-gdpr --format=json --progress=no"_ctv);
   prodigyAppendMachineHardwareShellSingleQuoted(command, inner);

   String output = {};
   int rc = -1;
   String failure = {};
   if (prodigyRunRecordedLocalCommand("speedtest"_ctv, "internet"_ctv, command, benchmark.captures, output, &rc, &failure) == false)
   {
      benchmark.failure = failure.size() > 0 ? failure : "speedtest failed"_ctv;
      return;
   }

   if (prodigyParseSpeedtestJSON(
         output,
         benchmark.latencyMs,
         benchmark.downloadMbps,
         benchmark.uploadMbps,
         &benchmark.serverName,
         &benchmark.interfaceName,
         &benchmark.sourceAddress
      ) == false)
   {
      benchmark.failure.assign("speedtest output malformed"_ctv);
      return;
   }

   benchmark.failure.clear();
}

static inline void prodigyFinalizeMachineHardwareBenchmarks(MachineHardwareProfile& hardware)
{
   prodigyTagInternetReachableNicSubnets(hardware.network);
   hardware.benchmarksComplete = true;
   for (const MachineDiskHardwareProfile& disk : hardware.disks)
   {
      if (disk.benchmark.failure.size() > 0)
      {
         hardware.benchmarksComplete = false;
         break;
      }
   }

   if (hardware.network.internet.attempted && hardware.network.internet.failure.size() > 0)
   {
      hardware.benchmarksComplete = false;
   }

   if (hardware.benchmarksComplete == false)
   {
      hardware.benchmarkFailure.assign("one or more optional hardware benchmarks were unavailable or failed"_ctv);
      return;
   }

   hardware.benchmarkFailure.clear();
}

static inline void prodigyDeferOptionalMachineHardwareBenchmarks(MachineHardwareProfile& hardware)
{
   hardware.benchmarksComplete = false;
   hardware.benchmarkFailure.assign("optional hardware benchmarks deferred from boot path"_ctv);
}

static inline void prodigyCollectGpuInventory(Vector<MachineGpuHardwareProfile>& gpus)
{
   gpus.clear();

   auto parseNvidiaInventory = [&] (const String& output) -> void {
      uint64_t start = 0;
      while (start < output.size())
      {
         uint64_t end = start;
         while (end < output.size() && output[end] != '\n')
         {
            end += 1;
         }

         if (end > start)
         {
            String line = output.substr(start, end - start, Copy::yes);
            prodigyTrimString(line);
            if (line.size() > 0)
            {
               Vector<String> fields;
               String current = {};
               bool inQuote = false;
               for (uint64_t i = 0; i < line.size(); ++i)
               {
                  if (line[i] == '"')
                  {
                     inQuote = (inQuote == false);
                     continue;
                  }
                  if (line[i] == ',' && inQuote == false)
                  {
                     prodigyTrimString(current);
                     fields.push_back(current);
                     current.clear();
                     continue;
                  }
                  current.append(line[i]);
               }
               prodigyTrimString(current);
               if (current.size() > 0)
               {
                  fields.push_back(current);
               }

               if (fields.size() >= 3)
               {
                  MachineGpuHardwareProfile& gpu = gpus.emplace_back();
                  gpu.vendor.assign("nvidia"_ctv);
                  gpu.busAddress.assign(fields[0]);
                  gpu.model.assign(fields[1]);
                  gpu.memoryMB = fields[2].as<uint32_t>();
               }
            }
         }

         start = end + 1;
      }
   };

   String command = {};
   prodigyAppendCommandPrefix(command, 4);
   prodigyAppendMachineHardwareShellSingleQuoted(command, "if command -v nvidia-smi >/dev/null 2>&1; then nvidia-smi --query-gpu=pci.bus_id,name,memory.total --format=csv,noheader,nounits; else exit 127; fi"_ctv);
   String output = {};
   Vector<MachineToolCapture> captures = {};
   if (prodigyRunRecordedLocalCommand("nvidia-smi"_ctv, "inventory"_ctv, command, captures, output))
   {
      parseNvidiaInventory(output);
      for (MachineGpuHardwareProfile& gpu : gpus)
      {
         gpu.captures = captures;
      }
      return;
   }

   command.clear();
   prodigyAppendCommandPrefix(command, 4);
    prodigyAppendMachineHardwareShellSingleQuoted(command, "if command -v lspci >/dev/null 2>&1; then lspci; else exit 127; fi"_ctv);
   output.clear();
   captures.clear();
   if (prodigyRunRecordedLocalCommand("lspci"_ctv, "inventory"_ctv, command, captures, output))
   {
      uint64_t start = 0;
      while (start < output.size())
      {
         uint64_t end = start;
         while (end < output.size() && output[end] != '\n')
         {
            end += 1;
         }

         if (end > start)
         {
            String line = output.substr(start, end - start, Copy::yes);
            prodigyTrimString(line);
            if (prodigyStringContains(line, "VGA compatible controller") || prodigyStringContains(line, "3D controller"))
            {
               MachineGpuHardwareProfile& gpu = gpus.emplace_back();
               gpu.model.assign(line);
               gpu.captures = captures;
            }
         }

         start = end + 1;
      }
   }
}

static inline void prodigyCollectMachineHardwareProfile(MachineHardwareProfile& hardware, const ProdigyMachineHardwareCollectorOptions& options = {})
{
   hardware = {};
   hardware.collectedAtMs = Time::now<TimeResolution::ms>();

   prodigyCollectCpuHardwareProfile(hardware.cpu, options);
   prodigyCollectMemoryHardwareProfile(hardware.memory, hardware.cpu, options);
   bool haveDisks = prodigyCollectDiskInventory(hardware.disks, hardware.captures);
   prodigyCollectNicInventory(hardware.network);
   prodigyCollectGpuInventory(hardware.gpus);

   bool haveNetworkAddressing = false;
   for (const MachineNicHardwareProfile& nic : hardware.network.nics)
   {
      if (nic.subnets.empty() == false)
      {
         haveNetworkAddressing = true;
         break;
      }
   }

   hardware.inventoryComplete =
      (hardware.cpu.logicalCores > 0
      && hardware.memory.totalMB > 0
      && (haveDisks || hardware.disks.size() > 0)
      && haveNetworkAddressing);

   if (hardware.inventoryComplete == false)
   {
      hardware.inventoryFailure.assign("failed to collect required cpu/memory/storage inventory"_ctv);
      return;
   }

   if (options.collectOptionalBenchmarks == false)
   {
      prodigyDeferOptionalMachineHardwareBenchmarks(hardware);
      return;
   }

   prodigyCollectDiskBenchmarks(hardware.disks, options);
   prodigyCollectInternetNetworkBenchmark(hardware.network.internet, options);
   prodigyFinalizeMachineHardwareBenchmarks(hardware);
}
