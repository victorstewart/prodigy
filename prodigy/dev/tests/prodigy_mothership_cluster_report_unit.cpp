#include <networking/includes.h>
#include <services/debug.h>
#include <macros/bytes.h>
#include <services/bitsery.h>
#include <services/filesystem.h>
#include <services/time.h>
#include <networking/message.h>
#include <services/prodigy.h>

#include <prodigy/build.identity.h>
#include <prodigy/mothership/mothership.cluster.registry.h>
#include <prodigy/wire.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#ifndef PRODIGY_TEST_BINARY_DIR
#define PRODIGY_TEST_BINARY_DIR ""
#endif

#ifndef PRODIGY_ROOT_DIR
#define PRODIGY_ROOT_DIR ""
#endif

class TestSuite
{
public:

   int failed = 0;

   void expect(bool condition, const char *name)
   {
      if (condition)
      {
         basics_log("PASS: %s\n", name);
      }
      else
      {
         basics_log("FAIL: %s\n", name);
         if (name != nullptr)
         {
            (void)::write(STDERR_FILENO, "FAIL: ", 6);
            (void)::write(STDERR_FILENO, name, std::strlen(name));
            (void)::write(STDERR_FILENO, "\n", 1);
         }
         failed += 1;
      }
   }
};

class ScopedEnvVar
{
private:

   String name = {};
   String previousValue = {};
   bool hadPreviousValue = false;

public:

   ScopedEnvVar(const char *envName, const String& value)
   {
      name.assign(envName);
      if (const char *previous = getenv(envName); previous && previous[0] != '\0')
      {
         previousValue.assign(previous);
         hadPreviousValue = true;
      }

      String valueText = {};
      valueText.assign(value);
      setenv(envName, valueText.c_str(), 1);
   }

   ~ScopedEnvVar()
   {
      if (hadPreviousValue)
      {
         setenv(name.c_str(), previousValue.c_str(), 1);
      }
      else
      {
         unsetenv(name.c_str());
      }
   }
};

static bool stringContains(const String& haystack, const char *needle)
{
   String text = {};
   text.assign(haystack);
   return std::strstr(text.c_str(), needle) != nullptr;
}

static bool stringMissing(const String& haystack, const char *needle)
{
   return stringContains(haystack, needle) == false;
}

static void writeFailureDetail(const char *label, const String& text)
{
   if (label != nullptr)
   {
      (void)::write(STDERR_FILENO, label, std::strlen(label));
   }

   if (text.size() > 0)
   {
      (void)::write(STDERR_FILENO, text.data(), size_t(text.size()));
   }

   (void)::write(STDERR_FILENO, "\n", 1);
}

struct MothershipWireHeader
{
   uint32_t size = 0;
   uint16_t topic = 0;
   uint8_t padding = 0;
   uint8_t headerSize = 0;
};

static_assert(sizeof(MothershipWireHeader) == 8);

static void appendClusterMachineConfig(MothershipProdigyCluster& cluster, const MachineConfig& config)
{
   MothershipProdigyClusterMachineSchema schema = {};
   schema.schema = config.slug;
   schema.kind = config.kind;
   schema.ipxeScriptURL = config.ipxeScriptURL;
   schema.vmImageURI = config.vmImageURI;
   schema.gcpInstanceTemplate = config.gcpInstanceTemplate;
   schema.gcpInstanceTemplateSpot = config.gcpInstanceTemplateSpot;
   cluster.machineSchemas.push_back(schema);
}

struct ControlServerState
{
   std::atomic<bool> stopRequested = false;
   uint32_t acceptCount = 0;
   bool sawPullClusterReport = false;
   bool sawMeasureApplication = false;
   bool sawSpinApplication = false;
   bool deployBlobMatched = false;
   uint16_t deployApplicationID = 0;
   String deployProgressMessage = {};
   String failure = {};
};

class ScopedUnixListener
{
public:

   String path = {};
   int fd = -1;

   ~ScopedUnixListener()
   {
      if (fd >= 0)
      {
         ::close(fd);
      }

      if (path.size() > 0)
      {
         (void)::unlink(path.c_str());
      }
   }
};

static ClusterMachine makeTopologyMachine(
   const String& schema,
   const String& privateAddress,
   bool isBrain,
   ClusterMachineSource source,
   ClusterMachineBacking backing,
   MachineLifetime lifetime)
{
   ClusterMachine machine = {};
   machine.source = source;
   machine.backing = backing;
   machine.lifetime = lifetime;
   machine.kind = MachineConfig::MachineKind::vm;
   machine.isBrain = isBrain;
   if (backing == ClusterMachineBacking::cloud)
   {
      machine.hasCloud = true;
      machine.cloud.schema = schema;
      machine.cloud.providerMachineType = schema;
      machine.cloud.cloudID = privateAddress;
   }
   machine.ssh.address = privateAddress;
   machine.ssh.port = 22;
   machine.ssh.user = "root"_ctv;
   machine.ssh.privateKeyPath = "/tmp/unit-test-key"_ctv;
   prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, privateAddress);
   prodigyAppendUniqueClusterMachineAddress(machine.addresses.publicAddresses, privateAddress);
   machine.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
   machine.totalLogicalCores = 8;
   machine.totalMemoryMB = 16384;
   machine.totalStorageMB = 262144;
   machine.ownedLogicalCores = 8;
   machine.ownedMemoryMB = 16384;
   machine.ownedStorageMB = 262144;
   return machine;
}

static MachineStatusReport makeMachineStatusReport(
   const String& schema,
   const String& state,
   bool isBrain,
   bool controlPlaneReachable,
   bool currentMaster,
   bool decommissioning,
   bool rebooting,
   bool updatingOS,
   bool hardwareFailure,
   int64_t bootTimeMs,
   int64_t uptimeMs,
   const String& publicAddress,
   const String& privateAddress,
   const String& cloudID,
   uint32_t totalLogicalCores,
   uint32_t totalMemoryMB,
   uint32_t totalStorageMB,
   uint32_t ownedLogicalCores,
   uint32_t ownedMemoryMB,
   uint32_t ownedStorageMB)
{
   MachineStatusReport report = {};
   report.state = state;
   report.isBrain = isBrain;
   report.controlPlaneReachable = controlPlaneReachable;
   report.currentMaster = currentMaster;
   report.decommissioning = decommissioning;
   report.rebooting = rebooting;
   report.updatingOS = updatingOS;
   report.hardwareFailure = hardwareFailure;
   report.bootTimeMs = bootTimeMs;
   report.uptimeMs = uptimeMs;
   if (cloudID.size() > 0)
   {
      report.hasCloud = true;
      report.cloud.schema = schema;
      report.cloud.providerMachineType = schema;
      report.cloud.cloudID = cloudID;
   }
   report.ssh.address = publicAddress.size() > 0 ? publicAddress : privateAddress;
   prodigyAppendUniqueClusterMachineAddress(report.addresses.publicAddresses, publicAddress);
   prodigyAppendUniqueClusterMachineAddress(report.addresses.privateAddresses, privateAddress);
   report.totalLogicalCores = totalLogicalCores;
   report.totalMemoryMB = totalMemoryMB;
   report.totalStorageMB = totalStorageMB;
   report.ownedLogicalCores = ownedLogicalCores;
   report.ownedMemoryMB = ownedMemoryMB;
   report.ownedStorageMB = ownedStorageMB;
   return report;
}

static void populateMachineIdentityReport(
   MachineStatusReport& report,
   const String& machineUUID,
   const String& source,
   const String& backing,
   const String& lifetime,
   const String& provider,
   const String& region,
   const String& zone,
   const String& sshAddress,
   uint16_t sshPort)
{
   report.machineUUID = machineUUID;
   report.source = source;
   report.backing = backing;
   report.lifetime = lifetime;
   report.provider = provider;
   report.region = region;
   report.zone = zone;
   report.ssh.address = sshAddress;
   report.ssh.port = sshPort;
}

static bool readExact(int fd, uint8_t *buffer, size_t length, String& failure)
{
   while (length > 0)
   {
      ssize_t rc = ::recv(fd, buffer, length, 0);
      if (rc > 0)
      {
         buffer += size_t(rc);
         length -= size_t(rc);
         continue;
      }

      if (rc < 0 && errno == EINTR)
      {
         continue;
      }

      if (rc == 0)
      {
         failure.assign("unexpected eof while reading unix control frame"_ctv);
      }
      else
      {
         failure.snprintf<"recv failed: {}"_ctv>(String(std::strerror(errno)));
      }

      return false;
   }

   failure.clear();
   return true;
}

static bool sendAll(int fd, const String& frame, String& failure)
{
   const uint8_t *buffer = frame.data();
   size_t remaining = size_t(frame.size());

   while (remaining > 0)
   {
      ssize_t rc = ::send(fd, buffer, remaining, MSG_NOSIGNAL);
      if (rc > 0)
      {
         buffer += size_t(rc);
         remaining -= size_t(rc);
         continue;
      }

      if (rc < 0 && errno == EINTR)
      {
         continue;
      }

      failure.snprintf<"send failed: {}"_ctv>(String(std::strerror(errno)));
      return false;
   }

   failure.clear();
   return true;
}

static bool sendAllFragmented(int fd, const String& frame, size_t chunkSize, useconds_t pauseUs, String& failure)
{
   const uint8_t *buffer = frame.data();
   size_t remaining = size_t(frame.size());

   while (remaining > 0)
   {
      size_t chunk = remaining < chunkSize ? remaining : chunkSize;
      ssize_t rc = ::send(fd, buffer, chunk, MSG_NOSIGNAL);
      if (rc > 0)
      {
         buffer += size_t(rc);
         remaining -= size_t(rc);
         if (remaining > 0 && pauseUs > 0)
         {
            ::usleep(pauseUs);
         }
         continue;
      }

      if (rc < 0 && errno == EINTR)
      {
         continue;
      }

      failure.snprintf<"send failed: {}"_ctv>(String(std::strerror(errno)));
      return false;
   }

   failure.clear();
   return true;
}

static bool recvOneMessageFrame(int fd, String& frame, String& failure)
{
   MothershipWireHeader header = {};
   if (readExact(fd, reinterpret_cast<uint8_t *>(&header), sizeof(header), failure) == false)
   {
      return false;
   }

   if (header.size < sizeof(Message))
   {
      failure.assign("received framed message smaller than Message header"_ctv);
      return false;
   }

   frame.clear();
   frame.append(reinterpret_cast<uint8_t *>(&header), sizeof(header));

   uint32_t remaining = header.size - uint32_t(sizeof(header));
   if (remaining == 0)
   {
      failure.clear();
      return true;
   }

   uint8_t scratch[4096];
   while (remaining > 0)
   {
      uint32_t chunk = (remaining < sizeof(scratch)) ? remaining : uint32_t(sizeof(scratch));
      if (readExact(fd, scratch, chunk, failure) == false)
      {
         return false;
      }

      frame.append(scratch, chunk);
      remaining -= chunk;
   }

   failure.clear();
   return true;
}

static bool createUnixListener(ScopedUnixListener& listener, String& failure)
{
   failure.clear();

   char pathBuffer[sizeof(sockaddr_un::sun_path)] = {};
   std::snprintf(
      pathBuffer,
      sizeof(pathBuffer),
      "/tmp/nametag-mship-cluster-report-%d-%u.sock",
      int(::getpid()),
      unsigned(Time::now<TimeResolution::ms>() & 0xffffffffu));
   listener.path.assign(pathBuffer);

   (void)::unlink(listener.path.c_str());

   listener.fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
   if (listener.fd < 0)
   {
      failure.snprintf<"socket failed: {}"_ctv>(String(std::strerror(errno)));
      return false;
   }

   struct sockaddr_un address = {};
   address.sun_family = AF_UNIX;
   std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", listener.path.c_str());
   socklen_t addressLen = socklen_t(sizeof(address.sun_family) + std::strlen(address.sun_path));

   if (::bind(listener.fd, reinterpret_cast<struct sockaddr *>(&address), addressLen) != 0)
   {
      failure.snprintf<"bind failed: {}"_ctv>(String(std::strerror(errno)));
      return false;
   }

   if (::listen(listener.fd, 16) != 0)
   {
      failure.snprintf<"listen failed: {}"_ctv>(String(std::strerror(errno)));
      return false;
   }

   return true;
}

static bool acceptNextClient(int listenerFD, ControlServerState& state, int& clientFD)
{
   clientFD = -1;

   while (state.stopRequested.load() == false)
   {
      struct pollfd pollFD = {};
      pollFD.fd = listenerFD;
      pollFD.events = POLLIN;

      int rc = ::poll(&pollFD, 1, 100);
      if (rc > 0 && (pollFD.revents & POLLIN))
      {
         clientFD = ::accept(listenerFD, nullptr, nullptr);
         if (clientFD >= 0)
         {
            state.acceptCount += 1;
            return true;
         }

         if (errno == EINTR)
         {
            continue;
         }

         state.failure.snprintf<"accept failed: {}"_ctv>(String(std::strerror(errno)));
         return false;
      }

      if (rc == 0)
      {
         continue;
      }

      if (rc < 0 && errno == EINTR)
      {
         continue;
      }

      state.failure.snprintf<"poll failed: {}"_ctv>(String(std::strerror(errno)));
      return false;
   }

   return false;
}

static bool handleClusterReportStep(int clientFD, ControlServerState& state, String& failure)
{
   String frame = {};
   if (recvOneMessageFrame(clientFD, frame, failure) == false)
   {
      return false;
   }

   Message *message = reinterpret_cast<Message *>(const_cast<uint8_t *>(frame.data()));
   if (MothershipTopic(message->topic) != MothershipTopic::pullClusterReport)
   {
      failure.assign("unexpected topic for clusterReport request"_ctv);
      return false;
   }

   state.sawPullClusterReport = true;

   ClusterStatusReport report = {};
   report.hasTopology = true;
   report.topology.version = 99;
   report.topology.machines.push_back(makeTopologyMachine(
      "report-brain"_ctv,
      "fd00::10"_ctv,
      true,
      ClusterMachineSource::adopted,
      ClusterMachineBacking::owned,
      MachineLifetime::owned));
   report.topology.machines.push_back(makeTopologyMachine(
      "report-worker-spot"_ctv,
      "fd00::20"_ctv,
      false,
      ClusterMachineSource::created,
      ClusterMachineBacking::cloud,
      MachineLifetime::spot));
   report.nMachines = 2;
   report.nSpotMachines = 1;
   report.nApplications = 0;
   report.machineReports.push_back(makeMachineStatusReport(
      "report-brain"_ctv,
      "healthy"_ctv,
      true,
      true,
      true,
      false,
      false,
      false,
      false,
      1'700'000'000'000ll,
      86'400'000ll,
      "2001:db8::10"_ctv,
      "fd00::10"_ctv,
      ""_ctv,
      8,
      16384,
      262144,
      8,
      16384,
      262144));
   populateMachineIdentityReport(
      report.machineReports.back(),
      "abc123"_ctv,
      "local"_ctv,
      "owned"_ctv,
      "owned"_ctv,
      ""_ctv,
      ""_ctv,
      ""_ctv,
      "fd00::10"_ctv,
      22);
   report.machineReports.back().deployedContainers.push_back("c-brain-1"_ctv);
   report.machineReports.back().deployedContainers.push_back("c-brain-2"_ctv);
   report.machineReports.back().applicationNames.push_back("radar"_ctv);
   report.machineReports.back().applicationNames.push_back("probe"_ctv);
   report.machineReports.back().deploymentIDs.push_back("101"_ctv);
   report.machineReports.back().deploymentIDs.push_back("202"_ctv);
   report.machineReports.back().shardGroups.push_back("7"_ctv);
   report.machineReports.back().shardGroups.push_back("9"_ctv);
   report.machineReports.back().activeContainers = 2;
   report.machineReports.back().reservedContainers = 1;
   report.machineReports.back().activeIsolatedLogicalCores = 4;
   report.machineReports.back().reservedIsolatedLogicalCores = 2;
   report.machineReports.back().activeSharedCPUMillis = 0;
   report.machineReports.back().reservedSharedCPUMillis = 500;
   report.machineReports.back().activeMemoryMB = 4096;
   report.machineReports.back().reservedMemoryMB = 2048;
   report.machineReports.back().activeStorageMB = 16384;
   report.machineReports.back().reservedStorageMB = 4096;
   report.machineReports.back().runningProdigyVersion = "123"_ctv;
   report.machineReports.back().approvedBundleSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv;
   report.machineReports.back().updateStage = "waitingForBundleEchos"_ctv;
   report.machineReports.back().stagedBundleSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv;
   {
      String largeSuffix = {};
      // Force recvExpectedTopic(...) to grow and preserve a partial frame.
      largeSuffix.reserve(512_KB);
      for (uint32_t i = 0; i < 512_KB; ++i)
      {
         largeSuffix.append(uint8_t('x'));
      }
      report.machineReports.back().stagedBundleSHA256.append(largeSuffix);
   }
   report.machineReports.push_back(makeMachineStatusReport(
      "report-worker-spot"_ctv,
      "hardwareFailure"_ctv,
      false,
      false,
      false,
      false,
      false,
      false,
      true,
      1'699'999'500'000ll,
      43'210ll,
      "2001:db8::20"_ctv,
      "fd00::20"_ctv,
      "i-worker-spot"_ctv,
      16,
      32768,
      524288,
      16,
      32768,
      524288));
   populateMachineIdentityReport(
      report.machineReports.back(),
      "def456"_ctv,
      "created"_ctv,
      "cloud"_ctv,
      "spot"_ctv,
      "aws"_ctv,
      "us-east-1"_ctv,
      "us-east-1c"_ctv,
      "fd00::20"_ctv,
      2202);
   report.machineReports.back().deployedContainers.push_back("c-worker-1"_ctv);
   report.machineReports.back().applicationNames.push_back("radar"_ctv);
   report.machineReports.back().deploymentIDs.push_back("101"_ctv);
   report.machineReports.back().shardGroups.push_back("7"_ctv);
   report.machineReports.back().activeContainers = 1;
   report.machineReports.back().reservedContainers = 0;
   report.machineReports.back().activeIsolatedLogicalCores = 2;
   report.machineReports.back().reservedIsolatedLogicalCores = 0;
   report.machineReports.back().activeSharedCPUMillis = 1000;
   report.machineReports.back().reservedSharedCPUMillis = 0;
   report.machineReports.back().activeMemoryMB = 2048;
   report.machineReports.back().reservedMemoryMB = 0;
   report.machineReports.back().activeStorageMB = 8192;
   report.machineReports.back().reservedStorageMB = 0;
   report.machineReports.back().updateStage = "idle"_ctv;

   String serialized = {};
   BitseryEngine::serialize(serialized, report);

   String response = {};
   Message::construct(response, MothershipTopic::pullClusterReport, serialized);
   return sendAllFragmented(clientFD, response, 257, 20'000, failure);
}

static bool handleOversizedClusterReportStep(int clientFD, ControlServerState& state, String& failure)
{
   String frame = {};
   if (recvOneMessageFrame(clientFD, frame, failure) == false)
   {
      return false;
   }

   Message *message = reinterpret_cast<Message *>(const_cast<uint8_t *>(frame.data()));
   if (MothershipTopic(message->topic) != MothershipTopic::pullClusterReport)
   {
      failure.assign("unexpected topic for oversized clusterReport request"_ctv);
      return false;
   }

   state.sawPullClusterReport = true;

   MothershipWireHeader oversized = {};
   oversized.size = ProdigyWire::maxControlFrameBytes + 16;
   oversized.topic = uint16_t(MothershipTopic::pullClusterReport);
   oversized.headerSize = uint8_t(sizeof(MothershipWireHeader));

   String response = {};
   response.append(reinterpret_cast<const uint8_t *>(&oversized), sizeof(oversized));
   return sendAll(clientFD, response, failure);
}

static bool writeFileText(const String& path, const String& contents, String& failure)
{
   String pathText = {};
   pathText.assign(path);
   FILE *file = std::fopen(pathText.c_str(), "wb");
   if (file == nullptr)
   {
      failure.snprintf<"fopen failed: {}"_ctv>(String(std::strerror(errno)));
      return false;
   }

   size_t written = std::fwrite(contents.data(), 1, size_t(contents.size()), file);
   int closeRC = std::fclose(file);
   if (written != size_t(contents.size()) || closeRC != 0)
   {
      failure.snprintf<"write failed: {}"_ctv>(String(std::strerror(errno)));
      return false;
   }

   failure.clear();
   return true;
}

static bool readFileBytes(const String& path, String& contents, String& failure)
{
   contents.clear();
   String pathText = {};
   pathText.assign(path);

   if (::access(pathText.c_str(), R_OK) != 0)
   {
      failure.snprintf<"file is not readable: {}"_ctv>(path);
      return false;
   }

   Filesystem::openReadAtClose(-1, pathText, contents);
   failure.clear();
   return true;
}

static bool copyFile(const String& sourcePath, const String& destinationPath, String& failure)
{
   String sourceText = {};
   sourceText.assign(sourcePath);
   String destinationText = {};
   destinationText.assign(destinationPath);

   std::error_code error;
   std::filesystem::copy_file(
      std::filesystem::path(sourceText.c_str()),
      std::filesystem::path(destinationText.c_str()),
      std::filesystem::copy_options::overwrite_existing,
      error);
   if (error)
   {
      failure.snprintf<"copy_file failed: {}"_ctv>(String(error.message().c_str()));
      return false;
   }

   failure.clear();
   return true;
}

static bool fileExists(const String& path)
{
   String pathText = {};
   pathText.assign(path);
   return std::filesystem::exists(std::filesystem::path(pathText.c_str()));
}

static bool executableOnPath(const char *name)
{
   if (name == nullptr || name[0] == '\0')
   {
      return false;
   }

   const char *pathEnv = std::getenv("PATH");
   if (pathEnv == nullptr || pathEnv[0] == '\0')
   {
      return false;
   }

   std::string pathList(pathEnv);
   size_t start = 0;
   while (start <= pathList.size())
   {
      size_t separator = pathList.find(':', start);
      std::string pathEntry = separator == std::string::npos
         ? pathList.substr(start)
         : pathList.substr(start, separator - start);
      if (pathEntry.empty())
      {
         pathEntry = ".";
      }

      std::filesystem::path candidate = std::filesystem::path(pathEntry) / name;
      if (::access(candidate.c_str(), X_OK) == 0)
      {
         return true;
      }

      if (separator == std::string::npos)
      {
         break;
      }

      start = separator + 1;
   }

   return false;
}

static String buildDeployPlanJSON(uint16_t applicationID, MachineCpuArchitecture architecture)
{
   char buffer[2048] = {};
   int written = std::snprintf(
      buffer,
      sizeof(buffer),
      "{\"config\":{\"type\":\"ApplicationType::stateless\",\"applicationID\":%u,\"versionID\":1,\"architecture\":\"%s\",\"filesystemMB\":64,\"storageMB\":64,\"memoryMB\":128,\"nLogicalCores\":1,\"msTilHealthy\":10000,\"sTilHealthcheck\":15,\"sTilKillable\":30},\"minimumSubscriberCapacity\":1024,\"isStateful\":false,\"stateless\":{\"nBase\":1,\"maxPerRackRatio\":1.0,\"maxPerMachineRatio\":1.0,\"moveableDuringCompaction\":true},\"useHostNetworkNamespace\":false,\"subscriptions\":[],\"advertisements\":[],\"moveConstructively\":true,\"requiresDatacenterUniqueTag\":false}",
      unsigned(applicationID),
      machineCpuArchitectureName(architecture));

   String json = {};
   if (written > 0)
   {
      json.assign(reinterpret_cast<const uint8_t *>(buffer), size_t(written));
   }
   return json;
}

static bool runCommand(
   const String& binary,
   const String *workingDirectory,
   const std::vector<std::pair<std::string, std::string>>& environment,
   const std::vector<std::string>& arguments,
   String& output,
   int& exitCode)
{
   output.clear();
   exitCode = -1;

   int pipeFDs[2] = {-1, -1};
   if (::pipe(pipeFDs) != 0)
   {
      return false;
   }

   pid_t pid = ::fork();
   if (pid < 0)
   {
      ::close(pipeFDs[0]);
      ::close(pipeFDs[1]);
      return false;
   }

   if (pid == 0)
   {
      String binaryText = {};
      binaryText.assign(binary);

      ::dup2(pipeFDs[1], STDOUT_FILENO);
      ::dup2(pipeFDs[1], STDERR_FILENO);
      ::close(pipeFDs[0]);
      ::close(pipeFDs[1]);

      if (workingDirectory && workingDirectory->size() > 0)
      {
         String cwd = {};
         cwd.assign(*workingDirectory);
         if (::chdir(cwd.c_str()) != 0)
         {
            std::perror("chdir");
            _exit(126);
         }
      }

      for (const auto& [name, value] : environment)
      {
         ::setenv(name.c_str(), value.c_str(), 1);
      }

      std::vector<char *> argv;
      argv.reserve(arguments.size() + 2);
      argv.push_back(const_cast<char *>(binaryText.c_str()));
      for (const std::string& argument : arguments)
      {
         argv.push_back(const_cast<char *>(argument.c_str()));
      }
      argv.push_back(nullptr);

      ::execv(binaryText.c_str(), argv.data());
      std::perror("execv");
      _exit(127);
   }

   ::close(pipeFDs[1]);

   char buffer[4096];
   while (true)
   {
      ssize_t readBytes = ::read(pipeFDs[0], buffer, sizeof(buffer));
      if (readBytes == 0)
      {
         break;
      }

      if (readBytes < 0)
      {
         ::close(pipeFDs[0]);
         (void)::waitpid(pid, nullptr, 0);
         return false;
      }

      output.append(reinterpret_cast<const uint8_t *>(buffer), size_t(readBytes));
   }

   ::close(pipeFDs[0]);

   int status = 0;
   if (::waitpid(pid, &status, 0) < 0)
   {
      return false;
   }

   if (WIFEXITED(status))
   {
      exitCode = WEXITSTATUS(status);
   }
   else if (WIFSIGNALED(status))
   {
      exitCode = 128 + WTERMSIG(status);
   }

   return true;
}

static bool runMothershipCommand(
   const String& mothershipBinary,
   const String& dbRoot,
   const std::vector<std::string>& arguments,
   String& output,
   int& exitCode)
{
   String dbRootText = {};
   dbRootText.assign(dbRoot);
   return runCommand(
      mothershipBinary,
      nullptr,
      {{"PRODIGY_MOTHERSHIP_TIDESDB_PATH", std::string(dbRootText.c_str())}},
      arguments,
      output,
      exitCode);
}

static bool buildDiscombobulatorArtifact(
   const String& repoRoot,
   const String& projectRoot,
   const String& filePath,
   const String& contextRoot,
   const String& outputBlob,
   String& output,
   int& exitCode)
{
   String manifestPath = {};
   manifestPath.assign(repoRoot);
   manifestPath.append("/prodigy/discombobulator/Cargo.toml"_ctv);

   String projectRootText = {};
   projectRootText.assign(projectRoot);
   String filePathText = {};
   filePathText.assign(filePath);
   String contextRootText = {};
   contextRootText.assign(contextRoot);
   String outputBlobText = {};
   outputBlobText.assign(outputBlob);

   return runCommand(
      "/usr/bin/env"_ctv,
      &projectRoot,
      {},
      {
         "cargo",
         "run",
         "--quiet",
         "--manifest-path",
         std::string(manifestPath.c_str()),
         "--",
         "build",
         "--file",
         std::string(filePathText.c_str()),
         "--context",
         std::string("src=") + contextRootText.c_str(),
         "--output",
         std::string(outputBlobText.c_str()),
         "--kind",
         "app"
      },
      output,
      exitCode);
}

static bool handleDeployStep(
   int clientFD,
   ControlServerState& state,
   const String& expectedBlobPath,
   uint16_t expectedApplicationID,
   MachineCpuArchitecture expectedArchitecture,
   bool closeAfterInitialOkay,
   String& failure)
{
   String frame = {};
   if (recvOneMessageFrame(clientFD, frame, failure) == false)
   {
      return false;
   }

   Message *message = reinterpret_cast<Message *>(const_cast<uint8_t *>(frame.data()));
   if (MothershipTopic(message->topic) != MothershipTopic::measureApplication)
   {
      failure.assign("unexpected topic for deploy measure request"_ctv);
      return false;
   }

   state.sawMeasureApplication = true;
   uint8_t *args = message->args;
   uint8_t *serializedPlanBytes = nullptr;
   uint32_t serializedPlanSize = Message::extractArg<ArgumentNature::variable, uint32_t>(args, serializedPlanBytes);
   String serializedPlan = {};
   serializedPlan.assign(serializedPlanBytes, serializedPlanSize);
   DeploymentPlan measurePlan = {};
   if (BitseryEngine::deserializeSafe(serializedPlan, measurePlan) == false)
   {
      failure.assign("failed to deserialize measureApplication plan"_ctv);
      return false;
   }

   if (measurePlan.config.applicationID != expectedApplicationID)
   {
      failure.assign("measureApplication plan carried unexpected applicationID"_ctv);
      return false;
   }

   if (measurePlan.config.architecture != expectedArchitecture)
   {
      failure.assign("measureApplication plan carried unexpected architecture"_ctv);
      return false;
   }

   String response = {};
   Message::construct(response, MothershipTopic::measureApplication, uint32_t(1), uint32_t(0), uint32_t(1));
   if (sendAll(clientFD, response, failure) == false)
   {
      return false;
   }

   frame.clear();
   if (recvOneMessageFrame(clientFD, frame, failure) == false)
   {
      return false;
   }

   message = reinterpret_cast<Message *>(const_cast<uint8_t *>(frame.data()));
   if (MothershipTopic(message->topic) != MothershipTopic::spinApplication)
   {
      failure.assign("unexpected topic for deploy spin request"_ctv);
      return false;
   }

   state.sawSpinApplication = true;
   args = message->args;
   uint16_t applicationID = 0;
   Message::extractArg<ArgumentNature::fixed>(args, applicationID);
   state.deployApplicationID = applicationID;
   if (applicationID != expectedApplicationID)
   {
      failure.assign("spinApplication carried unexpected applicationID"_ctv);
      return false;
   }

   serializedPlanBytes = nullptr;
   serializedPlanSize = Message::extractArg<ArgumentNature::variable, uint32_t>(args, serializedPlanBytes);
   serializedPlan.clear();
   serializedPlan.assign(serializedPlanBytes, serializedPlanSize);
   DeploymentPlan spinPlan = {};
   if (BitseryEngine::deserializeSafe(serializedPlan, spinPlan) == false)
   {
      failure.assign("failed to deserialize spinApplication plan"_ctv);
      return false;
   }

   if (spinPlan.config.applicationID != expectedApplicationID)
   {
      failure.assign("spinApplication plan carried unexpected applicationID"_ctv);
      return false;
   }

   uint8_t *blobBytes = nullptr;
   uint32_t blobSize = Message::extractArg<ArgumentNature::variable, uint32_t>(args, blobBytes);

   String expectedBlob = {};
   if (readFileBytes(expectedBlobPath, expectedBlob, failure) == false)
   {
      return false;
   }

   state.deployBlobMatched = (blobSize == expectedBlob.size()
      && (blobSize == 0 || std::memcmp(blobBytes, expectedBlob.data(), blobSize) == 0));
   if (state.deployBlobMatched == false)
   {
      failure.assign("spinApplication blob did not match builder output"_ctv);
      return false;
   }

   response.clear();
   Message::construct(response, MothershipTopic::spinApplication, uint8_t(SpinApplicationResponseCode::okay));
   if (sendAll(clientFD, response, failure) == false)
   {
      return false;
   }

   if (closeAfterInitialOkay)
   {
      return true;
   }

   ::usleep(20'000);

   state.deployProgressMessage.assign("deploy smoke progress"_ctv);
   response.clear();
   Message::construct(
      response,
      MothershipTopic::spinApplication,
      uint8_t(SpinApplicationResponseCode::progress),
      state.deployProgressMessage);
   String finished = {};
   Message::construct(finished, MothershipTopic::spinApplication, uint8_t(SpinApplicationResponseCode::finished));
   response.append(finished);
   return sendAll(clientFD, response, failure);
}

int main(void)
{
   TestSuite suite = {};

   char scratch[] = "/tmp/nametag-mothership-cluster-report-XXXXXX";
   char *created = ::mkdtemp(scratch);
   suite.expect(created != nullptr, "mkdtemp_created");
   if (created == nullptr)
   {
      return EXIT_FAILURE;
   }

   String dbRoot = {};
   dbRoot.assign(created);
   ScopedEnvVar dbOverride("PRODIGY_MOTHERSHIP_TIDESDB_PATH", dbRoot);

   ScopedUnixListener listener = {};
   String setupFailure = {};
   bool listenerReady = createUnixListener(listener, setupFailure);
   suite.expect(listenerReady, "unix_listener_created");
   if (listenerReady == false)
   {
      if (setupFailure.size() > 0)
      {
         basics_log("listener setup failure: %s\n", setupFailure.c_str());
      }

      return EXIT_FAILURE;
   }

   MothershipProdigyCluster storedCluster = {};
   storedCluster.name = "cluster-report-test"_ctv;
   storedCluster.deploymentMode = MothershipClusterDeploymentMode::local;
   storedCluster.includeLocalMachine = true;
   storedCluster.controls.push_back(MothershipProdigyClusterControl{
      .kind = MothershipClusterControlKind::unixSocket,
      .path = listener.path
   });
   appendClusterMachineConfig(storedCluster, MachineConfig{
      .kind = MachineConfig::MachineKind::bareMetal,
      .slug = "report-brain"_ctv,
      .nLogicalCores = 8,
      .nMemoryMB = 16384,
      .nStorageMB = 262144
   });
   appendClusterMachineConfig(storedCluster, MachineConfig{
      .kind = MachineConfig::MachineKind::vm,
      .slug = "report-worker-spot"_ctv,
      .vmImageURI = "image://worker-spot"_ctv,
      .nLogicalCores = 16,
      .nMemoryMB = 32768,
      .nStorageMB = 524288
   });
   storedCluster.desiredEnvironment = ProdigyEnvironmentKind::dev;
   storedCluster.topology.version = 7;
   storedCluster.topology.machines.push_back(makeTopologyMachine(
      "stale-brain"_ctv,
      "fd00::7"_ctv,
      true,
      ClusterMachineSource::adopted,
      ClusterMachineBacking::owned,
      MachineLifetime::owned));
   storedCluster.lastRefreshMs = 7;
   storedCluster.lastRefreshFailure = "stale-cache"_ctv;

   {
      String failure = {};
      MothershipClusterRegistry registry;
      MothershipProdigyCluster createdCluster = {};
      bool createdOK = registry.createCluster(storedCluster, &createdCluster, &failure);
      if (createdOK == false)
      {
         basics_log("create_cluster failure: %s\n", failure.c_str());
      }
      suite.expect(createdOK, "create_cluster_record");
      if (createdOK == false)
      {
         return EXIT_FAILURE;
      }

      storedCluster = createdCluster;
   }

   ControlServerState server = {};
   std::thread serverThread([&] () {
      auto closeClient = [] (int clientFD) -> void {
         if (clientFD >= 0)
         {
            (void)::shutdown(clientFD, SHUT_RDWR);
            ::close(clientFD);
         }
      };

      String stepFailure = {};
      int clientFD = -1;
      if (acceptNextClient(listener.fd, server, clientFD) == false)
      {
         return;
      }

      if (handleClusterReportStep(clientFD, server, stepFailure) == false)
      {
         server.failure = stepFailure;
         server.stopRequested.store(true);
         closeClient(clientFD);
         return;
      }

      closeClient(clientFD);
   });

   String binaryPath = {};
   binaryPath.assign(PRODIGY_TEST_BINARY_DIR);
   if (binaryPath.size() > 0)
   {
      binaryPath.append("/mothership"_ctv);
   }

   suite.expect(binaryPath.size() > 0, "mothership_binary_path_present");
   if (binaryPath.size() == 0)
   {
      server.stopRequested.store(true);
      serverThread.join();
      return EXIT_FAILURE;
   }

   String clusterReportOutput = {};
   int clusterReportExitCode = -1;
   bool ranClusterReport = runMothershipCommand(
      binaryPath,
      dbRoot,
      {"clusterReport", "cluster-report-test"},
      clusterReportOutput,
      clusterReportExitCode);
   suite.expect(ranClusterReport, "run_cluster_report_command");
   suite.expect(clusterReportExitCode == EXIT_SUCCESS, "cluster_report_exit_success");

   server.stopRequested.store(true);
   serverThread.join();

   suite.expect(server.failure.size() == 0, "cluster_report_server_no_failure");
   suite.expect(server.acceptCount == 1, "cluster_report_server_accept_count");
   suite.expect(server.sawPullClusterReport, "cluster_report_server_saw_pull_topic");
   if (server.failure.size() > 0)
   {
      basics_log("cluster_report_server failure: %s\n", server.failure.c_str());
   }

   suite.expect(stringContains(clusterReportOutput, "hasTopology: 1"), "cluster_report_output_has_topology");
   suite.expect(stringContains(clusterReportOutput, "topologyVersion: 99"), "cluster_report_output_topology_version");
   suite.expect(stringContains(clusterReportOutput, "topologyMachines: 2"), "cluster_report_output_topology_machines");
   suite.expect(stringContains(clusterReportOutput, "nMachines: 2"), "cluster_report_output_machine_count");
   suite.expect(stringContains(clusterReportOutput, "nSpotMachines: 1"), "cluster_report_output_spot_count");
   suite.expect(stringContains(clusterReportOutput, "Machine: state=healthy role=brain publicAddresses=2001:db8::10 privateAddresses=fd00::10"), "cluster_report_output_machine_status");
   suite.expect(stringContains(clusterReportOutput, "Machine: state=healthy role=brain publicAddresses=2001:db8::10 privateAddresses=fd00::10"), "cluster_report_output_brain_role");
   suite.expect(stringContains(clusterReportOutput, "identity uuid=abc123 source=local backing=owned lifetime=owned provider= region= zone= rackUUID=0 sshAddress=fd00::10 sshPort=22"), "cluster_report_output_brain_identity");
   suite.expect(stringContains(clusterReportOutput, "lifecycle controlPlaneReachable=1 currentMaster=1 decommissioning=0 rebooting=0 updatingOS=0 hardwareFailure=0 bootTimeMs=1700000000000 uptimeMs=86400000"), "cluster_report_output_brain_lifecycle");
   suite.expect(stringContains(clusterReportOutput, "placement containers=c-brain-1,c-brain-2 applications=radar,probe deploymentIDs=101,202 shardGroups=7,9"), "cluster_report_output_brain_placement");
   suite.expect(stringContains(clusterReportOutput, "capacity active containers=2 isolatedLogicalCores=4 sharedCPUMillis=0 memoryMB=4096 storageMB=16384 reserved containers=1 isolatedLogicalCores=2 sharedCPUMillis=500 memoryMB=2048 storageMB=4096"), "cluster_report_output_brain_capacity");
   suite.expect(stringContains(clusterReportOutput, "maintenance runningProdigyVersion=123 approvedBundleSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa updateStage=waitingForBundleEchos stagedBundleSHA256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), "cluster_report_output_brain_maintenance");
   suite.expect(stringContains(clusterReportOutput, "Machine: state=hardwareFailure role=worker cloudSchema=report-worker-spot"), "cluster_report_output_worker_state");
   suite.expect(stringContains(clusterReportOutput, "Machine: state=hardwareFailure role=worker cloudSchema=report-worker-spot"), "cluster_report_output_worker_role");
   suite.expect(stringContains(clusterReportOutput, "identity uuid=def456 source=created backing=cloud lifetime=spot provider=aws region=us-east-1 zone=us-east-1c rackUUID=0 sshAddress=fd00::20 sshPort=2202"), "cluster_report_output_worker_identity");
   suite.expect(stringContains(clusterReportOutput, "lifecycle controlPlaneReachable=0 currentMaster=0 decommissioning=0 rebooting=0 updatingOS=0 hardwareFailure=1 bootTimeMs=1699999500000 uptimeMs=43210"), "cluster_report_output_worker_lifecycle");
   suite.expect(stringContains(clusterReportOutput, "placement containers=c-worker-1 applications=radar deploymentIDs=101 shardGroups=7"), "cluster_report_output_worker_placement");
   suite.expect(stringContains(clusterReportOutput, "capacity active containers=1 isolatedLogicalCores=2 sharedCPUMillis=1000 memoryMB=2048 storageMB=8192 reserved containers=0 isolatedLogicalCores=0 sharedCPUMillis=0 memoryMB=0 storageMB=0"), "cluster_report_output_worker_capacity");
   suite.expect(stringContains(clusterReportOutput, "maintenance runningProdigyVersion= approvedBundleSHA256= updateStage=idle stagedBundleSHA256="), "cluster_report_output_worker_maintenance");

   String oversizedClusterReportFailureOutput = {};
   String oversizedClusterReportServerFailure = {};

   {
      String failure = {};
      MothershipClusterRegistry registry;
      MothershipProdigyCluster refreshedCluster = {};
      bool loadedOK = registry.getCluster("cluster-report-test"_ctv, refreshedCluster, &failure);
      if (loadedOK == false)
      {
         basics_log("load_cluster failure: %s\n", failure.c_str());
      }
      suite.expect(loadedOK, "load_refreshed_cluster_record");
      if (loadedOK)
      {
         suite.expect(refreshedCluster.topology.version == 99, "refreshed_cluster_topology_version");
         suite.expect(refreshedCluster.topology.machines.size() == 2, "refreshed_cluster_topology_machine_count");
         suite.expect(refreshedCluster.topology.machines[0].addresses.privateAddresses[0].address == "fd00::10"_ctv, "refreshed_cluster_topology_first_machine");
         suite.expect(refreshedCluster.topology.machines[1].cloud.schema == "report-worker-spot"_ctv, "refreshed_cluster_topology_second_machine");
         suite.expect(refreshedCluster.lastRefreshMs > 7, "refreshed_cluster_last_refresh_ms_updated");
         suite.expect(refreshedCluster.lastRefreshFailure.size() == 0, "refreshed_cluster_last_refresh_failure_cleared");
      }
   }

   {
      ControlServerState oversizedServer = {};
      std::thread oversizedServerThread([&] () {
         auto closeClient = [] (int clientFD) -> void {
            if (clientFD >= 0)
            {
               (void)::shutdown(clientFD, SHUT_RDWR);
               ::close(clientFD);
            }
         };

         String stepFailure = {};
         int clientFD = -1;
         if (acceptNextClient(listener.fd, oversizedServer, clientFD) == false)
         {
            return;
         }

         if (handleOversizedClusterReportStep(clientFD, oversizedServer, stepFailure) == false)
         {
            oversizedServer.failure = stepFailure;
            oversizedServer.stopRequested.store(true);
            closeClient(clientFD);
            return;
         }

         closeClient(clientFD);
      });

      String oversizedClusterReportOutput = {};
      int oversizedClusterReportExitCode = -1;
      bool ranOversizedClusterReport = runMothershipCommand(
         binaryPath,
         dbRoot,
         {"clusterReport", "cluster-report-test"},
         oversizedClusterReportOutput,
         oversizedClusterReportExitCode);
      oversizedClusterReportFailureOutput = oversizedClusterReportOutput;
      suite.expect(ranOversizedClusterReport, "run_oversized_cluster_report_command");
      suite.expect(oversizedClusterReportExitCode == EXIT_FAILURE, "oversized_cluster_report_exit_failure");
      suite.expect(
         stringContains(oversizedClusterReportOutput, "framed message exceeds control-frame limit"),
         "oversized_cluster_report_reason");

      oversizedServer.stopRequested.store(true);
      oversizedServerThread.join();

      suite.expect(oversizedServer.failure.size() == 0, "oversized_cluster_report_server_no_failure");
      suite.expect(oversizedServer.acceptCount == 1, "oversized_cluster_report_server_accept_count");
      suite.expect(oversizedServer.sawPullClusterReport, "oversized_cluster_report_server_saw_pull_topic");
      oversizedClusterReportServerFailure = oversizedServer.failure;
      if (ranOversizedClusterReport == false
         || oversizedClusterReportExitCode != EXIT_FAILURE
         || stringContains(oversizedClusterReportOutput, "framed message exceeds control-frame limit") == false
         || oversizedServer.acceptCount != 1
         || oversizedServer.sawPullClusterReport == false
         || oversizedServer.failure.size() > 0)
      {
         basics_log("oversized cluster report output:\n%s\n", oversizedClusterReportOutput.c_str());
         if (oversizedServer.failure.size() > 0)
         {
            basics_log("oversized cluster report server failure:\n%s\n", oversizedServer.failure.c_str());
         }
      }
   }

   if (executableOnPath("mkfs.btrfs"))
   {
      MachineCpuArchitecture currentArchitecture = nametagCurrentBuildMachineArchitecture();
      suite.expect(
         prodigyMachineCpuArchitectureSupportedTarget(currentArchitecture),
         "deploy_smoke_current_architecture_supported");

      ScopedUnixListener deployListener = {};
      setupFailure.clear();
      bool deployListenerReady = createUnixListener(deployListener, setupFailure);
      suite.expect(deployListenerReady, "deploy_smoke_unix_listener_created");
      if (deployListenerReady == false)
      {
         if (setupFailure.size() > 0)
         {
            basics_log("deploy listener setup failure: %s\n", setupFailure.c_str());
         }

         return EXIT_FAILURE;
      }

      String repoRoot = {};
      repoRoot.assign(PRODIGY_ROOT_DIR);
      suite.expect(repoRoot.size() > 0, "deploy_smoke_repo_root_present");
      if (repoRoot.size() == 0)
      {
         return EXIT_FAILURE;
      }

      String deployProjectRoot = {};
      deployProjectRoot.assign(dbRoot);
      deployProjectRoot.append("/deploy-smoke-project"_ctv);
      std::filesystem::create_directories(std::filesystem::path(deployProjectRoot.c_str()));

      String deployContextRoot = {};
      deployContextRoot.assign(deployProjectRoot);
      deployContextRoot.append("/src"_ctv);
      std::filesystem::create_directories(std::filesystem::path(deployContextRoot.c_str()));

      String deployContextBinary = {};
      deployContextBinary.assign(deployContextRoot);
      deployContextBinary.append("/true"_ctv);
      String binaryFixtureFailure = {};
      String hostTruePath = {};
      if (::access("/bin/true", R_OK) == 0)
      {
         hostTruePath.assign("/bin/true"_ctv);
      }
      else
      {
         hostTruePath.assign("/usr/bin/true"_ctv);
      }
      bool copiedHostTrue = copyFile(hostTruePath, deployContextBinary, binaryFixtureFailure);
      suite.expect(copiedHostTrue, "deploy_smoke_host_binary_copied_into_context");
      if (copiedHostTrue == false)
      {
         basics_log("deploy smoke context binary failure: %s\n", binaryFixtureFailure.c_str());
         return EXIT_FAILURE;
      }

      const uint16_t deployApplicationID = 62011;
      String discombobulatorFile = {};
      discombobulatorFile.assign(deployProjectRoot);
      discombobulatorFile.append("/DeploySmoke.DiscombobuFile"_ctv);
      String discombobulatorFileContents = {};
      discombobulatorFileContents.append("FROM scratch for "_ctv);
      discombobulatorFileContents.append(machineCpuArchitectureName(currentArchitecture));
      discombobulatorFileContents.append("\nCOPY {src} ./true /bin/true\nSURVIVE /bin/true\nEXECUTE [\"/bin/true\"]\n"_ctv);
      String discombobulatorFileFailure = {};
      bool wroteDiscombobuFile = writeFileText(discombobulatorFile, discombobulatorFileContents, discombobulatorFileFailure);
      suite.expect(wroteDiscombobuFile, "deploy_smoke_discombobulator_file_written");
      if (wroteDiscombobuFile == false)
      {
         basics_log("deploy smoke file write failure: %s\n", discombobulatorFileFailure.c_str());
         return EXIT_FAILURE;
      }

      String deployBlobPath = {};
      deployBlobPath.assign(deployProjectRoot);
      deployBlobPath.append("/deploy-smoke-container.zst"_ctv);

      String buildOutput = {};
      int buildExitCode = -1;
      bool builtArtifact = buildDiscombobulatorArtifact(
         repoRoot,
         deployProjectRoot,
         discombobulatorFile,
         deployContextRoot,
         deployBlobPath,
         buildOutput,
         buildExitCode);
      suite.expect(builtArtifact, "deploy_smoke_runs_discombobulator_build");
      suite.expect(buildExitCode == EXIT_SUCCESS, "deploy_smoke_discombobulator_build_exit_success");
      suite.expect(fileExists(deployBlobPath), "deploy_smoke_discombobulator_blob_exists");
      if (builtArtifact == false || buildExitCode != EXIT_SUCCESS)
      {
         basics_log("deploy smoke discombobulator output:\n%s\n", buildOutput.c_str());
         return EXIT_FAILURE;
      }

      MothershipProdigyCluster deployCluster = {};
      deployCluster.name = "cluster-deploy-smoke"_ctv;
      deployCluster.deploymentMode = MothershipClusterDeploymentMode::local;
      deployCluster.includeLocalMachine = true;
      deployCluster.architecture = currentArchitecture;
      deployCluster.controls.push_back(MothershipProdigyClusterControl{
         .kind = MothershipClusterControlKind::unixSocket,
         .path = deployListener.path
      });
      appendClusterMachineConfig(deployCluster, MachineConfig{
         .kind = MachineConfig::MachineKind::bareMetal,
         .slug = "deploy-brain"_ctv,
         .nLogicalCores = 8,
         .nMemoryMB = 16384,
         .nStorageMB = 262144
      });

      {
         String failure = {};
         MothershipClusterRegistry registry;
         MothershipProdigyCluster createdCluster = {};
         bool createdOK = registry.createCluster(deployCluster, &createdCluster, &failure);
         suite.expect(createdOK, "deploy_smoke_cluster_record_created");
         if (createdOK == false)
         {
            basics_log("deploy smoke create_cluster failure: %s\n", failure.c_str());
            return EXIT_FAILURE;
         }
      }

      ControlServerState deployServer = {};
      std::thread deployServerThread([&] () {
         auto closeClient = [] (int clientFD) -> void {
            if (clientFD >= 0)
            {
               (void)::shutdown(clientFD, SHUT_RDWR);
               ::close(clientFD);
            }
         };

         String stepFailure = {};
         int clientFD = -1;
         if (acceptNextClient(deployListener.fd, deployServer, clientFD) == false)
         {
            return;
         }

         if (handleDeployStep(clientFD, deployServer, deployBlobPath, deployApplicationID, currentArchitecture, false, stepFailure) == false)
         {
            deployServer.failure = stepFailure;
            deployServer.stopRequested.store(true);
            closeClient(clientFD);
            return;
         }

         closeClient(clientFD);
      });

      String deployOutput = {};
      int deployExitCode = -1;
      String deployPlanJSON = buildDeployPlanJSON(deployApplicationID, currentArchitecture);
      bool ranDeploy = runMothershipCommand(
         binaryPath,
         dbRoot,
         {"deploy", "cluster-deploy-smoke", std::string(deployPlanJSON.c_str()), std::string(deployBlobPath.c_str())},
         deployOutput,
         deployExitCode);
      suite.expect(ranDeploy, "deploy_smoke_runs_mothership_deploy");
      suite.expect(deployExitCode == EXIT_SUCCESS, "deploy_smoke_mothership_deploy_exit_success");
      if (ranDeploy == false || deployExitCode != EXIT_SUCCESS)
      {
         basics_log("deploy smoke mothership output:\n%s\n", deployOutput.c_str());
      }

      deployServer.stopRequested.store(true);
      deployServerThread.join();

      suite.expect(deployServer.failure.size() == 0, "deploy_smoke_server_no_failure");
      suite.expect(deployServer.acceptCount == 1, "deploy_smoke_server_accept_count");
      suite.expect(deployServer.sawMeasureApplication, "deploy_smoke_server_saw_measure_topic");
      suite.expect(deployServer.sawSpinApplication, "deploy_smoke_server_saw_spin_topic");
      suite.expect(deployServer.deployApplicationID == deployApplicationID, "deploy_smoke_spin_application_id_matches");
      suite.expect(deployServer.deployBlobMatched, "deploy_smoke_spin_blob_matches_builder_output");
      if (deployServer.failure.size() > 0)
      {
         basics_log("deploy smoke server failure: %s\n", deployServer.failure.c_str());
      }

      suite.expect(
         stringContains(deployOutput, "we will schedule 1 base instances and 0 surge instances"),
         "deploy_smoke_output_reports_measure_result");
      suite.expect(
         stringContains(deployOutput, "SpinApplicationResponseCode::okay"),
         "deploy_smoke_output_reports_initial_okay");
      suite.expect(
         deployExitCode == EXIT_SUCCESS,
         "deploy_smoke_handles_progress_and_finished_when_they_share_one_read");

      ScopedUnixListener localHarnessListener = {};
      setupFailure.clear();
      bool localHarnessListenerReady = createUnixListener(localHarnessListener, setupFailure);
      suite.expect(localHarnessListenerReady, "deploy_local_test_harness_unix_listener_created");
      if (localHarnessListenerReady == false)
      {
         if (setupFailure.size() > 0)
         {
            basics_log("deploy local test harness listener setup failure: %s\n", setupFailure.c_str());
         }

         return EXIT_FAILURE;
      }

      ControlServerState localHarnessServer = {};
      std::thread localHarnessServerThread([&] () {
         auto closeClient = [] (int clientFD) -> void {
            if (clientFD >= 0)
            {
               (void)::shutdown(clientFD, SHUT_RDWR);
               ::close(clientFD);
            }
         };

         String stepFailure = {};
         int clientFD = -1;
         if (acceptNextClient(localHarnessListener.fd, localHarnessServer, clientFD) == false)
         {
            return;
         }

         if (handleDeployStep(clientFD,
                              localHarnessServer,
                              deployBlobPath,
                              deployApplicationID,
                              currentArchitecture,
                              true,
                              stepFailure) == false)
         {
            localHarnessServer.failure = stepFailure;
            localHarnessServer.stopRequested.store(true);
            closeClient(clientFD);
            return;
         }

         closeClient(clientFD);
      });

      ScopedEnvVar localHarnessSocket("PRODIGY_MOTHERSHIP_SOCKET", localHarnessListener.path);
      ScopedEnvVar localHarnessEnv("PRODIGY_MOTHERSHIP_TEST_HARNESS", "/tmp/fake-prodigy-test-harness.sh"_ctv);

      String localHarnessDeployOutput = {};
      int localHarnessDeployExitCode = -1;
      bool ranLocalHarnessDeploy = runMothershipCommand(
         binaryPath,
         dbRoot,
         {"deploy", "local", std::string(deployPlanJSON.c_str()), std::string(deployBlobPath.c_str())},
         localHarnessDeployOutput,
         localHarnessDeployExitCode);
      suite.expect(ranLocalHarnessDeploy, "deploy_local_test_harness_runs_mothership_deploy");
      suite.expect(localHarnessDeployExitCode == EXIT_SUCCESS, "deploy_local_test_harness_returns_after_initial_okay");
      if (ranLocalHarnessDeploy == false || localHarnessDeployExitCode != EXIT_SUCCESS)
      {
         basics_log("deploy local test harness mothership output:\n%s\n", localHarnessDeployOutput.c_str());
      }

      localHarnessServer.stopRequested.store(true);
      localHarnessServerThread.join();

      suite.expect(localHarnessServer.failure.size() == 0, "deploy_local_test_harness_server_no_failure");
      suite.expect(localHarnessServer.acceptCount == 1, "deploy_local_test_harness_server_accept_count");
      suite.expect(localHarnessServer.sawMeasureApplication, "deploy_local_test_harness_server_saw_measure_topic");
      suite.expect(localHarnessServer.sawSpinApplication, "deploy_local_test_harness_server_saw_spin_topic");
      suite.expect(localHarnessServer.deployApplicationID == deployApplicationID, "deploy_local_test_harness_application_id_matches");
      suite.expect(localHarnessServer.deployBlobMatched, "deploy_local_test_harness_blob_matches_builder_output");
      suite.expect(
         stringContains(localHarnessDeployOutput, "SpinApplicationResponseCode::okay"),
         "deploy_local_test_harness_output_reports_initial_okay");
   }
   else
   {
      basics_log("SKIP: deploy smoke requires mkfs.btrfs on PATH\n");
   }

   String aliasOutput = {};
   int aliasExitCode = -1;
   bool ranAlias = runMothershipCommand(
      binaryPath,
      dbRoot,
      {"allApplicationsReport", "cluster-report-test"},
      aliasOutput,
      aliasExitCode);
   suite.expect(ranAlias, "run_legacy_alias_command");
   suite.expect(aliasExitCode == EXIT_FAILURE, "legacy_alias_exit_failure");
   suite.expect(stringContains(aliasOutput, "operation invalid"), "legacy_alias_reports_invalid_operation");

   String legacyUpdateOutput = {};
   int legacyUpdateExitCode = -1;
   bool ranLegacyUpdate = runMothershipCommand(
      binaryPath,
      dbRoot,
      {"updateCluster", "cluster-report-test", "{}"},
      legacyUpdateOutput,
      legacyUpdateExitCode);
   suite.expect(ranLegacyUpdate, "run_legacy_update_cluster_command");
   suite.expect(legacyUpdateExitCode == EXIT_FAILURE, "legacy_update_cluster_exit_failure");
   suite.expect(stringContains(legacyUpdateOutput, "operation invalid"), "legacy_update_cluster_reports_invalid_operation");

   String removedHostKeyFieldWorkspaceRoot = {};
   removedHostKeyFieldWorkspaceRoot.assign(dbRoot);
   removedHostKeyFieldWorkspaceRoot.append("/removed-host-key-field-workspace"_ctv);
   std::filesystem::create_directories(std::filesystem::path(removedHostKeyFieldWorkspaceRoot.c_str()));

   String removedHostKeyFieldRequest = {};
   removedHostKeyFieldRequest.append("{\"name\":\"removed-host-key-field\",\"deploymentMode\":\"test\",\"nBrains\":1,\"bootstrapSshHostKeyPackage\":{},\"machineSchemas\":[{\"schema\":\"test-brain\",\"kind\":\"vm\",\"vmImageURI\":\"test://removed-host-key-field\"}],\"test\":{\"workspaceRoot\":\""_ctv);
   removedHostKeyFieldRequest.append(removedHostKeyFieldWorkspaceRoot);
   removedHostKeyFieldRequest.append("\",\"machineCount\":1,\"brainBootstrapFamily\":\"ipv4\",\"enableFakeIpv4Boundary\":false,\"host\":{\"mode\":\"local\"}}}"_ctv);

   String removedHostKeyFieldOutput = {};
   int removedHostKeyFieldExitCode = -1;
   bool ranRemovedHostKeyField = runMothershipCommand(
      binaryPath,
      dbRoot,
      {"createCluster", std::string(removedHostKeyFieldRequest.c_str())},
      removedHostKeyFieldOutput,
      removedHostKeyFieldExitCode);
   suite.expect(ranRemovedHostKeyField, "run_create_cluster_removed_host_key_field_command");
   suite.expect(removedHostKeyFieldExitCode == EXIT_FAILURE, "create_cluster_removed_host_key_field_exit_failure");
   suite.expect(
      stringContains(removedHostKeyFieldOutput, "createCluster.bootstrapSshHostKeyPackage has been removed"),
      "create_cluster_removed_host_key_field_reason");

   String helpOutput = {};
   int helpExitCode = -1;
   bool ranHelp = runMothershipCommand(
      binaryPath,
      dbRoot,
      {"help"},
      helpOutput,
      helpExitCode);
   suite.expect(ranHelp, "run_help_command");
   suite.expect(helpExitCode == EXIT_SUCCESS, "help_exit_success");
   suite.expect(stringContains(helpOutput, "clusterReport [target: local|clusterName|clusterUUID]"), "help_includes_cluster_report");
   suite.expect(stringContains(helpOutput, "setLocalClusterMembership [name|clusterUUID] [json]"), "help_includes_set_local_cluster_membership");
   suite.expect(stringContains(helpOutput, "setTestClusterMachineCount [name|clusterUUID] [json]"), "help_includes_set_test_cluster_machine_count");
   suite.expect(stringMissing(helpOutput, "allApplicationsReport"), "help_omits_legacy_alias");
   suite.expect(stringMissing(helpOutput, "updateCluster [name|clusterUUID] [json]"), "help_omits_update_cluster");

   if (suite.failed != 0)
   {
      writeFailureDetail("detail cluster_report_output:\n", clusterReportOutput);
      writeFailureDetail("detail cluster_report_server_failure:\n", server.failure);
      writeFailureDetail("detail oversized_cluster_report_output:\n", oversizedClusterReportFailureOutput);
      writeFailureDetail("detail oversized_cluster_report_server_failure:\n", oversizedClusterReportServerFailure);
      writeFailureDetail("detail removed_host_key_field_output:\n", removedHostKeyFieldOutput);
      return EXIT_FAILURE;
   }

   return EXIT_SUCCESS;
}
