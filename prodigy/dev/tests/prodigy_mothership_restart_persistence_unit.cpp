#include <prodigy/bundle.artifact.h>
#include <services/debug.h>
#include <prodigy/mothership/mothership.cluster.registry.h>
#include <prodigy/types.h>

#include <services/bitsery.h>
#include <services/filesystem.h>
#include <networking/message.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#ifndef PRODIGY_TEST_BINARY_DIR
#define PRODIGY_TEST_BINARY_DIR ""
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
   size_t needleLength = std::strlen(needle);
   if (needleLength == 0)
   {
      return true;
   }

   return std::search(haystack.data(),
      haystack.data() + haystack.size(),
      needle,
      needle + needleLength) != (haystack.data() + haystack.size());
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

static std::vector<std::string> extractSortedNonEmptyLines(const String& output)
{
   String text = {};
   text.assign(output);

   std::istringstream stream(text.c_str());
   std::vector<std::string> lines;
   std::string line;
   while (std::getline(stream, line))
   {
      if (line.empty())
      {
         continue;
      }

      lines.push_back(line);
   }

   std::sort(lines.begin(), lines.end());
   return lines;
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

static ClusterMachine makeTopologyMachine(const String& schema, const String& privateAddress, bool isBrain)
{
   ClusterMachine machine = {};
   machine.source = ClusterMachineSource::adopted;
   machine.backing = ClusterMachineBacking::owned;
   machine.lifetime = MachineLifetime::owned;
   machine.kind = MachineConfig::MachineKind::bareMetal;
   machine.isBrain = isBrain;
   prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, privateAddress);
   prodigyAppendUniqueClusterMachineAddress(machine.addresses.publicAddresses, privateAddress);
   machine.ssh.address = privateAddress;
   machine.ssh.port = 22;
   machine.ssh.user = "root"_ctv;
   machine.ssh.privateKeyPath = "/tmp/restart-persistence-key"_ctv;
   machine.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
   machine.totalLogicalCores = 8;
   machine.totalMemoryMB = 16384;
   machine.totalStorageMB = 131072;
   machine.ownedLogicalCores = 8;
   machine.ownedMemoryMB = 16384;
   machine.ownedStorageMB = 131072;
   return machine;
}

static bool readExact(int fd, uint8_t *buffer, size_t length)
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

      return false;
   }

   return true;
}

static bool sendAll(int fd, const String& frame)
{
   const uint8_t *buffer = frame.data();
   size_t remaining = size_t(frame.size());

   while (remaining > 0)
   {
      ssize_t rc = ::send(fd, buffer, remaining, 0);
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

      return false;
   }

   return true;
}

static bool recvOneMessageFrame(int fd, String& frame)
{
   MothershipWireHeader header = {};
   if (readExact(fd, reinterpret_cast<uint8_t *>(&header), sizeof(header)) == false)
   {
      return false;
   }

   if (header.size < sizeof(Message))
   {
      return false;
   }

   frame.clear();
   frame.append(reinterpret_cast<const uint8_t *>(&header), sizeof(header));

   uint32_t remaining = header.size - uint32_t(sizeof(header));
   if (remaining == 0)
   {
      return true;
   }

   uint8_t scratch[4096];
   while (remaining > 0)
   {
      uint32_t chunk = (remaining < sizeof(scratch)) ? remaining : uint32_t(sizeof(scratch));
      if (readExact(fd, scratch, chunk) == false)
      {
         return false;
      }

      frame.append(scratch, chunk);
      remaining -= chunk;
   }

   return true;
}

static bool bindUnixListener(const String& path, ScopedUnixListener& listener)
{
   listener.path = path;
   (void)::unlink(listener.path.c_str());

   listener.fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
   if (listener.fd < 0)
   {
      return false;
   }

   struct sockaddr_un address = {};
   address.sun_family = AF_UNIX;
   std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", listener.path.c_str());
   if (::bind(listener.fd, reinterpret_cast<struct sockaddr *>(&address), sizeof(address)) != 0)
   {
      return false;
   }

   if (::listen(listener.fd, 1) != 0)
   {
      return false;
   }

   return true;
}

static bool acceptOneClient(int listenerFD, int& clientFD, int timeoutMs = 5000)
{
   clientFD = -1;

   struct pollfd pollFD = {};
   pollFD.fd = listenerFD;
   pollFD.events = POLLIN;

   int rc = ::poll(&pollFD, 1, timeoutMs);
   if (rc <= 0 || (pollFD.revents & POLLIN) == 0)
   {
      return false;
   }

   clientFD = ::accept(listenerFD, nullptr, nullptr);
   return clientFD >= 0;
}

static bool verifyPullClusterReportRequest(const String& frame)
{
   if (frame.size() < sizeof(Message))
   {
      return false;
   }

   const Message *message = reinterpret_cast<const Message *>(frame.data());
   return MothershipTopic(message->topic) == MothershipTopic::pullClusterReport;
}

static bool sendClusterReportResponse(int fd, const ClusterStatusReport& report)
{
   ClusterStatusReport payload = report;
   String serialized = {};
   BitseryEngine::serialize(serialized, payload);

   String response = {};
   Message::construct(response, MothershipTopic::pullClusterReport, serialized);
   return sendAll(fd, response);
}

static bool runMothershipCommand(const String& mothershipBinary, const String& dbRoot, const std::vector<std::string>& arguments, String& output, int& exitCode)
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
      binaryText.assign(mothershipBinary);
      String dbRootText = {};
      dbRootText.assign(dbRoot);

      ::dup2(pipeFDs[1], STDOUT_FILENO);
      ::dup2(pipeFDs[1], STDERR_FILENO);
      ::close(pipeFDs[0]);
      ::close(pipeFDs[1]);

      ::setenv("PRODIGY_MOTHERSHIP_TIDESDB_PATH", dbRootText.c_str(), 1);

      std::vector<char *> argv;
      argv.reserve(arguments.size() + 2);
      argv.push_back(const_cast<char *>(binaryText.c_str()));
      for (const std::string& argument : arguments)
      {
         argv.push_back(const_cast<char *>(argument.c_str()));
      }
      argv.push_back(nullptr);

      ::execv(binaryText.c_str(), argv.data());
      std::perror("execl");
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

static bool runMothershipPrintClusters(const String& mothershipBinary, const String& dbRoot, String& output, int& exitCode)
{
   return runMothershipCommand(mothershipBinary, dbRoot, {"printClusters"}, output, exitCode);
}

static bool runMothershipClusterReport(const String& mothershipBinary, const String& dbRoot, const char *target, const String& controlPath, const ClusterStatusReport& report, String& output, int& exitCode, String& serverFailure)
{
   output.clear();
   exitCode = -1;
   serverFailure.clear();

   ScopedUnixListener listener = {};
   if (bindUnixListener(controlPath, listener) == false)
   {
      serverFailure.assign("bind_unix_listener_failed"_ctv);
      return false;
   }

   int pipeFDs[2] = {-1, -1};
   if (::pipe(pipeFDs) != 0)
   {
      serverFailure.assign("pipe_failed"_ctv);
      return false;
   }

   pid_t pid = ::fork();
   if (pid < 0)
   {
      ::close(pipeFDs[0]);
      ::close(pipeFDs[1]);
      serverFailure.assign("fork_failed"_ctv);
      return false;
   }

   if (pid == 0)
   {
      String binaryText = {};
      binaryText.assign(mothershipBinary);
      String dbRootText = {};
      dbRootText.assign(dbRoot);

      ::dup2(pipeFDs[1], STDOUT_FILENO);
      ::dup2(pipeFDs[1], STDERR_FILENO);
      ::close(pipeFDs[0]);
      ::close(pipeFDs[1]);
      if (listener.fd >= 0)
      {
         ::close(listener.fd);
      }

      ::setenv("PRODIGY_MOTHERSHIP_TIDESDB_PATH", dbRootText.c_str(), 1);
      ::execl(binaryText.c_str(), binaryText.c_str(), "clusterReport", target, nullptr);
      std::perror("execl");
      _exit(127);
   }

   ::close(pipeFDs[1]);

   int clientFD = -1;
   if (acceptOneClient(listener.fd, clientFD) == false)
   {
      serverFailure.assign("accept_cluster_report_client_failed"_ctv);
   }
   else
   {
      String frame = {};
      if (recvOneMessageFrame(clientFD, frame) == false)
      {
         serverFailure.assign("recv_cluster_report_request_failed"_ctv);
      }
      else if (verifyPullClusterReportRequest(frame) == false)
      {
         serverFailure.assign("unexpected_cluster_report_request_topic"_ctv);
      }
      else if (sendClusterReportResponse(clientFD, report) == false)
      {
         serverFailure.assign("send_cluster_report_response_failed"_ctv);
      }
   }

   if (clientFD >= 0)
   {
      ::close(clientFD);
   }

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

static void renderUUIDHex(uint128_t clusterUUID, String& text)
{
   text.clear();
   text.assignItoh(clusterUUID);
}

static bool writeFileText(const String& path, const String& text)
{
   String pathText = {};
   pathText.assign(path);
   FILE *file = std::fopen(pathText.c_str(), "wb");
   if (file == nullptr)
   {
      return false;
   }

   bool ok = std::fwrite(text.data(), 1, size_t(text.size()), file) == size_t(text.size());
   ok = ok && (std::fclose(file) == 0);
   return ok;
}

static void cleanupPersistentStateRoots(const String& dbRoot)
{
   std::filesystem::remove_all(std::filesystem::path(std::string(reinterpret_cast<const char *>(dbRoot.data()), dbRoot.size())));

   String secretsPath = {};
   secretsPath.assign(dbRoot);
   secretsPath.append(".secrets"_ctv);
    std::filesystem::remove_all(std::filesystem::path(std::string(reinterpret_cast<const char *>(secretsPath.data()), secretsPath.size())));
}

int main(void)
{
   TestSuite suite = {};

   char scratch[] = "/tmp/nametag-mothership-restart-persistence-XXXXXX";
   char *created = ::mkdtemp(scratch);
   suite.expect(created != nullptr, "mkdtemp_created");
   if (created == nullptr)
   {
      return EXIT_FAILURE;
   }

   String dbRoot = {};
   dbRoot.assign(created);
   ScopedEnvVar dbOverride("PRODIGY_MOTHERSHIP_TIDESDB_PATH", dbRoot);

   String testWorkspaceRoot = {};
   testWorkspaceRoot.assign(dbRoot);
   testWorkspaceRoot.append("/test-workspace"_ctv);
   std::filesystem::create_directories(std::filesystem::path(testWorkspaceRoot.c_str()));

   String localControlSocketPath = {};
   localControlSocketPath.assign(dbRoot);
   localControlSocketPath.append("/restart-local.sock"_ctv);

   MothershipProdigyCluster localCluster = {};
   localCluster.name = "restart-local"_ctv;
   localCluster.deploymentMode = MothershipClusterDeploymentMode::local;
   localCluster.controls.push_back(MothershipProdigyClusterControl{
      .kind = MothershipClusterControlKind::unixSocket,
      .path = localControlSocketPath
   });
   appendClusterMachineConfig(localCluster, MachineConfig{
      .kind = MachineConfig::MachineKind::bareMetal,
      .slug = "restart-local-brain"_ctv,
      .nLogicalCores = 8,
      .nMemoryMB = 16384,
      .nStorageMB = 131072
   });
   localCluster.desiredEnvironment = ProdigyEnvironmentKind::dev;
   localCluster.topology.version = 5;
   localCluster.topology.machines.push_back(makeTopologyMachine("cached-local-brain"_ctv, "fd00::5"_ctv, true));
   localCluster.lastRefreshMs = 42;
   localCluster.lastRefreshFailure = "cached-local"_ctv;

   MothershipProdigyCluster testCluster = {};
   testCluster.name = "restart-test"_ctv;
   testCluster.deploymentMode = MothershipClusterDeploymentMode::test;
   testCluster.nBrains = 3;
   appendClusterMachineConfig(testCluster, MachineConfig{
      .kind = MachineConfig::MachineKind::vm,
      .slug = "restart-test-brain"_ctv,
      .vmImageURI = "test://restart-proof"_ctv,
      .nLogicalCores = 4,
      .nMemoryMB = 8192,
      .nStorageMB = 65536
   });
   testCluster.test.specified = true;
   testCluster.test.workspaceRoot = testWorkspaceRoot;
   testCluster.test.machineCount = 3;
   testCluster.test.host.mode = MothershipClusterTestHostMode::local;
   testCluster.test.brainBootstrapFamily = MothershipClusterTestBootstrapFamily::ipv4;
   testCluster.desiredEnvironment = ProdigyEnvironmentKind::dev;
   testCluster.lastRefreshMs = 77;
   testCluster.lastRefreshFailure = "cached-test"_ctv;

   MothershipProdigyCluster storedLocal = {};
   MothershipProdigyCluster storedTest = {};
   {
      String failure = {};
      MothershipClusterRegistry registry;
      bool createdLocal = registry.createCluster(localCluster, &storedLocal, &failure);
      if (!createdLocal) basics_log("detail create_local_cluster: %s\n", failure.c_str());
      suite.expect(createdLocal, "create_local_cluster");

      bool createdTest = registry.createCluster(testCluster, &storedTest, &failure);
      if (!createdTest) basics_log("detail create_test_cluster: %s\n", failure.c_str());
      suite.expect(createdTest, "create_test_cluster");

      Vector<MothershipProdigyCluster> seededClusters;
      bool listedSeeded = registry.listClusters(seededClusters, &failure);
      if (!listedSeeded) basics_log("detail list_seeded_clusters: %s\n", failure.c_str());
      suite.expect(listedSeeded, "list_seeded_clusters");
      suite.expect(seededClusters.size() == 2, "list_seeded_clusters_count");
   }

   String mothershipBinary = PRODIGY_TEST_BINARY_DIR "/mothership";
   int firstExitCode = -1;
   String firstOutput = {};
   bool firstRan = runMothershipPrintClusters(mothershipBinary, dbRoot, firstOutput, firstExitCode);
   suite.expect(firstRan, "run_print_clusters_first");
   suite.expect(firstExitCode == 0, "run_print_clusters_first_exit_code");

   int secondExitCode = -1;
   String secondOutput = {};
   bool secondRan = runMothershipPrintClusters(mothershipBinary, dbRoot, secondOutput, secondExitCode);
   suite.expect(secondRan, "run_print_clusters_second");
   suite.expect(secondExitCode == 0, "run_print_clusters_second_exit_code");

   if (firstRan == false || secondRan == false)
   {
      cleanupPersistentStateRoots(dbRoot);
      return EXIT_FAILURE;
   }

   auto firstLines = extractSortedNonEmptyLines(firstOutput);
   auto secondLines = extractSortedNonEmptyLines(secondOutput);
   suite.expect(firstLines == secondLines, "print_clusters_output_stable_across_process_restart");

   suite.expect(stringContains(firstOutput, "printClusters success=1 count=2"), "first_print_clusters_count");
   suite.expect(stringContains(secondOutput, "printClusters success=1 count=2"), "second_print_clusters_count");

   String localUUIDHex = {};
   renderUUIDHex(storedLocal.clusterUUID, localUUIDHex);
   String testUUIDHex = {};
   renderUUIDHex(storedTest.clusterUUID, testUUIDHex);

   suite.expect(stringContains(firstOutput, "name=restart-local"), "first_output_contains_local_name");
   suite.expect(stringContains(firstOutput, localUUIDHex.c_str()), "first_output_contains_local_uuid");
   suite.expect(stringContains(firstOutput, "lastRefreshFailure=cached-local"), "first_output_contains_local_refresh_failure");
   String controlPathNeedle = {};
   controlPathNeedle.snprintf<"control kind=unixSocket path={}"_ctv>(localControlSocketPath);
   suite.expect(stringContains(firstOutput, controlPathNeedle.c_str()), "first_output_contains_local_control_path");

   suite.expect(stringContains(firstOutput, "name=restart-test"), "first_output_contains_test_name");
   suite.expect(stringContains(firstOutput, testUUIDHex.c_str()), "first_output_contains_test_uuid");
   suite.expect(stringContains(firstOutput, "lastRefreshFailure=cached-test"), "first_output_contains_test_refresh_failure");

   String workspaceNeedle = {};
   workspaceNeedle.snprintf<"workspaceRoot={}"_ctv>(storedTest.test.workspaceRoot);
   suite.expect(stringContains(firstOutput, workspaceNeedle.c_str()), "first_output_contains_test_workspace");
   suite.expect(stringContains(firstOutput, "test hostMode=local"), "first_output_contains_test_host_mode");

   suite.expect(stringContains(secondOutput, "name=restart-local"), "second_output_contains_local_name");
   suite.expect(stringContains(secondOutput, localUUIDHex.c_str()), "second_output_contains_local_uuid");
   suite.expect(stringContains(secondOutput, "name=restart-test"), "second_output_contains_test_name");
   suite.expect(stringContains(secondOutput, testUUIDHex.c_str()), "second_output_contains_test_uuid");

   MachineCpuArchitecture currentArchitecture = nametagCurrentBuildMachineArchitecture();
   String bundleSourcePath = PRODIGY_TEST_BINARY_DIR;
   if (bundleSourcePath.size() > 0 && bundleSourcePath[bundleSourcePath.size() - 1] != '/')
   {
      bundleSourcePath.append('/');
   }
   bundleSourcePath.append(prodigyBundleFilename(currentArchitecture));
   String bundleSourceSHA256Path = {};
   prodigyResolveBundleSHA256Path(bundleSourcePath, bundleSourceSHA256Path);

   String bundleTestHome = {};
   bundleTestHome.assign(dbRoot);
   bundleTestHome.append("/bundle-home"_ctv);
   String bundleTestHomeText = {};
   bundleTestHomeText.assign(bundleTestHome);
   std::filesystem::create_directories(std::filesystem::path(bundleTestHomeText.c_str()));
   String bundleInstallHome = {};
   bundleInstallHome.assign(bundleTestHome);
   bundleInstallHome.append("/.local/share/prodigy"_ctv);
   String bundleInstallHomeText = {};
   bundleInstallHomeText.assign(bundleInstallHome);
   std::filesystem::create_directories(std::filesystem::path(bundleInstallHomeText.c_str()));

   String fallbackBundleInputPath = {};
   fallbackBundleInputPath.assign(bundleTestHome);
   fallbackBundleInputPath.append("/update-prodigy-input"_ctv);
   suite.expect(writeFileText(fallbackBundleInputPath, "#!/bin/sh\nexit 0\n"_ctv), "write_update_prodigy_fallback_input");

   String installedBundlePath = {};
   prodigyResolveBundlePathForDirectory(bundleInstallHome, currentArchitecture, installedBundlePath);
   String installedBundleSHA256Path = {};
   prodigyResolveBundleSHA256Path(installedBundlePath, installedBundleSHA256Path);

   {
      ScopedEnvVar homeOverride("HOME", bundleTestHome);
      ScopedEnvVar xdgOverride("XDG_DATA_HOME", ""_ctv);

      String missingBundleOutput = {};
      int missingBundleExitCode = -1;
      bool ranMissingBundle = runMothershipCommand(
         mothershipBinary,
         dbRoot,
         {"updateProdigy", "local", std::string(fallbackBundleInputPath.c_str())},
         missingBundleOutput,
         missingBundleExitCode);
      suite.expect(ranMissingBundle, "run_update_prodigy_missing_bundle");
      suite.expect(missingBundleExitCode == EXIT_FAILURE, "update_prodigy_missing_bundle_exit_failure");
      suite.expect(stringContains(missingBundleOutput, "updateProdigy failed to resolve bundle"), "update_prodigy_missing_bundle_reports_resolution_failure");
      suite.expect(stringContains(missingBundleOutput, "installed prodigy bundle artifact is not readable"), "update_prodigy_missing_bundle_reports_missing_bundle");
   }

   std::filesystem::copy_file(
      std::filesystem::path(bundleSourcePath.c_str()),
      std::filesystem::path(installedBundlePath.c_str()),
      std::filesystem::copy_options::overwrite_existing);

   {
      ScopedEnvVar homeOverride("HOME", bundleTestHome);
      ScopedEnvVar xdgOverride("XDG_DATA_HOME", ""_ctv);

      String missingSHAOutput = {};
      int missingSHAExitCode = -1;
      bool ranMissingSHA = runMothershipCommand(
         mothershipBinary,
         dbRoot,
         {"updateProdigy", "local", std::string(fallbackBundleInputPath.c_str())},
         missingSHAOutput,
         missingSHAExitCode);
      suite.expect(ranMissingSHA, "run_update_prodigy_missing_sha256_sidecar");
      suite.expect(missingSHAExitCode == EXIT_FAILURE, "update_prodigy_missing_sha256_sidecar_exit_failure");
      suite.expect(stringContains(missingSHAOutput, "updateProdigy rejected bundle"), "update_prodigy_missing_sha256_sidecar_reports_rejection");
      suite.expect(stringContains(missingSHAOutput, "bundle sha256 sidecar is not readable"), "update_prodigy_missing_sha256_sidecar_reason");
   }

   String correctBundleDigest = {};
   String bundleDigestFailure = {};
   suite.expect(prodigyComputeFileSHA256Hex(bundleSourcePath, correctBundleDigest, &bundleDigestFailure), "compute_update_prodigy_test_bundle_sha256");
   suite.expect(bundleDigestFailure.size() == 0, "compute_update_prodigy_test_bundle_sha256_clears_failure");

   String mismatchedDigest = correctBundleDigest;
   mismatchedDigest[0] = mismatchedDigest[0] == '0' ? '1' : '0';
   suite.expect(writeFileText(installedBundleSHA256Path, mismatchedDigest), "write_update_prodigy_mismatched_sha256_sidecar");

   {
      ScopedEnvVar homeOverride("HOME", bundleTestHome);
      ScopedEnvVar xdgOverride("XDG_DATA_HOME", ""_ctv);

      String mismatchOutput = {};
      int mismatchExitCode = -1;
      bool ranMismatch = runMothershipCommand(
         mothershipBinary,
         dbRoot,
         {"updateProdigy", "local", std::string(fallbackBundleInputPath.c_str())},
         mismatchOutput,
         mismatchExitCode);
      suite.expect(ranMismatch, "run_update_prodigy_mismatched_sha256_sidecar");
      suite.expect(mismatchExitCode == EXIT_FAILURE, "update_prodigy_mismatched_sha256_sidecar_exit_failure");
      suite.expect(stringContains(mismatchOutput, "updateProdigy rejected bundle"), "update_prodigy_mismatched_sha256_sidecar_reports_rejection");
      suite.expect(stringContains(mismatchOutput, "bundle sha256 mismatch"), "update_prodigy_mismatched_sha256_sidecar_reason");
   }

   std::filesystem::copy_file(
      std::filesystem::path(bundleSourceSHA256Path.c_str()),
      std::filesystem::path(installedBundleSHA256Path.c_str()),
      std::filesystem::copy_options::overwrite_existing);

   String legacyUpdateOutput = {};
   int legacyUpdateExitCode = -1;
   bool ranLegacyUpdate = runMothershipCommand(
      mothershipBinary,
      dbRoot,
      {"updateCluster", "restart-local", "{}"},
      legacyUpdateOutput,
      legacyUpdateExitCode);
   suite.expect(ranLegacyUpdate, "run_legacy_update_cluster_command");
   suite.expect(legacyUpdateExitCode == EXIT_FAILURE, "legacy_update_cluster_exit_failure");
   suite.expect(stringContains(legacyUpdateOutput, "operation invalid"), "legacy_update_cluster_reports_invalid_operation");

   String wrongModeLocalOutput = {};
   int wrongModeLocalExitCode = -1;
   bool ranWrongModeLocal = runMothershipCommand(
      mothershipBinary,
      dbRoot,
      {"setLocalClusterMembership", "restart-test", "{\"includeLocalMachine\":true,\"machines\":[]}"},
      wrongModeLocalOutput,
      wrongModeLocalExitCode);
   suite.expect(ranWrongModeLocal, "run_set_local_cluster_membership_wrong_mode");
   suite.expect(wrongModeLocalExitCode == EXIT_FAILURE, "set_local_cluster_membership_wrong_mode_exit_failure");
   suite.expect(stringContains(wrongModeLocalOutput, "setLocalClusterMembership requires deploymentMode=local"), "set_local_cluster_membership_wrong_mode_reason");

   String missingMachinesOutput = {};
   int missingMachinesExitCode = -1;
   bool ranMissingMachines = runMothershipCommand(
      mothershipBinary,
      dbRoot,
      {"setLocalClusterMembership", "restart-local", "{\"includeLocalMachine\":true}"},
      missingMachinesOutput,
      missingMachinesExitCode);
   suite.expect(ranMissingMachines, "run_set_local_cluster_membership_missing_machines");
   suite.expect(missingMachinesExitCode == EXIT_FAILURE, "set_local_cluster_membership_missing_machines_exit_failure");
   suite.expect(stringContains(missingMachinesOutput, "setLocalClusterMembership.machines required"), "set_local_cluster_membership_missing_machines_reason");

   String wrongModeTestOutput = {};
   int wrongModeTestExitCode = -1;
   bool ranWrongModeTest = runMothershipCommand(
      mothershipBinary,
      dbRoot,
      {"setTestClusterMachineCount", "restart-local", "{\"machineCount\":4}"},
      wrongModeTestOutput,
      wrongModeTestExitCode);
   suite.expect(ranWrongModeTest, "run_set_test_cluster_machine_count_wrong_mode");
   suite.expect(wrongModeTestExitCode == EXIT_FAILURE, "set_test_cluster_machine_count_wrong_mode_exit_failure");
   suite.expect(stringContains(wrongModeTestOutput, "setTestClusterMachineCount requires deploymentMode=test"), "set_test_cluster_machine_count_wrong_mode_reason");

   String missingMachineCountOutput = {};
   int missingMachineCountExitCode = -1;
   bool ranMissingMachineCount = runMothershipCommand(
      mothershipBinary,
      dbRoot,
      {"setTestClusterMachineCount", "restart-test", "{}"},
      missingMachineCountOutput,
      missingMachineCountExitCode);
   suite.expect(ranMissingMachineCount, "run_set_test_cluster_machine_count_missing_machine_count");
   suite.expect(missingMachineCountExitCode == EXIT_FAILURE, "set_test_cluster_machine_count_missing_machine_count_exit_failure");
   suite.expect(stringContains(missingMachineCountOutput, "setTestClusterMachineCount.machineCount required"), "set_test_cluster_machine_count_missing_machine_count_reason");

   ClusterStatusReport liveClusterReport = {};
   liveClusterReport.hasTopology = true;
   liveClusterReport.topology.version = 44;
   ClusterMachine reportedMachine = {};
   reportedMachine.source = ClusterMachineSource::adopted;
   reportedMachine.backing = ClusterMachineBacking::owned;
   reportedMachine.lifetime = MachineLifetime::owned;
   reportedMachine.kind = MachineConfig::MachineKind::bareMetal;
   reportedMachine.isBrain = true;
   reportedMachine.ssh.address = "fd00::10"_ctv;
   reportedMachine.ssh.user = "root"_ctv;
   reportedMachine.ssh.privateKeyPath = "/tmp/restart-local-key"_ctv;
   prodigyAppendUniqueClusterMachineAddress(reportedMachine.addresses.privateAddresses, "fd00::10"_ctv);
   reportedMachine.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
   reportedMachine.totalLogicalCores = 8;
   reportedMachine.totalMemoryMB = 16384;
   reportedMachine.totalStorageMB = 131072;
   reportedMachine.ownedLogicalCores = 8;
   reportedMachine.ownedMemoryMB = 16384;
   reportedMachine.ownedStorageMB = 131072;
   liveClusterReport.topology.machines.push_back(reportedMachine);
   liveClusterReport.nMachines = 1;
   liveClusterReport.nSpotMachines = 0;
   liveClusterReport.nApplications = 1;
   MachineStatusReport machineReport = {};
   machineReport.state = "healthy"_ctv;
   machineReport.isBrain = true;
   prodigyAppendUniqueClusterMachineAddress(machineReport.addresses.privateAddresses, "fd00::10"_ctv);
   machineReport.totalLogicalCores = 8;
   machineReport.totalMemoryMB = 16384;
   machineReport.totalStorageMB = 131072;
   machineReport.ownedLogicalCores = 8;
   machineReport.ownedMemoryMB = 16384;
   machineReport.ownedStorageMB = 131072;
   liveClusterReport.machineReports.push_back(machineReport);

   String clusterReportOutput = {};
   int clusterReportExitCode = -1;
   String clusterReportServerFailure = {};
   bool clusterReportRan = runMothershipClusterReport(
      mothershipBinary,
      dbRoot,
      "restart-local",
      localControlSocketPath,
      liveClusterReport,
      clusterReportOutput,
      clusterReportExitCode,
      clusterReportServerFailure);
   suite.expect(clusterReportRan, "run_cluster_report_live_status");
   suite.expect(clusterReportServerFailure.size() == 0, "run_cluster_report_live_status_server_failure_empty");
   suite.expect(clusterReportExitCode == 0, "run_cluster_report_live_status_exit_code");
   suite.expect(stringContains(clusterReportOutput, "nMachines: 1"), "cluster_report_output_machine_count");
   suite.expect(stringContains(clusterReportOutput, "nApplications: 1"), "cluster_report_output_application_count");
   suite.expect(stringContains(clusterReportOutput, "Machine: state=healthy role=brain"), "cluster_report_output_machine_state");

   MothershipProdigyCluster refreshedLocalAfterSuccess = {};
   {
      String failure = {};
      MothershipClusterRegistry registry;
      bool loaded = registry.getCluster("restart-local"_ctv, refreshedLocalAfterSuccess, &failure);
      if (!loaded) basics_log("detail load_cluster_after_cluster_report_success: %s\n", failure.c_str());
      suite.expect(loaded, "load_cluster_after_cluster_report_success");
   }
   suite.expect(refreshedLocalAfterSuccess.lastRefreshMs > storedLocal.lastRefreshMs, "cluster_report_success_updates_last_refresh_ms");
   suite.expect(refreshedLocalAfterSuccess.lastRefreshFailure.size() == 0, "cluster_report_success_clears_last_refresh_failure");
   suite.expect(refreshedLocalAfterSuccess.topology.version == liveClusterReport.topology.version, "cluster_report_success_persists_topology_version");
   suite.expect(refreshedLocalAfterSuccess.topology.machines.size() == liveClusterReport.topology.machines.size(), "cluster_report_success_persists_topology_machine_count");
   if (refreshedLocalAfterSuccess.topology.machines.empty() == false)
   {
      suite.expect(refreshedLocalAfterSuccess.topology.machines[0].addresses.privateAddresses.size() == 1 && refreshedLocalAfterSuccess.topology.machines[0].addresses.privateAddresses[0].address == "fd00::10"_ctv, "cluster_report_success_persists_topology_machine_identity");
   }

   ::usleep(2'000);

   String failedClusterReportOutput = {};
   int failedClusterReportExitCode = -1;
   bool failedClusterReportRan = runMothershipCommand(
      mothershipBinary,
      dbRoot,
      {"clusterReport", "restart-local"},
      failedClusterReportOutput,
      failedClusterReportExitCode);
   suite.expect(failedClusterReportRan, "run_cluster_report_failure_path");
   suite.expect(failedClusterReportExitCode != 0, "run_cluster_report_failure_path_exit_code");
   suite.expect(stringContains(failedClusterReportOutput, "clusterReport failed"), "cluster_report_failure_path_output");

   MothershipProdigyCluster refreshedLocalAfterFailure = {};
   {
      String failure = {};
      MothershipClusterRegistry registry;
      bool loaded = registry.getCluster("restart-local"_ctv, refreshedLocalAfterFailure, &failure);
      if (!loaded) basics_log("detail load_cluster_after_cluster_report_failure: %s\n", failure.c_str());
      suite.expect(loaded, "load_cluster_after_cluster_report_failure");
   }
   suite.expect(refreshedLocalAfterFailure.lastRefreshMs > refreshedLocalAfterSuccess.lastRefreshMs, "cluster_report_failure_updates_last_refresh_ms");
   suite.expect(refreshedLocalAfterFailure.lastRefreshFailure.size() > 0, "cluster_report_failure_persists_last_refresh_failure");

   cleanupPersistentStateRoots(dbRoot);

   if (suite.failed != 0)
   {
      String firstText = {};
      firstText.assign(firstOutput);
      String secondText = {};
      secondText.assign(secondOutput);
      String clusterReportText = {};
      clusterReportText.assign(clusterReportOutput);
      String failedClusterReportText = {};
      failedClusterReportText.assign(failedClusterReportOutput);
      String serverFailureText = {};
      serverFailureText.assign(clusterReportServerFailure);
      writeFailureDetail("detail first_output:\n", firstText);
      writeFailureDetail("detail second_output:\n", secondText);
      writeFailureDetail("detail cluster_report_output:\n", clusterReportText);
      writeFailureDetail("detail cluster_report_failure_output:\n", failedClusterReportText);
      writeFailureDetail("detail cluster_report_server_failure:\n", serverFailureText);
      return EXIT_FAILURE;
   }

   basics_log("mothership_restart_persistence_unit ok\n");
   return EXIT_SUCCESS;
}
