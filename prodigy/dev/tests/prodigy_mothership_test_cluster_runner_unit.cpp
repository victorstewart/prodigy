#include <cstdio>
#include <services/debug.h>
#include <cstdlib>
#include <cstring>
#include <algorithm>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define main nametag_mothership_main_disabled
#include <prodigy/mothership/mothership.cpp>
#undef main

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
         failed += 1;
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

static bool writeExecutableFile(const String& path, const char *contents)
{
   String pathText = path;
   int fd = ::open(pathText.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0700);
   if (fd < 0)
   {
      return false;
   }

   size_t remaining = std::strlen(contents);
   const char *cursor = contents;
   while (remaining > 0)
   {
      ssize_t written = ::write(fd, cursor, remaining);
      if (written < 0)
      {
         if (errno == EINTR)
         {
            continue;
         }

         ::close(fd);
         return false;
      }

      cursor += written;
      remaining -= size_t(written);
   }

   if (::close(fd) != 0)
   {
      return false;
   }

   return ::chmod(pathText.c_str(), 0700) == 0;
}

static bool ensureDirectory(const String& path)
{
   String pathText = path;
   std::error_code error;
   return std::filesystem::create_directories(pathText.c_str(), error) || std::filesystem::exists(pathText.c_str());
}

int main(void)
{
   TestSuite suite;

   char scratch[] = "/tmp/nametag-mothership-test-runner-XXXXXX";
   char *created = ::mkdtemp(scratch);
   suite.expect(created != nullptr, "mkdtemp_created");
   if (created == nullptr)
   {
      return EXIT_FAILURE;
   }

   String scratchRoot = {};
   scratchRoot.assign(created);

   String workspaceRoot = {};
   workspaceRoot.snprintf<"{}/cluster"_ctv>(scratchRoot);

   String harnessPath = {};
   harnessPath.snprintf<"{}/fake_harness.sh"_ctv>(scratchRoot);
   suite.expect(writeExecutableFile(harnessPath,
      "#!/usr/bin/env bash\n"
      "set -euo pipefail\n"
      "prodigy_bin=\"$1\"\n"
      "shift\n"
      "workspace_root=\"\"\n"
      "manifest_path=\"\"\n"
      "for arg in \"$@\"; do\n"
      "   case \"$arg\" in\n"
      "      --workspace-root=*) workspace_root=\"${arg#*=}\" ;;\n"
      "      --manifest-path=*) manifest_path=\"${arg#*=}\" ;;\n"
      "   esac\n"
      "done\n"
      "mkdir -p \"$workspace_root\"\n"
      ": > \"$workspace_root/prodigy-mothership.sock\"\n"
      "printf '{\"ready\":true}\\n' > \"$manifest_path\"\n"
      "trap 'exit 0' TERM INT\n"
      "while :; do sleep 1; done\n"),
      "write_fake_harness");

   String prodigyPath = {};
   prodigyPath.snprintf<"{}/fake_prodigy.sh"_ctv>(scratchRoot);
   suite.expect(writeExecutableFile(prodigyPath,
      "#!/usr/bin/env bash\n"
      "exit 0\n"),
      "write_fake_prodigy");

   String spacedRoot = {};
   spacedRoot.snprintf<"{}/space dir"_ctv>(scratchRoot);
   suite.expect(ensureDirectory(spacedRoot), "create_spaced_root");
   String spacedWorkspaceRoot = {};
   spacedWorkspaceRoot.snprintf<"{}/cluster workspace"_ctv>(spacedRoot);
   String spacedHarnessPath = {};
   spacedHarnessPath.snprintf<"{}/fake harness.sh"_ctv>(spacedRoot);
   suite.expect(writeExecutableFile(spacedHarnessPath,
      "#!/usr/bin/env bash\n"
      "set -euo pipefail\n"
      "prodigy_bin=\"$1\"\n"
      "shift\n"
      "workspace_root=\"\"\n"
      "manifest_path=\"\"\n"
      "for arg in \"$@\"; do\n"
      "   case \"$arg\" in\n"
      "      --workspace-root=*) workspace_root=\"${arg#*=}\" ;;\n"
      "      --manifest-path=*) manifest_path=\"${arg#*=}\" ;;\n"
      "   esac\n"
      "done\n"
      "mkdir -p \"$workspace_root\"\n"
      ": > \"$workspace_root/prodigy-mothership.sock\"\n"
      "printf '{\"ready\":true}\\n' > \"$manifest_path\"\n"
      "trap 'exit 0' TERM INT\n"
      "while :; do sleep 1; done\n"),
      "write_spaced_fake_harness");
   String spacedProdigyPath = {};
   spacedProdigyPath.snprintf<"{}/fake prodigy.sh"_ctv>(spacedRoot);
   suite.expect(writeExecutableFile(spacedProdigyPath,
      "#!/usr/bin/env bash\n"
      "exit 0\n"),
      "write_spaced_fake_prodigy");

   MothershipProdigyCluster cluster = {};
   cluster.name = "runner-test"_ctv;
   cluster.deploymentMode = MothershipClusterDeploymentMode::test;
   cluster.nBrains = 2;
   cluster.test.specified = true;
   cluster.test.host.mode = MothershipClusterTestHostMode::local;
   cluster.test.workspaceRoot = workspaceRoot;
   cluster.test.machineCount = 3;
   cluster.test.brainBootstrapFamily = MothershipClusterTestBootstrapFamily::private6;
   cluster.test.enableFakeIpv4Boundary = false;
   cluster.test.interContainerMTU = 9000;
   mothershipResolveTestClusterControlRecord(cluster.controls, cluster);

   String startCommand = {};
   mothershipBuildPersistentTestClusterStartCommand(harnessPath, prodigyPath, cluster, startCommand);
   suite.expect(startCommand.size() > 0, "build_start_command_nonempty");
   suite.expect(stringContains(startCommand, "setsid nohup env PRODIGY_DEV_KEEP_TMP=1 bash -lc"), "build_start_command_detaches_session");
   suite.expect(stringContains(startCommand, "PRODIGY_DEV_KEEP_TMP=1"), "build_start_command_preserves_workspace_on_failure");
   suite.expect(stringContains(startCommand, "--runner-mode=persistent"), "build_start_command_runner_mode");
   suite.expect(stringContains(startCommand, "--machines=3"), "build_start_command_machine_count");
   suite.expect(stringContains(startCommand, "--brains=2"), "build_start_command_brain_count");
   suite.expect(stringContains(startCommand, "--brain-bootstrap-family=private6"), "build_start_command_bootstrap_family");
   suite.expect(stringContains(startCommand, "--inter-container-mtu=9000"), "build_start_command_inter_container_mtu");

   String failure = {};
   bool started = prodigyRunLocalShellCommand(startCommand, &failure);
   if (started == false)
   {
      basics_log("detail start_failure=%s\n", failure.c_str());
   }
   suite.expect(started, "run_start_command");

   bool ready = mothershipWaitForLocalTestClusterReady(cluster, &failure, 5'000);
   if (ready == false)
   {
      basics_log("detail ready_failure=%s\n", failure.c_str());
   }
   suite.expect(ready, "wait_local_runner_ready");

   String manifestPath = {};
   mothershipResolveTestClusterManifestPath(cluster, manifestPath);
   String controlSocketPath = {};
   mothershipResolveTestClusterControlSocketPath(cluster, controlSocketPath);
   String pidPath = {};
   mothershipResolveTestClusterRunnerPIDPath(cluster, pidPath);
   String logPath = {};
   mothershipResolveTestClusterRunnerLogPath(cluster, logPath);

   suite.expect(::access(manifestPath.c_str(), R_OK) == 0, "runner_manifest_written");
   suite.expect(::access(controlSocketPath.c_str(), F_OK) == 0, "runner_control_socket_path_created");
   suite.expect(::access(pidPath.c_str(), R_OK) == 0, "runner_pid_written");
   suite.expect(::access(logPath.c_str(), F_OK) == 0, "runner_log_created");

   String stopCommand = {};
   mothershipBuildPersistentTestClusterStopCommand(cluster, stopCommand);
   suite.expect(stopCommand.size() > 0, "build_stop_command_nonempty");

   bool stopped = prodigyRunLocalShellCommand(stopCommand, &failure);
   if (stopped == false)
   {
      basics_log("detail stop_failure=%s\n", failure.c_str());
   }
   suite.expect(stopped, "run_stop_command");
   suite.expect(::access(workspaceRoot.c_str(), F_OK) != 0, "runner_workspace_removed");

   MothershipProdigyCluster spacedCluster = cluster;
   spacedCluster.name = "runner-test-spaced"_ctv;
   spacedCluster.test.workspaceRoot = spacedWorkspaceRoot;
   spacedCluster.test.brainBootstrapFamily = MothershipClusterTestBootstrapFamily::multihome6;
   spacedCluster.test.enableFakeIpv4Boundary = true;
   spacedCluster.test.interContainerMTU = 8192;
   mothershipResolveTestClusterControlRecord(spacedCluster.controls, spacedCluster);

   String spacedStartCommand = {};
   mothershipBuildPersistentTestClusterStartCommand(spacedHarnessPath, spacedProdigyPath, spacedCluster, spacedStartCommand);
   suite.expect(stringContains(spacedStartCommand, "setsid nohup env PRODIGY_DEV_KEEP_TMP=1 bash -lc"), "build_start_command_quotes_detached_session_prefix");
   suite.expect(stringContains(spacedStartCommand, "fake harness.sh"), "build_start_command_quotes_spaced_harness_path");
   suite.expect(stringContains(spacedStartCommand, "fake prodigy.sh"), "build_start_command_quotes_spaced_prodigy_path");
   suite.expect(stringContains(spacedStartCommand, "cluster workspace"), "build_start_command_quotes_spaced_workspace_path");
   suite.expect(stringContains(spacedStartCommand, "--brain-bootstrap-family=multihome6"), "build_start_command_multihome6");
   suite.expect(stringContains(spacedStartCommand, "--enable-fake-ipv4-boundary=1"), "build_start_command_fake_ipv4_boundary_enabled");
   suite.expect(stringContains(spacedStartCommand, "--inter-container-mtu=8192"), "build_start_command_inter_container_mtu_spaced");

   bool spacedStarted = prodigyRunLocalShellCommand(spacedStartCommand, &failure);
   if (spacedStarted == false)
   {
      basics_log("detail spaced_start_failure=%s\n", failure.c_str());
   }
   suite.expect(spacedStarted, "run_spaced_start_command");

   bool spacedReady = mothershipWaitForLocalTestClusterReady(spacedCluster, &failure, 5'000);
   if (spacedReady == false)
   {
      basics_log("detail spaced_ready_failure=%s\n", failure.c_str());
   }
   suite.expect(spacedReady, "wait_local_runner_ready_with_spaced_paths");

   String spacedStopCommand = {};
   mothershipBuildPersistentTestClusterStopCommand(spacedCluster, spacedStopCommand);
   bool spacedStopped = prodigyRunLocalShellCommand(spacedStopCommand, &failure);
   if (spacedStopped == false)
   {
      basics_log("detail spaced_stop_failure=%s\n", failure.c_str());
   }
   suite.expect(spacedStopped, "run_spaced_stop_command");
   suite.expect(::access(spacedWorkspaceRoot.c_str(), F_OK) != 0, "runner_spaced_workspace_removed");

   MothershipProdigyCluster timeoutCluster = cluster;
   timeoutCluster.name = "runner-test-timeout"_ctv;
   timeoutCluster.test.workspaceRoot.snprintf<"{}/timeout-cluster"_ctv>(scratchRoot);
   mothershipResolveTestClusterControlRecord(timeoutCluster.controls, timeoutCluster);
   String timeoutFailure = {};
   bool timeoutReady = mothershipWaitForLocalTestClusterReady(timeoutCluster, &timeoutFailure, 10);
   suite.expect(timeoutReady == false, "wait_local_runner_ready_timeout");
   suite.expect(stringContains(timeoutFailure, "timed out waiting for local test cluster manifest/socket"), "wait_local_runner_ready_timeout_reason");
   suite.expect(stringContains(timeoutFailure, "timeout-cluster"), "wait_local_runner_ready_timeout_mentions_workspace");

   String failingWorkspaceRoot = {};
   failingWorkspaceRoot.snprintf<"{}/failing-cluster"_ctv>(scratchRoot);
   String failingHarnessPath = {};
   failingHarnessPath.snprintf<"{}/failing_harness.sh"_ctv>(scratchRoot);
   suite.expect(writeExecutableFile(failingHarnessPath,
      "#!/usr/bin/env bash\n"
      "set -euo pipefail\n"
      "workspace_root=\"\"\n"
      "for arg in \"$@\"; do\n"
      "   case \"$arg\" in\n"
      "      --workspace-root=*) workspace_root=\"${arg#*=}\" ;;\n"
      "   esac\n"
      "done\n"
      "mkdir -p \"$workspace_root\"\n"
      "printf 'runner exited early\\n' >&2\n"
      "exit 1\n"),
      "write_failing_harness");

   MothershipProdigyCluster failingCluster = cluster;
   failingCluster.name = "runner-test-failing"_ctv;
   failingCluster.test.workspaceRoot = failingWorkspaceRoot;
   mothershipResolveTestClusterControlRecord(failingCluster.controls, failingCluster);
   String failingStartCommand = {};
   mothershipBuildPersistentTestClusterStartCommand(failingHarnessPath, prodigyPath, failingCluster, failingStartCommand);
   suite.expect(prodigyRunLocalShellCommand(failingStartCommand, &failure), "run_failing_start_command");

   String failingReadyFailure = {};
   bool failingReady = mothershipWaitForLocalTestClusterReady(failingCluster, &failingReadyFailure, 5'000);
   suite.expect(failingReady == false, "wait_local_runner_ready_runner_exit");
   suite.expect(stringContains(failingReadyFailure, "runner exited before ready"), "wait_local_runner_ready_runner_exit_reason");
   suite.expect(stringContains(failingReadyFailure, "failing-cluster"), "wait_local_runner_ready_runner_exit_mentions_workspace");
   String failingLogPath = {};
   mothershipResolveTestClusterRunnerLogPath(failingCluster, failingLogPath);
   suite.expect(::access(failingLogPath.c_str(), R_OK) == 0, "runner_exit_log_retained");

   String failingStopCommand = {};
   mothershipBuildPersistentTestClusterStopCommand(failingCluster, failingStopCommand);
   suite.expect(prodigyRunLocalShellCommand(failingStopCommand, &failure), "run_failing_stop_command");

   String cleanupCommand = {};
   cleanupCommand.assign("rm -rf "_ctv);
   prodigyAppendShellSingleQuoted(cleanupCommand, scratchRoot);
   prodigyRunLocalShellCommand(cleanupCommand, nullptr);

   if (suite.failed != 0)
   {
      basics_log("mothership_test_cluster_runner_unit failed=%d\n", suite.failed);
      return EXIT_FAILURE;
   }

   basics_log("mothership_test_cluster_runner_unit ok\n");
   return EXIT_SUCCESS;
}
