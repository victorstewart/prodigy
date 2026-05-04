#include <prodigy/bundle.artifact.h>
#include <services/debug.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

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
         failed += 1;
      }
   }
};

static bool fileExists(const String& path)
{
   String pathText = {};
   pathText.assign(path);

   struct stat status = {};
   return ::stat(pathText.c_str(), &status) == 0;
}

static bool stringContains(const String& haystack, const char *needle)
{
   String text = {};
   text.assign(haystack);
   return std::strstr(text.c_str(), needle) != nullptr;
}

static void trimTrailingWhitespace(String& text)
{
   while (text.size() > 0)
   {
      char ch = text[text.size() - 1];
      if (ch != '\n' && ch != '\r' && ch != '\t' && ch != ' ')
      {
         break;
      }

      text.resize(text.size() - 1);
   }
}

static bool commandOutput(const String& command, String& output)
{
   String commandText = {};
   commandText.assign(command);
   FILE *pipe = popen(commandText.c_str(), "r");
   if (pipe == nullptr)
   {
      return false;
   }

   output.clear();
   char buffer[4096];
   while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr)
   {
      output.append(buffer);
   }

   return pclose(pipe) == 0;
}

int main(void)
{
   TestSuite suite;

   String prodigyBinaryPath = PRODIGY_TEST_BINARY_DIR "/prodigy";
   String bundlePath = PRODIGY_TEST_BINARY_DIR;
   if (bundlePath.size() > 0 && bundlePath[bundlePath.size() - 1] != '/')
   {
      bundlePath.append('/');
   }
   bundlePath.append(prodigyBundleFilename());
   String bundleSHA256Path = {};
   prodigyResolveBundleSHA256Path(bundlePath, bundleSHA256Path);
   MachineCpuArchitecture currentArchitecture = nametagCurrentBuildMachineArchitecture();

   char tempDirectoryTemplate[] = "/tmp/prodigy-bundle-artifact-unit-XXXXXX";
   char *tempDirectoryRaw = ::mkdtemp(tempDirectoryTemplate);
   suite.expect(tempDirectoryRaw != nullptr, "mkdtemp");
   if (suite.failed != 0)
   {
      return EXIT_FAILURE;
   }

   String tempDirectory = {};
   tempDirectory.assign(tempDirectoryRaw);
   String failure = {};
   String resolvedBundlePath = {};
   suite.expect(prodigyResolveBuiltBundleArtifact(prodigyBinaryPath, resolvedBundlePath, &failure), "resolve_built_bundle_artifact");
   suite.expect(failure.size() == 0, "resolve_built_bundle_artifact_clears_failure");
   suite.expect(resolvedBundlePath == bundlePath, "resolve_built_bundle_artifact_path");
   suite.expect(prodigyResolveBundleArtifactInput(prodigyBinaryPath, currentArchitecture, resolvedBundlePath, &failure), "resolve_bundle_input_from_binary");
   suite.expect(failure.size() == 0, "resolve_bundle_input_from_binary_clears_failure");
   suite.expect(resolvedBundlePath == bundlePath, "resolve_bundle_input_from_binary_path");
   suite.expect(fileExists(bundlePath), "bundle_artifact_exists");
   suite.expect(fileExists(bundleSHA256Path), "bundle_sha256_sidecar_exists");

   String bundleDigest = {};
   suite.expect(prodigyComputeFileSHA256Hex(bundlePath, bundleDigest, &failure), "bundle_sha256");
   suite.expect(failure.size() == 0, "bundle_sha256_clears_failure");
   suite.expect(bundleDigest.size() == 64, "bundle_sha256_size");

   String expectedDigest = {};
   suite.expect(prodigyLoadBundleExpectedSHA256Hex(bundlePath, expectedDigest, &failure), "bundle_sha256_sidecar_loads");
   suite.expect(failure.size() == 0, "bundle_sha256_sidecar_loads_clears_failure");
   suite.expect(expectedDigest == bundleDigest, "bundle_sha256_sidecar_matches_bundle");

   String shaCommand = {};
   shaCommand.assign("sha256sum "_ctv);
   prodigyAppendShellSingleQuoted(shaCommand, bundlePath);
   String shaOutput = {};
   suite.expect(commandOutput(shaCommand, shaOutput), "bundle_sha256sum_command");
   trimTrailingWhitespace(shaOutput);

   String expectedDigestFromSha256sum = {};
   if (shaOutput.size() >= 64)
   {
      expectedDigestFromSha256sum.assign(shaOutput.substr(0, 64, Copy::yes));
   }
   suite.expect(expectedDigestFromSha256sum == bundleDigest, "bundle_sha256_matches_sha256sum");

   String approvedDigest = {};
   suite.expect(prodigyBundleMatchesExpectedSHA256Hex(bundlePath, bundleDigest, approvedDigest, &failure), "bundle_sha256_approval_accepts_match");
   suite.expect(failure.size() == 0, "bundle_sha256_approval_accepts_match_clears_failure");
   suite.expect(approvedDigest == bundleDigest, "bundle_sha256_approval_reports_actual_digest");

   String mismatchDigest = bundleDigest;
   mismatchDigest[0] = (mismatchDigest[0] == '0') ? '1' : '0';
   suite.expect(prodigyBundleMatchesExpectedSHA256Hex(bundlePath, mismatchDigest, approvedDigest, &failure) == false, "bundle_sha256_approval_rejects_mismatch");
   suite.expect(stringContains(failure, "mismatch"), "bundle_sha256_approval_rejects_with_mismatch_reason");

   String tarCommand = {};
   tarCommand.assign("tar --zstd -tf "_ctv);
   prodigyAppendShellSingleQuoted(tarCommand, bundlePath);
   String tarListing = {};
   suite.expect(commandOutput(tarCommand, tarListing), "list_bundle_artifact");
   suite.expect(stringContains(tarListing, "prodigy"), "bundle_contains_prodigy");
   suite.expect(stringContains(tarListing, "lib/"), "bundle_contains_lib_directory");
   suite.expect(stringContains(tarListing, "balancer.ebpf.o"), "bundle_contains_balancer_ebpf");
   suite.expect(stringContains(tarListing, "host.ingress.router.ebpf.o"), "bundle_contains_host_ingress_ebpf");
   suite.expect(stringContains(tarListing, "host.egress.router.ebpf.o"), "bundle_contains_host_egress_ebpf");
   suite.expect(stringContains(tarListing, "container.ingress.router.ebpf.o"), "bundle_contains_container_ingress_ebpf");
   suite.expect(stringContains(tarListing, "container.egress.router.ebpf.o"), "bundle_contains_container_egress_ebpf");
   suite.expect(stringContains(tarListing, "tunnel_to_nic.ebpf.o"), "bundle_contains_tunnel_to_nic_ebpf");
   suite.expect(stringContains(tarListing, "tools/fio"), "bundle_contains_fio_tool");
   suite.expect(stringContains(tarListing, "tools/iperf3"), "bundle_contains_iperf3_tool");
   suite.expect(stringContains(tarListing, "tools/sysbench"), "bundle_contains_sysbench_tool");
   suite.expect(stringContains(tarListing, "tools/lat_mem_rd"), "bundle_contains_lat_mem_rd_tool");
   suite.expect(stringContains(tarListing, "tools/bw_mem"), "bundle_contains_bw_mem_tool");
   suite.expect(stringContains(tarListing, "tools/speedtest"), "bundle_contains_speedtest_tool");
   suite.expect(stringContains(tarListing, "lib/libc.so.6") == false, "bundle_excludes_libc");
   suite.expect(stringContains(tarListing, "lib/libm.so.6") == false, "bundle_excludes_libm");
   suite.expect(stringContains(tarListing, "lib/libresolv.so.2") == false, "bundle_excludes_libresolv");
   suite.expect(stringContains(tarListing, "lib/ld-linux-x86-64.so.2") == false, "bundle_excludes_dynamic_loader");
   suite.expect(stringContains(tarListing, "lib/libstdc++.so.6") == false, "bundle_excludes_host_libstdcpp");
   suite.expect(stringContains(tarListing, "lib/libatomic.so.1"), "bundle_includes_libatomic");
   suite.expect(stringContains(tarListing, "lib/libgcc_s.so.1") == false, "bundle_excludes_host_libgcc_s");

   String inspectDirectory = {};
   inspectDirectory.assign(tempDirectory);
   inspectDirectory.append("/inspect-bundle"_ctv);
   String inspectCommand = {};
   inspectCommand.assign("rm -rf "_ctv);
   prodigyAppendShellSingleQuoted(inspectCommand, inspectDirectory);
   inspectCommand.append(" && mkdir -p "_ctv);
   prodigyAppendShellSingleQuoted(inspectCommand, inspectDirectory);
   inspectCommand.append(" && tar --zstd -xf "_ctv);
   prodigyAppendShellSingleQuoted(inspectCommand, bundlePath);
   inspectCommand.append(" -C "_ctv);
   prodigyAppendShellSingleQuoted(inspectCommand, inspectDirectory);
   inspectCommand.append(" ./prodigy && file "_ctv);
   String bundleBinaryPath = {};
   bundleBinaryPath.assign(inspectDirectory);
   bundleBinaryPath.append("/prodigy"_ctv);
   prodigyAppendShellSingleQuoted(inspectCommand, bundleBinaryPath);
   String bundleFileOutput = {};
   suite.expect(commandOutput(inspectCommand, bundleFileOutput), "inspect_bundle_binary_architecture");
   if (currentArchitecture == MachineCpuArchitecture::x86_64)
   {
      suite.expect(stringContains(bundleFileOutput, "x86-64"), "bundle_binary_is_x86_64");
   }
   else if (currentArchitecture == MachineCpuArchitecture::aarch64)
   {
      suite.expect(stringContains(bundleFileOutput, "ARM aarch64"), "bundle_binary_is_aarch64");
   }
   else if (currentArchitecture == MachineCpuArchitecture::riscv64)
   {
      suite.expect(stringContains(bundleFileOutput, "RISC-V"), "bundle_binary_is_riscv64");
   }

   String originalHome = {};
   const char *oldHome = std::getenv("HOME");
   if (oldHome != nullptr)
   {
      originalHome.assign(oldHome);
   }
   String originalXdgDataHome = {};
   const char *oldXdgDataHome = std::getenv("XDG_DATA_HOME");
   if (oldXdgDataHome != nullptr)
   {
      originalXdgDataHome.assign(oldXdgDataHome);
   }

   String fakeHome = {};
   fakeHome.assign(tempDirectory);
   fakeHome.append("/home"_ctv);
   String fakeHomeText = {};
   fakeHomeText.assign(fakeHome);
   String fakeBundleHome = {};
   fakeBundleHome.assign(fakeHome);
   fakeBundleHome.append("/.local/share/prodigy"_ctv);
   String prepareInstalledCommand = {};
   prepareInstalledCommand.assign("mkdir -p "_ctv);
   prodigyAppendShellSingleQuoted(prepareInstalledCommand, fakeBundleHome);
   prepareInstalledCommand.append(" && cp "_ctv);
   prodigyAppendShellSingleQuoted(prepareInstalledCommand, bundlePath);
   prepareInstalledCommand.append(" "_ctv);
   String installedBundlePath = {};
   prodigyResolveBundlePathForDirectory(fakeBundleHome, currentArchitecture, installedBundlePath);
   prodigyAppendShellSingleQuoted(prepareInstalledCommand, installedBundlePath);
   prepareInstalledCommand.append(" && cp "_ctv);
   prodigyAppendShellSingleQuoted(prepareInstalledCommand, bundleSHA256Path);
   String installedBundleSHA256Path = {};
   prodigyResolveBundleSHA256Path(installedBundlePath, installedBundleSHA256Path);
   prepareInstalledCommand.append(" "_ctv);
   prodigyAppendShellSingleQuoted(prepareInstalledCommand, installedBundleSHA256Path);
   suite.expect(prodigyRunLocalShellCommand(prepareInstalledCommand, &failure), "prepare_installed_bundle_home");
   suite.expect(failure.size() == 0, "prepare_installed_bundle_home_clears_failure");

   suite.expect(setenv("HOME", fakeHomeText.c_str(), 1) == 0, "set_fake_home");
   suite.expect(unsetenv("XDG_DATA_HOME") == 0, "unset_xdg_data_home");

   String resolvedInstalledBundlePath = {};
   suite.expect(prodigyResolveInstalledBundleArtifact(currentArchitecture, resolvedInstalledBundlePath, &failure), "resolve_installed_bundle_artifact");
   suite.expect(failure.size() == 0, "resolve_installed_bundle_artifact_clears_failure");
   suite.expect(resolvedInstalledBundlePath == installedBundlePath, "resolve_installed_bundle_artifact_path");

   String approvedInstalledDigest = {};
   String approvedInstalledBundlePath = {};
   suite.expect(prodigyResolveInstalledApprovedBundleArtifact(currentArchitecture, approvedInstalledBundlePath, approvedInstalledDigest, &failure), "resolve_installed_approved_bundle_artifact");
   suite.expect(failure.size() == 0, "resolve_installed_approved_bundle_artifact_clears_failure");
   suite.expect(approvedInstalledBundlePath == installedBundlePath, "resolve_installed_approved_bundle_artifact_path");
   suite.expect(approvedInstalledDigest == bundleDigest, "resolve_installed_approved_bundle_artifact_digest");

   String installedExpectedDigest = {};
   suite.expect(prodigyLoadBundleExpectedSHA256Hex(resolvedInstalledBundlePath, installedExpectedDigest, &failure), "load_installed_bundle_sha256_sidecar");
   suite.expect(failure.size() == 0, "load_installed_bundle_sha256_sidecar_clears_failure");
   suite.expect(installedExpectedDigest == bundleDigest, "installed_bundle_sha256_sidecar_matches_bundle");

   if (oldHome != nullptr)
   {
      String originalHomeText = {};
      originalHomeText.assign(originalHome);
      suite.expect(setenv("HOME", originalHomeText.c_str(), 1) == 0, "restore_home");
   }
   else
   {
      suite.expect(unsetenv("HOME") == 0, "unset_home");
   }

   if (oldXdgDataHome != nullptr)
   {
      String originalXdgDataHomeText = {};
      originalXdgDataHomeText.assign(originalXdgDataHome);
      suite.expect(setenv("XDG_DATA_HOME", originalXdgDataHomeText.c_str(), 1) == 0, "restore_xdg_data_home");
   }
   else
   {
      suite.expect(unsetenv("XDG_DATA_HOME") == 0, "leave_xdg_data_home_unset");
   }

   String installRoot = {};
   installRoot.assign(tempDirectory);
   installRoot.append("/installed-root"_ctv);
   suite.expect(prodigyInstallBundleToRoot(bundlePath, installRoot, &failure), "install_bundle_to_root");
   suite.expect(failure.size() == 0, "install_bundle_to_root_clears_failure");

   ProdigyInstallRootPaths installPaths = {};
   prodigyBuildInstallRootPaths(installRoot, installPaths);
   suite.expect(fileExists(installPaths.binaryPath), "installed_bundle_binary_exists");
   suite.expect(fileExists(installPaths.libraryDirectory), "installed_bundle_lib_directory_exists");
   suite.expect(fileExists(installPaths.toolsDirectory), "installed_bundle_tools_directory_exists");
   suite.expect(fileExists(installPaths.bundlePath), "installed_bundle_bundle_exists");

   String installedLibstdcppPath = {};
   installedLibstdcppPath.assign(installPaths.libraryDirectory);
   installedLibstdcppPath.append("/libstdc++.so.6"_ctv);
   suite.expect(fileExists(installedLibstdcppPath) == false, "installed_bundle_excludes_host_libstdcpp");

   String installedLibatomicPath = {};
   installedLibatomicPath.assign(installPaths.libraryDirectory);
   installedLibatomicPath.append("/libatomic.so.1"_ctv);
   suite.expect(fileExists(installedLibatomicPath), "installed_bundle_includes_libatomic");

   String installedLibgccPath = {};
   installedLibgccPath.assign(installPaths.libraryDirectory);
   installedLibgccPath.append("/libgcc_s.so.1"_ctv);
   suite.expect(fileExists(installedLibgccPath) == false, "installed_bundle_excludes_host_libgcc_s");

   static const char *requiredTools[] = {
      "fio",
      "iperf3",
      "sysbench",
      "lat_mem_rd",
      "bw_mem",
      "speedtest"
   };

   for (const char *requiredTool : requiredTools)
   {
      String installedToolPath = {};
      installedToolPath.assign(installPaths.toolsDirectory);
      installedToolPath.append('/');
      installedToolPath.append(requiredTool);
      suite.expect(fileExists(installedToolPath), requiredTool);
   }

   static const char *requiredObjects[] = {
      "balancer.ebpf.o",
      "host.ingress.router.ebpf.o",
      "host.egress.router.ebpf.o",
      "container.ingress.router.ebpf.o",
      "container.egress.router.ebpf.o",
      "tunnel_to_nic.ebpf.o"
   };

   for (const char *requiredObject : requiredObjects)
   {
      String installedObjectPath = {};
      installedObjectPath.assign(installRoot);
      installedObjectPath.append('/');
      installedObjectPath.append(requiredObject);
      suite.expect(fileExists(installedObjectPath), requiredObject);
   }

   String cleanupCommand = {};
   cleanupCommand.assign("rm -rf "_ctv);
   prodigyAppendShellSingleQuoted(cleanupCommand, tempDirectory);
   suite.expect(prodigyRunLocalShellCommand(cleanupCommand), "cleanup_temp_directory");

   if (suite.failed != 0)
   {
      basics_log("bundle_artifact_unit failed=%d\n", suite.failed);
      return EXIT_FAILURE;
   }

   basics_log("bundle_artifact_unit ok\n");
   return EXIT_SUCCESS;
}
