#include <filesystem>
#include <prodigy/bundle.artifact.h>
#include <prodigy/container.contract.h>
#include <services/debug.h>
#include <services/prodigy.h>

#include <simdjson.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PRODIGY_TEST_BINARY_DIR
#define PRODIGY_TEST_BINARY_DIR ""
#endif

class TestSuite {
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
      std::fprintf(stderr, "FAIL: %s\n", name);
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

static uint32_t stringOccurrences(const String& haystack, const String& needle)
{
  if (needle.empty())
  {
    return 0;
  }

  String text = {};
  text.assign(haystack);
  String match = {};
  match.assign(needle);
  uint32_t count = 0;
  const char *cursor = text.c_str();
  while ((cursor = std::strstr(cursor, match.c_str())) != nullptr)
  {
    count += 1;
    cursor += match.size();
  }
  return count;
}

static mode_t fileMode(const String& path)
{
  String pathText = {};
  pathText.assign(path);
  struct stat status = {};
  return ::stat(pathText.c_str(), &status) == 0
             ? status.st_mode & 0777
             : mode_t(-1);
}

static bool filesHaveEqualBytes(const String& left,
                                const String& right,
                                String *failure)
{
  String expectedDigest = {};
  String actualDigest = {};
  uint64_t expectedBytes = 0;
  return prodigyComputeFileSHA256Hex(
             left, expectedDigest, &expectedBytes, failure) &&
         prodigyFileMatchesExpectedSHA256HexAndSize(
             right, expectedDigest, expectedBytes, actualDigest, nullptr, failure);
}

static bool jsonTextEquals(simdjson::dom::element field, const char *expected)
{
  auto parsed = field.get_string();
  return parsed.error() == simdjson::SUCCESS &&
         parsed.value().size() == std::strlen(expected) &&
         std::memcmp(parsed.value().data(), expected, parsed.value().size()) == 0;
}

static bool resolverPlanHasExpectedIdentity(const String& path)
{
  String pathText = {};
  pathText.assign(path);
  String json = {};
  Filesystem::openReadAtClose(-1, pathText, json);
  if (json.empty())
  {
    return false;
  }
  json.need(simdjson::SIMDJSON_PADDING);

  simdjson::dom::parser parser;
  simdjson::dom::element document;
  uint64_t applicationID = 0;
  uint64_t versionID = 0;
  simdjson::dom::array advertisements;
  if (parser.parse(json.data(), json.size()).get(document) != simdjson::SUCCESS ||
      document["config"]["applicationID"].get(applicationID) != simdjson::SUCCESS ||
      document["config"]["versionID"].get(versionID) != simdjson::SUCCESS ||
      jsonTextEquals(document["config"]["type"], "ApplicationType::stateless") == false ||
      jsonTextEquals(document["config"]["architecture"],
                     machineCpuArchitectureName(nametagCurrentBuildMachineArchitecture())) == false ||
      document["advertisements"].get(advertisements) != simdjson::SUCCESS)
  {
    return false;
  }

  uint32_t advertisementCount = 0;
  bool exactAdvertisement = false;
  for (simdjson::dom::element advertisement : advertisements)
  {
    uint64_t port = 0;
    advertisementCount += 1;
    exactAdvertisement =
        jsonTextEquals(advertisement["service"], "MeshRegistry::DNS::resolver") &&
        advertisement["port"].get(port) == simdjson::SUCCESS &&
        port == 5353;
  }

  return applicationID == MeshRegistry::DNS::applicationID && versionID == 1 &&
         advertisementCount == 1 && exactAdvertisement;
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

int main(int argc, char *argv[])
{
  // Read-only preflight through the same owner used by updateProdigy. This
  // branch neither creates fixtures nor contacts or configures a cluster.
  if (argc == 3 && strcmp(argv[1], "--approve") == 0)
  {
    String path, digest, failure;
    path.assign(argv[2]);
    bool approved = prodigyApproveBundleArtifact(path, digest, &failure);
    dprintf(STDOUT_FILENO, "bundle_approval passed=%d sha256=%s failure=%s\n",
            int(approved), digest.c_str(), failure.c_str());
    return approved ? EXIT_SUCCESS : EXIT_FAILURE;
  }
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
  suite.expect(stringContains(tarListing, "container.ingress.router.declared.ebpf.o"), "bundle_contains_declared_container_ingress_ebpf");
  suite.expect(stringContains(tarListing, "container.egress.router.ebpf.o"), "bundle_contains_container_egress_ebpf");
  suite.expect(stringContains(tarListing, "container.egress.router.declared.ebpf.o"), "bundle_contains_declared_container_egress_ebpf");
  suite.expect(stringContains(tarListing, "tunnel_to_nic.ebpf.o"), "bundle_contains_tunnel_to_nic_ebpf");
  suite.expect(stringContains(tarListing, "tools/fio"), "bundle_contains_fio_tool");
  suite.expect(stringContains(tarListing, "tools/iperf3"), "bundle_contains_iperf3_tool");
  suite.expect(stringContains(tarListing, "tools/sysbench"), "bundle_contains_sysbench_tool");
  suite.expect(stringContains(tarListing, "tools/lat_mem_rd"), "bundle_contains_lat_mem_rd_tool");
  suite.expect(stringContains(tarListing, "tools/bw_mem"), "bundle_contains_bw_mem_tool");
  suite.expect(stringContains(tarListing, "tools/speedtest"), "bundle_contains_speedtest_tool");
  suite.expect(stringOccurrences(tarListing, "./tools/mothership\n"_ctv) == 1,
               "bundle_contains_mothership_once");
  suite.expect(stringContains(tarListing, "mothership.virtual.datacenter.provider.sh") == false,
               "bundle_embeds_virtual_datacenter_provider_in_mothership");
  String resolverArtifactEntry = {};
  resolverArtifactEntry.assign("./containers/prodigy-dns-resolver."_ctv);
  resolverArtifactEntry.append(machineCpuArchitectureName(currentArchitecture));
  resolverArtifactEntry.append(".container.zst\n"_ctv);
  suite.expect(stringOccurrences(tarListing, resolverArtifactEntry) == 1,
               "bundle_contains_exact_dns_resolver_container_name_once");
  suite.expect(stringOccurrences(tarListing, "./containers/prodigy-dns-resolver."_ctv) == 1,
               "bundle_contains_only_one_dns_resolver_container");
  suite.expect(stringOccurrences(
                   tarListing,
                   "./containers/plans/prodigy-dns-resolver.deployment.plan.v1.json\n"_ctv) == 1,
               "bundle_contains_exact_dns_resolver_plan_name_once");
  suite.expect(stringOccurrences(
                   tarListing,
                   "./containers/plans/prodigy-dns-resolver"_ctv) == 1,
               "bundle_contains_only_one_dns_resolver_plan");
  suite.expect(stringContains(tarListing, "lib/libc.so.6") == false, "bundle_excludes_libc");
  suite.expect(stringContains(tarListing, "lib/libm.so.6") == false, "bundle_excludes_libm");
  suite.expect(stringContains(tarListing, "lib/libresolv.so.2") == false, "bundle_excludes_libresolv");
  suite.expect(stringContains(tarListing, "lib/ld-linux-x86-64.so.2") == false, "bundle_excludes_dynamic_loader");
  suite.expect(stringContains(tarListing, "lib/libstdc++.so.6") == false, "bundle_excludes_host_libstdcpp");
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

  String colocatedBundle, fakeExecutable, registrationDigest;
  prodigyResolveInstalledBundlePathForRoot(fakeBundleHome, colocatedBundle);
  std::filesystem::copy_file(bundlePath.c_str(), colocatedBundle.c_str(), std::filesystem::copy_options::overwrite_existing);
  fakeExecutable = fakeBundleHome; fakeExecutable.append("/prodigy"_ctv);
  suite.expect(prodigyResolveInstalledBundleDigestForExecutable(fakeExecutable, registrationDigest) &&
               registrationDigest == bundleDigest, "registration_digest_uses_actual_install_root");
  suite.expect(!prodigyResolveInstalledBundleDigestForExecutable(""_ctv, registrationDigest) &&
               registrationDigest.empty(), "registration_digest_empty_executable_clears_stale_digest");

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
  suite.expect(fileExists(installPaths.bundleSHA256Path), "installed_bundle_sha256_sidecar_exists");
  String installedBundleExpectedDigest = {};
  suite.expect(prodigyLoadBundleExpectedSHA256Hex(installPaths.bundlePath, installedBundleExpectedDigest, &failure),
               "installed_bundle_sha256_sidecar_readable");
  suite.expect(failure.size() == 0, "installed_bundle_sha256_sidecar_read_clears_failure");
  suite.expect(installedBundleExpectedDigest == bundleDigest, "installed_bundle_sha256_sidecar_matches_bundle");

  String bundleBytes = {};
  Filesystem::openReadAtClose(-1, bundlePath, bundleBytes);
  suite.expect(bundleBytes.empty() == false, "bundle_bytes_available_for_normal_stage");

  String stagedBundlePath = {};
  stagedBundlePath.assign(tempDirectory);
  stagedBundlePath.append("/normal-stage.bundle.tar.zst"_ctv);
  String stagedDigest = {};
  suite.expect(prodigyStageBundleWithExpectedSHA256(
                   stagedBundlePath, bundleBytes, bundleDigest, stagedDigest, &failure),
               "normal_stage_bundle_with_verified_sha256_sidecar");
  suite.expect(failure.size() == 0, "normal_stage_bundle_clears_failure");
  suite.expect(stagedDigest == bundleDigest, "normal_stage_bundle_reports_verified_digest");
  String stagedExpectedDigest = {};
  suite.expect(prodigyLoadBundleExpectedSHA256Hex(stagedBundlePath, stagedExpectedDigest, &failure),
               "normal_stage_bundle_sidecar_readable");
  suite.expect(failure.size() == 0, "normal_stage_bundle_sidecar_clears_failure");
  suite.expect(stagedExpectedDigest == bundleDigest, "normal_stage_bundle_sidecar_matches_verified_digest");

  String preparedBundlePath = {};
  preparedBundlePath.assign(tempDirectory);
  preparedBundlePath.append("/prepared-stage.bundle.tar.zst"_ctv);
  ProdigyPreparedBundleArtifact preparedBundle = {};
  suite.expect(prodigyPrepareBundleArtifact(preparedBundle, preparedBundlePath, bundleBytes, bundleDigest, &failure),
               "prepared_bundle_stage_is_verified");
  suite.expect(preparedBundle.prepared && preparedBundle.published == false &&
                   preparedBundle.stageBundlePath != preparedBundle.bundlePath &&
                   fileExists(preparedBundle.stageBundlePath) && fileExists(preparedBundle.stageSHA256Path),
               "prepared_bundle_uses_private_bundle_and_sidecar_stages");
  suite.expect(prodigyPublishPreparedBundleArtifact(preparedBundle, &failure),
               "prepared_bundle_publishes_verified_stages");
  suite.expect(prodigyFsyncPublishedBundleArtifact(preparedBundle, &failure),
               "prepared_bundle_publication_parent_is_durable");
  suite.expect(preparedBundle.published && fileExists(preparedBundle.bundlePath) && fileExists(preparedBundle.sha256Path),
               "prepared_bundle_publish_exposes_bundle_and_sidecar");
  String publishedPreparedDigest = {};
  suite.expect(prodigyLoadBundleExpectedSHA256Hex(preparedBundle.bundlePath, publishedPreparedDigest, &failure) &&
                   publishedPreparedDigest == bundleDigest,
               "prepared_bundle_published_sidecar_matches_digest");
  suite.expect(::unlink(preparedBundle.bundlePath.c_str()) == 0 &&
                   Filesystem::openWriteAtClose(-1, preparedBundle.bundlePath, bundleBytes) == int(bundleBytes.size()),
               "prepared_bundle_published_target_is_replaced_before_stale_cleanup");
  prodigyDiscardPreparedBundleArtifact(preparedBundle);
  suite.expect(fileExists(preparedBundlePath), "prepared_bundle_cleanup_does_not_delete_replacement");

  // The two renames are deliberately not a pair-atomic operation. Make the
  // second target a directory so the first rename succeeds and the sidecar
  // rename fails, then ensure cleanup owns and removes that first final inode.
  String partialPublicationBundlePath = {};
  partialPublicationBundlePath.assign(tempDirectory);
  partialPublicationBundlePath.append("/partial-publication.bundle.tar.zst"_ctv);
  ProdigyPreparedBundleArtifact partialPublication = {};
  failure.clear();
  suite.expect(prodigyPrepareBundleArtifact(
                   partialPublication, partialPublicationBundlePath, bundleBytes, bundleDigest, &failure),
               "partial_publication_stage_is_verified");
  String partialPublicationFinalBundlePath = {};
  String partialPublicationFinalSHA256Path = {};
  String partialPublicationStageSHA256Path = {};
  partialPublicationFinalBundlePath.assign(partialPublication.bundlePath);
  partialPublicationFinalSHA256Path.assign(partialPublication.sha256Path);
  partialPublicationStageSHA256Path.assign(partialPublication.stageSHA256Path);
  std::error_code partialPublicationDirectoryError = {};
  suite.expect(std::filesystem::create_directory(
                   std::filesystem::path(partialPublicationFinalSHA256Path.c_str()), partialPublicationDirectoryError) &&
                   partialPublicationDirectoryError.value() == 0,
               "partial_publication_sidecar_target_is_directory");
  failure.clear();
  suite.expect(prodigyPublishPreparedBundleArtifact(partialPublication, &failure) == false &&
                   partialPublication.bundlePublished && partialPublication.sha256Published == false &&
                   partialPublication.published == false,
               "partial_publication_records_first_final_inode_before_sidecar_failure");
  prodigyDiscardPreparedBundleArtifact(partialPublication);
  suite.expect(fileExists(partialPublicationFinalBundlePath) == false &&
                   fileExists(partialPublicationStageSHA256Path) == false,
               "partial_publication_cleanup_removes_only_first_published_inode_and_stage");
  struct stat partialPublicationSidecarDirectory = {};
  suite.expect(::stat(partialPublicationFinalSHA256Path.c_str(), &partialPublicationSidecarDirectory) == 0 &&
                   S_ISDIR(partialPublicationSidecarDirectory.st_mode),
               "partial_publication_cleanup_preserves_unowned_sidecar_target");
  suite.expect(::rmdir(partialPublicationFinalSHA256Path.c_str()) == 0,
               "partial_publication_sidecar_target_cleanup");

  // A concurrent owner may replace the first final path before stale cleanup.
  // The recorded inode must prevent this request from unlinking that replacement.
  String replacedPartialPublicationBundlePath = {};
  replacedPartialPublicationBundlePath.assign(tempDirectory);
  replacedPartialPublicationBundlePath.append("/partial-publication-replaced.bundle.tar.zst"_ctv);
  ProdigyPreparedBundleArtifact replacedPartialPublication = {};
  failure.clear();
  suite.expect(prodigyPrepareBundleArtifact(
                   replacedPartialPublication, replacedPartialPublicationBundlePath, bundleBytes, bundleDigest, &failure),
               "partial_publication_replacement_stage_is_verified");
  String replacedFinalBundlePath = {};
  String replacedFinalSHA256Path = {};
  String replacedStageSHA256Path = {};
  replacedFinalBundlePath.assign(replacedPartialPublication.bundlePath);
  replacedFinalSHA256Path.assign(replacedPartialPublication.sha256Path);
  replacedStageSHA256Path.assign(replacedPartialPublication.stageSHA256Path);
  std::error_code replacedSidecarDirectoryError = {};
  suite.expect(std::filesystem::create_directory(
                   std::filesystem::path(replacedFinalSHA256Path.c_str()), replacedSidecarDirectoryError) &&
                   replacedSidecarDirectoryError.value() == 0,
               "partial_publication_replacement_sidecar_target_is_directory");
  failure.clear();
  suite.expect(prodigyPublishPreparedBundleArtifact(replacedPartialPublication, &failure) == false &&
                   replacedPartialPublication.bundlePublished && replacedPartialPublication.sha256Published == false,
               "partial_publication_replacement_records_first_final_inode");
  String independentReplacementPath = {};
  independentReplacementPath.assign(tempDirectory);
  independentReplacementPath.append("/independent-bundle-replacement"_ctv);
  std::error_code independentReplacementCopyError = {};
  suite.expect(std::filesystem::copy_file(
                   std::filesystem::path(replacedFinalBundlePath.c_str()),
                   std::filesystem::path(independentReplacementPath.c_str()),
                   std::filesystem::copy_options::none,
                   independentReplacementCopyError) && independentReplacementCopyError.value() == 0,
               "partial_publication_independent_replacement_is_created");
  struct stat independentReplacementMetadata = {};
  suite.expect(::stat(independentReplacementPath.c_str(), &independentReplacementMetadata) == 0 &&
                   (independentReplacementMetadata.st_dev != replacedPartialPublication.publishedBundleDevice ||
                    independentReplacementMetadata.st_ino != replacedPartialPublication.publishedBundleInode),
               "partial_publication_independent_replacement_has_distinct_inode");
  suite.expect(::rename(independentReplacementPath.c_str(), replacedFinalBundlePath.c_str()) == 0,
               "partial_publication_independent_replacement_is_published");
  prodigyDiscardPreparedBundleArtifact(replacedPartialPublication);
  struct stat survivingReplacementMetadata = {};
  suite.expect(::stat(replacedFinalBundlePath.c_str(), &survivingReplacementMetadata) == 0 &&
                   survivingReplacementMetadata.st_dev == independentReplacementMetadata.st_dev &&
                   survivingReplacementMetadata.st_ino == independentReplacementMetadata.st_ino &&
                   fileExists(replacedStageSHA256Path) == false,
               "partial_publication_cleanup_preserves_independently_replaced_final_inode");
  suite.expect(::rmdir(replacedFinalSHA256Path.c_str()) == 0,
               "partial_publication_replacement_sidecar_target_cleanup");

  String competingBundlePath = {};
  competingBundlePath.assign(tempDirectory);
  competingBundlePath.append("/competing-stage.bundle.tar.zst"_ctv);
  ProdigyPreparedBundleArtifact competingBundle = {};
  suite.expect(prodigyPrepareBundleArtifact(competingBundle, competingBundlePath, bundleBytes, bundleDigest, &failure),
               "prepared_bundle_competing_stage_is_verified");
  suite.expect(::unlink(competingBundle.stageBundlePath.c_str()) == 0 &&
                   Filesystem::openWriteAtClose(-1, competingBundle.stageBundlePath, bundleBytes) == int(bundleBytes.size()),
               "prepared_bundle_competing_stage_replaces_inode");
  suite.expect(prodigyPublishPreparedBundleArtifact(competingBundle, &failure) == false,
               "prepared_bundle_rejects_replaced_stage_inode");
  String competingStagePath = {};
  competingStagePath.assign(competingBundle.stageBundlePath);
  prodigyDiscardPreparedBundleArtifact(competingBundle);
  suite.expect(fileExists(competingStagePath),
               "prepared_bundle_cleanup_preserves_competing_replacement");

  String stagedInstallRoot = {};
  stagedInstallRoot.assign(tempDirectory);
  stagedInstallRoot.append("/normal-stage-installed-root"_ctv);
  suite.expect(prodigyInstallBundleToRoot(stagedBundlePath, stagedInstallRoot, &failure),
               "normal_stage_then_install_bundle");
  suite.expect(failure.size() == 0, "normal_stage_then_install_clears_failure");
  ProdigyInstallRootPaths stagedInstallPaths = {};
  prodigyBuildInstallRootPaths(stagedInstallRoot, stagedInstallPaths);
  String stagedInstalledDigest = {};
  suite.expect(prodigyLoadBundleExpectedSHA256Hex(stagedInstallPaths.bundlePath, stagedInstalledDigest, &failure),
               "normal_stage_install_sidecar_readable");
  suite.expect(failure.size() == 0, "normal_stage_install_sidecar_clears_failure");
  suite.expect(stagedInstalledDigest == bundleDigest, "normal_stage_install_sidecar_matches_verified_digest");

  String mismatchedStagePath = {};
  mismatchedStagePath.assign(tempDirectory);
  mismatchedStagePath.append("/mismatched-stage.bundle.tar.zst"_ctv);
  String mismatchedDigest = bundleDigest;
  mismatchedDigest[0] = mismatchedDigest[0] == '0' ? '1' : '0';
  String mismatchedActualDigest = {};
  suite.expect(prodigyStageBundleWithExpectedSHA256(
                   mismatchedStagePath, bundleBytes, mismatchedDigest, mismatchedActualDigest, &failure) == false,
               "normal_stage_rejects_digest_mismatch");
  suite.expect(stringContains(failure, "mismatch"), "normal_stage_mismatch_reports_reason");
  String mismatchedSidecarPath = {};
  prodigyResolveBundleSHA256Path(mismatchedStagePath, mismatchedSidecarPath);
  suite.expect(fileExists(mismatchedSidecarPath) == false, "normal_stage_mismatch_does_not_publish_sidecar");
  String mismatchedSidecarContent = {};
  mismatchedSidecarContent.assign(mismatchedDigest);
  mismatchedSidecarContent.append('\n');
  suite.expect(Filesystem::openWriteAtClose(-1, mismatchedSidecarPath, mismatchedSidecarContent) == int(mismatchedSidecarContent.size()),
               "mismatched_sidecar_written_for_install_rejection");
  String mismatchedInstallRoot = {};
  mismatchedInstallRoot.assign(tempDirectory);
  mismatchedInstallRoot.append("/mismatched-sidecar-installed-root"_ctv);
  suite.expect(prodigyInstallBundleToRoot(mismatchedStagePath, mismatchedInstallRoot, &failure) == false,
               "install_rejects_mismatched_sha256_sidecar");
  suite.expect(stringContains(failure, "mismatch"), "install_mismatched_sidecar_reports_reason");
  ProdigyInstallRootPaths mismatchedInstallPaths = {};
  prodigyBuildInstallRootPaths(mismatchedInstallRoot, mismatchedInstallPaths);
  suite.expect(fileExists(mismatchedInstallPaths.bundlePath) == false,
               "install_mismatched_sidecar_does_not_publish_bundle");

  String missingSidecarBundlePath = {};
  missingSidecarBundlePath.assign(tempDirectory);
  missingSidecarBundlePath.append("/missing-sidecar.bundle.tar.zst"_ctv);
  suite.expect(Filesystem::openWriteAtClose(-1, missingSidecarBundlePath, bundleBytes) == int(bundleBytes.size()),
               "missing_sidecar_bundle_bytes_written");
  String missingSidecarInstallRoot = {};
  missingSidecarInstallRoot.assign(tempDirectory);
  missingSidecarInstallRoot.append("/missing-sidecar-installed-root"_ctv);
  suite.expect(prodigyInstallBundleToRoot(missingSidecarBundlePath, missingSidecarInstallRoot, &failure) == false,
               "install_rejects_missing_sha256_sidecar");
  suite.expect(stringContains(failure, "sidecar is not readable"), "install_missing_sidecar_reports_reason");
  ProdigyInstallRootPaths missingSidecarInstallPaths = {};
  prodigyBuildInstallRootPaths(missingSidecarInstallRoot, missingSidecarInstallPaths);
  suite.expect(fileExists(missingSidecarInstallPaths.bundlePath) == false,
               "install_missing_sidecar_does_not_publish_bundle");

  String installedResolverArtifactPath = {};
  installedResolverArtifactPath.assign(installRoot);
  installedResolverArtifactPath.append("/containers/prodigy-dns-resolver."_ctv);
  installedResolverArtifactPath.append(machineCpuArchitectureName(currentArchitecture));
  installedResolverArtifactPath.append(".container.zst"_ctv);
  suite.expect(fileExists(installedResolverArtifactPath), "installed_bundle_dns_resolver_container_exists");
  suite.expect(fileMode(installedResolverArtifactPath) == 0644,
               "installed_bundle_dns_resolver_container_mode_0644");

  String generatedResolverArtifactPath = PRODIGY_TEST_BINARY_DIR;
  if (generatedResolverArtifactPath.size() > 0 &&
      generatedResolverArtifactPath[generatedResolverArtifactPath.size() - 1] != '/')
  {
    generatedResolverArtifactPath.append('/');
  }
  generatedResolverArtifactPath.append("prodigy-dns-resolver."_ctv);
  generatedResolverArtifactPath.append(machineCpuArchitectureName(currentArchitecture));
  generatedResolverArtifactPath.append(".container.zst"_ctv);
  suite.expect(filesHaveEqualBytes(generatedResolverArtifactPath,
                                   installedResolverArtifactPath,
                                   &failure),
               "installed_bundle_dns_resolver_container_matches_generated_bytes");
  suite.expect(failure.size() == 0,
               "installed_bundle_dns_resolver_container_comparison_clears_failure");
  suite.expect(prodigyValidateDiscombobulatorContainerBlobHeader(
                   installedResolverArtifactPath, &failure),
               "installed_bundle_dns_resolver_container_has_supported_app_header");
  suite.expect(failure.size() == 0,
               "installed_bundle_dns_resolver_container_header_clears_failure");

  String installedResolverPlanPath = {};
  installedResolverPlanPath.assign(installRoot);
  installedResolverPlanPath.append("/containers/plans/prodigy-dns-resolver.deployment.plan.v1.json"_ctv);
  suite.expect(fileExists(installedResolverPlanPath), "installed_bundle_dns_resolver_plan_exists");
  suite.expect(fileMode(installedResolverPlanPath) == 0644,
               "installed_bundle_dns_resolver_plan_mode_0644");

  String generatedResolverPlanPath = PRODIGY_TEST_BINARY_DIR;
  if (generatedResolverPlanPath.size() > 0 &&
      generatedResolverPlanPath[generatedResolverPlanPath.size() - 1] != '/')
  {
    generatedResolverPlanPath.append('/');
  }
  generatedResolverPlanPath.append("prodigy-dns-resolver.deployment.plan.v1.json"_ctv);
  suite.expect(filesHaveEqualBytes(generatedResolverPlanPath,
                                   installedResolverPlanPath,
                                   &failure),
               "installed_bundle_dns_resolver_plan_matches_generated_bytes");
  suite.expect(failure.size() == 0,
               "installed_bundle_dns_resolver_plan_comparison_clears_failure");
  suite.expect(resolverPlanHasExpectedIdentity(installedResolverPlanPath),
               "installed_bundle_dns_resolver_plan_has_exact_identity");

  String installedLibstdcppPath = {};
  installedLibstdcppPath.assign(installPaths.libraryDirectory);
  installedLibstdcppPath.append("/libstdc++.so.6"_ctv);
  suite.expect(fileExists(installedLibstdcppPath) == false, "installed_bundle_excludes_host_libstdcpp");

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
      "speedtest"};

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
      "container.ingress.router.declared.ebpf.o",
      "container.egress.router.ebpf.o",
      "container.egress.router.declared.ebpf.o",
      "tunnel_to_nic.ebpf.o"};

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
