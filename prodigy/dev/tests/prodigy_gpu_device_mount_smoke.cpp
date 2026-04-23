#include <prodigy/prodigy.h>
#include <services/debug.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <fcntl.h>
#include <sched.h>
#include <string>
#include <string_view>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

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

class DetectedNvidiaGPU
{
public:

   std::string model;
   std::string busAddress;
   uint32_t deviceMinor = 0;
};

static bool fileExists(const std::string& path)
{
   return access(path.c_str(), F_OK) == 0;
}

static std::optional<std::string> readFirstLineWithPrefix(const std::filesystem::path& path, std::string_view prefix)
{
   std::ifstream stream(path);
   if (stream.good() == false)
   {
      return std::nullopt;
   }

   std::string line;
   while (std::getline(stream, line))
   {
      if (line.rfind(prefix, 0) != 0)
      {
         continue;
      }

      size_t valueStart = line.find_first_not_of(" \t", prefix.size());
      if (valueStart == std::string::npos)
      {
         return std::string();
      }

      return line.substr(valueStart);
   }

   return std::nullopt;
}

static bool detectNvidiaGPU(DetectedNvidiaGPU& gpu)
{
   std::filesystem::path gpuRoot("/proc/driver/nvidia/gpus");
   if (std::filesystem::exists(gpuRoot) == false)
   {
      return false;
   }

   for (const auto& entry : std::filesystem::directory_iterator(gpuRoot))
   {
      if (entry.is_directory() == false)
      {
         continue;
      }

      std::filesystem::path infoPath = entry.path() / "information";
      std::optional<std::string> model = readFirstLineWithPrefix(infoPath, "Model:");
      std::optional<std::string> bus = readFirstLineWithPrefix(infoPath, "Bus Location:");
      std::optional<std::string> minor = readFirstLineWithPrefix(infoPath, "Device Minor:");
      if (model.has_value() == false || bus.has_value() == false || minor.has_value() == false)
      {
         continue;
      }

      uint32_t deviceMinor = uint32_t(std::strtoul(minor->c_str(), nullptr, 10));
      std::string nvidiaNode = "/dev/nvidia" + std::to_string(deviceMinor);
      if (fileExists(nvidiaNode) == false)
      {
         continue;
      }

      gpu.model = *model;
      gpu.busAddress = *bus;
      gpu.deviceMinor = deviceMinor;
      return true;
   }

   return false;
}

static bool statCharacterDevice(const std::string& path, struct stat& statbuf)
{
   if (stat(path.c_str(), &statbuf) != 0)
   {
      return false;
   }

   return S_ISCHR(statbuf.st_mode) != 0;
}

static bool openCharacterDevice(const std::string& path)
{
   int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
   if (fd < 0)
   {
      return false;
   }

   close(fd);
   return true;
}

static void appendUniquePath(std::vector<std::string>& paths, const std::string& path)
{
   for (const std::string& existing : paths)
   {
      if (existing == path)
      {
         return;
      }
   }

   paths.push_back(path);
}

static std::string lowerASCII(std::string text)
{
   for (char& c : text)
   {
      c = char(std::tolower(unsigned(c)));
   }

   return text;
}

static std::vector<std::string> expectedMountedGPUPaths(const DetectedNvidiaGPU& gpu)
{
   std::vector<std::string> paths = {
      "/dev/nvidia" + std::to_string(gpu.deviceMinor),
      "/dev/nvidiactl",
   };

   if (fileExists("/dev/nvidia-uvm"))
   {
      appendUniquePath(paths, "/dev/nvidia-uvm");
   }
   if (fileExists("/dev/nvidia-uvm-tools"))
   {
      appendUniquePath(paths, "/dev/nvidia-uvm-tools");
   }
   if (fileExists("/dev/nvidia-modeset"))
   {
      appendUniquePath(paths, "/dev/nvidia-modeset");
   }

   std::string loweredBus = lowerASCII(gpu.busAddress);
   for (const std::string& suffix : {"-card", "-render"})
   {
      std::string candidate = "/dev/dri/by-path/pci-" + loweredBus + suffix;
      if (fileExists(candidate) == false)
      {
         continue;
      }

      std::error_code error = {};
      std::filesystem::path canonical = std::filesystem::canonical(candidate, error);
      if (error.value() != 0)
      {
         continue;
      }

      appendUniquePath(paths, canonical.string());
   }

   return paths;
}

static bool makeDirectoryTree(const std::string& path)
{
   std::error_code error = {};
   std::filesystem::create_directories(path, error);
   return error.value() == 0;
}

static bool unmountTargetIfMounted(const std::string& path)
{
   if (fileExists(path) == false)
   {
      return true;
   }

   return umount2(path.c_str(), MNT_DETACH) == 0 || errno == EINVAL || errno == ENOENT;
}

int main(void)
{
   TestSuite suite;

   DetectedNvidiaGPU gpu = {};
   const bool foundGPU = detectNvidiaGPU(gpu);
   suite.expect(foundGPU, "detect_nvidia_gpu_from_proc");
   if (foundGPU == false)
   {
      return 1;
   }

   basics_log("GPU model=%s bus=%s minor=%u\n", gpu.model.c_str(), gpu.busAddress.c_str(), gpu.deviceMinor);

   char workspaceTemplate[] = "/tmp/prodigy-gpu-mount-smoke.XXXXXX";
   char *workspacePath = mkdtemp(workspaceTemplate);
   suite.expect(workspacePath != nullptr, "mkdtemp_workspace_created");
   if (workspacePath == nullptr)
   {
      return 1;
   }

   std::string workspace(workspacePath);
   std::string containerRoot = workspace + "/root";
   suite.expect(makeDirectoryTree(containerRoot), "create_container_root_directory");

   struct stat hostNetnsStat = {};
   suite.expect(stat("/proc/self/ns/net", &hostNetnsStat) == 0, "stat_host_netns");

   suite.expect(unshare(CLONE_NEWNS | CLONE_NEWNET) == 0, "unshare_mount_and_net_namespace");
   suite.expect(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == 0, "make_mount_namespace_private");

   struct stat isolatedNetnsStat = {};
   suite.expect(stat("/proc/self/ns/net", &isolatedNetnsStat) == 0, "stat_isolated_netns");
   suite.expect(hostNetnsStat.st_ino != 0 && hostNetnsStat.st_ino != isolatedNetnsStat.st_ino, "isolated_netns_differs_from_host");

   Container container = {};
   container.plan.uuid = uint128_t(0x1234);
   AssignedGPUDevice assigned = {};
   assigned.vendor = "nvidia"_ctv;
   assigned.model.assign(gpu.model.data(), gpu.model.size());
   assigned.busAddress.assign(gpu.busAddress.data(), gpu.busAddress.size());
   container.plan.assignedGPUDevices.push_back(assigned);

   String rootString = {};
   rootString.assign(containerRoot.data(), containerRoot.size());
   String failure = {};
   const bool mounted = ContainerManager::debugMountAssignedGPUDevicesInCurrentNamespace(&container, rootString, &failure);
   suite.expect(mounted, "mount_assigned_gpu_devices_in_current_namespace");
   if (mounted == false)
   {
      basics_log("mount failure: %s\n", failure.c_str());
   }

   std::vector<std::string> expectedPaths = expectedMountedGPUPaths(gpu);
   for (const std::string& sourcePath : expectedPaths)
   {
      String allowlistedPath = {};
      allowlistedPath.assign(sourcePath.data(), sourcePath.size());
      std::string allowlistLabel = "source_device_allowlisted_" + sourcePath;
      suite.expect(
         ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath(allowlistedPath),
         allowlistLabel.c_str());

      struct stat sourceStat = {};
      struct stat targetStat = {};
      const std::string targetPath = containerRoot + sourcePath;

      std::string sourceLabel = "source_device_exists_" + sourcePath;
      std::string targetLabel = "target_device_mounted_" + sourcePath;
      std::string matchLabel = "target_device_matches_source_rdev_" + sourcePath;

      const bool sourceOK = statCharacterDevice(sourcePath, sourceStat);
      const bool targetOK = statCharacterDevice(targetPath, targetStat);
      suite.expect(sourceOK, sourceLabel.c_str());
      suite.expect(targetOK, targetLabel.c_str());
      if (sourceOK && targetOK)
      {
         suite.expect(sourceStat.st_rdev == targetStat.st_rdev, matchLabel.c_str());
      }

      std::string openLabel = "target_device_openable_" + sourcePath;
      suite.expect(targetOK && openCharacterDevice(targetPath), openLabel.c_str());
   }

   for (auto it = expectedPaths.rbegin(); it != expectedPaths.rend(); ++it)
   {
      (void)unmountTargetIfMounted(containerRoot + *it);
   }

   std::filesystem::remove_all(workspace);
   return (suite.failed == 0) ? 0 : 1;
}
