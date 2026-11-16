#include <networking/includes.h>
#include <services/debug.h>

#include <prodigy/neuron/container.storage.layout.h>
#define PRODIGY_STORAGE_OWNERSHIP_TESTING 1
#include <prodigy/neuron/container.storage.ownership.h>
#include <fstream>
#include <sys/wait.h>

#include <cstdio>
#include <cstdlib>

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
      basics_log("FAIL: %s\n", name);
      failed += 1;
    }
  }
};

static MachineDiskHardwareProfile makeDisk(const char *mountPath)
{
  MachineDiskHardwareProfile disk = {};
  disk.mountPath.assign(mountPath);
  return disk;
}

static void storageOwnershipUnitTests(TestSuite& suite)
{
  if (geteuid() != 0) { basics_log("SKIP: storage ownership UID fixtures require root\n"); return; }
  char path[] = "/tmp/prodigy-ownership-unit-XXXXXX";
  char *created = mkdtemp(path);
  suite.expect(created != nullptr, "ownership fixture directory");
  if (!created) return;
  const auto root = std::filesystem::path(created);
  std::filesystem::create_directories(root / "source/kvdb");
  { std::ofstream out(root / "source/kvdb/value"); out << "persisted account bytes\n"; }
  std::filesystem::copy(root / "source", root / "copy", std::filesystem::copy_options::recursive);
  for (const char *tree : {"source", "copy"}) {
    int sparse = open((root / tree / "kvdb/sparse").c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    suite.expect(sparse >= 0 && !ftruncate(sparse, off_t(1) << 46) &&
                 pwrite(sparse, "retained", 8, off_t(1) << 40) == 8, "ownership creates sparse HSE-sized fixture");
    if (sparse >= 0) close(sparse);
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root / tree)) {
      chown(entry.path().c_str(), 65535, 65535);
      chmod(entry.path().c_str(), entry.is_directory() ? 0700 : 0600);
    }
    chown((root / tree).c_str(), 131070, 131070);
    chmod((root / tree).c_str(), 0700);
  }
  int source = open((root / "source").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  int copy = open((root / "copy").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  String error;
  ProdigyStorageOwnership::Tree before, after;
  suite.expect(ProdigyStorageOwnership::inspect(source, 131070, before, true, &error) && before.priorUID == 65535,
               "ownership recognizes new root and inherited private descendants");
  suite.expect(ProdigyStorageOwnership::normalize(copy, 65535, 131070, &error) &&
               ProdigyStorageOwnership::inspect(copy, 131070, after, true, &error) &&
               !after.priorUID && before.manifest == after.manifest,
               "ownership normalization preserves nested bytes and modes");
  struct stat original {};
  stat((root / "source/kvdb").c_str(), &original);
  suite.expect(original.st_uid == 65535 && (original.st_mode & 0777) == 0700,
               "ownership normalization leaves original source unchanged");
  symlink("/etc/passwd", (root / "copy/escape").c_str());
  lchown((root / "copy/escape").c_str(), 131071, 131072);
  chown((root / "copy/kvdb/value").c_str(), 131071, 131072);
  suite.expect(ProdigyStorageOwnership::inspect(copy, 131070, after, false, &error, true) && !after.priorUID,
               "ownership leaves already mapped multi-user application data alone");
  chown((root / "copy/kvdb/value").c_str(), 131070, 131070);
  suite.expect(!ProdigyStorageOwnership::inspect(copy, 131070, after, false, &error), "ownership rejects symlink traversal during conversion");
  unlink((root / "copy/escape").c_str());
  chmod((root / "copy/kvdb/value").c_str(), 0666);
  suite.expect(!ProdigyStorageOwnership::inspect(copy, 131070, after, false, &error), "ownership rejects foreign-writable file");
  chmod((root / "copy/kvdb/value").c_str(), 0600);
  chown((root / "copy/kvdb").c_str(), 196605, 196605);
  chown((root / "copy/kvdb/value").c_str(), 262140, 262140);
  suite.expect(!ProdigyStorageOwnership::inspect(copy, 131070, after, false, &error), "ownership rejects ambiguous predecessor identities");
  close(source); close(copy);
  std::filesystem::remove_all(root);
}
static bool ownershipSnapshot(const String& source, const String& target, String *error)
{
  String sourceText(source), targetText(target);
  pid_t child = fork();
  if (!child) { execlp("btrfs", "btrfs", "subvolume", "snapshot", sourceText.c_str(), targetText.c_str(), (char *)nullptr); _exit(127); }
  int status = 0;
  pid_t result;
  do result = waitpid(child, &status, 0); while (result < 0 && errno == EINTR);
  if (child <= 0 || result != child || !WIFEXITED(status) || WEXITSTATUS(status))
    return ProdigyStorageOwnership::fail(error, "fixture snapshot failed");
  return true;
}
static void storageOwnershipBtrfsTests(TestSuite& suite, const char *fixture)
{
  const std::filesystem::path parent(fixture);
  const String artifact("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
  for (uint8_t phase = 0; phase != 4; ++phase) {
    auto root = parent / ("phase-" + std::to_string(phase));
    std::filesystem::create_directory(root);
    String rootPath; rootPath.assign(root.string().c_str());
    auto data = root / "data";
    pid_t child = fork();
    if (!child) { execlp("btrfs", "btrfs", "subvolume", "create", data.c_str(), (char *)nullptr); _exit(127); }
    int status = 0; while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    suite.expect(WIFEXITED(status) && !WEXITSTATUS(status), "ownership creates real Btrfs data fixture");
    std::filesystem::create_directory(data / "kvdb");
    { std::ofstream out(data / "kvdb/value"); out << "retained account fixture\n"; }
    int sparse = open((data / "kvdb/sparse").c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    suite.expect(sparse >= 0 && !ftruncate(sparse, off_t(1) << 46) &&
                 pwrite(sparse, "retained", 8, off_t(1) << 40) == 8,
                 "ownership Btrfs transaction keeps HSE-sized sparse data");
    if (sparse >= 0) close(sparse);
    chown((data / "kvdb/sparse").c_str(), 65535, 65535);
    chown(data.c_str(), 131070, 131070); chmod(data.c_str(), 0755);
    chown((data / "kvdb").c_str(), 65535, 65535); chmod((data / "kvdb").c_str(), 0700);
    chown((data / "kvdb/value").c_str(), 65535, 65535); chmod((data / "kvdb/value").c_str(), 0600);
    int owner = open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    String error;
    const uint128_t uuid = 123 + phase;
    ProdigyStorageOwnership::interruptAfterPhase = phase;
    suite.expect(!ProdigyStorageOwnership::transfer(owner, rootPath, uuid, 666, 131070, artifact, 1234,
                  ownershipSnapshot, &error), "ownership interruption stops before application launch");
    suite.expect(ProdigyStorageOwnership::transfer(owner, rootPath, uuid, 666, 131070, artifact, 1234,
                  ownershipSnapshot, &error), "ownership resumes each durable transaction boundary");
    struct stat current {}, retained {};
    stat((data / "kvdb").c_str(), &current);
    auto backup = root / (".ownership-" + std::to_string(123 + phase) + ".source/kvdb");
    stat(backup.c_str(), &retained);
    suite.expect(current.st_uid == 131070 && retained.st_uid == 65535,
                 "ownership publishes new UID and retains original private source");
    { std::ofstream out(data / "kvdb/value", std::ios::app); out << "subsequent application write\n"; }
    chown((data / "kvdb/value").c_str(), 131071, 131072);
    symlink("value", (data / "kvdb/application-link").c_str());
    lchown((data / "kvdb/application-link").c_str(), 131071, 131072);
    suite.expect(ProdigyStorageOwnership::transfer(owner, rootPath, uuid, 666, 131070, artifact, 1234,
                  ownershipSnapshot, &error), "ownership completed receipt permits subsequent application data");
    suite.expect(!ProdigyStorageOwnership::transfer(owner, rootPath, uuid, 666, 131070,
                  String("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv), 1234,
                  ownershipSnapshot, &error), "ownership receipt rejects changed artifact identity");
    close(owner);
  }
}

int main(int argc, char **argv)
{
  TestSuite suite = {};
  storageOwnershipUnitTests(suite);
  if (argc == 2) storageOwnershipBtrfsTests(suite, argv[1]);

  {
    Vector<MachineDiskHardwareProfile> disks;
    disks.push_back(makeDisk("/"));
    disks.push_back(makeDisk("/boot"));
    disks.push_back(makeDisk("/boot/efi"));
    disks.push_back(makeDisk("/efi"));

    Vector<String> mountPaths;
    prodigyCollectUniqueContainerStorageMountPaths(disks, mountPaths);
    Vector<ProdigyContainerStorageDevicePlan> devices;
    prodigyBuildContainerStorageDevicePlan(mountPaths, "1234"_ctv, 512, devices);

    suite.expect(mountPaths.empty(), "container_storage_boot_only_inventory_has_no_storage_mounts");
    suite.expect(devices.empty(), "container_storage_boot_only_inventory_preserves_direct_backend");
  }

  {
    Vector<MachineDiskHardwareProfile> disks;
    disks.push_back(makeDisk("/"));
    disks.push_back(makeDisk("/boot"));
    disks.push_back(makeDisk("/boot/efi"));
    disks.push_back(makeDisk("/efi"));
    disks.push_back(makeDisk("/containers"));
    disks.push_back(makeDisk("/mnt/data-b"));
    disks.push_back(makeDisk("/mnt/data-a"));
    disks.push_back(makeDisk("/mnt/data-b"));

    Vector<String> mountPaths;
    prodigyCollectUniqueContainerStorageMountPaths(disks, mountPaths);

    suite.expect(mountPaths.size() == 2, "container_storage_mount_paths_filter_reserved_and_dedupe");
    suite.expect(mountPaths[0] == "/mnt/data-a"_ctv, "container_storage_mount_paths_sorts_first");
    suite.expect(mountPaths[1] == "/mnt/data-b"_ctv, "container_storage_mount_paths_sorts_second");

    Vector<ProdigyContainerStorageDevicePlan> devices;
    prodigyBuildContainerStorageDevicePlan(mountPaths, "1234"_ctv, 512, devices);
    suite.expect(devices.size() == 2, "container_storage_mixed_boot_inventory_keeps_data_devices");
    if (devices.size() == 2)
    {
      suite.expect(devices[0].backingFilePath == "/mnt/data-a/.prodigy/container-storage/1234.btrfs.loop"_ctv &&
                       devices[1].backingFilePath == "/mnt/data-b/.prodigy/container-storage/1234.btrfs.loop"_ctv &&
                       devices[0].sizeMB == 256 && devices[1].sizeMB == 256,
                   "container_storage_mixed_boot_inventory_preserves_data_backing_layout");
    }
  }

  suite.expect(prodigySelectContainerStorageDeviceCount(64, 4) == 0, "container_storage_device_count_rejects_too_small_total");
  suite.expect(prodigySelectContainerStorageDeviceCount(128, 4) == 1, "container_storage_device_count_single_device_floor");
  suite.expect(prodigySelectContainerStorageDeviceCount(300, 3) == 2, "container_storage_device_count_limits_by_minimum_device_size");
  suite.expect(prodigySelectContainerStorageDeviceCount(768, 5) == 5, "container_storage_device_count_uses_all_when_large_enough");

  {
    Vector<String> mountPaths;
    mountPaths.push_back("/mnt/a"_ctv);
    mountPaths.push_back("/mnt/b"_ctv);
    mountPaths.push_back("/mnt/c"_ctv);

    Vector<ProdigyContainerStorageDevicePlan> devices;
    prodigyBuildContainerStorageDevicePlan(mountPaths, "1234"_ctv, 300, devices);

    suite.expect(devices.size() == 2, "container_storage_plan_chooses_two_devices");
    suite.expect(devices[0].mountPath == "/mnt/a"_ctv, "container_storage_plan_first_mount_path");
    suite.expect(devices[1].mountPath == "/mnt/b"_ctv, "container_storage_plan_second_mount_path");
    suite.expect(devices[0].sizeMB == 150, "container_storage_plan_first_size");
    suite.expect(devices[1].sizeMB == 150, "container_storage_plan_second_size");
    suite.expect(devices[0].backingFilePath == "/mnt/a/.prodigy/container-storage/1234.btrfs.loop"_ctv, "container_storage_plan_first_backing_path");
    suite.expect(devices[1].backingFilePath == "/mnt/b/.prodigy/container-storage/1234.btrfs.loop"_ctv, "container_storage_plan_second_backing_path");
  }

  {
    Vector<uint64_t> perDeviceMB;
    bool split = prodigySplitContainerStorageAcrossDevices(385, 3, perDeviceMB);
    suite.expect(split, "container_storage_split_succeeds");
    suite.expect(perDeviceMB.size() == 3, "container_storage_split_count");
    suite.expect(perDeviceMB[0] == 129, "container_storage_split_first_remainder");
    suite.expect(perDeviceMB[1] == 128, "container_storage_split_second_remainder");
    suite.expect(perDeviceMB[2] == 128, "container_storage_split_third_remainder");
  }

  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
