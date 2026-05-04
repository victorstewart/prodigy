#include <networking/includes.h>
#include <services/debug.h>

#include <prodigy/neuron/container.storage.layout.h>

#include <cstdio>
#include <cstdlib>

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

static MachineDiskHardwareProfile makeDisk(const char *mountPath)
{
   MachineDiskHardwareProfile disk = {};
   disk.mountPath.assign(mountPath);
   return disk;
}

int main(void)
{
   TestSuite suite = {};

   {
      Vector<MachineDiskHardwareProfile> disks;
      disks.push_back(makeDisk("/"));
      disks.push_back(makeDisk("/boot"));
      disks.push_back(makeDisk("/containers"));
      disks.push_back(makeDisk("/mnt/data-b"));
      disks.push_back(makeDisk("/mnt/data-a"));
      disks.push_back(makeDisk("/mnt/data-b"));

      Vector<String> mountPaths;
      prodigyCollectUniqueContainerStorageMountPaths(disks, mountPaths);

      suite.expect(mountPaths.size() == 2, "container_storage_mount_paths_filter_reserved_and_dedupe");
      suite.expect(mountPaths[0] == "/mnt/data-a"_ctv, "container_storage_mount_paths_sorts_first");
      suite.expect(mountPaths[1] == "/mnt/data-b"_ctv, "container_storage_mount_paths_sorts_second");
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
