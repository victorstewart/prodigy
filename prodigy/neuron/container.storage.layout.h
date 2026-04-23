#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>

#include <prodigy/machine.hardware.types.h>

static constexpr uint32_t prodigyContainerStorageLoopMinimumDeviceMB = 128;

class ProdigyContainerStorageDevicePlan {
public:

   String mountPath;
   String backingFilePath;
   uint64_t sizeMB = 0;
};

static inline bool prodigyContainerStorageMountPathIsReserved(const String& mountPath)
{
   if (mountPath.size() == 0 || mountPath.equal("/"_ctv) || mountPath.equal("/boot"_ctv) || mountPath.equal("/boot/efi"_ctv))
   {
      return true;
   }

   static constexpr char containersPrefix[] = "/containers";
   size_t prefixLength = sizeof(containersPrefix) - 1;
   if (mountPath.size() >= prefixLength && memcmp(mountPath.data(), containersPrefix, prefixLength) == 0)
   {
      if (mountPath.size() == prefixLength || mountPath[prefixLength] == '/')
      {
         return true;
      }
   }

   return false;
}

static inline void prodigyCollectUniqueContainerStorageMountPaths(const Vector<MachineDiskHardwareProfile>& disks, Vector<String>& mountPaths)
{
   mountPaths.clear();

   for (const MachineDiskHardwareProfile& disk : disks)
   {
      if (prodigyContainerStorageMountPathIsReserved(disk.mountPath))
      {
         continue;
      }

      bool duplicate = false;
      for (const String& existing : mountPaths)
      {
         if (existing.equals(disk.mountPath))
         {
            duplicate = true;
            break;
         }
      }

      if (duplicate == false)
      {
         mountPaths.push_back(disk.mountPath);
      }
   }

   std::sort(mountPaths.begin(), mountPaths.end(), [] (const String& lhs, const String& rhs) -> bool {
      size_t common = std::min(lhs.size(), rhs.size());
      int cmp = memcmp(lhs.data(), rhs.data(), common);
      if (cmp != 0)
      {
         return cmp < 0;
      }

      return lhs.size() < rhs.size();
   });
}

static inline uint32_t prodigySelectContainerStorageDeviceCount(uint32_t targetStorageMB, uint32_t availableMountCount)
{
   if (targetStorageMB == 0 || availableMountCount == 0)
   {
      return 0;
   }

   uint32_t maxDevicesByMinimumSize = targetStorageMB / prodigyContainerStorageLoopMinimumDeviceMB;
   if (maxDevicesByMinimumSize == 0)
   {
      return 0;
   }

   return std::min(availableMountCount, maxDevicesByMinimumSize);
}

static inline bool prodigySplitContainerStorageAcrossDevices(uint32_t targetStorageMB, uint32_t deviceCount, Vector<uint64_t>& perDeviceMB)
{
   perDeviceMB.clear();

   if (targetStorageMB == 0 || deviceCount == 0)
   {
      return false;
   }

   perDeviceMB.reserve(deviceCount);

   uint64_t base = targetStorageMB / deviceCount;
   uint32_t remainder = targetStorageMB % deviceCount;

   for (uint32_t index = 0; index < deviceCount; ++index)
   {
      uint64_t sizeMB = base;
      if (index < remainder)
      {
         sizeMB += 1;
      }

      perDeviceMB.push_back(sizeMB);
   }

   return true;
}

static inline void prodigyContainerStorageRootPathForName(const String& containerName, String& path)
{
   path.snprintf<"/containers/storage/{}"_ctv>(containerName);
}

static inline void prodigyContainerStoragePayloadPathForName(const String& containerName, String& path)
{
   path.snprintf<"/containers/storage/{}/data"_ctv>(containerName);
}

static inline void prodigyContainerStorageBackingFilePathForMount(const String& mountPath, const String& containerName, String& path)
{
   path.snprintf<"{}/.prodigy/container-storage/{}.btrfs.loop"_ctv>(mountPath, containerName);
}

static inline void prodigyBuildContainerStorageDevicePlan(const Vector<String>& mountPaths, const String& containerName, uint32_t targetStorageMB, Vector<ProdigyContainerStorageDevicePlan>& devices)
{
   devices.clear();

   uint32_t deviceCount = prodigySelectContainerStorageDeviceCount(targetStorageMB, uint32_t(mountPaths.size()));
   if (deviceCount == 0)
   {
      return;
   }

   Vector<uint64_t> perDeviceMB;
   if (prodigySplitContainerStorageAcrossDevices(targetStorageMB, deviceCount, perDeviceMB) == false)
   {
      return;
   }

   devices.reserve(deviceCount);

   for (uint32_t index = 0; index < deviceCount; ++index)
   {
      ProdigyContainerStorageDevicePlan plan = {};
      plan.mountPath = mountPaths[index];
      prodigyContainerStorageBackingFilePathForMount(plan.mountPath, containerName, plan.backingFilePath);
      plan.sizeMB = perDeviceMB[index];
      devices.push_back(std::move(plan));
   }
}
