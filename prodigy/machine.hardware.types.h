#pragma once

#include <networking/includes.h>
#include <services/bitsery.h>
#include <networking/ip.h>
#include <types/types.containers.h>

enum class MachineMemoryTechnology : uint8_t {

   unknown = 0,
   ddr4 = 1,
   ddr5 = 2
};

enum class MachineCpuArchitecture : uint8_t {

   unknown = 0,
   x86_64 = 1,
   aarch64 = 2,
   arm = 3,
   riscv64 = 4
};

enum class MachineDiskKind : uint8_t {

   unknown = 0,
   nvme = 1,
   ssd = 2,
   hdd = 3
};

enum class MachineDiskBus : uint8_t {

   unknown = 0,
   sata = 1,
   pcie = 2,
   virtio = 3,
   scsi = 4,
   usb = 5
};

enum class MachineDiskFormFactor : uint8_t {

   unknown = 0,
   m2 = 1,
   u2 = 2,
   addin = 3,
   sata25 = 4,
   sata35 = 5
};

class MachineToolCapture
{
public:

   String tool;
   String phase;
   String command;
   String output;
   String failure;
   int32_t exitCode = 0;
   bool attempted = false;
   bool succeeded = false;

   bool operator==(const MachineToolCapture& other) const
   {
      return tool.equals(other.tool)
         && phase.equals(other.phase)
         && command.equals(other.command)
         && output.equals(other.output)
         && failure.equals(other.failure)
         && exitCode == other.exitCode
         && attempted == other.attempted
         && succeeded == other.succeeded;
   }

   bool operator!=(const MachineToolCapture& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, MachineToolCapture& capture)
{
   serializer.text1b(capture.tool, UINT32_MAX);
   serializer.text1b(capture.phase, UINT32_MAX);
   serializer.text1b(capture.command, UINT32_MAX);
   serializer.text1b(capture.output, UINT32_MAX);
   serializer.text1b(capture.failure, UINT32_MAX);
   serializer.value4b(capture.exitCode);
   serializer.value1b(capture.attempted);
   serializer.value1b(capture.succeeded);
}

class MachineCpuHardwareProfile {
public:

   String vendor;
   String model;
   MachineCpuArchitecture architecture = MachineCpuArchitecture::unknown;
   String architectureVersion;
   Vector<String> isaFeatures;
   uint32_t logicalCores = 0;
   uint32_t physicalCores = 0;
   uint32_t sockets = 0;
   uint32_t numaNodes = 0;
   uint32_t threadsPerCore = 0;
   uint32_t l3CacheMB = 0;
   uint64_t singleThreadScore = 0;
   uint64_t multiThreadScore = 0;
   Vector<MachineToolCapture> captures;

   bool operator==(const MachineCpuHardwareProfile& other) const
   {
      if (isaFeatures.size() != other.isaFeatures.size() || captures.size() != other.captures.size())
      {
         return false;
      }

      for (uint32_t i = 0; i < isaFeatures.size(); ++i)
      {
         if (isaFeatures[i].equals(other.isaFeatures[i]) == false)
         {
            return false;
         }
      }

      for (uint32_t i = 0; i < captures.size(); ++i)
      {
         if (captures[i] != other.captures[i])
         {
            return false;
         }
      }

      return vendor.equals(other.vendor)
         && model.equals(other.model)
         && architecture == other.architecture
         && architectureVersion.equals(other.architectureVersion)
         && logicalCores == other.logicalCores
         && physicalCores == other.physicalCores
         && sockets == other.sockets
         && numaNodes == other.numaNodes
         && threadsPerCore == other.threadsPerCore
         && l3CacheMB == other.l3CacheMB
         && singleThreadScore == other.singleThreadScore
         && multiThreadScore == other.multiThreadScore;
   }

   bool operator!=(const MachineCpuHardwareProfile& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, MachineCpuHardwareProfile& profile)
{
   serializer.text1b(profile.vendor, UINT32_MAX);
   serializer.text1b(profile.model, UINT32_MAX);
   serializer.value1b(profile.architecture);
   serializer.text1b(profile.architectureVersion, UINT32_MAX);
   serializer.container(profile.isaFeatures, UINT32_MAX);
   serializer.value4b(profile.logicalCores);
   serializer.value4b(profile.physicalCores);
   serializer.value4b(profile.sockets);
   serializer.value4b(profile.numaNodes);
   serializer.value4b(profile.threadsPerCore);
   serializer.value4b(profile.l3CacheMB);
   serializer.value8b(profile.singleThreadScore);
   serializer.value8b(profile.multiThreadScore);
   serializer.container(profile.captures, UINT32_MAX);
}

class MachineMemoryModuleHardwareProfile {
public:

   String locator;
   String manufacturer;
   String partNumber;
   String serial;
   uint32_t sizeMB = 0;
   uint32_t speedMTps = 0;
   MachineMemoryTechnology technology = MachineMemoryTechnology::unknown;

   bool operator==(const MachineMemoryModuleHardwareProfile& other) const
   {
      return locator.equals(other.locator)
         && manufacturer.equals(other.manufacturer)
         && partNumber.equals(other.partNumber)
         && serial.equals(other.serial)
         && sizeMB == other.sizeMB
         && speedMTps == other.speedMTps
         && technology == other.technology;
   }

   bool operator!=(const MachineMemoryModuleHardwareProfile& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, MachineMemoryModuleHardwareProfile& profile)
{
   serializer.text1b(profile.locator, UINT32_MAX);
   serializer.text1b(profile.manufacturer, UINT32_MAX);
   serializer.text1b(profile.partNumber, UINT32_MAX);
   serializer.text1b(profile.serial, UINT32_MAX);
   serializer.value4b(profile.sizeMB);
   serializer.value4b(profile.speedMTps);
   serializer.value1b(profile.technology);
}

class MachineMemoryHardwareProfile {
public:

   uint32_t totalMB = 0;
   MachineMemoryTechnology technology = MachineMemoryTechnology::unknown;
   Vector<MachineMemoryModuleHardwareProfile> modules;
   uint32_t latencyNs = 0;
   uint32_t readBandwidthMBps = 0;
   uint32_t writeBandwidthMBps = 0;
   Vector<MachineToolCapture> captures;

   bool operator==(const MachineMemoryHardwareProfile& other) const
   {
      if (modules.size() != other.modules.size() || captures.size() != other.captures.size())
      {
         return false;
      }

      for (uint32_t i = 0; i < modules.size(); ++i)
      {
         if (modules[i] != other.modules[i])
         {
            return false;
         }
      }

      for (uint32_t i = 0; i < captures.size(); ++i)
      {
         if (captures[i] != other.captures[i])
         {
            return false;
         }
      }

      return totalMB == other.totalMB
         && technology == other.technology
         && latencyNs == other.latencyNs
         && readBandwidthMBps == other.readBandwidthMBps
         && writeBandwidthMBps == other.writeBandwidthMBps;
   }

   bool operator!=(const MachineMemoryHardwareProfile& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, MachineMemoryHardwareProfile& profile)
{
   serializer.value4b(profile.totalMB);
   serializer.value1b(profile.technology);
   serializer.container(profile.modules, UINT32_MAX);
   serializer.value4b(profile.latencyNs);
   serializer.value4b(profile.readBandwidthMBps);
   serializer.value4b(profile.writeBandwidthMBps);
   serializer.container(profile.captures, UINT32_MAX);
}

class MachineDiskBenchmarkProfile {
public:

   uint32_t sequentialReadMBps = 0;
   uint32_t sequentialWriteMBps = 0;
   uint32_t randomReadIops = 0;
   uint32_t randomWriteIops = 0;
   uint32_t randomReadLatencyP50Us = 0;
   uint32_t randomReadLatencyP95Us = 0;
   uint32_t randomReadLatencyP99Us = 0;
   uint32_t randomReadLatencyP999Us = 0;
   uint32_t randomWriteLatencyP50Us = 0;
   uint32_t randomWriteLatencyP95Us = 0;
   uint32_t randomWriteLatencyP99Us = 0;
   uint32_t randomWriteLatencyP999Us = 0;
   String failure;
   Vector<MachineToolCapture> captures;

   bool operator==(const MachineDiskBenchmarkProfile& other) const
   {
      if (captures.size() != other.captures.size())
      {
         return false;
      }

      for (uint32_t i = 0; i < captures.size(); ++i)
      {
         if (captures[i] != other.captures[i])
         {
            return false;
         }
      }

      return sequentialReadMBps == other.sequentialReadMBps
         && sequentialWriteMBps == other.sequentialWriteMBps
         && randomReadIops == other.randomReadIops
         && randomWriteIops == other.randomWriteIops
         && randomReadLatencyP50Us == other.randomReadLatencyP50Us
         && randomReadLatencyP95Us == other.randomReadLatencyP95Us
         && randomReadLatencyP99Us == other.randomReadLatencyP99Us
         && randomReadLatencyP999Us == other.randomReadLatencyP999Us
         && randomWriteLatencyP50Us == other.randomWriteLatencyP50Us
         && randomWriteLatencyP95Us == other.randomWriteLatencyP95Us
         && randomWriteLatencyP99Us == other.randomWriteLatencyP99Us
         && randomWriteLatencyP999Us == other.randomWriteLatencyP999Us
         && failure.equals(other.failure);
   }

   bool operator!=(const MachineDiskBenchmarkProfile& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, MachineDiskBenchmarkProfile& profile)
{
   serializer.value4b(profile.sequentialReadMBps);
   serializer.value4b(profile.sequentialWriteMBps);
   serializer.value4b(profile.randomReadIops);
   serializer.value4b(profile.randomWriteIops);
   serializer.value4b(profile.randomReadLatencyP50Us);
   serializer.value4b(profile.randomReadLatencyP95Us);
   serializer.value4b(profile.randomReadLatencyP99Us);
   serializer.value4b(profile.randomReadLatencyP999Us);
   serializer.value4b(profile.randomWriteLatencyP50Us);
   serializer.value4b(profile.randomWriteLatencyP95Us);
   serializer.value4b(profile.randomWriteLatencyP99Us);
   serializer.value4b(profile.randomWriteLatencyP999Us);
   serializer.text1b(profile.failure, UINT32_MAX);
   serializer.container(profile.captures, UINT32_MAX);
}

class MachineDiskHardwareProfile {
public:

   String name;
   String path;
   String model;
   String serial;
   String wwn;
   MachineDiskKind kind = MachineDiskKind::unknown;
   MachineDiskBus bus = MachineDiskBus::unknown;
   MachineDiskFormFactor formFactor = MachineDiskFormFactor::unknown;
   String pcieLink;
   uint32_t pcieGeneration = 0;
   uint32_t pcieLanes = 0;
   uint32_t logicalSectorBytes = 0;
   uint32_t physicalSectorBytes = 0;
   uint64_t sizeMB = 0;
   String mountPath;
   MachineDiskBenchmarkProfile benchmark;
   Vector<MachineToolCapture> captures;

   bool operator==(const MachineDiskHardwareProfile& other) const
   {
      if (captures.size() != other.captures.size())
      {
         return false;
      }

      for (uint32_t i = 0; i < captures.size(); ++i)
      {
         if (captures[i] != other.captures[i])
         {
            return false;
         }
      }

      return name.equals(other.name)
         && path.equals(other.path)
         && model.equals(other.model)
         && serial.equals(other.serial)
         && wwn.equals(other.wwn)
         && kind == other.kind
         && bus == other.bus
         && formFactor == other.formFactor
         && pcieLink.equals(other.pcieLink)
         && pcieGeneration == other.pcieGeneration
         && pcieLanes == other.pcieLanes
         && logicalSectorBytes == other.logicalSectorBytes
         && physicalSectorBytes == other.physicalSectorBytes
         && sizeMB == other.sizeMB
         && mountPath.equals(other.mountPath)
         && benchmark == other.benchmark;
   }

   bool operator!=(const MachineDiskHardwareProfile& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, MachineDiskHardwareProfile& profile)
{
   serializer.text1b(profile.name, UINT32_MAX);
   serializer.text1b(profile.path, UINT32_MAX);
   serializer.text1b(profile.model, UINT32_MAX);
   serializer.text1b(profile.serial, UINT32_MAX);
   serializer.text1b(profile.wwn, UINT32_MAX);
   serializer.value1b(profile.kind);
   serializer.value1b(profile.bus);
   serializer.value1b(profile.formFactor);
   serializer.text1b(profile.pcieLink, UINT32_MAX);
   serializer.value4b(profile.pcieGeneration);
   serializer.value4b(profile.pcieLanes);
   serializer.value4b(profile.logicalSectorBytes);
   serializer.value4b(profile.physicalSectorBytes);
   serializer.value8b(profile.sizeMB);
   serializer.text1b(profile.mountPath, UINT32_MAX);
   serializer.object(profile.benchmark);
   serializer.container(profile.captures, UINT32_MAX);
}

class MachineNicSubnetHardwareProfile {
public:

   IPAddress address;
   IPPrefix subnet;
   IPAddress gateway;
   bool internetReachable = false;

   bool operator==(const MachineNicSubnetHardwareProfile& other) const
   {
      return address.equals(other.address)
         && subnet.equals(other.subnet)
         && gateway.equals(other.gateway)
         && internetReachable == other.internetReachable;
   }

   bool operator!=(const MachineNicSubnetHardwareProfile& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, MachineNicSubnetHardwareProfile& profile)
{
   serializer.object(profile.address);
   serializer.object(profile.subnet);
   serializer.object(profile.gateway);
   serializer.value1b(profile.internetReachable);
}

class MachineNicHardwareProfile {
public:

   String name;
   String driver;
   String mac;
   String busAddress;
   String vendorID;
   String deviceID;
   String vendor;
   String model;
   uint32_t linkSpeedMbps = 0;
   bool up = false;
   Vector<MachineNicSubnetHardwareProfile> subnets;
   Vector<MachineToolCapture> captures;

   bool operator==(const MachineNicHardwareProfile& other) const
   {
      if (subnets.size() != other.subnets.size() || captures.size() != other.captures.size())
      {
         return false;
      }

      for (uint32_t i = 0; i < subnets.size(); ++i)
      {
         if (subnets[i] != other.subnets[i])
         {
            return false;
         }
      }

      for (uint32_t i = 0; i < captures.size(); ++i)
      {
         if (captures[i] != other.captures[i])
         {
            return false;
         }
      }

      return name.equals(other.name)
         && driver.equals(other.driver)
         && mac.equals(other.mac)
         && busAddress.equals(other.busAddress)
         && vendorID.equals(other.vendorID)
         && deviceID.equals(other.deviceID)
         && vendor.equals(other.vendor)
         && model.equals(other.model)
         && linkSpeedMbps == other.linkSpeedMbps
         && up == other.up;
   }

   bool operator!=(const MachineNicHardwareProfile& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, MachineNicHardwareProfile& profile)
{
   serializer.text1b(profile.name, UINT32_MAX);
   serializer.text1b(profile.driver, UINT32_MAX);
   serializer.text1b(profile.mac, UINT32_MAX);
   serializer.text1b(profile.busAddress, UINT32_MAX);
   serializer.text1b(profile.vendorID, UINT32_MAX);
   serializer.text1b(profile.deviceID, UINT32_MAX);
   serializer.text1b(profile.vendor, UINT32_MAX);
   serializer.text1b(profile.model, UINT32_MAX);
   serializer.value4b(profile.linkSpeedMbps);
   serializer.value1b(profile.up);
   serializer.container(profile.subnets, UINT32_MAX);
   serializer.container(profile.captures, UINT32_MAX);
}

class MachineInternetBenchmarkProfile {
public:

   bool attempted = false;
   String serverName;
   String interfaceName;
   IPAddress sourceAddress;
   uint32_t latencyMs = 0;
   uint32_t downloadMbps = 0;
   uint32_t uploadMbps = 0;
   String failure;
   Vector<MachineToolCapture> captures;

   bool operator==(const MachineInternetBenchmarkProfile& other) const
   {
      if (captures.size() != other.captures.size())
      {
         return false;
      }

      for (uint32_t i = 0; i < captures.size(); ++i)
      {
         if (captures[i] != other.captures[i])
         {
            return false;
         }
      }

      return attempted == other.attempted
         && serverName.equals(other.serverName)
         && interfaceName.equals(other.interfaceName)
         && sourceAddress.equals(other.sourceAddress)
         && latencyMs == other.latencyMs
         && downloadMbps == other.downloadMbps
         && uploadMbps == other.uploadMbps
         && failure.equals(other.failure);
   }

   bool operator!=(const MachineInternetBenchmarkProfile& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, MachineInternetBenchmarkProfile& profile)
{
   serializer.value1b(profile.attempted);
   serializer.text1b(profile.serverName, UINT32_MAX);
   serializer.text1b(profile.interfaceName, UINT32_MAX);
   serializer.object(profile.sourceAddress);
   serializer.value4b(profile.latencyMs);
   serializer.value4b(profile.downloadMbps);
   serializer.value4b(profile.uploadMbps);
   serializer.text1b(profile.failure, UINT32_MAX);
   serializer.container(profile.captures, UINT32_MAX);
}

class MachineNetworkHardwareProfile {
public:

   Vector<MachineNicHardwareProfile> nics;
   MachineInternetBenchmarkProfile internet;
   Vector<MachineToolCapture> captures;

   bool operator==(const MachineNetworkHardwareProfile& other) const
   {
      if (nics.size() != other.nics.size() || captures.size() != other.captures.size())
      {
         return false;
      }

      for (uint32_t i = 0; i < nics.size(); ++i)
      {
         if (nics[i] != other.nics[i])
         {
            return false;
         }
      }

      for (uint32_t i = 0; i < captures.size(); ++i)
      {
         if (captures[i] != other.captures[i])
         {
            return false;
         }
      }

      return internet == other.internet;
   }

   bool operator!=(const MachineNetworkHardwareProfile& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, MachineNetworkHardwareProfile& profile)
{
   serializer.container(profile.nics, UINT32_MAX);
   serializer.object(profile.internet);
   serializer.container(profile.captures, UINT32_MAX);
}

class MachineGpuHardwareProfile {
public:

   String vendor;
   String model;
   String busAddress;
   uint32_t memoryMB = 0;
   Vector<MachineToolCapture> captures;

   bool operator==(const MachineGpuHardwareProfile& other) const
   {
      if (captures.size() != other.captures.size())
      {
         return false;
      }

      for (uint32_t i = 0; i < captures.size(); ++i)
      {
         if (captures[i] != other.captures[i])
         {
            return false;
         }
      }

      return vendor.equals(other.vendor)
         && model.equals(other.model)
         && busAddress.equals(other.busAddress)
         && memoryMB == other.memoryMB;
   }

   bool operator!=(const MachineGpuHardwareProfile& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, MachineGpuHardwareProfile& profile)
{
   serializer.text1b(profile.vendor, UINT32_MAX);
   serializer.text1b(profile.model, UINT32_MAX);
   serializer.text1b(profile.busAddress, UINT32_MAX);
   serializer.value4b(profile.memoryMB);
   serializer.container(profile.captures, UINT32_MAX);
}

class MachineHardwareProfile {
public:

   MachineCpuHardwareProfile cpu;
   MachineMemoryHardwareProfile memory;
   Vector<MachineDiskHardwareProfile> disks;
   MachineNetworkHardwareProfile network;
   Vector<MachineGpuHardwareProfile> gpus;
   int64_t collectedAtMs = 0;
   bool inventoryComplete = false;
   bool benchmarksComplete = false;
   String inventoryFailure;
   String benchmarkFailure;
   Vector<MachineToolCapture> captures;

   bool operator==(const MachineHardwareProfile& other) const
   {
      if (disks.size() != other.disks.size()
         || gpus.size() != other.gpus.size()
         || captures.size() != other.captures.size())
      {
         return false;
      }

      for (uint32_t i = 0; i < disks.size(); ++i)
      {
         if (disks[i] != other.disks[i])
         {
            return false;
         }
      }

      for (uint32_t i = 0; i < gpus.size(); ++i)
      {
         if (gpus[i] != other.gpus[i])
         {
            return false;
         }
      }

      for (uint32_t i = 0; i < captures.size(); ++i)
      {
         if (captures[i] != other.captures[i])
         {
            return false;
         }
      }

      return cpu == other.cpu
         && memory == other.memory
         && network == other.network
         && collectedAtMs == other.collectedAtMs
         && inventoryComplete == other.inventoryComplete
         && benchmarksComplete == other.benchmarksComplete
         && inventoryFailure.equals(other.inventoryFailure)
         && benchmarkFailure.equals(other.benchmarkFailure);
   }

   bool operator!=(const MachineHardwareProfile& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, MachineHardwareProfile& profile)
{
   serializer.object(profile.cpu);
   serializer.object(profile.memory);
   serializer.container(profile.disks, UINT32_MAX);
   serializer.object(profile.network);
   serializer.container(profile.gpus, UINT32_MAX);
   serializer.value8b(profile.collectedAtMs);
   serializer.value1b(profile.inventoryComplete);
   serializer.value1b(profile.benchmarksComplete);
   serializer.text1b(profile.inventoryFailure, UINT32_MAX);
   serializer.text1b(profile.benchmarkFailure, UINT32_MAX);
   serializer.container(profile.captures, UINT32_MAX);
}

static inline bool prodigyMachineHardwareHasInternetAccess(const MachineHardwareProfile& hardware)
{
   return hardware.network.internet.attempted
      && hardware.network.internet.failure.size() == 0
      && hardware.network.internet.latencyMs > 0
      && hardware.network.internet.downloadMbps > 0
      && hardware.network.internet.uploadMbps > 0;
}
