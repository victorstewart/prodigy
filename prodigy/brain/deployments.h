#pragma once
#include <arpa/inet.h>
#include <services/debug.h>
#include <prodigy/brain/timing.knobs.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <malloc.h>
#include <limits>
#include <string>

struct ProdigyDeployHeapMetrics {
  uint64_t used = 0;
  uint64_t mapped = 0;
  uint64_t free = 0;
};

static inline bool prodigyDebugDeployHeapEnabled(void)
{
  static int enabled = []() -> int {
    const char *value = std::getenv("PRODIGY_DEBUG_DEPLOY_HEAP");
    return (value && value[0] == '1' && value[1] == '\0') ? 1 : 0;
  }();

  return (enabled != 0);
}

static inline ProdigyDeployHeapMetrics prodigyReadDeployHeapMetrics(void)
{
  struct mallinfo2 info = mallinfo2();

  ProdigyDeployHeapMetrics metrics = {};
  metrics.used = uint64_t(info.uordblks);
  metrics.mapped = uint64_t(info.arena) + uint64_t(info.hblkhd);
  metrics.free = uint64_t(info.fordblks);
  return metrics;
}

static inline void prodigyLogDeployHeapSnapshot(
    const char *phase,
    uint64_t deploymentID,
    uint32_t applicationID,
    uint64_t toSchedule,
    uint64_t waitingOnContainers,
    uint64_t containers,
    uint32_t nShardGroups,
    uint32_t nTargetBase,
    uint32_t nDeployed,
    uint32_t nHealthy,
    uint64_t aux0 = 0,
    uint64_t aux1 = 0)
{
  if (prodigyDebugDeployHeapEnabled() == false)
  {
    return;
  }

  const ProdigyDeployHeapMetrics heap = prodigyReadDeployHeapMetrics();
  std::fprintf(stderr,
               "prodigy debug deploy-heap phase=%s deploymentID=%llu appID=%u toSchedule=%llu waiting=%llu containers=%llu shardGroups=%u nTargetBase=%u nDeployed=%u nHealthy=%u aux0=%llu aux1=%llu heapUsed=%llu heapMapped=%llu heapFree=%llu\n",
               (phase ? phase : "unknown"),
               (unsigned long long)deploymentID,
               unsigned(applicationID),
               (unsigned long long)toSchedule,
               (unsigned long long)waitingOnContainers,
               (unsigned long long)containers,
               unsigned(nShardGroups),
               unsigned(nTargetBase),
               unsigned(nDeployed),
               unsigned(nHealthy),
               (unsigned long long)aux0,
               (unsigned long long)aux1,
               (unsigned long long)heap.used,
               (unsigned long long)heap.mapped,
               (unsigned long long)heap.free);
  std::fflush(stderr);
}

static bool metricNameMatchesLiteral(const String& metricName, const char *literal)
{
  if (literal == nullptr)
  {
    return false;
  }

  size_t literalLength = std::strlen(literal);
  if (metricName.size() != literalLength)
  {
    return false;
  }

  if (literalLength == 0)
  {
    return true;
  }

  return (std::memcmp(metricName.data(), literal, literalLength) == 0);
}

static bool isNeuronCollectableScalingDimension(ScalingDimension dimension)
{
  switch (dimension)
  {
    case ScalingDimension::cpu:
    case ScalingDimension::memory:
    case ScalingDimension::storage:
      {
        return true;
      }
    case ScalingDimension::runtimeIngressQueueWaitComposite:
    case ScalingDimension::runtimeIngressHandlerComposite:
    default:
      {
        return false;
      }
  }
}

static bool scalingDimensionForMetricName(const String& metricName, ScalingDimension& dimension)
{
  for (ScalingDimension candidate : {
           ScalingDimension::cpu,
           ScalingDimension::memory,
           ScalingDimension::storage,
           ScalingDimension::runtimeIngressQueueWaitComposite,
           ScalingDimension::runtimeIngressHandlerComposite})
  {
    const char *builtinName = ProdigyMetrics::nameForScalingDimension(candidate);
    if (metricNameMatchesLiteral(metricName, builtinName))
    {
      dimension = candidate;
      return true;
    }
  }

  return false;
}

static inline bool prodigyMachineReadyForScheduling(const Machine *machine)
{
  if (machine == nullptr || machine->state != MachineState::healthy)
  {
    return false;
  }

  // Some deployment-unit fixtures exercise pure placement math without a live
  // neuron/control-stream model. Keep those synthetic machines schedulable,
  // but require an explicit runtime-ready barrier once a machine is actually
  // under neuron control.
  if (machine->neuron.machine == nullptr && machine->neuron.connected == false)
  {
    return true;
  }

  return BrainBase::neuronControlStreamActive(machine) && machine->runtimeReady;
}

class MachineResourcesDelta {
public:

  int32_t nLogicalCores = 0;
  int32_t sharedCPUMillis = 0;
  int32_t nMemoryMB = 0;
  int32_t nStorageMB = 0;
  uint32_t isolatedLogicalCoresCommitted = 0;
  uint32_t sharedCPUMillisCommitted = 0;
  Vector<uint32_t> gpuMemoryMBs;
  Vector<AssignedGPUDevice> gpuDevices;
};

static bool resolveMachineWhiteholeInternetSourceAddressForDeployment(const Machine *machine, ExternalAddressFamily family, IPAddress& address, String *addressText = nullptr)
{
  address = {};
  if (addressText)
  {
    addressText->clear();
  }

  if (machine == nullptr)
  {
    return false;
  }

  if (prodigyResolveMachineInternetSourceAddress(*machine, family, address, addressText))
  {
    return true;
  }

  if (thisBrain == nullptr || thisBrain->brainConfig.runtimeEnvironment.test.enabled == false)
  {
    return false;
  }

  if (family == ExternalAddressFamily::ipv4 && thisBrain->brainConfig.runtimeEnvironment.test.enableFakeIpv4Boundary)
  {
    if (machine->private4 != 0)
    {
      address = {};
      address.is6 = false;
      address.v4 = machine->private4;
      if (addressText)
      {
        (void)ClusterMachine::renderIPAddressLiteral(address, *addressText);
      }
      return true;
    }
  }

  Vector<ClusterMachinePeerAddress> candidates = {};
  prodigyCollectMachinePeerAddresses(*machine, candidates);
  for (const ClusterMachinePeerAddress& candidate : candidates)
  {
    if (candidate.address.size() == 0)
    {
      continue;
    }

    IPAddress candidateAddress = {};
    if (ClusterMachine::parseIPAddressLiteral(candidate.address, candidateAddress) == false)
    {
      continue;
    }

    if (candidateAddress.isNull() || candidateAddress.is6 != (family == ExternalAddressFamily::ipv6))
    {
      continue;
    }

    address = candidateAddress;
    if (addressText)
    {
      addressText->assign(candidate.address);
    }
    return true;
  }

  return false;
}

static bool machineHasWhiteholeInternetAccessForDeployment(const Machine *machine, ExternalAddressFamily family)
{
  if (machine == nullptr)
  {
    return false;
  }

  if (machine->hasInternetAccess)
  {
    return true;
  }

  IPAddress resolvedAddress = {};
  return resolveMachineWhiteholeInternetSourceAddressForDeployment(machine, family, resolvedAddress);
}

static uint32_t applicationRequiredWholeGPUs(const ApplicationConfig& config)
{
  return config.minGPUs;
}

static uint32_t applicationRequiredGPUMemoryGB(const ApplicationConfig& config)
{
  return config.gpuMemoryGB;
}

static uint32_t applicationRequiredGPUMemoryMB(const ApplicationConfig& config)
{
  uint32_t requestedGB = applicationRequiredGPUMemoryGB(config);
  if (requestedGB == 0)
  {
    return 0;
  }

  return requestedGB * 1024u;
}

static uint16_t prodigySharedCPUOvercommitPermille(uint16_t configured)
{
  if (configured < prodigySharedCPUOvercommitMinPermille || configured > prodigySharedCPUOvercommitMaxPermille)
  {
    return prodigySharedCPUOvercommitMinPermille;
  }

  return configured;
}

static uint16_t prodigyActiveSharedCPUOvercommitPermille(void)
{
  if (thisBrain == nullptr)
  {
    return prodigySharedCPUOvercommitMinPermille;
  }

  return prodigySharedCPUOvercommitPermille(thisBrain->brainConfig.sharedCPUOvercommitPermille);
}

static void prodigyRecomputeMachineCPUAvailability(Machine *machine, uint16_t overcommitPermille)
{
  if (machine == nullptr)
  {
    return;
  }

  overcommitPermille = prodigySharedCPUOvercommitPermille(overcommitPermille);

  int64_t physicalFreeCores = int64_t(machine->ownedLogicalCores) - int64_t(machine->isolatedLogicalCoresCommitted);
  int64_t sharedCapacityMillis = physicalFreeCores * int64_t(overcommitPermille);
  int64_t sharedAvailableMillis = sharedCapacityMillis - int64_t(machine->sharedCPUMillisCommitted);
  int64_t isolatedAvailableCores = physicalFreeCores - int64_t(prodigyRoundUpDivideU64(machine->sharedCPUMillisCommitted, overcommitPermille));

  machine->nLogicalCores_available = int32_t(std::clamp<int64_t>(
      isolatedAvailableCores,
      int64_t(std::numeric_limits<int32_t>::min()),
      int64_t(std::numeric_limits<int32_t>::max())));
  machine->sharedCPUMillis_available = int32_t(std::clamp<int64_t>(
      sharedAvailableMillis,
      int64_t(std::numeric_limits<int32_t>::min()),
      int64_t(std::numeric_limits<int32_t>::max())));
}

static void prodigyAdjustMachineCPUCommitment(Machine *machine, const ApplicationConfig& config, int64_t count)
{
  if (machine == nullptr || count == 0)
  {
    return;
  }

  auto saturatingAddUnsigned = [](uint32_t current, int64_t delta) -> uint32_t {
    int64_t expanded = int64_t(current) + delta;
    if (expanded < 0)
    {
      expanded = 0;
    }
    else if (expanded > int64_t(UINT32_MAX))
    {
      expanded = int64_t(UINT32_MAX);
    }

    return uint32_t(expanded);
  };

  if (applicationUsesSharedCPUs(config))
  {
    machine->sharedCPUMillisCommitted = saturatingAddUnsigned(
        machine->sharedCPUMillisCommitted,
        count * int64_t(applicationRequestedCPUMillis(config)));
  }
  else
  {
    machine->isolatedLogicalCoresCommitted = saturatingAddUnsigned(
        machine->isolatedLogicalCoresCommitted,
        count * int64_t(applicationRequiredIsolatedCores(config)));
  }

  prodigyRecomputeMachineCPUAvailability(machine, prodigyActiveSharedCPUOvercommitPermille());
}

static void prodigyApplyPlannedMachineScalarDelta(MachineResourcesDelta& deltas, const ApplicationConfig& config, int64_t count)
{
  if (count == 0)
  {
    return;
  }

  auto saturatingAddSigned32 = [](int32_t current, int64_t delta) -> int32_t {
    int64_t expanded = int64_t(current) + delta;
    if (expanded < int64_t(std::numeric_limits<int32_t>::min()))
    {
      expanded = int64_t(std::numeric_limits<int32_t>::min());
    }
    else if (expanded > int64_t(std::numeric_limits<int32_t>::max()))
    {
      expanded = int64_t(std::numeric_limits<int32_t>::max());
    }

    return int32_t(expanded);
  };

  if (applicationUsesSharedCPUs(config))
  {
    deltas.sharedCPUMillis = saturatingAddSigned32(
        deltas.sharedCPUMillis,
        -count * int64_t(applicationRequestedCPUMillis(config)));
  }
  else
  {
    deltas.nLogicalCores = saturatingAddSigned32(
        deltas.nLogicalCores,
        -count * int64_t(applicationRequiredIsolatedCores(config)));
  }

  deltas.nMemoryMB = saturatingAddSigned32(
      deltas.nMemoryMB,
      -count * int64_t(config.totalMemoryMB()));
  deltas.nStorageMB = saturatingAddSigned32(
      deltas.nStorageMB,
      -count * int64_t(config.totalStorageMB()));
}

static void prodigyComputeEffectiveMachineCPUAvailability(
    const Machine *machine,
    const MachineResourcesDelta *deltas,
    uint64_t& isolatedAvailableCores,
    uint64_t& sharedAvailableMillis)
{
  isolatedAvailableCores = 0;
  sharedAvailableMillis = 0;

  if (machine == nullptr)
  {
    return;
  }

  int64_t isolatedCommitted = int64_t(machine->isolatedLogicalCoresCommitted);
  int64_t sharedCommitted = int64_t(machine->sharedCPUMillisCommitted);
  if (deltas != nullptr)
  {
    isolatedCommitted -= int64_t(deltas->nLogicalCores);
    sharedCommitted -= int64_t(deltas->sharedCPUMillis);
  }

  if (isolatedCommitted < 0)
  {
    isolatedCommitted = 0;
  }
  if (sharedCommitted < 0)
  {
    sharedCommitted = 0;
  }

  uint16_t overcommitPermille = prodigyActiveSharedCPUOvercommitPermille();
  int64_t physicalFreeCores = int64_t(machine->ownedLogicalCores) - isolatedCommitted;
  if (physicalFreeCores < 0)
  {
    physicalFreeCores = 0;
  }

  int64_t sharedCapacityMillis = physicalFreeCores * int64_t(overcommitPermille);
  int64_t sharedAvailable = sharedCapacityMillis - sharedCommitted;
  if (sharedAvailable < 0)
  {
    sharedAvailable = 0;
  }

  int64_t isolatedAvailable = physicalFreeCores - int64_t(prodigyRoundUpDivideU64(uint64_t(sharedCommitted), overcommitPermille));
  if (isolatedAvailable < 0)
  {
    isolatedAvailable = 0;
  }

  isolatedAvailableCores = uint64_t(isolatedAvailable);
  sharedAvailableMillis = uint64_t(sharedAvailable);
}

static uint64_t prodigyEffectiveMachineScalarAvailability(
    int32_t available,
    const MachineResourcesDelta *deltas,
    int32_t MachineResourcesDelta::*member)
{
  int64_t effective = int64_t(available);
  if (deltas != nullptr)
  {
    effective += int64_t(deltas->*member);
  }

  if (effective < 0)
  {
    return 0;
  }

  return uint64_t(effective);
}

static bool prodigyMachineUsesCPUOvercommit(const Machine *machine, const MachineResourcesDelta *deltas = nullptr)
{
  if (machine == nullptr)
  {
    return false;
  }

  int64_t isolatedCommitted = int64_t(machine->isolatedLogicalCoresCommitted);
  int64_t sharedCommitted = int64_t(machine->sharedCPUMillisCommitted);
  if (deltas != nullptr)
  {
    isolatedCommitted -= int64_t(deltas->nLogicalCores);
    sharedCommitted -= int64_t(deltas->sharedCPUMillis);
  }

  if (isolatedCommitted < 0)
  {
    isolatedCommitted = 0;
  }
  if (sharedCommitted < 0)
  {
    sharedCommitted = 0;
  }

  int64_t physicalFreeCores = int64_t(machine->ownedLogicalCores) - isolatedCommitted;
  if (physicalFreeCores < 0)
  {
    physicalFreeCores = 0;
  }

  return sharedCommitted > (physicalFreeCores * int64_t(prodigyCPUUnitsPerCore));
}

static uint64_t prodigyMachineCPUOvercommitExcessMillis(const Machine *machine, const MachineResourcesDelta *deltas = nullptr)
{
  if (machine == nullptr)
  {
    return 0;
  }

  int64_t isolatedCommitted = int64_t(machine->isolatedLogicalCoresCommitted);
  int64_t sharedCommitted = int64_t(machine->sharedCPUMillisCommitted);
  if (deltas != nullptr)
  {
    isolatedCommitted -= int64_t(deltas->nLogicalCores);
    sharedCommitted -= int64_t(deltas->sharedCPUMillis);
  }

  if (isolatedCommitted < 0)
  {
    isolatedCommitted = 0;
  }
  if (sharedCommitted < 0)
  {
    sharedCommitted = 0;
  }

  int64_t physicalFreeCores = int64_t(machine->ownedLogicalCores) - isolatedCommitted;
  if (physicalFreeCores < 0)
  {
    physicalFreeCores = 0;
  }

  int64_t baselineSharedCapacity = physicalFreeCores * int64_t(prodigyCPUUnitsPerCore);
  if (sharedCommitted <= baselineSharedCapacity)
  {
    return 0;
  }

  return uint64_t(sharedCommitted - baselineSharedCapacity);
}

static bool prodigySharedCPUSchedulingMachineComesBefore(
    const Machine *lhs,
    const MachineResourcesDelta *lhsDeltas,
    const Machine *rhs,
    const MachineResourcesDelta *rhsDeltas)
{
  bool lhsOvercommitted = prodigyMachineUsesCPUOvercommit(lhs, lhsDeltas);
  bool rhsOvercommitted = prodigyMachineUsesCPUOvercommit(rhs, rhsDeltas);
  if (lhsOvercommitted != rhsOvercommitted)
  {
    return lhsOvercommitted == false;
  }

  uint64_t lhsIsolatedAvailable = 0;
  uint64_t lhsSharedAvailable = 0;
  prodigyComputeEffectiveMachineCPUAvailability(lhs, lhsDeltas, lhsIsolatedAvailable, lhsSharedAvailable);

  uint64_t rhsIsolatedAvailable = 0;
  uint64_t rhsSharedAvailable = 0;
  prodigyComputeEffectiveMachineCPUAvailability(rhs, rhsDeltas, rhsIsolatedAvailable, rhsSharedAvailable);

  if (lhsSharedAvailable != rhsSharedAvailable)
  {
    return lhsSharedAvailable > rhsSharedAvailable;
  }

  uint64_t lhsMemoryAvailable = prodigyEffectiveMachineScalarAvailability(lhs->memoryMB_available, lhsDeltas, &MachineResourcesDelta::nMemoryMB);
  uint64_t rhsMemoryAvailable = prodigyEffectiveMachineScalarAvailability(rhs->memoryMB_available, rhsDeltas, &MachineResourcesDelta::nMemoryMB);
  if (lhsMemoryAvailable != rhsMemoryAvailable)
  {
    return lhsMemoryAvailable > rhsMemoryAvailable;
  }

  uint64_t lhsStorageAvailable = prodigyEffectiveMachineScalarAvailability(lhs->storageMB_available, lhsDeltas, &MachineResourcesDelta::nStorageMB);
  uint64_t rhsStorageAvailable = prodigyEffectiveMachineScalarAvailability(rhs->storageMB_available, rhsDeltas, &MachineResourcesDelta::nStorageMB);
  if (lhsStorageAvailable != rhsStorageAvailable)
  {
    return lhsStorageAvailable > rhsStorageAvailable;
  }

  return prodigyMachineIdentityComesBefore(*lhs, *rhs);
}

static void prodigyAppendGPUMemoryMBs(Vector<uint32_t>& into, const Vector<uint32_t>& values)
{
  for (uint32_t value : values)
  {
    into.push_back(value);
  }
}

static void prodigyAppendAssignedGPUDevices(Vector<AssignedGPUDevice>& into, const Vector<AssignedGPUDevice>& values)
{
  for (const AssignedGPUDevice& value : values)
  {
    into.push_back(value);
  }
}

static AssignedGPUDevice prodigyAssignedGPUDeviceFromHardware(const MachineGpuHardwareProfile& gpu)
{
  AssignedGPUDevice assigned = {};
  assigned.vendor = gpu.vendor;
  assigned.model = gpu.model;
  assigned.busAddress = gpu.busAddress;
  assigned.memoryMB = gpu.memoryMB;
  return assigned;
}

static void prodigySortMachineAvailableGPUs(Machine *machine)
{
  if (machine == nullptr)
  {
    return;
  }

  std::sort(machine->availableGPUHardwareIndexes.begin(), machine->availableGPUHardwareIndexes.end(), [&](uint32_t lhs, uint32_t rhs) -> bool {
    const MachineGpuHardwareProfile& a = machine->hardware.gpus[lhs];
    const MachineGpuHardwareProfile& b = machine->hardware.gpus[rhs];
    if (a.memoryMB != b.memoryMB)
    {
      return a.memoryMB < b.memoryMB;
    }

    return std::lexicographical_compare(a.busAddress.data(), a.busAddress.data() + a.busAddress.size(),
                                        b.busAddress.data(), b.busAddress.data() + b.busAddress.size());
  });

  machine->availableGPUMemoryMBs.clear();
  for (uint32_t index : machine->availableGPUHardwareIndexes)
  {
    if (index < machine->hardware.gpus.size())
    {
      machine->availableGPUMemoryMBs.push_back(machine->hardware.gpus[index].memoryMB);
    }
  }
}

static bool prodigyAllocateWholeGPUSlots(
    Vector<uint32_t>& availableGPUMemoryMBs,
    Vector<uint32_t> *availableGPUHardwareIndexes,
    const Vector<MachineGpuHardwareProfile> *hardwareGPUs,
    uint32_t nGPUs,
    uint32_t minGPUMemoryMB,
    Vector<uint32_t>& assignedGPUMemoryMBs,
    Vector<AssignedGPUDevice> *assignedGPUDevices = nullptr)
{
  assignedGPUMemoryMBs.clear();
  if (assignedGPUDevices != nullptr)
  {
    assignedGPUDevices->clear();
  }

  if (nGPUs == 0)
  {
    return true;
  }

  Vector<uint32_t> selectedIndexes = {};
  for (uint32_t i = 0; i < availableGPUMemoryMBs.size(); ++i)
  {
    if (availableGPUMemoryMBs[i] < minGPUMemoryMB)
    {
      continue;
    }

    selectedIndexes.push_back(i);
    assignedGPUMemoryMBs.push_back(availableGPUMemoryMBs[i]);
    if (assignedGPUDevices != nullptr && availableGPUHardwareIndexes != nullptr && hardwareGPUs != nullptr && i < availableGPUHardwareIndexes->size())
    {
      uint32_t hardwareIndex = (*availableGPUHardwareIndexes)[i];
      if (hardwareIndex < hardwareGPUs->size())
      {
        assignedGPUDevices->push_back(prodigyAssignedGPUDeviceFromHardware((*hardwareGPUs)[hardwareIndex]));
      }
    }
    if (selectedIndexes.size() >= nGPUs)
    {
      break;
    }
  }

  if (selectedIndexes.size() < nGPUs)
  {
    assignedGPUMemoryMBs.clear();
    if (assignedGPUDevices != nullptr)
    {
      assignedGPUDevices->clear();
    }
    return false;
  }

  for (uint32_t cursor = selectedIndexes.size(); cursor > 0; --cursor)
  {
    uint32_t index = selectedIndexes[cursor - 1];
    availableGPUMemoryMBs.erase(availableGPUMemoryMBs.begin() + index);
    if (availableGPUHardwareIndexes != nullptr && index < availableGPUHardwareIndexes->size())
    {
      availableGPUHardwareIndexes->erase(availableGPUHardwareIndexes->begin() + index);
    }
  }

  return true;
}

static void prodigyReleaseWholeGPUSlots(Machine *machine, const Vector<uint32_t>& assignedGPUMemoryMBs, const Vector<AssignedGPUDevice> *assignedGPUDevices = nullptr)
{
  if (machine == nullptr || assignedGPUMemoryMBs.empty())
  {
    return;
  }

  bytell_hash_set<uint32_t> restoredIndexes = {};

  auto restoreIndex = [&](uint32_t index) -> void {
    if (restoredIndexes.contains(index) == false)
    {
      restoredIndexes.insert(index);
      machine->availableGPUHardwareIndexes.push_back(index);
    }
  };

  if (assignedGPUDevices != nullptr)
  {
    for (const AssignedGPUDevice& assigned : *assignedGPUDevices)
    {
      for (uint32_t index = 0; index < machine->hardware.gpus.size(); ++index)
      {
        if (machine->hardware.gpus[index].busAddress == assigned.busAddress)
        {
          restoreIndex(index);
          break;
        }
      }
    }
  }

  if (restoredIndexes.size() < assignedGPUMemoryMBs.size())
  {
    for (uint32_t memoryMB : assignedGPUMemoryMBs)
    {
      for (uint32_t index = 0; index < machine->hardware.gpus.size(); ++index)
      {
        if (restoredIndexes.contains(index))
        {
          continue;
        }

        bool alreadyAvailable = false;
        for (uint32_t availableIndex : machine->availableGPUHardwareIndexes)
        {
          if (availableIndex == index)
          {
            alreadyAvailable = true;
            break;
          }
        }

        if (alreadyAvailable == false && machine->hardware.gpus[index].memoryMB == memoryMB)
        {
          restoreIndex(index);
          break;
        }
      }
    }
  }

  if (machine->availableGPUHardwareIndexes.empty() == false)
  {
    prodigySortMachineAvailableGPUs(machine);
    return;
  }

  prodigyAppendGPUMemoryMBs(machine->availableGPUMemoryMBs, assignedGPUMemoryMBs);
  std::sort(machine->availableGPUMemoryMBs.begin(), machine->availableGPUMemoryMBs.end());
}

static uint32_t prodigyMachineMaxNicSpeedMbps(const Machine *machine)
{
  if (machine == nullptr)
  {
    return 0;
  }

  uint32_t speedMbps = 0;
  for (const MachineNicHardwareProfile& nic : machine->hardware.network.nics)
  {
    if (nic.linkSpeedMbps > speedMbps)
    {
      speedMbps = nic.linkSpeedMbps;
    }
  }

  return speedMbps;
}

static uint32_t prodigyMachineCountWholeGPUsMeetingMemory(const Machine *machine, uint32_t minimumMemoryMB)
{
  if (machine == nullptr)
  {
    return 0;
  }

  uint32_t count = 0;
  for (const MachineGpuHardwareProfile& gpu : machine->hardware.gpus)
  {
    if (gpu.memoryMB >= minimumMemoryMB)
    {
      count += 1;
    }
  }

  return count;
}

static bool prodigyMachineMeetsInternetBenchmarkCriteria(const Machine *machine, const ApplicationConfig& config)
{
  if (config.minInternetDownloadMbps == 0 && config.minInternetUploadMbps == 0 && config.maxInternetLatencyMs == 0)
  {
    return true;
  }

  if (machine == nullptr || machine->hasInternetAccess == false)
  {
    return false;
  }

  const MachineInternetBenchmarkProfile& benchmark = machine->hardware.network.internet;
  if (benchmark.attempted == false)
  {
    return false;
  }

  if (config.minInternetDownloadMbps > 0 && benchmark.downloadMbps < config.minInternetDownloadMbps)
  {
    return false;
  }

  if (config.minInternetUploadMbps > 0 && benchmark.uploadMbps < config.minInternetUploadMbps)
  {
    return false;
  }

  if (config.maxInternetLatencyMs > 0 && benchmark.latencyMs > config.maxInternetLatencyMs)
  {
    return false;
  }

  return true;
}

static bool prodigyMachineMeetsApplicationResourceCriteria(const Machine *machine, const ApplicationConfig& config)
{
  if (machine == nullptr)
  {
    return false;
  }

  MachineCpuArchitecture machineArchitecture = machine->hardware.cpu.architecture;
  if (machineArchitecture == MachineCpuArchitecture::unknown && thisBrain != nullptr && thisBrain->brainConfig.runtimeEnvironment.test.enabled && prodigyMachineReadyResourcesAvailable(*machine))
  {
    machineArchitecture = thisBrain->brainConfig.architecture;
  }

  if (config.architecture != MachineCpuArchitecture::unknown && machineArchitecture != config.architecture)
  {
    return false;
  }

  if (config.requiredIsaFeatures.empty() == false && prodigyIsaFeaturesMeetRequirements(machine->hardware.cpu.isaFeatures, config.requiredIsaFeatures) == false)
  {
    return false;
  }

  uint32_t requiredGPUs = applicationRequiredWholeGPUs(config);
  if (requiredGPUs > 0 && prodigyMachineCountWholeGPUsMeetingMemory(machine, applicationRequiredGPUMemoryMB(config)) < requiredGPUs)
  {
    return false;
  }

  uint64_t requiredNICSpeedMbps = uint64_t(config.nicSpeedGbps) * 1000u;
  if (requiredNICSpeedMbps > 0 && uint64_t(prodigyMachineMaxNicSpeedMbps(machine)) < requiredNICSpeedMbps)
  {
    return false;
  }

  if (prodigyMachineMeetsInternetBenchmarkCriteria(machine, config) == false)
  {
    return false;
  }

  return true;
}

static void prodigyDebitMachineScalarResources(Machine *machine, const ApplicationConfig& config, uint32_t count)
{
  if (machine == nullptr || count == 0)
  {
    return;
  }

  prodigyAdjustMachineCPUCommitment(machine, config, int64_t(count));
  machine->memoryMB_available -= int32_t(uint64_t(count) * uint64_t(config.totalMemoryMB()));
  machine->storageMB_available -= int32_t(uint64_t(count) * uint64_t(config.totalStorageMB()));
}

static void prodigyCreditMachineScalarResources(Machine *machine, const ApplicationConfig& config, uint32_t count)
{
  if (machine == nullptr || count == 0)
  {
    return;
  }

  prodigyAdjustMachineCPUCommitment(machine, config, -int64_t(count));
  machine->memoryMB_available += int32_t(uint64_t(count) * uint64_t(config.totalMemoryMB()));
  machine->storageMB_available += int32_t(uint64_t(count) * uint64_t(config.totalStorageMB()));
}

static bool prodigyReserveMachineGPUsForInstance(Machine *machine, const ApplicationConfig& config, Vector<uint32_t>& assignedGPUMemoryMBs, Vector<AssignedGPUDevice> *assignedGPUDevices = nullptr)
{
  if (machine == nullptr)
  {
    assignedGPUMemoryMBs.clear();
    if (assignedGPUDevices != nullptr)
    {
      assignedGPUDevices->clear();
    }
    return false;
  }

  return prodigyAllocateWholeGPUSlots(
      machine->availableGPUMemoryMBs,
      &machine->availableGPUHardwareIndexes,
      &machine->hardware.gpus,
      applicationRequiredWholeGPUs(config),
      applicationRequiredGPUMemoryMB(config),
      assignedGPUMemoryMBs,
      assignedGPUDevices);
}

static bool prodigyReserveMachineGPUsForInstances(Machine *machine, const ApplicationConfig& config, uint32_t count, Vector<uint32_t>& assignedGPUMemoryMBs, Vector<AssignedGPUDevice> *assignedGPUDevices = nullptr)
{
  assignedGPUMemoryMBs.clear();
  if (assignedGPUDevices != nullptr)
  {
    assignedGPUDevices->clear();
  }
  if (count == 0)
  {
    return true;
  }

  for (uint32_t i = 0; i < count; ++i)
  {
    Vector<uint32_t> perInstance = {};
    Vector<AssignedGPUDevice> perInstanceDevices = {};
    if (prodigyReserveMachineGPUsForInstance(machine, config, perInstance, &perInstanceDevices) == false)
    {
      prodigyReleaseWholeGPUSlots(machine, assignedGPUMemoryMBs, assignedGPUDevices);
      assignedGPUMemoryMBs.clear();
      if (assignedGPUDevices != nullptr)
      {
        assignedGPUDevices->clear();
      }
      return false;
    }

    prodigyAppendGPUMemoryMBs(assignedGPUMemoryMBs, perInstance);
    if (assignedGPUDevices != nullptr)
    {
      prodigyAppendAssignedGPUDevices(*assignedGPUDevices, perInstanceDevices);
    }
  }

  return true;
}

static void prodigyReleaseContainerGPUs(ContainerView *container)
{
  if (container == nullptr || container->machine == nullptr)
  {
    return;
  }

  if (container->assignedGPUMemoryMBs.empty())
  {
    return;
  }

  prodigyReleaseWholeGPUSlots(container->machine, container->assignedGPUMemoryMBs, &container->assignedGPUDevices);
  container->assignedGPUMemoryMBs.clear();
  container->assignedGPUDevices.clear();
}

static void prodigyConsumeAssignedGPUsFromMachineAvailability(
    Machine *machine,
    const Vector<uint32_t>& assignedGPUMemoryMBs,
    const Vector<AssignedGPUDevice>& assignedGPUDevices)
{
  if (machine == nullptr || assignedGPUMemoryMBs.empty())
  {
    return;
  }

  auto eraseMemoryOnly = [&](uint32_t memoryMB) -> void {
    if (auto it = std::find(machine->availableGPUMemoryMBs.begin(), machine->availableGPUMemoryMBs.end(), memoryMB); it != machine->availableGPUMemoryMBs.end())
    {
      machine->availableGPUMemoryMBs.erase(it);
    }
  };

  if (assignedGPUDevices.empty())
  {
    for (uint32_t memoryMB : assignedGPUMemoryMBs)
    {
      eraseMemoryOnly(memoryMB);
    }
    return;
  }

  for (const AssignedGPUDevice& assigned : assignedGPUDevices)
  {
    bool removed = false;
    for (auto it = machine->availableGPUHardwareIndexes.begin(); it != machine->availableGPUHardwareIndexes.end(); ++it)
    {
      uint32_t index = *it;
      if (index >= machine->hardware.gpus.size())
      {
        continue;
      }

      const MachineGpuHardwareProfile& gpu = machine->hardware.gpus[index];
      if (gpu.busAddress.equals(assigned.busAddress) == false)
      {
        continue;
      }

      machine->availableGPUHardwareIndexes.erase(it);
      eraseMemoryOnly(gpu.memoryMB);
      removed = true;
      break;
    }

    if (removed == false && assigned.memoryMB > 0)
    {
      eraseMemoryOnly(assigned.memoryMB);
    }
  }
}

static NeuronContainerMetricPolicy deriveNeuronMetricPolicyForDeployment(const DeploymentPlan& plan)
{
  NeuronContainerMetricPolicy policy;

  auto includeDimension = [&](ScalingDimension dimension) -> void {
    if (isNeuronCollectableScalingDimension(dimension))
    {
      policy.scalingDimensionsMask |= ProdigyMetrics::maskForScalingDimension(dimension);
    }
  };

  for (const HorizontalScaler& scaler : plan.horizontalScalers)
  {
    ScalingDimension dimension = ScalingDimension::cpu;
    if (scalingDimensionForMetricName(scaler.name, dimension))
    {
      includeDimension(dimension);
    }
  }

  for (const VerticalScaler& scaler : plan.verticalScalers)
  {
    includeDimension(scaler.resource);
  }

  if (policy.scalingDimensionsMask > 0)
  {
    policy.metricsCadenceMs = ProdigyMetrics::defaultNeuronCollectionCadenceMs;
  }

  return policy;
}

static const DistributableExternalSubnet *findWhiteholeRoutablePrefixForFamily(
    const BrainConfig& config,
    ExternalAddressFamily family,
    const Machine *machine = nullptr,
    uint128_t *requiredMachineUUID = nullptr)
{
  uint128_t required = 0;
  for (const DistributableExternalSubnet& subnet : config.distributableExternalSubnets)
  {
    if (distributableExternalSubnetMatchesFamily(subnet, family) == false)
    {
      continue;
    }

    if (distributableExternalSubnetAllowsWhiteholes(subnet) == false)
    {
      continue;
    }

    if (subnet.ingressScope == RoutableIngressScope::singleMachine)
    {
      if (subnet.machineUUID == 0)
      {
        continue;
      }
      if (machine != nullptr && subnet.machineUUID != machine->uuid)
      {
        if (required == 0)
        {
          required = subnet.machineUUID;
        }
        continue;
      }
      if (requiredMachineUUID)
      {
        *requiredMachineUUID = subnet.machineUUID;
      }
    }

    return &subnet;
  }

  if (requiredMachineUUID)
  {
    *requiredMachineUUID = required;
  }
  return nullptr;
}

enum class DeploymentTimeoutFlags : uint64_t {

  canariesMinimumLifetime,
  autoscale,
  shardGroupReady,
  statefulTopologyRollbackWindow
};

enum class LifecycleOp {

  none = 0,
  construct,
  updateInPlace,
  destruct
};

class CompactionTicket {
public:

  ApplicationDeployment *orchestrator = nullptr;
  bytell_hash_map<ApplicationDeployment *, uint32_t> pendingCompactions;
  bool waitingOnCompactions = false; // so deployments compacting for us know whether or not to wake us when final compaction completes
};

class DeploymentWork;

class WorkBase {
public:

  Machine *machine;
  ContainerView *oldContainer = 0; // destruct or update in place
  ContainerView *container = nullptr; // construct or update in place
  DeploymentWork *prev = nullptr;
  DeploymentWork *next = nullptr;

  LifecycleOp lifecycle;

  WorkBase() = default;
  WorkBase(LifecycleOp _lifecycle, Machine *_machine, ContainerView *_container, ContainerView *_oldContainer)
      : lifecycle(_lifecycle),
        machine(_machine),
        container(_container),
        oldContainer(_oldContainer)
  {}
  WorkBase(LifecycleOp _lifecycle, Machine *_machine, ContainerView *_container)
      : WorkBase(_lifecycle, _machine, _container, nullptr)
  {}
};

class StatelessWork : public WorkBase {
public:

  CompactionTicket *ticket = nullptr; // either a ticket for us to wait on compactions or a compaction

  StatelessWork(CompactionTicket *_ticket)
      : ticket(_ticket)
  {}

  StatelessWork(LifecycleOp _lifecycle, Machine *_machine, ContainerView *_container)
      : WorkBase(_lifecycle, _machine, _container)
  {
    // assert(lifecycle != LifecycleOp::construct, "StatelessWork() only LifecycleOp::construct valid for this constructor");
  }

  StatelessWork(LifecycleOp _lifecycle, ContainerView *_oldContainer)
      : WorkBase(_lifecycle, _oldContainer->machine, nullptr, _oldContainer)
  {
    // assert(lifecycle != LifecycleOp::destruct, "StatelessWork() only LifecycleOp::destruct valid for this constructor");
  }

  StatelessWork() = default; // needed so DeploymentWork has a default constructor
};

enum class DataStrategy : uint8_t {

  none = 0,
  genesis,
  changelog,
  seeding,
  sharding
};

class StatefulWork : public WorkBase {
public:

  DataStrategy data = DataStrategy::none; // if construct

  StatefulWork(LifecycleOp _lifecycle, Machine *_machine, ContainerView *_container, DataStrategy _data)
      : WorkBase(_lifecycle, _machine, _container),
        data(_data)
  {
    // static_assert(lifecycle != LifecycleOp::construct, "StatefulWork() only LifecycleOp::construct valid for this constructor");
  }

  StatefulWork(LifecycleOp _lifecycle, ContainerView *_oldContainer)
      : WorkBase(_lifecycle, _oldContainer->machine, nullptr, _oldContainer)
  {
    // static_assert(lifecycle != LifecycleOp::destruct, "StatefulWork() only LifecycleOp::destruct valid for this constructor");
  }

  StatefulWork(LifecycleOp _lifecycle, ContainerView *_container, ContainerView *_oldContainer)
      : WorkBase(_lifecycle, _container->machine, _container, _oldContainer),
        data(DataStrategy::changelog)
  {
    // static_assert(lifecycle != LifecycleOp::updateInPlace, "StatefulWork() only LifecycleOp::updateInPlace valid for this constructor");
  }

  StatefulWork() = default; // needed so DeploymentWork has a default constructor
};

class DeploymentWork : public std::variant<StatelessWork, StatefulWork> {
public:

  WorkBase *getBase(void)
  {
    return std::get_if<StatelessWork>(this) ? static_cast<WorkBase *>(std::get_if<StatelessWork>(this)) : static_cast<WorkBase *>(std::get_if<StatefulWork>(this));
  }
};

class CompoundSuspension {
public:

  CoroutineStack *execution = nullptr;
  std::vector<CoroutineStack *> waiters;

  CompoundSuspension(CoroutineStack *_execution, CoroutineStack *_waiter)
      : execution(_execution),
        waiters {_waiter}
  {}
  CompoundSuspension(CoroutineStack *_execution)
      : execution(_execution)
  {}
  CompoundSuspension() = default;
};

class MachineTicket {
public:

  CoroutineStack *coro;
  uint32_t nMore = 0; // nMore instances
  Vector<uint32_t> shardGroups; // at the beginning this is used the feed shard group into claims... then when consuming this is filled with shard group to schedule on that machine now
  Vector<uint32_t> placementTopologyEpochs;
  Vector<uint32_t> reservedGPUMemoryMBs;
  Vector<AssignedGPUDevice> reservedGPUDevices;

  Machine *machineNow = nullptr; // we set this and wake the coro
  uint32_t nNow = 0; // schedule n stateless onto machineNow
};

static bool prodigyReservePlanningGPUsForInstance(
    Machine *machine,
    MachineResourcesDelta *deltas,
    const ApplicationConfig& config,
    Vector<uint32_t>& assignedGPUMemoryMBs,
    Vector<AssignedGPUDevice>& assignedGPUDevices)
{
  assignedGPUMemoryMBs.clear();
  assignedGPUDevices.clear();

  uint32_t requiredGPUs = applicationRequiredWholeGPUs(config);
  if (requiredGPUs == 0)
  {
    return true;
  }

  if (machine == nullptr)
  {
    return false;
  }

  struct Candidate {
    bool fromDelta = false;
    uint32_t index = 0;
    uint32_t memoryMB = 0;
    AssignedGPUDevice device = {};
  };

  Vector<Candidate> candidates = {};
  uint32_t minimumMemoryMB = applicationRequiredGPUMemoryMB(config);

  if (deltas != nullptr)
  {
    for (uint32_t i = 0; i < deltas->gpuMemoryMBs.size(); ++i)
    {
      uint32_t memoryMB = deltas->gpuMemoryMBs[i];
      if (memoryMB >= minimumMemoryMB)
      {
        AssignedGPUDevice device = {};
        if (i < deltas->gpuDevices.size())
        {
          device = deltas->gpuDevices[i];
        }
        candidates.push_back(Candidate {true, i, memoryMB, device});
      }
    }
  }

  for (uint32_t i = 0; i < machine->availableGPUMemoryMBs.size(); ++i)
  {
    uint32_t memoryMB = machine->availableGPUMemoryMBs[i];
    if (memoryMB >= minimumMemoryMB)
    {
      AssignedGPUDevice device = {};
      if (i < machine->availableGPUHardwareIndexes.size())
      {
        uint32_t hardwareIndex = machine->availableGPUHardwareIndexes[i];
        if (hardwareIndex < machine->hardware.gpus.size())
        {
          device = prodigyAssignedGPUDeviceFromHardware(machine->hardware.gpus[hardwareIndex]);
        }
      }

      candidates.push_back(Candidate {false, i, memoryMB, device});
    }
  }

  std::sort(candidates.begin(), candidates.end(), [](const Candidate& lhs, const Candidate& rhs) -> bool {
    if (lhs.memoryMB != rhs.memoryMB)
    {
      return lhs.memoryMB < rhs.memoryMB;
    }

    if (lhs.fromDelta != rhs.fromDelta)
    {
      return lhs.fromDelta;
    }

    return lhs.index < rhs.index;
  });

  if (candidates.size() < requiredGPUs)
  {
    return false;
  }

  Vector<uint32_t> deltaIndexes = {};
  Vector<uint32_t> machineIndexes = {};

  for (uint32_t i = 0; i < requiredGPUs; ++i)
  {
    const Candidate& candidate = candidates[i];
    assignedGPUMemoryMBs.push_back(candidate.memoryMB);
    assignedGPUDevices.push_back(candidate.device);
    if (candidate.fromDelta)
    {
      deltaIndexes.push_back(candidate.index);
    }
    else
    {
      machineIndexes.push_back(candidate.index);
    }
  }

  std::sort(deltaIndexes.begin(), deltaIndexes.end(), std::greater<uint32_t> {});
  std::sort(machineIndexes.begin(), machineIndexes.end(), std::greater<uint32_t> {});

  if (deltas != nullptr)
  {
    for (uint32_t index : deltaIndexes)
    {
      deltas->gpuMemoryMBs.erase(deltas->gpuMemoryMBs.begin() + index);
      if (index < deltas->gpuDevices.size())
      {
        deltas->gpuDevices.erase(deltas->gpuDevices.begin() + index);
      }
    }
  }

  for (uint32_t index : machineIndexes)
  {
    machine->availableGPUMemoryMBs.erase(machine->availableGPUMemoryMBs.begin() + index);
    if (index < machine->availableGPUHardwareIndexes.size())
    {
      machine->availableGPUHardwareIndexes.erase(machine->availableGPUHardwareIndexes.begin() + index);
    }
  }

  return true;
}

static bool prodigyConsumeReservedMachineGPUsForInstance(Vector<uint32_t>& reservedGPUMemoryMBs, Vector<AssignedGPUDevice>& reservedGPUDevices, const ApplicationConfig& config, Vector<uint32_t>& assignedGPUMemoryMBs, Vector<AssignedGPUDevice>& assignedGPUDevices)
{
  assignedGPUMemoryMBs.clear();
  assignedGPUDevices.clear();

  uint32_t requiredGPUs = applicationRequiredWholeGPUs(config);
  if (requiredGPUs == 0)
  {
    return true;
  }

  if (reservedGPUMemoryMBs.size() < requiredGPUs || reservedGPUDevices.size() < requiredGPUs)
  {
    return false;
  }

  for (uint32_t i = 0; i < requiredGPUs; ++i)
  {
    assignedGPUMemoryMBs.push_back(reservedGPUMemoryMBs[0]);
    assignedGPUDevices.push_back(reservedGPUDevices[0]);
    reservedGPUMemoryMBs.erase(reservedGPUMemoryMBs.begin());
    reservedGPUDevices.erase(reservedGPUDevices.begin());
  }

  return true;
}

static bool prodigyTakeAssignedGPUsForScheduling(
    Machine *machine,
    MachineTicket *ticket,
    MachineResourcesDelta *deltas,
    const ApplicationConfig& config,
    Vector<uint32_t>& assignedGPUMemoryMBs,
    Vector<AssignedGPUDevice>& assignedGPUDevices)
{
  if (ticket != nullptr)
  {
    return prodigyConsumeReservedMachineGPUsForInstance(ticket->reservedGPUMemoryMBs, ticket->reservedGPUDevices, config, assignedGPUMemoryMBs, assignedGPUDevices);
  }

  return prodigyReservePlanningGPUsForInstance(machine, deltas, config, assignedGPUMemoryMBs, assignedGPUDevices);
}

class ApplicationDeployment : public TimeoutDispatcher {
private:

  static inline Pool<DeploymentWork, true> workPool;

  TimeoutPacket canaryTimer;
  TimeoutPacket shardTimer;
  TimeoutPacket autoscaleTimer;
  TimeoutPacket statefulWorkerTopologyRollbackTimer;

  uint64_t configuredAutoscalePeriodSeconds(void) const
  {
    const uint32_t configuredSeconds = thisBrain->brainConfig.autoscaleIntervalSeconds;
    if (configuredSeconds == 0 || configuredSeconds > 86'400)
    {
      return 180;
    }

    return configuredSeconds;
  }

  void setCanaryTimeout(void)
  {
    bool resetting = canaryTimer.isLive(); // a machine with canaries on it could've failed causing us to reschedule some or all of them

    // canary runtime is in minutes now
    canaryTimer.setTimeoutSeconds(plan.canariesMustLiveForMinutes * 60);

    if (resetting)
    {
      Ring::queueUpdateTimeout(&canaryTimer);
    }
    else
    {
      canaryTimer.dispatcher = this;
      canaryTimer.flags = uint64_t(DeploymentTimeoutFlags::canariesMinimumLifetime);
      Ring::queueTimeout(&canaryTimer);
    }
  }

  void canaryTimerExpired(void)
  {
    // we'll be suspended in deployCanaries
    if (canaryStack)
    {
      canaryStack->co_consume();
    }
  }

  // before calling this we check that if we move all stateless off machineA, that we could even fit any instanes of the desired
  CoroutineGenerator<Machine *> compactAtoBs(uint32_t nToFit, Machine *machineA, const bytell_hash_set<uint64_t>& excludeDeploymentIDs, Vector<Machine *>& machinesB, bytell_hash_map<Machine *, MachineResourcesDelta>& deltasByMachine, bool planCompactionWork)
  {
    struct PlannedMove {

      Machine *machineB;
      uint64_t deploymentID;
      uint32_t count;
      uint32_t nBase;
      uint32_t nSurge;
      Vector<ContainerView *> bases;
      Vector<ContainerView *> surges;

      PlannedMove(Machine *_machineB, uint64_t _deploymentID, uint32_t _count, uint32_t _nBase, uint32_t _nSurge)
          : machineB(_machineB),
            deploymentID(_deploymentID),
            count(_count),
            nBase(_nBase),
            nSurge(_nSurge)
      {}
    };

    // we can't schedule and account for moves until we're sure we can move enough to free up the requisite amount of space
    Vector<PlannedMove> plannedMoves;
    bytell_hash_map<Machine *, MachineResourcesDelta> planningDeltasByMachine = deltasByMachine;

    MachineResourcesDelta& donorInitialDeltas = deltasByMachine[machineA];
    uint64_t accumulated_nLogicalCores = 0;
    uint64_t accumulated_sharedCPUMillis = 0;
    prodigyComputeEffectiveMachineCPUAvailability(machineA, &donorInitialDeltas, accumulated_nLogicalCores, accumulated_sharedCPUMillis);
    uint64_t accumulated_memoryMB = prodigyEffectiveMachineScalarAvailability(machineA->memoryMB_available, &donorInitialDeltas, &MachineResourcesDelta::nMemoryMB);
    uint64_t accumulated_storageMB = prodigyEffectiveMachineScalarAvailability(machineA->storageMB_available, &donorInitialDeltas, &MachineResourcesDelta::nStorageMB);
    Vector<uint32_t> accumulatedGPUMemoryMBs = machineA->availableGPUMemoryMBs;
    prodigyAppendGPUMemoryMBs(accumulatedGPUMemoryMBs, donorInitialDeltas.gpuMemoryMBs);
    bool plannedMovesIncludeSharedCPU = false;

    // accumulate how many resources we could accumulate if we moved everything
    for (const auto& [deploymentID, containers] : machineA->containersByDeploymentID)
    {
      if (excludeDeploymentIDs.contains(deploymentID))
      {
        continue;
      }

      ApplicationDeployment *thisDeployment = thisBrain->deployments[deploymentID];

      if (thisDeployment == nullptr)
      {
        continue;
      }
      if (thisDeployment->statelessCompactionDonorIsQuiescent() == false)
      {
        continue;
      }

      DeploymentPlan& thisPlan = thisDeployment->plan;

      if (thisPlan.isStateful || thisPlan.stateless.moveableDuringCompaction == false)
      {
        continue;
      }

      uint32_t budget = 0;
      uint32_t nBase = 0;
      uint32_t nSurge = 0;

      for (ContainerView *container : containers)
      {
        if (statelessCompactionContainerIsEligible(container) == false)
        {
          continue;
        }

        budget += 1;

        // only base and surge possible because canary stage deployments are filtered out
        switch (container->lifetime)
        {
          case ApplicationLifetime::base:
            {
              nBase += 1;
              break;
            }
          case ApplicationLifetime::surge:
            {
              nSurge += 1;
              break;
            }
          case ApplicationLifetime::canary:
          default:
            break;
        }
      }

      for (Machine *machineB : machinesB)
      {
        if (machineB == machineA)
        {
          continue;
        }

        uint32_t thisBudget = clampBudgetByRackAndMachine(thisDeployment, machineB, budget);

        if (uint32_t moveN = nFitOnMachine(thisDeployment, machineB, thisBudget, planningDeltasByMachine[machineB]); moveN > 0) // we could move this many
        {
          uint32_t nSurgeToMove = 0;
          uint32_t nBaseToMove = 0;

          if (nSurge >= moveN)
          {
            nSurgeToMove = moveN;
            nSurge -= moveN;
          }
          else
          {
            // move as many surge as we can
            nSurgeToMove = nSurge;
            nSurge = 0;

            if (machineB->lifetime != MachineLifetime::spot)
            {
              uint32_t nRemaining = moveN - nSurgeToMove;

              if (nBase >= nRemaining)
              {
                nBaseToMove = nRemaining;
                nBase -= nRemaining;
              }
              else
              {
                // move as many base as we can
                nBaseToMove = nBase;
                nBase = 0;
              }
            }
          }

          moveN = nBaseToMove + nSurgeToMove;

          if (moveN > 0)
          {
            budget -= moveN;

            PlannedMove& plan = plannedMoves.emplace_back(machineB, deploymentID, moveN, nBaseToMove, nSurgeToMove);
            prodigyApplyPlannedMachineScalarDelta(planningDeltasByMachine[machineB], thisPlan.config, int64_t(moveN));

            uint32_t nMoreBase = nBaseToMove;
            uint32_t nMoreSurge = nSurgeToMove;

            for (ContainerView *container : containers)
            {
              if (statelessCompactionContainerIsEligible(container) == false)
              {
                continue;
              }

              // only base and surge possible because canary stage deployments are filtered out
              switch (container->lifetime)
              {
                case ApplicationLifetime::base:
                  {
                    if (nMoreBase > 0)
                    {
                      nMoreBase -= 1;
                      plan.bases.push_back(container);
                    }

                    break;
                  }
                case ApplicationLifetime::surge:
                  {
                    if (nMoreSurge > 0)
                    {
                      nMoreSurge -= 1;
                      plan.surges.push_back(container);
                    }

                    break;
                  }
                case ApplicationLifetime::canary:
                default:
                  break;
              }
            }

            if (applicationUsesSharedCPUs(thisPlan.config))
            {
              accumulated_sharedCPUMillis += (moveN * applicationRequestedCPUMillis(thisPlan.config));
              plannedMovesIncludeSharedCPU = true;
            }
            else
            {
              accumulated_nLogicalCores += (moveN * thisPlan.config.nLogicalCores);
            }
            accumulated_memoryMB += (moveN * thisPlan.config.totalMemoryMB());
            accumulated_storageMB += (moveN * thisPlan.config.totalStorageMB());
            for (ContainerView *container : plan.bases)
            {
              prodigyAppendGPUMemoryMBs(accumulatedGPUMemoryMBs, container->assignedGPUMemoryMBs);
            }
            for (ContainerView *container : plan.surges)
            {
              prodigyAppendGPUMemoryMBs(accumulatedGPUMemoryMBs, container->assignedGPUMemoryMBs);
            }

            if (budget == 0)
            {
              break; // we've now found places to move all of the instances of the container
            }
          }
        }
      }
    }

    if (plannedMoves.size() > 0) // we can move some containers, and we've accumulated all the resources we could free
    {
      // worst by assumed least effective moves first
      sorter(plannedMoves, [&](const PlannedMove& plannedMove) -> int64_t {
        ApplicationDeployment *thisDeployment = thisBrain->deployments.at(plannedMove.deploymentID);

        if (plan.config.storageMB > 0)
        {
          // sort by least storage
          return -thisDeployment->plan.config.totalStorageMB();
        }
        else if (isMemoryDominant(plan.config))
        {
          // sort by least memory
          return -thisDeployment->plan.config.totalMemoryMB();
        }
        else
        {
          // sort by logical cores
          if (applicationUsesSharedCPUs(thisDeployment->plan.config))
          {
            return -int64_t(applicationRequestedCPUMillis(thisDeployment->plan.config));
          }

          return -thisDeployment->plan.config.nLogicalCores;
        }
      });

      std::sort(accumulatedGPUMemoryMBs.begin(), accumulatedGPUMemoryMBs.end());
      uint32_t nFit = nFitOntoResources(this, accumulated_nLogicalCores, accumulated_sharedCPUMillis, accumulated_memoryMB, accumulated_storageMB, accumulatedGPUMemoryMBs, nToFit);

      // clamp nFit by how many we actually need room for....
      if (nToFit < nFit)
      {
        nFit = nToFit;
      }

      if (nFit > 0) // we can fit some
      {
        basics_log("compactAtoBs deploymentID=%llu donorPrivate4=%u nFit=%u plannedMoves=%llu\n",
                   (unsigned long long)plan.config.deploymentID(),
                   unsigned(machineA->private4),
                   unsigned(nFit),
                   (unsigned long long)plannedMoves.size());

        if (applicationRequiredWholeGPUs(plan.config) == 0 && applicationUsesSharedCPUs(plan.config) == false && plannedMovesIncludeSharedCPU == false)
        {
          uint64_t nLogicalCoresSlack = accumulated_nLogicalCores - (uint64_t(nFit) * uint64_t(plan.config.nLogicalCores));
          uint64_t nMemoryMBSlack = accumulated_memoryMB - (uint64_t(nFit) * uint64_t(plan.config.totalMemoryMB()));
          uint64_t nStorageMBSlack = accumulated_storageMB - (uint64_t(nFit) * uint64_t(plan.config.totalStorageMB()));

          // now filter the accumulations by the resources we actually need... preferring to move as few instances as possible
          for (auto it = plannedMoves.begin(); it != plannedMoves.end();)
          {
            PlannedMove& plannedMove = *it;

            ApplicationDeployment *thisDeployment = thisBrain->deployments.at(plannedMove.deploymentID);

            uint64_t nByCores = nLogicalCoresSlack / thisDeployment->plan.config.nLogicalCores;

            if (nByCores > 0)
            {
              uint64_t nByMemory = nMemoryMBSlack / thisDeployment->plan.config.totalMemoryMB();

              if (nByMemory > 0)
              {
                uint64_t nByStorage = nStorageMBSlack / thisDeployment->plan.config.totalStorageMB();

                if (nByStorage > 0)
                {
                  uint64_t nToCull64 = nByCores;
                  if (nByMemory < nToCull64)
                  {
                    nToCull64 = nByMemory;
                  }
                  if (nByStorage < nToCull64)
                  {
                    nToCull64 = nByStorage;
                  }
                  if (plannedMove.count < nToCull64)
                  {
                    nToCull64 = plannedMove.count;
                  }
                  uint32_t nToCull = static_cast<uint32_t>(nToCull64);

                  if (nToCull == plannedMove.count)
                  {
                    plannedMoves.erase(it);
                    continue;
                  }
                  else
                  {
                    plannedMove.count -= nToCull;

                    nLogicalCoresSlack -= nToCull * thisDeployment->plan.config.nLogicalCores;
                    nMemoryMBSlack -= nToCull * thisDeployment->plan.config.totalMemoryMB();
                    nStorageMBSlack -= nToCull * thisDeployment->plan.config.totalStorageMB();

                    if (plannedMove.nBase >= nToCull)
                    {
                      plannedMove.nBase -= nToCull;
                      plannedMove.bases.erase(plannedMove.bases.end() - nToCull, plannedMove.bases.end());
                    }
                    else
                    {
                      nToCull -= plannedMove.nBase;
                      plannedMove.nBase = 0;
                      plannedMove.nSurge -= nToCull;

                      plannedMove.bases.clear();
                      plannedMove.surges.erase(plannedMove.surges.end() - nToCull, plannedMove.surges.end());
                    }
                  }
                }
              }
            }

            ++it;
          }
        }

        // now we're moving the minimum number of containers to still achieve nFit

        // generate a stateless work object that sees us WAIT for all of the followings compactions, then schedules n of our application on that machine

        bytell_hash_set<ApplicationDeployment *> compactedDeployments;

        auto applyDonorDelta = [&](const PlannedMove& plannedMove) -> void {
          ApplicationDeployment *thisDeployment = thisBrain->deployments.at(plannedMove.deploymentID);
          DeploymentPlan& thisPlan = thisDeployment->plan;
          MachineResourcesDelta& donorDeltas = deltasByMachine[machineA];

          prodigyApplyPlannedMachineScalarDelta(donorDeltas, thisPlan.config, -int64_t(plannedMove.count));
          for (ContainerView *container : plannedMove.bases)
          {
            prodigyAppendGPUMemoryMBs(donorDeltas.gpuMemoryMBs, container->assignedGPUMemoryMBs);
            prodigyAppendAssignedGPUDevices(donorDeltas.gpuDevices, container->assignedGPUDevices);
          }
          for (ContainerView *container : plannedMove.surges)
          {
            prodigyAppendGPUMemoryMBs(donorDeltas.gpuMemoryMBs, container->assignedGPUMemoryMBs);
            prodigyAppendAssignedGPUDevices(donorDeltas.gpuDevices, container->assignedGPUDevices);
          }
        };

        if (planCompactionWork == false)
        {
          for (const PlannedMove& plannedMove : plannedMoves)
          {
            ApplicationDeployment *thisDeployment = thisBrain->deployments.at(plannedMove.deploymentID);
            applyDonorDelta(plannedMove);
            prodigyApplyPlannedMachineScalarDelta(deltasByMachine[plannedMove.machineB], thisDeployment->plan.config, int64_t(plannedMove.count));
          }

          co_yield machineA;
          co_return;
        }

        CompactionTicket *ticket = new CompactionTicket();
        ticket->orchestrator = this;

        for (PlannedMove& plannedMove : plannedMoves) // now schedule the moves
        {
          Machine *machineB = plannedMove.machineB;

          ApplicationDeployment *thisDeployment = thisBrain->deployments.at(plannedMove.deploymentID);
          DeploymentPlan& thisPlan = thisDeployment->plan;

          uint32_t moveN = plannedMove.count;

          applyDonorDelta(plannedMove);

          // moving moveN of deploymentID from machine A to machine B
          prodigyDebitMachineScalarResources(machineB, thisPlan.config, moveN);

          thisDeployment->countPerMachine[machineA] -= moveN;
          thisDeployment->countPerMachine[machineB] += moveN;

          thisDeployment->countPerRack[machineA->rack] -= moveN;
          thisDeployment->countPerRack[machineB->rack] += moveN;

          compactedDeployments.insert(thisDeployment);
          ticket->pendingCompactions[thisDeployment] += moveN * 2;

          auto scheduleMoves = [&](ApplicationLifetime lifetime, uint32_t nMoves) -> void {
            auto getContainerToDestroy = [&](ApplicationLifetime lifetime) -> ContainerView * {
              ContainerView *container = nullptr;

              switch (lifetime)
              {
                case ApplicationLifetime::base:
                  {
                    container = plannedMove.bases.back();
                    plannedMove.bases.pop_back();
                    break;
                  }
                case ApplicationLifetime::surge:
                  {
                    container = plannedMove.surges.back();
                    plannedMove.surges.pop_back();
                    break;
                  }
                default:
                  break;
              }

              return container;
            };

            do
            {
              ContainerView *containerToDestroy = getContainerToDestroy(lifetime);
              Vector<uint32_t> assignedGPUMemoryMBs = {};
              Vector<AssignedGPUDevice> assignedGPUDevices = {};
              bool reservedGPUs = prodigyReservePlanningGPUsForInstance(machineB, nullptr, thisPlan.config, assignedGPUMemoryMBs, assignedGPUDevices);
              assert(reservedGPUs && "planned compaction move must reserve machine GPUs");
              DeploymentWork *cwork = planStatelessConstruction(machineB, lifetime, std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices));
              DeploymentWork *dwork = planStatelessDestruction(containerToDestroy, "compaction");

              // cwork->ticket = ticket;
              // dwork->ticket = ticket;

              if (thisPlan.moveConstructively)
              {
                std::get<StatelessWork>(*cwork).next = dwork;
                std::get<StatelessWork>(*dwork).prev = cwork;

                thisDeployment->toSchedule.push_back(cwork);
                thisDeployment->toSchedule.push_back(dwork);
              }
              else
              {
                std::get<StatelessWork>(*dwork).next = cwork;
                std::get<StatelessWork>(*cwork).prev = dwork;

                thisDeployment->toSchedule.push_back(dwork);
                thisDeployment->toSchedule.push_back(cwork);
              }

            } while (--nMoves > 0);
          };

          if (plannedMove.nBase > 0)
          {
            scheduleMoves(ApplicationLifetime::base, plannedMove.nBase);
          }
          if (plannedMove.nSurge > 0)
          {
            scheduleMoves(ApplicationLifetime::surge, plannedMove.nSurge);
          }
        }

        for (ApplicationDeployment *deployment : compactedDeployments)
        {
          deployment->schedule(nullptr);
        }

        DeploymentWork *workAnon = workPool.get();
        workAnon->emplace<StatelessWork>(ticket);
        toSchedule.push_back(workAnon);

        waitingOnCompactions = true;

        // Assert a sentinel exists while we are marked waiting on compactions
        {
          bool found = false;
          for (DeploymentWork *w : toSchedule)
          {
            if (auto s = std::get_if<StatelessWork>(w); s && s->ticket && s->ticket->orchestrator == this)
            {
              found = true;
              break;
            }
          }
          assert(found && "waitingOnCompactions set without a compaction sentinel enqueued");
        }

        co_yield machineA;
      }
    }
  }

  CoroutineGenerator<Machine *> compact(bytell_hash_map<Machine *, MachineResourcesDelta>& deltasByMachine, bool planCompactionWork)
  {
    Vector<Machine *> recepientMachines;
    Vector<Machine *> donorMachines;

    bytell_hash_set<uint64_t> excludeDeploymentIDs;
    if (previous)
    {
      excludeDeploymentIDs.insert(previous->plan.config.deploymentID());
    }

    for (Machine *machine : thisBrain->machines)
    {
      if (prodigyMachineReadyForScheduling(machine) == false)
      {
        continue;
      }

      if (machine->lifetime == MachineLifetime::spot)
      {
        if (nDeployedSurge == nTargetSurge)
        {
          continue;
        }
      }

      donorMachines.push_back(machine);

      bool canReceive = applicationUsesSharedCPUs(plan.config)
                            ? (machine->sharedCPUMillis_available > 0)
                            : (machine->nLogicalCores_available > 0);
      if (canReceive)
      {
        recepientMachines.push_back(machine);
      }
    }

    if (recepientMachines.size() == 0)
    {
      co_return;
    }

    // negative value for descending
    sorter(donorMachines, [&](const Machine *machine) -> int64_t {
      if (plan.isStateful)
      {
        // we don't factor in the memory we'd have after all possible moves, because we want to discourage moves
        return -machine->memoryMB_available; // most memory available
      }
      else if (applicationUsesSharedCPUs(plan.config))
      {
        int64_t value = -machine->sharedCPUMillis_available;
        if (prodigyMachineUsesCPUOvercommit(machine))
        {
          value -= 1'000'000'000LL;
        }

        return value;
      }
      else
      {
        return -machine->nLogicalCores_available; // most cores available
      }
    });

    // negative value for descending
    sorter(recepientMachines, [&](const Machine *machine) -> int64_t {
      int64_t value = 0;

      if (plan.isStateful)
      {
        value = -machine->memoryMB_available;
      }
      else if (applicationUsesSharedCPUs(plan.config))
      {
        value = -machine->sharedCPUMillis_available;
        if (prodigyMachineUsesCPUOvercommit(machine) == false)
        {
          value -= 1'000'000'000LL;
        }
      }
      else
      {
        value = -machine->nLogicalCores_available;
      }

      // when we're moving containers from machineA to machineBs those containers could be base or surge...
      // so let's always sort spot machines first, such that surge instances will tend to be moved to
      // spot machines and not durable machines... even if this will means we'll have to iterate over
      // every spot machine (which will be many fewer than owned/reserved/ondemand) before getting to durable capacity
      if (machine->lifetime == MachineLifetime::spot)
      {
        value -= 50'000;
      }

      return value;
    });

    // what about two way compactions A <-> B ???
    // if 2 ways were necessary to create the required space, we'd be at such a redlining degree of occupancy
    // that it makes sense to just spin up more machines, rather than pay the insane computational cost to provide
    // such a further minuta of compaction... which would quickly become worthless anyway.
    // also if a machine is both a donor and a recepient... it is possible to for two way compactions to occur?

    for (Machine *donor : donorMachines)
    {
      uint32_t nToFit = nTarget() - nDeployed();

      // enforce rack + machine concentration limits
      // theoreticaly have some rack and machine budget room to schedule onto this machine not taking into account moveable resources
      if (uint32_t budget = clampBudgetByRackAndMachine(this, donor, nToFit); budget > 0)
      {
        for (Machine *machine : compactAtoBs(budget, donor, excludeDeploymentIDs, recepientMachines, deltasByMachine, planCompactionWork))
        {
          co_yield machine;
        }
      }
    }
  }

  template <typename TicketSpecializer>
  MachineTicket *requestMoreMachines(CoroutineStack *coro, ApplicationLifetime lifetime, uint32_t nMore, TicketSpecializer&& ticketSpecializer)
  {
    MachineTicket *ticket = new MachineTicket();
    ticket->coro = coro;
    ticket->nMore = nMore;
    ticketSpecializer(ticket);

    thisBrain->requestMachines(ticket, this, lifetime, nMore);

    return ticket;
  }

  struct DefaultTicketSpecializer {
    void operator()(MachineTicket *) const {}
  };

  template <typename TicketSpecializer = DefaultTicketSpecializer, typename ExtraBin = std::vector<Machine *>>
  CoroutineGenerator<std::pair<Machine *, MachineTicket *>> gatherMachinesForScheduling(CoroutineStack *coro, bool& scheduleSurgeOnReserved, bytell_hash_map<Machine *, MachineResourcesDelta>& deltasByMachine, bool allowCompaction, bool allowNewMachines, TicketSpecializer ticketSpecializer = {}, ExtraBin extraBin = ExtraBin {}, bool planCompactionWork = true)
  {
    struct CleanupGuard {
      MachineTicket *ticket = nullptr;

      ~CleanupGuard()
      {
        if (ticket)
        {
          delete ticket;
        }
      }
    } cleanupGuard;

    scheduleSurgeOnReserved = false;
    MachineTicket *ticket = nullptr;

  restart:

    Vector<Machine *> orderedMachines = {};
    for (const auto& [id, rack] : thisBrain->racks)
    {
      for (Machine *machine : rack->machines)
      {
        orderedMachines.push_back(machine);
      }
    }

    if (applicationUsesSharedCPUs(plan.config))
    {
      std::stable_sort(orderedMachines.begin(), orderedMachines.end(), [&](Machine *lhs, Machine *rhs) -> bool {
        auto lhsIt = deltasByMachine.find(lhs);
        auto rhsIt = deltasByMachine.find(rhs);
        return prodigySharedCPUSchedulingMachineComesBefore(
            lhs,
            lhsIt == deltasByMachine.end() ? nullptr : &lhsIt->second,
            rhs,
            rhsIt == deltasByMachine.end() ? nullptr : &rhsIt->second);
      });
    }

    for (Machine *machine : orderedMachines)
    {
      co_yield std::make_pair(machine, ticket);
    }

    Vector<Machine *> extraMachines = {};
    for (auto it = extraBin.begin(); it != extraBin.end();) // extraBin will be consumed
    {
      Machine *machine = *it;

      auto deltaIt = deltasByMachine.find(machine);
      const MachineResourcesDelta *deltas = (deltaIt == deltasByMachine.end()) ? nullptr : &deltaIt->second;
      uint64_t isolatedAvailable = 0;
      uint64_t sharedAvailable = 0;
      prodigyComputeEffectiveMachineCPUAvailability(machine, deltas, isolatedAvailable, sharedAvailable);

      bool canReceive = applicationUsesSharedCPUs(plan.config)
                            ? (sharedAvailable > 0)
                            : (isolatedAvailable > 0);
      if (canReceive == false)
      {
        it = extraBin.erase(it);
        continue;
      }
      else
      {
        it++;
      }

      extraMachines.push_back(machine);
    }

    if (applicationUsesSharedCPUs(plan.config))
    {
      std::stable_sort(extraMachines.begin(), extraMachines.end(), [&](Machine *lhs, Machine *rhs) -> bool {
        auto lhsIt = deltasByMachine.find(lhs);
        auto rhsIt = deltasByMachine.find(rhs);
        return prodigySharedCPUSchedulingMachineComesBefore(
            lhs,
            lhsIt == deltasByMachine.end() ? nullptr : &lhsIt->second,
            rhs,
            rhsIt == deltasByMachine.end() ? nullptr : &rhsIt->second);
      });
    }

    for (Machine *machine : extraMachines)
    {
      co_yield std::make_pair(machine, ticket);
    }

    if (nTargetSurge > nDeployedSurge)
    {
      if (scheduleSurgeOnReserved == false && (nTargetBase == nDeployedBase)) // never canaries if surge
      {
        // we deployed all the base instances we needed to but there wasn't enough spot capacity
        // to schedule all surge instances, so try to schedule them on durable machines for now

        scheduleSurgeOnReserved = true;
        goto restart;
      }
    }

    if (allowCompaction)
    {
      for (Machine *machine : compact(deltasByMachine, planCompactionWork))
      {
        co_yield std::make_pair(machine, ticket);
      }
    }

    if (allowNewMachines)
    {
      if (nTargetSurge > nDeployedSurge)
      {
        basics_log("gatherMachines request surge machines deploymentID=%llu target=%u deployed=%u\n",
                   (unsigned long long)plan.config.deploymentID(),
                   unsigned(nTargetSurge),
                   unsigned(nDeployedSurge));
        ticket = requestMoreMachines(coro, ApplicationLifetime::surge, nTargetSurge - nDeployedSurge, ticketSpecializer);
        cleanupGuard.ticket = ticket;

        do
        {
          nSuspended += 1;
          co_await coro->suspend(); // we'll be woken once a new machine comes healthy
          nSuspended -= 1;

          ticket->nMore -= ticket->nNow;

          co_yield std::make_pair(ticket->machineNow, ticket);

        } while (ticket->nMore > 0);

        delete ticket;
        cleanupGuard.ticket = nullptr;
      }

      if (nTargetCanary > nDeployedCanary)
      {
        basics_log("gatherMachines request canary machines deploymentID=%llu target=%u deployed=%u\n",
                   (unsigned long long)plan.config.deploymentID(),
                   unsigned(nTargetCanary),
                   unsigned(nDeployedCanary));
        ticket = requestMoreMachines(coro, ApplicationLifetime::canary, nTargetCanary - nDeployedCanary, ticketSpecializer);
        cleanupGuard.ticket = ticket;

        do
        {
          nSuspended += 1;
          co_await coro->suspend(); // we'll be woken once a new machine comes healthy
          nSuspended -= 1;

          ticket->nMore -= ticket->nNow;

          co_yield std::make_pair(ticket->machineNow, ticket);

        } while (ticket->nMore > 0);

        delete ticket;
        cleanupGuard.ticket = nullptr;
      }

      if (nTargetBase > nDeployedBase)
      {
        basics_log("gatherMachines request base machines deploymentID=%llu target=%u deployed=%u\n",
                   (unsigned long long)plan.config.deploymentID(),
                   unsigned(nTargetBase),
                   unsigned(nDeployedBase));
        ticket = requestMoreMachines(coro, ApplicationLifetime::base, nTargetBase - nDeployedBase, ticketSpecializer);
        cleanupGuard.ticket = ticket;

        do
        {
          nSuspended += 1;
          co_await coro->suspend(); // we'll be woken once a new machine comes healthy
          nSuspended -= 1;

          ticket->nMore -= ticket->nNow;

          co_yield std::make_pair(ticket->machineNow, ticket);

        } while (ticket->nMore > 0);

        delete ticket;
        cleanupGuard.ticket = nullptr;
      }
    }
  }

  template <typename ExtraBin = std::vector<Machine *>>
  CoroutineGenerator<std::pair<Machine *, MachineTicket *>> gatherMachinesForScheduling(CoroutineStack *coro, bytell_hash_map<Machine *, MachineResourcesDelta>& deltasByMachine, bool allowCompaction, bool allowNewMachines, ExtraBin extraBin = ExtraBin {})
  {
    bool scheduleSurgeOnReserved;

    for (auto&& pair : gatherMachinesForScheduling(coro, scheduleSurgeOnReserved, deltasByMachine, allowCompaction, allowNewMachines, [=](MachineTicket *ticket) -> void {
         },
                                                   std::move(extraBin)))
    {
      co_yield pair;
    }
  }

  bool isMemoryDominant(const ApplicationConfig& config)
  {
    return (float(config.totalMemoryMB()) / float(config.nLogicalCores)) > 8.0; // more than 8GB per logical core
  }

  // only called by stateless applications
  // whereas architectStateless maps a deployment + transition from old versions to the latest version, addInstances just maps n instances of this deployment
  // onto the cluster... either canaries of a new deployment or scaling an existing deployment in response to traffic surges
  void spinStateless(CoroutineStack *coro, Vector<ContainerView *>& containersToRedeploy, bool containersAreDead)
  {
    for (auto it = containersToRedeploy.begin(); it != containersToRedeploy.end();)
    {
      ContainerView *container = *it;
      if (container == nullptr || containers.contains(container) == false || container->machine == nullptr)
      {
        it = containersToRedeploy.erase(it);
      }
      else
      {
        it++;
      }
    }

    for (ContainerView *container : containersToRedeploy)
    {
      uint32_t& machineCount = countPerMachine[container->machine];
      if (machineCount > 0)
      {
        machineCount -= 1;
      }

      uint32_t& rackCount = countPerRack[container->machine->rack];
      if (rackCount > 0)
      {
        rackCount -= 1;
      }
    }

    if (containersToRedeploy.size() > 0)
    {
      basics_log("spinStateless redeployCount=%llu dead=%d target=%u deployed=%u\n",
                 (unsigned long long)containersToRedeploy.size(),
                 int(containersAreDead),
                 unsigned(nTarget()),
                 unsigned(nDeployed()));
    }

    auto maxAllowed = [](uint32_t total, float ratio) -> uint32_t {
      if (total == 0 || ratio <= 0.0f)
      {
        return 0U;
      }
      double allowed = std::ceil(static_cast<double>(total) * static_cast<double>(ratio));
      if (allowed < 1.0)
      {
        allowed = 1.0;
      }
      if (allowed > static_cast<double>(UINT32_MAX))
      {
        allowed = static_cast<double>(UINT32_MAX);
      }
      return static_cast<uint32_t>(allowed);
    };

    uint32_t maxPerRack = maxAllowed(nTarget(), plan.stateless.maxPerRackRatio);
    uint32_t maxPerMachine = maxAllowed(nTarget(), plan.stateless.maxPerMachineRatio);

    // if containersToRedeploy then we are draining a machine
    Machine *drainingMachine = nullptr;
    if (containersToRedeploy.size() > 0)
    {
      drainingMachine = containersToRedeploy.back()->machine;
    }

    bool scheduleSurgeOnReserved;
    // we don't need to bother with tracking deletion resources, because if there are even containers we are scheduling for destruction
    // either the machine failed or is not schedulable to... so we could never be considering it
    bytell_hash_map<Machine *, MachineResourcesDelta> deltasByMachine;

    auto machines = gatherMachinesForScheduling(coro, scheduleSurgeOnReserved, deltasByMachine, true, true);
    while (true)
    {
      if (machines.hasValue() == false)
      {
        if (machines.advance() == false)
        {
          if (machines.blocked())
          {
            if (coro == nullptr)
            {
              basics_log("spinStateless blocked without coroutine stack deploymentID=%llu\n",
                         (unsigned long long)plan.config.deploymentID());
              co_return;
            }

            uint32_t generatorSuspendIndex = coro->nextSuspendIndex();
            if (generatorSuspendIndex == 0)
            {
              basics_log("spinStateless invalid suspend ordering deploymentID=%llu\n",
                         (unsigned long long)plan.config.deploymentID());
              co_return;
            }

            nSuspended += 1;
            co_await coro->suspendAtIndex(generatorSuspendIndex - 1);
            nSuspended -= 1;
            continue;
          }

          break;
        }
      }

      auto yielded = machines.value();
      machines.clearValue();

      Machine *machine = yielded.first;
      MachineTicket *ticket = yielded.second;
      if (machine == nullptr)
      {
        continue;
      }
      if (prodigyMachineReadyForScheduling(machine) == false)
      {
        continue;
      }

      uint32_t nFit;

      if (ticket == nullptr)
      {
        uint32_t budget;

        switch (machine->lifetime)
        {
          case MachineLifetime::spot:
            {
              budget = nTargetSurge - nDeployedSurge;
              break;
            }
          case MachineLifetime::owned:
          case MachineLifetime::ondemand:
          case MachineLifetime::reserved:
            {
              if (scheduleSurgeOnReserved)
              {
                budget = nTarget() - nDeployed(); // schedule base, canary or surge
              }
              else
              {
                budget = nTargetBase - nDeployedBase;
                budget += nTargetCanary - nDeployedCanary;
              }

              break;
            }
        }

        if (uint32_t machineBudget = maxPerMachine - countPerMachine.getIf(machine); machineBudget < budget)
        {
          budget = machineBudget;
        }

        if (drainingMachine == nullptr || machine->rack != drainingMachine->rack)
        {
          if (uint32_t rackBudget = maxPerRack - countPerRack.getIf(machine->rack); rackBudget < budget)
          {
            budget = rackBudget;
          }
        }

        if (nFit = nFitOnMachine(this, machine, budget); nFit > 0)
        {
          countPerMachine[machine] += nFit;
          countPerRack[machine->rack] += nFit;

          prodigyDebitMachineScalarResources(machine, plan.config, nFit);
        }
        else
        {
          continue;
        }
      }
      else
      {
        nFit = ticket->nNow;
      }

      if (containersToRedeploy.size() > 0)
      {
        for (auto it = containersToRedeploy.begin(); it != containersToRedeploy.end() && nFit > 0;)
        {
          ContainerView *container = *it;
          if (container == nullptr || containers.contains(container) == false || container->machine == nullptr)
          {
            it = containersToRedeploy.erase(it);
            continue;
          }

          switch (machine->lifetime)
          {
            case MachineLifetime::spot:
              {
                if (container->lifetime != ApplicationLifetime::surge)
                {
                  it++;
                  continue;
                }

                break;
              }
            case MachineLifetime::owned:
            case MachineLifetime::ondemand:
            case MachineLifetime::reserved:
              {
                // When surge is not allowed on durable machines, only skip surge
                // containers. Base/canary redeploys must still be rescheduled.
                if (scheduleSurgeOnReserved == false && container->lifetime == ApplicationLifetime::surge)
                {
                  it++;
                  continue;
                }

                break;
              }
          }

          // this container can be schedule onto this machine
          it = containersToRedeploy.erase(it);

          switch (container->lifetime)
          {
            case ApplicationLifetime::base:
              {
                nDeployedBase += 1;
                break;
              }
            case ApplicationLifetime::canary:
              {
                nDeployedCanary += 1;
                break;
              }
            case ApplicationLifetime::surge:
              {
                nDeployedSurge += 1;
                break;
              }
          }

          switch (container->state)
          {
            case ContainerState::planned:
              {
                StatelessWork *work = std::get_if<StatelessWork>(container->plannedWork);
                Machine *previousMachine = container->machine;
                Vector<uint32_t> assignedGPUMemoryMBs = {};
                Vector<AssignedGPUDevice> assignedGPUDevices = {};
                bool assignedGPUs = prodigyTakeAssignedGPUsForScheduling(machine, ticket, nullptr, plan.config, assignedGPUMemoryMBs, assignedGPUDevices);
                assert(assignedGPUs && "planned stateless placement must reserve GPUs");
                if (container->machine != nullptr && container->machine != machine)
                {
                  prodigyReleaseContainerGPUs(container);
                }
                container->assignedGPUMemoryMBs = std::move(assignedGPUMemoryMBs);
                container->assignedGPUDevices = std::move(assignedGPUDevices);
                if (previousMachine != nullptr && previousMachine != machine)
                {
                  previousMachine->removeContainerIndexEntry(container->deploymentID, container);
                }
                work->machine = machine;
                work->container->machine = machine;
                machine->upsertContainerIndexEntry(container->deploymentID, container);

                if (plan.moveConstructively == false)
                {
                  if (DeploymentWork *linkedMeta = work->prev ?: work->next; linkedMeta)
                  {
                    toSchedule.push_back(linkedMeta);
                  }
                }

                toSchedule.push_back(container->plannedWork);

                if (plan.moveConstructively)
                {
                  if (DeploymentWork *linkedMeta = work->prev ?: work->next; linkedMeta)
                  {
                    toSchedule.push_back(linkedMeta);
                  }
                }

                break;
              }
            case ContainerState::scheduled:
            case ContainerState::healthy:
              {
                if (containersAreDead)
                {
                  basics_log("spinStateless replacement fromPrivate4=%u toPrivate4=%u lifetime=%u state=%u plannedWork=%p\n",
                             container->machine ? container->machine->private4 : 0,
                             machine->private4,
                             unsigned(container->lifetime),
                             unsigned(container->state),
                             (void *)container->plannedWork);
                  Vector<uint32_t> assignedGPUMemoryMBs = {};
                  Vector<AssignedGPUDevice> assignedGPUDevices = {};
                  bool assignedGPUs = prodigyTakeAssignedGPUsForScheduling(machine, ticket, nullptr, plan.config, assignedGPUMemoryMBs, assignedGPUDevices);
                  assert(assignedGPUs && "replacement stateless placement must reserve GPUs");
                  toSchedule.push_back(planStatelessConstruction(machine, container->lifetime, std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices)));
                  basics_log("spinStateless queuedReplacement deploymentID=%llu toPrivate4=%u toSchedule=%llu waitingOnContainers=%llu schedulingExecution=%p\n",
                             (unsigned long long)plan.config.deploymentID(),
                             machine->private4,
                             (unsigned long long)toSchedule.size(),
                             (unsigned long long)waitingOnContainers.size(),
                             (void *)schedulingStack.execution);
                  container->plannedWork = nullptr;
                  destructContainer(container);
                  containerDestroyed(container);
                }
                else
                {
                  DeploymentWork *dwork = planStatelessDestruction(container, "spinStatelessReschedule");
                  Vector<uint32_t> assignedGPUMemoryMBs = {};
                  Vector<AssignedGPUDevice> assignedGPUDevices = {};
                  bool assignedGPUs = prodigyTakeAssignedGPUsForScheduling(machine, ticket, nullptr, plan.config, assignedGPUMemoryMBs, assignedGPUDevices);
                  assert(assignedGPUs && "constructive stateless placement must reserve GPUs");
                  DeploymentWork *cwork = planStatelessConstruction(machine, container->lifetime, std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices));

                  scheduleConstructionDestruction(cwork, dwork);
                }

                break;
              }
            default:
              break; // others impossible here
          }
        }
      }
      else
      {
        do
        {
          if (nTargetBase > nDeployedBase)
          {
            nDeployedBase += 1;
            Vector<uint32_t> assignedGPUMemoryMBs = {};
            Vector<AssignedGPUDevice> assignedGPUDevices = {};
            bool assignedGPUs = prodigyTakeAssignedGPUsForScheduling(machine, ticket, nullptr, plan.config, assignedGPUMemoryMBs, assignedGPUDevices);
            assert(assignedGPUs && "stateless base placement must reserve GPUs");
            toSchedule.push_back(planStatelessConstruction(machine, ApplicationLifetime::base, std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices)));
          }
          else if (nTargetCanary > nDeployedCanary)
          {
            nDeployedCanary += 1;
            Vector<uint32_t> assignedGPUMemoryMBs = {};
            Vector<AssignedGPUDevice> assignedGPUDevices = {};
            bool assignedGPUs = prodigyTakeAssignedGPUsForScheduling(machine, ticket, nullptr, plan.config, assignedGPUMemoryMBs, assignedGPUDevices);
            assert(assignedGPUs && "stateless canary placement must reserve GPUs");
            toSchedule.push_back(planStatelessConstruction(machine, ApplicationLifetime::canary, std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices)));
          }
          else
          {
            nDeployedSurge += 1;
            Vector<uint32_t> assignedGPUMemoryMBs = {};
            Vector<AssignedGPUDevice> assignedGPUDevices = {};
            bool assignedGPUs = prodigyTakeAssignedGPUsForScheduling(machine, ticket, nullptr, plan.config, assignedGPUMemoryMBs, assignedGPUDevices);
            assert(assignedGPUs && "stateless surge placement must reserve GPUs");
            toSchedule.push_back(planStatelessConstruction(machine, ApplicationLifetime::surge, std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices)));
          }

        } while (--nFit > 0);
      }

      if (nDeployed() == nTarget())
      {
        break;
      }
    }

    if (containersToRedeploy.size() > 0)
    {
      basics_log("spinStateless unscheduledRedeployCount=%llu target=%u deployed=%u\n",
                 (unsigned long long)containersToRedeploy.size(),
                 unsigned(nTarget()),
                 unsigned(nDeployed()));
    }
  }

  void spinStateless(CoroutineStack *coro)
  {
    Vector<ContainerView *> containersToRedeploy;
    spinStateless(coro, containersToRedeploy, false);
  }

  // spinContainerForGroups is ONLY when we're adding new shard groups... as of now.. thus DataStrategy::sharding
  void spinStateful(CoroutineStack *coro, Vector<uint32_t>& spinContainerForGroups, Vector<ContainerView *>& containersToRedeploy, bool containersAreDead)
  {
    for (auto it = containersToRedeploy.begin(); it != containersToRedeploy.end();)
    {
      ContainerView *container = *it;
      if (container == nullptr || containers.contains(container) == false || container->machine == nullptr)
      {
        it = containersToRedeploy.erase(it);
      }
      else
      {
        it++;
      }
    }

    for (ContainerView *container : containersToRedeploy)
    {
      countPerMachine[container->machine] -= 1;
      countPerRack[container->machine->rack] -= 1;
      racksByShardGroup[container->shardGroup].erase(container->machine->rack);
    }

    auto rescheduleContainerOntoMachine = [&](Machine *machine, ContainerView *container, MachineTicket *ticket) -> void {
      switch (container->state)
      {
        case ContainerState::planned:
          {
            StatefulWork *work = std::get_if<StatefulWork>(container->plannedWork);
            Machine *previousMachine = container->machine;
            ApplicationConfig schedulingConfig = resourceConfigForContainer(container);
            Vector<uint32_t> assignedGPUMemoryMBs = {};
            Vector<AssignedGPUDevice> assignedGPUDevices = {};
            bool assignedGPUs = prodigyTakeAssignedGPUsForScheduling(machine, ticket, nullptr, schedulingConfig, assignedGPUMemoryMBs, assignedGPUDevices);
            assert(assignedGPUs && "planned stateful placement must reserve GPUs");
            if (container->machine != nullptr && container->machine != machine)
            {
              prodigyReleaseContainerGPUs(container);
            }
            container->assignedGPUMemoryMBs = std::move(assignedGPUMemoryMBs);
            container->assignedGPUDevices = std::move(assignedGPUDevices);
            if (previousMachine != nullptr && previousMachine != machine)
            {
              previousMachine->removeContainerIndexEntry(container->deploymentID, container);
            }
            work->machine = machine;
            work->container->machine = machine;
            machine->upsertContainerIndexEntry(container->deploymentID, container);

            switch (work->lifecycle)
            {
              case LifecycleOp::construct:
                {
                  if (plan.moveConstructively == false)
                  {
                    if (DeploymentWork *linkedMeta = work->prev ?: work->next; linkedMeta)
                    {
                      toSchedule.push_back(linkedMeta);
                    }
                  }

                  toSchedule.push_back(container->plannedWork);

                  if (plan.moveConstructively)
                  {
                    if (DeploymentWork *linkedMeta = work->prev ?: work->next; linkedMeta)
                    {
                      toSchedule.push_back(linkedMeta);
                    }
                  }
                  break;
                }
              case LifecycleOp::updateInPlace:
                {
                  std::get_if<StatefulWork>(container->plannedWork)->data = DataStrategy::seeding;

                  if (containersAreDead)
                  {
                    // sever the destruction and reissue a creation

                    work->lifecycle = LifecycleOp::construct;
                    work->oldContainer = nullptr; // the oldContainer was marked aboutToDestroy so it was already destroyed

                    toSchedule.push_back(container->plannedWork);
                  }
                  else
                  {
                    // issue independent destruction and creation
                    DeploymentWork *dwork = planStatefulDestruction(work->oldContainer);

                    work->lifecycle = LifecycleOp::construct;
                    work->oldContainer = nullptr;

                    scheduleConstructionDestruction(container->plannedWork, dwork);
                  }

                  break;
                }
              // not possible
              case LifecycleOp::none:
              case LifecycleOp::destruct:
                break;
            }

            break;
          }
        case ContainerState::scheduled:
        case ContainerState::healthy:
          {
            uint32_t topologyEpoch = container->explicitStatefulTopology.topologyEpoch;
            ApplicationConfig schedulingConfig = resourceConfigForContainer(container);
            if (containersAreDead)
            {
              basics_log("spinStateful replacement fromPrivate4=%u toPrivate4=%u shardGroup=%u state=%u plannedWork=%p\n",
                         container->machine ? container->machine->private4 : 0,
                         machine->private4,
                         container->shardGroup,
                         unsigned(container->state),
                         (void *)container->plannedWork);
              Vector<uint32_t> assignedGPUMemoryMBs = {};
              Vector<AssignedGPUDevice> assignedGPUDevices = {};
              bool assignedGPUs = prodigyTakeAssignedGPUsForScheduling(machine, ticket, nullptr, schedulingConfig, assignedGPUMemoryMBs, assignedGPUDevices);
              assert(assignedGPUs && "replacement stateful placement must reserve GPUs");
              toSchedule.push_back(planStatefulConstruction(machine, container->shardGroup, topologyEpoch, DataStrategy::seeding, std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices)));
              container->plannedWork = nullptr;
              destructContainer(container);
              containerDestroyed(container);
            }
            else
            {
              DeploymentWork *dwork = planStatefulDestruction(container);
              Vector<uint32_t> assignedGPUMemoryMBs = {};
              Vector<AssignedGPUDevice> assignedGPUDevices = {};
              bool assignedGPUs = prodigyTakeAssignedGPUsForScheduling(machine, ticket, nullptr, schedulingConfig, assignedGPUMemoryMBs, assignedGPUDevices);
              assert(assignedGPUs && "constructive stateful placement must reserve GPUs");
              DeploymentWork *cwork = planStatefulConstruction(machine, container->shardGroup, topologyEpoch, DataStrategy::seeding, std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices));

              scheduleConstructionDestruction(cwork, dwork);
            }

            break;
          }
        default:
          break; // others impossible here
      }
    };

    // we don't need to bother with tracking deletion resources, because if there are even containers we are scheduling for destruction
    // either the machine failed or is not schedulable to... so we could never be considering it
    bytell_hash_map<Machine *, MachineResourcesDelta> deltasByMachine;
    bool scheduleSurgeOnReserved = false; // obviously false for stateful
    bool allowCompaction = true;
    bool allowNewMachines = true;

    auto machines = gatherMachinesForScheduling(coro, scheduleSurgeOnReserved, deltasByMachine, allowCompaction, allowNewMachines, [=, this](MachineTicket *ticket) -> void {
      if (containersToRedeploy.size() > 0)
      {
        for (ContainerView *container : containersToRedeploy)
        {
          ticket->shardGroups.push_back(container->shardGroup);
          ticket->placementTopologyEpochs.push_back(container->explicitStatefulTopology.topologyEpoch);
        }
      }
      else
      {
        ticket->shardGroups = spinContainerForGroups;
        buildPlacementTopologyEpochs(ticket->placementTopologyEpochs, spinContainerForGroups);
      }
    });
    while (true)
    {
      if (machines.hasValue() == false)
      {
        if (machines.advance() == false)
        {
          if (machines.blocked())
          {
            if (coro == nullptr)
            {
              basics_log("spinStateful blocked without coroutine stack deploymentID=%llu\n",
                         (unsigned long long)plan.config.deploymentID());
              co_return;
            }

            uint32_t generatorSuspendIndex = coro->nextSuspendIndex();
            if (generatorSuspendIndex == 0)
            {
              basics_log("spinStateful invalid suspend ordering deploymentID=%llu\n",
                         (unsigned long long)plan.config.deploymentID());
              co_return;
            }

            nSuspended += 1;
            co_await coro->suspendAtIndex(generatorSuspendIndex - 1);
            nSuspended -= 1;
            continue;
          }

          break;
        }
      }

      auto yielded = machines.value();
      machines.clearValue();

      Machine *machine = yielded.first;
      MachineTicket *ticket = yielded.second;
      if (machine == nullptr)
      {
        continue;
      }
      if (prodigyMachineReadyForScheduling(machine) == false)
      {
        continue;
      }
      if (machine->lifetime == MachineLifetime::spot)
      {
        continue;
      }

      if (ticket == nullptr)
      {
        auto chargeMachine = [&](Machine *machine, const ApplicationConfig& config, uint32_t shardGroup) -> void {
          nDeployedBase += 1;

          countPerMachine[machine] += 1;
          countPerRack[machine->rack] += 1;
          racksByShardGroup[shardGroup].insert(machine->rack);

          prodigyDebitMachineScalarResources(machine, config, 1);
        };

        if (spinContainerForGroups.size() > 0)
        {
          for (auto it = spinContainerForGroups.begin(); it != spinContainerForGroups.end();)
          {
            if (uint32_t shardGroup = *it; canPlaceReplicaForShardGroupOnRack(shardGroup, machine->rack))
            {
              ApplicationConfig schedulingConfig = statefulConstructionConfigForShardGroup(shardGroup);
              if (nFitOnMachine(this, machine, 1, MachineResourcesDelta {}, &schedulingConfig) > 0)
              {
                chargeMachine(machine, schedulingConfig, shardGroup);

                Vector<uint32_t> assignedGPUMemoryMBs = {};
                Vector<AssignedGPUDevice> assignedGPUDevices = {};
                bool assignedGPUs = prodigyTakeAssignedGPUsForScheduling(machine, nullptr, nullptr, schedulingConfig, assignedGPUMemoryMBs, assignedGPUDevices);
                assert(assignedGPUs && "stateful scheduling must reserve GPUs");
                toSchedule.push_back(planStatefulConstruction(machine, shardGroup, statefulWorkerTopologyUpgradeLocksShardGroup(shardGroup) ? statefulWorkerTopologyUpgradeTargetEpoch : 0, topologyUpgradeConstructionDataStrategy(shardGroup), std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices)));

                it = spinContainerForGroups.erase(it);
              }
              else
              {
                break;
              }
            }
            else
            {
              it++;
            }
          }

          if (spinContainerForGroups.size() == 0)
          {
            break;
          }
        }
        else
        {
          for (auto it = containersToRedeploy.begin(); it != containersToRedeploy.end();)
          {
            ContainerView *container = *it;
            if (container == nullptr || containers.contains(container) == false || container->machine == nullptr)
            {
              it = containersToRedeploy.erase(it);
              continue;
            }

            if (canPlaceReplicaForShardGroupOnRack(container->shardGroup, machine->rack))
            {
              ApplicationConfig schedulingConfig = resourceConfigForContainer(container);
              if (nFitOnMachine(this, machine, 1, MachineResourcesDelta {}, &schedulingConfig) > 0)
              {
                chargeMachine(machine, schedulingConfig, container->shardGroup);
                rescheduleContainerOntoMachine(machine, container, nullptr);
                it = containersToRedeploy.erase(it);
              }
              else
              {
                break;
              }
            }
            else
            {
              it++;
            }
          }

          if (containersToRedeploy.size() == 0)
          {
            break;
          }
        }
      }
      else // ticket != nullptr so this machine is a new machine which we claimed on
      {
        for (uint32_t index = 0; index < ticket->shardGroups.size(); ++index)
        {
          uint32_t shardGroup = ticket->shardGroups[index];
          uint32_t topologyEpoch = placementTopologyEpochForIndex(ticket, index);
          nDeployedBase += 1;

          if (spinContainerForGroups.size() > 0)
          {
            ApplicationConfig schedulingConfig = statefulPlacementConfig(topologyEpoch);
            Vector<uint32_t> assignedGPUMemoryMBs = {};
            Vector<AssignedGPUDevice> assignedGPUDevices = {};
            bool assignedGPUs = prodigyTakeAssignedGPUsForScheduling(machine, ticket, nullptr, schedulingConfig, assignedGPUMemoryMBs, assignedGPUDevices);
            assert(assignedGPUs && "claimed stateful shard placement must consume reserved GPUs");
            toSchedule.push_back(planStatefulConstruction(machine, shardGroup, topologyEpoch, topologyUpgradeConstructionDataStrategy(shardGroup), std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices)));
          }
          else // containersToRedeploy
          {
            for (auto it = containersToRedeploy.begin(); it != containersToRedeploy.end();)
            {
              ContainerView *container = *it;
              if (container == nullptr || containers.contains(container) == false || container->machine == nullptr)
              {
                it = containersToRedeploy.erase(it);
                continue;
              }

              if (container->shardGroup == shardGroup && (topologyEpoch == 0 || container->explicitStatefulTopology.topologyEpoch == topologyEpoch))
              {
                rescheduleContainerOntoMachine(machine, container, ticket);
                it = containersToRedeploy.erase(it);
                break;
              }
            }
          }
        }
      }
    }
  }

  void spinStateful(CoroutineStack *coro, Vector<uint32_t>& spinContainerForGroups)
  {
    Vector<ContainerView *> containersToRedeploy;
    spinStateful(coro, spinContainerForGroups, containersToRedeploy, false);
  }

  void spinStateful(CoroutineStack *coro, Vector<ContainerView *>& containersToRedeploy, bool containersAreDead)
  {
    Vector<uint32_t> spinContainerForGroups;
    spinStateful(coro, spinContainerForGroups, containersToRedeploy, containersAreDead);
  }

  void rollback(void) // if canaries fail... we rollback
  {
    bool preserveContainerImage = false;
    if (previous && previous->plan.config.deploymentID() == plan.config.deploymentID())
    {
      // Vertical respins keep the same deployment identity; preserve shared container image state.
      preserveContainerImage = true;
    }

    thisBrain->deploymentFailed(this, plan.config.deploymentID(), "canaries failed"_ctv, preserveContainerImage);
    thisBrain->spinApplicationFin(this);

    if (auto it = thisBrain->deployments.find(plan.config.deploymentID()); it != thisBrain->deployments.end())
    {
      if (it->second == this)
      {
        thisBrain->deployments.erase(it);
      }
    }

    if (next) // roll forward
    {
      if (previous)
      {
        previous->next = next;
      }
      next->previous = previous;

      next->deploy();
    }
    else if (previous)
    {
      // the fact that previous is now the head deployment via deploymentsByApp, it regains control
      // that is the real rollback
      thisBrain->deploymentsByApp.insert_or_assign(plan.config.applicationID, previous);

      previous->next = nullptr;
      if (previous->state != DeploymentState::running)
      {
        previous->setDeploymentRunning();
      }
    }
    else
    {
      thisBrain->deploymentsByApp.erase(plan.config.applicationID);
    }

    delete this;
  }

  void beginDecommissioningForRollForward(void)
  {
    state = DeploymentState::decommissioning;
    stateChangedAtMs = Time::now<TimeResolution::ms>();
    Ring::queueCancelTimeout(&autoscaleTimer);
  }

  void setDeploymentRunning(void)
  {
    state = DeploymentState::running;
    stateChangedAtMs = Time::now<TimeResolution::ms>();
    if (plan.config.type == ApplicationType::task)
    {
      return;
    }
    autoscaleTimer.setTimeoutSeconds(configuredAutoscalePeriodSeconds());
    autoscaleTimer.dispatcher = this;
    autoscaleTimer.flags = uint64_t(DeploymentTimeoutFlags::autoscale);
    Ring::queueTimeout(&autoscaleTimer);
    autoscaleTrace("autoscale arm deploymentID=%llu seconds=%llu\n",
                   (unsigned long long)plan.config.deploymentID(),
                   (unsigned long long)configuredAutoscalePeriodSeconds());

    if (previous)
    {
      bool sameDeploymentID = (previous->plan.config.deploymentID() == plan.config.deploymentID());
      if (sameDeploymentID == false)
      {
        thisBrain->releaseRoutableResourceLeasesForDeployment(previous->plan.config.deploymentID());
        thisBrain->queueBrainReplication(BrainTopic::cullDeployment, previous->plan.config.deploymentID());
        ContainerStore::destroy(previous->plan.config.deploymentID());
      }

      delete previous;
      previous = nullptr;
    }

    dispatchDeferredStatefulScaleIntent();
  }

  void consumeSchedulingExecution(void)
  {
    CoroutineStack *execution = schedulingStack.execution;
    if (execution == nullptr)
    {
      return;
    }

    consumingSchedulingExecution = true;
    execution->co_consume();
    consumingSchedulingExecution = false;

    if (schedulingStack.execution == nullptr && retiredSchedulingExecution == execution)
    {
      delete retiredSchedulingExecution;
      retiredSchedulingExecution = nullptr;
    }
  }

  void handleContainerWaiters(ContainerView *container)
  {
    if (auto it = waitingOnContainers.find(container); it != waitingOnContainers.end())
    {
      switch (it->second)
      {
        case ContainerState::healthy: // waiting for container to be healthy
          {
            switch (container->state)
            {
              case ContainerState::healthy:
              case ContainerState::destroying:
              case ContainerState::destroyed:
                {
                  // fire
                  waitingOnContainers.erase(it);

                  if (waitingOnContainers.size() == 0)
                  {
                    if (schedulingStack.execution)
                    {
                      consumeSchedulingExecution();
                    }
                    dispatchDeferredStatefulScaleIntent();
                  }
                  break;
                }
              default:
                break; // else wait
            }

            break;
          }
        case ContainerState::destroyed: // waiting for container to be destroyed
          {
            if (container->state == ContainerState::destroyed)
            {
              // fire
              waitingOnContainers.erase(it);

              if (waitingOnContainers.size() == 0)
              {
                if (schedulingStack.execution)
                {
                  consumeSchedulingExecution();
                }
                dispatchDeferredStatefulScaleIntent();
              }
            }

            break;
          }
        default:
          break;
      }
    }
  }

  void calculateTargets(void)
  {
    if (plan.isStateful)
    {
      if (previous)
      {
        nShardGroups = previous->nShardGroups;
      }
      else
      {
        nShardGroups = 1;
      }

      nTargetBase = 0;
      for (uint32_t shardGroup = 0; shardGroup < nShardGroups; ++shardGroup)
      {
        nTargetBase += desiredReplicaCountForShardGroup(shardGroup);
      }
    }
    else
    {
      if (previous)
      {
        nTargetBase = previous->nTargetBase;
        nTargetSurge = previous->nTargetSurge;
      }

      // this works if no previous also because nTargetBase will be 0
      if (nTargetBase < plan.stateless.nBase)
      {
        uint32_t nDiff = (plan.stateless.nBase - nTargetBase);
        nTargetBase = plan.stateless.nBase;

        if (nTargetSurge > 0)
        {
          if (nTargetSurge < nDiff)
          {
            nTargetSurge = 0;
          }
          else
          {
            nTargetSurge -= nDiff;
          }
        }
      }
    }
  }

public:

  using StatefulWorkerTopologyUpgradePhase = ::StatefulWorkerTopologyUpgradePhase;
  constexpr static uint64_t statefulWorkerTopologyRollbackWindowMs = uint64_t(prodigyBrainStatefulTopologyRollbackWindowSeconds) * 1000ull;

#if PRODIGY_DEBUG
  void debugRollbackForTest(void)
  {
    rollback();
  }
#endif

  bool statefulWorkerTopologyUpgradePendingForAnyShardGroup(void) const
  {
    return (statefulWorkerTopologyUpgradePending && statefulWorkerTopologyLockedShardGroups.empty() == false);
  }

  bool statefulWorkerTopologyUpgradeLocksShardGroup(uint32_t shardGroup) const
  {
    return (statefulWorkerTopologyUpgradePendingForAnyShardGroup() && statefulWorkerTopologyLockedShardGroups.contains(shardGroup));
  }

  int64_t statefulWorkerTopologyUpgradeRollbackDeadlineMs(void) const
  {
    if (statefulWorkerTopologyUpgradePendingForAnyShardGroup() == false || statefulWorkerTopologyUpgradePhase != StatefulWorkerTopologyUpgradePhase::blueDraining || statefulWorkerTopologyUpgradePhaseChangedAtMs <= 0)
    {
      return 0;
    }

    const uint64_t phaseChangedAtMs = uint64_t(statefulWorkerTopologyUpgradePhaseChangedAtMs);
    const uint64_t maxInt64 = uint64_t(std::numeric_limits<int64_t>::max());
    const uint64_t rollbackWindowMs = statefulWorkerTopologyUpgradeRollbackWindowMsConfigured();
    if (phaseChangedAtMs > (maxInt64 - rollbackWindowMs))
    {
      return std::numeric_limits<int64_t>::max();
    }

    return int64_t(phaseChangedAtMs + rollbackWindowMs);
  }

  bool statefulWorkerTopologyUpgradeRollbackEligibleAt(int64_t nowMs) const
  {
    const int64_t deadlineMs = statefulWorkerTopologyUpgradeRollbackDeadlineMs();
    return (deadlineMs != 0 && nowMs < deadlineMs);
  }

  bool statefulWorkerTopologyUpgradeRollbackEligible(void) const
  {
    return statefulWorkerTopologyUpgradeRollbackEligibleAt(Time::now<TimeResolution::ms>());
  }

  uint64_t statefulWorkerTopologyUpgradeRollbackWindowMsConfigured(void) const
  {
    const char *value = std::getenv("PRODIGY_STATEFUL_TOPOLOGY_ROLLBACK_WINDOW_SECONDS");
    if (value == nullptr || value[0] == '\0')
    {
      return statefulWorkerTopologyRollbackWindowMs;
    }

    char *end = nullptr;
    unsigned long long seconds = std::strtoull(value, &end, 10);
    if (end == value || *end != '\0')
    {
      return statefulWorkerTopologyRollbackWindowMs;
    }

    constexpr uint64_t maxSeconds = uint64_t(std::numeric_limits<int64_t>::max()) / 1000ull;
    if (uint64_t(seconds) > maxSeconds)
    {
      return uint64_t(std::numeric_limits<int64_t>::max());
    }

    return uint64_t(seconds) * 1000ull;
  }

  void recomputeStatefulBaseTargetFromShardGroups(void)
  {
    nTargetBase = 0;
    for (uint32_t shardGroup = 0; shardGroup < nShardGroups; ++shardGroup)
    {
      nTargetBase += desiredReplicaCountForShardGroup(shardGroup);
    }
  }

  bool statefulDeferredScaleIntentPending(void) const
  {
    if (plan.isStateful == false)
    {
      return false;
    }

    if (deferredStatefulTargetShardGroups > nShardGroups)
    {
      return true;
    }

    return (deferredStatefulTargetLogicalCores > 0 && (deferredStatefulTargetLogicalCores != plan.config.nLogicalCores || deferredStatefulTargetMemoryMB != plan.config.memoryMB || deferredStatefulTargetStorageMB != plan.config.storageMB));
  }

  void seedStatefulDeferredScaleIntentFromCurrentState(void)
  {
    if (deferredStatefulTargetShardGroups < nShardGroups)
    {
      deferredStatefulTargetShardGroups = nShardGroups;
    }

    if (deferredStatefulTargetLogicalCores == 0)
    {
      deferredStatefulTargetLogicalCores = plan.config.nLogicalCores;
    }

    if (deferredStatefulTargetMemoryMB == 0)
    {
      deferredStatefulTargetMemoryMB = plan.config.memoryMB;
    }

    if (deferredStatefulTargetStorageMB == 0)
    {
      deferredStatefulTargetStorageMB = plan.config.storageMB;
    }
  }

  void requestDeferredStatefulShardGrowth(uint32_t additionalShardGroups = 1)
  {
    if (plan.isStateful == false || additionalShardGroups == 0)
    {
      return;
    }

    seedStatefulDeferredScaleIntentFromCurrentState();

    uint64_t nextTargetShardGroups = uint64_t(deferredStatefulTargetShardGroups) + uint64_t(additionalShardGroups);
    if (nextTargetShardGroups > UINT32_MAX)
    {
      nextTargetShardGroups = UINT32_MAX;
    }

    deferredStatefulTargetShardGroups = uint32_t(nextTargetShardGroups);
    statefulDeferredScaleIntentUpdatedAtMs = Time::now<TimeResolution::ms>();
    persistDeferredStatefulScaleIntent();
  }

  void requestDeferredStatefulTopologyTarget(uint16_t targetLogicalCores,
                                             uint32_t targetMemoryMB,
                                             uint32_t targetStorageMB)
  {
    if (plan.isStateful == false || targetLogicalCores == 0)
    {
      return;
    }

    seedStatefulDeferredScaleIntentFromCurrentState();
    deferredStatefulTargetLogicalCores = targetLogicalCores;
    deferredStatefulTargetMemoryMB = targetMemoryMB;
    deferredStatefulTargetStorageMB = targetStorageMB;
    statefulDeferredScaleIntentUpdatedAtMs = Time::now<TimeResolution::ms>();
    persistDeferredStatefulScaleIntent();
  }

  void applyStatefulWorkerTopologyUpgradeTargetResources(ApplicationConfig& config) const
  {
    if (statefulWorkerTopologyUpgradeTargetLogicalCores == 0)
    {
      return;
    }

    config.nLogicalCores = statefulWorkerTopologyUpgradeTargetLogicalCores;
    config.memoryMB = statefulWorkerTopologyUpgradeTargetMemoryMB;
    config.storageMB = statefulWorkerTopologyUpgradeTargetStorageMB;
  }

  ApplicationConfig statefulWorkerTopologyUpgradeTargetConfig(void) const
  {
    ApplicationConfig config = plan.config;
    applyStatefulWorkerTopologyUpgradeTargetResources(config);
    return config;
  }

  ApplicationConfig statefulPlacementConfig(uint32_t topologyEpoch) const
  {
    ApplicationConfig config = plan.config;
    if (statefulWorkerTopologyUpgradePendingForAnyShardGroup() && topologyEpoch != 0 && topologyEpoch == statefulWorkerTopologyUpgradeTargetEpoch)
    {
      applyStatefulWorkerTopologyUpgradeTargetResources(config);
    }

    return config;
  }

  ApplicationConfig statefulConstructionConfigForShardGroup(uint32_t shardGroup) const
  {
    ApplicationConfig config = plan.config;
    if (statefulWorkerTopologyUpgradeLocksShardGroup(shardGroup))
    {
      applyStatefulWorkerTopologyUpgradeTargetResources(config);
    }

    return config;
  }

  ApplicationConfig resourceConfigForContainer(const ContainerView *container) const
  {
    if (container == nullptr)
    {
      return plan.config;
    }

    if (container->isStateful)
    {
      return statefulPlacementConfig(container->explicitStatefulTopology.topologyEpoch);
    }

    return plan.config;
  }

  void buildPlacementTopologyEpochs(Vector<uint32_t>& placementTopologyEpochs, const Vector<uint32_t>& shardGroups) const
  {
    placementTopologyEpochs.clear();
    placementTopologyEpochs.reserve(shardGroups.size());

    for (uint32_t shardGroup : shardGroups)
    {
      placementTopologyEpochs.push_back(statefulWorkerTopologyUpgradeLocksShardGroup(shardGroup) ? statefulWorkerTopologyUpgradeTargetEpoch : 0);
    }
  }

  uint32_t placementTopologyEpochForIndex(const MachineTicket *ticket, uint32_t index) const
  {
    if (ticket == nullptr || index >= ticket->placementTopologyEpochs.size())
    {
      return 0;
    }

    return ticket->placementTopologyEpochs[index];
  }

  uint32_t desiredReplicaCountForShardGroup(uint32_t shardGroup) const
  {
    bool keepBlueAndGreen = (statefulWorkerTopologyUpgradeLocksShardGroup(shardGroup) && statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::greenBootstrap);
    return uint32_t(3 + (keepBlueAndGreen ? 3 : 0));
  }

  uint32_t maxReplicasPerRackForShardGroup(uint32_t shardGroup) const
  {
    return uint32_t(statefulWorkerTopologyUpgradeLocksShardGroup(shardGroup) ? 2 : 1);
  }

  uint32_t replicaCountForShardGroupOnRack(uint32_t shardGroup, Rack *rack)
  {
    if (rack == nullptr)
    {
      return 0;
    }

    uint32_t count = 0;
    for (ContainerView *container : containersByShardGroup[shardGroup])
    {
      if (container == nullptr || container->machine == nullptr)
      {
        continue;
      }

      if (container->state == ContainerState::destroyed)
      {
        continue;
      }

      if (container->machine->rack == rack)
      {
        ++count;
      }
    }

    if (count == 0 && racksByShardGroup[shardGroup].contains(rack))
    {
      count = 1;
    }

    return count;
  }

  bool canPlaceReplicaForShardGroupOnRack(uint32_t shardGroup, Rack *rack)
  {
    return (replicaCountForShardGroupOnRack(shardGroup, rack) < maxReplicasPerRackForShardGroup(shardGroup));
  }

  DataStrategy topologyUpgradeConstructionDataStrategy(uint32_t shardGroup) const
  {
    return statefulWorkerTopologyUpgradeLocksShardGroup(shardGroup) ? DataStrategy::seeding : DataStrategy::sharding;
  }

  DataStrategy architectedStatefulConstructionDataStrategy(uint32_t shardGroup) const
  {
    if (statefulWorkerTopologyUpgradeLocksShardGroup(shardGroup))
    {
      return DataStrategy::seeding;
    }

    return (previous ? DataStrategy::seeding : DataStrategy::genesis);
  }

  uint32_t currentServingStatefulTopologyEpochForLockedShardGroups(uint32_t fallbackWorkerCount) const
  {
    uint32_t sourceEpoch = 0;
    for (ContainerView *container : containers)
    {
      if (container == nullptr || container->isStateful == false || container->state == ContainerState::destroyed || statefulWorkerTopologyLockedShardGroups.contains(container->shardGroup) == false)
      {
        continue;
      }

      StatefulTopology topology = container->effectiveStatefulTopology(plan);
      if (topology.topologyEpoch == 0 || topology.workerCount != fallbackWorkerCount || prodigyStatefulTopologyServesClients(topology) == false)
      {
        continue;
      }

      if (sourceEpoch == 0)
      {
        sourceEpoch = topology.topologyEpoch;
      }
      else if (sourceEpoch != topology.topologyEpoch)
      {
        return fallbackWorkerCount;
      }
    }

    return (sourceEpoch == 0) ? fallbackWorkerCount : sourceEpoch;
  }

  void armStatefulWorkerTopologyUpgrade(uint32_t sourceWorkerCount,
                                        uint32_t targetWorkerCount,
                                        uint16_t targetLogicalCores,
                                        uint32_t targetMemoryMB,
                                        uint32_t targetStorageMB)
  {
    statefulWorkerTopologyUpgradePending = true;
    statefulWorkerTopologyUpgradePhase = StatefulWorkerTopologyUpgradePhase::greenBootstrap;
    statefulWorkerTopologyUpgradePhaseChangedAtMs = Time::now<TimeResolution::ms>();
    statefulWorkerTopologyUpgradeOperationID = generateTopologyUpgradeOperationID();
    statefulWorkerTopologyUpgradeSourceWorkerCount = sourceWorkerCount;
    statefulWorkerTopologyUpgradeTargetWorkerCount = targetWorkerCount;
    statefulWorkerTopologyUpgradeTargetLogicalCores = targetLogicalCores;
    statefulWorkerTopologyUpgradeTargetMemoryMB = targetMemoryMB;
    statefulWorkerTopologyUpgradeTargetStorageMB = targetStorageMB;
    statefulWorkerTopologyLockedShardGroups.clear();
    cancelStatefulWorkerTopologyUpgradeRollbackTimer();

    for (uint32_t shardGroup = 0; shardGroup < nShardGroups; ++shardGroup)
    {
      statefulWorkerTopologyLockedShardGroups.insert(shardGroup);
    }

    statefulWorkerTopologyUpgradeSourceEpoch = currentServingStatefulTopologyEpochForLockedShardGroups(sourceWorkerCount);
    statefulWorkerTopologyUpgradeTargetEpoch = generateDistinctTopologyUpgradeEpoch(statefulWorkerTopologyUpgradeSourceEpoch);

#if PRODIGY_DEBUG
    std::fprintf(stderr, "stateful topology upgrade arm deploymentID=%llu cores=%u->%u workers=%u->%u sourceEpoch=%u targetEpoch=%u lockedGroups=%u\n",
                 (unsigned long long)plan.config.deploymentID(),
                 unsigned(plan.config.nLogicalCores),
                 unsigned(targetLogicalCores),
                 unsigned(sourceWorkerCount),
                 unsigned(targetWorkerCount),
                 unsigned(statefulWorkerTopologyUpgradeSourceEpoch),
                 unsigned(statefulWorkerTopologyUpgradeTargetEpoch),
                 unsigned(statefulWorkerTopologyLockedShardGroups.size()));
    std::fflush(stderr);
#endif

    for (ContainerView *container : containers)
    {
      if (container == nullptr || statefulWorkerTopologyLockedShardGroups.contains(container->shardGroup) == false)
      {
        continue;
      }

      configureStatefulWorkerTopologyUpgradeSource(container);
      reconcileLiveStatefulTopologyServices(container);
    }

    persistStatefulWorkerTopologyUpgradeOperation();

    Vector<uint32_t> shardGroups = {};
    shardGroups.reserve(statefulWorkerTopologyLockedShardGroups.size() * 3);
    for (uint32_t shardGroup : statefulWorkerTopologyLockedShardGroups)
    {
      shardGroups.push_back(shardGroup);
      shardGroups.push_back(shardGroup);
      shardGroups.push_back(shardGroup);
    }

    if (thisBrain != nullptr && shardGroups.empty() == false)
    {
      spinStateful(nullptr, shardGroups);
      if (toSchedule.size() > 0)
      {
        schedule(nullptr);
      }
    }
  }

private:

  void deployCanaries(CoroutineStack *coro, uint32_t nCanaries)
  {
    state = DeploymentState::canaries;
    stateChangedAtMs = Time::now<TimeResolution::ms>();

    uint32_t deferredTargetBase = nTargetBase;
    uint32_t deferredTargetSurge = nTargetSurge;
    nTargetBase = 0;
    nTargetSurge = 0;
    nTargetCanary = nCanaries;

    // start canaries and once they run succesfully for some period of time and none fail, we can continue

    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          spinStateless(coro);
        }))
    {

      nSuspended += 1;
      co_await coro->suspendAtIndex(suspendIndex);
      nSuspended -= 1;
    }

    co_await coro->suspendUsRunThis([&](void) -> void {
      nSuspended += 1;
      schedule(coro);
      nSuspended -= 1;
    });

    if (state == DeploymentState::failed)
    {
      rollbackFailedCanaries();
      co_return;
    }

    canaryStack = coro;
    setCanaryTimeout();

    nSuspended += 1;
    co_await coro->suspend();
    nSuspended -= 1;

    if (state == DeploymentState::failed) // one or more canaries failed
    {
      rollbackFailedCanaries();
      co_return;
    }
    else
    {
      thisBrain->pushSpinApplicationProgressToMothership(this, "canaries succeeded"_ctv);

      uint32_t promotedHealthy = nHealthyCanary;
      nTargetBase = deferredTargetBase;
      nTargetSurge = deferredTargetSurge;
      nDeployedBase += nDeployedCanary;
      nDeployedCanary = 0;
      nHealthyBase += promotedHealthy;
      nTargetCanary = 0;
      nHealthyCanary = 0;

      if (previous && previous->state == DeploymentState::running)
      {
        previous->beginDecommissioningForRollForward();
      }

      // upgrade canaries
      for (ContainerView *container : containers)
      {
        if (container->lifetime == ApplicationLifetime::canary)
        {
          container->lifetime = ApplicationLifetime::base;
          container->proxySend(NeuronTopic::changeContainerLifetime, container->uuid, ApplicationLifetime::base);
        }
      }

      canaryStack = nullptr;
    }
  }

  void rollbackFailedCanaries(void)
  {
    canaryStack = nullptr;
    nTargetCanary = 0;
    nHealthyCanary = 0;

    // cancel canaries lifetime timeout
    Ring::queueCancelTimeout(&canaryTimer);

    auto copiedCanaries = containers;
    // kill the other canaries
    for (ContainerView *container : copiedCanaries)
    {
      if (container == nullptr || containers.contains(container) == false)
      {
        continue;
      }

      queueSend(container->machine, NeuronTopic::killContainer, container->uuid); // by the time these return... the deployment will have been destroyed....

      destructContainer(container);
      containerDestroyed(container);
    }

    rollback();
  }

  ContainerView *constructOnMachine(Machine *machine, ApplicationLifetime lifetime, Vector<uint32_t> assignedGPUMemoryMBs = {}, Vector<AssignedGPUDevice> assignedGPUDevices = {})
  {
    ContainerView *container = new ContainerView();
    container->createdAtMs = Time::now<TimeResolution::ms>();
    container->uuid = Random::generateNumberWithNBits<128, uint128_t>();
    container->state = ContainerState::planned;
    container->deploymentID = plan.config.deploymentID();
    container->applicationID = plan.config.applicationID;
    container->lifetime = lifetime;
    container->machine = machine;
    container->isStateful = plan.isStateful;
    if (plan.config.type == ApplicationType::task)
    {
      container->taskAttemptNumber = thisBrain->nextTaskAttemptNumber(plan);
    }
    container->assignedGPUMemoryMBs = std::move(assignedGPUMemoryMBs);
    container->assignedGPUDevices = std::move(assignedGPUDevices);

    thisBrain->containers.insert_or_assign(container->uuid, container);
    machine->upsertContainerIndexEntry(container->deploymentID, container);
    containers.insert(container);

    return container;
  }

  static uint64_t generateTopologyUpgradeOperationID(void)
  {
    uint64_t operationID = 0;
    while (operationID == 0)
    {
      operationID = Random::generateNumberWithNBits<64, uint64_t>();
    }

    return operationID;
  }

  static uint32_t generateDistinctTopologyUpgradeEpoch(uint32_t avoid)
  {
    uint32_t epoch = 0;
    while (epoch == 0 || epoch == avoid)
    {
      epoch = Random::generateNumberWithNBits<32, uint32_t>();
    }

    return epoch;
  }

  StatefulMeshRoles statefulMeshRolesForShardGroup(uint32_t shardGroup) const
  {
    return StatefulMeshRoles::forShardGroup(plan.stateful, plan.config.applicationID, shardGroup);
  }

  StatefulTopology statefulWorkerTopologyUpgradeSourceTopology(uint32_t shardGroup) const
  {
    StatefulTopology topology = {};
    topology.operationID = statefulWorkerTopologyUpgradeOperationID;
    topology.shardGroup = shardGroup;
    topology.topologyEpoch = statefulWorkerTopologyUpgradeSourceEpoch;
    topology.workerCount = statefulWorkerTopologyUpgradeSourceWorkerCount;
    topology.servingMode = (statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::blueDraining)
                               ? StatefulTopologyServingMode::drainOnly
                               : StatefulTopologyServingMode::serve;
    topology.sourceEpoch = statefulWorkerTopologyUpgradeSourceEpoch;
    topology.targetEpoch = statefulWorkerTopologyUpgradeTargetEpoch;
    topology.bridgeMode = (statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::blueDraining)
                              ? StatefulTopologyBridgeMode::targetToSource
                              : StatefulTopologyBridgeMode::sourceToTarget;
    return topology;
  }

  StatefulTopology statefulWorkerTopologyUpgradeTargetTopology(uint32_t shardGroup) const
  {
    StatefulTopology topology = {};
    topology.operationID = statefulWorkerTopologyUpgradeOperationID;
    topology.shardGroup = shardGroup;
    topology.topologyEpoch = statefulWorkerTopologyUpgradeTargetEpoch;
    topology.workerCount = statefulWorkerTopologyUpgradeTargetWorkerCount;
    topology.servingMode = (statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::blueDraining)
                               ? StatefulTopologyServingMode::serve
                               : StatefulTopologyServingMode::catchupOnly;
    topology.sourceEpoch = statefulWorkerTopologyUpgradeSourceEpoch;
    topology.targetEpoch = statefulWorkerTopologyUpgradeTargetEpoch;
    topology.bridgeMode = (statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::blueDraining)
                              ? StatefulTopologyBridgeMode::targetToSource
                              : StatefulTopologyBridgeMode::sourceToTarget;
    return topology;
  }

  void configureStatefulWorkerTopologyUpgradeSource(ContainerView *container)
  {
    if (container == nullptr)
    {
      return;
    }

    container->explicitStatefulMeshRoles = statefulMeshRolesForShardGroup(container->shardGroup);
    container->explicitStatefulTopology = statefulWorkerTopologyUpgradeSourceTopology(container->shardGroup);
  }

  void configureStatefulWorkerTopologyUpgradeTarget(ContainerView *container)
  {
    if (container == nullptr)
    {
      return;
    }

    container->explicitStatefulMeshRoles = statefulMeshRolesForShardGroup(container->shardGroup);
    container->explicitStatefulTopology = statefulWorkerTopologyUpgradeTargetTopology(container->shardGroup);
  }

public:

  bool captureStatefulWorkerTopologyUpgradeOperation(ProdigyStatefulWorkerTopologyUpgradeOperation& operation) const
  {
    operation = {};
    if (statefulWorkerTopologyUpgradePendingForAnyShardGroup() == false)
    {
      return false;
    }

    operation.deploymentID = plan.config.deploymentID();
    operation.applicationID = plan.config.applicationID;
    operation.operationID = statefulWorkerTopologyUpgradeOperationID;
    operation.phase = statefulWorkerTopologyUpgradePhase;
    operation.sourceWorkerCount = statefulWorkerTopologyUpgradeSourceWorkerCount;
    operation.targetWorkerCount = statefulWorkerTopologyUpgradeTargetWorkerCount;
    operation.sourceEpoch = statefulWorkerTopologyUpgradeSourceEpoch;
    operation.targetEpoch = statefulWorkerTopologyUpgradeTargetEpoch;
    operation.targetLogicalCores = statefulWorkerTopologyUpgradeTargetLogicalCores;
    operation.targetMemoryMB = statefulWorkerTopologyUpgradeTargetMemoryMB;
    operation.targetStorageMB = statefulWorkerTopologyUpgradeTargetStorageMB;
    operation.updatedAtMs = statefulWorkerTopologyUpgradePhaseChangedAtMs;

    operation.lockedShardGroups.reserve(statefulWorkerTopologyLockedShardGroups.size());
    for (uint32_t shardGroup : statefulWorkerTopologyLockedShardGroups)
    {
      operation.lockedShardGroups.push_back(shardGroup);
    }
    std::sort(operation.lockedShardGroups.begin(), operation.lockedShardGroups.end());

    return true;
  }

  bool restoreStatefulWorkerTopologyUpgradeOperation(const ProdigyStatefulWorkerTopologyUpgradeOperation& operation)
  {
    if (operation.deploymentID != plan.config.deploymentID() || operation.applicationID != plan.config.applicationID || operation.operationID == 0 || operation.phase == StatefulWorkerTopologyUpgradePhase::none || operation.lockedShardGroups.empty())
    {
      return false;
    }

    statefulWorkerTopologyUpgradePending = true;
    statefulWorkerTopologyUpgradePhase = operation.phase;
    statefulWorkerTopologyUpgradeOperationID = operation.operationID;
    statefulWorkerTopologyUpgradeSourceWorkerCount = operation.sourceWorkerCount;
    statefulWorkerTopologyUpgradeTargetWorkerCount = operation.targetWorkerCount;
    statefulWorkerTopologyUpgradeSourceEpoch = operation.sourceEpoch;
    statefulWorkerTopologyUpgradeTargetEpoch = operation.targetEpoch;
    statefulWorkerTopologyUpgradeTargetLogicalCores = operation.targetLogicalCores;
    statefulWorkerTopologyUpgradeTargetMemoryMB = operation.targetMemoryMB;
    statefulWorkerTopologyUpgradeTargetStorageMB = operation.targetStorageMB;
    statefulWorkerTopologyUpgradePhaseChangedAtMs = operation.updatedAtMs;
    statefulWorkerTopologyLockedShardGroups.clear();
    for (uint32_t shardGroup : operation.lockedShardGroups)
    {
      statefulWorkerTopologyLockedShardGroups.insert(shardGroup);
    }

    reconcileStatefulWorkerTopologyUpgradeContainers();
    armStatefulWorkerTopologyUpgradeRollbackTimer();
    return true;
  }

  bool restorePersistedStatefulWorkerTopologyUpgradeOperation(void)
  {
    if (thisBrain == nullptr)
    {
      return false;
    }

    for (const ProdigyStatefulWorkerTopologyUpgradeOperation& operation : thisBrain->statefulWorkerTopologyUpgradeRuntimeState)
    {
      if (restoreStatefulWorkerTopologyUpgradeOperation(operation))
      {
        return true;
      }
    }

    return false;
  }

  void persistStatefulWorkerTopologyUpgradeOperation(void)
  {
    if (thisBrain == nullptr)
    {
      return;
    }

    ProdigyStatefulWorkerTopologyUpgradeOperation snapshot = {};
    bool haveSnapshot = captureStatefulWorkerTopologyUpgradeOperation(snapshot);
    auto& operations = thisBrain->statefulWorkerTopologyUpgradeRuntimeState;

    for (auto it = operations.begin(); it != operations.end(); ++it)
    {
      if (it->deploymentID != plan.config.deploymentID())
      {
        continue;
      }

      if (haveSnapshot)
      {
        *it = std::move(snapshot);
      }
      else
      {
        operations.erase(it);
      }

      thisBrain->noteStatefulWorkerTopologyUpgradeRuntimeStateChanged();
      return;
    }

    if (haveSnapshot)
    {
      operations.push_back(std::move(snapshot));
      thisBrain->noteStatefulWorkerTopologyUpgradeRuntimeStateChanged();
    }
  }

  bool captureDeferredStatefulScaleIntent(ProdigyDeferredStatefulScaleIntent& intent) const
  {
    intent = {};
    if (statefulDeferredScaleIntentPending() == false)
    {
      return false;
    }

    intent.deploymentID = plan.config.deploymentID();
    intent.applicationID = plan.config.applicationID;
    intent.targetShardGroups = (deferredStatefulTargetShardGroups > nShardGroups)
                                   ? deferredStatefulTargetShardGroups
                                   : nShardGroups;
    intent.targetLogicalCores = (deferredStatefulTargetLogicalCores > 0)
                                    ? deferredStatefulTargetLogicalCores
                                    : plan.config.nLogicalCores;
    intent.targetMemoryMB = (deferredStatefulTargetMemoryMB > 0)
                                ? deferredStatefulTargetMemoryMB
                                : plan.config.memoryMB;
    intent.targetStorageMB = (deferredStatefulTargetStorageMB > 0)
                                 ? deferredStatefulTargetStorageMB
                                 : plan.config.storageMB;
    intent.updatedAtMs = statefulDeferredScaleIntentUpdatedAtMs;
    return true;
  }

  bool restoreDeferredStatefulScaleIntent(const ProdigyDeferredStatefulScaleIntent& intent)
  {
    if (intent.deploymentID != plan.config.deploymentID() || intent.applicationID != plan.config.applicationID)
    {
      return false;
    }

    deferredStatefulTargetShardGroups = (intent.targetShardGroups > nShardGroups)
                                            ? intent.targetShardGroups
                                            : nShardGroups;
    deferredStatefulTargetLogicalCores = (intent.targetLogicalCores > 0)
                                             ? intent.targetLogicalCores
                                             : plan.config.nLogicalCores;
    deferredStatefulTargetMemoryMB = (intent.targetMemoryMB > 0)
                                         ? intent.targetMemoryMB
                                         : plan.config.memoryMB;
    deferredStatefulTargetStorageMB = (intent.targetStorageMB > 0)
                                          ? intent.targetStorageMB
                                          : plan.config.storageMB;
    statefulDeferredScaleIntentUpdatedAtMs = intent.updatedAtMs;
    return statefulDeferredScaleIntentPending();
  }

  bool restorePersistedDeferredStatefulScaleIntent(void)
  {
    if (thisBrain == nullptr)
    {
      return false;
    }

    for (const ProdigyDeferredStatefulScaleIntent& intent : thisBrain->deferredStatefulScaleIntentRuntimeState)
    {
      if (restoreDeferredStatefulScaleIntent(intent))
      {
        return true;
      }
    }

    return false;
  }

  void persistDeferredStatefulScaleIntent(void)
  {
    if (thisBrain == nullptr)
    {
      return;
    }

    ProdigyDeferredStatefulScaleIntent snapshot = {};
    bool haveSnapshot = captureDeferredStatefulScaleIntent(snapshot);
    auto& intents = thisBrain->deferredStatefulScaleIntentRuntimeState;

    for (auto it = intents.begin(); it != intents.end(); ++it)
    {
      if (it->deploymentID != plan.config.deploymentID())
      {
        continue;
      }

      if (haveSnapshot)
      {
        *it = std::move(snapshot);
      }
      else
      {
        intents.erase(it);
      }

      thisBrain->noteDeferredStatefulScaleIntentRuntimeStateChanged();
      return;
    }

    if (haveSnapshot)
    {
      intents.push_back(std::move(snapshot));
      thisBrain->noteDeferredStatefulScaleIntentRuntimeStateChanged();
    }
  }

  void clearDeferredStatefulScaleIntent(void)
  {
    deferredStatefulTargetShardGroups = 0;
    deferredStatefulTargetLogicalCores = 0;
    deferredStatefulTargetMemoryMB = 0;
    deferredStatefulTargetStorageMB = 0;
    statefulDeferredScaleIntentUpdatedAtMs = 0;
    persistDeferredStatefulScaleIntent();
  }

  bool dispatchDeferredStatefulScaleIntent(void)
  {
    if (plan.isStateful == false || deployingNewShardGroup || statefulWorkerTopologyUpgradePendingForAnyShardGroup() || waitingOnContainers.empty() == false || toSchedule.empty() == false)
    {
      return false;
    }

    if (statefulDeferredScaleIntentPending() == false)
    {
      clearDeferredStatefulScaleIntent();
      return false;
    }

    if (deferredStatefulTargetLogicalCores > 0 && (deferredStatefulTargetLogicalCores != plan.config.nLogicalCores || deferredStatefulTargetMemoryMB != plan.config.memoryMB || deferredStatefulTargetStorageMB != plan.config.storageMB))
    {
      uint32_t oldWorkerCount = prodigyStatefulWorkerCountForLogicalCores(plan.config.nLogicalCores);
      uint32_t targetWorkerCount = prodigyStatefulWorkerCountForLogicalCores(deferredStatefulTargetLogicalCores);
      armStatefulWorkerTopologyUpgrade(
          oldWorkerCount,
          targetWorkerCount,
          deferredStatefulTargetLogicalCores,
          deferredStatefulTargetMemoryMB,
          deferredStatefulTargetStorageMB);
      persistDeferredStatefulScaleIntent();
      return true;
    }

    if (deferredStatefulTargetShardGroups > nShardGroups)
    {
      deployingNewShardGroup = true;

      Vector<uint32_t> shardGroups;
      shardGroups.insert(shardGroups.end(), 3, nShardGroups);

      nShardGroups += 1;
      recomputeStatefulBaseTargetFromShardGroups();
      persistDeferredStatefulScaleIntent();
      spinStateful(nullptr, shardGroups);
      if (toSchedule.size() > 0)
      {
        schedule(nullptr);
      }
      return true;
    }

    clearDeferredStatefulScaleIntent();
    return false;
  }

  void clearStatefulWorkerTopologyUpgradeOperation(void)
  {
    cancelStatefulWorkerTopologyUpgradeRollbackTimer();

    bytell_hash_set<uint32_t> lockedShardGroups = statefulWorkerTopologyLockedShardGroups;
    for (ContainerView *container : containers)
    {
      if (container == nullptr || lockedShardGroups.contains(container->shardGroup) == false)
      {
        continue;
      }

      container->clearStatefulTopologyCutoverBarrier();
    }

    statefulWorkerTopologyUpgradePending = false;
    statefulWorkerTopologyUpgradePhase = StatefulWorkerTopologyUpgradePhase::none;
    statefulWorkerTopologyUpgradeOperationID = 0;
    statefulWorkerTopologyUpgradeSourceWorkerCount = 0;
    statefulWorkerTopologyUpgradeTargetWorkerCount = 0;
    statefulWorkerTopologyUpgradeSourceEpoch = 0;
    statefulWorkerTopologyUpgradeTargetEpoch = 0;
    statefulWorkerTopologyUpgradeTargetLogicalCores = 0;
    statefulWorkerTopologyUpgradeTargetMemoryMB = 0;
    statefulWorkerTopologyUpgradeTargetStorageMB = 0;
    statefulWorkerTopologyUpgradePhaseChangedAtMs = 0;
    statefulWorkerTopologyLockedShardGroups.clear();
    persistStatefulWorkerTopologyUpgradeOperation();
  }

private:

  void cancelStatefulWorkerTopologyUpgradeRollbackTimer(void)
  {
    if (statefulWorkerTopologyRollbackTimer.isLive())
    {
      Ring::queueCancelTimeout(&statefulWorkerTopologyRollbackTimer);
    }
  }

  void armStatefulWorkerTopologyUpgradeRollbackTimer(void)
  {
    cancelStatefulWorkerTopologyUpgradeRollbackTimer();

    if (statefulWorkerTopologyUpgradePendingForAnyShardGroup() == false || statefulWorkerTopologyUpgradePhase != StatefulWorkerTopologyUpgradePhase::blueDraining)
    {
      return;
    }

    const int64_t nowMs = Time::now<TimeResolution::ms>();
    const int64_t deadlineMs = statefulWorkerTopologyUpgradeRollbackDeadlineMs();
    if (deadlineMs == 0 || nowMs >= deadlineMs)
    {
      scheduleStatefulWorkerTopologyUpgradeBlueRetirement();
      return;
    }

    if (Ring::getRingFD() <= 0)
    {
      return;
    }

    statefulWorkerTopologyRollbackTimer.setTimeoutMs(uint64_t(deadlineMs - nowMs));
    statefulWorkerTopologyRollbackTimer.dispatcher = this;
    statefulWorkerTopologyRollbackTimer.flags = uint64_t(DeploymentTimeoutFlags::statefulTopologyRollbackWindow);
    Ring::queueTimeout(&statefulWorkerTopologyRollbackTimer);
  }

  void statefulWorkerTopologyUpgradeRollbackWindowExpired(void)
  {
    scheduleStatefulWorkerTopologyUpgradeBlueRetirement();
  }

  static void clearStatefulWorkerTopologyCutoverBarrier(ContainerView *container)
  {
    if (container != nullptr)
    {
      container->clearStatefulTopologyCutoverBarrier();
    }
  }

  bool containerHasStatefulWorkerTopologyCutoverBarrier(const ContainerView *container) const
  {
    return (container != nullptr && container->hasStatefulTopologyCutoverBarrier(
                                        statefulWorkerTopologyUpgradeSourceEpoch,
                                        statefulWorkerTopologyUpgradeTargetEpoch));
  }

  bool containerUsesStatefulWorkerTopologyUpgradeTarget(const ContainerView *container) const
  {
    if (container == nullptr || container->isStateful == false)
    {
      return false;
    }

    const StatefulTopology& topology = container->explicitStatefulTopology;
    return (topology.operationID == statefulWorkerTopologyUpgradeOperationID && topology.topologyEpoch == statefulWorkerTopologyUpgradeTargetEpoch);
  }

  bool containerUsesStatefulWorkerTopologyUpgradeSource(const ContainerView *container) const
  {
    if (container == nullptr || container->isStateful == false)
    {
      return false;
    }

    const StatefulTopology& topology = container->explicitStatefulTopology;
    return (topology.operationID == statefulWorkerTopologyUpgradeOperationID && topology.topologyEpoch == statefulWorkerTopologyUpgradeSourceEpoch);
  }

  StatefulTopology statefulWorkerTopologyUpgradeSteadyTargetTopology(uint32_t shardGroup) const
  {
    StatefulTopology topology = {};
    topology.shardGroup = shardGroup;
    topology.topologyEpoch = statefulWorkerTopologyUpgradeTargetEpoch;
    topology.workerCount = statefulWorkerTopologyUpgradeTargetWorkerCount;
    topology.servingMode = StatefulTopologyServingMode::serve;
    topology.sourceEpoch = statefulWorkerTopologyUpgradeTargetEpoch;
    topology.targetEpoch = statefulWorkerTopologyUpgradeTargetEpoch;
    topology.bridgeMode = StatefulTopologyBridgeMode::none;
    return topology;
  }

  void updateVerticalAdjustmentForStatefulWorkerTopologyTarget(const ApplicationConfig& targetConfig)
  {
    if (verticalResourceBaseInitialized == false)
    {
      return;
    }

    auto adjustmentFromTarget = [](uint32_t base, uint32_t target) -> int32_t {
      int64_t delta = int64_t(target) - int64_t(base);
      if (delta > int64_t(std::numeric_limits<int32_t>::max()))
      {
        delta = int64_t(std::numeric_limits<int32_t>::max());
      }
      else if (delta < int64_t(std::numeric_limits<int32_t>::min()))
      {
        delta = int64_t(std::numeric_limits<int32_t>::min());
      }

      return int32_t(delta);
    };

    verticalAdjustment_nLogicalCores = adjustmentFromTarget(verticalResourceBase_nLogicalCores, targetConfig.nLogicalCores);
    verticalAdjustment_memoryMB = adjustmentFromTarget(verticalResourceBase_memoryMB, targetConfig.memoryMB);
    verticalAdjustment_storageMB = adjustmentFromTarget(verticalResourceBase_storageMB, targetConfig.storageMB);
  }

  void recountStatefulDeploymentCountersFromLiveContainers(void)
  {
    if (plan.isStateful == false)
    {
      return;
    }

    nDeployedBase = 0;
    nDeployedCanary = 0;
    nDeployedSurge = 0;
    nHealthyBase = 0;
    nHealthyCanary = 0;
    nHealthySurge = 0;

    for (ContainerView *container : containers)
    {
      if (container == nullptr || container->state == ContainerState::destroyed)
      {
        continue;
      }

      switch (container->lifetime)
      {
        case ApplicationLifetime::base:
          {
            nDeployedBase += 1;
            if (container->state == ContainerState::healthy)
            {
              nHealthyBase += 1;
            }
            break;
          }
        case ApplicationLifetime::canary:
          {
            nDeployedCanary += 1;
            if (container->state == ContainerState::healthy)
            {
              nHealthyCanary += 1;
            }
            break;
          }
        case ApplicationLifetime::surge:
          {
            nDeployedSurge += 1;
            if (container->state == ContainerState::healthy)
            {
              nHealthySurge += 1;
            }
            break;
          }
      }
    }
  }

  bool statefulWorkerTopologyUpgradeBlueRetired(void) const
  {
    if (statefulWorkerTopologyUpgradePendingForAnyShardGroup() == false || statefulWorkerTopologyUpgradePhase != StatefulWorkerTopologyUpgradePhase::blueDraining)
    {
      return false;
    }

    uint32_t observedTargets = 0;
    for (ContainerView *container : containers)
    {
      if (container == nullptr || statefulWorkerTopologyLockedShardGroups.contains(container->shardGroup) == false)
      {
        continue;
      }

      if (containerUsesStatefulWorkerTopologyUpgradeSource(container))
      {
        return false;
      }

      if (containerUsesStatefulWorkerTopologyUpgradeTarget(container))
      {
        ++observedTargets;
      }
    }

    return (observedTargets == uint32_t(statefulWorkerTopologyLockedShardGroups.size() * 3));
  }

  void completeStatefulWorkerTopologyUpgradeIfReady(void)
  {
    if (waitingOnContainers.empty() == false || toSchedule.empty() == false)
    {
      return;
    }

    if (statefulWorkerTopologyUpgradeBlueRetired() == false)
    {
      return;
    }

    ApplicationConfig targetConfig = statefulWorkerTopologyUpgradeTargetConfig();
    uint32_t targetWorkerCount = statefulWorkerTopologyUpgradeTargetWorkerCount;
    uint32_t targetEpoch = statefulWorkerTopologyUpgradeTargetEpoch;
    bytell_hash_set<uint32_t> lockedShardGroups = statefulWorkerTopologyLockedShardGroups;

    plan.config = targetConfig;
    updateVerticalAdjustmentForStatefulWorkerTopologyTarget(targetConfig);

    for (ContainerView *container : containers)
    {
      if (container == nullptr || lockedShardGroups.contains(container->shardGroup) == false)
      {
        continue;
      }

      container->explicitStatefulMeshRoles = statefulMeshRolesForShardGroup(container->shardGroup);
      container->explicitStatefulTopology = statefulWorkerTopologyUpgradeSteadyTargetTopology(container->shardGroup);
      container->explicitStatefulTopology.workerCount = targetWorkerCount;
      container->explicitStatefulTopology.topologyEpoch = targetEpoch;
      container->explicitStatefulTopology.sourceEpoch = targetEpoch;
      container->explicitStatefulTopology.targetEpoch = targetEpoch;
    }

    clearStatefulWorkerTopologyUpgradeOperation();

    recomputeStatefulBaseTargetFromShardGroups();
    recountStatefulDeploymentCountersFromLiveContainers();

    for (ContainerView *container : containers)
    {
      if (container == nullptr || lockedShardGroups.contains(container->shardGroup) == false)
      {
        continue;
      }

      reconcileLiveStatefulTopologyServices(container);
    }

    dispatchDeferredStatefulScaleIntent();
  }

  void rollbackStatefulWorkerTopologyUpgradeCutover(void)
  {
    if (statefulWorkerTopologyUpgradePendingForAnyShardGroup() == false || statefulWorkerTopologyUpgradePhase != StatefulWorkerTopologyUpgradePhase::blueDraining)
    {
      return;
    }

    if (statefulWorkerTopologyUpgradeRollbackEligible() == false)
    {
      scheduleStatefulWorkerTopologyUpgradeBlueRetirement();
      return;
    }

    bool haveSource = false;
    for (ContainerView *container : containers)
    {
      if (container == nullptr || statefulWorkerTopologyLockedShardGroups.contains(container->shardGroup) == false || containerUsesStatefulWorkerTopologyUpgradeSource(container) == false)
      {
        continue;
      }

      if (container->state != ContainerState::destroyed && container->state != ContainerState::destroying && container->state != ContainerState::aboutToDestroy)
      {
        haveSource = true;
        break;
      }
    }

    if (haveSource == false)
    {
      return;
    }

    statefulWorkerTopologyUpgradePhase = StatefulWorkerTopologyUpgradePhase::greenBootstrap;
    statefulWorkerTopologyUpgradePhaseChangedAtMs = Time::now<TimeResolution::ms>();
    for (uint32_t shardGroup : statefulWorkerTopologyLockedShardGroups)
    {
      masterForShardGroup.erase(shardGroup);
    }

    for (ContainerView *container : containers)
    {
      if (container == nullptr || container->isStateful == false || statefulWorkerTopologyLockedShardGroups.contains(container->shardGroup) == false)
      {
        continue;
      }

      clearStatefulWorkerTopologyCutoverBarrier(container);

      if (containerUsesStatefulWorkerTopologyUpgradeTarget(container))
      {
        configureStatefulWorkerTopologyUpgradeTarget(container);
      }
      else
      {
        configureStatefulWorkerTopologyUpgradeSource(container);
      }

      reconcileLiveStatefulTopologyServices(container);
    }

    persistStatefulWorkerTopologyUpgradeOperation();
  }

  void scheduleStatefulWorkerTopologyUpgradeBlueRetirement(void)
  {
    if (statefulWorkerTopologyUpgradePendingForAnyShardGroup() == false || statefulWorkerTopologyUpgradePhase != StatefulWorkerTopologyUpgradePhase::blueDraining)
    {
      return;
    }

    bool queued = false;
    for (ContainerView *container : containers)
    {
      if (container == nullptr || container->machine == nullptr || statefulWorkerTopologyLockedShardGroups.contains(container->shardGroup) == false || containerUsesStatefulWorkerTopologyUpgradeSource(container) == false || container->plannedWork != nullptr)
      {
        continue;
      }

      switch (container->state)
      {
        case ContainerState::planned:
        case ContainerState::scheduled:
        case ContainerState::healthy:
        case ContainerState::crashedRestarting:
          {
            scheduleStatefulDestruction(container);
            queued = true;
            break;
          }
        default:
          break;
      }
    }

    if (queued)
    {
      schedule(nullptr);
    }
  }

  bool statefulWorkerTopologyUpgradeGreenReadyForCutover(void) const
  {
    if (statefulWorkerTopologyUpgradePendingForAnyShardGroup() == false || statefulWorkerTopologyUpgradePhase != StatefulWorkerTopologyUpgradePhase::greenBootstrap)
    {
      return false;
    }

    const uint32_t expectedTargets = uint32_t(statefulWorkerTopologyLockedShardGroups.size() * 3);
    uint32_t observedTargets = 0;
    uint32_t readyTargets = 0;

    for (ContainerView *container : containers)
    {
      if (container == nullptr || statefulWorkerTopologyLockedShardGroups.contains(container->shardGroup) == false || containerUsesStatefulWorkerTopologyUpgradeTarget(container) == false)
      {
        continue;
      }

      ++observedTargets;
      if (container->state == ContainerState::healthy && container->runtimeReady && containerHasStatefulWorkerTopologyCutoverBarrier(container))
      {
        ++readyTargets;
      }
    }

    return (expectedTargets > 0 && observedTargets == expectedTargets && readyTargets == expectedTargets);
  }

  void commitStatefulWorkerTopologyUpgradeCutover(void)
  {
    if (statefulWorkerTopologyUpgradeGreenReadyForCutover() == false)
    {
      return;
    }

    statefulWorkerTopologyUpgradePhase = StatefulWorkerTopologyUpgradePhase::blueDraining;
    statefulWorkerTopologyUpgradePhaseChangedAtMs = Time::now<TimeResolution::ms>();
#if PRODIGY_DEBUG
    std::fprintf(stderr, "stateful topology cutover deploymentID=%llu sourceEpoch=%u targetEpoch=%u workers=%u->%u lockedGroups=%u\n",
                 (unsigned long long)plan.config.deploymentID(),
                 unsigned(statefulWorkerTopologyUpgradeSourceEpoch),
                 unsigned(statefulWorkerTopologyUpgradeTargetEpoch),
                 unsigned(statefulWorkerTopologyUpgradeSourceWorkerCount),
                 unsigned(statefulWorkerTopologyUpgradeTargetWorkerCount),
                 unsigned(statefulWorkerTopologyLockedShardGroups.size()));
    std::fflush(stderr);
#endif
    autoscaleTrace("autoscale topologyCutover deploymentID=%llu sourceEpoch=%u targetEpoch=%u workers=%u->%u lockedGroups=%u\n",
                   (unsigned long long)plan.config.deploymentID(),
                   unsigned(statefulWorkerTopologyUpgradeSourceEpoch),
                   unsigned(statefulWorkerTopologyUpgradeTargetEpoch),
                   unsigned(statefulWorkerTopologyUpgradeSourceWorkerCount),
                   unsigned(statefulWorkerTopologyUpgradeTargetWorkerCount),
                   unsigned(statefulWorkerTopologyLockedShardGroups.size()));
    for (uint32_t shardGroup : statefulWorkerTopologyLockedShardGroups)
    {
      masterForShardGroup.erase(shardGroup);
    }

    for (ContainerView *container : containers)
    {
      if (container == nullptr || container->isStateful == false || statefulWorkerTopologyLockedShardGroups.contains(container->shardGroup) == false)
      {
        continue;
      }

      clearStatefulWorkerTopologyCutoverBarrier(container);

      if (containerUsesStatefulWorkerTopologyUpgradeTarget(container))
      {
        configureStatefulWorkerTopologyUpgradeTarget(container);
      }
      else
      {
        configureStatefulWorkerTopologyUpgradeSource(container);
      }

      reconcileLiveStatefulTopologyServices(container);
    }

    persistStatefulWorkerTopologyUpgradeOperation();
    armStatefulWorkerTopologyUpgradeRollbackTimer();
  }

  void reconcileLiveStatefulTopologyServices(ContainerView *container)
  {
    if (container == nullptr || container->isStateful == false || thisBrain == nullptr || thisBrain->mesh == nullptr)
    {
      return;
    }

    StatefulMeshRoles roles = container->effectiveStatefulMeshRoles(plan);
    StatefulTopology topology = container->effectiveStatefulTopology(plan);

    auto ensureAdvertisement = [&](uint64_t service, ContainerState startAt, ContainerState stopAt) -> void {
      if (service == 0)
      {
        return;
      }

      auto it = container->advertisements.find(service);
      if (it == container->advertisements.end())
      {
        uint16_t port = container->getRandomAdvertisementPort();
        it = container->advertisements.emplace(service, Advertisement(service, startAt, stopAt, port)).first;
        container->advertisingOnPorts.insert(it->second.port);
      }

      if (startAt == ContainerState::scheduled)
      {
        if (container->state == ContainerState::scheduled || container->state == ContainerState::healthy)
        {
          thisBrain->mesh->advertise(service, container, it->second.port, false);
        }
      }
      else if (startAt == ContainerState::healthy && container->state == ContainerState::healthy)
      {
        thisBrain->mesh->advertise(service, container, it->second.port, false);
      }
    };

    auto eraseAdvertisement = [&](uint64_t service) -> void {
      if (service == 0)
      {
        return;
      }

      auto it = container->advertisements.find(service);
      if (it == container->advertisements.end())
      {
        return;
      }

      container->advertisingOnPorts.erase(it->second.port);
      thisBrain->mesh->stopAdvertisement(service, container, false);
      container->advertisements.erase(it);
    };

    auto ensureSubscription = [&](uint64_t service, ContainerState startAt, ContainerState stopAt, SubscriptionNature nature) -> void {
      if (service == 0)
      {
        return;
      }

      auto it = container->subscriptions.find(service);
      if (it == container->subscriptions.end())
      {
        it = container->subscriptions.emplace(service, Subscription(service, startAt, stopAt, nature)).first;
      }

      if (startAt == ContainerState::scheduled)
      {
        if (container->state == ContainerState::scheduled || container->state == ContainerState::healthy)
        {
          thisBrain->mesh->subscribe(service, container, it->second.nature, false);
        }
      }
    };

    auto eraseSubscription = [&](uint64_t service) -> void {
      if (service == 0)
      {
        return;
      }

      auto it = container->subscriptions.find(service);
      if (it == container->subscriptions.end())
      {
        return;
      }

      thisBrain->mesh->stopSubscription(service, container, it->second.nature, false);
      container->subscriptions.erase(it);
    };

    if (roles.topologyBridge != 0 && prodigyStatefulTopologyShouldAdvertiseBridge(topology))
    {
      ensureAdvertisement(roles.topologyBridge, ContainerState::scheduled, ContainerState::destroying);
    }
    else
    {
      eraseAdvertisement(roles.topologyBridge);
    }

    if (roles.topologyBridge != 0 && prodigyStatefulTopologyShouldSubscribeBridge(topology))
    {
      ensureSubscription(roles.topologyBridge, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all);
    }
    else
    {
      eraseSubscription(roles.topologyBridge);
    }

    if (prodigyStatefulTopologyServesClients(topology) == false)
    {
      eraseAdvertisement(roles.client);
      if (plan.stateful.allMasters == false)
      {
        auto masterIt = masterForShardGroup.find(container->shardGroup);
        if (masterIt != masterForShardGroup.end() && masterIt->second == container)
        {
          masterForShardGroup.erase(masterIt);
        }
      }
    }
    else if (roles.client != 0)
    {
      bool shouldAdvertiseClient = plan.stateful.allMasters;
      if (plan.stateful.allMasters == false)
      {
        auto masterIt = masterForShardGroup.find(container->shardGroup);
        if (masterIt == masterForShardGroup.end() || masterIt->second == nullptr || masterIt->second->state == ContainerState::destroyed)
        {
          masterForShardGroup.insert_or_assign(container->shardGroup, container);
          shouldAdvertiseClient = true;
        }
        else
        {
          shouldAdvertiseClient = (masterIt->second == container);
        }
      }

      if (shouldAdvertiseClient)
      {
        ensureAdvertisement(roles.client, ContainerState::healthy, ContainerState::destroying);
      }
      else
      {
        eraseAdvertisement(roles.client);
      }
    }
  }

  void reconcileStatefulWorkerTopologyUpgradeContainers(void)
  {
    if (statefulWorkerTopologyUpgradePendingForAnyShardGroup() == false)
    {
      return;
    }

    if (statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::blueDraining)
    {
      for (uint32_t shardGroup : statefulWorkerTopologyLockedShardGroups)
      {
        masterForShardGroup.erase(shardGroup);
      }
    }

    for (ContainerView *container : containers)
    {
      if (container == nullptr || container->isStateful == false || statefulWorkerTopologyLockedShardGroups.contains(container->shardGroup) == false)
      {
        continue;
      }

      const StatefulTopology& explicitTopology = container->explicitStatefulTopology;
      if (explicitTopology.operationID == statefulWorkerTopologyUpgradeOperationID && explicitTopology.topologyEpoch == statefulWorkerTopologyUpgradeTargetEpoch)
      {
        configureStatefulWorkerTopologyUpgradeTarget(container);
      }
      else
      {
        configureStatefulWorkerTopologyUpgradeSource(container);
      }

      reconcileLiveStatefulTopologyServices(container);
    }
  }

  bool isDecommissioning(void) const // it's possible the new deployment has to wait for this to complete work... and it won't be marked as decomissioning until after that?
  {
    if (next)
    {
      switch (next->state)
      {
        default: // no others possible

        // waitingToDeploy either means (still transitioning from n-2 deployment to n-1 deployment)
        // OR head is waiting for them to drain their scheduling queue
        case DeploymentState::waitingToDeploy: // technically this would be about to decommission
        case DeploymentState::canaries:
        case DeploymentState::deploying:
          {
            return true;
          }
      }
    }

    return false;
  }

  template <typename... Args>
  void queueSend(Machine *machine, NeuronTopic topic, Args&&...args)
  {
    if (machine == nullptr)
    {
      return;
    }

    uint32_t bytesBefore = machine->neuron.wBuffer.size();
    Message::construct(machine->neuron.wBuffer, topic, std::forward<Args>(args)...);
    bool closing = Ring::socketIsClosing(&machine->neuron);
    bool active = (closing == false && machine->neuron.isFixedFile && machine->neuron.fslot >= 0);
    uint32_t bytesAfter = machine->neuron.wBuffer.size();

#if PRODIGY_DEBUG
    if (topic == NeuronTopic::spinContainer || topic == NeuronTopic::killContainer || active == false || closing)
    {
      std::fprintf(stderr, "deployment queueSend topic=%u deploymentID=%llu machinePrivate4=%u active=%d closing=%d pendingSend=%d bytesBefore=%u bytesAfter=%u connected=%d fd=%d fslot=%d\n",
                   unsigned(topic),
                   (unsigned long long)plan.config.deploymentID(),
                   unsigned(machine->private4),
                   int(active),
                   int(closing),
                   int(machine->neuron.pendingSend),
                   unsigned(bytesBefore),
                   unsigned(bytesAfter),
                   int(machine->neuron.connected),
                   machine->neuron.fd,
                   machine->neuron.fslot);
      std::fflush(stderr);
    }
#endif

    Ring::queueSend(&machine->neuron);
  }

  Vector<ScalerState> lastScalerStates;
  bytell_hash_map<String, uint32_t> upCountByName;
  bytell_hash_map<String, uint32_t> downCountByName;
  bytell_hash_map<String, int64_t> lastUpChangeMsByName;
  bytell_hash_map<String, int64_t> lastDownChangeMsByName;

  static bool autoscaleTraceEnabled(void)
  {
    static int cached = -1;
    if (cached == -1)
    {
      const char *value = std::getenv("PRODIGY_AUTOSCALE_TRACE");
      cached = (value && value[0] == '1' && value[1] == '\0') ? 1 : 0;
    }

    return (cached == 1);
  }

  template <typename... Args>
  static void autoscaleTrace(const char *format, Args... args)
  {
    if (autoscaleTraceEnabled())
    {
      basics_log(format, args...);
    }
  }

  void loadStress(void)
  {
    if (isDecommissioning())
    {
      co_return; // if we're decommissoning we obviously aren't going to spin up more instances due to load
    }

    uint64_t queryTimeMs = Time::now<TimeResolution::ms>();
    thisBrain->trimContainerMetrics(queryTimeMs);
    lastScalerStates.clear();
    autoscaleTrace("autoscale tick deploymentID=%llu hScalers=%u vScalers=%u queryMs=%llu\n",
                   (unsigned long long)plan.config.deploymentID(),
                   unsigned(plan.horizontalScalers.size()),
                   unsigned(plan.verticalScalers.size()),
                   (unsigned long long)queryTimeMs);

    struct PercentileWindow {
      bool hasSamples = false;
      bool samplesSorted = false;
      uint32_t nScalersForWindow = 0;
      Vector<float> baseSamples;
      bytell_hash_map<uint64_t, double> valuesByPercentileBits;
    };

    bytell_hash_map<uint64_t, bytell_hash_map<int64_t, PercentileWindow>> percentileByMetricWindow;
    bytell_hash_map<uint64_t, bytell_hash_map<int64_t, uint32_t>> scalerCountByMetricWindow;

    enum class IngressLatencyDimension : uint8_t {
      none = 0,
      queueWait = 1,
      handler = 2
    };

    struct IngressHistogramWindow {
      bool hasSamples = false;
      uint64_t fineTotal = 0;
      uint64_t fineBuckets[32] = {};
      bytell_hash_map<uint64_t, double> valuesByPercentileBits;
    };

    struct IngressMetricKeySet {
      uint64_t queueWaitComposite = 0;
      uint64_t handlerComposite = 0;

      uint64_t queueWaitFineBuckets[32] = {};
      uint64_t handlerFineBuckets[32] = {};

      IngressMetricKeySet()
      {
        queueWaitComposite = ProdigyMetrics::runtimeIngressQueueWaitCompositeKey();
        handlerComposite = ProdigyMetrics::runtimeIngressHandlerCompositeKey();

        for (uint32_t index = 0; index < 32; index++)
        {
          std::string indexText = std::to_string(index);

          String queueFineName;
          queueFineName.assign("runtime.ingress.queue_wait_us.fine.bucket."_ctv);
          queueFineName.append(indexText.data(), indexText.size());
          queueWaitFineBuckets[index] = ProdigyMetrics::metricKeyForName(queueFineName);

          String handlerFineName;
          handlerFineName.assign("runtime.ingress.handler_us.fine.bucket."_ctv);
          handlerFineName.append(indexText.data(), indexText.size());
          handlerFineBuckets[index] = ProdigyMetrics::metricKeyForName(handlerFineName);
        }
      }
    };

    static const IngressMetricKeySet ingressMetricKeys;
    bytell_hash_map<uint8_t, bytell_hash_map<int64_t, IngressHistogramWindow>> ingressHistogramByDimensionLookback;

    auto ingressDimensionForMetricKey = [&](uint64_t metricKey) -> IngressLatencyDimension {
      if (metricKey == ingressMetricKeys.queueWaitComposite)
      {
        return IngressLatencyDimension::queueWait;
      }

      if (metricKey == ingressMetricKeys.handlerComposite)
      {
        return IngressLatencyDimension::handler;
      }

      return IngressLatencyDimension::none;
    };

    auto countScalers = [&]<typename T>(const Vector<T>& scalers) -> void {
      for (const T& scaler : scalers)
      {
        const uint64_t metricKey = thisBrain->metricKeyFromName(scaler.name);
        const int64_t lookbackMs = int64_t(scaler.lookbackSeconds) * 1000;
        if (lookbackMs <= 0)
        {
          continue;
        }

        auto& byLookback = scalerCountByMetricWindow[metricKey];
        auto it = byLookback.find(lookbackMs);
        if (it == byLookback.end())
        {
          byLookback.insert_or_assign(lookbackMs, 1);
        }
        else
        {
          it->second += 1;
        }
      }
    };

    if (plan.horizontalScalers.size() > 0)
    {
      countScalers(plan.horizontalScalers);
    }
    else
    {
      countScalers(plan.verticalScalers);
    }

    auto percentileToBits = [](double percentile) -> uint64_t {
      uint64_t bits = 0;
      memcpy(&bits, &percentile, sizeof(bits));
      return bits;
    };

    auto interpolateSortedPercentile = [&](const Vector<float>& samples, double percentile) -> double {
      if (samples.size() == 1)
      {
        return samples[0];
      }

      const double position = percentile * double(samples.size() - 1);
      const uint32_t lowerIndex = uint32_t(position);
      const uint32_t upperIndex = (lowerIndex + 1 < samples.size()) ? (lowerIndex + 1) : lowerIndex;
      const double fraction = position - double(lowerIndex);

      const double lowerValue = samples[lowerIndex];
      const double upperValue = samples[upperIndex];
      return lowerValue + ((upperValue - lowerValue) * fraction);
    };

    Vector<float> histogramSamplesScratch;

    auto collectMetricSum = [&](uint64_t deploymentID, uint64_t metricKey, int64_t lookbackMs) -> uint64_t {
      histogramSamplesScratch.clear();
      thisBrain->metrics.collectValues(deploymentID, nullptr, metricKey, queryTimeMs, lookbackMs, true, histogramSamplesScratch);

      double sum = 0.0;
      for (const float sample : histogramSamplesScratch)
      {
        if (sample > 0)
        {
          sum += double(sample);
        }
      }

      return (sum > 0.0) ? uint64_t(sum + 0.5) : 0;
    };

    auto percentileFromFineHistogram = [](const uint64_t *buckets, uint64_t totalCount, double percentile) -> double {
      if (buckets == nullptr || totalCount == 0 || !(percentile > 0.0 && percentile <= 1.0))
      {
        return 0.0;
      }

      uint64_t targetRank = uint64_t(percentile * double(totalCount));
      if (targetRank == 0)
      {
        targetRank = 1;
      }
      else if (targetRank > totalCount)
      {
        targetRank = totalCount;
      }

      uint64_t seen = 0;
      for (uint32_t index = 0; index < 32; index++)
      {
        seen += buckets[index];
        if (seen >= targetRank)
        {
          if (index == 0)
          {
            return 0.0;
          }

          if (index >= 31)
          {
            return double(std::numeric_limits<uint64_t>::max());
          }

          return double((uint64_t(1) << index) - 1);
        }
      }

      return double(std::numeric_limits<uint64_t>::max());
    };

    // later we can add long term predictions if we want to, so that we can reserve excess reserved capacity ahead of time
    auto evaluateScaler = [&](const Scaler& scaler, double& value) -> bool {
      const uint64_t deploymentID = plan.config.deploymentID();
      const uint64_t metricKey = thisBrain->metricKeyFromName(scaler.name);
      const int64_t lookbackMs = int64_t(scaler.lookbackSeconds) * 1000;

      if (lookbackMs <= 0)
      {
        value = 0;
        return false;
      }

      if (!(scaler.percentile > 0.0 && scaler.percentile <= 100.0))
      {
        basics_log("loadStress unsupported scaler percentile=%lf deploymentID=%llu\n",
                   scaler.percentile,
                   (unsigned long long)deploymentID);
        value = 0;
        return false;
      }

      const IngressLatencyDimension ingressDimension = ingressDimensionForMetricKey(metricKey);
      if (ingressDimension != IngressLatencyDimension::none)
      {
        auto& byLookback = ingressHistogramByDimensionLookback[uint8_t(ingressDimension)];
        auto ingressIt = byLookback.find(lookbackMs);
        if (ingressIt == byLookback.end())
        {
          IngressHistogramWindow window;
          const uint64_t *fineKeys = (ingressDimension == IngressLatencyDimension::queueWait)
                                         ? ingressMetricKeys.queueWaitFineBuckets
                                         : ingressMetricKeys.handlerFineBuckets;

          for (uint32_t index = 0; index < 32; index++)
          {
            const uint64_t bucketCount = collectMetricSum(deploymentID, fineKeys[index], lookbackMs);
            window.fineBuckets[index] = bucketCount;
            window.fineTotal += bucketCount;
          }

          window.hasSamples = (window.fineTotal > 0);

          byLookback.insert_or_assign(lookbackMs, std::move(window));
          ingressIt = byLookback.find(lookbackMs);
        }

        IngressHistogramWindow& window = ingressIt->second;
        if (window.hasSamples == false)
        {
          autoscaleTrace("autoscale ingressCompositeNoSamples deploymentID=%llu metric=%llu lookbackMs=%lld\n",
                         (unsigned long long)deploymentID,
                         (unsigned long long)metricKey,
                         (long long)lookbackMs);
          value = 0;
          return false;
        }

        const uint64_t percentileBits = percentileToBits(scaler.percentile);
        if (auto pit = window.valuesByPercentileBits.find(percentileBits); pit != window.valuesByPercentileBits.end())
        {
          value = pit->second;
          return true;
        }

        const double percentile = scaler.percentile / 100.0;
        value = percentileFromFineHistogram(window.fineBuckets, window.fineTotal, percentile);
        window.valuesByPercentileBits.insert_or_assign(percentileBits, value);
        autoscaleTrace("autoscale ingressComposite deploymentID=%llu metricKey=%llu percentile=%.2f threshold=%.4f direction=%u value=%.6f\n",
                       (unsigned long long)deploymentID,
                       (unsigned long long)metricKey,
                       scaler.percentile,
                       scaler.threshold,
                       unsigned(scaler.direction),
                       value);
        return true;
      }

      auto& byLookback = percentileByMetricWindow[metricKey];
      auto it = byLookback.find(lookbackMs);
      if (it == byLookback.end())
      {
        PercentileWindow window;
        if (auto countByLookbackIt = scalerCountByMetricWindow.find(metricKey); countByLookbackIt != scalerCountByMetricWindow.end())
        {
          if (auto countIt = countByLookbackIt->second.find(lookbackMs); countIt != countByLookbackIt->second.end())
          {
            window.nScalersForWindow = countIt->second;
          }
        }
        if (window.nScalersForWindow == 0)
        {
          window.nScalersForWindow = 1;
        }

        Vector<float> samples;
        thisBrain->metrics.collectValues(deploymentID, nullptr, metricKey, queryTimeMs, lookbackMs, true, samples);
        if (samples.size() > 0)
        {
          window.hasSamples = true;
          window.baseSamples = std::move(samples);
        }

        byLookback.insert_or_assign(lookbackMs, std::move(window));
        it = byLookback.find(lookbackMs);
      }

      PercentileWindow& window = it->second;
      if (window.hasSamples == false)
      {
        autoscaleTrace("autoscale noSamples deploymentID=%llu metric=%llu lookbackMs=%lld\n",
                       (unsigned long long)deploymentID,
                       (unsigned long long)metricKey,
                       (long long)lookbackMs);
        value = 0;
        return false;
      }

      const uint64_t percentileBits = percentileToBits(scaler.percentile);
      if (auto pit = window.valuesByPercentileBits.find(percentileBits); pit != window.valuesByPercentileBits.end())
      {
        value = pit->second;
        return true;
      }

      const double percentile = scaler.percentile / 100.0;

      if (window.nScalersForWindow > 1)
      {
        if (window.samplesSorted == false)
        {
          std::sort(window.baseSamples.begin(), window.baseSamples.end());
          window.samplesSorted = true;
        }

        value = interpolateSortedPercentile(window.baseSamples, percentile);
      }
      else
      {
        Vector<float> samples = window.baseSamples;
        value = metricsPercentileSelect(samples, percentile);
      }

      window.valuesByPercentileBits.insert_or_assign(percentileBits, value);
      autoscaleTrace("autoscale value deploymentID=%llu metricKey=%llu percentile=%.2f threshold=%.4f direction=%u value=%.6f\n",
                     (unsigned long long)deploymentID,
                     (unsigned long long)metricKey,
                     scaler.percentile,
                     scaler.threshold,
                     unsigned(scaler.direction),
                     value);
      return true;
    };

    // reissue autoscaling evaluation timer
    autoscaleTimer.setTimeoutSeconds(configuredAutoscalePeriodSeconds());
    Ring::queueTimeout(&autoscaleTimer);

    auto reapResponses = [&]<typename Scaler, typename Consumer>(const Vector<Scaler>& scalers, Consumer&& consumer) -> void {
      for (uint32_t i = 0; i < scalers.size(); i++)
      {
        const Scaler& scaler = scalers[i];
        double value = 0;
        bool hasValue = evaluateScaler(static_cast<const Scaler&>(scaler), value);

        lastScalerStates.emplace_back(scaler.name, value, queryTimeMs);

        if (hasValue == false)
        {
          continue;
        }

        if (scaler.threshold <= 0)
        {
          continue;
        }

        if (scaler.direction == Scaler::Direction::upscale && value >= scaler.threshold)
        {
          consumer(scaler, true);
        }
        else if (scaler.direction == Scaler::Direction::downscale && value <= scaler.threshold)
        {
          // Safety invariant: stateful deployments are never allowed to autoscale down.
          if (plan.isStateful)
          {
            continue;
          }

          consumer(scaler, false);
        }
      }
    };

    if (plan.horizontalScalers.size() > 0)
    {
      bool baseUp = false;
      bool baseDown = false;

      bool surgeUp = false;
      bool surgeDown = false;

      uint32_t baseMin = 0;
      uint32_t baseMax = 0;
      uint32_t surgeMin = 0;
      uint32_t surgeMax = 0;

      auto mergeBounds = [](const HorizontalScaler& scaler, uint32_t& minBound, uint32_t& maxBound) -> void {
        if (scaler.minValue > minBound)
        {
          minBound = scaler.minValue;
        }

        if (scaler.maxValue > 0)
        {
          if (maxBound == 0 || scaler.maxValue < maxBound)
          {
            maxBound = scaler.maxValue;
          }
        }
      };

      for (const HorizontalScaler& scaler : plan.horizontalScalers)
      {
        switch (scaler.lifetime)
        {
          case ApplicationLifetime::base:
            {
              mergeBounds(scaler, baseMin, baseMax);
              break;
            }
          case ApplicationLifetime::surge:
            {
              mergeBounds(scaler, surgeMin, surgeMax);
              break;
            }
          default:
            break;
        }
      }

      reapResponses(plan.horizontalScalers, [&](const HorizontalScaler& scaler, bool scaleUp) -> void {
        if (scaleUp)
        {
          switch (scaler.lifetime)
          {
            case ApplicationLifetime::base:
              {
                baseUp = true;
                break;
              }
            case ApplicationLifetime::surge:
              {
                surgeUp = true;
                break;
              }
            default:
              break;
          }
        }
        else // scaleDown
        {
          switch (scaler.lifetime)
          {
            case ApplicationLifetime::base:
              {
                baseDown = true;
                break;
              }
            case ApplicationLifetime::surge:
              {
                surgeDown = true;
                break;
              }
            default:
              break;
          }
        }
      });

      if (plan.isStateful)
      {
        baseDown = false;
        surgeDown = false;
      }

      if (baseUp || baseDown || surgeUp || surgeDown)
      {
        uint32_t beforeBase = nTargetBase;
        uint32_t beforeSurge = nTargetSurge;
        // these are checked often enough that we only need to spin up or down 1 unit at a time
        // (1 unit = 1 instance for stateless, 1 shard-group worth of replicas for stateful).
        const uint32_t baseStep = (plan.isStateful ? 3u : 1u);

        if (baseUp)
        {
          if (plan.isStateful && statefulWorkerTopologyUpgradePendingForAnyShardGroup())
          {
            requestDeferredStatefulShardGrowth(1);
          }
          else
          {
            nTargetBase += baseStep;
          }

          // reserve up implies surge down, if the application uses surge, since a surge instance would've been spun up earlier
          if (nTargetSurge > 0)
          {
            nTargetSurge -= 1;
          }
        }
        else if (baseDown)
        {
          if (nTargetBase > baseStep)
          {
            nTargetBase -= baseStep;
          }
          else
          {
            nTargetBase = 0;
          }
        }

        if (surgeUp) // you could get base up and surge up, if load keeps trending higher
        {
          nTargetSurge += 1;
        }
        else if (surgeDown)
        {
          if (nTargetSurge > 0)
          {
            nTargetSurge -= 1;
          }
          else if (!baseUp && !baseDown && !surgeUp)
          {
            co_return;
          }
        }

        auto clampTarget = [](uint32_t value, uint32_t minBound, uint32_t maxBound) -> uint32_t {
          if (value < minBound)
          {
            value = minBound;
          }
          if (maxBound > 0 && value > maxBound)
          {
            value = maxBound;
          }
          return value;
        };

        nTargetBase = clampTarget(nTargetBase, baseMin, baseMax);
        nTargetSurge = clampTarget(nTargetSurge, surgeMin, surgeMax);

        const bool baseChanged = (nTargetBase != beforeBase);
        const bool surgeChanged = (nTargetSurge != beforeSurge);
        const bool effectiveTargetChanged = (baseChanged || surgeChanged);

        if (effectiveTargetChanged)
        {
          if (plan.isStateful)
          {
            if (nTargetBase > beforeBase)
            {
              if (statefulWorkerTopologyUpgradePendingForAnyShardGroup())
              {
                autoscaleTrace("autoscale shardGrowthBlockedByTopologyUpgrade deploymentID=%llu shardGroups=%u lockedGroups=%u targetWorkers=%u\n",
                               (unsigned long long)plan.config.deploymentID(),
                               unsigned(nShardGroups),
                               unsigned(statefulWorkerTopologyLockedShardGroups.size()),
                               unsigned(statefulWorkerTopologyUpgradeTargetWorkerCount));
              }
              else
              {
                // flip this flag here that we're deploying a new shard group so that we wait for all those containers to be healthy
                deployingNewShardGroup = true;

                Vector<uint32_t> shardGroups;
                // Each shard group has three replicas; enqueue all three immediately.
                shardGroups.insert(shardGroups.end(), 3, nShardGroups);

                nShardGroups += 1;
                recomputeStatefulBaseTargetFromShardGroups();

                spinStateful(nullptr, shardGroups);
              }
            }
          }
          else
          {
            spinStateless(nullptr); // we don't need to wait on this
          }
        }

        autoscaleTrace("autoscale adjust deploymentID=%llu base=%u->%u surge=%u->%u baseUp=%d baseDown=%d surgeUp=%d surgeDown=%d\n",
                       (unsigned long long)plan.config.deploymentID(),
                       unsigned(beforeBase),
                       unsigned(nTargetBase),
                       unsigned(beforeSurge),
                       unsigned(nTargetSurge),
                       int(baseUp),
                       int(baseDown),
                       int(surgeUp),
                       int(surgeDown));
      }
      else if (isDecommissioning())
      {
        rollForward(); // there's a new deployment version waiting to be deployed
      }
    }
    else
    {
      int32_t cpuDiff = 0;
      int32_t memoryDiff = 0;
      int32_t storageDiff = 0;
      uint32_t cpuMin = 0;
      uint32_t cpuMax = 0;
      uint32_t memoryMin = 0;
      uint32_t memoryMax = 0;
      uint32_t storageMin = 0;
      uint32_t storageMax = 0;

      auto mergeResourceBounds = [](const VerticalScaler& scaler, uint32_t& minBound, uint32_t& maxBound) -> void {
        if (scaler.minValue > minBound)
        {
          minBound = scaler.minValue;
        }

        if (scaler.maxValue > 0)
        {
          if (maxBound == 0 || scaler.maxValue < maxBound)
          {
            maxBound = scaler.maxValue;
          }
        }
      };

      for (const VerticalScaler& scaler : plan.verticalScalers)
      {
        switch (scaler.resource)
        {
          case ScalingDimension::cpu:
            {
              mergeResourceBounds(scaler, cpuMin, cpuMax);
              break;
            }
          case ScalingDimension::memory:
            {
              mergeResourceBounds(scaler, memoryMin, memoryMax);
              break;
            }
          case ScalingDimension::storage:
            {
              mergeResourceBounds(scaler, storageMin, storageMax);
              break;
            }
          case ScalingDimension::runtimeIngressQueueWaitComposite:
          case ScalingDimension::runtimeIngressHandlerComposite:
            {
              break;
            }
        }
      }

      reapResponses(plan.verticalScalers, [&](const VerticalScaler& scaler, bool scaleUp) -> void {
        switch (scaler.resource)
        {
          case ScalingDimension::cpu:
            {
              if (scaleUp)
              {
                cpuDiff += scaler.increment;
              }
              else
              {
                cpuDiff -= scaler.increment;
              }

              break;
            }
          case ScalingDimension::memory:
            {
              if (scaleUp)
              {
                memoryDiff += scaler.increment;
              }
              else
              {
                memoryDiff -= scaler.increment;
              }

              break;
            }
          case ScalingDimension::storage:
            {
              if (scaleUp)
              {
                storageDiff += scaler.increment;
              }
              else
              {
                storageDiff -= scaler.increment;
              }

              break;
            }
          case ScalingDimension::runtimeIngressQueueWaitComposite:
          case ScalingDimension::runtimeIngressHandlerComposite:
            {
              break;
            }
        }
      });

      if (plan.isStateful)
      {
        if (cpuDiff < 0)
        {
          cpuDiff = 0;
        }
        if (memoryDiff < 0)
        {
          memoryDiff = 0;
        }
        if (storageDiff < 0)
        {
          storageDiff = 0;
        }
      }

      if (applicationUsesSharedCPUs(plan.config))
      {
        // Shared CPU mode keeps containers in the shared scheduler pool and
        // currently treats CPU as a placement budget, not an in-place
        // dedicated-core resizable resource.
        cpuDiff = 0;
      }

      if (verticalResourceBaseInitialized == false)
      {
        verticalResourceBase_nLogicalCores = plan.config.nLogicalCores;
        verticalResourceBase_memoryMB = plan.config.memoryMB;
        verticalResourceBase_storageMB = plan.config.storageMB;
        verticalResourceBaseInitialized = true;
      }

      auto addSignedDelta = [](int32_t current, int32_t delta) -> int32_t {
        int64_t expanded = int64_t(current) + int64_t(delta);

        if (expanded > int64_t(std::numeric_limits<int32_t>::max()))
        {
          expanded = int64_t(std::numeric_limits<int32_t>::max());
        }
        else if (expanded < int64_t(std::numeric_limits<int32_t>::min()))
        {
          expanded = int64_t(std::numeric_limits<int32_t>::min());
        }

        return int32_t(expanded);
      };

      auto applySignedAdjustment = [](uint32_t base, int32_t adjustment) -> uint32_t {
        if (adjustment >= 0)
        {
          uint64_t expanded = uint64_t(base) + uint64_t(adjustment);
          if (expanded > UINT32_MAX)
          {
            expanded = UINT32_MAX;
          }
          return uint32_t(expanded);
        }

        uint32_t magnitude = uint32_t(-adjustment);
        return (magnitude >= base) ? 0 : (base - magnitude);
      };

      auto clampTarget = [](uint32_t value, uint32_t minBound, uint32_t maxBound) -> uint32_t {
        if (value < minBound)
        {
          value = minBound;
        }
        if (maxBound > 0 && value > maxBound)
        {
          value = maxBound;
        }
        return value;
      };

      auto adjustmentFromTarget = [](uint32_t base, uint32_t target) -> int32_t {
        int64_t delta = int64_t(target) - int64_t(base);
        if (delta > int64_t(std::numeric_limits<int32_t>::max()))
        {
          delta = int64_t(std::numeric_limits<int32_t>::max());
        }
        else if (delta < int64_t(std::numeric_limits<int32_t>::min()))
        {
          delta = int64_t(std::numeric_limits<int32_t>::min());
        }

        return int32_t(delta);
      };

      int32_t nextAdjustment_nLogicalCores = addSignedDelta(verticalAdjustment_nLogicalCores, cpuDiff);
      int32_t nextAdjustment_memoryMB = addSignedDelta(verticalAdjustment_memoryMB, memoryDiff);
      int32_t nextAdjustment_storageMB = addSignedDelta(verticalAdjustment_storageMB, storageDiff);

      uint32_t cpuFloor = cpuMin;
      if (cpuFloor < verticalResourceBase_nLogicalCores)
      {
        cpuFloor = verticalResourceBase_nLogicalCores;
      }

      uint32_t memoryFloor = memoryMin;
      if (memoryFloor < verticalResourceBase_memoryMB)
      {
        memoryFloor = verticalResourceBase_memoryMB;
      }

      uint32_t storageFloor = storageMin;
      if (storageFloor < verticalResourceBase_storageMB)
      {
        storageFloor = verticalResourceBase_storageMB;
      }

      const uint32_t nextCores = clampTarget(applySignedAdjustment(verticalResourceBase_nLogicalCores, nextAdjustment_nLogicalCores), cpuFloor, cpuMax);
      const uint32_t nextMemoryMB = clampTarget(applySignedAdjustment(verticalResourceBase_memoryMB, nextAdjustment_memoryMB), memoryFloor, memoryMax);
      const uint32_t nextStorageMB = clampTarget(applySignedAdjustment(verticalResourceBase_storageMB, nextAdjustment_storageMB), storageFloor, storageMax);

      nextAdjustment_nLogicalCores = adjustmentFromTarget(verticalResourceBase_nLogicalCores, nextCores);
      nextAdjustment_memoryMB = adjustmentFromTarget(verticalResourceBase_memoryMB, nextMemoryMB);
      nextAdjustment_storageMB = adjustmentFromTarget(verticalResourceBase_storageMB, nextStorageMB);

      if (nextCores != plan.config.nLogicalCores || nextMemoryMB != plan.config.memoryMB || nextStorageMB != plan.config.storageMB)
      {
        uint32_t oldCores = plan.config.nLogicalCores;
        uint32_t oldMemoryMB = plan.config.memoryMB;
        uint32_t oldStorageMB = plan.config.storageMB;
        uint32_t oldTotalMemoryMB = plan.config.totalMemoryMB();
        uint32_t oldTotalStorageMB = plan.config.totalStorageMB();

        auto nextConfig = plan.config;
        nextConfig.nLogicalCores = nextCores;
        nextConfig.memoryMB = nextMemoryMB;
        nextConfig.storageMB = nextStorageMB;

        uint32_t nextTotalMemoryMB = nextConfig.totalMemoryMB();
        uint32_t nextTotalStorageMB = nextConfig.totalStorageMB();

        int32_t deltaCores = int32_t(nextCores) - int32_t(oldCores);
        int32_t deltaMemoryMB = int32_t(nextTotalMemoryMB) - int32_t(oldTotalMemoryMB);
        int32_t deltaStorageMB = int32_t(nextTotalStorageMB) - int32_t(oldTotalStorageMB);
        uint32_t oldWorkerCount = prodigyStatefulWorkerCountForLogicalCores(oldCores);
        uint32_t nextWorkerCount = prodigyStatefulWorkerCountForLogicalCores(nextCores);

        if (prodigyStatefulCoreChangeRequiresTopologyUpgrade(plan.isStateful, oldCores, nextCores))
        {
          if (deployingNewShardGroup)
          {
            requestDeferredStatefulTopologyTarget(uint16_t(nextCores), nextMemoryMB, nextStorageMB);
            autoscaleTrace("autoscale topologyUpgradeBlockedByShardGrowth deploymentID=%llu cores=%u->%u workers=%u->%u shardGroups=%u\n",
                           (unsigned long long)plan.config.deploymentID(),
                           unsigned(oldCores),
                           unsigned(nextCores),
                           unsigned(oldWorkerCount),
                           unsigned(nextWorkerCount),
                           unsigned(nShardGroups));
          }
          else
          {
            if (statefulWorkerTopologyUpgradePendingForAnyShardGroup() == false)
            {
              armStatefulWorkerTopologyUpgrade(oldWorkerCount, nextWorkerCount, uint16_t(nextCores), nextMemoryMB, nextStorageMB);
            }
            else
            {
              requestDeferredStatefulTopologyTarget(uint16_t(nextCores), nextMemoryMB, nextStorageMB);
            }

            autoscaleTrace("autoscale topologyUpgradeRequired deploymentID=%llu cores=%u->%u workers=%u->%u lockedGroups=%u pending=%u\n",
                           (unsigned long long)plan.config.deploymentID(),
                           unsigned(oldCores),
                           unsigned(nextCores),
                           unsigned(oldWorkerCount),
                           unsigned(nextWorkerCount),
                           unsigned(statefulWorkerTopologyLockedShardGroups.size()),
                           unsigned(statefulWorkerTopologyUpgradePending));
          }
        }
        else
        {

          bytell_hash_map<Machine *, uint32_t> containersPerMachine;
          for (ContainerView *container : containers)
          {
            if (container == nullptr || container->machine == nullptr)
            {
              continue;
            }
            if (container->state == ContainerState::destroyed)
            {
              continue;
            }

            containersPerMachine[container->machine] += 1;
          }

          bool hasHeadroom = true;
          for (const auto& [machine, count] : containersPerMachine)
          {
            if (machine == nullptr || count == 0)
            {
              continue;
            }

            int64_t requiredCores = (deltaCores > 0) ? (int64_t(deltaCores) * int64_t(count)) : 0;
            int64_t requiredMemoryMB = (deltaMemoryMB > 0) ? (int64_t(deltaMemoryMB) * int64_t(count)) : 0;
            int64_t requiredStorageMB = (deltaStorageMB > 0) ? (int64_t(deltaStorageMB) * int64_t(count)) : 0;

            if (requiredCores > machine->nLogicalCores_available || requiredMemoryMB > machine->memoryMB_available || requiredStorageMB > machine->storageMB_available)
            {
              hasHeadroom = false;
              break;
            }
          }

          if (hasHeadroom)
          {
            for (const auto& [machine, count] : containersPerMachine)
            {
              if (machine == nullptr || count == 0)
              {
                continue;
              }

              machine->nLogicalCores_available -= int32_t(int64_t(deltaCores) * int64_t(count));
              machine->memoryMB_available -= int32_t(int64_t(deltaMemoryMB) * int64_t(count));
              machine->storageMB_available -= int32_t(int64_t(deltaStorageMB) * int64_t(count));
            }

            plan.config = nextConfig;
            verticalAdjustment_nLogicalCores = nextAdjustment_nLogicalCores;
            verticalAdjustment_memoryMB = nextAdjustment_memoryMB;
            verticalAdjustment_storageMB = nextAdjustment_storageMB;

            bool isDownscale = (nextCores < oldCores || nextMemoryMB < oldMemoryMB || nextStorageMB < oldStorageMB);
            uint32_t graceSeconds = plan.config.sTilKillable;

            for (ContainerView *container : containers)
            {
              if (container == nullptr || container->machine == nullptr)
              {
                continue;
              }
              if (container->state == ContainerState::destroyed)
              {
                continue;
              }

              container->runtime_nLogicalCores = uint16_t(nextCores);
              container->runtime_memoryMB = nextTotalMemoryMB;
              container->runtime_storageMB = nextTotalStorageMB;

              queueSend(container->machine,
                        NeuronTopic::adjustContainerResources,
                        container->uuid,
                        uint16_t(nextCores),
                        uint32_t(nextMemoryMB),
                        uint32_t(nextStorageMB),
                        isDownscale,
                        graceSeconds);
            }

            autoscaleTrace("autoscale verticalInPlace deploymentID=%llu cores=%u->%u memMB=%u->%u storMB=%u->%u containers=%u\n",
                           (unsigned long long)plan.config.deploymentID(),
                           unsigned(oldCores),
                           unsigned(nextCores),
                           unsigned(oldMemoryMB),
                           unsigned(nextMemoryMB),
                           unsigned(oldStorageMB),
                           unsigned(nextStorageMB),
                           unsigned(containers.size()));
          }
          else
          {
            autoscaleTrace("autoscale verticalInPlace denied deploymentID=%llu cores=%u->%u memMB=%u->%u storMB=%u->%u\n",
                           (unsigned long long)plan.config.deploymentID(),
                           unsigned(oldCores),
                           unsigned(nextCores),
                           unsigned(oldMemoryMB),
                           unsigned(nextMemoryMB),
                           unsigned(oldStorageMB),
                           unsigned(nextStorageMB));
          }
        }
      }
      else if (isDecommissioning())
      {
        rollForward(); // there's a new deployment version waiting to be deployed
      }
    }
  }

public:

  bool statelessCompactionDonorIsQuiescent(void) const
  {
    if (state != DeploymentState::running)
    {
      return false;
    }
    if (isDecommissioning())
    {
      return false;
    }
    if (waitingOnCompactions)
    {
      return false;
    }
    if (waitingOnContainers.size() > 0)
    {
      return false;
    }
    if (toSchedule.size() > 0)
    {
      return false;
    }
    if (schedulingStack.execution != nullptr)
    {
      return false;
    }

    return true;
  }

  static bool statelessCompactionContainerIsEligible(ContainerView *container)
  {
    if (container == nullptr)
    {
      return false;
    }
    if (container->state != ContainerState::healthy)
    {
      return false;
    }

    switch (container->lifetime)
    {
      case ApplicationLifetime::base:
      case ApplicationLifetime::surge:
        {
          return true;
        }
      case ApplicationLifetime::canary:
      default:
        {
          return false;
        }
    }
  }

  uint32_t nTarget(void)
  {
    return nTargetBase + nTargetSurge + nTargetCanary;
  }

  uint32_t nTargetBase = 0;
  uint32_t nTargetSurge = 0;
  uint32_t nTargetCanary = 0;

  uint32_t nDeployed(void)
  {
    return nDeployedBase + nDeployedSurge + nDeployedCanary;
  }

  uint32_t nDeployedCanary = 0;
  uint32_t nDeployedBase = 0;
  uint32_t nDeployedSurge = 0;

  uint32_t nHealthyCanary = 0;
  uint32_t nHealthyBase = 0;
  uint32_t nHealthySurge = 0;

  uint32_t nHealthy(void)
  {
    return nHealthyCanary + nHealthyBase + nHealthySurge;
  }

  uint32_t nSuspended = 0;

  bool recoveredStatelessContainerHostIsLive(ContainerView *container) const
  {
    if (container == nullptr || container->machine == nullptr)
    {
      return false;
    }

    return prodigyMachineReadyForScheduling(container->machine);
  }

  void discardRecoveredStatelessContainersOnUnavailableHosts(const char *reason)
  {
    if (plan.isStateful)
    {
      return;
    }

    Vector<ContainerView *> staleContainers;
    for (ContainerView *container : containers)
    {
      if (container == nullptr || container->machine == nullptr || container->state == ContainerState::none || container->state == ContainerState::destroyed)
      {
        continue;
      }

      if (recoveredStatelessContainerHostIsLive(container))
      {
        continue;
      }

      staleContainers.push_back(container);
    }

    for (ContainerView *container : staleContainers)
    {
      if (container == nullptr || containers.contains(container) == false)
      {
        continue;
      }

      basics_log("deployment discard unavailable stateless container deploymentID=%llu appID=%u uuid=%llu machinePrivate4=%u state=%u reason=%s\n",
                 (unsigned long long)plan.config.deploymentID(),
                 unsigned(plan.config.applicationID),
                 (unsigned long long)container->uuid,
                 unsigned(container->machine ? container->machine->private4 : 0u),
                 unsigned(container->state),
                 (reason ? reason : "unspecified"));
      destructContainer(container);
      containerDestroyed(container);
    }
  }

  // Compatibility hook for reboot recovery flows invoked by Brain timeout paths.
  // Reconcile pending work and close target deficits after master/brain recovery.
  void recoverAfterReboot(void)
  {
#if PRODIGY_DEBUG
    std::fprintf(stderr,
                 "deployment recoverAfterReboot begin deploymentID=%llu appID=%u state=%u waiting=%llu toSchedule=%llu nDeployed=%u nTarget=%u nHealthy=%u suspended=%u\n",
                 (unsigned long long)plan.config.deploymentID(),
                 unsigned(plan.config.applicationID),
                 unsigned(state),
                 (unsigned long long)waitingOnContainers.size(),
                 (unsigned long long)toSchedule.size(),
                 unsigned(nDeployed()),
                 unsigned(nTarget()),
                 unsigned(nHealthy()),
                 unsigned(nSuspended));
    std::fflush(stderr);
#endif

    if (state == DeploymentState::failed || state == DeploymentState::decommissioning)
    {
      return;
    }
    if (plan.config.type == ApplicationType::task)
    {
      return;
    }

    bool activeLocalTransition = (state == DeploymentState::deploying || state == DeploymentState::canaries || waitingOnCompactions || waitingOnContainers.size() > 0 || schedulingStack.execution != nullptr || canaryStack != nullptr);
    if (nSuspended > 0)
    {
      if (activeLocalTransition)
      {
        return;
      }

#if PRODIGY_DEBUG
      std::fprintf(stderr,
                   "deployment recoverAfterReboot clear-stale-suspension deploymentID=%llu appID=%u suspended=%u\n",
                   (unsigned long long)plan.config.deploymentID(),
                   unsigned(plan.config.applicationID),
                   unsigned(nSuspended));
      std::fflush(stderr);
#endif
      nSuspended = 0;
    }

    if (toSchedule.size() > 0)
    {
#if PRODIGY_DEBUG
      std::fprintf(stderr,
                   "deployment recoverAfterReboot reschedule-pending deploymentID=%llu appID=%u toSchedule=%llu waiting=%llu\n",
                   (unsigned long long)plan.config.deploymentID(),
                   unsigned(plan.config.applicationID),
                   (unsigned long long)toSchedule.size(),
                   (unsigned long long)waitingOnContainers.size());
      std::fflush(stderr);
#endif
      schedule(nullptr);
      return;
    }

    // Rebuild deployed/healthy counters from recovered runtime state so
    // takeover replay can close deficits even after stale planning counters.
    uint32_t actualDeployedCanary = 0;
    uint32_t actualDeployedBase = 0;
    uint32_t actualDeployedSurge = 0;
    uint32_t actualHealthyCanary = 0;
    uint32_t actualHealthyBase = 0;
    uint32_t actualHealthySurge = 0;

    discardRecoveredStatelessContainersOnUnavailableHosts("recoverAfterReboot");

    for (ContainerView *container : containers)
    {
      bool countsAsDeployed = (container->state != ContainerState::none && container->state != ContainerState::destroyed);
      bool countsAsHealthy = (container->state == ContainerState::healthy);
      if (plan.isStateful == false && recoveredStatelessContainerHostIsLive(container) == false)
      {
        countsAsDeployed = false;
        countsAsHealthy = false;
      }

      switch (container->lifetime)
      {
        case ApplicationLifetime::canary:
          {
            if (countsAsDeployed)
            {
              actualDeployedCanary += 1;
            }
            if (countsAsHealthy)
            {
              actualHealthyCanary += 1;
            }
            break;
          }
        case ApplicationLifetime::base:
          {
            if (countsAsDeployed)
            {
              actualDeployedBase += 1;
            }
            if (countsAsHealthy)
            {
              actualHealthyBase += 1;
            }
            break;
          }
        case ApplicationLifetime::surge:
          {
            if (countsAsDeployed)
            {
              actualDeployedSurge += 1;
            }
            if (countsAsHealthy)
            {
              actualHealthySurge += 1;
            }
            break;
          }
      }
    }

    nDeployedCanary = actualDeployedCanary;
    nDeployedBase = actualDeployedBase;
    nDeployedSurge = actualDeployedSurge;
    nHealthyCanary = actualHealthyCanary;
    nHealthyBase = actualHealthyBase;
    nHealthySurge = actualHealthySurge;

    if (nTarget() == 0)
    {
      calculateTargets();
    }

    reconcileStatefulWorkerTopologyUpgradeContainers();

    for (ContainerView *container : containers)
    {
      if (plan.isStateful == false && recoveredStatelessContainerHostIsLive(container) == false)
      {
        continue;
      }

      if (container->state == ContainerState::scheduled || container->state == ContainerState::healthy)
      {
        container->replayActivePairingsToSelf();
        container->replayActivePairingsToPeers();
      }
    }

    // Recover underprovisioned deployments after master takeover when machine
    // registrations arrive after initial evaluateAfterNewMaster() planning.
    if (nDeployed() < nTarget())
    {
#if PRODIGY_DEBUG
      std::fprintf(stderr,
                   "deployment recoverAfterReboot underprovisioned deploymentID=%llu appID=%u nDeployed=%u nTarget=%u waiting=%llu hasHealthyMachines=%d\n",
                   (unsigned long long)plan.config.deploymentID(),
                   unsigned(plan.config.applicationID),
                   unsigned(nDeployed()),
                   unsigned(nTarget()),
                   (unsigned long long)waitingOnContainers.size(),
                   int(thisBrain->hasHealthyMachines()));
      std::fflush(stderr);
#endif
      // On master handoff, followers may still be reconnecting neuron control sockets.
      // Do not request additional machines until at least one machine is healthy.
      if (thisBrain->hasHealthyMachines() == false)
      {
        return;
      }

      architect(nullptr, false, false, false);

      if (toSchedule.size() > 0)
      {
        state = DeploymentState::deploying;
        stateChangedAtMs = Time::now<TimeResolution::ms>();
#if PRODIGY_DEBUG
        std::fprintf(stderr,
                     "deployment recoverAfterReboot reschedule-underprovisioned deploymentID=%llu appID=%u toSchedule=%llu waiting=%llu\n",
                     (unsigned long long)plan.config.deploymentID(),
                     unsigned(plan.config.applicationID),
                     (unsigned long long)toSchedule.size(),
                     (unsigned long long)waitingOnContainers.size());
        std::fflush(stderr);
#endif
        schedule(nullptr);
      }
    }
  }

  uint32_t brainEchos = 0; // we wait until both brains echo that they have the deployment blob when one is required
  bytell_hash_set<uint128_t> brainBlobQueuedPeerKeys = {};
  bytell_hash_set<uint128_t> brainBlobEchoPeerKeys = {};

  void cancelDeploymentWork(DeploymentWork *meta)
  {
    WorkBase *work = meta->getBase();

    if (work->lifecycle == LifecycleOp::updateInPlace)
    {
      // Clear both new and old containers' plannedWork to avoid dangling pointers
      if (work->container)
      {
        work->container->plannedWork = nullptr; // because the destruction container cleans this up
      }
      if (work->oldContainer)
      {
        work->oldContainer->plannedWork = nullptr;
      }
    }

    // sever any links
    if (DeploymentWork *linkedMeta = work->prev ?: work->next; linkedMeta)
    {
      WorkBase *linkedWork = linkedMeta->getBase();

      linkedWork->prev = nullptr;
      linkedWork->next = nullptr;
    }

    // If canceling the work that is currently being executed by schedule(),
    // do not mutate the queue or relinquish here. Let the scheduler own its lifecycle.
    if (meta != currentlyExecutingWork)
    {
      toSchedule.erase(meta);
      workPool.relinquish(meta);
    }
  }

  DeploymentWork *planStatelessConstruction(Machine *machine, ApplicationLifetime lifetime, Vector<uint32_t> assignedGPUMemoryMBs = {}, Vector<AssignedGPUDevice> assignedGPUDevices = {})
  {
    ContainerView *container = constructOnMachine(machine, lifetime, std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices));

    DeploymentWork *work = workPool.get();
    work->emplace<StatelessWork>(LifecycleOp::construct, machine, container);

    container->plannedWork = work;

    return work;
  }

  DeploymentWork *planStatefulConstruction(Machine *machine, ContainerView *container, DataStrategy dataStrategy)
  {
    if (statefulWorkerTopologyUpgradeLocksShardGroup(container->shardGroup) && container->explicitStatefulTopology.configured() == false)
    {
      configureStatefulWorkerTopologyUpgradeTarget(container);
    }

    DeploymentWork *work = workPool.get();
    work->emplace<StatefulWork>(LifecycleOp::construct, machine, container, dataStrategy);

    container->plannedWork = work;

    return work;
  }

  void configureStatefulPlacement(ContainerView *container, uint32_t topologyEpoch)
  {
    if (container == nullptr || statefulWorkerTopologyUpgradeLocksShardGroup(container->shardGroup) == false)
    {
      return;
    }

    if (topologyEpoch != 0)
    {
      if (topologyEpoch == statefulWorkerTopologyUpgradeTargetEpoch)
      {
        configureStatefulWorkerTopologyUpgradeTarget(container);
        return;
      }

      if (topologyEpoch == statefulWorkerTopologyUpgradeSourceEpoch)
      {
        configureStatefulWorkerTopologyUpgradeSource(container);
        return;
      }
    }

    configureStatefulWorkerTopologyUpgradeTarget(container);
  }

  DeploymentWork *planStatefulConstruction(Machine *machine, uint32_t shardGroup, DataStrategy dataStrategy, Vector<uint32_t> assignedGPUMemoryMBs = {}, Vector<AssignedGPUDevice> assignedGPUDevices = {})
  {
    ContainerView *container = constructOnMachine(machine, ApplicationLifetime::base, std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices));
    container->shardGroup = shardGroup;

    containersByShardGroup.insert(container->shardGroup, container);

    return planStatefulConstruction(machine, container, dataStrategy);
  }

  DeploymentWork *planStatefulConstruction(Machine *machine, uint32_t shardGroup, uint32_t topologyEpoch, DataStrategy dataStrategy, Vector<uint32_t> assignedGPUMemoryMBs = {}, Vector<AssignedGPUDevice> assignedGPUDevices = {})
  {
    ContainerView *container = constructOnMachine(machine, ApplicationLifetime::base, std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices));
    container->shardGroup = shardGroup;
    configureStatefulPlacement(container, topologyEpoch);

    containersByShardGroup.insert(container->shardGroup, container);

    return planStatefulConstruction(machine, container, dataStrategy);
  }

  DeploymentWork *planStatefulUpdateInPlace(ContainerView *oldContainer, Vector<uint32_t> assignedGPUMemoryMBs = {}, Vector<AssignedGPUDevice> assignedGPUDevices = {})
  {
    ContainerView *container = constructOnMachine(oldContainer->machine, ApplicationLifetime::base, std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices));
    container->shardGroup = oldContainer->shardGroup;

    DeploymentWork *work = workPool.get();
    work->emplace<StatefulWork>(LifecycleOp::updateInPlace, container, oldContainer);

    container->plannedWork = work;

    oldContainer->state = ContainerState::aboutToDestroy;
    oldContainer->plannedWork = work;

    return work;
  }

  DeploymentWork *planStatelessDestruction(ContainerView *container, const char *reason = "unspecified")
  {
    basics_log("planStatelessDestruction deploymentID=%llu appID=%u uuid=%llu stateBefore=%u machinePrivate4=%u lifetime=%u reason=%s\n",
               (unsigned long long)plan.config.deploymentID(),
               unsigned(plan.config.applicationID),
               (unsigned long long)(container ? container->uuid : 0),
               unsigned(container ? container->state : ContainerState::none),
               unsigned((container && container->machine) ? container->machine->private4 : 0u),
               unsigned(container ? container->lifetime : ApplicationLifetime::base),
               (reason ? reason : "null"));

    container->state = ContainerState::aboutToDestroy;

    DeploymentWork *work = workPool.get();
    work->emplace<StatelessWork>(LifecycleOp::destruct, container);

    container->plannedWork = work;

    return work;
  }

  DeploymentWork *planStatefulDestruction(ContainerView *container)
  {
    container->state = ContainerState::aboutToDestroy;

    DeploymentWork *work = workPool.get();
    work->emplace<StatefulWork>(LifecycleOp::destruct, container);

    container->plannedWork = work;

    return work;
  }

  void scheduleStatelessConstruction(Machine *machine, ApplicationLifetime lifetime)
  {
    toSchedule.push_back(planStatelessConstruction(machine, lifetime));
  }

  void scheduleStatefulConstruction(Machine *machine, uint32_t shardGroup, DataStrategy dataStrategy)
  {
    toSchedule.push_back(planStatefulConstruction(machine, shardGroup, dataStrategy));
  }

  void scheduleStatefulUpdateInPlace(ContainerView *oldContainer, Vector<uint32_t> assignedGPUMemoryMBs = {}, Vector<AssignedGPUDevice> assignedGPUDevices = {})
  {
    toSchedule.push_back(planStatefulUpdateInPlace(oldContainer, std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices)));
  }

  void scheduleStatelessDestruction(ContainerView *container)
  {
    toSchedule.push_back(planStatelessDestruction(container, "scheduleStatelessDestruction"));
  }

  void scheduleStatefulDestruction(ContainerView *container)
  {
    toSchedule.push_back(planStatefulDestruction(container));
  }

  void scheduleRemainingPreviousStatelessDestruction(const char *reason)
  {
    if (plan.isStateful || previous == nullptr || previous->containers.size() == 0)
    {
      return;
    }

    Vector<ContainerView *> oldContainers;
    for (ContainerView *container : previous->containers)
    {
      oldContainers.push_back(container);
    }

    for (ContainerView *container : oldContainers)
    {
      if (container == nullptr || previous->containers.contains(container) == false)
      {
        continue;
      }

      if (container->plannedWork != nullptr || container->state == ContainerState::aboutToDestroy || container->state == ContainerState::destroying || container->state == ContainerState::destroyed)
      {
        continue;
      }

      toSchedule.push_back(planStatelessDestruction(container, reason));
    }
  }

  void scheduleConstructionDestruction(DeploymentWork *cwork, DeploymentWork *dwork)
  {
    if (dwork)
    {
      auto assignNext = [&](DeploymentWork *a, DeploymentWork *b) -> void {
        if (StatelessWork *work = std::get_if<StatelessWork>(a); work)
        {
          work->next = b;
        }
        else if (StatefulWork *work = std::get_if<StatefulWork>(a); work)
        {
          work->next = b;
        }
      };

      auto assignPrev = [&](DeploymentWork *a, DeploymentWork *b) -> void {
        if (StatelessWork *work = std::get_if<StatelessWork>(a); work)
        {
          work->prev = b;
        }
        else if (StatefulWork *work = std::get_if<StatefulWork>(a); work)
        {
          work->prev = b;
        }
      };

      if (plan.moveConstructively)
      {
        assignNext(cwork, dwork);
        assignPrev(dwork, cwork);

        toSchedule.push_back(cwork);
        toSchedule.push_back(dwork);
      }
      else
      {
        assignNext(dwork, cwork);
        assignPrev(cwork, dwork);

        toSchedule.push_back(dwork);
        toSchedule.push_back(cwork);
      }
    }
    else
    {
      toSchedule.push_back(cwork);
    }
  }

  uint32_t nFitOnMachineClaim(MachineTicket *ticket, Machine *machine, uint32_t nMore) // called by requestMoreMachines
  {
    if (plan.isStateful && ticket != nullptr && ticket->placementTopologyEpochs.empty())
    {
      buildPlacementTopologyEpochs(ticket->placementTopologyEpochs, ticket->shardGroups);
    }

    if (plan.isStateful && ticket != nullptr && ticket->placementTopologyEpochs.empty() == false)
    {
      ApplicationConfig initialConfig = statefulPlacementConfig(ticket->placementTopologyEpochs[0]);
      if (nFitOnMachine(this, machine, 1, MachineResourcesDelta {}, &initialConfig) == 0)
      {
        return 0;
      }
    }
    else
    {
      if (nFitOnMachine(this, machine, 1) == 0)
      {
        return 0;
      }
    }

    Machine::Claim claim;

    if (plan.isStateful)
    {
      MachineResourcesDelta claimDeltas = {};
      uint32_t index = 0;
      for (auto it = ticket->shardGroups.begin(); it != ticket->shardGroups.end();)
      {
        if (uint32_t shardGroup = *it; canPlaceReplicaForShardGroupOnRack(shardGroup, machine->rack))
        {
          uint32_t topologyEpoch = (index < ticket->placementTopologyEpochs.size()) ? ticket->placementTopologyEpochs[index] : 0;
          ApplicationConfig schedulingConfig = statefulPlacementConfig(topologyEpoch);
          if (nFitOnMachine(this, machine, 1, claimDeltas, &schedulingConfig) > 0)
          {
            it = ticket->shardGroups.erase(it);
            if (index < ticket->placementTopologyEpochs.size())
            {
              ticket->placementTopologyEpochs.erase(ticket->placementTopologyEpochs.begin() + index);
            }

            claim.shardGroups.push_back(shardGroup);
            claim.placementTopologyEpochs.push_back(topologyEpoch);
            racksByShardGroup[shardGroup].insert(machine->rack);
            prodigyApplyPlannedMachineScalarDelta(claimDeltas, schedulingConfig, 1);
            if (applicationUsesSharedCPUs(schedulingConfig))
            {
              claim.reservedSharedCPUMillisTotal += applicationRequestedCPUMillis(schedulingConfig);
            }
            else
            {
              claim.reservedIsolatedLogicalCoresTotal += applicationRequiredIsolatedCores(schedulingConfig);
            }
            claim.reservedMemoryMBTotal += schedulingConfig.totalMemoryMB();
            claim.reservedStorageMBTotal += schedulingConfig.totalStorageMB();

            Vector<uint32_t> reservedGPUMemoryMBs = {};
            Vector<AssignedGPUDevice> reservedGPUDevices = {};
            bool reservedGPUs = prodigyReserveMachineGPUsForInstance(machine, schedulingConfig, reservedGPUMemoryMBs, &reservedGPUDevices);
            assert(reservedGPUs && "stateful machine claim must reserve GPUs for each selected placement");
            prodigyAppendGPUMemoryMBs(claim.reservedGPUMemoryMBs, reservedGPUMemoryMBs);
            prodigyAppendAssignedGPUDevices(claim.reservedGPUDevices, reservedGPUDevices);
          }
          else
          {
            break;
          }
        }
        else
        {
          it++;
          index += 1;
          continue;
        }
      }

      claim.nFit = claim.shardGroups.size();
    }
    else
    {
      uint32_t maxPerRack = static_cast<uint32_t>(float(nTarget()) * plan.stateless.maxPerRackRatio);
      uint32_t maxPerMachine = static_cast<uint32_t>(float(nTarget()) * plan.stateless.maxPerMachineRatio);
      uint32_t rackUsed = countPerRack.getIf(machine->rack);
      uint32_t machineUsed = countPerMachine.getIf(machine);
      uint32_t rackBudget = (rackUsed >= maxPerRack) ? 0 : (maxPerRack - rackUsed);
      uint32_t machineBudget = (machineUsed >= maxPerMachine) ? 0 : (maxPerMachine - machineUsed);

      if (nMore > rackBudget)
      {
        nMore = rackBudget;
      }
      if (nMore > machineBudget)
      {
        nMore = machineBudget;
      }

      claim.nFit = nFitOnMachine(this, machine, nMore);
    }

    uint32_t nFit = claim.nFit;

    if (nFit > 0)
    {
      if (plan.isStateful)
      {
        for (uint32_t topologyEpoch : claim.placementTopologyEpochs)
        {
          ApplicationConfig schedulingConfig = statefulPlacementConfig(topologyEpoch);
          prodigyDebitMachineScalarResources(machine, schedulingConfig, 1);
        }
      }
      else
      {
        claim.reservedIsolatedLogicalCoresPerInstance = applicationRequiredIsolatedCores(plan.config);
        claim.reservedSharedCPUMillisPerInstance = applicationUsesSharedCPUs(plan.config) ? applicationRequestedCPUMillis(plan.config) : 0;
        claim.reservedMemoryMBPerInstance = plan.config.totalMemoryMB();
        claim.reservedStorageMBPerInstance = plan.config.totalStorageMB();
        if (prodigyReserveMachineGPUsForInstances(machine, plan.config, nFit, claim.reservedGPUMemoryMBs, &claim.reservedGPUDevices) == false)
        {
          claim.nFit = 0;
          return 0;
        }

        prodigyDebitMachineScalarResources(machine, plan.config, nFit);
      }

      countPerMachine[machine] += nFit;
      countPerRack[machine->rack] += nFit;

      claim.ticket = ticket;
      machine->claims.emplace_back(std::move(claim));
    }

    return nFit;
  }

  // only used this stateless deployment
  // nToFit how many we're still trying to fit
  static uint32_t clampBudgetByRackAndMachine(ApplicationDeployment *deployment, Machine *machine, uint32_t nToFit)
  {
    auto maxAllowed = [](uint32_t total, float ratio) -> uint32_t {
      if (total == 0 || ratio <= 0.0f)
      {
        return 0U;
      }
      double allowed = std::ceil(static_cast<double>(total) * static_cast<double>(ratio));
      if (allowed < 1.0)
      {
        allowed = 1.0;
      }
      if (allowed > static_cast<double>(UINT32_MAX))
      {
        allowed = static_cast<double>(UINT32_MAX);
      }
      return static_cast<uint32_t>(allowed);
    };

    uint32_t maxPerRack = maxAllowed(deployment->nTarget(), deployment->plan.stateless.maxPerRackRatio);
    uint32_t maxPerMachine = maxAllowed(deployment->nTarget(), deployment->plan.stateless.maxPerMachineRatio);

    uint32_t rackUsed = deployment->countPerRack.getIf(machine->rack);
    uint32_t rackBudget = (rackUsed >= maxPerRack) ? 0 : (maxPerRack - rackUsed);
    if (rackBudget == 0)
    {
      return 0;
    }

    uint32_t machineUsed = deployment->countPerMachine.getIf(machine);
    uint32_t machineBudget = (machineUsed >= maxPerMachine) ? 0 : (maxPerMachine - machineUsed);
    if (machineBudget == 0)
    {
      return 0;
    }

    uint32_t nFit = nToFit;

    if (rackBudget < nToFit)
    {
      nFit = rackBudget;
    }
    if (machineBudget < nToFit)
    {
      nFit = machineBudget;
    }

    return nFit;
  }

  static uint32_t nFitOntoResources(
      ApplicationDeployment *deployment,
      uint64_t nCores,
      uint64_t sharedCPUMillis,
      uint64_t nMemoryMB,
      uint64_t nStorageMB,
      const Vector<uint32_t>& availableGPUMemoryMBs,
      uint32_t budget,
      const ApplicationConfig *configOverride = nullptr)
  {
    const ApplicationConfig& config = (configOverride ? *configOverride : deployment->plan.config);
    uint64_t capacityPerCores = 0;
    if (applicationUsesSharedCPUs(config))
    {
      uint64_t requestedSharedCPU = applicationRequestedCPUMillis(config);
      capacityPerCores = (requestedSharedCPU ? (sharedCPUMillis / requestedSharedCPU) : 0);
    }
    else
    {
      capacityPerCores = (config.nLogicalCores ? (nCores / config.nLogicalCores) : 0);
    }
    uint64_t capacityPerMemory = (config.totalMemoryMB() ? (nMemoryMB / config.totalMemoryMB()) : 0);
    uint64_t capacityPerStorage = (config.totalStorageMB() ? (nStorageMB / config.totalStorageMB()) : 0);

    uint64_t canScheduleN = budget;

    if (capacityPerCores < canScheduleN)
    {
      canScheduleN = capacityPerCores;
    }
    if (capacityPerMemory < canScheduleN)
    {
      canScheduleN = capacityPerMemory;
    }
    if (capacityPerStorage < canScheduleN)
    {
      canScheduleN = capacityPerStorage;
    }

    uint32_t requiredGPUs = applicationRequiredWholeGPUs(config);
    if (requiredGPUs > 0 && canScheduleN > 0)
    {
      Vector<uint32_t> scratchGPUMemoryMBs = availableGPUMemoryMBs;
      Vector<uint32_t> assignedGPUMemoryMBs = {};
      uint64_t capacityPerGPUs = 0;

      while (capacityPerGPUs < canScheduleN && prodigyAllocateWholeGPUSlots(
                                                   scratchGPUMemoryMBs,
                                                   nullptr,
                                                   nullptr,
                                                   requiredGPUs,
                                                   applicationRequiredGPUMemoryMB(config),
                                                   assignedGPUMemoryMBs))
      {
        capacityPerGPUs += 1;
      }

      if (capacityPerGPUs < canScheduleN)
      {
        canScheduleN = capacityPerGPUs;
      }
    }

    return static_cast<uint32_t>(canScheduleN);
  }

  static bool resolveWhiteholeSourceAddressForScheduling(
      Machine *machine,
      Whitehole& whitehole,
      uint128_t *requiredMachineUUID = nullptr,
      const ContainerView *container = nullptr,
      const RoutableResourceLeaseOwner *owner = nullptr)
  {
    (void)container;
    if (requiredMachineUUID)
    {
      *requiredMachineUUID = 0;
    }

    if (machine == nullptr || machine->state != MachineState::healthy || machineHasWhiteholeInternetAccessForDeployment(machine, whitehole.family) == false)
    {
      return false;
    }

    if (whitehole.source == ExternalAddressSource::hostPublicAddress)
    {
      if (resolveMachineWhiteholeInternetSourceAddressForDeployment(machine, whitehole.family, whitehole.address) == false)
      {
        return false;
      }

      whitehole.hasAddress = true;
      if (requiredMachineUUID)
      {
        *requiredMachineUUID = machine->uuid;
      }
      return true;
    }

    if (whitehole.source == ExternalAddressSource::registeredRoutablePrefix)
    {
      const DistributableExternalSubnet *subnet = findWhiteholeRoutablePrefixForFamily(
          thisBrain->brainConfig,
          whitehole.family,
          machine,
          requiredMachineUUID);
      if (subnet == nullptr)
      {
        return false;
      }

      IPPrefix registered = subnet->subnet.canonicalized();
      uint64_t firstOffset = distributableExternalSubnetIsHostPrefix(*subnet) ? 0 : 1;
      for (uint64_t offset = firstOffset; offset < firstOffset + 65'536u; ++offset)
      {
        IPAddress candidate = {};
        if (routablePrefixAddressAtOffset(registered, offset, candidate) == false)
        {
          break;
        }
        if (candidate.isNull() == false && whiteholeAddressHasFreePort(candidate, owner))
        {
          whitehole.address = candidate;
          whitehole.hasAddress = true;
          return true;
        }
      }

      return false;
    }

    return false;
  }

  static bool whiteholeAddressPortAlreadyInUse(const IPAddress& address, uint16_t sourcePort, const RoutableResourceLeaseOwner *owner = nullptr)
  {
    if (address.isNull() || sourcePort == 0)
    {
      return false;
    }

    for (const auto& [uuid, candidate] : thisBrain->containers)
    {
      (void)uuid;
      if (candidate == nullptr)
      {
        continue;
      }

      if (candidate->state == ContainerState::destroying || candidate->state == ContainerState::destroyed)
      {
        continue;
      }

      for (const Whitehole& existing : candidate->whiteholes)
      {
        if (existing.sourcePort == sourcePort && existing.address.equals(address))
        {
          return true;
        }
      }
    }

    RoutableResourceLease lease = {};
    lease.kind = RoutableResourceLeaseKind::whiteholeAddressPort;
    if (owner != nullptr)
    {
      lease.owner = *owner;
    }
    lease.address = address;
    lease.sourcePort = sourcePort;
    for (const RoutableResourceLease& existing : thisBrain->routableResourceLeaseRuntimeState)
    {
      if (routableResourceLeasesConflict(existing, lease))
      {
        return true;
      }
    }

    return false;
  }

  static bool whiteholeAddressHasFreePort(const IPAddress& address, const RoutableResourceLeaseOwner *owner = nullptr)
  {
    for (uint32_t port = 49'152; port <= 65'535; ++port)
    {
      if (whiteholeAddressPortAlreadyInUse(address, uint16_t(port), owner) == false)
      {
        return true;
      }
    }
    return false;
  }

  static bool allocateWhiteholeSourcePort(Whitehole& whitehole, const RoutableResourceLeaseOwner *owner = nullptr)
  {
    if (whitehole.address.isNull())
    {
      return false;
    }

    for (uint32_t port = 49'152; port <= 65'535; ++port)
    {
      uint16_t candidatePort = uint16_t(port);
      if (whiteholeAddressPortAlreadyInUse(whitehole.address, candidatePort, owner))
      {
        continue;
      }

      whitehole.sourcePort = candidatePort;
      whitehole.bindingNonce = Random::generateNumberWithNBits<64, uint64_t>();
      if (whitehole.bindingNonce == 0)
      {
        whitehole.bindingNonce = 1;
      }

      return true;
    }

    return false;
  }

  RoutableResourceLeaseOwner routableResourceLeaseOwner(void) const
  {
    RoutableResourceLeaseOwner owner = {};
    owner.applicationID = plan.config.applicationID;
    owner.deploymentID = plan.config.deploymentID();
    owner.lineageID = plan.config.applicationID;
    return owner;
  }

  bool reserveWhiteholeAddressPortLease(const Whitehole& whitehole, const RoutableResourceLeaseOwner& owner)
  {
    if (whitehole.hasAddress == false || whitehole.address.isNull() || whitehole.sourcePort == 0)
    {
      return false;
    }

    RoutableResourceLease lease = {};
    lease.kind = RoutableResourceLeaseKind::whiteholeAddressPort;
    lease.owner = owner;
    lease.address = whitehole.address;
    lease.sourcePort = whitehole.sourcePort;
    for (const DistributableExternalSubnet& subnet : thisBrain->brainConfig.distributableExternalSubnets)
    {
      if (distributableExternalSubnetAllowsWhiteholes(subnet) && distributableExternalSubnetContainsAddress(subnet, whitehole.address))
      {
        lease.registeredPrefixUUID = subnet.uuid;
        break;
      }
    }
    for (const RoutableResourceLease& existing : thisBrain->routableResourceLeaseRuntimeState)
    {
      if (existing.kind == lease.kind && existing.sourcePort == lease.sourcePort && existing.address.equals(lease.address) && routableResourceLeaseOwnersCompatible(existing.owner, lease.owner))
      {
        return true;
      }
      if (routableResourceLeasesConflict(existing, lease))
      {
        return false;
      }
    }

    thisBrain->routableResourceLeaseRuntimeState.push_back(lease);
    thisBrain->noteRoutableResourceLeaseRuntimeStateChanged();
    return true;
  }

  bool releaseWhiteholeAddressPortLease(const Whitehole& whitehole, const RoutableResourceLeaseOwner& owner)
  {
    if (whitehole.hasAddress == false || whitehole.address.isNull() || whitehole.sourcePort == 0)
    {
      return false;
    }

    bool released = false;
    for (auto it = thisBrain->routableResourceLeaseRuntimeState.begin(); it != thisBrain->routableResourceLeaseRuntimeState.end();)
    {
      if (it->kind == RoutableResourceLeaseKind::whiteholeAddressPort && it->owner.deploymentID == owner.deploymentID && it->address.equals(whitehole.address) && it->sourcePort == whitehole.sourcePort)
      {
        it = thisBrain->routableResourceLeaseRuntimeState.erase(it);
        released = true;
      }
      else
      {
        ++it;
      }
    }
    if (released)
    {
      thisBrain->noteRoutableResourceLeaseRuntimeStateChanged();
    }
    return released;
  }

  static uint32_t nFitOnMachine(ApplicationDeployment *deployment, Machine *machine, uint32_t budget, const MachineResourcesDelta& deltas = MachineResourcesDelta {}, const ApplicationConfig *configOverride = nullptr)
  {
    if (deployment == nullptr || machine == nullptr)
    {
      return 0;
    }

    const ApplicationConfig& config = (configOverride ? *configOverride : deployment->plan.config);

    if (prodigyMachineMeetsApplicationResourceCriteria(machine, config) == false)
    {
      return 0;
    }

    uint128_t requiredWormholeMachineUUID = 0;
    auto logWormholeReject = [&](const char *reason) -> uint32_t {
      if (deployment == nullptr || machine == nullptr || deployment->plan.wormholes.empty())
      {
        return 0;
      }

      String machineUUIDText = {};
      machineUUIDText.assignItoh(machine->uuid);
      String requiredUUIDText = {};
      requiredUUIDText.assignItoh(requiredWormholeMachineUUID);
      basics_log(
          "wormhole nFitOnMachine reject reason=%s deploymentID=%llu machineUUID=%s requiredMachineUUID=%s state=%d slug=%s private4=%u avail=%d/%d/%d/%d/%u budget=%u deltas=%d/%d/%d/%d/%u wormholes=%u\n",
          (reason ? reason : "unknown"),
          (unsigned long long)deployment->plan.config.deploymentID(),
          machineUUIDText.c_str(),
          requiredUUIDText.c_str(),
          int(machine->state),
          machine->slug.c_str(),
          unsigned(machine->private4),
          int(machine->nLogicalCores_available),
          int(machine->sharedCPUMillis_available),
          int(machine->memoryMB_available),
          int(machine->storageMB_available),
          unsigned(machine->availableGPUCount()),
          unsigned(budget),
          int(deltas.nLogicalCores),
          int(deltas.sharedCPUMillis),
          int(deltas.nMemoryMB),
          int(deltas.nStorageMB),
          unsigned(deltas.gpuMemoryMBs.size()),
          unsigned(deployment->plan.wormholes.size()));
      return 0;
    };

    for (const Wormhole& wormhole : deployment->plan.wormholes)
    {
      if (wormhole.source != ExternalAddressSource::registeredRoutablePrefix)
      {
        continue;
      }

      const DistributableExternalSubnet *registered = findRegisteredRoutablePrefix(
          thisBrain->brainConfig.distributableExternalSubnets,
          wormhole.routablePrefixUUID);
      if (registered == nullptr)
      {
        return logWormholeReject("registered-routable-prefix-missing");
      }

      if (registered->ingressScope != RoutableIngressScope::singleMachine)
      {
        continue;
      }

      if (registered->machineUUID == 0)
      {
        return logWormholeReject("registered-routable-prefix-machine-missing");
      }

      if (requiredWormholeMachineUUID == 0)
      {
        requiredWormholeMachineUUID = registered->machineUUID;
      }
      else if (requiredWormholeMachineUUID != registered->machineUUID)
      {
        return logWormholeReject("registered-routable-prefix-machine-conflict");
      }

      if (requiredWormholeMachineUUID != machine->uuid)
      {
        return logWormholeReject("registered-routable-prefix-machine-mismatch");
      }
    }

    uint128_t requiredWhiteholeMachineUUID = 0;
    auto logWhiteholeReject = [&](const char *reason) -> uint32_t {
      if (deployment == nullptr || machine == nullptr || deployment->plan.whiteholes.empty())
      {
        return 0;
      }

      String machineUUIDText = {};
      machineUUIDText.assignItoh(machine->uuid);
      String requiredUUIDText = {};
      requiredUUIDText.assignItoh(requiredWhiteholeMachineUUID);
      basics_log(
          "whitehole nFitOnMachine reject reason=%s deploymentID=%llu machineUUID=%s requiredMachineUUID=%s state=%d slug=%s private4=%u avail=%d/%d/%d/%d/%u budget=%u deltas=%d/%d/%d/%d/%u whiteholes=%u\n",
          (reason ? reason : "unknown"),
          (unsigned long long)deployment->plan.config.deploymentID(),
          machineUUIDText.c_str(),
          requiredUUIDText.c_str(),
          int(machine->state),
          machine->slug.c_str(),
          unsigned(machine->private4),
          int(machine->nLogicalCores_available),
          int(machine->sharedCPUMillis_available),
          int(machine->memoryMB_available),
          int(machine->storageMB_available),
          unsigned(machine->availableGPUCount()),
          unsigned(budget),
          int(deltas.nLogicalCores),
          int(deltas.sharedCPUMillis),
          int(deltas.nMemoryMB),
          int(deltas.nStorageMB),
          unsigned(deltas.gpuMemoryMBs.size()),
          unsigned(deployment->plan.whiteholes.size()));
      return 0;
    };

    for (const Whitehole& whiteholeTemplate : deployment->plan.whiteholes)
    {
      Whitehole resolvedWhitehole = whiteholeTemplate;
      uint128_t whiteholeMachineUUID = 0;
      if (resolveWhiteholeSourceAddressForScheduling(machine, resolvedWhitehole, &whiteholeMachineUUID) == false)
      {
        requiredWhiteholeMachineUUID = whiteholeMachineUUID;
        return logWhiteholeReject("whitehole-source-resolution");
      }

      if (requiredWhiteholeMachineUUID == 0 && whiteholeMachineUUID != 0)
      {
        requiredWhiteholeMachineUUID = whiteholeMachineUUID;
      }
    }

    int64_t nCores = static_cast<int64_t>(machine->nLogicalCores_available) + static_cast<int64_t>(deltas.nLogicalCores);
    int64_t nSharedCPU = static_cast<int64_t>(machine->sharedCPUMillis_available) + static_cast<int64_t>(deltas.sharedCPUMillis);
    int64_t nMemory = static_cast<int64_t>(machine->memoryMB_available) + static_cast<int64_t>(deltas.nMemoryMB);
    int64_t nStorage = static_cast<int64_t>(machine->storageMB_available) + static_cast<int64_t>(deltas.nStorageMB);
    Vector<uint32_t> availableGPUMemoryMBs = machine->availableGPUMemoryMBs;
    prodigyAppendGPUMemoryMBs(availableGPUMemoryMBs, deltas.gpuMemoryMBs);
    std::sort(availableGPUMemoryMBs.begin(), availableGPUMemoryMBs.end());

    uint32_t containerSlotBudget = machine->availableContainerSlotsForScheduling();
    if (containerSlotBudget == 0)
    {
      return logWhiteholeReject("container-slot-budget-exhausted");
    }

    if (budget > containerSlotBudget)
    {
      budget = containerSlotBudget;
    }

    uint64_t uCores = static_cast<uint64_t>(nCores > 0 ? nCores : 0);
    uint64_t uSharedCPU = static_cast<uint64_t>(nSharedCPU > 0 ? nSharedCPU : 0);
    uint64_t uMemory = static_cast<uint64_t>(nMemory > 0 ? nMemory : 0);
    uint64_t uStorage = static_cast<uint64_t>(nStorage > 0 ? nStorage : 0);

    uint32_t fit = nFitOntoResources(deployment, uCores, uSharedCPU, uMemory, uStorage, availableGPUMemoryMBs, budget, &config);
    if (fit == 0 && deployment != nullptr && deployment->plan.whiteholes.empty() == false)
    {
      String machineUUIDText = {};
      machineUUIDText.assignItoh(machine->uuid);
      String requiredUUIDText = {};
      requiredUUIDText.assignItoh(requiredWhiteholeMachineUUID);
      basics_log(
          "whitehole nFitOnMachine reject reason=resource-budget deploymentID=%llu machineUUID=%s requiredMachineUUID=%s effectiveAvail=%llu/%llu/%llu/%llu/%llu required=%u/%u/%u/%u/%u budget=%u containerSlots=%u\n",
          (unsigned long long)deployment->plan.config.deploymentID(),
          machineUUIDText.c_str(),
          requiredUUIDText.c_str(),
          (unsigned long long)uCores,
          (unsigned long long)uSharedCPU,
          (unsigned long long)uMemory,
          (unsigned long long)uStorage,
          (unsigned long long)availableGPUMemoryMBs.size(),
          unsigned(config.nLogicalCores),
          unsigned(applicationRequestedCPUMillis(config)),
          unsigned(config.totalMemoryMB()),
          unsigned(config.totalStorageMB()),
          unsigned(applicationRequiredWholeGPUs(config)),
          unsigned(budget),
          unsigned(containerSlotBudget));
    }

    return fit;
  }

  bool waitingOnCompactions = false; // if true, can't use this deployment in further compactions because it's blocked and won't be making progress on any work

  bytell_hash_map<ContainerView *, ContainerState> waitingOnContainers; // when creating or destroying, before we can make scheduling progress
  Vector<DeploymentWork *> toSchedule;
  DeploymentWork *currentlyExecutingWork = nullptr;

  bytell_hash_set<ContainerView *> containers;

  CompoundSuspension schedulingStack;
  bool consumingSchedulingExecution = false;
  CoroutineStack *retiredSchedulingExecution = nullptr;
  CoroutineStack *canaryStack = nullptr;

  ApplicationDeployment *previous = nullptr;
  ApplicationDeployment *next = nullptr;

  bytell_hash_map<uint32_t, ContainerView *> masterForShardGroup; // only for stateful + !allMasters

  DeploymentPlan plan;

  // Vertical autoscale is an in-place resource modifier over a stable deployment identity.
  // Keep signed deltas relative to the initial requested floor so we can scale back down safely.
  bool verticalResourceBaseInitialized = false;
  uint32_t verticalResourceBase_nLogicalCores = 0;
  uint32_t verticalResourceBase_memoryMB = 0;
  uint32_t verticalResourceBase_storageMB = 0;
  int32_t verticalAdjustment_nLogicalCores = 0;
  int32_t verticalAdjustment_memoryMB = 0;
  int32_t verticalAdjustment_storageMB = 0;
  bool statefulWorkerTopologyUpgradePending = false;
  StatefulWorkerTopologyUpgradePhase statefulWorkerTopologyUpgradePhase = StatefulWorkerTopologyUpgradePhase::none;
  uint64_t statefulWorkerTopologyUpgradeOperationID = 0;
  uint32_t statefulWorkerTopologyUpgradeSourceWorkerCount = 0;
  uint32_t statefulWorkerTopologyUpgradeTargetWorkerCount = 0;
  uint32_t statefulWorkerTopologyUpgradeSourceEpoch = 0;
  uint32_t statefulWorkerTopologyUpgradeTargetEpoch = 0;
  uint16_t statefulWorkerTopologyUpgradeTargetLogicalCores = 0;
  uint32_t statefulWorkerTopologyUpgradeTargetMemoryMB = 0;
  uint32_t statefulWorkerTopologyUpgradeTargetStorageMB = 0;
  int64_t statefulWorkerTopologyUpgradePhaseChangedAtMs = 0;
  bytell_hash_set<uint32_t> statefulWorkerTopologyLockedShardGroups;
  uint32_t deferredStatefulTargetShardGroups = 0;
  uint16_t deferredStatefulTargetLogicalCores = 0;
  uint32_t deferredStatefulTargetMemoryMB = 0;
  uint32_t deferredStatefulTargetStorageMB = 0;
  int64_t statefulDeferredScaleIntentUpdatedAtMs = 0;

  uint32_t nCrashes = 0;

  bytell_hash_map<Machine *, uint32_t> countPerMachine;
  bytell_hash_map<Rack *, uint32_t> countPerRack;

  // Keep cluster report payloads bounded and serialization-safe.
  constexpr static uint32_t maxFailureReports = 64;

  Vector<FailureReport> failureReports;

  // stateful
  uint32_t nShardGroups;
  bytell_hash_subset<uint32_t, ContainerView *> containersByShardGroup;
  bytell_hash_subset<uint32_t, Rack *> racksByShardGroup;

  bool deployingNewShardGroup = false;

  // end of stateful

  DeploymentState state = DeploymentState::none;
  int64_t stateChangedAtMs = 0;

  // we wait on...
  // 1) new machines so that we can schedule more containers
  // 2) canaries to surive or die over their assigned lifetime
  //			* this we could interrupt... we could just outright kill the canaries. doesn't make any sense to wait for them to deploy fully after either.
  // 3) on containers to be created or destroyed in order to continue making scheduling progress
  // 4) on other deployments to complete compactions for us

  void cullShardingServices(void)
  {
    deployingNewShardGroup = false;

    for (ContainerView *container : containersByShardGroup[nShardGroups - 1]) // must be the most recent shard group
    {
      for (uint32_t shardGroup = 0; shardGroup < (nShardGroups - 1); ++shardGroup)
      {
        StatefulMeshRoles roles = statefulMeshRolesForShardGroup(shardGroup);

        // cull sharding service pairings (this is the signal to delete the sharded data!!!!!!)
        thisBrain->mesh->stopSubscription(roles.sharding, container, SubscriptionNature::all, true);
        thisBrain->mesh->stopSubscription(roles.cousin, container, SubscriptionNature::all, true);
      }
    }

    dispatchDeferredStatefulScaleIntent();
  }

  void dispatchTimeout(TimeoutPacket *packet)
  {
    switch (DeploymentTimeoutFlags(packet->flags))
    {
      case DeploymentTimeoutFlags::canariesMinimumLifetime:
        {
          canaryTimerExpired();
          break;
        }
      case DeploymentTimeoutFlags::shardGroupReady:
        {
          cullShardingServices();
          break;
        }
      case DeploymentTimeoutFlags::autoscale:
        {
          loadStress();
          break;
        }
      case DeploymentTimeoutFlags::statefulTopologyRollbackWindow:
        {
          statefulWorkerTopologyUpgradeRollbackWindowExpired();
          break;
        }
    }
  }

  // it will first check which deployments were running on that machine
  // there must be some that were not marked for destruction, otherwise this function would've never been called
  void drainMachine(Machine *machine, bool failed)
  {
    Vector<ContainerView *> containersToRedeploy;
    Vector<ContainerView *> skippedScheduledContainers;
    bytell_hash_set<ContainerView *> seenContainers;

    auto& bin = machine->containersByDeploymentID[plan.config.deploymentID()];
    basics_log("drainMachine deploymentID=%llu machinePrivate4=%u failed=%d binSize=%llu\n",
               (unsigned long long)plan.config.deploymentID(),
               machine->private4,
               int(failed),
               (unsigned long long)bin.size());

    for (auto it = bin.begin(); it != bin.end();)
    {
      ContainerView *container = *it;
      it = bin.erase(it);

      if (container == nullptr)
      {
        continue;
      }

      if (seenContainers.contains(container))
      {
        continue;
      }
      seenContainers.insert(container);

      // Ignore stale machine index pointers that are no longer part of this
      // deployment's canonical container set.
      if (containers.contains(container) == false)
      {
        continue;
      }

      switch (container->state)
      {
        case ContainerState::planned:
        case ContainerState::scheduled:
        case ContainerState::crashedRestarting:
        case ContainerState::healthy:
          {
            if (failed == false && container->state == ContainerState::scheduled)
            {
              basics_log("drainMachine skip-scheduled-live-redeploy deploymentID=%llu appID=%u uuid=%llu machinePrivate4=%u waitingOnContainers=%llu toSchedule=%llu\n",
                         (unsigned long long)plan.config.deploymentID(),
                         unsigned(plan.config.applicationID),
                         (unsigned long long)container->uuid,
                         unsigned(machine->private4),
                         (unsigned long long)waitingOnContainers.size(),
                         (unsigned long long)toSchedule.size());
              skippedScheduledContainers.push_back(container);
              break;
            }

            if (isDecommissioning()) // this means the new head is actively or waiting to transitioning to itself
            {
              if (failed)
              {
                if (container->state == ContainerState::healthy)
                {
                  switch (container->lifetime)
                  {
                    case ApplicationLifetime::canary:
                      {
                        if (nHealthyCanary > 0)
                        {
                          nHealthyCanary -= 1;
                        }
                        break;
                      }
                    case ApplicationLifetime::base:
                      {
                        if (nHealthyBase > 0)
                        {
                          nHealthyBase -= 1;
                        }
                        break;
                      }
                    case ApplicationLifetime::surge:
                      {
                        if (nHealthySurge > 0)
                        {
                          nHealthySurge -= 1;
                        }
                        break;
                      }
                  }
                }

                destructContainer(container);
                containerDestroyed(container); // container object is destroyed here
              }
              else
              {
                // the master will destroy them soon, let that play out... don't move these
              }
            }
            else
            {
              if (failed && container->state == ContainerState::healthy)
              {
                switch (container->lifetime)
                {
                  case ApplicationLifetime::canary:
                    {
                      if (nHealthyCanary > 0)
                      {
                        nHealthyCanary -= 1;
                      }
                      break;
                    }
                  case ApplicationLifetime::base:
                    {
                      if (nHealthyBase > 0)
                      {
                        nHealthyBase -= 1;
                      }
                      break;
                    }
                  case ApplicationLifetime::surge:
                    {
                      if (nHealthySurge > 0)
                      {
                        nHealthySurge -= 1;
                      }
                      break;
                    }
                }
              }

              if (container->plannedWork) // aka ContainerState::planned + could be LifecycleOp::construct or LifecycleOp::updateInPlace
              {
                WorkBase *work = container->plannedWork->getBase();

                switch (work->lifecycle)
                {
                  case LifecycleOp::construct: // only construct has linked work to manage
                    {
                      if (DeploymentWork *linkedMeta = work->prev ?: work->next; linkedMeta)
                      {
                        WorkBase *linkedWork = linkedMeta->getBase();

                        if (failed == false || linkedWork->machine != machine)
                        {
                          // if there is a linked deletion, it's either a previous deployment.... or a compaction so we're being moved to a new machine.. or maybe we were draining a machine
                          // either way both are run on this deployment queue

                          // if the linked deletion is not on this machine, then we need to remove it from its deployment queue
                          // then we'll reschedule it once we reschedule the construction onto a new machine
                          toSchedule.erase(linkedMeta);
                        }
                        else // failed + linked deletion is on this machine
                        {
                          // it could be another deployment that might not run until after we do
                          // so just clear all links. we were run first... otherwise links would've been destroyed.

                          linkedWork->prev = nullptr;
                          linkedWork->next = nullptr;

                          work->prev = nullptr;
                          work->next = nullptr;
                        }
                      }
                    }
                  case LifecycleOp::updateInPlace:
                    {
                      if (failed)
                      {
                        // in spinStateful we transform it into a construct
                      }
                      else
                      {
                        // in spinStateful we split it into a destruct and a construct... moving the construct to another machine
                      }

                      break;
                    }
                  default:
                    break; // others impossible
                }

                toSchedule.erase(container->plannedWork);

                // re-planning to another machine so return the resources
                prodigyCreditMachineScalarResources(machine, plan.config, 1);
                prodigyReleaseContainerGPUs(container);
              }

              switch (container->lifetime)
              {
                case ApplicationLifetime::canary:
                  {
                    if (nDeployedCanary > 0)
                    {
                      nDeployedCanary -= 1;
                    }
                    break;
                  }
                case ApplicationLifetime::base:
                  {
                    if (nDeployedBase > 0)
                    {
                      nDeployedBase -= 1;
                    }

                    break;
                  }
                case ApplicationLifetime::surge:
                  {
                    if (nDeployedSurge > 0)
                    {
                      nDeployedSurge -= 1;
                    }
                    break;
                  }
              }

              containersToRedeploy.push_back(container);
            }

            break;
          }
        case ContainerState::aboutToDestroy:
          {
            // it's possible this is part of an update in place

            // if it's an update in place that means this is the previous deployment

            if (failed)
            {
              destructContainer(container);
              containerDestroyed(container); // container object is destroyed here
            }
            // else let this play out as is

            break;
          }
        case ContainerState::destroying:
          {
            if (failed)
            {
              containerDestroyed(container); // container object is destroyed here
            }

            break;
          }
        // not possible
        case ContainerState::none:
        case ContainerState::destroyed:
          break;
      }
    }

    for (ContainerView *container : skippedScheduledContainers)
    {
      machine->upsertContainerIndexEntry(plan.config.deploymentID(), container);
    }

    if (containersToRedeploy.size() > 0)
    {
      CoroutineStack *coro = new CoroutineStack();

      bool setCanaryClockAfter = false;

      if (nTargetCanary < nDeployedCanary)
      {
        Ring::queueCancelTimeout(&canaryTimer); // if there are other canaries they get an extended lease
        setCanaryClockAfter = true;
      }

      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            if (plan.isStateful)
            {
              spinStateful(coro, containersToRedeploy, failed);
            }
            else
            {
              spinStateless(coro, containersToRedeploy, failed);
            }
          }))
      {
        nSuspended += 1;
        co_await coro->suspendAtIndex(suspendIndex);
        nSuspended -= 1;
      }

      if (setCanaryClockAfter)
      {
        setCanaryTimeout();
      }

      delete coro;

      schedule(nullptr);
    }
  }

  void handleContainerStateChange(ContainerView *container, bool notifyContainer)
  {
    container->reconcileMeshAgainstState(notifyContainer);
    handleContainerWaiters(container);
  }

  void clearEquivalentHealthyWaiters(ContainerView *container)
  {
    if (container == nullptr || container->state != ContainerState::healthy)
    {
      return;
    }

    bool removed = false;
    for (auto it = waitingOnContainers.begin(); it != waitingOnContainers.end();)
    {
      ContainerView *waitingContainer = it->first;
      if (it->second == ContainerState::healthy && waitingContainer != nullptr && waitingContainer->uuid == container->uuid)
      {
        it = waitingOnContainers.erase(it);
        removed = true;
        continue;
      }

      ++it;
    }

    if (removed && waitingOnContainers.size() == 0)
    {
      if (schedulingStack.execution)
      {
        consumeSchedulingExecution();
      }
      dispatchDeferredStatefulScaleIntent();
    }
  }

  void containerIsHealthy(ContainerView *container)
  {
    if (container == nullptr)
    {
      return;
    }

    std::fprintf(stderr,
                 "deployment containerIsHealthy enter deploymentID=%llu appID=%u uuid=%llu stateBefore=%u waitingBefore=%llu nHealthy=%u/%u/%u\n",
                 (unsigned long long)plan.config.deploymentID(),
                 unsigned(plan.config.applicationID),
                 (unsigned long long)container->uuid,
                 unsigned(container->state),
                 (unsigned long long)waitingOnContainers.size(),
                 unsigned(nHealthyBase),
                 unsigned(nHealthyCanary),
                 unsigned(nHealthySurge));
    std::fflush(stderr);

    if (container->state == ContainerState::destroyed || container->state == ContainerState::destroying || container->state == ContainerState::aboutToDestroy)
    {
      return;
    }

    if (container->state == ContainerState::healthy)
    {
#if PRODIGY_DEBUG
      basics_log("deployment containerIsHealthy duplicate deploymentID=%llu appID=%u uuid=%llu waitingOnContainers=%llu nHealthy=%u/%u/%u\n",
                 (unsigned long long)plan.config.deploymentID(),
                 unsigned(plan.config.applicationID),
                 (unsigned long long)container->uuid,
                 (unsigned long long)waitingOnContainers.size(),
                 unsigned(nHealthyBase),
                 unsigned(nHealthyCanary),
                 unsigned(nHealthySurge));
#endif
      clearEquivalentHealthyWaiters(container);
      // Duplicate healthy notifications can occur across reconnect races.
      // Keep existing pairings warm without replaying state transitions/counters.
      container->replayActivePairingsToSelf();
      return;
    }

    container->state = ContainerState::healthy;
    handleContainerStateChange(container, true);
    clearEquivalentHealthyWaiters(container);
    container->replayActivePairingsToSelf();
    container->replayActivePairingsToPeers();

    switch (container->lifetime)
    {
      case ApplicationLifetime::canary:
        {
          nHealthyCanary += 1;
          break;
        }
      case ApplicationLifetime::base:
        {
          nHealthyBase += 1;
          break;
        }
      case ApplicationLifetime::surge:
        {
          nHealthySurge += 1;
          break;
        }
    }

#if PRODIGY_DEBUG
    basics_log("deployment containerIsHealthy applied deploymentID=%llu appID=%u uuid=%llu machinePrivate4=%u waitingOnContainers=%llu nHealthy=%u/%u/%u nDeployed=%u/%u/%u\n",
               (unsigned long long)plan.config.deploymentID(),
               unsigned(plan.config.applicationID),
               (unsigned long long)container->uuid,
               unsigned(container->machine ? container->machine->private4 : 0u),
               (unsigned long long)waitingOnContainers.size(),
               unsigned(nHealthyBase),
               unsigned(nHealthyCanary),
               unsigned(nHealthySurge),
               unsigned(nDeployedBase),
               unsigned(nDeployedCanary),
               unsigned(nDeployedSurge));
#endif

    if (state == DeploymentState::deploying)
    {
      String message;

      if (container->lifetime == ApplicationLifetime::canary)
      {
        message.snprintf<"{itoa} canaries are healthy"_ctv>(nHealthyCanary);
      }
      else
      {
        message.snprintf<"{itoa} containers are healthy"_ctv>(nHealthy());
      }

      thisBrain->pushSpinApplicationProgressToMothership(this, message);
    }

    std::fprintf(stderr,
                 "deployment containerIsHealthy exit deploymentID=%llu appID=%u uuid=%llu stateAfter=%u waitingAfter=%llu nHealthy=%u/%u/%u\n",
                 (unsigned long long)plan.config.deploymentID(),
                 unsigned(plan.config.applicationID),
                 (unsigned long long)container->uuid,
                 unsigned(container->state),
                 (unsigned long long)waitingOnContainers.size(),
                 unsigned(nHealthyBase),
                 unsigned(nHealthyCanary),
                 unsigned(nHealthySurge));
    std::fflush(stderr);

    if (plan.isStateful == false)
    {
      // only non stateful allowed to have wormholes right now

      thisBrain->sendNeuronOpenSwitchboardWormholes(container, plan.wormholes);
    }
    else
    {
      if (deployingNewShardGroup) // aka stateful
      {
        bool allHealthy = true;

        for (ContainerView *container : containersByShardGroup[nShardGroups - 1]) // must be the most recent shard group
        {
          if (container->state != ContainerState::healthy)
          {
            allHealthy = false;
            break;
          }
        }

        if (allHealthy)
        {
          // now set a timer to wait some number of seconds for clients to connect to them
          // then cull the sharding pairings (this is the signal to delete the sharded data!!!)
          // cousin pairings lifetime is tied to the sharding as otherwise we’d end up with bad keys if we delete the data before clients stop sending it.

          shardTimer.setTimeoutSeconds(15); // wait 15 seconds for clients to connect? seems long but not too long. surely should all connect byt then

          shardTimer.dispatcher = this;
          shardTimer.flags = uint64_t(DeploymentTimeoutFlags::shardGroupReady);
          Ring::queueTimeout(&shardTimer);
        }
      }
    }
  }

  void containerIsRuntimeReady(ContainerView *container)
  {
    if (container == nullptr)
    {
      return;
    }

    if (container->state == ContainerState::destroyed || container->state == ContainerState::destroying || container->state == ContainerState::aboutToDestroy)
    {
      return;
    }

    if (container->runtimeReady == false)
    {
      container->runtimeReady = true;
      container->replayRuntimeReadyPairings();
    }

    commitStatefulWorkerTopologyUpgradeCutover();
  }

  void containerStatefulTopologyCutoverBarrierUpdated(ContainerView *container)
  {
    if (container == nullptr)
    {
      return;
    }

    commitStatefulWorkerTopologyUpgradeCutover();
  }

  void destructContainer(ContainerView *container, bool cancelWork = true)
  {
    if (cancelWork && container->plannedWork)
    {
      cancelDeploymentWork(container->plannedWork);
    }

    if (container->state == ContainerState::aboutToDestroy)
    {
      switch (container->lifetime)
      {
        case ApplicationLifetime::canary:
          {
            if (nHealthyCanary > 0)
            {
              nHealthyCanary -= 1;
            }
            break;
          }
        case ApplicationLifetime::base:
          {
            if (nHealthyBase > 0)
            {
              nHealthyBase -= 1;
            }
            break;
          }
        case ApplicationLifetime::surge:
          {
            if (nHealthySurge > 0)
            {
              nHealthySurge -= 1;
            }
            break;
          }
      }
    }

    container->state = ContainerState::destroying;
    handleContainerStateChange(container, false);

    Machine *machine = container->machine;
    ApplicationConfig containerConfig = resourceConfigForContainer(container);

    if (container->fragment > 0)
    {
      machine->relinquishContainerFragment(container->fragment);
    }

    prodigyCreditMachineScalarResources(machine, containerConfig, 1);
    prodigyReleaseContainerGPUs(container);

    containers.erase(container);

    if (plan.isStateful)
    {
      while (containersByShardGroup.eraseEntry(container->shardGroup, container))
      {
      }

      if (!plan.stateful.allMasters && masterForShardGroup[container->shardGroup] == container)
      {
        changeShardGroupMaster(container->shardGroup);
      }
    }
    else
    {
      thisBrain->sendNeuronCloseSwitchboardWormholesToContainer(container);
    }

    if (container->whiteholes.empty() == false)
    {
      thisBrain->sendNeuronCloseSwitchboardWhiteholesToContainer(container);
    }

    machine->removeContainerIndexEntry(container->deploymentID, container);
  }

  void containerDestroyed(ContainerView *container)
  {
    // Prevent double-destroy; out-of-band confirmations after a forced local destroy should not re-enter.
    assert(container->state != ContainerState::destroyed && "containerDestroyed called on an already-destroyed container");
    RoutableResourceLeaseOwner owner = {};
    owner.applicationID = container->applicationID;
    owner.deploymentID = container->deploymentID;
    owner.lineageID = container->applicationID;
    for (const Whitehole& whitehole : container->whiteholes)
    {
      releaseWhiteholeAddressPortLease(whitehole, owner);
    }

    thisBrain->containers.erase(container->uuid);

    container->state = ContainerState::destroyed;
    handleContainerStateChange(container, false);
    completeStatefulWorkerTopologyUpgradeIfReady();

    delete container;
  }

  void taskAttemptContainerDone(ContainerView *container)
  {
    if (container == nullptr)
    {
      return;
    }

    switch (container->lifetime)
    {
      case ApplicationLifetime::canary:
        {
          if (nDeployedCanary > 0)
          {
            nDeployedCanary -= 1;
          }
          break;
        }
      case ApplicationLifetime::base:
        {
          if (nDeployedBase > 0)
          {
            nDeployedBase -= 1;
          }
          break;
        }
      case ApplicationLifetime::surge:
        {
          if (nDeployedSurge > 0)
          {
            nDeployedSurge -= 1;
          }
          break;
        }
    }

    destructContainer(container);
    containerDestroyed(container);
  }

  void failCanaries(void)
  {
    markCanariesFailed();

    if (canaryStack)
    {
      canaryStack->co_consume();
    }
  }

  void markCanariesFailed(void)
  {
    state = DeploymentState::failed;
    stateChangedAtMs = Time::now<TimeResolution::ms>();
    Ring::queueCancelTimeout(&canaryTimer);
  }

  void resumeFailedCanaryRollbackAfterContainerCleanup(void)
  {
    if (canaryStack)
    {
      canaryStack->co_consume();
      return;
    }

    if (waitingOnContainers.empty() && schedulingStack.execution)
    {
      consumeSchedulingExecution();
    }
  }

  void changeShardGroupMaster(uint32_t shardGroup)
  {
    StatefulMeshRoles roles = statefulMeshRolesForShardGroup(shardGroup);

    ContainerView *master = masterForShardGroup[shardGroup];

    master->advertisements.erase(roles.client);
    thisBrain->mesh->stopAdvertisement(roles.client, master, false);

    for (ContainerView *other : containersByShardGroup[shardGroup])
    {
      if (other == master)
      {
        continue;
      }

      switch (other->state)
      {
        case ContainerState::planned:
        case ContainerState::scheduled:
        case ContainerState::healthy:
          {
            break;
          }
        default:
          continue;
      }

      if (prodigyStatefulTopologyServesClients(other->effectiveStatefulTopology(plan)) == false)
      {
        continue;
      }

      master = other;
      masterForShardGroup[shardGroup] = master;

      uint16_t port = master->getRandomAdvertisementPort();

      master->advertisements.emplace(roles.client, Advertisement(roles.client, ContainerState::healthy, ContainerState::destroying, port));

      if (master->state == ContainerState::healthy)
      {
        thisBrain->mesh->advertise(roles.client, master, port, false);
      }

      break;
    }
  }

  void containerFailed(ContainerView *container, int64_t approxTimeMs, int signal, const String& report, bool restarted)
  {
    std::fprintf(stderr,
                 "deployment containerFailed debug deploymentID=%llu appID=%u uuid=%llu containerDeploymentID=%llu state=%u lifetime=%u signal=%d restarted=%d containersBefore=%llu waitingBefore=%llu reportBytes=%u\n",
                 (unsigned long long)plan.config.deploymentID(),
                 unsigned(plan.config.applicationID),
                 (unsigned long long)(container ? container->uuid : 0),
                 (unsigned long long)(container ? container->deploymentID : 0),
                 unsigned(container ? container->state : ContainerState::none),
                 unsigned(container ? container->lifetime : ApplicationLifetime::base),
                 signal,
                 int(restarted),
                 (unsigned long long)containers.size(),
                 (unsigned long long)waitingOnContainers.size(),
                 unsigned(report.size()));
    std::fflush(stderr);

    if (containerUsesStatefulWorkerTopologyUpgradeTarget(container))
    {
      rollbackStatefulWorkerTopologyUpgradeCutover();
    }

    bool failedCanary = false;

    if (container->state == ContainerState::healthy)
    {
      switch (container->lifetime)
      {
        case ApplicationLifetime::canary:
          {
            if (nHealthyCanary > 0)
            {
              nHealthyCanary -= 1;
            }
            break;
          }
        case ApplicationLifetime::base:
          {
            if (nHealthyBase > 0)
            {
              nHealthyBase -= 1;
            }
            break;
          }
        case ApplicationLifetime::surge:
          {
            if (nHealthySurge > 0)
            {
              nHealthySurge -= 1;
            }
            break;
          }
      }
    }

    String alert;
    alert.snprintf_add<"Application: {itoa}\n"_ctv>(plan.config.applicationID);
    alert.snprintf_add<"Deployment: {itoa}\n"_ctv>(plan.config.deploymentID());
    alert.snprintf_add<"Container: {itoa}\n"_ctv>(container->uuid);
    alert.snprintf_add<"Time(ms since epoch): {itoa}\n"_ctv>(approxTimeMs);
    alert.snprintf_add<"Nth Crash: {itoa}\n"_ctv>(container->nCrashes);
    alert.snprintf_add<"Signal: {itoa}\n"_ctv>(signal);
    alert.snprintf_add<"Restarted: {itoa}\n"_ctv>(restarted);
    alert.snprintf_add<"Canary: {itoa}\n"_ctv>(container->lifetime == ApplicationLifetime::canary);
    uint64_t reportBytes = (report.size() < 256) ? report.size() : 256;
    String subReport = report.substr(0, reportBytes, Copy::no);
    alert.snprintf_add<"Report: {}\n"_ctv>(subReport);

    thisBrain->batphone.sendEmail(thisBrain->brainConfig.reporter.from, thisBrain->brainConfig.reporter.to, "Container Crashed!"_ctv, alert);

    bool failedBeforeDeployHealthy = false;
    if (container->deploymentID == plan.config.deploymentID())
    {
      ApplicationLifetime lifetime = container->lifetime;

      container->nCrashes += 1;
      nCrashes += 1; // total crashes across entire deployment

      if (failureReports.size() >= maxFailureReports)
      {
        failureReports.erase(failureReports.begin());
      }

      FailureReport& failureReport = failureReports.emplace_back();
      failureReport.containerUUID = container->uuid;
      failureReport.report = report.substr(0, reportBytes);
      failureReport.approxTimeMs = approxTimeMs;
      failureReport.nthCrash = container->nCrashes;
      failureReport.signal = signal;
      failureReport.restarted = restarted;
      failureReport.wasCanary = (lifetime == ApplicationLifetime::canary);

      failedCanary = (lifetime == ApplicationLifetime::canary);
      failedBeforeDeployHealthy = restarted == false && failedCanary == false && state == DeploymentState::deploying && waitingOnContainers.contains(container);
    }
    // else a container from the previous deployment failed

    if (failedCanary)
    {
      markCanariesFailed();
      waitingOnContainers.clear();
    }

    if (restarted == false)
    {
      if (failedBeforeDeployHealthy)
      {
        state = DeploymentState::failed;
        stateChangedAtMs = Time::now<TimeResolution::ms>();
      }

      countPerMachine[container->machine] -= 1;
      countPerRack[container->machine->rack] -= 1;

      if (plan.isStateful)
      {
        racksByShardGroup[container->shardGroup].erase(container->machine->rack);
      }

      // let it play "destroying" so that the states line up
      // non restartable container could've had services exposed
      destructContainer(container);
      containerDestroyed(container);

      if (failedCanary)
      {
        resumeFailedCanaryRollbackAfterContainerCleanup();
        return;
      }
      if (failedBeforeDeployHealthy)
      {
        thisBrain->deploymentFailed(this, plan.config.deploymentID(), report.size() ? report : String("container failed before becoming healthy"_ctv));
        return;
      }
    }
    else
    {
      container->state = ContainerState::crashedRestarting;
      // Keep the restarting container's own pairing view warm so the next
      // process can seed current dependencies, but do not replay this dead
      // endpoint back out to peers while the old listener is gone. The mesh
      // graph itself stays intact for a process restart, otherwise `any`
      // subscribers get reassigned to a different live advertiser and can
      // keep a stale port after that advertiser restarts.
      container->deactivateActivePeerSubscriptionsForRestart();
      container->replayActivePairingsToSelf();
      container->runtimeReady = false;
      container->clearStatefulTopologyCutoverBarrier();
    }

    if (failedCanary)
    {
      resumeFailedCanaryRollbackAfterContainerCleanup();
    }
  }

  void schedule(CoroutineStack *waiter = nullptr)
  {
    if (plan.isStateful)
    {
#if PRODIGY_DEBUG
      std::fprintf(stderr, "schedule enter deploymentID=%llu waiter=%p toSchedule=%llu waitingOnContainers=%llu execution=%p\n",
                   (unsigned long long)plan.config.deploymentID(),
                   (void *)waiter,
                   (unsigned long long)toSchedule.size(),
                   (unsigned long long)waitingOnContainers.size(),
                   (void *)schedulingStack.execution);
#endif
    }

    if (schedulingStack.execution != nullptr)
    {
#if PRODIGY_DEBUG
      std::fprintf(stderr, "schedule deferred deploymentID=%llu waiter=%p toSchedule=%llu waitingOnContainers=%llu execution=%p\n",
                   (unsigned long long)plan.config.deploymentID(),
                   (void *)waiter,
                   (unsigned long long)toSchedule.size(),
                   (unsigned long long)waitingOnContainers.size(),
                   (void *)schedulingStack.execution);
#endif
      if (waiter)
      {
        schedulingStack.waiters.push_back(waiter);
      }
      co_return; // we're already suspended processing the scheduling queue
    }

    LifecycleOp last = LifecycleOp::none;

    auto executeWork = [&]<typename T>(T& work) -> void {
      last = work.lifecycle;

      Machine *machine = work.machine;

      auto setupContainerServices = [&](ContainerView *container) -> void {
        auto setupAdvertisement = [&](uint64_t service, ContainerState startAt, ContainerState stopAt, uint16_t port = 0, ServiceUserCapacity userCapacity = {}) -> void {
          if (port == 0)
          {
            port = container->getRandomAdvertisementPort(); // assign dynamically
          }

          Advertisement advertisement(service, startAt, stopAt, port);
          advertisement.userCapacity = userCapacity;
          container->advertisements.emplace(service, advertisement);

          if (startAt == ContainerState::scheduled)
          {
            thisBrain->mesh->advertise(service, container, port, false);
          }
        };

        auto setupSubscription = [&](uint64_t service, ContainerState startAt, ContainerState stopAt, SubscriptionNature nature) -> void {
          container->subscriptions.emplace(service, Subscription(service, startAt, stopAt, nature));

          if (startAt == ContainerState::scheduled)
          {
            thisBrain->mesh->subscribe(service, container, nature, false);
          }
        };

        for (const Subscription& subscription : plan.subscriptions)
        {
          setupSubscription(subscription.service, subscription.startAt, subscription.stopAt, subscription.nature);
        }

        for (const Advertisement& advertisement : plan.advertisements)
        {
          setupAdvertisement(advertisement.service, advertisement.startAt, advertisement.stopAt, advertisement.port, advertisement.userCapacity);
        }

        if constexpr (std::is_same_v<T, StatefulWork>)
        {
          StatefulMeshRoles roles = container->effectiveStatefulMeshRoles(plan);
          StatefulTopology topology = container->effectiveStatefulTopology(plan);

          setupAdvertisement(roles.sibling, ContainerState::scheduled, ContainerState::destroying);
          setupAdvertisement(roles.seeding, ContainerState::healthy, ContainerState::destroying);
          if (roles.topologyBridge != 0 && prodigyStatefulTopologyShouldAdvertiseBridge(topology))
          {
            setupAdvertisement(roles.topologyBridge, ContainerState::scheduled, ContainerState::destroying);
          }

          if (prodigyStatefulTopologyServesClients(topology) && (plan.stateful.allMasters || !masterForShardGroup.contains(container->shardGroup)))
          {
            if (!plan.stateful.allMasters)
            {
              masterForShardGroup.insert_or_assign(container->shardGroup, container);
            }

            setupAdvertisement(roles.client, ContainerState::healthy, ContainerState::destroying);
          }

          if (plan.stateful.neverShard == false)
          {
            setupAdvertisement(roles.cousin, ContainerState::scheduled, ContainerState::destroying);
            setupAdvertisement(roles.sharding, ContainerState::healthy, ContainerState::destroying);
          }

          setupSubscription(roles.sibling, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all);
          if (roles.topologyBridge != 0 && prodigyStatefulTopologyShouldSubscribeBridge(topology))
          {
            setupSubscription(roles.topologyBridge, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all);
          }

          if (plan.stateful.seedingAlways)
          {
            setupSubscription(roles.seeding, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all);
          }

          switch (work.data)
          {
            case DataStrategy::genesis:
              {
                break;
              }
            case DataStrategy::changelog: // still give them seeding just in case there is a problem they can start from scratch
            case DataStrategy::seeding:
              {
                if (plan.stateful.seedingAlways == false)
                {
                  setupSubscription(roles.seeding, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all);
                }

                break;
              }
            case DataStrategy::sharding:
              {
                // feed on 1 instance from every other shard group
                for (uint32_t shardGroup = 0; shardGroup < (nShardGroups - 1); ++shardGroup) // container->shardGroup will be (nShardGroups - 1) thus excluded
                {
                  StatefulMeshRoles shardRoles = statefulMeshRolesForShardGroup(shardGroup);

                  // we'll cancel this subscription manually once all shards in the group are healthy and clients have connected

                  // sharding won't begin until after all cousins have connected... otherwise we could miss writes
                  setupSubscription(shardRoles.sharding, ContainerState::scheduled, ContainerState::none, SubscriptionNature::all);

                  // these are so that the sharding-sender instances can send changes to the sharding-receiver instances
                  setupSubscription(shardRoles.cousin, ContainerState::scheduled, ContainerState::none, SubscriptionNature::all);
                }
                break;
              }
            case DataStrategy::none:
              break;
          }
        }
      };

      switch (work.lifecycle)
      {
        case LifecycleOp::updateInPlace:
        case LifecycleOp::construct:
          {
            ContainerView *replacingContainer = nullptr;

            if (work.lifecycle == LifecycleOp::updateInPlace)
            {
              replacingContainer = work.oldContainer;
              replacingContainer->state = ContainerState::destroying;
              handleContainerStateChange(replacingContainer, false);
            }

            ContainerView *container = work.container;

            container->state = ContainerState::scheduled;
            container->remainingSubscriberCapacity = plan.minimumSubscriberCapacity;

            container->fragment = machine->getContainerFragment();
            container->setMeshAddress(container_network_subnet6, thisBrain->brainConfig.datacenterFragment, machine->fragment, container->fragment);
            container->addresses.clear();
            container->addresses.emplace_back(container->meshAddress, uint8_t(128));
            container->wormholes = plan.wormholes;
            container->whiteholes = plan.whiteholes;

            RoutableResourceLeaseOwner whiteholeLeaseOwner = routableResourceLeaseOwner();
            for (Whitehole& whitehole : container->whiteholes)
            {
              whitehole.hasAddress = false;
              whitehole.address = {};
              whitehole.sourcePort = 0;
              whitehole.bindingNonce = 0;

              if (resolveWhiteholeSourceAddressForScheduling(machine, whitehole, nullptr, container, &whiteholeLeaseOwner) == false || whitehole.hasAddress == false || allocateWhiteholeSourcePort(whitehole, &whiteholeLeaseOwner) == false || reserveWhiteholeAddressPortLease(whitehole, whiteholeLeaseOwner) == false)
              {
                whitehole.hasAddress = false;
                whitehole.address = {};
                whitehole.sourcePort = 0;
                whitehole.bindingNonce = 0;
              }
            }

            setupContainerServices(container);

            ApplicationConfig containerConfig = resourceConfigForContainer(container);
            container->runtime_nLogicalCores = uint16_t(applicationSharedCPUCoreHint(containerConfig));
            container->runtime_memoryMB = containerConfig.totalMemoryMB();
            container->runtime_storageMB = containerConfig.totalStorageMB();
            ContainerPlan containerPlan = container->generatePlan(plan, nShardGroups, &containerConfig);
            if (containerPlan.isStateful)
            {
              prodigyPopulateDefaultStatefulTopology(containerPlan.statefulTopology, containerPlan.shardGroup, containerPlan.config);
            }
            thisBrain->applyCredentialsToContainerPlan(plan, *container, containerPlan);
            container->hasCredentialBundle = containerPlan.hasCredentialBundle;
            container->credentialBundle = containerPlan.credentialBundle;
            container->hasPendingCredentialBundle = false;
            container->pendingCredentialBundle = {};
            NeuronContainerMetricPolicy metricPolicy = deriveNeuronMetricPolicyForDeployment(plan);

            NeuronContainerBootstrap bootstrap;
            bootstrap.plan = std::move(containerPlan);
            bootstrap.metricPolicy = metricPolicy;

            String buffer;
            BitseryEngine::serialize(buffer, bootstrap);

            uint128_t replaceContainerUUID = 0;
            if (replacingContainer)
            {
              replaceContainerUUID = replacingContainer->uuid;
            }

#if PRODIGY_DEBUG
            std::fprintf(stderr, "schedule spinContainer deploymentID=%llu appID=%u machinePrivate4=%u containerUUID=%llu replaceUUID=%llu state=%d waitingBefore=%llu\n",
                         (unsigned long long)plan.config.deploymentID(),
                         unsigned(plan.config.applicationID),
                         (machine ? unsigned(machine->private4) : 0u),
                         (unsigned long long)container->uuid,
                         (unsigned long long)replaceContainerUUID,
                         int(state),
                         (unsigned long long)waitingOnContainers.size());
#endif

            queueSend(machine, NeuronTopic::spinContainer, replaceContainerUUID, buffer);
            if (container->whiteholes.empty() == false)
            {
              thisBrain->sendNeuronOpenSwitchboardWhiteholes(container, container->whiteholes);
            }

            if (plan.config.type == ApplicationType::task)
            {
              thisBrain->noteTaskAttemptAssigned(plan, *container);
            }
            else
            {
              waitingOnContainers.insert_or_assign(container, ContainerState::healthy);
            }
            container->plannedWork = nullptr;
            if (replacingContainer)
            {
              replacingContainer->plannedWork = nullptr;
            }

            break;
          }
        case LifecycleOp::destruct:
          {
            // we get 1 container to destroy
            ContainerView *container = work.oldContainer;
            assert(container != nullptr && "LifecycleOp::destruct requires oldContainer");

            if (container->plannedWork)
            {
              cancelDeploymentWork(container->plannedWork);
            }

            ApplicationDeployment *destructionOwner = this;
            if (container->deploymentID != plan.config.deploymentID())
            {
              if (previous && previous->plan.config.deploymentID() == container->deploymentID && previous->containers.contains(container))
              {
                destructionOwner = previous;
              }
              else if (auto deploymentIt = thisBrain->deployments.find(container->deploymentID); deploymentIt != thisBrain->deployments.end() && deploymentIt->second)
              {
                destructionOwner = deploymentIt->second;
              }
            }

            container->destructionWaiterDeploymentID = plan.config.deploymentID();
            destructionOwner->destructContainer(container, false);

            queueSend(machine, NeuronTopic::killContainer, container->uuid);

            waitingOnContainers.insert_or_assign(container, ContainerState::destroyed);
            container->plannedWork = nullptr;

            break;
          }
        case LifecycleOp::none:
          break;
      }

      if constexpr (std::is_same_v<T, StatelessWork>)
      {
        if (work.ticket)
        {
          if (auto it = work.ticket->pendingCompactions.find(this); --it->second == 0)
          {
            work.ticket->pendingCompactions.erase(it);

            if (work.ticket->pendingCompactions.size() == 0)
            {
              if (work.ticket->waitingOnCompactions)
              {
                work.ticket->orchestrator->consumeSchedulingExecution();
              }
            }
          }
        }
      }
    };

    CoroutineStack *coro = new CoroutineStack();

    schedulingStack.execution = coro;

    if (waiter)
    {
      schedulingStack.waiters.push_back(waiter);
    }

    for (auto it = toSchedule.begin(); it != toSchedule.end(); it = toSchedule.erase(it))
    {
      DeploymentWork *workAnon = *it;
      currentlyExecutingWork = workAnon;
      if (StatelessWork *work = std::get_if<StatelessWork>(workAnon))
      {
        if (work->ticket && work->ticket->orchestrator == this)
        {
          if (work->ticket->pendingCompactions.size() > 0) // we need to wait for other deployments to complete compaction work for us before we can continue
          {
            waitingOnCompactions = true;
            work->ticket->waitingOnCompactions = true;
            nSuspended += 1;
            co_await coro->suspend();
            nSuspended -= 1;
          }

          // compactions complete
          waitingOnCompactions = false;
          delete work->ticket;
        }
        else
        {
          if (last != LifecycleOp::none && last != work->lifecycle)
          {
            // wait for confirmations
            nSuspended += 1;
            co_await coro->suspend();
            nSuspended -= 1;
          }

          executeWork(*work);
        }
      }
      else if (StatefulWork *work = std::get_if<StatefulWork>(workAnon))
      {
        // we always start with updates in place, then one or more of those isn't possible
        // we alternate between creation and destructions

        bool waitForConfirmation = false;
        switch (last)
        {
          case LifecycleOp::construct:
            {
              // Initial stateful bring-up can require multiple constructive siblings
              // to exist before any one replica becomes healthy. Launch the whole
              // constructive set, then wait on health after the queue drains.
              waitForConfirmation = (work->lifecycle != LifecycleOp::construct);
              break;
            }
          case LifecycleOp::updateInPlace:
            {
              waitForConfirmation = true;
              break;
            }
          case LifecycleOp::destruct:
          case LifecycleOp::none:
            {
              break;
            }
        }

        if (waitForConfirmation)
        {
          nSuspended += 1;
          co_await coro->suspend();
          nSuspended -= 1;
        }

        executeWork(*work);
      }

      currentlyExecutingWork = nullptr;
      workPool.relinquish(workAnon);
    }

    if (waitingOnContainers.size() > 0)
    {
#if PRODIGY_DEBUG
      std::fprintf(stderr, "schedule waiting deploymentID=%llu waitingOnContainers=%llu\n",
                   (unsigned long long)plan.config.deploymentID(),
                   (unsigned long long)waitingOnContainers.size());
#endif
      nSuspended += 1;
      co_await coro->suspend();
      nSuspended -= 1;
    }

    for (CoroutineStack *waiter : schedulingStack.waiters)
    {
      waiter->co_consume();
    }

    schedulingStack.waiters.clear();
    schedulingStack.execution = nullptr;
    if (consumingSchedulingExecution)
    {
      retiredSchedulingExecution = coro;
    }
    else
    {
      delete coro;
    }

    if (state == DeploymentState::deploying)
    {
      if (plan.config.type == ApplicationType::task)
      {
        thisBrain->pushSpinApplicationProgressToMothership(this, "task attempt dispatched"_ctv);
      }
      else
      {
        thisBrain->pushSpinApplicationProgressToMothership(this, "all containers are deployed and healthy"_ctv);
        thisBrain->spinApplicationFin(this);
      }
      setDeploymentRunning();
    }

    if (isDecommissioning())
    {
      rollForward();
    }
  }

  // map over machines, including potential compactions
  // this calculates a deployment of an application over a cluster, including transitioning from the last version(s) to this most recent
  void architect(CoroutineStack *coro, bool onlyMeasure, bool allowCompactionForScheduling = true, bool allowNewMachinesForScheduling = true)
  {
    if (plan.isStateful)
    {
      prodigyLogDeployHeapSnapshot(
          "architect-begin",
          plan.config.deploymentID(),
          plan.config.applicationID,
          toSchedule.size(),
          waitingOnContainers.size(),
          containers.size(),
          nShardGroups,
          nTargetBase,
          nDeployed(),
          nHealthy(),
          uint64_t(onlyMeasure),
          uint64_t(previous != nullptr));
    }

    Vector<uint32_t> shardsForCreation; // only stateful

    bytell_hash_map<Machine *, MachineResourcesDelta> initialMachineResources; // used when measuring to revert
    bytell_hash_map<Machine *, MachineResourcesDelta> deltasByMachine; // we can't add back deletion resources until after the container is destroyed
    bytell_hash_set<Machine *> deletedOnMachines;

    auto logInitialMachineResources = [&](Machine *machine) -> void {
      if (initialMachineResources.contains(machine) == false)
      {
        MachineResourcesDelta& resources = initialMachineResources[machine];
        resources.nLogicalCores = machine->nLogicalCores_available;
        resources.sharedCPUMillis = machine->sharedCPUMillis_available;
        resources.nMemoryMB = machine->memoryMB_available;
        resources.nStorageMB = machine->storageMB_available;
        resources.isolatedLogicalCoresCommitted = machine->isolatedLogicalCoresCommitted;
        resources.sharedCPUMillisCommitted = machine->sharedCPUMillisCommitted;
        resources.gpuMemoryMBs = machine->availableGPUMemoryMBs;
        for (uint32_t index : machine->availableGPUHardwareIndexes)
        {
          if (index < machine->hardware.gpus.size())
          {
            resources.gpuDevices.push_back(prodigyAssignedGPUDeviceFromHardware(machine->hardware.gpus[index]));
          }
        }
      }
    };

    bytell_hash_set<ContainerView *> containersToDestroy;
    if (previous && previous->containers.size() > 0)
    {
      containersToDestroy = previous->containers;
    }

    // by the time we get to architect, by the time this new deployment is deploying, all previous work from the last deployment has completed
    // so all previous containers are healthy

    // there's no point in even attempting in-place updates for stateless
    if (plan.isStateful)
    {
      if (nShardGroups > 0)
      {
        for (uint32_t cursor = nShardGroups; cursor > 0; cursor--)
        {
          uint32_t n = cursor - 1;

          // if this were called by evaluateAfterNewMaster, we might have some containers that exist
          uint32_t existing = containersByShardGroup[n].size();
          uint32_t desired = desiredReplicaCountForShardGroup(n);
          if (existing < desired)
          {
            shardsForCreation.insert(shardsForCreation.end(), desired - existing, n); // tail will be shard groups 0, so we can harvest from tail
          }
        }
      }

      if (containersToDestroy.size() > 0)
      {
        if (plan.stateful.allowUpdateInPlace) // even if moveConstructively were true, this would override that for any that can be done in place
        {
          for (auto it = containersToDestroy.begin(); it != containersToDestroy.end();)
          {
            ContainerView *container = *it;

            Machine *machine = container->machine;
            if (BrainBase::neuronControlStreamActive(machine) == false)
            {
              it++;
              continue;
            }

            if (nFitOnMachine(this, machine, 1) > 0)
            {
              MachineResourcesDelta& deltas = deltasByMachine[machine];
              prodigyApplyPlannedMachineScalarDelta(deltas, previous->plan.config, -1);
              prodigyAppendGPUMemoryMBs(deltas.gpuMemoryMBs, container->assignedGPUMemoryMBs);
              prodigyAppendAssignedGPUDevices(deltas.gpuDevices, container->assignedGPUDevices);

              if (onlyMeasure)
              {
                logInitialMachineResources(machine);
              }
              // these may temporarily go negative but it doesn't matter
              prodigyDebitMachineScalarResources(machine, plan.config, 1);

              nDeployedBase += 1;

              // we don't need to change countPerMachine, countPerRack or racksByShardGroup because they remain the same with an in-place update

              shardsForCreation.erase(std::find(shardsForCreation.begin(), shardsForCreation.end(), container->shardGroup));

              Vector<uint32_t> assignedGPUMemoryMBs = {};
              Vector<AssignedGPUDevice> assignedGPUDevices = {};
              bool assignedGPUs = prodigyTakeAssignedGPUsForScheduling(machine, nullptr, &deltas, plan.config, assignedGPUMemoryMBs, assignedGPUDevices);
              assert(assignedGPUs && "stateful update in place must reserve GPUs");
              scheduleStatefulUpdateInPlace(container, std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices));

              it = containersToDestroy.erase(it);

              continue;
            }

            it++;
          }
        }
      }
    }

    auto planDeletion = [&](ContainerView *container) -> DeploymentWork * {
      MachineResourcesDelta& deltas = deltasByMachine[container->machine];
      prodigyApplyPlannedMachineScalarDelta(deltas, previous->plan.config, -1);
      prodigyAppendGPUMemoryMBs(deltas.gpuMemoryMBs, container->assignedGPUMemoryMBs);
      prodigyAppendAssignedGPUDevices(deltas.gpuDevices, container->assignedGPUDevices);

      DeploymentWork *dwork = nullptr;

      if (plan.isStateful)
      {
        dwork = planStatefulDestruction(container);
      }
      else
      {
        dwork = planStatelessDestruction(container, "planDeletion");
      }

      deletedOnMachines.insert(container->machine);

      return dwork;
    };

    auto selectPlanStatelessDeletion = [&](void) -> DeploymentWork * { // only stateless uses this
      if (auto it = containersToDestroy.begin(); it != containersToDestroy.end())
      {
        ContainerView *container = *it;

        containersToDestroy.erase(it);

        if (previous->containers.contains(container))
        {
          return planDeletion(container);
        }
      }

      return nullptr;
    };

    auto selectPlanStatefulDeletion = [&](uint32_t shardGroup) -> DeploymentWork * {
      // if no container still exists of that shard group, the loop will eventually terminate
      for (auto it = containersToDestroy.begin(); it != containersToDestroy.end(); it++)
      {
        if (ContainerView *container = *it; container->shardGroup == shardGroup)
        {
          containersToDestroy.erase(it);

          if (previous->containers.contains(container))
          {
            return planDeletion(container);
          }
          else
          {
            break;
          }
        }
      }

      return nullptr;
    };

    if (nDeployed() < nTarget()) // it's possible we scheduled all the stateful updates in place
    {
      bool scheduleSurgeOnReserved = false;
      bool allowCompaction = allowCompactionForScheduling;
      bool allowNewMachines = (onlyMeasure == false && allowNewMachinesForScheduling);

      if (plan.isStateful)
      {
        for (const auto& [machine, ticket] : gatherMachinesForScheduling(coro, scheduleSurgeOnReserved, deltasByMachine, allowCompaction, allowNewMachines, [=, this](MachineTicket *ticket) -> void {
               ticket->shardGroups = shardsForCreation;
               buildPlacementTopologyEpochs(ticket->placementTopologyEpochs, shardsForCreation);
             },
                                                                         deletedOnMachines, onlyMeasure == false))
        {
          if (machine == nullptr)
          {
            continue;
          }
          if (prodigyMachineReadyForScheduling(machine) == false)
          {
            continue;
          }
          if (machine->lifetime == MachineLifetime::spot)
          {
            continue;
          }

          if (ticket == nullptr)
          {
            for (auto it = shardsForCreation.begin(); it != shardsForCreation.end();)
            {
              if (uint32_t shardGroup = *it; canPlaceReplicaForShardGroupOnRack(shardGroup, machine->rack))
              {
                ApplicationConfig schedulingConfig = statefulConstructionConfigForShardGroup(shardGroup);
                if (nFitOnMachine(this, machine, 1, deltasByMachine[machine], &schedulingConfig) > 0)
                {
                  it = shardsForCreation.erase(it);

                  nDeployedBase += 1;

                  countPerMachine[machine] += 1;
                  countPerRack[machine->rack] += 1;
                  racksByShardGroup[shardGroup].insert(machine->rack);

                  if (onlyMeasure)
                  {
                    logInitialMachineResources(machine);
                  }
                  prodigyDebitMachineScalarResources(machine, schedulingConfig, 1);

                  DeploymentWork *dwork = selectPlanStatefulDeletion(shardGroup);
                  Vector<uint32_t> assignedGPUMemoryMBs = {};
                  Vector<AssignedGPUDevice> assignedGPUDevices = {};
                  bool assignedGPUs = prodigyTakeAssignedGPUsForScheduling(machine, nullptr, &deltasByMachine[machine], schedulingConfig, assignedGPUMemoryMBs, assignedGPUDevices);
                  assert(assignedGPUs && "stateful construction must reserve GPUs");
                  DeploymentWork *cwork = planStatefulConstruction(machine, shardGroup, statefulWorkerTopologyUpgradeLocksShardGroup(shardGroup) ? statefulWorkerTopologyUpgradeTargetEpoch : 0, architectedStatefulConstructionDataStrategy(shardGroup), std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices));

                  scheduleConstructionDestruction(cwork, dwork);
                }
                else
                {
                  break;
                }
              }
              else
              {
                it++;
                continue;
              }
            }

            if (shardsForCreation.size() == 0)
            {
              break;
            }
          }
          else // ticket != nullptr so this machine is a new machine which we claimed on
          {
            for (uint32_t index = 0; index < ticket->shardGroups.size(); ++index)
            {
              uint32_t shardGroup = ticket->shardGroups[index];
              uint32_t topologyEpoch = placementTopologyEpochForIndex(ticket, index);
              ApplicationConfig schedulingConfig = statefulPlacementConfig(topologyEpoch);
              nDeployedBase += 1;

              DeploymentWork *dwork = selectPlanStatefulDeletion(shardGroup);
              Vector<uint32_t> assignedGPUMemoryMBs = {};
              Vector<AssignedGPUDevice> assignedGPUDevices = {};
              bool assignedGPUs = prodigyTakeAssignedGPUsForScheduling(machine, ticket, nullptr, schedulingConfig, assignedGPUMemoryMBs, assignedGPUDevices);
              assert(assignedGPUs && "claimed stateful construction must consume reserved GPUs");
              DeploymentWork *cwork = planStatefulConstruction(machine, shardGroup, topologyEpoch, architectedStatefulConstructionDataStrategy(shardGroup), std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices));

              scheduleConstructionDestruction(cwork, dwork);
            }
          }
        }
      }
      else
      {
        auto maxAllowed = [](uint32_t total, float ratio) -> uint32_t {
          if (total == 0 || ratio <= 0.0f)
          {
            return 0U;
          }

          double allowed = std::ceil(static_cast<double>(total) * static_cast<double>(ratio));
          if (allowed < 1.0)
          {
            allowed = 1.0;
          }
          if (allowed > static_cast<double>(UINT32_MAX))
          {
            allowed = static_cast<double>(UINT32_MAX);
          }
          return static_cast<uint32_t>(allowed);
        };

        uint32_t maxPerRack = maxAllowed(nTarget(), plan.stateless.maxPerRackRatio);
        uint32_t maxPerMachine = maxAllowed(nTarget(), plan.stateless.maxPerMachineRatio);

        bool scheduleSurgeOnReserved;

        for (const auto& [machine, ticket] : gatherMachinesForScheduling(coro, scheduleSurgeOnReserved, deltasByMachine, allowCompaction, allowNewMachines, [=](MachineTicket *ticket) -> void {
             },
                                                                         deletedOnMachines, onlyMeasure == false))
        {
          if (machine == nullptr)
          {
            continue;
          }
          if (prodigyMachineReadyForScheduling(machine) == false)
          {
            continue;
          }

          bool isBase;
          uint32_t nFit;

          if (ticket == nullptr)
          {
            uint32_t budget;

            // only scheduleSurgeOnReserved if we've already scheduled all the base instances onto durable machines but
            // still had some surge instances left unscheduled onto spot machines, and so am scheduling them onto durable machines
            // so we never scheduled base and surge at the same time here
            if (machine->lifetime == MachineLifetime::spot || scheduleSurgeOnReserved)
            {
              isBase = false;
              budget = nTargetSurge - nDeployedSurge;
            }
            else
            {
              isBase = true;
              budget = nTargetBase - nDeployedBase;
            }

            if (budget == 0)
            {
              break; // we loop by machine, so it's possible we've already scheduled all our base or surge
            }

            if (uint32_t machineBudget = maxPerMachine - countPerMachine.getIf(machine); machineBudget < budget)
            {
              budget = machineBudget;
            }
            if (uint32_t rackBudget = maxPerRack - countPerRack.getIf(machine->rack); rackBudget < budget)
            {
              budget = rackBudget;
            }

            if (budget == 0)
            {
              break; // we loop by machine, so it's possible we've already scheduled all our base or surge
            }

            // nFit doesn't accurately capture the true machine resources... but we could also be destructing
            // containers on machines that we already passed over... so only way i guess is to loop over
            // deltasByMachine at the end

            if (nFit = nFitOnMachine(this, machine, budget, deltasByMachine[machine]); nFit > 0)
            {
              countPerMachine[machine] += nFit;
              countPerRack[machine->rack] += nFit;

              if (onlyMeasure)
              {
                logInitialMachineResources(machine);
              }
              prodigyDebitMachineScalarResources(machine, plan.config, nFit);
            }
            else
            {
              continue;
            }
          }
          else // ticket != nullptr, so this is a new machine
          {
            nFit = ticket->nNow;
            isBase = (machine->lifetime != MachineLifetime::spot);
          }

          if (isBase)
          {
            nDeployedBase += nFit;
          }
          else
          {
            nDeployedSurge += nFit;
          }

          do
          {
            DeploymentWork *dwork = selectPlanStatelessDeletion();
            Vector<uint32_t> assignedGPUMemoryMBs = {};
            Vector<AssignedGPUDevice> assignedGPUDevices = {};
            bool assignedGPUs = prodigyTakeAssignedGPUsForScheduling(machine, ticket, (ticket ? nullptr : &deltasByMachine[machine]), plan.config, assignedGPUMemoryMBs, assignedGPUDevices);
            assert(assignedGPUs && "stateless construction must reserve GPUs");
            DeploymentWork *cwork = planStatelessConstruction(machine, (isBase ? ApplicationLifetime::base : ApplicationLifetime::surge), std::move(assignedGPUMemoryMBs), std::move(assignedGPUDevices));

            scheduleConstructionDestruction(cwork, dwork);

          } while (--nFit > 0);

          if (nDeployed() == nTarget())
          {
            break;
          }
        }
      }
    }

    if (onlyMeasure)
    {
      for (const auto& [machine, resources] : initialMachineResources)
      {
        machine->nLogicalCores_available = resources.nLogicalCores;
        machine->sharedCPUMillis_available = resources.sharedCPUMillis;
        machine->memoryMB_available = resources.nMemoryMB;
        machine->storageMB_available = resources.nStorageMB;
        machine->isolatedLogicalCoresCommitted = resources.isolatedLogicalCoresCommitted;
        machine->sharedCPUMillisCommitted = resources.sharedCPUMillisCommitted;
        machine->availableGPUMemoryMBs = resources.gpuMemoryMBs;
        machine->availableGPUHardwareIndexes.clear();
        for (const AssignedGPUDevice& device : resources.gpuDevices)
        {
          for (uint32_t index = 0; index < machine->hardware.gpus.size(); ++index)
          {
            if (machine->hardware.gpus[index].busAddress == device.busAddress)
            {
              machine->availableGPUHardwareIndexes.push_back(index);
              break;
            }
          }
        }
      }
    }

    if (plan.isStateful)
    {
      prodigyLogDeployHeapSnapshot(
          "architect-end",
          plan.config.deploymentID(),
          plan.config.applicationID,
          toSchedule.size(),
          waitingOnContainers.size(),
          containers.size(),
          nShardGroups,
          nTargetBase,
          nDeployed(),
          nHealthy(),
          uint64_t(onlyMeasure),
          uint64_t(waitingOnCompactions));
    }
  }

  // called on the head deployment after new master
  void evaluateAfterNewMaster(void)
  {
    state = DeploymentState::deploying;
    stateChangedAtMs = Time::now<TimeResolution::ms>();

    // set autoscale timers to check for scaling

    if (plan.isStateful)
    {
      nShardGroups = containersByShardGroup.size();
      nTargetBase = 0;
      for (uint32_t shardGroup = 0; shardGroup < nShardGroups; ++shardGroup)
      {
        nTargetBase += desiredReplicaCountForShardGroup(shardGroup);
      }
      nTargetSurge = 0;
      nTargetCanary = 0;
      nDeployedBase = 0;
      nDeployedCanary = 0;
      nDeployedSurge = 0;
      nHealthyBase = 0;
      nHealthyCanary = 0;
      nHealthySurge = 0;

      for (ContainerView *container : containers)
      {
        switch (container->lifetime)
        {
          case ApplicationLifetime::base:
            {
              nDeployedBase += 1;
              if (container->state == ContainerState::healthy)
              {
                nHealthyBase += 1;
              }
              break;
            }
          case ApplicationLifetime::surge:
            {
              nTargetSurge += 1;
              nDeployedSurge += 1;
              if (container->state == ContainerState::healthy)
              {
                nHealthySurge += 1;
              }
              break;
            }
          case ApplicationLifetime::canary:
            {
              nTargetCanary += 1;
              nDeployedCanary += 1;
              if (container->state == ContainerState::healthy)
              {
                nHealthyCanary += 1;
              }
              break;
            }
        }
      }
    }
    else
    {
      discardRecoveredStatelessContainersOnUnavailableHosts("evaluateAfterNewMaster");
      nTargetBase = plan.stateless.nBase;
      nTargetSurge = 0;
      nTargetCanary = 0;
      nDeployedBase = 0;
      nDeployedCanary = 0;
      nDeployedSurge = 0;
      nHealthyBase = 0;
      nHealthyCanary = 0;
      nHealthySurge = 0;

      // possible we lost some containers
      for (ContainerView *container : containers)
      {
        // the simplest thing to do is to just blindly reopen every wormwhole and
        // have the switchboard auto-reject by containerID for exiting holes
        thisBrain->sendNeuronOpenSwitchboardWormholes(container, plan.wormholes);
        if (container->whiteholes.empty() == false)
        {
          thisBrain->sendNeuronOpenSwitchboardWhiteholes(container, container->whiteholes);
        }

        switch (container->lifetime)
        {
          case ApplicationLifetime::base:
            {
              nDeployedBase += 1;
              if (container->state == ContainerState::healthy)
              {
                nHealthyBase += 1;
              }
              break;
            }
          case ApplicationLifetime::surge:
            {
              // maybe we had more surge containers and lost some... but this will give us a rough approximation... and any missing will be created upon next loadStress
              nTargetSurge += 1;
              nDeployedSurge += 1;
              if (container->state == ContainerState::healthy)
              {
                nHealthySurge += 1;
              }
              break;
            }
          case ApplicationLifetime::canary:
            {
              // assume it was successful and destroy it
              scheduleStatelessDestruction(container);
              break;
            }
        }
      }
    }

    // if master failed while transitoning deployment versions, architect will clean up any containers from previous deployment
    if (nDeployedBase < nTargetBase)
    {
      architect(nullptr, false, false, false);
    }

    // if move constructively it's possible we could have had all our base instances but have left 1 old instance?
    scheduleRemainingPreviousStatelessDestruction("evaluateAfterNewMaster");

    if (toSchedule.size() > 0)
    {
      schedule(nullptr);
    }
    else
    {
      setDeploymentRunning();
    }
  }

  // might be dangerous to expose this as an option...
  void destroy(void)
  {
    clearStatefulWorkerTopologyUpgradeOperation();
    state = DeploymentState::decommissioning;
    stateChangedAtMs = Time::now<TimeResolution::ms>();

    if (containers.size() > 0)
    {
      for (ContainerView *container : containers)
      {
        if (plan.isStateful)
        {
          scheduleStatefulDestruction(container);
        }
        else
        {
          scheduleStatelessDestruction(container);
        }
      }

      CoroutineStack *coro = new CoroutineStack();

      co_await coro->suspendUsRunThis([&](void) -> void {
        schedule(coro);
      });

      delete coro;
    }

    thisBrain->deploymentsByApp.erase(plan.config.applicationID);
    thisBrain->releaseRoutableResourceLeasesForDeployment(plan.config.deploymentID());
    if (auto it = thisBrain->deployments.find(plan.config.deploymentID()); it != thisBrain->deployments.end())
    {
      if (it->second == this)
      {
        thisBrain->deployments.erase(it);
      }
    }

    // free this deployment object
    delete this;
  }

  void rollForward(void)
  {
    if (next && next->plan.canaryCount == 0)
    {
      beginDecommissioningForRollForward();
    }

    next->deploy();
  }

  void deploy(void)
  {
    if (plan.isStateful)
    {
      prodigyLogDeployHeapSnapshot(
          "deploy-begin",
          plan.config.deploymentID(),
          plan.config.applicationID,
          toSchedule.size(),
          waitingOnContainers.size(),
          containers.size(),
          nShardGroups,
          nTargetBase,
          nDeployed(),
          nHealthy(),
          uint64_t(state),
          uint64_t(previous != nullptr));
    }

    CoroutineStack *coro = new CoroutineStack();

    calculateTargets();

    // Always run canaries first if configured, regardless of previous deployment state,
    // and for both stateless and stateful applications.
    if (plan.canaryCount > 0)
    {
      thisBrain->pushSpinApplicationProgressToMothership(this, "deploying canaries"_ctv);

      co_await coro->suspendUsRunThis([&](void) -> void {
        nSuspended += 1;
        deployCanaries(coro, plan.canaryCount);
        nSuspended -= 1;
      });

      if (state == DeploymentState::failed)
      {
        delete coro;
        co_return;
      }
    }

    state = DeploymentState::deploying;
    stateChangedAtMs = Time::now<TimeResolution::ms>();

    architect(coro, false);

    delete coro;

    scheduleRemainingPreviousStatelessDestruction("deploy");

    if (plan.isStateful)
    {
#if PRODIGY_DEBUG
      std::fprintf(stderr, "deploy post-architect deploymentID=%llu nDeployed=%u nTarget=%u toSchedule=%llu waitingOnContainers=%llu\n",
                   (unsigned long long)plan.config.deploymentID(),
                   unsigned(nDeployed()),
                   unsigned(nTarget()),
                   (unsigned long long)toSchedule.size(),
                   (unsigned long long)waitingOnContainers.size());
#endif
      prodigyLogDeployHeapSnapshot(
          "deploy-post-architect",
          plan.config.deploymentID(),
          plan.config.applicationID,
          toSchedule.size(),
          waitingOnContainers.size(),
          containers.size(),
          nShardGroups,
          nTargetBase,
          nDeployed(),
          nHealthy(),
          uint64_t(state),
          uint64_t(schedulingStack.execution != nullptr));
    }

    thisBrain->pushSpinApplicationProgressToMothership(this, "architected instances onto machines. now beginning to schedule."_ctv);

    schedule(nullptr);

    if (plan.isStateful)
    {
#if PRODIGY_DEBUG
      std::fprintf(stderr, "deploy post-schedule deploymentID=%llu state=%u toSchedule=%llu waitingOnContainers=%llu execution=%p\n",
                   (unsigned long long)plan.config.deploymentID(),
                   unsigned(state),
                   (unsigned long long)toSchedule.size(),
                   (unsigned long long)waitingOnContainers.size(),
                   (void *)schedulingStack.execution);
#endif
      prodigyLogDeployHeapSnapshot(
          "deploy-post-schedule",
          plan.config.deploymentID(),
          plan.config.applicationID,
          toSchedule.size(),
          waitingOnContainers.size(),
          containers.size(),
          nShardGroups,
          nTargetBase,
          nDeployed(),
          nHealthy(),
          uint64_t(state),
          uint64_t(schedulingStack.execution != nullptr));
    }
  }

  uint32_t measure(void) // we could theoretically schedule this many instances
  {
    struct ContainerMeasureSnapshot {
      ContainerView *container = nullptr;
      ContainerState state = ContainerState::none;
      DeploymentWork *plannedWork = nullptr;
    };

    Vector<ContainerView *> originalContainers = {};
    bytell_hash_set<ContainerView *> originalContainerSet = {};
    Vector<ContainerMeasureSnapshot> originalContainerSnapshots = {};
    Vector<ContainerMeasureSnapshot> previousContainerSnapshots = {};
    Vector<DeploymentWork *> originalScheduledWork = toSchedule;
    auto originalWaitingOnContainers = waitingOnContainers;
    auto originalCountPerMachine = countPerMachine;
    auto originalCountPerRack = countPerRack;
    auto originalMasterForShardGroup = masterForShardGroup;
    auto originalRacksByShardGroup = racksByShardGroup;
    bool originalDeployingNewShardGroup = deployingNewShardGroup;
    bool originalWaitingOnCompactions = waitingOnCompactions;

    for (ContainerView *container : containers)
    {
      originalContainers.push_back(container);
      originalContainerSet.insert(container);
      originalContainerSnapshots.push_back(ContainerMeasureSnapshot {
          .container = container,
          .state = container->state,
          .plannedWork = container->plannedWork});
    }

    if (previous)
    {
      for (ContainerView *container : previous->containers)
      {
        previousContainerSnapshots.push_back(ContainerMeasureSnapshot {
            .container = container,
            .state = container->state,
            .plannedWork = container->plannedWork});
      }
    }

    // Seed stateful/stateless targets before overprovisioned measuring.
    calculateTargets();

    nTargetBase = UINT32_MAX;

    architect(nullptr, true);

    uint32_t nFit = nDeployed();

    bytell_hash_set<DeploymentWork *> originalScheduledWorkSet = {};
    for (DeploymentWork *work : originalScheduledWork)
    {
      if (work != nullptr)
      {
        originalScheduledWorkSet.insert(work);
      }
    }

    bytell_hash_set<DeploymentWork *> measureWorks = {};
    for (DeploymentWork *work : toSchedule)
    {
      if (work != nullptr && originalScheduledWorkSet.contains(work) == false && measureWorks.contains(work) == false)
      {
        measureWorks.insert(work);
        workPool.relinquish(work);
      }
    }

    Vector<ContainerView *> createdContainers = {};
    for (ContainerView *container : containers)
    {
      if (container != nullptr && originalContainerSet.contains(container) == false)
      {
        createdContainers.push_back(container);
      }
    }

    for (ContainerView *container : createdContainers)
    {
      if (container->machine != nullptr)
      {
        container->machine->removeContainerIndexEntry(container->deploymentID, container);
      }

      thisBrain->containers.erase(container->uuid);
      delete container;
    }

    for (const ContainerMeasureSnapshot& snapshot : originalContainerSnapshots)
    {
      if (snapshot.container)
      {
        snapshot.container->state = snapshot.state;
        snapshot.container->plannedWork = snapshot.plannedWork;
      }
    }

    for (const ContainerMeasureSnapshot& snapshot : previousContainerSnapshots)
    {
      if (snapshot.container)
      {
        snapshot.container->state = snapshot.state;
        snapshot.container->plannedWork = snapshot.plannedWork;
      }
    }

    containers.clear();
    for (ContainerView *container : originalContainers)
    {
      containers.insert(container);
    }

    containersByShardGroup.clear();
    for (ContainerView *container : originalContainers)
    {
      if (container && container->isStateful)
      {
        containersByShardGroup.insert(container->shardGroup, container);
      }
    }

    masterForShardGroup = originalMasterForShardGroup;
    waitingOnContainers = originalWaitingOnContainers;
    countPerMachine = originalCountPerMachine;
    countPerRack = originalCountPerRack;
    racksByShardGroup = originalRacksByShardGroup;
    toSchedule = originalScheduledWork;
    deployingNewShardGroup = originalDeployingNewShardGroup;
    waitingOnCompactions = originalWaitingOnCompactions;

    nTargetBase = 0;
    nTargetSurge = 0;
    nTargetCanary = 0;

    nDeployedBase = 0;
    nDeployedCanary = 0;
    nDeployedSurge = 0;
    nHealthyBase = 0;
    nHealthyCanary = 0;
    nHealthySurge = 0;

    calculateTargets();

    return nFit;
  }

  DeploymentStatusReport generateReport(void)
  {
    DeploymentStatusReport report {};

    report.versionID = plan.config.versionID;

    report.state = state;
    report.stateSinceMs = stateChangedAtMs;

    report.isStateful = plan.isStateful;
    report.nShardGroups = nShardGroups;

    report.nTarget = nTarget();
    report.nTargetBase = nTargetBase;
    report.nTargetSurge = nTargetSurge;

    report.nDeployed = nDeployed();
    report.nDeployedBase = nDeployedBase;
    report.nDeployedSurge = nDeployedSurge;
    report.nDeployedCanary = nDeployedCanary;

    report.nHealthy = nHealthy();
    report.nHealthyCanary = nHealthyCanary;
    report.nHealthyBase = nHealthyBase;
    report.nHealthySurge = nHealthySurge;
    report.nCrashes = nCrashes;

    if (failureReports.size() <= maxFailureReports)
    {
      report.failureReports = failureReports;
    }
    else
    {
      uint32_t start = static_cast<uint32_t>(failureReports.size() - maxFailureReports);
      for (uint32_t index = start; index < failureReports.size(); index++)
      {
        report.failureReports.push_back(failureReports[index]);
      }
    }
    report.lastScalerStates = lastScalerStates;

    // Per-container runtime resources. Fall back to deployment plan resources
    // when runtime uploads are not populated yet in this reporting window.
    for (ContainerView *cv : containers)
    {
      uint16_t runtimeCores = cv->runtime_nLogicalCores;
      uint32_t runtimeMemoryMB = cv->runtime_memoryMB;
      uint32_t runtimeStorageMB = cv->runtime_storageMB;

      if (runtimeCores == 0)
      {
        runtimeCores = uint16_t(applicationSharedCPUCoreHint(plan.config));
      }

      if (runtimeMemoryMB == 0)
      {
        runtimeMemoryMB = plan.config.totalMemoryMB();
      }

      if (runtimeStorageMB == 0)
      {
        runtimeStorageMB = plan.config.totalStorageMB();
      }

      report.containerRuntimes.emplace_back(cv->uuid, runtimeCores, runtimeMemoryMB, runtimeStorageMB);
    }

    return report;
  }
};
