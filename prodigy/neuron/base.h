#include <prodigy/containerstore.h>
#include <prodigy/container.device.map.h>
#include <prodigy/iaas/iaas.h>
#include <prodigy/machine.hardware.types.h>
#include <prodigy/runtime.environment.h>
#include <ebpf/program.h>
#include <ebpf/common/structs.h>

#pragma once

enum class NeuronTimeoutFlags : uint64_t {

  canceled = 0,
  killContainer,
  logTick,
  logGC,
  preemptCheck,
  restartContainer,
  metricsTick,
  walSync,
  resourceDeltaGrace,
  networkCleanup
};

class Container;
class ContainerPlan;
class TaskTermination;
class SwitchboardOverlayRoutingConfig;

class NeuronBase {
public:

  uint128_t uuid;
  uint32_t lcoreCount;
  uint16_t lcores[256]; // 0 = available, else count of consequentialy taken cores
  // Topology and placement helpers
  uint16_t lcoreNode[256]; // NUMA node id per lcore
  uint16_t lcoreSibling[256]; // SMT sibling lcore id (or self if unknown)
  uint16_t nodeCount = 1; // number of NUMA nodes detected
  uint16_t lastPlacePerNode[16] = {0}; // Next-Fit rotation per node (up to 16 nodes)
  double perCoreUtil[256] = {0.0}; // rolling avg per-core utilization estimate
  double nodeLoad[16] = {0.0}; // rolling avg per-node load
  bytell_hash_map<uint128_t, Container *> containers;
  // A spin coroutine can await its artifact before pushContainer publishes a
  // live Container. Preserve the canonical UUID and plan across that gap.
  bytell_hash_map<uint128_t, ContainerPlan> pendingContainerLaunchPlans;
  bytell_hash_map<uint128_t, uint64_t> pendingContainerLaunchGenerations;
  // A terminal lifecycle decision can overtake an already queued spin frame.
  // Keep that UUID retired for the current Brain-control generation so the
  // stale frame cannot publish an owner after Brain removes its canonical view.
  constexpr static uint32_t maximumTerminalContainerLaunchUUIDs = 4096;
  bytell_hash_set<uint128_t> terminalContainerLaunchUUIDs;
  uint64_t containerLaunchControlGeneration = 1;

  bytell_hash_map<uint128_t, Container *> quarantinedContainerNetworks;
  bytell_hash_map<pid_t, Container *> containerByPid;
  bytell_hash_set<uint128_t> statefulCrashed; // waiting on word from the brain what to do with the data

  EthDevice eth;
  uint32_t configuredInterContainerMTU = 0;
  bool configuredFakeIpv4Boundary = false;
  BPFProgram *tcx_ingress_program = nullptr;
  BPFProgram *tcx_egress_program = nullptr;
  ProdigyContainerDeviceMapCoordinator containerDeviceMaps;
  TimeoutPacket containerNetworkCleanupTick;
  bool containerNetworkCleanupTickQueued = false;
  struct local_container_subnet6 lcsubnet6 = {};

  String metro;
  IPAddress private4;
  IPAddress gateway4;
  String kernel;
  String osID;
  String osVersionID;
  int64_t bootTimeMs = 0;

  uint8_t datacenterUniqueTag(void)
  {
    return lcsubnet6.dpfx;
  }

  uint32_t desiredInterContainerMTU(void) const
  {
    return configuredInterContainerMTU > 0 ? configuredInterContainerMTU : eth.mtu;
  }

  uint32_t controlPlaneTCPMaxSegmentSize(int family) const
  {
    return prodigyTCPMaxSegmentSizeForMTU(desiredInterContainerMTU(), family);
  }

  bool haveFragments(void)
  {
    return (lcsubnet6.dpfx != 0);
  }

  IPPrefix generateAddress(const struct container_network_subnet6_prefix& subnet, uint8_t fragment, uint8_t cidr)
  {
    IPPrefix address;
    address.cidr = cidr;
    address.network.is6 = true;
    memcpy(address.network.v6, subnet.value, 11);
    memcpy(address.network.v6 + 11, &lcsubnet6.dpfx, 1);
    memcpy(address.network.v6 + 12, lcsubnet6.mpfx, 3);
    memcpy(address.network.v6 + 15, &fragment, 1);

    return address;
  }

  uint64_t beginPendingContainerLaunch(const ContainerPlan& plan)
  {
    if (plan.uuid == 0 || terminalContainerLaunchUUIDs.contains(plan.uuid) ||
        containers.contains(plan.uuid) || pendingContainerLaunchPlans.contains(plan.uuid))
    {
      return 0;
    }
    pendingContainerLaunchPlans.insert_or_assign(plan.uuid, plan);
    pendingContainerLaunchGenerations.insert_or_assign(plan.uuid, containerLaunchControlGeneration);
    return containerLaunchControlGeneration;
  }

  bool finishPendingContainerLaunch(uint128_t uuid, uint64_t admissionGeneration)
  {
    auto found = pendingContainerLaunchGenerations.find(uuid);
    if (admissionGeneration == 0 || found == pendingContainerLaunchGenerations.end() ||
        found->second != admissionGeneration)
    {
      return false;
    }
    pendingContainerLaunchPlans.erase(uuid);
    pendingContainerLaunchGenerations.erase(found);
    return true;
  }

  bool isPendingContainerLaunch(uint128_t uuid) const
  {
    return pendingContainerLaunchPlans.contains(uuid);
  }

  bool pendingContainerLaunchIsCurrent(uint128_t uuid, uint64_t admissionGeneration) const
  {
    auto found = pendingContainerLaunchGenerations.find(uuid);
    return admissionGeneration != 0 && found != pendingContainerLaunchGenerations.end() &&
           found->second == admissionGeneration &&
           admissionGeneration == containerLaunchControlGeneration &&
           pendingContainerLaunchPlans.contains(uuid) &&
           terminalContainerLaunchUUIDs.contains(uuid) == false;
  }

  bool retireContainerLaunch(uint128_t uuid)
  {
    if (uuid == 0)
    {
      return false;
    }
    if (terminalContainerLaunchUUIDs.contains(uuid))
    {
      return true;
    }
    if (terminalContainerLaunchUUIDs.size() >= maximumTerminalContainerLaunchUUIDs)
    {
      return false;
    }
    terminalContainerLaunchUUIDs.insert(uuid);
    return true;
  }

  bool isContainerLaunchRetired(uint128_t uuid) const
  {
    return terminalContainerLaunchUUIDs.contains(uuid);
  }

  void resetContainerLaunchControlGeneration(void)
  {
    containerLaunchControlGeneration += 1;
    if (containerLaunchControlGeneration == 0)
    {
      containerLaunchControlGeneration = 1;
    }
    pendingContainerLaunchPlans.clear();
    pendingContainerLaunchGenerations.clear();
    terminalContainerLaunchUUIDs.clear();
  }

  virtual void pushContainer(Container *container) = 0;
  virtual void popContainer(Container *container) = 0;
  virtual bool ensureHostNetworkingReady(String *failureReport = nullptr) = 0;

  virtual void downloadContainer(CoroutineStack *coro, uint64_t deploymentID) = 0;

  virtual void queueContainerKillAck(uint128_t containerUUID)
  {
    (void)containerUUID;
  }

  virtual void reportContainerFailed(uint128_t containerUUID, int64_t failureTimeMs, int terminalSignal, const String& crashReport, bool restart)
  {
    (void)containerUUID;
    (void)failureTimeMs;
    (void)terminalSignal;
    (void)crashReport;
    (void)restart;
  }

  virtual bool prepareTaskAttemptLaunch(const ContainerPlan& plan, bool& skipLaunch, String *failureReport = nullptr)
  {
    (void)plan;
    (void)failureReport;
    skipLaunch = false;
    return true;
  }

  virtual void noteTaskAttemptRunning(const ContainerPlan& plan)
  {
    (void)plan;
  }

  virtual bool noteTaskAttemptTerminal(const ContainerPlan& plan, const TaskTermination& termination)
  {
    (void)plan;
    (void)termination;
    return true;
  }

  virtual void reportTaskAttemptTerminal(uint64_t deploymentID, uint32_t attemptNumber, uint128_t containerUUID, const TaskTermination& termination)
  {
    (void)deploymentID;
    (void)attemptNumber;
    (void)containerUUID;
    (void)termination;
  }

  virtual void refreshContainerSwitchboardWormholes(Container *container)
  {
    (void)container;
  }

  virtual void openWhiteholesForLocalContainer(uint8_t fragment, const Vector<Whitehole>& whiteholes)
  {
    (void)fragment;
    (void)whiteholes;
  }

  virtual void closeWhiteholesForLocalContainer(uint8_t fragment)
  {
    (void)fragment;
  }

  virtual void syncWhiteholeBindingsForContainerPeer(Container *container)
  {
    (void)container;
  }

  virtual void syncContainerSwitchboardRuntime(Container *container)
  {
    (void)container;
  }

  virtual const SwitchboardOverlayRoutingConfig *overlayRoutingConfigForContainerNetworking(void) const
  {
    return nullptr;
  }

  virtual const MachineHardwareProfile *latestHardwareProfileIfReady(void) const
  {
    return nullptr;
  }

  virtual void ensureDeferredHardwareInventoryProgress(void)
  {
  }

  virtual bool quiesceArtifactIOForBundleExec(void)
  {
    return true;
  }

  // The Neuron computes this from the installed bundle in its ArtifactIO
  // worker before it registers with Brain.  Consumers may only observe the
  // ready cached attestation; they must never trigger filesystem work here.
  virtual const String *readyInstalledBundleDigest(void) const
  {
    return nullptr;
  }

  // A base-only Neuron implementation cannot prove that its live containers
  // have no control operations.  Block bundle exec until it has none.
  virtual bool quiesceContainerControlSocketsForBundleExec(void)
  {
    return containers.empty();
  }
};

inline NeuronBase *thisNeuron = nullptr;
