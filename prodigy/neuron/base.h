#include <prodigy/containerstore.h>
#include <prodigy/artifact.io.h>
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
  networkCleanup,
  bgpIPv6ReadinessRetry
};

// Cloud BGP cannot be configured until the kernel has installed a usable
// global IPv6 address. Keep this deliberately finite: 1/2/4/8/16/32-second
// retries followed by nine one-minute retries cover the ten-minute provider
// provisioning window without turning an unavailable account into an
// unbounded background poll.
constexpr static uint32_t prodigyBGPIPv6ReadinessRetryMaximumAttempts = 15;
constexpr static uint32_t prodigyBGPIPv6ReadinessRetryInitialDelayMs = 1'000;
constexpr static uint32_t prodigyBGPIPv6ReadinessRetryMaximumDelayMs = 60'000;

static inline bool prodigyBGPIPv6ReadinessRetryEligible(
    bool providerReady, const NeuronBGPConfig& config,
    NeuronBGPConfigurationRetry configurationRetry, uint32_t attempts)
{
  return providerReady && config.enabled == false &&
         configurationRetry == NeuronBGPConfigurationRetry::waitForPublicIPv6 &&
         attempts < prodigyBGPIPv6ReadinessRetryMaximumAttempts;
}

static inline uint32_t prodigyBGPIPv6ReadinessRetryDelayMs(uint32_t attempts)
{
  // The caller checks the attempt cap; retain the delay cap for robustness.
  if (attempts >= 6)
  {
    return prodigyBGPIPv6ReadinessRetryMaximumDelayMs;
  }
  return prodigyBGPIPv6ReadinessRetryInitialDelayMs << attempts;
}

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
    if (admissionGeneration != containerLaunchControlGeneration)
    {
      // The old worker owns its private cgroup/rootfs until its scope has
      // completed cleanup.  Keep the UUID reserved after that drain so an
      // authenticated replacement replay can start only once it is safe.
      found->second = 0;
      pendingContainerLaunchDrained(uuid);
      return true;
    }
    pendingContainerLaunchPlans.erase(uuid);
    pendingContainerLaunchGenerations.erase(found);
    return true;
  }

  bool isPendingContainerLaunch(uint128_t uuid) const
  {
    return pendingContainerLaunchPlans.contains(uuid);
  }

  bool pendingContainerLaunchIsDrained(uint128_t uuid) const
  {
    auto found = pendingContainerLaunchGenerations.find(uuid);
    return found != pendingContainerLaunchGenerations.end() && found->second == 0 &&
           pendingContainerLaunchPlans.contains(uuid);
  }

  bool rebindPendingContainerLaunchForStateUploadRestore(uint128_t uuid,
                                                         uint64_t admissionGeneration)
  {
    auto found = pendingContainerLaunchGenerations.find(uuid);
    if (admissionGeneration == 0 || found == pendingContainerLaunchGenerations.end() ||
        found->second != admissionGeneration || pendingContainerLaunchPlans.contains(uuid) == false)
    {
      return false;
    }
    found->second = containerLaunchControlGeneration;
    return true;
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

  void resetContainerLaunchControlGeneration(bool preservePendingLaunches = false)
  {
    containerLaunchControlGeneration += 1;
    if (containerLaunchControlGeneration == 0)
    {
      containerLaunchControlGeneration = 1;
    }
    if (preservePendingLaunches == false)
    {
      pendingContainerLaunchPlans.clear();
      pendingContainerLaunchGenerations.clear();
      terminalContainerLaunchUUIDs.clear();
    }
  }

  // The old worker has drained its cgroup/rootfs cleanup.  Only the
  // authenticated replacement state-upload path may release this reservation
  // and issue the canonical replay.
  bool handoffDrainedPendingContainerLaunchForAuthenticatedReplay(uint128_t uuid)
  {
    auto found = pendingContainerLaunchGenerations.find(uuid);
    if (found == pendingContainerLaunchGenerations.end() || found->second != 0 ||
        terminalContainerLaunchUUIDs.contains(uuid))
    {
      return false;
    }
    pendingContainerLaunchPlans.erase(uuid);
    pendingContainerLaunchGenerations.erase(found);
    return true;
  }

  virtual void pushContainer(Container *container) = 0;
  virtual void popContainer(Container *container) = 0;
  virtual void pendingContainerLaunchDrained(uint128_t) {}
  // Called in the isolated child immediately before exec. Secrets are resolved
  // from the live, exact-scope Vault cache, never from a serialized plan.
  virtual bool prepareCrossClusterMasqueGatewayExec(const ContainerPlan&,
      Vector<String>&, Vector<int32_t>&, String *failure = nullptr)
  {
    if (failure) failure->assign("MASQUE launch credentials are unavailable"_ctv);
    return false;
  }
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

  virtual ProdigyArtifactIO *containerArtifactIO(void)
  {
    return nullptr;
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
