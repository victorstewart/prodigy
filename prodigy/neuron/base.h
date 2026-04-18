#include <prodigy/containerstore.h>
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
   resourceDeltaGrace
};

class Container;
class SwitchboardOverlayRoutingConfig;

class NeuronBase {
public:

   uint128_t uuid;
	uint32_t lcoreCount;
   uint16_t lcores[256]; // 0 = available, else count of consequentialy taken cores
   // Topology and placement helpers
   uint16_t lcoreNode[256];     // NUMA node id per lcore
   uint16_t lcoreSibling[256];  // SMT sibling lcore id (or self if unknown)
   uint16_t nodeCount = 1;      // number of NUMA nodes detected
   uint16_t lastPlacePerNode[16] = {0}; // Next-Fit rotation per node (up to 16 nodes)
   double perCoreUtil[256] = {0.0};     // rolling avg per-core utilization estimate
   double nodeLoad[16] = {0.0};         // rolling avg per-node load
   bytell_hash_map<uint128_t, Container *> containers;
   bytell_hash_map<pid_t, Container *> containerByPid;
   bytell_hash_set<uint128_t> statefulCrashed; // waiting on word from the brain what to do with the data

   EthDevice eth;
   uint32_t configuredInterContainerMTU = 0;
   BPFProgram *tcx_ingress_program = nullptr;
   BPFProgram *tcx_egress_program = nullptr;
   struct local_container_subnet6 lcsubnet6;

   String metro;
   IPAddress private4;
   IPAddress gateway4;

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

   virtual void pushContainer(Container *container) = 0;
   virtual void popContainer(Container *container) = 0;
   virtual bool ensureHostNetworkingReady(String *failureReport = nullptr) = 0;

   virtual void downloadContainer(CoroutineStack *coro, uint64_t deploymentID) = 0;

   virtual void queueContainerKillAck(uint128_t containerUUID)
   {
      (void)containerUUID;
   }

   virtual void refreshContainerSwitchboardWormholes(Container *container)
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
};

inline NeuronBase *thisNeuron = nullptr;
