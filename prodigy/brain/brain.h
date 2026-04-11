#include <cpp-sort/adapters/verge_adapter.h>
#include <services/debug.h>
#include <cpp-sort/sorters/ska_sorter.h>
#include <ifaddrs.h>
#include <macros/time.h>
#include <memory>
#include <net/if.h>

static inline cppsort::verge_adapter<cppsort::ska_sorter> sorter;

#include <services/time.h>
#include <services/bitsery.h>
#include <services/filesystem.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/socket.h>
#include <networking/pool.h>
#include <networking/stream.h>
#include <networking/message.h>
#include <networking/ring.h>
#include <networking/reconnector.h>

#include <prodigy/bootstrap.config.h>
#include <prodigy/bundle.artifact.h>
#include <prodigy/brain.reachability.h>
#include <prodigy/cluster.bootstrap.h>
#include <prodigy/cluster.machine.helpers.h>
#include <prodigy/ingress.validation.h>
#include <prodigy/routable.address.helpers.h>
#include <prodigy/remote.bootstrap.h>
#include <prodigy/brain/timing.knobs.h>
#include <prodigy/brain/rack.h>
#include <prodigy/brain/machine.h>

#include <prodigy/brain/base.h>

#include <prodigy/brain/mesh.node.h>
#include <prodigy/brain/mesh.h>

#include <prodigy/brain/containerviews.h>

#include <prodigy/brain/deployments.h>

#include <prodigy/metro.networkmonitor.h>
#include <prodigy/memfd.blob.h>
#include <prodigy/wire.h>
#include <services/vault.h>

#pragma once

#ifndef NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE
#define NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE 0
#endif

enum class BrainTimeoutFlags : uint64_t {

	canceled = 0,
	updateOSWakeup,
	ignition,
	hardRebootedMachine,
	brainMissing,
	softEscalationCheck,
	transitionStuck,
	performHardReboot,
	postIgnitionRecovery,
	spotDecomissionChecker
};

inline void BrainBase::sendNeuronSwitchboardRoutableSubnets(void)
{
   String serializedSubnets;
   BitseryEngine::serialize(serializedSubnets, brainConfig.distributableExternalSubnets);

   for (Machine *machine : machines)
   {
      if (neuronControlStreamActive(machine) == false)
      {
         continue;
      }

      Message::construct(machine->neuron.wBuffer, NeuronTopic::configureSwitchboardRoutableSubnets, serializedSubnets);
      Ring::queueSend(&machine->neuron);
   }
}

inline void BrainBase::buildHostedSwitchboardIngressPrefixes(Machine *machine, Vector<IPPrefix>& prefixes) const
{
   prefixes.clear();
   if (machine == nullptr || machine->uuid == 0)
   {
      return;
   }

   auto appendPrefixIfMissing = [&] (const IPPrefix& candidate) -> void {

      for (const IPPrefix& existing : prefixes)
      {
         if (existing.equals(candidate))
         {
            return;
         }
      }

      prefixes.push_back(candidate);
   };

   for (const RegisteredRoutableAddress& address : brainConfig.routableAddresses)
   {
      if (address.machineUUID != machine->uuid || address.address.isNull())
      {
         continue;
      }

      IPPrefix prefix = {};
      if (makeHostedIngressPrefixForAddress(address.address, prefix) == false)
      {
         continue;
      }

      appendPrefixIfMissing(prefix);
   }

}

inline bool BrainBase::whiteholeTargetsNeuronMachine(ContainerView *container, Machine *targetMachine, const Whitehole& whitehole) const
{
   (void)whitehole;
   if (container == nullptr || targetMachine == nullptr)
   {
      return false;
   }

   return container->machine == targetMachine;
}

inline void BrainBase::collectWhiteholesForNeuronMachine(ContainerView *container, Machine *targetMachine, const Vector<Whitehole>& sourceWhiteholes, Vector<Whitehole>& whiteholes) const
{
   whiteholes.clear();
   if (container == nullptr || targetMachine == nullptr)
   {
      return;
   }

   for (const Whitehole& whitehole : sourceWhiteholes)
   {
      if (whitehole.hasAddress == false || whitehole.address.isNull() || whitehole.sourcePort == 0 || whitehole.bindingNonce == 0)
      {
         continue;
      }

      if (whiteholeTargetsNeuronMachine(container, targetMachine, whitehole) == false)
      {
         continue;
      }

      whiteholes.push_back(whitehole);
   }
}

inline void BrainBase::sendNeuronSwitchboardHostedIngressPrefixes(Machine *machine)
{
   if (neuronControlStreamActive(machine) == false)
   {
      return;
   }

   Vector<IPPrefix> prefixes = {};
   buildHostedSwitchboardIngressPrefixes(machine, prefixes);

   String serializedPrefixes = {};
   BitseryEngine::serialize(serializedPrefixes, prefixes);
   Message::construct(machine->neuron.wBuffer, NeuronTopic::configureSwitchboardHostedIngressPrefixes, serializedPrefixes);
   Ring::queueSend(&machine->neuron);
}

inline void BrainBase::sendNeuronSwitchboardHostedIngressPrefixes(void)
{
   for (Machine *machine : machines)
   {
      if (machine == nullptr)
      {
         continue;
      }

      sendNeuronSwitchboardHostedIngressPrefixes(machine);
   }
}

inline void BrainBase::sendNeuronRuntimeEnvironmentConfig(void)
{
   String serializedEnvironment;
   BitseryEngine::serialize(serializedEnvironment, brainConfig.runtimeEnvironment);

   for (Machine *machine : machines)
   {
      if (neuronControlStreamActive(machine) == false)
      {
         continue;
      }

      Message::construct(machine->neuron.wBuffer, NeuronTopic::configureRuntimeEnvironment, serializedEnvironment);
      Ring::queueSend(&machine->neuron);
   }
}

inline bool BrainBase::environmentBGPEnabled(void) const
{
   return iaas && iaas->bgpEnabledForEnvironment();
}

inline bool BrainBase::buildSwitchboardOverlayRoutingConfig(Machine *machine, SwitchboardOverlayRoutingConfig& config) const
{
   config = {};
   // Private container-network traffic between machines must route by machine
   // fragment through the overlay path. Hosted-ingress / pinned external
   // prefixes layer on top of that same machine-routing substrate; they do not
   // replace cross-machine private container delivery.
   config.containerNetworkViaOverlay = true;

   for (const DistributableExternalSubnet& subnet : brainConfig.distributableExternalSubnets)
   {
      if (subnet.routing == ExternalSubnetRouting::switchboardPinnedRoute)
      {
         config.overlaySubnets.push_back(subnet.subnet);
      }
   }

   if (machine == nullptr)
   {
      return true;
   }

   auto appendHostedIngressRouteIfMissing = [&] (const IPPrefix& prefix, uint32_t machineFragment) -> void
   {
      if (machineFragment == 0)
      {
         return;
      }

      for (const SwitchboardOverlayHostedIngressRoute& existing : config.hostedIngressRoutes)
      {
         if (existing.machineFragment == machineFragment
            && existing.prefix.equals(prefix))
         {
            return;
         }
      }

      SwitchboardOverlayHostedIngressRoute route = {};
      route.prefix = prefix;
      route.machineFragment = machineFragment;
      config.hostedIngressRoutes.push_back(route);
   };

   auto appendHostedIngressAddressIfMissing = [&] (const IPAddress& address, uint32_t machineFragment) -> void
   {
      IPPrefix prefix = {};
      if (machineFragment == 0 || address.isNull() || makeHostedIngressPrefixForAddress(address, prefix) == false)
      {
         return;
      }

      appendHostedIngressRouteIfMissing(prefix, machineFragment);
   };

   Vector<ClusterMachinePeerAddress> localCandidates = {};
   prodigyCollectMachinePeerAddresses(*machine, localCandidates);

   Vector<Machine *> sortedMachines = {};
   sortedMachines.reserve(machines.size());
   for (Machine *candidate : machines)
   {
      if (candidate != nullptr)
      {
         sortedMachines.push_back(candidate);
      }
   }

   std::sort(sortedMachines.begin(), sortedMachines.end(), [] (const Machine *lhs, const Machine *rhs) -> bool {

      return prodigyMachineIdentityComesBefore(*lhs, *rhs);
   });

   for (Machine *candidate : sortedMachines)
   {
      if (candidate == nullptr
         || candidate == machine
         || prodigyMachinesShareIdentity(*candidate, *machine)
         || candidate->fragment == 0)
      {
         continue;
      }

      Vector<ClusterMachinePeerAddress> remoteCandidates = {};
      prodigyCollectMachinePeerAddresses(*candidate, remoteCandidates);

      auto appendIPv6Route = [&] () -> bool
      {
         for (const ClusterMachinePeerAddress& remoteCandidate : remoteCandidates)
         {
            IPAddress transportAddress = {};
            if (ClusterMachine::parseIPAddressLiteral(remoteCandidate.address, transportAddress) == false
               || transportAddress.is6 == false)
            {
               continue;
            }

            IPAddress nextHop = {};
            nextHop = transportAddress;
            if (remoteCandidate.gateway.size() > 0)
            {
               if (ClusterMachine::parseIPAddressLiteral(remoteCandidate.gateway, nextHop) == false
                  || nextHop.is6 == false)
               {
                  continue;
               }
            }

            IPAddress sourceAddress = {};
            if (const MachineNicHardwareProfile *localNextHopNic = prodigyFindMachineNicContainingAddress(*machine, nextHop);
               localNextHopNic != nullptr)
            {
               const MachineNicSubnetHardwareProfile *localNextHopSubnet = nullptr;
               localNextHopNic = prodigyFindMachineNicContainingAddress(*machine, nextHop, &localNextHopSubnet);
               if (localNextHopSubnet == nullptr || localNextHopSubnet->address.is6 == false)
               {
                  continue;
               }

               sourceAddress = localNextHopSubnet->address;
            }
            else if (prodigyResolvePreferredLocalSourceAddress(localCandidates, remoteCandidate, sourceAddress) == false
               || sourceAddress.is6 == false)
            {
               continue;
            }

            SwitchboardOverlayMachineRoute route = {};
            route.machineFragment = candidate->fragment;
            route.nextHop = nextHop;
            route.sourceAddress = sourceAddress;

            const MachineNicSubnetHardwareProfile *localDirectSubnet = nullptr;
            const MachineNicHardwareProfile *localDirectNic = prodigyFindMachineNicContainingAddress(*machine, transportAddress, &localDirectSubnet);
            const MachineNicHardwareProfile *remoteDirectNic = prodigyFindMachineNicByAssignedAddress(*candidate, transportAddress);
            bool directPeerRoute = (remoteCandidate.gateway.size() == 0
               && localDirectNic != nullptr
               && localDirectSubnet != nullptr
               && localDirectSubnet->address.equals(sourceAddress));
            if (directPeerRoute)
            {
               if (remoteDirectNic == nullptr || remoteDirectNic->mac.size() == 0)
               {
                  continue;
               }

               route.useGatewayMAC = false;
               route.nextHopMAC.assign(remoteDirectNic->mac);
            }
            else
            {
               route.useGatewayMAC = true;
            }

            config.machineRoutes.push_back(route);
            return true;
         }

         return false;
      };

      (void)appendIPv6Route();

      if (candidate->publicAddress.size() > 0)
      {
         IPAddress publicAddress = {};
         if (ClusterMachine::parseIPAddressLiteral(candidate->publicAddress, publicAddress))
         {
            appendHostedIngressAddressIfMissing(publicAddress, candidate->fragment);
         }
      }

      for (const ClusterMachinePeerAddress& publicCandidate : candidate->peerAddresses)
      {
         if (prodigyClusterMachinePeerAddressIsPrivate(publicCandidate))
         {
            continue;
         }

         IPAddress publicAddress = {};
         if (ClusterMachine::parseIPAddressLiteral(publicCandidate.address, publicAddress))
         {
            appendHostedIngressAddressIfMissing(publicAddress, candidate->fragment);
         }
      }
   }

   for (const RegisteredRoutableAddress& address : brainConfig.routableAddresses)
   {
      if (address.address.isNull() || address.machineUUID == 0 || address.machineUUID == machine->uuid)
      {
         continue;
      }

      Machine *owner = nullptr;
      for (Machine *candidate : machines)
      {
         if (candidate != nullptr && candidate->uuid == address.machineUUID)
         {
            owner = candidate;
            break;
         }
      }

      if (owner == nullptr
         || owner->fragment == 0
         || prodigyMachinesShareIdentity(*owner, *machine))
      {
         continue;
      }

      IPPrefix prefix = {};
      if (makeHostedIngressPrefixForAddress(address.address, prefix) == false)
      {
         continue;
      }

      appendHostedIngressRouteIfMissing(prefix, owner->fragment);
   }

   return true;
}

inline void BrainBase::sendNeuronSwitchboardOverlayRoutes(Machine *machine)
{
   if (neuronControlStreamActive(machine) == false)
   {
      return;
   }

   SwitchboardOverlayRoutingConfig config = {};
   if (buildSwitchboardOverlayRoutingConfig(machine, config) == false)
   {
      return;
   }

   String serializedConfig = {};
   BitseryEngine::serialize(serializedConfig, config);
   Message::construct(machine->neuron.wBuffer, NeuronTopic::configureSwitchboardOverlayRoutes, serializedConfig);
   Ring::queueSend(&machine->neuron);
}

inline void BrainBase::sendNeuronSwitchboardOverlayRoutes(void)
{
   for (Machine *machine : machines)
   {
      if (machine == nullptr)
      {
         continue;
      }

      sendNeuronSwitchboardOverlayRoutes(machine);
   }
}

inline void BrainBase::sendNeuronSwitchboardStateSync(Machine *machine)
{
   if (neuronControlStreamActive(machine) == false)
   {
      return;
   }

   Message::appendEcho(machine->neuron.wBuffer, static_cast<uint16_t>(NeuronTopic::resetSwitchboardState));

   String serializedEnvironment;
   BitseryEngine::serialize(serializedEnvironment, brainConfig.runtimeEnvironment);
   Message::construct(machine->neuron.wBuffer, NeuronTopic::configureRuntimeEnvironment, serializedEnvironment);

   String serializedSubnets;
   BitseryEngine::serialize(serializedSubnets, brainConfig.distributableExternalSubnets);
   Message::construct(machine->neuron.wBuffer, NeuronTopic::configureSwitchboardRoutableSubnets, serializedSubnets);

   Vector<IPPrefix> hostedPrefixes = {};
   buildHostedSwitchboardIngressPrefixes(machine, hostedPrefixes);
   String serializedHostedPrefixes = {};
   BitseryEngine::serialize(serializedHostedPrefixes, hostedPrefixes);
   Message::construct(machine->neuron.wBuffer, NeuronTopic::configureSwitchboardHostedIngressPrefixes, serializedHostedPrefixes);

   SwitchboardOverlayRoutingConfig overlayConfig = {};
   if (buildSwitchboardOverlayRoutingConfig(machine, overlayConfig))
   {
      String serializedOverlayConfig = {};
      BitseryEngine::serialize(serializedOverlayConfig, overlayConfig);
      Message::construct(machine->neuron.wBuffer, NeuronTopic::configureSwitchboardOverlayRoutes, serializedOverlayConfig);
   }

   for (const auto& [uuid, container] : containers)
   {
      (void)uuid;
      if (container == nullptr || container->wormholes.empty())
      {
         continue;
      }

      if (container->state != ContainerState::healthy && container->state != ContainerState::crashedRestarting)
      {
         continue;
      }

      String serializedWormholes = {};
      BitseryEngine::serialize(serializedWormholes, container->wormholes);
      Message::construct(
         machine->neuron.wBuffer,
         NeuronTopic::openSwitchboardWormholes,
         container->generateContainerID(),
         serializedWormholes);
   }

   for (const auto& [uuid, container] : containers)
   {
      (void)uuid;
      if (container == nullptr || container->whiteholes.empty())
      {
         continue;
      }

      if (container->state != ContainerState::scheduled
         && container->state != ContainerState::healthy
         && container->state != ContainerState::crashedRestarting)
      {
         continue;
      }

      Vector<Whitehole> whiteholesForMachine = {};
      collectWhiteholesForNeuronMachine(container, machine, container->whiteholes, whiteholesForMachine);
      if (whiteholesForMachine.empty())
      {
         continue;
      }

      uint32_t headerOffset = Message::appendHeader(machine->neuron.wBuffer, static_cast<uint16_t>(NeuronTopic::openSwitchboardWhiteholes));
      Message::append(machine->neuron.wBuffer, container->generateContainerID());

      for (const Whitehole& whitehole : whiteholesForMachine)
      {
         Message::append(machine->neuron.wBuffer, whitehole.sourcePort);
         Message::appendAlignedBuffer<Alignment::one>(machine->neuron.wBuffer, whitehole.address.v6, 16);
         Message::append(machine->neuron.wBuffer, whitehole.address.is6);
         Message::append(machine->neuron.wBuffer, whitehole.transport);
         Message::append(machine->neuron.wBuffer, whitehole.bindingNonce);
      }

      Message::finish(machine->neuron.wBuffer, headerOffset);
   }

   Ring::queueSend(&machine->neuron);
}

inline void BrainBase::sendNeuronOpenSwitchboardWormholes(ContainerView *container, const Vector<Wormhole>& wormholes)
{
   if (container == nullptr || wormholes.empty())
   {
      return;
   }

   bool refreshHostedIngressPrefixes = false;
   for (const Wormhole& wormhole : wormholes)
   {
      if (wormhole.source == ExternalAddressSource::registeredRoutableAddress)
      {
         refreshHostedIngressPrefixes = true;
         break;
      }
   }

   String serializedWormholes = {};
   BitseryEngine::serialize(serializedWormholes, wormholes);

   for (Machine *machine : machines)
   {
      if (neuronControlStreamActive(machine) == false)
      {
         continue;
      }

      if (refreshHostedIngressPrefixes)
      {
         sendNeuronSwitchboardHostedIngressPrefixes(machine);
      }

      Message::construct(
         machine->neuron.wBuffer,
         NeuronTopic::openSwitchboardWormholes,
         container->generateContainerID(),
         serializedWormholes);
      Ring::queueSend(&machine->neuron);
   }
}

inline void BrainBase::sendNeuronRefreshContainerWormholes(ContainerView *container, const Vector<Wormhole>& wormholes)
{
   if (container == nullptr)
   {
      return;
   }

   String serializedWormholes = {};
   BitseryEngine::serialize(serializedWormholes, wormholes);
   container->proxySend(NeuronTopic::refreshContainerWormholes, container->uuid, serializedWormholes);
}

inline void BrainBase::sendNeuronCloseSwitchboardWormholesToContainer(ContainerView *container)
{
   if (container == nullptr)
   {
      return;
   }

   uint32_t containerID = container->generateContainerID();

   for (Machine *machine : machines)
   {
      if (neuronControlStreamActive(machine) == false)
      {
         continue;
      }

      Message::construct(machine->neuron.wBuffer, NeuronTopic::closeSwitchboardWormholesToContainer, containerID);
      Ring::queueSend(&machine->neuron);
   }
}

inline void BrainBase::sendNeuronOpenSwitchboardWhiteholes(ContainerView *container, const Vector<Whitehole>& whiteholes)
{
   if (container == nullptr || container->machine == nullptr || whiteholes.empty())
   {
      return;
   }

   for (Machine *machine : machines)
   {
      if (neuronControlStreamActive(machine) == false)
      {
         continue;
      }

      Vector<Whitehole> whiteholesForMachine = {};
      collectWhiteholesForNeuronMachine(container, machine, whiteholes, whiteholesForMachine);
      if (whiteholesForMachine.empty())
      {
         continue;
      }

      uint32_t headerOffset = Message::appendHeader(machine->neuron.wBuffer, static_cast<uint16_t>(NeuronTopic::openSwitchboardWhiteholes));
      Message::append(machine->neuron.wBuffer, container->generateContainerID());

      for (const Whitehole& whitehole : whiteholesForMachine)
      {
         Message::append(machine->neuron.wBuffer, whitehole.sourcePort);
         Message::appendAlignedBuffer<Alignment::one>(machine->neuron.wBuffer, whitehole.address.v6, 16);
         Message::append(machine->neuron.wBuffer, whitehole.address.is6);
         Message::append(machine->neuron.wBuffer, whitehole.transport);
         Message::append(machine->neuron.wBuffer, whitehole.bindingNonce);
      }

      Message::finish(machine->neuron.wBuffer, headerOffset);
      Ring::queueSend(&machine->neuron);
   }
}

inline void BrainBase::sendNeuronCloseSwitchboardWhiteholesToContainer(ContainerView *container)
{
   if (container == nullptr || container->machine == nullptr)
   {
      return;
   }

   uint32_t containerID = container->generateContainerID();
   Machine *machine = container->machine;
   if (neuronControlStreamActive(machine) == false)
   {
      return;
   }

   Message::construct(machine->neuron.wBuffer, NeuronTopic::closeSwitchboardWhiteholesToContainer, containerID);
   Ring::queueSend(&machine->neuron);
}

class Mothership : public TCPStream, public CoroutineStack {
private:

public:
   bool closeAfterSendDrain = false;

	Mothership()
	{
		rBuffer.reserve(8_KB);
		wBuffer.reserve(16_KB);
	}
};

class Brain : public BrainBase, public TimeoutDispatcher {
public:

	// any brain
	uint8_t nBrains = 0;
	uint32_t brainPeerKeepaliveSeconds = prodigyBrainPeerKeepaliveSeconds;
	int64_t boottimens;

	TCPSocket brainSocket;
	struct sockaddr_storage brain_saddr = {};
	socklen_t brain_saddrlen = sizeof(struct sockaddr_storage);
	IPAddress localBrainPeerAddress = {};
	String localBrainPeerAddressText;
   Vector<ClusterMachinePeerAddress> localBrainPeerAddresses;

	bool noMasterYet = true;
	bool weAreMaster = false;
	bool hasCompletedInitialMasterElection = false;

		enum class UpdateSelfState : uint8_t {
			idle,
			waitingForBundleEchos,
			waitingForFollowerReboots,
			waitingForRelinquishEchos
		};
		UpdateSelfState updateSelfState = UpdateSelfState::idle;
		uint32_t updateSelfExpectedEchos = 0;
		uint32_t updateSelfBundleEchos = 0;
		uint32_t updateSelfRelinquishEchos = 0;
		uint128_t updateSelfPlannedMasterPeerKey = 0;
		uint128_t pendingDesignatedMasterPeerKey = 0;
		bool updateSelfUseStagedBundleOnly = false;
		String updateSelfBundleBlob;
	bytell_hash_set<uint128_t> updateSelfBundleIssuedPeerKeys;
	bytell_hash_set<uint128_t> updateSelfBundleEchoPeerKeys;
	bytell_hash_set<uint128_t> updateSelfRelinquishEchoPeerKeys;
	bytell_hash_map<uint128_t, int64_t> updateSelfFollowerBootNsByPeerKey;
	bytell_hash_set<uint128_t> updateSelfFollowerReconnectedPeerKeys;
	bytell_hash_set<uint128_t> updateSelfFollowerRebootedPeerKeys;
	bytell_hash_set<uint128_t> updateSelfTransitionIssuedPeerKeys;
	bytell_hash_set<uint128_t> updateSelfRelinquishIssuedPeerKeys;
		static constexpr int64_t connectFailureLogIntervalMs = prodigyBrainConnectFailureLogIntervalMs;
		bytell_hash_map<uint64_t, int64_t> connectFailureNextLogMsByKey;

	// not master brain
	bool isMasterMissing = false;
	bool masterQuorumDegraded = false;

	// master brain
	bool ignited = false;

		TimeoutPacket osUpdateTimer;
		TimeoutPacket ignitionSwitch;
		TimeoutPacket spotDecomissionChecker;
		bytell_hash_map<BrainView *, TimeoutPacket *> brainWaiters;
	Vector<Machine *> operatingSystemUpdateOrder;

	bytell_hash_set<NeuronView *> neurons;

	// just create a new ssh instance each time we need it... simplies everything for now.. unless we intended to use it regularly
	bytell_hash_set<MachineSSH *> sshs;

				Mothership *mothership = nullptr;
				bytell_hash_set<Mothership *> closingMotherships;
				TCPSocket mothershipSocket;
			bool mothershipAcceptArmed = false;
			UnixSocket mothershipUnixSocket;
			bool mothershipUnixAcceptArmed = false;
			String mothershipUnixSocketPath;
         bytell_hash_map<uint64_t, Mothership *> spinApplicationMotherships;
		bytell_hash_map<uint128_t, Machine *> machinesByUUID;

		bytell_hash_map<String, uint32_t> nReservedRequestedBySlug;
		bytell_hash_map<uint16_t, ApplicationTlsVaultFactory> tlsVaultFactoriesByApp;
		bytell_hash_map<uint16_t, ApplicationApiCredentialSet> apiCredentialSetsByApp;
		bytell_hash_map<String, uint16_t> reservedApplicationIDsByName;
		bytell_hash_map<uint16_t, String> reservedApplicationNamesByID;
		bytell_hash_map<String, ApplicationServiceIdentity> reservedApplicationServicesByNameKey;
		bytell_hash_map<uint64_t, ApplicationServiceIdentity> reservedApplicationServicesByID;
		bytell_hash_map<uint32_t, String> reservedApplicationServiceNamesBySlotKey;
		bytell_hash_map<uint16_t, uint8_t> nextReservableServiceSlotByApplication;
		uint16_t nextReservableApplicationID = 1;
		uint64_t nextMintedClientTlsGeneration = 1;
		ProdigyMasterAuthorityRuntimeState masterAuthorityRuntimeState;

	// 2,592,000 seconds in 30 days. so even if each reboot took 20 seconds (in reality it'll be closer to 10 seconds, but should be more like 5 seconds)
	// we'd still have capacity to be rebooting to update the OS on over 125,000 machines a month, never doing more than 1 machine at at time.
	// google updates their machines at least once a month
	   // removed legacy OS update order; updates now driven by explicit targets

		bool isValidReservedApplicationName(const String& applicationName) const
		{
			uint32_t n = uint32_t(applicationName.size());
			if (n == 0 || n > 96)
			{
				return false;
			}

			const char *chars = reinterpret_cast<const char *>(applicationName.data());
			for (uint32_t i = 0; i < n; i += 1)
			{
				char c = chars[i];
				bool isAlpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
				bool isDigit = (c >= '0' && c <= '9');
				bool isAllowedPunct = (c == '_' || c == '-' || c == '.');
				if (isAlpha == false && isDigit == false && isAllowedPunct == false)
				{
					return false;
				}
			}

			return true;
		}

		bool isValidReservedServiceName(const String& serviceName) const
		{
			uint32_t n = uint32_t(serviceName.size());
			if (n == 0 || n > 96)
			{
				return false;
			}

			const char *chars = reinterpret_cast<const char *>(serviceName.data());
			for (uint32_t i = 0; i < n; i += 1)
			{
				char c = chars[i];
				bool isAlpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
				bool isDigit = (c >= '0' && c <= '9');
				bool isAllowedPunct = (c == '_' || c == '-');
				if (isAlpha == false && isDigit == false && isAllowedPunct == false)
				{
					return false;
				}
			}

			return true;
		}

		static uint32_t makeReservedServiceSlotKey(uint16_t applicationID, uint8_t serviceSlot)
		{
			return (uint32_t(applicationID) << 8) | uint32_t(serviceSlot);
		}

		static uint64_t materializeReservedService(const ApplicationServiceIdentity& identity)
		{
			if (identity.kind == ApplicationServiceIdentity::Kind::stateful)
			{
				return (uint64_t(identity.applicationID) << 48) | (uint64_t(identity.serviceSlot) << 40) | ((1ull << 10) - 1);
			}

			return (uint64_t(identity.applicationID) << 48) | (uint64_t(identity.serviceSlot) << 40);
		}

		String makeReservedServiceNameKey(uint16_t applicationID, const String& serviceName) const
		{
			String key;
			key.snprintf<"{}:{}"_ctv>(applicationID, serviceName);
			return key;
		}

		bool resolveReservedApplicationID(const String& applicationName, uint16_t& applicationID) const
		{
			if (auto byName = reservedApplicationIDsByName.find(applicationName); byName != reservedApplicationIDsByName.end())
			{
				applicationID = byName->second;
				return true;
			}

			return false;
		}

		bool reserveApplicationIDMapping(const String& applicationName, uint16_t applicationID, String *failure = nullptr)
		{
			if (applicationID == 0)
			{
				if (failure)
				{
					failure->assign("applicationID invalid"_ctv);
				}
				return false;
			}

			if (isValidReservedApplicationName(applicationName) == false)
			{
				if (failure)
				{
					failure->assign("applicationName invalid"_ctv);
				}
				return false;
			}

			if (auto byName = reservedApplicationIDsByName.find(applicationName); byName != reservedApplicationIDsByName.end() && byName->second != applicationID)
			{
				if (failure)
				{
					failure->assign("applicationName already reserved with different applicationID"_ctv);
				}
				return false;
			}

			if (auto byID = reservedApplicationNamesByID.find(applicationID); byID != reservedApplicationNamesByID.end() && byID->second.equals(applicationName) == false)
			{
				if (failure)
				{
					failure->assign("applicationID already reserved by a different applicationName"_ctv);
				}
				return false;
			}

			String ownedApplicationName = {};
			ownedApplicationName.assign(applicationName);
			reservedApplicationIDsByName.insert_or_assign(ownedApplicationName, applicationID);
			reservedApplicationNamesByID.insert_or_assign(applicationID, ownedApplicationName);
			if (applicationID >= nextReservableApplicationID && applicationID < UINT16_MAX)
			{
				nextReservableApplicationID = uint16_t(applicationID + 1);
			}

			return true;
		}

		bool reserveApplicationServiceMapping(const ApplicationServiceIdentity& identity, String *failure = nullptr)
		{
			if (identity.applicationID == 0 || isApplicationIDReserved(identity.applicationID) == false)
			{
				if (failure)
				{
					failure->assign("applicationID not reserved"_ctv);
				}
				return false;
			}

			if (isValidReservedServiceName(identity.serviceName) == false)
			{
				if (failure)
				{
					failure->assign("serviceName invalid"_ctv);
				}
				return false;
			}

			if (identity.serviceSlot == 0)
			{
				if (failure)
				{
					failure->assign("serviceSlot invalid"_ctv);
				}
				return false;
			}

			if (identity.kind != ApplicationServiceIdentity::Kind::stateless
			    && identity.kind != ApplicationServiceIdentity::Kind::stateful)
			{
				if (failure)
				{
					failure->assign("service kind invalid"_ctv);
				}
				return false;
			}

			String nameKey = makeReservedServiceNameKey(identity.applicationID, identity.serviceName);
			if (auto byName = reservedApplicationServicesByNameKey.find(nameKey); byName != reservedApplicationServicesByNameKey.end())
			{
				const ApplicationServiceIdentity& existing = byName->second;
				if (existing.serviceSlot != identity.serviceSlot || existing.kind != identity.kind)
				{
					if (failure)
					{
						failure->assign("serviceName already reserved with different shape"_ctv);
					}
					return false;
				}
			}

			uint32_t slotKey = makeReservedServiceSlotKey(identity.applicationID, identity.serviceSlot);
			if (auto bySlot = reservedApplicationServiceNamesBySlotKey.find(slotKey); bySlot != reservedApplicationServiceNamesBySlotKey.end()
			    && bySlot->second.equals(identity.serviceName) == false)
			{
				if (failure)
				{
					failure->assign("serviceSlot already reserved by a different serviceName"_ctv);
				}
				return false;
			}

			uint64_t service = materializeReservedService(identity);
			if (auto byService = reservedApplicationServicesByID.find(service); byService != reservedApplicationServicesByID.end())
			{
				const ApplicationServiceIdentity& existing = byService->second;
				if (existing.applicationID != identity.applicationID
				    || existing.serviceSlot != identity.serviceSlot
				    || existing.serviceName.equals(identity.serviceName) == false
				    || existing.kind != identity.kind)
				{
					if (failure)
					{
						failure->assign("service already reserved by a different mapping"_ctv);
					}
					return false;
				}
			}

			ApplicationServiceIdentity ownedIdentity = identity;
			String ownedServiceName = {};
			ownedServiceName.assign(identity.serviceName.data(), identity.serviceName.size());
			ownedIdentity.serviceName = std::move(ownedServiceName);
			String ownedNameKey = makeReservedServiceNameKey(ownedIdentity.applicationID, ownedIdentity.serviceName);

			reservedApplicationServicesByNameKey.insert_or_assign(ownedNameKey, ownedIdentity);
			reservedApplicationServicesByID.insert_or_assign(service, ownedIdentity);
			reservedApplicationServiceNamesBySlotKey.insert_or_assign(slotKey, ownedIdentity.serviceName);

			uint8_t nextSlot = uint8_t(identity.serviceSlot + 1);
			if (identity.serviceSlot < UINT8_MAX)
			{
				auto it = nextReservableServiceSlotByApplication.find(identity.applicationID);
				if (it == nextReservableServiceSlotByApplication.end() || it->second <= identity.serviceSlot)
				{
					nextReservableServiceSlotByApplication.insert_or_assign(identity.applicationID, nextSlot);
				}
			}

			return true;
		}

			bool resolveReservedApplicationService(uint16_t applicationID, const String& serviceName, ApplicationServiceIdentity& identity) const
			{
				String nameKey = makeReservedServiceNameKey(applicationID, serviceName);
				if (auto byName = reservedApplicationServicesByNameKey.find(nameKey); byName != reservedApplicationServicesByNameKey.end())
				{
				identity = byName->second;
				return true;
			}

				return false;
			}

			void capturePersistentReservedApplicationServices(Vector<ApplicationServiceIdentity>& services) const
			{
				services.clear();
				services.reserve(reservedApplicationServicesByID.size());
				for (const auto& [service, identity] : reservedApplicationServicesByID)
				{
					(void)service;
					services.push_back(identity);
				}

				std::sort(services.begin(), services.end(), [] (const ApplicationServiceIdentity& lhs, const ApplicationServiceIdentity& rhs) -> bool {
					if (lhs.applicationID != rhs.applicationID)
					{
						return lhs.applicationID < rhs.applicationID;
					}

					if (lhs.serviceSlot != rhs.serviceSlot)
					{
						return lhs.serviceSlot < rhs.serviceSlot;
					}

					if (lhs.kind != rhs.kind)
					{
						return uint8_t(lhs.kind) < uint8_t(rhs.kind);
					}

					return std::lexicographical_compare(
						lhs.serviceName.data(),
						lhs.serviceName.data() + lhs.serviceName.size(),
						rhs.serviceName.data(),
						rhs.serviceName.data() + rhs.serviceName.size());
				});
			}

			void restorePersistentReservedApplicationServices(const Vector<ApplicationServiceIdentity>& services)
			{
				initializeApplicationServiceReservationState();
				for (const ApplicationServiceIdentity& identity : services)
				{
					String failure;
					if (reserveApplicationServiceMapping(identity, &failure) == false)
					{
						String serviceName = {};
						serviceName.assign(identity.serviceName);
						basics_log("restorePersistentReservedApplicationServices reject appID=%u service=%s reason=%s\n",
							unsigned(identity.applicationID),
							serviceName.c_str(),
							failure.c_str());
					}
				}
			}

			void initializeApplicationIDReservationState(void)
			{
				reservedApplicationIDsByName.clear();
				reservedApplicationNamesByID.clear();
			nextReservableApplicationID = 1;
			for (const auto& [applicationName, applicationID] : MeshRegistry::applicationIDMappings)
			{
				if (applicationID == 0)
				{
					continue;
				}

				String failure;
				if (reserveApplicationIDMapping(applicationName, applicationID, &failure) == false)
				{
					basics_log("initializeApplicationIDReservationState conflict appID=%u reason=%s\n",
						unsigned(applicationID),
						failure.c_str());
				}
			}
		}

		void initializeApplicationServiceReservationState(void)
		{
			reservedApplicationServicesByNameKey.clear();
			reservedApplicationServicesByID.clear();
			reservedApplicationServiceNamesBySlotKey.clear();
			nextReservableServiceSlotByApplication.clear();

			for (const auto& [serviceName, service] : MeshRegistry::serviceMappings)
			{
				int64_t colon = serviceName.rfindChar(':');
				if (colon <= 0 || colon >= int64_t(serviceName.size() - 1))
				{
					continue;
				}

				if (serviceName.data()[colon - 1] != ':')
				{
					continue;
				}

				ApplicationServiceIdentity identity;
				identity.applicationID = uint16_t(service >> 48);
				identity.serviceName.assign(serviceName.substr(uint64_t(colon + 1), serviceName.size() - uint64_t(colon + 1), Copy::no));
				identity.serviceSlot = uint8_t((service >> 40) & 0xFFu);
				identity.kind = MeshServices::isPrefix(service) ? ApplicationServiceIdentity::Kind::stateful : ApplicationServiceIdentity::Kind::stateless;

				String failure;
				if (reserveApplicationServiceMapping(identity, &failure) == false)
				{
					basics_log("initializeApplicationServiceReservationState conflict appID=%u service=%s reason=%s\n",
						unsigned(identity.applicationID),
						identity.serviceName.c_str(),
						failure.c_str());
				}
			}
		}

		uint16_t takeNextReservableApplicationID(void)
		{
			for (uint32_t candidate = nextReservableApplicationID; candidate <= UINT16_MAX; candidate += 1)
			{
				if (candidate == 0) continue;

				uint16_t applicationID = uint16_t(candidate);
				if (reservedApplicationNamesByID.find(applicationID) == reservedApplicationNamesByID.end())
				{
					if (candidate < UINT16_MAX)
					{
						nextReservableApplicationID = uint16_t(candidate + 1);
					}
					else
					{
						nextReservableApplicationID = UINT16_MAX;
					}

					return applicationID;
				}
			}

			return 0;
		}

		uint8_t takeNextReservableServiceSlot(uint16_t applicationID)
		{
			uint32_t candidate = 1;
			if (auto it = nextReservableServiceSlotByApplication.find(applicationID); it != nextReservableServiceSlotByApplication.end() && it->second > 0)
			{
				candidate = it->second;
			}

			for (; candidate <= UINT8_MAX; candidate += 1)
			{
				uint8_t serviceSlot = uint8_t(candidate);
				uint32_t slotKey = makeReservedServiceSlotKey(applicationID, serviceSlot);
				if (reservedApplicationServiceNamesBySlotKey.find(slotKey) == reservedApplicationServiceNamesBySlotKey.end())
				{
					if (candidate < UINT8_MAX)
					{
						nextReservableServiceSlotByApplication.insert_or_assign(applicationID, uint8_t(candidate + 1));
					}
					else
					{
						nextReservableServiceSlotByApplication.insert_or_assign(applicationID, UINT8_MAX);
					}

					return serviceSlot;
				}
			}

			return 0;
		}

		uint128_t updateSelfPeerTrackingKey(const BrainView *brain) const
		{
			if (brain == nullptr)
			{
				return 0;
			}

			if (brain->private4 != 0)
			{
				return uint128_t(brain->private4);
			}

			IPAddress peerAddress = brain->peerAddress;
			if (peerAddress.isNull())
			{
				for (const ClusterMachinePeerAddress& candidate : brain->peerAddresses)
				{
					if (ClusterMachine::parseIPAddressLiteral(candidate.address, peerAddress))
					{
						break;
					}
				}
			}

			if (peerAddress.isNull() == false)
			{
				if (peerAddress.is6 == false)
				{
					peerAddress = peerAddress.create4in6();
				}

				uint128_t key = 0;
				memcpy(&key, peerAddress.v6, sizeof(key));
				return key;
			}

			return brain->uuid;
		}

		uint128_t updateSelfLocalPeerTrackingKey(void) const
		{
			if (thisNeuron != nullptr && thisNeuron->private4.isNull() == false && thisNeuron->private4.v4 != 0)
			{
				return uint128_t(thisNeuron->private4.v4);
			}

			IPAddress selfAddress = localBrainPeerAddress;
			if (selfAddress.isNull())
			{
				for (const ClusterMachinePeerAddress& candidate : localBrainPeerAddresses)
				{
					if (ClusterMachine::parseIPAddressLiteral(candidate.address, selfAddress))
					{
						break;
					}
				}
			}

			if (selfAddress.isNull())
			{
				return selfBrainUUID();
			}

			if (selfAddress.is6 == false)
			{
				selfAddress = selfAddress.create4in6();
			}

			uint128_t key = 0;
			memcpy(&key, selfAddress.v6, sizeof(key));
			return key;
		}

			ProdigyPersistentUpdateSelfState capturePersistentUpdateSelfState(void) const
			{
				ProdigyPersistentUpdateSelfState state = {};
				state.state = uint8_t(updateSelfState);
				state.expectedEchos = updateSelfExpectedEchos;
				state.bundleEchos = updateSelfBundleEchos;
				state.relinquishEchos = updateSelfRelinquishEchos;
				state.plannedMasterPeerKey = updateSelfPlannedMasterPeerKey;
				state.pendingDesignatedMasterPeerKey = pendingDesignatedMasterPeerKey;
				state.useStagedBundleOnly = updateSelfUseStagedBundleOnly;
				state.bundleBlob = updateSelfBundleBlob;

				for (uint128_t peerKey : updateSelfBundleEchoPeerKeys)
				{
					state.bundleEchoPeerKeys.push_back(peerKey);
				}
				for (uint128_t peerKey : updateSelfRelinquishEchoPeerKeys)
				{
					state.relinquishEchoPeerKeys.push_back(peerKey);
				}
				for (const auto& [peerKey, bootNs] : updateSelfFollowerBootNsByPeerKey)
				{
					ProdigyPersistentUpdateSelfFollowerBoot follower = {};
					follower.peerKey = peerKey;
					follower.bootNs = bootNs;
					state.followerBootNsByPeerKey.push_back(follower);
				}
				for (uint128_t peerKey : updateSelfFollowerRebootedPeerKeys)
				{
					state.followerRebootedPeerKeys.push_back(peerKey);
				}

				std::sort(state.bundleEchoPeerKeys.begin(), state.bundleEchoPeerKeys.end());
				std::sort(state.relinquishEchoPeerKeys.begin(), state.relinquishEchoPeerKeys.end());
				std::sort(state.followerBootNsByPeerKey.begin(), state.followerBootNsByPeerKey.end(),
					[](const ProdigyPersistentUpdateSelfFollowerBoot& lhs, const ProdigyPersistentUpdateSelfFollowerBoot& rhs) {
						return lhs.peerKey < rhs.peerKey;
					});
				std::sort(state.followerRebootedPeerKeys.begin(), state.followerRebootedPeerKeys.end());
				return state;
			}

			void restorePersistentUpdateSelfState(const ProdigyPersistentUpdateSelfState& state)
			{
				updateSelfState = UpdateSelfState::idle;
				if (state.state <= uint8_t(UpdateSelfState::waitingForRelinquishEchos))
				{
					updateSelfState = UpdateSelfState(state.state);
				}

				updateSelfExpectedEchos = state.expectedEchos;
				updateSelfBundleEchos = state.bundleEchos;
				updateSelfRelinquishEchos = state.relinquishEchos;
				updateSelfPlannedMasterPeerKey = state.plannedMasterPeerKey;
				pendingDesignatedMasterPeerKey = state.pendingDesignatedMasterPeerKey;
				if (pendingDesignatedMasterPeerKey > 0)
				{
					String pendingPeerKeyText = {};
					pendingPeerKeyText.snprintf<"{itoa}"_ctv>(pendingDesignatedMasterPeerKey);
					basics_log("restorePersistentUpdateSelfState pendingDesignatedMasterPeerKey=%s\n",
						pendingPeerKeyText.c_str());
				}
				updateSelfUseStagedBundleOnly = state.useStagedBundleOnly;
				updateSelfBundleBlob = state.bundleBlob;

				updateSelfBundleEchoPeerKeys.clear();
				updateSelfRelinquishEchoPeerKeys.clear();
				updateSelfFollowerBootNsByPeerKey.clear();
				updateSelfFollowerRebootedPeerKeys.clear();

				for (uint128_t peerKey : state.bundleEchoPeerKeys)
				{
					updateSelfBundleEchoPeerKeys.insert(peerKey);
				}
				for (uint128_t peerKey : state.relinquishEchoPeerKeys)
				{
					updateSelfRelinquishEchoPeerKeys.insert(peerKey);
				}
				for (const ProdigyPersistentUpdateSelfFollowerBoot& follower : state.followerBootNsByPeerKey)
				{
					updateSelfFollowerBootNsByPeerKey.insert_or_assign(follower.peerKey, follower.bootNs);
				}
				for (uint128_t peerKey : state.followerRebootedPeerKeys)
				{
					updateSelfFollowerRebootedPeerKeys.insert(peerKey);
				}
			}

			void refreshMasterAuthorityRuntimeStateFromLiveFields(void)
			{
				if (nextMintedClientTlsGeneration == 0)
				{
					nextMintedClientTlsGeneration = 1;
				}

            if (masterAuthorityRuntimeState.nextPendingAddMachinesOperationID == 0)
            {
               masterAuthorityRuntimeState.nextPendingAddMachinesOperationID = 1;
            }

				masterAuthorityRuntimeState.nextMintedClientTlsGeneration = nextMintedClientTlsGeneration;
				masterAuthorityRuntimeState.updateSelf = capturePersistentUpdateSelfState();
			}

         void upsertManagedMachineSchemaConfig(const ProdigyManagedMachineSchema& managedSchema)
         {
            MachineConfig machineConfig = {};
            prodigyBuildMachineConfigFromManagedMachineSchema(managedSchema, machineConfig);
            brainConfig.configBySlug.insert_or_assign(managedSchema.schema, std::move(machineConfig));
         }

         void eraseManagedMachineSchemaConfig(const String& schemaKey)
         {
            auto it = brainConfig.configBySlug.find(schemaKey);
            if (it != brainConfig.configBySlug.end())
            {
               brainConfig.configBySlug.erase(it);
            }
         }

         void syncManagedMachineSchemaConfigs(const Vector<ProdigyManagedMachineSchema>& previousSchemas, const Vector<ProdigyManagedMachineSchema>& incomingSchemas)
         {
            for (const ProdigyManagedMachineSchema& previousSchema : previousSchemas)
            {
               bool stillPresent = false;
               for (const ProdigyManagedMachineSchema& incomingSchema : incomingSchemas)
               {
                  if (incomingSchema.schema.equals(previousSchema.schema))
                  {
                     stillPresent = true;
                     break;
                  }
               }

               if (stillPresent == false)
               {
                  eraseManagedMachineSchemaConfig(previousSchema.schema);
               }
            }

            for (const ProdigyManagedMachineSchema& incomingSchema : incomingSchemas)
            {
               upsertManagedMachineSchemaConfig(incomingSchema);
            }
         }

         ProdigyPendingAddMachinesOperation *findPendingAddMachinesOperation(uint64_t operationID)
         {
            for (ProdigyPendingAddMachinesOperation& operation : masterAuthorityRuntimeState.pendingAddMachinesOperations)
            {
               if (operation.operationID == operationID)
               {
                  return &operation;
               }
            }

            return nullptr;
         }

         const ProdigyPendingAddMachinesOperation *findPendingAddMachinesOperation(uint64_t operationID) const
         {
            for (const ProdigyPendingAddMachinesOperation& operation : masterAuthorityRuntimeState.pendingAddMachinesOperations)
            {
               if (operation.operationID == operationID)
               {
                  return &operation;
               }
            }

            return nullptr;
         }

         uint64_t journalAddMachinesOperation(const AddMachines& request, const ClusterTopology& plannedTopology, const Vector<ClusterMachine>& machinesToBootstrap)
         {
            refreshMasterAuthorityRuntimeStateFromLiveFields();

            uint64_t operationID = masterAuthorityRuntimeState.nextPendingAddMachinesOperationID++;
            if (operationID == 0)
            {
               operationID = masterAuthorityRuntimeState.nextPendingAddMachinesOperationID++;
            }

            ProdigyPendingAddMachinesOperation operation = {};
            operation.operationID = operationID;
            operation.request = request;
            operation.plannedTopology = plannedTopology;
            operation.machinesToBootstrap = machinesToBootstrap;
            operation.updatedAtMs = Time::now<TimeResolution::ms>();
            masterAuthorityRuntimeState.pendingAddMachinesOperations.push_back(std::move(operation));
            noteMasterAuthorityRuntimeStateChanged();
            return operationID;
         }

         bool upsertPendingAddMachinesOperationMachine(uint64_t operationID, const ClusterMachine& machine, bool queueForBootstrap, bool replicate = true, bool persist = true)
         {
            if (ProdigyPendingAddMachinesOperation *operation = findPendingAddMachinesOperation(operationID); operation != nullptr)
            {
               bool changed = prodigyUpsertClusterMachineByIdentity(operation->plannedTopology.machines, machine);
               if (queueForBootstrap)
               {
                  changed = prodigyUpsertClusterMachineByIdentity(operation->machinesToBootstrap, machine) || changed;
               }

               if (changed)
               {
                  operation->updatedAtMs = Time::now<TimeResolution::ms>();
                  noteMasterAuthorityRuntimeStateChanged(replicate, persist);
               }

               return changed;
            }

            return false;
         }

         bool erasePendingAddMachinesOperationBootstrapMachine(uint64_t operationID, const ClusterMachine& machine, bool replicate = true, bool persist = true)
         {
            if (ProdigyPendingAddMachinesOperation *operation = findPendingAddMachinesOperation(operationID); operation != nullptr)
            {
               if (prodigyEraseClusterMachineByIdentity(operation->machinesToBootstrap, machine))
               {
                  operation->updatedAtMs = Time::now<TimeResolution::ms>();
                  noteMasterAuthorityRuntimeStateChanged(replicate, persist);
                  return true;
               }
            }

            return false;
         }

         bool erasePendingAddMachinesOperation(uint64_t operationID, bool replicate = true, bool persist = true)
         {
            auto& operations = masterAuthorityRuntimeState.pendingAddMachinesOperations;
            auto it = std::remove_if(operations.begin(), operations.end(), [=](const ProdigyPendingAddMachinesOperation& operation) {
               return operation.operationID == operationID;
            });

            if (it == operations.end())
            {
               return false;
            }

            operations.erase(it, operations.end());
            noteMasterAuthorityRuntimeStateChanged(replicate, persist);
            return true;
         }

         void updatePendingAddMachinesOperationFailure(uint64_t operationID, const String& failure, bool replicate = true, bool persist = true)
         {
            if (ProdigyPendingAddMachinesOperation *operation = findPendingAddMachinesOperation(operationID); operation != nullptr)
            {
               operation->resumeAttempts += 1;
               operation->updatedAtMs = Time::now<TimeResolution::ms>();
               operation->lastFailure = failure;
               noteMasterAuthorityRuntimeStateChanged(replicate, persist);
            }
         }

         bool pendingAddMachinesOperationHasUnreadyCreatedMachines(const ProdigyPendingAddMachinesOperation& operation) const
         {
            for (const ClusterMachine& machine : operation.plannedTopology.machines)
            {
               if (machine.source == ClusterMachineSource::created
                  && machine.backing == ClusterMachineBacking::cloud
                  && prodigyClusterMachineBootstrapReady(machine) == false)
               {
                  return true;
               }
            }

            return false;
         }

         bool refreshPendingAddMachinesOperationCreatedMachines(ProdigyPendingAddMachinesOperation& operation, String& failure)
         {
            failure.clear();
            if (pendingAddMachinesOperationHasUnreadyCreatedMachines(operation) == false)
            {
               return true;
            }

            String lookupScope = {};
            if (thisNeuron != nullptr && thisNeuron->metro.size() > 0)
            {
               lookupScope.assign(thisNeuron->metro);
            }
            else if (brainConfig.runtimeEnvironment.providerScope.size() > 0)
            {
               lookupScope.assign(brainConfig.runtimeEnvironment.providerScope);
            }

            bytell_hash_set<Machine *> providerMachines = {};
            iaas->getMachines(nullptr, lookupScope, providerMachines);

            bool changed = false;
            for (ClusterMachine& machine : operation.plannedTopology.machines)
            {
               if (machine.source != ClusterMachineSource::created
                  || machine.backing != ClusterMachineBacking::cloud
                  || prodigyClusterMachineBootstrapReady(machine))
               {
                  continue;
               }

               for (Machine *candidate : providerMachines)
               {
                  if (candidate == nullptr || prodigyClusterMachineMatchesMachineIdentity(machine, *candidate) == false)
                  {
                     continue;
                  }

                  ClusterMachine refreshed = machine;
                  prodigyRefreshCreatedClusterMachineFromSnapshot(
                     refreshed,
                     candidate,
                     operation.request.bootstrapSshUser,
                     operation.request.bootstrapSshPrivateKeyPath,
                     operation.request.bootstrapSshHostKeyPackage.publicKeyOpenSSH);
                  if (refreshed != machine)
                  {
                     machine = std::move(refreshed);
                     changed = true;
                  }

                  if (prodigyClusterMachineBootstrapReady(machine))
                  {
                     changed = prodigyUpsertClusterMachineByIdentity(operation.machinesToBootstrap, machine) || changed;
                  }

                  break;
               }
            }

            for (Machine *candidate : providerMachines)
            {
               delete candidate;
            }

            if (changed)
            {
               prodigyNormalizeClusterTopologyPeerAddresses(operation.plannedTopology);
               operation.updatedAtMs = Time::now<TimeResolution::ms>();
               noteMasterAuthorityRuntimeStateChanged();
            }

            if (pendingAddMachinesOperationHasUnreadyCreatedMachines(operation))
            {
               failure.assign("pending created machines are not yet ready to resume addMachines bootstrap"_ctv);
               return false;
            }

            return true;
         }

         bool mergePendingAddMachinesTopology(const ProdigyPendingAddMachinesOperation& operation, ClusterTopology& mergedTopology, String& failure) const
         {
            failure.clear();

            ClusterTopology authoritativeTopology = {};
            if (loadAuthoritativeClusterTopology(authoritativeTopology) == false)
            {
               failure.assign("failed to load authoritative topology for addMachines resume"_ctv);
               return false;
            }

            mergedTopology = authoritativeTopology;
            for (const ClusterMachine& machine : operation.plannedTopology.machines)
            {
               if (clusterTopologyContainsMachineIdentity(mergedTopology, machine))
               {
                  continue;
               }

               mergedTopology.machines.push_back(machine);
            }

            for (const ClusterMachine& removedMachine : operation.request.removedMachines)
            {
               auto it = std::remove_if(mergedTopology.machines.begin(), mergedTopology.machines.end(), [&] (const ClusterMachine& existing) {
                  return existing.sameIdentityAs(removedMachine);
               });
               mergedTopology.machines.erase(it, mergedTopology.machines.end());
            }

            prodigyNormalizeClusterTopologyPeerAddresses(mergedTopology);
            mergedTopology.version = authoritativeTopology.version + 1;
            return true;
         }

         virtual bool canSuspendRemoteBootstrap(void) const
         {
            return RingDispatcher::dispatcher != nullptr && Ring::getRingFD() > 0;
         }

         virtual bool queueClusterMachineBootstrapAsync(
            ProdigyRemoteBootstrapCoordinator& coordinator,
            ProdigyRemoteBootstrapBundleApprovalCache& bundleApprovalCache,
            const ClusterMachine& clusterMachine,
            const AddMachines& request,
            const ClusterTopology& topology,
            String& failure) const
         {
            ProdigyRemoteBootstrapPlan plan = {};
            if (prodigyBuildRemoteBootstrapPlan(clusterMachine, request, topology, brainConfig.runtimeEnvironment, plan, &failure) == false)
            {
               return false;
            }

            String internalSSHAddress = {};
            if (prodigyResolveClusterMachineInternalSSHAddress(clusterMachine, internalSSHAddress))
            {
               plan.ssh.address = internalSSHAddress;
            }

            ProdigyPreparedRemoteBootstrapPlan prepared = {};
            if (prodigyPrepareRemoteBootstrapPlan(clusterMachine, plan, prepared, &bundleApprovalCache, &failure) == false)
            {
               return false;
            }

            coordinator.startPreparedPlan(prepared);
            return true;
         }

         virtual bool bootstrapClusterMachineBlocking(
            const ClusterMachine& clusterMachine,
            const AddMachines& request,
            const ClusterTopology& topology,
            String& failure,
            ProdigyRemoteBootstrapBundleApprovalCache *bundleApprovalCache = nullptr) const
         {
            ProdigyRemoteBootstrapPlan plan = {};
            if (prodigyBuildRemoteBootstrapPlan(clusterMachine, request, topology, brainConfig.runtimeEnvironment, plan, &failure) == false)
            {
               return false;
            }

            String internalSSHAddress = {};
            if (prodigyResolveClusterMachineInternalSSHAddress(clusterMachine, internalSSHAddress))
            {
               plan.ssh.address = internalSSHAddress;
            }

            auto failBootstrap = [&] () -> bool {

               String label = {};
               clusterMachine.renderIdentityLabel(label);
               String reason = failure;
               failure.snprintf<"failed to bootstrap machine '{}': {}"_ctv>(label, reason);
               return false;
            };

            ProdigyPreparedRemoteBootstrapPlan prepared = {};
            if (prodigyPrepareRemoteBootstrapPlan(clusterMachine, plan, prepared, bundleApprovalCache, &failure) == false)
            {
               return failBootstrap();
            }

            Vector<ProdigyPreparedRemoteBootstrapPlan> preparedPlans = {};
            preparedPlans.push_back(std::move(prepared));
            if (prodigyExecutePreparedRemoteBootstrapPlans(preparedPlans, nullptr, &failure) == false)
            {
               return failBootstrap();
            }

            return true;
         }

         virtual void stopClusterMachineBootstrap(const ClusterMachine& clusterMachine) const
         {
            ProdigyRemoteBootstrapPlan plan = {};
            if (prodigyResolveClusterMachineSSHAddress(clusterMachine, plan.ssh.address) == false
               || clusterMachine.ssh.user.size() == 0
               || clusterMachine.ssh.hostPublicKeyOpenSSH.size() == 0)
            {
               return;
            }

            plan.ssh.port = clusterMachine.ssh.port > 0 ? clusterMachine.ssh.port : 22;
            plan.ssh.user = clusterMachine.ssh.user;
            plan.ssh.privateKeyPath = clusterMachine.ssh.privateKeyPath;
            plan.ssh.hostPublicKeyOpenSSH = clusterMachine.ssh.hostPublicKeyOpenSSH;
            plan.stopCommand.assign("systemctl stop prodigy"_ctv);

            bool useBootstrapSshKeyPackage = prodigyBootstrapSSHKeyPackageConfigured(brainConfig.bootstrapSshKeyPackage)
               && (plan.ssh.privateKeyPath.size() == 0
                  || plan.ssh.privateKeyPath.equals(brainConfig.bootstrapSshPrivateKeyPath)
                  || ::access(plan.ssh.privateKeyPath.c_str(), R_OK) != 0);
            if (useBootstrapSshKeyPackage == false && plan.ssh.privateKeyPath.size() == 0)
            {
               return;
            }

            LIBSSH2_SESSION *session = nullptr;
            int fd = -1;
            String failure = {};
            if (useBootstrapSshKeyPackage)
            {
               (void)prodigyConnectBlockingSSHSession(
                  plan.ssh.address,
                  plan.ssh.port,
                  plan.ssh.hostPublicKeyOpenSSH,
                  plan.ssh.user,
                  plan.ssh.privateKeyPath,
                  &brainConfig.bootstrapSshKeyPackage,
                  session,
                  fd,
                  &failure);
            }
            else
            {
               (void)prodigyConnectBlockingSSHSession(
                  plan.ssh.address,
                  plan.ssh.port,
                  plan.ssh.hostPublicKeyOpenSSH,
                  plan.ssh.user,
                  plan.ssh.privateKeyPath,
                  session,
                  fd,
                  &failure);
            }
            if (session == nullptr || fd < 0)
            {
               if (session) libssh2_session_free(session);
               if (fd >= 0) ::close(fd);
               return;
            }

            (void)prodigyRunBlockingSSHCommand(session, fd, plan.stopCommand, nullptr);
            libssh2_session_free(session);
            ::close(fd);
         }

         bool resumePendingAddMachinesOperation(uint64_t operationID)
         {
            if (operationID == 0)
            {
               return true;
            }

            ProdigyPendingAddMachinesOperation *persistedOperation = findPendingAddMachinesOperation(operationID);
            if (persistedOperation == nullptr)
            {
               return true;
            }

            String failure = {};
            Vector<ClusterMachine> startedMachines = {};

            if (refreshPendingAddMachinesOperationCreatedMachines(*persistedOperation, failure) == false)
            {
               updatePendingAddMachinesOperationFailure(operationID, failure);
               return false;
            }

            if (persistedOperation->machinesToBootstrap.empty() == false)
            {
               ProdigyRemoteBootstrapBundleApprovalCache bootstrapBundleApprovalCache = {};
               if (prodigyBootstrapItemsConcurrently<ClusterMachine>(
                     persistedOperation->machinesToBootstrap,
                     [this, &persistedOperation, &bootstrapBundleApprovalCache](const ClusterMachine& clusterMachine, String& bootstrapFailure) -> bool {

                        return bootstrapClusterMachineBlocking(
                           clusterMachine,
                           persistedOperation->request,
                           persistedOperation->plannedTopology,
                           bootstrapFailure,
                           &bootstrapBundleApprovalCache);
                     },
                     [this](const ClusterMachine& clusterMachine) -> void {

                        stopClusterMachineBootstrap(clusterMachine);
                     },
                     &startedMachines,
                     failure) == false)
               {
                  for (const ClusterMachine& clusterMachine : startedMachines)
                  {
                     stopClusterMachineBootstrap(clusterMachine);
                  }

                  updatePendingAddMachinesOperationFailure(operationID, failure);
                  return false;
               }
            }

            ClusterTopology mergedTopology = {};
            if (mergePendingAddMachinesTopology(*persistedOperation, mergedTopology, failure) == false)
            {
               updatePendingAddMachinesOperationFailure(operationID, failure);
               return false;
            }

            restoreBrainsFromClusterTopology(mergedTopology);
            restoreMachinesFromClusterTopology(mergedTopology);
            nBrains = clusterTopologyBrainCount(mergedTopology);
            initializeAllBrainPeersIfNeeded();

            if (persistAuthoritativeClusterTopology(mergedTopology) == false)
            {
               updatePendingAddMachinesOperationFailure(persistedOperation->operationID, "failed to persist authoritative cluster topology during addMachines resume"_ctv);
               return false;
            }

            if (nBrains > 1)
            {
               String serializedTopology = {};
               BitseryEngine::serialize(serializedTopology, mergedTopology);
               queueBrainReplication(BrainTopic::replicateClusterTopology, serializedTopology);
            }

            erasePendingAddMachinesOperation(operationID);
            return true;
         }

         void resumePendingAddMachinesOperations(void)
         {
            if (weAreMaster == false || masterAuthorityRuntimeState.pendingAddMachinesOperations.empty())
            {
               return;
            }

            Vector<uint64_t> operationIDs = {};
            operationIDs.reserve(masterAuthorityRuntimeState.pendingAddMachinesOperations.size());
            for (const ProdigyPendingAddMachinesOperation& operation : masterAuthorityRuntimeState.pendingAddMachinesOperations)
            {
               operationIDs.push_back(operation.operationID);
            }

            for (uint64_t operationID : operationIDs)
            {
               if (findPendingAddMachinesOperation(operationID) == nullptr)
               {
                  continue;
               }

               (void)resumePendingAddMachinesOperation(operationID);
            }
         }

			void queueMasterAuthorityRuntimeStateReplication(void)
			{
				refreshMasterAuthorityRuntimeStateFromLiveFields();
				if (weAreMaster == false || nBrains <= 1)
				{
					return;
				}

				if (prodigyDebugDeployHeapEnabled())
				{
					const ProdigyDeployHeapMetrics heap = prodigyReadDeployHeapMetrics();
					std::fprintf(stderr,
						"prodigy debug runtime-state-replication-begin generation=%llu deployments=%zu apps=%zu brains=%zu heapUsed=%llu heapMapped=%llu heapFree=%llu\n",
						(unsigned long long)masterAuthorityRuntimeState.generation,
						size_t(deployments.size()),
						size_t(deploymentsByApp.size()),
						size_t(brains.size()) + 1,
						(unsigned long long)heap.used,
						(unsigned long long)heap.mapped,
						(unsigned long long)heap.free);
					std::fflush(stderr);
				}

				String serialized;
				ProdigyMasterAuthorityRuntimeState replicatedRuntimeState = masterAuthorityRuntimeState;
				replicatedRuntimeState.updateSelf = {};
				BitseryEngine::serialize(serialized, replicatedRuntimeState);

				if (prodigyDebugDeployHeapEnabled())
				{
					const ProdigyDeployHeapMetrics heap = prodigyReadDeployHeapMetrics();
					std::fprintf(stderr,
						"prodigy debug runtime-state-replication-serialized generation=%llu bytes=%zu deployments=%zu apps=%zu heapUsed=%llu heapMapped=%llu heapFree=%llu\n",
						(unsigned long long)masterAuthorityRuntimeState.generation,
						size_t(serialized.size()),
						size_t(deployments.size()),
						size_t(deploymentsByApp.size()),
						(unsigned long long)heap.used,
						(unsigned long long)heap.mapped,
						(unsigned long long)heap.free);
					std::fflush(stderr);
				}
				queueBrainReplication(BrainTopic::replicateMasterAuthorityState, serialized);
			}

			void noteMasterAuthorityRuntimeStateChanged(bool replicate = true, bool persist = true)
			{
				refreshMasterAuthorityRuntimeStateFromLiveFields();
				if (masterAuthorityRuntimeState.generation < UINT64_MAX)
				{
					masterAuthorityRuntimeState.generation += 1;
				}

				if (replicate)
				{
					queueMasterAuthorityRuntimeStateReplication();
				}

				if (persist)
				{
					persistLocalRuntimeState();
				}
			}

			void captureAuthoritativeDeploymentPlans(bytell_hash_map<uint64_t, DeploymentPlan>& plans) const
			{
				plans = deploymentPlans;
				for (const auto& [deploymentID, deployment] : deployments)
				{
					if (deployment == nullptr)
					{
						continue;
					}

					plans.insert_or_assign(deploymentID, deployment->plan);
				}
			}

			void capturePersistentMasterAuthorityPackage(ProdigyPersistentMasterAuthorityPackage& package) const
				{
					package = {};
					package.tlsVaultFactoriesByApp = tlsVaultFactoriesByApp;
					package.apiCredentialSetsByApp = apiCredentialSetsByApp;
					package.reservedApplicationIDsByName = reservedApplicationIDsByName;
					package.reservedApplicationNamesByID = reservedApplicationNamesByID;
					capturePersistentReservedApplicationServices(package.reservedApplicationServices);
					package.nextReservableApplicationID = nextReservableApplicationID;
					captureAuthoritativeDeploymentPlans(package.deploymentPlans);
					package.failedDeployments = failedDeployments;
					package.runtimeState = masterAuthorityRuntimeState;
					package.runtimeState.nextMintedClientTlsGeneration = (nextMintedClientTlsGeneration == 0) ? 1 : nextMintedClientTlsGeneration;
				package.runtimeState.updateSelf = capturePersistentUpdateSelfState();
			}

			void applyPersistentMasterAuthorityPackage(const ProdigyPersistentMasterAuthorityPackage& package)
			{
            Vector<ProdigyManagedMachineSchema> previousSchemas = masterAuthorityRuntimeState.machineSchemas;
					tlsVaultFactoriesByApp = package.tlsVaultFactoriesByApp;
					apiCredentialSetsByApp = package.apiCredentialSetsByApp;
					reservedApplicationIDsByName = package.reservedApplicationIDsByName;
					reservedApplicationNamesByID = package.reservedApplicationNamesByID;
					restorePersistentReservedApplicationServices(package.reservedApplicationServices);
					nextReservableApplicationID = (package.nextReservableApplicationID == 0) ? 1 : package.nextReservableApplicationID;
					deploymentPlans = package.deploymentPlans;
					failedDeployments = package.failedDeployments;
					masterAuthorityRuntimeState = package.runtimeState;
	            if (masterAuthorityRuntimeState.nextPendingAddMachinesOperationID == 0)
            {
               masterAuthorityRuntimeState.nextPendingAddMachinesOperationID = 1;
            }
				nextMintedClientTlsGeneration = (masterAuthorityRuntimeState.nextMintedClientTlsGeneration == 0)
					? 1
					: masterAuthorityRuntimeState.nextMintedClientTlsGeneration;
				restorePersistentUpdateSelfState(masterAuthorityRuntimeState.updateSelf);
            syncManagedMachineSchemaConfigs(previousSchemas, masterAuthorityRuntimeState.machineSchemas);
			}

			bool applyReplicatedMasterAuthorityRuntimeState(const ProdigyMasterAuthorityRuntimeState& incoming, bool persist = true)
			{
				ProdigyMasterAuthorityRuntimeState sanitizedIncoming = incoming;
				sanitizedIncoming.updateSelf = {};
            if (sanitizedIncoming.nextPendingAddMachinesOperationID == 0)
            {
               sanitizedIncoming.nextPendingAddMachinesOperationID = 1;
            }

				bool shouldApply = false;
				if (sanitizedIncoming.generation > masterAuthorityRuntimeState.generation)
				{
					shouldApply = true;
				}
				else if (sanitizedIncoming.generation == masterAuthorityRuntimeState.generation
					&& sanitizedIncoming != masterAuthorityRuntimeState)
				{
					shouldApply = true;
				}

				if (shouldApply == false)
				{
					return false;
				}

            Vector<ProdigyManagedMachineSchema> previousSchemas = masterAuthorityRuntimeState.machineSchemas;
				masterAuthorityRuntimeState = sanitizedIncoming;
				nextMintedClientTlsGeneration = (sanitizedIncoming.nextMintedClientTlsGeneration == 0) ? 1 : sanitizedIncoming.nextMintedClientTlsGeneration;
            syncManagedMachineSchemaConfigs(previousSchemas, masterAuthorityRuntimeState.machineSchemas);

				if (persist)
				{
					persistLocalRuntimeState();
				}

				onMasterAuthorityRuntimeStateApplied();
				return true;
			}

			virtual void onMasterAuthorityRuntimeStateApplied(void)
			{
			}

         virtual bool claimLocalClusterOwnership(uint128_t clusterUUID, String *failure = nullptr)
         {
            (void)clusterUUID;
            if (failure) failure->clear();
            return true;
         }

         static uint64_t wormholeQuicCidRotationIntervalMs(const Wormhole& wormhole)
         {
            uint32_t rotationHours = wormhole.quicCidKeyState.rotationHours;
            if (rotationHours == 0)
            {
               rotationHours = 24;
            }

            return uint64_t(rotationHours) * 60ULL * 60ULL * 1000ULL;
         }

         static void mintWormholeQuicCidKeyMaterial(uint128_t& keyMaterial)
         {
            uint8_t key[16] = {};
            Crypto::fillWithSecureRandomBytes(key, sizeof(key));
            wormholeQuicCidStoreKeyBytes(keyMaterial, key);
         }

         bool ensureWormholeQuicCidKeyState(Wormhole& wormhole, int64_t nowMs, bool allowRotation)
         {
            if (wormholeUsesQuicCidEncryption(wormhole) == false)
            {
               return false;
            }

            bool changed = false;
            if (wormhole.quicCidKeyState.rotationHours == 0)
            {
               wormhole.quicCidKeyState.rotationHours = 24;
               changed = true;
            }

            if (wormhole.quicCidKeyState.activeKeyIndex > 1)
            {
               wormhole.quicCidKeyState.activeKeyIndex &= 0x01;
               changed = true;
            }

            if (wormhole.hasQuicCidKeyState == false)
            {
               mintWormholeQuicCidKeyMaterial(wormhole.quicCidKeyState.keyMaterialByIndex[0]);
               mintWormholeQuicCidKeyMaterial(wormhole.quicCidKeyState.keyMaterialByIndex[1]);
               wormhole.quicCidKeyState.activeKeyIndex = 0;
               wormhole.quicCidKeyState.rotatedAtMs = nowMs;
               wormhole.hasQuicCidKeyState = true;
               return true;
            }

            if (wormhole.quicCidKeyState.rotatedAtMs <= 0)
            {
               wormhole.quicCidKeyState.rotatedAtMs = nowMs;
               changed = true;
            }

            if (allowRotation == false)
            {
               return changed;
            }

            uint64_t rotationIntervalMs = wormholeQuicCidRotationIntervalMs(wormhole);
            if (rotationIntervalMs == 0 || nowMs < wormhole.quicCidKeyState.rotatedAtMs || uint64_t(nowMs - wormhole.quicCidKeyState.rotatedAtMs) < rotationIntervalMs)
            {
               return changed;
            }

            uint8_t nextKeyIndex = wormholeQuicCidInactiveKeyIndex(wormhole.quicCidKeyState);
            mintWormholeQuicCidKeyMaterial(wormhole.quicCidKeyState.keyMaterialByIndex[nextKeyIndex]);
            wormhole.quicCidKeyState.activeKeyIndex = nextKeyIndex;
            wormhole.quicCidKeyState.rotatedAtMs = nowMs;
            wormhole.hasQuicCidKeyState = true;
            return true;
         }

         bool prepareDeploymentPlanWormholeQuicCidState(DeploymentPlan& plan, int64_t nowMs)
         {
            bool changed = false;
            for (Wormhole& wormhole : plan.wormholes)
            {
               if (ensureWormholeQuicCidKeyState(wormhole, nowMs, false))
               {
                  changed = true;
               }
            }

            return changed;
         }

         void applyReplicatedDeploymentPlanLiveState(const DeploymentPlan& plan)
         {
            auto deploymentIt = deployments.find(plan.config.deploymentID());
            if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
            {
               return;
            }

            ApplicationDeployment *deployment = deploymentIt->second;
            deployment->plan = plan;
            for (ContainerView *container : deployment->containers)
            {
               if (container == nullptr)
               {
                  continue;
               }

               container->wormholes = plan.wormholes;
               container->whiteholes = plan.whiteholes;
            }
         }

         bool publishDeploymentWormholeState(ApplicationDeployment *deployment)
         {
            if (deployment == nullptr)
            {
               return false;
            }

            deploymentPlans.insert_or_assign(deployment->plan.config.deploymentID(), deployment->plan);
            applyReplicatedDeploymentPlanLiveState(deployment->plan);

            for (ContainerView *container : deployment->containers)
            {
               if (container == nullptr)
               {
                  continue;
               }

               container->wormholes = deployment->plan.wormholes;
               if (container->state != ContainerState::scheduled
                  && container->state != ContainerState::healthy
                  && container->state != ContainerState::crashedRestarting)
               {
                  continue;
               }

               sendNeuronOpenSwitchboardWormholes(container, container->wormholes);
               sendNeuronRefreshContainerWormholes(container, container->wormholes);
            }

            String serializedPlan = {};
            BitseryEngine::serialize(serializedPlan, deployment->plan);
            if (nBrains > 1)
            {
               queueBrainDeploymentReplication(serializedPlan, ""_ctv);
            }

            persistLocalRuntimeState();
            return true;
         }

         bool refreshDeploymentRegisteredRoutableAddressWormholes(ApplicationDeployment *deployment)
         {
            if (deployment == nullptr)
            {
               return false;
            }

            bool changed = false;
            for (Wormhole& wormhole : deployment->plan.wormholes)
            {
               if (wormhole.source != ExternalAddressSource::registeredRoutableAddress || wormhole.routableAddressUUID == 0)
               {
                  continue;
               }

               IPAddress previousAddress = wormhole.externalAddress;
               String resolveFailure = {};
               if (resolveWormholeRegisteredRoutableAddress(brainConfig.routableAddresses, wormhole, &resolveFailure) == false)
               {
                  continue;
               }

               if (previousAddress.equals(wormhole.externalAddress) == false)
               {
                  changed = true;
               }
            }

            if (changed == false)
            {
               return false;
            }

            return publishDeploymentWormholeState(deployment);
         }

         void refreshAllDeploymentRegisteredRoutableAddressWormholes(void)
         {
            if (weAreMaster == false)
            {
               return;
            }

            for (const auto& [deploymentID, deployment] : deployments)
            {
               (void)deploymentID;
               (void)refreshDeploymentRegisteredRoutableAddressWormholes(deployment);
            }
         }

         bool refreshDeploymentWormholeQuicCidState(ApplicationDeployment *deployment, int64_t nowMs, bool allowRotation)
         {
            if (deployment == nullptr)
            {
               return false;
            }

            if (prepareDeploymentPlanWormholeQuicCidState(deployment->plan, nowMs) == false)
            {
               bool rotated = false;
               for (Wormhole& wormhole : deployment->plan.wormholes)
               {
                  if (ensureWormholeQuicCidKeyState(wormhole, nowMs, allowRotation))
                  {
                     rotated = true;
                  }
               }

               if (rotated == false)
               {
                  return false;
               }
            }
            else
            {
               for (Wormhole& wormhole : deployment->plan.wormholes)
               {
                  (void)ensureWormholeQuicCidKeyState(wormhole, nowMs, allowRotation);
               }
            }

            return publishDeploymentWormholeState(deployment);
         }

         void refreshAllDeploymentWormholeQuicCidState(bool allowRotation)
         {
            if (weAreMaster == false)
            {
               return;
            }

            int64_t nowMs = Time::now<TimeResolution::ms>();
            for (const auto& [deploymentID, deployment] : deployments)
            {
               (void)deploymentID;
               (void)refreshDeploymentWormholeQuicCidState(deployment, nowMs, allowRotation);
            }
         }

			bool validateApplicationTlsVaultFactoryMaterial(const ApplicationTlsVaultFactory& factory, String *failure = nullptr) const
			{
				if (failure) failure->clear();

				X509 *rootCert = VaultPem::x509FromPem(factory.rootCertPem);
				EVP_PKEY *rootKey = VaultPem::privateKeyFromPem(factory.rootKeyPem);
				X509 *intermediateCert = VaultPem::x509FromPem(factory.intermediateCertPem);
				EVP_PKEY *intermediateKey = VaultPem::privateKeyFromPem(factory.intermediateKeyPem);

				bool ok = (rootCert != nullptr)
					&& (rootKey != nullptr)
					&& (intermediateCert != nullptr)
					&& (intermediateKey != nullptr);

				if (ok && X509_check_private_key(rootCert, rootKey) != 1)
				{
					ok = false;
					if (failure) failure->assign("root certificate does not match root key"_ctv);
				}

				if (ok && X509_check_private_key(intermediateCert, intermediateKey) != 1)
				{
					ok = false;
					if (failure) failure->assign("intermediate certificate does not match intermediate key"_ctv);
				}

				if (ok && X509_check_issued(rootCert, intermediateCert) != X509_V_OK)
				{
					ok = false;
					if (failure) failure->assign("intermediate certificate is not issued by root certificate"_ctv);
				}

				if (ok && X509_verify(intermediateCert, rootKey) != 1)
				{
					ok = false;
					if (failure) failure->assign("intermediate certificate signature invalid for root key"_ctv);
				}

				if (rootCert) X509_free(rootCert);
				if (rootKey) EVP_PKEY_free(rootKey);
				if (intermediateCert) X509_free(intermediateCert);
				if (intermediateKey) EVP_PKEY_free(intermediateKey);

				if (ok == false && failure && failure->size() == 0)
				{
					failure->assign("invalid tls vault factory material"_ctv);
				}

				return ok;
			}

				bool isApplicationIDReserved(uint16_t applicationID) const
				{
					return reservedApplicationNamesByID.find(applicationID) != reservedApplicationNamesByID.end();
				}

			bool validateDeploymentApplicationIdentity(const DeploymentPlan& plan, String& failure) const
			{
				(void)plan;
				failure.clear();
				return true;
			}

			static bool containsCredentialName(const Vector<String>& names, const String& target)
			{
				for (const String& name : names)
				{
					if (name.equals(target))
					{
						return true;
					}
				}

				return false;
			}

			const ApiCredential *findApiCredential(const ApplicationApiCredentialSet& set, const String& name) const
			{
				for (const ApiCredential& credential : set.credentials)
				{
					if (credential.name.equals(name))
					{
						return &credential;
					}
				}

				return nullptr;
			}

			bool shouldAcceptTlsFactoryReplication(const ApplicationTlsVaultFactory& incoming, const ApplicationTlsVaultFactory *existing) const
			{
				if (incoming.applicationID == 0)
				{
					return false;
				}

				if (existing == nullptr)
				{
					return true;
				}

				if (incoming.factoryGeneration != existing->factoryGeneration)
				{
					return incoming.factoryGeneration > existing->factoryGeneration;
				}

				return incoming.updatedAtMs >= existing->updatedAtMs;
			}

			bool shouldAcceptApiCredentialSetReplication(const ApplicationApiCredentialSet& incoming, const ApplicationApiCredentialSet *existing) const
			{
				if (incoming.applicationID == 0)
				{
					return false;
				}

				if (existing == nullptr)
				{
					return true;
				}

				if (incoming.setGeneration != existing->setGeneration)
				{
					return incoming.setGeneration > existing->setGeneration;
				}

				return incoming.updatedAtMs >= existing->updatedAtMs;
			}

			bool buildTlsBundleForContainer(const DeploymentPlan& deploymentPlan, const ContainerView& container, CredentialBundle& bundle, uint64_t& bundleGeneration)
			{
				(void)container;
				const bool trace = deploymentPlan.hasTlsIssuancePolicy
					|| deploymentPlan.hasApiCredentialPolicy
					|| deploymentPlan.config.applicationID == 6;

				if (trace)
				{
					basics_log(
						"buildTlsBundleForContainer enter appID=%u hasTlsPolicy=%u tlsAppID=%u enablePerContainerLeafs=%u identityNames=%u existingTls=%u existingApi=%u\n",
						unsigned(deploymentPlan.config.applicationID),
						unsigned(deploymentPlan.hasTlsIssuancePolicy),
						unsigned(deploymentPlan.tlsIssuancePolicy.applicationID),
						unsigned(deploymentPlan.tlsIssuancePolicy.enablePerContainerLeafs),
						unsigned(deploymentPlan.tlsIssuancePolicy.identityNames.size()),
						unsigned(bundle.tlsIdentities.size()),
						unsigned(bundle.apiCredentials.size()));
				}

				if (deploymentPlan.hasTlsIssuancePolicy == false)
				{
					if (trace)
					{
						basics_log("buildTlsBundleForContainer skip appID=%u reason=no_tls_policy\n", unsigned(deploymentPlan.config.applicationID));
					}
					return false;
				}

				const DeploymentTlsIssuancePolicy& tlsPolicy = deploymentPlan.tlsIssuancePolicy;
				if (tlsPolicy.enablePerContainerLeafs == false || tlsPolicy.identityNames.size() == 0)
				{
					if (trace)
					{
						basics_log(
							"buildTlsBundleForContainer skip appID=%u reason=policy_non_issuable enablePerContainerLeafs=%u identityNames=%u\n",
							unsigned(deploymentPlan.config.applicationID),
							unsigned(tlsPolicy.enablePerContainerLeafs),
							unsigned(tlsPolicy.identityNames.size()));
					}
					return false;
				}

				auto factoryIt = tlsVaultFactoriesByApp.find(tlsPolicy.applicationID);
				if (factoryIt == tlsVaultFactoriesByApp.end())
				{
					if (trace)
					{
						basics_log(
							"buildTlsBundleForContainer skip appID=%u reason=factory_missing tlsAppID=%u\n",
							unsigned(deploymentPlan.config.applicationID),
							unsigned(tlsPolicy.applicationID));
					}
					return false;
				}

				const ApplicationTlsVaultFactory& factory = factoryIt->second;
				X509 *interCert = VaultPem::x509FromPem(factory.intermediateCertPem);
				EVP_PKEY *interKey = VaultPem::privateKeyFromPem(factory.intermediateKeyPem);
				if (interCert == nullptr || interKey == nullptr)
				{
					if (trace)
					{
						basics_log(
							"buildTlsBundleForContainer skip appID=%u reason=intermediate_parse_failed cert=%u key=%u factoryGeneration=%llu\n",
							unsigned(deploymentPlan.config.applicationID),
							unsigned(interCert != nullptr),
							unsigned(interKey != nullptr),
							(unsigned long long)factory.factoryGeneration);
					}
					if (interCert) X509_free(interCert);
					if (interKey) EVP_PKEY_free(interKey);
					return false;
				}

				const CryptoScheme scheme = (factory.scheme == uint8_t(CryptoScheme::ed25519)) ? CryptoScheme::ed25519 : CryptoScheme::p256;
				uint32_t validityDays = tlsPolicy.leafValidityDays > 0 ? tlsPolicy.leafValidityDays : factory.defaultLeafValidityDays;
				if (validityDays == 0)
				{
					validityDays = 15;
				}

				int64_t nowMs = Time::now<TimeResolution::ms>();
				bool produced = false;

				for (const String& identityName : tlsPolicy.identityNames)
				{
					if (identityName.size() == 0)
					{
						continue;
					}

					X509 *leafCert = nullptr;
					EVP_PKEY *leafKey = nullptr;
					VaultCertificateRequest request = {};
					request.type = CertificateType::server;
					request.scheme = scheme;
					request.subjectCommonName = identityName;
					request.enableServerAuth = true;
					generateCertificateAndKeys(request, interCert, interKey, leafCert, leafKey);
					if (leafCert == nullptr || leafKey == nullptr)
					{
						if (leafCert) X509_free(leafCert);
						if (leafKey) EVP_PKEY_free(leafKey);
						continue;
					}

					X509_gmtime_adj(X509_getm_notBefore(leafCert), 0);
					X509_time_adj_ex(X509_getm_notAfter(leafCert), int(validityDays), 0, nullptr);
					(void)X509_sign(leafCert, interKey, (scheme == CryptoScheme::ed25519) ? nullptr : EVP_sha256());

					TlsIdentity identity;
					identity.name.assign(identityName);
					identity.generation = factory.factoryGeneration;
					identity.notBeforeMs = nowMs;
					identity.notAfterMs = nowMs + int64_t(validityDays) * 24 * 60 * 60 * 1000;

					bool ok = VaultPem::x509ToPem(leafCert, identity.certPem) && VaultPem::privateKeyToPem(leafKey, identity.keyPem);
					if (ok)
					{
						identity.chainPem.assign(factory.intermediateCertPem);
						identity.chainPem.append(factory.rootCertPem);
						bundle.tlsIdentities.push_back(identity);
						produced = true;
					}

					if (leafCert) X509_free(leafCert);
					if (leafKey) EVP_PKEY_free(leafKey);
				}

				X509_free(interCert);
				EVP_PKEY_free(interKey);

				if (produced && factory.factoryGeneration > bundleGeneration)
				{
					bundleGeneration = factory.factoryGeneration;
				}

				if (trace)
				{
					basics_log(
						"buildTlsBundleForContainer done appID=%u produced=%u tlsIdentities=%u bundleGeneration=%llu factoryGeneration=%llu\n",
						unsigned(deploymentPlan.config.applicationID),
						unsigned(produced),
						unsigned(bundle.tlsIdentities.size()),
						(unsigned long long)bundleGeneration,
						(unsigned long long)factory.factoryGeneration);
				}

				return produced;
			}

			bool buildCredentialBundleForContainer(const DeploymentPlan& deploymentPlan, const ContainerView& container, CredentialBundle& bundle)
			{
				bundle.tlsIdentities.clear();
				bundle.apiCredentials.clear();
				bundle.bundleGeneration = 0;

				bool produced = false;
				uint64_t bundleGeneration = 0;

				if (deploymentPlan.hasApiCredentialPolicy)
				{
					const DeploymentApiCredentialPolicy& apiPolicy = deploymentPlan.apiCredentialPolicy;
					if (auto setIt = apiCredentialSetsByApp.find(apiPolicy.applicationID); setIt != apiCredentialSetsByApp.end())
					{
						const ApplicationApiCredentialSet& set = setIt->second;
						for (const String& requiredName : apiPolicy.requiredCredentialNames)
						{
							if (const ApiCredential *credential = findApiCredential(set, requiredName); credential != nullptr)
							{
								bundle.apiCredentials.push_back(*credential);
								produced = true;
							}
						}

						if (set.setGeneration > bundleGeneration)
						{
							bundleGeneration = set.setGeneration;
						}
					}
				}

				if (buildTlsBundleForContainer(deploymentPlan, container, bundle, bundleGeneration))
				{
					produced = true;
				}

				bundle.bundleGeneration = produced ? bundleGeneration : 0;
				return produced;
			}

			void applyCredentialsToContainerPlan(const DeploymentPlan& deploymentPlan, const ContainerView& container, ContainerPlan& plan) override
			{
				const bool trace = deploymentPlan.hasTlsIssuancePolicy
					|| deploymentPlan.hasApiCredentialPolicy
					|| deploymentPlan.config.applicationID == 6;
				CredentialBundle bundle;
				if (buildCredentialBundleForContainer(deploymentPlan, container, bundle))
				{
					plan.hasCredentialBundle = true;
					plan.credentialBundle = std::move(bundle);
				}
				else
				{
					plan.hasCredentialBundle = false;
					plan.credentialBundle = CredentialBundle();
				}

				if (trace)
				{
					basics_log(
						"applyCredentialsToContainerPlan appID=%u containerUUID=%llu hasTlsPolicy=%u hasBundle=%u tlsIdentities=%u apiCredentials=%u bundleGeneration=%llu enablePerContainerLeafs=%u\n",
						unsigned(deploymentPlan.config.applicationID),
						(unsigned long long)container.uuid,
						unsigned(deploymentPlan.hasTlsIssuancePolicy),
						unsigned(plan.hasCredentialBundle),
						unsigned(plan.credentialBundle.tlsIdentities.size()),
						unsigned(plan.credentialBundle.apiCredentials.size()),
						(unsigned long long)plan.credentialBundle.bundleGeneration,
						unsigned(deploymentPlan.hasTlsIssuancePolicy ? deploymentPlan.tlsIssuancePolicy.enablePerContainerLeafs : false));
				}
			}

			void pushApiCredentialDeltaToLiveContainers(uint16_t applicationID, const ApplicationApiCredentialSet& set, const Vector<String>& updatedNames, const Vector<String>& removedNames, const String& reason)
			{
				if (updatedNames.size() == 0 && removedNames.size() == 0)
				{
					return;
				}

				for (const auto& [deploymentID, deployment] : deployments)
				{
					(void)deploymentID;
					if (deployment == nullptr) continue;
					if (deployment->plan.config.applicationID != applicationID) continue;
					if (deployment->plan.hasApiCredentialPolicy == false) continue;

					const DeploymentApiCredentialPolicy& policy = deployment->plan.apiCredentialPolicy;
					if (policy.refreshPushEnabled == false)
					{
						continue;
					}

					CredentialDelta delta;
					delta.bundleGeneration = set.setGeneration;
					if (reason.size() > 0)
					{
						delta.reason.assign(reason);
					}
					else
					{
						delta.reason.assign("api-credential-set-upsert"_ctv);
					}

					for (const String& requiredName : policy.requiredCredentialNames)
					{
						if (containsCredentialName(updatedNames, requiredName))
						{
							if (const ApiCredential *credential = findApiCredential(set, requiredName); credential != nullptr)
							{
								delta.updatedApi.push_back(*credential);
							}
						}

						if (containsCredentialName(removedNames, requiredName))
						{
							delta.removedApiNames.push_back(requiredName);
						}
					}

					if (delta.updatedApi.size() == 0 && delta.removedApiNames.size() == 0)
					{
						continue;
					}

					String serializedDelta;
					if (ProdigyWire::serializeCredentialDelta(serializedDelta, delta) == false)
					{
						continue;
					}

					for (ContainerView *container : deployment->containers)
					{
						if (container == nullptr)
						{
							continue;
						}

						switch (container->state)
						{
							case ContainerState::scheduled:
							case ContainerState::healthy:
							case ContainerState::crashedRestarting:
							{
								container->proxySend(NeuronTopic::refreshContainerCredentials, container->uuid, serializedDelta);
								break;
							}
							default: break;
						}
					}
				}
			}

	Brain()
	{
		mesh = new Mesh();
		initializeApplicationIDReservationState();
		initializeApplicationServiceReservationState();
	}

	uint128_t selfBrainUUID(void) const
	{
		if (thisNeuron == nullptr)
		{
			return 0;
		}

		return thisNeuron->uuid;
	}

	static int compareIPAddresses(const IPAddress& lhs, const IPAddress& rhs)
	{
		if (lhs.is6 != rhs.is6)
		{
			return lhs.is6 ? 1 : -1;
		}

		if (lhs.is6)
		{
			return memcmp(lhs.v6, rhs.v6, sizeof(lhs.v6));
		}

		if (lhs.v4 < rhs.v4)
		{
			return -1;
		}

		if (lhs.v4 > rhs.v4)
		{
			return 1;
		}

		return 0;
	}

	void collectLocalBrainCandidateAddresses(Vector<IPAddress>& localAddresses) const
	{
		localAddresses.clear();

		if (thisNeuron == nullptr)
		{
			return;
		}

      Vector<ClusterMachinePeerAddress> candidates;
      String preferredInterface = {};
      preferredInterface.assign(thisNeuron->eth.name);
      prodigyCollectLocalPeerAddressCandidates(preferredInterface, thisNeuron->private4, candidates);

      for (const ClusterMachinePeerAddress& candidate : candidates)
      {
         IPAddress parsedAddress = {};
         if (ClusterMachine::parseIPAddressLiteral(candidate.address, parsedAddress) == false)
         {
            continue;
         }

         bool alreadyPresent = false;
         for (const IPAddress& existing : localAddresses)
         {
            if (existing.equals(parsedAddress))
            {
               alreadyPresent = true;
               break;
            }
         }

         if (alreadyPresent == false)
         {
            localAddresses.push_back(parsedAddress);
         }
      }
	}

   void adoptLocalBrainPeerAddresses(const Vector<ClusterMachinePeerAddress>& candidates)
   {
      localBrainPeerAddresses.clear();
      for (const ClusterMachinePeerAddress& candidate : candidates)
      {
         prodigyAppendUniqueClusterMachinePeerAddress(localBrainPeerAddresses, candidate);
      }

      if (localBrainPeerAddresses.empty())
      {
         return;
      }

      bool currentStillPresent = false;
      for (const ClusterMachinePeerAddress& candidate : localBrainPeerAddresses)
      {
         if (candidate.address.equals(localBrainPeerAddressText))
         {
            currentStillPresent = true;
            break;
         }
      }

      if (currentStillPresent)
      {
         return;
      }

      IPAddress address = {};
      String addressText = {};
      if (ClusterMachine::parseIPAddressLiteral(localBrainPeerAddresses[0].address, address))
      {
         addressText.assign(localBrainPeerAddresses[0].address);
         adoptLocalBrainPeerAddress(address, addressText);
      }
   }

   void refreshLocalBrainPeerAddresses(void)
   {
      if (thisNeuron == nullptr)
      {
         localBrainPeerAddresses.clear();
         return;
      }

      Vector<ClusterMachinePeerAddress> candidates;
      String preferredInterface = {};
      preferredInterface.assign(thisNeuron->eth.name);
      prodigyCollectLocalPeerAddressCandidates(preferredInterface, thisNeuron->private4, candidates);
      if (candidates.empty() == false)
      {
         ClusterTopology topology = {};
         ClusterMachine self = {};
         self.isBrain = true;
         prodigyAssignClusterMachineAddressesFromPeerCandidates(self.addresses, candidates);
         topology.machines.push_back(self);
         prodigyNormalizeClusterTopologyPeerAddresses(topology);
         prodigyCollectClusterMachinePeerAddresses(topology.machines[0], candidates);
      }

      adoptLocalBrainPeerAddresses(candidates);
      if (thisNeuron != nullptr)
      {
         Machine *machine = nullptr;
         if (thisNeuron->uuid != 0)
         {
            if (auto it = machinesByUUID.find(thisNeuron->uuid); it != machinesByUUID.end())
            {
               machine = it->second;
            }
         }

         if (machine == nullptr)
         {
            for (Machine *candidateMachine : machines)
            {
               if (candidateMachine && candidateMachine->isThisMachine)
               {
                  machine = candidateMachine;
                  break;
               }
            }
         }

         if (machine != nullptr)
         {
            machine->peerAddresses = localBrainPeerAddresses;
            if (machine->privateAddress.size() == 0 && localBrainPeerAddressText.size() > 0)
            {
               machine->privateAddress = localBrainPeerAddressText;
            }
         }
      }
   }

   void adoptLocalMachineHardwareProfile(const MachineHardwareProfile& hardware) override
   {
      Machine *machine = nullptr;
      if (thisNeuron != nullptr && thisNeuron->uuid != 0)
      {
         if (auto it = machinesByUUID.find(thisNeuron->uuid); it != machinesByUUID.end())
         {
            machine = it->second;
         }
      }

      if (machine == nullptr)
      {
         for (Machine *candidateMachine : machines)
         {
            if (candidateMachine && candidateMachine->isThisMachine)
            {
               machine = candidateMachine;
               break;
            }
         }
      }

      if (machine == nullptr)
      {
         return;
      }

      applyMachineHardwareProfile(machine, hardware);
      if (machine->state != MachineState::healthy
         && machineReadyForHealthyState(machine))
      {
         handleMachineStateChange(machine, MachineState::healthy);
      }
   }

   void replayLocalMachineHardwareProfileIfReady(void)
   {
      if (thisNeuron == nullptr)
      {
         return;
      }

      thisNeuron->ensureDeferredHardwareInventoryProgress();
      if (const MachineHardwareProfile *hardware = thisNeuron->latestHardwareProfileIfReady(); hardware != nullptr)
      {
         adoptLocalMachineHardwareProfile(*hardware);
      }
   }

	bool localBrainAddressMatches(const IPAddress& address) const
	{
		if (address.isNull() || thisNeuron == nullptr)
		{
			return false;
		}

		Vector<IPAddress> localAddresses;
		collectLocalBrainCandidateAddresses(localAddresses);

		for (const IPAddress& localAddress : localAddresses)
		{
			if (localAddress.equals(address))
			{
				return true;
			}
		}

		return false;
	}

	void adoptLocalBrainPeerAddress(const IPAddress& address, const String& addressText)
	{
		if (address.isNull() == false)
		{
			localBrainPeerAddress = address;
		}

		if (addressText.size() > 0)
		{
			localBrainPeerAddressText = addressText;
		}
		else if (localBrainPeerAddress.isNull() == false)
		{
			(void)ClusterMachine::renderIPAddressLiteral(localBrainPeerAddress, localBrainPeerAddressText);
		}

      ClusterMachinePeerAddress candidate = {};
      if (localBrainPeerAddressText.size() > 0)
      {
         candidate.address.assign(localBrainPeerAddressText);
      }
      else if (localBrainPeerAddress.isNull() == false)
      {
         (void)ClusterMachine::renderIPAddressLiteral(localBrainPeerAddress, candidate.address);
      }

      if (candidate.address.size() > 0)
      {
         prodigyAppendUniqueClusterMachinePeerAddress(localBrainPeerAddresses, candidate);
      }
	}

	bool resolveLocalBrainPeerAddressFromIaaS(void)
	{
		if (iaas == nullptr)
		{
			return false;
		}

		IPAddress address = {};
		String addressText = {};
		if (iaas->resolveLocalBrainPeerAddress(address, addressText) == false)
		{
			return false;
		}

		adoptLocalBrainPeerAddress(address, addressText);
		return true;
	}

	bool shouldWeConnectToBrain(const BrainView *brain) const
	{
		if (brain == nullptr)
		{
			return false;
		}

		Vector<ClusterMachinePeerAddress> localCandidates = localBrainPeerAddresses;
		if (localCandidates.empty() && thisNeuron != nullptr)
		{
			String preferredInterface = {};
			preferredInterface.assign(thisNeuron->eth.name);
			prodigyCollectLocalPeerAddressCandidates(preferredInterface, thisNeuron->private4, localCandidates);
			if (localCandidates.empty() == false)
			{
				ClusterTopology topology = {};
				ClusterMachine self = {};
				self.isBrain = true;
				prodigyAssignClusterMachineAddressesFromPeerCandidates(self.addresses, localCandidates);
				topology.machines.push_back(self);
				prodigyNormalizeClusterTopologyPeerAddresses(topology);
				prodigyCollectClusterMachinePeerAddresses(topology.machines[0], localCandidates);
			}
		}

		Vector<ClusterMachinePeerAddress> peerCandidates = brain->peerAddresses;
		if (peerCandidates.empty())
		{
			if (brain->peerAddressText.size() > 0)
			{
				peerCandidates.push_back(ClusterMachinePeerAddress{brain->peerAddressText, 0});
			}
			else if (brain->peerAddress.isNull() == false)
			{
				String peerAddressText = {};
				if (ClusterMachine::renderIPAddressLiteral(brain->peerAddress, peerAddressText))
				{
					peerCandidates.push_back(ClusterMachinePeerAddress{peerAddressText, 0});
				}
			}
			else if (brain->private4 != 0)
			{
				IPAddress peerAddress = {};
				peerAddress.v4 = brain->private4;
				peerAddress.is6 = false;
				String peerAddressText = {};
				if (ClusterMachine::renderIPAddressLiteral(peerAddress, peerAddressText))
				{
					peerCandidates.push_back(ClusterMachinePeerAddress{peerAddressText, 0});
				}
			}
		}

		for (const ClusterMachinePeerAddress& peerCandidate : peerCandidates)
		{
			IPAddress peerAddress = {};
			if (ClusterMachine::parseIPAddressLiteral(peerCandidate.address, peerAddress) == false)
			{
				continue;
			}

			IPAddress preferredSelfAddress = {};
			if (prodigyResolvePreferredLocalSourceAddress(localCandidates, peerCandidate, preferredSelfAddress))
			{
				int addressCmp = compareIPAddresses(preferredSelfAddress, peerAddress);
				if (addressCmp != 0)
				{
					return addressCmp < 0;
				}
			}

			for (const ClusterMachinePeerAddress& localCandidate : localCandidates)
			{
				IPAddress selfAddress = {};
				if (ClusterMachine::parseIPAddressLiteral(localCandidate.address, selfAddress) == false)
				{
					continue;
				}

				if (selfAddress.is6 != peerAddress.is6)
				{
					continue;
				}

				int addressCmp = compareIPAddresses(selfAddress, peerAddress);
				if (addressCmp != 0)
				{
					return addressCmp < 0;
				}
			}
		}

		IPAddress selfAddress = localBrainPeerAddress;
		if (selfAddress.isNull() && thisNeuron != nullptr && thisNeuron->private4.v4 != 0)
		{
			selfAddress = thisNeuron->private4;
		}

		IPAddress peerAddress = brain->peerAddress;
		if (peerAddress.isNull() && brain->private4 != 0)
		{
			peerAddress = {};
			peerAddress.v4 = brain->private4;
			peerAddress.is6 = false;
		}

		if (selfAddress.isNull() == false && peerAddress.isNull() == false)
		{
			int addressCmp = compareIPAddresses(selfAddress, peerAddress);
			if (addressCmp != 0)
			{
				return addressCmp < 0;
			}
		}

		if (thisNeuron != nullptr && brain->uuid != 0 && thisNeuron->uuid != brain->uuid)
		{
			return thisNeuron->uuid < brain->uuid;
		}

		return false;
	}

	uint128_t getExistingMasterUUID(void) const
	{
		uint128_t existingMasterUUID = 0;

		if (weAreMaster)
		{
			existingMasterUUID = selfBrainUUID();
		}
		else if (noMasterYet == false)
		{
			for (BrainView *bv : brains)
			{
				if (bv->isMasterBrain)
				{
					existingMasterUUID = bv->uuid;
					break;
				}
			}
		}

		return existingMasterUUID;
	}

   void queueLocalPeerAddressCandidates(BrainView *brain)
   {
      if (brain == nullptr || brain->canQueueSend() == false)
      {
         return;
      }

      if (localBrainPeerAddresses.empty())
      {
         refreshLocalBrainPeerAddresses();
      }

      if (localBrainPeerAddresses.empty())
      {
         return;
      }

      String serializedCandidates = {};
      BitseryEngine::serialize(serializedCandidates, localBrainPeerAddresses);
      Message::construct(brain->wBuffer, BrainTopic::peerAddressCandidates, serializedCandidates);
      Ring::queueSend(brain);
   }

   bool updateBrainPeerAddressCandidates(BrainView *brain, const Vector<ClusterMachinePeerAddress>& candidates)
   {
      if (brain == nullptr || candidates.empty())
      {
         return false;
      }

      Vector<ClusterMachinePeerAddress> normalizedCandidates;
      for (const ClusterMachinePeerAddress& candidate : candidates)
      {
         prodigyAppendUniqueClusterMachinePeerAddress(normalizedCandidates, candidate);
      }

      if (normalizedCandidates.empty())
      {
         return false;
      }

      if (prodigyClusterMachinePeerAddressesEqual(brain->peerAddresses, normalizedCandidates))
      {
         return false;
      }

      adoptBrainPeerAddresses(brain, normalizedCandidates);
      if (brain->machine != nullptr)
      {
         brain->machine->peerAddresses = brain->peerAddresses;
         if (brain->machine->privateAddress.size() == 0 && brain->peerAddressText.size() > 0)
         {
            brain->machine->privateAddress = brain->peerAddressText;
         }
      }
      else
      {
         synchronizeBrainUUIDToMachine(brain);
      }

      if (weAreMaster == false)
      {
         return true;
      }

      ClusterTopology topology = {};
      if (loadAuthoritativeClusterTopology(topology) == false || topology.machines.empty())
      {
         return true;
      }

      bool updatedTopology = false;
      for (ClusterMachine& clusterMachine : topology.machines)
      {
         if (clusterMachine.isBrain == false)
         {
            continue;
         }

         bool matchesPeer = (brain->uuid != 0 && clusterMachine.uuid != 0 && clusterMachine.uuid == brain->uuid);
         if (matchesPeer == false && brain->machine != nullptr)
         {
            matchesPeer = prodigyClusterMachineMatchesMachineIdentity(clusterMachine, *brain->machine);
         }

         if (matchesPeer == false)
         {
            for (const ClusterMachinePeerAddress& candidate : normalizedCandidates)
            {
               IPAddress candidateAddress = {};
               if (ClusterMachine::parseIPAddressLiteral(candidate.address, candidateAddress) && clusterMachine.peerAddressMatches(candidateAddress, &candidate.address))
               {
                  matchesPeer = true;
                  break;
               }
            }
         }

         if (matchesPeer == false)
         {
            continue;
         }

         prodigyAssignClusterMachineAddressesFromPeerCandidates(clusterMachine.addresses, normalizedCandidates);

         updatedTopology = true;
         break;
      }

      if (updatedTopology == false)
      {
         return true;
      }

      prodigyNormalizeClusterTopologyPeerAddresses(topology);
      topology.version += 1;
      if (persistAuthoritativeClusterTopology(topology) == false)
      {
         return false;
      }

      String serializedTopology = {};
      BitseryEngine::serialize(serializedTopology, topology);
      queueBrainReplication(BrainTopic::replicateClusterTopology, serializedTopology);
      sendNeuronSwitchboardOverlayRoutes();
      return true;
   }

	uint128_t resolveConsistentExistingMasterUUID(void) const
	{
		uint128_t existingMasterUUID = 0;
		bool conflictingExistingMasterUUID = false;

		for (BrainView *brain : brains)
		{
			if (peerEligibleForClusterQuorum(brain) == false)
			{
				continue;
			}

			if (brain->existingMasterUUID == 0)
			{
				continue;
			}

			if (existingMasterUUID == 0)
			{
				existingMasterUUID = brain->existingMasterUUID;
			}
			else if (existingMasterUUID != brain->existingMasterUUID)
			{
				conflictingExistingMasterUUID = true;
				break;
			}
		}

		return conflictingExistingMasterUUID ? uint128_t(0) : existingMasterUUID;
	}

	uint128_t deriveRegisteredMasterUUID(void) const
	{
		uint128_t masterUUID = 0;
		uint128_t selfUUID = selfBrainUUID();
		if (selfUUID != 0)
		{
			masterUUID = selfUUID;
		}

		for (BrainView *bv : brains)
		{
			if (peerEligibleForClusterQuorum(bv) == false || bv->boottimens == 0 || bv->uuid == 0)
			{
				continue;
			}

			if (masterUUID == 0 || bv->uuid < masterUUID)
			{
				masterUUID = bv->uuid;
			}
		}

		return masterUUID;
	}

	bool activeBrainRegistrationsReadyForMasterElection(void)
	{
		if (selfBrainUUID() == 0 || boottimens == 0)
		{
			return false;
		}

		for (BrainView *bv : brains)
		{
			if (peerEligibleForClusterQuorum(bv) == false)
			{
				continue;
			}

			if (peerSocketActive(bv) == false)
			{
				continue;
			}

			if (bv->uuid == 0 || bv->boottimens == 0)
			{
				return false;
			}
		}

		return true;
	}

	bool resolveFailoverMasterByActivePeerAddressOrder(bool& preferSelf, bool *sawActivePeer = nullptr)
	{
		preferSelf = false;
		if (sawActivePeer != nullptr)
		{
			*sawActivePeer = false;
		}

		if (thisNeuron == nullptr || thisNeuron->private4.isNull())
		{
			return false;
		}

		uint32_t selfPrivate4 = thisNeuron->private4.v4;
		if (selfPrivate4 == 0)
		{
			return false;
		}

		preferSelf = true;
		bool sawComparableActivePeer = false;
		bool sawIncompleteActivePeer = false;
		for (BrainView *bv : brains)
		{
			if (peerEligibleForClusterQuorum(bv) == false)
			{
				continue;
			}

			if (peerSocketActive(bv) == false)
			{
				continue;
			}

			if (sawActivePeer != nullptr)
			{
				*sawActivePeer = true;
			}

			if (bv->private4 == 0)
			{
				basics_log("failoverAddressOrder skip-incomplete peer=%p uuid=%llu connected=%d quarantined=%d isFixed=%d fslot=%d\n",
					static_cast<void *>(bv),
					(unsigned long long)bv->uuid,
					int(bv->connected),
					int(bv->quarantined),
					int(bv->isFixedFile),
					bv->fslot);
				sawIncompleteActivePeer = true;
				continue;
			}

			sawComparableActivePeer = true;
			basics_log("failoverAddressOrder compare selfPrivate4=%u peerPrivate4=%u peerUUID=%llu preferSelfBefore=%d\n",
				unsigned(selfPrivate4),
				unsigned(bv->private4),
				(unsigned long long)bv->uuid,
				int(preferSelf));
			if (bv->private4 < selfPrivate4)
			{
				preferSelf = false;
			}
		}

		if (sawComparableActivePeer)
		{
			basics_log("failoverAddressOrder resolved selfPrivate4=%u preferSelf=%d incomplete=%d\n",
				unsigned(selfPrivate4),
				int(preferSelf),
				int(sawIncompleteActivePeer));
			return true;
		}

		if (sawIncompleteActivePeer)
		{
			preferSelf = false;
			basics_log("failoverAddressOrder waiting selfPrivate4=%u reason=incomplete-active-peer\n", unsigned(selfPrivate4));
			return false;
		}

		basics_log("failoverAddressOrder selfPrivate4=%u no-active-peers\n", unsigned(selfPrivate4));
		return true;
	}

	bool peerEligibleForClusterQuorum(BrainView *peer) const
	{
		if (peer == nullptr || peer->quarantined)
		{
			return false;
		}

		if (thisNeuron != nullptr)
		{
			if (peer->private4 != 0 && peer->private4 == thisNeuron->private4.v4)
			{
				return false;
			}

			uint128_t selfUUID = selfBrainUUID();
			if (selfUUID != 0 && peer->uuid != 0 && peer->uuid == selfUUID)
			{
				return false;
			}
		}

		return true;
	}

		uint64_t connectFailureLogKey(uint8_t socketKind, uint32_t private4, int result, bool quarantined) const
		{
			uint64_t key = 0;
			key |= (uint64_t(socketKind & 0x03u) << 62);
			key |= (uint64_t(private4) << 30);
			key |= (uint64_t(uint16_t(result)) << 14);
			key |= (quarantined ? (uint64_t(1) << 13) : 0);
			return key;
		}

		bool shouldLogConnectFailure(uint64_t key, uint32_t attemptNumber, uint32_t attemptBudget)
		{
			int64_t nowMs = Time::now<TimeResolution::ms>();
			int64_t &nextLogAtMs = connectFailureNextLogMsByKey[key];

			// Emit immediately on the first attempt for a failure-mode key, then gate repeats.
			if (attemptNumber == 1)
			{
				if (nextLogAtMs == 0 || nowMs >= nextLogAtMs)
				{
					nextLogAtMs = nowMs + connectFailureLogIntervalMs;
					return true;
				}
			}
			else if (attemptNumber == attemptBudget)
			{
				// Keep a periodic terminal-attempt heartbeat while the peer is unreachable.
				if (nextLogAtMs == 0 || nowMs >= nextLogAtMs)
				{
					nextLogAtMs = nowMs + connectFailureLogIntervalMs;
					return true;
				}
			}

			return false;
		}

		void recoverDeploymentsAfterNeuronState(void)
		{
			if (weAreMaster == false || ignited == false)
			{
				return;
			}

			for (const auto& [applicationID, head] : deploymentsByApp)
			{
				(void)applicationID;
				if (head == nullptr) continue;
				head->recoverAfterReboot();
			}
		}

	template <typename T>
	int loggableSocketFD(T *socket) const
	{
		if (socket == nullptr)
		{
			return -1;
		}

		if (socket->isFixedFile)
		{
			return Ring::getFDFromFixedFileSlot(socket->fslot);
		}

		return socket->fd;
	}

	void logMothershipReceiveBufferHead(const char *stage, Mothership *stream)
	{
		if (stream == nullptr)
		{
			return;
		}

		uint64_t outstanding = stream->rBuffer.outstandingBytes();
		uint32_t peekSize = 0;
		uint8_t sample[16] = {0};
		if (outstanding >= sizeof(uint32_t))
		{
			memcpy(&peekSize, stream->rBuffer.pHead(), sizeof(uint32_t));
		}

		uint64_t sampleCount = (outstanding < sizeof(sample) ? outstanding : sizeof(sample));
		if (sampleCount > 0)
		{
			memcpy(sample, stream->rBuffer.pHead(), sampleCount);
		}

			std::fprintf(stderr,
				"prodigy mothership %s outstanding=%llu peekSize=%u sampleBytes=%llu sample=%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x stream=%p fixedFD=%d fslot=%d master=%d\n",
				stage,
			(unsigned long long)outstanding,
			unsigned(peekSize),
			(unsigned long long)sampleCount,
			unsigned(sample[0]),
			unsigned(sample[1]),
			unsigned(sample[2]),
			unsigned(sample[3]),
			unsigned(sample[4]),
			unsigned(sample[5]),
			unsigned(sample[6]),
			unsigned(sample[7]),
			unsigned(sample[8]),
			unsigned(sample[9]),
			unsigned(sample[10]),
			unsigned(sample[11]),
			unsigned(sample[12]),
				unsigned(sample[13]),
				unsigned(sample[14]),
				unsigned(sample[15]),
				static_cast<void *>(stream),
				loggableSocketFD(stream),
				stream->fslot,
				int(weAreMaster));
		std::fflush(stderr);
	}

	void acceptHandler(void *socket, int fslot) override
	{
		if (socket == (void *)&brainSocket)
		{
			if (fslot >= 0)
			{
				IPAddress remoteAddress = {};
				String remoteAddressText = {};
				if (prodigySockaddrToIPAddress(reinterpret_cast<struct sockaddr *>(&brain_saddr), remoteAddress, &remoteAddressText) == false)
				{
					basics_log("brain accept unknown sockaddr family=%d fslot=%d\n", int(brain_saddr.ss_family), fslot);
					Ring::queueCloseRaw(fslot);
					brain_saddrlen = sizeof(brain_saddr);
								Ring::queueAccept(&brainSocket, reinterpret_cast<struct sockaddr*>(&brain_saddr), &brain_saddrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
					return;
				}

				BrainView *brain = nullptr;
				brain = findBrainViewByPeerAddress(remoteAddress);

				if (brain == nullptr && remoteAddress.is6 == false)
				{
					brain = findBrainViewByPrivate4(remoteAddress.v4);
				}

					if (brain)
					{
					if (peerSocketActive(brain))
					{
						uint128_t updateSelfPeerKey = updateSelfPeerTrackingKey(brain);
						bool expectedUpdateFollowerReconnect = (
							weAreMaster
							&& updateSelfState == UpdateSelfState::waitingForFollowerReboots
							&& updateSelfPeerKey != 0
							&& updateSelfFollowerBootNsByPeerKey.contains(updateSelfPeerKey));
						if (expectedUpdateFollowerReconnect)
						{
							std::fprintf(stderr,
								"prodigy updateProdigy follower-accept-replace private4=%u peerKey=%llu oldFslot=%d newFslot=%d\n",
								brain->private4,
								(unsigned long long)updateSelfPeerKey,
								brain->fslot,
								fslot);
							std::fflush(stderr);
							abandonSocketGeneration(brain);
						}
						else
						{
						// Connector ownership only decides who should initiate. If a known
						// peer has already established a live socket, keep that single
						// stream and drop only true duplicates.
						// Keep a single active accepted stream per peer.
						Ring::queueCloseRaw(fslot);
						brain_saddrlen = sizeof(brain_saddr);
						Ring::queueAccept(&brainSocket, reinterpret_cast<struct sockaddr*>(&brain_saddr), &brain_saddrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
						return;
						}
					}

					if (auto it = brainWaiters.find(brain); it != brainWaiters.end())
					{
						// possible it's already completed and is in the CQE queue, so this is the only way to cancel it without segfaulting
						TimeoutPacket *packet = it->second;
						packet->flags = uint64_t(BrainTimeoutFlags::canceled);

						brainWaiters.erase(it);
					}

						if (rawStreamIsActive(brain))
						{
							abandonSocketGeneration(brain);
						}

						// Accepted reconnects must not inherit buffered plaintext/ciphertext
						// or stale peer-verification state from the prior stream generation.
						// Keep the broader BrainView identity/runtime intact and scrub only
						// the transport buffers that can block fresh registration parsing.
						brain->fslot = fslot;
						brain->isFixedFile = true;
						brain->isNonBlocking = true;
						std::fprintf(stderr,
							"prodigy debug brain accept-known private4=%u fd=%d fslot=%d updateState=%u oldConnected=%d oldQuarantined=%d\n",
							brain->private4,
							brain->fd,
							brain->fslot,
							unsigned(updateSelfState),
							int(brain->connected),
							int(brain->quarantined));
						std::fflush(stderr);
						Ring::queueSetSockOptRaw(brain, SOL_TCP, TCP_CONGESTION, "dctcp", socklen_t(strlen("dctcp")), "brain accepted peer congestion");
							Ring::queueSetSockOptInt(brain, SOL_SOCKET, SO_KEEPALIVE, 1, "brain accepted peer keepalive");
							Ring::queueSetSockOptInt(brain, SOL_TCP, TCP_KEEPIDLE, int(std::max<uint32_t>(brainPeerKeepaliveSeconds, 1u)), "brain accepted peer keepidle");
							Ring::queueSetSockOptInt(brain, SOL_TCP, TCP_KEEPINTVL, int(std::max<uint32_t>(brainPeerKeepaliveSeconds / 3, 1u)), "brain accepted peer keepintvl");
							Ring::queueSetSockOptInt(brain, SOL_TCP, TCP_KEEPCNT, 3, "brain accepted peer keepcnt");
							if (ProdigyTransportTLSRuntime::configured() && brain->beginTransportTLS(true) == false)
							{
							queueCloseIfActive(brain);
							brain_saddrlen = sizeof(brain_saddr);
							Ring::queueAccept(&brainSocket, reinterpret_cast<struct sockaddr*>(&brain_saddr), &brain_saddrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
							return;
						}

				if (brain->quarantined) brainFound(brain);
				brain->connected = true;
				if (updateSelfState == UpdateSelfState::waitingForFollowerReboots)
				{
					uint128_t peerKey = updateSelfPeerTrackingKey(brain);
					if (peerKey != 0 && updateSelfFollowerBootNsByPeerKey.contains(peerKey))
					{
						updateSelfFollowerReconnectedPeerKeys.insert(peerKey);
					}
				}

				brain->sendRegistration(boottimens, version, getExistingMasterUUID());
            queueLocalPeerAddressCandidates(brain);
				queueUpdateSelfBundleToPeer(brain);
				queueUpdateSelfTransitionToPeer(brain);
				queueUpdateSelfRelinquishToPeer(brain);

						// they will send us a registration too
						Ring::queueRecv(brain);
						std::fprintf(stderr,
							"prodigy debug brain recv-armed private4=%u fd=%d fslot=%d pendingRecv=%d pendingSend=%d tls=%d negotiated=%d queuedBytes=%llu\n",
							brain->private4,
							brain->fd,
							brain->fslot,
							int(brain->pendingRecv),
							int(brain->pendingSend),
							int(brain->transportTLSEnabled()),
							int(brain->isTLSNegotiated()),
							(unsigned long long)brain->queuedSendOutstandingBytes());
						std::fflush(stderr);
					}
					else
					{
						basics_log("brain accept unknown peer address=%s fslot=%d\n", remoteAddressText.c_str(), fslot);
						Ring::queueCloseRaw(fslot); // we could put even better protections in here later.... maybe crypto keys
					}
				}

			brain_saddrlen = sizeof(brain_saddr);
			Ring::queueAccept(&brainSocket, reinterpret_cast<struct sockaddr*>(&brain_saddr), &brain_saddrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
		}
				else if (socket == (void *)&mothershipSocket)
					{
						mothershipAcceptArmed = false;
						std::fprintf(stderr, "prodigy mothership accept transport=tcp result=%d master=%d existing=%p listenerFD=%d listenerFslot=%d\n",
							fslot,
							int(weAreMaster),
							static_cast<void *>(mothership),
							mothershipSocket.fd,
							mothershipSocket.fslot);
						std::fflush(stderr);

						if (fslot >= 0)
						{
							if (weAreMaster == false)
							{
								// Followers never own commander control-plane sockets.
								std::fprintf(stderr, "prodigy mothership accept-close transport=tcp reason=follower acceptedFslot=%d\n", fslot);
								std::fflush(stderr);
								Ring::queueCloseRaw(fslot);
							}
							else if (mothership)
							{
								// Keep a single active mothership control stream per brain.
								// Close duplicate accepts and keep the existing stream stable.
								std::fprintf(stderr, "prodigy mothership accept-close transport=tcp reason=duplicate acceptedFslot=%d existingFD=%d existingFslot=%d\n",
									fslot,
									mothership->fd,
									mothership->fslot);
								std::fflush(stderr);
								Ring::queueCloseRaw(fslot);
							}
							else
							{
								mothership = new Mothership();
								mothership->fslot = fslot;
								mothership->isFixedFile = true;
								mothership->isNonBlocking = true;
								const int fixedFD = loggableSocketFD(mothership);
								std::fprintf(stderr, "prodigy mothership accept-adopt transport=tcp source=cqe acceptedFslot=%d fixedFD=%d isFixed=%d\n",
									fslot,
									fixedFD,
									int(mothership->isFixedFile));
								std::fflush(stderr);

								RingDispatcher::installMultiplexee(mothership, this);
								queueMothershipReceiveIfNeeded(mothership, "accept-tcp-cqe");
							}
						}

							if (weAreMaster)
							{
								// Keep the listener continuously armed so rapid mothership retries
								// are accepted and explicitly rejected instead of filling backlog.
							queueMothershipListenersIfNeeded();
						}
					}
					else if (socket == (void *)&mothershipUnixSocket)
					{
						mothershipUnixAcceptArmed = false;
						std::fprintf(stderr, "prodigy mothership accept transport=unix result=%d master=%d existing=%p listenerPath=%s listenerFD=%d listenerFslot=%d\n",
							fslot,
							int(weAreMaster),
							static_cast<void *>(mothership),
							mothershipUnixSocketPath.c_str(),
							mothershipUnixSocket.fd,
							mothershipUnixSocket.fslot);
						std::fflush(stderr);

						if (fslot >= 0)
						{
							if (weAreMaster == false)
							{
								std::fprintf(stderr, "prodigy mothership accept-close transport=unix reason=follower acceptedFslot=%d path=%s\n",
									fslot,
									mothershipUnixSocketPath.c_str());
								std::fflush(stderr);
								Ring::queueCloseRaw(fslot);
							}
							else if (mothership)
							{
								std::fprintf(stderr, "prodigy mothership accept-close transport=unix reason=duplicate acceptedFslot=%d existingFD=%d existingFslot=%d path=%s\n",
									fslot,
									mothership->fd,
									mothership->fslot,
									mothershipUnixSocketPath.c_str());
								std::fflush(stderr);
								Ring::queueCloseRaw(fslot);
							}
							else
							{
								mothership = new Mothership();
								mothership->fslot = fslot;
								mothership->isFixedFile = true;
								mothership->isNonBlocking = true;
								const int fixedFD = loggableSocketFD(mothership);
								std::fprintf(stderr, "prodigy mothership accept-adopt transport=unix source=cqe acceptedFslot=%d fixedFD=%d isFixed=%d path=%s\n",
									fslot,
									fixedFD,
									int(mothership->isFixedFile),
									mothershipUnixSocketPath.c_str());
								std::fflush(stderr);

								RingDispatcher::installMultiplexee(mothership, this);
								queueMothershipReceiveIfNeeded(mothership, "accept-unix-cqe");
							}
						}

						if (weAreMaster)
						{
							queueMothershipListenersIfNeeded();
						}
					}
			}

	void connectHandler(void *socket, int result) override
	{
			if (brains.contains(static_cast<BrainView *>(socket)))
			{
				BrainView *brain = static_cast<BrainView *>(socket);

				if (result == 0) // connected to brain
				{
					if (Ring::socketIsClosing(brain) || brain->isFixedFile == false || brain->fslot < 0)
					{
						return;
					}

					brain->connected = true;
					std::fprintf(stderr,
						"prodigy debug brain connect-ok private4=%u fd=%d fslot=%d updateState=%u weConnectToIt=%d\n",
						brain->private4,
						brain->fd,
						brain->fslot,
						unsigned(updateSelfState),
						int(brain->weConnectToIt));
					std::fflush(stderr);
					if (updateSelfState == UpdateSelfState::waitingForFollowerReboots)
					{
						std::fprintf(stderr, "prodigy updateProdigy peer-connect-ok private4=%u\n", brain->private4);
						std::fflush(stderr);
						uint128_t peerKey = updateSelfPeerTrackingKey(brain);
						if (peerKey != 0 && updateSelfFollowerBootNsByPeerKey.contains(peerKey))
						{
							updateSelfFollowerReconnectedPeerKeys.insert(peerKey);
						}
					}
					brain->connectAttemptSucceded();
					brain->rBuffer.clear();
					if (ProdigyTransportTLSRuntime::configured() && brain->beginTransportTLS(false) == false)
					{
						if (updateSelfState == UpdateSelfState::waitingForFollowerReboots)
						{
							std::fprintf(stderr, "prodigy updateProdigy peer-connect-tls-fail private4=%u\n", brain->private4);
							std::fflush(stderr);
						}
						queueCloseIfActive(brain);
						return;
					}
				// reset failure streak on success
				if (brain->machine)
				{
					brain->machine->brainConnectFailStreak = 0;
				}

				if (brain->quarantined) brainFound(brain);

				// it might have already registered with us... but that data could be old... it could've rebooted
				brain->sendRegistration(boottimens, version, getExistingMasterUUID());
            queueLocalPeerAddressCandidates(brain);
				queueUpdateSelfBundleToPeer(brain);
				queueUpdateSelfTransitionToPeer(brain);
				queueUpdateSelfRelinquishToPeer(brain);

				// We always need to receive the peer's registration/replication stream after connect.
				Ring::queueRecv(brain);
				std::fprintf(stderr,
					"prodigy debug brain recv-armed private4=%u fd=%d fslot=%d pendingRecv=%d pendingSend=%d tls=%d negotiated=%d queuedBytes=%llu\n",
					brain->private4,
					brain->fd,
					brain->fslot,
					int(brain->pendingRecv),
					int(brain->pendingSend),
					int(brain->transportTLSEnabled()),
					int(brain->isTLSNegotiated()),
					(unsigned long long)brain->queuedSendOutstandingBytes());
				std::fflush(stderr);
				}
				else
				{
					brain->connected = false;
					if (updateSelfState == UpdateSelfState::waitingForFollowerReboots)
					{
						std::fprintf(stderr,
							"prodigy updateProdigy peer-connect-fail private4=%u result=%d attempts=%u budget=%u\n",
							brain->private4,
							result,
							brain->nConnectionAttempts + 1,
							brain->getAttemptBudget());
						std::fflush(stderr);
					}
						uint32_t attemptNumber = brain->nConnectionAttempts + 1;
						uint32_t attemptBudget = brain->getAttemptBudget();
						uint64_t logKey = connectFailureLogKey(1, brain->private4, result, brain->quarantined);
						if (shouldLogConnectFailure(logKey, attemptNumber, attemptBudget))
						{
							basics_log("brain connect failed stream=%p private4=%u result=%d fslot=%d weConnectToIt=%d quarantined=%d attempt=%u/%u\n",
								static_cast<void *>(brain), brain->private4, result, brain->fslot, int(brain->weConnectToIt), int(brain->quarantined), attemptNumber, attemptBudget);
						}
					queueCloseIfActive(brain);

				if (brain->connectAttemptFailed())
				{
					if (brain->machine)
					{
						brain->machine->brainConnectFailStreak += 1;
						brain->machine->lastNeuronFailMs = Time::now<TimeResolution::ms>();
					}
					brainMissing(brain);
				}
			}
		}
		else if (neurons.contains(static_cast<NeuronView *>(socket)))
		{
			NeuronView *neuron = static_cast<NeuronView *>(socket);

				if (result == 0) // connected to neuron
				{
					if (Ring::socketIsClosing(neuron) || neuron->isFixedFile == false || neuron->fslot < 0)
					{
						return;
					}

					bool reconnecting = neuron->hadSuccessfulConnection;
					neuron->connected = true;
					neuron->hadSuccessfulConnection = true;
					basics_log("brain neuron connect ok stream=%p uuid=%llu private4=%u fd=%d fslot=%d tlsConfigured=%d\n",
						static_cast<void *>(neuron),
						(unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
						unsigned(neuron->machine ? neuron->machine->private4 : 0u),
						neuron->fd,
						neuron->fslot,
						int(ProdigyTransportTLSRuntime::configured()));
					neuron->connectAttemptSucceded();
					neuron->rBuffer.clear();
					if (ProdigyTransportTLSRuntime::configured() && neuron->beginTransportTLS(false) == false)
					{
						queueCloseIfActive(neuron);
						return;
					}

				// reset failure streak on success; clear binary update flag
				if (neuron->machine)
				{
					neuron->machine->neuronConnectFailStreak = 0;
					neuron->machine->inBinaryUpdate = false;
				}

				uint64_t pendingBytes = neuron->wBuffer.outstandingBytes();
				if (reconnecting && pendingBytes > 0)
				{
					// Reconnect starts a new stream generation; do not replay buffered payloads
					// from the prior connection because partial delivery state is unknowable.
					neuron->wBuffer.clear();
				}

				Message::construct(neuron->wBuffer, NeuronTopic::registration, ignited);
				Ring::queueSend(neuron);
				basics_log("brain neuron connect arm stream=%p uuid=%llu private4=%u fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d needsSendKick=%d wbytes=%u queued=%llu\n",
					static_cast<void *>(neuron),
					(unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
					unsigned(neuron->machine ? neuron->machine->private4 : 0u),
					neuron->fd,
					neuron->fslot,
					int(neuron->pendingSend),
					int(neuron->pendingRecv),
					int(neuron->isTLSNegotiated()),
					int(neuron->needsTransportTLSSendKick()),
					unsigned(neuron->wBuffer.size()),
					(unsigned long long)neuron->queuedSendOutstandingBytes());

				// the neuron will now send us its state
				Ring::queueRecv(neuron);
				basics_log("brain neuron recv arm stream=%p uuid=%llu private4=%u fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d needsSendKick=%d wbytes=%u queued=%llu\n",
					static_cast<void *>(neuron),
					(unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
					unsigned(neuron->machine ? neuron->machine->private4 : 0u),
					neuron->fd,
					neuron->fslot,
					int(neuron->pendingSend),
					int(neuron->pendingRecv),
					int(neuron->isTLSNegotiated()),
					int(neuron->needsTransportTLSSendKick()),
					unsigned(neuron->wBuffer.size()),
					(unsigned long long)neuron->queuedSendOutstandingBytes());

				// The initial neuron-control TLS exchange is queued from inside the connect
				// completion handler. Submit those SQEs immediately so the control channel can
				// begin progressing before unrelated control-plane work re-enters the loop.
				Ring::submitPending();
			}
				else
				{
						uint32_t attemptNumber = neuron->nConnectionAttempts + 1;
						uint32_t attemptBudget = neuron->getAttemptBudget();
						uint32_t machinePrivate4 = (neuron->machine ? neuron->machine->private4 : 0);
						uint64_t logKey = connectFailureLogKey(2, machinePrivate4, result, false);
						if (shouldLogConnectFailure(logKey, attemptNumber, attemptBudget))
						{
							basics_log("neuron connect failed private4=%u result=%d fslot=%d attempt=%u/%u\n",
								machinePrivate4, result, neuron->fslot, attemptNumber, attemptBudget);
						}
					queueCloseIfActive(neuron);

				if (neuron->connectAttemptFailed())
				{
					if (neuron->machine)
					{
						neuron->machine->neuronConnectFailStreak += 1;
						neuron->machine->lastNeuronFailMs = Time::now<TimeResolution::ms>();
					}
					handleMachineStateChange(neuron->machine, MachineState::missing);
				}
			}
		}
			else if (sshs.contains(static_cast<MachineSSH *>(socket)))
			{
				MachineSSH *ssh = static_cast<MachineSSH *>(socket);

				if (result == 0) // connected to brain
				{
					if (Ring::socketIsClosing(ssh))
					{
						return;
					}

					ssh->connectAttemptSucceded();
					ssh->execute();
				}
				else
				{
						Machine *sshMachine = nullptr;
						if (ssh->machine && machines.contains(ssh->machine))
						{
							sshMachine = ssh->machine;
						}

						basics_log("ssh connect failed machine=%u result=%d fd=%d fslot=%d fixed=%d\n",
							(sshMachine ? uint32_t(sshMachine->private4) : 0), result, ssh->fd, ssh->fslot, int(ssh->isFixedFile));
						queueCloseIfActive(ssh);

					if (ssh->connectAttemptFailed())
					{
						// we've failed out on connection tries
						// only master brain

						if (sshMachine)
						{
							handleMachineStateChange(sshMachine, MachineState::unresponsive);
						}
					}
				}
			}
		else
		{
			basics_log("connect handler unmatched socket=%p result=%d\n", socket, result);
		}
	}

	void brainFound(BrainView *brain)
	{
		// a brain we had quarantined reappeared... either the network restored OR we restarted the neuron program or the machine itself
		brain->boottimens = 0; // this will block any new master derivation until after it has registered
		brain->quarantined = false;
		brain->weConnectToIt = shouldWeConnectToBrain(brain);
		if (brain->weConnectToIt)
		{
			configureBrainPeerConnectAddress(brain);
		}
	}

   float calculateAliveBrainRatio(void)
   {
      uint32_t nBrainsAlive = 1;

		for (BrainView *bv : brains)
		{
			if (bv->quarantined == false) nBrainsAlive += 1;
		}

      // nBrains is computed as peers + self during getBrains().
      return (nBrains > 0)
                 ? float(nBrainsAlive) / float(nBrains)
                 : 0.0f;
   }

	void brainMissing(BrainView *brain)
	{
		brain->connected = false;
		bool expectedUpdateFollowerReboot = (
			updateSelfState == UpdateSelfState::waitingForFollowerReboots &&
			updateSelfFollowerBootNsByPeerKey.contains(updateSelfPeerTrackingKey(brain)));

		// During coordinated updateProdigy follower reboots, temporary peer loss is expected.
		// Keep the reconnect path armed, but suppress the failure remediation/election
		// side effects until the reboot-registration window completes.

		// we either got here because we failed 3 times in a row trying to connect (or reconnect) to a brain, OR we were never connected to / the connection broke and they never
		// reconnected to us

		bool firstMissingTransition = (brain->quarantined == false);
		brain->weConnectToIt = shouldWeConnectToBrain(brain);
		// On first missing transition, extend outbound reconnect attempts so transient
		// outages can heal without dropping reconnect permanently after the default budget.
		if (brain->weConnectToIt && firstMissingTransition)
		{
			configureBrainPeerConnectAddress(brain);
			brain->nConnectionAttempts = 0;
			brain->reconnectAfterClose = true;

			int64_t recoveryReconnectWindowMs = int64_t(brain->connectTimeoutMs) * int64_t(brain->nDefaultAttemptsBudget);
			if (recoveryReconnectWindowMs < prodigyBrainPeerRecoveryReconnectMinMs)
			{
				recoveryReconnectWindowMs = prodigyBrainPeerRecoveryReconnectMinMs;
			}

			if (brain->connectTimeoutMs > 0)
			{
				brain->attemptForMs(recoveryReconnectWindowMs);
			}
			else
			{
				brain->nAttemptsBudget = brain->nDefaultAttemptsBudget;
			}
		}

		if (expectedUpdateFollowerReboot)
		{
			if (weAreMaster && brain->weConnectToIt)
			{
				armOutboundPeerReconnect(brain);
			}

			co_return;
		}

		// One-time side effects (quarantine transition, majority/election flow) only on first missing transition.
		if (firstMissingTransition)
		{
			brain->quarantined = true;
			brain->existingMasterUUID = 0;
			basics_log("brainMissing private4=%u weAreMaster=%d peerWasMaster=%d weConnectToIt=%d\n",
				brain->private4, int(weAreMaster), int(brain->isMasterBrain), int(brain->weConnectToIt));

			// Master-side fallback: if a peer link drops, proactively dial it even when
			// canonical connector ownership is the opposite direction. This prevents
			// post-fault mesh stranding with zero established :313 links.
			if (weAreMaster)
			{
				armOutboundPeerReconnect(brain, true);
			}

			if (weAreMaster)
			{
				masterQuorumDegraded = true;
				bool retainMaster = shouldRetainMasterControlOnBrainLoss();
				if (retainMaster)
				{
					// Do not evacuate machine containers from a brain-link miss alone.
					// Network partitions can isolate the master from peers without machine failure,
					// and aggressive evacuation here causes destructive split-brain churn.
					// Machine/neuron health paths remain the source of truth for draining.
				}
				else
				{
					// no majority so we definitely forfeit master status
					forfeitMasterStatus();
				}
			}
				else
				{
					if (brain->isMasterBrain)
					{
						// the master brain is missing
						isMasterMissing = true;
						basics_log("brainMissing detected master private4=%u, starting masterMissing gossip\n", brain->private4);

						for (BrainView *bv : brains)
						{
							if (bv->quarantined == false)
							{
								// tell it the master is lost to us
								// chat with the other peers to see if they agree
								// then we'd select a new master
								// a major utiltiy of this is to test connectivity... it's possible this breaks the connection.. aka this would cascade the failure discovery
								bv->sendMasterMissing();

								// and if they all fail, we'll end up in our if (allQuarantined) bracket below
							}
						}

							// Do not derive immediately here.
							// We must wait for masterMissing gossip responses so an isolated minority
							// cannot self-elect from stale socket state and create split-brain.
							// Election is triggered from BrainTopic::masterMissing agreement handling.
					}

					if (isMasterMissing) // if master fails first, then the other brain fails, we'd run through here twice, otherwise once
					{
						bool allQuarantined = true;

					for (BrainView *bv : brains)
					{
						if (bv->quarantined == false)
						{
							allQuarantined = false;
							break;
						}
					}

						if (allQuarantined) // we could only be isolated if every brain connection fails.. aka all quarantined.. so this can only run once, one all have failed
						{
							basics_log("brainMissing all peers quarantined; evaluating isolated election nBrains=%u\n", nBrains);

							// In multi-brain clusters, isolated self-election is unsafe and can
							// create split-brain during transient partitions/heal windows.
							// Stay degraded and keep reconnecting until quorum gossip can derive.
							if (nBrains > 1)
							{
								co_return;
							}

							// Single-brain compatibility path.
							resetMasterBrainAssignment();
							basics_log("brainMissing elect-self reason=single-brain-isolation\n");
							selfElectAsMaster("brainMissing:single-brain-isolation");
					}
					else
					{
						// wait on those peers to respond about the missing master.. we would need a majority to elect (or if they all fail and their switches are still alive
						// we'd self elect in the above bracket)
					}
				}
			}
		}
	}

	void closeHandler(void *socket) override
	{
		if (socket == (void *)&brainSocket)
		{
			basics_log("brain listener socket closed private4=%u; rearming\n", thisNeuron->private4.v4);
			RingDispatcher::eraseMultiplexee(&brainSocket);

			brainSocket.recreateSocket();
			brainSocket.setIPVersion(AF_INET6);
			setsockopt(brainSocket.fd, IPPROTO_IPV6, IPV6_V6ONLY, (const int[]){0}, sizeof(int));
			brainSocket.setKeepaliveTimeoutSeconds(brainPeerKeepaliveSeconds);
			brainSocket.setSaddr("::"_ctv, uint16_t(ReservedPorts::brain));
			brainSocket.bindThenListen();

			RingDispatcher::installMultiplexee(&brainSocket, this);
			Ring::installFDIntoFixedFileSlot(&brainSocket);
			brain_saddrlen = sizeof(brain_saddr);
				Ring::queueAccept(&brainSocket, reinterpret_cast<struct sockaddr *>(&brain_saddr), &brain_saddrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
			co_return;
		}

			if (brains.contains(static_cast<BrainView *>(socket)))
			{
				BrainView *brain = static_cast<BrainView *>(socket);
				uint128_t updateSelfPeerKey = updateSelfPeerTrackingKey(brain);
				std::fprintf(stderr,
					"prodigy debug brain close private4=%u fd=%d fslot=%d updateState=%u weConnectToIt=%d peerKey=%llu\n",
					brain->private4,
					brain->fd,
					brain->fslot,
					unsigned(updateSelfState),
					int(brain->weConnectToIt),
					(unsigned long long)updateSelfPeerKey);
				std::fflush(stderr);
				if (updateSelfPeerKey != 0)
				{
					updateSelfBundleIssuedPeerKeys.erase(updateSelfPeerKey);
					// Keep the transition one-shot sticky across the intentional follower
					// reboot close. Reissuing it on reconnect can bounce the fresh process
					// again before its registration lands and the master credits the reboot.
					updateSelfRelinquishIssuedPeerKeys.erase(updateSelfPeerKey);
				}
				brain->connected = false;
            bool expectedUpdateFollowerReboot = (
               updateSelfState == UpdateSelfState::waitingForFollowerReboots &&
               updateSelfFollowerBootNsByPeerKey.contains(updateSelfPeerTrackingKey(brain)));

				brain->cancelSuspended();

			if (brain->weConnectToIt)
			{
				// this connection might've broken spuriously, or due to a network failure (maybe discovered when we sent a masterMissing message)
				// but regardless try to reconnect, if not we'll then assume and handle the failure
				if (brain->shouldReconnect())
				{
					// A connector-owned peer must discard the full prior transport
					// generation before redialing. Reusing stale TLS/BIO/send state
					// here can trap the mesh in connect/close churn against the same peer.
					brain->reset();
					brain->recreateSocket();
					configureBrainPeerConnectAddress(brain);
					if (installBrainPeerSocket(brain))
					{
						brain->attemptConnect();
					}
				}
				else
				{
					// Keep connector-owned peer links persistently re-armed while the cluster
					// runs. A transient partition can outlive the default reconnect budget
					// and otherwise strand the mesh with no active brain links.
					brain->reset();
					brain->recreateSocket();
					configureBrainPeerConnectAddress(brain);
					brain->nConnectionAttempts = 0;
					brain->reconnectAfterClose = true;

					int64_t reconnectWindowMs = int64_t(brain->connectTimeoutMs) * int64_t(brain->nDefaultAttemptsBudget);
					if (reconnectWindowMs < prodigyBrainPeerPersistentReconnectMinMs)
					{
						reconnectWindowMs = prodigyBrainPeerPersistentReconnectMinMs;
					}

					if (brain->connectTimeoutMs > 0)
					{
						brain->attemptForMs(reconnectWindowMs);
					}
					else
					{
						brain->nAttemptsBudget = brain->nDefaultAttemptsBudget;
					}

					if (installBrainPeerSocket(brain))
					{
						brain->attemptConnect();
					}
				}
			}
			else
			{
				// Wait one full inbound reconnect window plus a small slack so the
				// owner brain has a fair chance to redial before we quarantine it.
				// During coordinated follower reboots we still need this waiter armed;
				// skipping it can strand the master with no recovery path for the
				// rebooted accepted peer.

				TimeoutPacket *timeout = new TimeoutPacket();
				timeout->flags = uint64_t(BrainTimeoutFlags::brainMissing);
				timeout->originator = brain;
				timeout->dispatcher = this;
				timeout->setTimeoutMs(brain->nDefaultAttemptsBudget * brain->connectTimeoutMs + prodigyBrainPeerInboundMissingSlackMs);

				brainWaiters.insert_or_assign(brain, timeout);
				Ring::queueTimeout(timeout);
			}
		}
		else if (neurons.contains(static_cast<NeuronView *>(socket)))
		{
			NeuronView *neuron = static_cast<NeuronView *>(socket);
			neuron->connected = false;

			neuron->cancelSuspended();
			basics_log("brain neuron close stream=%p uuid=%llu private4=%u reconnect=%d fd=%d isFixed=%d fslot=%d\n",
				static_cast<void *>(neuron),
				(unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
				unsigned(neuron->machine ? neuron->machine->private4 : 0u),
				int(neuron->reconnectAfterClose),
				neuron->fd,
				int(neuron->isFixedFile),
				neuron->fslot);

				if (weAreMaster && neuron->shouldReconnect())
				{
					neuron->rBuffer.clear();
					neuron->recreateSocket();
					if (installNeuronControlSocket(neuron))
					{
						neuron->attemptConnect();
					}
				}
				else
				{
					disarmNeuronControlReconnect(neuron);
				}
			}
						else if (socket == (void *)&mothershipSocket)
						{
							basics_log("mothership listener socket closed weAreMaster=%d\n", int(weAreMaster));
							mothershipAcceptArmed = false;
							RingDispatcher::eraseMultiplexee(&mothershipSocket);

						if (weAreMaster)
					{
						armMothershipListener();
					}
				}
						else if (socket == (void *)&mothershipUnixSocket)
						{
							basics_log("mothership unix listener socket closed weAreMaster=%d path=%s\n", int(weAreMaster), mothershipUnixSocketPath.c_str());
							mothershipUnixAcceptArmed = false;
							RingDispatcher::eraseMultiplexee(&mothershipUnixSocket);

						if (weAreMaster)
						{
							armMothershipUnixListener();
						}
					}
					else if (socket == (void *)mothership)
					{
							basics_log("mothership stream closed weAreMaster=%d\n", int(weAreMaster));
                     clearSpinApplicationMothershipsForStream(mothership);
							RingDispatcher::eraseMultiplexee(mothership); // it'll reconnect to us
							delete mothership;
						mothership = nullptr;
						if (weAreMaster)
						{
							queueMothershipListenersIfNeeded();
						}
					}
					else if (closingMotherships.contains(static_cast<Mothership *>(socket)))
					{
							Mothership *closingStream = static_cast<Mothership *>(socket);
							basics_log("mothership retired stream closed weAreMaster=%d closingStreams=%zu\n",
								int(weAreMaster),
								size_t(closingMotherships.size()));
                     clearSpinApplicationMothershipsForStream(closingStream);
							RingDispatcher::eraseMultiplexee(closingStream);
						closingMotherships.erase(closingStream);
						delete closingStream;
						if (weAreMaster)
						{
							queueMothershipListenersIfNeeded();
						}
					}
		else if (sshs.contains(static_cast<MachineSSH *>(socket)))
		{
			MachineSSH *ssh = static_cast<MachineSSH *>(socket);

			ssh->cancelSuspended();

			if (ssh->shouldReconnect())
			{
				ssh->recreateSocket();
				ssh->attemptConnect();

					// mark as rebooting neuron during SSH restart flow
					if (ssh->machine) ssh->machine->state = MachineState::neuronRebooting;
			}
			else
			{
				// failure logic handled in connect handler
				// also possible this succeded and is now being destroyed
				sshs.erase(ssh);
				RingDispatcher::eraseMultiplexee(ssh);
				delete ssh;
			}
		}
	}

	void pollHandler(void *socket, int result) override
	{
			MachineSSH *ssh = static_cast<MachineSSH *>(socket);

		if (result & (POLLHUP | POLLERR))
		{
			Ring::queueClose(ssh);

			// it failed.... so we'd end up trying to reconnect and start again
		}
		else
		{
			ssh->co_consume();
		}
	}

		void assignMachineFragment(Machine *machine)
		{
			bool fakeIPv4Mode = false;
			#if NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE
			if (const char *mode = getenv("PRODIGY_DEV_FAKE_IPV4_MODE"); mode && mode[0] == '1' && mode[1] == '\0')
			{
				fakeIPv4Mode = true;
			}
			#endif

				do
				{
					if (fakeIPv4Mode)
					{
						IPAddress preferredAddress = {};
						uint32_t preferred = 0;
						if (prodigyResolveMachinePeerAddress(*machine, preferredAddress))
						{
							preferred = preferredAddress.is6
								? uint32_t(preferredAddress.v6[15])
								: (ntohl(preferredAddress.v4) & 0xFFu);
						}
						else if (machine->private4 != 0)
						{
							preferred = ntohl(machine->private4) & 0xFFu;
						}
						if (preferred == 0)
						{
							preferred = 1;
						}

					machine->fragment = 0;
					for (uint32_t offset = 0; offset < 255; ++offset)
					{
						uint32_t candidate = ((preferred + offset - 1u) % 255u) + 1u;
						if (usedMachineFragments.contains(candidate) == false)
						{
							machine->fragment = candidate;
							break;
						}
					}

					if (machine->fragment == 0)
					{
						machine->fragment = Random::generateNumberWithNBits<24, uint32_t>();
					}
				}
				else
				{
					machine->fragment = Random::generateNumberWithNBits<24, uint32_t>();
				}

			} while (usedMachineFragments.contains(machine->fragment));

		usedMachineFragments.insert(machine->fragment);

		struct local_container_subnet6 lcsubnet6;
		lcsubnet6.dpfx = brainConfig.datacenterFragment;
		lcsubnet6.mpfx[0] = static_cast<uint8_t>((machine->fragment >> 16) & 0xFF);
		lcsubnet6.mpfx[1] = static_cast<uint8_t>((machine->fragment >> 8) & 0xFF);
		lcsubnet6.mpfx[2] = static_cast<uint8_t>(machine->fragment & 0xFF);

		uint32_t headerOffset = Message::appendHeader(machine->neuron.wBuffer, NeuronTopic::assignFragment);
		Message::appendAlignedBuffer<Alignment::one>(machine->neuron.wBuffer, reinterpret_cast<uint8_t *>(&lcsubnet6), sizeof(struct local_container_subnet6));
		Message::finish(machine->neuron.wBuffer, headerOffset);

		if (streamIsActive(&machine->neuron))
		{
			Ring::queueSend(&machine->neuron);
		}

      sendNeuronSwitchboardOverlayRoutes();
	}

		void relinquishMachineFragment(Machine *machine)
		{
			usedMachineFragments.erase(machine->fragment);
			machine->fragment = 0;
	      sendNeuronSwitchboardOverlayRoutes();
		}

		bool machineReadyForHealthyState(Machine *machine) const
		{
			if (machine == nullptr)
			{
				return false;
			}

			if (neuronControlStreamActive(machine) == false)
			{
				return false;
			}

			// A connected neuron socket alone is not sufficient to host work. The
			// machine must have completed hardware inventory and received a container
			// subnet fragment before we advertise it as healthy to deployment
			// scheduling.
			if (machine->hardware.inventoryComplete == false || machine->fragment == 0)
			{
				return false;
			}

			return prodigyMachineReadyResourcesAvailable(*machine);
		}

      static void ownMachineConfig(const MachineConfig& source, MachineConfig& owned)
      {
         owned = {};
         owned.kind = source.kind;
         owned.slug.assign(source.slug);
         owned.ipxeScriptURL.assign(source.ipxeScriptURL);
         owned.vmImageURI.assign(source.vmImageURI);
         owned.gcpInstanceTemplate.assign(source.gcpInstanceTemplate);
         owned.gcpInstanceTemplateSpot.assign(source.gcpInstanceTemplateSpot);
         owned.nLogicalCores = source.nLogicalCores;
         owned.nMemoryMB = source.nMemoryMB;
         owned.nStorageMB = source.nStorageMB;
         owned.providesHostPublic4 = source.providesHostPublic4;
         owned.providesHostPublic6 = source.providesHostPublic6;
      }

      static void ownDistributableExternalSubnet(const DistributableExternalSubnet& source, DistributableExternalSubnet& owned)
      {
         owned = {};
         owned.uuid = source.uuid;
         owned.name.assign(source.name);
         owned.subnet = source.subnet;
         owned.routing = source.routing;
         owned.usage = source.usage;
      }

      static void ownRegisteredRoutableAddress(const RegisteredRoutableAddress& source, RegisteredRoutableAddress& owned)
      {
         owned = {};
         owned.uuid = source.uuid;
         owned.name.assign(source.name);
         owned.kind = source.kind;
         owned.family = source.family;
         owned.machineUUID = source.machineUUID;
         owned.address = source.address;
         owned.providerPool.assign(source.providerPool);
         owned.providerAllocationID.assign(source.providerAllocationID);
         owned.providerAssociationID.assign(source.providerAssociationID);
         owned.releaseOnRemove = source.releaseOnRemove;
      }

      static void ownRuntimeEnvironmentConfig(const ProdigyRuntimeEnvironmentConfig& source, ProdigyRuntimeEnvironmentConfig& owned)
      {
         prodigyOwnRuntimeEnvironmentConfig(source, owned);
         prodigyStripManagedCloudBootstrapCredentials(owned);
      }

      static void ownBrainConfig(const BrainConfig& source, BrainConfig& owned)
      {
         owned = {};
         for (const auto& [slug, machineConfig] : source.configBySlug)
         {
            String ownedSlug = {};
            ownedSlug.assign(slug);
            MachineConfig ownedMachineConfig = {};
            ownMachineConfig(machineConfig, ownedMachineConfig);
            owned.configBySlug.insert_or_assign(std::move(ownedSlug), std::move(ownedMachineConfig));
         }

         owned.clusterUUID = source.clusterUUID;
         owned.datacenterFragment = source.datacenterFragment;
         owned.autoscaleIntervalSeconds = source.autoscaleIntervalSeconds;
         owned.sharedCPUOvercommitPermille = source.sharedCPUOvercommitPermille;
         owned.requiredBrainCount = source.requiredBrainCount;
         owned.architecture = source.architecture;
         owned.bootstrapSshUser.assign(source.bootstrapSshUser);
         owned.bootstrapSshKeyPackage = source.bootstrapSshKeyPackage;
         owned.bootstrapSshHostKeyPackage = source.bootstrapSshHostKeyPackage;
         owned.bootstrapSshPrivateKeyPath.assign(source.bootstrapSshPrivateKeyPath);
         owned.remoteProdigyPath.assign(source.remoteProdigyPath);
         owned.controlSocketPath.assign(source.controlSocketPath);
         for (const DistributableExternalSubnet& sourceSubnet : source.distributableExternalSubnets)
         {
            DistributableExternalSubnet ownedSubnet = {};
            ownDistributableExternalSubnet(sourceSubnet, ownedSubnet);
            owned.distributableExternalSubnets.push_back(std::move(ownedSubnet));
         }
         for (const RegisteredRoutableAddress& sourceAddress : source.routableAddresses)
         {
            RegisteredRoutableAddress ownedAddress = {};
            ownRegisteredRoutableAddress(sourceAddress, ownedAddress);
            owned.routableAddresses.push_back(std::move(ownedAddress));
         }
         owned.reporter.to.assign(source.reporter.to);
         owned.reporter.from.assign(source.reporter.from);
         owned.reporter.smtp.assign(source.reporter.smtp);
         owned.reporter.password.assign(source.reporter.password);
         owned.vmImageURI.assign(source.vmImageURI);
         ownRuntimeEnvironmentConfig(source.runtimeEnvironment, owned.runtimeEnvironment);
      }

			void loadBrainConfigIf(void)
		{
	      iaas->configureRuntimeEnvironment(brainConfig.runtimeEnvironment);
	      for (Machine *machine : machines)
	      {
         if (machine == nullptr)
         {
            continue;
         }

	         sendNeuronSwitchboardStateSync(machine);
	      }

			const bool haveDatacenterFragment = (brainConfig.datacenterFragment != 0);
			if (haveDatacenterFragment)
			{
				batphone.setUsername(brainConfig.reporter.from);
				batphone.setPassword(brainConfig.reporter.password);
				batphone.setSMTP(brainConfig.reporter.smtp);
			}

			for (Machine *machine : machines) // accounts for us
			{
				auto it = brainConfig.configBySlug.find(machine->slug);
				if (it == brainConfig.configBySlug.end())
				{
					continue;
				}

				const MachineConfig& machineConfig = it->second;
				ClusterMachineOwnership ownership = {};
				ownership.mode = ClusterMachineOwnershipMode(machine->ownershipMode);
				ownership.nLogicalCoresCap = machine->ownershipLogicalCoresCap;
				ownership.nMemoryMBCap = machine->ownershipMemoryMBCap;
				ownership.nStorageMBCap = machine->ownershipStorageMBCap;
				ownership.nLogicalCoresBasisPoints = machine->ownershipLogicalCoresBasisPoints;
				ownership.nMemoryBasisPoints = machine->ownershipMemoryBasisPoints;
				ownership.nStorageBasisPoints = machine->ownershipStorageBasisPoints;

				if (machine->totalLogicalCores == 0) machine->totalLogicalCores = machineConfig.nLogicalCores;
				if (machine->totalMemoryMB == 0) machine->totalMemoryMB = machineConfig.nMemoryMB;
				if (machine->totalStorageMB == 0) machine->totalStorageMB = machineConfig.nStorageMB;

				uint32_t resolvedOwnedLogicalCores = machine->ownedLogicalCores;
				uint32_t resolvedOwnedMemoryMB = machine->ownedMemoryMB;
				uint32_t resolvedOwnedStorageMB = machine->ownedStorageMB;
				if (resolvedOwnedLogicalCores == 0 || resolvedOwnedMemoryMB == 0 || resolvedOwnedStorageMB == 0)
				{
					(void)clusterMachineResolveOwnedResources(
						ownership,
						machine->totalLogicalCores,
						machine->totalMemoryMB,
						machine->totalStorageMB,
						resolvedOwnedLogicalCores,
						resolvedOwnedMemoryMB,
						resolvedOwnedStorageMB
					);
				}

				machine->ownedLogicalCores = resolvedOwnedLogicalCores;
				machine->ownedMemoryMB = resolvedOwnedMemoryMB;
				machine->ownedStorageMB = resolvedOwnedStorageMB;
            machine->isolatedLogicalCoresCommitted = 0;
            machine->sharedCPUMillisCommitted = 0;
				machine->memoryMB_available = int32_t(resolvedOwnedMemoryMB);
				machine->storageMB_available = int32_t(resolvedOwnedStorageMB);
            machine->resetAvailableGPUMemoryMBsFromHardware();
            prodigyRecomputeMachineCPUAvailability(machine, prodigySharedCPUOvercommitPermille(brainConfig.sharedCPUOvercommitPermille));

            for (Machine::Claim& claim : machine->claims)
            {
               if (claim.nFit == 0)
               {
                  continue;
               }

               machine->isolatedLogicalCoresCommitted += (claim.reservedIsolatedLogicalCoresPerInstance * claim.nFit);
               machine->sharedCPUMillisCommitted += (claim.reservedSharedCPUMillisPerInstance * claim.nFit);
               machine->memoryMB_available -= int32_t(uint64_t(claim.reservedMemoryMBPerInstance) * uint64_t(claim.nFit));
               machine->storageMB_available -= int32_t(uint64_t(claim.reservedStorageMBPerInstance) * uint64_t(claim.nFit));
               prodigyConsumeAssignedGPUsFromMachineAvailability(machine, claim.reservedGPUMemoryMBs, claim.reservedGPUDevices);
            }

            for (const auto& [deploymentID, indexedContainers] : machine->containersByDeploymentID)
            {
               auto deploymentIt = deployments.find(deploymentID);
               if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
               {
                  continue;
               }

               const ApplicationConfig& indexedConfig = deploymentIt->second->plan.config;
               for (ContainerView *container : indexedContainers)
               {
                  if (container == nullptr)
                  {
                     continue;
                  }

                  if (container->state == ContainerState::destroyed)
                  {
                     continue;
                  }

                  prodigyDebitMachineScalarResources(machine, indexedConfig, 1);
                  prodigyConsumeAssignedGPUsFromMachineAvailability(machine, container->assignedGPUMemoryMBs, container->assignedGPUDevices);
               }
            }

            prodigyRecomputeMachineCPUAvailability(machine, prodigySharedCPUOvercommitPermille(brainConfig.sharedCPUOvercommitPermille));

				if (haveDatacenterFragment)
				{
					assignMachineFragment(machine);
				}

				if (machine->state != MachineState::healthy
					&& machineReadyForHealthyState(machine))
				{
					handleMachineStateChange(machine, MachineState::healthy);
				}

				if (machine->isThisMachine)
				{
	               // Local autoscaling metrics are ingested from neuron/container statistics;
	               // no extra metrics service subscriptions are required here.
				}
			}
		}

		virtual bool loadAuthoritativeClusterTopology(ClusterTopology& topology) const
		{
			(void)topology;
			return false;
		}

		virtual bool persistAuthoritativeClusterTopology(const ClusterTopology& topology)
		{
			(void)topology;
			persistLocalRuntimeState();
			return true;
		}

		bool loadOrPersistAuthoritativeClusterTopology(ClusterTopology& topology)
		{
			if (loadAuthoritativeClusterTopology(topology) && topology.machines.empty() == false)
			{
				return true;
			}

			persistLocalRuntimeState();
			return loadAuthoritativeClusterTopology(topology) && topology.machines.empty() == false;
		}

      void applyMachineHardwareProfile(Machine *machine, const MachineHardwareProfile& hardware)
      {
         if (machine == nullptr)
         {
            return;
         }

         bool changed = (machine->hardware != hardware);
         prodigyApplyHardwareProfileToMachine(*machine, hardware);
         if (changed == false)
         {
            return;
         }

         persistLocalRuntimeState();

         if (isActiveMaster())
         {
            ClusterTopology topology = {};
            if (loadAuthoritativeClusterTopology(topology) && topology.machines.empty() == false)
            {
               bool updatedTopology = false;
               for (ClusterMachine& clusterMachine : topology.machines)
               {
                  if (prodigyClusterMachineMatchesMachineIdentity(clusterMachine, *machine) == false)
                  {
                     continue;
                  }

                  prodigyApplyHardwareProfileToClusterMachine(clusterMachine, hardware);
                  updatedTopology = true;
                  break;
               }

               if (updatedTopology == false)
               {
                  return;
               }

               prodigyStripMachineHardwareCapturesFromClusterTopology(topology);
               topology.version += 1;
               if (persistAuthoritativeClusterTopology(topology) == false)
               {
                  return;
               }

               String serializedTopology = {};
               BitseryEngine::serialize(serializedTopology, topology);
               queueBrainReplication(BrainTopic::replicateClusterTopology, serializedTopology);
            }
         }
      }

		static bool resolveClusterMachinePrivate4(const ClusterMachine& clusterMachine, uint32_t& private4)
		{
			return clusterMachine.resolvePrivate4(private4);
		}

		static bool resolveClusterMachinePeerAddress(const ClusterMachine& clusterMachine, IPAddress& address, String& addressText)
		{
			address = {};
			addressText.clear();
			return clusterMachine.resolvePeerAddress(address, &addressText);
		}

      static void resolveClusterMachinePeerAddresses(const ClusterMachine& clusterMachine, Vector<ClusterMachinePeerAddress>& addresses)
      {
         prodigyCollectClusterMachinePeerAddresses(clusterMachine, addresses);
      }

		BrainView *findBrainViewByPrivate4(uint32_t private4) const
		{
			for (BrainView *brain : brains)
			{
				if (brain
					&& brain->private4 == private4
					&& brain->peerAddress.isNull()
					&& brain->peerAddressText.size() == 0)
				{
					return brain;
				}
			}

			return nullptr;
		}

		BrainView *findBrainViewByUUID(uint128_t uuid) const
		{
			for (BrainView *brain : brains)
			{
				if (brain && brain->uuid == uuid)
				{
					return brain;
				}
			}

			return nullptr;
		}

		BrainView *findBrainViewByUpdateSelfPeerKey(uint128_t peerKey) const
		{
			if (peerKey == 0)
			{
				return nullptr;
			}

			for (BrainView *brain : brains)
			{
				if (brain == nullptr)
				{
					continue;
				}

				if (updateSelfPeerTrackingKey(brain) == peerKey)
				{
					return brain;
				}
			}

			return nullptr;
		}

		BrainView *findBrainViewByPeerAddress(const IPAddress& address) const
		{
			for (BrainView *brain : brains)
			{
				if (brain == nullptr)
				{
					continue;
				}

            if (brain->peerAddress.equals(address))
				{
					return brain;
				}

            for (const ClusterMachinePeerAddress& candidate : brain->peerAddresses)
            {
               IPAddress candidateAddress = {};
               if (ClusterMachine::parseIPAddressLiteral(candidate.address, candidateAddress) && candidateAddress.equals(address))
               {
                  return brain;
               }
            }
			}

			return nullptr;
		}

      BrainView *findBrainViewByPeerAddresses(const Vector<ClusterMachinePeerAddress>& addresses) const
      {
         for (const ClusterMachinePeerAddress& candidate : addresses)
         {
            IPAddress address = {};
            if (ClusterMachine::parseIPAddressLiteral(candidate.address, address) == false)
            {
               continue;
            }

            if (BrainView *brain = findBrainViewByPeerAddress(address); brain != nullptr)
            {
               return brain;
            }
         }

         return nullptr;
      }

		static bool machineAddressMatchesLiteral(const String& candidate, const IPAddress& address, const String *addressText = nullptr)
		{
			if (candidate.size() == 0)
			{
				return false;
			}

			if (addressText && candidate.equals(*addressText))
			{
				return true;
			}

			IPAddress parsed = {};
			return ClusterMachine::parseIPAddressLiteral(candidate, parsed) && parsed.equals(address);
		}

		bool machineMatchesPeerAddress(const Machine *machine, const IPAddress& address, const String *addressText = nullptr) const
		{
			if (machine == nullptr || address.isNull())
			{
				return false;
			}

         return prodigyMachinePeerAddressMatches(*machine, address, addressText);
		}

      void adoptBrainPeerAddresses(BrainView *brain, const Vector<ClusterMachinePeerAddress>& addresses)
      {
         if (brain == nullptr)
         {
            return;
         }

         brain->peerAddresses.clear();
         for (const ClusterMachinePeerAddress& candidate : addresses)
         {
            prodigyAppendUniqueClusterMachinePeerAddress(brain->peerAddresses, candidate);
         }

         if (brain->peerAddresses.empty())
         {
            return;
         }

         uint32_t selectedIndex = 0;
         for (uint32_t index = 0; index < brain->peerAddresses.size(); ++index)
         {
            IPAddress peerAddress = {};
            if (ClusterMachine::parseIPAddressLiteral(brain->peerAddresses[index].address, peerAddress))
            {
               selectedIndex = index;
               break;
            }
         }

         brain->peerAddressIndex = selectedIndex;
         IPAddress peerAddress = {};
         if (ClusterMachine::parseIPAddressLiteral(brain->peerAddresses[selectedIndex].address, peerAddress))
         {
            brain->peerAddress = peerAddress;
            brain->peerAddressText = brain->peerAddresses[selectedIndex].address;
         }
      }

		static bool installBrainPeerSocket(BrainView *brain)
		{
			if (brain == nullptr || brain->fd < 0)
			{
				return false;
			}

			if (brain->daddrLen == 0)
			{
				return false;
			}

			if (Ring::bindSourceAddressBeforeFixedFileInstall(brain) == false)
			{
				return false;
			}

			int slot = Ring::adoptProcessFDIntoFixedFileSlot(brain->fd);
			if (slot < 0)
			{
				return false;
			}

			brain->fslot = slot;
			brain->isFixedFile = true;
			return true;
		}

		void configureBrainPeerConnectAddress(BrainView *brain, bool advanceCandidate = false) const
		{
			if (brain == nullptr)
			{
				return;
			}

         Vector<ClusterMachinePeerAddress> localCandidates = localBrainPeerAddresses;
         if (localCandidates.empty() && thisNeuron != nullptr)
         {
            String preferredInterface = {};
            preferredInterface.assign(thisNeuron->eth.name);
            prodigyCollectLocalPeerAddressCandidates(preferredInterface, thisNeuron->private4, localCandidates);
            if (localCandidates.empty() == false)
            {
               ClusterTopology topology = {};
               ClusterMachine self = {};
               self.isBrain = true;
               prodigyAssignClusterMachineAddressesFromPeerCandidates(self.addresses, localCandidates);
               topology.machines.push_back(self);
               prodigyNormalizeClusterTopologyPeerAddresses(topology);
               prodigyCollectClusterMachinePeerAddresses(topology.machines[0], localCandidates);
            }
         }

         IPAddress peerAddress = {};
         String peerAddressText = {};
         ClusterMachinePeerAddress selectedPeerCandidate = {};
         if (brain->peerAddresses.empty() == false)
         {
            if (advanceCandidate && brain->peerAddresses.size() > 1)
            {
               brain->peerAddressIndex = (brain->peerAddressIndex + 1) % uint32_t(brain->peerAddresses.size());
            }
            else if (brain->peerAddressIndex >= brain->peerAddresses.size())
            {
               brain->peerAddressIndex = 0;
            }

            if (ClusterMachine::parseIPAddressLiteral(brain->peerAddresses[brain->peerAddressIndex].address, peerAddress))
            {
               peerAddressText.assign(brain->peerAddresses[brain->peerAddressIndex].address);
               selectedPeerCandidate = brain->peerAddresses[brain->peerAddressIndex];
               brain->peerAddress = peerAddress;
               brain->peerAddressText = peerAddressText;
            }
         }

			if (peerAddress.isNull())
         {
            peerAddress = brain->peerAddress;
            peerAddressText = brain->peerAddressText;
         }

			if (peerAddress.isNull())
			{
				if (brain->private4 == 0)
				{
					return;
				}

				peerAddress = {};
				peerAddress.v4 = brain->private4;
				peerAddress.is6 = false;
				brain->peerAddress = peerAddress;
            if (peerAddressText.size() == 0)
				{
               (void)ClusterMachine::renderIPAddressLiteral(peerAddress, peerAddressText);
				}
            brain->peerAddressText = peerAddressText;
			}

			if ((brain->isFixedFile && brain->fslot >= 0)
				|| (brain->isFixedFile == false && brain->fd >= 0 && Ring::socketIsClosing(brain) == false))
			{
				return;
			}

			brain->setIPVersion(peerAddress.is6 ? AF_INET6 : AF_INET);
			brain->setDatacenterCongestion();
	         brain->saddrLen = 0;
	         String sourceAddressText = {};
	         if (selectedPeerCandidate.address.size() == 0 && peerAddressText.size() > 0)
	         {
	            selectedPeerCandidate.address.assign(peerAddressText);
	         }
	         if (selectedPeerCandidate.address.size() > 0)
	         {
	            IPAddress sourceAddress = {};
	            if (prodigyResolvePreferredLocalSourceAddress(localCandidates, selectedPeerCandidate, sourceAddress, &sourceAddressText))
	            {
	               brain->setSaddr(sourceAddress);
	            }
	         }
	         if (const char *ringVerbose = std::getenv("RING_VERBOSE_LOGS"); ringVerbose && ringVerbose[0] == '1' && ringVerbose[1] == '\0')
	         {
	            basics_log("configureBrainPeerConnectAddress stream=%p uuid=%llu private4=%u candidateIndex=%u peer=%s source=%s localCandidates=%u peerCandidates=%u\n",
	               static_cast<void *>(brain),
	               (unsigned long long)brain->uuid,
	               unsigned(brain->private4),
	               unsigned(brain->peerAddressIndex),
	               peerAddressText.size() > 0 ? peerAddressText.c_str() : "<unset>",
	               sourceAddressText.size() > 0 ? sourceAddressText.c_str() : "<unset>",
	               unsigned(localCandidates.size()),
	               unsigned(brain->peerAddresses.size()));
	         }
			brain->setDaddr(peerAddress, uint16_t(ReservedPorts::brain));
		}

		Machine *findMachineByIdentity(uint128_t uuid, uint32_t private4, const Vector<ClusterMachinePeerAddress> *peerAddresses = nullptr, const IPAddress *peerAddress = nullptr, const String *peerAddressText = nullptr) const
		{
			if (uuid != 0)
			{
				if (auto it = machinesByUUID.find(uuid); it != machinesByUUID.end())
				{
					return it->second;
				}
			}

         if (peerAddresses != nullptr)
         {
            for (const ClusterMachinePeerAddress& candidate : *peerAddresses)
            {
               IPAddress candidateAddress = {};
               if (ClusterMachine::parseIPAddressLiteral(candidate.address, candidateAddress) == false)
               {
                  continue;
               }

               for (Machine *machine : machines)
               {
                  if (machineMatchesPeerAddress(machine, candidateAddress, &candidate.address))
                  {
                     return machine;
                  }
               }
            }
         }

			if (peerAddress && peerAddress->isNull() == false)
			{
				for (Machine *machine : machines)
				{
					if (machineMatchesPeerAddress(machine, *peerAddress, peerAddressText))
					{
						return machine;
					}
				}
			}

			if (private4 != 0)
			{
				for (Machine *machine : machines)
				{
					if (machine && machine->private4 == private4)
					{
						return machine;
					}
				}
			}

			return nullptr;
		}

      Machine *findMachineByUUID(uint128_t uuid) const
      {
         if (uuid == 0)
         {
            return nullptr;
         }

         if (auto it = machinesByUUID.find(uuid); it != machinesByUUID.end())
         {
            return it->second;
         }

         return nullptr;
      }

      static bool addressLooksPublicRoutable(const IPAddress& address)
      {
         if (address.isNull())
         {
            return false;
         }

         if (address.is6 == false)
         {
            return isRFC1918Private4(address.v4) == false;
         }

         const uint8_t *v6 = address.v6;
         if (v6[0] == 0xfe && (v6[1] & 0xc0) == 0x80)
         {
            return false;
         }

         if ((v6[0] & 0xfe) == 0xfc)
         {
            return false;
         }

         return true;
      }

      bool resolveMachinePublicRouteAddress(const Machine *machine, ExternalAddressFamily family, IPAddress& address, String *addressText = nullptr) const
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

         auto tryLiteral = [&] (const String& text) -> bool {

            if (text.size() == 0)
            {
               return false;
            }

            IPAddress candidate = {};
            if (ClusterMachine::parseIPAddressLiteral(text, candidate) == false)
            {
               return false;
            }

            if (candidate.is6 != (family == ExternalAddressFamily::ipv6))
            {
               return false;
            }

            if (addressLooksPublicRoutable(candidate) == false)
            {
               return false;
            }

            address = candidate;
            if (addressText)
            {
               addressText->assign(text);
            }

            return true;
         };

         if (tryLiteral(machine->publicAddress))
         {
            return true;
         }

         for (const ClusterMachinePeerAddress& candidate : machine->peerAddresses)
         {
            if (tryLiteral(candidate.address))
            {
               return true;
            }
         }

         return tryLiteral(machine->sshAddress);
      }

      Machine *chooseMachineForPublicRoute(ExternalAddressFamily family, uint128_t preferredMachineUUID, IPAddress& address, String *addressText = nullptr) const
      {
         address = {};
         if (addressText)
         {
            addressText->clear();
         }

         if (preferredMachineUUID != 0)
         {
            Machine *preferred = findMachineByUUID(preferredMachineUUID);
            if (resolveMachinePublicRouteAddress(preferred, family, address, addressText))
            {
               return preferred;
            }

            return nullptr;
         }

         Vector<Machine *> sorted = {};
         sorted.reserve(machines.size());
         for (Machine *machine : machines)
         {
            if (machine != nullptr && machine->uuid != 0)
            {
               sorted.push_back(machine);
            }
         }

         std::sort(sorted.begin(), sorted.end(), [] (const Machine *lhs, const Machine *rhs) -> bool {
            return prodigyMachineIdentityComesBefore(*lhs, *rhs);
         });

         for (Machine *machine : sorted)
         {
            if (resolveMachinePublicRouteAddress(machine, family, address, addressText))
            {
               return machine;
            }
         }

         return nullptr;
      }

      Machine *chooseMachineForHostedRoute(uint128_t preferredMachineUUID) const
      {
         if (preferredMachineUUID != 0)
         {
            return findMachineByUUID(preferredMachineUUID);
         }

         Vector<Machine *> sorted = {};
         sorted.reserve(machines.size());
         for (Machine *machine : machines)
         {
            if (machine != nullptr && machine->uuid != 0)
            {
               sorted.push_back(machine);
            }
         }

         std::sort(sorted.begin(), sorted.end(), [] (const Machine *lhs, const Machine *rhs) -> bool {
            if (lhs == nullptr || rhs == nullptr)
            {
               return lhs != nullptr && rhs == nullptr;
            }

            bool lhsHealthyActive = lhs->state == MachineState::healthy && neuronControlStreamActive(lhs);
            bool rhsHealthyActive = rhs->state == MachineState::healthy && neuronControlStreamActive(rhs);
            if (lhsHealthyActive != rhsHealthyActive)
            {
               return lhsHealthyActive;
            }

            if (lhs->isBrain != rhs->isBrain)
            {
               return lhs->isBrain == false;
            }

            if (lhs->hasInternetAccess != rhs->hasInternetAccess)
            {
               return lhs->hasInternetAccess;
            }

            return prodigyMachineIdentityComesBefore(*lhs, *rhs);
         });

         return sorted.empty() ? nullptr : sorted[0];
      }

      bool resolveTestFakePublicPrefix(ExternalAddressFamily family, IPPrefix& prefix) const
      {
         prefix = {};
         if (brainConfig.runtimeEnvironment.test.enabled == false)
         {
            return false;
         }

         if (family == ExternalAddressFamily::ipv4)
         {
            if (brainConfig.runtimeEnvironment.test.enableFakeIpv4Boundary == false
               || brainConfig.runtimeEnvironment.test.fakePublicSubnet4.network.isNull())
            {
               return false;
            }

            prefix = brainConfig.runtimeEnvironment.test.fakePublicSubnet4;
            return true;
         }

         if (brainConfig.runtimeEnvironment.test.fakePublicSubnet6.network.isNull())
         {
            return false;
         }

         prefix = brainConfig.runtimeEnvironment.test.fakePublicSubnet6;
         return true;
      }

		bool clusterTopologyContainsMachineIdentity(const ClusterTopology& topology, const ClusterMachine& clusterMachine) const
		{
			for (const ClusterMachine& existing : topology.machines)
			{
				if (existing.sameIdentityAs(clusterMachine))
				{
					return true;
				}
			}

			return false;
		}

		static bool resolveClusterMachineSchemaKey(const ClusterMachine& clusterMachine, String& schemaKey)
		{
			if (clusterMachine.cloudPresent() && clusterMachine.cloud.schema.size() > 0)
			{
				schemaKey.assign(clusterMachine.cloud.schema);
				return true;
			}

			schemaKey.clear();
			return false;
		}

		void linkBrainViewToMachine(Machine *machine)
		{
			if (machine == nullptr || machine->isBrain == false)
			{
				return;
			}

			for (BrainView *brain : brains)
			{
				if (brain == nullptr)
				{
					continue;
				}

				if ((brain->uuid != 0 && machine->uuid != 0 && brain->uuid == machine->uuid)
					|| machineMatchesPeerAddress(machine, brain->peerAddress, &brain->peerAddressText))
				{
					machine->brain = brain;
					brain->machine = machine;
					return;
				}

            for (const ClusterMachinePeerAddress& candidate : brain->peerAddresses)
            {
               IPAddress candidateAddress = {};
               if (ClusterMachine::parseIPAddressLiteral(candidate.address, candidateAddress) == false)
               {
                  continue;
               }

               if (machineMatchesPeerAddress(machine, candidateAddress, &candidate.address))
               {
                  machine->brain = brain;
                  brain->machine = machine;
                  return;
               }
            }

				if (machine->private4 != 0
					&& brain->private4 != 0
					&& machine->private4 == brain->private4
					&& brain->peerAddress.isNull()
					&& brain->peerAddressText.size() == 0)
				{
					machine->brain = brain;
					brain->machine = machine;
					return;
				}
			}
		}

		void synchronizeBrainUUIDToMachine(BrainView *brain)
		{
			if (brain == nullptr || brain->uuid == 0)
			{
				return;
			}

			Machine *machine = brain->machine;
			if (machine == nullptr)
			{
				machine = findMachineByIdentity(0, brain->private4, &brain->peerAddresses,
					brain->peerAddress.isNull() ? nullptr : &brain->peerAddress,
					brain->peerAddressText.size() > 0 ? &brain->peerAddressText : nullptr);
				if (machine == nullptr)
				{
					return;
				}

				machine->brain = brain;
				brain->machine = machine;
			}

			if (machine->uuid == brain->uuid)
			{
				return;
			}

			if (machine->cloudID.size() > 0)
			{
				return;
			}

			if (machine->uuid != 0)
			{
				machinesByUUID.erase(machine->uuid);
			}

			machine->uuid = brain->uuid;
			machinesByUUID.insert_or_assign(machine->uuid, machine);
		}

		static uint32_t stableNonzeroRackUUIDForText(const String& text)
		{
			if (text.size() == 0)
			{
				return 0;
			}

			uint64_t hash = 1469598103934665603ULL;
			for (uint64_t i = 0; i < uint64_t(text.size()); i += 1)
			{
				hash ^= uint64_t(uint8_t(text[i]));
				hash *= 1099511628211ULL;
			}

			uint32_t rackUUID = uint32_t(hash ^ (hash >> 32));
			return rackUUID != 0 ? rackUUID : 1u;
		}

		uint32_t synthesizeTestClusterRackUUID(const ClusterMachine& clusterMachine, uint32_t resolvedPrivate4, const String& resolvedPeerAddressText) const
		{
			if (brainConfig.runtimeEnvironment.test.enabled == false || clusterMachine.rackUUID != 0)
			{
				return clusterMachine.rackUUID;
			}

			if (resolvedPrivate4 != 0)
			{
				return resolvedPrivate4;
			}

			if (uint32_t rackUUID = stableNonzeroRackUUIDForText(resolvedPeerAddressText))
			{
				return rackUUID;
			}

			Vector<ClusterMachinePeerAddress> candidates = {};
			resolveClusterMachinePeerAddresses(clusterMachine, candidates);
			for (const ClusterMachinePeerAddress& candidate : candidates)
			{
				if (uint32_t rackUUID = stableNonzeroRackUUIDForText(candidate.address))
				{
					return rackUUID;
				}
			}

			if (uint32_t rackUUID = stableNonzeroRackUUIDForText(clusterMachine.ssh.address))
			{
				return rackUUID;
			}

			return 1;
		}

		void applyClusterMachineRecord(Machine *machine, const ClusterMachine& clusterMachine, uint32_t resolvedPrivate4, const IPAddress& resolvedPeerAddress, const String& resolvedPeerAddressText)
		{
			if (machine == nullptr)
			{
				return;
			}

			String schema = {};
			(void)resolveClusterMachineSchemaKey(clusterMachine, schema);
			machine->slug = schema;
			machine->lifetime = clusterMachine.lifetime;
			if (clusterMachine.cloudPresent())
			{
				machine->type = clusterMachine.cloud.providerMachineType;
				machine->cloudID = clusterMachine.cloud.cloudID;
			}
			else
			{
				machine->type.clear();
				machine->cloudID.clear();
			}
			machine->topologySource = uint8_t(clusterMachine.source);
			machine->sshAddress = clusterMachine.ssh.address;
			machine->sshPort = clusterMachine.ssh.port > 0 ? clusterMachine.ssh.port : 22;
			machine->sshUser = clusterMachine.ssh.user;
			machine->sshPrivateKeyPath = clusterMachine.ssh.privateKeyPath;
         machine->sshHostPublicKeyOpenSSH = clusterMachine.ssh.hostPublicKeyOpenSSH;
         machine->publicAddress.clear();
         machine->privateAddress.clear();
         if (const ClusterMachineAddress *publicAddress = prodigyFirstClusterMachineAddress(clusterMachine.addresses.publicAddresses); publicAddress != nullptr)
         {
            machine->publicAddress = publicAddress->address;
         }
         if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(clusterMachine.addresses.privateAddresses); privateAddress != nullptr)
         {
            machine->privateAddress = privateAddress->address;
         }
         prodigyCollectClusterMachinePeerAddresses(clusterMachine, machine->peerAddresses);
			if (machine->privateAddress.size() == 0 && resolvedPeerAddressText.size() > 0)
			{
				machine->privateAddress = resolvedPeerAddressText;
			}
			else if (machine->privateAddress.size() == 0 && resolvedPrivate4 != 0)
			{
				struct in_addr address = {};
				address.s_addr = resolvedPrivate4;
				char buffer[INET_ADDRSTRLEN] = {};
				if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) != nullptr)
				{
					machine->privateAddress.assign(buffer);
				}
			}

			machine->ownershipMode = uint8_t(clusterMachine.ownership.mode);
			machine->ownershipLogicalCoresCap = clusterMachine.ownership.nLogicalCoresCap;
			machine->ownershipMemoryMBCap = clusterMachine.ownership.nMemoryMBCap;
			machine->ownershipStorageMBCap = clusterMachine.ownership.nStorageMBCap;
			machine->ownershipLogicalCoresBasisPoints = clusterMachine.ownership.nLogicalCoresBasisPoints;
			machine->ownershipMemoryBasisPoints = clusterMachine.ownership.nMemoryBasisPoints;
			machine->ownershipStorageBasisPoints = clusterMachine.ownership.nStorageBasisPoints;
			machine->totalLogicalCores = clusterMachine.totalLogicalCores;
			machine->totalMemoryMB = clusterMachine.totalMemoryMB;
			machine->totalStorageMB = clusterMachine.totalStorageMB;
			machine->ownedLogicalCores = clusterMachine.ownedLogicalCores;
			machine->ownedMemoryMB = clusterMachine.ownedMemoryMB;
			machine->ownedStorageMB = clusterMachine.ownedStorageMB;

			bool thisIsMachine = clusterMachineMatchesThisBrain(clusterMachine);
			uint128_t resolvedMachineUUID = clusterMachine.uuid;
			if (resolvedMachineUUID == 0)
			{
				if (thisIsMachine
					&& thisNeuron != nullptr
					&& thisNeuron->uuid != 0
					&& clusterMachine.cloud.cloudID.size() == 0)
				{
					resolvedMachineUUID = thisNeuron->uuid;
				}
				else if (machine->uuid != 0)
				{
					resolvedMachineUUID = machine->uuid;
				}
			}
			machine->uuid = resolvedMachineUUID;
			uint32_t rackUUID = synthesizeTestClusterRackUUID(clusterMachine, resolvedPrivate4, resolvedPeerAddressText);
			machine->rackUUID = rackUUID != 0 ? rackUUID : 1;
			machine->private4 = resolvedPrivate4;
         machine->gatewayPrivate4 = 0;
         if (clusterMachine.resolvePrivate4Gateway(machine->gatewayPrivate4) == false && thisNeuron != nullptr)
         {
            machine->gatewayPrivate4 = thisNeuron->gateway4.v4;
         }
				machine->creationTimeMs = clusterMachine.creationTimeMs;
				machine->isBrain = clusterMachine.isBrain;
				machine->isThisMachine = thisIsMachine;
				machine->neuron.machine = machine;
				prodigyConfigureMachineNeuronEndpoint(*machine, thisNeuron);
			}

		bool restoreBrainsFromClusterTopology(const ClusterTopology& topology)
		{
			bool restoredAny = false;

			for (const ClusterMachine& clusterMachine : topology.machines)
			{
				if (clusterMachine.isBrain == false)
				{
					continue;
				}

				IPAddress peerAddress = {};
				String peerAddressText = {};
				bool havePeerAddress = resolveClusterMachinePeerAddress(clusterMachine, peerAddress, peerAddressText);
            Vector<ClusterMachinePeerAddress> peerAddresses;
            resolveClusterMachinePeerAddresses(clusterMachine, peerAddresses);
				uint32_t resolvedPrivate4 = 0;
				(void)resolveClusterMachinePrivate4(clusterMachine, resolvedPrivate4);
				if (clusterMachineMatchesThisBrain(clusterMachine))
				{
               adoptLocalBrainPeerAddresses(peerAddresses);
					if (havePeerAddress)
					{
						adoptLocalBrainPeerAddress(peerAddress, peerAddressText);
					}
					continue;
				}

				BrainView *brain = nullptr;
            if (peerAddresses.empty() == false)
            {
               brain = findBrainViewByPeerAddresses(peerAddresses);
            }
				if (brain == nullptr && havePeerAddress)
				{
					brain = findBrainViewByPeerAddress(peerAddress);
				}
				if (brain == nullptr && clusterMachine.uuid != 0)
				{
					brain = findBrainViewByUUID(clusterMachine.uuid);
				}
				if (brain == nullptr && resolvedPrivate4 != 0)
				{
					brain = findBrainViewByPrivate4(resolvedPrivate4);
				}
				if (brain == nullptr)
				{
					brain = new BrainView();
					brains.insert(brain);
				}

				if (havePeerAddress)
				{
					brain->peerAddress = peerAddress;
					brain->peerAddressText = peerAddressText;
				}
				else
				{
					brain->peerAddress = {};
					brain->peerAddressText.clear();
				}

            adoptBrainPeerAddresses(brain, peerAddresses);

				if (clusterMachine.uuid != 0 || brain->uuid == 0)
				{
					brain->uuid = clusterMachine.uuid;
				}
				brain->private4 = resolvedPrivate4;
            brain->gatewayPrivate4 = 0;
            if (clusterMachine.resolvePrivate4Gateway(brain->gatewayPrivate4) == false && thisNeuron != nullptr)
            {
               brain->gatewayPrivate4 = thisNeuron->gateway4.v4;
            }
				brain->creationTimeMs = clusterMachine.creationTimeMs;
				linkBrainViewToMachine(findMachineByIdentity(clusterMachine.uuid, resolvedPrivate4, &peerAddresses, havePeerAddress ? &peerAddress : nullptr, havePeerAddress ? &peerAddressText : nullptr));
				synchronizeBrainUUIDToMachine(brain);
				restoredAny = true;
			}

			return restoredAny;
		}

		void initializeBrainPeerIfNeeded(BrainView *brain)
		{
			if (brain == nullptr || (brain->private4 == 0 && brain->peerAddress.isNull() && brain->peerAddresses.empty()))
			{
				std::fprintf(stderr,
					"prodigy brain init-peer-skip reason=missing-identity stream=%p private4=%u fd=%d isFixed=%d fslot=%d\n",
					static_cast<void *>(brain),
					unsigned(brain ? brain->private4 : 0),
					brain ? brain->fd : -1,
					brain ? int(brain->isFixedFile) : 0,
					brain ? brain->fslot : -1);
				std::fflush(stderr);
				return;
			}

         // Resume/reconcile paths can rebuild topology in synchronous or test-only contexts
         // before the Ring dispatcher exists. Peer socket bring-up only makes sense once
         // the event loop is actually live.
         if (RingDispatcher::dispatcher == nullptr || Ring::getRingFD() <= 0)
         {
            std::fprintf(stderr,
               "prodigy brain init-peer-skip reason=ring-inactive private4=%u dispatcher=%p ringFD=%d\n",
               unsigned(brain->private4),
               static_cast<void *>(RingDispatcher::dispatcher),
               Ring::getRingFD());
            std::fflush(stderr);
            return;
         }

			RingDispatcher::installMultiplexee(brain, this);

			bool isDevMode = BrainBase::controlPlaneDevModeEnabled();
			brain->connectTimeoutMs = BrainBase::controlPlaneConnectTimeoutMs(isDevMode);
			brain->nDefaultAttemptsBudget = BrainBase::controlPlaneConnectAttemptsBudget(isDevMode);
			brain->setKeepaliveTimeoutSeconds(brainPeerKeepaliveSeconds);

			if (brain->connected)
			{
				std::fprintf(stderr,
					"prodigy brain init-peer-skip reason=already-connected private4=%u fd=%d isFixed=%d fslot=%d\n",
					unsigned(brain->private4),
					brain->fd,
					int(brain->isFixedFile),
					brain->fslot);
				std::fflush(stderr);
				return;
			}

			if (brainWaiters.contains(brain))
			{
				std::fprintf(stderr,
					"prodigy brain init-peer-skip reason=waiter-active private4=%u fd=%d isFixed=%d fslot=%d\n",
					unsigned(brain->private4),
					brain->fd,
					int(brain->isFixedFile),
					brain->fslot);
				std::fflush(stderr);
				return;
			}

			if (brain->isFixedFile)
			{
				if (brain->fslot >= 0)
				{
					std::fprintf(stderr,
						"prodigy brain init-peer-skip reason=fixedfile-present private4=%u fd=%d isFixed=%d fslot=%d\n",
						unsigned(brain->private4),
						brain->fd,
						int(brain->isFixedFile),
						brain->fslot);
					std::fflush(stderr);
					return;
				}
			}
			else if (brain->fd >= 0)
			{
				std::fprintf(stderr,
					"prodigy brain init-peer-skip reason=fd-present private4=%u fd=%d isFixed=%d fslot=%d\n",
					unsigned(brain->private4),
					brain->fd,
					int(brain->isFixedFile),
					brain->fslot);
				std::fflush(stderr);
				return;
			}

			uint32_t connectAttemptTimeMs = BrainBase::machineInitialConnectAttemptTimeMs(
				brain->creationTimeMs,
				brain->connectTimeoutMs,
				brain->nDefaultAttemptsBudget,
				isDevMode);

			if (shouldWeConnectToBrain(brain))
			{
				brain->weConnectToIt = true;
				configureBrainPeerConnectAddress(brain);
				std::fprintf(stderr,
					"prodigy brain init-peer-connect private4=%u fd=%d isFixed=%d fslot=%d daddrLen=%u\n",
					unsigned(brain->private4),
					brain->fd,
					int(brain->isFixedFile),
					brain->fslot,
					unsigned(brain->daddrLen));
				std::fflush(stderr);

				if (installBrainPeerSocket(brain))
				{
					std::fprintf(stderr,
						"prodigy brain init-peer-connect-arm private4=%u fd=%d isFixed=%d fslot=%d\n",
						unsigned(brain->private4),
						brain->fd,
						int(brain->isFixedFile),
						brain->fslot);
					std::fflush(stderr);
					brain->attemptConnectForMs(connectAttemptTimeMs);
				}
				else
				{
					std::fprintf(stderr,
						"prodigy brain init-peer-connect-install-fail private4=%u fd=%d isFixed=%d fslot=%d daddrLen=%u\n",
						unsigned(brain->private4),
						brain->fd,
						int(brain->isFixedFile),
						brain->fslot,
						unsigned(brain->daddrLen));
					std::fflush(stderr);
				}
			}
			else
			{
				brain->weConnectToIt = false;
				std::fprintf(stderr,
					"prodigy brain init-peer-wait private4=%u fd=%d isFixed=%d fslot=%d\n",
					unsigned(brain->private4),
					brain->fd,
					int(brain->isFixedFile),
					brain->fslot);
				std::fflush(stderr);

				TimeoutPacket *timeout = new TimeoutPacket();
				timeout->flags = uint64_t(BrainTimeoutFlags::brainMissing);
				timeout->originator = brain;
				timeout->dispatcher = this;
				timeout->setTimeoutMs(connectAttemptTimeMs);

				brainWaiters.insert_or_assign(brain, timeout);
				Ring::queueTimeout(timeout);
			}
		}

		void initializeAllBrainPeersIfNeeded(void)
		{
			for (BrainView *brain : brains)
			{
				initializeBrainPeerIfNeeded(brain);
			}
		}

		bool normalizeAdoptedClusterMachine(const ClusterMachine& requested, const String& defaultSSHUser, const String& defaultSSHPrivateKeyPath, ClusterMachine& normalized, String& failure) const
		{
			normalized = requested;
			normalized.source = ClusterMachineSource::adopted;
			if (normalized.backing == ClusterMachineBacking::cloud)
			{
				normalized.hasCloud = true;
				String schemaKey = {};
				if (resolveClusterMachineSchemaKey(requested, schemaKey) == false)
				{
					failure.assign("cloud adopted machine requires cloud.schema"_ctv);
					return false;
				}

				auto it = brainConfig.configBySlug.find(schemaKey);
				if (it == brainConfig.configBySlug.end())
				{
					failure.snprintf<"unknown machine schema '{}'"_ctv>(schemaKey);
					return false;
				}

				const MachineConfig& machineConfig = it->second;
				normalized.cloud.schema = schemaKey;
				normalized.kind = machineConfig.kind;
				if (normalized.cloud.providerMachineType.size() == 0)
				{
					failure.assign("cloud adopted machine requires cloud.providerMachineType"_ctv);
					return false;
				}

				if (normalized.cloud.cloudID.size() == 0)
				{
					failure.assign("cloud adopted machine requires cloud.cloudID"_ctv);
					return false;
				}
			}
			else if (normalized.cloudPresent())
			{
				failure.assign("owned adopted machine must not include cloud fields"_ctv);
				return false;
			}

			if (normalized.ssh.user.size() == 0 && defaultSSHUser.size() > 0)
			{
				normalized.ssh.user.assign(defaultSSHUser);
			}

			if (normalized.ssh.privateKeyPath.size() == 0 && defaultSSHPrivateKeyPath.size() > 0)
			{
				normalized.ssh.privateKeyPath.assign(defaultSSHPrivateKeyPath);
			}

			if (normalized.ssh.user.size() == 0)
			{
				failure.assign("adopted machine sshUser required"_ctv);
				return false;
			}

			if (normalized.ssh.privateKeyPath.size() == 0)
			{
				failure.assign("adopted machine sshPrivateKeyPath required"_ctv);
				return false;
			}

			if (normalized.ssh.port == 0)
			{
				normalized.ssh.port = 22;
			}

			if (normalized.ssh.address.size() == 0)
			{
				if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(normalized.addresses.privateAddresses); privateAddress != nullptr)
				{
					normalized.ssh.address = privateAddress->address;
				}
				else if (const ClusterMachineAddress *publicAddress = prodigyFirstClusterMachineAddress(normalized.addresses.publicAddresses); publicAddress != nullptr)
				{
					normalized.ssh.address = publicAddress->address;
				}
			}

			if (normalized.ssh.address.size() == 0)
			{
				failure.assign("adopted machine sshAddress required"_ctv);
				return false;
			}

         if (normalized.ssh.hostPublicKeyOpenSSH.size() == 0)
         {
            failure.assign("adopted machine ssh.hostPublicKeyOpenSSH required"_ctv);
            return false;
         }

         String label = {};
         normalized.renderIdentityLabel(label);
         std::fprintf(stderr, "prodigy mothership adopted-probe-start machine=%.*s ssh=%.*s:%u user=%.*s\n",
            int(label.size()),
            label.c_str(),
            int(normalized.ssh.address.size()),
            normalized.ssh.address.c_str(),
            unsigned(normalized.ssh.port),
            int(normalized.ssh.user.size()),
            normalized.ssh.user.c_str());
         std::fflush(stderr);

			ProdigyRemoteMachineResources probedResources = {};
			String probeFailure;
			if (prodigyProbeRemoteMachineResources(normalized, probedResources, &probeFailure) == false)
			{
				failure.snprintf<"failed to probe adopted machine '{}': {}"_ctv>(label, probeFailure);
				return false;
			}
         std::fprintf(stderr, "prodigy mothership adopted-probe-ok machine=%.*s logicalCores=%u memoryMB=%u storageMB=%u peerAddresses=%u\n",
            int(label.size()),
            label.c_str(),
            unsigned(probedResources.totalLogicalCores),
            unsigned(probedResources.totalMemoryMB),
            unsigned(probedResources.totalStorageMB),
            uint32_t(probedResources.peerAddresses.size()));
         std::fflush(stderr);

			if (clusterMachineApplyOwnedResourcesFromTotals(normalized, probedResources.totalLogicalCores, probedResources.totalMemoryMB, probedResources.totalStorageMB, &failure) == false)
			{
				return false;
			}

			uint32_t resolvedPrivate4 = 0;
			if (resolveClusterMachinePrivate4(normalized, resolvedPrivate4) == false)
			{
            prodigyAssignClusterMachineAddressesFromPeerCandidates(normalized.addresses, probedResources.peerAddresses);
            ClusterTopology candidateTopology = {};
            for (const Machine *machine : machines)
            {
               if (machine == nullptr || machine->isBrain == false)
               {
                  continue;
               }

               ClusterMachine existing = {};
               existing.isBrain = machine->isBrain;
               existing.uuid = machine->uuid;
               existing.ssh.address = machine->sshAddress;
               prodigyAssignClusterMachineAddressesFromPeerCandidates(existing.addresses, machine->peerAddresses);
               String privateGateway = {};
               if (machine->gatewayPrivate4 != 0)
               {
                  IPAddress gatewayAddress = {};
                  gatewayAddress.v4 = machine->gatewayPrivate4;
                  gatewayAddress.is6 = false;
                  (void)ClusterMachine::renderIPAddressLiteral(gatewayAddress, privateGateway);
               }
               prodigyAppendUniqueClusterMachineAddress(existing.addresses.privateAddresses, machine->privateAddress, 0, privateGateway);
               prodigyAppendUniqueClusterMachineAddress(existing.addresses.publicAddresses, machine->publicAddress);
               candidateTopology.machines.push_back(existing);
            }

            ClusterMachine candidateSelf = normalized;
            candidateTopology.machines.push_back(candidateSelf);
            prodigyNormalizeClusterTopologyPeerAddresses(candidateTopology);
            if (candidateTopology.machines.empty() == false)
            {
               normalized.addresses = candidateTopology.machines.back().addresses;
            }

            Vector<ClusterMachinePeerAddress> normalizedCandidates = {};
            prodigyCollectClusterMachinePeerAddresses(normalized, normalizedCandidates);
            for (const ClusterMachinePeerAddress& candidate : normalizedCandidates)
            {
               IPAddress parsedAddress = {};
               if (ClusterMachine::parseIPAddressLiteral(candidate.address, parsedAddress) == false)
               {
                  continue;
               }

               if (resolvedPrivate4 == 0 && parsedAddress.is6 == false && prodigyClusterMachinePeerAddressIsPrivate(candidate))
               {
                  resolvedPrivate4 = parsedAddress.v4;
               }
            }
			}

			if (normalized.addresses.privateAddresses.empty())
			{
            if (resolvedPrivate4 != 0)
            {
               struct in_addr address = {};
               address.s_addr = resolvedPrivate4;
               char buffer[INET_ADDRSTRLEN] = {};
               if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) != nullptr)
               {
                  String privateAddress = {};
                  privateAddress.assign(buffer);
                  prodigyAppendUniqueClusterMachineAddress(normalized.addresses.privateAddresses, privateAddress);
               }
            }
			}

         if (normalized.addresses.privateAddresses.empty() && normalized.addresses.publicAddresses.empty())
         {
            ClusterTopology singletonTopology = {};
            singletonTopology.machines.push_back(normalized);
            prodigyNormalizeClusterTopologyPeerAddresses(singletonTopology);
            normalized.addresses = singletonTopology.machines[0].addresses;
         }

         if (normalized.ssh.address.size() == 0)
         {
            if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(normalized.addresses.privateAddresses); privateAddress != nullptr)
            {
               normalized.ssh.address = privateAddress->address;
            }
            else if (const ClusterMachineAddress *publicAddress = prodigyFirstClusterMachineAddress(normalized.addresses.publicAddresses); publicAddress != nullptr)
            {
               normalized.ssh.address = publicAddress->address;
            }
         }

			if (normalized.creationTimeMs == 0)
			{
				normalized.creationTimeMs = Time::now<TimeResolution::ms>();
			}

			return true;
		}

		bool clusterMachineMatchesThisBrain(const ClusterMachine& machine) const
		{
			if (thisNeuron == nullptr)
			{
				return false;
			}

			if (machine.uuid != 0 && machine.uuid == thisNeuron->uuid)
			{
				return true;
			}

         bool hadExplicitPeerAddress = false;
         auto explicitAddressMatches = [&] (const String& addressText) -> bool {

            if (addressText.size() == 0)
            {
               return false;
            }

            hadExplicitPeerAddress = true;
            IPAddress peerAddress = {};
            return ClusterMachine::parseIPAddressLiteral(addressText, peerAddress) && localBrainAddressMatches(peerAddress);
         };

         for (const ClusterMachineAddress& addressText : machine.addresses.privateAddresses)
         {
            if (explicitAddressMatches(addressText.address))
            {
               return true;
            }
         }

         for (const ClusterMachineAddress& addressText : machine.addresses.publicAddresses)
         {
            if (explicitAddressMatches(addressText.address))
            {
               return true;
            }
         }

         if (explicitAddressMatches(machine.ssh.address))
         {
            return true;
         }

         if (hadExplicitPeerAddress)
         {
            return false;
         }

         IPAddress peerAddress = {};
         String peerAddressText = {};
         return resolveClusterMachinePeerAddress(machine, peerAddress, peerAddressText) && localBrainAddressMatches(peerAddress);
		}

		bool probeCandidateBrainReachability(const ClusterTopology& currentTopology, const ClusterMachine& candidate, AddMachines& response) const
		{
			response.reachabilityProbeAddress.clear();
			response.reachabilityResults.clear();

			if (candidate.isBrain == false)
			{
				return true;
			}

			IPAddress targetAddress = {};
			if (candidate.resolvePeerAddress(targetAddress, &response.reachabilityProbeAddress) == false
				|| response.reachabilityProbeAddress.size() == 0)
			{
				response.failure.assign("candidate brain requires a reachable ipv4 or ipv6 address"_ctv);
				return false;
			}

			Vector<ClusterMachine> sourceBrains;
			for (const ClusterMachine& machine : currentTopology.machines)
			{
				if (machine.isBrain)
				{
					sourceBrains.push_back(machine);
				}
			}

			if (sourceBrains.empty())
			{
				return true;
			}

			return prodigyProbeAddressFromClusterBrains(
				sourceBrains,
				response.reachabilityProbeAddress,
				[this](const ClusterMachine& sourceBrain, const String& targetAddress, BrainReachabilityProbeResult& result, String& failure) -> bool {

					if (clusterMachineMatchesThisBrain(sourceBrain))
					{
						return prodigyProbeReachabilityLocally(targetAddress, result, &failure);
					}

					return prodigyProbeReachabilityOverSSH(sourceBrain, targetAddress, result, &failure);
				},
				response.reachabilityResults,
				response.failure
			);
		}

		bool restoreMachinesFromClusterTopology(const ClusterTopology& topology)
		{
			bool restoredAny = false;
			bytell_hash_set<Machine *> knownMachines = machines;

			for (const ClusterMachine& clusterMachine : topology.machines)
			{
				uint32_t resolvedPrivate4 = 0;
				(void)resolveClusterMachinePrivate4(clusterMachine, resolvedPrivate4);
				IPAddress resolvedPeerAddress = {};
				String resolvedPeerAddressText = {};
				bool havePeerAddress = resolveClusterMachinePeerAddress(clusterMachine, resolvedPeerAddress, resolvedPeerAddressText);
            Vector<ClusterMachinePeerAddress> resolvedPeerAddresses;
            resolveClusterMachinePeerAddresses(clusterMachine, resolvedPeerAddresses);

				Machine *machine = findMachineByIdentity(clusterMachine.uuid, resolvedPrivate4, &resolvedPeerAddresses, havePeerAddress ? &resolvedPeerAddress : nullptr, havePeerAddress ? &resolvedPeerAddressText : nullptr);
				bool knownMachine = (machine != nullptr) && knownMachines.contains(machine);
				std::fprintf(stderr, "prodigy topology restore-machine begin clusterUUID=%llu resolvedPrivate4=%u isBrain=%d known=%d machine=%p uuidPresent=%d peerCount=%u peer=%s\n",
					(unsigned long long)clusterMachine.uuid,
					unsigned(resolvedPrivate4),
					int(clusterMachine.isBrain),
					int(knownMachine),
					machine,
					int(clusterMachine.uuid != 0),
					uint32_t(resolvedPeerAddresses.size()),
					resolvedPeerAddressText.c_str());
				std::fflush(stderr);
				if (machine == nullptr)
				{
					machine = new Machine();
					std::fprintf(stderr, "prodigy topology restore-machine allocated machine=%p\n", machine);
					std::fflush(stderr);
				}

				applyClusterMachineRecord(machine, clusterMachine, resolvedPrivate4, resolvedPeerAddress, resolvedPeerAddressText);
				std::fprintf(stderr, "prodigy topology restore-machine applied machine=%p uuid=%llu private4=%u isBrain=%d isThisMachine=%d slug=%s cloudID=%s\n",
					machine,
					(unsigned long long)machine->uuid,
					unsigned(machine->private4),
					int(machine->isBrain),
					int(machine->isThisMachine),
					machine->slug.c_str(),
					machine->cloudID.c_str());
				std::fflush(stderr);

				if (knownMachine == false)
				{
					std::fprintf(stderr, "prodigy topology restore-machine finish-begin machine=%p uuid=%llu private4=%u\n",
						machine,
						(unsigned long long)machine->uuid,
						unsigned(machine->private4));
					std::fflush(stderr);
					finishMachineConfig(machine);
					std::fprintf(stderr, "prodigy topology restore-machine finish-done machine=%p uuid=%llu private4=%u fd=%d isFixed=%d fslot=%d\n",
						machine,
						(unsigned long long)machine->uuid,
						unsigned(machine->private4),
						machine->neuron.fd,
						int(machine->neuron.isFixedFile),
						machine->neuron.fslot);
					std::fflush(stderr);

					machine->state = BrainBase::machineBootstrapLifecycleState(machine->creationTimeMs);
				}
				else
				{
					std::fprintf(stderr, "prodigy topology restore-machine relink-begin machine=%p uuid=%llu private4=%u\n",
						machine,
						(unsigned long long)machine->uuid,
						unsigned(machine->private4));
					std::fflush(stderr);
					linkBrainViewToMachine(machine);
					std::fprintf(stderr, "prodigy topology restore-machine relink-done machine=%p uuid=%llu private4=%u brain=%p\n",
						machine,
						(unsigned long long)machine->uuid,
						unsigned(machine->private4),
						machine->brain);
					std::fflush(stderr);
				}

				machines.insert(machine);
				neurons.insert(&machine->neuron);
				if (machine->uuid != 0)
				{
					machinesByUUID.insert_or_assign(machine->uuid, machine);
				}
				if (machine->isThisMachine && thisNeuron != nullptr)
				{
					thisNeuron->ensureDeferredHardwareInventoryProgress();
					// The local neuron can finish deferred inventory before topology
					// restore links it to the runtime Machine. Replay any completed
					// inventory now so created seeds do not lose self hardware state.
					if (const MachineHardwareProfile *hardware = thisNeuron->latestHardwareProfileIfReady(); hardware != nullptr)
					{
						applyMachineHardwareProfile(machine, *hardware);
						if (machine->state != MachineState::healthy
							&& machineReadyForHealthyState(machine))
						{
							handleMachineStateChange(machine, MachineState::healthy);
						}
					}
				}
				std::fprintf(stderr, "prodigy topology restore-machine complete machine=%p uuid=%llu private4=%u\n",
					machine,
					(unsigned long long)machine->uuid,
					unsigned(machine->private4));
				std::fflush(stderr);

				restoredAny = true;
			}

			return restoredAny;
		}

      void noteLocalContainerHealthy(uint128_t containerUUID) override
      {
         std::fprintf(stderr,
            "brain noteLocalContainerHealthy enter uuid=%llu weAreMaster=%d tracked=%llu\n",
            (unsigned long long)containerUUID,
            int(weAreMaster),
            (unsigned long long)containers.size());
         std::fflush(stderr);

         if (weAreMaster == false)
         {
            return;
         }

         basics_log("brain local containerHealthy uuid=%llu containersTracked=%llu\n",
            (unsigned long long)containerUUID,
            (unsigned long long)containers.size());

         if (auto it = containers.find(containerUUID); it != containers.end())
         {
            ContainerView *container = it->second;
            ApplicationDeployment *deployment = nullptr;
            if (auto deploymentIt = deployments.find(container->deploymentID); deploymentIt != deployments.end())
            {
               deployment = deploymentIt->second;
            }

            basics_log("brain local containerHealthy apply uuid=%llu deploymentID=%llu appID=%u machinePrivate4=%u waitingOnContainers=%llu\n",
               (unsigned long long)containerUUID,
               (unsigned long long)container->deploymentID,
               unsigned(ApplicationConfig::extractApplicationID(container->deploymentID)),
               (container->machine ? unsigned(container->machine->private4) : 0u),
               (unsigned long long)(deployment ? deployment->waitingOnContainers.size() : 0));

            if (deployment)
            {
               std::fprintf(stderr,
                  "brain noteLocalContainerHealthy apply uuid=%llu deploymentID=%llu appID=%u waitingBefore=%llu stateBefore=%u\n",
                  (unsigned long long)containerUUID,
                  (unsigned long long)container->deploymentID,
                  unsigned(ApplicationConfig::extractApplicationID(container->deploymentID)),
                  (unsigned long long)deployment->waitingOnContainers.size(),
                  unsigned(container->state));
               std::fflush(stderr);
               deployment->containerIsHealthy(container);
               std::fprintf(stderr,
                  "brain noteLocalContainerHealthy done uuid=%llu deploymentID=%llu appID=%u waitingAfter=%llu stateAfter=%u\n",
                  (unsigned long long)containerUUID,
                  (unsigned long long)container->deploymentID,
                  unsigned(ApplicationConfig::extractApplicationID(container->deploymentID)),
                  (unsigned long long)deployment->waitingOnContainers.size(),
                  unsigned(container->state));
               std::fflush(stderr);
            }
            else
            {
               basics_log("brain local containerHealthy missing deployment for uuid=%llu deploymentID=%llu\n",
                  (unsigned long long)containerUUID,
                  (unsigned long long)container->deploymentID);
            }
         }
         else
         {
            basics_log("brain local containerHealthy missing uuid=%llu\n",
               (unsigned long long)containerUUID);
         }
      }

	void getMachines(CoroutineStack *coro)
	{
		ClusterTopology topology = {};
		(void)(loadAuthoritativeClusterTopology(topology) && restoreMachinesFromClusterTopology(topology));

		uint32_t suspendIndex = coro->nextSuspendIndex();

		bytell_hash_set<Machine *> knownMachines = machines;
		bytell_hash_map<uint128_t, Machine *> knownByUUID;
		for (Machine *machine : knownMachines)
		{
			if (machine && machine->uuid != 0)
			{
				knownByUUID.insert_or_assign(machine->uuid, machine);
			}
		}

		iaas->getMachines(coro, thisNeuron->metro, machines);

		if (suspendIndex < coro->nextSuspendIndex())
		{
			co_await coro->suspendAtIndex(suspendIndex);
		}

		Vector<Machine *> duplicateSnapshots;
      auto reconcileCanonicalMachineFromSnapshot = [&] (Machine *canonical, Machine *candidate) -> void {

         if (canonical == nullptr || candidate == nullptr)
         {
            return;
         }

         auto assignRack = [&] (Machine *machine, uint32_t rackUUID) -> void {

            if (machine == nullptr || rackUUID == 0)
            {
               return;
            }

            if (machine->rack != nullptr && machine->rack->uuid == rackUUID)
            {
               machine->rackUUID = rackUUID;
               return;
            }

            if (machine->rack != nullptr)
            {
               Rack *previousRack = machine->rack;
               previousRack->machines.erase(machine);
               if (previousRack->machines.empty())
               {
                  racks.erase(previousRack->uuid);
                  delete previousRack;
               }
            }

            Rack *rack = nullptr;
            if (auto rackIt = racks.find(rackUUID); rackIt != racks.end())
            {
               rack = rackIt->second;
            }
            else
            {
               rack = new Rack();
               rack->uuid = rackUUID;
               racks.insert_or_assign(rackUUID, rack);
            }

            machine->rackUUID = rackUUID;
            machine->rack = rack;
            rack->machines.insert(machine);
         };

         canonical->isBrain = candidate->isBrain;
         canonical->isThisMachine = candidate->isThisMachine;
         canonical->private4 = candidate->private4;
         canonical->gatewayPrivate4 = candidate->gatewayPrivate4;
         canonical->slug = candidate->slug;
         canonical->lifetime = candidate->lifetime;
         canonical->type = candidate->type;
         canonical->cloudID = candidate->cloudID;
         canonical->sshAddress = candidate->sshAddress;
         canonical->sshPort = candidate->sshPort;
         canonical->sshUser = candidate->sshUser;
         canonical->sshPrivateKeyPath = candidate->sshPrivateKeyPath;
         canonical->sshHostPublicKeyOpenSSH = candidate->sshHostPublicKeyOpenSSH;
         canonical->publicAddress = candidate->publicAddress;
         canonical->privateAddress = candidate->privateAddress;
         canonical->peerAddresses = candidate->peerAddresses;
         canonical->creationTimeMs = candidate->creationTimeMs;
         canonical->neuron.machine = canonical;
         prodigyConfigureMachineNeuronEndpoint(*canonical, thisNeuron);

         if (candidate->rackUUID != 0)
         {
            assignRack(canonical, candidate->rackUUID);
         }
      };

		for (Machine *candidate : machines)
		{
			if (knownMachines.contains(candidate))
			{
				continue;
			}

         Machine *canonical = nullptr;
			if (candidate->uuid != 0)
			{
				if (auto known = knownByUUID.find(candidate->uuid); known != knownByUUID.end())
				{
					canonical = known->second;
				}
         }

         if (canonical == nullptr)
         {
            for (Machine *knownMachine : knownMachines)
            {
               if (knownMachine != nullptr && prodigyMachinesShareIdentity(*knownMachine, *candidate))
               {
                  canonical = knownMachine;
                  break;
               }
            }
         }

         if (canonical != nullptr)
         {
            reconcileCanonicalMachineFromSnapshot(canonical, candidate);
            duplicateSnapshots.push_back(candidate);
            continue;
         }

			if (candidate->uuid != 0)
			{
				knownByUUID.insert_or_assign(candidate->uuid, candidate);
			}
		}

		for (Machine *snapshot : duplicateSnapshots)
		{
			machines.erase(snapshot);
			neurons.erase(&snapshot->neuron);

			if (snapshot->neuron.isFixedFile == false && snapshot->neuron.fd >= 0)
			{
				snapshot->neuron.close();
				snapshot->neuron.fd = -1;
			}

			delete snapshot;
		}

		for (Machine *machine : machines)
		{
			bool knownMachine = knownMachines.contains(machine);
			if (knownMachine == false)
			{
				finishMachineConfig(machine);

				// Freshly created machines are still bootstrapping, not updating their OS.
				machine->state = BrainBase::machineBootstrapLifecycleState(machine->creationTimeMs);
			}
			else
			{
				// Existing machine state comes from live control-plane lifecycle and must
				// survive master handoff; do not reset it on inventory refresh.
			}

			neurons.insert(&machine->neuron);
			if (machine->uuid != 0)
			{
				machinesByUUID.insert_or_assign(machine->uuid, machine);
			}
		}

		loadBrainConfigIf();

		// Wait one full initial control-plane reconnect window before declaring
		// startup ignited. Freshly created machines can continue bootstrapping
		// after this; ignition just avoids racing the first reconnect budget.
		bool isDevMode = BrainBase::controlPlaneDevModeEnabled();
		ignitionSwitch.flags = uint64_t(BrainTimeoutFlags::ignition);
		ignitionSwitch.setTimeoutMs(BrainBase::controlPlaneIgnitionTimeoutMs(isDevMode));
		ignitionSwitch.dispatcher = this;
		RingDispatcher::installMultiplexee(&ignitionSwitch, this);
		Ring::queueTimeout(&ignitionSwitch);

		// we could turn this on and off whether we have spot machines or not.... but just simpler to let it run always
		spotDecomissionChecker.flags = uint64_t(BrainTimeoutFlags::spotDecomissionChecker);
		spotDecomissionChecker.setTimeoutMs(prodigyBrainSpotDecommissionCheckIntervalMs); // every 90 seconds, gives us 30 seconds to get a new machine up if need be
		spotDecomissionChecker.dispatcher = this;
		RingDispatcher::installMultiplexee(&spotDecomissionChecker, this);
		Ring::queueTimeout(&spotDecomissionChecker);

		// if the last master brain failed...
		// after the ignition timeout we would autodetect that we can't connect to the neuron of the previous master brain,
		// then we'd try SSH, then we'd try hard rebooting... if that worked it would rejoin the brains, otherwise the machine would be reported for manual intervention
	}

		bool hasHealthyMachines(void) const override
		{
			for (Machine *machine : machines)
			{
				if (machine->state == MachineState::healthy)
				{
					return true;
				}
			}
			return false;
		}

	// we only called from afterRing at boot time
	void getBrains(void)
	{
		boottimens = Time::now<TimeResolution::ns>();

		iaas->boot();

		bool isDevMode = BrainBase::controlPlaneDevModeEnabled();

		// Keep brain-to-brain failure detection bounded in dev so master failover is testable.
		// Production uses a slightly larger bound to avoid churn from brief transients.
		brainPeerKeepaliveSeconds = (isDevMode ? prodigyBrainDevPeerKeepaliveSeconds : prodigyBrainPeerKeepaliveSeconds);

		// Fast-restore brain state from memfd if available
		{
			String brainState;
			int fd = -1;
			if (char *env = getenv("PRODIGY_BRAIN_STATE_FD"); env && env[0] != '\0')
			{
				fd = atoi(env);
			}
			else if (fcntl(4, F_GETFD) != -1)
			{
				fd = 4;
			}

			if (fd >= 0 && fcntl(fd, F_GETFD) != -1 && Memfd::readAll(fd, brainState))
			{
				MemfdBlobHeader header = {};
				const uint8_t *payload = nullptr;
				size_t payloadSize = 0;
				if (parseMemfdBlob(brainState, header, payload, payloadSize)
					&& header.kind == uint16_t(MemfdBlobKind::brainPlans))
				{
					String serializedPlans = {};
					serializedPlans.assign(reinterpret_cast<uint8_t *>(const_cast<uint8_t *>(payload)), payloadSize);
					Vector<DeploymentPlan> plans;
					if (BitseryEngine::deserializeSafe(serializedPlans, plans))
					{
						for (const auto& plan : plans)
						{
							deploymentPlans.insert_or_assign(plan.config.deploymentID(), plan);
						}
					}
				}
			}
		}

		// Connector ownership is derived from transport-address ordering until
		// registration exchanges persistent brain UUIDs, but the
		// listener itself must accept whichever IPv4/IPv6 address peers can route
		// to on this machine.
		brainSocket.setIPVersion(AF_INET6);
		setsockopt(brainSocket.fd, IPPROTO_IPV6, IPV6_V6ONLY, (const int[]){0}, sizeof(int));
		brainSocket.setKeepaliveTimeoutSeconds(brainPeerKeepaliveSeconds);
		brainSocket.setSaddr("::"_ctv, uint16_t(ReservedPorts::brain));
		brainSocket.bindThenListen();

		RingDispatcher::installMultiplexee(&brainSocket, this);
		Ring::installFDIntoFixedFileSlot(&brainSocket);
		brain_saddrlen = sizeof(brain_saddr);
		Ring::queueAccept(&brainSocket, reinterpret_cast<struct sockaddr *>(&brain_saddr), &brain_saddrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);

		CoroutineStack *coro = new CoroutineStack();

		bool selfIsBrain = false;
		ClusterTopology topology = {};
		if (loadAuthoritativeClusterTopology(topology) && topology.machines.empty() == false)
		{
			restoreBrainsFromClusterTopology(topology);

			for (const ClusterMachine& clusterMachine : topology.machines)
			{
				if (clusterMachine.isBrain == false)
				{
					continue;
				}

				if (clusterMachineMatchesThisBrain(clusterMachine))
				{
					selfIsBrain = true;
               Vector<ClusterMachinePeerAddress> peerAddresses;
               resolveClusterMachinePeerAddresses(clusterMachine, peerAddresses);
               adoptLocalBrainPeerAddresses(peerAddresses);
					IPAddress peerAddress = {};
					String peerAddressText = {};
					if (resolveClusterMachinePeerAddress(clusterMachine, peerAddress, peerAddressText))
					{
						adoptLocalBrainPeerAddress(peerAddress, peerAddressText);
					}
					break;
				}
			}

			nBrains = clusterTopologyBrainCount(topology);
         if (selfIsBrain)
         {
            refreshLocalBrainPeerAddresses();
         }
			delete coro;
		}
		else
		{
			uint32_t suspendIndex = coro->nextSuspendIndex();

			iaas->getBrains(coro, thisNeuron->uuid, selfIsBrain, brains);

			if (suspendIndex < coro->nextSuspendIndex())
			{
				co_await coro->suspendAtIndex(suspendIndex);
			}

			delete coro;

			nBrains = brains.size(); // every brain must be present and working for the cluster to initiate, but once it does it can run with fewer
			if (selfIsBrain) nBrains += 1;
			if (selfIsBrain)
			{
				(void)resolveLocalBrainPeerAddressFromIaaS();
            refreshLocalBrainPeerAddresses();
			}
		}

			for (BrainView *brain : brains)
			{
				initializeBrainPeerIfNeeded(brain);
			}

      std::fprintf(stderr, "prodigy brain getBrains selfIsBrain=%d nBrains=%u peerRegistrations=%u\n", int(selfIsBrain), nBrains, uint32_t(brains.size()));

		// Multi-brain bootstrap self-elects from brain registrations; only the elected master
		// should arm mothership listening.
		if (nBrains == 1)
		{
			basics_log("getBrains elect-self reason=single-brain-bootstrap\n");
			selfElectAsMaster("getBrains:single-brain-bootstrap"); // we are it
		}

      persistLocalRuntimeState();
	}

		void resetMasterBrainAssignment(void)
		{
			noMasterYet = true;
			isMasterMissing = false;
			pendingDesignatedMasterPeerKey = 0;

		for (BrainView *bv : brains)
		{
			bv->isMasterBrain = false;
			bv->isMasterMissing = false;
		}
	}

	virtual void configureCloudflareTunnel(String& mothershipEndpoint) = 0;
	virtual void teardownCloudflareTunnel(void) = 0;

		void configureMothershipUnixSocketPath(String& mothershipSocketPath)
		{
			resolveProdigyControlSocketPathFromProcess(mothershipSocketPath);
		}

			bool armMothershipUnixListener(void)
			{
				mothershipUnixAcceptArmed = false;
				mothershipUnixSocket.recreateSocket();
				mothershipUnixSocket.isFixedFile = false;
				mothershipUnixSocket.pendingSend = false;
			mothershipUnixSocket.pendingSendBytes = 0;
			mothershipUnixSocket.pendingRecv = false;

			configureMothershipUnixSocketPath(mothershipUnixSocketPath);
			if (mothershipUnixSocketPath.size() == 0)
			{
				basics_log("armMothershipUnixListener missing socket path\n");
				return false;
			}

			unlink(mothershipUnixSocketPath.c_str());
				mothershipUnixSocket.setSocketPath(mothershipUnixSocketPath.c_str());
				mothershipUnixSocket.saddr_storage = mothershipUnixSocket.daddr_storage;
				mothershipUnixSocket.saddrLen = mothershipUnixSocket.daddrLen;

            constexpr uint32_t bindRetryLimit = 50;
            bool listenerBound = false;
            for (uint32_t attempt = 1; attempt <= bindRetryLimit; attempt++)
            {
               unlink(mothershipUnixSocketPath.c_str());
               if (::bind(mothershipUnixSocket.fd, mothershipUnixSocket.saddr<struct sockaddr>(), mothershipUnixSocket.saddrLen) == 0)
               {
                  listenerBound = true;
                  break;
               }

               int err = errno;
               if (err == EADDRINUSE)
               {
                  if (attempt == bindRetryLimit)
                  {
                     basics_log("armMothershipUnixListener bind busy after retries path=%s; deferring election\n",
                        mothershipUnixSocketPath.c_str());
                     ::close(mothershipUnixSocket.fd);
                     mothershipUnixSocket.fd = -1;
                     return false;
                  }

                  usleep(20'000);
                  continue;
               }

               basics_log("armMothershipUnixListener bind failed path=%s errno=%d(%s)\n",
                  mothershipUnixSocketPath.c_str(),
                  err,
                  strerror(err));
               ::close(mothershipUnixSocket.fd);
               mothershipUnixSocket.fd = -1;
               return false;
            }

            if (listenerBound == false)
            {
               return false;
            }

            if (::listen(mothershipUnixSocket.fd, SOMAXCONN) != 0)
            {
               basics_log("armMothershipUnixListener listen failed path=%s errno=%d(%s)\n",
                  mothershipUnixSocketPath.c_str(),
                  errno,
                  strerror(errno));
               ::close(mothershipUnixSocket.fd);
               mothershipUnixSocket.fd = -1;
               return false;
            }

				RingDispatcher::installMultiplexee(&mothershipUnixSocket, this);
				Ring::installFDIntoFixedFileSlot(&mothershipUnixSocket);
				if (Ring::socketIsClosing(&mothershipUnixSocket) == false)
				{
					Ring::queueAccept(&mothershipUnixSocket, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
					mothershipUnixAcceptArmed = true;
					basics_log("armMothershipUnixListener queued initial accept path=%s isFixed=%d fd=%d fslot=%d weAreMaster=%d\n",
						mothershipUnixSocketPath.c_str(),
						int(mothershipUnixSocket.isFixedFile),
						mothershipUnixSocket.fd,
						mothershipUnixSocket.fslot,
						int(weAreMaster));
					std::fprintf(stderr, "prodigy mothership listen-arm transport=unix path=%s listenerFD=%d listenerFslot=%d master=%d phase=initial\n",
						mothershipUnixSocketPath.c_str(),
						mothershipUnixSocket.fd,
						mothershipUnixSocket.fslot,
						int(weAreMaster));
				std::fflush(stderr);
			}

			return true;
		}

			bool armMothershipListener(void)
			{
				// Recreate a clean listener socket for bootstrap and master transitions.
				mothershipAcceptArmed = false;
				mothershipSocket.recreateSocket();
				mothershipSocket.isFixedFile = false;
				mothershipSocket.pendingSend = false;
			mothershipSocket.pendingSendBytes = 0;
		mothershipSocket.pendingRecv = false;

		String mothershipEndpoint;
		configureCloudflareTunnel(mothershipEndpoint);
		if (mothershipEndpoint.size() == 0)
		{
			// Unix-socket-only control mode leaves the legacy TCP listener disabled.
			return false;
		}

		mothershipSocket.setIPVersion(AF_INET);
		mothershipSocket.setSaddr(mothershipEndpoint, uint16_t(ReservedPorts::mothership));

		constexpr uint32_t bindRetryLimit = 50;
		bool listenerBound = false;
		for (uint32_t attempt = 1; attempt <= bindRetryLimit; attempt++)
		{
			if (::bind(mothershipSocket.fd, mothershipSocket.saddr<struct sockaddr>(), mothershipSocket.saddrLen) == 0)
			{
				listenerBound = true;
				break;
			}

			int err = errno;
			if (err == EADDRINUSE)
			{
				if (attempt == bindRetryLimit)
				{
					basics_log("armMothershipListener bind busy after retries; deferring election\n");
					::close(mothershipSocket.fd);
					mothershipSocket.fd = -1;
					return false;
				}

				usleep(20'000);
				continue;
			}

			basics_log("armMothershipListener bind failed errno=%d(%s)\n", err, strerror(err));
			std::abort();
		}

		if (listenerBound == false)
		{
			return false;
		}

			if (::listen(mothershipSocket.fd, SOMAXCONN) != 0)
			{
				int err = errno;
				basics_log("armMothershipListener listen failed errno=%d(%s)\n", err, strerror(err));
				std::abort();
			}

					RingDispatcher::installMultiplexee(&mothershipSocket, this);
						Ring::installFDIntoFixedFileSlot(&mothershipSocket);
					// Bootstrap path: selfElectAsMaster() sets weAreMaster after this call,
					// so do not gate the first accept arm on weAreMaster.
					if (Ring::socketIsClosing(&mothershipSocket) == false)
					{
						Ring::queueAccept(&mothershipSocket, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
						mothershipAcceptArmed = true;
					basics_log("armMothershipListener queued initial accept isFixed=%d fd=%d fslot=%d weAreMaster=%d\n",
						int(mothershipSocket.isFixedFile),
						mothershipSocket.fd,
						mothershipSocket.fslot,
						int(weAreMaster));
					std::fprintf(stderr, "prodigy mothership listen-arm transport=tcp listenerFD=%d listenerFslot=%d master=%d phase=initial\n",
						mothershipSocket.fd,
						mothershipSocket.fslot,
						int(weAreMaster));
				std::fflush(stderr);
			}

				return true;
			}

		protected:

			virtual bool installNeuronControlSocketFromBrain(NeuronView *neuron)
			{
				return installNeuronControlSocket(neuron);
			}

			virtual void awaitSelfElectionMachineInventoryIfNeeded(CoroutineStack *coro, uint32_t suspendIndex)
			{
				if (coro && suspendIndex < coro->nextSuspendIndex())
				{
					co_await coro->suspendAtIndex(suspendIndex);
				}
			}

			virtual bool reconcileManagedMachineSchemasOnSelfElection(String *failure)
			{
				return reconcileManagedMachineSchemas(failure);
			}

		public:

		void forfeitMasterStatus(void)
		{
				basics_log("forfeitMasterStatus weAreMaster=%d\n", int(weAreMaster));
	      weAreMaster = false;
	      noMasterYet = true;
				mothershipAcceptArmed = false;
				mothershipUnixAcceptArmed = false;

	      teardownCloudflareTunnel();
			if (mothershipUnixSocketPath.size() > 0)
			{
				unlink(mothershipUnixSocketPath.c_str());
			}

	      // Relinquishing master also relinquishes any active mothership control stream.
	      if (mothership)
	      {
	         queueCloseIfActive(mothership);
	      }

	      if (mothershipSocket.isFixedFile)
	      {
	         if (mothershipSocket.fslot >= 0 && Ring::socketIsClosing(&mothershipSocket) == false)
	         {
	            Ring::queueClose(&mothershipSocket);
	         }
	      }
	      else if (mothershipSocket.fd >= 0 && Ring::socketIsClosing(&mothershipSocket) == false)
	      {
	         Ring::queueClose(&mothershipSocket);
	      }

			if (mothershipUnixSocket.isFixedFile)
			{
				if (mothershipUnixSocket.fslot >= 0 && Ring::socketIsClosing(&mothershipUnixSocket) == false)
				{
					Ring::queueClose(&mothershipUnixSocket);
				}
			}
			else if (mothershipUnixSocket.fd >= 0 && Ring::socketIsClosing(&mothershipUnixSocket) == false)
			{
				Ring::queueClose(&mothershipUnixSocket);
			}
	      // Only the active master may hold neuron control sockets.
	      for (NeuronView *nv : neurons)
	      {
				disarmNeuronControlReconnect(nv);
				nv->connected = false;
	         if (nv->isFixedFile)
	         {
	            if (nv->fslot >= 0 && Ring::socketIsClosing(nv) == false)
	            {
	               Ring::queueClose(nv);
	            }
	         }
	         else if (nv->fd >= 0 && Ring::socketIsClosing(nv) == false)
	         {
	            Ring::queueClose(nv);
	         }
	      }
	   }

		void selfElectAsMaster(const char *reason = "unspecified")
		{
			basics_log("selfElectAsMaster begin weAreMaster=%d reason=%s\n", int(weAreMaster), reason);
			if (weAreMaster)
			{
				co_return;
			}

			// Promotion must flip master ownership before listener arm so any immediate
			// close CQE races on mothership control-listener re-arm through closeHandler.
			weAreMaster = true;

			if (armMothershipUnixListener() == false)
			{
				weAreMaster = false;
				co_return;
			}

			(void)armMothershipListener();

				noMasterYet = false;
				pendingDesignatedMasterPeerKey = 0;
				masterQuorumDegraded = false;
				hasCompletedInitialMasterElection = true;
            noteMasterAuthorityRuntimeStateChanged();
            refreshAllDeploymentWormholeQuicCidState(false);
				basics_log("selfElectAsMaster complete\n");

		// During handover/updateProdigy a connector-owned peer link may already be
		// in failed state. Re-arm outbound connectors immediately on promotion so
		// peer-mesh quorum can recover inside the post-handover window.
		for (BrainView *bv : brains)
		{
			if (bv == nullptr || bv->weConnectToIt == false)
			{
				continue;
			}

			if (peerSocketActive(bv))
			{
				continue;
			}

			armOutboundPeerReconnect(bv);
		}

		// Broadcast our selected-master identity immediately so peers converge on this master.
			for (BrainView *bv : brains)
			{
				if (bv->quarantined) continue;
				bv->sendRegistration(boottimens, version, getExistingMasterUUID());
			}

				// Existing peer links and canonical connector ownership are sufficient here.

			CoroutineStack *coro = new CoroutineStack();

		uint32_t suspendIndex = coro->nextSuspendIndex();

		getMachines(coro);

		awaitSelfElectionMachineInventoryIfNeeded(coro, suspendIndex);

			delete coro;

			// Re-arm neuron control-plane sockets after machine inventory is known.
			// This must run after getMachines() because followers may not have
			// populated neuron socket state before becoming master.
			for (Machine *machine : machines)
			{
				NeuronView *nv = &machine->neuron;

				neurons.insert(nv);
				RingDispatcher::installMultiplexee(nv, this);
				nv->nConnectionAttempts = 0;
				nv->nAttemptsBudget = 0;
				nv->reconnectAfterClose = true;

				bool reconnectArmedByClose = Ring::socketIsClosing(nv);
				if (reconnectArmedByClose == false)
				{
					if (neuronControlSocketArmed(machine))
					{
						// Restored/master-inherited fixed slots are only reusable if the
						// transport is actually live or still progressing. Preserving a
						// disconnected fixed slot strands the master queueing control
						// traffic into a dead neuron stream.
						if (neuronControlStreamActive(machine) || nv->pendingSend || nv->pendingRecv)
						{
							continue;
						}

						abandonSocketGeneration(nv);
					}
				}

				if (reconnectArmedByClose == false)
				{
					nv->recreateSocket();
					if (installNeuronControlSocketFromBrain(nv))
					{
						nv->attemptForMs(BrainBase::machineInitialConnectAttemptTimeMs(
							machine->creationTimeMs,
							nv->connectTimeoutMs,
							nv->nDefaultAttemptsBudget));
						nv->attemptConnect();
					}
				}
			}

			for (const auto& [deploymentID, plan] : deploymentPlans)
			{
			ApplicationDeployment *deployment = new ApplicationDeployment(); // as neurons register and upload their state, these deployments will be populated
			deployment->plan = plan;

			deployments.insert_or_assign(plan.config.deploymentID(), deployment);

			if (auto it = deploymentsByApp.find(plan.config.applicationID); it != deploymentsByApp.end())
			{
				ApplicationDeployment *other = it->second;

				if (other->plan.config.versionID < deployment->plan.config.versionID)
				{
					// replace
					deploymentsByApp.insert_or_assign(plan.config.applicationID, deployment);
					deployment->previous = other;
					other->next = deployment;
				}
			}
			else
			{
				deploymentsByApp.insert_or_assign(plan.config.applicationID, deployment);
			}
		}

			// Deployment recovery still waits for healthy machine state transitions, but
			// interrupted addMachines journaling can resume immediately on promotion.
			deploymentPlans.clear();
         resumePendingAddMachinesOperations();
         String managedSchemaReconcileFailure = {};
         if (reconcileManagedMachineSchemasOnSelfElection(&managedSchemaReconcileFailure) == false)
         {
            basics_log("selfElectAsMaster managed machine schema reconcile failed reason=%s\n",
               managedSchemaReconcileFailure.c_str());
         }
		}

		void electBrainToMaster(BrainView *brain)
		{
			if (brain == nullptr)
			{
				return;
			}

			if (weAreMaster)
			{
				forfeitMasterStatus();
			}
			else
			{
				// Peer-master convergence must hard-stop any stale local ownership too.
				// Followers never hold commander or neuron control sockets.
				queueCloseIfActive(&mothershipSocket);
				queueCloseIfActive(&mothershipUnixSocket);
				if (mothership)
				{
					queueCloseIfActive(mothership);
				}

				for (NeuronView *nv : neurons)
				{
					disarmNeuronControlReconnect(nv);
					nv->connected = false;
					queueCloseIfActive(nv);
				}
			}

			noMasterYet = false;
			pendingDesignatedMasterPeerKey = 0;
			brain->isMasterBrain = true;
			hasCompletedInitialMasterElection = true;
			String masterUUIDText = {};
			masterUUIDText.snprintf<"{itoa}"_ctv>(brain->uuid);
			basics_log("electBrainToMaster uuid=%s\n", masterUUIDText.c_str());

         persistLocalRuntimeState();
		}

	void deriveMasterBrain(bool allowExistingMasterClaims = true)
	{
		// Initial master is cluster-derived, not mothership-selected.

      // when we first seed a datacenter, we'll seed the first machine first brain first. provide it subnets. let it become operational.
      // at this stage it's effectively a single-brain cluster (nBrainsExpected == 1). we can then instruct it to create the next 2 brains...
      // and then tell it to add them to its pool (this add function would be handy for our test environment to just "add" hardware we manually add, not cloud hardware we spin)
		// we can virtualize the API interacting functions... and create a subclassed Brain object for production vs ProdigyDev (using our LAN, for now)

		// it's possible we were master.. then lost connectivity.. then reconnected... only to discover that a master was voted in..
		// in that case we need to just recognize that as master..

			if (noMasterYet)
			{
				uint32_t nRegisteredBrains = 1; // include self
				for (BrainView *bv : brains)
				{
					if (peerEligibleForClusterQuorum(bv) && bv->boottimens > 0)
					{
						nRegisteredBrains += 1;
					}
				}

				// Initial bootstrap requires full registration across the fixed brain set.
				// After the first successful election, failover can proceed with majority.
				const uint32_t requiredRegisteredBrains =
					hasCompletedInitialMasterElection ? (uint32_t(nBrains / 2) + 1) : nBrains;
				basics_log("deriveMasterBrain gate hasInitial=%d nBrains=%u nRegistered=%u required=%u\n",
					int(hasCompletedInitialMasterElection), nBrains, nRegisteredBrains, requiredRegisteredBrains);
				if (nRegisteredBrains < requiredRegisteredBrains)
				{
					return;
				}

				if (hasCompletedInitialMasterElection && allowExistingMasterClaims == false)
				{
					bool preferSelfByAddressOrder = false;
					bool sawActivePeer = false;
					if (resolveFailoverMasterByActivePeerAddressOrder(preferSelfByAddressOrder, &sawActivePeer))
					{
						if (preferSelfByAddressOrder)
						{
							basics_log("deriveMasterBrain elect-self reason=active-peer-address-order\n");
							selfElectAsMaster("deriveMasterBrain:active-peer-address-order");
						}
						else
						{
							basics_log("deriveMasterBrain waiting for lower-address active peer to self-elect\n");
						}

						return;
					}

					if (sawActivePeer)
					{
						basics_log("deriveMasterBrain waiting for active peer identity convergence\n");
						return;
					}
				}

				if (activeBrainRegistrationsReadyForMasterElection() == false)
				{
					basics_log("deriveMasterBrain waiting for active peer registrations\n");
					return;
				}

				uint128_t existingMasterUUID = 0;
				if (allowExistingMasterClaims)
				{
					existingMasterUUID = resolveConsistentExistingMasterUUID();
				}

				for (BrainView *brain : brains)
				{
					brain->existingMasterUUID = 0; // clear all of these
				}

				bool adoptedExistingMaster = false;
				if (existingMasterUUID > 0) // peers report a consistent existing master
				{
					if (existingMasterUUID == selfBrainUUID())
					{
						// If a live quorum reports us as master, keep ownership.
						basics_log("deriveMasterBrain elect-self reason=consistent-existing-master\n");
						selfElectAsMaster("deriveMasterBrain:consistent-existing-master");
						adoptedExistingMaster = true;
					}
					else
					{
						if (BrainView *brain = findBrainViewByUUID(existingMasterUUID); brain != nullptr)
						{
							// Never adopt a missing/stale master candidate.
							if (brain->quarantined == false && brain->boottimens > 0)
							{
								electBrainToMaster(brain);
								adoptedExistingMaster = true;
							}
						}
					}
				}

				if (adoptedExistingMaster == false) // we need to derive one
				{
					if (hasCompletedInitialMasterElection)
					{
						bool preferSelfByAddressOrder = false;
						bool sawActivePeer = false;
						if (resolveFailoverMasterByActivePeerAddressOrder(preferSelfByAddressOrder, &sawActivePeer))
						{
							if (preferSelfByAddressOrder)
							{
								basics_log("deriveMasterBrain elect-self reason=active-peer-address-order\n");
								selfElectAsMaster("deriveMasterBrain:active-peer-address-order");
							}
							else
							{
								basics_log("deriveMasterBrain waiting for lower-address active peer to self-elect\n");
							}

							return;
						}

						if (sawActivePeer)
						{
							basics_log("deriveMasterBrain waiting for active peer identity convergence\n");
							return;
						}
					}

					uint128_t derivedMasterUUID = deriveRegisteredMasterUUID();
					{
						String derivedMasterUUIDText = {};
						String selfUUIDText = {};
						derivedMasterUUIDText.snprintf<"{itoa}"_ctv>(derivedMasterUUID);
						selfUUIDText.snprintf<"{itoa}"_ctv>(selfBrainUUID());
						basics_log("deriveMasterBrain fallback derivedUUID=%s selfUUID=%s\n",
							derivedMasterUUIDText.c_str(),
							selfUUIDText.c_str());
					}
					if (derivedMasterUUID == 0 || derivedMasterUUID == selfBrainUUID())
					{
						basics_log("deriveMasterBrain elect-self reason=derived-master-uuid\n");
						selfElectAsMaster("deriveMasterBrain:derived-master-uuid");
					}
						else if (BrainView *master = findBrainViewByUUID(derivedMasterUUID); master != nullptr)
						{
							electBrainToMaster(master);
						}
				}
		}

      persistLocalRuntimeState();
	}

	void deriveMasterBrainIf(void)
	{
		float aliveRatio = calculateAliveBrainRatio();
		bool connectedMajority = hasConnectedBrainMajority();
		basics_log("deriveMasterBrainIf isMasterMissing=%d aliveRatio=%.3f connectedMajority=%d\n",
			int(isMasterMissing), aliveRatio, int(connectedMajority));
		resetMasterBrainAssignment(); // either we now have no brain, or we derive a new one

		if (aliveRatio > 0.5f && connectedMajority)
		{
			// an outright majority of machines are alive and they all voted the master is missing

			// so derive a new master
			deriveMasterBrain(false);
		}
		else
		{
			// everyone alive agrees (might be no-one)
			// but to move forward we'd need to at least make sure those machines are really dead, not isolated

			// it's possible the master spuriously regained network here and reconnected??? that would've triggered brainFound()
			// even if, deriveMasterBrain will still rederive the correct master or fail if it hasn't registered yet

			// our switch can't be dead because we're only in here because someone responded

			bool reachableSwitchMajority = false;
			checkMetroReachabilityForMasterFailover(connectedMajority, reachableSwitchMajority);
			if (reachableSwitchMajority && connectedMajority)
			{
				// now counting alive (at least 1 other machine besdies us) + reachable, we have a majority
				deriveMasterBrain(false);
			}
			else
			{
				// we don't have a majority so no brain right now... (this could only happen if we ever upgraded to 5 brains from 3, otherwise we'd
				// always have 1 other brain alive, making 2 alive brains, to even be in this message handler)
			}
		}
	}

	virtual void checkMetroReachabilityForMasterFailover(bool& connectedMajority, bool& reachableSwitchMajority)
	{
		std::unique_ptr<MetroNetworkMonitor> monitor = std::make_unique<MetroNetworkMonitor>();
		monitor->check(thisNeuron->private4.v4, thisNeuron->gateway4.v4, brains);
		co_await monitor->suspend();

		connectedMajority = hasConnectedBrainMajority();
		reachableSwitchMajority = (monitor->ratioOfReachableSwitches() > 0.5f);
	}

	static bool selectScaleOutMachineConfig(const bytell_hash_map<String, MachineConfig>& configBySlug, const ApplicationConfig& config, uint32_t nMore, String& selectedSlug, const MachineConfig *&selectedConfig)
	{
		selectedSlug.clear();
		selectedConfig = nullptr;

		if (nMore == 0)
		{
			return false;
		}

		auto divideAndRoundUp = [] (uint64_t numerator, uint32_t denominator, uint32_t& result) -> bool {

			if (denominator == 0)
			{
				return false;
			}

			uint64_t quotient = (numerator + denominator - 1) / denominator;
			if (quotient == 0 || quotient > UINT32_MAX)
			{
				return false;
			}

			result = uint32_t(quotient);
			return true;
		};

		auto lexicalLess = [] (const String& a, const String& b) -> bool {

			uint64_t limit = std::min(a.size(), b.size());
			int comparison = memcmp(a.data(), b.data(), limit);
			if (comparison != 0)
			{
				return comparison < 0;
			}

			return a.size() < b.size();
		};

      uint16_t overcommitPermille = prodigySharedCPUOvercommitMinPermille;
      if (thisBrain != nullptr)
      {
         overcommitPermille = prodigySharedCPUOvercommitPermille(thisBrain->brainConfig.sharedCPUOvercommitPermille);
      }

		uint64_t requiredCPUUnits = applicationUsesSharedCPUs(config)
         ? (uint64_t(nMore) * uint64_t(applicationRequestedCPUMillis(config)))
         : (uint64_t(nMore) * uint64_t(config.nLogicalCores));
		uint64_t requiredMemoryMB = uint64_t(nMore) * config.totalMemoryMB();
		uint64_t requiredStorageMB = uint64_t(nMore) * config.totalStorageMB();

		uint32_t bestMachineCount = UINT32_MAX;
		uint64_t bestWasteCores = UINT64_MAX;
		uint64_t bestWasteMemoryMB = UINT64_MAX;
		uint64_t bestWasteStorageMB = UINT64_MAX;

		for (const auto& [candidateSlug, candidateConfig] : configBySlug)
		{
         if (config.architecture != MachineCpuArchitecture::unknown)
         {
            if (candidateConfig.cpu.architecture == MachineCpuArchitecture::unknown
               || candidateConfig.cpu.architecture != config.architecture)
            {
               continue;
            }
         }

         if (config.requiredIsaFeatures.empty() == false)
         {
            if (candidateConfig.cpu.authoritative() == false
               || prodigyIsaFeaturesMeetRequirements(candidateConfig.cpu.isaFeatures, config.requiredIsaFeatures) == false)
            {
               continue;
            }
         }

			uint32_t nByCores;
			uint32_t nByMemory;
			uint32_t nByStorage;

         uint64_t candidateCPUCapacity = applicationUsesSharedCPUs(config)
            ? (uint64_t(candidateConfig.nLogicalCores) * uint64_t(overcommitPermille))
            : uint64_t(candidateConfig.nLogicalCores);

			if (divideAndRoundUp(requiredCPUUnits, candidateCPUCapacity, nByCores) == false
				|| divideAndRoundUp(requiredMemoryMB, candidateConfig.nMemoryMB, nByMemory) == false
				|| divideAndRoundUp(requiredStorageMB, candidateConfig.nStorageMB, nByStorage) == false)
			{
				continue;
			}

			uint32_t machineCount = nByCores;
			if (nByMemory > machineCount) machineCount = nByMemory;
			if (nByStorage > machineCount) machineCount = nByStorage;

			uint64_t wasteCores = (uint64_t(machineCount) * candidateCPUCapacity) - requiredCPUUnits;
			uint64_t wasteMemoryMB = (uint64_t(machineCount) * candidateConfig.nMemoryMB) - requiredMemoryMB;
			uint64_t wasteStorageMB = (uint64_t(machineCount) * candidateConfig.nStorageMB) - requiredStorageMB;

			bool takeCandidate = false;
			if (selectedConfig == nullptr)
			{
				takeCandidate = true;
			}
			else if (machineCount < bestMachineCount)
			{
				takeCandidate = true;
			}
			else if (machineCount == bestMachineCount)
			{
				if (wasteCores < bestWasteCores)
				{
					takeCandidate = true;
				}
				else if (wasteCores == bestWasteCores)
				{
					if (wasteMemoryMB < bestWasteMemoryMB)
					{
						takeCandidate = true;
					}
					else if (wasteMemoryMB == bestWasteMemoryMB)
					{
						if (wasteStorageMB < bestWasteStorageMB)
						{
							takeCandidate = true;
						}
						else if (wasteStorageMB == bestWasteStorageMB && lexicalLess(candidateSlug, selectedSlug))
						{
							takeCandidate = true;
						}
					}
				}
			}

			if (takeCandidate)
			{
				selectedSlug = candidateSlug;
				selectedConfig = &candidateConfig;
				bestMachineCount = machineCount;
				bestWasteCores = wasteCores;
				bestWasteMemoryMB = wasteMemoryMB;
				bestWasteStorageMB = wasteStorageMB;
			}
		}

		return selectedConfig != nullptr;
	}

	void requestMachines(MachineTicket *ticket, ApplicationDeployment *deployment, ApplicationLifetime lifetime, uint32_t nMore) override
	{
		const ApplicationConfig& config = deployment->plan.config;

		retry: // there will be new MachineState::deploying machines now

			for (Machine *machine : machines)
			{
				if (machine->state == MachineState::deploying)
				{
					switch (lifetime)
					{
					case ApplicationLifetime::base:
					case ApplicationLifetime::canary:
					{
						if (machine->lifetime == MachineLifetime::spot) continue;
						break;
					}
					case ApplicationLifetime::surge:
					{
						if (machine->lifetime != MachineLifetime::spot) continue;
						break;
					}
				}

				// we need to log claims on machines otherwise it's impossible to know from one invocation of requestMachines to the next
				// how many of the resources of previously requested machines are spoken for, and thus would have to spin up new machines for
				// each invocation

				uint32_t nFit = deployment->nFitOnMachineClaim(ticket, machine, nMore);

				if (nFit > 0)
				{
					nMore -= nFit;

					if (nMore == 0) break;
				}
			}
		}

		if (nMore > 0) // we still need more machines
		{
			MachineLifetime machineLifetime;

			switch (lifetime)
			{
				case ApplicationLifetime::base:
				{
					// predictReservedCapacity30Days();
					[[fallthrough]];
				}
				case ApplicationLifetime::canary:
				{
					machineLifetime = MachineLifetime::ondemand;
					break;
				}
				case ApplicationLifetime::surge:
				{
					machineLifetime = MachineLifetime::spot;
					break;
				}
			}

			String slug;
			const MachineConfig *machineConfig = nullptr;

			if (selectScaleOutMachineConfig(brainConfig.configBySlug, config, nMore, slug, machineConfig) == false)
			{
				String message;
				message.append("unable to select a machine config for additional capacity\n"_ctv);
				message.snprintf_add<"Application: {itoa}\n"_ctv>(config.applicationID);
				message.snprintf_add<"Deployment: {itoa}\n"_ctv>(config.deploymentID());
				message.snprintf_add<"Lifetime: {itoa}\n"_ctv>(uint64_t(lifetime));
				message.snprintf_add<"RequestedInstances: {itoa}\n"_ctv>(nMore);
            if (applicationUsesSharedCPUs(config))
            {
               message.snprintf_add<"PerInstanceSharedCPUMillis: {itoa}\n"_ctv>(applicationRequestedCPUMillis(config));
            }
            else
            {
				   message.snprintf_add<"PerInstanceCores: {itoa}\n"_ctv>(config.nLogicalCores);
            }
				message.snprintf_add<"PerInstanceMemoryMB: {itoa}\n"_ctv>(config.totalMemoryMB());
				message.snprintf_add<"PerInstanceStorageMB: {itoa}\n"_ctv>(config.totalStorageMB());
				batphone.sendEmail(brainConfig.reporter.from, brainConfig.reporter.to, "unable to select machines master! 🤖"_ctv, message);
				co_return;
			}

			auto divideAndRoundUp = [=] (uint64_t numerator, uint64_t denominator) -> uint32_t {

				return uint32_t((numerator + denominator - 1) / denominator);
			};

         uint16_t overcommitPermille = prodigySharedCPUOvercommitPermille(brainConfig.sharedCPUOvercommitPermille);
         uint64_t requiredCPUUnits = applicationUsesSharedCPUs(config)
            ? (uint64_t(nMore) * uint64_t(applicationRequestedCPUMillis(config)))
            : (uint64_t(nMore) * uint64_t(config.nLogicalCores));
         uint64_t machineCPUCapacity = applicationUsesSharedCPUs(config)
            ? (uint64_t(machineConfig->nLogicalCores) * uint64_t(overcommitPermille))
            : uint64_t(machineConfig->nLogicalCores);

			uint32_t nByCores = divideAndRoundUp(requiredCPUUnits, machineCPUCapacity);
			uint32_t nByMemory = divideAndRoundUp(uint64_t(nMore) * config.totalMemoryMB(), machineConfig->nMemoryMB);
			uint32_t nByStorage = divideAndRoundUp(uint64_t(nMore) * config.totalStorageMB(), machineConfig->nStorageMB);

			uint32_t nMoreMachines = nByCores;
			if (nByMemory > nMoreMachines) nMoreMachines = nByMemory;
			if (nByStorage > nMoreMachines) nMoreMachines = nByStorage;

			// always email when creating more machines
			String message;
			message.append("we require more hardware to spin these additional instances:\n"_ctv);
			message.snprintf_add<"Application: {itoa}\n"_ctv>(config.applicationID);
			message.snprintf_add<"Deployment: {itoa}\n"_ctv>(config.deploymentID());

			switch (lifetime)
			{
				case ApplicationLifetime::base:
				{
					message.append("Application Lifetime: base\n"_ctv);
					break;
				}
				case ApplicationLifetime::surge:
				{
					message.append("Application Lifetime: surge\n"_ctv);
					break;
				}
				case ApplicationLifetime::canary:
				{
					message.append("Application Lifetime: canary\n"_ctv);
					break;
				}
			}

			message.snprintf_add<"nInstances: {itoa}\n"_ctv>(nMore);
         if (applicationUsesSharedCPUs(config))
         {
            message.snprintf_add<"Shared CPU per Instance (millis): {itoa}\n"_ctv>(applicationRequestedCPUMillis(config));
            message.snprintf_add<"Shared CPU Overcommit Permille: {itoa}\n"_ctv>(unsigned(overcommitPermille));
         }
         else
         {
			   message.snprintf_add<"Logical Cores per Instance: {itoa}\n"_ctv>(config.nLogicalCores);
         }
			message.snprintf_add<"Memory MB per Instance: {itoa}\n"_ctv>(config.totalMemoryMB());
			message.snprintf_add<"Storage MB per Instance: {itoa}\n"_ctv>(config.totalStorageMB());
			message.append("\n"_ctv);
			message.append("spinning these machines:\n"_ctv);

			switch (lifetime)
			{
				case ApplicationLifetime::base:
				case ApplicationLifetime::canary:
				{
					message.append("Machine Lifetime: ondemand\n"_ctv);
					break;
				}
				case ApplicationLifetime::surge:
				{
					message.append("Machine Lifetime: spot\n"_ctv);
					break;
				}
			}

			message.snprintf_add<"Slug: {}\n"_ctv>(slug);
			message.snprintf_add<"nMachines: {}\n"_ctv>(nMoreMachines);

			switch (machineLifetime)
			{
				case MachineLifetime::owned:
				{
					batphone.sendEmail(brainConfig.reporter.from, brainConfig.reporter.to, "i am spinning Owned machines master! 🤖"_ctv, message);
					break;
				}
				case MachineLifetime::reserved:
				{
					batphone.sendEmail(brainConfig.reporter.from, brainConfig.reporter.to, "i am spinning Reserved machines master! 🤖"_ctv, message);
					break;
				}
				default:
				case MachineLifetime::ondemand:
				{
					batphone.sendEmail(brainConfig.reporter.from, brainConfig.reporter.to, "i am spinning OnDemand machines master! 🤖"_ctv, message);
					break;
				}
				case MachineLifetime::spot:
				{
					batphone.sendEmail(brainConfig.reporter.from, brainConfig.reporter.to, "i am spinning Spot machines master! 🤖"_ctv, message);
					break;
				}
			}

				CoroutineStack *coro = new CoroutineStack();

				String error;

				uint32_t suspendIndex = coro->nextSuspendIndex();

            iaas->configureProvisioningClusterUUID(brainConfig.clusterUUID);
				iaas->spinMachines(coro, machineLifetime, *machineConfig, nMoreMachines, machines, error);

				if (suspendIndex < coro->nextSuspendIndex())
				{
					co_await coro->suspendAtIndex(suspendIndex);
				}

			delete coro;

			goto retry;
		}
	}

	void decommissionMachine(Machine *machine)
	{
		basics_log("decommissionMachine uuid=%llu private4=%u state=%u isBrain=%d cloudID=%s containers=%llu\n",
			(unsigned long long)(machine ? machine->uuid : 0),
			unsigned(machine ? machine->private4 : 0u),
			unsigned(machine ? machine->state : MachineState::unknown),
			int(machine ? machine->isBrain : false),
			(machine ? machine->cloudID.c_str() : ""),
			(unsigned long long)(machine ? machine->containersByDeploymentID.size() : 0u));

		evacuateFailedMachineContainers(machine);

		// if we need another machine, the deployments will request it

		if (machine->state == MachineState::hardwareFailure)
		{
			// destroy it
			iaas->destroyMachine(machine);
		}

		if (machine->fragment > 0)
		{
			relinquishMachineFragment(machine);
		}

		machines.erase(machine);
		machinesByUUID.erase(machine->uuid);
	      neurons.erase(&machine->neuron);

		for (MachineSSH *ssh : sshs)
		{
			if (ssh && ssh->machine == machine)
			{
				ssh->machine = nullptr;
			}
		}

		if (machine->brain)
		{
			machine->brain->machine = nullptr;
		}
		machine->brain = nullptr;
		machine->neuron.machine = nullptr;

      RingDispatcher::eraseMultiplexee(&machine->neuron);
      // Remove the Machine* mapping used for timeout originator routing
      RingDispatcher::eraseMultiplexee(machine);

		/// we have to close the socket.
		/// This object is deleted immediately, so close by raw slot/fd instead of
		/// pointer-based queueClose() callback dispatch.
			if (machine->neuron.isFixedFile)
			{
				if (machine->neuron.fslot >= 0)
				{
					Ring::queueCloseRaw(machine->neuron.fslot);
					machine->neuron.fslot = -1;
				}
			}
			else if (machine->neuron.fd >= 0)
			{
				machine->neuron.close();
				machine->neuron.fd = -1;
			}
			machine->neuron.isFixedFile = false;

		Rack *rack = machine->rack;
		rack->machines.erase(machine);

		if (rack->machines.size() == 0) // destroy rack too
		{
			racks.erase(rack->uuid);
			delete rack;
		}

		delete machine;
	}

	void checkForSpotTerminations(void)
	{
		CoroutineStack *coro = new CoroutineStack();

		Vector<String> decommissionedIDs;

		if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&] (void) -> void { iaas->checkForSpotTerminations(coro, decommissionedIDs); }))
		{
			co_await coro->suspendAtIndex(suspendIndex);
		}

		if (decommissionedIDs.size() > 0)
		{
			for (const String& id : decommissionedIDs)
			{
				Machine *machine = nullptr;
				for (const auto& pair : machinesByUUID)
				{
					if (pair.second && pair.second->cloudID == id)
					{
						machine = pair.second;
						break;
					}
				}

				if (machine == nullptr)
				{
					uint128_t uuid = String::numberFromHexString<uint128_t>(id);

					if (auto it = machinesByUUID.find(uuid); it != machinesByUUID.end())
					{
						machine = it->second;
					}
				}

				if (machine)
				{
					machine->state = MachineState::decommissioning;
					decommissionMachine(machine);
				}
			}
		}

		delete coro;
	}

   // Initiate drain on a single machine by asking every deployment with
   // containers on it to evacuate (kill/move) those containers. When the
   // last container departs, container lifecycle events will trigger
   // isMachineDrained(machine), which in turn performs the next step
   // (triggering the OS update when state==updatingOS).
	   void drainMachine(Machine *machine)
	{
		// we could be draining for multiple reasons, so machine->state set before this

		for (const auto& [deploymentID, containers] : machine->containersByDeploymentID)
		{
			(void)containers;
			if (auto deployment = deployments.find(deploymentID); deployment != deployments.end() && deployment->second)
			{
				deployment->second->drainMachine(machine, false);
			}
		}
	}

	void evacuateFailedMachineContainers(Machine *machine)
	{
		if (machine == nullptr)
		{
			return;
		}

		basics_log("evacuateFailedMachineContainers missingPrivate4=%u trackedContainers=%llu\n",
			machine->private4,
			(unsigned long long)containers.size());

			// Containers may still reference an equivalent Machine object through an older
			// snapshot. Drain every machine object that still resolves to the same machine
			// identity so failover does not strand deployment bins on duplicate objects.
			bytell_hash_set<Machine *> drainTargets;
			drainTargets.insert(machine);

			for (const auto& [containerUUID, container] : containers)
			{
				(void)containerUUID;
				if (container && container->machine && prodigyMachinesShareIdentity(*container->machine, *machine))
				{
					drainTargets.insert(container->machine);
				}
			}

		basics_log("evacuateFailedMachineContainers missingPrivate4=%u drainTargets=%llu\n",
			machine->private4,
			(unsigned long long)drainTargets.size());

		for (Machine *target : drainTargets)
		{
			if (target == nullptr || target->containersByDeploymentID.size() == 0)
			{
				if (target)
				{
					basics_log("evacuateFailedMachineContainers targetPrivate4=%u deploymentBins=0\n", target->private4);
				}
				continue;
			}

			basics_log("evacuateFailedMachineContainers targetPrivate4=%u deploymentBins=%llu\n",
				target->private4,
				(unsigned long long)target->containersByDeploymentID.size());

			for (const auto& [deploymentID, containersOnMachine] : target->containersByDeploymentID)
			{
				(void)containersOnMachine;
				if (auto it = deployments.find(deploymentID); it != deployments.end() && it->second)
				{
					it->second->drainMachine(target, true);
				}
			}

			target->containersByDeploymentID.clear();
		}
	}

   // Called opportunistically after container lifecycle events (destroy/failed)
   // to check whether the machine is now empty. If we were draining for an OS
   // update, this is where we actually trigger the OS update (neuron reboot).
   // NOTE: The drain scheduler's in-flight counters should be decremented when
   // the machine returns healthy after the reboot. See onDrainCompleteForOSUpdate.
   void isMachineDrained(Machine *machine)
	{
		if (machine->containersByDeploymentID.size() == 0)
		{
			switch (machine->state)
			{
				case MachineState::updatingOS:
				{
					machine->triggerOSUpdate();

					break;
				}
				case MachineState::decommissioning:
				{
					iaas->destroyMachine(machine);
					break;
				}
				default: break;
			}
		}
	}

	void scheduleNextOperatingSystemUpdate(void)
	{
		// we need to schedule the first update...
		Machine *machine = operatingSystemUpdateOrder.back();

		// every 30 days
		int64_t untilUpdateMs = machine->lastUpdatedOSMs + thirtyDaysInMilliseconds - Time::now<TimeResolution::ms>();

		// is this at least.. some minimum number of seconds in the future?
		// untilUpdateMs could also be in the past
		if (untilUpdateMs < thirtySecondsInMilliseconds) untilUpdateMs = thirtySecondsInMilliseconds;

		osUpdateTimer.setTimeoutMs(untilUpdateMs);
		Ring::queueTimeout(&osUpdateTimer);
	}

	bool isActiveMaster(void) const
	{
		return weAreMaster;
	}

		bool shouldReconnectNeuronControl(NeuronView *neuron) const
		{
			return (weAreMaster && neuron != nullptr && const_cast<NeuronView *>(neuron)->shouldReconnect());
		}

		bool canControlNeurons(void) const override
		{
			return weAreMaster;
		}

	protected:

		void armMachineNeuronControl(Machine *machine) override
		{
			if (machine == nullptr)
			{
				return;
			}

			neurons.insert(&machine->neuron);
			if (weAreMaster == false)
			{
				disarmNeuronControlReconnect(&machine->neuron);
				machine->neuron.connected = false;
				queueCloseIfActive(&machine->neuron);
				basics_log("brain armMachineNeuronControl skip-follower uuid=%llu private4=%u privateAddress=%s fd=%d isFixed=%d fslot=%d\n",
					(unsigned long long)machine->uuid,
					unsigned(machine->private4),
					machine->privateAddress.c_str(),
					machine->neuron.fd,
					int(machine->neuron.isFixedFile),
					machine->neuron.fslot);
				return;
			}

			basics_log("brain armMachineNeuronControl uuid=%llu private4=%u privateAddress=%s isThisMachine=%d fd=%d isFixed=%d fslot=%d\n",
				(unsigned long long)machine->uuid,
				unsigned(machine->private4),
				machine->privateAddress.c_str(),
				int(machine->isThisMachine),
				machine->neuron.fd,
				int(machine->neuron.isFixedFile),
				machine->neuron.fslot);
			BrainBase::armMachineNeuronControl(machine);
		}

	public:

	void onDrainCompleteForOSUpdate(Machine *machine)
	{
		(void)machine;
	}

	void armMachineUpdateTimerIfNeeded(void)
	{
		// Compatibility no-op for partially merged OS-drain scheduler.
	}

	void cancelMachineSoftWatchdog(Machine *machine)
	{
		if (machine == nullptr)
		{
			return;
		}

		if (machines.contains(machine) == false)
		{
			return;
		}

		if (machine->softWatchdog)
		{
			TimeoutPacket *watchdog = machine->softWatchdog;
			machine->softWatchdog = nullptr;

			RingDispatcher::eraseMultiplexee(watchdog);
			watchdog->flags = uint64_t(BrainTimeoutFlags::canceled);
			Ring::queueCancelTimeout(watchdog);
		}
	}

	void cancelMachineHardRebootWatchdog(Machine *machine)
	{
		if (machine == nullptr)
		{
			return;
		}

		if (machines.contains(machine) == false)
		{
			return;
		}

		if (machine->hardRebootWatchdog)
		{
			TimeoutPacket *watchdog = machine->hardRebootWatchdog;
			machine->hardRebootWatchdog = nullptr;

			RingDispatcher::eraseMultiplexee(watchdog);
			watchdog->flags = uint64_t(BrainTimeoutFlags::canceled);
			Ring::queueCancelTimeout(watchdog);
		}
	}

	void dispatchTimeout(TimeoutPacket *packet) override
	{
			switch (BrainTimeoutFlags(packet->flags))
		{
			case BrainTimeoutFlags::canceled:
			{
				RingDispatcher::eraseMultiplexee(packet);
				delete packet;
				break;
			}
			case BrainTimeoutFlags::ignition:
			{
				ignited = true;

				// at this point we've either connected to every neuron and gotten an upload of its state,
				// or we can assume the neuron is missing... and appropriate action would already be in progress

				Machine *thisMachine = nullptr;

				for (Machine *machine : machines)
				{
					// consider the machine registered if we've received neuron registration metadata
					if ((machine->lastUpdatedOSMs > 0 || machine->kernel.size() > 0)
                  && prodigyMachineHardwareInventoryReady(machine->hardware))
					{
						if (machine->state != MachineState::healthy
                     && machineReadyForHealthyState(machine))
						{
							handleMachineStateChange(machine, MachineState::healthy);
						}

						if (machine->state == MachineState::healthy)
						{
							// check if machine is unconfigured
							if (machine->fragment == 0) // unlikely though
							{
								assignMachineFragment(machine);
							}

							if (machine->isThisMachine == false)
							{
								operatingSystemUpdateOrder.push_back(machine);
							}
							else
							{
								// we'll insert the master brain at the very end, when it updates it'll effectively transfer control to another brain
								thisMachine = machine;
							}
						}
					}
					// else we'll be triaging it already
				}

				// loop over each application and recover runtime from inventory, then reconcile
				for (const auto& [applicationID, deployment] : deploymentsByApp)
				{
					deployment->recoverAfterReboot();
				}

		// configure operating system updater

				// this should be descending order so we can feed from the tail
				cppsort::verge_adapter<cppsort::ska_sorter> sorter;
				sorter(operatingSystemUpdateOrder, [] (Machine *machine) -> int64_t { return -machine->lastUpdatedOSMs; });

				if (thisMachine)
				{
					operatingSystemUpdateOrder.push_back(thisMachine); // insert self at tail so we consume it last
				}

					if (operatingSystemUpdateOrder.size() > 0)
					{
						osUpdateTimer.flags = uint64_t(BrainTimeoutFlags::updateOSWakeup);
						osUpdateTimer.dispatcher = this;
						RingDispatcher::installMultiplexee(&osUpdateTimer, this);
						scheduleNextOperatingSystemUpdate();
					}

					if (weAreMaster)
					{
						TimeoutPacket *recovery = new TimeoutPacket();
						recovery->flags = uint64_t(BrainTimeoutFlags::postIgnitionRecovery);
						recovery->dispatcher = this;
						recovery->setTimeoutMs(prodigyBrainPostIgnitionRecoveryTimeoutMs);
						RingDispatcher::installMultiplexee(recovery, this);
						Ring::queueTimeout(recovery);
					}

					break;
				}
			case BrainTimeoutFlags::brainMissing:
			{
				BrainView *brain = (BrainView *)packet->originator;

				brainWaiters.erase(brain);
				delete packet;

				brainMissing(brain);

				break;
			}
			case BrainTimeoutFlags::updateOSWakeup:
			{
				// run the update on the head machine

				Machine *machine = operatingSystemUpdateOrder.back();
				operatingSystemUpdateOrder.pop_back();
				operatingSystemUpdateOrder.insert(operatingSystemUpdateOrder.begin(), machine);

				machine->state = MachineState::updatingOS;
				drainMachine(machine);

				// once drained it will see the state and call back
				break;
			}
			case BrainTimeoutFlags::hardRebootedMachine:
			{
				Machine *machine = nullptr;
				if (packet->identifier > 0)
				{
					if (auto it = machinesByUUID.find(packet->identifier); it != machinesByUUID.end())
					{
						machine = it->second;
					}
				}
				else if (packet->originator != nullptr)
				{
					Machine *candidate = (Machine *)packet->originator;
					if (machines.contains(candidate))
					{
						machine = candidate;
					}
				}

				// A machine may have already been decommissioned before this timeout fires.
				// Drop stale reboot watchdog packets instead of dereferencing dead pointers.
				if (machine == nullptr || machine->hardRebootWatchdog != packet)
				{
					RingDispatcher::eraseMultiplexee(packet);
					delete packet;
					break;
				}

				machine->hardRebootWatchdog = nullptr;

				if (machine->state == MachineState::healthy) // did we reconnect to the neuron or brain?
				{

				}
			else
			{
				iaas->reportHardwareFailure(machine->uuid, ""_ctv);
				// we probably also want to text ourselves but... maybe we build a mothership app?

				// if it's not a reserved machine... can we just destroy it or?
				// Treat a hard-reboot timeout as a terminal host failure so deployments drain and reschedule.
				if (machine->state != MachineState::hardwareFailure && machine->state != MachineState::decommissioning)
				{
					handleMachineStateChange(machine, MachineState::hardwareFailure);
					decommissionMachine(machine);
				}
			}

				RingDispatcher::eraseMultiplexee(packet);
				delete packet;

				break;
			}
			case BrainTimeoutFlags::softEscalationCheck:
			{
				// If the machine isn't healthy yet after a soft SSH restart, escalate to unresponsive
				Machine *machine = nullptr;
				if (packet->identifier > 0)
				{
					if (auto it = machinesByUUID.find(packet->identifier); it != machinesByUUID.end())
					{
						machine = it->second;
					}
				}
				else if (packet->originator != nullptr)
				{
					Machine *candidate = (Machine *)packet->originator;
					if (machines.contains(candidate))
					{
						machine = candidate;
					}
				}

				if (machine == nullptr || machine->softWatchdog != packet)
				{
					RingDispatcher::eraseMultiplexee(packet);
					delete packet;
					break;
				}

				machine->softWatchdog = nullptr;

				RingDispatcher::eraseMultiplexee(packet);
				delete packet;

				if (machine && machine->state != MachineState::healthy && machine->state != MachineState::neuronRebooting)
				{
					basics_log("machine soft escalation timeout uuid=%llu private4=%u state=%u creationTimeMs=%lld\n",
						(unsigned long long)machine->uuid,
						unsigned(machine->private4),
						unsigned(machine->state),
						(long long)machine->creationTimeMs);
					// move to medium escalation
					handleMachineStateChange(machine, MachineState::unresponsive);
				}
				break;
			}
			case BrainTimeoutFlags::transitionStuck:
			{
				Machine *machine = (Machine *)packet->originator;
				RingDispatcher::eraseMultiplexee(packet);
				delete packet;

				if (machine && machine->state != MachineState::healthy)
				{
					// If still in a supposed update, consider it stuck and escalate
					if (machine->inBinaryUpdate || machine->state == MachineState::neuronRebooting)
					{
						machine->inBinaryUpdate = false;
						handleMachineStateChange(machine, MachineState::unresponsive);
					}
				}

				break;
			}
            case BrainTimeoutFlags::performHardReboot:
            {
				Machine *machine = (Machine *)packet->originator;
				RingDispatcher::eraseMultiplexee(packet);
				delete packet;

					if (machine)
					{
						machine->state = MachineState::hardRebooting;
						machine->hardRebootAttempts += 1;
						machine->lastHardRebootMs = Time::now<TimeResolution::ms>();

						iaas->hardRebootMachine(machine->uuid);

						cancelMachineHardRebootWatchdog(machine);
						TimeoutPacket *timeout = new TimeoutPacket();
						timeout->flags = uint64_t(BrainTimeoutFlags::hardRebootedMachine);
						timeout->identifier = machine->uuid;
						timeout->originator = machine;
						timeout->dispatcher = this;
						timeout->setTimeoutMs(prodigyBrainHardRebootWatchdogMs);
						RingDispatcher::installMultiplexee(timeout, this);
						Ring::queueTimeout(timeout);
						machine->hardRebootWatchdog = timeout;
					}

                break;
            }
	            case BrainTimeoutFlags::postIgnitionRecovery:
	            {
					recoverDeploymentsAfterNeuronState();

	                RingDispatcher::eraseMultiplexee(packet);
	                delete packet;
	                break;
	            }
				case BrainTimeoutFlags::spotDecomissionChecker:
				{
					checkForSpotTerminations();
	            refreshAllDeploymentWormholeQuicCidState(true);
					break;
				}
				default: break;
			}
		}

	void timeoutHandler(TimeoutPacket *packet, int result) override
	{
		if (packet->dispatcher)
		{
			packet->dispatcher->dispatchTimeout(packet);
		}
	}

			template <typename T>
			bool rawStreamIsActive(T *stream)
			{
				if (stream == nullptr)
				{
					return false;
				}

				if (Ring::socketIsClosing(stream))
				{
					return false;
				}

				if (stream->isFixedFile)
				{
					return (stream->fslot >= 0);
				}

				// Reconnect/bootstrap can briefly keep a live direct-fd stream around
				// until the fixed-file replacement is installed.
				return (stream->fd >= 0);
			}

			template <typename T>
			bool streamIsActive(T *stream)
			{
				if (rawStreamIsActive(stream) == false)
				{
					return false;
				}

				if constexpr (requires(T *value) { value->connected; })
				{
					return stream->connected;
				}

				return true;
			}

				template <typename T>
				void queueCloseIfActive(T *stream)
				{
					if (rawStreamIsActive(stream) == false)
					{
						return;
					}

					Ring::queueClose(stream);
				}

				template <typename T>
				void abandonSocketGeneration(T *stream)
				{
					if (stream == nullptr || Ring::socketIsClosing(stream))
					{
						return;
					}

					if (stream->isFixedFile && stream->fslot >= 0)
					{
						if (RingDispatcher::dispatcher != nullptr && Ring::getRingFD() > 0)
						{
							Ring::queueCancelAll(stream);
							Ring::queueCloseRaw(stream->fslot);
						}

						stream->fslot = -1;
						stream->isFixedFile = false;
					}
					else if (stream->fd >= 0)
					{
						::close(stream->fd);
						stream->fd = -1;
						stream->isFixedFile = false;
					}

					if constexpr (requires (T *value) { value->reset(); })
					{
						// A reconnect/accepted replacement must discard the full prior stream
						// generation, not just the raw fd. Leaving TLS/BIO/encrypted-buffer
						// state behind lets the next handshake consume stale allocator-backed
						// state on a fresh socket generation.
						stream->reset();
					}
					else
					{
						stream->pendingSend = false;
						stream->pendingRecv = false;
						stream->pendingSendBytes = 0;
						stream->bumpIoGeneration();

						if constexpr (requires (T *value) { value->connected; })
						{
							stream->connected = false;
						}

						if constexpr (requires (T *value) { value->rBuffer.clear(); })
						{
							stream->rBuffer.clear();
						}

						if constexpr (requires (T *value) { value->clearQueuedSendBytes(); })
						{
							stream->clearQueuedSendBytes();
						}

						if constexpr (requires (T *value) { value->tlsPeerVerified = false; value->tlsPeerUUID = 0; })
						{
							stream->tlsPeerVerified = false;
							stream->tlsPeerUUID = 0;
						}
					}
				}

				bool verifyBrainTransportTLSPeer(BrainView *brain)
				{
					if (brain == nullptr || brain->transportTLSEnabled() == false || brain->tlsPeerVerified)
					{
						return true;
					}

					if (brain->isTLSNegotiated() == false)
					{
						return true;
					}

					uint128_t peerUUID = 0;
					if (ProdigyTransportTLSRuntime::extractPeerUUID(brain->ssl, peerUUID) == false)
					{
						basics_log("brain transport tls missing peer uuid fd=%d fslot=%d\n", brain->fd, brain->fslot);
						return false;
					}

					if (brain->uuid != 0 && brain->uuid != peerUUID)
					{
						basics_log("brain transport tls uuid mismatch expected=%llu actual=%llu fd=%d fslot=%d\n",
							(unsigned long long)brain->uuid,
							(unsigned long long)peerUUID,
							brain->fd,
							brain->fslot);
						return false;
					}

					if (brain->machine && brain->machine->uuid != 0 && brain->machine->uuid != peerUUID)
					{
						basics_log("brain transport tls machine uuid mismatch expected=%llu actual=%llu fd=%d fslot=%d\n",
							(unsigned long long)brain->machine->uuid,
							(unsigned long long)peerUUID,
							brain->fd,
							brain->fslot);
						return false;
					}

					if (brain->uuid == 0)
					{
						brain->uuid = peerUUID;
					}

					brain->tlsPeerUUID = peerUUID;
					brain->tlsPeerVerified = true;
					basics_log("brain transport tls peer verified fd=%d fslot=%d\n", brain->fd, brain->fslot);
					return true;
				}

				bool verifyNeuronTransportTLSPeer(NeuronView *neuron)
				{
					if (neuron == nullptr || neuron->transportTLSEnabled() == false || neuron->tlsPeerVerified)
					{
						return true;
					}

					if (neuron->isTLSNegotiated() == false)
					{
						return true;
					}

					uint128_t peerUUID = 0;
					if (ProdigyTransportTLSRuntime::extractPeerUUID(neuron->ssl, peerUUID) == false)
					{
						basics_log("neuron transport tls missing peer uuid fd=%d fslot=%d\n", neuron->fd, neuron->fslot);
						return false;
					}

					Machine *machine = neuron->machine;
					if (machine && machine->uuid != 0 && machine->uuid != peerUUID)
					{
						basics_log("neuron transport tls uuid mismatch expected=%llu actual=%llu fd=%d fslot=%d\n",
							(unsigned long long)machine->uuid,
							(unsigned long long)peerUUID,
							neuron->fd,
							neuron->fslot);
						return false;
					}

					if (machine && machine->uuid == 0)
					{
						machine->uuid = peerUUID;
						machinesByUUID.insert_or_assign(machine->uuid, machine);
					}

					neuron->tlsPeerUUID = peerUUID;
					neuron->tlsPeerVerified = true;
#if PRODIGY_DEBUG
					basics_log("brain neuron transport tls peer verified fd=%d fslot=%d peerUUID=%llu machineUUID=%llu private4=%u cloudID=%s state=%u inventoryComplete=%d\n",
						neuron->fd,
						neuron->fslot,
						(unsigned long long)peerUUID,
						(unsigned long long)(machine ? machine->uuid : 0),
						unsigned(machine ? machine->private4 : 0u),
						(machine ? machine->cloudID.c_str() : ""),
						unsigned(machine ? uint32_t(machine->state) : 0u),
						int(machine ? machine->hardware.inventoryComplete : 0));
#else
					basics_log("brain neuron transport tls peer verified fd=%d fslot=%d\n", neuron->fd, neuron->fslot);
#endif
					return true;
				}

				void retireClosingMothershipStreamIfNeeded(Mothership *stream, const char *reason = nullptr)
				{
					if (stream == nullptr || stream != mothership)
					{
						return;
					}

					if (Ring::socketIsClosing(stream) == false)
					{
						return;
					}

					closingMotherships.insert(stream);
					mothership = nullptr;
					std::fprintf(stderr, "prodigy mothership retire-closing reason=%s stream=%p closingStreams=%zu master=%d\n",
						(reason ? reason : "unknown"),
						static_cast<void *>(stream),
						size_t(closingMotherships.size()),
						int(weAreMaster));
					std::fflush(stderr);
					if (weAreMaster)
					{
						queueMothershipListenersIfNeeded();
					}
				}

				void destroyIdleMothershipStreamNow(Mothership *stream, const char *reason = nullptr)
				{
					if (stream == nullptr || Ring::socketIsClosing(stream))
					{
						return;
					}

					std::fprintf(stderr, "prodigy mothership destroy-idle reason=%s stream=%p fd=%d fslot=%d master=%d\n",
						(reason ? reason : "unknown"),
						static_cast<void *>(stream),
						stream->fd,
						stream->fslot,
						int(weAreMaster));
					std::fflush(stderr);

					stream->closeAfterSendDrain = false;

					if (RingDispatcher::dispatcher != nullptr && Ring::getRingFD() > 0 && rawStreamIsActive(stream))
					{
						if (stream->isFixedFile && stream->fslot >= 0)
						{
							Ring::queueCancelAll(stream);
						}

						// Even a fully drained commander client must stay alive until the close
						// completion lands. Deleting it after a raw slot close lets stale CQEs
						// race with allocator reuse of the same object address.
						Ring::queueClose(stream);
						retireClosingMothershipStreamIfNeeded(stream, reason);
						return;
					}

					clearSpinApplicationMothershipsForStream(stream);
					closingMotherships.erase(stream);

					if (stream == mothership)
					{
						mothership = nullptr;
					}

					if (stream->isFixedFile && stream->fslot >= 0)
					{
						stream->fslot = -1;
						stream->isFixedFile = false;
					}
					else if (stream->fd >= 0)
					{
						::close(stream->fd);
						stream->fd = -1;
						stream->isFixedFile = false;
					}

					stream->TCPStream::reset();
					stream->CoroutineStack::reset();

					RingDispatcher::eraseMultiplexee(stream);
					delete stream;

					if (weAreMaster)
					{
						queueMothershipListenersIfNeeded();
					}
				}

				void queueCloseIfActive(Mothership *stream, const char *reason = nullptr)
				{
					if (streamIsActive(stream) == false)
					{
						return;
					}

					stream->closeAfterSendDrain = false;
					Ring::queueClose(stream);
					if (stream->pendingSend == false && stream->wBuffer.outstandingBytes() == 0)
					{
						retireClosingMothershipStreamIfNeeded(stream, reason);
					}
				}

				void closeMothershipAfterSendDrainIfNeeded(Mothership *stream, const char *reason = nullptr)
				{
					if (stream == nullptr || stream->closeAfterSendDrain == false)
					{
						return;
					}

					if (stream->pendingSend || stream->wBuffer.outstandingBytes() > 0)
					{
						return;
					}

					stream->closeAfterSendDrain = false;
					if (streamIsActive(stream))
					{
						Ring::queueClose(stream);
					}

					retireClosingMothershipStreamIfNeeded(stream, reason);
				}

				void queueCloseAfterSendDrain(Mothership *stream)
				{
					if (stream == nullptr)
					{
						return;
					}

					stream->closeAfterSendDrain = true;
					closeMothershipAfterSendDrainIfNeeded(stream, "send-drain-immediate");
				}

            Mothership *spinApplicationMothershipFor(ApplicationDeployment *deployment)
            {
               if (deployment == nullptr)
               {
                  return nullptr;
               }

               auto it = spinApplicationMotherships.find(deployment->plan.config.deploymentID());
               if (it == spinApplicationMotherships.end())
               {
                  return nullptr;
               }

               Mothership *stream = it->second;
               if (streamIsActive(stream) == false || Ring::socketIsClosing(stream))
               {
                  spinApplicationMotherships.erase(it);
                  return nullptr;
               }

               return stream;
            }

            void bindSpinApplicationMothership(ApplicationDeployment *deployment, Mothership *stream)
            {
               if (deployment == nullptr)
               {
                  return;
               }

               uint64_t deploymentID = deployment->plan.config.deploymentID();
               if (deploymentID == 0)
               {
                  return;
               }

               if (stream == nullptr || streamIsActive(stream) == false || Ring::socketIsClosing(stream))
               {
                  spinApplicationMotherships.erase(deploymentID);
                  return;
               }

               spinApplicationMotherships.insert_or_assign(deploymentID, stream);
            }

            void clearSpinApplicationMothership(ApplicationDeployment *deployment)
            {
               if (deployment == nullptr)
               {
                  return;
               }

               uint64_t deploymentID = deployment->plan.config.deploymentID();
               if (deploymentID == 0)
               {
                  return;
               }

               spinApplicationMotherships.erase(deploymentID);
            }

            void clearSpinApplicationMothershipsForStream(Mothership *stream)
            {
               if (stream == nullptr)
               {
                  return;
               }

               for (auto it = spinApplicationMotherships.begin(); it != spinApplicationMotherships.end();)
               {
                  if (it->second == stream)
                  {
                     it = spinApplicationMotherships.erase(it);
                  }
                  else
                  {
                     ++it;
                  }
               }
            }

					// The unix Mothership control stream now uses the same fixed-file recv/send
					// path as the TCP listener. There is no direct-fd compatibility pump.
					void queueMothershipReceiveIfNeeded(Mothership *stream, const char *reason)
				{
					if (stream == nullptr)
					{
						return;
					}

					if (Ring::socketIsClosing(stream) || streamIsActive(stream) == false)
					{
						std::fprintf(stderr, "prodigy mothership recv-rearm-skip reason=%s active=%d closing=%d stream=%p fd=%d fslot=%d\n",
							(reason ? reason : "unknown"),
							int(streamIsActive(stream)),
							int(Ring::socketIsClosing(stream)),
							static_cast<void *>(stream),
							stream->fd,
							stream->fslot);
						std::fflush(stderr);
						return;
					}

					std::fprintf(stderr, "prodigy mothership recv-arm reason=%s stream=%p fd=%d fslot=%d isFixed=%d pendingRecv=%d pendingSend=%d\n",
						(reason ? reason : "unknown"),
						static_cast<void *>(stream),
						loggableSocketFD(stream),
						stream->fslot,
						int(stream->isFixedFile),
						int(stream->pendingRecv),
						int(stream->pendingSend));
					std::fflush(stderr);
					Ring::queueRecv(stream);
					std::fprintf(stderr, "prodigy mothership recv-submit reason=%s pendingRecv=%d stream=%p fixedFD=%d fslot=%d rbytes=%zu remaining=%llu\n",
						(reason ? reason : "unknown"),
						int(stream->pendingRecv),
						static_cast<void *>(stream),
						loggableSocketFD(stream),
						stream->fslot,
						size_t(stream->rBuffer.size()),
						(unsigned long long)stream->rBuffer.remainingCapacity());
					std::fflush(stderr);
				}

				bool flushActiveMothershipSendBuffer(Mothership *stream, const char *reason)
				{
					if (stream == nullptr)
					{
						return false;
					}

					if (stream->wBuffer.size() == 0)
					{
						std::fprintf(stderr, "prodigy mothership send-skip reason=%s wbytes=0 active=%d stream=%p fd=%d fslot=%d\n",
							(reason ? reason : "unknown"),
							int(streamIsActive(stream)),
							static_cast<void *>(stream),
							stream->fd,
							stream->fslot);
						std::fflush(stderr);
						return true;
					}

					if (streamIsActive(stream) == false || Ring::socketIsClosing(stream))
					{
						std::fprintf(stderr, "prodigy mothership send-skip reason=%s wbytes=%zu active=%d closing=%d stream=%p fd=%d fslot=%d\n",
							(reason ? reason : "unknown"),
							size_t(stream->wBuffer.size()),
							int(streamIsActive(stream)),
							int(Ring::socketIsClosing(stream)),
							static_cast<void *>(stream),
							stream->fd,
							stream->fslot);
						std::fflush(stderr);
						return false;
					}

					std::fprintf(stderr, "prodigy mothership send-queue reason=%s wbytes=%zu stream=%p fd=%d fslot=%d pendingSend=%d\n",
						(reason ? reason : "unknown"),
						size_t(stream->wBuffer.size()),
						static_cast<void *>(stream),
						stream->fd,
						stream->fslot,
						int(stream->pendingSend));
					std::fflush(stderr);
					Ring::queueSend(stream);
					std::fprintf(stderr, "prodigy mothership send-submit reason=%s pendingSend=%d pendingSendBytes=%u wbytes=%zu active=%d stream=%p fixedFD=%d fslot=%d\n",
						(reason ? reason : "unknown"),
						int(stream->pendingSend),
						unsigned(stream->pendingSendBytes),
						size_t(stream->wBuffer.size()),
						int(streamIsActive(stream)),
						static_cast<void *>(stream),
						loggableSocketFD(stream),
						stream->fslot);
					std::fflush(stderr);
					return true;
				}

				bool processMothershipReceivedBytes(Mothership *stream, int result, const char *source)
				{
					if (stream == nullptr || result <= 0)
					{
						return false;
					}

					const uint64_t remaining = stream->rBuffer.remainingCapacity();
					if (uint64_t(result) > remaining)
					{
						basics_log("mothership recv overflow result=%d remaining=%llu fd=%d fslot=%d weAreMaster=%d source=%s\n",
							result,
							(unsigned long long)remaining,
							stream->fd,
							stream->fslot,
							int(weAreMaster),
							(source ? source : "unknown"));
						stream->rBuffer.clear();
						if (weAreMaster)
						{
							queueMothershipListenersIfNeeded();
						}
						queueCloseIfActive(stream);
						return false;
					}

					stream->rBuffer.advance(result);
					logMothershipReceiveBufferHead("recv-parse-head", stream);
					bool parseFailed = false;
					stream->extractMessages<Message>([&] (Message *message) -> void {
						size_t wBefore = size_t(stream->wBuffer.size());
						std::fprintf(stderr, "prodigy mothership dispatch-begin source=%s topic=%s(%u) size=%u wBefore=%zu stream=%p fd=%d fslot=%d\n",
							(source ? source : "unknown"),
							prodigyMothershipTopicName(MothershipTopic(message->topic)),
							unsigned(message->topic),
							unsigned(message->size),
							wBefore,
							static_cast<void *>(stream),
							stream->fd,
							stream->fslot);
						std::fflush(stderr);

						mothershipHandler(stream, message);
						size_t wAfter = size_t(stream->wBuffer.size());
						std::fprintf(stderr, "prodigy mothership dispatch-end source=%s topic=%s(%u) size=%u wAfter=%zu delta=%lld active=%d pendingSend=%d pendingRecv=%d\n",
							(source ? source : "unknown"),
							prodigyMothershipTopicName(MothershipTopic(message->topic)),
							unsigned(message->topic),
							unsigned(message->size),
							wAfter,
							static_cast<long long>(wAfter) - static_cast<long long>(wBefore),
							int(streamIsActive(stream)),
							int(stream->pendingSend),
							int(stream->pendingRecv));
						std::fflush(stderr);
					}, true, UINT32_MAX, 16, ProdigyWire::maxControlFrameBytes, parseFailed);

					if (parseFailed)
					{
						uint64_t outstanding = stream->rBuffer.outstandingBytes();
						uint32_t peekSize = 0;
						if (outstanding >= sizeof(uint32_t))
						{
							memcpy(&peekSize, stream->rBuffer.pHead(), sizeof(uint32_t));
						}

						basics_log("mothership recv parse failure outstanding=%llu peekSize=%u fd=%d fslot=%d weAreMaster=%d source=%s\n",
							(unsigned long long)outstanding,
							unsigned(peekSize),
							stream->fd,
							stream->fslot,
							int(weAreMaster),
							(source ? source : "unknown"));
						logMothershipReceiveBufferHead("recv-parse-failure", stream);
						stream->rBuffer.clear();
						if (weAreMaster)
						{
							queueMothershipListenersIfNeeded();
						}
						queueCloseIfActive(stream);
						return false;
					}

					if (stream->wBuffer.size() > 0)
					{
						return flushActiveMothershipSendBuffer(stream, source);
					}

					std::fprintf(stderr, "prodigy mothership send-skip reason=%s wbytes=%zu active=%d stream=%p fd=%d fslot=%d\n",
						(source ? source : "unknown"),
						size_t(stream->wBuffer.size()),
						int(streamIsActive(stream)),
						static_cast<void *>(stream),
						stream->fd,
						stream->fslot);
					std::fflush(stderr);
					return streamIsActive(stream);
				}

				void queueMothershipAcceptIfNeeded(void)
				{
					if (weAreMaster == false)
				{
					return;
				}

				if (mothershipAcceptArmed)
				{
					return;
				}

				if (Ring::socketIsClosing(&mothershipSocket))
				{
					return;
				}

				bool listenerActive = false;
				if (mothershipSocket.isFixedFile)
				{
					listenerActive = (mothershipSocket.fslot >= 0);
				}
				else
				{
					listenerActive = (mothershipSocket.fd >= 0);
				}

				if (listenerActive == false)
				{
					return;
				}

				Ring::queueAccept(&mothershipSocket, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
				mothershipAcceptArmed = true;
				std::fprintf(stderr, "prodigy mothership listen-arm transport=tcp listenerFD=%d listenerFslot=%d master=%d\n",
					mothershipSocket.fd,
					mothershipSocket.fslot,
					int(weAreMaster));
				std::fflush(stderr);
			}

				void queueMothershipUnixAcceptIfNeeded(void)
				{
					if (weAreMaster == false)
				{
					return;
				}

				if (mothershipUnixAcceptArmed)
				{
					return;
				}

				if (Ring::socketIsClosing(&mothershipUnixSocket))
				{
					return;
				}

				bool listenerActive = false;
				if (mothershipUnixSocket.isFixedFile)
				{
					listenerActive = (mothershipUnixSocket.fslot >= 0);
				}
				else
				{
					listenerActive = (mothershipUnixSocket.fd >= 0);
				}

				if (listenerActive == false)
				{
					return;
				}

				Ring::queueAccept(&mothershipUnixSocket, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
				mothershipUnixAcceptArmed = true;
				std::fprintf(stderr, "prodigy mothership listen-arm transport=unix path=%s listenerFD=%d listenerFslot=%d master=%d\n",
					mothershipUnixSocketPath.c_str(),
					mothershipUnixSocket.fd,
					mothershipUnixSocket.fslot,
					int(weAreMaster));
				std::fflush(stderr);
				}

				void queueMothershipListenersIfNeeded(void)
				{
					queueMothershipAcceptIfNeeded();
					queueMothershipUnixAcceptIfNeeded();
				}

		void recvHandler(void *socket, int result) override
		{
		if (brains.contains(static_cast<BrainView *>(socket)))
		{
			BrainView *brain = static_cast<BrainView *>(socket);
			if (brain->pendingRecv == false)
			{
				// Ignore stale/duplicate recv completions from prior socket generations.
				return;
			}
			brain->pendingRecv = false;

					if (result > 0)
					{
						std::fprintf(stderr,
							"prodigy debug brain recv-result private4=%u result=%d fd=%d fslot=%d tls=%d negotiated=%d peerVerified=%d pendingSend=%d pendingRecv=%d queuedBytes=%llu rbytes=%llu\n",
							brain->private4,
							result,
							brain->fd,
							brain->fslot,
							int(brain->transportTLSEnabled()),
							int(brain->isTLSNegotiated()),
							int(brain->tlsPeerVerified),
							int(brain->pendingSend),
							int(brain->pendingRecv),
							(unsigned long long)brain->queuedSendOutstandingBytes(),
							(unsigned long long)brain->rBuffer.outstandingBytes());
						std::fflush(stderr);
						const uint64_t remaining = brain->rBuffer.remainingCapacity();
						if (uint64_t(result) > remaining)
						{
							basics_log("brain recv overflow private4=%u result=%d remaining=%llu fd=%d fslot=%d\n",
								brain->private4,
								result,
								(unsigned long long)remaining,
								brain->fd,
								brain->fslot);
							brain->rBuffer.clear();
							queueCloseIfActive(brain);
							return;
						}

						if (brain->transportTLSEnabled())
						{
							if (brain->decryptTransportTLS(uint32_t(result)) == false || verifyBrainTransportTLSPeer(brain) == false)
							{
								brain->rBuffer.clear();
								queueCloseIfActive(brain);
								return;
							}
						}
						else
						{
							brain->rBuffer.advance(result);
						}

						bool parseFailed = false;
						brain->extractMessages<Message>([&] (Message *message) -> void {

						brainHandler(brain, message);
					}, true, UINT32_MAX, 16, ProdigyWire::maxControlFrameBytes, parseFailed);
					if (parseFailed)
					{
						uint64_t outstanding = brain->rBuffer.outstandingBytes();
						uint32_t peekSize = 0;
						if (outstanding >= sizeof(uint32_t))
						{
							memcpy(&peekSize, brain->rBuffer.pHead(), sizeof(uint32_t));
						}

						basics_log("brain recv parse failure private4=%u outstanding=%llu peekSize=%u fd=%d fslot=%d\n",
							brain->private4,
							(unsigned long long)outstanding,
							unsigned(peekSize),
							brain->fd,
							brain->fslot);
						brain->rBuffer.clear();
						queueCloseIfActive(brain);
						return;
					}

						if (streamIsActive(brain)
							&& brain->transportTLSEnabled()
							&& brain->needsTransportTLSSendKick())
						{
							Ring::queueSend(brain);
						}
						else if (brain->wBuffer.size() > 0 && streamIsActive(brain))
						{
							Ring::queueSend(brain);
						}

						if (streamIsActive(brain))
						{
							Ring::queueRecv(brain);
						}
					}
				else
				{
					queueCloseIfActive(brain);
				// try to reconnect... then when that fails...
			}
		}
		else if (neurons.contains(static_cast<NeuronView *>(socket)))
		{
			NeuronView *neuron = static_cast<NeuronView *>(socket);
			if (neuron->pendingRecv == false)
			{
				// Ignore stale/duplicate recv completions from prior socket generations.
				return;
			}

			neuron->pendingRecv = false;

					if (result > 0)
					{
						basics_log("brain neuron recv result uuid=%llu private4=%u result=%d fd=%d fslot=%d tlsNegotiated=%d peerVerified=%d pendingSend=%d pendingRecv=%d wbytes=%u queued=%llu rbytes=%llu\n",
							(unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
							unsigned(neuron->machine ? neuron->machine->private4 : 0u),
							result,
							neuron->fd,
							neuron->fslot,
							int(neuron->isTLSNegotiated()),
							int(neuron->tlsPeerVerified),
							int(neuron->pendingSend),
							int(neuron->pendingRecv),
							unsigned(neuron->wBuffer.size()),
							(unsigned long long)neuron->queuedSendOutstandingBytes(),
							(unsigned long long)neuron->rBuffer.outstandingBytes());
						const uint64_t remaining = neuron->rBuffer.remainingCapacity();
						if (uint64_t(result) > remaining)
						{
							basics_log("neuron recv overflow private4=%u result=%d remaining=%llu fd=%d fslot=%d\n",
								(neuron->machine ? neuron->machine->private4 : 0u),
								result,
								(unsigned long long)remaining,
								neuron->fd,
								neuron->fslot);
							neuron->rBuffer.clear();
							queueCloseIfActive(neuron);
							return;
						}

						if (neuron->transportTLSEnabled())
						{
							if (neuron->decryptTransportTLS(uint32_t(result)) == false || verifyNeuronTransportTLSPeer(neuron) == false)
							{
								neuron->rBuffer.clear();
								queueCloseIfActive(neuron);
								return;
							}
						}
						else
						{
							neuron->rBuffer.advance(result);
						}

						bool parseFailed = false;
						neuron->extractMessages<Message>([&] (Message *message) -> void {

						if (ProdigyIngressValidation::validateNeuronPayloadForBrain(message->topic, message->args, message->terminal()) == false)
						{
							basics_log("brain neuron recv invalid payload uuid=%llu private4=%u topic=%u fd=%d fslot=%d\n",
								(unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
								unsigned(neuron->machine ? neuron->machine->private4 : 0u),
								unsigned(message->topic),
								neuron->fd,
								neuron->fslot);
							neuron->rBuffer.clear();
							queueCloseIfActive(neuron);
							return;
						}

#if PRODIGY_DEBUG
						if (message->topic == uint16_t(NeuronTopic::registration)
							|| message->topic == uint16_t(NeuronTopic::machineHardwareProfile))
						{
							basics_log("brain neuron recv-dispatch topic=%u uuid=%llu private4=%u cloudID=%s state=%u inventoryComplete=%d bytes=%u fd=%d fslot=%d\n",
								unsigned(message->topic),
								(unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
								unsigned(neuron->machine ? neuron->machine->private4 : 0u),
								(neuron->machine ? neuron->machine->cloudID.c_str() : ""),
								unsigned(neuron->machine ? uint32_t(neuron->machine->state) : 0u),
								int(neuron->machine ? neuron->machine->hardware.inventoryComplete : 0),
								unsigned(message->size),
								neuron->fd,
								neuron->fslot);
						}
#endif
						neuronHandler(neuron, message);
					}, true, UINT32_MAX, 16, ProdigyWire::maxControlFrameBytes, parseFailed);
					if (parseFailed)
					{
						uint64_t outstanding = neuron->rBuffer.outstandingBytes();
						uint32_t peekSize = 0;
						uint8_t sample[8] = {0};
						if (outstanding >= sizeof(uint32_t))
						{
							memcpy(&peekSize, neuron->rBuffer.pHead(), sizeof(uint32_t));
						}
						uint64_t sampleCount = (outstanding < sizeof(sample) ? outstanding : sizeof(sample));
						if (sampleCount > 0)
						{
							memcpy(sample, neuron->rBuffer.pHead(), sampleCount);
						}

						basics_log("neuron recv parse failure private4=%u outstanding=%llu peekSize=%u fd=%d fslot=%d sample=%02x %02x %02x %02x %02x %02x %02x %02x\n",
							(neuron->machine ? neuron->machine->private4 : 0u),
							(unsigned long long)outstanding,
							unsigned(peekSize),
							neuron->fd,
							neuron->fslot,
							unsigned(sample[0]),
							unsigned(sample[1]),
							unsigned(sample[2]),
							unsigned(sample[3]),
							unsigned(sample[4]),
							unsigned(sample[5]),
							unsigned(sample[6]),
							unsigned(sample[7]));
						neuron->rBuffer.clear();
						queueCloseIfActive(neuron);
						return;
					}

#if PRODIGY_DEBUG
					{
						uint64_t outstanding = neuron->rBuffer.outstandingBytes();
						if (outstanding > 0)
						{
							uint32_t peekSize = 0;
							uint16_t peekTopic = 0;
							uint8_t peekHeader = 0;
							uint8_t peekPadding = 0;
							uint8_t sample[8] = {0};
							if (outstanding >= sizeof(uint32_t))
							{
								memcpy(&peekSize, neuron->rBuffer.pHead(), sizeof(uint32_t));
							}
							if (outstanding >= sizeof(Message))
							{
								Message *peek = reinterpret_cast<Message *>(neuron->rBuffer.pHead());
								peekTopic = peek->topic;
								peekHeader = peek->headerSize;
								peekPadding = peek->padding;
							}
							uint64_t sampleCount = (outstanding < sizeof(sample) ? outstanding : sizeof(sample));
							if (sampleCount > 0)
							{
								memcpy(sample, neuron->rBuffer.pHead(), sampleCount);
							}

							basics_log("brain neuron recv-partial uuid=%llu private4=%u cloudID=%s outstanding=%llu peekSize=%u peekTopic=%u peekHeader=%u peekPadding=%u fd=%d fslot=%d sample=%02x %02x %02x %02x %02x %02x %02x %02x\n",
								(unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
								unsigned(neuron->machine ? neuron->machine->private4 : 0u),
								(neuron->machine ? neuron->machine->cloudID.c_str() : ""),
								(unsigned long long)outstanding,
								unsigned(peekSize),
								unsigned(peekTopic),
								unsigned(peekHeader),
								unsigned(peekPadding),
								neuron->fd,
								neuron->fslot,
								unsigned(sample[0]),
								unsigned(sample[1]),
								unsigned(sample[2]),
								unsigned(sample[3]),
								unsigned(sample[4]),
								unsigned(sample[5]),
								unsigned(sample[6]),
								unsigned(sample[7]));
						}
					}
#endif

						if (streamIsActive(neuron)
							&& neuron->transportTLSEnabled()
							&& neuron->needsTransportTLSSendKick())
						{
							Ring::queueSend(neuron);
						}
						else if (neuron->wBuffer.size() > 0 && streamIsActive(neuron))
						{
							Ring::queueSend(neuron);
						}

						if (streamIsActive(neuron))
						{
							Ring::queueRecv(neuron);
						}
					}
				else
				{
					queueCloseIfActive(neuron);
				// try to reconnect... then when that fails...
			}
		}
			else if (socket == (void *)mothership)
			{
				if (mothership->pendingRecv == false)
				{
					// Ignore stale/duplicate recv completions from prior socket generations.
					return;
				}
				mothership->pendingRecv = false;
					std::fprintf(stderr, "prodigy mothership recv-complete result=%d stream=%p fd=%d fslot=%d isFixed=%d rbytes=%zu wbytes=%zu master=%d\n",
						result,
						static_cast<void *>(mothership),
						mothership->fd,
						mothership->fslot,
					int(mothership->isFixedFile),
					size_t(mothership->rBuffer.size()),
					size_t(mothership->wBuffer.size()),
					int(weAreMaster));
					std::fflush(stderr);

					if (result > 0)
					{
						if (processMothershipReceivedBytes(mothership, result, "io_uring-recv") == false)
						{
							return;
						}

						queueMothershipReceiveIfNeeded(mothership, "post-dispatch");
					}
				else
				{
					const bool closeCompletion = (result == -9 || result == -125);
					if (closeCompletion == false)
					{
						basics_log("mothership stream recv closed result=%d weAreMaster=%d\n", result, int(weAreMaster));
					}
						std::fprintf(stderr, "prodigy mothership recv-close result=%d closeCompletion=%d stream=%p fd=%d fslot=%d master=%d\n",
							result,
							int(closeCompletion),
							static_cast<void *>(mothership),
							mothership->fd,
							mothership->fslot,
						int(weAreMaster));
					std::fflush(stderr);
						if (weAreMaster && closeCompletion == false)
						{
							queueMothershipListenersIfNeeded();
						}
							if (mothership->pendingSend == false
								&& mothership->pendingRecv == false
								&& mothership->wBuffer.outstandingBytes() == 0)
							{
								// Local one-shot commander clients hit EOF immediately after
								// consuming the response. Retire the drained stream into the
								// normal close-completion lifecycle so stale CQEs cannot outlive
								// the object and collide with allocator reuse.
								destroyIdleMothershipStreamNow(mothership, "recv-eof-drained");
							}
						else
						{
							queueCloseIfActive(mothership);
						}
					}
				}
		}

		template <typename T>
		void sendHandler(T *stream, int result)
		{
			if (stream->pendingSend == false)
			{
				// Ignore stale/duplicate send completions from prior socket generations.
				return;
			}

			stream->pendingSend = false;
			uint32_t submittedBytes = stream->pendingSendBytes;
			stream->pendingSendBytes = 0;

					if (result > 0)
					{
						if (submittedBytes == 0 || uint32_t(result) > submittedBytes)
						{
							const uint64_t outstanding = stream->queuedSendOutstandingBytes();
							basics_log("brain send overflow stream=%p result=%d outstanding=%llu fd=%d fslot=%d\n",
								stream,
								result,
								(unsigned long long)outstanding,
								stream->fd,
								stream->fslot);
							stream->noteSendCompleted();
							stream->clearQueuedSendBytes();
							queueCloseIfActive(stream);
							return;
						}

						stream->consumeSentBytes(uint32_t(result), false);
						stream->noteSendCompleted();

					bool queueAnotherSend = (stream->wBuffer.outstandingBytes() > 0);
					if constexpr (requires (T *s) { s->transportTLSEnabled(); })
					{
						if (stream->transportTLSEnabled() && stream->needsTransportTLSSendKick())
						{
							queueAnotherSend = true;
						}
					}

					if (queueAnotherSend)
					{
						if (streamIsActive(stream))
						{
							Ring::queueSend(stream);
						}
						else
						{
							// We still have buffered bytes, but the socket dropped out of active
							// state between submissions/completions. Force close/reconnect so
							// connectHandler can re-register and flush pending bytes.
							queueCloseIfActive(stream);
						}
					}
				}
			else
			{
				stream->noteSendCompleted();
				// Do not carry partial stream bytes across reconnect boundaries.
				// A failed send may leave the buffer starting mid-frame; replaying that
				// tail on a new socket can desynchronize framing and corrupt parsing.
				stream->clearQueuedSendBytes();
				queueCloseIfActive(stream);
			}
		}

				void sendHandler(void *socket, int result) override
				{
					if (result <= 0 && socket == (void *)mothership && weAreMaster)
					{
						queueMothershipListenersIfNeeded();
					}

			if (brains.contains(static_cast<BrainView *>(socket)))
			{
				BrainView *brain = static_cast<BrainView *>(socket);
				std::fprintf(stderr,
					"prodigy debug brain send-result private4=%u result=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d tls=%d negotiated=%d peerVerified=%d queuedBytes=%llu wbytes=%u\n",
					brain->private4,
					result,
					brain->fd,
					brain->fslot,
					int(brain->pendingSend),
					int(brain->pendingRecv),
					int(brain->transportTLSEnabled()),
					int(brain->isTLSNegotiated()),
					int(brain->tlsPeerVerified),
					(unsigned long long)brain->queuedSendOutstandingBytes(),
					uint32_t(brain->wBuffer.outstandingBytes()));
				std::fflush(stderr);
				if (result <= 0)
				{
			basics_log("brain send failed stream=%p private4=%u result=%d isFixed=%d fslot=%d fd=%d updateProdigyState=%u\n",
				static_cast<void *>(brain), brain->private4, result, int(brain->isFixedFile), brain->fslot, brain->fd, uint32_t(updateSelfState));
				}
				sendHandler(brain, result);
				if (result > 0)
				{
					queueUpdateSelfBundleToPeer(brain);
					queueUpdateSelfTransitionToPeer(brain);
					queueUpdateSelfRelinquishToPeer(brain);
				}
			}
				else if (neurons.contains(static_cast<NeuronView *>(socket)))
				{
						NeuronView *neuron = static_cast<NeuronView *>(socket);
						uint32_t bytesBefore = neuron->wBuffer.size();
						if (result <= 0)
						{
							if (neuron->pendingSend)
							{
								neuron->wBuffer.noteSendCompleted();
							}
							neuron->pendingSend = false;
							neuron->pendingSendBytes = 0;
							// Failed send completions can leave a partial frame at head.
							// Drop buffered bytes before reconnect so framing stays valid.
							neuron->wBuffer.clear();
							basics_log("neuron send failed private4=%u result=%d isFixed=%d fslot=%d fd=%d machineState=%d wbytes=%u\n",
								(neuron->machine ? neuron->machine->private4 : 0u),
							result,
						int(neuron->isFixedFile),
						neuron->fslot,
						neuron->fd,
						(neuron->machine ? int(neuron->machine->state) : -1),
						unsigned(bytesBefore));
						queueCloseIfActive(neuron);
						return;
					}
					sendHandler(neuron, result);
					basics_log("neuron send complete private4=%u result=%d bytesBefore=%u bytesAfter=%u active=%d pendingSend=%d\n",
						(neuron->machine ? neuron->machine->private4 : 0u),
						result,
						unsigned(bytesBefore),
						unsigned(neuron->wBuffer.size()),
						int(streamIsActive(neuron)),
						int(neuron->pendingSend));
			}
			else if (socket == (void *)mothership)
			{
				Mothership *activeMothership = mothership;
				size_t bytesBefore = size_t(activeMothership->wBuffer.size());
				uint32_t submittedBytes = activeMothership->pendingSendBytes;
				bool pendingSendBefore = activeMothership->pendingSend;
				sendHandler(activeMothership, result);
					std::fprintf(stderr, "prodigy mothership send-complete result=%d submittedBytes=%u bytesBefore=%zu bytesAfter=%zu stream=%p fixedFD=%d fslot=%d active=%d pendingSendBefore=%d pendingSendAfter=%d pendingSendBytesAfter=%u\n",
						result,
						unsigned(submittedBytes),
						bytesBefore,
						size_t(activeMothership->wBuffer.size()),
						static_cast<void *>(activeMothership),
						loggableSocketFD(activeMothership),
						activeMothership->fslot,
					int(streamIsActive(activeMothership)),
					int(pendingSendBefore),
					int(activeMothership->pendingSend),
					unsigned(activeMothership->pendingSendBytes));
				std::fflush(stderr);
				closeMothershipAfterSendDrainIfNeeded(activeMothership, "send-complete-drained");
				if (Ring::socketIsClosing(activeMothership)
					&& activeMothership->pendingSend == false
					&& activeMothership->wBuffer.outstandingBytes() == 0)
				{
					retireClosingMothershipStreamIfNeeded(activeMothership, "send-complete-drained");
				}
			}
		}

	void handleMachineStateChange(Machine *machine, MachineState newState)
	{
		if (machine == nullptr)
		{
			co_return;
		}

		if (machines.contains(machine) == false)
		{
			co_return;
		}

		// it's possible to fail through multiple pathways, but we atomize the states enough that if the state
		// is already equal to the new desired state, the action is already being taken
		if (newState == machine->state) co_return;

		MachineState oldState = machine->state;
		basics_log("machine state change uuid=%llu private4=%u cloudID=%s old=%u new=%u isBrain=%d creationTimeMs=%lld lastUpdatedOSMs=%lld\n",
			(unsigned long long)machine->uuid,
			unsigned(machine->private4),
			machine->cloudID.c_str(),
			unsigned(oldState),
			unsigned(newState),
			int(machine->isBrain),
			(long long)machine->creationTimeMs,
			(long long)machine->lastUpdatedOSMs);
		machine->state = newState;

			switch (newState)
			{
				case MachineState::healthy:
				{
					// clear transient flags and counters when returning to healthy
					machine->inBinaryUpdate = false;
					machine->neuronConnectFailStreak = 0;
					machine->brainConnectFailStreak = 0;
					cancelMachineSoftWatchdog(machine);
					cancelMachineHardRebootWatchdog(machine);

					if (machine->claims.size() > 0) // the resources for these containers have already been charged and per machine bookkeeping done as well
					{
						for (auto it = machine->claims.begin(); it != machine->claims.end(); )
						{
						Machine::Claim& claim = *it;

						MachineTicket *ticket = claim.ticket;
						ticket->nNow = claim.nFit;
						ticket->shardGroups = claim.shardGroups;
                  ticket->reservedGPUMemoryMBs = claim.reservedGPUMemoryMBs;
                  ticket->reservedGPUDevices = claim.reservedGPUDevices;

						ticket->machineNow = machine;

						ticket->coro->co_consume();

						it = machine->claims.erase(it);
					}
				}

					switch (oldState)
					{
					case MachineState::deploying:
					{
						if (machine->lifetime == MachineLifetime::reserved || machine->lifetime == MachineLifetime::owned)
						{
							Vector<Machine *> donorMachines;

							for (Machine *machine : machines) // gather so we can sort
							{
								if (machine->state != MachineState::healthy) continue;

								if (machine->lifetime == MachineLifetime::ondemand)
								{
									donorMachines.push_back(machine);
								}
							}

							// sort by most available cores first... aka least busy
							sorter(donorMachines, [&] (const Machine *machine) -> int64_t {

								return machine->nLogicalCores_available;
							});

								for (Machine *donor : donorMachines)
								{
									for (auto& [deploymentID, containersOfDeployment] : donor->containersByDeploymentID)
									{
										auto deploymentIt = deployments.find(deploymentID);
										if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
										{
											continue;
										}

										ApplicationDeployment *deployment = deploymentIt->second;
										DeploymentPlan& plan = deployment->plan;

									uint32_t budget = containersOfDeployment.size(); // optimistically move them all

									// stateful budget (which is only rack budget) considered later
									if (plan.isStateful == false) budget = ApplicationDeployment::clampBudgetByRackAndMachine(deployment, machine, budget);

									if (uint32_t nFit = ApplicationDeployment::nFitOnMachine(deployment, machine, budget); nFit > 0)
									{
										for (auto it = containersOfDeployment.begin(); it != containersOfDeployment.end() && nFit > 0; )
										{
											ContainerView *container = *it;

											switch (container->state)
											{
												case ContainerState::planned:
												case ContainerState::scheduled:
												case ContainerState::crashedRestarting:
												case ContainerState::healthy:
												{
													if (donor->rack != machine->rack)
													{
														if (plan.isStateful)
														{
															if (deployment->racksByShardGroup[container->shardGroup].contains(machine->rack)) break;

															deployment->racksByShardGroup[container->shardGroup].erase(donor->rack);
															deployment->racksByShardGroup[container->shardGroup].insert(machine->rack);
														}

														deployment->countPerRack[donor->rack] -= 1;
														deployment->countPerRack[machine->rack] += 1;
													}

													nFit -= 1;

                                       prodigyDebitMachineScalarResources(machine, plan.config, 1);

													deployment->countPerMachine[donor] -= 1;
													deployment->countPerMachine[machine] += 1;

													if (container->state == ContainerState::planned)
													{
                                          prodigyCreditMachineScalarResources(donor, plan.config, 1);

														WorkBase *work = container->plannedWork->getBase();
                                          donor->removeContainerIndexEntry(container->deploymentID, container);

															work->machine = machine;
															work->container->machine = machine;
															machine->upsertContainerIndexEntry(container->deploymentID, container);

														if (work->lifecycle == LifecycleOp::updateInPlace)
														{
															work->lifecycle = LifecycleOp::construct;
															std::get_if<StatefulWork>(container->plannedWork)->data = DataStrategy::seeding;

															deployment->toSchedule.erase(container->plannedWork);

															DeploymentWork *dwork = deployment->planStatefulDestruction(work->oldContainer);

															work->oldContainer = nullptr;

															deployment->scheduleConstructionDestruction(container->plannedWork, dwork);
														}

														// delete us from containersByDeploymentID
														it = containersOfDeployment.erase(it);
														continue;
													}
													else
													{
														container->state = ContainerState::aboutToDestroy;
														deployment->handleContainerStateChange(container, true);

														if (plan.isStateful)
														{
															DeploymentWork *dwork = deployment->planStatefulDestruction(container);
															DeploymentWork *cwork = deployment->planStatefulConstruction(machine, container->shardGroup, DataStrategy::seeding);

															deployment->scheduleConstructionDestruction(cwork, dwork);
														}
														else
														{
															DeploymentWork *dwork = deployment->planStatelessDestruction(container);
															DeploymentWork *cwork = deployment->planStatelessConstruction(machine, container->lifetime);

															deployment->scheduleConstructionDestruction(cwork, dwork);
														}
													}

													break;
												}
												case ContainerState::aboutToDestroy: // destruction already planned
												case ContainerState::destroying: 	 // destruction already scheduled
												case ContainerState::destroyed: // not possible here
												case ContainerState::none:
												{
													break;
												}

												it++;
											}
										}
									}
								}

								// deployments will schedule containers onto on-demand and reserved with the same affinity... so it's possible
								// even if we move all containers off an on-demand machine, that by the time all the containers have been destroyed
								// that some other deployment has scheduled a container onto it... and thus it's not empty... and thus we can't destroy it

								// if we marked a machine as don't schedule to this... it's possible we need that capacity and then we'd end up scheduling
								// another on-demand... that works though but only if we fully unschedule it

								bool containersDrained = true;

								for (const auto& [deploymentID, containers] : donor->containersByDeploymentID)
								{
									for (ContainerView *container : containers)
									{
										switch (container->state)
										{
											case ContainerState::scheduled:
											case ContainerState::crashedRestarting:
											case ContainerState::healthy:
											{
												containersDrained = false;
												goto jumpout;
											}
											default: break;
										}
									}
								}
							jumpout:

								// nothing else will be scheduled to this machine now... and it will be decomissioned once the final container is destroyed off
								if (containersDrained) handleMachineStateChange(donor, MachineState::decommissioning);
							}
						}

						break;
					}
               case MachineState::updatingOS:
               {
                  // Returned healthy after an OS update.
                  onDrainCompleteForOSUpdate(machine);
                  armMachineUpdateTimerIfNeeded();
                  break;
               }
						default: break;
					}

					if (isActiveMaster())
					{
						for (const auto& [applicationID, head] : deploymentsByApp)
						{
							(void)applicationID;
							if (head && !head->plan.isStateful)
							{
								head->evaluateAfterNewMaster();
							}
						}
					}

					break;
				}
			case MachineState::missing:
			{
				// by the time we get here, we could've already progressed past this stage and be on SSH or hard rebooting or even reported it failed..
				// so check that state first, then return if

				switch (oldState)
				{
					case MachineState::deploying:
					{
						// we just created a machine but the neuron never came alive

						break;
					}
					case MachineState::neuronRebooting:
					{
						// should only take microseconds(?) for the neuron to become available again
						// if a brain, maybe 100ms for the brain socket to been accepting (after the neuron gathers its metadata and sees it's a brain)
						// then, if a brain and it connects to us, maybe another 100ms until it gathers all machines and connects to us
						// so either way this should always be captured witin the 750ms reconnect time

						// so not sure what we'd do in this situation though... might require manual intervention
						break;
					}
					case MachineState::healthy:
					{
						// it was healthy, now it's vanished

						break;
					}
					case MachineState::updatingOS:
					{
						// we already accounted for the reboot time + neuron start time in our "attempt reconnects until" factor


						break;
					}
					default: break;
				}

				// If we transitioned here during a binary update, give it space (state will be neuronRebooting)
				if (machine->inBinaryUpdate)
				{
					machine->state = MachineState::neuronRebooting;
					break;
				}

				// Missing host should release placement immediately so stateless/service
				// workloads can move without waiting for remediation escalation timeouts.
				evacuateFailedMachineContainers(machine);

				// even if the machine responded to pings, our next action would be to try
				// to SSH in and restart the neuron so there's no point of pinging, the SSH
				// TCP connection serves the same purpose, and has 0 risk of packets being dropped.

				// Budget: try SSH restart up to 2 times, then escalate to unresponsive
				if (machine->sshRestartAttempts >= 2)
				{
					machine->state = MachineState::unresponsive; // medium escalation
					co_return;
				}

				MachineSSH *ssh = new MachineSSH();
				sshs.insert(ssh);
				ssh->machine = machine;
            ssh->bootstrapSshKeyPackage = &brainConfig.bootstrapSshKeyPackage;
            ssh->bootstrapSshPrivateKeyPath = &brainConfig.bootstrapSshPrivateKeyPath;
				RingDispatcher::installMultiplexee(ssh, this);

				// isn't the point just to see if we can connect to SSH... and then if we can restart the neuron?
				// i guess this collapses both functions into one

				// as long as we can garauntee none of the captured context can be destroyed before
				// this lambda fires, then we're fine
					IPAddress sshAddress = {};
					uint16_t sshPort = 0;
					if (prodigyResolveMachineSSHSocketAddress(*machine, sshAddress, sshPort) == false)
					{
						sshs.erase(ssh);
						delete ssh;
						co_return;
					}

				ssh->setIPVersion(sshAddress.is6 ? AF_INET6 : AF_INET);
				ssh->setDatacenterCongestion();
				ssh->setDaddr(sshAddress, sshPort);
				ssh->machine = machine;

				bool isDevMode = BrainBase::controlPlaneDevModeEnabled();
				ssh->connectTimeoutMs = BrainBase::controlPlaneConnectTimeoutMs(isDevMode);
				ssh->nDefaultAttemptsBudget = BrainBase::controlPlaneConnectAttemptsBudget(isDevMode);
				uint32_t sshConnectAttemptTimeMs = BrainBase::machineInitialConnectAttemptTimeMs(
					machine->creationTimeMs,
					ssh->connectTimeoutMs,
					ssh->nDefaultAttemptsBudget);
				ssh->attemptForMs(sshConnectAttemptTimeMs);

				// technically it's possible that the network randomly broke then healed, so SSH succeeded.. then we restarted the neuron for no reason... but that'll never happen

					uint128_t sshMachineUUID = machine->uuid;
					ssh->registerAction(SSHAction::restartProdigy, [this, ssh, sshMachineUUID] (void) -> void {
						Machine *targetMachine = nullptr;
						if (auto machineIt = machinesByUUID.find(sshMachineUUID); machineIt != machinesByUUID.end())
						{
							targetMachine = machineIt->second;
						}

						// if the TCP connection succeded, every stage of restartProdigy will succeed
						// and then we'll be here
						// but if the TCP connection failed, then not
						// but if the SSH TCP connection failed, then we'd go straight to machine missing

	            if (targetMachine && isActiveMaster())
	            {
	               armMachineNeuronReconnect(targetMachine, BrainBase::machineInitialConnectAttemptTimeMs(
	                  targetMachine->creationTimeMs,
	                  targetMachine->neuron.connectTimeoutMs,
	                  targetMachine->neuron.nDefaultAttemptsBudget));
	            }

						if (targetMachine && targetMachine->brain)
						{
							armOutboundPeerReconnect(targetMachine->brain);
						}

						ssh->reconnectAfterClose = false;
						Ring::queueClose(ssh);
					});

				machine->sshRestartAttempts += 1;
				machine->lastSshAttemptMs = Time::now<TimeResolution::ms>();
				ssh->attemptConnect();

					// Arm a short watchdog to escalate if the SSH restart does not restore health
					cancelMachineSoftWatchdog(machine);
				machine->softWatchdog = new TimeoutPacket();
				machine->softWatchdog->flags = uint64_t(BrainTimeoutFlags::softEscalationCheck);
				machine->softWatchdog->identifier = machine->uuid;
				machine->softWatchdog->originator = machine;
				machine->softWatchdog->dispatcher = this;
				// Freshly bootstrapped machines can legitimately take much longer than 1s
				// before neuron/brain control sockets accept. Keep the SSH-restart escalation
				// path creation-aware so a brand-new machine is not hard-rebooted immediately.
				uint32_t softEscalationTimeoutMs = BrainBase::machineBootstrapSoftEscalationTimeoutMs(
					machine->creationTimeMs,
					machine->neuron.connectTimeoutMs,
					machine->neuron.nDefaultAttemptsBudget);
				machine->softWatchdog->setTimeoutMs(softEscalationTimeoutMs);
				basics_log("machine missing remediation uuid=%llu private4=%u sshWindowMs=%u softTimeoutMs=%u creationTimeMs=%lld sshRestartAttempts=%u\n",
					(unsigned long long)machine->uuid,
					unsigned(machine->private4),
					sshConnectAttemptTimeMs,
					softEscalationTimeoutMs,
					(long long)machine->creationTimeMs,
					unsigned(machine->sshRestartAttempts));
				RingDispatcher::installMultiplexee(machine->softWatchdog, this);
				Ring::queueTimeout(machine->softWatchdog);

				break;
			}
				case MachineState::unresponsive:
				{
					// SSH was unable to connect; escalate to IaaS hard reboot.
					machine->state = MachineState::hardRebooting;
					machine->hardRebootAttempts += 1;
					machine->lastHardRebootMs = Time::now<TimeResolution::ms>();
					basics_log("machine hard reboot escalation uuid=%llu private4=%u hardRebootAttempts=%u creationTimeMs=%lld\n",
						(unsigned long long)machine->uuid,
						unsigned(machine->private4),
						unsigned(machine->hardRebootAttempts),
						(long long)machine->creationTimeMs);

					iaas->hardRebootMachine(machine->uuid);

					cancelMachineHardRebootWatchdog(machine);
					TimeoutPacket *timeout = new TimeoutPacket();
					timeout->flags = uint64_t(BrainTimeoutFlags::hardRebootedMachine);
					timeout->identifier = machine->uuid;
					timeout->originator = machine;
					timeout->dispatcher = this;
					timeout->setTimeoutMs(prodigyBrainHardRebootWatchdogMs);
					RingDispatcher::installMultiplexee(timeout, this);
					Ring::queueTimeout(timeout);
					machine->hardRebootWatchdog = timeout;

				// let's also tell neuron and possibly brain to keep trying to reconnect?

				// we likely have to recreate the socket here
            if (isActiveMaster())
            {
               // Keep retry budget for the reboot window, but recycle any active
               // fixed-file slot through normal close completion before reopening.
               armMachineNeuronReconnect(machine, prodigyBrainHardRebootReconnectWindowMs);
	            }

				break;
			}
			case MachineState::hardRebooting:
			{

				break;
			}
				case MachineState::hardwareFailure:
				{
					break;
				}
			case MachineState::decommissioning:
			{
				// once the final container has been destroyed, transition into actual destruction of the machine

				break;
			}
			case MachineState::updatingOS:
			{
				// definitely share this, especially so they know the last time it was updated
				// or we'd share the state then after share the timestamp and new kernel version
				break;
			}
			// never shared as updates
			case MachineState::neuronRebooting: // no reason to share this
			case MachineState::unknown: // this is the base state of a machine more than 7 minutes old
			default: break;
		}
	}

	void transitionToNewBundle(void)
	{
		// should we serialize and save all the container data?
		String failure = {};
		String stagedBundlePath = prodigyStagedBundlePath();
		if (prodigyInstallBundleToRoot(stagedBundlePath, "/root/prodigy"_ctv, &failure) == false)
		{
			basics_log("transitionToNewBundle install failed: %s\n", failure.c_str());
			_exit(EXIT_FAILURE);
		}

		ProdigyInstallRootPaths installPaths = {};
		prodigyBuildInstallRootPaths("/root/prodigy"_ctv, installPaths);
		String libraryDirectoryText = {};
		libraryDirectoryText.assign(installPaths.libraryDirectory);
		(void)setenv("LD_LIBRARY_PATH", libraryDirectoryText.c_str(), 1);
		Ring::shutdownForExec();

		long maxFD = sysconf(_SC_OPEN_MAX);
		if (maxFD < 0) maxFD = 4096;
		for (int fd = 3; fd < maxFD; ++fd)
		{
			close(fd);
		}

		String binaryPathText = {};
		binaryPathText.assign(installPaths.binaryPath);
		Vector<char *> argv = {};
		if (buildLaunchArgumentsForExec(binaryPathText, argv))
		{
			execv(binaryPathText.c_str(), argv.data());
		}

		execl(binaryPathText.c_str(), binaryPathText.c_str(), (char * )NULL);
		_exit(EXIT_FAILURE);
	}

	void resetUpdateSelfState(bool clearBundleBlob = true)
	{
		updateSelfState = UpdateSelfState::idle;
		updateSelfExpectedEchos = 0;
		updateSelfBundleEchos = 0;
		updateSelfRelinquishEchos = 0;
		updateSelfPlannedMasterPeerKey = 0;
		updateSelfUseStagedBundleOnly = false;
		if (clearBundleBlob) updateSelfBundleBlob.clear();
		updateSelfBundleIssuedPeerKeys.clear();
		updateSelfBundleEchoPeerKeys.clear();
		updateSelfRelinquishEchoPeerKeys.clear();
		updateSelfFollowerBootNsByPeerKey.clear();
		updateSelfFollowerReconnectedPeerKeys.clear();
		updateSelfFollowerRebootedPeerKeys.clear();
		updateSelfTransitionIssuedPeerKeys.clear();
		updateSelfRelinquishIssuedPeerKeys.clear();
	}

	bool devSharedStagedBundleEnabled(void) const
	{
		if (const char *sharedStageEnv = getenv("PRODIGY_DEV_SHARED_STAGE_BUNDLE");
			sharedStageEnv && sharedStageEnv[0] == '1' && sharedStageEnv[1] == '\0')
		{
			return true;
		}

		return false;
	}

		bool peerSocketActive(BrainView *bv)
		{
			if (bv == nullptr) return false;
			if (bv->connected == false) return false;
			if (Ring::socketIsClosing(bv)) return false;
			if (bv->isFixedFile == false)
			{
				// fd/fslot are a union; negative slot means no active descriptor.
				if (bv->fslot < 0)
				{
					return false;
				}

				basics_log("peerSocketActive expected fixed-file peer=%p private4=%u fd=%d fslot=%d\n",
					bv, bv->private4, bv->fd, bv->fslot);
				std::abort();
			}
			return (bv->fslot >= 0);
		}

bool hasConnectedBrainMajority(void)
	{
		uint32_t connectedBrains = 1; // include self
		for (BrainView *peer : brains)
		{
			if (peerEligibleForClusterQuorum(peer) == false) continue;
			if (peerSocketActive(peer) == false) continue;
			connectedBrains += 1;
			}

			return (connectedBrains > (nBrains / 2));
		}

	bool shouldRetainMasterControlOnBrainLoss(void)
	{
		return hasConnectedBrainMajority();
	}

	void armOutboundPeerReconnect(BrainView *bv, bool forceConnectorOwnership = false)
	{
		if (bv == nullptr) return;
		if (bv->weConnectToIt == false && forceConnectorOwnership == false) return;
		const uint32_t preservedAttemptsBudget = bv->nAttemptsBudget;
		const int64_t preservedAttemptDeadlineMs = bv->attemptDeadlineMs;
		const bool preserveReconnectPolicy = (preservedAttemptsBudget > 0 || preservedAttemptDeadlineMs > 0);
		bv->connected = false;
		bv->nConnectionAttempts = 0;
		bv->reconnectAfterClose = true;

		bool reconnectArmedByClose = Ring::socketIsClosing(bv);
		if (reconnectArmedByClose == false && peerSocketActive(bv))
		{
			queueCloseIfActive(bv);
			reconnectArmedByClose = Ring::socketIsClosing(bv);
		}

		if (reconnectArmedByClose == false && rawStreamIsActive(bv))
		{
			abandonSocketGeneration(bv);
		}

		if (preserveReconnectPolicy)
		{
			bv->nAttemptsBudget = preservedAttemptsBudget;
			bv->attemptDeadlineMs = preservedAttemptDeadlineMs;
		}
		else
		{
			bv->nAttemptsBudget = 0;
			bv->attemptDeadlineMs = 0;
		}

		if (reconnectArmedByClose == false)
		{
			bv->recreateSocket();
			configureBrainPeerConnectAddress(bv);
			if (installBrainPeerSocket(bv))
			{
				bv->attemptConnect();
			}
		}
	}

	void armMachineNeuronReconnect(Machine *machine, int64_t reconnectWindowMs)
	{
		if (machine == nullptr)
		{
			return;
		}

		NeuronView *neuron = &machine->neuron;
		neuron->nConnectionAttempts = 0;
		neuron->reconnectAfterClose = true;
		neuron->attemptForMs(reconnectWindowMs);

		bool reconnectArmedByClose = Ring::socketIsClosing(neuron);
		if (reconnectArmedByClose == false)
		{
			if (neuronControlSocketArmed(machine))
			{
				queueCloseIfActive(neuron);
				reconnectArmedByClose = Ring::socketIsClosing(neuron);
			}
		}

		if (reconnectArmedByClose == false)
		{
			neuron->recreateSocket();
			if (installNeuronControlSocket(neuron))
			{
				neuron->attemptConnect();
			}
		}
	}

	void queueUpdateSelfBundleToPeer(BrainView *bv)
	{
		if (updateSelfState != UpdateSelfState::waitingForBundleEchos) return;
		if (bv == nullptr) return;
		if (updateSelfUseStagedBundleOnly == false && updateSelfBundleBlob.size() == 0) return;
		uint128_t peerKey = updateSelfPeerTrackingKey(bv);
		if (peerKey != 0 && updateSelfBundleEchoPeerKeys.contains(peerKey)) return;
		if (peerKey != 0 && updateSelfBundleIssuedPeerKeys.contains(peerKey)) return;
		if (bv->pendingSend) return;
		if (peerSocketActive(bv) == false)
		{
			std::fprintf(stderr,
				"prodigy updateProdigy bundle-peer-unavailable private4=%u quarantined=%d isFixed=%d fslot=%d fd=%d\n",
				bv->private4, int(bv->quarantined), int(bv->isFixedFile), bv->fslot, bv->fd);
			std::fflush(stderr);
			if (bv->weConnectToIt)
			{
				armOutboundPeerReconnect(bv);
			}
			return;
		}

		if (updateSelfUseStagedBundleOnly)
		{
			// Explicit dev fast path: brains share one writable /root staging area, so
			// /root/prodigy.bundle.new.tar.zst is already staged locally on every brain process.
			Message::construct(bv->wBuffer, BrainTopic::updateBundle, "__staged__"_ctv);
			std::fprintf(stderr, "prodigy updateProdigy bundle-staged-send private4=%u\n", bv->private4);
			std::fflush(stderr);
		}
		else
		{
			const uint64_t bundleSendHeadroom = 256_KB;
			// Large updateProdigy payloads can exceed the normal peer keepalive/user-timeout window.
			bv->setKeepaliveTimeoutSeconds(120);
			bv->wBuffer.reserve(bv->wBuffer.size() + updateSelfBundleBlob.size() + bundleSendHeadroom);
			Message::construct(bv->wBuffer, BrainTopic::updateBundle, updateSelfBundleBlob);
			std::fprintf(stderr, "prodigy updateProdigy bundle-send private4=%u bytes=%u\n", bv->private4, uint32_t(updateSelfBundleBlob.size()));
			std::fflush(stderr);
		}
		if (peerKey != 0)
		{
			updateSelfBundleIssuedPeerKeys.insert(peerKey);
		}
		Ring::queueSend(bv);
	}

	void queueUpdateSelfBundleToPendingPeers(void)
	{
		if (updateSelfState != UpdateSelfState::waitingForBundleEchos) return;

		for (BrainView *bv : brains)
		{
			queueUpdateSelfBundleToPeer(bv);
		}
	}

	bool updateSelfPeerStreamDrained(BrainView *bv)
	{
		if (bv == nullptr) return false;
		if (peerSocketActive(bv) == false) return false;
		return (bv->pendingSend == false);
	}

	void queueUpdateSelfTransitionToPeer(BrainView *bv)
	{
		if (updateSelfState != UpdateSelfState::waitingForFollowerReboots) return;
		if (bv == nullptr) return;

		uint128_t peerKey = updateSelfPeerTrackingKey(bv);
		if (peerKey == 0) return;
		if (updateSelfFollowerBootNsByPeerKey.contains(peerKey) == false) return;
		if (updateSelfFollowerRebootedPeerKeys.contains(peerKey)) return;
		if (updateSelfTransitionIssuedPeerKeys.contains(peerKey)) return;
		if (updateSelfPeerStreamDrained(bv) == false) return;

		updateSelfTransitionIssuedPeerKeys.insert(peerKey);
		std::fprintf(stderr, "prodigy updateProdigy follower-transition-send private4=%u peerKey=%llu\n",
			bv->private4,
			(unsigned long long)peerKey);
		std::fflush(stderr);
		std::fprintf(stderr,
			"prodigy updateProdigy follower-transition-construct private4=%u peerKey=%llu pendingSend=%d wbytes=%u tls=%d negotiated=%d\n",
			bv->private4,
			(unsigned long long)peerKey,
			int(bv->pendingSend),
			uint32_t(bv->wBuffer.outstandingBytes()),
			int(bv->transportTLSEnabled()),
			int(bv->isTLSNegotiated()));
		std::fflush(stderr);
		Message::construct(bv->wBuffer, BrainTopic::transitionToNewBundle, uint8_t(1));
		std::fprintf(stderr,
			"prodigy updateProdigy follower-transition-queued-message private4=%u peerKey=%llu wbytes=%u\n",
			bv->private4,
			(unsigned long long)peerKey,
			uint32_t(bv->wBuffer.outstandingBytes()));
		std::fflush(stderr);
		Ring::queueSend(bv);
		std::fprintf(stderr,
			"prodigy updateProdigy follower-transition-queue-send private4=%u peerKey=%llu pendingSend=%d queuedBytes=%llu\n",
			bv->private4,
			(unsigned long long)peerKey,
			int(bv->pendingSend),
			(unsigned long long)bv->queuedSendOutstandingBytes());
		std::fflush(stderr);
	}

	void queueUpdateSelfRelinquishToPeer(BrainView *bv)
	{
		if (updateSelfState != UpdateSelfState::waitingForRelinquishEchos) return;
		if (bv == nullptr) return;

		uint128_t peerKey = updateSelfPeerTrackingKey(bv);
		if (peerKey == 0) return;
		if (updateSelfFollowerRebootedPeerKeys.contains(peerKey) == false) return;
		if (updateSelfRelinquishEchoPeerKeys.contains(peerKey)) return;
		if (updateSelfRelinquishIssuedPeerKeys.contains(peerKey)) return;
		if (updateSelfPeerStreamDrained(bv) == false) return;

		updateSelfRelinquishIssuedPeerKeys.insert(peerKey);
		Message::construct(bv->wBuffer, BrainTopic::relinquishMasterStatus, uint8_t(1), updateSelfPlannedMasterPeerKey);
		Ring::queueSend(bv);
	}

		void beginUpdateSelfBundle(uint32_t expectedPeerEchos)
		{
			bool useStagedBundleOnly = updateSelfUseStagedBundleOnly;
			resetUpdateSelfState(false);
			updateSelfUseStagedBundleOnly = useStagedBundleOnly;
		// We're collecting echos from other brains that they received and saved the new bundle.
		updateSelfState = UpdateSelfState::waitingForBundleEchos;
			updateSelfExpectedEchos = expectedPeerEchos;

			std::fprintf(stderr,
				"prodigy updateProdigy begin expectedPeerEchos=%u stagedOnly=%d bundleBytes=%zu\n",
				expectedPeerEchos,
				int(updateSelfUseStagedBundleOnly),
				size_t(updateSelfBundleBlob.size()));
			std::fflush(stderr);
         noteMasterAuthorityRuntimeStateChanged();

			if (expectedPeerEchos == 0)
			{
				boottimens = Time::now<TimeResolution::ns>();
				forfeitMasterStatus();
				resetUpdateSelfState();
            noteMasterAuthorityRuntimeStateChanged();
				transitionToNewBundle();
				return;
			}

		queueUpdateSelfBundleToPendingPeers();
	}

	void maybeRelinquishMasterForUpdateSelf(void)
	{
		if (updateSelfState != UpdateSelfState::waitingForFollowerReboots) return;
		if (updateSelfFollowerRebootedPeerKeys.size() < updateSelfExpectedEchos) return;

		// Ask peers to derive the next master before we restart ourselves.
		updateSelfState = UpdateSelfState::waitingForRelinquishEchos;
		updateSelfRelinquishEchos = 0;
		updateSelfRelinquishEchoPeerKeys.clear();
		updateSelfRelinquishIssuedPeerKeys.clear();
		updateSelfPlannedMasterPeerKey = 0;
		for (BrainView *bv : brains)
		{
			if (bv == nullptr)
			{
				continue;
			}

			uint128_t peerKey = updateSelfPeerTrackingKey(bv);
			if (updateSelfFollowerRebootedPeerKeys.contains(peerKey) == false)
			{
				continue;
			}

			if (updateSelfPlannedMasterPeerKey == 0 || peerKey < updateSelfPlannedMasterPeerKey)
			{
				updateSelfPlannedMasterPeerKey = peerKey;
			}
		}
		if (updateSelfPlannedMasterPeerKey == 0) return;
			String nextMasterPeerKeyText = {};
			nextMasterPeerKeyText.snprintf<"{itoa}"_ctv>(updateSelfPlannedMasterPeerKey);
			std::fprintf(stderr,
				"prodigy updateProdigy relinquish-begin peers=%u nextMasterPeerKey=%s\n",
				updateSelfExpectedEchos,
				nextMasterPeerKeyText.c_str());
			std::fflush(stderr);
         noteMasterAuthorityRuntimeStateChanged();

			for (BrainView *bv : brains)
			{
			queueUpdateSelfRelinquishToPeer(bv);
		}
	}

	void maybeTransitionFollowersForUpdateSelf(void)
	{
		if (updateSelfState != UpdateSelfState::waitingForBundleEchos) return;
		if (updateSelfBundleEchos < updateSelfExpectedEchos) return;

		updateSelfState = UpdateSelfState::waitingForFollowerReboots;
			updateSelfFollowerBootNsByPeerKey.clear();
			updateSelfFollowerRebootedPeerKeys.clear();
			updateSelfTransitionIssuedPeerKeys.clear();
			updateSelfBundleBlob.clear();
         noteMasterAuthorityRuntimeStateChanged();

			// Followers should transition first so master handoff/restart happens last.
			std::fprintf(stderr, "prodigy updateProdigy follower-transition-begin peers=%u\n", updateSelfExpectedEchos);
			std::fflush(stderr);
		for (BrainView *bv : brains)
		{
			if (peerSocketActive(bv) == false)
			{
				continue;
			}

			uint128_t peerKey = updateSelfPeerTrackingKey(bv);
			if (peerKey != 0)
			{
				updateSelfFollowerBootNsByPeerKey.insert_or_assign(peerKey, bv->boottimens);
			}

			queueUpdateSelfTransitionToPeer(bv);
		}
	}

	void noteUpdateSelfFollowerReboot(BrainView *bv, const char *source, int64_t previousBootNs = 0)
	{
		if (updateSelfState != UpdateSelfState::waitingForFollowerReboots) return;
		if (bv == nullptr) return;

		uint128_t peerKey = updateSelfPeerTrackingKey(bv);
		if (peerKey == 0) return;
		if (updateSelfFollowerBootNsByPeerKey.contains(peerKey) == false) return;
		if (updateSelfFollowerRebootedPeerKeys.contains(peerKey)) return;

		updateSelfFollowerReconnectedPeerKeys.erase(peerKey);
		updateSelfFollowerRebootedPeerKeys.insert(peerKey);

		String rebootedUUIDText = {};
		rebootedUUIDText.snprintf<"{itoa}"_ctv>(bv->uuid);
		std::fprintf(stderr,
			"prodigy updateProdigy follower-reboot source=%s uuid=%s private4=%u %u/%u oldBootNs=%ld newBootNs=%ld\n",
			(source ? source : "unknown"),
			rebootedUUIDText.c_str(),
			bv->private4,
			uint32_t(updateSelfFollowerRebootedPeerKeys.size()),
			updateSelfExpectedEchos,
			(long)previousBootNs,
			(long)bv->boottimens);
		std::fflush(stderr);
		noteMasterAuthorityRuntimeStateChanged();

		maybeRelinquishMasterForUpdateSelf();
	}

	void onUpdateSelfPeerRegistration(BrainView *bv)
	{
		if (updateSelfState != UpdateSelfState::waitingForFollowerReboots) return;
		if (bv == nullptr) return;

		uint128_t peerKey = updateSelfPeerTrackingKey(bv);
		auto it = updateSelfFollowerBootNsByPeerKey.find(peerKey);
		std::fprintf(stderr,
			"prodigy updateProdigy follower-registration private4=%u tracked=%d oldBootNs=%ld newBootNs=%ld\n",
			bv->private4,
			int(it != updateSelfFollowerBootNsByPeerKey.end()),
			(long)(it != updateSelfFollowerBootNsByPeerKey.end() ? it->second : 0),
			(long)bv->boottimens);
		std::fflush(stderr);

		if (it != updateSelfFollowerBootNsByPeerKey.end())
		{
			int64_t previousBootNs = it->second;
			bool sawReconnect = updateSelfFollowerReconnectedPeerKeys.contains(peerKey);
			if ((bv->boottimens > 0 && bv->boottimens != previousBootNs) || sawReconnect)
			{
				noteUpdateSelfFollowerReboot(bv, sawReconnect ? "registration-reconnect" : "registration", previousBootNs);
			}
		}
	}

	void onUpdateSelfBundleEcho(BrainView *bv)
	{
		if (updateSelfState != UpdateSelfState::waitingForBundleEchos) return;
		if (bv == nullptr) return;

			uint128_t peerKey = updateSelfPeerTrackingKey(bv);
			if (peerKey != 0 && updateSelfBundleEchoPeerKeys.contains(peerKey) == false && updateSelfBundleEchos < updateSelfExpectedEchos)
			{
				updateSelfBundleEchoPeerKeys.insert(peerKey);
				updateSelfBundleEchos += 1;
            noteMasterAuthorityRuntimeStateChanged();
			}

		std::fprintf(stderr, "prodigy updateProdigy bundle-echo %u/%u\n", updateSelfBundleEchos, updateSelfExpectedEchos);
		std::fflush(stderr);
		maybeTransitionFollowersForUpdateSelf();
	}

	void onUpdateSelfRelinquishEcho(BrainView *bv)
	{
		if (updateSelfState != UpdateSelfState::waitingForRelinquishEchos) return;
		if (bv == nullptr) return;

			uint128_t peerKey = updateSelfPeerTrackingKey(bv);
			if (peerKey != 0 && updateSelfRelinquishEchoPeerKeys.contains(peerKey) == false && updateSelfRelinquishEchos < updateSelfExpectedEchos)
			{
				updateSelfRelinquishEchoPeerKeys.insert(peerKey);
				updateSelfRelinquishEchos += 1;
            noteMasterAuthorityRuntimeStateChanged();
			}

		std::fprintf(stderr, "prodigy updateProdigy relinquish-echo %u/%u\n", updateSelfRelinquishEchos, updateSelfExpectedEchos);
		std::fflush(stderr);
		if (updateSelfRelinquishEchos < updateSelfExpectedEchos) return;

		// Once every peer has acknowledged relinquish, we can safely restart ourselves.
			boottimens = Time::now<TimeResolution::ns>();
			forfeitMasterStatus();
			resetUpdateSelfState();
         noteMasterAuthorityRuntimeStateChanged();
			transitionToNewBundle();
		}

		BrainView *currentMasterPeer(void)
		{
		for (BrainView *peer : brains)
		{
			if (peer == nullptr)
			{
				continue;
			}

			if (peer->isMasterBrain == false)
			{
				continue;
			}

			if (peerSocketActive(peer) == false)
			{
				continue;
			}

			return peer;
		}

			return nullptr;
		}

		void replicateMetricSampleToFollowers(BrainView *excludePeer, uint64_t deploymentID, uint128_t containerUUID, int64_t sampleTimeMs, uint64_t metricKey, uint64_t metricValue)
		{
			if (nBrains <= 1)
			{
				return;
			}

			for (BrainView *peer : brains)
			{
				if (peer == nullptr || peer == excludePeer || peer->quarantined)
				{
					continue;
				}

				if (peerSocketActive(peer) == false)
				{
					continue;
				}

				Message::construct(peer->wBuffer, BrainTopic::replicateMetricsAppend, deploymentID, containerUUID, sampleTimeMs, metricKey, metricValue);
				Ring::queueSend(peer);
			}
		}

		void forwardMetricSampleToMaster(uint64_t deploymentID, uint128_t containerUUID, int64_t sampleTimeMs, uint64_t metricKey, uint64_t metricValue)
		{
			if (weAreMaster)
			{
            replicateMetricSampleToFollowers(nullptr, deploymentID, containerUUID, sampleTimeMs, metricKey, metricValue);
				return;
			}

		BrainView *masterPeer = currentMasterPeer();
		if (masterPeer == nullptr)
		{
			return;
		}

		uint32_t headerOffset = Message::appendHeader(masterPeer->wBuffer, BrainTopic::replicateMetricsAppend);
		Message::append(masterPeer->wBuffer, deploymentID);
		Message::append(masterPeer->wBuffer, containerUUID);
		Message::append(masterPeer->wBuffer, sampleTimeMs);
		Message::append(masterPeer->wBuffer, metricKey);
		Message::append(masterPeer->wBuffer, metricValue);
		Message::finish(masterPeer->wBuffer, headerOffset);
		Ring::queueSend(masterPeer);
	}

void brainHandler(BrainView *bv, Message *message)
{
   uint8_t *args = message->args;

  switch (BrainTopic(message->topic))
  {
#if 0
      case BrainTopic::reconcileMetrics:
      {
         // follower -> master: lastKnownMs(8)
         if (!isActiveMaster()) break;
         int64_t lastMs = 0;
         Message::extractArg<ArgumentNature::fixed>(args, lastMs);
         // Send metrics newer than lastMs in chunks
         const Vector<Measurement> &feed = metrics.all;
         const size_t maxPerChunk = 256; // keep messages moderate
         size_t start = 0;
         // find first index > lastMs
         while (start < feed.size() && feed[start].ms <= lastMs) ++start;
         for (size_t i = start; i < feed.size(); )
         {
            uint32_t h = Message::appendHeader(bv->wBuffer, BrainTopic::replicateMetricsAppend);
            uint16_t n = 0; size_t j = i;
            // reserve count field placeholder written above
            // Append up to maxPerChunk measurements
            Message::append(bv->wBuffer, uint16_t(0)); // placeholder; will overwrite after building
            size_t countPos = bv->wBuffer.size() - sizeof(uint16_t);
            for (; j < feed.size() && n < maxPerChunk; ++j, ++n)
            {
               const Measurement &m = feed[j];
               Message::append(bv->wBuffer, m.ms);
               Message::append(bv->wBuffer, m.deploymentID);
               Message::append(bv->wBuffer, m.containerUUID);
               Message::append(bv->wBuffer, m.metricKey);
               Message::append(bv->wBuffer, m.value);
            }
            // backpatch count
            memcpy(bv->wBuffer.data() + countPos, &n, sizeof(uint16_t));
            Message::finish(bv->wBuffer, h);
            Ring::queueSend(bv);
            i = j;
         }
         break;
      }
      case BrainTopic::replicateMetricsAppend:
      {
         // master -> follower: count(2), then {ms(8) dep(8) uuid(16) key(4) value(float)} * count
         uint16_t n = 0; Message::extractArg<ArgumentNature::fixed>(args, n);
         Vector<Measurement> batch; batch.reserve(n);
         for (uint16_t i = 0; i < n; ++i)
         {
            int64_t ms; uint64_t dep; uint128_t uuid; uint32_t key; float v;
            Message::extractArg<ArgumentNature::fixed>(args, ms);
            Message::extractArg<ArgumentNature::fixed>(args, dep);
            Message::extractArg<ArgumentNature::fixed>(args, uuid);
            Message::extractArg<ArgumentNature::fixed>(args, key);
            Message::extractArg<ArgumentNature::fixed>(args, v);
            metrics.record(dep, uuid, key, ms, v);
            batch.push_back(Measurement{ms, dep, uuid, key, v});
         }
         // If we're master and this came from a follower, fan-out to other peers (exclude sender)
         if (isActiveMaster())
         {
            for (BrainView *peer : brains)
            {
               if (peer == bv) continue;
               uint32_t h = Message::appendHeader(peer->wBuffer, BrainTopic::replicateMetricsAppend);
               uint16_t nout = (uint16_t)batch.size();
               Message::append(peer->wBuffer, nout);
               for (const auto &m : batch)
               {
                  Message::append(peer->wBuffer, m.ms);
                  Message::append(peer->wBuffer, m.deploymentID);
                  Message::append(peer->wBuffer, m.containerUUID);
                  Message::append(peer->wBuffer, m.metricKey);
                  Message::append(peer->wBuffer, m.value);
               }
               Message::finish(peer->wBuffer, h);
               Ring::queueSend(peer);
            }
         }
         break;
      }
      case BrainTopic::reconcileTd:
      {
         // follower -> master: lastMinuteEndMs(8)
         if (!isActiveMaster()) break;
         int64_t lastMinute = 0;
         Message::extractArg<ArgumentNature::fixed>(args, lastMinute);
         const Vector<TDMinute> &feed = tdminutes.all;
         const size_t maxPerChunk = 128;
         size_t start = 0;
         while (start < feed.size() && feed[start].minuteEndMs <= lastMinute) ++start;
         for (size_t i = start; i < feed.size(); )
         {
            uint32_t h = Message::appendHeader(bv->wBuffer, BrainTopic::replicateTdAppend);
            uint16_t n = 0; size_t j = i;
            Message::append(bv->wBuffer, uint16_t(0));
            size_t countPos = bv->wBuffer.size() - sizeof(uint16_t);
            for (; j < feed.size() && n < maxPerChunk; ++j, ++n)
            {
               const TDMinute &r = feed[j];
               Message::append(bv->wBuffer, r.minuteEndMs);
               Message::append(bv->wBuffer, r.deploymentID);
               Message::append(bv->wBuffer, r.containerUUID);
               Message::append(bv->wBuffer, r.metricKey);
               metrics::TDigestCodec::append(bv->wBuffer, r.digest);
            }
            memcpy(bv->wBuffer.data() + countPos, &n, sizeof(uint16_t));
            Message::finish(bv->wBuffer, h);
            Ring::queueSend(bv);
            i = j;
         }
         // Also stream any group-minute records newer than lastMinute (best-effort); reuse same reconcileTd? Keep group sync via recompute path on follower.
         break;
      }
      case BrainTopic::replicateTdAppend:
      {
         // master -> follower: count(2), then {minuteEnd(8) dep(8) uuid(16) key(4) digest} * count
         uint16_t n = 0; Message::extractArg<ArgumentNature::fixed>(args, n);
         Vector<TDMinute> batch; batch.reserve(n);
         for (uint16_t i = 0; i < n; ++i)
         {
            int64_t minuteEnd; uint64_t dep; uint128_t uuid; uint32_t key;
            Message::extractArg<ArgumentNature::fixed>(args, minuteEnd);
            Message::extractArg<ArgumentNature::fixed>(args, dep);
            Message::extractArg<ArgumentNature::fixed>(args, uuid);
            Message::extractArg<ArgumentNature::fixed>(args, key);
            metrics::TDigest d(200.0);
            bool ok = metrics::TDigestCodec::extract(args, message->terminal(), d);
            if (!ok) break;
            tdminutes.upsert(dep, uuid, key, minuteEnd, d);
            if (minuteEnd > tdLastMinuteApplied) tdLastMinuteApplied = minuteEnd;
            recomputeGroupMinute(dep, key, minuteEnd);
            batch.push_back(TDMinute{minuteEnd, dep, uuid, key, d});
         }
         // If we're master and this came from a follower, fan-out to other peers (exclude sender)
         if (isActiveMaster())
         {
            for (BrainView *peer : brains)
            {
               if (peer == bv) continue;
               uint32_t h = Message::appendHeader(peer->wBuffer, BrainTopic::replicateTdAppend);
               uint16_t nout = (uint16_t)batch.size();
               Message::append(peer->wBuffer, nout);
               for (const auto &r : batch)
               {
                  Message::append(peer->wBuffer, r.minuteEndMs);
                  Message::append(peer->wBuffer, r.deploymentID);
                  Message::append(peer->wBuffer, r.containerUUID);
                  Message::append(peer->wBuffer, r.metricKey);
                  metrics::TDigestCodec::append(peer->wBuffer, r.digest);
               }
               Message::finish(peer->wBuffer, h);
               Ring::queueSend(peer);
            }
         }
         break;
      }
#endif
			case BrainTopic::replicateMetricsAppend:
			{
				// follower -> master: deploymentID(8) containerUUID(16) sampleTimeMs(8) metricKey(8) metricValue(8)
				uint64_t deploymentID = 0;
				uint128_t containerUUID = 0;
				int64_t sampleTimeMs = 0;
				uint64_t metricKey = 0;
				uint64_t metricValue = 0;

				Message::extractArg<ArgumentNature::fixed>(args, deploymentID);
				Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
				Message::extractArg<ArgumentNature::fixed>(args, sampleTimeMs);
				Message::extractArg<ArgumentNature::fixed>(args, metricKey);
				Message::extractArg<ArgumentNature::fixed>(args, metricValue);

				recordContainerMetric(deploymentID, containerUUID, metricKey, sampleTimeMs, static_cast<double>(metricValue));
            if (weAreMaster && bv != nullptr)
            {
               replicateMetricSampleToFollowers(bv, deploymentID, containerUUID, sampleTimeMs, metricKey, metricValue);
            }
				break;
			}
         case BrainTopic::replicateMetricsSnapshot:
         {
            String serialized;
            Message::extractToStringView(args, serialized);

            Vector<ProdigyMetricSample> samples;
            if (BitseryEngine::deserializeSafe(serialized, samples))
            {
               metrics.importSamples(samples);
               persistLocalRuntimeState();
            }
            break;
         }
				// this is for adding new deployments
				case BrainTopic::replicateDeployment:
			{
				if (message->payloadSize() == 8) // echo
				{
					// deploymentID(8)

					uint64_t deploymentID;
					Message::extractArg<ArgumentNature::fixed>(args, deploymentID);

					if (auto it = deployments.find(deploymentID); it != deployments.end())
					{
						ApplicationDeployment *deployment = it->second;

						deployment->brainEchos += 1;

						if (deployment->brainEchos == 2 && deployment->state == DeploymentState::none) // what if a brain dies during this??? then when it comes back online and gets replicated the deployments it will echo back to us
						{
							spinApplication(deployment);
						}
					}
				}
				else
				{
					// plan{4} containerBlob{4}

					String serializedPlan;
					Message::extractToStringView(args, serializedPlan);

					DeploymentPlan plan;
					BitseryEngine::deserialize(serializedPlan, plan);

					deploymentPlans.insert_or_assign(plan.config.deploymentID(), plan);
               applyReplicatedDeploymentPlanLiveState(plan);

					String containerBlob;
					Message::extractToStringView(args, containerBlob);

					if (containerBlob.size() > 0)
					{
						String storeFailure = {};
						if (ContainerStore::store(
							plan.config.deploymentID(),
							containerBlob,
							nullptr,
							nullptr,
							&plan.config.containerBlobSHA256,
							&plan.config.containerBlobBytes,
							&storeFailure) == false)
						{
							basics_log(
								"replicateDeployment blob store failed deploymentID=%llu reason=%s\n",
								(unsigned long long)plan.config.deploymentID(),
								(storeFailure.size() > 0 ? storeFailure.c_str() : "unknown"));
						}
					}
						// else this replication carried only metadata (e.g. no-op image reuse path)

						Message::construct(bv->wBuffer, BrainTopic::replicateDeployment, plan.config.deploymentID());
                  persistLocalRuntimeState();
					}

					break;
				}
			// we're done with this.... either it failed and we're erasing it... or we replaced it and fully transitioned to the new deployment
			case BrainTopic::cullDeployment:
			{
				// deploymentID(8)
				uint64_t deploymentID;
				Message::extractArg<ArgumentNature::fixed>(args, deploymentID);

					deploymentPlans.erase(deploymentID);
					ContainerStore::destroy(deploymentID);
               persistLocalRuntimeState();

					break;
				}
			case BrainTopic::reconcileState:
			{
				uint8_t *args = message->args;
				uint8_t *terminal = message->terminal();

				// check what they have and send back culls and replications

				bytell_hash_set<uint64_t> deploymentIDs;

				do
				{
					uint64_t deploymentID;
					Message::extractArg<ArgumentNature::fixed>(args, deploymentID);

					deploymentIDs.insert(deploymentID);

				} while (args < terminal);

				uint64_t before = bv->wBuffer.size();

				String serializedBrainConfig;
				BitseryEngine::serialize(serializedBrainConfig, brainConfig);
				Message::construct(bv->wBuffer, BrainTopic::replicateBrainConfig, serializedBrainConfig);

				ClusterTopology authoritativeTopology = {};
				if (loadOrPersistAuthoritativeClusterTopology(authoritativeTopology))
				{
					String serializedTopology;
					BitseryEngine::serialize(serializedTopology, authoritativeTopology);
					Message::construct(bv->wBuffer, BrainTopic::replicateClusterTopology, serializedTopology);
				}

				bool abortedDeploymentReplication = false;
				for (const auto& [deploymentID, deployment] : deployments)
				{
					if (deploymentIDs.contains(deploymentID))
					{
						deploymentIDs.erase(deploymentID);
					}
					else
					{
						String serializedPlan;
						BitseryEngine::serialize(serializedPlan, deployment->plan);
						if (queueBrainDeploymentReplicationFromStoreToPeer(
							bv,
							serializedPlan,
							deployment->plan.config.deploymentID(),
							deployment->plan.config.containerBlobBytes) == false)
						{
							abortedDeploymentReplication = true;
							break;
						}
					}
				}

				if (abortedDeploymentReplication)
				{
					break;
				}

				for (uint64_t deploymentID : deploymentIDs) // all of these are culls
				{
					Message::construct(bv->wBuffer, BrainTopic::cullDeployment, deploymentID);
				}
					for (const auto& [applicationName, applicationID] : reservedApplicationIDsByName)
					{
						Message::construct(bv->wBuffer, BrainTopic::replicateApplicationIDReservation, applicationID, applicationName);
					}
					for (const auto& [service, identity] : reservedApplicationServicesByID)
					{
						(void)service;
						String serializedIdentity;
						BitseryEngine::serialize(serializedIdentity, identity);
						Message::construct(bv->wBuffer, BrainTopic::replicateApplicationServiceReservation, serializedIdentity);
					}
					for (const auto& [applicationID, factory] : tlsVaultFactoriesByApp)
					{
						(void)applicationID;
						String serializedFactory;
						BitseryEngine::serialize(serializedFactory, factory);
						Message::construct(bv->wBuffer, BrainTopic::replicateTlsVaultFactory, serializedFactory);
					}
						for (const auto& [applicationID, set] : apiCredentialSetsByApp)
						{
							(void)applicationID;
							String serializedSet;
							BitseryEngine::serialize(serializedSet, set);
							Message::construct(bv->wBuffer, BrainTopic::replicateApiCredentialSet, serializedSet);
						}
                  {
                     String serializedRuntimeState;
                     refreshMasterAuthorityRuntimeStateFromLiveFields();
                     ProdigyMasterAuthorityRuntimeState replicatedRuntimeState = masterAuthorityRuntimeState;
                     replicatedRuntimeState.updateSelf = {};
                     BitseryEngine::serialize(serializedRuntimeState, replicatedRuntimeState);
                     Message::construct(bv->wBuffer, BrainTopic::replicateMasterAuthorityState, serializedRuntimeState);
                  }
                  {
                     Vector<ProdigyMetricSample> metricSamples;
                     metrics.exportSamples(metricSamples);
                     if (metricSamples.empty() == false)
                     {
                        String serializedMetricSamples;
                        BitseryEngine::serialize(serializedMetricSamples, metricSamples);
                        Message::construct(bv->wBuffer, BrainTopic::replicateMetricsSnapshot, serializedMetricSamples);
                     }
                  }

						if (bv->wBuffer.size() > before && peerSocketActive(bv))
						{
							Ring::queueSend(bv);
				}

				break;
			}
			case BrainTopic::registration:
			{
				uint8_t *args = message->args;

				// uuid(16) boottimens(8) version(8) existingMasterUUID(16)
				Message::extractArg<ArgumentNature::fixed>(args, bv->uuid);
				Message::extractArg<ArgumentNature::fixed>(args, bv->boottimens);
				Message::extractArg<ArgumentNature::fixed>(args, bv->version);
				Message::extractArg<ArgumentNature::fixed>(args, bv->existingMasterUUID);
				std::fprintf(stderr,
					"prodigy debug brain registration private4=%u uuid=%llu boottimens=%ld existingMasterUUID=%llu updateState=%u\n",
					bv->private4,
					(unsigned long long)bv->uuid,
					(long)bv->boottimens,
					(unsigned long long)bv->existingMasterUUID,
					unsigned(updateSelfState));
				std::fflush(stderr);
				if (updateSelfState == UpdateSelfState::waitingForFollowerReboots ||
					updateSelfState == UpdateSelfState::waitingForRelinquishEchos)
				{
					uint128_t peerKey = updateSelfPeerTrackingKey(bv);
					std::fprintf(stderr,
						"prodigy updateProdigy registration-recv private4=%u peerKey=%llu boottimens=%ld state=%u\n",
						bv->private4,
						(unsigned long long)peerKey,
						(long)bv->boottimens,
						unsigned(updateSelfState));
					std::fflush(stderr);
				}
				synchronizeBrainUUIDToMachine(bv);
				onUpdateSelfPeerRegistration(bv);

				if (weAreMaster && bv->existingMasterUUID == selfBrainUUID())
				{
					bool conflictingMasterClaims = false;
					for (BrainView *peer : brains)
					{
						if (peerEligibleForClusterQuorum(peer) == false) continue;
						if (peer->existingMasterUUID == 0) continue;
						if (peer->existingMasterUUID == selfBrainUUID()) continue;
						conflictingMasterClaims = true;
						break;
					}

					if (conflictingMasterClaims == false)
					{
						masterQuorumDegraded = false;
					}
				}

				// If we are currently master but a majority of peers consistently report a different
				// existing master, relinquish and follow that majority to avoid split-brain on heal.
					if (weAreMaster && bv->existingMasterUUID > 0 && bv->existingMasterUUID != selfBrainUUID())
					{
						uint32_t majority = uint32_t(nBrains / 2) + 1;
						bytell_hash_map<uint128_t, uint32_t> votesByMasterUUID;

						for (BrainView *peer : brains)
						{
							if (peerEligibleForClusterQuorum(peer) == false) continue;
							if (peerSocketActive(peer) == false) continue;
							if (peer->existingMasterUUID == 0) continue;
							if (peer->existingMasterUUID == selfBrainUUID()) continue;

							votesByMasterUUID[peer->existingMasterUUID] += 1;
						}

					uint128_t candidateMasterUUID = 0;
					uint32_t candidateVotes = 0;
					for (const auto& [uuid, votes] : votesByMasterUUID)
					{
						if (votes > candidateVotes)
						{
							candidateMasterUUID = uuid;
							candidateVotes = votes;
						}
					}

						BrainView *candidateMasterBrain = findBrainViewByUUID(candidateMasterUUID);

							bool candidateMasterActive = (candidateMasterBrain != nullptr &&
								candidateMasterBrain->quarantined == false &&
								peerSocketActive(candidateMasterBrain));
							bool connectedMajority = hasConnectedBrainMajority();
							bool overrideByMajority = (candidateMasterUUID > 0 &&
								candidateVotes >= majority &&
								candidateMasterActive &&
								connectedMajority);
							bool overrideByDegradedRejoin = (candidateMasterUUID > 0 &&
								candidateVotes > 0 &&
								candidateMasterActive &&
								connectedMajority &&
								masterQuorumDegraded);

						if (overrideByMajority || overrideByDegradedRejoin)
						{
							String oldMasterUUIDText = {};
							String newMasterUUIDText = {};
							oldMasterUUIDText.snprintf<"{itoa}"_ctv>(selfBrainUUID());
							newMasterUUIDText.snprintf<"{itoa}"_ctv>(candidateMasterUUID);
							basics_log("registration master override old=%s new=%s votes=%u majority=%u degraded=%d mode=%s\n",
								oldMasterUUIDText.c_str(),
								newMasterUUIDText.c_str(),
								candidateVotes,
								majority,
								int(masterQuorumDegraded),
								overrideByMajority ? "majority" : "degraded-rejoin");

							forfeitMasterStatus();
							resetMasterBrainAssignment();

						for (BrainView *peer : brains)
						{
							if (peer->uuid == candidateMasterUUID)
							{
								electBrainToMaster(peer);
								break;
							}
						}
						}
						else
						{
							// Reconciliation requires quorum-majority reports from currently active peers.
							// Never relinquish master from stale/degraded claims.
						}
					}

					if (noMasterYet && weAreMaster == false && pendingDesignatedMasterPeerKey > 0)
					{
						uint128_t registrationPeerKey = updateSelfPeerTrackingKey(bv);
						uint128_t selfPeerKey = updateSelfLocalPeerTrackingKey();
						if (selfPeerKey > 0 && pendingDesignatedMasterPeerKey == selfPeerKey)
						{
							String pendingPeerKeyText = {};
							pendingPeerKeyText.snprintf<"{itoa}"_ctv>(pendingDesignatedMasterPeerKey);
							basics_log("registration elect-self reason=pending-designated-master peerKey=%s\n",
								pendingPeerKeyText.c_str());
							selfElectAsMaster("registration:pending-designated-master");
						}
						else if (registrationPeerKey == pendingDesignatedMasterPeerKey && bv->quarantined == false)
						{
							electBrainToMaster(bv);
						}
					}

					if (noMasterYet && weAreMaster == false && bv->existingMasterUUID > 0 && bv->existingMasterUUID != selfBrainUUID())
					{
						uint128_t registrationPeerKey = updateSelfPeerTrackingKey(bv);
						if (pendingDesignatedMasterPeerKey > 0 && registrationPeerKey != pendingDesignatedMasterPeerKey)
						{
							String claimUUIDText = {};
							String pendingPeerKeyText = {};
							String fromUUIDText = {};
							claimUUIDText.snprintf<"{itoa}"_ctv>(bv->existingMasterUUID);
							pendingPeerKeyText.snprintf<"{itoa}"_ctv>(pendingDesignatedMasterPeerKey);
							fromUUIDText.snprintf<"{itoa}"_ctv>(bv->uuid);
							basics_log("registration deferring non-designated master claim claim=%s pendingPeerKey=%s from=%s\n",
								claimUUIDText.c_str(), pendingPeerKeyText.c_str(), fromUUIDText.c_str());
						}
						else
						{
							if (BrainView *peer = findBrainViewByUUID(bv->existingMasterUUID); peer != nullptr)
							{
								electBrainToMaster(peer);
							}
						}
					}

					if (noMasterYet)
					{
						if (pendingDesignatedMasterPeerKey == 0)
						{
							deriveMasterBrain();
						}
						else
						{
							String pendingPeerKeyText = {};
							String fromUUIDText = {};
							String claimUUIDText = {};
							pendingPeerKeyText.snprintf<"{itoa}"_ctv>(pendingDesignatedMasterPeerKey);
							fromUUIDText.snprintf<"{itoa}"_ctv>(bv->uuid);
							claimUUIDText.snprintf<"{itoa}"_ctv>(bv->existingMasterUUID);
							basics_log("registration waiting designated master peerKey=%s from=%s claim=%s\n",
								pendingPeerKeyText.c_str(), fromUUIDText.c_str(), claimUUIDText.c_str());
						}

						if (!noMasterYet && !weAreMaster) // aka we just now have a master and it's not us
						{
							for (BrainView *bv : brains)
							{
								if (bv->isMasterBrain)
								{
									// send the deployments we have
									// the master will respond with any to cull and any we don't have yet

									uint32_t headerOffset = Message::appendHeader(bv->wBuffer, BrainTopic::reconcileState);

									for (const auto& [deploymentID, plan] : deploymentPlans)
									{
										Message::append(bv->wBuffer, plan.config.deploymentID());
									}

									Message::finish(bv->wBuffer, headerOffset);
								}
							}
						}
					}

					// late-join reconciliation: if we are master and peer has an older bundle, push and transition it now
					if (!noMasterYet && weAreMaster && bv->version < version)
					{
						if (peerSocketActive(bv))
						{
							bv->wBuffer.reserve(bv->wBuffer.size() + 512_KB);
							String prodigyBundlePath = {};
							prodigyResolveInstalledBundlePathForRoot("/root/prodigy"_ctv, prodigyBundlePath);
							uint32_t headerOffset = Message::appendHeader(bv->wBuffer, BrainTopic::updateBundle);
							Message::appendFile(bv->wBuffer, prodigyBundlePath);
							Message::finish(bv->wBuffer, headerOffset);
							Message::construct(bv->wBuffer, BrainTopic::transitionToNewBundle);
							Ring::queueSend(bv);
						}
					}

				break;
			}
         case BrainTopic::peerAddressCandidates:
         {
            String serialized;
            Message::extractToStringView(args, serialized);

            Vector<ClusterMachinePeerAddress> candidates;
            if (BitseryEngine::deserializeSafe(serialized, candidates))
            {
               (void)updateBrainPeerAddressCandidates(bv, candidates);
            }

            break;
         }
			case BrainTopic::masterMissing:
			{
					auto maybeDeriveOnMasterMissingAgreement = [&] () -> void
					{
						// Local vote must agree as well; then require currently reachable active peers.
						bool everyoneAgrees = isMasterMissing;
						uint32_t nBrainsAlive = 1;

						for (BrainView *peer : brains) // some might've been deleted from here because they connect to us
						{
							if (peerEligibleForClusterQuorum(peer) == false) continue;
							if (peerSocketActive(peer) == false) continue;
							nBrainsAlive += 1;
							if (peer->isMasterMissing == false) everyoneAgrees = false;
						}

					if (everyoneAgrees) deriveMasterBrainIf();
					basics_log("masterMissing agreement everyone=%d alive=%u local=%d\n", int(everyoneAgrees), nBrainsAlive, int(isMasterMissing));
				};

				if (message->isEcho()) // they're eliciting our state but also saying their state is true
				{
					bv->isMasterMissing = true;
					basics_log("masterMissing echo from=%u localIsMasterMissing=%d\n", bv->private4, int(isMasterMissing));
					bv->respondMasterMissing(isMasterMissing);
					maybeDeriveOnMasterMissingAgreement();
				}
				else
				{
					// they're sending their state
					// and we would only elicit if we thought the master was missing
					uint8_t *args = message->args;
					Message::extractArg<ArgumentNature::fixed>(args, bv->isMasterMissing);
					basics_log("masterMissing response from=%u value=%d\n", bv->private4, int(bv->isMasterMissing));
					maybeDeriveOnMasterMissingAgreement();
				}

				break;
			}
			case BrainTopic::updateBundle:
			{
				if (message->isEcho())
				{
					onUpdateSelfBundleEcho(bv);
				}
				else
				{
					// bundleBlob{4}

					String newBundle;
					Message::extractToStringView(args, newBundle);

					if (newBundle == "__staged__"_ctv && devSharedStagedBundleEnabled())
					{
						std::fprintf(stderr, "prodigy updateProdigy bundle-staged-recv from=%u\n", bv->private4);
						std::fflush(stderr);
					}
					else
					{
						std::fprintf(stderr, "prodigy updateProdigy bundle-recv from=%u bytes=%u\n", bv->private4, uint32_t(newBundle.size()));
						std::fflush(stderr);
						Filesystem::openWriteAtClose(-1, prodigyStagedBundlePath(), newBundle);
					}

					if (peerSocketActive(bv))
					{
						Message::construct(bv->wBuffer, BrainTopic::updateBundle); // this signals that we got the message
						Ring::queueSend(bv);
					}
				}

				break;
			}
			case BrainTopic::transitionToNewBundle:
			{
				std::fprintf(stderr,
					"prodigy updateProdigy transition-recv private4=%u master=%d\n",
					thisNeuron->private4.v4,
					int(weAreMaster));
				std::fflush(stderr);
				if (weAreMaster == false)
				{
					transitionToNewBundle();
				}

				break;
			}
				case BrainTopic::relinquishMasterStatus:
				{
					if (message->isEcho())
					{
						onUpdateSelfRelinquishEcho(bv);
					}
					else
					{
						uint8_t commandMarker = 0;
						uint128_t designatedMasterPeerKey = 0;
						if (args < message->terminal())
						{
							Message::extractArg<ArgumentNature::fixed>(args, commandMarker);
							(void)commandMarker;
						}
						if ((args + sizeof(uint128_t)) <= message->terminal())
						{
							Message::extractArg<ArgumentNature::fixed>(args, designatedMasterPeerKey);
						}

						resetMasterBrainAssignment();
						pendingDesignatedMasterPeerKey = designatedMasterPeerKey;
						{
							String designatedPeerKeyText = {};
							designatedPeerKeyText.snprintf<"{itoa}"_ctv>(designatedMasterPeerKey);
							basics_log("relinquishMasterStatus designatedMasterPeerKey=%s\n",
								designatedPeerKeyText.c_str());
						}

						bool electedDesignatedMaster = false;
						bool designatedMasterKnown = false;
						uint128_t selfPeerKey = updateSelfLocalPeerTrackingKey();
						if (designatedMasterPeerKey > 0 && designatedMasterPeerKey == selfPeerKey)
						{
							designatedMasterKnown = true;
							basics_log("relinquishMasterStatus elect-self reason=designated-master\n");
							selfElectAsMaster("relinquishMasterStatus:designated-master");
							electedDesignatedMaster = true;
						}
						else if (designatedMasterPeerKey > 0)
						{
							if (BrainView *peer = findBrainViewByUpdateSelfPeerKey(designatedMasterPeerKey); peer != nullptr)
							{
								designatedMasterKnown = true;
								if (peer->quarantined == false)
								{
									electBrainToMaster(peer);
									electedDesignatedMaster = true;
								}
							}
						}

						if (electedDesignatedMaster == false)
						{
							if (designatedMasterPeerKey > 0 && designatedMasterKnown)
							{
								String designatedPeerKeyText = {};
								designatedPeerKeyText.snprintf<"{itoa}"_ctv>(designatedMasterPeerKey);
								basics_log("relinquishMasterStatus waiting designated peerKey=%s (currently unavailable)\n",
									designatedPeerKeyText.c_str());
							}
							else
							{
								pendingDesignatedMasterPeerKey = 0;
								deriveMasterBrain();
							}
						}

						if (peerSocketActive(bv))
						{
							Message::construct(bv->wBuffer, BrainTopic::relinquishMasterStatus);
							Ring::queueSend(bv);
						}

                  noteMasterAuthorityRuntimeStateChanged(false, true);
					}

				break;
			}
			case BrainTopic::replicateBrainConfig:
			{
				// config{4}

				String serialized;
				Message::extractToStringView(args, serialized);

					BrainConfig deserializedConfig = {};
					if (BitseryEngine::deserializeSafe(serialized, deserializedConfig) == false)
					{
						break;
					}

               BrainConfig incomingConfig = {};
               ownBrainConfig(deserializedConfig, incomingConfig);

					String ownershipFailure = {};
					if (claimLocalClusterOwnership(incomingConfig.clusterUUID, &ownershipFailure) == false)
					{
						basics_log("replicateBrainConfig reject clusterUUID=%llu reason=%s\n",
							(unsigned long long)incomingConfig.clusterUUID,
							ownershipFailure.c_str());
						break;
					}

					brainConfig = incomingConfig;

						loadBrainConfigIf();
						if (noMasterYet)
						{
							// Configure distributes state only; do not force master selection from mothership.
							deriveMasterBrain();
						}

                  persistLocalRuntimeState();

						break;
					}
			case BrainTopic::replicateClusterTopology:
			{
				String serialized;
				Message::extractToStringView(args, serialized);

				ClusterTopology incomingTopology = {};
				if (BitseryEngine::deserializeSafe(serialized, incomingTopology) == false)
				{
					break;
				}

            prodigyStripMachineHardwareCapturesFromClusterTopology(incomingTopology);

				ClusterTopology existingTopology = {};
				if (loadAuthoritativeClusterTopology(existingTopology)
					&& existingTopology.machines.empty() == false
					&& existingTopology.version >= incomingTopology.version)
				{
					break;
				}

				restoreBrainsFromClusterTopology(incomingTopology);
				restoreMachinesFromClusterTopology(incomingTopology);
				nBrains = clusterTopologyBrainCount(incomingTopology);
				initializeAllBrainPeersIfNeeded();
				persistAuthoritativeClusterTopology(incomingTopology);
				break;
			}
				case BrainTopic::replicateApplicationIDReservation:
				{
					// applicationID(2) applicationName{4}
					uint16_t applicationID = 0;
				Message::extractArg<ArgumentNature::fixed>(args, applicationID);

				String applicationName;
				Message::extractToString(args, applicationName);

				String reserveFailure;
					if (reserveApplicationIDMapping(applicationName, applicationID, &reserveFailure) == false)
					{
						basics_log("replicateApplicationIDReservation reject appID=%u name=%s reason=%s\n",
							unsigned(applicationID),
							applicationName.c_str(),
							reserveFailure.c_str());
					}
               else
               {
                  persistLocalRuntimeState();
               }

					break;
				}
				case BrainTopic::replicateApplicationServiceReservation:
				{
					// identity{4}
					String serializedIdentity;
					Message::extractToStringView(args, serializedIdentity);

					ApplicationServiceIdentity identity;
					if (BitseryEngine::deserializeSafe(serializedIdentity, identity) == false)
					{
						break;
					}

					String reserveFailure;
						if (reserveApplicationServiceMapping(identity, &reserveFailure) == false)
						{
							basics_log("replicateApplicationServiceReservation reject appID=%u service=%s reason=%s\n",
								unsigned(identity.applicationID),
								identity.serviceName.c_str(),
								reserveFailure.c_str());
						}
	               else
	               {
	                  persistLocalRuntimeState();
	               }

						break;
					}
				case BrainTopic::replicateTlsVaultFactory:
				{
					// factory{4}
					String serializedFactory;
					Message::extractToStringView(args, serializedFactory);

					ApplicationTlsVaultFactory incoming;
					if (BitseryEngine::deserializeSafe(serializedFactory, incoming) == false)
					{
						break;
					}

					const ApplicationTlsVaultFactory *existing = nullptr;
					if (auto it = tlsVaultFactoriesByApp.find(incoming.applicationID); it != tlsVaultFactoriesByApp.end())
					{
						existing = &it->second;
					}

						if (shouldAcceptTlsFactoryReplication(incoming, existing))
						{
                     String validationFailure;
                     if (validateApplicationTlsVaultFactoryMaterial(incoming, &validationFailure))
                     {
								tlsVaultFactoriesByApp.insert_or_assign(incoming.applicationID, incoming);
                        persistLocalRuntimeState();
                     }
                     else
                     {
                        basics_log("replicateTlsVaultFactory reject appID=%u reason=%s\n",
                           unsigned(incoming.applicationID),
                           validationFailure.c_str());
                     }
						}

						break;
					}
				case BrainTopic::replicateApiCredentialSet:
				{
					// set{4}
					String serializedSet;
					Message::extractToStringView(args, serializedSet);

					ApplicationApiCredentialSet incoming;
					if (BitseryEngine::deserializeSafe(serializedSet, incoming) == false)
					{
						break;
					}

					const ApplicationApiCredentialSet *existing = nullptr;
					if (auto it = apiCredentialSetsByApp.find(incoming.applicationID); it != apiCredentialSetsByApp.end())
					{
						existing = &it->second;
					}

						if (shouldAcceptApiCredentialSetReplication(incoming, existing))
						{
							apiCredentialSetsByApp.insert_or_assign(incoming.applicationID, incoming);
                     persistLocalRuntimeState();
						}

						break;
					}
            case BrainTopic::replicateMasterAuthorityState:
            {
               String serialized;
               Message::extractToStringView(args, serialized);

               ProdigyMasterAuthorityRuntimeState incoming = {};
               if (BitseryEngine::deserializeSafe(serialized, incoming))
               {
                  (void)applyReplicatedMasterAuthorityRuntimeState(incoming, true);
               }

               break;
            }
					default: break;
				}
			}

	void spinApplication(ApplicationDeployment *deployment)
	{
		if (deployment != nullptr && prodigyDebugDeployHeapEnabled())
		{
			const ProdigyDeployHeapMetrics heap = prodigyReadDeployHeapMetrics();
			std::fprintf(stderr,
				"prodigy debug spinApplication-begin deploymentID=%llu appID=%u stateful=%d deployments=%zu apps=%zu brains=%zu heapUsed=%llu heapMapped=%llu heapFree=%llu\n",
				(unsigned long long)deployment->plan.config.deploymentID(),
				unsigned(deployment->plan.config.applicationID),
				int(deployment->plan.isStateful),
				size_t(deployments.size()),
				size_t(deploymentsByApp.size()),
				size_t(brains.size()) + 1,
				(unsigned long long)heap.used,
				(unsigned long long)heap.mapped,
				(unsigned long long)heap.free);
			std::fflush(stderr);
		}

		ApplicationDeployment *previous = nullptr;

		if (auto it = deploymentsByApp.find(deployment->plan.config.applicationID); it != deploymentsByApp.end())
		{
			previous = it->second;
		}

		deploymentsByApp.insert_or_assign(deployment->plan.config.applicationID, deployment);
		deployments.insert_or_assign(deployment->plan.config.deploymentID(), deployment);

		if (previous == nullptr)
		{
			deployment->deploy();
		}
		else
		{
			switch (previous->state)
			{
				case DeploymentState::none:  // they rapid fire sent another before we could begin work on this
				case DeploymentState::waitingToDeploy:

				{
					// previous->previous can never be nullptr when DeploymentState::none
					deployment->previous = previous->previous;
					previous->previous->next = deployment;

					delete previous;

					break;
				}
				case DeploymentState::canaries:
				case DeploymentState::deploying:
				{
					// still transitioning from n-2 deployment to n-1 deployment
					// once it finishes deploying, it will automatically transition
					// to this new one

					previous->next = deployment;
					deployment->previous = previous;

					deployment->state = DeploymentState::waitingToDeploy;

					// first of all we should NEVER be doing this... but if it ever did happen let's just gracefully
					// let each deployment complete then move forward

					// if we let it run to completion we're just going to destroy them all anyway.... but it's possible
					// if we stopped a stateful transition... that we'd have some n-2 and some n-1 and that is wouldn't be
					// possible to spin our entire n cluster from this disjoint basis

					break;
				}
				case DeploymentState::running:
				{
					previous->next = deployment;
					deployment->previous = previous;

					if (previous->nSuspended > 0) // they're in the middle of processing something... wait and they'll deploy us after
					{
						deployment->state = DeploymentState::waitingToDeploy;
					}
					else
					{
						previous->rollForward();
					}

					break;
				}
				case DeploymentState::failed:
				{
					// this happens if canaries fail....
					// otherwise should never happen?

					if (previous->previous) deployment->previous = previous->previous;


					// just delete this for now but maybe in the future we'd want to store failed results?
					delete previous;
					deployment->deploy();

					break;
				}
				case DeploymentState::decommissioning: break; // not possible

			}
		}

      persistLocalRuntimeState();

		if (deployment != nullptr && prodigyDebugDeployHeapEnabled())
		{
			const ProdigyDeployHeapMetrics heap = prodigyReadDeployHeapMetrics();
			std::fprintf(stderr,
				"prodigy debug spinApplication-end deploymentID=%llu appID=%u state=%u deployments=%zu apps=%zu heapUsed=%llu heapMapped=%llu heapFree=%llu\n",
				(unsigned long long)deployment->plan.config.deploymentID(),
				unsigned(deployment->plan.config.applicationID),
				unsigned(deployment->state),
				size_t(deployments.size()),
				size_t(deploymentsByApp.size()),
				(unsigned long long)heap.used,
				(unsigned long long)heap.mapped,
				(unsigned long long)heap.free);
			std::fflush(stderr);
		}
	}

	void respinApplication(ApplicationDeployment *deployment) override
	{
		if (deployment == nullptr)
		{
			return;
		}

		String serializedPlan;
		BitseryEngine::serialize(serializedPlan, deployment->plan);

		if (nBrains > 1)
		{
			queueBrainDeploymentReplication(serializedPlan, ""_ctv);

			String containerBlob;
			ContainerStore::get(deployment->plan.config.deploymentID(), containerBlob);

			if (containerBlob.size() > 0)
			{
				queueBrainDeploymentReplication(serializedPlan, containerBlob);
			}
		}

		// Apply the respin locally on the active master; replication keeps followers in sync.
		spinApplication(deployment);
	}

	void pushSpinApplicationProgressToMothership(ApplicationDeployment *deployment, StringType auto&& message)
	{
      Mothership *stream = spinApplicationMothershipFor(deployment);
		if (stream != nullptr)
		{
			Message::construct(
				stream->wBuffer,
				MothershipTopic::spinApplication,
				uint8_t(SpinApplicationResponseCode::progress),
				message);
			(void)flushActiveMothershipSendBuffer(stream, "spin-application-progress");
		}
	}

	void spinApplicationFailed(ApplicationDeployment *deployment, StringType auto&& message)
	{
      Mothership *stream = spinApplicationMothershipFor(deployment);
		if (stream != nullptr)
		{
			Message::construct(
				stream->wBuffer,
				MothershipTopic::spinApplication,
				uint8_t(SpinApplicationResponseCode::failed),
				message);
			(void)flushActiveMothershipSendBuffer(stream, "spin-application-failed");
		}

      clearSpinApplicationMothership(deployment);
	}

	void spinApplicationFin(ApplicationDeployment *deployment) override
	{
      Mothership *stream = spinApplicationMothershipFor(deployment);
		if (stream != nullptr)
		{
			Message::construct(
				stream->wBuffer,
				MothershipTopic::spinApplication,
				uint8_t(SpinApplicationResponseCode::finished));
			(void)flushActiveMothershipSendBuffer(stream, "spin-application-fin");
		}

      clearSpinApplicationMothership(deployment);
	}

	class ManagedAddMachinesWork {
	public:

		ManagedAddMachinesWork() : requiredBrainCount(0) {}

		Vector<CreateMachinesInstruction> createdMachines;
		uint32_t requiredBrainCount;

		bool empty(void) const
		{
			return createdMachines.empty() && requiredBrainCount == 0;
		}
	};

	static bool managedMachineSchemaMatchesClusterMachine(const ClusterMachine& machine, const ProdigyManagedMachineSchema& managedSchema)
	{
		return machine.source == ClusterMachineSource::created
			&& machine.backing == ClusterMachineBacking::cloud
			&& machine.cloudPresent()
			&& machine.lifetime == managedSchema.lifetime
			&& machine.cloud.schema.equals(managedSchema.schema)
			&& machine.cloud.providerMachineType.equals(managedSchema.providerMachineType);
	}

	static bool managedCreatedClusterMachineRemovalPriority(const ClusterMachine *lhs, const ClusterMachine *rhs)
	{
		if ((lhs->isBrain == false) != (rhs->isBrain == false))
		{
			return lhs->isBrain == false;
		}

		if (lhs->creationTimeMs != rhs->creationTimeMs)
		{
			return lhs->creationTimeMs > rhs->creationTimeMs;
		}

		return std::lexicographical_compare(
			lhs->cloud.schema.data(),
			lhs->cloud.schema.data() + lhs->cloud.schema.size(),
			rhs->cloud.schema.data(),
			rhs->cloud.schema.data() + rhs->cloud.schema.size());
	}

	bool buildManagedMachineSchemaRequest(const ClusterTopology& topology, AddMachines& request, ManagedAddMachinesWork& work, String *failure = nullptr)
	{
		request = {};
		work = ManagedAddMachinesWork();
		if (failure) failure->clear();

		request.clusterUUID = brainConfig.clusterUUID;
		request.architecture = brainConfig.architecture;
		request.bootstrapSshUser = brainConfig.bootstrapSshUser;
		request.bootstrapSshKeyPackage = brainConfig.bootstrapSshKeyPackage;
		request.bootstrapSshHostKeyPackage = brainConfig.bootstrapSshHostKeyPackage;
		request.bootstrapSshPrivateKeyPath = brainConfig.bootstrapSshPrivateKeyPath;
		request.remoteProdigyPath = brainConfig.remoteProdigyPath;
		request.controlSocketPath = brainConfig.controlSocketPath;
		work.requiredBrainCount = brainConfig.requiredBrainCount;

		auto removedMachineAlreadyCounted = [&] (const ClusterMachine& machine) -> bool {
			for (const ClusterMachine& removedMachine : request.removedMachines)
			{
				if (removedMachine.sameIdentityAs(machine))
				{
					return true;
				}
			}

			return false;
		};

		for (const ClusterMachine& existingMachine : topology.machines)
		{
			if (existingMachine.source != ClusterMachineSource::created)
			{
				continue;
			}

			bool wanted = false;
			for (const ProdigyManagedMachineSchema& managedSchema : masterAuthorityRuntimeState.machineSchemas)
			{
				if (managedMachineSchemaMatchesClusterMachine(existingMachine, managedSchema))
				{
					wanted = true;
					break;
				}
			}

			if (wanted == false)
			{
				request.removedMachines.push_back(existingMachine);
			}
		}

		for (const ProdigyManagedMachineSchema& managedSchema : masterAuthorityRuntimeState.machineSchemas)
		{
			Vector<const ClusterMachine *> matches = {};
			for (const ClusterMachine& existingMachine : topology.machines)
			{
				if (removedMachineAlreadyCounted(existingMachine))
				{
					continue;
				}

				if (managedMachineSchemaMatchesClusterMachine(existingMachine, managedSchema))
				{
					matches.push_back(&existingMachine);
				}
			}

			if (matches.size() <= managedSchema.budget)
			{
				continue;
			}

			std::sort(matches.begin(), matches.end(), managedCreatedClusterMachineRemovalPriority);
			uint32_t nRemove = uint32_t(matches.size()) - managedSchema.budget;
			for (uint32_t index = 0; index < nRemove; ++index)
			{
				request.removedMachines.push_back(*matches[index]);
			}
		}

		uint32_t finalBrainCount = clusterTopologyBrainCount(topology);
		for (const ClusterMachine& removedMachine : request.removedMachines)
		{
			if (removedMachine.isBrain)
			{
				finalBrainCount -= 1;
			}
		}

		uint32_t remainingBrains = (brainConfig.requiredBrainCount > finalBrainCount)
			? (brainConfig.requiredBrainCount - finalBrainCount)
			: 0;

		if (remainingBrains > 0)
		{
			uint32_t brainsNeedingSlots = remainingBrains;
			for (const ProdigyManagedMachineSchema& managedSchema : masterAuthorityRuntimeState.machineSchemas)
			{
				uint32_t existingCount = 0;
				Vector<const ClusterMachine *> replaceableMachines = {};
				for (const ClusterMachine& existingMachine : topology.machines)
				{
					if (removedMachineAlreadyCounted(existingMachine))
					{
						continue;
					}

					if (managedMachineSchemaMatchesClusterMachine(existingMachine, managedSchema) == false)
					{
						continue;
					}

					existingCount += 1;
					if (existingMachine.isBrain == false)
					{
						replaceableMachines.push_back(&existingMachine);
					}
				}

				uint32_t freeSlots = (managedSchema.budget > existingCount)
					? (managedSchema.budget - existingCount)
					: 0;

				if (brainsNeedingSlots <= freeSlots)
				{
					brainsNeedingSlots = 0;
					break;
				}

				brainsNeedingSlots -= freeSlots;
				if (replaceableMachines.empty())
				{
					continue;
				}

				std::sort(replaceableMachines.begin(), replaceableMachines.end(), managedCreatedClusterMachineRemovalPriority);
				uint32_t nReplace = std::min<uint32_t>(uint32_t(replaceableMachines.size()), brainsNeedingSlots);
				for (uint32_t index = 0; index < nReplace; ++index)
				{
					request.removedMachines.push_back(*replaceableMachines[index]);
				}

				brainsNeedingSlots -= nReplace;
				if (brainsNeedingSlots == 0)
				{
					break;
				}
			}
		}

		for (const ProdigyManagedMachineSchema& managedSchema : masterAuthorityRuntimeState.machineSchemas)
		{
			uint32_t existingCount = 0;
			for (const ClusterMachine& existingMachine : topology.machines)
			{
				if (removedMachineAlreadyCounted(existingMachine))
				{
					continue;
				}

				if (managedMachineSchemaMatchesClusterMachine(existingMachine, managedSchema))
				{
					existingCount += 1;
				}
			}

			if (existingCount >= managedSchema.budget)
			{
				continue;
			}

			uint32_t createCount = managedSchema.budget - existingCount;
			if (createCount == 0)
			{
				continue;
			}

			auto appendInstruction = [&] (uint32_t instructionCount, bool isBrainMachine) -> void {

				if (instructionCount == 0)
				{
					return;
				}

				CreateMachinesInstruction instruction = {};
				instruction.kind = managedSchema.kind;
				instruction.lifetime = managedSchema.lifetime;
				instruction.backing = ClusterMachineBacking::cloud;
				instruction.cloud.schema = managedSchema.schema;
				instruction.cloud.providerMachineType = managedSchema.providerMachineType;
				instruction.count = instructionCount;
				instruction.isBrain = isBrainMachine;
				instruction.region = managedSchema.region;
				instruction.zone = managedSchema.zone;
				work.createdMachines.push_back(std::move(instruction));
			};

			uint32_t brainCreateCount = std::min(createCount, remainingBrains);
			appendInstruction(brainCreateCount, true);
			appendInstruction(createCount - brainCreateCount, false);
			remainingBrains -= brainCreateCount;
		}

		if (remainingBrains > 0)
		{
			if (failure) failure->assign("cluster machineSchemas cannot satisfy nBrains");
			request = {};
			work = ManagedAddMachinesWork();
			return false;
		}

		return true;
	}

		bool reconcileManagedMachineSchemas(
         String *failure = nullptr,
         ProdigyTimingAttribution *timingAttribution = nullptr,
         ClusterTopology *reconciledTopology = nullptr)
			{
				if (failure) failure->clear();
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
         if (timingAttribution != nullptr)
         {
            *timingAttribution = {};
         }
#else
         (void)timingAttribution;
#endif
         auto loadReconciledTopologyOutput = [&] (const String& topologyFailure) -> bool {

            if (reconciledTopology == nullptr)
            {
               return true;
            }

            *reconciledTopology = {};
            if (loadOrPersistAuthoritativeClusterTopology(*reconciledTopology))
            {
               return true;
            }

            if (failure)
            {
               failure->assign(topologyFailure);
            }

            return false;
         };

         std::fprintf(stderr, "prodigy managedSchemas-reconcile-begin master=%d schemas=%u\n",
            int(weAreMaster),
            uint32_t(masterAuthorityRuntimeState.machineSchemas.size()));
         std::fflush(stderr);
				if (weAreMaster == false)
				{
					return loadReconciledTopologyOutput("authoritative cluster topology unavailable after machine schema reconcile"_ctv);
				}

				if (masterAuthorityRuntimeState.machineSchemas.empty())
				{
					return loadReconciledTopologyOutput("authoritative cluster topology unavailable after machine schema reconcile"_ctv);
				}

			ClusterTopology currentTopology = {};
			if (loadOrPersistAuthoritativeClusterTopology(currentTopology) == false)
			{
				if (failure) failure->assign("authoritative cluster topology unavailable"_ctv);
			return false;
		}

		AddMachines request = {};
		ManagedAddMachinesWork work = ManagedAddMachinesWork();
		if (buildManagedMachineSchemaRequest(currentTopology, request, work, failure) == false)
		{
			return false;
		}

      std::fprintf(stderr, "prodigy managedSchemas-reconcile-built adopted=%u ready=%u removed=%u created=%u requiredBrains=%u topologyMachines=%u\n",
         uint32_t(request.adoptedMachines.size()),
         uint32_t(request.readyMachines.size()),
         uint32_t(request.removedMachines.size()),
         uint32_t(work.createdMachines.size()),
         unsigned(work.requiredBrainCount),
         uint32_t(currentTopology.machines.size()));
      std::fflush(stderr);

			if (work.createdMachines.empty() && request.removedMachines.empty())
			{
	         std::fprintf(stderr, "prodigy managedSchemas-reconcile-noop topologyMachines=%u\n",
	            uint32_t(currentTopology.machines.size()));
	         std::fflush(stderr);
            if (reconciledTopology != nullptr)
            {
               *reconciledTopology = currentTopology;
            }
				return true;
			}

		AddMachines response = {};
      std::fprintf(stderr, "prodigy managedSchemas-reconcile-dispatch created=%u removed=%u\n",
         uint32_t(work.createdMachines.size()),
         uint32_t(request.removedMachines.size()));
      std::fflush(stderr);
		addMachines(nullptr, std::move(request), std::move(work), &response);
      std::fprintf(stderr, "prodigy managedSchemas-reconcile-result success=%d failureBytes=%zu hasTopology=%d topologyMachines=%u\n",
         int(response.success),
         size_t(response.failure.size()),
         int(response.hasTopology),
         (response.hasTopology ? uint32_t(response.topology.machines.size()) : 0u));
      std::fflush(stderr);
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
      if (timingAttribution != nullptr && response.hasTimingAttribution)
      {
         *timingAttribution = response.timingAttribution;
      }
#endif
		if (response.success == false)
		{
			if (failure)
			{
				*failure = response.failure;
			}
			return false;
		}

      if (reconciledTopology != nullptr)
      {
         if (response.hasTopology)
         {
            *reconciledTopology = std::move(response.topology);
         }
         else
         {
            *reconciledTopology = std::move(currentTopology);
         }
      }

		return true;
	}

	void addMachines(Mothership *mothership, AddMachines request, ManagedAddMachinesWork managedWork = ManagedAddMachinesWork(), AddMachines *capturedResponse = nullptr)
	{
		AddMachines response = {};
		response.success = false;
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
      uint64_t addMachinesStartNs = Time::now<TimeResolution::ns>();
      uint64_t addMachinesProviderWaitNs = 0;
#endif
		std::fprintf(stderr, "prodigy mothership addMachines-begin adopted=%u ready=%u removed=%u created=%u requiredBrains=%u stream=%p fd=%d fslot=%d master=%d\n",
			uint32_t(request.adoptedMachines.size()),
         uint32_t(request.readyMachines.size()),
         uint32_t(request.removedMachines.size()),
			uint32_t(managedWork.createdMachines.size()),
         unsigned(managedWork.requiredBrainCount),
			static_cast<void *>(mothership),
			(mothership ? mothership->fd : -1),
			(mothership ? mothership->fslot : -1),
			int(weAreMaster));
		std::fflush(stderr);

		const bool readOnlyTopologyRequest = request.adoptedMachines.empty() && request.readyMachines.empty() && request.removedMachines.empty() && managedWork.createdMachines.empty();
		ClusterTopology currentTopology = {};
		if (mothership != nullptr && managedWork.empty() == false)
		{
			response.failure.assign("addMachines only supports adopted/ready/removed machines"_ctv);
		}
		else if (loadOrPersistAuthoritativeClusterTopology(currentTopology) == false)
		{
			response.failure.assign("authoritative cluster topology unavailable"_ctv);
		}
		else
		{
			ClusterTopology targetTopology = currentTopology;
			uint32_t addedBrainCount = 0;
         uint64_t pendingAddMachinesOperationID = 0;
			Vector<ClusterMachine> machinesToBootstrap;
			Vector<ClusterMachine> startedMachines;
         Vector<ClusterMachine> streamedBootstrapQueuedMachines;
			std::vector<Machine *> createdProvisionedSnapshots;
         Vector<ClusterMachine> removedMachinesToDecommission;
         bool requireSynchronousBootstrap = (capturedResponse != nullptr && mothership == nullptr);
         bool bootstrapCanSuspend = (canSuspendRemoteBootstrap() && requireSynchronousBootstrap == false);
         bool incrementalCreatedBootstrapUsesBlocking = requireSynchronousBootstrap && iaas->supportsIncrementalProvisioningCallbacks();
         bool incrementalCreatedBootstrapUsesCoordinator = bootstrapCanSuspend && iaas->supportsIncrementalProvisioningCallbacks();
         bool incrementalCreatedBootstrapSupported = incrementalCreatedBootstrapUsesBlocking || incrementalCreatedBootstrapUsesCoordinator;
         ProdigyRemoteBootstrapCoordinator bootstrapCoordinator = {};
         ProdigyRemoteBootstrapBundleApprovalCache bootstrapBundleApprovalCache = {};
         std::fprintf(stderr, "prodigy mothership addMachines-bootstrap-mode sync=%d canSuspend=%d providerIncremental=%d blocking=%d coordinator=%d supported=%d capturedResponse=%p\n",
            int(requireSynchronousBootstrap),
            int(bootstrapCanSuspend),
            int(iaas->supportsIncrementalProvisioningCallbacks()),
            int(incrementalCreatedBootstrapUsesBlocking),
            int(incrementalCreatedBootstrapUsesCoordinator),
            int(incrementalCreatedBootstrapSupported),
            static_cast<void *>(capturedResponse));
         std::fflush(stderr);

			auto cleanupProvisionedSnapshots = [&] (bool destroyProviderMachines) -> void {

				for (Machine *snapshot : createdProvisionedSnapshots)
				{
					if (destroyProviderMachines)
					{
						iaas->destroyMachine(snapshot);
					}

					prodigyDestroyMachineSnapshot(snapshot);
				}

				createdProvisionedSnapshots.clear();
			};

         auto startedBootstrapContainsMachine = [&] (const ClusterMachine& machine) -> bool {

            return prodigyFindClusterMachineByIdentity(startedMachines, machine) != nullptr;
         };

         auto bootstrapQueueContainsMachine = [&] (const ClusterMachine& machine) -> bool {

            return prodigyFindClusterMachineByIdentity(machinesToBootstrap, machine) != nullptr;
         };

         auto streamedBootstrapQueueContainsMachine = [&] (const ClusterMachine& machine) -> bool {

            return prodigyFindClusterMachineByIdentity(streamedBootstrapQueuedMachines, machine) != nullptr;
         };

         class AddMachinesProvisioningProgressSink final : public BrainIaaSMachineProvisioningProgressSink
         {
         private:

            Brain *owner = nullptr;
            Mothership *mothership = nullptr;
            const AddMachines *request = nullptr;
            const CreateMachinesInstruction *instruction = nullptr;
            const MachineConfig *machineConfig = nullptr;
            ClusterTopology *targetTopology = nullptr;
            Vector<ClusterMachine> *machinesToBootstrap = nullptr;
            Vector<ClusterMachine> *startedMachines = nullptr;
            Vector<ClusterMachine> *streamedBootstrapQueuedMachines = nullptr;
            uint32_t *addedBrainCount = nullptr;
            uint64_t *pendingOperationID = nullptr;
            ProdigyRemoteBootstrapCoordinator *bootstrapCoordinator = nullptr;
            ProdigyRemoteBootstrapBundleApprovalCache *bootstrapBundleApprovalCache = nullptr;
            String *failure = nullptr;
            bool incrementalCreatedBootstrapBlocking = false;
            bool incrementalCreatedBootstrapCoordinator = false;

         public:

            AddMachinesProvisioningProgressSink(Brain *brain, Mothership *stream) : owner(brain), mothership(stream) {}

            void configureIncrementalCreatedBootstrap(
               const AddMachines *activeRequest,
               const CreateMachinesInstruction *activeInstruction,
               const MachineConfig *activeMachineConfig,
               ClusterTopology *activeTargetTopology,
               Vector<ClusterMachine> *activeMachinesToBootstrap,
               Vector<ClusterMachine> *activeStartedMachines,
               Vector<ClusterMachine> *activeStreamedBootstrapQueuedMachines,
               uint32_t *activeAddedBrainCount,
               uint64_t *activePendingOperationID,
               ProdigyRemoteBootstrapCoordinator *activeBootstrapCoordinator,
               ProdigyRemoteBootstrapBundleApprovalCache *activeBootstrapBundleApprovalCache,
               String *activeFailure,
               bool blockingEnabled,
               bool coordinatorEnabled)
            {
               request = activeRequest;
               instruction = activeInstruction;
               machineConfig = activeMachineConfig;
               targetTopology = activeTargetTopology;
               machinesToBootstrap = activeMachinesToBootstrap;
               startedMachines = activeStartedMachines;
               streamedBootstrapQueuedMachines = activeStreamedBootstrapQueuedMachines;
               addedBrainCount = activeAddedBrainCount;
               pendingOperationID = activePendingOperationID;
               bootstrapCoordinator = activeBootstrapCoordinator;
               bootstrapBundleApprovalCache = activeBootstrapBundleApprovalCache;
               failure = activeFailure;
               incrementalCreatedBootstrapBlocking = blockingEnabled;
               incrementalCreatedBootstrapCoordinator = coordinatorEnabled;
            }

            void clearIncrementalCreatedBootstrap(void)
            {
               request = nullptr;
               instruction = nullptr;
               machineConfig = nullptr;
               targetTopology = nullptr;
               machinesToBootstrap = nullptr;
               startedMachines = nullptr;
               streamedBootstrapQueuedMachines = nullptr;
               addedBrainCount = nullptr;
               pendingOperationID = nullptr;
               bootstrapCoordinator = nullptr;
               bootstrapBundleApprovalCache = nullptr;
               failure = nullptr;
               incrementalCreatedBootstrapBlocking = false;
               incrementalCreatedBootstrapCoordinator = false;
            }

            void reportMachineProvisioningAccepted(const String& cloudID) override
            {
               if ((incrementalCreatedBootstrapBlocking == false && incrementalCreatedBootstrapCoordinator == false)
                  || owner == nullptr
                  || request == nullptr
                  || instruction == nullptr
                  || machineConfig == nullptr
                  || targetTopology == nullptr
                  || pendingOperationID == nullptr
                  || *pendingOperationID == 0
                  || failure == nullptr
                  || failure->size() > 0
                  || cloudID.size() == 0)
               {
#if PRODIGY_DEBUG
                  basics_log("addMachines incremental accepted-skip cloudID=%.*s blocking=%d coordinator=%d owner=%p request=%p instruction=%p machineConfig=%p targetTopology=%p pendingOpPtr=%p pendingOp=%llu failureBytes=%llu\n",
                     int(cloudID.size()),
                     reinterpret_cast<const char *>(cloudID.data()),
                     int(incrementalCreatedBootstrapBlocking),
                     int(incrementalCreatedBootstrapCoordinator),
                     static_cast<void *>(owner),
                     static_cast<const void *>(request),
                     static_cast<const void *>(instruction),
                     static_cast<const void *>(machineConfig),
                     static_cast<void *>(targetTopology),
                     static_cast<void *>(pendingOperationID),
                     (unsigned long long)((pendingOperationID != nullptr) ? *pendingOperationID : 0ULL),
                     (unsigned long long)(failure != nullptr ? failure->size() : 0ULL));
#endif
                  return;
               }

#if PRODIGY_DEBUG
               basics_log("addMachines incremental accepted cloudID=%.*s op=%llu mode=%s\n",
                  int(cloudID.size()),
                  reinterpret_cast<const char *>(cloudID.data()),
                  (unsigned long long)*pendingOperationID,
                  incrementalCreatedBootstrapCoordinator ? "coordinator" : "blocking");
#endif

               ClusterMachine createdMachine = {};
               prodigyPopulateCreatedClusterMachineFromAcceptance(
                  createdMachine,
                  cloudID,
                  *instruction,
                  *machineConfig,
                  request->bootstrapSshUser,
                  request->bootstrapSshPrivateKeyPath,
                  request->bootstrapSshHostKeyPackage.publicKeyOpenSSH);
               bool inserted = false;
               if (prodigyUpsertClusterMachineByIdentity(targetTopology->machines, createdMachine, &inserted))
               {
                  if (inserted && createdMachine.isBrain && addedBrainCount != nullptr)
                  {
                     *addedBrainCount += 1;
                  }
               }

               (void)owner->upsertPendingAddMachinesOperationMachine(*pendingOperationID, createdMachine, false);
            }

            void reportMachineProvisioned(const Machine& machine) override
            {
               if ((incrementalCreatedBootstrapBlocking == false && incrementalCreatedBootstrapCoordinator == false)
                  || owner == nullptr
                  || request == nullptr
                  || instruction == nullptr
                  || machineConfig == nullptr
                  || targetTopology == nullptr
                  || machinesToBootstrap == nullptr
                  || startedMachines == nullptr
                  || pendingOperationID == nullptr
                  || *pendingOperationID == 0
                  || failure == nullptr
                  || failure->size() > 0
                  || machine.cloudID.size() == 0)
               {
#if PRODIGY_DEBUG
                  basics_log("addMachines incremental provisioned-skip cloudID=%.*s blocking=%d coordinator=%d owner=%p request=%p instruction=%p machineConfig=%p targetTopology=%p machinesToBootstrap=%p startedMachines=%p pendingOpPtr=%p pendingOp=%llu failureBytes=%llu cloudIDBytes=%llu\n",
                     int(machine.cloudID.size()),
                     reinterpret_cast<const char *>(machine.cloudID.data()),
                     int(incrementalCreatedBootstrapBlocking),
                     int(incrementalCreatedBootstrapCoordinator),
                     static_cast<void *>(owner),
                     static_cast<const void *>(request),
                     static_cast<const void *>(instruction),
                     static_cast<const void *>(machineConfig),
                     static_cast<void *>(targetTopology),
                     static_cast<void *>(machinesToBootstrap),
                     static_cast<void *>(startedMachines),
                     static_cast<void *>(pendingOperationID),
                     (unsigned long long)((pendingOperationID != nullptr) ? *pendingOperationID : 0ULL),
                     (unsigned long long)(failure != nullptr ? failure->size() : 0ULL),
                     (unsigned long long)machine.cloudID.size());
#endif
                  return;
               }

               ClusterMachine createdMachine = {};
               prodigyPopulateCreatedClusterMachineFromAcceptance(
                  createdMachine,
                  machine.cloudID,
                  *instruction,
                  *machineConfig,
                  request->bootstrapSshUser,
                  request->bootstrapSshPrivateKeyPath,
                  request->bootstrapSshHostKeyPackage.publicKeyOpenSSH);
               prodigyRefreshCreatedClusterMachineFromSnapshot(
                  createdMachine,
                  const_cast<Machine *>(&machine),
                  request->bootstrapSshUser,
                  request->bootstrapSshPrivateKeyPath,
                  request->bootstrapSshHostKeyPackage.publicKeyOpenSSH);

               bool inserted = false;
               if (prodigyUpsertClusterMachineByIdentity(targetTopology->machines, createdMachine, &inserted))
               {
                  prodigyNormalizeClusterTopologyPeerAddresses(*targetTopology);
                  if (inserted && createdMachine.isBrain && addedBrainCount != nullptr)
                  {
                     *addedBrainCount += 1;
                  }
               }

#if PRODIGY_DEBUG
               basics_log("addMachines incremental provisioned cloudID=%s op=%llu ssh=%s:%u mode=%s targetMachines=%u queued=%u started=%u streamed=%u inserted=%d owned=%u/%u/%u\n",
                  createdMachine.cloud.cloudID.c_str(),
                  (unsigned long long)*pendingOperationID,
                  createdMachine.ssh.address.c_str(),
                  unsigned(createdMachine.ssh.port),
                  incrementalCreatedBootstrapCoordinator ? "coordinator" : "blocking",
                  uint32_t(targetTopology->machines.size()),
                  uint32_t(machinesToBootstrap->size()),
                  uint32_t(startedMachines->size()),
                  uint32_t(streamedBootstrapQueuedMachines != nullptr ? streamedBootstrapQueuedMachines->size() : 0u),
                  int(inserted),
                  createdMachine.ownedLogicalCores,
                  createdMachine.ownedMemoryMB,
                  createdMachine.ownedStorageMB);
#endif

               (void)owner->upsertPendingAddMachinesOperationMachine(*pendingOperationID, createdMachine, true);
               if (prodigyFindClusterMachineByIdentity(*startedMachines, createdMachine) != nullptr)
               {
                  (void)owner->erasePendingAddMachinesOperationBootstrapMachine(*pendingOperationID, createdMachine);
                  prodigyEraseClusterMachineByIdentity(*machinesToBootstrap, createdMachine);
                  return;
               }

               if (prodigyFindClusterMachineByIdentity(*machinesToBootstrap, createdMachine) == nullptr)
               {
                  machinesToBootstrap->push_back(createdMachine);
               }

               if (incrementalCreatedBootstrapCoordinator)
               {
                  if (streamedBootstrapQueuedMachines != nullptr
                     && prodigyFindClusterMachineByIdentity(*streamedBootstrapQueuedMachines, createdMachine) != nullptr)
                  {
                     return;
                  }

                  String bootstrapFailure = {};
                  if (bootstrapCoordinator != nullptr
                     && bootstrapBundleApprovalCache != nullptr
                     && owner->queueClusterMachineBootstrapAsync(
                           *bootstrapCoordinator,
                           *bootstrapBundleApprovalCache,
                           createdMachine,
                           *request,
                           *targetTopology,
                           bootstrapFailure))
                  {
#if PRODIGY_DEBUG
                     basics_log("addMachines incremental bootstrap-queued cloudID=%s op=%llu ssh=%s:%u mode=coordinator pendingTasks=%u openSockets=%u streamed=%u queued=%u started=%u\n",
                        createdMachine.cloud.cloudID.c_str(),
                        (unsigned long long)*pendingOperationID,
                        createdMachine.ssh.address.c_str(),
                        unsigned(createdMachine.ssh.port),
                        unsigned(bootstrapCoordinator != nullptr ? bootstrapCoordinator->pendingTasks : 0u),
                        unsigned(bootstrapCoordinator != nullptr ? bootstrapCoordinator->openSockets : 0u),
                        uint32_t(streamedBootstrapQueuedMachines != nullptr ? streamedBootstrapQueuedMachines->size() : 0u),
                        uint32_t(machinesToBootstrap->size()),
                        uint32_t(startedMachines->size()));
#endif
                     if (streamedBootstrapQueuedMachines != nullptr)
                     {
                        streamedBootstrapQueuedMachines->push_back(createdMachine);
                     }

                     return;
                  }

                  failure->assign(bootstrapFailure.size() > 0 ? bootstrapFailure : "failed to queue streamed cluster bootstrap"_ctv);
                  return;
               }

               String bootstrapFailure = {};
#if PRODIGY_DEBUG
               basics_log("addMachines incremental bootstrap-start cloudID=%s op=%llu ssh=%s:%u mode=blocking targetMachines=%u queued=%u started=%u\n",
                  createdMachine.cloud.cloudID.c_str(),
                  (unsigned long long)*pendingOperationID,
                  createdMachine.ssh.address.c_str(),
                  unsigned(createdMachine.ssh.port),
                  uint32_t(targetTopology->machines.size()),
                  uint32_t(machinesToBootstrap->size()),
                  uint32_t(startedMachines->size()));
#endif
               if (owner->bootstrapClusterMachineBlocking(createdMachine, *request, *targetTopology, bootstrapFailure, bootstrapBundleApprovalCache))
               {
#if PRODIGY_DEBUG
                  basics_log("addMachines incremental bootstrap-ok cloudID=%s op=%llu ssh=%s:%u mode=blocking queued=%u started=%u\n",
                     createdMachine.cloud.cloudID.c_str(),
                     (unsigned long long)*pendingOperationID,
                     createdMachine.ssh.address.c_str(),
                     unsigned(createdMachine.ssh.port),
                     uint32_t(machinesToBootstrap->size()),
                     uint32_t(startedMachines->size() + 1));
#endif
                  startedMachines->push_back(createdMachine);
                  prodigyEraseClusterMachineByIdentity(*machinesToBootstrap, createdMachine);
                  (void)owner->erasePendingAddMachinesOperationBootstrapMachine(*pendingOperationID, createdMachine);
                  return;
               }

#if PRODIGY_DEBUG
               basics_log("addMachines incremental bootstrap-failed cloudID=%s op=%llu ssh=%s:%u mode=blocking failure=%s\n",
                  createdMachine.cloud.cloudID.c_str(),
                  (unsigned long long)*pendingOperationID,
                  createdMachine.ssh.address.c_str(),
                  unsigned(createdMachine.ssh.port),
                  bootstrapFailure.c_str());
#endif
               owner->stopClusterMachineBootstrap(createdMachine);
               failure->assign(bootstrapFailure);
            }

            void reportMachineProvisioningProgress(const Vector<MachineProvisioningProgress>& progress) override
            {
               if (owner == nullptr || mothership == nullptr || progress.empty())
               {
                  return;
               }

               if (Ring::socketIsClosing(mothership))
               {
                  return;
               }

               if ((mothership->isFixedFile && mothership->fslot < 0)
                  || (mothership->isFixedFile == false && mothership->fd < 0))
               {
                  return;
               }

               AddMachines response = {};
               response.isProgress = true;
               response.provisioningProgress = progress;

               String serializedResponse = {};
               BitseryEngine::serialize(serializedResponse, response);

               String framedResponse = {};
               Message::construct(framedResponse, MothershipTopic::addMachines, serializedResponse);
	               std::fprintf(stderr, "prodigy mothership addMachines-progress entries=%u serializedBytes=%zu stream=%p fd=%d fslot=%d\n",
	                  uint32_t(progress.size()),
	                  size_t(framedResponse.size()),
	                  static_cast<void *>(mothership),
	                  mothership->fd,
	                  mothership->fslot);
	               std::fflush(stderr);
	               mothership->wBuffer.append(framedResponse);
	               (void)owner->flushActiveMothershipSendBuffer(mothership, "addmachines-progress");
	            }
         };

         AddMachinesProvisioningProgressSink provisioningProgressSink(this, mothership);

			for (const ClusterMachine& requestedMachine : request.adoptedMachines)
			{
            String requestedLabel = {};
            requestedMachine.renderIdentityLabel(requestedLabel);
            std::fprintf(stderr, "prodigy mothership addMachines-adopted-normalize-start machine=%.*s\n",
               int(requestedLabel.size()),
               requestedLabel.c_str());
            std::fflush(stderr);

				ClusterMachine normalizedMachine = {};
				if (normalizeAdoptedClusterMachine(requestedMachine, request.bootstrapSshUser, request.bootstrapSshPrivateKeyPath, normalizedMachine, response.failure) == false)
				{
					break;
				}
            String normalizedLabel = {};
            normalizedMachine.renderIdentityLabel(normalizedLabel);
            std::fprintf(stderr, "prodigy mothership addMachines-adopted-normalize-ok machine=%.*s ssh=%.*s:%u privateAddresses=%u publicAddresses=%u\n",
               int(normalizedLabel.size()),
               normalizedLabel.c_str(),
               int(normalizedMachine.ssh.address.size()),
               normalizedMachine.ssh.address.c_str(),
               unsigned(normalizedMachine.ssh.port),
               uint32_t(normalizedMachine.addresses.privateAddresses.size()),
               uint32_t(normalizedMachine.addresses.publicAddresses.size()));
            std::fflush(stderr);

				if (clusterTopologyContainsMachineIdentity(targetTopology, normalizedMachine))
				{
					String label = {};
					normalizedMachine.renderIdentityLabel(label);
					response.failure.snprintf<"adopted machine '{}' conflicts with existing topology"_ctv>(label);
					break;
				}

				if (probeCandidateBrainReachability(currentTopology, normalizedMachine, response) == false)
				{
					break;
				}
            std::fprintf(stderr, "prodigy mothership addMachines-adopted-reachability-ok machine=%.*s probeAddress=%.*s results=%u\n",
               int(normalizedLabel.size()),
               normalizedLabel.c_str(),
               int(response.reachabilityProbeAddress.size()),
               response.reachabilityProbeAddress.c_str(),
               uint32_t(response.reachabilityResults.size()));
            std::fflush(stderr);

            ClusterTopology candidateTopology = targetTopology;
            candidateTopology.machines.push_back(normalizedMachine);
            prodigyNormalizeClusterTopologyPeerAddresses(candidateTopology);
            normalizedMachine = candidateTopology.machines.back();

				targetTopology = std::move(candidateTopology);
				machinesToBootstrap.push_back(normalizedMachine);
				if (normalizedMachine.isBrain)
				{
					addedBrainCount += 1;
				}
			}

         if (response.failure.size() == 0)
         {
            for (const ClusterMachine& removedMachine : request.removedMachines)
            {
               bool removedAny = false;
               auto it = std::remove_if(targetTopology.machines.begin(), targetTopology.machines.end(), [&] (const ClusterMachine& existingMachine) {
                  if (existingMachine.sameIdentityAs(removedMachine) == false)
                  {
                     return false;
                  }

                  removedAny = true;
                  return true;
               });

               if (removedAny)
               {
                  targetTopology.machines.erase(it, targetTopology.machines.end());
                  removedMachinesToDecommission.push_back(removedMachine);
               }
            }
         }

         if (response.failure.size() == 0)
         {
            for (const ClusterMachine& requestedMachine : request.readyMachines)
            {
               ClusterMachine readyMachine = requestedMachine;
               readyMachine.isBrain = requestedMachine.isBrain;
               if (clusterTopologyContainsMachineIdentity(targetTopology, readyMachine))
               {
                  continue;
               }

               ClusterTopology candidateTopology = targetTopology;
               candidateTopology.machines.push_back(readyMachine);
               prodigyNormalizeClusterTopologyPeerAddresses(candidateTopology);
               readyMachine = candidateTopology.machines.back();

               targetTopology = std::move(candidateTopology);
               if (readyMachine.isBrain)
               {
                  addedBrainCount += 1;
               }
            }
         }

			if (response.failure.size() == 0)
			{
				for (const CreateMachinesInstruction& instruction : managedWork.createdMachines)
				{
					if (instruction.backing != ClusterMachineBacking::cloud)
					{
						response.failure.assign("created machine instruction currently requires backing=cloud"_ctv);
						break;
					}

					if (instruction.cloud.schema.size() == 0)
					{
						response.failure.assign("created machine instruction requires cloud.schema"_ctv);
						break;
					}

					if (instruction.count == 0)
					{
						response.failure.assign("created machine instruction count required"_ctv);
						break;
					}

					if (instruction.lifetime == MachineLifetime::owned)
					{
						response.failure.assign("created machine instruction lifetime 'owned' is invalid for provider-created machines"_ctv);
						break;
					}

					String schemaKey = {};
					schemaKey.assign(instruction.cloud.schema);

					auto configIt = brainConfig.configBySlug.find(schemaKey);
					if (configIt == brainConfig.configBySlug.end())
					{
						response.failure.snprintf<"unknown machine schema '{}'"_ctv>(schemaKey);
						break;
					}

					const MachineConfig& machineConfig = configIt->second;
					if (instruction.kind != machineConfig.kind)
					{
						response.failure.snprintf<"created machine kind mismatch for schema '{}'"_ctv>(schemaKey);
						break;
					}

					if (iaas->supports(machineConfig.kind) == false)
					{
						response.failure.snprintf<"current runtime environment does not support machine kind for schema '{}'"_ctv>(schemaKey);
						break;
					}

					if (iaas->supportsAutoProvision() == false)
					{
						response.failure.assign("current runtime environment does not support automatic machine provisioning"_ctv);
						break;
					}

               if (incrementalCreatedBootstrapSupported && pendingAddMachinesOperationID == 0)
               {
                  pendingAddMachinesOperationID = journalAddMachinesOperation(request, targetTopology, machinesToBootstrap);
               }

					iaas->configureBootstrapSSHAccess(request.bootstrapSshUser, request.bootstrapSshKeyPackage, request.bootstrapSshHostKeyPackage, request.bootstrapSshPrivateKeyPath);
               iaas->configureProvisioningProgressSink(&provisioningProgressSink);
               provisioningProgressSink.configureIncrementalCreatedBootstrap(
                  &request,
                  &instruction,
                  &machineConfig,
                  &targetTopology,
                  &machinesToBootstrap,
                  &startedMachines,
                  &streamedBootstrapQueuedMachines,
                  &addedBrainCount,
                  &pendingAddMachinesOperationID,
                  &bootstrapCoordinator,
                  &bootstrapBundleApprovalCache,
                  &response.failure,
                  incrementalCreatedBootstrapUsesBlocking,
                  incrementalCreatedBootstrapUsesCoordinator);

					CoroutineStack *coro = new CoroutineStack();
					bytell_hash_set<Machine *> createdSnapshots;
					String providerError;

               std::fprintf(stderr, "prodigy mothership addMachines-spinMachines-start schema=%.*s requested=%u isBrain=%d lifetime=%u\n",
                  int(schemaKey.size()),
                  schemaKey.c_str(),
                  unsigned(instruction.count),
                  int(instruction.isBrain),
                  unsigned(instruction.lifetime));
					std::fflush(stderr);

               iaas->configureProvisioningClusterUUID(brainConfig.clusterUUID);
					uint32_t suspendIndex = coro->nextSuspendIndex();
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
               uint64_t providerWaitStartNs = Time::now<TimeResolution::ns>();
#endif
					iaas->spinMachines(coro, instruction.lifetime, machineConfig, instruction.count, instruction.isBrain, createdSnapshots, providerError);
					if (suspendIndex < coro->nextSuspendIndex())
					{
						co_await coro->suspendAtIndex(suspendIndex);
					}
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
               addMachinesProviderWaitNs += (Time::now<TimeResolution::ns>() - providerWaitStartNs);
#endif
               iaas->configureProvisioningProgressSink(nullptr);
               provisioningProgressSink.clearIncrementalCreatedBootstrap();
					delete coro;

					if (createdSnapshots.size() != instruction.count)
					{
						if (providerError.size() > 0)
						{
							response.failure = providerError;
						}
						else
						{
							response.failure.snprintf<"provider returned {itoa} created machines but {itoa} were requested"_ctv>(createdSnapshots.size(), instruction.count);
						}

						for (Machine *snapshot : createdSnapshots)
						{
							iaas->destroyMachine(snapshot);
							prodigyDestroyMachineSnapshot(snapshot);
						}
						break;
					}

					std::vector<Machine *> orderedSnapshots;
					orderedSnapshots.reserve(createdSnapshots.size());
					for (Machine *snapshot : createdSnapshots)
					{
						orderedSnapshots.push_back(snapshot);
                  createdProvisionedSnapshots.push_back(snapshot);
					}

						std::sort(orderedSnapshots.begin(), orderedSnapshots.end(), [&] (Machine *lhs, Machine *rhs) {
							return prodigyMachineIdentityComesBefore(*lhs, *rhs);
						});

               Vector<ClusterMachine> createdMachines = {};
					for (uint32_t index = 0; index < orderedSnapshots.size(); ++index)
					{
						Machine *snapshot = orderedSnapshots[index];
						ClusterMachine createdMachine = {};
						prodigyPopulateCreatedClusterMachineFromSnapshot(createdMachine, snapshot, instruction, machineConfig, request.bootstrapSshUser, request.bootstrapSshPrivateKeyPath, request.bootstrapSshHostKeyPackage.publicKeyOpenSSH);

                  bool duplicateCreatedIdentity = false;
                  for (const ClusterMachine& pendingCreatedMachine : createdMachines)
                  {
                     if (pendingCreatedMachine.sameIdentityAs(createdMachine))
                     {
                        duplicateCreatedIdentity = true;
                        break;
                     }
                  }

                  if (duplicateCreatedIdentity)
                  {
                     String label = {};
                     createdMachine.renderIdentityLabel(label);
                     response.failure.snprintf<"created machine '{}' conflicts with existing created machine"_ctv>(label);
                     break;
                  }

                  createdMachines.push_back(createdMachine);
					}

               if (response.failure.size() == 0 && createdMachines.empty() == false)
               {
                  for (const ClusterMachine& createdMachine : createdMachines)
                  {
                     bool inserted = false;
                     if (prodigyUpsertClusterMachineByIdentity(targetTopology.machines, createdMachine, &inserted))
                     {
                        if (inserted && createdMachine.isBrain)
                        {
                           addedBrainCount += 1;
                        }
                     }
                  }

                  prodigyNormalizeClusterTopologyPeerAddresses(targetTopology);
                  for (const ClusterMachine& createdMachine : createdMachines)
                  {
                     const ClusterMachine *normalizedMachine = prodigyFindClusterMachineByIdentity(targetTopology.machines, createdMachine);
                     if (normalizedMachine == nullptr)
                     {
                        continue;
                     }

                     if (startedBootstrapContainsMachine(*normalizedMachine) == false
                        && bootstrapQueueContainsMachine(*normalizedMachine) == false)
                     {
                        machinesToBootstrap.push_back(*normalizedMachine);
                     }

                     if (pendingAddMachinesOperationID > 0)
                     {
                        (void)upsertPendingAddMachinesOperationMachine(
                           pendingAddMachinesOperationID,
                           *normalizedMachine,
                           bootstrapQueueContainsMachine(*normalizedMachine));
                     }
                  }
               }

#if PRODIGY_DEBUG
               std::fprintf(stderr, "prodigy mothership addMachines-spinMachines-done schema=%.*s requested=%u snapshots=%zu createdMachines=%u started=%u queued=%u streamedQueued=%u providerErrorBytes=%zu pendingOperationID=%llu\n",
                  int(schemaKey.size()),
                  schemaKey.c_str(),
                  unsigned(instruction.count),
                  orderedSnapshots.size(),
                  uint32_t(createdMachines.size()),
                  uint32_t(startedMachines.size()),
                  uint32_t(machinesToBootstrap.size()),
                  uint32_t(streamedBootstrapQueuedMachines.size()),
                  size_t(providerError.size()),
                  (unsigned long long)pendingAddMachinesOperationID);
               std::fflush(stderr);
#endif

					if (response.failure.size() > 0)
					{
						break;
					}
				}
			}

			if (response.failure.size() == 0 && readOnlyTopologyRequest)
         {
            response.success = true;
            response.hasTopology = true;
            response.topology = currentTopology;
         }

			if (response.failure.size() == 0 && readOnlyTopologyRequest == false)
			{
				uint32_t finalBrainCount = clusterTopologyBrainCount(targetTopology);
            if (managedWork.requiredBrainCount > 0 && finalBrainCount < managedWork.requiredBrainCount)
            {
               response.failure.snprintf<"final brain count {itoa} is below requiredBrainCount {itoa}"_ctv>(finalBrainCount, managedWork.requiredBrainCount);
            }

            if (response.failure.size() > 0)
            {
               goto addmachines_finalize;
            }

				if (addedBrainCount > 0 && clusterTopologyBrainCountSatisfiesQuorum(finalBrainCount) == false)
				{
					response.failure.snprintf<"adding brain machines requires final brain count to be odd and >= 3 (got {itoa})"_ctv>(finalBrainCount);
				}
			}

			if (readOnlyTopologyRequest == false)
			{
            if (response.failure.size() == 0 && pendingAddMachinesOperationID == 0)
            {
               pendingAddMachinesOperationID = journalAddMachinesOperation(request, targetTopology, machinesToBootstrap);
            }

            auto rollbackBootstrapped = [this](const ClusterMachine& clusterMachine) -> void {

               stopClusterMachineBootstrap(clusterMachine);
            };

            // Internal managed-schema reconciliation captures an immediate response and cannot
            // suspend out while follower bootstrap is still in flight.
            if (canSuspendRemoteBootstrap() == false || requireSynchronousBootstrap)
            {
#if PRODIGY_DEBUG
               std::fprintf(stderr, "prodigy mothership addMachines-bootstrap-phase mode=blocking started=%u queued=%u streamedQueued=%u pendingOperationID=%llu\n",
                  uint32_t(startedMachines.size()),
                  uint32_t(machinesToBootstrap.size()),
                  uint32_t(streamedBootstrapQueuedMachines.size()),
                  (unsigned long long)pendingAddMachinesOperationID);
               std::fflush(stderr);
#endif
               if (response.failure.size() == 0
                  && prodigyBootstrapItemsConcurrently<ClusterMachine>(
                        machinesToBootstrap,
                        [this, &request, &targetTopology, &bootstrapBundleApprovalCache](const ClusterMachine& clusterMachine, String& failure) -> bool {

                           return bootstrapClusterMachineBlocking(clusterMachine, request, targetTopology, failure, &bootstrapBundleApprovalCache);
                        },
                        rollbackBootstrapped,
                        &startedMachines,
                        response.failure) == false)
               {
                  startedMachines.clear();
               }
            }
            else
            {
#if PRODIGY_DEBUG
               std::fprintf(stderr, "prodigy mothership addMachines-bootstrap-phase mode=coordinator started=%u queued=%u streamedQueued=%u pendingOperationID=%llu\n",
                  uint32_t(startedMachines.size()),
                  uint32_t(machinesToBootstrap.size()),
                  uint32_t(streamedBootstrapQueuedMachines.size()),
                  (unsigned long long)pendingAddMachinesOperationID);
               std::fflush(stderr);
#endif
               if (response.failure.size() == 0)
               {
                  for (const ClusterMachine& clusterMachine : machinesToBootstrap)
                  {
                     if (streamedBootstrapQueueContainsMachine(clusterMachine))
                     {
                        continue;
                     }

                     if (queueClusterMachineBootstrapAsync(
                           bootstrapCoordinator,
                           bootstrapBundleApprovalCache,
                           clusterMachine,
                           request,
                           targetTopology,
                           response.failure) == false)
                     {
                        break;
                     }

                     streamedBootstrapQueuedMachines.push_back(clusterMachine);
                  }
               }

               if (bootstrapCoordinator.pendingTasks > 0 || bootstrapCoordinator.openSockets > 0)
               {
                  uint32_t suspendIndex = bootstrapCoordinator.nextSuspendIndex();
                  bootstrapCoordinator.awaitCompletion();
                  if (suspendIndex < bootstrapCoordinator.nextSuspendIndex())
                  {
                     co_await bootstrapCoordinator.suspendAtIndex(suspendIndex);
                  }
               }

               Vector<ClusterMachine> bootstrappedMachines = {};
               String bootstrapFailure = {};
               bool bootstrapSucceeded = bootstrapCoordinator.finalize(&bootstrappedMachines, rollbackBootstrapped, bootstrapFailure);
               if (response.failure.size() == 0)
               {
                  if (bootstrapSucceeded == false)
                  {
                     startedMachines.clear();
                     response.failure = bootstrapFailure;
                  }
                  else
                  {
                     startedMachines = std::move(bootstrappedMachines);
                  }
               }
               else
               {
                  if (bootstrapSucceeded)
                  {
                     for (const ClusterMachine& clusterMachine : bootstrappedMachines)
                     {
                        rollbackBootstrapped(clusterMachine);
                     }
                  }
                  startedMachines.clear();
               }
            }
			}

			if (response.failure.size() == 0 && readOnlyTopologyRequest == false)
			{
            std::fprintf(stderr, "prodigy mothership addMachines-post-bootstrap started=%u targetMachines=%u currentVersion=%u\n",
               uint32_t(startedMachines.size()),
               uint32_t(targetTopology.machines.size()),
               uint32_t(currentTopology.version));
            std::fflush(stderr);
				targetTopology.version = currentTopology.version + 1;

            std::fprintf(stderr, "prodigy mothership addMachines-restore-brains version=%u brains=%u\n",
               uint32_t(targetTopology.version),
               uint32_t(clusterTopologyBrainCount(targetTopology)));
            std::fflush(stderr);
				restoreBrainsFromClusterTopology(targetTopology);
            std::fprintf(stderr, "prodigy mothership addMachines-restore-machines version=%u machines=%u\n",
               uint32_t(targetTopology.version),
               uint32_t(targetTopology.machines.size()));
            std::fflush(stderr);
				restoreMachinesFromClusterTopology(targetTopology);
				nBrains = clusterTopologyBrainCount(targetTopology);
            std::fprintf(stderr, "prodigy mothership addMachines-init-peers nBrains=%u\n", uint32_t(nBrains));
            std::fflush(stderr);
				initializeAllBrainPeersIfNeeded();

            std::fprintf(stderr, "prodigy mothership addMachines-persist-topology version=%u machines=%u\n",
               uint32_t(targetTopology.version),
               uint32_t(targetTopology.machines.size()));
            std::fflush(stderr);
					if (persistAuthoritativeClusterTopology(targetTopology) == false)
					{
						response.failure.assign("failed to persist authoritative cluster topology"_ctv);
					}
					else
					{
	               std::fprintf(stderr, "prodigy mothership addMachines-replicate-topology version=%u machines=%u\n",
	                  uint32_t(targetTopology.version),
	                  uint32_t(targetTopology.machines.size()));
	               std::fflush(stderr);
						String serializedTopology;
						BitseryEngine::serialize(serializedTopology, targetTopology);
						queueBrainReplication(BrainTopic::replicateClusterTopology, serializedTopology);

						response.success = true;
						response.hasTopology = true;
						response.topology = targetTopology;
	               if (pendingAddMachinesOperationID > 0)
	               {
                  std::fprintf(stderr, "prodigy mothership addMachines-clear-pending operationID=%llu\n",
                     (unsigned long long)pendingAddMachinesOperationID);
                  std::fflush(stderr);
                  (void)erasePendingAddMachinesOperation(pendingAddMachinesOperationID);
                  pendingAddMachinesOperationID = 0;
               }
				}
			}

addmachines_finalize:
			if (response.failure.size() > 0)
			{
				std::fprintf(stderr, "prodigy mothership addMachines-failure bytes=%zu text=%.*s\n",
					size_t(response.failure.size()),
					int(response.failure.size()),
					response.failure.c_str());
				std::fflush(stderr);
				for (const ClusterMachine& clusterMachine : startedMachines)
				{
					stopClusterMachineBootstrap(clusterMachine);
				}

				cleanupProvisionedSnapshots(true);
            if (pendingAddMachinesOperationID > 0)
            {
               (void)erasePendingAddMachinesOperation(pendingAddMachinesOperationID);
            }
			}
			else
			{
				cleanupProvisionedSnapshots(false);
			}
         if (response.success)
         {
            for (const ClusterMachine& removedMachine : removedMachinesToDecommission)
            {
               IPAddress peerAddress = {};
               String peerAddressText = {};
               bool havePeerAddress = removedMachine.resolvePeerAddress(peerAddress, &peerAddressText);
               uint32_t resolvedPrivate4 = 0;
               (void)removedMachine.resolvePrivate4(resolvedPrivate4);
               Vector<ClusterMachinePeerAddress> removedMachinePeerAddresses = {};
               prodigyCollectClusterMachinePeerAddresses(removedMachine, removedMachinePeerAddresses);

               Machine *machine = findMachineByIdentity(
                  removedMachine.uuid,
                  resolvedPrivate4,
                  &removedMachinePeerAddresses,
                  havePeerAddress ? &peerAddress : nullptr,
                  havePeerAddress ? &peerAddressText : nullptr);
               if (machine == nullptr)
               {
                  stopClusterMachineBootstrap(removedMachine);
                  continue;
               }

               if (thisNeuron != nullptr && machine->uuid == thisNeuron->uuid)
               {
                  continue;
               }

               decommissionMachine(machine);
            }
         }
		}

			if (response.success && managedWork.empty() && readOnlyTopologyRequest == false && weAreMaster)
			{
				String managedFailure = {};
            ClusterTopology managedTopology = {};
				if (reconcileManagedMachineSchemas(&managedFailure, nullptr, &managedTopology) == false)
				{
					response.success = false;
					response.hasTopology = false;
					response.topology = {};
					response.failure = managedFailure;
				}
				else
				{
					response.hasTopology = true;
               response.topology = std::move(managedTopology);
	         }
			}

#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
      response.hasTimingAttribution = true;
      prodigyFinalizeTimingAttribution(Time::now<TimeResolution::ns>() - addMachinesStartNs, addMachinesProviderWaitNs, response.timingAttribution);
#endif
         bool streamActive = streamIsActive(mothership);
			if (streamActive)
				{
					String serializedResponse;
					BitseryEngine::serialize(serializedResponse, response);
				std::fprintf(stderr, "prodigy mothership addMachines-end success=%d failureBytes=%zu hasTopology=%d topologyMachines=%u serializedBytes=%zu stream=%p fd=%d fslot=%d\n",
					int(response.success),
					size_t(response.failure.size()),
					int(response.hasTopology),
					(response.hasTopology ? uint32_t(response.topology.machines.size()) : 0u),
					size_t(serializedResponse.size()),
					static_cast<void *>(mothership),
					mothership->fd,
					mothership->fslot);
					std::fflush(stderr);
					Message::construct(mothership->wBuffer, MothershipTopic::addMachines, serializedResponse);
					bool sendOkay = flushActiveMothershipSendBuffer(mothership, "addmachines-final");
					if (sendOkay)
					{
						std::fprintf(stderr, "prodigy mothership addMachines-finished stream=%p fd=%d fslot=%d closing=1\n",
							static_cast<void *>(mothership),
							mothership->fd,
							mothership->fslot);
						std::fflush(stderr);
						queueCloseAfterSendDrain(mothership);
						}
				}

         if (capturedResponse != nullptr)
         {
            if (streamActive)
            {
               *capturedResponse = response;
            }
            else
            {
               *capturedResponse = std::move(response);
            }
         }
			}

	void mothershipHandler(Mothership *mothership, Message *message)
	{
		uint8_t *args = message->args;
		std::fprintf(stderr, "prodigy mothership handler topic=%s(%u) size=%u stream=%p fd=%d fslot=%d wbytes=%zu rbytes=%zu master=%d\n",
			prodigyMothershipTopicName(MothershipTopic(message->topic)),
			unsigned(message->topic),
			unsigned(message->size),
			static_cast<void *>(mothership),
			(mothership ? mothership->fd : -1),
			(mothership ? mothership->fslot : -1),
			(mothership ? size_t(mothership->wBuffer.size()) : size_t(0)),
			(mothership ? size_t(mothership->rBuffer.size()) : size_t(0)),
			int(weAreMaster));
		std::fflush(stderr);

		// Only the active master may serve mothership control-plane traffic.
		// Followers close opportunistic connections immediately.
		if (weAreMaster == false)
		{
			std::fprintf(stderr, "prodigy mothership handler-reject reason=not-master topic=%s(%u) stream=%p\n",
				prodigyMothershipTopicName(MothershipTopic(message->topic)),
				unsigned(message->topic),
				static_cast<void *>(mothership));
			std::fflush(stderr);
			queueCloseIfActive(mothership);
			return;
		}

      replayLocalMachineHardwareProfileIfReady();

		switch (MothershipTopic(message->topic))
		{
			case MothershipTopic::configure: // this must be the first thing done, before anything else... we could even reject deployments
			{
				// config{4}

				String serialized;
				Message::extractToStringView(args, serialized);

				BrainConfig deserializedConfig = {};
				BitseryEngine::deserialize(serialized, deserializedConfig);
            BrainConfig incomingConfig = {};
            ownBrainConfig(deserializedConfig, incomingConfig);
            uint16_t previousSharedCPUOvercommitPermille = brainConfig.sharedCPUOvercommitPermille;
				std::fprintf(stderr, "prodigy mothership configure-request clusterUUID=%llu datacenter=%u autoscale=%u requiredBrains=%u nMachineConfigs=%u nSubnets=%u runtimeConfigured=%d reporterConfigured=%d vmImage=%d\n",
					(unsigned long long)incomingConfig.clusterUUID,
					unsigned(incomingConfig.datacenterFragment),
					unsigned(incomingConfig.autoscaleIntervalSeconds),
               unsigned(incomingConfig.requiredBrainCount),
					uint32_t(incomingConfig.configBySlug.size()),
					uint32_t(incomingConfig.distributableExternalSubnets.size()),
					int(incomingConfig.runtimeEnvironment.configured()),
					int(incomingConfig.reporter.to.size() > 0
						|| incomingConfig.reporter.from.size() > 0
						|| incomingConfig.reporter.smtp.size() > 0
						|| incomingConfig.reporter.password.size() > 0),
					int(incomingConfig.vmImageURI.size() > 0));
				std::fflush(stderr);

            String ownershipFailure = {};
            if (claimLocalClusterOwnership(incomingConfig.clusterUUID, &ownershipFailure) == false)
            {
               std::fprintf(stderr, "prodigy mothership configure-reject clusterUUID=%llu reason=%s\n",
                  (unsigned long long)incomingConfig.clusterUUID,
                  ownershipFailure.c_str());
               std::fflush(stderr);
               queueCloseIfActive(mothership, "configure-owner-mismatch");
               break;
            }

            if (incomingConfig.clusterUUID != 0)
            {
               brainConfig.clusterUUID = incomingConfig.clusterUUID;
            }

            if (incomingConfig.datacenterFragment != 0)
            {
               brainConfig.datacenterFragment = incomingConfig.datacenterFragment;
            }

            if (incomingConfig.autoscaleIntervalSeconds != 0)
            {
               brainConfig.autoscaleIntervalSeconds = incomingConfig.autoscaleIntervalSeconds;
            }

            if (incomingConfig.sharedCPUOvercommitPermille >= prodigySharedCPUOvercommitMinPermille
               && incomingConfig.sharedCPUOvercommitPermille <= prodigySharedCPUOvercommitMaxPermille)
            {
               brainConfig.sharedCPUOvercommitPermille = incomingConfig.sharedCPUOvercommitPermille;
            }

            brainConfig.requiredBrainCount = incomingConfig.requiredBrainCount;
            brainConfig.architecture = incomingConfig.architecture;
            brainConfig.bootstrapSshUser = incomingConfig.bootstrapSshUser;
            brainConfig.bootstrapSshKeyPackage = incomingConfig.bootstrapSshKeyPackage;
            brainConfig.bootstrapSshHostKeyPackage = incomingConfig.bootstrapSshHostKeyPackage;
            brainConfig.bootstrapSshPrivateKeyPath = incomingConfig.bootstrapSshPrivateKeyPath;
            brainConfig.remoteProdigyPath = incomingConfig.remoteProdigyPath;
            brainConfig.controlSocketPath = incomingConfig.controlSocketPath;

            for (const auto& [slug, machineConfig] : incomingConfig.configBySlug)
            {
               brainConfig.configBySlug.insert_or_assign(slug, machineConfig);
            }

            if (incomingConfig.distributableExternalSubnets.empty() == false)
            {
               brainConfig.distributableExternalSubnets = incomingConfig.distributableExternalSubnets;
            }

            if (incomingConfig.reporter.to.size() > 0
               || incomingConfig.reporter.from.size() > 0
               || incomingConfig.reporter.smtp.size() > 0
               || incomingConfig.reporter.password.size() > 0)
            {
               brainConfig.reporter = incomingConfig.reporter;
            }

            if (incomingConfig.vmImageURI.size() > 0)
            {
               brainConfig.vmImageURI = incomingConfig.vmImageURI;
            }

            if (incomingConfig.runtimeEnvironment.configured())
            {
               ownRuntimeEnvironmentConfig(incomingConfig.runtimeEnvironment, brainConfig.runtimeEnvironment);
            }

            String serializedBrainConfig;
            BitseryEngine::serialize(serializedBrainConfig, brainConfig);

						loadBrainConfigIf();

							queueBrainReplication(BrainTopic::replicateBrainConfig, serializedBrainConfig);
                     persistLocalRuntimeState();

							if (noMasterYet)
							{
								deriveMasterBrain();
						}

						std::fprintf(stderr, "prodigy mothership configure-response clusterUUID=%llu datacenter=%u autoscale=%u nMachineConfigs=%u nSubnets=%u bytes=%zu noMasterYet=%d master=%d\n",
							(unsigned long long)brainConfig.clusterUUID,
							unsigned(brainConfig.datacenterFragment),
							unsigned(brainConfig.autoscaleIntervalSeconds),
							uint32_t(brainConfig.configBySlug.size()),
							uint32_t(brainConfig.distributableExternalSubnets.size()),
							size_t(serializedBrainConfig.size()),
							int(noMasterYet),
							int(weAreMaster));
					std::fflush(stderr);
                  basics_log("configure sharedCPUOvercommitPermille=%u previous=%u\n",
                     unsigned(brainConfig.sharedCPUOvercommitPermille),
                     unsigned(previousSharedCPUOvercommitPermille));
						Message::construct(mothership->wBuffer, MothershipTopic::configure, serializedBrainConfig);

						break;
					}
			case MothershipTopic::upsertMachineSchemas:
			{
				String serializedRequest = {};
				Message::extractToStringView(args, serializedRequest);

				UpsertMachineSchemas request = {};
				UpsertMachineSchemas response = {};
				if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
				{
					response.failure.assign("invalid upsertMachineSchemas payload"_ctv);
				}
				else if (request.patches.empty())
				{
					response.failure.assign("upsertMachineSchemas requires at least one schema patch"_ctv);
				}
				else
				{
               Vector<ProdigyManagedMachineSchema> previousSchemas = masterAuthorityRuntimeState.machineSchemas;
					response.upserted = uint32_t(request.patches.size());
					for (const ProdigyManagedMachineSchemaPatch& patch : request.patches)
					{
						bool created = false;
						if (prodigyUpsertManagedMachineSchema(masterAuthorityRuntimeState.machineSchemas, patch, &created, &response.failure) == false)
						{
							break;
						}

						if (created)
						{
							response.created += 1;
						}
					}

						if (response.failure.size() == 0)
						{
	                  syncManagedMachineSchemaConfigs(previousSchemas, masterAuthorityRuntimeState.machineSchemas);
							noteMasterAuthorityRuntimeStateChanged();

							String reconcileFailure = {};
                     ClusterTopology reconciledTopology = {};
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
	                  ProdigyTimingAttribution reconcileTiming = {};
							if (reconcileManagedMachineSchemas(&reconcileFailure, &reconcileTiming, &reconciledTopology) == false)
#else
							if (reconcileManagedMachineSchemas(&reconcileFailure, nullptr, &reconciledTopology) == false)
#endif
							{
								std::fprintf(stderr, "prodigy mothership upsertMachineSchemas-reconcile-failure bytes=%zu text=%.*s\n",
									size_t(reconcileFailure.size()),
									int(reconcileFailure.size()),
									reconcileFailure.c_str());
								std::fflush(stderr);
								response.failure = reconcileFailure;
							}
							else
							{
								response.hasTopology = true;
                        response.topology = std::move(reconciledTopology);
	                  }

							response.success = (response.failure.size() == 0);
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
                  response.hasTimingAttribution = true;
                  response.timingAttribution = reconcileTiming;
#endif
					}
				}

				String serializedResponse = {};
				BitseryEngine::serialize(serializedResponse, response);
				Message::construct(mothership->wBuffer, MothershipTopic::upsertMachineSchemas, serializedResponse);
				break;
			}
			case MothershipTopic::deltaMachineBudget:
			{
				String serializedRequest = {};
				Message::extractToStringView(args, serializedRequest);

				DeltaMachineBudget request = {};
				DeltaMachineBudget response = {};
				if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
				{
					response.failure.assign("invalid deltaMachineBudget payload"_ctv);
				}
				else
				{
					response.schema = request.schema;
					if (prodigyDeltaManagedMachineBudget(masterAuthorityRuntimeState.machineSchemas, request.schema, request.delta, &response.budget, &response.failure) == false)
					{
						response.success = false;
					}
						else
						{
							noteMasterAuthorityRuntimeStateChanged();

							String reconcileFailure = {};
                     ClusterTopology reconciledTopology = {};
							if (reconcileManagedMachineSchemas(&reconcileFailure, nullptr, &reconciledTopology) == false)
							{
								response.failure = reconcileFailure;
							}
							else
							{
								response.hasTopology = true;
                        response.topology = std::move(reconciledTopology);
	                  }

							response.success = (response.failure.size() == 0);
					}
				}

				String serializedResponse = {};
				BitseryEngine::serialize(serializedResponse, response);
				Message::construct(mothership->wBuffer, MothershipTopic::deltaMachineBudget, serializedResponse);
				break;
			}
			case MothershipTopic::deleteMachineSchema:
			{
				String serializedRequest = {};
				Message::extractToStringView(args, serializedRequest);

				DeleteMachineSchema request = {};
				DeleteMachineSchema response = {};
				if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
				{
					response.failure.assign("invalid deleteMachineSchema payload"_ctv);
				}
				else
				{
					response.schema = request.schema;
               Vector<ProdigyManagedMachineSchema> previousSchemas = masterAuthorityRuntimeState.machineSchemas;
					if (prodigyDeleteManagedMachineSchema(masterAuthorityRuntimeState.machineSchemas, request.schema, &response.removed, &response.failure) == false)
					{
						response.success = false;
					}
					else
					{
							if (response.removed)
							{
	                        syncManagedMachineSchemaConfigs(previousSchemas, masterAuthorityRuntimeState.machineSchemas);
								noteMasterAuthorityRuntimeStateChanged();

								String reconcileFailure = {};
                        ClusterTopology reconciledTopology = {};
								if (reconcileManagedMachineSchemas(&reconcileFailure, nullptr, &reconciledTopology) == false)
								{
									response.failure = reconcileFailure;
								}
								else
								{
									response.hasTopology = true;
                           response.topology = std::move(reconciledTopology);
	                     }
							}
							else if (loadOrPersistAuthoritativeClusterTopology(response.topology))
						{
							response.hasTopology = true;
						}
                  else
                  {
                     response.failure.assign("authoritative cluster topology unavailable"_ctv);
                  }

						response.success = (response.failure.size() == 0);
					}
				}

				String serializedResponse = {};
				BitseryEngine::serialize(serializedResponse, response);
				Message::construct(mothership->wBuffer, MothershipTopic::deleteMachineSchema, serializedResponse);
				break;
			}
			case MothershipTopic::addMachines:
			{
				String serializedRequest;
				Message::extractToStringView(args, serializedRequest);
				std::fprintf(stderr, "prodigy mothership addMachines-request bytes=%zu\n", size_t(serializedRequest.size()));
				std::fflush(stderr);

				AddMachines request = {};
				if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
				{
					AddMachines response = {};
					response.success = false;
					response.failure.assign("invalid addMachines payload"_ctv);
					std::fprintf(stderr, "prodigy mothership addMachines-request invalid-payload bytes=%zu\n", size_t(serializedRequest.size()));
					std::fflush(stderr);

					String serializedResponse;
					BitseryEngine::serialize(serializedResponse, response);
					Message::construct(mothership->wBuffer, MothershipTopic::addMachines, serializedResponse);
					(void)flushActiveMothershipSendBuffer(mothership, "addmachines-invalid");
					break;
				}

				std::fprintf(stderr, "prodigy mothership addMachines-request decoded adopted=%u ready=%u removed=%u readOnly=%d\n",
					uint32_t(request.adoptedMachines.size()),
					uint32_t(request.readyMachines.size()),
					uint32_t(request.removedMachines.size()),
					int(request.adoptedMachines.empty() && request.readyMachines.empty() && request.removedMachines.empty()));
				std::fflush(stderr);

				addMachines(mothership, std::move(request));
				break;
			}
			case MothershipTopic::registerRoutableSubnet:
			{
				String serializedRequest;
				Message::extractToStringView(args, serializedRequest);

				RoutableSubnetRegistration request = {};
				RoutableSubnetRegistration response = {};
				response.success = false;

				if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
				{
					response.failure.assign("invalid subnet payload"_ctv);
				}
				else if (request.subnet.name.size() == 0)
				{
					response.failure.assign("name required"_ctv);
				}
            else if (externalSubnetUsageIsValid(request.subnet.usage) == false)
            {
               response.failure.assign("usage invalid"_ctv);
            }
            else if (environmentBGPEnabled() == false)
            {
               response.failure.assign("routable subnet registration requires bgp-enabled environment"_ctv);
            }
            else if (request.subnet.routing != ExternalSubnetRouting::switchboardBGP)
            {
               response.failure.assign("routable subnet registration only supports switchboardBGP"_ctv);
            }
				else
				{
               request.subnet.subnet.canonicalize();

               if (routableExternalSubnetHasSupportedBreadth(request.subnet) == false)
               {
                  if (request.subnet.subnet.network.is6)
                  {
                     response.failure.assign("routable ipv6 subnet prefix must be between /4 and /48"_ctv);
                  }
                  else
                  {
                     response.failure.assign("routable ipv4 subnet prefix must be between /4 and /24"_ctv);
                  }
               }

					for (const DistributableExternalSubnet& existing : brainConfig.distributableExternalSubnets)
					{
                  if (response.failure.size() > 0)
                  {
                     break;
                  }

								if (existing.name.equals(request.subnet.name))
						{
							continue;
						}

						if (ipPrefixesOverlap(existing.subnet, request.subnet.subnet))
						{
							response.failure.snprintf<"routable subnet overlaps existing subnet '{}'"_ctv>(existing.name);
							break;
						}
					}

					bool replaced = false;
					if (response.failure.size() == 0)
					{
						for (DistributableExternalSubnet& existing : brainConfig.distributableExternalSubnets)
						{
							if (existing.name.equals(request.subnet.name))
							{
                        if (request.subnet.uuid == 0)
                        {
                           request.subnet.uuid = existing.uuid;
                        }

								existing = request.subnet;
								replaced = true;
								break;
							}
						}

						if (replaced == false)
						{
                     if (request.subnet.uuid == 0)
                     {
                        request.subnet.uuid = Random::generateNumberWithNBits<128, uint128_t>();
                     }

							brainConfig.distributableExternalSubnets.push_back(request.subnet);
						}

	               sendNeuronSwitchboardRoutableSubnets();
                  sendNeuronSwitchboardOverlayRoutes();

						String serializedBrainConfig;
						BitseryEngine::serialize(serializedBrainConfig, brainConfig);
						queueBrainReplication(BrainTopic::replicateBrainConfig, serializedBrainConfig);
                  persistLocalRuntimeState();
						response.success = true;
						response.created = !replaced;
					}
				}

				response.subnet = request.subnet;

				String serializedResponse;
				BitseryEngine::serialize(serializedResponse, response);
				Message::construct(mothership->wBuffer, MothershipTopic::registerRoutableSubnet, serializedResponse);
				break;
			}
			case MothershipTopic::unregisterRoutableSubnet:
			{
				String serializedRequest;
				Message::extractToStringView(args, serializedRequest);

				RoutableSubnetUnregistration request = {};
				RoutableSubnetUnregistration response = {};
				response.success = false;

				if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
				{
					response.failure.assign("invalid unregister payload"_ctv);
				}
				else if (request.name.size() == 0)
				{
					response.failure.assign("name required"_ctv);
				}
				else
				{
					response.name = request.name;

					bool removed = false;
					for (auto it = brainConfig.distributableExternalSubnets.begin(); it != brainConfig.distributableExternalSubnets.end(); ++it)
					{
							if (it->name.equals(request.name))
						{
							brainConfig.distributableExternalSubnets.erase(it);
							removed = true;
							break;
						}
					}

					if (removed)
					{
	               sendNeuronSwitchboardRoutableSubnets();
                  sendNeuronSwitchboardOverlayRoutes();

						String serializedBrainConfig;
						BitseryEngine::serialize(serializedBrainConfig, brainConfig);
						queueBrainReplication(BrainTopic::replicateBrainConfig, serializedBrainConfig);
                  persistLocalRuntimeState();
					}

					response.success = true;
					response.removed = removed;
				}

				if (response.name.size() == 0)
				{
					response.name = request.name;
				}

				String serializedResponse;
				BitseryEngine::serialize(serializedResponse, response);
				Message::construct(mothership->wBuffer, MothershipTopic::unregisterRoutableSubnet, serializedResponse);
				break;
			}
			case MothershipTopic::pullRoutableSubnets:
			{
				RoutableSubnetRegistryReport response = {};
				response.subnets = brainConfig.distributableExternalSubnets;
				response.success = true;

				String serializedResponse;
				BitseryEngine::serialize(serializedResponse, response);
				Message::construct(mothership->wBuffer, MothershipTopic::pullRoutableSubnets, serializedResponse);
				break;
			}
         case MothershipTopic::registerRoutableAddress:
         {
            String serializedRequest;
            Message::extractToStringView(args, serializedRequest);

            RoutableAddressRegistration request = {};
            RoutableAddressRegistration response = {};
            response.success = false;

            if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
            {
               response.failure.assign("invalid routable address payload"_ctv);
            }
            else if (request.name.size() == 0)
            {
               response.failure.assign("name required"_ctv);
            }
            else
            {
               RegisteredRoutableAddress *existing = findRegisteredRoutableAddress(brainConfig.routableAddresses, request.name, request.uuid);
               if (existing != nullptr)
               {
                  String existingAddressText = {};
                  (void)ClusterMachine::renderIPAddressLiteral(existing->address, existingAddressText);

                  bool sameRequest = existing->kind == request.kind
                     && existing->family == request.family
                     && (request.machineUUID == 0 || request.machineUUID == existing->machineUUID)
                     && (request.providerPool.size() == 0 || request.providerPool.equals(existing->providerPool))
                     && (request.requestedAddress.size() == 0 || request.requestedAddress.equals(existingAddressText));

                  if (sameRequest == false)
                  {
                     response.failure.assign("routable address already exists with different configuration; unregister it first"_ctv);
                  }
                  else
                  {
                     response.success = true;
                     response.created = false;
                     response.uuid = existing->uuid;
                     response.machineUUID = existing->machineUUID;
                     response.address = existing->address;
                  }
               }

               RegisteredRoutableAddress resolved = {};
               resolved.uuid = request.uuid;
               resolved.name = request.name;
               resolved.kind = request.kind;
               resolved.family = request.family;
               resolved.providerPool = request.providerPool;

               Machine *targetMachine = nullptr;

               if (response.success == false && response.failure.size() == 0)
               {
                  if (request.kind == RoutableAddressKind::testFakeAddress)
                  {
                     if (request.requestedAddress.size() > 0 || request.providerPool.size() > 0)
                     {
                        response.failure.assign("test fake routable addresses do not accept requestedAddress or providerPool"_ctv);
                     }
                     else
                     {
                        IPPrefix fakePrefix = {};
                        if (resolveTestFakePublicPrefix(request.family, fakePrefix) == false)
                        {
                           response.failure.assign("test fake routable address requires a configured fake public subnet for that family"_ctv);
                        }
                        else
                        {
                           targetMachine = chooseMachineForHostedRoute(request.machineUUID);
                           if (targetMachine == nullptr)
                           {
                              response.failure.assign("unable to select target machine for test fake routable address"_ctv);
                           }
                           else if (neuronControlStreamActive(targetMachine) == false)
                           {
                              response.failure.assign("target machine neuron control stream is not active"_ctv);
                           }
                           else if (allocateUniqueRegisteredAddressFromPrefix(fakePrefix, brainConfig.routableAddresses, resolved.address) == false)
                           {
                              response.failure.assign("failed to allocate unique test fake routable address"_ctv);
                           }
                        }
                     }
                  }
                  else if (request.kind == RoutableAddressKind::anyHostPublicAddress)
                  {
                     if (request.requestedAddress.size() > 0 || request.providerPool.size() > 0)
                     {
                        response.failure.assign("anyHostPublicAddress does not accept requestedAddress or providerPool"_ctv);
                     }
                     else
                     {
                        String addressText = {};
                        targetMachine = chooseMachineForPublicRoute(request.family, request.machineUUID, resolved.address, &addressText);
                        if (targetMachine == nullptr)
                        {
                           response.failure.assign("no machine with a matching public routable address is available"_ctv);
                        }
                        else if (neuronControlStreamActive(targetMachine) == false)
                        {
                           response.failure.assign("target machine neuron control stream is not active"_ctv);
                        }
                     }
                  }
                  else if (request.kind == RoutableAddressKind::providerElasticAddress)
                  {
                     if (iaas == nullptr)
                     {
                        response.failure.assign("provider elastic address requires active iaas runtime"_ctv);
                     }
                     else
                     {
                        if (request.machineUUID != 0)
                        {
                           targetMachine = findMachineByUUID(request.machineUUID);
                        }

                        if (targetMachine == nullptr)
                        {
                           Vector<Machine *> sorted = {};
                           for (Machine *machine : machines)
                           {
                              if (machine != nullptr && machine->cloudID.size() > 0)
                              {
                                 sorted.push_back(machine);
                              }
                           }

                           std::sort(sorted.begin(), sorted.end(), [] (const Machine *lhs, const Machine *rhs) -> bool {
                              return prodigyMachineIdentityComesBefore(*lhs, *rhs);
                           });

                           if (sorted.empty() == false)
                           {
                              targetMachine = sorted[0];
                           }
                        }

                        if (targetMachine == nullptr)
                        {
                           response.failure.assign("provider elastic address requires a cloud-backed target machine"_ctv);
                        }
                        else if (neuronControlStreamActive(targetMachine) == false)
                        {
                           response.failure.assign("target machine neuron control stream is not active"_ctv);
                        }
                        else
                        {
                           bool releaseOnRemove = false;
                           String allocationID = {};
                           String associationID = {};
                           if (iaas->assignProviderElasticAddress(targetMachine,
                              request.family,
                              request.requestedAddress,
                              request.providerPool,
                              resolved.address,
                              allocationID,
                              associationID,
                              releaseOnRemove,
                              response.failure) == false)
                           {
                              resolved.address = {};
                           }
                           else
                           {
                              resolved.providerAllocationID = allocationID;
                              resolved.providerAssociationID = associationID;
                              resolved.releaseOnRemove = releaseOnRemove;
                           }
                        }
                     }
                  }

                  if (response.failure.size() == 0 && targetMachine != nullptr)
                  {
                     if (const RegisteredRoutableAddress *duplicate = findRegisteredRoutableAddressByConcreteAddress(brainConfig.routableAddresses, resolved.address);
                        duplicate != nullptr)
                     {
                        response.failure.assign("routable address already registered; unregister the existing entry first"_ctv);
                     }
                  }

                  if (response.failure.size() == 0 && targetMachine != nullptr)
                  {
                     resolved.machineUUID = targetMachine->uuid;

                     if (resolved.uuid == 0)
                     {
                        resolved.uuid = Random::generateNumberWithNBits<128, uint128_t>();
                     }

                     brainConfig.routableAddresses.push_back(resolved);
                     refreshAllDeploymentRegisteredRoutableAddressWormholes();
                     for (Machine *machine : machines)
                     {
                        if (machine != nullptr)
                        {
                           sendNeuronSwitchboardStateSync(machine);
                        }
                     }

                     String serializedBrainConfig = {};
                     BitseryEngine::serialize(serializedBrainConfig, brainConfig);
                     queueBrainReplication(BrainTopic::replicateBrainConfig, serializedBrainConfig);
                     persistLocalRuntimeState();

                     response.success = true;
                     response.created = true;
                     response.uuid = resolved.uuid;
                     response.machineUUID = resolved.machineUUID;
                     response.address = resolved.address;
                  }
               }
            }

            response.name = request.name;
            response.kind = request.kind;
            response.family = request.family;
            response.requestedAddress = request.requestedAddress;
            response.providerPool = request.providerPool;

            String serializedResponse = {};
            BitseryEngine::serialize(serializedResponse, response);
            Message::construct(mothership->wBuffer, MothershipTopic::registerRoutableAddress, serializedResponse);
            break;
         }
         case MothershipTopic::unregisterRoutableAddress:
         {
            String serializedRequest;
            Message::extractToStringView(args, serializedRequest);

            RoutableAddressUnregistration request = {};
            RoutableAddressUnregistration response = {};
            response.success = false;

            if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
            {
               response.failure.assign("invalid routable address unregister payload"_ctv);
            }
            else if (request.name.size() == 0 && request.uuid == 0)
            {
               response.failure.assign("name or uuid required"_ctv);
            }
            else
            {
               bool removed = false;
               for (auto it = brainConfig.routableAddresses.begin(); it != brainConfig.routableAddresses.end(); ++it)
               {
                  if (registeredRoutableAddressMatchesIdentity(*it, request.name, request.uuid) == false)
                  {
                     continue;
                  }

                  if (it->kind == RoutableAddressKind::providerElasticAddress)
                  {
                     if (iaas == nullptr)
                     {
                        response.failure.assign("provider elastic address cleanup requires active iaas runtime"_ctv);
                        break;
                     }

                     if (iaas->releaseProviderElasticAddress(*it, response.failure) == false)
                     {
                        break;
                     }
                  }

                  response.uuid = it->uuid;
                  if (response.name.size() == 0)
                  {
                     response.name = it->name;
                  }

                  brainConfig.routableAddresses.erase(it);
                  removed = true;
                  break;
               }

               if (response.failure.size() == 0)
               {
                  if (removed)
                  {
                     for (Machine *machine : machines)
                     {
                        if (machine != nullptr)
                        {
                           sendNeuronSwitchboardStateSync(machine);
                        }
                     }

                     String serializedBrainConfig = {};
                     BitseryEngine::serialize(serializedBrainConfig, brainConfig);
                     queueBrainReplication(BrainTopic::replicateBrainConfig, serializedBrainConfig);
                     persistLocalRuntimeState();
                  }

                  response.success = true;
                  response.removed = removed;
               }
            }

            if (response.name.size() == 0)
            {
               response.name = request.name;
            }
            if (response.uuid == 0)
            {
               response.uuid = request.uuid;
            }

            String serializedResponse = {};
            BitseryEngine::serialize(serializedResponse, response);
            Message::construct(mothership->wBuffer, MothershipTopic::unregisterRoutableAddress, serializedResponse);
            break;
         }
         case MothershipTopic::pullRoutableAddresses:
         {
            RoutableAddressRegistryReport response = {};
            response.addresses = brainConfig.routableAddresses;
            response.success = true;

            String serializedResponse = {};
            BitseryEngine::serialize(serializedResponse, response);
            Message::construct(mothership->wBuffer, MothershipTopic::pullRoutableAddresses, serializedResponse);
            break;
         }
			case MothershipTopic::pullClusterReport:
			{
				ClusterStatusReport report{};
				report.hasTopology = loadOrPersistAuthoritativeClusterTopology(report.topology);
				report.nMachines = machines.size();
            int64_t nowMs = Time::now<TimeResolution::ms>();
            BrainView *masterPeer = currentMasterPeer();
            const char *clusterProviderName = nullptr;
            switch (brainConfig.runtimeEnvironment.kind)
            {
               case ProdigyEnvironmentKind::gcp:
               case ProdigyEnvironmentKind::aws:
               case ProdigyEnvironmentKind::azure:
               case ProdigyEnvironmentKind::vultr:
               {
                  clusterProviderName = prodigyEnvironmentKindName(brainConfig.runtimeEnvironment.kind);
                  break;
               }
               default:
               {
                  break;
               }
            }

            auto machineStateName = [] (MachineState state) -> const char * {
               switch (state)
               {
                  case MachineState::deploying: return "deploying";
                  case MachineState::unknown: return "unknown";
                  case MachineState::healthy: return "healthy";
                  case MachineState::missing: return "missing";
                  case MachineState::unresponsive: return "unresponsive";
                  case MachineState::neuronRebooting: return "neuronRebooting";
                  case MachineState::hardRebooting: return "hardRebooting";
                  case MachineState::updatingOS: return "updatingOS";
                  case MachineState::hardwareFailure: return "hardwareFailure";
                  case MachineState::unreachable: return "unreachable";
                  case MachineState::decommissioning: return "decommissioning";
               }

               return "unknown";
            };

            auto machineSourceName = [&] (const Machine *machine) -> const char * {
               if (machine == nullptr)
               {
                  return "unknown";
               }

               if (machine->isThisMachine
                  && machine->cloudID.size() == 0
                  && brainConfig.runtimeEnvironment.kind == ProdigyEnvironmentKind::dev)
               {
                  return "local";
               }

               switch (ClusterMachineSource(machine->topologySource))
               {
                  case ClusterMachineSource::adopted: return "adopted";
                  case ClusterMachineSource::created: return "created";
               }

               return "unknown";
            };

            auto machineLifetimeName = [] (MachineLifetime lifetime) -> const char * {
               switch (lifetime)
               {
                  case MachineLifetime::owned: return "owned";
                  case MachineLifetime::reserved: return "reserved";
                  case MachineLifetime::ondemand: return "ondemand";
                  case MachineLifetime::spot: return "spot";
               }

               return "unknown";
            };

            auto updateSelfStateName = [] (UpdateSelfState state) -> const char * {
               switch (state)
               {
                  case UpdateSelfState::idle: return "idle";
                  case UpdateSelfState::waitingForBundleEchos: return "waitingForBundleEchos";
                  case UpdateSelfState::waitingForFollowerReboots: return "waitingForFollowerReboots";
                  case UpdateSelfState::waitingForRelinquishEchos: return "waitingForRelinquishEchos";
               }

               return "idle";
            };

            auto resolveApplicationName = [&] (uint16_t applicationID, String& applicationName) -> void {
               applicationName.clear();

               if (auto it = reservedApplicationNamesByID.find(applicationID); it != reservedApplicationNamesByID.end())
               {
                  applicationName.assign(it->second);
                  return;
               }

               applicationName.assign(MeshRegistry::applicationNameMappings[applicationID]);
            };

            auto sortAndDedupeTextList = [] (Vector<String>& values) -> void {
               std::sort(values.begin(), values.end(), [] (const String& lhs, const String& rhs) -> bool {
                  size_t common = std::min(lhs.size(), rhs.size());
                  int cmp = memcmp(lhs.data(), rhs.data(), common);
                  if (cmp != 0)
                  {
                     return cmp < 0;
                  }

                  return lhs.size() < rhs.size();
               });
               values.erase(std::unique(values.begin(), values.end(), [] (const String& lhs, const String& rhs) -> bool {
                  return lhs.size() == rhs.size()
                     && memcmp(lhs.data(), rhs.data(), lhs.size()) == 0;
               }), values.end());
            };

            auto resolveMachineUpdateStage = [&] (Machine *machine) -> const char * {
               if (machine == nullptr)
               {
                  return "idle";
               }

               if (machine->isBrain)
               {
                  if (machine->isThisMachine && isActiveMaster())
                  {
                     return updateSelfStateName(updateSelfState);
                  }

                  if (machine->brain != nullptr)
                  {
                     switch (updateSelfState)
                     {
                        case UpdateSelfState::waitingForBundleEchos:
                        {
                           return updateSelfBundleEchoPeerKeys.contains(updateSelfPeerTrackingKey(machine->brain)) ? "bundleEchoed" : "waitingForBundle";
                        }
                        case UpdateSelfState::waitingForFollowerReboots:
                        {
                           return updateSelfFollowerRebootedPeerKeys.contains(updateSelfPeerTrackingKey(machine->brain)) ? "rebooted" : "waitingForReboot";
                        }
                        case UpdateSelfState::waitingForRelinquishEchos:
                        {
                           return updateSelfRelinquishEchoPeerKeys.contains(updateSelfPeerTrackingKey(machine->brain)) ? "relinquishEchoed" : "waitingForRelinquishEcho";
                        }
                        case UpdateSelfState::idle:
                        {
                           break;
                        }
                     }
                  }
               }

               if (machine->state == MachineState::neuronRebooting || machine->state == MachineState::hardRebooting)
               {
                  return "rebooting";
               }

               if (machine->inBinaryUpdate)
               {
                  return "updating";
               }

               return "idle";
            };

            String localInstalledBundleSHA256 = {};
            {
               String installedBundlePath = {};
               prodigyResolveInstalledBundlePathForRoot("/root/prodigy"_ctv, installedBundlePath);
               if (prodigyFileReadable(installedBundlePath))
               {
                  String digestFailure = {};
                  (void)prodigyComputeFileSHA256Hex(installedBundlePath, localInstalledBundleSHA256, &digestFailure);
               }
            }

            String stagedBundleSHA256 = {};
            {
               String stagedBundlePath = prodigyStagedBundlePath();
               if (prodigyFileReadable(stagedBundlePath))
               {
                  String digestFailure = {};
                  (void)prodigyComputeFileSHA256Hex(stagedBundlePath, stagedBundleSHA256, &digestFailure);
               }
            }

				for (Machine *machine : machines)
				{
					if (machine->lifetime == MachineLifetime::spot) report.nSpotMachines += 1;

               MachineStatusReport& mreport = report.machineReports.emplace_back();
               mreport.state.assign(machineStateName(machine->state));
               mreport.isBrain = machine->isBrain;
               mreport.controlPlaneReachable = neuronControlStreamActive(machine);
               mreport.currentMaster = machine->isBrain
                  && ((machine->isThisMachine && isActiveMaster())
                     || (machine->brain != nullptr && machine->brain == masterPeer));
               mreport.decommissioning = (machine->state == MachineState::decommissioning);
               mreport.rebooting = (machine->state == MachineState::neuronRebooting || machine->state == MachineState::hardRebooting);
               mreport.updatingOS = (machine->state == MachineState::updatingOS);
               mreport.hardwareFailure = (machine->state == MachineState::hardwareFailure || machine->hardwareFailureReport.size() > 0);
               mreport.bootTimeMs = machine->lastUpdatedOSMs;
               if (machine->lastUpdatedOSMs > 0 && machine->lastUpdatedOSMs <= nowMs)
               {
                  mreport.uptimeMs = nowMs - machine->lastUpdatedOSMs;
               }
               if (machine->uuid != 0)
               {
                  mreport.machineUUID.assignItoh(machine->uuid);
               }
               mreport.source.assign(machineSourceName(machine));
               mreport.backing.assign(clusterMachineBackingName(machine->cloudID.size() > 0 ? ClusterMachineBacking::cloud : ClusterMachineBacking::owned));
               mreport.lifetime.assign(machineLifetimeName(machine->lifetime));
               if (machine->cloudID.size() > 0 && clusterProviderName != nullptr && clusterProviderName[0] != '\0')
               {
                  mreport.provider.assign(clusterProviderName);
               }
               mreport.region.assign(machine->region);
               mreport.zone.assign(machine->zone);
               mreport.rackUUID = machine->rackUUID;
               if (machine->cloudID.size() > 0 || machine->slug.size() > 0 || machine->type.size() > 0)
               {
                  mreport.hasCloud = true;
                  mreport.cloud.schema.assign(machine->slug);
                  mreport.cloud.providerMachineType.assign(machine->type);
                  mreport.cloud.cloudID.assign(machine->cloudID);
               }
               String resolvedSSHAddress = {};
               if (prodigyResolveMachineSSHAddress(*machine, resolvedSSHAddress))
               {
                  mreport.ssh.address = resolvedSSHAddress;
               }
               mreport.ssh.port = machine->sshPort > 0 ? machine->sshPort : 22;
               mreport.ssh.user.assign(machine->sshUser);
               mreport.ssh.privateKeyPath.assign(machine->sshPrivateKeyPath);
               mreport.ssh.hostPublicKeyOpenSSH.assign(machine->sshHostPublicKeyOpenSSH);
               prodigyAssignClusterMachineAddressesFromPeerCandidates(mreport.addresses, machine->peerAddresses);
               prodigyAppendUniqueClusterMachineAddress(mreport.addresses.publicAddresses, machine->publicAddress);
               String privateGateway = {};
               if (machine->gatewayPrivate4 != 0)
               {
                  IPAddress gatewayAddress = {};
                  gatewayAddress.v4 = machine->gatewayPrivate4;
                  gatewayAddress.is6 = false;
                  (void)ClusterMachine::renderIPAddressLiteral(gatewayAddress, privateGateway);
               }
               prodigyAppendUniqueClusterMachineAddress(mreport.addresses.privateAddresses, machine->privateAddress, 0, privateGateway);
               mreport.totalLogicalCores = machine->totalLogicalCores;
               mreport.totalMemoryMB = machine->totalMemoryMB;
               mreport.totalStorageMB = machine->totalStorageMB;
               mreport.ownedLogicalCores = machine->ownedLogicalCores;
               mreport.ownedMemoryMB = machine->ownedMemoryMB;
               mreport.ownedStorageMB = machine->ownedStorageMB;
               for (const Machine::Claim& claim : machine->claims)
               {
                  if (claim.nFit == 0)
                  {
                     continue;
                  }

                  mreport.reservedContainers += claim.nFit;
                  mreport.reservedIsolatedLogicalCores += (claim.reservedIsolatedLogicalCoresPerInstance * claim.nFit);
                  mreport.reservedSharedCPUMillis += (claim.reservedSharedCPUMillisPerInstance * claim.nFit);
                  mreport.reservedMemoryMB += (claim.reservedMemoryMBPerInstance * claim.nFit);
                  mreport.reservedStorageMB += (claim.reservedStorageMBPerInstance * claim.nFit);
               }

               for (const auto& [deploymentID, indexedContainers] : machine->containersByDeploymentID)
               {
                  auto deploymentIt = deployments.find(deploymentID);
                  if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
                  {
                     continue;
                  }

                  ApplicationDeployment *deployment = deploymentIt->second;
                  const ApplicationConfig& config = deployment->plan.config;

                  String deploymentIDText = {};
                  deploymentIDText.snprintf<"{itoa}"_ctv>(deploymentID);
                  mreport.deploymentIDs.push_back(deploymentIDText);

                  String applicationName = {};
                  resolveApplicationName(ApplicationConfig::extractApplicationID(deploymentID), applicationName);
                  if (applicationName.size() > 0)
                  {
                     mreport.applicationNames.push_back(applicationName);
                  }

                  for (ContainerView *container : indexedContainers)
                  {
                     if (container == nullptr || container->state == ContainerState::destroyed)
                     {
                        continue;
                     }

                     if (container->uuid != 0)
                     {
                        String containerUUIDText = {};
                        containerUUIDText.assignItoh(container->uuid);
                        mreport.deployedContainers.push_back(containerUUIDText);
                     }

                     if (deployment->plan.isStateful)
                     {
                        String shardGroupText = {};
                        shardGroupText.snprintf<"{itoa}"_ctv>(container->shardGroup);
                        mreport.shardGroups.push_back(shardGroupText);
                     }

                     mreport.activeContainers += 1;
                     mreport.activeIsolatedLogicalCores += applicationRequiredIsolatedCores(config);
                     if (applicationUsesSharedCPUs(config))
                     {
                        mreport.activeSharedCPUMillis += applicationRequestedCPUMillis(config);
                     }
                     mreport.activeMemoryMB += config.totalMemoryMB();
                     mreport.activeStorageMB += config.totalStorageMB();
                  }
               }

               sortAndDedupeTextList(mreport.deployedContainers);
               sortAndDedupeTextList(mreport.applicationNames);
               sortAndDedupeTextList(mreport.deploymentIDs);
               sortAndDedupeTextList(mreport.shardGroups);

               if (machine->isThisMachine)
               {
                  mreport.approvedBundleSHA256.assign(localInstalledBundleSHA256);
               }
               if (machine->isThisMachine && version > 0)
               {
                  mreport.runningProdigyVersion.snprintf<"{itoa}"_ctv>(version);
               }
               else if (machine->brain != nullptr && machine->brain->version > 0)
               {
                  mreport.runningProdigyVersion.snprintf<"{itoa}"_ctv>(machine->brain->version);
               }
               mreport.updateStage.assign(resolveMachineUpdateStage(machine));
               if (machine->isBrain && stagedBundleSHA256.size() > 0)
               {
                  mreport.stagedBundleSHA256.assign(stagedBundleSHA256);
               }
               mreport.hardware = machine->hardware;
				}

				uint32_t nApplications;

				report.nApplications = deploymentsByApp.size();

				for (const auto& [applicationID, deployment] : deploymentsByApp)
				{
					ApplicationStatusReport& areport = report.applicationReports.emplace_back();
					areport.applicationID = applicationID;
					if (auto byID = reservedApplicationNamesByID.find(applicationID); byID != reservedApplicationNamesByID.end())
					{
						areport.applicationName = byID->second;
					}

					ApplicationDeployment *workingDeployment = deployment;

					do
					{
						areport.deploymentReports.push_back(workingDeployment->generateReport());
						workingDeployment = workingDeployment->previous;

					} while (workingDeployment);
				}

            prodigyPrepareClusterStatusReportForTransport(report);

				String serializedReport;
				BitseryEngine::serialize(serializedReport, report);

				basics_log("mothershipHandler pullClusterReport nMachines=%u nApps=%u bytes=%u\n", report.nMachines, report.nApplications, uint32_t(serializedReport.size()));
					std::fprintf(stderr, "prodigy mothership pullClusterReport-response nMachines=%u nApps=%u bytes=%zu\n",
						report.nMachines,
						report.nApplications,
						size_t(serializedReport.size()));
					std::fflush(stderr);
					Message::construct(mothership->wBuffer, MothershipTopic::pullClusterReport, serializedReport);
					{
						uint8_t sample[16] = {0};
						size_t sampleCount = (mothership->wBuffer.size() < sizeof(sample) ? size_t(mothership->wBuffer.size()) : sizeof(sample));
						if (sampleCount > 0)
						{
							memcpy(sample, mothership->wBuffer.data(), sampleCount);
						}
						std::fprintf(stderr,
							"prodigy mothership pullClusterReport-frame bytes=%zu sampleBytes=%zu sample=%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
							size_t(mothership->wBuffer.size()),
							sampleCount,
							unsigned(sample[0]),
							unsigned(sample[1]),
							unsigned(sample[2]),
							unsigned(sample[3]),
							unsigned(sample[4]),
							unsigned(sample[5]),
							unsigned(sample[6]),
							unsigned(sample[7]),
							unsigned(sample[8]),
							unsigned(sample[9]),
							unsigned(sample[10]),
							unsigned(sample[11]),
							unsigned(sample[12]),
							unsigned(sample[13]),
							unsigned(sample[14]),
							unsigned(sample[15]));
						std::fflush(stderr);
					}
					break;
				}
			case MothershipTopic::pullApplicationReport:
      {
				// applicationID(2)
				uint16_t applicationID;
				Message::extractArg<ArgumentNature::fixed>(args, applicationID);

					const auto debugPullApplicationReportMetrics = [&]() -> std::tuple<uint64_t, uint64_t, uint64_t> {
#if USE_MIMALLOC == 0
						struct mallinfo2 info = mallinfo2();
						return {
							uint64_t(info.uordblks),
							uint64_t(info.hblkhd),
							uint64_t(info.fordblks)
						};
#else
						return {0, 0, 0};
#endif
					};

				uint64_t chainCount = 0;
				uint64_t totalContainers = 0;
				uint64_t totalWaitingOnContainers = 0;
				uint64_t totalScheduledWork = 0;
				uint64_t totalFailureReports = 0;
				uint64_t currentContainers = 0;
				uint64_t currentWaitingOnContainers = 0;
				uint64_t currentScheduledWork = 0;
				uint64_t serializedBytes = 0;

				if (auto it = deploymentsByApp.find(applicationID); it != deploymentsByApp.end())
				{
					for (ApplicationDeployment *workingDeployment = it->second; workingDeployment; workingDeployment = workingDeployment->previous)
					{
						++chainCount;
						const uint64_t containersCount = workingDeployment->containers.size();
						const uint64_t waitingCount = workingDeployment->waitingOnContainers.size();
						const uint64_t scheduledCount = workingDeployment->toSchedule.size();

						totalContainers += containersCount;
						totalWaitingOnContainers += waitingCount;
						totalScheduledWork += scheduledCount;
						totalFailureReports += workingDeployment->failureReports.size();

						if (chainCount == 1)
						{
							currentContainers = containersCount;
							currentWaitingOnContainers = waitingCount;
							currentScheduledWork = scheduledCount;
						}
					}
				}

				const auto [heapUsedBefore, heapMappedBefore, heapFreeBefore] = debugPullApplicationReportMetrics();

				{
					ApplicationStatusReport report{};
					report.applicationID = applicationID;
					if (auto byID = reservedApplicationNamesByID.find(applicationID); byID != reservedApplicationNamesByID.end())
					{
						report.applicationName = byID->second;
					}

					if (auto it = deploymentsByApp.find(applicationID); it != deploymentsByApp.end())
					{
						ApplicationDeployment *workingDeployment = it->second;

						do
						{
							report.deploymentReports.push_back(workingDeployment->generateReport());
							workingDeployment = workingDeployment->previous;

						} while (workingDeployment);

					}

					String serializedReport;
					BitseryEngine::serialize(serializedReport, report);
					serializedBytes = serializedReport.size();

					Message::construct(mothership->wBuffer, MothershipTopic::pullApplicationReport, serializedReport);
				}

				const auto [heapUsedAfter, heapMappedAfter, heapFreeAfter] = debugPullApplicationReportMetrics();
				static uint64_t debugPullApplicationReportCount = 0;
				++debugPullApplicationReportCount;

				if (debugPullApplicationReportCount <= 8
					|| (debugPullApplicationReportCount % 8) == 0
					|| heapUsedAfter > (1024ull * 1024ull * 1024ull)
					|| heapMappedAfter > (1024ull * 1024ull * 1024ull))
				{
					std::fprintf(stderr,
						"prodigy debug pullApplicationReport-stats count=%llu appID=%u chain=%llu currentContainers=%llu currentWaiting=%llu currentSchedule=%llu totalContainers=%llu totalWaiting=%llu totalSchedule=%llu failureReports=%llu serializedBytes=%llu wbytes=%u heapUsedBefore=%llu heapMappedBefore=%llu heapFreeBefore=%llu heapUsedAfter=%llu heapMappedAfter=%llu heapFreeAfter=%llu\n",
						(unsigned long long)debugPullApplicationReportCount,
						unsigned(applicationID),
						(unsigned long long)chainCount,
						(unsigned long long)currentContainers,
						(unsigned long long)currentWaitingOnContainers,
						(unsigned long long)currentScheduledWork,
						(unsigned long long)totalContainers,
						(unsigned long long)totalWaitingOnContainers,
						(unsigned long long)totalScheduledWork,
						(unsigned long long)totalFailureReports,
						(unsigned long long)serializedBytes,
						unsigned(mothership ? mothership->wBuffer.outstandingBytes() : 0u),
						(unsigned long long)heapUsedBefore,
						(unsigned long long)heapMappedBefore,
						(unsigned long long)heapFreeBefore,
						(unsigned long long)heapUsedAfter,
						(unsigned long long)heapMappedAfter,
						(unsigned long long)heapFreeAfter);
					std::fflush(stderr);
				}

				break;;
			}
			case MothershipTopic::updateProdigy:
			{
				// bundleBlob{4}

				String newBundle;
				Message::extractToStringView(args, newBundle);

				Filesystem::openWriteAtClose(-1, prodigyStagedBundlePath(), newBundle);

				// Persist payload for retries in distributed mode by default.
				// The staged fast path is only safe when every brain shares one writable
				// /root staging area, so it is opt-in via PRODIGY_DEV_SHARED_STAGE_BUNDLE=1.
				updateSelfUseStagedBundleOnly = devSharedStagedBundleEnabled();
				if (updateSelfUseStagedBundleOnly)
				{
					updateSelfBundleBlob.clear();
				}
				else
				{
					updateSelfBundleBlob.assign(newBundle);
				}

				uint32_t expectedPeerEchos = 0;
				for (BrainView *bv : brains)
				{
					if (peerSocketActive(bv))
					{
						expectedPeerEchos += 1;
					}
				}

				// now wait for the echos
				beginUpdateSelfBundle(expectedPeerEchos);

         break;
      }
			case MothershipTopic::reserveApplicationID:
			{
				// request{4}
				String serializedRequest;
				Message::extractToStringView(args, serializedRequest);

				ApplicationIDReserveRequest request;
				ApplicationIDReserveResponse response;
				response.success = false;

				if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
				{
					response.failure.assign("invalid request payload"_ctv);
				}
				else if (isValidReservedApplicationName(request.applicationName) == false)
				{
					response.failure.assign("applicationName invalid"_ctv);
				}
				else
				{
					response.applicationName = request.applicationName;

					if (auto byName = reservedApplicationIDsByName.find(request.applicationName); byName != reservedApplicationIDsByName.end())
					{
						response.applicationID = byName->second;
						if (request.requestedApplicationID != 0 && request.requestedApplicationID != response.applicationID)
						{
							response.failure.assign("applicationName already reserved with different applicationID"_ctv);
						}
						else
						{
							response.success = true;
							response.created = false;
						}
					}
					else
					{
						if (request.createIfMissing == false)
						{
							response.failure.assign("applicationName not reserved"_ctv);
						}
						else
						{
							uint16_t assignedApplicationID = 0;
							if (request.requestedApplicationID != 0)
							{
								assignedApplicationID = request.requestedApplicationID;
							}
							else
							{
								assignedApplicationID = takeNextReservableApplicationID();
								if (assignedApplicationID == 0)
								{
									response.failure.assign("applicationID allocation exhausted"_ctv);
								}
							}

							if (assignedApplicationID != 0)
							{
								String reserveFailure;
								if (reserveApplicationIDMapping(request.applicationName, assignedApplicationID, &reserveFailure) == false)
								{
									response.failure = reserveFailure;
								}
								else
								{
									if (nBrains > 1)
									{
										queueBrainReplication(BrainTopic::replicateApplicationIDReservation, assignedApplicationID, request.applicationName);
									}

									response.applicationID = assignedApplicationID;
									response.success = true;
									response.created = true;
                           persistLocalRuntimeState();
								}
							}
						}
					}
               }

					String serializedResponse;
					BitseryEngine::serialize(serializedResponse, response);
				Message::construct(mothership->wBuffer, MothershipTopic::reserveApplicationID, serializedResponse);
				break;
			}
			case MothershipTopic::reserveServiceID:
			{
				// request{4}
				String serializedRequest;
				Message::extractToStringView(args, serializedRequest);

				ApplicationServiceReserveRequest request;
				ApplicationServiceReserveResponse response;
				response.success = false;

				if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
				{
					response.failure.assign("invalid request payload"_ctv);
				}
				else if (request.serviceName.size() == 0)
				{
					response.failure.assign("serviceName required"_ctv);
				}
				else
				{
					uint16_t applicationID = request.applicationID;
					if (applicationID == 0 && request.applicationName.size() > 0)
					{
						if (resolveReservedApplicationID(request.applicationName, applicationID) == false)
						{
							response.failure.assign("applicationName not reserved"_ctv);
						}
					}

					if (response.failure.size() == 0)
					{
						if (applicationID == 0)
						{
							response.failure.assign("applicationID required"_ctv);
						}
						else if (isApplicationIDReserved(applicationID) == false)
						{
							response.failure.assign("applicationID not reserved"_ctv);
						}
						else
						{
							response.applicationID = applicationID;
							if (auto byID = reservedApplicationNamesByID.find(applicationID); byID != reservedApplicationNamesByID.end())
							{
								response.applicationName = byID->second;
							}
							else
							{
								response.applicationName = request.applicationName;
							}
							response.serviceName = request.serviceName;

							ApplicationServiceIdentity existing;
							if (resolveReservedApplicationService(applicationID, request.serviceName, existing))
							{
								if (request.requestedServiceSlot != 0 && request.requestedServiceSlot != existing.serviceSlot)
								{
									response.failure.assign("serviceName already reserved with different serviceSlot"_ctv);
								}
								else if (request.kind != ApplicationServiceIdentity::Kind::unspecified && request.kind != existing.kind)
								{
									response.failure.assign("serviceName already reserved with different kind"_ctv);
								}
								else
								{
									response.service = materializeReservedService(existing);
									response.serviceSlot = existing.serviceSlot;
									response.kind = existing.kind;
									response.success = true;
									response.created = false;
								}
							}
							else if (request.createIfMissing == false)
							{
								response.failure.assign("serviceName not reserved"_ctv);
							}
							else
							{
								ApplicationServiceIdentity identity;
								identity.applicationID = applicationID;
								identity.serviceName = request.serviceName;
								identity.kind = request.kind;

								if (request.kind == ApplicationServiceIdentity::Kind::unspecified)
								{
									response.failure.assign("service kind required to create service"_ctv);
								}
								else if (request.requestedServiceSlot != 0)
								{
									identity.serviceSlot = request.requestedServiceSlot;
								}
								else
								{
									identity.serviceSlot = takeNextReservableServiceSlot(applicationID);
									if (identity.serviceSlot == 0)
									{
										response.failure.assign("serviceSlot allocation exhausted"_ctv);
									}
								}

								if (response.failure.size() == 0)
								{
									String reserveFailure;
										if (reserveApplicationServiceMapping(identity, &reserveFailure) == false)
										{
											response.failure = reserveFailure;
										}
										else
									{
										if (nBrains > 1)
										{
											String serializedIdentity;
											BitseryEngine::serialize(serializedIdentity, identity);
											queueBrainReplication(BrainTopic::replicateApplicationServiceReservation, serializedIdentity);
										}

											response.service = materializeReservedService(identity);
											response.serviceSlot = identity.serviceSlot;
											response.kind = identity.kind;
											response.success = true;
											response.created = true;
											persistLocalRuntimeState();
										}
									}
								}
							}
						}
				}

				String serializedResponse;
				BitseryEngine::serialize(serializedResponse, response);
				Message::construct(mothership->wBuffer, MothershipTopic::reserveServiceID, serializedResponse);
				break;
			}
			case MothershipTopic::upsertTlsVaultFactory:
			{
				// request{4}
				String serializedRequest;
				Message::extractToStringView(args, serializedRequest);

				TlsVaultFactoryUpsertRequest request;
				TlsVaultFactoryUpsertResponse response;
				response.success = false;
				response.applicationID = 0;

				if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
				{
					response.failure.assign("invalid request payload"_ctv);
				}
				else if (request.applicationID == 0)
				{
					response.failure.assign("applicationID required"_ctv);
				}
				else if (request.mode > 1)
				{
					response.failure.assign("mode invalid"_ctv);
				}
				else if (request.renewLeadPercent == 0 || request.renewLeadPercent >= 100)
				{
					response.failure.assign("renewLeadPercent must be in 1..99"_ctv);
				}
				else
				{
					response.applicationID = request.applicationID;

					bool created = false;
					ApplicationTlsVaultFactory factory;
					if (auto it = tlsVaultFactoriesByApp.find(request.applicationID); it != tlsVaultFactoriesByApp.end())
					{
						factory = it->second;
					}
					else
					{
						created = true;
						factory.applicationID = request.applicationID;
						factory.factoryGeneration = 0;
						factory.createdAtMs = Time::now<TimeResolution::ms>();
					}

					factory.updatedAtMs = Time::now<TimeResolution::ms>();
					factory.keySourceMode = request.mode;
					factory.scheme = request.scheme;
					if (request.defaultLeafValidityDays > 0)
					{
						factory.defaultLeafValidityDays = request.defaultLeafValidityDays;
					}
					factory.renewLeadPercent = request.renewLeadPercent;

					if (request.mode == 0)
					{
						X509 *rootCert = nullptr;
						EVP_PKEY *rootKey = nullptr;
						X509 *interCert = nullptr;
						EVP_PKEY *interKey = nullptr;

						CryptoScheme scheme = (request.scheme == uint8_t(CryptoScheme::ed25519)) ? CryptoScheme::ed25519 : CryptoScheme::p256;
						VaultCertificateRequest rootRequest = {};
						rootRequest.type = CertificateType::root;
						rootRequest.scheme = scheme;
						generateCertificateAndKeys(rootRequest, nullptr, nullptr, rootCert, rootKey);

						VaultCertificateRequest intermediateRequest = {};
						intermediateRequest.type = CertificateType::intermediary;
						intermediateRequest.scheme = scheme;
						generateCertificateAndKeys(intermediateRequest, rootCert, rootKey, interCert, interKey);

						bool ok = VaultPem::x509ToPem(rootCert, factory.rootCertPem)
							&& VaultPem::privateKeyToPem(rootKey, factory.rootKeyPem)
							&& VaultPem::x509ToPem(interCert, factory.intermediateCertPem)
							&& VaultPem::privateKeyToPem(interKey, factory.intermediateKeyPem);

						if (ok == false)
						{
							response.failure.assign("failed to generate PEM payloads"_ctv);
						}
						else
						{
							response.generatedRootCertPem = factory.rootCertPem;
							response.generatedRootKeyPem = factory.rootKeyPem;
							response.generatedIntermediateCertPem = factory.intermediateCertPem;
							response.generatedIntermediateKeyPem = factory.intermediateKeyPem;
						}

						if (rootCert) X509_free(rootCert);
						if (rootKey) EVP_PKEY_free(rootKey);
						if (interCert) X509_free(interCert);
						if (interKey) EVP_PKEY_free(interKey);
					}
						else
						{
							if (request.importRootCertPem.size() == 0 ||
								request.importRootKeyPem.size() == 0 ||
							request.importIntermediateCertPem.size() == 0 ||
							request.importIntermediateKeyPem.size() == 0)
						{
							response.failure.assign("import mode requires root/intermediate cert+key"_ctv);
						}
                  else
                  {
							factory.rootCertPem = request.importRootCertPem;
							factory.rootKeyPem = request.importRootKeyPem;
							factory.intermediateCertPem = request.importIntermediateCertPem;
							factory.intermediateKeyPem = request.importIntermediateKeyPem;
                  }
						}

                  if (response.failure.size() == 0)
                  {
                     String validationFailure;
                     if (validateApplicationTlsVaultFactoryMaterial(factory, &validationFailure) == false)
                     {
                        response.failure = validationFailure;
                     }
                  }

               if (response.failure.size() == 0)
               {
							factory.factoryGeneration += 1;
							tlsVaultFactoriesByApp.insert_or_assign(request.applicationID, factory);
                     persistLocalRuntimeState();

							response.success = true;
							response.created = created;
					response.mode = factory.keySourceMode;
						response.factoryGeneration = factory.factoryGeneration;
						response.effectiveLeafValidityDays = factory.defaultLeafValidityDays;
						response.effectiveRenewLeadPercent = factory.renewLeadPercent;

						if (nBrains > 1)
						{
							String serializedFactory;
							BitseryEngine::serialize(serializedFactory, factory);
							queueBrainReplication(BrainTopic::replicateTlsVaultFactory, serializedFactory);
						}
					}
            }

				String serializedResponse;
				BitseryEngine::serialize(serializedResponse, response);
				Message::construct(mothership->wBuffer, MothershipTopic::upsertTlsVaultFactory, serializedResponse);
				break;
			}
			case MothershipTopic::upsertApiCredentialSet:
			{
				// request{4}
				String serializedRequest;
				Message::extractToStringView(args, serializedRequest);

				ApiCredentialSetUpsertRequest request;
				ApiCredentialSetUpsertResponse response;
				response.success = false;
				response.applicationID = 0;

				if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
				{
					response.failure.assign("invalid request payload"_ctv);
				}
				else if (request.applicationID == 0)
				{
					response.failure.assign("applicationID required"_ctv);
				}
				else
				{
					response.applicationID = request.applicationID;

					ApplicationApiCredentialSet set;
					bool created = false;
					if (auto it = apiCredentialSetsByApp.find(request.applicationID); it != apiCredentialSetsByApp.end())
					{
						set = it->second;
					}
					else
					{
						created = true;
						set.applicationID = request.applicationID;
						set.createdAtMs = Time::now<TimeResolution::ms>();
						set.setGeneration = 0;
					}

					uint64_t nextSetGeneration = set.setGeneration + 1;
					bytell_hash_map<String, ApiCredential> merged;
					for (ApiCredential& existing : set.credentials)
					{
						merged.insert_or_assign(existing.name, existing);
					}

					bool invalidName = false;
					for (ApiCredential credential : request.upsertCredentials)
					{
						if (credential.name.size() == 0)
						{
							invalidName = true;
							break;
						}
						if (credential.generation == 0)
						{
							credential.generation = nextSetGeneration;
						}

						merged.insert_or_assign(credential.name, credential);
						response.updatedNames.push_back(credential.name);
					}

					if (invalidName)
					{
						response.failure.assign("credential name must not be empty"_ctv);
					}
					else
					{
						for (const String& name : request.removeCredentialNames)
						{
							if (name.size() == 0) continue;
							if (merged.find(name) != merged.end())
							{
								merged.erase(name);
								response.removedNames.push_back(name);
							}
						}

						set.credentials.clear();
						for (const auto& [name, credential] : merged)
						{
							(void)name;
							set.credentials.push_back(credential);
						}

							set.setGeneration = nextSetGeneration;
							set.updatedAtMs = Time::now<TimeResolution::ms>();
							apiCredentialSetsByApp.insert_or_assign(request.applicationID, set);

							response.setGeneration = set.setGeneration;
							response.success = true;
							(void)created;

								if (nBrains > 1)
								{
									String serializedSet;
									BitseryEngine::serialize(serializedSet, set);
									queueBrainReplication(BrainTopic::replicateApiCredentialSet, serializedSet);
								}

                        persistLocalRuntimeState();

								pushApiCredentialDeltaToLiveContainers(request.applicationID, set, response.updatedNames, response.removedNames, request.reason);
							}
					}

				String serializedResponse;
				BitseryEngine::serialize(serializedResponse, response);
				Message::construct(mothership->wBuffer, MothershipTopic::upsertApiCredentialSet, serializedResponse);
				break;
			}
			case MothershipTopic::mintClientTlsIdentity:
			{
				// request{4}
				String serializedRequest;
				Message::extractToStringView(args, serializedRequest);

				ClientTlsMintRequest request;
				ClientTlsMintResponse response;
				response.success = false;
				response.applicationID = 0;

				if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
				{
					response.failure.assign("invalid request payload"_ctv);
				}
				else if (request.applicationID == 0)
				{
					response.failure.assign("applicationID required"_ctv);
				}
				else if (request.name.size() == 0)
				{
					response.failure.assign("name required"_ctv);
				}
				else
				{
					response.applicationID = request.applicationID;
					response.name = request.name;

					auto factoryIt = tlsVaultFactoriesByApp.find(request.applicationID);
					if (factoryIt == tlsVaultFactoriesByApp.end())
					{
						response.failure.assign("no pre-existing vault factory for applicationID"_ctv);
					}
					else
					{
						const ApplicationTlsVaultFactory& factory = factoryIt->second;
						X509 *interCert = VaultPem::x509FromPem(factory.intermediateCertPem);
						EVP_PKEY *interKey = VaultPem::privateKeyFromPem(factory.intermediateKeyPem);
						if (interCert == nullptr || interKey == nullptr)
						{
							response.failure.assign("stored intermediate material is invalid"_ctv);
							if (interCert) X509_free(interCert);
							if (interKey) EVP_PKEY_free(interKey);
						}
						else
						{
							CryptoScheme scheme = (request.scheme == uint8_t(CryptoScheme::ed25519)) ? CryptoScheme::ed25519 : CryptoScheme::p256;
							X509 *clientCert = nullptr;
							EVP_PKEY *clientKey = nullptr;
							VaultCertificateRequest clientRequest = {};
							clientRequest.type = CertificateType::client;
							clientRequest.scheme = scheme;
							clientRequest.subjectCommonName = request.name;
							clientRequest.enableClientAuth = true;
							generateCertificateAndKeys(clientRequest, interCert, interKey, clientCert, clientKey);

							uint32_t validityDays = request.validityDays > 0 ? request.validityDays : factory.defaultLeafValidityDays;
							if (validityDays == 0) validityDays = 15;
							X509_gmtime_adj(X509_getm_notBefore(clientCert), 0);
							X509_time_adj_ex(X509_getm_notAfter(clientCert), int(validityDays), 0, nullptr);
							(void)X509_sign(clientCert, interKey, (scheme == CryptoScheme::ed25519) ? nullptr : EVP_sha256());

							bool ok = VaultPem::x509ToPem(clientCert, response.certPem) && VaultPem::privateKeyToPem(clientKey, response.keyPem);
								if (ok)
								{
									response.chainPem = factory.intermediateCertPem;
									response.chainPem.append(factory.rootCertPem);
									response.generation = nextMintedClientTlsGeneration++;
								response.issuerFactoryGeneration = factory.factoryGeneration;
									response.notBeforeMs = Time::now<TimeResolution::ms>();
									response.notAfterMs = response.notBeforeMs + int64_t(validityDays) * 24 * 60 * 60 * 1000;
									response.success = true;
                           noteMasterAuthorityRuntimeStateChanged();
								}
							else
							{
								response.failure.assign("failed to mint or encode client cert"_ctv);
							}

							if (clientCert) X509_free(clientCert);
							if (clientKey) EVP_PKEY_free(clientKey);
							if (interCert) X509_free(interCert);
							if (interKey) EVP_PKEY_free(interKey);
						}
					}
				}

				String serializedResponse;
				BitseryEngine::serialize(serializedResponse, response);
				Message::construct(mothership->wBuffer, MothershipTopic::mintClientTlsIdentity, serializedResponse);
				break;
			}
			case MothershipTopic::measureApplication:
			{
				// plan{4}

				String serializedPlan;
				Message::extractToStringView(args, serializedPlan);

				ApplicationDeployment *deployment = new ApplicationDeployment();

				BitseryEngine::deserialize(serializedPlan, deployment->plan);

				if (auto it = deploymentsByApp.find(deployment->plan.config.applicationID); it != deploymentsByApp.end())
				{
					deployment->previous = it->second;
				}

				// we could schedule this many
				uint32_t nFit = deployment->measure();

            if (nFit == 0 && deployment->plan.whiteholes.empty() == false)
            {
               basics_log(
                  "measureApplication whitehole-fit-zero deploymentID=%llu targetBase=%u targetSurge=%u whiteholes=%u machines=%u\n",
                  (unsigned long long)deployment->plan.config.deploymentID(),
                  unsigned(deployment->nTargetBase),
                  unsigned(deployment->nTargetSurge),
                  unsigned(deployment->plan.whiteholes.size()),
                  unsigned(machines.size())
               );

               for (Machine *machine : machines)
               {
                  if (machine == nullptr)
                  {
                     continue;
                  }

                  String machineUUIDText = {};
                  machineUUIDText.assignItoh(machine->uuid);
                  basics_log(
                     "measureApplication machine uuid=%s state=%d isBrain=%d isThisMachine=%d slug=%s private4=%u avail=%d/%d/%d rack=%u\n",
                     machineUUIDText.c_str(),
                     int(machine->state),
                     int(machine->isBrain),
                     int(machine->isThisMachine),
                     machine->slug.c_str(),
                     unsigned(machine->private4),
                     int(machine->nLogicalCores_available),
                     int(machine->memoryMB_available),
                     int(machine->storageMB_available),
                     unsigned(machine->rackUUID)
                  );
               }
            }

				// we would schedule these many
				uint32_t nBase = deployment->nTargetBase;
				uint32_t nSurge = deployment->nTargetSurge;

				// nBase(4) nSurge(4) nFit(4)
				Message::construct(mothership->wBuffer, MothershipTopic::measureApplication, nBase, nSurge, nFit);

				delete deployment;

				break;
			}
				case MothershipTopic::spinApplication:
				{
					// applicationID(2) plan{4} containerBlob{4}
					uint16_t applicationID;
					Message::extractArg<ArgumentNature::fixed>(args, applicationID);

					if (unlikely(applicationID == 0)) return;

					String serializedPlan;
					Message::extractToStringView(args, serializedPlan);

					if (unlikely(serializedPlan.size() == 0)) return;

					ApplicationDeployment *deployment = new ApplicationDeployment();

					BitseryEngine::deserialize(serializedPlan, deployment->plan);
					auto rejectInvalidPlan = [&](const String& reason) {
						delete deployment;
						Message::construct(
							mothership->wBuffer,
							MothershipTopic::spinApplication,
							uint8_t(SpinApplicationResponseCode::invalidPlan),
							reason);
					};

					if (deployment->plan.config.applicationID != applicationID)
					{
						rejectInvalidPlan("invalid plan: config.applicationID mismatches envelope"_ctv);
						return;
					}
					if (isApplicationIDReserved(applicationID) == false)
					{
						rejectInvalidPlan("invalid plan: applicationID not reserved"_ctv);
						return;
					}
					String identityFailure;
					if (validateDeploymentApplicationIdentity(deployment->plan, identityFailure) == false)
					{
						rejectInvalidPlan(identityFailure);
						return;
					}

					if (deployment->plan.hasTlsIssuancePolicy)
					{
						const DeploymentTlsIssuancePolicy& tlsPolicy = deployment->plan.tlsIssuancePolicy;
						if (tlsPolicy.applicationID == 0)
						{
							rejectInvalidPlan("invalid tls policy: applicationID missing"_ctv);
							return;
						}
						if (tlsPolicy.applicationID != deployment->plan.config.applicationID)
						{
							rejectInvalidPlan("invalid tls policy: applicationID mismatch"_ctv);
							return;
						}
						if (tlsVaultFactoriesByApp.find(tlsPolicy.applicationID) == tlsVaultFactoriesByApp.end())
						{
							rejectInvalidPlan("invalid tls policy: referenced vault factory does not exist"_ctv);
							return;
						}
					}

					if (deployment->plan.hasApiCredentialPolicy)
					{
						const DeploymentApiCredentialPolicy& apiPolicy = deployment->plan.apiCredentialPolicy;
						if (apiPolicy.applicationID == 0)
						{
							rejectInvalidPlan("invalid api credential policy: applicationID missing"_ctv);
							return;
						}
						if (apiPolicy.applicationID != deployment->plan.config.applicationID)
						{
							rejectInvalidPlan("invalid api credential policy: applicationID mismatch"_ctv);
							return;
						}

						auto setIt = apiCredentialSetsByApp.find(apiPolicy.applicationID);
						if (setIt == apiCredentialSetsByApp.end())
						{
							rejectInvalidPlan("invalid api credential policy: credential set does not exist"_ctv);
							return;
						}

						const ApplicationApiCredentialSet& set = setIt->second;
						for (const String& requiredName : apiPolicy.requiredCredentialNames)
						{
							bool found = false;
							for (const ApiCredential& credential : set.credentials)
							{
									if (credential.name.equals(requiredName))
								{
									found = true;
									break;
								}
							}

							if (found == false)
							{
								String reason;
								reason.snprintf<"invalid api credential policy: required key '{}' is not registered"_ctv>(requiredName);
								rejectInvalidPlan(reason);
								return;
							}
						}
					}

               if (needsDistributedExternalAddressFamily(deployment->plan, ExternalAddressFamily::ipv4)
                  && findAllocatableDistributableExternalSubnetForFamily(
                     brainConfig,
                     ExternalAddressFamily::ipv4,
                     ExternalSubnetUsage::whiteholes) == nullptr)
               {
                  rejectInvalidPlan("invalid plan: no registered distributable ipv4 subnet usable for whiteholes leaves the required 16 host bits"_ctv);
                  return;
               }

               if (needsDistributedExternalAddressFamily(deployment->plan, ExternalAddressFamily::ipv6)
                  && findAllocatableDistributableExternalSubnetForFamily(
                     brainConfig,
                     ExternalAddressFamily::ipv6,
                     ExternalSubnetUsage::whiteholes) == nullptr)
               {
                  rejectInvalidPlan("invalid plan: no registered distributable ipv6 subnet usable for whiteholes leaves the required 40 host bits"_ctv);
                  return;
               }

               for (const Wormhole& wormhole : deployment->plan.wormholes)
               {
                  if (wormhole.source != ExternalAddressSource::distributableSubnet
                     && wormhole.source != ExternalAddressSource::registeredRoutableAddress)
                  {
                     rejectInvalidPlan("invalid plan: wormholes currently require source == distributableSubnet or registeredRoutableAddress"_ctv);
                     return;
                  }
               }

               for (Wormhole& wormhole : deployment->plan.wormholes)
               {
                  if (wormhole.isQuic && wormhole.layer4 != IPPROTO_UDP)
                  {
                     rejectInvalidPlan("invalid plan: wormhole.isQuic requires layer4 == UDP"_ctv);
                     return;
                  }

                  if (wormhole.source == ExternalAddressSource::registeredRoutableAddress)
                  {
                     String resolveFailure = {};
                     if (resolveWormholeRegisteredRoutableAddress(brainConfig.routableAddresses, wormhole, &resolveFailure) == false)
                     {
                        rejectInvalidPlan(String("invalid plan: "_ctv) + resolveFailure);
                        return;
                     }

                     continue;
                  }

                  bool foundMatchingSubnet = false;
                  for (const DistributableExternalSubnet& subnet : brainConfig.distributableExternalSubnets)
                  {
                     if (distributableExternalSubnetContainsAddress(subnet, wormhole.externalAddress)
                        && distributableExternalSubnetAllowsWormholes(subnet))
                     {
                        foundMatchingSubnet = true;
                        break;
                     }
                  }

                  if (foundMatchingSubnet == false)
                  {
                     if (wormhole.externalAddress.is6)
                     {
                        rejectInvalidPlan("invalid plan: wormhole externalAddress is not within a registered distributable ipv6 subnet usable for wormholes"_ctv);
                     }
                     else
                     {
                        rejectInvalidPlan("invalid plan: wormhole externalAddress is not within a registered distributable ipv4 subnet usable for wormholes"_ctv);
                     }

                     return;
                  }
               }

               (void)prepareDeploymentPlanWormholeQuicCidState(deployment->plan, Time::now<TimeResolution::ms>());

               for (Whitehole& whitehole : deployment->plan.whiteholes)
               {
                  whitehole.hasAddress = false;
                  whitehole.address = {};
                  whitehole.sourcePort = 0;
                  whitehole.bindingNonce = 0;

                  if (whitehole.source == ExternalAddressSource::hostPublicAddress)
                  {
                     continue;
                  }

                  if (whitehole.source == ExternalAddressSource::distributableSubnet)
                  {
                     if (findAllocatableDistributableExternalSubnetForFamily(
                        brainConfig,
                        whitehole.family,
                        ExternalSubnetUsage::whiteholes) == nullptr)
                     {
                        if (whitehole.family == ExternalAddressFamily::ipv6)
                        {
                           rejectInvalidPlan("invalid plan: no registered distributable ipv6 subnet usable for whiteholes leaves the required 40 host bits"_ctv);
                        }
                        else
                        {
                           rejectInvalidPlan("invalid plan: no registered distributable ipv4 subnet usable for whiteholes leaves the required 16 host bits"_ctv);
                        }

                        return;
                     }

                     continue;
                  }

                  if (whitehole.source != ExternalAddressSource::hostPublicAddress)
                  {
                     rejectInvalidPlan("invalid plan: whiteholes currently require source == hostPublicAddress or distributableSubnet"_ctv);
                     return;
                  }
               }

					// they might just reisuse the application with the same deployment ID again if it fails
					if (auto it = failedDeployments.find(deployment->plan.config.deploymentID()); it != failedDeployments.end())
					{
						failedDeployments.erase(it);
				}

				String containerBlob;
				Message::extractToStringView(args, containerBlob);

				String trustedContainerBlobSHA256 = {};
				uint64_t trustedContainerBlobBytes = 0;
				String containerStoreFailure = {};
				if (ContainerStore::store(
					deployment->plan.config.deploymentID(),
					containerBlob,
					&trustedContainerBlobSHA256,
					&trustedContainerBlobBytes,
					nullptr,
					nullptr,
					&containerStoreFailure) == false)
				{
					String reason = {};
					reason.assign("invalid container blob: "_ctv);
					if (containerStoreFailure.size() > 0)
					{
						reason.append(containerStoreFailure);
					}
					else
					{
						reason.append("blob store rejected the payload"_ctv);
					}
					rejectInvalidPlan(reason);
					return;
				}

				deployment->plan.config.containerBlobSHA256 = trustedContainerBlobSHA256;
				deployment->plan.config.containerBlobBytes = trustedContainerBlobBytes;

				String trustedSerializedPlan = {};
				BitseryEngine::serialize(trustedSerializedPlan, deployment->plan);
				deployments.insert_or_assign(deployment->plan.config.deploymentID(), deployment);
               bindSpinApplicationMothership(deployment, mothership);

					// Replicate lightweight deployment metadata first so a follower can
					// take over scheduling even if the leader dies during large blob transfer.
					// Then fan out the blob payload for peers that rely on local image stores.
					if (nBrains > 1)
					{
						queueBrainDeploymentReplication(trustedSerializedPlan, ""_ctv);
						queueBrainDeploymentReplication(trustedSerializedPlan, containerBlob);
					}

				Message::construct(mothership->wBuffer, MothershipTopic::spinApplication, uint8_t(SpinApplicationResponseCode::okay));

				// The deploy CLI waits for the initial okay/invalidPlan frame before it starts
				// consuming streamed progress on the same topic.
				spinApplication(deployment);

				break;
			}
			// this is very dangerous so we might not even want this code to be active
			// case MothershipTopic::destroyApplication:
			// {
			// 	// appID(2)

			// 	uint16_t applicationID;
			// 	Message::extractArg<ArgumentNature::fixed>(args, applicationID);

			// 	if (unlikely(applicationID == 0)) return;

			// 	if (auto it = deploymentsByApp.find(applicationID); it != deploymentsByApp.end()) // if that application even exists
			// 	{
			// 		// we need to tell it to destroy every instance....
			// 		ApplicationDeployment *deployment = it->second;

			// 		deployment->destroy();

			// 		String empty;
			// 		queueBrainReplication(NeuronTopic::replicateDeployment, applicationID, empty);
			// 	}

			// 	// we could either create a new destroy application replication command or we could unwind it here and issue culls for each existing deployment?

			// 	break;
			// }
			default: break;
		}
	}

	void neuronHandler(NeuronView *neuron, Message *message)
	{
		uint8_t *args = message->args;
		uint8_t *terminal = message->terminal();

				switch (NeuronTopic(message->topic))
			{
			// given that the brain state upon connection is what matters (either new brain looking to feed on the neuron's data or operating brain ready to configure the neuron)
			// the brain should first express it's state, then the neuron responds in kind

			// brain sends
			// NeuronTopic::registration requiresState(1)

			// if requiresState == true
			// neuron sends... serialized containers + its fragments
			// NeuronTopic::stateUpload containers{4} fragment(4)

			// neuron always sends back
			// NeuronTopic::registration bootTimeMs(8) kernel{4} haveData(1)

			// if haveData == false
			// brain sends back
			// NeuronTopic::stateUpload containers{4} fragment(4)

			// maybe we should send it our registration... saying that we just became master and don't have data?
			case NeuronTopic::registration:
			{
				// bootTimeMs(8) kernel{4} haveData(1)
				uint8_t *args = message->args;

				Machine *machine = neuron->machine;

				Message::extractArg<ArgumentNature::fixed>(args, machine->lastUpdatedOSMs);
				Message::extractToString(args, machine->kernel);

				bool haveData;
				Message::extractArg<ArgumentNature::fixed>(args, haveData);

				if (haveData == false) // either 1) first time the neuron is connecting or 2) neuron crashed or 3) neuron was updated or 4) OS updated
				{
					if (ignited)
					{
						if (machine->fragment > 0)
						{
							// was previously configured.... must've crashed or neuron was updated or OS was updated (but maybe we don't keep containers on machines when OS updating)

							uint32_t headerOffset = Message::appendHeader(neuron->wBuffer, NeuronTopic::stateUpload);

							struct local_container_subnet6 fragment;
							fragment.dpfx = brainConfig.datacenterFragment;
							fragment.mpfx[0] = static_cast<uint8_t>((neuron->machine->fragment >> 16) & 0xFF);
							fragment.mpfx[1] = static_cast<uint8_t>((neuron->machine->fragment >> 8) & 0xFF);
							fragment.mpfx[2] = static_cast<uint8_t>(neuron->machine->fragment & 0xFF);

							Message::appendAlignedBuffer<Alignment::one>(neuron->wBuffer, (uint8_t *)&fragment, sizeof(struct local_container_subnet6));

							for (const auto& [deploymentID, containers] : machine->containersByDeploymentID) // might not be any
							{
								auto deploymentIt = deployments.find(deploymentID);
								if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
								{
									continue;
								}

								ApplicationDeployment *deployment = deploymentIt->second;

									for (ContainerView *container : containers)
									{
										ContainerPlan planToReplay = container->generatePlan(deployment->plan);
										applyCredentialsToContainerPlan(deployment->plan, *container, planToReplay);

                              NeuronContainerBootstrap bootstrap;
                              bootstrap.plan = std::move(planToReplay);
                              bootstrap.metricPolicy = deriveNeuronMetricPolicyForDeployment(deployment->plan);
                              String serializedBootstrap;
                              BitseryEngine::serialize(serializedBootstrap, bootstrap);
                              Message::appendValue(neuron->wBuffer, serializedBootstrap);
									}
							}

							Message::finish(neuron->wBuffer, headerOffset);

							Ring::queueSend(neuron);
						}
						else // neuron yet to ever be configured, assign fragment now
						{
							assignMachineFragment(machine);
						}

                  sendNeuronSwitchboardStateSync(machine);

					}
					// else main brain hasn't reached ignition yet. we need to wait for that otherwise we won't have gathered all
					// networking data from every machine, thus can't assign any
				}
				// else maybe some transitory connection breakage

               bool readyAfterRegistration = machineReadyForHealthyState(machine);
#if PRODIGY_DEBUG
               basics_log("brain neuron registration ready-check uuid=%llu private4=%u haveData=%d ready=%d inventoryComplete=%d total=%u/%u/%u owned=%u/%u/%u fd=%d fslot=%d\n",
                  (unsigned long long)(machine ? machine->uuid : 0),
                  unsigned(machine ? machine->private4 : 0u),
                  int(haveData),
                  int(readyAfterRegistration),
                  int(machine ? machine->hardware.inventoryComplete : 0),
                  unsigned(machine ? machine->totalLogicalCores : 0u),
                  unsigned(machine ? machine->totalMemoryMB : 0u),
                  unsigned(machine ? machine->totalStorageMB : 0u),
                  unsigned(machine ? machine->ownedLogicalCores : 0u),
                  unsigned(machine ? machine->ownedMemoryMB : 0u),
                  unsigned(machine ? machine->ownedStorageMB : 0u),
                  neuron->fd,
                  neuron->fslot);
#endif
						if (machine->state != MachineState::healthy
	                  && readyAfterRegistration)
						{
							handleMachineStateChange(machine, MachineState::healthy);
						}

					sendNeuronSwitchboardStateSync(machine);
					recoverDeploymentsAfterNeuronState();

					break;
				}
         case NeuronTopic::machineHardwareProfile:
         {
            String serialized = {};
            Message::extractToStringView(args, serialized);

#if PRODIGY_DEBUG
            basics_log("brain neuron machineHardwareProfile begin uuid=%llu private4=%u cloudID=%s bytes=%llu fd=%d fslot=%d state=%u inventoryComplete=%d\n",
               (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
               unsigned(neuron->machine ? neuron->machine->private4 : 0u),
               (neuron->machine ? neuron->machine->cloudID.c_str() : ""),
               (unsigned long long)serialized.size(),
               neuron->fd,
               neuron->fslot,
               unsigned(neuron->machine ? uint32_t(neuron->machine->state) : 0u),
               int(neuron->machine ? neuron->machine->hardware.inventoryComplete : 0));
#endif
            MachineHardwareProfile hardware = {};
            if (BitseryEngine::deserializeSafe(serialized, hardware) == false)
            {
               basics_log("brain neuron machineHardwareProfile deserialize failed uuid=%llu private4=%u bytes=%llu fd=%d fslot=%d\n",
                  (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                  unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                  (unsigned long long)serialized.size(),
                  neuron->fd,
                  neuron->fslot);
               queueCloseIfActive(neuron);
               break;
            }

            if (hardware.inventoryComplete == false)
            {
               basics_log("brain neuron machineHardwareProfile incomplete uuid=%llu private4=%u bytes=%llu fd=%d fslot=%d\n",
                  (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                  unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                  (unsigned long long)serialized.size(),
                  neuron->fd,
                  neuron->fslot);
               queueCloseIfActive(neuron);
               break;
            }

            Machine *machine = neuron->machine;
            bool readyBeforeHardware = machineReadyForHealthyState(machine);
            applyMachineHardwareProfile(machine, hardware);

#if PRODIGY_DEBUG
            bool readyAfterHardware = machineReadyForHealthyState(machine);
            basics_log("brain neuron machineHardwareProfile ok uuid=%llu private4=%u bytes=%llu inventoryComplete=%d logicalCores=%u memoryMB=%u disks=%llu nics=%llu failure=%s readyBefore=%d readyAfter=%d totals=%u/%u/%u owned=%u/%u/%u fd=%d fslot=%d\n",
               (unsigned long long)(machine ? machine->uuid : 0),
               unsigned(machine ? machine->private4 : 0u),
               (unsigned long long)serialized.size(),
               int(hardware.inventoryComplete),
               hardware.cpu.logicalCores,
               hardware.memory.totalMB,
               (unsigned long long)hardware.disks.size(),
               (unsigned long long)hardware.network.nics.size(),
               hardware.inventoryFailure.c_str(),
               int(readyBeforeHardware),
               int(readyAfterHardware),
               unsigned(machine ? machine->totalLogicalCores : 0u),
               unsigned(machine ? machine->totalMemoryMB : 0u),
               unsigned(machine ? machine->totalStorageMB : 0u),
               unsigned(machine ? machine->ownedLogicalCores : 0u),
               unsigned(machine ? machine->ownedMemoryMB : 0u),
               unsigned(machine ? machine->ownedStorageMB : 0u),
               neuron->fd,
               neuron->fslot);
#endif

	            if (machine->state != MachineState::healthy
	               && machineReadyForHealthyState(machine))
	            {
	               handleMachineStateChange(machine, MachineState::healthy);
	            }

            break;
         }
			case NeuronTopic::stateUpload:
			{
         // fragment(4) [containerPlan{4} + runtimeCores(2) + runtimeMemMB(4) + runtimeStorMB(4)]...

				struct local_container_subnet6 fragment;
				Message::extractBytes<Alignment::one>(args, (uint8_t *)&fragment, sizeof(struct local_container_subnet6));

				neuron->machine->fragment = (static_cast<uint32_t>(fragment.mpfx[0]) << 16) |
				   (static_cast<uint32_t>(fragment.mpfx[1]) << 8) |
				   static_cast<uint32_t>(fragment.mpfx[2]);

					uint8_t *terminal = message->terminal();
					bool malformedStateUpload = false;
					bytell_hash_set<uint128_t> reportedMachineContainerUUIDs = {};
#if PRODIGY_DEBUG
					const uint64_t indexedBefore = neuron->machine ? neuron->machine->containersByDeploymentID.size() : 0u;
#endif
					while (args < terminal)
					{
						String buffer;
						Message::extractToStringView(args, buffer);
						if (buffer.data() > terminal || buffer.size() > uint64_t(terminal - buffer.data()))
						{
							malformedStateUpload = true;
							break;
						}

	            ContainerPlan plan;
	            if (BitseryEngine::deserializeSafe(buffer, plan) == false)
	            {
	               malformedStateUpload = true;
	               break;
	            }

						reportedMachineContainerUUIDs.insert(plan.uuid);
						ContainerView *container = nullptr;
						if (auto existing = containers.find(plan.uuid); existing != containers.end())
						{
							container = existing->second;
						}
						else
						{
							container = new ContainerView();
						}

						uint64_t previousDeploymentID = container->deploymentID;
						uint32_t previousShardGroup = container->shardGroup;
						Machine *previousMachine = container->machine;
						ContainerState previousState = container->state;
						ContainerState uploadedState = plan.state;

						if (previousMachine)
						{
							previousMachine->removeContainerIndexEntry(previousDeploymentID, container);
						}

						if (previousDeploymentID > 0)
						{
								if (auto prevDeployment = deployments.find(previousDeploymentID); prevDeployment != deployments.end() && prevDeployment->second)
								{
									prevDeployment->second->containers.erase(container);
									if (prevDeployment->second->plan.isStateful)
									{
										while (prevDeployment->second->containersByShardGroup.eraseEntry(previousShardGroup, container)) {}
									}
								}
						}

						container->subscriptions.clear();
						container->advertisements.clear();
						container->advertisingOnPorts.clear();

	            container->uuid = plan.uuid;
						container->deploymentID = plan.config.deploymentID();
						container->applicationID = plan.config.applicationID;
						container->lifetime = plan.lifetime;
						container->state = uploadedState;
						container->machine = neuron->machine;
	            container->createdAtMs = plan.createdAtMs;
	            // Neuron state upload currently transmits the serialized container plan.
	            // Seed runtime usage from plan resources; live stats update these later.
							container->runtime_nLogicalCores = static_cast<uint16_t>(applicationSharedCPUCoreHint(plan.config));
							container->runtime_memoryMB = plan.config.totalMemoryMB();
							container->runtime_storageMB = plan.config.totalStorageMB();
							container->addresses = plan.addresses; // directly assigned interface addresses; currently just container-network IPv6
                     container->wormholes = plan.wormholes;
                     container->whiteholes = plan.whiteholes;
                     container->assignedGPUMemoryMBs = plan.assignedGPUMemoryMBs;
                     container->assignedGPUDevices = plan.assignedGPUDevices;
							container->fragment = plan.fragment;
						container->setMeshAddress(container_network_subnet6, brainConfig.datacenterFragment, neuron->machine->fragment, container->fragment);
						container->shardGroup = plan.shardGroup;
						container->subscriptions = plan.subscriptions;
	   				container->advertisements = plan.advertisements;

	   				auto deploymentIt = deployments.find(container->deploymentID);
						if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
						{
							continue;
						}
						ApplicationDeployment *deployment = deploymentIt->second;
	   				container->remainingSubscriberCapacity = deployment->plan.minimumSubscriberCapacity;

						for (const auto& [service, subscription] : container->subscriptions)
						{
							mesh->logSubscription(container, subscription.service, subscription.nature);
						}

						for (const auto& [service, advertisement] : container->advertisements)
						{
							mesh->logAdvertisement(container, advertisement.service);
							container->advertisingOnPorts.insert(advertisement.port);
						}

						for (const auto& [secret, pairings] : plan.advertisementPairings)
				      {
				         for (const AdvertisementPairing& pairing : pairings)
				         {
				         	mesh->logAdvertisementPairing(pairing.secret, container, pairing);

				         	// we could also just pull the stress right now.... and then calculate capacity exactly...
				         	// but this is a decent estimate to right now... then we don't have to add that extra logic path complexity
				         	// but if it really mattered in the future we could do that
				            container->remainingSubscriberCapacity -= 1;
				         }
				      }

				      for (const auto& [secret, pairings] : plan.subscriptionPairings)
				      {
				         for (const SubscriptionPairing& pairing : pairings)
				         {
				            mesh->logSubscriptionPairing(pairing.secret, container, pairing);

				         }
				      }

				      containers.insert_or_assign(container->uuid, container);
					      container->machine->upsertContainerIndexEntry(container->deploymentID, container);
					      deployment->containers.insert(container);

					      if (deployment->plan.isStateful)
	   				{
	   					deployment->containersByShardGroup.insert(container->shardGroup, container);
	   				}

						if (uploadedState == ContainerState::healthy && previousState != ContainerState::healthy)
						{
							container->state = previousState;
							deployment->containerIsHealthy(container);
						}
					}

						if (malformedStateUpload)
						{
							basics_log("brain stateUpload malformed plan payload from private4=%u\n",
								(neuron->machine ? unsigned(neuron->machine->private4) : 0u));
							neuron->rBuffer.clear();
							if (streamIsActive(neuron))
							{
							Ring::queueClose(neuron);
						}
						break;
					}

					Vector<ContainerView *> staleMachineContainerPointers;
					bytell_hash_set<uint128_t> staleMachineContainerUUIDs = {};
					for (const auto& [deploymentID, machineContainers] : neuron->machine->containersByDeploymentID)
					{
						(void)deploymentID;
						for (ContainerView *container : machineContainers)
						{
							if (container == nullptr)
							{
								continue;
							}

							if (reportedMachineContainerUUIDs.find(container->uuid) != reportedMachineContainerUUIDs.end())
							{
								continue;
							}

							if (staleMachineContainerUUIDs.find(container->uuid) == staleMachineContainerUUIDs.end())
							{
								staleMachineContainerUUIDs.insert(container->uuid);
								staleMachineContainerPointers.push_back(container);
							}
						}
					}

					for (ContainerView *stale : staleMachineContainerPointers)
					{
						if (stale == nullptr)
						{
							continue;
						}

							neuron->machine->removeContainerIndexEntry(stale->deploymentID, stale);
							if (auto deployment = deployments.find(stale->deploymentID); deployment != deployments.end() && deployment->second)
							{
								deployment->second->containers.erase(stale);
								if (deployment->second->plan.isStateful)
								{
									while (deployment->second->containersByShardGroup.eraseEntry(stale->shardGroup, stale)) {}
								}
							}

						if (auto canonical = containers.find(stale->uuid); canonical != containers.end() && canonical->second == stale)
						{
							containers.erase(stale->uuid);
						}

						delete stale;
					}

#if PRODIGY_DEBUG
					basics_log("brain stateUpload applied private4=%u reported=%llu stale=%llu indexedBefore=%llu indexedAfter=%llu canonicalContainers=%llu malformed=%d\n",
						unsigned(neuron->machine ? neuron->machine->private4 : 0u),
						(unsigned long long)reportedMachineContainerUUIDs.size(),
						(unsigned long long)staleMachineContainerPointers.size(),
						(unsigned long long)indexedBefore,
						(unsigned long long)(neuron->machine ? neuron->machine->containersByDeploymentID.size() : 0u),
						(unsigned long long)containers.size(),
						int(malformedStateUpload));
#endif

					sendNeuronSwitchboardStateSync(neuron->machine);
					recoverDeploymentsAfterNeuronState();

					break;
				}
			case NeuronTopic::hardwareFailure:
			{
				// report{4}
				uint8_t *args = message->args;

				Machine *machine = neuron->machine;

				Message::extractToString(args, machine->hardwareFailureReport);

				iaas->reportHardwareFailure(machine->uuid, machine->hardwareFailureReport);

				// update machine state before we call machineFailed
				handleMachineStateChange(machine, MachineState::hardwareFailure);

				decommissionMachine(machine);

				break;
			}
				case NeuronTopic::containerHealthy:
				{
					// containerUUID(16)

					uint128_t containerUUID;
					Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
#if PRODIGY_DEBUG
					basics_log("brain neuronHandler containerHealthy private4=%u uuid=%llu master=%d tracked=%llu\n",
						unsigned(neuron->machine ? neuron->machine->private4 : 0u),
						(unsigned long long)containerUUID,
						int(weAreMaster),
						(unsigned long long)containers.size());
#endif
               noteLocalContainerHealthy(containerUUID);

					break;
				}
			case NeuronTopic::containerStatistics:
			{
				// deploymentID(8) containerUUID(16) sampleTimeMs(8) [metricKey(8) metricValue(8)]...
				uint64_t deploymentID = 0;
				uint128_t containerUUID = 0;
				int64_t sampleTimeMs = 0;

				Message::extractArg<ArgumentNature::fixed>(args, deploymentID);
				Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
				Message::extractArg<ArgumentNature::fixed>(args, sampleTimeMs);

				auto containerIt = containers.find(containerUUID);
				if (containerIt == containers.end()) break;
				if (containerIt->second->deploymentID != deploymentID) break;
				if (deployments.contains(deploymentID) == false) break;

				int64_t nowMs = Time::now<TimeResolution::ms>();
				if (sampleTimeMs <= 0 || sampleTimeMs > nowMs + 10'000 || sampleTimeMs < nowMs - BrainBase::metricRetentionMs)
				{
					sampleTimeMs = nowMs;
				}

				while (args < terminal)
				{
					if (size_t(terminal - args) < (sizeof(uint64_t) * 2)) break;

					uint64_t metricKey = 0;
					uint64_t metricValue = 0;

					Message::extractArg<ArgumentNature::fixed>(args, metricKey);
					Message::extractArg<ArgumentNature::fixed>(args, metricValue);

					recordContainerMetric(deploymentID, containerUUID, metricKey, sampleTimeMs, static_cast<double>(metricValue));
					forwardMetricSampleToMaster(deploymentID, containerUUID, sampleTimeMs, metricKey, metricValue);
				}

				break;
			}
			case NeuronTopic::refreshContainerCredentials:
			{
				// containerUUID(16)
				uint128_t containerUUID = 0;
				Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
				basics_log("brain refreshContainerCredentialsAck uuid=%llu\n",
					(unsigned long long)containerUUID);
				break;
			}
			case NeuronTopic::killContainer: // echo-ing back after killing a container
			{
				// containerUUID(16)

				uint128_t containerUUID;
				Message::extractArg<ArgumentNature::fixed>(args, containerUUID);

				// if a canary failed and we rolled back a deployment to previous, it's possible
				// we would've issued canary kills and then destroyed the deployment before we get a reply
					if (auto it = containers.find(containerUUID); it != containers.end())
					{
						ContainerView *container = it->second;

						Machine *machine = container->machine;

                  std::fprintf(stderr, "brain killContainerAck begin uuid=%llu deploymentID=%llu appID=%u machinePrivate4=%u state=%u waiting=%llu containers=%llu\n",
                     (unsigned long long)containerUUID,
                     (unsigned long long)container->deploymentID,
                     unsigned(container->applicationID),
                     machine ? unsigned(machine->private4) : 0u,
                     unsigned(container->state),
                     (unsigned long long)((deployments.contains(container->deploymentID) && deployments[container->deploymentID]) ? deployments[container->deploymentID]->waitingOnContainers.size() : 0ull),
                     (unsigned long long)((deployments.contains(container->deploymentID) && deployments[container->deploymentID]) ? deployments[container->deploymentID]->containers.size() : 0ull));
                  std::fflush(stderr);

						auto deploymentIt = deployments.find(container->deploymentID);
						if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
						{
							break;
						}

						ApplicationDeployment *deployment = deploymentIt->second;
                  std::fprintf(stderr, "brain killContainerAck destroy-call uuid=%llu deploymentID=%llu waitingBefore=%llu containersBefore=%llu\n",
                     (unsigned long long)containerUUID,
                     (unsigned long long)container->deploymentID,
                     (unsigned long long)deployment->waitingOnContainers.size(),
                     (unsigned long long)deployment->containers.size());
                  std::fflush(stderr);
						deployment->containerDestroyed(container);
                  std::fprintf(stderr, "brain killContainerAck destroy-done uuid=%llu deploymentID=%llu waitingAfter=%llu containersAfter=%llu\n",
                     (unsigned long long)containerUUID,
                     (unsigned long long)container->deploymentID,
                     (unsigned long long)deployment->waitingOnContainers.size(),
                     (unsigned long long)deployment->containers.size());
                  std::fflush(stderr);

						isMachineDrained(machine);
                  std::fprintf(stderr, "brain killContainerAck drain-done uuid=%llu machinePrivate4=%u\n",
                     (unsigned long long)containerUUID,
                     machine ? unsigned(machine->private4) : 0u);
                  std::fflush(stderr);
					}
					break;
				}
			case NeuronTopic::containerFailed:
			{
				// containerUUID(16) approxTimeMs(8) signal(4) report{4} restarted(1)

				uint128_t containerUUID;
				Message::extractArg<ArgumentNature::fixed>(args, containerUUID);

				if (auto it = containers.find(containerUUID); it != containers.end())
					{
						ContainerView *container = it->second;

						Machine *machine = container->machine;

						// is it possible we'd ever destroy an application and orphan the containers? no right?
						uint16_t applicationID = ApplicationConfig::extractApplicationID(container->deploymentID);
						auto deploymentIt = deploymentsByApp.find(applicationID);
						if (deploymentIt == deploymentsByApp.end() || deploymentIt->second == nullptr)
						{
							break;
						}
						ApplicationDeployment *deployment = deploymentIt->second;

					int64_t approxTimeMs;
					Message::extractArg<ArgumentNature::fixed>(args, approxTimeMs);

					int signal;
					Message::extractArg<ArgumentNature::fixed>(args, signal);

					String report;
					Message::extractToStringView(args, report);

					bool restarted;
					Message::extractArg<ArgumentNature::fixed>(args, restarted);

					deployment->containerFailed(container, approxTimeMs, signal, report, restarted);

					if (restarted == false) isMachineDrained(machine);
				}

				break;
			}
			case NeuronTopic::requestContainerBlob:
			{
				// deploymentID(8)

				uint64_t deploymentID;
				Message::extractArg<ArgumentNature::fixed>(args, deploymentID);

				String containerBlobPath = ContainerStore::pathForContainerImage(deploymentID);
				std::fprintf(stderr, "brain requestContainerBlob deploymentID=%llu machinePrivate4=%u path=%s readable=%d\n",
					(unsigned long long)deploymentID,
					(neuron->machine ? unsigned(neuron->machine->private4) : 0u),
					containerBlobPath.c_str(),
					int(prodigyFileReadable(containerBlobPath)));
				std::fflush(stderr);

				uint32_t headerOffset = Message::appendHeader(neuron->wBuffer, NeuronTopic::requestContainerBlob);
				Message::append(neuron->wBuffer, deploymentID);
				Message::appendFile(neuron->wBuffer, containerBlobPath);
				Message::finish(neuron->wBuffer, headerOffset);

				Ring::queueSend(neuron);

				break;
			}
			case NeuronTopic::spotTerminationImminent:
			{
				// spot machine preemption imminent; immediately drain all containers
				Machine *machine = neuron->machine;
				if (machine)
				{
					machine->state = MachineState::decommissioning;
					decommissionMachine(machine);
				}

				break;
			}
			case NeuronTopic::ping:
			{
				break;
			}

			default: break;
		}
	}
	};

	#include <prodigy/brain/deployments.h>
