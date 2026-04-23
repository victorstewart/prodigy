#include <algorithm>
#include <services/bitsery.h>
#include <services/crypto.h>
#include <services/filesystem.h>
#include <services/time.h>
#include <networking/message.h>
#include <networking/stream.h>
#include <networking/ring.h>
#include <networking/ssh.h>
#include <networking/reconnector.h>
#include <prodigy/transport.tls.h>
#include <prodigy/machine.hardware.types.h>
#include <prodigy/types.h>
#include <SG14/inplace_function.h>

#pragma once

class Machine;
class Rack;
class BrainView;

enum class MachineState : uint8_t {

	deploying,
	unknown,
	healthy,
	missing,
	unresponsive,
	neuronRebooting,
	hardRebooting,
	updatingOS,
	hardwareFailure,
	unreachable,
	decommissioning
};

class NeuronView : public RingInterface, public ProdigyTransportTLSStream, public CoroutineStack, public Reconnector {
public:

	Machine *machine = nullptr;
	bool connected = false;
	bool hadSuccessfulConnection = false;

	void reset(void) override
	{
		ProdigyTransportTLSStream::reset();
		Reconnector::reset();
		connected = false;
		hadSuccessfulConnection = false;
	}
};

enum class SSHAction : uint8_t {

	restartProdigy,
	updateNeuron
};

static inline void prodigyResolveMachineRestartSSHCredentials(const Machine *machine, String& user, String& privateKeyPath);

class MachineSSH : public SSHClient, public Reconnector {
public:

	Machine *machine = nullptr;
   const Vault::SSHKeyPackage *bootstrapSshKeyPackage = nullptr;
   const String *bootstrapSshPrivateKeyPath = nullptr;

	SSHAction action;
	stdext::inplace_function<void(), 128> callback;

	void reset(void) override
	{
		SSHClient::reset();
		Reconnector::reset();
	}

	void restartProdigy(void);

	void registerAction(SSHAction thisAction, stdext::inplace_function<void(), 128>&& thisCallback)
	{
		action = thisAction;
		callback = std::move(thisCallback);
	}

	void execute(void)
	{
		switch (action)
		{
			case SSHAction::restartProdigy:
			{
				restartProdigy();
				break;
			}
			default: break;
		}
	}
};

class MachineTicket;
class ContainerView;

class MachineBase {
public:

	uint32_t private4 = 0;
	uint32_t gatewayPrivate4 = 0;
};

class Machine : public MachineBase {
public:

	struct Claim {

		MachineTicket *ticket;
		uint32_t nFit;						// if stateless
		Vector<uint32_t> shardGroups; // if stateful
      uint32_t reservedIsolatedLogicalCoresPerInstance = 0;
      uint32_t reservedSharedCPUMillisPerInstance = 0;
      uint32_t reservedMemoryMBPerInstance = 0;
      uint32_t reservedStorageMBPerInstance = 0;
      Vector<uint32_t> reservedGPUMemoryMBs;
      Vector<AssignedGPUDevice> reservedGPUDevices;
	};

	String slug;
	MachineLifetime lifetime;
	MachineState state;
	String type;
    String cloudID; // cloud provider resource identifier used by IaaS APIs
	uint8_t topologySource = 0; // ClusterMachineSource
	String region;
	String zone;
	String sshAddress;
	uint16_t sshPort = 22;
	String sshUser;
	String sshPrivateKeyPath;
   String sshHostPublicKeyOpenSSH;
	String publicAddress;
	String privateAddress;
   Vector<ClusterMachinePeerAddress> peerAddresses;
	uint8_t ownershipMode = 0; // ClusterMachineOwnershipMode
	uint32_t ownershipLogicalCoresCap = 0;
	uint32_t ownershipMemoryMBCap = 0;
	uint32_t ownershipStorageMBCap = 0;
	uint16_t ownershipLogicalCoresBasisPoints = 0;
	uint16_t ownershipMemoryBasisPoints = 0;
	uint16_t ownershipStorageBasisPoints = 0;
	uint32_t totalLogicalCores = 0;
	uint32_t totalMemoryMB = 0;
	uint32_t totalStorageMB = 0;
	MachineHardwareProfile hardware;
   bool hasInternetAccess = false;
	uint32_t ownedLogicalCores = 0;
	uint32_t ownedMemoryMB = 0;
	uint32_t ownedStorageMB = 0;
   Vector<uint32_t> availableGPUMemoryMBs;
   Vector<uint32_t> availableGPUHardwareIndexes;

	uint128_t uuid = 0; // this will match neuron uuid if isThisMachine
	uint32_t rackUUID = 0;
	Rack *rack = nullptr; // we could always change this to a uuid if we wanted to, we at least have to serialize it that way

	int64_t creationTimeMs = 0;
    // Reported Clear Linux VERSION_ID (from neuron registration)
    uint32_t clearVersion = 0;
    // Current VM image reference if known (IaaS-specific discovery)
    String currentImageURI;
	// Connectivity/maintenance tracking used by Brain health and update flows.
	uint32_t brainConnectFailStreak = 0;
	uint32_t neuronConnectFailStreak = 0;
	int64_t lastNeuronFailMs = 0;
	uint32_t sshRestartAttempts = 0;
	int64_t lastSshAttemptMs = 0;
	int64_t lastUpdatedOSMs = 0;
	uint32_t hardRebootAttempts = 0;
	int64_t lastHardRebootMs = 0;
	TimeoutPacket *softWatchdog = nullptr;
	TimeoutPacket *hardRebootWatchdog = nullptr;
	bool inBinaryUpdate = false;
	String kernel;

	bool isBrain = false; // iaas will flip this, and then we need to match the brain
	BrainView *brain = nullptr;
	NeuronView neuron;

	bool isThisMachine = false;

	String hardwareFailureReport;

	// so if this machine dies, we can unwind
	bytell_hash_subvector<uint64_t, ContainerView *> containersByDeploymentID;

   // Machine-local networking addresses containers by an 8-bit fragment.
   static constexpr uint32_t maxSchedulableContainers = 256u;

   uint32_t indexedContainerCount(void)
   {
      uint64_t total = 0;

      for (const auto& [deploymentID, containers] : containersByDeploymentID)
      {
         (void)deploymentID;
         total += containers.size();
         if (total >= maxSchedulableContainers)
         {
            return maxSchedulableContainers;
         }
      }

      return static_cast<uint32_t>(total);
   }

   uint32_t claimedContainerCount(void)
   {
      uint64_t total = 0;

      for (const Claim& claim : claims)
      {
         total += claim.nFit;
         if (total >= maxSchedulableContainers)
         {
            return maxSchedulableContainers;
         }
      }

      return static_cast<uint32_t>(total);
   }

   uint32_t reservedContainerSlots(void)
   {
      uint64_t total = indexedContainerCount();
      total += claimedContainerCount();
      if (total >= maxSchedulableContainers)
      {
         return maxSchedulableContainers;
      }

      return static_cast<uint32_t>(total);
   }

   uint32_t availableContainerSlotsForScheduling(void)
   {
      uint32_t reserved = reservedContainerSlots();
      return (reserved >= maxSchedulableContainers) ? 0u : (maxSchedulableContainers - reserved);
   }

   void resetAvailableGPUMemoryMBsFromHardware(void)
   {
      availableGPUMemoryMBs.clear();
      availableGPUHardwareIndexes.clear();

      for (uint32_t index = 0; index < hardware.gpus.size(); ++index)
      {
         availableGPUHardwareIndexes.push_back(index);
      }

      std::sort(availableGPUHardwareIndexes.begin(), availableGPUHardwareIndexes.end(), [&] (uint32_t lhs, uint32_t rhs) -> bool {
         const MachineGpuHardwareProfile& a = hardware.gpus[lhs];
         const MachineGpuHardwareProfile& b = hardware.gpus[rhs];
         if (a.memoryMB != b.memoryMB)
         {
            return a.memoryMB < b.memoryMB;
         }

         return std::lexicographical_compare(a.busAddress.data(), a.busAddress.data() + a.busAddress.size(),
            b.busAddress.data(), b.busAddress.data() + b.busAddress.size());
      });

      for (uint32_t index : availableGPUHardwareIndexes)
      {
         availableGPUMemoryMBs.push_back(hardware.gpus[index].memoryMB);
      }
   }

   uint32_t availableGPUCount(void) const
   {
      return uint32_t(availableGPUMemoryMBs.size());
   }

	void removeContainerIndexEntry(uint64_t deploymentID, ContainerView *container)
	{
		if (container == nullptr)
		{
			return;
		}

		while (containersByDeploymentID.eraseEntry(deploymentID, container)) {}

		if (auto it = containersByDeploymentID.find(deploymentID); it != containersByDeploymentID.end() && it->second.size() == 0)
		{
			containersByDeploymentID.erase(deploymentID);
		}
	}

	void upsertContainerIndexEntry(uint64_t deploymentID, ContainerView *container)
	{
		if (container == nullptr)
		{
			return;
		}

		removeContainerIndexEntry(deploymentID, container);
		containersByDeploymentID.insert(deploymentID, container);
	}

	// available for scheduling
	// allow these to go negative so that during compaction we can charge a machine for resources before the existing container is destroyed
   uint32_t isolatedLogicalCoresCommitted = 0;
   uint32_t sharedCPUMillisCommitted = 0;
   int32_t nLogicalCores_available = 0;
   int32_t sharedCPUMillis_available = 0;
   int32_t memoryMB_available = 0;
   int32_t storageMB_available = 0; 

   Vector<Claim> claims; // while waiting for machine to be deployed and become healthy

	uint32_t fragment = 0;
	bytell_hash_set<uint32_t> usedContainerFragments;

	uint8_t getContainerFragment(void)
	{
		uint8_t fragment = 0;

		do
		{
			fragment = Random::generateNumberWithNBits<8, uint8_t>();

		} while (usedContainerFragments.contains(fragment));

		usedContainerFragments.insert(fragment);

		return fragment;
	}

	void relinquishContainerFragment(uint8_t fragment)
	{
		usedContainerFragments.erase(fragment);
	}

   template <typename... Args>
	void queueSend(NeuronTopic topic, Args&&... args)
	{
		Message::construct(neuron.wBuffer, topic, std::forward<Args>(args)...);
		Ring::queueSend(&neuron);
	}

  // explicit OS update hook retained for compatibility with brain orchestration paths.
	void triggerOSUpdate(void)
	{
		state = MachineState::updatingOS;
	}

	Machine()
	{
		neuron.rBuffer.reserve(8_KB);
		neuron.wBuffer.reserve(16_KB);
	}
};

static inline void prodigyResolveMachineRestartSSHCredentials(const Machine *machine, String& user, String& privateKeyPath)
{
   if (const char *overrideUser = getenv("PRODIGY_MACHINE_SSH_USER"); overrideUser && overrideUser[0] != '\0')
   {
      user.assign(overrideUser);
   }
   else if (machine != nullptr && machine->sshUser.size() > 0)
   {
      user.assign(machine->sshUser);
   }
   else
   {
      user.assign("root"_ctv);
   }

   if (const char *overrideKey = getenv("PRODIGY_MACHINE_SSH_PRIVATE_KEY"); overrideKey && overrideKey[0] != '\0')
   {
      privateKeyPath.assign(overrideKey);
   }
   else if (machine != nullptr && machine->sshPrivateKeyPath.size() > 0)
   {
      privateKeyPath.assign(machine->sshPrivateKeyPath);
   }
   else
   {
      privateKeyPath.assign("/root/.ssh/id_ed25519"_ctv);
   }
}

inline void MachineSSH::restartProdigy(void)
{
   String sshUser = {};
   String sshPrivateKeyPath = {};
   prodigyResolveMachineRestartSSHCredentials(machine, sshUser, sshPrivateKeyPath);

   uint16_t sshPort = 22;
   if (machine != nullptr && machine->sshPort > 0)
   {
      sshPort = machine->sshPort;
   }

   uint32_t suspendIndex = nextSuspendIndex();
   configureExpectedHostKey(machine->sshAddress, sshPort, machine->sshHostPublicKeyOpenSSH);
   bool useBootstrapSshKeyPackage = bootstrapSshKeyPackage != nullptr
      && bootstrapSshKeyPackage->privateKeyOpenSSH.size() > 0
      && bootstrapSshKeyPackage->publicKeyOpenSSH.size() > 0
      && (sshPrivateKeyPath.size() == 0
         || (bootstrapSshPrivateKeyPath != nullptr && sshPrivateKeyPath.equals(*bootstrapSshPrivateKeyPath))
         || ::access(sshPrivateKeyPath.c_str(), R_OK) != 0);

   if (useBootstrapSshKeyPackage)
   {
      authenticate(sshUser, *bootstrapSshKeyPackage);
   }
   else
   {
      authenticate(sshUser, sshPrivateKeyPath);
   }

   co_await suspendAtIndex(suspendIndex);
   if (failed)
   {
      co_return;
   }

   suspendIndex = nextSuspendIndex();

   executeCommand("systemctl restart prodigy"_ctv);

   co_await suspendAtIndex(suspendIndex);
   if (failed)
   {
      co_return;
   }

   callback();
}
