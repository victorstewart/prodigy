#include <services/crypto.h>
#include <spawn.h>
#include <prodigy/cluster.machine.helpers.h>

#pragma once

class DevBrainIaaS : public BrainIaaS {
public:

	Vector<String> privates;

	void boot(void) override
	{
		// no network api to setup obviously lol
	}

    uint32_t supportedMachineKindsMask() const override { return 1u; /* bareMetal only */ }
    bool supportsAutoProvision() const override { return false; }

	void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) override
	{
		// obviously we don't create any new machines
		// but deployments would've queued container scheduling that is only triggered by new machines coming online... so just don't try to schedule too much?
	}

	void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines) override
	{
		uint32_t rackUUID = Crypto::insecureRandomNumber<uint32_t>();
		uint32_t gatewayPrivate4 = thisNeuron->gateway4.v4;
		if (gatewayPrivate4 == 0)
		{
			(void)inet_pton(AF_INET, "10.0.0.1", &gatewayPrivate4);
		}

		for (String& private4String : privates)
		{
			const char *private4Text = private4String.c_str();
			if (private4Text == nullptr || private4Text[0] == '\0') continue;

			uint32_t private4 = 0;
			if (inet_pton(AF_INET, private4Text, &private4) != 1) continue;

			Machine *machine = new Machine();
			machines.insert(machine);

			// Dev harness treats every listed private as a brain-capable machine.
				machine->isBrain = true;
				machine->isThisMachine = (thisNeuron->private4.v4 == private4);
				machine->uuid = (machine->isThisMachine && thisNeuron != nullptr) ? thisNeuron->uuid : uint128_t(0);
				machine->private4 = private4;
				machine->privateAddress.assign(private4String);
				machine->slug.assign("dev-baremetal"_ctv);
				machine->lifetime = MachineLifetime::owned;

			// Dev harness still runs reachability logic that expects a gateway.
			machine->gatewayPrivate4 = gatewayPrivate4;
			
			machine->neuron.machine = machine;

			machine->creationTimeMs = private4 * -1;

			rackUUID += 1;
			machine->rackUUID = rackUUID;

				prodigyConfigureMachineNeuronEndpoint(*machine, thisNeuron);
			}
		}

	// all 3 are brains
	void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains) override
	{
		uint32_t gatewayPrivate4 = thisNeuron->gateway4.v4;
		if (gatewayPrivate4 == 0)
		{
			(void)inet_pton(AF_INET, "10.0.0.1", &gatewayPrivate4);
		}

		for (String& private4String : privates)
		{
			const char *private4Text = private4String.c_str();
			if (private4Text == nullptr || private4Text[0] == '\0') continue;

			uint32_t private4 = 0;
			if (inet_pton(AF_INET, private4Text, &private4) != 1) continue;

			if (thisNeuron->private4.v4 != private4)
			{
					BrainView *brain = new BrainView();

					brain->uuid = 0;
					brain->private4 = private4;
					brain->peerAddress.is6 = false;
					brain->peerAddress.v4 = private4;
					brain->peerAddressText.assign(private4String);
					brain->gatewayPrivate4 = gatewayPrivate4;

				brain->creationTimeMs = private4 * -1;

				brains.insert(brain);
			}
			else
			{
				selfIsBrain = true;
			}
		}
	}

	void hardRebootMachine(uint128_t uuid) override
	{
		// this doesn't apply because for cloud machines this occurs through the management BIOS
	}

	void reportHardwareFailure(uint128_t uuid, const String& report) override
	{
		// no one to report to lol
	}

	void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
	{
		(void)coro;
		(void)decommissionedIDs;
	}

	void destroyMachine(Machine *machine) override
	{
		// we never do this obviously
	}
};

	class DevNeuronIaaS : public NeuronIaaS {
	public:

		void gatherSelfData(uint128_t& uuid, String& metro, bool& isBrain, EthDevice& eth, IPAddress& private4) override
		{	
		metro.assign("dev"_ctv);
		private4.is6 = false;

		// Runtime persistence owns the canonical brain UUID.
		private4.v4 = eth.getPrivate4();
		if (private4.v4 == 0)
		{
			// Fallback for older local setups that still rely on loopback-assigned private addresses.
			EthDevice lo;
			lo.setDevice("lo"_ctv);
			private4.v4 = lo.getPrivate4();
		}

		uuid = 0;

		// obviously no BGP here

			isBrain = true;
		}

      void setLocalContainerPrefixes(const Vector<IPPrefix>& prefixes) override
      {
         for (const IPPrefix& prefix : prefixes)
         {
            if (prefix.network.v6[0] != 0xfd) // this is the container-network subnet
            {
               continue;
            }

            char subnetString[INET6_ADDRSTRLEN] = {0};
            if (inet_ntop(AF_INET6, prefix.network.v6, subnetString, sizeof(subnetString)) == nullptr)
            {
               continue;
            }

            String config;
            String subnetText = {};
            subnetText.assign(subnetString);
            config.snprintf<"interface enp1s0 { AdvSendAdvert on; prefix {} { AdvOnLink on; AdvAutonomous on; }; AdvDefaultLifetime 0; };"_ctv>(subnetText);

            Filesystem::openWriteAtClose(-1, "/etc/radvd.conf"_ctv, config);

            // Spawn radvd without shell
            pid_t pid = -1; posix_spawn_file_actions_t fa; posix_spawn_file_actions_init(&fa);
            char *const argv[] = { (char*)"radvd", nullptr };
            int rc = posix_spawnp(&pid, "radvd", &fa, nullptr, argv, environ); (void)rc;
            posix_spawn_file_actions_destroy(&fa);
            return;
         }
      }

		void downloadContainerToPath(CoroutineStack *coro, uint64_t deploymentID, const String& path) override
		{
			// maybe we just store these locally on disk, then copy them to the path provided?
		}

		DevNeuronIaaS()
		{
		Filesystem::eraseFile("/etc/radvd.conf"_ctv);
	}
};
