#pragma once

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <prodigy/bootstrap.config.h>
#include <prodigy/iaas/iaas.h>
#include <prodigy/brain/base.h>
#include <prodigy/brain/machine.h>
#include <prodigy/netdev.detect.h>
#include <prodigy/peer.address.helpers.h>

class BootstrapBrainIaaS : public BrainIaaS
{
private:

   ProdigyBootstrapConfig config;

   class BootstrapPeer {
   public:

      bool isBrain = true;
      Vector<ClusterMachinePeerAddress> addresses;
   };

   static bool resolveBootstrapPeerAddress(const BootstrapPeer& peer, IPAddress& address, String& addressText)
   {
      address = {};
      addressText.clear();

      for (const ClusterMachinePeerAddress& candidate : peer.addresses)
      {
         if (candidate.address.size() == 0)
         {
            continue;
         }

         if (ClusterMachine::parseIPAddressLiteral(candidate.address, address) == false)
         {
            continue;
         }

         addressText.assign(candidate.address);
         return true;
      }

      return false;
   }

   static bool appendUniqueBootstrapPeer(Vector<BootstrapPeer>& peers, const BootstrapPeer& peer)
   {
      if (peer.addresses.empty())
      {
         return false;
      }

      for (const BootstrapPeer& existing : peers)
      {
         if (prodigyClusterMachinePeerAddressesEqual(existing.addresses, peer.addresses))
         {
            return false;
         }
      }

      peers.push_back(peer);
      return true;
   }

   void collectLocalCandidateAddresses(Vector<ClusterMachinePeerAddress>& localAddresses) const
   {
      String preferredInterface = {};
      IPAddress private4 = {};
      if (thisNeuron)
      {
         preferredInterface.assign(thisNeuron->eth.name);
         private4 = thisNeuron->private4;
      }

      prodigyCollectLocalPeerAddressCandidates(preferredInterface, private4, localAddresses);
   }

   bool isLocalBootstrapPeer(const BootstrapPeer& peer) const
   {
      Vector<ClusterMachinePeerAddress> localAddresses;
      collectLocalCandidateAddresses(localAddresses);

      for (const ClusterMachinePeerAddress& localAddress : localAddresses)
      {
         IPAddress localCandidateAddress = {};
         if (ClusterMachine::parseIPAddressLiteral(localAddress.address, localCandidateAddress) == false)
         {
            continue;
         }

         String addressText = {};
         for (const ClusterMachinePeerAddress& peerAddress : peer.addresses)
         {
            if (peerAddress.address.equals(localAddress.address))
            {
               return true;
            }

            IPAddress candidateAddress = {};
            if (ClusterMachine::parseIPAddressLiteral(peerAddress.address, candidateAddress) && candidateAddress.equals(localCandidateAddress))
            {
               return true;
            }
         }
      }

      return false;
   }

   bool resolvePreferredLocalBootstrapPeer(BootstrapPeer& peer) const
   {
      peer = {};

      Vector<ClusterMachinePeerAddress> localAddresses;
      collectLocalCandidateAddresses(localAddresses);
      if (localAddresses.empty())
      {
         return false;
      }

      peer.addresses = localAddresses;
      return true;
   }

   void collectBootstrapPeers(Vector<BootstrapPeer>& peers) const
   {
      peers.clear();

      for (const ProdigyBootstrapConfig::BootstrapPeer& configuredPeer : config.bootstrapPeers)
      {
         BootstrapPeer peer = {};
         peer.isBrain = configuredPeer.isBrain;
         peer.addresses = configuredPeer.addresses;
         (void)appendUniqueBootstrapPeer(peers, peer);
      }

      if (config.nodeRole != ProdigyBootstrapNodeRole::brain)
      {
         return;
      }

      bool haveLocalPeer = false;
      for (const BootstrapPeer& peer : peers)
      {
         if (isLocalBootstrapPeer(peer))
         {
            haveLocalPeer = true;
            break;
         }
      }

      if (haveLocalPeer == false)
      {
         BootstrapPeer localPeer = {};
         localPeer.isBrain = true;
         if (resolvePreferredLocalBootstrapPeer(localPeer))
         {
            peers.push_back(localPeer);
         }
      }
   }

   void configureNeuronAddressing(NeuronView& neuron, const BootstrapPeer& peer) const
   {
      IPAddress peerAddress = {};
      String peerAddressText = {};
      if (resolveBootstrapPeerAddress(peer, peerAddress, peerAddressText) == false)
      {
         return;
      }

      neuron.setIPVersion(peerAddress.is6 ? AF_INET6 : AF_INET);
      neuron.setDatacenterCongestion();
      IPAddress sourceAddress = {};
      if (peer.addresses.empty() == false)
      {
         Vector<ClusterMachinePeerAddress> localAddresses;
         collectLocalCandidateAddresses(localAddresses);
         if (prodigyResolvePreferredLocalSourceAddress(localAddresses, peer.addresses[0], sourceAddress))
         {
            neuron.setSaddr(sourceAddress);
         }
      }
      if (peerAddress.is6 == false && thisNeuron && thisNeuron->private4.v4 != 0)
      {
         neuron.setSaddr(thisNeuron->private4);
      }
      neuron.setDaddr(peerAddress, uint16_t(ReservedPorts::neuron));
   }

public:

   explicit BootstrapBrainIaaS(const ProdigyBootstrapConfig& bootstrapConfig) : config(bootstrapConfig) {}

   bool resolveLocalBrainPeerAddress(IPAddress& address, String& addressText) const override
   {
      address = {};
      addressText.clear();

      Vector<BootstrapPeer> peers;
      collectBootstrapPeers(peers);

      for (const BootstrapPeer& peer : peers)
      {
         if (isLocalBootstrapPeer(peer))
         {
            return resolveBootstrapPeerAddress(peer, address, addressText);
         }
      }

      return false;
   }

   void boot(void) override
   {
   }

   void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) override
   {
      (void)coro;
      (void)lifetime;
      (void)config;
      (void)count;
      (void)newMachines;
      error.assign("bootstrap iaas cannot provision machines"_ctv);
   }

   void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines) override
   {
      (void)coro;
      (void)metro;

      Vector<BootstrapPeer> peers;
      collectBootstrapPeers(peers);

      uint32_t rackUUID = 1;
      for (const BootstrapPeer& peer : peers)
      {
         IPAddress peerAddress = {};
         String peerAddressText = {};
         if (resolveBootstrapPeerAddress(peer, peerAddress, peerAddressText) == false)
         {
            continue;
         }

         Machine *machine = new Machine();
         machine->uuid = (isLocalBootstrapPeer(peer) && thisNeuron != nullptr) ? thisNeuron->uuid : uint128_t(0);
         machine->isBrain = peer.isBrain;
         machine->isThisMachine = isLocalBootstrapPeer(peer);
         machine->private4 = peerAddress.is6 ? 0u : peerAddress.v4;
         machine->gatewayPrivate4 = (thisNeuron ? thisNeuron->gateway4.v4 : 0);
         machine->privateAddress = peerAddressText;
         machine->peerAddresses = peer.addresses;
         machine->slug.assign("bootstrap"_ctv);
         machine->lifetime = MachineLifetime::owned;
         machine->creationTimeMs = 0;
         machine->rackUUID = rackUUID++;
         machine->neuron.machine = machine;
         configureNeuronAddressing(machine->neuron, peer);
         machines.insert(machine);
      }
   }

   void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains) override
   {
      (void)coro;
      (void)selfUUID;

      selfIsBrain = (config.nodeRole == ProdigyBootstrapNodeRole::brain);

      Vector<BootstrapPeer> peers;
      collectBootstrapPeers(peers);

      for (const BootstrapPeer& peer : peers)
      {
         bool isLocal = isLocalBootstrapPeer(peer);
         if (isLocal)
         {
            continue;
         }

         if (peer.isBrain == false)
         {
            continue;
         }

         IPAddress peerAddress = {};
         String peerAddressText = {};
         if (resolveBootstrapPeerAddress(peer, peerAddress, peerAddressText) == false)
         {
            continue;
         }

         BrainView *brain = new BrainView();
         brain->uuid = 0;
         brain->private4 = peerAddress.is6 ? 0u : peerAddress.v4;
         brain->gatewayPrivate4 = (thisNeuron ? thisNeuron->gateway4.v4 : 0);
         brain->creationTimeMs = 0;
         brain->peerAddress = peerAddress;
         brain->peerAddressText = peerAddressText;
         brain->peerAddresses = peer.addresses;
         brains.insert(brain);
      }
   }

   void hardRebootMachine(uint128_t uuid) override
   {
      (void)uuid;
   }

   void reportHardwareFailure(uint128_t uuid, const String& report) override
   {
      (void)uuid;
      (void)report;
   }

   void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
   {
      (void)coro;
      (void)decommissionedIDs;
   }

   void destroyMachine(Machine *machine) override
   {
      (void)machine;
   }

   uint32_t supportedMachineKindsMask() const override
   {
      return 3u;
   }

   bool supportsAutoProvision() const override
   {
      return false;
   }
};

class BootstrapNeuronIaaS : public NeuronIaaS
{
private:

   ProdigyBootstrapConfig config;

public:

   explicit BootstrapNeuronIaaS(const ProdigyBootstrapConfig& bootstrapConfig) : config(bootstrapConfig) {}

   void gatherSelfData(uint128_t& uuid, String& metro, bool& isBrain, EthDevice& eth, IPAddress& private4) override
   {
      String deviceName;
      if (prodigyResolvePrimaryNetworkDevice(deviceName))
      {
         eth.setDevice(deviceName);
      }

      metro.assign("bootstrap"_ctv);
      private4.is6 = false;
      private4.v4 = eth.getPrivate4();

      if (private4.v4 == 0)
      {
         EthDevice lo;
         lo.setDevice("lo"_ctv);
         private4.v4 = lo.getPrivate4();
      }

      uuid = 0;
      isBrain = (config.nodeRole == ProdigyBootstrapNodeRole::brain);
   }

   void downloadContainerToPath(CoroutineStack *coro, uint64_t deploymentID, const String& path) override
   {
      (void)coro;
      (void)deploymentID;
      (void)path;
   }
};
