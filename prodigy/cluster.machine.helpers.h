#pragma once

#include <arpa/inet.h>
#include <poll.h>

#include <prodigy/iaas/iaas.h>
#include <prodigy/neuron/base.h>
#include <prodigy/peer.address.helpers.h>
#include <prodigy/brain/timing.knobs.h>
#include <networking/includes.h>
#include <services/prodigy.h>
#include <prodigy/types.h>
#include <prodigy/brain/machine.h>

static inline void prodigyCollectMachinePeerAddresses(const Machine& machine, Vector<ClusterMachinePeerAddress>& candidates)
{
   candidates.clear();

   if (machine.peerAddresses.size() > 0)
   {
      for (const ClusterMachinePeerAddress& candidate : machine.peerAddresses)
      {
         prodigyAppendUniqueClusterMachinePeerAddress(candidates, candidate);
      }
      return;
   }

   if (machine.privateAddress.size() > 0)
   {
      String gatewayText = {};
      if (machine.gatewayPrivate4 != 0)
      {
         IPAddress gatewayAddress = {};
         gatewayAddress.v4 = machine.gatewayPrivate4;
         gatewayAddress.is6 = false;
         (void)ClusterMachine::renderIPAddressLiteral(gatewayAddress, gatewayText);
      }
      prodigyAppendUniqueClusterMachinePeerAddress(candidates, ClusterMachinePeerAddress{machine.privateAddress, 0, gatewayText});
   }

   if (machine.private4 != 0)
   {
      IPAddress private4Address = {};
      private4Address.v4 = machine.private4;
      private4Address.is6 = false;
      String private4Text = {};
      if (ClusterMachine::renderIPAddressLiteral(private4Address, private4Text))
      {
         String gatewayText = {};
         if (machine.gatewayPrivate4 != 0)
         {
            IPAddress gatewayAddress = {};
            gatewayAddress.v4 = machine.gatewayPrivate4;
            gatewayAddress.is6 = false;
            (void)ClusterMachine::renderIPAddressLiteral(gatewayAddress, gatewayText);
         }
         prodigyAppendUniqueClusterMachinePeerAddress(candidates, ClusterMachinePeerAddress{private4Text, 0, gatewayText});
      }
   }

   if (machine.publicAddress.size() > 0)
   {
      prodigyAppendUniqueClusterMachinePeerAddress(candidates, ClusterMachinePeerAddress{machine.publicAddress, 0, {}});
   }

   if (machine.sshAddress.size() > 0)
   {
      prodigyAppendUniqueClusterMachinePeerAddress(candidates, ClusterMachinePeerAddress{machine.sshAddress, 0, {}});
   }
}

static inline bool prodigyMachinePeerAddressMatches(const Machine& machine, const IPAddress& address, const String *addressText = nullptr)
{
   if (address.isNull())
   {
      return false;
   }

   Vector<ClusterMachinePeerAddress> candidates;
   prodigyCollectMachinePeerAddresses(machine, candidates);
   for (const ClusterMachinePeerAddress& candidate : candidates)
   {
      if (candidate.address.size() == 0)
      {
         continue;
      }

      if (addressText && candidate.address.equals(*addressText))
      {
         return true;
      }

      IPAddress candidateAddress = {};
      if (ClusterMachine::parseIPAddressLiteral(candidate.address, candidateAddress) && candidateAddress.equals(address))
      {
         return true;
      }
   }

   return false;
}

static inline bool prodigyResolveMachinePeerAddress(const Machine& machine, IPAddress& resolvedAddress, String *resolvedAddressText = nullptr)
{
   resolvedAddress = {};
   if (resolvedAddressText)
   {
      resolvedAddressText->clear();
   }

   Vector<ClusterMachinePeerAddress> candidates;
   prodigyCollectMachinePeerAddresses(machine, candidates);
   for (const ClusterMachinePeerAddress& candidate : candidates)
   {
      if (candidate.address.size() == 0)
      {
         continue;
      }

      if (ClusterMachine::parseIPAddressLiteral(candidate.address, resolvedAddress) == false)
      {
         continue;
      }

      if (resolvedAddressText)
      {
         resolvedAddressText->assign(candidate.address);
      }

      return true;
   }

   return false;
}

static inline bool prodigyResolveMachineSSHAddress(const Machine& machine, String& sshAddress)
{
   sshAddress.assign(machine.sshAddress);
   if (sshAddress.size() == 0)
   {
      if (machine.privateAddress.size() > 0)
      {
         sshAddress.assign(machine.privateAddress);
      }
      else
      {
         sshAddress.assign(machine.publicAddress);
      }
   }

   return sshAddress.size() > 0;
}

static inline bool prodigyResolveMachineSSHSocketAddress(const Machine& machine, IPAddress& resolvedAddress, uint16_t& resolvedPort, String *resolvedAddressText = nullptr)
{
   String sshAddress = {};
   if (prodigyResolveMachineSSHAddress(machine, sshAddress) == false)
   {
      resolvedAddress = {};
      resolvedPort = machine.sshPort > 0 ? machine.sshPort : 22;
      if (resolvedAddressText)
      {
         resolvedAddressText->clear();
      }
      return false;
   }

   if (ClusterMachine::parseIPAddressLiteral(sshAddress, resolvedAddress) == false)
   {
      resolvedPort = machine.sshPort > 0 ? machine.sshPort : 22;
      if (resolvedAddressText)
      {
         resolvedAddressText->clear();
      }
      return false;
   }

   resolvedPort = machine.sshPort > 0 ? machine.sshPort : 22;
   if (resolvedAddressText)
   {
      resolvedAddressText->assign(sshAddress);
   }

   return true;
}

static inline bool prodigyResolveMachineSSHSocketAddress(const Machine& machine, IPAddress& resolvedAddress, String *resolvedAddressText = nullptr)
{
   uint16_t resolvedPort = 0;
   return prodigyResolveMachineSSHSocketAddress(machine, resolvedAddress, resolvedPort, resolvedAddressText);
}

static inline void prodigyConfigureMachineNeuronEndpoint(Machine& machine, const NeuronBase *localNeuron)
{
   IPAddress peerAddress = {};
   if (prodigyResolveMachinePeerAddress(machine, peerAddress) == false)
   {
      return;
   }

   // Topology reapply runs against already-live machines too. Once the neuron socket
   // is installed into a fixed-file slot, recreating it here would destroy the live
   // transport and TCPSocket::setIPVersion() hard-aborts on fixed sockets.
   if (machine.neuron.isFixedFile == false)
   {
      machine.neuron.setIPVersion(peerAddress.is6 ? AF_INET6 : AF_INET);
      machine.neuron.setDatacenterCongestion();
   }

   ClusterMachinePeerAddress remoteCandidate = {};
   if (machine.peerAddresses.empty() == false)
   {
      remoteCandidate = machine.peerAddresses[0];
   }
   else if (machine.privateAddress.size() > 0)
   {
      remoteCandidate.address = machine.privateAddress;
   }

   if (localNeuron != nullptr && remoteCandidate.address.size() > 0)
   {
      Vector<ClusterMachinePeerAddress> localCandidates = {};
      String preferredInterface = {};
      preferredInterface.assign(localNeuron->eth.name);
      prodigyCollectLocalPeerAddressCandidates(preferredInterface, localNeuron->private4, localCandidates);

      IPAddress sourceAddress = {};
      if (prodigyResolvePreferredLocalSourceAddress(localCandidates, remoteCandidate, sourceAddress))
      {
         machine.neuron.setSaddr(sourceAddress);
      }
   }

   if (peerAddress.is6 == false && localNeuron != nullptr && localNeuron->private4.v4 != 0)
   {
      machine.neuron.setSaddr(localNeuron->private4);
   }
   machine.neuron.setDaddr(peerAddress, uint16_t(ReservedPorts::neuron));
}

static inline bool prodigyMachineProvisioningReady(const Machine& machine)
{
   IPAddress peerAddress = {};
   String sshAddress = {};
   return prodigyResolveMachinePeerAddress(machine, peerAddress)
      && prodigyResolveMachineSSHAddress(machine, sshAddress);
}

static inline bool prodigyMachineSSHSocketAcceptingConnections(const Machine& machine, uint32_t timeoutMs = prodigyBrainControlPlaneConnectTimeoutMs)
{
   IPAddress sshAddress = {};
   uint16_t sshPort = 0;
   if (prodigyResolveMachineSSHSocketAddress(machine, sshAddress, sshPort) == false)
   {
      return false;
   }

   TCPSocket probe = {};
   probe.setIPVersion(sshAddress.is6 ? AF_INET6 : AF_INET);
   probe.setNonBlocking();
   probe.setDatacenterCongestion();
   probe.setDaddr(sshAddress, sshPort);

   bool ready = false;
   int connectResult = probe.connect();
   if (connectResult == 0)
   {
      ready = true;
   }
   else
   {
      int connectErrno = errno;
      if (connectErrno == EINPROGRESS || connectErrno == EALREADY || connectErrno == EWOULDBLOCK || connectErrno == EAGAIN)
      {
         struct pollfd pollFD = {};
         pollFD.fd = probe.fd;
         pollFD.events = POLLOUT | POLLERR | POLLHUP;

         int pollResult = 0;
         do
         {
            pollResult = ::poll(&pollFD, 1, int(timeoutMs));
         }
         while (pollResult < 0 && errno == EINTR);

         if (pollResult > 0)
         {
            int socketError = 0;
            socklen_t socketErrorLen = sizeof(socketError);
            if (::getsockopt(probe.fd, SOL_SOCKET, SO_ERROR, &socketError, &socketErrorLen) == 0 && socketError == 0)
            {
               ready = true;
            }
         }
      }
   }

   if (probe.fd >= 0)
   {
      probe.close();
      probe.fd = -1;
   }

   return ready;
}

static inline bool prodigyMachineProvisioningSSHReady(const Machine& machine, uint32_t timeoutMs = prodigyBrainControlPlaneConnectTimeoutMs)
{
   return prodigyMachineProvisioningReady(machine)
      && prodigyMachineSSHSocketAcceptingConnections(machine, timeoutMs);
}

static inline bool prodigyMachinesShareIdentity(const Machine& lhs, const Machine& rhs)
{
   if (lhs.uuid != 0 && rhs.uuid != 0 && lhs.uuid == rhs.uuid)
   {
      return true;
   }

   if (lhs.cloudID.size() > 0
      && rhs.cloudID.size() > 0
      && lhs.cloudID.equals(rhs.cloudID))
   {
      return true;
   }

   IPAddress lhsPeerAddress = {};
   IPAddress rhsPeerAddress = {};
   bool lhsHasPeerAddress = prodigyResolveMachinePeerAddress(lhs, lhsPeerAddress);
   bool rhsHasPeerAddress = prodigyResolveMachinePeerAddress(rhs, rhsPeerAddress);
   if (lhsHasPeerAddress && prodigyMachinePeerAddressMatches(rhs, lhsPeerAddress))
   {
      return true;
   }

   if (rhsHasPeerAddress && prodigyMachinePeerAddressMatches(lhs, rhsPeerAddress))
   {
      return true;
   }

   String lhsSSHAddress = {};
   String rhsSSHAddress = {};
   if (prodigyResolveMachineSSHAddress(lhs, lhsSSHAddress)
      && prodigyResolveMachineSSHAddress(rhs, rhsSSHAddress)
      && lhsSSHAddress.equals(rhsSSHAddress))
   {
      return true;
   }

   return (lhsHasPeerAddress == false || rhsHasPeerAddress == false)
      && lhs.private4 != 0
      && rhs.private4 != 0
      && lhs.private4 == rhs.private4;
}

static inline bool prodigyMachineIdentityComesBefore(const Machine& lhs, const Machine& rhs)
{
   if (lhs.uuid != rhs.uuid)
   {
      return lhs.uuid < rhs.uuid;
   }

   IPAddress lhsPeerAddress = {};
   IPAddress rhsPeerAddress = {};
   String lhsPeerText = {};
   String rhsPeerText = {};
   bool lhsHasPeerAddress = prodigyResolveMachinePeerAddress(lhs, lhsPeerAddress, &lhsPeerText);
   bool rhsHasPeerAddress = prodigyResolveMachinePeerAddress(rhs, rhsPeerAddress, &rhsPeerText);
   if (lhsHasPeerAddress != rhsHasPeerAddress)
   {
      return lhsHasPeerAddress;
   }

   if (lhsPeerText.equals(rhsPeerText) == false)
   {
      return std::lexicographical_compare(lhsPeerText.data(), lhsPeerText.data() + lhsPeerText.size(),
         rhsPeerText.data(), rhsPeerText.data() + rhsPeerText.size());
   }

   if (lhs.cloudID.equals(rhs.cloudID) == false)
   {
      return std::lexicographical_compare(lhs.cloudID.data(), lhs.cloudID.data() + lhs.cloudID.size(),
         rhs.cloudID.data(), rhs.cloudID.data() + rhs.cloudID.size());
   }

   String lhsSSHAddress = {};
   String rhsSSHAddress = {};
   bool lhsHasSSHAddress = prodigyResolveMachineSSHAddress(lhs, lhsSSHAddress);
   bool rhsHasSSHAddress = prodigyResolveMachineSSHAddress(rhs, rhsSSHAddress);
   if (lhsHasSSHAddress != rhsHasSSHAddress)
   {
      return lhsHasSSHAddress;
   }

   if (lhsSSHAddress.equals(rhsSSHAddress) == false)
   {
      return std::lexicographical_compare(lhsSSHAddress.data(), lhsSSHAddress.data() + lhsSSHAddress.size(),
         rhsSSHAddress.data(), rhsSSHAddress.data() + rhsSSHAddress.size());
   }

   if (lhs.creationTimeMs != rhs.creationTimeMs)
   {
      return lhs.creationTimeMs < rhs.creationTimeMs;
   }

   if (lhs.rackUUID != rhs.rackUUID)
   {
      return lhs.rackUUID < rhs.rackUUID;
   }

   return std::lexicographical_compare(lhs.type.data(), lhs.type.data() + lhs.type.size(),
      rhs.type.data(), rhs.type.data() + rhs.type.size());
}

static inline void prodigyPopulateCreatedClusterMachineFromSnapshot(ClusterMachine& clusterMachine, Machine *snapshot, const CreateMachinesInstruction& instruction, const MachineConfig& machineConfig, const String& defaultSSHUser, const String& defaultSSHPrivateKeyPath, const String& defaultSSHHostPublicKeyOpenSSH)
{
   clusterMachine = {};
   clusterMachine.source = ClusterMachineSource::created;
   clusterMachine.backing = instruction.backing;
   clusterMachine.kind = machineConfig.kind;
   clusterMachine.lifetime = instruction.lifetime;
   clusterMachine.isBrain = instruction.isBrain;
   clusterMachine.hasCloud = true;
   clusterMachine.cloud.schema = instruction.cloud.schema;
   clusterMachine.cloud.providerMachineType = instruction.cloud.providerMachineType.size() > 0 ? instruction.cloud.providerMachineType : snapshot->type;
   clusterMachine.cloud.cloudID = snapshot->cloudID;
   clusterMachine.ssh.address = snapshot->sshAddress;
   clusterMachine.ssh.port = snapshot->sshPort > 0 ? snapshot->sshPort : 22;
   clusterMachine.ssh.user = snapshot->sshUser.size() > 0 ? snapshot->sshUser : defaultSSHUser;
   clusterMachine.ssh.privateKeyPath = snapshot->sshPrivateKeyPath.size() > 0 ? snapshot->sshPrivateKeyPath : defaultSSHPrivateKeyPath;
   clusterMachine.ssh.hostPublicKeyOpenSSH = snapshot->sshHostPublicKeyOpenSSH.size() > 0 ? snapshot->sshHostPublicKeyOpenSSH : defaultSSHHostPublicKeyOpenSSH;
   prodigyAssignClusterMachineAddressesFromPeerCandidates(clusterMachine.addresses, snapshot->peerAddresses);
   prodigyAppendUniqueClusterMachineAddress(clusterMachine.addresses.publicAddresses, snapshot->publicAddress);
   String privateGateway = {};
   if (snapshot->gatewayPrivate4 != 0)
   {
      IPAddress gatewayAddress = {};
      gatewayAddress.v4 = snapshot->gatewayPrivate4;
      gatewayAddress.is6 = false;
      (void)ClusterMachine::renderIPAddressLiteral(gatewayAddress, privateGateway);
   }
   prodigyAppendUniqueClusterMachineAddress(clusterMachine.addresses.privateAddresses, snapshot->privateAddress, 0, privateGateway);
   clusterMachine.uuid = snapshot->uuid;
   clusterMachine.rackUUID = snapshot->rackUUID;
   clusterMachine.creationTimeMs = snapshot->creationTimeMs > 0 ? snapshot->creationTimeMs : Time::now<TimeResolution::ms>();
   clusterMachine.hasInternetAccess = snapshot->hasInternetAccess;
   clusterMachine.hardware = snapshot->hardware;
   clusterMachine.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
   uint32_t resolvedLogicalCores = machineConfig.nLogicalCores > 0 ? machineConfig.nLogicalCores : snapshot->totalLogicalCores;
   uint32_t resolvedMemoryMB = machineConfig.nMemoryMB > 0 ? machineConfig.nMemoryMB : snapshot->totalMemoryMB;
   uint32_t resolvedStorageMB = machineConfig.nStorageMB > 0 ? machineConfig.nStorageMB : snapshot->totalStorageMB;
   clusterMachineApplyOwnedResourcesFromTotals(clusterMachine, resolvedLogicalCores, resolvedMemoryMB, resolvedStorageMB);

   if (clusterMachine.addresses.privateAddresses.empty() && snapshot->private4 != 0)
   {
      struct in_addr address = {};
      address.s_addr = snapshot->private4;
      char buffer[INET_ADDRSTRLEN] = {};
      if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) != nullptr)
      {
         String privateAddress = {};
         privateAddress.assign(buffer);
         prodigyAppendUniqueClusterMachineAddress(clusterMachine.addresses.privateAddresses, privateAddress, 0, privateGateway);
      }
   }

   if (clusterMachine.ssh.address.size() == 0)
   {
      if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(clusterMachine.addresses.privateAddresses); privateAddress != nullptr)
      {
         clusterMachine.ssh.address = privateAddress->address;
      }
      else if (const ClusterMachineAddress *publicAddress = prodigyFirstClusterMachineAddress(clusterMachine.addresses.publicAddresses); publicAddress != nullptr)
      {
         clusterMachine.ssh.address = publicAddress->address;
      }
   }

   if (clusterMachine.addresses.privateAddresses.empty() && clusterMachine.addresses.publicAddresses.empty())
   {
      ClusterTopology topology = {};
      topology.machines.push_back(clusterMachine);
      prodigyNormalizeClusterTopologyPeerAddresses(topology);
      clusterMachine.addresses = topology.machines[0].addresses;
   }
}

static inline void prodigyPopulateCreatedClusterMachineFromAcceptance(ClusterMachine& clusterMachine, const String& cloudID, const CreateMachinesInstruction& instruction, const MachineConfig& machineConfig, const String& defaultSSHUser, const String& defaultSSHPrivateKeyPath, const String& defaultSSHHostPublicKeyOpenSSH)
{
   clusterMachine = {};
   clusterMachine.source = ClusterMachineSource::created;
   clusterMachine.backing = instruction.backing;
   clusterMachine.kind = machineConfig.kind;
   clusterMachine.lifetime = instruction.lifetime;
   clusterMachine.isBrain = instruction.isBrain;
   clusterMachine.hasCloud = true;
   clusterMachine.cloud.schema = instruction.cloud.schema;
   clusterMachine.cloud.providerMachineType = instruction.cloud.providerMachineType.size() > 0
      ? instruction.cloud.providerMachineType
      : machineConfig.providerMachineType;
   clusterMachine.cloud.cloudID = cloudID;
   clusterMachine.ssh.port = 22;
   clusterMachine.ssh.user = defaultSSHUser;
   clusterMachine.ssh.privateKeyPath = defaultSSHPrivateKeyPath;
   clusterMachine.ssh.hostPublicKeyOpenSSH = defaultSSHHostPublicKeyOpenSSH;
   clusterMachine.creationTimeMs = Time::now<TimeResolution::ms>();
   clusterMachine.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
   clusterMachineApplyOwnedResourcesFromTotals(
      clusterMachine,
      machineConfig.nLogicalCores,
      machineConfig.nMemoryMB,
      machineConfig.nStorageMB);
}

static inline void prodigyRefreshCreatedClusterMachineFromSnapshot(ClusterMachine& clusterMachine, Machine *snapshot, const String& defaultSSHUser, const String& defaultSSHPrivateKeyPath, const String& defaultSSHHostPublicKeyOpenSSH)
{
   ClusterMachine refreshed = clusterMachine;
   refreshed.ssh.address = snapshot->sshAddress;
   refreshed.ssh.port = snapshot->sshPort > 0 ? snapshot->sshPort : (refreshed.ssh.port > 0 ? refreshed.ssh.port : 22);
   refreshed.ssh.user = snapshot->sshUser.size() > 0 ? snapshot->sshUser : (refreshed.ssh.user.size() > 0 ? refreshed.ssh.user : defaultSSHUser);
   refreshed.ssh.privateKeyPath = snapshot->sshPrivateKeyPath.size() > 0 ? snapshot->sshPrivateKeyPath : (refreshed.ssh.privateKeyPath.size() > 0 ? refreshed.ssh.privateKeyPath : defaultSSHPrivateKeyPath);
   refreshed.ssh.hostPublicKeyOpenSSH = snapshot->sshHostPublicKeyOpenSSH.size() > 0 ? snapshot->sshHostPublicKeyOpenSSH : (refreshed.ssh.hostPublicKeyOpenSSH.size() > 0 ? refreshed.ssh.hostPublicKeyOpenSSH : defaultSSHHostPublicKeyOpenSSH);
   refreshed.cloud.providerMachineType = refreshed.cloud.providerMachineType.size() > 0 ? refreshed.cloud.providerMachineType : snapshot->type;
   refreshed.cloud.cloudID = snapshot->cloudID.size() > 0 ? snapshot->cloudID : refreshed.cloud.cloudID;
   refreshed.addresses = {};
   prodigyAssignClusterMachineAddressesFromPeerCandidates(refreshed.addresses, snapshot->peerAddresses);
   prodigyAppendUniqueClusterMachineAddress(refreshed.addresses.publicAddresses, snapshot->publicAddress);
   String privateGateway = {};
   if (snapshot->gatewayPrivate4 != 0)
   {
      IPAddress gatewayAddress = {};
      gatewayAddress.v4 = snapshot->gatewayPrivate4;
      gatewayAddress.is6 = false;
      (void)ClusterMachine::renderIPAddressLiteral(gatewayAddress, privateGateway);
   }
   prodigyAppendUniqueClusterMachineAddress(refreshed.addresses.privateAddresses, snapshot->privateAddress, 0, privateGateway);
   refreshed.uuid = snapshot->uuid != 0 ? snapshot->uuid : refreshed.uuid;
   refreshed.rackUUID = snapshot->rackUUID != 0 ? snapshot->rackUUID : refreshed.rackUUID;
   refreshed.creationTimeMs = snapshot->creationTimeMs > 0 ? snapshot->creationTimeMs : (refreshed.creationTimeMs > 0 ? refreshed.creationTimeMs : Time::now<TimeResolution::ms>());
   refreshed.hasInternetAccess = refreshed.hasInternetAccess || snapshot->hasInternetAccess;
   if (snapshot->hardware.inventoryComplete)
   {
      refreshed.hardware = snapshot->hardware;
   }
   refreshed.totalLogicalCores = snapshot->totalLogicalCores > 0 ? snapshot->totalLogicalCores : refreshed.totalLogicalCores;
   refreshed.totalMemoryMB = snapshot->totalMemoryMB > 0 ? snapshot->totalMemoryMB : refreshed.totalMemoryMB;
   refreshed.totalStorageMB = snapshot->totalStorageMB > 0 ? snapshot->totalStorageMB : refreshed.totalStorageMB;
   if (refreshed.ownedLogicalCores == 0)
   {
      refreshed.ownedLogicalCores = refreshed.totalLogicalCores;
   }
   if (refreshed.ownedMemoryMB == 0)
   {
      refreshed.ownedMemoryMB = refreshed.totalMemoryMB;
   }
   if (refreshed.ownedStorageMB == 0)
   {
      refreshed.ownedStorageMB = refreshed.totalStorageMB;
   }

   if (refreshed.addresses.privateAddresses.empty() && snapshot->private4 != 0)
   {
      struct in_addr address = {};
      address.s_addr = snapshot->private4;
      char buffer[INET_ADDRSTRLEN] = {};
      if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) != nullptr)
      {
         String privateAddress = {};
         privateAddress.assign(buffer);
         prodigyAppendUniqueClusterMachineAddress(refreshed.addresses.privateAddresses, privateAddress, 0, privateGateway);
      }
   }

   if (refreshed.ssh.address.size() == 0)
   {
      if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(refreshed.addresses.privateAddresses); privateAddress != nullptr)
      {
         refreshed.ssh.address = privateAddress->address;
      }
      else if (const ClusterMachineAddress *publicAddress = prodigyFirstClusterMachineAddress(refreshed.addresses.publicAddresses); publicAddress != nullptr)
      {
         refreshed.ssh.address = publicAddress->address;
      }
   }

   if (refreshed.addresses.privateAddresses.empty() && refreshed.addresses.publicAddresses.empty())
   {
      ClusterTopology topology = {};
      topology.machines.push_back(refreshed);
      prodigyNormalizeClusterTopologyPeerAddresses(topology);
      refreshed.addresses = topology.machines[0].addresses;
   }

   clusterMachine = std::move(refreshed);
}

static inline void prodigyPopulateMachineProvisioningProgressFromMachine(MachineProvisioningProgress& progress, const Machine& machine)
{
   progress.ssh.address = machine.sshAddress;
   progress.ssh.port = machine.sshPort > 0 ? machine.sshPort : 22;
   progress.ssh.user = machine.sshUser;
   progress.ssh.privateKeyPath = machine.sshPrivateKeyPath;
   progress.ssh.hostPublicKeyOpenSSH = machine.sshHostPublicKeyOpenSSH;
   prodigyAssignClusterMachineAddressesFromPeerCandidates(progress.addresses, machine.peerAddresses);
   prodigyAppendUniqueClusterMachineAddress(progress.addresses.publicAddresses, machine.publicAddress);
   String privateGateway = {};
   if (machine.gatewayPrivate4 != 0)
   {
      IPAddress gatewayAddress = {};
      gatewayAddress.v4 = machine.gatewayPrivate4;
      gatewayAddress.is6 = false;
      (void)ClusterMachine::renderIPAddressLiteral(gatewayAddress, privateGateway);
   }
   prodigyAppendUniqueClusterMachineAddress(progress.addresses.privateAddresses, machine.privateAddress, 0, privateGateway);

   if (progress.ssh.address.size() == 0)
   {
      if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(progress.addresses.privateAddresses); privateAddress != nullptr)
      {
         progress.ssh.address = privateAddress->address;
      }
      else if (const ClusterMachineAddress *publicAddress = prodigyFirstClusterMachineAddress(progress.addresses.publicAddresses); publicAddress != nullptr)
      {
         progress.ssh.address = publicAddress->address;
      }
   }
}

static inline Machine prodigyBuildMachineSnapshotFromClusterMachine(const ClusterMachine& clusterMachine)
{
   Machine machine = {};
   if (clusterMachine.cloudPresent())
   {
      machine.slug = clusterMachine.cloud.schema;
      machine.type = clusterMachine.cloud.providerMachineType;
      machine.cloudID = clusterMachine.cloud.cloudID;
   }
   machine.sshAddress = clusterMachine.ssh.address;
   machine.sshPort = clusterMachine.ssh.port;
   machine.sshUser = clusterMachine.ssh.user;
   machine.sshPrivateKeyPath = clusterMachine.ssh.privateKeyPath;
   machine.sshHostPublicKeyOpenSSH = clusterMachine.ssh.hostPublicKeyOpenSSH;
   if (const ClusterMachineAddress *publicAddress = prodigyFirstClusterMachineAddress(clusterMachine.addresses.publicAddresses); publicAddress != nullptr)
   {
      machine.publicAddress = publicAddress->address;
   }
   if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(clusterMachine.addresses.privateAddresses); privateAddress != nullptr)
   {
      machine.privateAddress = privateAddress->address;
   }
   prodigyCollectClusterMachinePeerAddresses(clusterMachine, machine.peerAddresses);
   machine.uuid = clusterMachine.uuid;
   machine.rackUUID = clusterMachine.rackUUID;
   (void)clusterMachine.resolvePrivate4(machine.private4);
   (void)clusterMachine.resolvePrivate4Gateway(machine.gatewayPrivate4);
   machine.creationTimeMs = clusterMachine.creationTimeMs;
   machine.hasInternetAccess = clusterMachine.hasInternetAccess;
   machine.lifetime = clusterMachine.lifetime;
   machine.isBrain = clusterMachine.isBrain;
   machine.topologySource = uint8_t(clusterMachine.source);
   machine.ownershipMode = uint8_t(clusterMachine.ownership.mode);
   machine.ownershipLogicalCoresCap = clusterMachine.ownership.nLogicalCoresCap;
   machine.ownershipMemoryMBCap = clusterMachine.ownership.nMemoryMBCap;
   machine.ownershipStorageMBCap = clusterMachine.ownership.nStorageMBCap;
   machine.ownershipLogicalCoresBasisPoints = clusterMachine.ownership.nLogicalCoresBasisPoints;
   machine.ownershipMemoryBasisPoints = clusterMachine.ownership.nMemoryBasisPoints;
   machine.ownershipStorageBasisPoints = clusterMachine.ownership.nStorageBasisPoints;
   machine.totalLogicalCores = clusterMachine.totalLogicalCores;
   machine.totalMemoryMB = clusterMachine.totalMemoryMB;
   machine.totalStorageMB = clusterMachine.totalStorageMB;
   machine.hardware = clusterMachine.hardware;
   machine.ownedLogicalCores = clusterMachine.ownedLogicalCores;
   machine.ownedMemoryMB = clusterMachine.ownedMemoryMB;
   machine.ownedStorageMB = clusterMachine.ownedStorageMB;

   if (machine.private4 == 0 && machine.privateAddress.size() > 0)
   {
      String privateAddressText = {};
      privateAddressText.assign(machine.privateAddress);
      struct in_addr address = {};
      if (inet_pton(AF_INET, privateAddressText.c_str(), &address) == 1)
      {
         machine.private4 = address.s_addr;
      }
   }

   return machine;
}

static inline void prodigyBackfillClusterMachineFromAuthoritativeRecord(ClusterMachine& machine, const ClusterMachine& authoritative)
{
   if (machine.sameIdentityAs(authoritative) == false)
   {
      return;
   }

   if (machine.cloudPresent() == false && authoritative.cloudPresent())
   {
      machine.hasCloud = true;
      machine.backing = authoritative.backing;
      machine.cloud = authoritative.cloud;
      machine.source = authoritative.source;
      machine.lifetime = authoritative.lifetime;
   }
   else if (machine.cloudPresent() && authoritative.cloudPresent())
   {
      machine.backing = ClusterMachineBacking::cloud;
      if (machine.cloud.schema.size() == 0)
      {
         machine.cloud.schema = authoritative.cloud.schema;
      }
      if (machine.cloud.providerMachineType.size() == 0)
      {
         machine.cloud.providerMachineType = authoritative.cloud.providerMachineType;
      }
      if (machine.cloud.cloudID.size() == 0)
      {
         machine.cloud.cloudID = authoritative.cloud.cloudID;
      }
      if (machine.source == ClusterMachineSource::adopted && authoritative.source == ClusterMachineSource::created)
      {
         machine.source = authoritative.source;
      }
      if (machine.lifetime == MachineLifetime::owned && authoritative.lifetime != MachineLifetime::owned)
      {
         machine.lifetime = authoritative.lifetime;
      }
   }

   if (machine.ssh.address.size() == 0)
   {
      machine.ssh.address = authoritative.ssh.address;
   }
   if (machine.ssh.port == 0 && authoritative.ssh.port > 0)
   {
      machine.ssh.port = authoritative.ssh.port;
   }
   if (machine.ssh.user.size() == 0)
   {
      machine.ssh.user = authoritative.ssh.user;
   }
   if (machine.ssh.privateKeyPath.size() == 0)
   {
      machine.ssh.privateKeyPath = authoritative.ssh.privateKeyPath;
   }

   if (machine.addresses.privateAddresses.empty())
   {
      machine.addresses.privateAddresses = authoritative.addresses.privateAddresses;
   }
   if (machine.addresses.publicAddresses.empty())
   {
      machine.addresses.publicAddresses = authoritative.addresses.publicAddresses;
   }

   if (machine.uuid == 0 && authoritative.uuid != 0)
   {
      machine.uuid = authoritative.uuid;
   }
   if (machine.rackUUID == 0 && authoritative.rackUUID != 0)
   {
      machine.rackUUID = authoritative.rackUUID;
   }
   if (machine.creationTimeMs == 0 && authoritative.creationTimeMs > 0)
   {
      machine.creationTimeMs = authoritative.creationTimeMs;
   }
   if (machine.hasInternetAccess == false && authoritative.hasInternetAccess)
   {
      machine.hasInternetAccess = true;
   }

   if (machine.totalLogicalCores == 0)
   {
      machine.totalLogicalCores = authoritative.totalLogicalCores;
   }
   if (machine.totalMemoryMB == 0)
   {
      machine.totalMemoryMB = authoritative.totalMemoryMB;
   }
   if (machine.totalStorageMB == 0)
   {
      machine.totalStorageMB = authoritative.totalStorageMB;
   }
   if (machine.ownedLogicalCores == 0)
   {
      machine.ownedLogicalCores = authoritative.ownedLogicalCores;
   }
   if (machine.ownedMemoryMB == 0)
   {
      machine.ownedMemoryMB = authoritative.ownedMemoryMB;
   }
   if (machine.ownedStorageMB == 0)
   {
      machine.ownedStorageMB = authoritative.ownedStorageMB;
   }
   if (machine.hardware.inventoryComplete == false && authoritative.hardware.inventoryComplete)
   {
      machine.hardware = authoritative.hardware;
   }

   bool machineOwnershipDefault =
      machine.ownership.mode == ClusterMachineOwnershipMode::wholeMachine
      && machine.ownership.nLogicalCoresCap == 0
      && machine.ownership.nMemoryMBCap == 0
      && machine.ownership.nStorageMBCap == 0
      && machine.ownership.nLogicalCoresBasisPoints == 0
      && machine.ownership.nMemoryBasisPoints == 0
      && machine.ownership.nStorageBasisPoints == 0;
   bool authoritativeOwnershipSpecified =
      authoritative.ownership.mode != ClusterMachineOwnershipMode::wholeMachine
      || authoritative.ownership.nLogicalCoresCap > 0
      || authoritative.ownership.nMemoryMBCap > 0
      || authoritative.ownership.nStorageMBCap > 0
      || authoritative.ownership.nLogicalCoresBasisPoints > 0
      || authoritative.ownership.nMemoryBasisPoints > 0
      || authoritative.ownership.nStorageBasisPoints > 0;
   if (machineOwnershipDefault && authoritativeOwnershipSpecified)
   {
      machine.ownership = authoritative.ownership;
   }
}

static inline void prodigyBackfillClusterTopologyFromAuthoritative(ClusterTopology& topology, const ClusterTopology& authoritative)
{
   if (authoritative.machines.empty())
   {
      return;
   }

   for (ClusterMachine& machine : topology.machines)
   {
      for (const ClusterMachine& authoritativeMachine : authoritative.machines)
      {
         if (machine.sameIdentityAs(authoritativeMachine) == false)
         {
            continue;
         }

         prodigyBackfillClusterMachineFromAuthoritativeRecord(machine, authoritativeMachine);
         break;
      }
   }
}

static inline ClusterMachine *prodigyFindClusterMachineByIdentity(Vector<ClusterMachine>& machines, const ClusterMachine& target)
{
   for (ClusterMachine& machine : machines)
   {
      if (machine.sameIdentityAs(target))
      {
         return &machine;
      }
   }

   return nullptr;
}

static inline const ClusterMachine *prodigyFindClusterMachineByIdentity(const Vector<ClusterMachine>& machines, const ClusterMachine& target)
{
   for (const ClusterMachine& machine : machines)
   {
      if (machine.sameIdentityAs(target))
      {
         return &machine;
      }
   }

   return nullptr;
}

static inline bool prodigyUpsertClusterMachineByIdentity(Vector<ClusterMachine>& machines, const ClusterMachine& target, bool *inserted = nullptr)
{
   if (inserted != nullptr)
   {
      *inserted = false;
   }

   if (ClusterMachine *existing = prodigyFindClusterMachineByIdentity(machines, target); existing != nullptr)
   {
      bool changed = *existing != target;
      if (changed)
      {
         *existing = target;
      }
      return changed;
   }

   machines.push_back(target);
   if (inserted != nullptr)
   {
      *inserted = true;
   }
   return true;
}

static inline bool prodigyEraseClusterMachineByIdentity(Vector<ClusterMachine>& machines, const ClusterMachine& target)
{
   auto it = std::remove_if(machines.begin(), machines.end(), [&] (const ClusterMachine& machine) {
      return machine.sameIdentityAs(target);
   });

   if (it == machines.end())
   {
      return false;
   }

   machines.erase(it, machines.end());
   return true;
}

static inline bool prodigyClusterMachineBootstrapReady(const ClusterMachine& clusterMachine)
{
   String sshAddress = {};
   if (clusterMachine.ssh.address.size() > 0)
   {
      sshAddress.assign(clusterMachine.ssh.address);
   }
   else if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(clusterMachine.addresses.privateAddresses); privateAddress != nullptr)
   {
      sshAddress.assign(privateAddress->address);
   }
   else if (const ClusterMachineAddress *publicAddress = prodigyFirstClusterMachineAddress(clusterMachine.addresses.publicAddresses); publicAddress != nullptr)
   {
      sshAddress.assign(publicAddress->address);
   }

   return sshAddress.size() > 0
      && clusterMachine.ssh.user.size() > 0
      && clusterMachine.ssh.privateKeyPath.size() > 0;
}

static inline bool prodigyClusterMachineMatchesMachineIdentity(const ClusterMachine& clusterMachine, const Machine& machine)
{
   if (clusterMachine.uuid != 0 && machine.uuid != 0 && clusterMachine.uuid == machine.uuid)
   {
      return true;
   }

   if (clusterMachine.cloudPresent()
      && clusterMachine.cloud.cloudID.size() > 0
      && machine.cloudID.size() > 0
      && clusterMachine.cloud.cloudID.equals(machine.cloudID))
   {
      return true;
   }

   IPAddress clusterPeerAddress = {};
   bool clusterHasPeerAddress = clusterMachine.resolvePeerAddress(clusterPeerAddress);
   if (clusterHasPeerAddress && prodigyMachinePeerAddressMatches(machine, clusterPeerAddress))
   {
      return true;
   }

   IPAddress machinePeerAddress = {};
   if (prodigyResolveMachinePeerAddress(machine, machinePeerAddress) && clusterMachine.peerAddressMatches(machinePeerAddress))
   {
      return true;
   }

   if (clusterMachine.ssh.address.size() > 0
      && machine.sshAddress.size() > 0
      && clusterMachine.ssh.address.equals(machine.sshAddress))
   {
      return true;
   }

   bool machineHasPeerAddress = prodigyResolveMachinePeerAddress(machine, machinePeerAddress);
   uint32_t clusterPrivate4 = 0;
   return (clusterHasPeerAddress == false || machineHasPeerAddress == false)
      && clusterMachine.resolvePrivate4(clusterPrivate4)
      && machine.private4 != 0
      && clusterPrivate4 == machine.private4;
}

static inline const ClusterMachine *prodigyFindAuthoritativeClusterMachineForMachine(const ClusterTopology& authoritative, const Machine& machine)
{
   for (const ClusterMachine& candidate : authoritative.machines)
   {
      if (prodigyClusterMachineMatchesMachineIdentity(candidate, machine))
      {
         return &candidate;
      }
   }

   return nullptr;
}

static inline bool prodigyMachineHardwareInventoryReady(const MachineHardwareProfile& hardware)
{
   return hardware.inventoryComplete
      && hardware.cpu.logicalCores > 0
      && hardware.memory.totalMB > 0;
}

static inline bool prodigyMachineReadyResourcesAvailable(const Machine& machine)
{
   if (prodigyMachineHardwareInventoryReady(machine.hardware))
   {
      return true;
   }

   uint32_t readyLogicalCores = machine.ownedLogicalCores > 0
      ? machine.ownedLogicalCores
      : machine.totalLogicalCores;
   uint32_t readyMemoryMB = machine.ownedMemoryMB > 0
      ? machine.ownedMemoryMB
      : machine.totalMemoryMB;
   uint32_t readyStorageMB = machine.ownedStorageMB > 0
      ? machine.ownedStorageMB
      : machine.totalStorageMB;

   return readyLogicalCores > 0
      && readyMemoryMB > 0
      && readyStorageMB > 0;
}

static inline const MachineNicHardwareProfile *prodigyFindMachineNicByAssignedAddress(const Machine& machine,
   const IPAddress& address,
   const MachineNicSubnetHardwareProfile **matchedSubnet = nullptr)
{
   if (matchedSubnet)
   {
      *matchedSubnet = nullptr;
   }

   if (address.isNull() || prodigyMachineHardwareInventoryReady(machine.hardware) == false)
   {
      return nullptr;
   }

   for (const MachineNicHardwareProfile& nic : machine.hardware.network.nics)
   {
      for (const MachineNicSubnetHardwareProfile& subnet : nic.subnets)
      {
         if (subnet.address.equals(address) == false)
         {
            continue;
         }

         if (matchedSubnet)
         {
            *matchedSubnet = &subnet;
         }
         return &nic;
      }
   }

   return nullptr;
}

static inline const MachineNicHardwareProfile *prodigyFindMachineNicContainingAddress(const Machine& machine,
   const IPAddress& address,
   const MachineNicSubnetHardwareProfile **matchedSubnet = nullptr)
{
   if (matchedSubnet)
   {
      *matchedSubnet = nullptr;
   }

   if (address.isNull() || prodigyMachineHardwareInventoryReady(machine.hardware) == false)
   {
      return nullptr;
   }

   for (const MachineNicHardwareProfile& nic : machine.hardware.network.nics)
   {
      for (const MachineNicSubnetHardwareProfile& subnet : nic.subnets)
      {
         if (subnet.subnet.network.is6 != address.is6 || subnet.subnet.containsAddress(address) == false)
         {
            continue;
         }

         if (matchedSubnet)
         {
            *matchedSubnet = &subnet;
         }
         return &nic;
      }
   }

   return nullptr;
}

static inline bool prodigyResolveMachineInternetSourceAddress(const Machine& machine, ExternalAddressFamily family, IPAddress& address, String *addressText = nullptr)
{
   address = {};
   if (addressText)
   {
      addressText->clear();
   }

   if (machine.hasInternetAccess == false)
   {
      return false;
   }

   auto matchesFamily = [&] (const IPAddress& candidate) -> bool {

      return candidate.isNull() == false && candidate.is6 == (family == ExternalAddressFamily::ipv6);
   };

   if (matchesFamily(machine.hardware.network.internet.sourceAddress))
   {
      address = machine.hardware.network.internet.sourceAddress;
      if (addressText)
      {
         (void)ClusterMachine::renderIPAddressLiteral(address, *addressText);
      }
      return true;
   }

   for (const MachineNicHardwareProfile& nic : machine.hardware.network.nics)
   {
      for (const MachineNicSubnetHardwareProfile& subnet : nic.subnets)
      {
         if (subnet.internetReachable == false || matchesFamily(subnet.address) == false)
         {
            continue;
         }

         address = subnet.address;
         if (addressText)
         {
            (void)ClusterMachine::renderIPAddressLiteral(address, *addressText);
         }
         return true;
      }
   }

   return false;
}

static inline void prodigyApplyHardwareProfileToClusterMachine(ClusterMachine& machine, const MachineHardwareProfile& hardware)
{
   machine.hardware = hardware;
   machine.hasInternetAccess = prodigyMachineHardwareHasInternetAccess(hardware);

   if (prodigyMachineHardwareInventoryReady(hardware) == false)
   {
      return;
   }

   machine.totalLogicalCores = hardware.cpu.logicalCores;
   machine.totalMemoryMB = hardware.memory.totalMB;

   uint64_t totalStorageMB = 0;
   for (const MachineDiskHardwareProfile& disk : hardware.disks)
   {
      totalStorageMB += disk.sizeMB;
   }

   if (totalStorageMB > UINT32_MAX)
   {
      totalStorageMB = UINT32_MAX;
   }

   machine.totalStorageMB = uint32_t(totalStorageMB);
   (void)clusterMachineApplyOwnedResourcesFromTotals(machine, machine.totalLogicalCores, machine.totalMemoryMB, machine.totalStorageMB);
}

static inline void prodigyApplyHardwareProfileToMachine(Machine& machine, const MachineHardwareProfile& hardware)
{
   machine.hardware = hardware;
   machine.hasInternetAccess = prodigyMachineHardwareHasInternetAccess(hardware);

   if (prodigyMachineHardwareInventoryReady(hardware) == false)
   {
      return;
   }

   machine.totalLogicalCores = hardware.cpu.logicalCores;
   machine.totalMemoryMB = hardware.memory.totalMB;

   uint64_t totalStorageMB = 0;
   for (const MachineDiskHardwareProfile& disk : hardware.disks)
   {
      totalStorageMB += disk.sizeMB;
   }

   if (totalStorageMB > UINT32_MAX)
   {
      totalStorageMB = UINT32_MAX;
   }

   machine.totalStorageMB = uint32_t(totalStorageMB);

   ClusterMachineOwnership ownership = {};
   ownership.mode = ClusterMachineOwnershipMode(machine.ownershipMode);
   ownership.nLogicalCoresCap = machine.ownershipLogicalCoresCap;
   ownership.nMemoryMBCap = machine.ownershipMemoryMBCap;
   ownership.nStorageMBCap = machine.ownershipStorageMBCap;
   ownership.nLogicalCoresBasisPoints = machine.ownershipLogicalCoresBasisPoints;
   ownership.nMemoryBasisPoints = machine.ownershipMemoryBasisPoints;
   ownership.nStorageBasisPoints = machine.ownershipStorageBasisPoints;

   (void)clusterMachineResolveOwnedResources(
      ownership,
      machine.totalLogicalCores,
      machine.totalMemoryMB,
      machine.totalStorageMB,
      machine.ownedLogicalCores,
      machine.ownedMemoryMB,
      machine.ownedStorageMB
   );

   machine.isolatedLogicalCoresCommitted = 0;
   machine.sharedCPUMillisCommitted = 0;
   machine.nLogicalCores_available = int32_t(machine.ownedLogicalCores);
   uint64_t sharedCapacityMillis = uint64_t(machine.ownedLogicalCores) * uint64_t(prodigyCPUUnitsPerCore);
   machine.sharedCPUMillis_available = int32_t(std::min<uint64_t>(sharedCapacityMillis, uint64_t(INT32_MAX)));
   machine.memoryMB_available = int32_t(machine.ownedMemoryMB);
   machine.storageMB_available = int32_t(machine.ownedStorageMB);
   machine.resetAvailableGPUMemoryMBsFromHardware();
}

static inline void prodigyDestroyMachineSnapshot(Machine *snapshot)
{
   if (snapshot == nullptr)
   {
      return;
   }

   if (snapshot->neuron.isFixedFile == false && snapshot->neuron.fd >= 0)
   {
      snapshot->neuron.close();
      snapshot->neuron.fd = -1;
   }

   delete snapshot;
}

static inline void prodigyRenderClusterUUIDTagValue(uint128_t clusterUUID, String& value)
{
   value.clear();
   value.assignItoh(clusterUUID);
}

static inline bool prodigyEnsureCloudMachineTagged(BrainIaaS& iaas, uint128_t clusterUUID, const ClusterMachine& clusterMachine, String *failure = nullptr)
{
   if (failure) failure->clear();

   if (clusterMachine.backing != ClusterMachineBacking::cloud)
   {
      return true;
   }

   if (clusterMachine.cloud.cloudID.size() == 0)
   {
      if (failure) failure->assign("cloud machine missing cloudID"_ctv);
      return false;
   }

   if (clusterUUID == 0)
   {
      if (failure) failure->assign("clusterUUID required for cloud machine tagging"_ctv);
      return false;
   }

   Machine machine = prodigyBuildMachineSnapshotFromClusterMachine(clusterMachine);

   String clusterUUIDTagValue = {};
   prodigyRenderClusterUUIDTagValue(clusterUUID, clusterUUIDTagValue);

   String tagFailure = {};
   if (iaas.ensureProdigyMachineTags(clusterUUIDTagValue, &machine, tagFailure) == false)
   {
      if (failure) *failure = tagFailure.size() > 0 ? tagFailure : "provider tag update failed"_ctv;
      return false;
   }

   return true;
}
