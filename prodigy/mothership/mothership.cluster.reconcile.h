#pragma once

#include <prodigy/mothership/mothership.cluster.types.h>

static inline void mothershipFillAdoptedClusterMachine(const MothershipProdigyClusterMachine& source, ClusterMachine& target)
{
  target = {};
  target.source = ClusterMachineSource::adopted;
  target.backing = source.backing;
  target.kind = source.kind;
  target.lifetime = source.lifetime;
  target.isBrain = source.isBrain;
  target.hasCloud = source.cloudPresent();
  target.cloud = source.cloud;
  target.ssh = source.ssh;
  target.addresses = source.addresses;
  target.ownership = source.ownership;
  target.uuid = source.uuid;
  target.rackUUID = source.rackUUID;
}

static inline bool mothershipClusterWantsAdoptedMachine(
    const MothershipProdigyCluster& cluster,
    const ClusterMachine& existingMachine,
    const ClusterMachine *localMachine = nullptr)
{
  if (localMachine != nullptr && existingMachine.sameIdentityAs(*localMachine))
  {
    return mothershipClusterIncludesLocalMachine(cluster);
  }

  for (const MothershipProdigyClusterMachine& desiredMachine : cluster.machines)
  {
    ClusterMachine requestedMachine = {};
    mothershipFillAdoptedClusterMachine(desiredMachine, requestedMachine);
    if (existingMachine.sameIdentityAs(requestedMachine))
    {
      return true;
    }
  }

  return false;
}

static inline void mothershipAppendRemovedAdoptedClusterMachines(
    const MothershipProdigyCluster& cluster,
    const ClusterTopology& topology,
    AddMachines& request,
    const ClusterMachine *localMachine = nullptr)
{
  for (const ClusterMachine& existingMachine : topology.machines)
  {
    if (existingMachine.source != ClusterMachineSource::adopted)
    {
      continue;
    }

    // Local-machine membership is handled explicitly by the caller so it
    // does not get double-counted by the generic adopted-machine sweep.
    if (localMachine != nullptr && existingMachine.sameIdentityAs(*localMachine))
    {
      continue;
    }

    if (mothershipClusterWantsAdoptedMachine(cluster, existingMachine, localMachine))
    {
      continue;
    }

    request.removedMachines.push_back(existingMachine);
  }
}

static inline bool mothershipDeclaredAddressesMatchTopology(
    const Vector<ClusterMachineAddress>& declaredAddresses,
    const Vector<ClusterMachineAddress>& topologyAddresses)
{
  Vector<ClusterMachineAddress> normalizedDeclared = {};
  for (const ClusterMachineAddress& address : declaredAddresses)
  {
    prodigyAppendUniqueClusterMachineAddress(normalizedDeclared, address);
  }

  for (const ClusterMachineAddress& declaredAddress : normalizedDeclared)
  {
    bool found = false;
    for (const ClusterMachineAddress& topologyAddress : topologyAddresses)
    {
      ClusterMachineAddress normalizedTopologyAddress = {};
      if (prodigyNormalizeClusterMachineAddress(topologyAddress, normalizedTopologyAddress) &&
          normalizedTopologyAddress.address.equals(declaredAddress.address) &&
          normalizedTopologyAddress.cidr == declaredAddress.cidr)
      {
        found = true;
        break;
      }
    }

    if (found == false)
    {
      return false;
    }
  }

  return true;
}

static inline bool mothershipCanUpdateAdoptedMachineRack(
    const ClusterMachine& existingMachine,
    const ClusterMachine& requestedMachine)
{
  ClusterMachine candidate = existingMachine;
  candidate.source = requestedMachine.source;
  candidate.backing = requestedMachine.backing;
  candidate.kind = requestedMachine.kind;
  candidate.lifetime = requestedMachine.lifetime;
  candidate.isBrain = requestedMachine.isBrain;
  candidate.hasCloud = requestedMachine.hasCloud;
  candidate.cloud = requestedMachine.cloud;
  candidate.ssh = requestedMachine.ssh;
  candidate.ownership = requestedMachine.ownership;
  return existingMachine.source == ClusterMachineSource::adopted &&
         mothershipDeclaredAddressesMatchTopology(requestedMachine.addresses.privateAddresses, existingMachine.addresses.privateAddresses) &&
         mothershipDeclaredAddressesMatchTopology(requestedMachine.addresses.publicAddresses, existingMachine.addresses.publicAddresses) &&
         existingMachine.preservesIdentityAndConfigurationForRackUpdate(candidate);
}

static inline bool mothershipBuildClusterAddMachinesRequest(const MothershipProdigyCluster& cluster, const ClusterTopology& topology, AddMachines& request, String *failure = nullptr)
{
  request = {};
  if (failure)
  {
    failure->clear();
  }

  request.bootstrapSshUser = cluster.bootstrapSshUser;
  request.bootstrapSshKeyPackage = cluster.bootstrapSshKeyPackage;
  request.bootstrapSshHostKeyPackage = cluster.bootstrapSshHostKeyPackage;
  request.bootstrapSshPrivateKeyPath = cluster.bootstrapSshPrivateKeyPath;
  request.remoteProdigyPath = cluster.remoteProdigyPath;
  request.clusterUUID = cluster.clusterUUID;
  request.architecture = cluster.architecture;

  for (const MothershipProdigyClusterControl& control : cluster.controls)
  {
    if (control.kind == MothershipClusterControlKind::unixSocket && control.path.size() > 0)
    {
      request.controlSocketPath = control.path;
      break;
    }
  }

  for (const MothershipProdigyClusterMachine& desiredMachine : cluster.machines)
  {
    ClusterMachine requestedMachine = {};
    mothershipFillAdoptedClusterMachine(desiredMachine, requestedMachine);
    if (requestedMachine.uuid != 0 &&
        (std::count_if(topology.machines.begin(), topology.machines.end(),
            [&](const auto& machine) { return machine.uuid == requestedMachine.uuid; }) > 1 ||
         std::count_if(cluster.machines.begin(), cluster.machines.end(),
            [&](const auto& machine) { return machine.uuid == requestedMachine.uuid; }) > 1)) {
      if (failure) failure->assign("adopted machine UUID is ambiguous"_ctv); request = {}; return false;
    }

    bool alreadyPresent = false;
    for (const ClusterMachine& existingMachine : topology.machines)
    {
      if (existingMachine.sameIdentityAs(requestedMachine))
      {
        alreadyPresent = true;
        if (requestedMachine.uuid != 0 && existingMachine.uuid == requestedMachine.uuid)
        {
          ClusterMachine unchanged = requestedMachine;
          unchanged.addresses = existingMachine.addresses;
          if (mothershipCanUpdateAdoptedMachineRack(existingMachine, unchanged))
          {
            ClusterMachine update = existingMachine;
            if (update.peerAddresses.empty()) prodigyCollectClusterMachinePeerAddresses(existingMachine, update.peerAddresses);
            bool added = false;
            for (const auto *declared : {&requestedMachine.addresses.privateAddresses, &requestedMachine.addresses.publicAddresses})
              for (const auto& address : *declared)
              {
                IPAddress parsed = {};
                if (!ClusterMachine::parseIPAddressLiteral(address.address, parsed)) { request = {}; return false; }
                const bool present = mothershipDeclaredAddressesMatchTopology({address},
                    declared == &requestedMachine.addresses.privateAddresses ? existingMachine.addresses.privateAddresses : existingMachine.addresses.publicAddresses);
                if (present) continue;
                if (existingMachine.peerAddressMatches(parsed)) {
                  if (failure) failure->assign("adopted address addition changes an existing endpoint"_ctv); request = {}; return false;
                }
                if (!parsed.is6) { if (failure) failure->assign("adopted address addition requires IPv6"_ctv); request = {}; return false; }
                for (const auto& other : topology.machines)
                  if (other.uuid != existingMachine.uuid && other.peerAddressMatches(parsed)) {
                    if (failure) failure->assign("adopted address addition conflicts with another machine"_ctv); request = {}; return false;
                  }
                for (const auto& other : request.adoptedMachines)
                  if (other.uuid != existingMachine.uuid && other.peerAddressMatches(parsed)) {
                    if (failure) failure->assign("adopted address addition conflicts with another machine"_ctv); request = {}; return false;
                  }
                auto& destination = declared == &requestedMachine.addresses.privateAddresses ? update.addresses.privateAddresses : update.addresses.publicAddresses;
                prodigyAppendUniqueClusterMachineAddress(destination, address);
                prodigyAppendUniqueClusterMachinePeerAddress(update.peerAddresses, {address.address, address.cidr, address.gateway});
                added = true;
              }
            if (added) {
              if (requestedMachine.rackUUID != 0) update.rackUUID = requestedMachine.rackUUID;
              request.adoptedMachines.push_back(std::move(update));
              break;
            }
          }
        }
        if (requestedMachine.uuid != 0 &&
            existingMachine.uuid == requestedMachine.uuid &&
            mothershipCanUpdateAdoptedMachineRack(existingMachine, requestedMachine) == false)
        {
          if (failure)
          {
            failure->assign("adopted explicit UUID requires an unchanged known machine"_ctv);
          }
          request = {};
          return false;
        }
        if (requestedMachine.rackUUID != 0 && requestedMachine.rackUUID != existingMachine.rackUUID)
        {
          if (mothershipCanUpdateAdoptedMachineRack(existingMachine, requestedMachine) == false)
          {
            if (failure)
            {
              failure->assign("adopted rack update requires an unchanged known machine"_ctv);
            }
            request = {};
            return false;
          }

          ClusterMachine rackUpdate = existingMachine;
          rackUpdate.rackUUID = requestedMachine.rackUUID;
          request.adoptedMachines.push_back(std::move(rackUpdate));
        }
        break;
      }
    }

    if (alreadyPresent == false)
    {
      request.adoptedMachines.push_back(std::move(requestedMachine));
    }
  }

  return true;
}

static inline bool mothershipBuildDesiredClusterReconcileRequest(
    const MothershipProdigyCluster& controlCluster,
    const MothershipProdigyCluster& desiredCluster,
    const ClusterTopology& topology,
    AddMachines& request,
    bool& changed,
    String *failure = nullptr,
    const ClusterMachine *localMachine = nullptr,
    bool localMachineKnown = false)
{
  request = {};
  changed = false;
  if (failure)
  {
    failure->clear();
  }

  if (mothershipBuildClusterAddMachinesRequest(desiredCluster, topology, request, failure) == false)
  {
    return false;
  }

  if (desiredCluster.deploymentMode == MothershipClusterDeploymentMode::local)
  {
    if (desiredCluster.includeLocalMachine || mothershipClusterIncludesLocalMachine(controlCluster))
    {
      if (localMachine == nullptr)
      {
        if (failure)
        {
          failure->assign("local cluster reconcile requires local machine identity");
        }
        request = {};
        return false;
      }

      if (desiredCluster.includeLocalMachine && localMachineKnown == false)
      {
        request.readyMachines.push_back(*localMachine);
      }
      else if (desiredCluster.includeLocalMachine == false && localMachineKnown)
      {
        request.removedMachines.push_back(*localMachine);
      }
    }

    mothershipAppendRemovedAdoptedClusterMachines(desiredCluster, topology, request, localMachine);
  }
  else
  {
    mothershipAppendRemovedAdoptedClusterMachines(desiredCluster, topology, request);
  }

  changed = request.adoptedMachines.empty() == false || request.readyMachines.empty() == false || request.removedMachines.empty() == false;

  return true;
}
