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

static inline bool mothershipBuildClusterAddMachinesRequest(const MothershipProdigyCluster& cluster, const ClusterTopology& topology, AddMachines& request, String *failure = nullptr)
{
   request = {};
   if (failure) failure->clear();

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

      bool alreadyPresent = false;
      for (const ClusterMachine& existingMachine : topology.machines)
      {
         if (existingMachine.sameIdentityAs(requestedMachine))
         {
            alreadyPresent = true;
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
   if (failure) failure->clear();

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
            if (failure) failure->assign("local cluster reconcile requires local machine identity");
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

   changed = request.adoptedMachines.empty() == false
      || request.readyMachines.empty() == false
      || request.removedMachines.empty() == false;

   return true;
}
