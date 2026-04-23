#pragma once

#include <prodigy/bundle.artifact.h>
#include <prodigy/mothership/mothership.cluster.types.h>

class MothershipClusterRemoveSummary
{
public:

   bool stoppedLocalMachine = false;
   uint32_t wipedAdoptedMachines = 0;
   uint32_t destroyedCreatedCloudMachines = 0;
};

class MothershipClusterRemoveHooks
{
public:

   virtual ~MothershipClusterRemoveHooks() = default;

   virtual bool stopTestCluster(const MothershipProdigyCluster& cluster, String *failure = nullptr) = 0;
   virtual bool stopAndWipeLocalMachine(const MothershipProdigyCluster& cluster, String *failure = nullptr) = 0;
   virtual bool stopAndWipeAdoptedMachine(const MothershipProdigyCluster& cluster, const MothershipProdigyClusterMachine& machine, String *failure = nullptr) = 0;
   virtual bool destroyCreatedCloudMachines(const MothershipProdigyCluster& cluster, const Vector<ClusterMachine>& machines, uint32_t& destroyed, String *failure = nullptr) = 0;
};

static inline void mothershipBuildProdigyStateWipeCommand(const String& stateDBPath, String& command)
{
   command.assign("systemctl stop prodigy || true; systemctl disable prodigy || true; rm -rf /run/prodigy /var/lib/prodigy"_ctv);

   static constexpr const char *defaultStatePrefix = "/var/lib/prodigy/";
   if (stateDBPath.size() >= 17 && std::memcmp(stateDBPath.data(), defaultStatePrefix, 17) == 0)
   {
      return;
   }

   command.append(" "_ctv);
   prodigyAppendShellSingleQuoted(command, stateDBPath);
}

static inline void mothershipBuildRemoteProdigyUninstallCommand(const MothershipProdigyCluster& cluster, String& command)
{
   String remoteProdigyPath = {};
   if (cluster.remoteProdigyPath.size() > 0)
   {
      remoteProdigyPath = cluster.remoteProdigyPath;
   }
   else
   {
      remoteProdigyPath.assign(defaultMothershipRemoteProdigyPath());
   }

   ProdigyInstallRootPaths installPaths = {};
   prodigyBuildInstallRootPaths(remoteProdigyPath, installPaths);

   String remoteRootParent = {};
   prodigyDirname(remoteProdigyPath, remoteRootParent);

   String remoteUnitTempPath = {};
   remoteUnitTempPath.assign(remoteRootParent);
   if (remoteUnitTempPath.size() > 0 && remoteUnitTempPath[remoteUnitTempPath.size() - 1] != '/')
   {
      remoteUnitTempPath.append('/');
   }
   remoteUnitTempPath.append("prodigy.service.tmp"_ctv);

   String remoteBundleTempPath = {};
   remoteBundleTempPath.assign(remoteRootParent);
   if (remoteBundleTempPath.size() > 0 && remoteBundleTempPath[remoteBundleTempPath.size() - 1] != '/')
   {
      remoteBundleTempPath.append('/');
   }
   remoteBundleTempPath.append("prodigy.bundle.tar.zst.tmp"_ctv);

   String controlSocketPath = {};
   for (const MothershipProdigyClusterControl& control : cluster.controls)
   {
      if (control.kind == MothershipClusterControlKind::unixSocket && control.path.size() > 0)
      {
         controlSocketPath = control.path;
         break;
      }
   }

   command.assign("set -eu; systemctl stop prodigy || true; systemctl disable prodigy || true; rm -f /etc/systemd/system/prodigy.service /etc/systemd/system/prodigy.service.tmp /etc/systemd/system/multi-user.target.wants/prodigy.service"_ctv);
   command.append(" "_ctv);
   prodigyAppendShellSingleQuoted(command, remoteUnitTempPath);
   command.append(" "_ctv);
   prodigyAppendShellSingleQuoted(command, remoteBundleTempPath);
   command.append(" /root/prodigy.bundle.new.tar.zst"_ctv);
   if (controlSocketPath.size() > 0)
   {
      command.append(" "_ctv);
      prodigyAppendShellSingleQuoted(command, controlSocketPath);
   }
   command.append("; rm -rf /run/prodigy /var/lib/prodigy /var/log/prodigy "_ctv);
   prodigyAppendShellSingleQuoted(command, installPaths.installRoot);
   command.append(" "_ctv);
   prodigyAppendShellSingleQuoted(command, installPaths.installRootTemp);
   command.append(" "_ctv);
   prodigyAppendShellSingleQuoted(command, installPaths.installRootPrevious);
   command.append("; systemctl daemon-reload || true; systemctl reset-failed prodigy || true"_ctv);
}

static inline void mothershipRenderClusterRemoveMachineKey(const MothershipProdigyClusterMachine& machine, String& key)
{
   key.clear();

   if (machine.cloudPresent() && machine.cloud.cloudID.size() > 0)
   {
      key.assign(machine.cloud.cloudID);
      return;
   }

   if (machine.addresses.privateAddresses.empty() == false)
   {
      key.assign(machine.addresses.privateAddresses[0].address);
      return;
   }

   if (machine.ssh.address.size() > 0)
   {
      key.assign(machine.ssh.address);
      key.snprintf_add<":{itoa}"_ctv>(uint64_t(machine.ssh.port));
      return;
   }

   if (machine.addresses.publicAddresses.empty() == false)
   {
      key.assign(machine.addresses.publicAddresses[0].address);
      return;
   }

   key.assign(machine.cloud.schema);
   key.snprintf_add<":{itoa}:{itoa}"_ctv>(uint64_t(machine.source), uint64_t(machine.isBrain));
}

static inline bool mothershipAppendUniqueClusterRemoveMachine(Vector<MothershipProdigyClusterMachine>& machines, const MothershipProdigyClusterMachine& candidate)
{
   String candidateKey = {};
   mothershipRenderClusterRemoveMachineKey(candidate, candidateKey);

   for (const MothershipProdigyClusterMachine& existing : machines)
   {
      String existingKey = {};
      mothershipRenderClusterRemoveMachineKey(existing, existingKey);
      if (existingKey.equals(candidateKey))
      {
         return false;
      }
   }

   machines.push_back(candidate);
   return true;
}

static inline void mothershipPopulateRemoveMachineFromTopology(const ClusterMachine& source, MothershipProdigyClusterMachine& target)
{
   target = {};
   target.source = (source.source == ClusterMachineSource::created)
      ? MothershipClusterMachineSource::created
      : MothershipClusterMachineSource::adopted;
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

static inline void mothershipCollectAdoptedClusterRemoveMachines(const MothershipProdigyCluster& cluster, Vector<MothershipProdigyClusterMachine>& machines)
{
   machines.clear();

   for (const MothershipProdigyClusterMachine& machine : cluster.machines)
   {
      if (machine.source != MothershipClusterMachineSource::adopted)
      {
         continue;
      }

      (void)mothershipAppendUniqueClusterRemoveMachine(machines, machine);
   }

   if (cluster.deploymentMode != MothershipClusterDeploymentMode::remote)
   {
      return;
   }

   for (const ClusterMachine& topologyMachine : cluster.topology.machines)
   {
      if (topologyMachine.source != ClusterMachineSource::adopted)
      {
         continue;
      }

      MothershipProdigyClusterMachine machine = {};
      mothershipPopulateRemoveMachineFromTopology(topologyMachine, machine);
      (void)mothershipAppendUniqueClusterRemoveMachine(machines, machine);
   }
}

static inline void mothershipCollectCreatedCloudClusterRemoveMachines(const MothershipProdigyCluster& cluster, Vector<ClusterMachine>& machines)
{
   machines.clear();

   for (const ClusterMachine& topologyMachine : cluster.topology.machines)
   {
      if (topologyMachine.source != ClusterMachineSource::created
         || topologyMachine.backing != ClusterMachineBacking::cloud
         || topologyMachine.cloud.cloudID.size() == 0)
      {
         continue;
      }

      bool duplicate = false;
      for (const ClusterMachine& existing : machines)
      {
         if (existing.cloud.cloudID.equals(topologyMachine.cloud.cloudID))
         {
            duplicate = true;
            break;
         }
      }

      if (duplicate)
      {
         continue;
      }

      machines.push_back(topologyMachine);
   }
}

static inline bool mothershipRemoveClusterRuntime(const MothershipProdigyCluster& cluster, MothershipClusterRemoveHooks& hooks, MothershipClusterRemoveSummary& summary, String *failure = nullptr)
{
   summary = {};
   if (failure) failure->clear();

   if (cluster.deploymentMode == MothershipClusterDeploymentMode::test)
   {
      return hooks.stopTestCluster(cluster, failure);
   }

   if (cluster.deploymentMode == MothershipClusterDeploymentMode::local && mothershipClusterIncludesLocalMachine(cluster))
   {
      if (hooks.stopAndWipeLocalMachine(cluster, failure) == false)
      {
         return false;
      }

      summary.stoppedLocalMachine = true;
   }

   Vector<MothershipProdigyClusterMachine> adoptedMachines = {};
   mothershipCollectAdoptedClusterRemoveMachines(cluster, adoptedMachines);
   for (const MothershipProdigyClusterMachine& machine : adoptedMachines)
   {
      if (hooks.stopAndWipeAdoptedMachine(cluster, machine, failure) == false)
      {
         return false;
      }

      summary.wipedAdoptedMachines += 1;
   }

   if (cluster.deploymentMode != MothershipClusterDeploymentMode::remote)
   {
      return true;
   }

   Vector<ClusterMachine> createdCloudMachines = {};
   mothershipCollectCreatedCloudClusterRemoveMachines(cluster, createdCloudMachines);
   if (createdCloudMachines.empty())
   {
      return true;
   }

   return hooks.destroyCreatedCloudMachines(cluster, createdCloudMachines, summary.destroyedCreatedCloudMachines, failure);
}
