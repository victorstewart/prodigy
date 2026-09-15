#pragma once

#include <prodigy/bundle.artifact.h>
#include <prodigy/mothership/mothership.cluster.types.h>

class MothershipClusterRemoveSummary {
public:

  bool dnsTeardownCompleted = false;
  bool stoppedLocalMachine = false;
  uint32_t removedDNSRecords = 0;
  uint32_t wipedAdoptedMachines = 0;
  uint32_t destroyedCreatedCloudMachines = 0;
};

class MothershipClusterRemoveHooks {
public:

  virtual ~MothershipClusterRemoveHooks() = default;

  virtual bool removeDNSBindings(const MothershipProdigyCluster& cluster, uint32_t& removed, String *failure = nullptr) = 0;
  virtual bool stopTestCluster(const MothershipProdigyCluster& cluster, String *failure = nullptr) = 0;
  virtual bool stopAndWipeLocalMachine(const MothershipProdigyCluster& cluster, String *failure = nullptr) = 0;
  virtual bool stopAndWipeAdoptedMachine(const MothershipProdigyCluster& cluster, const MothershipProdigyClusterMachine& machine, String *failure = nullptr) = 0;
  virtual bool destroyCreatedCloudMachines(const MothershipProdigyCluster& cluster, const Vector<ClusterMachine>& machines, uint32_t& destroyed, String *failure = nullptr) = 0;
};

static inline void mothershipAppendProdigyOwnedStorageCleanupCommand(String& command)
{
  // Bootstrap creates this loop only when /containers is not already btrfs.
  // Do not unlink its backing file until the exact mount is gone.
  command.append(R"SH(load=$(systemctl show --property=LoadState --value prodigy) || { echo 'failed to query prodigy service' >&2; exit 1; };
if [ "$load" != not-found ]; then
  systemctl stop prodigy || { echo 'failed to stop prodigy' >&2; exit 1; };
  active=$(systemctl show --property=ActiveState --value prodigy) || exit 1;
  pid=$(systemctl show --property=MainPID --value prodigy) || exit 1;
  [ "$pid" = 0 ] || { echo 'prodigy remained active' >&2; exit 1; };
  case "$active" in inactive|failed) ;; *) echo 'prodigy service is still transitioning' >&2; exit 1;; esac;
  systemctl disable prodigy || true;
fi;
# Prodigy containers are placed in independent cgroup-v2 leaves, outside the
# prodigy.service control group. Stop every exact owned leaf before detaching
# its storage or erasing the controller state; otherwise an exited service can
# leave live application processes behind.
container_cgroup_root=/sys/fs/cgroup/containers.slice;
if [ -d "$container_cgroup_root" ]; then
  for container_leaf in "$container_cgroup_root"/*.slice/leaf; do
    [ -e "$container_leaf/cgroup.procs" ] || continue;
    [ -w "$container_leaf/cgroup.kill" ] || { echo 'owned container cgroup kill is unavailable' >&2; exit 1; };
    printf 1 >"$container_leaf/cgroup.kill" || { echo 'failed to kill owned container cgroup' >&2; exit 1; };
    container_procs=$(cat "$container_leaf/cgroup.procs") || { echo 'failed to read owned container cgroup' >&2; exit 1; };
    cgroup_kill_attempt=0;
    while [ -n "$container_procs" ] && [ "$cgroup_kill_attempt" -lt 20 ]; do
      sleep 0.05;
      container_procs=$(cat "$container_leaf/cgroup.procs") || { echo 'failed to read owned container cgroup' >&2; exit 1; };
      cgroup_kill_attempt=$((cgroup_kill_attempt + 1));
    done;
    [ -z "$container_procs" ] || { echo 'owned container cgroup remained populated' >&2; exit 1; };
  done;
fi;
img=/var/lib/prodigy/containers.btrfs.loop;
query_owned_loop() {
  loop=$(losetup -j "$img" --noheadings --output NAME) || { echo 'failed to query loop association' >&2; exit 1; };
  case "$loop" in
    '') ;;
    /dev/loop*) loop_number=${loop#/dev/loop}; case "$loop_number" in ''|*[!0-9]*) echo 'refusing ambiguous loop association' >&2; exit 1;; esac ;;
    *) echo 'refusing ambiguous loop association' >&2; exit 1;;
  esac;
};
query_owned_loop;
if mountpoint -q /containers; then
  source=$(findmnt -rn -o SOURCE --target /containers) || { echo 'failed to identify /containers source' >&2; exit 1; };
  fstype=$(findmnt -rn -o FSTYPE --target /containers) || { echo 'failed to identify /containers filesystem' >&2; exit 1; };
  if [ -e "$img" ]; then
    [ -n "$loop" ] && [ "$source" = "$loop" ] && [ "$fstype" = btrfs ] || { echo 'refusing ambiguous /containers loop mount' >&2; exit 1; };
    umount /containers || { echo 'failed to unmount owned /containers loop mount' >&2; exit 1; };
    if mountpoint -q /containers; then echo 'owned /containers loop mount remained mounted' >&2; exit 1; fi;
    query_owned_loop;
  else
    case "$source" in /dev/loop*) echo 'refusing unexpected /containers loop mount' >&2; exit 1;; esac;
  fi;
fi;
if [ -n "$loop" ]; then
  sources=$(findmnt -rn -o SOURCE) || { echo 'failed to query mount sources' >&2; exit 1; };
  set -f;
  for source in $sources; do
    case "$source" in "$loop"|"$loop"\[*) echo 'refusing loop still mounted outside /containers' >&2; exit 1;; esac;
  done;
  losetup -d "$loop" || { echo 'failed to detach owned /containers loop' >&2; exit 1; };
  query_owned_loop;
  [ -z "$loop" ] || { echo 'owned /containers loop remained attached' >&2; exit 1; };
fi)SH"_ctv);
}

static inline void mothershipBuildProdigyStateWipeCommand(const String& stateDBPath, String& command)
{
  command.assign("set -eu; "_ctv);
  mothershipAppendProdigyOwnedStorageCleanupCommand(command);
  command.append("; rm -rf /run/prodigy /var/lib/prodigy"_ctv);

  constexpr static const char *defaultStatePrefix = "/var/lib/prodigy/";
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

  command.assign("set -eu; "_ctv);
  mothershipAppendProdigyOwnedStorageCleanupCommand(command);
  command.append("; rm -f /etc/systemd/system/prodigy.service /etc/systemd/system/prodigy.service.tmp /etc/systemd/system/multi-user.target.wants/prodigy.service"_ctv);
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
    if (topologyMachine.source != ClusterMachineSource::created || topologyMachine.backing != ClusterMachineBacking::cloud || topologyMachine.cloud.cloudID.size() == 0)
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

static inline bool mothershipRemoveClusterRuntime(const MothershipProdigyCluster& cluster, MothershipClusterRemoveHooks& hooks, MothershipClusterRemoveSummary& summary, String *failure = nullptr, const String *completedDNSClusterUUID = nullptr)
{
  summary = {};
  if (failure)
  {
    failure->clear();
  }

  if (completedDNSClusterUUID != nullptr)
  {
    // Explicit operator recovery for an interrupted removal whose DNS teardown
    // already succeeded. A reusable name cannot authorize skipping this step
    // for a replacement cluster; require the exact previously removed UUID.
    String expectedUUID = {};
    expectedUUID.assignItoh(cluster.clusterUUID);
    if (cluster.clusterUUID == 0 || completedDNSClusterUUID->equals(expectedUUID) == false)
    {
      if (failure) failure->assign("removal resume requires the exact cluster UUID whose DNS teardown completed"_ctv);
      return false;
    }
  }
  else if (hooks.removeDNSBindings(cluster, summary.removedDNSRecords, failure) == false)
  {
    return false;
  }
  summary.dnsTeardownCompleted = true;

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
