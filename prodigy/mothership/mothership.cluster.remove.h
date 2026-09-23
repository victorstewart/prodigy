#pragma once

#include <algorithm>
#include <prodigy/bundle.artifact.h>
#include <prodigy/mothership/mothership.cluster.types.h>
#include <prodigy/persistent.state.h>

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

// This is deliberately the only thing the emergency reader is allowed to
// return.  In particular it is not a BrainConfig or a persistent snapshot:
// those also contain the credential and SSH-key sidecars needed to run a
// cluster.  The shared topology and lease payload is compared before
// Mothership touches the DNS provider. Source identity is kept separately:
// each queried machine necessarily reports a different local UUID.
class MothershipOfflineDNSCleanupInventory {
public:
  uint128_t clusterUUID = 0;
  uint128_t sourceSnapshotClusterUUID = 0;
  uint128_t sourceLocalMachineUUID = 0;
  uint128_t sourceOwnerClusterUUID = 0;
  class Machine {
  public:
    uint128_t uuid = 0;
    String sshAddress;
  };
  Vector<Machine> machines;
  Vector<RoutableResourceLease> dnsRecordLeases;
};

template <typename S>
static void serialize(S&& serializer, MothershipOfflineDNSCleanupInventory::Machine& machine)
{
  serializer.value16b(machine.uuid);
  serializer.text1b(machine.sshAddress, UINT32_MAX);
}

template <typename S>
static void serialize(S&& serializer, MothershipOfflineDNSCleanupInventory& inventory)
{
  serializer.value16b(inventory.clusterUUID);
  serializer.value16b(inventory.sourceSnapshotClusterUUID);
  serializer.value16b(inventory.sourceLocalMachineUUID);
  serializer.value16b(inventory.sourceOwnerClusterUUID);
  serializer.object(inventory.machines);
  serializer.object(inventory.dnsRecordLeases);
}

static inline bool mothershipOfflineDNSCleanupInventoryMatches(const MothershipOfflineDNSCleanupInventory& expected,
                                                                const MothershipOfflineDNSCleanupInventory& actual)
{
  if (expected.clusterUUID != actual.clusterUUID || expected.machines.size() != actual.machines.size() || expected.dnsRecordLeases.size() != actual.dnsRecordLeases.size()) return false;
  for (uint32_t i = 0; i < expected.machines.size(); ++i)
  {
    if (expected.machines[i].uuid != actual.machines[i].uuid || expected.machines[i].sshAddress != actual.machines[i].sshAddress) return false;
  }
  for (uint32_t i = 0; i < expected.dnsRecordLeases.size(); ++i)
  {
    if ((expected.dnsRecordLeases[i] == actual.dnsRecordLeases[i]) == false) return false;
  }
  return true;
}

enum class MothershipOfflineDNSRecoveryMode : uint8_t {
  strict = 0,
  allowUnconfiguredSnapshot = 1,
};

// The emergency reader intentionally opens only the public TideDB records.
// It never constructs ProdigyPersistentStateStore, which would consult the
// private sidecar to reconstruct runnable TLS and bootstrap state.
static inline bool mothershipBuildOfflineDNSCleanupInventory(const String& statePath, uint128_t expectedClusterUUID, bool allowUnconfiguredSnapshot, MothershipOfflineDNSCleanupInventory& inventory, String& failure)
{
  inventory = {};
  if (expectedClusterUUID == 0)
  {
    failure.assign("offline DNS recovery requires a nonzero cluster UUID"_ctv);
    return false;
  }
  TidesDB db(statePath);
  String serialized = {};
  if (db.read("brain", "snapshot", serialized, &failure) == false) return false;
  ProdigyPersistentStoredBrainSnapshot stored = {};
  if (prodigyLoadPersistentStoredRecord(serialized, stored) == false)
  {
    failure.assign("offline DNS recovery snapshot decode failed"_ctv);
    return false;
  }
  const uint128_t snapshotClusterUUID = stored.state.brainConfig.clusterUUID;
  if (snapshotClusterUUID != expectedClusterUUID && (allowUnconfiguredSnapshot == false || snapshotClusterUUID != 0))
  {
    failure.assign("offline DNS recovery snapshot cluster UUID does not match requested cluster"_ctv);
    return false;
  }
  inventory.clusterUUID = expectedClusterUUID;
  inventory.sourceSnapshotClusterUUID = snapshotClusterUUID;
  if (allowUnconfiguredSnapshot)
  {
    // This repair mode is only for the observed empty-cluster configuration
    // defect. A live deployment plan or DNS lease needs the ordinary,
    // fully configured snapshot recovery path.
    if (stored.state.masterAuthority.deploymentPlans.empty() == false)
    {
      failure.assign("offline unconfigured DNS recovery requires no deployment plans"_ctv);
      return false;
    }
    for (const RoutableResourceLease& lease : stored.state.masterAuthority.runtimeState.routableResourceLeases)
    {
      if (lease.kind == RoutableResourceLeaseKind::dnsRecord)
      {
        failure.assign("offline unconfigured DNS recovery requires no DNS leases"_ctv);
        return false;
      }
    }
    String localSerialized = {};
    if (db.read("brain", "local_brain_state", localSerialized, &failure) == false) return false;
    ProdigyPersistentStoredLocalBrainState local = {};
    if (prodigyLoadPersistentStoredRecord(localSerialized, local) == false)
    {
      failure.assign("offline DNS recovery local public state decode failed"_ctv);
      return false;
    }
    if (local.state.ownerClusterUUID != expectedClusterUUID || local.state.uuid == 0)
    {
      failure.assign("offline DNS recovery local public ownership does not match requested cluster"_ctv);
      return false;
    }
    inventory.sourceOwnerClusterUUID = local.state.ownerClusterUUID;
    inventory.sourceLocalMachineUUID = local.state.uuid;
  }
  for (const ClusterMachine& machine : stored.state.topology.machines)
  {
    if (machine.ssh.address.size() == 0)
    {
      failure.assign("offline DNS recovery snapshot topology has a machine without SSH address"_ctv);
      return false;
    }
    if (machine.uuid == 0)
    {
      failure.assign("offline DNS recovery snapshot topology has a machine without UUID"_ctv);
      return false;
    }
    inventory.machines.push_back({.uuid = machine.uuid, .sshAddress = machine.ssh.address});
  }
  for (const RoutableResourceLease& lease : stored.state.masterAuthority.runtimeState.routableResourceLeases)
  {
    if (lease.kind == RoutableResourceLeaseKind::dnsRecord) inventory.dnsRecordLeases.push_back(lease);
  }
  // A deterministic ordering makes inventories from different elected peers
  // byte-comparable without retaining a second recovery journal.
  std::sort(inventory.machines.begin(), inventory.machines.end(), [](const MothershipOfflineDNSCleanupInventory::Machine& a, const MothershipOfflineDNSCleanupInventory::Machine& b) { return a.uuid < b.uuid || (a.uuid == b.uuid && prodigyPersistentStringComesBefore(a.sshAddress, b.sshAddress)); });
  std::sort(inventory.dnsRecordLeases.begin(), inventory.dnsRecordLeases.end(), [](const RoutableResourceLease& a, const RoutableResourceLease& b) {
    RoutableResourceLease ac = a, bc = b; String as = {}, bs = {}; BitseryEngine::serialize(as, ac); BitseryEngine::serialize(bs, bc);
    const size_t common = std::min(as.size(), bs.size()); const int compared = common ? std::memcmp(as.data(), bs.data(), common) : 0;
    return compared != 0 ? compared < 0 : as.size() < bs.size();
  });
  failure.clear();
  return true;
}

// A deliberately narrow seam for the offline recovery ordering.  It keeps the
// unit proof independent of SSH and DNS transports: every root is quiesced,
// then every public inventory agrees, then DNS is removed, then (and only then)
// the normal wipe owner may run.
class MothershipOfflineDNSRecoveryHooks {
public:
  virtual ~MothershipOfflineDNSRecoveryHooks() = default;
  virtual bool quiesce(const MothershipProdigyClusterMachine& machine, String *failure) = 0;
  virtual bool exportInventory(const MothershipProdigyClusterMachine& machine, MothershipOfflineDNSCleanupInventory& inventory, String *failure) = 0;
  virtual bool removeDNS(const MothershipOfflineDNSCleanupInventory& inventory, uint32_t& removed, String *failure) = 0;
  virtual bool wipe(const MothershipProdigyClusterMachine& machine, String *failure) = 0;
};


static inline void mothershipAppendProdigyStopAndDrainCommand(String& command)
{
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
)SH"_ctv);
}

static inline void mothershipBuildProdigyStopAndDrainCommand(String& command)
{
  command.assign("set -eu; "_ctv);
  mothershipAppendProdigyStopAndDrainCommand(command);
}

static inline void mothershipAppendProdigyOwnedStorageCleanupCommand(String& command)
{
  mothershipAppendProdigyStopAndDrainCommand(command);
  command.append(R"SH(
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

// Preserve only the migration-owned database backups before the ordinary reset
// erases /var/lib/prodigy.  The destination name is the exact source basename
// below a UUID-specific directory, so a retry can recognize an already moved
// backup without widening cleanup to arbitrary state directories.
static inline void mothershipAppendProdigyMigrationResetCleanupCommand(uint128_t clusterUUID, String& command)
{
  if (clusterUUID == 0) { command.append("echo 'cluster reset cleanup requires a cluster UUID' >&2; exit 1; "_ctv); return; }

  String retainedRoot = {};
  retainedRoot.snprintf<"/var/lib/prodigy-retained/{itoh}"_ctv>(clusterUUID);
  command.append("umask 077; retained_root=/var/lib/prodigy-retained; cluster_retained_root="_ctv);
  prodigyAppendShellSingleQuoted(command, retainedRoot);
  command.append(R"SH(;
for retained_directory in "$retained_root" "$cluster_retained_root"; do
  test ! -L "$retained_directory" || { echo 'refusing retained directory symlink' >&2; exit 1; };
  mkdir -p "$retained_directory";
  test -d "$retained_directory" && test ! -L "$retained_directory" && test -O "$retained_directory" || { echo 'unsafe retained backup directory' >&2; exit 1; };
  chmod 700 "$retained_directory";
done;
if test -d /var/lib/prodigy; then test "$(stat -c %d /var/lib/prodigy)" = "$(stat -c %d "$retained_root")" || { echo 'retained backup destination is not on the state filesystem' >&2; exit 1; }; fi;
for source in /var/lib/prodigy/state.tidesdb9-* /var/lib/prodigy/state.secrets.tidesdb9-* /var/lib/prodigy/state.retained10-* /var/lib/prodigy/state.secrets.retained10-*; do
  test -e "$source" || test ! -L "$source" || { echo 'refusing retained backup symlink' >&2; exit 1; };
  test -e "$source" || continue;
  name=${source##*/}; suffix=${name##*-};
  case "${name%-*}" in state.tidesdb9|state.secrets.tidesdb9|state.retained10|state.secrets.retained10) ;; *) echo 'unsupported retained backup name' >&2; exit 1;; esac;
  test "${#suffix}" = 16 || { echo 'unsupported retained backup suffix' >&2; exit 1; };
  case "$suffix" in *[!0123456789abcdef]*) echo 'unsupported retained backup suffix' >&2; exit 1;; esac;
  test -d "$source" && test ! -L "$source" && test -O "$source" || { echo 'unsafe retained backup source' >&2; exit 1; };
  destination="$cluster_retained_root/$name";
  if test -e "$destination" || test -L "$destination"; then
    echo 'retained backup collision' >&2; exit 1;
  fi;
  mv -T "$source" "$destination" || { echo 'failed to preserve retained backup' >&2; exit 1; };
done;
sync -f "$cluster_retained_root"; if test -d /var/lib/prodigy; then sync -f /var/lib/prodigy; fi)SH"_ctv);
}

static inline void mothershipAppendProdigyMigrationFenceCleanupCommand(String& command)
{
  command.append(R"SH(dropin_directory=/etc/systemd/system/prodigy.service.d;
removed_migration_dropin=0;
for dropin in "$dropin_directory"/99-tidesdb-migration-????????????????.conf; do
  test -e "$dropin" || test ! -L "$dropin" || { echo 'refusing migration drop-in symlink' >&2; exit 1; };
  test -e "$dropin" || continue;
  name=${dropin##*/}; suffix=${name#99-tidesdb-migration-}; suffix=${suffix%.conf};
  case "$suffix" in *[!0123456789abcdef]*) echo 'refusing non-migration drop-in name' >&2; exit 1;; esac;
  test -f "$dropin" && test ! -L "$dropin" && test -O "$dropin" || { echo 'unsafe migration drop-in' >&2; exit 1; };
  fence=$(sed -n '2{s/^ConditionPathExists=!\(\/.*\/guest\/writers-fenced\)$/\1/p;}' "$dropin");
  test -n "$fence" && printf '[Unit]\nConditionPathExists=!%s\n' "$fence" | cmp -s - "$dropin" || { echo 'refusing non-migration drop-in' >&2; exit 1; };
  rm -- "$dropin" || { echo 'failed to remove migration drop-in' >&2; exit 1; };
  removed_migration_dropin=1;
done;
if test "$removed_migration_dropin" = 1; then sync -f "$dropin_directory"; systemctl daemon-reload; fi
)SH"_ctv);
}

static inline void mothershipBuildProdigyStateWipeCommand(const String& stateDBPath, uint128_t clusterUUID, String& command)
{
  command.assign("set -eu; "_ctv);
  mothershipAppendProdigyOwnedStorageCleanupCommand(command);
  command.append("; "_ctv);
  if (clusterUUID != 0) {
    mothershipAppendProdigyMigrationResetCleanupCommand(clusterUUID, command);
    command.append("; "_ctv);
  }
  command.append("rm -rf /run/prodigy /var/lib/prodigy"_ctv);
  constexpr static const char *defaultStatePrefix = "/var/lib/prodigy/";
  if (stateDBPath.size() < 17 || std::memcmp(stateDBPath.data(), defaultStatePrefix, 17) != 0) {
    command.append(" "_ctv);
    prodigyAppendShellSingleQuoted(command, stateDBPath);
  }
  if (clusterUUID != 0) {
    command.append("; "_ctv);
    mothershipAppendProdigyMigrationFenceCleanupCommand(command);
  }
}

static inline void mothershipBuildProdigyStateWipeCommand(const String& stateDBPath, String& command)
{
  mothershipBuildProdigyStateWipeCommand(stateDBPath, 0, command);
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

static inline bool mothershipRunOfflineDNSRecovery(const MothershipProdigyCluster& cluster, MothershipOfflineDNSRecoveryHooks& hooks, MothershipClusterRemoveSummary& summary, String *failure = nullptr, MothershipOfflineDNSRecoveryMode mode = MothershipOfflineDNSRecoveryMode::strict)
{
  summary = {};
  if (failure) failure->clear();
  if (cluster.clusterUUID == 0 || cluster.deploymentMode == MothershipClusterDeploymentMode::test || cluster.includeLocalMachine)
  {
    if (failure) failure->assign("offline DNS recovery requires an identified SSH-only cluster"_ctv);
    return false;
  }
  for (const MothershipProdigyClusterMachine& machine : cluster.machines)
  {
    if (machine.source != MothershipClusterMachineSource::adopted || machine.ssh.address.size() == 0 || machine.ssh.user.size() == 0)
    {
      if (failure) failure->assign("offline DNS recovery requires complete adopted SSH registration"_ctv);
      return false;
    }
  }
  Vector<MothershipProdigyClusterMachine> machines = {};
  mothershipCollectAdoptedClusterRemoveMachines(cluster, machines);
  if (machines.empty() || cluster.topology.machines.empty()) { if (failure) failure->assign("offline DNS recovery requires complete adopted topology"_ctv); return false; }
  MothershipOfflineDNSCleanupInventory expected = {}; expected.clusterUUID = cluster.clusterUUID;
  for (const ClusterMachine& machine : cluster.topology.machines)
  {
    if (machine.source != ClusterMachineSource::adopted || machine.uuid == 0 || machine.ssh.address.size() == 0) { if (failure) failure->assign("offline DNS recovery topology mapping is incomplete"_ctv); return false; }
    expected.machines.push_back({.uuid = machine.uuid, .sshAddress = machine.ssh.address});
  }
  std::sort(expected.machines.begin(), expected.machines.end(), [](const auto& a, const auto& b) { return a.uuid < b.uuid || (a.uuid == b.uuid && prodigyPersistentStringComesBefore(a.sshAddress, b.sshAddress)); });
  if (expected.machines.size() != machines.size()) { if (failure) failure->assign("offline DNS recovery adopted machine membership mismatch"_ctv); return false; }
  for (uint32_t i = 0; i < expected.machines.size(); ++i)
  {
    for (uint32_t previous = 0; previous < i; ++previous)
    {
      if (expected.machines[previous].uuid == expected.machines[i].uuid || expected.machines[previous].sshAddress == expected.machines[i].sshAddress)
      {
        if (failure) failure->assign("offline DNS recovery topology mapping is duplicate"_ctv);
        return false;
      }
    }
    bool found = false; for (const MothershipProdigyClusterMachine& registered : machines) if (registered.ssh.address == expected.machines[i].sshAddress) found = true;
    if (found == false) { if (failure) failure->assign("offline DNS recovery adopted machine membership mismatch"_ctv); return false; }
  }
  for (const MothershipProdigyClusterMachine& machine : machines)
    if (hooks.quiesce(machine, failure) == false) return false;
  MothershipOfflineDNSCleanupInventory inventory = {};
  bool sawAuthoritativeSnapshot = false;
  for (const MothershipProdigyClusterMachine& machine : machines)
  {
    MothershipOfflineDNSCleanupInventory observed = {};
    if (hooks.exportInventory(machine, observed, failure) == false) return false;
    if (observed.clusterUUID != cluster.clusterUUID ||
        (mode == MothershipOfflineDNSRecoveryMode::strict && observed.sourceSnapshotClusterUUID != cluster.clusterUUID) ||
        (mode == MothershipOfflineDNSRecoveryMode::allowUnconfiguredSnapshot &&
         observed.sourceSnapshotClusterUUID != 0 && observed.sourceSnapshotClusterUUID != cluster.clusterUUID) ||
        (inventory.clusterUUID != 0 && mothershipOfflineDNSCleanupInventoryMatches(inventory, observed) == false))
    { if (failure) failure->assign("offline DNS recovery inventories do not match"_ctv); return false; }

    if (mode == MothershipOfflineDNSRecoveryMode::allowUnconfiguredSnapshot)
    {
      uint128_t expectedLocalUUID = 0;
      for (const MothershipOfflineDNSCleanupInventory::Machine& expectedMachine : expected.machines)
        if (expectedMachine.sshAddress == machine.ssh.address) { expectedLocalUUID = expectedMachine.uuid; break; }
      if (observed.sourceOwnerClusterUUID != cluster.clusterUUID || observed.sourceLocalMachineUUID == 0 ||
          observed.sourceLocalMachineUUID != expectedLocalUUID)
      {
        if (failure) failure->assign("offline DNS recovery local public ownership does not match registered machine"_ctv);
        return false;
      }
    }
    sawAuthoritativeSnapshot = sawAuthoritativeSnapshot || observed.sourceSnapshotClusterUUID == cluster.clusterUUID;
    inventory = std::move(observed);
  }
  if (mode == MothershipOfflineDNSRecoveryMode::allowUnconfiguredSnapshot && sawAuthoritativeSnapshot == false)
  {
    if (failure) failure->assign("offline DNS recovery requires an authoritative snapshot witness"_ctv);
    return false;
  }
  if (mode == MothershipOfflineDNSRecoveryMode::allowUnconfiguredSnapshot && inventory.dnsRecordLeases.empty() == false)
  {
    if (failure) failure->assign("offline unconfigured DNS recovery requires no DNS leases"_ctv);
    return false;
  }
  MothershipOfflineDNSCleanupInventory observed = {}; observed.clusterUUID = inventory.clusterUUID; observed.machines = inventory.machines;
  if (mothershipOfflineDNSCleanupInventoryMatches(expected, observed) == false) { if (failure) failure->assign("offline DNS recovery inventory source membership mismatch"_ctv); return false; }
  if (hooks.removeDNS(inventory, summary.removedDNSRecords, failure) == false) return false;
  summary.dnsTeardownCompleted = true;
  for (const MothershipProdigyClusterMachine& machine : machines)
  {
    if (hooks.wipe(machine, failure) == false) return false;
    summary.wipedAdoptedMachines += 1;
  }
  return true;
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
