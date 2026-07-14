#pragma once

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

#include <services/time.h>

#include <prodigy/bootstrap.peers.h>
#include <prodigy/bundle.artifact.h>
#include <prodigy/mothership/mothership.cluster.test.h>
#include <prodigy/mothership/mothership.cluster.types.h>
#include <prodigy/persistent.state.h>

constexpr static const char *mothershipVirtualDatacenterPIDFilename = "virtual-datacenter.pid";
constexpr static const char *mothershipVirtualDatacenterReadyFilename = "virtual-datacenter.ready";
constexpr static const char *mothershipVirtualDatacenterProvisionedFilename = "virtual-datacenter.provisioned";
constexpr static const char *mothershipVirtualDatacenterRuntimeFilename = "virtual-datacenter.runtime";

static inline void mothershipVirtualDatacenterPath(const String& workspaceRoot, const char *name, String& path)
{
  path.assign(workspaceRoot);
  if (path.size() > 0 && path[path.size() - 1] != '/')
  {
    path.append('/');
  }
  path.append(name);
}

static inline bool mothershipVirtualDatacenterWriteFile(String& path, const String& contents, mode_t mode, String *failure = nullptr)
{
  String temporary = {};
  temporary.snprintf<"{}.{itoa}.tmp"_ctv>(path, uint64_t(::getpid()));
  int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (fd < 0)
  {
    if (failure)
    {
      failure->snprintf<"failed to open {}: {}"_ctv>(temporary, String(std::strerror(errno)));
    }
    return false;
  }

  uint64_t offset = 0;
  while (offset < contents.size())
  {
    ssize_t written = ::write(fd, contents.data() + offset, size_t(contents.size() - offset));
    if (written < 0 && errno == EINTR)
    {
      continue;
    }
    if (written <= 0)
    {
      int saved = errno;
      ::close(fd);
      ::unlink(temporary.c_str());
      if (failure)
      {
        failure->snprintf<"failed to write {}: {}"_ctv>(path, String(std::strerror(saved)));
      }
      return false;
    }
    offset += uint64_t(written);
  }

  if (::fsync(fd) != 0)
  {
    int saved = errno;
    ::close(fd);
    ::unlink(temporary.c_str());
    if (failure)
    {
      failure->snprintf<"failed to sync {}: {}"_ctv>(path, String(std::strerror(saved)));
    }
    return false;
  }
  ::close(fd);

  if (::rename(temporary.c_str(), path.c_str()) != 0)
  {
    int saved = errno;
    ::unlink(temporary.c_str());
    if (failure)
    {
      failure->snprintf<"failed to publish {}: {}"_ctv>(path, String(std::strerror(saved)));
    }
    return false;
  }
  if (failure)
  {
    failure->clear();
  }
  return true;
}

static inline void mothershipVirtualDatacenterMachineAddresses(uint32_t index, bool fakeIpv4Boundary, String& private4, String& private6, String& public6)
{
  char host[9] = {};
  std::snprintf(host, sizeof(host), "%x", 9 + index);
  private4.snprintf<"10.0.0.{itoa}"_ctv>(uint64_t(9 + index));
  private6.snprintf<"fd00:10::{}"_ctv>(String(host));
  if (fakeIpv4Boundary)
  {
    public6.snprintf<"2602:fac0:0:12ab:34cd::{}"_ctv>(String(host));
  }
  else
  {
    public6.snprintf<"2001:db8:100::{}"_ctv>(String(host));
  }
}

static inline bool mothershipBuildVirtualDatacenterTopology(const MothershipProdigyCluster& cluster, ClusterTopology& topology, String *failure = nullptr)
{
  topology = {};
  topology.version = 1;
  if (cluster.deploymentMode != MothershipClusterDeploymentMode::test || cluster.test.machineCount == 0 || cluster.nBrains == 0 || cluster.nBrains > cluster.test.machineCount)
  {
    if (failure)
    {
      failure->assign("invalid test cluster shape for virtual datacenter"_ctv);
    }
    return false;
  }

  String schema = {};
  if (cluster.machineSchemas.empty() == false)
  {
    schema = cluster.machineSchemas[0].schema;
  }

  for (uint32_t index = 1; index <= cluster.test.machineCount; ++index)
  {
    String private4 = {};
    String private6 = {};
    String public6 = {};
    mothershipVirtualDatacenterMachineAddresses(index, cluster.test.enableFakeIpv4Boundary, private4, private6, public6);

    ClusterMachine machine = {};
    machine.source = ClusterMachineSource::created;
    machine.backing = ClusterMachineBacking::owned;
    machine.kind = MachineConfig::MachineKind::vm;
    machine.lifetime = MachineLifetime::reserved;
    machine.isBrain = index <= cluster.nBrains;
    machine.rackUUID = index;
    machine.creationTimeMs = Time::now<TimeResolution::ms>();
    machine.hasCloud = schema.size() > 0;
    machine.cloud.schema = schema;
    prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, private4, 24);
    prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, private6, 64);
    prodigyAppendUniqueClusterMachineAddress(machine.addresses.publicAddresses, public6, 64);

    switch (cluster.test.brainBootstrapFamily)
    {
      case MothershipClusterTestBootstrapFamily::ipv4:
        prodigyAppendUniqueClusterMachinePeerAddress(machine.peerAddresses, ClusterMachinePeerAddress {private4, 24});
        break;
      case MothershipClusterTestBootstrapFamily::private6:
        prodigyAppendUniqueClusterMachinePeerAddress(machine.peerAddresses, ClusterMachinePeerAddress {private6, 64});
        break;
      case MothershipClusterTestBootstrapFamily::public6:
        prodigyAppendUniqueClusterMachinePeerAddress(machine.peerAddresses, ClusterMachinePeerAddress {public6, 64});
        break;
      case MothershipClusterTestBootstrapFamily::multihome6:
        prodigyAppendUniqueClusterMachinePeerAddress(machine.peerAddresses, ClusterMachinePeerAddress {private6, 64});
        prodigyAppendUniqueClusterMachinePeerAddress(machine.peerAddresses, ClusterMachinePeerAddress {public6, 64});
        break;
    }
    topology.machines.push_back(std::move(machine));
  }

  prodigyNormalizeClusterTopologyPeerAddresses(topology);
  if (failure)
  {
    failure->clear();
  }
  return true;
}

static inline bool mothershipProvisionVirtualDatacenter(
    const MothershipProdigyCluster& cluster,
    const ClusterTopology& topology,
    const ProdigyRuntimeEnvironmentConfig& runtimeEnvironment,
    const String& bundlePath,
    String *failure = nullptr)
{
  String approvedDigest = {};
  if (prodigyApproveBundleArtifact(bundlePath, approvedDigest, failure) == false)
  {
    return false;
  }

  String bootDirectory = {};
  mothershipVirtualDatacenterPath(cluster.test.workspaceRoot, "boot", bootDirectory);

  for (uint32_t index = 0; index < topology.machines.size(); ++index)
  {
    String installRoot = {};
    installRoot.snprintf<"{}/machines/{itoa}/root/prodigy"_ctv>(cluster.test.workspaceRoot, uint64_t(index + 1));
    if (prodigyInstallBundleToRoot(bundlePath, installRoot, failure) == false)
    {
      return false;
    }

    ProdigyPersistentBootState state = {};
    state.bootstrapConfig.nodeRole = topology.machines[index].isBrain ? ProdigyBootstrapNodeRole::brain : ProdigyBootstrapNodeRole::neuron;
    mothershipResolveTestClusterControlSocketPath(cluster, state.bootstrapConfig.controlSocketPath);
    prodigyRenderClusterTopologyBootstrapPeers(topology.machines[index], topology, state.bootstrapConfig.bootstrapPeers);
    state.initialTopology = topology;
    prodigyOwnRuntimeEnvironmentConfig(runtimeEnvironment, state.runtimeEnvironment);

    String bootJSON = {};
    renderProdigyPersistentBootStateJSON(state, bootJSON);
    String bootPath = {};
    bootPath.snprintf<"{}/{itoa}.json"_ctv>(bootDirectory, uint64_t(index + 1));
    if (mothershipVirtualDatacenterWriteFile(bootPath, bootJSON, 0600, failure) == false)
    {
      return false;
    }
  }

  String provisionedPath = {};
  mothershipVirtualDatacenterPath(cluster.test.workspaceRoot, mothershipVirtualDatacenterProvisionedFilename, provisionedPath);
  return mothershipVirtualDatacenterWriteFile(provisionedPath, approvedDigest, 0600, failure);
}
