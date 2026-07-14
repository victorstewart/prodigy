#pragma once

#include <prodigy/mothership/mothership.cluster.types.h>

constexpr static uint32_t mothershipTestClusterMachineLogicalCoresMax = 65'535;
constexpr static uint32_t mothershipTestClusterMachineMemoryMBMax = 16'777'216;
constexpr static uint32_t mothershipTestClusterMachineStorageMBMax = 1'048'576;
constexpr static uint32_t mothershipTestClusterStorageDeviceCountMax = 16;

static inline bool mothershipClusterUsesVirtualDatacenter(const MothershipProdigyCluster& cluster)
{
  return cluster.deploymentMode == MothershipClusterDeploymentMode::test;
}

static inline bool mothershipTestClusterWorkspaceRootValid(const String& workspaceRoot)
{
  if (workspaceRoot.size() < 4 || workspaceRoot[0] != '/' || workspaceRoot[workspaceRoot.size() - 1] == '/')
  {
    return false;
  }

  bool nested = false;
  uint32_t componentStart = 1;
  for (uint32_t index = 1; index <= workspaceRoot.size(); ++index)
  {
    if (index < workspaceRoot.size() && workspaceRoot[index] != '/')
    {
      continue;
    }
    uint32_t size = index - componentStart;
    if (size == 0 || (size == 1 && workspaceRoot[componentStart] == '.') ||
        (size == 2 && workspaceRoot[componentStart] == '.' && workspaceRoot[componentStart + 1] == '.'))
    {
      return false;
    }
    nested = nested || componentStart > 1;
    componentStart = index + 1;
  }
  return nested;
}

static inline void mothershipResolveTestClusterControlSocketPath(const MothershipProdigyCluster& cluster, String& path)
{
  String clusterUUID = {};
  clusterUUID.assignItoh(cluster.clusterUUID);
  path.assign("/tmp/prodigy-vdc-"_ctv);
  path.append(clusterUUID);
  path.append("/mothership.sock"_ctv);
}

static inline void mothershipResolveTestClusterManifestPath(const MothershipProdigyCluster& cluster, String& path)
{
  path.assign(cluster.test.workspaceRoot);
  if (path.size() > 0 && path[path.size() - 1] != '/')
  {
    path.append("/"_ctv);
  }
  path.append("test-cluster-manifest.json"_ctv);
}

static inline void mothershipResolveVirtualDatacenterPIDPath(const MothershipProdigyCluster& cluster, String& path)
{
  path.assign(cluster.test.workspaceRoot);
  if (path.size() > 0 && path[path.size() - 1] != '/')
  {
    path.append("/"_ctv);
  }
  path.append("virtual-datacenter.pid"_ctv);
}

static inline void mothershipResolveVirtualDatacenterLogPath(const MothershipProdigyCluster& cluster, String& path)
{
  path.assign(cluster.test.workspaceRoot);
  if (path.size() > 0 && path[path.size() - 1] != '/')
  {
    path.append("/"_ctv);
  }
  path.append("virtual-datacenter.log"_ctv);
}

static inline void mothershipResolveTestClusterControlRecord(Vector<MothershipProdigyClusterControl>& controls, const MothershipProdigyCluster& cluster)
{
  controls.clear();

  String socketPath = {};
  mothershipResolveTestClusterControlSocketPath(cluster, socketPath);
  controls.push_back(MothershipProdigyClusterControl {
      .kind = MothershipClusterControlKind::unixSocket,
      .path = socketPath});
}
