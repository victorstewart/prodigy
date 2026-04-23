#pragma once

#include <prodigy/mothership/mothership.cluster.types.h>

static inline bool mothershipClusterUsesTestRunner(const MothershipProdigyCluster& cluster)
{
   return cluster.deploymentMode == MothershipClusterDeploymentMode::test;
}

static inline bool mothershipClusterTestHostIsRemote(const MothershipProdigyCluster& cluster)
{
   return mothershipClusterUsesTestRunner(cluster)
      && cluster.test.host.mode == MothershipClusterTestHostMode::ssh;
}

static inline bool mothershipTestClusterWorkspaceRootValid(const String& workspaceRoot)
{
   return workspaceRoot.size() > 0 && workspaceRoot[0] == '/';
}

static inline void mothershipResolveTestClusterControlSocketPath(const MothershipProdigyCluster& cluster, String& path)
{
   path.assign(cluster.test.workspaceRoot);
   if (path.size() > 0 && path[path.size() - 1] != '/')
   {
      path.append("/"_ctv);
   }
   path.append("prodigy-mothership.sock"_ctv);
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

static inline void mothershipResolveTestClusterRunnerPIDPath(const MothershipProdigyCluster& cluster, String& path)
{
   path.assign(cluster.test.workspaceRoot);
   if (path.size() > 0 && path[path.size() - 1] != '/')
   {
      path.append("/"_ctv);
   }
   path.append("test-cluster-runner.pid"_ctv);
}

static inline void mothershipResolveTestClusterRunnerLogPath(const MothershipProdigyCluster& cluster, String& path)
{
   path.assign(cluster.test.workspaceRoot);
   if (path.size() > 0 && path[path.size() - 1] != '/')
   {
      path.append("/"_ctv);
   }
   path.append("test-cluster-runner.log"_ctv);
}

static inline void mothershipResolveTestClusterRunnerRemotePath(const MothershipProdigyCluster& cluster, String& path)
{
   path.assign(cluster.test.workspaceRoot);
   if (path.size() > 0 && path[path.size() - 1] != '/')
   {
      path.append("/"_ctv);
   }
   path.append("prodigy_test_cluster_runner.sh"_ctv);
}

static inline void mothershipResolveTestClusterControlRecord(Vector<MothershipProdigyClusterControl>& controls, const MothershipProdigyCluster& cluster)
{
   controls.clear();

   String socketPath = {};
   mothershipResolveTestClusterControlSocketPath(cluster, socketPath);
   controls.push_back(MothershipProdigyClusterControl {
      .kind = MothershipClusterControlKind::unixSocket,
      .path = socketPath
   });
}
