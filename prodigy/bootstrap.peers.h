#pragma once

#include <prodigy/bootstrap.config.h>
#include <prodigy/types.h>

static inline void prodigyRenderClusterTopologyBootstrapPeers(const ClusterMachine& localMachine, const ClusterTopology& topology, Vector<ProdigyBootstrapConfig::BootstrapPeer>& peers)
{
  peers.clear();

  ClusterTopology normalizedTopology = topology;
  prodigyNormalizeClusterTopologyPeerAddresses(normalizedTopology);
  for (const ClusterMachine& clusterMachine : normalizedTopology.machines)
  {
    if (clusterMachine.isBrain == false || clusterMachine.sameIdentityAs(localMachine))
    {
      continue;
    }

    ProdigyBootstrapConfig::BootstrapPeer peer = {};
    peer.isBrain = true;
    Vector<ClusterMachinePeerAddress> candidates = {};
    prodigyCollectClusterMachinePeerAddresses(clusterMachine, candidates);
    for (const ClusterMachinePeerAddress& candidate : candidates)
    {
      if (candidate.address.size() > 0)
      {
        peer.addresses.push_back(candidate);
      }
    }
    prodigyAppendUniqueBootstrapPeer(peers, peer);
  }

  std::sort(peers.begin(), peers.end(), prodigyBootstrapPeerComesBefore);
}
