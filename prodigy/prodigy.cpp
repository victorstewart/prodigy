#include <prodigy/prodigy.h>
#include <services/debug.h>
#include <prodigy/brain/brain.h>
#include <prodigy/bootstrap.config.h>
#include <prodigy/netdev.detect.h>
#include <prodigy/persistent.state.h>
#include <prodigy/iaas/runtime/runtime.h>

#include <arpa/inet.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <sys/stat.h>
#include <sys/file.h>

// Canonical Prodigy entrypoint. First boot is seeded by --boot-json or
// --boot-json-path and all later boots come from the local TidesDB-backed
// state database.

static ProdigyPersistentStateStore persistentStateStore;
static ProdigyPersistentBootState persistentBootState;
static ProdigyPersistentBrainSnapshot persistedBrainSnapshot;
static ProdigyPersistentLocalBrainState persistentLocalBrainState;
static bool havePersistedBrainSnapshot = false;
static ProdigyBootstrapConfig effectiveBootstrapConfig;

static bool prodigyReadTextFile(const String& path, String& content, String& failure)
{
   content.clear();
   failure.clear();

   String pathText = {};
   pathText.assign(path);
   FILE *file = std::fopen(pathText.c_str(), "rb");
   if (file == nullptr)
   {
      failure.snprintf<"failed to open {}"_ctv>(path);
      return false;
   }

   char buffer[4096] = {};
   while (true)
   {
      size_t readBytes = std::fread(buffer, 1, sizeof(buffer), file);
      if (readBytes > 0)
      {
         content.append(reinterpret_cast<const uint8_t *>(buffer), uint64_t(readBytes));
      }

      if (readBytes < sizeof(buffer))
      {
         if (std::ferror(file) != 0)
         {
            std::fclose(file);
            content.clear();
            failure.snprintf<"failed to read {}"_ctv>(path);
            return false;
         }

         break;
      }
   }

   std::fclose(file);
   return true;
}

static bool prodigyEnforceDevHostNetnsIsolation(String& failure)
{
   failure.clear();

   const char *devMode = getenv("PRODIGY_DEV_MODE");
   if (devMode == nullptr || devMode[0] != '1' || devMode[1] != '\0')
   {
      return true;
   }

   const char *hostNetnsInodeText = getenv("PRODIGY_HOST_NETNS_INO");
   if (hostNetnsInodeText == nullptr || hostNetnsInodeText[0] == '\0')
   {
      return true;
   }

   errno = 0;
   char *terminal = nullptr;
   unsigned long long expectedHostNetnsInode = std::strtoull(hostNetnsInodeText, &terminal, 10);
   if (errno != 0 || terminal == hostNetnsInodeText || terminal == nullptr || terminal[0] != '\0')
   {
      failure.assign("refusing dev run: invalid PRODIGY_HOST_NETNS_INO"_ctv);
      return false;
   }

   struct stat currentNetnsStat = {};
   if (::stat("/proc/self/ns/net", &currentNetnsStat) != 0)
   {
      failure.assign("refusing dev run: failed to stat current netns"_ctv);
      return false;
   }

   unsigned long long currentNetnsInode = static_cast<unsigned long long>(currentNetnsStat.st_ino);
   if (currentNetnsInode == expectedHostNetnsInode)
   {
      failure.snprintf<"refusing dev run: current netns inode {itoa} matches host netns inode {itoa}"_ctv>(
         currentNetnsInode,
         expectedHostNetnsInode);
      return false;
   }

   return true;
}

static void prodigyAppendClusterTopologyBrainPeers(Vector<ProdigyBootstrapConfig::BootstrapPeer>& peers, const ClusterTopology& topology)
{
   peers.clear();
   ClusterTopology normalizedTopology = topology;
   prodigyNormalizeClusterTopologyPeerAddresses(normalizedTopology);

   for (const ClusterMachine& clusterMachine : normalizedTopology.machines)
   {
      if (clusterMachine.isBrain == false)
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

static ClusterTopology prodigyCaptureClusterTopology(const Brain& brain, const ClusterTopology& authoritativeTopology)
{
   ClusterTopology topology = {};
   Vector<ClusterMachine> captured;
   captured.reserve(brain.machines.size());

   for (Machine *machine : brain.machines)
   {
      if (machine == nullptr)
      {
         continue;
      }

      const ClusterMachine *authoritativeMachine = prodigyFindAuthoritativeClusterMachineForMachine(authoritativeTopology, *machine);

      ClusterMachine clusterMachine = {};
      if (authoritativeMachine != nullptr)
      {
         clusterMachine = *authoritativeMachine;
      }
      else
      {
         clusterMachine.source = ClusterMachineSource(machine->topologySource);
         clusterMachine.backing = machine->cloudID.size() > 0 ? ClusterMachineBacking::cloud : ClusterMachineBacking::owned;
         clusterMachine.lifetime = machine->lifetime;
      }

      if (auto it = brain.brainConfig.configBySlug.find(machine->slug); it != brain.brainConfig.configBySlug.end())
      {
         clusterMachine.kind = it->second.kind;
         if (machine->totalLogicalCores == 0) clusterMachine.totalLogicalCores = it->second.nLogicalCores;
         if (machine->totalMemoryMB == 0) clusterMachine.totalMemoryMB = it->second.nMemoryMB;
         if (machine->totalStorageMB == 0) clusterMachine.totalStorageMB = it->second.nStorageMB;
      }

      clusterMachine.isBrain = machine->isBrain;
      if (machine->cloudID.size() > 0)
      {
         clusterMachine.backing = ClusterMachineBacking::cloud;
         clusterMachine.cloud.schema = machine->slug;
         clusterMachine.cloud.providerMachineType = machine->type;
         clusterMachine.cloud.cloudID = machine->cloudID;
      }
      clusterMachine.ssh.address = machine->sshAddress;
      clusterMachine.ssh.port = machine->sshPort;
      clusterMachine.ssh.user = machine->sshUser;
      clusterMachine.ssh.privateKeyPath = machine->sshPrivateKeyPath;
      clusterMachine.ssh.hostPublicKeyOpenSSH = machine->sshHostPublicKeyOpenSSH;
      prodigyAssignClusterMachineAddressesFromPeerCandidates(clusterMachine.addresses, machine->peerAddresses);
      prodigyAppendUniqueClusterMachineAddress(clusterMachine.addresses.publicAddresses, machine->publicAddress);
      String privateGateway = {};
      if (machine->gatewayPrivate4 != 0)
      {
         IPAddress gatewayAddress = {};
         gatewayAddress.v4 = machine->gatewayPrivate4;
         gatewayAddress.is6 = false;
         (void)ClusterMachine::renderIPAddressLiteral(gatewayAddress, privateGateway);
      }
      prodigyAppendUniqueClusterMachineAddress(clusterMachine.addresses.privateAddresses, machine->privateAddress, 0, privateGateway);

      clusterMachine.uuid = machine->uuid;
      clusterMachine.rackUUID = machine->rackUUID;
      clusterMachine.creationTimeMs = machine->creationTimeMs;
      if (clusterMachine.totalLogicalCores == 0) clusterMachine.totalLogicalCores = machine->totalLogicalCores > 0 ? machine->totalLogicalCores : machine->ownedLogicalCores;
      if (clusterMachine.totalMemoryMB == 0) clusterMachine.totalMemoryMB = machine->totalMemoryMB > 0 ? machine->totalMemoryMB : machine->ownedMemoryMB;
      if (clusterMachine.totalStorageMB == 0) clusterMachine.totalStorageMB = machine->totalStorageMB > 0 ? machine->totalStorageMB : machine->ownedStorageMB;
      clusterMachine.hardware = machine->hardware;
      clusterMachine.ownership.mode = ClusterMachineOwnershipMode(machine->ownershipMode);
      clusterMachine.ownership.nLogicalCoresCap = machine->ownershipLogicalCoresCap;
      clusterMachine.ownership.nMemoryMBCap = machine->ownershipMemoryMBCap;
      clusterMachine.ownership.nStorageMBCap = machine->ownershipStorageMBCap;
      clusterMachine.ownership.nLogicalCoresBasisPoints = machine->ownershipLogicalCoresBasisPoints;
      clusterMachine.ownership.nMemoryBasisPoints = machine->ownershipMemoryBasisPoints;
      clusterMachine.ownership.nStorageBasisPoints = machine->ownershipStorageBasisPoints;
      if (clusterMachine.ownedLogicalCores == 0) clusterMachine.ownedLogicalCores = machine->ownedLogicalCores;
      if (clusterMachine.ownedMemoryMB == 0) clusterMachine.ownedMemoryMB = machine->ownedMemoryMB;
      if (clusterMachine.ownedStorageMB == 0) clusterMachine.ownedStorageMB = machine->ownedStorageMB;
      if ((clusterMachine.ownedLogicalCores == 0 || clusterMachine.ownedMemoryMB == 0 || clusterMachine.ownedStorageMB == 0)
         && clusterMachine.totalLogicalCores > 0
         && clusterMachine.totalMemoryMB > 0
         && clusterMachine.totalStorageMB > 0)
      {
         (void)clusterMachineApplyOwnedResourcesFromTotals(clusterMachine, clusterMachine.totalLogicalCores, clusterMachine.totalMemoryMB, clusterMachine.totalStorageMB);
      }

      captured.push_back(std::move(clusterMachine));
   }

   if (captured.empty() == false)
   {
      // Live self snapshots do not always retain bootstrap-only provisioning
      // metadata such as cloud IDs and SSH credentials. Preserve that metadata
      // from the last authoritative topology when identity still matches.
      topology.machines = captured;
      prodigyBackfillClusterTopologyFromAuthoritative(topology, authoritativeTopology);
      captured.clear();
      for (ClusterMachine& machine : topology.machines)
      {
         captured.push_back(std::move(machine));
      }
      topology.machines.clear();
   }

   std::sort(captured.begin(), captured.end(), [] (const ClusterMachine& lhs, const ClusterMachine& rhs) {
      auto firstPrivate = [] (const ClusterMachine& machine) -> const ClusterMachineAddress * {
         return prodigyFirstClusterMachineAddress(machine.addresses.privateAddresses);
      };

      if (lhs.uuid != 0 && rhs.uuid != 0 && lhs.uuid != rhs.uuid)
      {
         return lhs.uuid < rhs.uuid;
      }

      if ((lhs.uuid != 0) != (rhs.uuid != 0))
      {
         return lhs.uuid != 0;
      }

      uint64_t compareBytes = lhs.cloud.cloudID.size();
      if (rhs.cloud.cloudID.size() < compareBytes)
      {
         compareBytes = rhs.cloud.cloudID.size();
      }

      int cmp = 0;
      if (compareBytes > 0)
      {
         cmp = memcmp(lhs.cloud.cloudID.data(), rhs.cloud.cloudID.data(), compareBytes);
      }

      if (cmp != 0)
      {
         return cmp < 0;
      }

      if (lhs.cloud.cloudID.size() != rhs.cloud.cloudID.size())
      {
         return lhs.cloud.cloudID.size() < rhs.cloud.cloudID.size();
      }

      const ClusterMachineAddress *lhsPrivate = firstPrivate(lhs);
      const ClusterMachineAddress *rhsPrivate = firstPrivate(rhs);
      uint64_t lhsPrivateSize = lhsPrivate ? lhsPrivate->address.size() : 0;
      uint64_t rhsPrivateSize = rhsPrivate ? rhsPrivate->address.size() : 0;
      compareBytes = lhsPrivateSize;
      if (rhsPrivateSize < compareBytes)
      {
         compareBytes = rhsPrivateSize;
      }

      cmp = 0;
      if (compareBytes > 0)
      {
         cmp = memcmp(lhsPrivate->address.data(), rhsPrivate->address.data(), compareBytes);
      }

      if (cmp != 0)
      {
         return cmp < 0;
      }

      if (lhsPrivateSize != rhsPrivateSize)
      {
         return lhsPrivateSize < rhsPrivateSize;
      }

      return std::lexicographical_compare(lhs.ssh.address.data(), lhs.ssh.address.data() + lhs.ssh.address.size(),
         rhs.ssh.address.data(), rhs.ssh.address.data() + rhs.ssh.address.size());
   });

   for (ClusterMachine& machine : captured)
   {
      topology.machines.push_back(std::move(machine));
   }

   if (topology.machines.empty() == false)
   {
      prodigyNormalizeClusterTopologyPeerAddresses(topology);
      prodigyStripMachineHardwareCapturesFromClusterTopology(topology);
      topology.version = authoritativeTopology.version + 1;
   }

   return topology;
}

static void prodigyDeriveBrainPeersFromSnapshot(Vector<ProdigyBootstrapConfig::BootstrapPeer>& peers, const ProdigyPersistentBrainSnapshot& snapshot)
{
   peers.clear();

   if (snapshot.topology.machines.empty() == false)
   {
      prodigyAppendClusterTopologyBrainPeers(peers, snapshot.topology);
      return;
   }

   peers = snapshot.brainPeers;
}

static bool loadProdigyStartupState(const String& bootJSON, String& failure)
{
   bool explicitBootJSON = (bootJSON.size() > 0);

   ProdigyPersistentBootState storedBootState = {};
   String storedBootFailure;
   bool haveStoredBootState = persistentStateStore.loadBootState(storedBootState, &storedBootFailure);

   if (haveStoredBootState == false
      && storedBootFailure.size() > 0
      && storedBootFailure != "record not found"_ctv)
   {
      failure = storedBootFailure;
      return false;
   }

   persistentBootState = {};
   if (haveStoredBootState)
   {
      persistentBootState = storedBootState;
   }

   if (explicitBootJSON)
   {
      if (parseProdigyPersistentBootStateJSON(bootJSON, persistentBootState, &failure) == false)
      {
         return false;
      }

      if (persistentStateStore.saveBootState(persistentBootState, &failure) == false)
      {
         return false;
      }
   }
   else if (haveStoredBootState == false)
   {
      failure.assign("no boot json provided and no persistent boot state found"_ctv);
      return false;
   }

   effectiveBootstrapConfig = persistentBootState.bootstrapConfig;

   ProdigyPersistentBrainSnapshot storedBrainSnapshot = {};
   String storedSnapshotFailure;
   havePersistedBrainSnapshot = persistentStateStore.loadBrainSnapshot(storedBrainSnapshot, &storedSnapshotFailure);
   if (havePersistedBrainSnapshot == false
      && storedSnapshotFailure.size() > 0
      && storedSnapshotFailure != "record not found"_ctv)
   {
      failure = storedSnapshotFailure;
      return false;
   }

   if (havePersistedBrainSnapshot && explicitBootJSON == false)
   {
      prodigyReplaceCachedBrainSnapshot(persistedBrainSnapshot, std::move(storedBrainSnapshot));
      prodigyStripMachineHardwareCapturesFromClusterTopology(persistedBrainSnapshot.topology);

      Vector<ProdigyBootstrapConfig::BootstrapPeer> topologyPeers;
      prodigyAppendClusterTopologyBrainPeers(topologyPeers, persistedBrainSnapshot.topology);
      if (topologyPeers.empty() == false)
      {
         effectiveBootstrapConfig.bootstrapPeers = std::move(topologyPeers);
      }
      else if (persistedBrainSnapshot.brainPeers.empty() == false)
      {
         effectiveBootstrapConfig.bootstrapPeers = persistedBrainSnapshot.brainPeers;
      }

      if (persistentBootState.runtimeEnvironment.configured() == false
         && persistedBrainSnapshot.brainConfig.runtimeEnvironment.configured())
      {
         prodigyOwnRuntimeEnvironmentConfig(persistedBrainSnapshot.brainConfig.runtimeEnvironment, persistentBootState.runtimeEnvironment);
      }
   }
   else
   {
      havePersistedBrainSnapshot = false;

      ClusterTopology initialTopology = {};
      if (prodigyResolveInitialTopologyFromBootState(persistentBootState, initialTopology))
      {
         Vector<ProdigyBootstrapConfig::BootstrapPeer> topologyPeers;
         prodigyAppendClusterTopologyBrainPeers(topologyPeers, initialTopology);
         if (topologyPeers.empty() == false)
         {
            effectiveBootstrapConfig.bootstrapPeers = std::move(topologyPeers);
         }
      }
   }

   return true;
}

static bool loadOrUpdateLocalBrainState(const String& transportTLSJSONPath, String& failure)
{
   failure.clear();

   ProdigyPersistentLocalBrainState state = {};
   String loadFailure = {};
   bool haveLocalState = persistentStateStore.loadLocalBrainState(state, &loadFailure);
   if (haveLocalState == false
      && loadFailure.size() > 0
      && loadFailure != "record not found"_ctv)
   {
      failure = loadFailure;
      return false;
   }

   if (transportTLSJSONPath.size() > 0)
   {
      String json = {};
      String ownedTransportTLSJSONPath = {};
      ownedTransportTLSJSONPath.assign(transportTLSJSONPath);
      Filesystem::openReadAtClose(-1, ownedTransportTLSJSONPath, json);
      if (json.size() == 0)
      {
         failure.snprintf<"failed to read transport tls json path {}"_ctv>(transportTLSJSONPath);
         return false;
      }

      ProdigyPersistentLocalBrainState incoming = {};
      if (parseProdigyPersistentLocalBrainStateJSON(json, incoming, &failure) == false)
      {
         return false;
      }

      if (state.uuid != 0 && incoming.uuid != 0 && state.uuid != incoming.uuid)
      {
         failure.assign("transport tls uuid does not match existing local uuid"_ctv);
         return false;
      }

      if (state.uuid != 0 && incoming.uuid == 0)
      {
         incoming.uuid = state.uuid;
      }

      ProdigyPersistentLocalBrainState ownershipProbe = state;
      if (prodigyEnsureLocalBrainOwnedByCluster(ownershipProbe, incoming.ownerClusterUUID, nullptr, &failure) == false)
      {
         return false;
      }

      if (incoming.ownerClusterUUID == 0)
      {
         incoming.ownerClusterUUID = ownershipProbe.ownerClusterUUID;
      }

      if (incoming.transportTLS.configured() == false && state.transportTLS.configured())
      {
         incoming.transportTLS = state.transportTLS;
      }
      else if (incoming.transportTLS.clusterRootKeyPem.size() == 0 && state.transportTLS.clusterRootKeyPem.size() > 0)
      {
         incoming.transportTLS.clusterRootKeyPem = state.transportTLS.clusterRootKeyPem;
      }

      state = incoming;
      haveLocalState = true;
   }

   bool backfilledOwnerClusterUUID = false;
   if (havePersistedBrainSnapshot)
   {
      prodigyBackfillLocalBrainOwnerClusterUUID(state, persistedBrainSnapshot, &backfilledOwnerClusterUUID);
      haveLocalState = haveLocalState || backfilledOwnerClusterUUID;
   }

   if (state.uuid == 0)
   {
      state.uuid = Random::generateNumberWithNBits<128, uint128_t>();
      haveLocalState = true;
   }

   const ProdigyTransportTLSAuthority& persistedTransportAuthority = persistedBrainSnapshot.masterAuthority.runtimeState.transportTLSAuthority;
   if (persistedTransportAuthority.canMintForCluster())
   {
      bool localMatchesPersistedAuthority =
         state.transportTLS.canMintForCluster()
         && state.transportTLS.generation == persistedTransportAuthority.generation
         && state.transportTLS.clusterRootCertPem == persistedTransportAuthority.clusterRootCertPem
         && state.transportTLS.clusterRootKeyPem == persistedTransportAuthority.clusterRootKeyPem
         && state.transportTLS.localCertPem.size() > 0
         && state.transportTLS.localKeyPem.size() > 0;

      if (localMatchesPersistedAuthority == false)
      {
         if (prodigyApplyTransportTLSAuthorityToLocalState(state, persistedTransportAuthority, &failure) == false)
         {
            return false;
         }

         haveLocalState = true;
      }
   }

   auto configureSharedDevTransportTLS = [&] () -> bool {

      const char *sharedDirEnv = getenv("PRODIGY_DEV_SHARED_TRANSPORT_TLS_DIR");
      if (sharedDirEnv == nullptr || sharedDirEnv[0] == '\0')
      {
         return false;
      }

      std::error_code mkdirError;
      std::filesystem::create_directories(sharedDirEnv, mkdirError);
      if (mkdirError)
      {
         String sharedDirText = {};
         sharedDirText.assign(sharedDirEnv);
         failure.snprintf<"failed to create shared dev transport tls directory {}"_ctv>(sharedDirText);
         return false;
      }

      String sharedDir = {};
      sharedDir.assign(sharedDirEnv);

      String lockPath = {};
      lockPath.snprintf<"{}/cluster-root.lock"_ctv>(sharedDir);
      int lockFD = Filesystem::openFileAt(-1, lockPath, O_RDWR | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
      if (lockFD < 0)
      {
         failure.snprintf<"failed to open shared dev transport tls lock {}"_ctv>(lockPath);
         return false;
      }

      if (flock(lockFD, LOCK_EX) != 0)
      {
         close(lockFD);
         failure.snprintf<"failed to lock shared dev transport tls directory {}"_ctv>(sharedDir);
         return false;
      }

      String rootCertPath = {};
      rootCertPath.snprintf<"{}/cluster-root.pem"_ctv>(sharedDir);
      String rootKeyPath = {};
      rootKeyPath.snprintf<"{}/cluster-root.key.pem"_ctv>(sharedDir);

      String rootCertPem = {};
      String rootKeyPem = {};
      Filesystem::openReadAtClose(-1, rootCertPath, rootCertPem);
      Filesystem::openReadAtClose(-1, rootKeyPath, rootKeyPem);

      if (rootCertPem.size() == 0 || rootKeyPem.size() == 0)
      {
         if (Vault::generateTransportRootCertificateEd25519(rootCertPem, rootKeyPem, &failure) == false)
         {
            (void)flock(lockFD, LOCK_UN);
            close(lockFD);
            return false;
         }

         if (Filesystem::openWriteAtClose(-1, rootCertPath, rootCertPem) < 0
            || Filesystem::openWriteAtClose(-1, rootKeyPath, rootKeyPem) < 0)
         {
            (void)flock(lockFD, LOCK_UN);
            close(lockFD);
            failure.assign("failed to persist shared dev transport tls root"_ctv);
            return false;
         }
      }

      (void)flock(lockFD, LOCK_UN);
      close(lockFD);

      String localCertPem = {};
      String localKeyPem = {};
      if (Vault::generateTransportNodeCertificateEd25519(
            rootCertPem,
            rootKeyPem,
            state.uuid,
            {},
            localCertPem,
            localKeyPem,
            &failure) == false)
      {
         return false;
      }

      state.transportTLS.generation = 1;
      state.transportTLS.clusterRootCertPem = rootCertPem;
      if (effectiveBootstrapConfig.nodeRole == ProdigyBootstrapNodeRole::brain
         || persistentBootState.bootstrapConfig.nodeRole == ProdigyBootstrapNodeRole::brain)
      {
         state.transportTLS.clusterRootKeyPem = rootKeyPem;
      }
      state.transportTLS.localCertPem = localCertPem;
      state.transportTLS.localKeyPem = localKeyPem;
      haveLocalState = true;
      return true;
   };

   if (state.transportTLSConfigured() == false
      && effectiveBootstrapConfig.bootstrapPeers.size() > 1)
   {
      if (configureSharedDevTransportTLS())
      {
         // Shared dev bootstrap material is only used in isolated harness flows.
      }
      else if (failure.size() > 0)
      {
         return false;
      }
   }

   if (state.transportTLSConfigured() == false
      && persistentBootState.bootstrapConfig.nodeRole == ProdigyBootstrapNodeRole::brain
      && effectiveBootstrapConfig.bootstrapPeers.size() <= 1)
   {
      String rootCertPem = {};
      String rootKeyPem = {};
      if (Vault::generateTransportRootCertificateEd25519(rootCertPem, rootKeyPem, &failure) == false)
      {
         return false;
      }

      Vector<String> addresses;
      String localCertPem = {};
      String localKeyPem = {};
      if (Vault::generateTransportNodeCertificateEd25519(rootCertPem, rootKeyPem, state.uuid, addresses, localCertPem, localKeyPem, &failure) == false)
      {
         return false;
      }

      state.transportTLS.generation = 1;
      state.transportTLS.clusterRootCertPem = rootCertPem;
      state.transportTLS.clusterRootKeyPem = rootKeyPem;
      state.transportTLS.localCertPem = localCertPem;
      state.transportTLS.localKeyPem = localKeyPem;
      haveLocalState = true;
   }

   if (haveLocalState && persistentStateStore.saveLocalBrainState(state, &failure) == false)
   {
      return false;
   }

   if (state.transportTLSConfigured())
   {
      ProdigyTransportTLSBootstrap bootstrap = {};
      prodigyBuildTransportTLSBootstrap(state, bootstrap);
      if (ProdigyTransportTLSRuntime::configure(bootstrap, &failure) == false)
      {
         return false;
      }
   }
   else if (effectiveBootstrapConfig.bootstrapPeers.size() > 1)
   {
      failure.assign("transport tls state required for multi-node cluster startup"_ctv);
      return false;
   }

   persistentLocalBrainState = state;
   return true;
}

static bool prodigyClaimPersistentLocalClusterOwnership(uint128_t clusterUUID, String& failure)
{
   failure.clear();

   ProdigyPersistentLocalBrainState updatedState = persistentLocalBrainState;
   bool changed = false;
   if (prodigyEnsureLocalBrainOwnedByCluster(updatedState, clusterUUID, &changed, &failure) == false)
   {
      return false;
   }

   if (changed == false)
   {
      return true;
   }

   if (persistentStateStore.saveLocalBrainState(updatedState, &failure) == false)
   {
      return false;
   }

   persistentLocalBrainState = updatedState;
   return true;
}

class ProdigyBrain : public Brain
{
public:

   bool claimLocalClusterOwnership(uint128_t clusterUUID, String *failure = nullptr) override
   {
      String localFailure = {};
      bool claimed = prodigyClaimPersistentLocalClusterOwnership(clusterUUID, localFailure);
      if (failure)
      {
         *failure = localFailure;
      }

      return claimed;
   }

   bool applyPersistedTransportTLSAuthority(void)
   {
      const ProdigyTransportTLSAuthority& authority = masterAuthorityRuntimeState.transportTLSAuthority;
      if (authority.canMintForCluster() == false)
      {
         return true;
      }

      ProdigyTransportTLSAuthority currentAuthority = {};
      prodigyBuildTransportTLSAuthority(persistentLocalBrainState, currentAuthority);
      bool localMatchesAuthority =
         currentAuthority == authority
         && persistentLocalBrainState.transportTLS.localCertPem.size() > 0
         && persistentLocalBrainState.transportTLS.localKeyPem.size() > 0;
      if (localMatchesAuthority)
      {
         return true;
      }

      ProdigyPersistentLocalBrainState updatedLocalState = persistentLocalBrainState;
      String failure;
      if (prodigyApplyTransportTLSAuthorityToLocalState(updatedLocalState, authority, &failure) == false)
      {
         basics_log("ProdigyBrain transport tls authority apply failed: %s\n", failure.c_str());
         return false;
      }

      if (persistentStateStore.saveLocalBrainState(updatedLocalState, &failure) == false)
      {
         basics_log("ProdigyBrain local brain state persist failed: %s\n", failure.c_str());
         return false;
      }

      ProdigyTransportTLSBootstrap bootstrap = {};
      prodigyBuildTransportTLSBootstrap(updatedLocalState, bootstrap);
      if (ProdigyTransportTLSRuntime::configure(bootstrap, &failure) == false)
      {
         basics_log("ProdigyBrain transport tls runtime configure failed: %s\n", failure.c_str());
         return false;
      }

      persistentLocalBrainState = updatedLocalState;
      return true;
   }

   ProdigyPersistentBrainSnapshot buildPersistentBrainSnapshot(const ClusterTopology *topologyOverride = nullptr)
   {
      prodigyRuntimeTrace(
         "prodigy persist snapshot-build-begin topologyOverride=%d havePersistedBrainSnapshot=%d bootTopology=%zu machines=%zu brains=%zu\n",
         int(topologyOverride != nullptr),
         int(havePersistedBrainSnapshot),
         size_t(persistentBootState.initialTopology.machines.size()),
         size_t(machines.size()),
         size_t(brains.size()));

      ProdigyPersistentBrainSnapshot snapshot = {};
      snapshot.brainConfig = brainConfig;
      if (topologyOverride)
      {
         snapshot.topology = *topologyOverride;
      }
      else
      {
         const ClusterTopology *authoritativeTopology =
            (havePersistedBrainSnapshot && persistedBrainSnapshot.topology.machines.empty() == false)
            ? &persistedBrainSnapshot.topology
            : (persistentBootState.initialTopology.machines.empty() == false
               ? &persistentBootState.initialTopology
               : nullptr);

         if (authoritativeTopology != nullptr)
         {
            snapshot.topology = *authoritativeTopology;
         }
         else
         {
            ClusterTopology emptyTopology = {};
            snapshot.topology = prodigyCaptureClusterTopology(*this, emptyTopology);
         }
      }

      prodigyStripMachineHardwareCapturesFromClusterTopology(snapshot.topology);

      capturePersistentMasterAuthorityPackage(snapshot.masterAuthority);
      metrics.exportSamples(snapshot.metricSamples);

      if (snapshot.topology.machines.empty() == false)
      {
         prodigyAppendClusterTopologyBrainPeers(snapshot.brainPeers, snapshot.topology);
      }
      else
      {
         Vector<ProdigyBootstrapConfig::BootstrapPeer> peers;
         if (thisNeuron)
         {
            ProdigyBootstrapConfig::BootstrapPeer localPeer = {};
            localPeer.isBrain = true;
            ClusterMachinePeerAddress candidate = {};
            if (localBrainPeerAddress.isNull() == false)
            {
               if (localBrainPeerAddressText.size() > 0)
               {
                  candidate.address.assign(localBrainPeerAddressText);
               }
               else
               {
                  (void)ClusterMachine::renderIPAddressLiteral(localBrainPeerAddress, candidate.address);
               }
            }
            else
            {
               IPAddress selfAddress = {};
               selfAddress.v4 = thisNeuron->private4.v4;
               selfAddress.is6 = false;
               (void)ClusterMachine::renderIPAddressLiteral(selfAddress, candidate.address);
            }

            prodigyAppendUniqueClusterMachinePeerAddress(localPeer.addresses, candidate);
            prodigyAppendUniqueBootstrapPeer(peers, localPeer);
         }

         for (BrainView *brain : brains)
         {
            if (brain == nullptr)
            {
               continue;
            }

            ProdigyBootstrapConfig::BootstrapPeer peer = {};
            peer.isBrain = true;
            for (const ClusterMachinePeerAddress& candidate : brain->peerAddresses)
            {
               prodigyAppendUniqueClusterMachinePeerAddress(peer.addresses, candidate);
            }

            if (peer.addresses.empty())
            {
               ClusterMachinePeerAddress candidate = {};
               if (brain->peerAddressText.size() > 0)
               {
                  candidate.address.assign(brain->peerAddressText);
               }
               else if (ClusterMachine::renderIPAddressLiteral(brain->peerAddress, candidate.address) == false && brain->private4 != 0)
               {
                  IPAddress fallback = {};
                  fallback.v4 = brain->private4;
                  fallback.is6 = false;
                  (void)ClusterMachine::renderIPAddressLiteral(fallback, candidate.address);
               }

               prodigyAppendUniqueClusterMachinePeerAddress(peer.addresses, candidate);
            }

            prodigyAppendUniqueBootstrapPeer(peers, peer);
         }

         std::sort(peers.begin(), peers.end(), prodigyBootstrapPeerComesBefore);
         snapshot.brainPeers = peers;
      }

      prodigyRuntimeTrace(
         "prodigy persist snapshot-build-end topologyMachines=%zu brainPeers=%zu metricSamples=%zu\n",
         size_t(snapshot.topology.machines.size()),
         size_t(snapshot.brainPeers.size()),
         size_t(snapshot.metricSamples.size()));
      return snapshot;
   }

   bool persistBrainSnapshot(ProdigyPersistentBrainSnapshot snapshot)
   {
      prodigyRuntimeTrace(
         "prodigy persist brain-snapshot-begin topologyMachines=%zu brainPeers=%zu\n",
         size_t(snapshot.topology.machines.size()),
         size_t(snapshot.brainPeers.size()));
      prodigyDeriveBrainPeersFromSnapshot(snapshot.brainPeers, snapshot);

      String failure;
      if (persistentStateStore.saveBrainSnapshot(snapshot, &failure) == false)
      {
         basics_log("ProdigyBrain brain-snapshot persist failed: %s\n", failure.c_str());
         return false;
      }

      ProdigyPersistentBootState bootState = persistentBootState;
      bootState.bootstrapConfig = effectiveBootstrapConfig;
      bootState.bootstrapSshUser = brainConfig.bootstrapSshUser;
      bootState.bootstrapSshKeyPackage = brainConfig.bootstrapSshKeyPackage;
      bootState.bootstrapSshHostKeyPackage = brainConfig.bootstrapSshHostKeyPackage;
      bootState.bootstrapSshPrivateKeyPath = brainConfig.bootstrapSshPrivateKeyPath;
      if (snapshot.brainPeers.empty() == false)
      {
         bootState.bootstrapConfig.bootstrapPeers = snapshot.brainPeers;
      }
      bootState.runtimeEnvironment = brainConfig.runtimeEnvironment.configured()
         ? brainConfig.runtimeEnvironment
         : persistentBootState.runtimeEnvironment;
      bootState.initialTopology = {};

      if (persistentStateStore.saveBootState(bootState, &failure) == false)
      {
         basics_log("ProdigyBrain boot-state persist failed: %s\n", failure.c_str());
         return false;
      }

      persistentBootState = bootState;
      prodigyReplaceCachedBrainSnapshot(persistedBrainSnapshot, std::move(snapshot));
      havePersistedBrainSnapshot = true;
      prodigyRuntimeTrace(
         "prodigy persist brain-snapshot-end storedPeers=%zu bootPeers=%zu\n",
         size_t(persistedBrainSnapshot.brainPeers.size()),
         size_t(persistentBootState.bootstrapConfig.bootstrapPeers.size()));
      return true;
   }

   void configureCloudflareTunnel(String& mothershipEndpoint) override
   {
      mothershipEndpoint.clear();
   }

   void teardownCloudflareTunnel(void) override
   {
   }

   void respinApplication(ApplicationDeployment *deployment) override
   {
      Brain::respinApplication(deployment);
   }

   void pushSpinApplicationProgressToMothership(ApplicationDeployment *deployment, const String& message) override
   {
      Brain::pushSpinApplicationProgressToMothership(deployment, message);
   }

   void spinApplicationFailed(ApplicationDeployment *deployment, const String& message) override
   {
      Brain::spinApplicationFailed(deployment, message);
   }

   void spinApplicationFin(ApplicationDeployment *deployment) override
   {
      Brain::spinApplicationFin(deployment);
   }

   void onMasterAuthorityRuntimeStateApplied(void) override
   {
      (void)applyPersistedTransportTLSAuthority();
   }

   void persistLocalRuntimeState(void) override
   {
      prodigyRuntimeTrace("prodigy persist local-runtime-begin\n");
      ProdigyPersistentBrainSnapshot snapshot = buildPersistentBrainSnapshot();
      (void)persistBrainSnapshot(std::move(snapshot));
      prodigyRuntimeTrace("prodigy persist local-runtime-end\n");
   }

   ProdigyBrain()
   {
      if (havePersistedBrainSnapshot)
      {
         brainConfig = persistedBrainSnapshot.brainConfig;
         applyPersistentMasterAuthorityPackage(persistedBrainSnapshot.masterAuthority);
         metrics.importSamples(persistedBrainSnapshot.metricSamples);
      }

      prodigyBackfillBrainConfigSSHFromBootState(persistentBootState, brainConfig);

      if (masterAuthorityRuntimeState.transportTLSAuthority.canMintForCluster() == false
         && persistentLocalBrainState.canMintTransportTLS())
      {
         prodigyBuildTransportTLSAuthority(persistentLocalBrainState, masterAuthorityRuntimeState.transportTLSAuthority);
      }

      refreshMasterAuthorityRuntimeStateFromLiveFields();

      if (brainConfig.runtimeEnvironment.configured() == false)
      {
         prodigyOwnRuntimeEnvironmentConfig(persistentBootState.runtimeEnvironment, brainConfig.runtimeEnvironment);
      }

      iaas = new RuntimeAwareBrainIaaS(&persistentStateStore, effectiveBootstrapConfig, persistentBootState);
   }

   bool loadAuthoritativeClusterTopology(ClusterTopology& topology) const override
   {
      if (havePersistedBrainSnapshot && persistedBrainSnapshot.topology.machines.empty() == false)
      {
         topology = persistedBrainSnapshot.topology;
         return true;
      }

      return prodigyResolveInitialTopologyFromBootState(persistentBootState, topology);
   }

   bool persistAuthoritativeClusterTopology(const ClusterTopology& topology) override
   {
      ProdigyPersistentBrainSnapshot snapshot = buildPersistentBrainSnapshot(&topology);
      bool persisted = persistBrainSnapshot(std::move(snapshot));
      if (persisted)
      {
         sendNeuronSwitchboardOverlayRoutes();
      }

      return persisted;
   }
};

class ProdigyNeuron : public Neuron
{
public:

   ProdigyNeuron()
   {
      iaas = new RuntimeAwareNeuronIaaS(&persistentStateStore, effectiveBootstrapConfig, persistentBootState);
   }
};

int main(int argc, char *argv[])
{
   String bootJSON;
   String bootJSONPath;
   String transportTLSJSONPath;
   bool persistOnly = false;
   bool printBootState = false;
   bool resetBrainSnapshot = false;

   for (int i = 1; i < argc; ++i)
   {
      const char *arg = argv[i];

      if (std::strncmp(arg, "--netdev=", 9) == 0)
      {
         prodigySetPrimaryNetworkDeviceOverride(arg + 9);
      }
      else if (std::strncmp(arg, "--boot-json=", 12) == 0)
      {
         bootJSON.assign(arg + 12);
      }
      else if (std::strncmp(arg, "--boot-json-path=", 17) == 0)
      {
         bootJSONPath.assign(arg + 17);
      }
      else if (std::strcmp(arg, "--persist-only") == 0)
      {
         persistOnly = true;
      }
      else if (std::strncmp(arg, "--transport-tls-json-path=", 26) == 0)
      {
         transportTLSJSONPath.assign(arg + 26);
      }
      else if (std::strcmp(arg, "--reset-brain-snapshot") == 0)
      {
         resetBrainSnapshot = true;
      }
      else if (std::strcmp(arg, "--print-boot-state") == 0)
      {
         printBootState = true;
      }
   }

   String failure;
   if (bootJSON.size() == 0 && bootJSONPath.size() > 0 && prodigyReadTextFile(bootJSONPath, bootJSON, failure) == false)
   {
      std::fprintf(stderr, "failed to load prodigy boot json file: %s\n", failure.c_str());
      return EXIT_FAILURE;
   }

   if (loadProdigyStartupState(bootJSON, failure) == false)
   {
      std::fprintf(stderr, "failed to load prodigy startup state: %s\n", failure.c_str());
      return EXIT_FAILURE;
   }

   if (loadOrUpdateLocalBrainState(transportTLSJSONPath, failure) == false)
   {
      std::fprintf(stderr, "failed to load prodigy local brain state: %s\n", failure.c_str());
      return EXIT_FAILURE;
   }

   std::fprintf(stderr,
      "prodigy startup nodeRole=%s bootstrapPeers=%u controlSocketPath=%s havePersistedBrainSnapshot=%d runtimeConfigured=%d\n",
      prodigyBootstrapNodeRoleName(persistentBootState.bootstrapConfig.nodeRole),
      uint32_t(effectiveBootstrapConfig.bootstrapPeers.size()),
      effectiveBootstrapConfig.controlSocketPath.c_str(),
      int(havePersistedBrainSnapshot),
      int(persistentBootState.runtimeEnvironment.configured()));

   if (resetBrainSnapshot)
   {
      String removeFailure;
      if (persistentStateStore.removeBrainSnapshot(&removeFailure) == false && removeFailure != "record not found"_ctv)
      {
         std::fprintf(stderr, "failed to reset persistent brain snapshot: %s\n", removeFailure.c_str());
         return EXIT_FAILURE;
      }

      persistedBrainSnapshot = {};
      havePersistedBrainSnapshot = false;
      std::fprintf(stderr, "prodigy startup reset persistent brain snapshot\n");
   }

   if (persistOnly)
   {
      return EXIT_SUCCESS;
   }

   if (printBootState)
   {
      String renderedState;
      renderProdigyPersistentBootStateJSON(persistentBootState, renderedState, true);
      (void)std::fwrite(renderedState.data(), 1, size_t(renderedState.size()), stdout);
      (void)std::fputc('\n', stdout);
      (void)std::fflush(stdout);
      return EXIT_SUCCESS;
   }

   if (prodigyEnforceDevHostNetnsIsolation(failure) == false)
   {
      std::fprintf(stderr, "%s\n", failure.c_str());
      return EXIT_FAILURE;
   }

   setenv("PRODIGY_MOTHERSHIP_SOCKET", effectiveBootstrapConfig.controlSocketPath.c_str(), 1);

   Prodigy<ProdigyNeuron, ProdigyBrain> prodigy;
   prodigy.prepare(argc, argv);
   prodigy.start();
   return EXIT_SUCCESS;
}
