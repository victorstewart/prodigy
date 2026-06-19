#include <prodigy/prodigy.h>
#include <limits.h>
#include <services/debug.h>
#include <prodigy/brain/brain.h>
#include <prodigy/dev/tests/prodigy_test_ssh_keys.h>

#include <cstdlib>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <unistd.h>

class TestSuite {
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    if (condition)
    {
      basics_log("PASS: %s\n", name);
    }
    else
    {
      basics_log("FAIL: %s\n", name);
      dprintf(STDERR_FILENO, "FAIL: %s\n", name);
      failed += 1;
    }
  }

  void expect(bool condition, const std::string& name)
  {
    expect(condition, name.c_str());
  }

  bool require(bool condition, const char *name)
  {
    expect(condition, name);
    return condition;
  }

  bool require(bool condition, const std::string& name)
  {
    return require(condition, name.c_str());
  }
};

static std::string testName(const char *prefix, const char *suffix)
{
  std::string name = (prefix != nullptr) ? prefix : "";
  if (name.empty() == false && suffix != nullptr && suffix[0] != '\0')
  {
    name.push_back('_');
  }
  if (suffix != nullptr)
  {
    name.append(suffix);
  }
  return name;
}

class TestBrain : public Brain {
public:

  uint32_t persistCalls = 0;
  uint32_t masterAuthorityApplyCalls = 0;
  uint32_t clusterOwnershipCalls = 0;
  uint128_t lastClaimedClusterUUID = 0;
  bool rejectClusterOwnership = false;
  String rejectClusterOwnershipFailure = {};
  uint32_t transitionToNewBundleCalls = 0;
  uint32_t systemContainerStoreCalls = 0;
  uint32_t mothershipTunnelRuntimeStartCalls = 0;
  uint32_t mothershipTunnelRuntimeStopCalls = 0;
  bool mothershipTunnelRuntimeStartSucceeds = false;
  String lastStoredSystemContainerSha256 = {};
  uint64_t lastStoredSystemContainerBytes = 0;
  String lastStoredSystemContainerBlob = {};
  MothershipTunnelProviderSpec lastMothershipTunnelProviderSpec = {};
  MothershipTunnelGatewayAuth lastMothershipTunnelProviderGatewayAuth = {};
  String lastMothershipTunnelProviderArtifactBlob = {};
  uint128_t nextMothershipTunnelProviderContainerUUID = 0x77070001;
  uint128_t lastStoppedMothershipTunnelProviderContainerUUID = 0;

  void configureMothershipControlIngress(String& mothershipEndpoint) override
  {
    mothershipEndpoint.assign("127.0.0.1"_ctv);
  }

  void teardownMothershipControlIngress(void) override
  {
  }

  void armMachineNeuronControl(Machine *machine) override
  {
    (void)machine;
  }

  void pushSpinApplicationProgressToMothership(ApplicationDeployment *deployment, const String& message) override
  {
    (void)deployment;
    (void)message;
  }

  void spinApplicationFailed(ApplicationDeployment *deployment, const String& message) override
  {
    (void)deployment;
    (void)message;
  }

  void persistLocalRuntimeState(void) override
  {
    persistCalls += 1;
  }

  bool storeSystemContainerArtifact(const String& sha256, uint64_t bytes, const String& blob, String *failure = nullptr) override
  {
    systemContainerStoreCalls += 1;
    lastStoredSystemContainerSha256 = sha256;
    lastStoredSystemContainerBytes = bytes;
    lastStoredSystemContainerBlob = blob;
    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  bool systemContainerArtifactPresent(const String& sha256, uint64_t bytes) override
  {
    return lastStoredSystemContainerSha256.equal(sha256) && lastStoredSystemContainerBytes == bytes;
  }

  bool loadSystemContainerArtifact(const String& sha256, uint64_t bytes, String& blob, String *failure = nullptr) override
  {
    if (systemContainerArtifactPresent(sha256, bytes) == false)
    {
      blob.clear();
      if (failure)
      {
        failure->assign("tunnel provider artifact missing from system store"_ctv);
      }
      return false;
    }

    blob = lastStoredSystemContainerBlob;
    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  bool startMothershipTunnelProviderRuntime(const MothershipTunnelProviderSpec& spec, const MothershipTunnelGatewayAuth& gatewayAuth, const String& artifactBlob, uint128_t& containerUUID, String *failure = nullptr) override
  {
    mothershipTunnelRuntimeStartCalls += 1;
    lastMothershipTunnelProviderSpec = spec;
    lastMothershipTunnelProviderGatewayAuth = gatewayAuth;
    lastMothershipTunnelProviderArtifactBlob = artifactBlob;
    if (mothershipTunnelRuntimeStartSucceeds == false)
    {
      containerUUID = 0;
      if (failure)
      {
        failure->assign("injected tunnel runtime launch failure"_ctv);
      }
      return false;
    }

    containerUUID = nextMothershipTunnelProviderContainerUUID;
    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  void stopMothershipTunnelProviderRuntime(uint128_t containerUUID) override
  {
    mothershipTunnelRuntimeStopCalls += 1;
    lastStoppedMothershipTunnelProviderContainerUUID = containerUUID;
  }

  void transitionToNewBundle(void) override
  {
    transitionToNewBundleCalls += 1;
  }

  bool claimLocalClusterOwnership(uint128_t clusterUUID, String *failure = nullptr) override
  {
    clusterOwnershipCalls += 1;
    lastClaimedClusterUUID = clusterUUID;
    if (rejectClusterOwnership)
    {
      if (failure)
      {
        if (rejectClusterOwnershipFailure.size() > 0)
        {
          *failure = rejectClusterOwnershipFailure;
        }
        else
        {
          failure->assign("cluster ownership rejected"_ctv);
        }
      }

      return false;
    }

    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  void onMasterAuthorityRuntimeStateApplied(void) override
  {
    masterAuthorityApplyCalls += 1;
  }

  void queueBrainPeerLargePayloadKeepaliveForTest(BrainView *brain)
  {
    queueBrainPeerLargePayloadKeepalive(brain);
  }

  void setBrainPeerKeepaliveSecondsForTest(uint32_t seconds)
  {
    brainPeerKeepaliveSeconds = seconds;
  }

  void queueAcceptedBrainPeerSocketOptionsForTest(BrainView *brain)
  {
    queueAcceptedBrainPeerSocketOptions(brain);
  }

  bool shouldReplaceActivePeerWithAcceptedStreamForTest(BrainView *brain, bool expectedUpdateFollowerReconnect) const
  {
    return shouldReplaceActivePeerWithAcceptedStream(brain, expectedUpdateFollowerReconnect);
  }

  bool machineReadyForHealthyStateForTest(Machine *machine) const
  {
    return machineReadyForHealthyState(machine);
  }

  void refreshNeuronControlHandshakeWatchdogForTest(NeuronView *neuron, const char *reason)
  {
    refreshNeuronControlHandshakeWatchdog(neuron, reason);
  }

  void refreshBrainPeerHandshakeWatchdogForTest(BrainView *brain, const char *reason)
  {
    refreshBrainPeerHandshakeWatchdog(brain, reason);
  }

  TimeoutPacket *neuronControlHandshakeWatchdogForTest(NeuronView *neuron)
  {
    if (auto it = neuronHandshakeWaiters.find(neuron); it != neuronHandshakeWaiters.end())
    {
      return it->second;
    }

    return nullptr;
  }

  TimeoutPacket *brainPeerHandshakeWatchdogForTest(BrainView *brain)
  {
    if (auto it = brainHandshakeWaiters.find(brain); it != brainHandshakeWaiters.end())
    {
      return it->second;
    }

    return nullptr;
  }

  void queueBrainDeploymentReplicationForTest(const String& serializedPlan, const String& containerBlob)
  {
    queueBrainDeploymentReplication(serializedPlan, containerBlob);
  }

  void queueBrainSystemContainerArtifactReplicationForTest(const String& sha256, uint64_t bytes, const String& blob)
  {
    queueBrainSystemContainerArtifactReplication(sha256, bytes, blob);
  }

  Machine *findMachineByUUIDForTest(uint128_t uuid)
  {
    if (auto it = machinesByUUID.find(uuid); it != machinesByUUID.end())
    {
      return it->second;
    }

    return nullptr;
  }
};

class TestDNSProvider final : public ProdigyDNSProvider {
public:

  uint32_t upsertCalls = 0;
  uint32_t removeCalls = 0;
  uint32_t presentTXTCalls = 0;
  uint32_t cleanupTXTCalls = 0;
  bool failUpsert = false;
  bool failRemove = false;
  Vector<ProdigyDNSRecordBinding> upserts;
  Vector<ProdigyDNSRecordBinding> removes;
  Vector<ProdigyDNSRecordBinding> presentedTXT;
  Vector<ProdigyDNSRecordBinding> cleanedTXT;
  Vector<ProdigyDNSRecordBinding> activeTXT;
  String lastCredentialMaterial;

  bool supportsProvider(const String& provider) const override
  {
    return routableResourceDNSPartEquals(provider, "cloudflare"_ctv, false);
  }

  bool upsert(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    upsertCalls += 1;
    upserts.push_back(record);
    lastCredentialMaterial = credential.material;
    if (failUpsert)
    {
      failure.assign("injected DNS upsert failure"_ctv);
      return false;
    }
    failure.clear();
    return true;
  }

  bool remove(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    (void)credential;
    removeCalls += 1;
    removes.push_back(record);
    if (failRemove)
    {
      failure.assign("injected DNS remove failure"_ctv);
      return false;
    }
    failure.clear();
    return true;
  }

  bool presentTXT(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    presentTXTCalls += 1;
    presentedTXT.push_back(record);
    lastCredentialMaterial = credential.material;
    if (failUpsert)
    {
      failure.assign("injected DNS upsert failure"_ctv);
      return false;
    }
    String value = {};
    if (prodigyDNSRecordSingleTXTValue(record, value, failure) == false)
    {
      return false;
    }
    bool exists = false;
    for (const ProdigyDNSRecordBinding& active : activeTXT)
    {
      exists = exists || (routableResourceDNSPartEquals(active.name, record.name, true) && active.values.size() == 1 && active.values[0].equals(value));
    }
    if (exists == false)
    {
      activeTXT.push_back(record);
    }
    failure.clear();
    return true;
  }

  bool cleanupTXT(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    (void)credential;
    cleanupTXTCalls += 1;
    cleanedTXT.push_back(record);
    if (failRemove)
    {
      failure.assign("injected DNS remove failure"_ctv);
      return false;
    }
    String value = {};
    if (prodigyDNSRecordSingleTXTValue(record, value, failure) == false)
    {
      return false;
    }
    for (auto it = activeTXT.begin(); it != activeTXT.end();)
    {
      if (routableResourceDNSPartEquals(it->name, record.name, true) && it->values.size() == 1 && it->values[0].equals(value))
      {
        it = activeTXT.erase(it);
      }
      else
      {
        ++it;
      }
    }
    failure.clear();
    return true;
  }
};

class PairingTrackingContainerView : public ContainerView {
public:

  uint32_t subscriptionActivateCalls = 0;
  uint32_t subscriptionDeactivateCalls = 0;
  uint128_t lastSubscriptionAddress = 0;
  uint64_t lastSubscriptionService = 0;
  uint16_t lastSubscriptionPort = 0;
  uint16_t lastSubscriptionApplicationID = 0;

  void subscriptionPairing(uint128_t secret, uint128_t address, uint64_t service, uint16_t port, uint16_t applicationID, bool activate) override
  {
    (void)secret;
    lastSubscriptionAddress = address;
    lastSubscriptionService = service;
    lastSubscriptionPort = port;
    lastSubscriptionApplicationID = applicationID;

    if (activate)
    {
      subscriptionActivateCalls += 1;
    }
    else
    {
      subscriptionDeactivateCalls += 1;
    }
  }
};

class StreamingTestBrain final : public TestBrain {
public:

  void pushSpinApplicationProgressToMothership(ApplicationDeployment *deployment, const String& message) override
  {
    Mothership *stream = spinApplicationMothershipFor(deployment);
    if (streamIsActive(stream))
    {
      Message::construct(
          stream->wBuffer,
          MothershipTopic::spinApplication,
          uint8_t(SpinApplicationResponseCode::progress),
          message);
    }
  }

  void spinApplicationFailed(ApplicationDeployment *deployment, const String& message) override
  {
    Mothership *stream = spinApplicationMothershipFor(deployment);
    if (streamIsActive(stream))
    {
      Message::construct(
          stream->wBuffer,
          MothershipTopic::spinApplication,
          uint8_t(SpinApplicationResponseCode::failed),
          message);
    }

    clearSpinApplicationMothership(deployment);
  }

  void spinApplicationFin(ApplicationDeployment *deployment) override
  {
    Mothership *stream = spinApplicationMothershipFor(deployment);
    if (streamIsActive(stream) == false)
    {
      return;
    }

    Message::construct(
        stream->wBuffer,
        MothershipTopic::spinApplication,
        uint8_t(SpinApplicationResponseCode::finished));
    clearSpinApplicationMothership(deployment);
  }
};

class ResumableAddMachinesBrain : public TestBrain {
public:

  mutable Vector<ClusterMachine> bootstrappedMachines;
  mutable Vector<ClusterMachine> stoppedMachines;
  mutable uint32_t blockingBootstrapCallsWithBundleCache = 0;
  mutable uint32_t blockingBootstrapCallsWithoutBundleCache = 0;
  ClusterTopology authoritativeTopology = {};
  bool failBootstrap = false;

  bool loadAuthoritativeClusterTopology(ClusterTopology& topology) const override
  {
    topology = authoritativeTopology;
    return true;
  }

  bool persistAuthoritativeClusterTopology(const ClusterTopology& topology) override
  {
    authoritativeTopology = topology;
    persistCalls += 1;
    return true;
  }

  bool bootstrapClusterMachineBlocking(
      const ClusterMachine& clusterMachine,
      const AddMachines& request,
      const ClusterTopology& topology,
      String& failure,
      ProdigyRemoteBootstrapBundleApprovalCache *bundleApprovalCache = nullptr) const override
  {
    (void)request;
    (void)topology;
    if (bundleApprovalCache != nullptr)
    {
      blockingBootstrapCallsWithBundleCache += 1;
    }
    else
    {
      blockingBootstrapCallsWithoutBundleCache += 1;
    }

    if (failBootstrap)
    {
      failure.assign("bootstrap failed"_ctv);
      return false;
    }

    bootstrappedMachines.push_back(clusterMachine);
    return true;
  }

  void stopClusterMachineBootstrap(const ClusterMachine& clusterMachine) const override
  {
    stoppedMachines.push_back(clusterMachine);
  }
};

class AsyncQueuedAddMachinesBrain final : public ResumableAddMachinesBrain {
public:

  mutable Vector<ClusterMachine> asyncQueuedMachines;

  bool canSuspendRemoteBootstrap(void) const override
  {
    return true;
  }

  bool queueClusterMachineBootstrapAsync(
      ProdigyRemoteBootstrapCoordinator& coordinator,
      ProdigyRemoteBootstrapBundleApprovalCache& bundleApprovalCache,
      const ClusterMachine& clusterMachine,
      const AddMachines& request,
      const ClusterTopology& topology,
      String& failure) const override
  {
    (void)coordinator;
    (void)bundleApprovalCache;
    (void)request;
    (void)topology;
    failure.clear();
    asyncQueuedMachines.push_back(clusterMachine);
    return true;
  }
};

static Machine *cloneMachineSnapshot(const Machine& source);

class NoopBrainIaaS : public BrainIaaS {
public:

  void boot(void) override {}

  void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) override
  {
    (void)coro;
    (void)lifetime;
    (void)config;
    (void)count;
    (void)newMachines;
    error.clear();
  }

  void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines) override
  {
    (void)coro;
    (void)metro;
    (void)machines;
  }

  void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains) override
  {
    (void)coro;
    (void)selfUUID;
    (void)brains;
    selfIsBrain = false;
  }

  void hardRebootMachine(uint128_t uuid) override
  {
    (void)uuid;
  }

  void reportHardwareFailure(uint128_t uuid, const String& report) override
  {
    (void)uuid;
    (void)report;
  }

  void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
  {
    (void)coro;
    (void)decommissionedIDs;
  }

  void destroyMachine(Machine *machine) override
  {
    (void)machine;
  }

  uint32_t supportedMachineKindsMask() const override
  {
    return 0;
  }
};

class TrackingBrainIaaS final : public NoopBrainIaaS {
public:

  uint32_t hardRebootCalls = 0;
  uint32_t reportHardwareFailureCalls = 0;
  uint32_t destroyCalls = 0;
  uint128_t lastHardRebootUUID = 0;
  uint128_t lastReportedHardwareFailureUUID = 0;
  uint128_t lastDestroyedUUID = 0;
  String lastHardwareFailureReport = {};

  void hardRebootMachine(uint128_t uuid) override
  {
    hardRebootCalls += 1;
    lastHardRebootUUID = uuid;
  }

  void reportHardwareFailure(uint128_t uuid, const String& report) override
  {
    reportHardwareFailureCalls += 1;
    lastReportedHardwareFailureUUID = uuid;
    lastHardwareFailureReport = report;
  }

  void destroyMachine(Machine *machine) override
  {
    destroyCalls += 1;
    lastDestroyedUUID = (machine ? machine->uuid : 0);
  }
};

class ElasticPrefixBrainIaaS final : public NoopBrainIaaS {
public:

  uint32_t assignCalls = 0;
  uint32_t releaseCalls = 0;
  Machine *lastMachine = nullptr;
  ExternalAddressFamily lastFamily = ExternalAddressFamily::ipv4;
  ElasticPrefixIntent lastIntent = ElasticPrefixIntent::create;
  String lastRequestedAddress = {};
  String lastProviderPool = {};
  DistributableExternalSubnet lastReleased = {};

  bool assignProviderElasticAddress(Machine *machine,
                                    ExternalAddressFamily family,
                                    ElasticPrefixIntent intent,
                                    const String& requestedAddress,
                                    const String& providerPool,
                                    IPPrefix& assignedPrefix,
                                    IPPrefix& deliveryPrefix,
                                    String& allocationID,
                                    String& associationID,
                                    bool& releaseOnRemove,
                                    String& error) override
  {
    assignCalls += 1;
    lastMachine = machine;
    lastFamily = family;
    lastIntent = intent;
    lastRequestedAddress.assign(requestedAddress);
    lastProviderPool.assign(providerPool);
    assignedPrefix = IPPrefix("198.51.100.88", false, 32);
    deliveryPrefix = IPPrefix("10.0.0.88", false, 32);
    allocationID.assign("alloc-88"_ctv);
    associationID.assign("assoc-88"_ctv);
    releaseOnRemove = true;
    error.clear();
    return true;
  }

  bool releaseProviderElasticAddress(const DistributableExternalSubnet& prefix, String& error) override
  {
    releaseCalls += 1;
    lastReleased = prefix;
    error.clear();
    return true;
  }
};

class AutoProvisionBrainIaaS final : public BrainIaaS {
public:

  uint32_t spinCalls = 0;
  uint32_t destroyCalls = 0;
  uint32_t acceptedCallbacks = 0;
  uint32_t provisionedCallbacks = 0;
  Vector<Machine *> snapshotsToReturn;
  Vector<Machine *> inventorySnapshots;
  Vector<String> destroyedCloudIDs;
  BrainIaaSMachineProvisioningProgressSink *progressSink = nullptr;
  ResumableAddMachinesBrain *observedBrain = nullptr;
  const Vector<ClusterMachine> *observedAsyncQueuedMachines = nullptr;
  bool sawPendingOperationDuringSpin = false;
  bool sawBootstrapDuringSpin = false;

  void boot(void) override {}

  void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) override
  {
    (void)coro;
    (void)lifetime;
    (void)config;
    (void)count;

    spinCalls += 1;
    error.clear();
    for (Machine *snapshot : snapshotsToReturn)
    {
      if (snapshot != nullptr && progressSink != nullptr)
      {
        progressSink->reportMachineProvisioningAccepted(snapshot->cloudID);
        acceptedCallbacks += 1;
        if (observedBrain != nullptr && observedBrain->masterAuthorityRuntimeState.pendingAddMachinesOperations.empty() == false)
        {
          sawPendingOperationDuringSpin = true;
        }

        progressSink->reportMachineProvisioned(*snapshot);
        provisionedCallbacks += 1;
        if ((observedBrain != nullptr && observedBrain->bootstrappedMachines.empty() == false) || (observedAsyncQueuedMachines != nullptr && observedAsyncQueuedMachines->empty() == false))
        {
          sawBootstrapDuringSpin = true;
        }
      }

      newMachines.insert(snapshot);
    }

    snapshotsToReturn.clear();
  }

  void configureProvisioningProgressSink(BrainIaaSMachineProvisioningProgressSink *sink) override
  {
    progressSink = sink;
  }

  void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines) override
  {
    (void)coro;
    (void)metro;
    for (Machine *snapshot : inventorySnapshots)
    {
      if (snapshot != nullptr)
      {
        machines.insert(cloneMachineSnapshot(*snapshot));
      }
    }
  }

  void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains) override
  {
    (void)coro;
    (void)selfUUID;
    (void)brains;
    selfIsBrain = false;
  }

  void hardRebootMachine(uint128_t uuid) override
  {
    (void)uuid;
  }

  void reportHardwareFailure(uint128_t uuid, const String& report) override
  {
    (void)uuid;
    (void)report;
  }

  void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
  {
    (void)coro;
    (void)decommissionedIDs;
  }

  void destroyMachine(Machine *machine) override
  {
    destroyCalls += 1;
    if (machine != nullptr)
    {
      destroyedCloudIDs.push_back(machine->cloudID);
    }
  }

  uint32_t supportedMachineKindsMask() const override
  {
    return 2u;
  }

  bool supportsAutoProvision() const override
  {
    return true;
  }

  bool supportsIncrementalProvisioningCallbacks() const override
  {
    return true;
  }
};

class NoopNeuronIaaS final : public NeuronIaaS {
public:

  void gatherSelfData(uint128_t& uuid, String& metro, bool& isBrain, EthDevice& eth, IPAddress& private4) override
  {
    uuid = 0;
    metro.clear();
    isBrain = false;
    (void)eth;
    private4 = {};
  }

  void downloadContainerToPath(CoroutineStack *coro, uint64_t deploymentID, const String& path) override
  {
    (void)coro;
    (void)deploymentID;
    (void)path;
  }
};

class TestNeuron final : public Neuron {
public:

  using DeferredHardwareInventoryResult = Neuron::DeferredHardwareInventoryResult;
  using ContainerMetricSampleState = Neuron::ContainerMetricSampleState;

  NoopNeuronIaaS localIaaS;
  bool failAcceptedBrainTransportTLSForTest = false;
  uint32_t refreshContainerSwitchboardWormholesCallsForTest = 0;
  uint32_t syncContainerSwitchboardRuntimeCallsForTest = 0;
  uint32_t popContainerCallsForTest = 0;
  uint32_t startOSUpdateCallsForTest = 0;
  String lastOSUpdateTargetOSIDForTest = {};
  String lastOSUpdateTargetOSVersionIDForTest = {};
  String lastOSUpdateCommandForTest = {};
  bool failOSUpdateStartForTest = false;
  uint128_t lastRefreshedContainerUUIDForTest = 0;
  Vector<Wormhole> lastRefreshedWormholesForTest = {};
  uint128_t lastSyncedContainerUUIDForTest = 0;
  uint128_t lastPoppedContainerUUIDForTest = 0;

  TestNeuron()
  {
    iaas = &localIaaS;
  }

  void pushContainer(Container *container) override
  {
    (void)container;
  }

  void popContainer(Container *container) override
  {
    if (container == nullptr)
    {
      return;
    }

    popContainerCallsForTest += 1;
    lastPoppedContainerUUIDForTest = container->plan.uuid;
    containers.erase(container->plan.uuid);
    if (container->pid > 0)
    {
      containerByPid.erase(container->pid);
    }
  }

  bool ensureHostNetworkingReady(String *failureReport = nullptr) override
  {
    if (failureReport)
    {
      failureReport->clear();
    }
    return true;
  }

  void downloadContainer(CoroutineStack *coro, uint64_t deploymentID) override
  {
    (void)coro;
    (void)deploymentID;
  }

  bool startOperatingSystemUpdate(const String& targetOSID, const String& targetOSVersionID, const String& updateCommand, String *failure = nullptr) override
  {
    startOSUpdateCallsForTest += 1;
    lastOSUpdateTargetOSIDForTest = targetOSID;
    lastOSUpdateTargetOSVersionIDForTest = targetOSVersionID;
    lastOSUpdateCommandForTest = updateCommand;
    if (failOSUpdateStartForTest)
    {
      if (failure)
      {
        failure->assign("injected OS update failure"_ctv);
      }
      return false;
    }

    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  void seedRegistrationState(int64_t bootMs, const String& kernelVersion, bool haveFragment, const String& reportedOSID = {}, const String& reportedOSVersionID = {})
  {
    bootTimeMs = bootMs;
    kernel = kernelVersion;
    osID = reportedOSID;
    osVersionID = reportedOSVersionID;
    lcsubnet6 = {};
    lcsubnet6.dpfx = haveFragment ? 1 : 0;
  }

  void seedLocalContainerSubnetForTest(uint8_t datacenterFragment, uint32_t machineFragment)
  {
    lcsubnet6 = {};
    lcsubnet6.dpfx = datacenterFragment;
    lcsubnet6.mpfx[0] = uint8_t((machineFragment >> 16) & 0xffu);
    lcsubnet6.mpfx[1] = uint8_t((machineFragment >> 8) & 0xffu);
    lcsubnet6.mpfx[2] = uint8_t(machineFragment & 0xffu);
  }

  void appendInitialFramesForTest(String& outbound)
  {
    (void)appendInitialBrainControlFrames(outbound);
  }

  static bool parseOSReleaseMetadataForTest(const String& osRelease, String& parsedOSID, String& parsedOSVersionID)
  {
    return Neuron::parseOSReleaseMetadata(osRelease, parsedOSID, parsedOSVersionID);
  }

  void seedBrainStreamForTest(bool connected)
  {
    if (brain != nullptr)
    {
      delete brain;
    }

    brain = new NeuronBrainControlStream();
    brain->isFixedFile = true;
    brain->fslot = 1;
    brain->connected = connected;
  }

  void seedStaleBrainStreamForTest(void)
  {
    seedBrainStreamForTest(false);
    if (brain != nullptr)
    {
      brain->isFixedFile = false;
      brain->fslot = -1;
      brain->fd = -1;
      brain->connected = false;
    }
  }

  void setBrainStreamConnectedForTest(bool connected)
  {
    if (brain != nullptr)
    {
      brain->connected = connected;
    }
  }

  void seedBrainStreamSocketForTest(int fd, bool connected)
  {
    seedBrainStreamForTest(connected);
    if (brain != nullptr)
    {
      brain->isFixedFile = false;
      brain->fd = fd;
      brain->rBuffer.reserve(8_KB);
      brain->wBuffer.reserve(16_KB);
    }
  }

  static void seedContainerSocketForTest(
      Container& container,
      uint128_t uuid,
      int fd,
      uint32_t rBufferCapacity = 8_KB,
      uint32_t wBufferCapacity = 8_KB)
  {
    container.plan.uuid = uuid;
    container.fd = fd;
    container.isFixedFile = false;
    if (rBufferCapacity > 0)
    {
      container.rBuffer.reserve(rBufferCapacity);
    }
    if (wBufferCapacity > 0)
    {
      container.wBuffer.reserve(wBufferCapacity);
    }
  }

  NeuronBrainControlStream *brainStreamForTest(void) const
  {
    return brain;
  }

  template <typename Dispatch>
  void recvBrainForTest(int result, Dispatch&& dispatch)
  {
    recvHandler(brain, result, std::forward<Dispatch>(dispatch));
  }

  void dispatchBrainMessageForTest(Message *message)
  {
    neuronHandler(message);
  }

  void sendBrainForTest(int result)
  {
    sendHandler(brain, result);
  }

  bool queueMachineHardwareProfileToBrainIfReadyForTest(const char *reason)
  {
    return queueMachineHardwareProfileToBrainIfReady(reason);
  }

  bool brainInitialMachineHardwareProfileQueuedForTest(void) const
  {
    return brain != nullptr && brain->initialMachineHardwareProfileQueued;
  }

  String& brainOutboundForTest(void)
  {
    return brain->wBuffer;
  }

  void adoptHardwareInventoryForTest(const MachineHardwareProfile& hardware, const String& serialized)
  {
    DeferredHardwareInventoryResult result = {};
    result.hardware = hardware;
    result.serializedHardwareProfile = serialized;
    adoptDeferredHardwareInventoryResult(std::move(result));
  }

  bool deferredHardwareInventoryReadyForAdoptionForTest(const MachineHardwareProfile& hardware, const String& serialized)
  {
    DeferredHardwareInventoryResult result = {};
    result.hardware = hardware;
    result.serializedHardwareProfile = serialized;
    return deferredHardwareInventoryResultReadyForAdoption(result);
  }

  void seedDeferredHardwareInventoryReadyForTest(const MachineHardwareProfile& hardware, const String& serialized)
  {
    DeferredHardwareInventoryResult result = {};
    result.hardware = hardware;
    result.serializedHardwareProfile = serialized;

    std::lock_guard<std::mutex> lock(deferredHardwareInventoryMutex);
    deferredHardwareInventoryReady = std::move(result);
    deferredHardwareInventoryInFlight = true;
  }

  void setDeferredHardwareInventoryInFlightForTest(bool inFlight)
  {
    std::lock_guard<std::mutex> lock(deferredHardwareInventoryMutex);
    deferredHardwareInventoryInFlight = inFlight;
  }

  bool completeDeferredHardwareInventoryIfReadyForTest(void)
  {
    return completeDeferredHardwareInventoryIfReady();
  }

  void deliverDeferredHardwareInventoryWakeForTest(void)
  {
    pollHandler(&deferredHardwareInventoryWake, POLLIN);
  }

  void pollDeferredHardwareInventoryWakeForTest(int result)
  {
    pollHandler(&deferredHardwareInventoryWake, result);
  }

  void seedOverlayRoutingConfigForTest(const SwitchboardOverlayRoutingConfig& config)
  {
    overlayRoutingConfig = config;
  }

  void syncOverlayRoutingProgramsForTest(void)
  {
    syncOverlayRoutingPrograms();
  }

  void ensureSwitchboardForTest(void)
  {
    (void)ensureSwitchboard();
  }

  void refreshContainerSwitchboardWormholes(Container *container) override
  {
    refreshContainerSwitchboardWormholesCallsForTest += 1;
    lastRefreshedContainerUUIDForTest = 0;
    lastRefreshedWormholesForTest.clear();
    if (container != nullptr)
    {
      lastRefreshedContainerUUIDForTest = container->plan.uuid;
      lastRefreshedWormholesForTest = container->plan.wormholes;
    }

    Neuron::refreshContainerSwitchboardWormholes(container);
  }

  void syncContainerSwitchboardRuntime(Container *container) override
  {
    syncContainerSwitchboardRuntimeCallsForTest += 1;
    lastSyncedContainerUUIDForTest = (container ? container->plan.uuid : uint128_t(0));
    Neuron::syncContainerSwitchboardRuntime(container);
  }

  uint32_t installedIngressOverlayPrefixes4CountForTest(void) const
  {
    return installedIngressOverlayPrefixes4.size();
  }

  uint32_t installedIngressOverlayPrefixes6CountForTest(void) const
  {
    return installedIngressOverlayPrefixes6.size();
  }

  uint32_t installedEgressOverlayPrefixes4CountForTest(void) const
  {
    return installedEgressOverlayPrefixes4.size();
  }

  uint32_t installedEgressOverlayPrefixes6CountForTest(void) const
  {
    return installedEgressOverlayPrefixes6.size();
  }

  uint32_t installedOverlayRouteKeysFullCountForTest(void) const
  {
    return installedOverlayRouteKeysFull.size();
  }

  uint32_t installedOverlayRouteKeysLow8CountForTest(void) const
  {
    return installedOverlayRouteKeysLow8.size();
  }

  void seedLocalContainerSubnetForTest(const local_container_subnet6& subnet)
  {
    lcsubnet6 = subnet;
  }

  uint32_t generateLocalContainerIDForTest(uint8_t fragment) const
  {
    return generateLocalContainerID(fragment);
  }

  void openLocalWhiteholesForTest(uint32_t containerID, const Vector<Whitehole>& whiteholes)
  {
    openLocalWhiteholes(containerID, whiteholes);
  }

  void closeLocalWhiteholesToContainerForTest(uint32_t containerID)
  {
    closeLocalWhiteholesToContainer(containerID);
  }

  uint32_t localWhiteholeBindingCountForContainerForTest(uint32_t containerID)
  {
    if (auto it = whiteholeBindingsByContainer.find(containerID); it != whiteholeBindingsByContainer.end())
    {
      return it->second.size();
    }

    return 0;
  }

  uint32_t installedWhiteholeBindingCountForTest(void) const
  {
    return installedEgressWhiteholeBindingKeys.size();
  }

  bool resolveOptionalHostRouterBPFPathsForTest(String& hostIngressPath, String& hostEgressPath, String *failureReport = nullptr) const
  {
    return resolveOptionalHostRouterBPFPaths(hostIngressPath, hostEgressPath, failureReport);
  }

  bool armBrainListenerForTest(void)
  {
    brainListener.setIPVersion(AF_INET);
    brainListener.setKeepaliveTimeoutSeconds(brainControlKeepaliveSeconds);
    brainListener.setSaddr(IPAddress("127.0.0.1", false), 0);
    brainListener.bindThenListen();
    Ring::installFDIntoFixedFileSlot(&brainListener);
    return (brainListener.isFixedFile && brainListener.fslot >= 0);
  }

  void queueBrainAcceptForTest(void)
  {
    queueBrainAccept();
  }

  void acceptBrainForTest(int fslot)
  {
    acceptHandler(&brainListener, fslot);
  }

  void setFailAcceptedBrainTransportTLSForTest(bool fail)
  {
    failAcceptedBrainTransportTLSForTest = fail;
  }

  bool brainListenerFixedForTest(void) const
  {
    return brainListener.isFixedFile && brainListener.fslot >= 0;
  }

  void queueContainerDownloadRequestForTest(uint64_t deploymentID)
  {
    Neuron::downloadContainer(nullptr, deploymentID);
  }

  uint64_t activeMetricsMaskForTest(const Container *container) const
  {
    return activeMetricsMask(container);
  }

  uint32_t normalizedMetricsCadenceMsForTest(const Container *container) const
  {
    return normalizedMetricsCadenceMs(container);
  }

  void registerContainerForTest(Container *container)
  {
    containers.insert_or_assign(container->plan.uuid, container);
  }

  void pushContainerForTest(Container *container)
  {
    if (container == nullptr)
    {
      return;
    }

    containers.insert_or_assign(container->plan.uuid, container);
    if (container->pid > 0)
    {
      containerByPid.insert_or_assign(container->pid, container);
    }

    if (container->plan.wormholes.empty() == false)
    {
      refreshContainerSwitchboardWormholes(container);
    }
  }

  void unregisterContainerForTest(uint128_t uuid)
  {
    containers.erase(uuid);
  }

  void connectContainerForTest(Container *container, int result)
  {
    connectHandler(container, result);
  }

  void closeSocketForTest(void *socket)
  {
    closeHandler(socket);
  }

  void waitContainerForTest(Container *container)
  {
    waitidHandler(container);
  }

  void recvSocketForTest(void *socket, int result)
  {
    recvHandler(socket, result);
  }

  void sendSocketForTest(void *socket, int result)
  {
    sendHandler(socket, result);
  }

  uint32_t minimumActiveMetricsCadenceMsForTest(void) const
  {
    return minimumActiveMetricsCadenceMs();
  }

  void ensureMetricsTickQueuedForTest(void)
  {
    ensureMetricsTickQueued();
  }

  bool metricsTickQueuedForTest(void) const
  {
    return metricsTickQueued;
  }

  uint64_t metricsTickFlagsForTest(void) const
  {
    return metricsTick.flags;
  }

  int64_t metricsTickTimeoutMsForTest(void)
  {
    return metricsTick.timeoutMs();
  }

  void ensureFailedContainerArtifactGCTickQueuedForTest(void)
  {
    ensureFailedContainerArtifactGCTickQueued();
  }

  bool failedContainerArtifactGCTickQueuedForTest(void) const
  {
    return failedContainerArtifactGCTickQueued;
  }

  uint64_t failedContainerArtifactGCTickFlagsForTest(void) const
  {
    return failedContainerArtifactGCTick.flags;
  }

  int64_t failedContainerArtifactGCTickTimeoutMsForTest(void)
  {
    return failedContainerArtifactGCTick.timeoutMs();
  }

  void timeoutFailedContainerArtifactGCTickForTest(int result)
  {
    timeoutHandler(&failedContainerArtifactGCTick, result);
  }

  static bool parseUnsignedDecimalForTest(const String& text, uint64_t& value)
  {
    return parseUnsignedDecimal(text, value);
  }

  static bool extractCpuUsageUsecForTest(const String& cpuStat, uint64_t& usageUsec)
  {
    return extractCpuUsageUsec(cpuStat, usageUsec);
  }

  static bool approximateDirectoryUsageBytesForTest(const String& path, uint64_t& usageBytes)
  {
    return approximateDirectoryUsageBytes(path, usageBytes);
  }

  static bool readContainerCpuUsageUsecForTest(const Container *container, uint64_t& usageUsec)
  {
    return readContainerCpuUsageUsec(container, usageUsec);
  }

  static bool readContainerMemoryCurrentBytesForTest(const Container *container, uint64_t& memoryCurrentBytes)
  {
    return readContainerMemoryCurrentBytes(container, memoryCurrentBytes);
  }

  static bool sampleContainerCpuUtilPctForTest(Container *container, ContainerMetricSampleState& sampleState, uint64_t sampleTimeNs, uint64_t& utilPct)
  {
    return sampleContainerCpuUtilPct(container, sampleState, sampleTimeNs, utilPct);
  }

  static bool sampleContainerMemoryUtilPctForTest(const Container *container, uint64_t& utilPct)
  {
    return sampleContainerMemoryUtilPct(container, utilPct);
  }

  static bool sampleContainerStorageUtilPctForTest(const Container *container, uint64_t& utilPct)
  {
    return sampleContainerStorageUtilPct(container, utilPct);
  }

  void collectContainerMetricsAndForwardForTest(uint64_t sampleTimeNs)
  {
    collectContainerMetricsAndForward(sampleTimeNs);
  }

  void queuePendingAdvertisementPayloadForTest(uint128_t containerUUID, const String& payload)
  {
    uint8_t *start = payload.data();
    queuePendingPairing(pendingAdvertisementPairings, containerUUID, start, start + payload.size());
  }

  void queuePendingSubscriptionPayloadForTest(uint128_t containerUUID, const String& payload)
  {
    uint8_t *start = payload.data();
    queuePendingPairing(pendingSubscriptionPairings, containerUUID, start, start + payload.size());
  }

  void queuePendingCredentialRefreshPayloadForTest(uint128_t containerUUID, uint32_t limitPerContainer, const String& payload)
  {
    queuePendingPayload(pendingCredentialRefreshes, containerUUID, limitPerContainer, payload);
  }

  uint32_t pendingAdvertisementPayloadCountForTest(uint128_t containerUUID)
  {
    if (auto it = pendingAdvertisementPairings.find(containerUUID); it != pendingAdvertisementPairings.end())
    {
      return it->second.size();
    }

    return 0;
  }

  uint32_t pendingSubscriptionPayloadCountForTest(uint128_t containerUUID)
  {
    if (auto it = pendingSubscriptionPairings.find(containerUUID); it != pendingSubscriptionPairings.end())
    {
      return it->second.size();
    }

    return 0;
  }

  uint32_t pendingCredentialRefreshPayloadCountForTest(uint128_t containerUUID)
  {
    if (auto it = pendingCredentialRefreshes.find(containerUUID); it != pendingCredentialRefreshes.end())
    {
      return it->second.size();
    }

    return 0;
  }

  void applyPendingPairingsForTest(Container *container)
  {
    applyPendingPairings(container);
  }

  void applyPendingCredentialRefreshesForTest(Container *container)
  {
    applyPendingCredentialRefreshes(container);
  }

  bool isTrackedContainerSocketForTest(void *socket) const
  {
    return isTrackedContainerSocket(socket);
  }

  template <typename T>
  static bool extractFixedArgBoundedForTest(uint8_t *& cursor, uint8_t *terminal, T& value)
  {
    return extractFixedArgBounded(cursor, terminal, value);
  }

  void timeoutHandlerForTest(TimeoutPacket *packet, int result)
  {
    timeoutHandler(packet, result);
  }

  void timeoutMetricsTickForTest(int result)
  {
    timeoutHandler(&metricsTick, result);
  }

  static bool rawBrainStreamIsActiveForTest(NeuronBrainControlStream *stream)
  {
    return rawStreamIsActive(stream);
  }

  static bool rawContainerStreamIsActiveForTest(Container *stream)
  {
    return rawStreamIsActive(stream);
  }

  static bool brainStreamIsClosingForTest(NeuronBrainControlStream *stream)
  {
    return Ring::socketIsClosing(stream);
  }

  static bool containerStreamIsClosingForTest(Container *stream)
  {
    return Ring::socketIsClosing(stream);
  }

  static bool brainStreamIsActiveForTest(NeuronBrainControlStream *stream)
  {
    return streamIsActive(stream);
  }

  static bool containerStreamIsActiveForTest(Container *stream)
  {
    return streamIsActive(stream);
  }

  static void queueCloseBrainStreamIfActiveForTest(NeuronBrainControlStream *stream)
  {
    queueCloseIfActive(stream);
  }

  static void queueCloseContainerStreamIfActiveForTest(Container *stream)
  {
    queueCloseIfActive(stream);
  }

  static bool verifyBrainTransportTLSPeerForTest(TestNeuron& neuron)
  {
    return neuron.verifyBrainTransportTLSPeer();
  }

  const MachineHardwareProfile *latestHardwareProfileIfReadyForTest(void) const
  {
    return latestHardwareProfileIfReady();
  }

  void seedHardwareProfileForTest(const MachineHardwareProfile& hardware, const String& serialized)
  {
    hardwareProfile = hardware;
    serializedHardwareProfile = serialized;
  }

  bool appendMachineHardwareProfileFrameIfReadyForTest(String& outbound)
  {
    return appendMachineHardwareProfileFrameIfReady(outbound);
  }

  static void serializeMachineHardwareProfileForBrainTransportForTest(const MachineHardwareProfile& hardware, String& serialized)
  {
    serializeMachineHardwareProfileForBrainTransport(hardware, serialized);
  }

  void ensureDeferredHardwareInventoryProgressForTest(void)
  {
    ensureDeferredHardwareInventoryProgress();
  }

  bool deferredHardwareInventoryInFlightForTest(void) const
  {
    return deferredHardwareInventoryInFlight;
  }

  bool deferredHardwareInventoryWakePollQueuedForTest(void) const
  {
    return deferredHardwareInventoryWakePollQueued;
  }

  void setDeferredHardwareInventoryWakeFDForTest(int fd)
  {
    deferredHardwareInventoryWake.fd = fd;
  }

  void armDeferredHardwareInventoryWakePollForTest(void)
  {
    armDeferredHardwareInventoryWakePoll();
  }

  void drainDeferredHardwareInventoryWakeForTest(void)
  {
    drainDeferredHardwareInventoryWake();
  }

protected:

  bool beginAcceptedBrainTransportTLS(NeuronBrainControlStream *stream) override
  {
    if (failAcceptedBrainTransportTLSForTest)
    {
      return false;
    }

    return Neuron::beginAcceptedBrainTransportTLS(stream);
  }
};

class ScopedRing final {
public:

  bool created = false;

  ScopedRing()
  {
    if (Ring::getRingFD() <= 0)
    {
      Ring::createRing(8, 8, 64, 32, -1, -1, 0);
      created = true;
    }
  }

  ~ScopedRing()
  {
    if (created)
    {
      Ring::shutdownForExec();
    }
  }
};

class ScopedFreshRing final {
public:

  bool hadRing = false;
  RingLifecycle *savedLifecycler = nullptr;

  ScopedFreshRing()
  {
    hadRing = (Ring::getRingFD() > 0);
    savedLifecycler = hadRing ? Ring::lifecycler : nullptr;
    if (hadRing)
    {
      Ring::shutdownForExec();
    }

    Ring::lifecycler = nullptr;
    Ring::createRing(8, 8, 64, 32, -1, -1, 0);
  }

  ~ScopedFreshRing()
  {
    Ring::shutdownForExec();
    Ring::lifecycler = savedLifecycler;
    if (hadRing)
    {
      Ring::createRing(8, 8, 64, 32, -1, -1, 0);
    }
  }
};

class ScopedSocketPair final {
public:

  int left = -1;
  int right = -1;

  ~ScopedSocketPair()
  {
    if (left >= 0)
    {
      close(left);
    }
    if (right >= 0)
    {
      close(right);
    }
  }

  bool create(TestSuite& suite, const char *name)
  {
    int sockets[2] = {-1, -1};
    bool created = (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockets) == 0);
    suite.expect(created, name);
    if (created == false)
    {
      if (sockets[0] >= 0)
      {
        close(sockets[0]);
      }
      if (sockets[1] >= 0)
      {
        close(sockets[1]);
      }
      return false;
    }

    left = sockets[0];
    right = sockets[1];
    return true;
  }

  bool create(TestSuite& suite, const std::string& name)
  {
    return create(suite, name.c_str());
  }

  int takeLeft(void)
  {
    int fd = left;
    left = -1;
    return fd;
  }

  int takeRight(void)
  {
    int fd = right;
    right = -1;
    return fd;
  }

  int adoptLeftIntoFixedFileSlot(void)
  {
    if (left < 0)
    {
      return -1;
    }

    int fslot = Ring::adoptProcessFDIntoFixedFileSlot(left);
    if (fslot >= 0)
    {
      left = -1;
    }

    return fslot;
  }
};

class ScopedEventFD final {
public:

  int fd = -1;

  ~ScopedEventFD()
  {
    if (fd >= 0)
    {
      close(fd);
    }
  }

  bool create(TestSuite& suite, const char *name)
  {
    fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    suite.expect(fd >= 0, name);
    return (fd >= 0);
  }

  bool create(TestSuite& suite, const std::string& name)
  {
    return create(suite, name.c_str());
  }

  int take(void)
  {
    int value = fd;
    fd = -1;
    return value;
  }
};

enum class BrainTransportTLSPeerMode : uint8_t {
  validUUID,
  missingUUID
};

static bool configureTransportRuntimeForNode(
    uint128_t nodeUUID,
    const String& rootCertPem,
    const String& rootKeyPem,
    const String& localCertPem,
    const String& localKeyPem,
    String *failure);
static bool generateTransportPeerCertificateWithoutUUID(
    const String& rootCertPem,
    const String& rootKeyPem,
    const Vector<String>& ipAddresses,
    String& certPem,
    String& keyPem,
    String *failure);
static void reserveTransportStream(ProdigyTransportTLSStream& stream);
static bool completeTransportHandshake(ProdigyTransportTLSStream& client, ProdigyTransportTLSStream& server, uint32_t maxRounds);

class BrainTransportTLSFixture final {
public:

  ScopedFreshRing scopedRing = {};
  ScopedSocketPair sockets = {};
  TestNeuron neuron = {};
  ProdigyTransportTLSStream brainClient = {};
  bool ready = false;
  int neuronBrainFD = -1;

  BrainTransportTLSFixture(
      TestSuite& suite,
      const char *prefix,
      uint128_t brainUUID,
      uint128_t neuronUUID,
      const char *brainAddress,
      const char *neuronAddress,
      BrainTransportTLSPeerMode peerMode = BrainTransportTLSPeerMode::validUUID,
      bool useDirectSocket = false)
      : prefix(prefix ? prefix : "")
  {
    ProdigyTransportTLSRuntime::clear();

    neuron.seedRegistrationState(24'681'357, "6.8.0-test"_ctv, false);
    if (useDirectSocket)
    {
      if (sockets.create(suite, testName(prefix, "creates_socketpair")) == false)
      {
        return;
      }

      neuronBrainFD = sockets.takeLeft();
      neuron.seedBrainStreamSocketForTest(neuronBrainFD, true);
    }
    else
    {
      neuron.seedBrainStreamForTest(true);
    }

    if (suite.require(neuron.brainStreamForTest() != nullptr, testName(prefix, "seeds_brain_stream")) == false)
    {
      return;
    }

    if (suite.require(Vault::generateTransportRootCertificateEd25519(rootCertPem, rootKeyPem, &failure), testName(prefix, "generate_root")) == false)
    {
      return;
    }

    Vector<String> brainAddresses = {};
    brainAddresses.push_back(String(brainAddress));
    if (peerMode == BrainTransportTLSPeerMode::validUUID)
    {
      if (suite.require(
              Vault::generateTransportNodeCertificateEd25519(
                  rootCertPem,
                  rootKeyPem,
                  brainUUID,
                  brainAddresses,
                  brainCertPem,
                  brainKeyPem,
                  &failure),
              testName(prefix, "generate_brain_leaf")) == false)
      {
        return;
      }
    }
    else
    {
      if (suite.require(
              generateTransportPeerCertificateWithoutUUID(
                  rootCertPem,
                  rootKeyPem,
                  brainAddresses,
                  brainCertPem,
                  brainKeyPem,
                  &failure),
              testName(prefix, "generate_peer_leaf")) == false)
      {
        return;
      }
    }

    Vector<String> neuronAddresses = {};
    neuronAddresses.push_back(String(neuronAddress));
    if (suite.require(
            Vault::generateTransportNodeCertificateEd25519(
                rootCertPem,
                rootKeyPem,
                neuronUUID,
                neuronAddresses,
                neuronCertPem,
                neuronKeyPem,
                &failure),
            testName(prefix, "generate_neuron_leaf")) == false)
    {
      return;
    }

    reserveTransportStream(brainClient);
    reserveTransportStream(*neuron.brainStreamForTest());

    if (suite.require(
            configureTransportRuntimeForNode(
                brainUUID,
                rootCertPem,
                rootKeyPem,
                brainCertPem,
                brainKeyPem,
                &failure),
            testName(prefix, "configure_client_runtime")) == false)
    {
      return;
    }

    if (suite.require(brainClient.beginTransportTLS(false), testName(prefix, "begin_client")) == false)
    {
      return;
    }

    if (suite.require(
            configureTransportRuntimeForNode(
                neuronUUID,
                rootCertPem,
                rootKeyPem,
                neuronCertPem,
                neuronKeyPem,
                &failure),
            testName(prefix, "configure_server_runtime")) == false)
    {
      return;
    }

    if (suite.require(neuron.brainStreamForTest()->beginTransportTLS(true), testName(prefix, "begin_server")) == false)
    {
      return;
    }

    ready = true;
  }

  ~BrainTransportTLSFixture()
  {
    ProdigyTransportTLSRuntime::clear();
    if (neuronBrainFD >= 0)
    {
      close(neuronBrainFD);
    }
  }

  bool completeHandshake(TestSuite& suite, const char *suffix = "complete_handshake")
  {
    if (ready == false)
    {
      return false;
    }

    return suite.require(
        ::completeTransportHandshake(brainClient, *neuron.brainStreamForTest(), 128),
        testName(prefix.c_str(), suffix));
  }

private:

  std::string prefix;
  String failure = {};
  String rootCertPem = {};
  String rootKeyPem = {};
  String brainCertPem = {};
  String brainKeyPem = {};
  String neuronCertPem = {};
  String neuronKeyPem = {};
};

// Keep socket/TLS fixture setup centralized in the shared helpers here.
// New fd-heavy neuron tests should extend these fixtures instead of inlining
// ad hoc `socketpair(...)` / `eventfd(...)` ownership and seed logic.

class BrainSocketFixture final {
public:

  ScopedFreshRing scopedRing = {};
  ScopedSocketPair sockets = {};
  TestNeuron neuron = {};
  int brainFD = -1;
  bool ready = false;

  BrainSocketFixture(TestSuite& suite, const char *prefix, bool connected = true)
  {
    if (sockets.create(suite, testName(prefix, "creates_socketpair")) == false)
    {
      return;
    }

    brainFD = sockets.takeLeft();
    neuron.seedBrainStreamSocketForTest(brainFD, connected);
    ready = suite.require(neuron.brainStreamForTest() != nullptr, testName(prefix, "seeds_brain_stream"));
  }

  ~BrainSocketFixture()
  {
    if (brainFD >= 0)
    {
      close(brainFD);
    }
  }
};

class ContainerSocketFixture final {
public:

  ScopedFreshRing scopedRing = {};
  ScopedSocketPair sockets = {};
  TestNeuron neuron = {};
  Container container = {};
  bool tracked = false;
  bool ready = false;

  ContainerSocketFixture(
      TestSuite& suite,
      const char *prefix,
      uint128_t containerUUID,
      bool registerContainer = true,
      int fd = std::numeric_limits<int>::min(),
      uint32_t rBufferCapacity = 8_KB,
      uint32_t wBufferCapacity = 8_KB)
  {
    if (fd == std::numeric_limits<int>::min())
    {
      if (sockets.create(suite, testName(prefix, "creates_socketpair")) == false)
      {
        return;
      }

      fd = sockets.takeLeft();
    }

    TestNeuron::seedContainerSocketForTest(container, containerUUID, fd, rBufferCapacity, wBufferCapacity);
    if (registerContainer)
    {
      neuron.registerContainerForTest(&container);
      tracked = true;
    }

    ready = true;
  }

  ~ContainerSocketFixture()
  {
    if (tracked)
    {
      neuron.unregisterContainerForTest(container.plan.uuid);
    }

    if (container.isFixedFile == false && container.fd >= 0)
    {
      close(container.fd);
      container.fd = -1;
    }
  }
};

class BrainContainerFixture final {
public:

  BrainSocketFixture brain;
  ScopedEventFD containerEvent = {};
  Container container = {};
  bool tracked = false;
  bool ready = false;

  BrainContainerFixture(
      TestSuite& suite,
      const char *prefix,
      uint128_t containerUUID,
      bool active = true,
      bool registerContainer = true,
      bool pendingDestroy = false)
      : brain(suite, prefix)
  {
    if (brain.ready == false)
    {
      return;
    }

    container.plan.uuid = containerUUID;
    container.fd = -1;
    container.isFixedFile = false;
    container.pendingDestroy = pendingDestroy;
    container.wBuffer.reserve(4_KB);

    if (active)
    {
      if (containerEvent.create(suite, testName(prefix, "creates_container_eventfd")) == false)
      {
        return;
      }

      container.fd = containerEvent.take();
    }

    if (registerContainer)
    {
      brain.neuron.registerContainerForTest(&container);
      tracked = true;
    }

    ready = true;
  }

  ~BrainContainerFixture()
  {
    if (tracked)
    {
      brain.neuron.unregisterContainerForTest(container.plan.uuid);
    }

    if (container.isFixedFile == false && container.fd >= 0)
    {
      close(container.fd);
      container.fd = -1;
    }
  }
};

static bool seedBrainInboundForTest(TestSuite& suite, TestNeuron& neuron, const char *prefix, const String& inbound)
{
  NeuronBrainControlStream *brain = neuron.brainStreamForTest();
  if (suite.require(brain != nullptr, testName(prefix, "has_brain_stream")) == false)
  {
    return false;
  }

  std::memcpy(brain->rBuffer.pTail(), inbound.data(), inbound.size());
  brain->pendingRecv = true;
  return true;
}

static uint32_t recvAndDispatchBrainForTest(TestNeuron& neuron, int bytes)
{
  uint32_t dispatchCount = 0;
  neuron.recvBrainForTest(bytes, [&](Message *message) {
    dispatchCount += 1;
    neuron.dispatchBrainMessageForTest(message);
  });
  return dispatchCount;
}

class ScopedTempDir final {
public:

  std::filesystem::path path;

  ScopedTempDir()
  {
    char pattern[] = "/tmp/prodigy-neuron-XXXXXX";
    if (char *created = ::mkdtemp(pattern))
    {
      path = created;
    }
  }

  ~ScopedTempDir()
  {
    if (path.empty() == false)
    {
      std::error_code error;
      std::filesystem::remove_all(path, error);
    }
  }

  bool valid(void) const
  {
    return path.empty() == false;
  }
};

static bool writeTextFile(const std::filesystem::path& path, const std::string& contents)
{
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output.is_open())
  {
    return false;
  }

  output.write(contents.data(), std::streamsize(contents.size()));
  return output.good();
}

static std::string toStdString(const String& text)
{
  return std::string(reinterpret_cast<const char *>(text.data()), text.size());
}

static bool writeSizedFile(const std::filesystem::path& path, uint64_t bytes)
{
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output.is_open())
  {
    return false;
  }

  std::string block(4096, 'x');
  while (bytes > 0)
  {
    uint64_t chunk = std::min<uint64_t>(bytes, block.size());
    output.write(block.data(), std::streamsize(chunk));
    if (!output.good())
    {
      return false;
    }

    bytes -= chunk;
  }

  return true;
}

template <typename... Args>
static Message *buildBrainMessage(String& buffer, BrainTopic topic, Args&&...args)
{
  buffer.clear();
  Message::construct(buffer, topic, std::forward<Args>(args)...);
  return reinterpret_cast<Message *>(buffer.data());
}

template <typename... Args>
static Message *buildMothershipMessage(String& buffer, MothershipTopic topic, Args&&...args)
{
  buffer.clear();
  Message::construct(buffer, topic, std::forward<Args>(args)...);
  return reinterpret_cast<Message *>(buffer.data());
}

static bool pullClusterStatusReportForTest(TestBrain& brain, ClusterStatusReport& report)
{
  Mothership mothership;
  String buffer;
  brain.mothershipHandler(&mothership, buildMothershipMessage(buffer, MothershipTopic::pullClusterReport));

  if (mothership.wBuffer.size() < sizeof(Message))
  {
    return false;
  }
  Message *response = reinterpret_cast<Message *>(mothership.wBuffer.data());
  if (MothershipTopic(response->topic) != MothershipTopic::pullClusterReport)
  {
    return false;
  }

  String serializedReport = {};
  uint8_t *responseArgs = response->args;
  Message::extractToStringView(responseArgs, serializedReport);
  return BitseryEngine::deserializeSafe(serializedReport, report);
}

template <typename... Args>
static Message *buildNeuronMessage(String& buffer, NeuronTopic topic, Args&&...args)
{
  buffer.clear();
  Message::construct(buffer, topic, std::forward<Args>(args)...);
  return reinterpret_cast<Message *>(buffer.data());
}

static Message *buildNeuronContainerPackedMessage(String& buffer, NeuronTopic topic, uint128_t containerUUID, const String& payload)
{
  buffer.clear();
  uint32_t headerOffset = Message::appendHeader(buffer, topic);
  Message::append(buffer, containerUUID);
  if (payload.size() > 0)
  {
    Message::append<Alignment::one>(
        buffer,
        reinterpret_cast<const uint8_t *>(payload.data()),
        uint32_t(payload.size()));
  }
  Message::finish(buffer, headerOffset);
  return reinterpret_cast<Message *>(buffer.data());
}

static Message *buildNeuronRawPayloadMessage(String& buffer, NeuronTopic topic, const String& payload)
{
  buffer.clear();
  uint32_t headerOffset = Message::appendHeader(buffer, topic);
  if (payload.size() > 0)
  {
    Message::append<Alignment::one>(
        buffer,
        reinterpret_cast<const uint8_t *>(payload.data()),
        uint32_t(payload.size()));
  }
  Message::finish(buffer, headerOffset);
  constexpr uint32_t headerBytes = Message::headerBytes;
  uint32_t logicalSize = headerBytes + uint32_t(payload.size());
  Message *message = reinterpret_cast<Message *>(buffer.data());
  message->size = logicalSize;
  message->padding = 0;
  buffer.resize(logicalSize);
  return reinterpret_cast<Message *>(buffer.data());
}

template <typename... Args>
static Message *buildContainerMessage(String& buffer, ContainerTopic topic, Args&&...args)
{
  buffer.clear();
  Message::construct(buffer, topic, std::forward<Args>(args)...);
  return reinterpret_cast<Message *>(buffer.data());
}

template <typename Handler>
static void forEachMessageInBuffer(String& buffer, Handler&& handler)
{
  uint8_t *cursor = buffer.data();
  uint8_t *end = buffer.data() + buffer.size();

  while (cursor < end)
  {
    Message *message = reinterpret_cast<Message *>(cursor);
    if (message->size == 0)
    {
      break;
    }

    handler(message);
    cursor += message->size;
  }
}

template <typename T>
static bool equalSerializedObjects(const T& lhs, const T& rhs)
{
  String serializedLhs = {};
  String serializedRhs = {};
  T mutableLhs = lhs;
  T mutableRhs = rhs;
  BitseryEngine::serialize(serializedLhs, mutableLhs);
  BitseryEngine::serialize(serializedRhs, mutableRhs);
  return serializedLhs.equals(serializedRhs);
}

static IPPrefix makePrefix(const char *cidr)
{
  const char *slash = std::strrchr(cidr, '/');
  if (slash == nullptr)
  {
    std::fprintf(stderr, "unable to parse cidr: %s\n", cidr);
    std::abort();
  }

  String addressText = {};
  addressText.assign(cidr, uint64_t(slash - cidr));

  IPPrefix prefix = {};
  if (ClusterMachine::parseIPAddressLiteral(addressText, prefix.network) == false)
  {
    std::fprintf(stderr, "unable to parse cidr address: %s\n", cidr);
    std::abort();
  }

  prefix.cidr = uint8_t(std::strtoul(slash + 1, nullptr, 10));
  return prefix;
}

static Machine *makeMachineSnapshot(const String& schema, const String& privateAddress, const String& cloudID, uint128_t uuid)
{
  Machine *snapshot = new Machine();
  snapshot->slug = schema;
  snapshot->type = schema;
  snapshot->cloudID = cloudID;
  snapshot->sshAddress = privateAddress;
  snapshot->sshUser = "root"_ctv;
  snapshot->sshPrivateKeyPath = "/tmp/test-key"_ctv;
  snapshot->privateAddress = privateAddress;
  snapshot->publicAddress = privateAddress;
  String privateAddressText = {};
  privateAddressText.assign(privateAddress);
  snapshot->private4 = IPAddress(privateAddressText.c_str(), false).v4;
  snapshot->uuid = uuid;
  snapshot->rackUUID = 7;
  snapshot->creationTimeMs = 111;
  return snapshot;
}

static Machine *cloneMachineSnapshot(const Machine& source)
{
  Machine *snapshot = new Machine();
  snapshot->slug = source.slug;
  snapshot->type = source.type;
  snapshot->cloudID = source.cloudID;
  snapshot->sshAddress = source.sshAddress;
  snapshot->sshPort = source.sshPort;
  snapshot->sshUser = source.sshUser;
  snapshot->sshPrivateKeyPath = source.sshPrivateKeyPath;
  snapshot->privateAddress = source.privateAddress;
  snapshot->publicAddress = source.publicAddress;
  snapshot->peerAddresses = source.peerAddresses;
  snapshot->private4 = source.private4;
  snapshot->gatewayPrivate4 = source.gatewayPrivate4;
  snapshot->uuid = source.uuid;
  snapshot->rackUUID = source.rackUUID;
  snapshot->creationTimeMs = source.creationTimeMs;
  snapshot->hasInternetAccess = source.hasInternetAccess;
  snapshot->osID = source.osID;
  snapshot->osVersionID = source.osVersionID;
  snapshot->currentImageURI = source.currentImageURI;
  snapshot->hardware = source.hardware;
  snapshot->lifetime = source.lifetime;
  snapshot->isBrain = source.isBrain;
  snapshot->topologySource = source.topologySource;
  snapshot->ownershipMode = source.ownershipMode;
  snapshot->ownershipLogicalCoresCap = source.ownershipLogicalCoresCap;
  snapshot->ownershipMemoryMBCap = source.ownershipMemoryMBCap;
  snapshot->ownershipStorageMBCap = source.ownershipStorageMBCap;
  snapshot->ownershipLogicalCoresBasisPoints = source.ownershipLogicalCoresBasisPoints;
  snapshot->ownershipMemoryBasisPoints = source.ownershipMemoryBasisPoints;
  snapshot->ownershipStorageBasisPoints = source.ownershipStorageBasisPoints;
  snapshot->totalLogicalCores = source.totalLogicalCores;
  snapshot->totalMemoryMB = source.totalMemoryMB;
  snapshot->totalStorageMB = source.totalStorageMB;
  snapshot->ownedLogicalCores = source.ownedLogicalCores;
  snapshot->ownedMemoryMB = source.ownedMemoryMB;
  snapshot->ownedStorageMB = source.ownedStorageMB;
  return snapshot;
}

static bool extractSerializedBrainPayload(String& buffer, BrainTopic topic, String& payload)
{
  bool found = false;
  payload.clear();
  forEachMessageInBuffer(buffer, [&](Message *message) {
    if (BrainTopic(message->topic) != topic)
    {
      return;
    }

    uint8_t *args = message->args;
    Message::extractToStringView(args, payload);
    found = true;
  });

  return found;
}

static void seedDeployRequestPlan(DeploymentPlan& plan, uint16_t applicationID)
{
  plan.config.applicationID = applicationID;
  plan.config.versionID = 1;
  plan.config.nLogicalCores = 1;
  plan.config.memoryMB = 64;
  plan.config.filesystemMB = 64;
  plan.config.storageMB = 64;
  plan.canaryCount = 1;
  plan.stateless.nBase = 1;
  plan.stateless.maxPerRackRatio = 1.0f;
  plan.stateless.maxPerMachineRatio = 1.0f;
}

static void seedStatefulDeployRequestPlan(DeploymentPlan& plan, uint16_t applicationID)
{
  seedDeployRequestPlan(plan, applicationID);
  plan.canaryCount = 0;
  plan.isStateful = true;
  plan.config.type = ApplicationType::stateful;
  plan.config.architecture = nametagCurrentBuildMachineArchitecture();
  plan.stateful.clientPrefix = (uint64_t(applicationID) << 48) | (uint64_t(1) << 40);
  plan.stateful.siblingPrefix = (uint64_t(applicationID) << 48) | (uint64_t(2) << 40);
  plan.stateful.cousinPrefix = (uint64_t(applicationID) << 48) | (uint64_t(3) << 40);
  plan.stateful.seedingPrefix = (uint64_t(applicationID) << 48) | (uint64_t(4) << 40);
  plan.stateful.shardingPrefix = (uint64_t(applicationID) << 48) | (uint64_t(5) << 40);
  plan.stateful.allowUpdateInPlace = true;
  plan.stateful.seedingAlways = false;
  plan.stateful.neverShard = false;
  plan.stateful.allMasters = false;
}

static void configureStatefulTopologySourceContainer(ContainerView& container,
                                                     const ApplicationDeployment& deployment,
                                                     const StatefulMeshRoles& roles,
                                                     uint32_t shardGroup,
                                                     uint128_t uuid)
{
  container = {};
  container.uuid = uuid;
  container.deploymentID = deployment.plan.config.deploymentID();
  container.applicationID = deployment.plan.config.applicationID;
  container.isStateful = true;
  container.shardGroup = shardGroup;
  container.state = ContainerState::healthy;
  container.runtimeReady = true;
  container.explicitStatefulMeshRoles = roles;
  container.explicitStatefulTopology.operationID = deployment.statefulWorkerTopologyUpgradeOperationID;
  container.explicitStatefulTopology.shardGroup = shardGroup;
  container.explicitStatefulTopology.topologyEpoch = deployment.statefulWorkerTopologyUpgradeSourceEpoch;
  container.explicitStatefulTopology.workerCount = deployment.statefulWorkerTopologyUpgradeSourceWorkerCount;
  container.explicitStatefulTopology.servingMode = StatefulTopologyServingMode::serve;
  container.explicitStatefulTopology.sourceEpoch = deployment.statefulWorkerTopologyUpgradeSourceEpoch;
  container.explicitStatefulTopology.targetEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
  container.explicitStatefulTopology.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;
}

static void configureStatefulTopologyTargetContainer(ContainerView& container,
                                                     const ApplicationDeployment& deployment,
                                                     const StatefulMeshRoles& roles,
                                                     uint32_t shardGroup,
                                                     uint128_t uuid)
{
  container = {};
  container.uuid = uuid;
  container.deploymentID = deployment.plan.config.deploymentID();
  container.applicationID = deployment.plan.config.applicationID;
  container.isStateful = true;
  container.shardGroup = shardGroup;
  container.state = ContainerState::healthy;
  container.runtimeReady = true;
  container.explicitStatefulMeshRoles = roles;
  container.explicitStatefulTopology.operationID = deployment.statefulWorkerTopologyUpgradeOperationID;
  container.explicitStatefulTopology.shardGroup = shardGroup;
  container.explicitStatefulTopology.topologyEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
  container.explicitStatefulTopology.workerCount = deployment.statefulWorkerTopologyUpgradeTargetWorkerCount;
  container.explicitStatefulTopology.servingMode = StatefulTopologyServingMode::catchupOnly;
  container.explicitStatefulTopology.sourceEpoch = deployment.statefulWorkerTopologyUpgradeSourceEpoch;
  container.explicitStatefulTopology.targetEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
  container.explicitStatefulTopology.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;
}

static void noteStatefulTopologyCutoverBarrier(ContainerView& container, const ApplicationDeployment& deployment)
{
  container.applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverSourceEpochKey(), deployment.statefulWorkerTopologyUpgradeSourceEpoch);
  container.applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverTargetEpochKey(), deployment.statefulWorkerTopologyUpgradeTargetEpoch);
  container.applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverReadyKey(), 1);
}

static void testSpinApplicationInvalidPlanUsesSingleTopicFrame(TestSuite& suite)
{
  StreamingTestBrain brain;
  NoopBrainIaaS iaas;
  Mothership mothership;
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.mothership = &mothership;
  mothership.isFixedFile = true;
  mothership.fslot = 1;

  DeploymentPlan plan = {};
  seedDeployRequestPlan(plan, 62'000);

  String serializedPlan = {};
  BitseryEngine::serialize(serializedPlan, plan);

  String requestBuffer = {};
  Message *message = buildMothershipMessage(
      requestBuffer,
      MothershipTopic::spinApplication,
      uint16_t(plan.config.applicationID),
      serializedPlan,
      "blob"_ctv);

  brain.mothershipHandler(&mothership, message);

  uint32_t frameCount = 0;
  bool sawInvalidPlan = false;
  String invalidPlanReason = {};

  forEachMessageInBuffer(mothership.wBuffer, [&](Message *frame) {
    frameCount += 1;
    suite.expect(MothershipTopic(frame->topic) == MothershipTopic::spinApplication, "spin_application_invalid_plan_uses_spin_application_topic");
    uint8_t *args = frame->args;
    uint8_t responseCode = uint8_t(SpinApplicationResponseCode::okay);
    Message::extractArg<ArgumentNature::fixed>(args, responseCode);
    sawInvalidPlan = (SpinApplicationResponseCode(responseCode) == SpinApplicationResponseCode::invalidPlan);
    if (args < frame->terminal())
    {
      Message::extractToStringView(args, invalidPlanReason);
    }
  });

  suite.expect(frameCount == 1, "spin_application_invalid_plan_uses_single_frame");
  suite.expect(sawInvalidPlan, "spin_application_invalid_plan_sets_invalid_code");
  suite.expect(invalidPlanReason == "invalid plan: applicationID not reserved"_ctv, "spin_application_invalid_plan_includes_reason");
}

static void testSpinApplicationProgressAppendsAfterOkayFrame(TestSuite& suite)
{
  StreamingTestBrain brain;
  Mothership mothership;
  brain.mothership = &mothership;
  mothership.isFixedFile = true;
  mothership.fslot = 1;

  ApplicationDeployment deployment = {};
  seedDeployRequestPlan(deployment.plan, 62'001);
  brain.bindSpinApplicationMothership(&deployment, &mothership);

  Message::construct(
      mothership.wBuffer,
      MothershipTopic::spinApplication,
      uint8_t(SpinApplicationResponseCode::okay));
  brain.pushSpinApplicationProgressToMothership(&deployment, "deploying canaries"_ctv);

  uint32_t frameCount = 0;
  SpinApplicationResponseCode firstFrame = SpinApplicationResponseCode::invalidPlan;
  SpinApplicationResponseCode secondFrame = SpinApplicationResponseCode::invalidPlan;
  String secondMessage = {};

  forEachMessageInBuffer(mothership.wBuffer, [&](Message *frame) {
    if (MothershipTopic(frame->topic) != MothershipTopic::spinApplication)
    {
      return;
    }

    uint8_t *args = frame->args;
    uint8_t responseCode = uint8_t(SpinApplicationResponseCode::invalidPlan);
    Message::extractArg<ArgumentNature::fixed>(args, responseCode);

    if (frameCount == 0)
    {
      firstFrame = SpinApplicationResponseCode(responseCode);
    }
    else if (frameCount == 1)
    {
      secondFrame = SpinApplicationResponseCode(responseCode);
      if (args < frame->terminal())
      {
        Message::extractToStringView(args, secondMessage);
      }
    }

    frameCount += 1;
  });

  suite.expect(frameCount >= 2, "spin_application_progress_appends_after_okay");
  suite.expect(firstFrame == SpinApplicationResponseCode::okay, "spin_application_progress_first_frame_is_okay");
  suite.expect(secondFrame == SpinApplicationResponseCode::progress, "spin_application_progress_second_frame_is_progress");
  suite.expect(secondMessage == "deploying canaries"_ctv, "spin_application_progress_message_matches");
}

static void testSpinApplicationProgressAcceptsDirectFdMothership(TestSuite& suite)
{
  StreamingTestBrain brain;
  Mothership mothership;
  brain.mothership = &mothership;
  mothership.isFixedFile = false;
  mothership.fd = 42;

  ApplicationDeployment deployment = {};
  seedDeployRequestPlan(deployment.plan, 62'011);
  brain.bindSpinApplicationMothership(&deployment, &mothership);

  brain.pushSpinApplicationProgressToMothership(&deployment, "direct fd active"_ctv);

  uint32_t frameCount = 0;
  SpinApplicationResponseCode responseCode = SpinApplicationResponseCode::invalidPlan;
  String progressMessage = {};

  forEachMessageInBuffer(mothership.wBuffer, [&](Message *frame) {
    if (MothershipTopic(frame->topic) != MothershipTopic::spinApplication)
    {
      return;
    }

    uint8_t *args = frame->args;
    uint8_t rawCode = uint8_t(SpinApplicationResponseCode::invalidPlan);
    Message::extractArg<ArgumentNature::fixed>(args, rawCode);
    responseCode = SpinApplicationResponseCode(rawCode);
    if (args < frame->terminal())
    {
      Message::extractToStringView(args, progressMessage);
    }
    frameCount += 1;
  });

  suite.expect(frameCount == 1, "spin_application_progress_direct_fd_emits_single_frame");
  suite.expect(responseCode == SpinApplicationResponseCode::progress, "spin_application_progress_direct_fd_sets_progress_code");
  suite.expect(progressMessage == "direct fd active"_ctv, "spin_application_progress_direct_fd_preserves_message");
}

static void testSpinApplicationProgressStaysOnOriginalDeployStream(TestSuite& suite)
{
  StreamingTestBrain brain;
  Mothership deployMothership;
  Mothership reportMothership;
  brain.mothership = &reportMothership;
  deployMothership.isFixedFile = true;
  deployMothership.fslot = 1;
  reportMothership.isFixedFile = true;
  reportMothership.fslot = 2;

  ApplicationDeployment deployment = {};
  seedDeployRequestPlan(deployment.plan, 62'012);
  brain.bindSpinApplicationMothership(&deployment, &deployMothership);

  brain.pushSpinApplicationProgressToMothership(&deployment, "original stream only"_ctv);

  uint32_t deployFrames = 0;
  uint32_t reportFrames = 0;

  forEachMessageInBuffer(deployMothership.wBuffer, [&](Message *frame) {
    if (MothershipTopic(frame->topic) == MothershipTopic::spinApplication)
    {
      deployFrames += 1;
    }
  });
  forEachMessageInBuffer(reportMothership.wBuffer, [&](Message *frame) {
    if (MothershipTopic(frame->topic) == MothershipTopic::spinApplication)
    {
      reportFrames += 1;
    }
  });

  suite.expect(deployFrames == 1, "spin_application_progress_uses_bound_deploy_stream");
  suite.expect(reportFrames == 0, "spin_application_progress_does_not_pollute_current_report_stream");
}

static void testSpinApplicationStagesFollowerBlobReplicationBehindMetadataEcho(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.nBrains = 3;

  BrainView followerA = {};
  followerA.connected = true;
  followerA.isFixedFile = true;
  followerA.fslot = 11;
  followerA.private4 = 0x0a00000b;
  BrainView followerB = {};
  followerB.connected = true;
  followerB.isFixedFile = true;
  followerB.fslot = 12;
  followerB.private4 = 0x0a00000c;
  brain.brains.insert(&followerA);
  brain.brains.insert(&followerB);

  ApplicationDeployment *deployment = new ApplicationDeployment();
  seedDeployRequestPlan(deployment->plan, 62'013);
  deployment->state = DeploymentState::waitingToDeploy;
  String containerBlob = "spin-stage-container-blob"_ctv;
  ContainerStore::destroy(deployment->plan.config.deploymentID());
  deployment->plan.config.containerBlobBytes = containerBlob.size();
  String containerBlobPath = ContainerStore::pathForContainerImage(deployment->plan.config.deploymentID());
  suite.expect(Filesystem::createDirectoryAt(-1, "/containers"_ctv, 0755) >= 0 || errno == EEXIST, "spin_application_stage_blob_create_containers_root");
  suite.expect(Filesystem::createDirectoryAt(-1, "/containers/store"_ctv, 0755) >= 0 || errno == EEXIST, "spin_application_stage_blob_create_store_root");
  suite.expect(
      Filesystem::openWriteAtClose(-1, containerBlobPath, containerBlob) == int(containerBlob.size()),
      "spin_application_stage_blob_store_fixture");

  brain.deployments.insert_or_assign(deployment->plan.config.deploymentID(), deployment);
  brain.deploymentPlans.insert_or_assign(deployment->plan.config.deploymentID(), deployment->plan);

  String serializedPlan = {};
  BitseryEngine::serialize(serializedPlan, deployment->plan);
  brain.queueBrainDeploymentReplicationForTest(serializedPlan, ""_ctv);

  if (auto it = brain.deployments.find(deployment->plan.config.deploymentID()); it != brain.deployments.end())
  {
    deployment = it->second;
  }

  suite.expect(deployment != nullptr, "spin_application_stage_blob_tracks_live_deployment");
  if (deployment == nullptr)
  {
    return;
  }

  auto countReplicateDeploymentFrames =
      [&](BrainView& follower, uint32_t& emptyBlobFrames, uint32_t& nonEmptyBlobFrames) -> void {
    emptyBlobFrames = 0;
    nonEmptyBlobFrames = 0;
    forEachMessageInBuffer(follower.wBuffer, [&](Message *frame) {
      if (BrainTopic(frame->topic) != BrainTopic::replicateDeployment)
      {
        return;
      }

      uint8_t *args = frame->args;
      String ignoredSerializedPlan = {};
      Message::extractToStringView(args, ignoredSerializedPlan);
      String observedBlob = {};
      Message::extractToStringView(args, observedBlob);
      if (observedBlob.size() == 0)
      {
        emptyBlobFrames += 1;
      }
      else
      {
        nonEmptyBlobFrames += 1;
      }
    });
  };

  uint32_t followerAEmpty = 0;
  uint32_t followerABlob = 0;
  uint32_t followerBEmpty = 0;
  uint32_t followerBBlob = 0;
  countReplicateDeploymentFrames(followerA, followerAEmpty, followerABlob);
  countReplicateDeploymentFrames(followerB, followerBEmpty, followerBBlob);
  suite.expect(followerAEmpty == 1 && followerABlob == 0, "spin_application_stage_blob_initially_queues_metadata_only_to_first_peer");
  suite.expect(followerBEmpty == 1 && followerBBlob == 0, "spin_application_stage_blob_initially_queues_metadata_only_to_second_peer");

  String echoBufferA = {};
  Message *echoA = buildBrainMessage(echoBufferA, BrainTopic::replicateDeployment, deployment->plan.config.deploymentID());
  brain.brainHandler(&followerA, echoA);
  countReplicateDeploymentFrames(followerA, followerAEmpty, followerABlob);
  countReplicateDeploymentFrames(followerB, followerBEmpty, followerBBlob);
  suite.expect(followerAEmpty == 1 && followerABlob == 1, "spin_application_stage_blob_first_echo_queues_blob_only_to_echoing_peer");
  suite.expect(followerBEmpty == 1 && followerBBlob == 0, "spin_application_stage_blob_first_echo_does_not_queue_blob_to_other_peer");
  suite.expect(deployment->brainEchos == 0, "spin_application_stage_blob_metadata_echo_does_not_count_as_blob_echo");

  String echoBufferASecond = {};
  Message *echoASecond = buildBrainMessage(echoBufferASecond, BrainTopic::replicateDeployment, deployment->plan.config.deploymentID());
  brain.brainHandler(&followerA, echoASecond);
  suite.expect(deployment->brainEchos == 1, "spin_application_stage_blob_second_echo_counts_first_peer_blob_ack");

  String echoBufferB = {};
  Message *echoB = buildBrainMessage(echoBufferB, BrainTopic::replicateDeployment, deployment->plan.config.deploymentID());
  brain.brainHandler(&followerB, echoB);
  countReplicateDeploymentFrames(followerB, followerBEmpty, followerBBlob);
  suite.expect(followerBEmpty == 1 && followerBBlob == 1, "spin_application_stage_blob_first_echo_queues_blob_to_second_peer");

  String echoBufferBSecond = {};
  Message *echoBSecond = buildBrainMessage(echoBufferBSecond, BrainTopic::replicateDeployment, deployment->plan.config.deploymentID());
  brain.brainHandler(&followerB, echoBSecond);
  suite.expect(deployment->brainEchos == 2, "spin_application_stage_blob_second_peer_blob_ack_counts_full_replication");
  suite.expect(deployment->brainBlobQueuedPeerKeys.size() == 2, "spin_application_stage_blob_tracks_blob_queue_per_peer");
  suite.expect(deployment->brainBlobEchoPeerKeys.size() == 2, "spin_application_stage_blob_tracks_blob_echo_per_peer");

  brain.deployments.erase(deployment->plan.config.deploymentID());
  brain.deploymentPlans.erase(deployment->plan.config.deploymentID());
  ContainerStore::destroy(deployment->plan.config.deploymentID());
  delete deployment;
}

static void testStatefulRequestMachinesClaimsDeployingMachinesWithSpecializedTicket(TestSuite& suite)
{
  StreamingTestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rackA = {};
  Rack rackB = {};
  Rack rackC = {};
  rackA.uuid = 620'031;
  rackB.uuid = 620'032;
  rackC.uuid = 620'033;
  brain.racks.insert_or_assign(rackA.uuid, &rackA);
  brain.racks.insert_or_assign(rackB.uuid, &rackB);
  brain.racks.insert_or_assign(rackC.uuid, &rackC);

  auto seedMachine = [&](
                         Machine& machine,
                         Rack& rack,
                         uint128_t uuid,
                         uint32_t private4,
                         const String& slug) -> void {
    machine.uuid = uuid;
    machine.private4 = private4;
    machine.slug = slug;
    machine.rack = &rack;
    machine.rackUUID = rack.uuid;
    machine.state = MachineState::deploying;
    machine.lifetime = MachineLifetime::owned;
    machine.isBrain = true;
    machine.hardware.inventoryComplete = true;
    machine.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
    machine.hardware.cpu.logicalCores = 8;
    machine.hardware.memory.totalMB = 8192;
    machine.ownedLogicalCores = 8;
    machine.ownedMemoryMB = 8192;
    machine.ownedStorageMB = 4096;
    machine.totalLogicalCores = 8;
    machine.totalMemoryMB = 8192;
    machine.totalStorageMB = 4096;
    machine.nLogicalCores_available = 8;
    machine.sharedCPUMillis_available = 0;
    machine.memoryMB_available = 8192;
    machine.storageMB_available = 4096;
    rack.machines.insert(&machine);
    brain.machines.insert(&machine);
    brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  };

  Machine machineA = {};
  Machine machineB = {};
  Machine machineC = {};
  seedMachine(machineA, rackA, uint128_t(0x62003101), 0x0a00000a, "stateful-wake-a"_ctv);
  seedMachine(machineB, rackB, uint128_t(0x62003102), 0x0a00000b, "stateful-wake-b"_ctv);
  seedMachine(machineC, rackC, uint128_t(0x62003103), 0x0a00000c, "stateful-wake-c"_ctv);

  DeploymentPlan plan = {};
  seedStatefulDeployRequestPlan(plan, 62'003);

  ApplicationDeployment deployment = {};
  deployment.plan = plan;
  deployment.nShardGroups = 1;
  deployment.nTargetBase = 3;

  MachineTicket ticket = {};
  ticket.coro = new CoroutineStack();
  ticket.shardGroups.push_back(0);
  ticket.shardGroups.push_back(0);
  ticket.shardGroups.push_back(0);

  brain.requestMachines(&ticket, &deployment, ApplicationLifetime::base, 3);

  suite.expect(ticket.shardGroups.size() == 0, "stateful_request_machines_consumes_specialized_groups_while_claiming");
  suite.expect(machineA.claims.size() == 1 && machineA.claims[0].nFit == 1, "stateful_request_machines_claims_first_deploying_machine");
  suite.expect(machineB.claims.size() == 1 && machineB.claims[0].nFit == 1, "stateful_request_machines_claims_second_deploying_machine");
  suite.expect(machineC.claims.size() == 1 && machineC.claims[0].nFit == 1, "stateful_request_machines_claims_third_deploying_machine");
  suite.expect(machineA.claims.size() == 1 && machineA.claims[0].shardGroups.size() == 1 && machineA.claims[0].shardGroups[0] == 0, "stateful_request_machines_preserves_group_on_first_machine_claim");
  suite.expect(machineB.claims.size() == 1 && machineB.claims[0].shardGroups.size() == 1 && machineB.claims[0].shardGroups[0] == 0, "stateful_request_machines_preserves_group_on_second_machine_claim");
  suite.expect(machineC.claims.size() == 1 && machineC.claims[0].shardGroups.size() == 1 && machineC.claims[0].shardGroups[0] == 0, "stateful_request_machines_preserves_group_on_third_machine_claim");
  suite.expect(deployment.countPerMachine.getIf(&machineA) == 1, "stateful_request_machines_updates_first_machine_counts");
  suite.expect(deployment.countPerMachine.getIf(&machineB) == 1, "stateful_request_machines_updates_second_machine_counts");
  suite.expect(deployment.countPerMachine.getIf(&machineC) == 1, "stateful_request_machines_updates_third_machine_counts");
  suite.expect(deployment.countPerRack.getIf(&rackA) == 1, "stateful_request_machines_updates_first_rack_counts");
  suite.expect(deployment.countPerRack.getIf(&rackB) == 1, "stateful_request_machines_updates_second_rack_counts");
  suite.expect(deployment.countPerRack.getIf(&rackC) == 1, "stateful_request_machines_updates_third_rack_counts");

  machineA.claims.clear();
  machineB.claims.clear();
  machineC.claims.clear();
  delete ticket.coro;

  brain.machinesByUUID.erase(machineA.uuid);
  brain.machinesByUUID.erase(machineB.uuid);
  brain.machinesByUUID.erase(machineC.uuid);
  brain.machines.erase(&machineA);
  brain.machines.erase(&machineB);
  brain.machines.erase(&machineC);
  rackA.machines.erase(&machineA);
  rackB.machines.erase(&machineB);
  rackC.machines.erase(&machineC);
  brain.racks.erase(rackA.uuid);
  brain.racks.erase(rackB.uuid);
  brain.racks.erase(rackC.uuid);

  thisBrain = previousBrain;
}

static void testSpinApplicationFailedFrameCarriesReason(TestSuite& suite)
{
  StreamingTestBrain brain;
  Mothership mothership;
  brain.mothership = &mothership;
  mothership.isFixedFile = true;
  mothership.fslot = 1;

  ApplicationDeployment deployment = {};
  seedDeployRequestPlan(deployment.plan, 62'002);
  brain.bindSpinApplicationMothership(&deployment, &mothership);

  brain.spinApplicationFailed(&deployment, "canaries failed"_ctv);

  uint32_t frameCount = 0;
  SpinApplicationResponseCode responseCode = SpinApplicationResponseCode::invalidPlan;
  String failureMessage = {};

  forEachMessageInBuffer(mothership.wBuffer, [&](Message *frame) {
    if (MothershipTopic(frame->topic) != MothershipTopic::spinApplication)
    {
      return;
    }

    uint8_t *args = frame->args;
    uint8_t rawCode = uint8_t(SpinApplicationResponseCode::invalidPlan);
    Message::extractArg<ArgumentNature::fixed>(args, rawCode);
    responseCode = SpinApplicationResponseCode(rawCode);
    if (args < frame->terminal())
    {
      Message::extractToStringView(args, failureMessage);
    }
    frameCount += 1;
  });

  suite.expect(frameCount == 1, "spin_application_failed_emits_single_frame");
  suite.expect(responseCode == SpinApplicationResponseCode::failed, "spin_application_failed_sets_failed_code");
  suite.expect(failureMessage == "canaries failed"_ctv, "spin_application_failed_preserves_reason");
}

static bool generateApplicationTlsFactory(ApplicationTlsVaultFactory& factory, String& failure, CryptoScheme scheme = CryptoScheme::ed25519)
{
  failure.clear();
  factory.scheme = uint8_t(scheme);
  factory.defaultLeafValidityDays = 15;

  X509 *rootCert = nullptr;
  EVP_PKEY *rootKey = nullptr;
  X509 *intermediateCert = nullptr;
  EVP_PKEY *intermediateKey = nullptr;

  VaultCertificateRequest rootRequest = {};
  rootRequest.type = CertificateType::root;
  rootRequest.scheme = scheme;
  generateCertificateAndKeys(rootRequest, nullptr, nullptr, rootCert, rootKey);

  VaultCertificateRequest intermediateRequest = {};
  intermediateRequest.type = CertificateType::intermediary;
  intermediateRequest.scheme = scheme;
  generateCertificateAndKeys(intermediateRequest, rootCert, rootKey, intermediateCert, intermediateKey);

  bool ok = (rootCert != nullptr) && (rootKey != nullptr) && (intermediateCert != nullptr) && (intermediateKey != nullptr) && VaultPem::x509ToPem(rootCert, factory.rootCertPem) && VaultPem::privateKeyToPem(rootKey, factory.rootKeyPem) && VaultPem::x509ToPem(intermediateCert, factory.intermediateCertPem) && VaultPem::privateKeyToPem(intermediateKey, factory.intermediateKeyPem);

  if (rootCert)
  {
    X509_free(rootCert);
  }
  if (rootKey)
  {
    EVP_PKEY_free(rootKey);
  }
  if (intermediateCert)
  {
    X509_free(intermediateCert);
  }
  if (intermediateKey)
  {
    EVP_PKEY_free(intermediateKey);
  }

  if (ok == false)
  {
    failure.assign("failed to generate application tls factory"_ctv);
  }

  return ok;
}

static void installACMEZoneDNSCredential(TestBrain& brain, uint16_t applicationID, const String& name, const String& zone)
{
  ApplicationApiCredentialSet set = {};
  set.applicationID = applicationID;
  ApiCredential credential = {};
  credential.name = name;
  credential.provider = "cloudflare"_ctv;
  credential.material = "secret"_ctv;
  credential.metadata.insert_or_assign("dnsScope"_ctv, "native-zone"_ctv);
  credential.metadata.insert_or_assign("dnsZones"_ctv, zone);
  set.credentials.push_back(credential);
  brain.apiCredentialSetsByApp[applicationID] = set;
}

static bool certificateHasDnsSan(const String& certPem, const String& expected)
{
  X509 *cert = VaultPem::x509FromPem(certPem);
  if (cert == nullptr)
  {
    return false;
  }

  GENERAL_NAMES *names = static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
  bool found = false;
  if (names)
  {
    for (int index = 0; index < sk_GENERAL_NAME_num(names); ++index)
    {
      const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, index);
      if (name == nullptr || name->type != GEN_DNS)
      {
        continue;
      }

      const ASN1_IA5STRING *dns = name->d.dNSName;
      const unsigned char *bytes = ASN1_STRING_get0_data(dns);
      const int length = ASN1_STRING_length(dns);
      if (length == int(expected.size()) && std::memcmp(bytes, expected.data(), expected.size()) == 0)
      {
        found = true;
        break;
      }
    }

    sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
  }

  X509_free(cert);
  return found;
}

static bool certificateHasIpSan(const String& certPem, const IPAddress& expected)
{
  X509 *cert = VaultPem::x509FromPem(certPem);
  if (cert == nullptr)
  {
    return false;
  }

  GENERAL_NAMES *names = static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
  bool found = false;
  if (names)
  {
    const int expectedLength = expected.is6 ? 16 : 4;
    for (int index = 0; index < sk_GENERAL_NAME_num(names); ++index)
    {
      const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, index);
      if (name == nullptr || name->type != GEN_IPADD)
      {
        continue;
      }

      const ASN1_OCTET_STRING *ip = name->d.iPAddress;
      const unsigned char *bytes = ASN1_STRING_get0_data(ip);
      const int length = ASN1_STRING_length(ip);
      if (length == expectedLength && std::memcmp(bytes, expected.v6, size_t(expectedLength)) == 0)
      {
        found = true;
        break;
      }
    }

    sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
  }

  X509_free(cert);
  return found;
}

static bool generateACMELineage(const std::filesystem::path& path, const Vector<String>& domains, String& certPem, String& keyPem, const Vector<IPAddress> *ipSans = nullptr, bool enableServerAuth = true, String *chainPem = nullptr)
{
  String failure = {};
  ApplicationTlsVaultFactory factory = {};
  factory.applicationID = 1;
  factory.factoryGeneration = 1;
  if (generateApplicationTlsFactory(factory, failure, CryptoScheme::p256) == false)
  {
    return false;
  }

  X509 *interCert = VaultPem::x509FromPem(factory.intermediateCertPem);
  EVP_PKEY *interKey = VaultPem::privateKeyFromPem(factory.intermediateKeyPem);
  X509 *leafCert = nullptr;
  EVP_PKEY *leafKey = nullptr;
  VaultCertificateRequest request = {};
  request.type = CertificateType::server;
  request.scheme = CryptoScheme::p256;
  request.subjectCommonName = domains.empty() ? "acme.example.com"_ctv : domains[0];
  request.enableServerAuth = enableServerAuth;
  generateCertificateAndKeys(request, interCert, interKey, leafCert, leafKey);

  Vector<IPAddress> noIPSans = {};
  bool ok = interCert != nullptr && interKey != nullptr && leafCert != nullptr && leafKey != nullptr &&
            brainAddCertificateSubjectAltNames(leafCert, domains, ipSans ? *ipSans : noIPSans) &&
            X509_gmtime_adj(X509_getm_notBefore(leafCert), 0) != nullptr &&
            X509_time_adj_ex(X509_getm_notAfter(leafCert), 90, 0, nullptr) != nullptr &&
            X509_sign(leafCert, interKey, EVP_sha256()) != 0 &&
            VaultPem::x509ToPem(leafCert, certPem) &&
            VaultPem::privateKeyToPem(leafKey, keyPem);

  if (ok)
  {
    String chain = factory.intermediateCertPem;
    chain.append(factory.rootCertPem);
    if (chainPem)
    {
      *chainPem = chain;
    }
    String fullchain = certPem;
    fullchain.append(chain);
    ok = writeTextFile(path / "fullchain.pem", toStdString(fullchain)) &&
         writeTextFile(path / "privkey.pem", toStdString(keyPem));
  }

  if (interCert)
  {
    X509_free(interCert);
  }
  if (interKey)
  {
    EVP_PKEY_free(interKey);
  }
  if (leafCert)
  {
    X509_free(leafCert);
  }
  if (leafKey)
  {
    EVP_PKEY_free(leafKey);
  }
  return ok;
}

static bool stringVectorContains(const Vector<String>& values, const String& needle)
{
  for (const String& value : values)
  {
    if (value.equal(needle))
    {
      return true;
    }
  }
  return false;
}

static bool extractQueuedCredentialDelta(Machine& machine, uint128_t& containerUUID, CredentialDelta& delta)
{
  if (machine.neuron.wBuffer.size() == 0)
  {
    return false;
  }

  Message *message = reinterpret_cast<Message *>(machine.neuron.wBuffer.data());
  if (NeuronTopic(message->topic) != NeuronTopic::refreshContainerCredentials)
  {
    return false;
  }

  String serialized = {};
  uint8_t *args = message->args;
  if (Message::extractArg<ArgumentNature::fixed>(args, containerUUID) == false)
  {
    return false;
  }
  Message::extractToStringView(args, serialized);
  return ProdigyWire::deserializeCredentialDelta(serialized, delta);
}

static bool generateTransportAuthority(ProdigyTransportTLSAuthority& authority, String& failure)
{
  failure.clear();

  String rootCertPem = {};
  String rootKeyPem = {};
  if (Vault::generateTransportRootCertificateEd25519(rootCertPem, rootKeyPem, &failure) == false)
  {
    return false;
  }

  authority = {};
  authority.generation = 11;
  authority.clusterRootCertPem = rootCertPem;
  authority.clusterRootKeyPem = rootKeyPem;
  return true;
}

static bool configureTransportRuntimeForNode(
    uint128_t nodeUUID,
    const String& rootCertPem,
    const String& rootKeyPem,
    const String& localCertPem,
    const String& localKeyPem,
    String *failure = nullptr)
{
  ProdigyTransportTLSBootstrap bootstrap = {};
  bootstrap.uuid = nodeUUID;
  bootstrap.transport.generation = 1;
  bootstrap.transport.clusterRootCertPem = rootCertPem;
  bootstrap.transport.clusterRootKeyPem = rootKeyPem;
  bootstrap.transport.localCertPem = localCertPem;
  bootstrap.transport.localKeyPem = localKeyPem;
  return ProdigyTransportTLSRuntime::configure(bootstrap, failure);
}

static bool generateTransportPeerCertificateWithoutUUID(
    const String& rootCertPem,
    const String& rootKeyPem,
    const Vector<String>& ipAddresses,
    String& certPem,
    String& keyPem,
    String *failure = nullptr)
{
  certPem.clear();
  keyPem.clear();
  if (failure)
  {
    failure->clear();
  }

  X509 *rootCert = VaultPem::x509FromPem(rootCertPem);
  EVP_PKEY *rootKey = VaultPem::privateKeyFromPem(rootKeyPem);
  if (rootCert == nullptr || rootKey == nullptr)
  {
    if (rootCert)
    {
      X509_free(rootCert);
    }
    if (rootKey)
    {
      EVP_PKEY_free(rootKey);
    }
    if (failure)
    {
      failure->assign("invalid transport root material"_ctv);
    }
    return false;
  }

  X509 *cert = nullptr;
  EVP_PKEY *key = nullptr;
  String subjectOrganization = {};
  bool ok = Vault::issueTransportCertificateEd25519(
      "not-a-transport-uuid"_ctv,
      subjectOrganization,
      false,
      true,
      true,
      825,
      ipAddresses,
      rootCert,
      rootKey,
      cert,
      key,
      failure);
  if (ok)
  {
    ok = VaultPem::x509ToPem(cert, certPem);
  }
  if (ok)
  {
    ok = VaultPem::privateKeyToPem(key, keyPem);
  }

  X509_free(rootCert);
  EVP_PKEY_free(rootKey);
  if (cert)
  {
    X509_free(cert);
  }
  if (key)
  {
    EVP_PKEY_free(key);
  }

  if (ok == false)
  {
    certPem.clear();
    keyPem.clear();
    if (failure && failure->size() == 0)
    {
      failure->assign("failed to generate transport peer certificate without uuid"_ctv);
    }
    return false;
  }

  if (failure)
  {
    failure->clear();
  }

  return true;
}

static void reserveTransportStream(ProdigyTransportTLSStream& stream)
{
  stream.rBuffer.reserve(8192);
  stream.wBuffer.reserve(16'384);
}

static bool pumpTransportBytes(ProdigyTransportTLSStream& from, ProdigyTransportTLSStream& to)
{
  uint32_t bytes = from.nBytesToSend();
  if (bytes == 0)
  {
    return false;
  }

  if (to.rBuffer.remainingCapacity() < bytes)
  {
    to.rBuffer.reserve(to.rBuffer.size() + bytes);
  }

  from.noteSendQueued();
  std::memcpy(to.rBuffer.pTail(), from.pBytesToSend(), bytes);
  if (to.decryptTransportTLS(bytes) == false)
  {
    from.noteSendCompleted();
    return false;
  }

  from.consumeSentBytes(bytes, false);
  from.noteSendCompleted();
  return true;
}

static bool copyEncryptedTransportBytes(ProdigyTransportTLSStream& from, StreamBuffer& destination, uint32_t& bytesCopied)
{
  bytesCopied = from.nBytesToSend();
  if (bytesCopied == 0)
  {
    return false;
  }

  if (destination.remainingCapacity() < bytesCopied)
  {
    destination.reserve(destination.size() + bytesCopied);
  }

  from.noteSendQueued();
  std::memcpy(destination.pTail(), from.pBytesToSend(), bytesCopied);
  from.consumeSentBytes(bytesCopied, false);
  from.noteSendCompleted();
  return true;
}

static bool completeTransportHandshake(ProdigyTransportTLSStream& client, ProdigyTransportTLSStream& server, uint32_t maxRounds = 128)
{
  for (uint32_t round = 0; round < maxRounds; ++round)
  {
    bool progressed = false;
    progressed = pumpTransportBytes(client, server) || progressed;
    progressed = pumpTransportBytes(server, client) || progressed;

    if (client.isTLSNegotiated() && server.isTLSNegotiated())
    {
      return true;
    }

    if (progressed == false)
    {
      break;
    }
  }

  return false;
}

static bool configureSingleNodeTransportRuntime(TestSuite& suite, const char *prefix, uint128_t nodeUUID)
{
  ProdigyTransportTLSRuntime::clear();

  String failure = {};
  String rootCertPem = {};
  String rootKeyPem = {};
  String certPem = {};
  String keyPem = {};
  if (suite.require(Vault::generateTransportRootCertificateEd25519(rootCertPem, rootKeyPem, &failure), testName(prefix, "generate_root")) == false)
  {
    return false;
  }

  Vector<String> addresses = {};
  addresses.push_back(String("fd00::10"));
  if (suite.require(
          Vault::generateTransportNodeCertificateEd25519(
              rootCertPem,
              rootKeyPem,
              nodeUUID,
              addresses,
              certPem,
              keyPem,
              &failure),
          testName(prefix, "generate_leaf")) == false)
  {
    return false;
  }

  return suite.require(
      configureTransportRuntimeForNode(nodeUUID, rootCertPem, rootKeyPem, certPem, keyPem, &failure),
      testName(prefix, "configure_runtime"));
}

static void testBrainAcceptKeepsLiveAcceptedTLSPeerHandshake(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;

  BrainView peer = {};
  peer.connected = true;
  peer.isFixedFile = true;
  peer.fslot = 17;
  peer.weConnectToIt = true;
  peer.currentStreamAccepted = true;
  reserveTransportStream(peer);

  if (configureSingleNodeTransportRuntime(suite, "brain_accept_unverified_tls_peer", uint128_t(0x8001)) == false)
  {
    ProdigyTransportTLSRuntime::clear();
    return;
  }

  if (suite.require(peer.beginTransportTLS(true), "brain_accept_unverified_tls_peer_begin_tls") == false)
  {
    ProdigyTransportTLSRuntime::clear();
    return;
  }

  suite.expect(peer.transportTLSEnabled(), "brain_accept_unverified_tls_peer_has_tls_transport");
  suite.expect(peer.isTLSNegotiated() == false, "brain_accept_unverified_tls_peer_starts_unnegotiated");
  suite.expect(
      brain.shouldReplaceActivePeerWithAcceptedStreamForTest(&peer, false) == false,
      "brain_accept_keeps_live_accepted_unverified_tls_peer_stream");

  peer.currentStreamAccepted = false;
  suite.expect(
      brain.shouldReplaceActivePeerWithAcceptedStreamForTest(&peer, false),
      "brain_accept_replaces_unverified_outbound_tls_peer_stream");

  peer.currentStreamAccepted = true;

  peer.tlsPeerVerified = true;
  suite.expect(
      brain.shouldReplaceActivePeerWithAcceptedStreamForTest(&peer, false) == false,
      "brain_accept_keeps_live_accepted_verified_but_unnegotiated_tls_peer_stream");

  ProdigyTransportTLSRuntime::clear();
}

static void testMachineReadyRequiresVerifiedTLSNeuronControl(TestSuite& suite)
{
  ScopedFreshRing ring = {};
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;

  Machine machine = {};
  machine.neuron.machine = &machine;
  machine.neuron.connected = true;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 9;
  machine.hardware.inventoryComplete = true;
  machine.hardware.cpu.logicalCores = 2;
  machine.hardware.memory.totalMB = 4096;

  suite.expect(
      brain.machineReadyForHealthyStateForTest(&machine),
      "machine_ready_allows_plain_control_when_tls_transport_is_not_enabled");

  reserveTransportStream(machine.neuron);
  if (configureSingleNodeTransportRuntime(suite, "machine_ready_tls_control", uint128_t(0x8002)) == false)
  {
    ProdigyTransportTLSRuntime::clear();
    return;
  }

  if (suite.require(machine.neuron.beginTransportTLS(false), "machine_ready_tls_control_begin_tls") == false)
  {
    ProdigyTransportTLSRuntime::clear();
    return;
  }

  suite.expect(
      brain.machineReadyForHealthyStateForTest(&machine) == false,
      "machine_ready_rejects_unverified_tls_neuron_control");

  machine.neuron.tlsPeerVerified = true;
  suite.expect(
      brain.machineReadyForHealthyStateForTest(&machine) == false,
      "machine_ready_rejects_verified_but_unnegotiated_tls_neuron_control");

  ProdigyTransportTLSRuntime::clear();
}

static DeploymentPlan makeDeploymentPlan(uint16_t applicationID, uint64_t versionID)
{
  DeploymentPlan plan = {};
  plan.config.applicationID = applicationID;
  plan.config.versionID = versionID;
  plan.config.filesystemMB = 64;
  plan.config.storageMB = 128;
  plan.config.memoryMB = 256;
  plan.config.nLogicalCores = 1;
  plan.config.msTilHealthy = 1000;
  plan.config.sTilHealthcheck = 5;
  plan.config.sTilKillable = 30;
  plan.minimumSubscriberCapacity = 1;
  plan.isStateful = false;
  plan.stateless.nBase = 2;
  plan.stateless.maxPerRackRatio = 0.6f;
  plan.stateless.maxPerMachineRatio = 0.5f;
  plan.canaryCount = 1;
  plan.canariesMustLiveForMinutes = 5;
  plan.moveConstructively = true;
  return plan;
}

static Wormhole makeTlsResumptionTestWormhole(void)
{
  Wormhole wormhole = {};
  wormhole.name.assign("public-api-quic"_ctv);
  wormhole.externalAddress = IPAddress("2001:db8::44", true);
  wormhole.externalPort = 443;
  wormhole.containerPort = 8443;
  wormhole.layer4 = IPPROTO_UDP;
  wormhole.isQuic = true;
  wormhole.source = ExternalAddressSource::distributableSubnet;
  wormhole.hasTlsResumptionConfig = true;
  wormhole.tlsResumption.alpns.push_back("h3"_ctv);
  wormhole.tlsResumption.sniNames.push_back("api.example.com"_ctv);
  return wormhole;
}

static TlsResumptionApplyAck makeTlsResumptionAck(const String& wormholeName, uint64_t generation)
{
  TlsResumptionApplyAck ack = {};

  TlsResumptionApplyResult result = {};
  result.wormholeName = wormholeName;
  result.generation = generation;
  result.success = true;
  ack.results.push_back(result);
  return ack;
}

static TlsResumptionSnapshot makeTlsResumptionTestSnapshot(const String& wormholeName, uint64_t generation, TlsResumptionKeyRole role)
{
  TlsResumptionSnapshot snapshot = {};
  snapshot.generation = generation;
  snapshot.wormholeName = wormholeName;

  TlsResumptionKeyEpoch epoch = {};
  epoch.generation = generation;
  epoch.role = role;
  for (uint32_t index = 0; index < sizeof(epoch.keyID); index += 1)
  {
    epoch.keyID[index] = uint8_t(0x20 + index);
  }
  for (uint32_t index = 0; index < sizeof(epoch.masterSecret); index += 1)
  {
    epoch.masterSecret[index] = uint8_t(0x40 + index);
  }
  epoch.issueUntilMs = role == TlsResumptionKeyRole::issueAndAccept ? 1'700'010'000'000 : 0;
  epoch.acceptUntilMs = 1'700'020'000'000;
  snapshot.keyRing.push_back(epoch);
  return snapshot;
}

static bool tlsResumptionSnapshotHasEpoch(const TlsResumptionSnapshot *snapshot, uint64_t generation)
{
  if (snapshot == nullptr)
  {
    return false;
  }

  for (const TlsResumptionKeyEpoch& epoch : snapshot->keyRing)
  {
    if (epoch.generation == generation)
    {
      return true;
    }
  }

  return false;
}

static bool tlsResumptionSnapshotHasEpochRole(const TlsResumptionSnapshot *snapshot, uint64_t generation, TlsResumptionKeyRole role, int phase = -1)
{
  if (snapshot == nullptr)
  {
    return false;
  }

  for (const TlsResumptionKeyEpoch& epoch : snapshot->keyRing)
  {
    if (epoch.generation == generation && epoch.role == role)
    {
      return phase < 0 || prodigyTlsResumptionEpochPhase(epoch) == uint8_t(phase);
    }
  }

  return false;
}

static bool setTlsResumptionEpochAcceptUntilMs(TlsResumptionSnapshot *snapshot, uint64_t generation, int64_t acceptUntilMs)
{
  if (snapshot == nullptr)
  {
    return false;
  }

  for (TlsResumptionKeyEpoch& epoch : snapshot->keyRing)
  {
    if (epoch.generation == generation)
    {
      epoch.acceptUntilMs = acceptUntilMs;
      return true;
    }
  }

  return false;
}

static bool setTlsResumptionEpochIssueUntilMs(TlsResumptionSnapshot *snapshot, uint64_t generation, int64_t issueUntilMs)
{
  if (snapshot == nullptr)
  {
    return false;
  }

  for (TlsResumptionKeyEpoch& epoch : snapshot->keyRing)
  {
    if (epoch.generation == generation)
    {
      epoch.issueUntilMs = issueUntilMs;
      return true;
    }
  }

  return false;
}

static void testReplicationAcceptanceRules(TestSuite& suite)
{
  TestBrain brain;

  ApplicationTlsVaultFactory tlsExisting;
  tlsExisting.applicationID = 7;
  tlsExisting.factoryGeneration = 10;
  tlsExisting.updatedAtMs = 200;

  ApplicationTlsVaultFactory tlsIncoming = tlsExisting;
  tlsIncoming.applicationID = 0;
  suite.expect(brain.shouldAcceptTlsFactoryReplication(tlsIncoming, &tlsExisting) == false, "tls_repl_reject_zero_appid");

  tlsIncoming.applicationID = tlsExisting.applicationID;
  tlsIncoming.factoryGeneration = 9;
  tlsIncoming.updatedAtMs = 999;
  suite.expect(brain.shouldAcceptTlsFactoryReplication(tlsIncoming, &tlsExisting) == false, "tls_repl_reject_older_generation");

  tlsIncoming.factoryGeneration = 10;
  tlsIncoming.updatedAtMs = 199;
  suite.expect(brain.shouldAcceptTlsFactoryReplication(tlsIncoming, &tlsExisting) == false, "tls_repl_reject_older_timestamp_same_generation");

  tlsIncoming.updatedAtMs = 200;
  suite.expect(brain.shouldAcceptTlsFactoryReplication(tlsIncoming, &tlsExisting), "tls_repl_accept_same_generation_same_timestamp");

  tlsIncoming.factoryGeneration = 11;
  tlsIncoming.updatedAtMs = 1;
  suite.expect(brain.shouldAcceptTlsFactoryReplication(tlsIncoming, &tlsExisting), "tls_repl_accept_newer_generation");

  ApplicationApiCredentialSet apiExisting;
  apiExisting.applicationID = 6;
  apiExisting.setGeneration = 20;
  apiExisting.updatedAtMs = 700;

  ApplicationApiCredentialSet apiIncoming = apiExisting;
  apiIncoming.applicationID = 0;
  suite.expect(brain.shouldAcceptApiCredentialSetReplication(apiIncoming, &apiExisting) == false, "api_repl_reject_zero_appid");

  apiIncoming.applicationID = apiExisting.applicationID;
  apiIncoming.setGeneration = 19;
  apiIncoming.updatedAtMs = 800;
  suite.expect(brain.shouldAcceptApiCredentialSetReplication(apiIncoming, &apiExisting) == false, "api_repl_reject_older_generation");

  apiIncoming.setGeneration = 20;
  apiIncoming.updatedAtMs = 699;
  suite.expect(brain.shouldAcceptApiCredentialSetReplication(apiIncoming, &apiExisting) == false, "api_repl_reject_older_timestamp_same_generation");

  apiIncoming.updatedAtMs = 700;
  suite.expect(brain.shouldAcceptApiCredentialSetReplication(apiIncoming, &apiExisting), "api_repl_accept_same_generation_same_timestamp");

  apiIncoming.setGeneration = 21;
  apiIncoming.updatedAtMs = 1;
  suite.expect(brain.shouldAcceptApiCredentialSetReplication(apiIncoming, &apiExisting), "api_repl_accept_newer_generation");
}

static void testCredentialBundleBuildAndApply(TestSuite& suite)
{
  TestBrain brain;

  DeploymentPlan deploymentPlan;
  deploymentPlan.config.applicationID = 6;
  deploymentPlan.hasTlsIssuancePolicy = true;
  deploymentPlan.tlsIssuancePolicy.applicationID = 6;
  deploymentPlan.tlsIssuancePolicy.enablePerContainerLeafs = true;
  deploymentPlan.tlsIssuancePolicy.leafValidityDays = 15;
  deploymentPlan.tlsIssuancePolicy.identityNames.push_back("inbound_server_tls"_ctv);
  deploymentPlan.tlsIssuancePolicy.dnsSans.push_back("nametag.social"_ctv);
  deploymentPlan.tlsIssuancePolicy.dnsSans.push_back("dev.nametag.social"_ctv);
  deploymentPlan.tlsIssuancePolicy.ipSans.push_back(IPAddress("10.0.0.18", false));
  deploymentPlan.tlsIssuancePolicy.ipSans.push_back(IPAddress("fd7a:115c:a1e0::18", true));
  deploymentPlan.hasApiCredentialPolicy = true;
  deploymentPlan.apiCredentialPolicy.applicationID = 6;
  deploymentPlan.apiCredentialPolicy.requiredCredentialNames.push_back("telnyx_bearer"_ctv);
  deploymentPlan.apiCredentialPolicy.requiredCredentialNames.push_back("cloudflare_dns"_ctv);
  deploymentPlan.apiCredentialPolicy.requiredCredentialNames.push_back("route53_dns"_ctv);
  deploymentPlan.apiCredentialPolicy.requiredCredentialNames.push_back("missing_name"_ctv);
  deploymentPlan.apiCredentialPolicy.refreshPushEnabled = true;
  Wormhole dnsWormhole = {};
  dnsWormhole.name = "api"_ctv;
  dnsWormhole.hasDNSConfig = true;
  dnsWormhole.dns.credentialName = "route53_dns"_ctv;
  deploymentPlan.wormholes.push_back(dnsWormhole);

  ApplicationApiCredentialSet set;
  set.applicationID = 6;
  set.setGeneration = 42;

  ApiCredential telnyx;
  telnyx.name.assign("telnyx_bearer"_ctv);
  telnyx.provider.assign("telnyx"_ctv);
  telnyx.generation = 2;
  telnyx.material.assign("secret-token"_ctv);
  set.credentials.push_back(telnyx);

  ApiCredential unrelated;
  unrelated.name.assign("other_provider_key"_ctv);
  unrelated.provider.assign("other"_ctv);
  unrelated.generation = 8;
  unrelated.material.assign("other-secret"_ctv);
  set.credentials.push_back(unrelated);

  ApiCredential scopedDNS;
  scopedDNS.name.assign("cloudflare_dns"_ctv);
  scopedDNS.provider.assign("cloudflare"_ctv);
  scopedDNS.generation = 3;
  scopedDNS.material.assign("dns-secret"_ctv);
  scopedDNS.metadata.insert_or_assign("dnsScope"_ctv, "native-zone"_ctv);
  scopedDNS.metadata.insert_or_assign("dnsZones"_ctv, "example.com"_ctv);
  set.credentials.push_back(scopedDNS);

  ApiCredential wormholeDNS;
  wormholeDNS.name.assign("route53_dns"_ctv);
  wormholeDNS.provider.assign("route53"_ctv);
  wormholeDNS.generation = 4;
  wormholeDNS.material.assign("route53-secret"_ctv);
  set.credentials.push_back(wormholeDNS);

  brain.apiCredentialSetsByApp.insert_or_assign(set.applicationID, set);

  ApplicationTlsVaultFactory factory = {};
  factory.applicationID = 6;
  factory.factoryGeneration = 77;
  factory.defaultLeafValidityDays = 15;
  String failure = {};
  suite.expect(generateApplicationTlsFactory(factory, failure, CryptoScheme::p256), "bundle_build_generate_tls_factory");
  suite.expect(failure.size() == 0, "bundle_build_generate_tls_factory_no_failure");
  brain.tlsVaultFactoriesByApp.insert_or_assign(factory.applicationID, factory);

  ContainerView container;
  CredentialBundle bundle;

  bool produced = brain.buildCredentialBundleForContainer(deploymentPlan, container, bundle);
  suite.expect(produced, "bundle_build_produced");
  suite.expect(bundle.apiCredentials.size() == 1, "bundle_build_only_required_api_credentials");
  suite.expect(bundle.apiCredentials[0].name.equal("telnyx_bearer"_ctv), "bundle_build_selected_required_name");
  suite.expect(bundle.bundleGeneration == 77, "bundle_build_generation_from_tls_factory");
  suite.expect(bundle.tlsIdentities.size() == 1, "bundle_build_generates_tls_identity");
  suite.expect(bundle.tlsIdentities[0].name.equal("inbound_server_tls"_ctv), "bundle_build_tls_identity_name");
  suite.expect(bundle.tlsIdentities[0].certPem.size() > 0, "bundle_build_tls_identity_cert");
  suite.expect(bundle.tlsIdentities[0].keyPem.size() > 0, "bundle_build_tls_identity_key");
  suite.expect(bundle.tlsIdentities[0].chainPem.size() > 0, "bundle_build_tls_identity_chain");
  suite.expect(bundle.tlsIdentities[0].dnsSans.size() == 2, "bundle_build_tls_identity_dns_sans");
  suite.expect(bundle.tlsIdentities[0].ipSans.size() == 2, "bundle_build_tls_identity_ip_sans");
  suite.expect(certificateHasDnsSan(bundle.tlsIdentities[0].certPem, "nametag.social"_ctv), "bundle_build_tls_cert_dns_san");
  suite.expect(certificateHasIpSan(bundle.tlsIdentities[0].certPem, IPAddress("10.0.0.18", false)), "bundle_build_tls_cert_ipv4_san");
  suite.expect(certificateHasIpSan(bundle.tlsIdentities[0].certPem, IPAddress("fd7a:115c:a1e0::18", true)), "bundle_build_tls_cert_ipv6_san");

  ContainerPlan containerPlan;
  brain.applyCredentialsToContainerPlan(deploymentPlan, container, containerPlan);
  suite.expect(containerPlan.hasCredentialBundle, "apply_credentials_sets_bundle_flag");
  suite.expect(containerPlan.credentialBundle.apiCredentials.size() == 1, "apply_credentials_copies_bundle");
  suite.expect(containerPlan.credentialBundle.tlsIdentities.size() == 1, "apply_credentials_copies_tls_bundle");
  suite.expect(containerPlan.credentialBundle.bundleGeneration == 77, "apply_credentials_copies_generation");

  Machine machine = {};
  machine.uuid = uint128_t(0x6006);
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 6;
  machine.neuron.connected = true;
  ContainerView liveContainer = {};
  liveContainer.uuid = uint128_t(0x6007);
  liveContainer.machine = &machine;
  liveContainer.deploymentID = deploymentPlan.config.deploymentID();
  liveContainer.state = ContainerState::healthy;
  ApplicationDeployment deployment = {};
  deployment.plan = deploymentPlan;
  deployment.containers.insert(&liveContainer);
  brain.deployments.insert_or_assign(deploymentPlan.config.deploymentID(), &deployment);
  Vector<String> updatedNames = {};
  updatedNames.push_back("telnyx_bearer"_ctv);
  updatedNames.push_back("cloudflare_dns"_ctv);
  updatedNames.push_back("route53_dns"_ctv);
  Vector<String> removedNames = {};
  brain.pushApiCredentialDeltaToLiveContainers(6, set, updatedNames, removedNames, "unit-api-refresh"_ctv);
  uint128_t refreshedContainer = {};
  CredentialDelta delta = {};
  suite.expect(extractQueuedCredentialDelta(machine, refreshedContainer, delta), "api_credential_delta_filters_dns_credentials");
  suite.expect(delta.updatedApi.size() == 1 && delta.updatedApi[0].name.equal("telnyx_bearer"_ctv), "api_credential_delta_delivers_only_app_credential");
  suite.expect(stringVectorContains(delta.removedApiNames, "cloudflare_dns"_ctv) && stringVectorContains(delta.removedApiNames, "route53_dns"_ctv), "api_credential_delta_removes_dns_credentials");
  brain.deployments.erase(deploymentPlan.config.deploymentID());

  DeploymentPlan noPolicyPlan;
  ContainerPlan noPolicyContainerPlan;
  brain.applyCredentialsToContainerPlan(noPolicyPlan, container, noPolicyContainerPlan);
  suite.expect(noPolicyContainerPlan.hasCredentialBundle == false, "apply_credentials_clears_bundle_without_policy");
  suite.expect(noPolicyContainerPlan.credentialBundle.apiCredentials.size() == 0, "apply_credentials_empty_without_policy");

  DeploymentPlan resumptionPlan = makeDeploymentPlan(6, 909);
  resumptionPlan.wormholes.push_back(makeTlsResumptionTestWormhole());

  ContainerView resumptionContainerA;
  resumptionContainerA.uuid = uint128_t(0xA001);
  CredentialBundle resumptionBundleA;
  suite.expect(brain.buildCredentialBundleForContainer(resumptionPlan, resumptionContainerA, resumptionBundleA), "bundle_build_resumption_produced");
  suite.expect(resumptionBundleA.tlsIdentities.size() == 0, "bundle_build_resumption_no_tls_identity");
  suite.expect(resumptionBundleA.apiCredentials.size() == 0, "bundle_build_resumption_no_api_credential");
  suite.expect(resumptionBundleA.tlsResumptionSnapshots.size() == 1, "bundle_build_resumption_snapshot_count");
  suite.expect(resumptionBundleA.tlsResumptionSnapshots[0].wormholeName.equal("public-api-quic"_ctv), "bundle_build_resumption_snapshot_wormhole_name");
  suite.expect(resumptionBundleA.tlsResumptionSnapshots[0].keyRing.size() == 1, "bundle_build_resumption_snapshot_key_ring_count");
  suite.expect(resumptionBundleA.tlsResumptionSnapshots[0].keyRing[0].role == TlsResumptionKeyRole::acceptOnly, "bundle_build_resumption_initial_epoch_accept_only");
  suite.expect(resumptionBundleA.bundleGeneration == resumptionBundleA.tlsResumptionSnapshots[0].generation, "bundle_build_resumption_generation_matches_snapshot");

  ContainerView resumptionContainerB;
  resumptionContainerB.uuid = uint128_t(0xA002);
  CredentialBundle resumptionBundleB;
  suite.expect(brain.buildCredentialBundleForContainer(resumptionPlan, resumptionContainerB, resumptionBundleB), "bundle_build_resumption_second_container_produced");
  suite.expect(resumptionBundleB.tlsResumptionSnapshots.size() == 1, "bundle_build_resumption_second_container_snapshot_count");
  suite.expect(resumptionBundleA.tlsResumptionSnapshots[0].generation == resumptionBundleB.tlsResumptionSnapshots[0].generation, "bundle_build_resumption_reuses_generation");
  suite.expect(resumptionBundleA.tlsResumptionSnapshots[0].keyRing.size() == 1 && resumptionBundleB.tlsResumptionSnapshots[0].keyRing.size() == 1 && prodigyTlsResumptionKeyEpochsEqual(resumptionBundleA.tlsResumptionSnapshots[0].keyRing[0], resumptionBundleB.tlsResumptionSnapshots[0].keyRing[0]), "bundle_build_resumption_reuses_key_epoch");

  ContainerPlan resumptionContainerPlan;
  brain.applyCredentialsToContainerPlan(resumptionPlan, resumptionContainerA, resumptionContainerPlan);
  suite.expect(resumptionContainerPlan.hasCredentialBundle, "apply_credentials_resumption_sets_bundle_flag");
  suite.expect(resumptionContainerPlan.credentialBundle.tlsResumptionSnapshots.size() == 1, "apply_credentials_resumption_copies_snapshot");
}

static void testTlsResumptionRotationAckCoverage(TestSuite& suite)
{
  TestBrain brain;
  DeploymentPlan plan = makeDeploymentPlan(6, 910);
  Wormhole wormhole = makeTlsResumptionTestWormhole();
  plan.wormholes.push_back(wormhole);

  ApplicationDeployment deployment = {};
  deployment.plan = plan;
  brain.deployments.insert_or_assign(plan.config.deploymentID(), &deployment);

  ContainerView containerA = {};
  containerA.uuid = uint128_t(0xB001);
  containerA.deploymentID = plan.config.deploymentID();
  containerA.state = ContainerState::healthy;
  ContainerView containerB = {};
  containerB.uuid = uint128_t(0xB002);
  containerB.deploymentID = plan.config.deploymentID();
  containerB.state = ContainerState::healthy;
  ContainerView containerScheduled = {};
  containerScheduled.uuid = uint128_t(0xB003);
  containerScheduled.deploymentID = plan.config.deploymentID();
  containerScheduled.state = ContainerState::scheduled;
  ContainerView containerRestarting = {};
  containerRestarting.uuid = uint128_t(0xB004);
  containerRestarting.deploymentID = plan.config.deploymentID();
  containerRestarting.state = ContainerState::crashedRestarting;
  deployment.containers.insert(&containerA);
  deployment.containers.insert(&containerB);
  deployment.containers.insert(&containerScheduled);
  deployment.containers.insert(&containerRestarting);
  brain.containers.insert_or_assign(containerA.uuid, &containerA);
  brain.containers.insert_or_assign(containerB.uuid, &containerB);
  brain.containers.insert_or_assign(containerScheduled.uuid, &containerScheduled);
  brain.containers.insert_or_assign(containerRestarting.uuid, &containerRestarting);

  String failure = {};
  auto currentSnapshot = [&]() -> TlsResumptionSnapshot * {
    return brain.mutableTlsResumptionSnapshotForWormhole(plan.config.deploymentID(), plan.wormholes[0].name);
  };
  auto coverageIs = [&](bool expected, const char *label) {
    suite.expect(brain.tlsResumptionAckCoverageSatisfied(plan, plan.wormholes[0], &failure) == expected, label);
  };
  auto recordAck = [&](ContainerView& container, uint64_t generation, bool success = true) -> bool {
    TlsResumptionApplyAck ack = makeTlsResumptionAck(plan.wormholes[0].name, generation);
    ack.results[0].success = success;
    if (success == false)
    {
      ack.results[0].failureReason.assign("registry rejected snapshot"_ctv);
    }
    return brain.recordTlsResumptionApplyAck(container.uuid, ack);
  };
  auto expectAck = [&](ContainerView& container, uint64_t generation, bool expected, const char *label, bool success = true) {
    suite.expect(recordAck(container, generation, success) == expected, label);
  };
  auto expectRole = [&](uint64_t generation, TlsResumptionKeyRole role, const char *label) {
    suite.expect(tlsResumptionSnapshotHasEpochRole(currentSnapshot(), generation, role), label);
  };

  TlsResumptionSnapshot *snapshot = brain.beginTlsResumptionAcceptOnlyRollout(plan, plan.wormholes[0], 1'700'000'100'000, false, &failure);
  suite.expect(snapshot != nullptr, "resumption_rotation_initial_rollout_snapshot");
  suite.expect(failure.size() == 0, "resumption_rotation_initial_rollout_no_failure");
  suite.expect(snapshot != nullptr && snapshot->keyRing.size() == 1, "resumption_rotation_initial_key_count");
  suite.expect(snapshot != nullptr && snapshot->keyRing[0].role == TlsResumptionKeyRole::acceptOnly, "resumption_rotation_initial_accept_only");
  suite.expect(snapshot != nullptr && prodigyTlsResumptionEpochPhase(snapshot->keyRing[0]) == 0, "resumption_rotation_initial_phase0");
  const uint64_t firstGeneration = snapshot != nullptr ? snapshot->generation : 0;

  coverageIs(false, "resumption_rotation_blocks_without_acks");
  suite.expect(brain.promoteTlsResumptionIssueEpochIfAcked(plan, plan.wormholes[0], 1'700'000'100'100, false, &failure) == false, "resumption_rotation_does_not_promote_without_acks");

  expectAck(containerA, firstGeneration, true, "resumption_rotation_records_first_ack");
  coverageIs(false, "resumption_rotation_blocks_partial_ack");
  suite.expect(brain.advanceTlsResumptionLifecycleForDeployment(plan, 1'700'000'100'250, false, false) == 0, "resumption_rotation_auto_promotion_blocks_partial_ack");

  expectAck(containerB, firstGeneration > 0 ? firstGeneration - 1 : 0, false, "resumption_rotation_ignores_stale_ack");
  coverageIs(false, "resumption_rotation_stale_ack_not_coverage");
  expectAck(containerB, firstGeneration, true, "resumption_rotation_records_failure_ack", false);
  coverageIs(false, "resumption_rotation_failure_ack_blocks");
  expectAck(containerB, firstGeneration, true, "resumption_rotation_records_second_success_ack");
  coverageIs(true, "resumption_rotation_coverage_after_all_success");
  containerScheduled.state = ContainerState::healthy;
  coverageIs(false, "resumption_rotation_scheduled_container_joining_gate_requires_ack");
  expectAck(containerScheduled, firstGeneration, true, "resumption_rotation_records_scheduled_join_ack");
  coverageIs(true, "resumption_rotation_scheduled_join_ack_satisfies_gate");
  containerScheduled.state = ContainerState::scheduled;
  containerRestarting.state = ContainerState::healthy;
  coverageIs(false, "resumption_rotation_restarted_container_joining_gate_requires_ack");
  expectAck(containerRestarting, firstGeneration, true, "resumption_rotation_records_restarted_join_ack");
  coverageIs(true, "resumption_rotation_restarted_join_ack_satisfies_gate");
  containerRestarting.state = ContainerState::crashedRestarting;
  brain.restoreTlsResumptionSnapshotsByWormhole(brain.captureTlsResumptionSnapshotsByWormhole(), true);
  coverageIs(true, "resumption_rotation_restore_preserves_matching_acks");
  suite.expect(brain.advanceTlsResumptionLifecycleForDeployment(plan, 1'700'000'100'600, false, false) == 1, "resumption_rotation_auto_promotes_after_coverage");

  TlsResumptionSnapshot *promoted = currentSnapshot();
  suite.expect(promoted != nullptr && promoted->keyRing.size() == 1 && promoted->keyRing[0].role == TlsResumptionKeyRole::issueAndAccept, "resumption_rotation_promoted_issue_epoch");
  suite.expect(promoted != nullptr && promoted->keyRing[0].issueUntilMs > 1'700'000'100'600, "resumption_rotation_sets_issue_until");
  suite.expect(
      promoted != nullptr &&
          brain.pushTlsResumptionUpdateToLiveContainers(plan, promoted, nullptr, promoted->generation, "unit-test"_ctv) == 4,
      "resumption_rotation_delta_attempts_all_refreshable_containers");

  ContainerView lateScheduled = {};
  lateScheduled.uuid = uint128_t(0xB005);
  lateScheduled.deploymentID = plan.config.deploymentID();
  lateScheduled.state = ContainerState::scheduled;
  ContainerPlan startupPlan = {};
  brain.applyCredentialsToContainerPlan(plan, lateScheduled, startupPlan);
  suite.expect(
      startupPlan.hasCredentialBundle &&
          startupPlan.credentialBundle.tlsResumptionSnapshots.size() == 1 &&
          startupPlan.credentialBundle.tlsResumptionSnapshots[0].generation == firstGeneration &&
          tlsResumptionSnapshotHasEpochRole(&startupPlan.credentialBundle.tlsResumptionSnapshots[0], firstGeneration, TlsResumptionKeyRole::issueAndAccept),
      "resumption_rotation_late_scheduled_startup_gets_promoted_bundle");

  TlsResumptionSnapshot *next = brain.beginTlsResumptionAcceptOnlyRollout(plan, plan.wormholes[0], 1'700'000'101'000, false, &failure);
  suite.expect(next != nullptr, "resumption_rotation_next_rollout_snapshot");
  const uint64_t secondGeneration = next != nullptr ? next->generation : 0;
  suite.expect(secondGeneration > firstGeneration, "resumption_rotation_next_generation_increases");
  suite.expect(next != nullptr && next->keyRing.size() == 2, "resumption_rotation_next_keeps_old_epoch");
  suite.expect(tlsResumptionSnapshotHasEpochRole(next, secondGeneration, TlsResumptionKeyRole::acceptOnly, 1), "resumption_rotation_next_accept_only_phase1");
  coverageIs(false, "resumption_rotation_next_rollout_clears_old_acks");
  expectAck(containerA, firstGeneration, false, "resumption_rotation_old_generation_ack_ignored_after_next");
  expectAck(containerA, secondGeneration, true, "resumption_rotation_records_next_ack_a");
  expectAck(containerB, secondGeneration, true, "resumption_rotation_records_next_ack_b");
  suite.expect(brain.promoteTlsResumptionIssueEpochIfAcked(plan, plan.wormholes[0], 1'700'000'101'400, false, &failure), "resumption_rotation_promotes_next_after_coverage");

  expectRole(firstGeneration, TlsResumptionKeyRole::acceptOnly, "resumption_rotation_old_issue_epoch_demoted");
  expectRole(secondGeneration, TlsResumptionKeyRole::issueAndAccept, "resumption_rotation_new_epoch_issue_and_accept");

  suite.expect(setTlsResumptionEpochAcceptUntilMs(currentSnapshot(), firstGeneration, 1'700'000'101'450), "resumption_rotation_marks_old_epoch_expired");
  suite.expect(brain.retireExpiredTlsResumptionEpochs(plan, 1'700'000'101'451, false) == 1, "resumption_rotation_retires_expired_old_epoch");
  TlsResumptionSnapshot *retired = currentSnapshot();
  suite.expect(retired != nullptr && retired->keyRing.size() == 1, "resumption_rotation_retire_keeps_current_epoch");
  suite.expect(tlsResumptionSnapshotHasEpoch(retired, firstGeneration) == false, "resumption_rotation_expired_old_epoch_removed");
  suite.expect(tlsResumptionSnapshotHasEpoch(retired, secondGeneration), "resumption_rotation_retire_keeps_new_generation");

  suite.expect(setTlsResumptionEpochIssueUntilMs(retired, secondGeneration, 1'700'000'101'500), "resumption_rotation_expires_issue_epoch");
  suite.expect(brain.advanceTlsResumptionLifecycleForDeployment(plan, 1'700'000'101'501, true, false) == 1, "resumption_rotation_scheduler_starts_next_rollout");
  TlsResumptionSnapshot *scheduled = currentSnapshot();
  const uint64_t thirdGeneration = scheduled != nullptr ? scheduled->generation : 0;
  suite.expect(thirdGeneration > secondGeneration, "resumption_rotation_scheduler_generation_increases");
  suite.expect(scheduled != nullptr && scheduled->keyRing.size() == 2, "resumption_rotation_scheduler_keeps_old_for_accept");
  suite.expect(tlsResumptionSnapshotHasEpoch(scheduled, secondGeneration), "resumption_rotation_scheduler_old_epoch_present");
  suite.expect(tlsResumptionSnapshotHasEpochRole(scheduled, thirdGeneration, TlsResumptionKeyRole::acceptOnly, 0), "resumption_rotation_scheduler_new_epoch_accept_only_phase0");
  suite.expect(brain.advanceTlsResumptionLifecycleForDeployment(plan, 1'700'000'101'550, false, false) == 0, "resumption_rotation_scheduler_blocks_without_new_acks");

  expectAck(containerA, thirdGeneration, true, "resumption_rotation_scheduler_records_ack_a");
  expectAck(containerB, thirdGeneration, true, "resumption_rotation_scheduler_records_ack_b");
  suite.expect(brain.advanceTlsResumptionLifecycleForDeployment(plan, 1'700'000'101'580, false, false) == 1, "resumption_rotation_scheduler_promotes_after_acks");
  expectRole(secondGeneration, TlsResumptionKeyRole::acceptOnly, "resumption_rotation_scheduler_demotes_previous_issue");
  expectRole(thirdGeneration, TlsResumptionKeyRole::issueAndAccept, "resumption_rotation_scheduler_promotes_new_issue");
}

static void testBrainHandlerReplicationPaths(TestSuite& suite)
{
  TestBrain brain;
  NoopBrainIaaS iaas;
  BrainView peer;
  brain.iaas = &iaas;
  brain.noMasterYet = false;
  String failure;
  String messageBuffer;

  String reserveFailure;
  suite.expect(brain.reserveApplicationIDMapping("ServiceReplicaApp"_ctv, 41'000, &reserveFailure), "replicate_service_reserve_app");

  ApplicationServiceIdentity existingService;
  existingService.applicationID = 41'000;
  existingService.serviceName.assign("clients"_ctv);
  existingService.serviceSlot = 1;
  existingService.kind = ApplicationServiceIdentity::Kind::stateful;
  reserveFailure.clear();
  suite.expect(brain.reserveApplicationServiceMapping(existingService, &reserveFailure), "replicate_service_seed_existing");

  ApplicationServiceIdentity newerService;
  newerService.applicationID = 41'000;
  newerService.serviceName.assign("siblings"_ctv);
  newerService.serviceSlot = 2;
  newerService.kind = ApplicationServiceIdentity::Kind::stateful;
  {
    String serialized;
    BitseryEngine::serialize(serialized, newerService);
    Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateApplicationServiceReservation, serialized);
    brain.brainHandler(&peer, message);
  }
  ApplicationServiceIdentity replicatedService;
  suite.expect(brain.resolveReservedApplicationService(41'000, "siblings"_ctv, replicatedService), "replicate_service_accepts_new_mapping");
  suite.expect(replicatedService.serviceSlot == 2, "replicate_service_applies_slot");

  ApplicationTlsVaultFactory existingTls = {};
  existingTls.applicationID = 7;
  existingTls.factoryGeneration = 5;
  existingTls.updatedAtMs = 200;
  existingTls.defaultLeafValidityDays = 15;
  existingTls.keySourceMode = 1;
  existingTls.scheme = uint8_t(CryptoScheme::ed25519);
  suite.expect(generateApplicationTlsFactory(existingTls, failure), "replicate_tls_generate_existing_factory");
  brain.tlsVaultFactoriesByApp.insert_or_assign(existingTls.applicationID, existingTls);

  ApplicationTlsVaultFactory staleTls = existingTls;
  staleTls.factoryGeneration = 4;
  staleTls.updatedAtMs = 999;
  {
    String serialized;
    BitseryEngine::serialize(serialized, staleTls);
    Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateTlsVaultFactory, serialized);
    brain.brainHandler(&peer, message);
  }
  suite.expect(brain.tlsVaultFactoriesByApp[7].factoryGeneration == 5, "replicate_tls_rejects_stale_update");
  suite.expect(brain.persistCalls == 1, "replicate_tls_rejects_stale_update_without_persist");

  ApplicationTlsVaultFactory newerTls = existingTls;
  newerTls.factoryGeneration = 6;
  newerTls.updatedAtMs = 1;
  newerTls.defaultLeafValidityDays = 30;
  {
    String serialized;
    BitseryEngine::serialize(serialized, newerTls);
    Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateTlsVaultFactory, serialized);
    brain.brainHandler(&peer, message);
  }
  suite.expect(brain.tlsVaultFactoriesByApp[7].factoryGeneration == 6, "replicate_tls_accepts_newer_generation");
  suite.expect(brain.tlsVaultFactoriesByApp[7].defaultLeafValidityDays == 30, "replicate_tls_applies_payload");
  suite.expect(brain.persistCalls == 2, "replicate_tls_persists_accepted_update");

  ApplicationApiCredentialSet existingApi = {};
  existingApi.applicationID = 7;
  existingApi.setGeneration = 10;
  existingApi.updatedAtMs = 300;
  brain.apiCredentialSetsByApp.insert_or_assign(existingApi.applicationID, existingApi);

  ApplicationApiCredentialSet staleApi = existingApi;
  staleApi.setGeneration = 9;
  staleApi.updatedAtMs = 999;
  {
    String serialized;
    BitseryEngine::serialize(serialized, staleApi);
    Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateApiCredentialSet, serialized);
    brain.brainHandler(&peer, message);
  }
  suite.expect(brain.apiCredentialSetsByApp[7].setGeneration == 10, "replicate_api_rejects_stale_update");
  suite.expect(brain.persistCalls == 2, "replicate_api_rejects_stale_update_without_persist");

  ApplicationApiCredentialSet newerApi = existingApi;
  newerApi.setGeneration = 11;
  newerApi.updatedAtMs = 1;
  ApiCredential credential;
  credential.name.assign("apns_client_tls"_ctv);
  credential.provider.assign("apple"_ctv);
  credential.generation = 3;
  credential.material.assign("pem-bytes"_ctv);
  newerApi.credentials.push_back(credential);
  {
    String serialized;
    BitseryEngine::serialize(serialized, newerApi);
    Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateApiCredentialSet, serialized);
    brain.brainHandler(&peer, message);
  }
  suite.expect(brain.apiCredentialSetsByApp[7].setGeneration == 11, "replicate_api_accepts_newer_generation");
  suite.expect(brain.apiCredentialSetsByApp[7].credentials.size() == 1, "replicate_api_applies_payload");
  suite.expect(brain.persistCalls == 3, "replicate_api_persists_accepted_update");

  BrainConfig replicatedConfig = {};
  replicatedConfig.clusterUUID = 0x7788;
  replicatedConfig.bootstrapSshUser = "root"_ctv;
  replicatedConfig.bootstrapSshPrivateKeyPath = "/tmp/replica-bootstrap-key"_ctv;
  replicatedConfig.remoteProdigyPath = "/opt/prodigy"_ctv;
  replicatedConfig.controlSocketPath = "/run/prodigy/control.sock"_ctv;
  String replicationFailure = {};
  suite.expect(
      prodigyReadSSHKeyPackageFromPrivateKeyPath(
          prodigyTestBootstrapSeedSSHPrivateKeyPath(),
          replicatedConfig.bootstrapSshKeyPackage,
          &replicationFailure),
      "replicate_brain_config_reads_bootstrap_ssh_key_package");
  suite.expect(
      prodigyReadSSHKeyPackageFromPrivateKeyPath(
          prodigyTestSSHDHostPrivateKeyPath(),
          replicatedConfig.bootstrapSshHostKeyPackage,
          &replicationFailure),
      "replicate_brain_config_reads_bootstrap_ssh_host_key_package");
  {
    String serialized;
    BitseryEngine::serialize(serialized, replicatedConfig);
    Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateBrainConfig, serialized);
    brain.brainHandler(&peer, message);
  }
  suite.expect(brain.brainConfig.clusterUUID == replicatedConfig.clusterUUID, "replicate_brain_config_applies_payload");
  suite.expect(brain.brainConfig.bootstrapSshUser.equals(replicatedConfig.bootstrapSshUser), "replicate_brain_config_applies_bootstrap_user");
  suite.expect(brain.brainConfig.bootstrapSshKeyPackage == replicatedConfig.bootstrapSshKeyPackage, "replicate_brain_config_applies_bootstrap_key_package");
  suite.expect(brain.brainConfig.bootstrapSshHostKeyPackage == replicatedConfig.bootstrapSshHostKeyPackage, "replicate_brain_config_applies_bootstrap_host_key_package");
  suite.expect(brain.clusterOwnershipCalls == 1, "replicate_brain_config_claims_cluster_ownership");
  suite.expect(brain.lastClaimedClusterUUID == replicatedConfig.clusterUUID, "replicate_brain_config_claims_expected_cluster_uuid");
  suite.expect(brain.persistCalls == 4, "replicate_brain_config_persists_on_apply");

  {
    Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateApplicationIDReservation, uint16_t(40'001), "ReplicaApp"_ctv);
    brain.brainHandler(&peer, message);
  }
  auto replicatedReservationIt = brain.reservedApplicationIDsByName.find("ReplicaApp"_ctv);
  suite.expect(replicatedReservationIt != brain.reservedApplicationIDsByName.end() && replicatedReservationIt->second == 40'001, "replicate_application_id_reservation_applies_payload");
  suite.expect(brain.persistCalls == 5, "replicate_application_id_reservation_persists_on_apply");

  DeploymentPlan plan = makeDeploymentPlan(40'001, 101);
  {
    String serialized;
    BitseryEngine::serialize(serialized, plan);
    Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateDeployment, serialized, ""_ctv);
    brain.brainHandler(&peer, message);
  }
  suite.expect(brain.deploymentPlans.find(plan.config.deploymentID()) != brain.deploymentPlans.end(), "replicate_deployment_stores_plan");
  suite.expect(brain.persistCalls == 6, "replicate_deployment_persists_on_apply");
  suite.expect(peer.wBuffer.size() > 0, "replicate_deployment_queues_echo");

  String cullResumptionWormholeName = {};
  cullResumptionWormholeName.assign("public-api-quic"_ctv);
  TlsResumptionSnapshot cullResumptionSnapshot = {};
  cullResumptionSnapshot.generation = 12;
  cullResumptionSnapshot.wormholeName = cullResumptionWormholeName;
  brain.tlsResumptionStateByDeployment[plan.config.deploymentID()].wormholes[cullResumptionWormholeName].snapshot = cullResumptionSnapshot;
  BrainTlsResumptionAckState cullAck = {};
  uint128_t cullContainerUUID = uint128_t(0xC011);
  cullAck.generation = cullResumptionSnapshot.generation;
  cullAck.success = true;
  brain.tlsResumptionStateByDeployment[plan.config.deploymentID()].wormholes[cullResumptionWormholeName].acksByContainer.insert_or_assign(cullContainerUUID, cullAck);

  peer.wBuffer.clear();
  {
    Message *message = buildBrainMessage(messageBuffer, BrainTopic::cullDeployment, plan.config.deploymentID());
    brain.brainHandler(&peer, message);
  }
  suite.expect(brain.deploymentPlans.find(plan.config.deploymentID()) == brain.deploymentPlans.end(), "cull_deployment_erases_plan");
  suite.expect(brain.tlsResumptionStateForWormhole(plan.config.deploymentID(), cullResumptionWormholeName) == nullptr, "cull_deployment_erases_tls_resumption_state");
  suite.expect(brain.persistCalls == 7, "cull_deployment_persists_on_apply");

  ProdigyMasterAuthorityRuntimeState runtimeState = {};
  runtimeState.generation = 7;
  suite.expect(generateTransportAuthority(runtimeState.transportTLSAuthority, failure), "replicate_master_authority_generate_transport_authority");
  runtimeState.nextMintedClientTlsGeneration = 55;
  runtimeState.updateSelf.state = uint8_t(Brain::UpdateSelfState::waitingForRelinquishEchos);
  runtimeState.updateSelf.expectedEchos = 3;
  runtimeState.updateSelf.bundleEchos = 2;
  runtimeState.updateSelf.relinquishEchos = 1;
  runtimeState.updateSelf.plannedMasterPeerKey = 0x1234;
  runtimeState.updateSelf.pendingDesignatedMasterPeerKey = 0x5678;
  runtimeState.updateSelf.useStagedBundleOnly = true;
  runtimeState.updateSelf.bundleBlob.assign("bundle"_ctv);
  runtimeState.updateSelf.bundleEchoPeerKeys.push_back(0xAA);
  runtimeState.updateSelf.relinquishEchoPeerKeys.push_back(0xBB);
  ProdigyPersistentUpdateSelfFollowerBoot followerBoot = {};
  followerBoot.peerKey = 0xCC;
  followerBoot.bootNs = 77;
  runtimeState.updateSelf.followerBootNsByPeerKey.push_back(followerBoot);
  runtimeState.updateSelf.followerRebootedPeerKeys.push_back(0xDD);
  runtimeState.nextPendingAddMachinesOperationID = 3;
  ProdigyPendingAddMachinesOperation pendingOperation = {};
  pendingOperation.operationID = 2;
  pendingOperation.request.bootstrapSshUser.assign("root"_ctv);
  pendingOperation.request.controlSocketPath.assign("/run/prodigy/control.sock"_ctv);
  pendingOperation.request.clusterUUID = 0x2201;
  pendingOperation.plannedTopology.version = 9;
  pendingOperation.plannedTopology.machines.push_back(ClusterMachine {});
  pendingOperation.resumeAttempts = 1;
  pendingOperation.updatedAtMs = 12'345;
  pendingOperation.lastFailure.assign("waiting for resume"_ctv);
  runtimeState.pendingAddMachinesOperations.push_back(pendingOperation);

  PublicTlsCertificateState publicTls = {};
  publicTls.spec.applicationID = plan.config.applicationID;
  publicTls.spec.deploymentID = plan.config.deploymentID();
  publicTls.spec.wormholeName.assign("api"_ctv);
  publicTls.spec.identityName.assign("api-public"_ctv);
  publicTls.spec.domains.push_back("api.example.com"_ctv);
  publicTls.spec.issuer.assign("letsencrypt"_ctv);
  publicTls.spec.keyType.assign("ecdsa"_ctv);
  publicTls.spec.staging = true;
  publicTls.spec.dnsProvider.assign("cloudflare"_ctv);
  publicTls.spec.dnsCredentialName.assign("prod-dns"_ctv);
  publicTls.spec.dnsZone.assign("example.com"_ctv);
  publicTls.spec.dnsTTL = 60;
  publicTls.identity.name = publicTls.spec.identityName;
  publicTls.identity.generation = 3;
  publicTls.identity.notBeforeMs = 1'700'000'000'000;
  publicTls.identity.notAfterMs = 1'700'086'400'000;
  publicTls.identity.certPem.assign("cert"_ctv);
  publicTls.identity.keyPem.assign("key"_ctv);
  publicTls.identity.chainPem.assign("chain"_ctv);
  publicTls.identity.dnsSans.push_back("api.example.com"_ctv);
  publicTls.certbotCertName.assign("app40001-api"_ctv);
  publicTls.lineagePath.assign("/var/lib/prodigy/certbot/7788/config/live/app40001-api"_ctv);
  publicTls.generation = publicTls.identity.generation;
  publicTls.nextRenewAtMs = prodigyCertificateRenewAtMs(publicTls.identity.notBeforeMs, publicTls.identity.notAfterMs, publicTls.spec.renewAfterLifetimePermille);
  publicTls.lastAttemptMs = 1'700'010'000'000;
  publicTls.lastSuccessMs = 1'700'010'001'000;
  AcmeDNS01ChallengeState challenge = {};
  challenge.provider = publicTls.spec.dnsProvider;
  challenge.credentialName = publicTls.spec.dnsCredentialName;
  challenge.zone = publicTls.spec.dnsZone;
  challenge.name.assign("_acme-challenge.api.example.com."_ctv);
  challenge.validation.assign("token"_ctv);
  challenge.ttl = 60;
  publicTls.pendingDNS01Challenges.push_back(challenge);
  runtimeState.publicTlsCertificates.push_back(publicTls);

  PrivateTlsVaultLifecycleState privateTls = {};
  privateTls.applicationID = publicTls.spec.applicationID;
  privateTls.factoryGeneration = 6;
  privateTls.rootNotBeforeMs = 1'700'000'000'000;
  privateTls.rootNotAfterMs = 1'725'920'000'000;
  privateTls.intermediateNotBeforeMs = 1'700'000'000'000;
  privateTls.intermediateNotAfterMs = 1'708'640'000'000;
  privateTls.leafNotBeforeMs = 1'700'000'000'000;
  privateTls.leafNotAfterMs = 1'701'296'000'000;
  privateTls.leafNextRenewAtMs = prodigyCertificateRenewAtMs(privateTls.leafNotBeforeMs, privateTls.leafNotAfterMs, prodigyDefaultCertificateRenewAfterLifetimePermille);
  privateTls.nextRenewAtMs = prodigyEarliestPositiveMs(
      prodigyCertificateRenewAtMs(privateTls.intermediateNotBeforeMs, privateTls.intermediateNotAfterMs, prodigyDefaultCertificateRenewAfterLifetimePermille),
      privateTls.leafNextRenewAtMs);
  privateTls.lastAttemptMs = 1'700'020'000'000;
  privateTls.lastSuccessMs = 1'700'020'001'000;
  runtimeState.privateTlsVaultLifecycles.push_back(privateTls);
  {
    String serialized;
    BitseryEngine::serialize(serialized, runtimeState);
    Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateMasterAuthorityState, serialized);
    brain.brainHandler(&peer, message);
  }
  ProdigyMasterAuthorityRuntimeState expectedRuntimeState = runtimeState;
  expectedRuntimeState.updateSelf = {};
  suite.expect(brain.masterAuthorityRuntimeState == expectedRuntimeState, "replicate_master_authority_applies_runtime_state");
  suite.expect(brain.nextMintedClientTlsGeneration == runtimeState.nextMintedClientTlsGeneration, "replicate_master_authority_updates_client_tls_generation");
  suite.expect(brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.size() == 1, "replicate_master_authority_restores_pending_addmachines_operation");
  suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates.size() == 1 && prodigyPublicTlsCertificateStatesEqual(brain.masterAuthorityRuntimeState.publicTlsCertificates[0], publicTls), "replicate_master_authority_restores_public_tls_certificate_state");
  suite.expect(brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles.size() == 1 && prodigyPrivateTlsVaultLifecycleStatesEqual(brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles[0], privateTls), "replicate_master_authority_restores_private_tls_lifecycle_state");
  suite.expect(brain.masterAuthorityApplyCalls == 1, "replicate_master_authority_calls_apply_hook");
  suite.expect(brain.persistCalls == 8, "replicate_master_authority_persists_on_apply");

  {
    String serialized;
    BitseryEngine::serialize(serialized, runtimeState);
    Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateMasterAuthorityState, serialized);
    brain.brainHandler(&peer, message);
  }
  suite.expect(brain.masterAuthorityApplyCalls == 1, "replicate_master_authority_ignores_duplicate_state");
  suite.expect(brain.persistCalls == 8, "replicate_master_authority_duplicate_does_not_persist");

  Vector<ProdigyMetricSample> metricSamples;
  ProdigyMetricSample metric = {};
  metric.ms = 1'700'000'000'000;
  metric.deploymentID = plan.config.deploymentID();
  metric.containerUUID = 0x9911;
  metric.metricKey = ProdigyMetrics::runtimeContainerCpuUtilPctKey();
  metric.value = 87.0f;
  metricSamples.push_back(metric);
  {
    String serialized;
    BitseryEngine::serialize(serialized, metricSamples);
    Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateMetricsSnapshot, serialized);
    brain.brainHandler(&peer, message);
  }
  Vector<ProdigyMetricSample> exportedMetrics;
  brain.metrics.exportSamples(exportedMetrics);
  suite.expect(exportedMetrics.size() == 1 && exportedMetrics[0] == metric, "replicate_metrics_snapshot_imports_samples");
  suite.expect(brain.persistCalls == 9, "replicate_metrics_snapshot_persists_on_apply");
}

static void testReconcileStateReplicatesCredentialAndTlsState(TestSuite& suite)
{
  TestBrain brain;
  BrainView follower;
  brain.brainConfig.clusterUUID = 0x2201;

  const uint16_t appID = 45'000;
  String applicationName;
  applicationName.assign("PersistentApp"_ctv);
  brain.reservedApplicationIDsByName.insert_or_assign(applicationName, appID);
  brain.reservedApplicationNamesByID.insert_or_assign(appID, applicationName);

  ApplicationServiceIdentity serviceIdentity;
  serviceIdentity.applicationID = appID;
  serviceIdentity.serviceName.assign("clients"_ctv);
  serviceIdentity.serviceSlot = 1;
  serviceIdentity.kind = ApplicationServiceIdentity::Kind::stateful;
  String reserveFailure;
  suite.expect(brain.reserveApplicationServiceMapping(serviceIdentity, &reserveFailure), "reconcile_state_service_seed");

  ApplicationTlsVaultFactory tlsFactory;
  tlsFactory.applicationID = appID;
  tlsFactory.factoryGeneration = 77;
  tlsFactory.updatedAtMs = 111;
  tlsFactory.defaultLeafValidityDays = 21;
  tlsFactory.keySourceMode = 1;
  tlsFactory.scheme = uint8_t(CryptoScheme::ed25519);
  String failure;
  suite.expect(generateApplicationTlsFactory(tlsFactory, failure), "reconcile_state_generate_tls_factory");
  brain.tlsVaultFactoriesByApp.insert_or_assign(appID, tlsFactory);

  ApplicationApiCredentialSet credentialSet;
  credentialSet.applicationID = appID;
  credentialSet.setGeneration = 88;
  credentialSet.updatedAtMs = 222;
  ApiCredential credential;
  credential.name.assign("telnyx_bearer"_ctv);
  credential.provider.assign("telnyx"_ctv);
  credential.generation = 9;
  credential.material.assign("secret"_ctv);
  credentialSet.credentials.push_back(credential);
  brain.apiCredentialSetsByApp.insert_or_assign(appID, credentialSet);
  brain.nextMintedClientTlsGeneration = 66;
  brain.masterAuthorityRuntimeState.generation = 44;
  suite.expect(generateTransportAuthority(brain.masterAuthorityRuntimeState.transportTLSAuthority, failure), "reconcile_state_generate_transport_authority");
  brain.refreshMasterAuthorityRuntimeStateFromLiveFields();
  brain.recordContainerMetric(0x1001, 0x1002, ProdigyMetrics::runtimeContainerCpuUtilPctKey(), 1'700'000'000'000, 33.0);

  BrainReconcileStateRequest request = {};
  String serializedRequest = {};
  BitseryEngine::serialize(serializedRequest, request);
  String requestBuffer;
  Message *reconcileMessage = buildBrainMessage(requestBuffer, BrainTopic::reconcileState, serializedRequest);
  brain.brainHandler(&follower, reconcileMessage);

  bool foundReservation = false;
  bool foundServiceReservation = false;
  bool foundTlsFactory = false;
  bool foundApiSet = false;
  bool foundBrainConfig = false;
  bool foundMasterAuthority = false;
  bool foundMetricsSnapshot = false;

  forEachMessageInBuffer(follower.wBuffer, [&](Message *message) -> void {
    BrainTopic topic = BrainTopic(message->topic);
    uint8_t *args = message->args;

    if (topic == BrainTopic::replicateApplicationIDReservation)
    {
      uint16_t replicatedID = 0;
      Message::extractArg<ArgumentNature::fixed>(args, replicatedID);
      String replicatedName;
      Message::extractToStringView(args, replicatedName);

      if (replicatedID == appID && replicatedName.equal(applicationName))
      {
        foundReservation = true;
      }
    }
    else if (topic == BrainTopic::replicateApplicationServiceReservation)
    {
      String serializedIdentity;
      Message::extractToStringView(args, serializedIdentity);

      ApplicationServiceIdentity decoded;
      if (BitseryEngine::deserializeSafe(serializedIdentity, decoded) && decoded.applicationID == appID && decoded.serviceName.equal("clients"_ctv) && decoded.serviceSlot == 1)
      {
        foundServiceReservation = true;
      }
    }
    else if (topic == BrainTopic::replicateBrainConfig)
    {
      String serializedBrainConfig;
      Message::extractToStringView(args, serializedBrainConfig);

      BrainConfig decoded = {};
      if (BitseryEngine::deserializeSafe(serializedBrainConfig, decoded) && decoded.clusterUUID == brain.brainConfig.clusterUUID)
      {
        foundBrainConfig = true;
      }
    }
    else if (topic == BrainTopic::replicateTlsVaultFactory)
    {
      String serializedFactory;
      Message::extractToStringView(args, serializedFactory);

      ApplicationTlsVaultFactory decoded;
      if (BitseryEngine::deserializeSafe(serializedFactory, decoded) && decoded.applicationID == appID && decoded.factoryGeneration == 77)
      {
        foundTlsFactory = true;
      }
    }
    else if (topic == BrainTopic::replicateApiCredentialSet)
    {
      String serializedSet;
      Message::extractToStringView(args, serializedSet);

      ApplicationApiCredentialSet decoded;
      if (BitseryEngine::deserializeSafe(serializedSet, decoded) && decoded.applicationID == appID && decoded.setGeneration == 88)
      {
        foundApiSet = true;
      }
    }
    else if (topic == BrainTopic::replicateMasterAuthorityState)
    {
      String serializedRuntimeState;
      Message::extractToStringView(args, serializedRuntimeState);

      ProdigyMasterAuthorityRuntimeState decoded = {};
      if (BitseryEngine::deserializeSafe(serializedRuntimeState, decoded) && decoded.generation == brain.masterAuthorityRuntimeState.generation && decoded.nextMintedClientTlsGeneration == brain.masterAuthorityRuntimeState.nextMintedClientTlsGeneration)
      {
        foundMasterAuthority = true;
      }
    }
    else if (topic == BrainTopic::replicateMetricsSnapshot)
    {
      String serializedSamples;
      Message::extractToStringView(args, serializedSamples);

      Vector<ProdigyMetricSample> decoded;
      if (BitseryEngine::deserializeSafe(serializedSamples, decoded) && decoded.size() == 1)
      {
        foundMetricsSnapshot = true;
      }
    }
  });

  suite.expect(foundBrainConfig, "reconcile_state_emits_brain_config_replication");
  suite.expect(foundReservation, "reconcile_state_emits_application_id_reservation_replication");
  suite.expect(foundServiceReservation, "reconcile_state_emits_service_reservation_replication");
  suite.expect(foundTlsFactory, "reconcile_state_emits_tls_factory_replication");
  suite.expect(foundApiSet, "reconcile_state_emits_api_credential_set_replication");
  suite.expect(foundMasterAuthority, "reconcile_state_emits_master_authority_replication");
  suite.expect(foundMetricsSnapshot, "reconcile_state_emits_metrics_snapshot_replication");
}

static void testSystemContainerArtifactReplicationQueuesTypedBlob(TestSuite& suite)
{
  TestBrain brain;
  BrainView follower;
  follower.connected = true;
  follower.weConnectToIt = true;
  follower.isFixedFile = true;
  follower.fslot = 18;
  brain.brains.insert(&follower);

  String blob = prodigyDiscombobulatorMothershipTunnelProviderBlobHeaderText();
  blob.append("payload"_ctv);
  String sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv;

  brain.queueBrainSystemContainerArtifactReplicationForTest(sha256, blob.size(), blob);

  bool sawArtifact = false;
  forEachMessageInBuffer(follower.wBuffer, [&](Message *message) {
    if (BrainTopic(message->topic) != BrainTopic::replicateSystemContainerArtifact)
    {
      return;
    }

    uint8_t *args = message->args;
    String queuedSha256;
    uint64_t bytes = 0;
    String queuedBlob;
    Message::extractToStringView(args, queuedSha256);
    Message::extractArg<ArgumentNature::fixed>(args, bytes);
    Message::extractToStringView(args, queuedBlob);

    sawArtifact = queuedSha256.equal(sha256) && bytes == blob.size() && queuedBlob.equal(blob);
  });

  suite.expect(sawArtifact, "system_container_artifact_replication_queues_typed_blob");
}

static MothershipConnectivityRuntimeConfig makeTunnelRuntimeConnectivityConfig(void)
{
  MothershipConnectivityRuntimeConfig config = {};
  config.kind = MothershipConnectivityKind::tunnelProvider;
  config.tunnelProvider.artifactSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv;
  config.tunnelProvider.artifactBytes = 512;
  config.tunnelProvider.dialEndpoint = "control.example.net:443"_ctv;
  config.tunnelProvider.egressHost = "1.1.1.1"_ctv;
  config.tunnelProvider.egressPort = 443;
  return config;
}

static MothershipTunnelGatewayAuth makeTunnelGatewayAuth(void)
{
  MothershipTunnelGatewayClientAuth clientAuth = {};
  MothershipTunnelGatewayAuth auth = {};
  String failure = {};
  (void)mothershipGenerateTunnelGatewayAuth(clientAuth, auth, &failure);
  return auth;
}

static MothershipTunnelProviderDesiredState makeTunnelProviderDesiredState(const MothershipConnectivityRuntimeConfig& config, const MothershipTunnelGatewayAuth& auth)
{
  MothershipTunnelProviderDesiredState desired = {};
  desired.connectivity = config;
  desired.gatewayAuth = auth;
  return desired;
}

static MothershipTunnelProviderConfigureRequest makeTunnelProviderConfigureRequest(const MothershipConnectivityRuntimeConfig& config, const MothershipTunnelGatewayAuth& auth, const String& blob)
{
  MothershipTunnelProviderConfigureRequest request = {};
  request.desired = makeTunnelProviderDesiredState(config, auth);
  request.artifactBlob = blob;
  return request;
}

static void testMothershipTunnelProviderRuntimeSpecIsStrict(TestSuite& suite)
{
  MothershipConnectivityRuntimeConfig config = makeTunnelRuntimeConnectivityConfig();
  String failure = {};
  suite.expect(mothershipConnectivityRuntimeConfigValid(config, &failure), "mothership_tunnel_runtime_spec_valid");
  config.tunnelProvider.egressPort = 0;
  suite.expect(mothershipConnectivityRuntimeConfigValid(config, &failure) == false && failure.equal("mothership tunnel-provider egress endpoint invalid"_ctv), "mothership_tunnel_runtime_spec_rejects_empty_egress");
}

static void testMothershipTunnelProviderConfigureAppliesAtomicallyAndReplicates(TestSuite& suite)
{
  TestBrain brain;
  Mothership mothership;
  BrainView follower;
  String blob = prodigyDiscombobulatorMothershipTunnelProviderBlobHeaderText();
  blob.append("payload"_ctv);
  MothershipConnectivityRuntimeConfig config = makeTunnelRuntimeConnectivityConfig();
  String artifactSha256 = {};
  suite.require(prodigyComputeSHA256Hex(blob, artifactSha256), "mothership_tunnel_provider_configure_blob_sha");
  config.tunnelProvider.artifactSha256 = artifactSha256;
  config.tunnelProvider.artifactBytes = blob.size();
  MothershipTunnelGatewayAuth auth = makeTunnelGatewayAuth();
  suite.require(auth.configured(), "mothership_tunnel_provider_configure_auth_fixture_configured");
  brain.weAreMaster = true;
  brain.nBrains = 2;
  brain.brainConfig.clusterUUID = 0x7707;
  follower.connected = true;
  follower.weConnectToIt = true;
  follower.isFixedFile = true;
  follower.fslot = 18;
  brain.brains.insert(&follower);

  MothershipTunnelProviderConfigureRequest request = makeTunnelProviderConfigureRequest(config, auth, blob);
  String serialized = {};
  BitseryEngine::serialize(serialized, request);

  String messageBuffer;
  Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::configureMothershipTunnelProvider, serialized);
  brain.mothershipHandler(&mothership, message);

  suite.expect(brain.systemContainerStoreCalls == 1, "mothership_tunnel_provider_configure_stores_artifact_once");
  suite.expect(brain.lastStoredSystemContainerSha256.equal(config.tunnelProvider.artifactSha256), "mothership_tunnel_provider_configure_stores_sha256");
  suite.expect(brain.lastStoredSystemContainerBytes == blob.size(), "mothership_tunnel_provider_configure_stores_bytes");
  suite.expect(brain.lastStoredSystemContainerBlob.equal(blob), "mothership_tunnel_provider_configure_stores_blob");
  suite.expect(equalSerializedObjects(brain.mothershipConnectivity, config), "mothership_tunnel_provider_configure_applies_runtime_config");
  suite.expect(equalSerializedObjects(brain.mothershipTunnelGatewayAuth, auth), "mothership_tunnel_provider_configure_applies_gateway_auth");
  suite.expect(brain.persistCalls == 1, "mothership_tunnel_provider_configure_persists_master_snapshot");

  Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
  String serializedResponse = {};
  uint8_t *responseArgs = responseMessage->args;
  Message::extractToStringView(responseArgs, serializedResponse);
  MothershipResponse response = {};
  suite.expect(MothershipTopic(responseMessage->topic) == MothershipTopic::configureMothershipTunnelProvider, "mothership_tunnel_provider_configure_response_topic");
  suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response) && response.success, "mothership_tunnel_provider_configure_response_success");

  TestBrain malformedAuthBrain;
  malformedAuthBrain.brainConfig.clusterUUID = 0x7707;
  MothershipTunnelProviderDesiredState malformedDesired = makeTunnelProviderDesiredState(config, auth);
  malformedDesired.gatewayAuth.serverKeyPem.assign("not-a-key"_ctv);
  String malformedAuthFailure = {};
  suite.expect(malformedAuthBrain.applyMothershipTunnelProviderDesiredState(malformedDesired, false, &malformedAuthFailure) == false && malformedAuthFailure.equal("mothership tunnel gateway auth certificate material invalid"_ctv), "mothership_tunnel_provider_rejects_malformed_material");
  suite.expect(malformedAuthBrain.persistCalls == 0, "mothership_tunnel_provider_rejects_malformed_before_persist");

  bool sawArtifact = false;
  bool sawMasterAuthority = false;
  forEachMessageInBuffer(follower.wBuffer, [&](Message *queued) {
    uint8_t *args = queued->args;
    if (BrainTopic(queued->topic) == BrainTopic::replicateSystemContainerArtifact)
    {
      String queuedSha256 = {};
      uint64_t queuedBytes = 0;
      String queuedBlob = {};
      Message::extractToStringView(args, queuedSha256);
      Message::extractArg<ArgumentNature::fixed>(args, queuedBytes);
      Message::extractToStringView(args, queuedBlob);
      sawArtifact = queuedSha256.equal(config.tunnelProvider.artifactSha256) && queuedBytes == blob.size() && queuedBlob.equal(blob);
      return;
    }
    if (BrainTopic(queued->topic) == BrainTopic::replicateMasterAuthorityState)
    {
      String replicatedSerialized = {};
      Message::extractToStringView(args, replicatedSerialized);
      ProdigyMasterAuthorityRuntimeState replicated = {};
      sawMasterAuthority = BitseryEngine::deserializeSafe(replicatedSerialized, replicated) &&
                           equalSerializedObjects(replicated.mothershipTunnelProviderDesiredState.connectivity, config) &&
                           equalSerializedObjects(replicated.mothershipTunnelProviderDesiredState.gatewayAuth, auth);
    }
  });
  suite.expect(sawArtifact, "mothership_tunnel_provider_configure_replicates_artifact");
  suite.expect(sawMasterAuthority, "mothership_tunnel_provider_configure_replicates_master_authority_desired_state");
}

static void testMothershipTunnelProviderReconcileBackfillsDesiredStateAndArtifact(TestSuite& suite)
{
  TestBrain brain;
  BrainView peer;
  peer.connected = true;
  peer.weConnectToIt = true;
  peer.isFixedFile = true;
  peer.fslot = 18;
  brain.weAreMaster = true;
  brain.brainConfig.clusterUUID = 0x7707;

  String blob = prodigyDiscombobulatorMothershipTunnelProviderBlobHeaderText();
  blob.append("payload"_ctv);
  MothershipConnectivityRuntimeConfig config = makeTunnelRuntimeConnectivityConfig();
  String artifactSha256 = {};
  suite.require(prodigyComputeSHA256Hex(blob, artifactSha256), "mothership_tunnel_provider_reconcile_blob_sha");
  config.tunnelProvider.artifactSha256 = artifactSha256;
  config.tunnelProvider.artifactBytes = blob.size();
  MothershipTunnelGatewayAuth auth = makeTunnelGatewayAuth();
  suite.require(auth.configured(), "mothership_tunnel_provider_reconcile_auth_fixture_configured");

  String failure = {};
  suite.require(brain.applyMothershipTunnelProviderConfigureRequest(makeTunnelProviderConfigureRequest(config, auth, blob), false, &failure), "mothership_tunnel_provider_reconcile_configure");

  BrainReconcileStateRequest request = {};
  String serializedRequest = {};
  BitseryEngine::serialize(serializedRequest, request);
  String messageBuffer;
  Message *message = buildBrainMessage(messageBuffer, BrainTopic::reconcileState, serializedRequest);
  brain.brainHandler(&peer, message);

  bool sawArtifact = false;
  bool sawMasterAuthority = false;
  int artifactIndex = -1;
  int masterAuthorityIndex = -1;
  int index = 0;
  forEachMessageInBuffer(peer.wBuffer, [&](Message *queued) {
    uint8_t *args = queued->args;
    if (BrainTopic(queued->topic) == BrainTopic::replicateSystemContainerArtifact)
    {
      String queuedSha256 = {};
      uint64_t queuedBytes = 0;
      String queuedBlob = {};
      Message::extractToStringView(args, queuedSha256);
      Message::extractArg<ArgumentNature::fixed>(args, queuedBytes);
      Message::extractToStringView(args, queuedBlob);
      sawArtifact = queuedSha256.equal(config.tunnelProvider.artifactSha256) && queuedBytes == blob.size() && queuedBlob.equal(blob);
      artifactIndex = index;
    }
    else if (BrainTopic(queued->topic) == BrainTopic::replicateMasterAuthorityState)
    {
      String serializedState = {};
      ProdigyMasterAuthorityRuntimeState state = {};
      Message::extractToStringView(args, serializedState);
      sawMasterAuthority = BitseryEngine::deserializeSafe(serializedState, state) &&
                           equalSerializedObjects(state.mothershipTunnelProviderDesiredState.connectivity, config) &&
                           equalSerializedObjects(state.mothershipTunnelProviderDesiredState.gatewayAuth, auth);
      masterAuthorityIndex = index;
    }
    index += 1;
  });
  suite.expect(sawArtifact, "mothership_tunnel_provider_reconcile_sends_missing_artifact");
  suite.expect(sawMasterAuthority, "mothership_tunnel_provider_reconcile_sends_master_authority_state");
  suite.expect(artifactIndex >= 0 && masterAuthorityIndex >= 0 && artifactIndex < masterAuthorityIndex, "mothership_tunnel_provider_reconcile_sends_artifact_before_state");

  peer.wBuffer.clear();
  SystemContainerArtifactRef ref = {};
  ref.sha256 = config.tunnelProvider.artifactSha256;
  ref.bytes = config.tunnelProvider.artifactBytes;
  request.systemArtifacts.push_back(ref);
  serializedRequest.clear();
  messageBuffer.clear();
  BitseryEngine::serialize(serializedRequest, request);
  message = buildBrainMessage(messageBuffer, BrainTopic::reconcileState, serializedRequest);
  brain.brainHandler(&peer, message);

  sawArtifact = false;
  sawMasterAuthority = false;
  forEachMessageInBuffer(peer.wBuffer, [&](Message *queued) {
    if (BrainTopic(queued->topic) == BrainTopic::replicateSystemContainerArtifact)
    {
      sawArtifact = true;
    }
    else if (BrainTopic(queued->topic) == BrainTopic::replicateMasterAuthorityState)
    {
      sawMasterAuthority = true;
    }
  });
  suite.expect(sawArtifact == false, "mothership_tunnel_provider_reconcile_skips_present_artifact");
  suite.expect(sawMasterAuthority, "mothership_tunnel_provider_reconcile_still_sends_master_authority_state");
}

static void testMothershipTunnelGatewayClientCertificateAdmission(TestSuite& suite)
{
  MothershipTunnelGatewayClientAuth clientAuth = {};
  MothershipTunnelGatewayAuth auth = {};
  String failure = {};
  suite.require(mothershipGenerateTunnelGatewayAuth(clientAuth, auth, &failure), "mothership_tunnel_gateway_admission_fixture_generated");
  suite.expect(mothershipTunnelGatewayAuthorizeClientCertificate(auth, clientAuth.clientCertPem, &failure), "mothership_tunnel_gateway_admits_authorized_client");
  suite.expect(failure.size() == 0, "mothership_tunnel_gateway_admit_clears_failure");
  suite.expect(mothershipTunnelGatewayAuthorizeClientCertificate(auth, "not-a-cert"_ctv, &failure) == false && failure.equal("mothership tunnel gateway client certificate invalid"_ctv), "mothership_tunnel_gateway_rejects_malformed_client_cert");
  suite.expect(mothershipTunnelGatewayAuthorizeClientCertificate(auth, auth.serverCertPem, &failure) == false && failure.equal("mothership tunnel gateway client certificate invalid"_ctv), "mothership_tunnel_gateway_rejects_server_cert_as_client");

}

static void testMothershipTunnelProviderDesiredStateMasterAuthorityReplicationApplies(TestSuite& suite)
{
  TestBrain brain;
  BrainView peer;
  MothershipConnectivityRuntimeConfig config = makeTunnelRuntimeConnectivityConfig();
  MothershipTunnelGatewayAuth auth = makeTunnelGatewayAuth();
  suite.require(auth.configured(), "mothership_tunnel_provider_master_authority_replication_fixture_configured");
  brain.brainConfig.clusterUUID = 0x7707;
  MothershipTunnelProviderDesiredState desired = makeTunnelProviderDesiredState(config, auth);
  ProdigyMasterAuthorityRuntimeState runtimeState = {};
  runtimeState.generation = 1;
  runtimeState.mothershipTunnelProviderDesiredState = desired;
  String serialized = {};
  BitseryEngine::serialize(serialized, runtimeState);

  String messageBuffer;
  Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateMasterAuthorityState, serialized);
  brain.brainHandler(&peer, message);

  suite.expect(equalSerializedObjects(brain.mothershipConnectivity, config), "mothership_tunnel_provider_master_authority_replication_applies_config");
  suite.expect(equalSerializedObjects(brain.mothershipTunnelGatewayAuth, auth), "mothership_tunnel_provider_master_authority_replication_applies_auth");
  suite.expect(brain.masterAuthorityApplyCalls == 1 && brain.persistCalls == 1, "mothership_tunnel_provider_master_authority_replication_persists_master_snapshot");

  TestBrain deniedBrain;
  MothershipConnectivityRuntimeConfig denied = makeTunnelRuntimeConnectivityConfig();
  denied.tunnelProvider.egressHost = "169.254.169.254"_ctv;
  MothershipTunnelProviderDesiredState deniedDesired = makeTunnelProviderDesiredState(denied, auth);
  ProdigyMasterAuthorityRuntimeState deniedRuntimeState = {};
  deniedRuntimeState.generation = 1;
  deniedRuntimeState.mothershipTunnelProviderDesiredState = deniedDesired;
  suite.expect(deniedBrain.applyReplicatedMasterAuthorityRuntimeState(deniedRuntimeState, false), "mothership_connectivity_rejects_metadata_runtime_egress_master_state_applies");
  suite.expect(deniedBrain.mothershipConnectivity.kind == MothershipConnectivityKind::ssh, "mothership_connectivity_rejects_metadata_runtime_egress_clears_local_config");
  suite.expect(deniedBrain.mothershipTunnelProviderRuntimeState.lastFailure.equal("mothership tunnel-provider egress literal denied"_ctv), "mothership_connectivity_rejects_metadata_runtime_egress_reason");
}

static void testMothershipTunnelProviderRuntimeStateConfigChanges(TestSuite& suite)
{
  TestBrain brain;
  brain.weAreMaster = true;
  MothershipTunnelGatewayAuth auth = makeTunnelGatewayAuth();
  suite.require(auth.configured(), "mothership_tunnel_runtime_auth_fixture_configured");
  brain.brainConfig.clusterUUID = 0x7707;
  MothershipConnectivityRuntimeConfig config = makeTunnelRuntimeConnectivityConfig();
  String failure = {};
  suite.require(brain.applyMothershipTunnelProviderDesiredState(makeTunnelProviderDesiredState(config, auth), false, &failure), "mothership_tunnel_runtime_initial_apply");
  suite.expect(brain.mothershipTunnelProviderRuntimeState.localContainerUUID == 0, "mothership_tunnel_runtime_not_running_without_launcher");
  suite.expect(brain.mothershipTunnelProviderRuntimeState.lastFailure.equal("tunnel provider artifact missing from system store"_ctv), "mothership_tunnel_runtime_requires_artifact");

  suite.require(brain.applyMothershipTunnelProviderDesiredState(makeTunnelProviderDesiredState(config, auth), false, &failure), "mothership_tunnel_runtime_repeat_apply");
  suite.expect(brain.mothershipTunnelRuntimeStopCalls == 0, "mothership_tunnel_runtime_repeat_apply_idempotent");

  config.tunnelProvider.dialEndpoint = "control2.example.net:443"_ctv;
  suite.require(brain.applyMothershipTunnelProviderDesiredState(makeTunnelProviderDesiredState(config, auth), false, &failure), "mothership_tunnel_runtime_spec_changed_apply");
  suite.expect(brain.mothershipTunnelProviderRuntimeState.lastFailure.equal("tunnel provider artifact missing from system store"_ctv), "mothership_tunnel_runtime_spec_change_rechecks_store");

  config.tunnelProvider.artifactSha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"_ctv;
  suite.require(brain.applyMothershipTunnelProviderDesiredState(makeTunnelProviderDesiredState(config, auth), false, &failure), "mothership_tunnel_runtime_artifact_changed_apply");
  suite.expect(brain.mothershipTunnelProviderRuntimeState.lastFailure.equal("tunnel provider artifact missing from system store"_ctv), "mothership_tunnel_runtime_artifact_change_rechecks_store");
}

static void testMothershipTunnelProviderRuntimeStateRequiresActiveMaster(TestSuite& suite)
{
  TestBrain brain;
  brain.mothershipTunnelProviderRuntimeState.localContainerUUID = 123;

  MothershipConnectivityRuntimeConfig config = makeTunnelRuntimeConnectivityConfig();
  MothershipTunnelGatewayAuth auth = makeTunnelGatewayAuth();
  String failure = {};
  suite.require(brain.applyMothershipTunnelProviderDesiredState(makeTunnelProviderDesiredState(config, auth), false, &failure), "mothership_tunnel_runtime_non_master_apply");
  const auto& state = brain.mothershipTunnelProviderRuntimeState;
  suite.expect(state.localContainerUUID == 0, "mothership_tunnel_runtime_non_master_stopped");
  suite.expect(state.lastFailure.equal("not active master"_ctv), "mothership_tunnel_runtime_non_master_failure");
  suite.expect(brain.mothershipTunnelRuntimeStopCalls == 1 && brain.lastStoppedMothershipTunnelProviderContainerUUID == 123, "mothership_tunnel_runtime_non_master_stops_local_instance");

  TestBrain relinquishingBrain;
  relinquishingBrain.weAreMaster = true;
  suite.require(relinquishingBrain.applyMothershipTunnelProviderDesiredState(makeTunnelProviderDesiredState(config, auth), false, &failure), "mothership_tunnel_runtime_relinquish_apply");
  relinquishingBrain.mothershipTunnelProviderRuntimeState.localContainerUUID = 456;
  relinquishingBrain.forfeitMasterStatus();
  const auto& relinquishedState = relinquishingBrain.mothershipTunnelProviderRuntimeState;
  suite.expect(relinquishedState.localContainerUUID == 0, "mothership_tunnel_runtime_relinquish_stopped");
  suite.expect(relinquishedState.lastFailure.equal("not active master"_ctv), "mothership_tunnel_runtime_relinquish_failure");
  suite.expect(relinquishingBrain.mothershipTunnelRuntimeStopCalls == 1 && relinquishingBrain.lastStoppedMothershipTunnelProviderContainerUUID == 456, "mothership_tunnel_runtime_relinquish_stops_local_instance");
}

static void testMothershipTunnelProviderRuntimeLaunchBoundary(TestSuite& suite)
{
  TestBrain brain;
  brain.weAreMaster = true;
  brain.mothershipTunnelRuntimeStartSucceeds = true;
  MothershipTunnelGatewayAuth auth = makeTunnelGatewayAuth();
  suite.require(auth.configured(), "mothership_tunnel_runtime_launch_auth_fixture_configured");
  brain.brainConfig.clusterUUID = 0x7707;

  String blob = prodigyDiscombobulatorMothershipTunnelProviderBlobHeaderText();
  blob.append("payload"_ctv);
  MothershipConnectivityRuntimeConfig config = makeTunnelRuntimeConnectivityConfig();
  String artifactSha256 = {};
  suite.require(prodigyComputeSHA256Hex(blob, artifactSha256), "mothership_tunnel_runtime_launch_blob_sha");
  config.tunnelProvider.artifactSha256 = artifactSha256;
  config.tunnelProvider.artifactBytes = blob.size();

  String failure = {};
  suite.require(brain.applyMothershipTunnelProviderDesiredState(makeTunnelProviderDesiredState(config, auth), false, &failure), "mothership_tunnel_runtime_launch_desired_apply");
  suite.require(brain.applySystemContainerArtifact(config.tunnelProvider.artifactSha256, config.tunnelProvider.artifactBytes, blob, false, &failure), "mothership_tunnel_runtime_launch_artifact_apply");

  const auto& state = brain.mothershipTunnelProviderRuntimeState;
  suite.expect(state.localContainerUUID == brain.nextMothershipTunnelProviderContainerUUID, "mothership_tunnel_runtime_launch_marks_running");
  suite.expect(state.lastFailure.equal("waiting for authenticated tunnel session"_ctv), "mothership_tunnel_runtime_launch_waits_for_gateway_session");
  suite.expect(brain.mothershipTunnelRuntimeStartCalls == 1, "mothership_tunnel_runtime_launch_starts_once");
  suite.expect(brain.lastMothershipTunnelProviderArtifactBlob.equal(blob), "mothership_tunnel_runtime_launch_carries_verified_blob");
  suite.expect(equalSerializedObjects(brain.lastMothershipTunnelProviderGatewayAuth, auth), "mothership_tunnel_runtime_launch_carries_gateway_auth");
  suite.expect(equalSerializedObjects(brain.lastMothershipTunnelProviderSpec, config.tunnelProvider), "mothership_tunnel_runtime_launch_carries_spec");

  suite.require(brain.applyMothershipTunnelProviderDesiredState(makeTunnelProviderDesiredState(config, auth), false, &failure), "mothership_tunnel_runtime_launch_repeat_config_apply");
  suite.expect(brain.mothershipTunnelRuntimeStartCalls == 1, "mothership_tunnel_runtime_launch_repeat_does_not_restart");
  suite.expect(brain.mothershipTunnelProviderRuntimeState.lastFailure.equal("waiting for authenticated tunnel session"_ctv), "mothership_tunnel_runtime_launch_repeat_keeps_pending_health");

  config.tunnelProvider.dialEndpoint = "control-restarted.example.net:443"_ctv;
  suite.require(brain.applyMothershipTunnelProviderDesiredState(makeTunnelProviderDesiredState(config, auth), false, &failure), "mothership_tunnel_runtime_launch_spec_change_apply");
  suite.expect(brain.mothershipTunnelRuntimeStopCalls == 1 && brain.lastStoppedMothershipTunnelProviderContainerUUID == brain.nextMothershipTunnelProviderContainerUUID, "mothership_tunnel_runtime_launch_spec_change_stops_old");
  suite.expect(brain.mothershipTunnelRuntimeStartCalls == 2 && brain.mothershipTunnelProviderRuntimeState.localContainerUUID == brain.nextMothershipTunnelProviderContainerUUID, "mothership_tunnel_runtime_launch_spec_change_restarts");

  MothershipConnectivityRuntimeConfig sshConfig = {};
  suite.require(brain.applyMothershipTunnelProviderDesiredState(makeTunnelProviderDesiredState(sshConfig, {}), false, &failure), "mothership_tunnel_runtime_launch_ssh_cutover_apply");
  suite.expect(brain.mothershipTunnelRuntimeStopCalls == 2, "mothership_tunnel_runtime_launch_ssh_cutover_stops_runtime");
  suite.expect(brain.mothershipTunnelProviderRuntimeState.localContainerUUID == 0, "mothership_tunnel_runtime_launch_ssh_cutover_clears_runtime");

  TestBrain gatewayFailureBrain;
  gatewayFailureBrain.weAreMaster = true;
  gatewayFailureBrain.brainConfig.clusterUUID = 0x7707;
  suite.require(gatewayFailureBrain.applyMothershipTunnelProviderDesiredState(makeTunnelProviderDesiredState(config, auth), false, &failure), "mothership_tunnel_runtime_gateway_failure_desired_apply");
  suite.require(gatewayFailureBrain.applySystemContainerArtifact(config.tunnelProvider.artifactSha256, config.tunnelProvider.artifactBytes, blob, false, &failure), "mothership_tunnel_runtime_gateway_failure_artifact_apply");
  suite.expect(gatewayFailureBrain.mothershipTunnelRuntimeStartCalls == 1, "mothership_tunnel_runtime_gateway_failure_attempts_runtime");
  suite.expect(gatewayFailureBrain.mothershipTunnelProviderRuntimeState.localContainerUUID == 0 && gatewayFailureBrain.mothershipTunnelProviderRuntimeState.lastFailure.equal("injected tunnel runtime launch failure"_ctv), "mothership_tunnel_runtime_gateway_failure_stops_runtime");
}

static void testMothershipTunnelProviderGatewaySessionMarksHealthy(TestSuite& suite)
{
  TestBrain brain;
  brain.mothershipConnectivity.kind = MothershipConnectivityKind::tunnelProvider;
  brain.mothershipTunnelProviderRuntimeState.localContainerUUID = 123;
  brain.mothershipTunnelProviderRuntimeState.lastFailure.assign("waiting for gateway session"_ctv);

  brain.noteMothershipTunnelProviderControlSession(true, true);
  suite.expect(brain.mothershipTunnelProviderRuntimeState.lastFailure.size() == 0, "mothership_tunnel_runtime_gateway_session_clears_failure");

  TestBrain notRunning;
  notRunning.mothershipConnectivity.kind = MothershipConnectivityKind::tunnelProvider;
  notRunning.mothershipTunnelProviderRuntimeState.lastFailure.assign("waiting for gateway session"_ctv);
  notRunning.noteMothershipTunnelProviderControlSession(true, true);
  suite.expect(notRunning.mothershipTunnelProviderRuntimeState.lastFailure.size() > 0, "mothership_tunnel_runtime_session_requires_running_provider");
}

static void testMothershipTunnelProviderContainerFailureStopsRuntime(TestSuite& suite)
{
  TestBrain brain;
  brain.weAreMaster = true;
  brain.mothershipTunnelRuntimeStartSucceeds = true;
  MothershipTunnelGatewayAuth auth = makeTunnelGatewayAuth();
  suite.require(auth.configured(), "mothership_tunnel_runtime_failure_auth_fixture_configured");
  brain.brainConfig.clusterUUID = 0x7707;

  String blob = prodigyDiscombobulatorMothershipTunnelProviderBlobHeaderText();
  blob.append("payload"_ctv);
  MothershipConnectivityRuntimeConfig config = makeTunnelRuntimeConnectivityConfig();
  String artifactSha256 = {};
  suite.require(prodigyComputeSHA256Hex(blob, artifactSha256), "mothership_tunnel_runtime_failure_blob_sha");
  config.tunnelProvider.artifactSha256 = artifactSha256;
  config.tunnelProvider.artifactBytes = blob.size();

  String failure = {};
  suite.require(brain.applyMothershipTunnelProviderDesiredState(makeTunnelProviderDesiredState(config, auth), false, &failure), "mothership_tunnel_runtime_failure_desired_apply");
  suite.require(brain.applySystemContainerArtifact(config.tunnelProvider.artifactSha256, config.tunnelProvider.artifactBytes, blob, false, &failure), "mothership_tunnel_runtime_failure_artifact_apply");

  uint128_t providerUUID = brain.mothershipTunnelProviderRuntimeState.localContainerUUID;
  Machine machine = {};
  machine.neuron.machine = &machine;
  String messageBuffer;
  brain.neuronHandler(
      &machine.neuron,
      buildNeuronMessage(messageBuffer, NeuronTopic::containerFailed, providerUUID, int64_t(0), int(125), "startup failed before exec"_ctv, false));

  suite.expect(brain.mothershipTunnelProviderRuntimeState.localContainerUUID == 0, "mothership_tunnel_runtime_failure_stops_runtime");
  suite.expect(brain.mothershipTunnelProviderRuntimeState.lastFailure.equal("mothership tunnel provider exited: startup failed before exec"_ctv), "mothership_tunnel_runtime_failure_reports_exit");
  suite.expect(brain.mothershipTunnelRuntimeStopCalls == 1, "mothership_tunnel_runtime_failure_stops_runtime_hook");

  brain.reconcileMothershipTunnelProviderRuntimeState();
  suite.expect(brain.mothershipTunnelRuntimeStartCalls == 1, "mothership_tunnel_runtime_failure_does_not_relaunch_same_spec");
}

static void testMothershipTunnelProviderStateUploadKillsStaleProvider(TestSuite& suite)
{
  TestBrain brain = {};
  brain.weAreMaster = true;
  brain.mothershipConnectivity = makeTunnelRuntimeConnectivityConfig();
  brain.mothershipTunnelProviderRuntimeState.localContainerUUID = 0x77070001;

  Machine machine = {};
  machine.uuid = uint128_t(0x77070002);
  machine.fragment = 0x7707;
  machine.neuron.machine = &machine;
  machine.neuron.connected = true;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 23;

  auto uploadProviderPlan = [&](uint128_t containerUUID) {
    ContainerPlan plan = {};
    plan.uuid = containerUUID;
    plan.fragment = prodigyMothershipTunnelProviderRuntimeFragment;
    plan.state = ContainerState::healthy;
    String serializedPlan = {};
    BitseryEngine::serialize(serializedPlan, plan);

    String uploadBuffer = {};
    uint32_t headerOffset = Message::appendHeader(uploadBuffer, NeuronTopic::stateUpload);
    local_container_subnet6 fragment = {};
    fragment.dpfx = 1;
    fragment.mpfx[0] = 0x00;
    fragment.mpfx[1] = 0x77;
    fragment.mpfx[2] = 0x07;
    Message::appendAlignedBuffer<Alignment::one>(uploadBuffer, reinterpret_cast<const uint8_t *>(&fragment), sizeof(fragment));
    Message::appendValue(uploadBuffer, serializedPlan);
    Message::finish(uploadBuffer, headerOffset);
    brain.neuronHandler(&machine.neuron, reinterpret_cast<Message *>(uploadBuffer.data()));
  };

  uploadProviderPlan(0x77070003);

  uint32_t killFrames = 0;
  uint128_t killedContainerUUID = 0;
  forEachMessageInBuffer(machine.neuron.wBuffer, [&](Message *queued) {
    if (NeuronTopic(queued->topic) != NeuronTopic::killContainer)
    {
      return;
    }
    uint8_t *args = queued->args;
    Message::extractArg<ArgumentNature::fixed>(args, killedContainerUUID);
    killFrames += 1;
  });
  suite.expect(killFrames == 1 && killedContainerUUID == uint128_t(0x77070003), "mothership_tunnel_state_upload_kills_stale_provider");

  machine.neuron.wBuffer.clear();
  uploadProviderPlan(0x77070001);
  killFrames = 0;
  forEachMessageInBuffer(machine.neuron.wBuffer, [&](Message *queued) {
    if (NeuronTopic(queued->topic) == NeuronTopic::killContainer)
    {
      killFrames += 1;
    }
  });
  suite.expect(killFrames == 0, "mothership_tunnel_state_upload_keeps_current_provider");
  suite.expect(brain.containers.contains(uint128_t(0x77070003)) == false && brain.containers.contains(uint128_t(0x77070001)) == false, "mothership_tunnel_state_upload_skips_app_container_index");
}

static void testClusterReportIncludesMothershipConnectivityStatus(TestSuite& suite)
{
  TestBrain brain;
  brain.weAreMaster = true;

  ClusterStatusReport defaultReport = {};
  suite.require(pullClusterStatusReportForTest(brain, defaultReport), "cluster_report_default_mothership_connectivity_deserializes");
  suite.expect(defaultReport.mothershipConnectivity.kind.equal("ssh"_ctv), "cluster_report_default_mothership_connectivity_kind");
  suite.expect(defaultReport.mothershipConnectivity.lastFailure.size() == 0, "cluster_report_default_mothership_connectivity_tunnel_status_empty");

  MothershipConnectivityRuntimeConfig config = makeTunnelRuntimeConnectivityConfig();
  MothershipTunnelGatewayAuth auth = makeTunnelGatewayAuth();
  String failure = {};
  suite.require(brain.applyMothershipTunnelProviderDesiredState(makeTunnelProviderDesiredState(config, auth), false, &failure), "cluster_report_mothership_connectivity_setup");

  ClusterStatusReport report = {};
  suite.require(pullClusterStatusReportForTest(brain, report), "cluster_report_mothership_connectivity_deserializes");
  suite.expect(report.mothershipConnectivity.kind.equal("tunnelProvider"_ctv), "cluster_report_mothership_connectivity_kind");
  suite.expect(
      report.mothershipConnectivity.lastFailure.equal("tunnel provider artifact missing from system store"_ctv),
      "cluster_report_mothership_connectivity_missing_artifact_failure");
}

static void testDeploymentReplicationBackpressureClosesPeer(TestSuite& suite)
{
  TestBrain brain;
  BrainView follower;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.nBrains = 2;

  follower.connected = true;
  follower.weConnectToIt = true;
  follower.isFixedFile = true;
  follower.fslot = 18;
  brain.brains.insert(&follower);

  String serializedPlan = {};
  serializedPlan.assign("serialized-plan"_ctv);

  suite.expect(
      brain.queueBrainDeploymentReplicationFromStoreToPeer(
          &follower,
          serializedPlan,
          0xDEADBEEF,
          BrainBase::brainPeerReplicationBufferedBytesLimit + 1) == false,
      "deployment_replication_backpressure_rejects_oversized_append");
  suite.expect(Ring::socketIsClosing(&follower), "deployment_replication_backpressure_closes_peer");
  suite.expect(follower.connected == false, "deployment_replication_backpressure_marks_peer_disconnected");
  suite.expect(follower.wBuffer.outstandingBytes() == 0, "deployment_replication_backpressure_clears_buffer");

  // This regression intentionally queues a close on a stack-owned peer view.
  // Reset the ring so later tests cannot inherit its stale identity entry.
  Ring::shutdownForExec();
  Ring::createRing(8, 8, 32, 32, -1, -1, 0);
}

static void testLargePayloadPeerKeepaliveUsesFixedFileSocketCommand(TestSuite& suite)
{
  ScopedFreshRing scopedRing = {};

  TestBrain brain;
  BrainView follower = {};
  follower.private4 = 0x0a000012;
  follower.connected = true;

  TCPSocket listener = {};
  listener.setIPVersion(AF_INET);
  listener.setSaddr("127.0.0.1"_ctv, 0);
  listener.bindThenListen();

  struct sockaddr_in listenerAddress = {};
  socklen_t listenerAddressLen = sizeof(listenerAddress);
  suite.expect(
      getsockname(listener.fd, reinterpret_cast<struct sockaddr *>(&listenerAddress), &listenerAddressLen) == 0,
      "large_payload_keepalive_gets_listener_address");

  TCPSocket client = {};
  client.setIPVersion(AF_INET);
  client.setDaddr("127.0.0.1"_ctv, ntohs(listenerAddress.sin_port));
  suite.expect(client.connect() == 0, "large_payload_keepalive_connects_client");

  int acceptedFD = listener.accept();
  suite.expect(acceptedFD >= 0, "large_payload_keepalive_accepts_client");

  int acceptedFslot = -1;
  if (acceptedFD >= 0)
  {
    acceptedFslot = Ring::adoptProcessFDIntoFixedFileSlot(acceptedFD, false);
  }
  suite.expect(acceptedFslot >= 0, "large_payload_keepalive_adopts_fixed_slot");

  if (acceptedFslot >= 0)
  {
    follower.isFixedFile = true;
    follower.fslot = acceptedFslot;
    brain.queueBrainPeerLargePayloadKeepaliveForTest(&follower);
    Ring::submitPending();
    usleep(20 * 1000);

    int keepaliveEnabled = 0;
    socklen_t keepaliveEnabledLen = sizeof(keepaliveEnabled);
    suite.expect(
        getsockopt(acceptedFD, SOL_SOCKET, SO_KEEPALIVE, &keepaliveEnabled, &keepaliveEnabledLen) == 0,
        "large_payload_keepalive_reads_so_keepalive");
    suite.expect(keepaliveEnabled == 1, "large_payload_keepalive_enables_keepalive");

    int userTimeoutMs = 0;
    socklen_t userTimeoutLen = sizeof(userTimeoutMs);
    suite.expect(
        getsockopt(acceptedFD, SOL_TCP, TCP_USER_TIMEOUT, &userTimeoutMs, &userTimeoutLen) == 0,
        "large_payload_keepalive_reads_tcp_user_timeout");
    suite.expect(
        userTimeoutMs == int(BrainBase::brainPeerLargePayloadKeepaliveSeconds * 1000u),
        "large_payload_keepalive_sets_tcp_user_timeout");
  }

  if (acceptedFD >= 0)
  {
    close(acceptedFD);
  }
  if (client.fd >= 0)
  {
    client.close();
  }
  if (listener.fd >= 0)
  {
    listener.close();
  }
}

static void testAcceptedBrainPeerSetsLargePayloadUserTimeout(TestSuite& suite)
{
  ScopedFreshRing scopedRing = {};

  TestBrain brain = {};
  brain.setBrainPeerKeepaliveSecondsForTest(prodigyBrainDevPeerKeepaliveSeconds);

  TCPSocket listener = {};
  listener.setIPVersion(AF_INET);
  listener.setSaddr("127.0.0.1"_ctv, 0);
  listener.bindThenListen();

  struct sockaddr_in listenerAddress = {};
  socklen_t listenerAddressLen = sizeof(listenerAddress);
  suite.expect(
      getsockname(listener.fd, reinterpret_cast<struct sockaddr *>(&listenerAddress), &listenerAddressLen) == 0,
      "accepted_brain_peer_keepalive_reads_listener_port");

  TCPSocket client = {};
  client.setIPVersion(AF_INET);
  client.setDaddr("127.0.0.1"_ctv, ntohs(listenerAddress.sin_port));
  suite.expect(client.connect() == 0, "accepted_brain_peer_keepalive_connects_client");

  int acceptedFD = listener.accept();
  suite.expect(acceptedFD >= 0, "accepted_brain_peer_keepalive_accepts_client");

  int acceptedFslot = -1;
  if (acceptedFD >= 0)
  {
    acceptedFslot = Ring::adoptProcessFDIntoFixedFileSlot(acceptedFD, false);
  }
  suite.expect(acceptedFslot >= 0, "accepted_brain_peer_keepalive_adopts_fixed_slot");

  if (acceptedFslot >= 0)
  {
    BrainView follower = {};
    follower.peerAddress = IPAddress("127.0.0.1", false);
    follower.private4 = follower.peerAddress.v4;
    follower.isFixedFile = true;
    follower.fslot = acceptedFslot;
    brain.queueAcceptedBrainPeerSocketOptionsForTest(&follower);
    Ring::submitPending();
    usleep(20 * 1000);

    int keepaliveIdleSeconds = 0;
    socklen_t keepaliveIdleLen = sizeof(keepaliveIdleSeconds);
    suite.expect(
        getsockopt(acceptedFD, SOL_TCP, TCP_KEEPIDLE, &keepaliveIdleSeconds, &keepaliveIdleLen) == 0,
        "accepted_brain_peer_keepalive_reads_keepidle");
    suite.expect(
        keepaliveIdleSeconds == int(prodigyBrainDevPeerKeepaliveSeconds),
        "accepted_brain_peer_keepalive_preserves_short_probe_budget");

    int userTimeoutMs = 0;
    socklen_t userTimeoutLen = sizeof(userTimeoutMs);
    suite.expect(
        getsockopt(acceptedFD, SOL_TCP, TCP_USER_TIMEOUT, &userTimeoutMs, &userTimeoutLen) == 0,
        "accepted_brain_peer_keepalive_reads_tcp_user_timeout");
    suite.expect(
        userTimeoutMs == int(BrainBase::brainPeerLargePayloadKeepaliveSeconds * 1000u),
        "accepted_brain_peer_keepalive_sets_large_payload_user_timeout");
  }

  if (acceptedFD >= 0)
  {
    close(acceptedFD);
  }
  if (client.fd >= 0)
  {
    client.close();
  }
  if (listener.fd >= 0)
  {
    listener.close();
  }
}

static void testMothershipConfigureAppliesClusterUUID(TestSuite& suite)
{
  TestBrain brain;
  NoopBrainIaaS iaas;
  Mothership mothership;
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;

  BrainConfig incoming = {};
  incoming.clusterUUID = 0x4401;

  String serialized;
  BitseryEngine::serialize(serialized, incoming);

  String messageBuffer;
  Message *configureMessage = buildMothershipMessage(messageBuffer, MothershipTopic::configure, serialized);
  brain.mothershipHandler(&mothership, configureMessage);

  suite.expect(brain.brainConfig.clusterUUID == incoming.clusterUUID, "mothership_configure_applies_cluster_uuid");
  suite.expect(brain.clusterOwnershipCalls == 1, "mothership_configure_claims_cluster_ownership");
  suite.expect(brain.lastClaimedClusterUUID == incoming.clusterUUID, "mothership_configure_claims_expected_cluster_uuid");
  suite.expect(brain.persistCalls == 1, "mothership_configure_persists_runtime_state");
}

static OperatingSystemUpdatePolicy makeOSUpdatePolicy(
    const String& osID,
    const String& targetVersionID,
    const String& command,
    bool includeVMs);

static void testMothershipConfigureOwnsMachineConfigsForManagedSchemas(TestSuite& suite)
{
  ResumableAddMachinesBrain brain;
  AutoProvisionBrainIaaS iaas;
  Mothership mothership = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;

  brain.authoritativeTopology.version = 5;
  brain.authoritativeTopology.machines.push_back(ClusterMachine {});
  brain.authoritativeTopology.machines.back().source = ClusterMachineSource::created;
  brain.authoritativeTopology.machines.back().backing = ClusterMachineBacking::cloud;
  brain.authoritativeTopology.machines.back().kind = MachineConfig::MachineKind::vm;
  brain.authoritativeTopology.machines.back().lifetime = MachineLifetime::ondemand;
  brain.authoritativeTopology.machines.back().isBrain = true;
  brain.authoritativeTopology.machines.back().uuid = 0x7702;
  brain.authoritativeTopology.machines.back().cloud.schema = "c7i-flex.large"_ctv;
  brain.authoritativeTopology.machines.back().cloud.providerMachineType = "c7i-flex.large"_ctv;
  brain.authoritativeTopology.machines.back().cloud.cloudID = "i-seed"_ctv;
  prodigyAppendUniqueClusterMachineAddress(brain.authoritativeTopology.machines.back().addresses.privateAddresses, "10.77.0.10"_ctv, 24, "10.77.0.1"_ctv);

  BrainConfig incoming = {};
  incoming.clusterUUID = 0x7701;
  incoming.requiredBrainCount = 1;
  incoming.architecture = MachineCpuArchitecture::x86_64;
  incoming.bootstrapSshUser = "root"_ctv;
  incoming.bootstrapSshPrivateKeyPath = "/tmp/test-key"_ctv;
  incoming.remoteProdigyPath = "/root/prodigy"_ctv;
  incoming.controlSocketPath = "/run/prodigy/control.sock"_ctv;
  incoming.osUpdatesEnabled = true;
  incoming.osUpdatePolicies.push_back(makeOSUpdatePolicy(
      "ubuntu"_ctv,
      "24.04"_ctv,
      "apt-get update && apt-get -y dist-upgrade && systemctl reboot"_ctv,
      true));
  incoming.maxOSDrains = 2;
  incoming.machineUpdateCadenceMins = 3;
  String failure = {};
  suite.expect(
      prodigyReadSSHKeyPackageFromPrivateKeyPath(
          prodigyTestBootstrapSeedSSHPrivateKeyPath(),
          incoming.bootstrapSshKeyPackage,
          &failure),
      "mothership_configure_reads_bootstrap_ssh_key_package");
  suite.expect(
      prodigyReadSSHKeyPackageFromPrivateKeyPath(
          prodigyTestSSHDHostPrivateKeyPath(),
          incoming.bootstrapSshHostKeyPackage,
          &failure),
      "mothership_configure_reads_bootstrap_ssh_host_key_package");
  incoming.runtimeEnvironment.kind = ProdigyEnvironmentKind::aws;
  incoming.runtimeEnvironment.providerScope = "acct-test/us-east-1"_ctv;
  incoming.runtimeEnvironment.providerCredentialMaterial = "AKIA:SECRET"_ctv;
  incoming.runtimeEnvironment.aws.bootstrapLaunchTemplateName = "prodigy-bootstrap-us-east-1"_ctv;
  incoming.runtimeEnvironment.aws.bootstrapLaunchTemplateVersion = "$Default"_ctv;
  incoming.runtimeEnvironment.aws.bootstrapCredentialRefreshCommand = "aws configure export-credentials --format process"_ctv;
  incoming.runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint = "run aws sso login --profile default"_ctv;
  incoming.runtimeEnvironment.aws.instanceProfileName = "prodigy-controller-profile"_ctv;
  incoming.runtimeEnvironment.aws.instanceProfileArn = "arn:aws:iam::123456789012:instance-profile/prodigy-controller-profile"_ctv;
  incoming.dnsProvider = "cloudflare"_ctv;
  incoming.dnsCredential.name = "cluster-cf"_ctv;
  incoming.dnsCredential.provider = "cloudflare"_ctv;
  incoming.dnsCredential.material = "cf-token"_ctv;
  incoming.dnsCredential.metadata.insert_or_assign("dnsZones"_ctv, "example.com"_ctv);
  incoming.acme.accountEmail = "ops@example.com"_ctv;
  incoming.acme.certbotInstall = "bundle"_ctv;
  incoming.acme.certbotPath = "/opt/prodigy/certbot/bin/certbot"_ctv;
  incoming.acme.certbotVersion = "5.6.0"_ctv;
  incoming.acme.termsAgreed = true;

  MachineConfig machineConfig = {};
  machineConfig.slug = "c7i-flex.large"_ctv;
  machineConfig.kind = MachineConfig::MachineKind::vm;
  machineConfig.vmImageURI = "resolve:ssm:/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"_ctv;
  machineConfig.nLogicalCores = 2;
  machineConfig.nMemoryMB = 4096;
  machineConfig.nStorageMB = 65'536;
  incoming.configBySlug.insert_or_assign(machineConfig.slug, machineConfig);

  String serializedConfigure = {};
  BitseryEngine::serialize(serializedConfigure, incoming);
  String configureBuffer = {};
  Message *configureMessage = buildMothershipMessage(configureBuffer, MothershipTopic::configure, serializedConfigure);
  brain.mothershipHandler(&mothership, configureMessage);

  auto configIt = brain.brainConfig.configBySlug.find("c7i-flex.large"_ctv);
  suite.expect(configIt != brain.brainConfig.configBySlug.end(), "mothership_configure_owns_machine_config_lookup");
  if (configIt != brain.brainConfig.configBySlug.end())
  {
    suite.expect(configIt->first.isInvariant() == false, "mothership_configure_owns_machine_config_key");
    suite.expect(configIt->second.slug.isInvariant() == false, "mothership_configure_owns_machine_config_slug");
    suite.expect(configIt->second.vmImageURI.isInvariant() == false, "mothership_configure_owns_machine_config_vm_image");
  }
  suite.expect(brain.brainConfig.bootstrapSshUser.isInvariant() == false, "mothership_configure_owns_bootstrap_user");
  suite.expect(brain.brainConfig.bootstrapSshPrivateKeyPath.isInvariant() == false, "mothership_configure_owns_bootstrap_key");
  suite.expect(brain.brainConfig.bootstrapSshKeyPackage == incoming.bootstrapSshKeyPackage, "mothership_configure_copies_bootstrap_key_package");
  suite.expect(brain.brainConfig.bootstrapSshHostKeyPackage == incoming.bootstrapSshHostKeyPackage, "mothership_configure_copies_bootstrap_host_key_package");
  suite.expect(brain.brainConfig.controlSocketPath.isInvariant() == false, "mothership_configure_owns_control_socket_path");
  suite.expect(brain.brainConfig.architecture == incoming.architecture, "mothership_configure_applies_architecture");
  suite.expect(brain.brainConfig.osUpdatesEnabled == incoming.osUpdatesEnabled, "mothership_configure_applies_os_updates_enabled");
  suite.expect(brain.brainConfig.osUpdatePolicies.size() == 1, "mothership_configure_applies_os_update_policy_count");
  suite.expect(brain.brainConfig.osUpdatePolicies.size() == 1 && brain.brainConfig.osUpdatePolicies[0].osID == "ubuntu"_ctv, "mothership_configure_applies_os_update_policy_os_id");
  suite.expect(brain.brainConfig.osUpdatePolicies.size() == 1 && brain.brainConfig.osUpdatePolicies[0].targetVersionID == "24.04"_ctv, "mothership_configure_applies_os_update_policy_target_version");
  suite.expect(brain.brainConfig.osUpdatePolicies.size() == 1 && brain.brainConfig.osUpdatePolicies[0].command == incoming.osUpdatePolicies[0].command, "mothership_configure_applies_os_update_policy_command");
  suite.expect(brain.brainConfig.osUpdatePolicies.size() == 1 && brain.brainConfig.osUpdatePolicies[0].includeVMs, "mothership_configure_applies_os_update_policy_include_vms");
  suite.expect(brain.brainConfig.maxOSDrains == incoming.maxOSDrains, "mothership_configure_applies_max_os_drains");
  suite.expect(brain.brainConfig.machineUpdateCadenceMins == incoming.machineUpdateCadenceMins, "mothership_configure_applies_machine_update_cadence");
  suite.expect(brain.brainConfig.runtimeEnvironment.providerScope.isInvariant() == false, "mothership_configure_owns_provider_scope");
  suite.expect(brain.brainConfig.runtimeEnvironment.providerCredentialMaterial.size() == 0, "mothership_configure_scrubs_provider_credential_on_managed_aws");
  suite.expect(brain.brainConfig.runtimeEnvironment.aws.bootstrapCredentialRefreshCommand.size() == 0, "mothership_configure_scrubs_aws_refresh_command_on_managed_aws");
  suite.expect(brain.brainConfig.runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint.size() == 0, "mothership_configure_scrubs_aws_refresh_hint_on_managed_aws");
  suite.expect(brain.brainConfig.runtimeEnvironment.aws.instanceProfileName.equals(incoming.runtimeEnvironment.aws.instanceProfileName), "mothership_configure_copies_aws_instance_profile_name");
  suite.expect(brain.brainConfig.runtimeEnvironment.aws.instanceProfileName.isInvariant() == false, "mothership_configure_owns_aws_instance_profile_name");
  suite.expect(brain.brainConfig.runtimeEnvironment.aws.instanceProfileArn.equals(incoming.runtimeEnvironment.aws.instanceProfileArn), "mothership_configure_copies_aws_instance_profile_arn");
  suite.expect(brain.brainConfig.runtimeEnvironment.aws.instanceProfileArn.isInvariant() == false, "mothership_configure_owns_aws_instance_profile_arn");
  suite.expect(brain.brainConfig.dnsProvider.equal("cloudflare"_ctv), "mothership_configure_applies_dns_provider");
  suite.expect(brain.brainConfig.dnsProvider.isInvariant() == false, "mothership_configure_owns_dns_provider");
  suite.expect(brain.brainConfig.dnsCredential.name.equal("cluster-cf"_ctv), "mothership_configure_applies_dns_credential_name");
  suite.expect(brain.brainConfig.dnsCredential.material.equal("cf-token"_ctv), "mothership_configure_applies_dns_credential_material");
  suite.expect(brain.brainConfig.dnsCredential.metadata["dnsZones"_ctv].equal("example.com"_ctv), "mothership_configure_applies_dns_credential_metadata");
  suite.expect(brain.brainConfig.acme.accountEmail.equal("ops@example.com"_ctv), "mothership_configure_applies_acme_email");
  suite.expect(brain.brainConfig.acme.certbotInstall.equal("bundle"_ctv), "mothership_configure_applies_acme_certbot_install");
  suite.expect(brain.brainConfig.acme.certbotPath.equal("/opt/prodigy/certbot/bin/certbot"_ctv), "mothership_configure_applies_acme_certbot_path");
  suite.expect(brain.brainConfig.acme.certbotVersion.equal("5.6.0"_ctv), "mothership_configure_applies_acme_certbot_version");
  suite.expect(brain.brainConfig.acme.termsAgreed, "mothership_configure_applies_acme_terms");

  serializedConfigure.reset();
  configureBuffer.reset();
  mothership.wBuffer.clear();

  UpsertMachineSchemas request = {};
  ProdigyManagedMachineSchemaPatch patch = {};
  patch.schema = "c7i-flex.large"_ctv;
  patch.hasKind = true;
  patch.kind = MachineConfig::MachineKind::vm;
  patch.hasLifetime = true;
  patch.lifetime = MachineLifetime::ondemand;
  patch.hasProviderMachineType = true;
  patch.providerMachineType = "c7i-flex.large"_ctv;
  patch.hasRegion = true;
  patch.region = "us-east-1"_ctv;
  patch.hasZone = true;
  patch.zone = "us-east-1a"_ctv;
  patch.hasBudget = true;
  patch.budget = 1;
  request.patches.push_back(patch);

  String serializedUpsert = {};
  BitseryEngine::serialize(serializedUpsert, request);
  String upsertBuffer = {};
  Message *upsertMessage = buildMothershipMessage(upsertBuffer, MothershipTopic::upsertMachineSchemas, serializedUpsert);
  brain.mothershipHandler(&mothership, upsertMessage);

  Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
  String serializedResponse = {};
  uint8_t *responseArgs = responseMessage->args;
  Message::extractToStringView(responseArgs, serializedResponse);

  UpsertMachineSchemas response = {};
  suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_configure_owned_strings_upsert_deserializes_response");
  suite.expect(response.success, "mothership_configure_owned_strings_upsert_succeeds");
  suite.expect(response.failure.size() == 0, "mothership_configure_owned_strings_upsert_no_failure");
  suite.expect(response.hasTopology, "mothership_configure_owned_strings_upsert_returns_topology");
  suite.expect(response.topology.machines.size() == 1, "mothership_configure_owned_strings_upsert_keeps_seed_topology");
  suite.expect(iaas.spinCalls == 0, "mothership_configure_owned_strings_upsert_does_not_reprovision_seed");
}

static void testMothershipConfigureRejectsClusterTakeover(TestSuite& suite)
{
  TestBrain brain;
  NoopBrainIaaS iaas;
  Mothership mothership = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.rejectClusterOwnership = true;
  brain.rejectClusterOwnershipFailure.assign("local machine already belongs to cluster a and refuses takeover by cluster b"_ctv);

  BrainConfig incoming = {};
  incoming.clusterUUID = 0x4402;

  String serialized = {};
  BitseryEngine::serialize(serialized, incoming);

  String messageBuffer = {};
  Message *configureMessage = buildMothershipMessage(messageBuffer, MothershipTopic::configure, serialized);
  brain.mothershipHandler(&mothership, configureMessage);

  suite.expect(brain.clusterOwnershipCalls == 1, "mothership_configure_reject_takeover_claim_called");
  suite.expect(brain.lastClaimedClusterUUID == incoming.clusterUUID, "mothership_configure_reject_takeover_claim_expected_cluster_uuid");
  suite.expect(brain.brainConfig.clusterUUID == 0, "mothership_configure_reject_takeover_preserves_cluster_uuid");
  suite.expect(brain.persistCalls == 0, "mothership_configure_reject_takeover_does_not_persist");
  suite.expect(mothership.wBuffer.size() == 0, "mothership_configure_reject_takeover_emits_no_ack");
}

static void testReplicateBrainConfigRejectsClusterTakeover(TestSuite& suite)
{
  TestBrain brain;
  BrainView peer = {};
  String messageBuffer = {};
  brain.rejectClusterOwnership = true;
  brain.rejectClusterOwnershipFailure.assign("local machine already belongs to cluster a and refuses takeover by cluster b"_ctv);
  brain.brainConfig.clusterUUID = 0x3301;

  BrainConfig replicatedConfig = {};
  replicatedConfig.clusterUUID = 0x3302;
  String serialized = {};
  BitseryEngine::serialize(serialized, replicatedConfig);

  Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateBrainConfig, serialized);
  brain.brainHandler(&peer, message);

  suite.expect(brain.clusterOwnershipCalls == 1, "replicate_brain_config_reject_takeover_claim_called");
  suite.expect(brain.lastClaimedClusterUUID == replicatedConfig.clusterUUID, "replicate_brain_config_reject_takeover_claim_expected_cluster_uuid");
  suite.expect(brain.brainConfig.clusterUUID == 0x3301, "replicate_brain_config_reject_takeover_preserves_cluster_uuid");
  suite.expect(brain.persistCalls == 0, "replicate_brain_config_reject_takeover_does_not_persist");
}

static void testMothershipConfigureLowersSharedCPUOvercommitWithoutMovingClaims(TestSuite& suite)
{
  TestBrain brain;
  NoopBrainIaaS iaas;
  Mothership mothership;
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.brainConfig.sharedCPUOvercommitPermille = 1500;

  Rack rack = {};
  rack.uuid = 0x5511;
  brain.racks.insert_or_assign(rack.uuid, &rack);

  Machine machine = {};
  machine.uuid = uint128_t(0x5512);
  machine.slug.assign("shared-box"_ctv);
  machine.rack = &rack;
  machine.state = MachineState::healthy;
  machine.lifetime = MachineLifetime::owned;
  machine.ownedLogicalCores = 4;
  machine.ownedMemoryMB = 8192;
  machine.ownedStorageMB = 8192;
  machine.totalLogicalCores = 4;
  machine.totalMemoryMB = 8192;
  machine.totalStorageMB = 8192;

  Machine::Claim claim = {};
  claim.nFit = 1;
  claim.reservedSharedCPUMillisPerInstance = 6000;
  machine.claims.push_back(claim);

  rack.machines.insert(&machine);
  brain.machines.insert(&machine);

  BrainConfig incoming = {};
  incoming.sharedCPUOvercommitPermille = 1000;
  incoming.machineReservedResources = prodigySmokeMachineReservedResources;
  MachineConfig machineConfig = {};
  machineConfig.slug = machine.slug;
  machineConfig.nLogicalCores = 4;
  machineConfig.nMemoryMB = 8192;
  machineConfig.nStorageMB = 8192;
  incoming.configBySlug.insert_or_assign(machineConfig.slug, machineConfig);

  String serialized;
  BitseryEngine::serialize(serialized, incoming);

  String messageBuffer;
  Message *configureMessage = buildMothershipMessage(messageBuffer, MothershipTopic::configure, serialized);
  brain.mothershipHandler(&mothership, configureMessage);

  suite.expect(brain.brainConfig.sharedCPUOvercommitPermille == 1000, "mothership_configure_applies_shared_cpu_overcommit");
  suite.expect(brain.brainConfig.machineReservedResources == prodigySmokeMachineReservedResources, "mothership_configure_applies_resource_reservation");
  suite.expect(machine.ownedLogicalCores == 4, "mothership_configure_resource_reservation_keeps_smoke_cores");
  suite.expect(brain.persistCalls == 1, "mothership_configure_shared_cpu_overcommit_persists_runtime_state");
  suite.expect(machine.claims.size() == 1, "mothership_configure_shared_cpu_overcommit_keeps_existing_claims");
  suite.expect(machine.sharedCPUMillisCommitted == 6000, "mothership_configure_shared_cpu_overcommit_preserves_committed_shared_cpu");
  suite.expect(machine.sharedCPUMillis_available < 0, "mothership_configure_shared_cpu_overcommit_can_leave_negative_shared_headroom");
  suite.expect(machine.nLogicalCores_available < 0, "mothership_configure_shared_cpu_overcommit_can_leave_negative_isolated_headroom");

  rack.machines.erase(&machine);
  brain.machines.erase(&machine);
  brain.racks.erase(rack.uuid);
}

static void testMachineSchemaMutationsQueueRuntimeStateReplication(TestSuite& suite)
{
  ResumableAddMachinesBrain brain;
  NoopBrainIaaS iaas;
  Mothership mothership;
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.nBrains = 2;
  brain.authoritativeTopology.version = 9;
  brain.authoritativeTopology.machines.push_back(ClusterMachine {});
  brain.authoritativeTopology.machines.back().source = ClusterMachineSource::adopted;
  brain.authoritativeTopology.machines.back().backing = ClusterMachineBacking::owned;
  brain.authoritativeTopology.machines.back().kind = MachineConfig::MachineKind::vm;
  brain.authoritativeTopology.machines.back().lifetime = MachineLifetime::owned;
  brain.authoritativeTopology.machines.back().isBrain = true;
  prodigyAppendUniqueClusterMachineAddress(brain.authoritativeTopology.machines.back().addresses.privateAddresses, "10.0.0.10"_ctv);

  BrainView follower = {};
  follower.isFixedFile = true;
  follower.fslot = 31;
  follower.connected = true;
  brain.brains.insert(&follower);

  auto extractReplicatedRuntimeState = [&](ProdigyMasterAuthorityRuntimeState& replicated) -> bool {
    bool found = false;
    replicated = {};
    forEachMessageInBuffer(follower.wBuffer, [&](Message *queued) {
      if (BrainTopic(queued->topic) != BrainTopic::replicateMasterAuthorityState)
      {
        return;
      }

      uint8_t *args = queued->args;
      String serialized = {};
      Message::extractToStringView(args, serialized);

      ProdigyMasterAuthorityRuntimeState decoded = {};
      if (BitseryEngine::deserializeSafe(serialized, decoded))
      {
        replicated = decoded;
        found = true;
      }
    });

    return found;
  };

  String messageBuffer = {};

  {
    UpsertMachineSchemas request = {};
    ProdigyManagedMachineSchemaPatch patch = {};
    patch.schema = "aws-brain-vm"_ctv;
    patch.hasKind = true;
    patch.kind = MachineConfig::MachineKind::vm;
    patch.hasLifetime = true;
    patch.lifetime = MachineLifetime::ondemand;
    patch.hasProviderMachineType = true;
    patch.providerMachineType = "c7i.large"_ctv;
    patch.hasRegion = true;
    patch.region = "us-east-1"_ctv;
    patch.hasZone = true;
    patch.zone = "us-east-1a"_ctv;
    patch.hasBudget = true;
    patch.budget = 0;
    request.patches.push_back(patch);

    String serializedRequest = {};
    BitseryEngine::serialize(serializedRequest, request);
    Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::upsertMachineSchemas, serializedRequest);
    brain.mothershipHandler(&mothership, message);

    Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
    String serializedResponse = {};
    uint8_t *responseArgs = responseMessage->args;
    Message::extractToStringView(responseArgs, serializedResponse);

    UpsertMachineSchemas response = {};
    suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_upsert_machine_schemas_deserializes_response");
    suite.expect(response.success, "mothership_upsert_machine_schemas_succeeds");
    suite.expect(response.created == 1, "mothership_upsert_machine_schemas_reports_created");
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
    suite.expect(response.hasTimingAttribution, "mothership_upsert_machine_schemas_reports_timing_attribution");
#endif
    suite.expect(response.hasTopology, "mothership_upsert_machine_schemas_returns_topology");
    suite.expect(response.topology.version == 9, "mothership_upsert_machine_schemas_returns_authoritative_topology");
    suite.expect(brain.masterAuthorityRuntimeState.machineSchemas.size() == 1, "mothership_upsert_machine_schemas_stores_runtime_state");
    suite.expect(brain.masterAuthorityRuntimeState.machineSchemas[0].schema == "aws-brain-vm"_ctv, "mothership_upsert_machine_schemas_stores_schema");

    ProdigyMasterAuthorityRuntimeState replicated = {};
    suite.expect(extractReplicatedRuntimeState(replicated), "mothership_upsert_machine_schemas_replication_queued");
    suite.expect(replicated.machineSchemas.size() == 1, "mothership_upsert_machine_schemas_replication_schema_count");
    suite.expect(replicated.machineSchemas[0].schema == "aws-brain-vm"_ctv, "mothership_upsert_machine_schemas_replication_schema");
    suite.expect(replicated.machineSchemas[0].budget == 0, "mothership_upsert_machine_schemas_replication_budget");
  }

  mothership.wBuffer.clear();
  follower.wBuffer.clear();

  {
    DeltaMachineBudget request = {};
    request.schema = "aws-brain-vm"_ctv;
    request.delta = -1;

    String serializedRequest = {};
    BitseryEngine::serialize(serializedRequest, request);
    Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::deltaMachineBudget, serializedRequest);
    brain.mothershipHandler(&mothership, message);

    Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
    String serializedResponse = {};
    uint8_t *responseArgs = responseMessage->args;
    Message::extractToStringView(responseArgs, serializedResponse);

    DeltaMachineBudget response = {};
    suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_delta_machine_budget_deserializes_response");
    suite.expect(response.success, "mothership_delta_machine_budget_succeeds");
    suite.expect(response.budget == 0, "mothership_delta_machine_budget_clamps_budget");
    suite.expect(response.hasTopology, "mothership_delta_machine_budget_returns_topology");

    ProdigyMasterAuthorityRuntimeState replicated = {};
    suite.expect(extractReplicatedRuntimeState(replicated), "mothership_delta_machine_budget_replication_queued");
    suite.expect(replicated.machineSchemas.size() == 1, "mothership_delta_machine_budget_replication_schema_count");
    suite.expect(replicated.machineSchemas[0].schema == "aws-brain-vm"_ctv, "mothership_delta_machine_budget_replication_schema");
    suite.expect(replicated.machineSchemas[0].budget == 0, "mothership_delta_machine_budget_replication_budget");
  }

  mothership.wBuffer.clear();
  follower.wBuffer.clear();

  {
    DeleteMachineSchema request = {};
    request.schema = "aws-brain-vm"_ctv;

    String serializedRequest = {};
    BitseryEngine::serialize(serializedRequest, request);
    Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::deleteMachineSchema, serializedRequest);
    brain.mothershipHandler(&mothership, message);

    Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
    String serializedResponse = {};
    uint8_t *responseArgs = responseMessage->args;
    Message::extractToStringView(responseArgs, serializedResponse);

    DeleteMachineSchema response = {};
    suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_delete_machine_schema_deserializes_response");
    suite.expect(response.success, "mothership_delete_machine_schema_succeeds");
    suite.expect(response.removed, "mothership_delete_machine_schema_reports_removed");
    suite.expect(response.hasTopology, "mothership_delete_machine_schema_returns_topology");
    suite.expect(brain.masterAuthorityRuntimeState.machineSchemas.empty(), "mothership_delete_machine_schema_clears_runtime_state");

    ProdigyMasterAuthorityRuntimeState replicated = {};
    suite.expect(extractReplicatedRuntimeState(replicated), "mothership_delete_machine_schema_replication_queued");
    suite.expect(replicated.machineSchemas.empty(), "mothership_delete_machine_schema_replication_empty");
  }
}

static void testManagedMachineSchemaRequestCarriesClusterUUID(TestSuite& suite)
{
  ResumableAddMachinesBrain brain;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.brainConfig.clusterUUID = 0x5501;
  brain.brainConfig.bootstrapSshUser = "root"_ctv;
  brain.brainConfig.bootstrapSshPrivateKeyPath = "/tmp/test-key"_ctv;
  brain.brainConfig.remoteProdigyPath = "/root/prodigy"_ctv;
  brain.brainConfig.controlSocketPath = "/run/prodigy/control.sock"_ctv;
  brain.brainConfig.requiredBrainCount = 1;
  brain.brainConfig.architecture = MachineCpuArchitecture::x86_64;

  ProdigyManagedMachineSchema managedSchema = {};
  managedSchema.schema = "aws-brain-vm"_ctv;
  managedSchema.kind = MachineConfig::MachineKind::vm;
  managedSchema.lifetime = MachineLifetime::ondemand;
  managedSchema.providerMachineType = "c7i-flex.large"_ctv;
  managedSchema.budget = 1;
  brain.masterAuthorityRuntimeState.machineSchemas.push_back(managedSchema);

  ClusterTopology topology = {};
  topology.machines.push_back(ClusterMachine {});
  topology.machines.back().source = ClusterMachineSource::created;
  topology.machines.back().backing = ClusterMachineBacking::cloud;
  topology.machines.back().kind = MachineConfig::MachineKind::vm;
  topology.machines.back().lifetime = MachineLifetime::ondemand;
  topology.machines.back().isBrain = true;
  topology.machines.back().uuid = 0x5502;
  topology.machines.back().cloud.schema = "aws-brain-vm"_ctv;
  topology.machines.back().cloud.providerMachineType = "c7i-flex.large"_ctv;
  topology.machines.back().cloud.cloudID = "i-seed"_ctv;
  prodigyAppendUniqueClusterMachineAddress(topology.machines.back().addresses.privateAddresses, "10.55.0.10"_ctv, 24, "10.55.0.1"_ctv);

  AddMachines request = {};
  Brain::ManagedAddMachinesWork work = {};
  String failure = {};
  bool ok = brain.buildManagedMachineSchemaRequest(topology, request, work, &failure);
  suite.expect(ok, "managed_schema_request_build_ok");
  suite.expect(failure.size() == 0, "managed_schema_request_build_no_failure");
  suite.expect(request.clusterUUID == brain.brainConfig.clusterUUID, "managed_schema_request_carries_cluster_uuid");
  suite.expect(request.architecture == brain.brainConfig.architecture, "managed_schema_request_carries_cluster_architecture");
  suite.expect(work.createdMachines.empty(), "managed_schema_request_counts_existing_seed_against_budget");
}

static void testManagedMachineSchemaRequestRejectsExistingSeedWithMismatchedKind(TestSuite& suite)
{
  ResumableAddMachinesBrain brain;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.brainConfig.clusterUUID = 0x6601;
  brain.brainConfig.requiredBrainCount = 1;

  ProdigyManagedMachineSchema managedSchema = {};
  managedSchema.schema = "c7i-flex.large"_ctv;
  managedSchema.kind = MachineConfig::MachineKind::vm;
  managedSchema.lifetime = MachineLifetime::ondemand;
  managedSchema.providerMachineType = "c7i-flex.large"_ctv;
  managedSchema.budget = 1;
  brain.masterAuthorityRuntimeState.machineSchemas.push_back(managedSchema);

  ClusterTopology topology = {};
  topology.machines.push_back(ClusterMachine {});
  topology.machines.back().source = ClusterMachineSource::created;
  topology.machines.back().backing = ClusterMachineBacking::cloud;
  topology.machines.back().kind = MachineConfig::MachineKind::bareMetal;
  topology.machines.back().lifetime = MachineLifetime::ondemand;
  topology.machines.back().isBrain = true;
  topology.machines.back().uuid = 0x6602;
  topology.machines.back().cloud.schema = "c7i-flex.large"_ctv;
  topology.machines.back().cloud.providerMachineType = "c7i-flex.large"_ctv;
  topology.machines.back().cloud.cloudID = "i-seed"_ctv;
  prodigyAppendUniqueClusterMachineAddress(topology.machines.back().addresses.privateAddresses, "10.66.0.10"_ctv, 24, "10.66.0.1"_ctv);

  AddMachines request = {};
  Brain::ManagedAddMachinesWork work = {};
  String failure = {};
  bool ok = brain.buildManagedMachineSchemaRequest(topology, request, work, &failure);
  suite.expect(ok, "managed_schema_request_seed_without_kind_build_ok");
  suite.expect(failure.size() == 0, "managed_schema_request_seed_without_kind_no_failure");
  suite.expect(work.createdMachines.size() == 1, "managed_schema_request_seed_kind_mismatch_creates_replacement");
  suite.expect(work.createdMachines.size() == 1 && work.createdMachines[0].isBrain, "managed_schema_request_seed_kind_mismatch_replaces_brain");
  suite.expect(request.removedMachines.size() == 1, "managed_schema_request_seed_kind_mismatch_removes_old_seed");
}

static void testManagedMachineSchemaRequestTreatsVMImageChangeAsReplacement(TestSuite& suite)
{
  ResumableAddMachinesBrain brain;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.brainConfig.clusterUUID = 0x6701;
  brain.brainConfig.requiredBrainCount = 0;

  ProdigyManagedMachineSchema managedSchema = {};
  managedSchema.schema = "worker-vm"_ctv;
  managedSchema.kind = MachineConfig::MachineKind::vm;
  managedSchema.lifetime = MachineLifetime::ondemand;
  managedSchema.providerMachineType = "c7i.large"_ctv;
  managedSchema.vmImageURI = "image://v2"_ctv;
  managedSchema.budget = 1;
  brain.masterAuthorityRuntimeState.machineSchemas.push_back(managedSchema);

  ClusterTopology topology = {};
  topology.machines.push_back(ClusterMachine {});
  topology.machines.back().source = ClusterMachineSource::created;
  topology.machines.back().backing = ClusterMachineBacking::cloud;
  topology.machines.back().kind = MachineConfig::MachineKind::vm;
  topology.machines.back().lifetime = MachineLifetime::ondemand;
  topology.machines.back().uuid = 0x6702;
  topology.machines.back().cloud.schema = "worker-vm"_ctv;
  topology.machines.back().cloud.providerMachineType = "c7i.large"_ctv;
  topology.machines.back().cloud.cloudID = "i-worker-old"_ctv;
  topology.machines.back().vmImageURI = "image://v1"_ctv;
  prodigyAppendUniqueClusterMachineAddress(topology.machines.back().addresses.privateAddresses, "10.67.0.20"_ctv, 24, "10.67.0.1"_ctv);

  AddMachines request = {};
  Brain::ManagedAddMachinesWork work = {};
  String failure = {};
  bool ok = brain.buildManagedMachineSchemaRequest(topology, request, work, &failure);
  suite.expect(ok, "managed_schema_request_vm_image_change_build_ok");
  suite.expect(failure.size() == 0, "managed_schema_request_vm_image_change_no_failure");
  suite.expect(request.removedMachines.size() == 1, "managed_schema_request_vm_image_change_removes_old_vm");
  suite.expect(work.createdMachines.size() == 1, "managed_schema_request_vm_image_change_creates_replacement");
  suite.expect(work.createdMachines.size() == 1 && work.createdMachines[0].cloud.schema == "worker-vm"_ctv, "managed_schema_request_vm_image_change_reuses_schema");

  topology.machines[0].vmImageURI = "image://v2"_ctv;
  request = {};
  work = {};
  ok = brain.buildManagedMachineSchemaRequest(topology, request, work, &failure);
  suite.expect(ok, "managed_schema_request_vm_image_match_build_ok");
  suite.expect(request.removedMachines.empty(), "managed_schema_request_vm_image_match_no_remove");
  suite.expect(work.createdMachines.empty(), "managed_schema_request_vm_image_match_no_create");
}

static void seedOSUpdateMachine(
    ResumableAddMachinesBrain& brain,
    Machine& machine,
    const String& slug,
    MachineConfig::MachineKind kind,
    uint32_t uuid,
    const String& osVersionID,
    bool isThisMachine = false)
{
  MachineConfig config = {};
  config.slug = slug;
  config.kind = kind;
  config.nLogicalCores = 4;
  config.nMemoryMB = 8192;
  config.nStorageMB = 65'536;
  if (kind == MachineConfig::MachineKind::vm)
  {
    config.vmImageURI = "image://current"_ctv;
  }
  brain.brainConfig.configBySlug.insert_or_assign(slug, config);

  machine.slug = slug;
  machine.uuid = uuid;
  machine.state = MachineState::healthy;
  machine.osID = "ubuntu"_ctv;
  machine.osVersionID = osVersionID;
  machine.lastUpdatedOSMs = int64_t(uuid) * 1000;
  machine.isThisMachine = isThisMachine;
  machine.neuron.machine = &machine;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = int(uuid % 64) + 1;
  machine.neuron.connected = true;
  if (kind == MachineConfig::MachineKind::vm)
  {
    machine.cloudID = "i-os-update"_ctv;
    machine.currentImageURI = "image://current"_ctv;
  }

  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);
}

static OperatingSystemUpdatePolicy makeOSUpdatePolicy(
    const String& osID,
    const String& targetVersionID,
    const String& command,
    bool includeVMs = false)
{
  OperatingSystemUpdatePolicy policy = {};
  policy.osID = osID;
  policy.targetVersionID = targetVersionID;
  policy.command = command;
  policy.includeVMs = includeVMs;
  return policy;
}

static bool extractQueuedOSUpdateTarget(Machine& machine, String& targetOSID, String& targetOSVersionID, String& updateCommand)
{
  if (machine.neuron.wBuffer.size() == 0)
  {
    return false;
  }

  Message *message = reinterpret_cast<Message *>(machine.neuron.wBuffer.data());
  if (NeuronTopic(message->topic) != NeuronTopic::updateOS)
  {
    return false;
  }

  uint8_t *args = message->args;
  Message::extractToStringView(args, targetOSID);
  Message::extractToStringView(args, targetOSVersionID);
  Message::extractToStringView(args, updateCommand);
  return true;
}

static bool extractQueuedRelinquishTarget(BrainView& peer, uint128_t& designatedPeerKey)
{
  if (peer.wBuffer.size() == 0)
  {
    return false;
  }

  Message *message = reinterpret_cast<Message *>(peer.wBuffer.data());
  if (BrainTopic(message->topic) != BrainTopic::relinquishMasterStatus)
  {
    return false;
  }

  uint8_t *args = message->args;
  uint8_t commandMarker = 0;
  if (Message::extractArg<ArgumentNature::fixed>(args, commandMarker) == false)
  {
    return false;
  }

  return Message::extractArg<ArgumentNature::fixed>(args, designatedPeerKey);
}

static void testOSUpdateSchedulerStartsFirstEligibleMachineWithoutCadenceDelay(TestSuite& suite)
{
  ResumableAddMachinesBrain brain;
  brain.weAreMaster = true;
  brain.ignited = true;
  brain.brainConfig.osUpdatesEnabled = true;
  brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, "true"_ctv));
  brain.brainConfig.maxOSDrains = 1;
  brain.brainConfig.machineUpdateCadenceMins = 30;

  Machine machine = {};
  seedOSUpdateMachine(brain, machine, "bare"_ctv, MachineConfig::MachineKind::bareMetal, 0x7001, "22.04"_ctv);

  brain.armMachineUpdateTimerIfNeeded();
  suite.expect(machine.state == MachineState::updatingOS, "os_update_scheduler_first_candidate_starts_without_cadence_delay");
  suite.expect(machine.osUpdateCommandIssued, "os_update_scheduler_first_candidate_queues_command");
  suite.expect(brain.lastOperatingSystemUpdateStartMs > 0, "os_update_scheduler_records_start_timestamp");

  String queuedOSID = {};
  String queuedOSVersionID = {};
  String queuedCommand = {};
  suite.expect(extractQueuedOSUpdateTarget(machine, queuedOSID, queuedOSVersionID, queuedCommand), "os_update_scheduler_first_candidate_update_message");
  suite.expect(queuedOSVersionID == "24.04"_ctv, "os_update_scheduler_first_candidate_target_version");
}

static void testOSUpdateSchedulerGatesTargetVMsConcurrencyAndReimages(TestSuite& suite)
{
  ResumableAddMachinesBrain brain;
  brain.weAreMaster = true;
  brain.ignited = true;
  brain.brainConfig.osUpdatesEnabled = true;
  brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy(
      "ubuntu"_ctv,
      "24.04"_ctv,
      "apt-get update && apt-get -y dist-upgrade && systemctl reboot"_ctv));
  brain.brainConfig.maxOSDrains = 1;
  brain.brainConfig.machineUpdateCadenceMins = 1;

  Machine bare = {};
  Machine vm = {};
  Machine current = {};
  Machine unknown = {};
  seedOSUpdateMachine(brain, bare, "bare"_ctv, MachineConfig::MachineKind::bareMetal, 0x7101, "22.04"_ctv);
  seedOSUpdateMachine(brain, vm, "vm"_ctv, MachineConfig::MachineKind::vm, 0x7102, "22.04"_ctv);
  seedOSUpdateMachine(brain, current, "current"_ctv, MachineConfig::MachineKind::bareMetal, 0x7103, "24.04"_ctv);
  seedOSUpdateMachine(brain, unknown, "unknown"_ctv, MachineConfig::MachineKind::bareMetal, 0x7104, String());

  bool started = brain.runMachineUpdateCadenceTick();
  suite.expect(started, "os_update_scheduler_starts_old_bare_metal");
  suite.expect(bare.state == MachineState::updatingOS, "os_update_scheduler_marks_machine_updating");
  suite.expect(bare.osUpdateCommandIssued, "os_update_scheduler_queues_neuron_command");
  String queuedOSID = {};
  String queuedOSVersionID = {};
  String queuedCommand = {};
  suite.expect(extractQueuedOSUpdateTarget(bare, queuedOSID, queuedOSVersionID, queuedCommand), "os_update_scheduler_queues_update_message");
  suite.expect(queuedOSID == "ubuntu"_ctv, "os_update_scheduler_queues_target_os_id");
  suite.expect(queuedOSVersionID == "24.04"_ctv, "os_update_scheduler_queues_target_os_version_id");
  suite.expect(queuedCommand == brain.brainConfig.osUpdatePolicies[0].command, "os_update_scheduler_queues_update_command");
  suite.expect(vm.state == MachineState::healthy, "os_update_scheduler_excludes_vm_by_default");
  suite.expect(current.state == MachineState::healthy, "os_update_scheduler_skips_current_version");
  suite.expect(unknown.state == MachineState::healthy, "os_update_scheduler_skips_unknown_version");

  started = brain.runMachineUpdateCadenceTick();
  suite.expect(started == false, "os_update_scheduler_respects_max_drains");

  bare.state = MachineState::healthy;
  bare.osVersionID = "24.04"_ctv;
  bare.osUpdateCommandIssued = false;
  brain.brainConfig.osUpdatePolicies[0].includeVMs = true;
  started = brain.runMachineUpdateCadenceTick();
  suite.expect(started, "os_update_scheduler_includes_vm_when_explicit");
  suite.expect(vm.state == MachineState::updatingOS, "os_update_scheduler_marks_vm_updating");
  queuedOSID.clear();
  queuedOSVersionID.clear();
  queuedCommand.clear();
  suite.expect(extractQueuedOSUpdateTarget(vm, queuedOSID, queuedOSVersionID, queuedCommand), "os_update_scheduler_queues_vm_update_message");
  suite.expect(queuedOSVersionID == "24.04"_ctv, "os_update_scheduler_queues_vm_target_version");

  vm.state = MachineState::healthy;
  vm.osVersionID = "22.04"_ctv;
  vm.osUpdateCommandIssued = false;
  vm.neuron.wBuffer.clear();
  brain.authoritativeTopology.machines.push_back(ClusterMachine {});
  brain.authoritativeTopology.machines.back().source = ClusterMachineSource::created;
  brain.authoritativeTopology.machines.back().backing = ClusterMachineBacking::cloud;
  brain.authoritativeTopology.machines.back().kind = MachineConfig::MachineKind::vm;
  brain.authoritativeTopology.machines.back().lifetime = MachineLifetime::ondemand;
  brain.authoritativeTopology.machines.back().cloud.schema = "vm"_ctv;
  brain.authoritativeTopology.machines.back().cloud.providerMachineType = "shape"_ctv;
  brain.authoritativeTopology.machines.back().vmImageURI = "image://old"_ctv;
  ProdigyManagedMachineSchema schema = {};
  schema.schema = "vm"_ctv;
  schema.kind = MachineConfig::MachineKind::vm;
  schema.lifetime = MachineLifetime::ondemand;
  schema.providerMachineType = "shape"_ctv;
  schema.vmImageURI = "image://new"_ctv;
  schema.budget = 1;
  brain.masterAuthorityRuntimeState.machineSchemas.push_back(schema);
  started = brain.runMachineUpdateCadenceTick();
  suite.expect(started == false, "os_update_scheduler_blocks_while_vm_reimage_pending");
  suite.expect(vm.osUpdateCommandIssued == false, "os_update_scheduler_no_command_during_reimage");
}

static void testOSUpdateLocalMasterHandsOffBeforeSelfUpdate(TestSuite& suite)
{
  ScopedFreshRing scopedRing = {};
  ResumableAddMachinesBrain brain;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.hasCompletedInitialMasterElection = true;
  brain.ignited = true;
  brain.nBrains = 3;
  brain.brainConfig.osUpdatesEnabled = true;
  brain.brainConfig.maxOSDrains = 1;
  brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, "apt-update"_ctv));

  Machine self = {};
  Machine peerMachine = {};
  seedOSUpdateMachine(brain, self, "self"_ctv, MachineConfig::MachineKind::bareMetal, 0x7301, "22.04"_ctv, true);
  seedOSUpdateMachine(brain, peerMachine, "peer"_ctv, MachineConfig::MachineKind::bareMetal, 0x7302, "24.04"_ctv);
  peerMachine.runtimeReady = true;

  BrainView peer = {};
  peer.machine = &peerMachine;
  peer.private4 = 0x0a580021;
  peer.uuid = peerMachine.uuid;
  peer.boottimens = 100;
  peer.registrationFresh = true;
  peer.connected = true;
  peer.isFixedFile = true;
  peer.fslot = 21;
  peerMachine.brain = &peer;
  brain.brains.insert(&peer);

  bool progressed = brain.runMachineUpdateCadenceTick();
  suite.expect(progressed, "os_update_local_master_handoff_progresses_scheduler");
  suite.expect(brain.weAreMaster == false, "os_update_local_master_handoff_forfeits_local_master");
  suite.expect(brain.noMasterYet == false, "os_update_local_master_handoff_keeps_master_selected");
  suite.expect(peer.isMasterBrain, "os_update_local_master_handoff_selects_updated_peer");
  suite.expect(self.state == MachineState::healthy, "os_update_local_master_handoff_does_not_mark_self_updating");
  suite.expect(self.osUpdateCommandIssued == false, "os_update_local_master_handoff_sends_no_self_update_command");

  uint128_t designatedPeerKey = 0;
  suite.expect(extractQueuedRelinquishTarget(peer, designatedPeerKey), "os_update_local_master_handoff_queues_relinquish");
  suite.expect(designatedPeerKey == uint128_t(peer.private4), "os_update_local_master_handoff_designates_target_peer");

  brain.brains.erase(&peer);
  brain.neurons.erase(&peerMachine.neuron);
  brain.machinesByUUID.erase(peerMachine.uuid);
  brain.machines.erase(&peerMachine);
  brain.neurons.erase(&self.neuron);
  brain.machinesByUUID.erase(self.uuid);
  brain.machines.erase(&self);
}

static void testOSUpdateLocalMasterDefersWithoutUpdatedHandoffPeer(TestSuite& suite)
{
  ScopedFreshRing scopedRing = {};
  ResumableAddMachinesBrain brain;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.hasCompletedInitialMasterElection = true;
  brain.ignited = true;
  brain.nBrains = 3;
  brain.brainConfig.osUpdatesEnabled = true;
  brain.brainConfig.maxOSDrains = 1;
  brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, "apt-update"_ctv));

  Machine self = {};
  Machine oldPeerMachine = {};
  seedOSUpdateMachine(brain, self, "self"_ctv, MachineConfig::MachineKind::bareMetal, 0x7311, "22.04"_ctv, true);
  seedOSUpdateMachine(brain, oldPeerMachine, "old-peer"_ctv, MachineConfig::MachineKind::bareMetal, 0x7312, "22.04"_ctv);
  oldPeerMachine.runtimeReady = true;
  oldPeerMachine.neuron.connected = false;

  BrainView peer = {};
  peer.machine = &oldPeerMachine;
  peer.private4 = 0x0a580022;
  peer.uuid = oldPeerMachine.uuid;
  peer.boottimens = 100;
  peer.registrationFresh = true;
  peer.connected = true;
  peer.isFixedFile = true;
  peer.fslot = 22;
  oldPeerMachine.brain = &peer;
  brain.brains.insert(&peer);

  bool progressed = brain.runMachineUpdateCadenceTick();
  suite.expect(progressed == false, "os_update_local_master_without_updated_peer_makes_no_progress");
  suite.expect(brain.weAreMaster, "os_update_local_master_without_updated_peer_remains_master");
  suite.expect(peer.isMasterBrain == false, "os_update_local_master_without_updated_peer_selects_no_peer");
  suite.expect(self.state == MachineState::healthy, "os_update_local_master_without_updated_peer_keeps_self_healthy");
  suite.expect(self.osUpdateCommandIssued == false, "os_update_local_master_without_updated_peer_sends_no_self_update");
  suite.expect(peer.wBuffer.empty(), "os_update_local_master_without_updated_peer_sends_no_relinquish");

  brain.brains.erase(&peer);
  brain.neurons.erase(&oldPeerMachine.neuron);
  brain.machinesByUUID.erase(oldPeerMachine.uuid);
  brain.machines.erase(&oldPeerMachine);
  brain.neurons.erase(&self.neuron);
  brain.machinesByUUID.erase(self.uuid);
  brain.machines.erase(&self);
}

static void testOSUpdateSingleBrainAllowsLocalMasterUpdate(TestSuite& suite)
{
  ScopedFreshRing scopedRing = {};
  ResumableAddMachinesBrain brain;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.hasCompletedInitialMasterElection = true;
  brain.ignited = true;
  brain.nBrains = 1;
  brain.brainConfig.osUpdatesEnabled = true;
  brain.brainConfig.maxOSDrains = 1;
  brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, "apt-update"_ctv));

  Machine self = {};
  seedOSUpdateMachine(brain, self, "self"_ctv, MachineConfig::MachineKind::bareMetal, 0x7321, "22.04"_ctv, true);

  bool progressed = brain.runMachineUpdateCadenceTick();
  suite.expect(progressed, "os_update_single_brain_local_master_progresses");
  suite.expect(brain.weAreMaster, "os_update_single_brain_local_master_keeps_master_role");
  suite.expect(self.state == MachineState::updatingOS, "os_update_single_brain_local_master_marks_updating");
  suite.expect(self.osUpdateCommandIssued, "os_update_single_brain_local_master_sends_update");

  brain.neurons.erase(&self.neuron);
  brain.machinesByUUID.erase(self.uuid);
  brain.machines.erase(&self);
}

static void testOSUpdateMachineStaysUpdatingUntilTargetVersionRuntimeReady(TestSuite& suite)
{
  ResumableAddMachinesBrain brain;
  brain.weAreMaster = true;
  brain.ignited = true;
  brain.brainConfig.datacenterFragment = 17;
  brain.brainConfig.osUpdatesEnabled = true;
  brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, "apt-update"_ctv));

  Machine machine = {};
  seedOSUpdateMachine(brain, machine, "bare"_ctv, MachineConfig::MachineKind::bareMetal, 0x7110, "22.04"_ctv);
  machine.state = MachineState::updatingOS;
  machine.osUpdateCommandIssued = true;
  machine.runtimeReady = true;
  machine.fragment = 1;
  machine.hardware.inventoryComplete = true;
  machine.hardware.cpu.logicalCores = 4;
  machine.hardware.memory.totalMB = 8192;

  brain.promoteMachineToHealthyIfReady(&machine);
  suite.expect(machine.state == MachineState::updatingOS, "os_update_machine_not_healthy_before_target_version");
  suite.expect(machine.osUpdateCommandIssued, "os_update_machine_keeps_command_issued_before_target_version");

  machine.osVersionID = "24.04"_ctv;
  machine.runtimeReady = false;
  brain.promoteMachineToHealthyIfReady(&machine);
  suite.expect(machine.state == MachineState::updatingOS, "os_update_machine_not_healthy_before_runtime_ready");

  machine.runtimeReady = true;
  brain.promoteMachineToHealthyIfReady(&machine);
  suite.expect(machine.state == MachineState::healthy, "os_update_machine_healthy_after_target_version_runtime_ready");
  suite.expect(machine.osUpdateCommandIssued == false, "os_update_machine_clears_command_after_completed_update");

  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
}

static void testOSUpdateHardRebootRecoveryStillRequiresTargetVersion(TestSuite& suite)
{
  ResumableAddMachinesBrain brain;
  brain.weAreMaster = true;
  brain.ignited = true;
  brain.brainConfig.datacenterFragment = 17;
  brain.brainConfig.osUpdatesEnabled = true;
  brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, "apt-update"_ctv));

  Machine machine = {};
  seedOSUpdateMachine(brain, machine, "bare"_ctv, MachineConfig::MachineKind::bareMetal, 0x7111, "22.04"_ctv);
  machine.state = MachineState::hardRebooting;
  machine.osUpdateCommandIssued = true;
  machine.runtimeReady = true;
  machine.fragment = 1;
  machine.hardware.inventoryComplete = true;
  machine.hardware.cpu.logicalCores = 4;
  machine.hardware.memory.totalMB = 8192;

  brain.promoteMachineToHealthyIfReady(&machine);
  suite.expect(machine.state == MachineState::hardRebooting, "os_update_hard_reboot_not_healthy_before_target_version");
  suite.expect(machine.osUpdateCommandIssued, "os_update_hard_reboot_keeps_command_before_target_version");

  machine.osVersionID = "24.04"_ctv;
  machine.runtimeReady = false;
  brain.promoteMachineToHealthyIfReady(&machine);
  suite.expect(machine.state == MachineState::hardRebooting, "os_update_hard_reboot_not_healthy_before_runtime_ready");

  machine.runtimeReady = true;
  brain.promoteMachineToHealthyIfReady(&machine);
  suite.expect(machine.state == MachineState::healthy, "os_update_hard_reboot_healthy_after_target_version_runtime_ready");
  suite.expect(machine.osUpdateCommandIssued == false, "os_update_hard_reboot_clears_command_after_completed_update");

  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
}

static void testOSUpdateHardRebootCountsAgainstDrainConcurrency(TestSuite& suite)
{
  ResumableAddMachinesBrain brain;
  brain.weAreMaster = true;
  brain.ignited = true;
  brain.brainConfig.osUpdatesEnabled = true;
  brain.brainConfig.maxOSDrains = 1;
  brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, "apt-update"_ctv));

  Machine rebooting = {};
  Machine eligible = {};
  seedOSUpdateMachine(brain, rebooting, "rebooting"_ctv, MachineConfig::MachineKind::bareMetal, 0x7112, "22.04"_ctv);
  seedOSUpdateMachine(brain, eligible, "eligible"_ctv, MachineConfig::MachineKind::bareMetal, 0x7113, "22.04"_ctv);
  rebooting.state = MachineState::hardRebooting;
  rebooting.osUpdateCommandIssued = true;

  bool started = brain.runMachineUpdateCadenceTick();
  suite.expect(started == false, "os_update_hard_reboot_counts_against_max_drains");
  suite.expect(eligible.state == MachineState::healthy, "os_update_hard_reboot_blocks_next_candidate");
  suite.expect(eligible.osUpdateCommandIssued == false, "os_update_hard_reboot_sends_no_second_command");

  brain.neurons.erase(&eligible.neuron);
  brain.machinesByUUID.erase(eligible.uuid);
  brain.machines.erase(&eligible);
  brain.neurons.erase(&rebooting.neuron);
  brain.machinesByUUID.erase(rebooting.uuid);
  brain.machines.erase(&rebooting);
}

static void testOSUpdateSchedulerFailsClosedAndRequiresDistroPolicy(TestSuite& suite)
{
  {
    ResumableAddMachinesBrain brain;
    brain.weAreMaster = true;
    brain.ignited = true;
    brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, "true"_ctv));

    Machine machine = {};
    seedOSUpdateMachine(brain, machine, "bare"_ctv, MachineConfig::MachineKind::bareMetal, 0x7200, "22.04"_ctv);
    bool started = brain.runMachineUpdateCadenceTick();
    suite.expect(started == false, "os_update_scheduler_global_switch_off_blocks_update");
    suite.expect(machine.state == MachineState::healthy, "os_update_scheduler_global_switch_off_keeps_machine_healthy");
    suite.expect(machine.osUpdateCommandIssued == false, "os_update_scheduler_global_switch_off_sends_no_update");
  }

  {
    ResumableAddMachinesBrain brain;
    brain.weAreMaster = true;
    brain.ignited = true;
    brain.brainConfig.osUpdatesEnabled = true;
    brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, String()));

    Machine machine = {};
    seedOSUpdateMachine(brain, machine, "bare"_ctv, MachineConfig::MachineKind::bareMetal, 0x7201, "22.04"_ctv);
    bool started = brain.runMachineUpdateCadenceTick();
    suite.expect(started == false, "os_update_scheduler_rejects_empty_command");
    suite.expect(machine.state == MachineState::healthy, "os_update_scheduler_empty_command_keeps_machine_healthy");
    suite.expect(machine.osUpdateCommandIssued == false, "os_update_scheduler_empty_command_sends_no_update");
    suite.expect(machine.neuron.wBuffer.empty(), "os_update_scheduler_empty_command_leaves_buffer_empty");
  }

  {
    ResumableAddMachinesBrain brain;
    brain.weAreMaster = true;
    brain.ignited = true;
    brain.brainConfig.osUpdatesEnabled = true;
    brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, "true"_ctv));

    Machine machine = {};
    seedOSUpdateMachine(brain, machine, "bare"_ctv, MachineConfig::MachineKind::bareMetal, 0x7202, "22.04"_ctv);
    machine.osID = "debian"_ctv;
    bool started = brain.runMachineUpdateCadenceTick();
    suite.expect(started == false, "os_update_scheduler_rejects_target_os_id_mismatch");
    suite.expect(machine.state == MachineState::healthy, "os_update_scheduler_os_id_mismatch_keeps_machine_healthy");
    suite.expect(machine.osUpdateCommandIssued == false, "os_update_scheduler_os_id_mismatch_sends_no_update");
  }

  {
    ResumableAddMachinesBrain brain;
    brain.weAreMaster = true;
    brain.ignited = true;
    brain.brainConfig.osUpdatesEnabled = true;

    Machine machine = {};
    seedOSUpdateMachine(brain, machine, "bare"_ctv, MachineConfig::MachineKind::bareMetal, 0x7203, "2026.04"_ctv);
    machine.osID = "any-distro"_ctv;
    bool started = brain.runMachineUpdateCadenceTick();
    suite.expect(started == false, "os_update_scheduler_rejects_missing_distro_policy");
    suite.expect(machine.state == MachineState::healthy, "os_update_scheduler_missing_policy_keeps_machine_healthy");
    suite.expect(machine.osUpdateCommandIssued == false, "os_update_scheduler_missing_policy_sends_no_update");
  }

  {
    ResumableAddMachinesBrain brain;
    brain.weAreMaster = true;
    brain.ignited = true;
    brain.brainConfig.osUpdatesEnabled = true;
    brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, "apt-update"_ctv));

    Machine ubuntu = {};
    Machine cachy = {};
    seedOSUpdateMachine(brain, ubuntu, "ubuntu-bare"_ctv, MachineConfig::MachineKind::bareMetal, 0x7206, "22.04"_ctv);
    seedOSUpdateMachine(brain, cachy, "cachy-bare"_ctv, MachineConfig::MachineKind::bareMetal, 0x7207, "2026.04"_ctv);
    cachy.osID = "cachyos"_ctv;

    bool started = brain.runMachineUpdateCadenceTick();
    suite.expect(started == false, "os_update_scheduler_missing_one_distro_policy_turns_off_all_updates");
    suite.expect(ubuntu.state == MachineState::healthy, "os_update_scheduler_missing_one_policy_keeps_matching_machine_healthy");
    suite.expect(ubuntu.osUpdateCommandIssued == false, "os_update_scheduler_missing_one_policy_sends_no_matching_update");
    suite.expect(cachy.osUpdateCommandIssued == false, "os_update_scheduler_missing_one_policy_sends_no_unmatched_update");
  }

  {
    ResumableAddMachinesBrain brain;
    brain.weAreMaster = true;
    brain.ignited = true;
    brain.brainConfig.osUpdatesEnabled = true;
    brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, "apt-update"_ctv));

    Machine machine = {};
    seedOSUpdateMachine(brain, machine, "unknown-identity"_ctv, MachineConfig::MachineKind::bareMetal, 0x7208, "22.04"_ctv);
    brain.machinesByUUID.erase(machine.uuid);
    machine.uuid = 0;

    bool started = brain.runMachineUpdateCadenceTick();
    suite.expect(started == false, "os_update_scheduler_waits_for_stable_machine_uuid");
    suite.expect(machine.state == MachineState::healthy, "os_update_scheduler_unknown_uuid_keeps_machine_healthy");
    suite.expect(machine.osUpdateCommandIssued == false, "os_update_scheduler_unknown_uuid_sends_no_update");
  }

  {
    ResumableAddMachinesBrain brain;
    brain.weAreMaster = true;
    brain.ignited = true;
    brain.brainConfig.osUpdatesEnabled = true;
    brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, "apt-update"_ctv));
    brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("debian"_ctv, "12.5"_ctv, "apt-debian"_ctv));

    Machine ubuntu = {};
    Machine debian = {};
    seedOSUpdateMachine(brain, ubuntu, "ubuntu-bare"_ctv, MachineConfig::MachineKind::bareMetal, 0x7204, "22.04"_ctv);
    seedOSUpdateMachine(brain, debian, "debian-bare"_ctv, MachineConfig::MachineKind::bareMetal, 0x7205, "12.4"_ctv);
    debian.osID = "debian"_ctv;
    ubuntu.lastUpdatedOSMs = 20;
    debian.lastUpdatedOSMs = 10;

    bool started = brain.runMachineUpdateCadenceTick();
    suite.expect(started, "os_update_scheduler_selects_matching_distro_policy");

    String queuedOSID = {};
    String queuedOSVersionID = {};
    String queuedCommand = {};
    suite.expect(extractQueuedOSUpdateTarget(debian, queuedOSID, queuedOSVersionID, queuedCommand), "os_update_scheduler_distro_policy_queues_update_message");
    suite.expect(queuedOSID == "debian"_ctv, "os_update_scheduler_distro_policy_queues_os_id");
    suite.expect(queuedOSVersionID == "12.5"_ctv, "os_update_scheduler_distro_policy_queues_target_version");
    suite.expect(queuedCommand == "apt-debian"_ctv, "os_update_scheduler_distro_policy_queues_command");
  }
}

static void testOSUpdateMissingTransitionWaitsForRebootRecovery(TestSuite& suite)
{
  TestBrain brain = {};
  TrackingBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  Machine machine = {};
  machine.uuid = uint128_t(0x7210);
  machine.private4 = 0x0a580011;
  machine.state = MachineState::updatingOS;
  machine.sshRestartAttempts = 2;
  machine.osUpdateCommandIssued = true;
  machine.neuron.machine = &machine;
  machine.neuron.connectTimeoutMs = 50;
  machine.neuron.nDefaultAttemptsBudget = 1;

  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  brain.handleMachineStateChange(&machine, MachineState::missing);

  suite.expect(machine.state == MachineState::hardRebooting, "os_update_missing_transition_waits_for_reboot_recovery");
  suite.expect(machine.hardRebootWatchdog != nullptr, "os_update_missing_transition_arms_reboot_watchdog");
  suite.expect(machine.lastHardRebootMs > 0, "os_update_missing_transition_records_reboot_wait_start");
  suite.expect(machine.neuron.reconnectAfterClose, "os_update_missing_transition_keeps_neuron_reconnect_enabled");
  suite.expect(machine.neuron.attemptDeadlineMs > Time::now<TimeResolution::ms>(), "os_update_missing_transition_extends_neuron_reconnect_window");
  suite.expect(machine.sshRestartAttempts == 2, "os_update_missing_transition_does_not_consume_ssh_restart_budget");
  suite.expect(iaas.hardRebootCalls == 0, "os_update_missing_transition_does_not_issue_iaas_reboot");
  suite.expect(iaas.reportHardwareFailureCalls == 0, "os_update_missing_transition_does_not_report_hardware_failure");
  suite.expect(iaas.destroyCalls == 0, "os_update_missing_transition_does_not_destroy_machine");

  brain.cancelMachineHardRebootWatchdog(&machine);
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
}

static void testOSUpdateCommandDeadlineFailsClosed(TestSuite& suite)
{
  ScopedFreshRing scopedRing = {};

  ResumableAddMachinesBrain brain = {};
  TrackingBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.ignited = true;
  brain.brainConfig.osUpdatesEnabled = true;
  brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, "false"_ctv));

  Rack *rack = new Rack();
  rack->uuid = 0x72109001;
  brain.racks.insert_or_assign(rack->uuid, rack);

  Machine *machine = new Machine();
  seedOSUpdateMachine(brain, *machine, "deadline-bare"_ctv, MachineConfig::MachineKind::bareMetal, 0x72109002, "22.04"_ctv);
  machine->rack = rack;
  machine->lifetime = MachineLifetime::owned;
  rack->machines.insert(machine);

  bool started = brain.runMachineUpdateCadenceTick();
  TimeoutPacket *watchdog = machine->osUpdateCommandWatchdog;

  suite.expect(started, "os_update_command_deadline_starts_update");
  suite.expect(watchdog != nullptr, "os_update_command_deadline_arms_watchdog");
  suite.expect(machine->state == MachineState::updatingOS, "os_update_command_deadline_machine_enters_updating");
  suite.expect(machine->osUpdateCommandIssued, "os_update_command_deadline_marks_command_issued");

  brain.dispatchTimeout(watchdog);

  suite.expect(iaas.reportHardwareFailureCalls == 1, "os_update_command_deadline_reports_hardware_failure");
  suite.expect(iaas.lastReportedHardwareFailureUUID == uint128_t(0x72109002), "os_update_command_deadline_reports_failed_machine_uuid");
  suite.expect(iaas.destroyCalls == 1, "os_update_command_deadline_destroys_failed_machine");
  suite.expect(brain.machinesByUUID.find(uint128_t(0x72109002)) == brain.machinesByUUID.end(), "os_update_command_deadline_removes_machine_index");
}

static void testOSUpdateBrainPeerCloseMarksExpectedReboot(TestSuite& suite)
{
  ScopedFreshRing scopedRing = {};

  TestBrain brain = {};
  TrackingBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.nBrains = 3;

  Machine machine = {};
  machine.uuid = uint128_t(0x7211);
  machine.private4 = 0x0a580012;
  machine.state = MachineState::updatingOS;
  machine.osUpdateCommandIssued = true;
  machine.neuron.machine = &machine;
  machine.neuron.connectTimeoutMs = 50;
  machine.neuron.nDefaultAttemptsBudget = 1;

  BrainView peer = {};
  peer.machine = &machine;
  peer.private4 = machine.private4;
  peer.uuid = machine.uuid;
  peer.weConnectToIt = true;
  peer.confirmedMissingTransportEpoch = 1;
  peer.queuedCloseTransportEpoch = 1;
  peer.transportEpoch = 1;
  peer.connectTimeoutMs = 50;
  peer.nDefaultAttemptsBudget = 1;
  machine.brain = &peer;

  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);
  brain.brains.insert(&peer);

  brain.closeHandler(&peer);

  suite.expect(machine.state == MachineState::hardRebooting, "os_update_brain_peer_close_marks_expected_reboot");
  suite.expect(machine.hardRebootWatchdog != nullptr, "os_update_brain_peer_close_arms_reboot_watchdog");
  suite.expect(machine.osUpdateCommandIssued, "os_update_brain_peer_close_preserves_update_completion_gate");
  suite.expect(iaas.hardRebootCalls == 0, "os_update_brain_peer_close_does_not_issue_iaas_reboot");

  brain.cancelMachineHardRebootWatchdog(&machine);
  brain.brains.erase(&peer);
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
}

static void testOSUpdateBrainRegistrationCompletesHardRebootedPeer(TestSuite& suite)
{
  TestBrain brain = {};
  brain.weAreMaster = true;
  brain.ignited = true;
  brain.brainConfig.datacenterFragment = 17;
  brain.brainConfig.osUpdatesEnabled = true;
  brain.brainConfig.osUpdatePolicies.push_back(makeOSUpdatePolicy("ubuntu"_ctv, "24.04"_ctv, "apt-update"_ctv));

  Machine machine = {};
  machine.uuid = uint128_t(0x7212);
  machine.private4 = 0x0a580013;
  machine.state = MachineState::hardRebooting;
  machine.osID = "ubuntu"_ctv;
  machine.osVersionID = "22.04"_ctv;
  machine.osUpdateCommandIssued = true;
  machine.runtimeReady = true;
  machine.fragment = 1;
  machine.neuron.machine = &machine;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 31;
  machine.neuron.connected = true;
  machine.hardware.inventoryComplete = true;
  machine.hardware.cpu.logicalCores = 4;
  machine.hardware.memory.totalMB = 8192;

  BrainView peer = {};
  peer.machine = &machine;
  peer.private4 = machine.private4;
  machine.brain = &peer;

  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);
  brain.brains.insert(&peer);

  String buffer = {};
  Message::construct(
      buffer,
      BrainTopic::registration,
      machine.uuid,
      int64_t(1'777'793'627'211'152'933),
      uint64_t(1),
      uint128_t(0),
      "linux-test"_ctv,
      "ubuntu"_ctv,
      "24.04"_ctv);
  Message *message = reinterpret_cast<Message *>(buffer.data());
  brain.brainHandler(&peer, message);

  suite.expect(machine.osVersionID == "24.04"_ctv, "os_update_brain_registration_updates_target_version");
  suite.expect(machine.state == MachineState::healthy, "os_update_brain_registration_completes_hard_rebooted_peer");
  suite.expect(machine.osUpdateCommandIssued == false, "os_update_brain_registration_clears_update_command");

  brain.brains.erase(&peer);
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
}

static void testNeuronOSUpdateParsingAndDispatch(TestSuite& suite)
{
  {
    String osRelease = {};
    osRelease.assign("NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=24.04\n"_ctv);
    String parsedOSID = {};
    String parsedOSVersionID = {};
    suite.expect(TestNeuron::parseOSReleaseMetadataForTest(osRelease, parsedOSID, parsedOSVersionID), "neuron_parse_os_release_plain_ok");
    suite.expect(parsedOSID == "ubuntu"_ctv, "neuron_parse_os_release_plain_id");
    suite.expect(parsedOSVersionID == "24.04"_ctv, "neuron_parse_os_release_plain_version_id");
  }

  {
    String osRelease = {};
    osRelease.assign("ID=\"debian\"\nVERSION_ID=\"12\"\n"_ctv);
    String parsedOSID = {};
    String parsedOSVersionID = {};
    suite.expect(TestNeuron::parseOSReleaseMetadataForTest(osRelease, parsedOSID, parsedOSVersionID), "neuron_parse_os_release_quoted_ok");
    suite.expect(parsedOSID == "debian"_ctv, "neuron_parse_os_release_quoted_id");
    suite.expect(parsedOSVersionID == "12"_ctv, "neuron_parse_os_release_quoted_version_id");
  }

  {
    String osRelease = {};
    osRelease.assign("NAME=\"No Version\"\n"_ctv);
    String parsedOSID = {};
    String parsedOSVersionID = {};
    suite.expect(TestNeuron::parseOSReleaseMetadataForTest(osRelease, parsedOSID, parsedOSVersionID) == false, "neuron_parse_os_release_missing_keys");
  }

  TestNeuron neuron = {};
  String failure = {};
  suite.expect(neuron.Neuron::startOperatingSystemUpdate(String(), "24.04"_ctv, "true"_ctv, &failure) == false, "neuron_update_os_rejects_empty_target_os_id");
  suite.expect(failure.size() > 0, "neuron_update_os_empty_target_os_id_reports_failure");
  failure.clear();
  suite.expect(neuron.Neuron::startOperatingSystemUpdate("ubuntu"_ctv, String(), "true"_ctv, &failure) == false, "neuron_update_os_rejects_empty_target_version");
  suite.expect(failure.size() > 0, "neuron_update_os_empty_target_version_reports_failure");
  failure.clear();
  suite.expect(neuron.Neuron::startOperatingSystemUpdate("ubuntu"_ctv, "24.04"_ctv, String(), &failure) == false, "neuron_update_os_rejects_empty_command");
  suite.expect(failure.size() > 0, "neuron_update_os_empty_command_reports_failure");

  neuron.seedBrainStreamForTest(true);
  String buffer = {};
  Message *message = buildNeuronMessage(buffer, NeuronTopic::updateOS, "ubuntu"_ctv, "24.04"_ctv, "true"_ctv);
  neuron.neuronHandler(message);
  suite.expect(neuron.startOSUpdateCallsForTest == 1, "neuron_update_os_dispatches_start");
  suite.expect(neuron.lastOSUpdateTargetOSIDForTest == "ubuntu"_ctv, "neuron_update_os_dispatches_target_os_id");
  suite.expect(neuron.lastOSUpdateTargetOSVersionIDForTest == "24.04"_ctv, "neuron_update_os_dispatches_target_os_version_id");
  suite.expect(neuron.lastOSUpdateCommandForTest == "true"_ctv, "neuron_update_os_dispatches_command");

  neuron.brainStreamForTest()->wBuffer.clear();
  neuron.failOSUpdateStartForTest = true;
  buffer.clear();
  message = buildNeuronMessage(buffer, NeuronTopic::updateOS, "ubuntu"_ctv, "24.10"_ctv, "false"_ctv);
  neuron.neuronHandler(message);
  suite.expect(neuron.startOSUpdateCallsForTest == 2, "neuron_update_os_failure_attempts_start");
  Message *failureMessage = reinterpret_cast<Message *>(neuron.brainStreamForTest()->wBuffer.data());
  suite.expect(NeuronTopic(failureMessage->topic) == NeuronTopic::hardwareFailure, "neuron_update_os_failure_reports_hardware_failure");
}

static void testMachineSchemaMutationsDriveManagedBudgetActions(TestSuite& suite)
{
  ResumableAddMachinesBrain brain;
  AutoProvisionBrainIaaS iaas;
  Mothership mothership;
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.nBrains = 1;
  brain.brainConfig.clusterUUID = 0x4401;
  brain.brainConfig.bootstrapSshUser = "root"_ctv;
  brain.brainConfig.bootstrapSshPrivateKeyPath = "/tmp/test-key"_ctv;
  brain.brainConfig.requiredBrainCount = 1;
  MachineConfig workerConfig = {};
  workerConfig.slug = "aws-worker-vm"_ctv;
  workerConfig.kind = MachineConfig::MachineKind::vm;
  workerConfig.nLogicalCores = 4;
  workerConfig.nMemoryMB = 8192;
  workerConfig.nStorageMB = 65'536;
  workerConfig.vmImageURI = "image://worker"_ctv;
  brain.brainConfig.configBySlug.insert_or_assign(workerConfig.slug, workerConfig);
  uint32_t bootstrapPrivate4 = IPAddress("10.0.0.10", false).v4;
  brain.authoritativeTopology.version = 9;
  brain.authoritativeTopology.machines.push_back(ClusterMachine {});
  brain.authoritativeTopology.machines.back().source = ClusterMachineSource::adopted;
  brain.authoritativeTopology.machines.back().backing = ClusterMachineBacking::owned;
  brain.authoritativeTopology.machines.back().kind = MachineConfig::MachineKind::vm;
  brain.authoritativeTopology.machines.back().lifetime = MachineLifetime::owned;
  brain.authoritativeTopology.machines.back().isBrain = true;
  brain.authoritativeTopology.machines.back().uuid = 0x1001;
  brain.authoritativeTopology.machines.back().rackUUID = 0x2001;
  brain.authoritativeTopology.machines.back().ssh.address.assign("10.0.0.10"_ctv);
  brain.authoritativeTopology.machines.back().ssh.user.assign("root"_ctv);
  brain.authoritativeTopology.machines.back().ssh.privateKeyPath.assign("/tmp/test-key"_ctv);
  prodigyAppendUniqueClusterMachineAddress(brain.authoritativeTopology.machines.back().addresses.privateAddresses, "10.0.0.10"_ctv, 24, "10.0.0.1"_ctv);
  brain.authoritativeTopology.machines.back().ownedLogicalCores = 4;
  brain.authoritativeTopology.machines.back().ownedMemoryMB = 8192;
  brain.authoritativeTopology.machines.back().ownedStorageMB = 65'536;
  brain.authoritativeTopology.machines.back().totalLogicalCores = 4;
  brain.authoritativeTopology.machines.back().totalMemoryMB = 8192;
  brain.authoritativeTopology.machines.back().totalStorageMB = 65'536;

  BrainView followerTransport = {};
  followerTransport.isFixedFile = true;
  followerTransport.fslot = 31;
  followerTransport.connected = true;
  followerTransport.uuid = 0x1001;
  followerTransport.private4 = bootstrapPrivate4;
  brain.brains.insert(&followerTransport);

  ResumableAddMachinesBrain followerBrain = {};
  NoopBrainIaaS followerIaaS = {};
  followerBrain.iaas = &followerIaaS;

  BrainView replicationPeer = {};
  replicationPeer.isFixedFile = true;
  replicationPeer.fslot = 41;
  replicationPeer.connected = true;
  replicationPeer.uuid = 0x1001;
  replicationPeer.private4 = bootstrapPrivate4;
  followerBrain.brains.insert(&replicationPeer);

  String messageBuffer = {};
  auto applyCurrentStateToFollower = [&]() -> bool {
    String serializedRuntimeState = {};
    BitseryEngine::serialize(serializedRuntimeState, brain.masterAuthorityRuntimeState);
    Message *runtimeMessage = buildBrainMessage(messageBuffer, BrainTopic::replicateMasterAuthorityState, serializedRuntimeState);
    followerBrain.brainHandler(&replicationPeer, runtimeMessage);

    String serializedTopology = {};
    BitseryEngine::serialize(serializedTopology, brain.authoritativeTopology);
    Message *topologyMessage = buildBrainMessage(messageBuffer, BrainTopic::replicateClusterTopology, serializedTopology);
    followerBrain.brainHandler(&replicationPeer, topologyMessage);
    return true;
  };

  {
    iaas.observedBrain = &brain;
    iaas.snapshotsToReturn.push_back(makeMachineSnapshot("aws-worker-vm"_ctv, "10.0.0.20"_ctv, "i-worker-0"_ctv, 0x5001));

    UpsertMachineSchemas request = {};
    ProdigyManagedMachineSchemaPatch patch = {};
    patch.schema = "aws-worker-vm"_ctv;
    patch.hasKind = true;
    patch.kind = MachineConfig::MachineKind::vm;
    patch.hasLifetime = true;
    patch.lifetime = MachineLifetime::ondemand;
    patch.hasProviderMachineType = true;
    patch.providerMachineType = "c7i.large"_ctv;
    patch.hasRegion = true;
    patch.region = "us-east-1"_ctv;
    patch.hasZone = true;
    patch.zone = "us-east-1a"_ctv;
    patch.hasBudget = true;
    patch.budget = 1;
    request.patches.push_back(patch);

    String serializedRequest = {};
    BitseryEngine::serialize(serializedRequest, request);
    Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::upsertMachineSchemas, serializedRequest);
    brain.mothershipHandler(&mothership, message);

    Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
    String serializedResponse = {};
    uint8_t *responseArgs = responseMessage->args;
    Message::extractToStringView(responseArgs, serializedResponse);

    UpsertMachineSchemas response = {};
    suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_upsert_machine_schemas_deserializes_response");
    suite.expect(response.success, "mothership_upsert_machine_schemas_succeeds");
    suite.expect(response.created == 1, "mothership_upsert_machine_schemas_reports_created");
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
    suite.expect(response.hasTimingAttribution, "mothership_upsert_machine_schemas_reports_timing_attribution");
#endif
    suite.expect(response.hasTopology, "mothership_upsert_machine_schemas_returns_topology");
    suite.expect(response.topology.version == 10, "mothership_upsert_machine_schemas_returns_updated_topology_version");
    suite.expect(response.topology.machines.size() == 2, "mothership_upsert_machine_schemas_returns_created_machine_topology");
    suite.expect(brain.masterAuthorityRuntimeState.machineSchemas.size() == 1, "mothership_upsert_machine_schemas_stores_runtime_state");
    suite.expect(brain.masterAuthorityRuntimeState.machineSchemas[0].schema == "aws-worker-vm"_ctv, "mothership_upsert_machine_schemas_stores_schema");
    suite.expect(brain.masterAuthorityRuntimeState.machineSchemas[0].budget == 1, "mothership_upsert_machine_schemas_stores_budget");
    suite.expect(iaas.spinCalls == 1, "mothership_upsert_machine_schemas_triggers_managed_provisioning");
    suite.expect(iaas.acceptedCallbacks == 1, "mothership_upsert_machine_schemas_reports_create_acceptance");
    suite.expect(iaas.provisionedCallbacks == 1, "mothership_upsert_machine_schemas_reports_ready_machine");
    suite.expect(iaas.sawPendingOperationDuringSpin, "mothership_upsert_machine_schemas_journals_before_spin_returns");
    suite.expect(iaas.sawBootstrapDuringSpin, "mothership_upsert_machine_schemas_bootstraps_before_spin_returns");
    suite.expect(brain.bootstrappedMachines.size() == 1, "mothership_upsert_machine_schemas_bootstraps_created_machine");
    suite.expect(brain.blockingBootstrapCallsWithBundleCache == 1, "mothership_upsert_machine_schemas_reuses_bundle_cache_for_blocking_bootstrap");
    suite.expect(brain.blockingBootstrapCallsWithoutBundleCache == 0, "mothership_upsert_machine_schemas_avoids_uncached_blocking_bootstrap");
    suite.expect(brain.authoritativeTopology.version == 10, "mothership_upsert_machine_schemas_persists_updated_topology_version");
    suite.expect(brain.authoritativeTopology.machines.size() == 2, "mothership_upsert_machine_schemas_persists_created_machine");

    bool foundCreatedMachine = false;
    for (const ClusterMachine& machine : brain.authoritativeTopology.machines)
    {
      if (machine.source == ClusterMachineSource::created && machine.cloud.schema.equals("aws-worker-vm"_ctv))
      {
        foundCreatedMachine = true;
        suite.expect(machine.backing == ClusterMachineBacking::cloud, "mothership_upsert_machine_schemas_created_machine_is_cloud");
        suite.expect(machine.cloud.cloudID.equals("i-worker-0"_ctv), "mothership_upsert_machine_schemas_created_machine_keeps_cloud_id");
      }
    }
    suite.expect(foundCreatedMachine, "mothership_upsert_machine_schemas_persists_created_machine_identity");

    uint32_t previousFollowerApplyCalls = followerBrain.masterAuthorityApplyCalls;
    suite.expect(applyCurrentStateToFollower(), "mothership_upsert_machine_schemas_follower_applies_replication");
    suite.expect(followerBrain.masterAuthorityRuntimeState.machineSchemas.size() == 1, "mothership_upsert_machine_schemas_follower_restores_runtime_state");
    if (followerBrain.masterAuthorityRuntimeState.machineSchemas.empty() == false)
    {
      suite.expect(followerBrain.masterAuthorityRuntimeState.machineSchemas[0].budget == 1, "mothership_upsert_machine_schemas_follower_restores_budget");
    }
    suite.expect(followerBrain.authoritativeTopology.machines.size() == 2, "mothership_upsert_machine_schemas_follower_restores_topology");
    suite.expect(followerBrain.masterAuthorityApplyCalls > previousFollowerApplyCalls, "mothership_upsert_machine_schemas_follower_applies_master_state");
  }

  mothership.wBuffer.clear();
  followerTransport.wBuffer.clear();

  {
    DeltaMachineBudget request = {};
    request.schema = "aws-worker-vm"_ctv;
    request.delta = -1;

    String serializedRequest = {};
    BitseryEngine::serialize(serializedRequest, request);
    Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::deltaMachineBudget, serializedRequest);
    brain.mothershipHandler(&mothership, message);

    Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
    String serializedResponse = {};
    uint8_t *responseArgs = responseMessage->args;
    Message::extractToStringView(responseArgs, serializedResponse);

    DeltaMachineBudget response = {};
    suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_delta_machine_budget_deserializes_response");
    suite.expect(response.success, "mothership_delta_machine_budget_succeeds");
    suite.expect(response.budget == 0, "mothership_delta_machine_budget_clamps_budget");
    suite.expect(response.hasTopology, "mothership_delta_machine_budget_returns_topology");
    suite.expect(response.topology.version == 11, "mothership_delta_machine_budget_returns_reconciled_topology_version");
    suite.expect(response.topology.machines.size() == 1, "mothership_delta_machine_budget_returns_pruned_topology");
    suite.expect(brain.authoritativeTopology.version == 11, "mothership_delta_machine_budget_persists_pruned_topology_version");
    suite.expect(brain.authoritativeTopology.machines.size() == 1, "mothership_delta_machine_budget_persists_pruned_topology");
    suite.expect(brain.masterAuthorityRuntimeState.machineSchemas.size() == 1, "mothership_delta_machine_budget_keeps_schema_entry");
    suite.expect(brain.masterAuthorityRuntimeState.machineSchemas[0].budget == 0, "mothership_delta_machine_budget_updates_runtime_budget");
    suite.expect(iaas.spinCalls == 1, "mothership_delta_machine_budget_does_not_reprovision");

    uint32_t previousFollowerApplyCalls = followerBrain.masterAuthorityApplyCalls;
    suite.expect(applyCurrentStateToFollower(), "mothership_delta_machine_budget_follower_applies_replication");
    suite.expect(followerBrain.masterAuthorityRuntimeState.machineSchemas.size() == 1, "mothership_delta_machine_budget_follower_keeps_schema_entry");
    if (followerBrain.masterAuthorityRuntimeState.machineSchemas.empty() == false)
    {
      suite.expect(followerBrain.masterAuthorityRuntimeState.machineSchemas[0].budget == 0, "mothership_delta_machine_budget_follower_updates_budget");
    }
    suite.expect(followerBrain.authoritativeTopology.machines.size() == 1, "mothership_delta_machine_budget_follower_prunes_topology");
    suite.expect(followerBrain.masterAuthorityApplyCalls > previousFollowerApplyCalls, "mothership_delta_machine_budget_follower_applies_master_state");
  }

  mothership.wBuffer.clear();
  followerTransport.wBuffer.clear();

  {
    DeleteMachineSchema request = {};
    request.schema = "aws-worker-vm"_ctv;

    String serializedRequest = {};
    BitseryEngine::serialize(serializedRequest, request);
    Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::deleteMachineSchema, serializedRequest);
    brain.mothershipHandler(&mothership, message);

    Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
    String serializedResponse = {};
    uint8_t *responseArgs = responseMessage->args;
    Message::extractToStringView(responseArgs, serializedResponse);

    DeleteMachineSchema response = {};
    suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_delete_machine_schema_deserializes_response");
    suite.expect(response.success, "mothership_delete_machine_schema_succeeds");
    suite.expect(response.removed, "mothership_delete_machine_schema_reports_removed");
    suite.expect(response.hasTopology, "mothership_delete_machine_schema_returns_topology");
    suite.expect(brain.masterAuthorityRuntimeState.machineSchemas.empty(), "mothership_delete_machine_schema_clears_runtime_state");
    suite.expect(brain.authoritativeTopology.version == 11, "mothership_delete_machine_schema_leaves_topology_version_when_no_machine_change");
    suite.expect(brain.authoritativeTopology.machines.size() == 1, "mothership_delete_machine_schema_leaves_pruned_topology");

    uint32_t previousFollowerApplyCalls = followerBrain.masterAuthorityApplyCalls;
    suite.expect(applyCurrentStateToFollower(), "mothership_delete_machine_schema_follower_applies_runtime_replication");
    suite.expect(followerBrain.masterAuthorityRuntimeState.machineSchemas.empty(), "mothership_delete_machine_schema_follower_clears_runtime_state");
    suite.expect(followerBrain.authoritativeTopology.machines.size() == 1, "mothership_delete_machine_schema_follower_keeps_latest_topology");
    suite.expect(followerBrain.masterAuthorityApplyCalls > previousFollowerApplyCalls, "mothership_delete_machine_schema_follower_applies_master_state");
  }
}

static void testReplicatedBrainConfigReplaysFullSwitchboardState(TestSuite& suite)
{
  TestBrain brain;
  NoopBrainIaaS iaas;
  brain.iaas = &iaas;

  Machine machine = {};
  machine.uuid = uint128_t(0x1111);
  machine.slug.assign("test-machine"_ctv);
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 7;
  machine.neuron.connected = true;
  machine.neuron.pendingSend = true;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

  BrainConfig replicated = {};
  replicated.runtimeEnvironment.test.enabled = true;

  DistributableExternalSubnet prefix = {};
  prefix.uuid = uint128_t(0xABC123);
  prefix.name.assign("public-route"_ctv);
  prefix.machineUUID = machine.uuid;
  prefix.ingressScope = RoutableIngressScope::singleMachine;
  prefix.usage = ExternalSubnetUsage::wormholes;
  prefix.subnet = IPPrefix("2602:fac0:0:12ab:34cd::77", true, 128);
  replicated.distributableExternalSubnets.push_back(prefix);

  brain.brainConfig = replicated;
  brain.loadBrainConfigIf();

  bool sawResetSwitchboard = false;
  bool sawHostedIngressPrefixes = false;
  bool sawRuntimeEnvironment = false;
  forEachMessageInBuffer(machine.neuron.wBuffer, [&](Message *queued) {
    if (NeuronTopic(queued->topic) == NeuronTopic::resetSwitchboardState && queued->isEcho())
    {
      sawResetSwitchboard = true;
    }
    else if (NeuronTopic(queued->topic) == NeuronTopic::configureSwitchboardHostedIngressPrefixes)
    {
      String payload = {};
      uint8_t *args = queued->args;
      Message::extractToStringView(args, payload);
      Vector<IPPrefix> prefixes = {};
      if (BitseryEngine::deserializeSafe(payload, prefixes) && prefixes.size() == 1 && prefixes[0].cidr == 128)
      {
        sawHostedIngressPrefixes = true;
      }
    }
    else if (NeuronTopic(queued->topic) == NeuronTopic::configureRuntimeEnvironment)
    {
      sawRuntimeEnvironment = true;
    }
  });

  suite.expect(sawResetSwitchboard, "replicate_brain_config_replays_switchboard_reset");
  suite.expect(sawHostedIngressPrefixes, "replicate_brain_config_replays_hosted_ingress_prefixes");
  suite.expect(sawRuntimeEnvironment, "replicate_brain_config_replays_runtime_environment");
}

static void testSwitchboardStateSyncReplaysWhiteholes(TestSuite& suite)
{
  TestBrain brain;
  NoopBrainIaaS iaas;
  brain.iaas = &iaas;

  Machine workerMachine = {};
  workerMachine.uuid = uint128_t(0x6666);
  workerMachine.fragment = 0x000203u;
  workerMachine.slug.assign("worker-machine"_ctv);
  workerMachine.neuron.isFixedFile = true;
  workerMachine.neuron.fslot = 8;
  workerMachine.neuron.connected = true;
  workerMachine.neuron.pendingSend = true;
  brain.machines.insert(&workerMachine);
  brain.machinesByUUID.insert_or_assign(workerMachine.uuid, &workerMachine);

  ContainerView container = {};
  container.machine = &workerMachine;
  container.fragment = 9;
  container.state = ContainerState::healthy;

  Whitehole whitehole = {};
  whitehole.transport = ExternalAddressTransport::tcp;
  whitehole.family = ExternalAddressFamily::ipv4;
  whitehole.source = ExternalAddressSource::registeredRoutablePrefix;
  whitehole.hasAddress = true;
  whitehole.address = IPAddress("203.0.113.77", false);
  whitehole.sourcePort = 55'123;
  whitehole.bindingNonce = 99;
  container.whiteholes.push_back(whitehole);

  brain.containers.insert_or_assign(uint128_t(0x9001), &container);
  brain.sendNeuronSwitchboardStateSync(&workerMachine);

  bool workerSawOpenWhiteholes = false;
  forEachMessageInBuffer(workerMachine.neuron.wBuffer, [&](Message *queued) {
    if (NeuronTopic(queued->topic) == NeuronTopic::openSwitchboardWhiteholes)
    {
      uint8_t *args = queued->args;
      uint8_t *terminal = queued->terminal();
      uint32_t containerID = 0;
      Message::extractArg<ArgumentNature::fixed>(args, containerID);
      if (containerID == container.generateContainerID())
      {
        uint16_t sourcePort = 0;
        IPAddress address = {};
        ExternalAddressTransport transport = ExternalAddressTransport::tcp;
        uint64_t bindingNonce = 0;
        Message::extractArg<ArgumentNature::fixed>(args, sourcePort);
        Message::extractBytes<Alignment::one>(args, address.v6, 16);
        Message::extractArg<ArgumentNature::fixed>(args, address.is6);
        Message::extractArg<ArgumentNature::fixed>(args, transport);
        Message::extractArg<ArgumentNature::fixed>(args, bindingNonce);
        if (args == terminal && sourcePort == whitehole.sourcePort && address.equals(whitehole.address) && transport == whitehole.transport && bindingNonce == whitehole.bindingNonce)
        {
          workerSawOpenWhiteholes = true;
        }
      }
    }
  });

  suite.expect(workerSawOpenWhiteholes, "switchboard_state_sync_replays_whiteholes_to_container_machine");
}

static void testQuicWormholeStateRefreshReplaysToNeuronsFollowersAndContainers(TestSuite& suite)
{
  TestBrain brain;
  NoopBrainIaaS iaas;
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.nBrains = 2;

  BrainView follower = {};
  follower.isFixedFile = true;
  follower.fslot = 17;
  follower.connected = true;
  brain.brains.insert(&follower);

  Machine machine = {};
  machine.uuid = uint128_t(0x7777);
  machine.fragment = 0x000777u;
  machine.slug.assign("quic-host"_ctv);
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 9;
  machine.neuron.connected = true;
  machine.neuron.pendingSend = true;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

  ContainerView container = {};
  container.uuid = uint128_t(0xABCD1234);
  container.machine = &machine;
  container.fragment = 5;
  container.state = ContainerState::healthy;
  brain.containers.insert_or_assign(container.uuid, &container);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(52'000, 1005);

  Wormhole wormhole = {};
  wormhole.externalAddress = IPAddress("203.0.113.90", false);
  wormhole.externalPort = 443;
  wormhole.containerPort = 8443;
  wormhole.layer4 = IPPROTO_UDP;
  wormhole.isQuic = true;
  wormhole.source = ExternalAddressSource::hostPublicAddress;
  wormhole.quicCidKeyState.rotationHours = 36;
  deployment.plan.wormholes.push_back(wormhole);
  deployment.containers.insert(&container);

  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentPlans.insert_or_assign(deployment.plan.config.deploymentID(), deployment.plan);

  const int64_t nowMs = 1'700'000'001'234LL;
  bool changed = brain.refreshDeploymentWormholeQuicCidState(&deployment, nowMs, false);

  suite.expect(changed, "quic_wormhole_refresh_changes_deployment_plan");
  suite.expect(deployment.plan.wormholes.size() == 1, "quic_wormhole_refresh_keeps_single_wormhole");
  suite.expect(deployment.plan.wormholes[0].hasQuicCidKeyState, "quic_wormhole_refresh_mints_key_state");
  suite.expect(deployment.plan.wormholes[0].quicCidKeyState.rotationHours == 36, "quic_wormhole_refresh_preserves_rotation_hours");
  suite.expect(deployment.plan.wormholes[0].quicCidKeyState.activeKeyIndex == 0, "quic_wormhole_refresh_sets_initial_active_key_index");
  suite.expect(deployment.plan.wormholes[0].quicCidKeyState.rotatedAtMs == nowMs, "quic_wormhole_refresh_sets_rotated_at");
  suite.expect(deployment.plan.wormholes[0].quicCidKeyState.keyMaterialByIndex[0] != uint128_t(0), "quic_wormhole_refresh_sets_key_slot_0");
  suite.expect(deployment.plan.wormholes[0].quicCidKeyState.keyMaterialByIndex[1] != uint128_t(0), "quic_wormhole_refresh_sets_key_slot_1");
  suite.expect(wormholeQuicCidKeyMaterialPhase(deployment.plan.wormholes[0].quicCidKeyState.keyMaterialByIndex[0]) == 0, "quic_wormhole_refresh_sets_key_slot_0_phase0");
  suite.expect(wormholeQuicCidKeyMaterialPhase(deployment.plan.wormholes[0].quicCidKeyState.keyMaterialByIndex[1]) == 1, "quic_wormhole_refresh_sets_key_slot_1_phase1");
  suite.expect(container.wormholes.size() == 1, "quic_wormhole_refresh_updates_live_container_wormholes");
  suite.expect(equalSerializedObjects(container.wormholes[0], deployment.plan.wormholes[0]), "quic_wormhole_refresh_live_container_matches_plan");
  suite.expect(brain.persistCalls == 1, "quic_wormhole_refresh_persists_runtime_state");

  bool sawNeuronOpen = false;
  bool sawContainerRefresh = false;
  forEachMessageInBuffer(machine.neuron.wBuffer, [&](Message *queued) {
    if (NeuronTopic(queued->topic) == NeuronTopic::openSwitchboardWormholes)
    {
      uint8_t *args = queued->args;
      uint32_t containerID = 0;
      Message::extractArg<ArgumentNature::fixed>(args, containerID);

      String serialized = {};
      Message::extractToStringView(args, serialized);

      Vector<Wormhole> decoded = {};
      if (containerID == container.generateContainerID() && BitseryEngine::deserializeSafe(serialized, decoded) && decoded.size() == 1 && equalSerializedObjects(decoded[0], deployment.plan.wormholes[0]))
      {
        sawNeuronOpen = true;
      }
    }
    else if (NeuronTopic(queued->topic) == NeuronTopic::refreshContainerWormholes)
    {
      uint8_t *args = queued->args;
      uint128_t containerUUID = 0;
      Message::extractArg<ArgumentNature::fixed>(args, containerUUID);

      String serialized = {};
      Message::extractToStringView(args, serialized);

      Vector<Wormhole> decoded = {};
      if (containerUUID == container.uuid && BitseryEngine::deserializeSafe(serialized, decoded) && decoded.size() == 1 && equalSerializedObjects(decoded[0], deployment.plan.wormholes[0]))
      {
        sawContainerRefresh = true;
      }
    }
  });

  bool sawFollowerReplication = false;
  forEachMessageInBuffer(follower.wBuffer, [&](Message *queued) {
    if (BrainTopic(queued->topic) != BrainTopic::replicateDeployment)
    {
      return;
    }

    uint8_t *args = queued->args;
    String serializedPlan = {};
    Message::extractToStringView(args, serializedPlan);

    DeploymentPlan decodedPlan = {};
    if (BitseryEngine::deserializeSafe(serializedPlan, decodedPlan) == false)
    {
      return;
    }

    String containerBlob = {};
    Message::extractToStringView(args, containerBlob);
    if (decodedPlan.wormholes.size() == 1 && equalSerializedObjects(decodedPlan.wormholes[0], deployment.plan.wormholes[0]) && containerBlob.size() == 0)
    {
      sawFollowerReplication = true;
    }
  });

  suite.expect(sawNeuronOpen, "quic_wormhole_refresh_replays_open_switchboard_wormholes");
  suite.expect(sawContainerRefresh, "quic_wormhole_refresh_replays_container_wormhole_refresh");
  suite.expect(sawFollowerReplication, "quic_wormhole_refresh_replicates_serialized_deployment_to_followers");
}

static void testQuicWormholeRotationAndNoopPaths(TestSuite& suite)
{
  TestBrain brain = {};
  brain.iaas = new NoopBrainIaaS();

  const int64_t initialNowMs = 1'700'000'005'000LL;
  suite.expect(brain.refreshDeploymentWormholeQuicCidState(nullptr, initialNowMs, true) == false, "quic_wormhole_refresh_null_deployment_is_noop");

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(52'001, 1006);

  Wormhole nonQuic = {};
  nonQuic.externalAddress = IPAddress("203.0.113.91", false);
  nonQuic.externalPort = 80;
  nonQuic.containerPort = 8080;
  nonQuic.layer4 = IPPROTO_TCP;
  nonQuic.source = ExternalAddressSource::hostPublicAddress;
  deployment.plan.wormholes.push_back(nonQuic);

  suite.expect(brain.refreshDeploymentWormholeQuicCidState(&deployment, initialNowMs, true) == false, "quic_wormhole_refresh_non_quic_wormhole_is_noop");
  suite.expect(brain.persistCalls == 0, "quic_wormhole_refresh_non_quic_wormhole_does_not_persist");

  deployment.plan.wormholes.clear();
  Wormhole quic = {};
  quic.externalAddress = IPAddress("203.0.113.92", false);
  quic.externalPort = 443;
  quic.containerPort = 8443;
  quic.layer4 = IPPROTO_UDP;
  quic.isQuic = true;
  quic.source = ExternalAddressSource::hostPublicAddress;
  quic.hasQuicCidKeyState = true;
  quic.quicCidKeyState.rotationHours = 0;
  quic.quicCidKeyState.activeKeyIndex = 3;
  quic.quicCidKeyState.rotatedAtMs = 0;
  quic.quicCidKeyState.keyMaterialByIndex[0] = uint128_t(0x1111222233334444ULL);
  quic.quicCidKeyState.keyMaterialByIndex[1] = uint128_t(0x5555666677778888ULL);
  deployment.plan.wormholes.push_back(quic);

  suite.expect(brain.refreshDeploymentWormholeQuicCidState(&deployment, initialNowMs, false), "quic_wormhole_refresh_normalizes_existing_key_state");
  suite.expect(deployment.plan.wormholes[0].quicCidKeyState.rotationHours == 24, "quic_wormhole_refresh_defaults_rotation_hours");
  suite.expect(deployment.plan.wormholes[0].quicCidKeyState.activeKeyIndex == 1, "quic_wormhole_refresh_clamps_active_key_index");
  suite.expect(deployment.plan.wormholes[0].quicCidKeyState.rotatedAtMs == initialNowMs, "quic_wormhole_refresh_sets_missing_rotated_at");
  suite.expect(wormholeQuicCidKeyMaterialPhase(deployment.plan.wormholes[0].quicCidKeyState.keyMaterialByIndex[0]) == 0, "quic_wormhole_refresh_normalizes_key_slot_0_phase0");
  suite.expect(wormholeQuicCidKeyMaterialPhase(deployment.plan.wormholes[0].quicCidKeyState.keyMaterialByIndex[1]) == 1, "quic_wormhole_refresh_normalizes_key_slot_1_phase1");
  suite.expect(brain.persistCalls == 1, "quic_wormhole_refresh_persists_normalized_state");

  uint128_t slot0BeforeRotation = deployment.plan.wormholes[0].quicCidKeyState.keyMaterialByIndex[0];
  suite.expect(brain.refreshDeploymentWormholeQuicCidState(&deployment, initialNowMs + 1000, true) == false, "quic_wormhole_refresh_skips_rotation_before_interval");
  suite.expect(deployment.plan.wormholes[0].quicCidKeyState.activeKeyIndex == 1, "quic_wormhole_refresh_preserves_active_key_index_before_interval");
  suite.expect(deployment.plan.wormholes[0].quicCidKeyState.keyMaterialByIndex[0] == slot0BeforeRotation, "quic_wormhole_refresh_preserves_inactive_key_before_interval");
  suite.expect(brain.persistCalls == 1, "quic_wormhole_refresh_noop_before_interval_does_not_persist");

  deployment.plan.wormholes[0].quicCidKeyState.rotationHours = 1;
  deployment.plan.wormholes[0].quicCidKeyState.rotatedAtMs = initialNowMs - (2 * 60 * 60 * 1000);
  suite.expect(brain.refreshDeploymentWormholeQuicCidState(&deployment, initialNowMs + (2 * 60 * 60 * 1000), true), "quic_wormhole_refresh_rotates_after_interval");
  suite.expect(deployment.plan.wormholes[0].quicCidKeyState.activeKeyIndex == 0, "quic_wormhole_refresh_switches_to_inactive_key_after_rotation");
  suite.expect(deployment.plan.wormholes[0].quicCidKeyState.rotatedAtMs == initialNowMs + (2 * 60 * 60 * 1000), "quic_wormhole_refresh_updates_rotated_at_after_rotation");
  suite.expect(deployment.plan.wormholes[0].quicCidKeyState.keyMaterialByIndex[0] != slot0BeforeRotation, "quic_wormhole_refresh_rekeys_rotated_slot");
  suite.expect(wormholeQuicCidKeyMaterialPhase(deployment.plan.wormholes[0].quicCidKeyState.keyMaterialByIndex[0]) == 0, "quic_wormhole_refresh_rotated_slot_keeps_phase0");
  suite.expect(brain.persistCalls == 2, "quic_wormhole_refresh_persists_rotated_state");
}

static void testWormholeAddressLeasesReserveAndConflict(TestSuite& suite)
{
  TestBrain brain;

  DeploymentPlan plan = {};
  plan.config.applicationID = 61'100;
  plan.config.versionID = 1;
  Wormhole wormhole = {};
  wormhole.name = "api"_ctv;
  wormhole.externalAddress = IPAddress("203.0.113.200", false);
  wormhole.externalPort = 443;
  wormhole.containerPort = 8443;
  wormhole.layer4 = IPPROTO_TCP;
  plan.wormholes.push_back(wormhole);

  String failure = {};
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(plan, failure, false), "wormhole_address_lease_dry_run_accepts_unowned_address");
  suite.expect(brain.routableResourceLeaseRuntimeState.empty(), "wormhole_address_lease_dry_run_does_not_mutate");
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(plan, failure, true), "wormhole_address_lease_commit_accepts_unowned_address");
  suite.expect(brain.routableResourceLeaseRuntimeState.size() == 1, "wormhole_address_lease_commit_records_one_lease");
  suite.expect(brain.masterAuthorityRuntimeState.routableResourceLeases.size() == 1, "wormhole_address_lease_commit_mirrors_master_runtime_state");
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(plan, failure, true), "wormhole_address_lease_commit_is_idempotent");
  suite.expect(brain.routableResourceLeaseRuntimeState.size() == 1, "wormhole_address_lease_idempotent_keeps_one_lease");

  DeploymentPlan sameAppUpgrade = plan;
  sameAppUpgrade.config.versionID = 2;
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(sameAppUpgrade, failure, false), "wormhole_address_lease_allows_same_lineage_upgrade");

  DeploymentPlan otherApp = plan;
  otherApp.config.applicationID = 61'101;
  otherApp.config.versionID = 1;
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(otherApp, failure, false) == false, "wormhole_address_lease_rejects_other_application_conflict");
  suite.expect(failure.equal("wormhole routable address is already owned"_ctv), "wormhole_address_lease_conflict_failure_text");
}

static void testRegisteredPrefixWormholeAddressAllocation(TestSuite& suite)
{
  TestBrain brain = {};
  DistributableExternalSubnet prefix = {};
  prefix.uuid = uint128_t(0xCC3301);
  prefix.usage = ExternalSubnetUsage::wormholes;
  prefix.subnet = IPPrefix("198.51.100.0", false, 30);
  brain.brainConfig.distributableExternalSubnets.push_back(prefix);

  auto makePlan = [&](uint16_t applicationID) {
    DeploymentPlan plan = {};
    plan.config.applicationID = applicationID;
    plan.config.versionID = 1;
    Wormhole wormhole = {};
    wormhole.name = "api"_ctv;
    wormhole.externalPort = 443;
    wormhole.containerPort = 8443;
    wormhole.layer4 = IPPROTO_TCP;
    wormhole.source = ExternalAddressSource::registeredRoutablePrefix;
    wormhole.routablePrefixUUID = prefix.uuid;
    plan.wormholes.push_back(wormhole);
    return plan;
  };
  String failure = {};
  DeploymentPlan first = makePlan(61'200);
  RoutableResourceLeaseOwner firstOwner = deploymentRoutableResourceLeaseOwner(first);
  suite.expect(resolveWormholeRegisteredRoutablePrefix(brain.brainConfig.distributableExternalSubnets, first.wormholes[0], &failure, &brain.routableResourceLeaseRuntimeState, &firstOwner), "registered_prefix_wormhole_allocates_first_address");
  suite.expect(first.wormholes[0].externalAddress.equals(IPAddress("198.51.100.1", false)), "registered_prefix_wormhole_first_address");
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(first, failure, true), "registered_prefix_wormhole_commits_first_address");

  DeploymentPlan second = makePlan(61'201);
  RoutableResourceLeaseOwner secondOwner = deploymentRoutableResourceLeaseOwner(second);
  suite.expect(resolveWormholeRegisteredRoutablePrefix(brain.brainConfig.distributableExternalSubnets, second.wormholes[0], &failure, &brain.routableResourceLeaseRuntimeState, &secondOwner), "registered_prefix_wormhole_skips_owned_address");
  suite.expect(second.wormholes[0].externalAddress.equals(IPAddress("198.51.100.2", false)), "registered_prefix_wormhole_second_address");
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(second, failure, false), "registered_prefix_wormhole_second_address_reserves");

  DeploymentPlan explicitConflict = makePlan(61'202);
  explicitConflict.wormholes[0].externalAddress = first.wormholes[0].externalAddress;
  RoutableResourceLeaseOwner conflictOwner = deploymentRoutableResourceLeaseOwner(explicitConflict);
  suite.expect(resolveWormholeRegisteredRoutablePrefix(brain.brainConfig.distributableExternalSubnets, explicitConflict.wormholes[0], &failure, &brain.routableResourceLeaseRuntimeState, &conflictOwner), "registered_prefix_wormhole_accepts_explicit_contained_conflict_before_lease_check");
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(explicitConflict, failure, false) == false, "registered_prefix_wormhole_rejects_explicit_owned_address");
}

static void testWormholeDNSLeasesAndCredentialValidation(TestSuite& suite)
{
  auto addPrefixAndCredential = [](TestBrain& brain, uint16_t applicationID, RoutableIngressScope scope = RoutableIngressScope::switchboardFleet) {
    DistributableExternalSubnet prefix = {};
    prefix.uuid = uint128_t(0xDD4401);
    prefix.usage = ExternalSubnetUsage::wormholes;
    prefix.ingressScope = scope;
    prefix.subnet = IPPrefix("203.0.113.0", false, 24);
    brain.brainConfig.distributableExternalSubnets.push_back(prefix);
    brain.brainConfig.dnsProvider = "cloudflare"_ctv;

    ApplicationApiCredentialSet set = {};
    set.applicationID = applicationID;
    ApiCredential credential = {};
    credential.name = "cf-prod"_ctv;
    credential.provider = "Cloudflare"_ctv;
    credential.material = "secret"_ctv;
    set.credentials.push_back(credential);
    brain.apiCredentialSetsByApp[set.applicationID] = set;
  };

  auto makePlan = [](uint16_t applicationID, uint64_t versionID, const char *address) {
    DeploymentPlan plan = {};
    plan.config.applicationID = applicationID;
    plan.config.versionID = versionID;
    Wormhole wormhole = {};
    wormhole.name = "api"_ctv;
    wormhole.externalAddress = IPAddress(address, false);
    wormhole.externalPort = 443;
    wormhole.containerPort = 8443;
    wormhole.layer4 = IPPROTO_TCP;
    wormhole.source = ExternalAddressSource::registeredRoutablePrefix;
    wormhole.routablePrefixUUID = uint128_t(0xDD4401);
    wormhole.hasDNSConfig = true;
    wormhole.dns.provider = "cloudflare"_ctv;
    wormhole.dns.credentialName = "cf-prod"_ctv;
    wormhole.dns.zone = "Example.COM."_ctv;
    wormhole.dns.name = "Api.Example.COM."_ctv;
    wormhole.dns.ttl = 300;
    plan.wormholes.push_back(wormhole);
    return plan;
  };

  TestBrain brain = {};
  TestDNSProvider dns = {};
  brain.dnsProvider = &dns;
  addPrefixAndCredential(brain, 61'400);
  String failure = {};
  DeploymentPlan plan = makePlan(61'400, 1, "203.0.113.10");
  suite.expect(brain.validateDeploymentWormholeDNSConfig(plan, plan.wormholes[0], failure), "wormhole_dns_validation_accepts_registered_credential");
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(plan, failure, false), "wormhole_dns_lease_dry_run_accepts");
  suite.expect(brain.routableResourceLeaseRuntimeState.empty(), "wormhole_dns_lease_dry_run_does_not_mutate");
  suite.expect(dns.upsertCalls == 0, "wormhole_dns_lease_dry_run_does_not_apply_record");
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(plan, failure, true), "wormhole_dns_lease_commit_accepts");
  suite.expect(brain.routableResourceLeaseRuntimeState.size() == 2, "wormhole_dns_lease_commit_records_address_and_dns");
  suite.expect(dns.upsertCalls == 1, "wormhole_dns_lease_commit_applies_record");
  suite.expect(dns.upserts.size() == 1 && dns.upserts[0].values.size() == 1 && dns.upserts[0].values[0].equal("203.0.113.10"_ctv), "wormhole_dns_lease_commit_targets_claimed_address");
  suite.expect(dns.upserts.size() == 1 && dns.upserts[0].credentialName.equal("cf-prod"_ctv), "wormhole_dns_lease_commit_uses_named_credential");
  suite.expect(dns.upserts.size() == 1 && dns.upserts[0].ttl == 300, "wormhole_dns_lease_commit_preserves_ttl");

  TestBrain clusterCredentialBrain = {};
  TestDNSProvider clusterDNS = {};
  clusterCredentialBrain.dnsProvider = &clusterDNS;
  addPrefixAndCredential(clusterCredentialBrain, 61'407);
  clusterCredentialBrain.brainConfig.dnsCredential.name = "cluster-cf"_ctv;
  clusterCredentialBrain.brainConfig.dnsCredential.provider = "cloudflare"_ctv;
  clusterCredentialBrain.brainConfig.dnsCredential.material = "cluster-secret"_ctv;
  DeploymentPlan clusterCredentialPlan = makePlan(61'407, 1, "203.0.113.42");
  clusterCredentialPlan.wormholes[0].dns.credentialName = "cluster-cf"_ctv;
  suite.expect(clusterCredentialBrain.validateDeploymentWormholeDNSConfig(clusterCredentialPlan, clusterCredentialPlan.wormholes[0], failure), "wormhole_dns_validation_accepts_cluster_credential");
  suite.expect(clusterCredentialBrain.reserveDeploymentWormholeAddressLeases(clusterCredentialPlan, failure, true), "wormhole_dns_lease_commit_uses_cluster_credential");
  suite.expect(clusterDNS.lastCredentialMaterial.equal("cluster-secret"_ctv), "wormhole_dns_provider_receives_cluster_credential");

  ProdigyPersistentMasterAuthorityPackage dnsPackage = {};
  brain.capturePersistentMasterAuthorityPackage(dnsPackage);

  TestDNSProvider followerDNS = {};
  TestBrain followerRestore = {};
  followerRestore.dnsProvider = &followerDNS;
  followerRestore.brainConfig.dnsProvider = "cloudflare"_ctv;
  followerRestore.applyPersistentMasterAuthorityPackage(dnsPackage);
  suite.expect(followerDNS.upsertCalls == 0, "wormhole_dns_restore_follower_does_not_apply_record");

  TestDNSProvider restoreDNS = {};
  TestBrain masterRestore = {};
  masterRestore.weAreMaster = true;
  masterRestore.dnsProvider = &restoreDNS;
  masterRestore.brainConfig.dnsProvider = "cloudflare"_ctv;
  masterRestore.applyPersistentMasterAuthorityPackage(dnsPackage);
  suite.expect(restoreDNS.upsertCalls == 1, "wormhole_dns_restore_master_reconciles_record");
  suite.expect(restoreDNS.upserts.size() == 1 && restoreDNS.upserts[0].values.size() == 1 && restoreDNS.upserts[0].values[0].equal("203.0.113.10"_ctv), "wormhole_dns_restore_master_targets_claimed_address");

  TestDNSProvider replicatedDNS = {};
  TestBrain replicatedMaster = {};
  replicatedMaster.weAreMaster = true;
  replicatedMaster.dnsProvider = &replicatedDNS;
  replicatedMaster.brainConfig.dnsProvider = "cloudflare"_ctv;
  replicatedMaster.apiCredentialSetsByApp = brain.apiCredentialSetsByApp;
  ProdigyMasterAuthorityRuntimeState replicatedState = dnsPackage.runtimeState;
  replicatedState.generation += 100;
  suite.expect(replicatedMaster.applyReplicatedMasterAuthorityRuntimeState(replicatedState, false), "wormhole_dns_replicated_master_state_applies");
  suite.expect(replicatedDNS.upsertCalls == 1, "wormhole_dns_replicated_master_state_reconciles_record");

  bool sawDNSLease = false;
  for (const RoutableResourceLease& lease : brain.routableResourceLeaseRuntimeState)
  {
    if (lease.kind == RoutableResourceLeaseKind::dnsRecord)
    {
      sawDNSLease = true;
      suite.expect(lease.address.equals(IPAddress("203.0.113.10", false)), "wormhole_dns_lease_records_claimed_address");
      suite.expect(lease.dnsType.equal("A"_ctv), "wormhole_dns_lease_infers_ipv4_a_record");
      suite.expect(lease.dnsProvider.equal("cloudflare"_ctv), "wormhole_dns_lease_records_provider");
      suite.expect(lease.dnsCredentialName.equal("cf-prod"_ctv), "wormhole_dns_lease_records_credential");
      suite.expect(lease.dnsTTL == 300, "wormhole_dns_lease_records_ttl");
    }
  }
  suite.expect(sawDNSLease, "wormhole_dns_lease_records_dns_kind");

  addPrefixAndCredential(brain, 61'401);
  DeploymentPlan other = makePlan(61'401, 1, "203.0.113.11");
  other.wormholes[0].dns.provider = "CLOUDFLARE"_ctv;
  other.wormholes[0].dns.zone = "example.com"_ctv;
  other.wormholes[0].dns.name = "api.example.com"_ctv;
  suite.expect(brain.validateDeploymentWormholeDNSConfig(other, other.wormholes[0], failure), "wormhole_dns_validation_casefolds_provider_zone_name");
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(other, failure, false) == false, "wormhole_dns_lease_rejects_other_application_record");
  suite.expect(failure.equal("wormhole DNS record is already owned"_ctv), "wormhole_dns_lease_conflict_failure_text");
  suite.expect(dns.upsertCalls == 1, "wormhole_dns_conflict_does_not_apply_record");

  DeploymentPlan missing = makePlan(61'400, 2, "203.0.113.12");
  missing.wormholes[0].dns.credentialName = "missing"_ctv;
  suite.expect(brain.validateDeploymentWormholeDNSConfig(missing, missing.wormholes[0], failure) == false, "wormhole_dns_validation_rejects_missing_credential");
  suite.expect(failure.equal("wormhole DNS credential is not registered"_ctv), "wormhole_dns_validation_missing_credential_text");

  DeploymentPlan wrongProvider = makePlan(61'400, 2, "203.0.113.12");
  wrongProvider.wormholes[0].dns.provider = "route53"_ctv;
  suite.expect(brain.validateDeploymentWormholeDNSConfig(wrongProvider, wrongProvider.wormholes[0], failure) == false, "wormhole_dns_validation_rejects_provider_mismatch");
  suite.expect(failure.equal("wormhole DNS provider is not enabled for this cluster"_ctv), "wormhole_dns_validation_provider_mismatch_text");

  DeploymentPlan wrongFamily = makePlan(61'400, 2, "203.0.113.12");
  wrongFamily.wormholes[0].dns.type = "AAAA"_ctv;
  suite.expect(brain.validateDeploymentWormholeDNSConfig(wrongFamily, wrongFamily.wormholes[0], failure) == false, "wormhole_dns_validation_rejects_family_mismatch");
  suite.expect(failure.equal("wormhole DNS record type must match the claimed address family"_ctv), "wormhole_dns_validation_family_mismatch_text");

  TestBrain singleMachineBrain = {};
  addPrefixAndCredential(singleMachineBrain, 61'402, RoutableIngressScope::singleMachine);
  DeploymentPlan singleMachine = makePlan(61'402, 1, "203.0.113.13");
  suite.expect(singleMachineBrain.validateDeploymentWormholeDNSConfig(singleMachine, singleMachine.wormholes[0], failure) == false, "wormhole_dns_validation_rejects_single_machine_without_opt_in");
  suite.expect(failure.equal("wormhole DNS on singleMachine prefixes requires allowSingleMachine=true"_ctv), "wormhole_dns_validation_single_machine_failure_text");
  singleMachine.wormholes[0].dns.allowSingleMachine = true;
  suite.expect(singleMachineBrain.validateDeploymentWormholeDNSConfig(singleMachine, singleMachine.wormholes[0], failure), "wormhole_dns_validation_accepts_single_machine_opt_in");

  TestBrain duplicateBrain = {};
  DeploymentPlan duplicate = makePlan(61'403, 1, "203.0.113.20");
  Wormhole duplicateWormhole = duplicate.wormholes[0];
  duplicateWormhole.name = "api2"_ctv;
  duplicateWormhole.externalAddress = IPAddress("203.0.113.21", false);
  duplicate.wormholes.push_back(duplicateWormhole);
  suite.expect(duplicateBrain.reserveDeploymentWormholeAddressLeases(duplicate, failure, false) == false, "wormhole_dns_lease_rejects_duplicate_record_in_plan");
  suite.expect(failure.equal("wormhole DNS record is already declared"_ctv), "wormhole_dns_lease_duplicate_record_failure_text");

  TestBrain transferBrain = {};
  TestDNSProvider transferDNS = {};
  transferBrain.dnsProvider = &transferDNS;
  addPrefixAndCredential(transferBrain, 61'404);
  DeploymentPlan previous = makePlan(61'404, 1, "203.0.113.30");
  DeploymentPlan current = makePlan(61'404, 2, "203.0.113.30");
  suite.expect(transferBrain.reserveDeploymentWormholeAddressLeases(previous, failure, true), "wormhole_dns_transfer_fixture_claims_previous");
  ApplicationDeployment currentDeployment = {};
  currentDeployment.plan = current;
  transferBrain.deploymentsByApp.insert_or_assign(current.config.applicationID, &currentDeployment);
  suite.expect(transferBrain.releaseRoutableResourceLeasesForDeployment(previous.config.deploymentID()) == 2, "wormhole_dns_transfer_rewrites_address_and_dns_owner");
  suite.expect(transferBrain.routableResourceLeaseRuntimeState.size() == 2, "wormhole_dns_transfer_keeps_two_leases");
  suite.expect(transferDNS.removeCalls == 0, "wormhole_dns_transfer_keeps_record_applied");
  for (const RoutableResourceLease& lease : transferBrain.routableResourceLeaseRuntimeState)
  {
    suite.expect(lease.owner.deploymentID == current.config.deploymentID(), "wormhole_dns_transfer_targets_current_deployment");
  }

  TestBrain failBrain = {};
  TestDNSProvider failDNS = {};
  failDNS.failUpsert = true;
  failBrain.dnsProvider = &failDNS;
  addPrefixAndCredential(failBrain, 61'405);
  DeploymentPlan failPlan = makePlan(61'405, 1, "203.0.113.40");
  suite.expect(failBrain.reserveDeploymentWormholeAddressLeases(failPlan, failure, true) == false, "wormhole_dns_apply_failure_rejects_commit");
  suite.expect(failure.equal("injected DNS upsert failure"_ctv), "wormhole_dns_apply_failure_surfaces_provider_error");
  suite.expect(failBrain.routableResourceLeaseRuntimeState.empty(), "wormhole_dns_apply_failure_does_not_commit_leases");

  TestBrain deleteBrain = {};
  TestDNSProvider deleteDNS = {};
  deleteBrain.dnsProvider = &deleteDNS;
  addPrefixAndCredential(deleteBrain, 61'406);
  DeploymentPlan deletePlan = makePlan(61'406, 1, "203.0.113.41");
  suite.expect(deleteBrain.reserveDeploymentWormholeAddressLeases(deletePlan, failure, true), "wormhole_dns_delete_failure_fixture_claims_address");
  deleteDNS.failRemove = true;
  suite.expect(deleteBrain.releaseRoutableResourceLeasesForDeployment(deletePlan.config.deploymentID()) == 0, "wormhole_dns_delete_failure_keeps_lease_owner");
  suite.expect(deleteBrain.routableResourceLeaseRuntimeState.size() == 2, "wormhole_dns_delete_failure_keeps_leases");
  deleteDNS.failRemove = false;
  suite.expect(deleteBrain.releaseRoutableResourceLeasesForDeployment(deletePlan.config.deploymentID()) == 2, "wormhole_dns_delete_success_releases_leases");
  suite.expect(deleteDNS.removeCalls == 2, "wormhole_dns_delete_retries_after_failure");
}

static void testWormholeAddressLeaseReleaseAndUpgradeTransfer(TestSuite& suite)
{
  TestBrain brain;

  auto makePlan = [](uint16_t applicationID, uint64_t versionID) {
    DeploymentPlan plan = {};
    plan.config.applicationID = applicationID;
    plan.config.versionID = versionID;
    Wormhole wormhole = {};
    wormhole.name = "api"_ctv;
    wormhole.externalAddress = IPAddress("203.0.113.210", false);
    wormhole.externalPort = 443;
    wormhole.containerPort = 8443;
    wormhole.layer4 = IPPROTO_TCP;
    plan.wormholes.push_back(wormhole);
    return plan;
  };

  String failure = {};
  DeploymentPlan released = makePlan(61'300, 1);
  DeploymentPlan otherApp = makePlan(61'301, 1);
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(released, failure, true), "wormhole_address_lease_release_fixture_claims_address");
  suite.expect(brain.releaseRoutableResourceLeasesForDeployment(released.config.deploymentID()) == 1, "wormhole_address_lease_release_removes_owner");
  suite.expect(brain.routableResourceLeaseRuntimeState.empty(), "wormhole_address_lease_release_clears_runtime_state");
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(otherApp, failure, false), "wormhole_address_lease_release_frees_address_for_other_app");

  brain.routableResourceLeaseRuntimeState.clear();
  DeploymentPlan previous = makePlan(61'302, 1);
  DeploymentPlan current = makePlan(61'302, 2);
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(previous, failure, true), "wormhole_address_lease_transfer_fixture_claims_previous");
  ApplicationDeployment currentDeployment = {};
  currentDeployment.plan = current;
  brain.deploymentsByApp.insert_or_assign(current.config.applicationID, &currentDeployment);
  suite.expect(brain.releaseRoutableResourceLeasesForDeployment(previous.config.deploymentID()) == 1, "wormhole_address_lease_transfer_rewrites_owner");
  suite.expect(brain.routableResourceLeaseRuntimeState.size() == 1, "wormhole_address_lease_transfer_keeps_one_lease");
  suite.expect(brain.routableResourceLeaseRuntimeState[0].owner.deploymentID == current.config.deploymentID(), "wormhole_address_lease_transfer_targets_current_deployment");
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(otherApp, failure, false) == false, "wormhole_address_lease_transfer_keeps_other_app_blocked");

  brain.deploymentsByApp.clear();
  brain.routableResourceLeaseRuntimeState.clear();
  DeploymentPlan previousWhitehole = makePlan(61'303, 1);
  DeploymentPlan currentWhitehole = makePlan(61'303, 2);
  RoutableResourceLease whiteholeLease = {};
  whiteholeLease.kind = RoutableResourceLeaseKind::whiteholeAddressPort;
  whiteholeLease.owner = deploymentRoutableResourceLeaseOwner(previousWhitehole);
  whiteholeLease.address = IPAddress("198.18.22.44", false);
  whiteholeLease.sourcePort = 49'152;
  brain.routableResourceLeaseRuntimeState.push_back(whiteholeLease);
  ApplicationDeployment currentWhiteholeDeployment = {};
  currentWhiteholeDeployment.plan = currentWhitehole;
  currentWhiteholeDeployment.nShardGroups = 1;
  ContainerView currentContainer = {};
  currentContainer.state = ContainerState::healthy;
  Whitehole currentLease = {};
  currentLease.hasAddress = true;
  currentLease.address = whiteholeLease.address;
  currentLease.sourcePort = whiteholeLease.sourcePort;
  currentWhiteholeDeployment.containersByShardGroup.insert(0, &currentContainer);
  currentContainer.whiteholes.push_back(currentLease);
  brain.deploymentsByApp.insert_or_assign(currentWhitehole.config.applicationID, &currentWhiteholeDeployment);
  suite.expect(brain.releaseRoutableResourceLeasesForDeployment(previousWhitehole.config.deploymentID()) == 1, "whitehole_ip_port_lease_transfer_rewrites_owner");
  suite.expect(brain.routableResourceLeaseRuntimeState.size() == 1, "whitehole_ip_port_lease_transfer_keeps_one_lease");
  suite.expect(brain.routableResourceLeaseRuntimeState[0].owner.deploymentID == currentWhitehole.config.deploymentID(), "whitehole_ip_port_lease_transfer_targets_current_deployment");
}

static void testRegisteredRoutablePrefixRefreshReplaysToNeuronsFollowersAndContainers(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas;
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.nBrains = 2;

  BrainView follower = {};
  follower.isFixedFile = true;
  follower.fslot = 18;
  follower.connected = true;
  brain.brains.insert(&follower);

  Machine machine = {};
  machine.uuid = uint128_t(0x8888);
  machine.fragment = 0x000888u;
  machine.slug.assign("registered-route-host"_ctv);
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 11;
  machine.neuron.connected = true;
  machine.neuron.pendingSend = true;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

  ContainerView container = {};
  container.uuid = uint128_t(0xABCD2234);
  container.machine = &machine;
  container.fragment = 6;
  container.state = ContainerState::healthy;
  brain.containers.insert_or_assign(container.uuid, &container);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(52'003, 1008);

  Wormhole wormhole = {};
  wormhole.externalPort = 443;
  wormhole.containerPort = 8443;
  wormhole.layer4 = IPPROTO_UDP;
  wormhole.isQuic = true;
  wormhole.source = ExternalAddressSource::registeredRoutablePrefix;
  wormhole.routablePrefixUUID = uint128_t(0x1234);
  deployment.plan.wormholes.push_back(wormhole);
  deployment.containers.insert(&container);

  DistributableExternalSubnet registered = {};
  registered.uuid = wormhole.routablePrefixUUID;
  registered.name = "nametag-test-address"_ctv;
  registered.machineUUID = machine.uuid;
  registered.ingressScope = RoutableIngressScope::singleMachine;
  registered.usage = ExternalSubnetUsage::wormholes;
  registered.subnet = IPPrefix("203.0.113.55", false, 32);
  registered.deliverySubnet = IPPrefix("10.0.0.55", false, 32);
  brain.brainConfig.distributableExternalSubnets.push_back(registered);

  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentPlans.insert_or_assign(deployment.plan.config.deploymentID(), deployment.plan);

  bool changed = brain.refreshDeploymentRegisteredRoutablePrefixWormholes(&deployment);

  suite.expect(changed, "registered_routable_refresh_changes_deployment_plan");
  suite.expect(deployment.plan.wormholes.size() == 1, "registered_routable_refresh_keeps_single_wormhole");
  suite.expect(deployment.plan.wormholes[0].externalAddress.equals(registered.subnet.network), "registered_routable_refresh_updates_deployment_external_address");
  suite.expect(deployment.plan.wormholes[0].deliveryAddress.equals(registered.deliverySubnet.network), "registered_routable_refresh_updates_deployment_delivery_address");
  suite.expect(container.wormholes.size() == 1, "registered_routable_refresh_updates_live_container_wormholes");
  suite.expect(container.wormholes[0].externalAddress.equals(registered.subnet.network), "registered_routable_refresh_live_container_matches_resolved_address");
  suite.expect(container.wormholes[0].deliveryAddress.equals(registered.deliverySubnet.network), "registered_routable_refresh_live_container_matches_delivery_address");
  suite.expect(brain.persistCalls == 1, "registered_routable_refresh_persists_runtime_state");

  bool sawNeuronOpen = false;
  bool sawContainerRefresh = false;
  forEachMessageInBuffer(machine.neuron.wBuffer, [&](Message *queued) {
    if (NeuronTopic(queued->topic) == NeuronTopic::openSwitchboardWormholes)
    {
      uint8_t *args = queued->args;
      uint32_t containerID = 0;
      Message::extractArg<ArgumentNature::fixed>(args, containerID);

      String serialized = {};
      Message::extractToStringView(args, serialized);

      Vector<Wormhole> decoded = {};
      if (containerID == container.generateContainerID() && BitseryEngine::deserializeSafe(serialized, decoded) && decoded.size() == 1 && equalSerializedObjects(decoded[0], deployment.plan.wormholes[0]))
      {
        sawNeuronOpen = true;
      }
    }
    else if (NeuronTopic(queued->topic) == NeuronTopic::refreshContainerWormholes)
    {
      uint8_t *args = queued->args;
      uint128_t containerUUID = 0;
      Message::extractArg<ArgumentNature::fixed>(args, containerUUID);

      String serialized = {};
      Message::extractToStringView(args, serialized);

      Vector<Wormhole> decoded = {};
      if (containerUUID == container.uuid && BitseryEngine::deserializeSafe(serialized, decoded) && decoded.size() == 1 && equalSerializedObjects(decoded[0], deployment.plan.wormholes[0]))
      {
        sawContainerRefresh = true;
      }
    }
  });

  bool sawFollowerReplication = false;
  forEachMessageInBuffer(follower.wBuffer, [&](Message *queued) {
    if (BrainTopic(queued->topic) != BrainTopic::replicateDeployment)
    {
      return;
    }

    uint8_t *args = queued->args;
    String serializedPlan = {};
    Message::extractToStringView(args, serializedPlan);

    DeploymentPlan decodedPlan = {};
    if (BitseryEngine::deserializeSafe(serializedPlan, decodedPlan) == false)
    {
      return;
    }

    String containerBlob = {};
    Message::extractToStringView(args, containerBlob);
    if (decodedPlan.wormholes.size() == 1 && equalSerializedObjects(decodedPlan.wormholes[0], deployment.plan.wormholes[0]) && containerBlob.size() == 0)
    {
      sawFollowerReplication = true;
    }
  });

  suite.expect(sawNeuronOpen, "registered_routable_refresh_replays_open_switchboard_wormholes");
  suite.expect(sawContainerRefresh, "registered_routable_refresh_replays_container_wormhole_refresh");
  suite.expect(sawFollowerReplication, "registered_routable_refresh_replicates_serialized_deployment_to_followers");
  suite.expect(brain.refreshDeploymentRegisteredRoutablePrefixWormholes(&deployment) == false, "registered_routable_refresh_noop_when_address_already_current");
}

static void testRegisteredRoutablePrefixWormholesRefreshHostedIngressBeforeOpen(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas;
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;

  Machine host = {};
  host.uuid = uint128_t(0x8899);
  host.fragment = 0x000889u;
  host.slug.assign("registered-route-host"_ctv);
  host.neuron.isFixedFile = true;
  host.neuron.fslot = 12;
  host.neuron.connected = true;
  host.neuron.pendingSend = true;
  brain.machines.insert(&host);
  brain.machinesByUUID.insert_or_assign(host.uuid, &host);

  Machine remote = {};
  remote.uuid = uint128_t(0x9900);
  remote.fragment = 0x000990u;
  remote.slug.assign("registered-route-remote"_ctv);
  remote.neuron.isFixedFile = true;
  remote.neuron.fslot = 13;
  remote.neuron.connected = true;
  remote.neuron.pendingSend = true;
  brain.machines.insert(&remote);
  brain.machinesByUUID.insert_or_assign(remote.uuid, &remote);

  DistributableExternalSubnet registered = {};
  registered.uuid = uint128_t(0x7788);
  registered.name = "wormhole-hosted-prefix"_ctv;
  registered.machineUUID = host.uuid;
  registered.ingressScope = RoutableIngressScope::singleMachine;
  registered.usage = ExternalSubnetUsage::wormholes;
  registered.subnet = IPPrefix("2001:db8:100::99", true, 128);
  registered.deliverySubnet = IPPrefix("2001:db8:200::99", true, 128);
  brain.brainConfig.distributableExternalSubnets.push_back(registered);

  ContainerView container = {};
  container.uuid = uint128_t(0xABCD3234);
  container.machine = &host;
  container.fragment = 7;
  container.state = ContainerState::healthy;

  Vector<Wormhole> wormholes = {};
  Wormhole wormhole = {};
  wormhole.externalAddress = IPAddress("2001:db8:100::1", true);
  wormhole.deliveryAddress = registered.deliverySubnet.network;
  wormhole.externalPort = 443;
  wormhole.containerPort = 8443;
  wormhole.layer4 = IPPROTO_UDP;
  wormhole.isQuic = true;
  wormhole.source = ExternalAddressSource::registeredRoutablePrefix;
  wormhole.routablePrefixUUID = registered.uuid;
  wormholes.push_back(wormhole);

  brain.sendNeuronOpenSwitchboardWormholes(&container, wormholes);

  auto assertSwitchboardOpenState = [&](Machine& machine, bool owner) {
    uint32_t hostedIngressIndex = UINT32_MAX;
    uint32_t openIndex = UINT32_MAX;
    uint32_t messageIndex = 0;
    bool hostedPrefixMatchesRoute = false;
    bool openMatchesContainer = false;

    forEachMessageInBuffer(machine.neuron.wBuffer, [&](Message *queued) {
      if (NeuronTopic(queued->topic) == NeuronTopic::configureSwitchboardHostedIngressPrefixes)
      {
        if (hostedIngressIndex == UINT32_MAX)
        {
          hostedIngressIndex = messageIndex;
        }

        String payload = {};
        uint8_t *args = queued->args;
        Message::extractToStringView(args, payload);

        Vector<IPPrefix> prefixes = {};
        if (BitseryEngine::deserializeSafe(payload, prefixes))
        {
          IPPrefix expectedPrefix = {};
          if (makeHostedIngressPrefixForAddress(registered.deliverySubnet.network, expectedPrefix))
          {
            for (const IPPrefix& prefix : prefixes)
            {
              if (prefix.equals(expectedPrefix))
              {
                hostedPrefixMatchesRoute = true;
                break;
              }
            }
          }
        }
      }
      else if (NeuronTopic(queued->topic) == NeuronTopic::openSwitchboardWormholes)
      {
        if (openIndex == UINT32_MAX)
        {
          openIndex = messageIndex;
        }

        uint8_t *args = queued->args;
        uint32_t containerID = 0;
        Message::extractArg<ArgumentNature::fixed>(args, containerID);

        String serialized = {};
        Message::extractToStringView(args, serialized);
        Vector<Wormhole> decoded = {};
        if (containerID == container.generateContainerID() && BitseryEngine::deserializeSafe(serialized, decoded) && decoded.size() == 1 && equalSerializedObjects(decoded[0], wormholes[0]))
        {
          openMatchesContainer = true;
        }
      }

      messageIndex += 1;
    });

    suite.expect(hostedIngressIndex != UINT32_MAX, owner
                                                       ? "registered_routable_wormhole_open_queues_hosted_ingress_prefixes_owner"
                                                       : "registered_routable_wormhole_open_queues_hosted_ingress_prefixes_remote");
    suite.expect(hostedPrefixMatchesRoute, owner
                                               ? "registered_routable_wormhole_open_uses_registered_hosted_prefix_owner"
                                               : "registered_routable_wormhole_open_uses_registered_hosted_prefix_remote");
    suite.expect(openIndex != UINT32_MAX, owner
                                              ? "registered_routable_wormhole_open_queues_open_message_owner"
                                              : "registered_routable_wormhole_open_queues_open_message_remote");
    suite.expect(openMatchesContainer, owner
                                           ? "registered_routable_wormhole_open_preserves_wormhole_payload_owner"
                                           : "registered_routable_wormhole_open_preserves_wormhole_payload_remote");
    suite.expect(hostedIngressIndex < openIndex, owner
                                                     ? "registered_routable_wormhole_open_refreshes_hosted_prefixes_before_open_owner"
                                                     : "registered_routable_wormhole_open_refreshes_hosted_prefixes_before_open_remote");
  };

  assertSwitchboardOpenState(host, true);
  assertSwitchboardOpenState(remote, false);
}

static void testApplyReplicatedDeploymentPlanLiveStateUpdatesTrackedContainers(TestSuite& suite)
{
  TestBrain brain = {};
  brain.iaas = new NoopBrainIaaS();

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(52'002, 1007);

  ContainerView first = {};
  first.uuid = uint128_t(0x6101);
  ContainerView second = {};
  second.uuid = uint128_t(0x6102);
  deployment.containers.insert(&first);
  deployment.containers.insert(&second);

  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

  DeploymentPlan replicated = deployment.plan;
  Wormhole wormhole = {};
  wormhole.externalAddress = IPAddress("203.0.113.93", false);
  wormhole.externalPort = 9443;
  wormhole.containerPort = 9443;
  wormhole.layer4 = IPPROTO_UDP;
  wormhole.isQuic = true;
  wormhole.source = ExternalAddressSource::hostPublicAddress;
  replicated.wormholes.push_back(wormhole);

  Whitehole whitehole = {};
  whitehole.transport = ExternalAddressTransport::tcp;
  whitehole.family = ExternalAddressFamily::ipv6;
  whitehole.sourcePort = 7001;
  whitehole.hasAddress = true;
  whitehole.address = IPAddress("fd00:10::6101", true);
  replicated.whiteholes.push_back(whitehole);

  brain.applyReplicatedDeploymentPlanLiveState(replicated);

  suite.expect(equalSerializedObjects(deployment.plan, replicated), "apply_replicated_deployment_plan_live_state_updates_tracked_plan");
  suite.expect(first.wormholes.size() == 1 && equalSerializedObjects(first.wormholes[0], replicated.wormholes[0]), "apply_replicated_deployment_plan_live_state_updates_first_container_wormholes");
  suite.expect(second.wormholes.size() == 1 && equalSerializedObjects(second.wormholes[0], replicated.wormholes[0]), "apply_replicated_deployment_plan_live_state_updates_second_container_wormholes");
  suite.expect(first.whiteholes.size() == 1 && equalSerializedObjects(first.whiteholes[0], replicated.whiteholes[0]), "apply_replicated_deployment_plan_live_state_updates_first_container_whiteholes");
  suite.expect(second.whiteholes.size() == 1 && equalSerializedObjects(second.whiteholes[0], replicated.whiteholes[0]), "apply_replicated_deployment_plan_live_state_updates_second_container_whiteholes");
}

static void testApplyReplicatedDeploymentPlanCleansTlsResumptionState(TestSuite& suite)
{
  TestBrain brain = {};
  brain.iaas = new NoopBrainIaaS();

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(52'003, 1008);

  Wormhole keep = {};
  keep.name.assign("keep-quic"_ctv);
  keep.externalAddress = IPAddress("203.0.113.101", false);
  keep.externalPort = 9443;
  keep.containerPort = 9443;
  keep.layer4 = IPPROTO_UDP;
  keep.isQuic = true;
  keep.source = ExternalAddressSource::hostPublicAddress;
  keep.hasTlsResumptionConfig = true;
  keep.tlsResumption.alpns.push_back("h3"_ctv);
  keep.tlsResumption.sniNames.push_back("keep.example.test"_ctv);
  Wormhole disabled = keep;
  disabled.name.assign("disabled-quic"_ctv);
  disabled.externalPort = 9444;
  disabled.containerPort = 9444;
  disabled.tlsResumption.sniNames.clear();
  disabled.tlsResumption.sniNames.push_back("disabled.example.test"_ctv);

  Wormhole removed = keep;
  removed.name.assign("removed-quic"_ctv);
  removed.externalPort = 9445;
  removed.containerPort = 9445;
  removed.tlsResumption.sniNames.clear();
  removed.tlsResumption.sniNames.push_back("removed.example.test"_ctv);

  deployment.plan.wormholes.push_back(keep);
  deployment.plan.wormholes.push_back(disabled);
  deployment.plan.wormholes.push_back(removed);

  ContainerView container = {};
  container.uuid = uint128_t(0x6201);
  container.deploymentID = deployment.plan.config.deploymentID();
  container.state = ContainerState::healthy;
  deployment.containers.insert(&container);
  brain.containers.insert_or_assign(container.uuid, &container);
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

  const int64_t nowMs = 1'700'000'202'000;
  suite.expect(brain.ensureTlsResumptionSnapshotForWormhole(deployment.plan, deployment.plan.wormholes[0], nowMs) != nullptr, "resumption_cleanup_seed_keep_snapshot");
  suite.expect(brain.ensureTlsResumptionSnapshotForWormhole(deployment.plan, deployment.plan.wormholes[1], nowMs) != nullptr, "resumption_cleanup_seed_disabled_snapshot");
  suite.expect(brain.ensureTlsResumptionSnapshotForWormhole(deployment.plan, deployment.plan.wormholes[2], nowMs) != nullptr, "resumption_cleanup_seed_removed_snapshot");

  auto seedAck = [&](const String& wormholeName) {
    BrainTlsResumptionWormholeState *state = brain.mutableTlsResumptionStateForWormhole(deployment.plan.config.deploymentID(), wormholeName);
    suite.expect(state != nullptr, "resumption_cleanup_seed_ack_snapshot_exists");
    BrainTlsResumptionAckState ack = {};
    ack.generation = state != nullptr ? state->snapshot.generation : 0;
    ack.success = true;
    if (state != nullptr)
    {
      state->acksByContainer.insert_or_assign(container.uuid, ack);
    }
  };
  seedAck(keep.name);
  seedAck(disabled.name);
  seedAck(removed.name);

  DeploymentPlan replicated = deployment.plan;
  replicated.wormholes.clear();
  replicated.wormholes.push_back(keep);
  Wormhole disabledConfig = disabled;
  disabledConfig.hasTlsResumptionConfig = false;
  replicated.wormholes.push_back(disabledConfig);

  brain.applyReplicatedDeploymentPlanLiveState(replicated);

  suite.expect(equalSerializedObjects(deployment.plan, replicated), "resumption_cleanup_apply_updates_plan");
  suite.expect(brain.tlsResumptionSnapshotForWormhole(replicated.config.deploymentID(), keep.name) != nullptr, "resumption_cleanup_preserves_declared_snapshot");
  suite.expect(brain.tlsResumptionSnapshotForWormhole(replicated.config.deploymentID(), disabled.name) == nullptr, "resumption_cleanup_removes_undeclared_snapshot");
  suite.expect(brain.tlsResumptionSnapshotForWormhole(replicated.config.deploymentID(), removed.name) == nullptr, "resumption_cleanup_removes_missing_snapshot");
  const BrainTlsResumptionWormholeState *keepState = brain.tlsResumptionStateForWormhole(replicated.config.deploymentID(), keep.name);
  suite.expect(keepState != nullptr && keepState->acksByContainer.find(container.uuid) != keepState->acksByContainer.end(), "resumption_cleanup_preserves_declared_ack");
  suite.expect(brain.tlsResumptionStateForWormhole(replicated.config.deploymentID(), disabled.name) == nullptr, "resumption_cleanup_removes_undeclared_ack");
  suite.expect(brain.tlsResumptionStateForWormhole(replicated.config.deploymentID(), removed.name) == nullptr, "resumption_cleanup_removes_missing_ack");
  suite.expect(container.wormholes.size() == 2 && container.wormholes[0].name.equal(keep.name) && container.wormholes[1].name.equal(disabled.name), "resumption_cleanup_updates_container_wormholes");
}

static void testUpdateSelfBundleEchoTransitionsFollowersAndQueuesTransition(TestSuite& suite)
{
  ScopedRing scopedRing = {};

  TestBrain brain = {};
  brain.nBrains = 1;
  brain.weAreMaster = false;
  brain.updateSelfUseStagedBundleOnly = true;
  brain.beginUpdateSelfBundle(2);

  BrainView peerA = {};
  peerA.private4 = 0x0a000011;
  peerA.boottimens = 101;
  peerA.connected = true;
  peerA.isFixedFile = true;
  peerA.fslot = 11;

  BrainView peerB = {};
  peerB.private4 = 0x0a000012;
  peerB.boottimens = 202;
  peerB.connected = true;
  peerB.isFixedFile = true;
  peerB.fslot = 12;

  brain.brains.insert(&peerA);
  brain.brains.insert(&peerB);

  brain.onUpdateSelfBundleEcho(&peerA);
  suite.expect(brain.updateSelfState == Brain::UpdateSelfState::waitingForBundleEchos, "update_self_bundle_echo_waits_for_all_peers");
  suite.expect(brain.updateSelfBundleEchos == 1, "update_self_bundle_echo_counts_first_peer");

  brain.onUpdateSelfBundleEcho(&peerB);

  suite.expect(brain.updateSelfState == Brain::UpdateSelfState::waitingForFollowerReboots, "update_self_bundle_echo_transitions_followers");
  suite.expect(brain.updateSelfFollowerBootNsByPeerKey.size() == 2, "update_self_bundle_echo_captures_follower_boot_ns");
  suite.expect(brain.updateSelfTransitionIssuedPeerKeys.contains(uint128_t(peerA.private4)), "update_self_bundle_echo_marks_transition_sent_peer_a");
  suite.expect(brain.updateSelfTransitionIssuedPeerKeys.contains(uint128_t(peerB.private4)), "update_self_bundle_echo_marks_transition_sent_peer_b");

  uint32_t peerATransitionFrames = 0;
  forEachMessageInBuffer(peerA.wBuffer, [&](Message *frame) {
    if (BrainTopic(frame->topic) == BrainTopic::transitionToNewBundle)
    {
      peerATransitionFrames += 1;
    }
  });

  uint32_t peerBTransitionFrames = 0;
  forEachMessageInBuffer(peerB.wBuffer, [&](Message *frame) {
    if (BrainTopic(frame->topic) == BrainTopic::transitionToNewBundle)
    {
      peerBTransitionFrames += 1;
    }
  });

  suite.expect(peerATransitionFrames == 1, "update_self_bundle_echo_queues_transition_for_peer_a");
  suite.expect(peerBTransitionFrames == 1, "update_self_bundle_echo_queues_transition_for_peer_b");
}

static void testUpdateSelfPeerRegistrationCreditsBootNsChange(TestSuite& suite)
{
  ScopedRing scopedRing = {};

  TestBrain brain = {};
  brain.nBrains = 1;
  brain.weAreMaster = false;
  brain.updateSelfState = Brain::UpdateSelfState::waitingForFollowerReboots;
  brain.updateSelfExpectedEchos = 1;

  BrainView peer = {};
  peer.private4 = 0x0a000021;
  peer.boottimens = 200;
  peer.connected = true;
  peer.isFixedFile = true;
  peer.fslot = 21;
  brain.brains.insert(&peer);
  brain.updateSelfFollowerBootNsByPeerKey.insert_or_assign(uint128_t(peer.private4), 100);

  brain.onUpdateSelfPeerRegistration(&peer);

  suite.expect(brain.updateSelfFollowerRebootedPeerKeys.contains(uint128_t(peer.private4)), "update_self_registration_boot_ns_change_marks_rebooted");
  suite.expect(brain.updateSelfState == Brain::UpdateSelfState::waitingForRelinquishEchos, "update_self_registration_boot_ns_change_starts_relinquish");
  suite.expect(brain.updateSelfPlannedMasterPeerKey == uint128_t(peer.private4), "update_self_registration_boot_ns_change_sets_designated_master");
  suite.expect(brain.updateSelfRelinquishIssuedPeerKeys.contains(uint128_t(peer.private4)), "update_self_registration_boot_ns_change_marks_relinquish_sent");

  uint32_t relinquishFrames = 0;
  uint8_t relinquishStatus = 0;
  uint128_t designatedPeerKey = 0;
  forEachMessageInBuffer(peer.wBuffer, [&](Message *frame) {
    if (BrainTopic(frame->topic) != BrainTopic::relinquishMasterStatus)
    {
      return;
    }

    uint8_t *args = frame->args;
    Message::extractArg<ArgumentNature::fixed>(args, relinquishStatus);
    Message::extractArg<ArgumentNature::fixed>(args, designatedPeerKey);
    relinquishFrames += 1;
  });

  suite.expect(relinquishFrames == 1, "update_self_registration_boot_ns_change_queues_relinquish");
  suite.expect(relinquishStatus == 1, "update_self_registration_boot_ns_change_sets_relinquish_status");
  suite.expect(designatedPeerKey == uint128_t(peer.private4), "update_self_registration_boot_ns_change_preserves_designated_master");
}

static void testUpdateSelfPeerRegistrationCreditsReconnectWithoutBootNsChange(TestSuite& suite)
{
  ScopedRing scopedRing = {};

  TestBrain brain = {};
  brain.nBrains = 1;
  brain.weAreMaster = false;
  brain.updateSelfState = Brain::UpdateSelfState::waitingForFollowerReboots;
  brain.updateSelfExpectedEchos = 1;

  BrainView peer = {};
  peer.private4 = 0x0a000031;
  peer.boottimens = 300;
  peer.connected = true;
  peer.isFixedFile = true;
  peer.fslot = 31;
  brain.brains.insert(&peer);
  brain.updateSelfFollowerBootNsByPeerKey.insert_or_assign(uint128_t(peer.private4), 300);
  brain.updateSelfFollowerReconnectedPeerKeys.insert(uint128_t(peer.private4));

  brain.onUpdateSelfPeerRegistration(&peer);

  suite.expect(brain.updateSelfFollowerRebootedPeerKeys.contains(uint128_t(peer.private4)), "update_self_registration_reconnect_marks_rebooted");
  suite.expect(brain.updateSelfFollowerReconnectedPeerKeys.contains(uint128_t(peer.private4)) == false, "update_self_registration_reconnect_consumes_reconnect_credit");
  suite.expect(brain.updateSelfState == Brain::UpdateSelfState::waitingForRelinquishEchos, "update_self_registration_reconnect_starts_relinquish");
}

static void testMaybeRelinquishMasterSelectsLowestPeerKey(TestSuite& suite)
{
  ScopedRing scopedRing = {};

  TestBrain brain = {};
  brain.nBrains = 1;
  brain.weAreMaster = false;
  brain.updateSelfState = Brain::UpdateSelfState::waitingForFollowerReboots;
  brain.updateSelfExpectedEchos = 2;

  BrainView higherPeer = {};
  higherPeer.private4 = 0x0a000042;
  higherPeer.boottimens = 420;
  higherPeer.connected = true;
  higherPeer.isFixedFile = true;
  higherPeer.fslot = 41;

  BrainView lowerPeer = {};
  lowerPeer.private4 = 0x0a000041;
  lowerPeer.boottimens = 410;
  lowerPeer.connected = true;
  lowerPeer.isFixedFile = true;
  lowerPeer.fslot = 42;

  brain.brains.insert(&higherPeer);
  brain.brains.insert(&lowerPeer);
  brain.updateSelfFollowerRebootedPeerKeys.insert(uint128_t(higherPeer.private4));
  brain.updateSelfFollowerRebootedPeerKeys.insert(uint128_t(lowerPeer.private4));

  brain.maybeRelinquishMasterForUpdateSelf();

  suite.expect(brain.updateSelfState == Brain::UpdateSelfState::waitingForRelinquishEchos, "update_self_relinquish_waits_for_echoes");
  suite.expect(brain.updateSelfPlannedMasterPeerKey == uint128_t(lowerPeer.private4), "update_self_relinquish_picks_lowest_peer_key");
  suite.expect(brain.updateSelfRelinquishIssuedPeerKeys.contains(uint128_t(higherPeer.private4)), "update_self_relinquish_issues_higher_peer");
  suite.expect(brain.updateSelfRelinquishIssuedPeerKeys.contains(uint128_t(lowerPeer.private4)), "update_self_relinquish_issues_lower_peer");

  uint32_t relinquishFrames = 0;
  uint128_t designatedPeerKey = 0;
  forEachMessageInBuffer(lowerPeer.wBuffer, [&](Message *frame) {
    if (BrainTopic(frame->topic) != BrainTopic::relinquishMasterStatus)
    {
      return;
    }

    uint8_t *args = frame->args;
    uint8_t status = 0;
    Message::extractArg<ArgumentNature::fixed>(args, status);
    Message::extractArg<ArgumentNature::fixed>(args, designatedPeerKey);
    relinquishFrames += 1;
  });

  suite.expect(relinquishFrames == 1, "update_self_relinquish_queues_message");
  suite.expect(designatedPeerKey == uint128_t(lowerPeer.private4), "update_self_relinquish_message_preserves_lowest_peer_key");
}

static void testUpdateSelfFinalRelinquishPersistsDesignatedHandoff(TestSuite& suite)
{
  ScopedRing scopedRing = {};

  TestBrain brain = {};
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.updateSelfState = Brain::UpdateSelfState::waitingForRelinquishEchos;
  brain.updateSelfExpectedEchos = 2;
  brain.updateSelfRelinquishEchos = 1;
  brain.updateSelfPlannedMasterPeerKey = 0x0a000041;
  brain.updateSelfRelinquishEchoPeerKeys.insert(0x0a000042);

  BrainView designatedPeer = {};
  designatedPeer.private4 = 0x0a000041;
  designatedPeer.boottimens = 410;
  designatedPeer.connected = true;
  designatedPeer.isFixedFile = true;
  designatedPeer.fslot = 41;
  brain.brains.insert(&designatedPeer);

  brain.onUpdateSelfRelinquishEcho(&designatedPeer);

  ProdigyPersistentMasterAuthorityPackage package = {};
  brain.capturePersistentMasterAuthorityPackage(package);

  suite.expect(brain.weAreMaster == false, "update_self_final_relinquish_forfeits_master");
  suite.expect(brain.noMasterYet, "update_self_final_relinquish_returns_to_no_master");
  suite.expect(brain.updateSelfState == Brain::UpdateSelfState::idle, "update_self_final_relinquish_resets_update_state");
  suite.expect(brain.pendingDesignatedMasterPeerKey == uint128_t(designatedPeer.private4), "update_self_final_relinquish_keeps_pending_designated_master");
  suite.expect(package.runtimeState.updateSelf.pendingDesignatedMasterPeerKey == uint128_t(designatedPeer.private4), "update_self_final_relinquish_persists_pending_designated_master");
  suite.expect(brain.transitionToNewBundleCalls == 1, "update_self_final_relinquish_transitions_once");

  brain.brains.erase(&designatedPeer);
}

static void testUpdateProdigyRespondsBeforeSingleBrainTransition(TestSuite& suite)
{
  ScopedRing scopedRing = {};

  String stagedPath = prodigyStagedBundlePath();
  String previousStagedBundle = {};
  bool hadStagedBundle = prodigyFileReadable(stagedPath);
  if (hadStagedBundle)
  {
    Filesystem::openReadAtClose(-1, stagedPath, previousStagedBundle);
  }
  auto restoreStagedBundle = [&]() {
    if (hadStagedBundle)
    {
      Filesystem::openWriteAtClose(-1, stagedPath, previousStagedBundle);
    }
    else
    {
      ::unlink(stagedPath.c_str());
    }
  };

  TestBrain brain = {};
  brain.nBrains = 1;
  brain.weAreMaster = true;
  brain.noMasterYet = false;

  Mothership mothership = {};
  mothership.isFixedFile = true;
  mothership.fslot = 42;
  brain.mothership = &mothership;
  brain.activeMotherships.insert(&mothership);

  String bundle = "unit-update-bundle"_ctv;
  String messageBuffer = {};
  Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::updateProdigy, bundle);
  brain.mothershipHandler(&mothership, message);

  Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
  String serializedResponse = {};
  uint8_t *responseArgs = responseMessage->args;
  Message::extractToStringView(responseArgs, serializedResponse);
  MothershipResponse response = {};
  suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "update_prodigy_response_deserializes");
  suite.expect(response.success, "update_prodigy_response_success");
  suite.expect(brain.updateSelfTransitionAfterMothershipAck, "update_prodigy_single_brain_defers_transition_until_ack");
  suite.expect(brain.transitionToNewBundleCalls == 0, "update_prodigy_single_brain_no_transition_before_ack_send");

  mothership.pendingSend = true;
  mothership.pendingSendBytes = uint32_t(mothership.wBuffer.outstandingBytes());
  mothership.noteSendQueued();
  brain.sendHandler(static_cast<void *>(&mothership), int(mothership.pendingSendBytes));
  suite.expect(brain.transitionToNewBundleCalls == 1, "update_prodigy_single_brain_transitions_after_ack_send");

  brain.activeMotherships.erase(&mothership);
  restoreStagedBundle();
}

static void testPersistentMasterAuthorityPackageRestore(TestSuite& suite)
{
  TestBrain source;
  TestBrain restored;
  String failure;

  ApplicationTlsVaultFactory tlsFactory = {};
  tlsFactory.applicationID = 19;
  tlsFactory.factoryGeneration = 4;
  tlsFactory.updatedAtMs = 111;
  tlsFactory.defaultLeafValidityDays = 20;
  tlsFactory.keySourceMode = 1;
  tlsFactory.scheme = uint8_t(CryptoScheme::ed25519);
  suite.expect(generateApplicationTlsFactory(tlsFactory, failure), "restore_package_generate_tls_factory");
  source.tlsVaultFactoriesByApp.insert_or_assign(tlsFactory.applicationID, tlsFactory);

  ApplicationApiCredentialSet apiSet = {};
  apiSet.applicationID = tlsFactory.applicationID;
  apiSet.setGeneration = 8;
  apiSet.updatedAtMs = 333;
  ApiCredential credential = {};
  credential.name.assign("apns_client_tls"_ctv);
  credential.provider.assign("apple"_ctv);
  credential.generation = 2;
  credential.material.assign("pem-bytes"_ctv);
  apiSet.credentials.push_back(credential);
  source.apiCredentialSetsByApp.insert_or_assign(apiSet.applicationID, apiSet);

  String appName;
  appName.assign("RestoredApp"_ctv);
  source.reserveApplicationIDMapping(appName, tlsFactory.applicationID);
  DeploymentPlan plan = makeDeploymentPlan(tlsFactory.applicationID, 203);
  String resumptionWormholeName = {};
  resumptionWormholeName.assign("public-api-quic"_ctv);
  TlsResumptionSnapshot resumptionSnapshot = {};
  resumptionSnapshot.generation = 44;
  resumptionSnapshot.wormholeName = resumptionWormholeName;
  TlsResumptionKeyEpoch resumptionEpoch = {};
  resumptionEpoch.generation = resumptionSnapshot.generation;
  resumptionEpoch.role = TlsResumptionKeyRole::acceptOnly;
  for (uint32_t index = 0; index < sizeof(resumptionEpoch.keyID); index += 1)
  {
    resumptionEpoch.keyID[index] = uint8_t(0x30u + index);
  }
  for (uint32_t index = 0; index < sizeof(resumptionEpoch.masterSecret); index += 1)
  {
    resumptionEpoch.masterSecret[index] = uint8_t(0x70u + index);
  }
  resumptionEpoch.acceptUntilMs = 99'999;
  resumptionSnapshot.keyRing.push_back(resumptionEpoch);
  source.tlsResumptionStateByDeployment[plan.config.deploymentID()].wormholes[resumptionWormholeName].snapshot = resumptionSnapshot;
  source.nextTlsResumptionGeneration = 45;
  source.deploymentPlans.insert_or_assign(plan.config.deploymentID(), plan);
  source.failedDeployments.insert_or_assign(plan.config.deploymentID(), "bundle-missing"_ctv);
  source.nextMintedClientTlsGeneration = 77;
  source.masterAuthorityRuntimeState.generation = 5;
  suite.expect(generateTransportAuthority(source.masterAuthorityRuntimeState.transportTLSAuthority, failure), "restore_package_generate_transport_authority");
  source.updateSelfState = Brain::UpdateSelfState::waitingForFollowerReboots;
  source.updateSelfExpectedEchos = 3;
  source.updateSelfBundleEchos = 2;
  source.updateSelfRelinquishEchos = 1;
  source.updateSelfPlannedMasterPeerKey = 0xAAA1;
  source.pendingDesignatedMasterPeerKey = 0xAAA2;
  source.updateSelfUseStagedBundleOnly = true;
  source.updateSelfBundleBlob.assign("bundle"_ctv);
  source.updateSelfBundleEchoPeerKeys.insert(0xAAA3);
  source.updateSelfRelinquishEchoPeerKeys.insert(0xAAA4);
  source.updateSelfFollowerBootNsByPeerKey.insert_or_assign(0xAAA5, 999);
  source.updateSelfFollowerRebootedPeerKeys.insert(0xAAA6);
  source.hasCompletedInitialMasterElection = true;
  source.masterAuthorityRuntimeState.nextPendingAddMachinesOperationID = 5;
  ProdigyPendingAddMachinesOperation pendingOperation = {};
  pendingOperation.operationID = 4;
  pendingOperation.request.bootstrapSshUser.assign("root"_ctv);
  pendingOperation.request.controlSocketPath.assign("/run/prodigy/control.sock"_ctv);
  pendingOperation.request.clusterUUID = 0x6601;
  pendingOperation.plannedTopology.version = 11;
  pendingOperation.plannedTopology.machines.push_back(ClusterMachine {});
  pendingOperation.resumeAttempts = 2;
  pendingOperation.updatedAtMs = 4444;
  pendingOperation.lastFailure.assign("pending"_ctv);
  source.masterAuthorityRuntimeState.pendingAddMachinesOperations.push_back(pendingOperation);
  source.refreshMasterAuthorityRuntimeStateFromLiveFields();

  ProdigyPersistentMasterAuthorityPackage package = {};
  source.capturePersistentMasterAuthorityPackage(package);
  restored.applyPersistentMasterAuthorityPackage(package);

  auto restoredTlsIt = restored.tlsVaultFactoriesByApp.find(tlsFactory.applicationID);
  auto restoredApiIt = restored.apiCredentialSetsByApp.find(apiSet.applicationID);
  auto restoredIDIt = restored.reservedApplicationIDsByName.find(appName);
  auto restoredNameIt = restored.reservedApplicationNamesByID.find(tlsFactory.applicationID);
  auto restoredPlanIt = restored.deploymentPlans.find(plan.config.deploymentID());
  auto restoredFailureIt = restored.failedDeployments.find(plan.config.deploymentID());
  auto restoredFollowerBootIt = restored.updateSelfFollowerBootNsByPeerKey.find(0xAAA5);
  const BrainTlsResumptionWormholeState *restoredResumption = restored.tlsResumptionStateForWormhole(plan.config.deploymentID(), resumptionWormholeName);

  suite.expect(restoredTlsIt != restored.tlsVaultFactoriesByApp.end() && equalSerializedObjects(restoredTlsIt->second, tlsFactory), "restore_package_restores_tls_factory");
  suite.expect(restoredApiIt != restored.apiCredentialSetsByApp.end() && equalSerializedObjects(restoredApiIt->second, apiSet), "restore_package_restores_api_credentials");
  suite.expect(restoredIDIt != restored.reservedApplicationIDsByName.end() && restoredIDIt->second == tlsFactory.applicationID, "restore_package_restores_application_id_reservation");
  suite.expect(restoredNameIt != restored.reservedApplicationNamesByID.end() && restoredNameIt->second.equal(appName), "restore_package_restores_application_name_reservation");
  suite.expect(restored.nextReservableApplicationID == source.nextReservableApplicationID, "restore_package_restores_next_application_id");
  suite.expect(restoredPlanIt != restored.deploymentPlans.end() && equalSerializedObjects(restoredPlanIt->second, plan), "restore_package_restores_deployment_plan");
  suite.expect(restoredFailureIt != restored.failedDeployments.end() && restoredFailureIt->second.equal("bundle-missing"_ctv), "restore_package_restores_failed_deployment");
  suite.expect(restored.masterAuthorityRuntimeState == source.masterAuthorityRuntimeState, "restore_package_restores_master_runtime_state");
  suite.expect(restored.hasCompletedInitialMasterElection, "restore_package_restores_initial_master_election_completion");
  suite.expect(restored.nextMintedClientTlsGeneration == source.nextMintedClientTlsGeneration, "restore_package_restores_client_tls_generation");
  suite.expect(restored.nextTlsResumptionGeneration == source.nextTlsResumptionGeneration, "restore_package_restores_tls_resumption_generation");
  suite.expect(restoredResumption != nullptr && equalSerializedObjects(restoredResumption->snapshot, resumptionSnapshot), "restore_package_restores_tls_resumption_snapshot");
  suite.expect(restored.updateSelfState == source.updateSelfState, "restore_package_restores_update_self_state");
  suite.expect(restoredFollowerBootIt != restored.updateSelfFollowerBootNsByPeerKey.end() && restoredFollowerBootIt->second == 999, "restore_package_restores_update_self_follower_boot");
  suite.expect(restored.masterAuthorityRuntimeState.pendingAddMachinesOperations.size() == 1, "restore_package_restores_pending_addmachines_operation");
}

static void testResumePendingAddMachinesOperations(TestSuite& suite)
{
  ResumableAddMachinesBrain brain;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.nBrains = 1;

  ClusterMachine existingMachine = {};
  existingMachine.uuid = 0x1001;
  existingMachine.isBrain = false;
  prodigyAppendUniqueClusterMachineAddress(existingMachine.addresses.privateAddresses, "10.0.0.10"_ctv, 24, "10.0.0.1"_ctv);
  brain.authoritativeTopology.version = 7;
  brain.authoritativeTopology.machines.push_back(existingMachine);

  ProdigyPendingAddMachinesOperation operation = {};
  operation.operationID = 1;
  operation.request.bootstrapSshUser.assign("root"_ctv);
  operation.request.bootstrapSshPrivateKeyPath.assign("/tmp/test-key"_ctv);
  operation.request.controlSocketPath.assign("/run/prodigy/control.sock"_ctv);
  operation.request.clusterUUID = 0x7701;
  operation.plannedTopology = brain.authoritativeTopology;

  ClusterMachine newMachine = {};
  newMachine.uuid = 0x1002;
  newMachine.isBrain = false;
  prodigyAppendUniqueClusterMachineAddress(newMachine.addresses.privateAddresses, "10.0.0.11"_ctv, 24, "10.0.0.1"_ctv);
  newMachine.ssh.address.assign("10.0.0.11"_ctv);
  newMachine.ssh.user.assign("root"_ctv);
  newMachine.ssh.privateKeyPath.assign("/tmp/test-key"_ctv);
  operation.plannedTopology.machines.push_back(newMachine);
  operation.machinesToBootstrap.push_back(newMachine);

  brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.push_back(operation);
  brain.masterAuthorityRuntimeState.nextPendingAddMachinesOperationID = 2;

  brain.resumePendingAddMachinesOperations();

  suite.expect(brain.bootstrappedMachines.size() == 1, "resume_pending_addmachines_bootstraps_machine");
  suite.expect(brain.bootstrappedMachines.size() == 1 && brain.bootstrappedMachines[0].uuid == newMachine.uuid, "resume_pending_addmachines_bootstraps_expected_machine");
  suite.expect(brain.blockingBootstrapCallsWithBundleCache == 1, "resume_pending_addmachines_reuses_bundle_cache");
  suite.expect(brain.blockingBootstrapCallsWithoutBundleCache == 0, "resume_pending_addmachines_avoids_uncached_bootstrap");
  suite.expect(brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.empty(), "resume_pending_addmachines_clears_journal_entry");
  suite.expect(brain.authoritativeTopology.version == 8, "resume_pending_addmachines_bumps_topology_version");
  suite.expect(brain.authoritativeTopology.machines.size() == 2, "resume_pending_addmachines_persists_merged_topology");
  suite.expect(brain.persistCalls >= 2, "resume_pending_addmachines_persists_runtime_and_topology");
}

static void testResumePendingAddMachinesRefreshesProvisionalCreatedMachine(TestSuite& suite)
{
  ResumableAddMachinesBrain brain;
  AutoProvisionBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.nBrains = 1;

  ClusterMachine existingMachine = {};
  existingMachine.uuid = 0x3001;
  existingMachine.isBrain = true;
  existingMachine.ssh.address.assign("10.2.0.10"_ctv);
  existingMachine.ssh.user.assign("root"_ctv);
  existingMachine.ssh.privateKeyPath.assign("/tmp/test-key"_ctv);
  prodigyAppendUniqueClusterMachineAddress(existingMachine.addresses.privateAddresses, "10.2.0.10"_ctv, 24, "10.2.0.1"_ctv);
  brain.authoritativeTopology.version = 12;
  brain.authoritativeTopology.machines.push_back(existingMachine);

  ProdigyPendingAddMachinesOperation operation = {};
  operation.operationID = 7;
  operation.request.bootstrapSshUser.assign("root"_ctv);
  operation.request.bootstrapSshPrivateKeyPath.assign("/tmp/test-key"_ctv);
  operation.request.controlSocketPath.assign("/run/prodigy/control.sock"_ctv);
  operation.request.clusterUUID = 0x8801;
  operation.plannedTopology = brain.authoritativeTopology;

  ClusterMachine createdMachine = {};
  createdMachine.source = ClusterMachineSource::created;
  createdMachine.backing = ClusterMachineBacking::cloud;
  createdMachine.kind = MachineConfig::MachineKind::vm;
  createdMachine.lifetime = MachineLifetime::ondemand;
  createdMachine.isBrain = false;
  createdMachine.hasCloud = true;
  createdMachine.cloud.schema.assign("aws-worker-vm"_ctv);
  createdMachine.cloud.providerMachineType.assign("c7i.large"_ctv);
  createdMachine.cloud.cloudID.assign("i-worker-7"_ctv);
  createdMachine.ssh.user.assign("root"_ctv);
  createdMachine.ssh.privateKeyPath.assign("/tmp/test-key"_ctv);
  createdMachine.ownedLogicalCores = 4;
  createdMachine.ownedMemoryMB = 8192;
  createdMachine.ownedStorageMB = 65'536;
  operation.plannedTopology.machines.push_back(createdMachine);

  brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.push_back(operation);
  brain.masterAuthorityRuntimeState.nextPendingAddMachinesOperationID = 8;
  iaas.inventorySnapshots.push_back(makeMachineSnapshot("aws-worker-vm"_ctv, "10.2.0.20"_ctv, "i-worker-7"_ctv, 0x3002));

  brain.resumePendingAddMachinesOperations();

  suite.expect(brain.bootstrappedMachines.size() == 1, "resume_pending_addmachines_refreshes_provisional_machine_for_bootstrap");
  suite.expect(brain.bootstrappedMachines.size() == 1 && brain.bootstrappedMachines[0].cloud.cloudID == "i-worker-7"_ctv, "resume_pending_addmachines_refreshes_expected_cloud_machine");
  suite.expect(brain.blockingBootstrapCallsWithBundleCache == 1, "resume_pending_addmachines_refresh_reuses_bundle_cache");
  suite.expect(brain.blockingBootstrapCallsWithoutBundleCache == 0, "resume_pending_addmachines_refresh_avoids_uncached_bootstrap");
  suite.expect(brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.empty(), "resume_pending_addmachines_refresh_clears_journal_entry");
  suite.expect(brain.authoritativeTopology.version == 13, "resume_pending_addmachines_refresh_bumps_topology_version");
  suite.expect(brain.authoritativeTopology.machines.size() == 2, "resume_pending_addmachines_refresh_persists_created_machine");
  bool foundRefreshedMachine = false;
  for (const ClusterMachine& machine : brain.authoritativeTopology.machines)
  {
    if (machine.cloudPresent() && machine.cloud.cloudID.equals("i-worker-7"_ctv))
    {
      foundRefreshedMachine = true;
      suite.expect(machine.ssh.address.equals("10.2.0.20"_ctv), "resume_pending_addmachines_refresh_restores_ssh_address");
      suite.expect(machine.uuid == 0x3002, "resume_pending_addmachines_refresh_restores_uuid");
    }
  }
  suite.expect(foundRefreshedMachine, "resume_pending_addmachines_refresh_finds_persisted_cloud_machine");
}

static void testResumePendingAddMachinesOperationFailureRetainsJournal(TestSuite& suite)
{
  ResumableAddMachinesBrain brain;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.nBrains = 1;
  brain.failBootstrap = true;

  ClusterMachine existingMachine = {};
  existingMachine.uuid = 0x2001;
  existingMachine.isBrain = false;
  prodigyAppendUniqueClusterMachineAddress(existingMachine.addresses.privateAddresses, "10.0.1.10"_ctv, 24, "10.0.1.1"_ctv);
  brain.authoritativeTopology.version = 4;
  brain.authoritativeTopology.machines.push_back(existingMachine);

  ProdigyPendingAddMachinesOperation operation = {};
  operation.operationID = 1;
  operation.request.bootstrapSshUser.assign("root"_ctv);
  operation.request.bootstrapSshPrivateKeyPath.assign("/tmp/test-key"_ctv);
  operation.request.controlSocketPath.assign("/run/prodigy/control.sock"_ctv);
  operation.request.clusterUUID = 0x7702;
  operation.plannedTopology = brain.authoritativeTopology;

  ClusterMachine newMachine = {};
  newMachine.uuid = 0x2002;
  newMachine.isBrain = false;
  prodigyAppendUniqueClusterMachineAddress(newMachine.addresses.privateAddresses, "10.0.1.11"_ctv, 24, "10.0.1.1"_ctv);
  newMachine.ssh.address.assign("10.0.1.11"_ctv);
  newMachine.ssh.user.assign("root"_ctv);
  newMachine.ssh.privateKeyPath.assign("/tmp/test-key"_ctv);
  operation.plannedTopology.machines.push_back(newMachine);
  operation.machinesToBootstrap.push_back(newMachine);

  brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.push_back(operation);
  brain.masterAuthorityRuntimeState.nextPendingAddMachinesOperationID = 2;

  brain.resumePendingAddMachinesOperations();

  suite.expect(brain.bootstrappedMachines.empty(), "resume_pending_addmachines_failure_does_not_record_bootstrap_success");
  suite.expect(brain.blockingBootstrapCallsWithBundleCache == 1, "resume_pending_addmachines_failure_reuses_bundle_cache");
  suite.expect(brain.blockingBootstrapCallsWithoutBundleCache == 0, "resume_pending_addmachines_failure_avoids_uncached_bootstrap");
  suite.expect(brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.size() == 1, "resume_pending_addmachines_failure_retains_journal_entry");
  suite.expect(brain.masterAuthorityRuntimeState.pendingAddMachinesOperations[0].resumeAttempts == 1, "resume_pending_addmachines_failure_increments_attempts");
  suite.expect(brain.masterAuthorityRuntimeState.pendingAddMachinesOperations[0].lastFailure.equal("bootstrap failed"_ctv), "resume_pending_addmachines_failure_records_reason");
  suite.expect(brain.authoritativeTopology.version == 4, "resume_pending_addmachines_failure_does_not_persist_topology");
  suite.expect(brain.persistCalls >= 1, "resume_pending_addmachines_failure_persists_runtime_state");
}

static void testSuspendableAddMachinesStreamsCreatedBootstrapDuringSpin(TestSuite& suite)
{
  AsyncQueuedAddMachinesBrain brain;
  AutoProvisionBrainIaaS iaas = {};
  brain.iaas = &iaas;
  iaas.observedBrain = &brain;
  iaas.observedAsyncQueuedMachines = &brain.asyncQueuedMachines;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.nBrains = 1;
  brain.brainConfig.clusterUUID = 0x9901;

  ClusterMachine seedMachine = {};
  seedMachine.uuid = 0x4001;
  seedMachine.source = ClusterMachineSource::created;
  seedMachine.backing = ClusterMachineBacking::cloud;
  seedMachine.kind = MachineConfig::MachineKind::vm;
  seedMachine.lifetime = MachineLifetime::ondemand;
  seedMachine.isBrain = true;
  seedMachine.cloud.schema.assign("seed-vm"_ctv);
  seedMachine.cloud.providerMachineType.assign("seed-vm"_ctv);
  seedMachine.cloud.cloudID.assign("seed-1"_ctv);
  seedMachine.ssh.address.assign("10.4.0.10"_ctv);
  seedMachine.ssh.user.assign("root"_ctv);
  seedMachine.ssh.privateKeyPath.assign("/tmp/test-key"_ctv);
  prodigyAppendUniqueClusterMachineAddress(seedMachine.addresses.privateAddresses, "10.4.0.10"_ctv, 24, "10.4.0.1"_ctv);
  brain.authoritativeTopology.version = 21;
  brain.authoritativeTopology.machines.push_back(seedMachine);

  MachineConfig workerConfig = {};
  workerConfig.kind = MachineConfig::MachineKind::vm;
  workerConfig.slug.assign("worker-vm"_ctv);
  workerConfig.providerMachineType.assign("worker-vm"_ctv);
  workerConfig.nLogicalCores = 2;
  workerConfig.nMemoryMB = 4096;
  workerConfig.nStorageMB = 32'768;
  brain.brainConfig.configBySlug.insert_or_assign(workerConfig.slug, workerConfig);

  AddMachines request = {};
  request.bootstrapSshUser.assign("root"_ctv);
  request.bootstrapSshPrivateKeyPath.assign("/tmp/test-key"_ctv);
  request.controlSocketPath.assign("/run/prodigy/control.sock"_ctv);
  request.clusterUUID = brain.brainConfig.clusterUUID;

  Brain::ManagedAddMachinesWork work = {};
  CreateMachinesInstruction instruction = {};
  instruction.backing = ClusterMachineBacking::cloud;
  instruction.kind = MachineConfig::MachineKind::vm;
  instruction.lifetime = MachineLifetime::ondemand;
  instruction.count = 1;
  instruction.isBrain = false;
  instruction.cloud.schema.assign("worker-vm"_ctv);
  work.createdMachines.push_back(instruction);

  iaas.snapshotsToReturn.push_back(makeMachineSnapshot("worker-vm"_ctv, "10.4.0.20"_ctv, "worker-1"_ctv, 0x4002));

  brain.addMachines(nullptr, request, work, nullptr);

  suite.expect(iaas.sawPendingOperationDuringSpin, "suspendable_addmachines_streams_pending_operation_before_spin_returns");
  suite.expect(iaas.sawBootstrapDuringSpin, "suspendable_addmachines_streams_bootstrap_before_spin_returns");
  suite.expect(brain.asyncQueuedMachines.size() == 1, "suspendable_addmachines_queues_single_async_bootstrap");
  suite.expect(brain.masterAuthorityRuntimeState.pendingAddMachinesOperations.empty(), "suspendable_addmachines_clears_pending_operation_on_success");
  suite.expect(brain.authoritativeTopology.version == 22, "suspendable_addmachines_persists_new_topology_version");
  suite.expect(brain.authoritativeTopology.machines.size() == 2, "suspendable_addmachines_persists_created_machine");
}

static void testReconcileManagedMachineSchemasSkipsEmptySchemaState(TestSuite& suite)
{
  ResumableAddMachinesBrain brain;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.nBrains = 1;

  ClusterMachine createdSeed = {};
  createdSeed.uuid = 0x3001;
  createdSeed.isBrain = true;
  createdSeed.source = ClusterMachineSource::created;
  createdSeed.backing = ClusterMachineBacking::cloud;
  createdSeed.kind = MachineConfig::MachineKind::vm;
  createdSeed.lifetime = MachineLifetime::ondemand;
  createdSeed.cloud.schema.assign("t3.micro"_ctv);
  createdSeed.cloud.providerMachineType.assign("t3.micro"_ctv);
  prodigyAppendUniqueClusterMachineAddress(createdSeed.addresses.privateAddresses, "10.0.2.10"_ctv, 24, "10.0.2.1"_ctv);
  createdSeed.ssh.address.assign("10.0.2.10"_ctv);
  createdSeed.ssh.user.assign("root"_ctv);
  createdSeed.ssh.privateKeyPath.assign("/tmp/test-key"_ctv);

  brain.authoritativeTopology.version = 9;
  brain.authoritativeTopology.machines.push_back(createdSeed);

  String failure = {};
  bool ok = brain.reconcileManagedMachineSchemas(&failure);

  suite.expect(ok, "reconcile_managed_machine_schemas_empty_state_ok");
  suite.expect(failure.size() == 0, "reconcile_managed_machine_schemas_empty_state_no_failure");
  suite.expect(brain.authoritativeTopology.version == 9, "reconcile_managed_machine_schemas_empty_state_keeps_topology_version");
  suite.expect(brain.authoritativeTopology.machines.size() == 1, "reconcile_managed_machine_schemas_empty_state_keeps_created_seed");
  suite.expect(brain.authoritativeTopology.machines.size() == 1 && brain.authoritativeTopology.machines[0] == createdSeed, "reconcile_managed_machine_schemas_empty_state_keeps_seed_identity");
  suite.expect(brain.persistCalls == 0, "reconcile_managed_machine_schemas_empty_state_does_not_persist");
}

static void testImportedTlsFactoryValidationRejectsBrokenPem(TestSuite& suite)
{
  TestBrain brain;
  Mothership mothership;
  NoopBrainIaaS iaas;
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;

  TlsVaultFactoryUpsertRequest request = {};
  request.applicationID = 60'001;
  request.mode = 1;
  request.scheme = uint8_t(CryptoScheme::ed25519);
  request.importRootCertPem.assign("invalid-root-cert"_ctv);
  request.importRootKeyPem.assign("invalid-root-key"_ctv);
  request.importIntermediateCertPem.assign("invalid-intermediate-cert"_ctv);
  request.importIntermediateKeyPem.assign("invalid-intermediate-key"_ctv);

  String serializedRequest;
  BitseryEngine::serialize(serializedRequest, request);

  String messageBuffer;
  Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::upsertTlsVaultFactory, serializedRequest);
  brain.mothershipHandler(&mothership, message);

  Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
  String serializedResponse;
  uint8_t *responseArgs = responseMessage->args;
  Message::extractToStringView(responseArgs, serializedResponse);

  TlsVaultFactoryUpsertResponse response = {};
  suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_upsert_tls_deserializes_response");
  suite.expect(response.success == false, "mothership_upsert_tls_rejects_invalid_import");
  suite.expect(response.failure.size() > 0, "mothership_upsert_tls_rejects_invalid_import_with_failure");
  suite.expect(brain.tlsVaultFactoriesByApp.find(request.applicationID) == brain.tlsVaultFactoriesByApp.end(), "mothership_upsert_tls_does_not_store_invalid_import");
  suite.expect(brain.persistCalls == 0, "mothership_upsert_tls_invalid_import_does_not_persist");
}

static void testImportedTlsFactoryEnablesBundleBuild(TestSuite& suite)
{
  TestBrain brain;
  Mothership mothership;
  NoopBrainIaaS iaas;
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;

  ApplicationTlsVaultFactory generated = {};
  String failure = {};
  suite.expect(generateApplicationTlsFactory(generated, failure, CryptoScheme::p256), "mothership_upsert_tls_generate_valid_import");
  suite.expect(failure.size() == 0, "mothership_upsert_tls_generate_valid_import_no_failure");

  TlsVaultFactoryUpsertRequest request = {};
  request.applicationID = 60'002;
  request.mode = 1;
  request.scheme = uint8_t(CryptoScheme::p256);
  request.importRootCertPem = generated.rootCertPem;
  request.importRootKeyPem = generated.rootKeyPem;
  request.importIntermediateCertPem = generated.intermediateCertPem;
  request.importIntermediateKeyPem = generated.intermediateKeyPem;
  request.defaultLeafValidityDays = 15;

  String serializedRequest;
  BitseryEngine::serialize(serializedRequest, request);

  String messageBuffer;
  Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::upsertTlsVaultFactory, serializedRequest);
  brain.mothershipHandler(&mothership, message);

  Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
  String serializedResponse;
  uint8_t *responseArgs = responseMessage->args;
  Message::extractToStringView(responseArgs, serializedResponse);

  TlsVaultFactoryUpsertResponse response = {};
  suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_upsert_tls_valid_import_deserializes_response");
  suite.expect(response.success, "mothership_upsert_tls_valid_import_success");
  suite.expect(brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles.size() == 1, "mothership_upsert_tls_valid_import_records_lifecycle");
  if (brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles.size() == 1)
  {
    const PrivateTlsVaultLifecycleState& lifecycle = brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles[0];
    suite.expect(lifecycle.applicationID == request.applicationID && lifecycle.factoryGeneration == response.factoryGeneration, "mothership_upsert_tls_valid_import_lifecycle_identity");
    suite.expect(lifecycle.rootNotBeforeMs > 0 && lifecycle.rootNotAfterMs > lifecycle.rootNotBeforeMs, "mothership_upsert_tls_valid_import_lifecycle_root_times");
    suite.expect(lifecycle.intermediateNotBeforeMs > 0 && lifecycle.intermediateNotAfterMs > lifecycle.intermediateNotBeforeMs, "mothership_upsert_tls_valid_import_lifecycle_intermediate_times");
    suite.expect(lifecycle.leafNextRenewAtMs > lifecycle.leafNotBeforeMs && lifecycle.nextRenewAtMs == lifecycle.leafNextRenewAtMs, "mothership_upsert_tls_valid_import_lifecycle_leaf_drives_next_renewal");
  }

  DeploymentPlan deploymentPlan;
  deploymentPlan.config.applicationID = request.applicationID;
  deploymentPlan.config.versionID = 1;
  deploymentPlan.hasTlsIssuancePolicy = true;
  deploymentPlan.tlsIssuancePolicy.applicationID = request.applicationID;
  deploymentPlan.tlsIssuancePolicy.enablePerContainerLeafs = true;
  deploymentPlan.tlsIssuancePolicy.leafValidityDays = 15;
  deploymentPlan.tlsIssuancePolicy.identityNames.push_back("inbound_server_tls"_ctv);

  ContainerView container;
  ContainerPlan containerPlan;
  brain.applyCredentialsToContainerPlan(deploymentPlan, container, containerPlan);
  suite.expect(containerPlan.hasCredentialBundle, "mothership_upsert_tls_valid_import_sets_bundle_flag");
  suite.expect(containerPlan.credentialBundle.tlsIdentities.size() == 1, "mothership_upsert_tls_valid_import_builds_tls_bundle");
  suite.expect(containerPlan.credentialBundle.tlsIdentities[0].name.equal("inbound_server_tls"_ctv), "mothership_upsert_tls_valid_import_bundle_name");

  ApplicationDeployment deployment = {};
  deployment.plan = deploymentPlan;
  container.uuid = uint128_t(0x6002);
  container.state = ContainerState::healthy;
  deployment.containers.insert(&container);
  brain.deployments.insert_or_assign(deploymentPlan.config.deploymentID(), &deployment);
  suite.expect(brain.pushPrivateTlsIdentityDeltaToLiveContainers(request.applicationID, "unit-test"_ctv) == 1, "mothership_upsert_tls_valid_import_pushes_live_tls_delta");
}

static void testCertificateLifecycleSchedulers(TestSuite& suite)
{
  {
    int64_t baseRenewAtMs = prodigyCertificateRenewAtMs(1000, 1000 + int64_t(90) * 24 * 60 * 60 * 1000, prodigyDefaultCertificateRenewAfterLifetimePermille);
    suite.expect(TestBrain::certificateLifecycleJitteredRenewAtMs(0, 1) == 0, "certificate_lifecycle_jitter_keeps_zero_renewal_disabled");
    suite.expect(TestBrain::certificateLifecycleJitteredRenewAtMs(baseRenewAtMs, 1) == baseRenewAtMs + 1, "certificate_lifecycle_jitter_is_deterministic");
    suite.expect(TestBrain::certificateLifecycleBackoffMs(1, 0) == TestBrain::certificateLifecycleBaseRetryDelayMs, "certificate_lifecycle_backoff_starts_at_base_delay");
    suite.expect(TestBrain::certificateLifecycleBackoffMs(3, 0) == TestBrain::certificateLifecycleBaseRetryDelayMs * 4, "certificate_lifecycle_backoff_grows_exponentially");
    suite.expect(TestBrain::certificateLifecycleBackoffMs(UINT32_MAX, 0) == TestBrain::certificateLifecycleMaxRetryDelayMs, "certificate_lifecycle_backoff_is_capped");
    suite.expect(TestBrain::certificateLifecycleBackoffActive(1000, 1000, 0, 1, 0), "certificate_lifecycle_backoff_blocks_same_tick_retry");
    suite.expect(TestBrain::certificateLifecycleBackoffActive(1000 + TestBrain::certificateLifecycleBaseRetryDelayMs, 1000, 0, 1, 0) == false, "certificate_lifecycle_backoff_expires_at_delay");
  }

  {
    TestBrain brain;
    brain.brainConfig.clusterUUID = uint128_t(0xAC01);
    brain.brainConfig.controlSocketPath = "/run/prodigy/control.sock"_ctv;
    brain.brainConfig.acme.accountEmail = "ops@example.com"_ctv;
    brain.brainConfig.acme.termsAgreed = true;

    DeploymentPlan plan = makeDeploymentPlan(60'010, 7);
    installACMEZoneDNSCredential(brain, plan.config.applicationID, "prod-dns"_ctv, "example.com"_ctv);
    Wormhole wormhole = {};
    wormhole.name = "api"_ctv;
    wormhole.hasDNSConfig = true;
    wormhole.dns.provider = "cloudflare"_ctv;
    wormhole.dns.credentialName = "prod-dns"_ctv;
    wormhole.dns.zone = "023e105f4ecef8ad9ca31a8372d0c353"_ctv;
    wormhole.dns.name = "Api.Example.COM."_ctv;
    wormhole.dns.ttl = 60;
    plan.wormholes.push_back(wormhole);

    WormholePublicTLSConfig publicTLS = {};
    publicTLS.wormholeName = wormhole.name;
    publicTLS.identityName = "api-public"_ctv;
    plan.publicTLS.push_back(publicTLS);

    String failure = {};
    suite.expect(brain.reconcilePublicTlsCertificateStatesForDeployment(plan, failure), "public_tls_reconcile_creates_state");
    suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates.size() == 1, "public_tls_reconcile_state_count");
    suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates[0].spec.domains.size() == 1 && brain.masterAuthorityRuntimeState.publicTlsCertificates[0].spec.domains[0].equal("api.example.com"_ctv), "public_tls_reconcile_derives_canonical_domain");
    suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates[0].spec.dnsZone.equal("023e105f4ecef8ad9ca31a8372d0c353"_ctv), "public_tls_reconcile_preserves_provider_zone_id");

    ScopedTempDir certbotTemp;
    if (suite.require(certbotTemp.valid(), "public_tls_scheduler_lock_temp_dir") == false)
    {
      return;
    }
    ProdigyCertbotPaths paths = {};
    paths.certbotPath = "/bin/false"_ctv;
    std::string configDirText = (certbotTemp.path / "config").string();
    std::string workDirText = (certbotTemp.path / "work").string();
    paths.configDir.assign(configDirText.data(), configDirText.size());
    paths.workDir.assign(workDirText.data(), workDirText.size());

    int64_t nowMs = Time::now<TimeResolution::ms>();
    int lockFD = -1;
    bool lockBusy = false;
    suite.expect(prodigyAcquireCertbotCertificateLock(brain.brainConfig, brain.masterAuthorityRuntimeState.publicTlsCertificates[0], paths, lockFD, &lockBusy, &failure), "public_tls_scheduler_lock_fixture_acquires");
    suite.expect(brain.advancePublicTlsCertificateLifecycles(nowMs, paths) == 0, "public_tls_scheduler_lock_blocks_duplicate_spawn");
    suite.expect(brain.publicTlsCertbotPids.empty() && brain.publicTlsCertbotLockFDs.empty(), "public_tls_scheduler_lock_skips_child_state");
    suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates[0].lastAttemptMs == 0, "public_tls_scheduler_lock_does_not_record_attempt");
    prodigyReleaseCertbotLockFD(lockFD);

    suite.expect(brain.advancePublicTlsCertificateLifecycles(nowMs, paths) == 1, "public_tls_scheduler_starts_certbot");
    suite.expect(brain.publicTlsCertbotLockFDs.size() == 1, "public_tls_scheduler_records_certbot_lock");

    uint32_t reaped = 0;
    for (uint32_t attempt = 0; attempt < 100 && reaped == 0; attempt += 1)
    {
      reaped = brain.reapPublicTlsCertbotProcesses(Time::now<TimeResolution::ms>());
      if (reaped == 0)
      {
        usleep(1000);
      }
    }
    suite.expect(reaped == 1, "public_tls_scheduler_reaps_certbot");
    suite.expect(brain.publicTlsCertbotLockFDs.empty(), "public_tls_scheduler_reap_releases_certbot_lock");
    suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates[0].lastSuccessMs == 0 && brain.masterAuthorityRuntimeState.publicTlsCertificates[0].lastFailure.size() > 0, "public_tls_scheduler_requires_import_hook");
    suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates[0].failureCount == 1, "public_tls_scheduler_records_failure_count");
    suite.expect(brain.advancePublicTlsCertificateLifecycles(nowMs, paths) == 0, "public_tls_scheduler_backoff_blocks_same_tick_retry");
  }

  {
    TestBrain brain;
    brain.brainConfig.acme.accountEmail = "ops@example.com"_ctv;
    brain.brainConfig.acme.termsAgreed = true;

    DeploymentPlan plan = makeDeploymentPlan(60'017, 13);
    installACMEZoneDNSCredential(brain, plan.config.applicationID, "prod-dns"_ctv, "example.com"_ctv);

    RoutableResourceLease binding = {};
    binding.kind = RoutableResourceLeaseKind::dnsRecord;
    binding.owner = deploymentRoutableResourceLeaseOwner(plan);
    binding.owner.name = "api-binding"_ctv;
    binding.registeredPrefixUUID = uint128_t(0xAC1701);
    binding.address = IPAddress("203.0.113.17", false);
    binding.dnsProvider = "cloudflare"_ctv;
    binding.dnsCredentialName = "prod-dns"_ctv;
    binding.dnsZone = "example.com"_ctv;
    binding.dnsName = "api.example.com"_ctv;
    binding.dnsTTL = 60;
    brain.routableResourceLeaseRuntimeState.push_back(binding);

    Wormhole wormhole = {};
    wormhole.name = "api"_ctv;
    wormhole.hasDNSConfig = true;
    wormhole.dns.bindingName = "api-binding"_ctv;
    plan.wormholes.push_back(wormhole);

    WormholePublicTLSConfig publicTLS = {};
    publicTLS.wormholeName = wormhole.name;
    publicTLS.identityName = "api-public"_ctv;
    plan.publicTLS.push_back(publicTLS);

    String failure = {};
    suite.expect(brain.reconcilePublicTlsCertificateStatesForDeployment(plan, failure) == false && failure.equal("public TLS requires resolved wormhole DNS provider, credentialName, zone, and ttl"_ctv), "public_tls_reconcile_requires_resolved_dns_binding");
    suite.expect(brain.resolveDeploymentWormholeDNSBinding(plan, plan.wormholes[0], failure), "public_tls_reconcile_resolves_dns_binding");
    suite.expect(brain.reconcilePublicTlsCertificateStatesForDeployment(plan, failure), "public_tls_reconcile_accepts_resolved_dns_binding");
    suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates.size() == 1, "public_tls_reconcile_dns_binding_state_count");
    if (brain.masterAuthorityRuntimeState.publicTlsCertificates.size() == 1)
    {
      const PublicTlsCertificateSpec& spec = brain.masterAuthorityRuntimeState.publicTlsCertificates[0].spec;
      suite.expect(spec.domains.size() == 1 && spec.domains[0].equal("api.example.com"_ctv), "public_tls_reconcile_dns_binding_derives_domain");
      suite.expect(spec.dnsProvider.equal("cloudflare"_ctv) && spec.dnsCredentialName.equal("prod-dns"_ctv) && spec.dnsZone.equal("example.com"_ctv) && spec.dnsTTL == 60, "public_tls_reconcile_dns_binding_copies_provider_config");
    }
  }

  {
    TestBrain brain;
    brain.brainConfig.acme.accountEmail = "ops@example.com"_ctv;
    brain.brainConfig.acme.termsAgreed = true;

    DeploymentPlan plan = makeDeploymentPlan(60'013, 10);
    Wormhole wormhole = {};
    wormhole.name = "api"_ctv;
    wormhole.hasDNSConfig = true;
    wormhole.dns.provider = "cloudflare"_ctv;
    wormhole.dns.credentialName = "prod-dns"_ctv;
    wormhole.dns.zone = "example.com"_ctv;
    wormhole.dns.name = "api.example.com"_ctv;
    wormhole.dns.ttl = 60;
    plan.wormholes.push_back(wormhole);
    WormholePublicTLSConfig publicTLS = {};
    publicTLS.wormholeName = wormhole.name;
    publicTLS.identityName = "api-public"_ctv;
    plan.publicTLS.push_back(publicTLS);

    String failure = {};
    suite.expect(brain.reconcilePublicTlsCertificateStatesForDeployment(plan, failure) == false && failure.equal("public TLS DNS credential is not registered"_ctv), "public_tls_reconcile_requires_dns_credential");
    installACMEZoneDNSCredential(brain, plan.config.applicationID, "prod-dns"_ctv, "example.net"_ctv);
    suite.expect(brain.reconcilePublicTlsCertificateStatesForDeployment(plan, failure) == false && failure.equal("ACME DNS credential does not cover challenge zone"_ctv), "public_tls_reconcile_rejects_out_of_scope_dns_credential");

    TestBrain accountBrain;
    accountBrain.brainConfig.acme.accountEmail = "ops@example.com"_ctv;
    accountBrain.brainConfig.acme.termsAgreed = true;
    ApplicationApiCredentialSet accountSet = {};
    accountSet.applicationID = plan.config.applicationID;
    ApiCredential accountCredential = {};
    accountCredential.name = "prod-dns"_ctv;
    accountCredential.provider = "cloudflare"_ctv;
    accountCredential.material = "secret"_ctv;
    accountCredential.metadata.insert_or_assign("dnsScope"_ctv, "native-account"_ctv);
    accountSet.credentials.push_back(accountCredential);
    accountBrain.apiCredentialSetsByApp[accountSet.applicationID] = accountSet;
    suite.expect(accountBrain.reconcilePublicTlsCertificateStatesForDeployment(plan, failure) == false && failure.equal("ACME DNS native-account scope requires dnsAccountScopeAccepted=true"_ctv), "public_tls_reconcile_rejects_unacknowledged_native_account_scope");
    accountBrain.apiCredentialSetsByApp[accountSet.applicationID].credentials[0].metadata.insert_or_assign("dnsAccountScopeAccepted"_ctv, "true"_ctv);
    suite.expect(accountBrain.reconcilePublicTlsCertificateStatesForDeployment(plan, failure), "public_tls_reconcile_accepts_native_account_scope");
    DeploymentPlan outsideDomainPlan = plan;
    outsideDomainPlan.publicTLS[0].domains.push_back("other.example.net"_ctv);
    suite.expect(accountBrain.reconcilePublicTlsCertificateStatesForDeployment(outsideDomainPlan, failure) == false && failure.equal("public TLS domain is not covered by wormhole DNS"_ctv), "public_tls_reconcile_rejects_domain_outside_declared_dns");
    plan.publicTLS[0].identityName = "../bad"_ctv;
    suite.expect(accountBrain.reconcilePublicTlsCertificateStatesForDeployment(plan, failure) == false && failure.equal("public TLS identityName must be a safe path segment"_ctv), "public_tls_reconcile_rejects_unsafe_identity_name");

    TestBrain serializedPlanBrain;
    serializedPlanBrain.brainConfig.acme.accountEmail = "ops@example.com"_ctv;
    serializedPlanBrain.brainConfig.acme.termsAgreed = true;
    installACMEZoneDNSCredential(serializedPlanBrain, plan.config.applicationID, "prod-dns"_ctv, "example.com"_ctv);
    DeploymentPlan invalidPublicTLS = makeDeploymentPlan(60'013, 10);
    invalidPublicTLS.wormholes.push_back(wormhole);
    invalidPublicTLS.publicTLS.push_back(publicTLS);
    invalidPublicTLS.publicTLS[0].issuer = "other-ca"_ctv;
    suite.expect(serializedPlanBrain.reconcilePublicTlsCertificateStatesForDeployment(invalidPublicTLS, failure) == false && failure.equal("public TLS issuer must be letsencrypt"_ctv), "public_tls_reconcile_rejects_serialized_issuer");
    invalidPublicTLS.publicTLS[0] = publicTLS;
    invalidPublicTLS.publicTLS[0].keyType = "ed25519"_ctv;
    suite.expect(serializedPlanBrain.reconcilePublicTlsCertificateStatesForDeployment(invalidPublicTLS, failure) == false && failure.equal("public TLS keyType must be ecdsa or rsa"_ctv), "public_tls_reconcile_rejects_serialized_key_type");
    invalidPublicTLS.publicTLS[0] = publicTLS;
    invalidPublicTLS.publicTLS[0].renewAfterLifetimePermille = 0;
    suite.expect(serializedPlanBrain.reconcilePublicTlsCertificateStatesForDeployment(invalidPublicTLS, failure) == false && failure.equal("public TLS renewAfterLifetimePermille must be in 1..999"_ctv), "public_tls_reconcile_rejects_serialized_renew_after");
    invalidPublicTLS.publicTLS[0] = publicTLS;
    invalidPublicTLS.publicTLS[0].domains.push_back("203.0.113.44"_ctv);
    suite.expect(serializedPlanBrain.reconcilePublicTlsCertificateStatesForDeployment(invalidPublicTLS, failure) == false && failure.equal("ACME DNS-01 identifier must be a DNS name"_ctv), "public_tls_reconcile_rejects_ip_literal_domain");
    invalidPublicTLS.publicTLS[0] = publicTLS;
    invalidPublicTLS.publicTLS[0].domains.push_back("api_example.com"_ctv);
    suite.expect(serializedPlanBrain.reconcilePublicTlsCertificateStatesForDeployment(invalidPublicTLS, failure) == false && failure.equal("ACME DNS-01 identifier is not a valid DNS name"_ctv), "public_tls_reconcile_rejects_invalid_dns_identifier");

    DeploymentPlan privateIdentityCollisionPlan = makeDeploymentPlan(60'013, 10);
    privateIdentityCollisionPlan.wormholes.push_back(wormhole);
    privateIdentityCollisionPlan.hasTlsIssuancePolicy = true;
    privateIdentityCollisionPlan.tlsIssuancePolicy.applicationID = privateIdentityCollisionPlan.config.applicationID;
    privateIdentityCollisionPlan.tlsIssuancePolicy.enablePerContainerLeafs = true;
    privateIdentityCollisionPlan.tlsIssuancePolicy.identityNames.push_back(publicTLS.identityName);
    privateIdentityCollisionPlan.publicTLS.push_back(publicTLS);
    suite.expect(serializedPlanBrain.reconcilePublicTlsCertificateStatesForDeployment(privateIdentityCollisionPlan, failure) == false && failure.equal("public TLS identityName conflicts with private TLS identityName"_ctv), "public_tls_reconcile_rejects_private_identity_collision");
    suite.expect(serializedPlanBrain.masterAuthorityRuntimeState.publicTlsCertificates.empty(), "public_tls_reconcile_private_identity_collision_creates_no_state");

    DeploymentPlan duplicateIdentityPlan = makeDeploymentPlan(60'013, 10);
    duplicateIdentityPlan.wormholes.push_back(wormhole);
    Wormhole secondWormhole = wormhole;
    secondWormhole.name = "api2"_ctv;
    secondWormhole.dns.name = "api2.example.com"_ctv;
    duplicateIdentityPlan.wormholes.push_back(secondWormhole);
    duplicateIdentityPlan.publicTLS.push_back(publicTLS);
    WormholePublicTLSConfig secondPublicTLS = publicTLS;
    secondPublicTLS.wormholeName = secondWormhole.name;
    duplicateIdentityPlan.publicTLS.push_back(secondPublicTLS);
    suite.expect(serializedPlanBrain.reconcilePublicTlsCertificateStatesForDeployment(duplicateIdentityPlan, failure) == false && failure.equal("public TLS identityName is already used"_ctv), "public_tls_reconcile_rejects_duplicate_identity_name");
    suite.expect(serializedPlanBrain.masterAuthorityRuntimeState.publicTlsCertificates.empty(), "public_tls_reconcile_duplicate_identity_creates_no_state");
  }

  {
    ScopedTempDir temp;
    if (suite.require(temp.valid(), "public_tls_scheduler_timeout_temp_dir") == false)
    {
      return;
    }
    std::filesystem::path certbotPath = temp.path / "sleep-certbot";
    suite.expect(writeTextFile(certbotPath, "#!/bin/sh\nsleep 30\n"), "public_tls_scheduler_timeout_writes_certbot_script");
    std::filesystem::permissions(certbotPath, std::filesystem::perms::owner_exec | std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);

    TestBrain brain;
    TestDNSProvider dns;
    brain.dnsProvider = &dns;
    brain.brainConfig.clusterUUID = uint128_t(0xAC03);
    brain.brainConfig.controlSocketPath = "/run/prodigy/control.sock"_ctv;
    brain.brainConfig.dnsProvider = "cloudflare"_ctv;
    brain.brainConfig.acme.accountEmail = "ops@example.com"_ctv;
    brain.brainConfig.acme.termsAgreed = true;

    DeploymentPlan plan = makeDeploymentPlan(60'015, 11);
    installACMEZoneDNSCredential(brain, plan.config.applicationID, "prod-dns"_ctv, "example.com"_ctv);
    Wormhole wormhole = {};
    wormhole.name = "api"_ctv;
    wormhole.hasDNSConfig = true;
    wormhole.dns.provider = "cloudflare"_ctv;
    wormhole.dns.credentialName = "prod-dns"_ctv;
    wormhole.dns.zone = "example.com"_ctv;
    wormhole.dns.name = "api.example.com"_ctv;
    wormhole.dns.ttl = 60;
    plan.wormholes.push_back(wormhole);
    WormholePublicTLSConfig publicTLS = {};
    publicTLS.wormholeName = wormhole.name;
    publicTLS.identityName = "api-public"_ctv;
    plan.publicTLS.push_back(publicTLS);

    String failure = {};
    suite.expect(brain.reconcilePublicTlsCertificateStatesForDeployment(plan, failure), "public_tls_scheduler_timeout_creates_state");
    ProdigyDNSRecordBinding staleTXT = {};
    staleTXT.provider = "cloudflare"_ctv;
    staleTXT.credentialName = "prod-dns"_ctv;
    staleTXT.zone = "example.com"_ctv;
    staleTXT.name = "_acme-challenge.api.example.com."_ctv;
    staleTXT.type = "TXT"_ctv;
    staleTXT.values.push_back("stale-token"_ctv);
    staleTXT.ttl = 60;
    dns.activeTXT.push_back(staleTXT);
    brain.masterAuthorityRuntimeState.publicTlsCertificates[0].pendingDNS01Challenges.push_back(TestBrain::acmeDNS01ChallengeStateFromRecord(staleTXT));
    ProdigyCertbotPaths paths = {};
    std::string certbotPathText = certbotPath.string();
    paths.certbotPath.assign(certbotPathText.data(), certbotPathText.size());
    int64_t nowMs = Time::now<TimeResolution::ms>();
    suite.expect(brain.advancePublicTlsCertificateLifecycles(nowMs, paths) == 1, "public_tls_scheduler_timeout_starts_certbot");
    String key = TestBrain::publicTlsCertificateRuntimeKey(brain.masterAuthorityRuntimeState.publicTlsCertificates[0]);
    brain.publicTlsCertbotStartedAtMs.insert_or_assign(key, nowMs - TestBrain::publicTlsCertbotTimeoutMs - 1);
    suite.expect(brain.reapPublicTlsCertbotProcesses(nowMs) == 1, "public_tls_scheduler_timeout_reaps_certbot");
    suite.expect(brain.publicTlsCertbotPids.empty() && brain.publicTlsCertbotStartedAtMs.empty(), "public_tls_scheduler_timeout_clears_process_state");
    suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates[0].lastFailure.equal("certbot process timed out"_ctv), "public_tls_scheduler_timeout_records_failure");
    suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates[0].pendingDNS01Challenges.empty(), "public_tls_scheduler_timeout_forgets_cleaned_txt_value");
    suite.expect(dns.cleanupTXTCalls == 1 && dns.activeTXT.empty(), "public_tls_scheduler_timeout_cleans_pending_txt_value");
  }

  {
    TestBrain brain;
    brain.brainConfig.acme.accountEmail = "ops@example.com"_ctv;
    brain.brainConfig.acme.termsAgreed = true;
    installACMEZoneDNSCredential(brain, 60'014, "prod-dns"_ctv, "example.com"_ctv);

    auto publicTLSPlan = [](uint64_t versionID, const String& dnsName) {
      DeploymentPlan plan = makeDeploymentPlan(60'014, versionID);
      Wormhole wormhole = {};
      wormhole.name = "api"_ctv;
      wormhole.hasDNSConfig = true;
      wormhole.dns.provider = "cloudflare"_ctv;
      wormhole.dns.credentialName = "prod-dns"_ctv;
      wormhole.dns.zone = "example.com"_ctv;
      wormhole.dns.name = dnsName;
      wormhole.dns.ttl = 60;
      plan.wormholes.push_back(wormhole);
      WormholePublicTLSConfig publicTLS = {};
      publicTLS.wormholeName = wormhole.name;
      publicTLS.identityName = "api-public"_ctv;
      plan.publicTLS.push_back(publicTLS);
      return plan;
    };

    String failure = {};
    DeploymentPlan v1 = publicTLSPlan(1, "api.example.com"_ctv);
    suite.expect(brain.reconcilePublicTlsCertificateStatesForDeployment(v1, failure), "public_tls_reconcile_upgrade_seeds_state");
    brain.masterAuthorityRuntimeState.publicTlsCertificates[0].identity.name = "api-public"_ctv;
    brain.masterAuthorityRuntimeState.publicTlsCertificates[0].identity.generation = 7;
    brain.masterAuthorityRuntimeState.publicTlsCertificates[0].identity.certPem = "cert-v7"_ctv;
    brain.masterAuthorityRuntimeState.publicTlsCertificates[0].identity.keyPem = "key-v7"_ctv;
    brain.masterAuthorityRuntimeState.publicTlsCertificates[0].identity.notBeforeMs = 1'700'000'000'000;
    brain.masterAuthorityRuntimeState.publicTlsCertificates[0].identity.notAfterMs = 1'700'086'400'000;
    brain.masterAuthorityRuntimeState.publicTlsCertificates[0].identity.dnsSans.push_back("api.example.com"_ctv);

    DeploymentPlan v2 = publicTLSPlan(2, "api.example.com"_ctv);
    suite.expect(brain.reconcilePublicTlsCertificateStatesForDeployment(v2, failure), "public_tls_reconcile_upgrade_transfers_compatible_state");
    suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates.size() == 1, "public_tls_reconcile_upgrade_keeps_single_state");
    suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates[0].spec.deploymentID == v2.config.deploymentID(), "public_tls_reconcile_upgrade_moves_owner");
    suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates[0].identity.certPem.equal("cert-v7"_ctv) && brain.masterAuthorityRuntimeState.publicTlsCertificates[0].identity.keyPem.equal("key-v7"_ctv), "public_tls_reconcile_upgrade_reuses_material");

    DeploymentPlan v2Renew = publicTLSPlan(2, "api.example.com"_ctv);
    v2Renew.publicTLS[0].renewAfterLifetimePermille = 500;
    suite.expect(brain.reconcilePublicTlsCertificateStatesForDeployment(v2Renew, failure), "public_tls_reconcile_renew_policy_keeps_material");
    const PublicTlsCertificateState& renewedPolicy = brain.masterAuthorityRuntimeState.publicTlsCertificates[0];
    int64_t expectedRenewAtMs = TestBrain::certificateLifecycleJitteredRenewAtMs(
        prodigyCertificateRenewAtMs(renewedPolicy.identity.notBeforeMs, renewedPolicy.identity.notAfterMs, renewedPolicy.spec.renewAfterLifetimePermille),
        TestBrain::publicTlsCertificateJitterSeed(renewedPolicy));
    suite.expect(renewedPolicy.identity.certPem.equal("cert-v7"_ctv) && renewedPolicy.nextRenewAtMs == expectedRenewAtMs, "public_tls_reconcile_renew_policy_reschedules_material");

    DeploymentPlan v2Staging = publicTLSPlan(2, "api.example.com"_ctv);
    v2Staging.publicTLS[0].staging = true;
    suite.expect(brain.reconcilePublicTlsCertificateStatesForDeployment(v2Staging, failure), "public_tls_reconcile_staging_flip_updates_state");
    suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates[0].identity.certPem.size() == 0 && brain.masterAuthorityRuntimeState.publicTlsCertificates[0].nextRenewAtMs == 0, "public_tls_reconcile_staging_flip_drops_material");

    ApplicationDeployment head = {};
    DeploymentPlan v3 = publicTLSPlan(3, "api2.example.com"_ctv);
    head.plan = v3;
    brain.deploymentsByApp.insert_or_assign(v3.config.applicationID, &head);
    suite.expect(brain.reconcilePublicTlsCertificateStatesForDeployment(v3, failure), "public_tls_reconcile_changed_domain_creates_new_state");
    suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates.size() == 2, "public_tls_reconcile_changed_domain_keeps_old_until_release");
    suite.expect(brain.releasePublicTlsCertificatesForDeployment(v2.config.deploymentID()) == 1, "public_tls_release_removes_untransferred_old_state");
    suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates.size() == 1 && brain.masterAuthorityRuntimeState.publicTlsCertificates[0].spec.deploymentID == v3.config.deploymentID(), "public_tls_release_leaves_new_owner_state");
  }

  {
    ScopedTempDir temp;
    if (suite.require(temp.valid(), "public_tls_scheduler_recovery_temp_dir") == false)
    {
      return;
    }

    TestBrain brain;
    brain.brainConfig.clusterUUID = uint128_t(0xAC02);
    brain.brainConfig.controlSocketPath = "/run/prodigy/control.sock"_ctv;
    brain.brainConfig.acme.accountEmail = "ops@example.com"_ctv;
    brain.brainConfig.acme.termsAgreed = true;

    DeploymentPlan plan = makeDeploymentPlan(60'012, 9);
    installACMEZoneDNSCredential(brain, plan.config.applicationID, "prod-dns"_ctv, "example.com"_ctv);
    Wormhole wormhole = {};
    wormhole.name = "api"_ctv;
    wormhole.hasDNSConfig = true;
    wormhole.dns.provider = "cloudflare"_ctv;
    wormhole.dns.credentialName = "prod-dns"_ctv;
    wormhole.dns.zone = "example.com"_ctv;
    wormhole.dns.name = "api.example.com"_ctv;
    wormhole.dns.ttl = 60;
    plan.wormholes.push_back(wormhole);

    WormholePublicTLSConfig publicTLS = {};
    publicTLS.wormholeName = wormhole.name;
    publicTLS.identityName = "api-public"_ctv;
    publicTLS.staging = true;
    plan.publicTLS.push_back(publicTLS);

    String failure = {};
    suite.expect(brain.reconcilePublicTlsCertificateStatesForDeployment(plan, failure), "public_tls_scheduler_recovery_creates_state");
    if (suite.require(brain.masterAuthorityRuntimeState.publicTlsCertificates.size() == 1, "public_tls_scheduler_recovery_state_count") == false)
    {
      return;
    }

    PublicTlsCertificateState& certificate = brain.masterAuthorityRuntimeState.publicTlsCertificates[0];
    std::filesystem::path configDir = temp.path / "config";
    std::filesystem::path lineageDir = configDir / "live" / toStdString(certificate.certbotCertName);
    std::filesystem::create_directories(lineageDir);
    Vector<String> domains = certificate.spec.domains;
    String certPem = {};
    String keyPem = {};
    suite.expect(generateACMELineage(lineageDir, domains, certPem, keyPem), "public_tls_scheduler_recovery_writes_lineage");

    certificate.lastAttemptMs = 1;
    certificate.lastSuccessMs = 0;
    certificate.failureCount = 2;
    certificate.lastFailure.clear();
    ProdigyCertbotPaths paths = {};
    std::string configDirText = configDir.string();
    paths.configDir.assign(configDirText.data(), configDirText.size());

    suite.expect(brain.advancePublicTlsCertificateLifecycles(Time::now<TimeResolution::ms>(), paths) == 0, "public_tls_scheduler_recovery_imports_without_spawn");
    suite.expect(certificate.identity.certPem.equals(certPem) && certificate.identity.keyPem.equals(keyPem), "public_tls_scheduler_recovery_imports_lineage_identity");
    suite.expect(certificate.lastSuccessMs >= certificate.lastAttemptMs && certificate.lastFailure.size() == 0, "public_tls_scheduler_recovery_records_success");
    suite.expect(certificate.failureCount == 0, "public_tls_scheduler_recovery_clears_failure_count");
    suite.expect(brain.publicTlsCertbotPids.empty(), "public_tls_scheduler_recovery_leaves_no_child_pid");
  }

  {
    ScopedTempDir temp;
    if (suite.require(temp.valid(), "public_tls_scheduler_fake_certbot_temp_dir") == false)
    {
      return;
    }

    std::filesystem::path fixtureDir = temp.path / "fixture";
    std::filesystem::create_directories(fixtureDir);
    Vector<String> domains = {};
    domains.push_back("api.example.com"_ctv);
    String certPem = {};
    String keyPem = {};
    suite.expect(generateACMELineage(fixtureDir, domains, certPem, keyPem), "public_tls_scheduler_fake_certbot_writes_fixture");

    TestBrain brain;
    TestDNSProvider dns;
    brain.dnsProvider = &dns;
    brain.brainConfig.dnsProvider = "cloudflare"_ctv;
    brain.brainConfig.clusterUUID = uint128_t(0xAC04);
    brain.brainConfig.controlSocketPath = "/run/prodigy/control.sock"_ctv;
    brain.brainConfig.acme.accountEmail = "ops@example.com"_ctv;
    brain.brainConfig.acme.termsAgreed = true;

    DeploymentPlan plan = makeDeploymentPlan(60'016, 12);
    installACMEZoneDNSCredential(brain, plan.config.applicationID, "prod-dns"_ctv, "example.com"_ctv);
    brain.apiCredentialSetsByApp[plan.config.applicationID].credentials[0].metadata.insert_or_assign("acmePropagationDelayMs"_ctv, "0"_ctv);
    Wormhole wormhole = {};
    wormhole.name = "api"_ctv;
    wormhole.hasDNSConfig = true;
    wormhole.dns.provider = "cloudflare"_ctv;
    wormhole.dns.credentialName = "prod-dns"_ctv;
    wormhole.dns.zone = "example.com"_ctv;
    wormhole.dns.name = "api.example.com"_ctv;
    wormhole.dns.ttl = 60;
    plan.wormholes.push_back(wormhole);
    WormholePublicTLSConfig publicTLS = {};
    publicTLS.wormholeName = wormhole.name;
    publicTLS.identityName = "api-public"_ctv;
    publicTLS.staging = true;
    plan.publicTLS.push_back(publicTLS);

    String failure = {};
    suite.expect(brain.reconcilePublicTlsCertificateStatesForDeployment(plan, failure), "public_tls_scheduler_fake_certbot_creates_state");
    if (suite.require(brain.masterAuthorityRuntimeState.publicTlsCertificates.size() == 1, "public_tls_scheduler_fake_certbot_state_count") == false)
    {
      return;
    }

    Machine machine = {};
    machine.uuid = uint128_t(0xAC1601);
    machine.neuron.isFixedFile = true;
    machine.neuron.fslot = 9;
    machine.neuron.connected = true;
    ContainerView container = {};
    container.uuid = uint128_t(0xAC1602);
    container.machine = &machine;
    container.deploymentID = plan.config.deploymentID();
    container.state = ContainerState::healthy;
    ApplicationDeployment deployment = {};
    deployment.plan = plan;
    deployment.containers.insert(&container);
    brain.deployments.insert_or_assign(plan.config.deploymentID(), &deployment);

    std::filesystem::path certbotPath = temp.path / "fake-certbot";
    std::filesystem::path configDir = temp.path / "config";
    PublicTlsCertificateState& certificate = brain.masterAuthorityRuntimeState.publicTlsCertificates[0];
    AcmeDNS01ChallengeRequest dnsRequest = {};
    dnsRequest.clusterUUID = brain.brainConfig.clusterUUID;
    dnsRequest.applicationID = plan.config.applicationID;
    dnsRequest.deploymentID = plan.config.deploymentID();
    dnsRequest.wormholeName = wormhole.name;
    dnsRequest.certName = certificate.certbotCertName;
    dnsRequest.identifier = "api.example.com"_ctv;
    dnsRequest.validation = "fake-certbot-token"_ctv;
    AcmeDNS01ChallengeResponse dnsResponse = {};
    suite.expect(brain.applyACMEDNS01Challenge(dnsRequest, false, dnsResponse) && dnsResponse.success, "public_tls_scheduler_fake_dns_presents_challenge");
    suite.expect(dns.activeTXT.size() == 1 && dns.activeTXT[0].name.equal("_acme-challenge.api.example.com."_ctv) && dns.activeTXT[0].values[0].equal("fake-certbot-token"_ctv), "public_tls_scheduler_fake_dns_records_value");
    suite.expect(certificate.pendingDNS01Challenges.size() == 1, "public_tls_scheduler_fake_dns_records_pending_value");
    suite.expect(brain.applyACMEDNS01Challenge(dnsRequest, true, dnsResponse) && dnsResponse.success, "public_tls_scheduler_fake_dns_cleans_challenge");
    suite.expect(dns.activeTXT.empty() && certificate.pendingDNS01Challenges.empty(), "public_tls_scheduler_fake_dns_cleans_value");
    std::filesystem::path lineageDir = configDir / "live" / toStdString(certificate.certbotCertName);
    std::string script = "#!/bin/sh\nmkdir -p '" + lineageDir.string() + "' || exit 3\ncp '" + (fixtureDir / "fullchain.pem").string() + "' '" + (lineageDir / "fullchain.pem").string() + "' || exit 4\ncp '" + (fixtureDir / "privkey.pem").string() + "' '" + (lineageDir / "privkey.pem").string() + "' || exit 5\n";
    suite.expect(writeTextFile(certbotPath, script), "public_tls_scheduler_fake_certbot_writes_script");
    std::filesystem::permissions(certbotPath, std::filesystem::perms::owner_exec | std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);

    ProdigyCertbotPaths paths = {};
    std::string certbotPathText = certbotPath.string();
    std::string configDirText = configDir.string();
    paths.certbotPath.assign(certbotPathText.data(), certbotPathText.size());
    paths.configDir.assign(configDirText.data(), configDirText.size());

    int64_t nowMs = Time::now<TimeResolution::ms>();
    suite.expect(brain.advancePublicTlsCertificateLifecycles(nowMs, paths) == 1, "public_tls_scheduler_fake_certbot_spawns");
    uint32_t reaped = 0;
    for (uint32_t attempt = 0; attempt < 100 && reaped == 0; attempt += 1)
    {
      reaped = brain.reapPublicTlsCertbotProcesses(Time::now<TimeResolution::ms>());
      if (reaped == 0)
      {
        usleep(1000);
      }
    }
    suite.expect(reaped == 1, "public_tls_scheduler_fake_certbot_reaps");
    suite.expect(certificate.lastFailure.equal("certbot completed without importing lineage"_ctv), "public_tls_scheduler_fake_certbot_requires_recovery_import");
    suite.expect(brain.advancePublicTlsCertificateLifecycles(nowMs, paths) == 0, "public_tls_scheduler_fake_certbot_recovers_lineage");
    suite.expect(certificate.identity.certPem.equals(certPem) && certificate.identity.keyPem.equals(keyPem), "public_tls_scheduler_fake_certbot_imports_identity");

    uint128_t refreshedContainer = 0;
    CredentialDelta delta = {};
    suite.expect(extractQueuedCredentialDelta(machine, refreshedContainer, delta), "public_tls_scheduler_fake_certbot_pushes_delta");
    suite.expect(refreshedContainer == container.uuid && delta.updatedTls.size() == 1 && delta.updatedTls[0].keyPem.equals(keyPem), "public_tls_scheduler_fake_certbot_delta_carries_key");
  }

  {
    TestBrain brain;
    ApplicationTlsVaultFactory factory = {};
    String failure = {};
    factory.applicationID = 60'011;
    factory.factoryGeneration = 5;
    factory.keySourceMode = 0;
    factory.defaultLeafValidityDays = 15;
    suite.expect(generateApplicationTlsFactory(factory, failure, CryptoScheme::p256), "private_tls_scheduler_generates_factory");
    brain.tlsVaultFactoriesByApp.insert_or_assign(factory.applicationID, factory);
    suite.expect(brain.upsertPrivateTlsVaultLifecycleState(factory, Time::now<TimeResolution::ms>(), &failure), "private_tls_scheduler_seeds_lifecycle");
    brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles[0].nextRenewAtMs = 1;
    brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles[0].leafNextRenewAtMs = 2;

    DeploymentPlan plan = makeDeploymentPlan(factory.applicationID, 8);
    plan.hasTlsIssuancePolicy = true;
    plan.tlsIssuancePolicy.applicationID = factory.applicationID;
    plan.tlsIssuancePolicy.enablePerContainerLeafs = true;
    plan.tlsIssuancePolicy.identityNames.push_back("inbound_server_tls"_ctv);

    Machine machine = {};
    machine.neuron.isFixedFile = true;
    machine.neuron.fslot = 10;
    machine.neuron.connected = true;

    ContainerView container = {};
    container.uuid = uint128_t(0xC011);
    container.machine = &machine;
    container.deploymentID = plan.config.deploymentID();
    container.state = ContainerState::healthy;

    ApplicationDeployment deployment = {};
    deployment.plan = plan;
    deployment.containers.insert(&container);
    brain.deployments.insert_or_assign(plan.config.deploymentID(), &deployment);
    brain.containers.insert_or_assign(container.uuid, &container);

    CredentialBundle initialBundle = {};
    uint64_t initialBundleGeneration = 0;
    suite.expect(brain.buildTlsBundleForContainer(plan, container, initialBundle, initialBundleGeneration) && initialBundle.tlsIdentities.size() == 1, "private_tls_scheduler_builds_initial_leaf");
    container.hasCredentialBundle = true;
    container.credentialBundle = initialBundle;

    int64_t nowMs = Time::now<TimeResolution::ms>();
    suite.expect(brain.advancePrivateTlsVaultLifecycles(nowMs, true) == 1, "private_tls_scheduler_advances_lifecycle");
    suite.expect(brain.tlsVaultFactoriesByApp[factory.applicationID].factoryGeneration == factory.factoryGeneration + 1, "private_tls_scheduler_rotates_authority_generation");
    suite.expect(brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles[0].lastSuccessMs == nowMs, "private_tls_scheduler_records_success");

    uint128_t refreshedContainer = 0;
    CredentialDelta delta = {};
    suite.expect(extractQueuedCredentialDelta(machine, refreshedContainer, delta), "private_tls_scheduler_queues_delta");
    suite.expect(refreshedContainer == container.uuid && delta.updatedTls.size() == 1 && delta.updatedTls[0].keyPem.size() > 0, "private_tls_scheduler_distributes_leaf");
    suite.expect(delta.updatedTls.size() == 1 && delta.updatedTls[0].generation == factory.factoryGeneration + 1, "private_tls_scheduler_authority_renewal_bumps_identity_generation");
    suite.expect(container.credentialBundle.tlsIdentities.size() == 1 && container.credentialBundle.tlsIdentities[0].generation == factory.factoryGeneration, "private_tls_scheduler_keeps_old_leaf_until_ack");
    suite.expect(container.hasPendingCredentialBundle && container.pendingCredentialBundle.tlsIdentities.size() == 1 && container.pendingCredentialBundle.tlsIdentities[0].generation == factory.factoryGeneration + 1, "private_tls_scheduler_stages_new_leaf_until_ack");
    suite.expect(brain.noteContainerCredentialRefreshAck(container.uuid), "private_tls_scheduler_ack_promotes_leaf");

    uint64_t authorityGeneration = brain.tlsVaultFactoriesByApp[factory.applicationID].factoryGeneration;
    machine.neuron.wBuffer.clear();
    brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles[0].nextRenewAtMs = 1;
    brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles[0].leafNextRenewAtMs = 1;
    suite.expect(brain.advancePrivateTlsVaultLifecycles(nowMs + 1, true) == 1, "private_tls_scheduler_advances_leaf_lifecycle");
    suite.expect(brain.tlsVaultFactoriesByApp[factory.applicationID].factoryGeneration == authorityGeneration + 1, "private_tls_scheduler_leaf_renewal_bumps_factory_generation");
    suite.expect(extractQueuedCredentialDelta(machine, refreshedContainer, delta), "private_tls_scheduler_queues_leaf_delta");
    suite.expect(delta.updatedTls.size() == 1 && delta.updatedTls[0].generation == authorityGeneration + 1, "private_tls_scheduler_leaf_renewal_bumps_identity_generation");
    suite.expect(brain.noteContainerCredentialRefreshAck(container.uuid), "private_tls_scheduler_ack_promotes_second_leaf");

    ApplicationTlsVaultFactory authorityBefore = brain.tlsVaultFactoriesByApp[factory.applicationID];
    PrivateTlsVaultLifecycleState& authorityLifecycle = brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles[0];
    int64_t rootBaseRenewAtMs = prodigyCertificateRenewAtMs(authorityLifecycle.rootNotBeforeMs, authorityLifecycle.rootNotAfterMs, prodigyDefaultCertificateRenewAfterLifetimePermille);
    int64_t rootRenewAtMs = TestBrain::certificateLifecycleJitteredRenewAtMs(rootBaseRenewAtMs, TestBrain::privateTlsVaultJitterSeed(authorityLifecycle) ^ 0xA11CE001ULL);
    PrivateTlsVaultLifecycleState authorityProbe = authorityLifecycle;
    authorityProbe.intermediateNotBeforeMs = 0;
    authorityProbe.intermediateNotAfterMs = 0;
    authorityProbe.nextRenewAtMs = rootBaseRenewAtMs;
    suite.expect(rootRenewAtMs > rootBaseRenewAtMs, "private_tls_scheduler_authority_jitter_fixture");
    suite.expect(TestBrain::privateTlsAuthorityRenewalDue(authorityProbe) == false, "private_tls_scheduler_authority_waits_for_jittered_deadline");
    authorityProbe.nextRenewAtMs = rootRenewAtMs;
    suite.expect(TestBrain::privateTlsAuthorityRenewalDue(authorityProbe), "private_tls_scheduler_authority_due_at_jittered_deadline");

    int64_t intermediateBaseRenewAtMs = prodigyCertificateRenewAtMs(authorityLifecycle.intermediateNotBeforeMs, authorityLifecycle.intermediateNotAfterMs, prodigyDefaultCertificateRenewAfterLifetimePermille);
    int64_t intermediateRenewAtMs = TestBrain::certificateLifecycleJitteredRenewAtMs(intermediateBaseRenewAtMs, TestBrain::privateTlsVaultJitterSeed(authorityLifecycle) ^ 0xA11CE002ULL);
    PrivateTlsVaultLifecycleState intermediateProbe = authorityLifecycle;
    intermediateProbe.rootNotBeforeMs = 0;
    intermediateProbe.rootNotAfterMs = 0;
    intermediateProbe.nextRenewAtMs = intermediateBaseRenewAtMs;
    suite.expect(intermediateRenewAtMs > intermediateBaseRenewAtMs, "private_tls_scheduler_intermediate_jitter_fixture");
    suite.expect(TestBrain::privateTlsAuthorityRenewalDue(intermediateProbe) == false, "private_tls_scheduler_intermediate_waits_for_jittered_deadline");
    intermediateProbe.nextRenewAtMs = intermediateRenewAtMs;
    suite.expect(TestBrain::privateTlsAuthorityRenewalDue(intermediateProbe), "private_tls_scheduler_intermediate_due_at_jittered_deadline");

    authorityLifecycle.nextRenewAtMs = rootRenewAtMs;
    authorityLifecycle.leafNextRenewAtMs = rootRenewAtMs + 1;
    uint64_t acceptedPrivateGeneration = container.credentialBundle.tlsIdentities[0].generation;
    String acceptedPrivateChain = container.credentialBundle.tlsIdentities[0].chainPem;
    machine.neuron.wBuffer.clear();
    suite.expect(rootRenewAtMs > nowMs && brain.advancePrivateTlsVaultLifecycles(rootRenewAtMs, true) == 1, "private_tls_scheduler_advances_authority_lifecycle_at_two_thirds");
    const ApplicationTlsVaultFactory& authorityAfter = brain.tlsVaultFactoriesByApp[factory.applicationID];
    suite.expect(authorityAfter.rootCertPem.equals(authorityBefore.rootCertPem) == false && authorityAfter.intermediateCertPem.equals(authorityBefore.intermediateCertPem) == false, "private_tls_scheduler_rotates_root_and_intermediate_material");
    suite.expect(extractQueuedCredentialDelta(machine, refreshedContainer, delta), "private_tls_scheduler_queues_authority_delta");
    String authorityChain = authorityAfter.intermediateCertPem;
    authorityChain.append(authorityAfter.rootCertPem);
    suite.expect(delta.updatedTls.size() == 1 && delta.updatedTls[0].generation == authorityAfter.factoryGeneration && delta.updatedTls[0].chainPem.equals(authorityChain), "private_tls_scheduler_authority_delta_carries_rotated_chain");
    suite.expect(container.credentialBundle.tlsIdentities.size() == 1 && container.credentialBundle.tlsIdentities[0].generation == acceptedPrivateGeneration && container.credentialBundle.tlsIdentities[0].chainPem.equals(acceptedPrivateChain), "private_tls_scheduler_authority_overlap_keeps_old_chain_until_ack");
    suite.expect(container.hasPendingCredentialBundle && container.pendingCredentialBundle.tlsIdentities.size() == 1 && container.pendingCredentialBundle.tlsIdentities[0].generation == authorityAfter.factoryGeneration && container.pendingCredentialBundle.tlsIdentities[0].chainPem.equals(authorityChain), "private_tls_scheduler_authority_overlap_stages_rotated_chain");
  }

  {
    TestBrain brain;
    ApplicationTlsVaultFactory factory = {};
    String failure = {};
    factory.applicationID = 60'014;
    factory.factoryGeneration = 3;
    factory.keySourceMode = 0;
    factory.defaultLeafValidityDays = 30;
    suite.expect(generateApplicationTlsFactory(factory, failure, CryptoScheme::p256), "private_tls_scheduler_override_generates_factory");
    factory.defaultLeafValidityDays = 30;
    brain.tlsVaultFactoriesByApp.insert_or_assign(factory.applicationID, factory);
    int64_t leafNotBeforeMs = 1'000'000;
    suite.expect(brain.upsertPrivateTlsVaultLifecycleState(factory, leafNotBeforeMs, &failure), "private_tls_scheduler_override_seeds_lifecycle");
    PrivateTlsVaultLifecycleState& lifecycle = brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles[0];
    int64_t dayMs = int64_t(24) * 60 * 60 * 1000;
    int64_t defaultRenewAtMs = TestBrain::certificateLifecycleJitteredRenewAtMs(prodigyCertificateRenewAtMs(leafNotBeforeMs, leafNotBeforeMs + int64_t(30) * dayMs, prodigyDefaultCertificateRenewAfterLifetimePermille), TestBrain::privateTlsVaultJitterSeed(lifecycle) ^ 0xA11CE003ULL);
    suite.expect(lifecycle.leafNextRenewAtMs == defaultRenewAtMs, "private_tls_scheduler_override_starts_with_factory_default_leaf_schedule");

    DeploymentPlan plan = makeDeploymentPlan(factory.applicationID, 11);
    plan.hasTlsIssuancePolicy = true;
    plan.tlsIssuancePolicy.applicationID = factory.applicationID;
    plan.tlsIssuancePolicy.enablePerContainerLeafs = true;
    plan.tlsIssuancePolicy.leafValidityDays = 3;
    plan.tlsIssuancePolicy.identityNames.push_back("short_leaf_tls"_ctv);
    ApplicationDeployment deployment = {};
    deployment.plan = plan;
    brain.deployments.insert_or_assign(plan.config.deploymentID(), &deployment);

    int64_t overrideRenewAtMs = TestBrain::certificateLifecycleJitteredRenewAtMs(prodigyCertificateRenewAtMs(leafNotBeforeMs, leafNotBeforeMs + int64_t(3) * dayMs, prodigyDefaultCertificateRenewAfterLifetimePermille), TestBrain::privateTlsVaultJitterSeed(lifecycle) ^ 0xA11CE003ULL);
    suite.expect(overrideRenewAtMs < defaultRenewAtMs, "private_tls_scheduler_override_fixture_shortens_schedule");
    suite.expect(brain.advancePrivateTlsVaultLifecycles(overrideRenewAtMs - 1, false) == 0, "private_tls_scheduler_override_waits_until_short_leaf_deadline");
    suite.expect(lifecycle.leafNextRenewAtMs == overrideRenewAtMs && lifecycle.nextRenewAtMs <= overrideRenewAtMs, "private_tls_scheduler_override_recomputes_shortest_live_leaf_schedule");
    suite.expect(brain.advancePrivateTlsVaultLifecycles(overrideRenewAtMs, false) == 1, "private_tls_scheduler_override_advances_at_short_leaf_deadline");
    suite.expect(brain.tlsVaultFactoriesByApp[factory.applicationID].factoryGeneration == factory.factoryGeneration + 1, "private_tls_scheduler_override_bumps_generation");
    suite.expect(brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles[0].leafNotAfterMs == overrideRenewAtMs + int64_t(3) * dayMs, "private_tls_scheduler_override_preserves_short_leaf_window_after_refresh");
  }

  {
    TestBrain brain;
    ApplicationTlsVaultFactory factory = {};
    String failure = {};
    factory.applicationID = 60'012;
    factory.factoryGeneration = 5;
    factory.keySourceMode = 1;
    factory.defaultLeafValidityDays = 15;
    suite.expect(generateApplicationTlsFactory(factory, failure, CryptoScheme::p256), "private_tls_scheduler_imported_generates_factory");
    brain.tlsVaultFactoriesByApp.insert_or_assign(factory.applicationID, factory);
    suite.expect(brain.upsertPrivateTlsVaultLifecycleState(factory, Time::now<TimeResolution::ms>(), &failure), "private_tls_scheduler_imported_seeds_lifecycle");
    brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles[0].nextRenewAtMs = 1;
    brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles[0].leafNextRenewAtMs = 1;

    DeploymentPlan plan = makeDeploymentPlan(factory.applicationID, 9);
    plan.hasTlsIssuancePolicy = true;
    plan.tlsIssuancePolicy.applicationID = factory.applicationID;
    plan.tlsIssuancePolicy.enablePerContainerLeafs = true;
    plan.tlsIssuancePolicy.identityNames.push_back("inbound_server_tls"_ctv);

    Machine machine = {};
    machine.neuron.isFixedFile = true;
    machine.neuron.fslot = 10;
    machine.neuron.connected = true;

    ContainerView container = {};
    container.uuid = uint128_t(0xC012);
    container.machine = &machine;
    container.deploymentID = plan.config.deploymentID();
    container.state = ContainerState::healthy;

    ApplicationDeployment deployment = {};
    deployment.plan = plan;
    deployment.containers.insert(&container);
    brain.deployments.insert_or_assign(plan.config.deploymentID(), &deployment);

    int64_t nowMs = Time::now<TimeResolution::ms>();
    suite.expect(brain.advancePrivateTlsVaultLifecycles(nowMs, true) == 1, "private_tls_scheduler_imported_advances_leaf_lifecycle");
    suite.expect(brain.tlsVaultFactoriesByApp[factory.applicationID].factoryGeneration == factory.factoryGeneration + 1, "private_tls_scheduler_imported_leaf_bumps_factory_generation");

    uint128_t refreshedContainer = 0;
    CredentialDelta delta = {};
    suite.expect(extractQueuedCredentialDelta(machine, refreshedContainer, delta), "private_tls_scheduler_imported_queues_leaf_delta");
    suite.expect(refreshedContainer == container.uuid && delta.updatedTls.size() == 1 && delta.updatedTls[0].generation == factory.factoryGeneration + 1, "private_tls_scheduler_imported_distributes_leaf");

    PrivateTlsVaultLifecycleState& lifecycle = brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles[0];
    lifecycle.nextRenewAtMs = TestBrain::certificateLifecycleJitteredRenewAtMs(prodigyCertificateRenewAtMs(lifecycle.rootNotBeforeMs, lifecycle.rootNotAfterMs, prodigyDefaultCertificateRenewAfterLifetimePermille), TestBrain::privateTlsVaultJitterSeed(lifecycle) ^ 0xA11CE001ULL);
    machine.neuron.wBuffer.clear();
    suite.expect(brain.advancePrivateTlsVaultLifecycles(lifecycle.nextRenewAtMs, true) == 0, "private_tls_scheduler_imported_blocks_authority_lifecycle");
    suite.expect(brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles[0].lastFailure.equal("external tls vault authority material requires operator refresh"_ctv), "private_tls_scheduler_imported_authority_requires_operator");
    suite.expect(brain.masterAuthorityRuntimeState.privateTlsVaultLifecycles[0].failureCount == 1, "private_tls_scheduler_imported_authority_records_failure_count");
    suite.expect(brain.advancePrivateTlsVaultLifecycles(lifecycle.nextRenewAtMs, true) == 0, "private_tls_scheduler_imported_authority_backoff_blocks_same_tick_retry");
  }
}

static void testRegisterRoutablePrefixAcceptsSingleMachineHostPrefix(TestSuite& suite)
{
  TestBrain brain;
  Mothership mothership;
  NoopBrainIaaS iaas;
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;

  Machine machine = {};
  machine.uuid = uint128_t(0x3355);
  machine.slug.assign("prefix-host"_ctv);
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

  RoutableSubnetRegistration request = {};
  request.subnet.name.assign("single-host-prefix"_ctv);
  request.subnet.subnet = IPPrefix("2001:db8:100::55", true, 128);
  request.subnet.usage = ExternalSubnetUsage::wormholes;
  request.subnet.ingressScope = RoutableIngressScope::singleMachine;

  String serializedRequest = {};
  BitseryEngine::serialize(serializedRequest, request);

  String messageBuffer = {};
  Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::registerRoutableSubnet, serializedRequest);
  brain.mothershipHandler(&mothership, message);

  Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
  String serializedResponse = {};
  uint8_t *responseArgs = responseMessage->args;
  Message::extractToStringView(responseArgs, serializedResponse);

  RoutableSubnetRegistration response = {};
  suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_register_routable_prefix_deserializes_response");
  suite.expect(response.success, "mothership_register_routable_prefix_accepts_single_machine_without_bgp");
  suite.expect(response.created, "mothership_register_routable_prefix_creates_single_machine_host_prefix");
  suite.expect(brain.brainConfig.distributableExternalSubnets.size() == 1, "mothership_register_routable_prefix_persists_prefix");
  if (brain.brainConfig.distributableExternalSubnets.size() == 1)
  {
    const DistributableExternalSubnet& stored = brain.brainConfig.distributableExternalSubnets[0];
    suite.expect(stored.ingressScope == RoutableIngressScope::singleMachine, "mothership_register_routable_prefix_persists_single_machine_scope");
    suite.expect(stored.machineUUID == machine.uuid, "mothership_register_routable_prefix_persists_machine_uuid");
    suite.expect(stored.subnet.equals(request.subnet.subnet), "mothership_register_routable_prefix_persists_host_prefix");
  }

  TestBrain ambiguousBrain;
  Mothership ambiguousMothership;
  Machine other = {};
  other.uuid = uint128_t(0x3356);
  ambiguousBrain.weAreMaster = true;
  ambiguousBrain.machines.insert(&machine);
  ambiguousBrain.machines.insert(&other);
  ambiguousBrain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  ambiguousBrain.machinesByUUID.insert_or_assign(other.uuid, &other);

  String ambiguousBuffer = {};
  Message *ambiguousMessage = buildMothershipMessage(ambiguousBuffer, MothershipTopic::registerRoutableSubnet, serializedRequest);
  ambiguousBrain.mothershipHandler(&ambiguousMothership, ambiguousMessage);

  responseMessage = reinterpret_cast<Message *>(ambiguousMothership.wBuffer.data());
  responseArgs = responseMessage->args;
  Message::extractToStringView(responseArgs, serializedResponse);
  suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_register_routable_prefix_ambiguous_deserializes_response");
  suite.expect(response.success == false, "mothership_register_routable_prefix_rejects_ambiguous_single_machine_owner");
}

static void testRegisterRoutablePrefixAllocatesElasticPrefix(TestSuite& suite)
{
  TestBrain brain;
  Mothership mothership;
  ElasticPrefixBrainIaaS iaas;
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;

  Machine machine = {};
  machine.uuid = uint128_t(0x3366);
  machine.cloudID.assign("cloud-3366"_ctv);
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 8;
  machine.neuron.connected = true;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

  RoutableSubnetRegistration request = {};
  request.subnet.name.assign("elastic-prefix"_ctv);
  request.subnet.kind = RoutablePrefixKind::elastic;
  request.subnet.usage = ExternalSubnetUsage::wormholes;
  request.subnet.ingressScope = RoutableIngressScope::singleMachine;
  request.subnet.providerPool.assign("pool-a"_ctv);
  request.family = ExternalAddressFamily::ipv4;
  request.elasticIntent = ElasticPrefixIntent::create;

  String serializedRequest = {};
  BitseryEngine::serialize(serializedRequest, request);

  String messageBuffer = {};
  Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::registerRoutableSubnet, serializedRequest);
  brain.mothershipHandler(&mothership, message);

  Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
  String serializedResponse = {};
  uint8_t *responseArgs = responseMessage->args;
  Message::extractToStringView(responseArgs, serializedResponse);

  RoutableSubnetRegistration response = {};
  suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_register_elastic_prefix_deserializes_response");
  suite.expect(response.success, "mothership_register_elastic_prefix_success");
  suite.expect(response.created, "mothership_register_elastic_prefix_created");
  suite.expect(iaas.assignCalls == 1, "mothership_register_elastic_prefix_calls_provider");
  suite.expect(iaas.lastMachine == &machine, "mothership_register_elastic_prefix_uses_single_machine");
  suite.expect(iaas.lastFamily == ExternalAddressFamily::ipv4, "mothership_register_elastic_prefix_passes_family");
  suite.expect(iaas.lastIntent == ElasticPrefixIntent::create, "mothership_register_elastic_prefix_passes_intent");
  suite.expect(iaas.lastProviderPool.equal("pool-a"_ctv), "mothership_register_elastic_prefix_passes_pool");
  suite.expect(brain.brainConfig.distributableExternalSubnets.size() == 1, "mothership_register_elastic_prefix_persists_one_prefix");
  if (brain.brainConfig.distributableExternalSubnets.size() == 1)
  {
    const DistributableExternalSubnet& stored = brain.brainConfig.distributableExternalSubnets[0];
    suite.expect(stored.kind == RoutablePrefixKind::elastic, "mothership_register_elastic_prefix_persists_kind");
    suite.expect(stored.subnet.equals(IPPrefix("198.51.100.88", false, 32)), "mothership_register_elastic_prefix_persists_host_prefix");
    suite.expect(stored.machineUUID == machine.uuid, "mothership_register_elastic_prefix_persists_machine_uuid");
    suite.expect(stored.providerAllocationID.equal("alloc-88"_ctv), "mothership_register_elastic_prefix_persists_allocation");
    suite.expect(stored.providerAssociationID.equal("assoc-88"_ctv), "mothership_register_elastic_prefix_persists_association");
    suite.expect(stored.releaseOnRemove, "mothership_register_elastic_prefix_persists_release_flag");
  }

  String unregisterRequestBuffer = {};
  RoutableSubnetUnregistration unregisterRequest = {};
  unregisterRequest.name.assign("elastic-prefix"_ctv);
  BitseryEngine::serialize(unregisterRequestBuffer, unregisterRequest);

  RoutableSubnetUnregistration unregisterResponse = {};
  auto sendUnregister = [&]() -> bool {
    String unregisterMessageBuffer = {};
    message = buildMothershipMessage(unregisterMessageBuffer, MothershipTopic::unregisterRoutableSubnet, unregisterRequestBuffer);
    mothership.wBuffer.clear();
    brain.mothershipHandler(&mothership, message);
    responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
    responseArgs = responseMessage->args;
    Message::extractToStringView(responseArgs, serializedResponse);
    unregisterResponse = {};
    return BitseryEngine::deserializeSafe(serializedResponse, unregisterResponse);
  };

  RoutableResourceLease liveLease = {};
  liveLease.kind = RoutableResourceLeaseKind::wormholeAddress;
  liveLease.owner.applicationID = 625;
  liveLease.owner.deploymentID = 1;
  liveLease.owner.lineageID = 625;
  liveLease.registeredPrefixUUID = brain.brainConfig.distributableExternalSubnets[0].uuid;
  liveLease.address = IPAddress("198.51.100.88", false);
  brain.routableResourceLeaseRuntimeState.push_back(liveLease);
  suite.expect(sendUnregister(), "mothership_unregister_elastic_prefix_in_use_deserializes_response");
  suite.expect(unregisterResponse.success == false, "mothership_unregister_elastic_prefix_rejects_owned_resource");
  suite.expect(unregisterResponse.failure.equal("routable prefix has owned resources"_ctv), "mothership_unregister_elastic_prefix_owned_resource_failure_text");
  suite.expect(iaas.releaseCalls == 0, "mothership_unregister_elastic_prefix_in_use_skips_provider_release");
  suite.expect(brain.brainConfig.distributableExternalSubnets.size() == 1, "mothership_unregister_elastic_prefix_in_use_keeps_prefix");
  brain.routableResourceLeaseRuntimeState.clear();

  suite.expect(sendUnregister(), "mothership_unregister_elastic_prefix_deserializes_response");
  suite.expect(unregisterResponse.success && unregisterResponse.removed, "mothership_unregister_elastic_prefix_success");
  suite.expect(iaas.releaseCalls == 1, "mothership_unregister_elastic_prefix_releases_provider");
  suite.expect(iaas.lastReleased.providerAllocationID.equal("alloc-88"_ctv), "mothership_unregister_elastic_prefix_release_allocation");
  suite.expect(brain.brainConfig.distributableExternalSubnets.empty(), "mothership_unregister_elastic_prefix_removes_prefix");
}

static void testPullRoutableResourceLeasesTopic(TestSuite& suite)
{
  TestBrain brain;
  Mothership mothership;
  brain.weAreMaster = true;

  RoutableResourceLease lease = {};
  lease.kind = RoutableResourceLeaseKind::whiteholeAddressPort;
  lease.owner.applicationID = 515;
  lease.owner.deploymentID = 9001;
  lease.owner.lineageID = 42;
  lease.owner.name.assign("egress"_ctv);
  lease.registeredPrefixUUID = uint128_t(0x515);
  lease.address = IPAddress("198.18.0.9", false);
  lease.sourcePort = 49'152;
  brain.routableResourceLeaseRuntimeState.push_back(lease);

  String messageBuffer = {};
  Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::pullRoutableResourceLeases);
  brain.mothershipHandler(&mothership, message);

  Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
  suite.expect(MothershipTopic(responseMessage->topic) == MothershipTopic::pullRoutableResourceLeases, "mothership_pull_routable_leases_topic");

  String serializedResponse = {};
  uint8_t *responseArgs = responseMessage->args;
  Message::extractToStringView(responseArgs, serializedResponse);
  RoutableResourceLeaseReport response = {};
  suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_pull_routable_leases_deserializes_response");
  suite.expect(response.success, "mothership_pull_routable_leases_success");
  suite.expect(response.leases.size() == 1 && response.leases[0] == lease, "mothership_pull_routable_leases_returns_runtime_state");
}

static void testDNSBindingTopicsReserveAddressAndApplyProvider(TestSuite& suite)
{
  TestBrain brain;
  Mothership mothership;
  TestDNSProvider dns;
  brain.weAreMaster = true;
  brain.dnsProvider = &dns;
  brain.brainConfig.dnsProvider = "cloudflare"_ctv;

  DistributableExternalSubnet prefix = {};
  prefix.uuid = uint128_t(0xDDBB01);
  prefix.usage = ExternalSubnetUsage::wormholes;
  prefix.ingressScope = RoutableIngressScope::switchboardFleet;
  prefix.subnet = IPPrefix("203.0.113.0", false, 24);
  brain.brainConfig.distributableExternalSubnets.push_back(prefix);

  ApplicationApiCredentialSet set = {};
  set.applicationID = 624;
  ApiCredential credential = {};
  credential.name = "cf-prod"_ctv;
  credential.provider = "cloudflare"_ctv;
  credential.material = "secret"_ctv;
  set.credentials.push_back(credential);
  brain.apiCredentialSetsByApp[set.applicationID] = set;

  RoutableResourceLease binding = {};
  binding.kind = RoutableResourceLeaseKind::dnsRecord;
  binding.owner.applicationID = set.applicationID;
  binding.owner.name = "api-binding"_ctv;
  binding.registeredPrefixUUID = prefix.uuid;
  binding.address = IPAddress("203.0.113.77", false);
  binding.dnsProvider = "cloudflare"_ctv;
  binding.dnsCredentialName = "cf-prod"_ctv;
  binding.dnsZone = "example.com."_ctv;
  binding.dnsName = "api.example.com."_ctv;
  binding.dnsTTL = 300;

  RoutableResourceLeaseReport request = {};
  request.leases.push_back(binding);
  String serializedRequest = {};
  BitseryEngine::serialize(serializedRequest, request);
  String messageBuffer = {};
  Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::upsertDNSBinding, serializedRequest);
  brain.mothershipHandler(&mothership, message);

  Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
  suite.expect(MothershipTopic(responseMessage->topic) == MothershipTopic::upsertDNSBinding, "mothership_upsert_dns_binding_topic");
  String serializedResponse = {};
  uint8_t *responseArgs = responseMessage->args;
  Message::extractToStringView(responseArgs, serializedResponse);
  RoutableResourceLeaseReport response = {};
  suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_upsert_dns_binding_deserializes_response");
  suite.expect(response.success, "mothership_upsert_dns_binding_success");
  suite.expect(response.leases.size() == 2, "mothership_upsert_dns_binding_returns_address_and_dns_leases");
  suite.expect(brain.routableResourceLeaseRuntimeState.size() == 2, "mothership_upsert_dns_binding_persists_two_leases");
  suite.expect(dns.upsertCalls == 1 && dns.upserts[0].values.size() == 1 && dns.upserts[0].values[0].equal("203.0.113.77"_ctv), "mothership_upsert_dns_binding_applies_provider_record");

  RoutableResourceLease movedBinding = binding;
  movedBinding.address = IPAddress("203.0.113.78", false);
  RoutableResourceLeaseReport movedResponse = {};
  suite.expect(brain.upsertDNSBindingLease(movedBinding, movedResponse) == false, "dns_binding_upsert_rejects_duplicate_binding_name_move");
  suite.expect(movedResponse.failure.equal("DNS binding name is already owned"_ctv), "dns_binding_upsert_duplicate_binding_name_failure_text");
  suite.expect(dns.upsertCalls == 1, "dns_binding_upsert_duplicate_binding_name_does_not_apply_provider");

  DeploymentPlan boundPlan = {};
  boundPlan.config.applicationID = set.applicationID;
  boundPlan.config.versionID = 1;
  boundPlan.config.architecture = nametagCurrentBuildMachineArchitecture();
  boundPlan.config.filesystemMB = 64;
  boundPlan.config.storageMB = 64;
  boundPlan.config.memoryMB = 128;
  boundPlan.config.nLogicalCores = 1;
  boundPlan.stateless.nBase = 1;
  boundPlan.stateless.maxPerRackRatio = 1.0f;
  boundPlan.stateless.maxPerMachineRatio = 1.0f;
  Wormhole boundWormhole = {};
  boundWormhole.name = "api"_ctv;
  boundWormhole.externalPort = 443;
  boundWormhole.containerPort = 8443;
  boundWormhole.layer4 = IPPROTO_TCP;
  boundWormhole.hasDNSConfig = true;
  boundWormhole.dns.bindingName = "api-binding"_ctv;
  boundPlan.wormholes.push_back(boundWormhole);
  Machine machine = {};
  machine.uuid = uint128_t(0xDDBB02);
  machine.state = MachineState::healthy;
  machine.lifetime = MachineLifetime::ondemand;
  machine.hardware.cpu.architecture = boundPlan.config.architecture;
  machine.nLogicalCores_available = 2;
  machine.memoryMB_available = 4096;
  machine.storageMB_available = 65'536;
  Rack rack = {};
  rack.uuid = 1;
  machine.rackUUID = rack.uuid;
  machine.rack = &rack;
  rack.machines.insert(&machine);
  brain.racks.insert_or_assign(rack.uuid, &rack);
  brain.machines.insert(&machine);
  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  String measureBuffer = {};
  uint32_t measureHeader = Message::appendHeader(measureBuffer, MothershipTopic::measureApplication);
  String serializedPlan = {};
  BitseryEngine::serialize(serializedPlan, boundPlan);
  Message::appendValue(measureBuffer, serializedPlan);
  Message::finish(measureBuffer, measureHeader);
  mothership.wBuffer.clear();
  brain.mothershipHandler(&mothership, reinterpret_cast<Message *>(measureBuffer.data()));
  responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
  suite.expect(MothershipTopic(responseMessage->topic) == MothershipTopic::measureApplication, "measure_application_dns_binding_topic");
  responseArgs = responseMessage->args;
  uint32_t nBase = 0;
  uint32_t nSurge = 0;
  uint32_t nFit = 0;
  Message::extractArg<ArgumentNature::fixed>(responseArgs, nBase);
  Message::extractArg<ArgumentNature::fixed>(responseArgs, nSurge);
  Message::extractArg<ArgumentNature::fixed>(responseArgs, nFit);
  suite.expect(nBase == 1, "measure_application_dns_binding_base_target");
  suite.expect(nSurge == 0, "measure_application_dns_binding_surge_target");
  suite.expect(nFit >= 1, "measure_application_resolves_wormhole_dns_binding");
  thisBrain = previousBrain;
  brain.machines.erase(&machine);
  brain.racks.erase(rack.uuid);

  String failure = {};
  suite.expect(brain.resolveDeploymentWormholeDNSBinding(boundPlan, boundPlan.wormholes[0], failure), "wormhole_dns_binding_resolves_existing_binding");
  suite.expect(boundPlan.wormholes[0].source == ExternalAddressSource::registeredRoutablePrefix, "wormhole_dns_binding_sets_registered_prefix_source");
  suite.expect(boundPlan.wormholes[0].routablePrefixUUID == prefix.uuid, "wormhole_dns_binding_sets_prefix_uuid");
  suite.expect(boundPlan.wormholes[0].externalAddress.equals(IPAddress("203.0.113.77", false)), "wormhole_dns_binding_sets_address");
  suite.expect(boundPlan.wormholes[0].dns.provider.equal("cloudflare"_ctv) && boundPlan.wormholes[0].dns.name.equal("api.example.com."_ctv), "wormhole_dns_binding_copies_record_config");
  suite.expect(brain.validateDeploymentWormholeDNSConfig(boundPlan, boundPlan.wormholes[0], failure), "wormhole_dns_binding_validates_resolved_config");
  suite.expect(brain.reserveDeploymentWormholeAddressLeases(boundPlan, failure, true), "wormhole_dns_binding_reuses_owned_leases");
  suite.expect(brain.routableResourceLeaseRuntimeState.size() == 2, "wormhole_dns_binding_does_not_duplicate_leases");
  suite.expect(dns.upsertCalls == 1, "wormhole_dns_binding_does_not_reapply_provider_record");

  DeploymentPlan conflictingPlan = boundPlan;
  conflictingPlan.wormholes[0] = boundWormhole;
  conflictingPlan.wormholes[0].dns.name = "other.example.com."_ctv;
  suite.expect(brain.resolveDeploymentWormholeDNSBinding(conflictingPlan, conflictingPlan.wormholes[0], failure) == false, "wormhole_dns_binding_rejects_inline_conflict");
  suite.expect(failure.equal("wormhole DNS binding config conflicts with binding"_ctv), "wormhole_dns_binding_inline_conflict_text");

  mothership.wBuffer.clear();
  messageBuffer.clear();
  message = buildMothershipMessage(messageBuffer, MothershipTopic::pullDNSBindings);
  brain.mothershipHandler(&mothership, message);
  responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
  suite.expect(MothershipTopic(responseMessage->topic) == MothershipTopic::pullDNSBindings, "mothership_pull_dns_bindings_topic");
  responseArgs = responseMessage->args;
  Message::extractToStringView(responseArgs, serializedResponse);
  suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_pull_dns_bindings_deserializes_response");
  suite.expect(response.success && response.leases.size() == 1 && response.leases[0].kind == RoutableResourceLeaseKind::dnsRecord, "mothership_pull_dns_bindings_filters_dns_leases");

  RoutableResourceLease deletion = {};
  deletion.dnsProvider = "cloudflare"_ctv;
  deletion.dnsZone = "example.com"_ctv;
  deletion.dnsName = "api.example.com"_ctv;
  deletion.dnsType = "A"_ctv;
  auto sendDeleteBinding = [&]() -> bool {
    request.leases.clear();
    request.leases.push_back(deletion);
    serializedRequest.clear();
    BitseryEngine::serialize(serializedRequest, request);
    mothership.wBuffer.clear();
    messageBuffer.clear();
    message = buildMothershipMessage(messageBuffer, MothershipTopic::deleteDNSBinding, serializedRequest);
    brain.mothershipHandler(&mothership, message);
    responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
    responseArgs = responseMessage->args;
    Message::extractToStringView(responseArgs, serializedResponse);
    response = {};
    return MothershipTopic(responseMessage->topic) == MothershipTopic::deleteDNSBinding && BitseryEngine::deserializeSafe(serializedResponse, response);
  };

  ApplicationDeployment liveDeployment = {};
  liveDeployment.plan = boundPlan;
  brain.deployments.insert_or_assign(boundPlan.config.deploymentID(), &liveDeployment);
  suite.expect(sendDeleteBinding(), "mothership_delete_dns_binding_in_use_deserializes_response");
  suite.expect(response.success == false, "mothership_delete_dns_binding_rejects_live_deployment");
  suite.expect(response.failure.equal("DNS binding is in use"_ctv), "mothership_delete_dns_binding_in_use_failure_text");
  suite.expect(dns.removeCalls == 0, "mothership_delete_dns_binding_in_use_does_not_remove_provider_record");
  suite.expect(brain.routableResourceLeaseRuntimeState.size() == 2, "mothership_delete_dns_binding_in_use_keeps_leases");
  brain.deployments.erase(boundPlan.config.deploymentID());

  suite.expect(sendDeleteBinding(), "mothership_delete_dns_binding_deserializes_response");
  suite.expect(response.success, "mothership_delete_dns_binding_success");
  suite.expect(dns.removeCalls == 1, "mothership_delete_dns_binding_removes_provider_record");
  suite.expect(brain.routableResourceLeaseRuntimeState.empty(), "mothership_delete_dns_binding_releases_address_and_dns_leases");

  DistributableExternalSubnet prefix6 = {};
  prefix6.uuid = uint128_t(0xDDBB06);
  prefix6.usage = ExternalSubnetUsage::wormholes;
  prefix6.ingressScope = RoutableIngressScope::switchboardFleet;
  prefix6.subnet = IPPrefix("2001:db8:113::", true, 64);
  brain.brainConfig.distributableExternalSubnets.push_back(prefix6);

  RoutableResourceLease binding6 = binding;
  binding6.owner.name = "api-v6-binding"_ctv;
  binding6.registeredPrefixUUID = prefix6.uuid;
  binding6.address = IPAddress("2001:db8:113::77", true);
  binding6.dnsName = "v6.example.com."_ctv;
  binding6.dnsType = "AAAA"_ctv;
  RoutableResourceLeaseReport response6 = {};
  suite.expect(brain.upsertDNSBindingLease(binding6, response6), "dns_binding_upsert_aaaa_success");

  DeploymentPlan boundPlan6 = boundPlan;
  boundPlan6.config.versionID = 2;
  boundPlan6.wormholes[0] = boundWormhole;
  boundPlan6.wormholes[0].dns.bindingName = "api-v6-binding"_ctv;
  ApplicationDeployment liveDeployment6 = {};
  liveDeployment6.plan = boundPlan6;
  brain.deployments.insert_or_assign(boundPlan6.config.deploymentID(), &liveDeployment6);

  deletion.dnsName = "v6.example.com"_ctv;
  deletion.dnsType = "AAAA"_ctv;
  suite.expect(sendDeleteBinding(), "mothership_delete_dns_binding_aaaa_in_use_deserializes_response");
  suite.expect(response.success == false, "mothership_delete_dns_binding_aaaa_rejects_live_deployment");
  suite.expect(response.failure.equal("DNS binding is in use"_ctv), "mothership_delete_dns_binding_aaaa_in_use_failure_text");
  suite.expect(dns.removeCalls == 1, "mothership_delete_dns_binding_aaaa_in_use_does_not_remove_provider_record");

  mothership.wBuffer.clear();
  messageBuffer.clear();
  message = buildMothershipMessage(messageBuffer, MothershipTopic::teardownDNSBindings);
  brain.mothershipHandler(&mothership, message);
  responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
  suite.expect(MothershipTopic(responseMessage->topic) == MothershipTopic::teardownDNSBindings, "mothership_teardown_dns_bindings_topic");
  responseArgs = responseMessage->args;
  Message::extractToStringView(responseArgs, serializedResponse);
  response = {};
  suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_teardown_dns_bindings_deserializes_response");
  suite.expect(response.success, "mothership_teardown_dns_bindings_success");
  suite.expect(response.leases.size() == 1 && response.leases[0].dnsType.equal("AAAA"_ctv), "mothership_teardown_dns_bindings_reports_aaaa");
  suite.expect(dns.removeCalls == 2, "mothership_teardown_dns_bindings_removes_provider_record");
  suite.expect(dns.removes.size() == 2 && dns.removes[1].type.equal("AAAA"_ctv) && dns.removes[1].values.size() == 1 && dns.removes[1].values[0].equal("2001:db8:113::77"_ctv), "mothership_teardown_dns_bindings_removes_aaaa_value");
  suite.expect(brain.routableResourceLeaseRuntimeState.empty(), "mothership_teardown_dns_bindings_releases_aaaa_address_and_dns_leases");
  brain.deployments.erase(boundPlan6.config.deploymentID());
}

static void testACMEDNS01ChallengeTopicsUsePublicTlsState(TestSuite& suite)
{
  TestBrain brain;
  Mothership mothership;
  TestDNSProvider dns;
  brain.weAreMaster = true;
  brain.brainConfig.clusterUUID = uint128_t(0xAC702);
  brain.dnsProvider = &dns;
  brain.brainConfig.dnsProvider = "cloudflare"_ctv;

  ApplicationApiCredentialSet set = {};
  set.applicationID = 702;
  ApiCredential credential = {};
  credential.name = "cf-prod"_ctv;
  credential.provider = "cloudflare"_ctv;
  credential.material = "secret"_ctv;
  credential.metadata.insert_or_assign("dnsScope"_ctv, "native-zone"_ctv);
  credential.metadata.insert_or_assign("dnsZones"_ctv, "example.com"_ctv);
  credential.metadata.insert_or_assign("acmePropagationDelayMs"_ctv, "0"_ctv);
  set.credentials.push_back(credential);
  brain.apiCredentialSetsByApp[set.applicationID] = set;

  PublicTlsCertificateState certificate = {};
  certificate.spec.applicationID = set.applicationID;
  certificate.spec.deploymentID = 9001;
  certificate.spec.wormholeName = "api"_ctv;
  certificate.spec.identityName = "api-public"_ctv;
  certificate.spec.domains.push_back("*.example.com"_ctv);
  certificate.spec.dnsProvider = "cloudflare"_ctv;
  certificate.spec.dnsCredentialName = "cf-prod"_ctv;
  certificate.spec.dnsZone = "example.com"_ctv;
  certificate.spec.dnsTTL = 45;
  certificate.certbotCertName = "app702-api"_ctv;
  brain.masterAuthorityRuntimeState.publicTlsCertificates.push_back(certificate);
  ProdigyDNSRecordBinding delayRecord = {};
  delayRecord.ttl = certificate.spec.dnsTTL;
  ApiCredential defaultCredential = {};
  suite.expect(TestBrain::acmeDNSPropagationDelayMs(delayRecord, credential) == 0, "mothership_acme_present_dns01_test_uses_zero_propagation_delay");
  suite.expect(TestBrain::acmeDNSPropagationDelayMs(delayRecord, defaultCredential) == 45'000, "mothership_acme_present_dns01_default_delay_uses_ttl");
  String containmentFailure = {};
  ApiCredential exactCredential = credential;
  exactCredential.metadata.clear();
  exactCredential.metadata.insert_or_assign("dnsScope"_ctv, "native-exact"_ctv);
  exactCredential.metadata.insert_or_assign("dnsRecords"_ctv, "_acme-challenge.example.com."_ctv);
  suite.expect(TestBrain::acmeDNSCredentialAllowsRecord(exactCredential, "_acme-challenge.example.com."_ctv, containmentFailure), "mothership_acme_dns_scope_allows_native_exact");
  exactCredential.metadata.insert_or_assign("dnsScope"_ctv, "webhook-exact"_ctv);
  suite.expect(TestBrain::acmeDNSCredentialAllowsRecord(exactCredential, "_acme-challenge.example.com."_ctv, containmentFailure), "mothership_acme_dns_scope_allows_webhook_exact");
  exactCredential.metadata.clear();
  exactCredential.metadata.insert_or_assign("dnsScope"_ctv, "native-account"_ctv);
  suite.expect(TestBrain::acmeDNSCredentialAllowsRecord(exactCredential, "_acme-challenge.example.com."_ctv, containmentFailure) == false && containmentFailure.equal("ACME DNS native-account scope requires dnsAccountScopeAccepted=true"_ctv), "mothership_acme_dns_scope_rejects_unacknowledged_native_account");
  exactCredential.metadata.insert_or_assign("dnsAccountScopeAccepted"_ctv, "true"_ctv);
  suite.expect(TestBrain::acmeDNSCredentialAllowsRecord(exactCredential, "_acme-challenge.example.com."_ctv, containmentFailure), "mothership_acme_dns_scope_allows_native_account");

  AcmeDNS01ChallengeRequest request = {};
  request.clusterUUID = brain.brainConfig.clusterUUID;
  request.applicationID = set.applicationID;
  request.deploymentID = certificate.spec.deploymentID;
  request.wormholeName = "api"_ctv;
  request.certName = "app702-api"_ctv;
  request.identifier = "*.example.com"_ctv;
  request.validation = "token-1"_ctv;

  auto sendChallenge = [&](MothershipTopic topic, AcmeDNS01ChallengeResponse& response) -> bool {
    String serializedRequest = {};
    BitseryEngine::serialize(serializedRequest, request);
    String messageBuffer = {};
    Message *message = buildMothershipMessage(messageBuffer, topic, serializedRequest);
    mothership.wBuffer.clear();
    brain.mothershipHandler(&mothership, message);
    Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
    if (MothershipTopic(responseMessage->topic) != topic)
    {
      return false;
    }
    String serializedResponse = {};
    uint8_t *responseArgs = responseMessage->args;
    Message::extractToStringView(responseArgs, serializedResponse);
    return BitseryEngine::deserializeSafe(serializedResponse, response);
  };

  AcmeDNS01ChallengeResponse response = {};
  suite.expect(sendChallenge(MothershipTopic::presentACMEDNS01Challenge, response), "mothership_acme_present_dns01_deserializes_response");
  suite.expect(response.success, "mothership_acme_present_dns01_success");
  suite.expect(dns.presentTXTCalls == 1, "mothership_acme_present_dns01_calls_provider");
  suite.expect(dns.presentedTXT.size() == 1 && dns.presentedTXT[0].name.equal("_acme-challenge.example.com."_ctv), "mothership_acme_present_dns01_canonicalizes_wildcard");
  suite.expect(dns.presentedTXT.size() == 1 && dns.presentedTXT[0].type.equal("TXT"_ctv) && dns.presentedTXT[0].values.size() == 1 && dns.presentedTXT[0].values[0].equal("token-1"_ctv), "mothership_acme_present_dns01_uses_exact_txt_value");
  suite.expect(dns.presentedTXT.size() == 1 && dns.presentedTXT[0].ttl == 45, "mothership_acme_present_dns01_uses_certificate_ttl");
  suite.expect(dns.activeTXT.size() == 1 && dns.activeTXT[0].values[0].equal("token-1"_ctv), "mothership_acme_present_dns01_tracks_first_txt_value");
  suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates[0].pendingDNS01Challenges.size() == 1, "mothership_acme_present_dns01_records_pending_value");
  suite.expect(brain.routableResourceLeaseRuntimeState.empty(), "mothership_acme_present_dns01_does_not_create_routable_lease");

  request.validation = "token-2"_ctv;
  response = {};
  suite.expect(sendChallenge(MothershipTopic::presentACMEDNS01Challenge, response), "mothership_acme_present_dns01_second_value_response");
  suite.expect(response.success, "mothership_acme_present_dns01_second_value_success");
  suite.expect(dns.activeTXT.size() == 2, "mothership_acme_present_dns01_preserves_simultaneous_values");
  suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates[0].pendingDNS01Challenges.size() == 2, "mothership_acme_present_dns01_records_second_pending_value");

  request.validation = "token-1"_ctv;
  response = {};
  suite.expect(sendChallenge(MothershipTopic::cleanupACMEDNS01Challenge, response), "mothership_acme_cleanup_dns01_deserializes_response");
  suite.expect(response.success, "mothership_acme_cleanup_dns01_success");
  suite.expect(dns.cleanupTXTCalls == 1 && dns.cleanedTXT.size() == 1 && dns.cleanedTXT[0].name.equal("_acme-challenge.example.com."_ctv), "mothership_acme_cleanup_dns01_removes_exact_name");
  suite.expect(dns.activeTXT.size() == 1 && dns.activeTXT[0].values[0].equal("token-2"_ctv), "mothership_acme_cleanup_dns01_preserves_other_value");
  suite.expect(brain.masterAuthorityRuntimeState.publicTlsCertificates[0].pendingDNS01Challenges.size() == 1 && brain.masterAuthorityRuntimeState.publicTlsCertificates[0].pendingDNS01Challenges[0].validation.equal("token-2"_ctv), "mothership_acme_cleanup_dns01_forgets_only_exact_value");
  suite.expect(brain.routableResourceLeaseRuntimeState.empty(), "mothership_acme_cleanup_dns01_does_not_create_routable_lease");

  brain.apiCredentialSetsByApp[set.applicationID].credentials[0].metadata.insert_or_assign("dnsZones"_ctv, "example.net"_ctv);
  response = {};
  suite.expect(sendChallenge(MothershipTopic::presentACMEDNS01Challenge, response), "mothership_acme_present_dns01_rejects_out_of_scope_credential_response");
  suite.expect(response.success == false && response.failure.equal("ACME DNS credential does not cover challenge zone"_ctv), "mothership_acme_present_dns01_rejects_out_of_scope_credential");
  suite.expect(dns.presentTXTCalls == 2, "mothership_acme_present_dns01_out_of_scope_skips_provider");

  request.identifier = "evil.example.net"_ctv;
  response = {};
  suite.expect(sendChallenge(MothershipTopic::presentACMEDNS01Challenge, response), "mothership_acme_present_dns01_rejects_wrong_domain_response");
  suite.expect(response.success == false && response.failure.equal("ACME identifier is not in certificate domains"_ctv), "mothership_acme_present_dns01_rejects_wrong_domain");
  suite.expect(dns.presentTXTCalls == 2, "mothership_acme_present_dns01_wrong_domain_skips_provider");

  brain.apiCredentialSetsByApp[set.applicationID].credentials[0].metadata.insert_or_assign("dnsZones"_ctv, "example.com"_ctv);
  request.identifier = "*.example.com"_ctv;
  request.clusterUUID = uint128_t(0xBAD702);
  response = {};
  suite.expect(sendChallenge(MothershipTopic::presentACMEDNS01Challenge, response), "mothership_acme_present_dns01_rejects_wrong_cluster_response");
  suite.expect(response.success == false && response.failure.equal("ACME hook cluster UUID mismatch"_ctv), "mothership_acme_present_dns01_rejects_wrong_cluster");
  suite.expect(dns.presentTXTCalls == 2, "mothership_acme_present_dns01_wrong_cluster_skips_provider");
  request.clusterUUID = brain.brainConfig.clusterUUID;
  suite.expect(brain.releasePublicTlsCertificatesForDeployment(certificate.spec.deploymentID) == 1, "mothership_acme_release_removes_certificate_state");
  suite.expect(dns.cleanupTXTCalls == 2 && dns.cleanedTXT.back().values[0].equal("token-2"_ctv), "mothership_acme_release_cleans_pending_txt_value");
  suite.expect(dns.activeTXT.empty(), "mothership_acme_release_leaves_no_active_txt_values");
}

static void testACMELineageImportValidatesAndDistributesPublicTls(TestSuite& suite)
{
  ScopedTempDir temp;
  if (suite.require(temp.valid(), "mothership_acme_import_temp_dir") == false)
  {
    return;
  }

  Vector<String> domains = {};
  domains.push_back("api.example.com"_ctv);
  domains.push_back("*.example.com"_ctv);

  const char *certbotCertName = "app703-api";
  std::filesystem::path lineageDir = temp.path / "live" / certbotCertName;
  std::filesystem::create_directories(lineageDir);
  std::string lineagePath = lineageDir.string();
  String certPem = {};
  String keyPem = {};
  if (suite.require(generateACMELineage(lineageDir, domains, certPem, keyPem), "mothership_acme_import_generates_lineage") == false)
  {
    return;
  }

  TestBrain brain;
  Mothership mothership;
  brain.weAreMaster = true;
  brain.brainConfig.clusterUUID = uint128_t(0xAC703);

  DeploymentPlan plan = makeDeploymentPlan(703, 91);
  WormholePublicTLSConfig publicTLS = {};
  publicTLS.wormholeName = "api"_ctv;
  publicTLS.identityName = "api-public"_ctv;
  publicTLS.domains = domains;
  publicTLS.renewAfterLifetimePermille = 667;
  publicTLS.staging = true;
  plan.publicTLS.push_back(publicTLS);

  PublicTlsCertificateState certificate = {};
  certificate.spec.applicationID = plan.config.applicationID;
  certificate.spec.deploymentID = plan.config.deploymentID();
  certificate.spec.wormholeName = publicTLS.wormholeName;
  certificate.spec.identityName = publicTLS.identityName;
  certificate.spec.domains = domains;
  certificate.spec.issuer = "letsencrypt"_ctv;
  certificate.spec.keyType = "ecdsa"_ctv;
  certificate.spec.staging = publicTLS.staging;
  certificate.spec.renewAfterLifetimePermille = publicTLS.renewAfterLifetimePermille;
  certificate.certbotCertName.assign(certbotCertName);
  certificate.lineagePath.assign(lineagePath.data(), lineagePath.size());
  certificate.failureCount = 4;
  certificate.lastFailure = "previous acme failure"_ctv;
  brain.masterAuthorityRuntimeState.publicTlsCertificates.push_back(certificate);

  Machine machine = {};
  machine.uuid = uint128_t(0xAC703);
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 9;
  machine.neuron.connected = true;
  Machine secondMachine = {};
  secondMachine.uuid = uint128_t(0xAC705);
  secondMachine.neuron.isFixedFile = true;
  secondMachine.neuron.fslot = 10;
  secondMachine.neuron.connected = true;

  ContainerView container = {};
  container.uuid = uint128_t(0xAC704);
  container.machine = &machine;
  container.deploymentID = plan.config.deploymentID();
  container.state = ContainerState::healthy;
  ContainerView secondContainer = {};
  secondContainer.uuid = uint128_t(0xAC706);
  secondContainer.machine = &secondMachine;
  secondContainer.deploymentID = plan.config.deploymentID();
  secondContainer.state = ContainerState::healthy;

  ApplicationDeployment deployment = {};
  deployment.plan = plan;
  deployment.containers.insert(&container);
  deployment.containers.insert(&secondContainer);
  brain.deployments.insert_or_assign(plan.config.deploymentID(), &deployment);

  AcmeLineageImportRequest request = {};
  request.clusterUUID = brain.brainConfig.clusterUUID;
  request.applicationID = plan.config.applicationID;
  request.deploymentID = plan.config.deploymentID();
  request.wormholeName = publicTLS.wormholeName;
  request.certName = certificate.certbotCertName;
  request.lineagePath.assign(lineagePath.data(), lineagePath.size());
  request.renewedDomains = domains;

  String serializedRequest = {};
  BitseryEngine::serialize(serializedRequest, request);
  String messageBuffer = {};
  Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::importACMELineage, serializedRequest);
  brain.mothershipHandler(&mothership, message);

  Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
  String serializedResponse = {};
  uint8_t *responseArgs = responseMessage->args;
  Message::extractToStringView(responseArgs, serializedResponse);
  AcmeLineageImportResponse response = {};
  suite.expect(MothershipTopic(responseMessage->topic) == MothershipTopic::importACMELineage, "mothership_acme_import_response_topic");
  suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_acme_import_deserializes_response");
  suite.expect(response.success, "mothership_acme_import_success");

  const PublicTlsCertificateState& stored = brain.masterAuthorityRuntimeState.publicTlsCertificates[0];
  suite.expect(stored.identity.name.equal("api-public"_ctv), "mothership_acme_import_sets_identity_name");
  suite.expect(stored.identity.certPem.equals(certPem), "mothership_acme_import_stores_leaf_cert");
  suite.expect(stored.identity.keyPem.equals(keyPem), "mothership_acme_import_stores_private_key");
  suite.expect(stored.identity.chainPem.size() > certPem.size(), "mothership_acme_import_stores_chain");
  suite.expect(stored.identity.dnsSans.size() == 2 && stored.identity.dnsSans[0].equal("api.example.com"_ctv) && stored.identity.dnsSans[1].equal("*.example.com"_ctv), "mothership_acme_import_stores_dns_sans");
  suite.expect(stringVectorContains(stored.identity.tags, "public"_ctv) && stringVectorContains(stored.identity.tags, "letsencrypt"_ctv) && stringVectorContains(stored.identity.tags, "wormhole:api"_ctv), "mothership_acme_import_tags_public_identity");
  suite.expect(stored.identity.notAfterMs > stored.identity.notBeforeMs, "mothership_acme_import_stores_lifetime");
  suite.expect(stored.nextRenewAtMs > stored.identity.notBeforeMs && stored.nextRenewAtMs < stored.identity.notAfterMs, "mothership_acme_import_sets_next_renewal");
  suite.expect(response.generation == stored.identity.generation && stored.generation == stored.identity.generation, "mothership_acme_import_generation_matches_identity");
  suite.expect(stored.lastSuccessMs == stored.lastAttemptMs && stored.lastFailure.size() == 0, "mothership_acme_import_records_success");
  suite.expect(stored.failureCount == 0, "mothership_acme_import_clears_failure_count");
  suite.expect(brain.persistCalls >= 1, "mothership_acme_import_persists_runtime_state");

  uint128_t refreshedContainer = 0;
  CredentialDelta delta = {};
  suite.expect(extractQueuedCredentialDelta(machine, refreshedContainer, delta), "mothership_acme_import_queues_tls_delta");
  suite.expect(refreshedContainer == container.uuid, "mothership_acme_import_delta_targets_container");
  suite.expect(delta.updatedTls.size() == 1 && delta.updatedTls[0].keyPem.equals(keyPem), "mothership_acme_import_delta_carries_same_key");
  suite.expect(delta.bundleGeneration == stored.identity.generation && delta.updatedTls[0].generation == stored.identity.generation, "mothership_acme_import_delta_generation_tracks_identity");
  uint128_t secondRefreshedContainer = 0;
  CredentialDelta secondDelta = {};
  suite.expect(extractQueuedCredentialDelta(secondMachine, secondRefreshedContainer, secondDelta), "mothership_acme_import_queues_second_tls_delta");
  suite.expect(secondRefreshedContainer == secondContainer.uuid && secondDelta.updatedTls.size() == 1 && secondDelta.updatedTls[0].keyPem.equals(keyPem) && secondDelta.updatedTls[0].generation == delta.updatedTls[0].generation, "mothership_acme_import_delta_carries_same_key_to_every_container");
  suite.expect(secondDelta.bundleGeneration == stored.identity.generation, "mothership_acme_import_second_delta_generation_tracks_identity");

  CredentialBundle startupBundle = {};
  ContainerView startupContainer = {};
  suite.expect(brain.buildCredentialBundleForContainer(plan, startupContainer, startupBundle), "mothership_acme_import_startup_bundle_builds");
  suite.expect(startupBundle.tlsIdentities.size() == 1 && startupBundle.tlsIdentities[0].keyPem.equals(keyPem), "mothership_acme_import_startup_bundle_carries_public_tls");
  suite.expect(startupBundle.bundleGeneration == stored.identity.generation, "mothership_acme_import_startup_bundle_generation_tracks_identity");

  uint64_t firstGeneration = stored.identity.generation;
  String renewedCertPem = {};
  String renewedKeyPem = {};
  suite.expect(generateACMELineage(lineageDir, domains, renewedCertPem, renewedKeyPem), "mothership_acme_import_generates_renewed_lineage");
  machine.neuron.wBuffer.clear();
  secondMachine.neuron.wBuffer.clear();
  AcmeLineageImportResponse renewedResponse = {};
  suite.expect(brain.importACMELineage(request, renewedResponse), "mothership_acme_import_renewal_success");
  const PublicTlsCertificateState& renewedStored = brain.masterAuthorityRuntimeState.publicTlsCertificates[0];
  suite.expect(renewedResponse.generation == firstGeneration + 1 && renewedStored.identity.generation == renewedResponse.generation && renewedStored.generation == renewedResponse.generation, "mothership_acme_import_renewal_increments_generation");
  suite.expect(renewedStored.identity.certPem.equals(renewedCertPem) && renewedStored.identity.keyPem.equals(renewedKeyPem), "mothership_acme_import_renewal_stores_new_lineage");
  suite.expect(extractQueuedCredentialDelta(machine, refreshedContainer, delta), "mothership_acme_import_renewal_queues_tls_delta");
  suite.expect(delta.updatedTls.size() == 1 && delta.updatedTls[0].generation == renewedResponse.generation && delta.updatedTls[0].keyPem.equals(renewedKeyPem) && delta.bundleGeneration == renewedResponse.generation, "mothership_acme_import_renewal_delta_tracks_generation");
  suite.expect(extractQueuedCredentialDelta(secondMachine, secondRefreshedContainer, secondDelta), "mothership_acme_import_renewal_queues_second_tls_delta");
  suite.expect(secondDelta.updatedTls.size() == 1 && secondDelta.updatedTls[0].generation == renewedResponse.generation && secondDelta.updatedTls[0].keyPem.equals(renewedKeyPem) && secondDelta.bundleGeneration == renewedResponse.generation, "mothership_acme_import_renewal_delta_reaches_every_container");
  startupBundle = {};
  suite.expect(brain.buildCredentialBundleForContainer(plan, startupContainer, startupBundle), "mothership_acme_import_renewal_startup_bundle_builds");
  suite.expect(startupBundle.tlsIdentities.size() == 1 && startupBundle.tlsIdentities[0].generation == renewedResponse.generation && startupBundle.tlsIdentities[0].keyPem.equals(renewedKeyPem) && startupBundle.bundleGeneration == renewedResponse.generation, "mothership_acme_import_renewal_startup_bundle_tracks_generation");

  auto directImportFails = [&](const std::filesystem::path& path, const String& expectedFailure, bool managedPath = false) -> bool {
    TestBrain importBrain;
    importBrain.brainConfig.clusterUUID = brain.brainConfig.clusterUUID;
    importBrain.masterAuthorityRuntimeState.publicTlsCertificates.push_back(certificate);
    AcmeLineageImportRequest invalidRequest = request;
    std::string invalidLineagePath = path.string();
    invalidRequest.lineagePath.assign(invalidLineagePath.data(), invalidLineagePath.size());
    if (managedPath)
    {
      importBrain.masterAuthorityRuntimeState.publicTlsCertificates[0].lineagePath = invalidRequest.lineagePath;
    }
    AcmeLineageImportResponse invalidResponse = {};
    return importBrain.importACMELineage(invalidRequest, invalidResponse) == false && invalidResponse.failure.equal(expectedFailure);
  };

  suite.expect(directImportFails(temp.path, "ACME lineage path is not managed by this cluster"_ctv), "mothership_acme_import_rejects_unmanaged_lineage_path");
  AcmeLineageImportRequest wrongClusterRequest = request;
  wrongClusterRequest.clusterUUID = uint128_t(0xBAD703);
  AcmeLineageImportResponse wrongClusterResponse = {};
  suite.expect(brain.importACMELineage(wrongClusterRequest, wrongClusterResponse) == false && wrongClusterResponse.failure.equal("ACME hook cluster UUID mismatch"_ctv), "mothership_acme_import_rejects_wrong_cluster");

  PublicTlsCertificateState nonStagingCertificate = certificate;
  nonStagingCertificate.spec.staging = false;
  TestBrain nonStagingBrain;
  nonStagingBrain.brainConfig.clusterUUID = brain.brainConfig.clusterUUID;
  nonStagingBrain.masterAuthorityRuntimeState.publicTlsCertificates.push_back(nonStagingCertificate);
  AcmeLineageImportResponse nonStagingResponse = {};
  suite.expect(nonStagingBrain.importACMELineage(request, nonStagingResponse) == false && nonStagingResponse.failure.equal("ACME certificate chain is not trusted"_ctv), "mothership_acme_import_rejects_untrusted_non_staging_chain");

  ScopedTempDir ipTemp;
  Vector<IPAddress> ipSans = {};
  ipSans.push_back(IPAddress("203.0.113.70", false));
  String ignoredCert = {};
  String ignoredKey = {};
  String wrongChain = {};
  ScopedTempDir chainTemp;
  ScopedTempDir invalidChainTemp;
  std::filesystem::path chainDir = chainTemp.path / "live" / certbotCertName;
  std::filesystem::path invalidChainDir = invalidChainTemp.path / "live" / certbotCertName;
  std::filesystem::create_directories(chainDir);
  std::filesystem::create_directories(invalidChainDir);
  suite.expect(chainTemp.valid() && invalidChainTemp.valid() && generateACMELineage(chainDir, domains, ignoredCert, ignoredKey, nullptr, true, &wrongChain), "mothership_acme_import_generates_wrong_chain_lineage");
  String invalidFullchain = certPem;
  invalidFullchain.append(wrongChain);
  suite.expect(writeTextFile(invalidChainDir / "fullchain.pem", toStdString(invalidFullchain)) && writeTextFile(invalidChainDir / "privkey.pem", toStdString(keyPem)), "mothership_acme_import_writes_invalid_chain_lineage");
  suite.expect(directImportFails(invalidChainDir, "ACME certificate chain is invalid"_ctv, true), "mothership_acme_import_rejects_invalid_chain");

  std::filesystem::path ipDir = ipTemp.path / "live" / certbotCertName;
  std::filesystem::create_directories(ipDir);
  suite.expect(ipTemp.valid() && generateACMELineage(ipDir, domains, ignoredCert, ignoredKey, &ipSans), "mothership_acme_import_generates_ip_san_lineage");
  suite.expect(directImportFails(ipDir, "ACME certificate contains unexpected IP SANs"_ctv, true), "mothership_acme_import_rejects_ip_sans");

  ScopedTempDir ekuTemp;
  ignoredCert.clear();
  ignoredKey.clear();
  std::filesystem::path ekuDir = ekuTemp.path / "live" / certbotCertName;
  std::filesystem::create_directories(ekuDir);
  suite.expect(ekuTemp.valid() && generateACMELineage(ekuDir, domains, ignoredCert, ignoredKey, nullptr, false), "mothership_acme_import_generates_no_server_auth_lineage");
  suite.expect(directImportFails(ekuDir, "ACME certificate is not valid for server authentication"_ctv, true), "mothership_acme_import_rejects_missing_server_auth");
}

static PublicTlsCertificateState makePublicTlsAckTestCertificate(const DeploymentPlan& plan)
{
  PublicTlsCertificateState certificate = {};
  certificate.spec.applicationID = plan.config.applicationID;
  certificate.spec.deploymentID = plan.config.deploymentID();
  certificate.spec.wormholeName = "api"_ctv;
  certificate.spec.identityName = "api-public"_ctv;
  certificate.spec.domains.push_back("api.example.com"_ctv);
  certificate.spec.issuer = "letsencrypt"_ctv;
  certificate.spec.keyType = "ecdsa"_ctv;
  certificate.certbotCertName = "app704-api"_ctv;
  certificate.identity.name = certificate.spec.identityName;
  certificate.identity.generation = 3;
  certificate.identity.certPem = "cert-v3"_ctv;
  certificate.identity.keyPem = "key-v3"_ctv;
  certificate.identity.chainPem = "chain-v3"_ctv;
  certificate.identity.dnsSans = certificate.spec.domains;
  return certificate;
}

static void testTlsIdentityAckAndStaleState(TestSuite& suite)
{
  TestBrain brain = {};
  brain.weAreMaster = true;

  DeploymentPlan plan = makeDeploymentPlan(704, 11);
  WormholePublicTLSConfig publicTLS = {};
  publicTLS.wormholeName = "api"_ctv;
  publicTLS.identityName = "api-public"_ctv;
  publicTLS.domains.push_back("api.example.com"_ctv);
  plan.publicTLS.push_back(publicTLS);

  PublicTlsCertificateState certificate = makePublicTlsAckTestCertificate(plan);
  brain.masterAuthorityRuntimeState.publicTlsCertificates.push_back(certificate);

  Machine machine = {};
  machine.uuid = uint128_t(0x7041);
  machine.private4 = 0x0A000041;
  machine.fragment = 0x1241;
  machine.state = MachineState::healthy;
  machine.runtimeReady = true;
  machine.neuron.machine = &machine;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 41;
  machine.neuron.connected = true;

  ContainerView container = {};
  container.uuid = uint128_t(0x7042);
  container.machine = &machine;
  container.deploymentID = plan.config.deploymentID();
  container.applicationID = plan.config.applicationID;
  container.lifetime = ApplicationLifetime::base;
  container.state = ContainerState::healthy;
  container.fragment = 2;
  container.createdAtMs = 123'704;

  ApplicationDeployment deployment = {};
  deployment.plan = plan;
  deployment.containers.insert(&container);
  brain.deployments.insert_or_assign(plan.config.deploymentID(), &deployment);
  brain.containers.insert_or_assign(container.uuid, &container);

  String failure = {};
  suite.expect(brain.tlsIdentityCoverageSatisfied(plan, &failure) == false, "tls_identity_freshness_missing_before_push");
  suite.expect(failure.size() > 0, "tls_identity_freshness_missing_reports_failure");

  TlsIdentity oldIdentity = certificate.identity;
  oldIdentity.generation -= 1;
  container.hasCredentialBundle = true;
  container.credentialBundle.bundleGeneration = 99;
  container.credentialBundle.tlsIdentities.push_back(oldIdentity);

  suite.expect(brain.pushPublicTlsIdentityDeltaToLiveContainers(brain.masterAuthorityRuntimeState.publicTlsCertificates[0], "unit-test"_ctv) == 1, "tls_identity_freshness_pushes_public_delta");
  suite.expect(container.hasPendingCredentialBundle, "tls_identity_freshness_records_pending_bundle");
  uint128_t refreshedContainer = 0;
  CredentialDelta pushedDelta = {};
  suite.expect(extractQueuedCredentialDelta(machine, refreshedContainer, pushedDelta) && refreshedContainer == container.uuid && pushedDelta.bundleGeneration == 99 && container.pendingCredentialBundle.bundleGeneration == 99, "tls_identity_freshness_preserves_bundle_generation");
  suite.expect(container.credentialBundle.tlsIdentities.size() == 1 && container.credentialBundle.tlsIdentities[0].generation == oldIdentity.generation, "tls_identity_freshness_keeps_old_generation_until_ack");
  bool pending = false;
  suite.expect(brain.containerTlsIdentitiesFresh(plan, container, &pending, nullptr) == false && pending, "tls_identity_freshness_pending_until_ack");

  DeploymentStatusReport report = deployment.generateReport();
  brain.summarizeDeploymentTlsIdentityFreshness(&deployment, report);
  suite.expect(report.nTlsIdentityExpected == 1 && report.nTlsIdentityStale == 1 && report.nTlsIdentityPending == 1, "tls_identity_freshness_report_counts_pending_stale");

  container.pendingCredentialBundleSinceMs = Time::now<TimeResolution::ms>() - TestBrain::credentialDeltaAckTimeoutMs - 1;
  report = deployment.generateReport();
  brain.summarizeDeploymentTlsIdentityFreshness(&deployment, report);
  suite.expect(report.nTlsIdentityExpected == 1 && report.nTlsIdentityStale == 1 && report.nTlsIdentityPending == 0, "tls_identity_freshness_pending_expires_to_stale");
  machine.neuron.wBuffer.clear();
  suite.expect(brain.retryStaleTlsIdentityDeltas() == 1, "tls_identity_freshness_retries_expired_pending");
  suite.expect(container.hasPendingCredentialBundle && container.pendingCredentialBundleSinceMs > 0, "tls_identity_freshness_retry_records_new_pending");

  CredentialApplyAck rejectedAck = {};
  TlsIdentityApplyResult tlsApply = {};
  tlsApply.identityName = certificate.identity.name;
  tlsApply.generation = certificate.identity.generation;
  tlsApply.success = false;
  tlsApply.failureReason = "application rejected TLS identity"_ctv;
  rejectedAck.tlsResults.push_back(tlsApply);
  suite.expect(brain.noteContainerCredentialApplyAck(container.uuid, rejectedAck) == false, "tls_identity_freshness_typed_reject_does_not_promote");
  suite.expect(container.hasPendingCredentialBundle == false && container.credentialRefreshFailure.equal("application rejected TLS identity"_ctv), "tls_identity_freshness_typed_reject_records_failure");
  suite.expect(container.credentialBundle.tlsIdentities.size() == 1 && container.credentialBundle.tlsIdentities[0].generation == oldIdentity.generation, "tls_identity_freshness_typed_reject_preserves_old_generation");
  pending = false;
  suite.expect(brain.containerTlsIdentitiesFresh(plan, container, &pending, nullptr) == false && pending == false, "tls_identity_freshness_rejected_is_stale_not_pending");

  machine.neuron.wBuffer.clear();
  suite.expect(brain.retryStaleTlsIdentityDeltas() == 1, "tls_identity_freshness_retries_after_typed_reject");
  tlsApply.success = true;
  tlsApply.failureReason.clear();
  CredentialApplyAck acceptedAck = {};
  acceptedAck.tlsResults.push_back(tlsApply);
  suite.expect(brain.noteContainerCredentialApplyAck(container.uuid, acceptedAck), "tls_identity_freshness_typed_ack_promotes_pending");
  suite.expect(container.hasPendingCredentialBundle == false && container.hasCredentialBundle, "tls_identity_freshness_ack_clears_pending");
  suite.expect(container.credentialRefreshFailure.size() == 0, "tls_identity_freshness_typed_ack_clears_failure");
  suite.expect(brain.tlsIdentityCoverageSatisfied(plan, &failure), "tls_identity_freshness_satisfied_after_ack");

  report = deployment.generateReport();
  brain.summarizeDeploymentTlsIdentityFreshness(&deployment, report);
  suite.expect(report.nTlsIdentityExpected == 1 && report.nTlsIdentityFresh == 1 && report.nTlsIdentityStale == 0 && report.nTlsIdentityPending == 0, "tls_identity_freshness_report_counts_fresh");

  container.hasCredentialBundle = false;
  container.credentialBundle = {};
  ContainerPlan uploadedPlan = container.generatePlan(plan);
  uploadedPlan.hasCredentialBundle = true;
  uploadedPlan.credentialBundle.tlsIdentities.push_back(certificate.identity);

  String uploadBuffer = {};
  uint32_t headerOffset = Message::appendHeader(uploadBuffer, NeuronTopic::stateUpload);
  local_container_subnet6 fragment = {};
  fragment.dpfx = 1;
  fragment.mpfx[0] = 0x00;
  fragment.mpfx[1] = 0x12;
  fragment.mpfx[2] = 0x41;
  Message::appendAlignedBuffer<Alignment::one>(uploadBuffer, reinterpret_cast<const uint8_t *>(&fragment), sizeof(fragment));
  String serializedPlan = {};
  BitseryEngine::serialize(serializedPlan, uploadedPlan);
  Message::appendValue(uploadBuffer, serializedPlan);
  Message::finish(uploadBuffer, headerOffset);

  Message *message = reinterpret_cast<Message *>(uploadBuffer.data());
  brain.neuronHandler(&machine.neuron, message);
  suite.expect(container.hasCredentialBundle && container.credentialBundle.tlsIdentities.size() == 1, "tls_identity_freshness_state_upload_restores_bundle");
  suite.expect(brain.tlsIdentityCoverageSatisfied(plan, &failure), "tls_identity_freshness_state_upload_satisfies_coverage");
}

static void testApplicationIdentityInvariants(TestSuite& suite)
{
  TestBrain brain;

  String reserveFailure;
  suite.expect(brain.reserveApplicationIDMapping("AppIdentityA"_ctv, 51'000, &reserveFailure), "reservation_accepts_new_name_id_pair");
  reserveFailure.clear();
  suite.expect(brain.reserveApplicationIDMapping("AppIdentityA"_ctv, 51'000, &reserveFailure), "reservation_accepts_existing_same_name_id_pair");
  reserveFailure.clear();
  suite.expect(brain.reserveApplicationIDMapping("AppIdentityA"_ctv, 51'001, &reserveFailure) == false, "reservation_rejects_name_with_different_id");
  reserveFailure.clear();
  suite.expect(brain.reserveApplicationIDMapping("AppIdentityB"_ctv, 51'000, &reserveFailure) == false, "reservation_rejects_id_with_different_name");
  reserveFailure.clear();

  ApplicationServiceIdentity clients;
  clients.applicationID = 51'000;
  clients.serviceName.assign("clients"_ctv);
  clients.serviceSlot = 1;
  clients.kind = ApplicationServiceIdentity::Kind::stateful;
  suite.expect(brain.reserveApplicationServiceMapping(clients, &reserveFailure), "service_reservation_accepts_new_shape");

  reserveFailure.clear();
  suite.expect(brain.reserveApplicationServiceMapping(clients, &reserveFailure), "service_reservation_accepts_existing_same_shape");

  ApplicationServiceIdentity clientsWrongSlot = clients;
  clientsWrongSlot.serviceSlot = 2;
  reserveFailure.clear();
  suite.expect(brain.reserveApplicationServiceMapping(clientsWrongSlot, &reserveFailure) == false, "service_reservation_rejects_same_name_different_slot");

  ApplicationServiceIdentity siblingsSameSlot = clients;
  siblingsSameSlot.serviceName.assign("siblings"_ctv);
  reserveFailure.clear();
  suite.expect(brain.reserveApplicationServiceMapping(siblingsSameSlot, &reserveFailure) == false, "service_reservation_rejects_same_slot_different_name");

  String dynamicApplicationNameBacking = {};
  dynamicApplicationNameBacking.assign("AppIdentityOwned"_ctv);
  String dynamicApplicationName = {};
  dynamicApplicationName.setInvariant(dynamicApplicationNameBacking.data(), dynamicApplicationNameBacking.size());
  reserveFailure.clear();
  suite.expect(brain.reserveApplicationIDMapping(dynamicApplicationName, 51'010, &reserveFailure), "reservation_owns_view_backed_application_name");
  auto dynamicReservationIt = brain.reservedApplicationIDsByName.find("AppIdentityOwned"_ctv);
  suite.expect(dynamicReservationIt != brain.reservedApplicationIDsByName.end(), "reservation_owns_view_backed_application_name_lookup");
  if (dynamicReservationIt != brain.reservedApplicationIDsByName.end())
  {
    suite.expect(dynamicReservationIt->first.isInvariant() == false, "reservation_owns_view_backed_application_name_key");
    suite.expect(dynamicReservationIt->second == 51'010, "reservation_owns_view_backed_application_name_value");
  }
  auto dynamicReservationNameIt = brain.reservedApplicationNamesByID.find(51'010);
  suite.expect(dynamicReservationNameIt != brain.reservedApplicationNamesByID.end(), "reservation_owns_view_backed_application_id_lookup");
  if (dynamicReservationNameIt != brain.reservedApplicationNamesByID.end())
  {
    suite.expect(dynamicReservationNameIt->second.isInvariant() == false, "reservation_owns_view_backed_application_name_value_string");
    suite.expect(dynamicReservationNameIt->second == "AppIdentityOwned"_ctv, "reservation_owns_view_backed_application_name_value_text");
  }

  String dynamicServiceNameBacking = {};
  dynamicServiceNameBacking.assign("dynamicclients"_ctv);
  ApplicationServiceIdentity dynamicService = {};
  dynamicService.applicationID = 51'010;
  dynamicService.serviceName.setInvariant(dynamicServiceNameBacking.data(), dynamicServiceNameBacking.size());
  dynamicService.serviceSlot = 4;
  dynamicService.kind = ApplicationServiceIdentity::Kind::stateful;
  reserveFailure.clear();
  suite.expect(brain.reserveApplicationServiceMapping(dynamicService, &reserveFailure), "service_reservation_owns_view_backed_service_name");
  auto dynamicServiceIt = brain.reservedApplicationServicesByID.find(Brain::materializeReservedService(dynamicService));
  suite.expect(dynamicServiceIt != brain.reservedApplicationServicesByID.end(), "service_reservation_owns_view_backed_service_lookup");
  if (dynamicServiceIt != brain.reservedApplicationServicesByID.end())
  {
    suite.expect(dynamicServiceIt->second.serviceName.isInvariant() == false, "service_reservation_owns_view_backed_service_name_value");
    suite.expect(dynamicServiceIt->second.serviceName == "dynamicclients"_ctv, "service_reservation_owns_view_backed_service_name_text");
  }
  String dynamicServiceNameKey = brain.makeReservedServiceNameKey(dynamicService.applicationID, "dynamicclients"_ctv);
  auto dynamicServiceNameIt = brain.reservedApplicationServicesByNameKey.find(dynamicServiceNameKey);
  suite.expect(dynamicServiceNameIt != brain.reservedApplicationServicesByNameKey.end(), "service_reservation_owns_view_backed_name_key_lookup");
  if (dynamicServiceNameIt != brain.reservedApplicationServicesByNameKey.end())
  {
    suite.expect(dynamicServiceNameIt->first == dynamicServiceNameKey, "service_reservation_owns_view_backed_name_key_text");
    suite.expect(dynamicServiceNameIt->first.isInvariant() == false, "service_reservation_owns_view_backed_name_key");
    suite.expect(dynamicServiceNameIt->second.serviceName.isInvariant() == false, "service_reservation_owns_view_backed_name_value");
  }
  auto dynamicServiceSlotIt = brain.reservedApplicationServiceNamesBySlotKey.find(Brain::makeReservedServiceSlotKey(dynamicService.applicationID, dynamicService.serviceSlot));
  suite.expect(dynamicServiceSlotIt != brain.reservedApplicationServiceNamesBySlotKey.end(), "service_reservation_owns_view_backed_slot_lookup");
  if (dynamicServiceSlotIt != brain.reservedApplicationServiceNamesBySlotKey.end())
  {
    suite.expect(dynamicServiceSlotIt->second.isInvariant() == false, "service_reservation_owns_view_backed_slot_name");
    suite.expect(dynamicServiceSlotIt->second == "dynamicclients"_ctv, "service_reservation_owns_view_backed_slot_name_text");
  }

  DeploymentPlan sameApplicationDifferentID;
  sameApplicationDifferentID.config.applicationID = 51'002;
  String identityFailure;
  suite.expect(brain.validateDeploymentApplicationIdentity(sameApplicationDifferentID, identityFailure), "deploy_identity_accepts_plan_without_binary_path");
  suite.expect(identityFailure.size() == 0, "deploy_identity_accepts_plan_without_binary_path_clears_failure");

  DeploymentPlan sameApplicationSameID;
  sameApplicationSameID.config.applicationID = 51'000;
  identityFailure.clear();
  suite.expect(brain.validateDeploymentApplicationIdentity(sameApplicationSameID, identityFailure), "deploy_identity_accepts_same_application_id_without_binary_path");
}

static void testApplicationReservationInitializersAndAllocators(TestSuite& suite)
{
  TestBrain brain;

  String reserveFailure;
  suite.expect(brain.reserveApplicationIDMapping("EphemeralApp"_ctv, 60'000, &reserveFailure), "reservation_initializer_seed_ephemeral_application");

  ApplicationServiceIdentity ephemeralService = {};
  ephemeralService.applicationID = 60'000;
  ephemeralService.serviceName.assign("clients"_ctv);
  ephemeralService.serviceSlot = 1;
  ephemeralService.kind = ApplicationServiceIdentity::Kind::stateful;
  reserveFailure.clear();
  suite.expect(brain.reserveApplicationServiceMapping(ephemeralService, &reserveFailure), "reservation_initializer_seed_ephemeral_service");

  brain.initializeApplicationIDReservationState();

  uint16_t reservedApplicationID = 0;
  suite.expect(brain.resolveReservedApplicationID("Hot"_ctv, reservedApplicationID), "reservation_initializer_restores_hot_application");
  suite.expect(reservedApplicationID == MeshRegistry::Hot::applicationID, "reservation_initializer_restores_hot_application_id");
  suite.expect(brain.resolveReservedApplicationID("EphemeralApp"_ctv, reservedApplicationID) == false, "reservation_initializer_clears_ephemeral_application");
  suite.expect(brain.takeNextReservableApplicationID() == 11, "reservation_initializer_next_application_id_starts_after_builtin_max");
  suite.expect(brain.takeNextReservableApplicationID() == 12, "reservation_initializer_next_application_id_advances");

  reserveFailure.clear();
  suite.expect(brain.reserveApplicationIDMapping("FreshStatefulApp"_ctv, 61'000, &reserveFailure), "reservation_initializer_seed_fresh_stateful_application");

  brain.initializeApplicationServiceReservationState();

  ApplicationServiceIdentity restoredHotClients = {};
  suite.expect(
      brain.resolveReservedApplicationService(MeshRegistry::Hot::applicationID, "clients"_ctv, restoredHotClients),
      "reservation_initializer_restores_hot_clients_service");
  suite.expect(restoredHotClients.serviceSlot == 1, "reservation_initializer_restores_hot_clients_slot");
  suite.expect(restoredHotClients.kind == ApplicationServiceIdentity::Kind::stateful, "reservation_initializer_restores_hot_clients_kind");
  suite.expect(brain.takeNextReservableServiceSlot(MeshRegistry::Hot::applicationID) == 6, "reservation_initializer_next_hot_slot_starts_after_builtin_range");
  suite.expect(brain.takeNextReservableServiceSlot(MeshRegistry::Telnyx::applicationID) == 2, "reservation_initializer_next_telnyx_slot_starts_after_builtin_client");
  suite.expect(brain.takeNextReservableServiceSlot(61'000) == 1, "reservation_initializer_fresh_application_service_slot_starts_at_one");
}

static void testApplicationReservationValidationFailures(TestSuite& suite)
{
  TestBrain brain;
  String reserveFailure;

  suite.expect(brain.reserveApplicationIDMapping("ZeroApplication"_ctv, 0, &reserveFailure) == false, "reservation_rejects_zero_application_id");
  suite.expect(reserveFailure.equals("applicationID invalid"_ctv), "reservation_rejects_zero_application_id_reason");

  reserveFailure.clear();
  suite.expect(brain.reserveApplicationIDMapping("invalid app"_ctv, 62'000, &reserveFailure) == false, "reservation_rejects_invalid_application_name");
  suite.expect(reserveFailure.equals("applicationName invalid"_ctv), "reservation_rejects_invalid_application_name_reason");

  ApplicationServiceIdentity invalidService = {};
  invalidService.applicationID = 62'000;
  invalidService.serviceName.assign("clients"_ctv);
  invalidService.serviceSlot = 1;
  invalidService.kind = ApplicationServiceIdentity::Kind::stateful;

  reserveFailure.clear();
  suite.expect(brain.reserveApplicationServiceMapping(invalidService, &reserveFailure) == false, "service_reservation_rejects_unreserved_application");
  suite.expect(reserveFailure.equals("applicationID not reserved"_ctv), "service_reservation_rejects_unreserved_application_reason");

  reserveFailure.clear();
  suite.expect(brain.reserveApplicationIDMapping("ValidationApp"_ctv, 62'000, &reserveFailure), "service_reservation_validation_seed_application");

  invalidService.serviceName.assign("bad service"_ctv);
  reserveFailure.clear();
  suite.expect(brain.reserveApplicationServiceMapping(invalidService, &reserveFailure) == false, "service_reservation_rejects_invalid_service_name");
  suite.expect(reserveFailure.equals("serviceName invalid"_ctv), "service_reservation_rejects_invalid_service_name_reason");

  invalidService.serviceName.assign("clients"_ctv);
  invalidService.serviceSlot = 0;
  reserveFailure.clear();
  suite.expect(brain.reserveApplicationServiceMapping(invalidService, &reserveFailure) == false, "service_reservation_rejects_zero_service_slot");
  suite.expect(reserveFailure.equals("serviceSlot invalid"_ctv), "service_reservation_rejects_zero_service_slot_reason");

  invalidService.serviceSlot = 1;
  invalidService.kind = ApplicationServiceIdentity::Kind(255);
  reserveFailure.clear();
  suite.expect(brain.reserveApplicationServiceMapping(invalidService, &reserveFailure) == false, "service_reservation_rejects_invalid_kind");
  suite.expect(reserveFailure.equals("service kind invalid"_ctv), "service_reservation_rejects_invalid_kind_reason");
}

static void testPersistentReservedServiceCaptureAndRestore(TestSuite& suite)
{
  TestBrain source;
  String reserveFailure;

  suite.expect(source.reserveApplicationIDMapping("CaptureApp"_ctv, 63'000, &reserveFailure), "persistent_service_capture_seed_application");

  ApplicationServiceIdentity clients = {};
  clients.applicationID = 63'000;
  clients.serviceName.assign("clients"_ctv);
  clients.serviceSlot = 2;
  clients.kind = ApplicationServiceIdentity::Kind::stateful;
  reserveFailure.clear();
  suite.expect(source.reserveApplicationServiceMapping(clients, &reserveFailure), "persistent_service_capture_seed_clients");

  ApplicationServiceIdentity siblings = {};
  siblings.applicationID = 63'000;
  siblings.serviceName.assign("siblings"_ctv);
  siblings.serviceSlot = 1;
  siblings.kind = ApplicationServiceIdentity::Kind::stateful;
  reserveFailure.clear();
  suite.expect(source.reserveApplicationServiceMapping(siblings, &reserveFailure), "persistent_service_capture_seed_siblings");

  Vector<ApplicationServiceIdentity> persistedServices;
  source.capturePersistentReservedApplicationServices(persistedServices);
  suite.expect(persistedServices.size() >= 2, "persistent_service_capture_emits_entries");
  suite.expect(persistedServices[0].applicationID <= persistedServices[persistedServices.size() - 1].applicationID, "persistent_service_capture_orders_by_application");

  TestBrain restored;
  reserveFailure.clear();
  suite.expect(restored.reserveApplicationIDMapping("CaptureApp"_ctv, 63'000, &reserveFailure), "persistent_service_restore_seed_application");
  restored.restorePersistentReservedApplicationServices(persistedServices);

  ApplicationServiceIdentity restoredSiblings = {};
  ApplicationServiceIdentity restoredClients = {};
  suite.expect(restored.resolveReservedApplicationService(63'000, "siblings"_ctv, restoredSiblings), "persistent_service_restore_resolves_siblings");
  suite.expect(restored.resolveReservedApplicationService(63'000, "clients"_ctv, restoredClients), "persistent_service_restore_resolves_clients");
  suite.expect(restoredSiblings.serviceSlot == 1, "persistent_service_restore_keeps_sibling_slot");
  suite.expect(restoredClients.serviceSlot == 2, "persistent_service_restore_keeps_client_slot");
  suite.expect(restored.takeNextReservableServiceSlot(63'000) == 3, "persistent_service_restore_restores_next_slot");
}

static void testMothershipReserveServiceTopic(TestSuite& suite)
{
  TestBrain brain;
  brain.weAreMaster = true;

  String reserveFailure;
  suite.expect(brain.reserveApplicationIDMapping("TopicServiceApp"_ctv, 52'000, &reserveFailure), "mothership_service_topic_seed_application");

  Mothership mothership;
  String requestBuffer;
  ApplicationServiceReserveRequest request;
  request.applicationID = 52'000;
  request.applicationName.assign("TopicServiceApp"_ctv);
  request.serviceName.assign("clients"_ctv);
  request.kind = ApplicationServiceIdentity::Kind::stateless;

  {
    String serializedRequest;
    BitseryEngine::serialize(serializedRequest, request);
    Message *message = buildMothershipMessage(requestBuffer, MothershipTopic::reserveServiceID, serializedRequest);
    brain.mothershipHandler(&mothership, message);
  }

  suite.expect(mothership.wBuffer.size() >= sizeof(Message), "mothership_service_topic_emits_response");

  ApplicationServiceReserveResponse response;
  response.success = false;
  if (mothership.wBuffer.size() >= sizeof(Message))
  {
    Message *message = reinterpret_cast<Message *>(mothership.wBuffer.data());
    String serializedResponse;
    uint8_t *args = message->args;
    Message::extractToStringView(args, serializedResponse);
    (void)BitseryEngine::deserializeSafe(serializedResponse, response);
  }

  suite.expect(response.success, "mothership_service_topic_success");
  suite.expect(response.applicationID == 52'000, "mothership_service_topic_returns_application_id");
  suite.expect(response.serviceName.equal("clients"_ctv), "mothership_service_topic_returns_service_name");
  suite.expect(response.service != 0, "mothership_service_topic_returns_service_value");
}

static void testNeuronInitialFramesDoNotRequireHardwareProfile(TestSuite& suite)
{
  TestNeuron neuron = {};
  neuron.seedRegistrationState(123'456, "6.8.0-test"_ctv, false, "ubuntu"_ctv, "24.04"_ctv);

  String outbound = {};
  neuron.appendInitialFramesForTest(outbound);

  uint32_t registrationFrames = 0;
  uint32_t hardwareFrames = 0;
  forEachMessageInBuffer(outbound, [&](Message *message) {
    if (NeuronTopic(message->topic) == NeuronTopic::registration)
    {
      uint8_t *args = message->args;
      int64_t bootTimeMs = 0;
      String kernel = {};
      String osID = {};
      String osVersionID = {};
      bool haveData = true;
      Message::extractArg<ArgumentNature::fixed>(args, bootTimeMs);
      Message::extractToStringView(args, kernel);
      Message::extractToStringView(args, osID);
      Message::extractToStringView(args, osVersionID);
      Message::extractArg<ArgumentNature::fixed>(args, haveData);
      registrationFrames += 1;
      suite.expect(bootTimeMs == 123'456, "neuron_initial_frames_registration_boot_time");
      suite.expect(kernel == "6.8.0-test"_ctv, "neuron_initial_frames_registration_kernel");
      suite.expect(osID == "ubuntu"_ctv, "neuron_initial_frames_registration_os_id");
      suite.expect(osVersionID == "24.04"_ctv, "neuron_initial_frames_registration_os_version_id");
      suite.expect(haveData == false, "neuron_initial_frames_registration_have_data");
    }
    if (NeuronTopic(message->topic) == NeuronTopic::machineHardwareProfile)
    {
      hardwareFrames += 1;
    }
  });

  suite.expect(registrationFrames == 1, "neuron_initial_frames_always_include_registration");
  suite.expect(hardwareFrames == 0, "neuron_initial_frames_skip_missing_hardware_profile");
}

static void testNeuronRegistrationBootTimeUsesEpochMs(TestSuite& suite)
{
  int64_t beforeMs = Time::now<TimeResolution::ms>();
  int64_t bootTimeMs = TestNeuron::registrationBootTimeMs();
  int64_t afterMs = Time::now<TimeResolution::ms>();

  suite.expect(bootTimeMs >= beforeMs, "neuron_registration_boot_time_not_before_epoch_sample");
  suite.expect(bootTimeMs <= afterMs, "neuron_registration_boot_time_not_after_epoch_sample");
  suite.expect(bootTimeMs > 1'000'000'000'000LL, "neuron_registration_boot_time_is_epoch_ms_not_uptime_ms");
}

static void testNeuronInitialFramesDeferAdoptedHardwareProfileUntilBrainStreamReady(TestSuite& suite)
{
  TestNeuron neuron = {};
  neuron.seedRegistrationState(987'654, "6.8.0-test"_ctv, true);

  MachineHardwareProfile hardware = {};
  hardware.inventoryComplete = true;
  hardware.cpu.logicalCores = 8;
  hardware.memory.totalMB = 32'768;

  String serializedHardware = {};
  BitseryEngine::serialize(serializedHardware, hardware);
  neuron.adoptHardwareInventoryForTest(hardware, serializedHardware);

  String outbound = {};
  neuron.appendInitialFramesForTest(outbound);

  uint32_t registrationFrames = 0;
  uint32_t hardwareFrames = 0;
  forEachMessageInBuffer(outbound, [&](Message *message) {
    if (NeuronTopic(message->topic) == NeuronTopic::registration)
    {
      registrationFrames += 1;
    }
    if (NeuronTopic(message->topic) == NeuronTopic::machineHardwareProfile)
    {
      hardwareFrames += 1;
    }
  });

  suite.expect(registrationFrames == 1, "neuron_initial_frames_preserve_registration_after_hardware_adopt");
  suite.expect(hardwareFrames == 0, "neuron_initial_frames_defer_adopted_hardware_profile_until_brain_stream_ready");
}

static void testNeuronDeferredHardwareInventoryAdoptionRequiresReadySerializedProfile(TestSuite& suite)
{
  TestNeuron neuron = {};

  MachineHardwareProfile incomplete = {};
  incomplete.cpu.logicalCores = 2;
  incomplete.memory.totalMB = 4096;

  String incompleteSerialized = {};
  BitseryEngine::serialize(incompleteSerialized, incomplete);

  MachineHardwareProfile complete = incomplete;
  complete.inventoryComplete = true;

  String completeSerialized = {};
  BitseryEngine::serialize(completeSerialized, complete);

  suite.expect(neuron.deferredHardwareInventoryReadyForAdoptionForTest(incomplete, incompleteSerialized) == false,
               "neuron_deferred_hardware_inventory_rejects_incomplete_profile");
  suite.expect(neuron.deferredHardwareInventoryReadyForAdoptionForTest(complete, String {}) == false,
               "neuron_deferred_hardware_inventory_rejects_missing_serialized_payload");
  suite.expect(neuron.deferredHardwareInventoryReadyForAdoptionForTest(complete, completeSerialized),
               "neuron_deferred_hardware_inventory_accepts_complete_serialized_profile");
}

static void testNeuronDeferredHardwareInventoryWakeAdoptsReadyProfile(TestSuite& suite)
{
  TestNeuron neuron = {};
  neuron.seedRegistrationState(13'579, "6.8.0-test"_ctv, false);

  MachineHardwareProfile hardware = {};
  hardware.inventoryComplete = true;
  hardware.cpu.logicalCores = 4;
  hardware.memory.totalMB = 8192;

  String serializedHardware = {};
  BitseryEngine::serialize(serializedHardware, hardware);
  neuron.seedDeferredHardwareInventoryReadyForTest(hardware, serializedHardware);
  neuron.deliverDeferredHardwareInventoryWakeForTest();

  String outbound = {};
  neuron.appendInitialFramesForTest(outbound);

  uint32_t hardwareFrames = 0;
  forEachMessageInBuffer(outbound, [&](Message *message) {
    if (NeuronTopic(message->topic) == NeuronTopic::machineHardwareProfile)
    {
      hardwareFrames += 1;
    }
  });

  suite.expect(hardwareFrames == 0, "neuron_deferred_hardware_inventory_wake_adopts_profile_without_prequeueing_initial_frame");
}

static void testNeuronEnsureDeferredHardwareInventoryProgressQueuesReadyProfileToActiveBrain(TestSuite& suite)
{
  TestNeuron neuron = {};
  neuron.seedRegistrationState(13'579, "6.8.0-test"_ctv, false);
  neuron.seedBrainStreamForTest(true);

  MachineHardwareProfile hardware = {};
  hardware.inventoryComplete = true;
  hardware.cpu.logicalCores = 4;
  hardware.memory.totalMB = 8192;

  String serializedHardware = {};
  BitseryEngine::serialize(serializedHardware, hardware);
  neuron.seedDeferredHardwareInventoryReadyForTest(hardware, serializedHardware);

  suite.expect(
      neuron.brainInitialMachineHardwareProfileQueuedForTest() == false,
      "neuron_deferred_inventory_progress_active_brain_starts_unqueued");
  suite.expect(
      neuron.latestHardwareProfileIfReadyForTest() == nullptr,
      "neuron_deferred_inventory_progress_active_brain_starts_unadopted");

  neuron.ensureDeferredHardwareInventoryProgressForTest();

  suite.expect(
      neuron.deferredHardwareInventoryInFlightForTest() == false,
      "neuron_deferred_inventory_progress_active_brain_clears_inflight");
  suite.expect(
      neuron.latestHardwareProfileIfReadyForTest() != nullptr,
      "neuron_deferred_inventory_progress_active_brain_adopts_hardware");
  suite.expect(
      neuron.brainInitialMachineHardwareProfileQueuedForTest(),
      "neuron_deferred_inventory_progress_active_brain_sets_queue_flag");

  uint32_t hardwareFrames = 0;
  String payload = {};
  forEachMessageInBuffer(neuron.brainOutboundForTest(), [&](Message *message) {
    if (NeuronTopic(message->topic) == NeuronTopic::machineHardwareProfile)
    {
      hardwareFrames += 1;
      uint8_t *args = message->args;
      Message::extractToStringView(args, payload);
    }
  });

  suite.expect(
      hardwareFrames == 1,
      "neuron_deferred_inventory_progress_active_brain_emits_single_hardware_frame");
  suite.expect(
      payload.equals(serializedHardware),
      "neuron_deferred_inventory_progress_active_brain_preserves_serialized_payload");
}

static void testNeuronQueuesCachedHardwareProfileWhenBrainStreamBecomesActive(TestSuite& suite)
{
  TestNeuron neuron = {};
  neuron.seedRegistrationState(24'680, "6.8.0-test"_ctv, false);
  neuron.seedBrainStreamForTest(false);

  MachineHardwareProfile hardware = {};
  hardware.inventoryComplete = true;
  hardware.cpu.logicalCores = 4;
  hardware.memory.totalMB = 8192;

  String serializedHardware = {};
  BitseryEngine::serialize(serializedHardware, hardware);
  neuron.adoptHardwareInventoryForTest(hardware, serializedHardware);

  suite.expect(neuron.brainOutboundForTest().size() == 0, "neuron_cached_hardware_profile_not_queued_before_stream_active");
  suite.expect(neuron.brainInitialMachineHardwareProfileQueuedForTest() == false, "neuron_cached_hardware_profile_flag_stays_clear_before_stream_active");

  neuron.setBrainStreamConnectedForTest(true);
  suite.expect(neuron.queueMachineHardwareProfileToBrainIfReadyForTest("unit-test"), "neuron_cached_hardware_profile_queues_once_stream_active");
  suite.expect(neuron.brainInitialMachineHardwareProfileQueuedForTest(), "neuron_cached_hardware_profile_sets_stream_flag_when_queued");

  uint32_t hardwareFrames = 0;
  String payload = {};
  forEachMessageInBuffer(neuron.brainOutboundForTest(), [&](Message *message) {
    if (NeuronTopic(message->topic) == NeuronTopic::machineHardwareProfile)
    {
      hardwareFrames += 1;
      uint8_t *args = message->args;
      Message::extractToStringView(args, payload);
    }
  });

  suite.expect(hardwareFrames == 1, "neuron_cached_hardware_profile_emits_single_frame_when_stream_active");
  suite.expect(payload.equals(serializedHardware), "neuron_cached_hardware_profile_preserves_serialized_payload");
  suite.expect(neuron.queueMachineHardwareProfileToBrainIfReadyForTest("unit-test-repeat") == false, "neuron_cached_hardware_profile_does_not_duplicate_after_first_queue");
}

static void testNeuronOverlayRoutingSyncWithoutPrograms(TestSuite& suite)
{
  TestNeuron neuron = {};

  SwitchboardOverlayRoutingConfig config = {};
  config.containerNetworkViaOverlay = true;
  config.overlaySubnets.push_back(makePrefix("198.18.55.77/12"));
  config.overlaySubnets.push_back(makePrefix("198.16.0.1/12"));
  config.overlaySubnets.push_back(makePrefix("2001:db8:abcd:1234:5678:9abc::1/64"));
  config.overlaySubnets.push_back(makePrefix("2001:db8:abcd:1234::beef/64"));

  SwitchboardOverlayMachineRoute route1 = {};
  route1.machineFragment = 0x000001u;
  route1.nextHop = IPAddress("198.51.100.44", false);
  route1.sourceAddress = IPAddress("198.51.100.10", false);
  route1.useGatewayMAC = true;

  SwitchboardOverlayMachineRoute route2 = {};
  route2.machineFragment = 0x000002u;
  route2.nextHop = IPAddress("2001:db8::44", true);
  route2.sourceAddress = IPAddress("2001:db8::10", true);
  route2.nextHopMAC = "fa:6d:18:7d:9f:5e"_ctv;

  SwitchboardOverlayMachineRoute route3 = {};
  route3.machineFragment = 0x010102u;
  route3.nextHop = IPAddress("2001:db8::45", true);
  route3.sourceAddress = IPAddress("2001:db8::11", true);
  route3.useGatewayMAC = true;

  SwitchboardOverlayMachineRoute invalidRoute = {};
  invalidRoute.machineFragment = 0;
  invalidRoute.nextHop = IPAddress("2001:db8::46", true);
  invalidRoute.sourceAddress = IPAddress("2001:db8::12", true);

  config.machineRoutes.push_back(route1);
  config.machineRoutes.push_back(route2);
  config.machineRoutes.push_back(route3);
  config.machineRoutes.push_back(invalidRoute);

  neuron.seedOverlayRoutingConfigForTest(config);
  neuron.syncOverlayRoutingProgramsForTest();

  suite.expect(neuron.installedIngressOverlayPrefixes4CountForTest() == 1, "neuron_overlay_sync_without_programs_dedupes_ingress_ipv4_prefixes");
  suite.expect(neuron.installedIngressOverlayPrefixes6CountForTest() == 1, "neuron_overlay_sync_without_programs_dedupes_ingress_ipv6_prefixes");
  suite.expect(neuron.installedEgressOverlayPrefixes4CountForTest() == 1, "neuron_overlay_sync_without_programs_dedupes_egress_ipv4_prefixes");
  suite.expect(neuron.installedEgressOverlayPrefixes6CountForTest() == 1, "neuron_overlay_sync_without_programs_dedupes_egress_ipv6_prefixes");
  suite.expect(neuron.installedOverlayRouteKeysFullCountForTest() == 3, "neuron_overlay_sync_without_programs_keeps_valid_full_routes");
  suite.expect(neuron.installedOverlayRouteKeysLow8CountForTest() == 1, "neuron_overlay_sync_without_programs_keeps_only_unique_low8_routes");
}

static void testNeuronWhiteholeBindingBookkeepingWithoutPrograms(TestSuite& suite)
{
  TestNeuron neuron = {};

  local_container_subnet6 subnet = {};
  subnet.dpfx = 0x7A;
  subnet.mpfx[0] = 0x01;
  subnet.mpfx[1] = 0x02;
  subnet.mpfx[2] = 0x03;
  neuron.seedLocalContainerSubnetForTest(subnet);

  Whitehole valid = {};
  valid.transport = ExternalAddressTransport::quic;
  valid.family = ExternalAddressFamily::ipv6;
  valid.source = ExternalAddressSource::registeredRoutablePrefix;
  valid.hasAddress = true;
  valid.address = IPAddress("2001:db8::44", true);
  valid.sourcePort = 5353;
  valid.bindingNonce = 0x12345678u;

  Whitehole invalid = valid;
  invalid.sourcePort = 0;

  Vector<Whitehole> whiteholes = {};
  whiteholes.push_back(invalid);
  whiteholes.push_back(valid);

  neuron.openLocalWhiteholesForTest(0x01020304u, whiteholes);

  suite.expect(neuron.localWhiteholeBindingCountForContainerForTest(0x01020304u) == 1, "neuron_whitehole_bookkeeping_without_programs_keeps_only_valid_bindings");
  suite.expect(neuron.installedWhiteholeBindingCountForTest() == 1, "neuron_whitehole_bookkeeping_without_programs_tracks_installed_keys");

  neuron.closeLocalWhiteholesToContainerForTest(0x01020304u);

  suite.expect(neuron.localWhiteholeBindingCountForContainerForTest(0x01020304u) == 0, "neuron_whitehole_bookkeeping_without_programs_erases_container_bindings");
  suite.expect(neuron.installedWhiteholeBindingCountForTest() == 0, "neuron_whitehole_bookkeeping_without_programs_clears_installed_keys");
}

static void testNeuronResolveOptionalHostRouterBPFPaths(TestSuite& suite)
{
  const char *oldIngress = std::getenv("PRODIGY_HOST_INGRESS_EBPF");
  const char *oldEgress = std::getenv("PRODIGY_HOST_EGRESS_EBPF");
  String oldIngressValue = {};
  String oldEgressValue = {};
  if (oldIngress)
  {
    oldIngressValue.assign(oldIngress);
  }
  if (oldEgress)
  {
    oldEgressValue.assign(oldEgress);
  }

  auto restoreEnv = [&]() -> void {
    if (oldIngress)
    {
      setenv("PRODIGY_HOST_INGRESS_EBPF", oldIngressValue.c_str(), 1);
    }
    else
    {
      unsetenv("PRODIGY_HOST_INGRESS_EBPF");
    }

    if (oldEgress)
    {
      setenv("PRODIGY_HOST_EGRESS_EBPF", oldEgressValue.c_str(), 1);
    }
    else
    {
      unsetenv("PRODIGY_HOST_EGRESS_EBPF");
    }
  };

  TestNeuron neuron = {};
  String ingress = {};
  String egress = {};
  String failure = {};

  unsetenv("PRODIGY_HOST_INGRESS_EBPF");
  unsetenv("PRODIGY_HOST_EGRESS_EBPF");
  suite.expect(neuron.resolveOptionalHostRouterBPFPathsForTest(ingress, egress, &failure) == false, "neuron_optional_host_router_paths_unset_returns_false");
  suite.expect(ingress.size() == 0 && egress.size() == 0, "neuron_optional_host_router_paths_unset_clears_outputs");
  suite.expect(failure.size() == 0, "neuron_optional_host_router_paths_unset_keeps_failure_empty");

  setenv("PRODIGY_HOST_INGRESS_EBPF", "/tmp/host-ingress.o", 1);
  unsetenv("PRODIGY_HOST_EGRESS_EBPF");
  failure.clear();
  suite.expect(neuron.resolveOptionalHostRouterBPFPathsForTest(ingress, egress, &failure) == false, "neuron_optional_host_router_paths_partial_env_rejected");
  suite.expect(failure.equals("PRODIGY_HOST_INGRESS_EBPF and PRODIGY_HOST_EGRESS_EBPF must be set together"_ctv), "neuron_optional_host_router_paths_partial_env_sets_failure");

  setenv("PRODIGY_HOST_EGRESS_EBPF", "/tmp/host-egress.o", 1);
  failure.clear();
  suite.expect(neuron.resolveOptionalHostRouterBPFPathsForTest(ingress, egress, &failure), "neuron_optional_host_router_paths_complete_env_accepted");
  suite.expect(ingress.equals("/tmp/host-ingress.o"_ctv), "neuron_optional_host_router_paths_complete_env_preserves_ingress");
  suite.expect(egress.equals("/tmp/host-egress.o"_ctv), "neuron_optional_host_router_paths_complete_env_preserves_egress");

  restoreEnv();
}

static void testNeuronQueueBrainAcceptPaths(TestSuite& suite)
{
  {
    TestNeuron neuron = {};
    neuron.queueBrainAcceptForTest();
    suite.expect(neuron.brainListenerFixedForTest() == false, "neuron_queue_brain_accept_requires_fixed_listener");
  }

  {
    ScopedFreshRing scopedRing = {};

    TestNeuron neuron = {};
    suite.expect(neuron.armBrainListenerForTest(), "neuron_queue_brain_accept_fixture_arms_listener");

    neuron.queueBrainAcceptForTest();

    suite.expect(neuron.brainListenerFixedForTest(), "neuron_queue_brain_accept_keeps_fixed_listener_active");
  }
}

static void testNeuronAcceptHandlerBrainControlPaths(TestSuite& suite)
{
  {
    ScopedFreshRing scopedRing = {};
    ProdigyTransportTLSRuntime::clear();

    TestNeuron neuron = {};
    suite.expect(neuron.armBrainListenerForTest(), "neuron_accept_handler_retry_fixture_arms_listener");

    neuron.acceptBrainForTest(-1);

    suite.expect(neuron.brainStreamForTest() == nullptr, "neuron_accept_handler_retry_without_fslot_keeps_brain_null");
    suite.expect(neuron.brainListenerFixedForTest(), "neuron_accept_handler_retry_without_fslot_keeps_listener_fixed");
  }

  {
    ScopedFreshRing scopedRing = {};
    ProdigyTransportTLSRuntime::clear();

    String failure = {};
    String rootCertPem = {};
    String rootKeyPem = {};
    suite.expect(
        Vault::generateTransportRootCertificateEd25519(rootCertPem, rootKeyPem, &failure),
        "neuron_accept_handler_tls_failure_generate_root");

    String neuronCertPem = {};
    String neuronKeyPem = {};
    Vector<String> neuronAddresses = {};
    neuronAddresses.push_back("fd00::20"_ctv);
    uint128_t neuronUUID = 0xACCE701ULL;
    suite.expect(
        Vault::generateTransportNodeCertificateEd25519(
            rootCertPem,
            rootKeyPem,
            neuronUUID,
            neuronAddresses,
            neuronCertPem,
            neuronKeyPem,
            &failure),
        "neuron_accept_handler_tls_failure_generate_leaf");
    suite.expect(
        configureTransportRuntimeForNode(
            neuronUUID,
            rootCertPem,
            rootKeyPem,
            neuronCertPem,
            neuronKeyPem,
            &failure),
        "neuron_accept_handler_tls_failure_configure_runtime");

    ScopedSocketPair sockets = {};
    if (sockets.create(suite, "neuron_accept_handler_tls_failure_creates_socketpair"))
    {
      int acceptedFslot = sockets.adoptLeftIntoFixedFileSlot();
      suite.expect(acceptedFslot >= 0, "neuron_accept_handler_tls_failure_adopts_fixed_slot");

      TestNeuron neuron = {};
      neuron.setFailAcceptedBrainTransportTLSForTest(true);

      neuron.acceptBrainForTest(acceptedFslot);

      suite.expect(neuron.brainStreamForTest() != nullptr, "neuron_accept_handler_tls_failure_creates_stream");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(neuron.brainStreamForTest()), "neuron_accept_handler_tls_failure_queues_close");
      suite.expect(TestNeuron::rawBrainStreamIsActiveForTest(neuron.brainStreamForTest()) == false, "neuron_accept_handler_tls_failure_retires_stream");
      suite.expect(neuron.brainStreamForTest()->pendingRecv == false, "neuron_accept_handler_tls_failure_skips_recv_arm");
      suite.expect(neuron.brainStreamForTest()->pendingSend == false, "neuron_accept_handler_tls_failure_skips_send_arm");
      suite.expect(neuron.brainOutboundForTest().size() == 0, "neuron_accept_handler_tls_failure_skips_initial_frames");
    }
  }

  {
    ScopedFreshRing scopedRing = {};
    ProdigyTransportTLSRuntime::clear();

    ScopedSocketPair sockets = {};
    if (sockets.create(suite, "neuron_accept_handler_active_brain_creates_socketpair"))
    {
      int acceptedFslot = sockets.adoptLeftIntoFixedFileSlot();
      suite.expect(acceptedFslot >= 0, "neuron_accept_handler_active_brain_adopts_fixed_slot");

      TestNeuron neuron = {};
      neuron.seedRegistrationState(13'579, "6.9.1-test"_ctv, true);
      neuron.seedBrainStreamForTest(true);
      NeuronBrainControlStream *existing = neuron.brainStreamForTest();

      neuron.acceptBrainForTest(acceptedFslot);

      suite.expect(neuron.brainStreamForTest() != existing, "neuron_accept_handler_active_brain_preempts_existing_stream");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(existing), "neuron_accept_handler_active_brain_closes_preempted_stream");
      suite.expect(neuron.brainStreamForTest() != nullptr, "neuron_accept_handler_active_brain_creates_replacement_stream");
      suite.expect(neuron.brainStreamForTest()->connected, "neuron_accept_handler_active_brain_marks_replacement_connected");
      suite.expect(neuron.brainStreamForTest()->isFixedFile, "neuron_accept_handler_active_brain_marks_replacement_fixed_file");
      suite.expect(neuron.brainStreamForTest()->fslot == acceptedFslot, "neuron_accept_handler_active_brain_preserves_replacement_fixed_slot");
      suite.expect(neuron.brainStreamForTest()->pendingRecv, "neuron_accept_handler_active_brain_arms_replacement_recv");
      suite.expect(neuron.brainStreamForTest()->pendingSend, "neuron_accept_handler_active_brain_arms_replacement_send");
    }
  }

  {
    ScopedFreshRing scopedRing = {};
    ProdigyTransportTLSRuntime::clear();

    ScopedSocketPair sockets = {};
    if (sockets.create(suite, "neuron_accept_handler_replaces_stale_brain_registration_only_creates_socketpair"))
    {
      int acceptedFslot = sockets.adoptLeftIntoFixedFileSlot();
      suite.expect(acceptedFslot >= 0, "neuron_accept_handler_replaces_stale_brain_registration_only_adopts_fixed_slot");

      TestNeuron neuron = {};
      neuron.seedRegistrationState(13'579, "6.9.1-test"_ctv, true);
      neuron.seedStaleBrainStreamForTest();

      neuron.acceptBrainForTest(acceptedFslot);

      suite.expect(neuron.brainStreamForTest() != nullptr, "neuron_accept_handler_replaces_stale_brain_registration_only_creates_stream");
      suite.expect(neuron.brainStreamForTest()->connected, "neuron_accept_handler_replaces_stale_brain_registration_only_marks_stream_connected");
      suite.expect(neuron.brainStreamForTest()->pendingRecv, "neuron_accept_handler_replaces_stale_brain_registration_only_arms_recv");
      suite.expect(neuron.brainStreamForTest()->pendingSend, "neuron_accept_handler_replaces_stale_brain_registration_only_arms_send");
      suite.expect(neuron.brainInitialMachineHardwareProfileQueuedForTest() == false, "neuron_accept_handler_replaces_stale_brain_registration_only_skips_hardware_queue");

      uint32_t registrationFrames = 0;
      uint32_t hardwareFrames = 0;
      uint32_t blobRequestFrames = 0;
      forEachMessageInBuffer(neuron.brainOutboundForTest(), [&](Message *frame) {
        switch (NeuronTopic(frame->topic))
        {
          case NeuronTopic::registration:
            registrationFrames += 1;
            break;
          case NeuronTopic::machineHardwareProfile:
            hardwareFrames += 1;
            break;
          case NeuronTopic::requestContainerBlob:
            blobRequestFrames += 1;
            break;
          default:
            break;
        }
      });

      suite.expect(registrationFrames == 1, "neuron_accept_handler_replaces_stale_brain_registration_only_queues_registration_frame");
      suite.expect(hardwareFrames == 0, "neuron_accept_handler_replaces_stale_brain_registration_only_skips_hardware_frame");
      suite.expect(blobRequestFrames == 0, "neuron_accept_handler_replaces_stale_brain_registration_only_skips_blob_request");
    }
  }

  {
    ScopedFreshRing scopedRing = {};
    ProdigyTransportTLSRuntime::clear();

    ScopedSocketPair sockets = {};
    if (sockets.create(suite, "neuron_accept_handler_replaces_stale_brain_creates_socketpair"))
    {
      int acceptedFslot = sockets.adoptLeftIntoFixedFileSlot();
      suite.expect(acceptedFslot >= 0, "neuron_accept_handler_replaces_stale_brain_adopts_fixed_slot");

      TestNeuron neuron = {};
      neuron.seedRegistrationState(13'579, "6.9.1-test"_ctv, true);
      neuron.seedStaleBrainStreamForTest();
      neuron.queueContainerDownloadRequestForTest(uint64_t(0xA114));

      MachineHardwareProfile hardware = {};
      hardware.inventoryComplete = true;
      hardware.cpu.logicalCores = 16;
      hardware.memory.totalMB = 32'768;
      String serializedHardware = {};
      BitseryEngine::serialize(serializedHardware, hardware);
      neuron.adoptHardwareInventoryForTest(hardware, serializedHardware);

      neuron.acceptBrainForTest(acceptedFslot);

      suite.expect(neuron.brainStreamForTest() != nullptr, "neuron_accept_handler_replaces_stale_brain_creates_stream");
      suite.expect(neuron.brainStreamForTest()->connected, "neuron_accept_handler_replaces_stale_brain_marks_stream_connected");
      suite.expect(neuron.brainStreamForTest()->isFixedFile, "neuron_accept_handler_replaces_stale_brain_marks_stream_fixed_file");
      suite.expect(neuron.brainStreamForTest()->fslot == acceptedFslot, "neuron_accept_handler_replaces_stale_brain_preserves_fixed_slot");
      suite.expect(neuron.brainStreamForTest()->pendingRecv, "neuron_accept_handler_replaces_stale_brain_arms_recv");
      suite.expect(neuron.brainStreamForTest()->pendingSend, "neuron_accept_handler_replaces_stale_brain_arms_send");
      suite.expect(neuron.brainInitialMachineHardwareProfileQueuedForTest(), "neuron_accept_handler_replaces_stale_brain_queues_hardware_profile");

      uint32_t registrationFrames = 0;
      uint32_t hardwareFrames = 0;
      uint32_t blobRequestFrames = 0;
      forEachMessageInBuffer(neuron.brainOutboundForTest(), [&](Message *frame) {
        switch (NeuronTopic(frame->topic))
        {
          case NeuronTopic::registration:
            registrationFrames += 1;
            break;
          case NeuronTopic::machineHardwareProfile:
            hardwareFrames += 1;
            break;
          case NeuronTopic::requestContainerBlob:
            blobRequestFrames += 1;
            break;
          default:
            break;
        }
      });

      suite.expect(registrationFrames == 1, "neuron_accept_handler_replaces_stale_brain_queues_registration_frame");
      suite.expect(hardwareFrames == 1, "neuron_accept_handler_replaces_stale_brain_queues_hardware_frame");
      suite.expect(blobRequestFrames == 1, "neuron_accept_handler_replaces_stale_brain_replays_blob_request");
    }
  }

  {
    ScopedFreshRing scopedRing = {};
    ProdigyTransportTLSRuntime::clear();

    ScopedSocketPair sockets = {};
    if (sockets.create(suite, "neuron_accept_handler_replaces_disconnected_raw_active_brain_creates_socketpair"))
    {
      int acceptedFslot = sockets.adoptLeftIntoFixedFileSlot();
      suite.expect(acceptedFslot >= 0, "neuron_accept_handler_replaces_disconnected_raw_active_brain_adopts_fixed_slot");

      TestNeuron neuron = {};
      neuron.seedRegistrationState(13'579, "6.9.1-test"_ctv, true);
      neuron.seedBrainStreamForTest(false);
      suite.expect(TestNeuron::rawBrainStreamIsActiveForTest(neuron.brainStreamForTest()), "neuron_accept_handler_replaces_disconnected_raw_active_brain_seed_is_raw_active");
      suite.expect(TestNeuron::brainStreamIsActiveForTest(neuron.brainStreamForTest()) == false, "neuron_accept_handler_replaces_disconnected_raw_active_brain_seed_is_not_connected");
      neuron.queueContainerDownloadRequestForTest(uint64_t(0xA116));

      MachineHardwareProfile hardware = {};
      hardware.inventoryComplete = true;
      hardware.cpu.logicalCores = 16;
      hardware.memory.totalMB = 32'768;
      String serializedHardware = {};
      BitseryEngine::serialize(serializedHardware, hardware);
      neuron.adoptHardwareInventoryForTest(hardware, serializedHardware);

      Container healthy = {};
      healthy.plan.uuid = uint128_t(0xA1004);
      healthy.plan.state = ContainerState::healthy;
      neuron.registerContainerForTest(&healthy);

      neuron.acceptBrainForTest(acceptedFslot);

      suite.expect(neuron.brainStreamForTest() != nullptr, "neuron_accept_handler_replaces_disconnected_raw_active_brain_creates_stream");
      suite.expect(neuron.brainStreamForTest()->connected, "neuron_accept_handler_replaces_disconnected_raw_active_brain_marks_stream_connected");
      suite.expect(neuron.brainStreamForTest()->isFixedFile, "neuron_accept_handler_replaces_disconnected_raw_active_brain_marks_stream_fixed_file");
      suite.expect(neuron.brainStreamForTest()->fslot == acceptedFslot, "neuron_accept_handler_replaces_disconnected_raw_active_brain_preserves_fixed_slot");
      suite.expect(neuron.brainStreamForTest()->pendingRecv, "neuron_accept_handler_replaces_disconnected_raw_active_brain_arms_recv");
      suite.expect(neuron.brainStreamForTest()->pendingSend, "neuron_accept_handler_replaces_disconnected_raw_active_brain_arms_send");
      suite.expect(neuron.brainInitialMachineHardwareProfileQueuedForTest(), "neuron_accept_handler_replaces_disconnected_raw_active_brain_queues_hardware_profile");

      uint32_t registrationFrames = 0;
      uint32_t hardwareFrames = 0;
      uint32_t blobRequestFrames = 0;
      uint32_t healthyFrames = 0;
      bool sawHealthy = false;
      forEachMessageInBuffer(neuron.brainOutboundForTest(), [&](Message *frame) {
        switch (NeuronTopic(frame->topic))
        {
          case NeuronTopic::registration:
            registrationFrames += 1;
            break;
          case NeuronTopic::machineHardwareProfile:
            hardwareFrames += 1;
            break;
          case NeuronTopic::requestContainerBlob:
            blobRequestFrames += 1;
            break;
          case NeuronTopic::containerHealthy:
            {
              uint8_t *args = frame->args;
              uint128_t containerUUID = 0;
              Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
              healthyFrames += 1;
              sawHealthy = sawHealthy || (containerUUID == healthy.plan.uuid);
              break;
            }
          default:
            break;
        }
      });

      suite.expect(registrationFrames == 1, "neuron_accept_handler_replaces_disconnected_raw_active_brain_queues_registration_frame");
      suite.expect(hardwareFrames == 1, "neuron_accept_handler_replaces_disconnected_raw_active_brain_queues_hardware_frame");
      suite.expect(blobRequestFrames == 1, "neuron_accept_handler_replaces_disconnected_raw_active_brain_replays_blob_request");
      suite.expect(healthyFrames == 1, "neuron_accept_handler_replaces_disconnected_raw_active_brain_replays_healthy_container");
      suite.expect(sawHealthy, "neuron_accept_handler_replaces_disconnected_raw_active_brain_preserves_healthy_uuid");

      neuron.unregisterContainerForTest(healthy.plan.uuid);
    }
  }

  {
    ScopedFreshRing scopedRing = {};
    ProdigyTransportTLSRuntime::clear();

    ScopedSocketPair sockets = {};
    if (sockets.create(suite, "neuron_accept_handler_replays_healthy_containers_creates_socketpair"))
    {
      int acceptedFslot = sockets.adoptLeftIntoFixedFileSlot();
      suite.expect(acceptedFslot >= 0, "neuron_accept_handler_replays_healthy_containers_adopts_fixed_slot");

      TestNeuron neuron = {};
      neuron.seedRegistrationState(24'680, "6.10.0-test"_ctv, true);
      neuron.seedStaleBrainStreamForTest();

      Container healthyA = {};
      healthyA.plan.uuid = uint128_t(0xA1001);
      healthyA.plan.state = ContainerState::healthy;
      neuron.registerContainerForTest(&healthyA);

      Container scheduled = {};
      scheduled.plan.uuid = uint128_t(0xA1002);
      scheduled.plan.state = ContainerState::scheduled;
      neuron.registerContainerForTest(&scheduled);

      Container healthyB = {};
      healthyB.plan.uuid = uint128_t(0xA1003);
      healthyB.plan.state = ContainerState::healthy;
      neuron.registerContainerForTest(&healthyB);

      neuron.acceptBrainForTest(acceptedFslot);

      uint32_t registrationFrames = 0;
      uint32_t healthyFrames = 0;
      bool sawHealthyA = false;
      bool sawHealthyB = false;
      bool sawScheduled = false;
      forEachMessageInBuffer(neuron.brainOutboundForTest(), [&](Message *frame) {
        switch (NeuronTopic(frame->topic))
        {
          case NeuronTopic::registration:
            registrationFrames += 1;
            break;
          case NeuronTopic::containerHealthy:
            {
              uint8_t *args = frame->args;
              uint128_t containerUUID = 0;
              Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
              healthyFrames += 1;
              sawHealthyA = sawHealthyA || (containerUUID == healthyA.plan.uuid);
              sawHealthyB = sawHealthyB || (containerUUID == healthyB.plan.uuid);
              sawScheduled = sawScheduled || (containerUUID == scheduled.plan.uuid);
              break;
            }
          default:
            break;
        }
      });

      suite.expect(registrationFrames == 1, "neuron_accept_handler_replays_healthy_containers_keeps_registration_frame");
      suite.expect(healthyFrames == 2, "neuron_accept_handler_replays_healthy_containers_replays_each_healthy_container_once");
      suite.expect(sawHealthyA, "neuron_accept_handler_replays_healthy_containers_includes_first_healthy_uuid");
      suite.expect(sawHealthyB, "neuron_accept_handler_replays_healthy_containers_includes_second_healthy_uuid");
      suite.expect(sawScheduled == false, "neuron_accept_handler_replays_healthy_containers_skips_nonhealthy_container");

      neuron.unregisterContainerForTest(healthyA.plan.uuid);
      neuron.unregisterContainerForTest(scheduled.plan.uuid);
      neuron.unregisterContainerForTest(healthyB.plan.uuid);
    }
  }
}

static void testNeuronCloseHandlerPaths(TestSuite& suite)
{
  {
    ScopedFreshRing scopedRing = {};

    TestNeuron neuron = {};
    suite.expect(neuron.armBrainListenerForTest(), "neuron_close_handler_brain_fixture_arms_listener");
    neuron.seedBrainStreamForTest(true);

    neuron.closeSocketForTest(neuron.brainStreamForTest());

    suite.expect(neuron.brainStreamForTest() == nullptr, "neuron_close_handler_brain_clears_brain_stream");
    suite.expect(neuron.brainListenerFixedForTest(), "neuron_close_handler_brain_rearms_listener");
  }

  {
    ScopedFreshRing scopedRing = {};

    int oldFD = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    suite.expect(oldFD >= 0, "neuron_close_handler_container_reconnect_creates_socket");
    if (oldFD >= 0)
    {
      TestNeuron neuron = {};
      Container container = {};
      container.plan.uuid = uint128_t(0xC061);
      container.name.assign("unit-close-reconnect"_ctv);
      container.pid = getpid();
      container.fd = oldFD;
      container.isFixedFile = false;
      container.rBuffer.reserve(8_KB);
      container.wBuffer.reserve(8_KB);
      neuron.registerContainerForTest(&container);

      neuron.closeSocketForTest(&container);

      suite.expect(container.isFixedFile, "neuron_close_handler_container_reconnect_reinstalls_fixed_file");
      suite.expect(container.fslot >= 0, "neuron_close_handler_container_reconnect_assigns_fixed_slot");
      suite.expect(TestNeuron::containerStreamIsClosingForTest(&container) == false, "neuron_close_handler_container_reconnect_keeps_socket_open");

      neuron.unregisterContainerForTest(container.plan.uuid);
    }
  }

  {
    ScopedFreshRing scopedRing = {};

    int oldFD = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    suite.expect(oldFD >= 0, "neuron_close_handler_container_pair_reconnect_creates_socket");
    if (oldFD >= 0)
    {
      TestNeuron neuron = {};
      Container container = {};
      container.plan.uuid = uint128_t(0xC062);
      container.name.assign("unit-close-pair-reconnect"_ctv);
      container.pid = getpid();
      container.setUnixPairHalf(oldFD);
      container.isFixedFile = false;
      container.rBuffer.reserve(8_KB);
      container.wBuffer.reserve(8_KB);
      neuron.registerContainerForTest(&container);

      neuron.closeSocketForTest(&container);

      suite.expect(container.isPair == false, "neuron_close_handler_container_pair_reconnect_replaces_pair_with_socket_path");
      suite.expect(container.isFixedFile, "neuron_close_handler_container_pair_reconnect_reinstalls_fixed_file");
      suite.expect(container.fslot >= 0, "neuron_close_handler_container_pair_reconnect_assigns_fixed_slot");
      suite.expect(String(container.daddr<struct sockaddr_un>()->sun_path).equal("/containers/unit-close-pair-reconnect/neuron.soc"_ctv), "neuron_close_handler_container_pair_reconnect_targets_neuron_socket");
      suite.expect(TestNeuron::containerStreamIsClosingForTest(&container) == false, "neuron_close_handler_container_pair_reconnect_keeps_socket_open");

      neuron.unregisterContainerForTest(container.plan.uuid);
    }
  }

  {
    ScopedFreshRing scopedRing = {};

    TestNeuron neuron = {};
    NeuronBase *previousNeuron = thisNeuron;
    thisNeuron = &neuron;
    neuron.seedBrainStreamForTest(true);

    Container *container = new Container();
    container->plan.uuid = uint128_t(0xC063);
    container->name.assign("unit-close-waitid-order"_ctv);
    container->pid = getpid();
    container->pendingDestroy = true;
    container->waitidPending = true;
    container->infop.si_pid = container->pid;
    container->infop.si_code = CLD_EXITED;
    container->infop.si_status = 7;
    neuron.registerContainerForTest(container);

    neuron.closeSocketForTest(container);

    suite.expect(neuron.popContainerCallsForTest == 0, "neuron_close_handler_pending_destroy_waits_for_waitid_before_finalize");
    suite.expect(container->destroyCloseCompleted, "neuron_close_handler_pending_destroy_records_close_completion");
    suite.expect(container->waitidPending, "neuron_close_handler_pending_destroy_keeps_waitid_pending");

    neuron.waitContainerForTest(container);

    uint32_t containerFailedFrames = 0;
    forEachMessageInBuffer(neuron.brainOutboundForTest(), [&](Message *message) {
      if (message->topic == uint16_t(NeuronTopic::containerFailed))
      {
        containerFailedFrames += 1;
      }
    });

    suite.expect(containerFailedFrames == 1, "neuron_waitid_pending_destroy_close_first_emits_container_failed");
    suite.expect(neuron.popContainerCallsForTest == 1, "neuron_waitid_pending_destroy_close_first_finalizes_after_waitid");
    suite.expect(neuron.lastPoppedContainerUUIDForTest == uint128_t(0xC063), "neuron_waitid_pending_destroy_close_first_pops_expected_container");

    if (neuron.lastPoppedContainerUUIDForTest != uint128_t(0xC063))
    {
      neuron.unregisterContainerForTest(container->plan.uuid);
      delete container;
    }

    thisNeuron = previousNeuron;
  }
}

static void testNeuronMetricsTickHelpers(TestSuite& suite)
{
  {
    TestNeuron neuron = {};
    Container container = {};
    container.plan.uuid = uint128_t(0x7101);
    container.neuronScalingDimensionsMask = ProdigyMetrics::maskForScalingDimension(ScalingDimension::cpu);
    container.neuronMetricsCadenceMs = 100;

    suite.expect(neuron.activeMetricsMaskForTest(nullptr) == 0, "neuron_metrics_helpers_null_container_has_zero_mask");
    suite.expect(neuron.activeMetricsMaskForTest(&container) == ProdigyMetrics::maskForScalingDimension(ScalingDimension::cpu), "neuron_metrics_helpers_keeps_collectable_cpu_mask");
    suite.expect(neuron.normalizedMetricsCadenceMsForTest(nullptr) == ProdigyMetrics::defaultNeuronCollectionCadenceMs, "neuron_metrics_helpers_null_container_uses_default_cadence");
    suite.expect(neuron.normalizedMetricsCadenceMsForTest(&container) == 250, "neuron_metrics_helpers_clamps_small_cadence");
  }

  {
    ScopedRing scopedRing = {};

    TestNeuron neuron = {};
    Container fast = {};
    fast.plan.uuid = uint128_t(0x7102);
    fast.neuronScalingDimensionsMask = ProdigyMetrics::maskForScalingDimension(ScalingDimension::memory);
    fast.neuronMetricsCadenceMs = 100;

    Container slow = {};
    slow.plan.uuid = uint128_t(0x7103);
    slow.neuronScalingDimensionsMask = ProdigyMetrics::maskForScalingDimension(ScalingDimension::storage);
    slow.neuronMetricsCadenceMs = 1000;

    Container inactive = {};
    inactive.plan.uuid = uint128_t(0x7104);
    inactive.neuronScalingDimensionsMask = 0;
    inactive.neuronMetricsCadenceMs = 50;

    neuron.registerContainerForTest(&fast);
    neuron.registerContainerForTest(&slow);
    neuron.registerContainerForTest(&inactive);

    suite.expect(neuron.minimumActiveMetricsCadenceMsForTest() == 250, "neuron_metrics_helpers_selects_minimum_active_cadence");

    neuron.ensureMetricsTickQueuedForTest();

    suite.expect(neuron.metricsTickQueuedForTest(), "neuron_metrics_helpers_queues_metrics_tick");
    suite.expect(neuron.metricsTickFlagsForTest() == uint64_t(NeuronTimeoutFlags::metricsTick), "neuron_metrics_helpers_sets_metrics_tick_flag");
    suite.expect(neuron.metricsTickTimeoutMsForTest() == 250, "neuron_metrics_helpers_sets_metrics_tick_timeout");

    neuron.unregisterContainerForTest(fast.plan.uuid);
    neuron.unregisterContainerForTest(slow.plan.uuid);
    neuron.unregisterContainerForTest(inactive.plan.uuid);
  }

  {
    ScopedRing scopedRing = {};

    TestNeuron neuron = {};
    suite.expect(neuron.minimumActiveMetricsCadenceMsForTest() == 0, "neuron_metrics_helpers_zero_without_active_metrics");

    neuron.ensureMetricsTickQueuedForTest();

    suite.expect(neuron.metricsTickQueuedForTest() == false, "neuron_metrics_helpers_skips_tick_without_active_metrics");
    suite.expect(neuron.metricsTickTimeoutMsForTest() == 0, "neuron_metrics_helpers_keeps_timeout_clear_without_active_metrics");
  }
}

static void testNeuronMetricSamplingHelpers(TestSuite& suite)
{
  uint64_t value = 0;
  suite.expect(TestNeuron::parseUnsignedDecimalForTest(" \t12345\n"_ctv, value) && value == 12'345, "neuron_metric_helpers_parse_unsigned_decimal_with_whitespace");
  suite.expect(TestNeuron::parseUnsignedDecimalForTest("42ms"_ctv, value) && value == 42, "neuron_metric_helpers_parse_unsigned_decimal_stops_at_suffix");
  suite.expect(TestNeuron::parseUnsignedDecimalForTest("n/a"_ctv, value) == false, "neuron_metric_helpers_parse_unsigned_decimal_rejects_invalid_input");

  suite.expect(TestNeuron::extractCpuUsageUsecForTest("user_usec 10\nusage_usec\t500000\n"_ctv, value) && value == 500'000, "neuron_metric_helpers_extract_cpu_usage_reads_usage_usec");
  suite.expect(TestNeuron::extractCpuUsageUsecForTest("usage_usec nope\n"_ctv, value) == false, "neuron_metric_helpers_extract_cpu_usage_rejects_non_numeric_value");
  suite.expect(TestNeuron::extractCpuUsageUsecForTest("user_usec 10\nsystem_usec 20\n"_ctv, value) == false, "neuron_metric_helpers_extract_cpu_usage_rejects_missing_key");

  ScopedTempDir temp = {};
  suite.expect(temp.valid(), "neuron_metric_helpers_creates_temp_root");
  if (temp.valid() == false)
  {
    return;
  }

  std::filesystem::path cgroupPath = temp.path / "cgroup";
  std::filesystem::path storagePath = temp.path / "storage";
  std::filesystem::path payloadFile = storagePath / "payload.bin";
  suite.expect(std::filesystem::create_directories(cgroupPath), "neuron_metric_helpers_creates_cgroup_dir");
  suite.expect(std::filesystem::create_directories(storagePath), "neuron_metric_helpers_creates_storage_dir");
  suite.expect(writeTextFile(cgroupPath / "cpu.stat", "usage_usec 500000\n"), "neuron_metric_helpers_writes_cpu_stat");
  suite.expect(writeTextFile(cgroupPath / "memory.current", "262144\n"), "neuron_metric_helpers_writes_memory_current");
  suite.expect(writeSizedFile(payloadFile, 524'288), "neuron_metric_helpers_writes_storage_payload");

  String missingPath = {};
  missingPath.assign((temp.path / "missing").c_str());
  suite.expect(TestNeuron::approximateDirectoryUsageBytesForTest(missingPath, value) == false, "neuron_metric_helpers_directory_usage_rejects_missing_path");

  String payloadPath = {};
  payloadPath.assign(payloadFile.c_str());
  suite.expect(TestNeuron::approximateDirectoryUsageBytesForTest(payloadPath, value) && value == 524'288, "neuron_metric_helpers_directory_usage_counts_regular_file");

  String storagePathString = {};
  storagePathString.assign(storagePath.c_str());
  suite.expect(TestNeuron::approximateDirectoryUsageBytesForTest(storagePathString, value) && value == 524'288, "neuron_metric_helpers_directory_usage_counts_directory_tree");

  int cgroupFD = ::open(cgroupPath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  suite.expect(cgroupFD >= 0, "neuron_metric_helpers_opens_synthetic_cgroup");
  if (cgroupFD < 0)
  {
    return;
  }

  Container container = {};
  container.plan.uuid = uint128_t(0x7105);
  container.plan.config.applicationID = 62'020;
  container.plan.config.versionID = 1;
  container.plan.config.nLogicalCores = 1;
  container.plan.config.memoryMB = 1;
  container.plan.config.storageMB = 1;
  container.cgroup = cgroupFD;
  container.storagePayloadPath.assign(storagePath.c_str());

  suite.expect(TestNeuron::readContainerCpuUsageUsecForTest(&container, value) && value == 500'000, "neuron_metric_helpers_reads_container_cpu_usage_usec");
  suite.expect(TestNeuron::readContainerMemoryCurrentBytesForTest(&container, value) && value == 262'144, "neuron_metric_helpers_reads_container_memory_current");

  TestNeuron::ContainerMetricSampleState sampleState = {};
  uint64_t utilPct = 0;
  suite.expect(TestNeuron::sampleContainerCpuUtilPctForTest(&container, sampleState, 1'000'000'000ULL, utilPct) == false, "neuron_metric_helpers_cpu_sampling_primes_initial_sample");
  suite.expect(sampleState.hasLastCpuUsage && sampleState.lastCpuUsageUs == 500'000, "neuron_metric_helpers_cpu_sampling_stores_initial_usage");

  sampleState.lastSampleNs = 1'000'000'000ULL;
  suite.expect(writeTextFile(cgroupPath / "cpu.stat", "usage_usec 1000000\n"), "neuron_metric_helpers_rewrites_cpu_stat");
  suite.expect(TestNeuron::sampleContainerCpuUtilPctForTest(&container, sampleState, 2'000'000'000ULL, utilPct) && utilPct == 50, "neuron_metric_helpers_cpu_sampling_computes_util_pct");
  suite.expect(TestNeuron::sampleContainerMemoryUtilPctForTest(&container, utilPct) && utilPct == 25, "neuron_metric_helpers_memory_sampling_computes_util_pct");
  suite.expect(TestNeuron::sampleContainerStorageUtilPctForTest(&container, utilPct) && utilPct == 50, "neuron_metric_helpers_storage_sampling_computes_util_pct");

  ::close(cgroupFD);
}

static void testNeuronCollectsContainerMetricsAndForwardsToBrain(TestSuite& suite)
{
  ScopedTempDir temp = {};
  suite.expect(temp.valid(), "neuron_collect_metrics_creates_temp_root");
  if (temp.valid() == false)
  {
    return;
  }

  std::filesystem::path cgroupPath = temp.path / "cgroup";
  std::filesystem::path storagePath = temp.path / "storage";
  suite.expect(std::filesystem::create_directories(cgroupPath), "neuron_collect_metrics_creates_cgroup_dir");
  suite.expect(std::filesystem::create_directories(storagePath), "neuron_collect_metrics_creates_storage_dir");
  suite.expect(writeTextFile(cgroupPath / "cpu.stat", "usage_usec 500000\n"), "neuron_collect_metrics_writes_initial_cpu_stat");
  suite.expect(writeTextFile(cgroupPath / "memory.current", "262144\n"), "neuron_collect_metrics_writes_memory_current");
  suite.expect(writeSizedFile(storagePath / "payload.bin", 524'288), "neuron_collect_metrics_writes_storage_payload");

  int cgroupFD = ::open(cgroupPath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  suite.expect(cgroupFD >= 0, "neuron_collect_metrics_opens_synthetic_cgroup");
  if (cgroupFD < 0)
  {
    return;
  }

  TestNeuron neuron = {};
  neuron.seedBrainStreamForTest(false);

  Container container = {};
  container.plan.uuid = uint128_t(0x7106);
  container.plan.config.applicationID = 62'021;
  container.plan.config.versionID = 2;
  container.plan.config.nLogicalCores = 1;
  container.plan.config.memoryMB = 1;
  container.plan.config.storageMB = 1;
  container.neuronScalingDimensionsMask =
      ProdigyMetrics::maskForScalingDimension(ScalingDimension::cpu) | ProdigyMetrics::maskForScalingDimension(ScalingDimension::memory) | ProdigyMetrics::maskForScalingDimension(ScalingDimension::storage);
  container.neuronMetricsCadenceMs = 250;
  container.cgroup = cgroupFD;
  container.storagePayloadPath.assign(storagePath.c_str());
  neuron.registerContainerForTest(&container);

  auto countMetricValue = [&](uint64_t metricKey, uint64_t expectedValue) -> uint32_t {
    uint32_t matches = 0;
    forEachMessageInBuffer(neuron.brainOutboundForTest(), [&](Message *frame) {
      if (NeuronTopic(frame->topic) != NeuronTopic::containerStatistics)
      {
        return;
      }

      uint8_t *args = frame->args;
      uint64_t observedDeploymentID = 0;
      uint128_t observedContainerUUID = 0;
      int64_t sampleTimeMs = 0;
      Message::extractArg<ArgumentNature::fixed>(args, observedDeploymentID);
      Message::extractArg<ArgumentNature::fixed>(args, observedContainerUUID);
      Message::extractArg<ArgumentNature::fixed>(args, sampleTimeMs);
      (void)observedDeploymentID;
      (void)observedContainerUUID;
      (void)sampleTimeMs;

      while (args < frame->terminal())
      {
        uint64_t observedMetricKey = 0;
        uint64_t observedMetricValue = 0;
        Message::extractArg<ArgumentNature::fixed>(args, observedMetricKey);
        Message::extractArg<ArgumentNature::fixed>(args, observedMetricValue);
        if (observedMetricKey == metricKey && observedMetricValue == expectedValue)
        {
          matches += 1;
        }
      }
    });

    return matches;
  };

  neuron.collectContainerMetricsAndForwardForTest(1'000'000'000ULL);
  suite.expect(countMetricValue(ProdigyMetrics::runtimeContainerCpuUtilPctKey(), 50) == 0, "neuron_collect_metrics_first_sample_skips_cpu_until_baseline");
  suite.expect(countMetricValue(ProdigyMetrics::runtimeContainerMemoryUtilPctKey(), 25) == 1, "neuron_collect_metrics_first_sample_emits_memory_metric");
  suite.expect(countMetricValue(ProdigyMetrics::runtimeContainerStorageUtilPctKey(), 50) == 1, "neuron_collect_metrics_first_sample_emits_storage_metric");

  neuron.brainOutboundForTest().clear();
  neuron.collectContainerMetricsAndForwardForTest(1'100'000'000ULL);
  suite.expect(neuron.brainOutboundForTest().size() == 0, "neuron_collect_metrics_respects_cadence_gate");

  suite.expect(writeTextFile(cgroupPath / "cpu.stat", "usage_usec 1000000\n"), "neuron_collect_metrics_updates_cpu_stat_for_second_sample");
  neuron.collectContainerMetricsAndForwardForTest(2'000'000'000ULL);
  suite.expect(countMetricValue(ProdigyMetrics::runtimeContainerCpuUtilPctKey(), 50) == 1, "neuron_collect_metrics_second_sample_emits_cpu_metric");
  suite.expect(countMetricValue(ProdigyMetrics::runtimeContainerMemoryUtilPctKey(), 25) == 1, "neuron_collect_metrics_second_sample_keeps_memory_metric");
  suite.expect(countMetricValue(ProdigyMetrics::runtimeContainerStorageUtilPctKey(), 50) == 1, "neuron_collect_metrics_second_sample_keeps_storage_metric");

  neuron.unregisterContainerForTest(container.plan.uuid);
  ::close(cgroupFD);
}

static void testNeuronPendingReplayHelpers(TestSuite& suite)
{
  TestNeuron neuron = {};
  Container container = {};
  container.plan.uuid = uint128_t(0x7107);
  container.plan.config.applicationID = 62'022;
  container.plan.config.versionID = 3;
  neuron.registerContainerForTest(&container);

  Container other = {};
  other.plan.uuid = uint128_t(0x7108);

  suite.expect(neuron.isTrackedContainerSocketForTest(&container), "neuron_pending_replay_tracks_registered_container");
  suite.expect(neuron.isTrackedContainerSocketForTest(&other) == false, "neuron_pending_replay_rejects_untracked_container");

  String advertisementPayload = {};
  suite.expect(
      ProdigyWire::serializeAdvertisementPairingPayload(
          advertisementPayload,
          uint128_t(0x1111),
          uint128_t(0x2222),
          uint64_t(0x3333),
          uint16_t(62'022),
          true),
      "neuron_pending_replay_serializes_advertisement_payload");
  neuron.queuePendingAdvertisementPayloadForTest(container.plan.uuid, advertisementPayload);
  neuron.queuePendingAdvertisementPayloadForTest(container.plan.uuid, advertisementPayload);
  suite.expect(neuron.pendingAdvertisementPayloadCountForTest(container.plan.uuid) == 1, "neuron_pending_replay_deduplicates_advertisement_payloads");

  String subscriptionPayload = {};
  suite.expect(
      ProdigyWire::serializeSubscriptionPairingPayload(
          subscriptionPayload,
          uint128_t(0x4444),
          uint128_t(0x5555),
          uint64_t(0x6666),
          uint16_t(8443),
          uint16_t(62'022),
          true),
      "neuron_pending_replay_serializes_subscription_payload");
  neuron.queuePendingSubscriptionPayloadForTest(container.plan.uuid, "broken"_ctv);
  neuron.queuePendingSubscriptionPayloadForTest(container.plan.uuid, subscriptionPayload);
  suite.expect(neuron.pendingSubscriptionPayloadCountForTest(container.plan.uuid) == 2, "neuron_pending_replay_queues_subscription_payloads");

  const uint128_t overflowContainerUUID = uint128_t(0x7109);
  neuron.queuePendingCredentialRefreshPayloadForTest(overflowContainerUUID, 2, "first"_ctv);
  neuron.queuePendingCredentialRefreshPayloadForTest(overflowContainerUUID, 2, "second"_ctv);
  neuron.queuePendingCredentialRefreshPayloadForTest(overflowContainerUUID, 2, "third"_ctv);
  suite.expect(neuron.pendingCredentialRefreshPayloadCountForTest(overflowContainerUUID) == 2, "neuron_pending_replay_caps_credential_payload_queue");

  CredentialDelta delta = {};
  delta.bundleGeneration = 9;
  delta.reason.assign("rotate"_ctv);
  ApiCredential api = {};
  api.name.assign("token"_ctv);
  api.provider.assign("example"_ctv);
  api.generation = 1;
  api.material.assign("secret-token"_ctv);
  delta.updatedApi.push_back(api);
  delta.updatedResumptionSnapshots.push_back(makeTlsResumptionTestSnapshot("pending-quic"_ctv, 77, TlsResumptionKeyRole::issueAndAccept));

  String credentialPayload = {};
  suite.expect(ProdigyWire::serializeCredentialDelta(credentialPayload, delta), "neuron_pending_replay_serializes_credential_delta");
  neuron.queuePendingCredentialRefreshPayloadForTest(container.plan.uuid, 2, credentialPayload);
  neuron.queuePendingCredentialRefreshPayloadForTest(container.plan.uuid, 2, credentialPayload);
  suite.expect(neuron.pendingCredentialRefreshPayloadCountForTest(container.plan.uuid) == 1, "neuron_pending_replay_deduplicates_credential_payloads");

  neuron.applyPendingPairingsForTest(&container);
  neuron.applyPendingCredentialRefreshesForTest(&container);

  suite.expect(neuron.pendingAdvertisementPayloadCountForTest(container.plan.uuid) == 0, "neuron_pending_replay_clears_advertisement_queue_after_apply");
  suite.expect(neuron.pendingSubscriptionPayloadCountForTest(container.plan.uuid) == 0, "neuron_pending_replay_clears_subscription_queue_after_apply");
  suite.expect(neuron.pendingCredentialRefreshPayloadCountForTest(container.plan.uuid) == 0, "neuron_pending_replay_clears_credential_queue_after_apply");

  auto advertisementIt = container.plan.advertisementPairings.find(uint64_t(0x3333));
  suite.expect(
      advertisementIt != container.plan.advertisementPairings.end() && advertisementIt->second.size() == 1 && advertisementIt->second[0].secret == uint128_t(0x1111),
      "neuron_pending_replay_applies_advertisement_pairing");

  auto subscriptionIt = container.plan.subscriptionPairings.find(uint64_t(0x6666));
  suite.expect(
      subscriptionIt != container.plan.subscriptionPairings.end() && subscriptionIt->second.size() == 1 && subscriptionIt->second[0].port == 8443,
      "neuron_pending_replay_applies_subscription_pairing");

  suite.expect(container.plan.hasCredentialBundle, "neuron_pending_replay_marks_credential_bundle_present");
  suite.expect(
      container.plan.credentialBundle.apiCredentials.size() == 1 && container.plan.credentialBundle.apiCredentials[0].name.equals("token"_ctv) && container.plan.credentialBundle.apiCredentials[0].material.equals("secret-token"_ctv),
      "neuron_pending_replay_applies_credential_refresh");
  suite.expect(
      container.plan.credentialBundle.tlsResumptionSnapshots.size() == 1 &&
          container.plan.credentialBundle.tlsResumptionSnapshots[0].wormholeName.equals("pending-quic"_ctv) &&
          container.plan.credentialBundle.tlsResumptionSnapshots[0].generation == 77 &&
          tlsResumptionSnapshotHasEpochRole(&container.plan.credentialBundle.tlsResumptionSnapshots[0], 77, TlsResumptionKeyRole::issueAndAccept),
      "neuron_pending_replay_applies_tls_resumption_refresh");

  uint32_t advertisementFrames = 0;
  uint32_t subscriptionFrames = 0;
  uint32_t credentialFrames = 0;
  forEachMessageInBuffer(container.wBuffer, [&](Message *frame) {
    if (ContainerTopic(frame->topic) == ContainerTopic::advertisementPairing)
    {
      advertisementFrames += 1;
    }
    else if (ContainerTopic(frame->topic) == ContainerTopic::subscriptionPairing)
    {
      subscriptionFrames += 1;
    }
    else if (ContainerTopic(frame->topic) == ContainerTopic::credentialsRefresh)
    {
      credentialFrames += 1;
    }
  });

  suite.expect(advertisementFrames == 1, "neuron_pending_replay_emits_advertisement_frame");
  suite.expect(subscriptionFrames == 1, "neuron_pending_replay_emits_subscription_frame");
  suite.expect(credentialFrames == 1, "neuron_pending_replay_emits_credential_refresh_frame");
}

static void testNeuronExtractFixedArgBoundedHelpers(TestSuite& suite)
{
  alignas(uint64_t) uint8_t buffer[32] = {};
  uint64_t expected = 0x1122334455667788ULL;
  std::memcpy(buffer + 8, &expected, sizeof(expected));

  uint8_t *cursor = buffer + 1;
  uint64_t value = 0;
  suite.expect(TestNeuron::extractFixedArgBoundedForTest(cursor, buffer + sizeof(buffer), value), "neuron_extract_fixed_arg_bounded_aligns_forward");
  suite.expect(value == expected, "neuron_extract_fixed_arg_bounded_reads_value");
  suite.expect(cursor == buffer + 8 + sizeof(expected), "neuron_extract_fixed_arg_bounded_advances_cursor");

  cursor = buffer + 1;
  value = 0;
  suite.expect(TestNeuron::extractFixedArgBoundedForTest(cursor, buffer + 15, value) == false, "neuron_extract_fixed_arg_bounded_rejects_truncated_aligned_value");

  cursor = buffer + sizeof(buffer) - 1;
  value = 0;
  suite.expect(TestNeuron::extractFixedArgBoundedForTest(cursor, buffer + sizeof(buffer) - 1, value) == false, "neuron_extract_fixed_arg_bounded_rejects_terminal_before_value");
}

static void testNeuronTimeoutHandlerPaths(TestSuite& suite)
{
  {
    TestNeuron neuron = {};
    neuron.timeoutHandlerForTest(nullptr, 0);
    suite.expect(true, "neuron_timeout_handler_accepts_null_packet");
  }

  {
    ScopedRing scopedRing = {};

    TestNeuron neuron = {};
    Container active = {};
    active.plan.uuid = uint128_t(0x7111);
    active.neuronScalingDimensionsMask = ProdigyMetrics::maskForScalingDimension(ScalingDimension::memory);
    active.neuronMetricsCadenceMs = 250;
    neuron.registerContainerForTest(&active);
    neuron.ensureMetricsTickQueuedForTest();
    suite.expect(neuron.metricsTickQueuedForTest(), "neuron_timeout_handler_fixture_queues_metrics_tick");

    neuron.timeoutMetricsTickForTest(-ECANCELED);
    suite.expect(neuron.metricsTickQueuedForTest() == false, "neuron_timeout_handler_canceled_metrics_tick_stays_disarmed");

    neuron.ensureMetricsTickQueuedForTest();
    suite.expect(neuron.metricsTickQueuedForTest(), "neuron_timeout_handler_requeues_metrics_tick_fixture");
    neuron.timeoutMetricsTickForTest(0);
    suite.expect(neuron.metricsTickQueuedForTest(), "neuron_timeout_handler_metrics_tick_rearms_when_metrics_active");

    neuron.unregisterContainerForTest(active.plan.uuid);
  }

  {
    ScopedRing scopedRing = {};

    TestNeuron neuron = {};
    neuron.ensureFailedContainerArtifactGCTickQueuedForTest();
    suite.expect(neuron.failedContainerArtifactGCTickQueuedForTest(), "neuron_timeout_handler_queues_failed_container_artifact_gc_tick");
    suite.expect(neuron.failedContainerArtifactGCTickFlagsForTest() == uint64_t(NeuronTimeoutFlags::logGC), "neuron_timeout_handler_sets_failed_container_artifact_gc_flag");
    suite.expect(neuron.failedContainerArtifactGCTickTimeoutMsForTest() == failedContainerArtifactCleanupIntervalMs, "neuron_timeout_handler_sets_failed_container_artifact_gc_timeout");

    neuron.timeoutFailedContainerArtifactGCTickForTest(-ECANCELED);
    suite.expect(neuron.failedContainerArtifactGCTickQueuedForTest() == false, "neuron_timeout_handler_canceled_failed_container_artifact_gc_tick_stays_disarmed");

    neuron.ensureFailedContainerArtifactGCTickQueuedForTest();
    suite.expect(neuron.failedContainerArtifactGCTickQueuedForTest(), "neuron_timeout_handler_requeues_failed_container_artifact_gc_tick_fixture");
    neuron.timeoutFailedContainerArtifactGCTickForTest(0);
    suite.expect(neuron.failedContainerArtifactGCTickQueuedForTest(), "neuron_timeout_handler_failed_container_artifact_gc_tick_rearms");
  }

  {
    TestNeuron neuron = {};
    TimeoutPacket *packet = new TimeoutPacket();
    packet->flags = uint64_t(NeuronTimeoutFlags::killContainer);
    packet->identifier = uint128_t(0x7112);

    Container container = {};
    container.plan.uuid = packet->identifier;
    container.killSwitch = packet;
    neuron.registerContainerForTest(&container);

    neuron.timeoutHandlerForTest(packet, -ECANCELED);
    suite.expect(container.killSwitch == nullptr, "neuron_timeout_handler_canceled_kill_container_clears_kill_switch");

    neuron.unregisterContainerForTest(container.plan.uuid);
  }

  {
    TestNeuron neuron = {};
    TimeoutPacket *packet = new TimeoutPacket();
    packet->flags = uint64_t(NeuronTimeoutFlags::killContainer);
    packet->identifier = uint128_t(0x7113);

    Container container = {};
    container.plan.uuid = packet->identifier;
    container.pid = 999'999;
    container.killSwitch = packet;
    neuron.registerContainerForTest(&container);

    neuron.timeoutHandlerForTest(packet, 0);
    suite.expect(container.killSwitch == nullptr, "neuron_timeout_handler_kill_container_clears_kill_switch");

    neuron.unregisterContainerForTest(container.plan.uuid);
  }
}

static void testNeuronStreamStateHelpers(TestSuite& suite)
{
  {
    if (Ring::getRingFD() > 0)
    {
      Ring::shutdownForExec();
    }
    Ring::createRing(8, 8, 32, 32, -1, -1, 0);

    NeuronBrainControlStream stream = {};
    ScopedEventFD closingFD = {};
    if (closingFD.create(suite, "neuron_stream_helpers_close_fixture_created"))
    {
      stream.fd = closingFD.take();
      stream.isFixedFile = false;
      stream.connected = false;

      suite.expect(TestNeuron::rawBrainStreamIsActiveForTest(nullptr) == false, "neuron_stream_helpers_raw_null_inactive");
      suite.expect(TestNeuron::rawBrainStreamIsActiveForTest(&stream), "neuron_stream_helpers_raw_direct_fd_active");
      suite.expect(TestNeuron::brainStreamIsActiveForTest(&stream) == false, "neuron_stream_helpers_brain_requires_connected_flag");

      stream.connected = true;
      suite.expect(TestNeuron::brainStreamIsActiveForTest(&stream), "neuron_stream_helpers_brain_connected_direct_fd_active");

      TestNeuron::queueCloseBrainStreamIfActiveForTest(&stream);
      suite.expect(TestNeuron::rawBrainStreamIsActiveForTest(&stream) == false, "neuron_stream_helpers_closed_direct_fd_inactive");
    }
    Ring::shutdownForExec();
    Ring::createRing(8, 8, 32, 32, -1, -1, 0);
    if (stream.fd >= 0)
    {
      close(stream.fd);
      stream.fd = -1;
    }

    stream = {};
    stream.connected = true;
    stream.isFixedFile = true;
    stream.fslot = 4;
    suite.expect(TestNeuron::rawBrainStreamIsActiveForTest(&stream), "neuron_stream_helpers_raw_fixed_file_active");
    suite.expect(TestNeuron::brainStreamIsActiveForTest(&stream), "neuron_stream_helpers_brain_fixed_file_connected_active");

    stream.fslot = -1;
    suite.expect(TestNeuron::rawBrainStreamIsActiveForTest(&stream) == false, "neuron_stream_helpers_raw_fixed_file_without_slot_inactive");
  }

  {
    Container container = {};
    container.fd = 12;
    container.isFixedFile = false;
    suite.expect(TestNeuron::containerStreamIsActiveForTest(&container), "neuron_stream_helpers_container_direct_fd_active");

    Container fixedFileContainer = {};
    fixedFileContainer.isFixedFile = true;
    fixedFileContainer.fslot = 5;
    suite.expect(TestNeuron::rawContainerStreamIsActiveForTest(&fixedFileContainer), "neuron_stream_helpers_container_raw_fixed_file_active");
    suite.expect(TestNeuron::containerStreamIsActiveForTest(&fixedFileContainer), "neuron_stream_helpers_container_fixed_file_active");

    fixedFileContainer.fslot = -1;
    suite.expect(TestNeuron::rawContainerStreamIsActiveForTest(&fixedFileContainer) == false, "neuron_stream_helpers_container_raw_fixed_file_without_slot_inactive");
    suite.expect(TestNeuron::containerStreamIsActiveForTest(&fixedFileContainer) == false, "neuron_stream_helpers_container_fixed_file_without_slot_inactive");

    container.fd = -1;
    suite.expect(TestNeuron::containerStreamIsActiveForTest(&container) == false, "neuron_stream_helpers_container_no_fd_inactive");
  }

  {
    ScopedRing scopedRing = {};

    NeuronBrainControlStream stream = {};
    ScopedEventFD brainEvent = {};
    if (brainEvent.create(suite, "neuron_stream_helpers_eventfd_fixture_created"))
    {
      stream.fd = brainEvent.take();
      stream.isFixedFile = false;
      stream.connected = true;
      TestNeuron::queueCloseBrainStreamIfActiveForTest(&stream);
      suite.expect(Ring::socketIsClosing(&stream), "neuron_stream_helpers_queue_close_marks_brain_stream_closing");
      close(stream.fd);
      stream.fd = -1;
    }

    Container container = {};
    ScopedEventFD containerEvent = {};
    if (containerEvent.create(suite, "neuron_stream_helpers_container_eventfd_fixture_created"))
    {
      container.fd = containerEvent.take();
      container.isFixedFile = false;
      TestNeuron::queueCloseContainerStreamIfActiveForTest(&container);
      suite.expect(Ring::socketIsClosing(&container), "neuron_stream_helpers_queue_close_marks_container_stream_closing");
      close(container.fd);
      container.fd = -1;
    }
  }
}

static void testNeuronBrainControlAndDeferredInventoryHelpers(TestSuite& suite)
{
  {
    NeuronBrainControlStream stream = {};
    stream.connected = true;
    stream.initialMachineHardwareProfileQueued = true;
    stream.fd = 33;
    stream.isFixedFile = true;
    stream.fslot = 7;
    stream.reset();
    suite.expect(stream.connected == false, "neuron_brain_control_reset_clears_connected");
    suite.expect(stream.initialMachineHardwareProfileQueued == false, "neuron_brain_control_reset_clears_initial_profile_flag");
  }

  {
    TestNeuron neuron = {};
    suite.expect(TestNeuron::verifyBrainTransportTLSPeerForTest(neuron), "neuron_verify_brain_transport_tls_peer_accepts_missing_brain");

    neuron.seedBrainStreamForTest(true);
    suite.expect(TestNeuron::verifyBrainTransportTLSPeerForTest(neuron), "neuron_verify_brain_transport_tls_peer_accepts_non_tls_stream");
  }

  {
    TestNeuron neuron = {};
    suite.expect(neuron.latestHardwareProfileIfReadyForTest() == nullptr, "neuron_hardware_profile_ready_returns_null_before_inventory_complete");

    String outbound = {};
    suite.expect(neuron.appendMachineHardwareProfileFrameIfReadyForTest(outbound) == false, "neuron_hardware_profile_frame_requires_serialized_profile");

    MachineHardwareProfile hardware = {};
    hardware.inventoryComplete = true;
    hardware.cpu.logicalCores = 16;
    hardware.memory.totalMB = 32'768;
    String serialized = {};
    serialized.assign("serialized-hardware"_ctv);
    neuron.seedHardwareProfileForTest(hardware, serialized);

    suite.expect(neuron.latestHardwareProfileIfReadyForTest() != nullptr, "neuron_hardware_profile_ready_returns_pointer_after_inventory_complete");
    suite.expect(neuron.appendMachineHardwareProfileFrameIfReadyForTest(outbound), "neuron_hardware_profile_frame_appends_when_serialized_profile_present");

    uint32_t profileFrames = 0;
    forEachMessageInBuffer(outbound, [&](Message *frame) {
      if (NeuronTopic(frame->topic) == NeuronTopic::machineHardwareProfile)
      {
        profileFrames += 1;
      }
    });
    suite.expect(profileFrames == 1, "neuron_hardware_profile_frame_emits_single_frame");
  }

  {
    TestNeuron neuron = {};
    suite.expect(neuron.deferredHardwareInventoryInFlightForTest() == false, "neuron_deferred_inventory_progress_starts_not_in_flight");
    neuron.ensureDeferredHardwareInventoryProgressForTest();
    suite.expect(neuron.deferredHardwareInventoryInFlightForTest() == false, "neuron_deferred_inventory_progress_without_ready_state_stays_idle");
  }

  {
    ScopedRing scopedRing = {};

    TestNeuron neuron = {};
    ScopedEventFD wake = {};
    if (wake.create(suite, "neuron_deferred_inventory_wake_creates_eventfd"))
    {
      int wakeFD = wake.take();
      neuron.setDeferredHardwareInventoryWakeFDForTest(wakeFD);
      suite.expect(neuron.deferredHardwareInventoryWakePollQueuedForTest() == false, "neuron_deferred_inventory_wake_poll_starts_disarmed");
      neuron.armDeferredHardwareInventoryWakePollForTest();
      suite.expect(neuron.deferredHardwareInventoryWakePollQueuedForTest(), "neuron_deferred_inventory_wake_poll_arms_once");
      uint64_t signal = 3;
      suite.expect(write(wakeFD, &signal, sizeof(signal)) == ssize_t(sizeof(signal)), "neuron_deferred_inventory_wake_writes_signal");
      neuron.drainDeferredHardwareInventoryWakeForTest();
      uint64_t leftover = 0;
      suite.expect(read(wakeFD, &leftover, sizeof(leftover)) == -1 && errno == EAGAIN, "neuron_deferred_inventory_wake_drain_consumes_all_signals");
      close(wakeFD);
    }
  }
}

static void testNeuronTransportTLSPeerVerificationGatesHardwareProfileQueueing(TestSuite& suite)
{
  constexpr uint128_t brainUUID = uint128_t(0xB10A);
  constexpr uint128_t neuronUUID = uint128_t(0xE2020);

  BrainTransportTLSFixture fixture(
      suite,
      "neuron_transport_tls",
      brainUUID,
      neuronUUID,
      "fd00::10",
      "fd00::20");
  if (fixture.ready == false)
  {
    return;
  }

  MachineHardwareProfile hardware = {};
  hardware.inventoryComplete = true;
  hardware.cpu.logicalCores = 8;
  hardware.memory.totalMB = 16'384;

  String serializedHardware = {};
  BitseryEngine::serialize(serializedHardware, hardware);
  fixture.neuron.adoptHardwareInventoryForTest(hardware, serializedHardware);

  suite.expect(
      fixture.neuron.queueMachineHardwareProfileToBrainIfReadyForTest("tls-unverified") == false,
      "neuron_transport_tls_hardware_profile_waits_for_peer_verification");
  suite.expect(
      fixture.neuron.brainInitialMachineHardwareProfileQueuedForTest() == false,
      "neuron_transport_tls_hardware_profile_flag_stays_clear_before_peer_verification");

  if (fixture.completeHandshake(suite, "complete_handshake") == false)
  {
    return;
  }

  fixture.neuron.brainOutboundForTest().clear();
  uint32_t bytesQueuedBeforeVerify = fixture.neuron.brainStreamForTest()->nBytesToSend();
  suite.expect(
      TestNeuron::verifyBrainTransportTLSPeerForTest(fixture.neuron),
      "neuron_transport_tls_verify_peer_after_handshake");
  suite.expect(
      fixture.neuron.brainStreamForTest()->tlsPeerVerified,
      "neuron_transport_tls_marks_peer_verified");
  suite.expect(
      fixture.neuron.brainStreamForTest()->tlsPeerUUID == brainUUID,
      "neuron_transport_tls_preserves_peer_uuid");

  suite.expect(
      fixture.neuron.brainInitialMachineHardwareProfileQueuedForTest(),
      "neuron_transport_tls_hardware_profile_flag_sets_during_peer_verification");
  suite.expect(
      fixture.neuron.brainStreamForTest()->nBytesToSend() > bytesQueuedBeforeVerify,
      "neuron_transport_tls_hardware_profile_queues_send_bytes_during_verification");
}

static void testNeuronMachineHardwareProfileTransportStripsCaptures(TestSuite& suite)
{
  MachineHardwareProfile hardware = {};
  hardware.inventoryComplete = true;
  hardware.cpu.logicalCores = 8;
  hardware.memory.totalMB = 16'384;

  MachineToolCapture capture = {};
  capture.tool.assign("tool"_ctv);
  capture.phase.assign("phase"_ctv);
  capture.command.assign("cmd"_ctv);
  for (uint32_t i = 0; i < 4096; ++i)
  {
    capture.output.append('x');
  }
  capture.attempted = true;
  capture.succeeded = true;

  hardware.captures.push_back(capture);
  hardware.cpu.captures.push_back(capture);
  hardware.memory.captures.push_back(capture);

  MachineDiskHardwareProfile disk = {};
  disk.sizeMB = 102'400;
  disk.captures.push_back(capture);
  disk.benchmark.captures.push_back(capture);
  hardware.disks.push_back(disk);

  MachineNicHardwareProfile nic = {};
  nic.name.assign("bond0"_ctv);
  nic.captures.push_back(capture);
  hardware.network.captures.push_back(capture);
  hardware.network.internet.captures.push_back(capture);
  hardware.network.nics.push_back(nic);

  MachineGpuHardwareProfile gpu = {};
  gpu.vendor.assign("nvidia"_ctv);
  gpu.model.assign("stub"_ctv);
  gpu.captures.push_back(capture);
  hardware.gpus.push_back(gpu);

  String rawSerialized = {};
  BitseryEngine::serialize(rawSerialized, hardware);

  String transportSerialized = {};
  TestNeuron::serializeMachineHardwareProfileForBrainTransportForTest(hardware, transportSerialized);
  suite.expect(
      transportSerialized.size() < rawSerialized.size(),
      "neuron_machine_hardware_transport_strips_captures_reduces_payload_size");

  MachineHardwareProfile roundtrip = {};
  suite.expect(
      BitseryEngine::deserializeSafe(transportSerialized, roundtrip),
      "neuron_machine_hardware_transport_strips_captures_roundtrips");
  suite.expect(roundtrip.inventoryComplete, "neuron_machine_hardware_transport_strips_captures_preserves_inventory_complete");
  suite.expect(roundtrip.cpu.logicalCores == hardware.cpu.logicalCores, "neuron_machine_hardware_transport_strips_captures_preserves_cpu_cores");
  suite.expect(roundtrip.memory.totalMB == hardware.memory.totalMB, "neuron_machine_hardware_transport_strips_captures_preserves_memory_total");
  suite.expect(roundtrip.captures.empty(), "neuron_machine_hardware_transport_strips_captures_clears_global_captures");
  suite.expect(roundtrip.cpu.captures.empty(), "neuron_machine_hardware_transport_strips_captures_clears_cpu_captures");
  suite.expect(roundtrip.memory.captures.empty(), "neuron_machine_hardware_transport_strips_captures_clears_memory_captures");
  suite.expect(roundtrip.disks.size() == 1, "neuron_machine_hardware_transport_strips_captures_preserves_disk_inventory");
  suite.expect(roundtrip.disks[0].captures.empty(), "neuron_machine_hardware_transport_strips_captures_clears_disk_captures");
  suite.expect(roundtrip.disks[0].benchmark.captures.empty(), "neuron_machine_hardware_transport_strips_captures_clears_disk_benchmark_captures");
  suite.expect(roundtrip.network.captures.empty(), "neuron_machine_hardware_transport_strips_captures_clears_network_captures");
  suite.expect(roundtrip.network.internet.captures.empty(), "neuron_machine_hardware_transport_strips_captures_clears_internet_captures");
  suite.expect(roundtrip.network.nics.size() == 1, "neuron_machine_hardware_transport_strips_captures_preserves_nic_inventory");
  suite.expect(roundtrip.network.nics[0].captures.empty(), "neuron_machine_hardware_transport_strips_captures_clears_nic_captures");
  suite.expect(roundtrip.gpus.size() == 1, "neuron_machine_hardware_transport_strips_captures_preserves_gpu_inventory");
  suite.expect(roundtrip.gpus[0].captures.empty(), "neuron_machine_hardware_transport_strips_captures_clears_gpu_captures");
}

static void testNeuronTransportTLSPeerVerificationAdoptsDeferredHardwareInventory(TestSuite& suite)
{
  constexpr uint128_t brainUUID = uint128_t(0xB10B);
  constexpr uint128_t neuronUUID = uint128_t(0xE2029);

  BrainTransportTLSFixture fixture(
      suite,
      "neuron_transport_tls_deferred_hardware",
      brainUUID,
      neuronUUID,
      "fd00::12",
      "fd00::22");
  if (fixture.ready == false)
  {
    return;
  }

  MachineHardwareProfile hardware = {};
  hardware.inventoryComplete = true;
  hardware.cpu.logicalCores = 16;
  hardware.memory.totalMB = 32'768;

  String serializedHardware = {};
  BitseryEngine::serialize(serializedHardware, hardware);
  fixture.neuron.seedDeferredHardwareInventoryReadyForTest(hardware, serializedHardware);

  suite.expect(
      fixture.neuron.latestHardwareProfileIfReadyForTest() == nullptr,
      "neuron_transport_tls_deferred_hardware_starts_unadopted");
  suite.expect(
      fixture.neuron.brainInitialMachineHardwareProfileQueuedForTest() == false,
      "neuron_transport_tls_deferred_hardware_flag_starts_clear");

  if (fixture.completeHandshake(suite, "complete_handshake") == false)
  {
    return;
  }

  fixture.neuron.brainOutboundForTest().clear();
  uint32_t bytesQueuedBeforeVerify = fixture.neuron.brainStreamForTest()->nBytesToSend();
  suite.expect(
      TestNeuron::verifyBrainTransportTLSPeerForTest(fixture.neuron),
      "neuron_transport_tls_deferred_hardware_verify_peer");
  suite.expect(
      fixture.neuron.brainInitialMachineHardwareProfileQueuedForTest(),
      "neuron_transport_tls_deferred_hardware_sets_queue_flag");
  suite.expect(
      fixture.neuron.deferredHardwareInventoryInFlightForTest() == false,
      "neuron_transport_tls_deferred_hardware_clears_inflight_after_adoption");
  suite.expect(
      fixture.neuron.latestHardwareProfileIfReadyForTest() != nullptr,
      "neuron_transport_tls_deferred_hardware_adopts_ready_inventory_during_verification");
  suite.expect(
      fixture.neuron.brainStreamForTest()->nBytesToSend() > bytesQueuedBeforeVerify,
      "neuron_transport_tls_deferred_hardware_queues_send_bytes_during_verification");

  fixture.brainClient.rBuffer.clear();
  uint32_t hardwareFrames = 0;
  String payload = {};
  for (uint32_t round = 0; round < 8 && hardwareFrames == 0; ++round)
  {
    bool progressed = false;
    progressed = pumpTransportBytes(*fixture.neuron.brainStreamForTest(), fixture.brainClient) || progressed;
    progressed = pumpTransportBytes(fixture.brainClient, *fixture.neuron.brainStreamForTest()) || progressed;

    hardwareFrames = 0;
    payload.clear();
    forEachMessageInBuffer(fixture.brainClient.rBuffer, [&](Message *message) {
      if (NeuronTopic(message->topic) == NeuronTopic::machineHardwareProfile)
      {
        hardwareFrames += 1;
        uint8_t *args = message->args;
        Message::extractToStringView(args, payload);
      }
    });

    if (progressed == false)
    {
      break;
    }
  }

  suite.expect(
      hardwareFrames == 1,
      "neuron_transport_tls_deferred_hardware_emits_single_machine_hardware_profile");
  suite.expect(
      payload.equals(serializedHardware),
      "neuron_transport_tls_deferred_hardware_preserves_serialized_payload");
}

static void testNeuronTransportTLSPeerVerificationRejectsPeerWithoutTransportUUID(TestSuite& suite)
{
  constexpr uint128_t brainUUID = uint128_t(0xBAD1);
  constexpr uint128_t neuronUUID = uint128_t(0xE2021);

  BrainTransportTLSFixture fixture(
      suite,
      "neuron_transport_tls_missing_uuid",
      brainUUID,
      neuronUUID,
      "fd00::11",
      "fd00::21",
      BrainTransportTLSPeerMode::missingUUID);
  if (fixture.ready == false)
  {
    return;
  }

  MachineHardwareProfile hardware = {};
  hardware.inventoryComplete = true;
  hardware.cpu.logicalCores = 8;
  hardware.memory.totalMB = 16'384;

  String serializedHardware = {};
  BitseryEngine::serialize(serializedHardware, hardware);
  fixture.neuron.adoptHardwareInventoryForTest(hardware, serializedHardware);

  if (fixture.completeHandshake(suite, "complete_handshake") == false)
  {
    return;
  }

  fixture.neuron.brainOutboundForTest().clear();
  uint32_t bytesQueuedBeforeVerify = fixture.neuron.brainStreamForTest()->nBytesToSend();

  suite.expect(
      TestNeuron::verifyBrainTransportTLSPeerForTest(fixture.neuron) == false,
      "neuron_transport_tls_missing_uuid_rejects_peer");
  suite.expect(
      fixture.neuron.brainStreamForTest()->tlsPeerVerified == false,
      "neuron_transport_tls_missing_uuid_keeps_peer_unverified");
  suite.expect(
      fixture.neuron.brainStreamForTest()->tlsPeerUUID == 0,
      "neuron_transport_tls_missing_uuid_keeps_peer_uuid_zero");
  suite.expect(
      fixture.neuron.brainInitialMachineHardwareProfileQueuedForTest() == false,
      "neuron_transport_tls_missing_uuid_does_not_queue_hardware_profile");
  suite.expect(
      fixture.neuron.brainStreamForTest()->nBytesToSend() == bytesQueuedBeforeVerify,
      "neuron_transport_tls_missing_uuid_leaves_pending_send_bytes_unchanged");
}

static void testNeuronTransportTLSPeerVerificationWaitsForNegotiation(TestSuite& suite)
{
  constexpr uint128_t brainUUID = uint128_t(0xB2020);
  constexpr uint128_t neuronUUID = uint128_t(0xE2022);

  BrainTransportTLSFixture fixture(
      suite,
      "neuron_transport_tls_unnegotiated",
      brainUUID,
      neuronUUID,
      "fd00::12",
      "fd00::22");
  if (fixture.ready == false)
  {
    return;
  }

  MachineHardwareProfile hardware = {};
  hardware.inventoryComplete = true;
  hardware.cpu.logicalCores = 4;
  hardware.memory.totalMB = 8192;

  String serializedHardware = {};
  BitseryEngine::serialize(serializedHardware, hardware);
  fixture.neuron.adoptHardwareInventoryForTest(hardware, serializedHardware);
  fixture.neuron.brainOutboundForTest().clear();

  uint32_t bytesQueuedBeforeVerify = fixture.neuron.brainStreamForTest()->nBytesToSend();
  suite.expect(
      TestNeuron::verifyBrainTransportTLSPeerForTest(fixture.neuron),
      "neuron_transport_tls_unnegotiated_verify_returns_true");
  suite.expect(
      fixture.neuron.brainStreamForTest()->tlsPeerVerified == false,
      "neuron_transport_tls_unnegotiated_keeps_peer_unverified");
  suite.expect(
      fixture.neuron.brainStreamForTest()->tlsPeerUUID == 0,
      "neuron_transport_tls_unnegotiated_keeps_peer_uuid_zero");
  suite.expect(
      fixture.neuron.brainInitialMachineHardwareProfileQueuedForTest() == false,
      "neuron_transport_tls_unnegotiated_does_not_queue_hardware_profile");
  suite.expect(
      fixture.neuron.brainStreamForTest()->nBytesToSend() == bytesQueuedBeforeVerify,
      "neuron_transport_tls_unnegotiated_leaves_pending_send_bytes_unchanged");
}

static void testNeuronTransportTLSRecvHandlerRejectsMissingUUIDPeer(TestSuite& suite)
{
  constexpr uint128_t brainUUID = uint128_t(0xBAD2);
  constexpr uint128_t neuronUUID = uint128_t(0xE3103);

  BrainTransportTLSFixture fixture(
      suite,
      "neuron_transport_tls_recv_missing_uuid",
      brainUUID,
      neuronUUID,
      "fd00::33",
      "fd00::34",
      BrainTransportTLSPeerMode::missingUUID,
      true);
  if (fixture.ready == false)
  {
    return;
  }

  if (fixture.completeHandshake(suite) == false)
  {
    return;
  }

  fixture.neuron.brainOutboundForTest().clear();
  Message::construct(fixture.brainClient.wBuffer, NeuronTopic::killContainer, uint128_t(0xD00D));
  uint32_t encryptedBytes = 0;
  suite.expect(
      copyEncryptedTransportBytes(fixture.brainClient, fixture.neuron.brainStreamForTest()->rBuffer, encryptedBytes),
      "neuron_transport_tls_recv_missing_uuid_encrypts_brain_message");
  suite.expect(encryptedBytes > 0, "neuron_transport_tls_recv_missing_uuid_encrypted_message_nonempty");
  fixture.neuron.brainStreamForTest()->pendingRecv = true;

  fixture.neuron.recvSocketForTest(fixture.neuron.brainStreamForTest(), int(encryptedBytes));

  suite.expect(fixture.neuron.brainStreamForTest()->tlsPeerVerified == false, "neuron_transport_tls_recv_missing_uuid_keeps_peer_unverified");
  suite.expect(fixture.neuron.brainStreamForTest()->tlsPeerUUID == 0, "neuron_transport_tls_recv_missing_uuid_keeps_peer_uuid_zero");
  suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()), "neuron_transport_tls_recv_missing_uuid_closes_stream");
  suite.expect(fixture.neuron.brainOutboundForTest().size() == 0, "neuron_transport_tls_recv_missing_uuid_emits_no_outbound_frames");
}

static void testNeuronTransportTLSBrainRecvAndSendHandlers(TestSuite& suite)
{
  constexpr uint128_t brainUUID = uint128_t(0xB2021);
  constexpr uint128_t neuronUUID = uint128_t(0xE2023);

  BrainTransportTLSFixture fixture(
      suite,
      "neuron_transport_tls_handlers",
      brainUUID,
      neuronUUID,
      "fd00::31",
      "fd00::32",
      BrainTransportTLSPeerMode::validUUID,
      true);
  if (fixture.ready == false)
  {
    return;
  }

  if (fixture.completeHandshake(suite) == false)
  {
    return;
  }

  suite.expect(fixture.brainClient.isTLSNegotiated(), "neuron_transport_tls_handlers_client_negotiated");
  suite.expect(fixture.neuron.brainStreamForTest()->isTLSNegotiated(), "neuron_transport_tls_handlers_server_negotiated");

  MachineHardwareProfile hardware = {};
  hardware.inventoryComplete = true;
  hardware.cpu.logicalCores = 12;
  hardware.memory.totalMB = 24'576;

  String serializedHardware = {};
  BitseryEngine::serialize(serializedHardware, hardware);
  fixture.neuron.adoptHardwareInventoryForTest(hardware, serializedHardware);

  fixture.brainClient.rBuffer.clear();
  fixture.neuron.brainStreamForTest()->rBuffer.clear();
  fixture.neuron.brainOutboundForTest().clear();

  String plaintextInbound = {};
  buildNeuronMessage(plaintextInbound, NeuronTopic::killContainer, uint128_t(0xC0FFEE));
  fixture.brainClient.wBuffer.append(plaintextInbound);

  uint32_t encryptedBytes = 0;
  suite.expect(
      copyEncryptedTransportBytes(fixture.brainClient, fixture.neuron.brainStreamForTest()->rBuffer, encryptedBytes),
      "neuron_transport_tls_handlers_copy_ciphertext");
  suite.expect(encryptedBytes > 0, "neuron_transport_tls_handlers_ciphertext_has_bytes");

  fixture.neuron.brainStreamForTest()->pendingRecv = true;
  suite.expect(fixture.neuron.brainStreamForTest()->tlsPeerVerified == false, "neuron_transport_tls_handlers_peer_unverified_before_recv");

  uint32_t dispatchCount = 0;
  fixture.neuron.recvBrainForTest(encryptedBytes, [&](Message *message) {
    dispatchCount += 1;
    fixture.neuron.dispatchBrainMessageForTest(message);
  });

  suite.expect(dispatchCount == 1, "neuron_transport_tls_handlers_recv_dispatches_single_message");
  suite.expect(fixture.neuron.brainStreamForTest()->tlsPeerVerified, "neuron_transport_tls_handlers_recv_verifies_peer");
  suite.expect(fixture.neuron.brainStreamForTest()->tlsPeerUUID == brainUUID, "neuron_transport_tls_handlers_recv_records_peer_uuid");
  suite.expect(fixture.neuron.brainStreamForTest()->pendingRecv, "neuron_transport_tls_handlers_recv_rearms_recv");
  suite.expect(fixture.neuron.brainStreamForTest()->pendingSend, "neuron_transport_tls_handlers_recv_kicks_send");
  suite.expect(fixture.neuron.brainStreamForTest()->pendingSendBytes > 0, "neuron_transport_tls_handlers_recv_tracks_send_bytes");
  suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()) == false, "neuron_transport_tls_handlers_recv_keeps_stream_open");

  uint32_t queuedCiphertextBeforeSend = fixture.neuron.brainStreamForTest()->queuedSendOutstandingBytes();
  suite.expect(queuedCiphertextBeforeSend > 1, "neuron_transport_tls_handlers_send_has_partialable_ciphertext");

  fixture.neuron.sendBrainForTest(int(queuedCiphertextBeforeSend - 1));

  suite.expect(fixture.neuron.brainStreamForTest()->pendingSend, "neuron_transport_tls_handlers_send_rearms_from_send_kick");
  suite.expect(fixture.neuron.brainStreamForTest()->pendingSendBytes > 0, "neuron_transport_tls_handlers_send_tracks_remaining_ciphertext");
  suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()) == false, "neuron_transport_tls_handlers_send_keeps_stream_open");
}

static void testNeuronTransportTLSRecvHandlerClosesOnMalformedFrame(TestSuite& suite)
{
  constexpr uint128_t brainUUID = uint128_t(0xB2022);
  constexpr uint128_t neuronUUID = uint128_t(0xE2024);

  BrainTransportTLSFixture fixture(
      suite,
      "neuron_transport_tls_malformed",
      brainUUID,
      neuronUUID,
      "fd00::41",
      "fd00::42",
      BrainTransportTLSPeerMode::validUUID,
      true);
  if (fixture.ready == false)
  {
    return;
  }

  if (fixture.completeHandshake(suite) == false)
  {
    return;
  }

  String malformed = {};
  uint32_t malformedSize = 1;
  Message::append(malformed, malformedSize);
  fixture.brainClient.wBuffer.append(malformed);

  uint32_t encryptedBytes = 0;
  suite.expect(
      copyEncryptedTransportBytes(fixture.brainClient, fixture.neuron.brainStreamForTest()->rBuffer, encryptedBytes),
      "neuron_transport_tls_malformed_encrypts_payload");
  suite.expect(encryptedBytes > 0, "neuron_transport_tls_malformed_encrypted_payload_nonempty");

  fixture.neuron.brainStreamForTest()->pendingRecv = true;
  fixture.neuron.recvSocketForTest(fixture.neuron.brainStreamForTest(), int(encryptedBytes));

  suite.expect(fixture.neuron.brainStreamForTest()->tlsPeerVerified, "neuron_transport_tls_malformed_verifies_peer_before_parse_failure");
  suite.expect(fixture.neuron.brainStreamForTest()->tlsPeerUUID == brainUUID, "neuron_transport_tls_malformed_records_peer_uuid");
  suite.expect(fixture.neuron.brainStreamForTest()->rBuffer.size() == 0, "neuron_transport_tls_malformed_clears_recv_buffer");
  suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()), "neuron_transport_tls_malformed_closes_stream");
}

static void testNeuronDeferredHardwareInventoryCompletionStates(TestSuite& suite)
{
  {
    TestNeuron neuron = {};
    suite.expect(
        neuron.completeDeferredHardwareInventoryIfReadyForTest(),
        "neuron_deferred_hardware_inventory_complete_idle_returns_true");
  }

  {
    TestNeuron neuron = {};
    neuron.setDeferredHardwareInventoryInFlightForTest(true);
    suite.expect(
        neuron.completeDeferredHardwareInventoryIfReadyForTest() == false,
        "neuron_deferred_hardware_inventory_complete_inflight_without_ready_returns_false");
    suite.expect(
        neuron.deferredHardwareInventoryInFlightForTest(),
        "neuron_deferred_hardware_inventory_complete_inflight_without_ready_preserves_inflight");
  }

  {
    TestNeuron neuron = {};

    MachineHardwareProfile hardware = {};
    hardware.inventoryComplete = true;
    hardware.cpu.logicalCores = 12;
    hardware.memory.totalMB = 24'576;

    String serializedHardware = {};
    BitseryEngine::serialize(serializedHardware, hardware);
    neuron.seedDeferredHardwareInventoryReadyForTest(hardware, serializedHardware);

    suite.expect(
        neuron.completeDeferredHardwareInventoryIfReadyForTest(),
        "neuron_deferred_hardware_inventory_complete_ready_profile_returns_true");
    suite.expect(
        neuron.deferredHardwareInventoryInFlightForTest() == false,
        "neuron_deferred_hardware_inventory_complete_ready_profile_clears_inflight");
    const MachineHardwareProfile *adopted = neuron.latestHardwareProfileIfReadyForTest();
    suite.expect(
        adopted != nullptr,
        "neuron_deferred_hardware_inventory_complete_ready_profile_adopts_hardware");
    if (adopted != nullptr)
    {
      suite.expect(adopted->cpu.logicalCores == hardware.cpu.logicalCores, "neuron_deferred_hardware_inventory_complete_ready_profile_preserves_cpu");
      suite.expect(adopted->memory.totalMB == hardware.memory.totalMB, "neuron_deferred_hardware_inventory_complete_ready_profile_preserves_memory");
    }
  }
}

static void testNeuronDeferredHardwareInventoryWakePollHandlerStates(TestSuite& suite)
{
  {
    ScopedRing scopedRing = {};

    TestNeuron neuron = {};
    ScopedEventFD wake = {};
    if (wake.create(suite, "neuron_deferred_inventory_wake_poll_handler_creates_eventfd"))
    {
      int wakeFD = wake.take();
      neuron.setDeferredHardwareInventoryWakeFDForTest(wakeFD);
      neuron.armDeferredHardwareInventoryWakePollForTest();
      suite.expect(neuron.deferredHardwareInventoryWakePollQueuedForTest(), "neuron_deferred_inventory_wake_poll_handler_arms_before_cancel");
      neuron.pollDeferredHardwareInventoryWakeForTest(-ECANCELED);
      suite.expect(neuron.deferredHardwareInventoryWakePollQueuedForTest() == false, "neuron_deferred_inventory_wake_poll_handler_cancel_leaves_disarmed");
      close(wakeFD);
    }
  }

  {
    ScopedRing scopedRing = {};

    TestNeuron neuron = {};
    ScopedEventFD wake = {};
    if (wake.create(suite, "neuron_deferred_inventory_wake_poll_handler_creates_rearm_eventfd"))
    {
      int wakeFD = wake.take();
      neuron.setDeferredHardwareInventoryWakeFDForTest(wakeFD);
      neuron.setDeferredHardwareInventoryInFlightForTest(true);
      neuron.armDeferredHardwareInventoryWakePollForTest();
      suite.expect(neuron.deferredHardwareInventoryWakePollQueuedForTest(), "neuron_deferred_inventory_wake_poll_handler_arms_before_rearm");

      uint64_t signal = 1;
      suite.expect(write(wakeFD, &signal, sizeof(signal)) == ssize_t(sizeof(signal)), "neuron_deferred_inventory_wake_poll_handler_writes_signal");
      neuron.pollDeferredHardwareInventoryWakeForTest(POLLIN);

      suite.expect(neuron.deferredHardwareInventoryWakePollQueuedForTest(), "neuron_deferred_inventory_wake_poll_handler_rearms_without_ready_result");
      suite.expect(neuron.deferredHardwareInventoryInFlightForTest(), "neuron_deferred_inventory_wake_poll_handler_preserves_inflight_without_ready_result");
      suite.expect(neuron.latestHardwareProfileIfReadyForTest() == nullptr, "neuron_deferred_inventory_wake_poll_handler_does_not_adopt_without_ready_result");
      close(wakeFD);
    }
  }
}

static void testNeuronRecvAndSendControlHandlers(TestSuite& suite)
{
  {
    BrainSocketFixture fixture(suite, "neuron_recv_handler_success");
    if (fixture.ready)
    {
      MachineHardwareProfile hardware = {};
      hardware.inventoryComplete = true;
      hardware.cpu.logicalCores = 6;
      hardware.memory.totalMB = 12'288;

      String serializedHardware = {};
      BitseryEngine::serialize(serializedHardware, hardware);

      String inbound = {};
      buildNeuronMessage(inbound, NeuronTopic::machineHardwareProfile, serializedHardware);
      std::memcpy(fixture.neuron.brainStreamForTest()->rBuffer.pTail(), inbound.data(), inbound.size());
      fixture.neuron.brainStreamForTest()->pendingRecv = true;

      uint32_t dispatchCount = 0;
      uint16_t observedTopic = 0;
      fixture.neuron.recvBrainForTest(int(inbound.size()), [&](Message *message) {
        dispatchCount += 1;
        observedTopic = message->topic;
      });

      suite.expect(dispatchCount == 1, "neuron_recv_handler_success_dispatches_single_message");
      suite.expect(observedTopic == uint16_t(NeuronTopic::machineHardwareProfile), "neuron_recv_handler_success_preserves_message_topic");
      suite.expect(fixture.neuron.brainStreamForTest()->pendingRecv, "neuron_recv_handler_success_rearms_recv");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()) == false, "neuron_recv_handler_success_keeps_stream_open");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_handler_stale");
    if (fixture.ready)
    {
      uint32_t staleSize = 4;
      std::memcpy(fixture.neuron.brainStreamForTest()->rBuffer.pTail(), &staleSize, sizeof(staleSize));
      fixture.neuron.brainStreamForTest()->rBuffer.advance(sizeof(staleSize));
      fixture.neuron.brainStreamForTest()->pendingRecv = false;
      fixture.neuron.recvBrainForTest(int(sizeof(staleSize)), [&](Message *) {
        suite.expect(false, "neuron_recv_handler_stale_duplicate_does_not_dispatch");
      });

      suite.expect(fixture.neuron.brainStreamForTest()->rBuffer.size() == sizeof(staleSize), "neuron_recv_handler_stale_duplicate_leaves_buffer_unchanged");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()) == false, "neuron_recv_handler_stale_duplicate_keeps_stream_open");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_handler_overflow");
    if (fixture.ready)
    {
      fixture.neuron.brainStreamForTest()->rBuffer.clear();
      fixture.neuron.brainStreamForTest()->rBuffer.reserve(8);
      fixture.neuron.brainStreamForTest()->pendingRecv = true;
      int overflowResult = int(fixture.neuron.brainStreamForTest()->rBuffer.remainingCapacity() + 1);
      fixture.neuron.recvBrainForTest(overflowResult, [&](Message *) {
        suite.expect(false, "neuron_recv_handler_overflow_does_not_dispatch");
      });

      suite.expect(fixture.neuron.brainStreamForTest()->rBuffer.size() == 0, "neuron_recv_handler_overflow_clears_buffer");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()), "neuron_recv_handler_overflow_closes_stream");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_handler_parse_failure");
    if (fixture.ready)
    {
      uint32_t malformedSize = 1;
      std::memcpy(fixture.neuron.brainStreamForTest()->rBuffer.pTail(), &malformedSize, sizeof(malformedSize));
      fixture.neuron.brainStreamForTest()->pendingRecv = true;
      uint32_t dispatchCount = 0;
      fixture.neuron.recvBrainForTest(int(sizeof(malformedSize)), [&](Message *) {
        dispatchCount += 1;
      });

      suite.expect(dispatchCount == 0, "neuron_recv_handler_parse_failure_does_not_dispatch");
      suite.expect(fixture.neuron.brainStreamForTest()->rBuffer.size() == 0, "neuron_recv_handler_parse_failure_clears_buffer");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()), "neuron_recv_handler_parse_failure_closes_stream");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_handler_oversized_frame");
    if (fixture.ready)
    {
      fixture.neuron.brainStreamForTest()->rBuffer.clear();
      fixture.neuron.brainStreamForTest()->rBuffer.reserve(64);
      uint64_t capacityBefore = fixture.neuron.brainStreamForTest()->rBuffer.remainingCapacity();
      uint32_t oversizedSize = ProdigyWire::maxControlFrameBytes + 16;
      std::memcpy(fixture.neuron.brainStreamForTest()->rBuffer.pTail(), &oversizedSize, sizeof(oversizedSize));
      fixture.neuron.brainStreamForTest()->pendingRecv = true;
      uint32_t dispatchCount = 0;
      fixture.neuron.recvBrainForTest(int(sizeof(oversizedSize)), [&](Message *) {
        dispatchCount += 1;
      });

      suite.expect(dispatchCount == 0, "neuron_recv_handler_oversized_frame_does_not_dispatch");
      suite.expect(fixture.neuron.brainStreamForTest()->rBuffer.size() == 0, "neuron_recv_handler_oversized_frame_clears_buffer");
      suite.expect(fixture.neuron.brainStreamForTest()->rBuffer.remainingCapacity() == capacityBefore, "neuron_recv_handler_oversized_frame_does_not_grow_buffer");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()), "neuron_recv_handler_oversized_frame_closes_stream");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_handler_negative");
    if (fixture.ready)
    {
      fixture.neuron.brainStreamForTest()->pendingRecv = true;
      fixture.neuron.recvBrainForTest(-ECONNRESET, [&](Message *) {
        suite.expect(false, "neuron_recv_handler_negative_does_not_dispatch");
      });

      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()), "neuron_recv_handler_negative_closes_stream");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_send_handler_partial");
    if (fixture.ready)
    {
      fixture.neuron.brainOutboundForTest().assign("abcdef"_ctv);
      Ring::queueSend(fixture.neuron.brainStreamForTest());
      suite.expect(fixture.neuron.brainStreamForTest()->pendingSend, "neuron_send_handler_partial_arms_initial_send");
      suite.expect(fixture.neuron.brainStreamForTest()->pendingSendBytes == 6, "neuron_send_handler_partial_tracks_initial_send_bytes");

      fixture.neuron.sendBrainForTest(3);

      suite.expect(fixture.neuron.brainStreamForTest()->pendingSend, "neuron_send_handler_partial_rearms_send");
      suite.expect(fixture.neuron.brainStreamForTest()->pendingSendBytes == 3, "neuron_send_handler_partial_tracks_remaining_send_bytes");
      suite.expect(fixture.neuron.brainStreamForTest()->wBuffer.outstandingBytes() == 3, "neuron_send_handler_partial_consumes_sent_prefix");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()) == false, "neuron_send_handler_partial_keeps_stream_open");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_send_handler_stale_and_error");
    if (fixture.ready)
    {
      fixture.neuron.brainOutboundForTest().assign("abcd"_ctv);

      fixture.neuron.sendBrainForTest(2);
      suite.expect(fixture.neuron.brainStreamForTest()->wBuffer.outstandingBytes() == 4, "neuron_send_handler_stale_duplicate_leaves_buffer_unchanged");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()) == false, "neuron_send_handler_stale_duplicate_keeps_stream_open");

      fixture.neuron.brainStreamForTest()->pendingSend = true;
      fixture.neuron.brainStreamForTest()->pendingSendBytes = 1;
      fixture.neuron.brainStreamForTest()->noteSendQueued();
      fixture.neuron.sendBrainForTest(2);
      suite.expect(fixture.neuron.brainOutboundForTest().size() == 0, "neuron_send_handler_overflow_clears_queued_bytes");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()), "neuron_send_handler_overflow_closes_stream");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_send_handler_negative");
    if (fixture.ready)
    {
      fixture.neuron.brainOutboundForTest().assign("wxyz"_ctv);
      fixture.neuron.brainStreamForTest()->pendingSend = true;
      fixture.neuron.brainStreamForTest()->pendingSendBytes = 4;
      fixture.neuron.brainStreamForTest()->noteSendQueued();
      fixture.neuron.sendBrainForTest(-EPIPE);

      suite.expect(fixture.neuron.brainOutboundForTest().size() == 0, "neuron_send_handler_negative_clears_queued_bytes");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()), "neuron_send_handler_negative_closes_stream");
    }
  }
}

static void testNeuronContainerConnectHandlerPaths(TestSuite& suite)
{
  {
    ContainerSocketFixture fixture(suite, "neuron_connect_handler_success", uint128_t(0xC011));
    if (fixture.ready)
    {
      fixture.container.wBuffer.assign("queued"_ctv);

      fixture.neuron.connectContainerForTest(&fixture.container, 0);

      suite.expect(fixture.container.pendingRecv, "neuron_connect_handler_success_arms_recv");
      suite.expect(fixture.container.pendingSend, "neuron_connect_handler_success_arms_send");
      suite.expect(fixture.container.pendingSendBytes == 6, "neuron_connect_handler_success_tracks_send_bytes");
      suite.expect(TestNeuron::containerStreamIsActiveForTest(&fixture.container), "neuron_connect_handler_success_keeps_container_active");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_connect_handler_skip", uint128_t(0xC012));
    if (fixture.ready)
    {
      fixture.container.pendingRecv = true;
      fixture.container.pendingSend = true;
      fixture.container.pendingSendBytes = 4;
      fixture.container.wBuffer.assign("skip"_ctv);

      fixture.neuron.connectContainerForTest(&fixture.container, 0);

      suite.expect(fixture.container.pendingRecv, "neuron_connect_handler_success_does_not_duplicate_recv");
      suite.expect(fixture.container.pendingSend, "neuron_connect_handler_success_does_not_duplicate_send");
      suite.expect(fixture.container.pendingSendBytes == 4, "neuron_connect_handler_success_preserves_existing_send_bytes");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_connect_handler_inactive", uint128_t(0xC013), true, -1);
    if (fixture.ready)
    {
      fixture.container.wBuffer.assign("inactive"_ctv);

      fixture.neuron.connectContainerForTest(&fixture.container, 0);

      suite.expect(fixture.container.pendingRecv == false, "neuron_connect_handler_inactive_skips_recv");
      suite.expect(fixture.container.pendingSend == false, "neuron_connect_handler_inactive_skips_send");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_connect_handler_pending_destroy", uint128_t(0xC014));
    if (fixture.ready)
    {
      fixture.container.pendingDestroy = true;
      fixture.container.wBuffer.assign("destroy"_ctv);

      fixture.neuron.connectContainerForTest(&fixture.container, 0);

      suite.expect(fixture.container.pendingRecv == false, "neuron_connect_handler_pending_destroy_skips_recv");
      suite.expect(fixture.container.pendingSend == false, "neuron_connect_handler_pending_destroy_skips_send");
      suite.expect(TestNeuron::containerStreamIsActiveForTest(&fixture.container), "neuron_connect_handler_pending_destroy_leaves_socket_untouched");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_connect_handler_untracked", uint128_t(0xC015), false);
    if (fixture.ready)
    {
      fixture.container.wBuffer.assign("untracked"_ctv);

      fixture.neuron.connectContainerForTest(&fixture.container, 0);

      suite.expect(fixture.container.pendingRecv == false, "neuron_connect_handler_untracked_skips_recv");
      suite.expect(fixture.container.pendingSend == false, "neuron_connect_handler_untracked_skips_send");
      suite.expect(TestNeuron::containerStreamIsClosingForTest(&fixture.container) == false, "neuron_connect_handler_untracked_keeps_socket_open");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_connect_handler_failure", uint128_t(0xC016));
    if (fixture.ready)
    {
      fixture.neuron.connectContainerForTest(&fixture.container, -ECONNREFUSED);

      suite.expect(TestNeuron::containerStreamIsClosingForTest(&fixture.container), "neuron_connect_handler_failure_closes_container");
      suite.expect(fixture.container.pendingRecv == false, "neuron_connect_handler_failure_does_not_arm_recv");
      suite.expect(fixture.container.pendingSend == false, "neuron_connect_handler_failure_does_not_arm_send");
    }
  }
}

static void testNeuronRecvDispatchesPairingAndCredentialMessages(TestSuite& suite)
{
  {
    BrainContainerFixture fixture(suite, "neuron_recv_advertisement_active", uint128_t(0x7000));
    if (fixture.ready)
    {
      String advertisementPayload = {};
      suite.expect(
          ProdigyWire::serializeAdvertisementPairingPayload(
              advertisementPayload,
              uint128_t(0x1101),
              uint128_t(0x2202),
              uint64_t(0x3303),
              uint16_t(77),
              true),
          "neuron_recv_advertisement_active_serializes_payload");

      String inbound = {};
      buildNeuronContainerPackedMessage(inbound, NeuronTopic::advertisementPairing, fixture.container.plan.uuid, advertisementPayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.brain.neuron, "neuron_recv_advertisement_active", inbound),
          "neuron_recv_advertisement_active_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.brain.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_advertisement_active_dispatches_once");
      auto it = fixture.container.plan.advertisementPairings.find(uint64_t(0x3303));
      suite.expect(
          it != fixture.container.plan.advertisementPairings.end() && it->second.size() == 1 && it->second[0].secret == uint128_t(0x1101) && it->second[0].address == uint128_t(0x2202),
          "neuron_recv_advertisement_active_applies_pairing");
      suite.expect(fixture.container.pendingSend, "neuron_recv_advertisement_active_queues_container_send");

      uint32_t frames = 0;
      forEachMessageInBuffer(fixture.container.wBuffer, [&](Message *frame) {
        if (ContainerTopic(frame->topic) == ContainerTopic::advertisementPairing)
        {
          frames += 1;
        }
      });
      suite.expect(frames == 1, "neuron_recv_advertisement_active_emits_container_frame");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_advertisement_missing_uuid");
    if (fixture.ready)
    {
      String inbound = {};
      buildNeuronMessage(inbound, NeuronTopic::advertisementPairing);
      suite.require(
          seedBrainInboundForTest(suite, fixture.neuron, "neuron_recv_advertisement_missing_uuid", inbound),
          "neuron_recv_advertisement_missing_uuid_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_advertisement_missing_uuid_dispatches_once");
      suite.expect(
          fixture.neuron.pendingAdvertisementPayloadCountForTest(uint128_t(0x7014)) == 0,
          "neuron_recv_advertisement_missing_uuid_does_not_queue_payload");
      suite.expect(fixture.neuron.brainOutboundForTest().size() == 0, "neuron_recv_advertisement_missing_uuid_emits_no_outbound_frames");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()), "neuron_recv_advertisement_missing_uuid_closes_stream");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_advertisement_missing");
    if (fixture.ready)
    {
      String advertisementPayload = {};
      suite.expect(
          ProdigyWire::serializeAdvertisementPairingPayload(
              advertisementPayload,
              uint128_t(0x7701),
              uint128_t(0x7702),
              uint64_t(0x7703),
              uint16_t(91),
              true),
          "neuron_recv_advertisement_missing_serializes_payload");

      String inbound = {};
      buildNeuronContainerPackedMessage(inbound, NeuronTopic::advertisementPairing, uint128_t(0x7010), advertisementPayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.neuron, "neuron_recv_advertisement_missing", inbound),
          "neuron_recv_advertisement_missing_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_advertisement_missing_dispatches_once");
      suite.expect(
          fixture.neuron.pendingAdvertisementPayloadCountForTest(uint128_t(0x7010)) == 1,
          "neuron_recv_advertisement_missing_queues_pending_payload");
    }
  }

  {
    BrainContainerFixture fixture(suite, "neuron_recv_advertisement_inactive", uint128_t(0x7015), false);
    if (fixture.ready)
    {
      String advertisementPayload = {};
      suite.expect(
          ProdigyWire::serializeAdvertisementPairingPayload(
              advertisementPayload,
              uint128_t(0x7711),
              uint128_t(0x7712),
              uint64_t(0x7713),
              uint16_t(92),
              true),
          "neuron_recv_advertisement_inactive_serializes_payload");

      String inbound = {};
      buildNeuronContainerPackedMessage(inbound, NeuronTopic::advertisementPairing, fixture.container.plan.uuid, advertisementPayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.brain.neuron, "neuron_recv_advertisement_inactive", inbound),
          "neuron_recv_advertisement_inactive_seeds_inbound");
      recvAndDispatchBrainForTest(fixture.brain.neuron, int(inbound.size()));

      auto it = fixture.container.plan.advertisementPairings.find(uint64_t(0x7713));
      suite.expect(
          it != fixture.container.plan.advertisementPairings.end() && it->second.size() == 1 && it->second[0].secret == uint128_t(0x7711) && it->second[0].address == uint128_t(0x7712),
          "neuron_recv_advertisement_inactive_applies_pairing");
      suite.expect(
          fixture.brain.neuron.pendingAdvertisementPayloadCountForTest(fixture.container.plan.uuid) == 1,
          "neuron_recv_advertisement_inactive_queues_pending_payload");
      suite.expect(
          fixture.container.pendingSend == false && fixture.container.wBuffer.size() == 0,
          "neuron_recv_advertisement_inactive_does_not_queue_container_send");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_advertisement_malformed");
    if (fixture.ready)
    {
      String inbound = {};
      buildNeuronContainerPackedMessage(inbound, NeuronTopic::advertisementPairing, uint128_t(0x7016), "broken"_ctv);
      suite.require(
          seedBrainInboundForTest(suite, fixture.neuron, "neuron_recv_advertisement_malformed", inbound),
          "neuron_recv_advertisement_malformed_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_advertisement_malformed_dispatches_once");
      suite.expect(
          fixture.neuron.pendingAdvertisementPayloadCountForTest(uint128_t(0x7016)) == 0,
          "neuron_recv_advertisement_malformed_does_not_queue_pending_payload");
      suite.expect(
          fixture.neuron.brainOutboundForTest().size() == 0,
          "neuron_recv_advertisement_malformed_emits_no_outbound_frames");
    }
  }

  {
    BrainContainerFixture fixture(suite, "neuron_recv_subscription_active", uint128_t(0x7010));
    if (fixture.ready)
    {
      String subscriptionPayload = {};
      suite.expect(
          ProdigyWire::serializeSubscriptionPairingPayload(
              subscriptionPayload,
              uint128_t(0x4401),
              uint128_t(0x5502),
              uint64_t(0x6603),
              uint16_t(7443),
              uint16_t(77),
              true),
          "neuron_recv_subscription_active_serializes_payload");

      String inbound = {};
      buildNeuronContainerPackedMessage(inbound, NeuronTopic::subscriptionPairing, fixture.container.plan.uuid, subscriptionPayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.brain.neuron, "neuron_recv_subscription_active", inbound),
          "neuron_recv_subscription_active_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.brain.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_subscription_active_dispatches_once");
      auto it = fixture.container.plan.subscriptionPairings.find(uint64_t(0x6603));
      suite.expect(
          it != fixture.container.plan.subscriptionPairings.end() && it->second.size() == 1 && it->second[0].secret == uint128_t(0x4401) && it->second[0].address == uint128_t(0x5502) && it->second[0].port == 7443,
          "neuron_recv_subscription_active_applies_pairing");
      suite.expect(fixture.container.pendingSend, "neuron_recv_subscription_active_queues_container_send");

      uint32_t frames = 0;
      forEachMessageInBuffer(fixture.container.wBuffer, [&](Message *frame) {
        if (ContainerTopic(frame->topic) == ContainerTopic::subscriptionPairing)
        {
          frames += 1;
        }
      });
      suite.expect(frames == 1, "neuron_recv_subscription_active_emits_container_frame");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_subscription_missing_uuid");
    if (fixture.ready)
    {
      String inbound = {};
      buildNeuronMessage(inbound, NeuronTopic::subscriptionPairing);
      suite.require(
          seedBrainInboundForTest(suite, fixture.neuron, "neuron_recv_subscription_missing_uuid", inbound),
          "neuron_recv_subscription_missing_uuid_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_subscription_missing_uuid_dispatches_once");
      suite.expect(
          fixture.neuron.pendingSubscriptionPayloadCountForTest(uint128_t(0x7019)) == 0,
          "neuron_recv_subscription_missing_uuid_does_not_queue_payload");
      suite.expect(fixture.neuron.brainOutboundForTest().size() == 0, "neuron_recv_subscription_missing_uuid_emits_no_outbound_frames");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()), "neuron_recv_subscription_missing_uuid_closes_stream");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_subscription_missing");
    if (fixture.ready)
    {
      String subscriptionPayload = {};
      suite.expect(
          ProdigyWire::serializeSubscriptionPairingPayload(
              subscriptionPayload,
              uint128_t(0x7701),
              uint128_t(0x7702),
              uint64_t(0x7703),
              uint16_t(8443),
              uint16_t(91),
              true),
          "neuron_recv_subscription_missing_serializes_payload");

      String inbound = {};
      buildNeuronContainerPackedMessage(inbound, NeuronTopic::subscriptionPairing, uint128_t(0x7011), subscriptionPayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.neuron, "neuron_recv_subscription_missing", inbound),
          "neuron_recv_subscription_missing_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_subscription_missing_dispatches_once");
      suite.expect(
          fixture.neuron.pendingSubscriptionPayloadCountForTest(uint128_t(0x7011)) == 1,
          "neuron_recv_subscription_missing_queues_pending_payload");
    }
  }

  {
    BrainContainerFixture fixture(suite, "neuron_recv_subscription_inactive", uint128_t(0x7017), false);
    if (fixture.ready)
    {
      String subscriptionPayload = {};
      suite.expect(
          ProdigyWire::serializeSubscriptionPairingPayload(
              subscriptionPayload,
              uint128_t(0x8811),
              uint128_t(0x8812),
              uint64_t(0x8813),
              uint16_t(9444),
              uint16_t(93),
              true),
          "neuron_recv_subscription_inactive_serializes_payload");

      String inbound = {};
      buildNeuronContainerPackedMessage(inbound, NeuronTopic::subscriptionPairing, fixture.container.plan.uuid, subscriptionPayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.brain.neuron, "neuron_recv_subscription_inactive", inbound),
          "neuron_recv_subscription_inactive_seeds_inbound");
      recvAndDispatchBrainForTest(fixture.brain.neuron, int(inbound.size()));

      auto it = fixture.container.plan.subscriptionPairings.find(uint64_t(0x8813));
      suite.expect(
          it != fixture.container.plan.subscriptionPairings.end() && it->second.size() == 1 && it->second[0].secret == uint128_t(0x8811) && it->second[0].address == uint128_t(0x8812) && it->second[0].port == 9444,
          "neuron_recv_subscription_inactive_applies_pairing");
      suite.expect(
          fixture.brain.neuron.pendingSubscriptionPayloadCountForTest(fixture.container.plan.uuid) == 1,
          "neuron_recv_subscription_inactive_queues_pending_payload");
      suite.expect(
          fixture.container.pendingSend == false && fixture.container.wBuffer.size() == 0,
          "neuron_recv_subscription_inactive_does_not_queue_container_send");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_subscription_malformed");
    if (fixture.ready)
    {
      String inbound = {};
      buildNeuronContainerPackedMessage(inbound, NeuronTopic::subscriptionPairing, uint128_t(0x7018), "broken"_ctv);
      suite.require(
          seedBrainInboundForTest(suite, fixture.neuron, "neuron_recv_subscription_malformed", inbound),
          "neuron_recv_subscription_malformed_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_subscription_malformed_dispatches_once");
      suite.expect(
          fixture.neuron.pendingSubscriptionPayloadCountForTest(uint128_t(0x7018)) == 0,
          "neuron_recv_subscription_malformed_does_not_queue_pending_payload");
      suite.expect(
          fixture.neuron.brainOutboundForTest().size() == 0,
          "neuron_recv_subscription_malformed_emits_no_outbound_frames");
    }
  }

  {
    BrainContainerFixture fixture(suite, "neuron_recv_advertisement_pending_destroy", uint128_t(0x7012), true, true, true);
    if (fixture.ready)
    {
      String advertisementPayload = {};
      suite.expect(
          ProdigyWire::serializeAdvertisementPairingPayload(
              advertisementPayload,
              uint128_t(0x8801),
              uint128_t(0x8802),
              uint64_t(0x8803),
              uint16_t(33),
              true),
          "neuron_recv_advertisement_pending_destroy_serializes_payload");

      String inbound = {};
      buildNeuronContainerPackedMessage(inbound, NeuronTopic::advertisementPairing, fixture.container.plan.uuid, advertisementPayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.brain.neuron, "neuron_recv_advertisement_pending_destroy", inbound),
          "neuron_recv_advertisement_pending_destroy_seeds_inbound");
      recvAndDispatchBrainForTest(fixture.brain.neuron, int(inbound.size()));

      suite.expect(
          fixture.container.plan.advertisementPairings.find(uint64_t(0x8803)) == fixture.container.plan.advertisementPairings.end(),
          "neuron_recv_advertisement_pending_destroy_skips_pairing");
      suite.expect(
          fixture.brain.neuron.pendingAdvertisementPayloadCountForTest(fixture.container.plan.uuid) == 0,
          "neuron_recv_advertisement_pending_destroy_does_not_queue_pending_payload");
      suite.expect(
          fixture.container.pendingSend == false && fixture.container.wBuffer.size() == 0,
          "neuron_recv_advertisement_pending_destroy_does_not_queue_container_send");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_credential_missing_uuid");
    if (fixture.ready)
    {
      String inbound = {};
      buildNeuronMessage(inbound, NeuronTopic::refreshContainerCredentials);
      suite.require(
          seedBrainInboundForTest(suite, fixture.neuron, "neuron_recv_credential_missing_uuid", inbound),
          "neuron_recv_credential_missing_uuid_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_credential_missing_uuid_dispatches_once");
      suite.expect(
          fixture.neuron.pendingCredentialRefreshPayloadCountForTest(uint128_t(0x7026)) == 0,
          "neuron_recv_credential_missing_uuid_does_not_queue_payload");
      suite.expect(fixture.neuron.brainOutboundForTest().size() == 0, "neuron_recv_credential_missing_uuid_emits_no_outbound_frames");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()), "neuron_recv_credential_missing_uuid_closes_stream");
    }
  }

  {
    String inbound = {};
    Message *message = buildNeuronRawPayloadMessage(inbound, NeuronTopic::advertisementPairing, "x"_ctv);

    suite.expect(
        ProdigyIngressValidation::validateNeuronPayloadForNeuron(message->topic, message->args, message->terminal()) == false,
        "neuron_validate_advertisement_missing_uuid_rejects");
  }

  {
    String inbound = {};
    Message *message = buildNeuronRawPayloadMessage(inbound, NeuronTopic::subscriptionPairing, "x"_ctv);

    suite.expect(
        ProdigyIngressValidation::validateNeuronPayloadForNeuron(message->topic, message->args, message->terminal()) == false,
        "neuron_validate_subscription_missing_uuid_rejects");
  }

  {
    String inbound = {};
    Message *message = buildNeuronRawPayloadMessage(inbound, NeuronTopic::refreshContainerCredentials, "x"_ctv);

    suite.expect(
        ProdigyIngressValidation::validateNeuronPayloadForNeuron(message->topic, message->args, message->terminal()) == false,
        "neuron_validate_credential_missing_uuid_rejects");
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_credential_typed_ack");
    if (fixture.ready)
    {
      TlsResumptionApplyAck ack = {};
      TlsResumptionApplyResult resumption = {};
      resumption.wormholeName.assign("public-api-quic"_ctv);
      resumption.generation = 42;
      resumption.success = true;
      ack.results.push_back(resumption);

      String ackPayload = {};
      suite.expect(
          ProdigyWire::serializeTlsResumptionApplyAck(ackPayload, ack),
          "neuron_recv_credential_typed_ack_serializes_result");

      String inbound = {};
      buildNeuronMessage(inbound, NeuronTopic::refreshContainerCredentials, uint128_t(0x7020), ackPayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.neuron, "neuron_recv_credential_typed_ack", inbound),
          "neuron_recv_credential_typed_ack_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_credential_typed_ack_dispatches_once");
      suite.expect(fixture.neuron.brainOutboundForTest().size() == 0, "neuron_recv_credential_typed_ack_emits_no_outbound_frames");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()) == false, "neuron_recv_credential_typed_ack_keeps_stream_open");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_credential_apply_ack");
    if (fixture.ready)
    {
      CredentialApplyAck ack = {};
      TlsIdentityApplyResult tls = {};
      tls.identityName.assign("api-public"_ctv);
      tls.generation = 7;
      tls.success = false;
      tls.failureReason.assign("rejected"_ctv);
      ack.tlsResults.push_back(tls);

      String ackPayload = {};
      suite.expect(
          ProdigyWire::serializeCredentialApplyAck(ackPayload, ack),
          "neuron_recv_credential_apply_ack_serializes_result");

      String inbound = {};
      buildNeuronMessage(inbound, NeuronTopic::refreshContainerCredentials, uint128_t(0x7021), ackPayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.neuron, "neuron_recv_credential_apply_ack", inbound),
          "neuron_recv_credential_apply_ack_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_credential_apply_ack_dispatches_once");
      suite.expect(fixture.neuron.brainOutboundForTest().size() == 0, "neuron_recv_credential_apply_ack_emits_no_outbound_frames");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()) == false, "neuron_recv_credential_apply_ack_keeps_stream_open");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_credential_malformed");
    if (fixture.ready)
    {
      String inbound = {};
      Message *message = buildNeuronMessage(inbound, NeuronTopic::refreshContainerCredentials, uint128_t(0x7025), "broken"_ctv);
      suite.expect(
          ProdigyIngressValidation::validateNeuronPayloadForBrain(message->topic, message->args, message->terminal()) == false,
          "neuron_recv_credential_malformed_validator_rejects_payload");
      suite.require(
          seedBrainInboundForTest(suite, fixture.neuron, "neuron_recv_credential_malformed", inbound),
          "neuron_recv_credential_malformed_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_credential_malformed_dispatches_once");
      suite.expect(
          fixture.neuron.pendingCredentialRefreshPayloadCountForTest(uint128_t(0x7025)) == 0,
          "neuron_recv_credential_malformed_does_not_queue_pending_payload");
      suite.expect(
          fixture.neuron.brainOutboundForTest().size() == 0,
          "neuron_recv_credential_malformed_emits_no_outbound_frames");
    }
  }

  {
    BrainContainerFixture fixture(suite, "neuron_recv_subscription_pending_destroy", uint128_t(0x7022), true, true, true);
    if (fixture.ready)
    {
      String subscriptionPayload = {};
      suite.expect(
          ProdigyWire::serializeSubscriptionPairingPayload(
              subscriptionPayload,
              uint128_t(0x9901),
              uint128_t(0x9902),
              uint64_t(0x9903),
              uint16_t(9443),
              uint16_t(45),
              true),
          "neuron_recv_subscription_pending_destroy_serializes_payload");

      String inbound = {};
      buildNeuronContainerPackedMessage(inbound, NeuronTopic::subscriptionPairing, fixture.container.plan.uuid, subscriptionPayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.brain.neuron, "neuron_recv_subscription_pending_destroy", inbound),
          "neuron_recv_subscription_pending_destroy_seeds_inbound");
      recvAndDispatchBrainForTest(fixture.brain.neuron, int(inbound.size()));

      suite.expect(
          fixture.container.plan.subscriptionPairings.find(uint64_t(0x9903)) == fixture.container.plan.subscriptionPairings.end(),
          "neuron_recv_subscription_pending_destroy_skips_pairing");
      suite.expect(
          fixture.brain.neuron.pendingSubscriptionPayloadCountForTest(fixture.container.plan.uuid) == 0,
          "neuron_recv_subscription_pending_destroy_does_not_queue_pending_payload");
      suite.expect(
          fixture.container.pendingSend == false && fixture.container.wBuffer.size() == 0,
          "neuron_recv_subscription_pending_destroy_does_not_queue_container_send");
    }
  }

  {
    BrainContainerFixture fixture(suite, "neuron_recv_wormholes_active", uint128_t(0x7026));
    if (fixture.ready)
    {
      fixture.brain.neuron.ensureSwitchboardForTest();

      Wormhole wormhole = {};
      wormhole.externalAddress = IPAddress("2001:db8:100::a", true);
      wormhole.externalPort = 443;
      wormhole.containerPort = 8443;
      wormhole.layer4 = IPPROTO_UDP;
      wormhole.isQuic = true;
      wormhole.source = ExternalAddressSource::hostPublicAddress;

      Vector<Wormhole> wormholes = {};
      wormholes.push_back(wormhole);

      String wormholePayload = {};
      BitseryEngine::serialize(wormholePayload, wormholes);

      String inbound = {};
      buildNeuronMessage(inbound, NeuronTopic::refreshContainerWormholes, fixture.container.plan.uuid, wormholePayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.brain.neuron, "neuron_recv_wormholes_active", inbound),
          "neuron_recv_wormholes_active_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.brain.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_wormholes_active_dispatches_once");
      suite.expect(
          fixture.container.plan.wormholes.size() == 1 && equalSerializedObjects(fixture.container.plan.wormholes[0], wormhole),
          "neuron_recv_wormholes_active_updates_live_plan");
      suite.expect(
          fixture.brain.neuron.refreshContainerSwitchboardWormholesCallsForTest == 1,
          "neuron_recv_wormholes_active_refreshes_switchboard_state");
      suite.expect(
          fixture.brain.neuron.syncContainerSwitchboardRuntimeCallsForTest == 1,
          "neuron_recv_wormholes_active_syncs_live_runtime");
      suite.expect(
          fixture.brain.neuron.lastRefreshedContainerUUIDForTest == fixture.container.plan.uuid,
          "neuron_recv_wormholes_active_tracks_refreshed_container_uuid");
      suite.expect(
          fixture.brain.neuron.lastSyncedContainerUUIDForTest == fixture.container.plan.uuid,
          "neuron_recv_wormholes_active_tracks_synced_container_uuid");
      suite.expect(
          fixture.brain.neuron.lastRefreshedWormholesForTest.size() == 1 && equalSerializedObjects(fixture.brain.neuron.lastRefreshedWormholesForTest[0], wormhole),
          "neuron_recv_wormholes_active_tracks_refreshed_wormholes");
      suite.expect(fixture.container.pendingSend, "neuron_recv_wormholes_active_queues_container_send");

      bool sawWormholesRefresh = false;
      forEachMessageInBuffer(fixture.container.wBuffer, [&](Message *frame) {
        if (ContainerTopic(frame->topic) != ContainerTopic::wormholesRefresh)
        {
          return;
        }

        uint8_t *args = frame->args;
        String serialized = {};
        Message::extractToStringView(args, serialized);

        Vector<Wormhole> decoded = {};
        if (BitseryEngine::deserializeSafe(serialized, decoded) && decoded.size() == 1 && equalSerializedObjects(decoded[0], wormhole))
        {
          sawWormholesRefresh = true;
        }
      });
      suite.expect(sawWormholesRefresh, "neuron_recv_wormholes_active_emits_container_frame");
    }
  }

  {
    BrainContainerFixture fixture(suite, "neuron_recv_wormholes_inactive", uint128_t(0x7027), false);
    if (fixture.ready)
    {
      fixture.brain.neuron.ensureSwitchboardForTest();

      Wormhole wormhole = {};
      wormhole.externalAddress = IPAddress("2001:db8:100::b", true);
      wormhole.externalPort = 443;
      wormhole.containerPort = 9443;
      wormhole.layer4 = IPPROTO_UDP;
      wormhole.isQuic = true;
      wormhole.source = ExternalAddressSource::registeredRoutablePrefix;
      wormhole.routablePrefixUUID = uint128_t(0x4455);

      Vector<Wormhole> wormholes = {};
      wormholes.push_back(wormhole);

      String wormholePayload = {};
      BitseryEngine::serialize(wormholePayload, wormholes);

      String inbound = {};
      buildNeuronMessage(inbound, NeuronTopic::refreshContainerWormholes, fixture.container.plan.uuid, wormholePayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.brain.neuron, "neuron_recv_wormholes_inactive", inbound),
          "neuron_recv_wormholes_inactive_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.brain.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_wormholes_inactive_dispatches_once");
      suite.expect(
          fixture.container.plan.wormholes.size() == 1 && equalSerializedObjects(fixture.container.plan.wormholes[0], wormhole),
          "neuron_recv_wormholes_inactive_updates_live_plan");
      suite.expect(
          fixture.brain.neuron.refreshContainerSwitchboardWormholesCallsForTest == 1,
          "neuron_recv_wormholes_inactive_refreshes_switchboard_state");
      suite.expect(
          fixture.brain.neuron.syncContainerSwitchboardRuntimeCallsForTest == 1,
          "neuron_recv_wormholes_inactive_syncs_live_runtime");
      suite.expect(
          fixture.container.pendingSend == false && fixture.container.wBuffer.size() == 0,
          "neuron_recv_wormholes_inactive_does_not_queue_container_send");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_wormholes_missing");
    if (fixture.ready)
    {
      Wormhole wormhole = {};
      wormhole.externalAddress = IPAddress("2001:db8:100::c", true);
      wormhole.externalPort = 443;
      wormhole.containerPort = 8443;
      wormhole.layer4 = IPPROTO_UDP;
      wormhole.isQuic = true;
      wormhole.source = ExternalAddressSource::hostPublicAddress;

      Vector<Wormhole> wormholes = {};
      wormholes.push_back(wormhole);

      String wormholePayload = {};
      BitseryEngine::serialize(wormholePayload, wormholes);

      String inbound = {};
      buildNeuronMessage(inbound, NeuronTopic::refreshContainerWormholes, uint128_t(0x7028), wormholePayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.neuron, "neuron_recv_wormholes_missing", inbound),
          "neuron_recv_wormholes_missing_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_wormholes_missing_dispatches_once");
      suite.expect(
          fixture.neuron.refreshContainerSwitchboardWormholesCallsForTest == 0,
          "neuron_recv_wormholes_missing_skips_switchboard_refresh");
      suite.expect(
          fixture.neuron.syncContainerSwitchboardRuntimeCallsForTest == 0,
          "neuron_recv_wormholes_missing_skips_runtime_sync");
      suite.expect(
          fixture.neuron.brainOutboundForTest().size() == 0,
          "neuron_recv_wormholes_missing_emits_no_outbound_frames");
    }
  }

  {
    BrainContainerFixture fixture(suite, "neuron_recv_wormholes_pending_destroy", uint128_t(0x7029), true, true, true);
    if (fixture.ready)
    {
      Wormhole wormhole = {};
      wormhole.externalAddress = IPAddress("2001:db8:100::d", true);
      wormhole.externalPort = 443;
      wormhole.containerPort = 8443;
      wormhole.layer4 = IPPROTO_UDP;
      wormhole.isQuic = true;
      wormhole.source = ExternalAddressSource::hostPublicAddress;

      Vector<Wormhole> wormholes = {};
      wormholes.push_back(wormhole);

      String wormholePayload = {};
      BitseryEngine::serialize(wormholePayload, wormholes);

      String inbound = {};
      buildNeuronMessage(inbound, NeuronTopic::refreshContainerWormholes, fixture.container.plan.uuid, wormholePayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.brain.neuron, "neuron_recv_wormholes_pending_destroy", inbound),
          "neuron_recv_wormholes_pending_destroy_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.brain.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_recv_wormholes_pending_destroy_dispatches_once");
      suite.expect(
          fixture.container.plan.wormholes.size() == 0,
          "neuron_recv_wormholes_pending_destroy_skips_live_plan_update");
      suite.expect(
          fixture.brain.neuron.refreshContainerSwitchboardWormholesCallsForTest == 0,
          "neuron_recv_wormholes_pending_destroy_skips_switchboard_refresh");
      suite.expect(
          fixture.brain.neuron.syncContainerSwitchboardRuntimeCallsForTest == 0,
          "neuron_recv_wormholes_pending_destroy_skips_runtime_sync");
      suite.expect(
          fixture.container.pendingSend == false && fixture.container.wBuffer.size() == 0,
          "neuron_recv_wormholes_pending_destroy_does_not_queue_container_send");
    }
  }
}

static void testNeuronOpenSwitchboardWormholesSyncsOwningRuntime(TestSuite& suite)
{
  {
    BrainContainerFixture fixture(suite, "neuron_open_switchboard_wormholes_local_owner", uint128_t(0x702A), false);
    if (fixture.ready)
    {
      fixture.brain.neuron.ensureSwitchboardForTest();

      local_container_subnet6 subnet = {};
      subnet.dpfx = 1;
      subnet.mpfx[0] = 0x00;
      subnet.mpfx[1] = 0x12;
      subnet.mpfx[2] = 0x34;
      fixture.brain.neuron.seedLocalContainerSubnetForTest(subnet);
      fixture.container.plan.fragment = 0x56;

      Wormhole wormhole = {};
      wormhole.externalAddress = IPAddress("2001:db8:100::f", true);
      wormhole.externalPort = 443;
      wormhole.containerPort = 8443;
      wormhole.layer4 = IPPROTO_UDP;
      wormhole.isQuic = true;
      wormhole.source = ExternalAddressSource::hostPublicAddress;

      Vector<Wormhole> wormholes = {};
      wormholes.push_back(wormhole);

      String wormholePayload = {};
      BitseryEngine::serialize(wormholePayload, wormholes);

      uint32_t containerID = fixture.brain.neuron.generateLocalContainerIDForTest(fixture.container.plan.fragment);

      String inbound = {};
      buildNeuronMessage(inbound, NeuronTopic::openSwitchboardWormholes, containerID, wormholePayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.brain.neuron, "neuron_open_switchboard_wormholes_local_owner", inbound),
          "neuron_open_switchboard_wormholes_local_owner_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.brain.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_open_switchboard_wormholes_local_owner_dispatches_once");
      suite.expect(
          fixture.brain.neuron.syncContainerSwitchboardRuntimeCallsForTest == 1,
          "neuron_open_switchboard_wormholes_local_owner_syncs_live_runtime");
      suite.expect(
          fixture.brain.neuron.lastSyncedContainerUUIDForTest == fixture.container.plan.uuid,
          "neuron_open_switchboard_wormholes_local_owner_tracks_synced_container_uuid");
      suite.expect(
          fixture.brain.neuron.refreshContainerSwitchboardWormholesCallsForTest == 0,
          "neuron_open_switchboard_wormholes_local_owner_skips_refresh_path");
    }
  }

  {
    BrainContainerFixture fixture(suite, "neuron_open_switchboard_wormholes_remote_owner", uint128_t(0x702B), false);
    if (fixture.ready)
    {
      fixture.brain.neuron.ensureSwitchboardForTest();

      local_container_subnet6 subnet = {};
      subnet.dpfx = 1;
      subnet.mpfx[0] = 0x00;
      subnet.mpfx[1] = 0x12;
      subnet.mpfx[2] = 0x34;
      fixture.brain.neuron.seedLocalContainerSubnetForTest(subnet);
      fixture.container.plan.fragment = 0x56;

      Wormhole wormhole = {};
      wormhole.externalAddress = IPAddress("2001:db8:100::10", true);
      wormhole.externalPort = 443;
      wormhole.containerPort = 8443;
      wormhole.layer4 = IPPROTO_UDP;
      wormhole.isQuic = true;
      wormhole.source = ExternalAddressSource::registeredRoutablePrefix;
      wormhole.routablePrefixUUID = uint128_t(0xAABBCCDD);

      Vector<Wormhole> wormholes = {};
      wormholes.push_back(wormhole);

      String wormholePayload = {};
      BitseryEngine::serialize(wormholePayload, wormholes);

      uint32_t remoteContainerID = fixture.brain.neuron.generateLocalContainerIDForTest(uint8_t(0x57));

      String inbound = {};
      buildNeuronMessage(inbound, NeuronTopic::openSwitchboardWormholes, remoteContainerID, wormholePayload);
      suite.require(
          seedBrainInboundForTest(suite, fixture.brain.neuron, "neuron_open_switchboard_wormholes_remote_owner", inbound),
          "neuron_open_switchboard_wormholes_remote_owner_seeds_inbound");
      uint32_t dispatchCount = recvAndDispatchBrainForTest(fixture.brain.neuron, int(inbound.size()));

      suite.expect(dispatchCount == 1, "neuron_open_switchboard_wormholes_remote_owner_dispatches_once");
      suite.expect(
          fixture.brain.neuron.syncContainerSwitchboardRuntimeCallsForTest == 0,
          "neuron_open_switchboard_wormholes_remote_owner_skips_runtime_sync");
      suite.expect(
          fixture.brain.neuron.lastSyncedContainerUUIDForTest == 0,
          "neuron_open_switchboard_wormholes_remote_owner_leaves_synced_uuid_empty");
      suite.expect(
          fixture.brain.neuron.refreshContainerSwitchboardWormholesCallsForTest == 0,
          "neuron_open_switchboard_wormholes_remote_owner_skips_refresh_path");
    }
  }
}

static void testNeuronRecvAndSendSocketWrappers(TestSuite& suite)
{
  {
    BrainSocketFixture fixture(suite, "neuron_recv_socket_brain_negative");
    if (fixture.ready)
    {
      fixture.neuron.brainStreamForTest()->pendingRecv = true;

      fixture.neuron.recvSocketForTest(fixture.neuron.brainStreamForTest(), -ECONNRESET);

      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()), "neuron_recv_socket_brain_negative_closes_stream");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_recv_socket_brain_success");
    if (fixture.ready)
    {
      String inbound = {};
      buildNeuronMessage(inbound, NeuronTopic::killContainer, uint128_t(0xC0FFEE));
      std::memcpy(fixture.neuron.brainStreamForTest()->rBuffer.pTail(), inbound.data(), inbound.size());
      fixture.neuron.brainStreamForTest()->pendingRecv = true;

      fixture.neuron.recvSocketForTest(fixture.neuron.brainStreamForTest(), int(inbound.size()));

      suite.expect(fixture.neuron.brainStreamForTest()->pendingRecv, "neuron_recv_socket_brain_success_rearms_recv");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()) == false, "neuron_recv_socket_brain_success_keeps_stream_open");

      uint32_t frames = 0;
      uint16_t forwardedTopic = 0;
      forEachMessageInBuffer(fixture.neuron.brainOutboundForTest(), [&](Message *message) {
        frames += 1;
        forwardedTopic = message->topic;
      });
      suite.expect(frames == 1, "neuron_recv_socket_brain_success_emits_single_frame");
      suite.expect(forwardedTopic == uint16_t(NeuronTopic::killContainer), "neuron_recv_socket_brain_success_forwards_kill_topic");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_recv_socket_container_success", uint128_t(0xC101));
    if (fixture.ready)
    {
      fixture.neuron.seedBrainStreamForTest(false);
      fixture.container.plan.config.applicationID = 62'010;
      fixture.container.plan.config.versionID = 9;
      fixture.container.plan.state = ContainerState::scheduled;

      String inbound = {};
      buildContainerMessage(inbound, ContainerTopic::healthy);
      std::memcpy(fixture.container.rBuffer.pTail(), inbound.data(), inbound.size());
      fixture.container.pendingRecv = true;

      fixture.neuron.recvSocketForTest(&fixture.container, int(inbound.size()));

      suite.expect(fixture.container.pendingRecv, "neuron_recv_socket_container_success_rearms_recv");
      suite.expect(TestNeuron::containerStreamIsClosingForTest(&fixture.container) == false, "neuron_recv_socket_container_success_keeps_stream_open");

      uint32_t forwardedCount = 0;
      uint16_t forwardedTopic = 0;
      forEachMessageInBuffer(fixture.neuron.brainOutboundForTest(), [&](Message *message) {
        forwardedCount += 1;
        forwardedTopic = message->topic;
      });
      suite.expect(forwardedCount == 1, "neuron_recv_socket_container_success_forwards_single_frame");
      suite.expect(forwardedTopic == uint16_t(NeuronTopic::containerHealthy), "neuron_recv_socket_container_success_forwards_healthy_topic");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_recv_socket_container_pending_destroy", uint128_t(0xC102));
    if (fixture.ready)
    {
      fixture.container.pendingDestroy = true;
      fixture.container.pendingRecv = true;

      fixture.neuron.recvSocketForTest(&fixture.container, -ECONNRESET);

      suite.expect(fixture.container.pendingRecv, "neuron_recv_socket_container_pending_destroy_leaves_recv_state_untouched");
      suite.expect(TestNeuron::containerStreamIsClosingForTest(&fixture.container) == false, "neuron_recv_socket_container_pending_destroy_keeps_stream_open");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_recv_socket_container_negative", uint128_t(0xC103));
    if (fixture.ready)
    {
      fixture.container.pendingRecv = true;

      fixture.neuron.recvSocketForTest(&fixture.container, -ECONNRESET);

      suite.expect(TestNeuron::containerStreamIsClosingForTest(&fixture.container), "neuron_recv_socket_container_negative_closes_stream");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_recv_socket_container_parse_failure", uint128_t(0xC104));
    if (fixture.ready)
    {
      fixture.container.pendingRecv = true;

      uint32_t malformedSize = 1;
      std::memcpy(fixture.container.rBuffer.pTail(), &malformedSize, sizeof(malformedSize));
      fixture.neuron.recvSocketForTest(&fixture.container, int(sizeof(malformedSize)));

      suite.expect(fixture.container.rBuffer.size() == 0, "neuron_recv_socket_container_parse_failure_clears_buffer");
      suite.expect(TestNeuron::containerStreamIsClosingForTest(&fixture.container), "neuron_recv_socket_container_parse_failure_closes_stream");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_recv_socket_container_overflow", uint128_t(0xC105), true, std::numeric_limits<int>::min(), 8, 8_KB);
    if (fixture.ready)
    {
      fixture.container.pendingRecv = true;

      int overflowResult = int(fixture.container.rBuffer.remainingCapacity() + 1);
      fixture.neuron.recvSocketForTest(&fixture.container, overflowResult);

      suite.expect(fixture.container.rBuffer.size() == 0, "neuron_recv_socket_container_overflow_clears_buffer");
      suite.expect(TestNeuron::containerStreamIsClosingForTest(&fixture.container), "neuron_recv_socket_container_overflow_closes_stream");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_recv_socket_container_untracked", uint128_t(0xC106), false);
    if (fixture.ready)
    {
      fixture.container.pendingRecv = true;

      fixture.neuron.recvSocketForTest(&fixture.container, -ECONNRESET);

      suite.expect(fixture.container.pendingRecv, "neuron_recv_socket_container_untracked_leaves_recv_state_untouched");
      suite.expect(TestNeuron::containerStreamIsClosingForTest(&fixture.container) == false, "neuron_recv_socket_container_untracked_keeps_stream_open");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_send_socket_brain_partial");
    if (fixture.ready)
    {
      fixture.neuron.brainOutboundForTest().assign("brain-send"_ctv);

      Ring::queueSend(fixture.neuron.brainStreamForTest());
      suite.expect(fixture.neuron.brainStreamForTest()->pendingSend, "neuron_send_socket_brain_partial_arms_initial_send");
      suite.expect(fixture.neuron.brainStreamForTest()->pendingSendBytes == 10, "neuron_send_socket_brain_partial_tracks_initial_send_bytes");

      fixture.neuron.sendSocketForTest(fixture.neuron.brainStreamForTest(), 4);

      suite.expect(fixture.neuron.brainStreamForTest()->pendingSend, "neuron_send_socket_brain_partial_rearms_send");
      suite.expect(fixture.neuron.brainStreamForTest()->pendingSendBytes == 6, "neuron_send_socket_brain_partial_tracks_remaining_send_bytes");
      suite.expect(fixture.neuron.brainStreamForTest()->wBuffer.outstandingBytes() == 6, "neuron_send_socket_brain_partial_consumes_sent_prefix");
      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()) == false, "neuron_send_socket_brain_partial_keeps_stream_open");
    }
  }

  {
    BrainSocketFixture fixture(suite, "neuron_send_socket_brain_negative");
    if (fixture.ready)
    {
      fixture.neuron.brainOutboundForTest().assign("brain"_ctv);
      fixture.neuron.brainStreamForTest()->pendingSend = true;
      fixture.neuron.brainStreamForTest()->pendingSendBytes = 5;
      fixture.neuron.brainStreamForTest()->noteSendQueued();

      fixture.neuron.sendSocketForTest(fixture.neuron.brainStreamForTest(), -EPIPE);

      suite.expect(TestNeuron::brainStreamIsClosingForTest(fixture.neuron.brainStreamForTest()), "neuron_send_socket_brain_negative_closes_stream");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_send_socket_container_partial", uint128_t(0xC107));
    if (fixture.ready)
    {
      fixture.container.wBuffer.assign("abcdef"_ctv);

      Ring::queueSend(&fixture.container);
      suite.expect(fixture.container.pendingSend, "neuron_send_socket_container_partial_arms_initial_send");
      suite.expect(fixture.container.pendingSendBytes == 6, "neuron_send_socket_container_partial_tracks_initial_send_bytes");

      fixture.neuron.sendSocketForTest(&fixture.container, 3);

      suite.expect(fixture.container.pendingSend, "neuron_send_socket_container_partial_rearms_send");
      suite.expect(fixture.container.pendingSendBytes == 3, "neuron_send_socket_container_partial_tracks_remaining_send_bytes");
      suite.expect(fixture.container.wBuffer.outstandingBytes() == 3, "neuron_send_socket_container_partial_consumes_sent_prefix");
      suite.expect(TestNeuron::containerStreamIsClosingForTest(&fixture.container) == false, "neuron_send_socket_container_partial_keeps_stream_open");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_send_socket_container_overflow", uint128_t(0xC108), true, std::numeric_limits<int>::min(), 8_KB, 8_KB);
    if (fixture.ready)
    {
      fixture.container.wBuffer.assign("abcd"_ctv);
      fixture.container.pendingSend = true;
      fixture.container.pendingSendBytes = 1;
      fixture.container.wBuffer.noteSendQueued();

      fixture.neuron.sendSocketForTest(&fixture.container, 2);

      suite.expect(fixture.container.wBuffer.size() == 0, "neuron_send_socket_container_overflow_clears_buffer");
      suite.expect(TestNeuron::containerStreamIsClosingForTest(&fixture.container), "neuron_send_socket_container_overflow_closes_stream");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_send_socket_container_negative", uint128_t(0xC109));
    if (fixture.ready)
    {
      fixture.container.wBuffer.assign("wxyz"_ctv);
      fixture.container.pendingSend = true;
      fixture.container.pendingSendBytes = 4;
      fixture.container.wBuffer.noteSendQueued();

      fixture.neuron.sendSocketForTest(&fixture.container, -EPIPE);

      suite.expect(fixture.container.wBuffer.size() == 0, "neuron_send_socket_container_negative_clears_buffer");
      suite.expect(TestNeuron::containerStreamIsClosingForTest(&fixture.container), "neuron_send_socket_container_negative_closes_stream");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_send_socket_container_pending_destroy", uint128_t(0xC10A));
    if (fixture.ready)
    {
      fixture.container.pendingDestroy = true;
      fixture.container.wBuffer.assign("destroy"_ctv);
      fixture.container.pendingSend = true;
      fixture.container.pendingSendBytes = 7;
      fixture.container.wBuffer.noteSendQueued();

      fixture.neuron.sendSocketForTest(&fixture.container, 0);

      suite.expect(fixture.container.pendingSend == false, "neuron_send_socket_container_pending_destroy_clears_pending_send");
      suite.expect(fixture.container.pendingSendBytes == 0, "neuron_send_socket_container_pending_destroy_clears_pending_send_bytes");
      suite.expect(fixture.container.wBuffer.size() == 0, "neuron_send_socket_container_pending_destroy_clears_buffer");
      suite.expect(TestNeuron::containerStreamIsClosingForTest(&fixture.container) == false, "neuron_send_socket_container_pending_destroy_keeps_stream_open");
    }
  }

  {
    ContainerSocketFixture fixture(suite, "neuron_send_socket_container_untracked", uint128_t(0xC10B), false);
    if (fixture.ready)
    {
      fixture.container.wBuffer.assign("skip"_ctv);
      fixture.container.pendingSend = true;
      fixture.container.pendingSendBytes = 4;
      fixture.container.wBuffer.noteSendQueued();

      fixture.neuron.sendSocketForTest(&fixture.container, 0);

      suite.expect(fixture.container.pendingSend, "neuron_send_socket_container_untracked_leaves_pending_send_untouched");
      suite.expect(fixture.container.pendingSendBytes == 4, "neuron_send_socket_container_untracked_leaves_send_bytes_untouched");
      suite.expect(fixture.container.wBuffer.size() > 0, "neuron_send_socket_container_untracked_leaves_buffer_untouched");
    }
  }
}

static void testNeuronPushContainerRefreshesTrackedWormholes(TestSuite& suite)
{
  {
    BrainContainerFixture fixture(suite, "neuron_push_container_wormholes", uint128_t(0x7030), false, false);
    if (fixture.ready)
    {
      Wormhole wormhole = {};
      wormhole.externalAddress = IPAddress("2001:db8:100::e", true);
      wormhole.externalPort = 443;
      wormhole.containerPort = 8443;
      wormhole.layer4 = IPPROTO_UDP;
      wormhole.isQuic = true;
      wormhole.source = ExternalAddressSource::hostPublicAddress;

      fixture.container.plan.wormholes.push_back(wormhole);
      fixture.container.pid = 1234;

      suite.expect(
          fixture.brain.neuron.refreshContainerSwitchboardWormholesCallsForTest == 0,
          "neuron_push_container_wormholes_starts_without_refresh");

      fixture.brain.neuron.pushContainerForTest(&fixture.container);
      fixture.tracked = true;

      suite.expect(
          fixture.brain.neuron.refreshContainerSwitchboardWormholesCallsForTest == 1,
          "neuron_push_container_wormholes_refreshes_switchboard_state");
      suite.expect(
          fixture.brain.neuron.syncContainerSwitchboardRuntimeCallsForTest == 1,
          "neuron_push_container_wormholes_syncs_live_runtime");
      suite.expect(
          fixture.brain.neuron.lastRefreshedContainerUUIDForTest == fixture.container.plan.uuid,
          "neuron_push_container_wormholes_tracks_container_uuid");
      suite.expect(
          fixture.brain.neuron.lastSyncedContainerUUIDForTest == fixture.container.plan.uuid,
          "neuron_push_container_wormholes_tracks_synced_container_uuid");
      suite.expect(
          fixture.brain.neuron.lastRefreshedWormholesForTest.size() == 1 && equalSerializedObjects(fixture.brain.neuron.lastRefreshedWormholesForTest[0], wormhole),
          "neuron_push_container_wormholes_tracks_live_wormholes");
    }
  }

  {
    BrainContainerFixture fixture(suite, "neuron_push_container_empty_wormholes", uint128_t(0x7031), false, false);
    if (fixture.ready)
    {
      fixture.container.pid = 1235;
      fixture.brain.neuron.pushContainerForTest(&fixture.container);
      fixture.tracked = true;

      suite.expect(
          fixture.brain.neuron.refreshContainerSwitchboardWormholesCallsForTest == 0,
          "neuron_push_container_empty_wormholes_skips_refresh_path");
      suite.expect(
          fixture.brain.neuron.syncContainerSwitchboardRuntimeCallsForTest == 0,
          "neuron_push_container_empty_wormholes_skips_runtime_sync");
      suite.expect(
          fixture.brain.neuron.lastRefreshedContainerUUIDForTest == 0,
          "neuron_push_container_empty_wormholes_leaves_refresh_uuid_empty");
      suite.expect(
          fixture.brain.neuron.lastRefreshedWormholesForTest.empty(),
          "neuron_push_container_empty_wormholes_keeps_empty_wormhole_state");
    }
  }
}

static void testNeuronContainerHandlerForwardsHealthyToBrain(TestSuite& suite)
{
  TestNeuron neuron = {};
  neuron.seedBrainStreamForTest(false);

  Container container = {};
  container.plan.uuid = uint128_t(0x5101);
  container.plan.config.applicationID = 62'010;
  container.plan.config.versionID = 7;
  container.plan.state = ContainerState::scheduled;

  String buffer = {};
  Message *message = buildContainerMessage(buffer, ContainerTopic::healthy);
  neuron.containerHandler(&container, message);

  uint32_t healthyFrames = 0;
  uint128_t observedContainerUUID = 0;
  forEachMessageInBuffer(neuron.brainOutboundForTest(), [&](Message *frame) {
    suite.expect(NeuronTopic(frame->topic) == NeuronTopic::containerHealthy, "neuron_container_healthy_frame_topic");
    if (NeuronTopic(frame->topic) != NeuronTopic::containerHealthy)
    {
      return;
    }

    uint8_t *args = frame->args;
    Message::extractArg<ArgumentNature::fixed>(args, observedContainerUUID);
    healthyFrames += 1;
  });

  suite.expect(container.plan.state == ContainerState::healthy, "neuron_container_healthy_marks_container_healthy");
  suite.expect(healthyFrames == 1, "neuron_container_healthy_emits_single_brain_frame");
  suite.expect(observedContainerUUID == container.plan.uuid, "neuron_container_healthy_preserves_container_uuid");
}

static void testNeuronContainerHandlerMarksMasterLocalContainerHealthyWithoutBrainStream(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  TestNeuron neuron = {};

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'012;

  Machine machine = {};
  machine.uuid = uint128_t(0x5103);
  machine.state = MachineState::healthy;
  machine.rack = &rack;
  machine.isThisMachine = true;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'012, 1);
  deployment.state = DeploymentState::deploying;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  Container container = {};
  container.plan.uuid = uint128_t(0x5104);
  container.plan.config = deployment.plan.config;
  container.plan.state = ContainerState::scheduled;

  ContainerView *view = new ContainerView();
  view->uuid = container.plan.uuid;
  view->deploymentID = deployment.plan.config.deploymentID();
  view->applicationID = deployment.plan.config.applicationID;
  view->machine = &machine;
  view->lifetime = ApplicationLifetime::base;
  view->state = ContainerState::scheduled;
  deployment.containers.insert(view);
  deployment.waitingOnContainers.insert_or_assign(view, ContainerState::healthy);
  brain.containers.insert_or_assign(view->uuid, view);
  machine.upsertContainerIndexEntry(view->deploymentID, view);

  String buffer = {};
  Message *message = buildContainerMessage(buffer, ContainerTopic::healthy);
  neuron.containerHandler(&container, message);

  suite.expect(container.plan.state == ContainerState::healthy, "neuron_container_healthy_without_brain_stream_marks_runtime_container_healthy");
  suite.expect(view->state == ContainerState::healthy, "neuron_container_healthy_without_brain_stream_marks_master_local_view_healthy");
  suite.expect(deployment.nHealthyBase == 1, "neuron_container_healthy_without_brain_stream_counts_master_local_container_once");
  suite.expect(deployment.waitingOnContainers.size() == 0, "neuron_container_healthy_without_brain_stream_clears_waiters");
  suite.expect(neuron.brainStreamForTest() == nullptr, "neuron_container_healthy_without_brain_stream_skips_missing_brain_frame");

  deployment.containers.erase(view);
  machine.removeContainerIndexEntry(view->deploymentID, view);
  brain.containers.erase(view->uuid);
  delete view;

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
  std::fprintf(stderr, "suite-check healthy-master-no-brain exit failed=%d\n", suite.failed);
}

static void testNeuronContainerHandlerRelaysHealthyToMasterPeerWithoutBrainStream(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = false;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  BrainView masterPeer = {};
  masterPeer.isMasterBrain = true;
  masterPeer.connected = true;
  masterPeer.isFixedFile = true;
  masterPeer.fslot = 41;
  masterPeer.private4 = 0x0A00000A;
  brain.brains.insert(&masterPeer);

  TestNeuron neuron = {};

  Container container = {};
  container.plan.uuid = uint128_t(0x5105);
  container.plan.config.applicationID = 62'012;
  container.plan.config.versionID = 7;
  container.plan.state = ContainerState::scheduled;

  String buffer = {};
  Message *message = buildContainerMessage(buffer, ContainerTopic::healthy);
  neuron.containerHandler(&container, message);

  uint32_t relayedHealthyFrames = 0;
  bool sawRelayedUUID = false;
  forEachMessageInBuffer(masterPeer.wBuffer, [&](Message *frame) {
    suite.expect(BrainTopic(frame->topic) == BrainTopic::replicateContainerHealthy, "neuron_container_healthy_without_brain_stream_relays_brain_topic");
    if (BrainTopic(frame->topic) != BrainTopic::replicateContainerHealthy)
    {
      return;
    }

    uint8_t *args = frame->args;
    uint128_t observedUUID = 0;
    Message::extractArg<ArgumentNature::fixed>(args, observedUUID);
    relayedHealthyFrames += 1;
    sawRelayedUUID = sawRelayedUUID || (observedUUID == container.plan.uuid);
  });

  suite.expect(container.plan.state == ContainerState::healthy, "neuron_container_healthy_without_brain_stream_marks_follower_runtime_container_healthy");
  suite.expect(relayedHealthyFrames == 1, "neuron_container_healthy_without_brain_stream_relays_single_master_peer_frame");
  suite.expect(sawRelayedUUID, "neuron_container_healthy_without_brain_stream_preserves_relayed_uuid");
  suite.expect(neuron.brainStreamForTest() == nullptr, "neuron_container_healthy_without_brain_stream_skips_missing_control_stream_frame");

  brain.brains.erase(&masterPeer);
  thisBrain = previousBrain;
}

static void testNeuronContainerHandlerMarksMasterLocalContainerHealthyWithActiveBrainStream(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  TestNeuron neuron = {};
  neuron.seedBrainStreamForTest(false);

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'013;

  Machine machine = {};
  machine.uuid = uint128_t(0x5105);
  machine.state = MachineState::healthy;
  machine.rack = &rack;
  machine.isThisMachine = true;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'013, 1);
  deployment.state = DeploymentState::deploying;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  Container container = {};
  container.plan.uuid = uint128_t(0x5106);
  container.plan.config = deployment.plan.config;
  container.plan.state = ContainerState::scheduled;

  ContainerView *view = new ContainerView();
  view->uuid = container.plan.uuid;
  view->deploymentID = deployment.plan.config.deploymentID();
  view->applicationID = deployment.plan.config.applicationID;
  view->machine = &machine;
  view->lifetime = ApplicationLifetime::base;
  view->state = ContainerState::scheduled;
  deployment.containers.insert(view);
  deployment.waitingOnContainers.insert_or_assign(view, ContainerState::healthy);
  brain.containers.insert_or_assign(view->uuid, view);
  machine.upsertContainerIndexEntry(view->deploymentID, view);

  String buffer = {};
  Message *message = buildContainerMessage(buffer, ContainerTopic::healthy);
  neuron.containerHandler(&container, message);

  uint32_t forwardedHealthyFrames = 0;
  bool sawForwardedUUID = false;
  forEachMessageInBuffer(neuron.brainOutboundForTest(), [&](Message *frame) {
    if (NeuronTopic(frame->topic) != NeuronTopic::containerHealthy)
    {
      return;
    }

    uint8_t *args = frame->args;
    uint128_t observedUUID = 0;
    Message::extractArg<ArgumentNature::fixed>(args, observedUUID);
    forwardedHealthyFrames += 1;
    sawForwardedUUID = sawForwardedUUID || (observedUUID == container.plan.uuid);
  });

  suite.expect(container.plan.state == ContainerState::healthy, "neuron_container_healthy_with_brain_stream_marks_runtime_container_healthy");
  suite.expect(view->state == ContainerState::healthy, "neuron_container_healthy_with_brain_stream_marks_master_local_view_healthy");
  suite.expect(deployment.nHealthyBase == 1, "neuron_container_healthy_with_brain_stream_counts_master_local_container_once");
  suite.expect(deployment.waitingOnContainers.size() == 0, "neuron_container_healthy_with_brain_stream_clears_waiters");
  suite.expect(forwardedHealthyFrames == 1, "neuron_container_healthy_with_brain_stream_keeps_forwarded_brain_frame");
  suite.expect(sawForwardedUUID, "neuron_container_healthy_with_brain_stream_preserves_forwarded_uuid");

  deployment.containers.erase(view);
  machine.removeContainerIndexEntry(view->deploymentID, view);
  brain.containers.erase(view->uuid);
  delete view;

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testNeuronContainerHandlerForwardsStatisticsToBrain(TestSuite& suite)
{
  TestNeuron neuron = {};
  neuron.seedBrainStreamForTest(false);

  Container container = {};
  container.plan.uuid = uint128_t(0x5102);
  container.plan.config.applicationID = 62'011;
  container.plan.config.versionID = 9;

  uint64_t deploymentID = container.plan.config.deploymentID();
  uint64_t cpuMetricKey = ProdigyMetrics::runtimeContainerCpuUtilPctKey();
  uint64_t memoryMetricKey = ProdigyMetrics::runtimeContainerMemoryUtilPctKey();
  int64_t beforeMs = Time::now<TimeResolution::ms>();

  String buffer = {};
  Message *message = buildContainerMessage(
      buffer,
      ContainerTopic::statistics,
      cpuMetricKey,
      uint64_t(77),
      memoryMetricKey,
      uint64_t(88));
  neuron.containerHandler(&container, message);
  int64_t afterMs = Time::now<TimeResolution::ms>();

  uint32_t statisticsFrames = 0;
  bool sawCpuMetric = false;
  bool sawMemoryMetric = false;
  forEachMessageInBuffer(neuron.brainOutboundForTest(), [&](Message *frame) {
    suite.expect(NeuronTopic(frame->topic) == NeuronTopic::containerStatistics, "neuron_container_statistics_frame_topic");
    if (NeuronTopic(frame->topic) != NeuronTopic::containerStatistics)
    {
      return;
    }

    statisticsFrames += 1;

    uint8_t *args = frame->args;
    uint64_t observedDeploymentID = 0;
    uint128_t observedContainerUUID = 0;
    int64_t sampleTimeMs = 0;
    Message::extractArg<ArgumentNature::fixed>(args, observedDeploymentID);
    Message::extractArg<ArgumentNature::fixed>(args, observedContainerUUID);
    Message::extractArg<ArgumentNature::fixed>(args, sampleTimeMs);

    suite.expect(observedDeploymentID == deploymentID, "neuron_container_statistics_preserves_deployment_id");
    suite.expect(observedContainerUUID == container.plan.uuid, "neuron_container_statistics_preserves_container_uuid");
    suite.expect(sampleTimeMs >= beforeMs && sampleTimeMs <= afterMs, "neuron_container_statistics_stamps_current_time");

    while (args < frame->terminal())
    {
      uint64_t metricKey = 0;
      uint64_t metricValue = 0;
      Message::extractArg<ArgumentNature::fixed>(args, metricKey);
      Message::extractArg<ArgumentNature::fixed>(args, metricValue);

      if (metricKey == cpuMetricKey && metricValue == 77)
      {
        sawCpuMetric = true;
      }

      if (metricKey == memoryMetricKey && metricValue == 88)
      {
        sawMemoryMetric = true;
      }
    }
  });

  suite.expect(statisticsFrames == 1, "neuron_container_statistics_emits_single_brain_frame");
  suite.expect(sawCpuMetric, "neuron_container_statistics_forwards_cpu_metric");
  suite.expect(sawMemoryMetric, "neuron_container_statistics_forwards_memory_metric");
}

static void testNeuronHandlerStoresRequestedContainerBlob(TestSuite& suite)
{
  TestNeuron neuron = {};

  const uint64_t deploymentID = 0x6201200000000001ull;
  String containerBlob = prodigyDiscombobulatorBlobHeaderText();
  containerBlob.append("unit-test-container-blob"_ctv);
  ContainerStore::destroy(deploymentID);

  String buffer = {};
  Message *message = buildNeuronMessage(buffer, NeuronTopic::requestContainerBlob, deploymentID, containerBlob);
  neuron.neuronHandler(message);

  String storedBlob = {};
  ContainerStore::get(deploymentID, storedBlob);
  suite.expect(storedBlob.equals(containerBlob), "neuron_request_container_blob_stores_blob");

  ContainerStore::destroy(deploymentID);

  String missingBuffer = {};
  Message *missingMessage = buildNeuronMessage(missingBuffer, NeuronTopic::requestContainerBlob, deploymentID, String());
  neuron.neuronHandler(missingMessage);
  suite.expect(ContainerStore::contains(deploymentID) == false, "neuron_request_container_blob_skips_empty_payload");
}

static void testNeuronSpinContainerRejectReportsFailure(TestSuite& suite)
{
  TestNeuron neuron = {};
  neuron.seedBrainStreamForTest(false);

  NeuronBase *previousNeuron = thisNeuron;
  thisNeuron = &neuron;

  ContainerPlan plan = {};
  plan.uuid = uint128_t(0x62013001);
  plan.config.applicationID = 62'013;
  plan.config.versionID = 1;
  plan.config.containerBlobSHA256.assign("invalid"_ctv);
  plan.config.containerBlobBytes = 3;
  const uint64_t deploymentID = plan.config.deploymentID();
  ContainerStore::destroy(deploymentID);

  String imagePath = ContainerStore::pathForContainerImage(deploymentID);
  suite.expect(Filesystem::createDirectoryAt(-1, "/containers"_ctv, 0755) >= 0 || errno == EEXIST, "spin_container_reject_create_containers_root");
  suite.expect(Filesystem::createDirectoryAt(-1, "/containers/store"_ctv, 0755) >= 0 || errno == EEXIST, "spin_container_reject_create_store_root");
  suite.expect(Filesystem::openWriteAtClose(-1, imagePath, "bad"_ctv) == 3, "spin_container_reject_fixture_blob");

  NeuronContainerBootstrap bootstrap = {};
  bootstrap.plan = plan;
  String serialized = {};
  BitseryEngine::serialize(serialized, bootstrap);

  String buffer = {};
  Message *message = buildNeuronMessage(buffer, NeuronTopic::spinContainer, uint128_t(0), serialized);
  neuron.dispatchBrainMessageForTest(message);

  uint32_t failures = 0;
  uint128_t failedUUID = 0;
  bool restarted = true;
  String report = {};
  forEachMessageInBuffer(neuron.brainOutboundForTest(), [&](Message *frame) {
    if (NeuronTopic(frame->topic) != NeuronTopic::containerFailed)
    {
      return;
    }
    uint8_t *args = frame->args;
    int64_t ignoredAt = 0;
    int ignoredSignal = 0;
    Message::extractArg<ArgumentNature::fixed>(args, failedUUID);
    Message::extractArg<ArgumentNature::fixed>(args, ignoredAt);
    Message::extractArg<ArgumentNature::fixed>(args, ignoredSignal);
    Message::extractToStringView(args, report);
    Message::extractArg<ArgumentNature::fixed>(args, restarted);
    failures += 1;
  });

  suite.expect(failures == 1, "spin_container_reject_reports_one_failure");
  suite.expect(failedUUID == plan.uuid, "spin_container_reject_reports_plan_uuid");
  suite.expect(restarted == false, "spin_container_reject_reports_non_restart");
  suite.expect(report.size() > 0, "spin_container_reject_reports_reason");

  ContainerStore::destroy(deploymentID);
  thisNeuron = previousNeuron;
}

static void testNeuronStateUploadSkipsExistingLiveContainer(TestSuite& suite)
{
  TestNeuron neuron = {};
  neuron.seedLocalContainerSubnetForTest(7, 0x123456);

  Container *container = new Container();
  container->plan.uuid = uint128_t(0x5104);
  container->plan.config.applicationID = 62'013;
  container->plan.config.versionID = 1;
  container->plan.state = ContainerState::healthy;
  container->pid = 4242;
  container->neuronScalingDimensionsMask = 1;
  container->neuronMetricsCadenceMs = 1000;
  neuron.containers.insert_or_assign(container->plan.uuid, container);
  neuron.containerByPid.insert_or_assign(container->pid, container);

  ContainerPlan uploadedPlan = container->plan;
  uploadedPlan.state = ContainerState::scheduled;
  NeuronContainerBootstrap bootstrap = {};
  bootstrap.plan = uploadedPlan;
  bootstrap.metricPolicy.scalingDimensionsMask = 0x5a5a;
  bootstrap.metricPolicy.metricsCadenceMs = 250;

  String serializedBootstrap = {};
  BitseryEngine::serialize(serializedBootstrap, bootstrap);

  String buffer = {};
  uint32_t headerOffset = Message::appendHeader(buffer, NeuronTopic::stateUpload);
  local_container_subnet6 fragment = {};
  fragment.dpfx = 7;
  fragment.mpfx[0] = 0x12;
  fragment.mpfx[1] = 0x34;
  fragment.mpfx[2] = 0x56;
  Message::appendAlignedBuffer<Alignment::one>(buffer, reinterpret_cast<const uint8_t *>(&fragment), sizeof(fragment));
  Message::appendValue(buffer, serializedBootstrap);
  Message::finish(buffer, headerOffset);

  Message *message = reinterpret_cast<Message *>(buffer.data());
  neuron.dispatchBrainMessageForTest(message);

  auto existing = neuron.containers.find(container->plan.uuid);
  suite.expect(existing != neuron.containers.end(), "neuron_state_upload_existing_live_container_still_tracked");
  suite.expect(existing != neuron.containers.end() && existing->second == container, "neuron_state_upload_existing_live_container_pointer_preserved");
  suite.expect(neuron.containers.size() == 1, "neuron_state_upload_existing_live_container_not_duplicated");
  suite.expect(container->plan.state == ContainerState::healthy, "neuron_state_upload_existing_live_container_keeps_runtime_state");
  suite.expect(container->pid == 4242, "neuron_state_upload_existing_live_container_keeps_pid");
  suite.expect(container->neuronScalingDimensionsMask == 0x5a5a, "neuron_state_upload_existing_live_container_refreshes_metric_mask");
  suite.expect(container->neuronMetricsCadenceMs == 250, "neuron_state_upload_existing_live_container_refreshes_metric_cadence");

  neuron.containerByPid.erase(container->pid);
  neuron.containers.erase(container->plan.uuid);
  delete container;
}

static void testNeuronHandlerKillContainerStopsContainerAndEchoesBrain(TestSuite& suite)
{
  ScopedRing scopedRing = {};

  TestNeuron neuron = {};
  neuron.seedBrainStreamForTest(false);

  Container *container = new Container();
  container->plan.uuid = uint128_t(0x5103);
  container->plan.config.applicationID = 62'012;
  container->plan.config.versionID = 11;
  neuron.containers.insert_or_assign(container->plan.uuid, container);

  NeuronBase *previousNeuron = thisNeuron;
  thisNeuron = &neuron;

  String buffer = {};
  Message *message = buildNeuronMessage(buffer, NeuronTopic::killContainer, container->plan.uuid);
  neuron.neuronHandler(message);

  uint32_t stopFrames = 0;
  forEachMessageInBuffer(container->wBuffer, [&](Message *frame) {
    if (ContainerTopic(frame->topic) == ContainerTopic::stop)
    {
      stopFrames += 1;
    }
  });

  uint32_t echoFrames = 0;
  uint128_t echoedContainerUUID = 0;
  forEachMessageInBuffer(neuron.brainOutboundForTest(), [&](Message *frame) {
    if (NeuronTopic(frame->topic) != NeuronTopic::killContainer)
    {
      return;
    }

    uint8_t *args = frame->args;
    Message::extractArg<ArgumentNature::fixed>(args, echoedContainerUUID);
    echoFrames += 1;
  });

  suite.expect(stopFrames == 1, "neuron_kill_container_queues_stop_frame");
  suite.expect(container->killSwitch != nullptr, "neuron_kill_container_arms_kill_switch");
  suite.expect(container->pendingKillAckToBrain, "neuron_kill_container_marks_pending_brain_ack");
  suite.expect(echoFrames == 0, "neuron_kill_container_defers_brain_ack_until_destroy");
  suite.expect(echoedContainerUUID == 0, "neuron_kill_container_no_immediate_brain_ack_uuid");

  thisNeuron = previousNeuron;
  neuron.containers.erase(container->plan.uuid);
  delete container;
}

static void testBrainNeuronHandlerMarksContainerHealthyOnceAndClearsWaiters(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'020;

  Machine machine = {};
  machine.uuid = uint128_t(0x5201);
  machine.state = MachineState::healthy;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'020, 1);
  deployment.state = DeploymentState::deploying;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  ContainerView *container = new ContainerView();
  container->uuid = uint128_t(0x5202);
  container->deploymentID = deployment.plan.config.deploymentID();
  container->machine = &machine;
  container->lifetime = ApplicationLifetime::base;
  container->state = ContainerState::scheduled;

  deployment.containers.insert(container);
  deployment.waitingOnContainers.insert_or_assign(container, ContainerState::healthy);
  brain.containers.insert_or_assign(container->uuid, container);
  machine.upsertContainerIndexEntry(container->deploymentID, container);

  String buffer = {};
  Message *message = buildNeuronMessage(buffer, NeuronTopic::containerHealthy, container->uuid);
  brain.neuronHandler(&machine.neuron, message);
  brain.neuronHandler(&machine.neuron, message);

  suite.expect(container->state == ContainerState::healthy, "brain_neuron_container_healthy_marks_container_healthy");
  suite.expect(deployment.nHealthyBase == 1, "brain_neuron_container_healthy_increments_count_once");
  suite.expect(deployment.waitingOnContainers.size() == 0, "brain_neuron_container_healthy_clears_waiters");

  deployment.containers.erase(container);
  machine.removeContainerIndexEntry(container->deploymentID, container);
  brain.containers.erase(container->uuid);
  delete container;

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainReplicatedContainerHealthyMarksContainerHealthyOnMaster(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'021;

  Machine machine = {};
  machine.uuid = uint128_t(0x5203);
  machine.state = MachineState::healthy;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'021, 1);
  deployment.state = DeploymentState::deploying;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  ContainerView *container = new ContainerView();
  container->uuid = uint128_t(0x5204);
  container->deploymentID = deployment.plan.config.deploymentID();
  container->machine = &machine;
  container->lifetime = ApplicationLifetime::base;
  container->state = ContainerState::scheduled;

  deployment.containers.insert(container);
  deployment.waitingOnContainers.insert_or_assign(container, ContainerState::healthy);
  brain.containers.insert_or_assign(container->uuid, container);
  machine.upsertContainerIndexEntry(container->deploymentID, container);

  BrainView follower = {};
  follower.private4 = 0x0A00000B;

  String buffer = {};
  Message *message = buildBrainMessage(buffer, BrainTopic::replicateContainerHealthy, container->uuid);
  brain.brainHandler(&follower, message);
  brain.brainHandler(&follower, message);

  suite.expect(container->state == ContainerState::healthy, "brain_replicated_container_healthy_marks_container_healthy");
  suite.expect(deployment.nHealthyBase == 1, "brain_replicated_container_healthy_increments_count_once");
  suite.expect(deployment.waitingOnContainers.size() == 0, "brain_replicated_container_healthy_clears_waiters");

  deployment.containers.erase(container);
  machine.removeContainerIndexEntry(container->deploymentID, container);
  brain.containers.erase(container->uuid);
  delete container;

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainContainerHealthyReplicatesRuntimeStateToFollowers(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'022;

  Machine machine = {};
  machine.uuid = uint128_t(0x5205);
  machine.private4 = 0x0A00002A;
  machine.state = MachineState::healthy;
  machine.fragment = 0x1234;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'022, 1);
  deployment.state = DeploymentState::deploying;
  deployment.nTargetBase = 1;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  ContainerView *container = new ContainerView();
  container->uuid = uint128_t(0x5206);
  container->deploymentID = deployment.plan.config.deploymentID();
  container->applicationID = deployment.plan.config.applicationID;
  container->machine = &machine;
  container->lifetime = ApplicationLifetime::base;
  container->state = ContainerState::scheduled;
  container->fragment = 8;
  container->createdAtMs = 123'460;
  container->runtime_nLogicalCores = 2;
  container->runtime_memoryMB = 512;
  container->runtime_storageMB = 1024;

  deployment.containers.insert(container);
  deployment.waitingOnContainers.insert_or_assign(container, ContainerState::healthy);
  brain.containers.insert_or_assign(container->uuid, container);
  machine.upsertContainerIndexEntry(container->deploymentID, container);

  BrainView follower = {};
  follower.connected = true;
  follower.isFixedFile = true;
  follower.fslot = 53;
  brain.brains.insert(&follower);

  String buffer = {};
  Message *message = buildNeuronMessage(buffer, NeuronTopic::containerHealthy, container->uuid);
  brain.neuronHandler(&machine.neuron, message);

  bool sawRuntimeState = false;
  BrainReplicatedContainerRuntimeState replicated = {};
  forEachMessageInBuffer(follower.wBuffer, [&](Message *frame) {
    if (BrainTopic(frame->topic) != BrainTopic::replicateContainerRuntimeState)
    {
      return;
    }

    uint8_t *args = frame->args;
    String serialized;
    Message::extractToStringView(args, serialized);
    sawRuntimeState = BitseryEngine::deserializeSafe(serialized, replicated);
  });

  suite.expect(sawRuntimeState, "brain_container_healthy_replicates_runtime_state");
  suite.expect(replicated.machineUUID == machine.uuid, "brain_container_healthy_replicates_machine_uuid");
  suite.expect(replicated.machinePrivate4 == machine.private4, "brain_container_healthy_replicates_machine_private4");
  suite.expect(replicated.plan.uuid == container->uuid, "brain_container_healthy_replicates_container_uuid");
  suite.expect(replicated.plan.state == ContainerState::healthy, "brain_container_healthy_replicates_healthy_state");
  suite.expect(replicated.runtimeLogicalCores == container->runtime_nLogicalCores, "brain_container_healthy_replicates_runtime_cores");

  brain.brains.erase(&follower);
  deployment.containers.erase(container);
  machine.removeContainerIndexEntry(container->deploymentID, container);
  brain.containers.erase(container->uuid);
  delete container;

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainReplicatedContainerRuntimeStateRestoresTakeoverView(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.ignited = true;
  brain.brainConfig.datacenterFragment = 1;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'023;

  Machine machine = {};
  machine.uuid = uint128_t(0x5207);
  machine.private4 = 0x0A00002B;
  machine.state = MachineState::healthy;
  machine.runtimeReady = true;
  machine.fragment = 0x1235;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 41;
  machine.neuron.connected = true;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'023, 1);
  deployment.plan.stateless.nBase = 1;
  deployment.nTargetBase = 1;
  deployment.state = DeploymentState::none;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  ContainerView seed = {};
  seed.uuid = uint128_t(0x5208);
  seed.deploymentID = deployment.plan.config.deploymentID();
  seed.applicationID = deployment.plan.config.applicationID;
  seed.machine = &machine;
  seed.lifetime = ApplicationLifetime::base;
  seed.state = ContainerState::healthy;
  seed.runtimeReady = true;
  seed.fragment = 9;
  seed.createdAtMs = 123'461;
  seed.runtime_nLogicalCores = 2;
  seed.runtime_memoryMB = 768;
  seed.runtime_storageMB = 2048;

  BrainReplicatedContainerRuntimeState runtimeState = {};
  runtimeState.machineUUID = machine.uuid;
  runtimeState.machinePrivate4 = machine.private4;
  runtimeState.plan = seed.generatePlan(deployment.plan);
  runtimeState.runtimeLogicalCores = seed.runtime_nLogicalCores;
  runtimeState.runtimeMemoryMB = seed.runtime_memoryMB;
  runtimeState.runtimeStorageMB = seed.runtime_storageMB;

  String serialized = {};
  BitseryEngine::serialize(serialized, runtimeState);

  BrainView source = {};
  String buffer = {};
  Message *message = buildBrainMessage(buffer, BrainTopic::replicateContainerRuntimeState, serialized);
  brain.brainHandler(&source, message);

  auto restoredIt = brain.containers.find(seed.uuid);
  ContainerView *restored = (restoredIt != brain.containers.end()) ? restoredIt->second : nullptr;
  suite.expect(restored != nullptr, "brain_replicated_runtime_state_restores_container");
  suite.expect(restored != nullptr && restored->machine == &machine, "brain_replicated_runtime_state_restores_machine");
  suite.expect(restored != nullptr && restored->state == ContainerState::healthy, "brain_replicated_runtime_state_restores_healthy_state");
  suite.expect(restored != nullptr && restored->runtimeReady == true, "brain_replicated_runtime_state_restores_runtime_ready");
  suite.expect(deployment.containers.contains(restored), "brain_replicated_runtime_state_indexes_deployment");
  suite.expect(machine.containersByDeploymentID.contains(deployment.plan.config.deploymentID()), "brain_replicated_runtime_state_indexes_machine");
  suite.expect(deployment.nDeployedBase == 1, "brain_replicated_runtime_state_rebuilds_deployed_count");
  suite.expect(deployment.nHealthyBase == 1, "brain_replicated_runtime_state_rebuilds_healthy_count");

  if (restored != nullptr)
  {
    deployment.containers.erase(restored);
    machine.removeContainerIndexEntry(restored->deploymentID, restored);
    brain.containers.erase(restored->uuid);
    delete restored;
  }

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainReplicatedContainerRuntimeStateWaitsForDeployment(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.ignited = true;
  brain.brainConfig.datacenterFragment = 1;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'024;

  Machine machine = {};
  machine.uuid = uint128_t(0x5209);
  machine.private4 = 0x0A00002C;
  machine.state = MachineState::healthy;
  machine.runtimeReady = true;
  machine.fragment = 0x1236;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 42;
  machine.neuron.connected = true;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'024, 1);
  deployment.plan.stateless.nBase = 1;
  deployment.nTargetBase = 1;

  ContainerView seed = {};
  seed.uuid = uint128_t(0x520A);
  seed.deploymentID = deployment.plan.config.deploymentID();
  seed.applicationID = deployment.plan.config.applicationID;
  seed.machine = &machine;
  seed.lifetime = ApplicationLifetime::base;
  seed.state = ContainerState::healthy;
  seed.fragment = 10;
  seed.createdAtMs = 123'462;

  BrainReplicatedContainerRuntimeState runtimeState = {};
  runtimeState.machineUUID = machine.uuid;
  runtimeState.machinePrivate4 = machine.private4;
  runtimeState.plan = seed.generatePlan(deployment.plan);

  brain.applyReplicatedContainerRuntimeState(runtimeState);
  suite.expect(brain.containers.find(seed.uuid) == brain.containers.end(), "brain_replicated_runtime_state_pending_before_deployment");

  deployment.state = DeploymentState::none;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);
  brain.applyPendingReplicatedContainerRuntimeStates(deployment.plan.config.deploymentID());

  auto restoredIt = brain.containers.find(seed.uuid);
  ContainerView *restored = (restoredIt != brain.containers.end()) ? restoredIt->second : nullptr;
  suite.expect(restored != nullptr, "brain_replicated_runtime_state_pending_applies_after_deployment");
  suite.expect(deployment.nHealthyBase == 1, "brain_replicated_runtime_state_pending_rebuilds_healthy_count");

  if (restored != nullptr)
  {
    deployment.containers.erase(restored);
    machine.removeContainerIndexEntry(restored->deploymentID, restored);
    brain.containers.erase(restored->uuid);
    delete restored;
  }

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainNeuronStateUploadRemovesStaleCanonicalMachineContainer(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'030;

  Machine machine = {};
  machine.uuid = uint128_t(0x5301);
  machine.state = MachineState::healthy;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'030, 1);
  deployment.state = DeploymentState::deploying;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  ContainerView *stale = new ContainerView();
  stale->uuid = uint128_t(0x5302);
  uint128_t staleUUID = stale->uuid;
  stale->deploymentID = deployment.plan.config.deploymentID();
  stale->applicationID = deployment.plan.config.applicationID;
  stale->machine = &machine;
  stale->lifetime = ApplicationLifetime::base;
  stale->state = ContainerState::healthy;
  stale->fragment = 9;
  stale->createdAtMs = 123'456;

  deployment.containers.insert(stale);
  brain.containers.insert_or_assign(stale->uuid, stale);
  machine.upsertContainerIndexEntry(stale->deploymentID, stale);

  ContainerView liveSeed = {};
  liveSeed.uuid = uint128_t(0x5303);
  liveSeed.fragment = 10;
  liveSeed.lifetime = ApplicationLifetime::base;
  liveSeed.state = ContainerState::healthy;
  liveSeed.createdAtMs = 123'457;
  liveSeed.shardGroup = 0;
  ContainerPlan livePlan = liveSeed.generatePlan(deployment.plan);

  String uploadBuffer = {};
  uint32_t headerOffset = Message::appendHeader(uploadBuffer, NeuronTopic::stateUpload);
  local_container_subnet6 fragment = {};
  fragment.dpfx = 1;
  fragment.mpfx[0] = 0x00;
  fragment.mpfx[1] = 0x12;
  fragment.mpfx[2] = 0x34;
  Message::appendAlignedBuffer<Alignment::one>(uploadBuffer, reinterpret_cast<const uint8_t *>(&fragment), sizeof(fragment));
  String serializedLivePlan = {};
  BitseryEngine::serialize(serializedLivePlan, livePlan);
  Message::appendValue(uploadBuffer, serializedLivePlan);
  Message::finish(uploadBuffer, headerOffset);

  Message *message = reinterpret_cast<Message *>(uploadBuffer.data());
  brain.neuronHandler(&machine.neuron, message);

  suite.expect(machine.runtimeReady == true, "brain_neuron_state_upload_marks_machine_runtime_ready");
  auto liveIt = brain.containers.find(livePlan.uuid);
  suite.expect(liveIt != brain.containers.end(), "brain_neuron_state_upload_tracks_reported_container");
  suite.expect(brain.containers.find(staleUUID) == brain.containers.end(), "brain_neuron_state_upload_removes_stale_canonical_container");
  suite.expect(deployment.containers.size() == 1, "brain_neuron_state_upload_prunes_deployment_container_set");
  suite.expect(machine.containersByDeploymentID.size() == 1, "brain_neuron_state_upload_prunes_machine_container_bins");

  ContainerView *live = (liveIt != brain.containers.end()) ? liveIt->second : nullptr;
  suite.expect(live != nullptr && live->machine == &machine, "brain_neuron_state_upload_assigns_live_container_machine");
  suite.expect(live != nullptr && live->deploymentID == deployment.plan.config.deploymentID(), "brain_neuron_state_upload_assigns_live_container_deployment");

  if (auto indexed = machine.containersByDeploymentID.find(deployment.plan.config.deploymentID()); indexed != machine.containersByDeploymentID.end())
  {
    suite.expect(indexed->second.size() == 1, "brain_neuron_state_upload_keeps_one_indexed_machine_container");
    suite.expect(indexed->second.size() == 1 && indexed->second[0] == live, "brain_neuron_state_upload_indexes_only_live_container");
  }
  else
  {
    suite.expect(false, "brain_neuron_state_upload_keeps_deployment_machine_index");
  }

  if (live != nullptr)
  {
    deployment.containers.erase(live);
    machine.removeContainerIndexEntry(live->deploymentID, live);
    brain.containers.erase(live->uuid);
    delete live;
  }

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainNeuronStateUploadHealthyContainerClearsWaiters(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'040;

  Machine machine = {};
  machine.uuid = uint128_t(0x5401);
  machine.state = MachineState::healthy;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'040, 1);
  deployment.state = DeploymentState::deploying;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  ContainerView *container = new ContainerView();
  container->uuid = uint128_t(0x5402);
  container->deploymentID = deployment.plan.config.deploymentID();
  container->applicationID = deployment.plan.config.applicationID;
  container->machine = &machine;
  container->lifetime = ApplicationLifetime::base;
  container->state = ContainerState::scheduled;
  container->fragment = 11;
  container->createdAtMs = 123'458;
  container->shardGroup = 0;

  deployment.containers.insert(container);
  deployment.waitingOnContainers.insert_or_assign(container, ContainerState::healthy);
  brain.containers.insert_or_assign(container->uuid, container);
  machine.upsertContainerIndexEntry(container->deploymentID, container);

  ContainerView healthySeed = *container;
  healthySeed.state = ContainerState::healthy;
  ContainerPlan healthyPlan = healthySeed.generatePlan(deployment.plan);

  String uploadBuffer = {};
  uint32_t headerOffset = Message::appendHeader(uploadBuffer, NeuronTopic::stateUpload);
  local_container_subnet6 fragment = {};
  fragment.dpfx = 1;
  fragment.mpfx[0] = 0x00;
  fragment.mpfx[1] = 0x12;
  fragment.mpfx[2] = 0x35;
  Message::appendAlignedBuffer<Alignment::one>(uploadBuffer, reinterpret_cast<const uint8_t *>(&fragment), sizeof(fragment));
  String serializedHealthyPlan = {};
  BitseryEngine::serialize(serializedHealthyPlan, healthyPlan);
  Message::appendValue(uploadBuffer, serializedHealthyPlan);
  Message::finish(uploadBuffer, headerOffset);

  Message *message = reinterpret_cast<Message *>(uploadBuffer.data());
  brain.neuronHandler(&machine.neuron, message);
  brain.neuronHandler(&machine.neuron, message);

  suite.expect(container->state == ContainerState::healthy, "brain_neuron_state_upload_healthy_marks_container_healthy");
  suite.expect(deployment.nHealthyBase == 1, "brain_neuron_state_upload_healthy_counts_container_once");
  suite.expect(deployment.waitingOnContainers.size() == 0, "brain_neuron_state_upload_healthy_clears_waiters");

  deployment.containers.erase(container);
  machine.removeContainerIndexEntry(container->deploymentID, container);
  brain.containers.erase(container->uuid);
  delete container;

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testDeployingContainerFailureFailsDeployment(TestSuite& suite)
{
  ScopedRing scopedRing = {};
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'049;
  Machine machine = {};
  machine.uuid = uint128_t(0x5490);
  machine.state = MachineState::healthy;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'049, 1);
  deployment.plan.canaryCount = 0;
  deployment.plan.stateless.nBase = 1;
  deployment.state = DeploymentState::deploying;
  deployment.nTargetBase = 1;
  deployment.nDeployedBase = 1;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  ContainerView *container = new ContainerView();
  container->uuid = uint128_t(0x5491);
  container->deploymentID = deployment.plan.config.deploymentID();
  container->applicationID = deployment.plan.config.applicationID;
  container->machine = &machine;
  container->lifetime = ApplicationLifetime::base;
  container->state = ContainerState::scheduled;
  deployment.containers.insert(container);
  deployment.countPerMachine[&machine] = 1;
  deployment.countPerRack[&rack] = 1;
  deployment.waitingOnContainers.insert_or_assign(container, ContainerState::healthy);
  brain.containers.insert_or_assign(container->uuid, container);
  machine.upsertContainerIndexEntry(container->deploymentID, container);

  deployment.containerFailed(container, int64_t(1'700'000'000'013), 0, "image rejected"_ctv, false);

  suite.expect(deployment.state == DeploymentState::failed, "deploying_container_failure_marks_deployment_failed");
  suite.expect(deployment.waitingOnContainers.empty(), "deploying_container_failure_clears_waiters");
  suite.expect(brain.containers.contains(uint128_t(0x5491)) == false, "deploying_container_failure_removes_container");
  suite.expect(brain.failedDeployments.contains(deployment.plan.config.deploymentID()), "deploying_container_failure_records_failed_deployment");

  brain.failedDeployments.erase(deployment.plan.config.deploymentID());
  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainNeuronStateUploadRestoresOnlyActiveMeshServices(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'043;

  Machine machine = {};
  machine.uuid = uint128_t(0x5404);
  machine.state = MachineState::healthy;
  machine.fragment = 0x1236;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'043, 1);
  deployment.state = DeploymentState::deploying;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  constexpr uint64_t scheduledService = 0x620430000001ULL;
  constexpr uint64_t healthyService = 0x620430000002ULL;

  ContainerView seed = {};
  seed.uuid = uint128_t(0x5405);
  seed.deploymentID = deployment.plan.config.deploymentID();
  seed.applicationID = deployment.plan.config.applicationID;
  seed.machine = &machine;
  seed.lifetime = ApplicationLifetime::base;
  seed.state = ContainerState::scheduled;
  seed.fragment = 12;
  seed.createdAtMs = 123'459;
  seed.shardGroup = 0;
  seed.advertisements.insert_or_assign(
      scheduledService,
      Advertisement(scheduledService, ContainerState::scheduled, ContainerState::destroying, 19'101));
  seed.advertisements.insert_or_assign(
      healthyService,
      Advertisement(healthyService, ContainerState::healthy, ContainerState::destroying, 19'102));

  auto uploadPlan = [&](ContainerPlan& plan) -> void {
    String uploadBuffer = {};
    uint32_t headerOffset = Message::appendHeader(uploadBuffer, NeuronTopic::stateUpload);
    local_container_subnet6 fragment = {};
    fragment.dpfx = 1;
    fragment.mpfx[0] = 0x00;
    fragment.mpfx[1] = 0x12;
    fragment.mpfx[2] = 0x36;
    Message::appendAlignedBuffer<Alignment::one>(uploadBuffer, reinterpret_cast<const uint8_t *>(&fragment), sizeof(fragment));
    String serializedPlan = {};
    BitseryEngine::serialize(serializedPlan, plan);
    Message::appendValue(uploadBuffer, serializedPlan);
    Message::finish(uploadBuffer, headerOffset);

    Message *message = reinterpret_cast<Message *>(uploadBuffer.data());
    brain.neuronHandler(&machine.neuron, message);
  };

  ContainerPlan scheduledPlan = seed.generatePlan(deployment.plan);
  scheduledPlan.state = ContainerState::scheduled;
  uploadPlan(scheduledPlan);

  auto liveIt = brain.containers.find(scheduledPlan.uuid);
  ContainerView *live = (liveIt != brain.containers.end()) ? liveIt->second : nullptr;
  suite.expect(live != nullptr, "brain_neuron_state_upload_active_services_tracks_container");
  suite.expect(
      live != nullptr && brain.mesh->isAdvertising(scheduledService, live),
      "brain_neuron_state_upload_restores_scheduled_advertisement");
  suite.expect(
      live != nullptr && brain.mesh->isAdvertising(healthyService, live) == false,
      "brain_neuron_state_upload_does_not_restore_healthy_advertisement_while_scheduled");

  ContainerPlan healthyPlan = seed.generatePlan(deployment.plan);
  healthyPlan.state = ContainerState::healthy;
  uploadPlan(healthyPlan);

  liveIt = brain.containers.find(healthyPlan.uuid);
  live = (liveIt != brain.containers.end()) ? liveIt->second : nullptr;
  suite.expect(
      live != nullptr && brain.mesh->isAdvertising(scheduledService, live),
      "brain_neuron_state_upload_keeps_scheduled_advertisement_when_healthy");
  suite.expect(
      live != nullptr && brain.mesh->isAdvertising(healthyService, live),
      "brain_neuron_state_upload_restores_healthy_advertisement_when_healthy");

  if (live != nullptr)
  {
    deployment.containers.erase(live);
    machine.removeContainerIndexEntry(live->deploymentID, live);
    brain.containers.erase(live->uuid);
    delete live;
  }

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainNeuronStateUploadRuntimeReadyFalseClearsStatefulTopologyBarrier(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'046;

  Machine machine = {};
  machine.uuid = uint128_t(0x5409);
  machine.state = MachineState::healthy;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  seedStatefulDeployRequestPlan(deployment.plan, 62'046);
  deployment.nShardGroups = 1;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  ContainerView *container = new ContainerView();
  container->uuid = uint128_t(0x5410);
  container->deploymentID = deployment.plan.config.deploymentID();
  container->applicationID = deployment.plan.config.applicationID;
  container->machine = &machine;
  container->lifetime = ApplicationLifetime::base;
  container->state = ContainerState::healthy;
  container->runtimeReady = true;
  container->fragment = 12;
  container->createdAtMs = 123'459;
  container->isStateful = true;
  container->shardGroup = 0;
  container->explicitStatefulMeshRoles = StatefulMeshRoles::forShardGroup(deployment.plan.stateful, deployment.plan.config.applicationID, 0);
  container->explicitStatefulTopology.shardGroup = 0;
  container->explicitStatefulTopology.topologyEpoch = 1;
  container->explicitStatefulTopology.workerCount = 1;
  container->explicitStatefulTopology.servingMode = StatefulTopologyServingMode::serve;
  container->explicitStatefulTopology.sourceEpoch = 1;
  container->explicitStatefulTopology.targetEpoch = 2;
  container->applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverSourceEpochKey(), 1);
  container->applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverTargetEpochKey(), 2);
  container->applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverReadyKey(), 1);

  deployment.containers.insert(container);
  deployment.containersByShardGroup.insert(0, container);
  brain.containers.insert_or_assign(container->uuid, container);
  machine.upsertContainerIndexEntry(container->deploymentID, container);

  ContainerView uploadedSeed = *container;
  uploadedSeed.runtimeReady = false;
  ContainerPlan uploadedPlan = uploadedSeed.generatePlan(deployment.plan);

  String uploadBuffer = {};
  uint32_t headerOffset = Message::appendHeader(uploadBuffer, NeuronTopic::stateUpload);
  local_container_subnet6 fragment = {};
  fragment.dpfx = 1;
  fragment.mpfx[0] = 0x00;
  fragment.mpfx[1] = 0x12;
  fragment.mpfx[2] = 0x36;
  Message::appendAlignedBuffer<Alignment::one>(uploadBuffer, reinterpret_cast<const uint8_t *>(&fragment), sizeof(fragment));
  String serializedPlan = {};
  BitseryEngine::serialize(serializedPlan, uploadedPlan);
  Message::appendValue(uploadBuffer, serializedPlan);
  Message::finish(uploadBuffer, headerOffset);

  Message *message = reinterpret_cast<Message *>(uploadBuffer.data());
  brain.neuronHandler(&machine.neuron, message);

  suite.expect(machine.runtimeReady == true, "brain_neuron_state_upload_runtime_not_ready_marks_machine_runtime_ready");
  suite.expect(container->runtimeReady == false, "brain_neuron_state_upload_runtime_not_ready_updates_runtime_state");
  suite.expect(container->statefulTopologyCutoverReady == false, "brain_neuron_state_upload_runtime_not_ready_clears_cutover_ready");
  suite.expect(container->statefulTopologyCutoverSourceEpoch == 0 && container->statefulTopologyCutoverTargetEpoch == 0, "brain_neuron_state_upload_runtime_not_ready_clears_cutover_epochs");

  deployment.containers.erase(container);
  while (deployment.containersByShardGroup.eraseEntry(0, container))
  {
  }
  machine.removeContainerIndexEntry(container->deploymentID, container);
  brain.containers.erase(container->uuid);
  delete container;

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainNeuronStateUploadRequiresMatchingAssignedFragmentForMachineRuntimeReady(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'047;

  Machine machine = {};
  machine.uuid = uint128_t(0x5411);
  machine.state = MachineState::hardRebooting;
  machine.fragment = 0x1236;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 41;
  machine.neuron.connected = true;
  machine.hardware.inventoryComplete = true;
  machine.hardware.cpu.logicalCores = 2;
  machine.hardware.memory.totalMB = 4096;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  auto sendStateUpload = [&](uint32_t reportedFragment) -> void {
    String uploadBuffer = {};
    uint32_t headerOffset = Message::appendHeader(uploadBuffer, NeuronTopic::stateUpload);
    local_container_subnet6 fragment = {};
    fragment.dpfx = uint8_t((reportedFragment > 0) ? 1 : 0);
    fragment.mpfx[0] = uint8_t((reportedFragment >> 16) & 0xffu);
    fragment.mpfx[1] = uint8_t((reportedFragment >> 8) & 0xffu);
    fragment.mpfx[2] = uint8_t(reportedFragment & 0xffu);
    Message::appendAlignedBuffer<Alignment::one>(uploadBuffer, reinterpret_cast<const uint8_t *>(&fragment), sizeof(fragment));
    Message::finish(uploadBuffer, headerOffset);

    Message *message = reinterpret_cast<Message *>(uploadBuffer.data());
    brain.neuronHandler(&machine.neuron, message);
  };

  sendStateUpload(0);
  suite.expect(machine.runtimeReady == false, "brain_neuron_state_upload_zero_fragment_is_not_runtime_ready");
  suite.expect(machine.state == MachineState::hardRebooting, "brain_neuron_state_upload_zero_fragment_keeps_reboot_wait");
  suite.expect(machine.fragment == 0x1236, "brain_neuron_state_upload_zero_fragment_preserves_assigned_fragment");
  suite.expect(machine.reportedFragment == 0, "brain_neuron_state_upload_zero_fragment_tracks_reported_fragment");

  sendStateUpload(0x654321);
  suite.expect(machine.runtimeReady == false, "brain_neuron_state_upload_mismatched_fragment_is_not_runtime_ready");
  suite.expect(machine.state == MachineState::hardRebooting, "brain_neuron_state_upload_mismatched_fragment_keeps_reboot_wait");
  suite.expect(machine.fragment == 0x1236, "brain_neuron_state_upload_mismatched_fragment_preserves_assigned_fragment");
  suite.expect(machine.reportedFragment == 0x654321, "brain_neuron_state_upload_mismatched_fragment_tracks_reported_fragment");

  sendStateUpload(0x1236);
  suite.expect(machine.runtimeReady == true, "brain_neuron_state_upload_matching_fragment_marks_machine_runtime_ready");
  suite.expect(machine.state == MachineState::healthy, "brain_neuron_state_upload_matching_fragment_recovers_rebooted_machine");
  suite.expect(machine.reportedFragment == 0x1236, "brain_neuron_state_upload_matching_fragment_tracks_reported_fragment");

  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainNeuronControlHandshakeWatchdogClosesStalledRebootRecovery(TestSuite& suite)
{
  ScopedFreshRing scopedRing = {};

  TestBrain brain = {};
  brain.weAreMaster = true;
  brain.ignited = true;
  brain.brainConfig.datacenterFragment = 1;

  Machine machine = {};
  machine.uuid = uint128_t(0x54021);
  machine.state = MachineState::hardRebooting;
  machine.fragment = 0x1236;
  machine.runtimeReady = false;
  machine.neuron.machine = &machine;
  machine.neuron.connected = true;
  machine.neuron.hadSuccessfulConnection = true;
  machine.neuron.reconnectAfterClose = true;
  machine.neuron.fd = 19;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 19;

  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  brain.refreshNeuronControlHandshakeWatchdogForTest(&machine.neuron, "unit-stalled");
  TimeoutPacket *watchdog = brain.neuronControlHandshakeWatchdogForTest(&machine.neuron);
  suite.expect(watchdog != nullptr, "brain_neuron_handshake_watchdog_arms_for_reboot_recovery");

  brain.dispatchTimeout(watchdog);

  suite.expect(brain.neuronControlHandshakeWatchdogForTest(&machine.neuron) == nullptr, "brain_neuron_handshake_watchdog_consumes_timeout");
  suite.expect(machine.neuronConnectFailStreak == 1, "brain_neuron_handshake_watchdog_counts_stalled_control_stream");
  suite.expect(Ring::socketIsClosing(&machine.neuron), "brain_neuron_handshake_watchdog_closes_stalled_control_stream");

  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
}

static void testBrainPeerHandshakeWatchdogClosesStalledRegistration(TestSuite& suite)
{
  ScopedFreshRing scopedRing = {};

  TestBrain brain = {};
  BrainView peer = {};
  peer.private4 = 0x0A0000A1;
  peer.connected = true;
  peer.reconnectAfterClose = true;
  peer.weConnectToIt = true;
  peer.isFixedFile = true;
  peer.fd = 37;
  peer.fslot = 37;
  peer.registrationFresh = false;

  brain.brains.insert(&peer);
  brain.refreshBrainPeerHandshakeWatchdogForTest(&peer, "unit-stalled-registration");
  TimeoutPacket *watchdog = brain.brainPeerHandshakeWatchdogForTest(&peer);
  suite.expect(watchdog != nullptr, "brain_peer_handshake_watchdog_arms_for_stale_peer_registration");

  if (watchdog != nullptr)
  {
    brain.dispatchTimeout(watchdog);
  }

  suite.expect(brain.brainPeerHandshakeWatchdogForTest(&peer) == nullptr, "brain_peer_handshake_watchdog_consumes_timeout");
  suite.expect(Ring::socketIsClosing(&peer), "brain_peer_handshake_watchdog_closes_stalled_peer_registration");

  brain.brains.erase(&peer);
}

static void testBrainPeerHandshakeWatchdogCancelsAfterFreshRegistration(TestSuite& suite)
{
  ScopedFreshRing scopedRing = {};

  TestBrain brain = {};
  BrainView peer = {};
  peer.private4 = 0x0A0000A2;
  peer.connected = true;
  peer.reconnectAfterClose = true;
  peer.weConnectToIt = true;
  peer.isFixedFile = true;
  peer.fslot = 38;
  peer.registrationFresh = false;

  brain.brains.insert(&peer);
  brain.refreshBrainPeerHandshakeWatchdogForTest(&peer, "unit-await-registration");
  TimeoutPacket *watchdog = brain.brainPeerHandshakeWatchdogForTest(&peer);
  suite.expect(watchdog != nullptr, "brain_peer_handshake_watchdog_arms_until_registration");

  peer.registrationFresh = true;
  brain.refreshBrainPeerHandshakeWatchdogForTest(&peer, "unit-registration");
  suite.expect(brain.brainPeerHandshakeWatchdogForTest(&peer) == nullptr, "brain_peer_handshake_watchdog_cancels_after_registration");

  brain.brains.erase(&peer);
}

static void testBrainNeuronControlHandshakeWatchdogCancelsAfterRuntimeReadyUpload(TestSuite& suite)
{
  ScopedFreshRing scopedRing = {};

  TestBrain brain = {};
  brain.weAreMaster = true;
  brain.ignited = true;
  brain.brainConfig.datacenterFragment = 1;

  Machine machine = {};
  machine.uuid = uint128_t(0x54022);
  machine.state = MachineState::hardRebooting;
  machine.fragment = 0x1236;
  machine.runtimeReady = false;
  machine.hardware.inventoryComplete = true;
  machine.hardware.cpu.logicalCores = 2;
  machine.hardware.memory.totalMB = 4096;
  machine.neuron.machine = &machine;
  machine.neuron.connected = true;
  machine.neuron.hadSuccessfulConnection = true;
  machine.neuron.fd = 20;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 20;
  machine.neuron.ProdigyTransportTLSStream::reset();

  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  brain.refreshNeuronControlHandshakeWatchdogForTest(&machine.neuron, "unit-state-upload");
  suite.expect(brain.neuronControlHandshakeWatchdogForTest(&machine.neuron) != nullptr, "brain_neuron_handshake_watchdog_tracks_runtime_refresh");

  String uploadBuffer = {};
  uint32_t headerOffset = Message::appendHeader(uploadBuffer, NeuronTopic::stateUpload);
  local_container_subnet6 fragment = {};
  fragment.dpfx = 1;
  fragment.mpfx[0] = 0x00;
  fragment.mpfx[1] = 0x12;
  fragment.mpfx[2] = 0x36;
  Message::appendAlignedBuffer<Alignment::one>(uploadBuffer, reinterpret_cast<const uint8_t *>(&fragment), sizeof(fragment));
  Message::finish(uploadBuffer, headerOffset);

  Message *message = reinterpret_cast<Message *>(uploadBuffer.data());
  brain.neuronHandler(&machine.neuron, message);

  suite.expect(machine.runtimeReady == true, "brain_neuron_handshake_watchdog_state_upload_marks_runtime_ready");
  suite.expect(machine.state == MachineState::healthy, "brain_neuron_handshake_watchdog_state_upload_promotes_healthy");
  suite.expect(brain.neuronControlHandshakeWatchdogForTest(&machine.neuron) == nullptr, "brain_neuron_handshake_watchdog_cancels_after_runtime_ready");

  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
}

static void testBrainNeuronStateUploadHealthyAdvertiserRefreshesPeerPairingsOnPortChange(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'045;

  Machine machine = {};
  machine.uuid = uint128_t(0x5407);
  machine.state = MachineState::healthy;
  machine.fragment = 0x1237;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'045, 1);
  deployment.state = DeploymentState::running;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  constexpr uint64_t service = 0x620450000001ULL;
  constexpr uint16_t initialPort = 19'111;
  constexpr uint16_t refreshedPort = 19'404;

  ContainerView *advertiser = new ContainerView();
  advertiser->uuid = uint128_t(0x5408);
  advertiser->deploymentID = deployment.plan.config.deploymentID();
  advertiser->applicationID = deployment.plan.config.applicationID;
  advertiser->machine = &machine;
  advertiser->lifetime = ApplicationLifetime::base;
  advertiser->state = ContainerState::healthy;
  advertiser->runtimeReady = true;
  advertiser->fragment = 13;
  advertiser->createdAtMs = 123'460;
  advertiser->remainingSubscriberCapacity = 64;
  advertiser->advertisements.insert_or_assign(
      service,
      Advertisement(service, ContainerState::scheduled, ContainerState::destroying, initialPort));
  advertiser->setMeshAddress(container_network_subnet6, brain.brainConfig.datacenterFragment, machine.fragment, advertiser->fragment);

  PairingTrackingContainerView subscriber = {};
  subscriber.applicationID = uint16_t(deployment.plan.config.applicationID + 1);
  subscriber.state = ContainerState::healthy;
  subscriber.runtimeReady = true;
  subscriber.fragment = 14;
  subscriber.remainingSubscriberCapacity = 64;
  subscriber.meshAddress = uint128_t(0x62045);
  subscriber.subscriptions.insert_or_assign(
      service,
      Subscription(service, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));

  deployment.containers.insert(advertiser);
  brain.containers.insert_or_assign(advertiser->uuid, advertiser);
  machine.upsertContainerIndexEntry(advertiser->deploymentID, advertiser);

  brain.mesh->advertise(service, advertiser, initialPort, false);
  brain.mesh->subscribe(service, &subscriber, SubscriptionNature::all, false);

  suite.expect(subscriber.subscribedTo.hasEntryFor(service, advertiser), "brain_neuron_state_upload_refresh_fixture_pairs_subscriber");

  ContainerView updatedSeed = *advertiser;
  updatedSeed.runtimeReady = true;
  updatedSeed.advertisements.insert_or_assign(
      service,
      Advertisement(service, ContainerState::scheduled, ContainerState::destroying, refreshedPort));
  ContainerPlan updatedPlan = updatedSeed.generatePlan(deployment.plan);
  updatedPlan.state = ContainerState::healthy;

  String uploadBuffer = {};
  uint32_t headerOffset = Message::appendHeader(uploadBuffer, NeuronTopic::stateUpload);
  local_container_subnet6 fragment = {};
  fragment.dpfx = 1;
  fragment.mpfx[0] = 0x00;
  fragment.mpfx[1] = 0x12;
  fragment.mpfx[2] = 0x37;
  Message::appendAlignedBuffer<Alignment::one>(uploadBuffer, reinterpret_cast<const uint8_t *>(&fragment), sizeof(fragment));
  String serializedHealthyPlan = {};
  BitseryEngine::serialize(serializedHealthyPlan, updatedPlan);
  Message::appendValue(uploadBuffer, serializedHealthyPlan);
  Message::finish(uploadBuffer, headerOffset);

  Message *message = reinterpret_cast<Message *>(uploadBuffer.data());
  brain.neuronHandler(&machine.neuron, message);

  suite.expect(
      subscriber.subscriptionActivateCalls == 1,
      "brain_neuron_state_upload_refresh_replays_subscription_pairing");
  suite.expect(
      subscriber.lastSubscriptionPort == refreshedPort,
      "brain_neuron_state_upload_refresh_uses_updated_port");
  suite.expect(
      subscriber.lastSubscriptionService == service,
      "brain_neuron_state_upload_refresh_preserves_service");
  suite.expect(
      subscriber.subscriptionDeactivateCalls == 0,
      "brain_neuron_state_upload_refresh_does_not_spuriously_deactivate");

  deployment.containers.erase(advertiser);
  machine.removeContainerIndexEntry(advertiser->deploymentID, advertiser);
  brain.containers.erase(advertiser->uuid);
  delete advertiser;

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainNeuronHandlerHealthyReplacementPointerClearsEquivalentWaiter(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'041;

  Machine machine = {};
  machine.uuid = uint128_t(0x5403);
  machine.state = MachineState::healthy;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'041, 1);
  deployment.state = DeploymentState::deploying;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  ContainerView *waiting = new ContainerView();
  waiting->uuid = uint128_t(0x5404);
  waiting->deploymentID = deployment.plan.config.deploymentID();
  waiting->applicationID = deployment.plan.config.applicationID;
  waiting->machine = &machine;
  waiting->lifetime = ApplicationLifetime::base;
  waiting->state = ContainerState::scheduled;
  deployment.waitingOnContainers.insert_or_assign(waiting, ContainerState::healthy);

  ContainerView *live = new ContainerView();
  live->uuid = waiting->uuid;
  live->deploymentID = deployment.plan.config.deploymentID();
  live->applicationID = deployment.plan.config.applicationID;
  live->machine = &machine;
  live->lifetime = ApplicationLifetime::base;
  live->state = ContainerState::scheduled;
  deployment.containers.insert(live);
  brain.containers.insert_or_assign(live->uuid, live);
  machine.upsertContainerIndexEntry(live->deploymentID, live);

  String buffer = {};
  Message *message = buildNeuronMessage(buffer, NeuronTopic::containerHealthy, live->uuid);
  brain.neuronHandler(&machine.neuron, message);
  brain.neuronHandler(&machine.neuron, message);

  suite.expect(live->state == ContainerState::healthy, "brain_neuron_container_healthy_replacement_pointer_marks_live_container_healthy");
  suite.expect(deployment.nHealthyBase == 1, "brain_neuron_container_healthy_replacement_pointer_counts_container_once");
  suite.expect(deployment.waitingOnContainers.size() == 0, "brain_neuron_container_healthy_replacement_pointer_clears_equivalent_waiter");

  deployment.containers.erase(live);
  machine.removeContainerIndexEntry(live->deploymentID, live);
  brain.containers.erase(live->uuid);
  delete live;
  delete waiting;

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainNeuronStateUploadHealthyReplacementPointerClearsEquivalentWaiter(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'042;

  Machine machine = {};
  machine.uuid = uint128_t(0x5405);
  machine.state = MachineState::healthy;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'042, 1);
  deployment.state = DeploymentState::deploying;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  ContainerView *waiting = new ContainerView();
  waiting->uuid = uint128_t(0x5406);
  waiting->deploymentID = deployment.plan.config.deploymentID();
  waiting->applicationID = deployment.plan.config.applicationID;
  waiting->machine = &machine;
  waiting->lifetime = ApplicationLifetime::base;
  waiting->state = ContainerState::scheduled;
  waiting->fragment = 12;
  waiting->createdAtMs = 123'459;
  waiting->shardGroup = 0;
  deployment.waitingOnContainers.insert_or_assign(waiting, ContainerState::healthy);

  ContainerView healthySeed = {};
  healthySeed.uuid = waiting->uuid;
  healthySeed.deploymentID = deployment.plan.config.deploymentID();
  healthySeed.applicationID = deployment.plan.config.applicationID;
  healthySeed.machine = &machine;
  healthySeed.lifetime = ApplicationLifetime::base;
  healthySeed.state = ContainerState::healthy;
  healthySeed.fragment = 12;
  healthySeed.createdAtMs = 123'459;
  healthySeed.shardGroup = 0;
  ContainerPlan healthyPlan = healthySeed.generatePlan(deployment.plan);

  String uploadBuffer = {};
  uint32_t headerOffset = Message::appendHeader(uploadBuffer, NeuronTopic::stateUpload);
  local_container_subnet6 fragment = {};
  fragment.dpfx = 1;
  fragment.mpfx[0] = 0x00;
  fragment.mpfx[1] = 0x12;
  fragment.mpfx[2] = 0x36;
  Message::appendAlignedBuffer<Alignment::one>(uploadBuffer, reinterpret_cast<const uint8_t *>(&fragment), sizeof(fragment));
  String serializedHealthyPlan = {};
  BitseryEngine::serialize(serializedHealthyPlan, healthyPlan);
  Message::appendValue(uploadBuffer, serializedHealthyPlan);
  Message::finish(uploadBuffer, headerOffset);

  Message *message = reinterpret_cast<Message *>(uploadBuffer.data());
  brain.neuronHandler(&machine.neuron, message);
  brain.neuronHandler(&machine.neuron, message);

  auto liveIt = brain.containers.find(healthyPlan.uuid);
  ContainerView *live = (liveIt != brain.containers.end()) ? liveIt->second : nullptr;
  suite.expect(live != nullptr, "brain_neuron_state_upload_healthy_replacement_pointer_tracks_live_container");
  suite.expect(live != nullptr && live->state == ContainerState::healthy, "brain_neuron_state_upload_healthy_replacement_pointer_marks_live_container_healthy");
  suite.expect(deployment.nHealthyBase == 1, "brain_neuron_state_upload_healthy_replacement_pointer_counts_container_once");
  suite.expect(deployment.waitingOnContainers.size() == 0, "brain_neuron_state_upload_healthy_replacement_pointer_clears_equivalent_waiter");
  suite.expect(deployment.containers.size() == 1, "brain_neuron_state_upload_healthy_replacement_pointer_keeps_single_live_container");

  if (live != nullptr)
  {
    deployment.containers.erase(live);
    machine.removeContainerIndexEntry(live->deploymentID, live);
    brain.containers.erase(live->uuid);
    delete live;
  }

  delete waiting;

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testMachineHealthyClaimWakePreservesTicketOutstandingCount(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  Rack rack = {};
  rack.uuid = 62'040;

  Machine machine = {};
  machine.uuid = uint128_t(0x62040001);
  machine.private4 = 0x0a000040;
  machine.state = MachineState::deploying;
  machine.runtimeReady = true;
  machine.rack = &rack;
  machine.rackUUID = rack.uuid;
  machine.lifetime = MachineLifetime::owned;
  rack.machines.insert(&machine);
  brain.racks.insert_or_assign(rack.uuid, &rack);
  brain.machines.insert(&machine);

  MachineTicket ticket = {};
  CoroutineStack coro = {};
  ticket.coro = &coro;
  ticket.nMore = 3;

  Machine::Claim claim = {};
  claim.ticket = &ticket;
  claim.nFit = 1;
  claim.shardGroups.push_back(0);
  machine.claims.push_back(std::move(claim));

  brain.handleMachineStateChange(&machine, MachineState::healthy);

  suite.expect(ticket.nNow == 1, "machine_healthy_claim_sets_ticket_nNow");
  suite.expect(ticket.machineNow == &machine, "machine_healthy_claim_sets_ticket_machineNow");
  suite.expect(ticket.nMore == 3, "machine_healthy_claim_preserves_ticket_outstanding_count");
  suite.expect(machine.claims.empty(), "machine_healthy_claim_drains_claim_from_machine");

  brain.machines.erase(&machine);
  brain.racks.erase(rack.uuid);
}

static void testMachineHealthyDefersClaimWakeUntilRuntimeReady(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  Rack rack = {};
  rack.uuid = 62'048;

  Machine machine = {};
  machine.uuid = uint128_t(0x62048001);
  machine.private4 = 0x0a000048;
  machine.state = MachineState::deploying;
  machine.fragment = 0x1234;
  machine.rack = &rack;
  machine.rackUUID = rack.uuid;
  machine.lifetime = MachineLifetime::owned;
  machine.neuron.machine = &machine;
  rack.machines.insert(&machine);
  brain.racks.insert_or_assign(rack.uuid, &rack);
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  MachineTicket ticket = {};
  CoroutineStack coro = {};
  ticket.coro = &coro;
  ticket.nMore = 2;

  Machine::Claim claim = {};
  claim.ticket = &ticket;
  claim.nFit = 1;
  claim.shardGroups.push_back(0);
  machine.claims.push_back(std::move(claim));

  brain.handleMachineStateChange(&machine, MachineState::healthy);

  suite.expect(ticket.nNow == 0, "machine_healthy_runtime_not_ready_keeps_ticket_nNow_zero");
  suite.expect(ticket.machineNow == nullptr, "machine_healthy_runtime_not_ready_keeps_ticket_machineNow_null");
  suite.expect(ticket.nMore == 2, "machine_healthy_runtime_not_ready_preserves_ticket_outstanding_count");
  suite.expect(machine.claims.size() == 1, "machine_healthy_runtime_not_ready_preserves_machine_claim");

  String uploadBuffer = {};
  uint32_t headerOffset = Message::appendHeader(uploadBuffer, NeuronTopic::stateUpload);
  local_container_subnet6 fragment = {};
  fragment.dpfx = 1;
  fragment.mpfx[0] = 0x00;
  fragment.mpfx[1] = 0x12;
  fragment.mpfx[2] = 0x34;
  Message::appendAlignedBuffer<Alignment::one>(uploadBuffer, reinterpret_cast<const uint8_t *>(&fragment), sizeof(fragment));
  Message::finish(uploadBuffer, headerOffset);

  Message *message = reinterpret_cast<Message *>(uploadBuffer.data());
  brain.neuronHandler(&machine.neuron, message);

  suite.expect(machine.runtimeReady == true, "machine_healthy_runtime_ready_state_upload_marks_machine_runtime_ready");
  suite.expect(ticket.nNow == 1, "machine_healthy_runtime_ready_claim_sets_ticket_nNow");
  suite.expect(ticket.machineNow == &machine, "machine_healthy_runtime_ready_claim_sets_ticket_machineNow");
  suite.expect(ticket.nMore == 2, "machine_healthy_runtime_ready_claim_preserves_ticket_outstanding_count");
  suite.expect(machine.claims.empty(), "machine_healthy_runtime_ready_drains_machine_claim");

  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  brain.racks.erase(rack.uuid);
}

static void testMachineHealthySkipsScheduledStatelessDonorMoveUntilQuiescent(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  Rack rack = {};
  rack.uuid = 62'043;

  Machine donor = {};
  donor.uuid = uint128_t(0x62043001);
  donor.private4 = IPAddress("10.0.0.81", false).v4;
  donor.state = MachineState::healthy;
  donor.rack = &rack;
  donor.rackUUID = rack.uuid;
  donor.lifetime = MachineLifetime::ondemand;
  donor.nLogicalCores_available = 32;
  donor.memoryMB_available = 32'768;
  donor.storageMB_available = 32'768;

  Machine receiver = {};
  receiver.uuid = uint128_t(0x62043002);
  receiver.private4 = IPAddress("10.0.0.82", false).v4;
  receiver.state = MachineState::deploying;
  receiver.rack = &rack;
  receiver.rackUUID = rack.uuid;
  receiver.lifetime = MachineLifetime::owned;
  receiver.nLogicalCores_available = 32;
  receiver.memoryMB_available = 32'768;
  receiver.storageMB_available = 32'768;

  rack.machines.insert(&donor);
  rack.machines.insert(&receiver);
  brain.racks.insert_or_assign(rack.uuid, &rack);
  brain.machines.insert(&donor);
  brain.machines.insert(&receiver);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'043, 1);
  deployment.plan.stateless.nBase = 1;
  deployment.plan.stateless.maxPerRackRatio = 1.0f;
  deployment.plan.stateless.maxPerMachineRatio = 1.0f;
  deployment.state = DeploymentState::deploying;
  deployment.nTargetBase = 1;
  deployment.nDeployedBase = 1;
  deployment.countPerMachine.insert_or_assign(&donor, 1);
  deployment.countPerRack.insert_or_assign(&rack, 1);
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

  ContainerView *container = new ContainerView();
  container->uuid = uint128_t(0x62043003);
  container->deploymentID = deployment.plan.config.deploymentID();
  container->applicationID = deployment.plan.config.applicationID;
  container->machine = &donor;
  container->lifetime = ApplicationLifetime::base;
  container->state = ContainerState::scheduled;
  deployment.containers.insert(container);
  deployment.waitingOnContainers.insert_or_assign(container, ContainerState::healthy);
  donor.upsertContainerIndexEntry(container->deploymentID, container);

  brain.handleMachineStateChange(&receiver, MachineState::healthy);

  suite.expect(receiver.state == MachineState::healthy, "machine_healthy_scheduled_stateless_skip_marks_receiver_healthy");
  suite.expect(container->state == ContainerState::scheduled, "machine_healthy_scheduled_stateless_skip_preserves_container_state");
  suite.expect(container->machine == &donor, "machine_healthy_scheduled_stateless_skip_preserves_container_machine");
  suite.expect(deployment.toSchedule.size() == 0, "machine_healthy_scheduled_stateless_skip_does_not_queue_replacement");
  suite.expect(deployment.waitingOnContainers.size() == 1, "machine_healthy_scheduled_stateless_skip_preserves_waiter");
  suite.expect(deployment.countPerMachine.getIf(&donor) == 1, "machine_healthy_scheduled_stateless_skip_preserves_donor_count");
  suite.expect(deployment.countPerMachine.getIf(&receiver) == 0, "machine_healthy_scheduled_stateless_skip_preserves_receiver_count");
  suite.expect(receiver.containersByDeploymentID.contains(container->deploymentID) == false, "machine_healthy_scheduled_stateless_skip_keeps_receiver_index_empty");

  donor.removeContainerIndexEntry(container->deploymentID, container);
  deployment.waitingOnContainers.erase(container);
  deployment.containers.erase(container);
  delete container;

  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.machines.erase(&receiver);
  brain.machines.erase(&donor);
  brain.racks.erase(rack.uuid);
}

static void testDrainMachineSkipsScheduledLiveRedeployUntilHealthy(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'044;

  Machine donor = {};
  donor.uuid = uint128_t(0x62044001);
  donor.private4 = IPAddress("10.0.0.91", false).v4;
  donor.state = MachineState::deploying;
  donor.rack = &rack;
  donor.rackUUID = rack.uuid;
  donor.lifetime = MachineLifetime::ondemand;
  donor.nLogicalCores_available = 32;
  donor.memoryMB_available = 32'768;
  donor.storageMB_available = 32'768;

  Machine receiver = {};
  receiver.uuid = uint128_t(0x62044002);
  receiver.private4 = IPAddress("10.0.0.92", false).v4;
  receiver.state = MachineState::healthy;
  receiver.rack = &rack;
  receiver.rackUUID = rack.uuid;
  receiver.lifetime = MachineLifetime::owned;
  receiver.nLogicalCores_available = 32;
  receiver.memoryMB_available = 32'768;
  receiver.storageMB_available = 32'768;

  rack.machines.insert(&donor);
  rack.machines.insert(&receiver);
  brain.racks.insert_or_assign(rack.uuid, &rack);
  brain.machines.insert(&donor);
  brain.machines.insert(&receiver);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'044, 1);
  deployment.plan.stateless.nBase = 1;
  deployment.plan.stateless.maxPerRackRatio = 1.0f;
  deployment.plan.stateless.maxPerMachineRatio = 1.0f;
  deployment.state = DeploymentState::running;
  deployment.nTargetBase = 1;
  deployment.nDeployedBase = 1;
  deployment.countPerMachine.insert_or_assign(&donor, 1);
  deployment.countPerRack.insert_or_assign(&rack, 1);
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

  ContainerView *container = new ContainerView();
  container->uuid = uint128_t(0x62044003);
  container->deploymentID = deployment.plan.config.deploymentID();
  container->applicationID = deployment.plan.config.applicationID;
  container->machine = &donor;
  container->lifetime = ApplicationLifetime::base;
  container->state = ContainerState::scheduled;
  deployment.containers.insert(container);
  deployment.waitingOnContainers.insert_or_assign(container, ContainerState::healthy);
  donor.upsertContainerIndexEntry(container->deploymentID, container);

  deployment.drainMachine(&donor, false);

  suite.expect(container->state == ContainerState::scheduled, "drain_machine_scheduled_live_redeploy_skip_preserves_container_state");
  suite.expect(container->machine == &donor, "drain_machine_scheduled_live_redeploy_skip_preserves_container_machine");
  suite.expect(deployment.toSchedule.size() == 0, "drain_machine_scheduled_live_redeploy_skip_does_not_queue_replacement");
  suite.expect(deployment.waitingOnContainers.size() == 1, "drain_machine_scheduled_live_redeploy_skip_preserves_waiter");
  suite.expect(deployment.nDeployedBase == 1, "drain_machine_scheduled_live_redeploy_skip_preserves_deployed_count");
  suite.expect(deployment.countPerMachine.getIf(&donor) == 1, "drain_machine_scheduled_live_redeploy_skip_preserves_donor_count");
  suite.expect(deployment.countPerMachine.getIf(&receiver) == 0, "drain_machine_scheduled_live_redeploy_skip_preserves_receiver_count");
  suite.expect(donor.containersByDeploymentID.contains(container->deploymentID), "drain_machine_scheduled_live_redeploy_skip_restores_machine_bin");
  suite.expect(donor.containersByDeploymentID[container->deploymentID].contains(container), "drain_machine_scheduled_live_redeploy_skip_restores_container_pointer");

  donor.removeContainerIndexEntry(container->deploymentID, container);
  deployment.waitingOnContainers.erase(container);
  deployment.containers.erase(container);
  delete container;

  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.machines.erase(&receiver);
  brain.machines.erase(&donor);
  brain.racks.erase(rack.uuid);
  thisBrain = previousBrain;
}

static void testBrainNeuronHandlerRecordsContainerStatisticsAndReplicates(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  Rack rack = {};
  rack.uuid = 62'021;

  Machine machine = {};
  machine.uuid = uint128_t(0x5203);
  machine.state = MachineState::healthy;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'021, 1);
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

  ContainerView *container = new ContainerView();
  container->uuid = uint128_t(0x5204);
  container->deploymentID = deployment.plan.config.deploymentID();
  container->machine = &machine;
  container->lifetime = ApplicationLifetime::base;
  container->state = ContainerState::healthy;
  container->runtimeReady = true;

  deployment.containers.insert(container);
  brain.containers.insert_or_assign(container->uuid, container);
  machine.upsertContainerIndexEntry(container->deploymentID, container);

  uint64_t cpuMetricKey = ProdigyMetrics::runtimeContainerCpuUtilPctKey();
  uint64_t memoryMetricKey = ProdigyMetrics::runtimeContainerMemoryUtilPctKey();
  int64_t beforeMs = Time::now<TimeResolution::ms>();

  String buffer = {};
  Message *message = buildNeuronMessage(
      buffer,
      NeuronTopic::containerStatistics,
      deployment.plan.config.deploymentID(),
      container->uuid,
      beforeMs + 60'000,
      cpuMetricKey,
      uint64_t(55),
      memoryMetricKey,
      uint64_t(66));
  brain.neuronHandler(&machine.neuron, message);

  int64_t afterMs = Time::now<TimeResolution::ms>();

  Vector<ProdigyMetricSample> exportedMetrics = {};
  brain.metrics.exportSamples(exportedMetrics);

  bool sawCpuMetric = false;
  bool sawMemoryMetric = false;
  for (const ProdigyMetricSample& sample : exportedMetrics)
  {
    if (sample.metricKey == cpuMetricKey && sample.value == 55.0f)
    {
      sawCpuMetric = sample.ms >= beforeMs && sample.ms <= afterMs;
    }

    if (sample.metricKey == memoryMetricKey && sample.value == 66.0f)
    {
      sawMemoryMetric = sample.ms >= beforeMs && sample.ms <= afterMs;
    }
  }

  suite.expect(exportedMetrics.size() == 2, "brain_neuron_container_statistics_records_two_samples");
  suite.expect(sawCpuMetric, "brain_neuron_container_statistics_records_cpu_metric");
  suite.expect(sawMemoryMetric, "brain_neuron_container_statistics_records_memory_metric");
  suite.expect(brain.persistCalls >= 1, "brain_neuron_container_statistics_persists_runtime_state");

  deployment.containers.erase(container);
  machine.removeContainerIndexEntry(container->deploymentID, container);
  brain.containers.erase(container->uuid);
  delete container;

  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
}

static void testBrainNeuronHandlerContainerStatisticsCanTriggerStatefulTopologyCutover(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'047;

  Machine machine = {};
  machine.uuid = uint128_t(0x5210);
  machine.state = MachineState::healthy;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  ApplicationDeployment deployment = {};
  seedStatefulDeployRequestPlan(deployment.plan, 62'047);
  deployment.nShardGroups = 1;
  deployment.armStatefulWorkerTopologyUpgrade(1, 1, 2, 64, 64);
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  StatefulMeshRoles roles = StatefulMeshRoles::forShardGroup(deployment.plan.stateful, deployment.plan.config.applicationID, 0);

  ContainerView sourceA = {};
  ContainerView sourceB = {};
  ContainerView sourceC = {};
  ContainerView targetA = {};
  ContainerView targetB = {};
  ContainerView targetC = {};
  ContainerView *sources[] = {&sourceA, &sourceB, &sourceC};
  ContainerView *targets[] = {&targetA, &targetB, &targetC};

  uint128_t uuidSeed = 0x5211;
  for (ContainerView *source : sources)
  {
    configureStatefulTopologySourceContainer(*source, deployment, roles, 0, ++uuidSeed);
    source->machine = &machine;
    deployment.containers.insert(source);
    deployment.containersByShardGroup.insert(0, source);
    brain.containers.insert_or_assign(source->uuid, source);
  }

  sourceA.advertisements.emplace(roles.client, Advertisement(roles.client, ContainerState::healthy, ContainerState::destroying, 19'131));
  sourceA.advertisingOnPorts.insert(19'131);
  deployment.masterForShardGroup.insert_or_assign(0, &sourceA);

  for (ContainerView *target : targets)
  {
    configureStatefulTopologyTargetContainer(*target, deployment, roles, 0, ++uuidSeed);
    target->machine = &machine;
    deployment.containers.insert(target);
    deployment.containersByShardGroup.insert(0, target);
    brain.containers.insert_or_assign(target->uuid, target);
  }

  noteStatefulTopologyCutoverBarrier(targetA, deployment);
  noteStatefulTopologyCutoverBarrier(targetB, deployment);

  suite.expect(deployment.statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::greenBootstrap, "brain_neuron_container_statistics_cutover_starts_in_green_bootstrap");

  String buffer = {};
  Message *message = buildNeuronMessage(
      buffer,
      NeuronTopic::containerStatistics,
      deployment.plan.config.deploymentID(),
      targetC.uuid,
      Time::now<TimeResolution::ms>(),
      ProdigyMetrics::runtimeStatefulTopologyCutoverSourceEpochKey(),
      uint64_t(deployment.statefulWorkerTopologyUpgradeSourceEpoch),
      ProdigyMetrics::runtimeStatefulTopologyCutoverTargetEpochKey(),
      uint64_t(deployment.statefulWorkerTopologyUpgradeTargetEpoch),
      ProdigyMetrics::runtimeStatefulTopologyCutoverReadyKey(),
      uint64_t(1));
  brain.neuronHandler(&machine.neuron, message);

  suite.expect(deployment.statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::blueDraining, "brain_neuron_container_statistics_cutover_enters_blue_draining");
  suite.expect(targetC.statefulTopologyCutoverReady == false, "brain_neuron_container_statistics_cutover_clears_target_barrier_after_cutover");

  for (ContainerView *container : sources)
  {
    deployment.containers.erase(container);
    while (deployment.containersByShardGroup.eraseEntry(0, container))
    {
    }
    brain.containers.erase(container->uuid);
  }

  for (ContainerView *container : targets)
  {
    deployment.containers.erase(container);
    while (deployment.containersByShardGroup.eraseEntry(0, container))
    {
    }
    brain.containers.erase(container->uuid);
  }

  deployment.masterForShardGroup.erase(0);
  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainReplicatedMetricAppendCanTriggerStatefulTopologyCutover(TestSuite& suite)
{
  TestBrain brain = {};
  brain.weAreMaster = false;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  ApplicationDeployment deployment = {};
  seedStatefulDeployRequestPlan(deployment.plan, 62'048);
  deployment.nShardGroups = 1;
  deployment.armStatefulWorkerTopologyUpgrade(1, 1, 2, 64, 64);
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  StatefulMeshRoles roles = StatefulMeshRoles::forShardGroup(deployment.plan.stateful, deployment.plan.config.applicationID, 0);

  ContainerView sourceA = {};
  ContainerView sourceB = {};
  ContainerView sourceC = {};
  ContainerView targetA = {};
  ContainerView targetB = {};
  ContainerView targetC = {};
  ContainerView *sources[] = {&sourceA, &sourceB, &sourceC};
  ContainerView *targets[] = {&targetA, &targetB, &targetC};

  uint128_t uuidSeed = 0x5221;
  for (ContainerView *source : sources)
  {
    configureStatefulTopologySourceContainer(*source, deployment, roles, 0, ++uuidSeed);
    deployment.containers.insert(source);
    deployment.containersByShardGroup.insert(0, source);
    brain.containers.insert_or_assign(source->uuid, source);
  }

  sourceA.advertisements.emplace(roles.client, Advertisement(roles.client, ContainerState::healthy, ContainerState::destroying, 19'141));
  sourceA.advertisingOnPorts.insert(19'141);
  deployment.masterForShardGroup.insert_or_assign(0, &sourceA);

  for (ContainerView *target : targets)
  {
    configureStatefulTopologyTargetContainer(*target, deployment, roles, 0, ++uuidSeed);
    deployment.containers.insert(target);
    deployment.containersByShardGroup.insert(0, target);
    brain.containers.insert_or_assign(target->uuid, target);
  }

  noteStatefulTopologyCutoverBarrier(targetA, deployment);
  noteStatefulTopologyCutoverBarrier(targetB, deployment);

  BrainView follower = {};
  String messageBuffer = {};

  Message *sourceEpochMessage = buildBrainMessage(
      messageBuffer,
      BrainTopic::replicateMetricsAppend,
      deployment.plan.config.deploymentID(),
      targetC.uuid,
      Time::now<TimeResolution::ms>(),
      ProdigyMetrics::runtimeStatefulTopologyCutoverSourceEpochKey(),
      uint64_t(deployment.statefulWorkerTopologyUpgradeSourceEpoch));
  brain.brainHandler(&follower, sourceEpochMessage);
  suite.expect(deployment.statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::greenBootstrap, "brain_replicated_metric_append_cutover_waits_after_source_epoch_metric");

  Message *targetEpochMessage = buildBrainMessage(
      messageBuffer,
      BrainTopic::replicateMetricsAppend,
      deployment.plan.config.deploymentID(),
      targetC.uuid,
      Time::now<TimeResolution::ms>(),
      ProdigyMetrics::runtimeStatefulTopologyCutoverTargetEpochKey(),
      uint64_t(deployment.statefulWorkerTopologyUpgradeTargetEpoch));
  brain.brainHandler(&follower, targetEpochMessage);
  suite.expect(deployment.statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::greenBootstrap, "brain_replicated_metric_append_cutover_waits_after_target_epoch_metric");

  Message *readyMessage = buildBrainMessage(
      messageBuffer,
      BrainTopic::replicateMetricsAppend,
      deployment.plan.config.deploymentID(),
      targetC.uuid,
      Time::now<TimeResolution::ms>(),
      ProdigyMetrics::runtimeStatefulTopologyCutoverReadyKey(),
      uint64_t(1));
  brain.brainHandler(&follower, readyMessage);

  suite.expect(deployment.statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::blueDraining, "brain_replicated_metric_append_cutover_enters_blue_draining");
  suite.expect(targetC.statefulTopologyCutoverReady == false, "brain_replicated_metric_append_cutover_clears_target_barrier_after_cutover");

  for (ContainerView *container : sources)
  {
    deployment.containers.erase(container);
    while (deployment.containersByShardGroup.eraseEntry(0, container))
    {
    }
    brain.containers.erase(container->uuid);
  }

  for (ContainerView *container : targets)
  {
    deployment.containers.erase(container);
    while (deployment.containersByShardGroup.eraseEntry(0, container))
    {
    }
    brain.containers.erase(container->uuid);
  }

  deployment.masterForShardGroup.erase(0);
  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  thisBrain = previousBrain;
}

static void testBrainNeuronHandlerHandlesRestartingContainerFailure(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.brainConfig.reporter.from.assign("alerts@example.com"_ctv);
  brain.brainConfig.reporter.to.assign("ops@example.com"_ctv);

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'022;

  Machine machine = {};
  machine.uuid = uint128_t(0x5205);
  machine.state = MachineState::healthy;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'022, 1);
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  ContainerView *container = new ContainerView();
  container->uuid = uint128_t(0x5206);
  container->deploymentID = deployment.plan.config.deploymentID();
  container->machine = &machine;
  container->lifetime = ApplicationLifetime::base;
  container->state = ContainerState::healthy;

  deployment.containers.insert(container);
  deployment.countPerMachine[&machine] = 1;
  deployment.countPerRack[&rack] = 1;
  deployment.nHealthyBase = 1;
  brain.containers.insert_or_assign(container->uuid, container);
  machine.upsertContainerIndexEntry(container->deploymentID, container);

  String buffer = {};
  Message *message = buildNeuronMessage(
      buffer,
      NeuronTopic::containerFailed,
      container->uuid,
      int64_t(1'700'000'000'001),
      int(11),
      "container crash"_ctv,
      true);
  brain.neuronHandler(&machine.neuron, message);

  suite.expect(container->state == ContainerState::crashedRestarting, "brain_neuron_container_failed_restart_marks_crashed_restarting");
  suite.expect(container->runtimeReady == false, "brain_neuron_container_failed_restart_clears_runtime_ready");
  suite.expect(deployment.nHealthyBase == 0, "brain_neuron_container_failed_restart_decrements_healthy_count");
  suite.expect(container->nCrashes == 1, "brain_neuron_container_failed_restart_increments_container_crash_count");
  suite.expect(deployment.failureReports.size() == 1, "brain_neuron_container_failed_restart_records_failure_report");
  suite.expect(deployment.failureReports.size() == 1 && deployment.failureReports[0].restarted, "brain_neuron_container_failed_restart_marks_report_restarted");
  suite.expect(brain.containers.contains(container->uuid), "brain_neuron_container_failed_restart_keeps_container_indexed");

  deployment.containers.erase(container);
  machine.removeContainerIndexEntry(container->deploymentID, container);
  brain.containers.erase(container->uuid);
  delete container;

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainNeuronHandlerRestartingContainerFailurePreservesAnySubscribersWithoutDeadReplay(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rackA = {};
  rackA.uuid = 62'024;
  Rack rackB = {};
  rackB.uuid = 62'025;

  Machine machineA = {};
  machineA.uuid = uint128_t(0x5210);
  machineA.state = MachineState::healthy;
  machineA.fragment = 0x45;
  machineA.rack = &rackA;
  machineA.neuron.machine = &machineA;
  brain.machines.insert(&machineA);
  brain.machinesByUUID.insert_or_assign(machineA.uuid, &machineA);

  Machine machineB = {};
  machineB.uuid = uint128_t(0x5211);
  machineB.state = MachineState::healthy;
  machineB.fragment = 0x46;
  machineB.rack = &rackB;
  machineB.neuron.machine = &machineB;
  brain.machines.insert(&machineB);
  brain.machinesByUUID.insert_or_assign(machineB.uuid, &machineB);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'024, 1);
  deployment.state = DeploymentState::running;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  constexpr uint64_t service = 0x620240000001ULL;
  constexpr uint16_t failedPort = 19'111;
  constexpr uint16_t replacementPort = 19'404;

  ContainerView *failedAdvertiser = new ContainerView();
  failedAdvertiser->uuid = uint128_t(0x5212);
  failedAdvertiser->deploymentID = deployment.plan.config.deploymentID();
  failedAdvertiser->applicationID = deployment.plan.config.applicationID;
  failedAdvertiser->machine = &machineA;
  failedAdvertiser->lifetime = ApplicationLifetime::base;
  failedAdvertiser->state = ContainerState::healthy;
  failedAdvertiser->runtimeReady = true;
  failedAdvertiser->fragment = 13;
  failedAdvertiser->remainingSubscriberCapacity = 64;
  failedAdvertiser->advertisements.insert_or_assign(
      service,
      Advertisement(service, ContainerState::healthy, ContainerState::destroying, failedPort));
  failedAdvertiser->setMeshAddress(
      container_network_subnet6,
      brain.brainConfig.datacenterFragment,
      machineA.fragment,
      failedAdvertiser->fragment);

  ContainerView *replacementAdvertiser = new ContainerView();
  replacementAdvertiser->uuid = uint128_t(0x5213);
  replacementAdvertiser->deploymentID = deployment.plan.config.deploymentID();
  replacementAdvertiser->applicationID = deployment.plan.config.applicationID;
  replacementAdvertiser->machine = &machineB;
  replacementAdvertiser->lifetime = ApplicationLifetime::base;
  replacementAdvertiser->state = ContainerState::healthy;
  replacementAdvertiser->runtimeReady = true;
  replacementAdvertiser->fragment = 14;
  replacementAdvertiser->remainingSubscriberCapacity = 64;
  replacementAdvertiser->advertisements.insert_or_assign(
      service,
      Advertisement(service, ContainerState::healthy, ContainerState::destroying, replacementPort));
  replacementAdvertiser->setMeshAddress(
      container_network_subnet6,
      brain.brainConfig.datacenterFragment,
      machineB.fragment,
      replacementAdvertiser->fragment);

  auto makeSubscriber = [&](uint16_t applicationID, uint8_t fragment, uint128_t meshAddress) {
    PairingTrackingContainerView subscriber = {};
    subscriber.applicationID = applicationID;
    subscriber.state = ContainerState::healthy;
    subscriber.runtimeReady = true;
    subscriber.fragment = fragment;
    subscriber.remainingSubscriberCapacity = 64;
    subscriber.meshAddress = meshAddress;
    subscriber.subscriptions.insert_or_assign(
        service,
        Subscription(service, ContainerState::healthy, ContainerState::destroying, SubscriptionNature::any));
    return subscriber;
  };

  PairingTrackingContainerView subscriberA = makeSubscriber(
      uint16_t(deployment.plan.config.applicationID + 1),
      15,
      uint128_t(0x62024015));
  PairingTrackingContainerView subscriberB = makeSubscriber(
      uint16_t(deployment.plan.config.applicationID + 2),
      16,
      uint128_t(0x62024016));

  deployment.containers.insert(failedAdvertiser);
  deployment.containers.insert(replacementAdvertiser);
  deployment.countPerMachine[&machineA] = 1;
  deployment.countPerMachine[&machineB] = 1;
  deployment.countPerRack[&rackA] = 1;
  deployment.countPerRack[&rackB] = 1;
  deployment.nHealthyBase = 2;
  brain.containers.insert_or_assign(failedAdvertiser->uuid, failedAdvertiser);
  brain.containers.insert_or_assign(replacementAdvertiser->uuid, replacementAdvertiser);
  machineA.upsertContainerIndexEntry(failedAdvertiser->deploymentID, failedAdvertiser);
  machineB.upsertContainerIndexEntry(replacementAdvertiser->deploymentID, replacementAdvertiser);

  brain.mesh->advertise(service, failedAdvertiser, failedPort, false);
  brain.mesh->subscribe(service, &subscriberA, SubscriptionNature::any, false);
  brain.mesh->advertise(service, replacementAdvertiser, replacementPort, false);
  brain.mesh->subscribe(service, &subscriberB, SubscriptionNature::any, false);

  PairingTrackingContainerView *migratingSubscriber = nullptr;
  PairingTrackingContainerView *stableSubscriber = nullptr;
  if (subscriberA.subscribedTo.hasEntryFor(service, failedAdvertiser))
  {
    migratingSubscriber = &subscriberA;
    stableSubscriber = &subscriberB;
  }
  else if (subscriberB.subscribedTo.hasEntryFor(service, failedAdvertiser))
  {
    migratingSubscriber = &subscriberB;
    stableSubscriber = &subscriberA;
  }

  suite.expect(
      migratingSubscriber != nullptr,
      "brain_neuron_container_failed_restart_preserve_fixture_retains_one_failed_pairing");
  suite.expect(
      stableSubscriber != nullptr && stableSubscriber->subscribedTo.hasEntryFor(service, replacementAdvertiser),
      "brain_neuron_container_failed_restart_preserve_fixture_pairs_other_subscriber_to_replacement");

  for (PairingTrackingContainerView *subscriber : {&subscriberA, &subscriberB})
  {
    subscriber->subscriptionActivateCalls = 0;
    subscriber->subscriptionDeactivateCalls = 0;
    subscriber->lastSubscriptionAddress = 0;
    subscriber->lastSubscriptionService = 0;
    subscriber->lastSubscriptionPort = 0;
    subscriber->lastSubscriptionApplicationID = 0;
  }

  deployment.containerFailed(
      failedAdvertiser,
      int64_t(1'700'000'000'011),
      11,
      "container crash"_ctv,
      true);

  suite.expect(
      failedAdvertiser->state == ContainerState::crashedRestarting,
      "brain_neuron_container_failed_restart_preserve_marks_crashed_restarting");
  suite.expect(
      failedAdvertiser->runtimeReady == false,
      "brain_neuron_container_failed_restart_preserve_clears_runtime_ready");
  suite.expect(
      migratingSubscriber->subscriptionDeactivateCalls >= 1,
      "brain_neuron_container_failed_restart_preserve_deactivates_failed_pairing");
  suite.expect(
      migratingSubscriber->subscriptionActivateCalls == 0,
      "brain_neuron_container_failed_restart_preserve_does_not_activate_replacement");
  suite.expect(
      migratingSubscriber->lastSubscriptionAddress == failedAdvertiser->pairingAddress(),
      "brain_neuron_container_failed_restart_preserve_deactivates_failed_address");
  suite.expect(
      migratingSubscriber->lastSubscriptionPort == failedPort,
      "brain_neuron_container_failed_restart_preserve_deactivates_failed_port");
  suite.expect(
      migratingSubscriber->subscribedTo.hasEntryFor(service, failedAdvertiser),
      "brain_neuron_container_failed_restart_preserve_keeps_failed_advertiser_edge");
  suite.expect(
      migratingSubscriber->subscribedTo.hasEntryFor(service, replacementAdvertiser) == false,
      "brain_neuron_container_failed_restart_preserve_avoids_spare_advertiser");
  suite.expect(
      brain.mesh->isAdvertising(service, failedAdvertiser),
      "brain_neuron_container_failed_restart_preserve_keeps_failed_advertisement");
  suite.expect(
      stableSubscriber->subscriptionDeactivateCalls == 0,
      "brain_neuron_container_failed_restart_preserve_keeps_replacement_peer_active");
  suite.expect(
      stableSubscriber->subscriptionActivateCalls == 0,
      "brain_neuron_container_failed_restart_preserve_avoids_duplicate_replacement_activation");

  migratingSubscriber->subscriptionActivateCalls = 0;
  migratingSubscriber->subscriptionDeactivateCalls = 0;
  migratingSubscriber->lastSubscriptionAddress = 0;
  migratingSubscriber->lastSubscriptionService = 0;
  migratingSubscriber->lastSubscriptionPort = 0;
  migratingSubscriber->lastSubscriptionApplicationID = 0;

  deployment.containerIsHealthy(failedAdvertiser);
  deployment.containerIsRuntimeReady(failedAdvertiser);

  suite.expect(
      failedAdvertiser->state == ContainerState::healthy && failedAdvertiser->runtimeReady,
      "brain_neuron_container_failed_restart_preserve_recovers_same_container");
  suite.expect(
      migratingSubscriber->subscriptionActivateCalls >= 1,
      "brain_neuron_container_failed_restart_preserve_replays_same_edge");
  suite.expect(
      migratingSubscriber->lastSubscriptionAddress == failedAdvertiser->pairingAddress(),
      "brain_neuron_container_failed_restart_preserve_replays_same_address");
  suite.expect(
      migratingSubscriber->lastSubscriptionPort == failedPort,
      "brain_neuron_container_failed_restart_preserve_replays_same_port");

  deployment.containers.erase(failedAdvertiser);
  deployment.containers.erase(replacementAdvertiser);
  machineA.removeContainerIndexEntry(failedAdvertiser->deploymentID, failedAdvertiser);
  machineB.removeContainerIndexEntry(replacementAdvertiser->deploymentID, replacementAdvertiser);
  brain.containers.erase(failedAdvertiser->uuid);
  brain.containers.erase(replacementAdvertiser->uuid);
  delete failedAdvertiser;
  delete replacementAdvertiser;

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.machinesByUUID.erase(machineA.uuid);
  brain.machinesByUUID.erase(machineB.uuid);
  brain.machines.erase(&machineA);
  brain.machines.erase(&machineB);
  thisBrain = previousBrain;
}

static void testBrainNeuronHandlerRestartingStatefulMasterKeepsClientServiceSticky(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'026;

  Machine machine = {};
  machine.uuid = uint128_t(0x5220);
  machine.state = MachineState::healthy;
  machine.fragment = 0x47;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

  ApplicationDeployment deployment = {};
  seedStatefulDeployRequestPlan(deployment.plan, 62'026);
  deployment.state = DeploymentState::running;
  deployment.nShardGroups = 1;
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  StatefulMeshRoles roles = StatefulMeshRoles::forShardGroup(
      deployment.plan.stateful,
      deployment.plan.config.applicationID,
      0);
  constexpr uint16_t clientPort = 4744;

  ContainerView failedMaster = {};
  failedMaster.uuid = uint128_t(0x5221);
  failedMaster.deploymentID = deployment.plan.config.deploymentID();
  failedMaster.applicationID = deployment.plan.config.applicationID;
  failedMaster.machine = &machine;
  failedMaster.lifetime = ApplicationLifetime::base;
  failedMaster.state = ContainerState::healthy;
  failedMaster.runtimeReady = true;
  failedMaster.isStateful = true;
  failedMaster.shardGroup = 0;
  failedMaster.fragment = 20;
  failedMaster.remainingSubscriberCapacity = 64;
  failedMaster.advertisements.insert_or_assign(
      roles.client,
      Advertisement(roles.client, ContainerState::healthy, ContainerState::destroying, clientPort));
  failedMaster.advertisingOnPorts.insert(clientPort);
  failedMaster.setMeshAddress(
      container_network_subnet6,
      brain.brainConfig.datacenterFragment,
      machine.fragment,
      failedMaster.fragment);

  ContainerView standby = {};
  standby.uuid = uint128_t(0x5222);
  standby.deploymentID = deployment.plan.config.deploymentID();
  standby.applicationID = deployment.plan.config.applicationID;
  standby.machine = &machine;
  standby.lifetime = ApplicationLifetime::base;
  standby.state = ContainerState::healthy;
  standby.runtimeReady = true;
  standby.isStateful = true;
  standby.shardGroup = 0;
  standby.fragment = 21;
  standby.remainingSubscriberCapacity = 64;
  standby.setMeshAddress(
      container_network_subnet6,
      brain.brainConfig.datacenterFragment,
      machine.fragment,
      standby.fragment);

  PairingTrackingContainerView subscriber = {};
  subscriber.applicationID = uint16_t(deployment.plan.config.applicationID + 1);
  subscriber.state = ContainerState::healthy;
  subscriber.runtimeReady = true;
  subscriber.fragment = 22;
  subscriber.remainingSubscriberCapacity = 64;
  subscriber.meshAddress = uint128_t(0x62026022);
  subscriber.subscriptions.insert_or_assign(
      roles.client,
      Subscription(roles.client, ContainerState::healthy, ContainerState::destroying, SubscriptionNature::any));

  deployment.containers.insert(&failedMaster);
  deployment.containers.insert(&standby);
  deployment.containersByShardGroup.insert(0, &failedMaster);
  deployment.containersByShardGroup.insert(0, &standby);
  deployment.masterForShardGroup.insert_or_assign(0, &failedMaster);
  deployment.countPerMachine[&machine] = 2;
  deployment.countPerRack[&rack] = 2;
  deployment.nHealthyBase = 2;
  brain.containers.insert_or_assign(failedMaster.uuid, &failedMaster);
  brain.containers.insert_or_assign(standby.uuid, &standby);
  machine.upsertContainerIndexEntry(failedMaster.deploymentID, &failedMaster);
  machine.upsertContainerIndexEntry(standby.deploymentID, &standby);

  brain.mesh->advertise(roles.client, &failedMaster, clientPort, false);
  brain.mesh->subscribe(roles.client, &subscriber, SubscriptionNature::any, false);
  subscriber.subscriptionActivateCalls = 0;
  subscriber.subscriptionDeactivateCalls = 0;

  deployment.containerFailed(
      &failedMaster,
      int64_t(1'700'000'000'012),
      9,
      "stateful master restart"_ctv,
      true);

  suite.expect(
      deployment.masterForShardGroup[0] == &failedMaster,
      "brain_neuron_stateful_restart_keeps_client_master_sticky");
  suite.expect(
      standby.advertisements.find(roles.client) == standby.advertisements.end(),
      "brain_neuron_stateful_restart_does_not_assign_unopened_client_port");
  suite.expect(
      subscriber.subscriptionActivateCalls == 0,
      "brain_neuron_stateful_restart_does_not_activate_unopened_client_port");
  suite.expect(
      subscriber.subscriptionDeactivateCalls >= 1,
      "brain_neuron_stateful_restart_deactivates_failed_client_port");
  suite.expect(
      subscriber.subscribedTo.hasEntryFor(roles.client, &standby) == false,
      "brain_neuron_stateful_restart_leaves_client_unpaired_until_same_master_returns");

  machine.removeContainerIndexEntry(failedMaster.deploymentID, &failedMaster);
  machine.removeContainerIndexEntry(standby.deploymentID, &standby);
  brain.containers.erase(failedMaster.uuid);
  brain.containers.erase(standby.uuid);
  deployment.masterForShardGroup.erase(0);
  while (deployment.containersByShardGroup.eraseEntry(0, &failedMaster))
  {
  }
  while (deployment.containersByShardGroup.eraseEntry(0, &standby))
  {
  }
  deployment.containers.erase(&failedMaster);
  deployment.containers.erase(&standby);
  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainNeuronHandlerHandlesNonRestartingContainerFailureAndDrainsMachine(TestSuite& suite)
{
  TestBrain brain = {};
  TrackingBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.brainConfig.reporter.from.assign("alerts@example.com"_ctv);
  brain.brainConfig.reporter.to.assign("ops@example.com"_ctv);

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'023;

  Machine machine = {};
  machine.uuid = uint128_t(0x5207);
  machine.state = MachineState::decommissioning;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'023, 1);
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

  ContainerView *container = new ContainerView();
  container->uuid = uint128_t(0x5208);
  container->deploymentID = deployment.plan.config.deploymentID();
  container->machine = &machine;
  container->lifetime = ApplicationLifetime::base;
  container->state = ContainerState::healthy;

  deployment.containers.insert(container);
  deployment.countPerMachine[&machine] = 1;
  deployment.countPerRack[&rack] = 1;
  deployment.nHealthyBase = 1;
  brain.containers.insert_or_assign(container->uuid, container);
  machine.upsertContainerIndexEntry(container->deploymentID, container);

  String buffer = {};
  Message *message = buildNeuronMessage(
      buffer,
      NeuronTopic::containerFailed,
      container->uuid,
      int64_t(1'700'000'000'002),
      int(9),
      "fatal crash"_ctv,
      false);
  brain.neuronHandler(&machine.neuron, message);

  suite.expect(brain.containers.contains(uint128_t(0x5208)) == false, "brain_neuron_container_failed_nonrestart_removes_container_index");
  suite.expect(deployment.failureReports.size() == 1, "brain_neuron_container_failed_nonrestart_records_failure_report");
  suite.expect(machine.containersByDeploymentID.size() == 0, "brain_neuron_container_failed_nonrestart_clears_machine_bins");
  suite.expect(iaas.destroyCalls == 1, "brain_neuron_container_failed_nonrestart_drains_machine");
  suite.expect(iaas.lastDestroyedUUID == machine.uuid, "brain_neuron_container_failed_nonrestart_reports_destroy_uuid");

  brain.deploymentsByApp.erase(deployment.plan.config.applicationID);
  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainNeuronHandlerProcessesKillContainerAckAndDrainsMachine(TestSuite& suite)
{
  TestBrain brain = {};
  TrackingBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *previousBrain = thisBrain;
  thisBrain = &brain;

  Rack rack = {};
  rack.uuid = 62'024;

  Machine machine = {};
  machine.uuid = uint128_t(0x5209);
  machine.state = MachineState::decommissioning;
  machine.rack = &rack;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

  ApplicationDeployment deployment = {};
  deployment.plan = makeDeploymentPlan(62'024, 1);
  brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

  ContainerView *container = new ContainerView();
  container->uuid = uint128_t(0x5210);
  container->deploymentID = deployment.plan.config.deploymentID();
  container->machine = &machine;
  container->state = ContainerState::destroying;
  brain.containers.insert_or_assign(container->uuid, container);

  String buffer = {};
  Message *message = buildNeuronMessage(buffer, NeuronTopic::killContainer, container->uuid);
  brain.neuronHandler(&machine.neuron, message);

  suite.expect(brain.containers.contains(uint128_t(0x5210)) == false, "brain_neuron_kill_container_ack_removes_container_index");
  suite.expect(iaas.destroyCalls == 1, "brain_neuron_kill_container_ack_drains_decommissioning_machine");
  suite.expect(iaas.lastDestroyedUUID == machine.uuid, "brain_neuron_kill_container_ack_reports_destroy_uuid");

  brain.deployments.erase(deployment.plan.config.deploymentID());
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = previousBrain;
}

static void testBrainNeuronHandlerQueuesRequestedContainerBlob(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  const uint64_t deploymentID = 0x6202500000000001ull;
  String containerBlob = prodigyDiscombobulatorBlobHeaderText();
  containerBlob.append("brain-side-container-blob"_ctv);
  String storeFailure = {};
  ContainerStore::destroy(deploymentID);
  suite.expect(
      ContainerStore::store(deploymentID, containerBlob, nullptr, nullptr, nullptr, nullptr, &storeFailure),
      "brain_neuron_request_container_blob_store_fixture");

  Machine machine = {};
  machine.uuid = uint128_t(0x5211);
  machine.neuron.machine = &machine;

  String buffer = {};
  Message *message = buildNeuronMessage(buffer, NeuronTopic::requestContainerBlob, deploymentID);
  brain.neuronHandler(&machine.neuron, message);

  uint32_t blobFrames = 0;
  uint64_t observedDeploymentID = 0;
  String observedBlob = {};
  forEachMessageInBuffer(machine.neuron.wBuffer, [&](Message *frame) {
    if (NeuronTopic(frame->topic) != NeuronTopic::requestContainerBlob)
    {
      return;
    }

    uint8_t *args = frame->args;
    Message::extractArg<ArgumentNature::fixed>(args, observedDeploymentID);
    Message::extractToStringView(args, observedBlob);
    blobFrames += 1;
  });

  suite.expect(blobFrames == 1, "brain_neuron_request_container_blob_emits_single_response");
  suite.expect(observedDeploymentID == deploymentID, "brain_neuron_request_container_blob_preserves_deployment_id");
  suite.expect(observedBlob.equals(containerBlob), "brain_neuron_request_container_blob_preserves_blob_payload");

  ContainerStore::destroy(deploymentID);

  const uint64_t missingDeploymentID = deploymentID + 1;
  String missingBuffer = {};
  Message *missingMessage = buildNeuronMessage(missingBuffer, NeuronTopic::requestContainerBlob, missingDeploymentID);
  brain.neuronHandler(&machine.neuron, missingMessage);

  bool sawMissingResponse = false;
  forEachMessageInBuffer(machine.neuron.wBuffer, [&](Message *frame) {
    if (NeuronTopic(frame->topic) != NeuronTopic::requestContainerBlob)
    {
      return;
    }

    uint8_t *args = frame->args;
    uint64_t frameDeploymentID = 0;
    String frameBlob = {};
    Message::extractArg<ArgumentNature::fixed>(args, frameDeploymentID);
    Message::extractToStringView(args, frameBlob);
    sawMissingResponse = sawMissingResponse || (frameDeploymentID == missingDeploymentID && frameBlob.size() == 0);
  });
  suite.expect(sawMissingResponse, "brain_neuron_request_container_blob_missing_emits_empty_payload");
}

static void testBrainNeuronHandlerOwnsRegistrationKernelString(TestSuite& suite)
{
  TestBrain brain = {};

  Machine machine = {};
  machine.uuid = uint128_t(0x5211);
  machine.state = MachineState::deploying;
  machine.neuron.machine = &machine;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  String buffer = {};
  Message *message = buildNeuronMessage(
      buffer,
      NeuronTopic::registration,
      int64_t(1'700'000'000'003),
      "linux-6.10.0"_ctv,
      "ubuntu"_ctv,
      "24.04"_ctv,
      true);
  brain.neuronHandler(&machine.neuron, message);

  buffer.clear();
  buffer.assign("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"_ctv);

  suite.expect(machine.lastUpdatedOSMs == int64_t(1'700'000'000'003), "brain_neuron_registration_preserves_last_updated_os_ms");
  suite.expect(machine.kernel == "linux-6.10.0"_ctv, "brain_neuron_registration_preserves_kernel_text");
  suite.expect(machine.osID == "ubuntu"_ctv, "brain_neuron_registration_preserves_os_id");
  suite.expect(machine.osVersionID == "24.04"_ctv, "brain_neuron_registration_preserves_os_version_id");
  suite.expect(machine.kernel.isInvariant() == false, "brain_neuron_registration_owns_kernel_text");

  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
}

static void testBrainNeuronRegistrationQueuesStateRefreshForRebootRecovery(TestSuite& suite)
{
  TestBrain brain = {};
  brain.ignited = true;
  brain.brainConfig.datacenterFragment = 1;

  Machine machine = {};
  machine.uuid = uint128_t(0x5215);
  machine.state = MachineState::hardRebooting;
  machine.fragment = 0x1236;
  machine.runtimeReady = false;
  machine.reportedDatacenterFragment = 1;
  machine.reportedFragment = 0x1236;
  machine.neuron.machine = &machine;
  machine.hardware.inventoryComplete = true;
  machine.hardware.cpu.logicalCores = 2;
  machine.hardware.memory.totalMB = 4096;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  String buffer = {};
  Message *message = buildNeuronMessage(
      buffer,
      NeuronTopic::registration,
      int64_t(1'700'000'000'015),
      "linux-6.10.0"_ctv,
      "fedora"_ctv,
      "44-prodigy-updated"_ctv,
      true);
  brain.neuronHandler(&machine.neuron, message);

  uint32_t stateUploads = 0;
  uint32_t reportedFragment = 0;
  uint8_t reportedDatacenter = 0;
  forEachMessageInBuffer(machine.neuron.wBuffer, [&](Message *queued) {
    if (NeuronTopic(queued->topic) != NeuronTopic::stateUpload)
    {
      return;
    }

    stateUploads += 1;
    uint8_t *args = queued->args;
    local_container_subnet6 fragment = {};
    Message::extractBytes<Alignment::one>(args, reinterpret_cast<uint8_t *>(&fragment), sizeof(fragment));
    reportedDatacenter = fragment.dpfx;
    reportedFragment = (uint32_t(fragment.mpfx[0]) << 16) | (uint32_t(fragment.mpfx[1]) << 8) | uint32_t(fragment.mpfx[2]);
  });

  suite.expect(stateUploads == 1, "brain_neuron_registration_reboot_recovery_queues_state_refresh");
  suite.expect(reportedDatacenter == 1, "brain_neuron_registration_reboot_recovery_state_refresh_datacenter");
  suite.expect(reportedFragment == 0x1236, "brain_neuron_registration_reboot_recovery_state_refresh_fragment");
  suite.expect(machine.runtimeReady == false, "brain_neuron_registration_reboot_recovery_waits_for_state_ack");

  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
}

static void testBrainNeuronRegistrationKeepsHealthyRuntimeReadyWithoutRefresh(TestSuite& suite)
{
  TestBrain brain = {};
  brain.ignited = true;
  brain.brainConfig.datacenterFragment = 1;

  Machine machine = {};
  machine.uuid = uint128_t(0x5216);
  machine.state = MachineState::healthy;
  machine.fragment = 0x1237;
  machine.runtimeReady = true;
  machine.reportedDatacenterFragment = 1;
  machine.reportedFragment = 0x1237;
  machine.neuron.machine = &machine;
  machine.hardware.inventoryComplete = true;
  machine.hardware.cpu.logicalCores = 2;
  machine.hardware.memory.totalMB = 4096;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  String buffer = {};
  Message *message = buildNeuronMessage(
      buffer,
      NeuronTopic::registration,
      int64_t(1'700'000'000'016),
      "linux-6.10.0"_ctv,
      "ubuntu"_ctv,
      "24.04"_ctv,
      true);
  brain.neuronHandler(&machine.neuron, message);

  uint32_t stateUploads = 0;
  forEachMessageInBuffer(machine.neuron.wBuffer, [&](Message *queued) {
    if (NeuronTopic(queued->topic) == NeuronTopic::stateUpload)
    {
      stateUploads += 1;
    }
  });

  suite.expect(stateUploads == 0, "brain_neuron_registration_healthy_runtime_skips_state_refresh");
  suite.expect(machine.runtimeReady == true, "brain_neuron_registration_healthy_runtime_stays_ready");
  suite.expect(machine.reportedFragment == 0x1237, "brain_neuron_registration_healthy_runtime_preserves_fragment");

  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
}

static void testBrainNeuronHandlerReportsHardwareFailureAndDecommissionsMachine(TestSuite& suite)
{
  TestBrain brain = {};
  TrackingBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  uint128_t rackUUID = uint128_t(0x62026);
  uint128_t machineUUID = uint128_t(0x5212);

  Rack *rack = new Rack();
  rack->uuid = rackUUID;
  brain.racks.insert_or_assign(rack->uuid, rack);

  Machine *machine = new Machine();
  machine->uuid = machineUUID;
  machine->state = MachineState::healthy;
  machine->rack = rack;
  machine->neuron.machine = machine;

  rack->machines.insert(machine);
  brain.machines.insert(machine);
  brain.machinesByUUID.insert_or_assign(machine->uuid, machine);
  brain.neurons.insert(&machine->neuron);

  String buffer = {};
  Message *message = buildNeuronMessage(buffer, NeuronTopic::hardwareFailure, "nvme unreachable"_ctv);
  brain.neuronHandler(&machine->neuron, message);

  buffer.clear();
  buffer.assign("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"_ctv);

  suite.expect(iaas.reportHardwareFailureCalls == 1, "brain_neuron_hardware_failure_reports_to_iaas");
  suite.expect(iaas.lastReportedHardwareFailureUUID == machineUUID, "brain_neuron_hardware_failure_preserves_report_uuid");
  suite.expect(iaas.lastHardwareFailureReport == "nvme unreachable"_ctv, "brain_neuron_hardware_failure_preserves_report_text");
  suite.expect(iaas.lastHardwareFailureReport.isInvariant() == false, "brain_neuron_hardware_failure_owns_report_text");
  suite.expect(iaas.destroyCalls == 1, "brain_neuron_hardware_failure_decommissions_machine");
  suite.expect(iaas.lastDestroyedUUID == machineUUID, "brain_neuron_hardware_failure_preserves_destroy_uuid");
  suite.expect(brain.findMachineByUUIDForTest(machineUUID) == nullptr, "brain_neuron_hardware_failure_removes_machine_from_cluster");
  suite.expect(brain.racks.contains(rackUUID) == false, "brain_neuron_hardware_failure_removes_empty_rack");
}

static void testBrainMachineStateMissingEscalatesWhenSshBudgetExhausted(TestSuite& suite)
{
  TestBrain brain = {};
  TrackingBrainIaaS iaas = {};
  brain.iaas = &iaas;

  Machine machine = {};
  machine.uuid = uint128_t(0x5213);
  machine.state = MachineState::healthy;
  machine.sshRestartAttempts = 2;

  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

  brain.handleMachineStateChange(&machine, MachineState::missing);

  suite.expect(machine.state == MachineState::unresponsive, "cluster_health_missing_budget_exhausted_escalates_to_unresponsive");
  suite.expect(iaas.hardRebootCalls == 0, "cluster_health_missing_budget_exhausted_defers_hard_reboot_until_timeout");

  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
}

static void testBrainSoftEscalationTimeoutPromotesMachineToHardReboot(TestSuite& suite)
{
  ScopedRing scopedRing = {};

  TestBrain brain = {};
  TrackingBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = false;

  Machine machine = {};
  machine.uuid = uint128_t(0x5214);
  machine.state = MachineState::missing;

  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

  TimeoutPacket *packet = new TimeoutPacket();
  packet->flags = uint64_t(BrainTimeoutFlags::softEscalationCheck);
  packet->identifier = machine.uuid;
  packet->originator = &machine;
  packet->dispatcher = &brain;
  machine.softWatchdog = packet;

  brain.dispatchTimeout(packet);

  suite.expect(machine.softWatchdog == nullptr, "cluster_health_soft_escalation_consumes_watchdog");
  suite.expect(machine.state == MachineState::hardRebooting, "cluster_health_soft_escalation_promotes_hard_reboot");
  suite.expect(machine.hardRebootAttempts == 1, "cluster_health_soft_escalation_increments_hard_reboot_attempts");
  suite.expect(iaas.hardRebootCalls == 1, "cluster_health_soft_escalation_calls_iaas_reboot");
  suite.expect(iaas.lastHardRebootUUID == machine.uuid, "cluster_health_soft_escalation_preserves_reboot_uuid");
  suite.expect(machine.hardRebootWatchdog != nullptr, "cluster_health_soft_escalation_arms_hard_reboot_watchdog");

  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
}

static void testBrainHardRebootTimeoutMarksHardwareFailureAndDecommissionsMachine(TestSuite& suite)
{
  ScopedRing scopedRing = {};

  TestBrain brain = {};
  TrackingBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = false;

  uint128_t rackUUID = uint128_t(0x62027);
  uint128_t machineUUID = uint128_t(0x5215);

  Rack *rack = new Rack();
  rack->uuid = rackUUID;
  brain.racks.insert_or_assign(rack->uuid, rack);

  Machine *machine = new Machine();
  machine->uuid = machineUUID;
  machine->state = MachineState::hardRebooting;
  machine->rack = rack;
  machine->neuron.machine = machine;

  rack->machines.insert(machine);
  brain.machines.insert(machine);
  brain.machinesByUUID.insert_or_assign(machine->uuid, machine);
  brain.neurons.insert(&machine->neuron);

  TimeoutPacket *packet = new TimeoutPacket();
  packet->flags = uint64_t(BrainTimeoutFlags::hardRebootedMachine);
  packet->identifier = machine->uuid;
  packet->originator = machine;
  packet->dispatcher = &brain;
  machine->hardRebootWatchdog = packet;

  brain.dispatchTimeout(packet);

  suite.expect(iaas.reportHardwareFailureCalls == 1, "cluster_health_hard_reboot_timeout_reports_hardware_failure");
  suite.expect(iaas.lastReportedHardwareFailureUUID == machineUUID, "cluster_health_hard_reboot_timeout_preserves_failure_uuid");
  suite.expect(iaas.destroyCalls == 1, "cluster_health_hard_reboot_timeout_decommissions_machine");
  suite.expect(iaas.lastDestroyedUUID == machineUUID, "cluster_health_hard_reboot_timeout_preserves_destroy_uuid");
  suite.expect(brain.findMachineByUUIDForTest(machineUUID) == nullptr, "cluster_health_hard_reboot_timeout_removes_machine");
  suite.expect(brain.racks.contains(rackUUID) == false, "cluster_health_hard_reboot_timeout_removes_empty_rack");
}

static ClusterMachine makeCreatedBrainClusterMachineForTest(uint128_t uuid, const String& cloudID, const String& privateAddress, const String& publicAddress)
{
  ClusterMachine machine = {};
  machine.uuid = uuid;
  machine.source = ClusterMachineSource::created;
  machine.backing = ClusterMachineBacking::cloud;
  machine.lifetime = MachineLifetime::ondemand;
  machine.kind = MachineConfig::MachineKind::vm;
  machine.isBrain = true;
  machine.hasCloud = true;
  machine.cloud.schema = "e2-medium"_ctv;
  machine.cloud.providerMachineType = "e2-medium"_ctv;
  machine.cloud.cloudID = cloudID;
  machine.ssh.address = publicAddress;
  machine.ssh.port = 22;
  machine.ssh.user = "root"_ctv;
  machine.ssh.privateKeyPath = "/root/.ssh/id_rsa"_ctv;
  machine.creationTimeMs = Time::now<TimeResolution::ms>();
  machine.addresses.privateAddresses.push_back(ClusterMachineAddress {privateAddress, 0, {}});
  machine.addresses.publicAddresses.push_back(ClusterMachineAddress {publicAddress, 0, {}});
  return machine;
}

static void testBrainNeuronHandlerAppliesMachineHardwareProfile(TestSuite& suite)
{
  ResumableAddMachinesBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;

  ClusterMachine clusterMachine = makeCreatedBrainClusterMachineForTest(0x4201, "gcp-follower-1"_ctv, "10.128.15.213"_ctv, "34.10.44.18"_ctv);
  brain.authoritativeTopology.machines.push_back(clusterMachine);

  Machine machine = {};
  machine.uuid = clusterMachine.uuid;
  machine.isBrain = true;
  machine.state = MachineState::deploying;
  machine.slug = clusterMachine.cloud.schema;
  machine.type = clusterMachine.cloud.providerMachineType;
  machine.cloudID = clusterMachine.cloud.cloudID;
  machine.privateAddress = "10.128.15.213"_ctv;
  machine.publicAddress = "34.10.44.18"_ctv;
  machine.private4 = IPAddress("10.128.15.213", false).v4;
  machine.fragment = 1;
  machine.neuron.machine = &machine;
  machine.neuron.connected = true;
  machine.neuron.fd = 9;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 16;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  suite.expect(brain.findMachineByUUIDForTest(0x4201) == &machine, "brain_neuron_hardware_machine_present");

  MachineHardwareProfile hardware = {};
  hardware.inventoryComplete = true;
  hardware.collectedAtMs = 111'222'333;
  hardware.cpu.logicalCores = 2;
  hardware.memory.totalMB = 4096;
  MachineDiskHardwareProfile disk = {};
  disk.sizeMB = 20'480;
  hardware.disks.push_back(disk);

  String serializedHardware = {};
  BitseryEngine::serialize(serializedHardware, hardware);

  String buffer = {};
  Message *message = buildNeuronMessage(buffer, NeuronTopic::machineHardwareProfile, serializedHardware);
  brain.neuronHandler(&machine.neuron, message);

  suite.expect(machine.hardware.inventoryComplete, "brain_neuron_hardware_inventory_complete");
  suite.expect(machine.hardware.collectedAtMs == 111'222'333, "brain_neuron_hardware_collected_at");
  suite.expect(machine.totalLogicalCores == 2, "brain_neuron_hardware_total_cores");
  suite.expect(machine.totalMemoryMB == 4096, "brain_neuron_hardware_total_memory");
  suite.expect(machine.totalStorageMB == 20'480, "brain_neuron_hardware_total_storage");
  suite.expect(machine.state == MachineState::healthy, "brain_neuron_hardware_marks_healthy");
  suite.expect(brain.authoritativeTopology.machines.size() == 1 && brain.authoritativeTopology.machines[0].hardware.inventoryComplete,
               "brain_neuron_hardware_persists_cluster_topology");
}

static void testBrainIgnitionRequiresNeuronControlBeforeHealthy(TestSuite& suite)
{
  bool createdRing = false;
  if (Ring::getRingFD() <= 0)
  {
    Ring::createRing(8, 8, 32, 32, -1, -1, 0);
    createdRing = true;
  }

  TestBrain brain = {};
  BrainBase *savedBrain = thisBrain;
  thisBrain = &brain;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.brainConfig.datacenterFragment = 1;

  Machine machine = {};
  machine.uuid = uint128_t(0x8811);
  machine.state = MachineState::deploying;
  machine.fragment = 1;
  machine.lastUpdatedOSMs = 1;
  machine.kernel = "linux"_ctv;
  machine.hardware.inventoryComplete = true;
  machine.hardware.cpu.logicalCores = 8;
  machine.hardware.memory.totalMB = 8192;
  machine.neuron.machine = &machine;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 23;
  machine.neuron.connected = false;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  TimeoutPacket ignition = {};
  ignition.flags = uint64_t(BrainTimeoutFlags::ignition);
  suite.expect(brain.machineReadyForHealthyState(&machine) == false, "brain_ignition_fixture_starts_without_active_neuron_control");
  brain.dispatchTimeout(&ignition);
  suite.expect(machine.state != MachineState::healthy, "brain_ignition_requires_neuron_control_before_marking_healthy");

  machine.neuron.connected = true;
  suite.expect(brain.machineReadyForHealthyState(&machine), "brain_ignition_fixture_becomes_ready_after_neuron_control");
  brain.dispatchTimeout(&ignition);
  suite.expect(machine.state == MachineState::healthy, "brain_ignition_marks_machine_healthy_after_neuron_control");

  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);

  if (createdRing)
  {
    Ring::shutdownForExec();
  }

  thisBrain = savedBrain;
}

static void testBrainHealthyRequiresInventoryAndFragment(TestSuite& suite)
{
  bool createdRing = false;
  if (Ring::getRingFD() <= 0)
  {
    Ring::createRing(8, 8, 32, 32, -1, -1, 0);
    createdRing = true;
  }

  TestBrain brain = {};
  BrainBase *savedBrain = thisBrain;
  thisBrain = &brain;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.brainConfig.datacenterFragment = 1;

  Machine machine = {};
  machine.uuid = uint128_t(0x8812);
  machine.state = MachineState::deploying;
  machine.lastUpdatedOSMs = 1;
  machine.kernel = "linux"_ctv;
  machine.neuron.machine = &machine;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 24;
  machine.neuron.connected = true;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  suite.expect(brain.machineReadyForHealthyState(&machine) == false, "brain_machine_ready_requires_hardware_inventory");

  machine.hardware.inventoryComplete = true;
  machine.hardware.cpu.logicalCores = 8;
  machine.hardware.memory.totalMB = 8192;
  suite.expect(brain.machineReadyForHealthyState(&machine) == false, "brain_machine_ready_requires_fragment_assignment");

  machine.fragment = 1;
  suite.expect(brain.machineReadyForHealthyState(&machine), "brain_machine_ready_accepts_connected_inventory_and_fragment");

  machine.hardware = {};
  machine.totalLogicalCores = 8;
  machine.totalMemoryMB = 8192;
  machine.totalStorageMB = 65'536;
  machine.ownedLogicalCores = 8;
  machine.ownedMemoryMB = 8192;
  machine.ownedStorageMB = 65'536;
  suite.expect(brain.machineReadyForHealthyState(&machine) == false, "brain_machine_ready_production_still_requires_hardware_inventory");

  brain.brainConfig.runtimeEnvironment.test.enabled = true;
  suite.expect(brain.machineReadyForHealthyState(&machine), "brain_machine_ready_test_cluster_accepts_configured_capacity_without_inventory");

  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);

  if (createdRing)
  {
    Ring::shutdownForExec();
  }

  thisBrain = savedBrain;
}

static void testTestClusterConfigOverridesCollectedHardwareCapacity(TestSuite& suite)
{
  ResumableAddMachinesBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  BrainBase *savedBrain = thisBrain;
  thisBrain = &brain;

  MachineConfig machineConfig = {};
  machineConfig.slug = "dev-baremetal"_ctv;
  machineConfig.kind = MachineConfig::MachineKind::vm;
  machineConfig.nLogicalCores = 8;
  machineConfig.nMemoryMB = 16'384;
  machineConfig.nStorageMB = 262'144;
  brain.brainConfig.runtimeEnvironment.test.enabled = true;
  brain.brainConfig.configBySlug.insert_or_assign(machineConfig.slug, machineConfig);

  Machine machine = {};
  machine.uuid = uint128_t(0x8813);
  machine.slug = "dev-baremetal"_ctv;
  machine.hardware.inventoryComplete = true;
  machine.hardware.cpu.logicalCores = 48;
  machine.hardware.memory.totalMB = 257'070;
  machine.totalLogicalCores = 48;
  machine.totalMemoryMB = 257'070;
  machine.totalStorageMB = 7'630'916;
  machine.ownedLogicalCores = 46;
  machine.ownedMemoryMB = 252'974;
  machine.ownedStorageMB = 7'626'820;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

  ClusterMachine topologyMachine = {};
  topologyMachine.uuid = machine.uuid;
  topologyMachine.source = ClusterMachineSource::adopted;
  topologyMachine.backing = ClusterMachineBacking::owned;
  topologyMachine.lifetime = MachineLifetime::reserved;
  topologyMachine.kind = MachineConfig::MachineKind::vm;
  topologyMachine.isBrain = true;
  topologyMachine.cloud.schema = machineConfig.slug;
  topologyMachine.hardware = machine.hardware;
  topologyMachine.totalLogicalCores = machine.totalLogicalCores;
  topologyMachine.totalMemoryMB = machine.totalMemoryMB;
  topologyMachine.totalStorageMB = machine.totalStorageMB;
  topologyMachine.ownedLogicalCores = machine.ownedLogicalCores;
  topologyMachine.ownedMemoryMB = machine.ownedMemoryMB;
  topologyMachine.ownedStorageMB = machine.ownedStorageMB;
  brain.authoritativeTopology.version = 10;
  brain.authoritativeTopology.machines.push_back(topologyMachine);

  brain.loadBrainConfigIf();

  suite.expect(machine.totalLogicalCores == 8, "test_cluster_config_overrides_collected_total_cores");
  suite.expect(machine.totalMemoryMB == 16'384, "test_cluster_config_overrides_collected_total_memory");
  suite.expect(machine.totalStorageMB == 262'144, "test_cluster_config_overrides_collected_total_storage");
  suite.expect(machine.ownedLogicalCores == 6, "test_cluster_config_overrides_collected_owned_cores");
  suite.expect(machine.ownedMemoryMB == 12'288, "test_cluster_config_overrides_collected_owned_memory");
  suite.expect(machine.ownedStorageMB == 258'048, "test_cluster_config_overrides_collected_owned_storage");
  suite.expect(machine.nLogicalCores_available == 6, "test_cluster_config_sets_available_cores");
  suite.expect(machine.memoryMB_available == 12'288, "test_cluster_config_sets_available_memory");
  suite.expect(machine.storageMB_available == 258'048, "test_cluster_config_sets_available_storage");

  MachineHardwareProfile collectedHardware = {};
  collectedHardware.inventoryComplete = true;
  collectedHardware.cpu.logicalCores = 48;
  collectedHardware.memory.totalMB = 257'070;
  MachineDiskHardwareProfile collectedDisk = {};
  collectedDisk.sizeMB = 7'630'916;
  collectedHardware.disks.push_back(collectedDisk);
  brain.applyMachineHardwareProfile(&machine, collectedHardware);

  suite.expect(machine.hardware.inventoryComplete, "test_cluster_config_preserves_collected_inventory_state");
  suite.expect(machine.hardware.cpu.logicalCores == 48, "test_cluster_config_preserves_collected_hardware_profile");
  suite.expect(machine.totalLogicalCores == 8, "test_cluster_config_hardware_apply_keeps_configured_total_cores");
  suite.expect(machine.totalMemoryMB == 16'384, "test_cluster_config_hardware_apply_keeps_configured_total_memory");
  suite.expect(machine.totalStorageMB == 262'144, "test_cluster_config_hardware_apply_keeps_configured_total_storage");
  suite.expect(machine.ownedLogicalCores == 6, "test_cluster_config_hardware_apply_keeps_configured_owned_cores");
  suite.expect(machine.nLogicalCores_available == 6, "test_cluster_config_hardware_apply_keeps_available_cores");

  uint32_t persistCallsAfterFirstApply = brain.persistCalls;
  uint64_t topologyVersionAfterFirstApply = brain.authoritativeTopology.version;
  brain.applyMachineHardwareProfile(&machine, collectedHardware);
  suite.expect(brain.persistCalls == persistCallsAfterFirstApply, "test_cluster_config_hardware_reapply_is_idempotent");
  suite.expect(brain.authoritativeTopology.version == topologyVersionAfterFirstApply, "test_cluster_config_hardware_reapply_does_not_bump_topology");

  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);
  thisBrain = savedBrain;
}

static void testBrainIgnitionAssignsFragmentBeforeHealthyTransition(TestSuite& suite)
{
  bool createdRing = false;
  if (Ring::getRingFD() <= 0)
  {
    Ring::createRing(8, 8, 32, 32, -1, -1, 0);
    createdRing = true;
  }

  TestBrain brain = {};
  BrainBase *savedBrain = thisBrain;
  thisBrain = &brain;
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.brainConfig.datacenterFragment = 1;

  Machine machine = {};
  machine.uuid = uint128_t(0x8813);
  machine.state = MachineState::deploying;
  machine.lastUpdatedOSMs = 1;
  machine.kernel = "linux"_ctv;
  machine.hardware.inventoryComplete = true;
  machine.hardware.cpu.logicalCores = 8;
  machine.hardware.memory.totalMB = 8192;
  machine.neuron.machine = &machine;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 25;
  machine.neuron.connected = true;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  suite.expect(machine.fragment == 0, "brain_ignition_assigns_fragment_fixture_starts_unconfigured");
  suite.expect(brain.machineReadyForHealthyState(&machine) == false, "brain_ignition_assigns_fragment_fixture_not_ready_without_fragment");

  TimeoutPacket ignition = {};
  ignition.flags = uint64_t(BrainTimeoutFlags::ignition);
  brain.dispatchTimeout(&ignition);

  suite.expect(machine.fragment != 0, "brain_ignition_assigns_fragment_before_healthy_transition");
  suite.expect(machine.state == MachineState::healthy, "brain_ignition_marks_registered_inventory_machine_healthy_after_fragment_assignment");

  brain.neurons.erase(&machine.neuron);
  brain.machinesByUUID.erase(machine.uuid);
  brain.machines.erase(&machine);

  if (createdRing)
  {
    Ring::shutdownForExec();
  }

  thisBrain = savedBrain;
}

static void testBrainNeuronHandlerClosesOnInvalidMachineHardwareProfile(TestSuite& suite)
{
  bool createdRing = false;
  if (Ring::getRingFD() <= 0)
  {
    Ring::createRing(8, 8, 32, 32, -1, -1, 0);
    createdRing = true;
  }

  ResumableAddMachinesBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;

  ClusterMachine clusterMachine = makeCreatedBrainClusterMachineForTest(0x4202, "gcp-follower-2"_ctv, "10.128.15.214"_ctv, "136.112.187.11"_ctv);
  brain.authoritativeTopology.machines.push_back(clusterMachine);

  Machine machine = {};
  machine.uuid = clusterMachine.uuid;
  machine.isBrain = true;
  machine.state = MachineState::deploying;
  machine.slug = clusterMachine.cloud.schema;
  machine.type = clusterMachine.cloud.providerMachineType;
  machine.cloudID = clusterMachine.cloud.cloudID;
  machine.privateAddress = "10.128.15.214"_ctv;
  machine.publicAddress = "136.112.187.11"_ctv;
  machine.private4 = IPAddress("10.128.15.214", false).v4;
  machine.neuron.machine = &machine;
  machine.neuron.connected = true;
  machine.neuron.fd = 10;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 17;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  suite.expect(brain.findMachineByUUIDForTest(0x4202) == &machine, "brain_neuron_invalid_hardware_machine_present");

  String buffer = {};
  Message *message = buildNeuronMessage(buffer, NeuronTopic::machineHardwareProfile, "not-bitsery"_ctv);
  brain.neuronHandler(&machine.neuron, message);

  suite.expect(machine.hardware.inventoryComplete == false, "brain_neuron_invalid_hardware_keeps_inventory_incomplete");
  suite.expect(Ring::socketIsClosing(&machine.neuron), "brain_neuron_invalid_hardware_closes_stream");

  if (createdRing)
  {
    Ring::shutdownForExec();
  }
}

static void testBrainNeuronHandlerClosesOnIncompleteMachineHardwareProfile(TestSuite& suite)
{
  bool createdRing = false;
  if (Ring::getRingFD() <= 0)
  {
    Ring::createRing(8, 8, 32, 32, -1, -1, 0);
    createdRing = true;
  }

  ResumableAddMachinesBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;
  brain.noMasterYet = false;

  ClusterMachine clusterMachine = makeCreatedBrainClusterMachineForTest(0x4203, "gcp-follower-3"_ctv, "10.128.15.215"_ctv, "136.112.187.12"_ctv);
  brain.authoritativeTopology.machines.push_back(clusterMachine);

  Machine machine = {};
  machine.uuid = clusterMachine.uuid;
  machine.isBrain = true;
  machine.state = MachineState::deploying;
  machine.slug = clusterMachine.cloud.schema;
  machine.type = clusterMachine.cloud.providerMachineType;
  machine.cloudID = clusterMachine.cloud.cloudID;
  machine.privateAddress = "10.128.15.215"_ctv;
  machine.publicAddress = "136.112.187.12"_ctv;
  machine.private4 = IPAddress("10.128.15.215", false).v4;
  machine.neuron.machine = &machine;
  machine.neuron.connected = true;
  machine.neuron.fd = 11;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = 18;
  brain.machines.insert(&machine);
  brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
  brain.neurons.insert(&machine.neuron);

  MachineHardwareProfile hardware = {};
  hardware.inventoryComplete = false;
  hardware.collectedAtMs = 111'222'334;
  hardware.cpu.logicalCores = 2;
  hardware.memory.totalMB = 4096;
  String serializedHardware = {};
  BitseryEngine::serialize(serializedHardware, hardware);

  String buffer = {};
  Message *message = buildNeuronMessage(buffer, NeuronTopic::machineHardwareProfile, serializedHardware);
  brain.neuronHandler(&machine.neuron, message);

  suite.expect(machine.hardware.inventoryComplete == false, "brain_neuron_incomplete_hardware_keeps_inventory_incomplete");
  suite.expect(machine.state == MachineState::deploying, "brain_neuron_incomplete_hardware_keeps_state_deploying");
  suite.expect(Ring::socketIsClosing(&machine.neuron), "brain_neuron_incomplete_hardware_closes_stream");

  if (createdRing)
  {
    Ring::shutdownForExec();
  }
}

static void testMothershipHandlerReplaysReadyLocalHardwareProfile(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  brain.iaas = &iaas;
  brain.weAreMaster = true;

  TestNeuron neuron = {};
  neuron.uuid = 0x2001;
  neuron.private4 = IPAddress("10.128.0.63", false);

  BrainBase *previousBrain = thisBrain;
  NeuronBase *previousNeuron = thisNeuron;
  thisBrain = &brain;
  thisNeuron = &neuron;

  ClusterTopology topology = {};
  ClusterMachine self = {};
  self.uuid = neuron.uuid;
  self.source = ClusterMachineSource::created;
  self.backing = ClusterMachineBacking::cloud;
  self.lifetime = MachineLifetime::ondemand;
  self.kind = MachineConfig::MachineKind::vm;
  self.isBrain = true;
  self.cloud.schema = "e2-medium"_ctv;
  self.cloud.providerMachineType = "e2-medium"_ctv;
  self.cloud.cloudID = "gcp-seed"_ctv;
  self.ssh.address = "34.30.210.167"_ctv;
  self.ssh.user = "root"_ctv;
  self.creationTimeMs = Time::now<TimeResolution::ms>();
  self.addresses.privateAddresses.push_back(ClusterMachineAddress {"10.128.0.63"_ctv, 0, {}});
  topology.machines.push_back(self);

  suite.expect(brain.restoreMachinesFromClusterTopology(topology), "mothership_replays_local_hardware_restore_topology");

  Machine *selfMachine = brain.findMachineByUUIDForTest(neuron.uuid);
  suite.expect(selfMachine != nullptr, "mothership_replays_local_hardware_machine_present");
  if (selfMachine != nullptr)
  {
    suite.expect(selfMachine->hardware.inventoryComplete == false, "mothership_replays_local_hardware_starts_incomplete");
  }

  MachineHardwareProfile hardware = {};
  hardware.inventoryComplete = true;
  hardware.collectedAtMs = 123'456;
  hardware.cpu.logicalCores = 4;
  hardware.memory.totalMB = 8192;
  MachineDiskHardwareProfile disk = {};
  disk.sizeMB = 40'960;
  hardware.disks.push_back(disk);

  String serializedHardware = {};
  BitseryEngine::serialize(serializedHardware, hardware);
  neuron.adoptHardwareInventoryForTest(hardware, serializedHardware);

  Mothership mothership = {};
  String buffer = {};
  Message *message = buildMothershipMessage(buffer, MothershipTopic::pullClusterReport);
  brain.mothershipHandler(&mothership, message);

  if (selfMachine != nullptr)
  {
    suite.expect(selfMachine->hardware.inventoryComplete, "mothership_replays_local_hardware_inventory_complete");
    suite.expect(selfMachine->hardware.collectedAtMs == 123'456, "mothership_replays_local_hardware_timestamp");
    suite.expect(selfMachine->totalLogicalCores == 4, "mothership_replays_local_hardware_cores");
    suite.expect(selfMachine->totalMemoryMB == 8192, "mothership_replays_local_hardware_memory");
    suite.expect(selfMachine->totalStorageMB == 40'960, "mothership_replays_local_hardware_storage");
  }

  thisBrain = previousBrain;
  thisNeuron = previousNeuron;
}

static void testGetMachinesPreservesTopologySchemaOverBootstrapSnapshot(TestSuite& suite)
{
  ResumableAddMachinesBrain brain = {};
  AutoProvisionBrainIaaS iaas = {};
  brain.iaas = &iaas;

  TestNeuron neuron = {};
  neuron.uuid = 0x2002;
  neuron.metro.assign("test-metro"_ctv);

  BrainBase *previousBrain = thisBrain;
  NeuronBase *previousNeuron = thisNeuron;
  thisBrain = &brain;
  thisNeuron = &neuron;

  MachineConfig machineConfig = {};
  machineConfig.slug = "dev-baremetal"_ctv;
  machineConfig.kind = MachineConfig::MachineKind::vm;
  machineConfig.nLogicalCores = 6;
  machineConfig.nMemoryMB = 12'288;
  machineConfig.nStorageMB = 65'536;
  brain.brainConfig.configBySlug.insert_or_assign(machineConfig.slug, machineConfig);

  ClusterMachine topologyMachine = {};
  topologyMachine.uuid = neuron.uuid;
  topologyMachine.source = ClusterMachineSource::adopted;
  topologyMachine.backing = ClusterMachineBacking::owned;
  topologyMachine.lifetime = MachineLifetime::reserved;
  topologyMachine.kind = MachineConfig::MachineKind::vm;
  topologyMachine.isBrain = true;
  topologyMachine.hasCloud = true;
  topologyMachine.cloud.schema = "dev-baremetal"_ctv;
  topologyMachine.rackUUID = 4;
  topologyMachine.ssh.address = "10.0.0.10"_ctv;
  topologyMachine.ssh.user = "root"_ctv;
  topologyMachine.ssh.privateKeyPath = "/tmp/test-key"_ctv;
  prodigyAppendUniqueClusterMachineAddress(topologyMachine.addresses.privateAddresses, "10.0.0.10"_ctv, 24, "10.0.0.1"_ctv);
  brain.authoritativeTopology.machines.push_back(topologyMachine);

  Machine *bootstrapSnapshot = new Machine();
  bootstrapSnapshot->uuid = neuron.uuid;
  bootstrapSnapshot->isBrain = true;
  bootstrapSnapshot->isThisMachine = true;
  bootstrapSnapshot->private4 = IPAddress("10.0.0.10", false).v4;
  bootstrapSnapshot->privateAddress = "10.0.0.10"_ctv;
  bootstrapSnapshot->slug = "bootstrap"_ctv;
  bootstrapSnapshot->lifetime = MachineLifetime::owned;
  bootstrapSnapshot->rackUUID = 4;
  iaas.inventorySnapshots.push_back(bootstrapSnapshot);

  CoroutineStack coro;
  brain.getMachines(&coro);
  coro.co_consume();

  Machine *machine = brain.findMachineByUUIDForTest(neuron.uuid);
  suite.expect(machine != nullptr, "brain_get_machines_preserves_topology_schema_machine_present");
  if (machine != nullptr)
  {
    suite.expect(machine->slug.equals("dev-baremetal"_ctv), "brain_get_machines_preserves_topology_schema");
    suite.expect(machine->lifetime == MachineLifetime::reserved, "brain_get_machines_preserves_topology_lifetime");
    suite.expect(machine->totalLogicalCores == 6, "brain_get_machines_applies_preserved_schema_total_cores");
    suite.expect(machine->totalMemoryMB == 12'288, "brain_get_machines_applies_preserved_schema_total_memory");
    suite.expect(machine->totalStorageMB == 65'536, "brain_get_machines_applies_preserved_schema_total_storage");
    suite.expect(machine->ownedLogicalCores == 4, "brain_get_machines_applies_preserved_schema_owned_cores");
    suite.expect(machine->ownedMemoryMB == 8192, "brain_get_machines_applies_preserved_schema_owned_memory");
    suite.expect(machine->ownedStorageMB == 61'440, "brain_get_machines_applies_preserved_schema_owned_storage");
  }

  iaas.inventorySnapshots.clear();
  delete bootstrapSnapshot;
  thisBrain = previousBrain;
  thisNeuron = previousNeuron;
}

static void testGetMachinesPreservesTopologyIPv6ControlAddressOverSparseSnapshot(TestSuite& suite)
{
  ResumableAddMachinesBrain brain = {};
  AutoProvisionBrainIaaS iaas = {};
  brain.iaas = &iaas;

  TestNeuron neuron = {};
  neuron.uuid = 0x2010;
  neuron.metro.assign("test-metro"_ctv);

  BrainBase *previousBrain = thisBrain;
  NeuronBase *previousNeuron = thisNeuron;
  thisBrain = &brain;
  thisNeuron = &neuron;

  const uint128_t peerUUID = 0x2011;
  ClusterMachine topologyMachine = {};
  topologyMachine.uuid = peerUUID;
  topologyMachine.source = ClusterMachineSource::adopted;
  topologyMachine.backing = ClusterMachineBacking::owned;
  topologyMachine.lifetime = MachineLifetime::reserved;
  topologyMachine.kind = MachineConfig::MachineKind::bareMetal;
  topologyMachine.isBrain = true;
  topologyMachine.rackUUID = 7;
  topologyMachine.ssh.address = "fd00:88::13"_ctv;
  topologyMachine.ssh.user = "root"_ctv;
  prodigyAppendUniqueClusterMachineAddress(topologyMachine.addresses.privateAddresses, "fd00:88::13"_ctv, 64, String());
  brain.authoritativeTopology.machines.push_back(topologyMachine);

  Machine *sparseSnapshot = new Machine();
  sparseSnapshot->uuid = peerUUID;
  sparseSnapshot->isBrain = true;
  sparseSnapshot->slug = "bootstrap"_ctv;
  sparseSnapshot->lifetime = MachineLifetime::owned;
  sparseSnapshot->rackUUID = 7;
  iaas.inventorySnapshots.push_back(sparseSnapshot);

  CoroutineStack coro;
  brain.getMachines(&coro);
  coro.co_consume();

  Machine *machine = brain.findMachineByUUIDForTest(peerUUID);
  suite.expect(machine != nullptr, "brain_get_machines_preserves_ipv6_topology_machine_present");
  if (machine != nullptr)
  {
    suite.expect(machine->privateAddress.equals("fd00:88::13"_ctv), "brain_get_machines_preserves_ipv6_private_address");
    suite.expect(machine->peerAddresses.empty() == false, "brain_get_machines_preserves_ipv6_peer_addresses");
    suite.expect(machine->peerAddresses.empty() == false && machine->peerAddresses[0].address.equals("fd00:88::13"_ctv), "brain_get_machines_preserves_ipv6_peer_address_value");

    IPAddress configuredAddress = {};
    String configuredAddressText = {};
    suite.expect(
        prodigySockaddrToIPAddress(machine->neuron.daddr<struct sockaddr>(), configuredAddress, &configuredAddressText),
        "brain_get_machines_preserves_ipv6_neuron_endpoint_parse");
    suite.expect(configuredAddress.is6, "brain_get_machines_preserves_ipv6_neuron_endpoint_family");
    suite.expect(configuredAddressText.equals("fd00:88::13"_ctv), "brain_get_machines_preserves_ipv6_neuron_endpoint_address");
  }

  iaas.inventorySnapshots.clear();
  delete sparseSnapshot;
  thisBrain = previousBrain;
  thisNeuron = previousNeuron;
}

int main(void)
{
  TestSuite suite;
  bool createdRing = false;
  if (Ring::getRingFD() <= 0)
  {
    Ring::createRing(8, 8, 32, 32, -1, -1, 0);
    createdRing = true;
  }

  testReplicationAcceptanceRules(suite);
  testCredentialBundleBuildAndApply(suite);
  testTlsResumptionRotationAckCoverage(suite);
  testBrainHandlerReplicationPaths(suite);
  testReconcileStateReplicatesCredentialAndTlsState(suite);
  testSystemContainerArtifactReplicationQueuesTypedBlob(suite);
  testMothershipTunnelProviderRuntimeSpecIsStrict(suite);
  testMothershipTunnelProviderConfigureAppliesAtomicallyAndReplicates(suite);
  testMothershipTunnelProviderReconcileBackfillsDesiredStateAndArtifact(suite);
  testMothershipTunnelGatewayClientCertificateAdmission(suite);
  testMothershipTunnelProviderDesiredStateMasterAuthorityReplicationApplies(suite);
  testMothershipTunnelProviderRuntimeStateConfigChanges(suite);
  testMothershipTunnelProviderRuntimeStateRequiresActiveMaster(suite);
  testMothershipTunnelProviderRuntimeLaunchBoundary(suite);
  testMothershipTunnelProviderGatewaySessionMarksHealthy(suite);
  testMothershipTunnelProviderContainerFailureStopsRuntime(suite);
  testMothershipTunnelProviderStateUploadKillsStaleProvider(suite);
  testClusterReportIncludesMothershipConnectivityStatus(suite);
  testDeploymentReplicationBackpressureClosesPeer(suite);
  testMothershipConfigureAppliesClusterUUID(suite);
  testMothershipConfigureOwnsMachineConfigsForManagedSchemas(suite);
  testMothershipConfigureRejectsClusterTakeover(suite);
  testMothershipConfigureLowersSharedCPUOvercommitWithoutMovingClaims(suite);
  testReplicateBrainConfigRejectsClusterTakeover(suite);
  testSpinApplicationInvalidPlanUsesSingleTopicFrame(suite);
  testSpinApplicationProgressAppendsAfterOkayFrame(suite);
  testSpinApplicationProgressAcceptsDirectFdMothership(suite);
  testSpinApplicationProgressStaysOnOriginalDeployStream(suite);
  testSpinApplicationStagesFollowerBlobReplicationBehindMetadataEcho(suite);
  testLargePayloadPeerKeepaliveUsesFixedFileSocketCommand(suite);
  testAcceptedBrainPeerSetsLargePayloadUserTimeout(suite);
  testStatefulRequestMachinesClaimsDeployingMachinesWithSpecializedTicket(suite);
  testSpinApplicationFailedFrameCarriesReason(suite);
  testMachineSchemaMutationsQueueRuntimeStateReplication(suite);
  testManagedMachineSchemaRequestCarriesClusterUUID(suite);
  testManagedMachineSchemaRequestRejectsExistingSeedWithMismatchedKind(suite);
  testManagedMachineSchemaRequestTreatsVMImageChangeAsReplacement(suite);
  testOSUpdateSchedulerStartsFirstEligibleMachineWithoutCadenceDelay(suite);
  testOSUpdateSchedulerGatesTargetVMsConcurrencyAndReimages(suite);
  testOSUpdateLocalMasterHandsOffBeforeSelfUpdate(suite);
  testOSUpdateLocalMasterDefersWithoutUpdatedHandoffPeer(suite);
  testOSUpdateSingleBrainAllowsLocalMasterUpdate(suite);
  testOSUpdateMachineStaysUpdatingUntilTargetVersionRuntimeReady(suite);
  testOSUpdateHardRebootRecoveryStillRequiresTargetVersion(suite);
  testOSUpdateHardRebootCountsAgainstDrainConcurrency(suite);
  testOSUpdateSchedulerFailsClosedAndRequiresDistroPolicy(suite);
  testOSUpdateMissingTransitionWaitsForRebootRecovery(suite);
  testOSUpdateCommandDeadlineFailsClosed(suite);
  testOSUpdateBrainPeerCloseMarksExpectedReboot(suite);
  testOSUpdateBrainRegistrationCompletesHardRebootedPeer(suite);
  testNeuronOSUpdateParsingAndDispatch(suite);
  testMachineSchemaMutationsDriveManagedBudgetActions(suite);
  testReplicatedBrainConfigReplaysFullSwitchboardState(suite);
  testSwitchboardStateSyncReplaysWhiteholes(suite);
  testQuicWormholeStateRefreshReplaysToNeuronsFollowersAndContainers(suite);
  testQuicWormholeRotationAndNoopPaths(suite);
  testWormholeAddressLeasesReserveAndConflict(suite);
  testRegisteredPrefixWormholeAddressAllocation(suite);
  testWormholeDNSLeasesAndCredentialValidation(suite);
  testWormholeAddressLeaseReleaseAndUpgradeTransfer(suite);
  testRegisteredRoutablePrefixRefreshReplaysToNeuronsFollowersAndContainers(suite);
  testRegisteredRoutablePrefixWormholesRefreshHostedIngressBeforeOpen(suite);
  testApplyReplicatedDeploymentPlanLiveStateUpdatesTrackedContainers(suite);
  testApplyReplicatedDeploymentPlanCleansTlsResumptionState(suite);
  testUpdateSelfBundleEchoTransitionsFollowersAndQueuesTransition(suite);
  testUpdateSelfPeerRegistrationCreditsBootNsChange(suite);
  testUpdateSelfPeerRegistrationCreditsReconnectWithoutBootNsChange(suite);
  testMaybeRelinquishMasterSelectsLowestPeerKey(suite);
  testUpdateSelfFinalRelinquishPersistsDesignatedHandoff(suite);
  testUpdateProdigyRespondsBeforeSingleBrainTransition(suite);
  testPersistentMasterAuthorityPackageRestore(suite);
  testResumePendingAddMachinesOperations(suite);
  testResumePendingAddMachinesRefreshesProvisionalCreatedMachine(suite);
  testResumePendingAddMachinesOperationFailureRetainsJournal(suite);
  testSuspendableAddMachinesStreamsCreatedBootstrapDuringSpin(suite);
  testReconcileManagedMachineSchemasSkipsEmptySchemaState(suite);
  testImportedTlsFactoryValidationRejectsBrokenPem(suite);
  testImportedTlsFactoryEnablesBundleBuild(suite);
  testCertificateLifecycleSchedulers(suite);
  testRegisterRoutablePrefixAcceptsSingleMachineHostPrefix(suite);
  testRegisterRoutablePrefixAllocatesElasticPrefix(suite);
  testPullRoutableResourceLeasesTopic(suite);
  testDNSBindingTopicsReserveAddressAndApplyProvider(suite);
  testACMEDNS01ChallengeTopicsUsePublicTlsState(suite);
  testACMELineageImportValidatesAndDistributesPublicTls(suite);
  testTlsIdentityAckAndStaleState(suite);
  testApplicationIdentityInvariants(suite);
  testApplicationReservationInitializersAndAllocators(suite);
  testApplicationReservationValidationFailures(suite);
  testPersistentReservedServiceCaptureAndRestore(suite);
  testMothershipReserveServiceTopic(suite);
  testNeuronInitialFramesDoNotRequireHardwareProfile(suite);
  testNeuronRegistrationBootTimeUsesEpochMs(suite);
  testNeuronInitialFramesDeferAdoptedHardwareProfileUntilBrainStreamReady(suite);
  testNeuronDeferredHardwareInventoryAdoptionRequiresReadySerializedProfile(suite);
  testNeuronDeferredHardwareInventoryWakeAdoptsReadyProfile(suite);
  testNeuronEnsureDeferredHardwareInventoryProgressQueuesReadyProfileToActiveBrain(suite);
  testBrainNeuronHandlerRestartingContainerFailurePreservesAnySubscribersWithoutDeadReplay(suite);
  testNeuronQueuesCachedHardwareProfileWhenBrainStreamBecomesActive(suite);
  testNeuronOverlayRoutingSyncWithoutPrograms(suite);
  testNeuronWhiteholeBindingBookkeepingWithoutPrograms(suite);
  testNeuronResolveOptionalHostRouterBPFPaths(suite);
  testNeuronQueueBrainAcceptPaths(suite);
  testNeuronAcceptHandlerBrainControlPaths(suite);
  testNeuronCloseHandlerPaths(suite);
  testNeuronMetricsTickHelpers(suite);
  testNeuronMetricSamplingHelpers(suite);
  testNeuronCollectsContainerMetricsAndForwardsToBrain(suite);
  testNeuronPendingReplayHelpers(suite);
  testNeuronExtractFixedArgBoundedHelpers(suite);
  testNeuronTimeoutHandlerPaths(suite);
  testNeuronStreamStateHelpers(suite);
  testNeuronBrainControlAndDeferredInventoryHelpers(suite);
  testNeuronTransportTLSPeerVerificationGatesHardwareProfileQueueing(suite);
  testNeuronMachineHardwareProfileTransportStripsCaptures(suite);
  testNeuronTransportTLSPeerVerificationAdoptsDeferredHardwareInventory(suite);
  testNeuronTransportTLSPeerVerificationRejectsPeerWithoutTransportUUID(suite);
  testNeuronTransportTLSPeerVerificationWaitsForNegotiation(suite);
  testNeuronTransportTLSBrainRecvAndSendHandlers(suite);
  testNeuronTransportTLSRecvHandlerClosesOnMalformedFrame(suite);
  testNeuronTransportTLSRecvHandlerRejectsMissingUUIDPeer(suite);
  testBrainAcceptKeepsLiveAcceptedTLSPeerHandshake(suite);
  testMachineReadyRequiresVerifiedTLSNeuronControl(suite);
  testNeuronDeferredHardwareInventoryCompletionStates(suite);
  testNeuronDeferredHardwareInventoryWakePollHandlerStates(suite);
  testNeuronRecvAndSendControlHandlers(suite);
  testNeuronOpenSwitchboardWormholesSyncsOwningRuntime(suite);
  testNeuronContainerConnectHandlerPaths(suite);
  testNeuronRecvDispatchesPairingAndCredentialMessages(suite);
  testNeuronPushContainerRefreshesTrackedWormholes(suite);
  testNeuronRecvAndSendSocketWrappers(suite);
  testNeuronContainerHandlerForwardsHealthyToBrain(suite);
  testNeuronContainerHandlerMarksMasterLocalContainerHealthyWithoutBrainStream(suite);
  testNeuronContainerHandlerRelaysHealthyToMasterPeerWithoutBrainStream(suite);
  testNeuronContainerHandlerMarksMasterLocalContainerHealthyWithActiveBrainStream(suite);
  testNeuronContainerHandlerForwardsStatisticsToBrain(suite);
  testNeuronHandlerStoresRequestedContainerBlob(suite);
  testNeuronSpinContainerRejectReportsFailure(suite);
  testNeuronStateUploadSkipsExistingLiveContainer(suite);
  testNeuronHandlerKillContainerStopsContainerAndEchoesBrain(suite);
  testBrainNeuronHandlerMarksContainerHealthyOnceAndClearsWaiters(suite);
  testBrainReplicatedContainerHealthyMarksContainerHealthyOnMaster(suite);
  testBrainContainerHealthyReplicatesRuntimeStateToFollowers(suite);
  testBrainReplicatedContainerRuntimeStateRestoresTakeoverView(suite);
  testBrainReplicatedContainerRuntimeStateWaitsForDeployment(suite);
  testBrainNeuronHandlerHealthyReplacementPointerClearsEquivalentWaiter(suite);
  testBrainNeuronStateUploadRemovesStaleCanonicalMachineContainer(suite);
  testBrainNeuronStateUploadHealthyContainerClearsWaiters(suite);
  testDeployingContainerFailureFailsDeployment(suite);
  testBrainNeuronStateUploadRestoresOnlyActiveMeshServices(suite);
  testBrainNeuronStateUploadRuntimeReadyFalseClearsStatefulTopologyBarrier(suite);
  testBrainNeuronStateUploadRequiresMatchingAssignedFragmentForMachineRuntimeReady(suite);
  testBrainNeuronControlHandshakeWatchdogClosesStalledRebootRecovery(suite);
  testBrainPeerHandshakeWatchdogClosesStalledRegistration(suite);
  testBrainPeerHandshakeWatchdogCancelsAfterFreshRegistration(suite);
  testBrainNeuronControlHandshakeWatchdogCancelsAfterRuntimeReadyUpload(suite);
  testBrainNeuronStateUploadHealthyAdvertiserRefreshesPeerPairingsOnPortChange(suite);
  testBrainNeuronStateUploadHealthyReplacementPointerClearsEquivalentWaiter(suite);
  testMachineHealthyClaimWakePreservesTicketOutstandingCount(suite);
  testMachineHealthyDefersClaimWakeUntilRuntimeReady(suite);
  testMachineHealthySkipsScheduledStatelessDonorMoveUntilQuiescent(suite);
  testDrainMachineSkipsScheduledLiveRedeployUntilHealthy(suite);
  testBrainNeuronHandlerRecordsContainerStatisticsAndReplicates(suite);
  testBrainNeuronHandlerContainerStatisticsCanTriggerStatefulTopologyCutover(suite);
  testBrainReplicatedMetricAppendCanTriggerStatefulTopologyCutover(suite);
  testBrainNeuronHandlerHandlesRestartingContainerFailure(suite);
  testBrainNeuronHandlerRestartingStatefulMasterKeepsClientServiceSticky(suite);
  testBrainNeuronHandlerHandlesNonRestartingContainerFailureAndDrainsMachine(suite);
  testBrainNeuronHandlerProcessesKillContainerAckAndDrainsMachine(suite);
  testBrainNeuronHandlerQueuesRequestedContainerBlob(suite);
  testBrainNeuronHandlerOwnsRegistrationKernelString(suite);
  testBrainNeuronRegistrationQueuesStateRefreshForRebootRecovery(suite);
  testBrainNeuronRegistrationKeepsHealthyRuntimeReadyWithoutRefresh(suite);
  testBrainNeuronHandlerReportsHardwareFailureAndDecommissionsMachine(suite);
  testBrainMachineStateMissingEscalatesWhenSshBudgetExhausted(suite);
  testBrainSoftEscalationTimeoutPromotesMachineToHardReboot(suite);
  testBrainHardRebootTimeoutMarksHardwareFailureAndDecommissionsMachine(suite);
  testBrainNeuronHandlerAppliesMachineHardwareProfile(suite);
  testBrainIgnitionRequiresNeuronControlBeforeHealthy(suite);
  testBrainHealthyRequiresInventoryAndFragment(suite);
  testTestClusterConfigOverridesCollectedHardwareCapacity(suite);
  testBrainIgnitionAssignsFragmentBeforeHealthyTransition(suite);
  testBrainNeuronHandlerClosesOnInvalidMachineHardwareProfile(suite);
  testBrainNeuronHandlerClosesOnIncompleteMachineHardwareProfile(suite);
  testMothershipHandlerReplaysReadyLocalHardwareProfile(suite);
  testGetMachinesPreservesTopologySchemaOverBootstrapSnapshot(suite);
  testGetMachinesPreservesTopologyIPv6ControlAddressOverSparseSnapshot(suite);

  if (createdRing)
  {
    Ring::shutdownForExec();
  }

  if (suite.failed == 0)
  {
    basics_log("PASS: prodigy_brain_replication_credentials_unit\n");
    return 0;
  }

  basics_log("FAIL: prodigy_brain_replication_credentials_unit failed=%d\n", suite.failed);
  return 1;
}
