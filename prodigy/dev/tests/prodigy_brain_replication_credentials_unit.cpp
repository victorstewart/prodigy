#include <prodigy/prodigy.h>
#include <services/debug.h>
#include <prodigy/brain/brain.h>
#include <prodigy/dev/tests/prodigy_test_ssh_keys.h>

#include <cstdlib>
#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <limits>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <unistd.h>

class TestSuite
{
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

class TestBrain : public Brain
{
public:
   uint32_t persistCalls = 0;
   uint32_t masterAuthorityApplyCalls = 0;
   uint32_t clusterOwnershipCalls = 0;
   uint128_t lastClaimedClusterUUID = 0;
   bool rejectClusterOwnership = false;
   String rejectClusterOwnershipFailure = {};

   void configureCloudflareTunnel(String& mothershipEndpoint) override
   {
      mothershipEndpoint.assign("127.0.0.1"_ctv);
   }

   void teardownCloudflareTunnel(void) override
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

      if (failure) failure->clear();
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

   void queueBrainDeploymentReplicationForTest(const String& serializedPlan, const String& containerBlob)
   {
      queueBrainDeploymentReplication(serializedPlan, containerBlob);
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

class PairingTrackingContainerView : public ContainerView
{
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

class StreamingTestBrain final : public TestBrain
{
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

class ResumableAddMachinesBrain : public TestBrain
{
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

class AsyncQueuedAddMachinesBrain final : public ResumableAddMachinesBrain
{
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

class NoopBrainIaaS : public BrainIaaS
{
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

class TrackingBrainIaaS final : public NoopBrainIaaS
{
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

class AutoProvisionBrainIaaS final : public BrainIaaS
{
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
            if ((observedBrain != nullptr && observedBrain->bootstrappedMachines.empty() == false)
               || (observedAsyncQueuedMachines != nullptr && observedAsyncQueuedMachines->empty() == false))
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

class NoopNeuronIaaS final : public NeuronIaaS
{
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

class TestNeuron final : public Neuron
{
public:
   using DeferredHardwareInventoryResult = Neuron::DeferredHardwareInventoryResult;
   using ContainerMetricSampleState = Neuron::ContainerMetricSampleState;

   NoopNeuronIaaS localIaaS;
   bool failAcceptedBrainTransportTLSForTest = false;
   uint32_t refreshContainerSwitchboardWormholesCallsForTest = 0;
   uint32_t syncContainerSwitchboardRuntimeCallsForTest = 0;
   uint32_t popContainerCallsForTest = 0;
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

   void seedRegistrationState(int64_t bootMs, const String& kernelVersion, bool haveFragment)
   {
      bootTimeMs = bootMs;
      kernel = kernelVersion;
      lcsubnet6 = {};
      lcsubnet6.dpfx = haveFragment ? 1 : 0;
   }

   void appendInitialFramesForTest(String& outbound)
   {
      (void)appendInitialBrainControlFrames(outbound);
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
   static bool extractFixedArgBoundedForTest(uint8_t *&cursor, uint8_t *terminal, T& value)
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

class ScopedRing final
{
public:
   bool created = false;

   ScopedRing()
   {
      if (Ring::getRingFD() <= 0)
      {
         Ring::createRing(8, 8, 32, 32, -1, -1, 0);
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

class ScopedFreshRing final
{
public:
   bool hadRing = false;

   ScopedFreshRing()
   {
      hadRing = (Ring::getRingFD() > 0);
      if (hadRing)
      {
         Ring::shutdownForExec();
      }

      Ring::createRing(8, 8, 32, 32, -1, -1, 0);
   }

   ~ScopedFreshRing()
   {
      Ring::shutdownForExec();
      if (hadRing)
      {
         Ring::createRing(8, 8, 32, 32, -1, -1, 0);
      }
   }
};

class ScopedSocketPair final
{
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

class ScopedEventFD final
{
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

enum class BrainTransportTLSPeerMode : uint8_t
{
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

class BrainTransportTLSFixture final
{
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

      neuron.seedRegistrationState(24681357, "6.8.0-test"_ctv, false);
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

class BrainSocketFixture final
{
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

class ContainerSocketFixture final
{
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

class BrainContainerFixture final
{
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
   neuron.recvBrainForTest(bytes, [&] (Message *message) {
      dispatchCount += 1;
      neuron.dispatchBrainMessageForTest(message);
   });
   return dispatchCount;
}

class ScopedTempDir final
{
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
static Message *buildBrainMessage(String& buffer, BrainTopic topic, Args&&... args)
{
   buffer.clear();
   Message::construct(buffer, topic, std::forward<Args>(args)...);
   return reinterpret_cast<Message *>(buffer.data());
}

template <typename... Args>
static Message *buildMothershipMessage(String& buffer, MothershipTopic topic, Args&&... args)
{
   buffer.clear();
   Message::construct(buffer, topic, std::forward<Args>(args)...);
   return reinterpret_cast<Message *>(buffer.data());
}

template <typename... Args>
static Message *buildNeuronMessage(String& buffer, NeuronTopic topic, Args&&... args)
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
static Message *buildContainerMessage(String& buffer, ContainerTopic topic, Args&&... args)
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
   forEachMessageInBuffer(buffer, [&] (Message *message) {
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
   seedDeployRequestPlan(plan, 62000);

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

   forEachMessageInBuffer(mothership.wBuffer, [&] (Message *frame) {
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
   seedDeployRequestPlan(deployment.plan, 62001);
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

   forEachMessageInBuffer(mothership.wBuffer, [&] (Message *frame) {
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
   seedDeployRequestPlan(deployment.plan, 62011);
   brain.bindSpinApplicationMothership(&deployment, &mothership);

   brain.pushSpinApplicationProgressToMothership(&deployment, "direct fd active"_ctv);

   uint32_t frameCount = 0;
   SpinApplicationResponseCode responseCode = SpinApplicationResponseCode::invalidPlan;
   String progressMessage = {};

   forEachMessageInBuffer(mothership.wBuffer, [&] (Message *frame) {
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
   seedDeployRequestPlan(deployment.plan, 62012);
   brain.bindSpinApplicationMothership(&deployment, &deployMothership);

   brain.pushSpinApplicationProgressToMothership(&deployment, "original stream only"_ctv);

   uint32_t deployFrames = 0;
   uint32_t reportFrames = 0;

   forEachMessageInBuffer(deployMothership.wBuffer, [&] (Message *frame) {
      if (MothershipTopic(frame->topic) == MothershipTopic::spinApplication)
      {
         deployFrames += 1;
      }
   });
   forEachMessageInBuffer(reportMothership.wBuffer, [&] (Message *frame) {
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
   seedDeployRequestPlan(deployment->plan, 62013);
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
      [&] (BrainView& follower, uint32_t& emptyBlobFrames, uint32_t& nonEmptyBlobFrames) -> void {
         emptyBlobFrames = 0;
         nonEmptyBlobFrames = 0;
         forEachMessageInBuffer(follower.wBuffer, [&] (Message *frame) {
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
   rackA.uuid = 620031;
   rackB.uuid = 620032;
   rackC.uuid = 620033;
   brain.racks.insert_or_assign(rackA.uuid, &rackA);
   brain.racks.insert_or_assign(rackB.uuid, &rackB);
   brain.racks.insert_or_assign(rackC.uuid, &rackC);

   auto seedMachine = [&] (
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
      machine.hardware.memory.totalMB = 8'192;
      machine.ownedLogicalCores = 8;
      machine.ownedMemoryMB = 8'192;
      machine.ownedStorageMB = 4'096;
      machine.totalLogicalCores = 8;
      machine.totalMemoryMB = 8'192;
      machine.totalStorageMB = 4'096;
      machine.nLogicalCores_available = 8;
      machine.sharedCPUMillis_available = 0;
      machine.memoryMB_available = 8'192;
      machine.storageMB_available = 4'096;
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
   seedStatefulDeployRequestPlan(plan, 62003);

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
   seedDeployRequestPlan(deployment.plan, 62002);
   brain.bindSpinApplicationMothership(&deployment, &mothership);

   brain.spinApplicationFailed(&deployment, "canaries failed"_ctv);

   uint32_t frameCount = 0;
   SpinApplicationResponseCode responseCode = SpinApplicationResponseCode::invalidPlan;
   String failureMessage = {};

   forEachMessageInBuffer(mothership.wBuffer, [&] (Message *frame) {
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
   factory.renewLeadPercent = 10;

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

   bool ok = (rootCert != nullptr)
      && (rootKey != nullptr)
      && (intermediateCert != nullptr)
      && (intermediateKey != nullptr)
      && VaultPem::x509ToPem(rootCert, factory.rootCertPem)
      && VaultPem::privateKeyToPem(rootKey, factory.rootKeyPem)
      && VaultPem::x509ToPem(intermediateCert, factory.intermediateCertPem)
      && VaultPem::privateKeyToPem(intermediateKey, factory.intermediateKeyPem);

   if (rootCert) X509_free(rootCert);
   if (rootKey) EVP_PKEY_free(rootKey);
   if (intermediateCert) X509_free(intermediateCert);
   if (intermediateKey) EVP_PKEY_free(intermediateKey);

   if (ok == false)
   {
      failure.assign("failed to generate application tls factory"_ctv);
   }

   return ok;
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
      if (rootCert) X509_free(rootCert);
      if (rootKey) EVP_PKEY_free(rootKey);
      if (failure) failure->assign("invalid transport root material"_ctv);
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
   if (cert) X509_free(cert);
   if (key) EVP_PKEY_free(key);

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
   stream.wBuffer.reserve(16384);
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
   deploymentPlan.tlsIssuancePolicy.renewLeadPercent = 10;
   deploymentPlan.tlsIssuancePolicy.identityNames.push_back("inbound_server_tls"_ctv);
   deploymentPlan.hasApiCredentialPolicy = true;
   deploymentPlan.apiCredentialPolicy.applicationID = 6;
   deploymentPlan.apiCredentialPolicy.requiredCredentialNames.push_back("telnyx_bearer"_ctv);
   deploymentPlan.apiCredentialPolicy.requiredCredentialNames.push_back("missing_name"_ctv);

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

   brain.apiCredentialSetsByApp.insert_or_assign(set.applicationID, set);

   ApplicationTlsVaultFactory factory = {};
   factory.applicationID = 6;
   factory.factoryGeneration = 77;
   factory.defaultLeafValidityDays = 15;
   factory.renewLeadPercent = 10;
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

   ContainerPlan containerPlan;
   brain.applyCredentialsToContainerPlan(deploymentPlan, container, containerPlan);
   suite.expect(containerPlan.hasCredentialBundle, "apply_credentials_sets_bundle_flag");
   suite.expect(containerPlan.credentialBundle.apiCredentials.size() == 1, "apply_credentials_copies_bundle");
   suite.expect(containerPlan.credentialBundle.tlsIdentities.size() == 1, "apply_credentials_copies_tls_bundle");
   suite.expect(containerPlan.credentialBundle.bundleGeneration == 77, "apply_credentials_copies_generation");

   DeploymentPlan noPolicyPlan;
   ContainerPlan noPolicyContainerPlan;
   brain.applyCredentialsToContainerPlan(noPolicyPlan, container, noPolicyContainerPlan);
   suite.expect(noPolicyContainerPlan.hasCredentialBundle == false, "apply_credentials_clears_bundle_without_policy");
   suite.expect(noPolicyContainerPlan.credentialBundle.apiCredentials.size() == 0, "apply_credentials_empty_without_policy");
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
   suite.expect(brain.reserveApplicationIDMapping("ServiceReplicaApp"_ctv, 41000, &reserveFailure), "replicate_service_reserve_app");

   ApplicationServiceIdentity existingService;
   existingService.applicationID = 41000;
   existingService.serviceName.assign("clients"_ctv);
   existingService.serviceSlot = 1;
   existingService.kind = ApplicationServiceIdentity::Kind::stateful;
   reserveFailure.clear();
   suite.expect(brain.reserveApplicationServiceMapping(existingService, &reserveFailure), "replicate_service_seed_existing");

   ApplicationServiceIdentity newerService;
   newerService.applicationID = 41000;
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
   suite.expect(brain.resolveReservedApplicationService(41000, "siblings"_ctv, replicatedService), "replicate_service_accepts_new_mapping");
   suite.expect(replicatedService.serviceSlot == 2, "replicate_service_applies_slot");

   ApplicationTlsVaultFactory existingTls = {};
   existingTls.applicationID = 7;
   existingTls.factoryGeneration = 5;
   existingTls.updatedAtMs = 200;
   existingTls.defaultLeafValidityDays = 15;
   existingTls.renewLeadPercent = 10;
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
      Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateApplicationIDReservation, uint16_t(40001), "ReplicaApp"_ctv);
      brain.brainHandler(&peer, message);
   }
   auto replicatedReservationIt = brain.reservedApplicationIDsByName.find("ReplicaApp"_ctv);
   suite.expect(replicatedReservationIt != brain.reservedApplicationIDsByName.end() && replicatedReservationIt->second == 40001, "replicate_application_id_reservation_applies_payload");
   suite.expect(brain.persistCalls == 5, "replicate_application_id_reservation_persists_on_apply");

   DeploymentPlan plan = makeDeploymentPlan(40001, 101);
   {
      String serialized;
      BitseryEngine::serialize(serialized, plan);
      Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateDeployment, serialized, ""_ctv);
      brain.brainHandler(&peer, message);
   }
   suite.expect(brain.deploymentPlans.find(plan.config.deploymentID()) != brain.deploymentPlans.end(), "replicate_deployment_stores_plan");
   suite.expect(brain.persistCalls == 6, "replicate_deployment_persists_on_apply");
   suite.expect(peer.wBuffer.size() > 0, "replicate_deployment_queues_echo");

   peer.wBuffer.clear();
   {
      Message *message = buildBrainMessage(messageBuffer, BrainTopic::cullDeployment, plan.config.deploymentID());
      brain.brainHandler(&peer, message);
   }
   suite.expect(brain.deploymentPlans.find(plan.config.deploymentID()) == brain.deploymentPlans.end(), "cull_deployment_erases_plan");
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
   pendingOperation.updatedAtMs = 12345;
   pendingOperation.lastFailure.assign("waiting for resume"_ctv);
   runtimeState.pendingAddMachinesOperations.push_back(pendingOperation);
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

   ProdigyMetricSamplesSnapshot metricSamples;
   ProdigyMetricSample metric = {};
   metric.ms = 1700000000000;
   metric.deploymentID = plan.config.deploymentID();
   metric.containerUUID = 0x9911;
   metric.metricKey = ProdigyMetrics::runtimeContainerCpuUtilPctKey();
   metric.value = 87.0f;
   metricSamples.samples.push_back(metric);
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

   const uint16_t appID = 45000;
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
   tlsFactory.renewLeadPercent = 15;
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
   brain.recordContainerMetric(0x1001, 0x1002, ProdigyMetrics::runtimeContainerCpuUtilPctKey(), 1700000000000, 33.0);

   String requestBuffer;
   Message *reconcileMessage = buildBrainMessage(requestBuffer, BrainTopic::reconcileState, uint64_t(0));
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
         if (BitseryEngine::deserializeSafe(serializedIdentity, decoded)
             && decoded.applicationID == appID
             && decoded.serviceName.equal("clients"_ctv)
             && decoded.serviceSlot == 1)
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
         if (BitseryEngine::deserializeSafe(serializedRuntimeState, decoded)
            && decoded.generation == brain.masterAuthorityRuntimeState.generation
            && decoded.nextMintedClientTlsGeneration == brain.masterAuthorityRuntimeState.nextMintedClientTlsGeneration)
         {
            foundMasterAuthority = true;
         }
      }
      else if (topic == BrainTopic::replicateMetricsSnapshot)
      {
         String serializedSamples;
         Message::extractToStringView(args, serializedSamples);

         ProdigyMetricSamplesSnapshot decoded;
         if (BitseryEngine::deserializeSafe(serializedSamples, decoded) && decoded.samples.size() == 1)
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

   MachineConfig machineConfig = {};
   machineConfig.slug = "c7i-flex.large"_ctv;
   machineConfig.kind = MachineConfig::MachineKind::vm;
   machineConfig.vmImageURI = "resolve:ssm:/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"_ctv;
   machineConfig.nLogicalCores = 2;
   machineConfig.nMemoryMB = 4096;
   machineConfig.nStorageMB = 65536;
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
   suite.expect(brain.brainConfig.runtimeEnvironment.providerScope.isInvariant() == false, "mothership_configure_owns_provider_scope");
   suite.expect(brain.brainConfig.runtimeEnvironment.providerCredentialMaterial.size() == 0, "mothership_configure_scrubs_provider_credential_on_managed_aws");
   suite.expect(brain.brainConfig.runtimeEnvironment.aws.bootstrapCredentialRefreshCommand.size() == 0, "mothership_configure_scrubs_aws_refresh_command_on_managed_aws");
   suite.expect(brain.brainConfig.runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint.size() == 0, "mothership_configure_scrubs_aws_refresh_hint_on_managed_aws");
   suite.expect(brain.brainConfig.runtimeEnvironment.aws.instanceProfileName.equals(incoming.runtimeEnvironment.aws.instanceProfileName), "mothership_configure_copies_aws_instance_profile_name");
   suite.expect(brain.brainConfig.runtimeEnvironment.aws.instanceProfileName.isInvariant() == false, "mothership_configure_owns_aws_instance_profile_name");
   suite.expect(brain.brainConfig.runtimeEnvironment.aws.instanceProfileArn.equals(incoming.runtimeEnvironment.aws.instanceProfileArn), "mothership_configure_copies_aws_instance_profile_arn");
   suite.expect(brain.brainConfig.runtimeEnvironment.aws.instanceProfileArn.isInvariant() == false, "mothership_configure_owns_aws_instance_profile_arn");

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

   auto extractReplicatedRuntimeState = [&] (ProdigyMasterAuthorityRuntimeState& replicated) -> bool {
      bool found = false;
      replicated = {};
      forEachMessageInBuffer(follower.wBuffer, [&] (Message *queued) {
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

static void testManagedMachineSchemaRequestMatchesExistingSeedWithoutKind(TestSuite& suite)
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
   suite.expect(work.createdMachines.empty(), "managed_schema_request_seed_without_kind_no_duplicate_create");
   suite.expect(request.removedMachines.empty(), "managed_schema_request_seed_without_kind_no_remove");
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
   workerConfig.nStorageMB = 65536;
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
   brain.authoritativeTopology.machines.back().ownedStorageMB = 65536;
   brain.authoritativeTopology.machines.back().totalLogicalCores = 4;
   brain.authoritativeTopology.machines.back().totalMemoryMB = 8192;
   brain.authoritativeTopology.machines.back().totalStorageMB = 65536;

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
   auto applyCurrentStateToFollower = [&] () -> bool {
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

   RegisteredRoutableAddress address = {};
   address.uuid = uint128_t(0xABC123);
   address.name.assign("public-route"_ctv);
   address.kind = RoutableAddressKind::testFakeAddress;
   address.family = ExternalAddressFamily::ipv6;
   address.machineUUID = machine.uuid;
   address.address = IPAddress("2602:fac0:0:12ab:34cd::77", true);
   replicated.routableAddresses.push_back(address);

   brain.brainConfig = replicated;
   brain.loadBrainConfigIf();

   bool sawResetSwitchboard = false;
   bool sawHostedIngressPrefixes = false;
   bool sawRuntimeEnvironment = false;
   forEachMessageInBuffer(machine.neuron.wBuffer, [&] (Message *queued) {
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
   whitehole.source = ExternalAddressSource::distributableSubnet;
   whitehole.hasAddress = true;
   whitehole.address = IPAddress("203.0.113.77", false);
   whitehole.sourcePort = 55123;
   whitehole.bindingNonce = 99;
   container.whiteholes.push_back(whitehole);

   brain.containers.insert_or_assign(uint128_t(0x9001), &container);
   brain.sendNeuronSwitchboardStateSync(&workerMachine);

   bool workerSawOpenWhiteholes = false;
   forEachMessageInBuffer(workerMachine.neuron.wBuffer, [&] (Message *queued) {
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
            if (args == terminal
               && sourcePort == whitehole.sourcePort
               && address.equals(whitehole.address)
               && transport == whitehole.transport
               && bindingNonce == whitehole.bindingNonce)
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
   deployment.plan = makeDeploymentPlan(52000, 1005);

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

   const int64_t nowMs = 1700000001234LL;
   bool changed = brain.refreshDeploymentWormholeQuicCidState(&deployment, nowMs, false);

   suite.expect(changed, "quic_wormhole_refresh_changes_deployment_plan");
   suite.expect(deployment.plan.wormholes.size() == 1, "quic_wormhole_refresh_keeps_single_wormhole");
   suite.expect(deployment.plan.wormholes[0].hasQuicCidKeyState, "quic_wormhole_refresh_mints_key_state");
   suite.expect(deployment.plan.wormholes[0].quicCidKeyState.rotationHours == 36, "quic_wormhole_refresh_preserves_rotation_hours");
   suite.expect(deployment.plan.wormholes[0].quicCidKeyState.activeKeyIndex == 0, "quic_wormhole_refresh_sets_initial_active_key_index");
   suite.expect(deployment.plan.wormholes[0].quicCidKeyState.rotatedAtMs == nowMs, "quic_wormhole_refresh_sets_rotated_at");
   suite.expect(deployment.plan.wormholes[0].quicCidKeyState.keyMaterialByIndex[0] != uint128_t(0), "quic_wormhole_refresh_sets_key_slot_0");
   suite.expect(deployment.plan.wormholes[0].quicCidKeyState.keyMaterialByIndex[1] != uint128_t(0), "quic_wormhole_refresh_sets_key_slot_1");
   suite.expect(container.wormholes.size() == 1, "quic_wormhole_refresh_updates_live_container_wormholes");
   suite.expect(equalSerializedObjects(container.wormholes[0], deployment.plan.wormholes[0]), "quic_wormhole_refresh_live_container_matches_plan");
   suite.expect(brain.persistCalls == 1, "quic_wormhole_refresh_persists_runtime_state");

   bool sawNeuronOpen = false;
   bool sawContainerRefresh = false;
   forEachMessageInBuffer(machine.neuron.wBuffer, [&] (Message *queued) {
      if (NeuronTopic(queued->topic) == NeuronTopic::openSwitchboardWormholes)
      {
         uint8_t *args = queued->args;
         uint32_t containerID = 0;
         Message::extractArg<ArgumentNature::fixed>(args, containerID);

         String serialized = {};
         Message::extractToStringView(args, serialized);

         Vector<Wormhole> decoded = {};
         if (containerID == container.generateContainerID()
            && BitseryEngine::deserializeSafe(serialized, decoded)
            && decoded.size() == 1
            && equalSerializedObjects(decoded[0], deployment.plan.wormholes[0]))
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
         if (containerUUID == container.uuid
            && BitseryEngine::deserializeSafe(serialized, decoded)
            && decoded.size() == 1
            && equalSerializedObjects(decoded[0], deployment.plan.wormholes[0]))
         {
            sawContainerRefresh = true;
         }
      }
   });

   bool sawFollowerReplication = false;
   forEachMessageInBuffer(follower.wBuffer, [&] (Message *queued) {
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
      if (decodedPlan.wormholes.size() == 1
         && equalSerializedObjects(decodedPlan.wormholes[0], deployment.plan.wormholes[0])
         && containerBlob.size() == 0)
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

   const int64_t initialNowMs = 1700000005000LL;
   suite.expect(brain.refreshDeploymentWormholeQuicCidState(nullptr, initialNowMs, true) == false, "quic_wormhole_refresh_null_deployment_is_noop");

   ApplicationDeployment deployment = {};
   deployment.plan = makeDeploymentPlan(52001, 1006);

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
   suite.expect(brain.persistCalls == 2, "quic_wormhole_refresh_persists_rotated_state");
}

static void testRegisteredRoutableAddressRefreshReplaysToNeuronsFollowersAndContainers(TestSuite& suite)
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
   deployment.plan = makeDeploymentPlan(52003, 1008);

   Wormhole wormhole = {};
   wormhole.externalAddress = IPAddress("203.0.113.10", false);
   wormhole.externalPort = 443;
   wormhole.containerPort = 8443;
   wormhole.layer4 = IPPROTO_UDP;
   wormhole.isQuic = true;
   wormhole.source = ExternalAddressSource::registeredRoutableAddress;
   wormhole.routableAddressUUID = uint128_t(0x1234);
   deployment.plan.wormholes.push_back(wormhole);
   deployment.containers.insert(&container);

   RegisteredRoutableAddress registered = {};
   registered.uuid = wormhole.routableAddressUUID;
   registered.name = "nametag-test-address"_ctv;
   registered.family = ExternalAddressFamily::ipv4;
   registered.kind = RoutableAddressKind::testFakeAddress;
   registered.machineUUID = machine.uuid;
   registered.address = IPAddress("203.0.113.55", false);
   brain.brainConfig.routableAddresses.push_back(registered);

   brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
   brain.deploymentPlans.insert_or_assign(deployment.plan.config.deploymentID(), deployment.plan);

   bool changed = brain.refreshDeploymentRegisteredRoutableAddressWormholes(&deployment);

   suite.expect(changed, "registered_routable_refresh_changes_deployment_plan");
   suite.expect(deployment.plan.wormholes.size() == 1, "registered_routable_refresh_keeps_single_wormhole");
   suite.expect(deployment.plan.wormholes[0].externalAddress.equals(registered.address), "registered_routable_refresh_updates_deployment_external_address");
   suite.expect(container.wormholes.size() == 1, "registered_routable_refresh_updates_live_container_wormholes");
   suite.expect(container.wormholes[0].externalAddress.equals(registered.address), "registered_routable_refresh_live_container_matches_resolved_address");
   suite.expect(brain.persistCalls == 1, "registered_routable_refresh_persists_runtime_state");

   bool sawNeuronOpen = false;
   bool sawContainerRefresh = false;
   forEachMessageInBuffer(machine.neuron.wBuffer, [&] (Message *queued) {
      if (NeuronTopic(queued->topic) == NeuronTopic::openSwitchboardWormholes)
      {
         uint8_t *args = queued->args;
         uint32_t containerID = 0;
         Message::extractArg<ArgumentNature::fixed>(args, containerID);

         String serialized = {};
         Message::extractToStringView(args, serialized);

         Vector<Wormhole> decoded = {};
         if (containerID == container.generateContainerID()
            && BitseryEngine::deserializeSafe(serialized, decoded)
            && decoded.size() == 1
            && equalSerializedObjects(decoded[0], deployment.plan.wormholes[0]))
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
         if (containerUUID == container.uuid
            && BitseryEngine::deserializeSafe(serialized, decoded)
            && decoded.size() == 1
            && equalSerializedObjects(decoded[0], deployment.plan.wormholes[0]))
         {
            sawContainerRefresh = true;
         }
      }
   });

   bool sawFollowerReplication = false;
   forEachMessageInBuffer(follower.wBuffer, [&] (Message *queued) {
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
      if (decodedPlan.wormholes.size() == 1
         && equalSerializedObjects(decodedPlan.wormholes[0], deployment.plan.wormholes[0])
         && containerBlob.size() == 0)
      {
         sawFollowerReplication = true;
      }
   });

   suite.expect(sawNeuronOpen, "registered_routable_refresh_replays_open_switchboard_wormholes");
   suite.expect(sawContainerRefresh, "registered_routable_refresh_replays_container_wormhole_refresh");
   suite.expect(sawFollowerReplication, "registered_routable_refresh_replicates_serialized_deployment_to_followers");
   suite.expect(brain.refreshDeploymentRegisteredRoutableAddressWormholes(&deployment) == false, "registered_routable_refresh_noop_when_address_already_current");
}

static void testRegisteredRoutableAddressWormholesRefreshHostedIngressBeforeOpen(TestSuite& suite)
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

   RegisteredRoutableAddress registered = {};
   registered.uuid = uint128_t(0x7788);
   registered.name = "wormhole-hosted-prefix"_ctv;
   registered.family = ExternalAddressFamily::ipv6;
   registered.kind = RoutableAddressKind::anyHostPublicAddress;
   registered.machineUUID = host.uuid;
   registered.address = IPAddress("2001:db8:100::99", true);
   brain.brainConfig.routableAddresses.push_back(registered);

   ContainerView container = {};
   container.uuid = uint128_t(0xABCD3234);
   container.machine = &host;
   container.fragment = 7;
   container.state = ContainerState::healthy;

   Vector<Wormhole> wormholes = {};
   Wormhole wormhole = {};
   wormhole.externalAddress = IPAddress("2001:db8:100::1", true);
   wormhole.externalPort = 443;
   wormhole.containerPort = 8443;
   wormhole.layer4 = IPPROTO_UDP;
   wormhole.isQuic = true;
   wormhole.source = ExternalAddressSource::registeredRoutableAddress;
   wormhole.routableAddressUUID = registered.uuid;
   wormholes.push_back(wormhole);

   brain.sendNeuronOpenSwitchboardWormholes(&container, wormholes);

   uint32_t hostedIngressIndex = UINT32_MAX;
   uint32_t openIndex = UINT32_MAX;
   uint32_t messageIndex = 0;
   bool hostedPrefixMatchesRoute = false;
   bool openMatchesContainer = false;

   forEachMessageInBuffer(host.neuron.wBuffer, [&] (Message *queued) {
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
            if (makeHostedIngressPrefixForAddress(registered.address, expectedPrefix))
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
         if (containerID == container.generateContainerID()
            && BitseryEngine::deserializeSafe(serialized, decoded)
            && decoded.size() == 1
            && equalSerializedObjects(decoded[0], wormholes[0]))
         {
            openMatchesContainer = true;
         }
      }

      messageIndex += 1;
   });

   suite.expect(hostedIngressIndex != UINT32_MAX, "registered_routable_wormhole_open_queues_hosted_ingress_prefixes");
   suite.expect(hostedPrefixMatchesRoute, "registered_routable_wormhole_open_uses_registered_hosted_prefix");
   suite.expect(openIndex != UINT32_MAX, "registered_routable_wormhole_open_queues_open_message");
   suite.expect(openMatchesContainer, "registered_routable_wormhole_open_preserves_wormhole_payload");
   suite.expect(hostedIngressIndex < openIndex, "registered_routable_wormhole_open_refreshes_hosted_prefixes_before_open");
}

static void testApplyReplicatedDeploymentPlanLiveStateUpdatesTrackedContainers(TestSuite& suite)
{
   TestBrain brain = {};
   brain.iaas = new NoopBrainIaaS();

   ApplicationDeployment deployment = {};
   deployment.plan = makeDeploymentPlan(52002, 1007);

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
   forEachMessageInBuffer(peerA.wBuffer, [&] (Message *frame) {
      if (BrainTopic(frame->topic) == BrainTopic::transitionToNewBundle)
      {
         peerATransitionFrames += 1;
      }
   });

   uint32_t peerBTransitionFrames = 0;
   forEachMessageInBuffer(peerB.wBuffer, [&] (Message *frame) {
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
   forEachMessageInBuffer(peer.wBuffer, [&] (Message *frame) {
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
   forEachMessageInBuffer(lowerPeer.wBuffer, [&] (Message *frame) {
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
   tlsFactory.renewLeadPercent = 10;
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

   suite.expect(restoredTlsIt != restored.tlsVaultFactoriesByApp.end() && equalSerializedObjects(restoredTlsIt->second, tlsFactory), "restore_package_restores_tls_factory");
   suite.expect(restoredApiIt != restored.apiCredentialSetsByApp.end() && equalSerializedObjects(restoredApiIt->second, apiSet), "restore_package_restores_api_credentials");
   suite.expect(restoredIDIt != restored.reservedApplicationIDsByName.end() && restoredIDIt->second == tlsFactory.applicationID, "restore_package_restores_application_id_reservation");
   suite.expect(restoredNameIt != restored.reservedApplicationNamesByID.end() && restoredNameIt->second.equal(appName), "restore_package_restores_application_name_reservation");
   suite.expect(restored.nextReservableApplicationID == source.nextReservableApplicationID, "restore_package_restores_next_application_id");
   suite.expect(restoredPlanIt != restored.deploymentPlans.end() && equalSerializedObjects(restoredPlanIt->second, plan), "restore_package_restores_deployment_plan");
   suite.expect(restoredFailureIt != restored.failedDeployments.end() && restoredFailureIt->second.equal("bundle-missing"_ctv), "restore_package_restores_failed_deployment");
   suite.expect(restored.masterAuthorityRuntimeState == source.masterAuthorityRuntimeState, "restore_package_restores_master_runtime_state");
   suite.expect(restored.nextMintedClientTlsGeneration == source.nextMintedClientTlsGeneration, "restore_package_restores_client_tls_generation");
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
   createdMachine.ownedStorageMB = 65536;
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
   workerConfig.nStorageMB = 32768;
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
   request.applicationID = 60001;
   request.mode = 1;
   request.scheme = uint8_t(CryptoScheme::ed25519);
   request.importRootCertPem.assign("invalid-root-cert"_ctv);
   request.importRootKeyPem.assign("invalid-root-key"_ctv);
   request.importIntermediateCertPem.assign("invalid-intermediate-cert"_ctv);
   request.importIntermediateKeyPem.assign("invalid-intermediate-key"_ctv);
   request.renewLeadPercent = 10;

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
   request.applicationID = 60002;
   request.mode = 1;
   request.scheme = uint8_t(CryptoScheme::p256);
   request.importRootCertPem = generated.rootCertPem;
   request.importRootKeyPem = generated.rootKeyPem;
   request.importIntermediateCertPem = generated.intermediateCertPem;
   request.importIntermediateKeyPem = generated.intermediateKeyPem;
   request.defaultLeafValidityDays = 15;
   request.renewLeadPercent = 10;

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

   DeploymentPlan deploymentPlan;
   deploymentPlan.config.applicationID = request.applicationID;
   deploymentPlan.hasTlsIssuancePolicy = true;
   deploymentPlan.tlsIssuancePolicy.applicationID = request.applicationID;
   deploymentPlan.tlsIssuancePolicy.enablePerContainerLeafs = true;
   deploymentPlan.tlsIssuancePolicy.leafValidityDays = 15;
   deploymentPlan.tlsIssuancePolicy.renewLeadPercent = 10;
   deploymentPlan.tlsIssuancePolicy.identityNames.push_back("inbound_server_tls"_ctv);

   ContainerView container;
   ContainerPlan containerPlan;
   brain.applyCredentialsToContainerPlan(deploymentPlan, container, containerPlan);
   suite.expect(containerPlan.hasCredentialBundle, "mothership_upsert_tls_valid_import_sets_bundle_flag");
   suite.expect(containerPlan.credentialBundle.tlsIdentities.size() == 1, "mothership_upsert_tls_valid_import_builds_tls_bundle");
   suite.expect(containerPlan.credentialBundle.tlsIdentities[0].name.equal("inbound_server_tls"_ctv), "mothership_upsert_tls_valid_import_bundle_name");
}

static void testRegisterRoutableAddressSkipsZeroUUIDHostedMachines(TestSuite& suite)
{
   TestBrain brain;
   Mothership mothership;
   NoopBrainIaaS iaas;
   brain.iaas = &iaas;
   brain.weAreMaster = true;
   brain.noMasterYet = false;
   brain.brainConfig.runtimeEnvironment.test.enabled = true;
   brain.brainConfig.runtimeEnvironment.test.enableFakeIpv4Boundary = true;
   brain.brainConfig.runtimeEnvironment.test.fakePublicSubnet4.network = IPAddress("198.18.0.0", false);
   brain.brainConfig.runtimeEnvironment.test.fakePublicSubnet4.cidr = 16;
   brain.brainConfig.runtimeEnvironment.test.fakePublicSubnet4.canonicalize();

   Machine zeroUUIDMachine = {};
   zeroUUIDMachine.slug.assign("bootstrap"_ctv);
   zeroUUIDMachine.privateAddress.assign("10.0.0.10"_ctv);
   zeroUUIDMachine.neuron.isFixedFile = true;
   zeroUUIDMachine.neuron.fslot = 7;
   zeroUUIDMachine.neuron.connected = true;

   Machine ownedMachine = {};
   ownedMachine.uuid = uint128_t(0x2222);
   ownedMachine.slug.assign("bootstrap"_ctv);
   ownedMachine.privateAddress.assign("10.0.0.11"_ctv);
   ownedMachine.neuron.isFixedFile = true;
   ownedMachine.neuron.fslot = 8;
   ownedMachine.neuron.connected = true;

   brain.machines.insert(&zeroUUIDMachine);
   brain.machines.insert(&ownedMachine);
   brain.machinesByUUID.insert_or_assign(ownedMachine.uuid, &ownedMachine);

   RoutableAddressRegistration request = {};
   request.name.assign("whitehole-test-ipv4"_ctv);
   request.kind = RoutableAddressKind::testFakeAddress;
   request.family = ExternalAddressFamily::ipv4;

   String serializedRequest;
   BitseryEngine::serialize(serializedRequest, request);

   String messageBuffer;
   Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::registerRoutableAddress, serializedRequest);
   brain.mothershipHandler(&mothership, message);

   Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
   String serializedResponse;
   uint8_t *responseArgs = responseMessage->args;
   Message::extractToStringView(responseArgs, serializedResponse);

   RoutableAddressRegistration response = {};
   suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_register_routable_address_deserializes_response");
   suite.expect(response.success, "mothership_register_routable_address_skips_zero_uuid_machine");
   suite.expect(response.created, "mothership_register_routable_address_creates_test_fake_address");
   suite.expect(response.machineUUID == ownedMachine.uuid, "mothership_register_routable_address_uses_nonzero_machine_uuid");
   suite.expect(response.address.isNull() == false, "mothership_register_routable_address_allocates_concrete_address");
   suite.expect(brain.brainConfig.routableAddresses.size() == 1, "mothership_register_routable_address_persists_address");
   suite.expect(brain.brainConfig.routableAddresses[0].machineUUID == ownedMachine.uuid, "mothership_register_routable_address_persists_nonzero_machine_uuid");
}

static void testRegisterRoutableAddressUsesPublicPeerCandidateWhenMachineFieldIsEmpty(TestSuite& suite)
{
   TestBrain brain;
   Mothership mothership;
   NoopBrainIaaS iaas;
   brain.iaas = &iaas;
   brain.weAreMaster = true;
   brain.noMasterYet = false;

   Machine machine = {};
   machine.uuid = uint128_t(0x3344);
   machine.slug.assign("bootstrap"_ctv);
   machine.sshAddress.assign("10.0.0.11"_ctv);
   machine.privateAddress.assign("10.0.0.11"_ctv);
   machine.neuron.isFixedFile = true;
   machine.neuron.fslot = 9;
   machine.neuron.connected = true;
   prodigyAppendUniqueClusterMachinePeerAddress(machine.peerAddresses, ClusterMachinePeerAddress{"10.0.0.11"_ctv, 24, "10.0.0.1"_ctv});
   prodigyAppendUniqueClusterMachinePeerAddress(machine.peerAddresses, ClusterMachinePeerAddress{"fd00:10::b"_ctv, 64, "fd00:10::1"_ctv});
   prodigyAppendUniqueClusterMachinePeerAddress(machine.peerAddresses, ClusterMachinePeerAddress{"2001:db8:100::b"_ctv, 64, "fd00:10::1"_ctv});

   brain.machines.insert(&machine);
   brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

   RoutableAddressRegistration request = {};
   request.name.assign("public-ipv6-route"_ctv);
   request.kind = RoutableAddressKind::anyHostPublicAddress;
   request.family = ExternalAddressFamily::ipv6;

   String serializedRequest = {};
   BitseryEngine::serialize(serializedRequest, request);

   String messageBuffer = {};
   Message *message = buildMothershipMessage(messageBuffer, MothershipTopic::registerRoutableAddress, serializedRequest);
   brain.mothershipHandler(&mothership, message);

   Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
   String serializedResponse = {};
   uint8_t *responseArgs = responseMessage->args;
   Message::extractToStringView(responseArgs, serializedResponse);

   RoutableAddressRegistration response = {};
   suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "mothership_register_routable_address_public_peer_deserializes_response");
   suite.expect(response.success, "mothership_register_routable_address_public_peer_accepts_peer_candidate");
   suite.expect(response.created, "mothership_register_routable_address_public_peer_creates_route");
   suite.expect(response.machineUUID == machine.uuid, "mothership_register_routable_address_public_peer_keeps_machine_uuid");

   String addressText = {};
   suite.expect(ClusterMachine::renderIPAddressLiteral(response.address, addressText), "mothership_register_routable_address_public_peer_renders_address");
   suite.expect(addressText.equals("2001:db8:100::b"_ctv), "mothership_register_routable_address_public_peer_uses_public_ipv6_candidate");
}

static void testApplicationIdentityInvariants(TestSuite& suite)
{
   TestBrain brain;

   String reserveFailure;
   suite.expect(brain.reserveApplicationIDMapping("AppIdentityA"_ctv, 51000, &reserveFailure), "reservation_accepts_new_name_id_pair");
   reserveFailure.clear();
   suite.expect(brain.reserveApplicationIDMapping("AppIdentityA"_ctv, 51000, &reserveFailure), "reservation_accepts_existing_same_name_id_pair");
   reserveFailure.clear();
   suite.expect(brain.reserveApplicationIDMapping("AppIdentityA"_ctv, 51001, &reserveFailure) == false, "reservation_rejects_name_with_different_id");
   reserveFailure.clear();
   suite.expect(brain.reserveApplicationIDMapping("AppIdentityB"_ctv, 51000, &reserveFailure) == false, "reservation_rejects_id_with_different_name");
   reserveFailure.clear();

   ApplicationServiceIdentity clients;
   clients.applicationID = 51000;
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
   suite.expect(brain.reserveApplicationIDMapping(dynamicApplicationName, 51010, &reserveFailure), "reservation_owns_view_backed_application_name");
   auto dynamicReservationIt = brain.reservedApplicationIDsByName.find("AppIdentityOwned"_ctv);
   suite.expect(dynamicReservationIt != brain.reservedApplicationIDsByName.end(), "reservation_owns_view_backed_application_name_lookup");
   if (dynamicReservationIt != brain.reservedApplicationIDsByName.end())
   {
      suite.expect(dynamicReservationIt->first.isInvariant() == false, "reservation_owns_view_backed_application_name_key");
      suite.expect(dynamicReservationIt->second == 51010, "reservation_owns_view_backed_application_name_value");
   }
   auto dynamicReservationNameIt = brain.reservedApplicationNamesByID.find(51010);
   suite.expect(dynamicReservationNameIt != brain.reservedApplicationNamesByID.end(), "reservation_owns_view_backed_application_id_lookup");
   if (dynamicReservationNameIt != brain.reservedApplicationNamesByID.end())
   {
      suite.expect(dynamicReservationNameIt->second.isInvariant() == false, "reservation_owns_view_backed_application_name_value_string");
      suite.expect(dynamicReservationNameIt->second == "AppIdentityOwned"_ctv, "reservation_owns_view_backed_application_name_value_text");
   }

   String dynamicServiceNameBacking = {};
   dynamicServiceNameBacking.assign("dynamicclients"_ctv);
   ApplicationServiceIdentity dynamicService = {};
   dynamicService.applicationID = 51010;
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
   sameApplicationDifferentID.config.applicationID = 51002;
   String identityFailure;
   suite.expect(brain.validateDeploymentApplicationIdentity(sameApplicationDifferentID, identityFailure), "deploy_identity_accepts_plan_without_binary_path");
   suite.expect(identityFailure.size() == 0, "deploy_identity_accepts_plan_without_binary_path_clears_failure");

   DeploymentPlan sameApplicationSameID;
   sameApplicationSameID.config.applicationID = 51000;
   identityFailure.clear();
   suite.expect(brain.validateDeploymentApplicationIdentity(sameApplicationSameID, identityFailure), "deploy_identity_accepts_same_application_id_without_binary_path");
}

static void testApplicationReservationInitializersAndAllocators(TestSuite& suite)
{
   TestBrain brain;

   String reserveFailure;
   suite.expect(brain.reserveApplicationIDMapping("EphemeralApp"_ctv, 60000, &reserveFailure), "reservation_initializer_seed_ephemeral_application");

   ApplicationServiceIdentity ephemeralService = {};
   ephemeralService.applicationID = 60000;
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
   suite.expect(brain.reserveApplicationIDMapping("FreshStatefulApp"_ctv, 61000, &reserveFailure), "reservation_initializer_seed_fresh_stateful_application");

   brain.initializeApplicationServiceReservationState();

   ApplicationServiceIdentity restoredHotClients = {};
   suite.expect(
      brain.resolveReservedApplicationService(MeshRegistry::Hot::applicationID, "clients"_ctv, restoredHotClients),
      "reservation_initializer_restores_hot_clients_service");
   suite.expect(restoredHotClients.serviceSlot == 1, "reservation_initializer_restores_hot_clients_slot");
   suite.expect(restoredHotClients.kind == ApplicationServiceIdentity::Kind::stateful, "reservation_initializer_restores_hot_clients_kind");
   suite.expect(brain.takeNextReservableServiceSlot(MeshRegistry::Hot::applicationID) == 6, "reservation_initializer_next_hot_slot_starts_after_builtin_range");
   suite.expect(brain.takeNextReservableServiceSlot(MeshRegistry::Telnyx::applicationID) == 2, "reservation_initializer_next_telnyx_slot_starts_after_builtin_client");
   suite.expect(brain.takeNextReservableServiceSlot(61000) == 1, "reservation_initializer_fresh_application_service_slot_starts_at_one");
}

static void testApplicationReservationValidationFailures(TestSuite& suite)
{
   TestBrain brain;
   String reserveFailure;

   suite.expect(brain.reserveApplicationIDMapping("ZeroApplication"_ctv, 0, &reserveFailure) == false, "reservation_rejects_zero_application_id");
   suite.expect(reserveFailure.equals("applicationID invalid"_ctv), "reservation_rejects_zero_application_id_reason");

   reserveFailure.clear();
   suite.expect(brain.reserveApplicationIDMapping("invalid app"_ctv, 62000, &reserveFailure) == false, "reservation_rejects_invalid_application_name");
   suite.expect(reserveFailure.equals("applicationName invalid"_ctv), "reservation_rejects_invalid_application_name_reason");

   ApplicationServiceIdentity invalidService = {};
   invalidService.applicationID = 62000;
   invalidService.serviceName.assign("clients"_ctv);
   invalidService.serviceSlot = 1;
   invalidService.kind = ApplicationServiceIdentity::Kind::stateful;

   reserveFailure.clear();
   suite.expect(brain.reserveApplicationServiceMapping(invalidService, &reserveFailure) == false, "service_reservation_rejects_unreserved_application");
   suite.expect(reserveFailure.equals("applicationID not reserved"_ctv), "service_reservation_rejects_unreserved_application_reason");

   reserveFailure.clear();
   suite.expect(brain.reserveApplicationIDMapping("ValidationApp"_ctv, 62000, &reserveFailure), "service_reservation_validation_seed_application");

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

   suite.expect(source.reserveApplicationIDMapping("CaptureApp"_ctv, 63000, &reserveFailure), "persistent_service_capture_seed_application");

   ApplicationServiceIdentity clients = {};
   clients.applicationID = 63000;
   clients.serviceName.assign("clients"_ctv);
   clients.serviceSlot = 2;
   clients.kind = ApplicationServiceIdentity::Kind::stateful;
   reserveFailure.clear();
   suite.expect(source.reserveApplicationServiceMapping(clients, &reserveFailure), "persistent_service_capture_seed_clients");

   ApplicationServiceIdentity siblings = {};
   siblings.applicationID = 63000;
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
   suite.expect(restored.reserveApplicationIDMapping("CaptureApp"_ctv, 63000, &reserveFailure), "persistent_service_restore_seed_application");
   restored.restorePersistentReservedApplicationServices(persistedServices);

   ApplicationServiceIdentity restoredSiblings = {};
   ApplicationServiceIdentity restoredClients = {};
   suite.expect(restored.resolveReservedApplicationService(63000, "siblings"_ctv, restoredSiblings), "persistent_service_restore_resolves_siblings");
   suite.expect(restored.resolveReservedApplicationService(63000, "clients"_ctv, restoredClients), "persistent_service_restore_resolves_clients");
   suite.expect(restoredSiblings.serviceSlot == 1, "persistent_service_restore_keeps_sibling_slot");
   suite.expect(restoredClients.serviceSlot == 2, "persistent_service_restore_keeps_client_slot");
   suite.expect(restored.takeNextReservableServiceSlot(63000) == 3, "persistent_service_restore_restores_next_slot");
}

static void testMothershipReserveServiceTopic(TestSuite& suite)
{
   TestBrain brain;
   brain.weAreMaster = true;

   String reserveFailure;
   suite.expect(brain.reserveApplicationIDMapping("TopicServiceApp"_ctv, 52000, &reserveFailure), "mothership_service_topic_seed_application");

   Mothership mothership;
   String requestBuffer;
   ApplicationServiceReserveRequest request;
   request.applicationID = 52000;
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
   suite.expect(response.applicationID == 52000, "mothership_service_topic_returns_application_id");
   suite.expect(response.serviceName.equal("clients"_ctv), "mothership_service_topic_returns_service_name");
   suite.expect(response.service != 0, "mothership_service_topic_returns_service_value");
}

static void testNeuronInitialFramesDoNotRequireHardwareProfile(TestSuite& suite)
{
   TestNeuron neuron = {};
   neuron.seedRegistrationState(123456, "6.8.0-test"_ctv, false);

   String outbound = {};
   neuron.appendInitialFramesForTest(outbound);

   uint32_t registrationFrames = 0;
   uint32_t hardwareFrames = 0;
   forEachMessageInBuffer(outbound, [&] (Message *message) {
      if (NeuronTopic(message->topic) == NeuronTopic::registration)
      {
         registrationFrames += 1;
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
   neuron.seedRegistrationState(987654, "6.8.0-test"_ctv, true);

   MachineHardwareProfile hardware = {};
   hardware.inventoryComplete = true;
   hardware.cpu.logicalCores = 8;
   hardware.memory.totalMB = 32768;

   String serializedHardware = {};
   BitseryEngine::serialize(serializedHardware, hardware);
   neuron.adoptHardwareInventoryForTest(hardware, serializedHardware);

   String outbound = {};
   neuron.appendInitialFramesForTest(outbound);

   uint32_t registrationFrames = 0;
   uint32_t hardwareFrames = 0;
   forEachMessageInBuffer(outbound, [&] (Message *message) {
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
   suite.expect(neuron.deferredHardwareInventoryReadyForAdoptionForTest(complete, String{}) == false,
      "neuron_deferred_hardware_inventory_rejects_missing_serialized_payload");
   suite.expect(neuron.deferredHardwareInventoryReadyForAdoptionForTest(complete, completeSerialized),
      "neuron_deferred_hardware_inventory_accepts_complete_serialized_profile");
}

static void testNeuronDeferredHardwareInventoryWakeAdoptsReadyProfile(TestSuite& suite)
{
   TestNeuron neuron = {};
   neuron.seedRegistrationState(13579, "6.8.0-test"_ctv, false);

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
   forEachMessageInBuffer(outbound, [&] (Message *message) {
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
   neuron.seedRegistrationState(13579, "6.8.0-test"_ctv, false);
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
   forEachMessageInBuffer(neuron.brainOutboundForTest(), [&] (Message *message) {
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
   neuron.seedRegistrationState(24680, "6.8.0-test"_ctv, false);
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
   forEachMessageInBuffer(neuron.brainOutboundForTest(), [&] (Message *message) {
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

   SwitchboardOverlayMachineRoute route2 = {};
   route2.machineFragment = 0x000002u;
   route2.nextHop = IPAddress("2001:db8::44", true);
   route2.sourceAddress = IPAddress("2001:db8::10", true);

   SwitchboardOverlayMachineRoute route3 = {};
   route3.machineFragment = 0x010102u;
   route3.nextHop = IPAddress("2001:db8::45", true);
   route3.sourceAddress = IPAddress("2001:db8::11", true);

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
   valid.source = ExternalAddressSource::distributableSubnet;
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

   auto restoreEnv = [&] () -> void {
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
         neuron.seedBrainStreamForTest(true);
         NeuronBrainControlStream *existing = neuron.brainStreamForTest();

         neuron.acceptBrainForTest(acceptedFslot);

         suite.expect(neuron.brainStreamForTest() == existing, "neuron_accept_handler_active_brain_preserves_existing_stream");
         suite.expect(neuron.brainStreamForTest()->connected, "neuron_accept_handler_active_brain_keeps_existing_stream_connected");
         suite.expect(neuron.brainStreamForTest()->pendingRecv == false, "neuron_accept_handler_active_brain_does_not_rearm_existing_recv");
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
         neuron.seedRegistrationState(13579, "6.9.1-test"_ctv, true);
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
         forEachMessageInBuffer(neuron.brainOutboundForTest(), [&] (Message *frame) {
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
         neuron.seedRegistrationState(13579, "6.9.1-test"_ctv, true);
         neuron.seedStaleBrainStreamForTest();
         neuron.queueContainerDownloadRequestForTest(uint64_t(0xA114));

         MachineHardwareProfile hardware = {};
         hardware.inventoryComplete = true;
         hardware.cpu.logicalCores = 16;
         hardware.memory.totalMB = 32768;
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
         forEachMessageInBuffer(neuron.brainOutboundForTest(), [&] (Message *frame) {
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
         neuron.seedRegistrationState(13579, "6.9.1-test"_ctv, true);
         neuron.seedBrainStreamForTest(false);
         suite.expect(TestNeuron::rawBrainStreamIsActiveForTest(neuron.brainStreamForTest()), "neuron_accept_handler_replaces_disconnected_raw_active_brain_seed_is_raw_active");
         suite.expect(TestNeuron::brainStreamIsActiveForTest(neuron.brainStreamForTest()) == false, "neuron_accept_handler_replaces_disconnected_raw_active_brain_seed_is_not_connected");
         neuron.queueContainerDownloadRequestForTest(uint64_t(0xA116));

         MachineHardwareProfile hardware = {};
         hardware.inventoryComplete = true;
         hardware.cpu.logicalCores = 16;
         hardware.memory.totalMB = 32768;
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
         forEachMessageInBuffer(neuron.brainOutboundForTest(), [&] (Message *frame) {
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
         neuron.seedRegistrationState(24680, "6.10.0-test"_ctv, true);
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
         forEachMessageInBuffer(neuron.brainOutboundForTest(), [&] (Message *frame) {
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
      forEachMessageInBuffer(neuron.brainOutboundForTest(), [&] (Message *message) {
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
   suite.expect(TestNeuron::parseUnsignedDecimalForTest(" \t12345\n"_ctv, value) && value == 12345, "neuron_metric_helpers_parse_unsigned_decimal_with_whitespace");
   suite.expect(TestNeuron::parseUnsignedDecimalForTest("42ms"_ctv, value) && value == 42, "neuron_metric_helpers_parse_unsigned_decimal_stops_at_suffix");
   suite.expect(TestNeuron::parseUnsignedDecimalForTest("n/a"_ctv, value) == false, "neuron_metric_helpers_parse_unsigned_decimal_rejects_invalid_input");

   suite.expect(TestNeuron::extractCpuUsageUsecForTest("user_usec 10\nusage_usec\t500000\n"_ctv, value) && value == 500000, "neuron_metric_helpers_extract_cpu_usage_reads_usage_usec");
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
   suite.expect(writeSizedFile(payloadFile, 524288), "neuron_metric_helpers_writes_storage_payload");

   String missingPath = {};
   missingPath.assign((temp.path / "missing").c_str());
   suite.expect(TestNeuron::approximateDirectoryUsageBytesForTest(missingPath, value) == false, "neuron_metric_helpers_directory_usage_rejects_missing_path");

   String payloadPath = {};
   payloadPath.assign(payloadFile.c_str());
   suite.expect(TestNeuron::approximateDirectoryUsageBytesForTest(payloadPath, value) && value == 524288, "neuron_metric_helpers_directory_usage_counts_regular_file");

   String storagePathString = {};
   storagePathString.assign(storagePath.c_str());
   suite.expect(TestNeuron::approximateDirectoryUsageBytesForTest(storagePathString, value) && value == 524288, "neuron_metric_helpers_directory_usage_counts_directory_tree");

   int cgroupFD = ::open(cgroupPath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
   suite.expect(cgroupFD >= 0, "neuron_metric_helpers_opens_synthetic_cgroup");
   if (cgroupFD < 0)
   {
      return;
   }

   Container container = {};
   container.plan.uuid = uint128_t(0x7105);
   container.plan.config.applicationID = 62020;
   container.plan.config.versionID = 1;
   container.plan.config.nLogicalCores = 1;
   container.plan.config.memoryMB = 1;
   container.plan.config.storageMB = 1;
   container.cgroup = cgroupFD;
   container.storagePayloadPath.assign(storagePath.c_str());

   suite.expect(TestNeuron::readContainerCpuUsageUsecForTest(&container, value) && value == 500000, "neuron_metric_helpers_reads_container_cpu_usage_usec");
   suite.expect(TestNeuron::readContainerMemoryCurrentBytesForTest(&container, value) && value == 262144, "neuron_metric_helpers_reads_container_memory_current");

   TestNeuron::ContainerMetricSampleState sampleState = {};
   uint64_t utilPct = 0;
   suite.expect(TestNeuron::sampleContainerCpuUtilPctForTest(&container, sampleState, 1'000'000'000ULL, utilPct) == false, "neuron_metric_helpers_cpu_sampling_primes_initial_sample");
   suite.expect(sampleState.hasLastCpuUsage && sampleState.lastCpuUsageUs == 500000, "neuron_metric_helpers_cpu_sampling_stores_initial_usage");

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
   suite.expect(writeSizedFile(storagePath / "payload.bin", 524288), "neuron_collect_metrics_writes_storage_payload");

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
   container.plan.config.applicationID = 62021;
   container.plan.config.versionID = 2;
   container.plan.config.nLogicalCores = 1;
   container.plan.config.memoryMB = 1;
   container.plan.config.storageMB = 1;
   container.neuronScalingDimensionsMask =
      ProdigyMetrics::maskForScalingDimension(ScalingDimension::cpu)
      | ProdigyMetrics::maskForScalingDimension(ScalingDimension::memory)
      | ProdigyMetrics::maskForScalingDimension(ScalingDimension::storage);
   container.neuronMetricsCadenceMs = 250;
   container.cgroup = cgroupFD;
   container.storagePayloadPath.assign(storagePath.c_str());
   neuron.registerContainerForTest(&container);

   auto countMetricValue = [&] (uint64_t metricKey, uint64_t expectedValue) -> uint32_t {
      uint32_t matches = 0;
      forEachMessageInBuffer(neuron.brainOutboundForTest(), [&] (Message *frame) {
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
   container.plan.config.applicationID = 62022;
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
         uint16_t(62022),
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
         uint16_t(62022),
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
      advertisementIt != container.plan.advertisementPairings.end()
      && advertisementIt->second.size() == 1
      && advertisementIt->second[0].secret == uint128_t(0x1111),
      "neuron_pending_replay_applies_advertisement_pairing");

   auto subscriptionIt = container.plan.subscriptionPairings.find(uint64_t(0x6666));
   suite.expect(
      subscriptionIt != container.plan.subscriptionPairings.end()
      && subscriptionIt->second.size() == 1
      && subscriptionIt->second[0].port == 8443,
      "neuron_pending_replay_applies_subscription_pairing");

   suite.expect(container.plan.hasCredentialBundle, "neuron_pending_replay_marks_credential_bundle_present");
   suite.expect(
      container.plan.credentialBundle.apiCredentials.size() == 1
      && container.plan.credentialBundle.apiCredentials[0].name.equals("token"_ctv)
      && container.plan.credentialBundle.apiCredentials[0].material.equals("secret-token"_ctv),
      "neuron_pending_replay_applies_credential_refresh");

   uint32_t advertisementFrames = 0;
   uint32_t subscriptionFrames = 0;
   uint32_t credentialFrames = 0;
   forEachMessageInBuffer(container.wBuffer, [&] (Message *frame) {
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
      container.pid = 999999;
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
      hardware.memory.totalMB = 32768;
      String serialized = {};
      serialized.assign("serialized-hardware"_ctv);
      neuron.seedHardwareProfileForTest(hardware, serialized);

      suite.expect(neuron.latestHardwareProfileIfReadyForTest() != nullptr, "neuron_hardware_profile_ready_returns_pointer_after_inventory_complete");
      suite.expect(neuron.appendMachineHardwareProfileFrameIfReadyForTest(outbound), "neuron_hardware_profile_frame_appends_when_serialized_profile_present");

      uint32_t profileFrames = 0;
      forEachMessageInBuffer(outbound, [&] (Message *frame) {
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
   hardware.memory.totalMB = 16384;

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
   hardware.memory.totalMB = 16384;

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
   disk.sizeMB = 102400;
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
   hardware.memory.totalMB = 32768;

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

   uint32_t hardwareFrames = 0;
   String payload = {};
   forEachMessageInBuffer(fixture.neuron.brainOutboundForTest(), [&] (Message *message) {
      if (NeuronTopic(message->topic) == NeuronTopic::machineHardwareProfile)
      {
         hardwareFrames += 1;
         uint8_t *args = message->args;
         Message::extractToStringView(args, payload);
      }
   });

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
   hardware.memory.totalMB = 16384;

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
   hardware.memory.totalMB = 24576;

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
   fixture.neuron.recvBrainForTest(encryptedBytes, [&] (Message *message) {
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
      hardware.memory.totalMB = 24576;

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
         hardware.memory.totalMB = 12288;

         String serializedHardware = {};
         BitseryEngine::serialize(serializedHardware, hardware);

         String inbound = {};
         buildNeuronMessage(inbound, NeuronTopic::machineHardwareProfile, serializedHardware);
         std::memcpy(fixture.neuron.brainStreamForTest()->rBuffer.pTail(), inbound.data(), inbound.size());
         fixture.neuron.brainStreamForTest()->pendingRecv = true;

         uint32_t dispatchCount = 0;
         uint16_t observedTopic = 0;
         fixture.neuron.recvBrainForTest(int(inbound.size()), [&] (Message *message) {
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
         fixture.neuron.recvBrainForTest(int(sizeof(staleSize)), [&] (Message *) {
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
         fixture.neuron.recvBrainForTest(overflowResult, [&] (Message *) {
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
         fixture.neuron.recvBrainForTest(int(sizeof(malformedSize)), [&] (Message *) {
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
         fixture.neuron.recvBrainForTest(int(sizeof(oversizedSize)), [&] (Message *) {
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
         fixture.neuron.recvBrainForTest(-ECONNRESET, [&] (Message *) {
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
            it != fixture.container.plan.advertisementPairings.end()
            && it->second.size() == 1
            && it->second[0].secret == uint128_t(0x1101)
            && it->second[0].address == uint128_t(0x2202),
            "neuron_recv_advertisement_active_applies_pairing");
         suite.expect(fixture.container.pendingSend, "neuron_recv_advertisement_active_queues_container_send");

         uint32_t frames = 0;
         forEachMessageInBuffer(fixture.container.wBuffer, [&] (Message *frame) {
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
            it != fixture.container.plan.advertisementPairings.end()
            && it->second.size() == 1
            && it->second[0].secret == uint128_t(0x7711)
            && it->second[0].address == uint128_t(0x7712),
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
            it != fixture.container.plan.subscriptionPairings.end()
            && it->second.size() == 1
            && it->second[0].secret == uint128_t(0x4401)
            && it->second[0].address == uint128_t(0x5502)
            && it->second[0].port == 7443,
            "neuron_recv_subscription_active_applies_pairing");
         suite.expect(fixture.container.pendingSend, "neuron_recv_subscription_active_queues_container_send");

         uint32_t frames = 0;
         forEachMessageInBuffer(fixture.container.wBuffer, [&] (Message *frame) {
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
            it != fixture.container.plan.subscriptionPairings.end()
            && it->second.size() == 1
            && it->second[0].secret == uint128_t(0x8811)
            && it->second[0].address == uint128_t(0x8812)
            && it->second[0].port == 9444,
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
      BrainContainerFixture fixture(suite, "neuron_recv_credential_active", uint128_t(0x7020));
      if (fixture.ready)
      {
         CredentialDelta delta = {};
         delta.bundleGeneration = 9;
         delta.reason.assign("rotate"_ctv);
         ApiCredential api = {};
         api.name.assign("token"_ctv);
         api.provider.assign("example"_ctv);
         api.generation = 1;
         api.material.assign("secret-token"_ctv);
         delta.updatedApi.push_back(api);

         String credentialPayload = {};
         suite.expect(
            ProdigyWire::serializeCredentialDelta(credentialPayload, delta),
            "neuron_recv_credential_active_serializes_delta");

         String inbound = {};
         buildNeuronMessage(inbound, NeuronTopic::refreshContainerCredentials, fixture.container.plan.uuid, credentialPayload);
         suite.require(
            seedBrainInboundForTest(suite, fixture.brain.neuron, "neuron_recv_credential_active", inbound),
            "neuron_recv_credential_active_seeds_inbound");
         recvAndDispatchBrainForTest(fixture.brain.neuron, int(inbound.size()));

         suite.expect(fixture.container.plan.hasCredentialBundle, "neuron_recv_credential_active_marks_bundle_present");
         suite.expect(
            fixture.container.plan.credentialBundle.apiCredentials.size() == 1
            && fixture.container.plan.credentialBundle.apiCredentials[0].name.equals("token"_ctv)
            && fixture.container.plan.credentialBundle.apiCredentials[0].material.equals("secret-token"_ctv),
            "neuron_recv_credential_active_applies_delta");
         suite.expect(fixture.container.pendingSend, "neuron_recv_credential_active_queues_container_send");

         uint32_t frames = 0;
         forEachMessageInBuffer(fixture.container.wBuffer, [&] (Message *frame) {
            if (ContainerTopic(frame->topic) == ContainerTopic::credentialsRefresh)
            {
               frames += 1;
            }
         });
         suite.expect(frames == 1, "neuron_recv_credential_active_emits_container_frame");
      }
   }

   {
      BrainContainerFixture fixture(suite, "neuron_recv_credential_inactive", uint128_t(0x7024), false);
      if (fixture.ready)
      {
         CredentialDelta delta = {};
         delta.bundleGeneration = 12;
         delta.reason.assign("inactive"_ctv);
         ApiCredential api = {};
         api.name.assign("token"_ctv);
         api.provider.assign("example"_ctv);
         api.generation = 4;
         api.material.assign("inactive-secret"_ctv);
         delta.updatedApi.push_back(api);

         String credentialPayload = {};
         suite.expect(
            ProdigyWire::serializeCredentialDelta(credentialPayload, delta),
            "neuron_recv_credential_inactive_serializes_delta");

         String inbound = {};
         buildNeuronMessage(inbound, NeuronTopic::refreshContainerCredentials, fixture.container.plan.uuid, credentialPayload);
         suite.require(
            seedBrainInboundForTest(suite, fixture.brain.neuron, "neuron_recv_credential_inactive", inbound),
            "neuron_recv_credential_inactive_seeds_inbound");
         recvAndDispatchBrainForTest(fixture.brain.neuron, int(inbound.size()));

         suite.expect(fixture.container.plan.hasCredentialBundle, "neuron_recv_credential_inactive_marks_bundle_present");
         suite.expect(
            fixture.container.plan.credentialBundle.apiCredentials.size() == 1
            && fixture.container.plan.credentialBundle.apiCredentials[0].material.equals("inactive-secret"_ctv),
            "neuron_recv_credential_inactive_applies_delta");
         suite.expect(
            fixture.brain.neuron.pendingCredentialRefreshPayloadCountForTest(fixture.container.plan.uuid) == 1,
            "neuron_recv_credential_inactive_queues_pending_payload");
         suite.expect(
            fixture.container.pendingSend == false && fixture.container.wBuffer.size() == 0,
            "neuron_recv_credential_inactive_does_not_queue_container_send");
      }
   }

   {
      BrainSocketFixture fixture(suite, "neuron_recv_credential_malformed");
      if (fixture.ready)
      {
         String inbound = {};
         buildNeuronMessage(inbound, NeuronTopic::refreshContainerCredentials, uint128_t(0x7025), "broken"_ctv);
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
      BrainSocketFixture fixture(suite, "neuron_recv_credential_missing");
      if (fixture.ready)
      {
         CredentialDelta delta = {};
         delta.bundleGeneration = 10;
         delta.reason.assign("missing-container"_ctv);
         ApiCredential api = {};
         api.name.assign("token"_ctv);
         api.provider.assign("example"_ctv);
         api.generation = 2;
         api.material.assign("missing-secret"_ctv);
         delta.updatedApi.push_back(api);

         String credentialPayload = {};
         suite.expect(
            ProdigyWire::serializeCredentialDelta(credentialPayload, delta),
            "neuron_recv_credential_missing_serializes_delta");

         String inbound = {};
         buildNeuronMessage(inbound, NeuronTopic::refreshContainerCredentials, uint128_t(0x7021), credentialPayload);
         suite.require(
            seedBrainInboundForTest(suite, fixture.neuron, "neuron_recv_credential_missing", inbound),
            "neuron_recv_credential_missing_seeds_inbound");
         recvAndDispatchBrainForTest(fixture.neuron, int(inbound.size()));

         suite.expect(
            fixture.neuron.pendingCredentialRefreshPayloadCountForTest(uint128_t(0x7021)) == 1,
            "neuron_recv_credential_missing_queues_pending_payload");
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
      BrainContainerFixture fixture(suite, "neuron_recv_credential_pending_destroy", uint128_t(0x7023), true, true, true);
      if (fixture.ready)
      {
         CredentialDelta delta = {};
         delta.bundleGeneration = 11;
         delta.reason.assign("pending-destroy"_ctv);
         ApiCredential api = {};
         api.name.assign("token"_ctv);
         api.provider.assign("example"_ctv);
         api.generation = 3;
         api.material.assign("skipped-secret"_ctv);
         delta.updatedApi.push_back(api);

         String credentialPayload = {};
         suite.expect(
            ProdigyWire::serializeCredentialDelta(credentialPayload, delta),
            "neuron_recv_credential_pending_destroy_serializes_delta");

         String inbound = {};
         buildNeuronMessage(inbound, NeuronTopic::refreshContainerCredentials, fixture.container.plan.uuid, credentialPayload);
         suite.require(
            seedBrainInboundForTest(suite, fixture.brain.neuron, "neuron_recv_credential_pending_destroy", inbound),
            "neuron_recv_credential_pending_destroy_seeds_inbound");
         recvAndDispatchBrainForTest(fixture.brain.neuron, int(inbound.size()));

         suite.expect(fixture.container.plan.hasCredentialBundle == false, "neuron_recv_credential_pending_destroy_skips_delta");
         suite.expect(
            fixture.brain.neuron.pendingCredentialRefreshPayloadCountForTest(fixture.container.plan.uuid) == 0,
            "neuron_recv_credential_pending_destroy_does_not_queue_pending_payload");
         suite.expect(
            fixture.container.pendingSend == false && fixture.container.wBuffer.size() == 0,
            "neuron_recv_credential_pending_destroy_does_not_queue_container_send");
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
            fixture.container.plan.wormholes.size() == 1
            && equalSerializedObjects(fixture.container.plan.wormholes[0], wormhole),
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
            fixture.brain.neuron.lastRefreshedWormholesForTest.size() == 1
            && equalSerializedObjects(fixture.brain.neuron.lastRefreshedWormholesForTest[0], wormhole),
            "neuron_recv_wormholes_active_tracks_refreshed_wormholes");
         suite.expect(fixture.container.pendingSend, "neuron_recv_wormholes_active_queues_container_send");

         bool sawWormholesRefresh = false;
         forEachMessageInBuffer(fixture.container.wBuffer, [&] (Message *frame) {
            if (ContainerTopic(frame->topic) != ContainerTopic::wormholesRefresh)
            {
               return;
            }

            uint8_t *args = frame->args;
            String serialized = {};
            Message::extractToStringView(args, serialized);

            Vector<Wormhole> decoded = {};
            if (BitseryEngine::deserializeSafe(serialized, decoded)
               && decoded.size() == 1
               && equalSerializedObjects(decoded[0], wormhole))
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
         wormhole.source = ExternalAddressSource::registeredRoutableAddress;
         wormhole.routableAddressUUID = uint128_t(0x4455);

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
            fixture.container.plan.wormholes.size() == 1
            && equalSerializedObjects(fixture.container.plan.wormholes[0], wormhole),
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
         wormhole.source = ExternalAddressSource::registeredRoutableAddress;
         wormhole.routableAddressUUID = uint128_t(0xAABBCCDD);

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
         forEachMessageInBuffer(fixture.neuron.brainOutboundForTest(), [&] (Message *message) {
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
         fixture.container.plan.config.applicationID = 62010;
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
         forEachMessageInBuffer(fixture.neuron.brainOutboundForTest(), [&] (Message *message) {
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
         fixture.brain.neuron.ensureSwitchboardForTest();

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
            fixture.brain.neuron.lastRefreshedWormholesForTest.size() == 1
            && equalSerializedObjects(fixture.brain.neuron.lastRefreshedWormholesForTest[0], wormhole),
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
   container.plan.config.applicationID = 62010;
   container.plan.config.versionID = 7;
   container.plan.state = ContainerState::scheduled;

   String buffer = {};
   Message *message = buildContainerMessage(buffer, ContainerTopic::healthy);
   neuron.containerHandler(&container, message);

   uint32_t healthyFrames = 0;
   uint128_t observedContainerUUID = 0;
   forEachMessageInBuffer(neuron.brainOutboundForTest(), [&] (Message *frame) {
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
   rack.uuid = 62012;

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
   deployment.plan = makeDeploymentPlan(62012, 1);
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
   suite.expect(neuron.brainOutboundForTest().size() == 0, "neuron_container_healthy_without_brain_stream_skips_missing_brain_frame");

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
   container.plan.config.applicationID = 62012;
   container.plan.config.versionID = 7;
   container.plan.state = ContainerState::scheduled;

   String buffer = {};
   Message *message = buildContainerMessage(buffer, ContainerTopic::healthy);
   neuron.containerHandler(&container, message);

   uint32_t relayedHealthyFrames = 0;
   bool sawRelayedUUID = false;
   forEachMessageInBuffer(masterPeer.wBuffer, [&] (Message *frame) {
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
   suite.expect(neuron.brainOutboundForTest().size() == 0, "neuron_container_healthy_without_brain_stream_skips_missing_control_stream_frame");

   brain.brains.erase(&masterPeer);
   thisBrain = previousBrain;
}

static void testNeuronContainerHandlerForwardsRuntimeReadyToBrainWithActiveBrainStream(TestSuite& suite)
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
   masterPeer.fslot = 42;
   masterPeer.private4 = 0x0A00000B;
   brain.brains.insert(&masterPeer);

   TestNeuron neuron = {};
   neuron.seedBrainStreamForTest(false);

   Container container = {};
   container.plan.uuid = uint128_t(0x5107);
   container.plan.config.applicationID = 62012;
   container.plan.config.versionID = 7;
   container.plan.state = ContainerState::scheduled;

   String buffer = {};
   Message *message = buildContainerMessage(buffer, ContainerTopic::runtimeReady);
   neuron.containerHandler(&container, message);

   uint32_t relayedRuntimeReadyFrames = 0;
   forEachMessageInBuffer(masterPeer.wBuffer, [&] (Message *frame) {
      suite.expect(BrainTopic(frame->topic) == BrainTopic::replicateContainerRuntimeReady, "neuron_container_runtime_ready_with_brain_stream_relays_brain_topic");
      if (BrainTopic(frame->topic) != BrainTopic::replicateContainerRuntimeReady)
      {
         return;
      }

      relayedRuntimeReadyFrames += 1;
   });

   uint32_t forwardedRuntimeReadyFrames = 0;
   bool sawForwardedUUID = false;
   forEachMessageInBuffer(neuron.brainOutboundForTest(), [&] (Message *frame) {
      if (NeuronTopic(frame->topic) != NeuronTopic::containerRuntimeReady)
      {
         return;
      }

      uint8_t *args = frame->args;
      uint128_t observedUUID = 0;
      Message::extractArg<ArgumentNature::fixed>(args, observedUUID);
      forwardedRuntimeReadyFrames += 1;
      sawForwardedUUID = sawForwardedUUID || (observedUUID == container.plan.uuid);
   });

   suite.expect(relayedRuntimeReadyFrames == 0, "neuron_container_runtime_ready_with_brain_stream_skips_master_peer_relay");
   suite.expect(forwardedRuntimeReadyFrames == 1, "neuron_container_runtime_ready_with_brain_stream_keeps_forwarded_control_frame");
   suite.expect(sawForwardedUUID, "neuron_container_runtime_ready_with_brain_stream_preserves_forwarded_uuid");

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
   rack.uuid = 62013;

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
   deployment.plan = makeDeploymentPlan(62013, 1);
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
   forEachMessageInBuffer(neuron.brainOutboundForTest(), [&] (Message *frame) {
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
   suite.expect(forwardedHealthyFrames == 0, "neuron_container_healthy_with_brain_stream_skips_forwarded_brain_frame");
   suite.expect(sawForwardedUUID == false, "neuron_container_healthy_with_brain_stream_has_no_forwarded_uuid");

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

static void testNeuronContainerHandlerMarksMasterLocalContainerRuntimeReadyWithActiveBrainStream(TestSuite& suite)
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
   rack.uuid = 62014;

   Machine machine = {};
   machine.uuid = uint128_t(0x5107);
   machine.state = MachineState::healthy;
   machine.rack = &rack;
   machine.isThisMachine = true;
   machine.neuron.machine = &machine;
   brain.machines.insert(&machine);
   brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
   brain.neurons.insert(&machine.neuron);

   ApplicationDeployment deployment = {};
   deployment.plan = makeDeploymentPlan(62014, 1);
   deployment.state = DeploymentState::deploying;
   brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
   brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

   Container container = {};
   container.plan.uuid = uint128_t(0x5108);
   container.plan.config = deployment.plan.config;
   container.plan.state = ContainerState::scheduled;

   ContainerView *view = new ContainerView();
   view->uuid = container.plan.uuid;
   view->deploymentID = deployment.plan.config.deploymentID();
   view->applicationID = deployment.plan.config.applicationID;
   view->machine = &machine;
   view->lifetime = ApplicationLifetime::base;
   view->state = ContainerState::scheduled;
   view->runtimeReady = false;
   deployment.containers.insert(view);
   brain.containers.insert_or_assign(view->uuid, view);
   machine.upsertContainerIndexEntry(view->deploymentID, view);

   String buffer = {};
   Message *message = buildContainerMessage(buffer, ContainerTopic::runtimeReady);
   neuron.containerHandler(&container, message);

   uint32_t forwardedRuntimeReadyFrames = 0;
   forEachMessageInBuffer(neuron.brainOutboundForTest(), [&] (Message *frame) {
      if (NeuronTopic(frame->topic) == NeuronTopic::containerRuntimeReady)
      {
         forwardedRuntimeReadyFrames += 1;
      }
   });

   suite.expect(view->runtimeReady, "neuron_container_runtime_ready_with_brain_stream_marks_master_local_view_ready");
   suite.expect(forwardedRuntimeReadyFrames == 0, "neuron_container_runtime_ready_with_brain_stream_skips_forwarded_control_frame_for_master");

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
   container.plan.config.applicationID = 62011;
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
   forEachMessageInBuffer(neuron.brainOutboundForTest(), [&] (Message *frame) {
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
   String containerBlob = {};
   containerBlob.assign("unit-test-container-blob"_ctv);
   ContainerStore::destroy(deploymentID);

   String buffer = {};
   Message *message = buildNeuronMessage(buffer, NeuronTopic::requestContainerBlob, deploymentID, containerBlob);
   neuron.neuronHandler(message);

   String storedBlob = {};
   ContainerStore::get(deploymentID, storedBlob);
   suite.expect(storedBlob.equals(containerBlob), "neuron_request_container_blob_stores_blob");

   ContainerStore::destroy(deploymentID);
}

static void testNeuronHandlerKillContainerStopsContainerAndEchoesBrain(TestSuite& suite)
{
   ScopedRing scopedRing = {};

   TestNeuron neuron = {};
   neuron.seedBrainStreamForTest(false);

   Container *container = new Container();
   container->plan.uuid = uint128_t(0x5103);
   container->plan.config.applicationID = 62012;
   container->plan.config.versionID = 11;
   neuron.containers.insert_or_assign(container->plan.uuid, container);

   NeuronBase *previousNeuron = thisNeuron;
   thisNeuron = &neuron;

   String buffer = {};
   Message *message = buildNeuronMessage(buffer, NeuronTopic::killContainer, container->plan.uuid);
   neuron.neuronHandler(message);

   uint32_t stopFrames = 0;
   forEachMessageInBuffer(container->wBuffer, [&] (Message *frame) {
      if (ContainerTopic(frame->topic) == ContainerTopic::stop)
      {
         stopFrames += 1;
      }
   });

   uint32_t echoFrames = 0;
   uint128_t echoedContainerUUID = 0;
   forEachMessageInBuffer(neuron.brainOutboundForTest(), [&] (Message *frame) {
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
   suite.expect(echoFrames == 1, "neuron_kill_container_echoes_to_brain");
   suite.expect(echoedContainerUUID == container->plan.uuid, "neuron_kill_container_echo_preserves_uuid");

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
   rack.uuid = 62020;

   Machine machine = {};
   machine.uuid = uint128_t(0x5201);
   machine.state = MachineState::healthy;
   machine.rack = &rack;
   machine.neuron.machine = &machine;
   brain.machines.insert(&machine);
   brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
   brain.neurons.insert(&machine.neuron);

   ApplicationDeployment deployment = {};
   deployment.plan = makeDeploymentPlan(62020, 1);
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
   rack.uuid = 62021;

   Machine machine = {};
   machine.uuid = uint128_t(0x5203);
   machine.state = MachineState::healthy;
   machine.rack = &rack;
   machine.neuron.machine = &machine;
   brain.machines.insert(&machine);
   brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
   brain.neurons.insert(&machine.neuron);

   ApplicationDeployment deployment = {};
   deployment.plan = makeDeploymentPlan(62021, 1);
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

static void testBrainNeuronStateUploadRemovesStaleCanonicalMachineContainer(TestSuite& suite)
{
   TestBrain brain = {};
   NoopBrainIaaS iaas = {};
   brain.iaas = &iaas;
   brain.weAreMaster = true;

   BrainBase *previousBrain = thisBrain;
   thisBrain = &brain;

   Rack rack = {};
   rack.uuid = 62030;

   Machine machine = {};
   machine.uuid = uint128_t(0x5301);
   machine.state = MachineState::healthy;
   machine.rack = &rack;
   machine.neuron.machine = &machine;
   brain.machines.insert(&machine);
   brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
   brain.neurons.insert(&machine.neuron);

   ApplicationDeployment deployment = {};
   deployment.plan = makeDeploymentPlan(62030, 1);
   deployment.state = DeploymentState::deploying;
   brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
   brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

   ContainerView *stale = new ContainerView();
   stale->uuid = uint128_t(0x5302);
   stale->deploymentID = deployment.plan.config.deploymentID();
   stale->applicationID = deployment.plan.config.applicationID;
   stale->machine = &machine;
   stale->lifetime = ApplicationLifetime::base;
   stale->state = ContainerState::healthy;
   stale->fragment = 9;
   stale->createdAtMs = 123456;

   deployment.containers.insert(stale);
   brain.containers.insert_or_assign(stale->uuid, stale);
   machine.upsertContainerIndexEntry(stale->deploymentID, stale);

   ContainerView liveSeed = {};
   liveSeed.uuid = uint128_t(0x5303);
   liveSeed.fragment = 10;
   liveSeed.lifetime = ApplicationLifetime::base;
   liveSeed.state = ContainerState::healthy;
   liveSeed.createdAtMs = 123457;
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

   auto liveIt = brain.containers.find(livePlan.uuid);
   suite.expect(liveIt != brain.containers.end(), "brain_neuron_state_upload_tracks_reported_container");
   suite.expect(brain.containers.find(stale->uuid) == brain.containers.end(), "brain_neuron_state_upload_removes_stale_canonical_container");
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
   rack.uuid = 62040;

   Machine machine = {};
   machine.uuid = uint128_t(0x5401);
   machine.state = MachineState::healthy;
   machine.rack = &rack;
   machine.neuron.machine = &machine;
   brain.machines.insert(&machine);
   brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
   brain.neurons.insert(&machine.neuron);

   ApplicationDeployment deployment = {};
   deployment.plan = makeDeploymentPlan(62040, 1);
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
   container->createdAtMs = 123458;
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

static void testBrainNeuronStateUploadRestoresOnlyActiveMeshServices(TestSuite& suite)
{
   TestBrain brain = {};
   NoopBrainIaaS iaas = {};
   brain.iaas = &iaas;
   brain.weAreMaster = true;

   BrainBase *previousBrain = thisBrain;
   thisBrain = &brain;

   Rack rack = {};
   rack.uuid = 62043;

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
   deployment.plan = makeDeploymentPlan(62043, 1);
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
   seed.createdAtMs = 123459;
   seed.shardGroup = 0;
   seed.advertisements.insert_or_assign(
      scheduledService,
      Advertisement(scheduledService, ContainerState::scheduled, ContainerState::destroying, 19101));
   seed.advertisements.insert_or_assign(
      healthyService,
      Advertisement(healthyService, ContainerState::healthy, ContainerState::destroying, 19102));

   auto uploadPlan = [&] (ContainerPlan& plan) -> void {
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

static void testBrainNeuronStateUploadRejectsHealthyAdvertiserPortChange(TestSuite& suite)
{
   TestBrain brain = {};
   NoopBrainIaaS iaas = {};
   brain.iaas = &iaas;
   brain.weAreMaster = true;

   BrainBase *previousBrain = thisBrain;
   thisBrain = &brain;

   Rack rack = {};
   rack.uuid = 62045;

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
   deployment.plan = makeDeploymentPlan(62045, 1);
   deployment.state = DeploymentState::running;
   brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
   brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

   constexpr uint64_t service = 0x620450000001ULL;
   constexpr uint16_t initialPort = 19111;
   constexpr uint16_t invalidPort = 19404;

   ContainerView *advertiser = new ContainerView();
   advertiser->uuid = uint128_t(0x5408);
   advertiser->deploymentID = deployment.plan.config.deploymentID();
   advertiser->applicationID = deployment.plan.config.applicationID;
   advertiser->machine = &machine;
   advertiser->lifetime = ApplicationLifetime::base;
   advertiser->state = ContainerState::healthy;
   advertiser->fragment = 13;
   advertiser->createdAtMs = 123460;
   advertiser->remainingSubscriberCapacity = 64;
   advertiser->advertisements.insert_or_assign(
      service,
      Advertisement(service, ContainerState::scheduled, ContainerState::destroying, initialPort));
   advertiser->setMeshAddress(container_network_subnet6, brain.brainConfig.datacenterFragment, machine.fragment, advertiser->fragment);

   PairingTrackingContainerView subscriber = {};
   subscriber.applicationID = uint16_t(deployment.plan.config.applicationID + 1);
   subscriber.state = ContainerState::healthy;
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
   updatedSeed.advertisements.insert_or_assign(
      service,
      Advertisement(service, ContainerState::scheduled, ContainerState::destroying, invalidPort));
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
      subscriber.subscriptionActivateCalls == 0,
      "brain_neuron_state_upload_rejects_port_change_without_pairing_activate");
   suite.expect(
      subscriber.lastSubscriptionPort != invalidPort,
      "brain_neuron_state_upload_rejects_port_change_without_new_port");
   suite.expect(
      advertiser->advertisements.at(service).port == initialPort,
      "brain_neuron_state_upload_rejects_port_change_preserves_current_port");
   suite.expect(
      subscriber.subscriptionDeactivateCalls == 0,
      "brain_neuron_state_upload_rejects_port_change_without_deactivate");

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
   rack.uuid = 62041;

   Machine machine = {};
   machine.uuid = uint128_t(0x5403);
   machine.state = MachineState::healthy;
   machine.rack = &rack;
   machine.neuron.machine = &machine;
   brain.machines.insert(&machine);
   brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
   brain.neurons.insert(&machine.neuron);

   ApplicationDeployment deployment = {};
   deployment.plan = makeDeploymentPlan(62041, 1);
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
   rack.uuid = 62042;

   Machine machine = {};
   machine.uuid = uint128_t(0x5405);
   machine.state = MachineState::healthy;
   machine.rack = &rack;
   machine.neuron.machine = &machine;
   brain.machines.insert(&machine);
   brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
   brain.neurons.insert(&machine.neuron);

   ApplicationDeployment deployment = {};
   deployment.plan = makeDeploymentPlan(62042, 1);
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
   waiting->createdAtMs = 123459;
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
   healthySeed.createdAtMs = 123459;
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
   rack.uuid = 62040;

   Machine machine = {};
   machine.uuid = uint128_t(0x62040001);
   machine.private4 = 0x0a000040;
   machine.state = MachineState::deploying;
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

static void testMachineHealthySkipsScheduledStatelessDonorMoveUntilQuiescent(TestSuite& suite)
{
   TestBrain brain = {};
   NoopBrainIaaS iaas = {};
   brain.iaas = &iaas;
   brain.weAreMaster = true;

   Rack rack = {};
   rack.uuid = 62043;

   Machine donor = {};
   donor.uuid = uint128_t(0x62043001);
   donor.private4 = IPAddress("10.0.0.81", false).v4;
   donor.state = MachineState::healthy;
   donor.rack = &rack;
   donor.rackUUID = rack.uuid;
   donor.lifetime = MachineLifetime::ondemand;
   donor.nLogicalCores_available = 32;
   donor.memoryMB_available = 32768;
   donor.storageMB_available = 32768;

   Machine receiver = {};
   receiver.uuid = uint128_t(0x62043002);
   receiver.private4 = IPAddress("10.0.0.82", false).v4;
   receiver.state = MachineState::deploying;
   receiver.rack = &rack;
   receiver.rackUUID = rack.uuid;
   receiver.lifetime = MachineLifetime::owned;
   receiver.nLogicalCores_available = 32;
   receiver.memoryMB_available = 32768;
   receiver.storageMB_available = 32768;

   rack.machines.insert(&donor);
   rack.machines.insert(&receiver);
   brain.racks.insert_or_assign(rack.uuid, &rack);
   brain.machines.insert(&donor);
   brain.machines.insert(&receiver);

   ApplicationDeployment deployment = {};
   deployment.plan = makeDeploymentPlan(62043, 1);
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
   rack.uuid = 62044;

   Machine donor = {};
   donor.uuid = uint128_t(0x62044001);
   donor.private4 = IPAddress("10.0.0.91", false).v4;
   donor.state = MachineState::deploying;
   donor.rack = &rack;
   donor.rackUUID = rack.uuid;
   donor.lifetime = MachineLifetime::ondemand;
   donor.nLogicalCores_available = 32;
   donor.memoryMB_available = 32768;
   donor.storageMB_available = 32768;

   Machine receiver = {};
   receiver.uuid = uint128_t(0x62044002);
   receiver.private4 = IPAddress("10.0.0.92", false).v4;
   receiver.state = MachineState::healthy;
   receiver.rack = &rack;
   receiver.rackUUID = rack.uuid;
   receiver.lifetime = MachineLifetime::owned;
   receiver.nLogicalCores_available = 32;
   receiver.memoryMB_available = 32768;
   receiver.storageMB_available = 32768;

   rack.machines.insert(&donor);
   rack.machines.insert(&receiver);
   brain.racks.insert_or_assign(rack.uuid, &rack);
   brain.machines.insert(&donor);
   brain.machines.insert(&receiver);

   ApplicationDeployment deployment = {};
   deployment.plan = makeDeploymentPlan(62044, 1);
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
   rack.uuid = 62021;

   Machine machine = {};
   machine.uuid = uint128_t(0x5203);
   machine.state = MachineState::healthy;
   machine.rack = &rack;
   machine.neuron.machine = &machine;
   brain.machines.insert(&machine);
   brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
   brain.neurons.insert(&machine.neuron);

   ApplicationDeployment deployment = {};
   deployment.plan = makeDeploymentPlan(62021, 1);
   brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

   ContainerView *container = new ContainerView();
   container->uuid = uint128_t(0x5204);
   container->deploymentID = deployment.plan.config.deploymentID();
   container->machine = &machine;
   container->lifetime = ApplicationLifetime::base;
   container->state = ContainerState::healthy;

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
      beforeMs + 60000,
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
   rack.uuid = 62022;

   Machine machine = {};
   machine.uuid = uint128_t(0x5205);
   machine.state = MachineState::healthy;
   machine.rack = &rack;
   machine.neuron.machine = &machine;
   brain.machines.insert(&machine);
   brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

   ApplicationDeployment deployment = {};
   deployment.plan = makeDeploymentPlan(62022, 1);
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
      int64_t(1700000000001),
      int(11),
      "container crash"_ctv,
      true);
   brain.neuronHandler(&machine.neuron, message);

   suite.expect(container->state == ContainerState::crashedRestarting, "brain_neuron_container_failed_restart_marks_crashed_restarting");
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

static void testBrainNeuronHandlerRestartingContainerFailureRebalancesAnySubscribersWithoutDeadReplay(TestSuite& suite)
{
   TestBrain brain = {};
   NoopBrainIaaS iaas = {};
   brain.iaas = &iaas;
   brain.weAreMaster = true;

   BrainBase *previousBrain = thisBrain;
   thisBrain = &brain;

   Rack rackA = {};
   rackA.uuid = 62024;
   Rack rackB = {};
   rackB.uuid = 62025;

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
   deployment.plan = makeDeploymentPlan(62024, 1);
   deployment.state = DeploymentState::running;
   brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
   brain.deploymentsByApp.insert_or_assign(deployment.plan.config.applicationID, &deployment);

   constexpr uint64_t service = 0x620240000001ULL;
   constexpr uint16_t failedPort = 19111;
   constexpr uint16_t replacementPort = 19404;

   ContainerView *failedAdvertiser = new ContainerView();
   failedAdvertiser->uuid = uint128_t(0x5212);
   failedAdvertiser->deploymentID = deployment.plan.config.deploymentID();
   failedAdvertiser->applicationID = deployment.plan.config.applicationID;
   failedAdvertiser->machine = &machineA;
   failedAdvertiser->lifetime = ApplicationLifetime::base;
   failedAdvertiser->state = ContainerState::healthy;
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

   auto makeSubscriber = [&] (uint16_t applicationID, uint8_t fragment, uint128_t meshAddress) {
      PairingTrackingContainerView subscriber = {};
      subscriber.applicationID = applicationID;
      subscriber.state = ContainerState::healthy;
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
   brain.mesh->subscribe(service, &subscriberB, SubscriptionNature::any, false);
   brain.mesh->advertise(service, replacementAdvertiser, replacementPort, false);

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
      "brain_neuron_container_failed_restart_rebalance_fixture_retains_one_failed_pairing");
   suite.expect(
      stableSubscriber != nullptr && stableSubscriber->subscribedTo.hasEntryFor(service, replacementAdvertiser),
      "brain_neuron_container_failed_restart_rebalance_fixture_pairs_other_subscriber_to_replacement");

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
      int64_t(1700000000011),
      11,
      "container crash"_ctv,
      true);

   suite.expect(
      failedAdvertiser->state == ContainerState::crashedRestarting,
      "brain_neuron_container_failed_restart_rebalance_marks_crashed_restarting");
   suite.expect(
      migratingSubscriber->subscriptionDeactivateCalls == 1,
      "brain_neuron_container_failed_restart_rebalance_deactivates_failed_pairing");
   suite.expect(
      migratingSubscriber->subscriptionActivateCalls == 1,
      "brain_neuron_container_failed_restart_rebalance_activates_only_replacement");
   suite.expect(
      migratingSubscriber->lastSubscriptionAddress == replacementAdvertiser->pairingAddress(),
      "brain_neuron_container_failed_restart_rebalance_uses_replacement_address");
   suite.expect(
      migratingSubscriber->lastSubscriptionPort == replacementPort,
      "brain_neuron_container_failed_restart_rebalance_uses_replacement_port");
   suite.expect(
      migratingSubscriber->subscribedTo.hasEntryFor(service, failedAdvertiser) == false,
      "brain_neuron_container_failed_restart_rebalance_removes_failed_advertiser");
   suite.expect(
      migratingSubscriber->subscribedTo.hasEntryFor(service, replacementAdvertiser),
      "brain_neuron_container_failed_restart_rebalance_pairs_spare_advertiser");
   suite.expect(
      stableSubscriber->subscriptionDeactivateCalls == 0,
      "brain_neuron_container_failed_restart_rebalance_keeps_replacement_peer_active");
   suite.expect(
      stableSubscriber->subscriptionActivateCalls == 0,
      "brain_neuron_container_failed_restart_rebalance_avoids_duplicate_replacement_activation");

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
   rack.uuid = 62023;

   Machine machine = {};
   machine.uuid = uint128_t(0x5207);
   machine.state = MachineState::decommissioning;
   machine.rack = &rack;
   machine.neuron.machine = &machine;
   brain.machines.insert(&machine);
   brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

   ApplicationDeployment deployment = {};
   deployment.plan = makeDeploymentPlan(62023, 1);
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
      int64_t(1700000000002),
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
   rack.uuid = 62024;

   Machine machine = {};
   machine.uuid = uint128_t(0x5209);
   machine.state = MachineState::decommissioning;
   machine.rack = &rack;
   machine.neuron.machine = &machine;
   brain.machines.insert(&machine);
   brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);

   ApplicationDeployment deployment = {};
   deployment.plan = makeDeploymentPlan(62024, 1);
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
   String containerBlob = {};
   containerBlob.assign("brain-side-container-blob"_ctv);
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
   forEachMessageInBuffer(machine.neuron.wBuffer, [&] (Message *frame) {
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
      int64_t(1700000000003),
      "linux-6.10.0"_ctv,
      true);
   brain.neuronHandler(&machine.neuron, message);

   buffer.clear();
   buffer.assign("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"_ctv);

   suite.expect(machine.lastUpdatedOSMs == int64_t(1700000000003), "brain_neuron_registration_preserves_last_updated_os_ms");
   suite.expect(machine.kernel == "linux-6.10.0"_ctv, "brain_neuron_registration_preserves_kernel_text");
   suite.expect(machine.kernel.isInvariant() == false, "brain_neuron_registration_owns_kernel_text");

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
   machine.addresses.privateAddresses.push_back(ClusterMachineAddress{privateAddress, 0, {}});
   machine.addresses.publicAddresses.push_back(ClusterMachineAddress{publicAddress, 0, {}});
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
   hardware.collectedAtMs = 111222333;
   hardware.cpu.logicalCores = 2;
   hardware.memory.totalMB = 4096;
   MachineDiskHardwareProfile disk = {};
   disk.sizeMB = 20480;
   hardware.disks.push_back(disk);

   String serializedHardware = {};
   BitseryEngine::serialize(serializedHardware, hardware);

   String buffer = {};
   Message *message = buildNeuronMessage(buffer, NeuronTopic::machineHardwareProfile, serializedHardware);
   brain.neuronHandler(&machine.neuron, message);

   suite.expect(machine.hardware.inventoryComplete, "brain_neuron_hardware_inventory_complete");
   suite.expect(machine.hardware.collectedAtMs == 111222333, "brain_neuron_hardware_collected_at");
   suite.expect(machine.totalLogicalCores == 2, "brain_neuron_hardware_total_cores");
   suite.expect(machine.totalMemoryMB == 4096, "brain_neuron_hardware_total_memory");
   suite.expect(machine.totalStorageMB == 20480, "brain_neuron_hardware_total_storage");
   suite.expect(machine.state == MachineState::healthy, "brain_neuron_hardware_marks_healthy");
   suite.expect(brain.authoritativeTopology.machines.size() == 1
      && brain.authoritativeTopology.machines[0].hardware.inventoryComplete,
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
   hardware.collectedAtMs = 111222334;
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
   self.addresses.privateAddresses.push_back(ClusterMachineAddress{"10.128.0.63"_ctv, 0, {}});
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
   hardware.collectedAtMs = 123456;
   hardware.cpu.logicalCores = 4;
   hardware.memory.totalMB = 8192;
   MachineDiskHardwareProfile disk = {};
   disk.sizeMB = 40960;
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
      suite.expect(selfMachine->hardware.collectedAtMs == 123456, "mothership_replays_local_hardware_timestamp");
      suite.expect(selfMachine->totalLogicalCores == 4, "mothership_replays_local_hardware_cores");
      suite.expect(selfMachine->totalMemoryMB == 8192, "mothership_replays_local_hardware_memory");
      suite.expect(selfMachine->totalStorageMB == 40960, "mothership_replays_local_hardware_storage");
   }

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
   testBrainHandlerReplicationPaths(suite);
   testReconcileStateReplicatesCredentialAndTlsState(suite);
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
   testManagedMachineSchemaRequestMatchesExistingSeedWithoutKind(suite);
   testMachineSchemaMutationsDriveManagedBudgetActions(suite);
   testReplicatedBrainConfigReplaysFullSwitchboardState(suite);
   testSwitchboardStateSyncReplaysWhiteholes(suite);
   testQuicWormholeStateRefreshReplaysToNeuronsFollowersAndContainers(suite);
   testQuicWormholeRotationAndNoopPaths(suite);
   testRegisteredRoutableAddressRefreshReplaysToNeuronsFollowersAndContainers(suite);
   testRegisteredRoutableAddressWormholesRefreshHostedIngressBeforeOpen(suite);
   testApplyReplicatedDeploymentPlanLiveStateUpdatesTrackedContainers(suite);
   testUpdateSelfBundleEchoTransitionsFollowersAndQueuesTransition(suite);
   testUpdateSelfPeerRegistrationCreditsBootNsChange(suite);
   testUpdateSelfPeerRegistrationCreditsReconnectWithoutBootNsChange(suite);
   testMaybeRelinquishMasterSelectsLowestPeerKey(suite);
   testPersistentMasterAuthorityPackageRestore(suite);
   testResumePendingAddMachinesOperations(suite);
   testResumePendingAddMachinesRefreshesProvisionalCreatedMachine(suite);
   testResumePendingAddMachinesOperationFailureRetainsJournal(suite);
   testSuspendableAddMachinesStreamsCreatedBootstrapDuringSpin(suite);
   testReconcileManagedMachineSchemasSkipsEmptySchemaState(suite);
   testImportedTlsFactoryValidationRejectsBrokenPem(suite);
   testImportedTlsFactoryEnablesBundleBuild(suite);
   testRegisterRoutableAddressSkipsZeroUUIDHostedMachines(suite);
   testRegisterRoutableAddressUsesPublicPeerCandidateWhenMachineFieldIsEmpty(suite);
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
   testBrainNeuronHandlerRestartingContainerFailureRebalancesAnySubscribersWithoutDeadReplay(suite);
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
   testNeuronContainerHandlerForwardsRuntimeReadyToBrainWithActiveBrainStream(suite);
   testNeuronContainerHandlerMarksMasterLocalContainerHealthyWithActiveBrainStream(suite);
   testNeuronContainerHandlerMarksMasterLocalContainerRuntimeReadyWithActiveBrainStream(suite);
   testNeuronContainerHandlerForwardsStatisticsToBrain(suite);
   testNeuronHandlerStoresRequestedContainerBlob(suite);
   testNeuronHandlerKillContainerStopsContainerAndEchoesBrain(suite);
   testBrainNeuronHandlerMarksContainerHealthyOnceAndClearsWaiters(suite);
   testBrainReplicatedContainerHealthyMarksContainerHealthyOnMaster(suite);
   testBrainNeuronHandlerHealthyReplacementPointerClearsEquivalentWaiter(suite);
   testBrainNeuronStateUploadRemovesStaleCanonicalMachineContainer(suite);
   testBrainNeuronStateUploadHealthyContainerClearsWaiters(suite);
   testBrainNeuronStateUploadRestoresOnlyActiveMeshServices(suite);
   testBrainNeuronStateUploadRejectsHealthyAdvertiserPortChange(suite);
   testBrainNeuronStateUploadHealthyReplacementPointerClearsEquivalentWaiter(suite);
   testMachineHealthyClaimWakePreservesTicketOutstandingCount(suite);
   testMachineHealthySkipsScheduledStatelessDonorMoveUntilQuiescent(suite);
   testDrainMachineSkipsScheduledLiveRedeployUntilHealthy(suite);
   testBrainNeuronHandlerRecordsContainerStatisticsAndReplicates(suite);
   testBrainNeuronHandlerHandlesRestartingContainerFailure(suite);
   testBrainNeuronHandlerHandlesNonRestartingContainerFailureAndDrainsMachine(suite);
   testBrainNeuronHandlerProcessesKillContainerAckAndDrainsMachine(suite);
   testBrainNeuronHandlerQueuesRequestedContainerBlob(suite);
   testBrainNeuronHandlerOwnsRegistrationKernelString(suite);
   testBrainNeuronHandlerReportsHardwareFailureAndDecommissionsMachine(suite);
   testBrainMachineStateMissingEscalatesWhenSshBudgetExhausted(suite);
   testBrainSoftEscalationTimeoutPromotesMachineToHardReboot(suite);
   testBrainHardRebootTimeoutMarksHardwareFailureAndDecommissionsMachine(suite);
   testBrainNeuronHandlerAppliesMachineHardwareProfile(suite);
   testBrainIgnitionRequiresNeuronControlBeforeHealthy(suite);
   testBrainHealthyRequiresInventoryAndFragment(suite);
   testBrainNeuronHandlerClosesOnInvalidMachineHardwareProfile(suite);
   testBrainNeuronHandlerClosesOnIncompleteMachineHardwareProfile(suite);
   testMothershipHandlerReplaysReadyLocalHardwareProfile(suite);

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
