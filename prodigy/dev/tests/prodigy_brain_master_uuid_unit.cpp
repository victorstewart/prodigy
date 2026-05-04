#include <prodigy/prodigy.h>
#include <services/debug.h>
#include <prodigy/brain/brain.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <sys/socket.h>
#include <sys/un.h>
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
         std::fprintf(stderr, "FAIL: %s\n", name);
         std::fflush(stderr);
         failed += 1;
      }
   }
};

static void testSigchldHandler(int, siginfo_t *, void *)
{
}

class ScopedSigchldAction
{
public:

   struct sigaction previous = {};
   bool valid = false;

   ScopedSigchldAction(void)
   {
      valid = sigaction(SIGCHLD, nullptr, &previous) == 0;
   }

   ~ScopedSigchldAction()
   {
      if (valid)
      {
         sigaction(SIGCHLD, &previous, nullptr);
      }
   }
};

static bool testSigchldIsDefaultWaitable(void)
{
   struct sigaction action = {};
   if (sigaction(SIGCHLD, nullptr, &action) != 0)
   {
      return false;
   }

   return prodigySigchldIsDefaultWaitable(action);
}

class TestNeuron final : public NeuronBase
{
public:

   void pushContainer(Container *container) override
   {
      (void)container;
   }

   void popContainer(Container *container) override
   {
      (void)container;
   }

   void downloadContainer(CoroutineStack *coro, uint64_t deploymentID) override
   {
      (void)coro;
      (void)deploymentID;
   }

   bool ensureHostNetworkingReady(String *failureReport = nullptr) override
   {
      if (failureReport)
      {
         failureReport->clear();
      }
      return true;
   }
};

class TestBrain final : public Brain
{
public:
   uint32_t persistCalls = 0;
   uint32_t metroReachabilityChecks = 0;
   bool overrideMetroReachabilityCheck = false;
   bool forcedConnectedMajorityAfterMetroCheck = false;
   bool forcedReachableSwitchMajority = false;
   uint32_t neuronControlInstallFromBrainCalls = 0;
   bool overrideNeuronControlInstallFromBrain = false;
   bool forcedNeuronControlInstallFromBrain = false;
   uint32_t armMachineNeuronControlCalls = 0;
   bool observedNeuronRegisteredBeforeArm = true;
   bool overrideArmMachineNeuronControl = false;
   uint32_t selfElectionMachineInventoryAwaitCalls = 0;
   bool overrideSelfElectionMachineInventoryAwait = false;
   uint32_t selfElectionManagedSchemaReconcileCalls = 0;
   bool overrideSelfElectionManagedSchemaReconcile = false;
   bool forcedSelfElectionManagedSchemaReconcile = true;
   String forcedSelfElectionManagedSchemaReconcileFailure = {};

   bool testActiveBrainRegistrationsReadyForMasterElection(void)
   {
      return activeBrainRegistrationsReadyForMasterElection();
   }

   bool testResolveFailoverMasterByActivePeerAddressOrder(bool& preferSelf, bool *sawActivePeer = nullptr)
   {
      return resolveFailoverMasterByActivePeerAddressOrder(preferSelf, sawActivePeer);
   }

   bool testShouldReconnectNeuronControl(NeuronView *neuron) const
   {
      return shouldReconnectNeuronControl(neuron);
   }

   void testDisarmNeuronControlReconnect(NeuronView *neuron)
   {
      disarmNeuronControlReconnect(neuron);
   }

   void testAbandonPeerSocketGeneration(BrainView *peer)
   {
      abandonSocketGeneration(peer);
   }

   void testArmOutboundPeerReconnect(BrainView *peer, bool forceConnectorOwnership = false)
   {
      armOutboundPeerReconnect(peer, forceConnectorOwnership);
   }

   bool testShouldRetainMasterControlOnBrainLoss(void)
   {
      return shouldRetainMasterControlOnBrainLoss();
   }

   bool testShouldWeConnectToBrain(const BrainView *brain) const
   {
      return shouldWeConnectToBrain(brain);
   }

   bool testShouldReplaceActivePeerWithAcceptedStream(BrainView *brain, bool expectedUpdateFollowerReconnect) const
   {
      return shouldReplaceActivePeerWithAcceptedStream(brain, expectedUpdateFollowerReconnect);
   }

	   bool testSelfElectAsMaster(const char *reason = "unit-test", bool replaceLiveMothershipListener = false)
	   {
	      return selfElectAsMaster(reason, replaceLiveMothershipListener);
	   }

	   void testSpinApplication(ApplicationDeployment *deployment)
	   {
	      spinApplication(deployment);
	   }

      void testHandleMachineStateChange(Machine *machine, MachineState state)
      {
         handleMachineStateChange(machine, state);
      }

	   void testElectBrainToMaster(BrainView *brain)
	   {
	      electBrainToMaster(brain);
	   }

   void testDeriveMasterBrain(bool allowExistingMasterClaims = true)
   {
      deriveMasterBrain(allowExistingMasterClaims);
   }

   void testDeriveMasterBrainIf(void)
   {
      deriveMasterBrainIf();
   }

   void testBrainHandler(BrainView *brain, Message *message)
   {
      brainHandler(brain, message);
   }

   void testBrainMissing(BrainView *brain)
   {
      brainMissing(brain);
   }

   void testBrainFound(BrainView *brain)
   {
      brainFound(brain);
   }

   void testInitializeBrainPeerIfNeeded(BrainView *brain)
   {
      initializeBrainPeerIfNeeded(brain);
   }

   void testInitializeAllBrainPeersIfNeeded(void)
   {
      initializeAllBrainPeersIfNeeded();
   }

   bool testInstallBrainPeerSocket(BrainView *brain)
   {
      return installBrainPeerSocket(brain);
   }

   uint128_t testGetExistingMasterUUID(void) const
   {
      return getExistingMasterUUID();
   }

   uint128_t testUpdateSelfPeerTrackingKey(const BrainView *brain) const
   {
      return updateSelfPeerTrackingKey(brain);
   }

   void testCloseHandler(void *socket)
   {
      closeHandler(socket);
   }

   void testRecvHandler(void *socket, int result)
   {
      recvHandler(socket, result);
   }

   void testDestroyIdleMothershipStreamNow(Mothership *stream, const char *reason = "unit-test")
   {
      destroyIdleMothershipStreamNow(stream, reason);
   }

   void testConnectHandler(void *socket, int result)
   {
      connectHandler(socket, result);
   }

   void testNeuronHandler(NeuronView *neuron, Message *message)
   {
      neuronHandler(neuron, message);
   }

   void testDispatchTimeout(TimeoutPacket *packet)
   {
      dispatchTimeout(packet);
   }

   void testRunBrainPeerHeartbeatTick(void)
   {
      runBrainPeerHeartbeatTick();
   }

   void testAcceptHandler(void *socket, int fslot)
   {
      acceptHandler(socket, fslot);
   }

   bool testRestoreMachinesFromClusterTopology(const ClusterTopology& topology)
   {
      return restoreMachinesFromClusterTopology(topology);
   }

   Machine *testFindMachineByUUID(uint128_t uuid) const
   {
      return findMachineByUUID(uuid);
   }

   bool testArmMothershipUnixListener(bool replaceLiveListener = false)
   {
      return armMothershipUnixListener(replaceLiveListener);
   }

   bool testMothershipUnixSocketPathOwnedByLocalListener(void)
   {
      return mothershipUnixSocketPathOwnedByLocalListener();
   }

   void testUnlinkMothershipUnixSocketPath(const char *reason, bool requireLocalOwnership = true)
   {
      unlinkMothershipUnixSocketPath(reason, requireLocalOwnership);
   }

   bool testMothershipUnixListenerActive(void) const
   {
      if (mothershipUnixSocket.isFixedFile)
      {
         return mothershipUnixSocket.fslot >= 0;
      }

      return mothershipUnixSocket.fd >= 0;
   }

   void testRegisterActiveMothership(Mothership *stream)
   {
      mothership = stream;
      if (stream != nullptr)
      {
         activeMotherships.insert(stream);
      }
   }

   size_t testActiveMothershipCount(void) const
   {
      return activeMotherships.size();
   }

   bool testContainsActiveMothership(Mothership *stream) const
   {
      return activeMotherships.contains(stream);
   }

   Mothership *testCurrentMothership(void) const
   {
      return mothership;
   }

   bool testHasBrainWaiter(BrainView *brain) const
   {
      return brainWaiters.contains(brain);
   }

   TimeoutPacket *testGetBrainWaiter(BrainView *brain) const
   {
      if (auto it = brainWaiters.find(brain); it != brainWaiters.end())
      {
         return it->second;
      }

      return nullptr;
   }

   bool testHasBrainReconnectWaiter(BrainView *brain) const
   {
      return brainReconnectWaiters.contains(brain);
   }

   TimeoutPacket *testGetBrainReconnectWaiter(BrainView *brain) const
   {
      if (auto it = brainReconnectWaiters.find(brain); it != brainReconnectWaiters.end())
      {
         return it->second;
      }

      return nullptr;
   }

   bool testHasBrainLivenessWaiter(BrainView *brain) const
   {
      return brainLivenessWaiters.contains(brain);
   }

   TimeoutPacket *testGetBrainLivenessWaiter(BrainView *brain) const
   {
      if (auto it = brainLivenessWaiters.find(brain); it != brainLivenessWaiters.end())
      {
         return it->second;
      }

      return nullptr;
   }

   bool testHasNeuronReconnectWaiter(NeuronView *neuron) const
   {
      return neuronReconnectWaiters.contains(neuron);
   }

   TimeoutPacket *testGetNeuronReconnectWaiter(NeuronView *neuron) const
   {
      if (auto it = neuronReconnectWaiters.find(neuron); it != neuronReconnectWaiters.end())
      {
         return it->second;
      }

      return nullptr;
   }

   void testEraseNeuronReconnectWaiter(NeuronView *neuron)
   {
      if (auto it = neuronReconnectWaiters.find(neuron); it != neuronReconnectWaiters.end())
      {
         delete it->second;
         neuronReconnectWaiters.erase(it);
      }
   }

   void testRefreshMasterPeerLivenessWaiter(BrainView *brain, const char *reason = "unit-test")
   {
      refreshMasterPeerLivenessWaiter(brain, reason);
   }

   void testCancelBrainLivenessWaiter(BrainView *brain, const char *reason = "unit-test")
   {
      cancelBrainLivenessWaiter(brain, reason);
   }

   TimeoutPacket *testInsertBrainLivenessWaiter(BrainView *brain)
   {
      TimeoutPacket *timeout = new TimeoutPacket();
      timeout->flags = uint64_t(BrainTimeoutFlags::brainPeerLiveness);
      timeout->originator = brain;
      timeout->dispatcher = this;
      brainLivenessWaiters.insert_or_assign(brain, timeout);
      return timeout;
   }

   void testEraseBrainLivenessWaiter(BrainView *brain)
   {
      if (auto it = brainLivenessWaiters.find(brain); it != brainLivenessWaiters.end())
      {
         delete it->second;
         brainLivenessWaiters.erase(it);
      }
   }

   void testEraseBrainReconnectWaiter(BrainView *brain)
   {
      if (auto it = brainReconnectWaiters.find(brain); it != brainReconnectWaiters.end())
      {
         delete it->second;
         brainReconnectWaiters.erase(it);
      }
   }

   void testInsertBrainWaiter(BrainView *brain)
   {
      TimeoutPacket *timeout = new TimeoutPacket();
      timeout->originator = brain;
      timeout->dispatcher = this;
      brainWaiters.insert_or_assign(brain, timeout);
   }

   void testEraseBrainWaiter(BrainView *brain)
   {
      if (auto it = brainWaiters.find(brain); it != brainWaiters.end())
      {
         delete it->second;
         brainWaiters.erase(it);
      }
   }

   void configureCloudflareTunnel(String& mothershipEndpoint) override
   {
      mothershipEndpoint.clear();
   }

   void teardownCloudflareTunnel(void) override
   {
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

   void checkMetroReachabilityForMasterFailover(bool& connectedMajority, bool& reachableSwitchMajority) override
   {
      metroReachabilityChecks += 1;
      if (overrideMetroReachabilityCheck)
      {
         connectedMajority = forcedConnectedMajorityAfterMetroCheck;
         reachableSwitchMajority = forcedReachableSwitchMajority;
         return;
      }

      Brain::checkMetroReachabilityForMasterFailover(connectedMajority, reachableSwitchMajority);
   }

protected:

   void armMachineNeuronControl(Machine *machine) override
   {
      armMachineNeuronControlCalls += 1;
      observedNeuronRegisteredBeforeArm = observedNeuronRegisteredBeforeArm
         && machine != nullptr
         && neurons.contains(&machine->neuron);

      if (overrideArmMachineNeuronControl)
      {
         return;
      }

      Brain::armMachineNeuronControl(machine);
   }

   bool installNeuronControlSocketFromBrain(NeuronView *neuron) override
   {
      neuronControlInstallFromBrainCalls += 1;
      if (overrideNeuronControlInstallFromBrain)
      {
         if (forcedNeuronControlInstallFromBrain && neuron != nullptr)
         {
            neuron->setIPVersion(AF_INET);
            neuron->setDaddr(IPAddress("127.0.0.1", false), uint16_t(ReservedPorts::neuron));
            if (neuron->isNonBlocking == false)
            {
               neuron->setNonBlocking();
            }
         }

         return forcedNeuronControlInstallFromBrain;
      }

      return Brain::installNeuronControlSocketFromBrain(neuron);
   }

   void awaitSelfElectionMachineInventoryIfNeeded(CoroutineStack *coro, uint32_t suspendIndex) override
   {
      if (overrideSelfElectionMachineInventoryAwait && coro != nullptr && suspendIndex < coro->nextSuspendIndex())
      {
         selfElectionMachineInventoryAwaitCalls += 1;
         coro->co_consume();
         return;
      }

      Brain::awaitSelfElectionMachineInventoryIfNeeded(coro, suspendIndex);
   }

   bool reconcileManagedMachineSchemasOnSelfElection(String *failure) override
   {
      selfElectionManagedSchemaReconcileCalls += 1;
      if (overrideSelfElectionManagedSchemaReconcile)
      {
         if (failure != nullptr)
         {
            failure->assign(forcedSelfElectionManagedSchemaReconcileFailure);
         }
         return forcedSelfElectionManagedSchemaReconcile;
      }

      return Brain::reconcileManagedMachineSchemasOnSelfElection(failure);
   }
};

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

static void suspendAndPopulateMachines(CoroutineStack& coro, bytell_hash_set<Machine *>& machines, Machine *machine, bool *resumed)
{
   co_await coro.suspend();

   if (machine != nullptr)
   {
      machines.insert(machine);
   }

   if (resumed != nullptr)
   {
      *resumed = true;
   }
}

class SuspendedGetMachinesBrainIaaS final : public NoopBrainIaaS
{
public:
   Machine *machineToPublish = nullptr;
   bool resumedAfterSuspend = false;
   uint32_t getMachinesCalls = 0;

   void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines) override
   {
      (void)metro;
      getMachinesCalls += 1;

      if (coro == nullptr)
      {
         if (machineToPublish != nullptr)
         {
            machines.insert(machineToPublish);
         }
         return;
      }

      suspendAndPopulateMachines(*coro, machines, machineToPublish, &resumedAfterSuspend);
   }
};

static BrainView *makePeer(uint128_t uuid, int64_t boottimens, uint32_t private4 = 0, const char *peerAddressText = nullptr)
{
   BrainView *peer = new BrainView();
   peer->uuid = uuid;
   peer->boottimens = boottimens;
   peer->registrationFresh = (uuid != 0 && boottimens != 0);
   peer->private4 = private4;
   if (peerAddressText != nullptr)
   {
      peer->peerAddress = IPAddress(peerAddressText, std::strchr(peerAddressText, ':') != nullptr);
      peer->peerAddressText.assign(peerAddressText);
   }
   return peer;
}

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

template <typename... Args>
static Message *buildBrainMessage(String& buffer, BrainTopic topic, Args&&... args)
{
   buffer.clear();
   if (topic == BrainTopic::registration)
   {
      Message::construct(buffer, topic, std::forward<Args>(args)..., "test-kernel"_ctv, "portablelinux"_ctv, "1"_ctv);
   }
   else
   {
      Message::construct(buffer, topic, std::forward<Args>(args)...);
   }
   return reinterpret_cast<Message *>(buffer.data());
}

template <typename... Args>
static Message *buildNeuronMessage(String& buffer, NeuronTopic topic, Args&&... args)
{
   buffer.clear();
   Message::construct(buffer, topic, std::forward<Args>(args)...);
   return reinterpret_cast<Message *>(buffer.data());
}

template <typename... Args>
static Message *buildBrainEcho(String& buffer, BrainTopic topic, Args&&... args)
{
   buffer.clear();
   Message::appendEcho(buffer, topic, std::forward<Args>(args)...);
   return reinterpret_cast<Message *>(buffer.data());
}

static DeploymentPlan makeDeploymentPlan(uint16_t applicationID, uint64_t versionID)
{
   DeploymentPlan plan = {};
   plan.config.type = ApplicationType::stateless;
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
   plan.stateless.nBase = 1;
   plan.stateless.maxPerRackRatio = 1.0f;
   plan.stateless.maxPerMachineRatio = 1.0f;
   plan.canaryCount = 1;
   plan.canariesMustLiveForMinutes = 5;
   plan.moveConstructively = true;
   return plan;
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

int main(void)
{
   TestSuite suite;

   TestNeuron neuron = {};
   neuron.uuid = uint128_t(0x100);
   neuron.private4 = IPAddress("10.0.0.10", false);
   thisNeuron = &neuron;

   suite.expect(prodigyBrainPeerHeartbeatTimeoutMs <= 5000u, "timing_knobs_bound_production_master_stale_detection");
   suite.expect(prodigyBrainDevPeerHeartbeatTimeoutMs <= 5000u, "timing_knobs_bound_dev_master_stale_detection");
   suite.expect(prodigyBrainPeerHeartbeatTimeoutMs >= prodigyBrainPeerHeartbeatIntervalMs * 3u, "timing_knobs_production_allows_multiple_missed_heartbeats");
   suite.expect(prodigyBrainDevPeerHeartbeatTimeoutMs >= prodigyBrainDevPeerHeartbeatIntervalMs * 3u, "timing_knobs_dev_allows_multiple_missed_heartbeats");

   {
      ScopedSigchldAction restore = {};

      struct sigaction custom = {};
      sigemptyset(&custom.sa_mask);
      custom.sa_sigaction = testSigchldHandler;
      custom.sa_flags = SA_SIGINFO;
      sigaction(SIGCHLD, &custom, nullptr);

      suite.expect(prodigyEnsureSigchldDefaultWaitable(), "sigchld_policy_repairs_custom_handler");
      suite.expect(testSigchldIsDefaultWaitable(), "sigchld_policy_custom_handler_becomes_default_waitable");
   }

   {
      ScopedSigchldAction restore = {};

      struct sigaction noChildWait = {};
      sigemptyset(&noChildWait.sa_mask);
      noChildWait.sa_handler = SIG_DFL;
      noChildWait.sa_flags = SA_NOCLDWAIT;
      sigaction(SIGCHLD, &noChildWait, nullptr);

      suite.expect(prodigyEnsureSigchldDefaultWaitable(), "sigchld_policy_repairs_no_child_wait");
      suite.expect(testSigchldIsDefaultWaitable(), "sigchld_policy_no_child_wait_becomes_default_waitable");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      brain.testInitializeBrainPeerIfNeeded(nullptr);
      suite.expect(true, "initialize_brain_peer_accepts_null_pointer");

      BrainView missingIdentity = {};
      brain.testInitializeBrainPeerIfNeeded(&missingIdentity);
      suite.expect(missingIdentity.connectTimeoutMs == 0, "initialize_brain_peer_missing_identity_leaves_timeout_unchanged");
      suite.expect(brain.testHasBrainWaiter(&missingIdentity) == false, "initialize_brain_peer_missing_identity_does_not_arm_waiter");

      suite.expect(Ring::getRingFD() <= 0, "initialize_brain_peer_ring_inactive_precondition");
      BrainView ringInactive = {};
      ringInactive.private4 = IPAddress("10.0.0.20", false).v4;
      brain.testInitializeBrainPeerIfNeeded(&ringInactive);
      suite.expect(ringInactive.connectTimeoutMs == 0, "initialize_brain_peer_ring_inactive_leaves_timeout_unchanged");
      suite.expect(brain.testHasBrainWaiter(&ringInactive) == false, "initialize_brain_peer_ring_inactive_does_not_arm_waiter");
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView connectedPeer = {};
      connectedPeer.private4 = IPAddress("10.0.0.21", false).v4;
      connectedPeer.connected = true;
      brain.testInitializeBrainPeerIfNeeded(&connectedPeer);
      suite.expect(connectedPeer.connectTimeoutMs == BrainBase::controlPlaneConnectTimeoutMs(BrainBase::controlPlaneDevModeEnabled()), "initialize_brain_peer_connected_configures_timeout_before_skip");
      suite.expect(connectedPeer.nDefaultAttemptsBudget == BrainBase::controlPlaneConnectAttemptsBudget(BrainBase::controlPlaneDevModeEnabled()), "initialize_brain_peer_connected_configures_attempt_budget_before_skip");
      suite.expect(brain.testHasBrainWaiter(&connectedPeer) == false, "initialize_brain_peer_connected_does_not_arm_waiter");

      BrainView waiterPeer = {};
      waiterPeer.private4 = IPAddress("10.0.0.22", false).v4;
      brain.testInsertBrainWaiter(&waiterPeer);
      brain.testInitializeBrainPeerIfNeeded(&waiterPeer);
      suite.expect(brain.testHasBrainWaiter(&waiterPeer), "initialize_brain_peer_waiter_active_preserves_waiter");
      suite.expect(waiterPeer.connectTimeoutMs == BrainBase::controlPlaneConnectTimeoutMs(BrainBase::controlPlaneDevModeEnabled()), "initialize_brain_peer_waiter_active_configures_timeout_before_skip");
      brain.testEraseBrainWaiter(&waiterPeer);

      BrainView fixedFilePeer = {};
      fixedFilePeer.private4 = IPAddress("10.0.0.23", false).v4;
      fixedFilePeer.isFixedFile = true;
      fixedFilePeer.fslot = 7;
      brain.testInitializeBrainPeerIfNeeded(&fixedFilePeer);
      suite.expect(fixedFilePeer.connectTimeoutMs == BrainBase::controlPlaneConnectTimeoutMs(BrainBase::controlPlaneDevModeEnabled()), "initialize_brain_peer_fixedfile_present_configures_timeout_before_skip");
      suite.expect(fixedFilePeer.fslot == 7, "initialize_brain_peer_fixedfile_present_preserves_slot");

      BrainView fdPeer = {};
      fdPeer.private4 = IPAddress("10.0.0.24", false).v4;
      fdPeer.fd = 11;
      brain.testInitializeBrainPeerIfNeeded(&fdPeer);
      suite.expect(fdPeer.connectTimeoutMs == BrainBase::controlPlaneConnectTimeoutMs(BrainBase::controlPlaneDevModeEnabled()), "initialize_brain_peer_fd_present_configures_timeout_before_skip");
      suite.expect(fdPeer.fd == 11, "initialize_brain_peer_fd_present_preserves_fd");

      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;
      brain.localBrainPeerAddresses.push_back(ClusterMachinePeerAddress{"10.0.0.10"_ctv, 24});

      BrainView connectPeer = {};
      connectPeer.private4 = IPAddress("10.0.0.20", false).v4;
      connectPeer.peerAddresses.push_back(ClusterMachinePeerAddress{"10.0.0.20"_ctv, 24});
      brain.testInitializeBrainPeerIfNeeded(&connectPeer);
      suite.expect(connectPeer.weConnectToIt, "initialize_brain_peer_connect_path_marks_connector_ownership");
      suite.expect(connectPeer.daddrLen > 0, "initialize_brain_peer_connect_path_configures_destination");
      suite.expect(connectPeer.fd == -1, "initialize_brain_peer_connect_path_closes_failed_process_fd");
      suite.expect(brain.testHasBrainReconnectWaiter(&connectPeer), "initialize_brain_peer_connect_path_arms_reconnect_on_install_failure");
      suite.expect(brain.testHasBrainWaiter(&connectPeer) == false, "initialize_brain_peer_connect_path_does_not_arm_missing_waiter_on_install_failure");
      brain.testEraseBrainReconnectWaiter(&connectPeer);

      BrainView waitPeer = {};
      waitPeer.private4 = IPAddress("10.0.0.5", false).v4;
      brain.testInitializeBrainPeerIfNeeded(&waitPeer);
      suite.expect(waitPeer.weConnectToIt == false, "initialize_brain_peer_wait_path_marks_non_connector");
      suite.expect(brain.testHasBrainWaiter(&waitPeer), "initialize_brain_peer_wait_path_arms_waiter");
      brain.testEraseBrainWaiter(&waitPeer);

      BrainView allInitConnected = {};
      allInitConnected.private4 = IPAddress("10.0.0.31", false).v4;
      allInitConnected.connected = true;
      BrainView allInitFixed = {};
      allInitFixed.private4 = IPAddress("10.0.0.32", false).v4;
      allInitFixed.isFixedFile = true;
      allInitFixed.fslot = 9;
      brain.brains.insert(&allInitConnected);
      brain.brains.insert(&allInitFixed);
      brain.testInitializeAllBrainPeersIfNeeded();
      suite.expect(allInitConnected.connectTimeoutMs == BrainBase::controlPlaneConnectTimeoutMs(BrainBase::controlPlaneDevModeEnabled()), "initialize_all_brain_peers_configures_connected_peer");
      suite.expect(allInitFixed.connectTimeoutMs == BrainBase::controlPlaneConnectTimeoutMs(BrainBase::controlPlaneDevModeEnabled()), "initialize_all_brain_peers_configures_fixedfile_peer");
      brain.brains.erase(&allInitConnected);
      brain.brains.erase(&allInitFixed);

      int noDaddrSockets[2] = {-1, -1};
      suite.expect(::socketpair(AF_UNIX, SOCK_STREAM, 0, noDaddrSockets) == 0, "install_brain_peer_socket_no_daddr_socketpair");
      if (noDaddrSockets[0] >= 0 && noDaddrSockets[1] >= 0)
      {
         BrainView noDaddrPeer = {};
         noDaddrPeer.fd = noDaddrSockets[0];
         suite.expect(brain.testInstallBrainPeerSocket(&noDaddrPeer) == false, "install_brain_peer_socket_rejects_missing_destination");
         ::close(noDaddrSockets[0]);
         ::close(noDaddrSockets[1]);
      }

      int bindFailSockets[2] = {-1, -1};
      suite.expect(::socketpair(AF_UNIX, SOCK_STREAM, 0, bindFailSockets) == 0, "install_brain_peer_socket_bind_fail_socketpair");
      if (bindFailSockets[0] >= 0 && bindFailSockets[1] >= 0)
      {
         BrainView bindFailPeer = {};
         bindFailPeer.fd = bindFailSockets[0];
         bindFailPeer.setSaddr(IPAddress("203.0.113.10", false));
         bindFailPeer.setDaddr(IPAddress("10.0.0.20", false), uint16_t(ReservedPorts::brain));
         suite.expect(brain.testInstallBrainPeerSocket(&bindFailPeer) == false, "install_brain_peer_socket_rejects_source_bind_failure");
         suite.expect(bindFailPeer.fd == -1, "install_brain_peer_socket_closes_fd_on_source_bind_failure");
         ::close(bindFailSockets[1]);
      }

      Vector<ClusterMachinePeerAddress> invalidLocalCandidates = {};
      invalidLocalCandidates.push_back(ClusterMachinePeerAddress{"not-an-ip"_ctv, 0});

      brain.localBrainPeerAddresses = invalidLocalCandidates;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      BrainView fallbackAddressOrder = {};
      fallbackAddressOrder.peerAddress = IPAddress("10.0.0.20", false);
      suite.expect(brain.testShouldWeConnectToBrain(&fallbackAddressOrder), "should_we_connect_to_brain_falls_back_to_local_and_peer_address_order");

      brain.localBrainPeerAddresses = invalidLocalCandidates;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      BrainView fallbackPrivate4Order = {};
      fallbackPrivate4Order.private4 = IPAddress("10.0.0.20", false).v4;
      suite.expect(brain.testShouldWeConnectToBrain(&fallbackPrivate4Order), "should_we_connect_to_brain_falls_back_to_peer_private4_when_peer_address_missing");

      brain.localBrainPeerAddresses = invalidLocalCandidates;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      BrainView fallbackUuidOrder = {};
      fallbackUuidOrder.peerAddress = IPAddress("10.0.0.10", false);
      fallbackUuidOrder.uuid = uint128_t(0x200);
      suite.expect(brain.testShouldWeConnectToBrain(&fallbackUuidOrder), "should_we_connect_to_brain_falls_back_to_uuid_when_addresses_tie");

      brain.localBrainPeerAddresses = invalidLocalCandidates;
      brain.localBrainPeerAddress = {};
      BrainView fallbackFalse = {};
      fallbackFalse.uuid = neuron.uuid;
      suite.expect(brain.testShouldWeConnectToBrain(&fallbackFalse) == false, "should_we_connect_to_brain_returns_false_when_no_address_or_uuid_tiebreaker_applies");

      Vector<ClusterMachinePeerAddress> ipv6OnlyCandidates = {};
      ipv6OnlyCandidates.push_back(ClusterMachinePeerAddress{"2001:db8::1"_ctv, 0});
      brain.localBrainPeerAddresses = ipv6OnlyCandidates;
      brain.localBrainPeerAddress = {};
      BrainView familyMismatchFalse = {};
      familyMismatchFalse.peerAddress = IPAddress("10.0.0.20", false);
      familyMismatchFalse.uuid = neuron.uuid;
      suite.expect(brain.testShouldWeConnectToBrain(&familyMismatchFalse), "should_we_connect_to_brain_skips_mismatched_local_candidate_family_and_falls_back_to_neuron_private4");

      Vector<ClusterMachinePeerAddress> tiedPreferredCandidates = {};
      tiedPreferredCandidates.push_back(ClusterMachinePeerAddress{"10.0.0.20"_ctv, 24});
      tiedPreferredCandidates.push_back(ClusterMachinePeerAddress{"10.0.0.10"_ctv, 24});
      brain.localBrainPeerAddresses = tiedPreferredCandidates;
      brain.localBrainPeerAddress = {};
      BrainView sameFamilyLowerFallback = {};
      sameFamilyLowerFallback.peerAddress = IPAddress("10.0.0.20", false);
      suite.expect(brain.testShouldWeConnectToBrain(&sameFamilyLowerFallback), "should_we_connect_to_brain_uses_later_same_family_candidate_when_preferred_source_ties");

      tiedPreferredCandidates[1].address = "10.0.0.30"_ctv;
      brain.localBrainPeerAddresses = tiedPreferredCandidates;
      BrainView sameFamilyHigherFallback = {};
      sameFamilyHigherFallback.peerAddress = IPAddress("10.0.0.20", false);
      suite.expect(brain.testShouldWeConnectToBrain(&sameFamilyHigherFallback) == false, "should_we_connect_to_brain_returns_false_for_later_same_family_candidate_greater_than_peer");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      brain.weAreMaster = false;
      brain.noMasterYet = false;

      BrainView nonMasterPeer = {};
      nonMasterPeer.uuid = uint128_t(0x311);
      nonMasterPeer.isMasterBrain = false;
      BrainView masterPeer = {};
      masterPeer.uuid = uint128_t(0x322);
      masterPeer.isMasterBrain = true;
      brain.brains.insert(&nonMasterPeer);
      brain.brains.insert(&masterPeer);

      suite.expect(brain.testGetExistingMasterUUID() == masterPeer.uuid, "get_existing_master_uuid_uses_master_peer_when_not_self_master");

      masterPeer.isMasterBrain = false;
      masterPeer.existingMasterUUID = masterPeer.uuid;
      suite.expect(brain.testGetExistingMasterUUID() == masterPeer.uuid, "get_existing_master_uuid_uses_existing_master_claim_when_master_bit_missing");

      masterPeer.existingMasterUUID = 0;
      suite.expect(brain.testGetExistingMasterUUID() == 0, "get_existing_master_uuid_returns_zero_without_marked_master_peer");

      brain.noMasterYet = true;
      masterPeer.isMasterBrain = true;
      suite.expect(brain.testGetExistingMasterUUID() == 0, "get_existing_master_uuid_respects_no_master_yet_flag");

      brain.brains.erase(&nonMasterPeer);
      brain.brains.erase(&masterPeer);
   }

   auto withUniqueMothershipSocket = [&] (const char *fixtureName, auto&& callback)
   {
      ScopedRing scopedRing = {};

      char socketDirectoryTemplate[] = "/tmp/prodigy-brain-master-XXXXXX";
      char *socketDirectory = ::mkdtemp(socketDirectoryTemplate);
      suite.expect(socketDirectory != nullptr, fixtureName);
      if (socketDirectory == nullptr)
      {
         return;
      }

      String socketPath = {};
      socketPath.assign(socketDirectory);
      socketPath.append("/mothership.sock"_ctv);

      const char *previousSocketPath = ::getenv("PRODIGY_MOTHERSHIP_SOCKET");
      String previousSocketPathText = {};
      if (previousSocketPath != nullptr)
      {
         previousSocketPathText.assign(previousSocketPath);
      }

      ::setenv("PRODIGY_MOTHERSHIP_SOCKET", socketPath.c_str(), 1);
      callback();

      if (previousSocketPath != nullptr)
      {
         ::setenv("PRODIGY_MOTHERSHIP_SOCKET", previousSocketPathText.c_str(), 1);
      }
      else
      {
         ::unsetenv("PRODIGY_MOTHERSHIP_SOCKET");
      }

      ::unlink(socketPath.c_str());
      ::rmdir(socketDirectory);
   };

   auto countQueuedTopics = [&] (String buffer, Vector<uint16_t>& topics) -> bool {

      topics.clear();
      forEachMessageInBuffer(buffer, [&] (Message *message) -> void {
         topics.push_back(message->topic);
      });
      return true;
   };

   auto findNeuronRegistrationRequiresState = [&] (String buffer, bool& requiresState) -> bool {
      bool found = false;
      forEachMessageInBuffer(buffer, [&] (Message *message) -> void {
         if (found || NeuronTopic(message->topic) != NeuronTopic::registration)
         {
            return;
         }

         uint8_t *args = message->args;
         if (args >= message->terminal())
         {
            return;
         }

         Message::extractArg<ArgumentNature::fixed>(args, requiresState);
         found = true;
      });
      return found;
   };

   auto installNeuronSocket = [&] (TestBrain& brain, Machine& machine, int& peerFD) -> bool {

      int sv[2] = {-1, -1};
      if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
      {
         return false;
      }

      RingDispatcher::installMultiplexee(&machine.neuron, &brain);
      machine.neuron.fd = sv[0];
      Ring::installFDIntoFixedFileSlot(&machine.neuron);
      peerFD = sv[1];
      return true;
   };

   auto installBrainPeerSocket = [&] (TestBrain& brain, BrainView& peer, int& peerFD) -> bool {

      int sv[2] = {-1, -1};
      if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
      {
         return false;
      }

      RingDispatcher::installMultiplexee(&peer, &brain);
      peer.fd = sv[0];
      Ring::installFDIntoFixedFileSlot(&peer);
      peerFD = sv[1];
      return true;
   };

   auto cleanupNeuronSocket = [&] (NeuronView& neuron, int& peerFD) -> void {

      if (neuron.isFixedFile)
      {
         Ring::uninstallFromFixedFileSlot(&neuron);
      }
      else if (neuron.fd >= 0)
      {
         ::close(neuron.fd);
      }

      neuron.fd = -1;
      neuron.isFixedFile = false;

      if (peerFD >= 0)
      {
         ::close(peerFD);
         peerFD = -1;
      }
   };

   auto cleanupBrainPeerSocket = [&] (BrainView& peer, int& peerFD) -> void {

      if (peer.isFixedFile)
      {
         Ring::uninstallFromFixedFileSlot(&peer);
      }
      else if (peer.fd >= 0)
      {
         ::close(peer.fd);
      }

      peer.fd = -1;
      peer.isFixedFile = false;

      if (peerFD >= 0)
      {
         ::close(peerFD);
         peerFD = -1;
      }
   };

   auto createUnixListener = [&] (const String& path, int& listenerFD) -> bool {
      String ownedPath = path;

      listenerFD = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
      if (listenerFD < 0)
      {
         return false;
      }

      struct sockaddr_un address = {};
      address.sun_family = AF_UNIX;
      std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", ownedPath.c_str());
      socklen_t addressLen = socklen_t(sizeof(address.sun_family) + std::strlen(address.sun_path));

      if (::bind(listenerFD, reinterpret_cast<struct sockaddr *>(&address), addressLen) != 0)
      {
         ::close(listenerFD);
         listenerFD = -1;
         return false;
      }

      if (::listen(listenerFD, SOMAXCONN) != 0)
      {
         ::close(listenerFD);
         listenerFD = -1;
         return false;
      }

      return true;
   };

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      Machine machine = {};
      machine.private4 = IPAddress("10.0.0.20", false).v4;
      machine.uuid = uint128_t(0x9020);
      machine.neuron.machine = &machine;
      brain.neurons.insert(&machine.neuron);

      int peerFD = -1;
      bool installed = installNeuronSocket(brain, machine, peerFD);
      suite.expect(installed, "brain_neuron_connect_handler_first_connect_installs_socket");
      if (installed)
      {
         machine.neuron.pendingConnect = true;
         Message::construct(machine.neuron.wBuffer, NeuronTopic::spinContainer, uint128_t(0), String("queued"_ctv));
         uint32_t queuedBytesBefore = machine.neuron.wBuffer.outstandingBytes();

         brain.testConnectHandler(&machine.neuron, 0);

         Vector<uint16_t> topics = {};
         suite.expect(countQueuedTopics(machine.neuron.wBuffer, topics), "brain_neuron_connect_handler_first_connect_parses_messages");
         suite.expect(machine.neuron.connected, "brain_neuron_connect_handler_first_connect_marks_connected");
         suite.expect(machine.neuron.hadSuccessfulConnection, "brain_neuron_connect_handler_first_connect_marks_successful_connection");
         suite.expect(machine.neuron.pendingConnect == false, "brain_neuron_connect_handler_first_connect_clears_pending_connect");
         suite.expect(machine.neuron.wBuffer.outstandingBytes() > queuedBytesBefore, "brain_neuron_connect_handler_first_connect_preserves_queued_bytes");
         suite.expect(topics.size() == 2, "brain_neuron_connect_handler_first_connect_keeps_original_and_registration_messages");
         suite.expect(topics[0] == uint16_t(NeuronTopic::spinContainer), "brain_neuron_connect_handler_first_connect_keeps_original_message_first");
         suite.expect(topics[1] == uint16_t(NeuronTopic::registration), "brain_neuron_connect_handler_first_connect_appends_registration");

         Ring::uninstallFromFixedFileSlot(&machine.neuron);
         ::close(peerFD);
         machine.neuron.fd = -1;
      }
   }

   {
      ScopedRing scopedRing = {};
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.noMasterYet = false;
      brain.ignited = true;
      brain.brainConfig.datacenterFragment = 0x55;

      Machine machine = {};
      machine.uuid = uint128_t(0x902155);
      machine.private4 = IPAddress("10.128.15.216", false).v4;
      machine.fragment = 0x123456;
      machine.state = MachineState::deploying;
      machine.neuron.machine = &machine;
      machine.neuron.connected = true;
      brain.machines.insert(&machine);
      brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
      brain.neurons.insert(&machine.neuron);

      int peerFD = -1;
      bool installed = installNeuronSocket(brain, machine, peerFD);
      suite.expect(installed, "brain_neuron_registration_installs_active_neuron_socket");
      if (installed)
      {
         String buffer = {};
         Message *message = buildNeuronMessage(
            buffer,
            NeuronTopic::registration,
            int64_t(1700000000004),
            "linux-6.10.1"_ctv,
            false);
         brain.testNeuronHandler(&machine.neuron, message);

         uint32_t stateUploadFrames = 0;
         uint32_t resetFrames = 0;
         uint32_t runtimeFrames = 0;
         forEachMessageInBuffer(machine.neuron.wBuffer, [&] (Message *queued) {
            if (NeuronTopic(queued->topic) == NeuronTopic::stateUpload)
            {
               stateUploadFrames += 1;
            }
            else if (NeuronTopic(queued->topic) == NeuronTopic::configureRuntimeEnvironment)
            {
               runtimeFrames += 1;
            }
            else if (NeuronTopic(queued->topic) == NeuronTopic::resetSwitchboardState && queued->isEcho())
            {
               resetFrames += 1;
            }
         });

         suite.expect(stateUploadFrames == 1, "brain_neuron_registration_replays_state_once_when_neuron_has_no_state");
         suite.expect(resetFrames == 1, "brain_neuron_registration_queues_single_switchboard_reset_when_neuron_has_no_state");
         suite.expect(runtimeFrames == 1, "brain_neuron_registration_queues_single_runtime_environment_sync_when_neuron_has_no_state");

         Ring::uninstallFromFixedFileSlot(&machine.neuron);
         ::close(peerFD);
         machine.neuron.fd = -1;
      }
      else
      {
         suite.expect(false, "brain_neuron_registration_skips_active_neuron_socket_expectations");
      }

      brain.neurons.erase(&machine.neuron);
      brain.machinesByUUID.erase(machine.uuid);
      brain.machines.erase(&machine);
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.overrideArmMachineNeuronControl = true;

      ClusterTopology topology = {};
      topology.version = 1;

      ClusterMachine machine = {};
      machine.source = ClusterMachineSource::adopted;
      machine.backing = ClusterMachineBacking::owned;
      machine.kind = MachineConfig::MachineKind::vm;
      machine.lifetime = MachineLifetime::owned;
      machine.uuid = uint128_t(0x90216);
      machine.creationTimeMs = Time::now<TimeResolution::ms>();
      machine.ssh.address = "10.0.0.216"_ctv;
      machine.ssh.user = "root"_ctv;
      prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, "10.0.0.216"_ctv, 24);
      topology.machines.push_back(machine);

      suite.expect(brain.testRestoreMachinesFromClusterTopology(topology),
         "restore_cluster_topology_machine_neuron_registered_before_finish_config_restore_succeeds");
      suite.expect(brain.armMachineNeuronControlCalls == 1,
         "restore_cluster_topology_machine_neuron_registered_before_finish_config_arms_control_once");
      suite.expect(brain.observedNeuronRegisteredBeforeArm,
         "restore_cluster_topology_machine_neuron_registered_before_finish_config_inserts_neuron_first");
	      suite.expect(brain.testFindMachineByUUID(uint128_t(0x90216)) != nullptr,
	         "restore_cluster_topology_machine_neuron_registered_before_finish_config_indexes_machine_by_uuid");
	   }

	   {
	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.weAreMaster = true;
	      brain.overrideArmMachineNeuronControl = true;

	      uint32_t private4 = IPAddress("10.0.0.217", false).v4;
	      BrainView *peer = makePeer(uint128_t(0x90217), int64_t(1234567890000), private4, "10.0.0.217");
	      peer->kernel = "linux-6.11.0-test"_ctv;
	      peer->osID = "portablelinux"_ctv;
	      peer->osVersionID = "1"_ctv;
	      brain.brains.insert(peer);

	      ClusterTopology topology = {};
	      topology.version = 1;

	      ClusterMachine machine = {};
	      machine.source = ClusterMachineSource::adopted;
	      machine.backing = ClusterMachineBacking::owned;
	      machine.kind = MachineConfig::MachineKind::vm;
	      machine.isBrain = true;
	      machine.lifetime = MachineLifetime::owned;
	      machine.uuid = peer->uuid;
	      machine.creationTimeMs = Time::now<TimeResolution::ms>();
	      machine.ssh.address = "10.0.0.217"_ctv;
	      machine.ssh.user = "root"_ctv;
	      prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, "10.0.0.217"_ctv, 24);
	      topology.machines.push_back(machine);

	      suite.expect(brain.testRestoreMachinesFromClusterTopology(topology),
	         "restore_cluster_topology_brain_peer_registration_before_machine_restore_succeeds");
	      suite.expect(peer->machine != nullptr,
	         "restore_cluster_topology_brain_peer_registration_before_machine_restore_links_machine");
	      suite.expect(peer->machine != nullptr && peer->machine->brain == peer,
	         "restore_cluster_topology_brain_peer_registration_before_machine_restore_links_peer");
	      suite.expect(peer->machine != nullptr && peer->machine->kernel == "linux-6.11.0-test"_ctv,
	         "restore_cluster_topology_brain_peer_registration_before_machine_restore_replays_kernel");
	      suite.expect(peer->machine != nullptr && peer->machine->osID == "portablelinux"_ctv,
	         "restore_cluster_topology_brain_peer_registration_before_machine_restore_replays_os_id");
	      suite.expect(peer->machine != nullptr && peer->machine->osVersionID == "1"_ctv,
	         "restore_cluster_topology_brain_peer_registration_before_machine_restore_replays_os_version_id");
	      suite.expect(peer->machine != nullptr && peer->machine->lastUpdatedOSMs == int64_t(1234567),
	         "restore_cluster_topology_brain_peer_registration_before_machine_restore_replays_boot_time_ms");

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      ScopedRing scopedRing = {};

	      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.overrideNeuronControlInstallFromBrain = true;
      brain.forcedNeuronControlInstallFromBrain = false;

      Machine machine = {};
      machine.uuid = uint128_t(0x90215);
      machine.private4 = IPAddress("10.0.0.215", false).v4;
      machine.neuron.machine = &machine;
      machine.neuron.connected = true;

      int peerFD = -1;
      bool installed = installNeuronSocket(brain, machine, peerFD);
      suite.expect(installed, "brain_finish_machine_config_preserves_active_neuron_control_installs_fixture");
      if (installed)
      {
         brain.finishMachineConfig(&machine);

         suite.expect(brain.neuronControlInstallFromBrainCalls == 0, "brain_finish_machine_config_preserves_active_neuron_control_skips_reinstall");
         suite.expect(machine.neuron.connected, "brain_finish_machine_config_preserves_active_neuron_control_keeps_connected");
         suite.expect(machine.neuron.isFixedFile, "brain_finish_machine_config_preserves_active_neuron_control_keeps_fixed_file");
         suite.expect(machine.neuron.fslot >= 0, "brain_finish_machine_config_preserves_active_neuron_control_keeps_fixed_slot");

         Ring::uninstallFromFixedFileSlot(&machine.neuron);
         ::close(peerFD);
         machine.neuron.fd = -1;
      }
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.ignited = true;

      Machine machine = {};
      machine.private4 = IPAddress("10.0.0.21", false).v4;
      machine.uuid = uint128_t(0x9021);
      machine.state = MachineState::healthy;
      machine.runtimeReady = true;
      machine.neuron.machine = &machine;
      machine.neuron.hadSuccessfulConnection = true;
      brain.neurons.insert(&machine.neuron);

      int peerFD = -1;
      bool installed = installNeuronSocket(brain, machine, peerFD);
      suite.expect(installed, "brain_neuron_connect_handler_reconnect_installs_socket");
      if (installed)
      {
         Message::construct(machine.neuron.wBuffer, NeuronTopic::spinContainer, uint128_t(0), String("stale"_ctv));

         brain.testConnectHandler(&machine.neuron, 0);

         Vector<uint16_t> topics = {};
         bool requiresState = true;
         suite.expect(countQueuedTopics(machine.neuron.wBuffer, topics), "brain_neuron_connect_handler_reconnect_parses_messages");
         suite.expect(findNeuronRegistrationRequiresState(machine.neuron.wBuffer, requiresState), "brain_neuron_connect_handler_reconnect_finds_registration_payload");
         suite.expect(topics.size() == 1, "brain_neuron_connect_handler_reconnect_drops_stale_payload");
         suite.expect(topics[0] == uint16_t(NeuronTopic::registration), "brain_neuron_connect_handler_reconnect_requeues_registration_only");
         suite.expect(requiresState == false, "brain_neuron_connect_handler_reconnect_does_not_request_authoritative_state_upload");

         Ring::uninstallFromFixedFileSlot(&machine.neuron);
         ::close(peerFD);
         machine.neuron.fd = -1;
      }
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x9022), 1, IPAddress("10.0.0.22", false).v4, "10.0.0.22");
      peer->connected = true;
      peer->weConnectToIt = false;
      peer->currentStreamAccepted = true;
      brain.brains.insert(peer);

      int fds[2] = {-1, -1};
      if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0)
      {
         suite.expect(false, "brain_connect_handler_accepted_stream_stale_connect_creates_socketpair");
      }
      else
      {
         peer->fd = fds[0];
         Ring::installFDIntoFixedFileSlot(peer);

         brain.testConnectHandler(peer, 0);

         suite.expect(peer->currentStreamAccepted, "brain_connect_handler_accepted_stream_stale_connect_keeps_accepted_flag");
         suite.expect(peer->connected, "brain_connect_handler_accepted_stream_stale_connect_keeps_connected_state");
         suite.expect(peer->pendingSend == false, "brain_connect_handler_accepted_stream_stale_connect_does_not_arm_send");
         suite.expect(peer->pendingRecv == false, "brain_connect_handler_accepted_stream_stale_connect_does_not_arm_recv");
         suite.expect(peer->wBuffer.outstandingBytes() == 0, "brain_connect_handler_accepted_stream_stale_connect_does_not_queue_registration");

         Ring::uninstallFromFixedFileSlot(peer);
         ::close(fds[1]);
         peer->fd = -1;
      }

      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.noMasterYet = false;

      BrainView *peer = makePeer(uint128_t(0x21f3), 193, IPAddress("10.0.0.21", false).v4, "10.0.0.21");
      peer->connected = true;
      peer->weConnectToIt = true;
      peer->registrationFresh = true;
      peer->isMasterBrain = true;
      peer->reconnectAfterClose = true;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      peer->transportEpoch = 2;
      peer->queuedCloseTransportEpoch = 1;
      peer->fd = -1;
      peer->fslot = -1;
      peer->isFixedFile = false;
      brain.brains.insert(peer);

      brain.testCloseHandler(peer);

      suite.expect(peer->connected == false, "brain_close_handler_inactive_advanced_transport_marks_peer_disconnected");
      suite.expect(peer->queuedCloseTransportEpoch == 0, "brain_close_handler_inactive_advanced_transport_clears_stale_epoch");
      suite.expect(brain.testHasBrainWaiter(peer), "brain_close_handler_inactive_advanced_transport_arms_master_missing_waiter");
      suite.expect(brain.testHasBrainReconnectWaiter(peer), "brain_close_handler_inactive_advanced_transport_arms_reconnect_waiter");

      brain.testEraseBrainWaiter(peer);
      brain.testEraseBrainReconnectWaiter(peer);
      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.weAreMaster = false;
      brain.noMasterYet = false;

      BrainView *peer = makePeer(uint128_t(0x21f), 0, IPAddress("10.0.0.19", false).v4, "10.0.0.19");
      peer->weConnectToIt = true;
      peer->reconnectAfterClose = true;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      peer->nConnectionAttempts = 0;
      peer->nAttemptsBudget = 9;
      peer->attemptDeadlineMs = 12345;
      peer->fd = -1;
      peer->isFixedFile = false;
      peer->connected = false;
      peer->registrationFresh = false;
      peer->existingMasterUUID = peer->uuid;
      brain.brains.insert(peer);

      brain.testCloseHandler(peer);

      TimeoutPacket *waiter = brain.testGetBrainWaiter(peer);
      suite.expect(waiter != nullptr, "brain_close_handler_connector_inert_master_claim_arms_waiter");
      suite.expect(peer->fd == -1, "brain_close_handler_connector_inert_master_claim_keeps_fd_unarmed");
      suite.expect(peer->isFixedFile == false, "brain_close_handler_connector_inert_master_claim_keeps_fixed_slot_unarmed");
      suite.expect(peer->reconnectAfterClose, "brain_close_handler_connector_inert_master_claim_preserves_reconnect_policy");
      suite.expect(peer->nConnectionAttempts == 0, "brain_close_handler_connector_inert_master_claim_preserves_attempt_counter");
      suite.expect(peer->nAttemptsBudget == 9, "brain_close_handler_connector_inert_master_claim_preserves_attempt_budget");
      suite.expect(peer->attemptDeadlineMs == 12345, "brain_close_handler_connector_inert_master_claim_preserves_attempt_deadline");

      brain.testEraseBrainWaiter(peer);
      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x21e1), 0, IPAddress("10.0.0.181", false).v4, "10.0.0.181");
      peer->weConnectToIt = true;
      peer->reconnectAfterClose = true;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      peer->nConnectionAttempts = 2;
      peer->nAttemptsBudget = 9;
      peer->attemptDeadlineMs = 12345;
      peer->fd = -1;
      peer->fslot = -1;
      peer->isFixedFile = false;
      brain.brains.insert(peer);

      brain.testInsertBrainWaiter(peer);
      TimeoutPacket *waiter = brain.testGetBrainWaiter(peer);
      suite.expect(waiter != nullptr, "brain_close_handler_dead_connector_retry_fixture_arms_waiter");

      peer->noteTransportActivated();
      peer->noteCloseQueuedForCurrentTransport();
      brain.testCloseHandler(peer);

      suite.expect(brain.testHasBrainWaiter(peer) == false, "brain_close_handler_dead_connector_retry_erases_waiter");
      suite.expect(waiter != nullptr && waiter->flags == uint64_t(BrainTimeoutFlags::canceled), "brain_close_handler_dead_connector_retry_marks_waiter_canceled");
      TimeoutPacket *reconnectWaiter = brain.testGetBrainReconnectWaiter(peer);
      suite.expect(reconnectWaiter != nullptr, "brain_close_handler_dead_connector_retry_arms_reconnect_waiter");
      suite.expect(peer->isFixedFile == false, "brain_close_handler_dead_connector_retry_defers_fixed_slot_reinstall");
      suite.expect(peer->fslot < 0, "brain_close_handler_dead_connector_retry_defers_slot_arm");
      suite.expect(peer->connectAttemptPending() == false, "brain_close_handler_dead_connector_retry_defers_connect_attempt");

      if (reconnectWaiter != nullptr)
      {
         brain.testDispatchTimeout(reconnectWaiter);
      }

      suite.expect(brain.testHasBrainReconnectWaiter(peer) == false, "brain_close_handler_dead_connector_retry_clears_reconnect_waiter");
      suite.expect(peer->isFixedFile, "brain_close_handler_dead_connector_retry_reinstalls_fixed_slot");
      suite.expect(peer->fslot >= 0, "brain_close_handler_dead_connector_retry_keeps_slot_armed");
      suite.expect(peer->connectAttemptPending(), "brain_close_handler_dead_connector_retry_submits_connect_attempt");
      suite.expect(peer->reconnectAfterClose, "brain_close_handler_dead_connector_retry_keeps_reconnect_policy_armed");
      suite.expect(peer->nConnectionAttempts == 0, "brain_close_handler_dead_connector_retry_resets_attempt_counter");
      suite.expect(peer->nAttemptsBudget == 0, "brain_close_handler_dead_connector_retry_clears_attempt_budget");
      suite.expect(peer->attemptDeadlineMs == 0, "brain_close_handler_dead_connector_retry_clears_attempt_deadline");

      if (peer->isFixedFile)
      {
         Ring::uninstallFromFixedFileSlot(peer);
      }

      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x21f2), 192, IPAddress("10.0.0.20", false).v4, "10.0.0.20");
      peer->connected = true;
      peer->weConnectToIt = true;
      peer->registrationFresh = true;
      peer->reconnectAfterClose = false;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_close_handler_stale_connector_close_after_reconnect_installs_fixture");
      if (installed)
      {
         peer->noteTransportActivated();
         peer->noteCloseQueuedForCurrentTransport();
         brain.testCloseHandler(peer);
         brain.testConnectHandler(peer, 0);
         peer->registrationFresh = true;

         const int replacementFslot = peer->fslot;
         const uint32_t replacementEpoch = peer->transportEpoch;

         brain.testCloseHandler(peer);

         suite.expect(peer->connected, "brain_close_handler_stale_connector_close_after_reconnect_keeps_replacement_connected");
         suite.expect(peer->currentStreamAccepted == false, "brain_close_handler_stale_connector_close_after_reconnect_keeps_connector_ownership");
         suite.expect(peer->registrationFresh, "brain_close_handler_stale_connector_close_after_reconnect_keeps_registration_fresh");
         suite.expect(peer->fslot == replacementFslot, "brain_close_handler_stale_connector_close_after_reconnect_preserves_replacement_slot");
         suite.expect(peer->transportEpoch == replacementEpoch, "brain_close_handler_stale_connector_close_after_reconnect_preserves_transport_epoch");

         cleanupBrainPeerSocket(*peer, peerFD);
      }

      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x22121), 213, IPAddress("127.0.0.1", false).v4, "127.0.0.1");
      peer->connected = true;
      peer->weConnectToIt = false;
      peer->currentStreamAccepted = true;
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_accept_handler_known_peer_replacement_advances_generation_installs_fixture");

      RingDispatcher::installMultiplexee(&brain.brainSocket, &brain);
      int listenerPair[2] = {-1, -1};
      suite.expect(
         ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, listenerPair) == 0,
         "brain_accept_handler_known_peer_replacement_advances_generation_creates_listener_pair");
      if (listenerPair[0] >= 0)
      {
         brain.brainSocket.fd = listenerPair[0];
         Ring::installFDIntoFixedFileSlot(&brain.brainSocket);
      }

      int acceptedFD = -1;
      int acceptedSlot = -1;
      int acceptedPair[2] = {-1, -1};
      suite.expect(
         ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, acceptedPair) == 0,
         "brain_accept_handler_known_peer_replacement_advances_generation_creates_accepted_pair");
      if (acceptedPair[0] >= 0)
      {
         acceptedFD = acceptedPair[0];
         if (peerFD >= 0)
         {
            ::close(peerFD);
         }
         peerFD = acceptedPair[1];
      }

      if (installed && acceptedFD >= 0)
      {
         peer->noteCloseQueuedForCurrentTransport();
         Ring::queueClose(peer);
         const uint8_t closeGeneration = peer->ioGeneration;

         struct sockaddr_in *acceptedAddress = reinterpret_cast<struct sockaddr_in *>(&brain.brain_saddr);
         memset(&brain.brain_saddr, 0, sizeof(brain.brain_saddr));
         acceptedAddress->sin_family = AF_INET;
         acceptedAddress->sin_port = htons(uint16_t(ReservedPorts::brain));
         acceptedAddress->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
         brain.brain_saddrlen = sizeof(struct sockaddr_in);

         acceptedSlot = Ring::adoptProcessFDIntoFixedFileSlot(acceptedFD, false);
         suite.expect(acceptedSlot >= 0, "brain_accept_handler_known_peer_replacement_advances_generation_adopts_fixed_slot");
         if (acceptedSlot >= 0)
         {
            brain.testAcceptHandler(&brain.brainSocket, acceptedSlot);

            suite.expect(peer->ioGeneration != closeGeneration, "brain_accept_handler_known_peer_replacement_advances_generation_bumps_generation_past_queued_close");
            suite.expect(peer->connected, "brain_accept_handler_known_peer_replacement_advances_generation_marks_connected");
            suite.expect(peer->currentStreamAccepted, "brain_accept_handler_known_peer_replacement_advances_generation_marks_accepted_stream");
         }
      }

      if (acceptedFD >= 0)
      {
         ::close(acceptedFD);
      }
      if (brain.brainSocket.isFixedFile)
      {
         Ring::uninstallFromFixedFileSlot(&brain.brainSocket);
      }
      if (brain.brainSocket.fd >= 0)
      {
         ::close(brain.brainSocket.fd);
         brain.brainSocket.fd = -1;
      }
      if (listenerPair[1] >= 0)
      {
         ::close(listenerPair[1]);
      }

      cleanupBrainPeerSocket(*peer, peerFD);
      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x22124), 216, IPAddress("127.0.0.1", false).v4, "127.0.0.1");
      peer->connected = false;
      peer->weConnectToIt = false;
      peer->currentStreamAccepted = true;
      peer->registrationFresh = true;
      peer->tlsPeerVerified = true;
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_arm_outbound_peer_reconnect_force_live_raw_accepted_installs_fixture");
      if (installed)
      {
         brain.testArmOutboundPeerReconnect(peer, true);

         suite.expect(Ring::socketIsClosing(peer), "brain_arm_outbound_peer_reconnect_force_live_raw_accepted_queues_tracked_close");
         suite.expect(peer->connectAttemptPending() == false, "brain_arm_outbound_peer_reconnect_force_live_raw_accepted_defers_redial_until_close_completion");
         suite.expect(peer->forceConnectorOwnershipUntilMasterAck, "brain_arm_outbound_peer_reconnect_force_live_raw_accepted_sets_force_connector_flag");

         brain.testCloseHandler(peer);
         if (TimeoutPacket *waiter = brain.testGetBrainWaiter(peer); waiter != nullptr)
         {
            waiter->flags = uint64_t(BrainTimeoutFlags::canceled);
            brain.testDispatchTimeout(waiter);
         }
      }

      cleanupBrainPeerSocket(*peer, peerFD);
      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x22123), 215, IPAddress("127.0.0.1", false).v4, "127.0.0.1");
      peer->connected = true;
      peer->weConnectToIt = false;
      peer->currentStreamAccepted = true;
      peer->registrationFresh = true;
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_arm_outbound_peer_reconnect_force_live_accepted_installs_fixture");
      if (installed)
      {
         brain.testArmOutboundPeerReconnect(peer, true);

         suite.expect(Ring::socketIsClosing(peer), "brain_arm_outbound_peer_reconnect_force_live_accepted_queues_tracked_close");
         suite.expect(peer->connectAttemptPending() == false, "brain_arm_outbound_peer_reconnect_force_live_accepted_defers_redial_until_close_completion");

         brain.testCloseHandler(peer);
         suite.expect(peer->forceConnectorOwnershipUntilMasterAck, "brain_arm_outbound_peer_reconnect_force_live_accepted_sets_force_connector_flag");
         if (TimeoutPacket *waiter = brain.testGetBrainWaiter(peer); waiter != nullptr)
         {
            waiter->flags = uint64_t(BrainTimeoutFlags::canceled);
            brain.testDispatchTimeout(waiter);
         }
      }

      cleanupBrainPeerSocket(*peer, peerFD);
      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x22122), 214, IPAddress("127.0.0.1", false).v4, "127.0.0.1");
      peer->connected = true;
      peer->weConnectToIt = false;
      peer->currentStreamAccepted = true;
      peer->registrationFresh = true;
      peer->noteTransportActivated();
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_close_handler_stale_accepted_close_after_reaccept_installs_fixture");

      RingDispatcher::installMultiplexee(&brain.brainSocket, &brain);
      int listenerPair[2] = {-1, -1};
      suite.expect(
         ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, listenerPair) == 0,
         "brain_close_handler_stale_accepted_close_after_reaccept_creates_listener_pair");
      if (listenerPair[0] >= 0)
      {
         brain.brainSocket.fd = listenerPair[0];
         Ring::installFDIntoFixedFileSlot(&brain.brainSocket);
      }

      int acceptedFD = -1;
      int acceptedSlot = -1;
      int acceptedPair[2] = {-1, -1};
      suite.expect(
         ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, acceptedPair) == 0,
         "brain_close_handler_stale_accepted_close_after_reaccept_creates_accepted_pair");
      if (acceptedPair[0] >= 0)
      {
         acceptedFD = acceptedPair[0];
         if (peerFD >= 0)
         {
            ::close(peerFD);
         }
         peerFD = acceptedPair[1];
      }

      if (installed && acceptedFD >= 0)
      {
         peer->noteCloseQueuedForCurrentTransport();
         Ring::queueClose(peer);
         brain.testCloseHandler(peer);
         suite.expect(brain.testHasBrainWaiter(peer), "brain_close_handler_stale_accepted_close_after_reaccept_arms_waiter_for_original_close");

         struct sockaddr_in *acceptedAddress = reinterpret_cast<struct sockaddr_in *>(&brain.brain_saddr);
         memset(&brain.brain_saddr, 0, sizeof(brain.brain_saddr));
         acceptedAddress->sin_family = AF_INET;
         acceptedAddress->sin_port = htons(uint16_t(ReservedPorts::brain));
         acceptedAddress->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
         brain.brain_saddrlen = sizeof(struct sockaddr_in);

         acceptedSlot = Ring::adoptProcessFDIntoFixedFileSlot(acceptedFD, false);
         suite.expect(acceptedSlot >= 0, "brain_close_handler_stale_accepted_close_after_reaccept_adopts_fixed_slot");
         if (acceptedSlot >= 0)
         {
            brain.testAcceptHandler(&brain.brainSocket, acceptedSlot);
            peer->registrationFresh = true;

            const int replacementFslot = peer->fslot;
            const uint32_t replacementEpoch = peer->transportEpoch;

            brain.testCloseHandler(peer);

            suite.expect(peer->connected, "brain_close_handler_stale_accepted_close_after_reaccept_keeps_replacement_connected");
            suite.expect(peer->currentStreamAccepted, "brain_close_handler_stale_accepted_close_after_reaccept_keeps_replacement_accepted");
            suite.expect(peer->registrationFresh, "brain_close_handler_stale_accepted_close_after_reaccept_keeps_replacement_registration_fresh");
            suite.expect(peer->fslot == replacementFslot, "brain_close_handler_stale_accepted_close_after_reaccept_preserves_replacement_slot");
            suite.expect(peer->transportEpoch == replacementEpoch, "brain_close_handler_stale_accepted_close_after_reaccept_preserves_transport_epoch");
            suite.expect(peer->confirmedMissingTransportEpoch == 0, "brain_close_handler_stale_accepted_close_after_reaccept_clears_confirmed_missing_epoch_on_reaccept");
            suite.expect(brain.testHasBrainWaiter(peer) == false, "brain_close_handler_stale_accepted_close_after_reaccept_does_not_rearm_waiter");
         }
      }

      if (acceptedFD >= 0)
      {
         ::close(acceptedFD);
      }
      if (brain.brainSocket.isFixedFile)
      {
         Ring::uninstallFromFixedFileSlot(&brain.brainSocket);
      }
      if (brain.brainSocket.fd >= 0)
      {
         ::close(brain.brainSocket.fd);
         brain.brainSocket.fd = -1;
      }
      if (listenerPair[1] >= 0)
      {
         ::close(listenerPair[1]);
      }

      cleanupBrainPeerSocket(*peer, peerFD);
      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.weAreMaster = false;
      brain.noMasterYet = false;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *masterPeer = makePeer(uint128_t(0x22124), 216, IPAddress("10.0.0.11", false).v4, "10.0.0.11");
      masterPeer->connected = true;
      masterPeer->weConnectToIt = false;
      masterPeer->currentStreamAccepted = true;
      masterPeer->registrationFresh = true;
      masterPeer->isFixedFile = true;
      masterPeer->fslot = 49;
      masterPeer->isMasterBrain = true;
      masterPeer->noteTransportActivated();
      masterPeer->confirmedMissingTransportEpoch = masterPeer->transportEpoch;
      brain.brains.insert(masterPeer);

      BrainView *followerPeer = makePeer(uint128_t(0x22125), 217, IPAddress("10.0.0.12", false).v4, "10.0.0.12");
      followerPeer->connected = true;
      followerPeer->isFixedFile = true;
      followerPeer->fslot = 50;
      brain.brains.insert(followerPeer);

      brain.testCloseHandler(masterPeer);

      bool sawMasterMissingFrame = false;
      forEachMessageInBuffer(followerPeer->wBuffer, [&] (Message *frame) {
         if (BrainTopic(frame->topic) == BrainTopic::masterMissing)
         {
            sawMasterMissingFrame = true;
         }
      });

      TimeoutPacket *waiter = brain.testGetBrainWaiter(masterPeer);
      suite.expect(masterPeer->quarantined == false, "brain_close_handler_liveness_confirmed_accepted_master_defers_quarantine");
      suite.expect(brain.isMasterMissing == false, "brain_close_handler_liveness_confirmed_accepted_master_defers_master_missing");
      suite.expect(masterPeer->confirmedMissingTransportEpoch == 0, "brain_close_handler_liveness_confirmed_accepted_master_clears_confirmed_missing_epoch");
      suite.expect(waiter != nullptr, "brain_close_handler_liveness_confirmed_accepted_master_arms_waiter");
      suite.expect(waiter != nullptr && waiter->timeoutMs() == int64_t(masterPeer->nDefaultAttemptsBudget * masterPeer->connectTimeoutMs + prodigyBrainPeerInboundMissingSlackMs), "brain_close_handler_liveness_confirmed_accepted_master_waiter_uses_failover_window");
      suite.expect(sawMasterMissingFrame == false, "brain_close_handler_liveness_confirmed_accepted_master_defers_master_missing_gossip");

      brain.testEraseBrainWaiter(masterPeer);
      brain.brains.erase(masterPeer);
      brain.brains.erase(followerPeer);
      delete masterPeer;
      delete followerPeer;
   }

   withUniqueMothershipSocket("brain_missing_master_prior_peer_vote_derives_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;
      brain.hasCompletedInitialMasterElection = true;
      brain.weAreMaster = false;
      brain.noMasterYet = false;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *masterPeer = makePeer(uint128_t(0x222), 20, IPAddress("10.0.0.11", false).v4, "10.0.0.11");
      masterPeer->connected = true;
      masterPeer->isFixedFile = true;
      masterPeer->fslot = 38;
      masterPeer->isMasterBrain = true;
      brain.brains.insert(masterPeer);

      BrainView *followerPeer = makePeer(uint128_t(0x332), 21, IPAddress("10.0.0.12", false).v4, "10.0.0.12");
      followerPeer->connected = true;
      followerPeer->isFixedFile = true;
      followerPeer->fslot = 39;
      followerPeer->isMasterMissing = true;
      brain.brains.insert(followerPeer);

      const char *socketPath = ::getenv("PRODIGY_MOTHERSHIP_SOCKET");
      suite.expect(socketPath != nullptr, "brain_missing_master_prior_peer_vote_has_mothership_socket");
      int existingListenerFD = -1;
      if (socketPath != nullptr)
      {
         suite.expect(createUnixListener(String(socketPath), existingListenerFD),
            "brain_missing_master_prior_peer_vote_creates_existing_listener");
      }

      brain.testBrainMissing(masterPeer);

      suite.expect(masterPeer->quarantined, "brain_missing_master_prior_peer_vote_quarantines_missing_master");
      suite.expect(brain.weAreMaster, "brain_missing_master_prior_peer_vote_derives_self_master");
      suite.expect(brain.noMasterYet == false, "brain_missing_master_prior_peer_vote_clears_no_master");

      brain.brains.erase(masterPeer);
      brain.brains.erase(followerPeer);
      delete masterPeer;
      delete followerPeer;
      if (existingListenerFD >= 0)
      {
         ::close(existingListenerFD);
      }
   });

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.weAreMaster = false;
      brain.noMasterYet = false;
      brain.localBrainPeerAddress = IPAddress("10.0.0.12", false);
      brain.localBrainPeerAddressText = "10.0.0.12"_ctv;

      BrainView *masterPeer = makePeer(uint128_t(0x22126), 218, IPAddress("10.0.0.11", false).v4, "10.0.0.11");
      masterPeer->connected = true;
      masterPeer->weConnectToIt = true;
      masterPeer->registrationFresh = true;
      masterPeer->isMasterBrain = true;
      masterPeer->noteTransportActivated();
      masterPeer->confirmedMissingTransportEpoch = masterPeer->transportEpoch;
      brain.brains.insert(masterPeer);

      BrainView *followerPeer = makePeer(uint128_t(0x22127), 219, IPAddress("10.0.0.13", false).v4, "10.0.0.13");
      followerPeer->connected = true;
      followerPeer->isFixedFile = true;
      followerPeer->fslot = 52;
      brain.brains.insert(followerPeer);

      brain.testCloseHandler(masterPeer);

      bool sawMasterMissingFrame = false;
      forEachMessageInBuffer(followerPeer->wBuffer, [&] (Message *frame) {
         if (BrainTopic(frame->topic) == BrainTopic::masterMissing)
         {
            sawMasterMissingFrame = true;
         }
      });

      TimeoutPacket *waiter = brain.testGetBrainWaiter(masterPeer);
      TimeoutPacket *reconnectWaiter = brain.testGetBrainReconnectWaiter(masterPeer);
      suite.expect(masterPeer->quarantined == false, "brain_close_handler_liveness_confirmed_connector_master_defers_quarantine");
      suite.expect(brain.isMasterMissing == false, "brain_close_handler_liveness_confirmed_connector_master_defers_master_missing");
      suite.expect(masterPeer->confirmedMissingTransportEpoch == 0, "brain_close_handler_liveness_confirmed_connector_master_clears_confirmed_missing_epoch");
      suite.expect(waiter != nullptr, "brain_close_handler_liveness_confirmed_connector_master_arms_waiter");
      suite.expect(reconnectWaiter != nullptr, "brain_close_handler_liveness_confirmed_connector_master_arms_reconnect_waiter");
      suite.expect(waiter != nullptr && waiter->timeoutMs() == int64_t(masterPeer->nDefaultAttemptsBudget * masterPeer->connectTimeoutMs + prodigyBrainPeerInboundMissingSlackMs), "brain_close_handler_liveness_confirmed_connector_master_waiter_uses_failover_window");
      suite.expect(sawMasterMissingFrame == false, "brain_close_handler_liveness_confirmed_connector_master_defers_master_missing_gossip");

      brain.testEraseBrainWaiter(masterPeer);
      brain.testEraseBrainReconnectWaiter(masterPeer);
      brain.brains.erase(masterPeer);
      brain.brains.erase(followerPeer);
      delete masterPeer;
      delete followerPeer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x90221), 2, IPAddress("10.0.0.23", false).v4, "10.0.0.23");
      peer->connected = false;
      peer->quarantined = false;
      peer->weConnectToIt = false;
      peer->currentStreamAccepted = false;
      brain.brains.insert(peer);

      int fds[2] = {-1, -1};
      if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0)
      {
         suite.expect(false, "brain_connect_handler_non_connector_stable_stale_connect_creates_socketpair");
      }
      else
      {
         peer->fd = fds[0];
         Ring::installFDIntoFixedFileSlot(peer);

         brain.testConnectHandler(peer, 0);

         suite.expect(peer->connected == false, "brain_connect_handler_non_connector_stable_stale_connect_keeps_disconnected");
         suite.expect(peer->currentStreamAccepted == false, "brain_connect_handler_non_connector_stable_stale_connect_keeps_accept_flag_clear");
         suite.expect(peer->pendingSend == false, "brain_connect_handler_non_connector_stable_stale_connect_does_not_arm_send");
         suite.expect(peer->pendingRecv == false, "brain_connect_handler_non_connector_stable_stale_connect_does_not_arm_recv");
         suite.expect(peer->wBuffer.outstandingBytes() == 0, "brain_connect_handler_non_connector_stable_stale_connect_does_not_queue_registration");

         Ring::uninstallFromFixedFileSlot(peer);
         ::close(fds[1]);
         peer->fd = -1;
      }

      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x90222), 3, IPAddress("10.0.0.24", false).v4, "10.0.0.24");
      peer->connected = false;
      peer->quarantined = true;
      peer->weConnectToIt = false;
      peer->currentStreamAccepted = false;
      brain.brains.insert(peer);

      int fds[2] = {-1, -1};
      if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0)
      {
         suite.expect(false, "brain_connect_handler_non_connector_quarantined_fallback_connect_creates_socketpair");
      }
      else
      {
         peer->fd = fds[0];
         Ring::installFDIntoFixedFileSlot(peer);

         brain.testConnectHandler(peer, 0);

         suite.expect(peer->connected, "brain_connect_handler_non_connector_quarantined_fallback_connect_marks_connected");
         suite.expect(peer->pendingRecv, "brain_connect_handler_non_connector_quarantined_fallback_connect_arms_recv");
         suite.expect(peer->pendingSend, "brain_connect_handler_non_connector_quarantined_fallback_connect_arms_send");
         suite.expect(peer->wBuffer.outstandingBytes() > 0, "brain_connect_handler_non_connector_quarantined_fallback_connect_queues_registration");

         Ring::uninstallFromFixedFileSlot(peer);
         ::close(fds[1]);
         peer->fd = -1;
      }

      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *peer = makePeer(uint128_t(0x90223), 4, IPAddress("10.0.0.24", false).v4, "10.0.0.24");
      peer->connected = false;
      peer->quarantined = true;
      peer->weConnectToIt = true;
      peer->currentStreamAccepted = false;
      brain.brains.insert(peer);
      brain.testInsertBrainWaiter(peer);

      int fds[2] = {-1, -1};
      if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0)
      {
         suite.expect(false, "brain_connect_handler_outbound_reconnect_cancels_stale_waiter_creates_socketpair");
      }
      else
      {
         peer->fd = fds[0];
         Ring::installFDIntoFixedFileSlot(peer);

         brain.testConnectHandler(peer, 0);

         suite.expect(brain.testHasBrainWaiter(peer) == false, "brain_connect_handler_outbound_reconnect_cancels_stale_waiter_arms_no_waiter");
         suite.expect(peer->connected, "brain_connect_handler_outbound_reconnect_cancels_stale_waiter_marks_connected");
         suite.expect(peer->quarantined == false, "brain_connect_handler_outbound_reconnect_cancels_stale_waiter_clears_quarantine");
         suite.expect(peer->pendingRecv, "brain_connect_handler_outbound_reconnect_cancels_stale_waiter_arms_recv");
         suite.expect(peer->pendingSend, "brain_connect_handler_outbound_reconnect_cancels_stale_waiter_arms_send");

         Ring::uninstallFromFixedFileSlot(peer);
         ::close(fds[1]);
         peer->fd = -1;
      }

      brain.testEraseBrainWaiter(peer);
      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      suite.expect(brain.shouldWeConnectToBrain(nullptr) == false, "connector_order_rejects_null_peer");

      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView peer = {};
      peer.uuid = uint128_t(0x070);
      peer.boottimens = 1;
      peer.peerAddress = IPAddress("10.0.0.20", false);

      suite.expect(brain.shouldWeConnectToBrain(&peer), "connector_order_renders_peer_address_without_text");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *peer = makePeer(uint128_t(0x050), 1, 0, "10.0.0.20");
      brain.brains.insert(peer);

      suite.expect(brain.shouldWeConnectToBrain(peer), "connector_order_prefers_transport_address_before_uuid");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      IPAddress savedPrivate4 = neuron.private4;
      neuron.private4 = IPAddress("10.0.0.10", false);

      BrainView *peer = makePeer(uint128_t(0x080), 1, IPAddress("10.0.0.20", false).v4);
      brain.brains.insert(peer);

      suite.expect(brain.shouldWeConnectToBrain(peer), "connector_order_falls_back_to_private4_when_transport_addresses_missing");

      brain.brains.erase(peer);
      delete peer;
      neuron.private4 = savedPrivate4;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.localBrainPeerAddress = IPAddress("10.0.0.29", false);
      brain.localBrainPeerAddressText = "10.0.0.29"_ctv;

      ClusterMachinePeerAddress localIPv4 = {};
      localIPv4.address = "10.0.0.29"_ctv;
      brain.localBrainPeerAddresses.push_back(localIPv4);

      ClusterMachinePeerAddress localIPv6 = {};
      localIPv6.address = "fd00:10::29"_ctv;
      localIPv6.cidr = 64;
      brain.localBrainPeerAddresses.push_back(localIPv6);

      BrainView *peer = makePeer(uint128_t(0x250), 1, 0, "fd00:10::10");
      ClusterMachinePeerAddress peerIPv6 = {};
      peerIPv6.address = "fd00:10::10"_ctv;
      peerIPv6.cidr = 64;
      peer->peerAddresses.push_back(peerIPv6);
      brain.brains.insert(peer);

      suite.expect(brain.shouldWeConnectToBrain(peer) == false, "connector_order_uses_same_family_candidate_before_ipv4_fallback");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.localBrainPeerAddress = IPAddress("fd00:10::50", true);
      brain.localBrainPeerAddressText = "fd00:10::50"_ctv;
      brain.localBrainPeerAddresses.push_back(ClusterMachinePeerAddress{"fd00:10::50"_ctv, 64});

      BrainView *peer = makePeer(uint128_t(0x040), 1, 0, "fd00:10::50");
      brain.brains.insert(peer);

      suite.expect(brain.shouldWeConnectToBrain(peer) == false, "connector_order_falls_back_to_uuid_when_addresses_tie");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.localBrainPeerAddress = IPAddress("fd00:10::29", true);
      brain.localBrainPeerAddressText = "fd00:10::29"_ctv;

      ClusterMachinePeerAddress localPrivate6 = {};
      localPrivate6.address = "fd00:10::29"_ctv;
      localPrivate6.cidr = 64;
      brain.localBrainPeerAddresses.push_back(localPrivate6);

      ClusterMachinePeerAddress localPublic6 = {};
      localPublic6.address = "2602:fac0:0:12ab:34cd::29"_ctv;
      localPublic6.cidr = 64;
      brain.localBrainPeerAddresses.push_back(localPublic6);

      BrainView *peer = makePeer(uint128_t(0x260), 1, 0, "2602:fac0:0:12ab:34cd::10");
      ClusterMachinePeerAddress peerPublic6 = {};
      peerPublic6.address = "2602:fac0:0:12ab:34cd::10"_ctv;
      peerPublic6.cidr = 64;
      peer->peerAddresses.push_back(peerPublic6);
      brain.brains.insert(peer);

      suite.expect(brain.shouldWeConnectToBrain(peer) == false, "connector_order_uses_matching_public6_candidate_before_private6");

      brain.configureBrainPeerConnectAddress(peer);
      IPAddress selectedSource = {};
      String selectedSourceText = {};
      suite.expect(
         prodigySockaddrToIPAddress(peer->saddr<struct sockaddr>(), selectedSource, &selectedSourceText),
         "connector_address_binds_source_candidate");
      suite.expect(selectedSourceText == "2602:fac0:0:12ab:34cd::29"_ctv, "connector_address_binds_matching_public6_source");
      suite.expect(
         prodigySockaddrToIPAddress(peer->daddr<struct sockaddr>(), selectedSource, &selectedSourceText),
         "connector_address_sets_destination_candidate");
      suite.expect(selectedSourceText == "2602:fac0:0:12ab:34cd::10"_ctv, "connector_address_sets_selected_public6_destination");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.localBrainPeerAddress = IPAddress("2602:fac0:0:12ab:34cd::29", true);
      brain.localBrainPeerAddressText = "2602:fac0:0:12ab:34cd::29"_ctv;

      ClusterMachinePeerAddress localPublic6 = {};
      localPublic6.address = "2602:fac0:0:12ab:34cd::29"_ctv;
      localPublic6.cidr = 64;
      brain.localBrainPeerAddresses.push_back(localPublic6);

      brain.configureBrainPeerConnectAddress(nullptr);
      suite.expect(true, "configure_brain_peer_connect_address_accepts_null_pointer");

      BrainView advancePeer = {};
      ClusterMachinePeerAddress advanceCandidate0 = {};
      advanceCandidate0.address = "2602:fac0:0:12ab:34cd::10"_ctv;
      advanceCandidate0.cidr = 64;
      ClusterMachinePeerAddress advanceCandidate1 = {};
      advanceCandidate1.address = "2602:fac0:0:12ab:34cd::11"_ctv;
      advanceCandidate1.cidr = 64;
      advancePeer.peerAddresses.push_back(advanceCandidate0);
      advancePeer.peerAddresses.push_back(advanceCandidate1);
      advancePeer.peerAddressIndex = 0;
      brain.configureBrainPeerConnectAddress(&advancePeer, true);
      suite.expect(advancePeer.peerAddressIndex == 1, "configure_brain_peer_connect_address_advances_candidate_index");
      IPAddress configuredAddress = {};
      String configuredAddressText = {};
      suite.expect(
         prodigySockaddrToIPAddress(advancePeer.daddr<struct sockaddr>(), configuredAddress, &configuredAddressText),
         "configure_brain_peer_connect_address_sets_advanced_destination");
      suite.expect(configuredAddressText == "2602:fac0:0:12ab:34cd::11"_ctv, "configure_brain_peer_connect_address_uses_advanced_candidate_destination");

      BrainView wrappedIndexPeer = {};
      wrappedIndexPeer.peerAddresses.push_back(advanceCandidate0);
      wrappedIndexPeer.peerAddresses.push_back(advanceCandidate1);
      wrappedIndexPeer.peerAddressIndex = 7;
      brain.configureBrainPeerConnectAddress(&wrappedIndexPeer);
      suite.expect(wrappedIndexPeer.peerAddressIndex == 0, "configure_brain_peer_connect_address_wraps_out_of_range_candidate_index");
      configuredAddress = {};
      configuredAddressText.clear();
      suite.expect(
         prodigySockaddrToIPAddress(wrappedIndexPeer.daddr<struct sockaddr>(), configuredAddress, &configuredAddressText),
         "configure_brain_peer_connect_address_sets_wrapped_destination");
      suite.expect(configuredAddressText == "2602:fac0:0:12ab:34cd::10"_ctv, "configure_brain_peer_connect_address_uses_wrapped_candidate_destination");

      BrainView fixedFilePeer = {};
      fixedFilePeer.peerAddress = IPAddress("10.0.0.30", false);
      fixedFilePeer.peerAddressText = "10.0.0.30"_ctv;
      fixedFilePeer.isFixedFile = true;
      fixedFilePeer.fslot = 5;
      brain.configureBrainPeerConnectAddress(&fixedFilePeer);
      suite.expect(fixedFilePeer.daddrLen == 0, "configure_brain_peer_connect_address_leaves_fixedfile_peer_untouched");

      BrainView fdPeerConfigured = {};
      fdPeerConfigured.peerAddress = IPAddress("10.0.0.31", false);
      fdPeerConfigured.peerAddressText = "10.0.0.31"_ctv;
      fdPeerConfigured.fd = 7;
      brain.configureBrainPeerConnectAddress(&fdPeerConfigured);
      suite.expect(fdPeerConfigured.daddrLen == 0, "configure_brain_peer_connect_address_leaves_active_fd_peer_untouched");

      BrainView mismatchedSourcePeer = {};
      ClusterMachinePeerAddress ipv4Candidate = {};
      ipv4Candidate.address = "10.0.0.20"_ctv;
      ipv4Candidate.cidr = 24;
      mismatchedSourcePeer.peerAddresses.push_back(ipv4Candidate);
      brain.configureBrainPeerConnectAddress(&mismatchedSourcePeer);
      suite.expect(mismatchedSourcePeer.saddrLen == 0, "configure_brain_peer_connect_address_skips_source_bind_when_candidate_family_mismatches");
      suite.expect(mismatchedSourcePeer.daddrLen > 0, "configure_brain_peer_connect_address_still_sets_destination_when_source_bind_skips");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.localBrainPeerAddress = IPAddress("fd00:1::10", true);
      brain.localBrainPeerAddressText = "fd00:1::10"_ctv;

      ClusterMachine explicitSelf = {};
      explicitSelf.uuid = neuron.uuid;
      prodigyAppendUniqueClusterMachineAddress(explicitSelf.addresses.privateAddresses, "fd00:1::10"_ctv);
      suite.expect(brain.clusterMachineMatchesThisBrain(explicitSelf), "self_match_accepts_explicit_peer_address");

      ClusterMachine stalePeerAddressOnly = {};
      ClusterMachinePeerAddress staleExplicitPeer = {};
      staleExplicitPeer.address = "fd00:1::20"_ctv;
      staleExplicitPeer.cidr = 64;
      Vector<ClusterMachinePeerAddress> staleCandidates = {};
      staleCandidates.push_back(staleExplicitPeer);
      prodigyAssignClusterMachineAddressesFromPeerCandidates(stalePeerAddressOnly.addresses, staleCandidates);
      suite.expect(brain.clusterMachineMatchesThisBrain(stalePeerAddressOnly) == false, "self_match_rejects_different_explicit_peer_address");

      ClusterMachine privateAddressOnly = {};
      prodigyAppendUniqueClusterMachineAddress(privateAddressOnly.addresses.privateAddresses, "10.0.0.10"_ctv, 24, "10.0.0.1"_ctv);
      suite.expect(brain.clusterMachineMatchesThisBrain(privateAddressOnly), "self_match_accepts_private_address_without_peer_candidate");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.boottimens = 10;

      BrainView *peerA = makePeer(uint128_t(0x400), 5);
      BrainView *peerB = makePeer(uint128_t(0x050), 50);
      brain.brains.insert(peerA);
      brain.brains.insert(peerB);

      suite.expect(brain.deriveRegisteredMasterUUID() == uint128_t(0x050), "derive_master_uuid_uses_lowest_uuid_not_boottime");

      brain.brains.erase(peerA);
      brain.brains.erase(peerB);
      delete peerA;
      delete peerB;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;

      BrainView *peerA = makePeer(uint128_t(0x200), 20, IPAddress("10.0.0.11", false).v4);
      peerA->connected = true;
      peerA->isFixedFile = true;
      peerA->fslot = 17;
      brain.brains.insert(peerA);

      BrainView *peerB = makePeer(uint128_t(0), 0, 0);
      brain.brains.insert(peerB);

      brain.testDeriveMasterBrain();

      suite.expect(brain.noMasterYet, "derive_master_brain_waits_for_full_initial_registration");
      suite.expect(brain.persistCalls == 0, "derive_master_brain_gate_return_skips_persist");
      suite.expect(peerA->isMasterBrain == false, "derive_master_brain_gate_return_does_not_mark_peer_master");

      brain.brains.erase(peerA);
      brain.brains.erase(peerB);
      delete peerA;
      delete peerB;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView peer = {};
      peer.weConnectToIt = false;
      peer.currentStreamAccepted = false;

      suite.expect(brain.testShouldReplaceActivePeerWithAcceptedStream(&peer, false), "brain_accept_prefers_canonical_inbound_over_fallback_outbound");

      peer.currentStreamAccepted = true;
      suite.expect(brain.testShouldReplaceActivePeerWithAcceptedStream(&peer, false) == false, "brain_accept_keeps_existing_canonical_inbound_stream");

      peer.weConnectToIt = true;
      peer.currentStreamAccepted = false;
      suite.expect(brain.testShouldReplaceActivePeerWithAcceptedStream(&peer, false) == false, "brain_accept_does_not_replace_connector_owned_outbound_stream");

      peer.weConnectToIt = false;
      peer.currentStreamAccepted = true;
      suite.expect(brain.testShouldReplaceActivePeerWithAcceptedStream(&peer, true), "brain_accept_replaces_expected_update_reconnect_even_when_inbound_active");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;

      BrainView *peerA = makePeer(uint128_t(0x050), 20, IPAddress("10.0.0.11", false).v4);
      peerA->connected = true;
      peerA->isFixedFile = true;
      peerA->fslot = 18;
      peerA->existingMasterUUID = uint128_t(0x050);
      brain.brains.insert(peerA);

      BrainView *peerB = makePeer(uint128_t(0x200), 30, IPAddress("10.0.0.12", false).v4);
      peerB->connected = true;
      peerB->isFixedFile = true;
      peerB->fslot = 19;
      peerB->existingMasterUUID = uint128_t(0x050);
      brain.brains.insert(peerB);

      brain.testDeriveMasterBrain();

      suite.expect(brain.noMasterYet == false, "derive_master_brain_adopts_consistent_existing_master");
      suite.expect(peerA->isMasterBrain, "derive_master_brain_marks_consistent_existing_master_peer");
      suite.expect(peerB->isMasterBrain == false, "derive_master_brain_does_not_mark_other_peer_master");
      suite.expect(peerA->existingMasterUUID == 0 && peerB->existingMasterUUID == 0, "derive_master_brain_clears_existing_master_votes_after_adoption");
      suite.expect(brain.persistCalls == 2, "derive_master_brain_persists_after_existing_master_adoption");

      brain.brains.erase(peerA);
      brain.brains.erase(peerB);
      delete peerA;
      delete peerB;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;

      BrainView *peerA = makePeer(uint128_t(0x050), 20, IPAddress("10.0.0.11", false).v4);
      peerA->connected = true;
      peerA->isFixedFile = true;
      peerA->fslot = 18;
      peerA->existingMasterUUID = uint128_t(0x900);
      brain.brains.insert(peerA);

      BrainView *peerB = makePeer(uint128_t(0x200), 30, IPAddress("10.0.0.12", false).v4);
      peerB->connected = true;
      peerB->isFixedFile = true;
      peerB->fslot = 19;
      peerB->existingMasterUUID = uint128_t(0x900);
      brain.brains.insert(peerB);

      brain.testDeriveMasterBrain();

      suite.expect(brain.noMasterYet == false, "derive_master_brain_unknown_existing_master_claim_falls_back");
      suite.expect(peerA->isMasterBrain, "derive_master_brain_unknown_existing_master_claim_elects_lowest_registered_peer");
      suite.expect(peerA->existingMasterUUID == 0 && peerB->existingMasterUUID == 0, "derive_master_brain_unknown_existing_master_claim_clears_votes");
      suite.expect(brain.persistCalls == 2, "derive_master_brain_unknown_existing_master_claim_persists");

      brain.brains.erase(peerA);
      brain.brains.erase(peerB);
      delete peerA;
      delete peerB;
   }

   withUniqueMothershipSocket("derive_master_brain_stale_existing_master_claim_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;

      BrainView *staleCandidate = makePeer(uint128_t(0x050), 0, IPAddress("10.0.0.13", false).v4);
      staleCandidate->connected = false;
      staleCandidate->isFixedFile = true;
      staleCandidate->fslot = 20;
      staleCandidate->existingMasterUUID = staleCandidate->uuid;
      brain.brains.insert(staleCandidate);

      BrainView *peerA = makePeer(uint128_t(0x200), 20, IPAddress("10.0.0.11", false).v4);
      peerA->connected = true;
      peerA->isFixedFile = true;
      peerA->fslot = 21;
      peerA->existingMasterUUID = staleCandidate->uuid;
      brain.brains.insert(peerA);

      BrainView *peerB = makePeer(uint128_t(0x300), 30, IPAddress("10.0.0.12", false).v4);
      peerB->connected = true;
      peerB->isFixedFile = true;
      peerB->fslot = 22;
      peerB->existingMasterUUID = staleCandidate->uuid;
      brain.brains.insert(peerB);

      brain.testDeriveMasterBrain();

      suite.expect(brain.weAreMaster, "derive_master_brain_stale_existing_master_claim_elects_self");
      suite.expect(staleCandidate->isMasterBrain == false, "derive_master_brain_stale_existing_master_claim_skips_stale_candidate");
      suite.expect(brain.noMasterYet == false, "derive_master_brain_stale_existing_master_claim_clears_no_master_flag");
      suite.expect(brain.persistCalls == 2, "derive_master_brain_stale_existing_master_claim_persists");

      brain.brains.erase(staleCandidate);
      brain.brains.erase(peerA);
      brain.brains.erase(peerB);
      delete staleCandidate;
      delete peerA;
      delete peerB;
   });

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;

      BrainView *peerA = makePeer(uint128_t(0x050), 20, IPAddress("10.0.0.11", false).v4);
      peerA->connected = true;
      peerA->isFixedFile = true;
      peerA->fslot = 23;
      brain.brains.insert(peerA);

      BrainView *peerB = makePeer(uint128_t(0x200), 30, IPAddress("10.0.0.12", false).v4);
      peerB->connected = true;
      peerB->isFixedFile = true;
      peerB->fslot = 24;
      brain.brains.insert(peerB);

      brain.testDeriveMasterBrain();

      suite.expect(peerA->isMasterBrain, "derive_master_brain_falls_back_to_lowest_registered_peer_uuid");
      suite.expect(brain.noMasterYet == false, "derive_master_brain_fallback_clears_no_master_flag");
      suite.expect(brain.persistCalls == 2, "derive_master_brain_fallback_persists");

      brain.brains.erase(peerA);
      brain.brains.erase(peerB);
      delete peerA;
      delete peerB;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;
      brain.hasCompletedInitialMasterElection = true;

      neuron.private4 = IPAddress("10.0.0.11", false);

      BrainView *peer = makePeer(uint128_t(0x200), 20, IPAddress("10.0.0.10", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 22;
      brain.brains.insert(peer);

      brain.testDeriveMasterBrain(false);

      suite.expect(brain.noMasterYet, "derive_master_brain_failover_waits_for_lower_address_peer");
      suite.expect(peer->isMasterBrain == false, "derive_master_brain_failover_wait_does_not_mark_master");
      suite.expect(brain.persistCalls == 0, "derive_master_brain_failover_wait_skips_persist");

      brain.brains.erase(peer);
      delete peer;
      neuron.private4 = IPAddress("10.0.0.10", false);
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;
      brain.hasCompletedInitialMasterElection = true;

      BrainView *peer = makePeer(uint128_t(0x200), 20, 0);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 31;
      brain.brains.insert(peer);

      brain.testDeriveMasterBrain(false);

      suite.expect(brain.noMasterYet, "derive_master_brain_waits_for_active_peer_identity_convergence_before_existing_claims");
      suite.expect(brain.persistCalls == 0, "derive_master_brain_identity_convergence_wait_skips_persist");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;
      brain.isMasterMissing = true;
      brain.overrideMetroReachabilityCheck = true;
      brain.forcedConnectedMajorityAfterMetroCheck = true;
      brain.forcedReachableSwitchMajority = true;

      BrainView *peerA = makePeer(uint128_t(0x050), 20, IPAddress("10.0.0.12", false).v4);
      peerA->connected = false;
      peerA->isFixedFile = true;
      peerA->fslot = 53;
      brain.brains.insert(peerA);

      BrainView *peerB = makePeer(uint128_t(0x200), 30, IPAddress("10.0.0.13", false).v4);
      peerB->connected = false;
      peerB->isFixedFile = true;
      peerB->fslot = 54;
      brain.brains.insert(peerB);

      brain.testDeriveMasterBrainIf();

      suite.expect(brain.metroReachabilityChecks == 1, "derive_master_brain_if_non_majority_runs_metro_check");
      suite.expect(peerA->isMasterBrain, "derive_master_brain_if_metro_majority_rederives_master");
      suite.expect(brain.persistCalls == 2, "derive_master_brain_if_metro_majority_persists");

      brain.brains.erase(peerA);
      brain.brains.erase(peerB);
      delete peerA;
      delete peerB;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;
      brain.isMasterMissing = true;
      brain.overrideMetroReachabilityCheck = true;
      brain.forcedConnectedMajorityAfterMetroCheck = false;
      brain.forcedReachableSwitchMajority = false;

      BrainView *peerA = makePeer(uint128_t(0x050), 20, IPAddress("10.0.0.12", false).v4);
      peerA->connected = false;
      peerA->isFixedFile = true;
      peerA->fslot = 55;
      brain.brains.insert(peerA);

      BrainView *peerB = makePeer(uint128_t(0x200), 30, IPAddress("10.0.0.13", false).v4);
      peerB->connected = false;
      peerB->isFixedFile = true;
      peerB->fslot = 56;
      brain.brains.insert(peerB);

      brain.testDeriveMasterBrainIf();

      suite.expect(brain.metroReachabilityChecks == 1, "derive_master_brain_if_non_majority_failed_check_runs_once");
      suite.expect(brain.noMasterYet, "derive_master_brain_if_non_majority_failed_check_keeps_no_master");
      suite.expect(brain.persistCalls == 0, "derive_master_brain_if_non_majority_failed_check_skips_persist");

      brain.brains.erase(peerA);
      brain.brains.erase(peerB);
      delete peerA;
      delete peerB;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;
      brain.hasCompletedInitialMasterElection = true;

      BrainView *peer = makePeer(uint128_t(0), 20, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 32;
      brain.brains.insert(peer);

      brain.testDeriveMasterBrain();

      suite.expect(brain.noMasterYet, "derive_master_brain_waits_for_active_peer_registration");
      suite.expect(brain.persistCalls == 0, "derive_master_brain_active_registration_wait_skips_persist");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;

      BrainView *peer = makePeer(uint128_t(0x050), 20, IPAddress("10.0.0.11", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 23;
      brain.brains.insert(peer);

      BrainView *peerB = makePeer(uint128_t(0x200), 30, IPAddress("10.0.0.12", false).v4);
      peerB->connected = true;
      peerB->isFixedFile = true;
      peerB->fslot = 24;
      brain.brains.insert(peerB);

      brain.testDeriveMasterBrainIf();

      suite.expect(peer->isMasterBrain, "derive_master_brain_if_majority_reuses_master_derivation");
      suite.expect(brain.persistCalls == 2, "derive_master_brain_if_majority_persists");

      brain.brains.erase(peer);
      brain.brains.erase(peerB);
      delete peer;
      delete peerB;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;
      brain.hasCompletedInitialMasterElection = true;

      BrainView *peer = makePeer(uint128_t(0x200), 20, 0);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 33;
      brain.brains.insert(peer);

      brain.testDeriveMasterBrain();

      suite.expect(brain.noMasterYet, "derive_master_brain_second_failover_waits_for_identity_convergence");
      suite.expect(brain.persistCalls == 0, "derive_master_brain_second_failover_identity_wait_skips_persist");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;
      brain.hasCompletedInitialMasterElection = true;

      neuron.private4 = IPAddress("10.0.0.11", false);

      BrainView *peer = makePeer(uint128_t(0x200), 20, IPAddress("10.0.0.10", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 37;
      brain.brains.insert(peer);

      brain.testDeriveMasterBrain();

      suite.expect(brain.noMasterYet, "derive_master_brain_second_failover_waits_for_lower_address_peer");
      suite.expect(brain.persistCalls == 0, "derive_master_brain_second_failover_lower_peer_wait_skips_persist");

      brain.brains.erase(peer);
      delete peer;
      neuron.private4 = IPAddress("10.0.0.10", false);
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      brain.noMasterYet = true;
      brain.pendingDesignatedMasterPeerKey = uint128_t(0x444);
      brain.hasCompletedInitialMasterElection = false;

      brain.testElectBrainToMaster(nullptr);

      suite.expect(brain.noMasterYet, "elect_brain_to_master_null_preserves_no_master_flag");
      suite.expect(brain.pendingDesignatedMasterPeerKey == uint128_t(0x444), "elect_brain_to_master_null_preserves_pending_designated_master");
      suite.expect(brain.hasCompletedInitialMasterElection == false, "elect_brain_to_master_null_preserves_initial_election_flag");
      suite.expect(brain.persistCalls == 0, "elect_brain_to_master_null_skips_persist");
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = false;
      brain.noMasterYet = true;
      brain.pendingDesignatedMasterPeerKey = uint128_t(0x555);

      auto makeSocketPair = [&suite](const char *fixtureName, int (&fds)[2]) -> bool
      {
         if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0)
         {
            suite.expect(false, fixtureName);
            fds[0] = -1;
            fds[1] = -1;
            return false;
         }

         return true;
      };

      int mothershipTcpPair[2] = {-1, -1};
      int mothershipUnixPair[2] = {-1, -1};
      int mothershipStreamPair[2] = {-1, -1};
      int neuronPair[2] = {-1, -1};

      if (makeSocketPair("elect_brain_to_master_follower_convergence_creates_mothership_tcp_pair", mothershipTcpPair) &&
          makeSocketPair("elect_brain_to_master_follower_convergence_creates_mothership_unix_pair", mothershipUnixPair) &&
          makeSocketPair("elect_brain_to_master_follower_convergence_creates_mothership_stream_pair", mothershipStreamPair) &&
          makeSocketPair("elect_brain_to_master_follower_convergence_creates_neuron_pair", neuronPair))
      {
	         brain.mothershipSocket.fd = mothershipTcpPair[0];
	         brain.mothershipSocket.isFixedFile = false;
	         brain.mothershipUnixSocket.fd = mothershipUnixPair[0];
	         brain.mothershipUnixSocket.isFixedFile = false;

	         char followerSocketDirectoryTemplate[] = "/tmp/prodigy-brain-follower-master-XXXXXX";
	         char *followerSocketDirectory = ::mkdtemp(followerSocketDirectoryTemplate);
	         String followerSocketPath = {};
	         int staleFollowerListenerFD = -1;
	         suite.expect(followerSocketDirectory != nullptr,
	            "elect_brain_to_master_follower_convergence_creates_stale_unix_socket_dir");
	         if (followerSocketDirectory != nullptr)
	         {
	            followerSocketPath.assign(followerSocketDirectory);
	            followerSocketPath.append("/mothership.sock"_ctv);
	            suite.expect(createUnixListener(followerSocketPath, staleFollowerListenerFD),
	               "elect_brain_to_master_follower_convergence_creates_stale_unix_socket_path");
	            suite.expect(::access(followerSocketPath.c_str(), F_OK) == 0,
	               "elect_brain_to_master_follower_convergence_stale_unix_socket_path_exists_before");
	            brain.mothershipUnixSocketPath.assign(followerSocketPath);
	         }

	         Mothership *staleMothership = new Mothership();
	         staleMothership->fd = mothershipStreamPair[0];
         staleMothership->isFixedFile = false;
         staleMothership->closeAfterSendDrain = true;
         brain.testRegisterActiveMothership(staleMothership);

         Machine machine = {};
         machine.neuron.machine = &machine;
         machine.neuron.fd = neuronPair[0];
         machine.neuron.isFixedFile = false;
         machine.neuron.connected = true;
         machine.neuron.reconnectAfterClose = true;
         machine.neuron.nConnectionAttempts = 4;
         machine.neuron.nAttemptsBudget = 9;
         brain.neurons.insert(&machine.neuron);

         BrainView *peer = makePeer(uint128_t(0x300), 20, IPAddress("10.0.0.12", false).v4);
         brain.testElectBrainToMaster(peer);

         suite.expect(peer->isMasterBrain, "elect_brain_to_master_follower_convergence_marks_peer_master");
         suite.expect(brain.noMasterYet == false, "elect_brain_to_master_follower_convergence_clears_no_master_flag");
         suite.expect(brain.pendingDesignatedMasterPeerKey == 0, "elect_brain_to_master_follower_convergence_clears_pending_designated_master");
         suite.expect(brain.hasCompletedInitialMasterElection, "elect_brain_to_master_follower_convergence_marks_initial_election_complete");
         suite.expect(brain.persistCalls == 1, "elect_brain_to_master_follower_convergence_persists");
	         suite.expect(Ring::socketIsClosing(&brain.mothershipSocket), "elect_brain_to_master_follower_convergence_closes_mothership_tcp_listener");
	         suite.expect(Ring::socketIsClosing(&brain.mothershipUnixSocket), "elect_brain_to_master_follower_convergence_closes_mothership_unix_listener");
		         if (followerSocketPath.size() > 0)
		         {
		            suite.expect(::access(followerSocketPath.c_str(), F_OK) == 0,
		               "elect_brain_to_master_follower_convergence_preserves_unowned_unix_socket_path");
		         }
	         suite.expect(Ring::socketIsClosing(staleMothership), "elect_brain_to_master_follower_convergence_closes_active_mothership_stream");
	         suite.expect(staleMothership->closeAfterSendDrain == false, "elect_brain_to_master_follower_convergence_disables_mothership_drain_close");
	         suite.expect(brain.mothership == nullptr, "elect_brain_to_master_follower_convergence_clears_active_mothership_stream");
         suite.expect(brain.closingMotherships.contains(staleMothership), "elect_brain_to_master_follower_convergence_tracks_retired_mothership_stream");
         suite.expect(machine.neuron.reconnectAfterClose == false, "elect_brain_to_master_follower_convergence_disarms_neuron_reconnect");
         suite.expect(machine.neuron.nConnectionAttempts == 0, "elect_brain_to_master_follower_convergence_resets_neuron_attempts");
         suite.expect(machine.neuron.nAttemptsBudget == 0, "elect_brain_to_master_follower_convergence_resets_neuron_budget");
         suite.expect(machine.neuron.connected == false, "elect_brain_to_master_follower_convergence_marks_neuron_disconnected");
         suite.expect(Ring::socketIsClosing(&machine.neuron), "elect_brain_to_master_follower_convergence_closes_neuron_control_stream");

         brain.neurons.erase(&machine.neuron);
	         brain.closingMotherships.erase(staleMothership);
	         delete staleMothership;
	         delete peer;
	         if (staleFollowerListenerFD >= 0)
	         {
	            ::close(staleFollowerListenerFD);
	         }
	         if (followerSocketPath.size() > 0)
	         {
	            ::unlink(followerSocketPath.c_str());
	         }
	         if (followerSocketDirectory != nullptr)
	         {
	            ::rmdir(followerSocketDirectory);
	         }
	      }

      for (int *fds : {mothershipTcpPair, mothershipUnixPair, mothershipStreamPair, neuronPair})
      {
         if (fds[0] >= 0)
         {
            ::close(fds[0]);
         }

         if (fds[1] >= 0)
         {
            ::close(fds[1]);
         }
      }
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.noMasterYet = false;
      brain.pendingDesignatedMasterPeerKey = uint128_t(0x666);

      Machine machine = {};
      machine.neuron.machine = &machine;
      machine.neuron.connected = true;
      machine.neuron.reconnectAfterClose = true;
      machine.neuron.nConnectionAttempts = 5;
      machine.neuron.nAttemptsBudget = 11;
      brain.neurons.insert(&machine.neuron);

      BrainView *peer = makePeer(uint128_t(0x301), 21, IPAddress("10.0.0.13", false).v4);
      brain.testElectBrainToMaster(peer);

      suite.expect(brain.weAreMaster == false, "elect_brain_to_master_master_handoff_clears_local_master_flag");
      suite.expect(peer->isMasterBrain, "elect_brain_to_master_master_handoff_marks_peer_master");
      suite.expect(brain.noMasterYet == false, "elect_brain_to_master_master_handoff_clears_no_master_flag_after_handoff");
      suite.expect(brain.pendingDesignatedMasterPeerKey == 0, "elect_brain_to_master_master_handoff_clears_pending_designated_master");
      suite.expect(machine.neuron.reconnectAfterClose == false, "elect_brain_to_master_master_handoff_disarms_neuron_reconnect");
      suite.expect(machine.neuron.nConnectionAttempts == 0, "elect_brain_to_master_master_handoff_resets_neuron_attempts");
      suite.expect(machine.neuron.nAttemptsBudget == 0, "elect_brain_to_master_master_handoff_resets_neuron_budget");
      suite.expect(machine.neuron.connected == false, "elect_brain_to_master_master_handoff_marks_neuron_disconnected");
      suite.expect(brain.persistCalls == 1, "elect_brain_to_master_master_handoff_persists");

      brain.neurons.erase(&machine.neuron);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x300), 20, IPAddress("10.0.0.12", false).v4);
      brain.testElectBrainToMaster(peer);

      suite.expect(peer->isMasterBrain, "elect_brain_to_master_marks_peer_master");
      suite.expect(brain.noMasterYet == false, "elect_brain_to_master_clears_no_master_flag");
      suite.expect(brain.persistCalls == 1, "elect_brain_to_master_persists");

      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.pendingDesignatedMasterPeerKey = uint128_t(IPAddress("10.0.0.12", false).v4);

      BrainView *peer = makePeer(uint128_t(0x050), 20, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 39;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::registration,
         uint128_t(0x200),
         int64_t(20),
         uint64_t(7),
         uint128_t(0));
      brain.testBrainHandler(peer, message);

      suite.expect(peer->isMasterBrain, "registration_pending_designated_master_elects_peer");
      suite.expect(brain.noMasterYet == false, "registration_pending_designated_master_clears_no_master_flag");
      suite.expect(brain.persistCalls == 1, "registration_pending_designated_master_persists_peer_election");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.updateSelfState = TestBrain::UpdateSelfState::waitingForFollowerReboots;
      brain.pendingDesignatedMasterPeerKey = uint128_t(IPAddress("10.0.0.12", false).v4);

      BrainView *peer = makePeer(uint128_t(0), 0, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 40;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::registration,
         uint128_t(0x200),
         int64_t(20),
         uint64_t(8),
         uint128_t(0));
      brain.testBrainHandler(peer, message);

      suite.expect(peer->isMasterBrain, "registration_update_self_waiting_follower_reboots_elects_designated_peer");
      suite.expect(brain.updateSelfState == TestBrain::UpdateSelfState::waitingForFollowerReboots, "registration_update_self_waiting_follower_reboots_keeps_state");

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();

	      BrainView *peer = makePeer(uint128_t(0x060), 21, IPAddress("10.0.0.13", false).v4);
	      peer->connected = true;
	      peer->isFixedFile = true;
	      peer->fslot = 46;
	      brain.brains.insert(peer);

	      String buffer = {};
	      Message *message = buildBrainMessage(buffer, BrainTopic::peerHeartbeat, false, uint64_t(7));
	      brain.testBrainHandler(peer, message);

	      Message *queued = (peer->wBuffer.size() > 0 ? reinterpret_cast<Message *>(peer->wBuffer.data()) : nullptr);
	      uint8_t *queuedArgs = (queued ? queued->args : nullptr);
	      bool echoedResponse = false;
	      uint64_t echoedNonce = 0;
	      bool parsedEchoedNonce = (
	         queuedArgs
	         && Message::extractArg<ArgumentNature::fixed>(queuedArgs, echoedResponse)
	         && Message::extractArg<ArgumentNature::fixed>(queuedArgs, echoedNonce));
	      suite.expect(peer->lastReceiveMs > 0, "peer_heartbeat_request_updates_last_receive");
	      suite.expect(queued != nullptr && BrainTopic(queued->topic) == BrainTopic::peerHeartbeat, "peer_heartbeat_request_queues_response");
	      suite.expect(parsedEchoedNonce && echoedResponse && echoedNonce == 7, "peer_heartbeat_request_preserves_nonce");

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();

	      BrainView *peer = makePeer(uint128_t(0x0601), 211, IPAddress("10.0.0.23", false).v4);
	      peer->connected = true;
	      peer->isFixedFile = true;
	      peer->fslot = 461;
	      peer->lastHeartbeatSentNonce = 11;
	      brain.brains.insert(peer);

	      String buffer = {};
	      Message *message = buildBrainMessage(buffer, BrainTopic::peerHeartbeat, true, uint64_t(11));
	      brain.testBrainHandler(peer, message);

	      suite.expect(peer->lastHeartbeatAckNonce == 11, "peer_heartbeat_response_updates_ack_nonce");
	      suite.expect(peer->lastHeartbeatAckMs > 0, "peer_heartbeat_response_updates_ack_time");

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      ScopedRing scopedRing = {};

	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.nBrains = 3;
	      brain.weAreMaster = true;
	      brain.noMasterYet = false;
	      brain.brainPeerHeartbeatIntervalMs = 1000;
	      brain.brainPeerHeartbeatTimeoutMs = 1;
	      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
	      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

	      BrainView *peerA = makePeer(uint128_t(0x0607), 217, IPAddress("10.0.0.11", false).v4, "10.0.0.11");
	      peerA->connected = true;
	      int peerAFD = -1;

	      BrainView *peerB = makePeer(uint128_t(0x0608), 218, IPAddress("10.0.0.12", false).v4, "10.0.0.12");
	      peerB->connected = true;
	      int peerBFD = -1;

	      bool installedA = installBrainPeerSocket(brain, *peerA, peerAFD);
	      bool installedB = installBrainPeerSocket(brain, *peerB, peerBFD);
	      suite.expect(installedA && installedB, "master_heartbeat_majority_loss_installs_peer_sockets");
	      if (installedA && installedB)
	      {
	         brain.brains.insert(peerA);
	         brain.brains.insert(peerB);
	         peerA->noteTransportActivated();
	         peerB->noteTransportActivated();
	         peerA->lastHeartbeatAckMs = Time::now<TimeResolution::ms>() - 10;
	         peerA->lastReceiveMs = peerA->lastHeartbeatAckMs;
	         peerA->lastHeartbeatSendMs = peerA->lastHeartbeatAckMs;
	         peerA->lastHeartbeatSentNonce = 2;
	         peerA->lastHeartbeatAckNonce = 1;
	         peerB->lastHeartbeatAckMs = Time::now<TimeResolution::ms>() - 10;
	         peerB->lastReceiveMs = peerB->lastHeartbeatAckMs;
	         peerB->lastHeartbeatSendMs = peerB->lastHeartbeatAckMs;
	         peerB->lastHeartbeatSentNonce = 2;
	         peerB->lastHeartbeatAckNonce = 1;

	         brain.testRunBrainPeerHeartbeatTick();

	         suite.expect(peerA->quarantined, "master_heartbeat_majority_loss_quarantines_first_stale_peer");
	         suite.expect(peerB->quarantined, "master_heartbeat_majority_loss_quarantines_second_stale_peer");
	         suite.expect(Ring::socketIsClosing(peerA), "master_heartbeat_majority_loss_closes_first_stale_peer");
	         suite.expect(Ring::socketIsClosing(peerB), "master_heartbeat_majority_loss_closes_second_stale_peer");
	         suite.expect(brain.weAreMaster == false, "master_heartbeat_majority_loss_forfeits_master");
	         suite.expect(brain.noMasterYet, "master_heartbeat_majority_loss_returns_to_no_master");

	         cleanupBrainPeerSocket(*peerA, peerAFD);
	         cleanupBrainPeerSocket(*peerB, peerBFD);
	      }
	      else
	      {
	         if (installedA)
	         {
	            cleanupBrainPeerSocket(*peerA, peerAFD);
	         }
	         if (installedB)
	         {
	            cleanupBrainPeerSocket(*peerB, peerBFD);
	         }
	      }

	      brain.brains.erase(peerA);
	      brain.brains.erase(peerB);
	      delete peerA;
	      delete peerB;
	   }

	   {
	      ScopedRing scopedRing = {};

	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.nBrains = 3;
	      brain.noMasterYet = false;
	      brain.brainPeerHeartbeatTimeoutMs = 1234;

	      BrainView *peer = makePeer(uint128_t(0x0602), 212, IPAddress("10.0.0.24", false).v4);
	      peer->connected = true;
	      int peerFD = -1;
	      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
	      suite.expect(installed, "master_liveness_registration_installs_socket");
	      if (installed)
	      {
	         brain.brains.insert(peer);

	         String buffer = {};
	         Message *message = buildBrainMessage(
	            buffer,
	            BrainTopic::registration,
	            peer->uuid,
	            peer->boottimens,
	            uint64_t(3),
	            peer->uuid);
	         brain.testBrainHandler(peer, message);

	         TimeoutPacket *waiter = brain.testGetBrainLivenessWaiter(peer);
	         suite.expect(waiter != nullptr, "master_liveness_registration_arms_waiter");
	         suite.expect(waiter != nullptr && waiter->timeoutMs() == 1234, "master_liveness_registration_uses_heartbeat_timeout");

	         cleanupBrainPeerSocket(*peer, peerFD);
	         brain.testCancelBrainLivenessWaiter(peer, "unit-cleanup");
	      }

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      ScopedRing scopedRing = {};

	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();

	      BrainView *peer = makePeer(uint128_t(0x0606), 216, IPAddress("10.0.0.28", false).v4);
	      peer->connected = true;
	      int peerFD = -1;
	      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
	      suite.expect(installed, "brain_recv_partial_frame_liveness_installs_socket");
	      if (installed)
	      {
	         brain.brains.insert(peer);
	         peer->pendingRecv = true;
	         peer->lastReceiveMs = Time::now<TimeResolution::ms>() - 1000;
	         int64_t oldLastReceiveMs = peer->lastReceiveMs;

	         String frame = {};
	         Message::construct(frame, BrainTopic::peerHeartbeat, false, uint64_t(99));
	         memcpy(peer->rBuffer.pTail(), frame.data(), sizeof(uint32_t));
	         peer->connected = false;

	         brain.testRecvHandler(peer, int(sizeof(uint32_t)));

	         suite.expect(peer->lastReceiveMs > oldLastReceiveMs, "brain_recv_partial_frame_liveness_updates_last_receive_without_complete_message");
	         suite.expect(peer->rBuffer.outstandingBytes() == sizeof(uint32_t), "brain_recv_partial_frame_liveness_preserves_partial_frame");
	         suite.expect(peer->pendingRecv == false, "brain_recv_partial_frame_liveness_does_not_leave_pending_recv");
	         suite.expect(Ring::socketIsClosing(peer) == false, "brain_recv_partial_frame_liveness_keeps_peer_open");

	         cleanupBrainPeerSocket(*peer, peerFD);
	      }

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      ScopedRing scopedRing = {};

	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.nBrains = 3;
	      brain.noMasterYet = false;
	      brain.brainPeerHeartbeatTimeoutMs = 2000;

	      BrainView *peer = makePeer(uint128_t(0x0603), 213, IPAddress("10.0.0.25", false).v4);
	      peer->existingMasterUUID = peer->uuid;
	      peer->connected = true;
	      peer->lastHeartbeatSentNonce = 71;
	      int peerFD = -1;
	      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
	      suite.expect(installed, "master_liveness_message_refresh_installs_socket");
	      if (installed)
	      {
	         brain.brains.insert(peer);
	         brain.testRefreshMasterPeerLivenessWaiter(peer, "first");
	         TimeoutPacket *firstWaiter = brain.testGetBrainLivenessWaiter(peer);

	         String requestBuffer = {};
	         Message *request = buildBrainMessage(requestBuffer, BrainTopic::peerHeartbeat, false, uint64_t(70));
	         brain.testBrainHandler(peer, request);
	         suite.expect(brain.testGetBrainLivenessWaiter(peer) == firstWaiter, "master_liveness_message_refresh_ignores_heartbeat_request");

	         String buffer = {};
	         Message *message = buildBrainMessage(buffer, BrainTopic::peerHeartbeat, true, uint64_t(71));
	         brain.testBrainHandler(peer, message);

	         TimeoutPacket *refreshedWaiter = brain.testGetBrainLivenessWaiter(peer);
	         suite.expect(firstWaiter != nullptr, "master_liveness_message_refresh_fixture_arms_waiter");
	         suite.expect(refreshedWaiter != nullptr, "master_liveness_message_refresh_keeps_waiter");
	         suite.expect(refreshedWaiter != firstWaiter, "master_liveness_message_refresh_replaces_waiter");
	         suite.expect(firstWaiter != nullptr && firstWaiter->flags == uint64_t(BrainTimeoutFlags::canceled), "master_liveness_message_refresh_cancels_old_waiter");

	         cleanupBrainPeerSocket(*peer, peerFD);
	         brain.testCancelBrainLivenessWaiter(peer, "unit-cleanup");
	      }

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      ScopedRing scopedRing = {};

	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.nBrains = 3;
	      brain.noMasterYet = false;
	      brain.brainPeerHeartbeatTimeoutMs = 2000;

	      BrainView *peer = makePeer(uint128_t(0x0604), 214, IPAddress("10.0.0.26", false).v4);
	      peer->existingMasterUUID = peer->uuid;
	      peer->connected = true;
	      int peerFD = -1;
	      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
	      suite.expect(installed, "master_liveness_timeout_installs_socket");
	      if (installed)
	      {
	         brain.brains.insert(peer);
	         peer->noteTransportActivated();
	         brain.testRefreshMasterPeerLivenessWaiter(peer, "timeout-fixture");
	         TimeoutPacket *waiter = brain.testGetBrainLivenessWaiter(peer);
	         suite.expect(waiter != nullptr, "master_liveness_timeout_fixture_arms_waiter");
	         if (waiter != nullptr)
	         {
	            brain.testDispatchTimeout(waiter);
	         }

	         suite.expect(brain.testHasBrainLivenessWaiter(peer) == false, "master_liveness_timeout_clears_waiter");
	         suite.expect(peer->confirmedMissingTransportEpoch == peer->transportEpoch, "master_liveness_timeout_marks_confirmed_missing_epoch");
	         suite.expect(peer->queuedCloseTransportEpoch == peer->transportEpoch, "master_liveness_timeout_queues_close_for_current_master");
	         suite.expect(Ring::socketIsClosing(peer), "master_liveness_timeout_marks_current_master_closing");

	         cleanupBrainPeerSocket(*peer, peerFD);
	      }

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      ScopedRing scopedRing = {};

	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.nBrains = 3;
	      brain.noMasterYet = false;
	      brain.brainPeerHeartbeatTimeoutMs = 2000;

	      BrainView *peer = makePeer(uint128_t(0x0605), 215, IPAddress("10.0.0.27", false).v4);
	      peer->connected = true;
	      int peerFD = -1;
	      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
	      suite.expect(installed, "master_liveness_non_master_timeout_installs_socket");
	      if (installed)
	      {
	         brain.brains.insert(peer);
	         peer->noteTransportActivated();

	         TimeoutPacket *waiter = brain.testInsertBrainLivenessWaiter(peer);
	         brain.testDispatchTimeout(waiter);

	         suite.expect(brain.testHasBrainLivenessWaiter(peer) == false, "master_liveness_non_master_timeout_clears_waiter");
	         suite.expect(peer->confirmedMissingTransportEpoch == 0, "master_liveness_non_master_timeout_keeps_confirmed_missing_clear");
	         suite.expect(Ring::socketIsClosing(peer) == false, "master_liveness_non_master_timeout_keeps_peer_open");

	         cleanupBrainPeerSocket(*peer, peerFD);
	      }

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      ScopedRing scopedRing = {};

	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.brainPeerHeartbeatIntervalMs = 1;
	      brain.brainPeerHeartbeatTimeoutMs = 1000;

	      BrainView *peer = makePeer(uint128_t(0x061), 22, IPAddress("10.0.0.14", false).v4);
	      peer->connected = true;
	      int peerFD = -1;
	      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
	      suite.expect(installed, "brain_peer_heartbeat_tick_installs_socket");
	      if (installed)
	      {
	         peer->lastReceiveMs = Time::now<TimeResolution::ms>();
	         brain.brains.insert(peer);

	         brain.runBrainPeerHeartbeatTick();

	         Message *queued = (peer->wBuffer.size() > 0 ? reinterpret_cast<Message *>(peer->wBuffer.data()) : nullptr);
	         uint8_t *queuedArgs = (queued ? queued->args : nullptr);
	         bool queuedResponse = true;
	         uint64_t queuedNonce = 0;
	         bool parsedQueuedNonce = (
	            queuedArgs
	            && Message::extractArg<ArgumentNature::fixed>(queuedArgs, queuedResponse)
	            && Message::extractArg<ArgumentNature::fixed>(queuedArgs, queuedNonce));
	         suite.expect(peer->lastHeartbeatSendMs > 0, "brain_peer_heartbeat_tick_records_send_time");
	         suite.expect(peer->lastHeartbeatSentNonce == 1, "brain_peer_heartbeat_tick_records_sent_nonce");
	         suite.expect(queued != nullptr && BrainTopic(queued->topic) == BrainTopic::peerHeartbeat, "brain_peer_heartbeat_tick_queues_ping");
	         suite.expect(queued != nullptr && queued->isEcho() == false, "brain_peer_heartbeat_tick_queues_request_payload");
	         suite.expect(parsedQueuedNonce && queuedResponse == false && queuedNonce == 1, "brain_peer_heartbeat_tick_queues_nonce");

	         cleanupBrainPeerSocket(*peer, peerFD);
	      }

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      ScopedRing scopedRing = {};

	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.weAreMaster = true;
	      brain.noMasterYet = false;
	      brain.boottimens = 10;
	      brain.version = 77;
	      brain.localBrainPeerAddress = IPAddress("10.0.0.20", false);
	      brain.localBrainPeerAddressText = "10.0.0.20"_ctv;
	      brain.brainPeerHeartbeatIntervalMs = 1;
	      brain.brainPeerHeartbeatTimeoutMs = 1000;

	      BrainView *peer = makePeer(uint128_t(0x0612), 222, IPAddress("10.0.0.18", false).v4, "10.0.0.18");
	      peer->connected = false;
	      peer->isFixedFile = false;
	      peer->fd = -1;
	      brain.brains.insert(peer);

	      brain.runBrainPeerHeartbeatTick();

	      suite.expect(peer->reconnectAfterClose, "brain_peer_heartbeat_tick_master_arms_force_reconnect_until_ack_when_peer_inactive_arms_reconnect");
	      suite.expect(peer->connectAttemptPending(), "brain_peer_heartbeat_tick_master_arms_force_reconnect_until_ack_when_peer_inactive_submits_connect_attempt");

	      if (peer->isFixedFile)
	      {
	         Ring::uninstallFromFixedFileSlot(peer);
	      }
	      else if (peer->fd >= 0)
	      {
	         ::close(peer->fd);
	      }
	      peer->fd = -1;
	      peer->isFixedFile = false;

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      ScopedRing scopedRing = {};

	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.weAreMaster = true;
	      brain.noMasterYet = false;
	      brain.boottimens = 10;
	      brain.version = 77;
	      brain.brainPeerHeartbeatIntervalMs = 1;
	      brain.brainPeerHeartbeatTimeoutMs = 1000;

	      BrainView *peer = makePeer(uint128_t(0x0611), 221, IPAddress("10.0.0.18", false).v4);
	      peer->connected = true;
	      int peerFD = -1;
	      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
	      suite.expect(installed, "brain_peer_heartbeat_tick_master_installs_socket");
	      if (installed)
	      {
	         peer->lastReceiveMs = Time::now<TimeResolution::ms>();
	         brain.brains.insert(peer);

	         brain.runBrainPeerHeartbeatTick();

	         bool sawRegistration = false;
	         bool sawHeartbeat = false;
	         uint128_t registrationUUID = 0;
	         uint128_t advertisedMasterUUID = 0;
	         forEachMessageInBuffer(peer->wBuffer, [&] (Message *message) {
	            if (BrainTopic(message->topic) == BrainTopic::registration)
	            {
	               uint8_t *args = message->args;
	               int64_t echoedBoottimens = 0;
	               uint64_t echoedVersion = 0;
	               (void)Message::extractArg<ArgumentNature::fixed>(args, registrationUUID);
	               (void)Message::extractArg<ArgumentNature::fixed>(args, echoedBoottimens);
	               (void)Message::extractArg<ArgumentNature::fixed>(args, echoedVersion);
	               (void)Message::extractArg<ArgumentNature::fixed>(args, advertisedMasterUUID);
	               sawRegistration = true;
	            }
	            else if (BrainTopic(message->topic) == BrainTopic::peerHeartbeat)
	            {
	               sawHeartbeat = true;
	            }
	         });

	         suite.expect(sawRegistration, "brain_peer_heartbeat_tick_master_advertises_registration_until_ack");
	         suite.expect(registrationUUID == neuron.uuid, "brain_peer_heartbeat_tick_master_advertises_self_uuid");
	         suite.expect(advertisedMasterUUID == neuron.uuid, "brain_peer_heartbeat_tick_master_advertises_self_master_uuid");
	         suite.expect(peer->lastMasterRegistrationAdvertiseMs > 0, "brain_peer_heartbeat_tick_master_records_registration_advertise_time");
	         suite.expect(sawHeartbeat, "brain_peer_heartbeat_tick_master_still_queues_heartbeat");

	         cleanupBrainPeerSocket(*peer, peerFD);
	      }

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      ScopedRing scopedRing = {};

	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.brainPeerHeartbeatIntervalMs = 1000;
	      brain.brainPeerHeartbeatTimeoutMs = 1;

	      BrainView *peer = makePeer(uint128_t(0x062), 23, IPAddress("10.0.0.15", false).v4);
	      peer->connected = true;
	      int peerFD = -1;
	      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
	      suite.expect(installed, "brain_peer_heartbeat_tick_stale_peer_installs_socket");
	      if (installed)
	      {
	         peer->noteTransportActivated();
	         peer->lastHeartbeatAckMs = Time::now<TimeResolution::ms>() - 10;
	         peer->lastReceiveMs = Time::now<TimeResolution::ms>() - 10;
	         peer->lastHeartbeatSendMs = peer->lastHeartbeatAckMs;
	         peer->lastHeartbeatSentNonce = 2;
	         peer->lastHeartbeatAckNonce = 1;
	         brain.brains.insert(peer);

	         brain.runBrainPeerHeartbeatTick();

	         suite.expect(peer->confirmedMissingTransportEpoch == peer->transportEpoch, "brain_peer_heartbeat_tick_marks_stale_peer_confirmed_missing_epoch");
	         suite.expect(peer->queuedCloseTransportEpoch == peer->transportEpoch, "brain_peer_heartbeat_tick_queues_close_for_stale_peer");
	         suite.expect(Ring::socketIsClosing(peer), "brain_peer_heartbeat_tick_marks_stale_peer_closing");

	         cleanupBrainPeerSocket(*peer, peerFD);
	      }

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      ScopedRing scopedRing = {};

	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.brainPeerHeartbeatIntervalMs = 1000;
	      brain.brainPeerHeartbeatTimeoutMs = 1;

	      BrainView *peer = makePeer(uint128_t(0x0621), 231, IPAddress("10.0.0.16", false).v4);
	      peer->connected = true;
	      int peerFD = -1;
	      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
	      suite.expect(installed, "brain_peer_heartbeat_tick_last_receive_stale_peer_installs_socket");
	      if (installed)
	      {
	         peer->noteTransportActivated();
	         peer->lastHeartbeatAckMs = 0;
	         peer->lastReceiveMs = Time::now<TimeResolution::ms>() - 10;
	         brain.brains.insert(peer);

	         brain.runBrainPeerHeartbeatTick();

	         suite.expect(peer->confirmedMissingTransportEpoch == 0, "brain_peer_heartbeat_tick_probes_stale_peer_without_outstanding_heartbeat");
	         suite.expect(peer->queuedCloseTransportEpoch == 0, "brain_peer_heartbeat_tick_does_not_close_before_probe_ack_deadline");
	         suite.expect(Ring::socketIsClosing(peer) == false, "brain_peer_heartbeat_tick_keeps_unprobed_stale_peer_open");
	         suite.expect(peer->lastHeartbeatSentNonce == 1, "brain_peer_heartbeat_tick_sends_first_probe_to_unprobed_stale_peer");

	         cleanupBrainPeerSocket(*peer, peerFD);
	      }

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      ScopedRing scopedRing = {};

	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.brainPeerHeartbeatIntervalMs = 1000;
	      brain.brainPeerHeartbeatTimeoutMs = 1;

	      BrainView *peer = makePeer(uint128_t(0x0622), 232, IPAddress("10.0.0.17", false).v4);
	      peer->connected = true;
	      int peerFD = -1;
	      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
	      suite.expect(installed, "brain_peer_heartbeat_tick_recent_receive_peer_installs_socket");
	      if (installed)
	      {
	         peer->noteTransportActivated();
	         peer->lastHeartbeatAckMs = Time::now<TimeResolution::ms>() - 10;
	         peer->lastReceiveMs = Time::now<TimeResolution::ms>();
	         brain.brains.insert(peer);

	         brain.runBrainPeerHeartbeatTick();

	         suite.expect(peer->confirmedMissingTransportEpoch == 0, "brain_peer_heartbeat_tick_recent_receive_without_ack_keeps_confirmed_missing_clear");
	         suite.expect(peer->queuedCloseTransportEpoch == 0, "brain_peer_heartbeat_tick_recent_receive_without_ack_does_not_queue_close");
	         suite.expect(Ring::socketIsClosing(peer) == false, "brain_peer_heartbeat_tick_recent_receive_without_ack_keeps_peer_open");

	         cleanupBrainPeerSocket(*peer, peerFD);
	      }

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.nBrains = 2;
      brain.boottimens = 10;

      BrainView *peer = makePeer(uint128_t(0), 0, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 43;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::registration,
         uint128_t(0x050),
         int64_t(20),
         uint64_t(9),
         uint128_t(0));
      brain.testBrainHandler(peer, message);

      suite.expect(peer->isMasterBrain, "registration_without_designated_master_derives_master");
      suite.expect(brain.noMasterYet == false, "registration_without_designated_master_clears_no_master_flag");
      suite.expect(peer->wBuffer.size() > 0 && BrainTopic(reinterpret_cast<Message *>(peer->wBuffer.data())->topic) == BrainTopic::reconcileState, "registration_without_designated_master_queues_reconcile_state");

      brain.brains.erase(peer);
      delete peer;
   }

   withUniqueMothershipSocket("registration_consistent_self_master_claim_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.masterQuorumDegraded = true;

      brain.testSelfElectAsMaster("unit-test");

      BrainView *peer = makePeer(uint128_t(0), 0, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 46;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::registration,
         uint128_t(0x200),
         int64_t(20),
         uint64_t(11),
         neuron.uuid);
      brain.testBrainHandler(peer, message);

      suite.expect(brain.weAreMaster, "registration_consistent_self_master_claim_keeps_self_master");
      suite.expect(brain.masterQuorumDegraded == false, "registration_consistent_self_master_claim_clears_quorum_degraded");
      suite.expect(brain.persistCalls == 1, "registration_consistent_self_master_claim_skips_extra_persist");

      brain.brains.erase(peer);
      delete peer;
   });

   withUniqueMothershipSocket("registration_self_master_claim_echo_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      brain.testSelfElectAsMaster("unit-test");

      BrainView *peer = makePeer(uint128_t(0), 0, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 47;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::registration,
         uint128_t(0x200),
         int64_t(20),
         uint64_t(0),
         uint128_t(0));
      brain.testBrainHandler(peer, message);

      bool sawRegistration = false;
      uint128_t echoedMasterUUID = 0;
      forEachMessageInBuffer(peer->wBuffer, [&](Message *queued) {
         if (BrainTopic(queued->topic) != BrainTopic::registration)
         {
            return;
         }

         uint8_t *args = queued->args;
         uint128_t echoedUUID = 0;
         int64_t echoedBoottimens = 0;
         uint64_t echoedVersion = 0;
         uint128_t queuedExistingMasterUUID = 0;
         if (Message::extractArg<ArgumentNature::fixed>(args, echoedUUID)
            && Message::extractArg<ArgumentNature::fixed>(args, echoedBoottimens)
            && Message::extractArg<ArgumentNature::fixed>(args, echoedVersion)
            && Message::extractArg<ArgumentNature::fixed>(args, queuedExistingMasterUUID))
         {
            sawRegistration = true;
            echoedMasterUUID = queuedExistingMasterUUID;
         }
      });

      suite.expect(sawRegistration, "registration_self_master_claim_echoes_registration");
      suite.expect(echoedMasterUUID == neuron.uuid, "registration_self_master_claim_echoes_self_master_uuid");

      brain.brains.erase(peer);
      delete peer;
   });

   withUniqueMothershipSocket("registration_conflicting_self_master_claim_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      brain.testSelfElectAsMaster("unit-test");
      brain.masterQuorumDegraded = true;

      BrainView *conflictingPeer = makePeer(uint128_t(0x300), 30, IPAddress("10.0.0.13", false).v4);
      conflictingPeer->connected = true;
      conflictingPeer->isFixedFile = true;
      conflictingPeer->fslot = 47;
      conflictingPeer->existingMasterUUID = conflictingPeer->uuid;
      brain.brains.insert(conflictingPeer);

      BrainView *peer = makePeer(uint128_t(0), 0, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 48;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::registration,
         uint128_t(0x200),
         int64_t(20),
         uint64_t(12),
         neuron.uuid);
      brain.testBrainHandler(peer, message);

      suite.expect(brain.weAreMaster, "registration_conflicting_self_master_claim_keeps_self_master");
      suite.expect(brain.masterQuorumDegraded, "registration_conflicting_self_master_claim_preserves_quorum_degraded");

      brain.brains.erase(conflictingPeer);
      brain.brains.erase(peer);
      delete conflictingPeer;
      delete peer;
   });

   withUniqueMothershipSocket("registration_majority_override_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;

      brain.testSelfElectAsMaster("unit-test");

      BrainView *candidate = makePeer(uint128_t(0x300), 30, IPAddress("10.0.0.13", false).v4);
      candidate->connected = true;
      candidate->isFixedFile = true;
      candidate->fslot = 47;
      candidate->existingMasterUUID = candidate->uuid;
      brain.brains.insert(candidate);

      BrainView *peer = makePeer(uint128_t(0), 0, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 48;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::registration,
         uint128_t(0x200),
         int64_t(20),
         uint64_t(12),
         uint128_t(0x300));
      brain.testBrainHandler(peer, message);

      suite.expect(brain.weAreMaster == false, "registration_majority_override_relinquishes_self_master");
      suite.expect(candidate->isMasterBrain, "registration_majority_override_elects_reported_master_peer");
      suite.expect(brain.noMasterYet == false, "registration_majority_override_keeps_cluster_mastered");
      suite.expect(brain.persistCalls == 2, "registration_majority_override_persists_new_master");

      brain.brains.erase(candidate);
      brain.brains.erase(peer);
      delete candidate;
      delete peer;
   });

   withUniqueMothershipSocket("registration_majority_override_ignores_stale_candidate_claim_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;

      brain.testSelfElectAsMaster("unit-test");

      BrainView *candidate = makePeer(uint128_t(0x300), 30, IPAddress("10.0.0.13", false).v4);
      candidate->connected = true;
      candidate->isFixedFile = true;
      candidate->fslot = 51;
      candidate->existingMasterUUID = candidate->uuid;
      candidate->registrationFresh = false;
      brain.brains.insert(candidate);

      BrainView *peer = makePeer(uint128_t(0), 0, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 52;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::registration,
         uint128_t(0x200),
         int64_t(20),
         uint64_t(12),
         uint128_t(0x300));
      brain.testBrainHandler(peer, message);

      suite.expect(brain.weAreMaster, "registration_majority_override_ignores_stale_candidate_claim_keeps_self_master");
      suite.expect(candidate->isMasterBrain == false, "registration_majority_override_ignores_stale_candidate_claim_does_not_elect_candidate");
      suite.expect(brain.persistCalls == 1, "registration_majority_override_ignores_stale_candidate_claim_skips_extra_persist");

      brain.brains.erase(candidate);
      brain.brains.erase(peer);
      delete candidate;
      delete peer;
   });

   withUniqueMothershipSocket("registration_non_majority_override_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 5;

      brain.testSelfElectAsMaster("unit-test");

      BrainView *candidate = makePeer(uint128_t(0x300), 30, IPAddress("10.0.0.13", false).v4);
      candidate->connected = true;
      candidate->isFixedFile = true;
      candidate->fslot = 49;
      candidate->existingMasterUUID = candidate->uuid;
      brain.brains.insert(candidate);

      BrainView *peer = makePeer(uint128_t(0), 0, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 50;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::registration,
         uint128_t(0x200),
         int64_t(20),
         uint64_t(13),
         uint128_t(0x300));
      brain.testBrainHandler(peer, message);

      suite.expect(brain.weAreMaster, "registration_non_majority_override_keeps_self_master");
      suite.expect(candidate->isMasterBrain == false, "registration_non_majority_override_does_not_elect_candidate");
      suite.expect(brain.persistCalls == 1, "registration_non_majority_override_skips_extra_persist");

      brain.brains.erase(candidate);
      brain.brains.erase(peer);
      delete candidate;
      delete peer;
   });

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0), 0, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 44;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::registration,
         uint128_t(0x200),
         int64_t(20),
         uint64_t(10),
         uint128_t(0x200));
      brain.testBrainHandler(peer, message);

      suite.expect(peer->isMasterBrain, "registration_existing_master_claim_elects_peer");

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.pendingDesignatedMasterPeerKey = uint128_t(IPAddress("10.0.0.12", false).v4);

	      BrainView *peer = makePeer(uint128_t(0), 0, IPAddress("10.0.0.12", false).v4);
	      peer->connected = true;
	      peer->isFixedFile = true;
	      peer->fslot = 44;
	      brain.brains.insert(peer);

	      String buffer = {};
	      Message *message = buildBrainMessage(
	         buffer,
	         BrainTopic::registration,
	         uint128_t(0x200),
	         int64_t(20),
	         uint64_t(8),
	         neuron.uuid);
	      brain.testBrainHandler(peer, message);

	      suite.expect(peer->isMasterBrain, "registration_pending_designated_master_ignores_stale_self_claim");
	      suite.expect(brain.weAreMaster == false, "registration_pending_designated_master_stale_self_claim_does_not_self_elect");
	      suite.expect(brain.noMasterYet == false, "registration_pending_designated_master_stale_self_claim_clears_no_master");
	      suite.expect(brain.pendingDesignatedMasterPeerKey == 0, "registration_pending_designated_master_stale_self_claim_clears_pending");

	      brain.brains.erase(peer);
	      delete peer;
	   }

	   {
	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.updateSelfState = TestBrain::UpdateSelfState::waitingForRelinquishEchos;
      brain.pendingDesignatedMasterPeerKey = uint128_t(IPAddress("10.0.0.12", false).v4);

      BrainView *peer = makePeer(uint128_t(0), 0, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 40;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::registration,
         uint128_t(0x200),
         int64_t(20),
         uint64_t(8),
         uint128_t(0));
      brain.testBrainHandler(peer, message);

      suite.expect(peer->isMasterBrain, "registration_update_self_waiting_relinquish_echos_elects_designated_peer");
      suite.expect(brain.updateSelfState == TestBrain::UpdateSelfState::waitingForRelinquishEchos, "registration_update_self_waiting_relinquish_echos_keeps_state");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.pendingDesignatedMasterPeerKey = uint128_t(IPAddress("10.0.0.99", false).v4);

      BrainView *candidate = makePeer(uint128_t(0x300), 30, IPAddress("10.0.0.13", false).v4);
      candidate->connected = true;
      candidate->isFixedFile = true;
      candidate->fslot = 49;
      brain.brains.insert(candidate);

      BrainView *peer = makePeer(uint128_t(0), 0, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 50;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::registration,
         uint128_t(0x200),
         int64_t(20),
         uint64_t(13),
         uint128_t(0x300));
      brain.testBrainHandler(peer, message);

      suite.expect(brain.noMasterYet, "registration_non_designated_master_claim_defers_election");
      suite.expect(candidate->isMasterBrain == false, "registration_non_designated_master_claim_keeps_candidate_unselected");
      suite.expect(brain.pendingDesignatedMasterPeerKey == uint128_t(IPAddress("10.0.0.99", false).v4), "registration_non_designated_master_claim_retains_pending_designation");
      suite.expect(brain.persistCalls == 0, "registration_non_designated_master_claim_skips_persist");

      brain.brains.erase(candidate);
      brain.brains.erase(peer);
      delete candidate;
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.noMasterYet = false;
      brain.version = 12;

      BrainView *peer = makePeer(uint128_t(0), 0, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 51;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::registration,
         uint128_t(0x200),
         int64_t(20),
         uint64_t(9),
         uint128_t(0));
      brain.testBrainHandler(peer, message);

      bool sawUpdateBundle = false;
      forEachMessageInBuffer(peer->wBuffer, [&] (Message *queued) {
         if (BrainTopic(queued->topic) == BrainTopic::updateBundle)
         {
            sawUpdateBundle = true;
         }
      });
      suite.expect(sawUpdateBundle, "registration_master_late_join_queues_bundle_update");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 2;
      brain.boottimens = 10;
      brain.isMasterMissing = true;

      BrainView *peer = makePeer(uint128_t(0x050), 20, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 45;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainEcho(buffer, BrainTopic::masterMissing);
      brain.testBrainHandler(peer, message);

      suite.expect(peer->isMasterBrain, "master_missing_agreement_derives_master");
      suite.expect(peer->wBuffer.size() > 0 && BrainTopic(reinterpret_cast<Message *>(peer->wBuffer.data())->topic) == BrainTopic::masterMissing, "master_missing_echo_queues_response");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 2;
      brain.boottimens = 10;
      brain.isMasterMissing = false;

      BrainView *peer = makePeer(uint128_t(0x050), 20, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 52;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::masterMissing,
         uint8_t(1));
      brain.testBrainHandler(peer, message);

      suite.expect(peer->isMasterMissing, "master_missing_response_records_peer_vote");
      suite.expect(brain.noMasterYet, "master_missing_response_without_local_vote_does_not_force_election");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x200), 20, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 40;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::relinquishMasterStatus,
         uint8_t(1),
         uint128_t(peer->private4));
      brain.testBrainHandler(peer, message);

      suite.expect(peer->isMasterBrain, "relinquish_status_designated_peer_elects_peer");
      suite.expect(brain.pendingDesignatedMasterPeerKey == 0, "relinquish_status_designated_peer_clears_pending_key_after_election");
      suite.expect(brain.persistCalls == 2, "relinquish_status_designated_peer_persists");

      brain.brains.erase(peer);
      delete peer;
   }

   withUniqueMothershipSocket("self_elect_master_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 1;
      brain.boottimens = 10;

      brain.testSelfElectAsMaster("unit-test");

      suite.expect(brain.weAreMaster, "self_elect_master_sets_master_flag");
      suite.expect(brain.noMasterYet == false, "self_elect_master_clears_no_master_flag");
      suite.expect(brain.hasCompletedInitialMasterElection, "self_elect_master_marks_initial_election_complete");
      suite.expect(brain.persistCalls == 1, "self_elect_master_persists_runtime_state");
   });

   withUniqueMothershipSocket("registration_pending_designated_master_self_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.pendingDesignatedMasterPeerKey = uint128_t(neuron.private4.v4);

      BrainView *peer = makePeer(uint128_t(0), 0, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 41;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::registration,
         uint128_t(0x200),
         int64_t(20),
         uint64_t(8),
         uint128_t(0));
      brain.testBrainHandler(peer, message);

      suite.expect(brain.weAreMaster, "registration_pending_designated_master_elects_self");
      suite.expect(brain.persistCalls == 1, "registration_pending_designated_master_self_persists");

      brain.brains.erase(peer);
      delete peer;
   });

   withUniqueMothershipSocket("derive_master_brain_existing_master_self_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;

      BrainView *peerA = makePeer(uint128_t(0x200), 20, IPAddress("10.0.0.11", false).v4);
      peerA->connected = true;
      peerA->isFixedFile = true;
      peerA->fslot = 34;
      peerA->existingMasterUUID = neuron.uuid;
      brain.brains.insert(peerA);

      BrainView *peerB = makePeer(uint128_t(0x300), 30, IPAddress("10.0.0.12", false).v4);
      peerB->connected = true;
      peerB->isFixedFile = true;
      peerB->fslot = 35;
      peerB->existingMasterUUID = neuron.uuid;
      brain.brains.insert(peerB);

      brain.testDeriveMasterBrain();

      suite.expect(brain.weAreMaster, "derive_master_brain_adopts_consistent_existing_master_self");
      suite.expect(brain.persistCalls == 2, "derive_master_brain_existing_master_self_persists");

      brain.brains.erase(peerA);
      brain.brains.erase(peerB);
      delete peerA;
      delete peerB;
   });

   withUniqueMothershipSocket("derive_master_brain_failover_self_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;
      brain.hasCompletedInitialMasterElection = true;

      BrainView *peer = makePeer(uint128_t(0x200), 20, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 36;
      brain.brains.insert(peer);

      brain.testDeriveMasterBrain(false);

      suite.expect(brain.weAreMaster, "derive_master_brain_failover_self_elects_by_address_order");
      suite.expect(brain.persistCalls == 1, "derive_master_brain_failover_self_election_persists");

      brain.brains.erase(peer);
      delete peer;
   });

   withUniqueMothershipSocket("derive_master_brain_rebooted_failover_majority_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      ProdigyPersistentMasterAuthorityPackage package = {};
      package.runtimeState.hasCompletedInitialMasterElection = true;
      brain.applyPersistentMasterAuthorityPackage(package);

      BrainView *peer = makePeer(uint128_t(0x200), 20, IPAddress("10.0.0.12", false).v4, "10.0.0.12");
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 42;
      brain.brains.insert(peer);

      brain.testDeriveMasterBrain();

      suite.expect(brain.hasCompletedInitialMasterElection, "derive_master_brain_rebooted_failover_restores_completed_initial_election");
      suite.expect(brain.weAreMaster, "derive_master_brain_rebooted_failover_self_elects_with_majority");
      suite.expect(brain.noMasterYet == false, "derive_master_brain_rebooted_failover_clears_no_master");
      suite.expect(brain.persistCalls == 1, "derive_master_brain_rebooted_failover_persists_self_election");

      brain.brains.erase(peer);
      delete peer;
   });

   withUniqueMothershipSocket("derive_master_brain_single_brain_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 1;
      brain.boottimens = 10;

      brain.testDeriveMasterBrain();

      suite.expect(brain.weAreMaster, "derive_master_brain_single_brain_fallback_self_elects");
      suite.expect(brain.persistCalls == 2, "derive_master_brain_single_brain_fallback_persists");
   });

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.noMasterYet = false;
      brain.pendingDesignatedMasterPeerKey = uint128_t(0x777);

      brain.testSelfElectAsMaster("already-master");

      suite.expect(brain.weAreMaster, "self_elect_as_master_already_master_preserves_master_flag");
      suite.expect(brain.noMasterYet == false, "self_elect_as_master_already_master_preserves_no_master_flag");
      suite.expect(brain.pendingDesignatedMasterPeerKey == uint128_t(0x777), "self_elect_as_master_already_master_preserves_pending_designated_master");
      suite.expect(brain.persistCalls == 0, "self_elect_as_master_already_master_skips_persist");
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.pendingDesignatedMasterPeerKey = uint128_t(0x888);

      const char *previousSocketPath = ::getenv("PRODIGY_MOTHERSHIP_SOCKET");
      String previousSocketPathText = {};
      if (previousSocketPath != nullptr)
      {
         previousSocketPathText.assign(previousSocketPath);
      }

      String invalidSocketPath = {};
      unsigned long long invalidSocketSeed = ((unsigned long long)::getpid() << 32) | 0xabcULL;
      String invalidSocketSeedText = {};
      invalidSocketSeedText.snprintf<"{itoa}"_ctv>(invalidSocketSeed);
      invalidSocketPath.assign("/tmp/prodigy-self-elect-invalid-"_ctv);
      invalidSocketPath.append(invalidSocketSeedText);
      invalidSocketPath.append("/mothership.sock"_ctv);
      ::setenv("PRODIGY_MOTHERSHIP_SOCKET", invalidSocketPath.c_str(), 1);

      brain.testSelfElectAsMaster("unix-listener-fail");

      suite.expect(brain.weAreMaster == false, "self_elect_as_master_listener_failure_clears_master_flag");
      suite.expect(brain.noMasterYet, "self_elect_as_master_listener_failure_preserves_no_master_flag");
      suite.expect(brain.pendingDesignatedMasterPeerKey == uint128_t(0x888), "self_elect_as_master_listener_failure_preserves_pending_designated_master");
      suite.expect(brain.mothershipUnixAcceptArmed == false, "self_elect_as_master_listener_failure_leaves_unix_accept_disarmed");
      suite.expect(brain.testMothershipUnixListenerActive() == false, "self_elect_as_master_listener_failure_leaves_unix_listener_inactive");
      suite.expect(brain.persistCalls == 0, "self_elect_as_master_listener_failure_skips_persist");

      if (previousSocketPath != nullptr)
      {
         ::setenv("PRODIGY_MOTHERSHIP_SOCKET", previousSocketPathText.c_str(), 1);
      }
      else
      {
         ::unsetenv("PRODIGY_MOTHERSHIP_SOCKET");
      }
   }

   withUniqueMothershipSocket("self_elect_as_master_rearms_connector_peers_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.boottimens = 10;

      BrainView *activeConnectorPeer = makePeer(uint128_t(0x210), 20, IPAddress("10.0.0.11", false).v4);
      activeConnectorPeer->weConnectToIt = true;
      activeConnectorPeer->connected = true;
      activeConnectorPeer->isFixedFile = true;
      activeConnectorPeer->fslot = 52;
      activeConnectorPeer->reconnectAfterClose = false;
      activeConnectorPeer->nConnectionAttempts = 3;
      activeConnectorPeer->nAttemptsBudget = 7;
      brain.brains.insert(activeConnectorPeer);

      BrainView *inactiveConnectorPeer = makePeer(uint128_t(0x220), 21, IPAddress("10.0.0.12", false).v4);
      inactiveConnectorPeer->weConnectToIt = true;
      inactiveConnectorPeer->connected = false;
      inactiveConnectorPeer->reconnectAfterClose = false;
      inactiveConnectorPeer->nConnectionAttempts = 6;
      inactiveConnectorPeer->nAttemptsBudget = 9;
      inactiveConnectorPeer->attemptDeadlineMs = 12345;
      brain.brains.insert(inactiveConnectorPeer);

      brain.testSelfElectAsMaster("unit-test");

      suite.expect(brain.weAreMaster, "self_elect_as_master_rearms_connector_peers_sets_master");
      suite.expect(activeConnectorPeer->fslot == 52, "self_elect_as_master_rearms_connector_peers_keeps_active_peer_socket");
      suite.expect(Ring::socketIsClosing(activeConnectorPeer) == false, "self_elect_as_master_rearms_connector_peers_keeps_active_peer_open");
      suite.expect(activeConnectorPeer->reconnectAfterClose == false, "self_elect_as_master_rearms_connector_peers_skips_active_peer_rearm");
      suite.expect(activeConnectorPeer->nConnectionAttempts == 3, "self_elect_as_master_rearms_connector_peers_preserves_active_peer_attempts");
      suite.expect(activeConnectorPeer->pendingSend || activeConnectorPeer->wBuffer.outstandingBytes() > 0, "self_elect_as_master_rearms_connector_peers_pushes_master_registration_over_active_peer");
      suite.expect(inactiveConnectorPeer->reconnectAfterClose, "self_elect_as_master_rearms_connector_peers_rearms_inactive_peer");
      suite.expect(inactiveConnectorPeer->nConnectionAttempts == 0, "self_elect_as_master_rearms_connector_peers_resets_inactive_peer_attempts");
      suite.expect(inactiveConnectorPeer->nAttemptsBudget == 9, "self_elect_as_master_rearms_connector_peers_preserves_inactive_peer_budget");
      suite.expect(inactiveConnectorPeer->attemptDeadlineMs == 12345, "self_elect_as_master_rearms_connector_peers_preserves_inactive_peer_deadline");
      suite.expect(inactiveConnectorPeer->fd >= 0, "self_elect_as_master_rearms_connector_peers_recreates_inactive_peer_socket");

      brain.brains.erase(activeConnectorPeer);
      brain.brains.erase(inactiveConnectorPeer);
      if (inactiveConnectorPeer->fd >= 0)
      {
         ::close(inactiveConnectorPeer->fd);
         inactiveConnectorPeer->fd = -1;
      }
      delete activeConnectorPeer;
      delete inactiveConnectorPeer;
   });

   withUniqueMothershipSocket("self_elect_as_master_preserves_active_accepted_peer_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.boottimens = 10;

      BrainView *acceptedPeer = makePeer(uint128_t(0x230), 22, IPAddress("10.0.0.13", false).v4);
      acceptedPeer->weConnectToIt = false;
      acceptedPeer->connected = true;
      acceptedPeer->currentStreamAccepted = true;
      acceptedPeer->isFixedFile = true;
      acceptedPeer->fslot = 61;
      acceptedPeer->reconnectAfterClose = false;
      brain.brains.insert(acceptedPeer);

      brain.testSelfElectAsMaster("unit-test");

      suite.expect(brain.weAreMaster, "self_elect_as_master_preserves_active_accepted_peer_sets_master");
      suite.expect(acceptedPeer->currentStreamAccepted, "self_elect_as_master_preserves_active_accepted_peer_keeps_accepted_flag");
      suite.expect(Ring::socketIsClosing(acceptedPeer) == false, "self_elect_as_master_preserves_active_accepted_peer_keeps_socket_open");
      suite.expect(acceptedPeer->reconnectAfterClose == false, "self_elect_as_master_preserves_active_accepted_peer_skips_forced_reconnect");
      suite.expect(acceptedPeer->forceConnectorOwnershipUntilMasterAck == false, "self_elect_as_master_preserves_active_accepted_peer_skips_force_connector_flag");
      suite.expect(acceptedPeer->pendingSend || acceptedPeer->wBuffer.outstandingBytes() > 0, "self_elect_as_master_preserves_active_accepted_peer_pushes_master_registration");

      brain.brains.erase(acceptedPeer);
      delete acceptedPeer;
   });

   withUniqueMothershipSocket("arm_mothership_unix_listener_preserves_live_existing_path", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      const char *socketPath = ::getenv("PRODIGY_MOTHERSHIP_SOCKET");
      suite.expect(socketPath != nullptr, "arm_mothership_unix_listener_preserves_live_existing_path_has_env");
      if (socketPath == nullptr)
      {
         return;
      }

      int existingListenerFD = -1;
      suite.expect(createUnixListener(String(socketPath), existingListenerFD),
         "arm_mothership_unix_listener_preserves_live_existing_path_creates_existing_listener");
      if (existingListenerFD < 0)
      {
         return;
      }

      suite.expect(brain.testArmMothershipUnixListener() == false,
         "arm_mothership_unix_listener_preserves_live_existing_path_defers_rebind");
      suite.expect(::access(socketPath, F_OK) == 0,
         "arm_mothership_unix_listener_preserves_live_existing_path_keeps_socket_path");

      int probeFD = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
      suite.expect(probeFD >= 0,
         "arm_mothership_unix_listener_preserves_live_existing_path_creates_probe_socket");
      if (probeFD >= 0)
      {
         struct sockaddr_un address = {};
         address.sun_family = AF_UNIX;
         std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", socketPath);
         socklen_t addressLen = socklen_t(sizeof(address.sun_family) + std::strlen(address.sun_path));
         suite.expect(::connect(probeFD, reinterpret_cast<struct sockaddr *>(&address), addressLen) == 0,
            "arm_mothership_unix_listener_preserves_live_existing_path_connects_existing_listener");
         ::close(probeFD);
      }

      ::close(existingListenerFD);
      ::unlink(socketPath);
   });

   withUniqueMothershipSocket("unlink_mothership_unix_socket_path_requires_local_ownership", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      const char *socketPath = ::getenv("PRODIGY_MOTHERSHIP_SOCKET");
      suite.expect(socketPath != nullptr, "unlink_mothership_unix_socket_path_requires_local_ownership_has_env");
      if (socketPath == nullptr)
      {
         return;
      }

      int existingListenerFD = -1;
      suite.expect(createUnixListener(String(socketPath), existingListenerFD),
         "unlink_mothership_unix_socket_path_requires_local_ownership_creates_existing_listener");
      if (existingListenerFD < 0)
      {
         return;
      }

      brain.mothershipUnixSocketPath.assign(socketPath);
      suite.expect(brain.testMothershipUnixSocketPathOwnedByLocalListener() == false,
         "unlink_mothership_unix_socket_path_requires_local_ownership_detects_unowned_path");

      brain.testUnlinkMothershipUnixSocketPath("unit-test");
      suite.expect(::access(socketPath, F_OK) == 0,
         "unlink_mothership_unix_socket_path_requires_local_ownership_preserves_unowned_path");

      int probeFD = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
      suite.expect(probeFD >= 0,
         "unlink_mothership_unix_socket_path_requires_local_ownership_creates_probe_socket");
      if (probeFD >= 0)
      {
         struct sockaddr_un address = {};
         address.sun_family = AF_UNIX;
         std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", socketPath);
         socklen_t addressLen = socklen_t(sizeof(address.sun_family) + std::strlen(address.sun_path));
         suite.expect(::connect(probeFD, reinterpret_cast<struct sockaddr *>(&address), addressLen) == 0,
            "unlink_mothership_unix_socket_path_requires_local_ownership_preserves_live_listener");
         ::close(probeFD);
      }

      brain.testUnlinkMothershipUnixSocketPath("unit-test-force", false);
      suite.expect(::access(socketPath, F_OK) != 0,
         "unlink_mothership_unix_socket_path_requires_local_ownership_allows_forced_unlink");

      ::close(existingListenerFD);
      ::unlink(socketPath);
   });

   withUniqueMothershipSocket("unlink_mothership_unix_socket_path_unlinks_owned_listener", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      const char *socketPath = ::getenv("PRODIGY_MOTHERSHIP_SOCKET");
      suite.expect(socketPath != nullptr, "unlink_mothership_unix_socket_path_unlinks_owned_listener_has_env");
      if (socketPath == nullptr)
      {
         return;
      }

      suite.expect(brain.testArmMothershipUnixListener(),
         "unlink_mothership_unix_socket_path_unlinks_owned_listener_arms_listener");
      suite.expect(brain.testMothershipUnixSocketPathOwnedByLocalListener(),
         "unlink_mothership_unix_socket_path_unlinks_owned_listener_detects_owned_path");

      brain.testUnlinkMothershipUnixSocketPath("unit-test");
      suite.expect(::access(socketPath, F_OK) != 0,
         "unlink_mothership_unix_socket_path_unlinks_owned_listener_removes_path");

      if (brain.mothershipUnixSocket.isFixedFile)
      {
         Ring::uninstallFromFixedFileSlot(&brain.mothershipUnixSocket);
      }
      if (brain.mothershipUnixSocket.fd >= 0)
      {
         ::close(brain.mothershipUnixSocket.fd);
         brain.mothershipUnixSocket.fd = -1;
      }
      brain.mothershipUnixSocket.fslot = -1;
      brain.mothershipUnixSocket.isFixedFile = false;
   });

   withUniqueMothershipSocket("self_elect_as_master_failover_replaces_live_listener_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      const char *socketPath = ::getenv("PRODIGY_MOTHERSHIP_SOCKET");
      suite.expect(socketPath != nullptr, "self_elect_as_master_failover_replaces_live_listener_has_env");
      if (socketPath == nullptr)
      {
         return;
      }

      int existingListenerFD = -1;
      suite.expect(createUnixListener(String(socketPath), existingListenerFD),
         "self_elect_as_master_failover_replaces_live_listener_creates_existing_listener");
      if (existingListenerFD < 0)
      {
         return;
      }

      brain.testSelfElectAsMaster("unit-test-failover", true);

      suite.expect(brain.weAreMaster, "self_elect_as_master_failover_replaces_live_listener_sets_master");
      suite.expect(::access(socketPath, F_OK) == 0,
         "self_elect_as_master_failover_replaces_live_listener_keeps_socket_path");

      int probeFD = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
      suite.expect(probeFD >= 0,
         "self_elect_as_master_failover_replaces_live_listener_creates_probe_socket");
      if (probeFD >= 0)
      {
         struct sockaddr_un address = {};
         address.sun_family = AF_UNIX;
         std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", socketPath);
         socklen_t addressLen = socklen_t(sizeof(address.sun_family) + std::strlen(address.sun_path));
         suite.expect(::connect(probeFD, reinterpret_cast<struct sockaddr *>(&address), addressLen) == 0,
            "self_elect_as_master_failover_replaces_live_listener_connects_new_listener");
         ::close(probeFD);
      }

      ::close(existingListenerFD);
      ::unlink(socketPath);
   });

   withUniqueMothershipSocket("self_elect_as_master_preserves_active_machine_neuron_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.boottimens = 10;
      brain.overrideNeuronControlInstallFromBrain = true;
      brain.forcedNeuronControlInstallFromBrain = true;

      Machine machine = {};
      machine.uuid = uint128_t(0x901);
      machine.privateAddress = "10.0.0.21"_ctv;
      machine.neuron.machine = &machine;
      machine.neuron.connected = true;
      machine.neuron.reconnectAfterClose = false;
      machine.neuron.nConnectionAttempts = 5;
      machine.neuron.nAttemptsBudget = 8;
      brain.machines.insert(&machine);

      int peerFD = -1;
      bool installed = installNeuronSocket(brain, machine, peerFD);
      suite.expect(installed, "self_elect_as_master_preserves_active_machine_neuron_installs_socket");
      if (installed)
      {
         const int preservedFslot = machine.neuron.fslot;
         brain.testSelfElectAsMaster("unit-test");

         suite.expect(brain.neurons.contains(&machine.neuron), "self_elect_as_master_preserves_active_machine_neuron_registers_neuron");
         suite.expect(machine.neuron.isFixedFile, "self_elect_as_master_preserves_active_machine_neuron_keeps_fixed_file");
         suite.expect(machine.neuron.fslot == preservedFslot, "self_elect_as_master_preserves_active_machine_neuron_keeps_fixed_file_slot");
         suite.expect(machine.neuron.reconnectAfterClose, "self_elect_as_master_preserves_active_machine_neuron_sets_reconnect_flag");
         suite.expect(machine.neuron.nConnectionAttempts == 0, "self_elect_as_master_preserves_active_machine_neuron_resets_attempts");
         suite.expect(machine.neuron.nAttemptsBudget == 0, "self_elect_as_master_preserves_active_machine_neuron_resets_budget");
         suite.expect(brain.neuronControlInstallFromBrainCalls == 0, "self_elect_as_master_preserves_active_machine_neuron_skips_reinstall");
      }

      brain.machines.erase(&machine);
      brain.neurons.erase(&machine.neuron);
      if (peerFD >= 0)
      {
         ::close(peerFD);
      }
      if (machine.neuron.isFixedFile == false && machine.neuron.fd >= 0)
      {
         ::close(machine.neuron.fd);
         machine.neuron.fd = -1;
      }
   });

   withUniqueMothershipSocket("self_elect_as_master_preserves_connect_pending_machine_neuron_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.boottimens = 10;
      brain.overrideNeuronControlInstallFromBrain = true;
      brain.forcedNeuronControlInstallFromBrain = true;

      Machine machine = {};
      machine.uuid = uint128_t(0x90101);
      machine.privateAddress = "10.0.0.210"_ctv;
      machine.neuron.machine = &machine;
      machine.neuron.connected = false;
      machine.neuron.hadSuccessfulConnection = false;
      machine.neuron.pendingConnect = true;
      machine.neuron.reconnectAfterClose = false;
      machine.neuron.nConnectionAttempts = 5;
      machine.neuron.nAttemptsBudget = 8;
      machine.neuron.attemptDeadlineMs = Time::now<TimeResolution::ms>() + 1000;
      brain.machines.insert(&machine);

      int peerFD = -1;
      bool installed = installNeuronSocket(brain, machine, peerFD);
      suite.expect(installed, "self_elect_as_master_preserves_connect_pending_machine_neuron_installs_socket");
      if (installed)
      {
         const int preservedFslot = machine.neuron.fslot;
         const int64_t preservedDeadlineMs = machine.neuron.attemptDeadlineMs;
         brain.testSelfElectAsMaster("unit-test");

         suite.expect(brain.neurons.contains(&machine.neuron), "self_elect_as_master_preserves_connect_pending_machine_neuron_registers_neuron");
         suite.expect(machine.neuron.isFixedFile, "self_elect_as_master_preserves_connect_pending_machine_neuron_keeps_fixed_file");
         suite.expect(machine.neuron.fslot == preservedFslot, "self_elect_as_master_preserves_connect_pending_machine_neuron_keeps_fixed_file_slot");
         suite.expect(machine.neuron.pendingConnect, "self_elect_as_master_preserves_connect_pending_machine_neuron_keeps_connect_pending");
         suite.expect(machine.neuron.attemptDeadlineMs == preservedDeadlineMs, "self_elect_as_master_preserves_connect_pending_machine_neuron_keeps_attempt_deadline");
         suite.expect(machine.neuron.reconnectAfterClose, "self_elect_as_master_preserves_connect_pending_machine_neuron_sets_reconnect_flag");
         suite.expect(machine.neuron.nConnectionAttempts == 0, "self_elect_as_master_preserves_connect_pending_machine_neuron_resets_attempts");
         suite.expect(machine.neuron.nAttemptsBudget == 0, "self_elect_as_master_preserves_connect_pending_machine_neuron_resets_budget");
         suite.expect(brain.neuronControlInstallFromBrainCalls == 0, "self_elect_as_master_preserves_connect_pending_machine_neuron_skips_reinstall");
      }

      brain.machines.erase(&machine);
      brain.neurons.erase(&machine.neuron);
      if (peerFD >= 0)
      {
         ::close(peerFD);
      }
      if (machine.neuron.isFixedFile == false && machine.neuron.fd >= 0)
      {
         ::close(machine.neuron.fd);
         machine.neuron.fd = -1;
      }
   });

   withUniqueMothershipSocket("self_elect_as_master_rebuilds_disconnected_machine_neuron_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.boottimens = 10;
      brain.overrideNeuronControlInstallFromBrain = true;
      brain.forcedNeuronControlInstallFromBrain = true;

      Machine machine = {};
      machine.uuid = uint128_t(0x9011);
      machine.privateAddress = "10.0.0.211"_ctv;
      machine.neuron.machine = &machine;
      machine.neuron.connected = false;
      machine.neuron.reconnectAfterClose = false;
      machine.neuron.nConnectionAttempts = 5;
      machine.neuron.nAttemptsBudget = 8;
      brain.machines.insert(&machine);

      int peerFD = -1;
      bool installed = installNeuronSocket(brain, machine, peerFD);
      suite.expect(installed, "self_elect_as_master_rebuilds_disconnected_machine_neuron_installs_socket");
      if (installed)
      {
         const int staleFslot = machine.neuron.fslot;
         brain.testSelfElectAsMaster("unit-test");

         suite.expect(brain.neurons.contains(&machine.neuron), "self_elect_as_master_rebuilds_disconnected_machine_neuron_registers_neuron");
         suite.expect(machine.neuron.reconnectAfterClose, "self_elect_as_master_rebuilds_disconnected_machine_neuron_sets_reconnect_flag");
         suite.expect(machine.neuron.nConnectionAttempts == 0, "self_elect_as_master_rebuilds_disconnected_machine_neuron_resets_attempts");
         suite.expect(machine.neuron.nAttemptsBudget > 0, "self_elect_as_master_rebuilds_disconnected_machine_neuron_rearms_attempt_budget");
         suite.expect(machine.neuron.fd >= 0, "self_elect_as_master_rebuilds_disconnected_machine_neuron_recreates_socket");
         suite.expect(machine.neuron.fslot != staleFslot, "self_elect_as_master_rebuilds_disconnected_machine_neuron_replaces_stale_fixed_slot");
         suite.expect(brain.neuronControlInstallFromBrainCalls == 1, "self_elect_as_master_rebuilds_disconnected_machine_neuron_reinstalls_socket");
      }

      brain.machines.erase(&machine);
      brain.neurons.erase(&machine.neuron);
      if (peerFD >= 0)
      {
         ::close(peerFD);
      }
      if (machine.neuron.fd >= 0)
      {
         ::close(machine.neuron.fd);
         machine.neuron.fd = -1;
      }
   });

   withUniqueMothershipSocket("self_elect_as_master_rearms_unarmed_machine_neuron_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.boottimens = 10;

      Machine machine = {};
      machine.uuid = uint128_t(0x902);
      machine.privateAddress = "10.0.0.22"_ctv;
      machine.neuron.machine = &machine;
      brain.machines.insert(&machine);

      brain.testSelfElectAsMaster("unit-test");

      suite.expect(brain.neurons.contains(&machine.neuron), "self_elect_as_master_rearms_unarmed_machine_neuron_registers_neuron");
      suite.expect(machine.neuron.reconnectAfterClose, "self_elect_as_master_rearms_unarmed_machine_neuron_sets_reconnect_flag");
      suite.expect(machine.neuron.nConnectionAttempts == 0, "self_elect_as_master_rearms_unarmed_machine_neuron_resets_attempts");
      suite.expect(machine.neuron.nAttemptsBudget == 0, "self_elect_as_master_rearms_unarmed_machine_neuron_resets_budget");
      suite.expect(machine.neuron.machine == &machine, "self_elect_as_master_rearms_unarmed_machine_neuron_preserves_machine_backpointer");
      suite.expect(Ring::socketIsClosing(&machine.neuron) == false, "self_elect_as_master_rearms_unarmed_machine_neuron_leaves_socket_open_for_reconnect");

      brain.machines.erase(&machine);
      brain.neurons.erase(&machine.neuron);
      if (machine.neuron.fd >= 0)
      {
         ::close(machine.neuron.fd);
         machine.neuron.fd = -1;
      }
   });

   withUniqueMothershipSocket("self_elect_as_master_connects_machine_neuron_socket_dir_created", [&] {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.boottimens = 10;
      brain.overrideNeuronControlInstallFromBrain = true;
      brain.forcedNeuronControlInstallFromBrain = true;

      Machine machine = {};
      machine.uuid = uint128_t(0x903);
      machine.creationTimeMs = Time::now<TimeResolution::ms>() - 1000;
      machine.neuron.machine = &machine;
      brain.machines.insert(&machine);

      brain.testSelfElectAsMaster("unit-test");

      suite.expect(brain.neurons.contains(&machine.neuron), "self_elect_as_master_connects_machine_neuron_registers_neuron");
      suite.expect(brain.neuronControlInstallFromBrainCalls == 1, "self_elect_as_master_connects_machine_neuron_invokes_install_seam");
      suite.expect(machine.neuron.fd >= 0, "self_elect_as_master_connects_machine_neuron_recreates_socket");
      suite.expect(machine.neuron.daddrLen > 0, "self_elect_as_master_connects_machine_neuron_configures_destination");
      suite.expect(machine.neuron.attemptDeadlineMs > 0, "self_elect_as_master_connects_machine_neuron_arms_attempt_window");
      suite.expect(machine.neuron.reconnectAfterClose, "self_elect_as_master_connects_machine_neuron_keeps_reconnect_enabled");
      suite.expect(Ring::socketIsClosing(&machine.neuron) == false, "self_elect_as_master_connects_machine_neuron_leaves_socket_open");

      brain.machines.erase(&machine);
      brain.neurons.erase(&machine.neuron);
      if (machine.neuron.fd >= 0)
      {
         ::close(machine.neuron.fd);
         machine.neuron.fd = -1;
      }
   });

   withUniqueMothershipSocket("self_elect_as_master_awaits_machine_inventory_suspend_socket_dir_created", [&] {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      SuspendedGetMachinesBrainIaaS iaas = {};
      brain.iaas = &iaas;
      brain.boottimens = 10;
      brain.overrideSelfElectionMachineInventoryAwait = true;

      Machine machine = {};
      machine.uuid = uint128_t(0x904);
      machine.creationTimeMs = Time::now<TimeResolution::ms>() - 2000;
      machine.neuron.machine = &machine;
      iaas.machineToPublish = &machine;

      brain.testSelfElectAsMaster("unit-test");

      suite.expect(iaas.getMachinesCalls == 1, "self_elect_as_master_machine_inventory_suspend_invokes_iaas_lookup_once");
      suite.expect(brain.selfElectionMachineInventoryAwaitCalls == 1, "self_elect_as_master_machine_inventory_suspend_awaits_inventory");
      suite.expect(iaas.resumedAfterSuspend, "self_elect_as_master_machine_inventory_suspend_resumes_inventory_coroutine");
      suite.expect(brain.machines.contains(&machine), "self_elect_as_master_machine_inventory_suspend_publishes_machine_before_neuron_rearm");
      suite.expect(brain.neurons.contains(&machine.neuron), "self_elect_as_master_machine_inventory_suspend_registers_machine_neuron_after_resume");
      suite.expect(machine.neuron.reconnectAfterClose, "self_elect_as_master_machine_inventory_suspend_enables_neuron_reconnect_after_resume");

      brain.machines.erase(&machine);
      brain.neurons.erase(&machine.neuron);
      if (machine.neuron.fd >= 0)
      {
         ::close(machine.neuron.fd);
         machine.neuron.fd = -1;
      }

      brain.iaas = nullptr;
   });

   withUniqueMothershipSocket("self_elect_as_master_recovers_pending_deployments_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      DeploymentPlan plan = makeDeploymentPlan(61000, 1);
      brain.deploymentPlans.insert_or_assign(plan.config.deploymentID(), plan);

      brain.testSelfElectAsMaster("unit-test");

      suite.expect(brain.deploymentPlans.empty(), "self_elect_as_master_recovers_pending_deployments_clears_pending_plan_map");
      suite.expect(brain.deployments.contains(plan.config.deploymentID()), "self_elect_as_master_recovers_pending_deployments_materializes_deployment");
      suite.expect(brain.deploymentsByApp.contains(plan.config.applicationID), "self_elect_as_master_recovers_pending_deployments_indexes_by_application");

      ApplicationDeployment *deployment = brain.deployments[plan.config.deploymentID()];
      suite.expect(deployment != nullptr, "self_elect_as_master_recovers_pending_deployments_stores_non_null_deployment");
      if (deployment != nullptr)
      {
         suite.expect(deployment->plan.config.deploymentID() == plan.config.deploymentID(), "self_elect_as_master_recovers_pending_deployments_preserves_plan_identity");
         suite.expect(brain.deploymentsByApp[plan.config.applicationID] == deployment, "self_elect_as_master_recovers_pending_deployments_points_app_index_at_materialized_deployment");
         delete deployment;
      }

	      brain.deployments.clear();
	      brain.deploymentsByApp.clear();
	   });

	   withUniqueMothershipSocket("spin_application_queues_new_deployment_behind_unstarted_baseline_socket_dir_created", [&] {
	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();

	      DeploymentPlan baselinePlan = makeDeploymentPlan(61003, 1);
	      DeploymentPlan nextPlan = makeDeploymentPlan(61003, 2);

	      ApplicationDeployment *baseline = new ApplicationDeployment();
	      baseline->plan = baselinePlan;
	      baseline->state = DeploymentState::none;

	      ApplicationDeployment *next = new ApplicationDeployment();
	      next->plan = nextPlan;

	      brain.deployments.insert_or_assign(baselinePlan.config.deploymentID(), baseline);
	      brain.deploymentsByApp.insert_or_assign(baselinePlan.config.applicationID, baseline);

	      brain.testSpinApplication(next);

	      suite.expect(brain.deploymentsByApp[nextPlan.config.applicationID] == next, "spin_application_queues_new_deployment_head_points_to_next");
	      suite.expect(brain.deployments.contains(baselinePlan.config.deploymentID()), "spin_application_queues_new_deployment_keeps_unstarted_baseline_indexed");
	      suite.expect(brain.deployments.contains(nextPlan.config.deploymentID()), "spin_application_queues_new_deployment_indexes_next");
	      suite.expect(baseline->next == next, "spin_application_queues_new_deployment_links_baseline_next");
	      suite.expect(next->previous == baseline, "spin_application_queues_new_deployment_links_next_previous");
	      suite.expect(next->state == DeploymentState::waitingToDeploy, "spin_application_queues_new_deployment_waits_for_baseline");
	      suite.expect(baseline->state == DeploymentState::none, "spin_application_queues_new_deployment_does_not_start_or_delete_baseline");

	      brain.deployments.clear();
	      brain.deploymentsByApp.clear();
	      delete next;
	      delete baseline;
	   });

      {
         ScopedRing scopedRing = {};

         TestBrain brain = {};
         brain.iaas = new NoopBrainIaaS();
         brain.weAreMaster = true;
         brain.ignited = true;

         BrainBase *savedBrain = thisBrain;
         thisBrain = &brain;

         Rack rack = {};
         rack.uuid = 61004;

         Machine machine = {};
         machine.uuid = uint128_t(0x61004);
         machine.private4 = IPAddress("10.0.0.44", false).v4;
         machine.rack = &rack;
         machine.state = MachineState::neuronRebooting;
         machine.lifetime = MachineLifetime::owned;
         rack.machines.insert(&machine);
         brain.racks.insert_or_assign(rack.uuid, &rack);
         brain.machines.insert(&machine);

         DeploymentPlan plan = makeDeploymentPlan(61004, 1);
         ApplicationDeployment *deployment = new ApplicationDeployment();
         deployment->plan = plan;
         deployment->state = DeploymentState::canaries;
         deployment->nSuspended = 1;
         deployment->nTargetBase = 0;
         deployment->nTargetCanary = 1;
         deployment->nDeployedCanary = 1;
         deployment->nHealthyCanary = 1;

         ContainerView *canary = new ContainerView();
         canary->uuid = uint128_t(0x6100401);
         canary->deploymentID = plan.config.deploymentID();
         canary->applicationID = plan.config.applicationID;
         canary->machine = &machine;
         canary->lifetime = ApplicationLifetime::canary;
         canary->state = ContainerState::healthy;
         deployment->containers.insert(canary);
         brain.containers.insert_or_assign(canary->uuid, canary);
         brain.deployments.insert_or_assign(plan.config.deploymentID(), deployment);
         brain.deploymentsByApp.insert_or_assign(plan.config.applicationID, deployment);

         brain.testHandleMachineStateChange(&machine, MachineState::healthy);

         suite.expect(machine.state == MachineState::healthy, "machine_healthy_recovery_marks_machine_healthy");
         suite.expect(deployment->state == DeploymentState::canaries, "machine_healthy_recovery_preserves_active_stateless_canaries_state");
         suite.expect(deployment->toSchedule.empty(), "machine_healthy_recovery_does_not_schedule_active_canary_destruction");
         suite.expect(deployment->containers.contains(canary), "machine_healthy_recovery_keeps_active_canary_container");
         suite.expect(canary->state == ContainerState::healthy, "machine_healthy_recovery_keeps_active_canary_healthy");
         suite.expect(deployment->nTargetCanary == 1 && deployment->nHealthyCanary == 1, "machine_healthy_recovery_preserves_active_canary_counts");

         brain.deployments.erase(plan.config.deploymentID());
         brain.deploymentsByApp.erase(plan.config.applicationID);
         brain.containers.erase(canary->uuid);
         deployment->containers.erase(canary);
         brain.machines.erase(&machine);
         brain.racks.erase(rack.uuid);
         rack.machines.erase(&machine);
         delete canary;
         delete deployment;
         thisBrain = savedBrain;
      }

	   withUniqueMothershipSocket("self_elect_as_master_promotes_newer_pending_deployment_socket_dir_created", [&] {
	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();

      DeploymentPlan olderPlan = makeDeploymentPlan(61001, 1);
      DeploymentPlan newerPlan = makeDeploymentPlan(61001, 2);

      ApplicationDeployment *older = new ApplicationDeployment();
      older->plan = olderPlan;
      brain.deployments.insert_or_assign(olderPlan.config.deploymentID(), older);
      brain.deploymentsByApp.insert_or_assign(olderPlan.config.applicationID, older);
      brain.deploymentPlans.insert_or_assign(newerPlan.config.deploymentID(), newerPlan);

      brain.testSelfElectAsMaster("unit-test");

      suite.expect(brain.deploymentPlans.empty(), "self_elect_as_master_promotes_newer_pending_deployment_clears_pending_plan_map");
      suite.expect(brain.deployments.contains(newerPlan.config.deploymentID()), "self_elect_as_master_promotes_newer_pending_deployment_materializes_newer_deployment");

      ApplicationDeployment *newer = brain.deployments[newerPlan.config.deploymentID()];
      suite.expect(newer != nullptr, "self_elect_as_master_promotes_newer_pending_deployment_stores_newer_deployment");
      if (newer != nullptr)
      {
         suite.expect(brain.deploymentsByApp[newerPlan.config.applicationID] == newer, "self_elect_as_master_promotes_newer_pending_deployment_repoints_app_index");
         suite.expect(newer->previous == older, "self_elect_as_master_promotes_newer_pending_deployment_links_previous_generation");
         suite.expect(older->next == newer, "self_elect_as_master_promotes_newer_pending_deployment_links_next_generation");
         delete newer;
      }

      delete older;
      brain.deployments.clear();
      brain.deploymentsByApp.clear();
   });

   withUniqueMothershipSocket("self_elect_as_master_keeps_newer_existing_deployment_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      DeploymentPlan existingPlan = makeDeploymentPlan(61002, 4);
      DeploymentPlan stalePendingPlan = makeDeploymentPlan(61002, 3);

      ApplicationDeployment *existing = new ApplicationDeployment();
      existing->plan = existingPlan;
      brain.deployments.insert_or_assign(existingPlan.config.deploymentID(), existing);
      brain.deploymentsByApp.insert_or_assign(existingPlan.config.applicationID, existing);
      brain.deploymentPlans.insert_or_assign(stalePendingPlan.config.deploymentID(), stalePendingPlan);

      brain.testSelfElectAsMaster("unit-test");

      suite.expect(brain.deploymentPlans.empty(), "self_elect_as_master_keeps_newer_existing_deployment_clears_pending_plan_map");
      suite.expect(brain.deployments.contains(stalePendingPlan.config.deploymentID()), "self_elect_as_master_keeps_newer_existing_deployment_still_materializes_pending_entry");
      suite.expect(brain.deploymentsByApp[existingPlan.config.applicationID] == existing, "self_elect_as_master_keeps_newer_existing_deployment_preserves_app_index");

      ApplicationDeployment *stale = brain.deployments[stalePendingPlan.config.deploymentID()];
      suite.expect(stale != nullptr, "self_elect_as_master_keeps_newer_existing_deployment_stores_stale_deployment");
      if (stale != nullptr)
      {
         suite.expect(stale->previous == nullptr, "self_elect_as_master_keeps_newer_existing_deployment_leaves_stale_previous_unset");
         suite.expect(stale->next == nullptr, "self_elect_as_master_keeps_newer_existing_deployment_leaves_stale_next_unset");
         delete stale;
      }

      delete existing;
      brain.deployments.clear();
      brain.deploymentsByApp.clear();
   });

   withUniqueMothershipSocket("self_elect_as_master_tolerates_managed_schema_reconcile_failure_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.overrideSelfElectionManagedSchemaReconcile = true;
      brain.forcedSelfElectionManagedSchemaReconcile = false;
      brain.forcedSelfElectionManagedSchemaReconcileFailure = "forced-managed-schema-failure"_ctv;

      brain.testSelfElectAsMaster("unit-test");

      suite.expect(brain.weAreMaster, "self_elect_as_master_tolerates_managed_schema_reconcile_failure_keeps_master");
      suite.expect(brain.selfElectionManagedSchemaReconcileCalls == 1, "self_elect_as_master_tolerates_managed_schema_reconcile_failure_invokes_reconcile_once");
      suite.expect(brain.deploymentPlans.empty(), "self_elect_as_master_tolerates_managed_schema_reconcile_failure_still_clears_pending_plan_map");
   });

   withUniqueMothershipSocket("derive_master_brain_second_failover_self_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.boottimens = 10;
      brain.hasCompletedInitialMasterElection = true;

      BrainView *peer = makePeer(uint128_t(0x200), 20, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 38;
      brain.brains.insert(peer);

      brain.testDeriveMasterBrain();

      suite.expect(brain.weAreMaster, "derive_master_brain_second_failover_self_elects_by_address_order");
      suite.expect(brain.persistCalls == 1, "derive_master_brain_second_failover_self_election_persists");

      brain.brains.erase(peer);
      delete peer;
   });

   withUniqueMothershipSocket("relinquish_status_designated_self_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x200), 20, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 42;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::relinquishMasterStatus,
         uint8_t(1),
         uint128_t(neuron.private4.v4));
      brain.testBrainHandler(peer, message);

      suite.expect(brain.weAreMaster, "relinquish_status_designated_self_elects_self");
      suite.expect(brain.persistCalls == 2, "relinquish_status_designated_self_persists");

      brain.brains.erase(peer);
      delete peer;
   });

   withUniqueMothershipSocket("relinquish_status_designated_self_replaces_live_listener_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      const char *socketPath = ::getenv("PRODIGY_MOTHERSHIP_SOCKET");
      suite.expect(socketPath != nullptr, "relinquish_status_designated_self_replaces_live_listener_has_env");
      if (socketPath == nullptr)
      {
         return;
      }

      int existingListenerFD = -1;
      suite.expect(createUnixListener(String(socketPath), existingListenerFD),
         "relinquish_status_designated_self_replaces_live_listener_creates_existing_listener");
      if (existingListenerFD < 0)
      {
         return;
      }

      BrainView *peer = makePeer(uint128_t(0x200), 20, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 43;
      brain.brains.insert(peer);

      String buffer = {};
      Message *message = buildBrainMessage(
         buffer,
         BrainTopic::relinquishMasterStatus,
         uint8_t(1),
         uint128_t(neuron.private4.v4));
      brain.testBrainHandler(peer, message);

      suite.expect(brain.weAreMaster, "relinquish_status_designated_self_replaces_live_listener_elects_self");
      suite.expect(brain.pendingDesignatedMasterPeerKey == 0,
         "relinquish_status_designated_self_replaces_live_listener_clears_pending_key");
      suite.expect(brain.persistCalls == 2, "relinquish_status_designated_self_replaces_live_listener_persists");

      int probeFD = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
      suite.expect(probeFD >= 0, "relinquish_status_designated_self_replaces_live_listener_creates_probe_socket");
      if (probeFD >= 0)
      {
         struct sockaddr_un address = {};
         address.sun_family = AF_UNIX;
         std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", socketPath);
         socklen_t addressLen = socklen_t(sizeof(address.sun_family) + std::strlen(address.sun_path));
         suite.expect(::connect(probeFD, reinterpret_cast<struct sockaddr *>(&address), addressLen) == 0,
            "relinquish_status_designated_self_replaces_live_listener_connects_new_listener");
         ::close(probeFD);
      }

      brain.brains.erase(peer);
      delete peer;
      ::close(existingListenerFD);
      ::unlink(socketPath);
   });

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.boottimens = 10;

      BrainView *peer = makePeer(uint128_t(0), 0);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 11;
      brain.brains.insert(peer);

      suite.expect(brain.testActiveBrainRegistrationsReadyForMasterElection() == false, "master_election_waits_for_active_peer_registration");

      peer->uuid = uint128_t(0x200);
      peer->boottimens = 20;
      suite.expect(brain.testActiveBrainRegistrationsReadyForMasterElection(), "master_election_accepts_registered_active_peer");

      peer->connected = false;
      peer->uuid = 0;
      peer->boottimens = 0;
      suite.expect(brain.testActiveBrainRegistrationsReadyForMasterElection(), "inactive_peer_without_registration_does_not_block_master_election");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.boottimens = 10;

      neuron.private4 = IPAddress("10.0.0.11", false);

      BrainView *peer = makePeer(uint128_t(0x300), 20, IPAddress("10.0.0.12", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 12;
      brain.brains.insert(peer);

      bool preferSelf = false;
      suite.expect(brain.testResolveFailoverMasterByActivePeerAddressOrder(preferSelf), "failover_address_order_resolves_with_active_peer_private4");
      suite.expect(preferSelf, "failover_address_order_prefers_lowest_active_private4");

      peer->private4 = IPAddress("10.0.0.10", false).v4;
      preferSelf = true;
      suite.expect(brain.testResolveFailoverMasterByActivePeerAddressOrder(preferSelf), "failover_address_order_resolves_with_lower_peer_private4");
      suite.expect(preferSelf == false, "failover_address_order_waits_for_lower_active_peer");

      brain.brains.erase(peer);
      delete peer;
      neuron.private4 = IPAddress("10.0.0.10", false);
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.boottimens = 10;

      neuron.private4 = IPAddress("10.0.0.10", false);

      BrainView *peer = makePeer(uint128_t(0x100), 20, IPAddress("10.0.0.10", false).v4);
      peer->connected = true;
      peer->isFixedFile = true;
      peer->fslot = 13;
      peer->existingMasterUUID = uint128_t(0x222);
      brain.brains.insert(peer);

      bool preferSelf = false;
      suite.expect(brain.testResolveFailoverMasterByActivePeerAddressOrder(preferSelf), "failover_address_order_ignores_self_aliased_peer");
      suite.expect(preferSelf, "failover_address_order_keeps_self_when_only_self_alias_peer_exists");
      suite.expect(brain.testActiveBrainRegistrationsReadyForMasterElection(), "self_aliased_peer_does_not_block_master_registration_ready");
      suite.expect(brain.resolveConsistentExistingMasterUUID() == 0, "self_aliased_peer_does_not_vote_existing_master");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.boottimens = 10;

      neuron.private4 = IPAddress("10.0.0.11", false);

      BrainView *lowerPeer = makePeer(uint128_t(0x200), 20, IPAddress("10.0.0.10", false).v4);
      lowerPeer->connected = true;
      lowerPeer->isFixedFile = true;
      lowerPeer->fslot = 14;
      brain.brains.insert(lowerPeer);

      BrainView *incompletePeer = makePeer(uint128_t(0), 20, 0);
      incompletePeer->connected = true;
      incompletePeer->isFixedFile = true;
      incompletePeer->fslot = 15;
      brain.brains.insert(incompletePeer);

      bool preferSelf = true;
      bool sawActivePeer = false;
      suite.expect(
         brain.testResolveFailoverMasterByActivePeerAddressOrder(preferSelf, &sawActivePeer),
         "failover_address_order_ignores_incomplete_active_peer_when_comparable_peer_exists");
      suite.expect(sawActivePeer, "failover_address_order_reports_active_peer_presence");
      suite.expect(preferSelf == false, "failover_address_order_waits_for_lower_peer_despite_incomplete_active_peer");

      brain.brains.erase(lowerPeer);
      brain.brains.erase(incompletePeer);
      delete lowerPeer;
      delete incompletePeer;
      neuron.private4 = IPAddress("10.0.0.10", false);
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.boottimens = 10;

      BrainView *incompletePeer = makePeer(uint128_t(0), 20, 0);
      incompletePeer->connected = true;
      incompletePeer->isFixedFile = true;
      incompletePeer->fslot = 16;
      brain.brains.insert(incompletePeer);

      bool preferSelf = true;
      bool sawActivePeer = false;
      suite.expect(
         brain.testResolveFailoverMasterByActivePeerAddressOrder(preferSelf, &sawActivePeer) == false,
         "failover_address_order_waits_when_only_active_peer_identity_is_incomplete");
      suite.expect(sawActivePeer, "failover_address_order_tracks_incomplete_active_peer_presence");

      brain.brains.erase(incompletePeer);
      delete incompletePeer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peerA = makePeer(uint128_t(0x200), 1);
      BrainView *peerB = makePeer(uint128_t(0x300), 1);
      peerA->existingMasterUUID = uint128_t(0x300);
      peerB->existingMasterUUID = uint128_t(0x300);
      brain.brains.insert(peerA);
      brain.brains.insert(peerB);

      suite.expect(brain.resolveConsistentExistingMasterUUID() == uint128_t(0x300), "consistent_existing_master_uuid_roundtrips");

      peerB->existingMasterUUID = uint128_t(0x400);
      suite.expect(brain.resolveConsistentExistingMasterUUID() == 0, "conflicting_existing_master_uuid_rejected");

      brain.brains.erase(peerA);
      brain.brains.erase(peerB);
      delete peerA;
      delete peerB;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      Machine machine = {};
      machine.neuron.machine = &machine;
      machine.neuron.reconnectAfterClose = true;
      machine.neuron.pendingConnect = true;
      machine.neuron.nConnectionAttempts = 2;
      machine.neuron.nAttemptsBudget = 7;
      machine.neuron.attemptDeadlineMs = Time::now<TimeResolution::ms>() + 1000;

      brain.weAreMaster = true;
      suite.expect(brain.testShouldReconnectNeuronControl(&machine.neuron), "neuron_control_reconnect_requires_active_master");

      brain.weAreMaster = false;
      suite.expect(brain.testShouldReconnectNeuronControl(&machine.neuron) == false, "neuron_control_reconnect_rejected_for_followers");

      brain.testDisarmNeuronControlReconnect(&machine.neuron);
      suite.expect(machine.neuron.reconnectAfterClose == false, "neuron_control_reconnect_disarm_clears_flag");
      suite.expect(machine.neuron.pendingConnect == false, "neuron_control_reconnect_disarm_clears_pending_connect");
      suite.expect(machine.neuron.nConnectionAttempts == 0, "neuron_control_reconnect_disarm_resets_attempts");
      suite.expect(machine.neuron.nAttemptsBudget == 0, "neuron_control_reconnect_disarm_resets_budget");
      suite.expect(machine.neuron.attemptDeadlineMs == 0, "neuron_control_reconnect_disarm_resets_deadline");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      Machine machine = {};
      machine.neuron.machine = &machine;
      machine.neuron.reconnectAfterClose = true;
      machine.neuron.pendingConnect = true;
      machine.neuron.nConnectionAttempts = 3;
      machine.neuron.nAttemptsBudget = 9;
      machine.neuron.attemptDeadlineMs = Time::now<TimeResolution::ms>() + 1000;

      brain.neurons.insert(&machine.neuron);
      brain.weAreMaster = true;
      brain.forfeitMasterStatus();

      suite.expect(brain.weAreMaster == false, "forfeit_master_status_clears_master_flag");
      suite.expect(machine.neuron.reconnectAfterClose == false, "forfeit_master_status_disarms_neuron_reconnect");
      suite.expect(machine.neuron.pendingConnect == false, "forfeit_master_status_clears_pending_neuron_connect");
      suite.expect(machine.neuron.nConnectionAttempts == 0, "forfeit_master_status_resets_neuron_attempts");
      suite.expect(machine.neuron.nAttemptsBudget == 0, "forfeit_master_status_resets_neuron_budget");
      suite.expect(machine.neuron.attemptDeadlineMs == 0, "forfeit_master_status_resets_neuron_deadline");
   }

   withUniqueMothershipSocket("forfeit_master_status_disarms_unix_listener_socket_dir_created", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.noMasterYet = false;

      const char *socketPath = ::getenv("PRODIGY_MOTHERSHIP_SOCKET");
      suite.expect(socketPath != nullptr, "forfeit_master_status_disarms_unix_listener_has_env");
      if (socketPath == nullptr)
      {
         return;
      }

      suite.expect(brain.testArmMothershipUnixListener(),
         "forfeit_master_status_disarms_unix_listener_arms_listener");
      suite.expect(brain.testMothershipUnixListenerActive(),
         "forfeit_master_status_disarms_unix_listener_starts_active");
      suite.expect(::access(socketPath, F_OK) == 0,
         "forfeit_master_status_disarms_unix_listener_creates_socket_path");

      brain.forfeitMasterStatus();

      suite.expect(brain.weAreMaster == false,
         "forfeit_master_status_disarms_unix_listener_clears_master_flag");
      suite.expect(brain.testMothershipUnixListenerActive() == false,
         "forfeit_master_status_disarms_unix_listener_marks_listener_inactive");
      suite.expect(::access(socketPath, F_OK) != 0,
         "forfeit_master_status_disarms_unix_listener_unlinks_socket_path");

      int probeFD = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
      suite.expect(probeFD >= 0,
         "forfeit_master_status_disarms_unix_listener_creates_probe_socket");
      if (probeFD >= 0)
      {
         struct sockaddr_un address = {};
         address.sun_family = AF_UNIX;
         std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", socketPath);
         socklen_t addressLen = socklen_t(sizeof(address.sun_family) + std::strlen(address.sun_path));
         suite.expect(::connect(probeFD, reinterpret_cast<struct sockaddr *>(&address), addressLen) != 0,
            "forfeit_master_status_disarms_unix_listener_rejects_new_clients");
         ::close(probeFD);
      }
   });

   {
      TestBrain brain = {};

      BrainView peer = {};
      peer.connected = true;
      peer.isFixedFile = true;
      peer.fslot = 77;
      peer.pendingSend = true;
      peer.pendingRecv = true;
      peer.pendingSendBytes = 19;
      peer.tlsPeerVerified = true;
      peer.tlsPeerUUID = 123;
      peer.wBuffer.assign("queued"_ctv);
      peer.rBuffer.assign("recv"_ctv);
      uint8_t previousGeneration = peer.ioGeneration;

      brain.testAbandonPeerSocketGeneration(&peer);

      suite.expect(peer.connected == false, "abandon_peer_socket_generation_clears_connected");
      suite.expect(peer.isFixedFile == false, "abandon_peer_socket_generation_clears_fixed_flag");
      suite.expect(peer.fslot == -1, "abandon_peer_socket_generation_clears_fixed_slot");
      suite.expect(peer.pendingSend == false, "abandon_peer_socket_generation_clears_pending_send");
      suite.expect(peer.pendingRecv == false, "abandon_peer_socket_generation_clears_pending_recv");
      suite.expect(peer.pendingSendBytes == 0, "abandon_peer_socket_generation_clears_pending_send_bytes");
      suite.expect(peer.ioGeneration != previousGeneration, "abandon_peer_socket_generation_bumps_generation");
      suite.expect(peer.wBuffer.size() == 0, "abandon_peer_socket_generation_clears_send_buffer");
      suite.expect(peer.rBuffer.size() == 0, "abandon_peer_socket_generation_clears_recv_buffer");
      suite.expect(peer.tlsPeerVerified == false, "abandon_peer_socket_generation_clears_tls_verification");
      suite.expect(peer.tlsPeerUUID == 0, "abandon_peer_socket_generation_clears_tls_uuid");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;

      BrainView *peerA = makePeer(uint128_t(0x200), 1, 0, "10.0.0.11");
      BrainView *peerB = makePeer(uint128_t(0x300), 1, 0, "10.0.0.12");
      peerA->connected = true;
      peerA->isFixedFile = true;
      peerA->fslot = 11;
      peerB->connected = false;
      brain.brains.insert(peerA);
      brain.brains.insert(peerB);

      suite.expect(brain.testShouldRetainMasterControlOnBrainLoss(), "brain_missing_master_retains_with_connected_majority");

      peerA->connected = false;
      peerA->fslot = -1;
      suite.expect(brain.testShouldRetainMasterControlOnBrainLoss() == false, "brain_missing_master_forfeits_without_connected_majority");

      brain.brains.erase(peerA);
      brain.brains.erase(peerB);
      delete peerA;
      delete peerB;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.weAreMaster = false;
      brain.updateSelfState = TestBrain::UpdateSelfState::waitingForFollowerReboots;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *peer = makePeer(uint128_t(0x220), 20, 0, "10.0.0.05");
      peer->connected = true;
      brain.brains.insert(peer);

      brain.updateSelfFollowerBootNsByPeerKey.insert_or_assign(brain.testUpdateSelfPeerTrackingKey(peer), peer->boottimens);
      brain.testBrainMissing(peer);

      suite.expect(peer->connected == false, "brain_missing_expected_update_reboot_marks_peer_disconnected");
      suite.expect(peer->quarantined == false, "brain_missing_expected_update_reboot_skips_quarantine");
      suite.expect(brain.weAreMaster == false, "brain_missing_expected_update_reboot_keeps_follower_role");
      suite.expect(brain.isMasterMissing == false, "brain_missing_expected_update_reboot_does_not_mark_master_missing");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

	      BrainView peer = {};
	      peer.weConnectToIt = true;
	      peer.connected = false;
	      peer.isFixedFile = false;
	      peer.fslot = -1;
	      peer.fd = ::dup(STDERR_FILENO);
      peer.connectTimeoutMs = 250;
      peer.nDefaultAttemptsBudget = 4;
      peer.nConnectionAttempts = 3;
      peer.attemptForMs(prodigyBrainPeerRecoveryReconnectMinMs);
      const int64_t expectedDeadlineMs = peer.attemptDeadlineMs;
      const uint32_t expectedAttemptsBudget = peer.nAttemptsBudget;

      brain.testArmOutboundPeerReconnect(&peer);

      suite.expect(peer.connected == false, "arm_outbound_peer_reconnect_marks_peer_disconnected");
      suite.expect(peer.reconnectAfterClose, "arm_outbound_peer_reconnect_arms_reconnect");
	      suite.expect(peer.nConnectionAttempts == 0, "arm_outbound_peer_reconnect_resets_attempt_counter");
	      suite.expect(peer.attemptDeadlineMs == expectedDeadlineMs, "arm_outbound_peer_reconnect_preserves_attempt_deadline");
	      suite.expect(peer.nAttemptsBudget == expectedAttemptsBudget, "arm_outbound_peer_reconnect_preserves_attempt_budget");
	      suite.expect(peer.isFixedFile == false, "arm_outbound_peer_reconnect_does_not_install_invalid_socket_without_address");
	   }

	   {
	      ScopedRing scopedRing = {};

	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();

	      BrainView peer = {};
	      peer.weConnectToIt = true;
	      peer.currentStreamAccepted = true;
	      peer.connected = false;
	      peer.isFixedFile = false;
	      peer.fslot = -1;
	      peer.fd = -1;

	      brain.testArmOutboundPeerReconnect(&peer);

	      suite.expect(peer.currentStreamAccepted == false, "arm_outbound_peer_reconnect_claims_connector_generation");
	      suite.expect(peer.isFixedFile == false, "arm_outbound_peer_reconnect_claims_connector_generation_without_address");
	   }

	   {
	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();

      BrainView peer = {};
      peer.private4 = IPAddress("10.0.0.24", false).v4;
      peer.weConnectToIt = true;
      peer.connected = false;
      peer.isFixedFile = false;
      peer.fslot = -1;
      peer.fd = ::dup(STDERR_FILENO);
      peer.connectTimeoutMs = 250;
      peer.nDefaultAttemptsBudget = 4;
      brain.testInsertBrainWaiter(&peer);

      TimeoutPacket *waiter = brain.testGetBrainWaiter(&peer);
      suite.expect(waiter != nullptr, "arm_outbound_peer_reconnect_cancels_stale_waiter_installs_waiter");

      brain.testArmOutboundPeerReconnect(&peer);

      suite.expect(brain.testHasBrainWaiter(&peer) == false, "arm_outbound_peer_reconnect_cancels_stale_waiter_erases_waiter");
      suite.expect(waiter != nullptr && waiter->flags == uint64_t(BrainTimeoutFlags::canceled), "arm_outbound_peer_reconnect_cancels_stale_waiter_marks_canceled");

      if (peer.isFixedFile)
      {
         Ring::uninstallFromFixedFileSlot(&peer);
      }
      else if (peer.fd >= 0)
      {
         ::close(peer.fd);
      }
      peer.fd = -1;
      peer.isFixedFile = false;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x21e), 0, IPAddress("10.0.0.18", false).v4, "10.0.0.18");
      peer->weConnectToIt = true;
      peer->reconnectAfterClose = true;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      peer->nConnectionAttempts = 2;
      peer->nAttemptsBudget = 9;
      peer->attemptDeadlineMs = 12345;
      peer->fd = -1;
      peer->isFixedFile = false;
      brain.brains.insert(peer);

      brain.testInsertBrainWaiter(peer);
      TimeoutPacket *waiter = brain.testGetBrainWaiter(peer);
      suite.expect(waiter != nullptr, "brain_close_handler_connector_inert_duplicate_cancels_waiter_fixture_arms_waiter");

      brain.testCloseHandler(peer);

      suite.expect(brain.testHasBrainWaiter(peer), "brain_close_handler_connector_inert_duplicate_preserves_waiter");
      suite.expect(waiter != nullptr && waiter->flags == 0, "brain_close_handler_connector_inert_duplicate_keeps_waiter_live");
      suite.expect(peer->fd == -1, "brain_close_handler_connector_inert_duplicate_keeps_fd_unarmed");
      suite.expect(peer->isFixedFile == false, "brain_close_handler_connector_inert_duplicate_keeps_fixed_slot_unarmed");
      suite.expect(peer->reconnectAfterClose, "brain_close_handler_connector_inert_duplicate_preserves_reconnect_policy");
      suite.expect(peer->nConnectionAttempts == 2, "brain_close_handler_connector_inert_duplicate_preserves_attempt_counter");
      suite.expect(peer->nAttemptsBudget == 9, "brain_close_handler_connector_inert_duplicate_preserves_attempt_budget");
      suite.expect(peer->attemptDeadlineMs == 12345, "brain_close_handler_connector_inert_duplicate_preserves_attempt_deadline");

      brain.testEraseBrainWaiter(peer);
      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.weAreMaster = false;
      brain.noMasterYet = false;

      BrainView *peer = makePeer(uint128_t(0x2202), 202, IPAddress("10.0.0.12", false).v4, "10.0.0.12");
      peer->connected = true;
      peer->weConnectToIt = true;
      peer->reconnectAfterClose = false;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      peer->existingMasterUUID = peer->uuid;
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_close_handler_connector_master_claim_installs_socket");
      if (installed)
      {
         peer->noteCloseQueuedForCurrentTransport();
         Ring::queueClose(peer);
         brain.testCloseHandler(peer);

         TimeoutPacket *waiter = brain.testGetBrainWaiter(peer);
         suite.expect(waiter != nullptr, "brain_close_handler_connector_master_claim_arms_missing_waiter");
         suite.expect(peer->connected == false, "brain_close_handler_connector_master_claim_marks_peer_disconnected");
         suite.expect(peer->registrationFresh == false, "brain_close_handler_connector_master_claim_clears_registration_freshness");
         suite.expect(peer->reconnectAfterClose, "brain_close_handler_connector_master_claim_rearms_reconnect");
         suite.expect(waiter != nullptr && waiter->timeoutMs() == int64_t(peer->nDefaultAttemptsBudget * peer->connectTimeoutMs + prodigyBrainPeerInboundMissingSlackMs), "brain_close_handler_connector_master_claim_waiter_uses_failover_window");

         cleanupBrainPeerSocket(*peer, peerFD);
      }

      brain.testEraseBrainWaiter(peer);
      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x21f), 19);
      peer->connected = true;
      peer->weConnectToIt = true;
      peer->reconnectAfterClose = false;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_close_handler_connector_cqe_cleared_closing_installs_fixture");
      if (installed)
      {
         suite.expect(Ring::socketIsClosing(peer) == false, "brain_close_handler_connector_cqe_cleared_closing_precondition");
         peer->noteCloseQueuedForCurrentTransport();
         brain.testCloseHandler(peer);

         suite.expect(peer->connected == false, "brain_close_handler_connector_cqe_cleared_closing_marks_disconnected");
         suite.expect(peer->registrationFresh == false, "brain_close_handler_connector_cqe_cleared_closing_clears_registration_freshness");
         suite.expect(peer->reconnectAfterClose, "brain_close_handler_connector_cqe_cleared_closing_rearms_reconnect");

         cleanupBrainPeerSocket(*peer, peerFD);
      }

      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x21f1), 191, IPAddress("10.0.0.19", false).v4, "10.0.0.19");
      peer->connected = true;
      peer->weConnectToIt = true;
      peer->reconnectAfterClose = false;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_close_handler_connector_cancels_stale_waiter_installs_fixture");
      if (installed)
      {
         brain.testInsertBrainWaiter(peer);
         TimeoutPacket *waiter = brain.testGetBrainWaiter(peer);
         suite.expect(waiter != nullptr, "brain_close_handler_connector_cancels_stale_waiter_arms_waiter");

         peer->noteCloseQueuedForCurrentTransport();
         Ring::queueClose(peer);
         brain.testCloseHandler(peer);

         suite.expect(brain.testHasBrainWaiter(peer) == false, "brain_close_handler_connector_cancels_stale_waiter_erases_waiter");
         suite.expect(waiter != nullptr && waiter->flags == uint64_t(BrainTimeoutFlags::canceled), "brain_close_handler_connector_cancels_stale_waiter_marks_canceled");
         suite.expect(peer->connected == false, "brain_close_handler_connector_cancels_stale_waiter_marks_disconnected");
         suite.expect(peer->reconnectAfterClose, "brain_close_handler_connector_cancels_stale_waiter_rearms_reconnect");

         cleanupBrainPeerSocket(*peer, peerFD);
      }

      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x220), 20);
      peer->connected = true;
      peer->weConnectToIt = true;
      peer->reconnectAfterClose = false;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_close_handler_connector_installs_socket");
      if (installed)
      {
         peer->noteCloseQueuedForCurrentTransport();
         Ring::queueClose(peer);
         brain.testCloseHandler(peer);

         suite.expect(peer->connected == false, "brain_close_handler_connector_marks_peer_disconnected");
         suite.expect(peer->registrationFresh == false, "brain_close_handler_connector_clears_registration_freshness");
         suite.expect(peer->reconnectAfterClose, "brain_close_handler_connector_rearms_reconnect");
         TimeoutPacket *reconnectWaiter = brain.testGetBrainReconnectWaiter(peer);
         suite.expect(reconnectWaiter != nullptr, "brain_close_handler_connector_arms_reconnect_waiter");
         suite.expect(peer->attemptDeadlineMs == 0, "brain_close_handler_connector_defers_persistent_reconnect_deadline_until_timer");

         cleanupBrainPeerSocket(*peer, peerFD);
         brain.testEraseBrainReconnectWaiter(peer);
      }

      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;

      BrainView *peer = makePeer(uint128_t(0x2201), 201, IPAddress("10.0.0.11", false).v4, "10.0.0.11");
      peer->connected = true;
      peer->weConnectToIt = true;
      peer->reconnectAfterClose = false;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      peer->isMasterBrain = true;
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_close_handler_connector_master_installs_socket");
      if (installed)
      {
         peer->noteCloseQueuedForCurrentTransport();
         Ring::queueClose(peer);
         brain.testCloseHandler(peer);

         TimeoutPacket *waiter = brain.testGetBrainWaiter(peer);
         suite.expect(waiter != nullptr, "brain_close_handler_connector_master_arms_missing_waiter");
         suite.expect(peer->connected == false, "brain_close_handler_connector_master_marks_peer_disconnected");
         suite.expect(peer->registrationFresh == false, "brain_close_handler_connector_master_clears_registration_freshness");
         suite.expect(peer->reconnectAfterClose, "brain_close_handler_connector_master_rearms_reconnect");
         TimeoutPacket *reconnectWaiter = brain.testGetBrainReconnectWaiter(peer);
         suite.expect(reconnectWaiter != nullptr, "brain_close_handler_connector_master_arms_reconnect_waiter");
         suite.expect(peer->attemptDeadlineMs == 0, "brain_close_handler_connector_master_defers_persistent_reconnect_deadline_until_timer");
         suite.expect(waiter != nullptr && waiter->timeoutMs() == int64_t(peer->nDefaultAttemptsBudget * peer->connectTimeoutMs + prodigyBrainPeerInboundMissingSlackMs), "brain_close_handler_connector_master_waiter_uses_failover_window");

         cleanupBrainPeerSocket(*peer, peerFD);
         brain.testEraseBrainReconnectWaiter(peer);
      }

      brain.testEraseBrainWaiter(peer);
      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.updateSelfState = TestBrain::UpdateSelfState::waitingForFollowerReboots;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *peer = makePeer(uint128_t(0x221), 21, IPAddress("10.0.0.11", false).v4, "10.0.0.11");
      peer->connected = true;
      peer->weConnectToIt = false;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      brain.brains.insert(peer);
      brain.updateSelfFollowerBootNsByPeerKey.insert_or_assign(brain.testUpdateSelfPeerTrackingKey(peer), peer->boottimens);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_close_handler_inbound_installs_socket");
      if (installed)
      {
         peer->noteCloseQueuedForCurrentTransport();
         Ring::queueClose(peer);
         brain.testCloseHandler(peer);

         suite.expect(peer->connected == false, "brain_close_handler_inbound_marks_peer_disconnected");
         suite.expect(peer->registrationFresh == false, "brain_close_handler_inbound_clears_registration_freshness");
         suite.expect(brain.testHasBrainWaiter(peer), "brain_close_handler_inbound_arms_missing_waiter");

         cleanupBrainPeerSocket(*peer, peerFD);
      }

      brain.testEraseBrainWaiter(peer);
      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x2212), 212, IPAddress("127.0.0.1", false).v4, "127.0.0.1");
      peer->connected = false;
      peer->quarantined = true;
      peer->weConnectToIt = false;
      brain.brains.insert(peer);
      brain.testInsertBrainWaiter(peer);

      TimeoutPacket *waiter = brain.testGetBrainWaiter(peer);
      suite.expect(waiter != nullptr, "brain_accept_handler_known_peer_cancels_stale_waiter_installs_waiter");

      RingDispatcher::installMultiplexee(&brain.brainSocket, &brain);
      int listenerPair[2] = {-1, -1};
      suite.expect(
         ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, listenerPair) == 0,
         "brain_accept_handler_known_peer_cancels_stale_waiter_creates_listener_pair");
      if (listenerPair[0] >= 0)
      {
         brain.brainSocket.fd = listenerPair[0];
         Ring::installFDIntoFixedFileSlot(&brain.brainSocket);
      }

      int acceptedFD = -1;
      int acceptedSlot = -1;
      int peerFD = -1;
      int acceptedPair[2] = {-1, -1};
      suite.expect(
         ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, acceptedPair) == 0,
         "brain_accept_handler_known_peer_cancels_stale_waiter_creates_accepted_pair");
      if (acceptedPair[0] >= 0)
      {
         acceptedFD = acceptedPair[0];
         peerFD = acceptedPair[1];
      }

      if (acceptedFD >= 0)
      {
         struct sockaddr_in *acceptedAddress = reinterpret_cast<struct sockaddr_in *>(&brain.brain_saddr);
         memset(&brain.brain_saddr, 0, sizeof(brain.brain_saddr));
         acceptedAddress->sin_family = AF_INET;
         acceptedAddress->sin_port = htons(uint16_t(ReservedPorts::brain));
         acceptedAddress->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
         brain.brain_saddrlen = sizeof(struct sockaddr_in);

         acceptedSlot = Ring::adoptProcessFDIntoFixedFileSlot(acceptedFD, false);
         suite.expect(acceptedSlot >= 0, "brain_accept_handler_known_peer_cancels_stale_waiter_adopts_fixed_slot");
         if (acceptedSlot >= 0)
         {
            brain.testAcceptHandler(&brain.brainSocket, acceptedSlot);

            suite.expect(brain.testHasBrainWaiter(peer) == false, "brain_accept_handler_known_peer_cancels_stale_waiter_erases_waiter");
            suite.expect(waiter != nullptr && waiter->flags == uint64_t(BrainTimeoutFlags::canceled), "brain_accept_handler_known_peer_cancels_stale_waiter_marks_canceled");
            suite.expect(peer->connected, "brain_accept_handler_known_peer_cancels_stale_waiter_marks_connected");
            suite.expect(peer->currentStreamAccepted, "brain_accept_handler_known_peer_cancels_stale_waiter_marks_accepted_stream");
            suite.expect(peer->pendingRecv, "brain_accept_handler_known_peer_cancels_stale_waiter_arms_recv");

            cleanupBrainPeerSocket(*peer, peerFD);
         }
      }

      if (acceptedFD >= 0)
      {
         ::close(acceptedFD);
      }
      if (brain.brainSocket.isFixedFile)
      {
         Ring::uninstallFromFixedFileSlot(&brain.brainSocket);
      }
      if (brain.brainSocket.fd >= 0)
      {
         ::close(brain.brainSocket.fd);
         brain.brainSocket.fd = -1;
      }
      if (listenerPair[1] >= 0)
      {
         ::close(listenerPair[1]);
      }

      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x2211), 211, IPAddress("10.0.0.11", false).v4, "10.0.0.11");
      peer->connected = true;
      peer->weConnectToIt = false;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_close_handler_inbound_duplicate_close_preserves_existing_waiter_installs_socket");
      if (installed)
      {
         peer->noteCloseQueuedForCurrentTransport();
         Ring::queueClose(peer);
         brain.testCloseHandler(peer);

         TimeoutPacket *firstWaiter = brain.testGetBrainWaiter(peer);
         suite.expect(firstWaiter != nullptr, "brain_close_handler_inbound_duplicate_close_preserves_existing_waiter_arms_waiter");

         brain.testCloseHandler(peer);

         suite.expect(brain.testGetBrainWaiter(peer) == firstWaiter, "brain_close_handler_inbound_duplicate_close_preserves_existing_waiter_pointer");

         cleanupBrainPeerSocket(*peer, peerFD);
      }

      brain.testEraseBrainWaiter(peer);
      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x222), 22);
      peer->connected = true;
      peer->weConnectToIt = true;
      peer->reconnectAfterClose = true;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_close_handler_connector_retry_installs_socket");
      if (installed)
      {
         peer->noteCloseQueuedForCurrentTransport();
         Ring::queueClose(peer);
         brain.testCloseHandler(peer);

         suite.expect(peer->connected == false, "brain_close_handler_connector_retry_marks_peer_disconnected");
         suite.expect(peer->reconnectAfterClose, "brain_close_handler_connector_retry_keeps_reconnect_armed");
         suite.expect(peer->nAttemptsBudget == 0, "brain_close_handler_connector_retry_leaves_attempt_budget_unset");

         cleanupBrainPeerSocket(*peer, peerFD);
      }

      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x2221), 22, IPAddress("10.0.0.31", false).v4, "10.0.0.31");
      peer->connected = true;
      peer->weConnectToIt = true;
      peer->reconnectAfterClose = true;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_close_handler_connector_retry_addressful_installs_fixture");
      if (installed)
      {
         peer->noteCloseQueuedForCurrentTransport();
         Ring::queueClose(peer);
         brain.testCloseHandler(peer);

         suite.expect(peer->connected == false, "brain_close_handler_connector_retry_addressful_marks_peer_disconnected");
         TimeoutPacket *reconnectWaiter = brain.testGetBrainReconnectWaiter(peer);
         suite.expect(reconnectWaiter != nullptr, "brain_close_handler_connector_retry_addressful_arms_reconnect_waiter");
         suite.expect(peer->isFixedFile == false, "brain_close_handler_connector_retry_addressful_defers_peer_socket_install");
         suite.expect(peer->fslot < 0, "brain_close_handler_connector_retry_addressful_defers_fixed_file_slot");

         cleanupBrainPeerSocket(*peer, peerFD);
         brain.testEraseBrainReconnectWaiter(peer);
      }

      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x223), 23);
      peer->connected = true;
      peer->weConnectToIt = true;
      peer->reconnectAfterClose = false;
      peer->connectTimeoutMs = 0;
      peer->nDefaultAttemptsBudget = 7;
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_close_handler_connector_zero_timeout_installs_socket");
      if (installed)
      {
         peer->noteCloseQueuedForCurrentTransport();
         Ring::queueClose(peer);
         brain.testCloseHandler(peer);

         suite.expect(peer->connected == false, "brain_close_handler_connector_zero_timeout_marks_peer_disconnected");
         TimeoutPacket *reconnectWaiter = brain.testGetBrainReconnectWaiter(peer);
         suite.expect(reconnectWaiter != nullptr, "brain_close_handler_connector_zero_timeout_arms_reconnect_waiter");
         suite.expect(peer->nAttemptsBudget == 0, "brain_close_handler_connector_zero_timeout_defers_default_attempt_budget_until_timer");

         cleanupBrainPeerSocket(*peer, peerFD);
         brain.testEraseBrainReconnectWaiter(peer);
      }

      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      BrainView *peer = makePeer(uint128_t(0x2231), 23, IPAddress("10.0.0.32", false).v4, "10.0.0.32");
      peer->connected = true;
      peer->weConnectToIt = true;
      peer->reconnectAfterClose = false;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_close_handler_connector_persistent_addressful_installs_fixture");
      if (installed)
      {
         peer->noteCloseQueuedForCurrentTransport();
         Ring::queueClose(peer);
         brain.testCloseHandler(peer);

         suite.expect(peer->connected == false, "brain_close_handler_connector_persistent_addressful_marks_peer_disconnected");
         TimeoutPacket *reconnectWaiter = brain.testGetBrainReconnectWaiter(peer);
         suite.expect(reconnectWaiter != nullptr, "brain_close_handler_connector_persistent_addressful_arms_reconnect_waiter");
         suite.expect(peer->attemptDeadlineMs == 0, "brain_close_handler_connector_persistent_addressful_defers_reconnect_deadline_until_timer");
         suite.expect(peer->isFixedFile == false, "brain_close_handler_connector_persistent_addressful_defers_peer_socket_install");
         suite.expect(peer->fslot < 0, "brain_close_handler_connector_persistent_addressful_defers_fixed_file_slot");

         cleanupBrainPeerSocket(*peer, peerFD);
         brain.testEraseBrainReconnectWaiter(peer);
      }

      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;

      Machine machine = {};
      machine.private4 = IPAddress("10.0.0.20", false).v4;
      machine.neuron.machine = &machine;
      machine.neuron.connected = true;
      machine.neuron.reconnectAfterClose = true;
      machine.neuron.connectTimeoutMs = 250;
      machine.neuron.nDefaultAttemptsBudget = 4;
      brain.neurons.insert(&machine.neuron);

      int peerFD = -1;
      bool installed = installNeuronSocket(brain, machine, peerFD);
      suite.expect(installed, "brain_close_handler_master_neuron_cqe_cleared_closing_installs_fixture");
      if (installed)
      {
         suite.expect(Ring::socketIsClosing(&machine.neuron) == false, "brain_close_handler_master_neuron_cqe_cleared_closing_precondition");
	         brain.testCloseHandler(&machine.neuron);

	         suite.expect(machine.neuron.connected == false, "brain_close_handler_master_neuron_cqe_cleared_closing_marks_disconnected");
	         suite.expect(machine.neuron.reconnectAfterClose, "brain_close_handler_master_neuron_cqe_cleared_closing_keeps_reconnect_armed");
	         TimeoutPacket *waiter = brain.testGetNeuronReconnectWaiter(&machine.neuron);
	         suite.expect(waiter != nullptr, "brain_close_handler_master_neuron_cqe_cleared_closing_arms_reconnect_waiter");
	         suite.expect(waiter != nullptr && waiter->timeoutMs() == machine.neuron.connectTimeoutMs, "brain_close_handler_master_neuron_cqe_cleared_closing_uses_connect_timeout_retry");
	         brain.testEraseNeuronReconnectWaiter(&machine.neuron);

	         cleanupNeuronSocket(machine.neuron, peerFD);
	      }
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;

      Machine machine = {};
      machine.private4 = IPAddress("10.0.0.20", false).v4;
      machine.neuron.machine = &machine;
      machine.neuron.connected = true;
      machine.neuron.reconnectAfterClose = true;
      machine.neuron.connectTimeoutMs = 250;
      machine.neuron.nDefaultAttemptsBudget = 4;
      brain.neurons.insert(&machine.neuron);

      int peerFD = -1;
      bool installed = installNeuronSocket(brain, machine, peerFD);
      suite.expect(installed, "brain_close_handler_master_neuron_installs_socket");
      if (installed)
      {
         Ring::queueClose(&machine.neuron);
	         brain.testCloseHandler(&machine.neuron);

	         suite.expect(machine.neuron.connected == false, "brain_close_handler_master_neuron_marks_disconnected");
	         suite.expect(machine.neuron.reconnectAfterClose, "brain_close_handler_master_neuron_keeps_reconnect_armed");
	         TimeoutPacket *waiter = brain.testGetNeuronReconnectWaiter(&machine.neuron);
	         suite.expect(waiter != nullptr, "brain_close_handler_master_neuron_arms_reconnect_waiter");

	         brain.testCloseHandler(&machine.neuron);
	         suite.expect(brain.testGetNeuronReconnectWaiter(&machine.neuron) == waiter, "brain_close_handler_master_neuron_duplicate_close_preserves_reconnect_waiter");
	         brain.testEraseNeuronReconnectWaiter(&machine.neuron);

	         cleanupNeuronSocket(machine.neuron, peerFD);
	      }
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      NeuronBase *savedLocalNeuron = thisNeuron;
      thisNeuron = nullptr;

      Machine machine = {};
      machine.privateAddress.assign("10.0.0.22"_ctv);
      machine.neuron.machine = &machine;
      machine.neuron.connected = true;
      machine.neuron.reconnectAfterClose = true;
      machine.neuron.connectTimeoutMs = 250;
      machine.neuron.nDefaultAttemptsBudget = 4;
      machine.neuron.setIPVersion(AF_INET);
      brain.neurons.insert(&machine.neuron);

      int peerFD = -1;
      bool installed = installNeuronSocket(brain, machine, peerFD);
      suite.expect(installed, "brain_close_handler_master_neuron_addressful_installs_fixture");
      if (installed)
      {
         Ring::queueClose(&machine.neuron);
	         brain.testCloseHandler(&machine.neuron);

	         suite.expect(machine.neuron.connected == false, "brain_close_handler_master_neuron_addressful_marks_disconnected");
	         TimeoutPacket *waiter = brain.testGetNeuronReconnectWaiter(&machine.neuron);
	         suite.expect(waiter != nullptr, "brain_close_handler_master_neuron_addressful_arms_reconnect_waiter");

	         if (waiter != nullptr)
	         {
	            brain.testDispatchTimeout(waiter);
	         }

	         suite.expect(machine.neuron.isFixedFile == false, "brain_close_handler_master_neuron_addressful_waits_for_close_completion_before_socket_install");
	         suite.expect(machine.neuron.fslot < 0, "brain_close_handler_master_neuron_addressful_keeps_fixed_file_slot_clear_while_close_in_flight");
	         suite.expect(machine.neuron.pendingConnect == false, "brain_close_handler_master_neuron_addressful_defers_connect_while_close_in_flight");
	         TimeoutPacket *deferredWaiter = brain.testGetNeuronReconnectWaiter(&machine.neuron);
	         suite.expect(deferredWaiter != nullptr, "brain_close_handler_master_neuron_addressful_rearms_reconnect_waiter_while_close_in_flight");
	         brain.testEraseNeuronReconnectWaiter(&machine.neuron);

         cleanupNeuronSocket(machine.neuron, peerFD);
      }

      thisNeuron = savedLocalNeuron;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      NeuronBase *savedLocalNeuron = thisNeuron;
      thisNeuron = nullptr;

      Machine machine = {};
      machine.uuid = uint128_t(0x90225);
      machine.privateAddress.assign("10.0.0.225"_ctv);
      machine.private4 = IPAddress("10.0.0.225", false).v4;
      machine.neuron.machine = &machine;
      machine.neuron.connected = true;
      machine.neuron.hadSuccessfulConnection = true;
      machine.neuron.reconnectAfterClose = true;
      machine.neuron.connectTimeoutMs = 250;
      machine.neuron.nDefaultAttemptsBudget = 4;
      machine.neuron.pendingSend = true;
      machine.neuron.pendingRecv = true;
      machine.neuron.pendingSendBytes = 17;
      machine.neuron.pendingConnect = true;
      machine.neuron.attemptDeadlineMs = Time::now<TimeResolution::ms>() + 1000;
      machine.neuron.tlsPeerVerified = true;
      machine.neuron.setIPVersion(AF_INET);
      Message::construct(machine.neuron.wBuffer, NeuronTopic::spinContainer, uint128_t(0), String("stale"_ctv));
      machine.neuron.rBuffer.reserve(8);
      memset(machine.neuron.rBuffer.pTail(), 0xAB, 4);
      machine.neuron.rBuffer.advance(4);
      brain.neurons.insert(&machine.neuron);

      int peerFD = -1;
      bool installed = installNeuronSocket(brain, machine, peerFD);
      suite.expect(installed, "brain_close_handler_master_neuron_reconnect_resets_transport_generation_installs_fixture");
      if (installed)
      {
	         brain.testCloseHandler(&machine.neuron);

	         suite.expect(machine.neuron.pendingSend == false, "brain_close_handler_master_neuron_reconnect_resets_transport_generation_clears_pending_send");
	         suite.expect(machine.neuron.pendingRecv == false, "brain_close_handler_master_neuron_reconnect_resets_transport_generation_clears_pending_recv");
	         suite.expect(machine.neuron.pendingSendBytes == 0, "brain_close_handler_master_neuron_reconnect_resets_transport_generation_clears_pending_send_bytes");
	         suite.expect(machine.neuron.pendingConnect == false, "brain_close_handler_master_neuron_reconnect_resets_transport_generation_defers_connect_until_waiter");
	         suite.expect(machine.neuron.wBuffer.outstandingBytes() == 0, "brain_close_handler_master_neuron_reconnect_resets_transport_generation_clears_buffered_send_bytes");
	         suite.expect(machine.neuron.rBuffer.outstandingBytes() == 0, "brain_close_handler_master_neuron_reconnect_resets_transport_generation_clears_buffered_recv_bytes");
	         suite.expect(machine.neuron.tlsPeerVerified == false, "brain_close_handler_master_neuron_reconnect_resets_transport_generation_clears_tls_peer");
	         TimeoutPacket *waiter = brain.testGetNeuronReconnectWaiter(&machine.neuron);
	         suite.expect(waiter != nullptr, "brain_close_handler_master_neuron_reconnect_resets_transport_generation_arms_reconnect_waiter");

	         if (waiter != nullptr)
	         {
	            brain.testDispatchTimeout(waiter);
	         }
	         suite.expect(machine.neuron.pendingConnect, "brain_close_handler_master_neuron_reconnect_resets_transport_generation_rearms_pending_connect_after_waiter");

	         brain.testConnectHandler(&machine.neuron, 0);

         Vector<uint16_t> topics = {};
         suite.expect(countQueuedTopics(machine.neuron.wBuffer, topics), "brain_close_handler_master_neuron_reconnect_resets_transport_generation_parses_messages");
         suite.expect(machine.neuron.pendingConnect == false, "brain_close_handler_master_neuron_reconnect_resets_transport_generation_connect_clears_pending_connect");
         suite.expect(machine.neuron.pendingSend, "brain_close_handler_master_neuron_reconnect_resets_transport_generation_rearms_registration_send");
         suite.expect(machine.neuron.pendingSendBytes > 0, "brain_close_handler_master_neuron_reconnect_resets_transport_generation_tracks_registration_send_bytes");
         suite.expect(topics.size() == 1, "brain_close_handler_master_neuron_reconnect_resets_transport_generation_drops_stale_payload");
         suite.expect(topics[0] == uint16_t(NeuronTopic::registration), "brain_close_handler_master_neuron_reconnect_resets_transport_generation_queues_registration_only");

         cleanupNeuronSocket(machine.neuron, peerFD);
      }

      thisNeuron = savedLocalNeuron;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = false;

      Machine machine = {};
      machine.private4 = IPAddress("10.0.0.21", false).v4;
      machine.neuron.machine = &machine;
      machine.neuron.connected = true;
      machine.neuron.reconnectAfterClose = true;
      machine.neuron.nConnectionAttempts = 2;
      machine.neuron.nAttemptsBudget = 5;
      brain.neurons.insert(&machine.neuron);

      int peerFD = -1;
      bool installed = installNeuronSocket(brain, machine, peerFD);
      suite.expect(installed, "brain_close_handler_follower_neuron_installs_socket");
      if (installed)
      {
         Ring::queueClose(&machine.neuron);
         brain.testCloseHandler(&machine.neuron);

         suite.expect(machine.neuron.connected == false, "brain_close_handler_follower_neuron_marks_disconnected");
	         suite.expect(machine.neuron.reconnectAfterClose == false, "brain_close_handler_follower_neuron_disarms_reconnect");
	         suite.expect(machine.neuron.nConnectionAttempts == 0, "brain_close_handler_follower_neuron_resets_attempts");
	         suite.expect(machine.neuron.nAttemptsBudget == 0, "brain_close_handler_follower_neuron_resets_budget");
	         suite.expect(brain.testHasNeuronReconnectWaiter(&machine.neuron) == false, "brain_close_handler_follower_neuron_does_not_arm_reconnect_waiter");

	         cleanupNeuronSocket(machine.neuron, peerFD);
	      }
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.mothershipAcceptArmed = true;

      brain.testCloseHandler(&brain.mothershipSocket);

      suite.expect(brain.mothershipAcceptArmed == false, "brain_close_handler_mothership_listener_disarms_accept");
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.mothershipAcceptArmed = true;

      brain.testCloseHandler(&brain.mothershipSocket);

      suite.expect(brain.mothershipAcceptArmed == false, "brain_close_handler_mothership_listener_master_clears_accept_when_tcp_disabled");
   }

   withUniqueMothershipSocket("brain_close_handler_mothership_unix_listener_rearms_when_master", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;

      suite.expect(brain.testArmMothershipUnixListener(), "brain_close_handler_mothership_unix_listener_rearm_fixture_arms_listener");
      suite.expect(brain.testMothershipUnixListenerActive(), "brain_close_handler_mothership_unix_listener_rearm_fixture_listener_active");

      const int closedListenerFD = brain.mothershipUnixSocket.fd;
      Ring::uninstallFromFixedFileSlot(&brain.mothershipUnixSocket);
      ::close(closedListenerFD);
      ::unlink(brain.mothershipUnixSocketPath.c_str());
      brain.mothershipUnixSocket.fd = -1;
      brain.mothershipUnixSocket.fslot = -1;
      brain.mothershipUnixSocket.isFixedFile = false;

      brain.testCloseHandler(&brain.mothershipUnixSocket);

      suite.expect(brain.testMothershipUnixListenerActive(), "brain_close_handler_mothership_unix_listener_rearms_listener_when_master");
   });

	   {
	      TestBrain brain = {};
	      brain.iaas = new NoopBrainIaaS();
	      brain.mothershipUnixAcceptArmed = true;

	      char socketDirectoryTemplate[] = "/tmp/prodigy-brain-close-follower-XXXXXX";
	      char *socketDirectory = ::mkdtemp(socketDirectoryTemplate);
	      String socketPath = {};
	      int listenerFD = -1;
	      suite.expect(socketDirectory != nullptr, "brain_close_handler_mothership_unix_listener_follower_creates_socket_dir");
	      if (socketDirectory != nullptr)
	      {
	         socketPath.assign(socketDirectory);
	         socketPath.append("/mothership.sock"_ctv);
	         suite.expect(createUnixListener(socketPath, listenerFD),
	            "brain_close_handler_mothership_unix_listener_follower_creates_socket_path");
	         suite.expect(::access(socketPath.c_str(), F_OK) == 0,
	            "brain_close_handler_mothership_unix_listener_follower_socket_path_exists_before");
	         brain.mothershipUnixSocketPath.assign(socketPath);
	      }

	      brain.testCloseHandler(&brain.mothershipUnixSocket);

	      suite.expect(brain.mothershipUnixAcceptArmed == false, "brain_close_handler_mothership_unix_listener_disarms_accept");
		      if (socketPath.size() > 0)
		      {
		         suite.expect(::access(socketPath.c_str(), F_OK) == 0,
		            "brain_close_handler_mothership_unix_listener_follower_preserves_unowned_socket_path");
		      }
	      if (listenerFD >= 0)
	      {
	         ::close(listenerFD);
	      }
	      if (socketPath.size() > 0)
	      {
	         ::unlink(socketPath.c_str());
	      }
	      if (socketDirectory != nullptr)
	      {
	         ::rmdir(socketDirectory);
	      }
	   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.testRegisterActiveMothership(new Mothership());

      brain.testCloseHandler(brain.mothership);

      suite.expect(brain.mothership == nullptr, "brain_close_handler_mothership_stream_clears_active_stream");
   }

   withUniqueMothershipSocket("brain_close_handler_mothership_stream_requeues_unix_accept_when_master", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;

      suite.expect(brain.testArmMothershipUnixListener(), "brain_close_handler_mothership_stream_rearm_fixture_arms_listener");
      brain.mothershipUnixAcceptArmed = false;
      brain.testRegisterActiveMothership(new Mothership());

      brain.testCloseHandler(brain.mothership);

      suite.expect(brain.mothership == nullptr, "brain_close_handler_mothership_stream_master_clears_active_stream");
      suite.expect(brain.testMothershipUnixListenerActive(), "brain_close_handler_mothership_stream_master_keeps_unix_listener_active");
   });

   {
      ScopedRing scopedRing = {};
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;
      brain.mothershipUnixSocketPath.assign("/tmp/prodigy-test-mothership.sock"_ctv);

      int firstPair[2] = {-1, -1};
      int secondPair[2] = {-1, -1};
      if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, firstPair) != 0)
      {
         suite.expect(false, "brain_mothership_accept_handler_keeps_existing_stream_creates_first_socketpair");
      }
      else if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, secondPair) != 0)
      {
         suite.expect(false, "brain_mothership_accept_handler_keeps_existing_stream_creates_second_socketpair");
      }
      else
      {
         int firstSlot = Ring::adoptProcessFDIntoFixedFileSlot(firstPair[0], false);
         int secondSlot = Ring::adoptProcessFDIntoFixedFileSlot(secondPair[0], false);
         suite.expect(firstSlot >= 0, "brain_mothership_accept_handler_keeps_existing_stream_installs_first_fixed_slot");
         suite.expect(secondSlot >= 0, "brain_mothership_accept_handler_keeps_existing_stream_installs_second_fixed_slot");

         if (firstSlot >= 0 && secondSlot >= 0)
         {
            brain.testAcceptHandler(&brain.mothershipUnixSocket, firstSlot);
            Mothership *firstStream = brain.testCurrentMothership();

            brain.testAcceptHandler(&brain.mothershipUnixSocket, secondSlot);
            Mothership *secondStream = brain.testCurrentMothership();

            suite.expect(firstStream != nullptr, "brain_mothership_accept_handler_keeps_existing_stream_tracks_first_stream");
            suite.expect(secondStream != nullptr, "brain_mothership_accept_handler_keeps_existing_stream_tracks_second_stream");
            suite.expect(secondStream != firstStream, "brain_mothership_accept_handler_keeps_existing_stream_uses_distinct_stream_objects");
            suite.expect(brain.testActiveMothershipCount() == 2, "brain_mothership_accept_handler_keeps_existing_stream_tracks_two_active_streams");
            suite.expect(brain.testContainsActiveMothership(firstStream), "brain_mothership_accept_handler_keeps_existing_stream_preserves_first_stream");
            suite.expect(brain.testContainsActiveMothership(secondStream), "brain_mothership_accept_handler_keeps_existing_stream_preserves_second_stream");
            suite.expect(Ring::socketIsClosing(firstStream) == false, "brain_mothership_accept_handler_keeps_existing_stream_does_not_close_first_stream");
            suite.expect(Ring::socketIsClosing(secondStream) == false, "brain_mothership_accept_handler_keeps_existing_stream_does_not_close_second_stream");

            brain.testCloseHandler(secondStream);
            suite.expect(brain.testActiveMothershipCount() == 1, "brain_mothership_accept_handler_keeps_existing_stream_closing_second_preserves_one_active_stream");
            suite.expect(brain.testContainsActiveMothership(firstStream), "brain_mothership_accept_handler_keeps_existing_stream_closing_second_preserves_first_stream");
            suite.expect(brain.testCurrentMothership() == firstStream, "brain_mothership_accept_handler_keeps_existing_stream_closing_second_repoints_current_stream");

            brain.testCloseHandler(firstStream);
            suite.expect(brain.testActiveMothershipCount() == 0, "brain_mothership_accept_handler_keeps_existing_stream_closing_first_clears_active_streams");
            suite.expect(brain.testCurrentMothership() == nullptr, "brain_mothership_accept_handler_keeps_existing_stream_closing_first_clears_current_stream");
         }
      }

      for (int fd : {firstPair[0], firstPair[1], secondPair[0], secondPair[1]})
      {
         if (fd >= 0)
         {
            ::close(fd);
         }
      }
   }

   {
      ScopedRing scopedRing = {};
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      int fds[2] = {-1, -1};
      if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) == 0)
      {
         Mothership *retiredStream = new Mothership();
         retiredStream->fd = fds[0];
         retiredStream->isFixedFile = false;
         retiredStream->closeAfterSendDrain = true;
         brain.testRegisterActiveMothership(retiredStream);
         Ring::installFDIntoFixedFileSlot(retiredStream);

         suite.expect(retiredStream->isFixedFile, "brain_destroy_idle_mothership_stream_fixture_installs_fixed_file");
         suite.expect(retiredStream->fslot >= 0, "brain_destroy_idle_mothership_stream_fixture_has_fixed_slot");

         brain.testDestroyIdleMothershipStreamNow(retiredStream);

         suite.expect(brain.mothership == nullptr, "brain_destroy_idle_mothership_stream_retires_active_pointer");
         suite.expect(brain.closingMotherships.contains(retiredStream), "brain_destroy_idle_mothership_stream_tracks_retired_stream");
         suite.expect(Ring::socketIsClosing(retiredStream), "brain_destroy_idle_mothership_stream_marks_stream_closing");
         suite.expect(retiredStream->closeAfterSendDrain == false, "brain_destroy_idle_mothership_stream_clears_drain_flag");
         suite.expect(retiredStream->isFixedFile == false, "brain_destroy_idle_mothership_stream_relinquishes_fixed_file_state");
         suite.expect(retiredStream->fslot == -1, "brain_destroy_idle_mothership_stream_clears_fixed_slot");

         brain.closingMotherships.erase(retiredStream);
         Ring::shutdownForExec();
         scopedRing.created = false;
         delete retiredStream;

         ::close(fds[1]);
         fds[0] = -1;
         fds[1] = -1;
      }
      else
      {
         suite.expect(false, "brain_destroy_idle_mothership_stream_creates_socketpair");
      }
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      Mothership *retiredStream = new Mothership();
      brain.closingMotherships.insert(retiredStream);

      brain.testCloseHandler(retiredStream);

      suite.expect(brain.closingMotherships.contains(retiredStream) == false, "brain_close_handler_mothership_retired_stream_erases_closing_set");
   }

   withUniqueMothershipSocket("brain_close_handler_retired_mothership_stream_requeues_unix_accept_when_master", [&] {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = true;

      suite.expect(brain.testArmMothershipUnixListener(), "brain_close_handler_retired_mothership_stream_rearm_fixture_arms_listener");
      brain.mothershipUnixAcceptArmed = false;

      Mothership *retiredStream = new Mothership();
      brain.closingMotherships.insert(retiredStream);

      brain.testCloseHandler(retiredStream);

      suite.expect(brain.closingMotherships.contains(retiredStream) == false, "brain_close_handler_retired_mothership_stream_master_erases_closing_set");
      suite.expect(brain.testMothershipUnixListenerActive(), "brain_close_handler_retired_mothership_stream_master_keeps_unix_listener_active");
   });

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      MachineSSH *ssh = new MachineSSH();
      ssh->reconnectAfterClose = false;
      brain.sshs.insert(ssh);

      brain.testCloseHandler(ssh);

      suite.expect(brain.sshs.contains(ssh) == false, "brain_close_handler_ssh_cleanup_erases_ssh_set");
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();

      Machine machine = {};
      machine.state = MachineState::healthy;

      MachineSSH *ssh = new MachineSSH();
      ssh->machine = &machine;
      ssh->reconnectAfterClose = true;
      ssh->connectTimeoutMs = 250;
      ssh->nDefaultAttemptsBudget = 4;
      brain.sshs.insert(ssh);

      brain.testCloseHandler(ssh);

      suite.expect(machine.state == MachineState::neuronRebooting, "brain_close_handler_ssh_reconnect_marks_machine_rebooting");
      suite.expect(brain.sshs.contains(ssh), "brain_close_handler_ssh_reconnect_keeps_ssh_registered");

      brain.sshs.erase(ssh);
      delete ssh;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;
      brain.localBrainPeerAddresses.push_back(ClusterMachinePeerAddress{"10.0.0.10"_ctv, 0});

      BrainView *peer = makePeer(uint128_t(0x220), 20, IPAddress("10.0.0.11", false).v4);
      peer->quarantined = true;
      peer->weConnectToIt = false;

      brain.testBrainFound(peer);

      suite.expect(peer->boottimens == 0, "brain_found_resets_boottime_until_reregistration");
      suite.expect(peer->quarantined == false, "brain_found_clears_quarantine");
      suite.expect(peer->weConnectToIt, "brain_found_recomputes_connector_ownership");
      suite.expect(peer->peerAddressText.equals("10.0.0.11"_ctv), "brain_found_configures_peer_connect_address_for_connector");

      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;
      brain.localBrainPeerAddresses.push_back(ClusterMachinePeerAddress{"10.0.0.10"_ctv, 0});

      BrainView *peer = makePeer(uint128_t(0x220), 21, IPAddress("10.0.0.9", false).v4);
      peer->quarantined = true;
      peer->weConnectToIt = true;

      brain.testBrainFound(peer);

      suite.expect(peer->boottimens == 0, "brain_found_non_connector_resets_boottime_until_reregistration");
      suite.expect(peer->quarantined == false, "brain_found_non_connector_clears_quarantine");
      suite.expect(peer->weConnectToIt == false, "brain_found_non_connector_does_not_claim_connector_ownership");
      suite.expect(peer->peerAddressText.size() == 0, "brain_found_non_connector_does_not_configure_connect_address");

      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = false;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *peer = makePeer(uint128_t(0x220), 22);
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      brain.brains.insert(peer);

      brain.testBrainMissing(peer);

      suite.expect(peer->quarantined, "brain_missing_sets_quarantine_on_first_missing_transition");
      suite.expect(peer->attemptDeadlineMs > 0, "brain_missing_first_transition_arms_reconnect_deadline");
      suite.expect(peer->reconnectAfterClose, "brain_missing_first_transition_marks_peer_for_reconnect");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = false;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *peer = makePeer(uint128_t(0x220), 221);
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      brain.brains.insert(peer);

      brain.testInsertBrainWaiter(peer);
      TimeoutPacket *activeWaiter = brain.testGetBrainWaiter(peer);
      suite.expect(activeWaiter != nullptr, "brain_missing_timeout_ignores_stale_untracked_packet_installs_waiter");
      if (activeWaiter != nullptr)
      {
         activeWaiter->flags = uint64_t(BrainTimeoutFlags::brainMissing);

         TimeoutPacket *staleWaiter = new TimeoutPacket();
         staleWaiter->flags = uint64_t(BrainTimeoutFlags::brainMissing);
         staleWaiter->originator = peer;
         staleWaiter->dispatcher = &brain;

         brain.testDispatchTimeout(staleWaiter);

         suite.expect(brain.testGetBrainWaiter(peer) == activeWaiter, "brain_missing_timeout_ignores_stale_untracked_packet_preserves_waiter");
         suite.expect(peer->quarantined == false, "brain_missing_timeout_ignores_stale_untracked_packet_does_not_quarantine");
      }

      brain.testEraseBrainWaiter(peer);
      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.weAreMaster = false;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *peer = makePeer(uint128_t(0x220), 222);
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      brain.brains.insert(peer);

      brain.testInsertBrainWaiter(peer);
      TimeoutPacket *activeWaiter = brain.testGetBrainWaiter(peer);
      suite.expect(activeWaiter != nullptr, "brain_missing_timeout_tracked_packet_installs_waiter");
      if (activeWaiter != nullptr)
      {
         activeWaiter->flags = uint64_t(BrainTimeoutFlags::brainMissing);
         brain.testDispatchTimeout(activeWaiter);

         suite.expect(brain.testHasBrainWaiter(peer) == false, "brain_missing_timeout_tracked_packet_clears_waiter");
         suite.expect(peer->quarantined, "brain_missing_timeout_tracked_packet_quarantines_peer");
      }

      brain.brains.erase(peer);
      delete peer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.weAreMaster = true;
      brain.updateSelfState = TestBrain::UpdateSelfState::waitingForFollowerReboots;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *peer = makePeer(uint128_t(0x220), 23);
      peer->connected = true;
      peer->connectTimeoutMs = 250;
      peer->nDefaultAttemptsBudget = 4;
      brain.brains.insert(peer);
      brain.updateSelfFollowerBootNsByPeerKey.insert_or_assign(brain.testUpdateSelfPeerTrackingKey(peer), peer->boottimens);

      brain.testBrainMissing(peer);

      suite.expect(peer->quarantined == false, "brain_missing_expected_update_reboot_master_skips_quarantine");
      suite.expect(peer->reconnectAfterClose, "brain_missing_expected_update_reboot_master_rearms_reconnect");
      suite.expect(peer->attemptDeadlineMs > 0, "brain_missing_expected_update_reboot_master_preserves_reconnect_window");
      suite.expect(brain.weAreMaster, "brain_missing_expected_update_reboot_master_keeps_master_role");

      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 1;
      brain.weAreMaster = true;
      brain.localBrainPeerAddress = IPAddress("10.0.0.12", false);
      brain.localBrainPeerAddressText = "10.0.0.12"_ctv;

      BrainView *peer = makePeer(uint128_t(0x2203), 223, IPAddress("10.0.0.11", false).v4, "10.0.0.11");
      peer->connected = true;
      peer->currentStreamAccepted = true;
      peer->registrationFresh = true;
      peer->tlsPeerVerified = true;
      brain.brains.insert(peer);

      int peerFD = -1;
      bool installed = installBrainPeerSocket(brain, *peer, peerFD);
      suite.expect(installed, "brain_missing_master_inflight_close_preserves_force_connector_fixture_installs");
      if (installed)
      {
         Ring::queueClose(peer);
         brain.testBrainMissing(peer);

         suite.expect(peer->quarantined, "brain_missing_master_inflight_close_does_not_stack_redial_quarantines_peer");
         suite.expect(Ring::socketIsClosing(peer), "brain_missing_master_inflight_close_does_not_stack_redial_keeps_close_in_flight");
         suite.expect(peer->connectAttemptPending() == false, "brain_missing_master_inflight_close_does_not_stack_redial_skips_duplicate_connect_attempt");
         suite.expect(brain.weAreMaster, "brain_missing_master_inflight_close_does_not_stack_redial_retains_master_role");

         brain.testCloseHandler(peer);
         if (TimeoutPacket *waiter = brain.testGetBrainWaiter(peer); waiter != nullptr)
         {
            waiter->flags = uint64_t(BrainTimeoutFlags::canceled);
            brain.testDispatchTimeout(waiter);
         }
      }

      cleanupBrainPeerSocket(*peer, peerFD);
      brain.brains.erase(peer);
      delete peer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.weAreMaster = false;
      brain.noMasterYet = false;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *masterPeer = makePeer(uint128_t(0x220), 20, IPAddress("10.0.0.11", false).v4, "10.0.0.11");
      masterPeer->connected = true;
      masterPeer->isFixedFile = true;
      masterPeer->fslot = 32;
      masterPeer->isMasterBrain = true;
      brain.brains.insert(masterPeer);

      BrainView *followerPeer = makePeer(uint128_t(0x330), 21, IPAddress("10.0.0.12", false).v4, "10.0.0.12");
      followerPeer->connected = true;
      followerPeer->isFixedFile = true;
      followerPeer->fslot = 33;
      brain.brains.insert(followerPeer);

      brain.testBrainMissing(masterPeer);

      bool sawMasterMissingFrame = false;
      forEachMessageInBuffer(followerPeer->wBuffer, [&] (Message *frame) {
         if (BrainTopic(frame->topic) == BrainTopic::masterMissing)
         {
            sawMasterMissingFrame = true;
         }
      });

      suite.expect(masterPeer->quarantined, "brain_missing_master_peer_quarantines_missing_master");
      suite.expect(brain.isMasterMissing, "brain_missing_master_peer_marks_master_missing");
      suite.expect(sawMasterMissingFrame, "brain_missing_master_peer_gossips_master_missing_to_other_peers");
      suite.expect(brain.weAreMaster == false, "brain_missing_master_peer_does_not_self_elect_immediately");

      brain.brains.erase(masterPeer);
      brain.brains.erase(followerPeer);
      delete masterPeer;
      delete followerPeer;
   }

   {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.weAreMaster = false;
      brain.noMasterYet = false;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *masterPeer = makePeer(uint128_t(0x221), 25, IPAddress("10.0.0.11", false).v4, "10.0.0.11");
      masterPeer->connected = true;
      masterPeer->isFixedFile = true;
      masterPeer->fslot = 36;
      masterPeer->existingMasterUUID = masterPeer->uuid;
      brain.brains.insert(masterPeer);

      BrainView *followerPeer = makePeer(uint128_t(0x331), 26, IPAddress("10.0.0.12", false).v4, "10.0.0.12");
      followerPeer->connected = true;
      followerPeer->isFixedFile = true;
      followerPeer->fslot = 37;
      brain.brains.insert(followerPeer);

      brain.testBrainMissing(masterPeer);

      bool sawMasterMissingFrame = false;
      forEachMessageInBuffer(followerPeer->wBuffer, [&] (Message *frame) {
         if (BrainTopic(frame->topic) == BrainTopic::masterMissing)
         {
            sawMasterMissingFrame = true;
         }
      });

      suite.expect(masterPeer->quarantined, "brain_missing_master_claim_quarantines_missing_master");
      suite.expect(brain.isMasterMissing, "brain_missing_master_claim_marks_master_missing");
      suite.expect(sawMasterMissingFrame, "brain_missing_master_claim_gossips_master_missing_to_other_peers");

      brain.brains.erase(masterPeer);
      brain.brains.erase(followerPeer);
      delete masterPeer;
      delete followerPeer;
   }

   withUniqueMothershipSocket("brain_missing_single_brain_isolation_socket_dir_created", [&] {
      ScopedRing scopedRing = {};

      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 1;
      brain.weAreMaster = false;
      brain.noMasterYet = false;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *masterPeer = makePeer(uint128_t(0x220), 20, IPAddress("10.0.0.11", false).v4, "10.0.0.11");
      masterPeer->connected = true;
      masterPeer->isFixedFile = true;
      masterPeer->fslot = 34;
      masterPeer->isMasterBrain = true;
      brain.brains.insert(masterPeer);

      brain.testBrainMissing(masterPeer);

      suite.expect(brain.weAreMaster, "brain_missing_single_brain_isolation_self_elects");
      suite.expect(brain.noMasterYet == false, "brain_missing_single_brain_isolation_clears_no_master");
      suite.expect(masterPeer->quarantined, "brain_missing_single_brain_isolation_quarantines_missing_peer");

      brain.brains.erase(masterPeer);
      delete masterPeer;
   });

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.weAreMaster = true;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *missingPeer = makePeer(uint128_t(0x220), 20);
      missingPeer->connected = true;
      missingPeer->connectTimeoutMs = 250;
      missingPeer->nDefaultAttemptsBudget = 4;
      brain.brains.insert(missingPeer);

      BrainView *healthyPeer = makePeer(uint128_t(0x330), 21);
      healthyPeer->connected = true;
      healthyPeer->isFixedFile = true;
      healthyPeer->fslot = 35;
      brain.brains.insert(healthyPeer);

      brain.testBrainMissing(missingPeer);

      suite.expect(brain.masterQuorumDegraded, "brain_missing_master_majority_marks_quorum_degraded");
      suite.expect(brain.weAreMaster, "brain_missing_master_majority_retains_master_role");
      suite.expect(missingPeer->quarantined, "brain_missing_master_majority_quarantines_missing_peer");
      suite.expect(missingPeer->reconnectAfterClose, "brain_missing_master_majority_arms_reconnect");

      brain.brains.erase(missingPeer);
      brain.brains.erase(healthyPeer);
      delete missingPeer;
      delete healthyPeer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 2;
      brain.weAreMaster = false;
      brain.noMasterYet = false;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *masterPeer = makePeer(uint128_t(0x220), 24);
      masterPeer->connected = true;
      masterPeer->isMasterBrain = true;
      brain.brains.insert(masterPeer);

      brain.testBrainMissing(masterPeer);

      suite.expect(masterPeer->quarantined, "brain_missing_all_quarantined_multi_brain_quarantines_master_peer");
      suite.expect(brain.isMasterMissing, "brain_missing_all_quarantined_multi_brain_marks_master_missing");
      suite.expect(brain.weAreMaster == false, "brain_missing_all_quarantined_multi_brain_does_not_self_elect");

      brain.brains.erase(masterPeer);
      delete masterPeer;
   }

   {
      TestBrain brain = {};
      brain.iaas = new NoopBrainIaaS();
      brain.nBrains = 3;
      brain.weAreMaster = true;
      brain.localBrainPeerAddress = IPAddress("10.0.0.10", false);
      brain.localBrainPeerAddressText = "10.0.0.10"_ctv;

      BrainView *peer = makePeer(uint128_t(0x220), 20);
      peer->connected = true;
      brain.brains.insert(peer);

      brain.testBrainMissing(peer);

      suite.expect(brain.masterQuorumDegraded, "brain_missing_master_path_marks_quorum_degraded");
      suite.expect(brain.weAreMaster == false, "brain_missing_master_path_forfeits_master_without_majority");
      suite.expect(peer->quarantined, "brain_missing_master_path_quarantines_peer");
      suite.expect(peer->reconnectAfterClose, "brain_missing_master_path_arms_reconnect");

      brain.brains.erase(peer);
      delete peer;
   }

   thisNeuron = nullptr;

   if (suite.failed != 0)
   {
      basics_log("prodigy_brain_master_uuid_unit failed=%d\n", suite.failed);
      return EXIT_FAILURE;
   }

   basics_log("prodigy_brain_master_uuid_unit ok\n");
   return EXIT_SUCCESS;
}
