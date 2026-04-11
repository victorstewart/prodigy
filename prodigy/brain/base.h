#pragma once

#include <services/bitsery.h>
#include <services/crypto.h>
#include <services/filesystem.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/socket.h>
#include <networking/pool.h>
#include <networking/stream.h>
#include <networking/message.h>
#include <networking/ring.h>
#include <prodigy/version.h>
#include <prodigy/iaas/iaas.h>
#include <prodigy/neuron/base.h>
#include <prodigy/containerstore.h>
#include <prodigy/brain/rack.h>
#include <prodigy/brain/machine.h>
#include <prodigy/brain/timing.knobs.h>
#include <prodigy/cluster.machine.helpers.h>
#include <prodigy/brain/metrics.h>
#include <prodigy/transport.tls.h>
#include <networking/email.client.h>
#include <networking/reconnector.h>

class ContainerView;
class ApplicationDeployment;
class MachineTicket;
class Mesh;
class Wormhole;

class BrainView : public RingInterface, public ProdigyTransportTLSStream, public CoroutineStack, public Reconnector {
public:

	Machine *machine = nullptr;
	uint128_t uuid = 0;
	int64_t boottimens = 0;
	int64_t creationTimeMs = 0;
	uint64_t version = 0;
	bool isMasterMissing = false;
	bool isMasterBrain = false;
	bool quarantined = false;
	bool weConnectToIt = false;
	bool connected = false;
	uint8_t datacenterFragment = 0;

	uint32_t private4 = 0; // even if it connects to us, allows us to keep it in the brain bin until (if ever) it reconnects to us. then we check the privates
	uint32_t gatewayPrivate4 = 0;
	IPAddress peerAddress = {};
	String peerAddressText;
   Vector<ClusterMachinePeerAddress> peerAddresses;
   uint32_t peerAddressIndex = 0;

	uint128_t existingMasterUUID = 0; // that master's persistent brain UUID

	BrainView()
	{
		rBuffer.reserve(8_KB);
		wBuffer.reserve(16_KB);
	}

	bool canQueueSend(void) const
	{
		if (connected == false)
		{
			return false;
		}

		if (isFixedFile == false || fslot < 0)
		{
			return false;
		}

		return (Ring::socketIsClosing(const_cast<BrainView *>(this)) == false);
	}

	void reset() override 
   {
      ProdigyTransportTLSStream::reset();
      Reconnector::reset();
		connected = false;
   }

	// we need some kind of log to know what updates to replay for slave brains?
	void sendRegistration(int64_t boottimens, uint64_t version, uint128_t existingMasterUUID)
	{
		if (canQueueSend() == false)
		{
			std::fprintf(stderr,
				"prodigy debug brain registration-skip private4=%u connected=%d isFixed=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d closing=%d tls=%d negotiated=%d wbytes=%u\n",
				private4,
				int(connected),
				int(isFixedFile),
				fd,
				fslot,
				int(pendingSend),
				int(pendingRecv),
				int(Ring::socketIsClosing(this)),
				int(transportTLSEnabled()),
				int(isTLSNegotiated()),
				uint32_t(wBuffer.outstandingBytes()));
			std::fflush(stderr);
			return;
		}

		// send them our uuid + boottimens
		// figure out who main brain is... if us then we gather machines and do other stuff, 
		// we would only be booting into main brain if we were the first machine in the datacenter... so by definition no other machines or state to gather/sync

		// uuid(16) boottimens(8) version(8) existingMasterUUID(16)
		uint32_t headerOffset = Message::appendHeader(wBuffer, static_cast<uint16_t>(BrainTopic::registration));
		Message::append(wBuffer, thisNeuron->uuid);
		Message::append(wBuffer, boottimens);
		Message::append(wBuffer, version);
		Message::append(wBuffer, existingMasterUUID);
		Message::finish(wBuffer, headerOffset);

		Ring::queueSend(this);
		std::fprintf(stderr,
			"prodigy debug brain registration-queued private4=%u connected=%d isFixed=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d tls=%d negotiated=%d sendBytes=%u queuedBytes=%llu wbytes=%u\n",
			private4,
			int(connected),
			int(isFixedFile),
			fd,
			fslot,
			int(pendingSend),
			int(pendingRecv),
			int(transportTLSEnabled()),
			int(isTLSNegotiated()),
			unsigned(pendingSendBytes),
			(unsigned long long)queuedSendOutstandingBytes(),
			uint32_t(wBuffer.outstandingBytes()));
		std::fflush(stderr);
	}

	void sendMasterMissing(void)
	{
		if (canQueueSend() == false)
		{
			return;
		}

		Message::appendEcho(wBuffer, static_cast<uint16_t>(BrainTopic::masterMissing));
		Ring::queueSend(this);
	}

	void respondMasterMissing(bool status)
	{
		if (canQueueSend() == false)
		{
			return;
		}

		Message::construct(wBuffer, static_cast<uint16_t>(BrainTopic::masterMissing), status);
		Ring::queueSend(this);
	}
};

class BrainBase : public RingMultiplexer {
public:

	static inline Vector<String> launchArguments = {};

	static void captureLaunchArguments(int argc, char *argv[])
	{
		launchArguments.clear();
		if (argc <= 0 || argv == nullptr)
		{
			return;
		}

		launchArguments.reserve(uint64_t(argc));
		for (int i = 0; i < argc; ++i)
		{
			if (argv[i] == nullptr)
			{
				break;
			}

			String argument = {};
			argument.assign(argv[i]);
			launchArguments.push_back(std::move(argument));
		}
	}

	static bool buildLaunchArgumentsForExec(const String& binaryPath, Vector<char *>& argv)
	{
		argv.clear();
		if (launchArguments.empty())
		{
			return false;
		}

		launchArguments[0].assign(binaryPath);
		argv.reserve(launchArguments.size() + 1);
		for (String& argument : launchArguments)
		{
			argv.push_back(const_cast<char *>(argument.c_str()));
		}

		argv.push_back(nullptr);
		return true;
	}

	static MachineState machineBootstrapLifecycleState(int64_t creationTimeMs)
	{
		if (creationTimeMs > 0)
		{
			if (int64_t sinceCreationMs = Time::now<TimeResolution::ms>() - creationTimeMs; sinceCreationMs < Time::minsToMs(7))
			{
				return MachineState::deploying;
			}
		}

		return MachineState::unknown;
	}

	static bool controlPlaneDevModeEnabled(void)
	{
		if (const char *devMode = getenv("PRODIGY_DEV_MODE"); devMode && devMode[0] == '1' && devMode[1] == '\0')
		{
			return true;
		}

		return false;
	}

	static uint32_t controlPlaneConnectTimeoutMs(bool isDevMode = false)
	{
		return (isDevMode ? prodigyBrainDevControlPlaneConnectTimeoutMs : prodigyBrainControlPlaneConnectTimeoutMs);
	}

	static uint32_t controlPlaneConnectAttemptsBudget(bool isDevMode = false)
	{
		return (isDevMode ? prodigyBrainDevControlPlaneConnectAttempts : prodigyBrainControlPlaneConnectAttempts);
	}

	static uint32_t machineInitialConnectAttemptTimeMs(int64_t creationTimeMs, int64_t connectTimeoutMs, uint32_t defaultAttemptsBudget, bool isDevMode = false)
	{
		uint32_t connectAttemptTimeMs = 0;
		if (creationTimeMs > 0)
		{
			if (int64_t sinceCreationMs = Time::now<TimeResolution::ms>() - creationTimeMs; sinceCreationMs < Time::minsToMs(7))
			{
				connectAttemptTimeMs = Time::minsToMs(7) - sinceCreationMs;
			}
		}

		connectAttemptTimeMs += uint32_t(connectTimeoutMs) * defaultAttemptsBudget;
		if (isDevMode && connectAttemptTimeMs < 10'000)
		{
			connectAttemptTimeMs = 10'000;
		}

		return connectAttemptTimeMs;
	}

	static uint32_t machineBootstrapSoftEscalationTimeoutMs(int64_t creationTimeMs, int64_t connectTimeoutMs, uint32_t defaultAttemptsBudget, bool isDevMode = false)
	{
		uint32_t timeoutMs = prodigyBrainControlPlaneSoftEscalationFloorMs;
		uint32_t bootstrapWindowMs = machineInitialConnectAttemptTimeMs(
			creationTimeMs,
			connectTimeoutMs,
			defaultAttemptsBudget,
			isDevMode);

		if (bootstrapWindowMs > timeoutMs)
		{
			timeoutMs = bootstrapWindowMs;
		}

		return timeoutMs;
	}

	static uint32_t controlPlaneIgnitionTimeoutMs(bool isDevMode = false)
	{
		return machineBootstrapSoftEscalationTimeoutMs(
			0,
			controlPlaneConnectTimeoutMs(isDevMode),
			controlPlaneConnectAttemptsBudget(isDevMode),
			isDevMode);
	}

	uint64_t version = ProdigyBinaryVersion;
	BrainConfig brainConfig;

	BrainIaaS *iaas;
	
	bytell_hash_map<uint32_t, Rack *> racks;
	bytell_hash_set<Machine *> machines;
	bytell_hash_set<BrainView *> brains;
	bytell_hash_map<uint128_t, ContainerView *> containers;
	bytell_hash_map<uint64_t, ApplicationDeployment *> deployments;
	bytell_hash_map<uint16_t, ApplicationDeployment *> deploymentsByApp; // when not master we only fill this

	// these are were non master brains store deployment plans
	bytell_hash_map<uint64_t, DeploymentPlan> deploymentPlans;

	// these will be culled once every 10 minutes
		TimeoutPacket failedDeploymentCleaner;
		bytell_hash_map<uint64_t, String> failedDeployments;

	EmailClient batphone;

	bytell_hash_set<uint32_t> usedMachineFragments;

		// only master also
		Mesh *mesh;
		MetricsStore metrics;

		static constexpr int64_t metricRetentionMs = prodigyBrainMetricRetentionMs; // 6h
		static constexpr int64_t metricTrimMinIntervalMs = prodigyBrainMetricTrimMinIntervalMs;
		static constexpr int64_t metricPersistMinIntervalMs = prodigyBrainMetricPersistMinIntervalMs;
		static constexpr int64_t autoscaleIntervalMs = prodigyBrainAutoscaleIntervalMs; // 1 minute
		int64_t lastMetricTrimMs = 0;
      int64_t lastMetricPersistMs = 0;

		static uint64_t metricKeyFromName(const String& metricName)
		{
			return ProdigyMetrics::metricKeyForName(metricName);
		}

		void recordContainerMetric(uint64_t deploymentID, uint128_t containerUUID, uint64_t metricKey, int64_t sampleTimeMs, double value)
		{
			metrics.record(deploymentID, containerUUID, metricKey, sampleTimeMs, value);

         int64_t nowMs = Time::now<TimeResolution::ms>();
         if (lastMetricPersistMs == 0 || (nowMs - lastMetricPersistMs) >= metricPersistMinIntervalMs)
         {
            lastMetricPersistMs = nowMs;
            persistLocalRuntimeState();
         }
		}

		void trimContainerMetrics(int64_t nowMs)
		{
			if (lastMetricTrimMs > 0 && (nowMs - lastMetricTrimMs) < metricTrimMinIntervalMs)
			{
				return;
			}

			metrics.trimRetention(nowMs, metricRetentionMs);
			lastMetricTrimMs = nowMs;
		}

	// some application might require vertical scaling instead of horizontal
		virtual void respinApplication(ApplicationDeployment *deployment) = 0;
		virtual void pushSpinApplicationProgressToMothership(ApplicationDeployment *deployment, const String& message) = 0;
		virtual void spinApplicationFailed(ApplicationDeployment *deployment, const String& message) = 0;
		virtual void spinApplicationFin(ApplicationDeployment *deployment) = 0;
      virtual void persistLocalRuntimeState(void)
      {
      }
      virtual void adoptLocalMachineHardwareProfile(const MachineHardwareProfile& hardware)
      {
         (void)hardware;
      }
      virtual void noteLocalContainerHealthy(uint128_t containerUUID)
      {
         (void)containerUUID;
      }
		virtual void applyCredentialsToContainerPlan(const DeploymentPlan& deploymentPlan, const ContainerView& container, ContainerPlan& plan)
		{
			(void)deploymentPlan;
			(void)container;
			(void)plan;
		}
		virtual bool canControlNeurons(void) const { return true; }
		virtual bool hasHealthyMachines(void) const
		{
		for (Machine *machine : machines)
		{
			if (machine->state == MachineState::healthy)
			{
				return true;
			}
		}

		return false;
	}

	protected:

			static bool installNeuronControlSocket(NeuronView *neuron)
			{
				if (neuron == nullptr || neuron->fd < 0)
				{
					return false;
				}

				if (neuron->machine != nullptr)
				{
					prodigyConfigureMachineNeuronEndpoint(*neuron->machine, thisNeuron);
				}

				if (neuron->daddrLen == 0)
				{
					return false;
				}

				if (Ring::bindSourceAddressBeforeFixedFileInstall(neuron) == false)
				{
					return false;
				}

				if (neuron->isNonBlocking == false)
				{
					neuron->setNonBlocking();
				}

				int processFD = neuron->fd;
				int slot = Ring::adoptProcessFDIntoFixedFileSlot(processFD);
				if (slot < 0)
				{
					::close(processFD);
					return false;
				}

				neuron->fslot = slot;
				neuron->isFixedFile = true;
				return true;
			}

			static void disarmNeuronControlReconnect(NeuronView *neuron)
			{
				if (neuron == nullptr)
				{
					return;
				}

				neuron->reconnectAfterClose = false;
				neuron->nConnectionAttempts = 0;
				neuron->nAttemptsBudget = 0;
			}

			virtual void armMachineNeuronControl(Machine *machine)
			{
				if (machine == nullptr)
				{
					return;
				}

				RingDispatcher::installMultiplexee(&machine->neuron, this);
				if (installNeuronControlSocket(&machine->neuron))
				{
					// Freshly provisioned cloud machines can take minutes before the
					// control socket is accepting. Give neuron-control reconnect the
					// same creation-aware grace window as brain-peer bootstrap so the
					// master does not reset/delete brand-new machines immediately.
					machine->neuron.attemptForMs(machineInitialConnectAttemptTimeMs(
						machine->creationTimeMs,
						machine->neuron.connectTimeoutMs,
						machine->neuron.nDefaultAttemptsBudget));
					machine->neuron.attemptConnect();
				}
			}

	public:

	void deploymentFailed(ApplicationDeployment *deployment, uint64_t deploymentID, StringType auto&& reason, bool preserveContainerImage = false)
	{
		spinApplicationFailed(deployment, reason);

		failedDeployments.insert_or_assign(deploymentID, reason);
      persistLocalRuntimeState();

		failedDeploymentCleaner.setTimeoutMs(prodigyBrainFailedDeploymentCleanerIntervalMs); // 90 seconds
		Ring::queueUpdateTimeout(&failedDeploymentCleaner);

		if (preserveContainerImage == false)
		{
			ContainerStore::destroy(deploymentID);
			queueBrainReplication(BrainTopic::cullDeployment, deploymentID);
		}
	}

	void finishMachineConfig(Machine *machine)
	{
		std::fprintf(stderr, "prodigy machine finish-config begin machine=%p uuid=%llu private4=%u isBrain=%d isThisMachine=%d slug=%s fd=%d isFixed=%d fslot=%d\n",
			machine,
			(unsigned long long)(machine ? machine->uuid : 0),
			unsigned(machine ? machine->private4 : 0),
			int(machine ? machine->isBrain : 0),
			int(machine ? machine->isThisMachine : 0),
			machine ? machine->slug.c_str() : "",
			machine ? machine->neuron.fd : -1,
			machine ? int(machine->neuron.isFixedFile) : 0,
			machine ? machine->neuron.fslot : -1);
		std::fflush(stderr);

		if (auto rackIt = racks.find(machine->rackUUID); rackIt != racks.end())
		{
			machine->rack = rackIt->second;
		}
		else
		{
			Rack *rack = new Rack();
			rack->uuid = machine->rackUUID;
			machine->rack = rack;
		
			racks[machine->rackUUID] = rack;
		}

      if (auto configIt = brainConfig.configBySlug.find(machine->slug); configIt != brainConfig.configBySlug.end())
      {
         MachineConfig& config = configIt->second;
         if (config.nLogicalCores == 0)
         {
            config.nLogicalCores = machine->totalLogicalCores > 0 ? machine->totalLogicalCores : machine->ownedLogicalCores;
         }
         if (config.nMemoryMB == 0)
         {
            config.nMemoryMB = machine->totalMemoryMB > 0 ? machine->totalMemoryMB : machine->ownedMemoryMB;
         }
         if (config.nStorageMB == 0)
         {
            config.nStorageMB = machine->totalStorageMB > 0 ? machine->totalStorageMB : machine->ownedStorageMB;
         }
      }

		if (machine->isBrain)
		{
			for (BrainView *brain : brains)
			{
				// Brain identity is source-address based (peer private4), not socket destination.
				if (brain->private4 == machine->private4)
				{
					machine->brain = brain;
					brain->machine = machine;

					break;
				}
			}
		}

		machine->rack->machines.insert(machine);
		machines.insert(machine); // the initial getMachines has already inserted them into here, but whatever

		bool isDevMode = controlPlaneDevModeEnabled();
		machine->neuron.connectTimeoutMs = controlPlaneConnectTimeoutMs(isDevMode);
		machine->neuron.nDefaultAttemptsBudget = controlPlaneConnectAttemptsBudget(isDevMode);

		// Register the Machine* as a multiplexee so timeouts that use
		// packet->originator = machine route back to this Brain
		std::fprintf(stderr, "prodigy machine finish-config install-multiplexee machine=%p uuid=%llu private4=%u\n",
			machine,
			(unsigned long long)machine->uuid,
			unsigned(machine->private4));
		std::fflush(stderr);
		RingDispatcher::installMultiplexee(machine, this);

		if (canControlNeurons() == false)
		{
			// Architecture rule: only the active master owns neuron control sockets.
			std::fprintf(stderr, "prodigy machine finish-config skip-control machine=%p uuid=%llu private4=%u\n",
				machine,
				(unsigned long long)machine->uuid,
				unsigned(machine->private4));
			std::fflush(stderr);
			return;
		}

		std::fprintf(stderr, "prodigy machine finish-config arm-control machine=%p uuid=%llu private4=%u\n",
			machine,
			(unsigned long long)machine->uuid,
			unsigned(machine->private4));
		std::fflush(stderr);
		armMachineNeuronControl(machine);
		std::fprintf(stderr, "prodigy machine finish-config done machine=%p uuid=%llu private4=%u fd=%d isFixed=%d fslot=%d\n",
			machine,
			(unsigned long long)machine->uuid,
			unsigned(machine->private4),
			machine->neuron.fd,
			int(machine->neuron.isFixedFile),
			machine->neuron.fslot);
		std::fflush(stderr);
	}

	void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count)
	{
		bool coroWasNull = !coro;

		if (coroWasNull) coro = new CoroutineStack();

		bytell_hash_set<Machine *> newMachines;
		String error;

		uint32_t suspendIndex = coro->nextSuspendIndex();

		iaas->spinMachines(coro, lifetime, config, count, newMachines, error);

		if (suspendIndex < coro->nextSuspendIndex())
		{
			co_await coro->suspendAtIndex(suspendIndex);
		}

		if (newMachines.size() > 0)
		{
			for (Machine *machine : newMachines)
			{
				finishMachineConfig(machine);
				machine->state = MachineState::deploying; // once the machine becomes healthy, we will feed it to deployments looking to schedule load
			}
		}
		else // error
		{
			String message;
			message.snprintf_add<"when trying to spin {itoa}x {} instances, we got the following error from the cloud provider api:\n\n"_ctv>(count, config.slug);
			message.snprintf_add<"Error: {}"_ctv>(error);

			String subject;

			switch (lifetime)
			{
				case MachineLifetime::owned:
				{
					subject.append("Failed to Spin Owned Hardware 🤖"_ctv);
					break;
				}
				case MachineLifetime::reserved:
				{
					subject.append("Failed to Spin Reserved Hardware 🤖"_ctv);
					break;
				}
				case MachineLifetime::ondemand:
				{
					subject.append("Failed to Spin OnDemand Hardware 🤖"_ctv);
					break;
				}
				case MachineLifetime::spot:
				{
					subject.append("Failed to Spin Spot Hardware 🤖"_ctv);
					break;
				}
			}

			batphone.sendEmail(brainConfig.reporter.from, brainConfig.reporter.to, subject, message);
		}

		if (coroWasNull) delete coro;
	}

	virtual void requestMachines(MachineTicket *ticket, ApplicationDeployment *deployment, ApplicationLifetime lifetime, uint32_t nMore) = 0;

   static constexpr uint64_t brainPeerReplicationBufferedBytesLimit = 512_MB;
   static constexpr uint64_t brainPeerReplicationFrameHeadroomBytes = 256_KB;

   uint64_t brainPeerBufferedBytes(const BrainView *brain) const
   {
      if (brain == nullptr)
      {
         return 0;
      }

      const uint64_t plaintextBytes = brain->wBuffer.outstandingBytes();
      if (brain->transportTLSEnabled())
      {
         return (plaintextBytes + brain->queuedSendOutstandingBytes());
      }

      return plaintextBytes;
   }

   bool allowBrainPeerReplicationAppend(BrainView *brain, uint64_t appendBytes, StringType auto&& reason)
   {
      if (brain == nullptr)
      {
         return false;
      }

      if (brain->connected == false || Ring::socketIsClosing(brain))
      {
         return false;
      }

      if (brain->isFixedFile)
      {
         if (brain->fslot < 0)
         {
            return false;
         }
      }
      else if (brain->fd < 0)
      {
         return false;
      }

      const uint64_t bufferedBytes = brainPeerBufferedBytes(brain);
      const bool overLimit = (
         appendBytes > brainPeerReplicationBufferedBytesLimit
         || bufferedBytes > brainPeerReplicationBufferedBytesLimit
         || bufferedBytes + appendBytes > brainPeerReplicationBufferedBytesLimit);
      if (overLimit == false)
      {
         return true;
      }

      String reasonText = {};
      reasonText.append(reason);
      basics_log(
         "brain replication backpressure private4=%u buffered=%llu append=%llu limit=%llu pendingSend=%d tls=%d reason=%s\n",
         brain->private4,
         (unsigned long long)bufferedBytes,
         (unsigned long long)appendBytes,
         (unsigned long long)brainPeerReplicationBufferedBytesLimit,
         int(brain->pendingSend),
         int(brain->transportTLSEnabled()),
         reasonText.c_str());

      // Fail closed and force a fresh reconciliation on reconnect. Carrying
      // arbitrarily large replication backlogs across peer churn can OOM the
      // active master.
      brain->noteSendCompleted();
      brain->clearQueuedSendBytes();
      brain->connected = false;

      if (Ring::socketIsClosing(brain) == false)
      {
         Ring::queueClose(brain);
      }

      return false;
   }

   bool queueBrainDeploymentReplicationToPeer(
      BrainView *brain,
      StringType auto&& serializedPlan,
      StringType auto&& containerBlob)
   {
      const uint64_t appendBytes = (
         uint64_t(serializedPlan.size())
         + uint64_t(containerBlob.size())
         + brainPeerReplicationFrameHeadroomBytes);
      if (allowBrainPeerReplicationAppend(brain, appendBytes, "replicateDeployment-live"_ctv) == false)
      {
         return false;
      }

      Message::construct(
         brain->wBuffer,
         BrainTopic::replicateDeployment,
         std::forward<decltype(serializedPlan)>(serializedPlan),
         std::forward<decltype(containerBlob)>(containerBlob));
      Ring::queueSend(brain);
      return true;
   }

   bool queueBrainDeploymentReplicationFromStoreToPeer(BrainView *brain, const String& serializedPlan, uint64_t deploymentID, uint64_t containerBlobBytes)
   {
      const uint64_t appendBytes = (
         uint64_t(serializedPlan.size())
         + containerBlobBytes
         + brainPeerReplicationFrameHeadroomBytes);
      if (allowBrainPeerReplicationAppend(brain, appendBytes, "replicateDeployment-store"_ctv) == false)
      {
         return false;
      }

      uint32_t headerOffset = Message::appendHeader(brain->wBuffer, BrainTopic::replicateDeployment);
      Message::appendValue(brain->wBuffer, serializedPlan);
      Message::appendFile(brain->wBuffer, ContainerStore::pathForContainerImage(deploymentID));
      Message::finish(brain->wBuffer, headerOffset);
      Ring::queueSend(brain);
      return true;
   }

   void queueBrainDeploymentReplication(StringType auto&& serializedPlan, StringType auto&& containerBlob)
   {
      for (BrainView *brain : brains)
      {
         if (brain == nullptr) continue;
         (void)queueBrainDeploymentReplicationToPeer(brain, serializedPlan, containerBlob);
      }
   }

	template <typename... Args>
	void queueBrainReplication(BrainTopic topic, Args&&... args)
	{
		for (BrainView *brain : brains)
		{
			if (brain == nullptr) continue;
			if (brain->connected == false) continue;
			if (Ring::socketIsClosing(brain)) continue;
			if (brain->isFixedFile)
			{
				if (brain->fslot < 0) continue;
			}
			else if (brain->fd < 0)
			{
				continue;
			}

			Message::construct(brain->wBuffer, topic, std::forward<Args>(args)...);
			Ring::queueSend(brain);
		}
	}

// neuron-owned switchboard activity
   static bool neuronControlSocketArmed(const Machine *machine);
   static bool neuronControlStreamActive(const Machine *machine);
   void sendNeuronRuntimeEnvironmentConfig(void);
   void sendNeuronSwitchboardRoutableSubnets(void);
   void sendNeuronSwitchboardHostedIngressPrefixes(void);
   void sendNeuronSwitchboardHostedIngressPrefixes(Machine *machine);
   void sendNeuronSwitchboardOverlayRoutes(void);
   void sendNeuronSwitchboardOverlayRoutes(Machine *machine);
   void sendNeuronSwitchboardStateSync(Machine *machine);
   void buildHostedSwitchboardIngressPrefixes(Machine *machine, Vector<IPPrefix>& prefixes) const;
   bool whiteholeTargetsNeuronMachine(ContainerView *container, Machine *targetMachine, const Whitehole& whitehole) const;
   void collectWhiteholesForNeuronMachine(ContainerView *container, Machine *targetMachine, const Vector<Whitehole>& sourceWhiteholes, Vector<Whitehole>& whiteholes) const;
   bool buildSwitchboardOverlayRoutingConfig(Machine *machine, SwitchboardOverlayRoutingConfig& config) const;
   bool environmentBGPEnabled(void) const;
   void sendNeuronOpenSwitchboardWormholes(ContainerView *container, const Vector<Wormhole>& wormholes);
   void sendNeuronRefreshContainerWormholes(ContainerView *container, const Vector<Wormhole>& wormholes);
   void sendNeuronCloseSwitchboardWormholesToContainer(ContainerView *container);
   void sendNeuronOpenSwitchboardWhiteholes(ContainerView *container, const Vector<Whitehole>& whiteholes);
   void sendNeuronCloseSwitchboardWhiteholesToContainer(ContainerView *container);
};

inline bool BrainBase::neuronControlSocketArmed(const Machine *machine)
{
   if (machine == nullptr)
   {
      return false;
   }

   const NeuronView *neuron = &machine->neuron;
   if (Ring::socketIsClosing(const_cast<NeuronView *>(neuron)))
   {
      return false;
   }

   if (Ring::getRingFD() <= 0)
   {
      return false;
   }

   return neuron->isFixedFile && neuron->fslot >= 0;
}

inline bool BrainBase::neuronControlStreamActive(const Machine *machine)
{
   if (neuronControlSocketArmed(machine) == false)
   {
      return false;
   }

   return machine->neuron.connected;
}

inline BrainBase *thisBrain = nullptr;
