#pragma once

#include <cerrno>
#include <services/debug.h>
#include <chrono>
#include <exception>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <macros/bytes.h>
#include <services/bitsery.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/msg.h>
#include <networking/pool.h>
#include <networking/socket.h>
#include <networking/netlink.h>
#include <networking/netkit.h>
#include <networking/eth.h>

#include <macros/datacenter.h>
#include <ebpf/interface.h>
#include <ebpf/common/structs.h>

#include <prodigy/neuron/base.h>
#include <prodigy/brain/base.h>
#include <prodigy/brain/timing.knobs.h>
#include <prodigy/neuron/bgp.runtime.h>
#include <prodigy/neuron/containers.h>
#include <prodigy/machine.hardware.h>
#include <prodigy/netdev.detect.h>
#include <prodigy/transport.tls.h>
#include <switchboard/overlay.route.h>
#include <switchboard/switchboard.h>
#include <switchboard/whitehole.route.h>
#include <prodigy/ingress.validation.h>
#include <prodigy/wire.h>

class NeuronBrainControlStream : public RingInterface, public ProdigyTransportTLSStream
{
public:

   bool connected = false;
   bool initialMachineHardwareProfileQueued = false;

   void reset(void) override
   {
      ProdigyTransportTLSStream::reset();
      connected = false;
      initialMachineHardwareProfileQueued = false;
   }
};

class Neuron : public NeuronBase, public RingInterface {
protected:

      struct LocalWhiteholeBindingEntry {

         portal_definition key = {};
         switchboard_whitehole_binding value = {};

         bool equals(const LocalWhiteholeBindingEntry& rhs) const
         {
            return switchboardPortalDefinitionEquals(key, rhs.key)
               && switchboardWhiteholeBindingEquals(value, rhs.value);
         }

         bool operator==(const LocalWhiteholeBindingEntry& rhs) const
         {
            return equals(rhs);
         }
      };

			NeuronIaaS *iaas;
         std::unique_ptr<NeuronBGPRuntime> bgp;
	      std::unique_ptr<Switchboard> switchboard;
         SwitchboardOverlayRoutingConfig overlayRoutingConfig;
         Vector<switchboard_overlay_prefix4_key> installedIngressOverlayPrefixes4;
         Vector<switchboard_overlay_prefix6_key> installedIngressOverlayPrefixes6;
         Vector<switchboard_overlay_prefix4_key> installedEgressOverlayPrefixes4;
         Vector<switchboard_overlay_prefix6_key> installedEgressOverlayPrefixes6;
         Vector<switchboard_overlay_machine_route_key> installedOverlayRouteKeysFull;
         Vector<switchboard_overlay_machine_route_key> installedOverlayRouteKeysLow8;
         Vector<switchboard_overlay_prefix4_key> installedHostedIngressRouteKeys4;
         Vector<switchboard_overlay_prefix6_key> installedHostedIngressRouteKeys6;
         Vector<portal_definition> installedEgressWhiteholeBindingKeys;
         bytell_hash_subvector<uint32_t, LocalWhiteholeBindingEntry> whiteholeBindingsByContainer;
		bytell_hash_subvector<uint64_t, CoroutineStack *> pendingContainerDownloads;
		bytell_hash_map<uint128_t, Vector<String>> pendingAdvertisementPairings;
		bytell_hash_map<uint128_t, Vector<String>> pendingSubscriptionPairings;
		bytell_hash_map<uint128_t, Vector<String>> pendingCredentialRefreshes;
		static constexpr uint32_t pendingPairingLimitPerContainer = 128;
		static constexpr uint32_t pendingCredentialRefreshLimitPerContainer = 128;
		static constexpr uint64_t pulseBatteryPassMetricKey = 0x50554C5345504151ULL; // "PULSEPAQ"
		uint32_t brainControlKeepaliveSeconds = 15;
      TimeoutPacket metricsTick;
      bool metricsTickQueued = false;
      TimeoutPacket failedContainerArtifactGCTick;
      bool failedContainerArtifactGCTickQueued = false;
      MachineHardwareProfile hardwareProfile;
      String serializedHardwareProfile;
      struct DeferredHardwareInventoryWake : public SocketBase {
      } deferredHardwareInventoryWake;
      bool deferredHardwareInventoryWakePollQueued = false;

      struct DeferredHardwareInventoryResult {

         MachineHardwareProfile hardware;
         String serializedHardwareProfile;
      };

      std::mutex deferredHardwareInventoryMutex;
      std::optional<DeferredHardwareInventoryResult> deferredHardwareInventoryReady;
      bool deferredHardwareInventoryInFlight = false;

      struct ContainerMetricSampleState {

         uint64_t lastSampleNs = 0;
         uint64_t lastCpuUsageUs = 0;
         bool hasLastCpuUsage = false;
      };

      bytell_hash_map<uint128_t, ContainerMetricSampleState> metricSampleStateByContainer;

      const MachineHardwareProfile *latestHardwareProfileIfReady(void) const override
      {
         return hardwareProfile.inventoryComplete ? &hardwareProfile : nullptr;
      }

      void ensureDeferredHardwareInventoryProgress(void) override
      {
         (void)completeDeferredHardwareInventoryIfReady();
      }

	static bool verboseNeuronSocketLogsEnabled(void)
	{
		static int cached = -1;
		if (cached == -1)
		{
			const char *value = std::getenv("PRODIGY_NEURON_VERBOSE_LOGS");
			cached = (value && value[0] == '1' && value[1] == '\0') ? 1 : 0;
		}

		return (cached == 1);
	}

		template <typename... Args>
		static void verboseNeuronSocketLog(const char *format, Args... args)
		{
			if (verboseNeuronSocketLogsEnabled())
			{
				basics_log(format, args...);
			}
		}

		template <typename T>
		static bool rawStreamIsActive(T *stream)
		{
			if (stream == nullptr)
			{
				return false;
			}

			if (Ring::socketIsClosing(stream))
			{
				return false;
			}

			if (stream->isFixedFile)
			{
				return (stream->fslot >= 0);
			}

			// Brain reconnect can briefly reintroduce a live direct-fd control stream
			// before the steady-state fixed-file path is restored.
			return (stream->fd >= 0);
		}

		template <typename T>
		static bool streamIsActive(T *stream)
		{
			if (rawStreamIsActive(stream) == false)
			{
				return false;
			}

			if constexpr (requires(T *value) { value->connected; })
			{
				return stream->connected;
			}

			return true;
		}

		template <typename T>
		static void queueCloseIfActive(T *stream)
		{
			if (rawStreamIsActive(stream) == false)
			{
				return;
			}

			Ring::queueClose(stream);
		}

      virtual bool beginAcceptedBrainTransportTLS(NeuronBrainControlStream *stream)
      {
         return stream->beginTransportTLS(true);
      }

      const SwitchboardOverlayRoutingConfig *overlayRoutingConfigForContainerNetworking(void) const override
      {
         return &overlayRoutingConfig;
      }

      template <typename Key, typename Equals>
      static bool overlayKeyPresent(const Vector<Key>& haystack, const Key& needle, Equals&& equals)
      {
         for (const Key& candidate : haystack)
         {
            if (equals(candidate, needle))
            {
               return true;
            }
         }

         return false;
      }

      template <typename Key, StringType MapName, typename Equals>
      void syncOverlayPresenceMap(BPFProgram *program,
         MapName&& mapName,
         Vector<Key>& installedKeys,
         const Vector<Key>& desiredKeys,
         Equals&& equals)
      {
         if (program == nullptr)
         {
            installedKeys = desiredKeys;
            return;
         }

         program->openMap(mapName, [&] (int map_fd) -> void {

            if (map_fd < 0)
            {
               basics_log("Neuron missing overlay presence map\n");
               return;
            }

            for (const Key& existing : installedKeys)
            {
               if (overlayKeyPresent(desiredKeys, existing, equals) == false)
               {
                  bpf_map_delete_elem(map_fd, &existing);
               }
            }

            __u8 present = 1;
            for (const Key& desired : desiredKeys)
            {
               bpf_map_update_elem(map_fd, &desired, &present, BPF_ANY);
            }
         });

         installedKeys = desiredKeys;
      }

      template <typename Key, typename Value, StringType MapName, typename Equals>
      void syncOverlayValueMap(BPFProgram *program,
         MapName&& mapName,
         Vector<Key>& installedKeys,
         const Vector<std::pair<Key, Value>>& desiredEntries,
         Equals&& equals)
      {
         Vector<Key> desiredKeys = {};
         desiredKeys.reserve(desiredEntries.size());
         for (const auto& entry : desiredEntries)
         {
            desiredKeys.push_back(entry.first);
         }

         if (program == nullptr)
         {
            installedKeys = desiredKeys;
            return;
         }

         program->openMap(mapName, [&] (int map_fd) -> void {

            if (map_fd < 0)
            {
               basics_log("Neuron missing overlay value map\n");
               return;
            }

            for (const Key& existing : installedKeys)
            {
               if (overlayKeyPresent(desiredKeys, existing, equals) == false)
               {
                  bpf_map_delete_elem(map_fd, &existing);
               }
            }

            for (const auto& entry : desiredEntries)
            {
               bpf_map_update_elem(map_fd, &entry.first, &entry.second, BPF_ANY);
            }
         });

         installedKeys = desiredKeys;
      }

      void syncContainerOverlayRoutingPrograms(void)
      {
         for (const auto& [uuid, container] : containers)
         {
            (void)uuid;
            if (container == nullptr || container->plan.useHostNetworkNamespace)
            {
               continue;
            }

            container->syncPeerOverlayRoutingProgram();
         }
      }

      void syncOverlayRoutingPrograms(void)
      {
         Vector<switchboard_overlay_prefix4_key> desiredPrefixes4 = {};
         Vector<switchboard_overlay_prefix6_key> desiredPrefixes6 = {};
         switchboardBuildOverlayPrefixKeys(overlayRoutingConfig.overlaySubnets, desiredPrefixes4, desiredPrefixes6);

         syncOverlayPresenceMap(tcx_ingress_program,
            "overlay_routable_prefixes4"_ctv,
            installedIngressOverlayPrefixes4,
            desiredPrefixes4,
            [] (const switchboard_overlay_prefix4_key& lhs, const switchboard_overlay_prefix4_key& rhs) -> bool {

               return switchboardOverlayPrefix4Equals(lhs, rhs);
            });
         syncOverlayPresenceMap(tcx_ingress_program,
            "overlay_routable_prefixes6"_ctv,
            installedIngressOverlayPrefixes6,
            desiredPrefixes6,
            [] (const switchboard_overlay_prefix6_key& lhs, const switchboard_overlay_prefix6_key& rhs) -> bool {

               return switchboardOverlayPrefix6Equals(lhs, rhs);
            });

         syncOverlayPresenceMap(tcx_egress_program,
            "overlay_routable_prefixes4"_ctv,
            installedEgressOverlayPrefixes4,
            desiredPrefixes4,
            [] (const switchboard_overlay_prefix4_key& lhs, const switchboard_overlay_prefix4_key& rhs) -> bool {

               return switchboardOverlayPrefix4Equals(lhs, rhs);
            });
         syncOverlayPresenceMap(tcx_egress_program,
            "overlay_routable_prefixes6"_ctv,
            installedEgressOverlayPrefixes6,
            desiredPrefixes6,
            [] (const switchboard_overlay_prefix6_key& lhs, const switchboard_overlay_prefix6_key& rhs) -> bool {

               return switchboardOverlayPrefix6Equals(lhs, rhs);
            });

         prodigySyncOverlayEgressRoutingProgram(tcx_egress_program,
            overlayRoutingConfig,
            installedEgressOverlayPrefixes4,
            installedEgressOverlayPrefixes6,
            installedOverlayRouteKeysFull,
            installedOverlayRouteKeysLow8,
            installedHostedIngressRouteKeys4,
            installedHostedIngressRouteKeys6);

         syncContainerOverlayRoutingPrograms();
      }

      void syncWhiteholeBindingsProgram(void)
      {
         Vector<std::pair<portal_definition, switchboard_whitehole_binding>> desiredBindings = {};
         desiredBindings.reserve(whiteholeBindingsByContainer.size());

         for (const auto& [containerID, bindings] : whiteholeBindingsByContainer)
         {
            (void)containerID;
            for (const LocalWhiteholeBindingEntry& binding : bindings)
            {
               desiredBindings.emplace_back(binding.key, binding.value);
            }
         }

         syncOverlayValueMap(tcx_egress_program,
            "whitehole_bindings"_ctv,
            installedEgressWhiteholeBindingKeys,
            desiredBindings,
            [] (const portal_definition& lhs, const portal_definition& rhs) -> bool {

               return switchboardPortalDefinitionEquals(lhs, rhs);
            });
      }

      void openLocalWhiteholes(uint32_t containerID, const Vector<Whitehole>& whiteholes)
      {
         whiteholeBindingsByContainer.erase(containerID);

         for (const Whitehole& whitehole : whiteholes)
         {
            LocalWhiteholeBindingEntry entry = {};
            if (switchboardBuildWhiteholeBinding(whitehole, containerID, lcsubnet6, entry.key, entry.value) == false)
            {
               continue;
            }

            whiteholeBindingsByContainer.emplace(containerID, entry);
         }

         syncWhiteholeBindingsProgram();
      }

      void closeLocalWhiteholesToContainer(uint32_t containerID)
      {
         whiteholeBindingsByContainer.erase(containerID);
         syncWhiteholeBindingsProgram();
      }

      bool resolveOptionalHostRouterBPFPaths(String& hostIngressPath, String& hostEgressPath, String *failureReport = nullptr) const
      {
         hostIngressPath.clear();
         hostEgressPath.clear();

         const char *ingressEnv = getenv("PRODIGY_HOST_INGRESS_EBPF");
         const char *egressEnv = getenv("PRODIGY_HOST_EGRESS_EBPF");
         bool haveIngress = (ingressEnv && *ingressEnv);
         bool haveEgress = (egressEnv && *egressEnv);

         if (haveIngress != haveEgress)
         {
            if (failureReport)
            {
               failureReport->assign("PRODIGY_HOST_INGRESS_EBPF and PRODIGY_HOST_EGRESS_EBPF must be set together"_ctv);
            }
            return false;
         }

         if (haveIngress == false)
         {
            return false;
         }

         hostIngressPath.assign(ingressEnv);
         hostEgressPath.assign(egressEnv);
         return true;
      }

			void queueBrainAccept(void)
			{
				if (brainListener.isFixedFile == false || brainListener.fslot < 0)
				{
					basics_log("queueBrainAccept missing fixed-file listener listenerFD=%d listenerFslot=%d\n",
						brainListener.fd,
						brainListener.fslot);
					return;
				}

				Ring::queueAccept(&brainListener, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
			}

		bool verifyBrainTransportTLSPeer(void)
		{
			if (brain == nullptr || brain->transportTLSEnabled() == false || brain->tlsPeerVerified)
			{
				return true;
			}

			if (brain->isTLSNegotiated() == false)
			{
				return true;
			}

			uint128_t peerUUID = 0;
			if (ProdigyTransportTLSRuntime::extractPeerUUID(brain->ssl, peerUUID) == false)
			{
				basics_log("neuron transport tls missing brain peer uuid fd=%d fslot=%d\n", brain->fd, brain->fslot);
				return false;
			}

			brain->tlsPeerUUID = peerUUID;
			brain->tlsPeerVerified = true;
			basics_log("neuron brain transport tls peer verified fd=%d fslot=%d\n", brain->fd, brain->fslot);
         (void)queueMachineHardwareProfileToBrainIfReady("transport-tls-peer-verified");
			return true;
		}

      static uint64_t monotonicNowNs(void)
      {
         struct timespec ts = {};
         if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
         {
            return 0;
         }

         return (uint64_t(ts.tv_sec) * 1'000'000'000ULL) + uint64_t(ts.tv_nsec);
      }

      static constexpr uint64_t collectableScalingDimensionsMask(void)
      {
         return ProdigyMetrics::maskForScalingDimension(ScalingDimension::cpu)
            | ProdigyMetrics::maskForScalingDimension(ScalingDimension::memory)
            | ProdigyMetrics::maskForScalingDimension(ScalingDimension::storage);
      }

      static uint64_t activeMetricsMask(const Container *container)
      {
         if (container == nullptr)
         {
            return 0;
         }

         return (container->neuronScalingDimensionsMask & collectableScalingDimensionsMask());
      }

      static uint32_t normalizedMetricsCadenceMs(const Container *container)
      {
         uint32_t cadenceMs = (container ? container->neuronMetricsCadenceMs : 0);
         if (cadenceMs == 0)
         {
            cadenceMs = ProdigyMetrics::defaultNeuronCollectionCadenceMs;
         }

         if (cadenceMs < 250)
         {
            cadenceMs = 250;
         }

         return cadenceMs;
      }

      uint32_t minimumActiveMetricsCadenceMs(void) const
      {
         uint32_t cadenceMs = 0;

         for (const auto& [uuid, container] : containers)
         {
            (void)uuid;
            uint64_t mask = activeMetricsMask(container);
            if (mask == 0)
            {
               continue;
            }

            uint32_t candidate = normalizedMetricsCadenceMs(container);
            if (cadenceMs == 0 || candidate < cadenceMs)
            {
               cadenceMs = candidate;
            }
         }

         return cadenceMs;
      }

      void armMetricsTick(uint32_t cadenceMs)
      {
         if (cadenceMs == 0)
         {
            return;
         }

         metricsTick.clear();
         metricsTick.flags = uint64_t(NeuronTimeoutFlags::metricsTick);
         metricsTick.originator = this;
         metricsTick.setTimeoutMs(cadenceMs);
         Ring::queueTimeout(&metricsTick);
         metricsTickQueued = true;
      }

      void ensureMetricsTickQueued(void)
      {
         if (metricsTickQueued)
         {
            return;
         }

         uint32_t cadenceMs = minimumActiveMetricsCadenceMs();
         if (cadenceMs == 0)
         {
            return;
         }

         armMetricsTick(cadenceMs);
      }

      void armFailedContainerArtifactGCTick(void)
      {
         failedContainerArtifactGCTick.clear();
         failedContainerArtifactGCTick.flags = uint64_t(NeuronTimeoutFlags::logGC);
         failedContainerArtifactGCTick.originator = this;
         failedContainerArtifactGCTick.setTimeoutMs(failedContainerArtifactCleanupIntervalMs);
         Ring::queueTimeout(&failedContainerArtifactGCTick);
         failedContainerArtifactGCTickQueued = true;
      }

      void ensureFailedContainerArtifactGCTickQueued(void)
      {
         if (failedContainerArtifactGCTickQueued)
         {
            return;
         }

         armFailedContainerArtifactGCTick();
      }

      void cleanupExpiredFailedContainerArtifacts(void)
      {
         String failure = {};
         if (ContainerManager::cleanupExpiredFailedContainerArtifacts(Time::now<TimeResolution::ms>(), &failure) == false
            && failure.size() > 0)
         {
            basics_log("neuron failed-container artifact gc failed reason=%s\n", failure.c_str());
         }
      }

      static DeferredHardwareInventoryResult collectDeferredHardwareInventoryResult(void)
      {
         DeferredHardwareInventoryResult result = {};
         ProdigyMachineHardwareCollectorOptions hardwareCollectorOptions = {};
         hardwareCollectorOptions.collectOptionalBenchmarks = false;
         prodigyCollectMachineHardwareProfile(result.hardware, hardwareCollectorOptions);
         BitseryEngine::serialize(result.serializedHardwareProfile, result.hardware);
         return result;
      }

      static bool deferredHardwareInventoryResultReadyForAdoption(const DeferredHardwareInventoryResult& result)
      {
         return result.serializedHardwareProfile.size() > 0
            && result.hardware.inventoryComplete;
      }

      void armDeferredHardwareInventoryWakePoll(void)
      {
         if (deferredHardwareInventoryWakePollQueued || deferredHardwareInventoryWake.fd < 0)
         {
            return;
         }

         Ring::queuePollProcessFD(&deferredHardwareInventoryWake, deferredHardwareInventoryWake.fd, false, POLLIN);
         deferredHardwareInventoryWakePollQueued = true;
      }

      void drainDeferredHardwareInventoryWake(void)
      {
         if (deferredHardwareInventoryWake.fd < 0)
         {
            return;
         }

         uint64_t signal = 0;
         while (::read(deferredHardwareInventoryWake.fd, &signal, sizeof(signal)) == sizeof(signal))
         {
         }
      }

      void beginDeferredHardwareInventoryCollection(void)
      {
         {
            std::lock_guard<std::mutex> lock(deferredHardwareInventoryMutex);
            if (deferredHardwareInventoryInFlight)
            {
               return;
            }

            deferredHardwareInventoryInFlight = true;
         }

         std::thread([this]() mutable {
            DeferredHardwareInventoryResult result = {};
            try
            {
               result = collectDeferredHardwareInventoryResult();
            }
            catch (const std::exception& ex)
            {
               basics_log("Neuron deferred hardware inventory threw exception=%s\n", ex.what());
            }
            catch (...)
            {
               basics_log("Neuron deferred hardware inventory threw exception=unknown\n");
            }

            {
               std::lock_guard<std::mutex> lock(deferredHardwareInventoryMutex);
               deferredHardwareInventoryReady = std::move(result);
            }

            if (deferredHardwareInventoryWake.fd >= 0)
            {
               uint64_t signal = 1;
               (void)::write(deferredHardwareInventoryWake.fd, &signal, sizeof(signal));
            }
         }).detach();
      }

      bool appendMachineHardwareProfileFrameIfReady(String& outbound)
      {
         if (serializedHardwareProfile.size() == 0)
         {
            return false;
         }

         Message::construct(outbound, NeuronTopic::machineHardwareProfile, serializedHardwareProfile);
         return true;
      }

      void appendInitialBrainControlFrames(String& outbound)
      {
         Message::construct(outbound, NeuronTopic::registration, bootTimeMs, kernel, haveFragments());
      }

      uint32_t appendHealthyContainerFrames(String& outbound)
      {
         uint32_t queued = 0;

         for (const auto& [containerUUID, container] : containers)
         {
            (void)containerUUID;
            if (container == nullptr || container->plan.state != ContainerState::healthy)
            {
               continue;
            }

            Message::construct(outbound, NeuronTopic::containerHealthy, container->plan.uuid);
            queued += 1;
         }

         return queued;
      }

      bool queueMachineHardwareProfileToBrainIfReady(const char *reason)
      {
         bool brainPresent = (brain != nullptr);
         bool brainActive = (brainPresent && streamIsActive(brain));
         bool brainAppReady = (brainPresent
            && brainActive
            && (brain->transportTLSEnabled() == false || (brain->isTLSNegotiated() && brain->tlsPeerVerified)));
         bool alreadyQueued = (brainPresent && brain->initialMachineHardwareProfileQueued);
         bool queuedHardwareProfile = false;
         if (brainPresent && brainAppReady && alreadyQueued == false && appendMachineHardwareProfileFrameIfReady(brain->wBuffer))
         {
            brain->initialMachineHardwareProfileQueued = true;
            queuedHardwareProfile = true;
            Ring::queueSend(brain);
            if (RingDispatcher::dispatcher != nullptr && Ring::getRingFD() > 0)
            {
               Ring::submitPending();
            }
         }

#if PRODIGY_DEBUG
         basics_log("Neuron machineHardwareProfile queue-to-brain reason=%s brainPresent=%d brainActive=%d brainAppReady=%d alreadyQueued=%d queued=%d serializedBytes=%llu fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d\n",
            (reason != nullptr ? reason : ""),
            int(brainPresent),
            int(brainActive),
            int(brainAppReady),
            int(alreadyQueued),
            int(queuedHardwareProfile),
            (unsigned long long)serializedHardwareProfile.size(),
            (brainPresent ? brain->fd : -1),
            (brainPresent ? brain->fslot : -1),
            int(brainPresent ? brain->pendingSend : 0),
            int(brainPresent ? brain->pendingRecv : 0),
            int(brainPresent ? brain->isTLSNegotiated() : 0),
            int(brainPresent ? brain->tlsPeerVerified : 0));
#endif
         return queuedHardwareProfile;
      }

      void adoptDeferredHardwareInventoryResult(DeferredHardwareInventoryResult result)
      {
         basics_log("Neuron adopting deferred hardware inventory inventoryComplete=%d serializedBytes=%llu logicalCores=%u memoryMB=%u disks=%llu nics=%llu\n",
            int(result.hardware.inventoryComplete),
            (unsigned long long)result.serializedHardwareProfile.size(),
            result.hardware.cpu.logicalCores,
            result.hardware.memory.totalMB,
            (unsigned long long)result.hardware.disks.size(),
            (unsigned long long)result.hardware.network.nics.size());
         hardwareProfile = std::move(result.hardware);
         serializedHardwareProfile = std::move(result.serializedHardwareProfile);

         if (hardwareProfile.inventoryComplete && thisBrain != nullptr)
         {
            thisBrain->adoptLocalMachineHardwareProfile(hardwareProfile);
         }

         bool brainPresent = (brain != nullptr);
         bool brainActive = (brainPresent && streamIsActive(brain));
         bool queuedHardwareProfile = queueMachineHardwareProfileToBrainIfReady("deferred-hardware-adopt");

#if PRODIGY_DEBUG
         basics_log("Neuron deferred hardware inventory send brainPresent=%d brainActive=%d queued=%d serializedBytes=%llu fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d\n",
            int(brainPresent),
            int(brainActive),
            int(queuedHardwareProfile),
            (unsigned long long)serializedHardwareProfile.size(),
            (brainPresent ? brain->fd : -1),
            (brainPresent ? brain->fslot : -1),
            int(brainPresent ? brain->pendingSend : 0),
            int(brainPresent ? brain->pendingRecv : 0),
            int(brainPresent ? brain->isTLSNegotiated() : 0),
            int(brainPresent ? brain->tlsPeerVerified : 0));
#endif
      }

      bool completeDeferredHardwareInventoryIfReady(void)
      {
         std::optional<DeferredHardwareInventoryResult> ready = std::nullopt;

         {
            std::lock_guard<std::mutex> lock(deferredHardwareInventoryMutex);
            if (deferredHardwareInventoryReady == std::nullopt)
            {
               return (deferredHardwareInventoryInFlight == false);
            }

            ready = std::move(deferredHardwareInventoryReady);
            deferredHardwareInventoryReady.reset();
            deferredHardwareInventoryInFlight = false;
         }

         if (ready == std::nullopt)
         {
            return true;
         }

         DeferredHardwareInventoryResult result = std::move(*ready);
         if (deferredHardwareInventoryResultReadyForAdoption(result) == false)
         {
            basics_log("Neuron deferred hardware inventory retry inventoryComplete=%d serializedBytes=%llu logicalCores=%u memoryMB=%u disks=%llu nics=%llu failure=%s\n",
               int(result.hardware.inventoryComplete),
               (unsigned long long)result.serializedHardwareProfile.size(),
               result.hardware.cpu.logicalCores,
               result.hardware.memory.totalMB,
               (unsigned long long)result.hardware.disks.size(),
               (unsigned long long)result.hardware.network.nics.size(),
               result.hardware.inventoryFailure.c_str());
            beginDeferredHardwareInventoryCollection();
            return false;
         }

         adoptDeferredHardwareInventoryResult(std::move(result));
         return true;
      }

      static bool parseUnsignedDecimal(const String& text, uint64_t& value)
      {
         value = 0;
         uint64_t index = 0;

         while (index < text.size())
         {
            uint8_t c = text[index];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            {
               index += 1;
               continue;
            }

            break;
         }

         if (index >= text.size() || text[index] < '0' || text[index] > '9')
         {
            return false;
         }

         while (index < text.size())
         {
            uint8_t c = text[index];
            if (c < '0' || c > '9')
            {
               break;
            }

            value = (value * 10) + uint64_t(c - '0');
            index += 1;
         }

         return true;
      }

      static bool extractCpuUsageUsec(const String& cpuStat, uint64_t& usageUsec)
      {
         static constexpr const char *key = "usage_usec";
         static constexpr uint64_t keyLength = 10;

         const uint8_t *bytes = reinterpret_cast<const uint8_t *>(cpuStat.data());
         uint64_t length = cpuStat.size();
         uint64_t offset = 0;

         while (offset < length)
         {
            uint64_t lineStart = offset;
            while (offset < length && bytes[offset] != '\n')
            {
               offset += 1;
            }
            uint64_t lineEnd = offset;
            if (offset < length && bytes[offset] == '\n')
            {
               offset += 1;
            }

            if ((lineEnd - lineStart) <= keyLength)
            {
               continue;
            }

            if (std::memcmp(bytes + lineStart, key, keyLength) != 0)
            {
               continue;
            }

            uint64_t valueStart = lineStart + keyLength;
            if (valueStart >= lineEnd || (bytes[valueStart] != ' ' && bytes[valueStart] != '\t'))
            {
               continue;
            }

            while (valueStart < lineEnd && (bytes[valueStart] == ' ' || bytes[valueStart] == '\t'))
            {
               valueStart += 1;
            }

            if (valueStart >= lineEnd || bytes[valueStart] < '0' || bytes[valueStart] > '9')
            {
               return false;
            }

            usageUsec = 0;
            while (valueStart < lineEnd)
            {
               uint8_t c = bytes[valueStart];
               if (c < '0' || c > '9')
               {
                  break;
               }

               usageUsec = (usageUsec * 10) + uint64_t(c - '0');
               valueStart += 1;
            }

            return true;
         }

         return false;
      }

      static bool readContainerCpuUsageUsec(const Container *container, uint64_t& usageUsec)
      {
         if (container == nullptr || container->cgroup < 0)
         {
            return false;
         }

         String cpuStat;
         Filesystem::openReadAtClose(container->cgroup, "cpu.stat"_ctv, cpuStat);
         if (cpuStat.size() == 0)
         {
            return false;
         }

         return extractCpuUsageUsec(cpuStat, usageUsec);
      }

      static bool readContainerMemoryCurrentBytes(const Container *container, uint64_t& memoryCurrentBytes)
      {
         if (container == nullptr || container->cgroup < 0)
         {
            return false;
         }

         String memoryCurrent;
         Filesystem::openReadAtClose(container->cgroup, "memory.current"_ctv, memoryCurrent);
         if (memoryCurrent.size() == 0)
         {
            return false;
         }

         return parseUnsignedDecimal(memoryCurrent, memoryCurrentBytes);
      }

      static bool approximateDirectoryUsageBytes(const String& path, uint64_t& usageBytes)
      {
         namespace fs = std::filesystem;
         std::error_code ec;

         fs::path root = prodigyFilesystemPathFromString(path);
         if (fs::exists(root, ec) == false || ec)
         {
            return false;
         }

         uint64_t totalBytes = 0;
         if (fs::is_regular_file(root, ec))
         {
            uint64_t fileBytes = fs::file_size(root, ec);
            if (ec)
            {
               return false;
            }

            usageBytes = fileBytes;
            return true;
         }
         ec.clear();

         fs::recursive_directory_iterator iterator(root, fs::directory_options::skip_permission_denied, ec);
         fs::recursive_directory_iterator end;
         if (ec)
         {
            return false;
         }

         while (iterator != end)
         {
            const fs::directory_entry& entry = *iterator;
            std::error_code entryError;
            fs::file_status status = entry.symlink_status(entryError);
            if (!entryError && fs::is_regular_file(status))
            {
               uint64_t entryBytes = entry.file_size(entryError);
               if (!entryError)
               {
                  totalBytes += entryBytes;
               }
            }

            iterator.increment(entryError);
            if (entryError)
            {
               entryError.clear();
            }
         }

         usageBytes = totalBytes;
         return true;
      }

      static bool sampleContainerCpuUtilPct(Container *container, ContainerMetricSampleState& sampleState, uint64_t sampleTimeNs, uint64_t& utilPct)
      {
         uint64_t usageUsec = 0;
         if (readContainerCpuUsageUsec(container, usageUsec) == false)
         {
            return false;
         }

         if (sampleState.hasLastCpuUsage == false || sampleState.lastSampleNs == 0 || usageUsec < sampleState.lastCpuUsageUs)
         {
            sampleState.lastCpuUsageUs = usageUsec;
            sampleState.hasLastCpuUsage = true;
            return false;
         }

         uint64_t elapsedNs = (sampleTimeNs > sampleState.lastSampleNs) ? (sampleTimeNs - sampleState.lastSampleNs) : 0;
         uint64_t deltaUsageUsec = usageUsec - sampleState.lastCpuUsageUs;
         sampleState.lastCpuUsageUs = usageUsec;

         if (elapsedNs == 0)
         {
            return false;
         }

         double elapsedUsec = double(elapsedNs) / 1'000.0;
         double cpuBudgetCores = 1.0;
         if (applicationUsesSharedCPUs(container->plan.config))
         {
            cpuBudgetCores = double(applicationRequestedCPUMillis(container->plan.config)) / double(prodigyCPUUnitsPerCore);
         }
         else
         {
            cpuBudgetCores = double(container->plan.config.nLogicalCores);
         }

         if (cpuBudgetCores <= 0.0)
         {
            cpuBudgetCores = 1.0;
         }

         double util = (double(deltaUsageUsec) * 100.0) / (elapsedUsec * cpuBudgetCores);
         if (util < 0.0)
         {
            util = 0.0;
         }
         else if (util > 100.0)
         {
            util = 100.0;
         }

         utilPct = uint64_t(util + 0.5);
         return true;
      }

      static bool sampleContainerMemoryUtilPct(const Container *container, uint64_t& utilPct)
      {
         uint64_t memoryCurrentBytes = 0;
         if (readContainerMemoryCurrentBytes(container, memoryCurrentBytes) == false)
         {
            return false;
         }

         uint64_t memoryLimitBytes = uint64_t(container->plan.config.memoryMB) * 1024ULL * 1024ULL;
         if (memoryLimitBytes == 0)
         {
            return false;
         }

         double util = (double(memoryCurrentBytes) * 100.0) / double(memoryLimitBytes);
         if (util < 0.0)
         {
            util = 0.0;
         }
         else if (util > 100.0)
         {
            util = 100.0;
         }

         utilPct = uint64_t(util + 0.5);
         return true;
      }

      static bool sampleContainerStorageUtilPct(const Container *container, uint64_t& utilPct)
      {
         if (container == nullptr || container->plan.config.storageMB == 0)
         {
            return false;
         }

         String storagePath;
         if (container->storagePayloadPath.size() > 0)
         {
            storagePath.assign(container->storagePayloadPath);
         }
         else
         {
            storagePath.snprintf<"/containers/storage/{itoa}"_ctv>(container->plan.uuid);
         }

         uint64_t usageBytes = 0;
         if (approximateDirectoryUsageBytes(storagePath, usageBytes) == false)
         {
            return false;
         }

         uint64_t storageLimitBytes = uint64_t(container->plan.config.storageMB) * 1024ULL * 1024ULL;
         if (storageLimitBytes == 0)
         {
            return false;
         }

         double util = (double(usageBytes) * 100.0) / double(storageLimitBytes);
         if (util < 0.0)
         {
            util = 0.0;
         }
         else if (util > 100.0)
         {
            util = 100.0;
         }

         utilPct = uint64_t(util + 0.5);
         return true;
      }

      void collectContainerMetricsAndForward(uint64_t sampleTimeNs)
      {
         bool queuedToBrain = false;
         int64_t sampleTimeMs = Time::now<TimeResolution::ms>();

         for (const auto& [containerUUID, container] : containers)
         {
            (void)containerUUID;

            uint64_t mask = activeMetricsMask(container);
            if (mask == 0)
            {
               continue;
            }

            auto& sampleState = metricSampleStateByContainer[container->plan.uuid];
            uint32_t cadenceMs = normalizedMetricsCadenceMs(container);
            if (sampleState.lastSampleNs > 0)
            {
               uint64_t elapsedNs = (sampleTimeNs > sampleState.lastSampleNs) ? (sampleTimeNs - sampleState.lastSampleNs) : 0;
               if (elapsedNs < (uint64_t(cadenceMs) * 1'000'000ULL))
               {
                  continue;
               }
            }

            uint64_t metricKeys[3] = {};
            uint64_t metricValues[3] = {};
            uint32_t metricCount = 0;

            if ((mask & ProdigyMetrics::maskForScalingDimension(ScalingDimension::cpu)) > 0)
            {
               uint64_t value = 0;
               if (sampleContainerCpuUtilPct(container, sampleState, sampleTimeNs, value))
               {
                  metricKeys[metricCount] = ProdigyMetrics::runtimeContainerCpuUtilPctKey();
                  metricValues[metricCount] = value;
                  metricCount += 1;
               }
            }

            if ((mask & ProdigyMetrics::maskForScalingDimension(ScalingDimension::memory)) > 0)
            {
               uint64_t value = 0;
               if (sampleContainerMemoryUtilPct(container, value))
               {
                  metricKeys[metricCount] = ProdigyMetrics::runtimeContainerMemoryUtilPctKey();
                  metricValues[metricCount] = value;
                  metricCount += 1;
               }
            }

            if ((mask & ProdigyMetrics::maskForScalingDimension(ScalingDimension::storage)) > 0)
            {
               uint64_t value = 0;
               if (sampleContainerStorageUtilPct(container, value))
               {
                  metricKeys[metricCount] = ProdigyMetrics::runtimeContainerStorageUtilPctKey();
                  metricValues[metricCount] = value;
                  metricCount += 1;
               }
            }

            sampleState.lastSampleNs = sampleTimeNs;

            if (metricCount == 0 || brain == nullptr)
            {
               continue;
            }

            uint32_t headerOffset = Message::appendHeader(brain->wBuffer, NeuronTopic::containerStatistics);
            Message::append(brain->wBuffer, container->plan.config.deploymentID());
            Message::append(brain->wBuffer, container->plan.uuid);
            Message::append(brain->wBuffer, sampleTimeMs);

            for (uint32_t index = 0; index < metricCount; index++)
            {
               Message::append(brain->wBuffer, metricKeys[index]);
               Message::append(brain->wBuffer, metricValues[index]);
            }

            Message::finish(brain->wBuffer, headerOffset);
            queuedToBrain = true;
         }

         if (queuedToBrain && streamIsActive(brain))
         {
            Ring::queueSend(brain);
         }
      }

			template <typename T>
			static bool extractFixedArgBounded(uint8_t *&cursor, uint8_t *terminal, T& value)
		{
			static_assert(std::is_trivially_copyable_v<T>);

			constexpr uintptr_t alignmentMask = uintptr_t(alignof(T) - 1);
			uintptr_t aligned = (reinterpret_cast<uintptr_t>(cursor) + alignmentMask) & ~alignmentMask;
			uint8_t *alignedCursor = reinterpret_cast<uint8_t *>(aligned);

			if (alignedCursor > terminal || (terminal - alignedCursor) < ptrdiff_t(sizeof(T)))
			{
				return false;
			}

			value = *reinterpret_cast<T *>(alignedCursor);
			cursor = alignedCursor + sizeof(T);
				return true;
			}

			void queuePendingPayload(bytell_hash_map<uint128_t, Vector<String>>& pendingPayloads,
				uint128_t containerUUID,
				uint32_t limitPerContainer,
				const String& payload)
			{
				if (payload.size() == 0)
				{
					return;
				}

				if (auto it = pendingPayloads.find(containerUUID); it != pendingPayloads.end())
				{
					for (const String& existing : it->second)
					{
							if (existing.equals(payload))
						{
							return;
						}
					}

					if (it->second.size() >= limitPerContainer)
					{
						it->second.pop_back();
					}

					String copy;
					copy.assign(payload.data(), payload.size());
					it->second.push_back(std::move(copy));
				}
				else
				{
					Vector<String> payloads;
					String copy;
					copy.assign(payload.data(), payload.size());
					payloads.push_back(std::move(copy));
					pendingPayloads.insert_or_assign(containerUUID, std::move(payloads));
				}
			}

			void queuePendingPayload(bytell_hash_map<uint128_t, Vector<String>>& pendingPayloads,
				uint128_t containerUUID,
				uint32_t limitPerContainer,
				uint8_t *start,
				uint8_t *terminal)
			{
				if (start == nullptr || terminal == nullptr || terminal <= start)
				{
					return;
				}

				String payload;
				payload.assign(start, uint64_t(terminal - start));
				queuePendingPayload(pendingPayloads, containerUUID, limitPerContainer, payload);
			}

			void queuePendingPairing(bytell_hash_map<uint128_t, Vector<String>>& pendingPairings,
				uint128_t containerUUID,
				uint8_t *start,
				uint8_t *terminal)
			{
				queuePendingPayload(pendingPairings, containerUUID, pendingPairingLimitPerContainer, start, terminal);
			}

			void applyPendingPairings(Container *container)
			{
				if (container == nullptr)
				{
					return;
				}

				bool queuedMessages = false;

				auto applyPendingForTopic = [&] (bytell_hash_map<uint128_t, Vector<String>>& pendingPairings, ContainerTopic topic, bool advertisement)
				{
					auto it = pendingPairings.find(container->plan.uuid);
					if (it == pendingPairings.end())
					{
						return;
					}

					Vector<String> payloads = std::move(it->second);
					pendingPairings.erase(container->plan.uuid);

						for (String& payload : payloads)
						{
							if (advertisement)
							{
								uint128_t secret = 0;
								uint128_t address = 0;
								uint64_t service = 0;
								uint16_t applicationID = 0;
								bool activate = false;
								if (ProdigyWire::deserializeAdvertisementPairingPayloadAuto(
									payload.data(),
									payload.size(),
									secret,
									address,
									service,
									applicationID,
									activate) == false)
								{
									continue;
								}

								container->plan.applyAdvertisementPairing(AdvertisementPairing(secret, address, service), activate);
								String packedPayload;
								if (ProdigyWire::serializeAdvertisementPairingPayload(
									packedPayload,
									secret,
									address,
									service,
									applicationID,
									activate) == false)
								{
									continue;
								}

								if (ProdigyWire::constructPackedFrame(container->wBuffer, topic, packedPayload))
								{
									queuedMessages = true;
								}
							}
							else
							{
								uint128_t secret = 0;
								uint128_t address = 0;
								uint64_t service = 0;
								uint16_t port = 0;
								uint16_t applicationID = 0;
								bool activate = false;
								if (ProdigyWire::deserializeSubscriptionPairingPayloadAuto(
									payload.data(),
									payload.size(),
									secret,
									address,
									service,
									port,
									applicationID,
									activate) == false)
								{
									continue;
								}

								container->plan.applySubscriptionPairing(SubscriptionPairing(secret, address, service, port), activate);
								String packedPayload;
								if (ProdigyWire::serializeSubscriptionPairingPayload(
									packedPayload,
									secret,
									address,
									service,
									port,
									applicationID,
									activate) == false)
								{
									continue;
								}

								if (ProdigyWire::constructPackedFrame(container->wBuffer, topic, packedPayload))
								{
									queuedMessages = true;
								}
							}
						}
					};

				applyPendingForTopic(pendingAdvertisementPairings, ContainerTopic::advertisementPairing, true);
				applyPendingForTopic(pendingSubscriptionPairings, ContainerTopic::subscriptionPairing, false);

				if (queuedMessages && streamIsActive(container))
				{
					Ring::queueSend(container);
				}
			}

			void applyPendingCredentialRefreshes(Container *container)
			{
				if (container == nullptr)
				{
					return;
				}

				auto it = pendingCredentialRefreshes.find(container->plan.uuid);
				if (it == pendingCredentialRefreshes.end())
				{
					return;
				}

				Vector<String> payloads = std::move(it->second);
				pendingCredentialRefreshes.erase(container->plan.uuid);

				bool queuedMessages = false;
				for (String& payload : payloads)
				{
					CredentialDelta delta;
					if (ProdigyWire::deserializeCredentialDeltaAuto(payload, delta) == false)
					{
						continue;
					}

					container->plan.hasCredentialBundle = true;
					applyCredentialDelta(container->plan.credentialBundle, delta);
					if (ProdigyWire::constructPackedFrame(container->wBuffer, ContainerTopic::credentialsRefresh, payload))
					{
						queuedMessages = true;
					}
				}

				if (queuedMessages && streamIsActive(container))
				{
					Ring::queueSend(container);
				}
			}

		bool isTrackedContainerSocket(void *socket) const
		{
			Container *target = static_cast<Container *>(socket);
			for (const auto& [uuid, container] : containers)
			{
				(void)uuid;
				if (container == target)
				{
					return true;
				}
			}

			return false;
		}

	void loadKernelVersion(void)
	{
		struct utsname buffer;
		uname(&buffer);

		kernel.assign(buffer.release); // 6.10.1-1453.native
		// kernel.resize(kernel.findChar('-'));
	}

   Switchboard *ensureSwitchboard(void)
   {
      if (!switchboard)
      {
         switchboard = std::make_unique<Switchboard>(eth);
      }

      switchboard->setHostEgressRouter(tcx_egress_program);

      return switchboard.get();
   }

   uint32_t generateLocalContainerID(uint8_t fragment) const
   {
      uint32_t containerID = uint32_t(lcsubnet6.mpfx[2]);
      containerID |= uint32_t(lcsubnet6.mpfx[1]) << 8;
      containerID |= uint32_t(lcsubnet6.mpfx[0]) << 16;
      containerID |= uint32_t(fragment) << 24;
      return containerID;
   }

   Container *findTrackedContainerByLocalID(uint32_t containerID) const
   {
      for (const auto& [uuid, container] : containers)
      {
         (void)uuid;
         if (container == nullptr || container->pendingDestroy)
         {
            continue;
         }

         if (generateLocalContainerID(container->plan.fragment) == containerID)
         {
            return container;
         }
      }

      return nullptr;
   }

   void refreshContainerSwitchboardWormholes(Container *container) override
   {
      if (switchboard == nullptr || container == nullptr || container->plan.wormholes.empty())
      {
         return;
      }

      uint32_t containerID = generateLocalContainerID(container->plan.fragment);

      switchboard->setLocalContainerSubnet(lcsubnet6);
      switchboard->openWormholes(containerID, container->plan.wormholes);

      // Wormhole refresh must also converge the target container's live peer
      // runtime immediately, not just the broader switchboard state, so the
      // first reply packets after a live refresh cannot miss the egress binding.
      syncContainerSwitchboardRuntime(container);
   }

   void syncContainerSwitchboardRuntime(Container *container) override
   {
      if (switchboard == nullptr
         || container == nullptr
         || container->plan.useHostNetworkNamespace
         || container->peer_program == nullptr)
      {
         return;
      }

      switchboard->syncPeerProgramRuntimeState(container->peer_program);
   }

      NeuronBGPRuntime *ensureBGP(void)
      {
         if (!bgp)
         {
            bgp = std::make_unique<NeuronBGPRuntime>();

            NeuronBGPConfig config = {};
            iaas->gatherBGPConfig(config, eth, private4);
            bgp->configure(config);
         }

         return bgp.get();
      }

	// we don't run this until after the brain sends us our fragment and any container plans, because we use
		// haveFragments as a test of whether it was a spurious connection break or a neuron crash/update or machine crash/update
			void setupNetworking(void)
			{
				IPPrefix containerSubnet6 = generateAddress(container_network_subnet6, 0, 120);
         Vector<IPPrefix> localPrefixes;
         localPrefixes.push_back(containerSubnet6);

		// and obviously we can't install this twice
		String hostIngressPath = {};
		String hostEgressPath = {};
      String hostRouterFailure = {};
      bool hostRouterBPFEnabled = resolveOptionalHostRouterBPFPaths(hostIngressPath, hostEgressPath, &hostRouterFailure);
      if (hostRouterFailure.size() > 0)
      {
         basics_log("setupNetworking invalid host router bpf configuration reason=%s ifidx=%d\n",
            hostRouterFailure.c_str(),
            eth.ifidx);
      }
      else if (hostRouterBPFEnabled)
      {
         if ((tcx_egress_program = eth.loadPreattachedProgram(BPF_TCX_EGRESS, hostEgressPath)) == nullptr)
         {
            tcx_egress_program = eth.attachBPF(BPF_TCX_EGRESS, hostEgressPath, "host_egress_router"_ctv);
            if (tcx_egress_program)
            {
               basics_log("setupNetworking attached host egress path=%s ifidx=%d\n",
                  hostEgressPath.c_str(), eth.ifidx);
            }
            else
            {
               basics_log("setupNetworking failed to attach host egress path=%s ifidx=%d\n",
                  hostEgressPath.c_str(), eth.ifidx);
            }
         }
         else
         {
            basics_log("setupNetworking loaded preattached host egress path=%s ifidx=%d\n",
               hostEgressPath.c_str(), eth.ifidx);
         }

			if ((tcx_ingress_program = eth.loadPreattachedProgram(BPF_TCX_INGRESS, hostIngressPath)))
			{
				basics_log("setupNetworking loaded preattached host ingress path=%s ifidx=%d\n",
					hostIngressPath.c_str(), eth.ifidx);
				// so we could gather our fragment this way but we don't need to
				// tcx_ingress_program->getArrayElement("local_container_subnet_map"_ctv, 0, lcsubnet6);

				// if we used the getULA(IPAddress& ula) on EthDevice with systemd network config files
				// to make subnets and fragments persist across operating system reboots.. but...
			}
			else
			{
					eth.addIP(containerSubnet6);

            String pinnedWhiteholeReplyPath = {};
            switchboardWhiteholeReplyFlowPinPath(pinnedWhiteholeReplyPath, eth.ifidx);

				// load and setup tcx ingress program
				tcx_ingress_program = eth.attachBPF(BPF_TCX_INGRESS, hostIngressPath, "host_ingress_router"_ctv,
               [&] (struct bpf_object *obj, Vector<int>& inner_map_fds) -> void {

                  int pinnedReplyMapFD = bpf_obj_get(pinnedWhiteholeReplyPath.c_str());
                  if (pinnedReplyMapFD < 0)
                  {
                     return;
                  }

                  if (struct bpf_map *replyMap = bpf_object__find_map_by_name(obj, "whitehole_reply_flows"))
                  {
                     bpf_map__reuse_fd(replyMap, pinnedReplyMapFD);
                  }

                  inner_map_fds.push_back(pinnedReplyMapFD);
               });
				if (tcx_ingress_program)
				{
					basics_log("setupNetworking attached host ingress path=%s ifidx=%d\n",
						hostIngressPath.c_str(), eth.ifidx);
					tcx_ingress_program->setArrayElement("local_container_subnet_map"_ctv, 0, lcsubnet6);
				}
				else
				{
					basics_log("setupNetworking failed to attach host ingress path=%s ifidx=%d\n",
						hostIngressPath.c_str(), eth.ifidx);
				}
			}
      }
      else
      {
         eth.addIP(containerSubnet6);
         basics_log("setupNetworking skipping host router bpf attach because PRODIGY_HOST_{INGRESS,EGRESS}_EBPF are unset ifidx=%d\n",
            eth.ifidx);
      }

      if (tcx_ingress_program)
      {
         tcx_ingress_program->setArrayElement("local_container_subnet_map"_ctv, 0, lcsubnet6);
      }

      if (tcx_egress_program)
      {
         tcx_egress_program->setArrayElement("mac_map"_ctv, 0, eth.mac);
         tcx_egress_program->setArrayElement("gateway_mac_map"_ctv, 0, eth.gateway_mac);
         tcx_egress_program->openMap("whitehole_reply_flows"_ctv, [&] (int map_fd) -> void {

            if (map_fd < 0)
            {
               return;
            }

            String pinPath = {};
            switchboardWhiteholeReplyFlowPinPath(pinPath, eth.ifidx);
            unlink(pinPath.c_str());
            (void)bpf_obj_pin(map_fd, pinPath.c_str());
         });
      }

         iaas->setLocalContainerPrefixes(localPrefixes);
         ensureBGP()->setMachinePrefixes(localPrefixes);

	      if (switchboard)
	      {
         switchboard->setHostEgressRouter(tcx_egress_program);
         switchboard->setLocalContainerSubnet(lcsubnet6);
      }

	      syncOverlayRoutingPrograms();
	}

      virtual bool ensureHostNetworkingReady(String *failureReport = nullptr) override
      {
         if (tcx_ingress_program && tcx_egress_program)
         {
            return true;
         }

         if (haveFragments() == false)
         {
            if (failureReport) failureReport->assign("neuron has no assigned fragment yet"_ctv);
            basics_log("ensureHostNetworkingReady failed reason=no-fragment ifidx=%d\n", eth.ifidx);
            return false;
         }

         String hostIngressPath = {};
         String hostEgressPath = {};
         String hostRouterFailure = {};
         bool hostRouterBPFEnabled = resolveOptionalHostRouterBPFPaths(hostIngressPath, hostEgressPath, &hostRouterFailure);
         if (hostRouterFailure.size() > 0)
         {
            if (failureReport)
            {
               failureReport->assign(hostRouterFailure);
            }

            basics_log("ensureHostNetworkingReady failed reason=%s ifidx=%d\n",
               hostRouterFailure.c_str(),
               eth.ifidx);
            return false;
         }

         setupNetworking();

         if (hostRouterBPFEnabled == false)
         {
            return true;
         }

         if (tcx_ingress_program == nullptr || tcx_egress_program == nullptr)
         {
            if (failureReport)
            {
               failureReport->snprintf<"host networking programs unavailable ingress={} egress={}"_ctv>(
                  String(tcx_ingress_program ? "ready" : "missing"),
                  String(tcx_egress_program ? "ready" : "missing"));
            }

            basics_log("ensureHostNetworkingReady failed ingress=%d egress=%d ifidx=%d\n",
               int(tcx_ingress_program != nullptr), int(tcx_egress_program != nullptr), eth.ifidx);
            return false;
         }

         return true;
      }

		public:

		String kernel;

		int64_t bootTimeMs;

			bool isBrain;
			TCPSocket brainListener;
				NeuronBrainControlStream *brain = nullptr;

		virtual void boot(void)
		{
		loadKernelVersion();
		bootTimeMs = Time::msSinceBoot();

		private4.is6 = false;
		
		iaas->gatherSelfData(uuid, metro, isBrain, eth, private4); // this is sync blocking

		gateway4.is6 = false;
		gateway4.v4 = eth.getPrivate4Gateway(private4.v4);
		bool gatewayMacResolved = eth.getGatewayMac(private4.v4, gateway4.v4);
		if (!gatewayMacResolved)
		{
			basics_log("Neuron::boot gateway mac unresolved netdev=%s ifidx=%d private4=%u gateway4=%u\n",
				eth.name.c_str(), eth.ifidx, ntohl(private4.v4), ntohl(gateway4.v4));
		}

         hardwareProfile = {};
         serializedHardwareProfile.clear();

			if (isBrain == false) ContainerStore::autoDestroy = true;

			if (const char *devMode = getenv("PRODIGY_DEV_MODE"); devMode && devMode[0] == '1' && devMode[1] == '\0')
			{
				brainControlKeepaliveSeconds = 6;
			}
			else
			{
				brainControlKeepaliveSeconds = 15;
			}

				brainListener.setIPVersion(AF_INET6);
				setsockopt(brainListener.fd, IPPROTO_IPV6, IPV6_V6ONLY, (const int[]){0}, sizeof(int));
				brainListener.setKeepaliveTimeoutSeconds(brainControlKeepaliveSeconds);
				brainListener.setSaddr("::"_ctv, uint16_t(ReservedPorts::neuron));
				brainListener.bindThenListen();

				RingDispatcher::installMultiplexee(&brainListener, this);
	      RingDispatcher::installMultiplexee(this, this);
			Ring::installFDIntoFixedFileSlot(&brainListener);
         deferredHardwareInventoryWake.fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
         if (deferredHardwareInventoryWake.fd < 0)
         {
            std::fprintf(stderr, "prodigy deferred hardware wake eventfd failed errno=%d(%s)\n", errno, strerror(errno));
            std::abort();
         }
         deferredHardwareInventoryWake.setNonBlocking();
         // The detached collector thread signals this eventfd via process-fd write(),
         // so it must retain a live process fd instead of being relinquished into a
         // fixed-file-only slot.
         RingDispatcher::installMultiplexee(&deferredHardwareInventoryWake, this);
         armDeferredHardwareInventoryWakePoll();
			queueBrainAccept();
         cleanupExpiredFailedContainerArtifacts();
         ensureFailedContainerArtifactGCTickQueued();
         beginDeferredHardwareInventoryCollection();
		}

	   void sendOrQueue(NeuronTopic topic, const String& payload)
	   {
	      if (brain)
	      {
	         Message::construct(brain->wBuffer, topic, payload);
	         if (streamIsActive(brain))
	         {
	            Ring::queueSend(brain);
	         }
	      }
	   }

	void hardwareFailureOccured(void) // we have 1 second to report the failure
	{
		// prodigy will auto shutdown

		if (brain)
		{
			String report;
			Filesystem::openReadAtClose(-1, "/run/hardwarefailure.txt"_ctv, report);

			Message::construct(brain->wBuffer, NeuronTopic::hardwareFailure);
			if (streamIsActive(brain))
			{
	   			Ring::queueSend(brain);
			}
		}
	}

   void queueContainerKillAck(uint128_t containerUUID) override
   {
      if (brain == nullptr)
      {
         return;
      }

      Message::construct(brain->wBuffer, NeuronTopic::killContainer, containerUUID);
      if (streamIsActive(brain))
      {
         Ring::queueSend(brain);
      }
   }

   void waitidHandler(void *waiter) override
   {
		// typedef struct {
		// 	int      si_signo;    /* Signal number */
		// 	int      si_errno;    /* An errno value */
		// 	int      si_code;     /* Signal code */
		// 	int      si_trapno;   /* Trap number that caused hardware-generated signal */
		// 	pid_t    si_pid;      /* Sending process ID */
		// 	uid_t    si_uid;      /* Real user ID of sending process */
		// 	int      si_status;   /* Exit value or signal */
		// 	clock_t  si_utime;    /* User time consumed */
		// 	clock_t  si_stime;    /* System time consumed */
		// 	sigval_t si_value;    /* Signal value */
		// 	int      si_int;      /* POSIX.1b signal */
		// 	void    *si_ptr;      /* POSIX.1b signal */
		// 	int      si_overrun;  /* Timer overrun count; POSIX.1b timers */
		// 	int      si_timerid;  /* Timer ID; POSIX.1b timers */
		// 	void    *si_addr;     /* Memory location which caused fault */
		// 	long     si_band;     /* Band event */
		// 	int      si_fd;       /* File descriptor */
		// 	short    si_addr_lsb; /* Least significant bit of address */
		// } siginfo_t;

   	uint128_t containerUUID;
   	bool killedOnPurpose;
      bool destroyAfterWait = false;

	   CoroutineStack *resumeAfterShutdown = nullptr;

		   	Container *container = reinterpret_cast<Container *>(waiter);
			siginfo_t infop = container->infop;
			bool nonRestartableStartupFailure = (infop.si_code == CLD_EXITED && infop.si_status == containerStartupFailureExitCode);
			String containerName = container->name;
			{
	   		containerUUID = container->plan.uuid;
	   		container->disableKillSwitch();
	   		container->closeSocket();
   		killedOnPurpose = container->killedOnPurpose;

   		resumeAfterShutdown = container->resumeAfterShutdown;
         destroyAfterWait = (killedOnPurpose || container->plan.restartOnFailure == false || nonRestartableStartupFailure);
   	}

	   	bool restart = (destroyAfterWait == false);

		basics_log("neuron waitid uuid=%llu pid=%d code=%d status=%d killedOnPurpose=%d restart=%d startupFailure=%d\n",
			(unsigned long long)containerUUID,
			int(infop.si_pid),
			int(infop.si_code),
			int(infop.si_status),
			int(killedOnPurpose),
			int(restart),
			int(nonRestartableStartupFailure));

		verboseNeuronSocketLog("neuron waitid uuid=%llu pid=%d code=%d status=%d killedOnPurpose=%d restart=%d startupFailure=%d\n",
			(unsigned long long)containerUUID,
			int(infop.si_pid),
			int(infop.si_code),
			int(infop.si_status),
			int(killedOnPurpose),
			int(restart),
			int(nonRestartableStartupFailure));

      int64_t failureTimeMs = Time::now<TimeResolution::ms>();

   	if (killedOnPurpose == false) 
   	{
   		statefulCrashed.insert(containerUUID);

   		String crashReport;
   		int terminalSignal = ContainerManager::terminalSignalForFailedContainer(infop);

         String retainedBundlePath = {};
         String retainedBundleFailure = {};
         if (ContainerManager::preserveFailedContainerArtifactsIfNeeded(
               container,
               failureTimeMs,
               &retainedBundlePath,
               &retainedBundleFailure) == false)
         {
            basics_log("neuron failed-container artifact retention failed uuid=%llu reason=%s\n",
               (unsigned long long)containerUUID,
               retainedBundleFailure.c_str());
         }
         else
         {
            basics_log("neuron failed-container artifacts retained uuid=%llu path=%s\n",
               (unsigned long long)containerUUID,
               retainedBundlePath.c_str());
         }

		            if (infop.si_code != CLD_EXITED) // child DID NOT exit via exit()... but by some crash
		            {

                // for stack traces
	   		// The best practice is to compile the binary with -O2 (or whatever optimization you are using) and -g together, then strip -g a.out -o a.out.release and 
	   		// ship the a.out.release binary, while keeping the full-debug a.out for future debugging.
				// That way you guarantee that all the symbol addresses are identical between the released executable and your full-debug copy.

		   		String path;
		   		path.snprintf<"/containers/{}/crashreport.txt"_ctv>(containerName);

                Filesystem::openReadAtClose(-1, path, crashReport);
                Filesystem::eraseFile(path);

				if (crashReport.size() == 0)
				{
					String stagePath;
					stagePath.snprintf<"/containers/{}/bootstage.txt"_ctv>(containerName);

					String bootStage;
					Filesystem::openReadAtClose(-1, stagePath, bootStage);
					Filesystem::eraseFile(stagePath);

					if (bootStage.size() > 0)
					{
						crashReport.assign("bootstage="_ctv);
						crashReport.append(bootStage);
					}
				}

                // If denied by seccomp (SIGSYS), include syscall number (Linux x86_64)
                if (terminalSignal == SIGSYS)
                {
#ifdef __linux__
#ifdef __x86_64__
                    int sysno = 0;
#ifdef si_syscall
                    sysno = infop.si_syscall;
#else
                    // glibc private layout; acceptable given our platform constraints
                    sysno = infop._sifields._sigsys._syscall;
#endif
                    crashReport.snprintf_add<"\n(denied syscall by seccomp: id={itoa})"_ctv>(sysno);
#else
                    crashReport.append("\n(denied syscall by seccomp)"_ctv);
#endif
#else
                    crashReport.append("\n(denied syscall by seccomp)"_ctv);
#endif
                }
            }
	            else
	            {
	               if (infop.si_status == containerStartupFailureExitCode)
	               {
	                  crashReport.assign("startup failed before exec"_ctv);
	               }
	               else
	               {
			   		String path;
			   		path.snprintf<"/containers/{}/crashreport.txt"_ctv>(containerName);

	                  Filesystem::openReadAtClose(-1, path, crashReport);
	                  if (crashReport.size() > 0)
	                  {
	                  	Filesystem::eraseFile(path);
	                  }
	                  else
	                  {
	                     crashReport.assign("exited with code "_ctv);
	                     String exitCode;
	                     exitCode.assignItoa(infop.si_status);
	                     crashReport.append(exitCode);
	                  }
	               }
	            }

			uint64_t previewBytes = (crashReport.size() < 1024) ? crashReport.size() : 1024;
			String preview;
			preview.reserve(previewBytes + 1);
			for (uint64_t idx = 0; idx < previewBytes; ++idx)
			{
				char c = crashReport[idx];
				if (c < 32 || c > 126)
				{
					c = '.';
				}
				preview.append(&c, 1);
			}
			char terminalNull = '\0';
			preview.append(&terminalNull, 1);
			basics_log("neuron crashReport uuid=%llu signal=%d reportBytes=%u preview=%s\n",
				(unsigned long long)containerUUID,
				terminalSignal,
				unsigned(crashReport.size()),
				(previewBytes > 0 ? preview.c_str() : "<empty>"));

			   // containerUUID(16) approxTimeMs(8) signal(4) report{4} restarted(1)
		      if (brain)
	      {
	   	   Message::construct(brain->wBuffer, NeuronTopic::containerFailed, containerUUID, failureTimeMs, terminalSignal, crashReport, restart);
	   	   if (streamIsActive(brain))
	   	   {
	   	   	Ring::queueSend(brain);
	   	   }
	      }

	   		if (restart) 
	   		{
	   			ContainerManager::restartContainer(container);
	   		}
            else
            {
               // this does not destroy any stateful storage
               // this deletes it from the bookkeeping
               ContainerManager::destroyContainer(container);
            }
	   	}
   	else if (resumeAfterShutdown)
   	{
         if (destroyAfterWait)
         {
            ContainerManager::destroyContainer(container);
         }
   		resumeAfterShutdown->co_consume();
   	}
      else if (destroyAfterWait)
      {
         ContainerManager::destroyContainer(container);
      }
   }

	void containerHandler(Container *container, Message *message)
	{
		uint8_t *args = message->args;
		uint8_t *terminal = message->terminal();

		if (ProdigyIngressValidation::validateContainerPayloadForNeuron(message->topic, args, terminal) == false)
		{
			queueCloseIfActive(container);
			return;
		}

		ContainerTopic topic = (ContainerTopic)message->topic;
		verboseNeuronSocketLog("neuron containerHandler uuid=%llu topic=%u size=%u\n",
			(unsigned long long)container->plan.uuid,
			unsigned(message->topic),
			unsigned(message->size));

		switch (topic)
		{
			case ContainerTopic::ping:
			{
				Message::construct(container->wBuffer, ContainerTopic::pong);
				if (streamIsActive(container))
				{
					Ring::queueSend(container);
				}

				break;
			}
			case ContainerTopic::pong:
			{
				
				break;
			}
			case ContainerTopic::healthy:
			{
				container->plan.state = ContainerState::healthy;
				basics_log("neuron containerHealthy uuid=%llu deploymentID=%llu appID=%u\n",
					(unsigned long long)container->plan.uuid,
					(unsigned long long)container->plan.config.deploymentID(),
					unsigned(container->plan.config.applicationID));
				std::fprintf(stderr,
					"neuron containerHealthy dispatch uuid=%llu deploymentID=%llu appID=%u thisBrain=%p canControl=%d brainPresent=%d brainActive=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d\n",
					(unsigned long long)container->plan.uuid,
					(unsigned long long)container->plan.config.deploymentID(),
					unsigned(container->plan.config.applicationID),
					static_cast<void *>(thisBrain),
					int(thisBrain != nullptr && thisBrain->canControlNeurons()),
					int(brain != nullptr),
					int(brain != nullptr && streamIsActive(brain)),
					brain ? brain->fd : -1,
					brain ? brain->fslot : -1,
					int(brain ? brain->pendingSend : 0),
					int(brain ? brain->pendingRecv : 0));
				std::fflush(stderr);

            if (thisBrain != nullptr && thisBrain->canControlNeurons())
            {
               thisBrain->noteLocalContainerHealthy(container->plan.uuid);
            }

            bool controllingBrainActive = (brain != nullptr && streamIsActive(brain));
#if PRODIGY_DEBUG
				basics_log("neuron containerHealthy brain-state uuid=%llu brainPresent=%d brainConnected=%d brainActive=%d pendingSend=%d pendingRecv=%d fd=%d fslot=%d\n",
					(unsigned long long)container->plan.uuid,
					int(brain != nullptr),
					int(brain ? brain->connected : 0),
					int(controllingBrainActive),
					int(brain ? brain->pendingSend : 0),
					int(brain ? brain->pendingRecv : 0),
					brain ? brain->fd : -1,
					brain ? brain->fslot : -1);
#endif

				// Explicitly notify brain that this container passed startup.
				// Deployment scheduling waits on this signal.
				if (brain)
				{
					Message::construct(brain->wBuffer, NeuronTopic::containerHealthy, container->plan.uuid);
					if (controllingBrainActive)
					{
						Ring::queueSend(brain);
					}
				}

				break;
			}
			case ContainerTopic::statistics:
			{
				// [metricKey(8) metricValue(8)]...
				// Forward container runtime metrics to the controlling brain with identity metadata.
				if (brain == nullptr) break;

				uint32_t headerOffset = Message::appendHeader(brain->wBuffer, NeuronTopic::containerStatistics);
				Message::append(brain->wBuffer, container->plan.config.deploymentID());
				Message::append(brain->wBuffer, container->plan.uuid);
				Message::append(brain->wBuffer, Time::now<TimeResolution::ms>());

				while (args < terminal)
				{
					if (size_t(terminal - args) < (sizeof(uint64_t) * 2)) break;

					uint64_t metricKey = 0;
					uint64_t metricValue = 0;

					Message::extractArg<ArgumentNature::fixed>(args, metricKey);
					Message::extractArg<ArgumentNature::fixed>(args, metricValue);

					if (metricKey == pulseBatteryPassMetricKey)
					{
						basics_log("PULSE_BATTERY_PASS_METRIC deploymentID=%llu uuid=%llu value=%llu\n",
							(unsigned long long)container->plan.config.deploymentID(),
							(unsigned long long)container->plan.uuid,
							(unsigned long long)metricValue);
					}

					Message::append(brain->wBuffer, metricKey);
					Message::append(brain->wBuffer, metricValue);
				}

				Message::finish(brain->wBuffer, headerOffset);
					if (streamIsActive(brain))
					{
						Ring::queueSend(brain);
					}

					break;
				}
			case ContainerTopic::resourceDeltaAck:
			{
				bool accepted = false;
				Message::extractArg<ArgumentNature::fixed>(args, accepted);
				basics_log("neuron resourceDeltaAck uuid=%llu accepted=%d\n",
					(unsigned long long)container->plan.uuid,
					int(accepted));
				break;
			}
			case ContainerTopic::credentialsRefresh:
			{
				if (brain)
				{
					Message::construct(brain->wBuffer, NeuronTopic::refreshContainerCredentials, container->plan.uuid);
					if (streamIsActive(brain))
					{
						Ring::queueSend(brain);
					}
				}

				break;
			}
			// case ContainerTopic::flag: // container changes its flag values (these only need to reside locally, because if the machine failed it'd start from scratch)
			// {
			// 	// flagIndex(8) flagValue(8)

			// 	uint64_t index;
			// 	Message::extractArg<ArgumentNature::fixed>(args, index);

			// 	uint64_t value;
			// 	Message::extractArg<ArgumentNature::fixed>(args, value);

			// 	if (index < container->plan.flags.size()) container->plan.flags[index] = value;

			// 	break;
			// }
			default: break;
		}
	}

   void downloadContainer(CoroutineStack *coro, uint64_t deploymentID) override
   {
      bool alreadyPending = pendingContainerDownloads.contains(deploymentID);

      if (pendingContainerDownloads.hasEntryFor(deploymentID, coro) == false)
      {
         pendingContainerDownloads.insert(deploymentID, coro);
      }

      if (alreadyPending == false)
      {
         std::fprintf(stderr, "neuron downloadContainer request deploymentID=%llu brainPresent=%d brainActive=%d pendingCount=%llu pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d fd=%d fslot=%d\n",
            (unsigned long long)deploymentID,
            int(brain != nullptr),
            int(streamIsActive(brain)),
            (unsigned long long)pendingContainerDownloads.size(),
            int(brain ? brain->pendingSend : 0),
            int(brain ? brain->pendingRecv : 0),
            int(brain ? brain->isTLSNegotiated() : 0),
            int(brain ? brain->tlsPeerVerified : 0),
            (brain ? brain->fd : -1),
            (brain ? brain->fslot : -1));
         std::fflush(stderr);
         Message::construct(brain->wBuffer, NeuronTopic::requestContainerBlob, deploymentID);
			         if (streamIsActive(brain))
			         {
			         	Ring::queueSend(brain);
			         }
      }
   }

	void neuronHandler(Message *message)
	{
		uint8_t *args = message->args;
		uint8_t *terminal = message->terminal();

		if (ProdigyIngressValidation::validateNeuronPayloadForNeuron(message->topic, args, terminal) == false)
		{
			if (brain)
			{
				brain->rBuffer.clear();
				queueCloseIfActive(brain);
			}
			return;
		}

		switch (NeuronTopic(message->topic))
		{
            case NeuronTopic::registration:
            {
                // requiresState(1)

				bool requiresState;
				Message::extractArg<ArgumentNature::fixed>(args, requiresState);

				if (requiresState)
				{
					uint32_t headerOffset = Message::appendHeader(brain->wBuffer, NeuronTopic::stateUpload);

					Message::appendAlignedBuffer<Alignment::one>(brain->wBuffer, (uint8_t *)&lcsubnet6, sizeof(struct local_container_subnet6));

						for (const auto& [uuid, container] : containers)
						{
                     (void)uuid;
                     String serializedPlan;
                     BitseryEngine::serialize(serializedPlan, container->plan);
                     Message::appendValue(brain->wBuffer, serializedPlan);
						}

					Message::finish(brain->wBuffer, headerOffset);

					if (streamIsActive(brain))
					{
						Ring::queueSend(brain);
					}
				}

				break;
			}
			case NeuronTopic::stateUpload:
			{
				// fragment(4, 1) containerPlan{4}...
				Message::extractBytes<Alignment::one>(args, (uint8_t *)&lcsubnet6, sizeof(struct local_container_subnet6));
				setupNetworking();

					bool malformedStateUpload = false;
					while (args < terminal) // it's possible that some of these containers died right?
					{
						String buffer;
						Message::extractToStringView(args, buffer);
						if (buffer.data() > terminal || buffer.size() > uint64_t(terminal - buffer.data()))
						{
							malformedStateUpload = true;
							break;
						}

                  NeuronContainerBootstrap bootstrap;
                  NeuronContainerMetricPolicy metricPolicy;
                  ContainerPlan restoredPlan;
                  if (BitseryEngine::deserializeSafe(buffer, bootstrap))
                  {
                     restoredPlan = std::move(bootstrap.plan);
                     metricPolicy = bootstrap.metricPolicy;
                  }
                  else if (BitseryEngine::deserializeSafe(buffer, restoredPlan) == false)
                  {
                     malformedStateUpload = true;
                     break;
                  }

						Container *container = new Container();
                  container->plan = std::move(restoredPlan);
                  container->neuronScalingDimensionsMask = metricPolicy.scalingDimensionsMask;
                  container->neuronMetricsCadenceMs = metricPolicy.metricsCadenceMs;

      			container->name.assignItoa(container->plan.uuid);
      			container->userID = 65535 * container->plan.fragment;

      			String output;
      			String path;
      			path.snprintf<"/sys/fs/cgroup/containers.slice/{}.slice/leaf"_ctv>(container->name);

      			container->cgroup = Filesystem::openDirectoryAt(-1, path);

      			path.snprintf<"/sys/fs/cgroup/containers.slice/{}.slice/cpuset.cpus"_ctv>(container->name);
					Filesystem::openReadAtClose(-1, path, output);

               memset(container->lcores, 0, sizeof(container->lcores));
               if (applicationUsesIsolatedCPUs(container->plan.config))
               {
					      // {itoa}-{itoa}
					      uint16_t lowCore = output.toNumber<uint16_t>(uint64_t(0), output.findChar('-', 1));

					      for (uint16_t index = 0; index < container->plan.config.nLogicalCores; ++index)
					      {
						      container->lcores[index] = lowCore + index;
					      }
               }

					Filesystem::openReadAtClose(container->cgroup, "cgroup.procs"_ctv, output);

					if (output.size() > 0)
					{
						// in the future if we ever need to run multiple processes inside a container,
						// then we'd need to check /proc/{pid}/status and line NSpid: 12345 1 to get the pid mapping to select pid 1
						container->pid = output.toNumber<pid_t>();
						container->pidfd = syscall(SYS_pidfd_open, container->pid, 0);

                  if (container->plan.useHostNetworkNamespace == false)
                  {
                     String restoreFailure;
						   if (container->restoreNetwork(&restoreFailure) == false)
                     {
                        basics_log("restoreContainer network restore failed uuid=%llu reason=%s\n",
                           (unsigned long long)container->plan.uuid,
                           restoreFailure.c_str());

                        bool restarted = false;
                        if (container->plan.restartOnFailure)
                        {
                           restarted = true;
                           ContainerManager::restartContainer(container);
                        }
                        else
                        {
                           ContainerManager::destroyContainer(container);
                        }

                        String empty;
                        Message::construct(brain->wBuffer, NeuronTopic::containerFailed, container->plan.uuid, 0, 0, empty, restarted);
                        Ring::queueSend(brain);
                        continue;
                     }
                  }
                  else
                  {
                     for (const IPPrefix& prefix : container->plan.addresses)
                     {
                        eth.addIP(prefix);
                     }

                     installDatacenterMeshRoutes(eth, lcsubnet6.dpfx);
                  }

						path.snprintf<"/containers/{}/neuron.soc"_ctv>(container->name);
						container->setSocketPath(path.c_str());
						pushContainer(container);
						Ring::queueWaitid(container, P_PID, container->pid);
						Ring::queueConnect(container);
					}
					else
					{
						bool restarted = false;
						
						if (container->plan.restartOnFailure)
						{
							restarted = true;
							ContainerManager::restartContainer(container);
						}
						else
						{
							ContainerManager::destroyContainer(container);
						}

						// containerUUID(16) approxTimeMs(8) signal(4) report{4} restarted(1)
						String empty;
						Message::construct(brain->wBuffer, NeuronTopic::containerFailed, container->plan.uuid, 0, 0, empty, restarted);
	   			if (streamIsActive(brain))
	   			{
	   				Ring::queueSend(brain);
	   			}
						}
				}

				if (malformedStateUpload)
				{
					basics_log("neuron stateUpload malformed plan payload\n");
					if (brain)
					{
						brain->rBuffer.clear();
						queueCloseIfActive(brain);
					}
				}

				break;
			}
			case NeuronTopic::assignFragment:
			{
				// fragment(4, 1)

				Message::extractBytes<Alignment::one>(args, (uint8_t *)&lcsubnet6, sizeof(struct local_container_subnet6));
				setupNetworking();

				setupNetworking();

				break;
			}
         case NeuronTopic::configureRuntimeEnvironment:
         {
            String serialized;
            Message::extractToStringView(args, serialized);

            ProdigyRuntimeEnvironmentConfig config = {};
            if (BitseryEngine::deserializeSafe(serialized, config))
            {
               iaas->configureRuntimeEnvironment(config);

               if (bgp)
               {
                  NeuronBGPConfig bgpConfig = {};
                  iaas->gatherBGPConfig(bgpConfig, eth, private4);
                  bgp->configure(bgpConfig);
               }
            }

            break;
         }
			case NeuronTopic::requestContainerBlob:
			{
				// deploymentID(8) containerBlob{4}

				uint64_t deploymentID;
				Message::extractArg<ArgumentNature::fixed>(args, deploymentID);

				String containerBlob;
				Message::extractToStringView(args, containerBlob);
				std::fprintf(stderr, "neuron requestContainerBlob response deploymentID=%llu bytes=%u pendingWaiters=%llu\n",
					(unsigned long long)deploymentID,
					unsigned(containerBlob.size()),
					(unsigned long long)(pendingContainerDownloads.contains(deploymentID) ? pendingContainerDownloads.countEntriesFor(deploymentID) : 0));
				std::fflush(stderr);

				String containerStoreFailure = {};
				if (ContainerStore::store(deploymentID, containerBlob, nullptr, nullptr, nullptr, nullptr, &containerStoreFailure) == false)
				{
					std::fprintf(stderr,
						"neuron requestContainerBlob store failed deploymentID=%llu reason=%s\n",
						(unsigned long long)deploymentID,
						(containerStoreFailure.size() > 0 ? containerStoreFailure.c_str() : "unknown"));
					std::fflush(stderr);
				}

				if (auto pendingIt = pendingContainerDownloads.find(deploymentID); pendingIt != pendingContainerDownloads.end())
				{
					Vector<CoroutineStack *> toResume;
					toResume = std::move(pendingIt->second);
					pendingContainerDownloads.erase(pendingIt);

					// Defensive dedupe: a coroutine may already be tracked for this deployment.
					bytell_hash_set<CoroutineStack *> resumed;
					for (CoroutineStack *coro : toResume)
					{
						if (coro == nullptr || resumed.contains(coro))
						{
							continue;
						}

						resumed.emplace(coro);
						coro->co_consume();
					}
				}

				break;
			}
			case NeuronTopic::spinContainer:
			{
				// replaceContainerUUID(16) plan{4} 

				uint128_t replaceContainerUUID;
				Message::extractArg<ArgumentNature::fixed>(args, replaceContainerUUID);

				String buffer;
				Message::extractToStringView(args, buffer);
				if (buffer.data() > terminal || buffer.size() > uint64_t(terminal - buffer.data()))
				{
					basics_log("neuron spinContainer malformed plan payload\n");
					break;
				}

            ContainerPlan plan;
            NeuronContainerMetricPolicy metricPolicy;
            NeuronContainerBootstrap bootstrap;
            if (BitseryEngine::deserializeSafe(buffer, bootstrap))
            {
               plan = std::move(bootstrap.plan);
               metricPolicy = bootstrap.metricPolicy;
            }
            else if (BitseryEngine::deserializeSafe(buffer, plan) == false)
            {
               basics_log("neuron spinContainer plan deserialize failed\n");
               break;
            }
				std::fprintf(stderr, "neuron spinContainer deploymentID=%llu appID=%u replaceUUID=%llu blobBytes=%llu blobSHA=%s\n",
					(unsigned long long)plan.config.deploymentID(),
					unsigned(plan.config.applicationID),
					(unsigned long long)replaceContainerUUID,
					(unsigned long long)plan.config.containerBlobBytes,
					plan.config.containerBlobSHA256.c_str());
				std::fflush(stderr);

				ContainerManager::spinContainer(plan, replaceContainerUUID, metricPolicy);

				if (replaceContainerUUID > 0) Message::construct(brain->wBuffer, NeuronTopic::killContainer, replaceContainerUUID);

				break;
			}
			case NeuronTopic::adjustContainerResources:
			{
				// containerUUID(16) nLogicalCores(2) memoryMB(4) storageMB(4) [isDownscale(1)] [graceSeconds(4)]

				uint128_t containerUUID = 0;
				uint16_t targetCores = 0;
				uint32_t targetMemoryMB = 0;
				uint32_t targetStorageMB = 0;
				bool isDownscale = false;
				uint32_t graceSeconds = 0;

				Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
				Message::extractArg<ArgumentNature::fixed>(args, targetCores);
				Message::extractArg<ArgumentNature::fixed>(args, targetMemoryMB);
				Message::extractArg<ArgumentNature::fixed>(args, targetStorageMB);

				if (terminal - args >= ptrdiff_t(sizeof(bool)))
				{
					Message::extractArg<ArgumentNature::fixed>(args, isDownscale);
				}

				if (terminal - args >= ptrdiff_t(sizeof(uint32_t)))
				{
					Message::extractArg<ArgumentNature::fixed>(args, graceSeconds);
				}

				if (auto it = containers.find(containerUUID); it != containers.end())
				{
					Container *container = it->second;
					String failureReport;
					if (ContainerManager::adjustRunningContainerResources(container, targetCores, targetMemoryMB, targetStorageMB, &failureReport))
					{
						String payload;
						if (ProdigyWire::serializeResourceDeltaPayload(payload, targetCores, targetMemoryMB, targetStorageMB, isDownscale, graceSeconds) &&
							ProdigyWire::constructPackedFrame(container->wBuffer, ContainerTopic::resourceDelta, payload) &&
							streamIsActive(container))
						{
							Ring::queueSend(container);
						}
					}
					else
					{
						basics_log("neuron adjustContainerResources failed uuid=%llu targetCores=%u targetMemoryMB=%u targetStorageMB=%u reason=%s\n",
							(unsigned long long)containerUUID,
							unsigned(targetCores),
							unsigned(targetMemoryMB),
							unsigned(targetStorageMB),
							(failureReport.size() ? failureReport.c_str() : "unknown"));
					}
				}

				break;
			}
			case NeuronTopic::changeContainerLifetime:
			{
				// containerUUID(16) lifetime(1)

				uint128_t containerUUID;
				Message::extractArg<ArgumentNature::fixed>(args, containerUUID);

				if (auto it = containers.find(containerUUID); it != containers.end())
				{
					Container *container = it->second;
					Message::extractArg<ArgumentNature::fixed>(args, container->plan.lifetime);
				}

				break;
			}
			case NeuronTopic::killContainer:
			{
				// containerUUID(16)

				uint128_t containerUUID;
				Message::extractArg<ArgumentNature::fixed>(args, containerUUID);

				if (auto it = containers.find(containerUUID); it != containers.end())
				{
					Container *container = it->second;
					container->pendingKillAckToBrain = true;
					container->stop();
				}
				else if (brain)
				{
					Message::construct(brain->wBuffer, NeuronTopic::killContainer, containerUUID);
					if (streamIsActive(brain))
					{
						Ring::queueSend(brain);
					}
				}

				break;
			}
	         case NeuronTopic::resetSwitchboardState:
	         {
               if (bgp)
               {
                  bgp->resetPublicRoutablePrefixes();
               }

               overlayRoutingConfig = {};
               syncOverlayRoutingPrograms();
               whiteholeBindingsByContainer.clear();
               syncWhiteholeBindingsProgram();

	            ensureSwitchboard()->setLocalContainerSubnet(lcsubnet6);
	            ensureSwitchboard()->resetState();
	            break;
         }
         case NeuronTopic::configureSwitchboardRoutableSubnets:
         {
            String serialized;
            Message::extractToStringView(args, serialized);

            Vector<DistributableExternalSubnet> routableSubnets;
            if (BitseryEngine::deserializeSafe(serialized, routableSubnets) == false)
            {
               basics_log("neuron configureSwitchboardRoutableSubnets deserialize failed\n");
               break;
            }

               ensureBGP()->setPublicRoutableSubnets(routableSubnets);
	            ensureSwitchboard()->setLocalContainerSubnet(lcsubnet6);
	            ensureSwitchboard()->setRoutableSubnets(routableSubnets);
	            break;
         }
         case NeuronTopic::configureSwitchboardHostedIngressPrefixes:
         {
            String serialized;
            Message::extractToStringView(args, serialized);

            Vector<IPPrefix> hostedPrefixes = {};
            if (BitseryEngine::deserializeSafe(serialized, hostedPrefixes) == false)
            {
               basics_log("neuron configureSwitchboardHostedIngressPrefixes deserialize failed\n");
               break;
            }

            ensureSwitchboard()->setLocalContainerSubnet(lcsubnet6);
            basics_log("neuron configureSwitchboardHostedIngressPrefixes count=%u\n", unsigned(hostedPrefixes.size()));
            ensureSwitchboard()->setHostedIngressPrefixes(hostedPrefixes);
            break;
         }
         case NeuronTopic::configureSwitchboardOverlayRoutes:
         {
            String serialized;
            Message::extractToStringView(args, serialized);

            SwitchboardOverlayRoutingConfig config = {};
            if (BitseryEngine::deserializeSafe(serialized, config) == false)
            {
               basics_log("neuron configureSwitchboardOverlayRoutes deserialize failed\n");
               break;
            }

            overlayRoutingConfig = config;
            syncOverlayRoutingPrograms();
            break;
         }
         case NeuronTopic::openSwitchboardWormholes:
         {
            uint32_t containerID = 0;
            Message::extractArg<ArgumentNature::fixed>(args, containerID);

            String serialized;
            Message::extractToStringView(args, serialized);

            Vector<Wormhole> wormholes = {};
            if (BitseryEngine::deserializeSafe(serialized, wormholes) == false)
            {
               basics_log("neuron openSwitchboardWormholes deserialize failed\n");
               break;
            }

            ensureSwitchboard()->setLocalContainerSubnet(lcsubnet6);
            basics_log("neuron openSwitchboardWormholes containerID=%u count=%u\n", containerID, unsigned(wormholes.size()));
            ensureSwitchboard()->openWormholes(containerID, wormholes);

            // The open topic must converge the live local peer runtime immediately
            // for the owning container, otherwise first in-cluster packets can race
            // ahead of the peer-program map update and miss the wormhole binding.
            if (Container *container = findTrackedContainerByLocalID(containerID); container != nullptr)
            {
               syncContainerSwitchboardRuntime(container);
            }
            break;
         }
         case NeuronTopic::refreshContainerWormholes:
         {
            uint128_t containerUUID = 0;
            Message::extractArg<ArgumentNature::fixed>(args, containerUUID);

            String serialized;
            Message::extractToStringView(args, serialized);

            Vector<Wormhole> wormholes = {};
            if (BitseryEngine::deserializeSafe(serialized, wormholes) == false)
            {
               basics_log("neuron refreshContainerWormholes deserialize failed\n");
               break;
            }

            if (auto it = containers.find(containerUUID); it != containers.end())
            {
               Container *container = it->second;
               if (container == nullptr || container->pendingDestroy)
               {
                  break;
               }

               container->plan.wormholes = wormholes;
               refreshContainerSwitchboardWormholes(container);
               if (streamIsActive(container))
               {
                  Message::construct(container->wBuffer, ContainerTopic::wormholesRefresh, serialized);
                  Ring::queueSend(container);
               }
            }

            break;
         }
         case NeuronTopic::closeSwitchboardWormholesToContainer:
         {
            uint32_t containerID = 0;
            Message::extractArg<ArgumentNature::fixed>(args, containerID);

            ensureSwitchboard()->setLocalContainerSubnet(lcsubnet6);
            ensureSwitchboard()->closeWormholesToContainer(containerID);
            break;
         }
         case NeuronTopic::openSwitchboardWhiteholes:
         {
            uint32_t containerID = 0;
            Message::extractArg<ArgumentNature::fixed>(args, containerID);

            Vector<Whitehole> whiteholes = {};
            while (args < terminal)
            {
               Whitehole whitehole = {};
               Message::extractArg<ArgumentNature::fixed>(args, whitehole.sourcePort);
               Message::extractBytes<Alignment::one>(args, whitehole.address.v6, 16);
               Message::extractArg<ArgumentNature::fixed>(args, whitehole.address.is6);
               Message::extractArg<ArgumentNature::fixed>(args, whitehole.transport);
               Message::extractArg<ArgumentNature::fixed>(args, whitehole.bindingNonce);
               whitehole.hasAddress = !whitehole.address.isNull();
               whiteholes.push_back(whitehole);
            }

            openLocalWhiteholes(containerID, whiteholes);
            break;
         }
         case NeuronTopic::closeSwitchboardWhiteholesToContainer:
         {
            uint32_t containerID = 0;
            Message::extractArg<ArgumentNature::fixed>(args, containerID);

            closeLocalWhiteholesToContainer(containerID);
            break;
         }
				case NeuronTopic::advertisementPairing:
				{
				// containerUUID(16) secret(16) address(16) service(8) applicationID(2) activate(1)

				uint128_t containerUUID = 0;
				Message::extractArg<ArgumentNature::fixed>(args, containerUUID);

				if (args > terminal)
				{
					basics_log("neuron advertisementPairing malformed bounds args=%p terminal=%p\n", args, terminal);
					break;
				}

				uint32_t payloadBytes = uint32_t(terminal - args);
				uint128_t secret = 0;
				uint128_t address = 0;
				uint64_t service = 0;
				uint16_t applicationID = 0;
				bool activate = false;
				if (ProdigyWire::deserializeAdvertisementPairingPayloadAuto(
					args,
					uint64_t(terminal - args),
					secret,
					address,
					service,
					applicationID,
					activate) == false)
				{
					basics_log("neuron advertisementPairing malformed payload containerUUID=%llu payloadBytes=%u\n",
						(unsigned long long)containerUUID,
						unsigned(payloadBytes));
					break;
				}

					if (auto it = containers.find(containerUUID); it != containers.end())
					{
						Container *container = it->second;
						if (container->pendingDestroy)
						{
							basics_log("neuron advertisementPairing skip pendingDestroy containerUUID=%llu payloadBytes=%u\n",
								(unsigned long long)containerUUID,
								unsigned(payloadBytes));
							break;
							}

							bool changed = container->plan.applyAdvertisementPairing(AdvertisementPairing(secret, address, service), activate);
							basics_log("neuron advertisementPairing apply containerUUID=%llu payloadBytes=%u streamActive=%d\n",
								(unsigned long long)containerUUID,
								unsigned(payloadBytes),
							int(streamIsActive(container)));

						if (changed)
						{
							if (streamIsActive(container))
							{
								String packedPayload;
								if (ProdigyWire::serializeAdvertisementPairingPayload(
									packedPayload,
									secret,
									address,
									service,
									applicationID,
									activate) &&
									ProdigyWire::constructPackedFrame(container->wBuffer, ContainerTopic::advertisementPairing, packedPayload))
								{
									Ring::queueSend(container);
								}
							}
							else
							{
								queuePendingPairing(pendingAdvertisementPairings, containerUUID, args, terminal);
							}
						}
					}
						else
					{
						queuePendingPairing(pendingAdvertisementPairings, containerUUID, args, terminal);
						basics_log("neuron advertisementPairing missing containerUUID=%llu payloadBytes=%u\n",
							(unsigned long long)containerUUID,
							unsigned(payloadBytes));
					}

				break;
			}
				case NeuronTopic::subscriptionPairing:
				{
				// containerUUID(16) secret(16) address(16) service(8) port(2) applicationID(2) activate(1)

				uint128_t containerUUID = 0;
				Message::extractArg<ArgumentNature::fixed>(args, containerUUID);

				if (args > terminal)
				{
					basics_log("neuron subscriptionPairing malformed bounds args=%p terminal=%p\n", args, terminal);
					break;
				}

				uint32_t payloadBytes = uint32_t(terminal - args);
				uint128_t secret = 0;
				uint128_t address = 0;
				uint64_t service = 0;
				uint16_t port = 0;
				uint16_t applicationID = 0;
				bool activate = false;
				if (ProdigyWire::deserializeSubscriptionPairingPayloadAuto(
					args,
					uint64_t(terminal - args),
					secret,
					address,
					service,
					port,
					applicationID,
					activate) == false)
				{
					basics_log("neuron subscriptionPairing malformed payload containerUUID=%llu payloadBytes=%u\n",
						(unsigned long long)containerUUID,
						unsigned(payloadBytes));
					break;
				}

					if (auto it = containers.find(containerUUID); it != containers.end())
					{
						Container *container = it->second;
						if (container->pendingDestroy)
						{
							basics_log("neuron subscriptionPairing skip pendingDestroy containerUUID=%llu payloadBytes=%u\n",
								(unsigned long long)containerUUID,
								unsigned(payloadBytes));
							break;
							}

							bool changed = container->plan.applySubscriptionPairing(SubscriptionPairing(secret, address, service, port), activate);
							basics_log("neuron subscriptionPairing apply containerUUID=%llu payloadBytes=%u streamActive=%d\n",
								(unsigned long long)containerUUID,
								unsigned(payloadBytes),
							int(streamIsActive(container)));

						if (changed)
						{
							if (streamIsActive(container))
							{
								String packedPayload;
								if (ProdigyWire::serializeSubscriptionPairingPayload(
									packedPayload,
									secret,
									address,
									service,
									port,
									applicationID,
									activate) &&
									ProdigyWire::constructPackedFrame(container->wBuffer, ContainerTopic::subscriptionPairing, packedPayload))
								{
									Ring::queueSend(container);
								}
							}
							else
							{
								queuePendingPairing(pendingSubscriptionPairings, containerUUID, args, terminal);
							}
						}
					}
						else
					{
						queuePendingPairing(pendingSubscriptionPairings, containerUUID, args, terminal);
						basics_log("neuron subscriptionPairing missing containerUUID=%llu payloadBytes=%u\n",
							(unsigned long long)containerUUID,
							unsigned(payloadBytes));
					}

				break;
			}
			case NeuronTopic::refreshContainerCredentials:
			{
				uint128_t containerUUID = 0;
				Message::extractArg<ArgumentNature::fixed>(args, containerUUID);

				String serializedDelta;
				Message::extractToStringView(args, serializedDelta);
				CredentialDelta delta;
				if (ProdigyWire::deserializeCredentialDeltaAuto(serializedDelta, delta) == false)
				{
					basics_log("neuron refreshContainerCredentials malformed delta containerUUID=%llu payloadBytes=%u\n",
						(unsigned long long)containerUUID,
						unsigned(serializedDelta.size()));
					break;
				}

				if (auto it = containers.find(containerUUID); it != containers.end())
				{
					Container *container = it->second;
					if (container->pendingDestroy)
					{
						basics_log("neuron refreshContainerCredentials skip pendingDestroy containerUUID=%llu payloadBytes=%u\n",
							(unsigned long long)containerUUID,
							unsigned(serializedDelta.size()));
						break;
					}

					container->plan.hasCredentialBundle = true;
					applyCredentialDelta(container->plan.credentialBundle, delta);

					if (streamIsActive(container))
					{
						if (ProdigyWire::constructPackedFrame(container->wBuffer, ContainerTopic::credentialsRefresh, serializedDelta))
						{
							Ring::queueSend(container);
						}
					}
					else
					{
						queuePendingPayload(pendingCredentialRefreshes, containerUUID, pendingCredentialRefreshLimitPerContainer, serializedDelta);
					}
				}
				else
				{
					queuePendingPayload(pendingCredentialRefreshes, containerUUID, pendingCredentialRefreshLimitPerContainer, serializedDelta);
					basics_log("neuron refreshContainerCredentials missing containerUUID=%llu payloadBytes=%u\n",
						(unsigned long long)containerUUID,
						unsigned(serializedDelta.size()));
				}

				break;
			}
			default: break;
		}
	}

		template <typename T, typename Dispatch>
		void recvHandler(T *stream, int result, Dispatch&& dispatch)
		{
		if constexpr (std::is_same_v<T, Container>)
		{
			ContainerManager::appendContainerTrace(stream,
				"neuron.recv enter result=%d pendingSend=%d pendingRecv=%d outstandingBefore=%llu fd=%d fslot=%d state=%u\n",
				result,
				int(stream->pendingSend),
				int(stream->pendingRecv),
				(unsigned long long)stream->queuedSendOutstandingBytes(),
				stream->fd,
				stream->fslot,
				unsigned(stream->plan.state));
		}
		if (stream->pendingRecv == false)
		{
			// Ignore stale/duplicate recv completions from prior socket generations.
			return;
		}
		stream->pendingRecv = false;

			if (result > 0)
			{
				const uint64_t remaining = stream->rBuffer.remainingCapacity();
				if (uint64_t(result) > remaining)
				{
					basics_log("neuron recv overflow stream=%p isBrain=%d result=%d remaining=%llu fd=%d fslot=%d\n",
						stream,
						int((void *)stream == (void *)brain),
						result,
						(unsigned long long)remaining,
						stream->fd,
						stream->fslot);
					stream->rBuffer.clear();
					queueCloseIfActive(stream);
					return;
				}

				if constexpr (requires (T *s) { s->transportTLSEnabled(); })
				{
					if (stream->transportTLSEnabled())
					{
						if (stream->decryptTransportTLS(uint32_t(result)) == false
							|| ((void *)stream == (void *)brain && verifyBrainTransportTLSPeer() == false))
						{
							stream->rBuffer.clear();
							queueCloseIfActive(stream);
							return;
						}
					}
					else
					{
						stream->rBuffer.advance(result);
					}
				}
				else
				{
					stream->rBuffer.advance(result);
				}

				bool parseFailed = false;
				stream->template extractMessages<Message>([&] (Message *message) -> void {

				dispatch(message);
			}, true, UINT32_MAX, 16, ProdigyWire::maxControlFrameBytes, parseFailed);
			if (parseFailed)
			{
				if constexpr (std::is_same_v<T, Container>)
				{
					ContainerManager::appendContainerTrace(stream,
						"neuron.recv parse-failed outstanding=%llu fd=%d fslot=%d\n",
						(unsigned long long)stream->rBuffer.outstandingBytes(),
						stream->fd,
						stream->fslot);
				}
				uint64_t outstanding = stream->rBuffer.outstandingBytes();
				uint32_t peekSize = 0;
				if (outstanding >= sizeof(uint32_t))
				{
					memcpy(&peekSize, stream->rBuffer.pHead(), sizeof(uint32_t));
				}

				basics_log("neuron recv parse failure stream=%p isBrain=%d outstanding=%llu peekSize=%u fd=%d fslot=%d\n",
					stream,
					int((void *)stream == (void *)brain),
					(unsigned long long)outstanding,
					unsigned(peekSize),
					stream->fd,
					stream->fslot);
				stream->rBuffer.clear();
				queueCloseIfActive(stream);
				return;
			}

			if constexpr (requires (T *s) { s->transportTLSEnabled(); })
			{
				if (stream->transportTLSEnabled()
					&& streamIsActive(stream)
					&& stream->needsTransportTLSSendKick())
				{
					Ring::queueSend(stream);
				}
			}

			if (streamIsActive(stream))
			{
				Ring::queueRecv(stream);
			}
			if constexpr (std::is_same_v<T, Container>)
			{
				ContainerManager::appendContainerTrace(stream,
					"neuron.recv done outstandingAfter=%llu pendingSend=%d pendingRecv=%d fd=%d fslot=%d state=%u\n",
					(unsigned long long)stream->rBuffer.outstandingBytes(),
					int(stream->pendingSend),
					int(stream->pendingRecv),
					stream->fd,
					stream->fslot,
					unsigned(stream->plan.state));
			}
		}
		else
		{
         if constexpr (std::is_same_v<T, Container>)
         {
            ContainerManager::appendContainerTrace(stream,
               "neuron.recv terminal result=%d pendingSend=%d pendingRecv=%d fd=%d fslot=%d state=%u\n",
               result,
               int(stream->pendingSend),
               int(stream->pendingRecv),
               stream->fd,
               stream->fslot,
               unsigned(stream->plan.state));
            basics_log("neuron recv terminal uuid=%llu deploymentID=%llu appID=%u result=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d state=%u\n",
               (unsigned long long)stream->plan.uuid,
               (unsigned long long)stream->plan.config.deploymentID(),
               unsigned(stream->plan.config.applicationID),
               result,
               stream->fd,
               stream->fslot,
               int(stream->pendingSend),
               int(stream->pendingRecv),
               unsigned(stream->plan.state));
         }
			queueCloseIfActive(stream);
		}
	}

		void recvHandler(void *socket, int result) override
		{
			verboseNeuronSocketLog("neuron recvHandler socket=%p brain=%p result=%d\n", socket, brain, result);
		if (socket == (void *)brain)
		{
			recvHandler(brain, result, [&] (Message *message) -> void {

				neuronHandler(message);
			});
		}
			else
			{
				Container *container = static_cast<Container *>(socket);
				if (isTrackedContainerSocket(socket) == false)
				{
					return;
				}
				if (container->pendingDestroy)
				{
					return;
				}

				recvHandler(container, result, [&] (Message *message) -> void {

					containerHandler(container, message);
				});
		}
	}

		template <typename T>
		void sendHandler(T *stream, int result)
		{
			if constexpr (std::is_same_v<T, Container>)
			{
				ContainerManager::appendContainerTrace(stream,
					"neuron.send enter result=%d pendingSend=%d pendingRecv=%d pendingSendBytes=%u outstandingBefore=%llu isFixed=%d fd=%d fslot=%d registeredFD=%d state=%u\n",
					result,
					int(stream->pendingSend),
					int(stream->pendingRecv),
					unsigned(stream->pendingSendBytes),
					(unsigned long long)stream->queuedSendOutstandingBytes(),
					int(stream->isFixedFile),
					stream->fd,
					stream->fslot,
					(stream->isFixedFile && stream->fslot >= 0 ? Ring::getFDFromFixedFileSlot(stream->fslot) : stream->fd),
					unsigned(stream->plan.state));
			}
			if (stream->pendingSend == false)
			{
				// Ignore stale/duplicate send completions from prior socket generations.
				return;
			}

			stream->pendingSend = false;
			uint32_t submittedBytes = stream->pendingSendBytes;
			stream->pendingSendBytes = 0;

			if (result > 0)
			{
				if (submittedBytes == 0 || uint32_t(result) > submittedBytes)
				{
					const uint64_t outstanding = stream->queuedSendOutstandingBytes();
					basics_log("neuron send overflow stream=%p isBrain=%d result=%d outstanding=%llu fd=%d fslot=%d\n",
						stream,
						int((void *)stream == (void *)brain),
						result,
						(unsigned long long)outstanding,
						stream->fd,
						stream->fslot);
					if constexpr (std::is_same_v<T, Container>)
					{
						ContainerManager::appendContainerTrace(stream,
							"neuron.send overflow result=%d outstanding=%llu fd=%d fslot=%d\n",
							result,
							(unsigned long long)outstanding,
							stream->fd,
							stream->fslot);
					}
					stream->noteSendCompleted();
					stream->clearQueuedSendBytes();
					queueCloseIfActive(stream);
					return;
				}

				stream->consumeSentBytes(uint32_t(result), false);
				stream->noteSendCompleted();

			bool queueAnotherSend = (stream->wBuffer.outstandingBytes() > 0);
			if constexpr (requires (T *s) { s->transportTLSEnabled(); })
			{
				if (stream->transportTLSEnabled() && stream->needsTransportTLSSendKick())
				{
					queueAnotherSend = true;
				}
			}

			if (queueAnotherSend && streamIsActive(stream))
			{
				Ring::queueSend(stream);
			}

			int tlsNegotiated = 0;
			int needsSendKick = 0;
			if constexpr (requires (T *s) { s->isTLSNegotiated(); s->needsTransportTLSSendKick(); })
			{
				tlsNegotiated = int(stream->isTLSNegotiated());
				needsSendKick = int(stream->needsTransportTLSSendKick());
			}

			verboseNeuronSocketLog("neuron send complete stream=%p isBrain=%d result=%d active=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d needsSendKick=%d wbytes=%u queued=%llu fd=%d fslot=%d\n",
				stream,
				int((void *)stream == (void *)brain),
				result,
				int(streamIsActive(stream)),
				int(stream->pendingSend),
				int(stream->pendingRecv),
				tlsNegotiated,
				needsSendKick,
				unsigned(stream->wBuffer.size()),
				(unsigned long long)stream->queuedSendOutstandingBytes(),
				stream->fd,
				stream->fslot);
			if constexpr (std::is_same_v<T, Container>)
			{
				ContainerManager::appendContainerTrace(stream,
					"neuron.send done result=%d pendingSend=%d pendingRecv=%d outstandingAfter=%llu isFixed=%d fd=%d fslot=%d registeredFD=%d state=%u\n",
					result,
					int(stream->pendingSend),
					int(stream->pendingRecv),
					(unsigned long long)stream->queuedSendOutstandingBytes(),
					int(stream->isFixedFile),
					stream->fd,
					stream->fslot,
					(stream->isFixedFile && stream->fslot >= 0 ? Ring::getFDFromFixedFileSlot(stream->fslot) : stream->fd),
					unsigned(stream->plan.state));
			}
			}
			else
			{
				stream->noteSendCompleted();
				// Do not replay partial frame tails after reconnect.
				stream->clearQueuedSendBytes();
				queueCloseIfActive(stream);
			}
		}

		void sendHandler(void *socket, int result) override
		{
			if (socket == (void *)brain)
			{
				sendHandler(brain, result);
			}
			else
			{
				Container *container = static_cast<Container *>(socket);
				if (isTrackedContainerSocket(socket) == false)
				{
					return;
				}
				if (container->pendingDestroy)
				{
					if (container->pendingSend)
					{
						container->wBuffer.noteSendCompleted();
					}
					container->pendingSend = false;
					container->pendingSendBytes = 0;
					container->wBuffer.clear();
					return;
				}

				sendHandler(container, result);
			}
		}

		void acceptHandler(void *socket, int fslot) override
		{
			verboseNeuronSocketLog("neuron acceptHandler listener=%p fslot=%d\n", socket, fslot);
			if (fslot >= 0)
	  		{
	  			if (brain != nullptr)
	  			{
	  				// Only one controlling brain stream is valid at a time. If the
	  				// current slot is already closing or stale, retire it and allow the
	  				// replacement accept to take over immediately.
	  				if (rawStreamIsActive(brain))
	  				{
	  					Ring::queueCloseRaw(fslot);
	  					return;
	  				}

	  				delete brain;
	  				brain = nullptr;
	  			}

	  			brain = new NeuronBrainControlStream();
	  			brain->connected = true;
	  			brain->rBuffer.reserve(8_KB);
	  			brain->wBuffer.reserve(16_KB);
				basics_log("neuron accepted brain control fslot=%d tlsConfigured=%d\n",
					fslot,
					int(ProdigyTransportTLSRuntime::configured()));

				// Accept-direct returns a fixed-file slot. Configure accepted TCP tuning
				// through io_uring socket commands and keep the steady-state path fixed-file only.
	  			brain->fslot = fslot;
	  			brain->isFixedFile = true;
				brain->isNonBlocking = true;
				Ring::queueSetSockOptRaw(brain, SOL_TCP, TCP_CONGESTION, "dctcp", socklen_t(strlen("dctcp")), "neuron accepted brain control congestion");
				Ring::queueSetSockOptInt(brain, SOL_SOCKET, SO_KEEPALIVE, 1, "neuron accepted brain control keepalive");
				Ring::queueSetSockOptInt(brain, SOL_TCP, TCP_KEEPIDLE, int(std::max<uint32_t>(brainControlKeepaliveSeconds, 1u)), "neuron accepted brain control keepidle");
				Ring::queueSetSockOptInt(brain, SOL_TCP, TCP_KEEPINTVL, int(std::max<uint32_t>(brainControlKeepaliveSeconds / 3, 1u)), "neuron accepted brain control keepintvl");
				Ring::queueSetSockOptInt(brain, SOL_TCP, TCP_KEEPCNT, 3, "neuron accepted brain control keepcnt");
				basics_log("neuron accepted brain control stream=%p fd=%d fslot=%d\n",
					static_cast<void *>(brain),
					brain->fd,
					brain->fslot);

				if (ProdigyTransportTLSRuntime::configured() && beginAcceptedBrainTransportTLS(brain) == false)
				{
					queueCloseIfActive(brain);
					return;
				}

	  			RingDispatcher::installMultiplexee(brain, this);
				const uint8_t recvGenerationBefore = brain->ioGeneration;
		      Ring::queueRecv(brain);
				basics_log("neuron accepted brain control recv-arm stream=%p fd=%d fslot=%d pendingSend=%d pendingRecv=%d tagBefore=%u tagAfter=%u rcap=%llu\n",
					static_cast<void *>(brain),
					brain->fd,
					brain->fslot,
					int(brain->pendingSend),
					int(brain->pendingRecv),
					unsigned(recvGenerationBefore),
					unsigned(brain->ioGeneration),
					(unsigned long long)brain->rBuffer.remainingCapacity());

	      brain->initialMachineHardwareProfileQueued = false;
	      appendInitialBrainControlFrames(brain->wBuffer);

	      for (const auto& [deploymentID, coros] : pendingContainerDownloads)
	      {
	      	(void)coros;
	      	Message::construct(brain->wBuffer, NeuronTopic::requestContainerBlob, deploymentID);
	      }

         (void)queueMachineHardwareProfileToBrainIfReady("brain-control-accept");
         (void)appendHealthyContainerFrames(brain->wBuffer);

	      if (streamIsActive(brain))
	      {
            if (brain->pendingSend == false)
            {
               Ring::queueSend(brain);
            }
	         verboseNeuronSocketLog("neuron accepted brain control send-arm fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d needsSendKick=%d wbytes=%u queued=%llu\n",
	            brain->fd,
	            brain->fslot,
	            int(brain->pendingSend),
	            int(brain->pendingRecv),
	            int(brain->isTLSNegotiated()),
	            int(brain->needsTransportTLSSendKick()),
	            unsigned(brain->wBuffer.size()),
	            (unsigned long long)brain->queuedSendOutstandingBytes());

				// The initial TLS/registration exchange is queued from inside the accept
				// completion handler. Submit those SQEs immediately so the master brain
				// can make progress without waiting for a later loop iteration.
				Ring::submitPending();
	      }
	   }
	   else queueBrainAccept();
		}

      void pollHandler(void *socket, int result) override
      {
         if (socket == (void *)&deferredHardwareInventoryWake)
         {
            deferredHardwareInventoryWakePollQueued = false;
            if (result != -ECANCELED)
            {
               drainDeferredHardwareInventoryWake();
               (void)completeDeferredHardwareInventoryIfReady();
               armDeferredHardwareInventoryWakePoll();
            }
            return;
         }
      }

			void closeHandler(void *socket) override
			{
			if (socket == (void *)brain)
			{
			// maybe the brain failed?
			// also possible we got cut off network wise?
			// it will reconnect to us
			basics_log("neuron brain control closed stream=%p fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d\n",
				static_cast<void *>(brain),
				brain->fd,
				brain->fslot,
				int(brain->pendingSend),
				int(brain->pendingRecv),
				int(brain->isTLSNegotiated()),
				int(brain->tlsPeerVerified));

				delete brain;
				brain = nullptr;
				queueBrainAccept();
					}
					else // container
					{
						if (isTrackedContainerSocket(socket) == false)
						{
							return;
						}
						Container *container = static_cast<Container *>(socket);
						if (container->pendingDestroy)
						{
							ContainerManager::finalizeContainerDestroy(container);
							return;
						}

						basics_log("neuron container socket closed uuid=%llu pid=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d\n",
							(unsigned long long)container->plan.uuid,
							int(container->pid),
							container->fd,
							container->fslot,
							int(container->pendingSend),
							int(container->pendingRecv));

						bool processAlive = false;
						if (container->pid > 0 && kill(container->pid, 0) == 0)
						{
							processAlive = true;
						}

						if (processAlive)
						{
							// The initial container control path can start as a unix socketpair,
							// but once the process is live the stable reconnect endpoint is the
							// container-local /neuron.soc listener. Reconnect through that
							// addressful socket for both pair-backed and non-pair streams.
							String path;
							path.snprintf<"/containers/{}/neuron.soc"_ctv>(container->name);
							container->setSocketPath(path.c_str());
							container->recreateSocket();
							Ring::installFDIntoFixedFileSlot(container);
							if (container->isFixedFile && container->fslot >= 0)
							{
								Ring::queueConnect(container);
							}
						}
					}
		}

		void connectHandler(void *socket, int result) override
		{
			if (socket == (void *)brain)
			{
				return;
			}

			if (isTrackedContainerSocket(socket) == false)
			{
				return;
			}

			Container *container = static_cast<Container *>(socket);
			if (container->pendingDestroy)
			{
				return;
			}

			if (result == 0)
			{
				if (streamIsActive(container) == false)
				{
					return;
				}

				if (container->pendingRecv == false)
				{
					Ring::queueRecv(container);
				}

				if (container->wBuffer.size() > 0 && container->pendingSend == false)
				{
					Ring::queueSend(container);
				}
			}
			else
			{
				basics_log("neuron container connect failed uuid=%llu result=%d fd=%d fslot=%d\n",
					(unsigned long long)container->plan.uuid,
					result,
					container->fd,
					container->fslot);
				queueCloseIfActive(container);
			}
		}

	void timeoutHandler(TimeoutPacket *packet, int result) override // the pointer always exists here
   {
      if (packet == nullptr)
      {
         return;
      }

      if (packet == &metricsTick)
      {
         metricsTickQueued = false;
      }
      else if (packet == &failedContainerArtifactGCTick)
      {
         failedContainerArtifactGCTickQueued = false;
      }

      if (result == -ECANCELED)
      {
         if (packet == &metricsTick)
         {
            return;
         }
         if (packet == &failedContainerArtifactGCTick)
         {
            return;
         }

         if (NeuronTimeoutFlags(packet->flags) == NeuronTimeoutFlags::killContainer)
         {
            if (auto it = containers.find(packet->identifier); it != containers.end())
            {
               if (it->second->killSwitch == packet)
               {
                  it->second->killSwitch = nullptr;
               }
            }
         }

         delete packet;
         return;
      }

	   	switch (NeuronTimeoutFlags(packet->flags))
	   	{
	   		case NeuronTimeoutFlags::killContainer:
	   		{
	   			if (auto it = containers.find(packet->identifier); it != containers.end())
					{
						Container *container = it->second;
						container->killSwitch = nullptr;
						kill(container->pid, SIGKILL);
					}

					delete packet;

	   			break;
	   		}
            case NeuronTimeoutFlags::metricsTick:
            {
               uint64_t sampleTimeNs = monotonicNowNs();
               if (sampleTimeNs > 0)
               {
                  collectContainerMetricsAndForward(sampleTimeNs);
               }

               ensureMetricsTickQueued();
               break;
            }
            case NeuronTimeoutFlags::logGC:
            {
               cleanupExpiredFailedContainerArtifacts();
               ensureFailedContainerArtifactGCTickQueued();
               break;
            }
	   		default: break;
	   	}
   }

	   void pushContainer(Container *container) override
	   {
	      containers.insert_or_assign(container->plan.uuid, container);
	      containerByPid.insert_or_assign(container->pid, container);

         if (container->plan.wormholes.empty() == false)
         {
            // Wormhole egress bindings depend on the live container map so the
            // local peer egress program can be discovered on the real host.
            refreshContainerSwitchboardWormholes(container);
         }

	      RingDispatcher::installMultiplexee(container, this);
	      Ring::installFDIntoFixedFileSlot(container);
	      if (container->isFixedFile == false || container->fslot < 0)
	      {
	         basics_log("neuron pushContainer failed to install fixed slot uuid=%llu fd=%d fslot=%d\n",
	            (unsigned long long)container->plan.uuid, container->fd, container->fslot);
	         std::abort();
	      }

	      applyPendingPairings(container);
	      applyPendingCredentialRefreshes(container);
         ensureMetricsTickQueued();
	   }

	   void popContainer(Container *container) override
	   {
	      containers.erase(container->plan.uuid);
	      containerByPid.erase(container->pid);
	      pendingAdvertisementPairings.erase(container->plan.uuid);
	      pendingSubscriptionPairings.erase(container->plan.uuid);
	      pendingCredentialRefreshes.erase(container->plan.uuid);
         metricSampleStateByContainer.erase(container->plan.uuid);

	      RingDispatcher::eraseMultiplexee(container);
	   }
};
