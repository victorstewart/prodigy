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
#include <dirent.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <spawn.h>
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

class NeuronBrainControlStream : public RingInterface, public ProdigyTransportTLSStream {
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

  class OSUpdateProcess : public SocketBase {
  public:

    pid_t pid = -1;
    bool active = false;
    bool pollQueued = false;
    String targetOSID;
    String targetOSVersionID;
  };

  struct LocalWhiteholeBindingEntry {

    portal_definition key = {};
    switchboard_whitehole_binding value = {};

    bool equals(const LocalWhiteholeBindingEntry& rhs) const
    {
      return switchboardPortalDefinitionEquals(key, rhs.key) && switchboardWhiteholeBindingEquals(value, rhs.value);
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
  ProdigyOverlayPresenceMirror<switchboard_overlay_prefix4_key> installedIngressOverlayPrefixes4;
  ProdigyOverlayPresenceMirror<switchboard_overlay_prefix6_key> installedIngressOverlayPrefixes6;
  ProdigyOverlayValueMirror<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route> installedIngressOverlayRouteKeysFull;
  ProdigyOverlayValueMirror<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route> installedIngressOverlayRouteKeysLow8;
  ProdigyOverlayValueMirror<switchboard_overlay_prefix4_key, switchboard_overlay_hosted_ingress_route4> installedIngressHostedIngressRouteKeys4;
  ProdigyOverlayValueMirror<switchboard_overlay_prefix6_key, switchboard_overlay_hosted_ingress_route6> installedIngressHostedIngressRouteKeys6;
  ProdigyOverlayPresenceMirror<switchboard_overlay_prefix4_key> installedEgressOverlayPrefixes4;
  ProdigyOverlayPresenceMirror<switchboard_overlay_prefix6_key> installedEgressOverlayPrefixes6;
  ProdigyOverlayValueMirror<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route> installedOverlayRouteKeysFull;
  ProdigyOverlayValueMirror<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route> installedOverlayRouteKeysLow8;
  ProdigyOverlayValueMirror<switchboard_overlay_prefix4_key, switchboard_overlay_hosted_ingress_route4> installedHostedIngressRouteKeys4;
  ProdigyOverlayValueMirror<switchboard_overlay_prefix6_key, switchboard_overlay_hosted_ingress_route6> installedHostedIngressRouteKeys6;
  ProdigyOverlayPresenceMirror<switchboard_overlay_prefix4_key> installedBalancerOverlayPrefixes4;
  ProdigyOverlayPresenceMirror<switchboard_overlay_prefix6_key> installedBalancerOverlayPrefixes6;
  ProdigyOverlayValueMirror<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route> installedBalancerOverlayRouteKeysFull;
  ProdigyOverlayValueMirror<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route> installedBalancerOverlayRouteKeysLow8;
  ProdigyOverlayValueMirror<switchboard_overlay_prefix4_key, switchboard_overlay_hosted_ingress_route4> installedBalancerHostedIngressRouteKeys4;
  ProdigyOverlayValueMirror<switchboard_overlay_prefix6_key, switchboard_overlay_hosted_ingress_route6> installedBalancerHostedIngressRouteKeys6;
  ProdigyOverlayValueMirror<portal_definition, switchboard_whitehole_binding> installedEgressWhiteholeBindingKeys;
  bytell_hash_subvector<uint32_t, LocalWhiteholeBindingEntry> whiteholeBindingsByContainer;
  bytell_hash_subvector<uint64_t, CoroutineStack *> pendingContainerDownloads;
  bytell_hash_map<uint128_t, Vector<String>> pendingAdvertisementPairings;
  bytell_hash_map<uint128_t, Vector<String>> pendingSubscriptionPairings;
  bytell_hash_map<uint128_t, Vector<String>> pendingCredentialRefreshes;
  bytell_hash_map<uint128_t, TaskAttemptJournalRecord> taskAttemptJournal;
  constexpr static uint32_t pendingPairingLimitPerContainer = 128;
  constexpr static uint32_t pendingCredentialRefreshLimitPerContainer = 128;
  constexpr static uint64_t pulseBatteryPassMetricKey = 0x50554C5345504151ULL; // "PULSEPAQ"
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
    (void)queueMachineHardwareProfileToBrainIfReady("ensure-progress");
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

  static String taskAttemptJournalRoot(void)
  {
    if (const char *root = getenv("PRODIGY_TASK_ATTEMPT_JOURNAL_ROOT"); root && root[0])
    {
      String path = {};
      path.assign(root);
      return path;
    }
    return "/var/lib/prodigy/task-attempts"_ctv;
  }

  static String taskAttemptJournalPath(uint64_t deploymentID, uint32_t attemptNumber)
  {
    String path = taskAttemptJournalRoot();
    if (path.size() == 0 || path[path.size() - 1] != '/')
    {
      path.append('/');
    }
    String leaf = {};
    leaf.snprintf<"{itoa}-{itoa}.bin"_ctv>(deploymentID, uint64_t(attemptNumber));
    path.append(leaf);
    return path;
  }

  bool persistTaskAttemptJournalRecord(TaskAttemptJournalRecord& record, String *failureReport = nullptr)
  {
    (void)Filesystem::createDirectoryAt(-1, taskAttemptJournalRoot(), 0755);
    String payload = {};
    BitseryEngine::serialize(payload, record);
    return ContainerStore::atomicWriteRuntimeFile(taskAttemptJournalPath(record.deploymentID, record.attemptNumber), payload, failureReport);
  }

  void eraseTaskAttemptJournalRecord(const TaskAttemptJournalRecord& record)
  {
    (void)::unlink(taskAttemptJournalPath(record.deploymentID, record.attemptNumber).c_str());
  }

  void pruneExpiredTaskAttemptJournalRecords(int64_t nowMs)
  {
    for (auto it = taskAttemptJournal.begin(); it != taskAttemptJournal.end();)
    {
      if (it->second.expired(nowMs))
      {
        eraseTaskAttemptJournalRecord(it->second);
        it = taskAttemptJournal.erase(it);
      }
      else
      {
        ++it;
      }
    }
  }

  void loadTaskAttemptJournal(void)
  {
    taskAttemptJournal.clear();
    String root = taskAttemptJournalRoot();
    int fd = Filesystem::openDirectoryAt(-1, root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
    {
      return;
    }

    DIR *dir = fdopendir(fd);
    if (dir == nullptr)
    {
      close(fd);
      return;
    }

    while (struct dirent *entry = readdir(dir))
    {
      if (entry->d_name[0] == '.')
      {
        continue;
      }

      String path = root;
      if (path.size() == 0 || path[path.size() - 1] != '/')
      {
        path.append('/');
      }
      path.append(entry->d_name);
      String payload = {};
      Filesystem::openReadAtClose(-1, path, payload);
      TaskAttemptJournalRecord record = {};
      if (payload.size() > 0 && BitseryEngine::deserializeSafe(payload, record) && record.deploymentID > 0 && record.attemptNumber > 0)
      {
        taskAttemptJournal.insert_or_assign(record.key(), record);
      }
    }
    closedir(dir);
    pruneExpiredTaskAttemptJournalRecords(Time::now<TimeResolution::ms>());
  }

  void replayTerminalTaskAttemptJournal(void)
  {
    pruneExpiredTaskAttemptJournalRecords(Time::now<TimeResolution::ms>());
    for (const auto& [key, record] : taskAttemptJournal)
    {
      (void)key;
      if (record.terminalOutbox())
      {
        reportTaskAttemptTerminal(record.deploymentID, record.attemptNumber, record.containerUUID, record.termination);
      }
    }
  }

  bool prepareTaskAttemptLaunch(const ContainerPlan& plan, bool& skipLaunch, String *failureReport = nullptr) override
  {
    skipLaunch = false;
    if (plan.config.type != ApplicationType::task)
    {
      return true;
    }

    const uint64_t deploymentID = plan.config.deploymentID();
    const uint32_t attemptNumber = plan.taskAttemptNumber;
    if (deploymentID == 0 || attemptNumber == 0)
    {
      if (failureReport)
      {
        failureReport->assign("task launch missing deployment or attempt id"_ctv);
      }
      return false;
    }

    const int64_t nowMs = Time::now<TimeResolution::ms>();
    pruneExpiredTaskAttemptJournalRecords(nowMs);
    auto key = prodigyTaskAttemptJournalKey(deploymentID, attemptNumber);
    if (auto it = taskAttemptJournal.find(key); it != taskAttemptJournal.end())
    {
      TaskAttemptJournalRecord& record = it->second;
      skipLaunch = true;
      if (record.terminalOutbox())
      {
        reportTaskAttemptTerminal(record.deploymentID, record.attemptNumber, record.containerUUID, record.termination);
      }
      else if (record.state != TaskAttemptJournalState::acknowledged && containers.contains(record.containerUUID) == false)
      {
        record.state = TaskAttemptJournalState::terminal;
        record.updatedAtMs = nowMs;
        record.expiresAtMs = 0;
        record.hasTermination = true;
        record.termination = {};
        record.termination.kind = TaskTerminationKind::lost;
        record.termination.observedAtMs = nowMs;
        record.termination.summary.assign("lost before duplicate task launch"_ctv);
        if (persistTaskAttemptJournalRecord(record, failureReport) == false)
        {
          return false;
        }
        reportTaskAttemptTerminal(record.deploymentID, record.attemptNumber, record.containerUUID, record.termination);
      }
      return true;
    }

    TaskAttemptJournalRecord record = {};
    record.deploymentID = deploymentID;
    record.attemptNumber = attemptNumber;
    record.containerUUID = plan.uuid;
    record.state = TaskAttemptJournalState::accepted;
    record.updatedAtMs = nowMs;
    if (persistTaskAttemptJournalRecord(record, failureReport) == false)
    {
      return false;
    }
    taskAttemptJournal.insert_or_assign(record.key(), record);
    return true;
  }

  void noteTaskAttemptRunning(const ContainerPlan& plan) override
  {
    if (plan.config.type != ApplicationType::task || plan.taskAttemptNumber == 0)
    {
      return;
    }

    TaskAttemptJournalRecord& record = taskAttemptJournal[prodigyTaskAttemptJournalKey(plan.config.deploymentID(), plan.taskAttemptNumber)];
    record.deploymentID = plan.config.deploymentID();
    record.attemptNumber = plan.taskAttemptNumber;
    record.containerUUID = plan.uuid;
    record.state = TaskAttemptJournalState::running;
    record.updatedAtMs = Time::now<TimeResolution::ms>();
    record.expiresAtMs = 0;
    record.hasTermination = false;
    record.termination = {};
    String ignored = {};
    (void)persistTaskAttemptJournalRecord(record, &ignored);
  }

  bool noteTaskAttemptTerminal(const ContainerPlan& plan, const TaskTermination& termination) override
  {
    if (plan.config.type != ApplicationType::task || plan.taskAttemptNumber == 0)
    {
      return true;
    }

    TaskAttemptJournalRecord& record = taskAttemptJournal[prodigyTaskAttemptJournalKey(plan.config.deploymentID(), plan.taskAttemptNumber)];
    record.deploymentID = plan.config.deploymentID();
    record.attemptNumber = plan.taskAttemptNumber;
    record.containerUUID = plan.uuid;
    record.state = TaskAttemptJournalState::terminal;
    record.updatedAtMs = termination.observedAtMs ? termination.observedAtMs : Time::now<TimeResolution::ms>();
    record.expiresAtMs = 0;
    record.hasTermination = true;
    record.termination = termination;

    String failure = {};
    if (persistTaskAttemptJournalRecord(record, &failure) == false)
    {
      basics_log("task terminal journal persist failed deploymentID=%llu attempt=%u reason=%s\n",
                 (unsigned long long)record.deploymentID,
                 unsigned(record.attemptNumber),
                 failure.c_str());
      return false;
    }

    reportTaskAttemptTerminal(record.deploymentID, record.attemptNumber, record.containerUUID, record.termination);
    return true;
  }

  void acknowledgeTaskAttemptTerminal(uint64_t deploymentID, uint32_t attemptNumber)
  {
    auto it = taskAttemptJournal.find(prodigyTaskAttemptJournalKey(deploymentID, attemptNumber));
    if (it == taskAttemptJournal.end())
    {
      return;
    }

    TaskAttemptJournalRecord& record = it->second;
    int64_t nowMs = Time::now<TimeResolution::ms>();
    record.state = TaskAttemptJournalState::acknowledged;
    record.updatedAtMs = nowMs;
    record.expiresAtMs = nowMs + prodigyTaskExecutionRecordRetentionMs;
    record.hasTermination = false;
    record.termination = {};
    String ignored = {};
    (void)persistTaskAttemptJournalRecord(record, &ignored);
    pruneExpiredTaskAttemptJournalRecords(nowMs);
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

    if constexpr (requires (T *value) { value->connected; })
    {
      return stream->connected;
    }

    return true;
  }

  template <typename T>
  static void queueCloseIfActive(T *stream)
  {
    if (rawStreamIsActive(stream) == false || Ring::socketIsClosing(stream))
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

  void syncSwitchboardBalancerOverlayRoutingProgram(void)
  {
    if (switchboard == nullptr)
    {
      return;
    }

    prodigySyncOverlayEgressRoutingProgram(switchboard->boundaryRouterProgram(),
                                           overlayRoutingConfig,
                                           installedBalancerOverlayPrefixes4,
                                           installedBalancerOverlayPrefixes6,
                                           installedBalancerOverlayRouteKeysFull,
                                           installedBalancerOverlayRouteKeysLow8,
                                           installedBalancerHostedIngressRouteKeys4,
                                           installedBalancerHostedIngressRouteKeys6);
  }

  void syncOverlayRoutingPrograms(void)
  {
    prodigySyncOverlayEgressRoutingProgram(tcx_ingress_program,
                                           overlayRoutingConfig,
                                           installedIngressOverlayPrefixes4,
                                           installedIngressOverlayPrefixes6,
                                           installedIngressOverlayRouteKeysFull,
                                           installedIngressOverlayRouteKeysLow8,
                                           installedIngressHostedIngressRouteKeys4,
                                           installedIngressHostedIngressRouteKeys6);

    prodigySyncOverlayEgressRoutingProgram(tcx_egress_program,
                                           overlayRoutingConfig,
                                           installedEgressOverlayPrefixes4,
                                           installedEgressOverlayPrefixes6,
                                           installedOverlayRouteKeysFull,
                                           installedOverlayRouteKeysLow8,
                                           installedHostedIngressRouteKeys4,
                                           installedHostedIngressRouteKeys6);

    syncSwitchboardBalancerOverlayRoutingProgram();
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

    prodigySyncOverlayValueMap(tcx_egress_program,
                               "whiteholes"_ctv,
                               installedEgressWhiteholeBindingKeys,
                               desiredBindings,
                               prodigyPortalDefinitionLess,
                               switchboardWhiteholeBindingEquals);
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

    if (Container *container = findTrackedContainerByLocalID(containerID))
    {
      container->syncPeerWhiteholeBindingsFrom(whiteholes);
    }
  }

  void closeLocalWhiteholesToContainer(uint32_t containerID)
  {
    if (Container *container = findTrackedContainerByLocalID(containerID))
    {
      container->clearPeerWhiteholeBindings();
    }

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
      std::fprintf(stderr,
                   "neuron brain tls-verify missing-peer-uuid fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d\n",
                   brain->fd,
                   brain->fslot,
                   int(brain->pendingSend),
                   int(brain->pendingRecv),
                   int(brain->isTLSNegotiated()));
      std::fflush(stderr);
      return false;
    }

    brain->tlsPeerUUID = peerUUID;
    brain->tlsPeerVerified = true;
    basics_log("neuron brain transport tls peer verified fd=%d fslot=%d\n", brain->fd, brain->fslot);
    std::fprintf(stderr,
                 "neuron brain tls-verify ok peerUUID=%llu fd=%d fslot=%d pendingSend=%d pendingRecv=%d queued=%llu\n",
                 (unsigned long long)peerUUID,
                 brain->fd,
                 brain->fslot,
                 int(brain->pendingSend),
                 int(brain->pendingRecv),
                 (unsigned long long)brain->queuedSendOutstandingBytes());
    std::fflush(stderr);
    (void)queueMachineHardwareProfileToBrainIfReady("transport-tls-peer-verified");
    return true;
  }

  void destroyRetiredBrainControlStream(NeuronBrainControlStream *stream)
  {
    if (stream == nullptr)
    {
      return;
    }

    closingBrainControls.erase(stream);
    RingDispatcher::eraseMultiplexee(stream);
    delete stream;
  }

  void destroyRetiredBrainControlStreamIfDrained(NeuronBrainControlStream *stream)
  {
    if (stream == nullptr || closingBrainControls.contains(stream) == false)
    {
      return;
    }

    if (Ring::socketIsClosing(stream) || rawStreamIsActive(stream) || stream->pendingSend || stream->pendingRecv)
    {
      return;
    }

    destroyRetiredBrainControlStream(stream);
  }

  void retireBrainControlStream(NeuronBrainControlStream *stream, const char *reason = nullptr)
  {
    if (stream == nullptr)
    {
      return;
    }

    if (stream == brain)
    {
      brain = nullptr;
    }

    // Keep replaced brain-control stream objects alive until their own close CQE
    // lands. Deleting them early lets stale close completions race with allocator
    // reuse and tear down the replacement control stream instead.
    bool awaitingCloseCompletion =
        Ring::socketIsClosing(stream) || rawStreamIsActive(stream) || stream->pendingSend || stream->pendingRecv;
    if (awaitingCloseCompletion == false)
    {
      destroyRetiredBrainControlStream(stream);
      return;
    }

    if (rawStreamIsActive(stream) && Ring::socketIsClosing(stream) == false)
    {
      queueCloseIfActive(stream);
    }

    closingBrainControls.insert(stream);
    basics_log("neuron retire brain control stream=%p reason=%s closing=%d active=%d pendingSend=%d pendingRecv=%d fd=%d fslot=%d retained=%zu\n",
               static_cast<void *>(stream),
               (reason ? reason : "unknown"),
               int(Ring::socketIsClosing(stream)),
               int(streamIsActive(stream)),
               int(stream->pendingSend),
               int(stream->pendingRecv),
               stream->fd,
               stream->fslot,
               size_t(closingBrainControls.size()));
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

  constexpr static uint64_t collectableScalingDimensionsMask(void)
  {
    return ProdigyMetrics::maskForScalingDimension(ScalingDimension::cpu) | ProdigyMetrics::maskForScalingDimension(ScalingDimension::memory) | ProdigyMetrics::maskForScalingDimension(ScalingDimension::storage);
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
    if (ContainerManager::cleanupExpiredFailedContainerArtifacts(Time::now<TimeResolution::ms>(), &failure) == false && failure.size() > 0)
    {
      basics_log("neuron failed-container artifact gc failed reason=%s\n", failure.c_str());
    }
  }

  static DeferredHardwareInventoryResult collectDeferredHardwareInventoryResult(void)
  {
    DeferredHardwareInventoryResult result = {};
    ProdigyMachineHardwareCollectorOptions hardwareCollectorOptions = {};
    hardwareCollectorOptions.allowLocalCommands = false;
    hardwareCollectorOptions.collectOptionalBenchmarks = false;
    prodigyCollectMachineHardwareProfile(result.hardware, hardwareCollectorOptions);
    serializeMachineHardwareProfileForBrainTransport(result.hardware, result.serializedHardwareProfile);
    return result;
  }

  static void serializeMachineHardwareProfileForBrainTransport(const MachineHardwareProfile& hardware, String& serialized)
  {
    MachineHardwareProfile transportHardware = hardware;
    // The brain only needs the structured hardware inventory for readiness
    // and scheduling. Large per-tool captures stay local so the initial
    // neuron-control frame does not balloon into multi-megabyte transport.
    prodigyStripMachineHardwareCapturesForClusterReport(transportHardware);
    serialized.clear();
    BitseryEngine::serialize(serialized, transportHardware);
  }

  static bool deferredHardwareInventoryResultReadyForAdoption(const DeferredHardwareInventoryResult& result)
  {
    return result.serializedHardwareProfile.size() > 0 && result.hardware.inventoryComplete;
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

    std::fprintf(stderr, "neuron deferred hardware begin wakeFD=%d\n", deferredHardwareInventoryWake.fd);
    std::fflush(stderr);

    std::thread([this]() mutable {
      DeferredHardwareInventoryResult result = {};
      try
      {
        result = collectDeferredHardwareInventoryResult();
      } catch (const std::exception& ex)
      {
        basics_log("Neuron deferred hardware inventory threw exception=%s\n", ex.what());
      } catch (...)
      {
        basics_log("Neuron deferred hardware inventory threw exception=unknown\n");
      }

      std::fprintf(stderr, "neuron deferred hardware collected inventoryComplete=%d serializedBytes=%llu logicalCores=%u memoryMB=%u disks=%llu nics=%llu failure=%s\n",
                   int(result.hardware.inventoryComplete),
                   (unsigned long long)result.serializedHardwareProfile.size(),
                   result.hardware.cpu.logicalCores,
                   result.hardware.memory.totalMB,
                   (unsigned long long)result.hardware.disks.size(),
                   (unsigned long long)result.hardware.network.nics.size(),
                   result.hardware.inventoryFailure.c_str());
      std::fflush(stderr);

      {
        std::lock_guard<std::mutex> lock(deferredHardwareInventoryMutex);
        deferredHardwareInventoryReady = std::move(result);
      }

      if (deferredHardwareInventoryWake.fd >= 0)
      {
        uint64_t signal = 1;
        ssize_t wrote = ::write(deferredHardwareInventoryWake.fd, &signal, sizeof(signal));
        std::fprintf(stderr, "neuron deferred hardware wake-signaled fd=%d wrote=%lld errno=%d(%s)\n",
                     deferredHardwareInventoryWake.fd,
                     (long long)wrote,
                     (wrote < 0 ? errno : 0),
                     (wrote < 0 ? strerror(errno) : "ok"));
        std::fflush(stderr);
      }
      else
      {
        std::fprintf(stderr, "neuron deferred hardware wake-skipped fd=%d\n", deferredHardwareInventoryWake.fd);
        std::fflush(stderr);
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
    Message::construct(outbound, NeuronTopic::registration, bootTimeMs, kernel, osID, osVersionID, haveFragments());
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
    // The deferred inventory worker can finish before its wake poll is
    // drained. If the first queue attempt arrives on a live brain stream,
    // adopt the ready snapshot here so the initial hardware profile does
    // not depend on that wake ordering.
    if (serializedHardwareProfile.size() == 0)
    {
      (void)completeDeferredHardwareInventoryIfReady();
    }

    bool brainPresent = (brain != nullptr);
    bool brainActive = (brainPresent && streamIsActive(brain));
    bool brainAppReady = (brainPresent && brainActive && (brain->transportTLSEnabled() == false || (brain->isTLSNegotiated() && brain->tlsPeerVerified)));
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
    else if (brainPresent && brainAppReady && alreadyQueued == false && serializedHardwareProfile.size() == 0)
    {
      bool deferredReadyPresent = false;
      bool deferredInFlight = false;
      {
        std::lock_guard<std::mutex> lock(deferredHardwareInventoryMutex);
        deferredReadyPresent = (deferredHardwareInventoryReady != std::nullopt);
        deferredInFlight = deferredHardwareInventoryInFlight;
      }

      std::fprintf(stderr, "neuron machineHardwareProfile unavailable reason=%s deferredReady=%d deferredInFlight=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d\n",
                   (reason != nullptr ? reason : ""),
                   int(deferredReadyPresent),
                   int(deferredInFlight),
                   (brainPresent ? brain->fd : -1),
                   (brainPresent ? brain->fslot : -1),
                   int(brainPresent ? brain->pendingSend : 0),
                   int(brainPresent ? brain->pendingRecv : 0),
                   int(brainPresent ? brain->isTLSNegotiated() : 0),
                   int(brainPresent ? brain->tlsPeerVerified : 0));
      std::fflush(stderr);
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
    bool brainPresentBeforeAdopt = (brain != nullptr);
    bool brainActiveBeforeAdopt = (brainPresentBeforeAdopt && streamIsActive(brain));
    std::fprintf(stderr,
                 "neuron deferred hardware adopt-begin inventoryComplete=%d serializedBytes=%llu brainPresent=%d brainActive=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d\n",
                 int(result.hardware.inventoryComplete),
                 (unsigned long long)result.serializedHardwareProfile.size(),
                 int(brainPresentBeforeAdopt),
                 int(brainActiveBeforeAdopt),
                 (brainPresentBeforeAdopt ? brain->fd : -1),
                 (brainPresentBeforeAdopt ? brain->fslot : -1),
                 int(brainPresentBeforeAdopt ? brain->pendingSend : 0),
                 int(brainPresentBeforeAdopt ? brain->pendingRecv : 0),
                 int(brainPresentBeforeAdopt ? brain->isTLSNegotiated() : 0),
                 int(brainPresentBeforeAdopt ? brain->tlsPeerVerified : 0));
    std::fflush(stderr);
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
    std::fprintf(stderr,
                 "neuron deferred hardware adopt-end brainPresent=%d brainActive=%d queued=%d serializedBytes=%llu fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d\n",
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
    std::fflush(stderr);

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
    bool deferredReadyPresent = false;
    bool deferredInFlight = false;

    {
      std::lock_guard<std::mutex> lock(deferredHardwareInventoryMutex);
      deferredReadyPresent = (deferredHardwareInventoryReady != std::nullopt);
      deferredInFlight = deferredHardwareInventoryInFlight;
      if (deferredHardwareInventoryReady == std::nullopt)
      {
        bool completed = (deferredHardwareInventoryInFlight == false);
        std::fprintf(stderr,
                     "neuron deferred hardware complete-skip readyPresent=%d inFlight=%d completed=%d serializedBytes=%llu brainPresent=%d brainActive=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d\n",
                     int(deferredReadyPresent),
                     int(deferredInFlight),
                     int(completed),
                     (unsigned long long)serializedHardwareProfile.size(),
                     int(brain != nullptr),
                     int(brain != nullptr && streamIsActive(brain)),
                     (brain ? brain->fd : -1),
                     (brain ? brain->fslot : -1),
                     int(brain ? brain->pendingSend : 0),
                     int(brain ? brain->pendingRecv : 0),
                     int(brain ? brain->isTLSNegotiated() : 0),
                     int(brain ? brain->tlsPeerVerified : 0));
        std::fflush(stderr);
        return completed;
      }

      ready = std::move(deferredHardwareInventoryReady);
      deferredHardwareInventoryReady.reset();
      deferredHardwareInventoryInFlight = false;
    }

    if (ready == std::nullopt)
    {
      std::fprintf(stderr,
                   "neuron deferred hardware complete-nullopt readyPresent=%d inFlight=%d serializedBytes=%llu brainPresent=%d brainActive=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d\n",
                   int(deferredReadyPresent),
                   int(deferredInFlight),
                   (unsigned long long)serializedHardwareProfile.size(),
                   int(brain != nullptr),
                   int(brain != nullptr && streamIsActive(brain)),
                   (brain ? brain->fd : -1),
                   (brain ? brain->fslot : -1),
                   int(brain ? brain->pendingSend : 0),
                   int(brain ? brain->pendingRecv : 0),
                   int(brain ? brain->isTLSNegotiated() : 0),
                   int(brain ? brain->tlsPeerVerified : 0));
      std::fflush(stderr);
      return true;
    }

    DeferredHardwareInventoryResult result = std::move(*ready);
    std::fprintf(stderr,
                 "neuron deferred hardware complete-ready readyPresent=%d inFlight=%d inventoryComplete=%d serializedBytes=%llu brainPresent=%d brainActive=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d\n",
                 int(deferredReadyPresent),
                 int(deferredInFlight),
                 int(result.hardware.inventoryComplete),
                 (unsigned long long)result.serializedHardwareProfile.size(),
                 int(brain != nullptr),
                 int(brain != nullptr && streamIsActive(brain)),
                 (brain ? brain->fd : -1),
                 (brain ? brain->fslot : -1),
                 int(brain ? brain->pendingSend : 0),
                 int(brain ? brain->pendingRecv : 0),
                 int(brain ? brain->isTLSNegotiated() : 0),
                 int(brain ? brain->tlsPeerVerified : 0));
    std::fflush(stderr);
    if (deferredHardwareInventoryResultReadyForAdoption(result) == false)
    {
      std::fprintf(stderr,
                   "neuron deferred hardware complete-retry inventoryComplete=%d serializedBytes=%llu failure=%s\n",
                   int(result.hardware.inventoryComplete),
                   (unsigned long long)result.serializedHardwareProfile.size(),
                   result.hardware.inventoryFailure.c_str());
      std::fflush(stderr);
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
    constexpr static const char *key = "usage_usec";
    constexpr static uint64_t keyLength = 10;

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
  static bool extractFixedArgBounded(uint8_t *& cursor, uint8_t *terminal, T& value)
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

    auto applyPendingForTopic = [&](bytell_hash_map<uint128_t, Vector<String>>& pendingPairings, ContainerTopic topic, bool advertisement) {
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
          if (ProdigyWire::deserializeAdvertisementPairingPayload(
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
          if (ProdigyWire::deserializeSubscriptionPairingPayload(
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
      if (ProdigyWire::deserializeCredentialDelta(payload, delta) == false)
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

  static bool parseOSReleaseValue(const String& osRelease, const char *key, String& parsed)
  {
    parsed.clear();
    if (key == nullptr)
    {
      return false;
    }

    uint64_t keySize = strlen(key);
    for (uint64_t start = 0; start < osRelease.size();)
    {
      uint64_t end = start;
      while (end < osRelease.size() && osRelease[end] != '\n')
      {
        end += 1;
      }

      if (end - start > keySize && memcmp(osRelease.data() + start, key, keySize) == 0 && osRelease[start + keySize] == '=')
      {
        uint64_t valueStart = start + keySize + 1;
        uint64_t valueEnd = end;
        if (valueStart < valueEnd && osRelease[valueStart] == '"')
        {
          valueStart += 1;
          if (valueEnd > valueStart && osRelease[valueEnd - 1] == '"')
          {
            valueEnd -= 1;
          }
        }

        if (valueStart == valueEnd)
        {
          return false;
        }

        parsed.assign(osRelease.substr(valueStart, valueEnd - valueStart, Copy::yes));
        return parsed.size() > 0;
      }

      start = (end < osRelease.size()) ? end + 1 : end;
    }

    return false;
  }

  static bool parseOSReleaseMetadata(const String& osRelease, String& parsedOSID, String& parsedOSVersionID)
  {
    bool haveID = parseOSReleaseValue(osRelease, "ID", parsedOSID);
    bool haveVersionID = parseOSReleaseValue(osRelease, "VERSION_ID", parsedOSVersionID);
    return haveID || haveVersionID;
  }

  void loadOSReleaseMetadata(void)
  {
    osID.clear();
    osVersionID.clear();
    String osRelease = {};

    const char *devMode = std::getenv("PRODIGY_DEV_MODE");
    const char *devOSReleasePath = std::getenv("PRODIGY_DEV_OS_RELEASE_PATH");
    if (devMode != nullptr && devMode[0] != '\0' && devMode[0] != '0' && devOSReleasePath != nullptr && devOSReleasePath[0] != '\0')
    {
      String path = {};
      path.assign(devOSReleasePath);
      Filesystem::openReadAtClose(-1, path, osRelease);
      if (parseOSReleaseMetadata(osRelease, osID, osVersionID))
      {
        return;
      }

      osRelease.clear();
    }

    Filesystem::openReadAtClose(-1, "/usr/lib/os-release"_ctv, osRelease);
    if (parseOSReleaseMetadata(osRelease, osID, osVersionID))
    {
      return;
    }

    osRelease.clear();
    Filesystem::openReadAtClose(-1, "/etc/os-release"_ctv, osRelease);
    (void)parseOSReleaseMetadata(osRelease, osID, osVersionID);
  }

  Switchboard *ensureSwitchboard(void)
  {
    if (!switchboard)
    {
      switchboard = std::make_unique<Switchboard>(eth);
    }

    switchboard->setHostIngressRouter(tcx_ingress_program);
    switchboard->setHostEgressRouter(tcx_egress_program);
    syncSwitchboardBalancerOverlayRoutingProgram();

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
    if (container == nullptr || container->plan.wormholes.empty())
    {
      return;
    }

    Switchboard *activeSwitchboard = ensureSwitchboard();
    uint32_t containerID = generateLocalContainerID(container->plan.fragment);

    activeSwitchboard->setLocalContainerSubnet(lcsubnet6);
    activeSwitchboard->openWormholes(containerID, container->plan.wormholes);
    syncSwitchboardBalancerOverlayRoutingProgram();

    // Wormhole refresh must also converge the target container's live peer
    // runtime immediately, not just the broader switchboard state, so the
    // first reply packets after a live refresh cannot miss the egress binding.
    syncContainerSwitchboardRuntime(container);
  }

  void openWhiteholesForLocalContainer(uint8_t fragment, const Vector<Whitehole>& whiteholes) override
  {
    if (whiteholes.empty())
    {
      return;
    }

    openLocalWhiteholes(generateLocalContainerID(fragment), whiteholes);
  }

  void closeWhiteholesForLocalContainer(uint8_t fragment) override
  {
    closeLocalWhiteholesToContainer(generateLocalContainerID(fragment));
  }

  void syncContainerSwitchboardRuntime(Container *container) override
  {
    if (switchboard == nullptr || container == nullptr || container->plan.useHostNetworkNamespace || container->peer_program == nullptr)
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
        tcx_egress_program = eth.attachBPF(BPF_TCX_EGRESS, hostEgressPath, "host_egress"_ctv);
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

      bool whiteholeReplyFlowPinned = false;
      if (tcx_egress_program)
      {
        whiteholeReplyFlowPinned = switchboardPinWhiteholeReplyFlowMap(tcx_egress_program, eth.ifidx);
        if (whiteholeReplyFlowPinned == false)
        {
          basics_log("setupNetworking failed to pin host whitehole reply flow map ifidx=%d\n",
                     eth.ifidx);
        }
      }

      if (whiteholeReplyFlowPinned == false)
      {
        basics_log("setupNetworking skipping host ingress attach because shared flow map pinning failed ifidx=%d\n",
                   eth.ifidx);
      }
      else
      {
        tcx_ingress_program = eth.loadPreattachedProgram(BPF_TCX_INGRESS, hostIngressPath);
#if NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE
        if (tcx_ingress_program)
        {
          bool hasPortalMaps = false;
          tcx_ingress_program->openMap("ext_portals"_ctv, [&](int mapFD) -> void {
            hasPortalMaps = mapFD >= 0;
          });
          if (hasPortalMaps == false)
          {
            basics_log("setupNetworking detaching stale host ingress without portal maps path=%s ifidx=%d\n",
                       hostIngressPath.c_str(), eth.ifidx);
            eth.detachBPF(BPF_TCX_INGRESS);
            tcx_ingress_program = nullptr;
          }
        }
#endif

        if (tcx_ingress_program)
        {
          basics_log("setupNetworking loaded preattached host ingress path=%s ifidx=%d\n",
                     hostIngressPath.c_str(), eth.ifidx);
          // so we could gather our fragment this way but we don't need to
          // tcx_ingress_program->getArrayElement("lc_subnet"_ctv, 0, lcsubnet6);

          // if we used the getULA(IPAddress& ula) on EthDevice with systemd network config files
          // to make subnets and fragments persist across operating system reboots.. but...
        }
        else
        {
          eth.addIP(containerSubnet6);

          // load and setup tcx ingress program
          tcx_ingress_program = eth.attachBPF(BPF_TCX_INGRESS, hostIngressPath, "host_ingress"_ctv,
                                              [&](struct bpf_object *obj, Vector<int>& inner_map_fds) -> void {
                                                (void)switchboardReusePinnedWhiteholeReplyFlowMap(obj, eth.ifidx, inner_map_fds);
                                              });
          if (tcx_ingress_program)
          {
            basics_log("setupNetworking attached host ingress path=%s ifidx=%d\n",
                       hostIngressPath.c_str(), eth.ifidx);
            tcx_ingress_program->setArrayElement("lc_subnet"_ctv, 0, lcsubnet6);
          }
          else
          {
            basics_log("setupNetworking failed to attach host ingress path=%s ifidx=%d\n",
                       hostIngressPath.c_str(), eth.ifidx);
          }
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
      tcx_ingress_program->setArrayElement("lc_subnet"_ctv, 0, lcsubnet6);
    }

    if (tcx_egress_program)
    {
      tcx_egress_program->setArrayElement("mac_map"_ctv, 0, eth.mac);
      tcx_egress_program->setArrayElement("gw_mac_map"_ctv, 0, eth.gateway_mac);
      (void)switchboardPinWhiteholeReplyFlowMap(tcx_egress_program, eth.ifidx);
    }

    iaas->setLocalContainerPrefixes(localPrefixes);
    ensureBGP()->setMachinePrefixes(localPrefixes);

    if (switchboard)
    {
      switchboard->setHostIngressRouter(tcx_ingress_program);
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
      if (failureReport)
      {
        failureReport->assign("neuron has no assigned fragment yet"_ctv);
      }
      basics_log("ensureHostNetworkingReady failed reason=no-fragment ifidx=%d dpfx=%u mpfx=%u.%u.%u brainPresent=%d brainActive=%d fd=%d fslot=%d\n",
                 eth.ifidx,
                 unsigned(lcsubnet6.dpfx),
                 unsigned(lcsubnet6.mpfx[0]),
                 unsigned(lcsubnet6.mpfx[1]),
                 unsigned(lcsubnet6.mpfx[2]),
                 int(brain != nullptr),
                 int(brain && streamIsActive(brain)),
                 (brain ? brain->fd : -1),
                 (brain ? brain->fslot : -1));
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

  bool isBrain;
  TCPSocket brainListener;
  NeuronBrainControlStream *brain = nullptr;
  bytell_hash_set<NeuronBrainControlStream *> closingBrainControls;
  OSUpdateProcess osUpdateProcess;

  static int64_t registrationBootTimeMs(void)
  {
    return Time::now<TimeResolution::ms>();
  }

  static void resetSignalForOSUpdateChild(int signal)
  {
    struct sigaction action = {};
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    (void)sigaction(signal, &action, nullptr);
  }

  static void closeOSUpdateChildFDs(void)
  {
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3u, ~0u, 0u) == 0)
    {
      return;
    }
#endif
    for (int fd = 3; fd < 4096; ++fd)
    {
      (void)syscall(SYS_close, fd);
    }
  }

  static int openOSUpdateChildFile(const char *path, int flags, mode_t mode = 0)
  {
    return int(syscall(SYS_openat, AT_FDCWD, path, flags, mode));
  }

  static void execOSUpdateChild(
      const char *shellPath,
      char *const *argv,
      char *const *envp)
  {
    sigset_t emptyMask = {};
    sigemptyset(&emptyMask);
    (void)sigprocmask(SIG_SETMASK, &emptyMask, nullptr);
    resetSignalForOSUpdateChild(SIGCHLD);
    resetSignalForOSUpdateChild(SIGTERM);
    resetSignalForOSUpdateChild(SIGINT);
    resetSignalForOSUpdateChild(SIGHUP);

    int nullFD = openOSUpdateChildFile("/dev/null", O_RDONLY | O_CLOEXEC);
    if (nullFD >= 0)
    {
      (void)syscall(SYS_dup2, nullFD, STDIN_FILENO);
      if (nullFD > STDERR_FILENO)
      {
        (void)syscall(SYS_close, nullFD);
      }
    }

    int logFD = openOSUpdateChildFile("/var/log/prodigy/os-update.log", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (logFD >= 0)
    {
      (void)syscall(SYS_dup2, logFD, STDOUT_FILENO);
      (void)syscall(SYS_dup2, logFD, STDERR_FILENO);
      if (logFD > STDERR_FILENO)
      {
        (void)syscall(SYS_close, logFD);
      }
    }

    closeOSUpdateChildFDs();
    (void)syscall(SYS_execve, shellPath, argv, envp);
    (void)syscall(SYS_exit, 127);
    __builtin_unreachable();
  }

  static pid_t forkOSUpdateLauncher(
      const char *shellPath,
      char *const *argv,
      char *const *envp)
  {
    pid_t launcher = fork();
    if (launcher != 0)
    {
      return launcher;
    }

    pid_t command = fork();
    if (command < 0)
    {
      (void)syscall(SYS_exit, 126);
    }

    if (command > 0)
    {
      (void)syscall(SYS_exit, 0);
    }

    (void)setsid();
    execOSUpdateChild(shellPath, argv, envp);
    __builtin_unreachable();
  }

  void clearOSUpdateProcess(void)
  {
    if (osUpdateProcess.fd >= 0)
    {
      (void)::close(osUpdateProcess.fd);
    }

    osUpdateProcess.fd = -1;
    osUpdateProcess.pid = -1;
    osUpdateProcess.active = false;
    osUpdateProcess.pollQueued = false;
    osUpdateProcess.targetOSID.clear();
    osUpdateProcess.targetOSVersionID.clear();
  }

  virtual bool startOperatingSystemUpdate(const String& targetOSID, const String& targetOSVersionID, const String& updateCommand, String *failure = nullptr)
  {
    if (failure)
    {
      failure->clear();
    }

    if (targetOSID.size() == 0)
    {
      if (failure)
      {
        failure->assign("target OS ID is empty"_ctv);
      }
      return false;
    }

    if (targetOSVersionID.size() == 0)
    {
      if (failure)
      {
        failure->assign("target OS VERSION_ID is empty"_ctv);
      }
      return false;
    }

    if (updateCommand.size() == 0)
    {
      if (failure)
      {
        failure->assign("OS update command is empty"_ctv);
      }
      return false;
    }

    String targetOSIDText = {};
    String targetOSVersionIDText = {};
    String updateCommandText = {};
    targetOSIDText.assign(targetOSID);
    targetOSVersionIDText.assign(targetOSVersionID);
    updateCommandText.assign(updateCommand);

    if (osUpdateProcess.active)
    {
      if (failure)
      {
        failure->snprintf<"OS update command already running pid={itoa}"_ctv>(int(osUpdateProcess.pid));
      }
      return false;
    }

    std::error_code createLogDirError = {};
    std::filesystem::create_directories("/var/log/prodigy", createLogDirError);

    String command = {};
    command.assign(updateCommandText);
    const char *shellPath = "/bin/sh";
    if (access(shellPath, X_OK) != 0)
    {
      shellPath = "/usr/bin/sh";
    }
    if (access(shellPath, X_OK) != 0)
    {
      if (failure)
      {
        failure->assign("missing executable /bin/sh or /usr/bin/sh for OS update command"_ctv);
      }
      return false;
    }

    char *argv[] = {
        const_cast<char *>("sh"),
        const_cast<char *>("-c"),
        const_cast<char *>(command.c_str()),
        nullptr};
    extern char **environ;
    std::vector<std::string> envStorage = {};
    for (char **entry = environ; entry != nullptr && *entry != nullptr; ++entry)
    {
      if (strncmp(*entry, "PRODIGY_TARGET_OS_ID=", 21) == 0 || strncmp(*entry, "PRODIGY_TARGET_OS_VERSION_ID=", 29) == 0 || strncmp(*entry, "PRODIGY_CURRENT_OS_ID=", 22) == 0 || strncmp(*entry, "PRODIGY_CURRENT_OS_VERSION_ID=", 30) == 0)
      {
        continue;
      }

      envStorage.emplace_back(*entry);
    }
    envStorage.emplace_back(std::string("PRODIGY_TARGET_OS_ID=") + targetOSIDText.c_str());
    envStorage.emplace_back(std::string("PRODIGY_TARGET_OS_VERSION_ID=") + targetOSVersionIDText.c_str());
    envStorage.emplace_back(std::string("PRODIGY_CURRENT_OS_ID=") + osID.c_str());
    envStorage.emplace_back(std::string("PRODIGY_CURRENT_OS_VERSION_ID=") + osVersionID.c_str());
    std::vector<char *> envp = {};
    envp.reserve(envStorage.size() + 1);
    for (std::string& value : envStorage)
    {
      envp.push_back(value.data());
    }
    envp.push_back(nullptr);

    pid_t pid = forkOSUpdateLauncher(shellPath, argv, envp.data());

    if (pid < 0)
    {
      if (failure)
      {
        failure->snprintf<"failed to start OS update command errno={itoa}({})"_ctv>(uint32_t(errno), String(strerror(errno)));
      }
      return false;
    }

    osUpdateProcess.pid = pid;
    osUpdateProcess.active = true;
    osUpdateProcess.pollQueued = false;
    osUpdateProcess.fd = int(syscall(SYS_pidfd_open, pid, 0));
    if (osUpdateProcess.fd >= 0)
    {
      osUpdateProcess.setNonBlocking();
    }
    osUpdateProcess.targetOSID.assign(targetOSIDText);
    osUpdateProcess.targetOSVersionID.assign(targetOSVersionIDText);
    if (osUpdateProcess.fd >= 0)
    {
      Ring::queuePollProcessFD(&osUpdateProcess, osUpdateProcess.fd, false, POLLIN);
      osUpdateProcess.pollQueued = true;
    }

    std::fprintf(stderr,
                 "neuron updateOS started targetOSID=%s targetOSVersionID=%s launcherPid=%lld pidfd=%d\n",
                 targetOSIDText.c_str(),
                 targetOSVersionIDText.c_str(),
                 (long long)pid,
                 osUpdateProcess.fd);
    std::fflush(stderr);
    basics_log("neuron updateOS started targetOSID=%s targetOSVersionID=%s launcherPid=%lld pidfd=%d\n",
               targetOSIDText.c_str(),
               targetOSVersionIDText.c_str(),
               (long long)pid,
               osUpdateProcess.fd);
    return true;
  }

  virtual void boot(void)
  {
    loadKernelVersion();
    loadOSReleaseMetadata();
    loadTaskAttemptJournal();
    bootTimeMs = registrationBootTimeMs();

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

    if (isBrain == false)
    {
      ContainerStore::autoDestroy = true;
    }

    if (const char *devMode = getenv("PRODIGY_DEV_MODE"); devMode && devMode[0] == '1' && devMode[1] == '\0')
    {
      brainControlKeepaliveSeconds = 6;
    }
    else
    {
      brainControlKeepaliveSeconds = 15;
    }

    brainListener.setIPVersion(AF_INET6);
    if (uint32_t maxSegmentSize = controlPlaneTCPMaxSegmentSize(AF_INET6); maxSegmentSize > 0)
    {
      (void)prodigySetTCPMaxSegmentSize(brainListener.fd, maxSegmentSize);
    }
    setsockopt(brainListener.fd, IPPROTO_IPV6, IPV6_V6ONLY, (const int[]) {0}, sizeof(int));
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
    bool pendingDestroyBeforeWait = false;

    CoroutineStack *resumeAfterShutdown = nullptr;

    Container *container = reinterpret_cast<Container *>(waiter);
    siginfo_t infop = container->infop;
    bool nonRestartableStartupFailure = (infop.si_code == CLD_EXITED && infop.si_status == containerStartupFailureExitCode);
    String containerName = container->name;
    {
      containerUUID = container->plan.uuid;
      pendingDestroyBeforeWait = container->pendingDestroy;
      container->waitidPending = false;
      container->disableKillSwitch();
      killedOnPurpose = container->killedOnPurpose;

      resumeAfterShutdown = container->resumeAfterShutdown;
      destroyAfterWait = (killedOnPurpose || container->plan.restartOnFailure == false || nonRestartableStartupFailure);
    }

    bool restart = (destroyAfterWait == false);
    if (restart)
    {
      if (container->isFixedFile && container->fslot >= 0 && Ring::socketIsClosing(container) == false)
      {
        Ring::queueCancelAll(container);
        Ring::queueCloseRaw(container->fslot);
      }
      else if (container->isFixedFile == false && container->fd >= 0)
      {
        close(container->fd);
      }

      if (container->pendingSend)
      {
        container->noteSendCompleted();
      }
      container->pendingSend = false;
      container->pendingRecv = false;
      container->pendingSendBytes = 0;
      container->pendingSendUserData = 0;
      container->pendingRecvUserData = 0;
      container->pendingConnectUserData = 0;
      container->pendingTCPFastOpenUserData = 0;
      container->rBuffer.clear();
      container->wBuffer.clear();
      container->fslot = -1;
      container->isFixedFile = false;
      container->bumpIoGeneration();
    }
    else
    {
      container->closeSocket();
    }

    std::fprintf(stderr,
                 "neuron waitid debug uuid=%llu pid=%d code=%d status=%d killedOnPurpose=%d pendingDestroyBefore=%d destroyAfter=%d restart=%d deploymentID=%llu lifetime=%u\n",
                 (unsigned long long)containerUUID,
                 int(infop.si_pid),
                 int(infop.si_code),
                 int(infop.si_status),
                 int(killedOnPurpose),
                 int(pendingDestroyBeforeWait),
                 int(destroyAfterWait),
                 int(restart),
                 (unsigned long long)container->plan.config.deploymentID(),
                 unsigned(container->plan.lifetime));
    std::fflush(stderr);

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

    if (container->plan.config.type == ApplicationType::task)
    {
      TaskTermination termination = {};
      termination.observedAtMs = failureTimeMs;
      termination.result = container->taskResult;

      if (killedOnPurpose)
      {
        termination.kind = TaskTerminationKind::cancelled;
        termination.summary.assign("cancelled"_ctv);
      }
      else if (nonRestartableStartupFailure)
      {
        termination.kind = TaskTerminationKind::startupFailed;
        termination.exitCode = infop.si_status;
        termination.summary.assign("startup failed before exec"_ctv);
      }
      else if (infop.si_code == CLD_EXITED)
      {
        termination.kind = TaskTerminationKind::exited;
        termination.exitCode = infop.si_status;
        termination.summary.snprintf<"exited with code {}"_ctv>(termination.exitCode);
      }
      else
      {
        termination.kind = TaskTerminationKind::signaled;
        termination.signal = ContainerManager::terminalSignalForFailedContainer(infop);
        termination.summary.snprintf<"terminated by signal {}"_ctv>(termination.signal);
      }

      (void)noteTaskAttemptTerminal(container->plan, termination);
      if (destroyAfterWait)
      {
        ContainerManager::destroyContainer(container);
      }
      if (pendingDestroyBeforeWait)
      {
        ContainerManager::finalizeContainerDestroyIfReady(container);
      }
      return;
    }

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
        String path;
        path.snprintf<"/containers/{}/crashreport.txt"_ctv>(containerName);
        Filesystem::openReadAtClose(-1, path, crashReport);
        if (crashReport.size() > 0)
        {
          Filesystem::eraseFile(path);
        }
        else if (container->rootfsPath.size() > 0)
        {
          path.assign(container->rootfsPath);
          path.append("/crashreport.txt"_ctv);
          Filesystem::openReadAtClose(-1, path, crashReport);
          if (crashReport.size() > 0)
          {
            Filesystem::eraseFile(path);
          }
        }
        if (crashReport.size() == 0 && infop.si_status == containerStartupFailureExitCode)
        {
          crashReport.assign("startup failed before exec"_ctv);
        }
        else if (crashReport.size() == 0)
        {
          crashReport.assign("exited with code "_ctv);
          String exitCode;
          exitCode.assignItoa(infop.si_status);
          crashReport.append(exitCode);
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

      reportContainerFailed(containerUUID, failureTimeMs, terminalSignal, crashReport, restart);

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

    if (pendingDestroyBeforeWait)
    {
      ContainerManager::finalizeContainerDestroyIfReady(container);
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

          bool controllingBrainActive = (brain != nullptr && streamIsActive(brain));
          if (thisBrain != nullptr && (thisBrain->canControlNeurons() || controllingBrainActive == false))
          {
            thisBrain->noteLocalContainerHealthy(container->plan.uuid);
          }
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
      case ContainerTopic::runtimeReady:
        {
          container->plan.runtimeReady = true;

          bool controllingBrainActive = (brain != nullptr && streamIsActive(brain));
          if (thisBrain != nullptr && (thisBrain->canControlNeurons() || controllingBrainActive == false))
          {
            thisBrain->noteLocalContainerRuntimeReady(container->plan.uuid);
          }

          if (brain)
          {
            Message::construct(brain->wBuffer, NeuronTopic::containerRuntimeReady, container->plan.uuid);
            if (controllingBrainActive)
            {
              Ring::queueSend(brain);
            }
          }

          break;
        }
      case ContainerTopic::taskResult:
        {
          if (container->plan.config.type != ApplicationType::task)
          {
            queueCloseIfActive(container);
            break;
          }
          if (uint64_t(terminal - args) > prodigyTaskResultMaxBytes)
          {
            queueCloseIfActive(container);
            break;
          }
          container->taskResult.assign(reinterpret_cast<const char *>(args), uint64_t(terminal - args));
          break;
        }
      case ContainerTopic::statistics:
        {
          // [metricKey(8) metricValue(8)]...
          // Forward container runtime metrics to the controlling brain with identity metadata.
          if (brain == nullptr)
          {
            break;
          }

          uint32_t headerOffset = Message::appendHeader(brain->wBuffer, NeuronTopic::containerStatistics);
          Message::append(brain->wBuffer, container->plan.config.deploymentID());
          Message::append(brain->wBuffer, container->plan.uuid);
          Message::append(brain->wBuffer, Time::now<TimeResolution::ms>());

          while (args < terminal)
          {
            if (size_t(terminal - args) < (sizeof(uint64_t) * 2))
            {
              break;
            }

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
            if (args < terminal)
            {
              String serializedAck;
              serializedAck.setInvariant(args, uint64_t(terminal - args));
              TlsResumptionApplyAck result;
              if (ProdigyWire::deserializeTlsResumptionApplyAckFramePayload(args, uint64_t(terminal - args), result))
              {
                Message::construct(brain->wBuffer, NeuronTopic::refreshContainerCredentials, container->plan.uuid, serializedAck);
              }
              else
              {
                break;
              }
            }
            else
            {
              Message::construct(brain->wBuffer, NeuronTopic::refreshContainerCredentials, container->plan.uuid);
            }
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
      default:
        break;
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

    auto queueNeuronStateUpload = [&]() -> void {
      if (brain == nullptr)
      {
        return;
      }

      basics_log("neuron queue stateUpload dpfx=%u mpfx=%u.%u.%u containers=%llu brainPresent=%d brainActive=%d fd=%d fslot=%d\n",
                 unsigned(lcsubnet6.dpfx),
                 unsigned(lcsubnet6.mpfx[0]),
                 unsigned(lcsubnet6.mpfx[1]),
                 unsigned(lcsubnet6.mpfx[2]),
                 (unsigned long long)containers.size(),
                 int(brain != nullptr),
                 int(streamIsActive(brain)),
                 (brain ? brain->fd : -1),
                 (brain ? brain->fslot : -1));

      uint32_t headerOffset = Message::appendHeader(brain->wBuffer, NeuronTopic::stateUpload);
      Message::appendAlignedBuffer<Alignment::one>(brain->wBuffer, (uint8_t *)&lcsubnet6, sizeof(struct local_container_subnet6));

      for (const auto& [uuid, container] : containers)
      {
        (void)uuid;
        String serializedPlan = {};
        BitseryEngine::serialize(serializedPlan, container->plan);
        Message::appendValue(brain->wBuffer, serializedPlan);
      }

      Message::finish(brain->wBuffer, headerOffset);

      if (streamIsActive(brain))
      {
        Ring::queueSend(brain);
      }
    };

    switch (NeuronTopic(message->topic))
    {
      case NeuronTopic::registration:
        {
          // requiresState(1)

          bool requiresState;
          Message::extractArg<ArgumentNature::fixed>(args, requiresState);

          if (requiresState)
          {
            queueNeuronStateUpload();
          }
          replayTerminalTaskAttemptJournal();

          break;
        }
      case NeuronTopic::stateUpload:
        {
          // fragment(4, 1) containerPlan{4}...
          struct local_container_subnet6 uploadedFragment = {};
          Message::extractBytes<Alignment::one>(args, (uint8_t *)&uploadedFragment, sizeof(struct local_container_subnet6));
          const bool hadFragments = haveFragments();
          const bool fragmentChanged = (memcmp(&lcsubnet6, &uploadedFragment, sizeof(uploadedFragment)) != 0);
          lcsubnet6 = uploadedFragment;
          basics_log("neuron apply stateUpload dpfx=%u mpfx=%u.%u.%u brainPresent=%d brainActive=%d fd=%d fslot=%d\n",
                     unsigned(lcsubnet6.dpfx),
                     unsigned(lcsubnet6.mpfx[0]),
                     unsigned(lcsubnet6.mpfx[1]),
                     unsigned(lcsubnet6.mpfx[2]),
                     int(brain != nullptr),
                     int(brain && streamIsActive(brain)),
                     (brain ? brain->fd : -1),
                     (brain ? brain->fslot : -1));
          if (hadFragments == false || fragmentChanged)
          {
            setupNetworking();
          }
          else
          {
            basics_log("neuron stateUpload networking already configured dpfx=%u mpfx=%u.%u.%u\n",
                       unsigned(lcsubnet6.dpfx),
                       unsigned(lcsubnet6.mpfx[0]),
                       unsigned(lcsubnet6.mpfx[1]),
                       unsigned(lcsubnet6.mpfx[2]));
          }

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

            if (auto existing = containers.find(restoredPlan.uuid); existing != containers.end() && existing->second != nullptr)
            {
              Container *liveContainer = existing->second;
              if (liveContainer->pendingDestroy == false)
              {
                liveContainer->neuronScalingDimensionsMask = metricPolicy.scalingDimensionsMask;
                liveContainer->neuronMetricsCadenceMs = metricPolicy.metricsCadenceMs;
                basics_log("neuron stateUpload skipped existing live container uuid=%llu pid=%d state=%u\n",
                           (unsigned long long)liveContainer->plan.uuid,
                           int(liveContainer->pid),
                           unsigned(liveContainer->plan.state));
                continue;
              }
            }

            Container *container = new Container();
            container->plan = std::move(restoredPlan);
            container->neuronScalingDimensionsMask = metricPolicy.scalingDimensionsMask;
            container->neuronMetricsCadenceMs = metricPolicy.metricsCadenceMs;

            container->name.assignItoa(container->plan.uuid);
            container->userID = 65'535 * container->plan.fragment;

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

                  if (container->plan.config.type == ApplicationType::task)
                  {
                    TaskTermination termination = {};
                    termination.kind = TaskTerminationKind::lost;
                    termination.observedAtMs = Time::now<TimeResolution::ms>();
                    termination.summary.assign("task network restore failed"_ctv);
                    (void)noteTaskAttemptTerminal(container->plan, termination);
                    ContainerManager::destroyContainer(container);
                  }
                  else
                  {
                    bool restarted = false;
                    uint128_t restoredUUID = container->plan.uuid;
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
                    reportContainerFailed(restoredUUID, 0, 0, empty, restarted);
                  }
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
              noteTaskAttemptRunning(container->plan);
              ContainerManager::queueContainerWaitid(container);
              Ring::queueConnect(container);
            }
            else
            {
              if (container->plan.config.type == ApplicationType::task)
              {
                TaskTermination termination = {};
                termination.kind = TaskTerminationKind::lost;
                termination.observedAtMs = Time::now<TimeResolution::ms>();
                termination.summary.assign("task process missing during neuron restore"_ctv);
                (void)noteTaskAttemptTerminal(container->plan, termination);
                ContainerManager::destroyContainer(container);
              }
              else
              {
                bool restarted = false;
                uint128_t restoredUUID = container->plan.uuid;
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
                reportContainerFailed(restoredUUID, 0, 0, empty, restarted);
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
          else
          {
            queueNeuronStateUpload();
          }

          break;
        }
      case NeuronTopic::updateOS:
        {
          String targetOSID = {};
          String targetOSVersionID = {};
          String updateCommand = {};
          Message::extractToStringView(args, targetOSID);
          Message::extractToStringView(args, targetOSVersionID);
          Message::extractToStringView(args, updateCommand);

          String targetOSIDText = {};
          String targetOSVersionIDText = {};
          String updateCommandText = {};
          targetOSIDText.assign(targetOSID);
          targetOSVersionIDText.assign(targetOSVersionID);
          updateCommandText.assign(updateCommand);

          String failure = {};
          if (startOperatingSystemUpdate(targetOSIDText, targetOSVersionIDText, updateCommandText, &failure) == false)
          {
            std::fprintf(stderr,
                         "neuron updateOS failed targetOSID=%s targetOSVersionID=%s reason=%s\n",
                         targetOSIDText.c_str(),
                         targetOSVersionIDText.c_str(),
                         failure.c_str());
            std::fflush(stderr);
            basics_log("neuron updateOS failed targetOSID=%s targetOSVersionID=%s reason=%s\n",
                       targetOSIDText.c_str(),
                       targetOSVersionIDText.c_str(),
                       failure.c_str());
            if (brain != nullptr)
            {
              Message::construct(brain->wBuffer, NeuronTopic::hardwareFailure, failure);
              if (streamIsActive(brain))
              {
                Ring::queueSend(brain);
              }
            }
          }

          break;
        }
      case NeuronTopic::assignFragment:
        {
          // fragment(4, 1)

          Message::extractBytes<Alignment::one>(args, (uint8_t *)&lcsubnet6, sizeof(struct local_container_subnet6));
          basics_log("neuron assignFragment dpfx=%u mpfx=%u.%u.%u brainPresent=%d brainActive=%d fd=%d fslot=%d\n",
                     unsigned(lcsubnet6.dpfx),
                     unsigned(lcsubnet6.mpfx[0]),
                     unsigned(lcsubnet6.mpfx[1]),
                     unsigned(lcsubnet6.mpfx[2]),
                     int(brain != nullptr),
                     int(brain && streamIsActive(brain)),
                     (brain ? brain->fd : -1),
                     (brain ? brain->fslot : -1));
          setupNetworking();
          queueNeuronStateUpload();

          break;
        }
      case NeuronTopic::configureRuntimeEnvironment:
        {
          String serialized;
          Message::extractToStringView(args, serialized);

          ProdigyRuntimeEnvironmentConfig config = {};
          if (BitseryEngine::deserializeSafe(serialized, config))
          {
            prodigyApplyInternalRuntimeEnvironmentDefaults(config);
            configuredInterContainerMTU = config.test.enabled ? config.test.interContainerMTU : 0;
            configuredFakeIpv4Boundary = config.test.enabled && config.test.enableFakeIpv4Boundary;
            if (uint32_t maxSegmentSize = controlPlaneTCPMaxSegmentSize(AF_INET6); maxSegmentSize > 0)
            {
              if (brainListener.isFixedFile && brainListener.fslot >= 0)
              {
                Ring::queueSetSockOptInt(&brainListener, SOL_TCP, TCP_MAXSEG, int(maxSegmentSize), "neuron brain listener tcp maxseg");
              }
              else
              {
                (void)prodigySetTCPMaxSegmentSize(brainListener.fd, maxSegmentSize);
              }
              if (brain && brain->isFixedFile && brain->fslot >= 0)
              {
                Ring::queueSetSockOptInt(brain, SOL_TCP, TCP_MAXSEG, int(maxSegmentSize), "neuron brain control tcp maxseg");
              }
              else if (brain && brain->fd >= 0)
              {
                (void)prodigySetTCPMaxSegmentSize(brain->fd, maxSegmentSize);
              }
            }
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

          if (containerBlob.size() > 0)
          {
            String containerStoreFailure = {};
            if (ContainerStore::store(deploymentID, containerBlob, nullptr, nullptr, nullptr, nullptr, &containerStoreFailure) == false)
            {
              std::fprintf(stderr,
                           "neuron requestContainerBlob store failed deploymentID=%llu reason=%s\n",
                           (unsigned long long)deploymentID,
                           (containerStoreFailure.size() > 0 ? containerStoreFailure.c_str() : "unknown"));
              std::fflush(stderr);
            }
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

          if (replaceContainerUUID > 0)
          {
            Message::construct(brain->wBuffer, NeuronTopic::killContainer, replaceContainerUUID);
          }

          break;
        }
      case NeuronTopic::taskAttemptTerminalAck:
        {
          uint64_t deploymentID = 0;
          uint32_t attemptNumber = 0;
          Message::extractArg<ArgumentNature::fixed>(args, deploymentID);
          Message::extractArg<ArgumentNature::fixed>(args, attemptNumber);
          acknowledgeTaskAttemptTerminal(deploymentID, attemptNumber);
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
            std::fprintf(stderr,
                         "neuron changeContainerLifetime uuid=%llu deploymentID=%llu old=%u\n",
                         (unsigned long long)containerUUID,
                         (unsigned long long)container->plan.config.deploymentID(),
                         unsigned(container->plan.lifetime));
            std::fflush(stderr);
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
            std::fprintf(stderr,
                         "neuron killContainer command uuid=%llu deploymentID=%llu lifetime=%u pendingDestroy=%d killedOnPurpose=%d pid=%d\n",
                         (unsigned long long)containerUUID,
                         (unsigned long long)container->plan.config.deploymentID(),
                         unsigned(container->plan.lifetime),
                         int(container->pendingDestroy),
                         int(container->killedOnPurpose),
                         int(container->pid));
            std::fflush(stderr);
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
          syncSwitchboardBalancerOverlayRoutingProgram();

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
          if (ProdigyWire::deserializeAdvertisementPairingPayload(
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
          if (ProdigyWire::deserializeSubscriptionPairingPayload(
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
          if (ProdigyWire::deserializeCredentialDelta(serializedDelta, delta) == false)
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
      default:
        break;
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
          if (stream->decryptTransportTLS(uint32_t(result)) == false || ((void *)stream == (void *)brain && verifyBrainTransportTLSPeer() == false))
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
      stream->template extractMessages<Message>([&](Message *message) -> void {
        dispatch(message);
      },
                                                true, UINT32_MAX, 16, ProdigyWire::maxControlFrameBytes, parseFailed);
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
        if (stream->transportTLSEnabled() && streamIsActive(stream) && stream->needsTransportTLSSendKick())
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
      if constexpr (std::is_same_v<T, NeuronBrainControlStream>)
      {
        std::fprintf(stderr,
                     "neuron brain recv-terminal result=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d fd=%d fslot=%d queued=%llu rbytes=%llu\n",
                     result,
                     int(stream->pendingSend),
                     int(stream->pendingRecv),
                     int(stream->isTLSNegotiated()),
                     int(stream->tlsPeerVerified),
                     stream->fd,
                     stream->fslot,
                     (unsigned long long)stream->queuedSendOutstandingBytes(),
                     (unsigned long long)stream->rBuffer.outstandingBytes());
        std::fflush(stderr);
      }
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
      recvHandler(brain, result, [&](Message *message) -> void {
        neuronHandler(message);
      });
    }
    else if (closingBrainControls.contains(static_cast<NeuronBrainControlStream *>(socket)))
    {
      NeuronBrainControlStream *closingBrain = static_cast<NeuronBrainControlStream *>(socket);
      closingBrain->pendingRecv = false;
      if (rawStreamIsActive(closingBrain) && Ring::socketIsClosing(closingBrain) == false)
      {
        queueCloseIfActive(closingBrain);
      }
      destroyRetiredBrainControlStreamIfDrained(closingBrain);
      return;
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

      recvHandler(container, result, [&](Message *message) -> void {
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
      if constexpr (std::is_same_v<T, NeuronBrainControlStream>)
      {
        std::fprintf(stderr,
                     "neuron brain send-terminal result=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d fd=%d fslot=%d queued=%llu wbytes=%u\n",
                     result,
                     int(stream->pendingSend),
                     int(stream->pendingRecv),
                     int(stream->isTLSNegotiated()),
                     int(stream->tlsPeerVerified),
                     stream->fd,
                     stream->fslot,
                     (unsigned long long)stream->queuedSendOutstandingBytes(),
                     unsigned(stream->wBuffer.size()));
        std::fflush(stderr);
      }
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
    else if (closingBrainControls.contains(static_cast<NeuronBrainControlStream *>(socket)))
    {
      NeuronBrainControlStream *closingBrain = static_cast<NeuronBrainControlStream *>(socket);
      if (closingBrain->pendingSend)
      {
        closingBrain->noteSendCompleted();
      }
      closingBrain->pendingSend = false;
      closingBrain->pendingSendBytes = 0;
      closingBrain->clearQueuedSendBytes();
      if (rawStreamIsActive(closingBrain) && Ring::socketIsClosing(closingBrain) == false)
      {
        queueCloseIfActive(closingBrain);
      }
      destroyRetiredBrainControlStreamIfDrained(closingBrain);
      return;
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
      // Keep one brain-control accept armed even while a current control
      // stream is live. Reboots and master handoffs can leave the old
      // stream half-open; the next accepted stream must be able to
      // preempt it without waiting for kernel EOF on the stale socket.
      queueBrainAccept();
      if (brain != nullptr)
      {
        // Only one controlling brain stream is valid at a time. A promoted
        // master must be able to displace a stale live stream left behind by
        // the old master during handoff/failover, so the accepted stream wins.
        retireBrainControlStream(brain, streamIsActive(brain) ? "accept-preempt-active" : "accept-replace");
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
      Ring::publishSocketGeneration(brain);
      Ring::queueSetSockOptRaw(brain, SOL_TCP, TCP_CONGESTION, "dctcp", socklen_t(strlen("dctcp")), "neuron accepted brain control congestion");
      Ring::queueSetSockOptInt(brain, SOL_SOCKET, SO_KEEPALIVE, 1, "neuron accepted brain control keepalive");
      Ring::queueSetSockOptInt(brain, SOL_TCP, TCP_KEEPIDLE, int(std::max<uint32_t>(brainControlKeepaliveSeconds, 1u)), "neuron accepted brain control keepidle");
      Ring::queueSetSockOptInt(brain, SOL_TCP, TCP_KEEPINTVL, int(std::max<uint32_t>(brainControlKeepaliveSeconds / 3, 1u)), "neuron accepted brain control keepintvl");
      Ring::queueSetSockOptInt(brain, SOL_TCP, TCP_KEEPCNT, 3, "neuron accepted brain control keepcnt");
      if (uint32_t maxSegmentSize = controlPlaneTCPMaxSegmentSize(AF_INET6); maxSegmentSize > 0)
      {
        Ring::queueSetSockOptInt(brain, SOL_TCP, TCP_MAXSEG, int(maxSegmentSize), "neuron accepted brain control tcp maxseg");
      }
      basics_log("neuron accepted brain control stream=%p fd=%d fslot=%d\n",
                 static_cast<void *>(brain),
                 brain->fd,
                 brain->fslot);
      std::fprintf(stderr, "neuron brain control accepted-live stream=%p fd=%d fslot=%d retained=%zu\n",
                   static_cast<void *>(brain),
                   brain->fd,
                   brain->fslot,
                   size_t(closingBrainControls.size()));
      std::fflush(stderr);

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

      bool queuedHardwareProfile = queueMachineHardwareProfileToBrainIfReady("brain-control-accept");
      std::fprintf(stderr,
                   "neuron brain control queue-hardware reason=accept stream=%p fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d queuedHardware=%d wbytes=%u queued=%llu serializedHardware=%llu\n",
                   static_cast<void *>(brain),
                   brain->fd,
                   brain->fslot,
                   int(brain->pendingSend),
                   int(brain->pendingRecv),
                   int(brain->isTLSNegotiated()),
                   int(brain->tlsPeerVerified),
                   int(queuedHardwareProfile),
                   unsigned(brain->wBuffer.size()),
                   (unsigned long long)brain->queuedSendOutstandingBytes(),
                   (unsigned long long)serializedHardwareProfile.size());
      std::fflush(stderr);
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
    else
    {
      queueBrainAccept();
    }
  }

  void pollHandler(void *socket, int result) override
  {
    if (socket == (void *)&osUpdateProcess)
    {
      osUpdateProcess.pollQueued = false;

      siginfo_t infop = {};
      if (osUpdateProcess.pid > 0)
      {
        (void)waitid(P_PID, osUpdateProcess.pid, &infop, WEXITED | WNOHANG);
      }

      basics_log("neuron updateOS launcher-poll targetOSID=%s targetOSVersionID=%s launcherPid=%lld result=%d code=%d status=%d\n",
                 osUpdateProcess.targetOSID.c_str(),
                 osUpdateProcess.targetOSVersionID.c_str(),
                 (long long)osUpdateProcess.pid,
                 result,
                 int(infop.si_code),
                 int(infop.si_status));
      std::fprintf(stderr,
                   "neuron updateOS launcher-poll targetOSID=%s targetOSVersionID=%s launcherPid=%lld result=%d code=%d status=%d\n",
                   osUpdateProcess.targetOSID.c_str(),
                   osUpdateProcess.targetOSVersionID.c_str(),
                   (long long)osUpdateProcess.pid,
                   result,
                   int(infop.si_code),
                   int(infop.si_status));
      std::fflush(stderr);
      clearOSUpdateProcess();
      return;
    }

    if (socket == (void *)&deferredHardwareInventoryWake)
    {
      deferredHardwareInventoryWakePollQueued = false;
      std::fprintf(stderr, "neuron deferred hardware wake result=%d fd=%d\n", result, deferredHardwareInventoryWake.fd);
      std::fflush(stderr);
      if (result != -ECANCELED)
      {
        drainDeferredHardwareInventoryWake();
        bool completed = completeDeferredHardwareInventoryIfReady();
        std::fprintf(stderr, "neuron deferred hardware wake-drain-complete result=%d completed=%d\n",
                     result,
                     int(completed));
        std::fflush(stderr);
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
      NeuronBrainControlStream *closingBrain = brain;
      basics_log("neuron brain control closed stream=%p fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d\n",
                 static_cast<void *>(closingBrain),
                 closingBrain->fd,
                 closingBrain->fslot,
                 int(closingBrain->pendingSend),
                 int(closingBrain->pendingRecv),
                 int(closingBrain->isTLSNegotiated()),
                 int(closingBrain->tlsPeerVerified));
      std::fprintf(stderr, "neuron brain control close-live stream=%p fd=%d fslot=%d retained=%zu\n",
                   static_cast<void *>(closingBrain),
                   closingBrain->fd,
                   closingBrain->fslot,
                   size_t(closingBrainControls.size()));
      std::fflush(stderr);

      retireBrainControlStream(closingBrain, "close-live-drain");
      queueBrainAccept();
    }
    else if (closingBrainControls.contains(static_cast<NeuronBrainControlStream *>(socket)))
    {
      NeuronBrainControlStream *closingBrain = static_cast<NeuronBrainControlStream *>(socket);
      basics_log("neuron retired brain control closed stream=%p pendingSend=%d pendingRecv=%d fd=%d fslot=%d retained=%zu\n",
                 static_cast<void *>(closingBrain),
                 int(closingBrain->pendingSend),
                 int(closingBrain->pendingRecv),
                 closingBrain->fd,
                 closingBrain->fslot,
                 size_t(closingBrainControls.size()));
      destroyRetiredBrainControlStream(closingBrain);
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
        container->destroyCloseCompleted = true;
        ContainerManager::finalizeContainerDestroyIfReady(container);
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
      default:
        break;
    }
  }

  void pushContainer(Container *container) override
  {
    containers.insert_or_assign(container->plan.uuid, container);
    containerByPid.insert_or_assign(container->pid, container);
    RingDispatcher::installMultiplexee(container, this);

    if (container->exposesNeuronSocket() == false)
    {
      return;
    }

    if (container->plan.wormholes.empty() == false)
    {
      // Wormhole egress bindings depend on the live container map so the
      // local peer egress program can be discovered on the real host.
      refreshContainerSwitchboardWormholes(container);
    }

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

  void reportContainerFailed(uint128_t containerUUID, int64_t failureTimeMs, int terminalSignal, const String& crashReport, bool restart) override
  {
    if (brain == nullptr)
    {
      return;
    }
    Message::construct(brain->wBuffer, NeuronTopic::containerFailed, containerUUID, failureTimeMs, terminalSignal, crashReport, restart);
    if (streamIsActive(brain))
    {
      Ring::queueSend(brain);
    }
  }

  void reportTaskAttemptTerminal(uint64_t deploymentID, uint32_t attemptNumber, uint128_t containerUUID, const TaskTermination& termination) override
  {
    if (brain == nullptr)
    {
      return;
    }

    String serialized = {};
    BitseryEngine::serialize(serialized, termination);
    Message::construct(brain->wBuffer, NeuronTopic::taskAttemptTerminal, deploymentID, attemptNumber, containerUUID, serialized);
    if (streamIsActive(brain))
    {
      Ring::queueSend(brain);
    }
  }
};
